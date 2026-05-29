//! `PrometheusRegistryAdapter` — implements `MetricRegistryPort` via
//! hand-encoded Prometheus text (exposition format version 0.0.4).
//!
//! # ADR-0006 deviation
//!
//! The original ADR-0006 specified use of `prometheus-client` for registry
//! management.  After evaluation, the `prometheus-client` label-set API
//! requires statically-typed label structs, which is incompatible with the
//! dynamic `BTreeMap<String,String>` label model in `MetricSample`.
//! Implementing the dynamic-label path with `prometheus-client` requires
//! registering separate `Family` instances per label-set cardinality, which
//! introduces significant complexity with no benefit over direct text encoding.
//!
//! **Decision**: hand-encode the Prometheus text format from `MetricSample`
//! values.  This produces spec-compliant output, keeps the adapter simple, and
//! avoids forcing the domain model to conform to the library's type constraints.
//!
//! # Exposition format
//!
//! The body is classic Prometheus text **version 0.0.4** — the format declared
//! by the HTTP adapter's `Content-Type` (`text/plain; version=0.0.4`). This is
//! deliberately **not** `OpenMetrics`: counter `# TYPE` lines keep the `_total`
//! suffix and the body carries **no `# EOF` trailer** (the `OpenMetrics`
//! terminator). Mixing the `OpenMetrics` trailer into a 0.0.4-typed body is a
//! format inconsistency, so it is not emitted.
//!
//! # ADR-0023 — lock-free storage
//!
//! The encoded body is now stored in `arc_swap::ArcSwap<Arc<str>>` (RCU).
//! `update_samples` does an atomic `store()`; `encode_text` does a wait-free
//! `load()`.  No `Mutex` or `RwLock` is used anywhere in this adapter.

use std::sync::Arc;

use arc_swap::ArcSwap;

use nlx_domain::metric::{MetricKind, MetricSample, MetricValue};
use nlx_ports::driven::MetricRegistryPort;
use std::collections::BTreeMap;
use std::fmt::Write as FmtWrite;
use thiserror::Error;

/// Errors emitted by the prometheus-client adapter.
#[derive(Debug, Error)]
pub enum RegistryError {
    /// Text encoding failed.
    #[error("OpenMetrics encode error: {0}")]
    Encode(String),
}

/// Driven adapter that maps [`MetricSample`]s into Prometheus text (0.0.4).
///
/// The encoded body is stored after every [`MetricRegistryPort::update_samples`]
/// call.  The HTTP `/metrics` handler reads it via
/// [`MetricRegistryPort::encode_text`].  Snapshot semantics: each call to
/// `update_samples` fully replaces the stored body.
///
/// **Lock-free (ADR-0023):** uses `ArcSwap<Arc<str>>` (RCU) — zero `Mutex` /
/// `RwLock`.  Writers do one atomic pointer swap; readers do one wait-free load.
pub struct PrometheusRegistryAdapter {
    /// Latest encoded Prometheus text body; updated atomically by `update_samples`.
    encoded: ArcSwap<Arc<str>>,
}

impl std::fmt::Debug for PrometheusRegistryAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrometheusRegistryAdapter").finish()
    }
}

impl PrometheusRegistryAdapter {
    /// Construct a new adapter with an empty body.
    #[must_use]
    pub fn new() -> Self {
        Self {
            encoded: ArcSwap::new(Arc::new(Arc::from(""))),
        }
    }
}

impl Default for PrometheusRegistryAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricRegistryPort for PrometheusRegistryAdapter {
    async fn update_samples(&self, samples: Vec<MetricSample>) -> Result<(), String> {
        let text = encode_samples(&samples).map_err(|e| e.to_string())?;
        // Atomic RCU store — no lock, no blocking, safe from any thread.
        self.encoded.store(Arc::new(Arc::from(text.as_str())));
        Ok(())
    }

    async fn encode_text(&self) -> Result<String, String> {
        // Wait-free load — returns a guard that keeps the Arc alive.
        let guard = self.encoded.load();
        Ok(guard.as_ref().to_string())
    }
}

// ---------------------------------------------------------------------------
// Text encoding
// ---------------------------------------------------------------------------

/// Produce a valid Prometheus text exposition (version 0.0.4) from `samples`.
///
/// Groups by metric name; emits one `# HELP` + `# TYPE` header per name,
/// followed by all sample lines.  Within a name group, label sets are
/// sorted for deterministic output.  No `# EOF` trailer is emitted — the body
/// is classic 0.0.4, not `OpenMetrics` (see module docs).
///
/// # Errors
///
/// Returns [`RegistryError::Encode`] if string formatting fails (practically
/// infallible for in-memory `String` writes, but propagated for correctness).
fn encode_samples(samples: &[MetricSample]) -> Result<String, RegistryError> {
    let mut groups: BTreeMap<&'static str, GroupEntry<'_>> = BTreeMap::new();

    for sample in samples {
        let entry = groups.entry(sample.name).or_insert_with(|| GroupEntry {
            help: sample.help,
            kind: sample.kind,
            observations: Vec::new(),
        });
        entry.observations.push((&sample.labels, &sample.value));
    }

    let mut out = String::with_capacity(samples.len().saturating_mul(64));

    for (name, group) in &groups {
        let help_escaped = escape_help(group.help);
        writeln!(out, "# HELP {name} {help_escaped}")
            .map_err(|e| RegistryError::Encode(e.to_string()))?;
        writeln!(out, "# TYPE {name} {}", kind_str(group.kind))
            .map_err(|e| RegistryError::Encode(e.to_string()))?;

        for (labels, value) in &group.observations {
            write_sample_line(&mut out, name, labels, value)
                .map_err(|e| RegistryError::Encode(e.to_string()))?;
        }
    }

    Ok(out)
}

/// Temporary container while building metric groups.
struct GroupEntry<'a> {
    help: &'static str,
    kind: MetricKind,
    observations: Vec<(&'a BTreeMap<String, String>, &'a MetricValue)>,
}

/// Prometheus metric type string.
fn kind_str(kind: MetricKind) -> &'static str {
    match kind {
        MetricKind::Counter => "counter",
        MetricKind::Gauge => "gauge",
        MetricKind::Histogram => "histogram",
    }
}

/// Escape a HELP string: `\` → `\\`, newline → `\n`.
fn escape_help(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out
}

/// Escape a label value per the Prometheus 0.0.4 text-format spec.
///
/// Defined escapes: `\` → `\\`, `"` → `\"`, newline → `\n`.
///
/// Non-printable ASCII control characters below `U+0020` (other than the
/// newline `U+000A` which receives its own escape above) are **stripped**.
/// The Prometheus/OpenMetrics text format defines no escape sequence for
/// arbitrary control bytes; including them unescaped causes spec-violating
/// output that parsers may reject or misinterpret.  Stripping is the safe
/// conforming choice (SEC-INFO-002).
fn escape_label_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            // Strip non-printable ASCII controls (U+0000–U+001F excluding \n).
            c if (c as u32) < 0x20 => {}
            other => out.push(other),
        }
    }
    out
}

/// Write one `name{labels} value` line into `out`.
fn write_sample_line(
    out: &mut String,
    name: &str,
    labels: &BTreeMap<String, String>,
    value: &MetricValue,
) -> Result<(), std::fmt::Error> {
    out.push_str(name);

    if !labels.is_empty() {
        out.push('{');
        let mut first = true;
        for (k, v) in labels {
            if !first {
                out.push(',');
            }
            first = false;
            write!(out, "{}=\"{}\"", k, escape_label_value(v))?;
        }
        out.push('}');
    }

    out.push(' ');

    match value {
        MetricValue::U64(n) => write!(out, "{n}")?,
        MetricValue::F64(f) => write_f64(out, *f)?,
    }

    out.push('\n');
    Ok(())
}

/// Write an f64 in a Prometheus-compatible way.
fn write_f64(out: &mut String, v: f64) -> Result<(), std::fmt::Error> {
    if v.is_nan() {
        out.push_str("NaN");
    } else if v.is_infinite() {
        if v.is_sign_positive() {
            out.push_str("+Inf");
        } else {
            out.push_str("-Inf");
        }
    } else {
        write!(out, "{v}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::cast_possible_truncation,
        reason = "test code; panics on unexpected failure are intentional"
    )]

    use super::*;
    use std::collections::BTreeMap;

    // -----------------------------------------------------------------------
    // Existing regression tests
    // -----------------------------------------------------------------------

    #[test]
    fn round_trip_gauge_and_counter() {
        let mut labels = BTreeMap::new();
        labels.insert("collector".to_owned(), "rtnetlink".to_owned());

        let samples = vec![
            MetricSample::gauge(
                "nft_up",
                "Exporter liveness: 1 if up, 0 otherwise.",
                BTreeMap::new(),
                1.0,
            ),
            MetricSample::counter(
                "nft_scrape_collector_error_total",
                "Total scrape errors per collector.",
                labels,
                7,
            ),
        ];

        let text = encode_samples(&samples).expect("encode should succeed");
        assert!(text.contains("# HELP nft_up"), "missing HELP for nft_up");
        assert!(text.contains("# TYPE nft_up gauge"), "missing TYPE gauge");
        assert!(text.contains("nft_up 1"), "missing nft_up value");
        assert!(
            text.contains("# TYPE nft_scrape_collector_error_total counter"),
            "missing counter TYPE"
        );
        assert!(
            text.contains(r#"nft_scrape_collector_error_total{collector="rtnetlink"} 7"#),
            "missing labelled counter value"
        );
    }

    /// The body is classic 0.0.4 — it must NOT carry the `OpenMetrics` `# EOF`
    /// trailer, because the HTTP adapter serves `Content-Type: text/plain;
    /// version=0.0.4`. A trailing `OpenMetrics` marker under a 0.0.4
    /// content-type is a format inconsistency (parses as a comment; should not
    /// exist).
    #[test]
    fn encode_samples_has_no_openmetrics_eof_trailer() {
        let samples = vec![MetricSample::gauge(
            "nft_up",
            "Exporter up.",
            BTreeMap::new(),
            1.0,
        )];
        let text = encode_samples(&samples).expect("encode ok");
        assert!(
            !text.contains("# EOF"),
            "0.0.4 body must not contain the OpenMetrics # EOF trailer: {text}"
        );
        // The body still ends with a newline-terminated sample line.
        assert!(text.ends_with('\n'), "body must end with a newline");
        assert!(
            text.trim_end().ends_with("nft_up 1"),
            "last line must be the sample, not a trailer: {text}"
        );
    }

    #[test]
    fn escape_label_value_special_chars() {
        assert_eq!(escape_label_value(r#"a\"b"#), r#"a\\\"b"#);
        assert_eq!(escape_label_value("a\nb"), r"a\nb");
    }

    // -----------------------------------------------------------------------
    // TC-013: encode_samples edge cases
    // -----------------------------------------------------------------------

    /// Empty label map must produce a bare `name value` line with no `{…}`.
    #[test]
    fn encode_samples_empty_labels() {
        let samples = vec![MetricSample::gauge(
            "nft_up",
            "Exporter up.",
            BTreeMap::new(),
            1.0,
        )];
        let text = encode_samples(&samples).expect("encode ok");
        // Must NOT contain braces for empty label set.
        assert!(
            !text.contains('{'),
            "empty label set must not emit braces: {text}"
        );
        assert!(
            text.contains("nft_up 1"),
            "bare sample line missing: {text}"
        );
    }

    /// Label value containing a double-quote must be `\"` in the output.
    #[test]
    fn encode_samples_label_value_quote_escape() {
        let mut labels = BTreeMap::new();
        labels.insert("iface".to_owned(), r#"eth"0"#.to_owned());
        let samples = vec![MetricSample::gauge("nft_rx", "RX bytes.", labels, 0.0)];
        let text = encode_samples(&samples).expect("encode ok");
        assert!(
            text.contains(r#"iface="eth\"0""#),
            "quote not escaped in output: {text}"
        );
    }

    /// Label value containing a backslash must be `\\` in the output.
    #[test]
    fn encode_samples_label_value_backslash_escape() {
        let mut labels = BTreeMap::new();
        labels.insert("path".to_owned(), r"a\b".to_owned());
        let samples = vec![MetricSample::gauge("nft_rx", "RX bytes.", labels, 0.0)];
        let text = encode_samples(&samples).expect("encode ok");
        assert!(
            text.contains(r#"path="a\\b""#),
            "backslash not escaped in output: {text}"
        );
    }

    /// Label value containing a newline must be `\n` (literal two chars) in
    /// the output — a raw newline inside a label value would break parsers.
    #[test]
    fn encode_samples_label_value_newline_escape() {
        let mut labels = BTreeMap::new();
        labels.insert("desc".to_owned(), "line1\nline2".to_owned());
        let samples = vec![MetricSample::gauge("nft_rx", "RX bytes.", labels, 0.0)];
        let text = encode_samples(&samples).expect("encode ok");
        assert!(
            text.contains(r#"desc="line1\nline2""#),
            "newline not escaped in output: {text}"
        );
    }

    /// Label value containing ASCII control chars (< 0x20, excluding \n)
    /// must be stripped — SEC-INFO-002.
    #[test]
    fn encode_samples_label_value_control_chars_stripped() {
        // NUL (0x00), BEL (0x07), TAB (0x09) embedded.
        let value = "a\x00b\x07c\x09d".to_owned();
        let mut labels = BTreeMap::new();
        labels.insert("v".to_owned(), value);
        let samples = vec![MetricSample::gauge("nft_rx", "RX bytes.", labels, 0.0)];
        let text = encode_samples(&samples).expect("encode ok");
        // Control chars must not appear in the output (newlines are structural).
        assert!(
            !text.chars().any(|c| (c as u32) < 0x20 && c != '\n'),
            "control char leaked into output: {text:?}"
        );
        // The printable characters must survive.
        assert!(
            text.contains(r#"v="abcd""#),
            "printable chars not preserved: {text}"
        );
    }

    /// A counter metric name must appear with `_total` suffix in the sample
    /// line when the name already carries it (no double-suffix).
    #[test]
    fn encode_samples_counter_total_suffix_present() {
        let samples = vec![MetricSample::counter(
            "nft_scrape_errors_total",
            "Total errors.",
            BTreeMap::new(),
            42,
        )];
        let text = encode_samples(&samples).expect("encode ok");
        // Exactly one occurrence of the name in the sample line.
        let sample_line = text
            .lines()
            .find(|l| !l.starts_with('#'))
            .expect("sample line present");
        assert!(
            sample_line.starts_with("nft_scrape_errors_total "),
            "counter sample line must carry _total suffix: {sample_line}"
        );
        assert!(
            !sample_line.contains("nft_scrape_errors_total_total"),
            "double _total suffix emitted: {sample_line}"
        );
    }

    /// `# HELP` and `# TYPE` lines must appear before the first sample line
    /// for every metric group.
    #[test]
    fn encode_samples_help_type_emission_order() {
        let samples = vec![
            MetricSample::gauge("metric_a", "Help A.", BTreeMap::new(), 1.0),
            MetricSample::gauge("metric_b", "Help B.", BTreeMap::new(), 2.0),
        ];
        let text = encode_samples(&samples).expect("encode ok");

        for name in &["metric_a", "metric_b"] {
            let help_pos = text
                .find(&format!("# HELP {name}"))
                .expect("HELP line present");
            let type_pos = text
                .find(&format!("# TYPE {name}"))
                .expect("TYPE line present");
            // First non-comment line that starts with the metric name.
            let sample_pos = text
                .lines()
                .filter(|l| l.starts_with(name))
                .find_map(|l| text.find(l))
                .expect("sample line present");
            assert!(help_pos < sample_pos, "HELP must precede sample for {name}");
            assert!(type_pos < sample_pos, "TYPE must precede sample for {name}");
        }
    }

    /// Multiple samples for the same metric name must all appear under a
    /// single `# HELP` / `# TYPE` header pair (stable group + dedup of headers),
    /// even when the input pushes them NON-consecutively (interleaved).
    #[test]
    fn encode_samples_stable_sort_and_dedup_headers() {
        let mut labels_a = BTreeMap::new();
        labels_a.insert("iface".to_owned(), "eth0".to_owned());
        let mut labels_b = BTreeMap::new();
        labels_b.insert("iface".to_owned(), "eth1".to_owned());

        // Interleave two metric names to prove grouping is by name, not order.
        let samples = vec![
            MetricSample::counter("nft_rx_total", "RX bytes total.", labels_b.clone(), 200),
            MetricSample::gauge("nft_other", "Other.", BTreeMap::new(), 9.0),
            MetricSample::counter("nft_rx_total", "RX bytes total.", labels_a.clone(), 100),
        ];
        let text = encode_samples(&samples).expect("encode ok");

        // Exactly one HELP and one TYPE header for the metric name.
        let help_count = text.matches("# HELP nft_rx_total").count();
        let type_count = text.matches("# TYPE nft_rx_total").count();
        assert_eq!(help_count, 1, "duplicate HELP headers: {text}");
        assert_eq!(type_count, 1, "duplicate TYPE headers: {text}");

        // Both sample lines present.
        assert!(
            text.contains(r#"nft_rx_total{iface="eth0"} 100"#),
            "eth0 sample missing: {text}"
        );
        assert!(
            text.contains(r#"nft_rx_total{iface="eth1"} 200"#),
            "eth1 sample missing: {text}"
        );

        // The two nft_rx_total samples must be contiguous (grouped), with the
        // interleaved nft_other not appearing between them.
        let first = text.find("nft_rx_total{").expect("first rx sample");
        let last = text.rfind("nft_rx_total{").expect("last rx sample");
        let between = &text[first..last];
        assert!(
            !between.contains("nft_other "),
            "interleaved family broke grouping: {text}"
        );
    }

    // -----------------------------------------------------------------------
    // f64 special-value rendering (Inf / NaN)
    // -----------------------------------------------------------------------

    /// `+Inf`, `-Inf`, and `NaN` must render in their Prometheus spellings,
    /// not Rust's `inf` / `-inf` / `NaN` Display defaults (`inf` is invalid).
    #[test]
    fn encode_samples_f64_inf_and_nan() {
        let samples = vec![
            MetricSample::gauge(
                "nft_pos_inf",
                "positive inf.",
                BTreeMap::new(),
                f64::INFINITY,
            ),
            MetricSample::gauge(
                "nft_neg_inf",
                "negative inf.",
                BTreeMap::new(),
                f64::NEG_INFINITY,
            ),
            MetricSample::gauge("nft_nan", "nan.", BTreeMap::new(), f64::NAN),
        ];
        let text = encode_samples(&samples).expect("encode ok");
        assert!(text.contains("nft_pos_inf +Inf"), "want +Inf: {text}");
        assert!(text.contains("nft_neg_inf -Inf"), "want -Inf: {text}");
        assert!(text.contains("nft_nan NaN"), "want NaN: {text}");
        assert!(
            !text.contains(" inf\n") && !text.contains(" -inf\n"),
            "raw Rust inf spelling leaked: {text}"
        );
    }

    // -----------------------------------------------------------------------
    // Unit tests for escape_label_value (direct function coverage)
    // -----------------------------------------------------------------------

    #[test]
    fn escape_label_value_nul_stripped() {
        assert_eq!(escape_label_value("a\x00b"), "ab");
    }

    #[test]
    fn escape_label_value_tab_stripped() {
        // TAB (0x09) is a control char < 0x20; must be stripped.
        assert_eq!(escape_label_value("a\tb"), "ab");
    }

    #[test]
    fn escape_label_value_bel_stripped() {
        assert_eq!(escape_label_value("a\x07b"), "ab");
    }

    #[test]
    fn escape_label_value_cr_stripped() {
        // CR (0x0D) must be stripped.
        assert_eq!(escape_label_value("a\rb"), "ab");
    }

    #[test]
    fn escape_label_value_printable_ascii_unchanged() {
        let s = "hello world! 123 @#$%^&*()-=+[]|;:',.<>?/`~";
        assert_eq!(escape_label_value(s), s);
    }

    #[test]
    fn escape_label_value_multibyte_unicode_unchanged() {
        // Multi-byte Unicode codepoints (>= U+0080) must pass through unchanged.
        let s = "interface: cafe/Munchen";
        assert_eq!(escape_label_value(s), s);
    }

    #[test]
    fn escape_label_value_combined() {
        // Mix of backslash, quote, newline, control chars, and plain text.
        // input:    a \ b " c \n d \x00 e \x1f e
        // expected: a \\ b \" c \n d          e      e   (controls stripped)
        let input = "a\\b\"c\nd\x00e\x1fe";
        assert_eq!(escape_label_value(input), r#"a\\b\"c\ndee"#);
    }
}
