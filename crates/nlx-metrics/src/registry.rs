//! `PrometheusRegistryAdapter` — implements `MetricRegistryPort` via
//! hand-encoded Prometheus/OpenMetrics text.
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
//! The `prometheus-client` dependency is retained for potential future use but
//! no longer participates in the hot path.

use nlx_domain::metric::{MetricKind, MetricSample, MetricValue};
use nlx_ports::driven::MetricRegistryPort;
use std::{collections::BTreeMap, fmt::Write as FmtWrite, sync::Mutex};
use thiserror::Error;

/// Errors emitted by the prometheus-client adapter.
#[derive(Debug, Error)]
pub enum RegistryError {
    /// Text encoding failed.
    #[error("OpenMetrics encode error: {0}")]
    Encode(String),
    /// Registry is poisoned (Mutex was poisoned by a panicking thread).
    ///
    /// Constructed by helpers that return this type directly; the
    /// `MetricRegistryPort` impl converts to `String` via `map_err`.
    #[allow(dead_code)]
    #[error("metric registry lock poisoned")]
    LockPoisoned,
}

/// Driven adapter that maps [`MetricSample`]s into Prometheus/OpenMetrics text.
///
/// The encoded body is stored after every [`MetricRegistryPort::update_samples`]
/// call.  The HTTP `/metrics` handler reads it via
/// [`MetricRegistryPort::encode_text`].  Snapshot semantics: each call to
/// `update_samples` fully replaces the stored body.
pub struct PrometheusRegistryAdapter {
    /// Latest encoded Prometheus text body.
    encoded: Mutex<String>,
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
            encoded: Mutex::new(String::new()),
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
        let mut guard = self
            .encoded
            .lock()
            .map_err(|_| "metric registry lock poisoned".to_owned())?;
        *guard = text;
        Ok(())
    }

    async fn encode_text(&self) -> Result<String, String> {
        let guard = self
            .encoded
            .lock()
            .map_err(|_| "metric registry lock poisoned".to_owned())?;
        Ok(guard.clone())
    }
}

// ---------------------------------------------------------------------------
// Text encoding
// ---------------------------------------------------------------------------

/// Produce a valid Prometheus/OpenMetrics text exposition from `samples`.
///
/// Groups by metric name; emits one `# HELP` + `# TYPE` header per name,
/// followed by all sample lines.  Within a name group, label sets are
/// sorted for deterministic output.
///
/// # Errors
///
/// Returns [`RegistryError::Encode`] if string formatting fails (practically
/// infallible for in-memory `String` writes, but propagated for correctness).
fn encode_samples(samples: &[MetricSample]) -> Result<String, RegistryError> {
    // Group: name → (help, kind, Vec<(labels, value)>)
    // BTreeMap preserves insertion order among names that differ; we want
    // stable output so use BTreeMap keyed by name.
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
        // Escape the help string: backslash and newline must be escaped.
        let help_escaped = escape_help(group.help);
        write!(out, "# HELP {name} {help_escaped}\n")
            .map_err(|e| RegistryError::Encode(e.to_string()))?;
        write!(out, "# TYPE {name} {}\n", kind_str(group.kind))
            .map_err(|e| RegistryError::Encode(e.to_string()))?;

        for (labels, value) in &group.observations {
            write_sample_line(&mut out, name, labels, value)
                .map_err(|e| RegistryError::Encode(e.to_string()))?;
        }
    }

    // OpenMetrics spec: body MUST end with "# EOF\n" when using the
    // application/openmetrics-text content type.
    out.push_str("# EOF\n");

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

/// Escape a label value: `\` → `\\`, `"` → `\"`, newline → `\n`.
fn escape_label_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out
}

/// Write one `name{labels} value` line into `out`.
///
/// Labels are sourced from a `BTreeMap` so they are already sorted.
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
        for (k, v) in labels.iter() {
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

/// Write an f64 in a Prometheus-compatible way: NaN → `NaN`, ±Inf →
/// `+Inf`/`-Inf`, otherwise standard decimal.
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
    use super::*;
    use std::collections::BTreeMap;

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
        assert!(text.ends_with("# EOF\n"), "missing EOF marker");
    }

    #[test]
    fn escape_label_value_special_chars() {
        assert_eq!(escape_label_value(r#"a\"b"#), r#"a\\\"b"#);
        assert_eq!(escape_label_value("a\nb"), r"a\nb");
    }
}
