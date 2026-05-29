//! `softirq` collector — `/proc/softirqs` (ADR-0027).
//!
//! Per-CPU `NET_RX` / `NET_TX` softirq counts. No netlink API exists for these;
//! they are the canonical measure of softirq imbalance across receive and
//! transmit paths.
//!
//! ## File format (kernel `fs/proc/softirqs.c::show_softirqs`, 6.17)
//!
//! ```text
//!                         CPU0      CPU1      CPU2      ...
//!            NET_TX:       123       456       789  ...
//!            NET_RX:      1234      5678      9012  ...
//! ```
//!
//! - **Header line**: 20 spaces of padding, then `CPU%-8d` per online CPU.
//!   The Nth token (after stripping the `CPU` prefix) gives the CPU id for
//!   the Nth count column.
//! - **Data lines**: `%12s:` right-aligned name + `:`, then one decimal value
//!   per CPU (10-wide, space-separated). Only `NET_TX` and `NET_RX` rows are
//!   parsed; all others are skipped.
//!
//! | row name | kind label | metric                  |
//! |----------|------------|-------------------------|
//! | `NET_RX` | `net_rx`   | `nft_softirq_total`     |
//! | `NET_TX` | `net_tx`   | `nft_softirq_total`     |
//!
//! Labels: `{cpu, kind}`. One series per `(cpu, kind)` pair → ~2 × `n_cpu`.

use std::collections::BTreeMap;

use nlx_domain::metric::MetricSample;
use nlx_ports::{
    collector::{BoxFuture, Collector},
    error::CollectError,
};

use crate::{readable, safe_read};

const PATH: &str = "/proc/softirqs";

/// Collector for `/proc/softirqs` (per-CPU `NET_RX` / `NET_TX` softirq counts).
pub struct SoftirqCollector;

impl Collector for SoftirqCollector {
    fn name(&self) -> &'static str {
        "softirq"
    }

    fn collect(&self) -> BoxFuture<'_, Result<Vec<MetricSample>, CollectError>> {
        Box::pin(async move {
            let text = safe_read(PATH).map_err(|e| CollectError::Io(e.to_string()))?;
            Ok(parse(&text))
        })
    }

    fn probe_available(&self) -> BoxFuture<'_, bool> {
        Box::pin(async move { readable(PATH) })
    }
}

/// Parse the full `/proc/softirqs` text into samples.
///
/// Only `NET_RX` and `NET_TX` rows are emitted. Rows with fewer count columns
/// than CPU ids are truncated defensively (extra CPUs in the header are
/// silently ignored for that row).
fn parse(text: &str) -> Vec<MetricSample> {
    let mut lines = text.lines();

    // ---- header line --------------------------------------------------------
    // Format: "                    CPU0      CPU1      ..."
    // Tokens that start with "CPU" give the id for the corresponding column.
    let Some(header_line) = lines.next() else {
        return Vec::new();
    };

    // Build a Vec<String> mapping column index → cpu-id string.
    let cpu_ids: Vec<String> = header_line
        .split_whitespace()
        .filter_map(|tok| tok.strip_prefix("CPU").map(std::borrow::ToOwned::to_owned))
        .collect();

    if cpu_ids.is_empty() {
        return Vec::new();
    }

    // ---- data rows ----------------------------------------------------------
    let mut out = Vec::new();

    for line in lines {
        // Each line: "  NAME:   val0   val1   ..."
        // Split at the first ':' to get the name and the counts string.
        let Some(colon_pos) = line.find(':') else {
            continue;
        };
        let row_name = line[..colon_pos].trim();
        let kind = match row_name {
            "NET_RX" => "net_rx",
            "NET_TX" => "net_tx",
            _ => continue,
        };

        // Parse decimal count columns after the colon.
        let counts: Vec<u64> = line[colon_pos + 1..]
            .split_whitespace()
            .map(|s| s.parse::<u64>().unwrap_or(0))
            .collect();

        // Emit one sample per CPU, stopping at the shorter of (cpu_ids, counts).
        for (cpu_id, &value) in cpu_ids.iter().zip(counts.iter()) {
            let mut labels = BTreeMap::new();
            labels.insert("cpu".to_owned(), cpu_id.clone());
            labels.insert("kind".to_owned(), kind.to_owned());
            out.push(MetricSample::counter(
                "nft_softirq_total",
                "Per-CPU softirq invocation count (NET_RX and NET_TX).",
                labels,
                value,
            ));
        }
    }

    out
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::float_cmp,
        clippy::cast_precision_loss,
        clippy::cast_lossless,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::items_after_statements,
        reason = "test"
    )]

    use super::*;
    use nlx_domain::metric::MetricKind;

    /// Realistic `/proc/softirqs` excerpt with 4 CPUs (ids 0-3).
    /// Format mirrors `show_softirqs` in `fs/proc/softirqs.c` (kernel 6.17):
    /// 20-space pad + `CPU%-8d` header; `%12s:` + 10-wide decimal columns.
    const SAMPLE: &str = concat!(
        "                    CPU0      CPU1      CPU2      CPU3\n",
        "          HI:          0         0         0         0\n",
        "       TIMER:    1234567    987654    112233    445566\n",
        "      NET_TX:       1000      2000      3000      4000\n",
        "      NET_RX:      10000     20000     30000     40000\n",
        "       BLOCK:       5555      6666      7777      8888\n",
    );

    fn find<'a>(samples: &'a [MetricSample], cpu: &str, kind: &str) -> Option<&'a MetricSample> {
        samples.iter().find(|m| {
            m.name == "nft_softirq_total"
                && m.labels.get("cpu").map(String::as_str) == Some(cpu)
                && m.labels.get("kind").map(String::as_str) == Some(kind)
        })
    }

    #[test]
    fn emits_only_net_rx_and_net_tx_rows() {
        let out = parse(SAMPLE);
        // 4 CPUs × 2 kinds = 8 samples; no HI / TIMER / BLOCK.
        assert_eq!(out.len(), 8, "expected exactly 8 samples (4 cpu × 2 kind)");
        for s in &out {
            let kind = s.labels.get("kind").map_or("", String::as_str);
            assert!(
                kind == "net_rx" || kind == "net_tx",
                "unexpected kind label: {kind}"
            );
        }
    }

    #[test]
    fn cpu_ids_come_from_header_not_line_index() {
        let out = parse(SAMPLE);
        // Header has CPU0..CPU3; verify all four ids appear.
        for cpu in ["0", "1", "2", "3"] {
            assert!(
                find(&out, cpu, "net_rx").is_some(),
                "missing net_rx sample for cpu={cpu}"
            );
        }
    }

    #[test]
    fn decodes_decimal_values_correctly() {
        let out = parse(SAMPLE);
        use nlx_domain::metric::MetricValue;
        let val = |cpu: &str, kind: &str| match find(&out, cpu, kind).unwrap().value {
            MetricValue::U64(n) => n,
            MetricValue::F64(f) => f as u64,
        };
        assert_eq!(val("0", "net_tx"), 1000);
        assert_eq!(val("1", "net_tx"), 2000);
        assert_eq!(val("2", "net_tx"), 3000);
        assert_eq!(val("3", "net_tx"), 4000);
        assert_eq!(val("0", "net_rx"), 10000);
        assert_eq!(val("3", "net_rx"), 40000);
    }

    #[test]
    fn all_samples_are_counters() {
        let out = parse(SAMPLE);
        for s in &out {
            assert_eq!(
                s.kind,
                MetricKind::Counter,
                "expected Counter for {}",
                s.name
            );
        }
    }

    #[test]
    fn short_row_truncates_defensively() {
        // Row has fewer columns than the header; the extra CPUs are skipped.
        let input = concat!(
            "                    CPU0      CPU1      CPU2      CPU3\n",
            "      NET_TX:        42        99\n", // only 2 of 4 columns
        );
        let out = parse(input);
        assert_eq!(out.len(), 2, "only 2 count columns present → 2 samples");
        assert!(find(&out, "0", "net_tx").is_some());
        assert!(find(&out, "1", "net_tx").is_some());
        assert!(find(&out, "2", "net_tx").is_none());
    }

    #[test]
    fn missing_header_yields_no_samples() {
        let out = parse("");
        assert!(out.is_empty());
    }

    #[test]
    fn header_with_no_cpu_tokens_yields_no_samples() {
        let input = "      (no cpu columns here)\n      NET_TX:   100\n";
        let out = parse(input);
        assert!(
            out.is_empty(),
            "empty cpu_ids must short-circuit to empty result"
        );
    }

    #[test]
    fn non_numeric_count_is_treated_as_zero() {
        let input = concat!("                    CPU0\n", "      NET_TX:        bad\n",);
        let out = parse(input);
        assert_eq!(out.len(), 1);
        use nlx_domain::metric::MetricValue;
        assert_eq!(out[0].value, MetricValue::U64(0));
    }

    #[test]
    fn cpu_id_parsed_correctly_for_high_numbered_cpu() {
        // E.g. CPU17 → id "17".
        let input = concat!("                    CPU17\n", "      NET_RX:      99999\n",);
        let out = parse(input);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].labels.get("cpu").map(String::as_str), Some("17"));
    }
}
