//! `softnet` collector — `/proc/net/softnet_stat` (ADR-0027).
//!
//! Per-CPU softirq receive-path health. No netlink API exists for this; it is
//! the single best signal for backlog drops and NAPI budget exhaustion.
//!
//! ## Column layout (kernel `net/core/net-procfs.c::softnet_seq_show`, 6.17)
//!
//! 15 hex columns per line, one line per online CPU:
//!
//! | idx | field                         | metric                              |
//! |-----|-------------------------------|-------------------------------------|
//! | 0   | `processed`                   | `nft_softnet_processed_total`       |
//! | 1   | `dropped`                     | `nft_softnet_dropped_total`         |
//! | 2   | `time_squeeze`                | `nft_softnet_time_squeeze_total`    |
//! | 3-8 | legacy (fastroute/collision)  | — (always 0)                        |
//! | 9   | `received_rps`                | `nft_softnet_received_rps_total`    |
//! | 10  | `flow_limit_count`            | `nft_softnet_flow_limit_count_total`|
//! | 11  | `input_qlen + process_qlen`   | `nft_softnet_backlog_length` (gauge)|
//! | 12  | **cpu id** (owning CPU)       | `cpu` label                         |
//! | 13  | `input_qlen`                  | — (covered by backlog)              |
//! | 14  | `process_qlen`                | — (covered by backlog)              |
//!
//! The CPU id is column 12, not the line index: offline CPUs are skipped, so the
//! kernel emits the owning CPU explicitly.

use std::collections::BTreeMap;

use nlx_domain::metric::MetricSample;
use nlx_ports::{
    collector::{BoxFuture, Collector},
    error::CollectError,
};

use crate::{readable, safe_read};

const PATH: &str = "/proc/net/softnet_stat";

// Column indices (see module docs).
const COL_PROCESSED: usize = 0;
const COL_DROPPED: usize = 1;
const COL_TIME_SQUEEZE: usize = 2;
const COL_RECEIVED_RPS: usize = 9;
const COL_FLOW_LIMIT: usize = 10;
const COL_BACKLOG: usize = 11;
const COL_CPU: usize = 12;
// A line must carry at least up to the CPU-id column to be usable.
const MIN_COLS: usize = COL_CPU + 1;

/// Collector for `/proc/net/softnet_stat` (per-CPU softirq receive health).
pub struct SoftnetCollector;

impl Collector for SoftnetCollector {
    fn name(&self) -> &'static str {
        "softnet"
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

/// Parse the full `softnet_stat` text into samples (one set per online CPU).
#[allow(
    clippy::cast_precision_loss,
    reason = "backlog gauge is f64; a queue length never loses meaningful precision"
)]
fn parse(text: &str) -> Vec<MetricSample> {
    let mut out = Vec::new();

    for line in text.lines() {
        // Each field is a fixed-width hex word; missing/short lines are skipped.
        let cols: Vec<u64> = line
            .split_whitespace()
            .map(|h| u64::from_str_radix(h, 16).unwrap_or(0))
            .collect();
        if cols.len() < MIN_COLS {
            continue;
        }

        let mut labels = BTreeMap::new();
        labels.insert("cpu".to_owned(), cols[COL_CPU].to_string());

        push_counter(
            &mut out,
            "nft_softnet_processed_total",
            "Packets processed in the per-CPU softirq receive path (softnet processed).",
            &labels,
            cols[COL_PROCESSED],
        );
        push_counter(
            &mut out,
            "nft_softnet_dropped_total",
            "Packets dropped because the per-CPU backlog queue was full.",
            &labels,
            cols[COL_DROPPED],
        );
        push_counter(
            &mut out,
            "nft_softnet_time_squeeze_total",
            "Times the NAPI poll loop ran out of budget/time with work remaining (time_squeeze).",
            &labels,
            cols[COL_TIME_SQUEEZE],
        );
        push_counter(
            &mut out,
            "nft_softnet_received_rps_total",
            "Times this CPU was woken to process packets steered to it via RPS.",
            &labels,
            cols[COL_RECEIVED_RPS],
        );
        push_counter(
            &mut out,
            "nft_softnet_flow_limit_count_total",
            "Packets dropped by the flow-limit mechanism (CONFIG_NET_FLOW_LIMIT).",
            &labels,
            cols[COL_FLOW_LIMIT],
        );

        out.push(MetricSample::gauge(
            "nft_softnet_backlog_length",
            "Current per-CPU backlog queue length (input + process queues).",
            labels,
            cols[COL_BACKLOG] as f64,
        ));
    }

    out
}

/// Push a counter sample, cloning the shared label set.
fn push_counter(
    out: &mut Vec<MetricSample>,
    name: &'static str,
    help: &'static str,
    labels: &BTreeMap<String, String>,
    value: u64,
) {
    out.push(MetricSample::counter(name, help, labels.clone(), value));
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::float_cmp,
        clippy::cast_precision_loss,
        clippy::cast_lossless,
        reason = "test"
    )]

    use super::*;
    use nlx_domain::metric::MetricValue;

    /// A real 15-column line (kernel 6.17). cpu id is column 12.
    const SAMPLE: &str = concat!(
        "0bce27fa 00000007 00000004 00000000 00000000 00000000 00000000 00000000 ",
        "00000000 0000000a 00000002 00000005 00000000 00000000 00000000\n",
        "089574a9 00000000 00000005 00000000 00000000 00000000 00000000 00000000 ",
        "00000000 00000000 00000000 00000000 00000001 00000000 00000000\n",
    );

    fn find<'a>(s: &'a [MetricSample], name: &str, cpu: &str) -> Option<&'a MetricSample> {
        s.iter()
            .find(|m| m.name == name && m.labels.get("cpu").map(String::as_str) == Some(cpu))
    }

    #[test]
    fn parses_cpu_id_from_column_12_not_line_index() {
        let out = parse(SAMPLE);
        // Line 0 has cpu col=0x00000000 → cpu 0; line 1 has cpu col=0x00000001 → cpu 1.
        assert!(find(&out, "nft_softnet_processed_total", "0").is_some());
        assert!(find(&out, "nft_softnet_processed_total", "1").is_some());
    }

    #[test]
    fn decodes_hex_columns_to_values() {
        let out = parse(SAMPLE);
        // cpu 0: processed=0x0bce27fa, dropped=0x07, time_squeeze=0x04,
        // received_rps=0x0a, flow_limit=0x02, backlog=0x05.
        let v = |name: &str| match find(&out, name, "0").unwrap().value {
            MetricValue::U64(n) => n as f64,
            MetricValue::F64(f) => f,
        };
        assert_eq!(v("nft_softnet_processed_total"), 0x0bce_27fa as f64);
        assert_eq!(v("nft_softnet_dropped_total"), 7.0);
        assert_eq!(v("nft_softnet_time_squeeze_total"), 4.0);
        assert_eq!(v("nft_softnet_received_rps_total"), 10.0);
        assert_eq!(v("nft_softnet_flow_limit_count_total"), 2.0);
        assert_eq!(v("nft_softnet_backlog_length"), 5.0);
    }

    #[test]
    fn backlog_is_a_gauge_others_are_counters() {
        let out = parse(SAMPLE);
        assert_eq!(
            find(&out, "nft_softnet_backlog_length", "0").unwrap().kind,
            nlx_domain::metric::MetricKind::Gauge
        );
        assert_eq!(
            find(&out, "nft_softnet_processed_total", "0").unwrap().kind,
            nlx_domain::metric::MetricKind::Counter
        );
    }

    #[test]
    fn short_lines_are_skipped_not_panicked() {
        let out = parse("dead beef\n00000001 00000002\n");
        assert!(out.is_empty(), "short lines must be skipped");
    }

    #[test]
    fn empty_input_yields_no_samples() {
        assert!(parse("").is_empty());
    }
}
