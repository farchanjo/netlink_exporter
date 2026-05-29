//! `MetricSample` — the canonical currency between collectors and the metrics
//! adapter.
//!
//! A `MetricSample` is a typed, labelled observation produced by a collector
//! and consumed by the `MetricRegistryPort` driven port.  It carries no
//! prometheus-client types; the adapter is responsible for mapping samples to
//! the registry representation.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A single labelled metric observation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricSample {
    /// Fully qualified metric name, e.g. `nft_link_rx_bytes_total`.
    pub name: &'static str,
    /// Human-readable description forwarded to the HELP line.
    pub help: &'static str,
    /// Metric kind.
    pub kind: MetricKind,
    /// Label key-value pairs, sorted for deterministic output.
    pub labels: BTreeMap<String, String>,
    /// Observed value.
    pub value: MetricValue,
}

/// Prometheus metric kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MetricKind {
    /// Monotonically increasing counter.
    Counter,
    /// Arbitrary current value.
    Gauge,
    /// Pre-aggregated histogram (sum + count + buckets).
    Histogram,
}

/// Observed value for a metric sample.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MetricValue {
    /// 64-bit unsigned integer (counters, most kernel stats).
    U64(u64),
    /// 64-bit float (latencies, ratios).
    F64(f64),
}

impl MetricSample {
    /// Construct a counter sample.
    #[must_use]
    pub fn counter(
        name: &'static str,
        help: &'static str,
        labels: BTreeMap<String, String>,
        value: u64,
    ) -> Self {
        Self {
            name,
            help,
            kind: MetricKind::Counter,
            labels,
            value: MetricValue::U64(value),
        }
    }

    /// Construct a gauge sample.
    #[must_use]
    pub fn gauge(
        name: &'static str,
        help: &'static str,
        labels: BTreeMap<String, String>,
        value: f64,
    ) -> Self {
        Self {
            name,
            help,
            kind: MetricKind::Gauge,
            labels,
            value: MetricValue::F64(value),
        }
    }
}
