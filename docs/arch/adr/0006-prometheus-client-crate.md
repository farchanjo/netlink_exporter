---
status: accepted
date: 2026-05-28
deciders: [eonf]
consulted: []
informed: []
---

# Use prometheus-client 0.24 (OpenMetrics-native) and reject prometheus 0.14 (legacy text format)

## Context and Problem Statement

Two major Rust Prometheus client crates exist in the ecosystem: `prometheus-client` (OpenMetrics-native, maintained by the Prometheus project) and `prometheus` (legacy Prometheus text format, originally ported from the Go client). A third option is the `metrics` crate with `metrics-exporter-prometheus` facade.

The Prometheus Operator `ServiceMonitor` CRD and Prometheus >= 2.40 support the OpenMetrics content-type (`application/openmetrics-text; version=1.0.0`), which provides correct counter semantics (`_total` suffix mandatory), exemplar support, and `info` metric type. The nft_exporter uses `_total` counters throughout its metric contract and requires correct counter reset semantics.

## Considered Options

- prometheus-client 0.24 OpenMetrics-native (chosen)
- prometheus 0.14 legacy text format
- metrics + metrics-exporter-prometheus facade

## Decision Outcome

**Chosen option: prometheus-client 0.24.1.**

`prometheus-client` is used exclusively in `nft_exporter_adapter_prom` (the `PrometheusRegistryAdapter`). Domain-core crates never import it; only `MetricRegistryPort` is visible to domain code.

Key capabilities used:

- `Family<L: EncodeLabelSet, M>` for all counter and gauge families, parameterized on typed label structs derived with `#[derive(Clone, Hash, PartialEq, Eq, EncodeLabelSet)]`.
- `Counter<f64, AtomicU64>` for monotonically increasing counters (conntrack, link bytes/packets, nftables rule hits).
- `Gauge<f64, AtomicU64>` for state gauges (conntrack entries, socket counts, ethtool stats).
- `text_format::encode(&mut buf, &registry)` produces the OpenMetrics text body served on GET /metrics with `Content-Type: application/openmetrics-text; version=1.0.0; charset=utf-8`.
- `Info` metric type for `nft_build_info` and `nft_link_info` metadata gauges.

`cargo deny` rules ban both `prometheus` and `metrics-exporter-prometheus` from the workspace to prevent accidental mixing of two registry implementations in the same binary.

**Consequences:**

- Positive: Prometheus Operator `ServiceMonitor` with `honorLabels: true` correctly detects the OpenMetrics content-type and enables counter reset detection. Grafana datasource does not require workarounds for the `_total` suffix.
- Positive: `Family<L, M>` with typed label structs catches label dimension mismatches at compile time, not at runtime.
- Positive: The `prometheus-client` crate has zero unsafe code in its registry and encoding path; `cargo geiger` confirms 0 unsafe blocks in the adapter crate.
- Negative: `prometheus-client 0.24` has a different API surface than `prometheus 0.14`; community examples and StackOverflow answers often target the older crate. New contributors must read the `prometheus-client` docs specifically.
- Negative: `prometheus-client` does not yet support native histogram buckets (as of 0.24.1); if histogram metrics are needed in a future iteration, a `Histogram` wrapper must be added.

**Rejected options:**

- *prometheus 0.14 legacy text format*: Emits `# TYPE foo counter` without the mandatory `_total` suffix required by OpenMetrics. Prometheus >= 2.40 in OpenMetrics mode would reject the scrape or misclassify counter metrics. The crate is in maintenance mode with no active feature development.
- *metrics + metrics-exporter-prometheus facade*: The `metrics` crate abstracts over multiple backends but the `metrics-exporter-prometheus` backend targets the legacy `prometheus 0.14` API as of its latest release. It also does not support typed label structs; all labels are `&'static str` key-value pairs, losing compile-time label set validation.
