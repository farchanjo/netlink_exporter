---
status: accepted
date: 2026-05-28
deciders: [eonf]
consulted: []
informed: []
---

# Enforce bounded cardinality on every metric family by aggregating at collection time and forbidding per-flow/per-route/per-socket label dimensions

## Context and Problem Statement

The nft_exporter runs as a DaemonSet on every node. A busy node can have hundreds of thousands of active conntrack entries, tens of thousands of routing table prefixes, and thousands of open sockets. If any metric family emits one time series per kernel entity, Prometheus cardinality explodes, TSDB head block memory consumption on the Prometheus server grows proportionally with node count, and scrape latency can exceed the configured scrape timeout.

The team needs a design-time rule, enforced in both the CUE schema and the Rego policy, that caps the total number of time series the exporter can emit per node at a hard ceiling, regardless of workload characteristics.

## Considered Options

- Aggregate-only model with bounded label sets (chosen)
- Per-flow/per-route emission with Prometheus recording rules for aggregation
- Dynamic label allow-listing via config file

## Decision Outcome

**Chosen option: aggregate-only model with bounded label sets.**

No metric family may carry per-connection, per-route-prefix, per-socket-inode, or per-MAC-address label values. Aggregation happens inside the collector at collection time, before any data reaches `MetricRegistryPort`:

- **Conntrack**: `ConntrackAggregator` groups `ConntrackFlow` entries by `(protocol, state, direction)` and sums byte/packet counters. Maximum cardinality: ~40 series (`|protocol|~8 × |state|~5`).
- **Routes**: aggregated by `(table, family, protocol, route_type)`. No destination prefix label. Maximum cardinality: ~480 series.
- **Neighbors**: aggregated by `(interface, family, state)`. No IP or MAC label. Maximum cardinality: ~3072 series.
- **Sockets**: aggregated by `(protocol, state)`. No port or inode label. Maximum cardinality: ~24 series.
- **nftables rules**: only rules with a non-empty `comment` expression are exported; anonymous rules are suppressed and counted in `nft_scrape_collector_error_total{reason=cardinality_overflow}` once the anonymous-rule count exceeds 500.

Overall ceiling: 50,000 series per node. When any metric family would exceed its declared bound (defined in `docs/arch/schemas/metric_contract.cue`), the collector suppresses the offending family for that scrape and increments `nft_scrape_collector_error_total{collector, reason=cardinality_overflow}`.

The Rego policy `nft_exporter.metric.cardinality` runs in CI against the CUE-encoded metric contract and rejects any new metric definition that adds an unbounded label dimension.

**Consequences:**

- Positive: Prometheus server TSDB head block memory is bounded at a predictable ceiling regardless of workload. A 500-node cluster emitting 50,000 series each produces 25 million active series, within Prometheus 2.40+ operational range with adequate memory.
- Positive: Scrape latency is bounded because OpenMetrics text encoding of a fixed series count is O(1) in workload size.
- Positive: The cardinality overflow counter gives operators a signal when the configured ruleset or traffic pattern is approaching the ceiling without silently dropping data.
- Negative: Aggregation hides individual flow or route detail. Operators who need per-flow visibility must use conntrack CLI tools or a dedicated flow exporter (e.g., `goflow2`) rather than this exporter.
- Negative: The comment-based nftables rule export means rules without comments are invisible. Operators must annotate production rulesets with `comment "..."` expressions to get per-rule counters.

**Rejected options:**

- *Per-flow/per-route emission with recording rules*: Shifts the cardinality problem to the Prometheus server. On a high-traffic node with 500k conntrack entries, the scrape response would be hundreds of megabytes per scrape interval, exceeding default `scrape_timeout` values and causing Prometheus storage pressure. Recording rules also require operator configuration outside the exporter.
- *Dynamic label allow-listing via config file*: Adds configuration surface area and creates a path for operators to accidentally re-enable unbounded cardinality dimensions. The invariant "no per-flow label" must be unconditional, not optional.
