---
status: accepted
date: 2026-05-28
deciders: [eonf]
consulted: []
informed: []
---

# Provide include/exclude regex filtering for interface names and per-collector enable flags to manage cardinality on hosts with many virtual interfaces

## Context and Problem Statement

The probe host has 29 network interfaces visible via `RTM_GETLINK`. The majority are `veth` pairs created by container runtimes (Docker, containerd) and are ephemeral. Exporting all 29 interfaces at full metric depth produces:

- `rtnetlink` context: 29 x 12 counter/gauge families = approximately 348 rtnetlink series per scrape. Within the ADR-0005 ceiling individually.
- `ethtool` context: 59 stats per interface (standard groups: eth-mac, eth-phy, eth-ctrl, rmon) x 29 = 1,711 ethtool series. Approaches the ADR-0005 1,000-series soft ceiling for a single collector.
- TC qdisc context: cardinality grows linearly with the number of active containers in a DaemonSet scenario because each `veth` peer typically carries at least one `noqueue` or `fq_codel` qdisc entry.

`veth` interfaces also expose no meaningful ethtool hardware statistics (driver returns `EOPNOTSUPP`) and their link counters duplicate the data already available on the container-side `eth0` interface. Including them inflates cardinality without adding observability value.

In a Kubernetes node DaemonSet deployment, the number of `veth` interfaces scales with pod count. A node running 110 pods (default kubelet maximum) would produce 110 x 59 = 6,490 ethtool series, violating the ADR-0005 hard ceiling.

No existing ADR addresses interface-level cardinality control. The per-collector enable/disable mechanism described in ADR-0007 operates at the subsystem level and does not provide interface-level granularity.

## Considered Options

- **Static allowlist of interface name prefixes in config**: simple to implement but requires operator knowledge of all physical interface names; breaks in heterogeneous environments where physical NIC names vary (`eth0`, `enp3s0`, `eno1`, `bond0`).
- **Hardcoded exclusion of veth and docker bridge interfaces**: non-configurable; breaks for users who legitimately need veth metrics (e.g., monitoring container network isolation).
- **Include/exclude regex pair with sane defaults** (chosen): operators express intent as patterns; defaults exclude nothing (include all, exclude nothing) so the out-of-the-box experience is complete; operators tighten for their environment. The exclude pattern `^(veth|cali|tunl|flannel|cni)` covers the common Kubernetes CNI interface name prefixes in a single line.

## Decision Outcome

**Chosen option: include/exclude regex pair with per-collector enable flags.**

Two fields are added to `ExporterConfig`:

- `interface_include_regex` (string, default `".*"`): include all interfaces whose `IFLA_IFNAME` matches this pattern.
- `interface_exclude_regex` (string, default `""`): exclude interfaces whose `IFLA_IFNAME` matches this pattern. Empty string means no exclusions.

Both patterns are compiled to `Regex` objects at startup (using the `regex 1.11` crate) and stored in `Arc<InterfaceFilter>`. A compilation failure is a fatal startup error with a descriptive message identifying which field failed to compile.

**Evaluation semantics (applied in order):**

1. If `interface_include_regex` is set and does not match `IFLA_IFNAME`, the interface is filtered out.
2. If `interface_exclude_regex` is non-empty and matches `IFLA_IFNAME`, the interface is filtered out regardless of the include result.
3. Exclude wins when both match.

**Application points:**

- In `RtnetlinkAdapter`: immediately after `IFLA_IFNAME` decode, before any series accumulation for that interface.
- In `TcNetlinkAdapter`: after `tcm_ifindex` to interface name resolution (via the rtnetlink name table snapshot), before any TC qdisc series accumulation.
- The `EthtoolAdapter` reuses the same `Arc<InterfaceFilter>` and applies it before issuing per-interface unicast genetlink requests (`LINKSETTINGS_GET`, `PAUSE_GET`, `FEC_GET`), avoiding unnecessary round-trips to the kernel for filtered interfaces.
- `ConntrackAdapter`, `NftablesAdapter`, and `SockDiagAdapter` do not use interface-level filtering; they are unaffected.

**Observability:**

A new counter metric `nft_link_filtered_total` with label `collector` is incremented once per filtered interface per scrape. This allows operators to verify that the filter configuration is matching the expected set of interfaces and to detect configuration drift when new interface name prefixes appear.

**Per-collector enable flags:**

The existing `ExporterConfig.collectors` list from ADR-0007 is extended to explicitly enumerate the `tc` collector as a separately disableable subsystem:

```toml
[collectors]
enabled = ["rtnetlink", "conntrack", "nftables", "sockdiag", "ethtool", "tc"]
```

Disabling `tc` suppresses all `RTM_GETQDISC` dump requests and all `nft_tc_*` metric families. This is unchanged behavior for the other five collectors; the `tc` collector is newly enumerated as a named flag rather than implicitly enabled.

**Typical operator configuration for a Kubernetes node:**

```toml
interface_exclude_regex = "^(veth|cali|tunl|flannel|cni|docker|br-)"
```

On the probe host with 29 interfaces (26 veth, 1 physical, 1 loopback, 1 docker bridge), this reduces:

- rtnetlink series: 29 x 12 = 348 -> 2 x 12 = 24 (physical + loopback, excluding docker bridge as it carries no meaningful hardware data).
- ethtool series: 1,711 -> 59 (physical NIC only; loopback and docker bridge return `EOPNOTSUPP`).
- TC qdisc series: proportional reduction.

**Consequences:**

- Positive: Cardinality on the probe host drops from approximately 2,059 to approximately 83 series when the default veth exclude pattern is applied, an 96% reduction without loss of data from physical interfaces.
- Positive: The filter is configuration-driven; no code change is required when the operator adds a new CNI plugin with a new interface prefix.
- Positive: `nft_link_filtered_total` provides a feedback loop: an operator who misconfigures the exclude regex to match physical interfaces will see the counter increment and no corresponding link metrics, making the misconfiguration immediately visible.
- Positive: The `Arc<InterfaceFilter>` is shared across all adapters; the regex is compiled once at startup, not per-scrape.
- Negative: Regex compilation errors are fatal at startup. Operators with complex patterns must validate them before deployment. The startup error message includes the offending pattern and the `regex` crate error text.
- Negative: Interface name to index mapping in `TcNetlinkAdapter` requires a snapshot of the rtnetlink name table from the most recent `RTM_GETLINK` dump. If an interface appears in `RTM_GETQDISC` output but not in the name table snapshot (race condition), its name resolves to the empty string and the include regex `".*"` matches the empty string, so it passes through with label `interface=""`. This is a known edge case; the empty-label series is observable and documented in the `nft_tc_qdisc_info` help string.
