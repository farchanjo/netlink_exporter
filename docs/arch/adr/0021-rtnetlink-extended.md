---
status: accepted
date: 2026-05-28
deciders: [eonf]
consulted: []
informed: []
---

# Add rtnetlink-extended bounded context for per-interface xstats, bridge FDB entry count, fib policy-rule count, and nexthop-object count

## Context and Problem Statement

The existing `rtnetlink` bounded context (ADR-0011, section 4 of
`docs/arch/domain/netlink-protocol.md`) collects `rtnl_link_stats64` via
`IFLA_STATS64` (RTM_GETLINK) and aggregated route and neighbor counts.
Four kernel subsystem surfaces remain unobserved:

1. **Extended per-interface link statistics** — the kernel exposes
   `RTM_GETSTATS` (nlmsg_type 94) with `IFLA_STATS_LINK_64` (a full
   `rtnl_link_stats64` read, same wire layout as `IFLA_STATS64`),
   `IFLA_STATS_LINK_XSTATS` (driver-specific bridge and bond stats embedded as a
   nested `link_xstats_type` attribute), and
   `IFLA_STATS_LINK_OFFLOAD_XSTATS` (hardware-offload counters added by
   switchdev/tc-offload drivers). These attributes are not present in ordinary
   RTM_GETLINK replies and require a separate RTM_GETSTATS dump. The kernel
   probe host carries a bridge (`br0`); the xstats payload for bridge interfaces
   carries `BRIDGE_XSTATS_VLAN` and `BRIDGE_XSTATS_MCAST` sub-attributes,
   exposing per-interface multicast and flooding counters unavailable via
   IFLA_STATS64.

2. **Bridge FDB entry count** — issuing `RTM_GETNEIGH` with
   `ndmsg.ndm_family = AF_BRIDGE (7)` returns all bridge forwarding-database
   entries. The existing neighbor collector explicitly skips `ndm_family=7`
   (ADR-0011 gotcha G-21, section 4.6 of netlink-protocol.md) to avoid
   cardinality from per-MAC series. A bounded count of total FDB entries per
   bridge interface satisfies the observability need without violating ADR-0005.
   Probe ground truth: the test host had 150 FDB entries during the probe run.

3. **FIB policy-rule count** — `RTM_GETRULE` (nlmsg_type 82) dumps the Linux
   fib policy-routing rule table. The count per address family is a bounded
   gauge (typically < 20 rules on any well-configured host) and provides
   visibility into asymmetric routing configurations (e.g., VRF rules, source
   routing, DSCP-based forwarding).

4. **Nexthop object count** — `RTM_GETNEXTHOP` (nlmsg_type 118) dumps the
   kernel nexthop object table, a feature added in Linux 5.3 for next-hop
   groups used by BGP and ECMP. The count (bounded to operator-controlled group
   configurations, typically < 1 000) exposes FIB group state without per-route
   prefix cardinality.

None of these four surfaces are collected by the existing `rtnetlink` collector.
Adding them to the existing collector would expand its scope, complicate its
ReadModel, and violate the single-responsibility principle. An independent
bounded context is the correct partitioning.

A `procfs` fallback (reading `/proc/net/fib_rules`) was considered but ruled out
on the same basis as ADR-0011: the test host's procfs paths may be incomplete
in containerised environments, and the netlink wire provides richer structured
data with machine-readable attribute encoding.

## Considered Options

- **Skip these surfaces**: no implementation. Operators who need extended xstats,
  FDB cardinality, FIB rule visibility, or nexthop tracking would have no signal.
  This is the lowest-effort option but leaves observable kernel state dark.

- **Extend existing `rtnetlink` bounded context**: add RTM_GETSTATS, FDB
  RTM_GETNEIGH, RTM_GETRULE, and RTM_GETNEXTHOP to `RtnetlinkCollector`. The
  single NETLINK_ROUTE socket is shared. However, the ReadModel would become a
  heterogeneous aggregate spanning four distinct kernel message types, each with
  its own fixed header and attribute catalogue. The existing `link_snapshot.cue`
  and `route_table_snapshot.cue` schemas do not accommodate this data.

- **Add via procfs**: read `/proc/net/fib_rules` for rule count and
  `/sys/class/net/<iface>/brforward` for FDB entries. Procfs is incomplete in
  containerised environments (`/proc/net/fib_rules` requires a network namespace
  that matches the collecting process). The xstats and nexthop surfaces have no
  procfs equivalent. This option is a partial solution only.

- **Direct netlink via new `rtnetlink-extended` bounded context** (chosen):
  implement a separate `RtnetlinkExtendedCollector` (Concrete Strategy) backed
  by a new `RtnetlinkExtendedAdapter` implementing
  `NetlinkRtnetlinkExtendedPort` (driven port). Reuse the shared NETLINK_ROUTE
  socket from `nft_exporter_netlink_socket`. Runtime-gate the collector by
  checking for `RTM_GETSTATS` kernel availability at startup (`ENOTSUP` or
  `EINVAL` on kernels < 4.20 that do not implement `RTM_GETSTATS`);
  `nft_scrape_collector_available{collector="rtnetlink-extended"}` emits 0 when
  the gate test fails.

## Decision Outcome

**Chosen option: direct netlink via new `rtnetlink-extended` bounded context.**

A new bounded context `rtnetlink-extended` is added to the nft_exporter
architecture. It reuses the same NETLINK_ROUTE (family=0) socket protocol and
wire framing conventions established in ADR-0011 and documented in
`netlink-protocol.md` section 4.

**Wire messages issued per scrape (in order):**

1. `RTM_GETSTATS (94)` with `nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP (0x0301)`
   and body `if_stats_msg { ifindex=0, filter_mask=IFLA_STATS_LINK_64 |
   IFLA_STATS_LINK_XSTATS | IFLA_STATS_LINK_OFFLOAD_XSTATS }`.
   Responses carry `RTM_NEWSTATS (93)` frames.

2. `RTM_GETNEIGH (30)` with `ndmsg.ndm_family = AF_BRIDGE (7)`.
   Counts entries per `ndm_ifindex`; emits `nft_bridge_fdb_entries`.

3. `RTM_GETRULE (82)` with `rtmsg.rtm_family` set to each of `AF_INET (2)`,
   `AF_INET6 (10)`, `AF_MPLS (28)` in separate requests.
   Counts rules per family; emits `nft_fib_rules`.

4. `RTM_GETNEXTHOP (118)` with `nhmsg.nh_family = AF_UNSPEC (0)`.
   Counts total nexthop objects; emits `nft_nexthop_objects`.
   Runtime-gated: EINVAL on kernel < 5.3 sets the metric to 0 without error.

**New metric families:**

| Metric | Type | Labels | Cardinality bound |
|---|---|---|---|
| `nft_link_xstats_bridge_rx_multicast_bytes_total` | counter | `interface` | ~512 |
| `nft_link_xstats_bridge_tx_multicast_bytes_total` | counter | `interface` | ~512 |
| `nft_link_xstats_offload_rx_bytes_total` | counter | `interface` | ~512 |
| `nft_link_xstats_offload_tx_bytes_total` | counter | `interface` | ~512 |
| `nft_bridge_fdb_entries` | gauge | `interface` | ~32 one per bridge device |
| `nft_fib_rules` | gauge | `family` | ~3 (inet, inet6, mpls) |
| `nft_nexthop_objects` | gauge | [] | 1 |

All metrics use the `nft_` prefix, snake_case naming, `_total` suffix for
counters, and base SI units (bytes). No per-MAC, per-rule, or per-prefix labels
are emitted; cardinality is strictly bounded by hardware topology and operator
configuration.

**Runtime availability gate:**

At startup, `RtnetlinkExtendedAdapter` sends a probe `RTM_GETSTATS` request with
`ifindex=1` (loopback). If the kernel returns `EINVAL` or `ENOTSUP`, the
collector is marked unavailable:

```
nft_scrape_collector_available{collector="rtnetlink-extended"} = 0
```

On kernels >= 4.20 that support `RTM_GETSTATS`, the value is 1. The
`nft_nexthop_objects` metric is separately gated on kernel >= 5.3 via a
`RTM_GETNEXTHOP` probe; it emits 0 rather than an error when nexthop objects
are unsupported.

**Configuration:**

The new collector is added to `ExporterConfig.collectors` as the string
`"rtnetlink_extended"`. It is disabled by default in the shipped configuration
(`collectors` list does not include it by default) and must be explicitly enabled
by operators who require it. This matches the opt-in pattern established for
`ethtool` in ADR-0008.

**Consequences:**

- Positive: Four previously dark kernel surfaces are observable without changes
  to the existing `rtnetlink` collector or its ReadModels.
- Positive: The runtime availability gate prevents spurious errors on kernels
  that predate `RTM_GETSTATS` (< 4.20) or nexthop objects (< 5.3), making the
  exporter binary portable across a wider kernel range.
- Positive: Cardinality remains bounded; all labels are derived from interface
  name, address family, or fixed enumeration — not from per-flow or per-rule
  identifiers.
- Positive: The new adapter crate (`nft_exporter_adapter_rt_extended`) follows
  the same `rustix + linux-raw-sys + zerocopy + bytemuck + byteorder` stack as
  the existing adapters (ADR-0011); no new infrastructure crates are introduced.
- Negative: A fifth RTM_GET* dump request is added to each scrape on nodes where
  the collector is enabled. On hosts with many bridge interfaces this increases
  the RTM_GETSTATS response volume. The 4 MiB SO_RCVBUF established by ADR-0011
  is sufficient for hosts with up to ~512 interfaces.
- Negative: `if_stats_msg` is a newer fixed header (added alongside RTM_GETSTATS
  in kernel 4.20). Its wire layout must be manually maintained in
  `netlink-protocol.md` section 4 as it is not exposed in earlier `linux-raw-sys`
  versions.
