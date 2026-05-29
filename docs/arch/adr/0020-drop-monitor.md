---
status: superseded
date: 2026-05-28
deciders: [eonf]
consulted: []
informed: []
---

# Add drop-monitor bounded context via direct generic-netlink NET_DM family with runtime gating

> **Superseded by [ADR-0026](0026-drop-monitor-hybrid-multicast-accumulator.md).**
> This ADR's per-reason `NET_DM_ATTR_REASON` summary-mode design does not match
> kernel reality: SUMMARY mode delivers per-*location* counts (no reason string;
> reasons exist only in PACKET mode), and `NET_DM_CMD_STATS_GET` returns the
> monitor's overflow counter, not drop totals. ADR-0026 documents the
> as-implemented hybrid model (multicast accumulator for real totals + an
> honestly-named overflow-pull health metric), verified live on a kernel with
> `CONFIG_NET_DROP_MONITOR=y`.

## Context and Problem Statement

The Linux kernel's drop_monitor subsystem (generic-netlink family NET_DM,
multicast group NET_DM_GRP_ALERT) exposes software and hardware packet-drop
events attributed to named drop reasons (NET_DM_ATTR_REASON). These reason
strings are stable across kernel versions and map to entries in the kernel's
drop-reason enum (include/net/dropreason.h, introduced in 5.19 and extended in
6.x). The data is read-mostly — it is produced by the kernel independently of
any dump request once monitoring is activated with NET_DM_CMD_MONITOR_START.

No existing collector in nft_exporter observes drop_monitor data. The existing
conntrack collector emits nft_conntrack_drop_total (per-CPU nf_conntrack_stat
drop field), which counts tracked-connection drops only; it does not capture
generic kernel soft-drop or hardware-drop events surfaced by drop_monitor.

Without this information, operators have no Prometheus signal for:

- SKB soft-drop events attributed to a specific kernel subsystem (e.g.
  "NET_DM_REASON_TC_INGRESS", "NET_DM_REASON_CONNTRACK", "NET_DM_REASON_GRE")
  that are outside the conntrack fast path.
- Hardware port drop events from NICs that support NET_DM hardware reporting
  (mlx5, bnxt, hns3, netdevsim).

The drop_monitor module (net/core/drop_monitor.c) may or may not be loaded on
a given host. The NET_DM genetlink family does not exist when the module is
absent; CTRL_CMD_GETFAMILY returns ENOENT. The collector must gate on the
family-resolution result and report availability via
nft_scrape_collector_available{collector="drop-monitor"} rather than failing
the scrape.

Enabling per-packet event delivery at high drop rates would produce unbounded
event cardinality. Only summary-mode counters aggregated by drop reason are
collected; per-packet event records are never stored or emitted.

**Operator note:** After the exporter starts and the family is resolved, the
collector issues NET_DM_CMD_MONITOR_START to activate the kernel's summary-mode
accounting. This does NOT enable per-packet hardware tracing; it only enables
the kernel's internal drop-reason counters. Hardware-level drop monitoring for
supported NICs requires additional kernel configuration outside nft_exporter
(e.g. devlink health reporters). Operators should verify that activating
drop_monitor summary mode is acceptable in their environment before enabling
this collector.

## Considered Options

- **Skip**: do not add a drop-monitor collector. Operators remain without a
  Prometheus signal for per-reason kernel packet drops beyond what conntrack
  exposes.
- **procfs-based drop counting**: read /sys or /proc paths for drop_monitor
  state. No stable procfs interface exists for per-reason drop counts; the
  kernel exposes drop_monitor data only via the NET_DM genetlink family.
- **Direct generic-netlink NET_DM family** (chosen): resolve the NET_DM
  genetlink family via CTRL_CMD_GETFAMILY, gate on ENOENT when the
  drop_monitor module is absent, issue NET_DM_CMD_CONFIG to select summary
  mode, issue NET_DM_CMD_MONITOR_START, and consume NET_DM_CMD_ALERT multicast
  notifications aggregating counters by NET_DM_ATTR_REASON string. No
  per-packet event storage.

## Decision Outcome

**Chosen option: direct generic-netlink NET_DM family, runtime-gated.**

A new bounded context "drop-monitor" is added alongside the six existing
bounded contexts. It follows the same hexagonal pattern: one DrivenPort
(NetlinkDropMonitorPort), one Collector strategy (DropMonitorCollector), and
one driven adapter (DropMonitorAdapter).

**Family resolution and runtime gating:**

The DropMonitorAdapter resolves the NET_DM genetlink family ID by sending
CTRL_CMD_GETFAMILY to GENL_ID_CTRL (16) with
CTRL_ATTR_FAMILY_NAME = "NET_DM\0". The resolved family ID is cached in an
OnceLock<u16> on the adapter. If CTRL_CMD_GETFAMILY returns ENOENT, the
adapter sets a boolean `module_absent` flag; all subsequent collect() calls
return immediately with an empty DropMonitorSnapshot and emit:

```
nft_scrape_collector_available{collector="drop-monitor"} 0
```

When the family is resolved successfully, the adapter emits:

```
nft_scrape_collector_available{collector="drop-monitor"} 1
```

**Mode: summary only.**

The adapter issues NET_DM_CMD_CONFIG with attribute
NET_DM_ATTR_MONITOR_STATUS = NET_DM_ATTR_MONITOR_STATUS_SUMMARY. This
instructs the kernel to aggregate drop events by reason before emitting
notifications, rather than delivering one notification per dropped packet.
Summary mode is the only supported mode; per-packet event mode (alert mode) is
explicitly unsupported by this collector because it would produce unbounded
event throughput.

**Multicast subscription:**

After NET_DM_CMD_MONITOR_START succeeds, the adapter subscribes to the
NET_DM_GRP_ALERT multicast group by calling bind() with nl_groups set to the
bitmask for that group. Incoming NET_DM_CMD_ALERT frames carry nested
attributes including NET_DM_ATTR_REASON (NUL-terminated string) and
NET_DM_ATTR_NUM_DROPPED (u64 native-endian), plus an optional
NET_DM_ATTR_HW_TRAP_NAME for hardware drops.

**Aggregation:**

The adapter maintains an in-memory HashMap<DropReasonKey, u64> that accumulates
NET_DM_ATTR_NUM_DROPPED across all received NET_DM_CMD_ALERT frames within a
scrape interval. On each collect() call the map is drained into a
DropMonitorSnapshot and reset. This produces monotonically increasing counters
exposed as nft_drop_packets_total{reason, origin}.

**Label design:**

- `reason`: the NET_DM_ATTR_REASON string (software drop) or
  NET_DM_ATTR_HW_TRAP_NAME string (hardware drop). Bounded by the kernel's
  drop-reason enum; approximately 60-80 distinct software reason strings plus a
  small number of NIC-specific hardware trap names.
- `origin`: "sw" for software drops, "hw" for hardware drops.

Both labels are bounded in cardinality (kernel enum + driver-specific hardware
trap names; not per-flow, not per-packet, not per-address).

**Kernel minimum version:**

NET_DM summary mode with NET_DM_ATTR_REASON string attributes requires kernel
>= 5.17 (drop-reason enum added; prior kernels used a raw integer location).
When the kernel module is present but the reason attribute is absent (kernel
< 5.17), the adapter logs a single tracing::warn span and emits no
nft_drop_packets_total series.

**Collector enable flag:**

The ExporterConfig.collectors list from ADR-0013 is extended with a
"drop-monitor" entry:

```toml
[collectors]
enabled = ["rtnetlink", "conntrack", "nftables", "sockdiag", "ethtool", "tc", "drop-monitor"]
```

The collector is opt-in: it is not present in the default enabled list because
activating NET_DM_CMD_MONITOR_START has a side effect (enables kernel drop
accounting overhead). Operators who want the metrics must explicitly add
"drop-monitor" to the enabled list.

**Consequences:**

- Positive: operators gain per-reason packet-drop counters attributable to
  specific kernel subsystems, filling a gap not covered by conntrack or ethtool
  metrics.
- Positive: runtime gating via CTRL_CMD_GETFAMILY ENOENT means hosts without
  the drop_monitor module loaded experience no errors, only
  nft_scrape_collector_available{collector="drop-monitor"}=0.
- Positive: summary mode prevents per-packet event flood; cardinality is
  bounded by the kernel drop-reason enum (~60-80 strings).
- Positive: follows ADR-0011 (direct netlink wire protocol); no new crate
  dependency beyond the five already used (rustix, linux-raw-sys, zerocopy,
  bytemuck, byteorder).
- Negative: activating NET_DM_CMD_MONITOR_START introduces a small per-drop
  kernel accounting overhead. Hosts under severe packet-drop load may see
  measurable CPU impact. Operators must opt in explicitly.
- Negative: hardware drop events (NET_DM_ATTR_HW_TRAP_NAME) depend on NIC
  driver support; most drivers do not implement hardware drop reporting. No
  error is raised when hardware trap names are absent.
- Negative: kernel < 5.17 with drop_monitor module loaded will have the family
  resolved but no NET_DM_ATTR_REASON strings; the adapter emits
  nft_scrape_collector_available=1 but zero nft_drop_packets_total series and
  one tracing::warn event per scrape.
