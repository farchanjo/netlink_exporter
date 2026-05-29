---
status: accepted
date: 2026-05-28
deciders: [eonf]
consulted: []
informed: []
---

# Gate each collector on subsystem availability at scrape time and emit availability series instead of erroring

## Context and Problem Statement

The probe host does not load all kernel subsystems that `nft_exporter` can
collect from. Specifically, at the time of this decision the following
collectors reference subsystems that may be absent:

- **WireGuard collector**: `wireguard` kernel module not loaded; the genetlink
  family `wireguard` is absent from `CTRL_CMD_GETFAMILY` replies.
- **Devlink collector**: `CONFIG_NET_DEVLINK` is not compiled into the running
  kernel; the genetlink family `devlink` is absent.
- **ip_vs collector**: the `ip_vs` kernel module is not loaded; the
  `PROC_NET_IP_VS_STATS` procfs path does not exist.
- **Drop monitor collector**: the `NET_DM` genetlink family is absent on the
  probe host.

Without an availability gate, each of these collectors fails at the first
scrape with a `CollectorError::NetlinkFamilyNotFound` or an `io::Error`
(procfs path absent). Under the stale-snapshot fallback policy (ADR-0007),
a first-scrape failure produces no snapshot at all for that collector; the
metric families disappear from the scrape response entirely, which Prometheus
treats as a stale series and eventually expires. The operator has no signal
distinguishing "subsystem absent" from "subsystem broken".

A host where wireguard, devlink, ip_vs, and drop_monitor are not loaded is a
valid and common deployment target. The scrape must succeed and must provide
explicit availability signals so operators can suppress alerting for absent
subsystems without modifying the exporter configuration.

An additional concern: genetlink family resolution via `CTRL_CMD_GETFAMILY` is
itself a netlink round-trip that can fail transiently. The availability check
must distinguish permanent absence (family never registered) from transient
error (netlink socket temporarily unavailable).

## Considered Options

- **Fatal startup error if any enabled collector's subsystem is absent**: the
  binary exits at startup if any enabled collector cannot probe its subsystem.
  Operators must explicitly disable absent collectors in config before starting
  the exporter.
- **Silent omission**: if a collector's subsystem is absent, the collector is
  silently excluded from the scrape; no metric is emitted to indicate the
  omission.
- **Availability probe at scrape time with explicit availability metric**
  (chosen): every collector probes subsystem availability at the start of each
  scrape. If unavailable, the collector emits
  `nft_scrape_collector_available{collector="<name>"}=0` and zero series for
  its metric families. The scrape returns HTTP 200 with all available-collector
  data intact. Permanently absent subsystems produce a stable
  `...available=0` series that operators can use in alerting rules.

## Decision Outcome

**Chosen option: availability probe at scrape time with explicit availability metric.**

### Availability probe contract

Every `Collector` implementation must call its availability probe at the top of
`async fn collect()` before issuing any dump request. The probe is a single
netlink round-trip; it must not cache results across scrapes so that subsystem
load events (e.g., `modprobe wireguard`) are reflected in the next scrape
without a restart.

**Probe methods by subsystem type:**

| Subsystem type | Probe method |
|---|---|
| Generic netlink (genetlink) family | `CTRL_CMD_GETFAMILY` unicast with the family name; `ENOENT` response = absent; success = available |
| Kernel module via procfs sentinel | `stat(2)` on the canonical procfs path (e.g., `/proc/net/ip_vs_stats`); `ENOENT` = absent; `EACCES` = permission error (treat as available, error separately) |
| Module via sysfs sentinel | `stat(2)` on the sysfs device directory; `ENOENT` = absent |

The probe is a read-only kernel query. It does not modify kernel state.

### Availability metric

A new gauge metric family is introduced:

```
nft_scrape_collector_available{collector="<name>"} <0|1>
```

- Value `1`: the subsystem was reachable at scrape time; the collector's metric
  families are present in the response.
- Value `0`: the subsystem was not reachable at scrape time; all metric families
  for this collector emit zero samples. The collector name appears in the
  `collector` label with the same value used in the `enabled` list in
  `ExporterConfig`.

**Prometheus naming conventions (ADR-0005, snake_case, nft_ prefix, base units):**

- Family name: `nft_scrape_collector_available`
- Label: `collector` with values from the fixed set
  `{rtnetlink, conntrack, nftables, sockdiag, ethtool, tc, wireguard, devlink,
  ip_vs, drop_monitor}`. This set is bounded and enumerable; it does not grow
  with workload.
- Type: `gauge` (not a counter; the value can flip between 0 and 1 when the
  module is loaded or unloaded between scrapes).

The existing `nft_scrape_collector_success{collector}` gauge (ADR-0007)
continues to reflect whether the collector completed without error. The two
metrics carry distinct semantics:

| Metric | Value `0` means |
|---|---|
| `nft_scrape_collector_available` | subsystem absent from kernel at scrape time |
| `nft_scrape_collector_success` | subsystem present but collection failed (error, timeout, panic) |

Both may be `0` simultaneously; `available=0` takes logical precedence (the
collector short-circuits before any dump).

### Scrape-success invariant

A scrape is considered successful (HTTP 200, `nft_up=1`) if and only if all
collectors that have `available=1` complete without error. Collectors with
`available=0` do not affect `nft_up`. This preserves the invariant that
`nft_up=0` always signals a real collection failure, not the mere absence of an
optional kernel subsystem.

### Collector interface extension

The `Collector` port trait gains an associated probe step. Because port traits
are runtime-agnostic (ADR-0014), the probe is expressed as an `async fn`:

```rust
/// Called once per scrape before `collect()`.
/// Returns `Ok(true)` if the subsystem is available, `Ok(false)` if absent,
/// `Err(CollectorError)` on transient netlink errors.
async fn probe_availability(&self) -> Result<bool, CollectorError>;
```

`ScrapeLifecycle::collect_all` calls `probe_availability()` for each collector
before spawning the `collect()` future into the `JoinSet`. If
`probe_availability()` returns `Ok(false)`, the collector is not spawned; the
`ScrapeLifecycle` directly emits `nft_scrape_collector_available{collector}=0`
and zero series for all metric families declared by that collector.

A `CollectorError::Transient` returned by `probe_availability()` is treated as
`available=1` with an immediate pass-through to `collect()`, which will then
fail on the first real request and activate the stale-snapshot fallback. This
distinguishes "the socket is temporarily unresponsive" from "the family is
permanently absent".

### Consequences

- Positive: The scrape always returns HTTP 200 on a host where optional
  subsystems are absent. Prometheus alerting rules can condition on
  `nft_scrape_collector_available` rather than on series disappearance, which
  avoids false alerts during planned module changes.
- Positive: `modprobe wireguard` followed by the next scrape automatically
  transitions `nft_scrape_collector_available{collector="wireguard"}` from `0`
  to `1` without a restart.
- Positive: The availability probe adds at most one genetlink
  `CTRL_CMD_GETFAMILY` or one `stat(2)` call per enabled collector per scrape.
  On a host where all collectors are available, the probe round-trips complete
  in microseconds and are dominated by the subsequent dump latency.
- Negative: On hosts where several optional collectors are absent, every scrape
  pays the probe cost for each absent collector. For `CTRL_CMD_GETFAMILY` the
  kernel responds with `ENOENT` immediately; the overhead is negligible.
- Negative: The `probe_availability()` method increases the surface of the
  `Collector` port trait. All existing collector implementations must be updated
  to add the method. Implementations that currently have no meaningful
  availability check return `Ok(true)` unconditionally.
