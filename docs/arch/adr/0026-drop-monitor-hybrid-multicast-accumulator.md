---
status: accepted
date: 2026-05-29
deciders: [eonf]
consulted: []
informed: []
---

# Drop-monitor: hybrid multicast accumulator (real totals) plus overflow-pull health

Refines and supersedes ADR-0020 (drop-monitor collector). Builds on ADR-0023
(monoio io_uring runtime, lock-free), ADR-0024 (netlink io_uring SEND/RECV) and
ADR-0025 (native-API only).

## Context and Problem Statement

ADR-0020 specified a NET_DM multicast collector but the first implementation
shipped a pull-only model: every scrape issued `NET_DM_CMD_STATS_GET` and
exported `NET_DM_ATTR_STATS_DROPPED` as `nft_drop_packets_total`.

Live verification on a kernel with `CONFIG_NET_DROP_MONITOR=y`
(Ubuntu 24.04, kernel 6.17.0-generic) proved two defects:

1. **Multi-scrape failure.** `NET_DM_CMD_START` returns `-EAGAIN` (errno 11) —
   not `EBUSY`/`EALREADY` — when the trace state already equals the requested
   value (`set_all_monitor_traces()`, `net/core/drop_monitor.c:1227`). The
   collector only tolerated `EBUSY`/`EALREADY`, so every scrape after the first
   failed (`success=0`, no metrics). Fixed separately by tolerating `EAGAIN`.

2. **Wrong metric semantics.** `NET_DM_ATTR_STATS_DROPPED` returned by
   `NET_DM_CMD_STATS_GET` is the monitor's own **overflow counter** — it is
   incremented only on the `unlock_free` path when a per-CPU drop queue is full
   (`net/core/drop_monitor.c:533-536`), i.e. drops the monitor itself could not
   report. Under normal load it stays `0` regardless of how many packets the
   kernel drops. Generating 500 real drops produced `nft_drop_packets_total 0`.
   The real per-location drop counts are delivered only on the
   `NET_DM_GRP_ALERT` **multicast** stream (`trace_drop_common()` →
   `genlmsg_multicast()`), never via `STATS_GET`.

A pull-only design therefore cannot report real drop totals.

## Considered Options

- **A — honest pull only**: keep `STATS_GET`, rename the metric to reflect that
  it is an overflow/health counter. Cheap, no background task, but gives no real
  drop totals.
- **B — multicast accumulator**: subscribe to `NET_DM_GRP_ALERT`, accumulate
  real SW/HW drop totals. Gives true totals; requires a background listener.
- **B + A (chosen)**: do both — multicast accumulator for the real totals AND
  the overflow counter exposed under an honest name as a monitor-health signal.

## Decision Outcome

**Chosen: B + A — hybrid model.**

### B — background multicast accumulator (real totals)

`setup_and_spawn_listener` performs a **privileged setup** on the caller thread,
then spawns a **recv-only** OS thread:

- Setup (privileged): open an `AF_NETLINK`/`NETLINK_GENERIC` socket, resolve the
  NET_DM family id and the `events` multicast group id via `CTRL_CMD_GETFAMILY`
  (`CTRL_ATTR_MCAST_GROUPS` → `CTRL_ATTR_MCAST_GRP_NAME` / `CTRL_ATTR_MCAST_GRP_ID`),
  enable SUMMARY-mode monitoring (`NET_DM_CMD_CONFIG` + `NET_DM_CMD_START`,
  unicast, before joining), and join `events`.
- Recv loop (unprivileged): receive `NET_DM_CMD_ALERT` frames and accumulate.

**Everything is io_uring (ADR-0024).** The CTRL resolve, CONFIG, START, and the
ALERT recv use `IORING_OP_SEND`/`IORING_OP_RECV`; the group-join
`setsockopt(NETLINK_ADD_MEMBERSHIP)` uses `IORING_OP_URING_CMD` /
`SOCKET_URING_OP_SETSOCKOPT` (io-uring crate `opcode::SetSockOpt`, kernel ≥ 6.7),
falling back to a blocking `libc::setsockopt` only when the op returns
`EOPNOTSUPP`/`EINVAL`/`ENOSYS` on older kernels.

**Capability ordering.** The `events` group is declared
`GENL_MCAST_CAP_SYS_ADMIN` (`net/core/drop_monitor.c:187`), so the join needs
`CAP_SYS_ADMIN` (and CONFIG/START need `CAP_NET_ADMIN`). The privileged setup
therefore runs **before** the process drops capabilities (ADR-0009 — see also
the CAP_SYS_ADMIN note added to ADR-0009 for the drop_monitor case); the
recv-only thread spawned afterwards needs no capabilities. The listener is
started only when the NET_DM family was available at probe time.

Each SUMMARY-mode ALERT carries (after `genlmsghdr`):

- `NLA_UNSPEC` (type 0) = `net_dm_alert_msg { u32 entries; net_dm_drop_point points[] }`,
  each `net_dm_drop_point { u8 pc[8]; u32 count }` (12 B). Sum of `count` = SW drops.
- optional `NET_DM_ATTR_HW_ENTRIES` (17) → `NET_DM_ATTR_HW_ENTRY` (18) →
  `NET_DM_ATTR_HW_TRAP_COUNT` (19, u32). Sum = HW drops.

Counts accumulate into a shared `DropCounters { sw: AtomicU64, hw: AtomicU64 }`.
The collector reads these lock-free on each scrape and exports:

```
nft_drop_packets_total{origin="sw",reason="total"}
nft_drop_packets_total{origin="hw",reason="total"}
```

The netlink RECV uses io_uring (ADR-0024). The listener thread uses only
`AtomicU64` — no `Mutex`/`RwLock` (ADR-0023). It is spawned **before** the
capability drop (the `events` multicast group is declared
`GENL_MCAST_CAP_SYS_ADMIN` in `net/core/drop_monitor.c:187`, so joining it
requires `CAP_SYS_ADMIN`; see ADR-0009 for the overall capability model), and
only when the NET_DM family was available at probe time.

**SUMMARY not PACKET mode, and no per-reason labels.** SUMMARY-mode alerts carry
per-drop-*location* (kernel PC) counts, which are summed to a bounded total
(`reason="total"`). Per-reason breakdown (`NET_DM_ATTR_REASON`) exists only in
PACKET mode (`NET_DM_CMD_PACKET_ALERT`, one message per dropped packet), a
firehose with unbounded throughput under load. Per-reason labelling is therefore
deferred; `parse_alert_frame` is retained for a future opt-in PACKET-mode path.

### A — overflow-pull health metric

On each scrape the collector additionally issues `NET_DM_CMD_STATS_GET`
(best-effort; failure is non-fatal) and exports the overflow counter under an
honest name:

```
nft_drop_monitor_unreported_total{origin="sw"}
nft_drop_monitor_unreported_total{origin="hw"}
```

This is a monitor-health signal (drops the kernel drop-monitor could not enqueue
for reporting), explicitly NOT a drop total.

### Consequences

- Positive: real SW/HW drop totals are now exported, live-verified on
  kernel 6.17 (`CONFIG_NET_DROP_MONITOR=y`): 500 generated drops were reflected
  in `nft_drop_packets_total{origin="sw"}`.
- Positive: `collect()` never fails on the totals (atomic read), so the
  collector reports `success=1` whenever NET_DM is available.
- Positive: lock-free (ADR-0023), io_uring RECV (ADR-0024), native API only
  (ADR-0025) all preserved.
- Negative: introduces one background OS thread for the multicast listener
  (the only non-monoio thread in the process). Justified: monoio is
  thread-per-core and a blocking, indefinite multicast recv must not run on the
  executor thread.
- Negative: no per-reason breakdown in SUMMARY mode (cardinality/throughput
  trade-off); deferred to a future PACKET-mode opt-in.
- Cardinality: `origin` ∈ {sw, hw}; `reason` = "total" — fully bounded.

### Verification

vm.services (kernel 6.17.4-pve) lacks `CONFIG_NET_DROP_MONITOR`; the probe
correctly reports `available=0` there. End-to-end verification was performed on
a host with the feature compiled in (Ubuntu 24.04, kernel 6.17.0-generic):
`available=1`, `success=1` across consecutive scrapes, and generated SW drops
reflected in `nft_drop_packets_total`.
