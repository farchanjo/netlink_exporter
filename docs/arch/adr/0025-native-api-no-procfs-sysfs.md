---
status: accepted
date: 2026-05-29
deciders: [eonf]
consulted: []
informed: []
---

# Native kernel APIs only — no procfs or sysfs reads

## Context and Problem Statement

The exporter is a direct-netlink design (ADR-0011). Several collectors could
shortcut to text files under `/proc` or `/sys` (e.g. `/proc/net/xfrm_stat`,
`/proc/net/nf_conntrack`, `/sys/class/net`, `/proc/sys/kernel/io_uring_disabled`).
Mixing procfs/sysfs text parsing with the netlink data path is fragile (format
drift across kernels), slower, and inconsistent with the "kernel-integrated"
architecture goal.

## Considered Options

- Allow `/proc` and `/sys` as convenient fallbacks — rejected: fragile, breaks
  the native-API model, inconsistent surface.
- Native kernel APIs only (netlink, generic netlink, direct syscalls); forbid
  `/proc` and `/sys` reads in exporter code (chosen).

## Decision Outcome

Chosen option: **the exporter reads ALL data via native kernel APIs**
(netlink / generic netlink / direct syscalls). `/proc` and `/sys` reads are
forbidden in exporter code paths.

Consequences applied across the codebase:

- `xfrm`: `/proc/net/xfrm_stat` MIB parse removed. SA/SP counts come from
  `XFRM_MSG_GETSA` / `XFRM_MSG_GETPOLICY` dumps and `XFRM_MSG_GETSADINFO` /
  `GETSPDINFO`. The MIB error counters (`XfrmInError`, …) have no netlink path
  and are therefore **omitted** rather than read from procfs.
- conntrack: ctnetlink `CTA_STATS_*` and `CTA_STATS_GLOBAL_ENTRIES` (netlink) —
  never `/proc/net/nf_conntrack` or the `nf_conntrack_count` sysctl.
- interface enumeration: `RTM_GETLINK` (netlink) — never `/sys/class/net`.
- io_uring availability: detected by the `io_uring_setup` result (monoio
  FusionDriver falls back to epoll on `EPERM`/`ENOSYS`) — never
  `/proc/sys/kernel/io_uring_disabled`. Kernel version, if needed, via the
  `uname(2)` syscall, never `/proc/version`.

**Enforcement:** a CI grep gate rejects any string literal `/proc/` or `/sys/`
in `crates/**` exporter code (comments documenting the prohibition are allowed).

**Trade-off:** data with no netlink/genl/syscall path (e.g. the xfrm MIB
counters) is dropped rather than sourced from procfs. This is accepted: purity
and robustness of the native-API model outweigh the lost counters, which are
better served by a dedicated node-exporter.
