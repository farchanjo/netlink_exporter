---
status: accepted
date: 2026-05-28
deciders: [eonf]
consulted: []
informed: []
---

# Add XFRM/IPsec observability collector via direct NETLINK_XFRM, runtime-gated

## Context and Problem Statement

The probe host has the `xfrm_user` kernel module loaded and `/proc/net/xfrm_stat`
live. IPsec deployments managed by strongSwan, Libreswan, or the kernel's native
XFRM subsystem expose no metrics through any of the six existing collectors
(rtnetlink, conntrack, nftables, sock_diag, tc, ethtool). Operators cannot observe
Security Association (SA) count, Security Policy (SPD) entries, SAD/SPD watermarks,
or XFRM error counters (dropped inbound packets, policy blocks, state protocol
errors) without running manual `ip xfrm state count` or `cat /proc/net/xfrm_stat`
commands.

The XFRM subsystem communicates via `NETLINK_XFRM` (protocol family 6). The kernel
exposes four dump/query commands relevant to observability:

- `XFRM_MSG_GETSA` (0x7) — full dump of the Security Association Database (SAD),
  one `xfrm_usersa_info` struct per reply frame.
- `XFRM_MSG_GETPOLICY` (0x9) — full dump of the Security Policy Database (SPD),
  one `xfrm_userpolicy_info` struct per reply frame.
- `XFRM_MSG_GETSADINFO` (0x11) — single-frame reply carrying global SAD watermarks
  (`xfrm_sadinfo`: `sadhcnt`, `sadhmcnt`).
- `XFRM_MSG_GETSPDINFO` (0x12) — single-frame reply carrying global SPD watermarks
  (`xfrm_spdinfo`: `spdhcnt`, `spdhmcnt`, `spdbtree` policy counts).

The `/proc/net/xfrm_stat` file provides per-CPU-aggregated XFRM error counters
(`XfrmInError`, `XfrmInNoStates`, `XfrmInStateProtoError`, `XfrmOutPolBlock`, etc.)
as plain text key-value pairs. These counters are not exposed through any
`NETLINK_XFRM` message type and must be sourced from procfs.

No existing ADR covers `NETLINK_XFRM`. The collector must be runtime-gated:
hosts without IPsec configured have an empty SAD and SPD; the collector must
report `nft_scrape_collector_available{collector="xfrm-ipsec"} 0` and emit zero
metric series (other than the availability gauge) when the subsystem probe fails
or returns empty tables, rather than a fatal error.

## Considered Options

- **Skip — no XFRM collector**: IPsec observability remains a gap. Operators
  continue using manual CLI inspection. No code or schema changes required.
  Rejected because the probe host has `xfrm_user` loaded and live state, making
  this an active observability blind spot rather than a theoretical one.

- **procfs-only (`/proc/net/xfrm_stat` + `ip xfrm state count` via subprocess)**:
  `/proc/net/xfrm_stat` is available on the probe host and covers error counters.
  SA and SP counts would require shelling out to `ip xfrm state count` or
  `ip xfrm policy count`, which introduces subprocess dependency, parse fragility
  against `iproute2` version drift, and breaks the ADR-0009 minimal-privilege
  model (subprocess execution is not in the allowed-capability set). The procfs
  file alone does not provide SA count, SP count, or SAD/SPD watermarks.
  Rejected because it cannot satisfy the full metric requirement without subprocess
  invocation.

- **Direct NETLINK_XFRM wire protocol (chosen)**: Open a raw `AF_NETLINK` socket
  with `protocol=NETLINK_XFRM` (6). Issue `XFRM_MSG_GETSA` and
  `XFRM_MSG_GETPOLICY` dumps to count SA and SP entries. Issue
  `XFRM_MSG_GETSADINFO` and `XFRM_MSG_GETSPDINFO` for watermarks. Parse
  `/proc/net/xfrm_stat` for error counters (the only source). Gate the collector
  at startup by probing `XFRM_MSG_GETSADINFO`; treat `ENOENT` or `EPROTONOSUPPORT`
  as "subsystem absent" and set `nft_scrape_collector_available 0`. Consistent
  with ADR-0011 direct-wire mandate.

## Decision Outcome

**Chosen option: direct NETLINK_XFRM wire protocol with runtime availability gate.**

A new bounded context `xfrm-ipsec` is added with the following driven port and
collector strategy:

**Port:** `NetlinkXfrmIpsecPort` — driven port in the domain hexagonal model
(ADR-0002). The adapter crate `nft_exporter_adapter_xfrm` implements this port
using `rustix 1.1.4` socket primitives, `linux-raw-sys 0.12.1` UAPI constants,
and `zerocopy 0.8` for zero-copy struct casting of `xfrm_usersa_info` and
`xfrm_userpolicy_info` frames. Procfs parsing for `/proc/net/xfrm_stat` uses
`std::fs::File` + line-by-line iteration (sync, inside
`tokio::task::spawn_blocking` per ADR-0007).

**Runtime availability gate:** At collector startup, `XfrmIpsecAdapter` issues
`XFRM_MSG_GETSADINFO` (a non-destructive single-frame query) with a 500 ms
timeout. If the socket returns `EPROTONOSUPPORT`, `ENOENT`, `EPERM`, or the
`xfrm_user` module is absent (socket creation fails with `EPROTONOSUPPORT`), the
adapter sets its internal `available` flag to `false`. On each scrape cycle, when
`available=false`, the collector emits only
`nft_scrape_collector_available{collector="xfrm-ipsec"} 0` and returns
immediately without netlink I/O. No error counter is incremented for the
absent-subsystem path; it is an expected operating mode on non-IPsec hosts.

**Metric families produced:**

| Metric | Type | Labels | Source |
|---|---|---|---|
| `nft_xfrm_sa_count` | gauge | `proto`, `mode` | `XFRM_MSG_GETSA` dump count |
| `nft_xfrm_sp_count` | gauge | `dir`, `action` | `XFRM_MSG_GETPOLICY` dump count |
| `nft_xfrm_sad_hash_count` | gauge | [] | `XFRM_MSG_GETSADINFO sadhcnt` |
| `nft_xfrm_sad_hash_max` | gauge | [] | `XFRM_MSG_GETSADINFO sadhmcnt` |
| `nft_xfrm_spd_hash_count` | gauge | [] | `XFRM_MSG_GETSPDINFO spdhcnt` |
| `nft_xfrm_spd_hash_max` | gauge | [] | `XFRM_MSG_GETSPDINFO spdhmcnt` |
| `nft_xfrm_stat_total` | counter | `counter` | `/proc/net/xfrm_stat` line keys |
| `nft_scrape_collector_available` | gauge | `collector="xfrm-ipsec"` | availability gate |

The `counter` label on `nft_xfrm_stat_total` is bounded to the fixed set of
keys defined in `/proc/net/xfrm_stat`: `XfrmInError`, `XfrmInNoStates`,
`XfrmInStateProtoError`, `XfrmInStateModeError`, `XfrmInStateSeqError`,
`XfrmInStateExpired`, `XfrmInStateMismatch`, `XfrmInStateInvalid`,
`XfrmInTmplMismatch`, `XfrmInNoPols`, `XfrmInPolBlock`, `XfrmInPolError`,
`XfrmOutError`, `XfrmOutBundleGenError`, `XfrmOutBundleCheckError`,
`XfrmOutNoStates`, `XfrmOutStateProtoError`, `XfrmOutStateModeError`,
`XfrmOutStateSeqError`, `XfrmOutStateExpired`, `XfrmOutPolBlock`,
`XfrmOutPolDead`, `XfrmOutPolError`, `XfrmFwdHdrError`, `XfrmOutStateInvalid`,
`XfrmAcquireError`. Unknown keys are silently ignored; no dynamic label expansion.
Cardinality is bounded to exactly 26 series.

**Configuration:** A new collector name `"xfrm_ipsec"` is added to
`#CollectorName`. When absent from the `collectors` list, the adapter is not
instantiated (no socket opened). When present, the runtime gate controls whether
metrics are emitted. Default: `"xfrm_ipsec"` added to the default list but
gated — hosts without the subsystem see only the availability gauge.

**Consequences:**

- Positive: IPsec SA/SP count and XFRM error counters are observable from
  Prometheus without manual CLI inspection or subprocess execution.
- Positive: The runtime gate makes the collector safe to enable by default on
  mixed fleets; non-IPsec hosts emit one gauge series at value 0.
- Positive: Consistent with ADR-0011 direct-wire mandate; no new high-level
  netlink crate dependency.
- Positive: Cardinality is strictly bounded: `nft_xfrm_sa_count` and
  `nft_xfrm_sp_count` have bounded label sets (proto in 4 values, mode in 4,
  dir in 3, action in 3); `nft_xfrm_stat_total` is bounded to 26 fixed counter
  names from the kernel ABI.
- Negative: `/proc/net/xfrm_stat` parsing requires `spawn_blocking`; adds one
  blocking-thread allocation per scrape on IPsec hosts. Acceptable given that
  the xfrm_stat file is small (< 1 KiB).
- Negative: `xfrm_usersa_info` and `xfrm_userpolicy_info` structs are larger
  than other subsystem message bodies (220 and 164 bytes respectively); the
  receive buffer tuning already applied (4 MiB per ADR-0011) is sufficient for
  SAD sizes up to ~19,000 SAs before `ENOBUFS` risk.
