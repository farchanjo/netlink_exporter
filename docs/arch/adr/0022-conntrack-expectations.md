---
status: accepted
date: 2026-05-28
deciders: [eonf]
consulted: []
informed: []
---

# Add a conntrack-expectations collector via direct ctnetlink, runtime-gated

## Context and Problem Statement

The kernel connection-tracking subsystem maintains two distinct tables: the main
conntrack table (tracked by the existing `conntrack` collector via
`IPCTNL_MSG_CT_GET`) and the expectations table. An expectation is a short-lived
placeholder entry created by a connection-tracking helper (for example, the FTP,
SIP, H.323, or TFTP helpers) to describe a future secondary flow that the helper
knows will arrive. Expectations are stored under `NFNL_SUBSYS_CTNETLINK_EXP`
(subsystem id `2`) and are accessible via `IPCTNL_MSG_EXP_GET` and
`IPCTNL_MSG_EXP_GET_STATS_CPU`.

No existing collector exposes expectation-table size or helper activity. In
environments running stateful helpers (FTP passive mode, SIP, H.323, or TFTP
through nftables `ct helper` rules), unmonitored expectation storms can silently
exhaust the expectation table, causing secondary flows to be rejected and
breaking application connectivity. The symptoms (broken FTP data channels,
dropped SIP media) are invisible in the existing `nft_conntrack_*` metrics
because those metrics cover only the main table.

The expectations subsystem is not always present: kernels built without
`CONFIG_NF_CONNTRACK` or without the specific helper modules will return
`ENOENT` or `EPERM` when the exporter opens an `IPCTNL_MSG_EXP_GET` dump.
The collector must therefore be runtime-gated and must emit
`nft_scrape_collector_available{collector="conntrack-expectations"}` to signal
probe-time subsystem availability.

Cardinality is bounded because the legal label dimensions are
`l4proto` (one of the eight `#ConntrackProtocol` strings) and `helper`
(a bounded set of NUL-terminated ASCII strings registered by the kernel helper
modules: `ftp`, `tftp`, `sip`, `h323`, `pptp`, `irc`, `amanda`, `netbios_ns`,
`snmp`, `broadcast` — at most approximately 20 values in practice).

Sharing the existing `NETLINK_NETFILTER` socket family (protocol `12`) used by
`ConntrackAdapter` and `NftablesAdapter` is required by ADR-0009 (single socket
file descriptor per netlink family) and ADR-0011 (direct wire implementation).

## Considered Options

- **Skip — do not expose expectation-table metrics**: lowest implementation
  cost; invisible to operators. Rejected because expectation storms are a known
  operational failure mode for SIP and FTP deployments.

- **Procfs-based counting via `/proc/net/nf_conntrack_expect`**: reads the
  expectation table as text; no capability beyond what is already needed.
  Rejected for two reasons: (1) ADR-0011 mandates direct netlink and forbids
  procfs-based counting after the procfs path proved empty on the probe host
  during the ADR-0011 research phase; (2) procfs parsing requires per-line
  string allocation whereas the netlink path is zero-copy.

- **Direct netlink via `IPCTNL_MSG_EXP_GET` dump with runtime gate** (chosen):
  consistent with ADR-0011; reuses the `NETLINK_NETFILTER` socket opened for
  `ConntrackAdapter`; produces a bounded `ConntrackExpectationSummary` ReadModel
  aggregated by `(l4proto, helper)`; emits a runtime-availability metric;
  isolates gracefully when the subsystem is absent.

## Decision Outcome

**Chosen option: direct netlink `IPCTNL_MSG_EXP_GET` dump with runtime gate.**

A new bounded context `conntrack-expectations` is added alongside the existing
`conntrack` context. The implementation follows the hexagonal port model
(ADR-0002) and the direct wire protocol mandate (ADR-0011).

**New driven port:** `NetlinkConntrackExpectationsPort` (async trait in
`nft_exporter_domain_ct_exp`). Methods:

- `async fn dump_expectations(&self) -> Result<Vec<ConntrackExpectation>, CollectorError>`
- `async fn get_exp_stats_cpu(&self) -> Result<ExpectationStats, CollectorError>`

**New adapter crate:** `nft_exporter_adapter_ct_exp` implementing
`NetlinkConntrackExpectationsPort`. Uses the shared `NETLINK_NETFILTER` socket.
Wire encoding: `NFNL_SUBSYS_CTNETLINK_EXP = 2`, `nlmsg_type = (2 << 8) |
IPCTNL_MSG_EXP_GET (0) = 0x0200` for the dump, `nlmsg_flags = 0x0301`
(NLM_F_REQUEST | NLM_F_DUMP). For stats: `nlmsg_type = (2 << 8) |
IPCTNL_MSG_EXP_GET_STATS_CPU (3) = 0x0203`, `nlmsg_flags = 0x0001`.

**Runtime gate:** On first scrape, issue one `IPCTNL_MSG_EXP_GET` request. If
the kernel returns `ENOENT` or `EPERM`, set
`nft_scrape_collector_available{collector="conntrack-expectations"} = 0` and
return an empty `ConntrackExpectationSummary` (zero `expectations_total`). On
success set the gauge to `1`. The gate state persists across scrapes; it is
re-evaluated only if the collector was previously unavailable and a scrape
succeeds.

**ReadModel:** `ConntrackExpectationSummary` (immutable, one per scrape epoch).
Fields:

- `expectations_by_key: Vec<ExpectationBucketCount>` — aggregated by
  `(l4proto, helper)`. Cardinality bound: at most 8 protocols times at most
  20 helper strings = 160 series.
- `exp_stats: ExpectationStats` — zero-label global counters from
  `IPCTNL_MSG_EXP_GET_STATS_CPU`: `new` (expectations created), `delete`
  (expectations deleted), `new_failed` (allocation failures).

**Metric families emitted:**

| Metric | Type | Labels | Cardinality bound |
|---|---|---|---|
| `nft_conntrack_expectation_entries` | gauge | `l4proto`, `helper` | ~160 |
| `nft_conntrack_expectation_new_total` | counter | none | 1 |
| `nft_conntrack_expectation_delete_total` | counter | none | 1 |
| `nft_conntrack_expectation_new_failed_total` | counter | none | 1 |
| `nft_scrape_collector_available` | gauge | `collector` | one per collector |

**Cardinality guard:** If the number of distinct `(l4proto, helper)` keys
observed during a single dump exceeds 256, stop iteration and increment
`nft_scrape_collector_error_total{collector="conntrack-expectations",
reason="cardinality_overflow"}`. Serve the stale snapshot.

**Consequences:**

- Positive: operators gain visibility into SIP, FTP, and H.323 helper activity
  without per-expectation cardinality; the label set is fully bounded.
- Positive: the runtime gate ensures zero overhead on kernels without helper
  modules; `nft_scrape_collector_available` makes the absence observable.
- Positive: no new netlink socket file descriptor is opened; the shared
  `NETLINK_NETFILTER` socket lifecycle is unchanged (ADR-0009).
- Positive: the collector is independently disable-able via the `collectors`
  enable list (ADR-0013), letting operators suppress it on hosts where helpers
  are never loaded.
- Negative: `IPCTNL_MSG_EXP_GET_STATS_CPU` CPU-stat struct layout has varied
  across kernels; the adapter must gate on payload length, same as
  `nf_conntrack_stat` (ADR-0011 precedent). Unknown trailing fields are set to
  zero rather than emitted.
- Negative: helper names are NUL-terminated kernel strings registered by
  modules; an unexpected or very long helper name must be truncated to 64 bytes
  to avoid label-value explosion.
