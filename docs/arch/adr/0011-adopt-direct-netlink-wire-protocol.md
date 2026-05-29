---
status: accepted
date: 2026-05-28
deciders: [eonf]
consulted: []
informed: []
supersedes: ADR-0004
---

# Adopt direct AF_NETLINK wire protocol implementation across all six subsystem adapters

## Context and Problem Statement

ADR-0004 standardized on the rust-netlink org crate stack (rtnetlink, netlink-packet-\*, rustables, netlink-proto, netlink-sys) with a vendored patch to `netlink-packet-netfilter` for `IPCTNL_MSG_CT_GET_STATS_CPU`. Five wire-protocol research probes conducted against the live kernel confirmed that the rust-netlink org abstractions actively prevent access to the raw byte framing required for:

- `IPCTNL_MSG_CT_GET_STATS_CPU`: per-CPU `nf_conntrack_stat` structs arrive without any `nlattr` wrapper; the patched codec in `netlink-packet-netfilter` cannot model the three kernel-version-dependent struct sizes (52/56/60 bytes) without forking the crate's framing model.
- `NLM_F_DUMP_INTR` restart semantics: `netlink-proto`'s framed codec does not expose the `nlmsg_flags` bitmask on individual frames mid-dump; detecting `NLM_F_DUMP_INTR` requires reading the raw `nlmsghdr`.
- `TCA_STATS2` nested attribute parsing: `netlink-packet-route`'s TC module does not correctly handle the `NLA_F_NESTED` bit-15 mask before attribute type matching, causing incorrect parses for `gnet_stats_basic` and `gnet_stats_queue`.
- genetlink family resolution: `genetlink 0.2.6`'s `OnceLock` caching model conflicts with the per-scrape socket lifecycle required by `ScrapeLifecycle`.
- Conntrack procfs path (`/proc/net/nf_conntrack`) is empty on the probe host; the only live source is the `NETLINK_NETFILTER` ctnetlink path. The rust-netlink org stack's partial ctnetlink support, combined with the vendored patch maintenance burden, makes the crate stack untenable as the sole transport.

The vendored patch (`vendor/patches/0001-add-stats-cpu-codec.patch`) is an ongoing maintenance liability: every upstream `netlink-packet-netfilter` release requires a manual rebase. The `make update-vendor-netfilter` automation handles only minor version bumps and has already failed once against a breaking re-export change.

Direct hand-written AF_NETLINK codecs over raw sockets provide full control of dump-and-parse semantics, zero-copy struct casting, and exact kernel-version-adaptive parsing without any upstream dependency on the rust-netlink org.

## Considered Options

- **High-level rtnetlink crate stack** (ADR-0004 choice): rtnetlink 0.21, netlink-packet-route 0.30, netlink-packet-netfilter 0.2 vendored + patched, netlink-packet-sock-diag 0.4.2, netlink-packet-generic 0.4.0, genetlink 0.2.6, netlink-proto 0.12.0, netlink-sys 0.8.8, rustables 0.8.7.
- **Mid-level netlink-packet-\* crates only** (without rtnetlink): use `netlink-packet-core` framing with custom message codecs per subsystem; avoid rtnetlink's opinionated handle API while still using the upstream attribute parsers.
- **Direct wire protocol over raw AF_NETLINK sockets** (chosen): rustix 1.1.4 for socket syscalls, linux-raw-sys 0.12.1 for UAPI constants and repr(C) structs, zerocopy 0.8 and bytemuck 1.25 for zero-copy struct parsing, byteorder 1.5.0 for big-endian nfnetlink payload fields. No rust-netlink org crate in the dependency graph.

## Decision Outcome

**Chosen option: direct wire protocol over raw AF_NETLINK sockets.**

All six netlink subsystem adapters implement the wire protocol directly against raw AF_NETLINK sockets. The crate assignments are:

- **rustix 1.1.4**: `socket_with`, `bind` (sockaddr_nl with `nl_pid=0`), `sendmsg`, `recvmsg`, `setsockopt` (`SO_RCVBUF`, `NETLINK_GET_STRICT_CHK`) via inline syscalls on x86-64 and aarch64. No libc shim; hermetic musl build preserved.
- **linux-raw-sys 0.12.1**: Generated UAPI constants and `repr(C)` structs: `nlmsghdr`, `nlattr`, `rtgenmsg`, `rtmsg`, `ifinfomsg`, `ifaddrmsg`, `ndmsg`, `nfgenmsg`, `genlmsghdr`, `tcmsg`, `inet_diag_req_v2`, `inet_diag_msg`.
- **zerocopy 0.8** (stable branch only; 0.9.0-alpha.0 is explicitly banned): `FromBytes + IntoBytes + Unaligned` derives for zero-copy casting of fixed kernel structs (`nlmsghdr`, `nlattr`, `ifinfomsg`, `nf_conntrack_stat`, `gnet_stats_basic`, `gnet_stats_queue`) from `&[u8]` slices with runtime alignment validation.
- **bytemuck 1.25.0**: `Pod + Zeroable` derives for smaller leaf structs where zerocopy's streaming abstraction is not needed (`nf_conntrack_stat` per-CPU parse, `gnet_stats_basic` inside `TCA_STATS2`).
- **byteorder 1.5.0**: `NetworkEndian` reads for big-endian payload fields inside nfnetlink (`CTA_COUNTERS_BYTES` u64 be, `CTA_STATUS` u32 be, `CTA_PROTO_SRC_PORT` u16 be, `nfgenmsg.res_id` `__be16`). All `nlmsghdr` and `nlattr` header fields are native-endian and require no conversion.

A single shared crate, `nft_exporter_netlink_socket`, owns the socket lifecycle code:

- `SO_RCVBUF` tuning to a minimum of 4 MiB.
- `NETLINK_GET_STRICT_CHK` setsockopt (kernel >= 4.20; `ENOPROTOOPT` silently ignored on older kernels).
- `ENOBUFS` circuit-breaker: double `SO_RCVBUF` on first occurrence, abort on second, serve stale snapshot, increment `nft_netlink_errors_total{errno=ENOBUFS}`.
- `NLM_F_DUMP_INTR` restart logic: discard accumulated state, restart dump, cap at `ExporterConfig.netlink_dump_max_restarts` (default 8), then return `CollectorError::DumpIntr` and activate stale-snapshot fallback.

This crate replaces `netlink-sys 0.8.8` and `netlink-proto 0.12.0` entirely.

**Justification grounded in wire-research probes:**

- Conntrack procfs empty on the probe host confirms `NETLINK_NETFILTER` is the only live source; direct wire control is required for `IPCTNL_MSG_CT_GET_STATS_CPU` with kernel-version-adaptive struct sizing.
- Full control of dump-and-parse enables correct `NLM_F_DUMP_INTR` detection on every received frame, not only on `NLMSG_DONE`.
- Zero-copy via zerocopy `FromBytes` avoids allocations in the hot path (29 interfaces × 24 u64 counters per scrape).
- Smaller dependency surface: 5 infrastructure crates replace 10 rust-netlink org crates; `cargo deny` workspace bans cover the full removed stack.
- Exact kernel-version control: `nf_conntrack_stat` size variants (52/56/60 bytes), `rtnl_link_stats64` size variants (192/200 bytes), and `NETLINK_GET_STRICT_CHK` availability are all handled by conditional payload-length checks at runtime rather than feature flags or vendored patches.

**Consequences:**

- Positive: The vendored `netlink-packet-netfilter` patch and `make update-vendor-netfilter` Makefile target are removed. `IPCTNL_MSG_CT_GET_STATS_CPU` is implemented natively.
- Positive: `rustables` is removed; `NftablesAdapter` speaks raw `NETLINK_NETFILTER` nfnetlink wire directly. No C toolchain or sysroot required; hermetic musl cross-compilation preserved.
- Positive: The three pre-draft ADR files numbered `0011-*` (`rtnetlink-raw-socket-implementation`, `ctnetlink-wire-protocol`, `ethtool-genetlink-wire-protocol`) and `0014-sock-diag-tc-wire-protocol` are incorporated into `docs/arch/domain/netlink-protocol.md` and retired as standalone ADRs.
- Positive: `cargo deny` workspace bans are extended to cover: `rtnetlink`, `netlink-packet-route`, `netlink-packet-core`, `netlink-packet-netfilter`, `netlink-packet-sock-diag`, `netlink-packet-generic`, `genetlink`, `netlink-proto`, `netlink-sys`, `rustables`, `ethtool` (the netlink crate), and `neli`.
- Positive: `docs/arch/domain/overview.md` driven-port table is updated: `NetlinkRtPort` adapter uses rustix; `NetlinkConntrackPort` adapter uses rustix; all adapter crate infrastructure-crate references change from rust-netlink org to the five low-level crates listed above.
- Negative: All six adapter crates are rewritten against the new socket abstraction. The wire-protocol reference (`docs/arch/domain/netlink-protocol.md`) documents every struct layout, attribute catalogue, and endianness invariant to make future maintainers productive without the upstream crate documentation.
- Negative: Attribute parsing is hand-written per subsystem; bugs in `NLA_ALIGN` advance logic or `NLA_F_NESTED` bit masking must be caught by integration tests (ADR-0012) rather than by upstream crate test suites.
