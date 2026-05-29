---
status: superseded
date: 2026-05-28
deciders: [eonf]
consulted: []
informed: []
---

# Standardize on the rust-netlink org crate stack with vendored netlink-packet-netfilter patch for IPCTNL_MSG_CT_GET_STATS_CPU

Superseded by ADR-0011.

## Context and Problem Statement

The exporter reads six distinct kernel netlink API families: NETLINK_ROUTE (rtnetlink + TC), NETLINK_NETFILTER (ctnetlink + nfnetlink/nftables), NETLINK_SOCK_DIAG, and NETLINK_GENERIC (ethtool). Two independent Rust netlink ecosystems exist: the `rust-netlink` organization crates (`netlink-sys`, `netlink-proto`, `netlink-packet-core`, `netlink-packet-route`, etc.) and the `neli` crate.

Additionally, the ctnetlink path requires `IPCTNL_MSG_CT_GET_STATS_CPU` per-CPU statistics, which no upstream crate currently encodes. The nftables path requires a pure-Rust nfnetlink client; the only C-binding alternative (`nftnl`) wraps `libnftnl` via FFI and prevents hermetic musl cross-compilation.

## Considered Options

- rust-netlink org stack + vendored netlink-packet-netfilter patch (chosen)
- neli 0.7.4 as single alternative stack
- Mixed: rust-netlink for rtnetlink + neli for conntrack + nftnl for nftables

## Decision Outcome

**Chosen option: rust-netlink org stack with vendored patch.**

All six subsystems share the following common transport base: `netlink-sys 0.8.8` (async socket via `tokio::io::unix::AsyncFd`), `netlink-proto 0.12.0` (framed tokio codec), and `netlink-packet-core 0.8.1` (NetlinkMessage framing, NLM_F_DUMP flag). On top of this shared base:

- NETLINK_ROUTE: `rtnetlink 0.21.0` + `netlink-packet-route 0.30.0` (RTM_GET* + TC module with TcStats2 / Xstats).
- NETLINK_NETFILTER/ctnetlink: `netlink-packet-netfilter 0.2.0` vendored under `vendor/netlink-packet-netfilter`. The vendor copy is patched to add approximately 400 lines implementing `IPCTNL_MSG_CT_GET_STATS_CPU` codec (nf_conntrack_stat struct decoding). The patch is tracked as a git range in `vendor/patches/0001-add-stats-cpu-codec.patch`.
- NETLINK_NETFILTER/nftables: `rustables 0.8.7` — pure Rust, no `libnftnl` FFI dependency, hermetic musl build.
- NETLINK_SOCK_DIAG: `netlink-packet-sock-diag 0.4.2` with `AF_INET`/`AF_INET6` and `INET_DIAG_SKMEMINFO` decoding.
- NETLINK_GENERIC: `netlink-packet-generic 0.4.0` + `genetlink 0.2.6` (family resolution) + `ethtool 0.2.9` (default-features=false, tokio feature only).

The `neli` crate is explicitly excluded via `cargo deny` to prevent a second netlink stack from entering the dependency graph.

**Consequences:**

- Positive: Single shared `AsyncSocket` implementation across all subsystems; socket fd management, SO_RCVBUF tuning, and ENOBUFS circuit-breaker logic are written once.
- Positive: `rustables 0.8.7` requires no C toolchain, enabling hermetic `cargo build --target x86_64-unknown-linux-musl` without a sysroot.
- Positive: The vendored `netlink-packet-netfilter` patch path provides `IPCTNL_MSG_CT_GET_STATS_CPU` without waiting for an upstream PR to merge, unblocking per-CPU conntrack statistics.
- Negative: Vendoring introduces maintenance burden: the patch must be rebased against upstream releases. A `Makefile` target `make update-vendor-netfilter` automates this for minor version bumps.
- Negative: `rustables` is less actively maintained than `libnftnl`-backed alternatives; an upstream abandonment would require a fork. Monitored via Dependabot and a 90-day review calendar entry.

**Rejected options:**

- *neli 0.7.4 as single alternative stack*: `neli` has a synchronous API surface incompatible with the tokio-based async runtime. Wrapping it in `spawn_blocking` would serialize all six subsystem collectors onto the blocking thread pool, eliminating concurrent fan-out. The `neli` crate also lacks TC/TCA_STATS2 and nftables message codecs.
- *Mixed stack (rust-netlink + neli + nftnl)*: Three different socket abstraction layers would each require separate `SO_RCVBUF`, `ENOBUFS`, and circuit-breaker implementations. `nftnl` wraps `libnftnl.so` via `bindgen`-generated FFI, which requires the `libnftnl-dev` package in the musl cross-compilation sysroot and breaks hermetic static builds.
