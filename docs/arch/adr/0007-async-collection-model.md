---
status: superseded
date: 2026-05-28
deciders: [eonf]
consulted: []
informed: []
superseded_by: ADR-0014
---

# Use tokio 1.52 as the single async runtime with per-scrape JoinSet fan-out and per-collector timeout

Superseded by ADR-0014.

## Context and Problem Statement

Each GET /metrics pull must concurrently collect from up to six independent netlink subsystems. Sequential collection would serialize latency across all six subsystems; a single slow or hung collector (e.g., ethtool on a NIC with a buggy driver) would block the entire scrape and cause a Prometheus timeout.

The team must choose an async runtime, a concurrency model for per-scrape fan-out, and a timeout enforcement mechanism that is compatible with the `netlink-sys` async socket layer, supports per-collector isolation (so one panic does not abort the others), and avoids blocking-thread consumption for normal netlink I/O.

A secondary constraint: opening a netlink socket in a different network namespace (netns) requires calling `setns(2)` with `CLONE_NEWNET`, which is unsafe in a multi-threaded process because it affects all threads sharing the same thread group. The netns socket-opening path must be isolated from the tokio worker thread pool.

## Considered Options

- tokio 1.52 JoinSet per-scrape fan-out (chosen)
- smol/async-io (incompatible with rtnetlink tokio dependency)
- Blocking sync per-scrape in spawn_blocking threads

## Decision Outcome

**Chosen option: tokio 1.52 with JoinSet fan-out.**

`tokio` is declared with `features = ["rt-multi-thread", "macros", "time", "sync", "io-util"]`. No other async runtime is permitted in the workspace (`cargo deny` bans `async-std`, `smol`, `async-io`).

**Per-scrape fan-out**: `ScrapeLifecycle::collect_all` spawns each enabled collector into a `tokio::task::JoinSet<Result<Box<dyn ReadModel>, CollectorError>>`. All collectors run concurrently on the tokio worker thread pool.

**Per-collector timeout**: Each collector future is wrapped with `tokio::time::timeout(Duration::from_millis(per_collector_budget_ms), collector.collect())` before being pushed into the `JoinSet`. The `per_collector_budget_ms` is derived from `ExporterConfig.scrape_timeout_ms` divided by the number of enabled collectors plus a fixed 200 ms margin for encoding.

**Panic isolation**: Each collector task is spawned with `JoinSet::spawn`, which catches panics as `JoinError::Cancelled`/`JoinError::Panic`. The `ScrapeLifecycle` catch-unwind boundary in `post_process` detects panic results, logs the backtrace, records `nft_scrape_collector_success{collector=...} 0` and `nft_scrape_collector_error_total{collector, reason=panic}`, and falls back to the last successful `ReadModel` snapshot (stale-snapshot policy).

**Netlink socket I/O**: All netlink sockets are opened as non-blocking via `netlink-sys::AsyncSocket` backed by `tokio::io::unix::AsyncFd`. No `spawn_blocking` is used for normal netlink reads or writes.

**Netns isolation**: When per-netns collection is enabled, a dedicated `std::thread` (named `netns-opener`) opens the netlink socket fd inside the target netns and passes the fd back to the main tokio runtime via a `tokio::sync::oneshot` channel. This avoids calling `setns(CLONE_NEWNET)` on a tokio worker thread, which would affect all workers sharing the thread-local netns.

**Consequences:**

- Positive: Six collectors run concurrently; wall-clock scrape duration is bounded by the slowest collector plus encoding, not the sum of all collectors.
- Positive: A panicking collector does not abort other collectors; the scrape returns stale data for the panicking subsystem and fresh data for the rest. `nft_up` reflects critical-collector health independently.
- Positive: `tokio::time::timeout` is cancel-safe by construction; the future is dropped on timeout and the netlink socket fd is closed via the `Drop` impl of `AsyncSocket`.
- Negative: The `std::thread` for netns socket opening introduces a short synchronous rendezvous per netns per scrape. For the common single-netns case this thread is not started.
- Negative: `tokio::task::JoinSet` was stabilized in tokio 1.35; users on older tokio versions cannot use this pattern. The `rust-version = "1.87"` constraint in `Cargo.toml` ensures tokio 1.52 is reachable.

**Rejected options:**

- *smol/async-io*: `rtnetlink 0.21` and `netlink-sys 0.8.8` hard-depend on `tokio::io::unix::AsyncFd`. Using `smol` would require forking the entire rust-netlink crate stack or wrapping every netlink socket in a compatibility shim, which is not justified.
- *Blocking sync per-scrape in spawn_blocking threads*: Tokio's `spawn_blocking` pool defaults to 512 threads. Six collectors per scrape across hundreds of concurrent scrapes would exhaust the pool. Netlink socket reads in blocking mode are not interruptible by timeout logic without a dedicated watchdog thread per collector.
