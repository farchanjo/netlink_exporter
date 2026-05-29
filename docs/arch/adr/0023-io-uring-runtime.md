---
status: accepted
date: 2026-05-29
deciders: [eonf]
consulted: []
informed: []
supersedes: ADR-0014
---

# Adopt monoio 0.2 as the io_uring-first async runtime; replace tokio/mio/axum in adapter layer

Supersedes ADR-0014.

## Context and Problem Statement

ADR-0014 confined `tokio 1.52` and `mio 1.0` to the `nlx-netlink` driven adapter
and the binary composition root. The `NetlinkSocket` transport uses
`tokio::io::unix::AsyncFd` for epoll readiness; the HTTP server uses
`axum 0.8` + `tokio::net::TcpListener`.

The project requires an io_uring-first runtime for two reasons:

1. **Transport efficiency.** The current `AsyncFd` model registers the
   `AF_NETLINK` fd with epoll. Every dump loop iteration involves an epoll
   `EPOLLIN` wakeup followed by a blocking `recvmsg(2)` syscall. With
   `IORING_OP_RECVMSG` and registered buffers, the kernel writes directly into
   a pre-pinned buffer and posts a CQE; no intermediate epoll event and no
   separate data syscall are required.

2. **Runtime simplicity.** tokio's work-stealing multi-thread executor is
   overprovisioned for this workload. The scrape fan-out is serialized per
   subsystem within one scrape epoch; the HTTP accept path handles at most one
   concurrent `/metrics` request. A thread-per-core share-nothing model maps
   directly onto this access pattern.

The workspace MSRV is 1.87 and the edition is 2024.

## Considered Options

### Option 1 — monoio 0.2.4 + monoio-http 0.3.12 (chosen)

ByteDance-backed thread-per-core runtime. io_uring-first with a compile-time
`legacy` feature that activates an epoll/mio fallback when `io_uring_setup` is
unavailable (e.g., Kubernetes `RuntimeDefault` seccomp). `monoio-http 0.3` is a
full HTTP/1 server built natively on monoio using `http 1.0`, `httparse`, and
`service-async`. The `poll-io` feature provides `monoio::io::PollFd` as a
drop-in replacement for `tokio::io::unix::AsyncFd`. Full tokio removal is
possible: monoio has zero tokio dependency when compiled without
`feature = "tokio-compat"`.

### Option 2 — tokio-uring 0.5.0

Hard dependency on tokio (cannot be removed; `tokio ^1.2` is a mandatory dep).
No maintained axum/hyper server integration for tokio-uring net types. Last
stable release 2024-05-27; no 2025/2026 activity. Rejected: tokio stays in the
graph, HTTP adapter unsolved, maintenance concern.

### Option 3 — glommio 0.9.0

MSRV declared at 1.65, incompatible with the workspace `rust_2024_compatibility
= "deny"` lint group. Last release 2024-03-25 (15+ months stale at decision
date). HTTP requires ntex as a full framework replacement. Rejected: MSRV
conflict is a hard block.

### Option 4 — keep tokio 1.52 + mio 1.0 (status quo)

Retains all current code. Does not achieve io_uring-first transport. Rejected:
does not meet the stated objective.

## Decision Outcome

**Chosen option: monoio 0.2.4 + monoio-http 0.3.12**, as the mandated io_uring
runtime across the adapter layer and binary composition root.

### Hexagonal confinement invariant (extends ADR-0014)

The runtime-confinement rule established by ADR-0014 is updated to reflect the
new runtime crates. The invariant remains: runtime crates are permitted only in
driven adapter crates and the binary composition root. Domain-core crates and
port-trait definitions remain runtime-agnostic.

| Layer | monoio | monoio-http | service-async | tokio | mio | axum |
|---|---|---|---|---|---|---|
| Domain-core crates | forbidden | forbidden | forbidden | forbidden | forbidden | forbidden |
| Port-trait definitions | forbidden | forbidden | forbidden | forbidden | forbidden | forbidden |
| `nlx-netlink` driven adapter | permitted (`poll-io` feature) | forbidden | forbidden | removed | removed | removed |
| `nlx-http` driving adapter | permitted | permitted | permitted | removed | removed | removed |
| Binary composition root | permitted | forbidden | permitted | removed | removed | removed |

Port traits continue to use plain `async fn` syntax (desugars to `impl Future`,
executor-agnostic). No trait method signature may reference `monoio::`,
`service_async::`, or any runtime-specific type as a parameter, return type, or
associated type bound.

### AF_NETLINK transport — io_uring SQ/CQ model

The `NetlinkSocket` transport in `nlx-netlink` replaces the `AsyncFd` epoll
readiness pattern with `monoio::io::PollFd` (from the `poll-io` feature). The
`PollFd` readiness path drives `AF_NETLINK` fd wakeup via `IORING_OP_POLL_ADD`
on the io_uring SQ, replacing epoll `EPOLLIN`. The send/receive data path uses
`IORING_OP_SENDMSG` and `IORING_OP_RECVMSG` with registered buffers
(`IORING_REGISTER_BUFFERS`) pinned for the ring's lifetime.

The blocking-thread bridge model described in the io_uring netlink transport
analysis applies: each `NetlinkSocket::dump` call executes the SQ/CQ loop from
inside a dedicated blocking thread (`monoio::spawn_blocking` equivalent) to
avoid blocking the monoio executor. The `NetlinkSocket` public API is unchanged:

```
pub fn open(nl_family: i32) -> Result<Self>
pub async fn dump(&mut self, msg_type: u16, flags: u16, payload: &[u8]) -> Result<Vec<Vec<u8>>>
pub async fn request_single(...) -> Result<Option<Vec<u8>>>
pub async fn resolve_genl_family(&mut self, name: &str) -> Result<Option<u16>>
```

Minimum kernel version for the io_uring path: **5.7** (required for
`IOSQE_BUFFER_SELECT`). On kernel < 5.7, `NetlinkSocket::open` detects the
version via `rustix::system::uname()` and falls back to the `PollFd` readiness
path without registered buffers (pure `IORING_OP_POLL_ADD` + standard
`sendmsg`/`recvmsg` syscalls). On kernel < 5.1 the monoio `legacy` feature
activates the epoll path transparently.

### HTTP adapter replacement

`nlx-http` replaces `axum 0.8` + `tokio::net::TcpListener` with:

- `monoio::net::TcpListener` for the accept loop.
- `monoio-http 0.3` (feature `parsed`) for HTTP/1 framing.
- `service-async 0.2` for handler composition.

The three routes (`/metrics`, `/healthz`, `/ready`) are implemented as a
path-dispatch match inside a `service-async` handler. No axum `Router`,
`State`, tower middleware, or `IntoResponse` trait is used. The
`ScrapeTriggerPort`, `HealthPort`, `ReadinessPort`, and `MetricRegistryPort`
trait signatures are unchanged.

### Thread-per-core composition root

The binary replaces `#[tokio::main]` with a `std::thread::spawn` × N pattern
where each thread runs a monoio runtime instance:

```
Thread 0 (main)  — monoio::RuntimeBuilder HTTP accept + metrics encode
Thread 1         — monoio::RuntimeBuilder nlx-netlink dump (NETLINK_ROUTE)
Thread 2         — monoio::RuntimeBuilder nlx-netlink dump (NETLINK_NETFILTER)
Thread 3         — monoio::RuntimeBuilder nlx-netlink dump (NETLINK_GENERIC et al.)
```

Shared state between threads is **lock-free** (RCU). Each subsystem thread owns
one `arc_swap::ArcSwap<MetricSnapshot>`: a scrape pass builds a fresh immutable
`MetricSnapshot` and publishes it with an atomic `store()`; the HTTP thread reads
every subsystem's snapshot with a wait-free `load()`. No `Mutex`, `RwLock`, or
`tokio::sync` primitive is used anywhere — a reader (`/metrics`) never blocks a
writer (scrape) and vice versa. Per-collector self-telemetry counters
(`nft_scrape_collector_error_total`, `success`) use `AtomicU64` with `Relaxed`
ordering. `monoio::task::JoinHandle` replaces `tokio::task::JoinSet` for
intra-thread task fan-out.

### Seccomp and sysctl operational requirements

**io_uring requires explicit seccomp allowances.** The Kubernetes
`RuntimeDefault` seccomp profile (moby/containerd default) denies
`io_uring_setup(2)` (syscall 425), `io_uring_enter(2)` (426), and
`io_uring_register(2)` (427). A DaemonSet pod running under `RuntimeDefault`
will receive `EPERM` on `io_uring_setup` at startup and crash immediately.

**Required actions for container deployments:**

1. **Seccomp profile:** Deploy a Localhost custom profile to
   `/var/lib/kubelet/seccomp/nft-exporter-io-uring.json` on every node before
   the DaemonSet is applied. The profile must add `SCMP_ACT_ALLOW` for
   `io_uring_setup`, `io_uring_enter`, and `io_uring_register` while retaining
   `SCMP_ACT_ERRNO` for `execve`, `execveat`, `ptrace`, `bpf`, `perf_event_open`,
   and `clone(CLONE_NEWUSER)`. The DaemonSet `securityContext.seccompProfile`
   must change from `type: RuntimeDefault` to
   `type: Localhost, localhostProfile: nft-exporter-io-uring.json`.

2. **sysctl:** `kernel.io_uring_disabled` must be `0` on all target nodes.
   Value `1` blocks unprivileged processes (the exporter drops `CAP_NET_ADMIN`
   after socket init and has no `CAP_SYS_ADMIN`). Value `2` blocks all
   callers. CIS Level 2 hardening profiles for RHEL 9 and Ubuntu 24.04 may set
   this to `1` by default. Verify with `sysctl kernel.io_uring_disabled` before
   deploying.

3. **Kernel floor:** Minimum kernel `5.15 LTS` for DaemonSet deployments.
   The `deploy/k8s/daemonset.yaml` nodeAffinity must gate on kernel >= 5.15 and
   an init-container must verify `kernel.io_uring_disabled=0` at pod startup.

4. **systemd unit:** `SystemCallFilter` in
   `deploy/systemd/nft-exporter.service` must add `@io-uring` (systemd >= 249)
   or the explicit names `io_uring_setup io_uring_enter io_uring_register`
   (systemd < 249).

5. **epoll fallback:** Compile with `monoio = { features = ["iouring", "legacy"] }`.
   Set `MONOIO_DRIVER=legacy` to force the epoll path without recompiling. This
   allows the same binary to run in environments where io_uring is blocked. The
   transport and HTTP code are unaffected by driver selection.

**Security posture note:** io_uring maps SQ/CQ ring buffers shared with the
kernel into the process address space via `mmap`. This increases the attack
surface compared to the epoll baseline. The historical CVE rate for io_uring
(CVE-2022-29582, CVE-2023-2598, CVE-2024-0582, CVE-2024-1086) is materially
higher than for epoll. Nodes must be kept patched to kernel >= 6.6.14 (or >=
6.7.2) to close CVE-2024-0582. All ADR-0009 hardening invariants
(`allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`,
`MemoryDenyWriteExecute`, `ProtectKernelTunables`, AppArmor `runtime/default`,
capability drop after socket init) are retained unchanged.

### Workspace dependency changes

Removed from workspace: `tokio`, `mio`, `axum`, `tower`, `tower-http`.
Added to workspace:

```toml
[workspace.dependencies]
monoio      = { version = "0.2", features = ["iouring", "legacy", "macros", "signal", "poll-io"] }
monoio-http = { version = "0.3", features = ["parsed"] }
service-async = { version = "0.2" }
arc-swap    = { version = "1.7" }   # lock-free RCU snapshot sharing (no Mutex/RwLock)
```

### Lock-free invariant

The exporter is **lock-free**: no `std::sync::Mutex`, `std::sync::RwLock`,
`parking_lot`, or `tokio::sync` lock appears in any crate. Cross-thread sharing
uses `arc_swap::ArcSwap` (RCU) for snapshots and `core::sync::atomic` for
counters. A `cargo deny` / grep CI gate rejects re-introduction of `Mutex`/`RwLock`.

The `io-uring` crate is not added as a workspace dependency; monoio manages its
own `io-uring` transitive dependency internally. This avoids version skew.

### Link to superseded ADR

This ADR supersedes ADR-0014. ADR-0014's hexagonal confinement invariant table,
the port-trait runtime-agnostic rule, and the `cargo deny` ban on `async-std`,
`smol`, and `async-io` remain in force. Only the permitted runtime crates in the
adapter layer change: `tokio` and `mio` are replaced by `monoio`, `monoio-http`,
and `service-async`. The JoinSet fan-out, per-collector timeout, panic isolation,
and netns isolation decisions from ADR-0007 remain valid; their implementation
moves from `tokio::task::JoinSet` to `monoio::task::JoinHandle` collection.

### Consequences

**Positive:**

- `AF_NETLINK` send/receive uses `IORING_OP_SENDMSG`/`IORING_OP_RECVMSG` with
  registered buffers, eliminating per-dump buffer allocation and epoll wakeup
  overhead.
- Full tokio removal eliminates the work-stealing scheduler overhead for a
  workload that is serial-per-subsystem.
- The `legacy` feature provides a transparent epoll fallback for environments
  where `io_uring_setup` is blocked without any code change.
- Thread-per-core model simplifies reasoning about task locality and buffer
  ownership.

**Negative:**

- `monoio-http` + `service-async` are ByteDance-internal abstractions with
  limited community documentation. The HTTP adapter must be kept under 100 lines
  with full rustdoc coverage.
- Replacing axum's `Router`, `State`, and tower middleware requires rewriting
  `nlx-http/src/server.rs`. Estimated scope: 200–300 lines.
- No `JoinSet` equivalent: fan-out uses `monoio::task::JoinHandle` + manual
  result collection.
- Deployment teams must pre-provision the Localhost seccomp profile on every
  node and verify the `io_uring_disabled` sysctl. Missing either causes
  `CrashLoopBackOff`.
