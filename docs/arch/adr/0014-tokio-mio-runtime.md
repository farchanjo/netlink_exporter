---
status: superseded
date: 2026-05-28
deciders: [eonf]
consulted: []
informed: []
supersedes: ADR-0007
superseded-by: ADR-0023
---

# Confine tokio 1.52 and mio to driven adapters only; use AsyncFd for AF_NETLINK fd readiness

Superseded by ADR-0023.

Supersedes ADR-0007.

## Context and Problem Statement

ADR-0007 accepted tokio 1.52 as the single async runtime and documented its
`JoinSet` fan-out and per-collector timeout model. It did not specify at which
architectural layer `tokio` and the underlying `mio` polling library may appear,
nor did it make the `mio` dependency explicit. As the workspace grows, there is a
risk that domain-core crates or port-trait definitions import `tokio` directly
for runtime-specific types (e.g., `tokio::net::UnixStream`, `tokio::sync::Mutex`),
violating the hexagonal no-infra-import invariant established in ADR-0002.

A concrete trigger: the `nlx-netlink` driven adapter (successor to the raw-socket
layer described in ADR-0011) wraps a non-blocking raw `AF_NETLINK` fd in
`tokio::io::unix::AsyncFd<RawFd>` to integrate with the tokio reactor. This
construct depends on both `tokio` (for `AsyncFd`) and `mio` (for the epoll
readiness integration that `AsyncFd` invokes internally). Neither dependency
belongs in domain-core crates or port-trait definitions. Without an explicit
policy, the Rego hexagonal guard would warn on any `tokio` dependency in a
domain-core crate but would not flag `mio`.

The workspace needs a precise rule that:

1. Pins where `tokio` and `mio` may appear.
2. Makes the `mio` dependency explicit in `Cargo.toml` so `cargo deny` can audit it.
3. Keeps port traits runtime-agnostic so the domain can be exercised with any
   executor in tests.

## Considered Options

- **Blocking thread-per-socket**: one `std::thread` per netlink socket that blocks
  on `recvmsg(2)`. No async runtime dependency in the adapter. Scrape fan-out is
  managed with `std::sync::mpsc` channels.
- **tokio AsyncFd + mio epoll** (chosen): non-blocking `AF_NETLINK` fd registered
  with the tokio reactor via `AsyncFd`; the fd is woken by epoll readiness events
  managed by `mio`. Runtime confined to the `nlx-netlink` driven adapter and the
  binary composition root; domain-core and port traits are runtime-agnostic.
- **Raw mio Poll loop without tokio**: drive a `mio::Poll` event loop directly
  inside each adapter, without tokio. Eliminates the tokio executor but also
  eliminates `JoinSet` fan-out, timeout, and cancellation, requiring reimplementation
  of all concurrency primitives.

## Decision Outcome

**Chosen option: tokio AsyncFd + mio epoll, confined to driven adapters and the
composition root.**

### Runtime confinement invariant

The hexagonal boundary established by ADR-0002 is extended with the following
adapter-confinement rule (also enforced by the updated `hexagonal.rego` policy):

| Layer | tokio | mio |
|---|---|---|
| Domain-core crates (`*_core`, `nft_exporter_domain_*`) | forbidden | forbidden |
| Port-trait definitions (traits declared in domain-core) | runtime-agnostic `async fn` only; no `tokio::` or `mio::` types as bounds or associated types | forbidden |
| Driven adapter crates (`nlx-netlink`, `nft_exporter_adapter_*`) | permitted — `tokio::io::unix::AsyncFd`, `tokio::task::JoinSet`, `tokio::time::timeout`, `tokio::sync::oneshot` | permitted — as indirect dep via tokio; explicit `mio` dependency pinned |
| Composition root (`bin/nft_exporter`) | permitted — `#[tokio::main]`, `tokio::runtime::Builder` | permitted |

**Port traits are runtime-agnostic.** Driven port traits use `async fn` syntax
(stabilized in Rust 1.75, required by `rust-version = "1.87"` in `Cargo.toml`).
The `async fn` in a trait desugars to `impl Future`, which is executor-agnostic.
No trait method signature may reference `tokio::`, `mio::`, or any runtime-specific
type as a parameter, return type, or bound.

### AsyncFd integration for AF_NETLINK fd readiness

The `nlx-netlink` driven adapter owns the raw `AF_NETLINK` fd lifecycle. The fd
is created non-blocking via `rustix::net::socket_with` with `O_NONBLOCK`
(ADR-0011). Readiness on the fd is integrated with the tokio reactor as follows:

```
let async_fd = tokio::io::unix::AsyncFd::new(raw_fd)?;
loop {
    let mut guard = async_fd.readable().await?;
    match guard.try_io(|inner| recvmsg_nonblock(inner.get_ref())) {
        Ok(result) => { /* process nlmsg */ }
        Err(_would_block) => { guard.clear_ready(); }
    }
}
```

`AsyncFd::readable()` suspends the calling task until `mio` reports the fd as
readable via epoll (`EPOLLIN`). The underlying `mio::Registry::register` call is
made by `AsyncFd::new`; `mio` is therefore a required runtime dependency of the
`nlx-netlink` adapter crate, not of domain-core or ports.

### Explicit mio dependency

`mio` must appear in the `[dependencies]` section of `Cargo.toml` for the
`nlx-netlink` adapter crate with the `os-poll` and `os-ext` feature flags:

```toml
# Cargo.toml of nlx-netlink
[dependencies]
mio = { version = "1.0", features = ["os-poll", "os-ext"] }
tokio = { version = "1.52", features = ["rt-multi-thread", "macros", "time", "sync", "io-util"] }
```

Making `mio` explicit, rather than relying on tokio's re-export, enables
`cargo deny` to audit the `mio` version independently and prevents silent
upgrades when tokio bumps its internal `mio` pin.

### Cargo deny additions

The `deny.toml` workspace ban list gains the following entries to prevent
runtime leakage into domain-core crates. These bans are companion to the Rego
policy and provide a CI-enforced hard gate:

```toml
[[bans.deny]]
name = "async-std"

[[bans.deny]]
name = "smol"

[[bans.deny]]
name = "async-io"
```

The existing tokio ban in domain-core is enforced via Rego warn-level deny
(ADR-0002 / `hexagonal.rego`). `mio` in domain-core is now also a deny-level
Rego violation (see updated `hexagonal.rego`).

### Consequences

- Positive: Port traits with `async fn` desugar to `impl Future`, keeping the
  domain testable with a lightweight single-threaded test executor
  (`tokio::test` or any `futures::executor::block_on`-style runner) without
  importing the tokio multi-thread runtime.
- Positive: The `mio` version is pinned explicitly in the adapter crate, giving
  `cargo deny` visibility for CVE auditing.
- Positive: The Rego deny rule in `hexagonal.rego` now flags both `tokio` and
  `mio` when they appear as direct dependencies of domain-core crates.
- Negative: Developers writing new adapter crates must be aware that
  `AsyncFd::new` registers the fd with the current tokio runtime; calling it
  outside a tokio context panics. This is documented in the `nlx-netlink`
  adapter crate's module-level rustdoc.
- Negative: The explicit `mio` version pin in the adapter crate may lag behind
  tokio's internal pin if a semver-compatible `mio` update is released; a
  `cargo update --precise` is required in that case. `cargo deny` will surface
  the version mismatch.

**Link to superseded ADR:** This ADR supersedes ADR-0007, which chose tokio
generically without specifying layer confinement or making mio explicit. The
`JoinSet` fan-out, per-collector timeout, panic isolation, and netns isolation
decisions in ADR-0007 remain in force; only the confinement and mio-explicit
rules are added here.
