//! # nlx-netlink — Driven Infrastructure Adapters
//!
//! **Hexagonal role: DRIVEN ADAPTERS (right-side, infrastructure).**
//!
//! This crate owns:
//!
//! - [`transport`] — `NetlinkSocket` wrapper: non-blocking `AF_NETLINK` fd
//!   created via `rustix`, driven by **monoio 0.2** with `io_uring` as the
//!   kernel I/O backend (ADR-0023, ADR-0024).  The fd is registered with the
//!   monoio executor using [`monoio::io::PollFd`] (from the `poll-io`
//!   feature), which issues `IORING_OP_POLL_ADD` on the `io_uring` SQ for
//!   readiness.  Send/receive use plain `IORING_OP_SEND` / `IORING_OP_RECV`
//!   (no registered buffers, no sendmsg/recvmsg variants) with a ring depth
//!   of **32 SQEs** per `spawn_blocking` call.  The dump loop executes from
//!   inside `monoio::spawn_blocking` so it never blocks the single monoio
//!   executor thread.
//!
//! - [`collectors`] — one module per netlink subsystem implementing the
//!   corresponding driven port trait from `nlx-ports` *and* the
//!   [`nlx_ports::collector::Collector`] strategy trait.
//!
//! ## Runtime confinement
//!
//! `monoio` lives exclusively in this crate and in the binary composition
//! root (`netlink_exporter`).  `tokio`, `mio`, and `axum` are **absent** from
//! the dependency graph (ADR-0002, ADR-0023).  Domain-core crates
//! (`nlx-domain`, `nlx-ports`) must not import `monoio` or any other runtime
//! crate.
//!
//! ## Executor model
//!
//! The binary runs **one monoio thread** (the composition root thread) with a
//! `monoio-http 0.3` HTTP/1 server (hand-rolled, not axum).  Each scrape
//! fan-out uses `monoio::spawn_blocking` per enabled collector; those tasks
//! execute the `io_uring` `IORING_OP_SEND`/`IORING_OP_RECV` loop and return a
//! `MetricSnapshot` via a channel.  There is no work-stealing multi-thread
//! scheduler.
//!
//! ## `PollFd` usage note
//!
//! [`monoio::io::PollFd::new`] registers the fd with the current monoio
//! `io_uring` instance.  All `NetlinkSocket::open_*` constructors must be
//! called from within a monoio async context.  On kernels < 5.1, monoio's
//! `legacy` feature activates an epoll fallback transparently (ADR-0023).

#![deny(missing_docs)]

pub mod collectors;
pub mod transport;
pub mod wire;
