//! # nlx-netlink — Driven Infrastructure Adapters
//!
//! **Hexagonal role: DRIVEN ADAPTERS (right-side, infrastructure).**
//!
//! This crate owns:
//!
//! - [`transport`] — `NetlinkSocket` wrapper: non-blocking `AF_NETLINK` fd
//!   created via `rustix`, registered with the tokio reactor using
//!   `tokio::io::unix::AsyncFd` for `mio`-backed readiness (ADR-0014 §AsyncFd).
//!
//! - [`collectors`] — one module per netlink subsystem implementing the
//!   corresponding driven port trait from `nlx-ports` *and* the
//!   [`nlx_ports::collector::Collector`] strategy trait.
//!
//! ## Runtime confinement
//!
//! `tokio` and `mio` live exclusively in this crate and in the binary
//! composition root (`netlink_exporter`).  They must not appear in
//! `nlx-domain` or `nlx-ports` (ADR-0002, ADR-0014).
//!
//! ## `AsyncFd` usage note
//!
//! `AsyncFd::new` registers the fd with the current tokio runtime.  Calling
//! it outside a `#[tokio::main]` context panics.  All `NetlinkSocket::open_*`
//! constructors must be called from within an async tokio task.

#![deny(missing_docs)]

pub mod collectors;
pub mod transport;
pub mod wire;
