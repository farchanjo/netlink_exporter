//! # nlx-http — Driving HTTP Adapter
//!
//! **Hexagonal role: DRIVING ADAPTER (left-side, inbound).**
//!
//! This crate implements a minimal hand-rolled HTTP/1.1 server over
//! [`monoio::net::TcpListener`] (`io_uring`, single-threaded, ADR-0023).
//! There is **no axum, no tower, and no hyper** in this crate or its
//! dependency tree — those frameworks were removed when the runtime was
//! migrated from `tokio` to `monoio`.
//!
//! Three routes are served:
//!
//! - `GET /metrics` → [`nlx_ports::driving::ScrapeTriggerPort::scrape`] →
//!   Prometheus 0.0.4 text body (`Content-Type: text/plain; version=0.0.4`).
//! - `GET /healthz`  → [`nlx_ports::driving::HealthPort::is_healthy`] → 200/503.
//! - `GET /ready`    → [`nlx_ports::driving::ReadinessPort::is_ready`] → 200/503.
//!
//! Default listen address: `0.0.0.0:33400` (ADR-0010).
//!
//! ## Hexagonal note
//!
//! HTTP framing and request parsing are confined to this crate.  They must not
//! appear in `nlx-domain`, `nlx-ports`, or collector crates (ADR-0002).
//!
//! ## `BufResult` ownership model
//!
//! monoio `AsyncReadRent`/`AsyncWriteRentExt` use an owned-buffer contract:
//! the `Vec<u8>` is moved into the syscall, pinned for the `io_uring` SQE
//! lifetime, and returned in the `(Result, Vec<u8>)` tuple after the CQE fires.
//! All I/O in this crate follows that pattern.

#![deny(missing_docs)]

mod server;

pub use server::{AxumHttpAdapter, HttpAdapterConfig};
