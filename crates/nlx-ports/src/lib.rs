//! # nlx-ports — Hexagonal Port Trait Definitions
//!
//! **Hexagonal role: PORTS (application boundary).**
//!
//! This crate declares *all* driving ports (left-side, inbound) and driven ports
//! (right-side, outbound) that separate the application core from infrastructure.
//!
//! ## Driving ports (left-side — inbound adapters call these)
//!
//! - [`driving::ScrapeTriggerPort`] — triggers a full metric scrape cycle.
//! - [`driving::HealthPort`] — liveness probe.
//! - [`driving::ReadinessPort`] — readiness probe.
//!
//! ## Driven ports (right-side — infrastructure adapters implement these)
//!
//! One trait per netlink subsystem collector plus registry, clock, and config
//! ports.  All async methods use native AFIT (`async fn` in traits, stabilised
//! Rust 1.75, required by `rust-version = "1.87"`).
//!
//! ## Hexagonal invariant
//!
//! This crate depends only on `nlx-domain`.  It MUST NOT import `tokio`, `mio`,
//! `axum`, `prometheus-client`, `rustix`, `linux-raw-sys`, `zerocopy`,
//! `bytemuck`, `byteorder`, `clap`, `figment`, or `serde_json`.
//! Enforcement: `hexagonal.rego` (Rego deny) + `cargo deny` bans + ADR-0002 /
//! ADR-0014.

#![deny(missing_docs)]

pub mod collector;
pub mod driven;
pub mod driving;
pub mod error;
