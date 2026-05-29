//! # nlx-http — Driving HTTP Adapter
//!
//! **Hexagonal role: DRIVING ADAPTER (left-side, inbound).**
//!
//! This crate wires an Axum HTTP server to the driving port traits:
//!
//! - `GET /metrics` → [`nlx_ports::driving::ScrapeTriggerPort::scrape`] →
//!   UTF-8 `OpenMetrics` text body.
//! - `GET /healthz`  → [`nlx_ports::driving::HealthPort::is_healthy`] → 200/503.
//! - `GET /ready`    → [`nlx_ports::driving::ReadinessPort::is_ready`] → 200/503.
//!
//! Default listen address: `0.0.0.0:9456` (ADR-0010).
//!
//! ## Hexagonal note
//!
//! `axum` and `tower` are confined to this crate and the binary composition
//! root.  They must not appear in `nlx-domain`, `nlx-ports`, or collector
//! crates (ADR-0002).

#![deny(missing_docs)]

mod server;

pub use server::{AxumHttpAdapter, HttpAdapterConfig};
