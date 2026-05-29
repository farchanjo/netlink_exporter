//! # nlx-metrics — `OpenMetrics` Text Exposition Adapter
//!
//! **Hexagonal role: DRIVEN ADAPTER (metrics registry).**
//!
//! This crate provides [`PrometheusRegistryAdapter`] which implements
//! [`nlx_ports::driven::MetricRegistryPort`] using `prometheus-client`.
//!
//! The adapter accepts [`nlx_domain::metric::MetricSample`] values produced
//! by collectors and maps them into the `prometheus-client` registry.  The
//! `/metrics` HTTP endpoint calls [`MetricRegistryPort::encode_text`] to obtain
//! the UTF-8 `OpenMetrics` text exposition.
//!
//! ## Hexagonal note
//!
//! `prometheus-client` is confined to this crate.  It must not appear in
//! `nlx-domain`, `nlx-ports`, or any collector crate (ADR-0002, ADR-0006).

#![deny(missing_docs)]

mod registry;

pub use registry::PrometheusRegistryAdapter;
