//! Collector strategy trait.
//!
//! Every collector (rtnetlink, tc, conntrack, nftables, sock-diag, ethtool,
//! ipvs, wireguard, devlink, drop-monitor, xfrm, conntrack-expect) implements
//! this trait.  The application core iterates over `dyn Collector` references
//! to run a fan-out scrape; individual implementations live in `nlx-netlink`.
//!
//! ## Object safety note
//!
//! Rust's AFIT (async fn in traits) does not yet yield object-safe traits
//! (stabilised Rust 1.75, but `dyn Trait` dispatch requires explicit
//! `Pin<Box<dyn Future>>` return types until the feature matures in a later
//! release).  This trait uses explicit `Pin<Box<dyn Future<Output=…> + Send>>`
//! returns so that `Box<dyn Collector>` collections compile correctly in the
//! composition root.  Implementors may use `async fn` bodies that internally
//! return `Box::pin(async move { … })`.
//!
//! Neither `tokio` nor `mio` types appear in any signature (ADR-0014).

use std::{future::Future, pin::Pin};

use crate::error::CollectError;
use nlx_domain::metric::MetricSample;

/// Heap-allocated boxed future alias used by object-safe async methods.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Strategy trait implemented by every netlink collector.
///
/// The application core calls [`collect`] on each enabled collector during a
/// scrape cycle and aggregates the returned [`MetricSample`] stream into the
/// `MetricRegistryPort`.
///
/// [`collect`]: Collector::collect
pub trait Collector: Send + Sync {
    /// Unique, stable name for this collector, used as the `collector` label
    /// value in self-telemetry metrics (e.g. `"rtnetlink"`, `"conntrack"`).
    fn name(&self) -> &str;

    /// Collect all metrics for one scrape cycle.
    ///
    /// Implementations may open a fresh netlink socket per call or reuse a
    /// pooled one.  The returned `Vec` may be empty when the subsystem is
    /// available but has no data to report.
    ///
    /// # Errors
    ///
    /// Returns [`CollectError`] on socket I/O failure, parse errors, timeout,
    /// or subsystem unavailability.
    fn collect(&self) -> BoxFuture<'_, Result<Vec<MetricSample>, CollectError>>;

    /// Probe whether the collector's kernel subsystem is available.
    ///
    /// Called once at startup to populate
    /// `nft_scrape_collector_available{collector=<name>}`.  A return value of
    /// `false` means the scrape will be skipped and the metric will be 0.
    fn probe_available(&self) -> BoxFuture<'_, bool>;
}
