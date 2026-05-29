//! Driving (left-side) port traits.
//!
//! These traits are called by inbound adapters (e.g., the Axum HTTP adapter)
//! to trigger application-core behaviour.  Implementations live in the
//! application core or in the composition root.

use nlx_domain::metric::MetricSample;

use crate::error::CollectError;

/// Triggers a full metric scrape cycle across all enabled collectors.
///
/// The HTTP `/metrics` handler calls this port.  The application core drives
/// the fan-out, aggregates results, and updates the `MetricRegistryPort`.
pub trait ScrapeTriggerPort: Send + Sync {
    /// Run one complete scrape across all enabled collectors.
    ///
    /// Returns the full set of [`MetricSample`]s produced this cycle.
    ///
    /// # Errors
    ///
    /// Returns [`CollectError`] if the scrape fails catastrophically (e.g. all
    /// critical collectors errored).  Partial failures are represented in
    /// self-telemetry metrics and do not propagate as `Err`.
    fn scrape(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<MetricSample>, CollectError>> + Send;
}

/// Liveness probe port.
///
/// The HTTP `/healthz` handler calls this port.  Returns `true` when the
/// exporter process is alive and its internal state machine is consistent.
pub trait HealthPort: Send + Sync {
    /// Returns `true` if the exporter is alive.
    fn is_healthy(&self) -> impl std::future::Future<Output = bool> + Send;
}

/// Readiness probe port.
///
/// The HTTP `/ready` handler calls this port.  Returns `true` when the
/// exporter has completed its initial startup probe and is ready to serve
/// scrape requests.
pub trait ReadinessPort: Send + Sync {
    /// Returns `true` if the exporter is ready to serve traffic.
    fn is_ready(&self) -> impl std::future::Future<Output = bool> + Send;
}
