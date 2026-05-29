//! `PrometheusRegistryAdapter` — implements `MetricRegistryPort` with
//! `prometheus-client`.

use nlx_domain::metric::{MetricKind, MetricSample, MetricValue};
use nlx_ports::driven::MetricRegistryPort;
use prometheus_client::{
    encoding::text::encode,
    metrics::{counter::Counter, gauge::Gauge},
    registry::Registry,
};
use std::sync::Mutex;
use thiserror::Error;

/// Errors emitted by the prometheus-client adapter.
#[derive(Debug, Error)]
pub enum RegistryError {
    /// Text encoding failed.
    #[error("OpenMetrics encode error: {0}")]
    Encode(String),
    /// Registry is poisoned (Mutex was poisoned by a panicking thread).
    #[error("metric registry lock poisoned")]
    LockPoisoned,
}

/// Driven adapter that maps [`MetricSample`]s into a `prometheus-client`
/// [`Registry`] and encodes the result as OpenMetrics text.
///
/// The registry is rebuilt on each [`MetricRegistryPort::update_samples`]
/// call to guarantee that stale series from previous scrapes are not retained.
pub struct PrometheusRegistryAdapter {
    /// Serialised access to the registry.  Rebuilt each scrape cycle.
    inner: Mutex<Registry>,
}

impl std::fmt::Debug for PrometheusRegistryAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrometheusRegistryAdapter").finish()
    }
}

impl PrometheusRegistryAdapter {
    /// Construct a new adapter with an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Registry::default()),
        }
    }
}

impl Default for PrometheusRegistryAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricRegistryPort for PrometheusRegistryAdapter {
    async fn update_samples(&self, samples: Vec<MetricSample>) -> Result<(), String> {
        // TODO(impl): rebuild registry from samples.  For each unique (name, kind),
        // register a prometheus-client metric family; for each sample,
        // record the label-set observation.
        // Stub: rebuild an empty registry to preserve correct semantics shape.
        let mut registry = Registry::default();
        apply_samples(&mut registry, &samples).map_err(|e| e.to_string())?;
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| "metric registry lock poisoned")?;
        *guard = registry;
        Ok(())
    }

    async fn encode_text(&self) -> Result<String, String> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| "metric registry lock poisoned".to_owned())?;
        let mut buf = String::new();
        encode(&mut buf, &guard).map_err(|e| e.to_string())?;
        Ok(buf)
    }
}

/// Register all samples into `registry`.
///
/// # Errors
///
/// Returns [`RegistryError`] if text encoding fails.
fn apply_samples(_registry: &mut Registry, samples: &[MetricSample]) -> Result<(), RegistryError> {
    // TODO(impl): group samples by (name, kind); register metric families;
    // observe values with label sets.
    // Stub: iterate to validate the shape compiles.
    for sample in samples {
        match (&sample.kind, &sample.value) {
            (MetricKind::Counter, MetricValue::U64(_v)) => {
                // TODO(impl): find-or-create Counter<u64> family, observe.
                let _: Counter = Counter::default();
            }
            (MetricKind::Gauge, MetricValue::F64(_v)) => {
                // TODO(impl): find-or-create Gauge<f64> family, set.
                let _: Gauge = Gauge::default();
            }
            _ => {
                // TODO(impl): handle remaining combinations.
            }
        }
    }
    Ok(())
}
