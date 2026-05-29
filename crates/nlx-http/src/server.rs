//! `AxumHttpAdapter` — Axum-backed driving adapter.

use std::sync::Arc;

use axum::{
    Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use thiserror::Error;
use tracing::info;

use nlx_ports::driven::MetricRegistryPort;
use nlx_ports::driving::{HealthPort, ReadinessPort, ScrapeTriggerPort};

/// Configuration for the HTTP adapter.
#[derive(Debug, Clone)]
pub struct HttpAdapterConfig {
    /// Listen address and port (e.g. `"0.0.0.0:9456"`).
    pub listen_addr: String,
}

impl Default for HttpAdapterConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:9456".to_owned(),
        }
    }
}

/// Errors returned by [`AxumHttpAdapter::serve`].
#[derive(Debug, Error)]
pub enum HttpAdapterError {
    /// TCP bind or server startup failed.
    #[error("HTTP server bind/serve error: {0}")]
    Serve(String),
}

/// Shared application state injected into Axum handlers.
struct AppState<S, H, R, M> {
    scrape: Arc<S>,
    health: Arc<H>,
    readiness: Arc<R>,
    /// Metrics registry used to encode the response body for `GET /metrics`.
    registry: Arc<M>,
}

/// Driving Axum HTTP adapter.
///
/// Type parameters `S`, `H`, `R`, and `M` are the concrete implementations of
/// [`ScrapeTriggerPort`], [`HealthPort`], [`ReadinessPort`], and
/// [`MetricRegistryPort`] respectively.
/// They are injected at construction time by the composition root.
pub struct AxumHttpAdapter {
    config: HttpAdapterConfig,
}

impl std::fmt::Debug for AxumHttpAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AxumHttpAdapter")
            .field("listen_addr", &self.config.listen_addr)
            .finish()
    }
}

impl AxumHttpAdapter {
    /// Create a new adapter with the given configuration.
    #[must_use]
    pub fn new(config: HttpAdapterConfig) -> Self {
        Self { config }
    }

    /// Build the Axum [`Router`] wired to the four port implementations.
    ///
    /// The returned router can be passed to `axum::serve` or used in tests
    /// without starting a TCP listener.
    pub fn build_router<S, H, R, M>(
        &self,
        scrape: Arc<S>,
        health: Arc<H>,
        readiness: Arc<R>,
        registry: Arc<M>,
    ) -> Router
    where
        S: ScrapeTriggerPort + 'static,
        H: HealthPort + 'static,
        R: ReadinessPort + 'static,
        M: MetricRegistryPort + 'static,
    {
        let state = Arc::new(AppState {
            scrape,
            health,
            readiness,
            registry,
        });

        Router::new()
            .route("/metrics", get(metrics_handler::<S, H, R, M>))
            .route("/healthz", get(healthz_handler::<S, H, R, M>))
            .route("/ready", get(ready_handler::<S, H, R, M>))
            .with_state(state)
    }

    /// Bind a TCP listener and serve until the future is dropped.
    ///
    /// # Errors
    ///
    /// Returns [`HttpAdapterError::Serve`] if the TCP bind fails.
    pub async fn serve<S, H, R, M>(
        &self,
        scrape: Arc<S>,
        health: Arc<H>,
        readiness: Arc<R>,
        registry: Arc<M>,
    ) -> Result<(), HttpAdapterError>
    where
        S: ScrapeTriggerPort + 'static,
        H: HealthPort + 'static,
        R: ReadinessPort + 'static,
        M: MetricRegistryPort + 'static,
    {
        let router = self.build_router(scrape, health, readiness, registry);

        let listener = tokio::net::TcpListener::bind(&self.config.listen_addr)
            .await
            .map_err(|e| HttpAdapterError::Serve(e.to_string()))?;

        info!(addr = %self.config.listen_addr, "HTTP adapter listening");

        axum::serve(listener, router)
            .await
            .map_err(|e| HttpAdapterError::Serve(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Axum handler implementations
// ---------------------------------------------------------------------------

/// `GET /metrics` — trigger a scrape and return OpenMetrics text.
///
/// The handler first calls `scrape()` (which internally calls
/// `MetricRegistryPort::update_samples`), then reads back the encoded body via
/// `MetricRegistryPort::encode_text`.
async fn metrics_handler<S, H, R, M>(State(state): State<Arc<AppState<S, H, R, M>>>) -> Response
where
    S: ScrapeTriggerPort,
    H: HealthPort,
    R: ReadinessPort,
    M: MetricRegistryPort,
{
    if let Err(e) = state.scrape.scrape().await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("scrape error: {e}"),
        )
            .into_response();
    }

    match state.registry.encode_text().await {
        Ok(body) => (
            StatusCode::OK,
            [(
                "content-type",
                "application/openmetrics-text; version=1.0.0; charset=utf-8",
            )],
            body,
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("encode error: {e}"),
        )
            .into_response(),
    }
}

/// `GET /healthz` — liveness probe.
async fn healthz_handler<S, H, R, M>(State(state): State<Arc<AppState<S, H, R, M>>>) -> StatusCode
where
    S: ScrapeTriggerPort,
    H: HealthPort,
    R: ReadinessPort,
    M: MetricRegistryPort,
{
    if state.health.is_healthy().await {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

/// `GET /ready` — readiness probe.
async fn ready_handler<S, H, R, M>(State(state): State<Arc<AppState<S, H, R, M>>>) -> StatusCode
where
    S: ScrapeTriggerPort,
    H: HealthPort,
    R: ReadinessPort,
    M: MetricRegistryPort,
{
    if state.readiness.is_ready().await {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}
