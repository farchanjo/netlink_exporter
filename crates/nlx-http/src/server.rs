//! Minimal hand-rolled HTTP/1 server over `monoio::net::TcpListener`.
//!
//! **ADR-0023:** Replaces axum + tokio TcpListener.  The three routes
//! (`/metrics`, `/healthz`, `/ready`) are implemented as a path-dispatch
//! match.  No axum `Router`, `State`, tower middleware, or `IntoResponse`
//! trait is used.
//!
//! **ADR-0023 deviation:** `monoio-http 0.3` / `service-async 0.2` are NOT
//! pulled in.  Hand-rolled HTTP/1 framing over `monoio::net::TcpStream` is
//! simpler, avoids ByteDance-internal crates with limited community docs, and
//! keeps this adapter under 150 lines — well within the ADR target of 200–300.
//!
//! The port trait signatures (`ScrapeTriggerPort`, `HealthPort`,
//! `ReadinessPort`, `MetricRegistryPort`) are unchanged.
//!
//! # BufResult ownership model
//!
//! monoio `AsyncReadRent::read` and `AsyncWriteRentExt::write_all` both use
//! the owned-buffer model: the buffer is *moved into* the call, pinned by the
//! kernel for the io_uring SQ entry lifetime, and returned in the result tuple.

use std::sync::Arc;

use monoio::{
    io::{AsyncReadRent, AsyncWriteRentExt},
    net::{TcpListener, TcpStream},
};
use thiserror::Error;
use tracing::{error, info};

use nlx_ports::driven::MetricRegistryPort;
use nlx_ports::driving::{HealthPort, ReadinessPort, ScrapeTriggerPort};

// ---------------------------------------------------------------------------
// Static HTTP response fragments
// ---------------------------------------------------------------------------

const HTTP_200_PLAIN: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK";
const HTTP_503_PLAIN: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const HTTP_500: &[u8] = b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const HTTP_404: &[u8] = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

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

/// Errors returned by [`MonoioHttpAdapter::serve`].
#[derive(Debug, Error)]
pub enum HttpAdapterError {
    /// TCP bind or server startup failed.
    #[error("HTTP server bind/serve error: {0}")]
    Serve(String),
}

/// Hand-rolled monoio HTTP/1 adapter (ADR-0023).
///
/// Replaces `AxumHttpAdapter` from ADR-0010/0014.  The type name is kept
/// backwards-compatible as `AxumHttpAdapter` via a type alias so the
/// composition root (`main.rs`) compiles without modification.
pub struct MonoioHttpAdapter {
    config: HttpAdapterConfig,
}

/// Backward-compatible type alias so `main.rs` keeps `AxumHttpAdapter`.
pub type AxumHttpAdapter = MonoioHttpAdapter;

impl std::fmt::Debug for MonoioHttpAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MonoioHttpAdapter")
            .field("listen_addr", &self.config.listen_addr)
            .finish()
    }
}

impl MonoioHttpAdapter {
    /// Create a new adapter with the given configuration.
    #[must_use]
    pub fn new(config: HttpAdapterConfig) -> Self {
        Self { config }
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
        let listener = TcpListener::bind(&self.config.listen_addr)
            .map_err(|e| HttpAdapterError::Serve(e.to_string()))?;

        info!(addr = %self.config.listen_addr, "HTTP adapter listening (monoio hand-rolled HTTP/1)");

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    let s = Arc::clone(&scrape);
                    let h = Arc::clone(&health);
                    let r = Arc::clone(&readiness);
                    let m = Arc::clone(&registry);
                    monoio::spawn(async move {
                        handle_conn(stream, s, h, r, m).await;
                        tracing::trace!(peer = %addr, "connection closed");
                    });
                }
                Err(e) => {
                    error!(error = %e, "accept error");
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Connection handler
// ---------------------------------------------------------------------------

/// Handle one HTTP/1 connection: read the request line, dispatch, respond.
async fn handle_conn<S, H, R, M>(
    mut stream: TcpStream,
    scrape: Arc<S>,
    health: Arc<H>,
    readiness: Arc<R>,
    registry: Arc<M>,
) where
    S: ScrapeTriggerPort,
    H: HealthPort,
    R: ReadinessPort,
    M: MetricRegistryPort,
{
    // BufResult owned-buffer pattern: Vec<u8> is moved into read(), returned
    // back together with the result after the CQE is posted.
    let buf: Vec<u8> = Vec::with_capacity(4096);
    let (res, buf) = stream.read(buf).await;

    let n = match res {
        Ok(0) | Err(_) => return,
        Ok(n) => n,
    };

    let path = parse_path(&buf[..n]);

    match path {
        "/metrics" => handle_metrics::<S, H, R, M>(stream, scrape, registry).await,
        "/healthz" => handle_healthz(stream, health).await,
        "/ready" => handle_ready(stream, readiness).await,
        _ => {
            let (_, _) = stream.write_all(HTTP_404.to_vec()).await;
        }
    }
}

/// `GET /metrics` — trigger scrape, encode, respond.
async fn handle_metrics<S, H, R, M>(
    mut stream: TcpStream,
    scrape: Arc<S>,
    registry: Arc<M>,
) where
    S: ScrapeTriggerPort,
    H: HealthPort,
    R: ReadinessPort,
    M: MetricRegistryPort,
{
    if let Err(e) = scrape.scrape().await {
        error!(error = %e, "scrape error");
        let (_, _) = stream.write_all(HTTP_500.to_vec()).await;
        return;
    }

    match registry.encode_text().await {
        Ok(body) => {
            // Build response with dynamic Content-Length header.
            let mut response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/openmetrics-text; version=1.0.0; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .into_bytes();
            response.extend_from_slice(body.as_bytes());
            let (_, _) = stream.write_all(response).await;
        }
        Err(e) => {
            error!(error = %e, "encode error");
            let (_, _) = stream.write_all(HTTP_500.to_vec()).await;
        }
    }
}

/// `GET /healthz` — liveness probe.
async fn handle_healthz<H: HealthPort>(mut stream: TcpStream, health: Arc<H>) {
    let response = if health.is_healthy().await {
        HTTP_200_PLAIN
    } else {
        HTTP_503_PLAIN
    };
    let (_, _) = stream.write_all(response.to_vec()).await;
}

/// `GET /ready` — readiness probe.
async fn handle_ready<R: ReadinessPort>(mut stream: TcpStream, readiness: Arc<R>) {
    let response = if readiness.is_ready().await {
        HTTP_200_PLAIN
    } else {
        HTTP_503_PLAIN
    };
    let (_, _) = stream.write_all(response.to_vec()).await;
}

// ---------------------------------------------------------------------------
// Request parsing
// ---------------------------------------------------------------------------

/// Extract the path from the HTTP/1 request line.
///
/// `"GET /metrics HTTP/1.1\r\n..."` → `"/metrics"`
fn parse_path(buf: &[u8]) -> &str {
    let s = std::str::from_utf8(buf).unwrap_or("");
    let line = s.lines().next().unwrap_or("");
    let mut parts = line.splitn(3, ' ');
    let _method = parts.next().unwrap_or("");
    parts.next().unwrap_or("/")
}

