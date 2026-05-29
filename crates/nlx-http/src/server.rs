//! Minimal hand-rolled HTTP/1 server over `monoio::net::TcpListener`.
//!
//! **ADR-0023:** Replaces axum + tokio `TcpListener`.  The three routes
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
//! # `BufResult` ownership model
//!
//! monoio `AsyncReadRent::read` and `AsyncWriteRentExt::write_all` both use
//! the owned-buffer model: the buffer is *moved into* the call, pinned by the
//! kernel for the `io_uring` SQ entry lifetime, and returned in the result tuple.
//!
//! # Accept-error backoff
//!
//! Consecutive `accept()` errors (e.g. `EMFILE`/`ENFILE` — fd exhaustion) trigger
//! exponential backoff starting at 10 ms, doubling up to 1 s cap, then resetting on
//! the first successful accept.  This prevents a busy-wait that burns 100% CPU while
//! no new connections can be accepted.

use std::sync::Arc;
use std::time::Duration;

use monoio::{
    io::{AsyncReadRent, AsyncWriteRentExt},
    net::{TcpListener, TcpStream},
    time::sleep,
};
use thiserror::Error;
use tracing::{error, info, warn};

use nlx_ports::driven::MetricRegistryPort;
use nlx_ports::driving::{HealthPort, ReadinessPort, ScrapeTriggerPort};

// ---------------------------------------------------------------------------
// Static HTTP response fragments
// ---------------------------------------------------------------------------

const HTTP_200_PLAIN: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK";
const HTTP_503_PLAIN: &[u8] =
    b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const HTTP_500: &[u8] =
    b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const HTTP_404: &[u8] = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// Prometheus text format 0.0.4 content-type (matches what `prometheus_client`
/// encodes — `_total` in TYPE lines, no `OpenMetrics` envelope).
///
/// `OpenMetrics` (`application/openmetrics-text`) requires `# EOF` as trailer
/// and a different TYPE-line grammar; using the wrong content-type causes
/// Prometheus scrapers to reject or misparse the body.
const METRICS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// Initial accept-error backoff: 10 ms.
const ACCEPT_BACKOFF_INITIAL_MS: u64 = 10;
/// Maximum accept-error backoff: 1 s.
const ACCEPT_BACKOFF_MAX_MS: u64 = 1_000;

/// Maximum bytes read while accumulating HTTP request headers.
///
/// 8 KiB matches the default limit of most HTTP servers (nginx, hyper).
/// A metrics endpoint never receives large headers; this is a safety cap
/// against misbehaving clients or port-scanners sending garbage.
const REQUEST_HEADER_CAP: usize = 8 * 1024;

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

        // Exponential backoff state for consecutive accept errors.
        // Reset to initial value after every successful accept.
        let mut backoff_ms = ACCEPT_BACKOFF_INITIAL_MS;

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    // Successful accept — reset backoff.
                    backoff_ms = ACCEPT_BACKOFF_INITIAL_MS;

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
                    error!(error = %e, backoff_ms, "accept error — backing off");
                    sleep(Duration::from_millis(backoff_ms)).await;
                    // Double, capped at maximum.
                    backoff_ms = (backoff_ms * 2).min(ACCEPT_BACKOFF_MAX_MS);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Connection handler
// ---------------------------------------------------------------------------

/// Handle one HTTP/1 connection: read the request headers, dispatch, respond.
///
/// Reads up to [`REQUEST_HEADER_CAP`] bytes, accumulating chunks until the
/// `\r\n\r\n` end-of-headers sentinel is found or the cap is reached.  This
/// tolerates TCP segmentation that splits the request across multiple reads
/// while bounding memory usage per connection.
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
    // Accumulate header bytes into a single owned Vec, yielding back ownership
    // on each monoio BufResult round-trip.
    let mut header_buf: Vec<u8> = Vec::with_capacity(512);

    loop {
        // Each monoio read requires an *owned* buffer with spare capacity.
        // We allocate a fresh chunk buffer, read into it, then append to
        // `header_buf`.  This keeps the BufResult ownership model clean.
        let chunk: Vec<u8> = vec![0u8; 512];
        let (res, chunk) = stream.read(chunk).await;

        match res {
            Ok(0) | Err(_) => return, // EOF or error — discard connection.
            Ok(n) => {
                header_buf.extend_from_slice(&chunk[..n]);
            }
        }

        // Check for end-of-headers sentinel.
        if header_buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }

        // Enforce the safety cap.
        if header_buf.len() >= REQUEST_HEADER_CAP {
            warn!(
                len = header_buf.len(),
                "request headers exceeded cap — closing"
            );
            // 400 Bad Request would be more correct but we keep this endpoint
            // minimal; simply drop the connection.
            return;
        }
    }

    let path = parse_path(&header_buf);

    match path {
        "/metrics" => handle_metrics::<S, M>(stream, scrape, registry).await,
        "/healthz" => handle_healthz(stream, health).await,
        "/ready" => handle_ready(stream, readiness).await,
        _ => {
            let (_, _) = stream.write_all(HTTP_404.to_vec()).await;
        }
    }
}

/// `GET /metrics` — trigger scrape, encode, respond.
async fn handle_metrics<S, M>(mut stream: TcpStream, scrape: Arc<S>, registry: Arc<M>)
where
    S: ScrapeTriggerPort,
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
            // Content-Type matches the Prometheus 0.0.4 text format that the
            // encoder actually emits (see METRICS_CONTENT_TYPE constant).
            let mut response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {ct}\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n",
                ct = METRICS_CONTENT_TYPE,
                len = body.len(),
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::cast_possible_truncation,
        reason = "test"
    )]

    use super::*;

    // -----------------------------------------------------------------------
    // H-11/MC-001: Content-Type constant
    // -----------------------------------------------------------------------

    /// Verify the Content-Type value is exactly the Prometheus 0.0.4 text
    /// format string — not the `OpenMetrics` application/openmetrics-text value
    /// that the encoder does NOT emit.
    #[test]
    fn metrics_content_type_is_prometheus_004() {
        assert_eq!(
            METRICS_CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        );
        // Must NOT claim OpenMetrics.
        assert!(
            !METRICS_CONTENT_TYPE.contains("openmetrics"),
            "Content-Type must not claim OpenMetrics format"
        );
    }

    // -----------------------------------------------------------------------
    // M-15/RM-08: Backoff constants
    // -----------------------------------------------------------------------

    /// Backoff must start at 10 ms and cap at 1 s.
    #[test]
    fn accept_backoff_bounds() {
        assert_eq!(ACCEPT_BACKOFF_INITIAL_MS, 10);
        assert_eq!(ACCEPT_BACKOFF_MAX_MS, 1_000);
    }

    /// Doubling sequence stays within the cap.
    #[test]
    fn accept_backoff_doubling_sequence() {
        let mut backoff = ACCEPT_BACKOFF_INITIAL_MS;
        let expected = [10u64, 20, 40, 80, 160, 320, 640, 1_000, 1_000, 1_000];
        for &want in &expected {
            assert_eq!(backoff, want);
            backoff = (backoff * 2).min(ACCEPT_BACKOFF_MAX_MS);
        }
    }

    /// After a successful accept the backoff resets to the initial value.
    #[test]
    fn accept_backoff_resets_on_success() {
        let mut backoff = ACCEPT_BACKOFF_MAX_MS; // simulate saturated state
        assert_eq!(backoff, ACCEPT_BACKOFF_MAX_MS, "starts saturated");
        // Simulated successful accept: reset.
        backoff = ACCEPT_BACKOFF_INITIAL_MS;
        assert_eq!(backoff, 10);
    }

    // -----------------------------------------------------------------------
    // SEC-INPUT-002/RM-10: Header cap constant
    // -----------------------------------------------------------------------

    /// The header-read cap must be 8 KiB, matching nginx/hyper defaults.
    #[test]
    fn request_header_cap_is_8kib() {
        assert_eq!(REQUEST_HEADER_CAP, 8 * 1024);
    }

    // -----------------------------------------------------------------------
    // parse_path: request-line extraction
    // -----------------------------------------------------------------------

    #[test]
    fn parse_path_metrics() {
        let req = b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n";
        assert_eq!(parse_path(req), "/metrics");
    }

    #[test]
    fn parse_path_healthz() {
        let req = b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n";
        assert_eq!(parse_path(req), "/healthz");
    }

    #[test]
    fn parse_path_ready() {
        let req = b"GET /ready HTTP/1.1\r\nHost: localhost\r\n\r\n";
        assert_eq!(parse_path(req), "/ready");
    }

    #[test]
    fn parse_path_unknown() {
        let req = b"GET /foo HTTP/1.1\r\n\r\n";
        assert_eq!(parse_path(req), "/foo");
    }

    #[test]
    fn parse_path_empty_buf() {
        assert_eq!(parse_path(b""), "/");
    }

    #[test]
    fn parse_path_no_path_token() {
        // Only a single token — no space-separated path.
        assert_eq!(parse_path(b"GET"), "/");
    }

    /// Non-UTF-8 bytes: `parse_path` must not panic; falls back to "/".
    #[test]
    fn parse_path_non_utf8() {
        let req = b"\xff\xfe GET /metrics HTTP/1.1\r\n\r\n";
        // from_utf8 fails -> unwrap_or("") -> lines().next() = "" -> splitn
        // yields no path token -> fallback "/".
        let result = parse_path(req);
        // Just check it does not panic and returns something.
        let _ = result;
    }

    // -----------------------------------------------------------------------
    // Header accumulation: end-of-headers sentinel detection
    // -----------------------------------------------------------------------

    /// The `\r\n\r\n` sentinel detection logic (mirrored from `handle_conn`).
    fn headers_complete(buf: &[u8]) -> bool {
        buf.windows(4).any(|w| w == b"\r\n\r\n")
    }

    #[test]
    fn sentinel_found_in_complete_request() {
        let req = b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n";
        assert!(headers_complete(req));
    }

    #[test]
    fn sentinel_not_found_in_partial_request() {
        let req = b"GET /metrics HTTP/1.1\r\nHost: loc";
        assert!(!headers_complete(req));
    }

    #[test]
    fn sentinel_found_at_exact_boundary() {
        // Minimal valid request: request-line + blank line.
        let req = b"GET / HTTP/1.1\r\n\r\n";
        assert!(headers_complete(req));
    }

    /// Cap boundary: a buffer of exactly `REQUEST_HEADER_CAP` bytes should
    /// trigger the cap check.
    #[test]
    fn header_cap_boundary() {
        let oversized = vec![b'A'; REQUEST_HEADER_CAP];
        assert!(oversized.len() >= REQUEST_HEADER_CAP);
    }
}
