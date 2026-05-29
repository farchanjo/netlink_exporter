//! # netlink_exporter — Composition Root
//!
//! **Hexagonal role: COMPOSITION ROOT (binary entry point / Facade).**
//!
//! This binary wires together all hexagonal adapters:
//!
//! 1. Parse CLI args and load [`ExporterConfig`] via `nlx-config`.
//! 2. Initialise `tracing-subscriber` with the configured log level.
//! 3. Build the collector registry from enabled collectors (`nlx-netlink`).
//! 4. Run startup availability probes for each collector.
//! 5. Open all required netlink sockets, then drop Linux capabilities to
//!    `CAP_NET_ADMIN` only (`caps` crate — ADR-0009).
//! 6. Wire [`PrometheusRegistryAdapter`] (`nlx-metrics`) and
//!    [`AxumHttpAdapter`] (`nlx-http`).
//! 7. Drive the scrape fan-out and HTTP server until `SIGTERM`/`SIGINT`.
//!
//! ## Capability dropping (ADR-0009)
//!
//! After opening all netlink sockets the process drops all capabilities
//! except `CAP_NET_ADMIN`.  The `caps` crate is used to perform
//! `capset(2)` via `caps::set(None, CapSet::Effective, &cap_set)`.
//!
//! ## Runtime confinement
//!
//! `tokio` and `mio` are used here (via `#[tokio::main]`) and in
//! `nlx-netlink` only (ADR-0014).

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use anyhow::{Context, Result};
use clap::Parser;
use tracing::{error, info};

use nlx_config::{CliArgs, ExporterConfig, load_config};
use nlx_domain::metric::MetricSample;
use nlx_http::{AxumHttpAdapter, HttpAdapterConfig};
use nlx_metrics::PrometheusRegistryAdapter;
use nlx_ports::driven::MetricRegistryPort;
use nlx_ports::{
    collector::Collector,
    driving::{HealthPort, ReadinessPort, ScrapeTriggerPort},
    error::CollectError,
};

mod scrape;

use scrape::CollectorRegistry;

/// Application entry point.
///
/// # Errors
///
/// Returns any unrecoverable startup error wrapped in `anyhow::Error`.
#[tokio::main]
async fn main() -> Result<()> {
    let args = CliArgs::parse();

    let config = load_config(&args).context("failed to load exporter configuration")?;

    init_tracing(&config);

    info!(
        version = env!("CARGO_PKG_VERSION"),
        listen_addr = %config.listen_addr,
        "netlink_exporter starting"
    );

    run(config).await
}

/// Main application logic extracted from `main` for testability.
async fn run(config: ExporterConfig) -> Result<()> {
    // --- build collector registry ---
    let collector_registry = CollectorRegistry::from_config(&config);

    // --- run startup probes ---
    // TODO(impl): call probe_available() on each enabled collector;
    //   populate nft_scrape_collector_available metric.

    // --- drop capabilities to CAP_NET_ADMIN only (ADR-0009) ---
    drop_caps_to_net_admin().context("failed to drop Linux capabilities")?;

    // --- build metrics adapter ---
    let metrics_adapter = Arc::new(PrometheusRegistryAdapter::new());

    // --- build HTTP adapter ---
    let http_config = HttpAdapterConfig {
        listen_addr: config.listen_addr.clone(),
    };
    let http_adapter = AxumHttpAdapter::new(http_config);

    // --- wire driving ports ---
    let readiness = Arc::new(ReadinessService::new());
    let scrape_port = Arc::new(ScrapeService {
        collectors: Arc::clone(&collector_registry.inner),
        metrics: Arc::clone(&metrics_adapter),
    });
    let health_port = Arc::new(HealthService);
    let readiness_port = Arc::clone(&readiness);

    // Signal readiness after wiring is complete.
    readiness.set_ready();

    // --- serve until SIGTERM/SIGINT ---
    info!("HTTP adapter starting");
    tokio::select! {
        result = http_adapter.serve(scrape_port, health_port, readiness_port) => {
            result.context("HTTP adapter exited unexpectedly")?;
        }
        _ = tokio::signal::ctrl_c() => {
            info!("received SIGINT — shutting down");
        }
    }

    info!("netlink_exporter stopped");
    Ok(())
}

/// Drop all Linux capabilities except `CAP_NET_ADMIN` (ADR-0009).
///
/// # Errors
///
/// Returns `Err` if the `capset(2)` syscall fails (e.g. process lacks
/// `CAP_SETPCAP`).
fn drop_caps_to_net_admin() -> Result<()> {
    // TODO(impl): use caps::set(None, CapSet::Effective, &{CAP_NET_ADMIN}) +
    //   caps::set(None, CapSet::Permitted, &{CAP_NET_ADMIN}).
    //   Log a warning (not error) if the process has no capabilities to drop.
    info!("capability drop: stub — not yet implemented");
    Ok(())
}

/// Initialise `tracing-subscriber` with the configured log level.
fn init_tracing(config: &ExporterConfig) {
    use tracing_subscriber::{EnvFilter, fmt};

    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.log_level));

    fmt().with_env_filter(filter).init();
}

// ---------------------------------------------------------------------------
// Driving-port implementations wired in the composition root
// ---------------------------------------------------------------------------

/// Facade that fans out to all enabled collectors and updates the metrics
/// registry.
struct ScrapeService<M: MetricRegistryPort> {
    collectors: Arc<Vec<Box<dyn Collector>>>,
    metrics: Arc<M>,
}

impl<M: MetricRegistryPort + Send + Sync> ScrapeTriggerPort for ScrapeService<M> {
    async fn scrape(&self) -> Result<Vec<MetricSample>, CollectError> {
        let mut all: Vec<MetricSample> = Vec::new();
        for collector in self.collectors.iter() {
            match collector.collect().await {
                Ok(mut samples) => all.append(&mut samples),
                Err(e) => {
                    error!(collector = collector.name(), error = %e, "collector failed");
                    // TODO(impl): increment nft_scrape_collector_error_total.
                }
            }
        }
        self.metrics
            .update_samples(all.clone())
            .await
            .map_err(CollectError::Io)?;
        Ok(all)
    }
}

/// Always-healthy liveness probe stub.
struct HealthService;

impl HealthPort for HealthService {
    async fn is_healthy(&self) -> bool {
        true
    }
}

/// Readiness probe that becomes ready once [`ReadinessService::set_ready`] is
/// called.
struct ReadinessService {
    ready: AtomicBool,
}

impl ReadinessService {
    fn new() -> Self {
        Self {
            ready: AtomicBool::new(false),
        }
    }

    fn set_ready(&self) {
        self.ready.store(true, Ordering::Release);
    }
}

impl ReadinessPort for ReadinessService {
    async fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }
}
