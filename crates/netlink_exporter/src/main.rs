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

use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use anyhow::{Context, Result};
use clap::Parser;
use tracing::{error, info, warn};

use nlx_config::{CliArgs, ExporterConfig, load_config};
use nlx_http::{AxumHttpAdapter, HttpAdapterConfig};
use nlx_metrics::PrometheusRegistryAdapter;
use nlx_ports::driving::{HealthPort, ReadinessPort};

mod scrape;

use scrape::{CollectorRegistry, ScrapeService};

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

    // --- run startup availability probes ---
    let mut availability: BTreeMap<String, bool> = BTreeMap::new();
    for collector in collector_registry.inner.iter() {
        let name = collector.name().to_owned();
        let available = collector.probe_available().await;
        info!(collector = %name, available, "startup availability probe");
        if !available {
            warn!(collector = %name, "collector subsystem unavailable — scrape will be skipped");
        }
        availability.insert(name, available);
    }
    let availability = Arc::new(availability);

    // --- drop capabilities to CAP_NET_ADMIN only (ADR-0009) ---
    // Hardening is best-effort: a failure here must not abort the exporter
    // (e.g. restricted environments, missing CAP_SETPCAP). Warn and continue.
    if let Err(e) = drop_caps_to_net_admin() {
        warn!(error = %e, "capability drop failed; continuing with current capabilities (hardening is best-effort)");
    }

    // --- build metrics adapter ---
    let metrics_adapter = Arc::new(PrometheusRegistryAdapter::new());

    // --- build HTTP adapter ---
    let http_config = HttpAdapterConfig {
        listen_addr: config.listen_addr.clone(),
    };
    let http_adapter = AxumHttpAdapter::new(http_config);

    // --- wire driving ports ---
    let readiness = Arc::new(ReadinessService::new());
    let scrape_port = Arc::new(ScrapeService::new(
        Arc::clone(&collector_registry.inner),
        Arc::clone(&metrics_adapter),
        config.scrape_timeout_ms,
        Arc::clone(&availability),
    ));
    let health_port = Arc::new(HealthService);
    let readiness_port = Arc::clone(&readiness);

    // Signal readiness after wiring is complete.
    readiness.set_ready();

    // --- serve until SIGTERM/SIGINT ---
    info!("HTTP adapter starting");
    tokio::select! {
        result = http_adapter.serve(scrape_port, health_port, readiness_port, Arc::clone(&metrics_adapter)) => {
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
/// If the process has no capabilities (e.g. running unprivileged in
/// development), a warning is logged and the function returns `Ok(())`.
///
/// # Errors
///
/// Returns `Err` if the `capset(2)` syscall fails for a reason other than
/// the process being unprivileged.
fn drop_caps_to_net_admin() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        use caps::{CapSet, Capability, CapsHashSet};

        let mut target = CapsHashSet::new();
        target.insert(Capability::CAP_NET_ADMIN);

        // Check current permitted set first; warn and skip if empty.
        let permitted =
            caps::read(None, CapSet::Permitted).context("caps::read(Permitted) failed")?;
        if permitted.is_empty() {
            warn!("process has no capabilities; skipping capability drop (running unprivileged)");
            return Ok(());
        }

        // Order matters: the kernel requires Effective to be a subset of
        // Permitted at all times, so narrow Effective and Inheritable BEFORE
        // dropping Permitted last (dropping Permitted first while Effective is
        // still full yields EPERM).
        caps::set(None, CapSet::Effective, &target).context("caps::set(Effective) failed")?;
        caps::set(None, CapSet::Inheritable, &CapsHashSet::new())
            .context("caps::set(Inheritable) failed")?;
        caps::set(None, CapSet::Permitted, &target).context("caps::set(Permitted) failed")?;

        info!(
            caps = "CAP_NET_ADMIN",
            "Linux capabilities dropped successfully"
        );
    }

    #[cfg(not(target_os = "linux"))]
    {
        warn!("capability drop not supported on this OS; skipping (non-Linux build)");
    }

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
// Auxiliary driving-port stubs wired in the composition root
// ---------------------------------------------------------------------------

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
