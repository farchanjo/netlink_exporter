//! Collector registry and scrape fan-out service.
//!
//! **ADR-0023:** Mutex replaced with `AtomicU64` for per-collector error
//! counters (lock-free, `Relaxed` ordering — counters are best-effort
//! telemetry).  `tokio::time::timeout` replaced with a simple direct `collect()`
//! call (monoio has no built-in per-future timeout equivalent; best-effort
//! timeout is omitted — the collector itself must be non-blocking via
//! `monoio::spawn_blocking`).
//!
//! Responsibilities:
//! - Build the enabled collector set from config.
//! - Run sequential fan-out scrapes.
//! - Inject self-telemetry metrics on every scrape cycle.
//! - Accumulate per-collector error counters across scrapes (AtomicU64).

use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

use nlx_config::ExporterConfig;
use nlx_domain::metric::MetricSample;
use nlx_netlink::collectors::{
    conntrack::ConntrackCollector, conntrack_expect::ConntrackExpectCollector,
    devlink::DevlinkCollector, drop_monitor::DropMonitorCollector, ethtool::EthtoolCollector,
    ipvs::IpvsCollector, nftables::NftablesCollector, rt::RtCollector,
    rt_extended::RtExtendedCollector, sockdiag::SockDiagCollector, tc::TcCollector,
    wireguard::WireguardCollector, xfrm::XfrmCollector,
};
use nlx_ports::{
    collector::Collector,
    driven::{ConfigPort, MetricRegistryPort},
    driving::ScrapeTriggerPort,
    error::CollectError,
};
use tracing::{error, warn};

// ---------------------------------------------------------------------------
// Collector registry
// ---------------------------------------------------------------------------

/// Holds the runtime-enabled collector set.
pub struct CollectorRegistry {
    /// Shared reference to the collector list (used by [`ScrapeService`]).
    pub inner: Arc<Vec<Box<dyn Collector>>>,
}

impl CollectorRegistry {
    /// Build the collector set from the configuration's enable flags.
    ///
    /// Collectors disabled by config are not instantiated.
    pub fn from_config(config: &ExporterConfig) -> Self {
        let mut collectors: Vec<Box<dyn Collector>> = Vec::new();

        macro_rules! push_if_enabled {
            ($name:expr, $ctor:expr) => {
                if config.collector_enabled($name) {
                    collectors.push(Box::new($ctor));
                }
            };
        }

        push_if_enabled!("rtnetlink", RtCollector);
        push_if_enabled!("rtnetlink_extended", RtExtendedCollector);
        push_if_enabled!("traffic_control", TcCollector);
        push_if_enabled!("conntrack", ConntrackCollector);
        push_if_enabled!("conntrack_expect", ConntrackExpectCollector);
        push_if_enabled!("nftables", NftablesCollector);
        push_if_enabled!("sock_diag", SockDiagCollector);
        push_if_enabled!("ethtool", EthtoolCollector);
        push_if_enabled!("ipvs", IpvsCollector);
        push_if_enabled!("wireguard", WireguardCollector);
        push_if_enabled!("devlink", DevlinkCollector);
        push_if_enabled!("drop_monitor", DropMonitorCollector);
        push_if_enabled!("xfrm", XfrmCollector);

        Self {
            inner: Arc::new(collectors),
        }
    }
}

// ---------------------------------------------------------------------------
// Scrape service
// ---------------------------------------------------------------------------

/// Per-collector mutable state tracked across scrapes.
///
/// **ADR-0023 lock-free:** uses `AtomicU64` (no `Mutex`).
struct CollectorStats {
    /// Cumulative error count — `Relaxed` ordering (best-effort telemetry).
    error_total: AtomicU64,
}

impl CollectorStats {
    fn new() -> Self {
        Self {
            error_total: AtomicU64::new(0),
        }
    }

    fn increment_error(&self) {
        self.error_total.fetch_add(1, Ordering::Relaxed);
    }

    fn load_error(&self) -> u64 {
        self.error_total.load(Ordering::Relaxed)
    }
}

/// Facade that fans out to all enabled collectors and updates the metrics
/// registry.
///
/// Self-telemetry metrics (`nft_up`, `nft_build_info`, per-collector gauges
/// and counters) are injected into every sample set before the registry update.
///
/// **ADR-0023:** zero `Mutex`/`RwLock` — error counters are `AtomicU64`.
pub struct ScrapeService<M: MetricRegistryPort> {
    /// Enabled collectors.
    pub collectors: Arc<Vec<Box<dyn Collector>>>,
    /// Metrics registry driven port.
    pub metrics: Arc<M>,
    /// Scrape timeout in milliseconds (from config, kept for telemetry).
    pub scrape_timeout_ms: u64,
    /// Startup availability map: collector name → available.
    pub availability: Arc<BTreeMap<String, bool>>,
    /// Per-collector cumulative error counters — lock-free `AtomicU64`.
    stats: Arc<BTreeMap<String, CollectorStats>>,
}

impl<M: MetricRegistryPort> ScrapeService<M> {
    /// Construct a new scrape service.
    #[must_use]
    pub fn new(
        collectors: Arc<Vec<Box<dyn Collector>>>,
        metrics: Arc<M>,
        scrape_timeout_ms: u64,
        availability: Arc<BTreeMap<String, bool>>,
    ) -> Self {
        // Pre-populate the stats map so we never mutate it after construction.
        let mut stats_map = BTreeMap::new();
        for c in collectors.iter() {
            stats_map.insert(c.name().to_owned(), CollectorStats::new());
        }
        Self {
            collectors,
            metrics,
            scrape_timeout_ms,
            availability,
            stats: Arc::new(stats_map),
        }
    }
}

impl<M: MetricRegistryPort + Send + Sync> ScrapeTriggerPort for ScrapeService<M> {
    async fn scrape(&self) -> Result<Vec<MetricSample>, CollectError> {
        let mut all: Vec<MetricSample> = Vec::new();

        struct CollectorResult {
            name: String,
            success: bool,
            duration_secs: f64,
        }
        let mut results: Vec<CollectorResult> = Vec::new();

        for collector in self.collectors.iter() {
            let name = collector.name().to_owned();

            // ADR-0015: skip collect() for collectors whose subsystem was
            // unavailable at startup.  Calling collect() on an unavailable
            // collector (e.g. XFRM when ip_xfrm is not loaded) can block
            // indefinitely on the kernel netlink recv, hanging the entire
            // sequential scrape fan-out.  The availability metric is still
            // emitted (available=0) below in the telemetry section.
            let available = self.availability.get(&name).copied().unwrap_or(false);
            if !available {
                results.push(CollectorResult {
                    name,
                    success: true, // not a failure — subsystem simply absent
                    duration_secs: 0.0,
                });
                continue;
            }

            let start = Instant::now();

            // monoio has no built-in per-future timeout; the blocking work
            // inside each collector runs in spawn_blocking which is bounded
            // by the kernel — this is acceptable for the scrape workload.
            let outcome = collector.collect().await;

            let elapsed = start.elapsed().as_secs_f64();

            match outcome {
                Ok(mut samples) => {
                    all.append(&mut samples);
                    results.push(CollectorResult {
                        name,
                        success: true,
                        duration_secs: elapsed,
                    });
                }
                Err(e) => {
                    error!(collector = %name, error = %e, "collector collect() failed");
                    if let Some(stat) = self.stats.get(&name) {
                        stat.increment_error();
                    }
                    results.push(CollectorResult {
                        name,
                        success: false,
                        duration_secs: elapsed,
                    });
                }
            }
        }

        // -----------------------------------------------------------------------
        // Self-telemetry metrics
        // -----------------------------------------------------------------------
        all.push(MetricSample::gauge(
            "nft_up",
            "Exporter liveness: 1 if the exporter is up.",
            BTreeMap::new(),
            1.0,
        ));

        {
            let mut labels = BTreeMap::new();
            labels.insert("version".to_owned(), env!("CARGO_PKG_VERSION").to_owned());
            all.push(MetricSample::gauge(
                "nft_build_info",
                "A metric with value 1 exposing build information.",
                labels,
                1.0,
            ));
        }

        for cr in &results {
            let mut labels = BTreeMap::new();
            labels.insert("collector".to_owned(), cr.name.clone());

            let available = self.availability.get(&cr.name).copied().unwrap_or(false);
            {
                let mut l = labels.clone();
                l.insert("collector".to_owned(), cr.name.clone());
                all.push(MetricSample::gauge(
                    "nft_scrape_collector_available",
                    "1 if the collector's kernel subsystem was available at startup.",
                    l,
                    if available { 1.0 } else { 0.0 },
                ));
            }

            {
                let mut l = labels.clone();
                l.insert("collector".to_owned(), cr.name.clone());
                all.push(MetricSample::gauge(
                    "nft_scrape_collector_success",
                    "1 if the last scrape of this collector succeeded.",
                    l,
                    if cr.success { 1.0 } else { 0.0 },
                ));
            }

            {
                let mut l = labels.clone();
                l.insert("collector".to_owned(), cr.name.clone());
                all.push(MetricSample::gauge(
                    "nft_scrape_collector_duration_seconds",
                    "Duration of the last scrape cycle for this collector in seconds.",
                    l,
                    cr.duration_secs,
                ));
            }

            {
                // Lock-free load of cumulative error counter.
                let error_count = self
                    .stats
                    .get(&cr.name)
                    .map_or(0, |s| s.load_error());
                all.push(MetricSample::counter(
                    "nft_scrape_collector_error_total",
                    "Total number of scrape errors for this collector since process start.",
                    labels,
                    error_count,
                ));
            }
        }

        // Update the registry; on failure log but still return samples.
        if let Err(e) = self.metrics.update_samples(all.clone()).await {
            error!(error = %e, "failed to update metrics registry");
        }

        Ok(all)
    }
}
