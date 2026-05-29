//! Collector registry and scrape fan-out service.
//!
//! Responsibilities:
//! - Build the enabled collector set from config.
//! - Run timed fan-out scrapes with per-collector `tokio::time::timeout`.
//! - Inject self-telemetry metrics on every scrape cycle.
//! - Accumulate per-collector error counters across scrapes.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
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
use tokio::time::{Duration, timeout};
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
#[derive(Default)]
struct CollectorStats {
    /// Cumulative error count (incremented on every failed `collect()`).
    error_total: u64,
}

/// Facade that fans out to all enabled collectors, applies per-collector
/// timeouts, and updates the metrics registry.
///
/// Self-telemetry metrics (`nft_up`, `nft_build_info`, per-collector gauges
/// and counters) are injected into every sample set before the registry update.
pub struct ScrapeService<M: MetricRegistryPort> {
    /// Enabled collectors.
    pub collectors: Arc<Vec<Box<dyn Collector>>>,
    /// Metrics registry driven port.
    pub metrics: Arc<M>,
    /// Scrape timeout in milliseconds (from config).
    pub scrape_timeout_ms: u64,
    /// Startup availability map: collector name → available.
    pub availability: Arc<BTreeMap<String, bool>>,
    /// Per-collector cumulative error counters; guarded for multi-request safety.
    stats: Mutex<BTreeMap<String, CollectorStats>>,
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
        Self {
            collectors,
            metrics,
            scrape_timeout_ms,
            availability,
            stats: Mutex::new(BTreeMap::new()),
        }
    }
}

impl<M: MetricRegistryPort + Send + Sync> ScrapeTriggerPort for ScrapeService<M> {
    async fn scrape(&self) -> Result<Vec<MetricSample>, CollectError> {
        let timeout_dur = Duration::from_millis(self.scrape_timeout_ms);
        let mut all: Vec<MetricSample> = Vec::new();

        // Per-collector scrape results tracked for self-telemetry.
        struct CollectorResult {
            name: String,
            success: bool,
            duration_secs: f64,
        }
        let mut results: Vec<CollectorResult> = Vec::new();

        for collector in self.collectors.iter() {
            let name = collector.name().to_owned();
            let start = Instant::now();

            let outcome = timeout(timeout_dur, collector.collect()).await;

            let elapsed = start.elapsed().as_secs_f64();

            match outcome {
                Ok(Ok(mut samples)) => {
                    all.append(&mut samples);
                    results.push(CollectorResult {
                        name,
                        success: true,
                        duration_secs: elapsed,
                    });
                }
                Ok(Err(e)) => {
                    error!(collector = %name, error = %e, "collector collect() failed");
                    // Increment persistent error counter.
                    if let Ok(mut guard) = self.stats.lock() {
                        guard.entry(name.clone()).or_default().error_total = guard
                            .entry(name.clone())
                            .or_default()
                            .error_total
                            .saturating_add(1);
                    }
                    results.push(CollectorResult {
                        name,
                        success: false,
                        duration_secs: elapsed,
                    });
                }
                Err(_timeout_elapsed) => {
                    warn!(
                        collector = %name,
                        timeout_ms = self.scrape_timeout_ms,
                        "collector timed out"
                    );
                    if let Ok(mut guard) = self.stats.lock() {
                        guard.entry(name.clone()).or_default().error_total = guard
                            .entry(name.clone())
                            .or_default()
                            .error_total
                            .saturating_add(1);
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
        // nft_up{} 1
        all.push(MetricSample::gauge(
            "nft_up",
            "Exporter liveness: 1 if the exporter is up.",
            BTreeMap::new(),
            1.0,
        ));

        // nft_build_info{version="<ver>"} 1
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

            // nft_scrape_collector_available{collector}
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

            // nft_scrape_collector_success{collector}
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

            // nft_scrape_collector_duration_seconds{collector}
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

            // nft_scrape_collector_error_total{collector} — cumulative counter
            {
                let error_count = self
                    .stats
                    .lock()
                    .map(|g| g.get(&cr.name).map_or(0, |s| s.error_total))
                    .unwrap_or(0);
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
