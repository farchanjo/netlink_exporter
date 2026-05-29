//! Collector registry and scrape fan-out service.
//!
//! **ADR-0023:** Mutex replaced with `AtomicU64` for per-collector error
//! counters (lock-free, `Relaxed` ordering — counters are best-effort
//! telemetry).  Each `collect()` call is wrapped in `monoio::time::timeout`
//! so that a single hung subsystem cannot stall the entire HTTP response.
//! Timer support is enabled at runtime construction (`enable_timer()` in
//! `main.rs`).
//!
//! Responsibilities:
//! - Build the enabled collector set from config.
//! - Run sequential fan-out scrapes with per-collector timeout.
//! - Inject self-telemetry metrics on every scrape cycle.
//! - Accumulate per-collector error counters across scrapes (`AtomicU64`).

use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use monoio::time::timeout;
use nlx_config::ExporterConfig;
use nlx_domain::metric::MetricSample;
use nlx_netlink::collectors::{
    conntrack::ConntrackCollector,
    conntrack_expect::ConntrackExpectCollector,
    devlink::DevlinkCollector,
    drop_monitor::{DropCounters, DropMonitorCollector},
    ethtool::EthtoolCollector,
    ipvs::IpvsCollector,
    nftables::NftablesCollector,
    rt::RtCollector,
    rt_extended::RtExtendedCollector,
    sockdiag::SockDiagCollector,
    tc::TcCollector,
    wireguard::WireguardCollector,
    xfrm::XfrmCollector,
};
use nlx_ports::{
    collector::Collector,
    driven::{ConfigPort, MetricRegistryPort},
    driving::ScrapeTriggerPort,
    error::CollectError,
};
use nlx_procfs::softnet::SoftnetCollector;
use tracing::error;

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
    /// Collectors disabled by config are not instantiated. The `drop_monitor`
    /// collector is wired to the shared [`DropCounters`] populated by the
    /// background multicast listener (ADR-0020 hybrid model).
    pub fn from_config(config: &ExporterConfig, drop_counters: Arc<DropCounters>) -> Self {
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
        push_if_enabled!(
            "wireguard",
            WireguardCollector::new(config.wireguard_max_peers)
        );
        push_if_enabled!("devlink", DevlinkCollector);
        if config.collector_enabled("drop_monitor") {
            collectors.push(Box::new(DropMonitorCollector::with_counters(drop_counters)));
        }
        push_if_enabled!("xfrm", XfrmCollector);

        // procfs/sysfs collectors (ADR-0027) — opt-in, default off.
        push_if_enabled!("softnet", SoftnetCollector);

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
    /// Startup availability map: collector name → available.
    pub availability: Arc<BTreeMap<String, bool>>,
    /// Per-collector timeout in milliseconds (from [`ExporterConfig`]).
    ///
    /// Each `collect()` future is wrapped in `monoio::time::timeout`; on
    /// expiry the collector is marked failed and the fan-out continues.
    scrape_timeout_ms: u64,
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
            availability,
            scrape_timeout_ms,
            stats: Arc::new(stats_map),
        }
    }
}

impl<M: MetricRegistryPort + Send + Sync> ScrapeTriggerPort for ScrapeService<M> {
    #[allow(
        clippy::too_many_lines,
        reason = "cohesive scrape fan-out + self-telemetry block; splitting would obscure the sequential wire layout"
    )]
    #[allow(
        clippy::items_after_statements,
        reason = "local helper struct kept next to its use inside the async fn body"
    )]
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

            // Wrap collect() in a monoio timer so that a hung subsystem cannot
            // stall the full scrape fan-out.  The monoio timer driver is
            // initialised in main.rs via RuntimeBuilder::enable_timer().
            //
            // `timeout()` returns `Err(Elapsed)` when the deadline fires;
            // `Ok(Err(CollectError))` when the collector itself fails.
            let timed = timeout(
                Duration::from_millis(self.scrape_timeout_ms),
                collector.collect(),
            )
            .await;

            let elapsed = start.elapsed().as_secs_f64();

            // Flatten the two error layers into a single `Result<…, CollectError>`.
            let outcome: Result<Vec<MetricSample>, CollectError> = match timed {
                Ok(inner) => inner,
                Err(_elapsed) => Err(CollectError::Timeout {
                    millis: self.scrape_timeout_ms,
                }),
            };

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
                    .map_or(0, CollectorStats::load_error);
                all.push(MetricSample::counter(
                    "nft_scrape_collector_error_total",
                    "Total number of scrape errors for this collector since process start.",
                    labels,
                    error_count,
                ));
            }
        }

        // Update the registry; on failure log but still return samples.
        //
        // RM-05: `update_samples` takes `Vec<MetricSample>` by value (port
        // trait signature), so we must clone `all` here to keep the owned
        // copy for the `Ok(all)` return.  Eliminating this double-allocation
        // would require changing the `MetricRegistryPort` trait to accept a
        // shared reference or an `Arc<[MetricSample]>` — out of scope for
        // this change.  The clone is O(n) in sample count; acceptable for
        // Prometheus scrape cadence.
        if let Err(e) = self.metrics.update_samples(all.clone()).await {
            error!(error = %e, "failed to update metrics registry");
        }

        Ok(all)
    }
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
        clippy::cast_precision_loss,
        reason = "test"
    )]

    use std::{collections::BTreeMap, future::Future, pin::Pin, sync::Arc, time::Duration};

    use nlx_domain::metric::{MetricSample, MetricValue};
    use nlx_ports::{
        collector::Collector, driven::MetricRegistryPort, driving::ScrapeTriggerPort,
        error::CollectError,
    };

    use super::{CollectorStats, ScrapeService};

    /// Extract the f64 value from a `MetricSample` (gauge / f64-backed counter).
    fn sample_f64(s: &MetricSample) -> f64 {
        match s.value {
            MetricValue::F64(v) => v,
            MetricValue::U64(v) => v as f64,
        }
    }

    /// Find a sample by metric name and optional `collector` label value.
    fn find_sample<'a>(
        samples: &'a [MetricSample],
        metric_name: &str,
        collector_label: Option<&str>,
    ) -> Option<&'a MetricSample> {
        samples.iter().find(|s| {
            s.name == metric_name
                && collector_label
                    .is_none_or(|c| s.labels.get("collector").map(String::as_str) == Some(c))
        })
    }

    // -----------------------------------------------------------------------
    // Pure unit test — no runtime required
    // -----------------------------------------------------------------------

    /// `CollectError::Timeout` Display must include the configured millisecond
    /// value so operators can correlate it with their config.
    ///
    /// Wire: no kernel constants involved — pure string formatting.
    #[test]
    fn collect_error_timeout_display() {
        let err = CollectError::Timeout { millis: 5_000 };
        let text = err.to_string();
        assert!(
            text.contains("5000"),
            "Display should include the millis value; got: {text}"
        );
        // The thiserror template is `"scrape timeout after {millis}ms"`.
        assert!(
            text.contains("timeout") || text.contains("ms"),
            "Display should mention timeout or ms; got: {text}"
        );
    }

    /// `CollectorStats` starts at zero and increments atomically.
    #[test]
    fn collector_stats_increment() {
        let s = CollectorStats::new();
        assert_eq!(s.load_error(), 0);
        s.increment_error();
        s.increment_error();
        assert_eq!(s.load_error(), 2);
    }

    // -----------------------------------------------------------------------
    // Monoio-runtime tests — require the timer driver
    // -----------------------------------------------------------------------

    /// Minimal no-op `MetricRegistryPort` stub for test isolation.
    struct NopRegistry;

    impl MetricRegistryPort for NopRegistry {
        async fn update_samples(&self, _samples: Vec<MetricSample>) -> Result<(), String> {
            Ok(())
        }

        async fn encode_text(&self) -> Result<String, String> {
            Ok(String::new())
        }
    }

    /// A collector that returns a fixed sample set immediately.
    struct FastCollector {
        label: &'static str,
    }

    impl Collector for FastCollector {
        fn name(&self) -> &str {
            self.label
        }

        fn collect(
            &self,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<MetricSample>, CollectError>> + '_>> {
            Box::pin(async {
                Ok(vec![MetricSample::gauge(
                    "test_metric",
                    "test",
                    BTreeMap::new(),
                    1.0,
                )])
            })
        }

        fn probe_available(&self) -> Pin<Box<dyn Future<Output = bool> + '_>> {
            Box::pin(async { true })
        }
    }

    /// A collector that sleeps longer than any reasonable test timeout.
    struct HangingCollector {
        label: &'static str,
    }

    impl Collector for HangingCollector {
        fn name(&self) -> &str {
            self.label
        }

        fn collect(
            &self,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<MetricSample>, CollectError>> + '_>> {
            Box::pin(async {
                // Sleep for 30 s — well beyond any test timeout.
                monoio::time::sleep(Duration::from_secs(30)).await;
                Ok(vec![])
            })
        }

        fn probe_available(&self) -> Pin<Box<dyn Future<Output = bool> + '_>> {
            Box::pin(async { true })
        }
    }

    /// Build a monoio runtime with the timer driver enabled, mirroring
    /// `main.rs`. Returned inline (not via a typed helper) because
    /// `enable_timer()` wraps the driver in `TimeDriver<_>`, whose concrete
    /// type is not nameable here — type inference handles it at the call site.
    macro_rules! build_rt {
        () => {{
            let pool = Box::new(monoio::blocking::DefaultThreadPool::new(2));
            monoio::RuntimeBuilder::<monoio::FusionDriver>::new()
                .with_entries(256)
                .enable_timer()
                .attach_thread_pool(pool)
                .build()
                .expect("monoio runtime")
        }};
    }

    /// A fast collector must produce samples and be recorded as success.
    #[test]
    fn fast_collector_succeeds() {
        let mut rt = build_rt!();
        rt.block_on(async {
            let collectors: Arc<Vec<Box<dyn Collector>>> =
                Arc::new(vec![Box::new(FastCollector { label: "fast" })]);
            let mut avail = BTreeMap::new();
            avail.insert("fast".to_owned(), true);

            let svc = ScrapeService::new(
                Arc::clone(&collectors),
                Arc::new(NopRegistry),
                // 2-second timeout — fast collector resolves instantly.
                2_000,
                Arc::new(avail),
            );

            let samples = svc.scrape().await.expect("scrape must succeed");

            // At minimum the self-telemetry nft_up gauge and the fast
            // collector's own sample must be present.
            assert!(
                samples.iter().any(|s| s.name == "nft_up"),
                "nft_up must be present"
            );
            assert!(
                samples.iter().any(|s| s.name == "test_metric"),
                "collector sample must be present"
            );
            // The scrape_collector_success gauge for "fast" must be 1.0.
            let success_sample =
                find_sample(&samples, "nft_scrape_collector_success", Some("fast"));
            assert!(
                success_sample.is_some(),
                "success gauge for fast collector must exist"
            );
            #[allow(
                clippy::float_cmp,
                reason = "integer-backed 0/1 gauge; exact equality correct"
            )]
            {
                assert_eq!(
                    sample_f64(success_sample.unwrap()),
                    1.0,
                    "fast collector must be success=1"
                );
            }
        });
    }

    /// A hanging collector must be timed out and marked as failure; the
    /// overall `scrape()` must return `Ok` (not propagate the timeout as a
    /// fatal error to the caller).
    #[test]
    fn hanging_collector_is_timed_out_and_marked_failed() {
        let mut rt = build_rt!();
        rt.block_on(async {
            let collectors: Arc<Vec<Box<dyn Collector>>> = Arc::new(vec![
                Box::new(FastCollector { label: "fast" }),
                Box::new(HangingCollector { label: "hung" }),
            ]);
            let mut avail = BTreeMap::new();
            avail.insert("fast".to_owned(), true);
            avail.insert("hung".to_owned(), true);

            // 50 ms timeout — hanging collector will always exceed this.
            let svc = ScrapeService::new(
                Arc::clone(&collectors),
                Arc::new(NopRegistry),
                50,
                Arc::new(avail),
            );

            // scrape() must succeed overall even when one collector hangs.
            let samples = svc
                .scrape()
                .await
                .expect("scrape must not propagate timeout");

            #[allow(
                clippy::float_cmp,
                reason = "integer-backed 0/1 gauge; exact equality correct"
            )]
            {
                // fast collector succeeds
                let fast_success =
                    find_sample(&samples, "nft_scrape_collector_success", Some("fast"));
                assert_eq!(
                    sample_f64(fast_success.expect("fast success gauge")),
                    1.0,
                    "fast collector must be success=1"
                );

                // hung collector is marked failed
                let hung_success =
                    find_sample(&samples, "nft_scrape_collector_success", Some("hung"));
                assert_eq!(
                    sample_f64(hung_success.expect("hung success gauge")),
                    0.0,
                    "hung collector must be success=0 after timeout"
                );
            }
        });
    }

    /// Verify that the cumulative error counter is incremented on each timeout.
    ///
    /// The `nft_scrape_collector_error_total` counter is backed by an
    /// `AtomicU64`; after N timed-out scrapes the counter must equal N.
    #[test]
    fn timeout_increments_error_counter() {
        let mut rt = build_rt!();
        rt.block_on(async {
            let collectors: Arc<Vec<Box<dyn Collector>>> =
                Arc::new(vec![Box::new(HangingCollector { label: "hung2" })]);
            let mut avail = BTreeMap::new();
            avail.insert("hung2".to_owned(), true);

            // 50 ms timeout — hanging collector always exceeds this.
            let svc = ScrapeService::new(
                Arc::clone(&collectors),
                Arc::new(NopRegistry),
                50,
                Arc::new(avail),
            );

            // First scrape — 1 timeout.
            let _ = svc.scrape().await.expect("scrape ok");
            // Second scrape — 2 timeouts total.
            let _ = svc.scrape().await.expect("scrape ok");
            // Third scrape — 3 timeouts total; read telemetry from this result.
            let samples = svc.scrape().await.expect("scrape ok");

            let err_counter =
                find_sample(&samples, "nft_scrape_collector_error_total", Some("hung2"));
            // The counter carries a U64 value; sample_f64 casts it losslessly
            // for uniform comparison (3 fits in f64 exactly).
            let count = sample_f64(err_counter.expect("error_total counter must be present"));

            // 3 scrapes × 1 timeout each = 3.
            #[allow(
                clippy::float_cmp,
                reason = "integer counter cast to f64; exact equality is correct"
            )]
            {
                assert_eq!(count, 3.0, "error counter must equal number of timeouts");
            }
        });
    }
}
