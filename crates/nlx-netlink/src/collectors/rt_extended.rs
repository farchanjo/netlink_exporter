//! `RTM_GETSTATS` extended link stats, bridge FDB, FIB rules, nexthop objects.
//!
//! Netlink family: `NETLINK_ROUTE` (0).
//! Messages used: `RTM_GETSTATS` (kernel >= 4.20), `RTM_GETNEIGH` (AF_BRIDGE),
//!   `RTM_GETRULE`, `RTM_GETNEXTHOP` (kernel >= 5.3).
//! ADR refs: ADR-0011, ADR-0014.

use nlx_domain::{error::DomainError, metric::MetricSample};
use nlx_ports::{
    collector::{BoxFuture, Collector},
    driven::NetlinkRtExtendedPort,
    error::CollectError,
};

/// Adapter implementing [`NetlinkRtExtendedPort`] and [`Collector`] for
/// extended rtnetlink statistics.
pub struct RtExtendedCollector;

impl NetlinkRtExtendedPort for RtExtendedCollector {
    async fn dump_link_xstats(&self) -> Result<Vec<MetricSample>, DomainError> {
        todo!("RtExtendedCollector::dump_link_xstats")
    }

    async fn dump_bridge_fdb_counts(&self) -> Result<Vec<MetricSample>, DomainError> {
        todo!("RtExtendedCollector::dump_bridge_fdb_counts")
    }

    async fn dump_fib_rule_counts(&self) -> Result<Vec<MetricSample>, DomainError> {
        todo!("RtExtendedCollector::dump_fib_rule_counts")
    }

    async fn dump_nexthop_count(&self) -> Result<u64, DomainError> {
        todo!("RtExtendedCollector::dump_nexthop_count")
    }
}

impl Collector for RtExtendedCollector {
    fn name(&self) -> &str {
        "rtnetlink_extended"
    }

    fn collect(&self) -> BoxFuture<'_, Result<Vec<MetricSample>, CollectError>> {
        Box::pin(async move {
            // TODO(impl): fan-out to all dump_* methods and merge into MetricSample vec.
            todo!("RtExtendedCollector::collect")
        })
    }

    fn probe_available(&self) -> BoxFuture<'_, bool> {
        Box::pin(async move {
            // Probe by sending RTM_GETSTATS; EINVAL on kernel < 4.20 → false.
            true
        })
    }
}
