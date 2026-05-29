//! Drop-monitor genetlink collector.
//!
//! Netlink family: `NETLINK_GENERIC` (16), family name `"NET_DM"`.
//! Flow: `NET_DM_CMD_MONITOR_START` (summary mode),
//!   then periodic `NET_DM_ATTR_STATS` dump for aggregated counts.
//! ADR refs: ADR-0011, ADR-0014.

use nlx_domain::{error::DomainError, metric::MetricSample, model::drop_monitor::DropEvent};
use nlx_ports::{
    collector::{BoxFuture, Collector},
    driven::NetlinkDropMonitorPort,
    error::CollectError,
};

/// Adapter implementing [`NetlinkDropMonitorPort`] and [`Collector`] for
/// drop-monitor event aggregation.
pub struct DropMonitorCollector;

impl NetlinkDropMonitorPort for DropMonitorCollector {
    async fn dump_drop_events(&self) -> Result<Vec<DropEvent>, DomainError> {
        todo!("DropMonitorCollector::dump_drop_events")
    }
}

impl Collector for DropMonitorCollector {
    fn name(&self) -> &str {
        "drop_monitor"
    }

    fn collect(&self) -> BoxFuture<'_, Result<Vec<MetricSample>, CollectError>> {
        Box::pin(async move { todo!("DropMonitorCollector::collect") })
    }

    fn probe_available(&self) -> BoxFuture<'_, bool> {
        Box::pin(async move { false })
    }
}
