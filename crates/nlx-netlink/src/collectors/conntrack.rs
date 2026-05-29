//! Conntrack collector.
//!
//! Netlink family: `NETLINK_NETFILTER` (12).
//! Messages used: `IPCTNL_MSG_CT_GET` (flow dump),
//!   `IPCTNL_MSG_CT_GET_STATS_CPU` (per-CPU stats, nf_conntrack_stat struct
//!   size 52/56/60 bytes depending on kernel version).
//! ADR refs: ADR-0011 (procfs path empty; ctnetlink is sole source), ADR-0014.

use nlx_domain::{
    error::DomainError,
    metric::MetricSample,
    model::conntrack::{ConntrackFlow, ConntrackStat},
};
use nlx_ports::{
    collector::{BoxFuture, Collector},
    driven::NetlinkConntrackPort,
    error::CollectError,
};

/// Adapter implementing [`NetlinkConntrackPort`] and [`Collector`] for
/// conntrack flows and per-CPU statistics.
pub struct ConntrackCollector;

impl NetlinkConntrackPort for ConntrackCollector {
    async fn dump_flows(&self) -> Result<Vec<ConntrackFlow>, DomainError> {
        todo!("ConntrackCollector::dump_flows")
    }

    async fn dump_stats(&self) -> Result<Vec<ConntrackStat>, DomainError> {
        todo!("ConntrackCollector::dump_stats")
    }
}

impl Collector for ConntrackCollector {
    fn name(&self) -> &str {
        "conntrack"
    }

    fn collect(&self) -> BoxFuture<'_, Result<Vec<MetricSample>, CollectError>> {
        Box::pin(async move { todo!("ConntrackCollector::collect") })
    }

    fn probe_available(&self) -> BoxFuture<'_, bool> {
        Box::pin(async move { true })
    }
}
