//! Conntrack expectations collector.
//!
//! Netlink family: `NETLINK_NETFILTER` (12), subsystem `NFNL_SUBSYS_CTNETLINK_EXP` (2).
//! Messages used: `IPCTNL_MSG_EXP_GET` (expectation dump, nlmsg_type=0x0200),
//!   `IPCTNL_MSG_EXP_GET_STATS_CPU` (per-CPU stats, nlmsg_type=0x0203).
//! ADR refs: ADR-0011, ADR-0014.

use nlx_domain::{
    error::DomainError, metric::MetricSample, model::conntrack::ConntrackExpectEntry,
};
use nlx_ports::{
    collector::{BoxFuture, Collector},
    driven::NetlinkConntrackExpectPort,
    error::CollectError,
};

/// Adapter implementing [`NetlinkConntrackExpectPort`] and [`Collector`] for
/// conntrack expectations.
pub struct ConntrackExpectCollector;

impl NetlinkConntrackExpectPort for ConntrackExpectCollector {
    async fn dump_expectations(&self) -> Result<Vec<ConntrackExpectEntry>, DomainError> {
        todo!("ConntrackExpectCollector::dump_expectations")
    }
}

impl Collector for ConntrackExpectCollector {
    fn name(&self) -> &str {
        "conntrack_expect"
    }

    fn collect(&self) -> BoxFuture<'_, Result<Vec<MetricSample>, CollectError>> {
        Box::pin(async move { todo!("ConntrackExpectCollector::collect") })
    }

    fn probe_available(&self) -> BoxFuture<'_, bool> {
        Box::pin(async move { true })
    }
}
