//! Traffic-control collector.
//!
//! Netlink family: `NETLINK_ROUTE` (0).
//! Messages used: `RTM_GETQDISC`, `RTM_GETTCLASS`, `RTM_GETTFILTER`.
//! ADR refs: ADR-0011 (TCA_STATS2 NLA_F_NESTED bit-15 masking), ADR-0014.

use nlx_domain::{error::DomainError, metric::MetricSample, model::tc::TcReadModel};
use nlx_ports::{
    collector::{BoxFuture, Collector},
    driven::NetlinkTcPort,
    error::CollectError,
};

/// Adapter implementing [`NetlinkTcPort`] and [`Collector`] for traffic
/// control statistics.
pub struct TcCollector;

impl NetlinkTcPort for TcCollector {
    async fn dump_tc(&self) -> Result<Vec<TcReadModel>, DomainError> {
        todo!("TcCollector::dump_tc")
    }
}

impl Collector for TcCollector {
    fn name(&self) -> &str {
        "traffic_control"
    }

    fn collect(&self) -> BoxFuture<'_, Result<Vec<MetricSample>, CollectError>> {
        Box::pin(async move { todo!("TcCollector::collect") })
    }

    fn probe_available(&self) -> BoxFuture<'_, bool> {
        Box::pin(async move { true })
    }
}
