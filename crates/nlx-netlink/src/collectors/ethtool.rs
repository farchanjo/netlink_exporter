//! Ethtool genetlink collector.
//!
//! Netlink family: `NETLINK_GENERIC` (16), family name `"ethtool"`.
//! Messages used: `ETHTOOL_MSG_STATS_GET`, `ETHTOOL_MSG_LINKSETTINGS_GET`,
//!   `ETHTOOL_MSG_PAUSE_GET`, `ETHTOOL_MSG_FEC_GET`.
//! ADR refs: ADR-0011 (genetlink family resolution via `CTRL_CMD_GETFAMILY`),
//!   ADR-0014.

use nlx_domain::{error::DomainError, metric::MetricSample, model::ethtool::EthtoolStats};
use nlx_ports::{
    collector::{BoxFuture, Collector},
    driven::NetlinkEthtoolPort,
    error::CollectError,
};

/// Adapter implementing [`NetlinkEthtoolPort`] and [`Collector`] for ethtool
/// statistics.
pub struct EthtoolCollector;

impl NetlinkEthtoolPort for EthtoolCollector {
    async fn dump_ethtool_stats(&self) -> Result<Vec<EthtoolStats>, DomainError> {
        todo!("EthtoolCollector::dump_ethtool_stats")
    }
}

impl Collector for EthtoolCollector {
    fn name(&self) -> &str {
        "ethtool"
    }

    fn collect(&self) -> BoxFuture<'_, Result<Vec<MetricSample>, CollectError>> {
        Box::pin(async move { todo!("EthtoolCollector::collect") })
    }

    fn probe_available(&self) -> BoxFuture<'_, bool> {
        Box::pin(async move { false })
    }
}
