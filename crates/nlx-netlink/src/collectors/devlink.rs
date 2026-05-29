//! Devlink genetlink collector.
//!
//! Netlink family: `NETLINK_GENERIC` (16), family name `"devlink"`.
//! Messages used: `DEVLINK_CMD_GET`, `DEVLINK_CMD_PORT_GET`,
//!   `DEVLINK_CMD_HEALTH_REPORTER_GET`.
//! ADR refs: ADR-0011, ADR-0014.

use nlx_domain::{
    error::DomainError,
    metric::MetricSample,
    model::devlink::{DevlinkDevice, DevlinkHealthReporter, DevlinkPort},
};
use nlx_ports::{
    collector::{BoxFuture, Collector},
    driven::NetlinkDevlinkPort,
    error::CollectError,
};

/// Adapter implementing [`NetlinkDevlinkPort`] and [`Collector`] for devlink
/// device health and port metadata.
pub struct DevlinkCollector;

impl NetlinkDevlinkPort for DevlinkCollector {
    async fn dump_devices(&self) -> Result<Vec<DevlinkDevice>, DomainError> {
        todo!("DevlinkCollector::dump_devices")
    }

    async fn dump_ports(&self) -> Result<Vec<DevlinkPort>, DomainError> {
        todo!("DevlinkCollector::dump_ports")
    }

    async fn dump_health_reporters(&self) -> Result<Vec<DevlinkHealthReporter>, DomainError> {
        todo!("DevlinkCollector::dump_health_reporters")
    }
}

impl Collector for DevlinkCollector {
    fn name(&self) -> &str {
        "devlink"
    }

    fn collect(&self) -> BoxFuture<'_, Result<Vec<MetricSample>, CollectError>> {
        Box::pin(async move { todo!("DevlinkCollector::collect") })
    }

    fn probe_available(&self) -> BoxFuture<'_, bool> {
        Box::pin(async move { false })
    }
}
