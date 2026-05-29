//! WireGuard genetlink collector.
//!
//! Netlink family: `NETLINK_GENERIC` (16), family name `"wireguard"`.
//! Messages used: `WG_CMD_GET_DEVICE`.
//! ADR refs: ADR-0011, ADR-0014.

use nlx_domain::{error::DomainError, metric::MetricSample, model::wireguard::WireguardDevice};
use nlx_ports::{
    collector::{BoxFuture, Collector},
    driven::NetlinkWireguardPort,
    error::CollectError,
};

/// Adapter implementing [`NetlinkWireguardPort`] and [`Collector`] for
/// WireGuard device and peer statistics.
pub struct WireguardCollector;

impl NetlinkWireguardPort for WireguardCollector {
    async fn dump_devices(&self) -> Result<Vec<WireguardDevice>, DomainError> {
        todo!("WireguardCollector::dump_devices")
    }
}

impl Collector for WireguardCollector {
    fn name(&self) -> &str {
        "wireguard"
    }

    fn collect(&self) -> BoxFuture<'_, Result<Vec<MetricSample>, CollectError>> {
        Box::pin(async move { todo!("WireguardCollector::collect") })
    }

    fn probe_available(&self) -> BoxFuture<'_, bool> {
        Box::pin(async move { false })
    }
}
