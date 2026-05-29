//! IPVS genetlink collector.
//!
//! Netlink family: `NETLINK_GENERIC` (16), family name `"IPVS"`.
//! Messages used: `IPVS_CMD_GET_SERVICE`, `IPVS_CMD_GET_DEST`.
//! ADR refs: ADR-0011, ADR-0014.

use nlx_domain::{
    error::DomainError,
    metric::MetricSample,
    model::ipvs::{IpvsDestination, IpvsService},
};
use nlx_ports::{
    collector::{BoxFuture, Collector},
    driven::NetlinkIpvsPort,
    error::CollectError,
};

/// Adapter implementing [`NetlinkIpvsPort`] and [`Collector`] for IPVS
/// virtual services and destinations.
pub struct IpvsCollector;

impl NetlinkIpvsPort for IpvsCollector {
    async fn dump_services(&self) -> Result<Vec<IpvsService>, DomainError> {
        todo!("IpvsCollector::dump_services")
    }

    async fn dump_destinations(
        &self,
        service: &IpvsService,
    ) -> Result<Vec<IpvsDestination>, DomainError> {
        let _ = service;
        todo!("IpvsCollector::dump_destinations")
    }
}

impl Collector for IpvsCollector {
    fn name(&self) -> &str {
        "ipvs"
    }

    fn collect(&self) -> BoxFuture<'_, Result<Vec<MetricSample>, CollectError>> {
        Box::pin(async move { todo!("IpvsCollector::collect") })
    }

    fn probe_available(&self) -> BoxFuture<'_, bool> {
        Box::pin(async move { false })
    }
}
