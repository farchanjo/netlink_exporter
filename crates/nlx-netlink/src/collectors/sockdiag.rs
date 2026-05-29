//! Socket-diagnostics collector.
//!
//! Netlink family: `NETLINK_SOCK_DIAG` (4).
//! Messages used: `SOCK_DIAG_BY_FAMILY` (`inet_diag_req_v2`) for TCP and UDP.
//! ADR refs: ADR-0011, ADR-0014.

use nlx_domain::{error::DomainError, metric::MetricSample, model::sockdiag::SockDiagEntry};
use nlx_ports::{
    collector::{BoxFuture, Collector},
    driven::NetlinkSockDiagPort,
    error::CollectError,
};

/// Adapter implementing [`NetlinkSockDiagPort`] and [`Collector`] for
/// socket diagnostics.
pub struct SockDiagCollector;

impl NetlinkSockDiagPort for SockDiagCollector {
    async fn dump_sockets(&self) -> Result<Vec<SockDiagEntry>, DomainError> {
        todo!("SockDiagCollector::dump_sockets")
    }
}

impl Collector for SockDiagCollector {
    fn name(&self) -> &str {
        "sock_diag"
    }

    fn collect(&self) -> BoxFuture<'_, Result<Vec<MetricSample>, CollectError>> {
        Box::pin(async move { todo!("SockDiagCollector::collect") })
    }

    fn probe_available(&self) -> BoxFuture<'_, bool> {
        Box::pin(async move { true })
    }
}
