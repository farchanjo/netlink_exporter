//! `NETLINK_ROUTE` rtnetlink collector.
//!
//! Netlink family: `NETLINK_ROUTE` (0).
//! Messages used: `RTM_GETLINK`, `RTM_GETADDR`, `RTM_GETROUTE`, `RTM_GETNEIGH`.
//! ADR refs: ADR-0011 (direct wire), ADR-0014 (tokio AsyncFd confinement).

use nlx_domain::metric::MetricSample;
use nlx_domain::{
    error::DomainError,
    model::{
        address::AddressReadModel, link::LinkReadModel, neighbor::NeighborReadModel,
        route::RouteReadModel,
    },
};
use nlx_ports::{
    collector::{BoxFuture, Collector},
    driven::NetlinkRtPort,
    error::CollectError,
};

/// Adapter implementing [`NetlinkRtPort`] and [`Collector`] for the
/// `NETLINK_ROUTE` family (rtnetlink).
pub struct RtCollector;

impl NetlinkRtPort for RtCollector {
    async fn dump_links(&self) -> Result<Vec<LinkReadModel>, DomainError> {
        // TODO(impl): open NetlinkSocket(NETLINK_ROUTE), send RTM_GETLINK|NLM_F_DUMP,
        //   parse ifinfomsg + IFLA_STATS64, return LinkReadModel vec.
        todo!("RtCollector::dump_links")
    }

    async fn dump_addresses(&self) -> Result<Vec<AddressReadModel>, DomainError> {
        // TODO(impl): RTM_GETADDR|NLM_F_DUMP → ifaddrmsg + IFA_FLAGS.
        todo!("RtCollector::dump_addresses")
    }

    async fn dump_routes(&self) -> Result<Vec<RouteReadModel>, DomainError> {
        // TODO(impl): RTM_GETROUTE|NLM_F_DUMP → rtmsg aggregation key.
        todo!("RtCollector::dump_routes")
    }

    async fn dump_neighbors(&self) -> Result<Vec<NeighborReadModel>, DomainError> {
        // TODO(impl): RTM_GETNEIGH|NLM_F_DUMP → ndmsg aggregation key.
        todo!("RtCollector::dump_neighbors")
    }
}

impl Collector for RtCollector {
    fn name(&self) -> &str {
        "rtnetlink"
    }

    fn collect(&self) -> BoxFuture<'_, Result<Vec<MetricSample>, CollectError>> {
        Box::pin(async move {
            // TODO(impl): call dump_links, dump_addresses, dump_routes, dump_neighbors;
            //   map results to MetricSample vec.
            todo!("RtCollector::collect")
        })
    }

    fn probe_available(&self) -> BoxFuture<'_, bool> {
        Box::pin(async move {
            // NETLINK_ROUTE is always available; probe by opening a socket.
            // TODO(impl): try NetlinkSocket::open(NETLINK_ROUTE); return false on error.
            true
        })
    }
}
