//! XFRM IPsec collector.
//!
//! Netlink family: `NETLINK_XFRM` (6).
//! Messages used: `XFRM_MSG_GETSA`, `XFRM_MSG_GETPOLICY`,
//!   `XFRM_MSG_GETSADINFO`, `XFRM_MSG_GETSPDINFO`.
//! ADR refs: ADR-0011, ADR-0014.

use nlx_domain::{
    error::DomainError,
    metric::MetricSample,
    model::xfrm::{XfrmPolicy, XfrmSadInfo, XfrmSpdInfo, XfrmState},
};
use nlx_ports::{
    collector::{BoxFuture, Collector},
    driven::NetlinkXfrmPort,
    error::CollectError,
};

/// Adapter implementing [`NetlinkXfrmPort`] and [`Collector`] for XFRM
/// IPsec Security Associations and Policies.
pub struct XfrmCollector;

impl NetlinkXfrmPort for XfrmCollector {
    async fn dump_sa(&self) -> Result<Vec<XfrmState>, DomainError> {
        todo!("XfrmCollector::dump_sa")
    }

    async fn dump_policies(&self) -> Result<Vec<XfrmPolicy>, DomainError> {
        todo!("XfrmCollector::dump_policies")
    }

    async fn get_sad_info(&self) -> Result<XfrmSadInfo, DomainError> {
        todo!("XfrmCollector::get_sad_info")
    }

    async fn get_spd_info(&self) -> Result<XfrmSpdInfo, DomainError> {
        todo!("XfrmCollector::get_spd_info")
    }
}

impl Collector for XfrmCollector {
    fn name(&self) -> &str {
        "xfrm"
    }

    fn collect(&self) -> BoxFuture<'_, Result<Vec<MetricSample>, CollectError>> {
        Box::pin(async move { todo!("XfrmCollector::collect") })
    }

    fn probe_available(&self) -> BoxFuture<'_, bool> {
        Box::pin(async move { true })
    }
}
