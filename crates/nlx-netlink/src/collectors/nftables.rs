//! nftables collector.
//!
//! Netlink family: `NETLINK_NETFILTER` (12), nfnetlink nftables subsystem.
//! Messages used: `NFT_MSG_GETTABLE`, `NFT_MSG_GETCHAIN`, `NFT_MSG_GETCOUNTER`,
//!   `NFT_MSG_GETSET`, `NFT_MSG_GETRULE`.
//! ADR refs: ADR-0011 (direct wire, rustables removed), ADR-0014.

use nlx_domain::{
    error::DomainError,
    metric::MetricSample,
    model::nftables::{NftChain, NftCounter, NftSet, NftTable},
};
use nlx_ports::{
    collector::{BoxFuture, Collector},
    driven::NetlinkNftablesPort,
    error::CollectError,
};

/// Adapter implementing [`NetlinkNftablesPort`] and [`Collector`] for nftables
/// metadata and counters.
pub struct NftablesCollector;

impl NetlinkNftablesPort for NftablesCollector {
    async fn dump_tables(&self) -> Result<Vec<NftTable>, DomainError> {
        todo!("NftablesCollector::dump_tables")
    }

    async fn dump_chains(&self) -> Result<Vec<NftChain>, DomainError> {
        todo!("NftablesCollector::dump_chains")
    }

    async fn dump_counters(&self) -> Result<Vec<NftCounter>, DomainError> {
        todo!("NftablesCollector::dump_counters")
    }

    async fn dump_sets(&self) -> Result<Vec<NftSet>, DomainError> {
        todo!("NftablesCollector::dump_sets")
    }
}

impl Collector for NftablesCollector {
    fn name(&self) -> &str {
        "nftables"
    }

    fn collect(&self) -> BoxFuture<'_, Result<Vec<MetricSample>, CollectError>> {
        Box::pin(async move { todo!("NftablesCollector::collect") })
    }

    fn probe_available(&self) -> BoxFuture<'_, bool> {
        Box::pin(async move { true })
    }
}
