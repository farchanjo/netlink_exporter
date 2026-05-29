//! Collector registry — builds the enabled collector list from config.

use std::sync::Arc;

use nlx_config::ExporterConfig;
use nlx_netlink::collectors::{
    conntrack::ConntrackCollector, conntrack_expect::ConntrackExpectCollector,
    devlink::DevlinkCollector, drop_monitor::DropMonitorCollector, ethtool::EthtoolCollector,
    ipvs::IpvsCollector, nftables::NftablesCollector, rt::RtCollector,
    rt_extended::RtExtendedCollector, sockdiag::SockDiagCollector, tc::TcCollector,
    wireguard::WireguardCollector, xfrm::XfrmCollector,
};
use nlx_ports::collector::Collector;

/// Holds the runtime-enabled collector set.
pub struct CollectorRegistry {
    /// Shared reference to the collector list (used by [`ScrapeService`]).
    pub inner: Arc<Vec<Box<dyn Collector>>>,
}

impl CollectorRegistry {
    /// Build the collector set from the configuration's enable flags.
    ///
    /// Collectors disabled by config are not instantiated.
    pub fn from_config(config: &ExporterConfig) -> Self {
        let mut collectors: Vec<Box<dyn Collector>> = Vec::new();

        macro_rules! push_if_enabled {
            ($name:expr, $ctor:expr) => {
                if config.collector_enabled($name) {
                    collectors.push(Box::new($ctor));
                }
            };
        }

        push_if_enabled!("rtnetlink", RtCollector);
        push_if_enabled!("rtnetlink_extended", RtExtendedCollector);
        push_if_enabled!("traffic_control", TcCollector);
        push_if_enabled!("conntrack", ConntrackCollector);
        push_if_enabled!("conntrack_expect", ConntrackExpectCollector);
        push_if_enabled!("nftables", NftablesCollector);
        push_if_enabled!("sock_diag", SockDiagCollector);
        push_if_enabled!("ethtool", EthtoolCollector);
        push_if_enabled!("ipvs", IpvsCollector);
        push_if_enabled!("wireguard", WireguardCollector);
        push_if_enabled!("devlink", DevlinkCollector);
        push_if_enabled!("drop_monitor", DropMonitorCollector);
        push_if_enabled!("xfrm", XfrmCollector);

        Self {
            inner: Arc::new(collectors),
        }
    }
}
