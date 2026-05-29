//! Driven (right-side) port traits.
//!
//! Each trait in this module represents one outbound dependency boundary.
//! Infrastructure adapter crates implement these traits; the domain core only
//! knows the trait, never the concrete adapter.
//!
//! ## Netlink subsystem ports
//!
//! One trait per collector family (ADR-0011, ADR-0002):
//!
//! - [`NetlinkRtPort`] — `NETLINK_ROUTE` rtnetlink: links, addresses, routes,
//!   neighbors.
//! - [`NetlinkRtExtendedPort`] — `RTM_GETSTATS` extended stats, bridge FDB,
//!   FIB rules, nexthop objects (`rtnetlink-extended` context).
//! - [`NetlinkTcPort`] — Traffic control (`RTM_GETQDISC`, `RTM_GETTCLASS`,
//!   `RTM_GETTFILTER`).
//! - [`NetlinkConntrackPort`] — `NETLINK_NETFILTER` ctnetlink.
//! - [`NetlinkConntrackExpectPort`] — ctnetlink expectations subsystem.
//! - [`NetlinkNftablesPort`] — nfnetlink nftables.
//! - [`NetlinkSockDiagPort`] — `NETLINK_SOCK_DIAG`.
//! - [`NetlinkEthtoolPort`] — ethtool genetlink family.
//! - [`NetlinkIpvsPort`] — IPVS genetlink family.
//! - [`NetlinkWireguardPort`] — WireGuard genetlink family.
//! - [`NetlinkDevlinkPort`] — devlink genetlink family.
//! - [`NetlinkDropMonitorPort`] — drop-monitor genetlink family.
//! - [`NetlinkXfrmPort`] — `NETLINK_XFRM`.
//!
//! ## Infrastructure ports
//!
//! - [`MetricRegistryPort`] — OpenMetrics text exposition.
//! - [`ClockPort`] — monotonic clock abstraction for testability.
//! - [`ConfigPort`] — runtime configuration access.

use nlx_domain::{
    error::DomainError,
    metric::MetricSample,
    model::{
        address::AddressReadModel,
        conntrack::{ConntrackExpectEntry, ConntrackFlow, ConntrackStat},
        devlink::{DevlinkDevice, DevlinkHealthReporter, DevlinkPort},
        drop_monitor::DropEvent,
        ethtool::EthtoolStats,
        ipvs::{IpvsDestination, IpvsService},
        link::LinkReadModel,
        neighbor::NeighborReadModel,
        nftables::{NftChain, NftCounter, NftSet, NftTable},
        route::RouteReadModel,
        sockdiag::SockDiagEntry,
        tc::TcReadModel,
        wireguard::WireguardDevice,
        xfrm::{XfrmPolicy, XfrmSadInfo, XfrmSpdInfo, XfrmState},
    },
};

// ---------------------------------------------------------------------------
// Netlink subsystem driven ports
// ---------------------------------------------------------------------------

/// Driven port for `NETLINK_ROUTE` rtnetlink: links, addresses, routes,
/// neighbors.  Adapter: `nlx-netlink` (ADR-0011).
pub trait NetlinkRtPort: Send + Sync {
    /// Dump all network links.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] on netlink I/O failure.
    fn dump_links(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<LinkReadModel>, DomainError>> + Send;

    /// Dump all interface addresses.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] on netlink I/O failure.
    fn dump_addresses(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<AddressReadModel>, DomainError>> + Send;

    /// Dump all routes.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] on netlink I/O failure.
    fn dump_routes(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<RouteReadModel>, DomainError>> + Send;

    /// Dump all neighbor (ARP/NDP) entries.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] on netlink I/O failure.
    fn dump_neighbors(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<NeighborReadModel>, DomainError>> + Send;
}

/// Driven port for `RTM_GETSTATS` extended link stats, bridge FDB, FIB rules,
/// and nexthop objects (`rtnetlink-extended` context).  Adapter: `nlx-netlink`.
pub trait NetlinkRtExtendedPort: Send + Sync {
    /// Dump extended per-interface stats (`RTM_GETSTATS`).
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] on netlink I/O failure.
    fn dump_link_xstats(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<MetricSample>, DomainError>> + Send;

    /// Count bridge FDB entries per bridge device.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] on netlink I/O failure.
    fn dump_bridge_fdb_counts(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<MetricSample>, DomainError>> + Send;

    /// Count installed FIB policy-routing rules per address family.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] on netlink I/O failure.
    fn dump_fib_rule_counts(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<MetricSample>, DomainError>> + Send;

    /// Count installed nexthop objects (kernel >= 5.3).
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] on netlink I/O failure.
    fn dump_nexthop_count(
        &self,
    ) -> impl std::future::Future<Output = Result<u64, DomainError>> + Send;
}

/// Driven port for traffic control (`RTM_GETQDISC`, `RTM_GETTCLASS`,
/// `RTM_GETTFILTER`).  Adapter: `nlx-netlink` (ADR-0011).
pub trait NetlinkTcPort: Send + Sync {
    /// Dump all qdisc, class, and filter read models.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] on netlink I/O failure.
    fn dump_tc(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<TcReadModel>, DomainError>> + Send;
}

/// Driven port for `NETLINK_NETFILTER` ctnetlink conntrack flows and stats.
/// Adapter: `nlx-netlink` (ADR-0011).
pub trait NetlinkConntrackPort: Send + Sync {
    /// Dump all active conntrack flows.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] on netlink I/O failure.
    fn dump_flows(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<ConntrackFlow>, DomainError>> + Send;

    /// Fetch per-CPU conntrack stats via `IPCTNL_MSG_CT_GET_STATS_CPU`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] on netlink I/O failure.
    fn dump_stats(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<ConntrackStat>, DomainError>> + Send;
}

/// Driven port for ctnetlink expectations (`NFNL_SUBSYS_CTNETLINK_EXP`).
/// Adapter: `nlx-netlink` (ADR-0011).
pub trait NetlinkConntrackExpectPort: Send + Sync {
    /// Dump active conntrack expectations.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] on netlink I/O failure.
    fn dump_expectations(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<ConntrackExpectEntry>, DomainError>> + Send;
}

/// Driven port for nfnetlink nftables.  Adapter: `nlx-netlink` (ADR-0011).
pub trait NetlinkNftablesPort: Send + Sync {
    /// Dump all nftables tables.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] on netlink I/O failure.
    fn dump_tables(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<NftTable>, DomainError>> + Send;

    /// Dump all nftables chains.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] on netlink I/O failure.
    fn dump_chains(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<NftChain>, DomainError>> + Send;

    /// Dump all named counter objects.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] on netlink I/O failure.
    fn dump_counters(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<NftCounter>, DomainError>> + Send;

    /// Dump all named sets.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] on netlink I/O failure.
    fn dump_sets(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<NftSet>, DomainError>> + Send;
}

/// Driven port for `NETLINK_SOCK_DIAG` (`inet_diag`).
/// Adapter: `nlx-netlink` (ADR-0011).
pub trait NetlinkSockDiagPort: Send + Sync {
    /// Dump socket diagnostic entries for TCP and UDP.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] on netlink I/O failure.
    fn dump_sockets(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<SockDiagEntry>, DomainError>> + Send;
}

/// Driven port for the ethtool genetlink family
/// (`ETHTOOL_MSG_STATS_GET`, `ETHTOOL_MSG_LINKSETTINGS_GET`,
/// `ETHTOOL_MSG_PAUSE_GET`, `ETHTOOL_MSG_FEC_GET`).
/// Adapter: `nlx-netlink` (ADR-0011).
pub trait NetlinkEthtoolPort: Send + Sync {
    /// Dump ethtool statistics for all interfaces.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] on netlink I/O failure or genetlink family
    /// resolution failure.
    fn dump_ethtool_stats(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<EthtoolStats>, DomainError>> + Send;
}

/// Driven port for the IPVS genetlink family.
/// Adapter: `nlx-netlink` (ADR-0011).
pub trait NetlinkIpvsPort: Send + Sync {
    /// Dump IPVS virtual services.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] on netlink I/O failure.
    fn dump_services(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<IpvsService>, DomainError>> + Send;

    /// Dump IPVS real-server destinations for a given virtual service.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] on netlink I/O failure.
    fn dump_destinations(
        &self,
        service: &IpvsService,
    ) -> impl std::future::Future<Output = Result<Vec<IpvsDestination>, DomainError>> + Send;
}

/// Driven port for the WireGuard genetlink family (`WG_CMD_GET_DEVICE`).
/// Adapter: `nlx-netlink` (ADR-0011).
pub trait NetlinkWireguardPort: Send + Sync {
    /// Dump WireGuard device and peer metadata.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] on netlink I/O failure.
    fn dump_devices(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<WireguardDevice>, DomainError>> + Send;
}

/// Driven port for the devlink genetlink family
/// (`DEVLINK_CMD_GET`, `DEVLINK_CMD_PORT_GET`,
/// `DEVLINK_CMD_HEALTH_REPORTER_GET`).
/// Adapter: `nlx-netlink` (ADR-0011).
pub trait NetlinkDevlinkPort: Send + Sync {
    /// Dump devlink devices.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] on netlink I/O failure.
    fn dump_devices(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<DevlinkDevice>, DomainError>> + Send;

    /// Dump devlink ports.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] on netlink I/O failure.
    fn dump_ports(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<DevlinkPort>, DomainError>> + Send;

    /// Dump devlink health reporters.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] on netlink I/O failure.
    fn dump_health_reporters(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<DevlinkHealthReporter>, DomainError>> + Send;
}

/// Driven port for the drop-monitor genetlink family
/// (`NET_DM_CMD_MONITOR_START` / `NET_DM_ATTR_STATS`).
/// Adapter: `nlx-netlink` (ADR-0011).
pub trait NetlinkDropMonitorPort: Send + Sync {
    /// Retrieve aggregated drop events from the drop-monitor subsystem.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] on netlink I/O failure or module unavailability.
    fn dump_drop_events(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<DropEvent>, DomainError>> + Send;
}

/// Driven port for `NETLINK_XFRM`
/// (`XFRM_MSG_GETSA`, `XFRM_MSG_GETPOLICY`,
/// `XFRM_MSG_GETSADINFO`, `XFRM_MSG_GETSPDINFO`).
/// Adapter: `nlx-netlink` (ADR-0011).
pub trait NetlinkXfrmPort: Send + Sync {
    /// Dump XFRM Security Association states.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] on netlink I/O failure.
    fn dump_sa(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<XfrmState>, DomainError>> + Send;

    /// Dump XFRM Security Policies.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] on netlink I/O failure.
    fn dump_policies(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<XfrmPolicy>, DomainError>> + Send;

    /// Fetch SAD hash info (`XFRM_MSG_GETSADINFO`).
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] on netlink I/O failure.
    fn get_sad_info(
        &self,
    ) -> impl std::future::Future<Output = Result<XfrmSadInfo, DomainError>> + Send;

    /// Fetch SPD hash info (`XFRM_MSG_GETSPDINFO`).
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] on netlink I/O failure.
    fn get_spd_info(
        &self,
    ) -> impl std::future::Future<Output = Result<XfrmSpdInfo, DomainError>> + Send;
}

// ---------------------------------------------------------------------------
// Infrastructure driven ports
// ---------------------------------------------------------------------------

/// Driven port for OpenMetrics text exposition.
///
/// The `nlx-metrics` adapter implements this using `prometheus-client`.
pub trait MetricRegistryPort: Send + Sync {
    /// Register or update a batch of [`MetricSample`]s.
    ///
    /// The adapter is responsible for mapping `MetricSample` values to the
    /// internal prometheus-client registry representation.  Each call may be a
    /// full replacement (snapshot semantics) or incremental update depending on
    /// the adapter implementation.
    ///
    /// # Errors
    ///
    /// Returns a `String` error description on registration failure.
    fn update_samples(
        &self,
        samples: Vec<MetricSample>,
    ) -> impl std::future::Future<Output = Result<(), String>> + Send;

    /// Encode the current registry state as an OpenMetrics text body.
    ///
    /// Returns the UTF-8 encoded text exposition suitable for HTTP response.
    ///
    /// # Errors
    ///
    /// Returns a `String` error description on encoding failure.
    fn encode_text(&self) -> impl std::future::Future<Output = Result<String, String>> + Send;
}

/// Monotonic clock abstraction.
///
/// Enables deterministic time injection in tests.  The real adapter wraps
/// `std::time::Instant`.
pub trait ClockPort: Send + Sync {
    /// Returns the number of seconds elapsed since an arbitrary epoch.
    fn now_secs(&self) -> f64;
}

/// Runtime configuration access port.
///
/// Implemented by `nlx-config`'s `ExporterConfig` loader.
pub trait ConfigPort: Send + Sync {
    /// Scrape timeout in milliseconds.
    fn scrape_timeout_ms(&self) -> u64;

    /// HTTP listen address (e.g. `"0.0.0.0:9456"`).
    fn listen_addr(&self) -> &str;

    /// Returns `true` if the named collector is enabled.
    fn collector_enabled(&self, name: &str) -> bool;
}
