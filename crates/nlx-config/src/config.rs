//! `ExporterConfig` — the merged configuration value object.

use serde::{Deserialize, Serialize};

/// Collector enable/disable flags.
///
/// Each flag corresponds to one [`nlx_ports::collector::Collector`]
/// implementation.  Disabled collectors are skipped at startup probe time and
/// produce no metric series.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CollectorFlags {
    /// Enable the `rtnetlink` collector (links, addresses, routes, neighbors).
    pub rtnetlink: bool,
    /// Enable the `rtnetlink_extended` collector (xstats, bridge FDB, FIB rules,
    /// nexthop objects).
    pub rtnetlink_extended: bool,
    /// Enable the `traffic_control` collector (qdisc, class, filter).
    pub traffic_control: bool,
    /// Enable the `conntrack` collector.
    pub conntrack: bool,
    /// Enable the `conntrack_expect` collector.
    pub conntrack_expect: bool,
    /// Enable the `nftables` collector.
    pub nftables: bool,
    /// Enable the `sock_diag` collector.
    pub sock_diag: bool,
    /// Enable the `ethtool` collector.
    pub ethtool: bool,
    /// Enable the `ipvs` collector.
    pub ipvs: bool,
    /// Enable the `wireguard` collector.
    pub wireguard: bool,
    /// Enable the `devlink` collector.
    pub devlink: bool,
    /// Enable the `drop_monitor` collector.
    pub drop_monitor: bool,
    /// Enable the `xfrm` collector.
    pub xfrm: bool,
}

impl Default for CollectorFlags {
    fn default() -> Self {
        Self {
            rtnetlink: true,
            rtnetlink_extended: true,
            traffic_control: true,
            conntrack: true,
            conntrack_expect: true,
            nftables: true,
            sock_diag: true,
            ethtool: false, // runtime-gated: probe required
            ipvs: false,
            wireguard: false,
            devlink: false,
            drop_monitor: false,
            xfrm: false,
        }
    }
}

/// Full exporter configuration.
///
/// Loaded from (in order of precedence): CLI flags → `NLX_*` env vars →
/// TOML file → built-in defaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ExporterConfig {
    /// HTTP listen address for the metrics and health endpoints.
    pub listen_addr: String,

    /// Scrape timeout in milliseconds per collector.
    pub scrape_timeout_ms: u64,

    /// Maximum `NLM_F_DUMP_INTR` restarts before activating stale-snapshot
    /// fallback (ADR-0011).
    pub netlink_dump_max_restarts: u32,

    /// Log level string (e.g. `"info"`, `"debug"`).
    pub log_level: String,

    /// Optional regex for interface names to include (all if `None`).
    pub interface_include_regex: Option<String>,

    /// Optional regex for interface names to exclude (none if `None`).
    pub interface_exclude_regex: Option<String>,

    /// Maximum number of WireGuard peers to export per interface.
    pub wireguard_max_peers: usize,

    /// Collector enable flags.
    pub collectors: CollectorFlags,
}

impl Default for ExporterConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:9456".to_owned(),
            scrape_timeout_ms: 30_000,
            netlink_dump_max_restarts: 8,
            log_level: "info".to_owned(),
            interface_include_regex: None,
            interface_exclude_regex: None,
            wireguard_max_peers: 1_000,
            collectors: CollectorFlags::default(),
        }
    }
}

impl nlx_ports::driven::ConfigPort for ExporterConfig {
    fn scrape_timeout_ms(&self) -> u64 {
        self.scrape_timeout_ms
    }

    fn listen_addr(&self) -> &str {
        &self.listen_addr
    }

    fn collector_enabled(&self, name: &str) -> bool {
        match name {
            "rtnetlink" => self.collectors.rtnetlink,
            "rtnetlink_extended" => self.collectors.rtnetlink_extended,
            "traffic_control" => self.collectors.traffic_control,
            "conntrack" => self.collectors.conntrack,
            "conntrack_expect" => self.collectors.conntrack_expect,
            "nftables" => self.collectors.nftables,
            "sock_diag" => self.collectors.sock_diag,
            "ethtool" => self.collectors.ethtool,
            "ipvs" => self.collectors.ipvs,
            "wireguard" => self.collectors.wireguard,
            "devlink" => self.collectors.devlink,
            "drop_monitor" => self.collectors.drop_monitor,
            "xfrm" => self.collectors.xfrm,
            _ => false,
        }
    }
}
