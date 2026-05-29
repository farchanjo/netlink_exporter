//! `NETLINK_ROUTE` extended collectors — rtnetlink-extended bounded context.
//!
//! Netlink family: `NETLINK_ROUTE` (0).
//! Messages used (ADR-0021, netlink-protocol.md §17):
//!  - `RTM_GETSTATS` (94) → per-interface xstats (bridge mcast, hw offload).
//!  - `RTM_GETNEIGH` (30) with `AF_BRIDGE (7)` → bridge FDB entry counts.
//!  - `RTM_GETRULE` (82) with AF_INET/INET6/MPLS → FIB policy-rule counts.
//!  - `RTM_GETNEXTHOP` (118) → nexthop object total count.
//!
//! ## Runtime gate
//!
//! `probe_available()` sends a probe `RTM_GETSTATS` with `ifindex=1`.
//! `EINVAL` (errno 22) or `ENOTSUP` (errno 95) → returns `false`.  On kernels
//! < 5.3, `RTM_GETNEXTHOP` returns `EINVAL`; the nexthop metric emits 0 rather
//! than an error.
//!
//! ## Cardinality
//!
//! All metrics are labelled by interface name or address-family string only;
//! no per-prefix, per-MAC, or per-rule cardinality.

use std::collections::BTreeMap;

use nlx_domain::{error::DomainError, metric::MetricSample};
use nlx_ports::{
    collector::{BoxFuture, Collector},
    driven::NetlinkRtExtendedPort,
    error::CollectError,
};
use tracing::{debug, warn};

use crate::{
    transport::NetlinkSocket,
    wire::{nested_attrs, parse_attrs},
};

const NETLINK_ROUTE: i32 = 0;

// RTM message types (native-endian u16 in nlmsghdr.nlmsg_type).
// RTM_GETSTATS = 94, RTM_NEWSTATS = 93 (ADR-0021 §17.1).
const RTM_GETSTATS: u16 = 94;
// RTM_GETNEIGH = 30 (with ndmsg.ndm_family = AF_BRIDGE=7 for FDB).
const RTM_GETNEIGH: u16 = 30;
// RTM_GETRULE = 82 (FIB policy-routing rules).
const RTM_GETRULE: u16 = 82;
// RTM_GETNEXTHOP = 118 (kernel >= 5.3).
const RTM_GETNEXTHOP: u16 = 118;

// Address families.
const AF_UNSPEC: u8 = 0;
const AF_BRIDGE: u8 = 7;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const AF_MPLS: u8 = 28;

// if_stats_msg filter_mask bits (§17.1).
const IFLA_STATS_LINK_64: u32 = 1;
const IFLA_STATS_LINK_XSTATS: u32 = 2;
const IFLA_STATS_LINK_OFFLOAD_XSTATS: u32 = 8;

// Attributes in RTM_NEWSTATS replies (IFLA_STATS_* enum, effective types).
const IFLA_STATS_A_LINK_64: u16 = 1; // rtnl_link_stats64 blob
const IFLA_STATS_A_LINK_XSTATS: u16 = 2; // nested bridge/bond xstats
const IFLA_STATS_A_OFFLOAD_XSTATS: u16 = 4; // nested hw offload stats

// BRIDGE_XSTATS types inside IFLA_STATS_LINK_XSTATS.
const BRIDGE_XSTATS_VLAN: u16 = 1; // skip
const BRIDGE_XSTATS_MCAST: u16 = 2; // br_mcast_stats

// ifla_offload_xstats_type inside IFLA_STATS_LINK_OFFLOAD_XSTATS.
const IFLA_OFFLOAD_XSTATS_CPU_HIT: u16 = 1; // rtnl_hw_stats64
const IFLA_OFFLOAD_XSTATS_HW_S_INFO: u16 = 2; // skip
const IFLA_OFFLOAD_XSTATS_L3_STATS: u16 = 3; // rtnl_hw_stats64

// rtnl_hw_stats64 byte offsets (64 bytes, all u64 LE).
const HW_STATS64_RX_BYTES_OFF: usize = 16;
const HW_STATS64_TX_BYTES_OFF: usize = 24;

/// Adapter implementing [`NetlinkRtExtendedPort`] and [`Collector`] for extended
/// rtnetlink statistics.
pub struct RtExtendedCollector;

impl NetlinkRtExtendedPort for RtExtendedCollector {
    async fn dump_link_xstats(&self) -> Result<Vec<MetricSample>, DomainError> {
        let mut sock = NetlinkSocket::open(NETLINK_ROUTE)
            .map_err(|e| DomainError::Collector(e.to_string()))?;
        collect_link_xstats(&mut sock)
            .await
            .map_err(|e| DomainError::Collector(e.to_string()))
    }

    async fn dump_bridge_fdb_counts(&self) -> Result<Vec<MetricSample>, DomainError> {
        let mut sock = NetlinkSocket::open(NETLINK_ROUTE)
            .map_err(|e| DomainError::Collector(e.to_string()))?;
        collect_bridge_fdb(&mut sock)
            .await
            .map_err(|e| DomainError::Collector(e.to_string()))
    }

    async fn dump_fib_rule_counts(&self) -> Result<Vec<MetricSample>, DomainError> {
        let mut sock = NetlinkSocket::open(NETLINK_ROUTE)
            .map_err(|e| DomainError::Collector(e.to_string()))?;
        collect_fib_rules(&mut sock)
            .await
            .map_err(|e| DomainError::Collector(e.to_string()))
    }

    async fn dump_nexthop_count(&self) -> Result<u64, DomainError> {
        let mut sock = NetlinkSocket::open(NETLINK_ROUTE)
            .map_err(|e| DomainError::Collector(e.to_string()))?;
        collect_nexthop_count(&mut sock)
            .await
            .map_err(|e| DomainError::Collector(e.to_string()))
    }
}

impl Collector for RtExtendedCollector {
    fn name(&self) -> &str {
        "rtnetlink_extended"
    }

    fn collect(&self) -> BoxFuture<'_, Result<Vec<MetricSample>, CollectError>> {
        Box::pin(async move {
            let mut sock =
                NetlinkSocket::open(NETLINK_ROUTE).map_err(|e| CollectError::Io(e.to_string()))?;

            let mut out = Vec::new();

            // 1. Extended per-interface link stats (bridge mcast, offload).
            match collect_link_xstats(&mut sock).await {
                Ok(samples) => out.extend(samples),
                Err(e) => {
                    // EINVAL on kernel < 4.20 — treat as unavailable, not fatal.
                    if e.contains("errno=22") || e.contains("errno=95") {
                        debug!("RTM_GETSTATS not supported (kernel < 4.20); skipping xstats");
                    } else {
                        return Err(CollectError::Io(e));
                    }
                }
            }

            // 2. Bridge FDB entry counts.
            match collect_bridge_fdb(&mut sock).await {
                Ok(samples) => out.extend(samples),
                Err(e) => warn!(error = %e, "bridge FDB dump failed"),
            }

            // 3. FIB policy-rule counts.
            match collect_fib_rules(&mut sock).await {
                Ok(samples) => out.extend(samples),
                Err(e) => warn!(error = %e, "FIB rule dump failed"),
            }

            // 4. Nexthop object count.
            match collect_nexthop_count(&mut sock).await {
                Ok(count) => out.push(MetricSample::gauge(
                    "nft_nexthop_objects",
                    "Total installed kernel nexthop objects (kernel >= 5.3; 0 if unsupported).",
                    BTreeMap::new(),
                    count as f64,
                )),
                Err(e) => {
                    if e.contains("errno=22") {
                        // EINVAL — kernel < 5.3 (G-33).
                        out.push(MetricSample::gauge(
                            "nft_nexthop_objects",
                            "Total installed kernel nexthop objects (kernel >= 5.3; 0 if unsupported).",
                            BTreeMap::new(),
                            0.0,
                        ));
                    } else {
                        warn!(error = %e, "nexthop dump failed");
                    }
                }
            }

            Ok(out)
        })
    }

    fn probe_available(&self) -> BoxFuture<'_, bool> {
        Box::pin(async move {
            // Probe by sending RTM_GETSTATS with ifindex=1 (loopback), filter_mask=1.
            let Ok(mut sock) = NetlinkSocket::open(NETLINK_ROUTE) else {
                return false;
            };
            // if_stats_msg (16 bytes): family=0, pad=0, pad=0, ifindex=1, filter_mask=1.
            let mut body = vec![AF_UNSPEC, 0u8, 0u8, 0u8]; // family + 3 pad bytes
            body.extend_from_slice(&1u32.to_ne_bytes()); // ifindex = 1 (loopback)
            body.extend_from_slice(&IFLA_STATS_LINK_64.to_ne_bytes()); // filter_mask
            body.extend_from_slice(&0u32.to_ne_bytes()); // pad to 16 bytes

            match sock.request_single(RTM_GETSTATS, 0, &body).await {
                Ok(_) => true,
                Err(crate::transport::NetlinkError::KernelError { errno: 22 }) => false, // EINVAL
                Err(crate::transport::NetlinkError::KernelError { errno: 95 }) => false, // ENOTSUP
                Err(_) => false,
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Collection sub-functions
// ---------------------------------------------------------------------------

/// Dump `RTM_GETSTATS` and emit bridge-mcast and hw-offload xstat metrics.
async fn collect_link_xstats(sock: &mut NetlinkSocket) -> Result<Vec<MetricSample>, String> {
    // if_stats_msg (16 bytes): family=AF_UNSPEC, ifindex=0 (all), filter_mask.
    let filter: u32 = IFLA_STATS_LINK_XSTATS | IFLA_STATS_LINK_OFFLOAD_XSTATS;
    let body = build_if_stats_msg(0, filter);

    let mut restarts = 0u32;
    let frames = loop {
        match sock.dump(RTM_GETSTATS, 0, &body).await {
            Ok(f) => break f,
            Err(crate::transport::NetlinkError::DumpIntr) => {
                restarts += 1;
                if restarts >= crate::transport::MAX_DUMP_RESTARTS {
                    return Err("RTM_GETSTATS dump interrupted too many times".into());
                }
            }
            Err(e) => return Err(e.to_string()),
        }
    };

    let mut out = Vec::new();
    for frame in &frames {
        // RTM_NEWSTATS body starts with if_stats_msg (16 bytes).
        if frame.len() < 16 {
            continue;
        }
        // Extract ifindex from if_stats_msg at offset 4 (u32 LE, §17.1).
        let ifindex = u32::from_ne_bytes(frame[4..8].try_into().unwrap_or([0u8; 4]));
        // Build an interface label.  Without a link-name resolution map we use
        // the ifindex string — callers that have a link map can post-process.
        let if_label = format!("if{ifindex}");

        let attrs_buf = &frame[16..];
        for attr in parse_attrs(attrs_buf) {
            match attr.ty {
                IFLA_STATS_A_LINK_XSTATS => {
                    parse_bridge_xstats(attr.payload, &if_label, &mut out);
                }
                IFLA_STATS_A_OFFLOAD_XSTATS => {
                    parse_offload_xstats(attr.payload, &if_label, &mut out);
                }
                IFLA_STATS_A_LINK_64 => {
                    // Full rtnl_link_stats64 already collected by RtCollector.
                    // Not duplicated here.
                }
                _ => {}
            }
        }
    }
    Ok(out)
}

/// Dump `RTM_GETNEIGH` with `AF_BRIDGE` and count FDB entries per interface.
async fn collect_bridge_fdb(sock: &mut NetlinkSocket) -> Result<Vec<MetricSample>, String> {
    // ndmsg (12 bytes): family=AF_BRIDGE, rest zero.
    let mut body = [0u8; 12];
    body[0] = AF_BRIDGE;

    let mut restarts = 0u32;
    let frames = loop {
        match sock.dump(RTM_GETNEIGH, 0, &body).await {
            Ok(f) => break f,
            Err(crate::transport::NetlinkError::DumpIntr) => {
                restarts += 1;
                if restarts >= crate::transport::MAX_DUMP_RESTARTS {
                    return Err("RTM_GETNEIGH AF_BRIDGE dump interrupted".into());
                }
            }
            Err(e) => return Err(e.to_string()),
        }
    };

    // Count entries per ifindex (ndmsg.ndm_ifindex at bytes 4-7).
    let mut counts: BTreeMap<u32, u64> = BTreeMap::new();
    for frame in &frames {
        if frame.len() < 12 {
            continue;
        }
        // Only count AF_BRIDGE frames (ndm_family at byte 0).
        if frame[0] != AF_BRIDGE {
            continue;
        }
        let ifindex = u32::from_ne_bytes(frame[4..8].try_into().unwrap_or([0u8; 4]));
        *counts.entry(ifindex).or_insert(0) += 1;
    }

    let out = counts
        .into_iter()
        .map(|(ifindex, count)| {
            let mut labels = BTreeMap::new();
            labels.insert("interface".to_owned(), format!("if{ifindex}"));
            MetricSample::gauge(
                "nft_bridge_fdb_entries",
                "Bridge forwarding-database entry count per bridge interface.",
                labels,
                count as f64,
            )
        })
        .collect();
    Ok(out)
}

/// Dump `RTM_GETRULE` for AF_INET, AF_INET6, AF_MPLS and count rules per family.
async fn collect_fib_rules(sock: &mut NetlinkSocket) -> Result<Vec<MetricSample>, String> {
    let families: &[(&str, u8)] = &[("inet", AF_INET), ("inet6", AF_INET6), ("mpls", AF_MPLS)];
    let mut out = Vec::new();

    for (family_label, family) in families {
        // fib_rule_hdr (12 bytes, §17.5): family at byte 0.
        let mut body = [0u8; 12];
        body[0] = *family;

        let count = match sock.dump(RTM_GETRULE, 0, &body).await {
            Ok(frames) => frames.len() as u64,
            Err(crate::transport::NetlinkError::KernelError { errno: 22 }) => {
                // EINVAL — AF_MPLS rules on kernel < 4.3 (G-32); emit 0.
                debug!(
                    family = family_label,
                    "RTM_GETRULE EINVAL (kernel too old or AF not supported); emitting 0"
                );
                0
            }
            Err(crate::transport::NetlinkError::DumpIntr) => {
                warn!(
                    family = family_label,
                    "RTM_GETRULE dump interrupted; emitting 0"
                );
                0
            }
            Err(e) => return Err(e.to_string()),
        };

        let mut labels = BTreeMap::new();
        labels.insert("family".to_owned(), (*family_label).to_owned());
        out.push(MetricSample::gauge(
            "nft_fib_rules",
            "Number of installed FIB policy-routing rules per address family.",
            labels,
            count as f64,
        ));
    }
    Ok(out)
}

/// Dump `RTM_GETNEXTHOP` and return the total nexthop object count.
async fn collect_nexthop_count(sock: &mut NetlinkSocket) -> Result<u64, String> {
    // nhmsg (8 bytes, §17.6): all zero for AF_UNSPEC dump.
    let body = [0u8; 8];

    let frames = match sock.dump(RTM_GETNEXTHOP, 0, &body).await {
        Ok(f) => f,
        Err(crate::transport::NetlinkError::KernelError { errno: 22 }) => {
            // EINVAL — kernel < 5.3 (G-33).
            return Err("errno=22".into());
        }
        Err(e) => return Err(e.to_string()),
    };
    Ok(frames.len() as u64)
}

// ---------------------------------------------------------------------------
// Wire builders
// ---------------------------------------------------------------------------

/// Build `if_stats_msg` (16 bytes, §17.1).
fn build_if_stats_msg(ifindex: u32, filter_mask: u32) -> Vec<u8> {
    let mut body = Vec::with_capacity(16);
    body.push(AF_UNSPEC); // ifi_family
    body.push(0u8); // pad1
    body.extend_from_slice(&0u16.to_ne_bytes()); // pad2
    body.extend_from_slice(&ifindex.to_ne_bytes());
    body.extend_from_slice(&filter_mask.to_ne_bytes());
    body.extend_from_slice(&0u32.to_ne_bytes()); // pad to 16
    body
}

// ---------------------------------------------------------------------------
// xstat parsers
// ---------------------------------------------------------------------------

/// Parse `IFLA_STATS_LINK_XSTATS` payload (bridge mcast stats, §17.2).
fn parse_bridge_xstats(payload: &[u8], if_label: &str, out: &mut Vec<MetricSample>) {
    for attr in nested_attrs(payload) {
        match attr.ty {
            BRIDGE_XSTATS_MCAST => {
                // br_mcast_stats: rx_bytes @ 0 u64, tx_bytes @ 8 u64.
                if attr.payload.len() < 16 {
                    continue;
                }
                let rx = u64::from_ne_bytes(attr.payload[0..8].try_into().unwrap_or([0u8; 8]));
                let tx = u64::from_ne_bytes(attr.payload[8..16].try_into().unwrap_or([0u8; 8]));
                let mut labels = BTreeMap::new();
                labels.insert("interface".to_owned(), if_label.to_owned());
                out.push(MetricSample::counter(
                    "nft_link_xstats_bridge_rx_multicast_bytes_total",
                    "Bridge interface multicast receive bytes (RTM_GETSTATS BRIDGE_XSTATS_MCAST).",
                    labels.clone(),
                    rx,
                ));
                out.push(MetricSample::counter(
                    "nft_link_xstats_bridge_tx_multicast_bytes_total",
                    "Bridge interface multicast transmit bytes (RTM_GETSTATS BRIDGE_XSTATS_MCAST).",
                    labels,
                    tx,
                ));
            }
            BRIDGE_XSTATS_VLAN => {
                // br_vlan_stats — not exported.
            }
            _ => {}
        }
    }
}

/// Parse `IFLA_STATS_LINK_OFFLOAD_XSTATS` payload (hw stats, §17.3).
fn parse_offload_xstats(payload: &[u8], if_label: &str, out: &mut Vec<MetricSample>) {
    for attr in nested_attrs(payload) {
        match attr.ty {
            IFLA_OFFLOAD_XSTATS_CPU_HIT | IFLA_OFFLOAD_XSTATS_L3_STATS => {
                // rtnl_hw_stats64 (64 bytes): rx_bytes @ 16, tx_bytes @ 24.
                if attr.payload.len() < HW_STATS64_TX_BYTES_OFF + 8 {
                    continue;
                }
                let rx = u64::from_ne_bytes(
                    attr.payload[HW_STATS64_RX_BYTES_OFF..HW_STATS64_RX_BYTES_OFF + 8]
                        .try_into()
                        .unwrap_or([0u8; 8]),
                );
                let tx = u64::from_ne_bytes(
                    attr.payload[HW_STATS64_TX_BYTES_OFF..HW_STATS64_TX_BYTES_OFF + 8]
                        .try_into()
                        .unwrap_or([0u8; 8]),
                );
                let mut labels = BTreeMap::new();
                labels.insert("interface".to_owned(), if_label.to_owned());
                out.push(MetricSample::counter(
                    "nft_link_xstats_offload_rx_bytes_total",
                    "Hardware offload receive bytes per interface (RTM_GETSTATS OFFLOAD_XSTATS).",
                    labels.clone(),
                    rx,
                ));
                out.push(MetricSample::counter(
                    "nft_link_xstats_offload_tx_bytes_total",
                    "Hardware offload transmit bytes per interface (RTM_GETSTATS OFFLOAD_XSTATS).",
                    labels,
                    tx,
                ));
            }
            IFLA_OFFLOAD_XSTATS_HW_S_INFO => {
                // Availability info — skip.
            }
            _ => {}
        }
    }
}
