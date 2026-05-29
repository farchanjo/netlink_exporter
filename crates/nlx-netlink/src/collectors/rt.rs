//! `NETLINK_ROUTE` rtnetlink collector.
//!
//! Netlink family: `NETLINK_ROUTE` (0).
//! Messages used: `RTM_GETLINK`, `RTM_GETADDR`, `RTM_GETROUTE`, `RTM_GETNEIGH`.
//! ADR refs: ADR-0011 (direct wire), ADR-0014 (tokio AsyncFd confinement).
//!
//! ## Wire layout references (netlink-protocol.md §4)
//!
//! - `ifinfomsg` 16 B: family(1) pad(1) type(2) index(4) flags(4) change(4)
//! - `ifaddrmsg` 8 B: family(1) prefixlen(1) flags(1) scope(1) index(4)
//! - `rtmsg` 12 B: family(1) dst_len(1) src_len(1) tos(1) table(1) proto(1)
//!   scope(1) type(1) flags(4)
//! - `ndmsg` 12 B: family(1) pad1(1) pad2(2) ifindex(4) state(2) flags(1)
//!   type(1)
//! - `rtnl_link_stats64` at IFLA_STATS64: 192-200 B of u64 LE fields

use std::collections::BTreeMap;

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
use tracing::{debug, warn};

use crate::transport::{MAX_DUMP_RESTARTS, NetlinkError, NetlinkSocket};
use crate::wire::{parse_attrs, read_u8, read_u32, read_u64};

// ---------------------------------------------------------------------------
// NETLINK_ROUTE constant
// ---------------------------------------------------------------------------
const NETLINK_ROUTE: i32 = 0;

// RTM_GET* message type constants (from linux/rtnetlink.h)
const RTM_GETLINK: u16 = 18;
const RTM_GETADDR: u16 = 22;
const RTM_GETROUTE: u16 = 26;
const RTM_GETNEIGH: u16 = 30;

// Address families
const AF_UNSPEC: u8 = 0;
const AF_BRIDGE: u8 = 7;

// IFF flags (ifi_flags)
const IFF_UP: u32 = 0x1;
const IFF_RUNNING: u32 = 0x40;

// IFLA_* attribute types
const IFLA_IFNAME: u16 = 3;
const IFLA_OPERSTATE: u16 = 16;
const IFLA_STATS64: u16 = 23;

// rtnl_link_stats64 field offsets (LE u64 values)
const STATS64_RX_PACKETS: usize = 0;
const STATS64_TX_PACKETS: usize = 8;
const STATS64_RX_BYTES: usize = 16;
const STATS64_TX_BYTES: usize = 24;
const STATS64_RX_ERRORS: usize = 32;
const STATS64_TX_ERRORS: usize = 40;
const STATS64_RX_DROPPED: usize = 48;
const STATS64_TX_DROPPED: usize = 56;

// NDA_* neighbour attribute types (not parsed — ADR-0005 cardinality guard).
// Kept as named constants for documentation; not read in code.
#[expect(
    dead_code,
    reason = "ADR-0005: NDA_DST payload is never stored or emitted"
)]
const NDA_DST: u16 = 1;
#[expect(
    dead_code,
    reason = "ADR-0005: NDA_LLADDR payload is never stored or emitted"
)]
const NDA_LLADDR: u16 = 2;

// NUD state bit constants for neighbour entries
const NUD_INCOMPLETE: u16 = 0x01;
const NUD_REACHABLE: u16 = 0x02;
const NUD_STALE: u16 = 0x04;
const NUD_DELAY: u16 = 0x08;
const NUD_PROBE: u16 = 0x10;
const NUD_FAILED: u16 = 0x20;
const NUD_NOARP: u16 = 0x40;
const NUD_PERMANENT: u16 = 0x80;

// RTA_TABLE attribute for route (overrides rtmsg.rtm_table for IDs > 255)
const RTA_TABLE: u16 = 15;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Convert `ifinfomsg.ifi_family`/`ifaddrmsg.ifa_family`/`ndmsg.ndm_family`
/// to a label string (inet/inet6/other).
fn family_label(family: u8) -> &'static str {
    match family {
        2 => "inet",
        10 => "inet6",
        _ => "other",
    }
}

/// Convert a NUD state bit-field to a label string.
fn nud_state_label(state: u16) -> &'static str {
    // State is one bit set at a time (per kernel docs).
    if state & NUD_PERMANENT != 0 {
        "permanent"
    } else if state & NUD_REACHABLE != 0 {
        "reachable"
    } else if state & NUD_STALE != 0 {
        "stale"
    } else if state & NUD_DELAY != 0 {
        "delay"
    } else if state & NUD_PROBE != 0 {
        "probe"
    } else if state & NUD_FAILED != 0 {
        "failed"
    } else if state & NUD_NOARP != 0 {
        "noarp"
    } else if state & NUD_INCOMPLETE != 0 {
        "incomplete"
    } else {
        "unknown"
    }
}

/// Decode a NUL-terminated interface name from `IFLA_IFNAME` payload.
fn decode_ifname(payload: &[u8]) -> Option<String> {
    // Strip trailing NUL byte(s) if present.
    let trimmed = payload
        .iter()
        .position(|&b| b == 0)
        .map_or(payload, |pos| &payload[..pos]);
    std::str::from_utf8(trimmed).ok().map(str::to_owned)
}

/// Build a zeroed `ifinfomsg` (16 bytes), ifi_family=AF_UNSPEC, for a full
/// RTM_GETLINK dump. A correctly-sized fixed header is mandatory when the
/// kernel has NETLINK_GET_STRICT_CHK enabled — a short `rtgenmsg` yields
/// EINVAL and an empty dump.
fn ifinfomsg_payload() -> [u8; 16] {
    [0u8; 16]
}

/// Build a zeroed `ifaddrmsg` (8 bytes) for a full RTM_GETADDR dump.
fn ifaddrmsg_payload() -> [u8; 8] {
    [0u8; 8]
}

/// Build a zeroed `rtmsg` (12 bytes) for a DUMP of all routes.
fn rtmsg_payload() -> [u8; 12] {
    [0u8; 12]
}

/// Build a zeroed `ndmsg` (12 bytes) for a full RTM_GETNEIGH dump.
fn ndmsg_payload() -> [u8; 12] {
    [0u8; 12]
}

/// Run a dump with up to `MAX_DUMP_RESTARTS` retries on `DumpIntr`.
async fn dump_with_retries(
    sock: &mut NetlinkSocket,
    msg_type: u16,
    payload: &[u8],
) -> Result<Vec<Vec<u8>>, NetlinkError> {
    let mut restarts = 0u32;
    loop {
        match sock.dump(msg_type, 0, payload).await {
            Ok(frames) => return Ok(frames),
            Err(NetlinkError::DumpIntr) => {
                restarts += 1;
                if restarts >= MAX_DUMP_RESTARTS {
                    warn!(msg_type, restarts, "NLM_F_DUMP_INTR max restarts exceeded");
                    return Err(NetlinkError::DumpIntr);
                }
                debug!(msg_type, restarts, "NLM_F_DUMP_INTR — retrying");
            }
            Err(e) => return Err(e),
        }
    }
}

/// Map a `NetlinkError` to a `CollectError`.
fn nl_err_to_collect(e: NetlinkError) -> CollectError {
    match e {
        NetlinkError::DumpIntr => CollectError::DumpIntr,
        NetlinkError::RecvBufOverflow => CollectError::RecvBufOverflow,
        NetlinkError::Parse(s) => CollectError::Parse(s),
        other => CollectError::Io(other.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Link stats collection (RTM_GETLINK)
// ---------------------------------------------------------------------------

struct LinkStats {
    name: String,
    up: bool,
    rx_bytes: u64,
    tx_bytes: u64,
    rx_packets: u64,
    tx_packets: u64,
    rx_errors: u64,
    tx_errors: u64,
    rx_dropped: u64,
    tx_dropped: u64,
}

/// Parse a single `RTM_NEWLINK` frame payload into a `LinkStats`.
///
/// Frame layout: `ifinfomsg` (16 B) + rtattrs.
fn parse_link_frame(payload: &[u8]) -> Option<LinkStats> {
    // ifinfomsg is 16 bytes.
    if payload.len() < 16 {
        return None;
    }
    // ifi_flags at offset 8 (u32 LE).
    let ifi_flags = u32::from_ne_bytes([payload[8], payload[9], payload[10], payload[11]]);

    // RTattrs start at offset 16 (NLMSG_ALIGN(ifinfomsg) = 16).
    let attr_buf = &payload[16..];

    let mut name: Option<String> = None;
    let mut operstate: Option<u8> = None;
    let mut stats64_payload: Option<&[u8]> = None;

    for attr in parse_attrs(attr_buf) {
        match attr.ty {
            IFLA_IFNAME => {
                name = decode_ifname(attr.payload);
            }
            IFLA_OPERSTATE => {
                operstate = read_u8(attr.payload);
            }
            IFLA_STATS64 => {
                if attr.payload.len() >= 64 {
                    // We need at least through tx_dropped offset 56+8=64.
                    stats64_payload = Some(attr.payload);
                }
            }
            _ => {}
        }
    }

    let name = name?;

    // Determine link-up: operstate=6 means "up"; also check IFF_UP | IFF_RUNNING.
    let up = operstate.map_or_else(|| ifi_flags & IFF_UP != 0, |s| s == 6)
        && (ifi_flags & IFF_UP != 0)
        && (ifi_flags & IFF_RUNNING != 0);

    let (rx_bytes, tx_bytes, rx_packets, tx_packets, rx_errors, tx_errors, rx_dropped, tx_dropped) =
        stats64_payload.map_or((0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64), |s| {
            let rx_packets = read_u64(&s[STATS64_RX_PACKETS..]).unwrap_or(0);
            let tx_packets = read_u64(&s[STATS64_TX_PACKETS..]).unwrap_or(0);
            let rx_bytes = read_u64(&s[STATS64_RX_BYTES..]).unwrap_or(0);
            let tx_bytes = read_u64(&s[STATS64_TX_BYTES..]).unwrap_or(0);
            let rx_errors = read_u64(&s[STATS64_RX_ERRORS..]).unwrap_or(0);
            let tx_errors = read_u64(&s[STATS64_TX_ERRORS..]).unwrap_or(0);
            let rx_dropped = read_u64(&s[STATS64_RX_DROPPED..]).unwrap_or(0);
            let tx_dropped = read_u64(&s[STATS64_TX_DROPPED..]).unwrap_or(0);
            (
                rx_bytes, tx_bytes, rx_packets, tx_packets, rx_errors, tx_errors, rx_dropped,
                tx_dropped,
            )
        });

    Some(LinkStats {
        name,
        up,
        rx_bytes,
        tx_bytes,
        rx_packets,
        tx_packets,
        rx_errors,
        tx_errors,
        rx_dropped,
        tx_dropped,
    })
}

/// Emit `MetricSample`s for one link's stats.
fn emit_link_metrics(stats: &LinkStats, out: &mut Vec<MetricSample>) {
    let device = stats.name.as_str();
    let mut labels = BTreeMap::new();
    labels.insert("device".to_owned(), device.to_owned());

    macro_rules! counter {
        ($name:literal, $help:literal, $val:expr) => {
            out.push(MetricSample::counter($name, $help, labels.clone(), $val));
        };
    }

    counter!(
        "nft_link_receive_bytes_total",
        "Total bytes received on the interface.",
        stats.rx_bytes
    );
    counter!(
        "nft_link_transmit_bytes_total",
        "Total bytes transmitted on the interface.",
        stats.tx_bytes
    );
    counter!(
        "nft_link_receive_packets_total",
        "Total packets received on the interface.",
        stats.rx_packets
    );
    counter!(
        "nft_link_transmit_packets_total",
        "Total packets transmitted on the interface.",
        stats.tx_packets
    );
    counter!(
        "nft_link_receive_errors_total",
        "Total receive errors on the interface.",
        stats.rx_errors
    );
    counter!(
        "nft_link_transmit_errors_total",
        "Total transmit errors on the interface.",
        stats.tx_errors
    );
    counter!(
        "nft_link_receive_drops_total",
        "Total receive drops on the interface.",
        stats.rx_dropped
    );
    counter!(
        "nft_link_transmit_drops_total",
        "Total transmit drops on the interface.",
        stats.tx_dropped
    );

    // nft_link_up gauge: 1.0 if up, 0.0 otherwise.
    out.push(MetricSample::gauge(
        "nft_link_up",
        "1 if the interface is operationally up, 0 otherwise.",
        labels,
        if stats.up { 1.0_f64 } else { 0.0_f64 },
    ));
}

// ---------------------------------------------------------------------------
// Address count (RTM_GETADDR)
// ---------------------------------------------------------------------------

/// Count addresses by `ifa_family` (inet / inet6).
/// Returns a map from family label to count.
fn count_addresses(frames: &[Vec<u8>]) -> BTreeMap<String, u64> {
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    for frame in frames {
        // ifaddrmsg: ifa_family at offset 0.
        if frame.is_empty() {
            continue;
        }
        let family = family_label(frame[0]);
        *counts.entry(family.to_owned()).or_insert(0) += 1;
    }
    counts
}

// ---------------------------------------------------------------------------
// Route count (RTM_GETROUTE)
// ---------------------------------------------------------------------------

/// Key for aggregating routes: (family_label, table_str).
#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct RouteKey {
    family: String,
    table: String,
}

/// Count routes by (family, table). Parse `rtmsg` (12 B) + RTA_TABLE attr.
fn count_routes(frames: &[Vec<u8>]) -> BTreeMap<RouteKey, u64> {
    let mut counts: BTreeMap<RouteKey, u64> = BTreeMap::new();
    for frame in frames {
        // rtmsg is 12 bytes.
        if frame.len() < 12 {
            continue;
        }
        let rtm_family = frame[0];
        let rtm_table = frame[4]; // u8 table ID (0-255)
        let family = family_label(rtm_family).to_owned();

        // Check for RTA_TABLE (type=15) u32 attribute which overrides rtm_table.
        let attr_buf = &frame[12..];
        let mut table_id: u32 = u32::from(rtm_table);
        for attr in parse_attrs(attr_buf) {
            if attr.ty == RTA_TABLE {
                if let Some(v) = read_u32(attr.payload) {
                    table_id = v;
                }
                break;
            }
        }

        let key = RouteKey {
            family,
            table: table_id.to_string(),
        };
        *counts.entry(key).or_insert(0) += 1;
    }
    counts
}

// ---------------------------------------------------------------------------
// Neighbour count (RTM_GETNEIGH)
// ---------------------------------------------------------------------------

/// Key for aggregating neighbours: (family_label, state_label).
#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct NeighKey {
    family: String,
    state: String,
}

/// Count neighbours by (family, state). Parse `ndmsg` (12 B).
/// Skip AF_BRIDGE entries.
fn count_neighbours(frames: &[Vec<u8>]) -> BTreeMap<NeighKey, u64> {
    let mut counts: BTreeMap<NeighKey, u64> = BTreeMap::new();
    for frame in frames {
        // ndmsg is 12 bytes.
        if frame.len() < 12 {
            continue;
        }
        let ndm_family = frame[0];
        if ndm_family == AF_BRIDGE {
            continue; // skip bridge entries (ADR-0005)
        }
        // ndm_state at offset 8: u16 LE (one bit set at a time).
        let ndm_state = u16::from_ne_bytes([frame[8], frame[9]]);
        // NDA_DST and NDA_LLADDR are deliberately not parsed (ADR-0005 cardinality guard).

        let key = NeighKey {
            family: family_label(ndm_family).to_owned(),
            state: nud_state_label(ndm_state).to_owned(),
        };
        *counts.entry(key).or_insert(0) += 1;
    }
    counts
}

// ---------------------------------------------------------------------------
// RtCollector
// ---------------------------------------------------------------------------

/// Adapter implementing [`NetlinkRtPort`] and [`Collector`] for the
/// `NETLINK_ROUTE` family (rtnetlink).
pub struct RtCollector;

impl NetlinkRtPort for RtCollector {
    async fn dump_links(&self) -> Result<Vec<LinkReadModel>, DomainError> {
        // Not needed for direct metric collection path; stub returns empty.
        Ok(Vec::new())
    }

    async fn dump_addresses(&self) -> Result<Vec<AddressReadModel>, DomainError> {
        Ok(Vec::new())
    }

    async fn dump_routes(&self) -> Result<Vec<RouteReadModel>, DomainError> {
        Ok(Vec::new())
    }

    async fn dump_neighbors(&self) -> Result<Vec<NeighborReadModel>, DomainError> {
        Ok(Vec::new())
    }
}

impl Collector for RtCollector {
    fn name(&self) -> &str {
        "rtnetlink"
    }

    fn collect(&self) -> BoxFuture<'_, Result<Vec<MetricSample>, CollectError>> {
        Box::pin(async move {
            let mut sock =
                NetlinkSocket::open(NETLINK_ROUTE).map_err(|e| CollectError::Unavailable {
                    reason: e.to_string(),
                })?;

            let mut samples = Vec::new();

            // --- RTM_GETLINK: link stats -------------------------------------
            let link_frames = dump_with_retries(&mut sock, RTM_GETLINK, &ifinfomsg_payload())
                .await
                .map_err(nl_err_to_collect)?;

            for frame in &link_frames {
                if let Some(stats) = parse_link_frame(frame) {
                    emit_link_metrics(&stats, &mut samples);
                }
            }

            // --- RTM_GETADDR: address counts ---------------------------------
            let addr_frames = dump_with_retries(&mut sock, RTM_GETADDR, &ifaddrmsg_payload())
                .await
                .map_err(nl_err_to_collect)?;

            for (family, count) in count_addresses(&addr_frames) {
                let mut labels = BTreeMap::new();
                labels.insert("family".to_owned(), family);
                samples.push(MetricSample::gauge(
                    "nft_address_count",
                    "Number of IP addresses assigned by address family.",
                    labels,
                    count as f64,
                ));
            }

            // --- RTM_GETROUTE: route counts -----------------------------------
            let route_frames = dump_with_retries(&mut sock, RTM_GETROUTE, &rtmsg_payload())
                .await
                .map_err(nl_err_to_collect)?;

            for (key, count) in count_routes(&route_frames) {
                let mut labels = BTreeMap::new();
                labels.insert("family".to_owned(), key.family);
                labels.insert("table".to_owned(), key.table);
                samples.push(MetricSample::gauge(
                    "nft_route_count",
                    "Number of routes by address family and routing table.",
                    labels,
                    count as f64,
                ));
            }

            // --- RTM_GETNEIGH: neighbour counts -------------------------------
            let neigh_frames = dump_with_retries(&mut sock, RTM_GETNEIGH, &ndmsg_payload())
                .await
                .map_err(nl_err_to_collect)?;

            for (key, count) in count_neighbours(&neigh_frames) {
                let mut labels = BTreeMap::new();
                labels.insert("family".to_owned(), key.family);
                labels.insert("state".to_owned(), key.state);
                samples.push(MetricSample::gauge(
                    "nft_neighbor_count",
                    "Number of neighbour (ARP/NDP) entries by family and state.",
                    labels,
                    count as f64,
                ));
            }

            Ok(samples)
        })
    }

    fn probe_available(&self) -> BoxFuture<'_, bool> {
        Box::pin(async move {
            // NETLINK_ROUTE is always available; probe by attempting to open.
            NetlinkSocket::open(NETLINK_ROUTE).is_ok()
        })
    }
}
