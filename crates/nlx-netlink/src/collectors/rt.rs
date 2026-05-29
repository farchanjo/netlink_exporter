//! `NETLINK_ROUTE` rtnetlink collector.
//!
//! Netlink family: `NETLINK_ROUTE` (0).
//! Messages used: `RTM_GETLINK`, `RTM_GETADDR`, `RTM_GETROUTE`, `RTM_GETNEIGH`.
//! ADR refs: ADR-0011 (direct wire), ADR-0014 (tokio `AsyncFd` confinement).
//!
//! ## Wire layout references (netlink-protocol.md §4)
//!
//! - `ifinfomsg` 16 B: family(1) pad(1) type(2) index(4) flags(4) change(4)
//! - `ifaddrmsg` 8 B: family(1) prefixlen(1) flags(1) scope(1) index(4)
//! - `rtmsg` 12 B: family(1) `dst_len(1)` `src_len(1)` tos(1) table(1) proto(1)
//!   scope(1) type(1) flags(4)
//! - `ndmsg` 12 B: family(1) pad1(1) pad2(2) ifindex(4) state(2) flags(1)
//!   type(1)
//! - `rtnl_link_stats64` at `IFLA_STATS64`: 192-200 B of u64 LE fields

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

/// Build a zeroed `ifinfomsg` (16 bytes), `ifi_family=AF_UNSPEC`, for a full
/// `RTM_GETLINK` dump. A correctly-sized fixed header is mandatory when the
/// kernel has `NETLINK_GET_STRICT_CHK` enabled — a short `rtgenmsg` yields
/// EINVAL and an empty dump.
fn ifinfomsg_payload() -> [u8; 16] {
    [0u8; 16]
}

/// Build a zeroed `ifaddrmsg` (8 bytes) for a full `RTM_GETADDR` dump.
fn ifaddrmsg_payload() -> [u8; 8] {
    [0u8; 8]
}

/// Build a zeroed `rtmsg` (12 bytes) for a DUMP of all routes.
fn rtmsg_payload() -> [u8; 12] {
    [0u8; 12]
}

/// Build a zeroed `ndmsg` (12 bytes) for a full `RTM_GETNEIGH` dump.
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

/// Map a routing table ID to a bounded label string.
///
/// Well-known kernel table IDs (`linux/rtnetlink.h` `enum rt_class_t`):
/// - 0   = `RT_TABLE_UNSPEC`
/// - 253 = `RT_TABLE_DEFAULT`
/// - 254 = `RT_TABLE_MAIN`
/// - 255 = `RT_TABLE_LOCAL`
///
/// All other IDs are bucketed as `"other"` to prevent unbounded label
/// cardinality on systems with many policy-routing tables (MC-002).
fn table_label(id: u32) -> &'static str {
    match id {
        0 => "unspec",
        253 => "default",
        254 => "main",
        255 => "local",
        _ => "other",
    }
}

/// Key for aggregating routes: (`family_label`, `table_label`).
#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct RouteKey {
    family: String,
    table: String,
}

/// Count routes by (family, table). Parse `rtmsg` (12 B) + `RTA_TABLE` attr.
///
/// The table label is bounded to the four well-known names (`unspec`,
/// `default`, `main`, `local`) plus `"other"` for all user-defined tables,
/// preventing unbounded Prometheus label cardinality (MC-002).
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
            table: table_label(table_id).to_owned(),
        };
        *counts.entry(key).or_insert(0) += 1;
    }
    counts
}

// ---------------------------------------------------------------------------
// Neighbour count (RTM_GETNEIGH)
// ---------------------------------------------------------------------------

/// Key for aggregating neighbours: (`family_label`, `state_label`).
#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct NeighKey {
    family: String,
    state: String,
}

/// Count neighbours by (family, state). Parse `ndmsg` (12 B).
/// Skip `AF_BRIDGE` entries.
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
    fn name(&self) -> &'static str {
        "rtnetlink"
    }

    #[allow(
        clippy::cast_precision_loss,
        reason = "metric gauge values are f64; precision loss on large u64 counters is inherent to Prometheus exposition"
    )]
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

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::cast_possible_truncation,
        clippy::too_many_arguments,
        reason = "test"
    )]

    use super::*;
    use crate::wire::{NLA_HDRLEN, align4};

    // -----------------------------------------------------------------------
    // Wire-building helpers
    // -----------------------------------------------------------------------

    /// Build a flat nlattr TLV: `u16 nla_len LE | u16 nla_type LE | payload | padding`.
    fn make_nla(ty: u16, payload: &[u8]) -> Vec<u8> {
        let nla_len = NLA_HDRLEN + payload.len();
        let padded = align4(nla_len);
        let mut out = Vec::with_capacity(padded);
        out.extend_from_slice(&(nla_len as u16).to_ne_bytes());
        out.extend_from_slice(&ty.to_ne_bytes());
        out.extend_from_slice(payload);
        out.resize(padded, 0u8);
        out
    }

    /// Build a minimal `ifinfomsg` (16 B) with `ifi_flags` at offset 8 (u32 LE).
    ///
    /// Wire layout (`linux/if_link.h` `struct ifinfomsg`):
    ///   family(1) pad(1) type(2) index(4) flags(4) change(4)
    fn make_ifinfomsg(ifi_flags: u32) -> Vec<u8> {
        let mut hdr = vec![0u8; 16];
        // ifi_flags: offset 8, u32 LE
        hdr[8..12].copy_from_slice(&ifi_flags.to_ne_bytes());
        hdr
    }

    /// Build a `rtnl_link_stats64` payload (at least 64 B covering through
    /// `tx_dropped` at offset 56).
    ///
    /// Field offsets (all u64 LE, `linux/if_link.h` `struct rtnl_link_stats64`):
    ///   `rx_packets@0`, `tx_packets@8`, `rx_bytes@16`, `tx_bytes@24`,
    ///   `rx_errors@32`, `tx_errors@40`, `rx_dropped@48`, `tx_dropped@56`
    fn make_stats64(
        rx_packets: u64,
        tx_packets: u64,
        rx_bytes: u64,
        tx_bytes: u64,
        rx_errors: u64,
        tx_errors: u64,
        rx_dropped: u64,
        tx_dropped: u64,
    ) -> Vec<u8> {
        let mut s = vec![0u8; 64];
        s[0..8].copy_from_slice(&rx_packets.to_ne_bytes());
        s[8..16].copy_from_slice(&tx_packets.to_ne_bytes());
        s[16..24].copy_from_slice(&rx_bytes.to_ne_bytes());
        s[24..32].copy_from_slice(&tx_bytes.to_ne_bytes());
        s[32..40].copy_from_slice(&rx_errors.to_ne_bytes());
        s[40..48].copy_from_slice(&tx_errors.to_ne_bytes());
        s[48..56].copy_from_slice(&rx_dropped.to_ne_bytes());
        s[56..64].copy_from_slice(&tx_dropped.to_ne_bytes());
        s
    }

    /// Build a minimal `rtmsg` (12 B).
    ///
    /// Wire layout (linux/rtnetlink.h `struct rtmsg`):
    ///   family(1) `dst_len(1)` `src_len(1)` tos(1) table(1) protocol(1) scope(1) type(1) flags(4)
    fn make_rtmsg(family: u8, table: u8) -> Vec<u8> {
        let mut hdr = vec![0u8; 12];
        hdr[0] = family;
        hdr[4] = table; // rtm_table: u8 at offset 4
        hdr
    }

    // -----------------------------------------------------------------------
    // TC-002: parse_link_frame
    // -----------------------------------------------------------------------

    /// Happy path: `ifinfomsg` (`IFF_UP|IFF_RUNNING`, operstate=6) + `IFLA_IFNAME`
    /// + `IFLA_STATS64`.  Verifies all eight counter fields are decoded correctly.
    #[test]
    fn parse_link_frame_happy() {
        // IFF_UP = 0x1, IFF_RUNNING = 0x40
        let ifi_flags: u32 = IFF_UP | IFF_RUNNING;
        let mut frame = make_ifinfomsg(ifi_flags);

        // IFLA_IFNAME = 3, NUL-terminated
        frame.extend_from_slice(&make_nla(IFLA_IFNAME, b"eth0\0"));
        // IFLA_OPERSTATE = 16, operstate = 6 (IF_OPER_UP)
        frame.extend_from_slice(&make_nla(IFLA_OPERSTATE, &[6u8]));
        // IFLA_STATS64 = 23
        let stats = make_stats64(100, 200, 1000, 2000, 3, 4, 5, 6);
        frame.extend_from_slice(&make_nla(IFLA_STATS64, &stats));

        let link = parse_link_frame(&frame).unwrap();
        assert_eq!(link.name, "eth0");
        assert!(link.up, "interface should be up");
        assert_eq!(link.rx_packets, 100);
        assert_eq!(link.tx_packets, 200);
        assert_eq!(link.rx_bytes, 1000);
        assert_eq!(link.tx_bytes, 2000);
        assert_eq!(link.rx_errors, 3);
        assert_eq!(link.tx_errors, 4);
        assert_eq!(link.rx_dropped, 5);
        assert_eq!(link.tx_dropped, 6);
    }

    /// Frame too short (< 16 B) must return `None`.
    #[test]
    fn parse_link_frame_too_short_returns_none() {
        let frame = vec![0u8; 10];
        assert!(parse_link_frame(&frame).is_none());
    }

    /// Frame with `IFLA_IFNAME` absent must return `None` (name is required).
    #[test]
    fn parse_link_frame_no_ifname_returns_none() {
        let ifi_flags: u32 = IFF_UP | IFF_RUNNING;
        let mut frame = make_ifinfomsg(ifi_flags);
        // Append only IFLA_OPERSTATE, no IFLA_IFNAME
        frame.extend_from_slice(&make_nla(IFLA_OPERSTATE, &[6u8]));
        assert!(parse_link_frame(&frame).is_none());
    }

    /// Frame with no `IFLA_STATS64` must still parse (stats default to zero).
    #[test]
    fn parse_link_frame_no_stats64_returns_zero_counters() {
        let ifi_flags: u32 = IFF_UP | IFF_RUNNING;
        let mut frame = make_ifinfomsg(ifi_flags);
        frame.extend_from_slice(&make_nla(IFLA_IFNAME, b"lo\0"));
        let link = parse_link_frame(&frame).unwrap();
        assert_eq!(link.name, "lo");
        assert_eq!(link.rx_bytes, 0);
        assert_eq!(link.tx_bytes, 0);
    }

    /// Interface is reported down when `IFF_UP` is absent.
    #[test]
    fn parse_link_frame_down_interface() {
        // No IFF_UP bit
        let ifi_flags: u32 = 0;
        let mut frame = make_ifinfomsg(ifi_flags);
        frame.extend_from_slice(&make_nla(IFLA_IFNAME, b"eth1\0"));
        let link = parse_link_frame(&frame).unwrap();
        assert!(!link.up, "interface without IFF_UP must be down");
    }

    // -----------------------------------------------------------------------
    // TC-002: count_routes
    // -----------------------------------------------------------------------

    /// Route with `RTA_TABLE` NLA overriding `rtm_table` byte.
    /// Table 254 (main) with inet family.
    #[test]
    fn count_routes_with_rta_table_nla_main() {
        // rtmsg: family=2 (AF_INET), rtm_table=0 (will be overridden by NLA)
        let mut frame = make_rtmsg(2, 0);
        // RTA_TABLE = 15, payload = 254u32 LE (RT_TABLE_MAIN)
        frame.extend_from_slice(&make_nla(RTA_TABLE, &254u32.to_ne_bytes()));

        let counts = count_routes(&[frame]);
        let key = counts.keys().next().unwrap();
        assert_eq!(key.family, "inet");
        assert_eq!(key.table, "main");
        assert_eq!(counts[key], 1);
    }

    /// Route without `RTA_TABLE` NLA — uses `rtm_table` byte directly.
    /// Table byte 255 (local).
    #[test]
    fn count_routes_without_rta_table_nla_local() {
        // rtmsg: family=10 (AF_INET6), rtm_table=255 (RT_TABLE_LOCAL), no NLA
        let frame = make_rtmsg(10, 255);

        let counts = count_routes(&[frame]);
        let key = counts.keys().next().unwrap();
        assert_eq!(key.family, "inet6");
        assert_eq!(key.table, "local");
        assert_eq!(counts[key], 1);
    }

    /// User-defined table ID (e.g. 100) must be bucketed as `"other"`.
    #[test]
    fn count_routes_user_defined_table_bucketed_as_other() {
        // rtmsg: family=2, rtm_table=100
        let frame = make_rtmsg(2, 100);
        let counts = count_routes(&[frame]);
        let key = counts.keys().next().unwrap();
        assert_eq!(
            key.table, "other",
            "user-defined table 100 must map to 'other'"
        );
    }

    /// Large table ID via `RTA_TABLE` NLA (e.g. 1000) must also be `"other"`.
    #[test]
    fn count_routes_large_rta_table_bucketed_as_other() {
        let mut frame = make_rtmsg(2, 0);
        frame.extend_from_slice(&make_nla(RTA_TABLE, &1000u32.to_ne_bytes()));
        let counts = count_routes(&[frame]);
        let key = counts.keys().next().unwrap();
        assert_eq!(key.table, "other");
    }

    /// Frames shorter than 12 B are skipped without panic.
    #[test]
    fn count_routes_short_frame_skipped() {
        let frame: Vec<u8> = vec![0u8; 5];
        let counts = count_routes(&[frame]);
        assert!(counts.is_empty());
    }

    // -----------------------------------------------------------------------
    // TC-002: table_label
    // -----------------------------------------------------------------------

    #[test]
    fn table_label_well_known_ids() {
        assert_eq!(table_label(0), "unspec");
        assert_eq!(table_label(253), "default");
        assert_eq!(table_label(254), "main");
        assert_eq!(table_label(255), "local");
    }

    #[test]
    fn table_label_unknown_ids_are_other() {
        assert_eq!(table_label(1), "other");
        assert_eq!(table_label(100), "other");
        assert_eq!(table_label(252), "other");
        assert_eq!(table_label(256), "other");
        assert_eq!(table_label(u32::MAX), "other");
    }

    // -----------------------------------------------------------------------
    // TC-002: nud_state_label
    // -----------------------------------------------------------------------

    #[test]
    fn nud_state_label_individual_bits() {
        assert_eq!(nud_state_label(NUD_PERMANENT), "permanent");
        assert_eq!(nud_state_label(NUD_REACHABLE), "reachable");
        assert_eq!(nud_state_label(NUD_STALE), "stale");
        assert_eq!(nud_state_label(NUD_DELAY), "delay");
        assert_eq!(nud_state_label(NUD_PROBE), "probe");
        assert_eq!(nud_state_label(NUD_FAILED), "failed");
        assert_eq!(nud_state_label(NUD_NOARP), "noarp");
        assert_eq!(nud_state_label(NUD_INCOMPLETE), "incomplete");
    }

    #[test]
    fn nud_state_label_zero_is_unknown() {
        assert_eq!(nud_state_label(0), "unknown");
    }

    /// When multiple bits are set, the highest-priority label wins.
    /// `NUD_PERMANENT` has the highest priority in the chain.
    #[test]
    fn nud_state_label_permanent_wins_over_reachable() {
        let state = NUD_PERMANENT | NUD_REACHABLE;
        assert_eq!(nud_state_label(state), "permanent");
    }

    // -----------------------------------------------------------------------
    // TC-002: decode_ifname
    // -----------------------------------------------------------------------

    #[test]
    fn decode_ifname_with_trailing_nul() {
        let payload = b"eth0\0";
        assert_eq!(decode_ifname(payload), Some("eth0".to_owned()));
    }

    #[test]
    fn decode_ifname_without_trailing_nul() {
        let payload = b"eth0";
        assert_eq!(decode_ifname(payload), Some("eth0".to_owned()));
    }

    #[test]
    fn decode_ifname_empty_payload() {
        assert_eq!(decode_ifname(b""), Some(String::new()));
    }

    #[test]
    fn decode_ifname_only_nul() {
        // Payload is a single NUL byte — should yield empty string.
        assert_eq!(decode_ifname(b"\0"), Some(String::new()));
    }

    #[test]
    fn decode_ifname_invalid_utf8_returns_none() {
        // 0xFF is not valid UTF-8.
        let payload: &[u8] = &[0xFF, 0xFE];
        assert_eq!(decode_ifname(payload), None);
    }
}
