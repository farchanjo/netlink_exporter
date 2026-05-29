//! Traffic-control collector.
//!
//! Netlink family: `NETLINK_ROUTE` (0).
//! Messages used: `RTM_GETQDISC` (type 38), `RTM_GETTCLASS`, `RTM_GETTFILTER`.
//! ADR refs: ADR-0011 (`TCA_STATS2` `NLA_F_NESTED` bit-15 masking), ADR-0014.
//!
//! ## Wire layout (netlink-protocol.md §7)
//!
//! `tcmsg` 20 B: family(1) pad1(1) pad2(2) ifindex(4) handle(4) parent(4)
//! info(4).
//!
//! `TCA_KIND` (type=1): NUL-terminated qdisc name string.
//! `TCA_STATS2` (type=7): nested nlattr container with:
//!   - `TCA_STATS_BASIC` (1): `gnet_stats_basic` 12 B — u64 bytes + u32 packets
//!   - `TCA_STATS_QUEUE` (3): `gnet_stats_queue` 20 B — 5× u32 (qlen, backlog,
//!     drops, requeues, overlimits)
//!
//! Interface name is resolved from `tcm_ifindex` via a prior `RTM_GETLINK` dump.

use std::collections::BTreeMap;

use nlx_domain::{error::DomainError, metric::MetricSample, model::tc::TcReadModel};
use nlx_ports::{
    collector::{BoxFuture, Collector},
    driven::NetlinkTcPort,
    error::CollectError,
};
use tracing::{debug, warn};

use crate::transport::{MAX_DUMP_RESTARTS, NetlinkError, NetlinkSocket};
use crate::wire::{nested_attrs, parse_attrs, read_u64};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const NETLINK_ROUTE: i32 = 0;

/// `RTM_GETQDISC` — dump all qdiscs.
const RTM_GETQDISC: u16 = 38;

/// `RTM_GETLINK` — used to build the ifindex → name map.
const RTM_GETLINK: u16 = 18;

// TCA_* attribute types
const TCA_KIND: u16 = 1;
const TCA_STATS2: u16 = 7;

// TCA_STATS2 nested attribute types
const TCA_STATS_BASIC: u16 = 1;
const TCA_STATS_QUEUE: u16 = 3;

// IFLA_IFNAME attribute type
const IFLA_IFNAME: u16 = 3;

// ---------------------------------------------------------------------------
// Payload builders
// ---------------------------------------------------------------------------

/// `ifinfomsg` payload (16 bytes, `ifi_family=AF_UNSPEC`) for the `RTM_GETLINK`
/// dump used to build the ifindex→name map. A short rtgenmsg is rejected under
/// `NETLINK_GET_STRICT_CHK` (empty dump → every device resolves to "unknown").
fn ifinfomsg_payload() -> [u8; 16] {
    [0u8; 16]
}

/// `tcmsg` payload for `RTM_GETQDISC` dump: 20 bytes all-zero except family=0.
fn tcmsg_payload() -> [u8; 20] {
    [0u8; 20]
}

// ---------------------------------------------------------------------------
// Retry helper
// ---------------------------------------------------------------------------

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

fn nl_err_to_collect(e: NetlinkError) -> CollectError {
    match e {
        NetlinkError::DumpIntr => CollectError::DumpIntr,
        NetlinkError::RecvBufOverflow => CollectError::RecvBufOverflow,
        NetlinkError::Parse(s) => CollectError::Parse(s),
        other => CollectError::Io(other.to_string()),
    }
}

// ---------------------------------------------------------------------------
// ifindex → name map (built from RTM_GETLINK dump)
// ---------------------------------------------------------------------------

/// Build a map from `ifindex` (i32) to interface name using `RTM_GETLINK`.
///
/// # Errors
///
/// Returns [`NetlinkError`] if the `RTM_GETLINK` dump fails or is interrupted
/// beyond the restart limit.
async fn build_ifindex_map(
    sock: &mut NetlinkSocket,
) -> Result<BTreeMap<i32, String>, NetlinkError> {
    let frames = dump_with_retries(sock, RTM_GETLINK, &ifinfomsg_payload()).await?;
    let mut map = BTreeMap::new();
    for frame in &frames {
        // ifinfomsg: 16 bytes; ifi_index at offset 4 (i32 LE).
        if frame.len() < 16 {
            continue;
        }
        let ifindex = i32::from_ne_bytes([frame[4], frame[5], frame[6], frame[7]]);
        let attr_buf = &frame[16..];
        for attr in parse_attrs(attr_buf) {
            if attr.ty == IFLA_IFNAME {
                if let Some(name) = decode_ifname(attr.payload) {
                    map.insert(ifindex, name);
                }
                break;
            }
        }
    }
    Ok(map)
}

fn decode_ifname(payload: &[u8]) -> Option<String> {
    let trimmed = payload
        .iter()
        .position(|&b| b == 0)
        .map_or(payload, |pos| &payload[..pos]);
    std::str::from_utf8(trimmed).ok().map(str::to_owned)
}

// ---------------------------------------------------------------------------
// TCA_STATS2 parsing
// ---------------------------------------------------------------------------

struct QdiscStats {
    /// Total bytes through qdisc (from `gnet_stats_basic`).
    bytes: u64,
    /// Total packets through qdisc (from `gnet_stats_basic`).
    packets: u64,
    /// Drops (from `gnet_stats_queue`).
    drops: u32,
    /// Overlimits (from `gnet_stats_queue`).
    overlimits: u32,
    /// Backlog bytes (from `gnet_stats_queue`).
    backlog: u32,
}

/// Parse `TCA_STATS2` payload (nested attrs: `TCA_STATS_BASIC` + `TCA_STATS_QUEUE`).
fn parse_tca_stats2(payload: &[u8]) -> Option<QdiscStats> {
    let mut bytes = 0u64;
    let mut packets = 0u64;
    let mut drops = 0u32;
    let mut overlimits = 0u32;
    let mut backlog = 0u32;
    let mut found_basic = false;

    for attr in nested_attrs(payload) {
        // Mask bit 15 (NLA_F_NESTED may be set on inner types per §7.3).
        let eff_ty = attr.ty & 0x7FFF;
        match eff_ty {
            TCA_STATS_BASIC => {
                // gnet_stats_basic: u64 bytes @ 0, u32 packets @ 8 (12 B total).
                if attr.payload.len() >= 12 {
                    bytes = read_u64(attr.payload).unwrap_or(0);
                    packets = u64::from(u32::from_ne_bytes([
                        attr.payload[8],
                        attr.payload[9],
                        attr.payload[10],
                        attr.payload[11],
                    ]));
                    found_basic = true;
                }
            }
            TCA_STATS_QUEUE => {
                // gnet_stats_queue: u32 qlen@0, backlog@4, drops@8, requeues@12, overlimits@16
                if attr.payload.len() >= 20 {
                    backlog = u32::from_ne_bytes([
                        attr.payload[4],
                        attr.payload[5],
                        attr.payload[6],
                        attr.payload[7],
                    ]);
                    drops = u32::from_ne_bytes([
                        attr.payload[8],
                        attr.payload[9],
                        attr.payload[10],
                        attr.payload[11],
                    ]);
                    overlimits = u32::from_ne_bytes([
                        attr.payload[16],
                        attr.payload[17],
                        attr.payload[18],
                        attr.payload[19],
                    ]);
                }
            }
            _ => {}
        }
    }

    if found_basic {
        Some(QdiscStats {
            bytes,
            packets,
            drops,
            overlimits,
            backlog,
        })
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Frame parsing
// ---------------------------------------------------------------------------

struct QdiscEntry {
    ifindex: i32,
    kind: String,
    stats: Option<QdiscStats>,
}

/// Parse a single `RTM_NEWQDISC` frame into a `QdiscEntry`.
///
/// Frame layout: `tcmsg` (20 B) + rtattrs.
fn parse_qdisc_frame(payload: &[u8]) -> Option<QdiscEntry> {
    if payload.len() < 20 {
        return None;
    }
    // tcm_ifindex at offset 4 (i32 LE).
    let ifindex = i32::from_ne_bytes([payload[4], payload[5], payload[6], payload[7]]);

    let attr_buf = &payload[20..];
    let mut kind: Option<String> = None;
    let mut stats: Option<QdiscStats> = None;

    for attr in parse_attrs(attr_buf) {
        match attr.ty {
            TCA_KIND => {
                kind = decode_ifname(attr.payload); // same NUL-strip logic
            }
            TCA_STATS2 => {
                stats = parse_tca_stats2(attr.payload);
            }
            _ => {}
        }
    }

    let kind = kind.unwrap_or_else(|| "unknown".to_owned());
    Some(QdiscEntry {
        ifindex,
        kind,
        stats,
    })
}

// ---------------------------------------------------------------------------
// Metric emission
// ---------------------------------------------------------------------------

fn emit_qdisc_metrics(entry: &QdiscEntry, iface_name: &str, out: &mut Vec<MetricSample>) {
    let Some(ref stats) = entry.stats else {
        // noqueue and other qdiscs without TCA_STATS2 → no counter metrics (§7.4).
        return;
    };

    let mut labels = BTreeMap::new();
    labels.insert("device".to_owned(), iface_name.to_owned());
    labels.insert("kind".to_owned(), entry.kind.clone());

    out.push(MetricSample::counter(
        "nft_tc_qdisc_bytes_total",
        "Total bytes processed by the qdisc.",
        labels.clone(),
        stats.bytes,
    ));
    out.push(MetricSample::counter(
        "nft_tc_qdisc_packets_total",
        "Total packets processed by the qdisc.",
        labels.clone(),
        stats.packets,
    ));
    out.push(MetricSample::counter(
        "nft_tc_qdisc_drops_total",
        "Total packets dropped by the qdisc.",
        labels.clone(),
        u64::from(stats.drops),
    ));
    out.push(MetricSample::counter(
        "nft_tc_qdisc_overlimits_total",
        "Total overlimit events on the qdisc.",
        labels.clone(),
        u64::from(stats.overlimits),
    ));
    out.push(MetricSample::gauge(
        "nft_tc_qdisc_backlog_bytes",
        "Current backlog size of the qdisc in bytes.",
        labels,
        f64::from(stats.backlog),
    ));
}

// ---------------------------------------------------------------------------
// TcCollector
// ---------------------------------------------------------------------------

/// Adapter implementing [`NetlinkTcPort`] and [`Collector`] for traffic
/// control statistics.
pub struct TcCollector;

impl NetlinkTcPort for TcCollector {
    async fn dump_tc(&self) -> Result<Vec<TcReadModel>, DomainError> {
        // Not needed for the direct metric-collection path.
        Ok(Vec::new())
    }
}

impl Collector for TcCollector {
    fn name(&self) -> &'static str {
        "traffic_control"
    }

    fn collect(&self) -> BoxFuture<'_, Result<Vec<MetricSample>, CollectError>> {
        Box::pin(async move {
            let mut sock =
                NetlinkSocket::open(NETLINK_ROUTE).map_err(|e| CollectError::Unavailable {
                    reason: e.to_string(),
                })?;

            // Build ifindex → name map from a prior RTM_GETLINK dump.
            let ifindex_map = build_ifindex_map(&mut sock)
                .await
                .map_err(nl_err_to_collect)?;

            // Dump all qdiscs via RTM_GETQDISC.
            let qdisc_frames = dump_with_retries(&mut sock, RTM_GETQDISC, &tcmsg_payload())
                .await
                .map_err(nl_err_to_collect)?;

            let mut samples = Vec::new();

            for frame in &qdisc_frames {
                let Some(entry) = parse_qdisc_frame(frame) else {
                    continue;
                };
                let iface_name = ifindex_map
                    .get(&entry.ifindex)
                    .map_or("unknown", String::as_str);
                emit_qdisc_metrics(&entry, iface_name, &mut samples);
            }

            Ok(samples)
        })
    }

    fn probe_available(&self) -> BoxFuture<'_, bool> {
        // NETLINK_ROUTE / RTM_GETQDISC is always available on Linux.
        Box::pin(async move { true })
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

    /// Build a `gnet_stats_basic` payload (12 B).
    ///
    /// Wire layout (`linux/gen_stats.h` `struct gnet_stats_basic_sync`):
    ///   bytes(8 u64 LE) + packets(4 u32 LE)
    fn make_gnet_stats_basic(bytes: u64, packets: u32) -> Vec<u8> {
        let mut s = vec![0u8; 12];
        s[0..8].copy_from_slice(&bytes.to_ne_bytes());
        s[8..12].copy_from_slice(&packets.to_ne_bytes());
        s
    }

    /// Build a `gnet_stats_queue` payload (20 B).
    ///
    /// Wire layout (`linux/gen_stats.h` `struct gnet_stats_queue`):
    ///   qlen(4) backlog(4) drops(4) requeues(4) overlimits(4)  — all u32 LE
    fn make_gnet_stats_queue(
        qlen: u32,
        backlog: u32,
        drops: u32,
        requeues: u32,
        overlimits: u32,
    ) -> Vec<u8> {
        let mut s = vec![0u8; 20];
        s[0..4].copy_from_slice(&qlen.to_ne_bytes());
        s[4..8].copy_from_slice(&backlog.to_ne_bytes());
        s[8..12].copy_from_slice(&drops.to_ne_bytes());
        s[12..16].copy_from_slice(&requeues.to_ne_bytes());
        s[16..20].copy_from_slice(&overlimits.to_ne_bytes());
        s
    }

    /// Build a `tcmsg` (20 B) with `tcm_ifindex` at offset 4 (i32 LE).
    ///
    /// Wire layout (`linux/pkt_sched.h` `struct tcmsg`):
    ///   family(1) pad1(1) pad2(2) ifindex(4) handle(4) parent(4) info(4)
    fn make_tcmsg(ifindex: i32) -> Vec<u8> {
        let mut hdr = vec![0u8; 20];
        hdr[4..8].copy_from_slice(&ifindex.to_ne_bytes());
        hdr
    }

    // -----------------------------------------------------------------------
    // TC-003: parse_tca_stats2
    // -----------------------------------------------------------------------

    /// Happy path: `TCA_STATS_BASIC` + `TCA_STATS_QUEUE` both present.
    /// Verifies `bytes`, `packets`, `drops`, `overlimits`, and `backlog`.
    #[test]
    fn parse_tca_stats2_basic_and_queue_present() {
        // Build nested TCA_STATS2 payload: TCA_STATS_BASIC(1) + TCA_STATS_QUEUE(3)
        let basic = make_gnet_stats_basic(9_000_000, 1_000);
        let queue = make_gnet_stats_queue(5, 4096, 7, 2, 3);

        let mut payload = Vec::new();
        payload.extend_from_slice(&make_nla(TCA_STATS_BASIC, &basic));
        payload.extend_from_slice(&make_nla(TCA_STATS_QUEUE, &queue));

        let stats = parse_tca_stats2(&payload).unwrap();
        assert_eq!(stats.bytes, 9_000_000);
        assert_eq!(stats.packets, 1_000);
        assert_eq!(stats.drops, 7);
        assert_eq!(stats.overlimits, 3);
        assert_eq!(stats.backlog, 4096);
    }

    /// `TCA_STATS_BASIC` with `NLA_F_NESTED` bit set (bit 15) on type field —
    /// the parser must mask bit 15 and still recognise `TCA_STATS_BASIC`.
    #[test]
    fn parse_tca_stats2_basic_nested_flag_masked() {
        // TCA_STATS_BASIC = 1; with NLA_F_NESTED (0x8000) the wire type is 0x8001.
        let basic = make_gnet_stats_basic(42, 7);
        let payload = make_nla(0x8001u16, &basic);

        let stats = parse_tca_stats2(&payload).unwrap();
        assert_eq!(stats.bytes, 42);
        assert_eq!(stats.packets, 7);
    }

    /// When `TCA_STATS_BASIC` is absent the function must return `None`.
    #[test]
    fn parse_tca_stats2_missing_basic_returns_none() {
        // Only TCA_STATS_QUEUE present — no basic → None.
        let queue = make_gnet_stats_queue(0, 0, 0, 0, 0);
        let payload = make_nla(TCA_STATS_QUEUE, &queue);

        assert!(
            parse_tca_stats2(&payload).is_none(),
            "missing TCA_STATS_BASIC must return None"
        );
    }

    /// Empty payload returns `None`.
    #[test]
    fn parse_tca_stats2_empty_payload_returns_none() {
        assert!(parse_tca_stats2(&[]).is_none());
    }

    /// `TCA_STATS_BASIC` payload shorter than 12 B is ignored (not decoded).
    #[test]
    fn parse_tca_stats2_basic_too_short_returns_none() {
        // Only 8 bytes of payload — less than gnet_stats_basic 12 B.
        let short_basic = vec![0u8; 8];
        let payload = make_nla(TCA_STATS_BASIC, &short_basic);
        assert!(
            parse_tca_stats2(&payload).is_none(),
            "undersized TCA_STATS_BASIC must not set found_basic"
        );
    }

    // -----------------------------------------------------------------------
    // TC-003: parse_qdisc_frame
    // -----------------------------------------------------------------------

    /// Happy path: `tcmsg` header + `TCA_KIND` + `TCA_STATS2` (basic + queue).
    #[test]
    fn parse_qdisc_frame_with_stats() {
        let mut frame = make_tcmsg(2); // ifindex=2

        // TCA_KIND = 1, NUL-terminated qdisc name
        frame.extend_from_slice(&make_nla(TCA_KIND, b"fq_codel\0"));

        // TCA_STATS2 = 7, nested payload
        let basic = make_gnet_stats_basic(500_000, 250);
        let queue = make_gnet_stats_queue(10, 8192, 3, 1, 2);
        let mut stats2_payload = Vec::new();
        stats2_payload.extend_from_slice(&make_nla(TCA_STATS_BASIC, &basic));
        stats2_payload.extend_from_slice(&make_nla(TCA_STATS_QUEUE, &queue));
        frame.extend_from_slice(&make_nla(TCA_STATS2, &stats2_payload));

        let entry = parse_qdisc_frame(&frame).unwrap();
        assert_eq!(entry.ifindex, 2);
        assert_eq!(entry.kind, "fq_codel");

        let stats = entry.stats.unwrap();
        assert_eq!(stats.bytes, 500_000);
        assert_eq!(stats.packets, 250);
        assert_eq!(stats.drops, 3);
        assert_eq!(stats.overlimits, 2);
        assert_eq!(stats.backlog, 8192);
    }

    /// Frame without `TCA_STATS2`: `stats` field must be `None`; `kind` falls back.
    #[test]
    fn parse_qdisc_frame_no_stats2() {
        let mut frame = make_tcmsg(3);
        frame.extend_from_slice(&make_nla(TCA_KIND, b"noqueue\0"));
        // No TCA_STATS2

        let entry = parse_qdisc_frame(&frame).unwrap();
        assert_eq!(entry.ifindex, 3);
        assert_eq!(entry.kind, "noqueue");
        assert!(entry.stats.is_none(), "no TCA_STATS2 → stats must be None");
    }

    /// Frame without `TCA_KIND` falls back to `"unknown"`.
    #[test]
    fn parse_qdisc_frame_no_kind_defaults_to_unknown() {
        let frame = make_tcmsg(1); // Only tcmsg header, no attrs

        let entry = parse_qdisc_frame(&frame).unwrap();
        assert_eq!(entry.kind, "unknown");
    }

    /// Frame shorter than 20 B (`tcmsg` minimum) returns `None`.
    #[test]
    fn parse_qdisc_frame_too_short_returns_none() {
        let frame = vec![0u8; 10];
        assert!(parse_qdisc_frame(&frame).is_none());
    }

    /// `tcm_ifindex` is decoded correctly from offset 4 (i32 LE).
    ///
    /// Reference: `linux/pkt_sched.h` `struct tcmsg`, field `tcm_ifindex`.
    #[test]
    fn parse_qdisc_frame_ifindex_at_offset_4() {
        let mut frame = make_tcmsg(42);
        frame.extend_from_slice(&make_nla(TCA_KIND, b"pfifo_fast\0"));

        let entry = parse_qdisc_frame(&frame).unwrap();
        assert_eq!(entry.ifindex, 42);
    }
}
