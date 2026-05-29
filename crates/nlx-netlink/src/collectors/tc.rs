//! Traffic-control collector.
//!
//! Netlink family: `NETLINK_ROUTE` (0).
//! Messages used: `RTM_GETQDISC` (type 38), `RTM_GETTCLASS`, `RTM_GETTFILTER`.
//! ADR refs: ADR-0011 (TCA_STATS2 NLA_F_NESTED bit-15 masking), ADR-0014.
//!
//! ## Wire layout (netlink-protocol.md §7)
//!
//! `tcmsg` 20 B: family(1) pad1(1) pad2(2) ifindex(4) handle(4) parent(4)
//! info(4).
//!
//! TCA_KIND (type=1): NUL-terminated qdisc name string.
//! TCA_STATS2 (type=7): nested nlattr container with:
//!   - TCA_STATS_BASIC (1): `gnet_stats_basic` 12 B — u64 bytes + u32 packets
//!   - TCA_STATS_QUEUE (3): `gnet_stats_queue` 20 B — 5× u32 (qlen, backlog,
//!     drops, requeues, overlimits)
//!
//! Interface name is resolved from `tcm_ifindex` via a prior RTM_GETLINK dump.

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

const AF_UNSPEC: u8 = 0;

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

/// Minimal `rtgenmsg` payload (1 byte, AF_UNSPEC) for RTM_GETLINK dump.
fn rtgenmsg_payload() -> [u8; 1] {
    [AF_UNSPEC]
}

/// `tcmsg` payload for RTM_GETQDISC dump: 20 bytes all-zero except family=0.
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

/// Build a map from `ifindex` (i32) to interface name using RTM_GETLINK.
async fn build_ifindex_map(
    sock: &mut NetlinkSocket,
) -> Result<BTreeMap<i32, String>, NetlinkError> {
    let frames = dump_with_retries(sock, RTM_GETLINK, &rtgenmsg_payload()).await?;
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
    /// Total bytes through qdisc (from gnet_stats_basic).
    bytes: u64,
    /// Total packets through qdisc (from gnet_stats_basic).
    packets: u64,
    /// Drops (from gnet_stats_queue).
    drops: u32,
    /// Overlimits (from gnet_stats_queue).
    overlimits: u32,
    /// Backlog bytes (from gnet_stats_queue).
    backlog: u32,
}

/// Parse `TCA_STATS2` payload (nested attrs: TCA_STATS_BASIC + TCA_STATS_QUEUE).
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
    fn name(&self) -> &str {
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
                    .map(String::as_str)
                    .unwrap_or("unknown");
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
