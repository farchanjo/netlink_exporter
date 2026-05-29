//! Ethtool genetlink collector.
//!
//! Netlink family: `NETLINK_GENERIC` (16), family name `"ethtool"`.
//! Messages used: `ETHTOOL_MSG_STATS_GET` (cmd=37).
//! ADR refs: ADR-0011, ADR-0014, netlink-protocol.md §8.
//!
//! ## Runtime gate
//!
//! `probe_available()` calls `resolve_genl_family("ethtool")`. `Ok(None)` means
//! the kernel module / Kconfig is not loaded; the collector returns `Ok(vec![])`
//! on every `collect()` call — no error, no panic.

use std::collections::BTreeMap;

use nlx_domain::{error::DomainError, metric::MetricSample, model::ethtool::EthtoolStats};
use nlx_ports::{
    collector::{BoxFuture, Collector},
    driven::NetlinkEthtoolPort,
    error::CollectError,
};
use tracing::debug;

use crate::{
    transport::NetlinkSocket,
    wire::{nested_attrs, parse_attrs, read_u64},
};

// NETLINK_GENERIC family protocol constant.
const NETLINK_GENERIC: i32 = 16;

// genlmsghdr command constants (§8.2).
const ETHTOOL_MSG_STATS_GET: u8 = 37;
const ETHTOOL_GENL_VERSION: u8 = 1;

// ETHTOOL_A_STATS top-level attribute types (§8).
const ETHTOOL_A_STATS_HEADER: u16 = 1;
const ETHTOOL_A_STATS_GROUPS: u16 = 3;
const ETHTOOL_A_STATS_GRP: u16 = 4;

// ETHTOOL_A_HEADER sub-attribute: ifindex.
const ETHTOOL_A_HEADER_DEV_INDEX: u16 = 2;
const ETHTOOL_A_HEADER_DEV_NAME: u16 = 3;

// ETHTOOL_A_STATS_GRP sub-attributes.
const ETHTOOL_A_STATS_GRP_STAT: u16 = 4;

// ETHTOOL_A_STATS_GRP_STAT sub-attrs.
const ETHTOOL_A_STATS_GRP_STAT_NAME: u16 = 1;
const ETHTOOL_A_STATS_GRP_STAT_VALUE: u16 = 2;

// Request all four standard groups: eth-mac, eth-phy, eth-ctrl, rmon (bits 0-3).
const STATS_GROUPS_ALL: u32 = 0x0F;

// Metric cardinality bounds — stat names from standard groups are uapi-stable.
const MAX_STAT_NAMES: usize = 128;

/// Adapter implementing [`NetlinkEthtoolPort`] and [`Collector`] for ethtool
/// statistics.
pub struct EthtoolCollector;

impl NetlinkEthtoolPort for EthtoolCollector {
    async fn dump_ethtool_stats(&self) -> Result<Vec<EthtoolStats>, DomainError> {
        let mut sock = NetlinkSocket::open(NETLINK_GENERIC)
            .map_err(|e| DomainError::Collector(e.to_string()))?;

        let family_id = sock
            .resolve_genl_family("ethtool")
            .await
            .map_err(|e| DomainError::Collector(e.to_string()))?;

        let Some(family_id) = family_id else {
            debug!("ethtool genetlink family not loaded; returning empty stats");
            return Ok(vec![]);
        };

        let payload = build_stats_get_payload();
        let mut restarts = 0u32;
        let frames = loop {
            match sock.dump(family_id, 0, &payload).await {
                Ok(frames) => break frames,
                Err(crate::transport::NetlinkError::DumpIntr) => {
                    restarts += 1;
                    if restarts >= crate::transport::MAX_DUMP_RESTARTS {
                        return Err(DomainError::Collector(
                            "ethtool dump interrupted (NLM_F_DUMP_INTR) too many times".into(),
                        ));
                    }
                }
                Err(e) => return Err(DomainError::Collector(e.to_string())),
            }
        };

        let mut result = Vec::with_capacity(frames.len());
        for frame in &frames {
            if let Some(stats) = parse_stats_reply(frame) {
                result.push(stats);
            }
        }
        Ok(result)
    }
}

impl Collector for EthtoolCollector {
    fn name(&self) -> &'static str {
        "ethtool"
    }

    #[allow(
        clippy::cast_precision_loss,
        reason = "metric gauge values are f64; precision loss on large u64 counters is inherent to Prometheus exposition"
    )]
    fn collect(&self) -> BoxFuture<'_, Result<Vec<MetricSample>, CollectError>> {
        Box::pin(async move {
            let mut sock = NetlinkSocket::open(NETLINK_GENERIC)
                .map_err(|e| CollectError::Io(e.to_string()))?;

            let family_id = sock
                .resolve_genl_family("ethtool")
                .await
                .map_err(|e| CollectError::Io(e.to_string()))?;

            let Some(family_id) = family_id else {
                debug!("ethtool genetlink family not loaded; skipping collect");
                return Ok(vec![]);
            };

            let payload = build_stats_get_payload();
            let mut restarts = 0u32;
            let frames = loop {
                match sock.dump(family_id, 0, &payload).await {
                    Ok(frames) => break frames,
                    Err(crate::transport::NetlinkError::DumpIntr) => {
                        restarts += 1;
                        if restarts >= crate::transport::MAX_DUMP_RESTARTS {
                            return Err(CollectError::DumpIntr);
                        }
                    }
                    Err(crate::transport::NetlinkError::RecvBufOverflow) => {
                        return Err(CollectError::RecvBufOverflow);
                    }
                    Err(e) => return Err(CollectError::Io(e.to_string())),
                }
            };

            let mut out = Vec::with_capacity(frames.len() * 8);
            for frame in &frames {
                // genlmsghdr is 4 bytes; attrs start at offset 4.
                if frame.len() < 4 {
                    continue;
                }
                let attrs_buf = &frame[4..];
                let Some((if_name, stats)) = parse_stats_attrs(attrs_buf) else {
                    continue;
                };
                // Bounded: standard groups produce ≤128 stat names per interface.
                for (stat_name, value) in stats.iter().take(MAX_STAT_NAMES) {
                    let mut labels = BTreeMap::new();
                    labels.insert("interface".to_owned(), if_name.clone());
                    labels.insert("stat".to_owned(), stat_name.clone());
                    // Ethtool counters reset on interface down — use gauge (§8.6).
                    out.push(MetricSample::gauge(
                        "nft_ethtool_stat",
                        "Ethtool NIC statistic (gauge — resets on link down).",
                        labels,
                        *value as f64,
                    ));
                }
            }
            Ok(out)
        })
    }

    fn probe_available(&self) -> BoxFuture<'_, bool> {
        Box::pin(async move {
            let Ok(mut sock) = NetlinkSocket::open(NETLINK_GENERIC) else {
                return false;
            };
            matches!(sock.resolve_genl_family("ethtool").await, Ok(Some(_)))
        })
    }
}

// ---------------------------------------------------------------------------
// Wire helpers
// ---------------------------------------------------------------------------

/// Build the `ETHTOOL_MSG_STATS_GET` payload (genlmsghdr + `ETHTOOL_A_STATS_GROUPS`).
fn build_stats_get_payload() -> Vec<u8> {
    let mut buf = Vec::with_capacity(32);
    // genlmsghdr (4 bytes): cmd=37, version=1, reserved=0.
    buf.push(ETHTOOL_MSG_STATS_GET);
    buf.push(ETHTOOL_GENL_VERSION);
    buf.extend_from_slice(&0u16.to_ne_bytes());

    // ETHTOOL_A_STATS_GROUPS = 3, payload u32.
    let groups = STATS_GROUPS_ALL;
    push_nlattr(&mut buf, ETHTOOL_A_STATS_GROUPS, &groups.to_ne_bytes());

    buf
}

/// Push a flat nlattr into `buf`.
#[allow(
    clippy::cast_possible_truncation,
    reason = "nlattr length fits u16 by construction: NLA_HDRLEN + payload never exceeds 65535"
)]
fn push_nlattr(buf: &mut Vec<u8>, ty: u16, payload: &[u8]) {
    use crate::wire::{NLA_HDRLEN, align4};
    let nla_len = (NLA_HDRLEN + payload.len()) as u16;
    buf.extend_from_slice(&nla_len.to_ne_bytes());
    buf.extend_from_slice(&ty.to_ne_bytes());
    buf.extend_from_slice(payload);
    let pad = align4(NLA_HDRLEN + payload.len()) - (NLA_HDRLEN + payload.len());
    buf.extend(std::iter::repeat_n(0u8, pad));
}

/// Parse one `ETHTOOL_MSG_STATS_REPLY` frame payload (after genlmsghdr).
/// Returns `(interface_name, stat_map)` or `None` on parse failure.
fn parse_stats_attrs(attrs_buf: &[u8]) -> Option<(String, BTreeMap<String, u64>)> {
    let mut if_name = String::new();
    let mut stats = BTreeMap::new();

    for attr in parse_attrs(attrs_buf) {
        match attr.ty {
            ETHTOOL_A_STATS_HEADER => {
                // Nested: parse ETHTOOL_A_HEADER_DEV_NAME.
                for inner in nested_attrs(attr.payload) {
                    if inner.ty == ETHTOOL_A_HEADER_DEV_NAME && !inner.payload.is_empty() {
                        let end = inner
                            .payload
                            .iter()
                            .position(|&b| b == 0)
                            .unwrap_or(inner.payload.len());
                        if_name = String::from_utf8_lossy(&inner.payload[..end]).into_owned();
                    }
                    // ETHTOOL_A_HEADER_DEV_INDEX also present but we prefer name.
                    let _ = ETHTOOL_A_HEADER_DEV_INDEX;
                }
            }
            ETHTOOL_A_STATS_GRP => {
                // Nested per-group: each contains multiple ETHTOOL_A_STATS_GRP_STAT.
                for grp_attr in nested_attrs(attr.payload) {
                    if grp_attr.ty == ETHTOOL_A_STATS_GRP_STAT {
                        // Nested: ETHTOOL_A_STATS_GRP_STAT_NAME + VALUE.
                        let mut stat_name = String::new();
                        let mut stat_val: Option<u64> = None;
                        for stat_attr in nested_attrs(grp_attr.payload) {
                            match stat_attr.ty {
                                ETHTOOL_A_STATS_GRP_STAT_NAME => {
                                    let end = stat_attr
                                        .payload
                                        .iter()
                                        .position(|&b| b == 0)
                                        .unwrap_or(stat_attr.payload.len());
                                    stat_name = String::from_utf8_lossy(&stat_attr.payload[..end])
                                        .into_owned();
                                }
                                ETHTOOL_A_STATS_GRP_STAT_VALUE => {
                                    stat_val = read_u64(stat_attr.payload);
                                }
                                _ => {}
                            }
                        }
                        if !stat_name.is_empty() {
                            if let Some(v) = stat_val {
                                stats.insert(stat_name, v);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    if if_name.is_empty() {
        return None;
    }
    Some((if_name, stats))
}

/// Parse a full frame (including genlmsghdr) into `EthtoolStats`.
fn parse_stats_reply(frame: &[u8]) -> Option<EthtoolStats> {
    if frame.len() < 4 {
        return None;
    }
    let attrs_buf = &frame[4..];
    let (if_name, stats) = parse_stats_attrs(attrs_buf)?;
    Some(EthtoolStats {
        if_name,
        stats,
        speed_mbps: None,
        duplex: "unknown".to_owned(),
        autoneg: "unknown".to_owned(),
        port: "unknown".to_owned(),
        pause_rx_frames: None,
        pause_tx_frames: None,
        fec_corrected: BTreeMap::new(),
    })
}
