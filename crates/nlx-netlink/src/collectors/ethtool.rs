//! Ethtool genetlink collector.
//!
//! Netlink family: `NETLINK_GENERIC` (16), family name `"ethtool"`.
//! Message used: `ETHTOOL_MSG_STATS_GET` (cmd=32), issued as an `NLM_F_DUMP`
//! across every interface.
//! ADR refs: ADR-0011, ADR-0014, netlink-protocol.md §8.
//!
//! ## Wire format (verified against the running kernel)
//!
//! The request carries an empty `ETHTOOL_A_STATS_HEADER` (so the dump iterates
//! all netdevs) plus an `ETHTOOL_A_STATS_GROUPS` **nested bitset** selecting the
//! four IEEE standard groups (eth-phy, eth-mac, eth-ctrl, rmon). The bitset uses
//! the compact `SIZE` + `VALUE` + `MASK` form.
//!
//! Each reply frame contains an `ETHTOOL_A_STATS_HEADER` (interface name) and one
//! `ETHTOOL_A_STATS_GRP` per group. A group nest carries `ETHTOOL_A_STATS_GRP_ID`
//! (which group) and, when the driver populates it, `ETHTOOL_A_STATS_GRP_STAT` —
//! a nest of **indexed `u64` values** (the nlattr *type* is the stat index within
//! the group; there are no name attributes on the wire). Stat names come from the
//! fixed, uapi-stable per-group tables in [`stat_name`]. Drivers mark unpopulated
//! stats with `~0` (`u64::MAX`); those are skipped.
//!
//! ## Runtime gate
//!
//! `probe_available()` calls `resolve_genl_family("ethtool")`. `Ok(None)` means
//! the ethtool genetlink family is not registered; `collect()` returns
//! `Ok(vec![])` — no error, no panic.

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
    wire::{NLA_HDRLEN, align4, nested_attrs, parse_attrs, read_u32, read_u64},
};

// NETLINK_GENERIC family protocol constant.
const NETLINK_GENERIC: i32 = 16;

// genlmsghdr command + version (verified via <linux/ethtool_netlink.h>).
const ETHTOOL_MSG_STATS_GET: u8 = 32;
const ETHTOOL_GENL_VERSION: u8 = 1;

// nlattr nested flag.
const NLA_F_NESTED: u16 = 0x8000;

// ETHTOOL_A_STATS_* top-level attribute types.
const ETHTOOL_A_STATS_HEADER: u16 = 2;
const ETHTOOL_A_STATS_GROUPS: u16 = 3;
const ETHTOOL_A_STATS_GRP: u16 = 4;

// ETHTOOL_A_HEADER_* sub-attributes (inside ETHTOOL_A_STATS_HEADER).
const ETHTOOL_A_HEADER_DEV_NAME: u16 = 2;

// ETHTOOL_A_STATS_GRP_* sub-attributes (inside ETHTOOL_A_STATS_GRP).
const ETHTOOL_A_STATS_GRP_ID: u16 = 2;
const ETHTOOL_A_STATS_GRP_STAT: u16 = 4;

// ethtool bitset attribute types (compact form).
const ETHTOOL_A_BITSET_SIZE: u16 = 2;
const ETHTOOL_A_BITSET_VALUE: u16 = 4;
const ETHTOOL_A_BITSET_MASK: u16 = 5;

// Standard stat group ids (enum ethtool_stats_groups bit positions).
const ETHTOOL_STATS_ETH_PHY: u32 = 0;
const ETHTOOL_STATS_ETH_MAC: u32 = 1;
const ETHTOOL_STATS_ETH_CTRL: u32 = 2;
const ETHTOOL_STATS_RMON: u32 = 3;

// Bitset selecting the four standard groups (bits 0..3). The declared bit count
// must match the kernel's `__ETHTOOL_STATS_CNT` (5: phy, mac, ctrl, rmon,
// phydev) — a larger value (e.g. 32) is rejected with EINVAL.
const STATS_GROUPS_ALL: u32 = 0x0F;
const STATS_NBITS: u32 = 5;

// Drivers fill unpopulated standard stats with all-ones.
const STAT_UNSET: u64 = u64::MAX;

/// Adapter implementing [`NetlinkEthtoolPort`] and [`Collector`] for ethtool
/// standard statistics.
pub struct EthtoolCollector;

impl NetlinkEthtoolPort for EthtoolCollector {
    async fn dump_ethtool_stats(&self) -> Result<Vec<EthtoolStats>, DomainError> {
        let mut sock = NetlinkSocket::open(NETLINK_GENERIC)
            .map_err(|e| DomainError::Collector(e.to_string()))?;

        let Some(family_id) = sock
            .resolve_genl_family("ethtool")
            .await
            .map_err(|e| DomainError::Collector(e.to_string()))?
        else {
            debug!("ethtool genetlink family not loaded; returning empty stats");
            return Ok(vec![]);
        };

        let frames = dump_stats(&mut sock, family_id)
            .await
            .map_err(|e| DomainError::Collector(e.to_string()))?;

        let mut result = Vec::with_capacity(frames.len());
        for frame in &frames {
            if frame.len() < 4 {
                continue;
            }
            if let Some((if_name, stats)) = parse_stats_frame(&frame[4..]) {
                let mut map = BTreeMap::new();
                for (group, name, value) in stats {
                    map.insert(format!("{group}_{name}"), value);
                }
                result.push(EthtoolStats {
                    if_name,
                    stats: map,
                    speed_mbps: None,
                    duplex: "unknown".to_owned(),
                    autoneg: "unknown".to_owned(),
                    port: "unknown".to_owned(),
                    pause_rx_frames: None,
                    pause_tx_frames: None,
                    fec_corrected: BTreeMap::new(),
                });
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

            let frames = dump_stats(&mut sock, family_id)
                .await
                .map_err(map_dump_err)?;

            let mut out = Vec::with_capacity(frames.len() * 8);
            for frame in &frames {
                // genlmsghdr is 4 bytes; attrs start at offset 4.
                if frame.len() < 4 {
                    continue;
                }
                let Some((if_name, stats)) = parse_stats_frame(&frame[4..]) else {
                    continue;
                };
                for (group, stat, value) in stats {
                    let mut labels = BTreeMap::new();
                    labels.insert("interface".to_owned(), if_name.clone());
                    labels.insert("group".to_owned(), group.to_owned());
                    labels.insert("stat".to_owned(), stat.to_owned());
                    // Ethtool standard counters reset on interface down — gauge (§8.6).
                    out.push(MetricSample::gauge(
                        "nft_ethtool_stat",
                        "Ethtool standard NIC statistic (gauge — resets on link down).",
                        labels,
                        value as f64,
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
// Dump driver
// ---------------------------------------------------------------------------

fn map_dump_err(e: crate::transport::NetlinkError) -> CollectError {
    match e {
        crate::transport::NetlinkError::DumpIntr => CollectError::DumpIntr,
        crate::transport::NetlinkError::RecvBufOverflow => CollectError::RecvBufOverflow,
        other => CollectError::Io(other.to_string()),
    }
}

/// Issue the `ETHTOOL_MSG_STATS_GET` dump and return the raw reply frames.
async fn dump_stats(
    sock: &mut NetlinkSocket,
    family_id: u16,
) -> Result<Vec<Vec<u8>>, crate::transport::NetlinkError> {
    let payload = build_stats_get_payload();
    let mut restarts = 0u32;
    loop {
        match sock.dump(family_id, 0, &payload).await {
            Ok(frames) => return Ok(frames),
            Err(crate::transport::NetlinkError::DumpIntr) => {
                restarts += 1;
                if restarts >= crate::transport::MAX_DUMP_RESTARTS {
                    return Err(crate::transport::NetlinkError::DumpIntr);
                }
            }
            Err(e) => return Err(e),
        }
    }
}

// ---------------------------------------------------------------------------
// Wire builders
// ---------------------------------------------------------------------------

/// Build the `ETHTOOL_MSG_STATS_GET` request body: genlmsghdr + empty header
/// (dump all interfaces) + a `ETHTOOL_A_STATS_GROUPS` bitset selecting the four
/// standard groups.
fn build_stats_get_payload() -> Vec<u8> {
    let mut buf = Vec::with_capacity(48);
    // genlmsghdr (4 bytes): cmd=32, version=1, reserved=0.
    buf.push(ETHTOOL_MSG_STATS_GET);
    buf.push(ETHTOOL_GENL_VERSION);
    buf.extend_from_slice(&0u16.to_ne_bytes());

    // Empty STATS_HEADER (nested) → dump iterates every netdev.
    push_nla(&mut buf, ETHTOOL_A_STATS_HEADER | NLA_F_NESTED, &[]);

    // STATS_GROUPS bitset (compact: SIZE + VALUE + MASK).
    let mut bitset = Vec::with_capacity(24);
    push_nla(
        &mut bitset,
        ETHTOOL_A_BITSET_SIZE,
        &STATS_NBITS.to_ne_bytes(),
    );
    push_nla(
        &mut bitset,
        ETHTOOL_A_BITSET_VALUE,
        &STATS_GROUPS_ALL.to_ne_bytes(),
    );
    push_nla(
        &mut bitset,
        ETHTOOL_A_BITSET_MASK,
        &STATS_GROUPS_ALL.to_ne_bytes(),
    );
    push_nla(&mut buf, ETHTOOL_A_STATS_GROUPS | NLA_F_NESTED, &bitset);

    buf
}

/// Push a flat nlattr into `buf`.
#[allow(
    clippy::cast_possible_truncation,
    reason = "nlattr length fits u16 by construction: NLA_HDRLEN + payload never exceeds 65535"
)]
fn push_nla(buf: &mut Vec<u8>, ty: u16, payload: &[u8]) {
    let nla_len = (NLA_HDRLEN + payload.len()) as u16;
    buf.extend_from_slice(&nla_len.to_ne_bytes());
    buf.extend_from_slice(&ty.to_ne_bytes());
    buf.extend_from_slice(payload);
    let pad = align4(NLA_HDRLEN + payload.len()) - (NLA_HDRLEN + payload.len());
    buf.extend(std::iter::repeat_n(0u8, pad));
}

// ---------------------------------------------------------------------------
// Name tables (uapi-stable; indices = nlattr type within each group nest)
// ---------------------------------------------------------------------------

/// Prometheus `group` label for a stat group id.
fn group_label(gid: u32) -> Option<&'static str> {
    match gid {
        ETHTOOL_STATS_ETH_PHY => Some("eth_phy"),
        ETHTOOL_STATS_ETH_MAC => Some("eth_mac"),
        ETHTOOL_STATS_ETH_CTRL => Some("eth_ctrl"),
        ETHTOOL_STATS_RMON => Some("rmon"),
        _ => None,
    }
}

/// Map a `(group id, stat index)` pair to its stable stat name, mirroring the
/// `enum ethtool_a_stats_eth_*` definitions in `<linux/ethtool_netlink.h>`.
fn stat_name(gid: u32, index: u16) -> Option<&'static str> {
    match gid {
        ETHTOOL_STATS_ETH_PHY => match index {
            0 => Some("symbol_err"),
            _ => None,
        },
        ETHTOOL_STATS_ETH_MAC => match index {
            0 => Some("tx_pkt"),
            1 => Some("single_collision"),
            2 => Some("multiple_collision"),
            3 => Some("rx_pkt"),
            4 => Some("fcs_err"),
            5 => Some("alignment_err"),
            6 => Some("tx_bytes"),
            7 => Some("tx_deferred"),
            8 => Some("late_collision"),
            9 => Some("excessive_collision"),
            10 => Some("tx_internal_err"),
            11 => Some("carrier_sense_err"),
            12 => Some("rx_bytes"),
            13 => Some("rx_internal_err"),
            14 => Some("tx_multicast"),
            15 => Some("tx_broadcast"),
            16 => Some("excessive_deferral"),
            17 => Some("rx_multicast"),
            18 => Some("rx_broadcast"),
            19 => Some("in_range_len_err"),
            20 => Some("out_of_range_len"),
            21 => Some("frame_too_long"),
            _ => None,
        },
        ETHTOOL_STATS_ETH_CTRL => match index {
            0 => Some("tx_pause_frames"),
            1 => Some("rx_pause_frames"),
            2 => Some("rx_unsupported_pause"),
            _ => None,
        },
        ETHTOOL_STATS_RMON => match index {
            0 => Some("undersize_pkts"),
            1 => Some("oversize_pkts"),
            2 => Some("fragments"),
            3 => Some("jabbers"),
            _ => None,
        },
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/// A single emitted standard statistic: `(group label, stat name, value)`.
type StatTriple = (&'static str, &'static str, u64);

/// Parse one `ETHTOOL_MSG_STATS_GET` reply frame (attrs after genlmsghdr).
/// Returns `(interface_name, [(group, stat, value)])` or `None` when the frame
/// carries no interface header.
fn parse_stats_frame(attrs_buf: &[u8]) -> Option<(String, Vec<StatTriple>)> {
    let mut if_name = String::new();
    let mut out: Vec<StatTriple> = Vec::new();

    for attr in parse_attrs(attrs_buf) {
        match attr.ty {
            ETHTOOL_A_STATS_HEADER => {
                for inner in nested_attrs(attr.payload) {
                    if inner.ty == ETHTOOL_A_HEADER_DEV_NAME && !inner.payload.is_empty() {
                        let end = inner
                            .payload
                            .iter()
                            .position(|&b| b == 0)
                            .unwrap_or(inner.payload.len());
                        if_name = String::from_utf8_lossy(&inner.payload[..end]).into_owned();
                    }
                }
            }
            ETHTOOL_A_STATS_GRP => parse_group(attr.payload, &mut out),
            _ => {}
        }
    }

    if if_name.is_empty() {
        return None;
    }
    Some((if_name, out))
}

/// Parse one `ETHTOOL_A_STATS_GRP` nest. The group id precedes the stats, and —
/// crucially — the kernel emits **one `ETHTOOL_A_STATS_GRP_STAT` nest per stat**
/// (each carrying a single indexed `u64`), not a single nest holding them all.
/// `ETHTOOL_A_STATS_GRP_HIST_*` (e.g. rmon histograms) are ignored.
fn parse_group(grp_buf: &[u8], out: &mut Vec<StatTriple>) {
    let mut gid: Option<u32> = None;
    for attr in nested_attrs(grp_buf) {
        if attr.ty == ETHTOOL_A_STATS_GRP_ID {
            gid = read_u32(attr.payload);
        }
    }
    let Some(gid) = gid else {
        return;
    };
    let Some(group) = group_label(gid) else {
        return;
    };

    for attr in nested_attrs(grp_buf) {
        if attr.ty != ETHTOOL_A_STATS_GRP_STAT {
            continue;
        }
        for stat in nested_attrs(attr.payload) {
            // The nlattr type is the stat index within the group; payload is a u64.
            let Some(value) = read_u64(stat.payload) else {
                continue;
            };
            if value == STAT_UNSET {
                continue; // driver did not populate this stat
            }
            if let Some(name) = stat_name(gid, stat.ty) {
                out.push((group, name, value));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests (TC-005)
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    reason = "test"
)]
mod tests {
    use super::*;
    use crate::wire::{NLA_HDRLEN, align4, read_u32};

    /// Build a flat NLA (`nla_len`, ty, payload, padding).
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

    /// Build a nested NLA (`NLA_F_NESTED | ty`) wrapping `inner` bytes.
    fn make_nested(ty: u16, inner: &[u8]) -> Vec<u8> {
        make_nla(ty | NLA_F_NESTED, inner)
    }

    // -----------------------------------------------------------------------
    // build_stats_get_payload
    // -----------------------------------------------------------------------

    /// Payload starts with the correct genlmsghdr (cmd=32, version=1).
    #[test]
    fn build_payload_genl_header() {
        let buf = build_stats_get_payload();
        assert!(buf.len() >= 4, "must be at least genlmsghdr size");
        assert_eq!(buf[0], ETHTOOL_MSG_STATS_GET, "cmd byte must be 32");
        assert_eq!(buf[1], ETHTOOL_GENL_VERSION, "version byte must be 1");
        assert_eq!(buf[2], 0);
        assert_eq!(buf[3], 0);
    }

    /// Payload carries an (empty) `STATS_HEADER` and a `STATS_GROUPS` bitset that
    /// selects the four standard groups via SIZE + VALUE + MASK.
    #[test]
    fn build_payload_has_header_and_groups_bitset() {
        let buf = build_stats_get_payload();
        let attrs: Vec<_> = parse_attrs(&buf[4..]).collect();
        assert!(
            attrs.iter().any(|a| a.ty == ETHTOOL_A_STATS_HEADER),
            "STATS_HEADER must be present"
        );
        let groups = attrs
            .iter()
            .find(|a| a.ty == ETHTOOL_A_STATS_GROUPS)
            .expect("STATS_GROUPS must be present");

        let mut size = None;
        let mut value = None;
        let mut mask = None;
        for inner in nested_attrs(groups.payload) {
            match inner.ty {
                ETHTOOL_A_BITSET_SIZE => size = read_u32(inner.payload),
                ETHTOOL_A_BITSET_VALUE => value = read_u32(inner.payload),
                ETHTOOL_A_BITSET_MASK => mask = read_u32(inner.payload),
                _ => {}
            }
        }
        assert_eq!(size, Some(STATS_NBITS), "bitset SIZE must be the bit count");
        assert_eq!(value, Some(STATS_GROUPS_ALL), "bitset VALUE must be 0x0F");
        assert_eq!(mask, Some(STATS_GROUPS_ALL), "bitset MASK must be 0x0F");
    }

    // -----------------------------------------------------------------------
    // parse_stats_frame — header + grp + indexed grp_stat
    // -----------------------------------------------------------------------

    /// Build a `STATS_GRP` nest: `GRP_ID` followed by one `GRP_STAT` nest per
    /// stat, each carrying a single indexed `u64` — exactly as the kernel emits.
    fn make_group(gid: u32, stats: &[(u16, u64)]) -> Vec<u8> {
        let mut inner = Vec::new();
        inner.extend(make_nla(ETHTOOL_A_STATS_GRP_ID, &gid.to_ne_bytes()));
        for (idx, val) in stats {
            let one = make_nla(*idx, &val.to_ne_bytes());
            inner.extend(make_nested(ETHTOOL_A_STATS_GRP_STAT, &one));
        }
        make_nested(ETHTOOL_A_STATS_GRP, &inner)
    }

    fn make_header(dev: &[u8]) -> Vec<u8> {
        make_nested(
            ETHTOOL_A_STATS_HEADER,
            &make_nla(ETHTOOL_A_HEADER_DEV_NAME, dev),
        )
    }

    /// A frame with an eth-mac group maps indices to the correct names/values.
    #[test]
    fn parse_eth_mac_group_indices() {
        let mut buf = Vec::new();
        buf.extend(make_header(b"eth0\0"));
        // index 0=tx_pkt, 6=tx_bytes, 3=rx_pkt, 12=rx_bytes
        buf.extend(make_group(
            ETHTOOL_STATS_ETH_MAC,
            &[(0, 100), (6, 5000), (3, 90), (12, 4000)],
        ));

        let (if_name, stats) = parse_stats_frame(&buf).expect("must parse");
        assert_eq!(if_name, "eth0");
        let m: BTreeMap<(&str, &str), u64> = stats.iter().map(|(g, s, v)| ((*g, *s), *v)).collect();
        assert_eq!(m.get(&("eth_mac", "tx_pkt")).copied(), Some(100));
        assert_eq!(m.get(&("eth_mac", "tx_bytes")).copied(), Some(5000));
        assert_eq!(m.get(&("eth_mac", "rx_pkt")).copied(), Some(90));
        assert_eq!(m.get(&("eth_mac", "rx_bytes")).copied(), Some(4000));
    }

    /// Multiple groups in one frame are all parsed with the right labels.
    #[test]
    fn parse_multiple_groups() {
        let mut buf = Vec::new();
        buf.extend(make_header(b"eth1\0"));
        buf.extend(make_group(ETHTOOL_STATS_ETH_CTRL, &[(0, 7), (1, 8)]));
        buf.extend(make_group(ETHTOOL_STATS_RMON, &[(2, 3)]));

        let (_n, stats) = parse_stats_frame(&buf).expect("must parse");
        let m: BTreeMap<(&str, &str), u64> = stats.iter().map(|(g, s, v)| ((*g, *s), *v)).collect();
        assert_eq!(m.get(&("eth_ctrl", "tx_pause_frames")).copied(), Some(7));
        assert_eq!(m.get(&("eth_ctrl", "rx_pause_frames")).copied(), Some(8));
        assert_eq!(m.get(&("rmon", "fragments")).copied(), Some(3));
    }

    /// `~0` (`u64::MAX`) sentinel values are skipped (driver did not populate).
    #[test]
    fn parse_skips_unset_sentinel() {
        let mut buf = Vec::new();
        buf.extend(make_header(b"eth2\0"));
        buf.extend(make_group(
            ETHTOOL_STATS_ETH_MAC,
            &[(0, 42), (1, STAT_UNSET)],
        ));

        let (_n, stats) = parse_stats_frame(&buf).expect("must parse");
        assert_eq!(stats.len(), 1, "unset stat must be skipped");
        assert_eq!(stats[0], ("eth_mac", "tx_pkt", 42));
    }

    /// Unknown stat indices (beyond the known table) are skipped, not panicked.
    #[test]
    fn parse_skips_unknown_index() {
        let mut buf = Vec::new();
        buf.extend(make_header(b"eth3\0"));
        buf.extend(make_group(ETHTOOL_STATS_ETH_MAC, &[(0, 1), (99, 2)]));

        let (_n, stats) = parse_stats_frame(&buf).expect("must parse");
        assert_eq!(stats.len(), 1, "unknown index must be skipped");
        assert_eq!(stats[0].1, "tx_pkt");
    }

    /// A group with no `GRP_STAT` nest (driver reports the group but no data)
    /// yields no stats but still parses the frame.
    #[test]
    fn parse_empty_group_yields_no_stats() {
        let mut buf = Vec::new();
        buf.extend(make_header(b"eth4\0"));
        // GRP with only GRP_ID, no GRP_STAT.
        let inner = make_nla(ETHTOOL_A_STATS_GRP_ID, &ETHTOOL_STATS_ETH_MAC.to_ne_bytes());
        buf.extend(make_nested(ETHTOOL_A_STATS_GRP, &inner));

        let (if_name, stats) = parse_stats_frame(&buf).expect("must parse");
        assert_eq!(if_name, "eth4");
        assert!(stats.is_empty(), "empty group must yield no stats");
    }

    /// A frame without an interface header returns None.
    #[test]
    fn parse_missing_ifname_returns_none() {
        let buf = make_group(ETHTOOL_STATS_ETH_MAC, &[(0, 1)]);
        assert!(
            parse_stats_frame(&buf).is_none(),
            "missing if_name must return None"
        );
    }

    /// An unknown group id is ignored entirely.
    #[test]
    fn parse_unknown_group_ignored() {
        let mut buf = Vec::new();
        buf.extend(make_header(b"eth5\0"));
        buf.extend(make_group(99, &[(0, 123)]));
        let (_n, stats) = parse_stats_frame(&buf).expect("must parse");
        assert!(stats.is_empty(), "unknown group id must be ignored");
    }

    // -----------------------------------------------------------------------
    // name tables
    // -----------------------------------------------------------------------

    #[test]
    fn group_labels_match_ids() {
        assert_eq!(group_label(0), Some("eth_phy"));
        assert_eq!(group_label(1), Some("eth_mac"));
        assert_eq!(group_label(2), Some("eth_ctrl"));
        assert_eq!(group_label(3), Some("rmon"));
        assert_eq!(group_label(4), None);
    }

    #[test]
    fn stat_names_spot_check() {
        assert_eq!(stat_name(ETHTOOL_STATS_ETH_MAC, 0), Some("tx_pkt"));
        assert_eq!(stat_name(ETHTOOL_STATS_ETH_MAC, 6), Some("tx_bytes"));
        assert_eq!(stat_name(ETHTOOL_STATS_ETH_MAC, 12), Some("rx_bytes"));
        assert_eq!(stat_name(ETHTOOL_STATS_ETH_MAC, 21), Some("frame_too_long"));
        assert_eq!(stat_name(ETHTOOL_STATS_ETH_MAC, 22), None);
        assert_eq!(stat_name(ETHTOOL_STATS_ETH_PHY, 0), Some("symbol_err"));
        assert_eq!(stat_name(ETHTOOL_STATS_RMON, 3), Some("jabbers"));
    }
}
