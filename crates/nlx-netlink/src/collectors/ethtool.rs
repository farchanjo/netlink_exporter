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
//!
//! ## Label sanitization (MC-009)
//!
//! The `stat` label value is driver-supplied and can contain arbitrary bytes.
//! `sanitize_stat_label` strips non-printable ASCII, replaces them with `_`, and
//! caps the string at [`MAX_STAT_LABEL_LEN`] characters to bound Prometheus label
//! cardinality and prevent exposition formatting failures.

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

// MC-009: maximum byte length of the sanitized stat label.
// Standard ethtool stat names are at most 32 chars (ETH_GSTRING_LEN=32); cap
// at 64 to allow extended names while still bounding label cardinality.
const MAX_STAT_LABEL_LEN: usize = 64;

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
                    // MC-009: sanitize driver-supplied stat name before use as label.
                    labels.insert("stat".to_owned(), sanitize_stat_label(stat_name));
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

/// MC-009: sanitize a driver-supplied stat name for use as a Prometheus label.
///
/// Rules applied in order:
/// 1. Replace any byte that is not printable ASCII (0x20–0x7E) with `_`.
/// 2. Truncate to at most [`MAX_STAT_LABEL_LEN`] characters.
///
/// Standard ethtool stat names (`ETH_GSTRING_LEN` = 32 in the kernel) are
/// always ASCII; this guard handles out-of-spec or future driver behaviour.
fn sanitize_stat_label(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii() && !c.is_ascii_control() {
                c
            } else {
                '_'
            }
        })
        .take(MAX_STAT_LABEL_LEN)
        .collect()
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
    use crate::wire::{NLA_HDRLEN, align4};

    // -----------------------------------------------------------------------
    // NLA construction helpers (local to tests)
    // -----------------------------------------------------------------------

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
        make_nla(ty | 0x8000, inner)
    }

    // -----------------------------------------------------------------------
    // build_stats_get_payload
    // -----------------------------------------------------------------------

    /// TC-005-A: payload starts with correct genlmsghdr bytes.
    #[test]
    fn build_payload_genl_header() {
        let buf = build_stats_get_payload();
        assert!(buf.len() >= 4, "must be at least genlmsghdr size");
        assert_eq!(buf[0], ETHTOOL_MSG_STATS_GET, "cmd byte must be 37");
        assert_eq!(buf[1], ETHTOOL_GENL_VERSION, "version byte must be 1");
        // reserved u16
        assert_eq!(buf[2], 0);
        assert_eq!(buf[3], 0);
    }

    /// TC-005-B: payload contains `ETHTOOL_A_STATS_GROUPS` (type=3) NLA with `STATS_GROUPS_ALL`.
    #[test]
    fn build_payload_contains_stats_groups_nla() {
        let buf = build_stats_get_payload();
        // Attrs start after genlmsghdr (4 bytes).
        let attrs: Vec<_> = crate::wire::parse_attrs(&buf[4..]).collect();
        assert!(!attrs.is_empty(), "must have at least one NLA");
        let groups_attr = attrs
            .iter()
            .find(|a| a.ty == ETHTOOL_A_STATS_GROUPS)
            .expect("ETHTOOL_A_STATS_GROUPS (type=3) must be present");
        let val = crate::wire::read_u32(groups_attr.payload).expect("u32 payload");
        assert_eq!(val, STATS_GROUPS_ALL, "groups bitmask must be 0x0F");
    }

    // -----------------------------------------------------------------------
    // parse_stats_attrs — 3-level NLA payload
    // -----------------------------------------------------------------------

    /// TC-005-C: parse a synthetic 3-level NLA payload (header→group→stat).
    ///
    /// Wire layout mirrored from kernel `ethtool_stats_get_reply`:
    ///   `ETHTOOL_A_STATS_HEADER` (nested) {
    ///       `ETHTOOL_A_HEADER_DEV_NAME` = "eth0\0"
    ///   }
    ///   `ETHTOOL_A_STATS_GRP` (nested) {
    ///       `ETHTOOL_A_STATS_GRP_STAT` (nested) {
    ///           `ETHTOOL_A_STATS_GRP_STAT_NAME` = "`rx_packets\0`"
    ///           `ETHTOOL_A_STATS_GRP_STAT_VALUE` = 42u64
    ///       }
    ///   }
    #[test]
    fn parse_stats_attrs_three_level_nla() {
        // Inner-most stat pair.
        let stat_name_bytes = b"rx_packets\0";
        let stat_val_bytes = 42u64.to_ne_bytes();
        let mut stat_inner = Vec::new();
        stat_inner.extend(make_nla(ETHTOOL_A_STATS_GRP_STAT_NAME, stat_name_bytes));
        stat_inner.extend(make_nla(ETHTOOL_A_STATS_GRP_STAT_VALUE, &stat_val_bytes));

        // Group wrapper.
        let grp_stat = make_nested(ETHTOOL_A_STATS_GRP_STAT, &stat_inner);
        let grp = make_nested(ETHTOOL_A_STATS_GRP, &grp_stat);

        // Header with dev name.
        let dev_name_nla = make_nla(ETHTOOL_A_HEADER_DEV_NAME, b"eth0\0");
        let header = make_nested(ETHTOOL_A_STATS_HEADER, &dev_name_nla);

        let mut attrs_buf = Vec::new();
        attrs_buf.extend(header);
        attrs_buf.extend(grp);

        let result = parse_stats_attrs(&attrs_buf).expect("must parse successfully");
        assert_eq!(result.0, "eth0", "interface name must be eth0");
        assert_eq!(
            result.1.get("rx_packets").copied(),
            Some(42u64),
            "rx_packets stat must be 42"
        );
    }

    /// TC-005-D: multiple groups, multiple stats per group are all collected.
    #[test]
    fn parse_stats_attrs_multiple_stats() {
        // Build two stat pairs: tx_packets=10, rx_errors=5.
        let make_stat = |name: &[u8], val: u64| -> Vec<u8> {
            let mut inner = Vec::new();
            inner.extend(make_nla(ETHTOOL_A_STATS_GRP_STAT_NAME, name));
            inner.extend(make_nla(ETHTOOL_A_STATS_GRP_STAT_VALUE, &val.to_ne_bytes()));
            make_nested(ETHTOOL_A_STATS_GRP_STAT, &inner)
        };

        let mut grp_payload = Vec::new();
        grp_payload.extend(make_stat(b"tx_packets\0", 10));
        grp_payload.extend(make_stat(b"rx_errors\0", 5));
        let grp = make_nested(ETHTOOL_A_STATS_GRP, &grp_payload);

        let dev_name_nla = make_nla(ETHTOOL_A_HEADER_DEV_NAME, b"eth1\0");
        let header = make_nested(ETHTOOL_A_STATS_HEADER, &dev_name_nla);

        let mut buf = Vec::new();
        buf.extend(header);
        buf.extend(grp);

        let (if_name, stats) = parse_stats_attrs(&buf).expect("must parse");
        assert_eq!(if_name, "eth1");
        assert_eq!(stats.get("tx_packets").copied(), Some(10u64));
        assert_eq!(stats.get("rx_errors").copied(), Some(5u64));
    }

    /// TC-005-E: missing interface name returns None.
    #[test]
    fn parse_stats_attrs_missing_ifname_returns_none() {
        // Only a GRP attr, no HEADER.
        let stat_inner: Vec<u8> = Vec::new();
        let grp = make_nested(ETHTOOL_A_STATS_GRP, &stat_inner);
        assert!(
            parse_stats_attrs(&grp).is_none(),
            "missing if_name must return None"
        );
    }

    // -----------------------------------------------------------------------
    // parse_stats_reply
    // -----------------------------------------------------------------------

    /// TC-005-F: `parse_stats_reply` requires genlmsghdr prefix; too-short returns None.
    #[test]
    fn parse_stats_reply_too_short_returns_none() {
        assert!(parse_stats_reply(&[]).is_none());
        assert!(parse_stats_reply(&[0, 1, 2]).is_none());
    }

    /// TC-005-G: `parse_stats_reply` skips genlmsghdr (4 bytes) and parses remainder.
    #[test]
    fn parse_stats_reply_full_frame() {
        let stat_val_bytes = 99u64.to_ne_bytes();
        let mut stat_inner = Vec::new();
        stat_inner.extend(make_nla(ETHTOOL_A_STATS_GRP_STAT_NAME, b"rx_crc_errors\0"));
        stat_inner.extend(make_nla(ETHTOOL_A_STATS_GRP_STAT_VALUE, &stat_val_bytes));
        let grp_stat = make_nested(ETHTOOL_A_STATS_GRP_STAT, &stat_inner);
        let grp = make_nested(ETHTOOL_A_STATS_GRP, &grp_stat);

        let dev_name_nla = make_nla(ETHTOOL_A_HEADER_DEV_NAME, b"eth2\0");
        let header = make_nested(ETHTOOL_A_STATS_HEADER, &dev_name_nla);

        // Full frame: 4-byte genlmsghdr + attrs.
        let mut frame = vec![ETHTOOL_MSG_STATS_GET, ETHTOOL_GENL_VERSION, 0, 0];
        frame.extend(header);
        frame.extend(grp);

        let result = parse_stats_reply(&frame).expect("must parse full frame");
        assert_eq!(result.if_name, "eth2");
        assert_eq!(result.stats.get("rx_crc_errors").copied(), Some(99u64));
    }

    // -----------------------------------------------------------------------
    // Non-UTF-8 stat name (TC-005-H)
    // -----------------------------------------------------------------------

    /// TC-005-H: a stat name with non-UTF-8 bytes is lossy-decoded.
    ///
    /// The kernel always produces valid UTF-8 stat strings (they are `char *`
    /// from `ethtool_gstrings`), but `from_utf8_lossy` guarantees no panic.
    /// The non-UTF-8 replacement char U+FFFD then gets sanitized to `_` by
    /// `sanitize_stat_label`.
    #[test]
    fn parse_stats_attrs_non_utf8_stat_name_is_sanitized() {
        // b"\xFF\xFE" are invalid UTF-8 start bytes; from_utf8_lossy replaces them.
        let bad_name: &[u8] = b"\xFF\xFEbad_stat\0";
        let mut stat_inner = Vec::new();
        stat_inner.extend(make_nla(ETHTOOL_A_STATS_GRP_STAT_NAME, bad_name));
        stat_inner.extend(make_nla(
            ETHTOOL_A_STATS_GRP_STAT_VALUE,
            &7u64.to_ne_bytes(),
        ));
        let grp_stat = make_nested(ETHTOOL_A_STATS_GRP_STAT, &stat_inner);
        let grp = make_nested(ETHTOOL_A_STATS_GRP, &grp_stat);

        let dev_name_nla = make_nla(ETHTOOL_A_HEADER_DEV_NAME, b"eth0\0");
        let header = make_nested(ETHTOOL_A_STATS_HEADER, &dev_name_nla);

        let mut buf = Vec::new();
        buf.extend(header);
        buf.extend(grp);

        // parse_stats_attrs stores the raw lossy-decoded name.
        let (_if_name, stats) = parse_stats_attrs(&buf).expect("must parse even with bad name");
        // The map will have exactly one entry; its key contains U+FFFD chars.
        assert_eq!(stats.len(), 1, "exactly one stat");
        let raw_key = stats.keys().next().expect("one key");
        // Sanitize and verify no non-printable or non-ASCII chars remain.
        let sanitized = sanitize_stat_label(raw_key);
        assert!(
            sanitized
                .chars()
                .all(|c| c.is_ascii() && !c.is_ascii_control()),
            "sanitized label must be printable ASCII; got: {sanitized:?}"
        );
    }

    // -----------------------------------------------------------------------
    // sanitize_stat_label (MC-009)
    // -----------------------------------------------------------------------

    #[test]
    fn sanitize_stat_label_plain_ascii_unchanged() {
        assert_eq!(sanitize_stat_label("rx_packets"), "rx_packets");
    }

    #[test]
    fn sanitize_stat_label_replaces_control_chars() {
        let input = "rx\x01packets\x7f";
        let out = sanitize_stat_label(input);
        assert_eq!(out, "rx_packets_");
    }

    #[test]
    fn sanitize_stat_label_replaces_non_ascii() {
        // U+00E9 (é) is non-ASCII; must be replaced with '_'.
        let input = "rx_\u{00E9}rrors";
        let out = sanitize_stat_label(input);
        assert_eq!(out, "rx__rrors");
    }

    #[test]
    fn sanitize_stat_label_caps_at_max_len() {
        let long: String = "a".repeat(MAX_STAT_LABEL_LEN + 10);
        let out = sanitize_stat_label(&long);
        assert_eq!(out.len(), MAX_STAT_LABEL_LEN);
    }

    #[test]
    fn sanitize_stat_label_empty_input() {
        assert_eq!(sanitize_stat_label(""), "");
    }

    #[test]
    fn sanitize_stat_label_space_kept() {
        // Space (0x20) is printable ASCII — must not be replaced.
        assert_eq!(sanitize_stat_label("rx packets"), "rx packets");
    }
}
