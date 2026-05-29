//! Drop-monitor genetlink collector.
//!
//! Netlink family: `NETLINK_GENERIC` (16), family name `"NET_DM"`.
//! ADR refs: ADR-0011, ADR-0014, netlink-protocol.md §16.
//!
//! ## Runtime gate
//!
//! `probe_available()` calls `resolve_genl_family("NET_DM")`. `Ok(None)` means
//! the `drop_monitor` module is not loaded; `collect()` returns `Ok(vec![])`.
//!
//! ## Protocol (derived from linux/net/core/drop_monitor.c + uapi/linux/net_dropmon.h)
//!
//! Commands (genl family version = 2):
//!
//! | Cmd | Value | Flags | Description |
//! |-----|-------|-------|-------------|
//! | `NET_DM_CMD_CONFIG`    | 2 | `GENL_ADMIN_PERM` | Set alert mode, trunc/queue len |
//! | `NET_DM_CMD_START`     | 3 | `GENL_ADMIN_PERM` | Start SW/HW monitoring |
//! | `NET_DM_CMD_STOP`      | 4 | `GENL_ADMIN_PERM` | Stop SW/HW monitoring |
//! | `NET_DM_CMD_STATS_GET` | 8 | (none, unprivileged) | Pull aggregate drop counts |
//!
//! `NET_DM_CMD_STATS_GET` (unicast, no `NLM_F_DUMP`) replies with
//! `NET_DM_CMD_STATS_NEW` containing:
//!
//! - `NET_DM_ATTR_STATS`    (type=12, nested) → `NET_DM_ATTR_STATS_DROPPED` (type=0, u64) SW total
//! - `NET_DM_ATTR_HW_STATS` (type=13, nested) → `NET_DM_ATTR_STATS_DROPPED` (type=0, u64) HW total
//!
//! **No per-reason breakdown from STATS_GET.** Per-reason data lives only in
//! the `NET_DM_GRP_ALERT` multicast stream (PACKET-mode alerts). STATS_GET
//! is used here for a simple, lock-free, per-scrape pull that requires no
//! background task.
//!
//! ## Collection model
//!
//! On each `collect()` call:
//!
//! 1. Resolve `"NET_DM"` family (fast; cached kernel-side).
//! 2. Send `NET_DM_CMD_CONFIG` + `NET_DM_CMD_START` (idempotent; EBUSY/EALREADY ignored).
//! 3. Send `NET_DM_CMD_STATS_GET`; parse reply.
//! 4. Emit `nft_drop_packets_total{origin="sw", reason="total"}` and
//!    `nft_drop_packets_total{origin="hw", reason="total"}`.
//!
//! ## Cardinality
//!
//! Fixed: two label combinations `{origin="sw", reason="total"}` and
//! `{origin="hw", reason="total"}`.  Zero cardinality explosion.
//!
//! ## Monitoring prerequisites
//!
//! `NET_DM_CMD_STATS_GET` returns valid counters only after `NET_DM_CMD_START`
//! has been called at least once (by this exporter or by `dropwatch -l kas`).
//! `collect()` always attempts START before querying stats; idempotent starts
//! return kernel error `EBUSY` (16) which is silently ignored.

use std::collections::BTreeMap;

use nlx_domain::{error::DomainError, metric::MetricSample, model::drop_monitor::DropEvent};
use nlx_ports::{
    collector::{BoxFuture, Collector},
    driven::NetlinkDropMonitorPort,
    error::CollectError,
};
use tracing::{debug, warn};

use crate::{
    transport::NetlinkSocket,
    wire::{NLA_HDRLEN, align4, nested_attrs, parse_attrs, read_u64},
};

const NETLINK_GENERIC: i32 = 16;

// ---------------------------------------------------------------------------
// NET_DM commands — from uapi/linux/net_dropmon.h (enum starting at 0).
// ---------------------------------------------------------------------------

/// `NET_DM_CMD_CONFIG` — configure alert mode. Requires `CAP_NET_ADMIN`.
const NET_DM_CMD_CONFIG: u8 = 2;
/// `NET_DM_CMD_START` — begin monitoring. Requires `CAP_NET_ADMIN`.
const NET_DM_CMD_START: u8 = 3;
/// `NET_DM_CMD_STATS_GET` — pull aggregate drop statistics. No privilege required.
const NET_DM_CMD_STATS_GET: u8 = 8;

/// Generic netlink family version for `NET_DM` (family `.version = 2`).
const NET_DM_GENL_VERSION: u8 = 2;

// ---------------------------------------------------------------------------
// NET_DM attribute types — from uapi/linux/net_dropmon.h (enum net_dm_attr).
// ---------------------------------------------------------------------------

/// `NET_DM_ATTR_ALERT_MODE` (u8): summary=0, packet=1.
const NET_DM_ATTR_ALERT_MODE: u16 = 1;
/// `NET_DM_ATTR_STATS` (nested): contains `NET_DM_ATTR_STATS_DROPPED`.
const NET_DM_ATTR_STATS: u16 = 12;
/// `NET_DM_ATTR_HW_STATS` (nested): contains `NET_DM_ATTR_STATS_DROPPED`.
const NET_DM_ATTR_HW_STATS: u16 = 13;

// ---------------------------------------------------------------------------
// NET_DM inner stats attributes — from uapi/linux/net_dropmon.h
// (enum starting at 0: NET_DM_ATTR_STATS_DROPPED = 0, but the first enum
// member is actually 0=DROPPED when counting from 0).
//
// The kernel code:
//   attr = nla_nest_start(msg, NET_DM_ATTR_STATS);
//   nla_put_u64_64bit(msg, NET_DM_ATTR_STATS_DROPPED, dropped, NET_DM_ATTR_PAD)
//
// `NET_DM_ATTR_STATS_DROPPED` is type 0 inside the nested STATS container
// (it is the first value in its own enum starting at 0).
// ---------------------------------------------------------------------------

/// `NET_DM_ATTR_STATS_DROPPED` (u64) — inner attr type 0 inside the STATS/HW_STATS nested.
const NET_DM_ATTR_STATS_DROPPED: u16 = 0;

/// Summary alert mode (kernel: `NET_DM_ALERT_MODE_SUMMARY = 0`).
///
/// From uapi/linux/net_dropmon.h:
/// ```c
/// enum net_dm_alert_mode {
///     NET_DM_ALERT_MODE_SUMMARY,   // = 0
///     NET_DM_ALERT_MODE_PACKET,    // = 1
/// };
/// ```
const NET_DM_ALERT_MODE_SUMMARY: u8 = 0;

/// Kernel errno `EBUSY` (16) — returned when `NET_DM_CMD_CONFIG` is sent while
/// monitoring is already active, or when `NET_DM_CMD_START` is called again.
/// Safe to ignore; the monitoring session started by a previous call is reused.
const EBUSY: i32 = 16;

/// Kernel errno `EALREADY` (114) — alternative "already monitoring" error on
/// some kernel versions.
const EALREADY: i32 = 114;

/// Kernel errno `EAGAIN` (11) — returned by `set_all_monitor_traces()` when the
/// trace state already equals the requested value (kernel:
/// "Trace state is already set to the requested value",
/// `net/core/drop_monitor.c:1227`). This is the actual error `NET_DM_CMD_START`
/// returns on the second and subsequent scrapes — NOT `EBUSY`/`EALREADY`. Safe
/// to ignore: monitoring is already active, which is the desired outcome.
const EAGAIN: i32 = 11;

// ---------------------------------------------------------------------------
// Public collector struct
// ---------------------------------------------------------------------------

/// Adapter implementing [`NetlinkDropMonitorPort`] and [`Collector`] for
/// drop-monitor aggregate statistics.
///
/// Uses `NET_DM_CMD_STATS_GET` per scrape (unicast pull). No background task,
/// no `Mutex`, no `Arc` — the collector itself is a zero-sized unit struct.
pub struct DropMonitorCollector;

// ---------------------------------------------------------------------------
// NetlinkDropMonitorPort implementation
// ---------------------------------------------------------------------------

impl NetlinkDropMonitorPort for DropMonitorCollector {
    async fn dump_drop_events(&self) -> Result<Vec<DropEvent>, DomainError> {
        let mut sock = NetlinkSocket::open(NETLINK_GENERIC)
            .map_err(|e| DomainError::Collector(e.to_string()))?;

        let Some(family_id) = sock
            .resolve_genl_family("NET_DM")
            .await
            .map_err(|e| DomainError::Collector(e.to_string()))?
        else {
            debug!("NET_DM genetlink family not loaded");
            return Ok(vec![]);
        };

        // Ensure monitoring is active before querying stats.
        start_monitoring(&mut sock, family_id)
            .await
            .map_err(|e| DomainError::Collector(e.to_string()))?;

        fetch_stats(&mut sock, family_id)
            .await
            .map_err(|e| DomainError::Collector(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Collector implementation
// ---------------------------------------------------------------------------

impl Collector for DropMonitorCollector {
    fn name(&self) -> &str {
        "drop_monitor"
    }

    fn collect(&self) -> BoxFuture<'_, Result<Vec<MetricSample>, CollectError>> {
        Box::pin(async move {
            let mut sock = NetlinkSocket::open(NETLINK_GENERIC)
                .map_err(|e| CollectError::Io(e.to_string()))?;

            let Some(family_id) = sock
                .resolve_genl_family("NET_DM")
                .await
                .map_err(|e| CollectError::Io(e.to_string()))?
            else {
                debug!("NET_DM genetlink family not loaded; skipping collect");
                return Ok(vec![]);
            };

            // Start monitoring (idempotent — EBUSY/EALREADY silently ignored).
            start_monitoring(&mut sock, family_id)
                .await
                .map_err(|e| CollectError::Io(e.to_string()))?;

            // Pull aggregate statistics via NET_DM_CMD_STATS_GET.
            let events = fetch_stats(&mut sock, family_id)
                .await
                .map_err(|e| CollectError::Io(e.to_string()))?;

            let mut out = Vec::with_capacity(events.len());
            for ev in events {
                let mut labels = BTreeMap::new();
                labels.insert("origin".to_owned(), ev.origin);
                labels.insert("reason".to_owned(), ev.reason);
                out.push(MetricSample::counter(
                    "nft_drop_packets_total",
                    "Kernel drop-monitor aggregated packet drops (NET_DM_CMD_STATS_GET).",
                    labels,
                    ev.dropped,
                ));
            }
            Ok(out)
        })
    }

    fn probe_available(&self) -> BoxFuture<'_, bool> {
        Box::pin(async move {
            let Ok(mut sock) = NetlinkSocket::open(NETLINK_GENERIC) else {
                return false;
            };
            matches!(sock.resolve_genl_family("NET_DM").await, Ok(Some(_)))
        })
    }
}

// ---------------------------------------------------------------------------
// Wire helpers
// ---------------------------------------------------------------------------

/// Build a 4-byte `genlmsghdr` prefix: `cmd`, `version=NET_DM_GENL_VERSION`, 2×reserved.
fn genl_hdr(cmd: u8) -> [u8; 4] {
    [cmd, NET_DM_GENL_VERSION, 0u8, 0u8]
}

/// Append one `nlattr` TLV to `buf`.
fn push_nla(buf: &mut Vec<u8>, ty: u16, payload: &[u8]) {
    let nla_len = (NLA_HDRLEN + payload.len()) as u16;
    buf.extend_from_slice(&nla_len.to_ne_bytes());
    buf.extend_from_slice(&ty.to_ne_bytes());
    buf.extend_from_slice(payload);
    let pad = align4(NLA_HDRLEN + payload.len()) - (NLA_HDRLEN + payload.len());
    buf.extend(std::iter::repeat_n(0u8, pad));
}

// ---------------------------------------------------------------------------
// Protocol operations
// ---------------------------------------------------------------------------

/// Send `NET_DM_CMD_CONFIG` (summary mode) then `NET_DM_CMD_START`.
///
/// Both commands require `CAP_NET_ADMIN`. Kernel errors `EBUSY` (16, CONFIG
/// while monitoring), `EAGAIN` (11, START when trace state already ON), and
/// `EALREADY` (114) are silently ignored — they all indicate monitoring is
/// already active, which is the desired outcome on every scrape after the first.
///
/// `NLM_F_ACK` (flag value 4) is OR-d into the flags by `request_single` on
/// top of `NLM_F_REQUEST`.  This ensures the kernel sends an acknowledgment
/// frame so the call site can confirm the command was accepted.
async fn start_monitoring(
    sock: &mut NetlinkSocket,
    family_id: u16,
) -> Result<(), crate::transport::NetlinkError> {
    use crate::transport::NetlinkError;

    // --- NET_DM_CMD_CONFIG: set SUMMARY alert mode ---
    // Payload: genlmsghdr(cmd=2,ver=2) + NLA(ALERT_MODE=0).
    let mut config_payload = genl_hdr(NET_DM_CMD_CONFIG).to_vec();
    push_nla(&mut config_payload, NET_DM_ATTR_ALERT_MODE, &[NET_DM_ALERT_MODE_SUMMARY]);

    // NLM_F_ACK = 4 so the kernel sends an ack/err frame we can read.
    match sock.request_single(family_id, 4, &config_payload).await {
        Ok(_) => {}
        Err(NetlinkError::KernelError { errno })
            if errno == EBUSY || errno == EALREADY || errno == EAGAIN =>
        {
            // Monitoring already active — CONFIG is rejected while monitoring is
            // running (kernel: "Cannot configure drop monitor during monitoring").
            // This is expected on the second and subsequent scrapes.
            debug!(errno, "NET_DM_CMD_CONFIG EBUSY/EALREADY/EAGAIN — monitoring already active");
        }
        Err(e) => return Err(e),
    }

    // --- NET_DM_CMD_START: enable SW monitoring ---
    // No extra attrs → kernel defaults to software-drops-only (backward compat).
    let start_payload = genl_hdr(NET_DM_CMD_START).to_vec();
    match sock.request_single(family_id, 4, &start_payload).await {
        Ok(_) => {}
        Err(NetlinkError::KernelError { errno })
            if errno == EBUSY || errno == EALREADY || errno == EAGAIN =>
        {
            debug!(errno, "NET_DM_CMD_START EBUSY/EALREADY/EAGAIN — already monitoring");
        }
        Err(e) => return Err(e),
    }

    Ok(())
}

/// Issue `NET_DM_CMD_STATS_GET` and parse the `NET_DM_CMD_STATS_NEW` reply.
///
/// The reply contains two nested attrs:
///
/// - `NET_DM_ATTR_STATS`    (type=12) → `NET_DM_ATTR_STATS_DROPPED` (type=0, u64) — SW total
/// - `NET_DM_ATTR_HW_STATS` (type=13) → `NET_DM_ATTR_STATS_DROPPED` (type=0, u64) — HW total
///
/// Both are returned as [`DropEvent`] entries with `origin="sw"/"hw"` and
/// `reason="total"`.
///
/// # Wire format
///
/// ```text
/// nlmsghdr (16 B)
///   └── genlmsghdr (4 B): cmd=NET_DM_CMD_STATS_NEW, ver=2
///         └── nlattr: type=NET_DM_ATTR_STATS (12), NLA_F_NESTED
///               └── nlattr: type=NET_DM_ATTR_STATS_DROPPED (0), payload=u64 (8 B)
///         └── nlattr: type=NET_DM_ATTR_HW_STATS (13), NLA_F_NESTED
///               └── nlattr: type=NET_DM_ATTR_STATS_DROPPED (0), payload=u64 (8 B)
/// ```
async fn fetch_stats(
    sock: &mut NetlinkSocket,
    family_id: u16,
) -> Result<Vec<DropEvent>, crate::transport::NetlinkError> {
    // Payload: genlmsghdr(cmd=8, ver=2), no attrs.
    let stats_payload = genl_hdr(NET_DM_CMD_STATS_GET).to_vec();

    // NLM_F_REQUEST only (flag 0) — no dump, no ack needed; `request_single`
    // OR-s NLM_F_REQUEST automatically.  Pass flags=0 so we don't request an
    // explicit ack frame (the reply IS the response).
    let reply = sock.request_single(family_id, 0, &stats_payload).await?;

    let Some(payload) = reply else {
        warn!("NET_DM_CMD_STATS_GET returned empty reply");
        return Ok(vec![]);
    };

    // Skip genlmsghdr (4 bytes): cmd + version + reserved[2].
    if payload.len() < 4 {
        warn!(len = payload.len(), "NET_DM_CMD_STATS_GET reply too short for genlmsghdr");
        return Ok(vec![]);
    }
    let attrs_buf = &payload[4..];

    let mut sw_dropped: u64 = 0;
    let mut hw_dropped: u64 = 0;

    for attr in parse_attrs(attrs_buf) {
        match attr.ty {
            NET_DM_ATTR_STATS => {
                for inner in nested_attrs(attr.payload) {
                    if inner.ty == NET_DM_ATTR_STATS_DROPPED {
                        sw_dropped = read_u64(inner.payload).unwrap_or(0);
                    }
                }
            }
            NET_DM_ATTR_HW_STATS => {
                for inner in nested_attrs(attr.payload) {
                    if inner.ty == NET_DM_ATTR_STATS_DROPPED {
                        hw_dropped = read_u64(inner.payload).unwrap_or(0);
                    }
                }
            }
            _ => {}
        }
    }

    debug!(sw_dropped, hw_dropped, "NET_DM_CMD_STATS_GET parsed");

    Ok(vec![
        DropEvent {
            reason: "total".to_owned(),
            origin: "sw".to_owned(),
            dropped: sw_dropped,
        },
        DropEvent {
            reason: "total".to_owned(),
            origin: "hw".to_owned(),
            dropped: hw_dropped,
        },
    ])
}

// ---------------------------------------------------------------------------
// Parser for NET_DM_GRP_ALERT multicast frames (future use)
// ---------------------------------------------------------------------------

/// Parse one `NET_DM_CMD_ALERT` (summary-mode) or `NET_DM_CMD_PACKET_ALERT`
/// (packet-mode) frame payload (after `genlmsghdr`).
///
/// Summary-mode ALERT frames (`NET_DM_CMD_ALERT` = 1) carry a legacy
/// `net_dm_alert_msg` structure via `NLA_UNSPEC` plus optional `NET_DM_ATTR_HW_ENTRIES`
/// nested attrs for hardware drops.  They do NOT contain `NET_DM_ATTR_REASON`.
///
/// Packet-mode ALERT frames (`NET_DM_CMD_PACKET_ALERT` = 5) carry:
/// - `NET_DM_ATTR_ORIGIN` (u16): `0`=SW, `1`=HW
/// - `NET_DM_ATTR_REASON` (string, kernel ≥ 5.17): drop-reason name
/// - `NET_DM_ATTR_STATS` (nested): dropped count for this alert
/// - `NET_DM_ATTR_HW_TRAP_NAME` (string, HW only): hardware trap name
///
/// This function handles both; returns `None` when required fields are absent.
///
/// **Not called in the STATS_GET pull model.** Retained for the future multicast
/// subscriber integration (NET_DM_GRP_ALERT group, group index 1).
#[expect(dead_code, reason = "reserved for future NET_DM_GRP_ALERT multicast integration")]
pub(crate) fn parse_alert_frame(attrs_buf: &[u8]) -> Option<DropEvent> {
    // Attribute type constants used only in this function (from enum net_dm_attr).
    // Counting from UNSPEC=0: ORIGIN=14, HW_TRAP_NAME=16, REASON=23.
    const NET_DM_ATTR_ORIGIN: u16 = 14;
    const NET_DM_ATTR_HW_TRAP_NAME: u16 = 16;
    const NET_DM_ATTR_REASON: u16 = 23;
    const NET_DM_ORIGIN_SW: u16 = 0;

    let mut origin_raw: u16 = 0;
    let mut reason: Option<String> = None;
    let mut hw_trap: Option<String> = None;
    let mut dropped: u64 = 0;

    for attr in parse_attrs(attrs_buf) {
        match attr.ty {
            NET_DM_ATTR_ORIGIN => {
                origin_raw = crate::wire::read_u16(attr.payload).unwrap_or(0);
            }
            NET_DM_ATTR_REASON => {
                let end = attr
                    .payload
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(attr.payload.len());
                reason = Some(String::from_utf8_lossy(&attr.payload[..end]).into_owned());
            }
            NET_DM_ATTR_HW_TRAP_NAME => {
                let end = attr
                    .payload
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(attr.payload.len());
                hw_trap = Some(String::from_utf8_lossy(&attr.payload[..end]).into_owned());
            }
            NET_DM_ATTR_STATS => {
                for inner in nested_attrs(attr.payload) {
                    if inner.ty == NET_DM_ATTR_STATS_DROPPED {
                        dropped = dropped.saturating_add(read_u64(inner.payload).unwrap_or(0));
                    }
                }
            }
            _ => {}
        }
    }

    let origin_str = if origin_raw == NET_DM_ORIGIN_SW { "sw" } else { "hw" };

    let reason_str = if origin_raw == NET_DM_ORIGIN_SW {
        match reason {
            Some(r) => r,
            None => {
                // NET_DM_ATTR_REASON absent — summary-mode ALERT or kernel < 5.17.
                // Summary-mode ALERT frames carry per-PC drop counts in the legacy
                // net_dm_alert_msg struct (NLA_UNSPEC) without a reason string.
                warn!("NET_DM alert missing NET_DM_ATTR_REASON (summary-mode or kernel < 5.17)");
                return None;
            }
        }
    } else {
        hw_trap.unwrap_or_else(|| "unknown".to_owned())
    };

    Some(DropEvent {
        reason: reason_str,
        origin: origin_str.to_owned(),
        dropped,
    })
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{NLA_HDRLEN, align4};

    /// Build a minimal nlattr TLV.
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

    /// Build a nested nlattr: outer type wrapping an inner sequence.
    fn make_nested_nla(outer_ty: u16, inner: &[u8]) -> Vec<u8> {
        // NLA_F_NESTED = 0x8000 — mirrors what the kernel sends.
        make_nla(outer_ty | 0x8000, inner)
    }

    /// Synthesise a `NET_DM_CMD_STATS_NEW` reply payload (after nlmsghdr):
    /// genlmsghdr(4 B) + STATS nested + HW_STATS nested.
    fn make_stats_reply(sw: u64, hw: u64) -> Vec<u8> {
        // genlmsghdr: cmd=NET_DM_CMD_STATS_NEW(9), ver=2, reserved[2].
        let mut buf = vec![9u8, 2u8, 0u8, 0u8];

        // Inner STATS_DROPPED attr (type=0, u64).
        let inner_sw = make_nla(NET_DM_ATTR_STATS_DROPPED, &sw.to_ne_bytes());
        buf.extend_from_slice(&make_nested_nla(NET_DM_ATTR_STATS, &inner_sw));

        let inner_hw = make_nla(NET_DM_ATTR_STATS_DROPPED, &hw.to_ne_bytes());
        buf.extend_from_slice(&make_nested_nla(NET_DM_ATTR_HW_STATS, &inner_hw));

        buf
    }

    #[test]
    fn genl_hdr_bytes() {
        let hdr = genl_hdr(NET_DM_CMD_STATS_GET);
        assert_eq!(hdr[0], 8, "cmd must be NET_DM_CMD_STATS_GET");
        assert_eq!(hdr[1], NET_DM_GENL_VERSION, "version must be 2");
        assert_eq!(hdr[2], 0);
        assert_eq!(hdr[3], 0);
    }

    #[test]
    fn parse_stats_reply_sw_and_hw() {
        let reply = make_stats_reply(1234, 5678);
        // Simulate what fetch_stats does after receiving the reply.
        assert!(reply.len() >= 4, "reply must have genlmsghdr");
        let attrs_buf = &reply[4..];

        let mut sw_dropped = 0u64;
        let mut hw_dropped = 0u64;
        for attr in parse_attrs(attrs_buf) {
            match attr.ty {
                NET_DM_ATTR_STATS => {
                    for inner in nested_attrs(attr.payload) {
                        if inner.ty == NET_DM_ATTR_STATS_DROPPED {
                            sw_dropped = read_u64(inner.payload).unwrap_or(0);
                        }
                    }
                }
                NET_DM_ATTR_HW_STATS => {
                    for inner in nested_attrs(attr.payload) {
                        if inner.ty == NET_DM_ATTR_STATS_DROPPED {
                            hw_dropped = read_u64(inner.payload).unwrap_or(0);
                        }
                    }
                }
                _ => {}
            }
        }
        assert_eq!(sw_dropped, 1234, "SW dropped mismatch");
        assert_eq!(hw_dropped, 5678, "HW dropped mismatch");
    }

    #[test]
    fn parse_stats_reply_zeroes() {
        let reply = make_stats_reply(0, 0);
        let attrs_buf = &reply[4..];
        let mut sw = 0u64;
        let mut hw = 0u64;
        for attr in parse_attrs(attrs_buf) {
            match attr.ty {
                NET_DM_ATTR_STATS => {
                    for inner in nested_attrs(attr.payload) {
                        if inner.ty == NET_DM_ATTR_STATS_DROPPED {
                            sw = read_u64(inner.payload).unwrap_or(0);
                        }
                    }
                }
                NET_DM_ATTR_HW_STATS => {
                    for inner in nested_attrs(attr.payload) {
                        if inner.ty == NET_DM_ATTR_STATS_DROPPED {
                            hw = read_u64(inner.payload).unwrap_or(0);
                        }
                    }
                }
                _ => {}
            }
        }
        assert_eq!(sw, 0);
        assert_eq!(hw, 0);
    }

    #[test]
    fn parse_alert_frame_sw_with_reason() {
        // Packet-mode alert: ORIGIN=0(sw) + REASON="SKB_DROP_REASON_TCP_CSUM" + STATS.
        const NET_DM_ATTR_ORIGIN: u16 = 14;
        const NET_DM_ATTR_REASON: u16 = 23; // FLOW_ACTION_COOKIE=22, REASON=23

        let origin_bytes = 0u16.to_ne_bytes();
        let reason_str = b"SKB_DROP_REASON_TCP_CSUM\0";
        let dropped_bytes = 42u64.to_ne_bytes();
        let inner_dropped = make_nla(NET_DM_ATTR_STATS_DROPPED, &dropped_bytes);
        let stats_nla = make_nested_nla(NET_DM_ATTR_STATS, &inner_dropped);

        let mut buf = Vec::new();
        buf.extend_from_slice(&make_nla(NET_DM_ATTR_ORIGIN, &origin_bytes));
        buf.extend_from_slice(&make_nla(NET_DM_ATTR_REASON, reason_str));
        buf.extend_from_slice(&stats_nla);

        let ev = parse_alert_frame(&buf);
        assert!(ev.is_some(), "must parse a valid SW alert frame");
        let ev = ev.unwrap();
        assert_eq!(ev.origin, "sw");
        assert_eq!(ev.reason, "SKB_DROP_REASON_TCP_CSUM");
        assert_eq!(ev.dropped, 42);
    }

    #[test]
    fn parse_alert_frame_missing_reason_returns_none() {
        // SW origin but no REASON attr — must return None (summary mode or old kernel).
        const NET_DM_ATTR_ORIGIN: u16 = 14; // confirmed: ORIGIN is the 14th enum value
        let origin_bytes = 0u16.to_ne_bytes();
        let buf = make_nla(NET_DM_ATTR_ORIGIN, &origin_bytes);
        let ev = parse_alert_frame(&buf);
        assert!(ev.is_none(), "missing REASON for SW alert must yield None");
    }

    #[test]
    fn parse_alert_frame_hw_trap() {
        const NET_DM_ATTR_ORIGIN: u16 = 14;
        const NET_DM_ATTR_HW_TRAP_NAME: u16 = 16;

        let origin_bytes = 1u16.to_ne_bytes(); // HW
        let trap_name = b"blackhole\0";

        let mut buf = Vec::new();
        buf.extend_from_slice(&make_nla(NET_DM_ATTR_ORIGIN, &origin_bytes));
        buf.extend_from_slice(&make_nla(NET_DM_ATTR_HW_TRAP_NAME, trap_name));

        let ev = parse_alert_frame(&buf);
        assert!(ev.is_some());
        let ev = ev.unwrap();
        assert_eq!(ev.origin, "hw");
        assert_eq!(ev.reason, "blackhole");
        assert_eq!(ev.dropped, 0);
    }

    #[test]
    fn collector_name_is_drop_monitor() {
        assert_eq!(DropMonitorCollector.name(), "drop_monitor");
    }
}
