//! Conntrack expectations collector — `NETLINK_NETFILTER` (12).
//!
//! Subsystem: `NFNL_SUBSYS_CTNETLINK_EXP = 2`.
//!
//! ## Messages used
//!
//! | Message | `nlmsg_type` | Purpose |
//! |---|---|---|
//! | `IPCTNL_MSG_EXP_GET` | `0x0200` | Full expectation table dump |
//!
//! ## Metrics emitted
//!
//! | Metric | Type | Labels |
//! |---|---|---|
//! | `nft_conntrack_expectations` | gauge | (none) |
//!
//! The gauge counts the total number of active conntrack expectations.
//! Per-expectation IP/port details are discarded at parse time (ADR-0005).
//!
//! ## Graceful degradation
//!
//! When the kernel returns `ENOENT`, `EPERM`, or any socket error, the
//! collector marks itself unavailable and emits an empty metric set rather
//! than returning an error.  This is the §18.2 "runtime gate" behaviour.
//!
//! ## Wire format
//!
//! Each reply frame: `nlmsghdr` (16) + `nfgenmsg` (4) + nlattr chain.
//! The nlattr chain carries `CTA_EXPECT_*` attributes; we read only
//! `CTA_EXPECT_HELPER_NAME` and the `CTA_PROTO_NUM` inside
//! `CTA_EXPECT_TUPLE` for the `ConntrackExpectEntry` model.
//!
//! ADR refs: ADR-0011, ADR-0014, ADR-0005.

use std::collections::BTreeMap;

use tracing::{debug, warn};

use nlx_domain::{
    error::DomainError, metric::MetricSample, model::conntrack::ConntrackExpectEntry,
};
use nlx_ports::{
    collector::{BoxFuture, Collector},
    driven::NetlinkConntrackExpectPort,
    error::CollectError,
};

use crate::{
    transport::{MAX_DUMP_RESTARTS, NetlinkError, NetlinkSocket},
    wire::{nested_attrs, parse_attrs, read_u8},
};

// ---------------------------------------------------------------------------
// Wire constants
// ---------------------------------------------------------------------------

/// `NETLINK_NETFILTER` protocol number.
const NETLINK_NETFILTER: i32 = 12;

/// `nfgenmsg` header size.
const NFGENMSG_LEN: usize = 4;

// nlmsg_type: (NFNL_SUBSYS_CTNETLINK_EXP=2) << 8 | msg_type
const IPCTNL_MSG_EXP_GET: u16 = (2u16 << 8) | 0;

// CTA_EXPECT_* attribute types (effective, flags stripped)
const CTA_EXPECT_TUPLE: u16 = 2;
const CTA_EXPECT_HELPER_NAME: u16 = 6;

// Nested inside CTA_EXPECT_TUPLE
const CTA_TUPLE_PROTO: u16 = 2;
const CTA_PROTO_NUM: u16 = 1;

// ---------------------------------------------------------------------------
// nfgenmsg builder
// ---------------------------------------------------------------------------

/// 4-byte `nfgenmsg` with `AF_UNSPEC`, version 0, `res_id` 0.
fn nfgenmsg_unspec() -> [u8; 4] {
    [0u8, 0u8, 0u8, 0u8]
}

// ---------------------------------------------------------------------------
// L4 proto → string
// ---------------------------------------------------------------------------

fn proto_label(proto: u8) -> &'static str {
    match proto {
        6 => "tcp",
        17 => "udp",
        1 => "icmp",
        58 => "icmpv6",
        132 => "sctp",
        _ => "other",
    }
}

// ---------------------------------------------------------------------------
// Frame parser
// ---------------------------------------------------------------------------

/// NUL-terminator stripper for helper name.
fn strip_nul(payload: &[u8]) -> &[u8] {
    match payload.last() {
        Some(&0) => &payload[..payload.len().saturating_sub(1)],
        _ => payload,
    }
}

/// Parse one `IPCTNL_MSG_EXP_GET` reply frame into a `ConntrackExpectEntry`.
///
/// `frame` starts at nfgenmsg (4 bytes); nlattr chain at offset 4.
/// Per-connection IP/port data inside the nested tuples is discarded (ADR-0005).
fn parse_expect_frame(frame: &[u8]) -> Option<ConntrackExpectEntry> {
    if frame.len() < NFGENMSG_LEN {
        return None;
    }

    let attrs_buf = &frame[NFGENMSG_LEN..];
    let mut l4proto: u8 = 0;
    let mut helper = String::new();

    for attr in parse_attrs(attrs_buf) {
        match attr.ty {
            CTA_EXPECT_TUPLE => {
                // Nested: extract proto number from CTA_TUPLE_PROTO → CTA_PROTO_NUM.
                // IP addresses inside the tuple are discarded (ADR-0005).
                for inner in nested_attrs(attr.payload) {
                    if inner.ty == CTA_TUPLE_PROTO {
                        for proto_attr in nested_attrs(inner.payload) {
                            if proto_attr.ty == CTA_PROTO_NUM {
                                l4proto = read_u8(proto_attr.payload).unwrap_or(0);
                            }
                        }
                    }
                }
            }
            CTA_EXPECT_HELPER_NAME => {
                // NUL-terminated ASCII; truncate to 64 bytes (§18.2).
                let trimmed = strip_nul(attr.payload);
                let capped = &trimmed[..trimmed.len().min(64)];
                helper = String::from_utf8_lossy(capped).into_owned();
            }
            _ => {
                // All other attributes (CTA_EXPECT_MASTER, CTA_EXPECT_MASK,
                // CTA_EXPECT_TIMEOUT, CTA_EXPECT_ID, CTA_EXPECT_ZONE,
                // CTA_EXPECT_FLAGS, CTA_EXPECT_CLASS) are discarded per §18.4.
            }
        }
    }

    Some(ConntrackExpectEntry {
        l4proto: proto_label(l4proto).to_owned(),
        helper,
    })
}

// ---------------------------------------------------------------------------
// Dump helper
// ---------------------------------------------------------------------------

/// Issue `IPCTNL_MSG_EXP_GET` dump and return parsed expectations.
///
/// Returns `Ok(None)` when the kernel signals the subsystem is absent
/// (ENOENT or EPERM).  Any other error is propagated.
///
/// # Errors
///
/// Returns [`NetlinkError`] on socket I/O failures unrelated to availability.
async fn dump_expectations_raw(
    sock: &mut NetlinkSocket,
) -> Result<Option<Vec<ConntrackExpectEntry>>, NetlinkError> {
    let payload = nfgenmsg_unspec();
    let mut restarts: u32 = 0;

    let frames = loop {
        match sock.dump(IPCTNL_MSG_EXP_GET, 0, &payload).await {
            Ok(f) => break f,
            Err(NetlinkError::DumpIntr) if restarts < MAX_DUMP_RESTARTS => {
                restarts = restarts.saturating_add(1);
                warn!(restart = restarts, "expect dump interrupted; retrying");
            }
            // §18.2 runtime gate: ENOENT or EPERM → unavailable, not an error.
            Err(NetlinkError::KernelError { errno }) if errno == 2 || errno == 1 => {
                debug!(errno, "IPCTNL_MSG_EXP_GET: subsystem unavailable");
                return Ok(None);
            }
            Err(e) => return Err(e),
        }
    };

    debug!(frames = frames.len(), "IPCTNL_MSG_EXP_GET frames");

    // Cardinality guard: cap at 256 distinct (l4proto, helper) keys (§18.2).
    let mut entries: Vec<ConntrackExpectEntry> = Vec::new();
    let mut key_count: usize = 0;
    const CARDINALITY_CAP: usize = 256;

    for frame in &frames {
        if key_count >= CARDINALITY_CAP {
            warn!("conntrack_expect: cardinality cap reached; truncating");
            break;
        }
        if let Some(entry) = parse_expect_frame(frame) {
            entries.push(entry);
            key_count = key_count.saturating_add(1);
        }
    }

    Ok(Some(entries))
}

// ---------------------------------------------------------------------------
// ConntrackExpectCollector
// ---------------------------------------------------------------------------

/// Adapter implementing [`NetlinkConntrackExpectPort`] and [`Collector`] for
/// conntrack expectations.
///
/// Degrades gracefully when the kernel subsystem is absent.
pub struct ConntrackExpectCollector;

impl NetlinkConntrackExpectPort for ConntrackExpectCollector {
    async fn dump_expectations(&self) -> Result<Vec<ConntrackExpectEntry>, DomainError> {
        let mut sock = NetlinkSocket::open(NETLINK_NETFILTER)
            .map_err(|e| DomainError::Collector(e.to_string()))?;

        match dump_expectations_raw(&mut sock).await {
            Ok(Some(entries)) => Ok(entries),
            Ok(None) => Ok(vec![]), // graceful — subsystem absent
            Err(e) => Err(DomainError::Collector(e.to_string())),
        }
    }
}

impl Collector for ConntrackExpectCollector {
    fn name(&self) -> &str {
        "conntrack_expect"
    }

    fn collect(&self) -> BoxFuture<'_, Result<Vec<MetricSample>, CollectError>> {
        Box::pin(async move {
            let mut sock = match NetlinkSocket::open(NETLINK_NETFILTER) {
                Ok(s) => s,
                Err(_) => {
                    // Socket open failure → treat as unavailable, return empty.
                    return Ok(vec![]);
                }
            };

            let entries = match dump_expectations_raw(&mut sock).await {
                Ok(Some(e)) => e,
                Ok(None) => {
                    // Kernel subsystem absent — emit nothing gracefully.
                    return Ok(vec![]);
                }
                Err(NetlinkError::DumpIntr) => return Err(CollectError::DumpIntr),
                Err(NetlinkError::RecvBufOverflow) => {
                    return Err(CollectError::RecvBufOverflow);
                }
                Err(e) => return Err(CollectError::Io(e.to_string())),
            };

            let count = entries.len();

            let empty_labels: BTreeMap<String, String> = BTreeMap::new();
            Ok(vec![MetricSample::gauge(
                "nft_conntrack_expectations",
                "Number of active conntrack expectations.",
                empty_labels,
                count as f64,
            )])
        })
    }

    fn probe_available(&self) -> BoxFuture<'_, bool> {
        Box::pin(async move {
            // Probe: open socket and attempt a dump.
            // ENOENT/EPERM → false (graceful); other errors → false; success → true.
            let sock = match NetlinkSocket::open(NETLINK_NETFILTER) {
                Ok(s) => s,
                Err(_) => return false,
            };
            let mut sock = sock;
            let payload = nfgenmsg_unspec();
            match sock.dump(IPCTNL_MSG_EXP_GET, 0, &payload).await {
                Ok(_) => true,
                Err(NetlinkError::KernelError { errno }) if errno == 2 || errno == 1 => false,
                Err(_) => false,
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{NLA_HDRLEN, align4};

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

    /// Build a minimal CTA_EXPECT_TUPLE nested attr with CTA_PROTO_NUM.
    fn make_tuple_attr(proto: u8) -> Vec<u8> {
        // innermost: CTA_PROTO_NUM
        let proto_num_nla = make_nla(CTA_PROTO_NUM, &[proto]);
        // middle: CTA_TUPLE_PROTO containing CTA_PROTO_NUM
        let tuple_proto_nla = make_nla(CTA_TUPLE_PROTO, &proto_num_nla);
        // outer: CTA_EXPECT_TUPLE containing CTA_TUPLE_PROTO
        make_nla(CTA_EXPECT_TUPLE, &tuple_proto_nla)
    }

    fn make_helper_attr(name: &str) -> Vec<u8> {
        let mut payload = name.as_bytes().to_vec();
        payload.push(0u8);
        make_nla(CTA_EXPECT_HELPER_NAME, &payload)
    }

    #[test]
    fn parse_expect_frame_extracts_proto_and_helper() {
        let mut frame = vec![0u8, 0u8, 0u8, 0u8]; // nfgenmsg
        frame.extend_from_slice(&make_tuple_attr(6)); // TCP
        frame.extend_from_slice(&make_helper_attr("ftp"));

        let entry = parse_expect_frame(&frame).expect("should parse");
        assert_eq!(entry.l4proto, "tcp");
        assert_eq!(entry.helper, "ftp");
    }

    #[test]
    fn parse_expect_frame_unknown_proto() {
        let mut frame = vec![0u8, 0u8, 0u8, 0u8];
        frame.extend_from_slice(&make_tuple_attr(99)); // unknown → "other"

        let entry = parse_expect_frame(&frame).expect("should parse");
        assert_eq!(entry.l4proto, "other");
    }

    #[test]
    fn parse_expect_frame_too_short_returns_none() {
        assert!(parse_expect_frame(&[0u8; 3]).is_none());
    }

    #[test]
    fn strip_nul_removes_trailing_nul() {
        assert_eq!(strip_nul(b"ftp\0"), b"ftp");
        assert_eq!(strip_nul(b"ftp"), b"ftp");
        assert_eq!(strip_nul(b""), b"");
    }

    #[test]
    fn proto_label_coverage() {
        assert_eq!(proto_label(6), "tcp");
        assert_eq!(proto_label(17), "udp");
        assert_eq!(proto_label(1), "icmp");
        assert_eq!(proto_label(0), "other");
    }

    #[test]
    fn nfgenmsg_unspec_correct() {
        let m = nfgenmsg_unspec();
        assert_eq!(m, [0u8, 0u8, 0u8, 0u8]);
    }
}
