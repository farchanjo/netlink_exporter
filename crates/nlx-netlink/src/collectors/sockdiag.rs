//! Socket-diagnostics collector.
//!
//! Netlink family: `NETLINK_SOCK_DIAG` (4).
//! Messages used: `SOCK_DIAG_BY_FAMILY` (20) with `inet_diag_req_v2` for
//! `AF_INET` + `AF_INET6`, `IPPROTO_TCP` + `IPPROTO_UDP`.
//!
//! Wire reference: netlink-protocol.md §6.
//! ADR refs: ADR-0011, ADR-0014.
//!
//! ## Metrics produced
//!
//! | Metric | Labels | Type |
//! |--------|--------|------|
//! | `nft_socket_count` | `{protocol, state}` | gauge |
//! | `nft_socket_receive_queue_bytes` | `{protocol, state}` | gauge |
//! | `nft_socket_send_queue_bytes` | `{protocol, state}` | gauge |
//! | `nft_socket_drops_total` | `{protocol}` | counter |
//! | `nft_socket_retransmits_total` | `{protocol="tcp"}` | counter |

use std::collections::BTreeMap;

use nlx_domain::{error::DomainError, metric::MetricSample, model::sockdiag::SockDiagEntry};
use nlx_ports::{
    collector::{BoxFuture, Collector},
    driven::NetlinkSockDiagPort,
    error::CollectError,
};
use tracing::debug;

use crate::transport::{MAX_DUMP_RESTARTS, NetlinkError, NetlinkSocket};

// ---------------------------------------------------------------------------
// Wire constants (netlink-protocol.md §6)
// ---------------------------------------------------------------------------

/// `NETLINK_SOCK_DIAG` protocol constant (ADR-0011 §socket model).
const NETLINK_SOCK_DIAG: i32 = 4;

/// `SOCK_DIAG_BY_FAMILY` — `msg_type` for `inet_diag` requests.
/// kernel: `include/uapi/linux/sock_diag.h`.
const SOCK_DIAG_BY_FAMILY: u16 = 20;

/// `inet_diag_req_v2` size: 56 bytes.
/// Layout: `sdiag_family(1)` + `sdiag_protocol(1)` + `idiag_ext(1)` + pad(1)
///       + `idiag_states(4)` + `inet_diag_sockid(48)` = 56.
const INET_DIAG_REQ_V2_LEN: usize = 56;

/// Address families (netlink-protocol.md §6.5).
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

/// IP protocols.
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

/// `idiag_ext` bitmask: request `INET_DIAG_SKMEMINFO` (bit 6 = 0x40, i.e.
/// `1 << (INET_DIAG_SKMEMINFO - 1)` = `1 << 6`) +
/// `INET_DIAG_INFO` (bit 1 = 0x02, i.e. `1 << (INET_DIAG_INFO - 1)` = `1 << 1`).
/// Combined = 0x42 per §6.1.
/// kernel: `include/uapi/linux/inet_diag.h` enum, line 134–143
///   (`INET_DIAG_NONE=0`, `INET_DIAG_MEMINFO=1`, `INET_DIAG_INFO=2`, …,
///    `INET_DIAG_TCLASS=6`, `INET_DIAG_SKMEMINFO=7`).
const IDIAG_EXT_SKMEMINFO_AND_INFO: u8 = 0x42;

/// Request all socket states.
const IDIAG_STATES_ALL: u32 = 0xFFFF_FFFF;

/// `inet_diag_msg` minimum size: 72 bytes.
const INET_DIAG_MSG_MIN: usize = 72;

/// `inet_diag_msg.idiag_state` offset: 1.
const IDIAG_STATE_OFFSET: usize = 1;

/// `inet_diag_msg.idiag_rqueue` offset: 56.
const IDIAG_RQUEUE_OFFSET: usize = 56;

/// `inet_diag_msg.idiag_wqueue` offset: 60.
const IDIAG_WQUEUE_OFFSET: usize = 60;

/// nlattr types in a `sock_diag` reply (netlink-protocol.md §6.3, §6.4).
/// `INET_DIAG_INFO` `nla_type` = 2.
/// kernel: `include/uapi/linux/inet_diag.h` line 137.
const INET_DIAG_INFO: u16 = 2;
/// `INET_DIAG_SKMEMINFO` `nla_type` = 7.
/// kernel: `include/uapi/linux/inet_diag.h` line 142
///   (`INET_DIAG_NONE=0` … `INET_DIAG_TCLASS=6`, `INET_DIAG_SKMEMINFO=7`).
/// WC-006 fix: was incorrectly 6 (`INET_DIAG_TCLASS`).
const INET_DIAG_SKMEMINFO: u16 = 7;

/// Byte offset of `skmem_drop` within `INET_DIAG_SKMEMINFO` payload
/// (index 8, byte offset 32). See §6.3 / gotcha G-13.
const SKMEMINFO_DROP_OFFSET: usize = 32;

/// Byte offset of `tcpi_total_retrans` within `INET_DIAG_INFO` / `tcp_info`
/// payload (§6.4 / gotcha G-14).
///
/// `struct tcp_info` layout (kernel `include/uapi/linux/tcp.h` line 229):
///   offset 0–7:   8 × u8 fields (`tcpi_state` … `tcpi_delivery_rate_app_limited`)
///   offset 8:     `tcpi_rto`     (u32)
///   offset 12:    `tcpi_ato`     (u32)  ← old (wrong) offset read `tcpi_ato`
///   offset 16:    `tcpi_snd_mss` (u32)
///   offset 20:    `tcpi_rcv_mss` (u32)
///   offset 24:    `tcpi_unacked` (u32)
///   offset 28:    `tcpi_sacked`  (u32)
///   offset 32:    `tcpi_lost`    (u32)
///   offset 36:    `tcpi_retrans` (u32)
///   offset 40:    `tcpi_fackets` (u32)
///   offset 44:    `tcpi_last_data_sent` (u32)
///   offset 48:    `tcpi_last_ack_sent`  (u32)
///   offset 52:    `tcpi_last_data_recv` (u32)
///   offset 56:    `tcpi_last_ack_recv`  (u32)
///   offset 60:    `tcpi_pmtu`           (u32)
///   offset 64:    `tcpi_rcv_ssthresh`   (u32)
///   offset 68:    `tcpi_rtt`            (u32)
///   offset 72:    `tcpi_rttvar`         (u32)
///   offset 76:    `tcpi_snd_ssthresh`   (u32)
///   offset 80:    `tcpi_snd_cwnd`       (u32)
///   offset 84:    `tcpi_advmss`         (u32)
///   offset 88:    `tcpi_reordering`     (u32)
///   offset 92:    `tcpi_rcv_rtt`        (u32)
///   offset 96:    `tcpi_rcv_space`      (u32)
///   offset 100:   `tcpi_total_retrans`  (u32)  ← cumulative retransmit counter
///
/// TC-004 fix: the metric `nft_socket_retransmits_total` is a *cumulative*
/// counter; the correct field is `tcpi_total_retrans` (u32 @ offset 100),
/// not `tcpi_retransmits` (u8 @ offset 2, current in-flight only) and not
/// `tcpi_ato` (u32 @ offset 12, ACK timeout).
const TCP_INFO_TOTAL_RETRANS_OFFSET: usize = 100;

// ---------------------------------------------------------------------------
// Internal aggregation key
// ---------------------------------------------------------------------------

/// Bounded cardinality key for socket count accumulation.
///
/// Family is intentionally dropped before forming this key (§6.5):
/// "Do not distinguish IPv4 from IPv6 at the metric level".
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct SockKey {
    protocol: Protocol,
    state: SocketState,
}

/// Supported protocols (bounded enum — no per-protocol label cardinality).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// TCP states (RFC 793) + UDP pseudo-state.
///
/// Kernel encodes state in `inet_diag_msg.idiag_state` as a `u8`.
/// For UDP sockets the kernel always returns `TCP_CLOSE (7)` which we map
/// to `"unconnected"` per gotcha G-12.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum SocketState {
    Established,
    SynSent,
    SynRecv,
    FinWait1,
    FinWait2,
    TimeWait,
    Close,
    CloseWait,
    LastAck,
    Listen,
    Closing,
    NewSynRecv,
    /// UDP-only pseudo-state (maps from `idiag_state=7` for UDP). G-12.
    Unconnected,
    /// Unknown kernel state value — bounded bucket for future-proofing.
    Other(u8),
}

impl SocketState {
    /// Map kernel `idiag_state` to a [`SocketState`].
    ///
    /// `is_udp = true` causes state 7 (`TCP_CLOSE`) to map to `Unconnected`
    /// instead of `Close` (gotcha G-12).
    fn from_kernel(state: u8, is_udp: bool) -> Self {
        match state {
            1 => Self::Established,
            2 => Self::SynSent,
            3 => Self::SynRecv,
            4 => Self::FinWait1,
            5 => Self::FinWait2,
            6 => Self::TimeWait,
            7 if is_udp => Self::Unconnected, // G-12: UDP never "close"
            7 => Self::Close,
            8 => Self::CloseWait,
            9 => Self::LastAck,
            10 => Self::Listen,
            11 => Self::Closing,
            12 => Self::NewSynRecv,
            other => Self::Other(other),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Established => "established",
            Self::SynSent => "syn_sent",
            Self::SynRecv => "syn_recv",
            Self::FinWait1 => "fin_wait1",
            Self::FinWait2 => "fin_wait2",
            Self::TimeWait => "time_wait",
            Self::Close => "close",
            Self::CloseWait => "close_wait",
            Self::LastAck => "last_ack",
            Self::Listen => "listen",
            Self::Closing => "closing",
            Self::NewSynRecv => "new_syn_recv",
            Self::Unconnected => "unconnected",
            Self::Other(_) => "other",
        }
    }
}

// ---------------------------------------------------------------------------
// Per-bucket accumulator
// ---------------------------------------------------------------------------

/// Accumulated statistics per `(protocol, state)` bucket.
#[derive(Debug, Default)]
struct Bucket {
    count: u64,
    rqueue: u64,
    wqueue: u64,
}

// ---------------------------------------------------------------------------
// Collector implementation
// ---------------------------------------------------------------------------

/// Adapter implementing [`NetlinkSockDiagPort`] and [`Collector`] for
/// socket diagnostics via `NETLINK_SOCK_DIAG` (protocol 4).
///
/// Issues four dump requests per scrape (`AF_INET×{TCP,UDP`} and
/// `AF_INET6×{TCP,UDP`}) and aggregates counts by `(protocol, state)`.
pub struct SockDiagCollector;

impl NetlinkSockDiagPort for SockDiagCollector {
    async fn dump_sockets(&self) -> Result<Vec<SockDiagEntry>, DomainError> {
        // The Collector::collect path is the sole consumer; this port method
        // is provided for completeness but returns an empty vec since the
        // domain model is not used in the direct-aggregation path.
        Ok(Vec::new())
    }
}

impl Collector for SockDiagCollector {
    fn name(&self) -> &'static str {
        "sock_diag"
    }

    fn collect(&self) -> BoxFuture<'_, Result<Vec<MetricSample>, CollectError>> {
        Box::pin(async move { collect_sockdiag().await })
    }

    fn probe_available(&self) -> BoxFuture<'_, bool> {
        Box::pin(async move {
            // Availability probe: try to open the NETLINK_SOCK_DIAG socket.
            match NetlinkSocket::open(NETLINK_SOCK_DIAG) {
                Ok(_) => true,
                Err(e) => {
                    debug!(error = %e, "sock_diag probe: socket open failed");
                    false
                }
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Core collection logic
// ---------------------------------------------------------------------------

/// Collect socket diagnostics and produce `MetricSample`s.
#[allow(
    clippy::cast_precision_loss,
    reason = "metric gauge values are f64; precision loss on large counters is inherent to Prometheus exposition"
)]
async fn collect_sockdiag() -> Result<Vec<MetricSample>, CollectError> {
    let mut sock =
        NetlinkSocket::open(NETLINK_SOCK_DIAG).map_err(|e| CollectError::Io(e.to_string()))?;

    // Aggregation maps.
    // bucket_map: (protocol, state) → Bucket
    let mut bucket_map: BTreeMap<SockKey, Bucket> = BTreeMap::new();
    // drops per protocol (from INET_DIAG_SKMEMINFO index 8)
    let mut drops: BTreeMap<Protocol, u64> = BTreeMap::new();
    // retransmits (TCP only, from INET_DIAG_INFO / tcp_info tcpi_total_retrans @ offset 100)
    let mut retransmits: u64 = 0;

    // Issue four dumps: AF_INET×TCP, AF_INET×UDP, AF_INET6×TCP, AF_INET6×UDP.
    for &family in &[AF_INET, AF_INET6] {
        for &(proto, protocol) in &[(IPPROTO_TCP, Protocol::Tcp), (IPPROTO_UDP, Protocol::Udp)] {
            let frames = dump_one_family(&mut sock, family, proto)
                .await
                .map_err(|e| match e {
                    NetlinkError::DumpIntr => CollectError::DumpIntr,
                    NetlinkError::RecvBufOverflow => CollectError::RecvBufOverflow,
                    other => CollectError::Io(other.to_string()),
                })?;

            let is_udp = protocol == Protocol::Udp;
            for frame in &frames {
                parse_frame(
                    frame,
                    protocol,
                    is_udp,
                    &mut bucket_map,
                    &mut drops,
                    &mut retransmits,
                )
                .map_err(CollectError::Parse)?;
            }
        }
    }

    // Build MetricSamples.
    let mut samples = Vec::new();

    // nft_socket_count / nft_socket_receive_queue_bytes / nft_socket_send_queue_bytes
    for (key, bucket) in &bucket_map {
        let proto_str = key.protocol.as_str();
        let state_str = key.state.as_str();

        let mut lc = BTreeMap::new();
        lc.insert("protocol".into(), proto_str.into());
        lc.insert("state".into(), state_str.into());

        samples.push(MetricSample::gauge(
            "nft_socket_count",
            "Number of sockets by protocol and state",
            lc.clone(),
            bucket.count as f64,
        ));

        samples.push(MetricSample::gauge(
            "nft_socket_receive_queue_bytes",
            "Sum of receive queue bytes per socket bucket",
            lc.clone(),
            bucket.rqueue as f64,
        ));

        samples.push(MetricSample::gauge(
            "nft_socket_send_queue_bytes",
            "Sum of send queue bytes per socket bucket",
            lc,
            bucket.wqueue as f64,
        ));
    }

    // nft_socket_drops_total
    for (proto, drop_count) in &drops {
        let mut lc = BTreeMap::new();
        lc.insert("protocol".into(), proto.as_str().into());
        samples.push(MetricSample::counter(
            "nft_socket_drops_total",
            "Total socket drops from INET_DIAG_SKMEMINFO",
            lc,
            *drop_count,
        ));
    }

    // nft_socket_retransmits_total (TCP only)
    if retransmits > 0 || drops.contains_key(&Protocol::Tcp) {
        let mut lc = BTreeMap::new();
        lc.insert("protocol".into(), "tcp".into());
        samples.push(MetricSample::counter(
            "nft_socket_retransmits_total",
            "Total TCP cumulative retransmits from tcp_info",
            lc,
            retransmits,
        ));
    }

    Ok(samples)
}

/// Send a single `SOCK_DIAG_BY_FAMILY` dump and return the raw frame payloads
/// (each payload is the body after the `nlmsghdr`).
///
/// Retries up to `MAX_DUMP_RESTARTS` on `NLM_F_DUMP_INTR`.
async fn dump_one_family(
    sock: &mut NetlinkSocket,
    family: u8,
    proto: u8,
) -> crate::transport::Result<Vec<Vec<u8>>> {
    // Build inet_diag_req_v2 (56 bytes, native-endian per §10).
    let mut req = [0u8; INET_DIAG_REQ_V2_LEN];
    req[0] = family; // sdiag_family
    req[1] = proto; // sdiag_protocol
    req[2] = IDIAG_EXT_SKMEMINFO_AND_INFO; // idiag_ext
    req[3] = 0; // pad
    // idiag_states @ offset 4: u32 LE = 0xFFFFFFFF
    req[4..8].copy_from_slice(&IDIAG_STATES_ALL.to_le_bytes());
    // inet_diag_sockid @ offset 8..56 — all zero = full dump, no filter

    for attempt in 0..MAX_DUMP_RESTARTS {
        match sock.dump(SOCK_DIAG_BY_FAMILY, 0, &req).await {
            Ok(frames) => return Ok(frames),
            Err(NetlinkError::DumpIntr) => {
                debug!(
                    attempt,
                    family, proto, "SOCK_DIAG dump interrupted; retrying"
                );
            }
            Err(e) => return Err(e),
        }
    }

    Err(NetlinkError::DumpIntr)
}

/// Parse one `inet_diag_msg` frame and accumulate into the aggregation maps.
///
/// Returns `Err(String)` on a hard parse failure.  Silently skips frames that
/// are too short to contain the minimum fixed struct (defensive, not fatal).
fn parse_frame(
    frame: &[u8],
    protocol: Protocol,
    is_udp: bool,
    bucket_map: &mut BTreeMap<SockKey, Bucket>,
    drops: &mut BTreeMap<Protocol, u64>,
    retransmits: &mut u64,
) -> Result<(), String> {
    if frame.len() < INET_DIAG_MSG_MIN {
        // Silently skip — frame is too short to carry inet_diag_msg.
        // This can happen with malformed or truncated replies.
        return Ok(());
    }

    // idiag_state @ offset 1 (u8).
    let state = SocketState::from_kernel(frame[IDIAG_STATE_OFFSET], is_udp);

    // idiag_rqueue @ offset 56 (u32 LE) per §10.
    let rqueue = u64::from(u32::from_le_bytes(
        frame[IDIAG_RQUEUE_OFFSET..IDIAG_RQUEUE_OFFSET + 4]
            .try_into()
            .map_err(|_| "idiag_rqueue slice error".to_owned())?,
    ));

    // idiag_wqueue @ offset 60 (u32 LE).
    let wqueue = u64::from(u32::from_le_bytes(
        frame[IDIAG_WQUEUE_OFFSET..IDIAG_WQUEUE_OFFSET + 4]
            .try_into()
            .map_err(|_| "idiag_wqueue slice error".to_owned())?,
    ));

    // Accumulate into bucket.
    let bucket = bucket_map.entry(SockKey { protocol, state }).or_default();
    bucket.count += 1;
    bucket.rqueue += rqueue;
    bucket.wqueue += wqueue;

    // Parse nlattr chain that follows the fixed 72-byte inet_diag_msg.
    // The inet_diag_sockid embedded in the struct spans bytes 4..52;
    // total fixed struct = 72 bytes. nlattrs start at offset 72.
    let attr_buf = &frame[INET_DIAG_MSG_MIN..];

    for nla in crate::wire::parse_attrs(attr_buf) {
        match nla.ty {
            INET_DIAG_SKMEMINFO => {
                // 9 × u32 LE; skmem_drop at index 8 (offset 32). G-13.
                if nla.payload.len() >= SKMEMINFO_DROP_OFFSET + 4 {
                    let drop_val = u64::from(u32::from_le_bytes(
                        nla.payload[SKMEMINFO_DROP_OFFSET..SKMEMINFO_DROP_OFFSET + 4]
                            .try_into()
                            .map_err(|_| "skmem_drop slice error".to_owned())?,
                    ));
                    *drops.entry(protocol).or_insert(0) += drop_val;
                }
            }
            INET_DIAG_INFO if !is_udp => {
                // tcp_info blob; tcpi_total_retrans at offset 100 (u32 LE). G-14.
                // kernel: include/uapi/linux/tcp.h struct tcp_info line 269.
                if nla.payload.len() >= TCP_INFO_TOTAL_RETRANS_OFFSET + 4 {
                    let r = u64::from(u32::from_le_bytes(
                        nla.payload
                            [TCP_INFO_TOTAL_RETRANS_OFFSET..TCP_INFO_TOTAL_RETRANS_OFFSET + 4]
                            .try_into()
                            .map_err(|_| "tcp total_retrans slice error".to_owned())?,
                    ));
                    *retransmits += r;
                }
            }
            _ => {}
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests (TC-021)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::cast_possible_truncation,
        reason = "test"
    )]

    use std::collections::BTreeMap;

    use super::{
        Bucket, IDIAG_EXT_SKMEMINFO_AND_INFO, INET_DIAG_INFO, INET_DIAG_MSG_MIN,
        INET_DIAG_SKMEMINFO, TCP_INFO_TOTAL_RETRANS_OFFSET,
    };

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Build a minimal (72-byte) `inet_diag_msg` payload with `idiag_state=1`
    /// (ESTABLISHED) and the given rqueue/wqueue values.
    fn make_inet_diag_msg(rqueue: u32, wqueue: u32) -> Vec<u8> {
        let mut buf = vec![0u8; INET_DIAG_MSG_MIN];
        // offset 0: sdiag_family (AF_INET = 2)
        buf[0] = 2;
        // offset 1: idiag_state = TCP_ESTABLISHED = 1
        buf[1] = 1;
        // offset 56: idiag_rqueue (u32 LE)
        buf[56..60].copy_from_slice(&rqueue.to_le_bytes());
        // offset 60: idiag_wqueue (u32 LE)
        buf[60..64].copy_from_slice(&wqueue.to_le_bytes());
        buf
    }

    /// Build a 4-byte-aligned NLA header + payload.
    ///
    /// `nla_len` = 4 (header) + `payload.len()`.
    /// Wire layout: `nla_len` (u16 LE) | `nla_type` (u16 LE) | payload | padding.
    fn make_nla(nla_type: u16, payload: &[u8]) -> Vec<u8> {
        let nla_len = 4u16 + payload.len() as u16;
        let pad = (4 - (payload.len() % 4)) % 4;
        let mut buf = Vec::with_capacity(4 + payload.len() + pad);
        buf.extend_from_slice(&nla_len.to_le_bytes());
        buf.extend_from_slice(&nla_type.to_le_bytes());
        buf.extend_from_slice(payload);
        buf.extend(std::iter::repeat_n(0u8, pad));
        buf
    }

    /// Build a 9-element SKMEMINFO payload (9 × u32 LE), setting index `i` to `val`.
    fn make_skmeminfo_payload(index: usize, val: u32) -> Vec<u8> {
        let mut payload = vec![0u8; 9 * 4];
        payload[index * 4..index * 4 + 4].copy_from_slice(&val.to_le_bytes());
        payload
    }

    /// Build a `tcp_info`-shaped payload of `len` bytes, setting `tcpi_total_retrans`
    /// (offset 100, u32 LE) to `val`.
    fn make_tcp_info_payload(val: u32) -> Vec<u8> {
        // Minimum size to reach tcpi_total_retrans (offset 100) + 4 bytes = 104.
        let mut payload = vec![0u8; TCP_INFO_TOTAL_RETRANS_OFFSET + 4];
        payload[TCP_INFO_TOTAL_RETRANS_OFFSET..TCP_INFO_TOTAL_RETRANS_OFFSET + 4]
            .copy_from_slice(&val.to_le_bytes());
        payload
    }

    // -----------------------------------------------------------------------
    // WC-006 / WC-007: constant correctness
    // -----------------------------------------------------------------------

    /// `INET_DIAG_SKMEMINFO` must equal 7 (kernel `inet_diag.h` line 142).
    #[test]
    fn test_inet_diag_skmeminfo_ordinal() {
        assert_eq!(
            INET_DIAG_SKMEMINFO, 7,
            "WC-006: INET_DIAG_SKMEMINFO must be 7"
        );
    }

    /// `INET_DIAG_INFO` must equal 2 (kernel `inet_diag.h` line 137).
    #[test]
    fn test_inet_diag_info_ordinal() {
        assert_eq!(INET_DIAG_INFO, 2, "INET_DIAG_INFO must be 2");
    }

    /// `idiag_ext` bitmask: bit for SKMEMINFO = 1<<(7-1) = 0x40; INFO = 1<<(2-1) = 0x02.
    /// Combined = 0x42.  (WC-007)
    #[test]
    fn test_idiag_ext_bitmask() {
        let skmeminfo_bit: u8 = 1 << (INET_DIAG_SKMEMINFO as u8 - 1); // 0x40
        let info_bit: u8 = 1 << (INET_DIAG_INFO as u8 - 1); // 0x02
        assert_eq!(
            IDIAG_EXT_SKMEMINFO_AND_INFO,
            skmeminfo_bit | info_bit,
            "WC-007: ext bitmask must be 0x42"
        );
        assert_eq!(IDIAG_EXT_SKMEMINFO_AND_INFO, 0x42);
    }

    // -----------------------------------------------------------------------
    // TC-004: TCP_INFO_TOTAL_RETRANS_OFFSET
    // -----------------------------------------------------------------------

    /// The cumulative retransmit counter `tcpi_total_retrans` sits at byte
    /// offset 100 in `struct tcp_info`.
    ///
    /// Layout derivation (kernel tcp.h line 229):
    ///   8 u8 fields → 8 bytes (offsets 0–7)
    ///   `tcpi_rto` .. `tcpi_rcv_space`: 23 u32 fields × 4 = 92 bytes (offsets 8–99)
    ///   `tcpi_total_retrans`: u32 @ offset 100.
    #[test]
    fn test_tcp_info_total_retrans_offset() {
        assert_eq!(
            TCP_INFO_TOTAL_RETRANS_OFFSET, 100,
            "TC-004: tcpi_total_retrans must be at byte offset 100"
        );
    }

    // -----------------------------------------------------------------------
    // TC-021: parse_frame correctly reads skmem_drop and total_retrans
    // -----------------------------------------------------------------------

    /// Verify that `INET_DIAG_SKMEMINFO` NLA (type=7) with `skmem_drop` at
    /// index 8 (byte offset 32) is correctly parsed and accumulated into `drops`.
    #[test]
    fn test_parse_frame_skmem_drop() {
        use super::{Protocol, SockKey, parse_frame};

        let expected_drop: u32 = 0x0000_00AB;

        // Build frame: inet_diag_msg + INET_DIAG_SKMEMINFO NLA
        let mut frame = make_inet_diag_msg(1024, 512);
        let skmem_payload = make_skmeminfo_payload(8, expected_drop); // index 8 = offset 32
        frame.extend_from_slice(&make_nla(INET_DIAG_SKMEMINFO, &skmem_payload));

        let mut bucket_map: BTreeMap<SockKey, Bucket> = BTreeMap::new();
        let mut drops: BTreeMap<Protocol, u64> = BTreeMap::new();
        let mut retransmits: u64 = 0;

        parse_frame(
            &frame,
            Protocol::Tcp,
            false,
            &mut bucket_map,
            &mut drops,
            &mut retransmits,
        )
        .expect("parse_frame must not fail on well-formed SKMEMINFO NLA");

        assert_eq!(
            drops.get(&Protocol::Tcp).copied().unwrap_or(0),
            u64::from(expected_drop),
            "skmem_drop must be read from SKMEMINFO payload index 8 (offset 32)"
        );
        assert_eq!(
            retransmits, 0,
            "retransmits must remain zero when no INET_DIAG_INFO NLA"
        );
    }

    /// Verify that `INET_DIAG_INFO` NLA (type=2) with `tcpi_total_retrans` at
    /// offset 100 is correctly parsed and accumulated into `retransmits`.
    #[test]
    fn test_parse_frame_total_retrans() {
        use super::{Protocol, SockKey, parse_frame};

        let expected_retrans: u32 = 0x0000_1234;

        // Build frame: inet_diag_msg + INET_DIAG_INFO NLA
        let mut frame = make_inet_diag_msg(0, 0);
        let tcp_info_payload = make_tcp_info_payload(expected_retrans);
        frame.extend_from_slice(&make_nla(INET_DIAG_INFO, &tcp_info_payload));

        let mut bucket_map: BTreeMap<SockKey, Bucket> = BTreeMap::new();
        let mut drops: BTreeMap<Protocol, u64> = BTreeMap::new();
        let mut retransmits: u64 = 0;

        parse_frame(
            &frame,
            Protocol::Tcp,
            false,
            &mut bucket_map,
            &mut drops,
            &mut retransmits,
        )
        .expect("parse_frame must not fail on well-formed INET_DIAG_INFO NLA");

        assert_eq!(
            retransmits,
            u64::from(expected_retrans),
            "tcpi_total_retrans must be read from tcp_info at byte offset 100"
        );
        assert!(
            drops.is_empty(),
            "drops must remain empty when no INET_DIAG_SKMEMINFO NLA"
        );
    }

    /// Verify that both NLAs in a single frame are parsed together correctly.
    #[test]
    fn test_parse_frame_both_nlas() {
        use super::{Protocol, SockKey, parse_frame};

        let expected_drop: u32 = 42;
        let expected_retrans: u32 = 99;

        let mut frame = make_inet_diag_msg(2048, 1024);
        // Append SKMEMINFO NLA (type 7) then INET_DIAG_INFO NLA (type 2).
        let skmem_payload = make_skmeminfo_payload(8, expected_drop);
        frame.extend_from_slice(&make_nla(INET_DIAG_SKMEMINFO, &skmem_payload));
        let tcp_info_payload = make_tcp_info_payload(expected_retrans);
        frame.extend_from_slice(&make_nla(INET_DIAG_INFO, &tcp_info_payload));

        let mut bucket_map: BTreeMap<SockKey, Bucket> = BTreeMap::new();
        let mut drops: BTreeMap<Protocol, u64> = BTreeMap::new();
        let mut retransmits: u64 = 0;

        parse_frame(
            &frame,
            Protocol::Tcp,
            false,
            &mut bucket_map,
            &mut drops,
            &mut retransmits,
        )
        .expect("parse_frame must not fail on combined NLA frame");

        assert_eq!(
            drops.get(&Protocol::Tcp).copied().unwrap_or(0),
            u64::from(expected_drop),
            "skmem_drop must be accumulated from SKMEMINFO NLA"
        );
        assert_eq!(
            retransmits,
            u64::from(expected_retrans),
            "tcpi_total_retrans must be accumulated from INET_DIAG_INFO NLA"
        );
    }

    /// Verify that `INET_DIAG_INFO` NLA is ignored for UDP sockets (`is_udp=true`).
    #[test]
    fn test_parse_frame_udp_skips_tcp_info() {
        use super::{Protocol, SockKey, parse_frame};

        let mut frame = make_inet_diag_msg(0, 0);
        // idiag_state = 7 for UDP (TCP_CLOSE → maps to Unconnected)
        frame[1] = 7;
        let tcp_info_payload = make_tcp_info_payload(9999);
        frame.extend_from_slice(&make_nla(INET_DIAG_INFO, &tcp_info_payload));

        let mut bucket_map: BTreeMap<SockKey, Bucket> = BTreeMap::new();
        let mut drops: BTreeMap<Protocol, u64> = BTreeMap::new();
        let mut retransmits: u64 = 0;

        parse_frame(
            &frame,
            Protocol::Udp,
            true, // is_udp = true
            &mut bucket_map,
            &mut drops,
            &mut retransmits,
        )
        .expect("parse_frame must not fail for UDP frame");

        assert_eq!(
            retransmits, 0,
            "INET_DIAG_INFO must be ignored for UDP sockets"
        );
    }

    /// Verify that a frame shorter than `INET_DIAG_MSG_MIN` is silently skipped.
    #[test]
    fn test_parse_frame_short_frame_silently_skipped() {
        use super::{Protocol, SockKey, parse_frame};

        let frame = vec![0u8; INET_DIAG_MSG_MIN - 1];

        let mut bucket_map: BTreeMap<SockKey, Bucket> = BTreeMap::new();
        let mut drops: BTreeMap<Protocol, u64> = BTreeMap::new();
        let mut retransmits: u64 = 0;

        parse_frame(
            &frame,
            Protocol::Tcp,
            false,
            &mut bucket_map,
            &mut drops,
            &mut retransmits,
        )
        .expect("short frame must be silently skipped, not errored");

        assert!(
            bucket_map.is_empty(),
            "no bucket must be created for a short frame"
        );
    }

    /// Verify that a `tcp_info` payload that is shorter than
    /// `TCP_INFO_TOTAL_RETRANS_OFFSET + 4` does not produce a retransmit count
    /// (rather than panicking or returning an error).
    #[test]
    fn test_parse_frame_truncated_tcp_info_no_retrans() {
        use super::{Protocol, SockKey, parse_frame};

        // Payload is only 12 bytes — does not reach offset 100.
        let short_tcp_info = vec![0xFFu8; 12];

        let mut frame = make_inet_diag_msg(0, 0);
        frame.extend_from_slice(&make_nla(INET_DIAG_INFO, &short_tcp_info));

        let mut bucket_map: BTreeMap<SockKey, Bucket> = BTreeMap::new();
        let mut drops: BTreeMap<Protocol, u64> = BTreeMap::new();
        let mut retransmits: u64 = 0;

        parse_frame(
            &frame,
            Protocol::Tcp,
            false,
            &mut bucket_map,
            &mut drops,
            &mut retransmits,
        )
        .expect("truncated tcp_info must be tolerated");

        assert_eq!(
            retransmits, 0,
            "truncated tcp_info must produce zero retransmits"
        );
    }
}
