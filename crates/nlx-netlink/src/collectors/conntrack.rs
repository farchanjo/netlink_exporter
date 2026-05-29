//! Conntrack collector — `NETLINK_NETFILTER` (12).
//!
//! ## Paths implemented
//!
//! * **`IPCTNL_MSG_CT_GET_STATS_CPU` (0x0105)** — unicast request, one frame per
//!   CPU.  Reply body is a raw `nf_conntrack_stat` struct (52/56/60 bytes).
//!   Counters are accumulated across CPUs and emitted as prometheus counters.
//!
//! * **`IPCTNL_MSG_CT_GET_STATS` (0x0106)** — unicast request.  Reply carries
//!   `CTA_STATS_GLOBAL_ENTRIES` (u64 big-endian) which becomes the
//!   `nft_conntrack_entries` gauge.
//!
//! ## Kernel gotchas
//!
//! * [G-03] `nfgenmsg.res_id` is `__be16` — always decode with `from_be_bytes`.
//! * [G-04] `nf_conntrack_stat` has three size variants (52/56/60); guard
//!   optional fields with `payload.len()` checks.
//! * [G-05] `CTA_COUNTERS_*` are big-endian u64 in flow entries (not used here).
//! * [G-24] Use `AF_UNSPEC` (0) for stats requests to capture both IPv4/IPv6.
//!
//! ADR refs: ADR-0011 (direct wire; procfs path empty), ADR-0014, ADR-0005.

use std::collections::BTreeMap;

use tracing::{debug, warn};

use nlx_domain::{
    error::DomainError,
    metric::MetricSample,
    model::conntrack::{ConntrackFlow, ConntrackStat},
};
use nlx_ports::{
    collector::{BoxFuture, Collector},
    driven::NetlinkConntrackPort,
    error::CollectError,
};

use crate::{
    transport::{MAX_DUMP_RESTARTS, NLMSG_HDRLEN, NetlinkError, NetlinkSocket},
    wire::{nested_attrs, parse_attrs, read_u8, read_u32_be, read_u64_be},
};

// ---------------------------------------------------------------------------
// Wire constants — NETLINK_NETFILTER (protocol 12)
// ---------------------------------------------------------------------------

/// `NETLINK_NETFILTER` protocol number.
const NETLINK_NETFILTER: i32 = 12;

/// `nfgenmsg` is 4 bytes appended immediately after `nlmsghdr` in every
/// `NETLINK_NETFILTER` message.
const NFGENMSG_LEN: usize = 4;

/// Offset of nlattr chain after nlmsghdr (16) + nfgenmsg (4).
const ATTRS_OFFSET: usize = NLMSG_HDRLEN + NFGENMSG_LEN;

// `nlmsg_type` values: (NFNL_SUBSYS_CTNETLINK=1) << 8 | msg_type
/// Per-CPU stats — raw `nf_conntrack_stat` body, no nlattr wrapping.
const IPCTNL_MSG_CT_GET_STATS_CPU: u16 = (1u16 << 8) | 4;
/// Global stats — carries `CTA_STATS_GLOBAL_ENTRIES`.
const IPCTNL_MSG_CT_GET_STATS: u16 = (1u16 << 8) | 5;

// ctattr_stats_cpu attribute types (enum ctattr_stats_cpu, nfnetlink_conntrack.h).
// The per-CPU reply is an nlattr chain of big-endian u32 values (ctnetlink uses
// nla_put_be32) — NOT a raw nf_conntrack_stat struct at fixed offsets.
const CTA_STATS_FOUND: u16 = 2;
const CTA_STATS_INVALID: u16 = 4;
const CTA_STATS_INSERT: u16 = 8;
const CTA_STATS_INSERT_FAILED: u16 = 9;
const CTA_STATS_DROP: u16 = 10;
const CTA_STATS_EARLY_DROP: u16 = 11;
const CTA_STATS_ERROR: u16 = 12;
const CTA_STATS_SEARCH_RESTART: u16 = 13;
const CTA_STATS_CLASH_RESOLVE: u16 = 14;
const CTA_STATS_CHAIN_TOOLONG: u16 = 15;

// enum ctattr_stats_global: CTA_STATS_GLOBAL_ENTRIES is a big-endian u32.
const CTA_STATS_GLOBAL_ENTRIES: u16 = 1;

// ---------------------------------------------------------------------------
// nfgenmsg builder
// ---------------------------------------------------------------------------

/// Build a 4-byte `nfgenmsg` with `AF_UNSPEC` (0), version 0, `res_id` 0.
fn nfgenmsg_unspec() -> [u8; 4] {
    [0u8, 0u8, 0u8, 0u8] // nfgen_family=0, version=0, res_id=[0,0]
}

// ---------------------------------------------------------------------------
// Stat accumulator
// ---------------------------------------------------------------------------

#[derive(Default)]
struct CpuStatSum {
    found: u64,
    invalid: u64,
    insert: u64,
    insert_failed: u64,
    drop: u64,
    early_drop: u64,
    error: u64,
    search_restart: u64,
    clash_resolve: Option<u64>,
    chaintoolong: Option<u64>,
}

/// Parse one per-CPU stats frame body (nlattr chain after nfgenmsg) and
/// accumulate into `sum`.
///
/// Values are nlattr-encoded big-endian u32 (`nla_put_be32`). Optional tail
/// fields (clash_resolve, chain_toolong) are simply absent on older kernels.
fn accumulate_cpu_stat(payload: &[u8], sum: &mut CpuStatSum) {
    for attr in parse_attrs(payload) {
        let v = u64::from(read_u32_be(attr.payload).unwrap_or(0));
        match attr.ty {
            CTA_STATS_FOUND => sum.found += v,
            CTA_STATS_INVALID => sum.invalid += v,
            CTA_STATS_INSERT => sum.insert += v,
            CTA_STATS_INSERT_FAILED => sum.insert_failed += v,
            CTA_STATS_DROP => sum.drop += v,
            CTA_STATS_EARLY_DROP => sum.early_drop += v,
            CTA_STATS_ERROR => sum.error += v,
            CTA_STATS_SEARCH_RESTART => sum.search_restart += v,
            CTA_STATS_CLASH_RESOLVE => *sum.clash_resolve.get_or_insert(0) += v,
            CTA_STATS_CHAIN_TOOLONG => *sum.chaintoolong.get_or_insert(0) += v,
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Collector helpers
// ---------------------------------------------------------------------------

/// Fetch per-CPU conntrack stats and return a single aggregated `ConntrackStat`.
///
/// Uses `request_single` (unicast, not dump) because the kernel replies with one
/// frame per CPU and terminates with an ACK, not `NLMSG_DONE`.  We call it in a
/// loop collecting frames until `None` or error.
///
/// # Errors
///
/// Returns [`NetlinkError`] on socket I/O or kernel error.
async fn fetch_cpu_stats(sock: &mut NetlinkSocket) -> Result<ConntrackStat, NetlinkError> {
    let nfgenmsg = nfgenmsg_unspec();
    let mut sum = CpuStatSum::default();

    // The kernel sends one frame per CPU.  `dump` is the right mechanism
    // because the kernel terminates the multi-part reply with NLMSG_DONE.
    let frames = sock.dump(IPCTNL_MSG_CT_GET_STATS_CPU, 0, &nfgenmsg).await?;

    debug!(
        cpu_frames = frames.len(),
        "IPCTNL_MSG_CT_GET_STATS_CPU frames"
    );

    for frame in &frames {
        // frame = nfgenmsg (4 bytes) + raw nf_conntrack_stat body
        if frame.len() < NFGENMSG_LEN {
            warn!("CT_GET_STATS_CPU frame too short ({} bytes)", frame.len());
            continue;
        }
        let payload = &frame[NFGENMSG_LEN..];
        accumulate_cpu_stat(payload, &mut sum);
    }

    Ok(ConntrackStat {
        found: sum.found,
        insert: sum.insert,
        drop: sum.drop,
        early_drop: sum.early_drop,
        invalid: sum.invalid,
        clash_resolve: sum.clash_resolve,
        chaintoolong: sum.chaintoolong,
    })
}

/// Fetch the global conntrack entry count via `IPCTNL_MSG_CT_GET_STATS`.
///
/// Reply carries `CTA_STATS_GLOBAL_ENTRIES` (type 1) as a big-endian u64.
///
/// # Errors
///
/// Returns [`NetlinkError`] on socket I/O or parse error.
async fn fetch_global_entries(sock: &mut NetlinkSocket) -> Result<u64, NetlinkError> {
    let nfgenmsg = nfgenmsg_unspec();
    let frame_opt = sock
        .request_single(IPCTNL_MSG_CT_GET_STATS, 0, &nfgenmsg)
        .await?;

    let frame = match frame_opt {
        Some(f) => f,
        None => return Ok(0),
    };

    // frame = nfgenmsg (4 bytes) + nlattr chain
    if frame.len() < NFGENMSG_LEN {
        return Ok(0);
    }

    let attrs_buf = &frame[NFGENMSG_LEN..];
    for attr in parse_attrs(attrs_buf) {
        if attr.ty == CTA_STATS_GLOBAL_ENTRIES {
            // CTA_STATS_GLOBAL_ENTRIES is a big-endian u32.
            if let Some(v) = read_u32_be(attr.payload) {
                return Ok(u64::from(v));
            }
        }
    }

    Ok(0)
}

// ---------------------------------------------------------------------------
// Protocol number → label
// ---------------------------------------------------------------------------

fn proto_label(proto: u8) -> &'static str {
    match proto {
        6 => "tcp",
        17 => "udp",
        1 => "icmp",
        58 => "icmpv6",
        132 => "sctp",
        33 => "dccp",
        136 => "udplite",
        _ => "other",
    }
}

// TCP state (CTA_PROTOINFO_TCP_STATE u8) → label
fn tcp_state_label(state: u8) -> &'static str {
    match state {
        0 => "none",
        1 => "syn_sent",
        2 => "syn_recv",
        3 => "established",
        4 => "fin_wait",
        5 => "close_wait",
        6 => "last_ack",
        7 => "time_wait",
        8 => "close",
        9 => "listen",
        _ => "other",
    }
}

// ---------------------------------------------------------------------------
// Flow parsing (CT_GET dump)  — §5.4
// ---------------------------------------------------------------------------

/// CTA_* top-level attribute type constants (effective, flags stripped).
const CTA_TUPLE_ORIG: u16 = 1;
const CTA_STATUS: u16 = 3;
const CTA_PROTOINFO: u16 = 4;
const CTA_COUNTERS_ORIG: u16 = 9;
const CTA_COUNTERS_REPLY: u16 = 10;

// Nested inside CTA_TUPLE_ORIG / CTA_TUPLE_REPLY
const CTA_TUPLE_PROTO: u16 = 2;
const CTA_PROTO_NUM: u16 = 1;

// Nested inside CTA_PROTOINFO
const CTA_PROTOINFO_TCP: u16 = 1;
const CTA_PROTOINFO_TCP_STATE: u16 = 1;

// Nested inside CTA_COUNTERS_ORIG / CTA_COUNTERS_REPLY
const CTA_COUNTERS_PACKETS: u16 = 1;
const CTA_COUNTERS_BYTES: u16 = 2;

/// Parse one conntrack flow frame into a `ConntrackFlow`.
///
/// `frame` starts at the first byte of nfgenmsg (i.e. after nlmsghdr).
/// Returns `None` when key attributes are absent (degenerate frame).
fn parse_flow_frame(frame: &[u8]) -> Option<ConntrackFlow> {
    if frame.len() < NFGENMSG_LEN {
        return None;
    }

    let attrs_buf = &frame[NFGENMSG_LEN..];

    let mut proto: u8 = 0;
    let mut state = String::from("new");
    let mut orig_bytes: u64 = 0;
    let mut orig_packets: u64 = 0;
    let mut reply_bytes: u64 = 0;
    let mut reply_packets: u64 = 0;
    let mut is_tcp = false;

    for attr in parse_attrs(attrs_buf) {
        match attr.ty {
            CTA_TUPLE_ORIG => {
                // Extract proto number from nested CTA_TUPLE_PROTO → CTA_PROTO_NUM
                for inner in nested_attrs(attr.payload) {
                    if inner.ty == CTA_TUPLE_PROTO {
                        for proto_attr in nested_attrs(inner.payload) {
                            if proto_attr.ty == CTA_PROTO_NUM {
                                if let Some(p) = read_u8(proto_attr.payload) {
                                    proto = p;
                                    is_tcp = p == 6;
                                }
                            }
                        }
                    }
                }
            }
            CTA_STATUS => {
                if !is_tcp {
                    // [G-06] CTA_STATUS is big-endian u32; IPS_ASSURED = bit 2.
                    if let Some(status) = read_u32_be(attr.payload) {
                        state = if status & 0x0000_0004 != 0 {
                            String::from("established")
                        } else {
                            String::from("new")
                        };
                    }
                }
            }
            CTA_PROTOINFO => {
                if is_tcp {
                    for inner in nested_attrs(attr.payload) {
                        if inner.ty == CTA_PROTOINFO_TCP {
                            for tcp_attr in nested_attrs(inner.payload) {
                                if tcp_attr.ty == CTA_PROTOINFO_TCP_STATE {
                                    if let Some(s) = read_u8(tcp_attr.payload) {
                                        state = tcp_state_label(s).to_owned();
                                    }
                                }
                            }
                        }
                    }
                }
            }
            CTA_COUNTERS_ORIG => {
                for inner in nested_attrs(attr.payload) {
                    match inner.ty {
                        CTA_COUNTERS_PACKETS => {
                            // [G-05] big-endian u64
                            orig_packets = read_u64_be(inner.payload).unwrap_or(0);
                        }
                        CTA_COUNTERS_BYTES => {
                            orig_bytes = read_u64_be(inner.payload).unwrap_or(0);
                        }
                        _ => {}
                    }
                }
            }
            CTA_COUNTERS_REPLY => {
                for inner in nested_attrs(attr.payload) {
                    match inner.ty {
                        CTA_COUNTERS_PACKETS => {
                            reply_packets = read_u64_be(inner.payload).unwrap_or(0);
                        }
                        CTA_COUNTERS_BYTES => {
                            reply_bytes = read_u64_be(inner.payload).unwrap_or(0);
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    Some(ConntrackFlow {
        protocol: proto_label(proto).to_owned(),
        state,
        orig_bytes,
        orig_packets,
        reply_bytes,
        reply_packets,
    })
}

// ---------------------------------------------------------------------------
// Full CT dump (stats-only mode)
// ---------------------------------------------------------------------------

/// Maximum conntrack entries to process during a CT_GET dump.  Exceeding this
/// cap triggers a cardinality-overflow error (§5.5).
const CT_DUMP_MAX_ENTRIES: usize = 200_000;

/// Dump all conntrack flows (CT_GET).
///
/// Returns `(Vec<ConntrackFlow>, entry_count)`.  If `entry_count >
/// CT_DUMP_MAX_ENTRIES` the caller should surface a cardinality error.
///
/// # Errors
///
/// Returns [`NetlinkError`] on socket I/O or dump interrupt.
async fn dump_flows_raw(sock: &mut NetlinkSocket) -> Result<Vec<ConntrackFlow>, NetlinkError> {
    let nfgenmsg = nfgenmsg_unspec();

    let mut restarts: u32 = 0;
    let frames = loop {
        match sock.dump(IPCTNL_MSG_CT_GET_STATS_CPU, 0, &nfgenmsg).await {
            Ok(f) => break f,
            Err(NetlinkError::DumpIntr) if restarts < MAX_DUMP_RESTARTS => {
                restarts = restarts.saturating_add(1);
                warn!(restart = restarts, "CT dump interrupted; retrying");
            }
            Err(e) => return Err(e),
        }
    };

    let mut flows: Vec<ConntrackFlow> = Vec::new();
    let mut count: usize = 0;

    for frame in &frames {
        if count >= CT_DUMP_MAX_ENTRIES {
            warn!(
                count,
                "conntrack dump exceeded CT_DUMP_MAX_ENTRIES; truncating"
            );
            break;
        }
        if let Some(flow) = parse_flow_frame(frame) {
            flows.push(flow);
            count = count.saturating_add(1);
        }
    }

    Ok(flows)
}

// ---------------------------------------------------------------------------
// collect() helper — converts stats into MetricSamples
// ---------------------------------------------------------------------------

fn stat_to_samples(stat: &ConntrackStat, entries: u64) -> Vec<MetricSample> {
    let empty: BTreeMap<String, String> = BTreeMap::new();
    let mut out = Vec::with_capacity(10);

    out.push(MetricSample::counter(
        "nft_conntrack_found_total",
        "Total conntrack lookup hits (sum across CPUs).",
        empty.clone(),
        stat.found,
    ));
    out.push(MetricSample::counter(
        "nft_conntrack_insert_total",
        "Total conntrack entries inserted (sum across CPUs).",
        empty.clone(),
        stat.insert,
    ));
    out.push(MetricSample::counter(
        "nft_conntrack_drop_total",
        "Total conntrack packets dropped because table was full (sum across CPUs).",
        empty.clone(),
        stat.drop,
    ));
    out.push(MetricSample::counter(
        "nft_conntrack_early_drop_total",
        "Total conntrack early drop events (sum across CPUs).",
        empty.clone(),
        stat.early_drop,
    ));
    out.push(MetricSample::counter(
        "nft_conntrack_invalid_total",
        "Total invalid conntrack packets (sum across CPUs).",
        empty.clone(),
        stat.invalid,
    ));

    if let Some(cr) = stat.clash_resolve {
        out.push(MetricSample::counter(
            "nft_conntrack_clash_resolve_total",
            "Total conntrack clash-resolve events (kernel >= 5.10, sum across CPUs).",
            empty.clone(),
            cr,
        ));
    }

    if let Some(cl) = stat.chaintoolong {
        out.push(MetricSample::counter(
            "nft_conntrack_chaintoolong_total",
            "Total conntrack chain-too-long events (kernel >= 5.12, sum across CPUs).",
            empty.clone(),
            cl,
        ));
    }

    out.push(MetricSample::gauge(
        "nft_conntrack_entries",
        "Current number of active conntrack entries.",
        empty,
        entries as f64,
    ));

    out
}

// ---------------------------------------------------------------------------
// ConntrackCollector
// ---------------------------------------------------------------------------

/// Adapter implementing [`NetlinkConntrackPort`] and [`Collector`] for
/// conntrack per-CPU statistics and global entry count.
///
/// Flow-level per-(proto, state) metrics are omitted here per the task scope
/// (stats-only; bounded cardinality).
pub struct ConntrackCollector;

impl NetlinkConntrackPort for ConntrackCollector {
    async fn dump_flows(&self) -> Result<Vec<ConntrackFlow>, DomainError> {
        let mut sock = NetlinkSocket::open(NETLINK_NETFILTER)
            .map_err(|e| DomainError::Collector(e.to_string()))?;

        let mut restarts: u32 = 0;
        let frames = loop {
            let nfgenmsg = nfgenmsg_unspec();
            match sock.dump((1u16 << 8) | 0, 0, &nfgenmsg).await {
                Ok(f) => break f,
                Err(NetlinkError::DumpIntr) if restarts < MAX_DUMP_RESTARTS => {
                    restarts = restarts.saturating_add(1);
                }
                Err(e) => return Err(DomainError::Collector(e.to_string())),
            }
        };

        let mut flows = Vec::new();
        for frame in &frames {
            if let Some(flow) = parse_flow_frame(frame) {
                flows.push(flow);
                if flows.len() >= CT_DUMP_MAX_ENTRIES {
                    break;
                }
            }
        }
        Ok(flows)
    }

    async fn dump_stats(&self) -> Result<Vec<ConntrackStat>, DomainError> {
        let mut sock = NetlinkSocket::open(NETLINK_NETFILTER)
            .map_err(|e| DomainError::Collector(e.to_string()))?;
        let stat = fetch_cpu_stats(&mut sock)
            .await
            .map_err(|e| DomainError::Collector(e.to_string()))?;
        Ok(vec![stat])
    }
}

impl Collector for ConntrackCollector {
    fn name(&self) -> &str {
        "conntrack"
    }

    fn collect(&self) -> BoxFuture<'_, Result<Vec<MetricSample>, CollectError>> {
        Box::pin(async move {
            let mut sock = NetlinkSocket::open(NETLINK_NETFILTER)
                .map_err(|e| CollectError::Io(e.to_string()))?;

            // 1. Per-CPU stats
            let stat = fetch_cpu_stats(&mut sock).await.map_err(map_nl_err)?;

            // 2. Global entries gauge
            let entries = fetch_global_entries(&mut sock).await.unwrap_or_else(|e| {
                warn!(error = %e, "CT_GET_STATS: could not fetch global entries; using 0");
                0
            });

            Ok(stat_to_samples(&stat, entries))
        })
    }

    fn probe_available(&self) -> BoxFuture<'_, bool> {
        Box::pin(async move {
            // Availability: open a NETLINK_NETFILTER socket and issue
            // IPCTNL_MSG_CT_GET_STATS_CPU.  Success → nf_conntrack present.
            match NetlinkSocket::open(NETLINK_NETFILTER) {
                Err(_) => false,
                Ok(mut sock) => {
                    let nfgenmsg = nfgenmsg_unspec();
                    sock.dump(IPCTNL_MSG_CT_GET_STATS_CPU, 0, &nfgenmsg)
                        .await
                        .is_ok()
                }
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

fn map_nl_err(e: NetlinkError) -> CollectError {
    match e {
        NetlinkError::DumpIntr => CollectError::DumpIntr,
        NetlinkError::RecvBufOverflow => CollectError::RecvBufOverflow,
        NetlinkError::KernelError { errno: 2 } => CollectError::Unavailable {
            reason: "ENOENT — nf_conntrack not present".into(),
        },
        other => CollectError::Io(other.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Allow unused in non-linux builds (parse helpers reference wire constants)
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proto_label_known() {
        assert_eq!(proto_label(6), "tcp");
        assert_eq!(proto_label(17), "udp");
        assert_eq!(proto_label(1), "icmp");
        assert_eq!(proto_label(99), "other");
    }

    #[test]
    fn tcp_state_label_known() {
        assert_eq!(tcp_state_label(3), "established");
        assert_eq!(tcp_state_label(7), "time_wait");
        assert_eq!(tcp_state_label(200), "other");
    }

    /// Append one big-endian u32 nlattr (type, value) — 4-byte header (native
    /// nla_len/nla_type) + 4-byte big-endian payload (matches ctnetlink).
    fn push_be32_nla(buf: &mut Vec<u8>, ty: u16, val: u32) {
        let len: u16 = 8;
        buf.extend_from_slice(&len.to_ne_bytes());
        buf.extend_from_slice(&ty.to_ne_bytes());
        buf.extend_from_slice(&val.to_be_bytes());
    }

    #[test]
    fn accumulate_cpu_stat_minimal() {
        // Kernel < 5.10: only always-present counters, no clash/chain attrs.
        let mut payload = Vec::new();
        push_be32_nla(&mut payload, CTA_STATS_FOUND, 7);
        push_be32_nla(&mut payload, CTA_STATS_DROP, 3);

        let mut sum = CpuStatSum::default();
        accumulate_cpu_stat(&payload, &mut sum);

        assert_eq!(sum.found, 7);
        assert_eq!(sum.drop, 3);
        assert!(sum.clash_resolve.is_none(), "clash_resolve should be absent");
        assert!(sum.chaintoolong.is_none(), "chaintoolong should be absent");
    }

    #[test]
    fn accumulate_cpu_stat_full() {
        // Kernel >= 5.12: clash_resolve and chain_toolong present.
        let mut payload = Vec::new();
        push_be32_nla(&mut payload, CTA_STATS_FOUND, 1);
        push_be32_nla(&mut payload, CTA_STATS_CLASH_RESOLVE, 5);
        push_be32_nla(&mut payload, CTA_STATS_CHAIN_TOOLONG, 2);

        let mut sum = CpuStatSum::default();
        accumulate_cpu_stat(&payload, &mut sum);

        assert_eq!(sum.found, 1);
        assert_eq!(sum.clash_resolve, Some(5));
        assert_eq!(sum.chaintoolong, Some(2));
    }

    #[test]
    fn nfgenmsg_unspec_is_four_bytes() {
        assert_eq!(nfgenmsg_unspec().len(), 4);
        assert_eq!(nfgenmsg_unspec(), [0u8, 0u8, 0u8, 0u8]);
    }

    #[test]
    fn stat_to_samples_contains_entries_gauge() {
        let stat = ConntrackStat {
            found: 10,
            insert: 5,
            drop: 1,
            early_drop: 0,
            invalid: 2,
            clash_resolve: Some(3),
            chaintoolong: None,
        };
        let samples = stat_to_samples(&stat, 42);
        let entries = samples.iter().find(|s| s.name == "nft_conntrack_entries");
        assert!(entries.is_some(), "entries gauge must be present");
        if let Some(s) = entries {
            assert_eq!(s.value, nlx_domain::metric::MetricValue::F64(42.0));
        }

        // clash_resolve counter must be present (Some)
        assert!(
            samples
                .iter()
                .any(|s| s.name == "nft_conntrack_clash_resolve_total")
        );

        // chaintoolong must NOT appear (None)
        assert!(
            !samples
                .iter()
                .any(|s| s.name == "nft_conntrack_chaintoolong_total")
        );
    }
}
