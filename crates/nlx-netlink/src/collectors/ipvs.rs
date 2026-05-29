//! IPVS genetlink collector.
//!
//! Netlink family: `NETLINK_GENERIC` (16), family name `"IPVS"`.
//! Messages used: `IPVS_CMD_GET_SERVICE` (cmd=4), `IPVS_CMD_GET_DEST` (cmd=8).
//! ADR refs: ADR-0011, ADR-0014, netlink-protocol.md §13.
//!
//! ## Runtime gate
//!
//! `probe_available()` calls `resolve_genl_family("IPVS")`. `Ok(None)` means the
//! `ip_vs` module is not loaded; `collect()` returns `Ok(vec![])` — no error.
//!
//! ## Wire correctness
//!
//! Critical fixes vs. original implementation (see netlink-protocol.md §13.12):
//!
//! - `IPVS_SVC_ATTR_STATS64` is type **12**, not 11 (11 is `IPVS_SVC_ATTR_PE_NAME`).
//! - `GET_DEST` requests wrap service key attrs inside `IPVS_CMD_ATTR_SERVICE`
//!   (type=1) `NLA_NESTED` container — the kernel's handler rejects top-level attrs.
//! - Dest address family is read from `IPVS_DEST_ATTR_ADDR_FAMILY` (id=11) with
//!   fallback to service AF; the old colon-check fails for fwmark services.
//! - STATS32 fallback: when STATS64 absent, parse STATS (type=10) u32 fields and
//!   widen to u64 so older kernels produce non-zero metrics.
//!
//! ## Cardinality (MC-003)
//!
//! **Service metrics** carry `{proto, vip, port}` labels.  The IPVS service table
//! is operator-defined and bounded by `IPVS_MAX_SERVICES` (512).  VIP addresses
//! appear in labels; this is intentional and safe because the number of distinct
//! VIPs equals the number of services, which is already bounded.
//!
//! **Destination metrics** carry `{proto, vip, port, rip, rport}` labels.  The
//! number of real servers per service is bounded by `IPVS_MAX_DESTS` (256) and is
//! operator-controlled via `ipvsadm`.  The total destination series count is
//! bounded by `IPVS_MAX_SERVICES × IPVS_MAX_DESTS = 131 072`.  This is well
//! within Prometheus cardinality limits for typical IPVS deployments; operators
//! managing unusually large pools should reduce the caps via config.
//!
//! ## Metric naming (MC-006)
//!
//! EMA rate gauges (CPS / PPS / BPS) use the `_rate` suffix per Prometheus
//! naming conventions — `_per_second` is not a recognised standard suffix.
//! The kernel stats are exponential moving averages, not instantaneous rates,
//! but `_rate` correctly signals "this is a rate gauge, not a counter".

use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, Ipv6Addr},
};

use nlx_domain::{
    error::DomainError,
    metric::MetricSample,
    model::ipvs::{IpvsDestination, IpvsService},
};
use nlx_ports::{
    collector::{BoxFuture, Collector},
    driven::NetlinkIpvsPort,
    error::CollectError,
};
use tracing::debug;

use crate::{
    transport::NetlinkSocket,
    wire::{
        NLA_HDRLEN, align4, nested_attrs, parse_attrs, read_u16, read_u16_be, read_u32, read_u64,
    },
};

const NETLINK_GENERIC: i32 = 16;

// genlmsghdr commands (IPVS_GENL_VERSION = 1).
const IPVS_CMD_GET_SERVICE: u8 = 4;
const IPVS_CMD_GET_DEST: u8 = 8;
const IPVS_GENL_VERSION: u8 = 1;

// Top-level command attribute types (IPVS_CMD_ATTR_*, §13.4).
// All service-level attrs inside IPVS_CMD_ATTR_SERVICE; dest attrs inside IPVS_CMD_ATTR_DEST.
const IPVS_CMD_ATTR_SERVICE: u16 = 1;
const IPVS_CMD_ATTR_DEST: u16 = 2;

// IPVS service attribute types (enum ipvs_svc_attrs, §13.5).
const IPVS_SVC_ATTR_AF: u16 = 1;
const IPVS_SVC_ATTR_PROTOCOL: u16 = 2;
const IPVS_SVC_ATTR_ADDR: u16 = 3;
const IPVS_SVC_ATTR_PORT: u16 = 4;
const IPVS_SVC_ATTR_FWMARK: u16 = 5;
const IPVS_SVC_ATTR_SCHED_NAME: u16 = 6;
// IPVS_SVC_ATTR_FLAGS   = 7  (not parsed)
// IPVS_SVC_ATTR_TIMEOUT = 8  (not parsed)
// IPVS_SVC_ATTR_NETMASK = 9  (not parsed)
const IPVS_SVC_ATTR_STATS: u16 = 10; // 32-bit stats (fallback for kernels < 3.15)
// IPVS_SVC_ATTR_PE_NAME = 11 (persistence engine name — NOT STATS64)
const IPVS_SVC_ATTR_STATS64: u16 = 12; // 64-bit stats (preferred, §13.8)

// IPVS destination attribute types (enum ipvs_dest_attrs, §13.6).
const IPVS_DEST_ATTR_ADDR: u16 = 1;
const IPVS_DEST_ATTR_PORT: u16 = 2;
// IPVS_DEST_ATTR_FWD_METHOD = 3 (not parsed)
const IPVS_DEST_ATTR_WEIGHT: u16 = 4;
const IPVS_DEST_ATTR_ACTIVE_CONNS: u16 = 7;
const IPVS_DEST_ATTR_INACT_CONNS: u16 = 8;
const IPVS_DEST_ATTR_STATS: u16 = 10; // 32-bit stats (fallback)
const IPVS_DEST_ATTR_ADDR_FAMILY: u16 = 11; // dest AF override (§13.6)
const IPVS_DEST_ATTR_STATS64: u16 = 12; // 64-bit stats (preferred)

// IPVS stats64 inner attr types (enum ipvs_stats_attrs, §13.8).
const IPVS_STATS_ATTR_CONNS: u16 = 1;
const IPVS_STATS_ATTR_INPKTS: u16 = 2;
const IPVS_STATS_ATTR_OUTPKTS: u16 = 3;
const IPVS_STATS_ATTR_INBYTES: u16 = 4;
const IPVS_STATS_ATTR_OUTBYTES: u16 = 5;
const IPVS_STATS_ATTR_CPS: u16 = 6;
const IPVS_STATS_ATTR_INPPS: u16 = 7;
const IPVS_STATS_ATTR_OUTPPS: u16 = 8;
const IPVS_STATS_ATTR_INBPS: u16 = 9;
const IPVS_STATS_ATTR_OUTBPS: u16 = 10;

// Cardinality hard caps (§13.10).
const IPVS_MAX_SERVICES: usize = 512;
const IPVS_MAX_DESTS: usize = 256;

// Address families.
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

/// Adapter implementing [`NetlinkIpvsPort`] and [`Collector`] for IPVS.
pub struct IpvsCollector;

impl NetlinkIpvsPort for IpvsCollector {
    async fn dump_services(&self) -> Result<Vec<IpvsService>, DomainError> {
        let mut sock = NetlinkSocket::open(NETLINK_GENERIC)
            .map_err(|e| DomainError::Collector(e.to_string()))?;

        let Some(family_id) = resolve_family(&mut sock).await? else {
            return Ok(vec![]);
        };

        dump_services_with_sock(&mut sock, family_id).await
    }

    async fn dump_destinations(
        &self,
        service: &IpvsService,
    ) -> Result<Vec<IpvsDestination>, DomainError> {
        let mut sock = NetlinkSocket::open(NETLINK_GENERIC)
            .map_err(|e| DomainError::Collector(e.to_string()))?;

        let Some(family_id) = resolve_family(&mut sock).await? else {
            return Ok(vec![]);
        };

        dump_dests_for(&mut sock, family_id, service).await
    }
}

impl Collector for IpvsCollector {
    fn name(&self) -> &'static str {
        "ipvs"
    }

    fn collect(&self) -> BoxFuture<'_, Result<Vec<MetricSample>, CollectError>> {
        Box::pin(async move {
            let mut sock = NetlinkSocket::open(NETLINK_GENERIC)
                .map_err(|e| CollectError::Io(e.to_string()))?;

            let family_id = sock
                .resolve_genl_family("IPVS")
                .await
                .map_err(|e| CollectError::Io(e.to_string()))?;

            let Some(family_id) = family_id else {
                debug!("IPVS genetlink family not loaded; skipping collect");
                return Ok(vec![]);
            };

            let services = dump_services_with_sock(&mut sock, family_id)
                .await
                .map_err(|e| CollectError::Io(e.to_string()))?;

            let mut out = Vec::new();
            for svc in services.iter().take(IPVS_MAX_SERVICES) {
                let svc_labels = svc_labels(svc);
                push_svc_metrics(&mut out, svc, &svc_labels);

                let dests = dump_dests_for(&mut sock, family_id, svc)
                    .await
                    .map_err(|e| CollectError::Io(e.to_string()))?;

                for dest in dests.iter().take(IPVS_MAX_DESTS) {
                    push_dest_metrics(&mut out, svc, dest);
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
            matches!(sock.resolve_genl_family("IPVS").await, Ok(Some(_)))
        })
    }
}

// ---------------------------------------------------------------------------
// Internal async helpers
// ---------------------------------------------------------------------------

async fn resolve_family(sock: &mut NetlinkSocket) -> Result<Option<u16>, DomainError> {
    sock.resolve_genl_family("IPVS")
        .await
        .map_err(|e| DomainError::Collector(e.to_string()))
}

async fn dump_services_with_sock(
    sock: &mut NetlinkSocket,
    family_id: u16,
) -> Result<Vec<IpvsService>, DomainError> {
    let payload = build_genl_payload(IPVS_CMD_GET_SERVICE);
    let mut restarts = 0u32;
    let frames = loop {
        match sock.dump(family_id, 0, &payload).await {
            Ok(f) => break f,
            Err(crate::transport::NetlinkError::DumpIntr) => {
                restarts += 1;
                if restarts >= crate::transport::MAX_DUMP_RESTARTS {
                    return Err(DomainError::Collector(
                        "IPVS service dump interrupted".into(),
                    ));
                }
            }
            Err(e) => return Err(DomainError::Collector(e.to_string())),
        }
    };

    let mut result = Vec::with_capacity(frames.len());
    for frame in &frames {
        if frame.len() < 4 {
            continue;
        }
        // Frame payload starts after 4-byte genlmsghdr.
        // Top-level attrs are IPVS_CMD_ATTR_SERVICE (type=1) nested containers.
        let top_attrs = &frame[4..];
        for top in parse_attrs(top_attrs) {
            if top.ty == IPVS_CMD_ATTR_SERVICE {
                if let Some(svc) = parse_service(top.payload) {
                    result.push(svc);
                }
            }
        }
    }
    Ok(result)
}

async fn dump_dests_for(
    sock: &mut NetlinkSocket,
    family_id: u16,
    svc: &IpvsService,
) -> Result<Vec<IpvsDestination>, DomainError> {
    // Build GET_DEST request with service key attrs wrapped in IPVS_CMD_ATTR_SERVICE nest.
    let payload = build_dest_request(svc);
    let frames = sock
        .dump(family_id, 0, &payload)
        .await
        .map_err(|e| DomainError::Collector(e.to_string()))?;

    let mut result = Vec::with_capacity(frames.len());
    for frame in &frames {
        if frame.len() < 4 {
            continue;
        }
        // Top-level attrs: IPVS_CMD_ATTR_DEST (type=2) nested containers.
        let top_attrs = &frame[4..];
        for top in parse_attrs(top_attrs) {
            if top.ty == IPVS_CMD_ATTR_DEST {
                if let Some(dest) = parse_destination(top.payload, svc) {
                    result.push(dest);
                }
            }
        }
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// Wire builders
// ---------------------------------------------------------------------------

/// Build a minimal genlmsghdr-only payload (no extra attrs).
fn build_genl_payload(cmd: u8) -> Vec<u8> {
    vec![cmd, IPVS_GENL_VERSION, 0, 0]
}

/// Build a `GET_DEST` request with service key attrs wrapped in
/// `IPVS_CMD_ATTR_SERVICE` (type=1) `NLA_NESTED` container.
///
/// The kernel `GET_DEST` handler calls `nlmsg_parse()` expecting service key
/// attrs inside this outer nest (§13.7 / G-34). Omitting the nest returns
/// `EINVAL` or an empty multipart response.
#[allow(
    clippy::cast_possible_truncation,
    reason = "nlattr length fits u16 by construction; NLA payloads are bounded to u16::MAX by the kernel ABI"
)]
fn build_dest_request(svc: &IpvsService) -> Vec<u8> {
    let mut buf = vec![IPVS_CMD_GET_DEST, IPVS_GENL_VERSION, 0u8, 0u8];

    // Encode protocol as u16.
    let proto: u16 = match svc.proto.as_str() {
        "tcp" => 6,
        "udp" => 17,
        "sctp" => 132,
        _ => 0,
    };

    // Helper: push a single NLA into `target`.
    let push_nla = |target: &mut Vec<u8>, ty: u16, payload: &[u8]| {
        let nla_len = (NLA_HDRLEN + payload.len()) as u16;
        target.extend_from_slice(&nla_len.to_ne_bytes());
        target.extend_from_slice(&ty.to_ne_bytes());
        target.extend_from_slice(payload);
        let pad = align4(NLA_HDRLEN + payload.len()) - (NLA_HDRLEN + payload.len());
        target.extend(std::iter::repeat_n(0u8, pad));
    };

    // Build the inner service-key attrs into a temporary buffer.
    let mut inner: Vec<u8> = Vec::new();

    // AF — derived from VIP string or fwmark fallback.
    let af: u16 = if svc.vip.contains(':') {
        AF_INET6
    } else {
        AF_INET
    };
    push_nla(&mut inner, IPVS_SVC_ATTR_AF, &af.to_ne_bytes());

    if svc.port.starts_with("0x") {
        // Fwmark service: emit AF + FWMARK.
        if let Ok(fwmark) = u32::from_str_radix(svc.port.trim_start_matches("0x"), 16) {
            push_nla(&mut inner, IPVS_SVC_ATTR_FWMARK, &fwmark.to_ne_bytes());
        }
    } else {
        // IP:port service: emit AF + PROTOCOL + ADDR + PORT.
        push_nla(&mut inner, IPVS_SVC_ATTR_PROTOCOL, &proto.to_ne_bytes());

        if !svc.vip.is_empty() {
            if let Ok(v4) = svc.vip.parse::<Ipv4Addr>() {
                push_nla(&mut inner, IPVS_SVC_ATTR_ADDR, &v4.octets());
            } else if let Ok(v6) = svc.vip.parse::<Ipv6Addr>() {
                push_nla(&mut inner, IPVS_SVC_ATTR_ADDR, &v6.octets());
            }
        }

        if let Ok(port) = svc.port.parse::<u16>() {
            // Port is __be16 on the wire (§13.5 / G-29).
            push_nla(&mut inner, IPVS_SVC_ATTR_PORT, &port.to_be_bytes());
        }
    }

    // Wrap inner attrs in IPVS_CMD_ATTR_SERVICE (type=1) nested NLA.
    // NLA_F_NESTED (0x8000) is set on the type per kernel convention.
    push_nla(&mut buf, IPVS_CMD_ATTR_SERVICE | 0x8000, &inner);

    buf
}

// ---------------------------------------------------------------------------
// Parsers
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Stats64 {
    conns: u64,
    in_pkts: u64,
    out_pkts: u64,
    in_bytes: u64,
    out_bytes: u64,
    cps: u64,
    in_pps: u64,
    out_pps: u64,
    in_bps: u64,
    out_bps: u64,
}

/// Parse a STATS64 nested attr payload (all fields u64 native-endian).
fn parse_stats64(payload: &[u8]) -> Stats64 {
    let mut s = Stats64::default();
    for attr in nested_attrs(payload) {
        match attr.ty {
            IPVS_STATS_ATTR_CONNS => s.conns = read_u64(attr.payload).unwrap_or(0),
            IPVS_STATS_ATTR_INPKTS => s.in_pkts = read_u64(attr.payload).unwrap_or(0),
            IPVS_STATS_ATTR_OUTPKTS => s.out_pkts = read_u64(attr.payload).unwrap_or(0),
            IPVS_STATS_ATTR_INBYTES => s.in_bytes = read_u64(attr.payload).unwrap_or(0),
            IPVS_STATS_ATTR_OUTBYTES => s.out_bytes = read_u64(attr.payload).unwrap_or(0),
            IPVS_STATS_ATTR_CPS => s.cps = read_u64(attr.payload).unwrap_or(0),
            IPVS_STATS_ATTR_INPPS => s.in_pps = read_u64(attr.payload).unwrap_or(0),
            IPVS_STATS_ATTR_OUTPPS => s.out_pps = read_u64(attr.payload).unwrap_or(0),
            IPVS_STATS_ATTR_INBPS => s.in_bps = read_u64(attr.payload).unwrap_or(0),
            IPVS_STATS_ATTR_OUTBPS => s.out_bps = read_u64(attr.payload).unwrap_or(0),
            _ => {}
        }
    }
    s
}

/// Parse a STATS32 fallback nested attr payload (u32 native-endian fields).
///
/// Used when `IPVS_SVC_ATTR_STATS64` / `IPVS_DEST_ATTR_STATS64` (type=12) is
/// absent — older kernels only emit the 32-bit variant (type=10).
fn parse_stats32(payload: &[u8]) -> Stats64 {
    let mut s = Stats64::default();
    for attr in nested_attrs(payload) {
        match attr.ty {
            IPVS_STATS_ATTR_CONNS => s.conns = u64::from(read_u32(attr.payload).unwrap_or(0)),
            IPVS_STATS_ATTR_INPKTS => s.in_pkts = u64::from(read_u32(attr.payload).unwrap_or(0)),
            IPVS_STATS_ATTR_OUTPKTS => {
                s.out_pkts = u64::from(read_u32(attr.payload).unwrap_or(0));
            }
            // inbytes / outbytes are u64 even in the 32-bit struct.
            IPVS_STATS_ATTR_INBYTES => s.in_bytes = read_u64(attr.payload).unwrap_or(0),
            IPVS_STATS_ATTR_OUTBYTES => s.out_bytes = read_u64(attr.payload).unwrap_or(0),
            IPVS_STATS_ATTR_CPS => s.cps = u64::from(read_u32(attr.payload).unwrap_or(0)),
            IPVS_STATS_ATTR_INPPS => s.in_pps = u64::from(read_u32(attr.payload).unwrap_or(0)),
            IPVS_STATS_ATTR_OUTPPS => s.out_pps = u64::from(read_u32(attr.payload).unwrap_or(0)),
            IPVS_STATS_ATTR_INBPS => s.in_bps = u64::from(read_u32(attr.payload).unwrap_or(0)),
            IPVS_STATS_ATTR_OUTBPS => s.out_bps = u64::from(read_u32(attr.payload).unwrap_or(0)),
            _ => {}
        }
    }
    s
}

#[allow(
    clippy::unnecessary_wraps,
    reason = "signature kept uniform with sibling parsers"
)]
fn parse_service(attrs_buf: &[u8]) -> Option<IpvsService> {
    let mut af: u16 = AF_INET;
    let mut proto: u16 = 0;
    let mut addr_bytes: Option<Vec<u8>> = None;
    let mut port: u16 = 0;
    let mut fwmark: u32 = 0;
    let mut sched = String::from("unknown");
    let mut stats64_payload: Option<Vec<u8>> = None;
    let mut stats32_payload: Option<Vec<u8>> = None;

    for attr in parse_attrs(attrs_buf) {
        match attr.ty {
            IPVS_SVC_ATTR_AF => af = read_u16(attr.payload).unwrap_or(AF_INET),
            IPVS_SVC_ATTR_PROTOCOL => proto = read_u16(attr.payload).unwrap_or(0),
            IPVS_SVC_ATTR_ADDR => addr_bytes = Some(attr.payload.to_vec()),
            IPVS_SVC_ATTR_PORT => {
                // Network byte order (§13.5, G-29).
                port = read_u16_be(attr.payload).unwrap_or(0);
            }
            IPVS_SVC_ATTR_FWMARK => fwmark = read_u32(attr.payload).unwrap_or(0),
            IPVS_SVC_ATTR_SCHED_NAME => {
                let end = attr
                    .payload
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(attr.payload.len());
                sched = String::from_utf8_lossy(&attr.payload[..end]).into_owned();
            }
            IPVS_SVC_ATTR_STATS64 => {
                // type=12 — preferred 64-bit stats (§13.8).
                stats64_payload = Some(attr.payload.to_vec());
            }
            IPVS_SVC_ATTR_STATS => {
                // type=10 — 32-bit fallback for older kernels.
                stats32_payload = Some(attr.payload.to_vec());
            }
            _ => {}
        }
    }

    // STATS64 preferred; fall back to STATS32 when absent.
    let stats = if let Some(p) = stats64_payload {
        parse_stats64(&p)
    } else if let Some(p) = stats32_payload {
        parse_stats32(&p)
    } else {
        Stats64::default()
    };

    let proto_str = match proto {
        6 => "tcp",
        17 => "udp",
        132 => "sctp",
        _ => "unknown",
    };

    let (vip, port_str) = if fwmark != 0 {
        (String::new(), format!("0x{fwmark:x}"))
    } else {
        let vip = addr_to_str(af, addr_bytes.as_deref().unwrap_or(&[]));
        (vip, port.to_string())
    };

    Some(IpvsService {
        proto: proto_str.to_owned(),
        vip,
        port: port_str,
        sched,
        conns: stats.conns,
        in_pkts: stats.in_pkts,
        out_pkts: stats.out_pkts,
        in_bytes: stats.in_bytes,
        out_bytes: stats.out_bytes,
        cps: stats.cps,
        in_pps: stats.in_pps,
        out_pps: stats.out_pps,
        in_bps: stats.in_bps,
        out_bps: stats.out_bps,
    })
}

#[allow(
    clippy::unnecessary_wraps,
    reason = "signature kept uniform with sibling parsers"
)]
fn parse_destination(attrs_buf: &[u8], svc: &IpvsService) -> Option<IpvsDestination> {
    // Prefer IPVS_DEST_ATTR_ADDR_FAMILY (id=11) for AF.
    // Fallback: derive from service AF (not from svc.vip colon-check, which
    // fails for fwmark services where vip is empty — §13.6 / G-35).
    let svc_af: u16 = if svc.vip.contains(':') {
        AF_INET6
    } else {
        AF_INET
    };

    let mut dest_af: Option<u16> = None;
    let mut addr_bytes: Option<Vec<u8>> = None;
    let mut rport: u16 = 0;
    let mut weight: u32 = 0;
    let mut active: u32 = 0;
    let mut inactive: u32 = 0;
    let mut stats64_payload: Option<Vec<u8>> = None;
    let mut stats32_payload: Option<Vec<u8>> = None;

    for attr in parse_attrs(attrs_buf) {
        match attr.ty {
            IPVS_DEST_ATTR_ADDR => addr_bytes = Some(attr.payload.to_vec()),
            IPVS_DEST_ATTR_PORT => {
                rport = read_u16_be(attr.payload).unwrap_or(0);
            }
            IPVS_DEST_ATTR_WEIGHT => weight = read_u32(attr.payload).unwrap_or(0),
            IPVS_DEST_ATTR_ACTIVE_CONNS => active = read_u32(attr.payload).unwrap_or(0),
            IPVS_DEST_ATTR_INACT_CONNS => inactive = read_u32(attr.payload).unwrap_or(0),
            IPVS_DEST_ATTR_ADDR_FAMILY => {
                dest_af = read_u16(attr.payload);
            }
            IPVS_DEST_ATTR_STATS64 => {
                stats64_payload = Some(attr.payload.to_vec());
            }
            IPVS_DEST_ATTR_STATS => {
                stats32_payload = Some(attr.payload.to_vec());
            }
            _ => {}
        }
    }

    let af = dest_af.unwrap_or(svc_af);
    let stats = if let Some(p) = stats64_payload {
        parse_stats64(&p)
    } else if let Some(p) = stats32_payload {
        parse_stats32(&p)
    } else {
        Stats64::default()
    };

    let rip = addr_to_str(af, addr_bytes.as_deref().unwrap_or(&[]));
    Some(IpvsDestination {
        svc_proto: svc.proto.clone(),
        svc_vip: svc.vip.clone(),
        svc_port: svc.port.clone(),
        rip,
        rport: rport.to_string(),
        weight,
        active_conns: active,
        inactive_conns: inactive,
        conns: stats.conns,
        in_bytes: stats.in_bytes,
        out_bytes: stats.out_bytes,
    })
}

fn addr_to_str(af: u16, bytes: &[u8]) -> String {
    match af {
        AF_INET if bytes.len() >= 4 => {
            Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string()
        }
        AF_INET6 if bytes.len() >= 16 => {
            let arr: [u8; 16] = bytes[..16].try_into().unwrap_or([0u8; 16]);
            Ipv6Addr::from(arr).to_string()
        }
        _ => String::new(),
    }
}

// ---------------------------------------------------------------------------
// Metric builders
// ---------------------------------------------------------------------------

fn svc_labels(svc: &IpvsService) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    m.insert("proto".to_owned(), svc.proto.clone());
    m.insert("vip".to_owned(), svc.vip.clone());
    m.insert("port".to_owned(), svc.port.clone());
    m
}

#[allow(
    clippy::cast_precision_loss,
    reason = "metric gauge values are f64; precision loss on large u64 counters is inherent to Prometheus exposition"
)]
fn push_svc_metrics(
    out: &mut Vec<MetricSample>,
    svc: &IpvsService,
    labels: &BTreeMap<String, String>,
) {
    let push_ctr = |out: &mut Vec<MetricSample>, name, help, value| {
        out.push(MetricSample::counter(name, help, labels.clone(), value));
    };
    let push_gauge =
        |out: &mut Vec<MetricSample>, name: &'static str, help: &'static str, value: f64| {
            out.push(MetricSample::gauge(name, help, labels.clone(), value));
        };

    push_ctr(
        out,
        "nft_ipvs_connections_total",
        "IPVS virtual service total connections.",
        svc.conns,
    );
    push_ctr(
        out,
        "nft_ipvs_incoming_packets_total",
        "IPVS virtual service incoming packets.",
        svc.in_pkts,
    );
    push_ctr(
        out,
        "nft_ipvs_outgoing_packets_total",
        "IPVS virtual service outgoing packets.",
        svc.out_pkts,
    );
    push_ctr(
        out,
        "nft_ipvs_incoming_bytes_total",
        "IPVS virtual service incoming bytes.",
        svc.in_bytes,
    );
    push_ctr(
        out,
        "nft_ipvs_outgoing_bytes_total",
        "IPVS virtual service outgoing bytes.",
        svc.out_bytes,
    );
    // MC-006: use _rate suffix (Prometheus naming); _per_second is non-standard.
    push_gauge(
        out,
        "nft_ipvs_connections_rate",
        "IPVS virtual service EMA connections per second.",
        svc.cps as f64,
    );
    push_gauge(
        out,
        "nft_ipvs_incoming_packets_rate",
        "IPVS virtual service EMA incoming packets per second.",
        svc.in_pps as f64,
    );
    push_gauge(
        out,
        "nft_ipvs_outgoing_packets_rate",
        "IPVS virtual service EMA outgoing packets per second.",
        svc.out_pps as f64,
    );
    push_gauge(
        out,
        "nft_ipvs_incoming_bytes_rate",
        "IPVS virtual service EMA incoming bytes per second.",
        svc.in_bps as f64,
    );
    push_gauge(
        out,
        "nft_ipvs_outgoing_bytes_rate",
        "IPVS virtual service EMA outgoing bytes per second.",
        svc.out_bps as f64,
    );
}

fn push_dest_metrics(out: &mut Vec<MetricSample>, svc: &IpvsService, dest: &IpvsDestination) {
    let mut labels = BTreeMap::new();
    labels.insert("proto".to_owned(), svc.proto.clone());
    labels.insert("vip".to_owned(), svc.vip.clone());
    labels.insert("port".to_owned(), svc.port.clone());
    labels.insert("rip".to_owned(), dest.rip.clone());
    labels.insert("rport".to_owned(), dest.rport.clone());

    let push_gauge =
        |out: &mut Vec<MetricSample>, name: &'static str, help: &'static str, value: f64| {
            out.push(MetricSample::gauge(name, help, labels.clone(), value));
        };
    let push_ctr = |out: &mut Vec<MetricSample>, name, help, value| {
        out.push(MetricSample::counter(name, help, labels.clone(), value));
    };

    push_gauge(
        out,
        "nft_ipvs_dest_weight",
        "IPVS destination configured weight.",
        f64::from(dest.weight),
    );
    push_gauge(
        out,
        "nft_ipvs_dest_active_connections",
        "IPVS destination current active connections.",
        f64::from(dest.active_conns),
    );
    push_gauge(
        out,
        "nft_ipvs_dest_inactive_connections",
        "IPVS destination current inactive connections.",
        f64::from(dest.inactive_conns),
    );
    push_ctr(
        out,
        "nft_ipvs_dest_connections_total",
        "IPVS destination total connections.",
        dest.conns,
    );
    push_ctr(
        out,
        "nft_ipvs_dest_incoming_bytes_total",
        "IPVS destination total incoming bytes.",
        dest.in_bytes,
    );
    push_ctr(
        out,
        "nft_ipvs_dest_outgoing_bytes_total",
        "IPVS destination total outgoing bytes.",
        dest.out_bytes,
    );
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::panic,
    clippy::match_wildcard_for_single_variants,
    clippy::float_cmp,
    reason = "test code; inputs are controlled constants and truncation is safe for test NLA sizes"
)]
mod tests {
    use super::*;
    use crate::wire::NLA_HDRLEN;

    /// Build a single NLA (type, payload) into a Vec<u8>.
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

    /// Build a nested NLA (`NLA_F_NESTED` | type) wrapping inner bytes.
    fn make_nested(ty: u16, inner: &[u8]) -> Vec<u8> {
        make_nla(ty | 0x8000, inner)
    }

    // --- CRITICAL: IPVS_SVC_ATTR_STATS64 must be 12, not 11 -----------

    #[test]
    fn svc_attr_stats64_id_is_12() {
        assert_eq!(
            IPVS_SVC_ATTR_STATS64, 12,
            "IPVS_SVC_ATTR_STATS64 must be 12; 11 is IPVS_SVC_ATTR_PE_NAME"
        );
    }

    #[test]
    fn dest_attr_stats64_id_is_12() {
        assert_eq!(IPVS_DEST_ATTR_STATS64, 12);
    }

    #[test]
    fn dest_attr_addr_family_id_is_11() {
        assert_eq!(IPVS_DEST_ATTR_ADDR_FAMILY, 11);
    }

    // --- parse_stats64 parses all ten u64 fields ---

    #[test]
    fn parse_stats64_all_fields() {
        let mut inner = Vec::new();
        inner.extend(make_nla(IPVS_STATS_ATTR_CONNS, &100u64.to_ne_bytes()));
        inner.extend(make_nla(IPVS_STATS_ATTR_INPKTS, &200u64.to_ne_bytes()));
        inner.extend(make_nla(IPVS_STATS_ATTR_OUTPKTS, &300u64.to_ne_bytes()));
        inner.extend(make_nla(IPVS_STATS_ATTR_INBYTES, &400u64.to_ne_bytes()));
        inner.extend(make_nla(IPVS_STATS_ATTR_OUTBYTES, &500u64.to_ne_bytes()));
        inner.extend(make_nla(IPVS_STATS_ATTR_CPS, &10u64.to_ne_bytes()));
        inner.extend(make_nla(IPVS_STATS_ATTR_INPPS, &20u64.to_ne_bytes()));
        inner.extend(make_nla(IPVS_STATS_ATTR_OUTPPS, &30u64.to_ne_bytes()));
        inner.extend(make_nla(IPVS_STATS_ATTR_INBPS, &40u64.to_ne_bytes()));
        inner.extend(make_nla(IPVS_STATS_ATTR_OUTBPS, &50u64.to_ne_bytes()));

        let s = parse_stats64(&inner);
        assert_eq!(s.conns, 100);
        assert_eq!(s.in_pkts, 200);
        assert_eq!(s.out_pkts, 300);
        assert_eq!(s.in_bytes, 400);
        assert_eq!(s.out_bytes, 500);
        assert_eq!(s.cps, 10);
        assert_eq!(s.in_pps, 20);
        assert_eq!(s.out_pps, 30);
        assert_eq!(s.in_bps, 40);
        assert_eq!(s.out_bps, 50);
    }

    // --- parse_stats32 fallback widens u32 -> u64 ---

    #[test]
    fn parse_stats32_widens_to_u64() {
        let mut inner = Vec::new();
        inner.extend(make_nla(IPVS_STATS_ATTR_CONNS, &42u32.to_ne_bytes()));
        inner.extend(make_nla(IPVS_STATS_ATTR_INPKTS, &77u32.to_ne_bytes()));
        // inbytes / outbytes are u64 even in stats32 variant
        inner.extend(make_nla(IPVS_STATS_ATTR_INBYTES, &1024u64.to_ne_bytes()));
        inner.extend(make_nla(IPVS_STATS_ATTR_OUTBYTES, &2048u64.to_ne_bytes()));

        let s = parse_stats32(&inner);
        assert_eq!(s.conns, 42);
        assert_eq!(s.in_pkts, 77);
        assert_eq!(s.in_bytes, 1024);
        assert_eq!(s.out_bytes, 2048);
    }

    // --- parse_service: STATS64 preferred over STATS32 ---

    #[test]
    fn parse_service_prefers_stats64_over_stats32() {
        // STATS32 payload: conns=5
        let mut stats32 = Vec::new();
        stats32.extend(make_nla(IPVS_STATS_ATTR_CONNS, &5u32.to_ne_bytes()));
        // STATS64 payload: conns=999
        let mut stats64 = Vec::new();
        stats64.extend(make_nla(IPVS_STATS_ATTR_CONNS, &999u64.to_ne_bytes()));

        let mut buf = Vec::new();
        buf.extend(make_nla(IPVS_SVC_ATTR_AF, &AF_INET.to_ne_bytes()));
        buf.extend(make_nla(IPVS_SVC_ATTR_PROTOCOL, &6u16.to_ne_bytes()));
        let ip: u32 = 0x0A63_6363; // 10.99.99.99 BE
        buf.extend(make_nla(IPVS_SVC_ATTR_ADDR, &ip.to_be_bytes()));
        buf.extend(make_nla(IPVS_SVC_ATTR_PORT, &80u16.to_be_bytes()));
        buf.extend(make_nested(IPVS_SVC_ATTR_STATS, &stats32)); // type=10
        buf.extend(make_nested(IPVS_SVC_ATTR_STATS64, &stats64)); // type=12

        let svc = parse_service(&buf).expect("parse_service must return Some");
        assert_eq!(
            svc.conns, 999,
            "STATS64 (type=12) must win over STATS32 (type=10)"
        );
    }

    // --- parse_service: falls back to STATS32 when STATS64 absent ---

    #[test]
    fn parse_service_fallback_to_stats32() {
        let mut stats32 = Vec::new();
        stats32.extend(make_nla(IPVS_STATS_ATTR_CONNS, &88u32.to_ne_bytes()));

        let mut buf = Vec::new();
        buf.extend(make_nla(IPVS_SVC_ATTR_AF, &AF_INET.to_ne_bytes()));
        buf.extend(make_nla(IPVS_SVC_ATTR_PROTOCOL, &6u16.to_ne_bytes()));
        buf.extend(make_nla(IPVS_SVC_ATTR_PORT, &8080u16.to_be_bytes()));
        buf.extend(make_nested(IPVS_SVC_ATTR_STATS, &stats32));

        let svc = parse_service(&buf).expect("parse_service fallback");
        assert_eq!(svc.conns, 88);
    }

    // --- parse_service: type=11 is PE_NAME, must NOT be parsed as STATS64 ---

    #[test]
    fn parse_service_type11_is_pe_name_not_stats64() {
        // If old code used IPVS_SVC_ATTR_STATS64=11, this would corrupt stats.
        // Type 11 = IPVS_SVC_ATTR_PE_NAME. With the fix (STATS64=12), type 11
        // must be ignored, leaving stats at zero.
        let pe_name_bytes = b"pe_name_junk\0";
        let mut buf = Vec::new();
        buf.extend(make_nla(IPVS_SVC_ATTR_AF, &AF_INET.to_ne_bytes()));
        buf.extend(make_nla(IPVS_SVC_ATTR_PROTOCOL, &6u16.to_ne_bytes()));
        buf.extend(make_nla(11u16, pe_name_bytes)); // raw type 11 — PE_NAME
        // No STATS64 (type=12) present

        let svc = parse_service(&buf).expect("parse_service pe_name test");
        // Stats must be default zero — type 11 must NOT be parsed as stats64
        assert_eq!(
            svc.conns, 0,
            "type=11 is PE_NAME; must not be mistaken for STATS64"
        );
    }

    // --- build_dest_request wraps attrs in IPVS_CMD_ATTR_SERVICE nest ---

    #[test]
    fn build_dest_request_has_service_nest() {
        let svc = IpvsService {
            proto: "tcp".to_owned(),
            vip: "10.99.99.99".to_owned(),
            port: "80".to_owned(),
            sched: "rr".to_owned(),
            conns: 0,
            in_pkts: 0,
            out_pkts: 0,
            in_bytes: 0,
            out_bytes: 0,
            cps: 0,
            in_pps: 0,
            out_pps: 0,
            in_bps: 0,
            out_bps: 0,
        };

        let payload = build_dest_request(&svc);
        // First 4 bytes: genlmsghdr
        assert_eq!(payload[0], IPVS_CMD_GET_DEST, "cmd byte must be GET_DEST=8");
        assert_eq!(payload[1], IPVS_GENL_VERSION, "version byte must be 1");

        // Next NLA must be IPVS_CMD_ATTR_SERVICE (type=1, possibly with NLA_F_NESTED bit).
        let top_attrs: Vec<_> = parse_attrs(&payload[4..]).collect();
        assert!(
            !top_attrs.is_empty(),
            "must have at least one top-level NLA"
        );
        assert_eq!(
            top_attrs[0].ty, IPVS_CMD_ATTR_SERVICE,
            "first top-level NLA must be IPVS_CMD_ATTR_SERVICE (type=1)"
        );

        // The nest payload must contain IPVS_SVC_ATTR_AF (type=1).
        let inner_attrs: Vec<_> = parse_attrs(top_attrs[0].payload).collect();
        let has_af = inner_attrs.iter().any(|a| a.ty == IPVS_SVC_ATTR_AF);
        assert!(has_af, "service nest must contain IPVS_SVC_ATTR_AF");

        // Must contain IPVS_SVC_ATTR_PROTOCOL (type=2) for ip:port service.
        let has_proto = inner_attrs.iter().any(|a| a.ty == IPVS_SVC_ATTR_PROTOCOL);
        assert!(
            has_proto,
            "service nest must contain IPVS_SVC_ATTR_PROTOCOL for ip:port service"
        );

        // Must contain IPVS_SVC_ATTR_PORT (type=4) with big-endian 80.
        let port_attr = inner_attrs.iter().find(|a| a.ty == IPVS_SVC_ATTR_PORT);
        assert!(
            port_attr.is_some(),
            "service nest must contain IPVS_SVC_ATTR_PORT"
        );
        let port_val = read_u16_be(port_attr.unwrap().payload).expect("port must be readable");
        assert_eq!(port_val, 80u16, "port must be 80 (big-endian on wire)");
    }

    // --- build_dest_request: fwmark service uses FWMARK attr, not PORT ---

    #[test]
    fn build_dest_request_fwmark_service() {
        let svc = IpvsService {
            proto: "tcp".to_owned(),
            vip: String::new(),
            port: "0x1f".to_owned(), // fwmark=31
            sched: "rr".to_owned(),
            conns: 0,
            in_pkts: 0,
            out_pkts: 0,
            in_bytes: 0,
            out_bytes: 0,
            cps: 0,
            in_pps: 0,
            out_pps: 0,
            in_bps: 0,
            out_bps: 0,
        };

        let payload = build_dest_request(&svc);
        let top_attrs: Vec<_> = parse_attrs(&payload[4..]).collect();
        assert_eq!(top_attrs[0].ty, IPVS_CMD_ATTR_SERVICE);

        let inner_attrs: Vec<_> = parse_attrs(top_attrs[0].payload).collect();
        let has_fwmark = inner_attrs.iter().any(|a| a.ty == IPVS_SVC_ATTR_FWMARK);
        assert!(
            has_fwmark,
            "fwmark service must contain IPVS_SVC_ATTR_FWMARK"
        );
        let has_port = inner_attrs.iter().any(|a| a.ty == IPVS_SVC_ATTR_PORT);
        assert!(
            !has_port,
            "fwmark service must NOT contain IPVS_SVC_ATTR_PORT"
        );
    }

    // --- parse_destination: reads IPVS_DEST_ATTR_ADDR_FAMILY (id=11) for AF ---

    #[test]
    fn parse_destination_uses_dest_addr_family() {
        // Service is fwmark (vip="") so svc_af defaults to AF_INET.
        // Destination has ADDR_FAMILY=AF_INET6 and a 16-byte addr.
        let svc = IpvsService {
            proto: "tcp".to_owned(),
            vip: String::new(),
            port: "0x1".to_owned(),
            sched: "rr".to_owned(),
            conns: 0,
            in_pkts: 0,
            out_pkts: 0,
            in_bytes: 0,
            out_bytes: 0,
            cps: 0,
            in_pps: 0,
            out_pps: 0,
            in_bps: 0,
            out_bps: 0,
        };

        // IPv6 loopback ::1
        let v6_addr: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut buf = Vec::new();
        buf.extend(make_nla(
            IPVS_DEST_ATTR_ADDR_FAMILY,
            &AF_INET6.to_ne_bytes(),
        ));
        buf.extend(make_nla(IPVS_DEST_ATTR_ADDR, &v6_addr));
        buf.extend(make_nla(IPVS_DEST_ATTR_PORT, &9100u16.to_be_bytes()));
        buf.extend(make_nla(IPVS_DEST_ATTR_WEIGHT, &1u32.to_ne_bytes()));

        let dest = parse_destination(&buf, &svc).expect("must parse destination");
        assert_eq!(dest.rip, "::1", "IPv6 address must be decoded correctly");
        assert_eq!(dest.rport, "9100");
        assert_eq!(dest.weight, 1);
    }

    // --- parse_destination: reads weight (IPVS_DEST_ATTR_WEIGHT, id=4) ---

    #[test]
    fn parse_destination_reads_weight() {
        let svc = IpvsService {
            proto: "tcp".to_owned(),
            vip: "10.0.0.1".to_owned(),
            port: "80".to_owned(),
            sched: "rr".to_owned(),
            conns: 0,
            in_pkts: 0,
            out_pkts: 0,
            in_bytes: 0,
            out_bytes: 0,
            cps: 0,
            in_pps: 0,
            out_pps: 0,
            in_bps: 0,
            out_bps: 0,
        };

        let mut buf = Vec::new();
        buf.extend(make_nla(
            IPVS_DEST_ATTR_ADDR,
            &Ipv4Addr::new(127, 0, 0, 1).octets(),
        ));
        buf.extend(make_nla(IPVS_DEST_ATTR_PORT, &9100u16.to_be_bytes()));
        buf.extend(make_nla(IPVS_DEST_ATTR_WEIGHT, &5u32.to_ne_bytes()));
        buf.extend(make_nla(IPVS_DEST_ATTR_ACTIVE_CONNS, &3u32.to_ne_bytes()));
        buf.extend(make_nla(IPVS_DEST_ATTR_INACT_CONNS, &1u32.to_ne_bytes()));

        let dest = parse_destination(&buf, &svc).expect("must parse dest");
        assert_eq!(dest.weight, 5);
        assert_eq!(dest.active_conns, 3);
        assert_eq!(dest.inactive_conns, 1);
    }

    // --- addr_to_str handles IPv4 and IPv6 ---

    #[test]
    fn addr_to_str_ipv4() {
        let bytes = Ipv4Addr::new(10, 99, 99, 99).octets();
        assert_eq!(addr_to_str(AF_INET, &bytes), "10.99.99.99");
    }

    #[test]
    fn addr_to_str_ipv6_loopback() {
        let bytes: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(addr_to_str(AF_INET6, &bytes), "::1");
    }

    #[test]
    fn addr_to_str_unknown_af_returns_empty() {
        assert_eq!(addr_to_str(99, &[1, 2, 3, 4]), String::new());
    }

    // --- MC-006: rate gauge names use _rate suffix, not _per_second ---

    fn make_test_svc() -> IpvsService {
        IpvsService {
            proto: "tcp".to_owned(),
            vip: "10.0.0.1".to_owned(),
            port: "80".to_owned(),
            sched: "rr".to_owned(),
            conns: 0,
            in_pkts: 0,
            out_pkts: 0,
            in_bytes: 0,
            out_bytes: 0,
            cps: 10,
            in_pps: 20,
            out_pps: 30,
            in_bps: 40,
            out_bps: 50,
        }
    }

    #[test]
    fn push_svc_metrics_uses_rate_suffix_not_per_second() {
        let svc = make_test_svc();
        let labels = svc_labels(&svc);
        let mut out = Vec::new();
        push_svc_metrics(&mut out, &svc, &labels);

        let names: Vec<&str> = out.iter().map(|s| s.name).collect();

        // _rate gauges must be present.
        assert!(
            names.contains(&"nft_ipvs_connections_rate"),
            "connections_rate gauge must exist"
        );
        assert!(
            names.contains(&"nft_ipvs_incoming_packets_rate"),
            "incoming_packets_rate gauge must exist"
        );
        assert!(
            names.contains(&"nft_ipvs_outgoing_packets_rate"),
            "outgoing_packets_rate gauge must exist"
        );
        assert!(
            names.contains(&"nft_ipvs_incoming_bytes_rate"),
            "incoming_bytes_rate gauge must exist"
        );
        assert!(
            names.contains(&"nft_ipvs_outgoing_bytes_rate"),
            "outgoing_bytes_rate gauge must exist"
        );

        // _per_second gauges must NOT appear (MC-006 rename).
        for name in &names {
            assert!(
                !name.ends_with("_per_second"),
                "gauge name must not use _per_second suffix (MC-006): {name}"
            );
        }
    }

    #[test]
    fn push_svc_metrics_rate_values_match_stats() {
        let svc = make_test_svc();
        let labels = svc_labels(&svc);
        let mut out = Vec::new();
        push_svc_metrics(&mut out, &svc, &labels);

        let find_f64 = |name: &str| -> f64 {
            let s = out.iter().find(|s| s.name == name).expect(name);
            match s.value {
                nlx_domain::metric::MetricValue::F64(v) => v,
                _ => panic!("{name} must have F64 value"),
            }
        };

        assert!((find_f64("nft_ipvs_connections_rate") - 10.0_f64).abs() < f64::EPSILON);
        assert!((find_f64("nft_ipvs_incoming_packets_rate") - 20.0_f64).abs() < f64::EPSILON);
        assert!((find_f64("nft_ipvs_outgoing_packets_rate") - 30.0_f64).abs() < f64::EPSILON);
        assert!((find_f64("nft_ipvs_incoming_bytes_rate") - 40.0_f64).abs() < f64::EPSILON);
        assert!((find_f64("nft_ipvs_outgoing_bytes_rate") - 50.0_f64).abs() < f64::EPSILON);
    }
}
