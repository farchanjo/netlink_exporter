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
//! ## Cardinality
//!
//! Labels: `{proto, vip, port}` for services; `{proto, vip, port, rip, rport}`
//! for destinations.  Per-flow / per-IP addresses are bounded by the IPVS
//! service table (operator-controlled).  Hard cap: 512 services, 256 dests/svc.

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
    wire::{nested_attrs, parse_attrs, read_u16, read_u16_be, read_u32, read_u64},
};

const NETLINK_GENERIC: i32 = 16;

// genlmsghdr commands (IPVS_GENL_VERSION = 1).
const IPVS_CMD_GET_SERVICE: u8 = 4;
const IPVS_CMD_GET_DEST: u8 = 8;
const IPVS_GENL_VERSION: u8 = 1;

// IPVS service attribute types (enum ipvs_svc_attrs, §13.4).
const IPVS_SVC_ATTR_AF: u16 = 1;
const IPVS_SVC_ATTR_PROTOCOL: u16 = 2;
const IPVS_SVC_ATTR_ADDR: u16 = 3;
const IPVS_SVC_ATTR_PORT: u16 = 4;
const IPVS_SVC_ATTR_FWMARK: u16 = 5;
const IPVS_SVC_ATTR_SCHED_NAME: u16 = 6;
const IPVS_SVC_ATTR_STATS64: u16 = 11;

// IPVS destination attribute types (enum ipvs_dest_attrs, §13.5).
const IPVS_DEST_ATTR_ADDR: u16 = 1;
const IPVS_DEST_ATTR_PORT: u16 = 2;
const IPVS_DEST_ATTR_ACTIVE_CONNS: u16 = 7;
const IPVS_DEST_ATTR_INACT_CONNS: u16 = 8;
const IPVS_DEST_ATTR_STATS64: u16 = 12;

// IPVS stats64 inner attr types (enum ipvs_stats_attrs, §13.6).
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

// Cardinality hard caps (§13.8).
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
    fn name(&self) -> &str {
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
        let attrs = &frame[4..];
        if let Some(svc) = parse_service(attrs) {
            result.push(svc);
        }
    }
    Ok(result)
}

async fn dump_dests_for(
    sock: &mut NetlinkSocket,
    family_id: u16,
    svc: &IpvsService,
) -> Result<Vec<IpvsDestination>, DomainError> {
    // Build GET_DEST request with service key attrs.
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
        let attrs = &frame[4..];
        if let Some(dest) = parse_destination(attrs, svc) {
            result.push(dest);
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

/// Build a GET_DEST request referencing the given virtual service.
fn build_dest_request(svc: &IpvsService) -> Vec<u8> {
    use crate::wire::{NLA_HDRLEN, align4};

    let mut buf = vec![IPVS_CMD_GET_DEST, IPVS_GENL_VERSION, 0u8, 0u8];

    // Encode protocol as u16.
    let proto: u16 = match svc.proto.as_str() {
        "tcp" => 6,
        "udp" => 17,
        "sctp" => 132,
        _ => 0,
    };

    let push = |buf: &mut Vec<u8>, ty: u16, payload: &[u8]| {
        let nla_len = (NLA_HDRLEN + payload.len()) as u16;
        buf.extend_from_slice(&nla_len.to_ne_bytes());
        buf.extend_from_slice(&ty.to_ne_bytes());
        buf.extend_from_slice(payload);
        let pad = align4(NLA_HDRLEN + payload.len()) - (NLA_HDRLEN + payload.len());
        buf.extend(std::iter::repeat_n(0u8, pad));
    };

    // AF — u16 based on VIP format.
    let af: u16 = if svc.vip.contains(':') {
        AF_INET6
    } else {
        AF_INET
    };
    push(&mut buf, IPVS_SVC_ATTR_AF, &af.to_ne_bytes());
    push(&mut buf, IPVS_SVC_ATTR_PROTOCOL, &proto.to_ne_bytes());

    // Encode VIP address (network byte order).
    if !svc.vip.is_empty() {
        if let Ok(v4) = svc.vip.parse::<Ipv4Addr>() {
            push(&mut buf, IPVS_SVC_ATTR_ADDR, &v4.octets());
        } else if let Ok(v6) = svc.vip.parse::<Ipv6Addr>() {
            push(&mut buf, IPVS_SVC_ATTR_ADDR, &v6.octets());
        }
    }

    // Encode port (network byte order).
    if let Ok(port) = svc.port.parse::<u16>() {
        push(&mut buf, IPVS_SVC_ATTR_PORT, &port.to_be_bytes());
    }

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

fn parse_service(attrs_buf: &[u8]) -> Option<IpvsService> {
    let mut af: u16 = AF_INET;
    let mut proto: u16 = 0;
    let mut addr_bytes: Option<Vec<u8>> = None;
    let mut port: u16 = 0;
    let mut fwmark: u32 = 0;
    let mut sched = String::from("unknown");
    let mut stats = Stats64::default();

    for attr in parse_attrs(attrs_buf) {
        match attr.ty {
            IPVS_SVC_ATTR_AF => af = read_u16(attr.payload).unwrap_or(AF_INET),
            IPVS_SVC_ATTR_PROTOCOL => proto = read_u16(attr.payload).unwrap_or(0),
            IPVS_SVC_ATTR_ADDR => addr_bytes = Some(attr.payload.to_vec()),
            IPVS_SVC_ATTR_PORT => {
                // Network byte order (§13.4, G-29).
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
                stats = parse_stats64(attr.payload);
            }
            _ => {}
        }
    }

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

fn parse_destination(attrs_buf: &[u8], svc: &IpvsService) -> Option<IpvsDestination> {
    let af: u16 = if svc.vip.contains(':') {
        AF_INET6
    } else {
        AF_INET
    };
    let mut addr_bytes: Option<Vec<u8>> = None;
    let mut rport: u16 = 0;
    let mut active: u32 = 0;
    let mut inactive: u32 = 0;
    let mut stats = Stats64::default();

    for attr in parse_attrs(attrs_buf) {
        match attr.ty {
            IPVS_DEST_ATTR_ADDR => addr_bytes = Some(attr.payload.to_vec()),
            IPVS_DEST_ATTR_PORT => {
                rport = read_u16_be(attr.payload).unwrap_or(0);
            }
            IPVS_DEST_ATTR_ACTIVE_CONNS => active = read_u32(attr.payload).unwrap_or(0),
            IPVS_DEST_ATTR_INACT_CONNS => inactive = read_u32(attr.payload).unwrap_or(0),
            IPVS_DEST_ATTR_STATS64 => {
                stats = parse_stats64(attr.payload);
            }
            _ => {}
        }
    }

    let rip = addr_to_str(af, addr_bytes.as_deref().unwrap_or(&[]));
    Some(IpvsDestination {
        svc_proto: svc.proto.clone(),
        svc_vip: svc.vip.clone(),
        svc_port: svc.port.clone(),
        rip,
        rport: rport.to_string(),
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
    push_gauge(
        out,
        "nft_ipvs_connections_per_second",
        "IPVS virtual service EMA connections per second.",
        svc.cps as f64,
    );
    push_gauge(
        out,
        "nft_ipvs_incoming_packets_per_second",
        "IPVS virtual service EMA incoming packets per second.",
        svc.in_pps as f64,
    );
    push_gauge(
        out,
        "nft_ipvs_outgoing_packets_per_second",
        "IPVS virtual service EMA outgoing packets per second.",
        svc.out_pps as f64,
    );
    push_gauge(
        out,
        "nft_ipvs_incoming_bytes_per_second",
        "IPVS virtual service EMA incoming bytes per second.",
        svc.in_bps as f64,
    );
    push_gauge(
        out,
        "nft_ipvs_outgoing_bytes_per_second",
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
