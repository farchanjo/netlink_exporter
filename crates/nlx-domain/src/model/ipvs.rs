//! IPVS genetlink read models.

use serde::{Deserialize, Serialize};

/// IPVS virtual service read model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpvsService {
    /// Protocol string: `"tcp"`, `"udp"`, `"sctp"`.
    pub proto: String,
    /// Virtual IP in presentation form (IPv4 or IPv6); empty for fwmark services.
    pub vip: String,
    /// Port as decimal string, or fwmark as hex string.
    pub port: String,
    /// Scheduler name (e.g. `"rr"`, `"lc"`, `"wlc"`).
    pub sched: String,
    /// Total connections (`IPVS_STATS64_ATTR_CONNS`).
    pub conns: u64,
    /// Total incoming packets.
    pub in_pkts: u64,
    /// Total outgoing packets.
    pub out_pkts: u64,
    /// Total incoming bytes.
    pub in_bytes: u64,
    /// Total outgoing bytes.
    pub out_bytes: u64,
    /// EMA connections per second.
    pub cps: u64,
    /// EMA incoming packets per second.
    pub in_pps: u64,
    /// EMA outgoing packets per second.
    pub out_pps: u64,
    /// EMA incoming bytes per second.
    pub in_bps: u64,
    /// EMA outgoing bytes per second.
    pub out_bps: u64,
}

/// IPVS real-server destination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpvsDestination {
    /// Parent virtual service proto.
    pub svc_proto: String,
    /// Parent virtual IP.
    pub svc_vip: String,
    /// Parent virtual port.
    pub svc_port: String,
    /// Real server IP in presentation form.
    pub rip: String,
    /// Real server port as decimal string.
    pub rport: String,
    /// Current active connections.
    pub active_conns: u32,
    /// Current inactive connections.
    pub inactive_conns: u32,
    /// Total connections to this destination.
    pub conns: u64,
    /// Total incoming bytes to this destination.
    pub in_bytes: u64,
    /// Total outgoing bytes from this destination.
    pub out_bytes: u64,
}
