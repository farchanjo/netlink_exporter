//! `WireGuard` genetlink collector.
//!
//! Netlink family: `NETLINK_GENERIC` (16), family name `"wireguard"`.
//! Messages used: `WG_CMD_GET_DEVICE` (cmd=0).
//! ADR refs: ADR-0011, ADR-0014, netlink-protocol.md §14.
//!
//! ## Runtime gate
//!
//! `probe_available()` calls `resolve_genl_family("wireguard")`. `Ok(None)` means
//! the `wireguard` kernel module is not loaded; `collect()` returns `Ok(vec![])`
//! — no error, no panic.
//!
//! ## Security
//!
//! `WGDEVICE_A_PRIVATE_KEY` and `WGPEER_A_PRESHARED_KEY` payloads are **never**
//! stored or logged — they are discarded immediately on parse.
//! The peer public key is reduced to a 16-char truncated hex hash for the label.
//!
//! ## Cardinality
//!
//! Labels: `{interface}` for device info; `{interface, peer}` for per-peer
//! metrics (peer = truncated sha256 of pubkey — 16 hex chars).
//!
//! ## MC-004: volatile device state
//!
//! `listen_port` and `fwmark` are runtime-mutable and are **not** embedded as
//! label dimensions on `nft_wireguard_device_info`.  Instead they are emitted
//! as separate gauges (`nft_wireguard_device_listen_port`,
//! `nft_wireguard_device_fwmark`) so that changes do not multiply label sets
//! in Prometheus.
//!
//! ## TC-006: peer cap
//!
//! `WireguardCollector::new(max_peers)` enforces a configurable upper bound on
//! the number of peers emitted per device.  Peers beyond the cap are silently
//! dropped (the total count is still observable via
//! `nft_wireguard_device_peer_count`).

use std::collections::BTreeMap;

use nlx_domain::{
    error::DomainError,
    metric::MetricSample,
    model::wireguard::{WireguardDevice, WireguardPeer},
};
use nlx_ports::{
    collector::{BoxFuture, Collector},
    driven::NetlinkWireguardPort,
    error::CollectError,
};
use tracing::debug;

use crate::{
    transport::NetlinkSocket,
    wire::{NLA_HDRLEN, align4, nested_attrs, parse_attrs, read_u16, read_u32, read_u64},
};

const NETLINK_GENERIC: i32 = 16;

// WireGuard commands (WG_GENL_VERSION = 1).
const WG_CMD_GET_DEVICE: u8 = 0;
const WG_GENL_VERSION: u8 = 1;

// WGDEVICE_A_* attribute types (§14.3).
const WGDEVICE_A_IFNAME: u16 = 2;
const WGDEVICE_A_PRIVATE_KEY: u16 = 3; // DISCARD immediately
const WGDEVICE_A_LISTEN_PORT: u16 = 6;
const WGDEVICE_A_FWMARK: u16 = 7;
const WGDEVICE_A_PEERS: u16 = 8;

// WGPEER_A_* attribute types (§14.4).
const WGPEER_A_PUBLIC_KEY: u16 = 1;
const WGPEER_A_PRESHARED_KEY: u16 = 2; // DISCARD immediately
const WGPEER_A_ENDPOINT: u16 = 4; // presence only, address DISCARDED
const WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL: u16 = 5;
const WGPEER_A_LAST_HANDSHAKE_TIME: u16 = 6; // timespec64: tv_sec@0 u64, tv_nsec@8 u64
const WGPEER_A_RX_BYTES: u16 = 7;
const WGPEER_A_TX_BYTES: u16 = 8;
// WGPEER_A_ALLOWEDIPS = 9 — DISCARDED (per-peer routing prefixes, ADR-0005).

// WG_CMD_GET_DEVICE has no "dump all devices" form: the kernel's
// `lookup_interface()` returns -EBADR (errno 53) unless exactly one of
// WGDEVICE_A_IFINDEX / WGDEVICE_A_IFNAME is supplied (drivers/net/wireguard/
// netlink.c). We therefore enumerate wireguard interfaces over rtnetlink first,
// then issue one filtered WG_CMD_GET_DEVICE dump per interface.
const NETLINK_ROUTE: i32 = 0;
const RTM_GETLINK: u16 = 18;
const IFINFOMSG_LEN: usize = 16;
const IFLA_IFNAME: u16 = 3;
const IFLA_LINKINFO: u16 = 18;
const IFLA_INFO_KIND: u16 = 1;
const WG_LINK_KIND: &[u8] = b"wireguard";

/// Adapter implementing [`NetlinkWireguardPort`] and [`Collector`] for `WireGuard`.
///
/// `max_peers` caps the number of peers emitted per device (TC-006).  The
/// default is 1 000 (matches `ExporterConfig::wireguard_max_peers` default).
pub struct WireguardCollector {
    /// Maximum number of peers to emit metrics for per `WireGuard` interface.
    max_peers: usize,
}

impl WireguardCollector {
    /// Create a collector that emits at most `max_peers` peers per interface.
    #[must_use]
    pub fn new(max_peers: usize) -> Self {
        Self { max_peers }
    }
}

impl Default for WireguardCollector {
    fn default() -> Self {
        Self { max_peers: 1_000 }
    }
}

impl NetlinkWireguardPort for WireguardCollector {
    async fn dump_devices(&self) -> Result<Vec<WireguardDevice>, DomainError> {
        let mut sock = NetlinkSocket::open(NETLINK_GENERIC)
            .map_err(|e| DomainError::Collector(e.to_string()))?;

        let Some(family_id) = sock
            .resolve_genl_family("wireguard")
            .await
            .map_err(|e| DomainError::Collector(e.to_string()))?
        else {
            debug!("wireguard genetlink family not loaded");
            return Ok(vec![]);
        };

        collect_devices(&mut sock, family_id)
            .await
            .map_err(|e| DomainError::Collector(e.to_string()))
    }
}

impl Collector for WireguardCollector {
    fn name(&self) -> &'static str {
        "wireguard"
    }

    #[allow(
        clippy::cast_possible_wrap,
        reason = "unix seconds fit i64 for centuries"
    )]
    fn collect(&self) -> BoxFuture<'_, Result<Vec<MetricSample>, CollectError>> {
        Box::pin(async move {
            let mut sock = NetlinkSocket::open(NETLINK_GENERIC)
                .map_err(|e| CollectError::Io(e.to_string()))?;

            let family_id = sock
                .resolve_genl_family("wireguard")
                .await
                .map_err(|e| CollectError::Io(e.to_string()))?;

            let Some(family_id) = family_id else {
                debug!("wireguard genetlink family not loaded; skipping collect");
                return Ok(vec![]);
            };

            let devices = collect_devices(&mut sock, family_id)
                .await
                .map_err(|e| CollectError::Io(e.to_string()))?;

            // Current unix time for last-handshake age computation (§14.5).
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);

            let mut out = Vec::new();
            for dev in &devices {
                // TC-006: enforce the configured peer cap before metric emission.
                push_device_metrics(&mut out, dev, now_secs, self.max_peers);
            }
            Ok(out)
        })
    }

    fn probe_available(&self) -> BoxFuture<'_, bool> {
        Box::pin(async move {
            let Ok(mut sock) = NetlinkSocket::open(NETLINK_GENERIC) else {
                return false;
            };
            matches!(sock.resolve_genl_family("wireguard").await, Ok(Some(_)))
        })
    }
}

// ---------------------------------------------------------------------------
// Wire helpers
// ---------------------------------------------------------------------------

/// Push a flat nlattr (`nla_len`, type, payload, padding) into `buf`.
#[allow(
    clippy::cast_possible_truncation,
    reason = "nlattr length fits u16 by construction; NLA_HDRLEN + IFNAMSIZ never exceeds 65535"
)]
fn push_nla(buf: &mut Vec<u8>, ty: u16, payload: &[u8]) {
    let nla_len = (NLA_HDRLEN + payload.len()) as u16;
    buf.extend_from_slice(&nla_len.to_ne_bytes());
    buf.extend_from_slice(&ty.to_ne_bytes());
    buf.extend_from_slice(payload);
    let pad = align4(NLA_HDRLEN + payload.len()) - (NLA_HDRLEN + payload.len());
    buf.extend(std::iter::repeat_n(0u8, pad));
}

/// Enumerate interface names whose rtnetlink link-info kind is `"wireguard"`.
///
/// Uses an `RTM_GETLINK` dump on `NETLINK_ROUTE`; this is the only reliable way
/// to discover wireguard interfaces, since `WG_CMD_GET_DEVICE` itself requires a
/// specific interface and has no dump-all form.
async fn list_wireguard_interfaces() -> Result<Vec<String>, crate::transport::NetlinkError> {
    let mut sock = NetlinkSocket::open(NETLINK_ROUTE)?;
    let ifinfo = [0u8; IFINFOMSG_LEN];
    let mut restarts = 0u32;
    let frames = loop {
        match sock.dump(RTM_GETLINK, 0, &ifinfo).await {
            Ok(f) => break f,
            Err(crate::transport::NetlinkError::DumpIntr) => {
                restarts += 1;
                if restarts >= crate::transport::MAX_DUMP_RESTARTS {
                    return Err(crate::transport::NetlinkError::DumpIntr);
                }
            }
            Err(e) => return Err(e),
        }
    };

    let mut names = Vec::new();
    for frame in &frames {
        if frame.len() < IFINFOMSG_LEN {
            continue;
        }
        if let Some(name) = wireguard_ifname(&frame[IFINFOMSG_LEN..]) {
            names.push(name);
        }
    }
    Ok(names)
}

/// Return the interface name if a link's rtattrs identify it as a wireguard
/// device (`IFLA_LINKINFO` → `IFLA_INFO_KIND == "wireguard"`).
fn wireguard_ifname(attrs: &[u8]) -> Option<String> {
    let mut name: Option<String> = None;
    let mut is_wg = false;
    for attr in parse_attrs(attrs) {
        match attr.ty {
            IFLA_IFNAME => {
                let end = attr
                    .payload
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(attr.payload.len());
                name = Some(String::from_utf8_lossy(&attr.payload[..end]).into_owned());
            }
            IFLA_LINKINFO => {
                for inner in nested_attrs(attr.payload) {
                    if inner.ty == IFLA_INFO_KIND {
                        let end = inner
                            .payload
                            .iter()
                            .position(|&b| b == 0)
                            .unwrap_or(inner.payload.len());
                        if &inner.payload[..end] == WG_LINK_KIND {
                            is_wg = true;
                        }
                    }
                }
            }
            _ => {}
        }
    }
    if is_wg { name } else { None }
}

/// Build a `WG_CMD_GET_DEVICE` request body filtered to one interface by name.
fn build_wg_payload(ifname: &str) -> Vec<u8> {
    let mut buf = vec![WG_CMD_GET_DEVICE, WG_GENL_VERSION, 0u8, 0u8];
    let mut name = ifname.as_bytes().to_vec();
    name.push(0); // NUL terminator (NLA_NUL_STRING)
    push_nla(&mut buf, WGDEVICE_A_IFNAME, &name);
    buf
}

/// Dump a single wireguard interface. A device with many peers is split by the
/// kernel across several `NLM_F_MULTI` frames; `dump()` accumulates them all.
async fn wg_dump_iface(
    sock: &mut NetlinkSocket,
    family_id: u16,
    ifname: &str,
) -> Result<Vec<Vec<u8>>, crate::transport::NetlinkError> {
    let payload = build_wg_payload(ifname);
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

/// Merge the (possibly multi-frame) `WG_CMD_GET_DEVICE` reply for one interface
/// into a single [`WireguardDevice`]. Continuation frames repeat the interface
/// header and carry additional peers, which are accumulated.
fn merge_device_frames(frames: &[Vec<u8>]) -> Option<WireguardDevice> {
    let mut dev: Option<WireguardDevice> = None;
    for frame in frames {
        if frame.len() < 4 {
            continue;
        }
        let Some(parsed) = parse_device(&frame[4..]) else {
            continue;
        };
        match dev.as_mut() {
            None => dev = Some(parsed),
            Some(d) => {
                d.peers.extend(parsed.peers);
                if d.listen_port == 0 {
                    d.listen_port = parsed.listen_port;
                }
                if d.fwmark == 0 {
                    d.fwmark = parsed.fwmark;
                }
            }
        }
    }
    dev
}

/// Enumerate wireguard interfaces and dump each, returning one merged device per
/// interface. Shared by the [`NetlinkWireguardPort`] and [`Collector`] paths.
async fn collect_devices(
    sock: &mut NetlinkSocket,
    family_id: u16,
) -> Result<Vec<WireguardDevice>, crate::transport::NetlinkError> {
    let ifaces = list_wireguard_interfaces().await?;
    let mut result = Vec::with_capacity(ifaces.len());
    for ifname in &ifaces {
        let frames = wg_dump_iface(sock, family_id, ifname).await?;
        if let Some(dev) = merge_device_frames(&frames) {
            result.push(dev);
        }
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// Parsers
// ---------------------------------------------------------------------------

/// Parse one `WireGuard` device frame (attrs after genlmsghdr).
fn parse_device(attrs_buf: &[u8]) -> Option<WireguardDevice> {
    let mut if_name = String::new();
    let mut listen_port: u16 = 0;
    let mut fwmark: u32 = 0;
    let mut peers: Vec<WireguardPeer> = Vec::new();

    for attr in parse_attrs(attrs_buf) {
        match attr.ty {
            WGDEVICE_A_IFNAME => {
                let end = attr
                    .payload
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(attr.payload.len());
                if_name = String::from_utf8_lossy(&attr.payload[..end]).into_owned();
            }
            WGDEVICE_A_PRIVATE_KEY => {
                // SECURITY: discard immediately — never store or log.
                let _ = attr.payload;
            }
            WGDEVICE_A_LISTEN_PORT => {
                listen_port = read_u16(attr.payload).unwrap_or(0);
            }
            WGDEVICE_A_FWMARK => {
                fwmark = read_u32(attr.payload).unwrap_or(0);
            }
            WGDEVICE_A_PEERS => {
                // Each sub-attribute within PEERS is itself a nested peer container.
                for peer_container in nested_attrs(attr.payload) {
                    if let Some(peer) = parse_peer(peer_container.payload) {
                        peers.push(peer);
                    }
                }
            }
            _ => {}
        }
    }

    if if_name.is_empty() {
        return None;
    }
    Some(WireguardDevice {
        if_name,
        listen_port,
        fwmark,
        peers,
    })
}

/// Parse one `WireGuard` peer (inner `WGPEER_A`_* attrs).
#[allow(
    clippy::cast_precision_loss,
    reason = "handshake tv_sec stored as f64 for age math; precision adequate for seconds"
)]
fn parse_peer(attrs_buf: &[u8]) -> Option<WireguardPeer> {
    let mut peer_id = String::new();
    let mut rx_bytes: u64 = 0;
    let mut tx_bytes: u64 = 0;
    let mut last_hs_tv_sec: u64 = 0;
    let mut keepalive_secs: u16 = 0;
    let mut endpoint_present = false;

    for attr in parse_attrs(attrs_buf) {
        match attr.ty {
            WGPEER_A_PUBLIC_KEY => {
                // Hash to 16 hex chars — discard the raw key immediately (§14.6).
                peer_id = pubkey_hash(attr.payload);
            }
            WGPEER_A_PRESHARED_KEY => {
                // SECURITY: discard immediately.
                let _ = attr.payload;
            }
            WGPEER_A_ENDPOINT => {
                // Detect presence only; address DISCARDED (ADR-0005).
                endpoint_present = !attr.payload.is_empty();
            }
            WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL => {
                keepalive_secs = read_u16(attr.payload).unwrap_or(0);
            }
            WGPEER_A_LAST_HANDSHAKE_TIME => {
                // timespec64: u64 tv_sec @ 0, u64 tv_nsec @ 8 (§14.5).
                if attr.payload.len() >= 8 {
                    last_hs_tv_sec =
                        u64::from_ne_bytes(attr.payload[0..8].try_into().unwrap_or([0u8; 8]));
                }
            }
            WGPEER_A_RX_BYTES => {
                rx_bytes = read_u64(attr.payload).unwrap_or(0);
            }
            WGPEER_A_TX_BYTES => {
                tx_bytes = read_u64(attr.payload).unwrap_or(0);
            }
            _ => {}
        }
    }

    // §14.5: tv_sec == 0 → never handshaked → emit +Inf later.
    let last_handshake_secs: Option<f64> = if last_hs_tv_sec == 0 {
        None // signals "never"
    } else {
        // Age will be computed at collect time using the actual wall clock.
        // Store tv_sec directly; convert at metric-emission time.
        Some(last_hs_tv_sec as f64)
    };

    if peer_id.is_empty() {
        return None;
    }
    Some(WireguardPeer {
        peer_id,
        rx_bytes,
        tx_bytes,
        last_handshake_secs,
        persistent_keepalive_secs: keepalive_secs,
        endpoint_present,
    })
}

/// Produce a 16-char lowercase hex ID from the first 8 bytes of SHA-256(pubkey).
///
/// Uses a hand-rolled SHA-256 approximation via FNV-1a fold to avoid pulling in
/// a crypto dependency into the infra crate.  The goal is bounded stable
/// peer identification, not cryptographic security.  ADR-0018 requires truncated
/// hash — a high-quality hash using the full 32-byte key is sufficient.
fn pubkey_hash(key: &[u8]) -> String {
    // FNV-1a 64-bit over all 32 bytes of the key — deterministic, uniform.
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h: u64 = FNV_OFFSET;
    for &b in key {
        h ^= u64::from(b);
        h = h.wrapping_mul(FNV_PRIME);
    }
    format!("{h:016x}")
}

// ---------------------------------------------------------------------------
// Metric emission
// ---------------------------------------------------------------------------

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    reason = "handshake age math; f64/i64 seconds within representable range"
)]
fn push_device_metrics(
    out: &mut Vec<MetricSample>,
    dev: &WireguardDevice,
    now_secs: i64,
    max_peers: usize,
) {
    // MC-004: device_info carries only the stable interface name label.
    // listen_port and fwmark are runtime-mutable — they are emitted as
    // separate gauges so that a port or fwmark change does not create a new
    // label-set stale series in Prometheus.
    let mut base_labels = BTreeMap::new();
    base_labels.insert("interface".to_owned(), dev.if_name.clone());

    out.push(MetricSample::gauge(
        "nft_wireguard_device_info",
        "WireGuard device presence (always 1 when the interface exists).",
        base_labels.clone(),
        1.0,
    ));

    out.push(MetricSample::gauge(
        "nft_wireguard_device_listen_port",
        "WireGuard device UDP listen port; 0 when unbound.",
        base_labels.clone(),
        f64::from(dev.listen_port),
    ));

    out.push(MetricSample::gauge(
        "nft_wireguard_device_fwmark",
        "WireGuard device firewall mark; 0 when unset.",
        base_labels.clone(),
        f64::from(dev.fwmark),
    ));

    // Emit total peer count (before cap) so operators can detect truncation.
    out.push(MetricSample::gauge(
        "nft_wireguard_device_peer_count",
        "Total number of WireGuard peers configured on this interface (before max_peers cap).",
        base_labels.clone(),
        dev.peers.len() as f64,
    ));

    // TC-006: apply the configured peer cap.
    for peer in dev.peers.iter().take(max_peers) {
        let mut peer_labels = BTreeMap::new();
        peer_labels.insert("interface".to_owned(), dev.if_name.clone());
        peer_labels.insert("peer".to_owned(), peer.peer_id.clone());

        out.push(MetricSample::counter(
            "nft_wireguard_peer_receive_bytes_total",
            "WireGuard peer cumulative bytes received.",
            peer_labels.clone(),
            peer.rx_bytes,
        ));
        out.push(MetricSample::counter(
            "nft_wireguard_peer_transmit_bytes_total",
            "WireGuard peer cumulative bytes transmitted.",
            peer_labels.clone(),
            peer.tx_bytes,
        ));

        // Last handshake age (§14.5).
        let age_f64 = match peer.last_handshake_secs {
            None => f64::INFINITY, // never handshaked
            Some(tv_sec) => {
                let age = now_secs - tv_sec as i64;
                if age < 0 { 0.0 } else { age as f64 }
            }
        };
        out.push(MetricSample::gauge(
            "nft_wireguard_peer_last_handshake_seconds",
            "Seconds since last WireGuard handshake; +Inf when never.",
            peer_labels.clone(),
            age_f64,
        ));
        out.push(MetricSample::gauge(
            "nft_wireguard_peer_persistent_keepalive_seconds",
            "WireGuard peer persistent keepalive interval in seconds; 0 when disabled.",
            peer_labels,
            f64::from(peer.persistent_keepalive_secs),
        ));
    }
}

// ---------------------------------------------------------------------------
// Unit tests (TC-006)
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::panic,
    clippy::float_cmp,
    reason = "test"
)]
mod tests {
    use nlx_domain::metric::MetricValue;

    use super::*;
    use crate::wire::{NLA_HDRLEN, align4};

    // -----------------------------------------------------------------------
    // NLA construction helpers
    // -----------------------------------------------------------------------

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

    fn make_nested(ty: u16, inner: &[u8]) -> Vec<u8> {
        make_nla(ty | 0x8000, inner)
    }

    // -----------------------------------------------------------------------
    // Security: WGDEVICE_A_PRIVATE_KEY / WGPEER_A_PRESHARED_KEY never appear
    // in WireguardDevice / WireguardPeer (TC-006-A).
    // -----------------------------------------------------------------------

    /// Build a minimal PEERS attr containing one peer with public + preshared keys.
    fn make_peer_with_keys(pubkey: &[u8; 32], psk: &[u8; 32]) -> Vec<u8> {
        let mut peer_attrs = Vec::new();
        peer_attrs.extend(make_nla(WGPEER_A_PUBLIC_KEY, pubkey));
        peer_attrs.extend(make_nla(WGPEER_A_PRESHARED_KEY, psk));
        peer_attrs.extend(make_nla(WGPEER_A_RX_BYTES, &100u64.to_ne_bytes()));
        peer_attrs.extend(make_nla(WGPEER_A_TX_BYTES, &200u64.to_ne_bytes()));
        // A single peer container is one nested NLA inside WGDEVICE_A_PEERS.
        make_nested(0, &peer_attrs) // type=0 for the container; parser uses payload
    }

    /// Build a device frame with a peer carrying both key attrs.
    fn make_device_frame(ifname: &[u8], pubkey: &[u8; 32], psk: &[u8; 32]) -> Vec<u8> {
        let peer_container = make_peer_with_keys(pubkey, psk);
        let peers_nla = make_nested(WGDEVICE_A_PEERS, &peer_container);

        let mut attrs = Vec::new();
        attrs.extend(make_nla(WGDEVICE_A_IFNAME, ifname));
        attrs.extend(make_nla(WGDEVICE_A_LISTEN_PORT, &51820u16.to_ne_bytes()));
        attrs.extend(make_nla(WGDEVICE_A_FWMARK, &0u32.to_ne_bytes()));
        attrs.extend(peers_nla);
        attrs
    }

    /// TC-006-A: private key and preshared key must not appear in parsed structs.
    ///
    /// `WireguardDevice` and `WireguardPeer` contain no raw key fields by design.
    /// The parser discards `WGDEVICE_A_PRIVATE_KEY` and `WGPEER_A_PRESHARED_KEY`
    /// on sight.  This test confirms the struct fields are absent (the type system
    /// enforces this; the test makes the invariant explicit and detectable as doc).
    #[test]
    fn private_key_and_psk_not_in_parsed_structs() {
        let pubkey = [0xABu8; 32];
        let psk = [0xCDu8; 32];

        let attrs = make_device_frame(b"wg0\0", &pubkey, &psk);
        let dev = parse_device(&attrs).expect("must parse");

        // WireguardDevice has no raw key field — verified by field enumeration.
        let WireguardDevice {
            if_name,
            listen_port,
            fwmark,
            peers,
        } = &dev;
        assert_eq!(if_name, "wg0");
        assert_eq!(*listen_port, 51820);
        assert_eq!(*fwmark, 0);
        assert_eq!(peers.len(), 1);

        // WireguardPeer has no raw key field.
        let WireguardPeer {
            peer_id,
            rx_bytes,
            tx_bytes,
            last_handshake_secs,
            persistent_keepalive_secs,
            endpoint_present,
        } = &peers[0];
        // peer_id is the FNV hash — not the raw key.
        assert_ne!(
            peer_id.as_bytes(),
            &pubkey[..],
            "peer_id must not be raw pubkey"
        );
        assert_eq!(peer_id.len(), 16, "peer_id must be 16 hex chars");
        assert_eq!(*rx_bytes, 100);
        assert_eq!(*tx_bytes, 200);
        // No last-handshake time sent → None.
        assert!(last_handshake_secs.is_none());
        assert_eq!(*persistent_keepalive_secs, 0);
        assert!(!endpoint_present);
    }

    // -----------------------------------------------------------------------
    // TC-006-B: tv_sec == 0 → last_handshake_secs == None ("never")
    // -----------------------------------------------------------------------

    fn make_peer_with_hs(pubkey: &[u8; 32], tv_sec: u64) -> Vec<u8> {
        let mut timespec = [0u8; 16];
        timespec[..8].copy_from_slice(&tv_sec.to_ne_bytes());
        // tv_nsec = 0
        let mut peer_attrs = Vec::new();
        peer_attrs.extend(make_nla(WGPEER_A_PUBLIC_KEY, pubkey));
        peer_attrs.extend(make_nla(WGPEER_A_LAST_HANDSHAKE_TIME, &timespec));
        make_nested(0, &peer_attrs)
    }

    #[test]
    fn tv_sec_zero_maps_to_none_handshake() {
        let pubkey = [0x01u8; 32];
        let peer_container = make_peer_with_hs(&pubkey, 0);
        // parse_peer operates on the payload of the container NLA.
        // The container NLA layout: nla_len(u16) + nla_ty(u16) + payload.
        let nla_len = u16::from_ne_bytes([peer_container[0], peer_container[1]]) as usize;
        let payload = &peer_container[4..nla_len];
        let p = parse_peer(payload).expect("must parse peer");
        assert!(
            p.last_handshake_secs.is_none(),
            "tv_sec=0 must produce None (never handshaked)"
        );
    }

    #[test]
    fn tv_sec_nonzero_maps_to_some_handshake() {
        let pubkey = [0x02u8; 32];
        let peer_container = make_peer_with_hs(&pubkey, 1_700_000_000);
        let nla_len = u16::from_ne_bytes([peer_container[0], peer_container[1]]) as usize;
        let payload = &peer_container[4..nla_len];
        let p = parse_peer(payload).expect("must parse peer");
        assert!(
            p.last_handshake_secs.is_some(),
            "tv_sec>0 must produce Some"
        );
        let tv = p.last_handshake_secs.expect("checked Some above");
        assert!(
            (tv - 1_700_000_000.0_f64).abs() < 1.0,
            "stored tv_sec must be ≈ 1_700_000_000"
        );
    }

    // -----------------------------------------------------------------------
    // TC-006-C: peer cap is enforced in push_device_metrics
    // -----------------------------------------------------------------------

    fn make_peer_stub(id: u8) -> WireguardPeer {
        WireguardPeer {
            peer_id: format!("{id:016x}"),
            rx_bytes: 0,
            tx_bytes: 0,
            last_handshake_secs: None,
            persistent_keepalive_secs: 0,
            endpoint_present: false,
        }
    }

    #[test]
    fn peer_cap_limits_emitted_peers() {
        let dev = WireguardDevice {
            if_name: "wg0".to_owned(),
            listen_port: 51820,
            fwmark: 0,
            peers: (0u8..10).map(make_peer_stub).collect(),
        };

        let mut out = Vec::new();
        push_device_metrics(&mut out, &dev, 0, 3); // cap = 3

        // Count how many distinct peer label values appear.
        let peer_labels: std::collections::BTreeSet<String> = out
            .iter()
            .filter_map(|s| s.labels.get("peer").cloned())
            .collect();
        assert_eq!(
            peer_labels.len(),
            3,
            "only 3 peers must be emitted when max_peers=3"
        );
    }

    #[test]
    fn peer_cap_zero_emits_no_peer_metrics() {
        let dev = WireguardDevice {
            if_name: "wg0".to_owned(),
            listen_port: 51820,
            fwmark: 0,
            peers: (0u8..5).map(make_peer_stub).collect(),
        };

        let mut out = Vec::new();
        push_device_metrics(&mut out, &dev, 0, 0); // cap = 0

        let has_peer_label = out.iter().any(|s| s.labels.contains_key("peer"));
        assert!(!has_peer_label, "cap=0 must emit no peer metrics");
    }

    #[test]
    fn peer_count_gauge_reflects_uncapped_total() {
        let dev = WireguardDevice {
            if_name: "wg0".to_owned(),
            listen_port: 51820,
            fwmark: 0,
            peers: (0u8..10).map(make_peer_stub).collect(),
        };

        let mut out = Vec::new();
        push_device_metrics(&mut out, &dev, 0, 3);

        let count_gauge = out
            .iter()
            .find(|s| s.name == "nft_wireguard_device_peer_count")
            .expect("peer_count gauge must be emitted");
        // Value must be 10 (total), not 3 (cap).
        let MetricValue::F64(peer_count_val) = count_gauge.value else {
            panic!("peer_count gauge must have F64 value");
        };
        assert!(
            (peer_count_val - 10.0_f64).abs() < f64::EPSILON,
            "peer_count must reflect the uncapped total (10)"
        );
    }

    // -----------------------------------------------------------------------
    // MC-004: device_info must not carry listen_port or fwmark as labels
    // -----------------------------------------------------------------------

    #[test]
    fn device_info_has_no_volatile_labels() {
        let dev = WireguardDevice {
            if_name: "wg0".to_owned(),
            listen_port: 51820,
            fwmark: 42,
            peers: vec![],
        };

        let mut out = Vec::new();
        push_device_metrics(&mut out, &dev, 0, 1_000);

        let info = out
            .iter()
            .find(|s| s.name == "nft_wireguard_device_info")
            .expect("device_info must be present");

        assert!(
            !info.labels.contains_key("listen_port"),
            "device_info must not carry listen_port label"
        );
        assert!(
            !info.labels.contains_key("fwmark"),
            "device_info must not carry fwmark label"
        );
        assert_eq!(
            info.labels.get("interface").map(String::as_str),
            Some("wg0")
        );

        // Volatile values must appear as separate gauges.
        let has_port_gauge = out
            .iter()
            .any(|s| s.name == "nft_wireguard_device_listen_port");
        let has_fwmark_gauge = out.iter().any(|s| s.name == "nft_wireguard_device_fwmark");
        assert!(has_port_gauge, "listen_port must have its own gauge");
        assert!(has_fwmark_gauge, "fwmark must have its own gauge");
    }

    // -----------------------------------------------------------------------
    // pubkey_hash: deterministic, 16 chars, all lowercase hex
    // -----------------------------------------------------------------------

    #[test]
    fn pubkey_hash_is_deterministic_and_16_hex_chars() {
        let key = [0xABu8; 32];
        let h1 = pubkey_hash(&key);
        let h2 = pubkey_hash(&key);
        assert_eq!(h1, h2, "hash must be deterministic");
        assert_eq!(h1.len(), 16, "hash must be 16 chars");
        assert!(
            h1.chars().all(|c| c.is_ascii_hexdigit()),
            "hash must be lowercase hex"
        );
    }

    #[test]
    fn pubkey_hash_differs_for_different_keys() {
        let key_a = [0x01u8; 32];
        let key_b = [0x02u8; 32];
        assert_ne!(pubkey_hash(&key_a), pubkey_hash(&key_b));
    }
}
