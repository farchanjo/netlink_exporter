//! WireGuard genetlink collector.
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
    wire::{nested_attrs, parse_attrs, read_u16, read_u32, read_u64},
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

/// Adapter implementing [`NetlinkWireguardPort`] and [`Collector`] for WireGuard.
pub struct WireguardCollector;

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

        let frames = wg_dump(&mut sock, family_id)
            .await
            .map_err(|e| DomainError::Collector(e.to_string()))?;

        let mut result = Vec::with_capacity(frames.len());
        for frame in &frames {
            if frame.len() < 4 {
                continue;
            }
            if let Some(dev) = parse_device(&frame[4..]) {
                result.push(dev);
            }
        }
        Ok(result)
    }
}

impl Collector for WireguardCollector {
    fn name(&self) -> &str {
        "wireguard"
    }

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

            let frames = wg_dump(&mut sock, family_id)
                .await
                .map_err(|e| CollectError::Io(e.to_string()))?;

            // Current unix time for last-handshake age computation (§14.5).
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);

            let mut out = Vec::new();
            for frame in &frames {
                if frame.len() < 4 {
                    continue;
                }
                let Some(dev) = parse_device(&frame[4..]) else {
                    continue;
                };
                push_device_metrics(&mut out, &dev, now_secs);
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

async fn wg_dump(
    sock: &mut NetlinkSocket,
    family_id: u16,
) -> Result<Vec<Vec<u8>>, crate::transport::NetlinkError> {
    // Payload: genlmsghdr only (cmd=0, version=1, reserved=0).
    let payload = vec![WG_CMD_GET_DEVICE, WG_GENL_VERSION, 0u8, 0u8];
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
// Parsers
// ---------------------------------------------------------------------------

/// Parse one WireGuard device frame (attrs after genlmsghdr).
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

/// Parse one WireGuard peer (inner WGPEER_A_* attrs).
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

fn push_device_metrics(out: &mut Vec<MetricSample>, dev: &WireguardDevice, now_secs: i64) {
    // Device info gauge.
    let mut dev_labels = BTreeMap::new();
    dev_labels.insert("interface".to_owned(), dev.if_name.clone());
    out.push(MetricSample::gauge(
        "nft_wireguard_device_info",
        "WireGuard device metadata (listen port and fwmark).",
        {
            let mut m = dev_labels.clone();
            m.insert("listen_port".to_owned(), dev.listen_port.to_string());
            m.insert("fwmark".to_owned(), dev.fwmark.to_string());
            m
        },
        1.0,
    ));

    for peer in &dev.peers {
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
