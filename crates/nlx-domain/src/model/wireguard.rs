//! WireGuard genetlink read model.

use serde::{Deserialize, Serialize};

/// WireGuard device and its peers (`WG_CMD_GET_DEVICE`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WireguardDevice {
    /// Interface name.
    pub if_name: String,
    /// UDP listen port (`WGDEVICE_A_LISTEN_PORT` u16 LE); 0 when unbound.
    pub listen_port: u16,
    /// Firewall mark (`WGDEVICE_A_FWMARK` u32 LE); 0 when unset.
    pub fwmark: u32,
    /// Peers attached to this device.
    pub peers: Vec<WireguardPeer>,
}

/// One WireGuard peer.
///
/// The public key is hashed to an 8-byte hex string for the `peer` label
/// (ADR-0018 anti-cardinality rule).  The raw key is not stored.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WireguardPeer {
    /// 16-character hex hash of the public key, or operator-configured name.
    pub peer_id: String,
    /// Cumulative bytes received (`WGPEER_A_RX_BYTES` u64 native-endian).
    pub rx_bytes: u64,
    /// Cumulative bytes transmitted (`WGPEER_A_TX_BYTES` u64 native-endian).
    pub tx_bytes: u64,
    /// Seconds since last handshake (`now - WGPEER_A_LAST_HANDSHAKE_TIME.tv_sec`).
    /// `None` when `tv_sec == 0` (never completed a handshake).
    pub last_handshake_secs: Option<f64>,
    /// Persistent keepalive interval in seconds; 0 when disabled.
    pub persistent_keepalive_secs: u16,
    /// `true` when `WGPEER_A_ENDPOINT` is present in the kernel response.
    pub endpoint_present: bool,
}
