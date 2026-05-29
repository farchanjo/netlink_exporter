//! Ethtool genetlink read model.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Ethtool statistics and link settings for one interface.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EthtoolStats {
    /// Interface name.
    pub if_name: String,
    /// Named NIC statistics (`ETHTOOL_MSG_STATS_GET`).
    pub stats: BTreeMap<String, u64>,
    /// Link speed in Mbps; `None` when unknown.
    pub speed_mbps: Option<u32>,
    /// Duplex string: `"full"`, `"half"`, `"unknown"`.
    pub duplex: String,
    /// Auto-negotiation: `"on"` or `"off"`.
    pub autoneg: String,
    /// Port type string (e.g. `"MII"`, `"FIBRE"`, `"TP"`).
    pub port: String,
    /// Total PAUSE RX frames (`ETHTOOL_A_PAUSE_STAT_RX_FRAMES`).
    pub pause_rx_frames: Option<u64>,
    /// Total PAUSE TX frames (`ETHTOOL_A_PAUSE_STAT_TX_FRAMES`).
    pub pause_tx_frames: Option<u64>,
    /// FEC corrected blocks per lane (`ETHTOOL_A_FEC_STAT_CORRECTED`).
    pub fec_corrected: BTreeMap<String, u64>,
}
