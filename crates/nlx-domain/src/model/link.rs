//! Link (network interface) read model.

use serde::{Deserialize, Serialize};

/// Read model for one network interface (`RTM_NEWLINK`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LinkReadModel {
    /// Interface index (`ifla_ifindex`).
    pub index: u32,
    /// Interface name (e.g. `"eth0"`).
    pub name: String,
    /// Optional alias string (`IFLA_IFALIAS`).
    pub alias: Option<String>,
    /// Link type string (e.g. `"ether"`, `"loopback"`).
    pub link_type: String,
    /// Operational state string (`IFLA_OPERSTATE`).
    pub operstate: String,
    /// Flags bitmask (`IFF_UP`, `IFF_LOOPBACK`, …).
    pub flags: u32,
    /// MTU in bytes (`IFLA_MTU`).
    pub mtu: u32,
    /// Link speed in Mbps; `None` when unknown.
    pub speed_mbps: Option<i64>,
    /// Receive byte counter (`IFLA_STATS64 rx_bytes`).
    pub rx_bytes: u64,
    /// Transmit byte counter (`IFLA_STATS64 tx_bytes`).
    pub tx_bytes: u64,
    /// Receive packet counter.
    pub rx_packets: u64,
    /// Transmit packet counter.
    pub tx_packets: u64,
    /// Receive error counter.
    pub rx_errors: u64,
    /// Transmit error counter.
    pub tx_errors: u64,
    /// Receive drop counter.
    pub rx_dropped: u64,
    /// Transmit drop counter.
    pub tx_dropped: u64,
}
