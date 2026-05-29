//! Socket diagnostic read model (`NETLINK_SOCK_DIAG`).

use serde::{Deserialize, Serialize};

/// Aggregated socket diagnostic entry (no per-socket or per-port data).
///
/// Per-socket inode and per-port labels are excluded (ADR-0005).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SockDiagEntry {
    /// Protocol string: `"tcp"`, `"udp"`, `"udplite"`.
    pub protocol: String,
    /// TCP state string (e.g. `"established"`, `"listen"`); `"unconnected"` for UDP.
    pub state: String,
    /// Total receive queue bytes across all sockets in this bucket.
    pub recv_queue_bytes: u64,
    /// Total send queue bytes across all sockets in this bucket.
    pub send_queue_bytes: u64,
    /// Total socket drop packets (all states, same protocol).
    pub drops: u64,
    /// Total TCP retransmit count (TCP only; 0 for UDP).
    pub retransmits: u64,
}
