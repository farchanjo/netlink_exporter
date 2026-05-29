//! Conntrack domain read models.

use serde::{Deserialize, Serialize};

/// Aggregation key for one conntrack flow bucket.
///
/// Per-flow IP/port labels are explicitly excluded (ADR-0005 cardinality rule).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConntrackFlow {
    /// L4 protocol string (`"tcp"`, `"udp"`, `"icmp"`, …).
    pub protocol: String,
    /// Connection state string (TCP states or `"new"` / `"established"`).
    pub state: String,
    /// Byte counter for original direction.
    pub orig_bytes: u64,
    /// Packet counter for original direction.
    pub orig_packets: u64,
    /// Byte counter for reply direction.
    pub reply_bytes: u64,
    /// Packet counter for reply direction.
    pub reply_packets: u64,
}

/// Per-CPU conntrack statistics from `IPCTNL_MSG_CT_GET_STATS_CPU`.
///
/// Struct size is kernel-version dependent:
/// - 52 bytes (kernel < 5.10)
/// - 56 bytes (kernel 5.10–5.11)
/// - 60 bytes (kernel >= 5.12)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConntrackStat {
    /// Total found entries (sum across CPUs).
    pub found: u64,
    /// Total insert events.
    pub insert: u64,
    /// Total drop events.
    pub drop: u64,
    /// Total early drop events.
    pub early_drop: u64,
    /// Total invalid events.
    pub invalid: u64,
    /// Clash resolve events (kernel >= 5.10; `None` on older kernels).
    pub clash_resolve: Option<u64>,
    /// Chain too-long events (kernel >= 5.12; `None` on older kernels).
    pub chaintoolong: Option<u64>,
}

/// One conntrack expectation entry from `IPCTNL_MSG_EXP_GET`.
///
/// Per-expectation IP/port are discarded at parse time (ADR-0005).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConntrackExpectEntry {
    /// L4 protocol string.
    pub l4proto: String,
    /// Helper name (NUL-stripped `CTA_EXPECT_HELPER_NAME`); empty when absent.
    pub helper: String,
}
