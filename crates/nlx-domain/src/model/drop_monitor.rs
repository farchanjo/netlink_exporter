//! Drop-monitor genetlink read model.

use serde::{Deserialize, Serialize};

/// One aggregated drop-monitor event bucket.
///
/// Per-flow and per-address data are excluded (ADR-0005).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DropEvent {
    /// Drop reason string from `NET_DM_ATTR_REASON` (software) or
    /// `NET_DM_ATTR_HW_TRAP_NAME` (hardware).
    pub reason: String,
    /// Origin: `"sw"` for software drops, `"hw"` for hardware drops.
    pub origin: String,
    /// Total dropped packets (`NET_DM_ATTR_STATS_DROPPED`).
    pub dropped: u64,
}
