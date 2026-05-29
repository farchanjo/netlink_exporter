//! XFRM `IPsec` read models.

use serde::{Deserialize, Serialize};

/// One XFRM Security Association (SA) from `XFRM_MSG_GETSA`.
///
/// Aggregation key only — no per-SA identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct XfrmState {
    /// Protocol string: `"esp"`, `"ah"`, `"comp"`, `"other"`.
    pub proto: String,
    /// Mode string: `"tunnel"`, `"transport"`, `"beet"`, `"other"`.
    pub mode: String,
}

/// One XFRM Security Policy (SP) from `XFRM_MSG_GETPOLICY`.
///
/// Aggregation key only.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct XfrmPolicy {
    /// Direction: `"in"`, `"fwd"`, `"out"`.
    pub dir: String,
    /// Action: `"allow"` or `"block"`.
    pub action: String,
}

/// XFRM SAD hash table info (`XFRM_MSG_GETSADINFO`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XfrmSadInfo {
    /// SAD hash current count (`xfrm_sadinfo.sadhcnt`).
    pub hash_count: u32,
    /// SAD hash maximum count (`xfrm_sadinfo.sadhmcnt`).
    pub hash_max: u32,
}

/// XFRM SPD hash table info (`XFRM_MSG_GETSPDINFO`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XfrmSpdInfo {
    /// SPD hash current count (`xfrm_spdinfo.spdhcnt`).
    pub hash_count: u32,
    /// SPD hash maximum count (`xfrm_spdinfo.spdhmcnt`).
    pub hash_max: u32,
}
