//! Neighbor (ARP/NDP) read model.

use serde::{Deserialize, Serialize};

/// Aggregation key for neighbor counting (no per-IP or per-MAC data).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NeighborReadModel {
    /// Interface name.
    pub if_name: String,
    /// Address family: `"inet"` or `"inet6"`.
    pub family: String,
    /// NUD state string (e.g. `"reachable"`, `"stale"`, `"failed"`).
    pub state: String,
}
