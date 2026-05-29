//! Route read model.

use serde::{Deserialize, Serialize};

/// Aggregation key for route counting (no per-destination data).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RouteReadModel {
    /// Routing table id as string.
    pub table: String,
    /// Address family: `"inet"` or `"inet6"`.
    pub family: String,
    /// Route protocol string (e.g. `"kernel"`, `"boot"`, `"static"`).
    pub protocol: String,
    /// Route type string (e.g. `"unicast"`, `"local"`, `"blackhole"`).
    pub route_type: String,
}
