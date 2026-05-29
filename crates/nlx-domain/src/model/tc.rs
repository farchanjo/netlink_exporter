//! Traffic-control read model (qdisc, class, filter).

use serde::{Deserialize, Serialize};

/// Kind of TC object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TcKind {
    /// Queueing discipline (`RTM_GETQDISC`).
    Qdisc,
    /// Traffic class (`RTM_GETTCLASS`).
    Class,
    /// Tc filter (`RTM_GETTFILTER`).
    Filter,
}

/// Read model for one TC object with its statistics.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TcReadModel {
    /// Kind (qdisc, class, or filter).
    pub kind: TcKind,
    /// Interface name.
    pub if_name: String,
    /// Handle as hex string (e.g. `"1:0"`).
    pub handle: String,
    /// Parent handle as hex string; `"root"` for root qdisc.
    pub parent: String,
    /// Kind name string (e.g. `"htb"`, `"fq_codel"`, `"flower"`).
    pub kind_name: String,
    /// Direction for filters: `"ingress"` or `"egress"`.
    pub direction: Option<String>,
    /// `gnet_stats_basic` bytes.
    pub bytes: u64,
    /// `gnet_stats_basic` packets.
    pub packets: u64,
    /// `gnet_stats_queue` drops.
    pub drops: u64,
    /// `gnet_stats_queue` overlimits.
    pub overlimits: u64,
    /// `gnet_stats_queue` backlog in bytes.
    pub backlog: u64,
}
