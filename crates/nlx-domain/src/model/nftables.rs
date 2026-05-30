//! nftables read models.
//!
//! Domain structs for the nftables firewall observability surface (ADR-0030).
//! All structs are pure data — no I/O, no kernel types.

use serde::{Deserialize, Serialize};

/// nftables table read model (`NFT_MSG_GETTABLE`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NftTable {
    /// Table name.
    pub name: String,
    /// Address family string (`"inet"`, `"ip"`, `"ip6"`, `"arp"`, `"bridge"`, `"netdev"`).
    pub family: String,
}

/// nftables chain read model (`NFT_MSG_GETCHAIN`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NftChain {
    /// Parent table name.
    pub table: String,
    /// Chain name.
    pub chain: String,
    /// Chain type (`"filter"`, `"route"`, `"nat"`); empty for non-base chains.
    pub chain_type: String,
    /// Netfilter hook name (e.g. `"input"`, `"forward"`); empty for non-base chains.
    pub hook: String,
    /// Hook priority; 0 when not a base chain.
    pub priority: i32,
    /// Default policy (`"accept"` or `"drop"`); empty for non-base chains.
    pub policy: String,
}

/// Named nftables counter object (`NFT_MSG_GETOBJ` with `NFT_OBJECT_COUNTER`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NftCounter {
    /// Parent table name.
    pub table: String,
    /// Counter name.
    pub name: String,
    /// Byte count.
    pub bytes: u64,
    /// Packet count.
    pub packets: u64,
}

/// Named nftables set or map (`NFT_MSG_GETSET`).
///
/// Anonymous sets (`NFT_SET_ANONYMOUS` flag) are excluded — only named sets
/// are exported (ADR-0005 cardinality).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NftSet {
    /// Parent table name.
    pub table: String,
    /// Set name.
    pub name: String,
    /// Key type string (e.g. `"ipv4_addr"`, `"inet_service"`).
    pub key_type: String,
    /// Current element count.
    pub element_count: u32,
}

/// Rule with counter expression (from `NFT_MSG_GETRULE`).
///
/// Only rules carrying a non-empty `comment` in `NFTA_RULE_USERDATA` and a
/// `"counter"` expression in `NFTA_RULE_EXPRESSIONS` are exported
/// (ADR-0005 cardinality rule).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NftRuleCounter {
    /// Parent table name.
    pub table: String,
    /// Parent chain name.
    pub chain: String,
    /// Rule comment expression; guaranteed non-empty.
    pub comment: String,
    /// Byte count from the rule's counter expression.
    pub bytes: u64,
    /// Packet count from the rule's counter expression.
    pub packets: u64,
}

/// Named nftables quota object (`NFT_MSG_GETOBJ` with `NFT_OBJECT_QUOTA`).
///
/// Source: `NFTA_QUOTA_BYTES` (1, BE u64), `NFTA_QUOTA_CONSUMED` (4, BE u64),
/// `NFTA_QUOTA_FLAGS` (2, BE u32) bit 1 = `NFT_QUOTA_F_DEPLETED`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NftQuota {
    /// Parent table name.
    pub table: String,
    /// Quota object name.
    pub name: String,
    /// Configured ceiling in bytes (`NFTA_QUOTA_BYTES`).
    pub bytes_ceiling: u64,
    /// Bytes consumed so far (`NFTA_QUOTA_CONSUMED`).
    pub bytes_consumed: u64,
    /// `true` when `NFT_QUOTA_F_DEPLETED` bit is set in `NFTA_QUOTA_FLAGS`.
    pub depleted: bool,
}

/// Named nftables limit object (`NFT_MSG_GETOBJ` with `NFT_OBJECT_LIMIT`).
///
/// Captures the static configuration; no runtime token-bucket state is exported.
/// Source: `NFTA_LIMIT_RATE` (1, BE u64), `NFTA_LIMIT_BURST` (3, BE u32),
/// `NFTA_LIMIT_TYPE` (4, BE u32).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NftLimit {
    /// Parent table name.
    pub table: String,
    /// Limit object name.
    pub name: String,
    /// Rate in tokens per `unit_secs` seconds (`NFTA_LIMIT_RATE`, BE u64).
    pub rate: u64,
    /// Time unit in seconds (`NFTA_LIMIT_UNIT`, BE u64).
    pub unit_secs: u64,
    /// Burst allowance (`NFTA_LIMIT_BURST`, BE u32).
    pub burst: u32,
    /// Limit type: `"pkts"` (`NFT_LIMIT_PKTS=0`), `"bytes"` (`NFT_LIMIT_PKT_BYTES=1`).
    pub limit_type: String,
}

/// Named nftables flowtable (`NFT_MSG_GETFLOWTABLE`).
///
/// Source: `NFTA_FLOWTABLE_TABLE` (1), `NFTA_FLOWTABLE_NAME` (2),
/// `NFTA_FLOWTABLE_HOOK` (3, nested), `NFTA_FLOWTABLE_FLAGS` (7, BE u32).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NftFlowtable {
    /// Parent table name.
    pub table: String,
    /// Flowtable name.
    pub name: String,
    /// Hook point name (mapped from `NFTA_FLOWTABLE_HOOK_NUM`).
    pub hook: String,
    /// Hook priority, reinterpreted as signed i32 (`NFTA_FLOWTABLE_HOOK_PRIORITY`).
    pub priority: i32,
    /// `true` when `NFT_FLOWTABLE_HW_OFFLOAD` (bit 0) is set in `NFTA_FLOWTABLE_FLAGS`.
    pub hw_offload: bool,
}
