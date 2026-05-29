//! nftables read models.

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

/// Named nftables counter object (`NFT_MSG_GETCOUNTER`).
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
/// Only rules carrying a non-empty `comment` expression are exported
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
