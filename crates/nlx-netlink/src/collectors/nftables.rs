//! nftables collector — `NETLINK_NETFILTER` (12), `NFNL_SUBSYS_NFTABLES` (10).
//!
//! ## Messages used
//!
//! | Message | `nlmsg_type` | Purpose |
//! |---|---|---|
//! | `NFT_MSG_GETTABLE`     | `0x0A01` | Table dump — family + name |
//! | `NFT_MSG_GETCHAIN`     | `0x0A04` | Chain dump — table, name, hook, policy |
//! | `NFT_MSG_GETRULE`      | `0x0A07` | Rule dump — expr walk for counter + userdata comment |
//! | `NFT_MSG_GETSET`       | `0x0A0A` | Named set dump — element count + key type |
//! | `NFT_MSG_GETGEN`       | `0x0A10` | Ruleset generation ID |
//! | `NFT_MSG_GETOBJ`       | `0x0A13` | Object dump — counter / quota / limit |
//! | `NFT_MSG_GETFLOWTABLE` | `0x0A17` | Flowtable dump — hook, priority, HW offload flag |
//!
//! `nlmsg_type = (NFNL_SUBSYS_NFTABLES=10) << 8 | msg_type`.  The enum in
//! `nf_tables.h` starts at 0 with `NFT_MSG_NEWTABLE`; GET variants are at
//! positions 1, 4, 7, 10, 16, 19, and 23 (verified against Linux 6.17 UAPI).
//!
//! ## Metrics emitted (ADR-0030)
//!
//! | Metric | Type | Labels |
//! |---|---|---|
//! | `nft_table_info` | gauge=1 | `table`, `family` |
//! | `nft_chain_info` | gauge=1 | `table`, `chain`, `type`, `hook`, `priority`, `policy` |
//! | `nft_rule_counter_bytes_total` | counter | `table`, `chain`, `comment` |
//! | `nft_rule_counter_packets_total` | counter | `table`, `chain`, `comment` |
//! | `nft_named_counter_bytes_total` | counter | `table`, `name` |
//! | `nft_named_counter_packets_total` | counter | `table`, `name` |
//! | `nft_set_elements` | gauge | `table`, `name`, `type` |
//! | `nft_named_quota_bytes_total` | gauge | `table`, `name` |
//! | `nft_named_quota_consumed_bytes_total` | gauge | `table`, `name` |
//! | `nft_named_quota_depleted` | gauge 0/1 | `table`, `name` |
//! | `nft_named_limit_rate` | gauge | `table`, `name`, `type` |
//! | `nft_named_limit_burst` | gauge | `table`, `name`, `type` |
//! | `nft_ruleset_generation` | gauge | (none) |
//! | `nft_flowtable_info` | gauge=1 | `table`, `name`, `hook`, `priority`, `hw_offload` |
//!
//! ## Wire format notes
//!
//! Every `NETLINK_NETFILTER` frame starts with a 4-byte `nfgenmsg` after the
//! 16-byte `nlmsghdr`.  The nlattr chain starts at byte offset 20 from the
//! message start (offset 4 within the frame slice, which starts after nlmsghdr).
//!
//! `nfgenmsg.nfgen_family` in the _reply_ carries the address family (see
//! `family_label`).
//!
//! ## Byte-order of integer nftables NLAs
//!
//! Most nftables integer attributes are serialised big-endian by the kernel via
//! `nla_put_be32` / `nla_put_be64`.  Use `read_u32_be` / `read_u64_be` for all
//! nftables integer attributes.
//!
//! ## Cardinality overflow guard
//!
//! Anonymous rules (no comment) are counted.  When the anonymous count exceeds
//! `ANON_RULE_OVERFLOW_THRESHOLD` in a single scrape,
//! `nft_scrape_collector_error_total{collector="nftables",reason="cardinality_overflow"}`
//! is emitted (ADR-0005, ADR-0030).
//!
//! ## ADR references
//!
//! ADR-0011 (direct wire; rustables removed), ADR-0014 (tokio-only in adapter),
//! ADR-0005 (cardinality), ADR-0003 (edition 2024, MSRV 1.87), ADR-0030
//! (complete nftables firewall observability).

use std::collections::BTreeMap;

use tracing::{debug, warn};

use nlx_domain::{
    error::DomainError,
    metric::MetricSample,
    model::nftables::{
        NftChain, NftCounter, NftFlowtable, NftLimit, NftQuota, NftRuleCounter, NftSet, NftTable,
    },
};
use nlx_ports::{
    collector::{BoxFuture, Collector},
    driven::NetlinkNftablesPort,
    error::CollectError,
};

use crate::{
    transport::{MAX_DUMP_RESTARTS, NetlinkError, NetlinkSocket},
    wire::{nested_attrs, parse_attrs, read_u32_be, read_u64_be},
};

// ---------------------------------------------------------------------------
// Wire constants — message types
// ---------------------------------------------------------------------------

/// `NETLINK_NETFILTER` protocol number.
const NETLINK_NETFILTER: i32 = 12;

/// nfgenmsg: 4 bytes (`nfgen_family` u8 + version u8 + `res_id` __be16).
const NFGENMSG_LEN: usize = 4;

// NFNL_SUBSYS_NFTABLES = 10; nlmsg_type = (10 << 8) | msg_type
//
// nf_tables.h enum (0-based): NEWTABLE=0, GETTABLE=1, DELTABLE=2,
// NEWCHAIN=3, GETCHAIN=4, DELCHAIN=5, NEWRULE=6, GETRULE=7, DELRULE=8,
// NEWSET=9, GETSET=10, DELSET=11, NEWSETELEM=12, GETSETELEM=13, DELSETELEM=14,
// NEWGEN=15, GETGEN=16, TRACE=17, NEWOBJ=18, GETOBJ=19,
// GETFLOWTABLE=23 (NEWFLOWTABLE=20, GETFLOWTABLE=21 in older kernels;
//                  kernel 4.16+ uses 23 — verify via nf_tables.h NFT_MSG_GETFLOWTABLE).
const NFT_MSG_GETTABLE: u16 = (10u16 << 8) | 1; // 0x0A01
const NFT_MSG_GETCHAIN: u16 = (10u16 << 8) | 4; // 0x0A04
const NFT_MSG_GETRULE: u16 = (10u16 << 8) | 7; // 0x0A07
const NFT_MSG_GETSET: u16 = (10u16 << 8) | 10; // 0x0A0A
const NFT_MSG_GETGEN: u16 = (10u16 << 8) | 16; // 0x0A10
const NFT_MSG_GETOBJ: u16 = (10u16 << 8) | 19; // 0x0A13
const NFT_MSG_GETFLOWTABLE: u16 = (10u16 << 8) | 23; // 0x0A17

// ---------------------------------------------------------------------------
// Wire constants — object types
// ---------------------------------------------------------------------------

const NFT_OBJECT_COUNTER: u32 = 1;
const NFT_OBJECT_QUOTA: u32 = 2;
const NFT_OBJECT_LIMIT: u32 = 4;

// ---------------------------------------------------------------------------
// Wire constants — nlattr types
// ---------------------------------------------------------------------------

// NFTA_TABLE_*
const NFTA_TABLE_NAME: u16 = 1;

// NFTA_CHAIN_*
const NFTA_CHAIN_TABLE: u16 = 1;
const NFTA_CHAIN_NAME: u16 = 3;
const NFTA_CHAIN_HOOK: u16 = 4;
const NFTA_CHAIN_POLICY: u16 = 5;
const NFTA_CHAIN_TYPE: u16 = 7;

// NFTA_HOOK_* (nested inside NFTA_CHAIN_HOOK)
const NFTA_HOOK_HOOKNUM: u16 = 1;
const NFTA_HOOK_PRIORITY: u16 = 2;

// NFTA_RULE_*
const NFTA_RULE_TABLE: u16 = 1;
const NFTA_RULE_CHAIN: u16 = 2;
const NFTA_RULE_EXPRESSIONS: u16 = 4;
const NFTA_RULE_USERDATA: u16 = 7;

// NFTA_LIST_ELEM / NFTA_EXPR_*
const NFTA_LIST_ELEM: u16 = 1;
const NFTA_EXPR_NAME: u16 = 1;
const NFTA_EXPR_DATA: u16 = 2;

// NFTA_OBJ_*
const NFTA_OBJ_TABLE: u16 = 1;
const NFTA_OBJ_NAME: u16 = 2;
const NFTA_OBJ_TYPE: u16 = 3;
const NFTA_OBJ_DATA: u16 = 4;

// NFTA_COUNTER_* (nested in NFTA_OBJ_DATA for counter objects)
const NFTA_COUNTER_BYTES: u16 = 1;
const NFTA_COUNTER_PACKETS: u16 = 2;

// NFTA_SET_*
const NFTA_SET_TABLE: u16 = 1;
const NFTA_SET_NAME: u16 = 2;
const NFTA_SET_FLAGS: u16 = 3;
const NFTA_SET_KEY_TYPE: u16 = 4;
const NFTA_SET_DESC: u16 = 9;
const NFTA_SET_COUNT: u16 = 20;

// NFTA_SET_DESC_* (nested inside NFTA_SET_DESC)
const NFTA_SET_DESC_SIZE: u16 = 1;

/// Anonymous set flag — exclude from emission (ADR-0005 cardinality).
const NFT_SET_ANONYMOUS: u32 = 0x0001;

// NFTA_QUOTA_*
const NFTA_QUOTA_BYTES: u16 = 1;
const NFTA_QUOTA_FLAGS: u16 = 2;
const NFTA_QUOTA_CONSUMED: u16 = 4;

/// Bit 1 of NFTA_QUOTA_FLAGS: quota has been exhausted.
const NFT_QUOTA_F_DEPLETED: u32 = 1 << 1;

// NFTA_LIMIT_*
const NFTA_LIMIT_RATE: u16 = 1;
const NFTA_LIMIT_UNIT: u16 = 2;
const NFTA_LIMIT_BURST: u16 = 3;
const NFTA_LIMIT_TYPE: u16 = 4;

// NFTA_GEN_*
const NFTA_GEN_ID: u16 = 1;

// NFTA_FLOWTABLE_*
const NFTA_FLOWTABLE_TABLE: u16 = 1;
const NFTA_FLOWTABLE_NAME: u16 = 2;
const NFTA_FLOWTABLE_HOOK: u16 = 3;
const NFTA_FLOWTABLE_FLAGS: u16 = 7;

// NFTA_FLOWTABLE_HOOK_* (nested inside NFTA_FLOWTABLE_HOOK)
const NFTA_FLOWTABLE_HOOK_NUM: u16 = 1;
const NFTA_FLOWTABLE_HOOK_PRIORITY: u16 = 2;

/// Bit 0 of NFTA_FLOWTABLE_FLAGS: hardware offload active.
const NFT_FLOWTABLE_HW_OFFLOAD: u32 = 1 << 0;

/// Hard cap on emitted per-rule counter series per scrape. Commented-counter
/// rules beyond this cap are dropped and the excess is reported via
/// `nft_scrape_collector_error_total{reason=cardinality_overflow}`.
/// Anonymous/comment-less rules are suppressed upstream and do NOT count as
/// overflow (ADR-0005, ADR-0030).
const RULE_COUNTER_MAX_SERIES: usize = 1000;

// ---------------------------------------------------------------------------
// nfgen_family / hook / policy label maps
// ---------------------------------------------------------------------------

fn family_label(nfgen_family: u8) -> &'static str {
    // NFPROTO_* from include/uapi/linux/netfilter.h (NOT nf_tables.h):
    // UNSPEC=0, INET=1, IPV4=2, ARP=3, NETDEV=5, BRIDGE=7, IPV6=10.
    // (DECNET=12 was removed from the kernel.)
    match nfgen_family {
        0 => "unspec",
        1 => "inet",
        2 => "ip",
        3 => "arp",
        5 => "netdev",
        7 => "bridge",
        10 => "ip6",
        _ => "other",
    }
}

fn hook_label(hooknum: u32) -> &'static str {
    match hooknum {
        0 => "prerouting",
        1 => "input",
        2 => "forward",
        3 => "output",
        4 => "postrouting",
        5 => "ingress",
        6 => "egress",
        _ => "other",
    }
}

fn policy_label(policy: u32) -> &'static str {
    match policy {
        0 => "drop",
        1 => "accept",
        _ => "other",
    }
}

/// Map a `NFTA_SET_KEY_TYPE` u32 to a human-readable type string.
fn key_type_label(key_type: u32) -> &'static str {
    match key_type {
        0x000c => "ipv4_addr",
        0x000d => "ipv6_addr",
        0x000b => "inet_service",
        0x0005 => "ether_addr",
        0x0009 => "mark",
        _ => "other",
    }
}

/// Map `NFTA_LIMIT_TYPE` u32 to a type string.
fn limit_type_label(limit_type: u32) -> &'static str {
    match limit_type {
        0 => "pkts",
        1 => "bytes",
        _ => "other",
    }
}

// ---------------------------------------------------------------------------
// nfgenmsg builder
// ---------------------------------------------------------------------------

/// Build a 4-byte `nfgenmsg` for the given `nfgen_family`.
/// `version=0`, `res_id=[0,0]` for dump requests.
fn nfgenmsg(family: u8) -> [u8; 4] {
    [family, 0u8, 0u8, 0u8]
}

// ---------------------------------------------------------------------------
// NUL-terminated string helper
// ---------------------------------------------------------------------------

/// Strip a trailing NUL byte from a kernel NUL-terminated attribute payload
/// and return a `String`.  Invalid UTF-8 is replaced with U+FFFD.
fn cstr_to_string(payload: &[u8]) -> String {
    let trimmed = match payload.last() {
        Some(&0) => &payload[..payload.len().saturating_sub(1)],
        _ => payload,
    };
    String::from_utf8_lossy(trimmed).into_owned()
}

// ---------------------------------------------------------------------------
// Dump helpers with DumpIntr restart
// ---------------------------------------------------------------------------

/// Issue a `NETLINK_NETFILTER` dump with `NLM_F_DUMP` and retry on
/// `NLM_F_DUMP_INTR` (capped at `MAX_DUMP_RESTARTS`).
///
/// # Errors
///
/// Returns [`NetlinkError`] on socket I/O or when restart cap is exceeded.
async fn nft_dump(
    sock: &mut NetlinkSocket,
    msg_type: u16,
    nfgen_family: u8,
) -> Result<Vec<Vec<u8>>, NetlinkError> {
    let payload = nfgenmsg(nfgen_family);
    let mut restarts: u32 = 0;
    loop {
        match sock.dump(msg_type, 0, &payload).await {
            Ok(frames) => return Ok(frames),
            Err(NetlinkError::DumpIntr) if restarts < MAX_DUMP_RESTARTS => {
                restarts = restarts.saturating_add(1);
                warn!(
                    restart = restarts,
                    msg_type, "nftables dump interrupted; retrying"
                );
            }
            Err(e) => return Err(e),
        }
    }
}

// ---------------------------------------------------------------------------
// Table parsing
// ---------------------------------------------------------------------------

/// Parse one `NFT_MSG_GETTABLE` reply frame into an [`NftTable`].
fn parse_table_frame(frame: &[u8]) -> Option<NftTable> {
    if frame.len() < NFGENMSG_LEN {
        return None;
    }
    let family = family_label(frame[0]).to_owned();
    let attrs_buf = &frame[NFGENMSG_LEN..];
    let mut name = String::new();

    for attr in parse_attrs(attrs_buf) {
        if attr.ty == NFTA_TABLE_NAME {
            name = cstr_to_string(attr.payload);
        }
    }

    if name.is_empty() {
        return None;
    }

    Some(NftTable { name, family })
}

// ---------------------------------------------------------------------------
// Chain parsing
// ---------------------------------------------------------------------------

/// Parse one `NFT_MSG_GETCHAIN` reply frame into an [`NftChain`].
#[allow(
    clippy::assigning_clones,
    reason = "clarity: assigning &'static str via to_owned is idiomatic here"
)]
fn parse_chain_frame(frame: &[u8]) -> Option<NftChain> {
    if frame.len() < NFGENMSG_LEN {
        return None;
    }
    let attrs_buf = &frame[NFGENMSG_LEN..];

    let mut table = String::new();
    let mut chain = String::new();
    let mut chain_type = String::new();
    let mut hook = String::new();
    let mut priority: i32 = 0;
    let mut policy = String::new();

    for attr in parse_attrs(attrs_buf) {
        match attr.ty {
            NFTA_CHAIN_TABLE => table = cstr_to_string(attr.payload),
            NFTA_CHAIN_NAME => chain = cstr_to_string(attr.payload),
            NFTA_CHAIN_TYPE => chain_type = cstr_to_string(attr.payload),
            NFTA_CHAIN_POLICY => {
                if let Some(p) = read_u32_be(attr.payload) {
                    policy = policy_label(p).to_owned();
                }
            }
            NFTA_CHAIN_HOOK => {
                for hook_attr in nested_attrs(attr.payload) {
                    match hook_attr.ty {
                        NFTA_HOOK_HOOKNUM => {
                            if let Some(h) = read_u32_be(hook_attr.payload) {
                                hook = hook_label(h).to_owned();
                            }
                        }
                        NFTA_HOOK_PRIORITY => {
                            if let Some(p) = read_u32_be(hook_attr.payload) {
                                #[expect(
                                    clippy::cast_possible_wrap,
                                    reason = "nft hook priority is signed s32 in uapi; bit pattern preserved"
                                )]
                                {
                                    priority = p as i32;
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    if chain.is_empty() {
        return None;
    }

    Some(NftChain {
        table,
        chain,
        chain_type,
        hook,
        priority,
        policy,
    })
}

// ---------------------------------------------------------------------------
// Rule parsing (counter expression + userdata comment)
// ---------------------------------------------------------------------------

/// Walk a `NFTA_RULE_USERDATA` TLV blob and return the type-0 record as a
/// comment string, or `None` when absent or empty.
///
/// TLV layout: `[type: u8][len: u8][data: len bytes]...`
/// The null terminator (if present) is stripped.
fn extract_rule_comment(blob: &[u8]) -> Option<String> {
    let mut pos = 0usize;
    while pos + 2 <= blob.len() {
        let ty = blob[pos];
        let len = blob[pos + 1] as usize;
        let end = pos.saturating_add(2).saturating_add(len);
        if end > blob.len() {
            break;
        }
        if ty == 0 && len > 0 {
            // Strip trailing NUL if present.
            let data = &blob[pos + 2..end];
            let stripped = match data.last() {
                Some(&0) => &data[..data.len().saturating_sub(1)],
                _ => data,
            };
            let comment = String::from_utf8_lossy(stripped).into_owned();
            if !comment.is_empty() {
                return Some(comment);
            }
        }
        pos = pos.saturating_add(2).saturating_add(len);
    }
    None
}

/// Parse one `NFT_MSG_GETRULE` reply frame.
///
/// Returns `Some(NftRuleCounter)` only when:
/// - `NFTA_RULE_USERDATA` contains a non-empty type-0 TLV comment, AND
/// - `NFTA_RULE_EXPRESSIONS` contains an expr named `"counter"` with
///   `NFTA_COUNTER_BYTES` / `NFTA_COUNTER_PACKETS`.
///
/// Returns `None` for anonymous rules or rules without a counter expression.
fn parse_rule_frame(frame: &[u8]) -> Option<NftRuleCounter> {
    if frame.len() < NFGENMSG_LEN {
        return None;
    }
    let attrs_buf = &frame[NFGENMSG_LEN..];

    let mut table = String::new();
    let mut chain = String::new();
    let mut comment: Option<String> = None;
    let mut counter_bytes: Option<u64> = None;
    let mut counter_packets: Option<u64> = None;

    for attr in parse_attrs(attrs_buf) {
        match attr.ty {
            NFTA_RULE_TABLE => table = cstr_to_string(attr.payload),
            NFTA_RULE_CHAIN => chain = cstr_to_string(attr.payload),
            NFTA_RULE_USERDATA => {
                comment = extract_rule_comment(attr.payload);
            }
            NFTA_RULE_EXPRESSIONS => {
                // Walk the expression list; find the first "counter" expr.
                for list_attr in nested_attrs(attr.payload) {
                    if list_attr.ty != NFTA_LIST_ELEM {
                        continue;
                    }
                    let mut expr_name = String::new();
                    let mut expr_bytes: Option<u64> = None;
                    let mut expr_packets: Option<u64> = None;

                    for expr_attr in nested_attrs(list_attr.payload) {
                        match expr_attr.ty {
                            NFTA_EXPR_NAME => {
                                expr_name = cstr_to_string(expr_attr.payload);
                            }
                            NFTA_EXPR_DATA => {
                                for data_attr in nested_attrs(expr_attr.payload) {
                                    match data_attr.ty {
                                        NFTA_COUNTER_BYTES => {
                                            expr_bytes = read_u64_be(data_attr.payload);
                                        }
                                        NFTA_COUNTER_PACKETS => {
                                            expr_packets = read_u64_be(data_attr.payload);
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            _ => {}
                        }
                    }

                    if expr_name == "counter" {
                        counter_bytes = expr_bytes;
                        counter_packets = expr_packets;
                        break;
                    }
                }
            }
            _ => {}
        }
    }

    let comment = comment?;
    let bytes = counter_bytes?;
    let packets = counter_packets?;

    Some(NftRuleCounter {
        table,
        chain,
        comment,
        bytes,
        packets,
    })
}

// ---------------------------------------------------------------------------
// Object parsing — dispatcher + per-type parsers
// ---------------------------------------------------------------------------

/// Read only `NFTA_OBJ_TYPE` from a frame (fast-path for dispatch).
fn parse_obj_type(frame: &[u8]) -> Option<u32> {
    if frame.len() < NFGENMSG_LEN {
        return None;
    }
    for attr in parse_attrs(&frame[NFGENMSG_LEN..]) {
        if attr.ty == NFTA_OBJ_TYPE {
            return read_u32_be(attr.payload);
        }
    }
    None
}

/// Parse one `NFT_MSG_GETOBJ` frame as a named counter object.
fn parse_counter(frame: &[u8]) -> Option<NftCounter> {
    if frame.len() < NFGENMSG_LEN {
        return None;
    }
    let attrs_buf = &frame[NFGENMSG_LEN..];

    let mut table = String::new();
    let mut name = String::new();
    let mut obj_type: u32 = 0;
    let mut bytes: u64 = 0;
    let mut packets: u64 = 0;

    for attr in parse_attrs(attrs_buf) {
        match attr.ty {
            NFTA_OBJ_TABLE => table = cstr_to_string(attr.payload),
            NFTA_OBJ_NAME => name = cstr_to_string(attr.payload),
            NFTA_OBJ_TYPE => {
                obj_type = read_u32_be(attr.payload).unwrap_or(0);
            }
            NFTA_OBJ_DATA => {
                for data_attr in nested_attrs(attr.payload) {
                    match data_attr.ty {
                        NFTA_COUNTER_BYTES => {
                            bytes = read_u64_be(data_attr.payload).unwrap_or(0);
                        }
                        NFTA_COUNTER_PACKETS => {
                            packets = read_u64_be(data_attr.payload).unwrap_or(0);
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    if obj_type != NFT_OBJECT_COUNTER || name.is_empty() {
        return None;
    }

    Some(NftCounter {
        table,
        name,
        bytes,
        packets,
    })
}

/// Parse one `NFT_MSG_GETOBJ` frame as a named quota object.
fn parse_quota(frame: &[u8]) -> Option<NftQuota> {
    if frame.len() < NFGENMSG_LEN {
        return None;
    }
    let attrs_buf = &frame[NFGENMSG_LEN..];

    let mut table = String::new();
    let mut name = String::new();
    let mut obj_type: u32 = 0;
    let mut bytes_ceiling: u64 = 0;
    let mut bytes_consumed: u64 = 0;
    let mut quota_flags: u32 = 0;

    for attr in parse_attrs(attrs_buf) {
        match attr.ty {
            NFTA_OBJ_TABLE => table = cstr_to_string(attr.payload),
            NFTA_OBJ_NAME => name = cstr_to_string(attr.payload),
            NFTA_OBJ_TYPE => {
                obj_type = read_u32_be(attr.payload).unwrap_or(0);
            }
            NFTA_OBJ_DATA => {
                for data_attr in nested_attrs(attr.payload) {
                    match data_attr.ty {
                        NFTA_QUOTA_BYTES => {
                            bytes_ceiling = read_u64_be(data_attr.payload).unwrap_or(0);
                        }
                        NFTA_QUOTA_FLAGS => {
                            quota_flags = read_u32_be(data_attr.payload).unwrap_or(0);
                        }
                        NFTA_QUOTA_CONSUMED => {
                            bytes_consumed = read_u64_be(data_attr.payload).unwrap_or(0);
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    if obj_type != NFT_OBJECT_QUOTA || name.is_empty() {
        return None;
    }

    Some(NftQuota {
        table,
        name,
        bytes_ceiling,
        bytes_consumed,
        depleted: (quota_flags & NFT_QUOTA_F_DEPLETED) != 0,
    })
}

/// Parse one `NFT_MSG_GETOBJ` frame as a named limit object.
fn parse_limit(frame: &[u8]) -> Option<NftLimit> {
    if frame.len() < NFGENMSG_LEN {
        return None;
    }
    let attrs_buf = &frame[NFGENMSG_LEN..];

    let mut table = String::new();
    let mut name = String::new();
    let mut obj_type: u32 = 0;
    let mut rate: u64 = 0;
    let mut unit_secs: u64 = 1;
    let mut burst: u32 = 0;
    let mut limit_type_raw: u32 = 0;

    for attr in parse_attrs(attrs_buf) {
        match attr.ty {
            NFTA_OBJ_TABLE => table = cstr_to_string(attr.payload),
            NFTA_OBJ_NAME => name = cstr_to_string(attr.payload),
            NFTA_OBJ_TYPE => {
                obj_type = read_u32_be(attr.payload).unwrap_or(0);
            }
            NFTA_OBJ_DATA => {
                for data_attr in nested_attrs(attr.payload) {
                    match data_attr.ty {
                        NFTA_LIMIT_RATE => {
                            rate = read_u64_be(data_attr.payload).unwrap_or(0);
                        }
                        NFTA_LIMIT_UNIT => {
                            unit_secs = read_u64_be(data_attr.payload).unwrap_or(1);
                        }
                        NFTA_LIMIT_BURST => {
                            burst = read_u32_be(data_attr.payload).unwrap_or(0);
                        }
                        NFTA_LIMIT_TYPE => {
                            limit_type_raw = read_u32_be(data_attr.payload).unwrap_or(0);
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    if obj_type != NFT_OBJECT_LIMIT || name.is_empty() {
        return None;
    }

    Some(NftLimit {
        table,
        name,
        rate,
        unit_secs,
        burst,
        limit_type: limit_type_label(limit_type_raw).to_owned(),
    })
}

// ---------------------------------------------------------------------------
// Set parsing
// ---------------------------------------------------------------------------

/// Parse one `NFT_MSG_GETSET` reply frame into an [`NftSet`].
///
/// Returns `None` for anonymous sets (`NFT_SET_ANONYMOUS` flag).
fn parse_set_frame(frame: &[u8]) -> Option<NftSet> {
    if frame.len() < NFGENMSG_LEN {
        return None;
    }
    let attrs_buf = &frame[NFGENMSG_LEN..];

    let mut table = String::new();
    let mut name = String::new();
    let mut set_flags: u32 = 0;
    let mut key_type_raw: u32 = 0;
    let mut element_count: u32 = 0;

    for attr in parse_attrs(attrs_buf) {
        match attr.ty {
            NFTA_SET_TABLE => table = cstr_to_string(attr.payload),
            NFTA_SET_NAME => name = cstr_to_string(attr.payload),
            NFTA_SET_FLAGS => {
                set_flags = read_u32_be(attr.payload).unwrap_or(0);
            }
            NFTA_SET_KEY_TYPE => {
                key_type_raw = read_u32_be(attr.payload).unwrap_or(0);
            }
            NFTA_SET_COUNT => {
                element_count = read_u32_be(attr.payload).unwrap_or(0);
            }
            NFTA_SET_DESC => {
                // Fallback: read element count from NFTA_SET_DESC_SIZE when
                // NFTA_SET_COUNT is absent.
                if element_count == 0 {
                    for desc_attr in nested_attrs(attr.payload) {
                        if desc_attr.ty == NFTA_SET_DESC_SIZE {
                            element_count = read_u32_be(desc_attr.payload).unwrap_or(0);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    // Skip anonymous sets — cardinality guard (ADR-0005).
    if (set_flags & NFT_SET_ANONYMOUS) != 0 || name.is_empty() {
        return None;
    }

    Some(NftSet {
        table,
        name,
        key_type: key_type_label(key_type_raw).to_owned(),
        element_count,
    })
}

// ---------------------------------------------------------------------------
// Generation parsing
// ---------------------------------------------------------------------------

/// Parse one `NFT_MSG_GETGEN` reply frame and return `NFTA_GEN_ID` (BE u32).
fn parse_gen_frame(frame: &[u8]) -> Option<u32> {
    if frame.len() < NFGENMSG_LEN {
        return None;
    }
    for attr in parse_attrs(&frame[NFGENMSG_LEN..]) {
        if attr.ty == NFTA_GEN_ID {
            return read_u32_be(attr.payload);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Flowtable parsing
// ---------------------------------------------------------------------------

/// Parse one `NFT_MSG_GETFLOWTABLE` reply frame into an [`NftFlowtable`].
fn parse_flowtable_frame(frame: &[u8]) -> Option<NftFlowtable> {
    if frame.len() < NFGENMSG_LEN {
        return None;
    }
    let attrs_buf = &frame[NFGENMSG_LEN..];

    let mut table = String::new();
    let mut name = String::new();
    let mut hook = String::new();
    let mut priority: i32 = 0;
    let mut ft_flags: u32 = 0;

    for attr in parse_attrs(attrs_buf) {
        match attr.ty {
            NFTA_FLOWTABLE_TABLE => table = cstr_to_string(attr.payload),
            NFTA_FLOWTABLE_NAME => name = cstr_to_string(attr.payload),
            NFTA_FLOWTABLE_FLAGS => {
                ft_flags = read_u32_be(attr.payload).unwrap_or(0);
            }
            NFTA_FLOWTABLE_HOOK => {
                for hook_attr in nested_attrs(attr.payload) {
                    match hook_attr.ty {
                        NFTA_FLOWTABLE_HOOK_NUM => {
                            if let Some(h) = read_u32_be(hook_attr.payload) {
                                hook = hook_label(h).to_owned();
                            }
                        }
                        NFTA_FLOWTABLE_HOOK_PRIORITY => {
                            if let Some(p) = read_u32_be(hook_attr.payload) {
                                #[expect(
                                    clippy::cast_possible_wrap,
                                    reason = "flowtable hook priority is signed s32; bit pattern preserved"
                                )]
                                {
                                    priority = p as i32;
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    if name.is_empty() {
        return None;
    }

    Some(NftFlowtable {
        table,
        name,
        hook,
        priority,
        hw_offload: (ft_flags & NFT_FLOWTABLE_HW_OFFLOAD) != 0,
    })
}

// ---------------------------------------------------------------------------
// collect() metric builder
// ---------------------------------------------------------------------------

/// Build the full ADR-0030 metric surface from parsed read models.
///
/// `anonymous_rule_count` is the number of rules that were skipped because
/// they lacked a comment or counter expression.
#[allow(
    clippy::cast_precision_loss,
    reason = "metric gauge/counter values are f64; precision loss on large counters is inherent to Prometheus exposition"
)]
#[allow(
    clippy::too_many_arguments,
    reason = "all arguments represent orthogonal data domains"
)]
fn build_metrics(
    tables: &[NftTable],
    chains: &[NftChain],
    rule_counters: &[NftRuleCounter],
    named_counters: &[NftCounter],
    sets: &[NftSet],
    quotas: &[NftQuota],
    limits: &[NftLimit],
    generation: u32,
    flowtables: &[NftFlowtable],
    anonymous_rule_count: u64,
) -> Vec<MetricSample> {
    let mut out = Vec::new();

    // A. nft_table_info — one gauge=1 per table.
    for t in tables {
        let mut labels = BTreeMap::new();
        labels.insert("table".to_owned(), t.name.clone());
        labels.insert("family".to_owned(), t.family.clone());
        out.push(MetricSample::gauge(
            "nft_table_info",
            "Metadata gauge (always 1) for each nftables table.",
            labels,
            1.0,
        ));
    }

    // B. nft_chain_info — one gauge=1 per chain.
    for c in chains {
        let mut labels = BTreeMap::new();
        labels.insert("table".to_owned(), c.table.clone());
        labels.insert("chain".to_owned(), c.chain.clone());
        labels.insert("type".to_owned(), c.chain_type.clone());
        labels.insert("hook".to_owned(), c.hook.clone());
        labels.insert("priority".to_owned(), c.priority.to_string());
        labels.insert("policy".to_owned(), c.policy.clone());
        out.push(MetricSample::gauge(
            "nft_chain_info",
            "Metadata gauge (always 1) for each nftables chain.",
            labels,
            1.0,
        ));
    }

    // C. nft_rule_counter_{bytes,packets}_total — per-rule hit counters.
    // HARD CAP: emit at most RULE_COUNTER_MAX_SERIES commented-counter rules;
    // the excess is dropped and reported as cardinality_overflow (ADR-0030).
    // Anonymous/comment-less rules were already suppressed upstream and are
    // informational only here (not overflow).
    debug!(
        anonymous_rule_count,
        commented_rules = rule_counters.len(),
        "nftables rule-counter cardinality"
    );
    for rc in rule_counters.iter().take(RULE_COUNTER_MAX_SERIES) {
        let mut labels = BTreeMap::new();
        labels.insert("table".to_owned(), rc.table.clone());
        labels.insert("chain".to_owned(), rc.chain.clone());
        labels.insert("comment".to_owned(), rc.comment.clone());

        out.push(MetricSample::counter(
            "nft_rule_counter_bytes_total",
            "Total bytes matched by nftables rules carrying a counter expression.",
            labels.clone(),
            rc.bytes,
        ));
        out.push(MetricSample::counter(
            "nft_rule_counter_packets_total",
            "Total packets matched by nftables rules carrying a counter expression.",
            labels,
            rc.packets,
        ));
    }

    // Cardinality overflow guard: report the count of commented-counter rules
    // dropped because they exceeded the per-scrape hard cap.
    let dropped = rule_counters.len().saturating_sub(RULE_COUNTER_MAX_SERIES);
    if dropped > 0 {
        warn!(
            dropped,
            cap = RULE_COUNTER_MAX_SERIES,
            "nft_rule_counter series capped; excess dropped"
        );
        let mut labels = BTreeMap::new();
        labels.insert("collector".to_owned(), "nftables".to_owned());
        labels.insert("reason".to_owned(), "cardinality_overflow".to_owned());
        out.push(MetricSample::counter(
            "nft_scrape_collector_error_total",
            "Total errors during collection partitioned by collector and reason.",
            labels,
            dropped as u64,
        ));
    }

    // D. nft_named_counter_{bytes,packets}_total — named counter objects.
    for nc in named_counters {
        let mut labels = BTreeMap::new();
        labels.insert("table".to_owned(), nc.table.clone());
        labels.insert("name".to_owned(), nc.name.clone());

        out.push(MetricSample::counter(
            "nft_named_counter_bytes_total",
            "Total bytes counted by a named nftables counter object.",
            labels.clone(),
            nc.bytes,
        ));
        out.push(MetricSample::counter(
            "nft_named_counter_packets_total",
            "Total packets counted by a named nftables counter object.",
            labels,
            nc.packets,
        ));
    }

    // E. nft_set_elements — named set element counts.
    for s in sets {
        let mut labels = BTreeMap::new();
        labels.insert("table".to_owned(), s.table.clone());
        labels.insert("name".to_owned(), s.name.clone());
        labels.insert("type".to_owned(), s.key_type.clone());
        out.push(MetricSample::gauge(
            "nft_set_elements",
            "Current number of elements in a named nftables set or map.",
            labels,
            s.element_count as f64,
        ));
    }

    // F. nft_named_quota_* — quota object stats.
    for q in quotas {
        let mut labels = BTreeMap::new();
        labels.insert("table".to_owned(), q.table.clone());
        labels.insert("name".to_owned(), q.name.clone());

        out.push(MetricSample::gauge(
            "nft_named_quota_bytes_total",
            "Configured quota ceiling in bytes for a named nftables quota object.",
            labels.clone(),
            q.bytes_ceiling as f64,
        ));
        out.push(MetricSample::gauge(
            "nft_named_quota_consumed_bytes_total",
            "Bytes consumed against the quota ceiling for a named nftables quota object.",
            labels.clone(),
            q.bytes_consumed as f64,
        ));
        out.push(MetricSample::gauge(
            "nft_named_quota_depleted",
            "1 when the named quota object is depleted, 0 otherwise.",
            labels,
            if q.depleted { 1.0 } else { 0.0 },
        ));
    }

    // F2. nft_named_limit_{rate,burst} — limit object config.
    for l in limits {
        let mut labels = BTreeMap::new();
        labels.insert("table".to_owned(), l.table.clone());
        labels.insert("name".to_owned(), l.name.clone());
        labels.insert("type".to_owned(), l.limit_type.clone());

        out.push(MetricSample::gauge(
            "nft_named_limit_rate",
            "Configured rate for a named nftables limit object.",
            labels.clone(),
            l.rate as f64,
        ));
        out.push(MetricSample::gauge(
            "nft_named_limit_burst",
            "Configured burst allowance for a named nftables limit object.",
            labels,
            l.burst as f64,
        ));
    }

    // G. nft_ruleset_generation — single scalar, no labels.
    out.push(MetricSample::gauge(
        "nft_ruleset_generation",
        "Current nftables ruleset generation ID (NFTA_GEN_ID).",
        BTreeMap::new(),
        generation as f64,
    ));

    // H. nft_flowtable_info — one gauge=1 per flowtable.
    for ft in flowtables {
        let mut labels = BTreeMap::new();
        labels.insert("table".to_owned(), ft.table.clone());
        labels.insert("name".to_owned(), ft.name.clone());
        labels.insert("hook".to_owned(), ft.hook.clone());
        labels.insert("priority".to_owned(), ft.priority.to_string());
        labels.insert(
            "hw_offload".to_owned(),
            if ft.hw_offload {
                "1".to_owned()
            } else {
                "0".to_owned()
            },
        );
        out.push(MetricSample::gauge(
            "nft_flowtable_info",
            "Metadata gauge (always 1) for each nftables flowtable.",
            labels,
            1.0,
        ));
    }

    out
}

// ---------------------------------------------------------------------------
// NftablesCollector
// ---------------------------------------------------------------------------

/// Adapter implementing [`NetlinkNftablesPort`] and [`Collector`] for the full
/// ADR-0030 nftables firewall observability surface.
pub struct NftablesCollector;

impl NetlinkNftablesPort for NftablesCollector {
    async fn dump_tables(&self) -> Result<Vec<NftTable>, DomainError> {
        let mut sock = NetlinkSocket::open(NETLINK_NETFILTER)
            .map_err(|e| DomainError::Collector(e.to_string()))?;
        let frames = nft_dump(&mut sock, NFT_MSG_GETTABLE, 0)
            .await
            .map_err(|e| DomainError::Collector(e.to_string()))?;
        debug!(frames = frames.len(), "NFT_MSG_GETTABLE frames");
        Ok(frames.iter().filter_map(|f| parse_table_frame(f)).collect())
    }

    async fn dump_chains(&self) -> Result<Vec<NftChain>, DomainError> {
        let mut sock = NetlinkSocket::open(NETLINK_NETFILTER)
            .map_err(|e| DomainError::Collector(e.to_string()))?;
        let frames = nft_dump(&mut sock, NFT_MSG_GETCHAIN, 0)
            .await
            .map_err(|e| DomainError::Collector(e.to_string()))?;
        debug!(frames = frames.len(), "NFT_MSG_GETCHAIN frames");
        Ok(frames.iter().filter_map(|f| parse_chain_frame(f)).collect())
    }

    async fn dump_counters(&self) -> Result<Vec<NftCounter>, DomainError> {
        let mut sock = NetlinkSocket::open(NETLINK_NETFILTER)
            .map_err(|e| DomainError::Collector(e.to_string()))?;
        let frames = nft_dump(&mut sock, NFT_MSG_GETOBJ, 0)
            .await
            .map_err(|e| DomainError::Collector(e.to_string()))?;
        debug!(frames = frames.len(), "NFT_MSG_GETOBJ frames");
        Ok(frames.iter().filter_map(|f| parse_counter(f)).collect())
    }

    async fn dump_sets(&self) -> Result<Vec<NftSet>, DomainError> {
        let mut sock = NetlinkSocket::open(NETLINK_NETFILTER)
            .map_err(|e| DomainError::Collector(e.to_string()))?;
        let frames = nft_dump(&mut sock, NFT_MSG_GETSET, 0)
            .await
            .map_err(|e| DomainError::Collector(e.to_string()))?;
        debug!(frames = frames.len(), "NFT_MSG_GETSET frames");
        Ok(frames.iter().filter_map(|f| parse_set_frame(f)).collect())
    }

    async fn dump_rule_counters(&self) -> Result<Vec<NftRuleCounter>, DomainError> {
        let mut sock = NetlinkSocket::open(NETLINK_NETFILTER)
            .map_err(|e| DomainError::Collector(e.to_string()))?;
        let frames = nft_dump(&mut sock, NFT_MSG_GETRULE, 0)
            .await
            .map_err(|e| DomainError::Collector(e.to_string()))?;
        debug!(frames = frames.len(), "NFT_MSG_GETRULE frames");
        Ok(frames.iter().filter_map(|f| parse_rule_frame(f)).collect())
    }

    async fn dump_quota_objects(&self) -> Result<Vec<NftQuota>, DomainError> {
        let mut sock = NetlinkSocket::open(NETLINK_NETFILTER)
            .map_err(|e| DomainError::Collector(e.to_string()))?;
        let frames = nft_dump(&mut sock, NFT_MSG_GETOBJ, 0)
            .await
            .map_err(|e| DomainError::Collector(e.to_string()))?;
        debug!(frames = frames.len(), "NFT_MSG_GETOBJ (quota) frames");
        Ok(frames.iter().filter_map(|f| parse_quota(f)).collect())
    }

    async fn dump_limit_objects(&self) -> Result<Vec<NftLimit>, DomainError> {
        let mut sock = NetlinkSocket::open(NETLINK_NETFILTER)
            .map_err(|e| DomainError::Collector(e.to_string()))?;
        let frames = nft_dump(&mut sock, NFT_MSG_GETOBJ, 0)
            .await
            .map_err(|e| DomainError::Collector(e.to_string()))?;
        debug!(frames = frames.len(), "NFT_MSG_GETOBJ (limit) frames");
        Ok(frames.iter().filter_map(|f| parse_limit(f)).collect())
    }

    async fn get_ruleset_generation(&self) -> Result<u32, DomainError> {
        let mut sock = NetlinkSocket::open(NETLINK_NETFILTER)
            .map_err(|e| DomainError::Collector(e.to_string()))?;
        // GETGEN is a single GET, NOT a NLM_F_DUMP request. Using the dump loop
        // would block forever waiting for an NLMSG_DONE that a non-dump GETGEN
        // reply never sends — use request_single (one send, one recv).
        let payload = nfgenmsg(0);
        let reply = sock
            .request_single(NFT_MSG_GETGEN, 0, &payload)
            .await
            .map_err(|e| DomainError::Collector(e.to_string()))?;
        debug!(present = reply.is_some(), "NFT_MSG_GETGEN reply");
        Ok(reply.and_then(|f| parse_gen_frame(&f)).unwrap_or(0))
    }

    async fn dump_flowtables(&self) -> Result<Vec<NftFlowtable>, DomainError> {
        let mut sock = NetlinkSocket::open(NETLINK_NETFILTER)
            .map_err(|e| DomainError::Collector(e.to_string()))?;
        let frames = nft_dump(&mut sock, NFT_MSG_GETFLOWTABLE, 0)
            .await
            .map_err(|e| DomainError::Collector(e.to_string()))?;
        debug!(frames = frames.len(), "NFT_MSG_GETFLOWTABLE frames");
        Ok(frames
            .iter()
            .filter_map(|f| parse_flowtable_frame(f))
            .collect())
    }
}

impl Collector for NftablesCollector {
    fn name(&self) -> &'static str {
        "nftables"
    }

    fn collect(&self) -> BoxFuture<'_, Result<Vec<MetricSample>, CollectError>> {
        Box::pin(async move {
            // Each dump uses its OWN fresh NETLINK_NETFILTER socket (sequential
            // dumps on a shared socket stall). GETGEN is a single GET handled by
            // get_ruleset_generation via request_single, NOT the dump loop.
            let tables = self.dump_tables().await.map_err(map_domain_err)?;
            let chains = self.dump_chains().await.map_err(map_domain_err)?;
            let rule_counters = self.dump_rule_counters().await.map_err(map_domain_err)?;
            let named_counters = self.dump_counters().await.map_err(map_domain_err)?;
            let sets = self.dump_sets().await.map_err(map_domain_err)?;
            let quotas = self.dump_quota_objects().await.map_err(map_domain_err)?;
            let limits = self.dump_limit_objects().await.map_err(map_domain_err)?;
            let generation = self
                .get_ruleset_generation()
                .await
                .map_err(map_domain_err)?;
            let flowtables = self.dump_flowtables().await.map_err(map_domain_err)?;

            debug!(
                tables = tables.len(),
                chains = chains.len(),
                rule_counters = rule_counters.len(),
                named_counters = named_counters.len(),
                quotas = quotas.len(),
                limits = limits.len(),
                sets = sets.len(),
                generation,
                flowtables = flowtables.len(),
                "nftables collect complete"
            );

            // anonymous_rule_count is informational only (overflow is driven by
            // the emitted-series hard cap inside build_metrics).
            Ok(build_metrics(
                &tables,
                &chains,
                &rule_counters,
                &named_counters,
                &sets,
                &quotas,
                &limits,
                generation,
                &flowtables,
                0,
            ))
        })
    }

    fn probe_available(&self) -> BoxFuture<'_, bool> {
        Box::pin(async move {
            match NetlinkSocket::open(NETLINK_NETFILTER) {
                Err(_) => false,
                Ok(mut sock) => nft_dump(&mut sock, NFT_MSG_GETTABLE, 0).await.is_ok(),
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

fn map_domain_err(e: DomainError) -> CollectError {
    CollectError::Io(e.to_string())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test assertions; panics are acceptable in test code"
)]
mod tests {
    use super::*;
    use crate::wire::{NLA_HDRLEN, align4};

    // -----------------------------------------------------------------------
    // Wire frame helpers
    // -----------------------------------------------------------------------

    #[allow(
        clippy::cast_possible_truncation,
        reason = "nlattr length fits u16 by construction in test fixtures"
    )]
    fn make_nla(ty: u16, payload: &[u8]) -> Vec<u8> {
        let nla_len = NLA_HDRLEN + payload.len();
        let padded = align4(nla_len);
        let mut out = Vec::with_capacity(padded);
        out.extend_from_slice(&(nla_len as u16).to_ne_bytes());
        out.extend_from_slice(&ty.to_ne_bytes());
        out.extend_from_slice(payload);
        out.resize(padded, 0u8);
        out
    }

    fn make_nested_nla(ty: u16, inner: &[u8]) -> Vec<u8> {
        make_nla(ty | 0x8000u16, inner) // NLA_F_NESTED set in wire encoding
    }

    fn make_table_frame(family: u8, name: &str) -> Vec<u8> {
        let mut frame = vec![family, 0u8, 0u8, 0u8]; // nfgenmsg
        let mut nul_name = name.as_bytes().to_vec();
        nul_name.push(0u8);
        frame.extend_from_slice(&make_nla(NFTA_TABLE_NAME, &nul_name));
        frame
    }

    /// Build a chain frame with HOOK nested containing HOOKNUM + PRIORITY (BE).
    fn make_chain_frame_be(hooknum: u32, priority: i32, policy: u32) -> Vec<u8> {
        let mut frame = vec![2u8, 0u8, 0u8, 0u8]; // nfgenmsg AF_INET(2)
        frame.extend_from_slice(&make_nla(NFTA_CHAIN_TABLE, b"filter "));
        frame.extend_from_slice(&make_nla(NFTA_CHAIN_NAME, b"input "));
        frame.extend_from_slice(&make_nla(NFTA_CHAIN_TYPE, b"filter "));

        let mut hook_inner = make_nla(NFTA_HOOK_HOOKNUM, &hooknum.to_be_bytes());
        #[expect(
            clippy::cast_sign_loss,
            reason = "reinterpret signed priority bits as u32 for big-endian wire encoding"
        )]
        hook_inner.extend_from_slice(&make_nla(
            NFTA_HOOK_PRIORITY,
            &(priority as u32).to_be_bytes(),
        ));
        frame.extend_from_slice(&make_nested_nla(NFTA_CHAIN_HOOK, &hook_inner));
        frame.extend_from_slice(&make_nla(NFTA_CHAIN_POLICY, &policy.to_be_bytes()));
        frame
    }

    /// Build a rule frame with a "counter" expression and a userdata comment.
    fn make_rule_frame_with_counter(
        table: &str,
        chain: &str,
        comment: &str,
        bytes: u64,
        packets: u64,
    ) -> Vec<u8> {
        let mut frame = vec![0u8; 4]; // nfgenmsg

        // Table + chain
        let mut tbl = table.as_bytes().to_vec();
        tbl.push(0u8);
        let mut chn = chain.as_bytes().to_vec();
        chn.push(0u8);
        frame.extend_from_slice(&make_nla(NFTA_RULE_TABLE, &tbl));
        frame.extend_from_slice(&make_nla(NFTA_RULE_CHAIN, &chn));

        // Userdata TLV: type=0, len=comment.len()+1, data=comment+NUL
        let comment_bytes = comment.as_bytes();
        let tlv_len = comment_bytes.len() + 1; // +1 for NUL
        let mut userdata = vec![0u8, tlv_len as u8];
        userdata.extend_from_slice(comment_bytes);
        userdata.push(0u8); // NUL terminator
        frame.extend_from_slice(&make_nla(NFTA_RULE_USERDATA, &userdata));

        // Expressions: one LIST_ELEM containing EXPR_NAME="counter" + EXPR_DATA
        let mut expr_name_bytes = b"counter".to_vec();
        expr_name_bytes.push(0u8);
        let expr_name_nla = make_nla(NFTA_EXPR_NAME, &expr_name_bytes);

        let bytes_nla = make_nla(NFTA_COUNTER_BYTES, &bytes.to_be_bytes());
        let pkts_nla = make_nla(NFTA_COUNTER_PACKETS, &packets.to_be_bytes());
        let mut counter_data = bytes_nla;
        counter_data.extend_from_slice(&pkts_nla);
        let expr_data_nla = make_nested_nla(NFTA_EXPR_DATA, &counter_data);

        let mut expr_inner = expr_name_nla;
        expr_inner.extend_from_slice(&expr_data_nla);
        let list_elem_nla = make_nested_nla(NFTA_LIST_ELEM, &expr_inner);

        let exprs_nla = make_nested_nla(NFTA_RULE_EXPRESSIONS, &list_elem_nla);
        frame.extend_from_slice(&exprs_nla);

        frame
    }

    // -----------------------------------------------------------------------
    // Table tests
    // -----------------------------------------------------------------------

    #[test]
    fn parse_table_frame_basic() {
        let frame = make_table_frame(2, "my_table"); // AF_INET
        let table = parse_table_frame(&frame).expect("should parse");
        assert_eq!(table.family, "ip");
        assert_eq!(table.name, "my_table");
    }

    #[test]
    fn parse_table_frame_empty_name_returns_none() {
        let frame = vec![1u8, 0u8, 0u8, 0u8]; // nfgenmsg only, no NFTA_TABLE_NAME
        assert!(parse_table_frame(&frame).is_none());
    }

    // -----------------------------------------------------------------------
    // Chain tests (existing + extended coverage)
    // -----------------------------------------------------------------------

    #[test]
    fn parse_chain_frame_policy_accept_big_endian() {
        let frame = make_chain_frame_be(1, 0, 1 /* NF_ACCEPT */);
        let chain = parse_chain_frame(&frame).expect("should parse chain frame");
        assert_eq!(chain.policy, "accept");
    }

    #[test]
    fn parse_chain_frame_policy_drop_big_endian() {
        let frame = make_chain_frame_be(3, 0, 0 /* NF_DROP */);
        let chain = parse_chain_frame(&frame).expect("should parse chain frame");
        assert_eq!(chain.policy, "drop");
    }

    #[test]
    fn parse_chain_frame_hooknum_input_big_endian() {
        let frame = make_chain_frame_be(1, 0, 1);
        let chain = parse_chain_frame(&frame).expect("should parse");
        assert_eq!(chain.hook, "input");
    }

    #[test]
    fn parse_chain_frame_hooknum_forward_big_endian() {
        let frame = make_chain_frame_be(2, 0, 1);
        let chain = parse_chain_frame(&frame).expect("should parse");
        assert_eq!(chain.hook, "forward");
    }

    #[test]
    fn parse_chain_frame_priority_negative_big_endian() {
        let frame = make_chain_frame_be(1, -100, 1);
        let chain = parse_chain_frame(&frame).expect("should parse");
        assert_eq!(chain.priority, -100);
    }

    // -----------------------------------------------------------------------
    // Rule counter tests
    // -----------------------------------------------------------------------

    #[test]
    fn parse_rule_frame_with_comment_and_counter() {
        let frame = make_rule_frame_with_counter("filter", "input", "allow_https", 4096, 32);
        let rc = parse_rule_frame(&frame).expect("should parse rule with counter+comment");
        assert_eq!(rc.table, "filter");
        assert_eq!(rc.chain, "input");
        assert_eq!(rc.comment, "allow_https");
        assert_eq!(rc.bytes, 4096);
        assert_eq!(rc.packets, 32);
    }

    #[test]
    fn parse_rule_frame_anonymous_returns_none() {
        // Rule with no NFTA_RULE_USERDATA → no comment → None.
        let mut frame = vec![0u8; 4];
        frame.extend_from_slice(&make_nla(NFTA_RULE_TABLE, b"filter\0"));
        frame.extend_from_slice(&make_nla(NFTA_RULE_CHAIN, b"input\0"));
        // Expressions with counter but no userdata.
        let bytes_nla = make_nla(NFTA_COUNTER_BYTES, &0u64.to_be_bytes());
        let pkts_nla = make_nla(NFTA_COUNTER_PACKETS, &0u64.to_be_bytes());
        let mut counter_data = bytes_nla;
        counter_data.extend_from_slice(&pkts_nla);
        let expr_data_nla = make_nested_nla(NFTA_EXPR_DATA, &counter_data);
        let expr_name_nla = make_nla(NFTA_EXPR_NAME, b"counter\0");
        let mut expr_inner = expr_name_nla;
        expr_inner.extend_from_slice(&expr_data_nla);
        let list_elem = make_nested_nla(NFTA_LIST_ELEM, &expr_inner);
        let exprs = make_nested_nla(NFTA_RULE_EXPRESSIONS, &list_elem);
        frame.extend_from_slice(&exprs);
        assert!(parse_rule_frame(&frame).is_none());
    }

    #[test]
    fn parse_rule_frame_no_counter_returns_none() {
        // Rule has comment but only a "meta" expression (no counter).
        let mut frame = vec![0u8; 4];
        frame.extend_from_slice(&make_nla(NFTA_RULE_TABLE, b"filter\0"));
        frame.extend_from_slice(&make_nla(NFTA_RULE_CHAIN, b"input\0"));
        // Userdata with comment.
        let comment_bytes = b"my_rule";
        let tlv_len = comment_bytes.len() + 1;
        let mut userdata = vec![0u8, tlv_len as u8];
        userdata.extend_from_slice(comment_bytes);
        userdata.push(0u8);
        frame.extend_from_slice(&make_nla(NFTA_RULE_USERDATA, &userdata));
        // Expression: "meta" (not counter).
        let expr_name_nla = make_nla(NFTA_EXPR_NAME, b"meta\0");
        let list_elem = make_nested_nla(NFTA_LIST_ELEM, &expr_name_nla);
        let exprs = make_nested_nla(NFTA_RULE_EXPRESSIONS, &list_elem);
        frame.extend_from_slice(&exprs);
        assert!(parse_rule_frame(&frame).is_none());
    }

    // -----------------------------------------------------------------------
    // Named counter object tests (existing)
    // -----------------------------------------------------------------------

    #[test]
    fn parse_counter_obj_bytes_big_endian() {
        let bytes_be: u64 = 0x0102_0304_0506_0708;
        let pkts_be: u64 = 0x0000_0000_0000_0042;

        let bytes_nla = make_nla(NFTA_COUNTER_BYTES, &bytes_be.to_be_bytes());
        let pkts_nla = make_nla(NFTA_COUNTER_PACKETS, &pkts_be.to_be_bytes());
        let mut data_inner = bytes_nla;
        data_inner.extend_from_slice(&pkts_nla);
        let obj_data_nla = make_nested_nla(NFTA_OBJ_DATA, &data_inner);

        let mut frame = vec![0u8; 4];
        frame.extend_from_slice(&make_nla(NFTA_OBJ_TABLE, b"filter\0"));
        frame.extend_from_slice(&make_nla(NFTA_OBJ_NAME, b"my_counter\0"));
        frame.extend_from_slice(&make_nla(NFTA_OBJ_TYPE, &1u32.to_be_bytes()));
        frame.extend_from_slice(&obj_data_nla);

        let counter = parse_counter(&frame).expect("should parse counter frame");
        assert_eq!(counter.bytes, bytes_be);
        assert_eq!(counter.packets, pkts_be);
    }

    #[test]
    fn parse_obj_frame_non_counter_returns_none_for_parse_counter() {
        let mut frame = vec![0u8; 4];
        frame.extend_from_slice(&make_nla(NFTA_OBJ_TYPE, &2u32.to_be_bytes())); // quota
        frame.extend_from_slice(&make_nla(NFTA_OBJ_NAME, b"x\0"));
        assert!(parse_counter(&frame).is_none());
    }

    // -----------------------------------------------------------------------
    // Set tests
    // -----------------------------------------------------------------------

    #[test]
    fn parse_set_frame_named_set() {
        let mut frame = vec![0u8; 4];
        frame.extend_from_slice(&make_nla(NFTA_SET_TABLE, b"filter\0"));
        frame.extend_from_slice(&make_nla(NFTA_SET_NAME, b"blacklist\0"));
        frame.extend_from_slice(&make_nla(NFTA_SET_FLAGS, &0u32.to_be_bytes()));
        frame.extend_from_slice(&make_nla(NFTA_SET_KEY_TYPE, &0x000cu32.to_be_bytes())); // ipv4_addr
        frame.extend_from_slice(&make_nla(NFTA_SET_COUNT, &42u32.to_be_bytes()));

        let set = parse_set_frame(&frame).expect("should parse named set");
        assert_eq!(set.table, "filter");
        assert_eq!(set.name, "blacklist");
        assert_eq!(set.key_type, "ipv4_addr");
        assert_eq!(set.element_count, 42);
    }

    #[test]
    fn parse_set_frame_anonymous_excluded() {
        let mut frame = vec![0u8; 4];
        frame.extend_from_slice(&make_nla(NFTA_SET_TABLE, b"filter\0"));
        frame.extend_from_slice(&make_nla(NFTA_SET_NAME, b"__anon_set\0"));
        frame.extend_from_slice(&make_nla(NFTA_SET_FLAGS, &NFT_SET_ANONYMOUS.to_be_bytes()));
        frame.extend_from_slice(&make_nla(NFTA_SET_COUNT, &10u32.to_be_bytes()));
        assert!(parse_set_frame(&frame).is_none());
    }

    // -----------------------------------------------------------------------
    // Generation test
    // -----------------------------------------------------------------------

    #[test]
    fn parse_gen_frame_be() {
        let mut frame = vec![0u8; 4]; // nfgenmsg
        frame.extend_from_slice(&make_nla(NFTA_GEN_ID, &42u32.to_be_bytes()));
        let gen_id = parse_gen_frame(&frame).expect("should parse gen frame");
        assert_eq!(gen_id, 42);
    }

    // -----------------------------------------------------------------------
    // Quota tests
    // -----------------------------------------------------------------------

    #[test]
    fn parse_quota_frame_depleted() {
        let quota_flags = NFT_QUOTA_F_DEPLETED;

        let bytes_nla = make_nla(NFTA_QUOTA_BYTES, &1_000_000u64.to_be_bytes());
        let flags_nla = make_nla(NFTA_QUOTA_FLAGS, &quota_flags.to_be_bytes());
        let consumed_nla = make_nla(NFTA_QUOTA_CONSUMED, &1_000_001u64.to_be_bytes());

        let mut data_inner = bytes_nla;
        data_inner.extend_from_slice(&flags_nla);
        data_inner.extend_from_slice(&consumed_nla);
        let obj_data_nla = make_nested_nla(NFTA_OBJ_DATA, &data_inner);

        let mut frame = vec![0u8; 4];
        frame.extend_from_slice(&make_nla(NFTA_OBJ_TABLE, b"filter\0"));
        frame.extend_from_slice(&make_nla(NFTA_OBJ_NAME, b"monthly_cap\0"));
        frame.extend_from_slice(&make_nla(NFTA_OBJ_TYPE, &NFT_OBJECT_QUOTA.to_be_bytes()));
        frame.extend_from_slice(&obj_data_nla);

        let quota = parse_quota(&frame).expect("should parse quota");
        assert!(quota.depleted, "quota should be marked depleted");
        assert_eq!(quota.bytes_ceiling, 1_000_000);
        assert_eq!(quota.bytes_consumed, 1_000_001);
    }

    #[test]
    fn parse_quota_frame_not_depleted() {
        let bytes_nla = make_nla(NFTA_QUOTA_BYTES, &1_000_000u64.to_be_bytes());
        let flags_nla = make_nla(NFTA_QUOTA_FLAGS, &0u32.to_be_bytes());
        let consumed_nla = make_nla(NFTA_QUOTA_CONSUMED, &500_000u64.to_be_bytes());

        let mut data_inner = bytes_nla;
        data_inner.extend_from_slice(&flags_nla);
        data_inner.extend_from_slice(&consumed_nla);
        let obj_data_nla = make_nested_nla(NFTA_OBJ_DATA, &data_inner);

        let mut frame = vec![0u8; 4];
        frame.extend_from_slice(&make_nla(NFTA_OBJ_TABLE, b"filter\0"));
        frame.extend_from_slice(&make_nla(NFTA_OBJ_NAME, b"daily_cap\0"));
        frame.extend_from_slice(&make_nla(NFTA_OBJ_TYPE, &NFT_OBJECT_QUOTA.to_be_bytes()));
        frame.extend_from_slice(&obj_data_nla);

        let quota = parse_quota(&frame).expect("should parse quota");
        assert!(!quota.depleted);
        assert_eq!(quota.bytes_consumed, 500_000);
    }

    // -----------------------------------------------------------------------
    // Limit tests
    // -----------------------------------------------------------------------

    #[test]
    fn parse_limit_frame_bytes_type() {
        let rate_nla = make_nla(NFTA_LIMIT_RATE, &1_000_000u64.to_be_bytes());
        let unit_nla = make_nla(NFTA_LIMIT_UNIT, &1u64.to_be_bytes()); // 1 second
        let burst_nla = make_nla(NFTA_LIMIT_BURST, &256u32.to_be_bytes());
        let type_nla = make_nla(NFTA_LIMIT_TYPE, &1u32.to_be_bytes()); // NFT_LIMIT_PKT_BYTES

        let mut data_inner = rate_nla;
        data_inner.extend_from_slice(&unit_nla);
        data_inner.extend_from_slice(&burst_nla);
        data_inner.extend_from_slice(&type_nla);
        let obj_data_nla = make_nested_nla(NFTA_OBJ_DATA, &data_inner);

        let mut frame = vec![0u8; 4];
        frame.extend_from_slice(&make_nla(NFTA_OBJ_TABLE, b"filter\0"));
        frame.extend_from_slice(&make_nla(NFTA_OBJ_NAME, b"bw_limit\0"));
        frame.extend_from_slice(&make_nla(NFTA_OBJ_TYPE, &NFT_OBJECT_LIMIT.to_be_bytes()));
        frame.extend_from_slice(&obj_data_nla);

        let limit = parse_limit(&frame).expect("should parse limit");
        assert_eq!(limit.limit_type, "bytes");
        assert_eq!(limit.rate, 1_000_000);
        assert_eq!(limit.burst, 256);
        assert_eq!(limit.unit_secs, 1);
    }

    #[test]
    fn parse_limit_frame_pkts_type() {
        let rate_nla = make_nla(NFTA_LIMIT_RATE, &100u64.to_be_bytes());
        let unit_nla = make_nla(NFTA_LIMIT_UNIT, &1u64.to_be_bytes());
        let burst_nla = make_nla(NFTA_LIMIT_BURST, &0u32.to_be_bytes());
        let type_nla = make_nla(NFTA_LIMIT_TYPE, &0u32.to_be_bytes()); // NFT_LIMIT_PKTS

        let mut data_inner = rate_nla;
        data_inner.extend_from_slice(&unit_nla);
        data_inner.extend_from_slice(&burst_nla);
        data_inner.extend_from_slice(&type_nla);
        let obj_data_nla = make_nested_nla(NFTA_OBJ_DATA, &data_inner);

        let mut frame = vec![0u8; 4];
        frame.extend_from_slice(&make_nla(NFTA_OBJ_TABLE, b"filter\0"));
        frame.extend_from_slice(&make_nla(NFTA_OBJ_NAME, b"syn_limit\0"));
        frame.extend_from_slice(&make_nla(NFTA_OBJ_TYPE, &NFT_OBJECT_LIMIT.to_be_bytes()));
        frame.extend_from_slice(&obj_data_nla);

        let limit = parse_limit(&frame).expect("should parse limit");
        assert_eq!(limit.limit_type, "pkts");
    }

    // -----------------------------------------------------------------------
    // Flowtable tests
    // -----------------------------------------------------------------------

    #[test]
    fn parse_flowtable_frame_hw_offload_on() {
        let flags = NFT_FLOWTABLE_HW_OFFLOAD;

        let mut hook_inner = make_nla(NFTA_FLOWTABLE_HOOK_NUM, &5u32.to_be_bytes()); // ingress
        hook_inner.extend_from_slice(&make_nla(NFTA_FLOWTABLE_HOOK_PRIORITY, &0i32.to_be_bytes()));
        let hook_nla = make_nested_nla(NFTA_FLOWTABLE_HOOK, &hook_inner);

        let mut frame = vec![0u8; 4];
        frame.extend_from_slice(&make_nla(NFTA_FLOWTABLE_TABLE, b"filter\0"));
        frame.extend_from_slice(&make_nla(NFTA_FLOWTABLE_NAME, b"ft0\0"));
        frame.extend_from_slice(&hook_nla);
        frame.extend_from_slice(&make_nla(NFTA_FLOWTABLE_FLAGS, &flags.to_be_bytes()));

        let ft = parse_flowtable_frame(&frame).expect("should parse flowtable");
        assert!(ft.hw_offload, "hw_offload bit must be set");
        assert_eq!(ft.name, "ft0");
        assert_eq!(ft.hook, "ingress");
    }

    #[test]
    fn parse_flowtable_frame_no_offload() {
        let mut hook_inner = make_nla(NFTA_FLOWTABLE_HOOK_NUM, &1u32.to_be_bytes());
        hook_inner.extend_from_slice(&make_nla(NFTA_FLOWTABLE_HOOK_PRIORITY, &0u32.to_be_bytes()));
        let hook_nla = make_nested_nla(NFTA_FLOWTABLE_HOOK, &hook_inner);

        let mut frame = vec![0u8; 4];
        frame.extend_from_slice(&make_nla(NFTA_FLOWTABLE_TABLE, b"nat\0"));
        frame.extend_from_slice(&make_nla(NFTA_FLOWTABLE_NAME, b"sw_ft\0"));
        frame.extend_from_slice(&hook_nla);
        frame.extend_from_slice(&make_nla(NFTA_FLOWTABLE_FLAGS, &0u32.to_be_bytes()));

        let ft = parse_flowtable_frame(&frame).expect("should parse flowtable");
        assert!(!ft.hw_offload);
    }

    // -----------------------------------------------------------------------
    // build_metrics tests
    // -----------------------------------------------------------------------

    #[test]
    fn build_metrics_table_info_one_per_table() {
        let tables = vec![
            NftTable {
                name: "filter".to_owned(),
                family: "ip".to_owned(),
            },
            NftTable {
                name: "nat".to_owned(),
                family: "inet".to_owned(),
            },
        ];
        let metrics = build_metrics(&tables, &[], &[], &[], &[], &[], &[], 0, &[], 0);
        let table_info: Vec<_> = metrics
            .iter()
            .filter(|s| s.name == "nft_table_info")
            .collect();
        assert_eq!(table_info.len(), 2);
        assert!(table_info.iter().any(|s| {
            s.labels
                .get("table")
                .map(|v| v == "filter")
                .unwrap_or(false)
        }));
        assert!(
            table_info
                .iter()
                .any(|s| s.labels.get("table").map(|v| v == "nat").unwrap_or(false))
        );
    }

    #[test]
    fn build_metrics_chain_info_has_priority_label() {
        let chains = vec![NftChain {
            table: "filter".to_owned(),
            chain: "input".to_owned(),
            chain_type: "filter".to_owned(),
            hook: "input".to_owned(),
            priority: -100,
            policy: "drop".to_owned(),
        }];
        let metrics = build_metrics(&[], &chains, &[], &[], &[], &[], &[], 0, &[], 0);
        let chain_info = metrics
            .iter()
            .find(|s| s.name == "nft_chain_info")
            .expect("nft_chain_info must be emitted");
        assert_eq!(
            chain_info.labels.get("priority").map(|v| v.as_str()),
            Some("-100")
        );
    }

    #[test]
    fn build_metrics_named_counter_correct_prefix() {
        let counters = vec![NftCounter {
            table: "filter".to_owned(),
            name: "http_in".to_owned(),
            bytes: 1024,
            packets: 8,
        }];
        let metrics = build_metrics(&[], &[], &[], &counters, &[], &[], &[], 0, &[], 0);
        assert!(
            metrics
                .iter()
                .any(|s| s.name == "nft_named_counter_bytes_total"),
            "must emit nft_named_counter_bytes_total"
        );
        assert!(
            metrics
                .iter()
                .any(|s| s.name == "nft_named_counter_packets_total"),
            "must emit nft_named_counter_packets_total"
        );
        // Old incorrect prefix must NOT appear.
        assert!(
            !metrics
                .iter()
                .any(|s| s.name == "nft_nft_counter_bytes_total"),
            "old nft_nft_counter_bytes_total must NOT be emitted"
        );
    }

    #[test]
    fn build_metrics_ruleset_generation_emitted() {
        let metrics = build_metrics(&[], &[], &[], &[], &[], &[], &[], 99, &[], 0);
        let gen_metric = metrics
            .iter()
            .find(|s| s.name == "nft_ruleset_generation")
            .expect("nft_ruleset_generation must be emitted");
        assert!(gen_metric.labels.is_empty(), "generation has no labels");
        assert_eq!(gen_metric.value, nlx_domain::metric::MetricValue::F64(99.0));
    }

    fn rc(i: usize) -> NftRuleCounter {
        NftRuleCounter {
            table: "t".to_owned(),
            chain: "c".to_owned(),
            comment: format!("rule{i}"),
            bytes: 1,
            packets: 1,
        }
    }

    #[test]
    fn build_metrics_cardinality_overflow_emitted_when_exceeded() {
        // RULE_COUNTER_MAX_SERIES + 1 commented rules → cap at MAX, 1 dropped.
        let rcs: Vec<NftRuleCounter> = (0..=RULE_COUNTER_MAX_SERIES).map(rc).collect();
        let metrics = build_metrics(&[], &[], &rcs, &[], &[], &[], &[], 0, &[], 0);
        let overflow = metrics
            .iter()
            .find(|s| s.name == "nft_scrape_collector_error_total")
            .expect("overflow error counter must be emitted");
        assert_eq!(
            overflow.labels.get("reason").map(|v| v.as_str()),
            Some("cardinality_overflow")
        );
        assert_eq!(
            overflow.value,
            nlx_domain::metric::MetricValue::U64(1),
            "exactly the excess (len - cap) is reported"
        );
        let emitted = metrics
            .iter()
            .filter(|s| s.name == "nft_rule_counter_bytes_total")
            .count();
        assert_eq!(
            emitted, RULE_COUNTER_MAX_SERIES,
            "emission capped at the limit"
        );
    }

    #[test]
    fn build_metrics_no_overflow_under_cap_or_for_anonymous() {
        // Under the cap → no overflow. Anonymous count is informational only and
        // must NOT trigger overflow (ADR-0030).
        let rcs: Vec<NftRuleCounter> = (0..10).map(rc).collect();
        let metrics = build_metrics(&[], &[], &rcs, &[], &[], &[], &[], 0, &[], 9999);
        let overflow = metrics
            .iter()
            .find(|s| s.name == "nft_scrape_collector_error_total");
        assert!(
            overflow.is_none(),
            "no overflow when commented rules are under the cap, regardless of anonymous count"
        );
    }

    // -----------------------------------------------------------------------
    // Wire constant correctness
    // -----------------------------------------------------------------------

    #[test]
    fn nft_msg_constants_match_kernel_enum() {
        assert_eq!(NFT_MSG_GETTABLE, 0x0A01);
        assert_eq!(NFT_MSG_GETCHAIN, 0x0A04);
        assert_eq!(NFT_MSG_GETRULE, 0x0A07);
        assert_eq!(NFT_MSG_GETSET, 0x0A0A);
        assert_eq!(NFT_MSG_GETGEN, 0x0A10);
        assert_eq!(NFT_MSG_GETOBJ, 0x0A13);
        assert_eq!(NFT_MSG_GETFLOWTABLE, 0x0A17);
    }

    // -----------------------------------------------------------------------
    // Helper coverage
    // -----------------------------------------------------------------------

    #[test]
    fn cstr_to_string_strips_nul() {
        assert_eq!(cstr_to_string(b"hello\0"), "hello");
    }

    #[test]
    fn cstr_to_string_no_nul_passthrough() {
        assert_eq!(cstr_to_string(b"world"), "world");
    }

    #[test]
    fn family_label_coverage() {
        assert_eq!(family_label(0), "unspec");
        assert_eq!(family_label(1), "inet");
        assert_eq!(family_label(2), "ip");
        assert_eq!(family_label(10), "ip6");
        assert_eq!(family_label(255), "other");
    }

    #[test]
    fn key_type_label_coverage() {
        assert_eq!(key_type_label(0x000c), "ipv4_addr");
        assert_eq!(key_type_label(0x000d), "ipv6_addr");
        assert_eq!(key_type_label(0x000b), "inet_service");
        assert_eq!(key_type_label(0x0005), "ether_addr");
        assert_eq!(key_type_label(0x0009), "mark");
        assert_eq!(key_type_label(0xFFFF), "other");
    }

    #[test]
    fn extract_rule_comment_valid() {
        let comment = b"my_rule";
        let tlv_len = comment.len() + 1;
        let mut blob = vec![0u8, tlv_len as u8];
        blob.extend_from_slice(comment);
        blob.push(0u8);
        assert_eq!(extract_rule_comment(&blob), Some("my_rule".to_owned()));
    }

    #[test]
    fn extract_rule_comment_absent() {
        assert_eq!(extract_rule_comment(&[]), None);
    }
}
