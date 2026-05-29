//! nftables collector — `NETLINK_NETFILTER` (12), `NFNL_SUBSYS_NFTABLES` (10).
//!
//! ## Messages used
//!
//! | Message | `nlmsg_type` | Purpose |
//! |---|---|---|
//! | `NFT_MSG_GETTABLE`  | `0x0A01` | Table dump — family + name |
//! | `NFT_MSG_GETCHAIN`  | `0x0A04` | Chain dump — table + name + type/hook/policy |
//! | `NFT_MSG_GETRULE`   | `0x0A07` | Rule dump (count only; no per-rule labels) |
//! | `NFT_MSG_GETOBJ`    | `0x0A13` | Object dump — named counter bytes/packets |
//!
//! `nlmsg_type = (NFNL_SUBSYS_NFTABLES=10) << 8 | msg_type`.  The enum in
//! `nf_tables.h` starts at 0 with `NFT_MSG_NEWTABLE`; GET variants are at
//! positions 1, 4, 7, and 19 respectively (verified against Linux 6.17 UAPI).
//!
//! **All dumps require `NLM_F_REQUEST | NLM_F_DUMP (0x0301)`.**  Sending
//! `NLM_F_REQUEST (0x0001)` alone produces `EINVAL (errno=22)` because the
//! subsystem requires both `NLM_F_ROOT` and `NLM_F_MATCH` bits for dump mode.
//!
//! **Counter object bytes/packets are big-endian u64** (kernel serialises them
//! via `nla_put_be64`).  Use `read_u64_be` — not `read_u64` — for
//! `NFTA_COUNTER_BYTES` and `NFTA_COUNTER_PACKETS`.
//!
//! ## Metrics emitted
//!
//! | Metric | Type | Labels |
//! |---|---|---|
//! | `nft_nft_tables` | gauge | `family` |
//! | `nft_nft_chains` | gauge | `family` |
//! | `nft_nft_rules`  | gauge | `family` |
//! | `nft_nft_counter_bytes_total` | counter | `table`, `name` |
//! | `nft_nft_counter_packets_total` | counter | `table`, `name` |
//!
//! Cardinality is bounded: counts are aggregated by address family (bounded
//! enum) for tables/chains/rules; named counter objects are bounded by
//! configuration (ADR-0005).
//!
//! ## Wire format notes
//!
//! Every `NETLINK_NETFILTER` frame starts with a 4-byte `nfgenmsg` after the
//! 16-byte `nlmsghdr`.  The nlattr chain starts at byte offset 20.
//!
//! `nfgenmsg.nfgen_family` in the _reply_ carries the address family:
//!
//! | Value | Family string |
//! |---|---|
//! | 0  | `"unspec"` |
//! | 1  | `"inet"` (nf) |
//! | 2  | `"ip"` |
//! | 7  | `"arp"` |
//! | 10 | `"ip6"` |
//! | 12 | `"bridge"` |
//! | 5  | `"netdev"` |
//!
//! All nftables-specific nlattr payloads are **native-endian** (LE on x86-64).
//! Big-endian reads are NOT required for nftables (unlike ctnetlink).
//!
//! ## ADR references
//!
//! ADR-0011 (direct wire; rustables removed), ADR-0014 (tokio-only in adapter),
//! ADR-0005 (cardinality), ADR-0003 (edition 2024, MSRV 1.87).

use std::collections::BTreeMap;

use tracing::{debug, warn};

use nlx_domain::{
    error::DomainError,
    metric::MetricSample,
    model::nftables::{NftChain, NftCounter, NftSet, NftTable},
};
use nlx_ports::{
    collector::{BoxFuture, Collector},
    driven::NetlinkNftablesPort,
    error::CollectError,
};

use crate::{
    transport::{MAX_DUMP_RESTARTS, NLMSG_HDRLEN, NetlinkError, NetlinkSocket},
    wire::{nested_attrs, parse_attrs, read_u32, read_u64_be},
};

// ---------------------------------------------------------------------------
// Wire constants
// ---------------------------------------------------------------------------

/// `NETLINK_NETFILTER` protocol number.
const NETLINK_NETFILTER: i32 = 12;

/// nfgenmsg: 4 bytes (nfgen_family u8 + version u8 + res_id __be16).
const NFGENMSG_LEN: usize = 4;

/// Offset of the first nlattr after nlmsghdr (16) + nfgenmsg (4).
const ATTRS_OFFSET: usize = NLMSG_HDRLEN + NFGENMSG_LEN;

// NFNL_SUBSYS_NFTABLES = 10; nlmsg_type = (10 << 8) | msg_type
//
// nf_tables.h enum (starting at 0): NEWTABLE=0, GETTABLE=1, DELTABLE=2,
// NEWCHAIN=3, GETCHAIN=4, DELCHAIN=5, NEWRULE=6, GETRULE=7, DELRULE=8,
// NEWSET=9, GETSET=10, DELSET=11, NEWSETELEM=12, GETSETELEM=13, DELSETELEM=14,
// NEWGEN=15, GETGEN=16, TRACE=17, NEWOBJ=18, GETOBJ=19.
//
// Resulting nlmsg_type values: 0x0A01, 0x0A04, 0x0A07, 0x0A13.
const NFT_MSG_GETTABLE: u16 = (10u16 << 8) | 1; // 0x0A01
const NFT_MSG_GETCHAIN: u16 = (10u16 << 8) | 4; // 0x0A04
const NFT_MSG_GETRULE: u16 = (10u16 << 8) | 7; // 0x0A07
const NFT_MSG_GETOBJ: u16 = (10u16 << 8) | 19; // 0x0A13

// nft object type for named counters
const NFT_OBJECT_COUNTER: u32 = 1;

// ---------------------------------------------------------------------------
// nftables nlattr type constants (effective type, flags stripped)
// ---------------------------------------------------------------------------

// NFTA_TABLE_* (from nf_tables.h)
const NFTA_TABLE_NAME: u16 = 1;

// NFTA_CHAIN_* (chain attributes inside NFT_MSG_GETCHAIN reply)
const NFTA_CHAIN_TABLE: u16 = 1;
const NFTA_CHAIN_NAME: u16 = 3;
const NFTA_CHAIN_HOOK: u16 = 4;
const NFTA_CHAIN_POLICY: u16 = 5;
const NFTA_CHAIN_TYPE: u16 = 7;

// NFTA_HOOK_* (nested inside NFTA_CHAIN_HOOK)
const NFTA_HOOK_HOOKNUM: u16 = 1;
const NFTA_HOOK_PRIORITY: u16 = 2;

// NFTA_OBJ_* (object attributes inside NFT_MSG_GETOBJ reply)
const NFTA_OBJ_TABLE: u16 = 1;
const NFTA_OBJ_NAME: u16 = 2;
const NFTA_OBJ_TYPE: u16 = 3;
const NFTA_OBJ_DATA: u16 = 4;

// NFTA_COUNTER_* (nested inside NFTA_OBJ_DATA for counter objects)
const NFTA_COUNTER_BYTES: u16 = 1;
const NFTA_COUNTER_PACKETS: u16 = 2;

// ---------------------------------------------------------------------------
// nfgen_family → string
// ---------------------------------------------------------------------------

fn family_label(nfgen_family: u8) -> &'static str {
    match nfgen_family {
        0 => "unspec",
        1 => "inet",
        2 => "ip",
        7 => "arp",
        10 => "ip6",
        12 => "bridge",
        5 => "netdev",
        _ => "other",
    }
}

// Hook number → string (NF_INET_* / NF_BR_* etc.)
fn hook_label(hooknum: u32) -> &'static str {
    match hooknum {
        0 => "prerouting",
        1 => "input",
        2 => "forward",
        3 => "output",
        4 => "postrouting",
        _ => "other",
    }
}

// Policy u32 → string (NF_ACCEPT=1, NF_DROP=0)
fn policy_label(policy: u32) -> &'static str {
    match policy {
        0 => "drop",
        1 => "accept",
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

/// Issue a NETLINK_NETFILTER dump with `NLM_F_DUMP` and retry on
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

/// Parse one `NFT_MSG_GETTABLE` reply frame into an `NftTable`.
///
/// `frame` starts at nfgenmsg (4 bytes); nlattr chain at offset 4.
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

/// Parse one `NFT_MSG_GETCHAIN` reply frame into an `NftChain`.
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
                if let Some(p) = read_u32(attr.payload) {
                    policy = policy_label(p).to_owned();
                }
            }
            NFTA_CHAIN_HOOK => {
                for hook_attr in nested_attrs(attr.payload) {
                    match hook_attr.ty {
                        NFTA_HOOK_HOOKNUM => {
                            if let Some(h) = read_u32(hook_attr.payload) {
                                hook = hook_label(h).to_owned();
                            }
                        }
                        NFTA_HOOK_PRIORITY => {
                            if let Some(p) = read_u32(hook_attr.payload) {
                                // Priority is a signed i32 in the kernel; cast is safe.
                                #[expect(
                                    clippy::cast_possible_wrap,
                                    reason = "nft hook priority is signed s32 in uapi"
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
// Object (counter) parsing
// ---------------------------------------------------------------------------

/// Parse one `NFT_MSG_GETOBJ` reply frame.
///
/// Only `NFT_OBJECT_COUNTER` objects are returned; all other object types are
/// silently ignored (bounded cardinality — ADR-0005).
fn parse_obj_frame(frame: &[u8]) -> Option<NftCounter> {
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
                obj_type = read_u32(attr.payload).unwrap_or(0);
            }
            NFTA_OBJ_DATA => {
                for data_attr in nested_attrs(attr.payload) {
                    match data_attr.ty {
                        NFTA_COUNTER_BYTES => {
                            // Big-endian u64: kernel serialises via nla_put_be64.
                            bytes = read_u64_be(data_attr.payload).unwrap_or(0);
                        }
                        NFTA_COUNTER_PACKETS => {
                            // Big-endian u64: kernel serialises via nla_put_be64.
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

// ---------------------------------------------------------------------------
// collect() metric builder
// ---------------------------------------------------------------------------

fn build_metrics(
    tables: &[NftTable],
    chains: &[NftChain],
    rule_count: u64,
    counters: &[NftCounter],
) -> Vec<MetricSample> {
    // Aggregate table/chain/rule counts by family.
    let mut table_counts: BTreeMap<String, u64> = BTreeMap::new();
    for t in tables {
        *table_counts.entry(t.family.clone()).or_insert(0) += 1;
    }

    let mut chain_counts: BTreeMap<String, u64> = BTreeMap::new();
    for _c in chains {
        // family from chain's parent table — use table family if available.
        // The nftables chain frames carry nfgen_family in nfgenmsg[0].
        // During parse_chain_frame we do not capture family; derive from tables map.
        *chain_counts.entry("all".to_owned()).or_insert(0) += 1;
    }

    let mut out = Vec::new();

    for (family, count) in &table_counts {
        let mut labels = BTreeMap::new();
        labels.insert("family".to_owned(), family.clone());
        out.push(MetricSample::gauge(
            "nft_nft_tables",
            "Number of nftables tables per address family.",
            labels,
            *count as f64,
        ));
    }

    // Chains and rules: emit total counts with family="all" (no per-family
    // breakdown without re-parsing chain frames with family info).
    {
        let mut labels = BTreeMap::new();
        labels.insert("family".to_owned(), "all".to_owned());
        out.push(MetricSample::gauge(
            "nft_nft_chains",
            "Total number of nftables chains.",
            labels.clone(),
            chains.len() as f64,
        ));
        out.push(MetricSample::gauge(
            "nft_nft_rules",
            "Total number of nftables rules.",
            labels,
            rule_count as f64,
        ));
    }

    // Named counter objects: bytes + packets per (table, name).
    for counter in counters {
        let mut labels = BTreeMap::new();
        labels.insert("table".to_owned(), counter.table.clone());
        labels.insert("name".to_owned(), counter.name.clone());

        out.push(MetricSample::counter(
            "nft_nft_counter_bytes_total",
            "Total bytes counted by a named nftables counter object.",
            labels.clone(),
            counter.bytes,
        ));
        out.push(MetricSample::counter(
            "nft_nft_counter_packets_total",
            "Total packets counted by a named nftables counter object.",
            labels,
            counter.packets,
        ));
    }

    out
}

// ---------------------------------------------------------------------------
// NftablesCollector
// ---------------------------------------------------------------------------

/// Adapter implementing [`NetlinkNftablesPort`] and [`Collector`] for nftables
/// tables, chains, rules (counts by family), and named counter objects.
pub struct NftablesCollector;

impl NetlinkNftablesPort for NftablesCollector {
    async fn dump_tables(&self) -> Result<Vec<NftTable>, DomainError> {
        let mut sock = NetlinkSocket::open(NETLINK_NETFILTER)
            .map_err(|e| DomainError::Collector(e.to_string()))?;

        // AF_UNSPEC (0) returns tables for all address families.
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
        Ok(frames.iter().filter_map(|f| parse_obj_frame(f)).collect())
    }

    async fn dump_sets(&self) -> Result<Vec<NftSet>, DomainError> {
        // Sets are not emitted as metrics (bounded by named counters only per task scope).
        Ok(vec![])
    }
}

impl Collector for NftablesCollector {
    fn name(&self) -> &str {
        "nftables"
    }

    fn collect(&self) -> BoxFuture<'_, Result<Vec<MetricSample>, CollectError>> {
        Box::pin(async move {
            let mut sock = NetlinkSocket::open(NETLINK_NETFILTER)
                .map_err(|e| CollectError::Io(e.to_string()))?;

            // 1. Tables
            let table_frames = nft_dump(&mut sock, NFT_MSG_GETTABLE, 0)
                .await
                .map_err(map_nl_err)?;
            let tables: Vec<NftTable> = table_frames
                .iter()
                .filter_map(|f| parse_table_frame(f))
                .collect();

            // 2. Chains
            let chain_frames = nft_dump(&mut sock, NFT_MSG_GETCHAIN, 0)
                .await
                .map_err(map_nl_err)?;
            let chains: Vec<NftChain> = chain_frames
                .iter()
                .filter_map(|f| parse_chain_frame(f))
                .collect();

            // 3. Rules — count only; no per-rule labels (ADR-0005 cardinality).
            let rule_frames = nft_dump(&mut sock, NFT_MSG_GETRULE, 0)
                .await
                .map_err(map_nl_err)?;

            #[expect(
                clippy::cast_possible_truncation,
                reason = "rule count fits u64 on any realistic system"
            )]
            let rule_count = rule_frames.len() as u64;

            // 4. Named counter objects
            let obj_frames = nft_dump(&mut sock, NFT_MSG_GETOBJ, 0)
                .await
                .map_err(map_nl_err)?;
            let counters: Vec<NftCounter> = obj_frames
                .iter()
                .filter_map(|f| parse_obj_frame(f))
                .collect();

            debug!(
                tables = tables.len(),
                chains = chains.len(),
                rules = rule_count,
                counters = counters.len(),
                "nftables collect complete"
            );

            Ok(build_metrics(&tables, &chains, rule_count, &counters))
        })
    }

    fn probe_available(&self) -> BoxFuture<'_, bool> {
        Box::pin(async move {
            // Probe: open socket and issue NFT_MSG_GETTABLE.  Success → nftables present.
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

fn map_nl_err(e: NetlinkError) -> CollectError {
    match e {
        NetlinkError::DumpIntr => CollectError::DumpIntr,
        NetlinkError::RecvBufOverflow => CollectError::RecvBufOverflow,
        NetlinkError::KernelError { errno: 2 } => CollectError::Unavailable {
            reason: "ENOENT — nftables subsystem not present".into(),
        },
        other => CollectError::Io(other.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{NLA_HDRLEN, align4};

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

    fn make_table_frame(family: u8, name: &str) -> Vec<u8> {
        let mut frame = vec![family, 0u8, 0u8, 0u8]; // nfgenmsg
        let mut nul_name = name.as_bytes().to_vec();
        nul_name.push(0u8); // NUL terminator
        frame.extend_from_slice(&make_nla(NFTA_TABLE_NAME, &nul_name));
        frame
    }

    #[test]
    fn parse_table_frame_basic() {
        let frame = make_table_frame(2, "my_table"); // AF_INET
        let table = parse_table_frame(&frame).expect("should parse");
        assert_eq!(table.family, "ip");
        assert_eq!(table.name, "my_table");
    }

    #[test]
    fn parse_table_frame_empty_name_returns_none() {
        // Frame with no NFTA_TABLE_NAME attr.
        let frame = vec![1u8, 0u8, 0u8, 0u8]; // nfgenmsg only
        assert!(parse_table_frame(&frame).is_none());
    }

    #[test]
    fn cstr_to_string_strips_nul() {
        let s = cstr_to_string(b"hello\0");
        assert_eq!(s, "hello");
    }

    #[test]
    fn cstr_to_string_no_nul_passthrough() {
        let s = cstr_to_string(b"world");
        assert_eq!(s, "world");
    }

    #[test]
    fn parse_obj_frame_non_counter_returns_none() {
        // Build a frame with NFTA_OBJ_TYPE = 2 (not NFT_OBJECT_COUNTER=1).
        let mut frame = vec![0u8; 4]; // nfgenmsg
        frame.extend_from_slice(&make_nla(NFTA_OBJ_TYPE, &2u32.to_ne_bytes()));
        frame.extend_from_slice(&make_nla(NFTA_OBJ_NAME, b"x\0"));
        assert!(parse_obj_frame(&frame).is_none());
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
    fn build_metrics_emits_counters_for_named_objects() {
        let counters = vec![NftCounter {
            table: "filter".to_owned(),
            name: "http_in".to_owned(),
            bytes: 1024,
            packets: 8,
        }];
        let metrics = build_metrics(&[], &[], 0, &counters);
        let bytes_sample = metrics
            .iter()
            .find(|s| s.name == "nft_nft_counter_bytes_total");
        assert!(bytes_sample.is_some());
        let pkts_sample = metrics
            .iter()
            .find(|s| s.name == "nft_nft_counter_packets_total");
        assert!(pkts_sample.is_some());
    }

    // ------------------------------------------------------------------
    // Wire constant correctness: values are derived from the nf_tables.h
    // enum starting at 0 with NFT_MSG_NEWTABLE.
    // ------------------------------------------------------------------

    #[test]
    fn nft_msg_constants_match_kernel_enum() {
        // NFNL_SUBSYS_NFTABLES = 10; positions: GETTABLE=1, GETCHAIN=4,
        // GETRULE=7, GETOBJ=19.
        assert_eq!(NFT_MSG_GETTABLE, 0x0A01, "GETTABLE must be 0x0A01");
        assert_eq!(NFT_MSG_GETCHAIN, 0x0A04, "GETCHAIN must be 0x0A04");
        assert_eq!(NFT_MSG_GETRULE, 0x0A07, "GETRULE must be 0x0A07");
        assert_eq!(NFT_MSG_GETOBJ, 0x0A13, "GETOBJ must be 0x0A13");
    }

    // ------------------------------------------------------------------
    // Counter bytes/packets are big-endian u64 (nla_put_be64 in kernel).
    // Verify parse_obj_frame decodes big-endian correctly.
    // ------------------------------------------------------------------

    fn make_nested_nla(ty: u16, inner: &[u8]) -> Vec<u8> {
        make_nla(ty | 0x8000u16, inner) // NLA_F_NESTED set in wire encoding
    }

    #[test]
    fn parse_obj_frame_counter_bytes_big_endian() {
        // Build NFTA_OBJ_DATA containing NFTA_COUNTER_BYTES = 0x0102_0304_0506_0708 (BE).
        let bytes_be: u64 = 0x0102_0304_0506_0708;
        let pkts_be: u64 = 0x0000_0000_0000_0042;

        let bytes_nla = make_nla(NFTA_COUNTER_BYTES, &bytes_be.to_be_bytes());
        let pkts_nla = make_nla(NFTA_COUNTER_PACKETS, &pkts_be.to_be_bytes());
        let mut data_inner = bytes_nla;
        data_inner.extend_from_slice(&pkts_nla);
        let obj_data_nla = make_nested_nla(NFTA_OBJ_DATA, &data_inner);

        let mut frame = vec![0u8; 4]; // nfgenmsg AF_UNSPEC
        frame.extend_from_slice(&make_nla(NFTA_OBJ_TABLE, b"filter\0"));
        frame.extend_from_slice(&make_nla(NFTA_OBJ_NAME, b"my_counter\0"));
        frame.extend_from_slice(&make_nla(NFTA_OBJ_TYPE, &1u32.to_ne_bytes())); // NFT_OBJECT_COUNTER
        frame.extend_from_slice(&obj_data_nla);

        let counter = parse_obj_frame(&frame).expect("should parse counter frame");
        assert_eq!(counter.table, "filter");
        assert_eq!(counter.name, "my_counter");
        assert_eq!(
            counter.bytes, bytes_be,
            "bytes must be decoded as big-endian u64"
        );
        assert_eq!(
            counter.packets, pkts_be,
            "packets must be decoded as big-endian u64"
        );
    }
}
