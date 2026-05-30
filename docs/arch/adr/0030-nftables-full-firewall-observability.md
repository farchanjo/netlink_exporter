---
status: accepted
date: 2026-05-30
deciders: [eonf]
consulted: []
informed: []
amends: metric_contract.cue (nftables descriptors)
---

# Complete nftables firewall monitoring: bounded metric surface, name-drift fix,
and full wire-path implementation

## Context and Problem Statement

The v0.1.1 nftables collector (`nlx-netlink/src/collectors/nftables.rs`) emits
five metric families. Three are structurally wrong relative to the contract
(`nft_nft_tables`, `nft_nft_chains`, `nft_nft_rules`); two have name drift
(`nft_nft_counter_bytes_total`, `nft_nft_counter_packets_total` — prefix
mismatch vs. contract). Five metric families declared in `metric_contract.cue`
are entirely absent from the code:

| Contract metric | Code status |
|---|---|
| `nft_rule_counter_{bytes,packets}_total{table,chain,comment}` | Domain type defined, never populated |
| `nft_named_counter_{bytes,packets}_total{table,name}` | Emitted under wrong prefix `nft_nft_counter_*` |
| `nft_set_elements{table,name,type}` | `dump_sets` unconditionally returns `Ok(vec![])` |
| `nft_chain_info{table,chain,type,hook,priority,policy}` | Parsed correctly, discarded in `build_metrics` |
| `nft_table_info{table,family}` | Emitted as rollup count, not per-table gauge |

Additionally the contract has no coverage for:
- Ruleset generation change detection (`NFT_MSG_GETGEN` / `NFTA_GEN_ID`).
- Named quota/limit/connlimit object exhaustion (`NFT_OBJECT_QUOTA=2`,
  `NFT_OBJECT_LIMIT=4`, `NFT_OBJECT_CONNLIMIT=5`).
- Flowtable topology (`NFT_MSG_GETFLOWTABLE`).

The code never issues `NFT_MSG_GETSET` (0x0A0A), `NFT_MSG_GETGEN` (0x0A10), or
`NFT_MSG_GETFLOWTABLE` (0x0A17). The existing rule dump (`NFT_MSG_GETRULE`
0x0A07) is already sent but its payloads (`NFTA_RULE_EXPRESSIONS`,
`NFTA_RULE_USERDATA`) are never parsed.

All attribute constants and byte-order facts are sourced from:
- `linux-6.17.13/include/uapi/linux/netfilter/nf_tables.h`
- `linux-6.17.13/net/netfilter/nf_tables_api.c`

ADR references: ADR-0005 (cardinality), ADR-0011 (wire-only protocol),
ADR-0027 (no procfs/sysfs for netlink-reachable signals).

## Considered Options

1. **Minimal fix**: fix the name drift only, leave capability gaps.
2. **Full bounded surface** (chosen): fix name drift, implement all six missing
   capabilities under ADR-0005 cardinality bounds. Each new metric family has a
   documented cardinality ceiling and source wire message.
3. **Unlimited per-rule/per-element expansion**: rejected — violates ADR-0005.

## Decision Outcome

**Chosen option: full bounded metric surface with strict ADR-0005 compliance.**

### Final metric surface — nftables context

All metrics below replace or supplement the existing five. The two emitted under
wrong names (`nft_nft_counter_*`) are renamed; the three aggregated counts
(`nft_nft_tables`, `nft_nft_chains`, `nft_nft_rules`) are replaced.

#### A. Table inventory (per-table metadata)

| Metric | Type | Labels | Cardinality bound | Source |
|---|---|---|---|---|
| `nft_table_info` | gauge (=1) | `table`, `family` | ~50 | `NFT_MSG_GETTABLE` (0x0A01) — `NFTA_TABLE_NAME` (1, NLA_STRING), `nfgenmsg.nfgen_family` |

Replaces `nft_nft_tables{family}` (count rollup). Family label values:
`unspec`, `inet`, `ip`, `ip6`, `arp`, `bridge`, `netdev`.

#### B. Chain topology metadata (per-chain info)

| Metric | Type | Labels | Cardinality bound | Source |
|---|---|---|---|---|
| `nft_chain_info` | gauge (=1) | `table`, `chain`, `type`, `hook`, `priority`, `policy` | ~200 | `NFT_MSG_GETCHAIN` (0x0A04) — already parsed, not emitted |

Replaces `nft_nft_chains{family="all"}`. All six label values are already
populated by `parse_chain_frame`. `type` empty for non-base chains; `hook` and
`policy` empty for non-base chains; `priority` stringified `i32`. Hook label
values: `prerouting`, `input`, `forward`, `output`, `postrouting`, `ingress`,
`egress`, `other`. Policy label values: `accept`, `drop`, `other`.

#### C. Per-rule hit counters keyed by comment

| Metric | Type | Labels | Cardinality bound | Source |
|---|---|---|---|---|
| `nft_rule_counter_bytes_total` | counter | `table`, `chain`, `comment` | ~1000 (ADR-0005 overflow guard at 500 anonymous-rule threshold) | `NFT_MSG_GETRULE` (0x0A07) — `NFTA_RULE_EXPRESSIONS` (4, nested), `NFTA_RULE_USERDATA` (7, TLV blob) |
| `nft_rule_counter_packets_total` | counter | `table`, `chain`, `comment` | ~1000 | same |

Wire parsing required:
- `NFTA_RULE_TABLE` (1, NLA_STRING) — parent table.
- `NFTA_RULE_CHAIN` (2, NLA_STRING) — parent chain.
- `NFTA_RULE_EXPRESSIONS` (4, NLA_NESTED) — iterate `NFTA_LIST_ELEM` (type 1)
  children; each contains `NFTA_EXPR_NAME` (1, NLA_STRING) and `NFTA_EXPR_DATA`
  (2, NLA_NESTED). Locate `NFTA_EXPR_NAME == "counter"`; read
  `NFTA_COUNTER_BYTES` (1, BE u64) and `NFTA_COUNTER_PACKETS` (2, BE u64) from
  `NFTA_EXPR_DATA`.
- `NFTA_RULE_USERDATA` (7, NLA_BINARY, max 256 bytes) — TLV walk; type 0
  (`NFTNL_UDATA_RULE_COMMENT`) is the null-terminated comment string. Only rules
  with a non-empty comment are exported; anonymous rules are counted in
  `nft_scrape_collector_error_total{reason=cardinality_overflow}` when the
  anonymous count exceeds 500 in a single scrape.

#### D. Named counter objects (corrected name)

| Metric | Type | Labels | Cardinality bound | Source |
|---|---|---|---|---|
| `nft_named_counter_bytes_total` | counter | `table`, `name` | ~500 | `NFT_MSG_GETOBJ` (0x0A13) — `NFT_OBJECT_COUNTER` (1) |
| `nft_named_counter_packets_total` | counter | `table`, `name` | ~500 | same |

Renames `nft_nft_counter_bytes_total` / `nft_nft_counter_packets_total`. Wire
parsing already correct; only the emitted metric name changes.

#### E. Set/map element counts

| Metric | Type | Labels | Cardinality bound | Source |
|---|---|---|---|---|
| `nft_set_elements` | gauge | `table`, `name`, `type` | ~500 | `NFT_MSG_GETSET` (0x0A0A) — new message, not currently sent |

Wire parsing required:
- `NFTA_SET_TABLE` (1, NLA_STRING).
- `NFTA_SET_NAME` (2, NLA_STRING).
- `NFTA_SET_KEY_TYPE` (3, NLA_U32, BE u32) — map to string: `0x0c` → `"ipv4_addr"`,
  `0x0d` → `"ipv6_addr"`, `0x0d000d` → `"inet_addr"`, `0x0b` → `"inet_service"`,
  `0x09` → `"mark"`, `0x05` → `"ether_addr"`, others → hex string.
- `NFTA_SET_DESC` (9, NLA_NESTED) → `NFTA_SET_DESC_SIZE` (1, NLA_U32, BE u32)
  — current element count. This is the count path; no `NFT_MSG_GETSETELEM` dump.
- `NFTA_SET_COUNT` (20, NLA_U32, BE u32) — alternative element count on newer
  kernels; use if present, fall back to `NFTA_SET_DESC_SIZE`.
- Sets with flag `NFT_SET_ANONYMOUS` (0x001) are excluded (anonymous sets are
  compiler-internal; their names are not operator-controlled).

#### F. Named quota/limit/connlimit object stats

| Metric | Type | Labels | Cardinality bound | Source |
|---|---|---|---|---|
| `nft_named_quota_bytes_total` | gauge | `table`, `name` | ~200 | `NFT_MSG_GETOBJ` (0x0A13) — `NFT_OBJECT_QUOTA` (2) |
| `nft_named_quota_consumed_bytes_total` | gauge | `table`, `name` | ~200 | same |
| `nft_named_quota_depleted` | gauge (0 or 1) | `table`, `name` | ~200 | same — `NFT_QUOTA_F_DEPLETED` bit 1 of `NFTA_QUOTA_FLAGS` |
| `nft_named_limit_rate` | gauge | `table`, `name`, `type` | ~200 | `NFT_MSG_GETOBJ` — `NFT_OBJECT_LIMIT` (4) |
| `nft_named_limit_burst` | gauge | `table`, `name`, `type` | ~200 | same |

Wire parsing for `NFT_OBJECT_QUOTA` (2):
- `NFTA_QUOTA_BYTES` (1, NLA_U64, BE u64) — ceiling.
- `NFTA_QUOTA_CONSUMED` (4, NLA_U64, BE u64) — consumed bytes.
- `NFTA_QUOTA_FLAGS` (2, NLA_U32, BE u32) — bit 0 = `NFT_QUOTA_F_INV`,
  bit 1 = `NFT_QUOTA_F_DEPLETED`.

Wire parsing for `NFT_OBJECT_LIMIT` (4):
- `NFTA_LIMIT_RATE` (1, NLA_U64, BE u64).
- `NFTA_LIMIT_UNIT` (2, NLA_U64, BE u64) — seconds (1/60/3600/86400/604800).
- `NFTA_LIMIT_BURST` (3, NLA_U32, BE u32).
- `NFTA_LIMIT_TYPE` (4, NLA_U32, BE u32) — 0=`pkts`, 1=`bytes`; becomes `type` label.
- `NFTA_LIMIT_FLAGS` (5, NLA_U32, BE u32) — bit 0 = `NFT_LIMIT_F_INV`.

`NFT_OBJECT_CONNLIMIT` (5): `NFTA_CONNLIMIT_COUNT` returns the configured
threshold, not the live connection count; no runtime stats are exported by the
kernel. This object type is used for configuration audit only and is NOT
included in the metric surface (ADR-0005: no value in surfacing a static config
param as a runtime metric when the live count is inaccessible).

#### G. Ruleset generation

| Metric | Type | Labels | Cardinality bound | Source |
|---|---|---|---|---|
| `nft_ruleset_generation` | gauge | (none) | 1 | `NFT_MSG_GETGEN` (0x0A10) — `NFTA_GEN_ID` (1, NLA_U32, BE u32) |

`NFT_MSG_GETGEN` = `(10 << 8) | 16` = `0x0A10`. `NFTA_GEN_ID` is a monotonic
u32 that the kernel increments on every successful transaction. A change signals
that the ruleset has been modified. Cardinality: exactly 1 series (no labels).
Alert rule: `changes(nft_ruleset_generation[5m]) > 0` indicates ruleset
modification.

#### H. Flowtable topology

| Metric | Type | Labels | Cardinality bound | Source |
|---|---|---|---|---|
| `nft_flowtable_info` | gauge (=1) | `table`, `name`, `hook`, `priority`, `hw_offload` | ~20 | `NFT_MSG_GETFLOWTABLE` (0x0A17) — new message |

Wire parsing required:
- `NFTA_FLOWTABLE_TABLE` (1, NLA_STRING).
- `NFTA_FLOWTABLE_NAME` (2, NLA_STRING).
- `NFTA_FLOWTABLE_HOOK` (3, NLA_NESTED) → `NFTA_FLOWTABLE_HOOK_NUM` (1, BE u32)
  + `NFTA_FLOWTABLE_HOOK_PRIORITY` (2, BE u32, signed s32).
- `NFTA_FLOWTABLE_FLAGS` (7, NLA_U32, BE u32): bit 0 = `NFT_FLOWTABLE_HW_OFFLOAD`;
  `hw_offload` label = `"1"` when set, `"0"` otherwise.

`NFT_MSG_GETFLOWTABLE` = `(10 << 8) | 23` = `0x0A17`.

### Suppressed metrics from v0.1.1

The following metrics are removed and must no longer appear in scrape output:
- `nft_nft_tables{family}` — replaced by `nft_table_info{table,family}`.
- `nft_nft_chains{family}` — replaced by `nft_chain_info{...}`.
- `nft_nft_rules{family}` — no replacement (rule count is derivable from
  `count(nft_rule_counter_bytes_total)`; a bare opaque count has no alerting
  value absent per-rule labels).
- `nft_nft_counter_bytes_total` — renamed to `nft_named_counter_bytes_total`.
- `nft_nft_counter_packets_total` — renamed to `nft_named_counter_packets_total`.

### Cardinality summary

| Group | Series ceiling | Enforcement |
|---|---|---|
| `nft_table_info` | ~50 | bounded by table count |
| `nft_chain_info` | ~200 | bounded by chain count |
| `nft_rule_counter_*` | ~1000 | comment-keyed; anonymous rules suppressed at 500 |
| `nft_named_counter_*` | ~500 | bounded by named object count |
| `nft_set_elements` | ~500 | one per named set (anonymous sets excluded) |
| `nft_named_quota_*` | ~200 | bounded by named quota/limit object count |
| `nft_ruleset_generation` | 1 | no labels |
| `nft_flowtable_info` | ~20 | bounded by flowtable count |
| **Total nftables** | **~2471** | within ADR-0005 50k ceiling |

### Wire constants — new messages added

```
NFT_MSG_GETSET      = (10 << 8) | 10  = 0x0A0A
NFT_MSG_GETGEN      = (10 << 8) | 16  = 0x0A10
NFT_MSG_GETFLOWTABLE = (10 << 8) | 23 = 0x0A17
NFT_MSG_GETOBJ_RESET = (10 << 8) | 21 = 0x0A15  (optional: reset-on-read for quota)
```

All new numeric attributes use `nla_put_be32` / `nla_put_be64` — same
endianness invariant as existing attributes (ADR-0011, byteorder crate).

## Consequences

**Positive:**
- Complete firewall observability surface: every operator-meaningful nftables
  entity is reachable as a Prometheus metric.
- Per-rule hit attribution via comment key allows forensic identification of
  exactly which rules are matching traffic without needing `nft list ruleset`
  output.
- Quota depletion alerting (`nft_named_quota_depleted == 1`) provides a native
  signal for data-cap enforcement events previously invisible to Prometheus.
- Ruleset generation gauge (`nft_ruleset_generation`) enables anomaly detection
  on unexpected firewall changes (security operations use case).
- Flowtable hardware-offload detection allows correlating traffic drops with
  offload state changes on mlx5 hardware.
- All name drift is resolved: the contract and the code will emit identical
  metric names after implementation.

**Negative:**
- Per-rule parsing (`NFTA_RULE_EXPRESSIONS` walk) adds ~O(rules × expressions)
  processing per scrape. Mitigated by the ~1000 comment-keyed rule ceiling and
  early exit once `"counter"` expression is found.
- Three new `NFT_MSG_*` dump requests increase scrape netlink traffic. On a
  typical host with ~50 sets, ~1 flowtable, and 1 generation message, the
  added volume is negligible (<10 KB).
- Operators who relied on `nft_nft_counter_*` in existing Prometheus rules must
  update their queries to `nft_named_counter_*`. This is a breaking change in
  the metric surface; it is justified because the old names were wrong relative
  to the spec from inception.
- `nft_nft_rules` (bare count) is removed without replacement. Operators
  needing rule counts should use `count(nft_rule_counter_bytes_total)` (named
  rules only) or issue `nft list ruleset` for full inventory.

## Implementation plan

See inline section below (returned as the final agent output for the Implement
phase).
