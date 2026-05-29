// DDD role: AggregateRoot
package schemas

// #NftFamily enumerates the nftables table address families.
#NftFamily: "inet" | "ip" | "ip6" | "arp" | "bridge" | "netdev"

// #NftHook enumerates the Netfilter hook points where a chain can be attached.
// Regular (non-base) chains have no hook; base chains MUST have one.
#NftHook:
	"prerouting" |
	"input" |
	"forward" |
	"output" |
	"postrouting" |
	"ingress" |
	"egress"

// #NftChainType enumerates nftables chain type strings for base chains.
// Regular chains leave this field empty.
#NftChainType: "" | "filter" | "nat" | "route"

// #NftPolicy enumerates the default verdict for a base chain.
// Regular chains do not have a policy.
#NftPolicy: "accept" | "drop"

// #NftPriority is the netfilter hook priority as a signed integer.
// Standard priorities: NF_IP_PRI_CONNTRACK=-200, NF_IP_PRI_FILTER=0,
// NF_IP_PRI_NAT_SRC=100, NF_IP_PRI_NAT_DST=-100.
#NftPriority: int

// #TableIdentity is the (family, name) pair that uniquely identifies
// an nftables table within a network namespace.
#TableIdentity: {
	family: #NftFamily
	name:   string & !=""
}

// #ChainIdentity is the (table, chain_name) pair that uniquely identifies
// an nftables chain (the NftChain aggregate root identity).
#ChainIdentity: {
	table:      #TableIdentity
	chain_name: string & !=""
}

// #NftCounterExpr holds the byte/packet counter values for a single rule
// that carries a counter expression. Counters are monotonically non-decreasing
// within a scrape epoch (reset only on ruleset reload or explicit nft reset).
#NftCounterExpr: {
	bytes:   uint64
	packets: uint64
}

// #NftRule is an entity within the NftChain aggregate. Rules are ordered;
// handle is the kernel-assigned numeric identifier.
// Only rules with a non-empty comment are exported as Prometheus metrics
// to enforce the cardinality bound (~1000 series max).
#NftRule: {
	// handle is the kernel-assigned rule handle within the chain.
	handle: uint64

	// comment is the NFT rule comment string. Empty for anonymous rules.
	// Used as the "comment" label in nft_rule_counter_bytes_total.
	comment: string

	// counter holds the rule counter expression value. Absent when the rule
	// has no counter expression.
	counter?: #NftCounterExpr

	// Cardinality invariant: anonymous rules (empty comment) with counters
	// MUST NOT be emitted as metric time series when their aggregate count
	// exceeds 500 within a single chain. NftablesCollector enforces this
	// and increments nft_scrape_collector_error_total{reason=cardinality_overflow}.
}

// #NftRuleList is an ordered list of rules owned by a chain.
#NftRuleList: [...#NftRule]

// #NftChain is the AggregateRoot for an nftables chain.
// Identity: identity (the ChainIdentity ValueObject).
// The aggregate owns its NftRuleList and is immutable within a scrape epoch.
#NftChain: {
	// identity is the (table, chain_name) composite identity of this chain.
	identity: #ChainIdentity

	// chain_type is the nftables chain type. Empty string for regular chains.
	chain_type: #NftChainType

	// hook is the netfilter hook point. Only set for base chains.
	hook?: #NftHook

	// priority is the hook priority. Only set for base chains.
	priority?: #NftPriority

	// policy is the default verdict for a base chain. Only set for base chains.
	policy?: #NftPolicy

	// rules is the ordered list of rule entities owned by this chain.
	rules: #NftRuleList

	// Invariant: base chains MUST have hook, priority, and policy.
	// Regular chains MUST NOT have hook or policy.
	// This invariant is enforced at the collector level; CUE uses optional
	// fields to represent the conditional presence pattern.
}
