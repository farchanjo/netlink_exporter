// DDD role: ReadModel
package schemas

// #RuleCounterEntry holds the counter values for one nftables rule that
// carries a counter expression. Only rules with a non-empty comment are
// included (enforces cardinality bound; anonymous rules are suppressed
// when their total across a chain exceeds 500).
// Maps to nft_rule_counter_bytes_total and nft_rule_counter_packets_total.
#RuleCounterEntry: {
	// table is the nftables table name; used as the "table" Prometheus label.
	table: string & !=""

	// chain is the nftables chain name; used as the "chain" label.
	chain: string & !=""

	// comment is the NFT rule comment; used as the "comment" label.
	// Empty-comment rules are excluded from this ReadModel by NftablesCollector.
	comment: string & !=""

	// bytes is the total bytes matched by this rule since last ruleset reload.
	bytes: uint64

	// packets is the total packets matched by this rule since last ruleset reload.
	packets: uint64
}

// #NamedCounterEntry holds the values for one named nftables counter object
// (NFT_MSG_GETCOUNTER). Named counters persist across ruleset reloads.
// Maps to nft_named_counter_bytes_total and nft_named_counter_packets_total.
#NamedCounterEntry: {
	// table is the nftables table name; used as the "table" label.
	table: string & !=""

	// name is the named counter object name; used as the "name" label.
	name: string & !=""

	// bytes is the total bytes counted by this named counter.
	bytes: uint64

	// packets is the total packets counted by this named counter.
	packets: uint64
}

// #SetElementCount holds the element count for one nftables set or map.
// Does NOT emit per-element time series; only the aggregate count is stored.
// Maps to nft_set_elements gauge.
#SetElementCount: {
	// table is the nftables table name; used as the "table" label.
	table: string & !=""

	// name is the set or map name; used as the "name" label.
	name: string & !=""

	// set_type is the set key type string (e.g. "ipv4_addr", "inet_service",
	// "ether_addr", "ipv4_addr . inet_service"); used as the "type" label.
	set_type: string & !=""

	// element_count is the current number of elements in this set or map.
	element_count: uint64
}

// #ChainInfoEntry holds metadata for one nftables chain.
// Maps to nft_chain_info metadata gauge (value always 1).
#ChainInfoEntry: {
	// table is the nftables table name; used as the "table" label.
	table: string & !=""

	// chain is the chain name; used as the "chain" label.
	chain: string & !=""

	// chain_type is the chain type string ("filter", "nat", "route", or "").
	// Used as the "type" label.
	chain_type: #NftChainType

	// hook is the netfilter hook point string; empty for regular chains.
	// Used as the "hook" label.
	hook: string

	// priority is the hook priority as a decimal string; empty for regular chains.
	// Used as the "priority" label.
	priority: string

	// policy is the default chain policy ("accept" or "drop").
	// Empty for regular chains. Used as the "policy" label.
	policy: string
}

// #TableInfoEntry holds metadata for one nftables table.
// Maps to nft_table_info metadata gauge (value always 1).
#TableInfoEntry: {
	// table is the nftables table name; used as the "table" label.
	table: string & !=""

	// family is the nftables address family string; used as the "family" label.
	family: #NftFamily
}

// #NftCounterSnapshot is the immutable ReadModel produced by NftablesCollector
// for the NFNL_SUBSYS_NFTABLES subsystem in one scrape epoch.
// It is valid only for the duration of the current HTTP /metrics response.
#NftCounterSnapshot: {
	// epoch_ns is the Unix nanosecond timestamp when this snapshot was captured.
	// Used by nft_exporter_snapshot_age_seconds self-metric.
	epoch_ns: uint64

	// rule_counters is the list of rule counter entries (comment-filtered).
	// Cardinality bound: ~1000 entries.
	rule_counters: [...#RuleCounterEntry]

	// named_counters is the list of named counter object entries.
	// Cardinality bound: ~500 entries.
	named_counters: [...#NamedCounterEntry]

	// set_counts is the list of set element count entries.
	// Cardinality bound: ~500 entries.
	set_counts: [...#SetElementCount]

	// chain_info is the list of chain metadata entries.
	// Cardinality bound: ~200 entries.
	chain_info: [...#ChainInfoEntry]

	// table_info is the list of table metadata entries.
	// Cardinality bound: ~50 entries.
	table_info: [...#TableInfoEntry]

	// cardinality_overflow_count is the number of anonymous rules suppressed
	// during this scrape due to the 500-anonymous-rules-per-chain ceiling.
	// Non-zero values also increment nft_scrape_collector_error_total{reason=cardinality_overflow}.
	cardinality_overflow_count: uint32
}
