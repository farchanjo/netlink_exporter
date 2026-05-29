// DDD role: ReadModel
package schemas

// #ConntrackStateCount holds the aggregated count of conntrack flows
// in a specific (protocol, state) bucket.
// Maps directly to one time series in nft_conntrack_entries gauge.
#ConntrackStateCount: {
	protocol: #ConntrackProtocol
	state:    #ConntrackState
	count:    uint64
}

// #ConntrackDirectionalBytes holds aggregated byte and packet totals
// across all flows for a specific (protocol, direction) combination.
// Maps to nft_conntrack_bytes_total and nft_conntrack_packets_total counters.
#ConntrackDirectionalBytes: {
	protocol:  #ConntrackProtocol
	direction: #ConntrackDirection
	bytes:     uint64
	packets:   uint64
}

// #ConntrackGlobalStats holds the per-CPU aggregated global statistics
// sourced from IPCTNL_MSG_CT_GET_STATS_CPU replies.
// Each field maps to a zero-label counter or gauge metric.
#ConntrackGlobalStats: {
	// max_entries is the nf_conntrack_max sysctl value.
	// Maps to nft_conntrack_max_entries gauge.
	max_entries: uint64

	// insert is the sum of per-CPU insert counters.
	// Maps to nft_conntrack_insert_total counter.
	insert: uint64

	// drop is the sum of per-CPU drop counters (packets that could not be tracked).
	// Maps to nft_conntrack_drop_total counter.
	drop: uint64

	// early_drop is the sum of per-CPU early_drop counters (evictions for new flows).
	// Maps to nft_conntrack_early_drop_total counter.
	early_drop: uint64

	// found is the sum of per-CPU found counters (successful lookups).
	// Maps to nft_conntrack_found_total counter.
	found: uint64

	// invalid is the sum of per-CPU invalid counters (packets in invalid state).
	// Maps to nft_conntrack_invalid_total counter.
	invalid: uint64
}

// #ConntrackSummary is the immutable ReadModel produced by ConntrackAggregator
// (DomainService) from the raw ConntrackFlow aggregate root instances.
// This is the ONLY conntrack data structure that reaches MetricRegistryPort.
//
// CRITICAL invariant: this ReadModel contains aggregated counts ONLY.
// No per-flow, per-IP, per-port, or per-MAC information is present.
// Per-flow cardinality is strictly forbidden per ADR-0005.
#ConntrackSummary: {
	// epoch_ns is the Unix nanosecond timestamp when this snapshot was captured.
	// Used by nft_exporter_snapshot_age_seconds self-metric.
	epoch_ns: uint64

	// state_counts is the list of aggregated flow counts by (protocol, state).
	// Cardinality bound: ~40 entries (8 protocols x 5 states).
	state_counts: [...#ConntrackStateCount]

	// directional_bytes is the list of aggregated byte/packet totals
	// by (protocol, direction).
	// Cardinality bound: ~16 entries (8 protocols x 2 directions).
	directional_bytes: [...#ConntrackDirectionalBytes]

	// global is the global conntrack statistics from per-CPU counters.
	global: #ConntrackGlobalStats
}
