// DDD role: ReadModel
package schemas

// #TcHandle is the ValueObject representing a TC object handle in the kernel's
// major:minor hex notation (e.g. major=1, minor=0 displayed as "1:0").
// Both major and minor are uint16 values. The root handle is (0, 0).
#TcHandle: {
	// major is the major handle component (uint16).
	major: uint16

	// minor is the minor handle component (uint16). 0 for qdiscs; non-zero
	// for traffic classes and filters attached to a class hierarchy.
	minor: uint16

	// display is the canonical human-readable string form "major:minor" in hex
	// without leading zeros, e.g. "1:0", "ffff:0", "1:10".
	display: =~"^[0-9a-f]+:[0-9a-f]+$"
}

// #TcKind is the qdisc/class/filter kind string as reported by TCA_KIND.
// Examples: "pfifo_fast", "htb", "tbf", "sfq", "ingress", "clsact",
// "flower", "u32", "bpf", "matchall", "fq_codel", "cake".
#TcKind: string & !=""

// #TcDirection enumerates filter attachment direction.
#TcDirection: "ingress" | "egress"

// #GnetStatsBasic holds the gnet_stats_basic fields from TCA_STATS2.
// These are the primary byte and packet throughput counters.
#GnetStatsBasic: {
	bytes:   uint64
	packets: uint32
}

// #GnetStatsQueue holds the gnet_stats_queue fields from TCA_STATS2.
// These capture queue depth and drop/overlimit events.
#GnetStatsQueue: {
	qlen:       uint32
	backlog:    uint32
	drops:      uint32
	requeues:   uint32
	overlimits: uint32
}

// #QdiscStats holds the combined TCA_STATS2 decoded values for a qdisc.
#QdiscStats: {
	basic: #GnetStatsBasic
	queue: #GnetStatsQueue
}

// #QdiscEntry is an entity (within the TcTreeSnapshot ReadModel) representing
// one qdisc instance. The handle is the qdisc's own handle; parent is the
// parent handle (TC_H_ROOT for root qdiscs, TC_H_INGRESS for ingress).
#QdiscEntry: {
	// interface is the interface name; used as the "interface" Prometheus label.
	interface: string & !=""

	// handle is the qdisc handle ValueObject.
	handle: #TcHandle

	// parent is the parent handle. TC_H_ROOT = {major: 0xffff, minor: 0xffff}.
	parent: #TcHandle

	// kind is the qdisc scheduler kind string.
	kind: #TcKind

	// stats holds the TCA_STATS2 decoded counters. Absent when the kernel
	// returns no stats (some virtual qdiscs omit them).
	stats?: #QdiscStats
}

// #ClassStats holds combined TCA_STATS2 fields for a traffic class entry.
#ClassStats: {
	basic: #GnetStatsBasic
	queue: #GnetStatsQueue
}

// #ClassEntry is a traffic class record from RTM_GETTCLASS responses.
#ClassEntry: {
	// interface is the parent interface name.
	interface: string & !=""

	// handle is the class handle.
	handle: #TcHandle

	// parent is the parent qdisc or class handle.
	parent: #TcHandle

	// kind is the class kind (e.g. "htb", "hfsc", "cbq").
	kind: #TcKind

	// stats holds the TCA_STATS2 decoded counters.
	stats?: #ClassStats
}

// #FilterEntry is a filter record from RTM_GETTFILTER responses.
// Cardinality bound: ~4096 entries; direction in (ingress, egress).
#FilterEntry: {
	// interface is the parent interface name.
	interface: string & !=""

	// handle is the filter handle.
	handle: #TcHandle

	// kind is the filter kind (e.g. "flower", "u32", "bpf", "matchall").
	kind: #TcKind

	// direction indicates whether the filter is on the ingress or egress path.
	direction: #TcDirection

	// stats holds the TCA_STATS2 decoded counters for matched traffic.
	stats?: #GnetStatsBasic
}

// #TcTreeSnapshot is the immutable ReadModel produced by TcCollector
// for the RTM_GETQDISC, RTM_GETTCLASS, and RTM_GETTFILTER subsystems
// for one scrape epoch. The name "tree" reflects the qdisc-class-filter
// hierarchy encoded by the handle/parent relationship.
#TcTreeSnapshot: {
	// epoch_ns is the Unix nanosecond timestamp when this snapshot was captured.
	epoch_ns: uint64

	// qdiscs is the complete list of qdisc entries visible in this network namespace.
	qdiscs: [...#QdiscEntry]

	// classes is the complete list of traffic class entries.
	classes: [...#ClassEntry]

	// filters is the complete list of tc filter entries.
	filters: [...#FilterEntry]
}
