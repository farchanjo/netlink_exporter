// DDD role: AggregateRoot
package schemas

// #ConntrackProtocol enumerates the layer-4 protocol identifiers used in
// conntrack entries. Values match the IPPROTO_* constants mapped to strings
// by the ctnetlink attribute decoder.
#ConntrackProtocol:
	"tcp" |
	"udp" |
	"udplite" |
	"icmp" |
	"icmpv6" |
	"sctp" |
	"dccp" |
	"gre"

// #ConntrackState enumerates the connection states reported by ctnetlink.
// For TCP entries the state maps to the TCP state machine; for stateless
// protocols (UDP, ICMP) the kernel reports a simplified state.
#ConntrackState:
	"none" |
	"new" |
	"established" |
	"related" |
	"invalid" |
	"untracked" |
	"syn_sent" |
	"syn_recv" |
	"fin_wait" |
	"close_wait" |
	"last_ack" |
	"time_wait" |
	"close" |
	"listen"

// #ConntrackDirection enumerates the two traffic directions tracked per flow.
#ConntrackDirection: "original" | "reply"

// #Ipv4Address is an IPv4 address string in dotted-decimal notation.
#Ipv4Address: =~"^([0-9]{1,3}\\.){3}[0-9]{1,3}$"

// #Ipv6Address is an IPv6 address string in compressed or full notation.
#Ipv6Address: =~"^[0-9a-fA-F:]+$"

// #IpAddress is either an IPv4 or IPv6 address string.
#IpAddress: #Ipv4Address | #Ipv6Address

// #L4Port is a TCP/UDP/SCTP/DCCP port number. Valid range: 0-65535.
// ICMP entries use src_port for type and dst_port for code.
#L4Port: >=0 & <=65535

// #FlowKey is the ValueObject that uniquely identifies a conntrack flow
// within a network namespace for one scrape epoch.
// CRITICAL: FlowKey fields are NEVER used as Prometheus label dimensions.
// They exist solely for internal deduplication inside ConntrackAggregator.
#FlowKey: {
	src_ip:   #IpAddress
	dst_ip:   #IpAddress
	protocol: #ConntrackProtocol
	src_port: #L4Port
	dst_port: #L4Port
}

// #CounterState holds the monotonically non-decreasing byte and packet
// counters for one traffic direction of a conntrack flow.
// Invariant: both bytes and packets are uint64 (never negative) and MUST
// be non-decreasing within the lifetime of a single scrape epoch.
#CounterState: {
	bytes:   uint64
	packets: uint64
}

// #DirectionalCounters groups both directional counter states for a flow.
#DirectionalCounters: {
	original: #CounterState
	reply:    #CounterState
}

// #ConntrackFlow is the AggregateRoot for one kernel connection-tracking entry.
// Identity: key (the FlowKey ValueObject). The aggregate is immutable within
// a scrape epoch — the kernel is the sole authority on flow state.
//
// ConntrackFlow is NEVER emitted as a Prometheus time series directly.
// It is consumed by ConntrackAggregator (DomainService) which groups flows
// by (protocol, state) to produce the bounded-cardinality ConntrackSummary.
#ConntrackFlow: {
	// key uniquely identifies the flow. Never used as a Prometheus label.
	key: #FlowKey

	// protocol is the layer-4 protocol of this flow.
	protocol: #ConntrackProtocol

	// state is the current conntrack state of this flow.
	state: #ConntrackState

	// mark is the optional conntrack mark (NFCT_MSG_MARK). 0 when unset.
	mark: uint32

	// zone is the conntrack zone ID. 0 is the default zone.
	zone: uint16

	// timeout_secs is the remaining flow timeout in seconds.
	timeout_secs: uint32

	// counters holds byte and packet counts per direction.
	counters: #DirectionalCounters

	// is_assured indicates the flow has passed the assured threshold
	// (TCP established, UDP reply seen).
	is_assured: bool

	// Cardinality guard: aggregation MUST happen before metric emission.
	// ConntrackFlow is private to the Conntrack bounded context.
}
