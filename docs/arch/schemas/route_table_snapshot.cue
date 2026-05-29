// DDD role: ReadModel
package schemas

// #RouteFamily enumerates the address family strings used in route aggregation.
// Matches RTA_FAMILY attribute values mapped to strings.
#RouteFamily: "inet" | "inet6" | "mpls"

// #RouteProtocol enumerates the routing protocol identifiers as strings.
// Values match the RTPROT_* constants mapped to lower-case strings.
#RouteProtocol:
	"unspec" |
	"redirect" |
	"kernel" |
	"boot" |
	"static" |
	"gated" |
	"ra" |
	"mrt" |
	"zebra" |
	"bird" |
	"dnrouted" |
	"xorp" |
	"ntk" |
	"dhcp" |
	"mrouted" |
	"babel" |
	"bgp" |
	"isis" |
	"ospf" |
	"rip" |
	"eigrp" |
	"other"

// #RouteType enumerates the route type strings derived from RTN_* constants.
#RouteType:
	"unspec" |
	"unicast" |
	"local" |
	"broadcast" |
	"anycast" |
	"multicast" |
	"blackhole" |
	"unreachable" |
	"prohibit" |
	"throw" |
	"nat" |
	"xresolve"

// #RouteTableId is the routing table identifier. Standard tables:
// 253=default, 254=main, 255=local. Custom tables: 1-252.
#RouteTableId: >=0 & <=4294967295

// #RouteAggregateKey is the composite aggregation key for route counts.
// CRITICAL: destination prefix (RTA_DST) is intentionally absent to enforce
// bounded cardinality per ADR-0005. Routes are NEVER emitted per destination.
#RouteAggregateKey: {
	table:      #RouteTableId
	family:     #RouteFamily
	protocol:   #RouteProtocol
	route_type: #RouteType
}

// #RouteCountEntry is one aggregated route count record.
// Maps directly to one time series in nft_route_count gauge.
#RouteCountEntry: {
	key:   #RouteAggregateKey
	count: uint64
}

// #RouteTableSnapshot is the immutable ReadModel produced by RtnetlinkCollector
// for the RTM_GETROUTE subsystem. Contains only aggregated counts keyed by
// (table, family, protocol, route_type). Destination prefixes are never stored.
#RouteTableSnapshot: {
	// epoch_ns is the Unix nanosecond timestamp when this snapshot was captured.
	epoch_ns: uint64

	// routes is the list of aggregated route count entries.
	// Cardinality bound: ~480 entries worst case.
	routes: [...#RouteCountEntry]
}

// #NeighborState enumerates the ARP/NDP neighbor cache entry states.
// Values map to NUD_* kernel constants.
#NeighborState:
	"incomplete" |
	"reachable" |
	"stale" |
	"delay" |
	"probe" |
	"failed" |
	"noarp" |
	"permanent"

// #NeighborAggregateKey is the composite key for neighbor count aggregation.
// CRITICAL: IP address (RTA_DST) and MAC address (NDA_LLADDR) are intentionally
// absent to enforce bounded cardinality per ADR-0005.
#NeighborAggregateKey: {
	interface: string & !=""
	family:    "inet" | "inet6"
	state:     #NeighborState
}

// #NeighborCountEntry is one aggregated neighbor count record.
// Maps directly to one time series in nft_neighbor_count gauge.
#NeighborCountEntry: {
	key:   #NeighborAggregateKey
	count: uint64
}

// #NeighborSnapshot is the immutable ReadModel produced by RtnetlinkCollector
// for the RTM_GETNEIGH subsystem. Contains only aggregated counts; individual
// IP and MAC addresses are never stored or emitted as metric labels.
#NeighborSnapshot: {
	// epoch_ns is the Unix nanosecond timestamp when this snapshot was captured.
	epoch_ns: uint64

	// neighbors is the list of aggregated neighbor count entries.
	// Cardinality bound: ~3072 entries worst case.
	neighbors: [...#NeighborCountEntry]
}
