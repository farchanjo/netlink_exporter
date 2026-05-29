// DDD role: ReadModel
package schemas

// #LinkEntry is an immutable summary of one network interface for a single
// scrape epoch. It flattens the #Link aggregate root into a record optimised
// for direct projection into metric label sets and counter values.
// No mutable state; produced by RtnetlinkCollector and consumed by
// PrometheusRegistryAdapter within one HTTP /metrics response cycle.
#LinkEntry: {
	// ifindex is the kernel interface index (identity from the Link aggregate).
	ifindex: #IfIndex

	// name is the interface name used as the "interface" Prometheus label.
	name: string & !=""

	// alias is the IFLA_IFALIAS string; empty when not configured.
	alias: string

	// link_type is the ARPHRD hardware type used as the "link_type" label.
	link_type: #LinkType

	// operstate is the RFC-2863 operational state used as the "operstate" label.
	operstate: #OperState

	// flags is the IFLA_FLAGS hex string used as the "flags" label.
	flags: #IfFlags

	// mtu_bytes is the current MTU; maps to nft_link_mtu_bytes gauge value.
	mtu_bytes: #Mtu

	// speed_bits is the link speed in bps (-1 when unknown);
	// maps to nft_link_speed_bits gauge value.
	speed_bits: int & >=-1

	// stats is the IFLA_STATS64 snapshot; absent when the driver omits it.
	stats?: #IfStats64
}

// #AddressEntry is an immutable record for one IP address assigned to an
// interface. Projected into nft_address_info and nft_address_count metrics.
#AddressEntry: {
	// ifindex identifies the parent interface.
	ifindex: #IfIndex

	// interface_name is the parent interface name used as the "interface" label.
	interface_name: string & !=""

	// family is the address family string: "inet" (IPv4) or "inet6" (IPv6).
	family: "inet" | "inet6"

	// address is the IP address in standard notation (without prefix length).
	address: string & !=""

	// prefix_length is the prefix length in bits (0-32 for IPv4, 0-128 for IPv6).
	prefix_length: >=0 & <=128

	// scope is the address scope string: "host", "link", "global", or "site".
	scope: "host" | "link" | "global" | "site"
}

// #LinkSnapshot is the immutable ReadModel produced by RtnetlinkCollector
// for the RTM_GETLINK and RTM_GETADDR subsystem for one scrape epoch.
// It is valid only for the duration of the current HTTP /metrics response.
// ScrapeLifecycle wraps this in MetricSnapshot before passing it downstream.
#LinkSnapshot: {
	// epoch_ns is the Unix nanosecond timestamp when this snapshot was captured.
	// Used by nft_exporter_snapshot_age_seconds self-metric.
	epoch_ns: uint64

	// links is the complete list of link entries visible in this network namespace.
	links: [...#LinkEntry]

	// addresses is the complete list of address entries across all interfaces.
	addresses: [...#AddressEntry]
}
