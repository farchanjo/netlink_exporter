// DDD role: ValueObject
package schemas

// ---------------------------------------------------------------------------
// interface_filter.cue — InterfaceFilter value object (ADR-0013)
//
// Encodes the regex-based include/exclude filtering applied to interface names
// (IFLA_IFNAME) before any series are accumulated. The filter is evaluated in
// RtnetlinkAdapter (after IFLA_IFNAME decode) and TcNetlinkAdapter (after
// tcm_ifindex-to-name resolution). Exclude wins when both patterns match.
//
// Context: the probe host exposes 29 network interfaces, the majority of which
// are veth pairs. Without filtering, ethtool stats would produce up to 1711
// series (29 x 59 stat names). A typical Kubernetes-node operator configuration
// such as interface_exclude_regex = '^(veth|cali|tunl|flannel|cni)' reduces
// the rtnetlink cardinality by ~85% on this host.
// ---------------------------------------------------------------------------

// #InterfaceFilterConfig is the ValueObject encoding interface filter policy.
// Both fields are optional regex strings. The filter is compiled into a Regex
// object at startup and stored in an Arc<InterfaceFilter> shared across adapter
// crates. Neither field is mutated after startup; the filter is immutable for
// the lifetime of the process.
#InterfaceFilterConfig: {
	// interface_include_regex is a POSIX extended regular expression.
	// When non-empty, only interface names that match this pattern are collected.
	// When empty or absent, all interfaces pass the include test (equivalent to '.*').
	// Compiled to Regex at startup; ENOMEM or invalid syntax causes a fatal startup error.
	// Env: NFT_EXPORTER_INTERFACE_INCLUDE_REGEX. CLI: --interface-include-regex.
	// Default: ".*" (include all).
	interface_include_regex: string | *".*"

	// interface_exclude_regex is a POSIX extended regular expression.
	// When non-empty, any interface name that matches this pattern is suppressed
	// even if it also matches interface_include_regex (exclude wins).
	// When empty or absent, no interfaces are suppressed by the exclude test.
	// Env: NFT_EXPORTER_INTERFACE_EXCLUDE_REGEX. CLI: --interface-exclude-regex.
	// Default: "" (exclude nothing).
	interface_exclude_regex: string | *""
}

// #FilterSemantics documents the evaluation semantics enforced by InterfaceFilter.
// These constraints must be implemented identically in RtnetlinkAdapter and
// TcNetlinkAdapter; any divergence is a bug.
#FilterSemantics: {
	// exclude_wins_on_both_match: when both interface_include_regex and
	// interface_exclude_regex match a given IFLA_IFNAME, the interface is
	// suppressed. This ensures operators can use a broad include pattern and
	// a more specific exclude to carve out exceptions without operator surprise.
	exclude_wins_on_both_match: true

	// application_point_rtnetlink: the filter is applied in RtnetlinkAdapter
	// after IFLA_IFNAME is decoded from the RTM_NEWLINK message, before any
	// rtnl_link_stats64 fields are accumulated into LinkSnapshot.
	application_point_rtnetlink: "after IFLA_IFNAME decode in RtnetlinkAdapter, before series accumulation"

	// application_point_tc: the filter is applied in TcNetlinkAdapter after
	// tcm_ifindex is resolved to an interface name via the link map populated by
	// the prior RTM_GETLINK dump, before any TCA_STATS2 fields are accumulated.
	application_point_tc: "after tcm_ifindex to name resolution in TcNetlinkAdapter, before series accumulation"

	// filtered_counter: each filtered interface increments nft_link_filtered_total
	// once per scrape per enabled collector that applies interface filtering.
	// This counter allows operators to verify their regex patterns are matching
	// the expected interfaces.
	filtered_counter: "nft_link_filtered_total{collector}"
}

// #InterfaceFilterDefault is the production default configuration.
// With this default, all interfaces are collected and none are excluded.
// Operators should override interface_exclude_regex to suppress virtual
// interfaces (e.g. '^(veth|cali|tunl|flannel|cni)' on Kubernetes nodes).
#InterfaceFilterDefault: #InterfaceFilterConfig & {
	interface_include_regex: ".*"
	interface_exclude_regex: ""
}

// #InterfaceFilterKubernetesNode is a reference configuration for Kubernetes
// DaemonSet deployments where container network interfaces should be excluded.
// This is provided as documentation; it is not enforced at runtime.
#InterfaceFilterKubernetesNode: #InterfaceFilterConfig & {
	interface_include_regex: ".*"
	interface_exclude_regex: "^(veth|cali|tunl|flannel|cni|lxc|cilium)"
}

// #FilteredInterfaceCounterSpec documents the nft_link_filtered_total counter
// that is incremented for each interface suppressed by the filter.
// This counter allows operators to observe how many interfaces were filtered
// per scrape per collector, aiding regex pattern validation.
#FilteredInterfaceCounterSpec: {
	// metric is the Prometheus metric name.
	metric: "nft_link_filtered_total"

	// type is the OpenMetrics metric type.
	type: "counter"

	// labels is the ordered list of label dimension names.
	labels: ["collector"]

	// cardinality_bound is the worst-case series ceiling.
	// One series per enabled collector that applies interface filtering.
	// Currently: rtnetlink and traffic_control (tc) = 2 series.
	cardinality_bound: "~6 one per enabled collector that applies interface filtering"

	// increment_semantics: this counter is incremented once per filtered
	// interface per collector per scrape. It is NOT a counter of suppressed
	// metrics; it is a counter of suppressed interfaces.
	increment_semantics: "once per filtered interface per collector per scrape epoch"
}
