// DDD role: ReadModel
package schemas

// ---------------------------------------------------------------------------
// rtnetlink_extended.cue — wire-level value objects and ReadModel for the
// rtnetlink-extended bounded context (ADR-0021).
//
// Subsystem: NETLINK_ROUTE (family=0).
// Wire messages issued: RTM_GETSTATS (94), RTM_GETNEIGH/AF_BRIDGE (30),
// RTM_GETRULE (82), RTM_GETNEXTHOP (118).
// Kernel range: RTM_GETSTATS >= 4.20; RTM_GETNEXTHOP >= 5.3.
// All byte offsets assume little-endian (x86-64 / arm64).
//
// Grounded in include/uapi/linux/if_link.h (IFLA_STATS_* enum),
// include/uapi/linux/rtnetlink.h (RTM_GETSTATS, RTM_GETRULE, RTM_GETNEXTHOP),
// include/uapi/linux/nexthop.h (nhmsg).
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// RTM_GETSTATS wire types
// ---------------------------------------------------------------------------

// #IfStatsMsgFamily restricts the rtgen family byte in if_stats_msg.
// RTM_GETSTATS uses AF_UNSPEC (0) for all-interface dumps.
#IfStatsMsgFamily: 0 // AF_UNSPEC

// #IfStatsFilterMask is the bitmask placed in the if_stats_msg.filter_mask
// field to select which IFLA_STATS_* attribute groups the kernel returns.
// Source: include/uapi/linux/if_link.h enum rtnl_link_stats_type.
//
// IFLA_STATS_LINK_64          = 0 (bit 0): full rtnl_link_stats64 (200 bytes)
// IFLA_STATS_LINK_XSTATS      = 1 (bit 1): driver xstats (bridge, bond, etc.)
// IFLA_STATS_LINK_OFFLOAD_XSTATS = 3 (bit 3): hw-offload stats (switchdev/tc)
//
// The adapter requests all three: filter_mask = (1<<0)|(1<<1)|(1<<3) = 0x0B.
#IfStatsFilterMask: >=0 & <=65535

// #IfStatsFilterMaskFull is the recommended filter_mask requesting all three
// xstat groups collected by RtnetlinkExtendedAdapter.
#IfStatsFilterMaskFull: #IfStatsFilterMask & 0x0B

// #IfStatsMsg is the fixed 16-byte body of RTM_GETSTATS / RTM_NEWSTATS.
// The body follows nlmsghdr immediately; RTattrs start at NLMSG_HDRLEN + 16.
// Source: include/uapi/linux/if_link.h struct if_stats_msg.
#IfStatsMsg: {
	// ifi_family: must be AF_UNSPEC (0) for dump requests. u8.
	ifi_family: uint8 & 0

	// pad1: padding byte; ignore on receive. u8.
	pad1: uint8

	// pad2: padding halfword; ignore on receive. u16.
	pad2: uint16

	// ifindex: 0 in dump requests (all interfaces); interface index in replies.
	// u32 native-endian.
	ifindex: uint32

	// filter_mask: bitmask of IFLA_STATS_* groups requested/present. u32 LE.
	// See #IfStatsFilterMask and #IfStatsFilterMaskFull.
	filter_mask: #IfStatsFilterMask
}

// ---------------------------------------------------------------------------
// IFLA_STATS_* attribute type codes (RTM_GETSTATS / RTM_NEWSTATS)
// Source: include/uapi/linux/if_link.h enum rtnl_link_stats_type
// ---------------------------------------------------------------------------

// #IflaStatsType enumerates the top-level attribute types in RTM_NEWSTATS
// responses. Strip NLA_F_NESTED (bit 15) before matching.
#IflaStatsType:
	0 | // IFLA_STATS_UNSPEC            (skip)
	1 | // IFLA_STATS_LINK_64           rtnl_link_stats64 (192 or 200 bytes)
	2 | // IFLA_STATS_LINK_XSTATS       nested link_xstats_type payload
	3 | // IFLA_STATS_LINK_XSTATS_SLAVE nested (for VLAN, bond slave)
	4 | // IFLA_STATS_LINK_OFFLOAD_XSTATS nested hw-offload stats
	5   // IFLA_STATS_AF_SPEC           nested per-family stats (skip)

// #IflaStatsTypeCode is the raw u16 for use in match expressions.
#IflaStatsTypeCode: >=0 & <=65535

// ---------------------------------------------------------------------------
// BRIDGE_XSTATS_* sub-attribute type codes (IFLA_STATS_LINK_XSTATS for bridges)
// Source: include/uapi/linux/if_bridge.h enum bridge_xstats_type
// ---------------------------------------------------------------------------

// #BridgeXstatsType enumerates the sub-attribute types nested inside
// IFLA_STATS_LINK_XSTATS when the interface is a Linux bridge device.
// The sub-attribute payload is a struct br_mcast_stats or br_vlan_stats blob.
#BridgeXstatsType:
	0 | // BRIDGE_XSTATS_UNSPEC  (skip)
	1 | // BRIDGE_XSTATS_VLAN    br_vlan_stats (8 bytes: rx_bytes u32, tx_bytes u32)
	2 | // BRIDGE_XSTATS_MCAST   br_mcast_stats (variable; rx/tx multicast counters)
	3   // BRIDGE_XSTATS_PAD     (skip)

// #BrMcastStats documents the relevant fields extracted from the
// BRIDGE_XSTATS_MCAST payload for nft_link_xstats_bridge_rx/tx_multicast_bytes.
// Only the rx_bytes and tx_bytes summary fields are exported; per-group counters
// are discarded (ADR-0005 cardinality enforcement).
#BrMcastStats: {
	// rx_bytes: total bytes received in multicast frames on this bridge port.
	// u64 native-endian; byte offset 0 in the br_mcast_stats payload.
	rx_bytes: uint64

	// tx_bytes: total bytes transmitted in multicast frames on this bridge port.
	// u64 native-endian; byte offset 8 in the br_mcast_stats payload.
	tx_bytes: uint64
}

// #OffloadXstatsType enumerates the sub-attribute types inside
// IFLA_STATS_LINK_OFFLOAD_XSTATS for switchdev/tc-offload drivers.
// Source: include/uapi/linux/if_link.h enum ifla_offload_xstats_type.
#OffloadXstatsType:
	0 | // IFLA_OFFLOAD_XSTATS_UNSPEC       (skip)
	1 | // IFLA_OFFLOAD_XSTATS_CPU_HIT      rtnl_hw_stats64 blob; CPU-path stats
	2 | // IFLA_OFFLOAD_XSTATS_HW_S_INFO    nested hw-stats availability info
	3   // IFLA_OFFLOAD_XSTATS_L3_STATS     rtnl_hw_stats64 for L3 offload

// #RtnlHwStats64Wire documents the rtnl_hw_stats64 payload layout used by
// IFLA_OFFLOAD_XSTATS_CPU_HIT and IFLA_OFFLOAD_XSTATS_L3_STATS.
// Only rx_bytes and tx_bytes are exported; other counters are not emitted.
// Source: include/uapi/linux/if_link.h struct rtnl_hw_stats64.
#RtnlHwStats64Wire: {
	// rx_packets u64 @ 0 (not exported)
	rx_packets: uint64
	// tx_packets u64 @ 8 (not exported)
	tx_packets: uint64
	// rx_bytes u64 @ 16 -> nft_link_xstats_offload_rx_bytes_total
	rx_bytes: uint64
	// tx_bytes u64 @ 24 -> nft_link_xstats_offload_tx_bytes_total
	tx_bytes: uint64
	// rx_errors u64 @ 32 (not exported)
	rx_errors: uint64
	// tx_errors u64 @ 40 (not exported)
	tx_errors: uint64
	// rx_dropped u64 @ 48 (not exported)
	rx_dropped: uint64
	// tx_dropped u64 @ 56 (not exported)
	tx_dropped: uint64
}

// ---------------------------------------------------------------------------
// RTM_GETNEIGH / AF_BRIDGE — FDB entry counting
// ---------------------------------------------------------------------------

// #BridgeNdMsgFamily is the ndm_family value for bridge FDB dump requests.
// RTM_GETNEIGH with ndm_family=AF_BRIDGE (7) returns bridge forwarding-database
// entries. The existing RtnetlinkAdapter skips ndm_family=7 (gotcha G-21);
// this context collects it for bounded FDB entry counting only.
#BridgeNdMsgFamily: 7 // AF_BRIDGE

// #BridgeFdbAggKey is the aggregate key for FDB entry counting.
// The adapter counts entries per (interface) by mapping ndm_ifindex to name
// from the link snapshot. MAC addresses are discarded (ADR-0005).
#BridgeFdbAggKey: {
	// interface: IFLA_IFNAME of the bridge device owning the FDB.
	// Resolved by looking up ndm_ifindex in the link name table.
	interface: string & !=""
}

// #BridgeFdbSnapshot is the ReadModel produced by the FDB dump phase.
// It maps bridge interface names to total FDB entry counts.
// Cardinality is bounded by the number of bridge devices on the host (typically
// 1-8 on any real network appliance; well under the ADR-0005 ceiling).
#BridgeFdbSnapshot: {
	// entries maps each bridge interface name to its total FDB count.
	// The count on the probe host was 150 during the grounding probe.
	entries: {[string]: uint64}

	// scraped_at_unix_secs records the Unix epoch second when this snapshot
	// was produced, for nft_exporter_snapshot_age_seconds self-telemetry.
	scraped_at_unix_secs: uint64
}

// ---------------------------------------------------------------------------
// RTM_GETRULE — FIB policy-rule counting
// ---------------------------------------------------------------------------

// #FibRuleFamily enumerates the address families used in RTM_GETRULE requests.
// One dump request is issued per family.
#FibRuleFamily:
	2  | // AF_INET  — IPv4 policy rules
	10 | // AF_INET6 — IPv6 policy rules
	28   // AF_MPLS  — MPLS policy rules (kernel >= 4.3; EINVAL if unsupported)

// #FibRuleFamilyLabel maps kernel AF_* constants to human-readable label strings
// used in nft_fib_rules{family=...}.
#FibRuleFamilyLabel: "inet" | "inet6" | "mpls"

// #FibRuleMsg is the 12-byte body of RTM_GETRULE / RTM_NEWRULE messages.
// Source: include/uapi/linux/fib_rules.h struct fib_rule_hdr.
// For dump requests all fields are zero except family.
#FibRuleMsg: {
	// family: address family (AF_INET=2, AF_INET6=10, AF_MPLS=28). u8.
	family: uint8

	// dst_len, src_len: prefix lengths; both 0 in dump requests. u8.
	dst_len: uint8
	src_len: uint8

	// tos: type of service; 0 in dump requests. u8.
	tos: uint8

	// table: routing table id (RT_TABLE_UNSPEC=0 in dumps). u8.
	table: uint8

	// action: FR_ACT_*; 0 in dump requests. u8.
	action: uint8

	// flags: u32 native-endian.
	flags: uint32
}

// #FibRulesSnapshot is the ReadModel produced by the RTM_GETRULE phase.
// Maps each address-family label to the total count of installed policy rules.
#FibRulesSnapshot: {
	// rules_by_family maps "inet", "inet6", "mpls" to rule count.
	rules_by_family: {[#FibRuleFamilyLabel]: uint64}

	// scraped_at_unix_secs is the snapshot timestamp (Unix epoch seconds).
	scraped_at_unix_secs: uint64
}

// ---------------------------------------------------------------------------
// RTM_GETNEXTHOP — nexthop-object counting
// ---------------------------------------------------------------------------

// #NhMsg is the 8-byte body of RTM_GETNEXTHOP / RTM_NEWNEXTHOP messages.
// Source: include/uapi/linux/nexthop.h struct nhmsg.
// For a full dump, all fields are zero (nh_family = AF_UNSPEC).
#NhMsg: {
	// nh_family: AF_UNSPEC (0) for all-nexthop dumps. u8.
	nh_family: uint8

	// nh_scope: route scope; 0 in dump requests. u8.
	nh_scope: uint8

	// nh_protocol: routing protocol (RTPROT_*); 0 in dump requests. u8.
	nh_protocol: uint8

	// resvd: padding; ignore. u8.
	resvd: uint8

	// nh_flags: NHF_* bitmask; 0 in dump requests. u32 native-endian.
	nh_flags: uint32
}

// #NhSnapshotAvailability records whether RTM_GETNEXTHOP is supported.
// The adapter issues a probe dump at startup; EINVAL or EOPNOTSUPP on kernels
// < 5.3 sets available=false. nft_nexthop_objects emits 0 when unavailable.
#NhSnapshotAvailability: "available" | "unavailable_kernel_too_old"

// #NhObjectSnapshot is the ReadModel for the RTM_GETNEXTHOP phase.
#NhObjectSnapshot: {
	// total is the count of installed nexthop objects (groups + individual).
	// Bounded by operator-controlled routing configuration; typically < 1 000
	// even in large BGP deployments.
	total: uint64

	// availability records the kernel capability probe result.
	availability: #NhSnapshotAvailability

	// scraped_at_unix_secs is the snapshot timestamp (Unix epoch seconds).
	scraped_at_unix_secs: uint64
}

// ---------------------------------------------------------------------------
// Composite ReadModel
// ---------------------------------------------------------------------------

// #RtnetlinkExtendedSnapshot is the aggregate ReadModel produced by one
// RtnetlinkExtendedCollector scrape. It combines the four sub-snapshots into a
// single value object returned to MetricRegistryPort.
#RtnetlinkExtendedSnapshot: {
	// xstats_available records whether RTM_GETSTATS is supported by the kernel.
	// Set to false on kernels < 4.20. When false, all nft_link_xstats_* and
	// nft_bridge_fdb_entries metrics are absent for this scrape.
	xstats_available: bool

	// bridge_fdb is the FDB entry counts per bridge interface.
	bridge_fdb: #BridgeFdbSnapshot

	// fib_rules is the policy-rule counts per address family.
	fib_rules: #FibRulesSnapshot

	// nexthops is the total nexthop object count and availability flag.
	nexthops: #NhObjectSnapshot
}

// ---------------------------------------------------------------------------
// Wire-to-metric mapping table
// ---------------------------------------------------------------------------

// #RtnetlinkExtendedMetricMap documents the mapping from wire attribute or
// aggregate field to the Prometheus metric name exported by this context.
#RtnetlinkExtendedMetricMap: {
	// mappings: ordered list of (wire_source, metric_name, labels, type) records.
	mappings: [
		{
			wire_source: "RTM_NEWSTATS IFLA_STATS_LINK_XSTATS / BRIDGE_XSTATS_MCAST rx_bytes"
			metric_name: "nft_link_xstats_bridge_rx_multicast_bytes_total"
			labels:      ["interface"]
			metric_type: "counter"
		},
		{
			wire_source: "RTM_NEWSTATS IFLA_STATS_LINK_XSTATS / BRIDGE_XSTATS_MCAST tx_bytes"
			metric_name: "nft_link_xstats_bridge_tx_multicast_bytes_total"
			labels:      ["interface"]
			metric_type: "counter"
		},
		{
			wire_source: "RTM_NEWSTATS IFLA_STATS_LINK_OFFLOAD_XSTATS rtnl_hw_stats64.rx_bytes"
			metric_name: "nft_link_xstats_offload_rx_bytes_total"
			labels:      ["interface"]
			metric_type: "counter"
		},
		{
			wire_source: "RTM_NEWSTATS IFLA_STATS_LINK_OFFLOAD_XSTATS rtnl_hw_stats64.tx_bytes"
			metric_name: "nft_link_xstats_offload_tx_bytes_total"
			labels:      ["interface"]
			metric_type: "counter"
		},
		{
			wire_source: "RTM_GETNEIGH AF_BRIDGE entry count per ndm_ifindex"
			metric_name: "nft_bridge_fdb_entries"
			labels:      ["interface"]
			metric_type: "gauge"
		},
		{
			wire_source: "RTM_GETRULE per-family rule count"
			metric_name: "nft_fib_rules"
			labels:      ["family"]
			metric_type: "gauge"
		},
		{
			wire_source: "RTM_GETNEXTHOP total entry count"
			metric_name: "nft_nexthop_objects"
			labels:      []
			metric_type: "gauge"
		},
		{
			wire_source: "RtnetlinkExtendedAdapter.xstats_available probe"
			metric_name: "nft_scrape_collector_available"
			labels:      ["collector"]
			metric_type: "gauge"
		},
	]
}

// ---------------------------------------------------------------------------
// Dump request specification
// ---------------------------------------------------------------------------

// #RtnetlinkExtendedDumpSequence specifies all four dump requests issued per
// scrape in deterministic order. Each entry is an extension of #DumpRequest
// (see rtnetlink_wire.cue) with an additional body_struct field.
#RtnetlinkExtendedDumpPhase: {
	// phase_name: human-readable name used in tracing spans.
	phase_name: string & !=""

	// msg_type: the RTM_GET* nlmsg_type constant (u16).
	msg_type: uint16

	// nlmsg_flags: NLM_F_REQUEST | NLM_F_DUMP = 0x0301 for dump phases.
	nlmsg_flags: 0x0301

	// body_family: family byte in the fixed-struct body (ndmsg/rtmsg/nhmsg).
	body_family: uint8

	// kernel_min_version: earliest kernel version that supports this message type.
	kernel_min_version: string & !=""
}

// #RtnetlinkExtendedDumpSequence is the ordered list of dump phases per scrape.
#RtnetlinkExtendedDumpSequence: [
	{
		phase_name:          "xstats"
		msg_type:            94 // RTM_GETSTATS
		nlmsg_flags:         0x0301
		body_family:         0  // AF_UNSPEC; body is if_stats_msg not rtgenmsg
		kernel_min_version:  "4.20"
	},
	{
		phase_name:          "bridge_fdb"
		msg_type:            30 // RTM_GETNEIGH
		nlmsg_flags:         0x0301
		body_family:         7  // AF_BRIDGE
		kernel_min_version:  "3.3"
	},
	{
		phase_name:          "fib_rules_inet"
		msg_type:            82 // RTM_GETRULE
		nlmsg_flags:         0x0301
		body_family:         2  // AF_INET
		kernel_min_version:  "2.6.25"
	},
	{
		phase_name:          "fib_rules_inet6"
		msg_type:            82 // RTM_GETRULE
		nlmsg_flags:         0x0301
		body_family:         10 // AF_INET6
		kernel_min_version:  "2.6.25"
	},
	{
		phase_name:          "fib_rules_mpls"
		msg_type:            82 // RTM_GETRULE
		nlmsg_flags:         0x0301
		body_family:         28 // AF_MPLS
		kernel_min_version:  "4.3"
	},
	{
		phase_name:          "nexthops"
		msg_type:            118 // RTM_GETNEXTHOP
		nlmsg_flags:         0x0301
		body_family:         0   // AF_UNSPEC; body is nhmsg
		kernel_min_version:  "5.3"
	},
]
