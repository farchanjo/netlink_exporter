// DDD role: DomainService
package schemas

// ---------------------------------------------------------------------------
// Naming conventions and namespace enforcement
// ---------------------------------------------------------------------------

// #MetricName is a Prometheus metric name that MUST begin with "nft_".
#MetricName: =~"^nft_"

// #MetricType enumerates the OpenMetrics metric types used by this exporter.
#MetricType: "gauge" | "counter"

// #MetricUnit enumerates valid unit strings for this exporter's metric families.
#MetricUnit: "bytes" | "packets" | "bits" | "seconds" | "none"

// #CardinalityBound is a human-readable string describing the worst-case series
// count for a metric family (e.g. "~512", "~50000"). Never numeric — intent is
// documentation of the analytical bound, not a machine-enforced ceiling.
#CardinalityBound: string & !=""

// ---------------------------------------------------------------------------
// Forbidden label dimensions (cardinality enforcement)
// ---------------------------------------------------------------------------

// #ForbiddenLabelName lists label dimensions that must never appear in any
// metric family emitted by this exporter. These labels produce unbounded
// cardinality and are forbidden by ADR-0005.
#ForbiddenLabelName:
	"flow_id" |
	"destination_prefix" |
	"source_prefix" |
	"socket_inode" |
	"mac_address" |
	"src_ip" |
	"dst_ip" |
	"src_port" |
	"dst_port"

// ---------------------------------------------------------------------------
// MetricDescriptor: the canonical definition of one metric family
// ---------------------------------------------------------------------------

// #MetricDescriptor encodes the full contract for a single metric family.
// Every entry in the metric_contract list below conforms to this schema.
#MetricDescriptor: {
	// context is the bounded-context slug that owns this metric.
	context: "rtnetlink" | "traffic-control" | "conntrack" | "nftables" | "sock-diag" | "ethtool" | "self" | "xfrm-ipsec" | "ipvs" | "wireguard" | "devlink" | "drop-monitor" | "rtnetlink-extended"

	// metric is the full Prometheus metric name (nft_ prefix enforced).
	metric: #MetricName

	// type is the OpenMetrics metric type.
	type: #MetricType

	// unit describes what the numeric value represents.
	unit: #MetricUnit

	// labels is the ordered list of label dimension names for this family.
	// No element may appear in #ForbiddenLabelName.
	labels: [...string]

	// cardinality_bound is a human-readable worst-case series ceiling.
	cardinality_bound: #CardinalityBound

	// help is the HELP string registered in the OpenMetrics exposition.
	help: string & !=""
}

// ---------------------------------------------------------------------------
// SelfMetricDescriptor: self-telemetry metrics (no unit field in blueprint)
// ---------------------------------------------------------------------------

// #SelfMetricDescriptor describes an exporter self-telemetry metric family.
#SelfMetricDescriptor: {
	name:   #MetricName
	type:   #MetricType
	labels: [...string]
	help:   string & !=""
}

// ---------------------------------------------------------------------------
// Full metric_contract: all metric families emitted by nft_exporter
// ---------------------------------------------------------------------------

// #MetricContract is the authoritative list of all metric family descriptors.
// Violations of this contract (wrong type, wrong labels, missing nft_ prefix,
// cardinality overflow) are surfaced via nft_scrape_collector_error_total.
#MetricContract: [...#MetricDescriptor]

// metric_contract is the bound instance validated by `cue vet`.
metric_contract: #MetricContract & [
	// --- rtnetlink context ---
	{context: "rtnetlink", metric: "nft_link_info", type:              "gauge", unit: "none", labels: ["interface", "alias", "link_type", "operstate", "flags"], cardinality_bound: "~512 one series per network interface", help: "Metadata gauge (always 1) for each network link. Labels carry alias, type (ether/loopback/noarp), operstate, and flags as hex string."},
	{context: "rtnetlink", metric: "nft_link_receive_bytes_total", type: "counter", unit:     "bytes", labels: ["interface"], cardinality_bound: "~512", help: "Total bytes received on the interface since boot (IFLA_STATS64 rx_bytes)."},
	{context: "rtnetlink", metric: "nft_link_transmit_bytes_total", type: "counter", unit:    "bytes", labels: ["interface"], cardinality_bound: "~512", help: "Total bytes transmitted on the interface since boot (IFLA_STATS64 tx_bytes)."},
	{context: "rtnetlink", metric: "nft_link_receive_packets_total", type: "counter", unit:   "packets", labels: ["interface"], cardinality_bound: "~512", help: "Total packets received on the interface since boot (IFLA_STATS64 rx_packets)."},
	{context: "rtnetlink", metric: "nft_link_transmit_packets_total", type: "counter", unit:  "packets", labels: ["interface"], cardinality_bound: "~512", help: "Total packets transmitted on the interface since boot (IFLA_STATS64 tx_packets)."},
	{context: "rtnetlink", metric: "nft_link_receive_errors_total", type: "counter", unit:    "packets", labels: ["interface"], cardinality_bound: "~512", help: "Total receive errors on the interface (IFLA_STATS64 rx_errors)."},
	{context: "rtnetlink", metric: "nft_link_transmit_errors_total", type: "counter", unit:   "packets", labels: ["interface"], cardinality_bound: "~512", help: "Total transmit errors on the interface (IFLA_STATS64 tx_errors)."},
	{context: "rtnetlink", metric: "nft_link_receive_dropped_total", type: "counter", unit:   "packets", labels: ["interface"], cardinality_bound: "~512", help: "Total receive drops (IFLA_STATS64 rx_dropped)."},
	{context: "rtnetlink", metric: "nft_link_transmit_dropped_total", type: "counter", unit:  "packets", labels: ["interface"], cardinality_bound: "~512", help: "Total transmit drops (IFLA_STATS64 tx_dropped)."},
	{context: "rtnetlink", metric: "nft_link_mtu_bytes", type:            "gauge", unit: "bytes", labels: ["interface"], cardinality_bound: "~512", help: "Current MTU of the network interface in bytes (IFLA_MTU)."},
	{context: "rtnetlink", metric: "nft_link_speed_bits", type:           "gauge", unit: "bits", labels: ["interface"], cardinality_bound: "~512", help: "Link speed in bits per second; -1 when unknown."},
	{context: "rtnetlink", metric: "nft_address_info", type:              "gauge", unit: "none", labels: ["interface", "family", "address", "prefix_length", "scope"], cardinality_bound: "~2048 one series per (interface, family, address); scope in (host,link,global,site)", help: "Metadata gauge (always 1) for each configured IP address on an interface."},
	{context: "rtnetlink", metric: "nft_address_count", type:             "gauge", unit: "none", labels: ["interface", "family"], cardinality_bound: "~1024 |interfaces| x 2 families (inet, inet6)", help: "Number of IP addresses assigned to an interface, partitioned by address family."},
	{context: "rtnetlink", metric: "nft_route_count", type:               "gauge", unit: "none", labels: ["table", "family", "protocol", "route_type"], cardinality_bound: "~480 |table|~6 x |family|~3 x |protocol|~8 x |route_type|~8; NEVER per-destination prefix", help: "Count of routes aggregated by (table, family, protocol, route_type). No per-route time series."},
	{context: "rtnetlink", metric: "nft_neighbor_count", type:            "gauge", unit: "none", labels: ["interface", "family", "state"], cardinality_bound: "~3072 |interfaces|~512 x |family|~2 x |state|~6; NEVER per-IP or per-MAC", help: "Number of neighbor table (ARP/NDP) entries in each state, per interface and family."},
	{context: "rtnetlink", metric: "nft_link_filtered_total", type:      "counter", unit: "none", labels: ["collector"], cardinality_bound: "~6 one per enabled collector that applies interface filtering", help: "Total number of interface names suppressed by interface_include_regex / interface_exclude_regex per collector per scrape. Allows operators to verify filter configuration is matching expected interfaces (ADR-0013)."},
	{context: "rtnetlink", metric: "nft_address_flags_info", type:       "gauge", unit: "none", labels: ["interface", "family", "address", "permanent", "deprecated", "tentative"], cardinality_bound: "~2048 same as nft_address_info", help: "Flag metadata gauge (always 1) for each configured IP address. permanent/deprecated/tentative label values: 1 or 0 (IFA_FLAGS u32 extended flags: IFA_F_PERMANENT=0x80, IFA_F_DEPRECATED=0x20, IFA_F_TENTATIVE=0x40)."},

	// --- traffic-control context ---
	{context: "traffic-control", metric: "nft_tc_qdisc_info", type:           "gauge", unit: "none", labels: ["interface", "handle", "parent", "kind"], cardinality_bound: "~2048 interfaces x qdiscs per interface; handle is hex string (e.g. 1:0)", help: "Metadata gauge (always 1) for each qdisc instance. Labels carry handle, parent, and kind."},
	{context: "traffic-control", metric: "nft_tc_qdisc_bytes_total", type:    "counter", unit: "bytes", labels: ["interface", "handle", "kind"], cardinality_bound: "~2048", help: "Total bytes processed by the qdisc (TCA_STATS2 gnet_stats_basic bytes)."},
	{context: "traffic-control", metric: "nft_tc_qdisc_packets_total", type:  "counter", unit: "packets", labels: ["interface", "handle", "kind"], cardinality_bound: "~2048", help: "Total packets processed by the qdisc (gnet_stats_basic packets)."},
	{context: "traffic-control", metric: "nft_tc_qdisc_drops_total", type:    "counter", unit: "packets", labels: ["interface", "handle", "kind"], cardinality_bound: "~2048", help: "Total packets dropped by the qdisc (gnet_stats_queue drops)."},
	{context: "traffic-control", metric: "nft_tc_qdisc_overlimits_total", type: "counter", unit: "packets", labels: ["interface", "handle", "kind"], cardinality_bound: "~2048", help: "Total overlimit events (token bucket or rate limit exceeded)."},
	{context: "traffic-control", metric: "nft_tc_qdisc_backlog_bytes", type:  "gauge", unit: "bytes", labels: ["interface", "handle", "kind"], cardinality_bound: "~2048", help: "Current backlog size in bytes for the qdisc (gnet_stats_queue backlog)."},
	{context: "traffic-control", metric: "nft_tc_class_bytes_total", type:    "counter", unit: "bytes", labels: ["interface", "handle", "parent", "kind"], cardinality_bound: "~8192 bounded by operator-controlled TC class tree depth", help: "Total bytes processed by this traffic class (RTM_GETTCLASS TCA_STATS2)."},
	{context: "traffic-control", metric: "nft_tc_class_packets_total", type:  "counter", unit: "packets", labels: ["interface", "handle", "parent", "kind"], cardinality_bound: "~8192", help: "Total packets processed by this traffic class."},
	{context: "traffic-control", metric: "nft_tc_class_drops_total", type:    "counter", unit: "packets", labels: ["interface", "handle", "parent", "kind"], cardinality_bound: "~8192", help: "Total packets dropped by this traffic class."},
	{context: "traffic-control", metric: "nft_tc_filter_packets_total", type: "counter", unit: "packets", labels: ["interface", "handle", "kind", "direction"], cardinality_bound: "~4096 direction in (ingress,egress); kind in (flower,u32,bpf,matchall)", help: "Total packets matched by this tc filter (RTM_GETTFILTER TCA_STATS2)."},
	{context: "traffic-control", metric: "nft_tc_filter_bytes_total", type:   "counter", unit: "bytes", labels: ["interface", "handle", "kind", "direction"], cardinality_bound: "~4096", help: "Total bytes matched by this tc filter."},

	// --- conntrack context ---
	{context: "conntrack", metric: "nft_conntrack_entries", type:       "gauge", unit: "none", labels: ["protocol", "state"], cardinality_bound: "~96 worst case (|protocol|~8 x |TCP states|~10 + non-TCP established/new); practical ~40 on this host; NEVER one series per flow", help: "Current number of conntrack entries aggregated by (protocol, state). Per-flow time series are strictly forbidden. TCP state label values: none, syn_sent, syn_recv, established, fin_wait, close_wait, last_ack, time_wait, close, listen (via CTA_PROTOINFO_TCP_STATE u8). Non-TCP state label values: new (IPS_ASSURED clear), established (IPS_ASSURED set)."},
	{context: "conntrack", metric: "nft_conntrack_bytes_total", type:   "counter", unit: "bytes", labels: ["protocol", "direction"], cardinality_bound: "~16 |protocol|~8 x |direction|~2 (original,reply); aggregated across all flows", help: "Total bytes counted by conntrack aggregated across all flows, partitioned by protocol and direction."},
	{context: "conntrack", metric: "nft_conntrack_packets_total", type: "counter", unit: "packets", labels: ["protocol", "direction"], cardinality_bound: "~16", help: "Total packets counted by conntrack aggregated across all flows, partitioned by protocol and direction."},
	{context: "conntrack", metric: "nft_conntrack_max_entries", type:   "gauge", unit: "none", labels: [], cardinality_bound: "1", help: "Maximum number of conntrack entries allowed (nf_conntrack_max sysctl)."},
	{context: "conntrack", metric: "nft_conntrack_insert_total", type:  "counter", unit: "none", labels: [], cardinality_bound: "1", help: "Total conntrack entries inserted (IPCTNL_MSG_CT_GET_STATS_CPU sum insert across CPUs). Sourced from nf_conntrack_stat.insert; struct size 52 bytes (kernel<5.10), 56 bytes (5.10-5.11), 60 bytes (>=5.12)."},
	{context: "conntrack", metric: "nft_conntrack_drop_total", type:    "counter", unit: "none", labels: [], cardinality_bound: "1", help: "Total packets dropped because conntrack could not track them. Sourced from nf_conntrack_stat.drop (per-CPU sum via IPCTNL_MSG_CT_GET_STATS_CPU)."},
	{context: "conntrack", metric: "nft_conntrack_early_drop_total", type: "counter", unit: "none", labels: [], cardinality_bound: "1", help: "Total entries evicted early to make room for new connections. Sourced from nf_conntrack_stat.early_drop (per-CPU sum via IPCTNL_MSG_CT_GET_STATS_CPU)."},
	{context: "conntrack", metric: "nft_conntrack_found_total", type:   "counter", unit: "none", labels: [], cardinality_bound: "1", help: "Total successful conntrack lookups (sum found across CPUs via IPCTNL_MSG_CT_GET_STATS_CPU)."},
	{context: "conntrack", metric: "nft_conntrack_invalid_total", type: "counter", unit: "none", labels: [], cardinality_bound: "1", help: "Total packets in invalid state that could not be tracked. Sourced from nf_conntrack_stat.invalid (per-CPU sum via IPCTNL_MSG_CT_GET_STATS_CPU)."},
	{context: "conntrack", metric: "nft_conntrack_clash_resolve_total", type: "counter", unit: "none", labels: [], cardinality_bound: "1", help: "Total clash resolution events (nf_conntrack_stat.clash_resolve, kernel>=5.10; absent on older kernels — value stays 0 and no series is emitted when nf_conntrack_stat payload_len < 56)."},
	{context: "conntrack", metric: "nft_conntrack_chaintoolong_total", type: "counter", unit: "none", labels: [], cardinality_bound: "1", help: "Total hash chain too-long events (nf_conntrack_stat.chaintoolong, kernel>=5.12; absent on older kernels — value stays 0 and no series is emitted when nf_conntrack_stat payload_len < 60)."},

	// --- nftables context ---
	{context: "nftables", metric: "nft_rule_counter_bytes_total", type:    "counter", unit: "bytes", labels: ["table", "chain", "comment"], cardinality_bound: "~1000 bounded by number of rules with non-empty comment expression; anonymous rules counted in nft_scrape_collector_error_total{reason=cardinality_overflow} after exceeding 500; do NOT aggregate by (family,table,chain) as that loses the comment identity — the comment IS the bounded key", help: "Total bytes matched by nftables rules carrying a counter expression, keyed by (table, chain, comment). Only rules with a non-empty comment expression are exported; anonymous rules are suppressed per ADR-0005."},
	{context: "nftables", metric: "nft_rule_counter_packets_total", type:  "counter", unit: "packets", labels: ["table", "chain", "comment"], cardinality_bound: "~1000 bounded by number of rules with non-empty comment expression; see nft_rule_counter_bytes_total", help: "Total packets matched by nftables rules carrying a counter expression, keyed by (table, chain, comment)."},
	{context: "nftables", metric: "nft_named_counter_bytes_total", type:   "counter", unit: "bytes", labels: ["table", "name"], cardinality_bound: "~500 bounded by number of named counter objects in the ruleset", help: "Total bytes counted by a named nftables counter object (NFT_MSG_GETCOUNTER)."},
	{context: "nftables", metric: "nft_named_counter_packets_total", type: "counter", unit: "packets", labels: ["table", "name"], cardinality_bound: "~500", help: "Total packets counted by a named nftables counter object."},
	{context: "nftables", metric: "nft_set_elements", type:                "gauge", unit: "none", labels: ["table", "name", "type"], cardinality_bound: "~500 bounded by number of named sets; type is the set key type string", help: "Current number of elements in an nftables set or map. Does NOT emit per-element time series."},
	{context: "nftables", metric: "nft_chain_info", type:                  "gauge", unit: "none", labels: ["table", "chain", "type", "hook", "priority", "policy"], cardinality_bound: "~200 bounded by total chains in the ruleset; hook in (prerouting,input,forward,output,postrouting,ingress,egress); policy in (accept,drop)", help: "Metadata gauge (always 1) for each nftables chain."},
	{context: "nftables", metric: "nft_table_info", type:                  "gauge", unit: "none", labels: ["table", "family"], cardinality_bound: "~50", help: "Metadata gauge (always 1) for each nftables table. Family in (inet,ip,ip6,arp,bridge,netdev)."},

	// --- sock-diag context ---
	{context: "sock-diag", metric: "nft_socket_count", type:               "gauge", unit: "none", labels: ["protocol", "state"], cardinality_bound: "~24 |protocol|~3 (tcp,udp,udplite) x |state|~8; UDP/UDPLite emit only state=unconnected; NEVER per-socket or per-port", help: "Number of sockets in each state aggregated by (protocol, state)."},
	{context: "sock-diag", metric: "nft_socket_receive_queue_bytes", type: "gauge", unit: "bytes", labels: ["protocol", "state"], cardinality_bound: "~24", help: "Total receive queue bytes across all sockets in a given (protocol, state) bucket (idiag_rqueue sum)."},
	{context: "sock-diag", metric: "nft_socket_send_queue_bytes", type:    "gauge", unit: "bytes", labels: ["protocol", "state"], cardinality_bound: "~24", help: "Total send queue bytes across all sockets in a given (protocol, state) bucket (idiag_wqueue sum)."},
	{context: "sock-diag", metric: "nft_socket_drops_total", type:         "counter", unit: "packets", labels: ["protocol"], cardinality_bound: "~3", help: "Total packets dropped by sockets (INET_DIAG_SKMEMINFO skmem_drop), aggregated across all states per protocol."},
	{context: "sock-diag", metric: "nft_socket_retransmits_total", type:   "counter", unit: "packets", labels: ["protocol"], cardinality_bound: "~1 TCP only", help: "Total TCP retransmit count across all sockets (INET_DIAG_INFO tcpi_retransmits sum)."},

	// --- ethtool context ---
	{context: "ethtool", metric: "nft_ethtool_stat", type:                "gauge", unit: "none", labels: ["interface", "stat"], cardinality_bound: "~50000 |interfaces|~512 x |stat|~100; stat name set is fixed at driver compile time; promoted to gauge because ethtool counters reset on interface down (non-monotonic)", help: "Current value of a named ethtool NIC statistic. Use rate() for alerting, not counter delta."},
	{context: "ethtool", metric: "nft_ethtool_link_info", type:           "gauge", unit: "none", labels: ["interface", "speed", "duplex", "autoneg", "port"], cardinality_bound: "~512", help: "Metadata gauge (always 1) for ethtool link settings. speed in Mbps string; duplex in (full,half,unknown); autoneg in (on,off)."},
	{context: "ethtool", metric: "nft_ethtool_pause_rx_total", type:      "counter", unit: "packets", labels: ["interface"], cardinality_bound: "~512", help: "Total Ethernet PAUSE frames received (ETHTOOL_MSG_PAUSE_GET ETHTOOL_A_PAUSE_STAT_RX_FRAMES)."},
	{context: "ethtool", metric: "nft_ethtool_pause_tx_total", type:      "counter", unit: "packets", labels: ["interface"], cardinality_bound: "~512", help: "Total Ethernet PAUSE frames transmitted (ETHTOOL_A_PAUSE_STAT_TX_FRAMES)."},
	{context: "ethtool", metric: "nft_ethtool_fec_corrected_total", type: "counter", unit: "none", labels: ["interface", "lane"], cardinality_bound: "~2048 |interfaces|~512 x |lane|~4; only emitted when FEC is active", help: "Total FEC corrected codeword blocks per lane (ETHTOOL_MSG_FEC_GET ETHTOOL_A_FEC_STAT_CORRECTED)."},

	// --- xfrm-ipsec context ---
	{context: "xfrm-ipsec", metric: "nft_xfrm_sa_count", type: "gauge", unit: "none", labels: ["proto", "mode"], cardinality_bound: "~16 |proto|~4 (esp,ah,comp,other) x |mode|~4 (tunnel,transport,beet,other); aggregated from XFRM_MSG_GETSA dump frame count", help: "Current number of IPsec Security Associations (SAs) in the SAD, aggregated by (proto, mode). proto values: esp, ah, comp, other. mode values: tunnel, transport, beet, other. Sourced from XFRM_MSG_GETSA dump (NETLINK_XFRM family 6)."},
	{context: "xfrm-ipsec", metric: "nft_xfrm_sp_count", type: "gauge", unit: "none", labels: ["dir", "action"], cardinality_bound: "~6 |dir|~3 (in,fwd,out) x |action|~2 (allow,block); aggregated from XFRM_MSG_GETPOLICY dump frame count", help: "Current number of IPsec Security Policies (SPs) in the SPD, aggregated by (dir, action). dir values: in, fwd, out. action values: allow, block. Sourced from XFRM_MSG_GETPOLICY dump (NETLINK_XFRM family 6)."},
	{context: "xfrm-ipsec", metric: "nft_xfrm_sad_hash_count", type: "gauge", unit: "none", labels: [], cardinality_bound: "1", help: "Current number of entries in the SAD hash table (xfrm_sadinfo.sadhcnt) from XFRM_MSG_GETSADINFO. Reflects active SA hash occupancy."},
	{context: "xfrm-ipsec", metric: "nft_xfrm_sad_hash_max", type: "gauge", unit: "none", labels: [], cardinality_bound: "1", help: "SAD hash table bucket count (xfrm_sadinfo.sadhmcnt) from XFRM_MSG_GETSADINFO. Used to assess hash table utilization relative to current SA count."},
	{context: "xfrm-ipsec", metric: "nft_xfrm_spd_hash_count", type: "gauge", unit: "none", labels: [], cardinality_bound: "1", help: "Current number of entries in the SPD hash table (xfrm_spdinfo.spdhcnt) from XFRM_MSG_GETSPDINFO."},
	{context: "xfrm-ipsec", metric: "nft_xfrm_spd_hash_max", type: "gauge", unit: "none", labels: [], cardinality_bound: "1", help: "SPD hash table bucket count (xfrm_spdinfo.spdhmcnt) from XFRM_MSG_GETSPDINFO."},
	{context: "xfrm-ipsec", metric: "nft_xfrm_stat_total", type: "counter", unit: "none", labels: ["counter"], cardinality_bound: "26 exactly — fixed kernel ABI set from /proc/net/xfrm_stat; counter label values: XfrmInError XfrmInNoStates XfrmInStateProtoError XfrmInStateModeError XfrmInStateSeqError XfrmInStateExpired XfrmInStateMismatch XfrmInStateInvalid XfrmInTmplMismatch XfrmInNoPols XfrmInPolBlock XfrmInPolError XfrmOutError XfrmOutBundleGenError XfrmOutBundleCheckError XfrmOutNoStates XfrmOutStateProtoError XfrmOutStateModeError XfrmOutStateSeqError XfrmOutStateExpired XfrmOutPolBlock XfrmOutPolDead XfrmOutPolError XfrmFwdHdrError XfrmOutStateInvalid XfrmAcquireError", help: "XFRM subsystem error counters from /proc/net/xfrm_stat, partitioned by counter name. The counter label is bounded to the 26-entry kernel ABI-stable key set. Unknown keys from future kernel versions are silently ignored."},
	{context: "xfrm-ipsec", metric: "nft_scrape_collector_available", type: "gauge", unit: "none", labels: ["collector"], cardinality_bound: "~8 one series per runtime-gated collector", help: "1 if the collector's kernel subsystem is available (module loaded, startup probe succeeded); 0 if the probe returned EPROTONOSUPPORT, ENOENT, or EPERM. Shared self-telemetry metric used by all runtime-gated collectors."},

	// --- ipvs context ---
	{context: "ipvs", metric: "nft_ipvs_service_info", type: "gauge", unit: "none", labels: ["proto", "vip", "port", "sched"], cardinality_bound: "~512 bounded by ipvs_max_services config key; one series per virtual service", help: "Metadata gauge (always 1) for each IPVS virtual service. proto in (tcp,udp,sctp); vip is IPv4/IPv6 presentation form or empty for fwmark services; port is decimal string or fwmark hex string; sched is scheduler name (rr, lc, wlc, sh, ...)."},
	{context: "ipvs", metric: "nft_ipvs_connections_total", type: "counter", unit: "none", labels: ["proto", "vip", "port"], cardinality_bound: "~512", help: "Total connections handled by this virtual service (IPVS_STATS64_ATTR_CONNS). Sourced from IPVS_SVC_ATTR_STATS64 nested attribute; falls back to IPVS_SVC_ATTR_STATS on kernel < 3.15."},
	{context: "ipvs", metric: "nft_ipvs_incoming_packets_total", type: "counter", unit: "packets", labels: ["proto", "vip", "port"], cardinality_bound: "~512", help: "Total incoming packets for this virtual service (IPVS_STATS64_ATTR_INPKTS)."},
	{context: "ipvs", metric: "nft_ipvs_outgoing_packets_total", type: "counter", unit: "packets", labels: ["proto", "vip", "port"], cardinality_bound: "~512", help: "Total outgoing packets for this virtual service (IPVS_STATS64_ATTR_OUTPKTS)."},
	{context: "ipvs", metric: "nft_ipvs_incoming_bytes_total", type: "counter", unit: "bytes", labels: ["proto", "vip", "port"], cardinality_bound: "~512", help: "Total incoming bytes for this virtual service (IPVS_STATS64_ATTR_INBYTES)."},
	{context: "ipvs", metric: "nft_ipvs_outgoing_bytes_total", type: "counter", unit: "bytes", labels: ["proto", "vip", "port"], cardinality_bound: "~512", help: "Total outgoing bytes for this virtual service (IPVS_STATS64_ATTR_OUTBYTES)."},
	{context: "ipvs", metric: "nft_ipvs_connections_per_second", type: "gauge", unit: "none", labels: ["proto", "vip", "port"], cardinality_bound: "~512", help: "Exponential-moving-average connections per second for this virtual service (IPVS_STATS64_ATTR_CPS). Kernel computes this as a 1-second EMA; use delta() not rate() in alerting rules."},
	{context: "ipvs", metric: "nft_ipvs_incoming_packets_per_second", type: "gauge", unit: "packets", labels: ["proto", "vip", "port"], cardinality_bound: "~512", help: "EMA incoming packets per second for this virtual service (IPVS_STATS64_ATTR_INPPS)."},
	{context: "ipvs", metric: "nft_ipvs_outgoing_packets_per_second", type: "gauge", unit: "packets", labels: ["proto", "vip", "port"], cardinality_bound: "~512", help: "EMA outgoing packets per second for this virtual service (IPVS_STATS64_ATTR_OUTPPS)."},
	{context: "ipvs", metric: "nft_ipvs_incoming_bytes_per_second", type: "gauge", unit: "bytes", labels: ["proto", "vip", "port"], cardinality_bound: "~512", help: "EMA incoming bytes per second for this virtual service (IPVS_STATS64_ATTR_INBPS)."},
	{context: "ipvs", metric: "nft_ipvs_outgoing_bytes_per_second", type: "gauge", unit: "bytes", labels: ["proto", "vip", "port"], cardinality_bound: "~512", help: "EMA outgoing bytes per second for this virtual service (IPVS_STATS64_ATTR_OUTBPS)."},
	{context: "ipvs", metric: "nft_ipvs_dest_active_connections", type: "gauge", unit: "none", labels: ["proto", "vip", "port", "rip", "rport"], cardinality_bound: "~131072 ipvs_max_services(512) x ipvs_max_dests_per_service(256); bounded by operator LVS config", help: "Current number of active connections to this real server (IPVS_DEST_ATTR_ACTIVE_CONNS). Active connections are in data transfer; inactive are in TIME_WAIT."},
	{context: "ipvs", metric: "nft_ipvs_dest_inactive_connections", type: "gauge", unit: "none", labels: ["proto", "vip", "port", "rip", "rport"], cardinality_bound: "~131072", help: "Current number of inactive (TIME_WAIT) connections to this real server (IPVS_DEST_ATTR_INACT_CONNS)."},
	{context: "ipvs", metric: "nft_ipvs_dest_connections_total", type: "counter", unit: "none", labels: ["proto", "vip", "port", "rip", "rport"], cardinality_bound: "~131072", help: "Total connections handled by this real server (IPVS_DEST_ATTR_STATS64 IPVS_STATS64_ATTR_CONNS)."},
	{context: "ipvs", metric: "nft_ipvs_dest_incoming_bytes_total", type: "counter", unit: "bytes", labels: ["proto", "vip", "port", "rip", "rport"], cardinality_bound: "~131072", help: "Total incoming bytes handled by this real server (IPVS_DEST_ATTR_STATS64 IPVS_STATS64_ATTR_INBYTES)."},
	{context: "ipvs", metric: "nft_ipvs_dest_outgoing_bytes_total", type: "counter", unit: "bytes", labels: ["proto", "vip", "port", "rip", "rport"], cardinality_bound: "~131072", help: "Total outgoing bytes handled by this real server (IPVS_DEST_ATTR_STATS64 IPVS_STATS64_ATTR_OUTBYTES)."},
	{context: "ipvs", metric: "nft_ipvs_connection_table_size", type: "gauge", unit: "none", labels: [], cardinality_bound: "1", help: "IPVS connection table capacity reported by IPVS_CMD_GET_INFO (IPVS_INFO_ATTR_CONN_TAB_SIZE). This is the maximum simultaneous tracked connections, not the current count."},

	// --- wireguard context ---
	{context: "wireguard", metric: "nft_wireguard_device_info", type: "gauge", unit: "none", labels: ["interface", "listen_port", "fwmark"], cardinality_bound: "~16 one per WireGuard interface; bounded by network interface count", help: "Metadata gauge (always 1) for each WireGuard device. listen_port is the UDP listen port stringified; 0 when not bound. fwmark is the firewall mark stringified; 0 when not set. Source: WGDEVICE_A_LISTEN_PORT u16 LE, WGDEVICE_A_FWMARK u32 LE."},
	{context: "wireguard", metric: "nft_wireguard_peer_receive_bytes_total", type: "counter", unit: "bytes", labels: ["interface", "peer"], cardinality_bound: "~1000 bounded by ExporterConfig.wireguard_max_peers default 1000; peer label is 16-char hex hash of public key or operator name (ADR-0018)", help: "Cumulative bytes received from a WireGuard peer since interface creation. Source: WGPEER_A_RX_BYTES u64 native-endian. Peer identity label is SHA-256(public_key)[0..8] hex or configured wireguard_peer_names value."},
	{context: "wireguard", metric: "nft_wireguard_peer_transmit_bytes_total", type: "counter", unit: "bytes", labels: ["interface", "peer"], cardinality_bound: "~1000 same bound as nft_wireguard_peer_receive_bytes_total", help: "Cumulative bytes transmitted to a WireGuard peer since interface creation. Source: WGPEER_A_TX_BYTES u64 native-endian."},
	{context: "wireguard", metric: "nft_wireguard_peer_last_handshake_seconds", type: "gauge", unit: "seconds", labels: ["interface", "peer"], cardinality_bound: "~1000", help: "Seconds elapsed since the last completed WireGuard Noise handshake with this peer (now - WGPEER_A_LAST_HANDSHAKE_TIME.tv_sec). Value is +Inf when the peer has never completed a handshake (tv_sec=0). Alert when > 180 seconds (WireGuard re-initiates after 3 minutes of silence by default)."},
	{context: "wireguard", metric: "nft_wireguard_peer_persistent_keepalive_seconds", type: "gauge", unit: "seconds", labels: ["interface", "peer"], cardinality_bound: "~1000", help: "Configured persistent keepalive interval in seconds for this peer. Source: WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL u16 LE. Value 0 means keepalive is disabled."},
	{context: "wireguard", metric: "nft_wireguard_peer_endpoint_present", type: "gauge", unit: "none", labels: ["interface", "peer"], cardinality_bound: "~1000", help: "1 when WGPEER_A_ENDPOINT is present in the kernel response (peer has a known UDP endpoint address); 0 when absent (peer not yet reachable or roaming-unresolved). The endpoint address itself is never stored or emitted as a label."},

	// --- devlink context ---
	{context: "devlink", metric: "nft_devlink_device_info", type: "gauge", unit: "none", labels: ["bus_name", "dev_name"], cardinality_bound: "~8 bounded by hardware device count per node; typically 1-4 devlink devices", help: "Metadata gauge (always 1) for each devlink device visible via DEVLINK_CMD_GET. Absent when nft_scrape_collector_available{collector=\"devlink\"}=0."},
	{context: "devlink", metric: "nft_devlink_port_info", type: "gauge", unit: "none", labels: ["bus_name", "dev_name", "port"], cardinality_bound: "~64 bounded by hardware port count; port label is stringified DEVLINK_ATTR_PORT_INDEX u32", help: "Metadata gauge (always 1) for each devlink port from DEVLINK_CMD_PORT_GET. port label is the decimal port_index string."},
	{context: "devlink", metric: "nft_devlink_health_reporter_error_total", type: "counter", unit: "none", labels: ["bus_name", "dev_name", "reporter"], cardinality_bound: "~64 bounded by (devices ~4) x (reporters per device ~8); reporter names are driver-defined strings e.g. fw_fatal rx tx", help: "Cumulative number of health reporter error events since device initialisation (DEVLINK_ATTR_HEALTH_REPORTER_ERR_COUNT u64 LE via DEVLINK_CMD_HEALTH_REPORTER_GET)."},
	{context: "devlink", metric: "nft_devlink_health_reporter_recover_total", type: "counter", unit: "none", labels: ["bus_name", "dev_name", "reporter"], cardinality_bound: "~64 same bound as nft_devlink_health_reporter_error_total", help: "Cumulative number of health reporter recovery events since device initialisation (DEVLINK_ATTR_HEALTH_REPORTER_RECOVER_COUNT u64 LE via DEVLINK_CMD_HEALTH_REPORTER_GET)."},
	{context: "devlink", metric: "nft_devlink_health_reporter_state", type: "gauge", unit: "none", labels: ["bus_name", "dev_name", "reporter", "state"], cardinality_bound: "~448 bounded by ~64 reporters x 7 state values; state in (healthy,error,auto_recover,dumping,corrective_action,unavailable,unknown); always 1 for the current state", help: "Current health state of a devlink reporter (DEVLINK_ATTR_HEALTH_REPORTER_STATE u8). Emitted as value 1 with the current state in the state label; unknown future kernel state values map to state=unknown."},

	// --- drop-monitor context ---
	{context: "drop-monitor", metric: "nft_drop_packets_total", type: "counter", unit: "packets", labels: ["reason", "origin"], cardinality_bound: "~220 worst case: |reason|~80 sw + ~30 hw trap names x |origin|~2 (sw,hw); bounded by kernel drop-reason enum in include/net/dropreason.h; not per-flow, not per-address", help: "Total packets dropped, aggregated by drop reason and origin. Software drops: reason=NET_DM_ATTR_REASON string (kernel >= 5.17), origin=sw. Hardware drops: reason=NET_DM_ATTR_HW_TRAP_NAME, origin=hw. Sourced from NET_DM_ATTR_STATS / NET_DM_ATTR_STATS_DROPPED u64 native-endian. Zero-drop intervals emit no series. Requires drop_monitor module loaded and NET_DM_CMD_MONITOR_START issued in summary mode."},

	// --- rtnetlink-extended context ---
	{context: "rtnetlink-extended", metric: "nft_link_xstats_bridge_rx_multicast_bytes_total", type: "counter", unit: "bytes", labels: ["interface"], cardinality_bound: "~512 one series per bridge interface; no per-group or per-VLAN expansion", help: "Total multicast bytes received on a bridge interface (RTM_NEWSTATS IFLA_STATS_LINK_XSTATS BRIDGE_XSTATS_MCAST rx_bytes). Absent when RTM_GETSTATS returns EINVAL (kernel < 4.20)."},
	{context: "rtnetlink-extended", metric: "nft_link_xstats_bridge_tx_multicast_bytes_total", type: "counter", unit: "bytes", labels: ["interface"], cardinality_bound: "~512", help: "Total multicast bytes transmitted on a bridge interface (RTM_NEWSTATS IFLA_STATS_LINK_XSTATS BRIDGE_XSTATS_MCAST tx_bytes). Absent when RTM_GETSTATS returns EINVAL (kernel < 4.20)."},
	{context: "rtnetlink-extended", metric: "nft_link_xstats_offload_rx_bytes_total", type: "counter", unit: "bytes", labels: ["interface"], cardinality_bound: "~512 one series per interface with hardware-offload xstats; absent for interfaces without switchdev/tc-offload support", help: "Total bytes received via hardware offload path (RTM_NEWSTATS IFLA_STATS_LINK_OFFLOAD_XSTATS rtnl_hw_stats64.rx_bytes). Emitted only when the attribute is present in the RTM_NEWSTATS reply for this interface."},
	{context: "rtnetlink-extended", metric: "nft_link_xstats_offload_tx_bytes_total", type: "counter", unit: "bytes", labels: ["interface"], cardinality_bound: "~512", help: "Total bytes transmitted via hardware offload path (RTM_NEWSTATS IFLA_STATS_LINK_OFFLOAD_XSTATS rtnl_hw_stats64.tx_bytes). Emitted only when the attribute is present in the RTM_NEWSTATS reply."},
	{context: "rtnetlink-extended", metric: "nft_bridge_fdb_entries", type: "gauge", unit: "none", labels: ["interface"], cardinality_bound: "~32 one series per bridge device; NEVER per-MAC or per-VLAN; probe host ground truth: 150 entries on br0", help: "Total number of bridge forwarding-database entries on a bridge device (RTM_GETNEIGH AF_BRIDGE entry count per ndm_ifindex). MAC addresses are discarded at parse time (ADR-0005). Absent when RTM_GETSTATS availability probe fails."},
	{context: "rtnetlink-extended", metric: "nft_fib_rules", type: "gauge", unit: "none", labels: ["family"], cardinality_bound: "~3 one series per address family (inet, inet6, mpls); NEVER per-rule or per-prefix", help: "Count of installed fib policy-routing rules per address family (RTM_GETRULE). family label values: inet (AF_INET), inet6 (AF_INET6), mpls (AF_MPLS; emits 0 when EINVAL on kernel < 4.3)."},
	{context: "rtnetlink-extended", metric: "nft_nexthop_objects", type: "gauge", unit: "none", labels: [], cardinality_bound: "1 single scalar total count of all nexthop objects; NEVER per-nexthop or per-group", help: "Total number of installed nexthop objects (RTM_GETNEXTHOP entry count, kernel >= 5.3). Emits 0 when RTM_GETNEXTHOP returns EINVAL on kernels < 5.3 without incrementing error counters. Bounded by operator-controlled routing configuration."},

	// --- conntrack-expectations context (conntrack bounded context) ---
	{context: "conntrack", metric: "nft_conntrack_expectation_entries", type: "gauge", unit: "none", labels: ["l4proto", "helper"], cardinality_bound: "~160 |l4proto|~8 x |helper|~20; helper is NUL-stripped CTA_EXPECT_HELPER_NAME (ftp, tftp, sip, h323, pptp, irc, amanda, netbios_ns, snmp, broadcast, etc.); empty string when attribute absent; truncated to 64 bytes", help: "Current number of active conntrack expectations aggregated by (l4proto, helper). Sourced from IPCTNL_MSG_EXP_GET dump (NFNL_SUBSYS_CTNETLINK_EXP=2, nlmsg_type=0x0200). Zero series emitted when subsystem is unavailable (nft_scrape_collector_available=0). Per-expectation IP, port, and ID labels are strictly forbidden per ADR-0005."},
	{context: "conntrack", metric: "nft_conntrack_expectation_new_total", type: "counter", unit: "none", labels: [], cardinality_bound: "1", help: "Total conntrack expectations created across all CPUs. Sourced from nf_ct_exp_stat.new field (offset 0, u32 native-endian) summed across all IPCTNL_MSG_EXP_GET_STATS_CPU reply frames (nlmsg_type=0x0203). Zero when subsystem unavailable."},
	{context: "conntrack", metric: "nft_conntrack_expectation_delete_total", type: "counter", unit: "none", labels: [], cardinality_bound: "1", help: "Total conntrack expectations deleted across all CPUs. Sourced from nf_ct_exp_stat.delete field (offset 4, u32 native-endian) summed via IPCTNL_MSG_EXP_GET_STATS_CPU. Zero when subsystem unavailable."},
	{context: "conntrack", metric: "nft_conntrack_expectation_new_failed_total", type: "counter", unit: "none", labels: [], cardinality_bound: "1", help: "Total conntrack expectation allocation failures across all CPUs. Sourced from nf_ct_exp_stat.new_failed field (offset 8, u32 native-endian) summed via IPCTNL_MSG_EXP_GET_STATS_CPU. Zero when subsystem unavailable."},
]

// ---------------------------------------------------------------------------
// Self-telemetry metric contract
// ---------------------------------------------------------------------------

// #SelfMetricsContract is the authoritative list of exporter self-telemetry
// metric families (nft_scrape_*, nft_up, nft_build_info, nft_netlink_*).
#SelfMetricsContract: [...#SelfMetricDescriptor]

self_metrics: #SelfMetricsContract & [
	{name: "nft_scrape_duration_seconds", type:          "gauge", labels: [], help: "Total wall-clock duration of the most recent full scrape across all collectors, in seconds."},
	{name: "nft_scrape_collector_duration_seconds", type: "gauge", labels: ["collector"], help: "Duration in seconds of the most recent scrape for each collector. Values: rtnetlink, traffic_control, conntrack, nftables, sock_diag, ethtool."},
	{name: "nft_scrape_collector_success", type:          "gauge", labels: ["collector"], help: "1 if the last scrape for this collector succeeded, 0 if it failed (netlink error, timeout, permission denied, or panic)."},
	{name: "nft_scrape_collector_error_total", type:      "counter", labels: ["collector", "reason"], help: "Total errors during collection partitioned by collector and reason. reason values: netlink_timeout, netlink_permission_denied, netlink_truncated, cardinality_overflow, parse_error, kernel_unsupported, panic, dump_intr (NLM_F_DUMP_INTR cap exceeded after 8 restarts; stale snapshot activated), genl_family_unresolved (CTRL_CMD_GETFAMILY returned ENOENT; ethtool genetlink family not registered on this kernel)."},
	{name: "nft_up", type:                               "gauge", labels: [], help: "1 if all critical collectors (rtnetlink, conntrack, nftables) succeeded on the most recent scrape; 0 otherwise. Primary health signal for alerting."},
	{name: "nft_build_info", type:                        "gauge", labels: ["version", "revision", "rust_version", "build_date"], help: "Metadata gauge (always 1) carrying build metadata. Enables version tracking and alert routing."},
	{name: "nft_netlink_socket_count", type:              "gauge", labels: ["family"], help: "Number of open netlink sockets, partitioned by family (NETLINK_ROUTE, NETLINK_NETFILTER, NETLINK_SOCK_DIAG, NETLINK_GENERIC). NETLINK_NETFILTER is used for both ctnetlink (conntrack) and nfnetlink (nftables) subsystems after rustables removal. NETLINK_GENERIC is used for ethtool family resolution and stats only (one socket per adapter instance, not per subsystem). Diagnoses socket leaks."},
	{name: "nft_netlink_errors_total", type:              "counter", labels: ["family", "errno"], help: "Total netlink error responses per family and errno string (EPERM, ENOENT, ENOBUFS, ENOMEM, EAGAIN). Diagnoses permission or buffer issues."},
	{name: "nft_exporter_snapshot_age_seconds", type:     "gauge", labels: ["collector"], help: "Seconds since the last successful ReadModel snapshot for each collector. Alert when age exceeds two scrape intervals to detect stale-snapshot fallback activation."},
]
