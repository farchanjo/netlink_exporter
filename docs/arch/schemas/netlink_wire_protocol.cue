// DDD role: ValueObject
package schemas

// ---------------------------------------------------------------------------
// NETLINK_SOCK_DIAG wire-protocol value objects (ADR-0014)
// ---------------------------------------------------------------------------

// #SockDiagFamily enumerates the AF_* constants valid in sdiag_family.
#SockDiagFamily: 2 | 10 // AF_INET=2, AF_INET6=10

// #SockDiagProtocol enumerates sdiag_protocol constants.
// IPPROTO_TCP=6, IPPROTO_UDP=17, IPPROTO_UDPLITE=136.
#SockDiagProtocol: 6 | 17 | 136

// #InetDiagExt is a bitmask describing which optional attributes the kernel
// should append after struct inet_diag_msg. The two bits used by nft_exporter:
//   bit 1 (value 2)  = INET_DIAG_INFO      (struct tcp_info, retransmit data)
//   bit 5 (value 32) = INET_DIAG_SKMEMINFO (9 x u32, skmem_drop at index 8)
// Combined value: 0x22 (INET_DIAG_INFO | INET_DIAG_SKMEMINFO).
#InetDiagExt: uint8

// #InetDiagReqV2 models the request payload for SOCK_DIAG_BY_FAMILY.
// Wire size: 56 bytes (nlmsghdr adds 20 bytes for total of 76).
#InetDiagReqV2: {
	// sdiag_family selects the address family for the dump.
	sdiag_family: #SockDiagFamily

	// sdiag_protocol selects the IP protocol.
	sdiag_protocol: #SockDiagProtocol

	// idiag_ext is the bitmask of optional response attributes.
	// Set to 0x22 for retransmit + skmem_drop data.
	idiag_ext: #InetDiagExt

	// idiag_states is the bitmask of TCP_* state bits to include.
	// 0xffffffff requests all states.
	idiag_states: uint32

	// id is the inet_diag_sockid filter; zero-valued means no filter (full dump).
	id_zero: bool // true when all id fields are zero (full dump)
}

// #InetDiagMsgField documents the fixed fields of struct inet_diag_msg.
// Byte offsets are from the start of the struct payload (after nlmsghdr).
#InetDiagMsgField: {
	// name is the C struct field name.
	name: string & !=""

	// offset_bytes is the byte offset of the field within the struct.
	offset_bytes: uint8

	// size_bytes is the field width.
	size_bytes: 1 | 2 | 4 | 8 | 48

	// note is an implementation note for the adapter.
	note: string
}

// inet_diag_msg_layout is the normative field layout of struct inet_diag_msg.
// Total struct size: 72 bytes.
inet_diag_msg_layout: [...#InetDiagMsgField] & [
	{name: "idiag_family", offset_bytes: 0, size_bytes: 1, note: "AF_INET or AF_INET6; same as request sdiag_family"},
	{name: "idiag_state", offset_bytes: 1, size_bytes: 1, note: "TCP_* state constant mapped to SocketState label string; see tcp_state_map"},
	{name: "idiag_timer", offset_bytes: 2, size_bytes: 1, note: "retransmit timer type; not used for metrics"},
	{name: "idiag_retrans", offset_bytes: 3, size_bytes: 1, note: "number of retransmissions in current timer; not used for metrics (use INET_DIAG_INFO tcpi_retransmits instead)"},
	{name: "id (inet_diag_sockid)", offset_bytes: 4, size_bytes: 48, note: "local/remote port+addr+cookie; NEVER stored or emitted as a label"},
	{name: "idiag_expires", offset_bytes: 52, size_bytes: 4, note: "expiry time in jiffies; not used"},
	{name: "idiag_rqueue", offset_bytes: 56, size_bytes: 4, note: "receive queue occupancy in bytes; accumulated into recv_queue_bytes per (protocol, state) bucket"},
	{name: "idiag_wqueue", offset_bytes: 60, size_bytes: 4, note: "send queue occupancy in bytes; accumulated into send_queue_bytes per (protocol, state) bucket"},
	{name: "idiag_uid", offset_bytes: 64, size_bytes: 4, note: "socket owner UID; not used for metrics"},
	{name: "idiag_inode", offset_bytes: 68, size_bytes: 4, note: "socket inode number; FORBIDDEN as a Prometheus label (ADR-0005)"},
]

// #TcpStateEntry maps an idiag_state integer to its Prometheus label string.
#TcpStateEntry: {
	// kernel_value is the TCP_* constant value (1–12).
	kernel_value: uint8 & >=1 & <=12

	// kernel_name is the C constant name.
	kernel_name: string & !=""

	// label_string is the value used in the "state" Prometheus label.
	label_string: #SocketState
}

// tcp_state_map is the normative TCP state integer-to-label mapping.
tcp_state_map: [...#TcpStateEntry] & [
	{kernel_value: 1,  kernel_name: "TCP_ESTABLISHED",  label_string: "established"},
	{kernel_value: 2,  kernel_name: "TCP_SYN_SENT",     label_string: "syn_sent"},
	{kernel_value: 3,  kernel_name: "TCP_SYN_RECV",     label_string: "syn_recv"},
	{kernel_value: 4,  kernel_name: "TCP_FIN_WAIT1",    label_string: "fin_wait1"},
	{kernel_value: 5,  kernel_name: "TCP_FIN_WAIT2",    label_string: "fin_wait2"},
	{kernel_value: 6,  kernel_name: "TCP_TIME_WAIT",    label_string: "time_wait"},
	{kernel_value: 7,  kernel_name: "TCP_CLOSE",        label_string: "close"},
	{kernel_value: 8,  kernel_name: "TCP_CLOSE_WAIT",   label_string: "close_wait"},
	{kernel_value: 9,  kernel_name: "TCP_LAST_ACK",     label_string: "last_ack"},
	{kernel_value: 10, kernel_name: "TCP_LISTEN",       label_string: "listen"},
	{kernel_value: 11, kernel_name: "TCP_CLOSING",      label_string: "closing"},
	{kernel_value: 12, kernel_name: "TCP_NEW_SYN_RECV", label_string: "new_syn_recv"},
]

// #UdpStateRule documents that UDP/UDPLite always report idiag_state=7 (TCP_CLOSE)
// which must be mapped to "unconnected" to avoid confusion with TCP CLOSE semantics.
#UdpStateRule: {
	sdiag_protocol:   17 | 136 // IPPROTO_UDP or IPPROTO_UDPLITE
	kernel_state:     7        // TCP_CLOSE constant
	mapped_label:     "unconnected"
	rationale:        "The kernel repurposes TCP_CLOSE (7) to mean unconnected for UDP; mapping prevents metric consumers from confusing this with TCP socket teardown."
}

// #SkmemDropLayout documents the layout of INET_DIAG_SKMEMINFO (nla_type=6).
// The attribute payload is 9 consecutive u32 values in little-endian byte order.
#SkmemDropLayout: {
	nla_type:       6
	constant_name:  "INET_DIAG_SKMEMINFO"
	fields: [...{index: uint8, name: string, note: string}] & [
		{index: 0, name: "sk_rmem_alloc",  note: "allocated receive memory"},
		{index: 1, name: "sk_rcvbuf",      note: "receive buffer size"},
		{index: 2, name: "sk_wmem_alloc",  note: "allocated send memory"},
		{index: 3, name: "sk_sndbuf",      note: "send buffer size"},
		{index: 4, name: "sk_fwd_alloc",   note: "forward-allocated memory"},
		{index: 5, name: "sk_wmem_queued", note: "queued send memory"},
		{index: 6, name: "sk_optmem",      note: "option memory"},
		{index: 7, name: "sk_backlog",     note: "socket backlog"},
		{index: 8, name: "skmem_drop",     note: "METRIC: accumulated into nft_socket_drops_total per protocol; byte offset 32 from attribute payload start"},
	]
}

// ---------------------------------------------------------------------------
// NETLINK_ROUTE TC wire-protocol value objects (ADR-0014)
// ---------------------------------------------------------------------------

// #TcMsgField documents the fixed fields of struct tcmsg.
// Total struct size: 20 bytes.
#TcMsgField: {
	name:         string & !=""
	offset_bytes: uint8
	size_bytes:   1 | 2 | 4
	note:         string
}

// tcmsg_layout is the normative field layout of struct tcmsg.
tcmsg_layout: [...#TcMsgField] & [
	{name: "tcm_family",  offset_bytes: 0,  size_bytes: 1, note: "AF_UNSPEC (0) for global dump"},
	{name: "tcm__pad1",   offset_bytes: 1,  size_bytes: 1, note: "padding; set to 0"},
	{name: "tcm__pad2",   offset_bytes: 2,  size_bytes: 2, note: "padding; set to 0"},
	{name: "tcm_ifindex", offset_bytes: 4,  size_bytes: 4, note: "interface index; 0 for all interfaces; maps to 'interface' label via if_indextoname"},
	{name: "tcm_handle",  offset_bytes: 8,  size_bytes: 4, note: "qdisc handle u32: major=(v>>16) as u16, minor=(v&0xFFFF) as u16; display as 'major:minor' lowercase hex"},
	{name: "tcm_parent",  offset_bytes: 12, size_bytes: 4, note: "parent handle; TC_H_ROOT=0xFFFFFFFF displays as 'ffff:ffff'; TC_H_INGRESS=0xFFFFFFF1 displays as 'ffff:fff1'"},
	{name: "tcm_info",    offset_bytes: 16, size_bytes: 4, note: "0 for qdiscs; not used for metrics"},
]

// #TcAttrId documents the TCA_* netlink attribute types relevant to stats.
#TcAttrId: {
	nla_type:      uint16
	constant_name: string & !=""
	payload_type:  string & !=""
	note:          string
}

// tc_attr_ids is the normative list of TCA_* attribute IDs parsed by TcNetlinkAdapter.
tc_attr_ids: [...#TcAttrId] & [
	{nla_type: 1, constant_name: "TCA_KIND",    payload_type: "NUL-terminated ASCII string", note: "qdisc kind e.g. 'htb', 'noqueue', 'ingress'; mapped to 'kind' Prometheus label"},
	{nla_type: 2, constant_name: "TCA_OPTIONS", payload_type: "qdisc-specific blob",          note: "not decoded for metrics"},
	{nla_type: 7, constant_name: "TCA_STATS2",  payload_type: "nested nlattr chain",          note: "container for TCA_STATS_BASIC and TCA_STATS_QUEUE sub-attributes"},
]

// #TcStats2SubAttrId documents the sub-attribute IDs inside TCA_STATS2.
#TcStats2SubAttrId: {
	nla_type:      uint16
	constant_name: string & !=""
	struct_name:   string & !=""
	size_bytes:    uint8
	note:          string
}

// tca_stats2_sub_attrs is the normative list of sub-attribute IDs inside TCA_STATS2.
tca_stats2_sub_attrs: [...#TcStats2SubAttrId] & [
	{nla_type: 1, constant_name: "TCA_STATS_BASIC", struct_name: "gnet_stats_basic", size_bytes: 12, note: "minimum 12 bytes; may be padded to 16 on some kernels; use nla_len for bounds"},
	{nla_type: 3, constant_name: "TCA_STATS_QUEUE", struct_name: "gnet_stats_queue", size_bytes: 20, note: "exactly 20 bytes; all fields u32 little-endian"},
]

// #GnetStatsBasicLayout documents the byte layout of struct gnet_stats_basic.
#GnetStatsBasicLayout: {
	struct_name: "gnet_stats_basic"
	header_path: "uapi/linux/gen_stats.h"
	endianness:  "little-endian"
	fields: [...{offset_bytes: uint8, size_bytes: 4 | 8, name: string, rust_type: string, metric: string | "none"}] & [
		{offset_bytes: 0, size_bytes: 8, name: "bytes",   rust_type: "u64", metric: "nft_tc_qdisc_bytes_total (counter)"},
		{offset_bytes: 8, size_bytes: 4, name: "packets", rust_type: "u32", metric: "nft_tc_qdisc_packets_total (counter)"},
	]
}

// #GnetStatsQueueLayout documents the byte layout of struct gnet_stats_queue.
#GnetStatsQueueLayout: {
	struct_name: "gnet_stats_queue"
	header_path: "uapi/linux/gen_stats.h"
	endianness:  "little-endian"
	fields: [...{offset_bytes: uint8, size_bytes: 4, name: string, rust_type: string, metric: string}] & [
		{offset_bytes: 0,  size_bytes: 4, name: "qlen",       rust_type: "u32", metric: "not emitted; informational only"},
		{offset_bytes: 4,  size_bytes: 4, name: "backlog",    rust_type: "u32", metric: "nft_tc_qdisc_backlog_bytes (gauge, instantaneous bytes in queue)"},
		{offset_bytes: 8,  size_bytes: 4, name: "drops",      rust_type: "u32", metric: "nft_tc_qdisc_drops_total (counter)"},
		{offset_bytes: 12, size_bytes: 4, name: "requeues",   rust_type: "u32", metric: "not emitted; informational only"},
		{offset_bytes: 16, size_bytes: 4, name: "overlimits", rust_type: "u32", metric: "nft_tc_qdisc_overlimits_total (counter)"},
	]
}

// #TcHandleConstant documents the special TC handle sentinel values.
#TcHandleConstant: {
	constant_name: string & !=""
	u32_value:     uint32
	major:         uint16
	minor:         uint16
	display:       =~"^[0-9a-f]+:[0-9a-f]+$"
	meaning:       string
}

// tc_handle_constants is the normative list of TC sentinel handle values.
tc_handle_constants: [...#TcHandleConstant] & [
	{constant_name: "TC_H_ROOT",    u32_value: 0xFFFFFFFF, major: 0xFFFF, minor: 0xFFFF, display: "ffff:ffff", meaning: "root qdisc parent sentinel; reported in tcm_parent for root qdiscs"},
	{constant_name: "TC_H_INGRESS", u32_value: 0xFFFFFFF1, major: 0xFFFF, minor: 0xFFF1, display: "ffff:fff1", meaning: "ingress qdisc parent sentinel; reported in tcm_parent for ingress qdiscs"},
	{constant_name: "TC_H_UNSPEC",  u32_value: 0x00000000, major: 0x0000, minor: 0x0000, display: "0:0",       meaning: "unspecified; default handle for noqueue qdisc"},
]

// ---------------------------------------------------------------------------
// Probe ground-truth validation (ADR-0014 §1.7 and §2.8)
// ---------------------------------------------------------------------------

// #ProbeSocketExpectation encodes a concrete metric value from the real probe.
#ProbeSocketExpectation: {
	metric:   #MetricName
	protocol: #SockProtocol
	state:    #SocketState
	// value is the exact expected count; "at_least_N" expressed as uint64 lower bound.
	min_value: uint64
	max_value: uint64 | *18446744073709551615 // u64::MAX = unbounded upper
}

// probe_socket_expectations is the authoritative probe-grounded list of
// metric bounds that integration tests must assert. Probe date: 2026-05-28.
probe_socket_expectations: [...#ProbeSocketExpectation] & [
	{metric: "nft_socket_count", protocol: "tcp", state: "listen",      min_value: 53,  max_value: 53},
	{metric: "nft_socket_count", protocol: "tcp", state: "established", min_value: 1,   max_value: 1},
	// TCP total across all states must equal 574.
	// Remainder (574 - 53 - 1 = 520) distributed across close/time_wait/etc.
	// Not pinned here because transient states vary; total is asserted in tests.
]

// #ProbeTcExpectation encodes a concrete qdisc observation from the real probe.
#ProbeTcExpectation: {
	interface: string & !=""
	handle:    =~"^[0-9a-f]+:[0-9a-f]+$"
	parent:    =~"^[0-9a-f]+:[0-9a-f]+$"
	kind:      string & !=""
	// stats_present indicates whether TCA_STATS2 is expected in the response.
	stats_present: bool
}

// probe_tc_expectations is the authoritative probe-grounded list of
// qdisc observations. Probe date: 2026-05-28.
probe_tc_expectations: [...#ProbeTcExpectation] & [
	{interface: "eth0", handle: "0:0", parent: "ffff:ffff", kind: "noqueue", stats_present: false},
]
