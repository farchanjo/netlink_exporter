// DDD role: ValueObject
package schemas

// ---------------------------------------------------------------------------
// ctnetlink wire-protocol value objects
// Grounded in: linux/netfilter/nfnetlink.h
//              linux/netfilter/nfnetlink_conntrack.h
//              linux/netfilter/nf_conntrack_common.h
// Used by ConntrackAdapter (nft_exporter_adapter_ct) only.
// NEVER crosses the port boundary into domain-core as raw bytes.
// ---------------------------------------------------------------------------

// #NfnlSubsys enumerates the NFNL_SUBSYS_* constants embedded in nlmsg_type.
// NFNL_SUBSYS_CTNETLINK = 1.
#NfnlSubsys: 1

// #CtMsgType enumerates the IPCTNL_MSG_CT_* constants for the lower byte of
// nlmsg_type.  nlmsg_type = (NFNL_SUBSYS_CTNETLINK << 8) | #CtMsgType.
#CtMsgType:
	1 | // IPCTNL_MSG_CT_GET   — dump or single-entry get
	5 | // IPCTNL_MSG_CT_GET_STATS_CPU — per-CPU stats (preferred for counters)
	6   // IPCTNL_MSG_CT_GET_STATS    — global entry count

// #CtMsgTypeEncoded lists the full 16-bit nlmsg_type values (host byte order).
#CtMsgTypeEncoded: {
	ct_get:           0x0101
	ct_get_stats_cpu: 0x0105
	ct_get_stats:     0x0106
}

// #NfGenFamily enumerates the nfgen_family values placed in nfgenmsg.nfgen_family.
// AF_UNSPEC is used for stats requests; AF_INET and AF_INET6 are used for dumps.
#NfGenFamily:
	0 |  // AF_UNSPEC — used for CT_GET_STATS_CPU and CT_GET_STATS requests
	2 |  // AF_INET
	10   // AF_INET6

// #NfgenmsgVersion is the fixed value of nfgenmsg.version.
// NFNETLINK_V0 = 0.
#NfgenmsgVersion: 0

// #NfgenmsgWire is the 4-byte nfgenmsg header that follows nlmsghdr in every
// NETLINK_NETFILTER message.
//
// CRITICAL endianness: res_id is __be16 (big-endian) in the kernel UAPI.
// For outbound requests set res_id_be = [0x00, 0x00].
// For CT_GET_STATS_CPU replies res_id_be carries the CPU index (0-based)
// encoded big-endian: cpu_index = u16::from_be_bytes(res_id_be).
#NfgenmsgWire: {
	// nfgen_family is one of #NfGenFamily.
	nfgen_family: #NfGenFamily

	// version is always NFNETLINK_V0 = 0.
	version: #NfgenmsgVersion & 0

	// res_id_be is the raw big-endian bytes of the res_id field.
	// Decode with: u16::from_be_bytes(res_id_be).
	res_id_be: bytes & {
		len(res_id_be) == 2
	}
}

// ---------------------------------------------------------------------------
// Request descriptors: minimum request wire layouts (no attributes)
// ---------------------------------------------------------------------------

// #CtStatsRequest describes a CT_GET_STATS_CPU or CT_GET_STATS request.
// The wire message is exactly 20 bytes: nlmsghdr (16) + nfgenmsg (4).
// No nlattr payload is required.
#CtStatsRequest: {
	// nlmsg_type must be ct_get_stats_cpu (0x0105) or ct_get_stats (0x0106).
	nlmsg_type: #CtMsgTypeEncoded.ct_get_stats_cpu | #CtMsgTypeEncoded.ct_get_stats

	// nlmsg_flags = NLM_F_REQUEST = 0x0001.
	nlmsg_flags: 0x0001

	// nfgenmsg follows nlmsghdr immediately.
	nfgenmsg: #NfgenmsgWire & {
		nfgen_family: 0 // AF_UNSPEC
	}

	// total_bytes is the wire size: nlmsghdr(16) + nfgenmsg(4) = 20.
	total_bytes: 20
}

// #CtDumpRequest describes a CT_GET dump request (NLM_F_REQUEST | NLM_F_DUMP).
#CtDumpRequest: {
	// nlmsg_type = IPCTNL_MSG_CT_GET = 0x0101.
	nlmsg_type: #CtMsgTypeEncoded.ct_get

	// nlmsg_flags = NLM_F_REQUEST(0x0001) | NLM_F_DUMP(0x0300) = 0x0301.
	nlmsg_flags: 0x0301

	nfgenmsg: #NfgenmsgWire & {
		// AF_INET or AF_INET6; kernel returns entries for both when AF_UNSPEC
		// is used on kernels >= 3.19.  Use AF_UNSPEC (0) for broadest compat.
		nfgen_family: 0 | 2 | 10
	}

	total_bytes: 20
}

// ---------------------------------------------------------------------------
// nf_conntrack_stat: per-CPU reply payload for CT_GET_STATS_CPU
// All fields are native-endian u32.
// Struct size varies by kernel version:
//   52 bytes (13 fields) — kernel < 5.10
//   56 bytes (14 fields) — kernel 5.10–5.11  (adds clash_resolve)
//   60 bytes (15 fields) — kernel >= 5.12    (adds chaintoolong)
// Parse only fields within nlmsg_payload_len; treat absent trailing fields as 0.
// ---------------------------------------------------------------------------

// #NfConntrackStat describes the parsed per-CPU stat payload.
// Each field is a uint32 summed across all CPUs to produce ConntrackGlobalStats.
#NfConntrackStat: {
	// searched: obsolete on kernel >= 5.15; always 0.
	searched: uint32

	// found: number of successful conntrack lookups on this CPU.
	found: uint32

	// new: number of new connections created on this CPU.
	new: uint32

	// invalid: number of packets received in invalid state on this CPU.
	invalid: uint32

	// ignore: obsolete on kernel >= 5.15; always 0.
	ignore: uint32

	// delete: obsolete.
	delete: uint32

	// delete_list: obsolete.
	delete_list: uint32

	// insert: number of conntrack entries inserted on this CPU.
	insert: uint32

	// insert_failed: number of failed insertions (duplicate, table full) on this CPU.
	insert_failed: uint32

	// drop: packets dropped because conntrack could not track them on this CPU.
	drop: uint32

	// early_drop: entries evicted to make room for new flows on this CPU.
	early_drop: uint32

	// error: miscellaneous errors on this CPU.
	error: uint32

	// search_restart: number of lookup restarts (e.g., due to lockless race) on this CPU.
	search_restart: uint32

	// clash_resolve: number of clash resolutions on this CPU (kernel >= 5.10; may be absent).
	clash_resolve: uint32

	// chaintoolong: number of hash chain too-long events on this CPU (kernel >= 5.12; may be absent).
	chaintoolong: uint32
}

// #NfConntrackStatSum is the per-CPU stat summed across all CPUs.
// This is what ConntrackAdapter produces after consuming all CT_GET_STATS_CPU replies.
// Only the fields present in ConntrackGlobalStats are tracked here;
// obsolete fields (searched, ignore, delete, delete_list) are dropped.
#NfConntrackStatSum: {
	found:          uint64
	new:            uint64
	invalid:        uint64
	insert:         uint64
	insert_failed:  uint64
	drop:           uint64
	early_drop:     uint64
	error:          uint64
	search_restart: uint64
	clash_resolve:  uint64
	chaintoolong:   uint64
}

// ---------------------------------------------------------------------------
// CTA_STATS_GLOBAL_ENTRIES from CT_GET_STATS reply
// ---------------------------------------------------------------------------

// #CtaStatsGlobalEntries is the parsed value of the CTA_STATS_GLOBAL_ENTRIES
// nlattr (type=9) from the CT_GET_STATS (0x0106) reply.
// Wire encoding: u64 big-endian.
// Maps to nft_conntrack_max_entries (the nf_conntrack_max sysctl value).
#CtaStatsGlobalEntries: {
	// nla_type = 9 (CTA_STATS_GLOBAL_ENTRIES).
	nla_type: 9

	// value is the big-endian u64 parsed with u64::from_be_bytes(data[0..8]).
	value: uint64
}

// ---------------------------------------------------------------------------
// Top-level CTA_* attribute type constants for CT_GET dump replies
// ---------------------------------------------------------------------------

// #CtaType enumerates the top-level CTA_* nlattr type values used in
// CT_GET dump reply messages. The nested flag (bit 15) is stripped before
// matching: effective_type = nla_type & !(1u16 << 15).
#CtaType: {
	tuple_orig:     1   // nested: CTA_TUPLE_ORIG
	tuple_reply:    2   // nested: CTA_TUPLE_REPLY
	status:         3   // u32 big-endian: IPS_* bitmask
	protoinfo:      4   // nested: protocol-specific state
	timeout:        7   // u32 big-endian: remaining timeout in seconds
	mark:           8   // u32 big-endian: conntrack mark
	counters_orig:  9   // nested: original direction byte/packet counters
	counters_reply: 10  // nested: reply direction byte/packet counters
	use_count:      11  // u32 big-endian: reference count (ignored by adapter)
	id:             12  // u32 big-endian: internal kernel ID — NEVER a label
	zone:           18  // u16 big-endian: conntrack zone
}

// #CtaTupleIpType enumerates the CTA_IP_* sub-attribute types within
// CTA_TUPLE_IP nested attribute.
#CtaTupleIpType: {
	v4_src: 1  // u32 big-endian IPv4 address
	v4_dst: 2  // u32 big-endian IPv4 address
	v6_src: 3  // 16 bytes big-endian IPv6 address
	v6_dst: 4  // 16 bytes big-endian IPv6 address
}

// #CtaTupleProtoType enumerates the CTA_PROTO_* sub-attribute types within
// CTA_TUPLE_PROTO nested attribute.
#CtaTupleProtoType: {
	num:       1  // u8: IPPROTO_* value
	src_port:  2  // u16 big-endian: source port (TCP/UDP/SCTP/DCCP)
	dst_port:  3  // u16 big-endian: destination port
	icmp_id:   4  // u16 big-endian: ICMP identifier
	icmp_type: 5  // u8: ICMP type
	icmp_code: 6  // u8: ICMP code
}

// #CtaProtoinfoType enumerates the CTA_PROTOINFO_* sub-attribute types within
// CTA_PROTOINFO nested attribute.
#CtaProtoinfoType: {
	tcp:  1  // nested: TCP protoinfo
	dccp: 2  // nested: DCCP protoinfo (not parsed by adapter)
	sctp: 3  // nested: SCTP protoinfo (not parsed by adapter)
}

// #CtaProtoinfoTcpType enumerates the CTA_PROTOINFO_TCP_* sub-attribute types.
#CtaProtoinfoTcpType: {
	state:        1  // u8: TCP_CONNTRACK_* state enum
	wscale_orig:  2  // u8: window scale original direction
	wscale_reply: 3  // u8: window scale reply direction
	flags_orig:   4  // 2 bytes: TCP flags original direction
	flags_reply:  5  // 2 bytes: TCP flags reply direction
}

// #CtaCountersType enumerates the CTA_COUNTERS_* sub-attribute types within
// CTA_COUNTERS_ORIG and CTA_COUNTERS_REPLY nested attributes.
// All values are u64 big-endian.
#CtaCountersType: {
	packets: 1  // u64 big-endian: total packets in this direction
	bytes:   2  // u64 big-endian: total bytes in this direction
}

// ---------------------------------------------------------------------------
// TCP state mapping
// ---------------------------------------------------------------------------

// #TcpConntrackState maps the u8 CTA_PROTOINFO_TCP_STATE value to ConntrackState.
// Values 0–9 are defined by TCP_CONNTRACK_* in nf_conntrack_tcp.h.
#TcpConntrackState: {
	none:       0  // TCP_CONNTRACK_NONE
	syn_sent:   1  // TCP_CONNTRACK_SYN_SENT
	syn_recv:   2  // TCP_CONNTRACK_SYN_RECV
	established: 3 // TCP_CONNTRACK_ESTABLISHED
	fin_wait:   4  // TCP_CONNTRACK_FIN_WAIT
	close_wait: 5  // TCP_CONNTRACK_CLOSE_WAIT
	last_ack:   6  // TCP_CONNTRACK_LAST_ACK
	time_wait:  7  // TCP_CONNTRACK_TIME_WAIT
	close:      8  // TCP_CONNTRACK_CLOSE
	listen:     9  // TCP_CONNTRACK_LISTEN (deprecated)
}

// ---------------------------------------------------------------------------
// IPS_* status bit positions in CTA_STATUS u32
// ---------------------------------------------------------------------------

// #IpsStatusBits documents the bit positions of the IPS_* constants used by
// ConntrackAdapter when deriving ConntrackState for non-TCP protocols.
#IpsStatusBits: {
	// assured: bit 2 (1 << 2 = 0x00000004).
	// Set when a reply packet has been seen (flow is assured).
	// ConntrackAdapter maps IPS_ASSURED=1 to state "established" for
	// UDP, ICMP, and other stateless protocols.
	assured: 2

	// confirmed: bit 3 (1 << 3 = 0x00000008).
	// Set when the flow is fully confirmed in the conntrack table.
	confirmed: 3

	// src_nat: bit 9 (1 << 9 = 0x00000200). Source NAT applied.
	src_nat: 9

	// dst_nat: bit 10 (1 << 10 = 0x00000400). Destination NAT applied.
	dst_nat: 10
}

// ---------------------------------------------------------------------------
// IPPROTO_* values used in CTA_PROTO_NUM
// ---------------------------------------------------------------------------

// #IpProto maps protocol names to their IPPROTO_* numeric values as they
// appear in CTA_TUPLE_PROTO.CTA_PROTO_NUM (u8, native-endian).
// Maps to #ConntrackProtocol string values in domain schemas.
#IpProto: {
	icmp:    1
	tcp:     6
	udp:     17
	dccp:    33
	gre:     47
	icmpv6:  58
	sctp:    132
	udplite: 136
}

// ---------------------------------------------------------------------------
// Cardinality invariants enforced by ConntrackAdapter (wire → domain boundary)
// ---------------------------------------------------------------------------

// #ConntrackDumpAggKey is the key type for in-process aggregation maps.
// Both maps are bounded: |protocol| × |state| ≤ 112 and
//                        |protocol| × |direction| ≤ 16.
// NEVER include ip, port, id, zone, mark, or timeout in these keys.
#ConntrackDumpAggKey: {
	// state_key groups flows by (protocol, state) for nft_conntrack_entries.
	state_key: {
		protocol: #ConntrackProtocol
		state:    #ConntrackState
	}

	// direction_key groups flows by (protocol, direction) for
	// nft_conntrack_bytes_total and nft_conntrack_packets_total.
	direction_key: {
		protocol:  #ConntrackProtocol
		direction: #ConntrackDirection
	}
}
