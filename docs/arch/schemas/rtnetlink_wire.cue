// DDD role: ValueObject
package schemas

// ---------------------------------------------------------------------------
// rtnetlink wire-level value objects
// Grounded in linux-6.17.13 include/uapi/linux/{netlink,rtnetlink,if_link,
// if_addr,neighbour}.h.  All byte offsets assume little-endian (x86-64 / arm64).
// ---------------------------------------------------------------------------

// #NlMsgType enumerates the nlmsg_type values used by the rtnetlink collector.
// RTM_* values are the kernel enum; NLMSG_* are the control message types.
#NlMsgType:
	"NLMSG_NOOP"  |  // 0x01
	"NLMSG_ERROR" |  // 0x02
	"NLMSG_DONE"  |  // 0x03
	"RTM_NEWLINK" |  // 16
	"RTM_GETLINK" |  // 18
	"RTM_NEWADDR" |  // 20
	"RTM_GETADDR" |  // 22
	"RTM_NEWROUTE" | // 24
	"RTM_GETROUTE" | // 26
	"RTM_NEWNEIGH" | // 28
	"RTM_GETNEIGH"   // 30

// #NlMsgTypeCode is the raw u16 value of nlmsg_type.
// Used for exhaustive matching in the Rust receive loop.
#NlMsgTypeCode: >=1 & <=65535

// #NlMsgFlags encodes the nlmsg_flags bitmask.
// Dump requests combine NLM_F_REQUEST | NLM_F_DUMP (= 0x0301).
// Responses set NLM_F_MULTI (0x02) for multi-part messages.
// NLM_F_DUMP_INTR (0x10) signals mid-dump inconsistency; triggers restart.
#NlMsgFlags: {
	request:     bool // NLM_F_REQUEST = 0x0001
	multi:       bool // NLM_F_MULTI   = 0x0002
	dump_intr:   bool // NLM_F_DUMP_INTR = 0x0010
	dump:        bool // NLM_F_DUMP = NLM_F_ROOT|NLM_F_MATCH = 0x0300
}

// #NlMsgHeader represents the 16-byte nlmsghdr fixed header.
// All integers are native-endian (little-endian on x86-64 / arm64).
// On-wire size: 16 bytes; NLMSG_HDRLEN = NLMSG_ALIGN(16) = 16.
#NlMsgHeader: {
	// nlmsg_len: total length of the netlink message including this header.
	nlmsg_len: uint32

	// nlmsg_type: message content type (RTM_* or NLMSG_* constant).
	nlmsg_type: #NlMsgTypeCode

	// nlmsg_flags: bitmask of NLM_F_* flags.
	nlmsg_flags: uint16

	// nlmsg_seq: sequence number chosen by the sender.
	nlmsg_seq: uint32

	// nlmsg_pid: port ID of the sending socket; 0 in requests.
	nlmsg_pid: uint32
}

// #RtgenMsg is the 1-byte body used with RTM_GETLINK, RTM_GETADDR,
// RTM_GETNEIGH dump requests.  rtgen_family = AF_UNSPEC (0) requests all
// interfaces; AF_INET (2) or AF_INET6 (10) filter by family.
// Total request on wire: NLMSG_ALIGN(16 + 1) = 20 bytes.
#RtgenMsg: {
	rtgen_family: uint8 // 0 = AF_UNSPEC, 2 = AF_INET, 10 = AF_INET6
}

// #RtMsg is the 12-byte body used with RTM_GETROUTE dump requests.
// All fields are 0 (AF_UNSPEC / RT_TABLE_UNSPEC) for a full-table dump.
// Total request on wire: NLMSG_ALIGN(16 + 12) = 28 bytes.
#RtMsg: {
	rtm_family:   uint8  // AF_UNSPEC=0
	rtm_dst_len:  uint8  // 0 for dump
	rtm_src_len:  uint8  // 0 for dump
	rtm_tos:      uint8  // 0
	rtm_table:    uint8  // RT_TABLE_UNSPEC=0
	rtm_protocol: uint8  // RTPROT_UNSPEC=0
	rtm_scope:    uint8  // RT_SCOPE_UNIVERSE=0
	rtm_type:     uint8  // RTN_UNSPEC=0
	rtm_flags:    uint32 // 0
}

// #IfInfoMsg is the 16-byte body in RTM_NEWLINK responses.
// RTattrs start at byte offset 32 from nlmsghdr start
// (= NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(ifinfomsg))).
#IfInfoMsg: {
	ifi_family:  uint8  // AF_UNSPEC in responses
	ifi_pad:     uint8  // padding; ignore (kernel name __ifi_pad; __ reserved in CUE)
	ifi_type:    uint16 // ARPHRD_* hardware type (1=ether, 772=loopback)
	ifi_index:   int32  // kernel interface index (always positive in practice)
	ifi_flags:   uint32 // IFF_* bitmask
	ifi_change:  uint32 // 0xFFFFFFFF in dump responses
}

// #IfAddrMsg is the 8-byte body in RTM_NEWADDR responses.
// RTattrs start at byte offset 24.
#IfAddrMsg: {
	ifa_family:    uint8  // AF_INET=2, AF_INET6=10
	ifa_prefixlen: uint8  // 0-32 (v4) or 0-128 (v6)
	ifa_flags:     uint8  // IFA_F_PERMANENT=0x80, IFA_F_SECONDARY=0x01, etc.
	ifa_scope:     uint8  // RT_SCOPE_HOST=254, RT_SCOPE_LINK=253,
	                      // RT_SCOPE_UNIVERSE=0, RT_SCOPE_SITE=200
	ifa_index:     uint32 // parent interface index
}

// #NdMsg is the 12-byte body in RTM_NEWNEIGH responses.
// RTattrs start at byte offset 28.
#NdMsg: {
	ndm_family:   uint8  // AF_INET=2, AF_INET6=10
	ndm_pad1:     uint8  // padding; ignore
	ndm_pad2:     uint16 // padding; ignore
	ndm_ifindex:  int32  // interface index
	ndm_state:    uint16 // NUD_* bitmask (see #NudState)
	ndm_flags:    uint8  // NTF_* flags
	ndm_type:     uint8  // RTN_UNICAST=1 for normal entries
}

// #RtAttr is the 4-byte TLV header preceding each attribute payload.
// rta_len includes these 4 bytes.  Payload starts at byte offset 4.
// Alignment: RTA_ALIGN(rta_len) = (rta_len + 3) & ~3.
#RtAttr: {
	rta_len:  uint16 // total attribute length including this header
	rta_type: uint16 // attribute type constant (IFLA_* / IFA_* / RTA_* / NDA_*)
}

// ---------------------------------------------------------------------------
// IFLA_* attribute type codes (RTM_GETLINK / RTM_NEWLINK)
// ---------------------------------------------------------------------------

// #IflaType enumerates the IFLA_* attribute type constants used by the
// RtnetlinkAdapter when parsing RTM_NEWLINK responses.
#IflaType:
	0  | // IFLA_UNSPEC      (skip)
	1  | // IFLA_ADDRESS     hardware MAC (6 bytes Ethernet)
	3  | // IFLA_IFNAME      NUL-terminated name
	4  | // IFLA_MTU         u32 MTU in bytes
	10 | // IFLA_MASTER      u32 master ifindex
	16 | // IFLA_OPERSTATE   u8  IF_OPER_* (0-6)
	20 | // IFLA_IFALIAS     NUL-terminated alias string
	23 | // IFLA_STATS64     rtnl_link_stats64 (200 bytes)
	33   // IFLA_CARRIER     u8  carrier (0/1)

// #IflaTypeCode is the raw u16 for use in match expressions.
#IflaTypeCode: >=0 & <=65535

// ---------------------------------------------------------------------------
// IFA_* attribute type codes (RTM_GETADDR / RTM_NEWADDR)
// ---------------------------------------------------------------------------

// #IfaType enumerates the IFA_* attribute type constants used when parsing
// RTM_NEWADDR responses.
#IfaType:
	0 | // IFA_UNSPEC    (skip)
	1 | // IFA_ADDRESS   prefix address (for p2p: remote end)
	2 | // IFA_LOCAL     local interface address (preferred for non-p2p)
	3 | // IFA_LABEL     NUL-terminated label (e.g. "eth0:1")
	4 | // IFA_BROADCAST broadcast address
	6 | // IFA_CACHEINFO struct ifa_cacheinfo (lifetimes)
	8   // IFA_FLAGS     u32 extended flags (supersedes ifa_flags u8)

// ---------------------------------------------------------------------------
// RTA_* attribute type codes (RTM_GETROUTE / RTM_NEWROUTE)
// ---------------------------------------------------------------------------

// #RtaType enumerates the RTA_* attribute type constants used during route
// aggregation.  Payload bytes of RTA_DST / RTA_SRC / RTA_GATEWAY are
// intentionally discarded; only RTA_TABLE is retained.
#RtaType:
	0  | // RTA_UNSPEC   (skip)
	1  | // RTA_DST      destination prefix (DISCARDED — not stored)
	2  | // RTA_SRC      source prefix (DISCARDED — not stored)
	3  | // RTA_IIF      s32 ingress ifindex
	4  | // RTA_OIF      s32 egress ifindex
	5  | // RTA_GATEWAY  next-hop address (DISCARDED — not stored)
	6  | // RTA_PRIORITY u32 route metric
	15   // RTA_TABLE    u32 table ID (overrides rtmsg.rtm_table for id > 255)

// ---------------------------------------------------------------------------
// NDA_* attribute type codes (RTM_GETNEIGH / RTM_NEWNEIGH)
// ---------------------------------------------------------------------------

// #NdaType enumerates the NDA_* attribute type constants used during neighbor
// aggregation.  NDA_DST and NDA_LLADDR payloads are intentionally discarded.
#NdaType:
	0 | // NDA_UNSPEC    (skip)
	1 | // NDA_DST       neighbor IP address (DISCARDED — not stored)
	2 | // NDA_LLADDR    neighbor MAC address (DISCARDED — not stored)
	3 | // NDA_CACHEINFO struct nda_cacheinfo (timing; skip)
	4 | // NDA_PROBES    u32 probe count
	8   // NDA_IFINDEX   u32 actual ifindex for FDB entries

// ---------------------------------------------------------------------------
// Operational state and neighbor state enumerations
// ---------------------------------------------------------------------------

// #IfOperState is the u8 value from IFLA_OPERSTATE.
// Maps to #OperState strings (see link.cue).
#IfOperState: >=0 & <=6
// 0=unknown, 1=notpresent, 2=down, 3=lowerlayerdown,
// 4=testing, 5=dormant, 6=up

// #NudState is the u16 ndm_state bitmask.
// Multiple NUD_* bits may be set simultaneously (e.g. NUD_NOARP|NUD_PERMANENT).
#NudState: >=0 & <=255
// NUD_INCOMPLETE=0x01, NUD_REACHABLE=0x02, NUD_STALE=0x04,
// NUD_DELAY=0x08, NUD_PROBE=0x10, NUD_FAILED=0x20,
// NUD_NOARP=0x40, NUD_PERMANENT=0x80

// ---------------------------------------------------------------------------
// rtnl_link_stats64 wire layout value object
// ---------------------------------------------------------------------------

// #LinkStats64Wire documents the exact 200-byte on-wire layout of
// rtnl_link_stats64 as carried in IFLA_STATS64 attribute payload.
// All fields are u64 little-endian.
//
// NOTE: rx_otherhost_dropped (byte 192) was added in kernel 5.18.
// Implementations MUST verify payload length >= 200 before reading it;
// on kernel < 5.18 the payload is 192 bytes and this field is absent.
#LinkStats64Wire: {
	// byte 0-7
	rx_packets: uint64
	// byte 8-15
	tx_packets: uint64
	// byte 16-23
	rx_bytes: uint64
	// byte 24-31
	tx_bytes: uint64
	// byte 32-39
	rx_errors: uint64
	// byte 40-47
	tx_errors: uint64
	// byte 48-55
	rx_dropped: uint64
	// byte 56-63
	tx_dropped: uint64
	// byte 64-71
	multicast: uint64
	// byte 72-79
	collisions: uint64
	// byte 80-87
	rx_length_errors: uint64
	// byte 88-95
	rx_over_errors: uint64
	// byte 96-103
	rx_crc_errors: uint64
	// byte 104-111
	rx_frame_errors: uint64
	// byte 112-119
	rx_fifo_errors: uint64
	// byte 120-127
	rx_missed_errors: uint64
	// byte 128-135
	tx_aborted_errors: uint64
	// byte 136-143
	tx_carrier_errors: uint64
	// byte 144-151
	tx_fifo_errors: uint64
	// byte 152-159
	tx_heartbeat_errors: uint64
	// byte 160-167
	tx_window_errors: uint64
	// byte 168-175
	rx_compressed: uint64
	// byte 176-183
	tx_compressed: uint64
	// byte 184-191
	rx_nohandler: uint64
	// byte 192-199 (kernel >= 5.18 only; absent on older kernels)
	rx_otherhost_dropped?: uint64
}

// #Stats64Size documents the two valid payload sizes for IFLA_STATS64.
// Implementations MUST accept both sizes.
#Stats64Size: 192 | 200

// ---------------------------------------------------------------------------
// Dump recipe specification
// ---------------------------------------------------------------------------

// #DumpRequest captures the fields needed to construct a valid RTM_GET* dump
// request message, independent of the Rust struct layout used to serialise it.
#DumpRequest: {
	// msg_type is the RTM_GET* constant for this dump.
	msg_type: "RTM_GETLINK" | "RTM_GETADDR" | "RTM_GETROUTE" | "RTM_GETNEIGH"

	// nlmsg_flags must be NLM_F_REQUEST | NLM_F_DUMP = 0x0301.
	nlmsg_flags: 0x0301

	// seq is the caller-chosen sequence number; monotonically increasing.
	seq: uint32

	// For LINK / ADDR / NEIGH: body is a single rtgenmsg byte (AF_UNSPEC=0).
	// For ROUTE: body is a zeroed 12-byte rtmsg.
	body_family: uint8 // 0 for AF_UNSPEC
}

// #DumpPolicy encodes the operational constraints for the dump loop.
#DumpPolicy: {
	// max_restarts is the maximum number of NLM_F_DUMP_INTR restarts before
	// the collector returns CollectorError::DumpIntr and falls back to the
	// stale snapshot.  Configurable via ExporterConfig.netlink_dump_max_restarts.
	max_restarts: >=1 & <=32

	// so_rcvbuf_bytes is the requested SO_RCVBUF size in bytes.
	// Recommended: 4 MiB (4194304).
	so_rcvbuf_bytes: >=131072 & <=67108864

	// strict_chk_enabled indicates whether NETLINK_GET_STRICT_CHK is set.
	// Must be true on kernels >= 4.20; safe to set on all modern kernels.
	strict_chk_enabled: bool
}

// #DumpPolicyDefault is the recommended DumpPolicy for the RtnetlinkAdapter.
#DumpPolicyDefault: #DumpPolicy & {
	max_restarts:       8
	so_rcvbuf_bytes:    4194304
	strict_chk_enabled: true
}

// ---------------------------------------------------------------------------
// Metric mapping table (wire field -> Prometheus metric name)
// ---------------------------------------------------------------------------

// #Stats64MetricMapping documents which rtnl_link_stats64 fields are exported
// as Prometheus counters and which are stored only in #IfStats64.
#Stats64MetricMapping: {
	// exported_fields lists the eight field names that produce Prometheus counters
	// (label: interface=<IFLA_IFNAME>).  All are type=counter, unit=bytes or packets.
	exported_fields: [
		"rx_bytes",     // -> nft_link_receive_bytes_total
		"tx_bytes",     // -> nft_link_transmit_bytes_total
		"rx_packets",   // -> nft_link_receive_packets_total
		"tx_packets",   // -> nft_link_transmit_packets_total
		"rx_errors",    // -> nft_link_receive_errors_total
		"tx_errors",    // -> nft_link_transmit_errors_total
		"rx_dropped",   // -> nft_link_receive_dropped_total
		"tx_dropped",   // -> nft_link_transmit_dropped_total
	]

	// stored_only_fields are kept in #IfStats64 for future metrics but are
	// not currently exported per ADR-0005 cardinality constraints.
	stored_only_fields: [
		"multicast",
		"collisions",
		"rx_length_errors",
		"rx_over_errors",
		"rx_crc_errors",
		"rx_frame_errors",
		"rx_fifo_errors",
		"rx_missed_errors",
		"tx_aborted_errors",
		"tx_carrier_errors",
		"tx_fifo_errors",
		"tx_heartbeat_errors",
		"tx_window_errors",
		"rx_compressed",
		"tx_compressed",
		"rx_nohandler",
		"rx_otherhost_dropped",
	]
}
