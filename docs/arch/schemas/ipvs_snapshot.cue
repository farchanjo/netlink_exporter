// DDD role: ReadModel
package schemas

// ---------------------------------------------------------------------------
// ipvs_snapshot.cue — wire-level value objects and ReadModel for the IPVS
// generic-netlink subsystem (NETLINK_GENERIC, family "IPVS", version 1).
//
// The IPVS kernel module exposes the Linux Virtual Server load-balancer state
// via a generic-netlink family resolved by CTRL_CMD_GETFAMILY("IPVS\0").
// Commands IPVS_CMD_GET_INFO, IPVS_CMD_GET_SERVICE, and IPVS_CMD_GET_DEST
// provide per-virtual-service and per-real-server connection, packet, and
// byte counters. Source: include/uapi/linux/ip_vs.h.
//
// ADR-0017 mandates direct generic-netlink wire protocol (ADR-0011 extension).
// Runtime gating: when ip_vs is absent (ENOENT on family resolution),
// nft_scrape_collector_available{collector="ipvs"}=0 is emitted and all
// nft_ipvs_* series are suppressed without incrementing error counters.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Generic-netlink IPVS family constants
// ---------------------------------------------------------------------------

// #IpvsFamilyName is the NUL-terminated string sent in CTRL_ATTR_FAMILY_NAME
// during CTRL_CMD_GETFAMILY to resolve the IPVS dynamic family id.
// Source: include/uapi/linux/ip_vs.h IPVS_GENL_NAME.
#IpvsFamilyName: "IPVS"

// #IpvsFamilyVersion is the protocol version of the IPVS generic-netlink family.
// Source: include/uapi/linux/ip_vs.h IPVS_GENL_VERSION.
#IpvsFamilyVersion: 1 & uint8

// ---------------------------------------------------------------------------
// IPVS command codes (genlmsghdr.cmd)
// ---------------------------------------------------------------------------

// #IpvsCmd enumerates the generic-netlink command codes for the IPVS family.
// Source: include/uapi/linux/ip_vs.h enum ipvs_genl_commands IPVS_CMD_*.
// Only the subset sent or received by this exporter is listed.
#IpvsCmd:
	1  | // IPVS_CMD_NEW_SERVICE    — not used (read-only exporter)
	2  | // IPVS_CMD_SET_SERVICE    — not used
	3  | // IPVS_CMD_DEL_SERVICE    — not used
	4  | // IPVS_CMD_GET_SERVICE    — dump all virtual services (NLM_F_DUMP)
	5  | // IPVS_CMD_NEW_DEST       — not used
	6  | // IPVS_CMD_SET_DEST       — not used
	7  | // IPVS_CMD_DEL_DEST       — not used
	8  | // IPVS_CMD_GET_DEST       — dump destinations for one service (unicast per service)
	9  | // IPVS_CMD_NEW_DAEMON     — not used
	10 | // IPVS_CMD_DEL_DAEMON     — not used
	11 | // IPVS_CMD_GET_DAEMON     — not used
	12 | // IPVS_CMD_SET_CONFIG     — not used
	13 | // IPVS_CMD_GET_CONFIG     — not used
	14 | // IPVS_CMD_SET_INFO       — not used
	15   // IPVS_CMD_GET_INFO       — unicast; returns connection table size

// #IpvsCmdGetInfo is the command for the IPVS_CMD_GET_INFO unicast request.
// Returns IPVS_INFO_ATTR_VERSION and IPVS_INFO_ATTR_CONN_TAB_SIZE.
#IpvsCmdGetInfo: 15 & #IpvsCmd

// #IpvsCmdGetService is the command for the IPVS_CMD_GET_SERVICE dump.
// When sent with NLM_F_DUMP the kernel replies with one frame per virtual service.
#IpvsCmdGetService: 4 & #IpvsCmd

// #IpvsCmdGetDest is the command for the per-service destination dump.
// Sent as unicast with a service key; returns one frame per real server.
#IpvsCmdGetDest: 8 & #IpvsCmd

// ---------------------------------------------------------------------------
// IPVS_CMD_GET_INFO attribute types
// ---------------------------------------------------------------------------

// #IpvsInfoAttr enumerates top-level attributes in IPVS_CMD_GET_INFO replies.
// Source: include/uapi/linux/ip_vs.h enum ipvs_info_attrs IPVS_INFO_ATTR_*.
#IpvsInfoAttr:
	1 | // IPVS_INFO_ATTR_VERSION      — u32 native-endian IPVS version
	2   // IPVS_INFO_ATTR_CONN_TAB_SIZE — u32 native-endian connection table size

// ---------------------------------------------------------------------------
// IPVS service attribute types (IPVS_SVC_ATTR_*)
// ---------------------------------------------------------------------------

// #IpvsSvcAttr enumerates top-level attributes in IPVS_CMD_GET_SERVICE replies.
// Source: include/uapi/linux/ip_vs.h enum ipvs_svc_attrs IPVS_SVC_ATTR_*.
#IpvsSvcAttr:
	1  | // IPVS_SVC_ATTR_AF       — u16 native-endian address family (AF_INET=2, AF_INET6=10)
	2  | // IPVS_SVC_ATTR_PROTOCOL — u16 native-endian; IPPROTO_TCP=6, IPPROTO_UDP=17, IPPROTO_SCTP=132
	3  | // IPVS_SVC_ATTR_ADDR     — binary address (4 bytes AF_INET; 16 bytes AF_INET6)
	4  | // IPVS_SVC_ATTR_PORT     — u16 big-endian (network byte order)
	5  | // IPVS_SVC_ATTR_FWMARK   — u32 native-endian firewall mark (mutually exclusive with ADDR+PORT)
	6  | // IPVS_SVC_ATTR_SCHED_NAME — NUL-terminated scheduler string ("rr", "lc", "wlc", ...)
	7  | // IPVS_SVC_ATTR_FLAGS    — nested; not used by this exporter
	8  | // IPVS_SVC_ATTR_TIMEOUT  — u32 native-endian; not a metric
	9  | // IPVS_SVC_ATTR_NETMASK  — u32 native-endian; not a metric
	10 | // IPVS_SVC_ATTR_STATS    — nested 32-bit stats (fallback; kernel < 3.15)
	11   // IPVS_SVC_ATTR_STATS64  — nested 64-bit stats (preferred; kernel >= 3.15)

// ---------------------------------------------------------------------------
// IPVS destination attribute types (IPVS_DEST_ATTR_*)
// ---------------------------------------------------------------------------

// #IpvsDestAttr enumerates top-level attributes in IPVS_CMD_GET_DEST replies.
// Source: include/uapi/linux/ip_vs.h enum ipvs_dest_attrs IPVS_DEST_ATTR_*.
#IpvsDestAttr:
	1  | // IPVS_DEST_ATTR_ADDR          — binary real-server address (4 or 16 bytes)
	2  | // IPVS_DEST_ATTR_PORT          — u16 big-endian port
	3  | // IPVS_DEST_ATTR_FWD_METHOD    — u32 native-endian forwarding mode (0=masq,1=local,2=tunnel)
	4  | // IPVS_DEST_ATTR_WEIGHT        — u32 native-endian scheduling weight
	5  | // IPVS_DEST_ATTR_U_THRESH      — u32 native-endian upper conn threshold
	6  | // IPVS_DEST_ATTR_L_THRESH      — u32 native-endian lower conn threshold
	7  | // IPVS_DEST_ATTR_ACTIVE_CONNS  — u32 native-endian active connections
	8  | // IPVS_DEST_ATTR_INACT_CONNS   — u32 native-endian inactive connections
	9  | // IPVS_DEST_ATTR_PERSIST_CONNS — u32 native-endian persistent connections
	10 | // IPVS_DEST_ATTR_STATS         — nested 32-bit stats (fallback; kernel < 3.15)
	11 | // IPVS_DEST_ATTR_ADDR_FAMILY   — u16 native-endian (may differ from service AF on DS-Lite)
	12   // IPVS_DEST_ATTR_STATS64       — nested 64-bit stats (preferred; kernel >= 3.15)

// ---------------------------------------------------------------------------
// IPVS stats64 attribute types (IPVS_STATS64_ATTR_*)
// ---------------------------------------------------------------------------

// #IpvsStats64Attr enumerates attributes inside IPVS_SVC_ATTR_STATS64 and
// IPVS_DEST_ATTR_STATS64 nested containers.
// Source: include/uapi/linux/ip_vs.h enum ipvs_stats_attrs IPVS_STATS_ATTR_*.
// The 64-bit variants share the same attribute type numbering; the nest parent
// determines which struct (ipvs_stats64 vs ipvs_stats) is used.
#IpvsStats64Attr:
	1 | // IPVS_STATS_ATTR_CONNS   — u64 native-endian total connections
	2 | // IPVS_STATS_ATTR_INPKTS  — u64 native-endian total incoming packets
	3 | // IPVS_STATS_ATTR_OUTPKTS — u64 native-endian total outgoing packets
	4 | // IPVS_STATS_ATTR_INBYTES — u64 native-endian total incoming bytes
	5 | // IPVS_STATS_ATTR_OUTBYTES — u64 native-endian total outgoing bytes
	6 | // IPVS_STATS_ATTR_CPS     — u64 native-endian connections per second (EMA)
	7 | // IPVS_STATS_ATTR_INPPS   — u64 native-endian incoming packets per second (EMA)
	8 | // IPVS_STATS_ATTR_OUTPPS  — u64 native-endian outgoing packets per second (EMA)
	9 | // IPVS_STATS_ATTR_INBPS   — u64 native-endian incoming bytes per second (EMA)
	10  // IPVS_STATS_ATTR_OUTBPS  — u64 native-endian outgoing bytes per second (EMA)

// ---------------------------------------------------------------------------
// Endianness notes for IPVS wire fields
// ---------------------------------------------------------------------------

// #IpvsEndianNotes documents the endianness of every IPVS wire field decoded
// by IpvsAdapter. All NETLINK_GENERIC scalar fields are native-endian (LE on
// x86-64/aarch64) EXCEPT port fields which follow network byte order.
//
// Field                          Endianness    Rust read
// IPVS_SVC_ATTR_AF               native LE     u16::from_ne_bytes
// IPVS_SVC_ATTR_PROTOCOL         native LE     u16::from_ne_bytes
// IPVS_SVC_ATTR_ADDR (AF_INET)   network BE    Ipv4Addr::from([b0,b1,b2,b3])
// IPVS_SVC_ATTR_ADDR (AF_INET6)  network BE    Ipv6Addr::from(<[u8;16]>)
// IPVS_SVC_ATTR_PORT             network BE    u16::from_be_bytes
// IPVS_SVC_ATTR_FWMARK           native LE     u32::from_ne_bytes
// IPVS_DEST_ATTR_PORT            network BE    u16::from_be_bytes
// IPVS_STATS64_ATTR_CONNS et al  native LE     u64::from_ne_bytes
// IPVS_STATS64_ATTR_CPS et al    native LE     u64::from_ne_bytes
#IpvsEndianNotes: "See ipvs_snapshot.cue inline comments for per-field endianness"

// ---------------------------------------------------------------------------
// Value objects — address representation
// ---------------------------------------------------------------------------

// #IpvsAddressFamily enumerates the address families used by IPVS.
// Source: AF_INET and AF_INET6 from include/uapi/linux/socket.h.
#IpvsAddressFamily: 2 | 10

// #IpvsProtocol enumerates IP protocols used in IPVS service definitions.
// Source: include/uapi/linux/in.h IPPROTO_*.
#IpvsProtocol:
	6   | // IPPROTO_TCP
	17  | // IPPROTO_UDP
	132   // IPPROTO_SCTP

// #IpvsForwardingMethod enumerates the destination forwarding modes.
// Source: include/uapi/linux/ip_vs.h IP_VS_CONN_F_FWD_MASK flags.
#IpvsForwardingMethod:
	"masq"   | // 0 — NAT masquerading (most common for cloud LB)
	"local"  | // 1 — local server (direct delivery)
	"tunnel"   // 2 — IP-in-IP tunneling

// ---------------------------------------------------------------------------
// Value objects — stats payload
// ---------------------------------------------------------------------------

// #IpvsStats64 holds the 64-bit per-service or per-destination counters decoded
// from IPVS_SVC_ATTR_STATS64 or IPVS_DEST_ATTR_STATS64 nested containers.
// All fields are native-endian u64 on wire (little-endian on x86-64/aarch64).
#IpvsStats64: {
	// conns is the total number of connections handled (IPVS_STATS_ATTR_CONNS).
	// Maps to nft_ipvs_connections_total counter.
	conns: uint64

	// inpkts is the total incoming packet count (IPVS_STATS_ATTR_INPKTS).
	// Maps to nft_ipvs_incoming_packets_total counter.
	inpkts: uint64

	// outpkts is the total outgoing packet count (IPVS_STATS_ATTR_OUTPKTS).
	// Maps to nft_ipvs_outgoing_packets_total counter.
	outpkts: uint64

	// inbytes is the total incoming byte count (IPVS_STATS_ATTR_INBYTES).
	// Maps to nft_ipvs_incoming_bytes_total counter.
	inbytes: uint64

	// outbytes is the total outgoing byte count (IPVS_STATS_ATTR_OUTBYTES).
	// Maps to nft_ipvs_outgoing_bytes_total counter.
	outbytes: uint64

	// cps is the exponential-moving-average connections per second
	// (IPVS_STATS_ATTR_CPS). Maps to nft_ipvs_connections_per_second gauge.
	// The kernel computes this as a 1-second EMA; use delta() in alerting.
	cps: uint64

	// inpps is the EMA incoming packets per second (IPVS_STATS_ATTR_INPPS).
	// Maps to nft_ipvs_incoming_packets_per_second gauge.
	inpps: uint64

	// outpps is the EMA outgoing packets per second (IPVS_STATS_ATTR_OUTPPS).
	// Maps to nft_ipvs_outgoing_packets_per_second gauge.
	outpps: uint64

	// inbps is the EMA incoming bytes per second (IPVS_STATS_ATTR_INBPS).
	// Maps to nft_ipvs_incoming_bytes_per_second gauge.
	inbps: uint64

	// outbps is the EMA outgoing bytes per second (IPVS_STATS_ATTR_OUTBPS).
	// Maps to nft_ipvs_outgoing_bytes_per_second gauge.
	outbps: uint64
}

// ---------------------------------------------------------------------------
// Value objects — service key
// ---------------------------------------------------------------------------

// #IpvsServiceKey is the identity key for a virtual service. Exactly one of the
// two key variants is populated per service:
//   addr+port variant: af, protocol, vip, port (non-zero port)
//   fwmark variant:    af=0, protocol=0, vip="", port=0, fwmark>0
//
// The adapter decodes the key from IPVS_SVC_ATTR_AF + IPVS_SVC_ATTR_PROTOCOL +
// IPVS_SVC_ATTR_ADDR + IPVS_SVC_ATTR_PORT (addr+port) or IPVS_SVC_ATTR_FWMARK.
#IpvsServiceKey: {
	// af is the address family: 2=AF_INET, 10=AF_INET6, 0=fwmark-only service.
	af: uint16

	// protocol is the IP protocol number: 6=TCP, 17=UDP, 132=SCTP, 0=fwmark.
	protocol: uint16

	// vip is the virtual IP address in presentation form (IPv4 dotted-decimal or
	// IPv6 colon-hex). Empty string when the service uses a fwmark key.
	// NEVER used as a Prometheus label when it would produce unbounded cardinality;
	// bounded by operator-controlled LVS configuration (ADR-0017).
	vip: string

	// port is the virtual port number as a decimal string ("0" for fwmark services).
	port: string

	// fwmark is the firewall mark for fwmark-based services. 0 when addr+port.
	fwmark: uint32
}

// ---------------------------------------------------------------------------
// Entity — destination
// ---------------------------------------------------------------------------

// #IpvsDestEntry is an entity representing one real server (destination) within
// a virtual service. The composite key is (service_key, rip, rport).
#IpvsDestEntry: {
	// rip is the real server address in presentation form.
	// Bounded by operator LVS config; not unbounded per-flow traffic.
	rip: string & !=""

	// rport is the real server port as a decimal string.
	rport: string & !=""

	// fwd_method is the forwarding mode for this destination.
	fwd_method: #IpvsForwardingMethod

	// weight is the scheduling weight (0 = inactive destination).
	weight: uint32

	// active_conns is the current number of active connections to this destination
	// (IPVS_DEST_ATTR_ACTIVE_CONNS). Maps to nft_ipvs_dest_active_connections gauge.
	active_conns: uint32

	// inact_conns is the current number of inactive (time-wait) connections
	// (IPVS_DEST_ATTR_INACT_CONNS). Maps to nft_ipvs_dest_inactive_connections gauge.
	inact_conns: uint32

	// stats64 holds the 64-bit cumulative and rate counters for this destination.
	// Absent on kernels < 3.15 where only 32-bit IPVS_DEST_ATTR_STATS is available.
	stats64?: #IpvsStats64
}

// ---------------------------------------------------------------------------
// Entity — virtual service
// ---------------------------------------------------------------------------

// #IpvsServiceEntry is an entity representing one virtual service (VIP:port or
// fwmark) in the IPVS table. Produced from IPVS_CMD_GET_SERVICE reply frames.
#IpvsServiceEntry: {
	// key uniquely identifies this virtual service.
	key: #IpvsServiceKey

	// sched_name is the scheduler string from IPVS_SVC_ATTR_SCHED_NAME
	// (e.g. "rr", "lc", "wlc", "sh", "dh", "lblc"). Used as informational
	// label in nft_ipvs_service_info but not in counter families to avoid
	// cardinality amplification.
	sched_name: string & !=""

	// stats64 holds the aggregate 64-bit counters for this virtual service.
	// Absent on kernels < 3.15; adapter falls back to IPVS_SVC_ATTR_STATS.
	stats64?: #IpvsStats64

	// destinations is the list of real servers for this service.
	// Populated by IpvsAdapter.get_dest() after the service dump completes.
	destinations: [...#IpvsDestEntry]
}

// ---------------------------------------------------------------------------
// ReadModel — IpvsSnapshot
// ---------------------------------------------------------------------------

// #IpvsSnapshot is the immutable ReadModel produced by IpvsCollector for one
// scrape epoch. It captures the full IPVS table state: info counters, all
// virtual services, and all destinations per service.
//
// The Collector Strategy (IpvsCollector) translates this snapshot into the
// nft_ipvs_* Prometheus metric families listed in the metric_contract.
//
// When ip_vs is absent (available=false), all fields except available and
// epoch_ns are empty/zero. The Collector emits only
// nft_scrape_collector_available{collector="ipvs"}=0 and suppresses all
// nft_ipvs_* series.
#IpvsSnapshot: {
	// epoch_ns is the Unix nanosecond timestamp when this snapshot was captured.
	epoch_ns: uint64

	// available indicates whether the IPVS generic-netlink family resolved
	// successfully. false when ip_vs module is absent (CTRL_CMD_GETFAMILY ENOENT).
	// Maps to nft_scrape_collector_available{collector="ipvs"} gauge.
	available: bool

	// conn_tab_size is the kernel connection table capacity
	// (IPVS_INFO_ATTR_CONN_TAB_SIZE). Maps to nft_ipvs_connection_table_size gauge.
	// Zero when available=false.
	conn_tab_size: uint32

	// services is the complete list of virtual service entries for this epoch.
	// Empty when available=false or when no virtual services are configured.
	services: [...#IpvsServiceEntry]
}

// ---------------------------------------------------------------------------
// Metric-to-wire mapping reference (documentation only — not machine-validated)
// ---------------------------------------------------------------------------

// #IpvsMetricMapping documents the canonical wire-field to Prometheus metric
// translation performed by IpvsCollector. Labels that appear in multiple
// families are defined once here.
//
// Service-level labels: proto, vip, port (or port="" and fwmark hex string as port)
// Dest-level labels:    proto, vip, port, rip, rport
//
// Metric families:
//
// nft_ipvs_service_info{proto, vip, port, sched}        gauge  1 per service
// nft_ipvs_connections_total{proto, vip, port}           counter IPVS_STATS_ATTR_CONNS
// nft_ipvs_incoming_packets_total{proto, vip, port}      counter IPVS_STATS_ATTR_INPKTS
// nft_ipvs_outgoing_packets_total{proto, vip, port}      counter IPVS_STATS_ATTR_OUTPKTS
// nft_ipvs_incoming_bytes_total{proto, vip, port}        counter IPVS_STATS_ATTR_INBYTES
// nft_ipvs_outgoing_bytes_total{proto, vip, port}        counter IPVS_STATS_ATTR_OUTBYTES
// nft_ipvs_connections_per_second{proto, vip, port}      gauge   IPVS_STATS_ATTR_CPS (EMA)
// nft_ipvs_incoming_packets_per_second{proto, vip, port} gauge   IPVS_STATS_ATTR_INPPS (EMA)
// nft_ipvs_outgoing_packets_per_second{proto, vip, port} gauge   IPVS_STATS_ATTR_OUTPPS (EMA)
// nft_ipvs_incoming_bytes_per_second{proto, vip, port}   gauge   IPVS_STATS_ATTR_INBPS (EMA)
// nft_ipvs_outgoing_bytes_per_second{proto, vip, port}   gauge   IPVS_STATS_ATTR_OUTBPS (EMA)
//
// nft_ipvs_dest_active_connections{proto,vip,port,rip,rport}   gauge DEST_ATTR_ACTIVE_CONNS
// nft_ipvs_dest_inactive_connections{proto,vip,port,rip,rport} gauge DEST_ATTR_INACT_CONNS
// nft_ipvs_dest_connections_total{proto,vip,port,rip,rport}    counter DEST_ATTR_STATS64 conns
// nft_ipvs_dest_incoming_bytes_total{proto,vip,port,rip,rport} counter DEST_ATTR_STATS64 inbytes
// nft_ipvs_dest_outgoing_bytes_total{proto,vip,port,rip,rport} counter DEST_ATTR_STATS64 outbytes
//
// nft_ipvs_connection_table_size{} gauge INFO_ATTR_CONN_TAB_SIZE
//
// Availability sentinel (self-telemetry, emitted regardless of available flag):
// nft_scrape_collector_available{collector="ipvs"} gauge 1=present 0=absent
#IpvsMetricMapping: "See ipvs_snapshot.cue inline comments for full mapping"
