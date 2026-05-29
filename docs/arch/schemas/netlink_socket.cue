// DDD role: ValueObject
package schemas

// ---------------------------------------------------------------------------
// netlink_socket.cue — NetlinkSocketConfig value object (ADR-0011)
//
// Encodes the shared socket configuration consumed by all six adapter crates
// via the unified nft_exporter_netlink_socket crate. This crate is the sole
// location for AF_NETLINK socket lifecycle code: creation (rustix::net::socket_with),
// bind (sockaddr_nl nl_pid=0), SO_RCVBUF tuning, NETLINK_GET_STRICT_CHK
// setsockopt, ENOBUFS circuit-breaker, and NLM_F_DUMP_INTR restart logic.
//
// Replaces the implicit socket configuration previously embedded in the
// rust-netlink org adapter defaults (ADR-0004, now superseded by ADR-0011).
// ---------------------------------------------------------------------------

// #NetlinkFamily enumerates the AF_NETLINK protocol constants used as the
// third argument to socket(AF_NETLINK, SOCK_RAW, protocol).
// Source: include/uapi/linux/netlink.h NETLINK_*.
#NetlinkFamily:
	0  | // NETLINK_ROUTE        — rtnetlink (link/addr/route/neigh/tc)
	4  | // NETLINK_SOCK_DIAG    — inet socket diagnostics
	12 | // NETLINK_NETFILTER    — ctnetlink (conntrack) and nfnetlink (nftables)
	16   // NETLINK_GENERIC      — genetlink (ethtool family resolution + stats)

// #NetlinkFamilyName provides human-readable names for the netlink family constants.
// Used in metric labels and log messages.
#NetlinkFamilyName: {
	route:       "NETLINK_ROUTE"
	sock_diag:   "NETLINK_SOCK_DIAG"
	netfilter:   "NETLINK_NETFILTER"
	generic:     "NETLINK_GENERIC"
}

// #RecvBufBytes is the requested SO_RCVBUF size for all netlink sockets.
// The kernel doubles the value passed to setsockopt (SO_RCVBUF) — for a
// target of 4 MiB, pass 2 MiB (2097152). nft_exporter_netlink_socket
// applies the doubling internally so callers specify the desired effective size.
// Minimum: 128 KiB (sufficient for small kernel tables).
// Maximum: 32 MiB (avoids excessive kernel buffer allocation on busy nodes).
#RecvBufBytes: >=131072 & <=33554432

// #DumpMaxRestarts is the maximum number of NLM_F_DUMP_INTR restarts the
// dump loop will attempt before returning CollectorError::DumpIntr and
// activating the stale-snapshot fallback.
// Must be >= 1 (at least one retry on INTR) and <= 32 (avoids infinite loop
// on pathological kernel behaviour).
#DumpMaxRestarts: >=1 & <=32

// #NetlinkSocketConfig is the ValueObject encoding the full socket management
// policy for one AF_NETLINK socket. All adapter crates receive this config at
// construction time from the unified nft_exporter_netlink_socket crate.
// The config is immutable after startup.
#NetlinkSocketConfig: {
	// recv_buffer_bytes is the effective SO_RCVBUF size in bytes.
	// nft_exporter_netlink_socket calls setsockopt(SOL_SOCKET, SO_RCVBUF, value/2)
	// to achieve the target effective size (kernel doubles the value).
	// Increase on nodes with large routing tables or high conntrack entry counts
	// to reduce ENOBUFS errors on RTM_GETROUTE and IPCTNL_MSG_CT_GET dumps.
	// Env: NFT_EXPORTER_NETLINK_RECV_BUF_BYTES. Default: 4194304 (4 MiB).
	recv_buffer_bytes: #RecvBufBytes

	// netlink_dump_max_restarts caps the number of dump restart attempts on
	// NLM_F_DUMP_INTR (kernel data changed during dump).
	// After this many consecutive INTR restarts, the collector returns
	// CollectorError::DumpIntr and ScrapeLifecycle activates the stale snapshot.
	// Env: NFT_EXPORTER_NETLINK_DUMP_MAX_RESTARTS. Default: 8.
	netlink_dump_max_restarts: #DumpMaxRestarts

	// netlink_strict_check_enabled controls whether NETLINK_GET_STRICT_CHK
	// setsockopt is applied to the NETLINK_ROUTE socket.
	// When true, the kernel validates dump requests more strictly and respects
	// filter attributes (IFLA_EXT_MASK). Requires kernel >= 4.20.
	// On older kernels the setsockopt returns ENOPROTOOPT and is silently ignored.
	// IMPORTANT: never set RTEXT_FILTER_SKIP_STATS in IFLA_EXT_MASK when
	// collecting link counters — it suppresses IFLA_STATS64 from responses.
	// Default: true.
	netlink_strict_check_enabled: bool
}

// #NetlinkSocketConfigDefault is the recommended production default.
// All adapter crates use this config unless explicitly overridden in ExporterConfig.
#NetlinkSocketConfigDefault: #NetlinkSocketConfig & {
	recv_buffer_bytes:            4194304 // 4 MiB
	netlink_dump_max_restarts:    8
	netlink_strict_check_enabled: true
}

// ---------------------------------------------------------------------------
// ENOBUFS circuit-breaker policy
// ---------------------------------------------------------------------------

// #EnobufPolicy documents the two-strike ENOBUFS handling enforced by
// nft_exporter_netlink_socket. This policy applies to all six adapters.
#EnobufPolicy: {
	// first_occurrence: on the first ENOBUFS from recvmsg, the socket's
	// SO_RCVBUF is doubled (up to recv_buffer_bytes * 2), the current
	// dump is restarted from the beginning, and nft_netlink_errors_total
	// is incremented with errno="ENOBUFS".
	first_occurrence: "double SO_RCVBUF and restart dump; increment nft_netlink_errors_total{errno=ENOBUFS}"

	// second_occurrence: on the second ENOBUFS in the same dump sequence,
	// the collector aborts the current scrape, returns CollectorError::Enobufs,
	// and ScrapeLifecycle activates the stale-snapshot fallback.
	// nft_scrape_collector_error_total{reason=netlink_truncated} is incremented.
	second_occurrence: "abort scrape; activate stale snapshot; increment nft_scrape_collector_error_total{reason=netlink_truncated}"

	// max_recv_buf_bytes_after_doubling is the effective ceiling applied when
	// doubling the receive buffer. Prevents runaway allocation.
	max_recv_buf_bytes_after_doubling: 8388608 // 8 MiB (2 x 4 MiB default)
}

// ---------------------------------------------------------------------------
// NLM_F_DUMP_INTR restart semantics
// ---------------------------------------------------------------------------

// #DumpIntrPolicy documents the dump-interrupt restart semantics enforced by
// nft_exporter_netlink_socket. NLM_F_DUMP_INTR (bit 4 of nlmsg_flags) signals
// that the underlying kernel data structure was modified during the dump.
#DumpIntrPolicy: {
	// check_on_every_frame: the DUMP_INTR bit must be checked on every received
	// nlmsghdr frame in the dump sequence, not only on the NLMSG_DONE frame.
	// A missed DUMP_INTR on an intermediate RTM_NEW* frame yields stale data.
	check_on_every_frame: true

	// discard_on_intr: when DUMP_INTR is detected, all accumulated ReadModel
	// state for the current dump is discarded before restarting.
	discard_on_intr: true

	// max_restarts_before_stale: after this many consecutive INTR restarts,
	// the collector returns CollectorError::DumpIntr and the stale snapshot
	// is served for this scrape epoch. Configurable via netlink_dump_max_restarts.
	max_restarts_before_stale: #DumpMaxRestarts

	// error_reason: the reason string incremented in nft_scrape_collector_error_total
	// when the restart cap is exceeded.
	error_reason: "dump_intr"
}

// ---------------------------------------------------------------------------
// Socket lifecycle per adapter
// ---------------------------------------------------------------------------

// #AdapterSocketAssignment documents which AF_NETLINK family each adapter uses.
// Each adapter crate opens exactly one socket per family via nft_exporter_netlink_socket.
// The NETLINK_ROUTE socket is shared for both RTM_GET* and RTM_GETQDISC dumps
// (serialized within TcNetlinkAdapter; never concurrent with RtnetlinkAdapter).
#AdapterSocketAssignment: {
	// rtnetlink_adapter uses NETLINK_ROUTE (0) for RTM_GETLINK, RTM_GETADDR,
	// RTM_GETROUTE, and RTM_GETNEIGH dumps.
	rtnetlink_adapter: 0   // NETLINK_ROUTE

	// tc_adapter uses NETLINK_ROUTE (0) for RTM_GETQDISC dump.
	// NOTE: rtnetlink_adapter and tc_adapter share the same NETLINK_ROUTE
	// family but use separate socket file descriptors; they are never
	// multiplexed on a single fd.
	tc_adapter: 0          // NETLINK_ROUTE

	// conntrack_adapter uses NETLINK_NETFILTER (12) for CT_GET_STATS_CPU,
	// CT_GET_STATS, and CT_GET dump requests. After rustables removal,
	// the NftablesAdapter also uses NETLINK_NETFILTER (12) for nfnetlink
	// (NFT_MSG_GETTABLE / NFT_MSG_GETCHAIN / NFT_MSG_GETRULE / NFT_MSG_GETCOUNTER).
	conntrack_adapter: 12  // NETLINK_NETFILTER

	// nftables_adapter uses NETLINK_NETFILTER (12) — see conntrack_adapter note.
	nftables_adapter: 12   // NETLINK_NETFILTER

	// sock_diag_adapter uses NETLINK_SOCK_DIAG (4) for SOCK_DIAG_BY_FAMILY dumps
	// across AF_INET and AF_INET6 for TCP, UDP, and UDPLite.
	sock_diag_adapter: 4   // NETLINK_SOCK_DIAG

	// ethtool_adapter uses NETLINK_GENERIC (16) for CTRL_CMD_GETFAMILY
	// (ethtool family id resolution) and all ETHTOOL_MSG_* requests.
	// One socket per adapter instance; family id cached in OnceLock<u16>.
	ethtool_adapter: 16    // NETLINK_GENERIC
}
