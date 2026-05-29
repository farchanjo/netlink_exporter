// DDD role: ReadModel
package schemas

// #SockProtocol enumerates the layer-4 protocols reported by SOCK_DIAG_BY_FAMILY.
// Only tcp, udp, and udplite are collected; raw sockets are excluded by design
// (CAP_NET_RAW is not requested).
#SockProtocol: "tcp" | "udp" | "udplite"

// #TcpState enumerates the TCP socket state strings derived from the
// inet_diag_msg.idiag_state field (TCP_* kernel constants).
#TcpState:
	"established" |
	"syn_sent" |
	"syn_recv" |
	"fin_wait1" |
	"fin_wait2" |
	"time_wait" |
	"close" |
	"close_wait" |
	"last_ack" |
	"listen" |
	"closing" |
	"new_syn_recv"

// #UdpState enumerates the state strings emitted for UDP and UDPLite sockets.
// The kernel always reports state=7 (CLOSE) for UDP; mapped to "unconnected"
// to avoid confusion with TCP CLOSE semantics.
#UdpState: "unconnected"

// #SocketState is the union of all state strings used as the "state" label.
// TCP sockets may be in any #TcpState; UDP/UDPLite sockets emit only "unconnected".
#SocketState: #TcpState | #UdpState

// #SocketBucket is the aggregation key for one (protocol, state) socket bucket.
#SocketBucket: {
	protocol: #SockProtocol
	state:    #SocketState
}

// #SocketCountEntry holds aggregated socket statistics for one (protocol, state)
// bucket. Maps directly to nft_socket_count, nft_socket_receive_queue_bytes,
// and nft_socket_send_queue_bytes gauge metric families.
//
// CRITICAL invariant: individual socket inodes, ports, and addresses are NEVER
// stored in this ReadModel. Only aggregated totals per bucket are retained.
#SocketCountEntry: {
	// bucket is the (protocol, state) aggregation key.
	bucket: #SocketBucket

	// count is the number of sockets in this (protocol, state) bucket.
	// Maps to nft_socket_count gauge.
	count: uint64

	// recv_queue_bytes is the sum of idiag_rqueue across all sockets in this bucket.
	// Maps to nft_socket_receive_queue_bytes gauge.
	recv_queue_bytes: uint64

	// send_queue_bytes is the sum of idiag_wqueue across all sockets in this bucket.
	// Maps to nft_socket_send_queue_bytes gauge.
	send_queue_bytes: uint64
}

// #SocketDropEntry holds the per-protocol aggregated drop count sourced from
// INET_DIAG_SKMEMINFO skmem_drop. Maps to nft_socket_drops_total counter.
#SocketDropEntry: {
	protocol: #SockProtocol
	drops:    uint64
}

// #SocketRetransmitEntry holds the TCP retransmit count aggregated across
// all TCP sockets (INET_DIAG_INFO tcpi_retransmits sum).
// Maps to nft_socket_retransmits_total counter. TCP-only; no UDP entry.
#SocketRetransmitEntry: {
	protocol: "tcp"
	retransmits: uint64
}

// #SocketStateHistogram is the immutable ReadModel produced by SockDiagCollector
// for the SOCK_DIAG_BY_FAMILY (AF_INET, AF_INET6) subsystem in one scrape epoch.
//
// Invariants:
//   - UDP and UDPLite entries appear only with state="unconnected".
//   - No per-socket, per-port, or per-address data is present.
//   - retransmits contains at most one entry (tcp protocol).
#SocketStateHistogram: {
	// epoch_ns is the Unix nanosecond timestamp when this snapshot was captured.
	epoch_ns: uint64

	// buckets is the list of (protocol, state) socket count entries.
	// Cardinality bound: ~24 entries (3 protocols x up to 8 states for TCP;
	// UDP/UDPLite emit only 1 state each).
	buckets: [...#SocketCountEntry]

	// drops is the per-protocol aggregated socket drop list.
	// Cardinality bound: ~3 entries (one per protocol).
	drops: [...#SocketDropEntry]

	// retransmits holds TCP retransmit totals. At most one entry.
	retransmits: [...#SocketRetransmitEntry]
}
