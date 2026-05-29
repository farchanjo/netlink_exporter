// DDD role: ReadModel
package schemas

// ---------------------------------------------------------------------------
// wireguard_snapshot.cue — wire-level value objects and ReadModel for the
// WireGuard generic-netlink bounded context.
//
// These types span two DDD concerns:
//   ValueObject — kernel uapi wire structures decoded by WireguardAdapter
//   ReadModel   — immutable WireguardSnapshot consumed by MetricRegistryPort
//
// DDD role header above designates the aggregate role of this file (ReadModel)
// because the dominant consumer is MetricRegistryPort. The individual wire
// ValueObjects are subordinate parsing artifacts used only within the adapter.
//
// Wire path: NETLINK_GENERIC socket -> CTRL_CMD_GETFAMILY "wireguard" ->
//   WG_CMD_GET_DEVICE dump -> WireguardAdapter -> WireguardSnapshot ->
//   MetricRegistryPort -> nft_wireguard_* OpenMetrics text
//
// ADR reference: ADR-0018 (wireguard bounded context, direct genetlink,
//   runtime-gated). Protocol reference: section 12 of netlink-protocol.md.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Generic-netlink command codes for the WireGuard family
// ---------------------------------------------------------------------------

// #WgCmd enumerates the WireGuard generic-netlink command codes.
// Source: include/uapi/linux/wireguard.h WG_CMD_*.
// The family uses version=1 in genlmsghdr for all commands.
#WgCmd:
	0 | // WG_CMD_GET_DEVICE — get a single interface (NLM_F_DUMP) identified by
	    //                     exactly one of WGDEVICE_A_IFNAME / WGDEVICE_A_IFINDEX
	1   // WG_CMD_SET_DEVICE — configure a WireGuard device (never used by exporter)

// #WgCmdGetDevice is the command value for the per-interface dump request.
// WG_CMD_GET_DEVICE has NO dump-all form: lookup_interface() returns -EBADR
// (errno 53) unless exactly one of WGDEVICE_A_IFNAME / WGDEVICE_A_IFINDEX is
// present. The exporter therefore enumerates WireGuard interfaces first via an
// RTM_GETLINK dump (IFLA_INFO_KIND == "wireguard") and issues one filtered
// WG_CMD_GET_DEVICE dump (with WGDEVICE_A_IFNAME) per interface.
#WgCmdGetDevice: 0 & #WgCmd

// #WgFamilyName is the NUL-terminated name sent in CTRL_ATTR_FAMILY_NAME
// when resolving the WireGuard generic-netlink family via CTRL_CMD_GETFAMILY.
// The kernel compares this byte-for-byte against the registered family name.
#WgFamilyName: "wireguard"

// #WgGenlVersion is the version field in genlmsghdr for all WG_CMD_* requests.
// Source: include/uapi/linux/wireguard.h WG_GENL_VERSION = 1.
// Sending version != 1 causes EINVAL.
#WgGenlVersion: 1

// ---------------------------------------------------------------------------
// Top-level device attribute types (WGDEVICE_A_*)
// ---------------------------------------------------------------------------

// #WgDeviceAttr enumerates top-level nlattr types in WG_CMD_GET_DEVICE replies.
// Source: include/uapi/linux/wireguard.h WGDEVICE_A_*.
// All values are native-endian unless noted. NLA_F_NESTED (bit 15) is set on
// nested attributes; strip before comparing (same rule as ethtool, [G-02]).
#WgDeviceAttr:
	0 | // WGDEVICE_A_UNSPEC        — padding; ignore
	1 | // WGDEVICE_A_IFINDEX       — u32 LE interface index
	2 | // WGDEVICE_A_IFNAME        — NUL-terminated ASCII interface name
	3 | // WGDEVICE_A_PRIVATE_KEY   — 32 bytes curve25519 key (FORBIDDEN as label)
	4 | // WGDEVICE_A_PUBLIC_KEY    — 32 bytes curve25519 key (used for peer-map lookup only)
	5 | // WGDEVICE_A_FLAGS         — u32 LE bitmask
	6 | // WGDEVICE_A_LISTEN_PORT   — u16 LE UDP listen port; 0 when not bound
	7 | // WGDEVICE_A_FWMARK        — u32 LE firewall mark; 0 when not set
	8   // WGDEVICE_A_PEERS         — nested list of WGPEER_A_* nests (NLA_F_NESTED)

// #WgDeviceIfname is the attribute type for the interface name string.
// Decoded as NUL-terminated UTF-8; trailing NUL stripped before use.
// Used as the `interface` label value in all nft_wireguard_* metric families.
#WgDeviceIfname: 2 & #WgDeviceAttr

// #WgDeviceListenPort is the attribute type for the UDP listen port.
// Encoded as u16 native-endian. Value 0 means the device is not listening.
// Emitted as the `listen_port` label in nft_wireguard_device_info.
#WgDeviceListenPort: 6 & #WgDeviceAttr

// #WgDeviceFwmark is the attribute type for the firewall mark.
// Encoded as u32 native-endian. Value 0 means no fwmark is set.
// Emitted as the `fwmark` label in nft_wireguard_device_info.
#WgDeviceFwmark: 7 & #WgDeviceAttr

// #WgDevicePeers is the attribute type for the nested peer list container.
// This attribute has NLA_F_NESTED set; strip bit 15 before type comparison.
// The payload is an nlattr chain where each sub-attribute is itself a nested
// WGPEER_A_* group (see #WgPeerAttr). Each sub-attribute represents one peer.
#WgDevicePeers: 8 & #WgDeviceAttr

// #WgDevicePrivateKeyAttr documents the WGDEVICE_A_PRIVATE_KEY attribute type.
// Its payload is 32 bytes of raw key material and MUST be discarded immediately
// after the nla_type is identified. The private key must never be stored, logged,
// or used as a Prometheus label (ADR-0009 privilege minimization;
// ADR-0005 cardinality and secrets policy).
#WgDevicePrivateKeyAttr: 3 & #WgDeviceAttr

// ---------------------------------------------------------------------------
// Per-peer attribute types (WGPEER_A_*)
// ---------------------------------------------------------------------------

// #WgPeerAttr enumerates nlattr types within one peer nest.
// Source: include/uapi/linux/wireguard.h WGPEER_A_*.
// Each peer is represented as a nested nlattr group inside WGDEVICE_A_PEERS.
// The exporter iterates WGDEVICE_A_PEERS sub-attributes; each one is a nested
// container whose payload is itself a WGPEER_A_* nlattr chain.
#WgPeerAttr:
	0 | // WGPEER_A_UNSPEC                       — padding; ignore
	1 | // WGPEER_A_PUBLIC_KEY                   — 32 bytes curve25519; identity input
	2 | // WGPEER_A_PRESHARED_KEY                — 32 bytes (FORBIDDEN as label)
	3 | // WGPEER_A_FLAGS                        — u32 LE bitmask
	4 | // WGPEER_A_ENDPOINT                     — sockaddr_in or sockaddr_in6 (presence only)
	5 | // WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL — u16 LE seconds; 0 = disabled
	6 | // WGPEER_A_LAST_HANDSHAKE_TIME           — timespec64: two u64 LE fields (tv_sec, tv_nsec)
	7 | // WGPEER_A_RX_BYTES                     — u64 LE cumulative receive bytes
	8 | // WGPEER_A_TX_BYTES                     — u64 LE cumulative transmit bytes
	9   // WGPEER_A_ALLOWEDIPS                   — nested list of allowed IP prefixes (not collected)

// #WgPeerPublicKey is the attribute type for the peer public key.
// The 32-byte payload is used exclusively as input to the peer identity hash
// function (SHA-256, first 8 bytes encoded as 16 lowercase hex characters).
// The raw bytes are never stored beyond the hash computation call site.
#WgPeerPublicKey: 1 & #WgPeerAttr

// #WgPeerEndpoint is the attribute type for the peer endpoint address.
// Payload is a sockaddr_in (16 bytes) or sockaddr_in6 (28 bytes).
// The exporter reads only the nla_len to detect presence; the address bytes
// are never decoded, stored, or used as a label (ADR-0005 cardinality:
// remote IP addresses are unbounded).
#WgPeerEndpoint: 4 & #WgPeerAttr

// #WgPeerPersistentKeepalive is the attribute type for keepalive interval.
// Encoded as u16 native-endian, in seconds. Value 0 means keepalive is
// disabled. Emitted as gauge nft_wireguard_peer_persistent_keepalive_seconds.
#WgPeerPersistentKeepalive: 5 & #WgPeerAttr

// #WgPeerLastHandshakeTime is the attribute type for the last handshake timestamp.
// Payload is a timespec64 struct: two u64 native-endian fields.
//   tv_sec  @ byte  0: Unix timestamp seconds of last completed handshake
//   tv_nsec @ byte  8: nanoseconds component (0 when no handshake yet)
// All-zero timespec (tv_sec=0, tv_nsec=0) means no handshake has ever completed.
// The adapter converts to handshake age in seconds: now_unix_seconds - tv_sec.
// When tv_sec=0 the gauge emits +Inf (see ADR-0018 consequences).
#WgPeerLastHandshakeTime: 6 & #WgPeerAttr

// #WgPeerRxBytes is the attribute type for cumulative receive bytes.
// Encoded as u64 native-endian. Monotonically increasing per kernel restart.
// Maps to counter nft_wireguard_peer_receive_bytes_total.
#WgPeerRxBytes: 7 & #WgPeerAttr

// #WgPeerTxBytes is the attribute type for cumulative transmit bytes.
// Encoded as u64 native-endian. Monotonically increasing per kernel restart.
// Maps to counter nft_wireguard_peer_transmit_bytes_total.
#WgPeerTxBytes: 8 & #WgPeerAttr

// ---------------------------------------------------------------------------
// Wire payload value objects
// ---------------------------------------------------------------------------

// #WgTimespec64 is the kernel timespec64 carried by WGPEER_A_LAST_HANDSHAKE_TIME.
// Both fields are encoded native-endian (u64 LE on x86-64/aarch64).
// Source: POSIX struct timespec with 64-bit tv_sec to avoid 2038 overflow.
#WgTimespec64: {
	// tv_sec is the Unix time in seconds of the last completed Noise handshake.
	// Value 0 indicates no handshake has ever completed for this peer.
	tv_sec: uint64

	// tv_nsec is the nanoseconds component of the timestamp.
	// Always 0 when tv_sec is 0 (no handshake).
	tv_nsec: uint64 & >=0 & <=999999999
}

// #WgPeerIdentityHash is the bounded peer identity label derived from the
// public key. It is computed as lowercase-hex(SHA-256(raw_pubkey_bytes)[0..8]).
// Exactly 16 characters; character set [0-9a-f]. The full 32-byte public key
// is never stored or emitted. When the operator provides a name map entry for
// the peer, the map value replaces this hash in the Prometheus label.
#WgPeerIdentityHash: =~"^[0-9a-f]{16}$"

// #WgPeerName is the operator-supplied human-readable name for a peer.
// Read from ExporterConfig.wireguard_peer_names (map keyed by base64url
// public key). Must match [a-zA-Z0-9_.-]{1,64} to be accepted; entries
// failing this pattern are rejected at config load time with a startup error.
#WgPeerName: =~"^[a-zA-Z0-9_.\\-]{1,64}$"

// #WgPeerLabel is the value of the `peer` Prometheus label dimension.
// Either the truncated-hash form or the operator-supplied name form.
#WgPeerLabel: #WgPeerIdentityHash | #WgPeerName

// #WgListenPort is the u16 UDP port on which a WireGuard device listens.
// Encoded native-endian. Value 0 means the device has no UDP socket open.
// Emitted as a string label in nft_wireguard_device_info.
#WgListenPort: uint16

// #WgFwmark is the u32 firewall mark applied to WireGuard tunnel packets.
// Value 0 means no fwmark is configured. Emitted as a string label.
#WgFwmark: uint32

// ---------------------------------------------------------------------------
// ReadModel: per-peer metrics snapshot
// ---------------------------------------------------------------------------

// #WgPeerSnapshot is an immutable ReadModel for one WireGuard peer within
// one scrape epoch. Produced by WireguardAdapter per peer in the genl dump;
// consumed by MetricRegistryPort to emit per-peer metric families.
//
// The public key raw bytes are absent: only the derived label is stored,
// preventing accidental logging of key material beyond the adapter boundary.
#WgPeerSnapshot: {
	// peer_label is the bounded Prometheus label value identifying this peer.
	// Either a 16-character truncated public-key hash or an operator name.
	peer_label: #WgPeerLabel

	// rx_bytes is the cumulative byte count received from this peer.
	// Source: WGPEER_A_RX_BYTES u64 native-endian. Maps to
	// nft_wireguard_peer_receive_bytes_total.
	rx_bytes: uint64

	// tx_bytes is the cumulative byte count transmitted to this peer.
	// Source: WGPEER_A_TX_BYTES u64 native-endian. Maps to
	// nft_wireguard_peer_transmit_bytes_total.
	tx_bytes: uint64

	// last_handshake_age_seconds is the number of seconds elapsed since the
	// most recent completed Noise handshake, computed as:
	//   now_unix_seconds - WGPEER_A_LAST_HANDSHAKE_TIME.tv_sec
	// Value is +Inf when tv_sec == 0 (peer has never completed a handshake).
	// Maps to gauge nft_wireguard_peer_last_handshake_seconds.
	last_handshake_age_seconds: number & >=0

	// persistent_keepalive_seconds is the configured keepalive interval in
	// seconds. Value 0 means keepalive is disabled. Maps to gauge
	// nft_wireguard_peer_persistent_keepalive_seconds.
	persistent_keepalive_seconds: uint16

	// endpoint_present is true when WGPEER_A_ENDPOINT is present in the wire
	// response (peer has a configured or learned endpoint address). false when
	// the attribute is absent (peer not yet roaming-resolved). Maps to gauge
	// nft_wireguard_peer_endpoint_present with values 1.0 / 0.0.
	endpoint_present: bool
}

// ---------------------------------------------------------------------------
// ReadModel: per-device metrics snapshot
// ---------------------------------------------------------------------------

// #WgDeviceSnapshot is an immutable ReadModel for one WireGuard device (wg
// interface) within one scrape epoch. Aggregates all peer snapshots for the
// device. Produced by WireguardAdapter once per WGDEVICE_A_* reply frame;
// consumed by MetricRegistryPort.
#WgDeviceSnapshot: {
	// interface_name is the WireGuard network interface name (WGDEVICE_A_IFNAME),
	// used as the `interface` label on all nft_wireguard_* metric families.
	interface_name: =~"^[a-zA-Z][a-zA-Z0-9_.-]{0,15}$"

	// listen_port is the UDP port the device is bound to (WGDEVICE_A_LISTEN_PORT).
	// Stringified for the `listen_port` label in nft_wireguard_device_info.
	// Value 0 is emitted as the string "0" (not bound).
	listen_port: #WgListenPort

	// fwmark is the firewall mark for tunnel packets (WGDEVICE_A_FWMARK).
	// Stringified for the `fwmark` label in nft_wireguard_device_info.
	// Value 0 is emitted as "0" (not set).
	fwmark: #WgFwmark

	// peers is the list of peer snapshots for this device, bounded by
	// ExporterConfig.wireguard_max_peers (default 1000 across all devices).
	peers: [...#WgPeerSnapshot]
}

// ---------------------------------------------------------------------------
// ReadModel: collector-level WireGuard snapshot
// ---------------------------------------------------------------------------

// #WireguardSnapshot is the top-level ReadModel produced by WireguardCollector
// and passed to MetricRegistryPort. Immutable; valid for exactly one scrape
// epoch.
#WireguardSnapshot: {
	// available indicates whether the WireGuard generic-netlink family was
	// successfully resolved at startup. When false, devices and all metric
	// families are empty; nft_scrape_collector_available{collector="wireguard"}
	// is 0. When true, devices contains one entry per WireGuard interface.
	available: bool

	// devices is the list of per-device snapshots collected in this scrape.
	// Empty when available is false or when no WireGuard interfaces exist.
	devices: [...#WgDeviceSnapshot]

	// peer_count_total is the total number of peer snapshots across all devices.
	// Used to enforce the wireguard_max_peers cardinality cap. When this value
	// equals ExporterConfig.wireguard_max_peers the collector increments
	// nft_scrape_collector_error_total{reason="cardinality_overflow"} and
	// activates the stale-snapshot fallback for the wireguard collector.
	peer_count_total: uint32
}

// ---------------------------------------------------------------------------
// Wire-to-metric mapping reference (documentation only — CUE struct)
// ---------------------------------------------------------------------------

// #WgMetricMapping documents the wire attribute to Prometheus metric mapping
// for each WireGuard metric family. This is a documentation struct only;
// the authoritative metric contract is in metric_contract.cue.
#WgMetricMapping: {
	// device_info_labels maps the nft_wireguard_device_info label dimensions
	// to their wire attribute sources.
	device_info_labels: {
		interface:   "WGDEVICE_A_IFNAME NUL-terminated string"
		listen_port: "WGDEVICE_A_LISTEN_PORT u16 LE stringified"
		fwmark:      "WGDEVICE_A_FWMARK u32 LE stringified"
	}

	// peer_metric_labels maps the label dimensions shared by all per-peer
	// metric families to their wire attribute sources.
	peer_metric_labels: {
		interface: "WGDEVICE_A_IFNAME of the enclosing device"
		peer:      "SHA-256(WGPEER_A_PUBLIC_KEY)[0..8] hex or wireguard_peer_names map value"
	}

	// byte_counters_source documents that both rx and tx byte counters are u64
	// native-endian values from WGPEER_A_RX_BYTES and WGPEER_A_TX_BYTES.
	// They are monotonically increasing since the WireGuard interface was
	// created (or the kernel module loaded); they do not reset on peer removal.
	byte_counters_source: "WGPEER_A_RX_BYTES / WGPEER_A_TX_BYTES u64 LE native-endian"

	// handshake_age_source documents the age computation for the last-handshake
	// gauge: age = ClockPort::now_unix_seconds() - WGPEER_A_LAST_HANDSHAKE_TIME.tv_sec.
	// Both fields in timespec64 are u64 LE. tv_sec=0 maps to +Inf gauge value.
	handshake_age_source: "now - WGPEER_A_LAST_HANDSHAKE_TIME.tv_sec; +Inf when tv_sec=0"
}

// ---------------------------------------------------------------------------
// Cardinality bounds for the wireguard bounded context
// ---------------------------------------------------------------------------

// #WgCardinalityBounds documents the worst-case series counts for the
// wireguard bounded context under default configuration.
#WgCardinalityBounds: {
	// device_info series: one per WireGuard interface; typical hosts have 1-4.
	device_info: "~16 one per WireGuard interface; bounded by network interface count"

	// per_peer_series: three metric families x peer count x interface count.
	// wireguard_max_peers (default 1000) caps total peers across all interfaces.
	per_peer_series: "~3000 per-peer counters+gauges x wireguard_max_peers=1000 default; bounded by config"

	// total_wireguard_series: device_info + per_peer_series * 5 metric families.
	total_wireguard_series: "~5016 absolute worst case at default wireguard_max_peers; well within ADR-0005 ceiling"
}
