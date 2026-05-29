// DDD role: AggregateRoot
package schemas

// #OperState enumerates RFC-2863 operational states as reported by the kernel
// in IFLA_OPERSTATE (IF_OPER_* values from linux/if.h).
#OperState:
	"unknown" |
	"notpresent" |
	"down" |
	"lowerlayerdown" |
	"testing" |
	"dormant" |
	"up"

// #LinkType enumerates the ARPHRD_* hardware type strings as reported by
// the kernel in IFLA_LINK. Values are the lower-cased ARPHRD constant suffix.
#LinkType: "ether" | "loopback" | "noarp" | "infiniband" | "tunnel" | "tunnel6" | "sit" | "gre" | "ip6gre" | "ipip" | "ppp" | "void"

// #IfFlags is a non-empty hex string encoding the IFLA_FLAGS bitmask
// (IFF_UP, IFF_BROADCAST, IFF_LOOPBACK, etc.) as reported by the kernel.
// Format example: "0x1043" (IFF_UP | IFF_BROADCAST | IFF_MULTICAST | IFF_RUNNING).
#IfFlags: =~"^0x[0-9a-fA-F]+$"

// #IfIndex is the kernel interface index. MUST be a strictly positive integer.
// Matches the IFLA_LINK attribute value used as the Link identity.
#IfIndex: >0

// #MacAddress is a non-empty string in colon-separated lowercase hex notation.
// Example: "52:54:00:ab:cd:ef". Empty string is used for non-Ethernet interfaces.
#MacAddress: =~"^([0-9a-f]{2}:){5}[0-9a-f]{2}$" | ""

// #Mtu is the link MTU in bytes. Valid range: 68 (IPv4 minimum) to 65535.
#Mtu: >=68 & <=65535

// #IfStats64 holds the IFLA_STATS64 counter values for one interface.
// All counter fields are monotonically non-decreasing since interface creation
// (or last interface down/up cycle for drivers that reset on down).
#IfStats64: {
	rx_bytes:      uint64
	tx_bytes:      uint64
	rx_packets:    uint64
	tx_packets:    uint64
	rx_errors:     uint64
	tx_errors:     uint64
	rx_dropped:    uint64
	tx_dropped:    uint64
	multicast:     uint64
	collisions:    uint64
	rx_length_errors: uint64
	rx_over_errors:   uint64
	rx_crc_errors:    uint64
	rx_frame_errors:  uint64
	rx_fifo_errors:   uint64
	rx_missed_errors: uint64
	tx_aborted_errors:  uint64
	tx_carrier_errors:  uint64
	tx_fifo_errors:     uint64
	tx_heartbeat_errors: uint64
	tx_window_errors:    uint64
}

// #LinkAddress is an IP address (IPv4 or IPv6 CIDR string) assigned to a Link.
#LinkAddress: =~"^[0-9a-fA-F:.]+/[0-9]+$"

// #AddressList is the list of IP addresses currently assigned to a Link.
// Invariant: when #Link.operstate == "up", this list MUST be non-empty
// (at minimum a link-local IPv6 address or the loopback address is present).
#AddressList: [...#LinkAddress]

// #Link is the AggregateRoot for a Linux network interface.
// Identity: ifindex. An ifindex is unique within a network namespace
// for the lifetime of the interface. Links are never updated in-place;
// the RtnetlinkCollector produces a fresh LinkSnapshot each scrape epoch.
#Link: {
	// ifindex is the stable kernel interface index (identity of this aggregate).
	ifindex: #IfIndex

	// name is the interface name (e.g. "eth0", "lo", "bond0").
	name: string & !=""

	// alias is the optional IFLA_IFALIAS string. Empty when not set.
	alias: string

	// link_type is the ARPHRD hardware type.
	link_type: #LinkType

	// operstate is the RFC-2863 operational state.
	operstate: #OperState

	// flags is the IFLA_FLAGS bitmask as a hex string.
	flags: #IfFlags

	// mac_address is the hardware address. Empty for non-Ethernet interfaces.
	mac_address: #MacAddress

	// mtu_bytes is the current MTU.
	mtu_bytes: #Mtu

	// speed_bits is the link speed in bits per second; -1 when unknown or
	// not applicable (loopback, tunnel interfaces).
	speed_bits: int & >=-1

	// stats is the IFLA_STATS64 snapshot. Absent when the driver does not
	// support IFLA_STATS64 (extremely rare on modern kernels).
	stats?: #IfStats64

	// addresses is the list of IP addresses configured on this interface.
	// Non-empty invariant is enforced at the collector level for operstate=up.
	addresses: #AddressList

	// Invariant: when operstate is "up", addresses must contain at least one entry.
	if operstate == "up" {
		addresses: [_, ...]
	}
}
