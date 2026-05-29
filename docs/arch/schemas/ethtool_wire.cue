// DDD role: ValueObject
package schemas

// ---------------------------------------------------------------------------
// ethtool_wire.cue — wire-level value objects for the ETHTOOL genetlink path
//
// These types represent the kernel uapi structures that cross the NETLINK_GENERIC
// socket boundary. They are pure value objects: no methods, no mutation, no
// infrastructure imports. The EthtoolAdapter in nft_exporter_adapter_ethtool
// deserialises kernel bytes into these types; the EthtoolCollector translates
// them into NicStatSnapshot (see nic_stat_snapshot.cue).
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Generic-netlink control (family resolution)
// ---------------------------------------------------------------------------

// #GenlMsgHdr is the generic-netlink message header that follows the standard
// nlmsghdr in every NETLINK_GENERIC datagram. Layout (4 bytes, no padding):
//   cmd:      u8  — the genetlink command (e.g. CTRL_CMD_GETFAMILY = 3)
//   version:  u8  — protocol version (1 for ethtool, 2 for generic control)
//   reserved: u16 — must be zero; kernel ignores on receive, writes zero on reply
//
// The kernel reads this header before dispatching to the family op table. Any
// message sent to the ethtool family MUST use genlmsghdr with version = 1.
#GenlMsgHdr: {
	// cmd is the genetlink command code. Encoded as u8 native-endian on wire.
	cmd: uint8

	// version is the family-specific protocol version. For the ethtool family
	// this is always 1 (ETHTOOL_GENL_VERSION). For the control family it is 2.
	version: uint8

	// reserved must always be 0.
	reserved: uint16 & 0
}

// #CtrlCmd enumerates the NETLINK_GENERIC control commands used during family
// resolution. Source: include/uapi/linux/genetlink.h CTRL_CMD_*.
#CtrlCmd:
	1 | // CTRL_CMD_NEWFAMILY
	2 | // CTRL_CMD_DELFAMILY
	3 | // CTRL_CMD_GETFAMILY  — the one we send
	4 | // CTRL_CMD_NEWOPS
	5 | // CTRL_CMD_DELOPS
	6   // CTRL_CMD_GETOPS

// #CtrlCmdGetFamily is the command value for family resolution requests.
// Send genlmsghdr{cmd: 3, version: 2, reserved: 0} to family id 16 with
// CTRL_ATTR_FAMILY_NAME = "ethtool\0" to resolve the dynamic family id.
#CtrlCmdGetFamily: 3 & #CtrlCmd

// #GenlCtrlFamilyId is the well-known, static family id for the genetlink
// control family (GENL_ID_CTRL = 16). This is the ONLY genetlink family whose
// id is fixed. All other families (including ethtool) must be resolved via it.
#GenlCtrlFamilyId: 16

// #CtrlAttrType enumerates the netlink attribute types used in CTRL_CMD_GETFAMILY
// responses. Source: include/uapi/linux/genetlink.h CTRL_ATTR_*.
#CtrlAttrType:
	1 | // CTRL_ATTR_FAMILY_ID    — u16, the resolved dynamic family id
	2 | // CTRL_ATTR_FAMILY_NAME  — NUL-terminated string ("ethtool\0")
	3 | // CTRL_ATTR_VERSION      — u32
	4 | // CTRL_ATTR_HDRSIZE      — u32
	5 | // CTRL_ATTR_MAXATTR      — u32
	6 | // CTRL_ATTR_OPS          — nested ops table
	7   // CTRL_ATTR_MCAST_GROUPS — nested multicast group table

// #EthtoolFamilyName is the NUL-terminated family name sent in
// CTRL_ATTR_FAMILY_NAME when resolving the ethtool genetlink family.
// The kernel compares this against registered family names case-sensitively.
#EthtoolFamilyName: "ethtool"

// #ResolvedFamilyId is the result of CTRL_CMD_GETFAMILY: the dynamic u16
// assigned to the ethtool family by the kernel at boot. Typical values on a
// Linux 5.15–6.x kernel are in the range 25–35, but must never be assumed;
// always resolve at runtime and cache in a OnceLock<u16>.
#ResolvedFamilyId: >=16 & <=65535 & uint16

// ---------------------------------------------------------------------------
// Ethtool genetlink message types (commands)
// ---------------------------------------------------------------------------

// #EthtoolCmd enumerates the ethtool genetlink command codes used by this
// exporter. Source: include/uapi/linux/ethtool_netlink.h ETHTOOL_MSG_*_GET.
// The full enum has > 40 values; only the subset this exporter sends is listed.
#EthtoolCmd:
	1  | // ETHTOOL_MSG_STRSET_GET         — string set (driver -S names; not used)
	4  | // ETHTOOL_MSG_LINKSETTINGS_GET   — link speed, duplex, autoneg, port
	11 | // ETHTOOL_MSG_PAUSE_GET          — PAUSE frame counters
	21 | // ETHTOOL_MSG_FEC_GET            — FEC corrected/uncorrected per lane
	37   // ETHTOOL_MSG_STATS_GET          — standard stat groups (primary path)

// #EthtoolMsgStatsGet is the command code for the standard stats query.
// Requires kernel >= 5.12. Supports NLM_F_DUMP to enumerate all interfaces.
#EthtoolMsgStatsGet: 37 & #EthtoolCmd

// #EthtoolMsgLinkSettingsGet is the command code for link settings.
// Used in unicast mode (one request per interface, ETHTOOL_A_HEADER_DEV_INDEX).
#EthtoolMsgLinkSettingsGet: 4 & #EthtoolCmd

// #EthtoolMsgPauseGet is the command code for PAUSE frame statistics.
#EthtoolMsgPauseGet: 11 & #EthtoolCmd

// #EthtoolMsgFecGet is the command code for FEC per-lane statistics.
#EthtoolMsgFecGet: 21 & #EthtoolCmd

// ---------------------------------------------------------------------------
// Request header attribute (ETHTOOL_A_HEADER_*)
// ---------------------------------------------------------------------------

// #EthtoolHeaderAttr enumerates nested attributes inside ETHTOOL_A_*_HEADER.
// Source: include/uapi/linux/ethtool_netlink.h ETHTOOL_A_HEADER_*.
// The header nest identifies the target interface and request flags.
#EthtoolHeaderAttr:
	1 | // ETHTOOL_A_HEADER_DEV_INDEX  — u32 ifindex; 0 = dump all
	2 | // ETHTOOL_A_HEADER_DEV_NAME   — string; alternative to dev_index
	3   // ETHTOOL_A_HEADER_FLAGS      — u32; ETHTOOL_FLAG_COMPACT_BITSETS etc.

// #EthtoolHeaderDevIndex is the attribute type for the interface index inside
// the request header nest. Value 0 requests a dump of all interfaces.
// For unicast requests, set to the target ifindex (u32 native-endian).
#EthtoolHeaderDevIndex: 1 & #EthtoolHeaderAttr

// ---------------------------------------------------------------------------
// Stats message attributes (ETHTOOL_A_STATS_*)
// ---------------------------------------------------------------------------

// #EthtoolStatsAttr enumerates the top-level attributes of ETHTOOL_MSG_STATS_*.
// Source: include/uapi/linux/ethtool_netlink.h ETHTOOL_A_STATS_*.
#EthtoolStatsAttr:
	1 | // ETHTOOL_A_STATS_HEADER  — nested header (dev_index, flags)
	2 | // ETHTOOL_A_STATS_GROUPS  — u32 bitmask of requested stat groups
	3   // ETHTOOL_A_STATS_GRP     — nested; repeated once per group in reply

// #EthtoolStatsGroups is the bitmask value sent in ETHTOOL_A_STATS_GROUPS.
// Source: include/uapi/linux/ethtool_netlink.h enum ethtool_stats_eth_*.
// This exporter requests all four standard groups simultaneously.
#EthtoolStatsGroups: {
	// eth_mac corresponds to ETH_STATS_ETH_MAC (bit 0) — IEEE 802.3 MAC counters:
	// FramesTransmittedOK, SingleCollisionFrames, MultipleCollisionFrames,
	// FramesReceivedOK, FrameCheckSequenceErrors, AlignmentErrors,
	// OctetsTransmittedOK, FramesWithDeferredXmissions, LateCollisions,
	// FramesAbortedDueTXCSMACOLLISIONS, FramesLostDueTXInternalMACError,
	// CarrierSenseErrors, OctetsReceivedOK, FramesLostDueRXInternalMACError,
	// MulticastFramesXmittedOK, BroadcastFramesXmittedOK, FramesWithExcessiveDeferral,
	// MulticastFramesReceivedOK, BroadcastFramesReceivedOK, InRangeLengthErrors,
	// OutOfRangeLengthField, FrameTooLongErrors.
	eth_mac: bool

	// eth_phy corresponds to ETH_STATS_ETH_PHY (bit 1) — IEEE 802.3 PHY counters:
	// SymbolErrorDuringCarrier, etc.
	eth_phy: bool

	// eth_ctrl corresponds to ETH_STATS_ETH_CTRL (bit 2) — 802.3 MAC CTRL counters:
	// MACControlFramesTransmitted, MACControlFramesReceived,
	// UnsupportedOpcodesReceived.
	eth_ctrl: bool

	// rmon corresponds to ETH_STATS_RMON (bit 3) — RMON histogram counters:
	// etherStatsPkts64Octets through etherStatsPkts1024to1518Octets (rx and tx).
	rmon: bool
}

// #EthtoolStatsGroupsMask is the u32 bitmask requesting all four groups.
// Bit layout: eth_mac=bit0 eth_phy=bit1 eth_ctrl=bit2 rmon=bit3.
// Value 0x0F selects all four groups. Sent little-endian in the nlattr payload.
#EthtoolStatsGroupsMask: 0x0F

// #EthtoolStatsGrpAttr enumerates attributes inside an ETHTOOL_A_STATS_GRP nest.
// Source: include/uapi/linux/ethtool_netlink.h ETHTOOL_A_STATS_GRP_*.
#EthtoolStatsGrpAttr:
	1 | // ETHTOOL_A_STATS_GRP_PAD      — zero pad
	2 | // ETHTOOL_A_STATS_GRP_ID       — u32 group id (eth_mac=0 phy=1 ctrl=2 rmon=3)
	3 | // ETHTOOL_A_STATS_GRP_SS_ID    — u32 string-set id for this group
	4 | // ETHTOOL_A_STATS_GRP_STAT     — nested; one per stat counter
	5   // ETHTOOL_A_STATS_GRP_HIST_RX  — nested RMON histogram (rx)

// #EthtoolStatsGrpStatAttr enumerates attributes inside an ETHTOOL_A_STATS_GRP_STAT nest.
// Each such nest carries exactly one named counter value.
#EthtoolStatsGrpStatAttr:
	1 | // ETHTOOL_A_STATS_GRP_STAT_PAD   — zero pad
	2 | // ETHTOOL_A_STATS_GRP_STAT_NAME  — NUL-terminated string (uapi-stable name)
	3   // ETHTOOL_A_STATS_GRP_STAT_VALUE — u64 little-endian counter value

// ---------------------------------------------------------------------------
// Link settings attributes (ETHTOOL_A_LINKSETTINGS_*)
// ---------------------------------------------------------------------------

// #EthtoolLinkSettingsAttr enumerates attributes of ETHTOOL_MSG_LINKSETTINGS_*.
// Source: include/uapi/linux/ethtool_netlink.h ETHTOOL_A_LINKSETTINGS_*.
// Only the subset decoded by this exporter is listed.
#EthtoolLinkSettingsAttr:
	1  | // ETHTOOL_A_LINKSETTINGS_HEADER   — nested header
	2  | // ETHTOOL_A_LINKSETTINGS_SPEED    — u32 Mbps; SPEED_UNKNOWN = 0xFFFFFFFF
	3  | // ETHTOOL_A_LINKSETTINGS_DUPLEX   — u8; 0=half 1=full 255=unknown
	4  | // ETHTOOL_A_LINKSETTINGS_PORT     — u8; 0=tp 1=aui 2=mii 3=fibre 4=bnc 5=da 239=none 255=other
	5  | // ETHTOOL_A_LINKSETTINGS_PHYAD    — u8 PHY address
	6  | // ETHTOOL_A_LINKSETTINGS_TRANSCEIVER — u8
	7    // ETHTOOL_A_LINKSETTINGS_AUTONEG  — u8; 0=off 1=on

// #LinkSpeedUnknown is the sentinel value returned in ETHTOOL_A_LINKSETTINGS_SPEED
// when the driver reports no valid speed. The adapter maps this to the string "unknown"
// in LinkSettings.speed rather than emitting 4294967295 in the metric.
#LinkSpeedUnknown: 0xFFFFFFFF & uint32

// ---------------------------------------------------------------------------
// PAUSE stats attributes (ETHTOOL_A_PAUSE_STAT_*)
// ---------------------------------------------------------------------------

// #EthtoolPauseStatAttr enumerates attributes inside the PAUSE stats nest.
// Source: include/uapi/linux/ethtool_netlink.h ETHTOOL_A_PAUSE_STAT_*.
#EthtoolPauseStatAttr:
	1 | // ETHTOOL_A_PAUSE_STAT_PAD        — zero pad
	2 | // ETHTOOL_A_PAUSE_STAT_TX_FRAMES  — u64
	3   // ETHTOOL_A_PAUSE_STAT_RX_FRAMES  — u64

// ---------------------------------------------------------------------------
// FEC stats attributes (ETHTOOL_A_FEC_STAT_*)
// ---------------------------------------------------------------------------

// #EthtoolFecStatAttr enumerates attributes inside the FEC stats nest.
// Source: include/uapi/linux/ethtool_netlink.h ETHTOOL_A_FEC_STAT_*.
// FEC counters are keyed by lane index (0-based) in nested lane entries.
#EthtoolFecStatAttr:
	1 | // ETHTOOL_A_FEC_STAT_PAD          — zero pad
	2 | // ETHTOOL_A_FEC_STAT_CORRECTED    — nested u64 per lane
	3   // ETHTOOL_A_FEC_STAT_UNCORR       — nested u64 per lane (not collected)

// ---------------------------------------------------------------------------
// Wire layout: nlattr TLV framing
// ---------------------------------------------------------------------------

// #NlAttrHdr represents the 4-byte header prepended to every netlink attribute.
// Layout on wire (little-endian, 4-byte aligned total including payload):
//   nla_len:  u16 — total length including this 4-byte header
//   nla_type: u16 — attribute type; top two bits carry NLA_F_NESTED (bit 15)
//                   and NLA_F_NET_BYTEORDER (bit 14) flags
//
// Nested attributes set NLA_F_NESTED (0x8000) in nla_type. The adapter must
// strip this flag before comparing against #EthtoolStatsAttr values.
#NlAttrHdr: {
	// nla_len is the total byte length of the attribute: 4 (header) + payload + pad.
	nla_len: uint16

	// nla_type is the attribute type code. Strip 0x8000 (NLA_F_NESTED) before
	// matching. Nested attributes may not have NLA_F_NET_BYTEORDER set.
	nla_type: uint16
}

// #NlaAlignment is the required alignment of each nlattr in bytes. Every nlattr
// starts at an offset that is a multiple of 4. The padding bytes between
// attributes are zero-filled by the kernel and must be skipped by the parser.
#NlaAlignment: 4

// ---------------------------------------------------------------------------
// veth-specific probe notes (grounded against real probe data)
// ---------------------------------------------------------------------------

// #VethSupportedStats lists the ethtool stats that a veth interface DOES support
// via standard genetlink. veth does NOT implement the four standard groups
// (eth-mac, eth-phy, eth-ctrl, rmon); ETHTOOL_MSG_STATS_GET returns EOPNOTSUPP.
// However veth exposes three non-group stats visible via ethtool crate probes:
//   peer_ifindex  — the ifindex of the veth peer (not a stat group counter)
//   xdp.*         — XDP drop/error/pass counts when an XDP program is attached
//   page_pool.*   — page pool memory reclaim counters when page_pool is active
//
// These are accessible only via ETHTOOL_MSG_STRSET_GET (driver -S path) which
// this exporter intentionally does not use. Therefore veth interfaces return
// EOPNOTSUPP for all ETHTOOL_MSG_STATS_GET group requests and are skipped.
#VethSupportedStats: {
	// standard_groups_supported indicates whether veth supports the four standard
	// stat groups. This is always false; veth returns EOPNOTSUPP for STATS_GET.
	standard_groups_supported: false

	// driver_strings_only indicates that the only stats veth exposes are
	// driver -S strings (peer_ifindex, xdp.*, page_pool.*). Since this exporter
	// does not collect driver strings, no nft_ethtool_stat series are emitted
	// for any veth interface.
	driver_strings_only: true
}

// ---------------------------------------------------------------------------
// Cardinality notes for standard stat groups
// ---------------------------------------------------------------------------

// #StandardGroupStatCount is the approximate maximum number of named stats
// returned per interface per group when all four groups are requested.
// These counts are derived from kernel 6.x uapi definitions:
//   eth-mac: 22 counters (IEEE 802.3 Clause 30)
//   eth-phy:  6 counters
//   eth-ctrl: 3 counters
//   rmon:    28 counters (rx histogram + tx histogram, 7 buckets each x 2)
// Total per interface: ~59. Used to derive #NicStatSnapshot cardinality_bound.
#StandardGroupStatCount: {
	eth_mac:  22
	eth_phy:  6
	eth_ctrl: 3
	rmon:     28
	total:    59
}
