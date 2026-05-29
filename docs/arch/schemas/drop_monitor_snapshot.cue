// DDD role: ReadModel
package schemas

// ---------------------------------------------------------------------------
// drop_monitor_snapshot.cue — wire-level value objects and ReadModel for the
// NET_DM generic-netlink subsystem (drop_monitor kernel module).
//
// These types represent the kernel uapi structures that cross the
// NETLINK_GENERIC / NET_DM socket boundary. They are pure value objects: no
// methods, no mutation, no infrastructure imports.
//
// The DropMonitorAdapter in nft_exporter_adapter_dm resolves the NET_DM family
// via CTRL_CMD_GETFAMILY, subscribes to the NET_DM_GRP_ALERT multicast group,
// issues NET_DM_CMD_MONITOR_START in summary mode, and deserialises incoming
// NET_DM_CMD_ALERT notifications into these types.
//
// The DropMonitorCollector translates the DropMonitorSnapshot into
// nft_drop_packets_total and nft_scrape_collector_available metric families.
//
// Reference kernel headers:
//   include/uapi/linux/net_dm.h      — NET_DM commands, attributes, groups
//   include/net/dropreason.h         — drop reason enum (kernel >= 5.17)
//   net/core/drop_monitor.c          — implementation
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Generic-netlink family resolution for NET_DM
// ---------------------------------------------------------------------------

// #NetDmFamilyName is the NUL-terminated family name used in
// CTRL_ATTR_FAMILY_NAME during CTRL_CMD_GETFAMILY resolution.
// The kernel compares this against registered family names case-sensitively.
// The drop_monitor module must be loaded for this family to be registered;
// ENOENT from CTRL_CMD_GETFAMILY indicates the module is absent.
#NetDmFamilyName: "NET_DM"

// #NetDmGrpAlert is the name of the multicast group that carries
// NET_DM_CMD_ALERT notifications. After family resolution, the adapter
// looks up this group name in CTRL_ATTR_MCAST_GROUPS to find the group ID,
// then calls bind() with nl_groups set to (1 << (group_id - 1)).
#NetDmGrpAlert: "NET_DM_GRP_ALERT"

// ---------------------------------------------------------------------------
// NET_DM commands (genlmsghdr.cmd values)
// ---------------------------------------------------------------------------

// #NetDmCmd enumerates the generic-netlink command codes for the NET_DM family.
// Source: include/uapi/linux/net_dm.h NET_DM_CMD_*.
// Only the subset used by this exporter is listed.
#NetDmCmd:
	0 | // NET_DM_CMD_UNSPEC         — ignore
	1 | // NET_DM_CMD_ALERT          — kernel -> user: drop event notification
	2 | // NET_DM_CMD_CONFIG         — user -> kernel: configure monitoring mode
	3 | // NET_DM_CMD_START          — user -> kernel: start monitoring
	4   // NET_DM_CMD_STOP           — user -> kernel: stop monitoring

// #NetDmCmdAlert is the command code for incoming drop alert notifications.
// The kernel sends these unsolicited on the NET_DM_GRP_ALERT multicast group
// after NET_DM_CMD_START has been issued.
#NetDmCmdAlert: 1 & #NetDmCmd

// #NetDmCmdConfig is the command code sent by the exporter to configure
// the monitoring mode before starting. Must be sent before NET_DM_CMD_START.
#NetDmCmdConfig: 2 & #NetDmCmd

// #NetDmCmdStart is the command code sent by the exporter to activate
// drop monitoring. The kernel begins aggregating or delivering drop events
// after this command is acknowledged.
#NetDmCmdStart: 3 & #NetDmCmd

// ---------------------------------------------------------------------------
// NET_DM top-level attribute types (net_dm_attr)
// ---------------------------------------------------------------------------

// #NetDmAttr enumerates the attribute type constants for NET_DM_CMD_ALERT and
// NET_DM_CMD_CONFIG messages. Source: include/uapi/linux/net_dm.h
// NET_DM_ATTR_*.
// Always strip NLA_F_NESTED (bit 15) before matching nla_type.
#NetDmAttr:
	0  | // NET_DM_ATTR_UNSPEC            — ignore
	1  | // NET_DM_ATTR_ALERT_MODE        — u8: per-packet(0) or summary(1)
	2  | // NET_DM_ATTR_PC                — u64: program counter of drop site (sw)
	3  | // NET_DM_ATTR_SYMBOL            — string: kernel symbol at drop site (sw)
	4  | // NET_DM_ATTR_IN_PORT           — nested: ingress port info
	5  | // NET_DM_ATTR_TIMESTAMP         — u64: nanoseconds since boot
	6  | // NET_DM_ATTR_PROTO             — u16: EtherType of dropped packet
	7  | // NET_DM_ATTR_PAYLOAD           — bytes: first N bytes of packet (truncated)
	8  | // NET_DM_ATTR_PAD               — alignment pad; ignore
	9  | // NET_DM_ATTR_TRUNC_LEN         — u32: number of bytes included in payload
	10 | // NET_DM_ATTR_ORIG_LEN          — u32: original packet length before truncation
	11 | // NET_DM_ATTR_QUEUE_LEN         — u32: event queue length
	12 | // NET_DM_ATTR_STATS             — nested: aggregate per-reason counters
	13 | // NET_DM_ATTR_HW_STATS          — nested: aggregate per-HW-trap counters
	14 | // NET_DM_ATTR_ORIGIN            — u16: SW=0 HW=1
	15 | // NET_DM_ATTR_HW_TRAP_GROUP_NAME — string: HW trap group name
	16 | // NET_DM_ATTR_HW_TRAP_NAME      — string: HW trap name (per-port label)
	17 | // NET_DM_ATTR_HW_ENTRIES        — nested: list of HW drop entries
	18 | // NET_DM_ATTR_HW_ENTRY          — nested: one HW entry (name + count)
	19 | // NET_DM_ATTR_HW_TRAP_COUNT     — u32: count for this HW trap entry
	20 | // NET_DM_ATTR_SW_DROPS          — nested: list of SW per-reason entries
	21 | // NET_DM_ATTR_HW_DROPS          — nested: list of HW per-trap entries
	22   // NET_DM_ATTR_REASON            — string: drop reason name (kernel >= 5.17)

// #NetDmAttrReason is the attribute type for the drop reason string in summary
// mode alerts. Payload is a NUL-terminated UTF-8 string (e.g.
// "NET_DM_REASON_TC_INGRESS", "NET_DM_REASON_CONNTRACK"). Kernel >= 5.17.
// Strip trailing NUL before use.
#NetDmAttrReason: 22 & #NetDmAttr

// #NetDmAttrNumDropped is the attribute type for the u64 counter carried in
// summary-mode alert frames. This count is the number of packets dropped with
// the associated reason since the last alert notification. Payload is u64
// native-endian (little-endian on x86-64/aarch64).
// Note: this attribute has numeric value 12 in the per-stats nested attr.
// In the flat frame context for per-packet alerts it does not appear.
#NetDmAttrStats: 12 & #NetDmAttr

// ---------------------------------------------------------------------------
// NET_DM stats nested attributes (inside NET_DM_ATTR_STATS nest)
// ---------------------------------------------------------------------------

// #NetDmStatsAttr enumerates the nested attributes inside NET_DM_ATTR_STATS.
// Each entry carries one per-reason aggregate counter.
// Source: include/uapi/linux/net_dm.h NET_DM_ATTR_STATS_*.
#NetDmStatsAttr:
	0 | // NET_DM_ATTR_STATS_UNSPEC         — ignore
	1   // NET_DM_ATTR_STATS_DROPPED        — u64 native-endian: packets dropped

// #NetDmAttrStatsDropped is the attribute type for the u64 packet drop count
// inside the NET_DM_ATTR_STATS nested attribute. Payload is u64 native-endian.
#NetDmAttrStatsDropped: 1 & #NetDmStatsAttr

// ---------------------------------------------------------------------------
// Alert mode configuration
// ---------------------------------------------------------------------------

// #NetDmAlertMode enumerates the two supported monitoring modes.
// Source: include/uapi/linux/net_dm.h NET_DM_ALERT_MODE_*.
// Only summary mode is supported by this exporter.
#NetDmAlertMode:
	0 | // NET_DM_ALERT_MODE_PACKET  — per-packet events (NOT supported)
	1   // NET_DM_ALERT_MODE_SUMMARY — aggregated per-reason counters (supported)

// #NetDmAlertModeSummary is the alert mode value sent in NET_DM_ATTR_ALERT_MODE
// during NET_DM_CMD_CONFIG. The kernel aggregates drops by reason before
// emitting alert frames, preventing per-packet event flood.
#NetDmAlertModeSummary: 1 & #NetDmAlertMode

// ---------------------------------------------------------------------------
// Drop origin enumeration
// ---------------------------------------------------------------------------

// #DropOrigin distinguishes software drops from hardware drops.
// Derived from NET_DM_ATTR_ORIGIN (u16) in the alert frame.
// Origin string is the "origin" label in nft_drop_packets_total.
#DropOrigin: "sw" | "hw"

// #DropOriginSw is the label string for software-originated drops.
// Wire value: NET_DM_ATTR_ORIGIN = 0.
#DropOriginSw: "sw" & #DropOrigin

// #DropOriginHw is the label string for hardware-originated drops.
// Wire value: NET_DM_ATTR_ORIGIN = 1.
#DropOriginHw: "hw" & #DropOrigin

// ---------------------------------------------------------------------------
// Wire-level value objects: parsed from NET_DM_CMD_ALERT frames
// ---------------------------------------------------------------------------

// #DropReasonKey is the ValueObject that uniquely identifies a drop-reason
// series within a DropMonitorSnapshot. It forms the label set for the
// nft_drop_packets_total metric family.
//
// Cardinality: approximately 60-80 software reason strings (bounded by the
// kernel drop-reason enum in include/net/dropreason.h) plus a small number of
// NIC-specific hardware trap names per supported NIC model. Neither
// field is per-flow, per-packet, or per-address; cardinality is bounded.
#DropReasonKey: {
	// reason is the drop reason string. For software drops this is the value of
	// NET_DM_ATTR_REASON (kernel >= 5.17), e.g. "NET_DM_REASON_TC_INGRESS".
	// For hardware drops this is NET_DM_ATTR_HW_TRAP_NAME.
	// NUL byte is stripped before storage.
	reason: string & !=""

	// origin distinguishes software drops ("sw") from hardware drops ("hw").
	// Derived from NET_DM_ATTR_ORIGIN u16: 0 -> "sw", 1 -> "hw".
	origin: #DropOrigin
}

// #DropReasonCounter accumulates the packet drop count for one DropReasonKey
// within a scrape interval. The count is the sum of all NET_DM_ATTR_STATS
// NET_DM_ATTR_STATS_DROPPED u64 values received for this key during the
// interval.
#DropReasonCounter: {
	// key identifies the drop reason and origin for this counter.
	key: #DropReasonKey

	// packets_dropped is the number of packets dropped with this reason during
	// the accumulation interval. Sourced from NET_DM_ATTR_STATS_DROPPED u64.
	// This value is accumulated monotonically; it is emitted as a counter delta
	// in nft_drop_packets_total.
	packets_dropped: uint64
}

// ---------------------------------------------------------------------------
// ReadModel: DropMonitorSnapshot
// ---------------------------------------------------------------------------

// #DropMonitorAvailability describes the collector runtime-gate state.
// The adapter sets this after CTRL_CMD_GETFAMILY on the NET_DM family name.
#DropMonitorAvailability:
	"available"   | // family resolved; monitor active
	"unavailable" | // family ENOENT; drop_monitor module not loaded
	"degraded"      // family resolved but NET_DM_CMD_START returned error

// #DropMonitorSnapshot is the immutable ReadModel produced by
// DropMonitorCollector for one scrape epoch. It carries per-reason packet drop
// counters aggregated across all NET_DM_CMD_ALERT frames received during the
// scrape interval, plus the availability status of the subsystem.
//
// Invariants:
// - When availability != "available", entries is empty.
// - reason_attr_supported being false means the kernel is < 5.17; no entries
//   are produced even when availability = "available".
// - epoch_ns is the Unix nanosecond timestamp when the snapshot was captured.
#DropMonitorSnapshot: {
	// epoch_ns is the Unix nanosecond timestamp when this snapshot was captured.
	epoch_ns: uint64

	// availability indicates whether the NET_DM genetlink family was resolved
	// and monitoring is active. Drives nft_scrape_collector_available value.
	availability: #DropMonitorAvailability

	// reason_attr_supported indicates that the kernel sent NET_DM_ATTR_REASON
	// strings in alert frames. False when kernel < 5.17 (module present but
	// drop-reason enum not yet exported). When false, entries is empty.
	reason_attr_supported: bool

	// entries is the list of per-reason drop counters accumulated during this
	// scrape interval. Empty when availability != "available" or when
	// reason_attr_supported is false.
	entries: [...#DropReasonCounter]
}

// ---------------------------------------------------------------------------
// Metric mapping reference (informational — enforced by metric_contract.cue)
// ---------------------------------------------------------------------------

// #DropMonitorMetricMap documents the wire-to-metric translation performed by
// DropMonitorCollector. This is a documentation-only value object; it is not
// used at runtime.
#DropMonitorMetricMap: {
	// packets_total maps DropReasonCounter.packets_dropped to the
	// nft_drop_packets_total counter metric family with labels (reason, origin).
	packets_total: {
		metric:  "nft_drop_packets_total"
		type:    "counter"
		unit:    "packets"
		source:  "NET_DM_ATTR_STATS / NET_DM_ATTR_STATS_DROPPED u64 (native-endian)"
		labels: ["reason", "origin"]
		cardinality_bound: "~160 |reason|~80 x |origin|~2"
	}

	// collector_available maps DropMonitorSnapshot.availability to the
	// nft_scrape_collector_available gauge family with label collector="drop-monitor".
	collector_available: {
		metric: "nft_scrape_collector_available"
		type:   "gauge"
		source: "CTRL_CMD_GETFAMILY NET_DM result; 1=family resolved, 0=ENOENT"
		labels: ["collector"]
	}
}

// ---------------------------------------------------------------------------
// Endianness rules for NET_DM attributes
// ---------------------------------------------------------------------------

// #NetDmEndianness documents the endianness of NET_DM attribute payloads.
// All NET_DM attribute payload values are native-endian (little-endian on
// x86-64 and aarch64 — the two supported targets of this exporter).
// There are no big-endian fields in the NET_DM uapi (unlike ctnetlink which
// uses big-endian for CTA_COUNTERS_*, CTA_STATUS, etc.).
#NetDmEndianness: {
	// dropped_count endianness for NET_DM_ATTR_STATS_DROPPED u64.
	dropped_count: "native-endian (u64::from_ne_bytes)"

	// alert_mode endianness for NET_DM_ATTR_ALERT_MODE u8.
	alert_mode: "u8 — no endianness conversion"

	// origin endianness for NET_DM_ATTR_ORIGIN u16.
	origin: "native-endian (u16::from_ne_bytes)"

	// genlmsghdr fields are always native-endian (same as ETHTOOL_* family).
	genlmsghdr: "native-endian"
}

// ---------------------------------------------------------------------------
// Cardinality constraint
// ---------------------------------------------------------------------------

// #DropMonitorCardinalityBound documents the worst-case series counts.
// Bounded by the kernel drop-reason enum and NIC-specific hardware trap names.
// Neither dimension is per-flow, per-packet, or per-address.
#DropMonitorCardinalityBound: {
	// sw_reasons is the approximate number of distinct software drop reason
	// strings exported by the kernel drop-reason enum (include/net/dropreason.h).
	// As of kernel 6.8: approximately 60-80 entries. The enum is extended
	// across kernel versions but is bounded by design (one entry per code path).
	sw_reasons: >=60 & <=200 & uint64

	// hw_trap_names is the approximate number of distinct hardware trap names
	// per supported NIC model. Bounded by the NIC driver's devlink health
	// reporter implementation; typical mlx5 has < 30 distinct trap names.
	hw_trap_names: >=0 & <=100 & uint64

	// total_series is the worst-case nft_drop_packets_total series count.
	// |reason| * |origin| = (sw_reasons + hw_trap_names) * 2.
	// Practical maximum: (80 + 30) * 2 = 220. Well within ADR-0005 ceiling.
	total_series_bound: "~220 worst case; practical ~100 on a host with one NIC model"
}
