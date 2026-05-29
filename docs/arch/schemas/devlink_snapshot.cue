// DDD role: ReadModel
package schemas

// ---------------------------------------------------------------------------
// devlink_snapshot.cue — wire-level value objects and ReadModel for the
// devlink generic-netlink collector (Devlink bounded context).
//
// These types represent the kernel uapi structures and attribute payloads that
// cross the NETLINK_GENERIC socket boundary via the "devlink" genl family.
// They are pure value objects and a ReadModel: no methods, no mutation, no
// infrastructure imports. DevlinkAdapter in nft_exporter_adapter_devlink
// deserialises kernel bytes into these types; DevlinkCollector translates them
// into metric label sets for MetricRegistryPort.
//
// Wire note: the devlink genl family must be resolved at runtime via
// CTRL_CMD_GETFAMILY (family name "devlink\0"). The resolved family id is
// cached in a OnceLock<u16>. ENOENT from CTRL_CMD_GETFAMILY means the subsystem
// is absent on this host; set collector_available=false and emit no further
// requests (runtime gate per ADR-0019).
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Generic-netlink devlink command constants
// ---------------------------------------------------------------------------

// #DevlinkCmd enumerates the devlink genetlink command codes used by this
// collector. Source: include/uapi/linux/devlink.h DEVLINK_CMD_*.
// Only the subset issued by this exporter is listed.
#DevlinkCmd:
	1  | // DEVLINK_CMD_GET              — device info dump
	5  | // DEVLINK_CMD_PORT_GET         — port info dump
	52   // DEVLINK_CMD_HEALTH_REPORTER_GET — health reporter dump

// #DevlinkCmdGet is the command code for device enumeration.
// Send with NLM_F_REQUEST|NLM_F_DUMP and no filter attributes to dump all
// devlink devices visible to this network namespace.
#DevlinkCmdGet: 1 & #DevlinkCmd

// #DevlinkCmdPortGet is the command code for port enumeration.
// Send with NLM_F_REQUEST|NLM_F_DUMP to retrieve all ports across all devices.
#DevlinkCmdPortGet: 5 & #DevlinkCmd

// #DevlinkCmdHealthReporterGet is the command code for health reporter dump.
// Requires the bus_name and dev_name filter attributes when issued per-device.
// Issue once per device obtained from DevlinkCmdGet. A per-device dump also
// returns the device's port-level reporters (carrying DEVLINK_ATTR_PORT_INDEX).
#DevlinkCmdHealthReporterGet: 52 & #DevlinkCmd

// #DevlinkFamilyName is the NUL-terminated string used in CTRL_ATTR_FAMILY_NAME
// when resolving the devlink genl family via CTRL_CMD_GETFAMILY.
// The kernel compares this case-sensitively against registered family names.
#DevlinkFamilyName: "devlink"

// ---------------------------------------------------------------------------
// Top-level attribute types (DEVLINK_ATTR_*)
// ---------------------------------------------------------------------------

// #DevlinkAttr enumerates the top-level nlattr types used in devlink messages.
// Source: include/uapi/linux/devlink.h DEVLINK_ATTR_*.
// Only attributes parsed by this exporter are listed; the full enum has > 200
// entries across kernel versions. Strip NLA_F_NESTED (bit 15) before matching.
#DevlinkAttr:
	1  | // DEVLINK_ATTR_BUS_NAME               — NUL-terminated string ("pci", "platform")
	2  | // DEVLINK_ATTR_DEV_NAME               — NUL-terminated string ("0000:03:00.0")
	3  | // DEVLINK_ATTR_PORT_INDEX             — u32, port number within device
	4  | // DEVLINK_ATTR_PORT_TYPE              — u16 (DEVLINK_PORT_TYPE_*)
	5  | // DEVLINK_ATTR_PORT_DESIRED_TYPE      — u16
	6  | // DEVLINK_ATTR_PORT_NETDEV_IFINDEX    — u32
	7  | // DEVLINK_ATTR_PORT_NETDEV_NAME       — NUL-terminated string
	8  | // DEVLINK_ATTR_PORT_IBDEV_NAME        — NUL-terminated string
	57 | // DEVLINK_ATTR_HEALTH_REPORTER        — nested; one per reporter in dump
	58 | // DEVLINK_ATTR_HEALTH_REPORTER_NAME   — NUL-terminated string (inside reporter nest)
	59 | // DEVLINK_ATTR_HEALTH_REPORTER_STATE  — u8; 0=healthy 1=error 2=auto_recover 3=dumping 4=corrective_action 5=unavailable
	60 | // DEVLINK_ATTR_HEALTH_REPORTER_ERR_COUNT    — u64 LE cumulative error events
	61   // DEVLINK_ATTR_HEALTH_REPORTER_RECOVER_COUNT — u64 LE cumulative recovery events

// #DevlinkAttrBusName is the attribute type carrying the device bus identifier.
// Always present in DEVLINK_CMD_GET and DEVLINK_CMD_PORT_GET replies.
// Payload: NUL-terminated ASCII string; strip trailing NUL before use.
#DevlinkAttrBusName: 1 & #DevlinkAttr

// #DevlinkAttrDevName is the attribute type carrying the device name within
// the bus namespace (e.g. "0000:03:00.0" for PCI, "gpio-keys" for platform).
// Payload: NUL-terminated ASCII string.
#DevlinkAttrDevName: 2 & #DevlinkAttr

// #DevlinkAttrPortIndex is the attribute type carrying the u32 port number.
// Port indices start at 0 and are contiguous per device.
#DevlinkAttrPortIndex: 3 & #DevlinkAttr

// #DevlinkAttrHealthReporter is the nested container attribute. Its payload
// is an nlattr chain containing DevlinkAttrHealthReporterName,
// DevlinkAttrHealthReporterState, DevlinkAttrHealthReporterErrCount, and
// DevlinkAttrHealthReporterRecoverCount.
// Strip NLA_F_NESTED (0x8000) before matching the type value 57.
#DevlinkAttrHealthReporter: 57 & #DevlinkAttr

// #DevlinkAttrHealthReporterName is the attribute type for the reporter name
// string inside a DEVLINK_ATTR_HEALTH_REPORTER nest.
// Payload: NUL-terminated ASCII string; examples: "fw_fatal", "rx", "tx".
#DevlinkAttrHealthReporterName: 58 & #DevlinkAttr

// #DevlinkAttrHealthReporterState is the u8 reporter health state.
// Map to the reporter_state label string via #DevlinkHealthState.
#DevlinkAttrHealthReporterState: 59 & #DevlinkAttr

// #DevlinkAttrHealthReporterErrCount is the cumulative u64 LE error event
// counter since device initialisation. Sourced from
// devlink_health_reporter.health_reporter_err_count in the kernel.
#DevlinkAttrHealthReporterErrCount: 60 & #DevlinkAttr

// #DevlinkAttrHealthReporterRecoverCount is the cumulative u64 LE recovery
// event counter since device initialisation.
#DevlinkAttrHealthReporterRecoverCount: 61 & #DevlinkAttr

// ---------------------------------------------------------------------------
// Port type enumeration
// ---------------------------------------------------------------------------

// #DevlinkPortType enumerates the DEVLINK_PORT_TYPE_* values from the kernel
// uapi. Used to populate the port_type label in nft_devlink_port_info.
#DevlinkPortType:
	0 | // DEVLINK_PORT_TYPE_NOTSET — port type not configured
	1 | // DEVLINK_PORT_TYPE_AUTO  — port type automatically determined
	2 | // DEVLINK_PORT_TYPE_ETH   — Ethernet port
	3   // DEVLINK_PORT_TYPE_IB    — InfiniBand port

// #DevlinkPortTypeName maps the u16 wire value to a bounded label string.
// The adapter must perform this mapping before constructing DevlinkPortEntry;
// the raw integer must never reach MetricRegistryPort as a label.
#DevlinkPortTypeName: "notset" | "auto" | "eth" | "ib"

// ---------------------------------------------------------------------------
// Health reporter state enumeration
// ---------------------------------------------------------------------------

// #DevlinkHealthState enumerates the u8 health reporter state values.
// Source: include/uapi/linux/devlink.h devlink_health_reporter_state.
// Versions after kernel 5.9 may add states; unknown values map to "unknown".
#DevlinkHealthState:
	0 | // DEVLINK_HEALTH_REPORTER_STATE_HEALTHY
	1 | // DEVLINK_HEALTH_REPORTER_STATE_ERROR
	2 | // DEVLINK_HEALTH_REPORTER_STATE_AUTO_RECOVER
	3 | // DEVLINK_HEALTH_REPORTER_STATE_DUMPING
	4 | // DEVLINK_HEALTH_REPORTER_STATE_CORRECTIVE_ACTION
	5   // DEVLINK_HEALTH_REPORTER_STATE_UNAVAILABLE

// #DevlinkHealthStateName maps the u8 wire value to a bounded label string.
// Unknown values (future kernel additions) must be mapped to "unknown" rather
// than emitting a raw integer, preventing unbounded label cardinality.
#DevlinkHealthStateName: "healthy" | "error" | "auto_recover" | "dumping" | "corrective_action" | "unavailable" | "unknown"

// ---------------------------------------------------------------------------
// Wire parsing notes
// ---------------------------------------------------------------------------

// #DevlinkWireNotes documents the critical parsing rules for devlink genl
// messages. These complement the general rules in netlink-protocol.md.
#DevlinkWireNotes: {
	// genl_header_offset is the byte offset where the nlattr chain begins.
	// All devlink messages follow nlmsghdr (16 bytes) + genlmsghdr (4 bytes).
	genl_header_offset: 20

	// attr_strip_nested indicates that all devlink container attributes have
	// NLA_F_NESTED (bit 15) set. Strip with nla_type & 0x1FFF before matching.
	attr_strip_nested: true

	// err_count_endian: devlink health reporter counters are u64 little-endian.
	// Use u64::from_le_bytes; the general "native-endian" rule for NETLINK_GENERIC
	// applies (section 10, netlink-protocol.md).
	err_count_endian: "little-endian"

	// per_device_reporter_dump: DEVLINK_CMD_HEALTH_REPORTER_GET dumps must be
	// issued once per device using bus_name and dev_name filter attributes.
	// A global NLM_F_DUMP without device filters returns EINVAL on kernels < 5.18.
	// Issue a separate dump per device obtained from DEVLINK_CMD_GET.
	per_device_reporter_dump: true

	// state_unknown_fallback: reporter state values not in #DevlinkHealthState
	// (future kernel additions) must map to label "unknown" rather than the raw
	// integer. This prevents unbounded label cardinality over time.
	state_unknown_fallback: "unknown"
}

// ---------------------------------------------------------------------------
// Domain value objects
// ---------------------------------------------------------------------------

// #DevlinkBusName is a non-empty string identifying the kernel bus namespace.
// Common values: "pci", "platform", "auxiliary". Used as Prometheus label.
#DevlinkBusName: string & !=""

// #DevlinkDevName is a non-empty string identifying the device within its bus.
// For PCI: the BDF address "0000:03:00.0". For platform: a kernel device name.
// Used as Prometheus label. Cardinality bounded by hardware topology.
#DevlinkDevName: string & !=""

// #DevlinkReporterName is the name of a health reporter as returned in
// DEVLINK_ATTR_HEALTH_REPORTER_NAME. Examples: "fw_fatal", "rx", "tx", "fw".
// Bounded by driver implementation; typically 1-8 reporters per device.
#DevlinkReporterName: string & !=""

// #DevlinkPortNumber is the u32 port index within the device. Stringified as
// the "port" Prometheus label. Cardinality bounded by hardware port count.
#DevlinkPortNumber: uint32

// ---------------------------------------------------------------------------
// ReadModel aggregate roots
// ---------------------------------------------------------------------------

// #DevlinkDeviceEntry is a device entity within DevlinkSnapshot. One entry
// exists per devlink device visible in DEVLINK_CMD_GET dump replies.
// The (bus_name, dev_name) pair is the device identity key.
#DevlinkDeviceEntry: {
	// bus_name identifies the kernel bus (e.g. "pci", "platform").
	bus_name: #DevlinkBusName

	// dev_name identifies the device within the bus namespace.
	dev_name: #DevlinkDevName
}

// #DevlinkPortEntry is a port entity within DevlinkSnapshot. One entry exists
// per port returned by DEVLINK_CMD_PORT_GET. The port belongs to the device
// identified by (bus_name, dev_name).
#DevlinkPortEntry: {
	// bus_name ties this port to its parent device.
	bus_name: #DevlinkBusName

	// dev_name ties this port to its parent device.
	dev_name: #DevlinkDevName

	// port_index is the DEVLINK_ATTR_PORT_INDEX u32 value. Stringified as
	// the "port" label in nft_devlink_port_info.
	port_index: #DevlinkPortNumber

	// port_type_name is the mapped label string from DEVLINK_ATTR_PORT_TYPE u16.
	// Unknown values from future kernels map to "unknown" at parse time.
	port_type_name: #DevlinkPortTypeName | "unknown"

	// netdev_name is the associated network interface name from
	// DEVLINK_ATTR_PORT_NETDEV_NAME when the port is bound to an Ethernet
	// netdevice. Empty string when absent (IB ports, unbound ports).
	netdev_name: string
}

// #DevlinkHealthReporterEntry is a health reporter entity within
// DevlinkSnapshot. One entry exists per DEVLINK_ATTR_HEALTH_REPORTER nest
// returned by DEVLINK_CMD_HEALTH_REPORTER_GET.
#DevlinkHealthReporterEntry: {
	// bus_name ties this reporter to its parent device.
	bus_name: #DevlinkBusName

	// dev_name ties this reporter to its parent device.
	dev_name: #DevlinkDevName

	// reporter_name is the DEVLINK_ATTR_HEALTH_REPORTER_NAME string.
	reporter_name: #DevlinkReporterName

	// state_name is the mapped label string from
	// DEVLINK_ATTR_HEALTH_REPORTER_STATE u8.
	state_name: #DevlinkHealthStateName

	// error_count is the cumulative u64 error event count from
	// DEVLINK_ATTR_HEALTH_REPORTER_ERR_COUNT. Exposed as
	// nft_devlink_health_reporter_error_total. Read as u64 little-endian.
	error_count: uint64

	// recover_count is the cumulative u64 recovery event count from
	// DEVLINK_ATTR_HEALTH_REPORTER_RECOVER_COUNT. Exposed as
	// nft_devlink_health_reporter_recover_total. Read as u64 little-endian.
	recover_count: uint64
}

// #DevlinkSnapshot is the immutable ReadModel produced by DevlinkCollector for
// one scrape epoch. It is passed to MetricRegistryPort which encodes it into
// the nft_devlink_* metric families.
//
// When collector_available is false (devlink genl family returned ENOENT),
// devices, ports, and reporters are all empty lists and no nft_devlink_*
// series are emitted, only nft_scrape_collector_available{collector="devlink"}=0.
#DevlinkSnapshot: {
	// epoch_ns is the Unix nanosecond timestamp when this snapshot was captured.
	epoch_ns: uint64

	// collector_available indicates whether the devlink genl family was
	// successfully resolved on this host. False means ENOENT from
	// CTRL_CMD_GETFAMILY; no subsystem is loaded.
	collector_available: bool

	// devices is the list of devlink device entries from DEVLINK_CMD_GET.
	devices: [...#DevlinkDeviceEntry]

	// ports is the list of devlink port entries from DEVLINK_CMD_PORT_GET.
	ports: [...#DevlinkPortEntry]

	// reporters is the list of health reporter entries from
	// DEVLINK_CMD_HEALTH_REPORTER_GET, issued once per device.
	reporters: [...#DevlinkHealthReporterEntry]
}

// ---------------------------------------------------------------------------
// Metric mapping reference (informational — canonical contract in metric_contract.cue)
// ---------------------------------------------------------------------------

// #DevlinkMetricMapping documents the wire-to-metric translation for each
// DevlinkSnapshot field. This is the reference used when implementing the
// MetricRegistryPort translation layer.
#DevlinkMetricMapping: {
	nft_devlink_device_info: {
		source: "#DevlinkDeviceEntry"
		type:   "gauge"
		labels: ["bus_name", "dev_name"]
		value:  "always 1"
		help:   "Metadata gauge (always 1) for each devlink device. Present when DEVLINK_CMD_GET succeeds."
	}
	nft_devlink_port_info: {
		source: "#DevlinkPortEntry"
		type:   "gauge"
		labels: ["bus_name", "dev_name", "port"]
		value:  "always 1"
		help:   "Metadata gauge (always 1) for each devlink port. port label is the stringified port_index."
	}
	nft_devlink_health_reporter_error_total: {
		source: "#DevlinkHealthReporterEntry.error_count"
		type:   "counter"
		labels: ["bus_name", "dev_name", "reporter"]
		value:  "DEVLINK_ATTR_HEALTH_REPORTER_ERR_COUNT u64"
		help:   "Cumulative number of health reporter error events since device init."
	}
	nft_devlink_health_reporter_recover_total: {
		source: "#DevlinkHealthReporterEntry.recover_count"
		type:   "counter"
		labels: ["bus_name", "dev_name", "reporter"]
		value:  "DEVLINK_ATTR_HEALTH_REPORTER_RECOVER_COUNT u64"
		help:   "Cumulative number of health reporter recovery events since device init."
	}
	nft_devlink_health_reporter_state: {
		source: "#DevlinkHealthReporterEntry.state_name"
		type:   "gauge"
		labels: ["bus_name", "dev_name", "reporter", "state"]
		value:  "always 1; state label carries the mapped health state string"
		help:   "Current health state of a devlink reporter. state in (healthy, error, auto_recover, dumping, corrective_action, unavailable, unknown)."
	}
}
