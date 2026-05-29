// DDD role: ReadModel
package schemas

// #EthtoolStatName is a non-empty string identifying an ethtool NIC statistic.
// Stat names are fixed at driver compile time (e.g. "rx_packets", "tx_errors",
// "rx_no_buffer_count", "port.rx_prio0_buf_discard"). Used as the "stat" label
// in nft_ethtool_stat gauge.
#EthtoolStatName: string & !=""

// #EthtoolStat is a ValueObject holding one named ethtool statistic value
// for a single interface. The value is typed as int64 to accommodate drivers
// that report signed counter deltas; practically always non-negative.
//
// These counters may reset on interface down (non-monotonic) — hence the
// metric type is gauge, not counter. Alerting rules MUST use rate() or delta().
#EthtoolStat: {
	// name is the driver-specific statistic name; used as the "stat" label.
	name: #EthtoolStatName

	// value is the current statistic value as reported by the kernel via
	// ETHTOOL_MSG_STATS_GET. Treat as a snapshot, not a monotonic counter.
	value: int64
}

// #LinkDuplex enumerates the duplex mode strings from ETHTOOL_MSG_LINKSETTINGS_GET.
#LinkDuplex: "full" | "half" | "unknown"

// #LinkAutoneg enumerates the auto-negotiation mode strings.
#LinkAutoneg: "on" | "off"

// #LinkSettings holds the ethtool link settings metadata for one interface.
// Maps to the nft_ethtool_link_info metadata gauge (value always 1).
#LinkSettings: {
	// interface is the interface name; used as the "interface" label.
	interface: string & !=""

	// speed is the link speed in Mbps as a string (e.g. "1000", "10000").
	// "unknown" when the driver reports SPEED_UNKNOWN.
	speed: string & !=""

	// duplex is the duplex mode.
	duplex: #LinkDuplex

	// autoneg indicates whether auto-negotiation is enabled.
	autoneg: #LinkAutoneg

	// port is the physical connector type string (e.g. "tp", "fibre", "da",
	// "none", "other").
	port: string & !=""
}

// #PauseStats holds PAUSE frame counters for one interface sourced from
// ETHTOOL_MSG_PAUSE_GET. Maps to nft_ethtool_pause_rx_total and
// nft_ethtool_pause_tx_total counters.
#PauseStats: {
	// interface is the interface name; used as the "interface" label.
	interface: string & !=""

	// rx_frames is the total PAUSE frames received (ETHTOOL_A_PAUSE_STAT_RX_FRAMES).
	rx_frames: uint64

	// tx_frames is the total PAUSE frames transmitted (ETHTOOL_A_PAUSE_STAT_TX_FRAMES).
	tx_frames: uint64
}

// #FecLane is the lane index for FEC statistics. Valid range: 0-7.
// Most NICs report 1-4 lanes; the actual count depends on the physical layer.
#FecLane: >=0 & <=7

// #FecCounterEntry holds FEC corrected codeword counts per lane per interface.
// Only emitted when FEC is active on the NIC.
// Maps to nft_ethtool_fec_corrected_total counter.
#FecCounterEntry: {
	// interface is the interface name; used as the "interface" label.
	interface: string & !=""

	// lane is the physical lane index; used as the "lane" label.
	lane: #FecLane

	// corrected is the total FEC corrected codeword blocks on this lane
	// (ETHTOOL_MSG_FEC_GET ETHTOOL_A_FEC_STAT_CORRECTED).
	corrected: uint64
}

// #NicStatEntry holds all ethtool statistics for one network interface.
#NicStatEntry: {
	// interface is the interface name; used as the "interface" label in
	// nft_ethtool_stat gauge.
	interface: string & !=""

	// stats is the list of named statistic value objects for this interface.
	// The set of stat names is driver-defined and fixed at compile time.
	// Cardinality contribution per interface: up to ~100 stat names.
	stats: [...#EthtoolStat]

	// supported indicates whether this interface supports ethtool genetlink.
	// When false (EOPNOTSUPP probe returned error), stats is empty and the
	// interface is skipped entirely for all ethtool metric families.
	supported: bool
}

// #NicStatSnapshot is the immutable ReadModel produced by EthtoolCollector
// for the ETHTOOL genetlink family in one scrape epoch.
// Requires kernel >= 5.12 and driver support; gates on per-NIC EOPNOTSUPP probe.
//
// Cardinality: up to 50,000 series total (~512 interfaces x ~100 stat names).
// This is the highest-cardinality metric family in the exporter.
#NicStatSnapshot: {
	// epoch_ns is the Unix nanosecond timestamp when this snapshot was captured.
	epoch_ns: uint64

	// nics is the list of per-interface ethtool stat entries.
	nics: [...#NicStatEntry]

	// link_settings is the list of link settings metadata records.
	// Cardinality bound: ~512 entries (one per interface).
	link_settings: [...#LinkSettings]

	// pause is the list of PAUSE frame counter records.
	// Cardinality bound: ~512 entries (one per interface; absent for unsupported NICs).
	pause: [...#PauseStats]

	// fec is the list of FEC corrected codeword counter records.
	// Cardinality bound: ~2048 entries (~512 interfaces x ~4 lanes);
	// emitted only for interfaces with active FEC.
	fec: [...#FecCounterEntry]
}
