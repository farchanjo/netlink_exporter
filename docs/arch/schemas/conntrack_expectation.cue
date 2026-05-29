// DDD role: ReadModel
package schemas

// ---------------------------------------------------------------------------
// conntrack-expectations bounded context — wire-to-metric value objects
// Grounded in: linux/netfilter/nfnetlink_conntrack.h
//              NFNL_SUBSYS_CTNETLINK_EXP = 2
//              IPCTNL_MSG_EXP_GET (0x0200), IPCTNL_MSG_EXP_GET_STATS_CPU (0x0203)
// Used by ConntrackExpectationsAdapter (nft_exporter_adapter_ct_exp) only.
// NEVER crosses the port boundary into domain-core as raw bytes.
// ---------------------------------------------------------------------------

// #CtExpSubsys is the NFNL_SUBSYS_CTNETLINK_EXP constant.
// nlmsg_type = (2 << 8) | msg_type_low_byte.
#CtExpSubsys: 2

// #CtExpMsgType enumerates the IPCTNL_MSG_EXP_* low bytes.
#CtExpMsgType:
	0 | // IPCTNL_MSG_EXP_GET — dump request; nlmsg_type = 0x0200
	3   // IPCTNL_MSG_EXP_GET_STATS_CPU — per-CPU stats; nlmsg_type = 0x0203

// #CtExpMsgTypeEncoded lists the full 16-bit nlmsg_type values (host byte order).
#CtExpMsgTypeEncoded: {
	exp_get:           0x0200
	exp_get_stats_cpu: 0x0203
}

// ---------------------------------------------------------------------------
// Request descriptors
// ---------------------------------------------------------------------------

// #ExpDumpRequest describes the wire layout for an IPCTNL_MSG_EXP_GET dump.
// Wire size: nlmsghdr (16) + nfgenmsg (4) = 20 bytes.
// nlmsg_flags = NLM_F_REQUEST (0x0001) | NLM_F_DUMP (0x0300) = 0x0301.
// nfgen_family = AF_UNSPEC (0) to retrieve all address families.
#ExpDumpRequest: {
	nlmsg_type:  #CtExpMsgTypeEncoded.exp_get
	nlmsg_flags: 0x0301
	nfgenmsg: #NfgenmsgWire & {
		nfgen_family: 0 // AF_UNSPEC
	}
	total_bytes: 20
}

// #ExpStatsRequest describes the wire layout for an IPCTNL_MSG_EXP_GET_STATS_CPU request.
// Wire size: nlmsghdr (16) + nfgenmsg (4) = 20 bytes.
// nlmsg_flags = NLM_F_REQUEST = 0x0001.
// nfgen_family = AF_UNSPEC (0).
#ExpStatsRequest: {
	nlmsg_type:  #CtExpMsgTypeEncoded.exp_get_stats_cpu
	nlmsg_flags: 0x0001
	nfgenmsg: #NfgenmsgWire & {
		nfgen_family: 0 // AF_UNSPEC
	}
	total_bytes: 20
}

// ---------------------------------------------------------------------------
// CTA_EXPECT_* top-level attribute types
// Parsed from IPCTNL_MSG_EXP_GET dump reply frames.
// Strip NLA_F_NESTED (bit 15) before matching effective type.
// ---------------------------------------------------------------------------

// #CtaExpType enumerates the CTA_EXPECT_* nlattr type constants.
// Source: linux/netfilter/nfnetlink_conntrack.h CTA_EXPECT_* enum.
#CtaExpType: {
	master:    1   // nested: master flow tuple (CTA_TUPLE_ORIG format)
	tuple:     2   // nested: expected flow tuple
	mask:      3   // nested: expected flow mask tuple
	timeout:   4   // u32 big-endian: remaining timeout in seconds (DISCARDED — cardinality)
	id:        5   // u32 big-endian: internal expectation ID (DISCARDED — unbounded)
	helper_name: 6 // NUL-terminated ASCII string: helper name (e.g. "ftp", "sip")
	zone:      7   // u16 big-endian: conntrack zone (DISCARDED — cardinality)
	flags:     8   // u32 big-endian: expectation flags bitmask
	class:     9   // u32 big-endian: expectation class (DISCARDED)
}

// ---------------------------------------------------------------------------
// nf_ct_exp_stat — per-CPU stat struct from IPCTNL_MSG_EXP_GET_STATS_CPU
// ---------------------------------------------------------------------------

// #NfCtExpStat describes the parsed per-CPU expectation stat struct.
// Reply body starts at offset NLMSG_HDRLEN + 4 (after nlmsghdr + nfgenmsg).
// All fields are native-endian u32. Parse only fields within the actual
// payload length; treat absent trailing fields as zero.
//
// Known struct layout (all kernel versions through 6.9):
//   Offset 0: new        — expectations created on this CPU
//   Offset 4: delete     — expectations deleted on this CPU
//   Offset 8: new_failed — expectation allocation failures on this CPU
//
// CRITICAL: Check payload_len before reading each field. Additional fields
// may be appended in future kernels. Treat absent trailing fields as zero.
#NfCtExpStat: {
	// new is the number of expectations created on this CPU.
	new: uint32

	// delete is the number of expectations deleted on this CPU.
	delete: uint32

	// new_failed is the number of expectation allocation failures on this CPU.
	new_failed: uint32
}

// #NfCtExpStatSum is the per-CPU stat summed across all CPUs.
// This is what ConntrackExpectationsAdapter produces after consuming all
// IPCTNL_MSG_EXP_GET_STATS_CPU reply frames.
#NfCtExpStatSum: {
	new:        uint64
	delete:     uint64
	new_failed: uint64
}

// ---------------------------------------------------------------------------
// Bounded-cardinality domain objects
// ---------------------------------------------------------------------------

// #ExpHelperName is a NUL-stripped ASCII string from CTA_EXPECT_HELPER_NAME.
// Bounded by the finite set of kernel-registered helper module names.
// Truncated to 64 bytes if the kernel returns a longer value (defensive).
// Known values: "ftp", "tftp", "sip", "h323", "pptp", "irc", "amanda",
//               "netbios_ns", "snmp", "broadcast", "nfs", "ftp-data".
// The empty string "" is substituted when CTA_EXPECT_HELPER_NAME is absent.
#ExpHelperName: string & {
	len(#ExpHelperName) <= 64
}

// #ExpAggKey is the aggregation key for the expectations ReadModel.
// Only l4proto and helper are used; all other per-expectation attributes
// are discarded immediately on parse (ADR-0005 cardinality enforcement).
// Cardinality bound: |l4proto| x |helper| <= 8 x 20 = 160.
#ExpAggKey: {
	// l4proto is the layer-4 protocol of the expected flow tuple.
	// Sourced from CTA_EXPECT_TUPLE > CTA_TUPLE_PROTO > CTA_PROTO_NUM (u8).
	// Mapped to string via #IpProto the same way as ConntrackAdapter.
	l4proto: #ConntrackProtocol

	// helper is the NUL-stripped CTA_EXPECT_HELPER_NAME value.
	// Empty string when the attribute is absent (un-helpered expectation).
	helper: #ExpHelperName
}

// #ExpectationBucketCount holds the count of active expectations in one
// (l4proto, helper) bucket.
// Maps directly to one time series of nft_conntrack_expectation_entries gauge.
#ExpectationBucketCount: {
	key:   #ExpAggKey
	count: uint64
}

// ---------------------------------------------------------------------------
// Forbidden per-expectation attributes (cardinality enforcement)
// ---------------------------------------------------------------------------

// The following CTA_EXPECT_* attributes MUST NEVER appear as Prometheus
// label dimensions or metric keys (ADR-0005):
//
//   CTA_EXPECT_ID      — internal kernel ID; changes across scrapes; unbounded
//   CTA_EXPECT_TIMEOUT — remaining seconds; continuous value; unbounded
//   CTA_EXPECT_ZONE    — zone ID; multiplies cardinality
//   CTA_EXPECT_CLASS   — expectation class; sparse enum; unbounded in practice
//   CTA_EXPECT_MASTER  — master flow 5-tuple (IPs + ports); per-connection
//   CTA_EXPECT_TUPLE   — expected flow 5-tuple (IPs + ports); per-connection
//   CTA_EXPECT_MASK    — mask tuple; per-connection

// ---------------------------------------------------------------------------
// ReadModel: ConntrackExpectationSummary
// ---------------------------------------------------------------------------

// #ExpectationStats is the zero-label global expectation-creation counters,
// produced by summing #NfCtExpStat across all CPUs.
// Each field maps to a zero-label counter metric.
#ExpectationStats: {
	// new is the total expectations created across all CPUs.
	// Maps to nft_conntrack_expectation_new_total counter.
	new: uint64

	// delete is the total expectations deleted across all CPUs.
	// Maps to nft_conntrack_expectation_delete_total counter.
	delete: uint64

	// new_failed is the total expectation allocation failures across all CPUs.
	// Maps to nft_conntrack_expectation_new_failed_total counter.
	new_failed: uint64
}

// #ConntrackExpectationSummary is the immutable ReadModel produced by
// ConntrackExpectationsCollector for one scrape epoch.
// This is the ONLY conntrack-expectations data structure that reaches
// MetricRegistryPort.
//
// CRITICAL invariant: this ReadModel contains aggregated counts ONLY.
// No per-expectation IP address, port, timeout, or ID is present.
// Per-expectation cardinality is strictly forbidden per ADR-0005.
//
// When the subsystem is unavailable (ENOENT / EPERM at probe time),
// expectations_by_key is empty and all stats counters are zero.
// The nft_scrape_collector_available{collector="conntrack-expectations"}
// gauge carries the availability signal in that case.
#ConntrackExpectationSummary: {
	// epoch_ns is the Unix nanosecond timestamp when this snapshot was captured.
	// Used by nft_exporter_snapshot_age_seconds self-metric.
	epoch_ns: uint64

	// available is true when the IPCTNL_MSG_EXP_GET dump succeeded at probe time.
	// false when the kernel returned ENOENT or EPERM.
	// Maps to nft_scrape_collector_available{collector="conntrack-expectations"}.
	available: bool

	// expectations_by_key is the list of expectation counts by (l4proto, helper).
	// Cardinality bound: at most 160 entries (8 protocols x 20 helper names).
	// Empty when available=false.
	expectations_by_key: [...#ExpectationBucketCount]

	// stats holds the zero-label global expectation counters from per-CPU stats.
	// All fields are zero when available=false.
	stats: #ExpectationStats
}
