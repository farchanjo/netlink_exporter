// DDD role: ReadModel
package schemas

// ---------------------------------------------------------------------------
// XFRM/IPsec bounded context — wire-to-metric value objects and read model
// NETLINK_XFRM (family 6): XFRM_MSG_GETSA, XFRM_MSG_GETPOLICY,
// XFRM_MSG_GETSADINFO, XFRM_MSG_GETSPDINFO + /proc/net/xfrm_stat
// ADR-0016
// ---------------------------------------------------------------------------

// #XfrmProto enumerates the IPsec transform protocol values carried in the
// xfrm_usersa_id.proto field. Values match IANA IP protocol numbers.
// esp=50 (Encapsulating Security Payload), ah=51 (Authentication Header),
// comp=108 (IP Payload Compression), route2=97 (IPSEC ROUTE), hao=135 (Home Address).
// "other" covers any value not in this bounded set.
#XfrmProto: "esp" | "ah" | "comp" | "other"

// #XfrmMode enumerates the SA mode from xfrm_usersa_info.mode.
// tunnel=0, transport=1, routeoptimization=2, in_trigger=3, beet=4.
// "other" covers any value not in this bounded set.
#XfrmMode: "tunnel" | "transport" | "beet" | "other"

// #XfrmPolicyDir enumerates SPD entry direction from xfrm_userpolicy_info.dir.
// in=0, fwd=1, out=2.
#XfrmPolicyDir: "in" | "fwd" | "out"

// #XfrmPolicyAction enumerates the SPD entry action from xfrm_userpolicy_info.action.
// allow=0 (XFRM_POLICY_ALLOW), block=1 (XFRM_POLICY_BLOCK).
#XfrmPolicyAction: "allow" | "block"

// #XfrmStatKey enumerates the fixed-set counter names from /proc/net/xfrm_stat.
// Each key maps to one time series of nft_xfrm_stat_total{counter=<key>}.
// Cardinality is bounded to exactly 26 series — the kernel ABI-stable key set.
#XfrmStatKey:
	"XfrmInError" |
	"XfrmInNoStates" |
	"XfrmInStateProtoError" |
	"XfrmInStateModeError" |
	"XfrmInStateSeqError" |
	"XfrmInStateExpired" |
	"XfrmInStateMismatch" |
	"XfrmInStateInvalid" |
	"XfrmInTmplMismatch" |
	"XfrmInNoPols" |
	"XfrmInPolBlock" |
	"XfrmInPolError" |
	"XfrmOutError" |
	"XfrmOutBundleGenError" |
	"XfrmOutBundleCheckError" |
	"XfrmOutNoStates" |
	"XfrmOutStateProtoError" |
	"XfrmOutStateModeError" |
	"XfrmOutStateSeqError" |
	"XfrmOutStateExpired" |
	"XfrmOutPolBlock" |
	"XfrmOutPolDead" |
	"XfrmOutPolError" |
	"XfrmFwdHdrError" |
	"XfrmOutStateInvalid" |
	"XfrmAcquireError"

// #XfrmSaCountBucket is the aggregated SA count for a (proto, mode) pair.
// Maps to one time series of nft_xfrm_sa_count{proto=...,mode=...}.
// Produced by counting xfrm_usersa_info frames from XFRM_MSG_GETSA dump.
#XfrmSaCountBucket: {
	// proto is the IPsec transform protocol for this bucket.
	proto: #XfrmProto

	// mode is the SA operating mode for this bucket.
	mode: #XfrmMode

	// count is the number of SAs in this (proto, mode) combination.
	count: uint64
}

// #XfrmSpCountBucket is the aggregated SP count for a (dir, action) pair.
// Maps to one time series of nft_xfrm_sp_count{dir=...,action=...}.
// Produced by counting xfrm_userpolicy_info frames from XFRM_MSG_GETPOLICY dump.
#XfrmSpCountBucket: {
	// dir is the SPD entry direction for this bucket.
	dir: #XfrmPolicyDir

	// action is the SPD entry action for this bucket.
	action: #XfrmPolicyAction

	// count is the number of SPs in this (dir, action) combination.
	count: uint64
}

// #XfrmSadInfo holds the global SAD hash table watermarks from XFRM_MSG_GETSADINFO.
// Maps to nft_xfrm_sad_hash_count and nft_xfrm_sad_hash_max gauges.
#XfrmSadInfo: {
	// hash_count is the current number of entries in the SAD hash table (sadhcnt).
	// Maps to nft_xfrm_sad_hash_count gauge (no labels).
	hash_count: uint32

	// hash_max is the SAD hash table size (sadhmcnt, i.e. the bucket count).
	// Maps to nft_xfrm_sad_hash_max gauge (no labels).
	hash_max: uint32
}

// #XfrmSpdInfo holds the global SPD hash table watermarks from XFRM_MSG_GETSPDINFO.
// Maps to nft_xfrm_spd_hash_count and nft_xfrm_spd_hash_max gauges.
#XfrmSpdInfo: {
	// hash_count is the current number of entries in the SPD hash table (spdhcnt).
	// Maps to nft_xfrm_spd_hash_count gauge (no labels).
	hash_count: uint32

	// hash_max is the SPD hash table size (spdhmcnt).
	// Maps to nft_xfrm_spd_hash_max gauge (no labels).
	hash_max: uint32
}

// #XfrmStatEntry is one counter from /proc/net/xfrm_stat.
// Each entry maps to one series of nft_xfrm_stat_total{counter=key}.
#XfrmStatEntry: {
	// key is one of the 26 fixed kernel ABI counter names.
	key: #XfrmStatKey

	// value is the aggregated (already per-CPU summed by the kernel) counter value.
	value: uint64
}

// #XfrmSnapshot is the immutable ReadModel produced by XfrmIpsecCollector
// for one scrape epoch. It carries aggregated SA/SP counts, SAD/SPD watermarks,
// and XFRM error counters. No per-SA or per-SP label expansion occurs; all
// data is pre-aggregated into bounded label sets before reaching this ReadModel.
//
// When available=false (runtime gate: xfrm_user absent or EPERM at startup),
// sa_counts, sp_counts, sad_info, spd_info, and stat_counters are empty or
// zero-valued, and only nft_scrape_collector_available{collector="xfrm-ipsec"} 0
// is emitted.
#XfrmSnapshot: {
	// epoch_ns is the Unix nanosecond timestamp when this snapshot was captured.
	// Used by nft_exporter_snapshot_age_seconds self-metric.
	epoch_ns: uint64

	// available reflects the runtime gate result. false when xfrm_user is absent
	// or the capability check fails. Maps to
	// nft_scrape_collector_available{collector="xfrm-ipsec"}.
	available: bool

	// sa_counts is the aggregated SA count list by (proto, mode).
	// Sourced from XFRM_MSG_GETSA dump frame count.
	// Cardinality bound: at most |#XfrmProto| x |#XfrmMode| = 4 x 4 = 16 entries.
	// Empty when available=false or SAD is empty.
	sa_counts: [...#XfrmSaCountBucket]

	// sp_counts is the aggregated SP count list by (dir, action).
	// Sourced from XFRM_MSG_GETPOLICY dump frame count.
	// Cardinality bound: at most |#XfrmPolicyDir| x |#XfrmPolicyAction| = 3 x 2 = 6.
	// Empty when available=false or SPD is empty.
	sp_counts: [...#XfrmSpCountBucket]

	// sad_info holds global SAD hash watermarks from XFRM_MSG_GETSADINFO.
	// Absent when available=false.
	sad_info?: #XfrmSadInfo

	// spd_info holds global SPD hash watermarks from XFRM_MSG_GETSPDINFO.
	// Absent when available=false.
	spd_info?: #XfrmSpdInfo

	// stat_counters is the list of XFRM error counters from /proc/net/xfrm_stat.
	// Each entry maps to one nft_xfrm_stat_total series.
	// Cardinality bound: exactly 26 entries (kernel ABI-stable key set).
	// Empty when available=false or /proc/net/xfrm_stat is unreadable.
	stat_counters: [...#XfrmStatEntry]
}
