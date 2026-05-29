// DDD role: ReadModel
package schemas

// #CollectorStatus enumerates the result of a single collector's scrape attempt.
#CollectorStatus: "success" | "timeout" | "permission_denied" | "netlink_truncated" | "parse_error" | "kernel_unsupported" | "panic" | "stale_snapshot"

// #CollectorResult holds the per-collector outcome metadata recorded by
// ScrapeLifecycle. Used to populate nft_scrape_collector_success and
// nft_scrape_collector_duration_seconds self-metrics.
#CollectorResult: {
	// collector is the canonical collector slug used as the "collector" label.
	collector: #CollectorName

	// status is the final outcome of this collector's scrape attempt.
	status: #CollectorStatus

	// duration_ns is the wall-clock duration of this collector's scrape in nanoseconds.
	// Projected to seconds for nft_scrape_collector_duration_seconds gauge.
	duration_ns: uint64

	// is_stale indicates that the data in the corresponding ReadModel was carried
	// over from a previous epoch (catch-unwind stale-snapshot fallback activated).
	is_stale: bool
}

// #MetricSnapshot is the top-level immutable ReadModel produced by ScrapeLifecycle
// at the end of each GET /metrics pull cycle. It aggregates all subsystem
// ReadModels from one scrape epoch into a single value consumed by
// PrometheusRegistryAdapter for OpenMetrics text encoding.
//
// Lifecycle: created by ScrapeLifecycle after the JoinSet fan-out completes;
// passed to MetricRegistryPort.flush(); discarded after the HTTP response body
// is sent. Never stored durably; the kernel is the sole source of truth.
//
// Invariants:
//   - All epoch_ns fields within nested ReadModels should be <= snapshot_epoch_ns.
//   - A stale ReadModel from a previous epoch may be present when its collector
//     panicked or timed out and catch-unwind fallback activated.
//   - The snapshot is valid for exactly one /metrics HTTP response.
#MetricSnapshot: {
	// snapshot_epoch_ns is the Unix nanosecond timestamp when ScrapeLifecycle
	// completed the collect_all phase. Used for nft_scrape_duration_seconds.
	snapshot_epoch_ns: uint64

	// scrape_duration_ns is the total wall-clock duration of the full scrape
	// in nanoseconds (from pre_scrape_hook to post_process completion).
	// Projected to seconds for nft_scrape_duration_seconds gauge.
	scrape_duration_ns: uint64

	// collector_results holds the per-collector outcome metadata for all
	// collectors that were attempted in this scrape cycle (enabled or disabled).
	collector_results: [...#CollectorResult]

	// link is the LinkSnapshot from RtnetlinkCollector. Absent when the
	// rtnetlink collector is disabled in ExporterConfig.
	link?: #LinkSnapshot

	// route_table is the RouteTableSnapshot from RtnetlinkCollector.
	// Shares the same scrape epoch as link. Absent when rtnetlink is disabled.
	route_table?: #RouteTableSnapshot

	// neighbor is the NeighborSnapshot from RtnetlinkCollector.
	// Shares the same scrape epoch as link. Absent when rtnetlink is disabled.
	neighbor?: #NeighborSnapshot

	// tc_tree is the TcTreeSnapshot from TcCollector. Absent when the
	// traffic_control collector is disabled.
	tc_tree?: #TcTreeSnapshot

	// conntrack is the ConntrackSummary from ConntrackCollector. Absent when
	// the conntrack collector is disabled.
	conntrack?: #ConntrackSummary

	// nft is the NftCounterSnapshot from NftablesCollector. Absent when the
	// nftables collector is disabled.
	nft?: #NftCounterSnapshot

	// sockets is the SocketStateHistogram from SockDiagCollector. Absent when
	// the sock_diag collector is disabled.
	sockets?: #SocketStateHistogram

	// ethtool is the NicStatSnapshot from EthtoolCollector. Absent when the
	// ethtool collector is disabled.
	ethtool?: #NicStatSnapshot
}
