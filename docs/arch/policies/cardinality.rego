# cardinality.rego
#
# Package: nft_exporter.exposition.cardinality
#
# Intent: Enforce the bounded-cardinality contract from ADR-0005 (metric-cardinality-strategy).
#   The kernel exports unbounded dimensions such as per-flow tuples, per-route destination
#   prefixes, per-socket inodes, and per-conntrack-entry identifiers. Emitting any of these
#   as Prometheus label values would produce an unbounded time-series cardinality explosion,
#   violating the 50,000-series-per-node ceiling and potentially crashing Prometheus.
#
#   This policy denies any metric definition that includes a label from the forbidden
#   high-cardinality dimension list. Only bounded enumerations (protocol, state, direction,
#   route_type, family, hook, policy, collector, reason, etc.) are permitted.
#
#   Forbidden label names (case-insensitive):
#     flow_id, flow_key, src_ip, dst_ip, source_ip, destination_ip,
#     src_port, dst_port, source_port, destination_port,
#     route_prefix, destination_prefix, prefix,
#     socket_inode, inode,
#     conntrack_id, ct_id,
#     mac_address, mac, hw_addr
#
# Usage: conftest test --policy docs/arch/policies/ <input>
# Input shape: {"metrics": [{"name": "...", "type": "...", "labels": ["label1", "label2"]}]}

package nft_exporter.exposition.cardinality

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# Forbidden high-cardinality label names (all lower-case for case-insensitive comparison).
forbidden_labels := {
	"flow_id",
	"flow_key",
	"src_ip",
	"dst_ip",
	"source_ip",
	"destination_ip",
	"src_port",
	"dst_port",
	"source_port",
	"destination_port",
	"route_prefix",
	"destination_prefix",
	"prefix",
	"socket_inode",
	"inode",
	"conntrack_id",
	"ct_id",
	"mac_address",
	"mac",
	"hw_addr",
}

deny contains msg if {
	metric := input.metrics[_]
	label := metric.labels[_]
	lower(label) in forbidden_labels
	msg := sprintf(
		"metric %q uses high-cardinality label %q; forbidden by ADR-0005 (aggregate by bounded enum instead)",
		[metric.name, label],
	)
}
