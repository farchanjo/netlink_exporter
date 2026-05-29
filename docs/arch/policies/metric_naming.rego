# metric_naming.rego
#
# Package: nft_exporter.exposition.metric_naming
#
# Intent: Enforce the metric naming contract defined in docs/arch/schemas/metric_contract.cue.
#   Every metric family emitted by nft_exporter MUST satisfy all four rules simultaneously:
#     1. Name is snake_case (lower-case letters, digits, underscores only; no hyphens, no dots).
#     2. Name is prefixed with "nft_" (project namespace guard).
#     3. Counter metrics have names ending in "_total" (OpenMetrics _total suffix mandate).
#     4. Non-base units are forbidden: names must not contain "_milliseconds", "_microseconds",
#        "_nanoseconds", "_kilobytes", "_megabytes", "_gigabytes", "_kbps", "_mbps", "_gbps"
#        (base units are bytes, seconds, bits, packets, none).
#
# Usage: conftest test --policy docs/arch/policies/ <input>
# Input shape: {"metrics": [{"name": "...", "type": "counter|gauge", ...}]}

package nft_exporter.exposition.metric_naming

import future.keywords.contains
import future.keywords.if

# Rule 1 + 2: name must be snake_case and start with "nft_"
deny contains msg if {
	metric := input.metrics[_]
	not regex.match(`^nft_[a-z][a-z0-9_]*$`, metric.name)
	msg := sprintf(
		"metric %q violates naming: must match ^nft_[a-z][a-z0-9_]*$ (snake_case with nft_ prefix)",
		[metric.name],
	)
}

# Rule 3: counter type metrics must end in "_total"
deny contains msg if {
	metric := input.metrics[_]
	metric.type == "counter"
	not endswith(metric.name, "_total")
	msg := sprintf(
		"counter metric %q must end with _total (OpenMetrics requirement)",
		[metric.name],
	)
}

# Rule 4: non-base time units forbidden (milliseconds, microseconds, nanoseconds)
deny contains msg if {
	metric := input.metrics[_]
	non_base_time_units := ["_milliseconds", "_microseconds", "_nanoseconds"]
	unit := non_base_time_units[_]
	contains(metric.name, unit)
	msg := sprintf(
		"metric %q uses non-base time unit %q; use _seconds instead",
		[metric.name, unit],
	)
}

# Rule 4: non-base size units forbidden (kilobytes, megabytes, gigabytes)
deny contains msg if {
	metric := input.metrics[_]
	non_base_size_units := ["_kilobytes", "_megabytes", "_gigabytes"]
	unit := non_base_size_units[_]
	contains(metric.name, unit)
	msg := sprintf(
		"metric %q uses non-base size unit %q; use _bytes instead",
		[metric.name, unit],
	)
}

# Rule 4: non-base rate units forbidden (_kbps, _mbps, _gbps)
deny contains msg if {
	metric := input.metrics[_]
	non_base_rate_units := ["_kbps", "_mbps", "_gbps"]
	unit := non_base_rate_units[_]
	contains(metric.name, unit)
	msg := sprintf(
		"metric %q uses non-base rate unit %q; use _bits_per_second or emit raw counter and let Prometheus compute rate",
		[metric.name, unit],
	)
}
