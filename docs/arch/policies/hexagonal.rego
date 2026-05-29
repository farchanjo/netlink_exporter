# hexagonal.rego
#
# Package: nft_exporter.architecture.hexagonal
#
# Intent: Enforce the hexagonal (ports-and-adapters) no-infra-import rule from ADR-0002.
#   Domain-core crates MUST NOT import infrastructure crates. The rule is:
#
#     A crate whose name matches *_core or nft_exporter_domain_* (domain side) must not
#     declare a dependency on any crate in the forbidden infrastructure set.
#
#   Forbidden infrastructure crates in domain-core context:
#     rtnetlink, netlink-packet-route, netlink-packet-netfilter, netlink-packet-sock-diag,
#     netlink-proto, netlink-sys, netlink-packet-generic, genetlink, ethtool, rustables,
#     axum, hyper, prometheus-client, prometheus, clap, config, serde_json, caps,
#     tracing-subscriber, tokio (only the rt-multi-thread / macros features imply infra;
#     the domain may use tokio traits only through its port definitions — runtime start is
#     infra; however, because feature-level enforcement is outside Cargo.toml dependency
#     graph inspection, we flag any direct tokio dependency in domain-core crates as a
#     warning-level violation requiring review).
#
#   Input shape (produced by a companion script that reads Cargo.toml files):
#   {
#     "crates": [
#       {
#         "name": "nft_exporter_rtnetlink_core",
#         "is_domain_core": true,
#         "dependencies": ["tokio", "thiserror", "rtnetlink"]
#       },
#       ...
#     ]
#   }
#
# Usage: conftest test --policy docs/arch/policies/ <cargo-manifest.json>

package nft_exporter.architecture.hexagonal

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# Infrastructure crates that domain-core crates must never depend on.
infra_crates := {
	# Netlink transport and codec crates — adapter layer only
	"rtnetlink",
	"netlink-packet-route",
	"netlink-packet-netfilter",
	"netlink-packet-sock-diag",
	"netlink-packet-generic",
	"netlink-proto",
	"netlink-sys",
	"genetlink",
	"ethtool",
	"rustables",
	# HTTP server and client — adapter layer only
	"axum",
	"hyper",
	"tower",
	"tower-http",
	# Prometheus client — exposition adapter layer only
	"prometheus-client",
	"prometheus",
	# CLI parsing — infra entry-point only
	"clap",
	# Config file parsing — infra config adapter only
	"config",
	# JSON serialization — infra only (domain uses plain Rust types)
	"serde_json",
	# Capability management — infra startup only
	"caps",
	# Structured logging subscriber — infra only (domain may use tracing macros via the tracing facade, not subscriber)
	"tracing-subscriber",
	# systemd notify — infra only
	"sd-notify",
	"libsystemd",
}

# A crate is classified as domain-core if the manifest explicitly marks it.
is_domain_core(crate) if {
	crate.is_domain_core == true
}

# Deny: domain-core crate imports a forbidden infrastructure crate.
deny contains msg if {
	crate := input.crates[_]
	is_domain_core(crate)
	dep := crate.dependencies[_]
	dep in infra_crates
	msg := sprintf(
		"domain-core crate %q must not depend on infrastructure crate %q (ADR-0002: hexagonal no-infra-import rule)",
		[crate.name, dep],
	)
}

# Warn (expressed as deny with [WARN] prefix): domain-core crate imports tokio directly.
# Tokio async traits (AsyncRead, AsyncWrite) are acceptable via indirect dependency through
# port trait definitions, but a direct dependency suggests the crate may be wiring the runtime.
deny contains msg if {
	crate := input.crates[_]
	is_domain_core(crate)
	dep := crate.dependencies[_]
	dep == "tokio"
	msg := sprintf(
		"[WARN] domain-core crate %q has a direct tokio dependency; verify only port trait bounds are used (no rt-multi-thread/macros features) — ADR-0002",
		[crate.name],
	)
}

# Deny: any crate that is NOT an adapter and NOT domain-core references infra crates.
# Catches shared utility crates that accidentally pull in infrastructure.
deny contains msg if {
	crate := input.crates[_]
	not crate.is_domain_core
	not crate.is_adapter
	dep := crate.dependencies[_]
	dep in infra_crates
	msg := sprintf(
		"shared/utility crate %q depends on infrastructure crate %q; only adapter crates may reference infra — ADR-0002",
		[crate.name, dep],
	)
}
