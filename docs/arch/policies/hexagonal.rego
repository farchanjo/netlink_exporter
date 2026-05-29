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
#     tracing-subscriber, rustix, netlink (ADR-0011 low-level syscall layer).
#
#   Async runtime crates (ADR-0014 adapter-confinement invariant):
#     tokio and mio are deny-level violations in domain-core crates. Port traits must
#     use plain `async fn` (desugars to `impl Future`, executor-agnostic). tokio and
#     mio may appear ONLY in driven adapter crates (nlx-netlink, nft_exporter_adapter_*)
#     and the binary composition root (bin/). A direct dependency in domain-core implies
#     the crate is wiring the runtime, which belongs exclusively to the composition root.
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
#
# Tokio/mio adapter-confinement invariant (ADR-0014):
#   tokio and mio are async-runtime infrastructure. Domain-core crates and
#   port-trait definitions must remain runtime-agnostic — port traits use
#   plain `async fn` syntax (desugars to `impl Future`, executor-agnostic).
#   tokio and mio may appear ONLY in driven adapter crates (e.g., nlx-netlink,
#   nft_exporter_adapter_*) and in the binary composition root (bin/).
#   Any direct dependency on tokio or mio in a domain-core crate is a
#   deny-level violation; it implies the crate is wiring the runtime, which
#   is exclusively the composition root's responsibility.
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
	# Low-level syscall and UAPI crates — adapter layer only (ADR-0011)
	"rustix",
	"linux-raw-sys",
	# Zero-copy wire codec crates — adapter layer only (ADR-0011/0014)
	"zerocopy",
	"bytemuck",
	"byteorder",
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

# Deny: domain-core or ports crate imports tokio directly.
#
# ADR-0014 (tokio/mio adapter-confinement invariant): tokio is an async runtime
# infrastructure crate. Domain-core crates and port-trait crates must not declare
# a direct dependency on tokio. Port traits use plain `async fn` (impl Future),
# which is executor-agnostic. tokio may only appear in driven adapter crates and
# the binary composition root. A direct tokio dependency in domain-core implies
# the crate is wiring the runtime — that responsibility belongs exclusively to
# the composition root (bin/).
deny contains msg if {
	crate := input.crates[_]
	is_domain_core(crate)
	dep := crate.dependencies[_]
	dep == "tokio"
	msg := sprintf(
		"domain-core crate %q must not depend on tokio; port traits use plain async fn (runtime-agnostic) — ADR-0014 adapter-confinement invariant",
		[crate.name],
	)
}

# Deny: domain-core or ports crate imports mio directly.
#
# ADR-0014: mio provides the epoll/kqueue readiness layer used by tokio's AsyncFd.
# It is infrastructure confined to the nlx-netlink driven adapter and the binary
# composition root. A direct mio dependency in domain-core crates is a violation
# of the same adapter-confinement invariant as tokio.
deny contains msg if {
	crate := input.crates[_]
	is_domain_core(crate)
	dep := crate.dependencies[_]
	dep == "mio"
	msg := sprintf(
		"domain-core crate %q must not depend on mio; mio is runtime infrastructure confined to driven adapters (nlx-netlink) and the composition root — ADR-0014",
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
