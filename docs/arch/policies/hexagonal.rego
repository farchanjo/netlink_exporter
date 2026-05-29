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
#     monoio, monoio-http, monoio-compat, service-async (ADR-0023 io_uring runtime layer),
#     axum, hyper, prometheus-client, prometheus, clap, config, serde_json, caps,
#     tracing-subscriber, rustix, netlink (ADR-0011 low-level syscall layer).
#
#   Async runtime crates (ADR-0023 adapter-confinement invariant, supersedes ADR-0014):
#     monoio and monoio-http are the mandated io_uring runtime. They are deny-level
#     violations in domain-core crates. Port traits must use plain `async fn` (desugars
#     to `impl Future`, executor-agnostic). monoio may appear ONLY in driven adapter
#     crates (nlx-netlink, nft_exporter_adapter_*) and the binary composition root (bin/).
#     tokio and mio are no longer permitted anywhere in the workspace (removed by ADR-0023).
#     A direct dependency on tokio, mio, monoio, or monoio-http in domain-core implies
#     the crate is wiring the runtime, which belongs exclusively to the composition root.
#
#   Input shape (produced by a companion script that reads Cargo.toml files):
#   {
#     "crates": [
#       {
#         "name": "nft_exporter_rtnetlink_core",
#         "is_domain_core": true,
#         "dependencies": ["monoio", "thiserror", "rtnetlink"]
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
# monoio adapter-confinement invariant (ADR-0023, supersedes ADR-0014):
#   monoio 0.2 is the mandated io_uring async runtime. Domain-core crates and
#   port-trait definitions must remain runtime-agnostic — port traits use
#   plain `async fn` syntax (desugars to `impl Future`, executor-agnostic).
#   monoio and monoio-http may appear ONLY in driven adapter crates (e.g.,
#   nlx-netlink, nft_exporter_adapter_*) and in the binary composition root
#   (bin/). tokio and mio have been removed from the workspace (ADR-0023);
#   they appear in this set to deny any accidental re-introduction.
#   Any direct dependency on monoio, monoio-http, tokio, or mio in a domain-core
#   crate is a deny-level violation; it implies the crate is wiring the runtime,
#   which is exclusively the composition root's responsibility.
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
	# io_uring async runtime — adapter layer and composition root only (ADR-0023)
	"monoio",
	"monoio-http",
	"monoio-compat",
	"service-async",
	# Lock-free RCU snapshot sharing — adapter/composition-root only (ADR-0023 lock-free invariant)
	"arc-swap",
	# Removed runtime crates — deny re-introduction (ADR-0023 supersedes ADR-0014)
	"tokio",
	"mio",
	# HTTP server and client — adapter layer only (axum removed by ADR-0023; kept to deny re-introduction)
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
	# Zero-copy wire codec crates — adapter layer only (ADR-0011/0023)
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

# Deny: domain-core or ports crate imports monoio directly.
#
# ADR-0023 (monoio adapter-confinement invariant, supersedes ADR-0014): monoio 0.2
# is the mandated io_uring async runtime infrastructure crate. Domain-core crates
# and port-trait crates must not declare a direct dependency on monoio or
# monoio-http. Port traits use plain `async fn` (impl Future), which is
# executor-agnostic. monoio may only appear in driven adapter crates (nlx-netlink,
# nft_exporter_adapter_*) and the binary composition root. A direct monoio
# dependency in domain-core implies the crate is wiring the runtime — that
# responsibility belongs exclusively to the composition root (bin/).
deny contains msg if {
	crate := input.crates[_]
	is_domain_core(crate)
	dep := crate.dependencies[_]
	dep == "monoio"
	msg := sprintf(
		"domain-core crate %q must not depend on monoio; port traits use plain async fn (runtime-agnostic) — ADR-0023 adapter-confinement invariant",
		[crate.name],
	)
}

# Deny: domain-core or ports crate imports monoio-http directly.
#
# ADR-0023: monoio-http is the HTTP server layer confined to the nlx-http driven
# adapter. It is infrastructure; domain-core crates have no HTTP concern.
deny contains msg if {
	crate := input.crates[_]
	is_domain_core(crate)
	dep := crate.dependencies[_]
	dep == "monoio-http"
	msg := sprintf(
		"domain-core crate %q must not depend on monoio-http; HTTP is infrastructure confined to the nlx-http adapter — ADR-0023",
		[crate.name],
	)
}

# Deny: domain-core or ports crate imports tokio directly.
#
# tokio has been removed from the workspace by ADR-0023. This rule prevents
# accidental re-introduction via a new crate added to domain-core.
deny contains msg if {
	crate := input.crates[_]
	is_domain_core(crate)
	dep := crate.dependencies[_]
	dep == "tokio"
	msg := sprintf(
		"domain-core crate %q must not depend on tokio; tokio was removed from the workspace by ADR-0023 (replaced by monoio)",
		[crate.name],
	)
}

# Deny: domain-core or ports crate imports mio directly.
#
# mio has been removed from the workspace by ADR-0023. This rule prevents
# accidental re-introduction.
deny contains msg if {
	crate := input.crates[_]
	is_domain_core(crate)
	dep := crate.dependencies[_]
	dep == "mio"
	msg := sprintf(
		"domain-core crate %q must not depend on mio; mio was removed from the workspace by ADR-0023",
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
