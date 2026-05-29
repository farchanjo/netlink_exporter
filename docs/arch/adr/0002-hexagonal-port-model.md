---
status: accepted
date: 2026-05-28
deciders: [eonf]
consulted: []
informed: []
---

# Adopt hexagonal (ports-and-adapters) architecture with no-infra-import rule for domain-core crates

## Context and Problem Statement

The nft_exporter must read from six distinct Linux netlink/genetlink API families and expose the result as OpenMetrics text over HTTP. Without a clear architectural boundary, infrastructure concerns (rtnetlink socket I/O, prometheus-client registry types, axum handler signatures) would bleed into the collection and aggregation logic. This coupling makes domain logic untestable without a live kernel and prevents replacing any infrastructure crate without modifying collection code.

The team needs a structural rule that is machine-enforceable, not just a convention, to prevent infra imports from entering domain-core crates over time.

## Considered Options

- Hexagonal ports-and-adapters (chosen)
- Layered architecture without port traits
- Single-crate monolith with feature flags

## Decision Outcome

**Chosen option: hexagonal ports-and-adapters.**

Domain-core crates declare only `async trait` ports and domain value objects. They must not import `rtnetlink`, `rustables`, `prometheus-client`, `axum`, or any other infrastructure crate. All infrastructure dependencies live exclusively in adapter crates (`nft_exporter_adapter_rt`, `nft_exporter_adapter_tc`, `nft_exporter_adapter_ct`, `nft_exporter_adapter_nft`, `nft_exporter_adapter_sockdiag`, `nft_exporter_adapter_ethtool`, `nft_exporter_adapter_prom`, `nft_exporter_adapter_http`).

Enforcement: `cargo deny` rules in `deny.toml` list domain-core crate names and reject any dependency path that would introduce infra crates into them. Workspace-level `[dependencies]` table in `Cargo.toml` does not re-export infra crates.

**Consequences:**

- Positive: Domain aggregates (`Link`, `ConntrackFlow`, `NftChain`) and ReadModels are testable with in-process fakes implementing the port traits, requiring no running kernel.
- Positive: Swapping a netlink client crate (e.g., replacing `rtnetlink 0.21` with a future `0.22`) is scoped entirely to one adapter crate and does not touch domain logic.
- Positive: `cargo deny check bans` in CI provides a hard gate; PRs that add infra imports to domain-core crates fail the build.
- Negative: More crates in the workspace increases initial setup complexity and compile-unit graph depth.
- Negative: Developers must understand the port abstraction before adding a new metric family; a short onboarding document in `docs/arch/` is required.

**Rejected options:**

- *Layered architecture without port traits*: Domain code would call rtnetlink APIs directly, making unit tests require a live netlink socket or extensive mocking of concrete types. The Linux-specific code path would be untestable on macOS CI runners.
- *Single-crate monolith with feature flags*: Feature flags do not enforce dependency isolation; `#[cfg(feature = "rtnetlink")]` does not prevent accidental imports in non-flagged modules. Compile times for the full crate grow proportionally with all six collector paths.
