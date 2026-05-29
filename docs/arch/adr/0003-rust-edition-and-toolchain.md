---
status: accepted
date: 2026-05-28
deciders: [eonf]
consulted: []
informed: []
---

# Use Rust edition 2024 pinned at stable >= 1.87 with native async fn in traits

## Context and Problem Statement

The exporter declares `async trait` ports for all six netlink subsystems and three cross-cutting ports (MetricRegistryPort, ClockPort, ConfigPort). Before Rust 1.75, `async fn` in traits required the `async-trait` proc-macro crate, which wraps every return type in `Pin<Box<dyn Future>>`, introducing a heap allocation per call and additional compile-time dependency.

The team must choose an edition and minimum supported Rust version (MSRV) that gives access to native async fn in traits, edition 2024 language improvements, and supports the two musl cross-compilation targets (`x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`) needed for hermetic static binaries.

## Considered Options

- Rust stable >= 1.87 edition 2024 with native async fn in traits (chosen)
- Rust stable edition 2021 with async-trait crate
- Rust nightly

## Decision Outcome

**Chosen option: Rust stable >= 1.87 edition 2024 with native async fn in traits.**

`rust-toolchain.toml` at workspace root pins `channel = "stable"` with `components = ["rustfmt", "clippy"]` and `targets = ["x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl"]`. Every `Cargo.toml` in the workspace declares `edition = "2024"`. The workspace `Cargo.toml` sets `rust-version = "1.87"` so `cargo check --offline` reports a clear error on older toolchains.

Native `async fn` in traits (stabilized in 1.75) eliminates the `async-trait` proc-macro dependency. The `return-position impl Trait in traits` (RPITIT) feature, stable since 1.75, is used for the `ClockPort` and `ConfigPort` sync traits. Edition 2024 provides the improved `impl Trait` scoping rules and the refined `let`-chains syntax used in netlink attribute parsing.

**Consequences:**

- Positive: No heap allocation per port dispatch call; all port calls are zero-cost async with direct state-machine monomorphization.
- Positive: `async-trait` proc-macro is removed from the dependency graph, reducing compile time and eliminating a common source of confusing error messages around `Send` bounds.
- Positive: Edition 2024 `if let` chains reduce boilerplate in netlink attribute decoding arms.
- Positive: Both musl targets are declared in `rust-toolchain.toml`; `rustup` installs them automatically in CI.
- Negative: Contributors must use stable >= 1.87; older distro-shipped `rustc` versions are not supported. The `rust-version` field in `Cargo.toml` surfaces a clear error.
- Negative: Edition 2024 breaks a small number of edition 2021 patterns (e.g., `gen` is now a reserved keyword); all crates must be audited and migrated during the edition bump.

**Rejected options:**

- *Rust stable edition 2021 with async-trait crate*: Adds `async-trait 0.1` as a mandatory dependency in every domain-core crate, embedding `Box<dyn Future>` allocations on every netlink port dispatch (up to six concurrent per scrape). Also pulls in `syn` and `proc-macro2` into the build graph.
- *Rust nightly*: Nightly features are unstable by definition; the toolchain can break any day. CI pinning nightly to a specific date creates maintenance overhead and blocks automatic stable security updates. Static musl cross-compilation is fully supported on stable.
