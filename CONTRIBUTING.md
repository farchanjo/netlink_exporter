# Contributing to nft_exporter

## Table of Contents

- [Prerequisites](#prerequisites)
- [Development Workflow (Spec-First)](#development-workflow-spec-first)
- [Conventional Commits](#conventional-commits)
- [Cross-Musl Build](#cross-musl-build)
- [Remote Integration Test Loop](#remote-integration-test-loop)
- [How to Add a New Collector](#how-to-add-a-new-collector)

---

## Prerequisites

| Tool | Version | Purpose |
|---|---|---|
| Rust toolchain | stable >= 1.87 (pinned in `rust-toolchain.toml`) | Compiler and `cargo` |
| `mise` | any | Manages musl cross-compilation targets and auxiliary tools |
| `cue` | >= 0.9 | Schema validation (`spec validate`) |
| `cargo deny` | >= 0.16 | Dependency policy enforcement |
| Merkle vault daemon | running locally | SSH credential bridge for integration tests |

Install the Rust toolchain targets declared in `rust-toolchain.toml`:

```
rustup show   # installs the pinned toolchain and both musl targets automatically
```

---

## Development Workflow (Spec-First)

All changes follow a spec-first sequence. **No implementation code may be
merged without prior spec validation passing.** The guard is enforced by
`spec validate` in the `spec:validate` CI stage which runs before
`unit:test` and `build:musl`.

### 1. Update the spec

Every change that introduces, modifies, or removes a metric family, a domain
concept, a port, or an infrastructure decision must begin here:

| Artifact | Location | Required when |
|---|---|---|
| ADR (MADR 4.0) | `docs/arch/adr/NNNN-<slug>.md` | Any architectural or infrastructure decision |
| CUE schema | `docs/arch/schemas/<name>.cue` | New domain value object or wire-protocol struct |
| `metric_contract.cue` row | `docs/arch/schemas/metric_contract.cue` | Any new or changed metric family |
| Gherkin feature | `docs/arch/specs/features/<name>.feature` | New observable behavior |
| Glossary entry | `docs/arch/glossary.md` | New ubiquitous-language term |

### 2. Validate the spec

```
spec validate
```

This command runs `cue vet`, Rego policy checks (cardinality, hexagonal
boundary, DDD role, metric naming), MADR lint, and Mermaid diagram syntax
checks. All checks must pass with exit 0 before writing implementation code.

### 3. Implement

Write Rust code to satisfy the Gherkin scenarios and CUE contracts you
validated in step 2. Domain-core crates must never import infrastructure
crates; `cargo deny check bans` enforces this rule in CI.

### 4. Run unit tests

```
cargo test --workspace
```

All collectors have in-process fakes implementing the port traits. No Linux
kernel is required for unit tests.

### 5. Run the linter

```
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
cargo deny check
```

### 6. Open a merge request

Reference the ADR number(s) in the MR description. The CI pipeline runs
`spec:validate`, `unit:test`, `build:musl`, `integration:remote` (on Linux
runners), and `security:scan` in dependency order.

---

## Conventional Commits

Commit messages must follow the Angular format:

```
<type>(<scope>): <subject>
```

**Types:** `feat`, `fix`, `refactor`, `test`, `docs`, `chore`, `perf`,
`build`, `ci`

**Scopes** (examples): `rtnetlink`, `conntrack`, `nftables`, `sockdiag`,
`ethtool`, `tc`, `wireguard`, `devlink`, `drop-monitor`, `xfrm-ipsec`,
`ipvs`, `rtnetlink-extended`, `conntrack-expectations`, `spec`, `ci`, `sec`

**Rules:**

- Subject line in imperative present tense, lowercase, no trailing period,
  72 characters maximum.
- Breaking changes append `!` after the scope: `feat(conntrack)!: ...` and
  include a `BREAKING CHANGE:` footer.
- Reference ADR numbers in the footer: `ADR-0015: collector runtime gating`.
- Never batch unrelated changes in one commit. Break work into small,
  contextual commits.

**Examples:**

```
feat(conntrack): add expectation statistics from IPCTNL_MSG_EXP_GET_STATS_CPU

ADR-0022: conntrack expectations
```

```
fix(rtnetlink): handle rtnl_link_stats64 200-byte struct on kernel >= 5.18
```

```
docs(spec): add metric_contract rows for devlink health reporter counters

ADR-0019: devlink
```

---

## Cross-Musl Build

The release binary is a fully static musl binary with no dynamic library
dependencies. Both x86_64 and aarch64 targets are required for CI to pass.

### Local build (macOS or Linux)

```
cargo build --target x86_64-unknown-linux-musl --release
cargo build --target aarch64-unknown-linux-musl --release
```

The musl targets are declared in `rust-toolchain.toml`; `rustup` installs
them automatically. No sysroot is required; the hermetic musl property is
preserved by using only pure-Rust dependencies (rustix, zerocopy, bytemuck,
byteorder, tokio, axum, prometheus-client).

### Verifying the binary is fully static

```
file target/x86_64-unknown-linux-musl/release/nft_exporter
# must contain: statically linked, stripped
```

### Build profile

The release profile (`Cargo.toml`) sets `opt-level = "s"`, `lto = true`,
`codegen-units = 1`, `panic = "abort"`, `strip = "symbols"`. Link-time
optimization increases build time (approximately 4 minutes on a 4-core
runner) but is only applied on `--release`; incremental dev builds use the
`dev` profile.

---

## Remote Integration Test Loop

Integration tests run on a remote Linux VM on `vm.services` because macOS
and Docker-on-macOS cannot expose real AF_NETLINK sockets to the container
(see ADR-0012).

### Prerequisites

The SSH private key must be stored in the Merkle vault before running
integration tests:

```
vault bind netlink-exporter
# key must be at vault://netlink-exporter/ssh/vm-services-root
```

The vault daemon must be running locally:

```
vault doctor
```

### Triggering the loop manually

The CI pipeline handles the full loop automatically. To run it manually from
the development host, follow the three-phase process described in ADR-0012:

**Phase 1 — Cross-compile:**

```
cargo build --target x86_64-unknown-linux-musl --release
```

**Phase 2 — Deploy and execute:**

Use the Merkle vault bridge to inject the SSH credential without exposing it
in the shell. The key is always accessed via `vault.write_tempfile` +
`vault.revoke_tempfile`; never revealed or pasted. Remote operations use
`ssh_connect` (reuse=auto) + `ssh_exec`; never `ssh_run`. Binary transfer
uses `ssh_rsync`; never chained `ssh_upload` calls.

**Phase 3 — Validate:**

After two scrape intervals (2 x 15 s), validate the metric output against
the CUE contract:

```
curl -sf http://127.0.0.1:9456/metrics | cue vet - docs/arch/schemas/metric_contract.cue
```

A non-zero exit from `cue vet` means the implementation violates the metric
contract and must be fixed before merge.

### CI gate

The `integration:remote` DAG stage runs after `unit:test` and `build:musl`.
It is gated behind `CI_INTEGRATION_VM_ENABLED` (default `"true"` on Linux
runners). VM teardown always runs in `after_script`, regardless of test
outcome.

---

## How to Add a New Collector

Each collector is a new **bounded context** with a **driven port** and a
**Strategy** implementation. The process is:

### Step 1: Write the ADR

Create `docs/arch/adr/NNNN-<subsystem-slug>.md` (next sequential number).
The ADR must document:

- The netlink API family and message types involved.
- Why `CAP_NET_ADMIN` is sufficient (or request an exception via ADR-0009).
- Whether the collector is always-on, opt-in, or runtime-gated (see ADR-0015).
- Any kernel version constraints and how older kernels are handled.

Status must be `accepted` before the implementation is merged.

### Step 2: Add CUE schemas

Create or extend files under `docs/arch/schemas/`:

- `<subsystem>_snapshot.cue` — CUE schema for the ReadModel struct.
- `<subsystem>_wire.cue` (if applicable) — CUE schema for the wire-protocol
  structs (nlmsghdr, nlattr layout, struct sizes).

### Step 3: Add metric_contract rows

Add one `#MetricDescriptor` entry per new metric family to
`docs/arch/schemas/metric_contract.cue`. Every entry must:

- Use the `nft_` prefix (enforced by `#MetricName`).
- Declare `context` matching the bounded-context slug.
- Set `cardinality_bound` to a human-readable worst-case ceiling.
- List no label in `#ForbiddenLabelName` (flow_id, src_ip, dst_ip,
  src_port, dst_port, socket_inode, mac_address, destination_prefix,
  source_prefix).

### Step 4: Write a Gherkin feature

Create `docs/arch/specs/features/<subsystem>.feature`. The feature must
cover at least:

- Normal collection scenario (subsystem present, happy path).
- Runtime-gating scenario (if applicable): module absent produces
  `nft_scrape_collector_available{collector="<name>"}=0`.
- Stale-snapshot scenario: subsystem errors do not fail the whole scrape.

### Step 5: Run spec validate

```
spec validate
```

All checks must pass before writing Rust code.

### Step 6: Implement the bounded context

Create the following crate structure (or add to an existing crate if the
subsystem shares a netlink socket family):

```
nft_exporter_domain_<subsystem>/   # domain-core: port trait + ReadModel
nft_exporter_adapter_<subsystem>/  # adapter: port implementation
```

Domain-core crates must not import any infrastructure crate. The Rego
policy `hexagonal.rego` and `cargo deny` enforce this rule in CI.

Implement `probe_availability()` per ADR-0015. For runtime-gated collectors,
the probe issues `CTRL_CMD_GETFAMILY` (genetlink) or a `stat(2)` check (procfs
sentinel). A permanent `ENOENT` must result in `Ok(false)`, not an error.

Register the new collector in `CollectorRegistry` (`ExporterApp`). No
changes to `ScrapeLifecycle` are needed; the Strategy + Abstract Factory
pattern (ADR-0002, ADR-0015) makes `ScrapeLifecycle` open to extension
without modification.

### Step 7: Update docs

- Add the new bounded context and its ReadModel to `docs/arch/domain/overview.md`.
- Add new ubiquitous-language terms to `docs/arch/glossary.md`.
- Update the Structurizr workspace DSL at `docs/arch/architecture/workspace.dsl`.

### Step 8: Open the merge request

Reference the ADR in the MR description. The CI pipeline validates spec
artifacts, runs unit tests with in-process fakes, builds the musl binary,
and executes the remote integration test loop against the new collector.
