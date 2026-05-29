# CLAUDE.md — project guide for `nft_exporter`

Context for AI assistants working in this repository. Read this first; it captures the
non-obvious constraints that are easy to get wrong.

## What this is

A Prometheus exporter for full Linux network observability, reading the kernel **directly over
`AF_NETLINK`** on a **`monoio` / `io_uring`** runtime. Hexagonal (ports & adapters), 8 crates,
lock-free (`arc-swap` RCU + atomics). Binary name: **`netlink_exporter`** (NOT `nft_exporter` — that
is only the project/repo name). Serves Prometheus text `0.0.4` on `:9456` (`/metrics`, `/healthz`,
`/ready`).

## ⚠️ Build & toolchain constraints (read before building)

- **Rust is pinned to `1.96.0`** (`rust-toolchain.toml`), **edition 2024**, **MSRV `1.96`**
  (`Cargo.toml`). See [ADR-0003](docs/arch/adr/0003-rust-edition-and-toolchain.md).
- **The full workspace builds on Linux ONLY.** `monoio`'s io_uring data path is Linux-specific.
  `nlx-netlink`, `nlx-http`, and the `netlink_exporter` binary do **not** compile on macOS.
- **No musl / no static.** `monoio` does not compile against `*-linux-musl`; release binaries are
  **dynamic glibc** (`*-linux-gnu`). Container runtime is glibc distroless (`Dockerfile`).
- **Pure crates build anywhere:** `nlx-procfs`, `nlx-domain`, `nlx-ports`, `nlx-metrics`,
  `nlx-config` have no `monoio` dependency → `cargo test -p nlx-procfs` etc. run on macOS.
- The local mac uses **Homebrew Rust** (no rustup); it ignores `rust-toolchain.toml` and may lag the
  pinned version. With MSRV `1.96`, a local toolchain `< 1.96` will refuse to build — verify on the
  Linux build host instead.

## Dev loop (how work actually happens here)

- **Edit LOCAL** on the mac. **Build & test REMOTE** on the Linux box. Never edit on the server.
- Push code with `rsync` (exclude `target` and `.git`):
  `rsync -az --delete --exclude target --exclude .git -e "ssh -i ~/.ssh/id_rsa" ./ root@<host>:/root/nft_pr/`
- Build host: `ssh -l root 213.155.16.6` (key `~/.ssh/id_rsa`). Install the toolchain with
  `rustup ... --default-toolchain 1.96.0 --profile minimal` then `rustup component add rustfmt clippy`
  (do NOT pass `--component a b` to rustup-init — space-separated args are a usage error).
- **This box is PRODUCTION.** Real `mlx5` NICs and `wg-la1`/`wg-la2` WireGuard interfaces are live —
  never delete or modify them. **Clean up after every test** (`rm -rf /root/nft_pr ~/.rustup ~/.cargo`
  and kill any exporter); leave zero junk.

## ⚠️ Running the exporter over SSH (known hazard)

Do **not** start the exporter with `&` / `nohup` / `setsid` inside an ssh session that the harness
then backgrounds — the process group gets reaped (ssh exit 255, empty capture). Instead:

- Preferred: the **ssh-mcp** async model — `ssh_exec` the server (returns a `command_id`, stays
  alive), `curl` from a **separate** `ssh_exec` on the same session, then `ssh_exec_cancel` the server.
- Or: a **short foreground** ssh that completes within the tool timeout
  (`RUST_LOG=info ./netlink_exporter & sleep 6; curl >file; kill`) and read the file in a separate
  read-only ssh.

## Architecture (crates)

| Crate | Hexagonal role |
|-------|----------------|
| `nlx-domain` | Pure domain core — `MetricSample`, ReadModels, `DomainError`. No I/O, no infra deps. |
| `nlx-ports` | Ports — `Collector`, `MetricRegistryPort`, `HealthPort`, `ReadinessPort`, `ConfigPort`. |
| `nlx-netlink` | Driven adapters — 13 netlink/genetlink collectors. |
| `nlx-procfs` | Driven adapters — 8 opt-in procfs/sysfs collectors (the ONLY crate allowed to read `/proc`+`/sys`). |
| `nlx-metrics` | Prometheus `0.0.4` encoder + `ArcSwap` snapshot store + dedup guard. |
| `nlx-http` | Driving adapter — hand-rolled `monoio` HTTP/1 (`/metrics`, `/healthz`, `/ready`). |
| `nlx-config` | `NLX_` env + TOML loader (`figment`) + clap CLI. |
| `netlink_exporter` | Composition root / binary — `scrape.rs` builds the registry, `main.rs` wires + drops caps. |

## Collectors (21)

- **13 netlink, default ON:** `rtnetlink`, `rtnetlink_extended`, `traffic_control`, `conntrack`,
  `conntrack_expect`, `nftables`, `sock_diag`, `ethtool`, `ipvs`, `wireguard`, `devlink`,
  `drop_monitor`, `xfrm`.
- **8 procfs/sysfs, default OFF** (ADR-0027): `softnet`, `netstat`, `softirq`, `irq`, `sockstat`,
  `nic_bql`, `nic_pcie`, `nic_temp`.
- Enable a collector: env `NLX_COLLECTORS__<UPPER_NAME>=true` (double underscore nests into the flags
  struct), or the `[collectors]` TOML table. Registry: `crates/netlink_exporter/src/scrape.rs`
  (`push_if_enabled!`). Flags + `collector_enabled` match: `crates/nlx-config/src/config.rs`.

## Conventions & gates

- **Native-API-first** (ADR-0025): every datum that has a netlink API uses it. `/proc`+`/sys` reads
  are an opt-in exception (ADR-0027), default-off, isolated in `nlx-procfs` behind a path allowlist.
- **ADR-first** for architecture/feature changes (MADR under `docs/arch/adr/`); the impl-gate expects
  the artifact before source edits.
- **Metric contract:** `docs/arch/schemas/metric_contract.cue` — validate with
  `cd docs/arch/schemas && cue vet metric_contract.cue`. `nft_` prefix enforced; high-cardinality
  labels (flow_id, src_ip, …) forbidden. Update it whenever metric names/labels change.
- **C4 model:** `docs/arch/architecture/workspace.dsl` (Structurizr) — keep in sync with the code.
- **Verification (on the Linux build host):** `cargo build --workspace --release`,
  `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets`, `cargo test --workspace`.
- **Cardinality:** aggregate per-object series (qdisc per `device,kind`; AER per device, not per bit);
  the serializer's dedup guard is a backstop, not a license to emit dupes.
- **Do NOT** modify `Cargo.toml [lints.*]`, `clippy.toml`, `rust-toolchain.toml`, or `#![deny]`
  attributes without explicit user permission.
- **No CI:** `.github/` was intentionally removed; there is no automated gate. Verify locally/remotely.
- en-US for all artifacts; small contextual commits (Angular Conventional Commits).

## Known tech debt

- `nlx-netlink` carries ~249 clippy `indexing_slicing` / `arithmetic_side_effects` warnings (warnings,
  not errors — build is green). The same family was already cleaned in `nlx-procfs`. A
  behavior-preserving cleanup (`.get()` / `saturating_*`) is a good follow-up.
- `nlx-http` exposes a legacy `pub type AxumHttpAdapter = MonoioHttpAdapter` alias (no axum is used);
  renaming call sites and removing the alias is a minor cleanup.

## Release

- Tag `v0.1.0` is built from the tagged commit on the Linux host (glibc, x86_64); assets +
  `SHA256SUMS` are attached to the GitHub release. musl/static is not produced (see above).
