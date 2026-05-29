# CLAUDE.md — authoritative onboarding guide for `nft_exporter`

This file is the first thing an AI assistant must read before touching any file in this repository.
It covers what the project is, how to build and test it, what rules to follow, and where every spec
artifact lives. Read top to bottom before writing a single line of code.

---

## What this is

A Prometheus exporter for full Linux network observability. It reads the kernel **directly over
`AF_NETLINK` / `NETLINK_GENERIC`** using a **`monoio` / `io_uring`** async runtime
(thread-per-core, no tokio). Architecture: hexagonal (ports-and-adapters), 8 crates,
lock-free (`arc-swap` RCU + `AtomicU64`/`AtomicBool`). The deployable binary is **`netlink_exporter`**
(`nft_exporter` is the project/repo name only). Serves Prometheus text `0.0.4` on port **`9456`**
at `/metrics`, `/healthz`, and `/ready`. 21 collectors — 13 netlink (default ON) + 8 procfs/sysfs
(default OFF, ADR-0027 opt-in).

> **Before building:** Linux-only full build (no macOS for `nlx-netlink`/`nlx-http`/binary).
> Builds are **dynamic glibc** — **musl does NOT work** (`monoio`'s io_uring path will not compile
> against `*-linux-musl`; verified). The release binary and the container image are both glibc; the
> `Makefile`/`Dockerfile` musl history (ADR-0008) is stale drift — ignore it. Rust pinned to
> `1.96.0` (`rust-toolchain.toml`). Binary name is `netlink_exporter`; env prefix is `NLX_`; port
> is `9456`.

---

## Respect the specs before writing code

**No source code is written or merged until the governing spec artifact exists or is updated.**

### Before you write code — change-type checklist

| Change type | Required spec artifact FIRST |
|---|---|
| Architecture or structural decision | Write/update an ADR (MADR 4.0) under `docs/arch/adr/NNNN-<slug>.md`; status must be `accepted` before implementation merges |
| New or renamed metric family / label | Update `docs/arch/schemas/metric_contract.cue`; pass `cue vet docs/arch/schemas/metric_contract.cue` |
| New observable behavior / feature | Create or update a Gherkin feature under `docs/arch/specs/features/<subsystem>.feature` |
| New domain value object or wire struct | Create `docs/arch/schemas/<name>_snapshot.cue`; file must begin with `// DDD role: <Role>` |
| New ubiquitous-language term | Add to `docs/arch/glossary.md` before using the term in code or comments |
| Data-collection change | Native kernel API first (ADR-0025); procfs/sysfs only via ADR-0027 opt-in path — requires its own ADR |
| hexagonal boundary change | Confirm `hexagonal.rego` and `cargo deny check bans` still pass; domain-core crates may never import infra crates |

The **full spec validation gate** — must exit 0 before any implementation code is written or merged:

```sh
spec validate
# or the equivalent manual steps:
cue vet ./docs/arch/schemas/...
conftest test --policy docs/arch/policies/ <input>
```

Run this locally before writing code (e.g. `make spec-validate`). There is **no CI** in the repo
(see "No CI" below), so this gate is enforced by discipline + the local impl-gate, not a pipeline.

**Key spec artifacts** (all under `docs/arch/`):
- `schemas/metric_contract.cue` — canonical metric family registry (primary gate)
- `adr/` — 28 decision records (see ADR Index)
- `specs/features/` — 18 Gherkin feature files
- `policies/` — 4 Rego policies (`cardinality.rego`, `hexagonal.rego`, `ddd_role.rego`, `metric_naming.rego`)
- `architecture/workspace.dsl` — authoritative C4 Structurizr model
- `glossary.md`, `slo/slo.md`, `operations/runbook.md`, `threat-model/threat-model.md`

---

## Build & Run

### Pinned toolchain, MSRV, edition

| Setting | Value |
|---|---|
| Pinned channel | `1.96.0` (`rust-toolchain.toml`) |
| MSRV | `1.96` (`workspace.package.rust-version`) |
| Edition | `2024` |
| Resolver | `3` |
| Registered targets | `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu` |

The local mac uses **Homebrew Rust** (no rustup), so `rust-toolchain.toml` is silently ignored.
If `cargo` refuses with an MSRV error, you are on the wrong host — use the Linux build host.

### Linux-only build constraint

**The full workspace does not build on macOS.** `monoio` (io_uring-first, thread-per-core) is
Linux-specific. Only `nlx-domain`, `nlx-ports`, `nlx-config`, `nlx-metrics`, and `nlx-procfs` build
on macOS (no `monoio` dependency).

**Musl does NOT build — ignore the musl targets.** The `Makefile` carries `build-musl-x86` /
`build-musl-arm64` targets and the `Dockerfile` once built static musl (ADR-0008), but `monoio`'s
io_uring data path does not compile against `*-linux-musl` (verified: `monoio` fails with ~15
compile errors). These targets are **stale drift** — they also reference `BINARY := nft_exporter`,
which is the wrong binary name (it is `netlink_exporter`). Build glibc only
(`*-unknown-linux-gnu`); the container image is glibc distroless.

### Linux kernel requirement

`monoio::FusionDriver` detects io_uring availability at runtime via `io_uring_setup(2)` and falls
back to epoll on `EPERM`/`ENOSYS`. Minimum: Linux 5.1. Recommended: 5.11+ (full opcode set).

### Required Linux capabilities

After netlink sockets are opened the process drops all capabilities except `CAP_NET_ADMIN`.

```
CAP_NET_ADMIN          # always required
CAP_SYS_ADMIN          # only when drop_monitor collector is enabled
```

### Configuration precedence

1. CLI flags (highest)
2. `NLX_`-prefixed environment variables (`NLX_COLLECTORS__SOFTNET=true` — double underscore for nesting)
3. `nft_exporter.toml` in the working directory
4. Built-in defaults (lowest)

| Env var | CLI flag | Default |
|---|---|---|
| `NLX_CONFIG_PATH` | `--config` | `nft_exporter.toml` |
| `NLX_LISTEN_ADDR` | `--listen-addr` | `0.0.0.0:9456` |
| `NLX_LOG_LEVEL` | `--log-level` | `info` |
| `NLX_SCRAPE_TIMEOUT_MS` | — | `30000` |

`RUST_LOG` (tracing-subscriber `EnvFilter`) takes precedence over `NLX_LOG_LEVEL`.

### HTTP endpoints

| Path | Purpose | Success | Failure |
|---|---|---|---|
| `GET /metrics` | Prometheus text 0.0.4 | `200 text/plain; version=0.0.4` | `500` |
| `GET /healthz` | Liveness | `200 OK` | `503` |
| `GET /ready` | Readiness | `200 OK` | `503` |

Hand-rolled HTTP/1 over `monoio::net::TcpListener` — no axum, no tower, no hyper.

### Build / run / install commands

```sh
# ── Verify pinned toolchain is installed ────────────────────────────────────
rustup show

# ── Debug build (macOS: pure crates only) ───────────────────────────────────
cargo build -p nlx-domain -p nlx-ports -p nlx-config -p nlx-metrics -p nlx-procfs

# ── Release build — Linux x86_64 (glibc) ────────────────────────────────────
cargo build --release --locked --bin netlink_exporter \
    --target x86_64-unknown-linux-gnu

# ── Release build — Linux aarch64 (glibc) ───────────────────────────────────
cargo build --release --locked --bin netlink_exporter \
    --target aarch64-unknown-linux-gnu

# ── Container image (glibc distroless runtime) ──────────────────────────────
docker build -f Dockerfile -t netlink_exporter:dev .
make docker    # tags as ghcr.io/example/nft_exporter:<git-describe>

# ── Run on Linux (built-in defaults) ────────────────────────────────────────
./target/release/netlink_exporter

# ── Run with overrides ──────────────────────────────────────────────────────
NLX_LISTEN_ADDR=0.0.0.0:9456 NLX_LOG_LEVEL=debug \
    ./target/release/netlink_exporter

./target/release/netlink_exporter --config /etc/nft_exporter/nft_exporter.toml

# ── Run as container ────────────────────────────────────────────────────────
docker run --rm --cap-add=NET_ADMIN -p 9456:9456 netlink_exporter:dev

# With drop_monitor (also needs CAP_SYS_ADMIN):
docker run --rm --cap-add=NET_ADMIN --cap-add=SYS_ADMIN \
    -p 9456:9456 -e NLX_LOG_LEVEL=debug netlink_exporter:dev

# ── Lint ────────────────────────────────────────────────────────────────────
make lint
# Equivalent manual steps (matches the Makefile lint target exactly):
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
# Note: cargo deny check is NOT part of make lint; run it separately if needed.

# ── Unit tests ──────────────────────────────────────────────────────────────
cargo test --workspace                          # Linux build host
cargo test -p nlx-procfs -p nlx-domain -p nlx-ports -p nlx-config -p nlx-metrics  # macOS (pure crates only)

# ── Verify endpoints (on a running instance) ─────────────────────────────────
curl http://localhost:9456/metrics
curl http://localhost:9456/healthz
curl http://localhost:9456/ready

# ── Clean ────────────────────────────────────────────────────────────────────
cargo clean
```

---

## Test & Verify

### Unit tests

All `#[cfg(test)]` blocks use in-process fakes implementing port traits. No live kernel or
AF_NETLINK socket is required. Six crates carry unit tests; `nlx-netlink` and `nlx-http` require a
Linux kernel so their tests only run on the build host.

```sh
# Linux build host — full workspace
cargo test --workspace

# macOS — only pure crates
cargo test -p nlx-procfs -p nlx-domain -p nlx-ports -p nlx-config -p nlx-metrics
```

### Metric contract validation

```sh
# Validate all CUE schemas
cue vet ./docs/arch/schemas/...

# Validate the specific contract file
cue vet docs/arch/schemas/metric_contract.cue

# Full spec gate (cue vet + Rego policies + MADR lint + Mermaid)
spec validate
```

### Live scrape validation

After running on the Linux host, validate the live output against the contract:

```sh
curl -sf http://127.0.0.1:9456/metrics | cue vet - docs/arch/schemas/metric_contract.cue
```

A non-zero exit means the implementation violates the contract. This is the integration test gate
(ADR-0012 Phase 3). `promtool` is not used; CUE is the sole validation gate.

### Lint baseline (never modify without permission)

Source: `Cargo.toml` lines 89–108 (`[workspace.lints.*]`).

Rust layer: `unsafe_code = warn` (every `unsafe` requires `SAFETY:` comment), `missing_docs = warn`,
`unused_must_use = deny`, `future_incompatible = deny`, `nonstandard_style = deny`.

Clippy layer: `pedantic = warn`, `missing_errors_doc = deny`, `missing_panics_doc = deny`,
`unwrap_used = deny`, `expect_used = deny`, `panic = deny`, `indexing_slicing = warn`,
`arithmetic_side_effects = warn`.

`nlx-netlink` currently carries ~249 `indexing_slicing`/`arithmetic_side_effects` warnings (advisory,
not errors — build is green). Do not treat these as new regressions.

### No CI

There is **no CI in the repo**: `.github/` was deliberately removed and there is no
`.gitlab-ci.yml`. (Some ADRs/docs describe an aspirational GitLab pipeline; it is not present here.)
Run every gate yourself before committing: `cargo fmt --all -- --check`, `cargo clippy`,
`cargo test --workspace` (on the Linux host), and `cue vet` / `make spec-validate` for the specs.

---

## Architecture

### Workspace layout

```
netlink_exporter  (binary — composition root)
    ├── nlx-config        (driven adapter — config: figment TOML + NLX_ env + clap CLI)
    ├── nlx-http          (driving adapter — hand-rolled monoio HTTP/1)
    ├── nlx-metrics       (driven adapter — Prometheus 0.0.4 encoder + ArcSwap snapshot)
    ├── nlx-netlink       (driven adapters — AF_NETLINK transport + 13 collectors)
    ├── nlx-procfs        (driven adapters — 8 opt-in procfs/sysfs collectors)
    ├── nlx-ports         ← nlx-domain  (port trait definitions)
    └── nlx-domain        (innermost — pure domain core, no I/O, no infra)
```

Dependency flow is strictly inward. Nothing in the inner rings imports from the outer rings.
`hexagonal.rego` (via `conftest`) and `cargo deny check bans` machine-enforce this constraint.

### Crate roles

| Crate | Hexagonal role | Key deps |
|---|---|---|
| `nlx-domain` | Domain core — `MetricSample`, `MetricKind`, `ReadModel`s, `ScrapeLifecycle`, domain errors | `thiserror`, `serde` (no infra) |
| `nlx-ports` | Port definitions — all driving and driven trait interfaces | `nlx-domain` only |
| `nlx-netlink` | Driven adapters — `NetlinkSocket` transport + 13 subsystem collectors | `rustix`, `linux-raw-sys`, `zerocopy`, `bytemuck`, `monoio`, `io-uring`, `caps` |
| `nlx-procfs` | Driven adapters — opt-in `/proc`/`/sys` collectors; ONLY crate allowed to read procfs/sysfs | `nlx-domain`, `nlx-ports`, `tracing` |
| `nlx-metrics` | Driven adapter — hand-encodes Prometheus text 0.0.4; stores result in `ArcSwap<Arc<str>>` | `nlx-domain`, `nlx-ports`, `arc-swap` |
| `nlx-http` | Driving adapter — hand-rolled HTTP/1 over `monoio::net::TcpListener`; routes `/metrics`, `/healthz`, `/ready` | `nlx-ports`, `monoio` |
| `nlx-config` | Driven adapter — `figment` (TOML + env) + `clap` CLI; implements `ConfigPort` | `nlx-domain`, `nlx-ports`, `figment`, `clap` |
| `netlink_exporter` | Composition root / binary — wires adapters, drops capabilities, drives serve loop | all above crates, `monoio`, `arc-swap`, `caps`, `anyhow` |

### Runtime

Single **monoio** `FusionDriver` runtime (io_uring-first, epoll fallback), constructed with
`attach_thread_pool(DefaultThreadPool::new(4))` to enable `monoio::spawn_blocking`. No tokio, no mio,
no axum.

Lock-free cross-thread state:
- `arc_swap::ArcSwap<Arc<str>>` — RCU store for encoded Prometheus body
- `std::sync::atomic::AtomicU64` — per-collector error counters (`Relaxed`)
- `std::sync::atomic::AtomicBool` — readiness flag

No `Mutex` or `RwLock` exists anywhere in the data path (ADR-0023).

### Netlink transport data path

`NetlinkSocket` (`crates/nlx-netlink/src/transport.rs`) wraps a raw `AF_NETLINK` `OwnedFd`. Because
AF_NETLINK sockets are blocking, `dump()` and `request_single()` `dup(2)` the fd, move it onto a
`monoio::spawn_blocking` thread, and there construct a per-call `io_uring::IoUring` ring (depth 32)
to submit `IORING_OP_SEND` + `IORING_OP_RECV` SQEs. Single-in-flight discipline satisfies the
io_uring buffer-lifetime contract without unsafe aliasing.

Wire families:

| Protocol | Value | Collectors |
|---|---|---|
| `NETLINK_ROUTE` | 0 | `rtnetlink`, `rtnetlink_extended`, `traffic_control` |
| `NETLINK_SOCK_DIAG` | 4 | `sock_diag` |
| `NETLINK_XFRM` | 6 | `xfrm` |
| `NETLINK_NETFILTER` | 12 | `conntrack`, `conntrack_expect`, `nftables` |
| `NETLINK_GENERIC` | 16 | `ethtool`, `ipvs`, `wireguard`, `devlink`, `drop_monitor` |

`resolve_genl_family()` sends `CTRL_CMD_GETFAMILY` to `GENL_ID_CTRL` to resolve dynamic family IDs
at startup.

### Scrape flow

```
HTTP GET /metrics
  → MonoioHttpAdapter::handle_metrics()                       [nlx-http / driving adapter]
      → ScrapeTriggerPort::scrape()                           [port trait]
          → ScrapeService::scrape()                           [scrape.rs / composition root]
              for each enabled Collector (Box<dyn Collector>):
                  monoio::time::timeout(scrape_timeout_ms, collector.collect())
                  → NetlinkSocket::dump() via spawn_blocking  [nlx-netlink / driven adapter]
                    IORING_OP_SEND + IORING_OP_RECV loop
                    parse_datagram() → Vec<Vec<u8>>
                    domain model construction → Vec<MetricSample>
              + procfs collectors (safe_read path-prefix allowlist)
              + self-telemetry samples
          → MetricRegistryPort::update_samples(Vec<MetricSample>)
              → PrometheusRegistryAdapter::encode_samples()   [nlx-metrics / driven adapter]
                  hand-encode Prometheus text 0.0.4
                  ArcSwap::store(Arc::new(Arc::from(text)))   ← atomic pointer swap
  → MetricRegistryPort::encode_text()
      → ArcSwap::load()                                       ← wait-free
  → HTTP 200 Content-Type: text/plain; version=0.0.4
```

Hung collectors are abandoned at `monoio::time::timeout`; `ScrapeService` marks failure,
increments `AtomicU64` error counter, and continues fan-out. Overall `scrape()` returns `Ok`
regardless of partial failures.

### Capability model (ADR-0009)

After all sockets are opened, `main.rs` calls `drop_caps_to_net_admin()` via the `caps` crate —
restricts the process to `CAP_NET_ADMIN` only (Effective, Permitted, Inheritable). Release profile
sets `panic = "abort"` so a capability-drop failure terminates immediately.

---

## Collectors & Metrics

### Netlink collectors — 13, default ON

Source: `crates/nlx-netlink/src/collectors/`; config keys under `[collectors]` TOML / `NLX_COLLECTORS__*` env.

| Collector | Config key | Netlink family | Purpose |
|---|---|---|---|
| `rtnetlink` | `collectors.rtnetlink` | `NETLINK_ROUTE` (0); `RTM_GETLINK`, `RTM_GETADDR`, `RTM_GETROUTE`, `RTM_GETNEIGH` | Link stats, IP addresses, route/neighbor counts |
| `rtnetlink_extended` | `collectors.rtnetlink_extended` | `NETLINK_ROUTE` (0); `RTM_GETSTATS`, `RTM_GETNEIGH` AF_BRIDGE, `RTM_GETRULE`, `RTM_GETNEXTHOP` | Bridge xstats, hw-offload xstats, bridge FDB, FIB rules, nexthop objects |
| `traffic_control` | `collectors.traffic_control` | `NETLINK_ROUTE` (0); `RTM_GETQDISC`, `RTM_GETTCLASS`, `RTM_GETTFILTER` | Qdisc bytes/packets/drops/overlimits/backlog; TC class and filter counters |
| `conntrack` | `collectors.conntrack` | `NETLINK_NETFILTER` (12); `IPCTNL_MSG_CT_GET_STATS_CPU`, flow dump | Flow counts by (protocol, state); byte/packet counters; per-CPU stats |
| `conntrack_expect` | `collectors.conntrack_expect` | `NETLINK_NETFILTER` (12), `NFNL_SUBSYS_CTNETLINK_EXP=2`; `IPCTNL_MSG_EXP_GET` | Active expectations by (l4proto, helper) |
| `nftables` | `collectors.nftables` | `NETLINK_NETFILTER` (12), `NFNL_SUBSYS_NFTABLES=10`; `NFT_MSG_GET*` | Table/chain/rule/named-counter metrics; set element counts; keyed by (table, chain, comment) |
| `sock_diag` | `collectors.sock_diag` | `NETLINK_SOCK_DIAG` (4); `SOCK_DIAG_BY_FAMILY` | Socket counts, queue bytes, drops, TCP retransmits by (protocol, state) |
| `ethtool` | `collectors.ethtool` | `NETLINK_GENERIC`; `ETHTOOL_MSG_STATS_GET` (cmd=32), PAUSE, FEC | IEEE NIC stats, pause frames, FEC errors. Runtime-gated. |
| `ipvs` | `collectors.ipvs` | `NETLINK_GENERIC`; `IPVS_CMD_GET_SERVICE`, `IPVS_CMD_GET_DEST` | VS metadata, EMA throughput, per-RS connection counts. Runtime-gated. |
| `wireguard` | `collectors.wireguard` | `NETLINK_GENERIC`; `WG_CMD_GET_DEVICE` | Per-interface, per-peer rx/tx bytes, handshake age. Peer pubkey hashed to 16-char hex. Runtime-gated. |
| `devlink` | `collectors.devlink` | `NETLINK_GENERIC`; `DEVLINK_CMD_GET`, `DEVLINK_CMD_PORT_GET`, `DEVLINK_CMD_HEALTH_REPORTER_GET` (52) | Device/port metadata, health reporter error/recover counts. Runtime-gated. |
| `drop_monitor` | `collectors.drop_monitor` | `NETLINK_GENERIC`; `NET_DM_CMD_STATS_GET` | SW/HW drop totals by reason. Hybrid: background multicast thread + per-scrape poll (ADR-0020). Runtime-gated. |
| `xfrm` | `collectors.xfrm` | `NETLINK_XFRM` (6); `XFRM_MSG_GETSA`, `XFRM_MSG_GETPOLICY`, `XFRM_MSG_GETSADINFO`, `XFRM_MSG_GETSPDINFO` | IPsec SA/SP counts, SAD/SPD hash occupancy, 26 XFRM error counters |

### Procfs/sysfs collectors — 8, default OFF (ADR-0027)

Source: `crates/nlx-procfs/src/`; all reads via `safe_read()` / `safe_read_dir()` with
path-prefix allowlist (`/proc/net`, `/proc/softirqs`, `/proc/interrupts`, `/proc/irq`,
`/sys/class/net`, `/sys/bus/pci/devices`). Enabling any of these requires explicit user opt-in.

| Collector | Config key | Kernel source | Purpose |
|---|---|---|---|
| `softnet` | `collectors.softnet` | `/proc/net/softnet_stat` | Per-CPU softirq receive path health |
| `netstat` | `collectors.netstat` | `/proc/net/snmp` + `/proc/net/netstat` | IP/TCP/UDP/ICMP MIB counters |
| `softirq` | `collectors.softirq` | `/proc/softirqs` | Per-CPU NET_RX/NET_TX counts |
| `irq` | `collectors.irq` | `/proc/interrupts` | Hardware IRQ counts by IRQ number and device |
| `sockstat` | `collectors.sockstat` | `/proc/net/sockstat` | Per-protocol socket allocation snapshot |
| `nic_bql` | `collectors.nic_bql` | `/sys/class/net/<dev>/queues/tx-*/byte_queue_limits/` | BQL limit ceiling and in-flight bytes |
| `nic_pcie` | `collectors.nic_pcie` | `/sys/class/net/<dev>/device/{current_link_speed,...}` | PCIe link speed/width, AER error counts; physical functions only |
| `nic_temp` | `collectors.nic_temp` | `/sys/class/net/<dev>/device/hwmon/` | NIC hardware temperature via hwmon sysfs |

### Enabling a collector

```sh
# Environment variable (double underscore = TOML nesting)
NLX_COLLECTORS__SOFTNET=true ./netlink_exporter
NLX_COLLECTORS__WIREGUARD=false ./netlink_exporter

# TOML config file
# [collectors]
# softnet  = true
# netstat  = true
# nic_pcie = true
# wireguard = false
```

Source of truth for flags and dispatch: `crates/nlx-config/src/config.rs` (`CollectorFlags`,
`collector_enabled()` at line 222–248). Registry build: `crates/netlink_exporter/src/scrape.rs`
(`push_if_enabled!`).

### Self-telemetry metrics

| Metric | Type | Key labels |
|---|---|---|
| `nft_scrape_duration_seconds` | gauge | — |
| `nft_scrape_collector_duration_seconds` | gauge | `collector` |
| `nft_scrape_collector_success` | gauge | `collector` |
| `nft_scrape_collector_error_total` | counter | `collector`, `reason` |
| `nft_scrape_collector_available` | gauge | `collector` |
| `nft_up` | gauge | — (primary health signal) |
| `nft_build_info` | gauge | `version`, `revision`, `rust_version`, `build_date` |
| `nft_netlink_socket_count` | gauge | `family` |
| `nft_netlink_errors_total` | counter | `family`, `errno` |
| `nft_exporter_snapshot_age_seconds` | gauge | `collector` |

### Cardinality rules (ADR-0005)

Forbidden as label values (enforced by `cardinality.rego`):
`flow_id`, `destination_prefix`, `source_prefix`, `socket_inode`, `mac_address`,
`src_ip`, `dst_ip`, `src_port`, `dst_port`

Aggregate always at collection time. Per-flow, per-destination-prefix, per-socket-inode
labels are never permitted. The 50,000-series-per-node ceiling is the operational constraint.

---

## Configuration

Config is resolved in CLI → env → TOML → defaults order. Key rules:

- `NLX_` prefix; nested keys use `__` (double underscore).
- TOML file is `nft_exporter.toml` in the working directory by default.
- `RUST_LOG` takes precedence over `NLX_LOG_LEVEL` for log filtering.
- Interface filtering: include/exclude regex via `[interface_filter]` section (ADR-0013).

Source: `crates/nlx-config/src/config.rs` (line 201: `listen_addr = "0.0.0.0:9456"`,
line 202: `scrape_timeout_ms = 30_000`); CLI args: `crates/nlx-config/src/cli.rs`.

---

## Conventions & Gates

### Commit convention (Angular Conventional Commits)

```
<type>(<scope>): <subject>
```

Types: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`, `perf`, `build`, `ci`.
Subject: imperative, lowercase, no trailing period, max 72 chars.
Breaking change: append `!` after scope and include a `BREAKING CHANGE:` footer.
ADR reference in footer: e.g. `ADR-0015: collector runtime gating`.
Never batch unrelated changes in one commit.

### Language

All written artifacts (code, comments, docs, commits, ADRs) must use **en-US** spelling and grammar.

### Lint files — never modify without permission

`Cargo.toml [lints.*]`, `clippy.toml`, `rust-toolchain.toml`, `#![deny]` attributes. Fix code to
comply with existing lint rules; never weaken the rules.

### Cardinality backstop

The serializer's dedup guard is a backstop, not a license to emit duplicate series. Aggregate at
collection time: qdisc per `(device, kind)`; AER per device (not per bit); conntrack per
`(protocol, state)` never per-flow; routes per `(table, family, protocol, route_type)` never
per-destination; WireGuard peers — truncated SHA-256 hex hash of pubkey, never raw key.

### Known tech debt

- `nlx-netlink` carries ~249 `indexing_slicing`/`arithmetic_side_effects` clippy warnings (advisory;
  build is green). Cleanup via `.get()` / `saturating_*` is a good follow-up.
- `nlx-http` exposes a legacy `pub type AxumHttpAdapter = MonoioHttpAdapter` alias (no axum used);
  minor rename cleanup is pending.

---

## Dev-loop & Gotchas

### Edit local, build remote

1. **Edit on the Mac.** Never edit directly on the Linux build host.
2. **Push with rsync** (exclude `target` and `.git`):
   ```sh
   rsync -az --delete --exclude target --exclude .git \
     -e "ssh -i ~/.ssh/id_rsa" \
     ./ root@213.155.16.6:/root/nft_pr/
   ```
3. **Build and test on the Linux host:**
   ```sh
   ssh -l root 213.155.16.6
   cd /root/nft_pr
   cargo build --workspace --release
   cargo test --workspace
   cargo clippy --workspace --all-targets -- -D warnings
   cargo fmt --all -- --check
   cargo deny check
   ```
4. **First-time toolchain install on the host** (run once, not every session):
   ```sh
   rustup-init --default-toolchain 1.96.0 --profile minimal -y
   rustup component add rustfmt clippy
   ```
   Do NOT pass `--component rustfmt clippy` as space-separated args to `rustup-init` — usage error.

5. **Clean up unconditionally after every test session.** The build host (`213.155.16.6`) is
   **production hardware** with live `mlx5` NICs and `wg-la1`/`wg-la2` WireGuard interfaces.
   Never delete or modify those.
   ```sh
   rm -rf /root/nft_pr ~/.rustup ~/.cargo
   pkill -f netlink_exporter || true
   ```

### SSH hazard: do NOT background the exporter with `&` in a single ssh call

`ssh root@host 'netlink_exporter &'` causes the process group to be reaped when the ssh session
closes → `ssh exit 255` + empty capture.

**Preferred — ssh-mcp async model:**
1. `ssh_exec` the exporter (returns a `command_id`, stays alive in the background).
2. `ssh_exec` a `curl` on the same persistent session.
3. `ssh_exec_cancel` the server command when done.

**Acceptable — foreground ssh that completes within tool timeout:**
```sh
ssh -i ~/.ssh/id_rsa root@213.155.16.6 \
  'RUST_LOG=info ./netlink_exporter & sleep 6; curl http://127.0.0.1:9456/metrics >/tmp/out; kill %1'
# then read /tmp/out in a separate read-only ssh call
```

Never use `nohup`, `setsid`, or `disown` inside a harness-managed ssh session.

### Remote integration test loop (ADR-0012)

Integration tests require a real Linux kernel. Kernel struct sizes vary by version
(`rtnl_link_stats64`: 192 bytes < 5.18, 200 bytes >= 5.18; `nf_conntrack_stat`: 52/56/60 bytes).
Docker-on-macOS cannot expose the host netns.

Three-phase loop:

**Phase 1 — build (glibc, on the Linux host):**
```sh
# musl does NOT work (monoio) — build glibc. Do NOT use `make build-musl-x86`
# (it targets musl + the stale `nft_exporter` binary name).
cargo build --release --locked --bin netlink_exporter --target x86_64-unknown-linux-gnu
# Produces: target/x86_64-unknown-linux-gnu/release/netlink_exporter
```

**Phase 2 — deploy via Merkle vault + ssh-mcp:**
- SSH key at `vault://netlink-exporter/ssh/vm-services-root`.
- Access via `vault.write_tempfile` (mode 0600) + `vault.revoke_tempfile` in cleanup. Never `vault.reveal` + paste.
- Transfer via `ssh_rsync` (never chained `ssh_upload`).
- Remote commands via `ssh_connect(reuse=auto)` + `ssh_exec` (never `ssh_run`).

**Phase 3 — validate:**
```sh
curl -sf http://127.0.0.1:9456/metrics | cue vet - docs/arch/schemas/metric_contract.cue
```

> ⚠️ `make test-remote` is **drifted**: it depends on the non-functional musl build and the stale
> `nft_exporter` binary name, so it does not run as-is. The reliable loop is manual: `rsync` the tree
> to the Linux host, build glibc there (above), run a short foreground scrape, then clean up. See
> "Dev-loop & Gotchas".

### macOS partial-build matrix

| Crate | macOS | Linux |
|---|---|---|
| `nlx-domain`, `nlx-ports`, `nlx-config`, `nlx-metrics`, `nlx-procfs` | yes | yes |
| `nlx-netlink`, `nlx-http`, `netlink_exporter` binary | **NO** | yes |

---

## ADR Index

All ADRs under `docs/arch/adr/` in MADR 4.0 format. Status must be `accepted` before implementation merges.

| Number | Title | Notes |
|---|---|---|
| 0001 | Record architecture decisions | |
| 0002 | Hexagonal (ports-and-adapters) architecture; no-infra-import rule for domain-core | |
| 0003 | Rust edition 2024, stable >= 1.96, native async fn in traits | |
| 0004 | rust-netlink org crate stack; vendored netlink-packet-netfilter patch | Superseded by 0011 |
| 0005 | Bounded cardinality on every metric family; forbidden per-flow/route/socket label dimensions | |
| 0006 | prometheus-client 0.24 (OpenMetrics-native) | Superseded by hand-rolled encoder |
| 0007 | tokio 1.52 single async runtime with per-scrape JoinSet fan-out | Superseded by 0023 |
| 0008 | Static musl binary in distroless | Superseded by glibc / 0023 |
| 0009 | CAP_NET_ADMIN only; drop all other caps after socket open | |
| 0010 | axum 0.8 HTTP server | Superseded by hand-rolled monoio HTTP (0023) |
| 0011 | Direct AF_NETLINK wire protocol across all subsystem adapters | |
| 0012 | Remote integration tests on Linux VM via Merkle vault_spawn + ssh-mcp in CI | |
| 0013 | Include/exclude regex filtering for interface names; per-collector enable flags | |
| 0014 | tokio + mio confined to driven adapters; AsyncFd for AF_NETLINK readiness | Superseded by 0023 |
| 0015 | Gate each collector on subsystem availability; emit availability series | |
| 0016 | XFRM/IPsec collector via NETLINK_XFRM, runtime-gated | |
| 0017 | IPVS (LVS) collector via generic-netlink, runtime-gated | |
| 0018 | WireGuard collector via generic-netlink, runtime-gated | |
| 0019 | devlink collector via direct netlink, runtime-gated | |
| 0020 | drop-monitor via NET_DM generic-netlink; hybrid multicast accumulator | |
| 0021 | rtnetlink-extended bounded context (xstats, bridge FDB, FIB rules, nexthops) | |
| 0022 | conntrack-expectations collector via ctnetlink, runtime-gated | |
| 0023 | monoio 0.2 io_uring-first runtime; replace tokio/mio/axum in adapter layer | |
| 0024 | Drive netlink data path with io_uring SEND/RECV | |
| 0025 | Native kernel APIs only — no procfs/sysfs reads (hard default) | |
| 0026 | drop-monitor: hybrid multicast accumulator (real totals) + overflow-pull health | |
| 0027 | Opt-in procfs/sysfs relax for stack, IRQ, and hardware metrics | |
| 0028 | Aggregate nic_pcie AER counters to bound exposition cardinality | |

---

## File Map — where to find X

| What you need | Path |
|---|---|
| Binary entry point | `crates/netlink_exporter/src/main.rs` |
| Scrape fan-out + collector registry | `crates/netlink_exporter/src/scrape.rs` |
| CLI flags | `crates/nlx-config/src/cli.rs` |
| Config defaults + `CollectorFlags` + `collector_enabled()` | `crates/nlx-config/src/config.rs` |
| AF_NETLINK transport (io_uring send/recv) | `crates/nlx-netlink/src/transport.rs` |
| All 13 netlink collectors (one file each) | `crates/nlx-netlink/src/collectors/` |
| All 8 procfs/sysfs collectors | `crates/nlx-procfs/src/` |
| Prometheus encoder + ArcSwap snapshot | `crates/nlx-metrics/src/registry.rs` |
| Hand-rolled HTTP/1 server + route table | `crates/nlx-http/src/server.rs` |
| Domain core (MetricSample, ReadModels, errors) | `crates/nlx-domain/src/` |
| Port traits (all driving + driven interfaces) | `crates/nlx-ports/src/` |
| **Metric contract (primary spec gate)** | `docs/arch/schemas/metric_contract.cue` |
| All CUE schemas (26 files) | `docs/arch/schemas/` |
| Rego policies (4 policies) | `docs/arch/policies/` |
| Gherkin features (18 files) | `docs/arch/specs/features/` |
| C4 Structurizr model | `docs/arch/architecture/workspace.dsl` |
| ADRs (28 decisions) | `docs/arch/adr/` |
| OpenAPI spec | `docs/arch/api/openapi.yaml` |
| Glossary | `docs/arch/glossary.md` |
| SLO | `docs/arch/slo/slo.md` |
| Operations runbook | `docs/arch/operations/runbook.md` |
| Threat model | `docs/arch/threat-model/threat-model.md` |
| Domain notes + wire docs | `docs/arch/domain/` |
| CUE module root | `docs/arch/cue.mod/` |
| Workspace manifest (lints, shared deps) | `Cargo.toml` |
| Toolchain pin | `rust-toolchain.toml` |
| Container image definition | `Dockerfile` |
| Make targets | `Makefile` |
| Wire references: kernel, nftables, iproute2 | `~/dev/linux-6.17.13`, `~/dev/nftables`, `~/dev/iproute2` |

---

## Release

Tag `v0.1.0` ships a **dynamic glibc x86_64** binary built from the tagged commit on the Linux host
(`netlink_exporter-v0.1.0-x86_64-unknown-linux-gnu.tar.gz` + `SHA256SUMS`). No musl/static artifact
is produced — `monoio` does not compile against musl (ADR-0008 superseded by the glibc/ADR-0023
runtime).
