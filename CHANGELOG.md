# Changelog

All notable changes to nft_exporter will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.1] - 2026-05-30

### Changed

- **Default HTTP listen port `9456` → `33400`** (ADR-0010 amendment); still
  configurable via `NLX_LISTEN_ADDR` / `--listen-addr`.
- **Rust toolchain + MSRV → `1.96`** (edition 2024). Release profile optimized:
  `opt-level=3`, `lto="fat"`, `codegen-units=1`, `strip="symbols"`.
- **`nic_pcie` AER counters aggregated per device** (dropped the `kind` label) —
  ADR-0028; ~91% fewer series for that collector.
- Builds are **dynamic glibc** (musl dropped — `monoio` is glibc-only,
  ADR-0023); container image on glibc distroless.

### Added

- **Debian package (`.deb`)** — systemd unit, `/etc/default/nft_exporter`
  (EnvironmentFile), conffiles, and `make deb` (ADR-0029). `Depends: libc6,
  libcap2-bin`.
- Rewritten **Makefile** (`make deb` / `release` / `lint` / `test` / …) using the
  correct binary name (`netlink_exporter`) and the glibc target.

### Fixed

- **`drop_monitor` starts under the packaged service**: startup `CAP_SYS_ADMIN`
  (NET_DM multicast join, ADR-0026) is granted via **file capabilities**
  (`setcap`), because systemd `AmbientCapabilities` does not satisfy the join.
  The unit runs non-root and the binary drops to `CAP_NET_ADMIN` after the join.
- Cleared pre-existing clippy `indexing_slicing` / `arithmetic_side_effects`
  warnings in the procfs collectors.

### Docs

- Presentation-quality README with a full deployment guide; spec-first
  `CLAUDE.md` onboarding guide; C4 `workspace.dsl` refreshed to the
  monoio/wire-direct architecture; GitHub Actions CI removed.

## [0.1.0] - 2026-05-29

### Added

#### Architecture specification (docs/arch)

- **ADR-0001**: Adopt MADR 4.0 for recording architecture decisions.
- **ADR-0002**: Hexagonal ports-and-adapters architecture with
  `cargo deny` enforcement of no-infra-import rule in domain-core crates.
- **ADR-0003**: Rust edition 2024 pinned at stable >= 1.87 with native
  `async fn` in traits (no `async-trait` proc-macro dependency).
- **ADR-0004** (superseded by ADR-0011): Initial netlink crate stack
  selection (rtnetlink, netlink-packet-\*, rustables, genetlink).
- **ADR-0005**: Bounded cardinality strategy — aggregate-only model,
  forbidden label dimensions (flow_id, src_ip, dst_ip, src_port, dst_port,
  socket_inode, mac_address, destination_prefix, source_prefix), 50,000
  series per node ceiling.
- **ADR-0006** (superseded by ADR-0011): prometheus-client 0.24.1 crate
  selection.
- **ADR-0007** (superseded by ADR-0014): Initial async collection model
  using tokio 1.52 with per-scrape JoinSet fan-out.
- **ADR-0008**: Static musl binary packaging (x86_64 + aarch64) in
  `gcr.io/distroless/static-debian12:nonroot` with nfpm .deb/.rpm packages,
  cosign OIDC signing, SLSA L3 provenance, and syft SPDX-JSON SBOM.
- **ADR-0009**: `CAP_NET_ADMIN` only; immediate post-socket-open capability
  drop via caps 0.5.6; reject `CAP_NET_RAW` and `CAP_SYS_ADMIN` by design;
  custom seccomp profile and systemd hardening.
- **ADR-0010** (superseded by ADR-0011): HTTP exposition stack using axum.
- **ADR-0011**: Direct AF_NETLINK wire protocol implementation across all
  subsystem adapters using rustix 1.1.4, linux-raw-sys 0.12.1, zerocopy 0.8,
  bytemuck 1.25, byteorder 1.5.0; supersedes crate-based stack.
- **ADR-0012**: Cross-compile to musl on macOS; execute integration tests on
  remote Linux VM via Merkle vault_spawn bridge; ssh-mcp v7.0 governs all
  remote operations.
- **ADR-0013**: Interface and collector filtering via
  `interface_include_regex` / `interface_exclude_regex` per collector.
- **ADR-0014**: tokio + mio runtime selection with AsyncFd for non-blocking
  AF_NETLINK I/O; supersedes ADR-0007.
- **ADR-0015**: Collector runtime gating — every collector probes subsystem
  availability at scrape time; absent subsystems emit
  `nft_scrape_collector_available{collector}=0` rather than failing the scrape.
- **ADR-0016**: xfrm-ipsec collector for NETLINK_XFRM SA/SP/xfrm_stat
  metrics, runtime-gated.
- **ADR-0017**: IPVS collector via NETLINK_GENERIC IPVS family,
  runtime-gated.
- **ADR-0018**: WireGuard collector via NETLINK_GENERIC wireguard family,
  runtime-gated; peer identity via SHA-256(public_key)[0..8] hex hash.
- **ADR-0019**: Devlink collector via NETLINK_GENERIC devlink family,
  runtime-gated; health reporter state and error/recovery counters.
- **ADR-0020**: Drop-monitor collector via NETLINK_GENERIC NET_DM family in
  summary mode, opt-in runtime-gated.
- **ADR-0021**: RtnetlinkExtended collector for RTM_GETSTATS
  (bridge/offload xstats), RTM_GETNEIGH AF_BRIDGE (FDB entry count),
  RTM_GETRULE (fib rules per family), RTM_GETNEXTHOP (nexthop objects),
  opt-in.
- **ADR-0022**: ConntrackExpectations collector for IPCTNL_MSG_EXP_GET and
  IPCTNL_MSG_EXP_GET_STATS_CPU; aggregated by (l4proto, helper).

#### CUE schemas (docs/arch/schemas)

- `config.cue` — ExporterConfig schema.
- `conntrack_expectation.cue`, `conntrack_flow.cue`, `conntrack_summary.cue`
  — Conntrack and ConntrackExpectations ReadModel schemas.
- `ctnetlink_wire.cue` — ctnetlink wire-protocol struct schema.
- `devlink_snapshot.cue` — Devlink ReadModel schema.
- `drop_monitor_snapshot.cue` — DropMonitor ReadModel schema.
- `ethtool_wire.cue` — ethtool genetlink wire schema.
- `interface_filter.cue` — interface filtering configuration schema.
- `ipvs_snapshot.cue` — IPVS ReadModel schema.
- `link_snapshot.cue`, `link.cue` — rtnetlink Link ReadModel schema.
- `metric_contract.cue` — authoritative metric family contract; 70+
  `#MetricDescriptor` rows covering rtnetlink, traffic-control, conntrack,
  nftables, sock-diag, ethtool, xfrm-ipsec, ipvs, wireguard, devlink,
  drop-monitor, rtnetlink-extended, and conntrack-expectations bounded
  contexts, plus self-telemetry metrics.
- `metric_snapshot.cue`, `netlink_socket.cue`, `netlink_wire_protocol.cue`
  — core domain and wire-protocol schemas.
- `nft_chain.cue`, `nft_counter_snapshot.cue` — nftables ReadModel schemas.
- `nic_stat_snapshot.cue` — ethtool NicStat ReadModel schema.
- `route_table_snapshot.cue` — route table ReadModel schema.
- `rtnetlink_extended.cue`, `rtnetlink_wire.cue` — extended rtnetlink
  schemas.
- `socket_state_histogram.cue` — SockDiag SocketStateHistogram schema.
- `tc_tree_snapshot.cue` — TrafficControl TcTree ReadModel schema.
- `wireguard_snapshot.cue` — WireGuard ReadModel schema.
- `xfrm_snapshot.cue` — XFRM IPsec ReadModel schema.

#### Rego policies (docs/arch/policies)

- `cardinality.rego` — rejects metric definitions with unbounded label
  dimensions; enforced in CI against metric_contract.cue.
- `ddd_role.rego` — enforces DDD tactical role annotations in domain-core
  crates.
- `hexagonal.rego` — rejects infra imports in domain-core crates.
- `metric_naming.rego` — enforces `nft_` prefix, snake_case, and base-unit
  naming conventions.

#### Gherkin features (docs/arch/specs/features)

- `cardinality-guard.feature`
- `collector-failure-isolation.feature`
- `conntrack-expectations.feature`
- `conntrack.feature`
- `devlink.feature`
- `drop-monitor.feature`
- `ethtool.feature`
- `ipvs.feature`
- `link-address.feature`
- `nftables.feature`
- `remote-integration.feature`
- `route-neighbor.feature`
- `rtnetlink-extended.feature`
- `scrape-lifecycle.feature`
- `sock-diag.feature`
- `tc-qdisc.feature`
- `wireguard.feature`
- `xfrm-ipsec.feature`

#### Domain documentation

- `docs/arch/domain/overview.md` — bounded-context map, hexagonal
  ports-and-adapters diagram, ubiquitous language table, and design
  invariants.
- `docs/arch/domain/netlink-protocol.md` — netlink wire-protocol reference
  (nlmsghdr, nlattr, NLM_F_DUMP, NLM_F_DUMP_INTR, nfgenmsg).
- `docs/arch/domain/ethtool-wire-notes.md` — ethtool genetlink wire notes.
- `docs/arch/glossary.md` — ubiquitous language glossary covering all
  bounded contexts and key infrastructure terms.
- `docs/arch/slo/slo.md` — SLO definitions (scrape success rate, latency,
  availability).
- `docs/arch/operations/runbook.md` — operator runbook.
- `docs/arch/threat-model/threat-model.md` — full STRIDE threat model with
  impact/likelihood ratings and mitigations for all ten threat scenarios.

[Unreleased]: https://github.com/eonf/nft_exporter/compare/HEAD...HEAD
