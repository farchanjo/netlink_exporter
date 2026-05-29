---
status: accepted
date: 2026-05-28
deciders: [eonf]
consulted: []
informed: []
---

# Cross-compile to musl on macOS and execute integration tests on remote Linux VM via Merkle vault_spawn bridge in CI

## Context and Problem Statement

`nft_exporter` speaks directly to the Linux kernel via raw `AF_NETLINK` sockets (ADR-0011). Unit tests that mock the socket layer can verify parser correctness but cannot detect regressions in:

- kernel `nlattr` alignment and `NLM_F_DUMP_INTR` semantics on real kernel versions.
- `nf_conntrack_stat` struct size variants (52/56/60 bytes) across kernel versions.
- `rtnl_link_stats64` at 192 vs 200 bytes (kernel < 5.18 vs >= 5.18).
- `NETLINK_GET_STRICT_CHK` availability on kernel < 4.20.
- Capability drop sequence (ADR-0009) followed by successful socket operations.

The development host is macOS; the CI runner fleet includes macOS agents. Neither platform can run AF_NETLINK. A remote Linux VM with netlink capabilities is required for integration testing. The VM is provisioned by the `vm.services` infrastructure and is accessible only via SSH with credentials stored in the Merkle vault.

The integration loop must:
1. Produce a fully static binary on macOS without a Linux sysroot.
2. Transfer the binary to the VM securely without exposing credentials in chat or CI logs.
3. Execute the binary as root, scrape `/metrics` twice at 15-second intervals, and validate the OpenMetrics response against the CUE metric contract schema.
4. Tear down the VM after the job regardless of outcome.

## Considered Options

- **Docker-in-Docker Linux container on the macOS CI runner**: avoids a remote VM but requires `--privileged` mode for AF_NETLINK; Docker Desktop's Linux VM does not expose the host netns, so conntrack and nftables data is empty.
- **QEMU-based local Linux VM managed by CI**: complex setup; QEMU is not available on all macOS CI runner tiers; VM lifecycle management adds significant CI YAML complexity.
- **Remote Linux VM on vm.services with Merkle vault_spawn bridge** (chosen): the VM runs native Linux with full netlink access; credential injection uses `vault_spawn` decode bridge, never `vault.reveal` + paste; binary transfer uses `ssh_rsync` for correctness and speed.

## Decision Outcome

**Chosen option: remote Linux VM on vm.services with Merkle vault_spawn bridge.**

The integration test loop proceeds in three phases:

### Phase 1: Cross-compile on macOS

```
cargo build --target x86_64-unknown-linux-musl --release
```

The musl toolchain is installed via `mise` (`.mise.toml` entry: `rust-target = "x86_64-unknown-linux-musl"`). The binary is fully static and requires no shared libraries on the target. An `aarch64-unknown-linux-musl` variant is built in parallel for ARM64 VM targets. No sysroot is required; the hermetic musl build property established by ADR-0004 and carried forward by ADR-0011 is preserved.

### Phase 2: Deploy and execute on the remote Linux VM

The SSH credential is stored at `vault://netlink-exporter/ssh/vm-services-root` in the Merkle vault. It is accessed exclusively via the `vault_spawn` decode bridge pattern:

1. `vault.write_tempfile` writes the private key to a memory-backed tempfile with mode 0600.
2. `vault.ssh.exec` (or the `ssh-mcp` `ssh_connect` + `ssh_exec` pattern proxied through `vault_spawn`) executes the binary as root on the VM.
3. `vault.revoke_tempfile` is called in the CI job `after_script` block, unconditionally.

The ssh-mcp v7.0 skill governs all remote operations. Hard rules enforced:

- `ssh_connect(reuse=auto, agent_id=nft_exporter_ci)` + `ssh_exec` for every command on the VM. `ssh_run` is never used (it pays a full handshake per call and tears the session down).
- Binary and fixture transfer via `ssh_rsync(transport=auto)`. `ssh_upload` is never chained for multi-file transfers.
- Async log streaming via `sub_open command://<id>/output` and `sub_close` on completion. Hot-polling via `ssh_shell_read` in a loop is forbidden.
- `sub_open` is always paired with `sub_close` (or `release_when_no_subs=true` on the final call).
- `ssh_disconnect` is called after all VM work is complete and the job outcome is recorded.

The exporter binary is executed as root for two scrape intervals (2 x 15 s). The scrape endpoint is validated with:

```
curl -sf http://127.0.0.1:9100/metrics | cue vet - docs/arch/schemas/metric_contract.cue
```

A non-zero exit from `cue vet` fails the integration job.

### Phase 3: GitLab CI integration

A new DAG stage `integration:remote` is added to `.gitlab-ci.yml`:

- Runs after `unit:test` and `build:musl` stages.
- Provisions the VM via the `vault_spawn` bridge.
- Runs the exporter binary for two scrape intervals (2 x 15 s).
- Scrapes `/metrics` and validates the OpenMetrics response against `docs/arch/schemas/metric_contract.cue` using `cue vet`.
- Tears down the VM after the job regardless of outcome (`after_script` always runs).
- Gated behind `CI_INTEGRATION_VM_ENABLED` variable (default: `"true"` on Linux runners, `"false"` on macOS-only runners).

A privileged Linux runner with a dedicated network namespace (`--network-mode=host`) is required for the `integration:remote` stage so that the CI job can reach the VM on `vm.services` and the exporter binary can open AF_NETLINK sockets if a local smoke-test mode is also desired.

**Consequences:**

- Positive: Integration tests exercise real kernel netlink paths, catching `nlattr` alignment bugs and struct size variants that unit tests cannot detect.
- Positive: The `vault_spawn` bridge ensures the SSH private key is never present in CI logs, environment variables visible to untrusted jobs, or Claude conversation context.
- Positive: The musl static binary approach means no runtime dependency installation on the VM; the test is the binary plus `curl` and `cue` which are pre-installed on all `vm.services` images.
- Negative: Integration tests depend on `vm.services` availability; network partitions or VM provisioning failures produce false negatives. Mitigated by a 3-minute timeout and automatic retry (max 2) on the `integration:remote` job.
- Negative: The `vault_spawn` pattern requires the Merkle vault daemon to be running on the macOS CI agent; this is enforced via the `SessionStart` hook check in `.claude/settings.json` but must also be verified in CI via a pre-job `vault.doctor` call.
