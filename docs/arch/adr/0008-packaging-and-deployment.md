---
status: accepted
date: 2026-05-28
deciders: [eonf]
consulted: []
informed: []
---

# Ship as static musl binary (x86_64 + aarch64) in gcr.io/distroless/static-debian12:nonroot and as .deb/.rpm systemd packages

## Context and Problem Statement

The exporter must run on heterogeneous Linux environments: Kubernetes clusters (x86_64 and ARM64 nodes), bare-metal servers running Debian/Ubuntu, and RPM-based systems running RHEL/Rocky. A glibc dynamic binary introduces runtime libc version coupling; a container image with a glibc runtime (e.g., `debian:bookworm-slim`) carries a large attack surface and must be updated whenever glibc CVEs are published.

The team needs a packaging strategy that is hermetic (no runtime library dependencies), reproducible (same binary from the same source), minimal attack surface, and compatible with both the Kubernetes and systemd deployment targets.

## Considered Options

- static musl + distroless:nonroot (chosen)
- glibc dynamic binary in alpine runtime
- Multi-process one-binary-per-subsystem architecture

## Decision Outcome

**Chosen option: static musl binary in distroless:nonroot with nfpm .deb/.rpm packages.**

**Build flags**: `RUSTFLAGS="-C target-feature=+crt-static"` with Cargo profile `[profile.release]`: `opt-level = "s"`, `lto = true`, `codegen-units = 1`, `panic = "abort"`, `strip = "symbols"`. The result is a fully static musl binary with no dynamic library dependencies (`ldd` output: `not a dynamic executable`).

**Cross-compilation**: CI uses `cross 0.2.x` (Docker-based cross-compilation) for `aarch64-unknown-linux-musl`. Local development uses `cargo-zigbuild` as a fallback (no Docker required). Both produce bit-identical binaries given the same source commit.

**Container runtime image**: `gcr.io/distroless/static-debian12:nonroot` referenced by `sha256` digest in `Dockerfile` and Kubernetes manifests. The nonroot variant sets uid/gid 65532 (`nonroot:nonroot`). The container has no shell, no package manager, and no C library; the only file is the `nft_exporter` binary plus `/etc/passwd` and `/etc/ssl/certs/`.

**Container image signing**: `cosign` keyless OIDC signing in CI (GitHub Actions OIDC provider); SLSA L3 provenance attached as an OCI referrer; `syft` SPDX-JSON SBOM attached as an OCI referrer; `Trivy` and `Grype` CVE scans run against the final image layer before push.

**Systemd packages**: `nfpm` generates `.deb` and `.rpm` packages from `nfpm.yaml`. The package installs the binary at `/usr/local/bin/nft_exporter`, creates system user `nft-exporter` (uid allocated by the distro), and installs `nft-exporter.service` with `AmbientCapabilities=CAP_NET_ADMIN`, `NoNewPrivileges=true`, and `ProtectSystem=strict`.

**Consequences:**

- Positive: Zero runtime library dependencies; the binary runs on any Linux kernel >= 5.12 regardless of the host libc version or installed packages.
- Positive: The distroless image has a minimal CVE surface; only the Rust standard library (compiled into the binary) and the nft_exporter code itself need to be scanned.
- Positive: Image digest pinning in manifests prevents silent tag mutation; Renovate Bot updates the digest reference via PR with a CI check gate.
- Positive: `panic = "abort"` eliminates stack unwinding code, reducing binary size; `strip = "symbols"` removes DWARF debug info from the release binary (debug info ships separately as a detached `.dbg` artifact in CI).
- Negative: `lto = true` with `codegen-units = 1` increases release build time significantly (measured at ~4 minutes on a 4-core GitHub Actions runner for the x86_64 target). Incremental builds use the `dev` profile; LTO applies only to `release`.
- Negative: musl's allocator (dlmalloc) is less performant than glibc's ptmalloc2 under sustained allocation pressure. For the nft_exporter's allocation pattern (short-lived per-scrape ReadModel vecs, low sustained throughput) this is not a concern.

**Rejected options:**

- *glibc dynamic binary in alpine runtime*: Alpine uses musl libc, making the "glibc dynamic + alpine" combination contradictory. A glibc dynamic binary in a `debian:bookworm-slim` runtime image pulls in ~80 MB of packages and requires separate CVE management for libc. The distroless image is ~2 MB.
- *Multi-process one-binary-per-subsystem architecture*: Splitting the six collectors into separate processes requires IPC (Unix socket or shared memory) for the scrape aggregation step, adding latency and operational complexity. It also requires six separate DaemonSet containers per node, multiplying the pod count and Kubernetes control-plane load.
