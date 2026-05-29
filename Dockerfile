# syntax=docker/dockerfile:1
# -----------------------------------------------------------------------------
# nft_exporter container image — dynamic glibc binary on a distroless runtime.
#
# NOTE: musl / fully-static builds are NOT used. The monoio io_uring data path
# (ADR-0023/0024) links glibc and does not compile against musl, so the binary
# is dynamically linked (ldd: libc.so.6, libgcc_s.so.1). The original static
# musl approach (ADR-0008) is therefore superseded for this runtime.
# -----------------------------------------------------------------------------

# --- Stage 1: build -----------------------------------------------------------
FROM rust:1.96-slim AS builder

WORKDIR /build

# Copy the full Cargo workspace: manifests, lockfile, toolchain pin, and every
# member crate under crates/. The toolchain pin (rust-toolchain.toml) keeps the
# build reproducible at the project's pinned Rust version.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates

# Build the release binary. [profile.release] sets panic = "abort".
# BuildKit cache mounts speed up rebuilds without baking caches into the layer.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release --locked --bin netlink_exporter \
 && strip target/release/netlink_exporter \
 && cp target/release/netlink_exporter /netlink_exporter

# --- Stage 2: runtime ---------------------------------------------------------
# distroless/cc carries glibc + libgcc_s (what the dynamic binary needs) and
# nothing else — no shell, no package manager. Runs as uid 65532 (nonroot).
FROM gcr.io/distroless/cc-debian12:nonroot

COPY --from=builder /netlink_exporter /usr/local/bin/netlink_exporter

# Prometheus metrics / health port (ADR-0010).
EXPOSE 33400

# Defaults — override with `docker run -e` or Kubernetes `env:`.
# The exporter reads NLX_-prefixed variables (double-underscore nests into the
# collector flags, e.g. NLX_COLLECTORS__NIC_PCIE=true).
ENV NLX_LISTEN_ADDR="0.0.0.0:33400" \
    NLX_LOG_LEVEL="info" \
    NLX_SCRAPE_TIMEOUT_MS="30000"

# The process opens netlink sockets, then drops to CAP_NET_ADMIN at runtime.
# Grant CAP_NET_ADMIN (and CAP_SYS_ADMIN if the drop_monitor collector is
# enabled) via the container/orchestrator security context — see the README.
ENTRYPOINT ["/usr/local/bin/netlink_exporter"]
