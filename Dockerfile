# -----------------------------------------------------------------------------
# Stage 1: build — cross-compile a fully static musl binary (ADR-0008)
#
# Requires the musl cross-compilation toolchain on the build host:
#   rustup target add x86_64-unknown-linux-musl
#   # macOS: brew install filosottile/musl-cross/musl-cross
#   # Linux: apt-get install musl-tools
#
# The final binary is stripped and contains no dynamic library references
# (ldd output: "not a dynamic executable").  ADR-0008 mandates:
#   opt-level = "s", lto = true, codegen-units = 1,
#   panic = "abort", strip = "symbols".
# -----------------------------------------------------------------------------
FROM --platform=linux/amd64 rust:1.87-slim AS builder

# Install the musl cross-compilation toolchain for the target
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    musl-tools \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Register the musl target with the Rust toolchain
RUN rustup target add x86_64-unknown-linux-musl

WORKDIR /build

# ------------------------------------------------------------------
# Cache the dependency layer: copy manifests first, then source.
# The two-step pattern prevents re-downloading crates on source edits.
# ------------------------------------------------------------------
COPY Cargo.toml Cargo.lock ./
# Create a stub lib/main so `cargo fetch` resolves the full dependency graph
RUN mkdir -p src && echo 'fn main() {}' > src/main.rs

# Fetch all crates into the layer cache (no network in subsequent builds)
RUN cargo fetch --target x86_64-unknown-linux-musl

# Now copy the real source tree
COPY src ./src

# Build the release binary with full hardening flags (ADR-0008):
#   -C target-feature=+crt-static  — embed libc into the binary
#   LTO, single codegen-unit, and symbol-strip are set in Cargo.toml
#   [profile.release] section (opt-level="s", lto=true, codegen-units=1,
#   panic="abort", strip="symbols").
RUN RUSTFLAGS="-C target-feature=+crt-static" \
    cargo build \
      --release \
      --target x86_64-unknown-linux-musl \
      --locked

# Verify the binary is fully static before shipping the image layer.
# If `ldd` does NOT print "not a dynamic executable" the build fails here.
RUN ldd target/x86_64-unknown-linux-musl/release/nft_exporter 2>&1 | \
    grep -q "not a dynamic executable"

# Copy the verified binary to a well-known path for the final stage
RUN cp target/x86_64-unknown-linux-musl/release/nft_exporter /nft_exporter

# -----------------------------------------------------------------------------
# Stage 2: final — minimal distroless image (ADR-0008)
#
# gcr.io/distroless/static-debian12:nonroot
#   - uid/gid 65532 (nonroot:nonroot) — satisfies runAsNonRoot: true
#   - No shell, no package manager, no C library
#   - Binary is the only executable in the image
#
# Reference by sha256 digest in production manifests (ADR-0008).
# Renovate Bot updates the digest reference via PR.
# -----------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot

# Copy only the verified static binary from the builder stage
COPY --from=builder /nft_exporter /usr/local/bin/nft_exporter

# Expose the Prometheus metrics port (port 9456, registered in ADR-0010)
EXPOSE 9456

# Default environment — overridable via Kubernetes env: or docker run -e
ENV NFT_EXPORTER_LISTEN="0.0.0.0:9456" \
    NFT_EXPORTER_SCRAPE_TIMEOUT_MS="9800" \
    NFT_EXPORTER_LOG_FORMAT="json" \
    NFT_EXPORTER_LOG_LEVEL="info"

# The distroless nonroot image already sets USER 65532 (nonroot).
# ENTRYPOINT is exec-form — no shell interpretation, no signal wrapping.
ENTRYPOINT ["/usr/local/bin/nft_exporter"]
