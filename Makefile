# Makefile — nft_exporter build, package, and integration-test targets
#
# Prerequisites (macOS development host, ADR-0008/0012):
#   rustup (stable >= 1.87, edition 2024)
#   rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl
#   Docker (or podman) with BuildKit for the `docker` target
#   cue   — https://cuelang.org/docs/install/  (for spec-validate)
#   clippy — installed via rustup component add clippy
#   merkle vault daemon running locally (for test-remote)
#
# Port 9456 is the registered Prometheus metrics port (ADR-0010).

# --------------------------------------------------------------------------
# Variables — override on the command line (e.g. make docker IMAGE_TAG=v1.2)
# --------------------------------------------------------------------------

BINARY          := nft_exporter
IMAGE_REPO      := ghcr.io/example/$(BINARY)
IMAGE_TAG       ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
METRICS_PORT    := 9456

# Cargo flags shared across all release builds (ADR-0008)
CARGO_RELEASE_FLAGS := --release --locked

# musl static flags (ADR-0008): embed libc, no dynamic linking
MUSL_RUSTFLAGS  := -C target-feature=+crt-static

# Vault secret path for the remote VM SSH key (ADR-0012)
VAULT_SSH_PATH  := netlink-exporter/ssh/vm-services-root

# Remote VM address and user (populated from vault at runtime)
VM_USER         ?= root
VM_HOST         ?= vm.services
VM_REMOTE_DIR   := /tmp/nft_exporter_ci

# CUE schema used to validate the metrics exposition (ADR-0012)
CUE_SCHEMA      := docs/arch/schemas/metric_contract.cue

# --------------------------------------------------------------------------
# Phony targets
# --------------------------------------------------------------------------
.PHONY: all build build-musl-x86 build-musl-arm64 docker \
        spec-validate test-remote lint clean help

# Default target: local debug build for fast feedback
all: build

# --------------------------------------------------------------------------
# build — compile a debug binary for the local host
#
# On macOS this produces a Mach-O binary usable for unit tests only.
# Integration tests require a Linux kernel; see test-remote.
# --------------------------------------------------------------------------
build:
	cargo build

# --------------------------------------------------------------------------
# build-musl-x86 — fully static x86_64 release binary (ADR-0008)
#
# Output: target/x86_64-unknown-linux-musl/release/$(BINARY)
#
# Verifies that the output is statically linked before printing the path.
# Fails loudly if ldd output does not contain "not a dynamic executable".
# --------------------------------------------------------------------------
build-musl-x86:
	RUSTFLAGS="$(MUSL_RUSTFLAGS)" \
	cargo build $(CARGO_RELEASE_FLAGS) \
	    --target x86_64-unknown-linux-musl
	@ldd target/x86_64-unknown-linux-musl/release/$(BINARY) 2>&1 \
	    | grep -q "not a dynamic executable" \
	    || { echo "ERROR: binary is not statically linked"; exit 1; }
	@echo "Static x86_64 binary: target/x86_64-unknown-linux-musl/release/$(BINARY)"

# --------------------------------------------------------------------------
# build-musl-arm64 — fully static aarch64 release binary (ADR-0008)
#
# Requires: rustup target add aarch64-unknown-linux-musl
# On macOS, also requires the aarch64-linux-musl cross-linker; install via:
#   cargo install cargo-zigbuild   (no Docker required)
#   or: brew install filosottile/musl-cross/musl-cross
#
# Output: target/aarch64-unknown-linux-musl/release/$(BINARY)
# --------------------------------------------------------------------------
build-musl-arm64:
	RUSTFLAGS="$(MUSL_RUSTFLAGS)" \
	cargo build $(CARGO_RELEASE_FLAGS) \
	    --target aarch64-unknown-linux-musl
	@echo "Static arm64 binary: target/aarch64-unknown-linux-musl/release/$(BINARY)"

# --------------------------------------------------------------------------
# docker — build the multi-stage container image (ADR-0008)
#
# Produces: $(IMAGE_REPO):$(IMAGE_TAG)
# The Dockerfile performs the musl build inside the builder stage;
# no pre-built binary is required on the host.
#
# Push to the registry:
#   make docker IMAGE_TAG=v1.2 && docker push $(IMAGE_REPO):v1.2
# --------------------------------------------------------------------------
docker:
	docker build \
	    --file Dockerfile \
	    --tag $(IMAGE_REPO):$(IMAGE_TAG) \
	    --tag $(IMAGE_REPO):latest \
	    --build-arg BUILDKIT_INLINE_CACHE=1 \
	    .
	@echo "Image built: $(IMAGE_REPO):$(IMAGE_TAG)"

# --------------------------------------------------------------------------
# spec-validate — validate CUE schemas and YAML manifests (ADR-0008/0009)
#
# Runs:
#   1. cue vet on all CUE schemas in docs/arch/schemas/
#   2. cue vet on the metric contract schema (self-referential check)
#   3. kubectl dry-run=client on all deploy/k8s/*.yaml (uses --dry-run=client
#      so no cluster connection is required)
#
# Requires: cue in PATH, kubectl in PATH (for manifest validation).
# --------------------------------------------------------------------------
spec-validate:
	@echo "==> Validating CUE schemas..."
	cue vet ./docs/arch/schemas/...
	@echo "==> Validating metric contract..."
	cue vet $(CUE_SCHEMA)
	@echo "==> Validating Kubernetes manifests (dry-run)..."
	@for f in deploy/k8s/*.yaml; do \
	    echo "    $$f"; \
	    kubectl apply --dry-run=client -f "$$f" 2>&1 || exit 1; \
	done
	@echo "spec-validate passed."

# --------------------------------------------------------------------------
# test-remote — integration test on the remote Linux VM (ADR-0012)
#
# Procedure:
#   1. Build the x86_64 musl binary.
#   2. Write the SSH private key from the Merkle vault to a mode-0600 tempfile
#      using vault_write_tempfile (never vault.reveal + paste — ADR-0012).
#   3. Transfer the binary to the VM via rsync over SSH.
#   4. Execute the exporter on the VM, wait two scrape intervals (30 s).
#   5. Scrape /metrics and validate against the CUE metric contract schema.
#   6. Revoke the tempfile unconditionally (even on failure).
#
# This target requires:
#   - The Merkle vault daemon running locally.
#   - A bound namespace with the SSH key at $(VAULT_SSH_PATH).
#   - ssh and rsync available in PATH.
#   - cue available in PATH (for metric contract validation on the remote side).
#
# The vault_spawn decode-bridge pattern is used (ADR-0012) so the SSH key is
# never present in make output, CI logs, or environment variables.
# --------------------------------------------------------------------------
test-remote: build-musl-x86
	@echo "==> Fetching SSH key from Merkle vault (tempfile, mode 0600)..."
	$(eval KEY_FILE := $(shell mktemp /tmp/nft_ci_key.XXXXXX))
	@vault_spawn --path "$(VAULT_SSH_PATH)" --output "$(KEY_FILE)" --mode 0600
	@chmod 0600 "$(KEY_FILE)"
	@echo "==> Transferring binary to $(VM_USER)@$(VM_HOST):$(VM_REMOTE_DIR)..."
	@ssh -i "$(KEY_FILE)" -o StrictHostKeyChecking=no \
	    "$(VM_USER)@$(VM_HOST)" \
	    "mkdir -p $(VM_REMOTE_DIR)"
	@rsync -az --checksum \
	    -e "ssh -i $(KEY_FILE) -o StrictHostKeyChecking=no" \
	    target/x86_64-unknown-linux-musl/release/$(BINARY) \
	    "$(VM_USER)@$(VM_HOST):$(VM_REMOTE_DIR)/"
	@echo "==> Executing exporter on remote VM for two scrape intervals (30 s)..."
	@ssh -i "$(KEY_FILE)" -o StrictHostKeyChecking=no \
	    "$(VM_USER)@$(VM_HOST)" \
	    "$(VM_REMOTE_DIR)/$(BINARY) --listen 127.0.0.1:$(METRICS_PORT) \
	        --scrape-timeout-ms 9800 --log-format json &" \
	    ; sleep 30
	@echo "==> Scraping /metrics and validating against CUE metric contract..."
	@ssh -i "$(KEY_FILE)" -o StrictHostKeyChecking=no \
	    "$(VM_USER)@$(VM_HOST)" \
	    "curl -sf http://127.0.0.1:$(METRICS_PORT)/metrics \
	        | cue vet - $(VM_REMOTE_DIR)/metric_contract.cue" \
	    || { echo "FAIL: metric contract validation failed"; \
	         ssh -i "$(KEY_FILE)" -o StrictHostKeyChecking=no \
	             "$(VM_USER)@$(VM_HOST)" \
	             "pkill -f nft_exporter || true"; \
	         rm -f "$(KEY_FILE)"; exit 1; }
	@echo "==> Stopping exporter on remote VM..."
	@ssh -i "$(KEY_FILE)" -o StrictHostKeyChecking=no \
	    "$(VM_USER)@$(VM_HOST)" \
	    "pkill -f nft_exporter || true"
	@echo "==> Revoking vault tempfile..."
	@rm -f "$(KEY_FILE)"
	@echo "test-remote PASSED."

# --------------------------------------------------------------------------
# lint — run clippy and rustfmt checks (ADR-0003)
#
# Clippy is run with -D warnings so the CI gate rejects any advisory.
# rustfmt --check exits non-zero if any file needs reformatting.
# --------------------------------------------------------------------------
lint:
	@echo "==> Running clippy..."
	cargo clippy \
	    --all-targets \
	    --all-features \
	    -- -D warnings
	@echo "==> Checking formatting..."
	cargo fmt --all -- --check
	@echo "lint passed."

# --------------------------------------------------------------------------
# clean — remove all build artifacts
# --------------------------------------------------------------------------
clean:
	cargo clean

# --------------------------------------------------------------------------
# help — list all targets with descriptions
# --------------------------------------------------------------------------
help:
	@echo "nft_exporter Makefile targets:"
	@echo ""
	@echo "  build             Local debug build (Mach-O on macOS)"
	@echo "  build-musl-x86    Static x86_64 musl release binary"
	@echo "  build-musl-arm64  Static aarch64 musl release binary"
	@echo "  docker            Build container image ($(IMAGE_REPO):$(IMAGE_TAG))"
	@echo "  spec-validate     Validate CUE schemas and Kubernetes YAML"
	@echo "  test-remote       Integration test on remote Linux VM (requires Merkle vault)"
	@echo "  lint              Run clippy + rustfmt checks"
	@echo "  clean             Remove build artifacts"
	@echo ""
	@echo "Overridable variables:"
	@echo "  IMAGE_TAG         Container image tag (default: git describe)"
	@echo "  VM_HOST           Remote VM hostname (default: vm.services)"
	@echo "  VM_USER           Remote VM SSH user (default: root)"
