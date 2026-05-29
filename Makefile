# Makefile — nft_exporter build & Debian packaging
#
# Toolchain: Rust 1.96 (pinned in rust-toolchain.toml), edition 2024.
# The full workspace builds on LINUX ONLY (monoio/io_uring); the pure crates
# build anywhere. Release binaries and the .deb are dynamic glibc — musl does
# NOT build (monoio is glibc-only; ADR-0023). Metrics port 9456 (ADR-0010).

BINARY        := netlink_exporter
PKG           := netlink-exporter
VERSION       := $(shell sed -n 's/^version *= *"\(.*\)"/\1/p' crates/netlink_exporter/Cargo.toml | head -n1)
ARCH          := $(shell dpkg --print-architecture 2>/dev/null || echo amd64)
TARGET        := x86_64-unknown-linux-gnu
RELEASE_BIN   := target/$(TARGET)/release/$(BINARY)
DEB           := $(PKG)_$(VERSION)_$(ARCH).deb
IMAGE_REPO    := ghcr.io/example/$(PKG)
IMAGE_TAG     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
CUE_SCHEMA    := docs/arch/schemas/metric_contract.cue

.PHONY: all build release deb docker lint fmt test spec-validate clean help

all: build

## build         Debug build of the binary (Linux)
build:
	cargo build --bin $(BINARY)

## release       Optimized glibc release binary (stripped)
release:
	cargo build --release --locked --bin $(BINARY) --target $(TARGET)
	@strip $(RELEASE_BIN) 2>/dev/null || true
	@echo "Release binary: $(RELEASE_BIN)"

## deb           Build the Debian package ($(DEB))
deb: release
	packaging/deb/build-deb.sh $(RELEASE_BIN) $(VERSION) $(ARCH)
	@echo "Package: $(DEB)"

## docker        Build the glibc distroless container image
docker:
	docker build --file Dockerfile \
	    --tag $(IMAGE_REPO):$(IMAGE_TAG) --tag $(IMAGE_REPO):latest .
	@echo "Image: $(IMAGE_REPO):$(IMAGE_TAG)"

## lint          clippy (-D warnings) + rustfmt --check
lint:
	cargo clippy --workspace --all-targets -- -D warnings
	cargo fmt --all -- --check

## fmt           Format all code
fmt:
	cargo fmt --all

## test          Run the workspace test suite (Linux for the full workspace)
test:
	cargo test --workspace

## spec-validate Validate the CUE metric contract (spec-first gate)
spec-validate:
	cue vet $(CUE_SCHEMA)

## clean         Remove build artifacts and built .debs
clean:
	cargo clean
	@rm -f $(PKG)_*.deb

## help          List targets
help:
	@echo "nft_exporter — targets (BINARY=$(BINARY), VERSION=$(VERSION), ARCH=$(ARCH)):"
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /'
