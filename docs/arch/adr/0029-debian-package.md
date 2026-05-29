---
status: accepted
date: 2026-05-29
deciders: [eonf]
consulted: []
informed: []
---

# Ship a Debian package (.deb) for Debian/Ubuntu deployment

## Context and Problem Statement

The exporter is distributed as a raw glibc binary (GitHub release tarball,
ADR-0023) and a glibc distroless container image (ADR-0008 superseded by the
glibc runtime). On Debian/Ubuntu hosts — the common bare-metal/VM target for a
node-level network exporter — operators want native package management:
`apt install`/`dpkg -i`, a managed systemd unit, a dedicated service user, a
config file tracked as a conffile, and clean removal. Hand-copying the binary +
writing a unit (as the README documents) works but is not first-class.

## Decision

Provide a first-class **`.deb`** package built from in-repo assets under
`packaging/deb/`.

- **Package name:** `netlink-exporter` (dpkg naming: lowercase, hyphen).
  **Binary:** `/usr/bin/netlink_exporter` (the crate's bin name, unchanged).
- **Architecture:** `amd64` (glibc dynamic — `monoio` does not build musl, ADR-0023).
  `Depends: libc6`.
- **systemd unit:** `/lib/systemd/system/nft_exporter.service` — runs as the
  unprivileged `nft-exporter` system user with `AmbientCapabilities=CAP_NET_ADMIN`
  and a hardened sandbox (ADR-0009).
- **Config:** `/etc/nft_exporter/nft_exporter.toml`, declared as a **conffile**
  so operator edits survive upgrades.
- **Maintainer scripts:** `postinst` creates the `nft-exporter` system user and
  runs `systemctl daemon-reload`; `prerm` stops/disables the unit; `postrm`
  removes the user on `purge`.
- **Build:** assembled by `packaging/deb/build-deb.sh` with `dpkg-deb --build`
  from a release glibc binary. No debhelper/cargo-deb dependency required; the
  script runs on any Debian/Ubuntu host (the Linux build host).

The package version tracks the crate version (`0.1.0`).

## Consequences

- **Good:** `apt`/`dpkg` lifecycle on Debian/Ubuntu — install, upgrade
  (conffile-preserving), and `purge` all work; the service is managed by systemd
  out of the box with least privilege.
- **Good:** packaging is reproducible from the repo (`packaging/deb/`), not an
  ad-hoc copy; the README/CLAUDE deployment guidance can point at it.
- **Neutral:** the `.deb` is glibc/amd64 only, matching the release binary and
  the kernel/runtime constraints (Linux ≥ 5.1, io_uring with epoll fallback).
  An arm64 `.deb` can follow the same recipe once an aarch64 glibc build host is
  available.
- **Bad / mitigation:** the unit grants `CAP_NET_ADMIN` ambient; enabling the
  `drop_monitor` collector additionally needs `CAP_SYS_ADMIN`, which an operator
  must add to the unit (documented in the unit comments and the README).

## Amendment (2026-05-29) — EnvironmentFile + Makefile target

- **`/etc/default/nft_exporter`** is shipped as a second **conffile** and loaded by the
  unit via `EnvironmentFile=-/etc/default/nft_exporter` (the `-` tolerates absence). This is
  the Debian-idiomatic place for per-host service environment: operators set `NLX_*` overrides
  there (which take precedence over the TOML) without editing the unit. The inline
  `Environment=` line was removed from the unit in favour of this file.
- **`make deb`** (root `Makefile`) is the entry point: it runs `release` (glibc
  `--target x86_64-unknown-linux-gnu`, stripped) then `packaging/deb/build-deb.sh`. The
  Makefile was also corrected to the real binary name (`netlink_exporter`) and glibc target;
  its prior musl/`nft_exporter` targets were stale drift and were removed.

Conffiles in the package: `/etc/nft_exporter/nft_exporter.toml` and `/etc/default/nft_exporter`.

## Validation

- `dpkg-deb --info` / `--contents` on the built artifact; install on a Ubuntu
  host, confirm the unit starts and `/metrics` serves on `:9456`, then `purge`
  and confirm the user/unit are removed. Build host: the project's Linux build
  box (`packaging/deb/build-deb.sh`).
