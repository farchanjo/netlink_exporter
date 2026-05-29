#!/usr/bin/env bash
# Build the netlink-exporter .deb from a release glibc binary.
#
#   usage: build-deb.sh <path-to-netlink_exporter-binary> [version] [arch]
#
# Produces ./netlink-exporter_<version>_<arch>.deb in the current directory.
# Runs on any Debian/Ubuntu host (needs dpkg-deb); no debhelper/cargo-deb.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="${1:?usage: build-deb.sh <binary> [version] [arch]}"
VERSION="${2:-0.1.0}"
ARCH="${3:-amd64}"
PKG="netlink-exporter"

[ -x "$BIN" ] || { echo "error: binary not found/executable: $BIN" >&2; exit 1; }

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
chmod 755 "$STAGE"   # mktemp defaults to 0700; the package root must be 0755

# --- payload layout ---
install -D -m 0755 "$BIN"                       "$STAGE/usr/bin/netlink_exporter"
install -D -m 0644 "$HERE/nft_exporter.service" "$STAGE/lib/systemd/system/nft_exporter.service"
install -D -m 0644 "$HERE/nft_exporter.toml"    "$STAGE/etc/nft_exporter/nft_exporter.toml"
install -D -m 0644 "$HERE/nft_exporter.default" "$STAGE/etc/default/nft_exporter"

# --- DEBIAN metadata ---
install -d -m 0755 "$STAGE/DEBIAN"
SIZE_KB="$(du -sk "$STAGE/usr" "$STAGE/lib" "$STAGE/etc" | awk '{s+=$1} END{print s+0}')"

cat > "$STAGE/DEBIAN/control" <<EOF
Package: $PKG
Version: $VERSION
Architecture: $ARCH
Maintainer: eonf <fabricio@eonf.ltd>
Section: net
Priority: optional
Depends: libc6
Installed-Size: $SIZE_KB
Homepage: https://github.com/farchanjo/netlink_exporter
Description: Linux netlink Prometheus exporter
 Full-spectrum Linux network observability for Prometheus. Reads the kernel
 directly over AF_NETLINK on an io_uring runtime. 21 collectors (13 netlink
 default-on + 8 opt-in procfs/sysfs). Serves Prometheus text 0.0.4 on :9456.
EOF

printf '/etc/nft_exporter/nft_exporter.toml\n/etc/default/nft_exporter\n' > "$STAGE/DEBIAN/conffiles"

for s in postinst prerm postrm; do
  install -m 0755 "$HERE/$s" "$STAGE/DEBIAN/$s"
done

# --- build (reproducible ownership) ---
OUT="${PKG}_${VERSION}_${ARCH}.deb"
dpkg-deb --root-owner-group --build "$STAGE" "$OUT"

echo "BUILT: $OUT"
dpkg-deb --info "$OUT"
dpkg-deb --contents "$OUT"
