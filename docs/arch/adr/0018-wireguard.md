---
status: accepted
date: 2026-05-28
deciders: [eonf]
consulted: []
informed: []
---

# Add WireGuard collector via direct generic-netlink, runtime-gated

## Context and Problem Statement

Operators running WireGuard tunnels on Linux hosts that are also monitored by
nft_exporter currently have no Prometheus visibility into tunnel health. The
kernel exposes WireGuard state exclusively through a generic-netlink (NETLINK_GENERIC)
family named "wireguard", not through procfs or sysfs. No procfs or sysfs path
provides peer-level byte counts, last-handshake timestamps, or persistent-keepalive
configuration in a stable machine-readable form.

The WireGuard generic-netlink family may not be present on all kernels (requires
`CONFIG_WIREGUARD=y` or the `wireguard.ko` module loaded). An attempt to resolve
the family that returns `ENOENT` must not be treated as a fatal startup error;
it must produce `nft_scrape_collector_available{collector="wireguard"}=0` and
suppress all WireGuard metric families silently.

Cardinality risk exists at the peer identity label. WireGuard peer public keys are
32-byte curve25519 points (64 hex characters). Using the raw public key as a
Prometheus label violates ADR-0005: on a host acting as a VPN gateway with
hundreds of peers the series count is unbounded by operator configuration, and
the label value is opaque to humans. A bounded identity requires either a
configurable name map or a truncated cryptographic identifier.

Three collection strategies have been considered:

1. Skip WireGuard entirely; instruct operators to use the official
   `prometheus_wireguard_exporter` sidecar.
2. Read `/proc/net/dev` + `wg show` via subprocess for WireGuard-specific
   metrics.
3. Issue `WG_CMD_GET_DEVICE` dump over the WireGuard generic-netlink family
   with a truncated public-key-hash peer identity label, bounded cardinality,
   and runtime availability gating.

## Considered Options

- **Skip WireGuard** — zero implementation cost. Leaves a visibility gap for
  operators who have consolidated all network observability into nft_exporter.
  Requires a sidecar deployment with independent configuration and scrape jobs.
  Rejected: the hexagonal port model and Strategy pattern (ADR-0002) make adding
  a new bounded context low-cost; requiring a sidecar for a single subsystem
  contradicts the consolidation goal.

- **procfs / `wg show` subprocess** — `/proc/net/dev` provides only aggregate
  interface-level counters; it does not expose per-peer byte counts,
  last-handshake age, or persistent-keepalive configuration. Parsing `wg show`
  output from a subprocess couples the collector to the `wg` userspace binary,
  introduces a process-spawn overhead per scrape, and violates ADR-0011 (direct
  wire protocol mandate) and ADR-0009 (no subprocess execution). Rejected.

- **Direct generic-netlink, runtime-gated** (chosen) — resolve the "wireguard"
  genetlink family at startup via `CTRL_CMD_GETFAMILY` on the shared
  `NETLINK_GENERIC` socket. On `ENOENT`: cache as unavailable, set
  `nft_scrape_collector_available{collector="wireguard"}=0`, and suppress all
  WireGuard series without error. On success: issue `WG_CMD_GET_DEVICE` dump
  with `NLM_F_DUMP` to enumerate all WireGuard interfaces, parse per-peer
  attributes, and emit bounded metrics with a truncated-public-key-hash peer
  identity label capped at 16 hex characters (8 bytes of SHA-256 over the
  raw 32-byte key). Optional operator name map (keyed by full public key
  base64) overrides the truncated hash label.

## Decision Outcome

**Chosen option: direct generic-netlink, runtime-gated.**

### New bounded context: wireguard

A new `WireguardCollector` is added as the seventh Collector strategy. Its
driven port is `NetlinkWireguardPort` (NETLINK_GENERIC, shared socket, separate
family-id slot in the `OnceLock` cache). The collector is enabled by adding
`"wireguard"` to `ExporterConfig.collectors.enabled`; it is excluded from the
default enabled list because its availability is host-dependent.

### Family resolution

`CTRL_CMD_GETFAMILY` is sent to `GENL_ID_CTRL=16` with
`CTRL_ATTR_FAMILY_NAME="wireguard\0"`. The resolved `family_id` is cached in a
dedicated `OnceLock<Option<u16>>`:

- `Some(id)` — family resolved; collector active.
- `None` — `ENOENT` returned; collector reports available=0 and emits no series.

The ethtool family-id `OnceLock` pattern (section 8.1 of
`docs/arch/domain/netlink-protocol.md`) is reused verbatim.

### WG_CMD_GET_DEVICE dump

`WG_CMD_GET_DEVICE` has **no dump-all form**. The kernel's `lookup_interface()`
returns `-EBADR` (errno 53) unless exactly one of `WGDEVICE_A_IFINDEX` /
`WGDEVICE_A_IFNAME` is supplied (`drivers/net/wireguard/netlink.c`). The exporter
therefore:

1. Enumerates WireGuard interfaces via an `RTM_GETLINK` dump on `NETLINK_ROUTE`,
   keeping links whose `IFLA_LINKINFO` → `IFLA_INFO_KIND` equals `"wireguard"`.
2. For each interface, issues `nlmsghdr{type=family_id,
   flags=NLM_F_REQUEST|NLM_F_DUMP}` + `genlmsghdr{cmd=WG_CMD_GET_DEVICE=0,
   version=1}` + `WGDEVICE_A_IFNAME` (the interface name).

A single interface's reply may span several `NLM_F_MULTI` frames when its peers
do not fit in one message; the frames are merged by interface. Each frame carries
`WGDEVICE_A_*` top-level attributes, with `WGDEVICE_A_PEERS` (type=8) as a nested
list of `WGPEER_A_*` entries.

### Peer identity label strategy

The `peer` label value is computed as follows:

1. Extract `WGPEER_A_PUBLIC_KEY` (type=1) — 32 raw bytes (curve25519 public key).
2. Compute SHA-256 over the 32 bytes using the `sha2` crate (already in the
   dependency graph via `prometheus-client`'s build-time hashing).
3. Take the first 8 bytes of the SHA-256 digest; encode as lowercase hex (16
   characters). This is the default peer identity label.
4. If `ExporterConfig.wireguard_peer_names` contains an entry whose key matches
   the base64url-encoded public key (RFC 4648 no-pad form), the map value
   replaces the truncated hash. The value must be non-empty, at most 64 bytes
   of printable ASCII, and must match `[a-zA-Z0-9_.-]{1,64}`. Entries failing
   validation are logged at WARN and fall back to the truncated hash.

Cardinality bound: `|wg_interfaces| x |peers_per_interface|`. The
`ExporterConfig.wireguard_max_peers` field (default: 1000) caps total peer
series emitted per scrape. When the cap is exceeded, the collector emits
`nft_scrape_collector_error_total{collector="wireguard", reason="cardinality_overflow"}`
and serves the stale snapshot for the wireguard collector.

### Metric families

All metric names carry the `nft_wireguard_` prefix per Prometheus naming
conventions and the existing `nft_` namespace (ADR-0005). Types and units follow
the existing metric_contract.cue schema patterns.

| Metric | Type | Labels | Source attribute |
|---|---|---|---|
| `nft_wireguard_device_info` | gauge | `interface`, `listen_port`, `fwmark` | `WGDEVICE_A_LISTEN_PORT`, `WGDEVICE_A_FWMARK` |
| `nft_wireguard_peer_receive_bytes_total` | counter | `interface`, `peer` | `WGPEER_A_RX_BYTES` |
| `nft_wireguard_peer_transmit_bytes_total` | counter | `interface`, `peer` | `WGPEER_A_TX_BYTES` |
| `nft_wireguard_peer_last_handshake_seconds` | gauge | `interface`, `peer` | `WGPEER_A_LAST_HANDSHAKE_TIME` (age from `ClockPort::now()`) |
| `nft_wireguard_peer_persistent_keepalive_seconds` | gauge | `interface`, `peer` | `WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL`; 0 when disabled |
| `nft_wireguard_peer_endpoint_present` | gauge | `interface`, `peer` | 1 when `WGPEER_A_ENDPOINT` is present; 0 when absent |
| `nft_scrape_collector_available` | gauge | `collector="wireguard"` | 1 when genl family resolved; 0 when `ENOENT` |

### Runtime gating

The `WireguardCollector.collect()` AFIT method checks the cached
`OnceLock<Option<u16>>` on every call:

```
if family_id.get() == Some(None) {
    self.available_gauge.set(0.0);
    return Ok(WireguardSnapshot::empty());
}
```

No netlink socket I/O is attempted when the family is absent. The
`nft_scrape_collector_success{collector="wireguard"}` gauge still reports 1 for
an absent family (absence is not a failure); only `nft_scrape_collector_available`
distinguishes loaded vs not-loaded.

### Consequences

- Positive: WireGuard operators gain per-peer byte counts, handshake age, and
  keepalive visibility via a single scrape job with no additional sidecar.
- Positive: Hosts without WireGuard loaded experience zero overhead: one failed
  `CTRL_CMD_GETFAMILY` at startup, then the OnceLock short-circuits every scrape.
- Positive: The hexagonal port model absorbs the new subsystem with no changes
  to ScrapeLifecycle, MetricRegistryPort, or any existing adapter crate.
- Positive: Peer identity cardinality is bounded by both the configurable name
  map and the `wireguard_max_peers` hard cap.
- Negative: The 16-character truncated key hash is opaque; operators must
  configure `wireguard_peer_names` for human-readable labels in large deployments.
- Negative: The `sha2` crate is added to the dependency graph. `cargo deny` must
  be updated to allow it; audit risk is the SHA-2 implementation surface.
- Negative: `WGPEER_A_LAST_HANDSHAKE_TIME` carries a `timespec64` (seconds +
  nanoseconds as two `u64` values, native-endian). Peers that have never
  completed a handshake report all-zero timespec; the collector emits the gauge
  as `+Inf` (no handshake ever) rather than 0 to avoid confusion with a
  handshake that occurred exactly at the Unix epoch.
