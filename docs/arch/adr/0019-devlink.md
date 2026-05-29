---
status: accepted
date: 2026-05-28
deciders: [eonf]
consulted: []
informed: []
---

# Add devlink collector via direct netlink, runtime-gated on subsystem availability

## Context and Problem Statement

The Linux `devlink` subsystem (kernel >= 4.6, `CONFIG_NET_DEVLINK`) exposes
device-level health information that no existing collector surfaces:

- Physical SmartNIC / switch-ASIC health reporters (error counts, recovery
  counts, reporter state) via `DEVLINK_CMD_HEALTH_REPORTER_GET`.
- Per-port metadata (port flavour, traffic rate limits) via `DEVLINK_CMD_PORT_GET`.
- Device identity (bus_name, dev_name) for mapping hardware events to Prometheus
  labels that operators can correlate with node hardware inventory.

This data is only accessible via the `devlink` generic-netlink family; it is not
present in `NETLINK_ROUTE`, `NETLINK_NETFILTER`, or `NETLINK_SOCK_DIAG`. The
existing ethtool collector (ADR-0011, section 8) covers NIC traffic statistics
but does not address hardware health state.

`devlink` is absent on many hosts (virtual machines, containers, kernels without
`CONFIG_NET_DEVLINK`). The collector must therefore be runtime-gated:
`CTRL_CMD_GETFAMILY` returning `ENOENT` is a normal condition, not an error.
The gate outcome is published as `nft_scrape_collector_available{collector="devlink"}`.

Three implementation paths were evaluated:

1. **Skip** — do not collect devlink data; operators who need it use raw
   `devlink` CLI output via textfile collector. Simple but forfeits structured
   Prometheus labels and cardinality enforcement.
2. **Procfs / sysfs** — read `/sys/bus/pci/devices/*/net/*/devlink` or
   `/proc/net/devlink`. No stable procfs interface exists for health reporters;
   the kernel exposes devlink exclusively through generic-netlink.
3. **Direct generic-netlink** (chosen) — resolve the `devlink` genl family via
   `CTRL_CMD_GETFAMILY`, then issue `DEVLINK_CMD_GET` (device dump),
   `DEVLINK_CMD_PORT_GET` (port dump), and
   `DEVLINK_CMD_HEALTH_REPORTER_GET` (health reporter dump) using the same
   direct-netlink wire implementation mandated by ADR-0011.

## Considered Options

- **Skip**: no new code; devlink health data is unavailable in Prometheus.
- **Procfs / sysfs scraping**: no stable kernel interface; fragile; no health
  reporter state visible.
- **Direct generic-netlink** (chosen): consistent with ADR-0011; provides
  structured labels; cardinality is bounded by hardware topology (rarely more
  than a few devices per node); runtime-gated so virtual-only hosts pay zero
  cost.

## Decision Outcome

**Chosen option: direct generic-netlink, runtime-gated.**

A new `DevlinkCollector` (`Concrete Strategy`, Devlink bounded context) is
added alongside the existing six collectors. It follows the same hexagonal
structure as `EthtoolCollector` (ADR-0002, ADR-0011):

- **Driving port**: `NetlinkDevlinkPort` — async trait with three methods:
  `get_devices`, `get_ports`, `get_health_reporters`. Each returns a typed
  domain stream.
- **Driven adapter**: `DevlinkAdapter` — opens one `NETLINK_GENERIC` socket
  (shared with the ethtool socket multiplexer via `AsyncFd<OwnedFd>`), resolves
  the `devlink` family id via `CTRL_CMD_GETFAMILY` (cached in `OnceLock<u16>`),
  issues NLM_F_DUMP requests for each command, parses nlattr chains into
  domain value objects.
- **ReadModel**: `DevlinkSnapshot` — immutable snapshot of devices, ports,
  and health reporters produced per scrape epoch.

**Runtime gate:**

At startup (and on the first scrape after a `CollectorRegistry` rebuild),
`DevlinkAdapter::resolve_family()` issues `CTRL_CMD_GETFAMILY` with
`CTRL_ATTR_FAMILY_NAME="devlink\0"`. On `ENOENT`, it sets
`collector_available = false` and emits:

```
nft_scrape_collector_available{collector="devlink"} 0
```

No further netlink requests are issued for this scrape or any subsequent scrape
until the exporter is restarted. The `DevlinkCollector` returns an empty
`DevlinkSnapshot` immediately.

When the family resolves successfully, `collector_available = true` and:

```
nft_scrape_collector_available{collector="devlink"} 1
```

**Metric families (nft_devlink_ prefix):**

| Metric | Type | Labels |
|---|---|---|
| `nft_devlink_device_info` | gauge | `bus_name`, `dev_name` |
| `nft_devlink_port_info` | gauge | `bus_name`, `dev_name`, `port` |
| `nft_devlink_health_reporter_error_total` | counter | `bus_name`, `dev_name`, `reporter` |
| `nft_devlink_health_reporter_recover_total` | counter | `bus_name`, `dev_name`, `reporter` |
| `nft_devlink_health_reporter_state` | gauge | `bus_name`, `dev_name`, `reporter` |
| `nft_scrape_collector_available` | gauge | `collector` |

Label cardinality is bounded by hardware topology: typically 1-4 devices
(bus_name in `pci`, `platform`), 1-16 ports, and 1-8 health reporter names per
device. Worst-case series count is approximately 256.

**Consequences:**

- Positive: devlink health reporter errors and recovery events are observable in
  Prometheus without requiring host-level CLI access.
- Positive: Runtime gate means zero cost on hosts without devlink (VMs,
  containers). `nft_scrape_collector_available` provides a clear signal to
  operators whether devlink data is expected.
- Positive: Consistent with ADR-0011 direct-wire mandate; no new external
  dependencies.
- Positive: Label set is bounded by hardware topology, not by traffic volume;
  cardinality ADR-0005 constraints are satisfied.
- Negative: Requires `CAP_NET_ADMIN` (already held per ADR-0009) for devlink
  genetlink access.
- Negative: `devlink` netlink ABI has changed across kernel versions for some
  reporter attributes. The adapter must check payload bounds before reading
  version-conditional fields, following the same pattern as
  `nf_conntrack_stat` size checks (ADR-0011 section 5.3).
