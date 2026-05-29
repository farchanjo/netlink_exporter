---
status: accepted
date: 2026-05-29
deciders: [eonf]
consulted: []
informed: []
---

# Opt-in procfs/sysfs relax for stack, IRQ and hardware metrics

## Context and Problem Statement

ADR-0025 forbids `/proc` and `/sys` reads: the exporter is native-API-only
(netlink / generic netlink / direct syscalls). That decision holds for every
metric that *has* a native API.

However, a class of high-value Linux network-observability signals has **no
netlink API at all** — the kernel exposes them only through procfs/sysfs:

- **Stack pressure**: `/proc/net/softnet_stat` (per-CPU backlog drops,
  `time_squeeze` = NAPI budget exhaustion, RPS), `/proc/softirqs` (`NET_RX` /
  `NET_TX` per CPU).
- **IP/TCP/UDP/ICMP MIB**: `/proc/net/snmp` + `/proc/net/netstat`
  (`TcpRetransSegs`, `TCPLostRetransmit`, `ListenDrops`, `ListenOverflows`,
  out-of-order, …). `sock_diag` gives per-socket state, never these aggregate
  MIB counters.
- **IRQ accounting**: `/proc/interrupts` (per-IRQ per-CPU counts),
  `/proc/irq/N/smp_affinity`. The netdev genl family (ADR pending) exposes the
  IRQ *number* bound to each NAPI, but **not** the interrupt counts or affinity.
- **NIC hardware health**: sysfs `byte_queue_limits` (BQL), RPS/XPS steering
  config, PCIe AER error counters, PCIe link speed/width (downtrain detection),
  `hwmon` temperature, `numa_node`.
- **Socket memory pressure**: `/proc/net/sockstat` (TCP mem pages, orphans).

A complete Linux network exporter must surface these. The choice is: stay
strictly native (and omit them forever), or carve a **narrow, documented,
opt-in** exception.

## Considered Options

1. **Stay strict (ADR-0025 unchanged)** — reject. Permanently omits the entire
   stack-pressure / IRQ / hardware-health layer that is the core value of a
   network exporter and that `node_exporter` already covers.
2. **Drop the native-only rule entirely** — reject. Loses the architectural
   discipline that keeps the netlink data path clean and kernel-version-robust.
3. **Narrow, opt-in, isolated procfs/sysfs exception (chosen)** — allow
   procfs/sysfs reads *only* for signals with no netlink API, isolated in a
   dedicated crate, behind default-off flags, with a fixed path allowlist.

## Decision Outcome

Chosen: **option 3**. ADR-0025 remains the default and the rule for every
metric that has a native API. This ADR carves a bounded exception:

- **Isolation**: all procfs/sysfs reads live in a single dedicated crate,
  `nlx-procfs`. No `/proc` or `/sys` read is permitted anywhere else (the
  netlink crates stay native-only). The boundary is auditable in one place.
- **Path allowlist**: `nlx-procfs` reads only via a `safe_read` helper that
  rejects any path not under a fixed prefix allowlist
  (`/proc/net/`, `/proc/softirqs`, `/proc/interrupts`, `/proc/irq/`,
  `/proc/net/sockstat*`, `/sys/class/net/`, `/sys/bus/pci/devices/`) and rejects
  `..` traversal. No writes, ever.
- **Default-off**: every procfs/sysfs collector ships **disabled by default**
  (opt-in via config), unlike the native collectors which default-on. Operators
  explicitly opt into the relaxed surface.
- **No duplication**: a procfs/sysfs collector must NOT re-expose a metric that a
  netlink collector already provides (e.g. link byte/packet counters
  `IFLA_STATS64`, carrier-flap counters `IFLA_CARRIER_*`, ethtool channels/rings/
  coalesce, IRQ↔NAPI binding via netdev genl). Only netlink-absent signals.
- **Defensive parsing**: pseudo-file formats drift across kernels. Parsers must
  tolerate missing columns/rows, never panic, and skip unrecognised lines.

### Collectors introduced under this ADR

| collector  | source                                   | default |
|------------|------------------------------------------|---------|
| `softnet`  | `/proc/net/softnet_stat`                 | off     |
| `netstat`  | `/proc/net/snmp` + `/proc/net/netstat`   | off     |
| `softirq`  | `/proc/softirqs` (NET_RX/NET_TX)         | off     |
| `irq`      | `/proc/interrupts` + `/proc/irq/*/smp_affinity` | off |
| `sockstat` | `/proc/net/sockstat`                     | off     |
| `nic_bql`  | `/sys/class/net/*/queues/tx-*/byte_queue_limits` | off |
| `nic_pcie` | `/sys/class/net/*/device/{current_link_*,aer_dev_*}` | off |
| `nic_temp` | `/sys/class/net/*/device/hwmon/*/temp*`  | off     |

## Consequences

- The exporter can be a complete network observability source, not just the
  netlink-reachable subset.
- The relaxed surface is opt-in, isolated, allowlisted, read-only, and
  documented — the native-only guarantee of ADR-0025 still holds for everything
  outside `nlx-procfs` and for every default-on collector.
- Cardinality: per-CPU and per-IRQ metrics scale with core/IRQ count (128 CPUs,
  hundreds of IRQs on large hosts). Collectors aggregate or bound where sensible
  and document the bound.

Supersedes the absoluteness of [ADR-0025] for the enumerated netlink-absent
signals only; ADR-0025 otherwise remains in force.
