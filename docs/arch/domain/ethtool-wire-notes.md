# Ethtool genetlink: wire-level implementation notes

This document is the authoritative wire-level reference for the EthtoolAdapter
(`nft_exporter_adapter_ethtool`). It covers every byte sequence that crosses the
NETLINK_GENERIC socket, how those bytes map to kernel uapi constants, how the Rust
`ethtool 0.2.9` + `genetlink 0.2.6` crate stack encodes the requests, and the
cardinality and correctness constraints that flow from ADR-0005 and ADR-0011.

All claims are grounded against real veth probe data and against the following kernel
uapi headers:

- `include/uapi/linux/genetlink.h` — generic-netlink control family
- `include/uapi/linux/ethtool_netlink.h` — ethtool genetlink commands and attributes
- `include/uapi/linux/ethtool.h` — stat group id constants

---

## 1. Why NETLINK_GENERIC requires family resolution

NETLINK_ROUTE, NETLINK_NETFILTER, and NETLINK_SOCK_DIAG are **static** kernel families:
their numeric identifiers are compiled into the kernel and never change across reboots.
A process can open `socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)` and immediately send
RTM_GETLINK messages because the family number 1 is a compile-time constant.

NETLINK_GENERIC is different. It is a **multiplexed family** (`AF_NETLINK` socket with
`protocol = NETLINK_GENERIC = 16`) whose purpose is to host multiple sub-families
(called "generic netlink families") without consuming a static protocol number for each.
Every sub-family — including ethtool — registers itself at kernel module load time and
receives a **dynamically assigned 16-bit family id** from the kernel. This id typically
lands in the range 25–40 on a standard distribution kernel, but the actual value depends
on the order in which kernel modules initialise and can differ between reboots or kernel
builds.

Before any ethtool message can be sent, the exporter must resolve the ethtool family id
by querying the **genetlink control family** (the only family with a fixed id of 16 =
`GENL_ID_CTRL`). This resolution happens exactly once per process lifetime; the result
is stored in a `std::sync::OnceLock<u16>` inside the adapter. If the kernel does not have
the ethtool genetlink family registered (pre-5.10 kernels or kernels built without
`CONFIG_ETHTOOL_NETLINK`), the control family returns `ENOENT` and the ethtool collector
sets `nft_scrape_collector_success{collector="ethtool"} = 0`.

```
+---exporter process------------------------------+
|                                                 |
|  EthtoolAdapter::resolve_family()               |
|    called once, result cached in OnceLock<u16>  |
|                                                 |
|  +-NETLINK_GENERIC socket (fd)---------------+  |
|  |                                           |  |
|  |  --> CTRL_CMD_GETFAMILY                   |  |
|  |      family id = 16 (GENL_ID_CTRL)        |  |
|  |      CTRL_ATTR_FAMILY_NAME = "ethtool\0"  |  |
|  |                                           |  |
|  |  <-- CTRL_CMD_NEWFAMILY reply             |  |
|  |      CTRL_ATTR_FAMILY_ID = 0x001F (e.g.)  |  |
|  |      CTRL_ATTR_FAMILY_NAME = "ethtool"    |  |
|  |      CTRL_ATTR_VERSION = 1                |  |
|  |      CTRL_ATTR_MAXATTR = 65 (approx)      |  |
|  |      CTRL_ATTR_MCAST_GROUPS = [...]       |  |
|  |                                           |  |
|  +-------------------------------------------+  |
|                                                 |
|  resolved_family_id: u16 = 31  (example)        |
|                                                 |
+-------------------------------------------------+
```

---

## 2. Wire format: nlmsghdr + genlmsghdr

Every NETLINK_GENERIC datagram starts with the standard 16-byte `nlmsghdr` followed
immediately by the 4-byte `genlmsghdr`. Netlink attributes follow immediately after.

```
Byte offset   Field             Size  Notes
-----------   -----             ----  -----
0             nlmsg_len         u32   total datagram length including this header
4             nlmsg_type        u16   family id (16 for ctrl, resolved id for ethtool)
6             nlmsg_flags       u16   NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP etc.
8             nlmsg_seq         u32   sequence number; adapter increments per request
12            nlmsg_pid         u32   sender pid; 0 means kernel; process uses getpid()
16            cmd               u8    genetlink command (CTRL_CMD_GETFAMILY=3 etc.)
17            version           u8    protocol version (2 for ctrl, 1 for ethtool)
18            reserved          u16   must be zero
20            [attributes]            nlattr TLV stream starts here
```

All multi-byte integers are little-endian (native on x86-64; also native on arm64 LE
which is the target for `aarch64-unknown-linux-musl`).

### nlattr TLV layout

Each netlink attribute is:

```
Byte offset   Field      Size  Notes
-----------   -----      ----  -----
0             nla_len    u16   total length = 4 + payload_len (before padding)
2             nla_type   u16   attribute type; bit 15 = NLA_F_NESTED; bit 14 = NLA_F_NET_BYTEORDER
4             [payload]        payload bytes; zero-padded to next 4-byte boundary
```

Nested attributes set `nla_type |= 0x8000` (NLA_F_NESTED). The parser must mask off
`0x8000` before comparing against attribute type constants. Nested attribute payloads
are themselves a stream of nlattr TLVs.

---

## 3. Phase 1: CTRL_CMD_GETFAMILY wire sequence

### Request

```
nlmsghdr {
    nlmsg_len:   28,          // 16 (nlmsghdr) + 4 (genlmsghdr) + 8 (one nlattr)
    nlmsg_type:  16,          // GENL_ID_CTRL
    nlmsg_flags: 0x0005,      // NLM_F_REQUEST | NLM_F_ACK
    nlmsg_seq:   1,
    nlmsg_pid:   <pid>,
}
genlmsghdr {
    cmd:      3,              // CTRL_CMD_GETFAMILY
    version:  2,
    reserved: 0,
}
nlattr {
    nla_len:  12,             // 4 header + 7 ("ethtool") + 1 NUL + 0 pad
    nla_type: 2,              // CTRL_ATTR_FAMILY_NAME
    payload:  b"ethtool\0",
}
// padded to 4-byte alignment: total nlmsg_len = 28
```

### Reply attributes of interest

| nla_type | Constant               | Payload  | Notes                                         |
|----------|------------------------|----------|-----------------------------------------------|
| 1        | CTRL_ATTR_FAMILY_ID    | u16 LE   | Store in OnceLock; use in all ethtool msgs    |
| 2        | CTRL_ATTR_FAMILY_NAME  | "ethtool" | Verify matches; discard otherwise             |
| 3        | CTRL_ATTR_VERSION      | u32      | Informational; ethtool uses version 1         |
| 7        | CTRL_ATTR_MCAST_GROUPS | nested   | Contains multicast group ids for notifications |

The multicast groups are not used by this exporter (we use request/reply, not async
notifications), but the `genetlink 0.2.6` crate parses them as part of the family
descriptor and makes them available if needed for future extension.

### Rust adapter pattern

```rust
// In nft_exporter_adapter_ethtool — EthtoolAdapter::resolve_family
static ETHTOOL_FAMILY_ID: OnceLock<u16> = OnceLock::new();

async fn resolve_family(handle: &GenetlinkHandle) -> Result<u16, EthtoolAdapterError> {
    if let Some(&id) = ETHTOOL_FAMILY_ID.get() {
        return Ok(id);
    }
    let family = handle
        .resolve_family_id("ethtool")  // genetlink crate helper
        .await
        .map_err(|_| EthtoolAdapterError::FamilyNotFound)?;
    let _ = ETHTOOL_FAMILY_ID.set(family);
    Ok(family)
}
```

---

## 4. Phase 2: ETHTOOL_MSG_STATS_GET (NLM_F_DUMP)

### Request

```
nlmsghdr {
    nlmsg_len:   52,
    nlmsg_type:  <resolved_family_id>,
    nlmsg_flags: 0x0305,      // NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP | NLM_F_ATOMIC
    nlmsg_seq:   2,
    nlmsg_pid:   <pid>,
}
genlmsghdr {
    cmd:      37,             // ETHTOOL_MSG_STATS_GET
    version:  1,              // ETHTOOL_GENL_VERSION
    reserved: 0,
}
// ETHTOOL_A_STATS_HEADER nest (contains ETHTOOL_A_HEADER_DEV_INDEX = 0 for dump)
nlattr {
    nla_len:  20,
    nla_type: 0x8001,         // ETHTOOL_A_STATS_HEADER | NLA_F_NESTED = 1 | 0x8000
    payload: {
        nlattr { nla_len: 8, nla_type: 1, payload: u32(0) }  // DEV_INDEX = 0 (all)
    }
}
// ETHTOOL_A_STATS_GROUPS = 0x0F (all four groups)
nlattr {
    nla_len:  8,
    nla_type: 2,              // ETHTOOL_A_STATS_GROUPS
    payload:  u32(0x0000000F),
}
```

NLM_F_DUMP causes the kernel to reply with one `ETHTOOL_MSG_STATS_REPLY` per interface
that supports at least one of the requested stat groups. The dump is terminated by a
`NLMSG_DONE` message with zero payload.

### Reply attribute tree

```
nlmsghdr { nlmsg_type: <resolved_id>, nlmsg_flags: NLM_F_MULTI, ... }
genlmsghdr { cmd: 38 (ETHTOOL_MSG_STATS_REPLY), version: 1 }
ETHTOOL_A_STATS_HEADER (nested)
    ETHTOOL_A_HEADER_DEV_INDEX  = u32(ifindex)
    ETHTOOL_A_HEADER_DEV_NAME   = "eth0\0"
ETHTOOL_A_STATS_GRP (nested)     <--- repeated per requested group
    ETHTOOL_A_STATS_GRP_ID      = u32(0)  // ETH_STATS_ETH_MAC
    ETHTOOL_A_STATS_GRP_SS_ID   = u32(2)  // string-set id for this group
    ETHTOOL_A_STATS_GRP_STAT (nested)     <--- repeated per counter in group
        ETHTOOL_A_STATS_GRP_STAT_NAME  = "FramesTransmittedOK\0"
        ETHTOOL_A_STATS_GRP_STAT_VALUE = u64(987654)
    ETHTOOL_A_STATS_GRP_STAT (nested)
        ETHTOOL_A_STATS_GRP_STAT_NAME  = "FramesReceivedOK\0"
        ETHTOOL_A_STATS_GRP_STAT_VALUE = u64(543210)
    ... (up to 22 stats for eth-mac)
ETHTOOL_A_STATS_GRP (nested)     // ETH_STATS_ETH_PHY
    ETHTOOL_A_STATS_GRP_ID      = u32(1)
    ...
```

### Stat group id constants

| u32 value | Kernel constant          | Stats exposed                                   |
|-----------|--------------------------|------------------------------------------------|
| 0         | ETH_STATS_ETH_MAC        | IEEE 802.3 Clause 30 MAC counters (~22 names)  |
| 1         | ETH_STATS_ETH_PHY        | IEEE 802.3 PHY symbol error counters (~6)       |
| 2         | ETH_STATS_ETH_CTRL       | MAC CTRL (PAUSE opcodes received/sent) (~3)     |
| 3         | ETH_STATS_RMON           | RMON histogram (rx+tx buckets) (~28)            |

Source: `include/uapi/linux/ethtool.h` enum `ethtool_stats_eth_mac_id` and siblings,
and `include/uapi/linux/ethtool_netlink.h` enum `ethtool_stats_grps`.

### Parsing algorithm in Rust

```rust
// Pseudocode — actual impl uses netlink-packet-core attribute iteration
fn parse_stats_reply(msg: EthtoolMessage) -> NicStatEntry {
    let mut stats = Vec::new();
    for grp in msg.attributes.filter(ETHTOOL_A_STATS_GRP) {
        for stat in grp.nested().filter(ETHTOOL_A_STATS_GRP_STAT) {
            // SAFETY: genlmsghdr version = 1 guarantees both NAME and VALUE
            // are present in every STAT nest per the ethtool netlink protocol.
            let name = stat.nested()
                .find(ETHTOOL_A_STATS_GRP_STAT_NAME)
                .and_then(|a| a.value_str_lossy())
                .unwrap_or_default();
            let value = stat.nested()
                .find(ETHTOOL_A_STATS_GRP_STAT_VALUE)
                .and_then(|a| a.value_u64())
                .unwrap_or(0);
            if !name.is_empty() {
                stats.push(EthtoolStat { name, value: value as i64 });
            }
        }
    }
    NicStatEntry { interface: iface_name, stats, supported: true }
}
```

---

## 5. Phase 3: Link settings, PAUSE, FEC (unicast per interface)

For each interface with `supported = true`, the adapter sends three unicast requests
in parallel (via `tokio::join!` or `FuturesUnordered`):

### 5.1 ETHTOOL_MSG_LINKSETTINGS_GET

```
genlmsghdr { cmd: 4, version: 1 }
ETHTOOL_A_LINKSETTINGS_HEADER (nested)
    ETHTOOL_A_HEADER_DEV_INDEX = u32(ifindex)
```

Reply attributes decoded:

| Attribute                          | Type | Notes                                                   |
|------------------------------------|------|---------------------------------------------------------|
| ETHTOOL_A_LINKSETTINGS_SPEED       | u32  | Mbps; 0xFFFFFFFF = unknown → emit string "unknown"      |
| ETHTOOL_A_LINKSETTINGS_DUPLEX      | u8   | 0=half, 1=full, 255=unknown                             |
| ETHTOOL_A_LINKSETTINGS_PORT        | u8   | 0=tp, 1=aui, 2=mii, 3=fibre, 4=bnc, 5=da, 239=none     |
| ETHTOOL_A_LINKSETTINGS_AUTONEG     | u8   | 0=off, 1=on                                             |

Speed is emitted as a Mbps string label (e.g., "10000") not as a numeric gauge. The
`nft_ethtool_link_info` gauge is always 1; the speed/duplex/autoneg/port values live
in label dimensions rather than metric values, enabling standard PromQL label filtering.

### 5.2 ETHTOOL_MSG_PAUSE_GET

```
genlmsghdr { cmd: 11, version: 1 }
ETHTOOL_A_PAUSE_HEADER (nested)
    ETHTOOL_A_HEADER_DEV_INDEX = u32(ifindex)
```

Reply contains `ETHTOOL_A_PAUSE_STAT` (nested) with:

| Nested attribute              | Type | Metric emitted                |
|-------------------------------|------|-------------------------------|
| ETHTOOL_A_PAUSE_STAT_RX_FRAMES | u64 | nft_ethtool_pause_rx_total    |
| ETHTOOL_A_PAUSE_STAT_TX_FRAMES | u64 | nft_ethtool_pause_tx_total    |

If the driver returns EOPNOTSUPP for this command, PAUSE stats are omitted silently.
The interface is not marked unsupported overall; only PAUSE stats are absent.

### 5.3 ETHTOOL_MSG_FEC_GET

```
genlmsghdr { cmd: 21, version: 1 }
ETHTOOL_A_FEC_HEADER (nested)
    ETHTOOL_A_HEADER_DEV_INDEX = u32(ifindex)
```

Reply structure:

```
ETHTOOL_A_FEC_STAT (nested)
    ETHTOOL_A_FEC_STAT_CORRECTED (nested, one sub-attr per lane)
        lane_0: u64(corrected_blocks_on_lane_0)
        lane_1: u64(corrected_blocks_on_lane_1)
        ...
```

The lane sub-attributes are indexed by their `nla_type` value (0-based lane index).
The adapter iterates all sub-attrs inside `ETHTOOL_A_FEC_STAT_CORRECTED` and emits one
`nft_ethtool_fec_corrected_total{interface, lane}` counter per lane.

If EOPNOTSUPP is returned (FEC not active or not supported), no FEC series are emitted
for that interface. This is not counted as an error; it is expected for copper/1G links.

---

## 6. Standard stat groups vs. driver -S strings

This section explains the cardinality argument that drives ADR-0011.

### Standard groups (chosen path)

Standard stat groups are defined in the kernel uapi:

- `ETH_STATS_ETH_MAC` (id 0): counters from IEEE 802.3 Clause 30 MIB. Names such as
  `FramesTransmittedOK`, `FrameCheckSequenceErrors`, `OctetsReceivedOK`. The kernel
  defines exactly these names; drivers implement a subset. The name set is **stable**
  across kernel versions and **bounded** (~22 names for eth-mac).

- `ETH_STATS_ETH_PHY` (id 1): PHY-layer counters. Names such as
  `SymbolErrorDuringCarrier`. Bounded (~6 names).

- `ETH_STATS_ETH_CTRL` (id 2): MAC control frame counters. Names such as
  `MACControlFramesTransmitted`. Bounded (~3 names).

- `ETH_STATS_RMON` (id 3): RMON histogram. Names follow the pattern
  `etherStatsPkts64Octets`, `etherStatsPkts65to127Octets`, etc. Bounded (~28 names
  covering 7 rx buckets + 7 tx buckets + 14 oversized variants).

Total per interface: at most ~59 named counters. On 512 interfaces: ~30 208 series.
Below the 50 000 ADR-0005 ceiling.

### Driver -S strings (rejected path)

The legacy ethtool ioctl path (`ETHTOOL_GSTRINGS` / `SIOCETHTOOL`) exposes a
driver-defined array of 32-byte C strings. There is no naming contract; drivers invent
names at will. The count and names change between driver versions without notice.

Example driver string counts from production NICs:

| Driver     | Example strings                                      | Count |
|------------|------------------------------------------------------|-------|
| mlx5       | `rx_prio0_buf_discard`, `port.rx_pci_signal_integrity` | > 2000 |
| bnxt_en    | `rx_ucast_pkts`, `hw_drop_pkts`, `rx_xdp_drop`      | ~350  |
| igb        | `rx_packets`, `tx_packets`, `rx_errors`              | ~25   |
| virtio-net | (none — EOPNOTSUPP)                                  | 0     |
| veth       | `peer_ifindex`, `xdp.drop`, `page_pool.allocated`   | ~12   |

On a node with 4 mlx5 ports x 2000 strings each: 8000 series per node, within bound.
On a node with 512 veth pairs each with a real mlx5 uplink: unbounded by interface
count. This exporter runs as a DaemonSet on nodes that may have hundreds of veth
interfaces (one per container); the driver -S path is incompatible with ADR-0005.

The genetlink `ETHTOOL_MSG_STRSET_GET` command (cmd = 1) is the new equivalent for
driver -S name enumeration. It is also not used by this exporter for the same reason.

### Cardinality warning

Any future attempt to add `ETHTOOL_MSG_STRSET_GET` or the legacy `ETHTOOL_GSTRINGS`
ioctl path to this exporter MUST be gated by a Rego policy check in CI. The policy
`nft_exporter.metric.cardinality` in `docs/arch/policies/cardinality.rego` already
rejects metric families with unbounded label dimensions. The `stat` label on
`nft_ethtool_stat` is explicitly bounded because the standard group stat names form a
finite set defined in the kernel uapi.

---

## 7. EOPNOTSUPP handling

The kernel returns EOPNOTSUPP (errno 95) in the nlmsgerr payload when:

- The interface does not support the ethtool genetlink API at all (virtual, loopback).
- A specific command is not implemented by the driver (PAUSE on a loopback, FEC on copper).
- The kernel is < 5.12 and ETHTOOL_MSG_STATS_GET is not registered.

The adapter distinguishes three cases:

| Condition                              | Errno    | Action                                              |
|----------------------------------------|----------|-----------------------------------------------------|
| Family not found in CTRL_CMD_GETFAMILY | ENOENT   | collector_success = 0; reason = kernel_unsupported  |
| STATS_GET EOPNOTSUPP for one interface | EOPNOTSUPP | Mark interface supported = false; no series emitted |
| PAUSE_GET EOPNOTSUPP for one interface | EOPNOTSUPP | Skip PAUSE stats for that interface; not an error   |
| FEC_GET EOPNOTSUPP for one interface   | EOPNOTSUPP | Skip FEC stats for that interface; not an error     |

Only the family-not-found case increments `nft_scrape_collector_error_total`. Per-interface
EOPNOTSUPP is treated as a normal capability probe result, not an error.

---

## 8. veth probe ground truth

Real probe data from a `veth` interface pair on Linux 6.x confirms:

- `ETHTOOL_MSG_STATS_GET` with groups 0x0F returns EOPNOTSUPP. No `nft_ethtool_stat`
  series are emitted for any veth interface.
- `ETHTOOL_MSG_LINKSETTINGS_GET` on veth returns speed 10000 (10 Gbps virtual link),
  duplex full, autoneg off, port "none" (port value 239 = NONE in the uapi).
- `ETHTOOL_MSG_PAUSE_GET` returns EOPNOTSUPP for veth.
- `ETHTOOL_MSG_FEC_GET` returns EOPNOTSUPP for veth.
- `peer_ifindex`, `xdp.*`, and `page_pool.*` stats visible via ethtool CLI on veth are
  driver -S strings (accessible via `ETHTOOL_MSG_STRSET_GET` / `ETHTOOL_GSTRINGS`).
  They are NOT accessible via the standard group path and are therefore not collected.

This probe result is the basis for the `#VethSupportedStats` value object in
`docs/arch/schemas/ethtool_wire.cue`.

---

## 9. Metric mapping

| Kernel source                                      | Rust type   | Prometheus metric               | Labels               |
|----------------------------------------------------|-------------|---------------------------------|----------------------|
| ETHTOOL_A_STATS_GRP_STAT_NAME + VALUE              | EthtoolStat | nft_ethtool_stat (gauge)        | interface, stat      |
| ETHTOOL_A_LINKSETTINGS_SPEED/DUPLEX/AUTONEG/PORT   | LinkSettings| nft_ethtool_link_info (gauge=1) | interface, speed, duplex, autoneg, port |
| ETHTOOL_A_PAUSE_STAT_RX_FRAMES                     | u64         | nft_ethtool_pause_rx_total      | interface            |
| ETHTOOL_A_PAUSE_STAT_TX_FRAMES                     | u64         | nft_ethtool_pause_tx_total      | interface            |
| ETHTOOL_A_FEC_STAT_CORRECTED (per lane)            | u64         | nft_ethtool_fec_corrected_total | interface, lane      |

`nft_ethtool_stat` is typed as `gauge` (not `counter`) because ethtool statistics reset
when an interface is brought down and back up. This makes them non-monotonic: a counter
that decreases violates OpenMetrics counter semantics. Operators must use `rate()` or
`delta()` over the gauge value for rate calculations, as documented in the HELP string
and in the `#EthtoolStat` CUE comment.

---

## 10. Crate stack mapping

| Wire operation                    | Rust crate               | Type / method                                  |
|-----------------------------------|--------------------------|------------------------------------------------|
| Open NETLINK_GENERIC socket       | netlink-sys 0.8.8        | `AsyncSocket::new(NETLINK_GENERIC)`            |
| CTRL_CMD_GETFAMILY                | genetlink 0.2.6          | `GenetlinkHandle::resolve_family_id("ethtool")`|
| ETHTOOL_MSG_STATS_GET dump        | ethtool 0.2.9            | `EthtoolHandle::stats().get(None)`             |
| ETHTOOL_MSG_LINKSETTINGS_GET      | ethtool 0.2.9            | `EthtoolHandle::link_settings().get(ifindex)`  |
| ETHTOOL_MSG_PAUSE_GET             | ethtool 0.2.9            | `EthtoolHandle::pause().get(ifindex)`          |
| ETHTOOL_MSG_FEC_GET               | ethtool 0.2.9            | `EthtoolHandle::fec().get(ifindex)`            |
| Attribute parsing                 | netlink-packet-generic 0.4.0 | `GenlMessage<EthtoolHeader>` attr iteration |
| Async framing                     | netlink-proto 0.12.0     | `Connection<GenlMessage<_>>`                   |

The `ethtool 0.2.9` crate uses `default-features = false` with only the `tokio` feature
enabled, as declared in ADR-0004. This prevents the crate from pulling in `async-std`.

---

## 11. Error taxonomy

| Kernel error | Rust errno | EthtoolAdapterError variant       | Metric impact                                       |
|--------------|------------|------------------------------------|-----------------------------------------------------|
| ENOENT       | 2          | `FamilyNotFound`                  | collector_success=0; error_total reason=kernel_unsupported |
| EOPNOTSUPP   | 95         | `InterfaceUnsupported(ifindex)`   | No series for that interface; not counted as error  |
| EPERM        | 1          | `PermissionDenied`                | collector_success=0; error_total reason=netlink_permission_denied |
| ENOBUFS      | 105        | `ReceiveBufferOverflow`           | collector_success=0; error_total reason=netlink_truncated; ENOBUFS circuit-breaker engages |
| ENOMEM       | 12         | `KernelOom`                       | collector_success=0; retried with backoff            |

ENOBUFS requires special handling: the kernel drops the entire dump response when the
receive buffer is exhausted. The adapter doubles `SO_RCVBUF` (up to 4 MB) on the first
ENOBUFS, then retries. If a second ENOBUFS occurs the scrape fails with
`reason=netlink_truncated` and the stale-snapshot fallback activates.
