# Glossary

Ubiquitous-language terms for the nft_exporter domain. One term per
definition; keep entries en-US and CommonMark.

## nft_exporter

The product bounded by this architecture specification.

---

## Collector

A concrete implementation of the Collector strategy trait responsible for one
netlink subsystem family. Maps raw kernel nlmsghdr byte streams to ReadModels.
Registered in CollectorRegistry at startup. Six concrete collectors exist:
RtnetlinkCollector, TcCollector, ConntrackCollector, NftablesCollector,
SockDiagCollector, EthtoolCollector.

## CollectorRegistry

The Abstract Factory (GoF) that instantiates and holds all enabled Collector
strategies based on ExporterConfig. Adding a new subsystem requires only a new
concrete strategy registered here; no changes to ScrapeLifecycle are needed.
Implements the Open/Closed Principle alongside the Strategy pattern.

## ConntrackAggregator

A Domain Service in the Conntrack bounded context that groups raw ConntrackFlow
entries by (protocol, state, direction) and sums byte and packet counters. Pure
domain logic with no kernel or infrastructure dependency; fully unit-testable
with synthetic FlowKey value objects.

## ConntrackFlow

An AggregateRoot representing one kernel connection-tracking entry, identified
by FlowKey. Carries CounterState (packets, bytes) per direction (original and
reply). Never emitted as a Prometheus time series; consumed only by
ConntrackAggregator to produce the ConntrackSummary ReadModel.

## ConntrackSummary

A ReadModel produced by ConntrackAggregator that aggregates ConntrackFlow
entries by (protocol, state) for metric emission. The only conntrack data
structure that reaches MetricRegistryPort. Enforces the cardinality rule:
at most |protocol| x |state| = approximately 40 time series.

## DrivenPort

An async trait declared in a domain-core crate that the domain calls outward
toward infrastructure. One DrivenPort exists per netlink subsystem family plus
MetricRegistryPort, ClockPort, and ConfigPort. Implemented exclusively in
adapter crates. Domain-core crates must never import the implementing struct.

## DrivingPort

An async trait declared in the domain-core crate that external actors call
inward toward the domain. The four DrivingPorts are ScrapeTriggerPort,
HealthPort, ReadinessPort, and CliConfigPort. Implemented by AxumHttpAdapter
in the adapter layer.

## ExporterApp

The Facade (GoF) that wires all ports and adapters, opens netlink sockets,
drops capabilities via the caps crate immediately after all socket file
descriptors are opened, and starts the tokio runtime and axum HTTP server.
The sole entry point of the nft_exporter binary in main.rs.

## FlowKey

A ValueObject (src_ip, dst_ip, protocol, src_port, dst_port) that uniquely
identifies a conntrack flow within a scrape epoch. FlowKey is never used as a
Prometheus label; it is used only internally by ConntrackAggregator to group
ConntrackFlow entries before producing the ConntrackSummary ReadModel.

## Link

An AggregateRoot representing a Linux network interface where ifindex is the
identity. Owns its AddressList and operational Flags bitmask. Invariant: the
AddressList must be non-empty when operstate=up. Produced by
RtnetlinkCollector via RTM_GETLINK requests over NetlinkRtPort.

## MetricSnapshot

An immutable value produced by ScrapeLifecycle containing all ReadModels from
one scrape epoch. Passed to MetricRegistryPort for OpenMetrics text encoding.
Valid only for one HTTP /metrics response; never cached across scrapes.

## NftChain

An AggregateRoot representing an nftables chain, identified by (table name,
chain name). Owns its NftRuleList and referenced SetList. Default policy
(accept or drop) and hook attachment point (prerouting, input, forward, output,
postrouting, ingress, egress) are immutable within a scrape epoch.

## ReadModel

An immutable snapshot of domain state valid for exactly one scrape epoch,
produced by a Collector and consumed by MetricRegistryPort. The exporter never
writes kernel state; the kernel is the sole authority. ReadModels carry no
mutable references and are constructed once per scrape.

## ScrapeLifecycle

The Template Method (GoF) orchestrator that enforces the invariant async
sequence pre_scrape_hook -> collect_all -> post_process -> publish ->
post_scrape_hook for every GET /metrics pull. Applies a catch-unwind boundary
and stale-snapshot fallback policy per collector. Records
nft_scrape_collector_success and nft_scrape_collector_error_total telemetry
regardless of individual collector outcome.

## TcHandle

A ValueObject (major: u16, minor: u16) representing a TC object handle in the
kernel's major:minor hex notation (for example, 0x0001:0x0000 displayed as
1:0). Used to identify QdiscNode entities and traffic class entities in the
TcTreeSnapshot ReadModel.

---

## bytemuck

A crate providing Pod and Zeroable derive macros used for zero-copy casting of
smaller leaf kernel structs (nf_conntrack_stat per-CPU parse, gnet_stats_basic
inside TCA_STATS2) from raw byte slices. Complements zerocopy where zerocopy's
streaming abstraction is not needed. Version 1.25.0 in nft_exporter. See also:
zerocopy.

## byteorder

A crate providing NetworkEndian reads for big-endian payload fields inside
nfnetlink (CTA_COUNTERS_BYTES u64 be, CTA_STATUS u32 be,
CTA_PROTO_SRC_PORT u16 be) and ctnetlink. All nlmsghdr and nlattr header
fields are native-endian and require no byteorder conversion. Version 1.5.0.

## ctnetlink

The netlink subsystem for connection tracking, accessed via NETLINK_NETFILTER
(protocol=12) with NFNL_SUBSYS_CTNETLINK=1 encoded in the high byte of
nlmsg_type. nft_exporter issues three distinct message types:
IPCTNL_MSG_CT_GET_STATS_CPU (0x0105) for per-CPU global counters summed into
zero-label metrics; IPCTNL_MSG_CT_GET_STATS (0x0106) for the global entry
ceiling; and IPCTNL_MSG_CT_GET (0x0101) for the full conntrack table dump
aggregated by (protocol, state) and (protocol, direction). Requires
CAP_NET_ADMIN per ADR-0009.

## genetlink

Generic netlink (NETLINK_GENERIC, protocol=16), a multiplexing layer on top of
AF_NETLINK that hosts dynamically registered families. Each family has a
numeric ID assigned at kernel module load time; the ID is resolved at runtime
via CTRL_CMD_GETFAMILY (sent to static family id GENL_ID_CTRL=16 with
CTRL_ATTR_FAMILY_NAME='ethtool'). The resolved ID is cached in an `OnceLock<u16>`
and used as nlmsg_type for all subsequent ETHTOOL_MSG_* requests. nft_exporter
uses genetlink exclusively for the ethtool subsystem.

## NETLINK_GET_STRICT_CHK

A SOL_NETLINK socket option (value=11, available kernel >= 4.20) that enables
strict request validation. When set to 1, the kernel rejects malformed dump
requests and respects filter attributes such as IFLA_EXT_MASK. nft_exporter
sets this option via setsockopt immediately after bind on the NETLINK_ROUTE
socket, ignoring ENOPROTOOPT on older kernels. Important: setting
RTEXT_FILTER_SKIP_STATS in IFLA_EXT_MASK suppresses IFLA_STATS64 from
RTM_NEWLINK responses; nft_exporter never sets this filter when collecting
link counters.

## nfgenmsg

The 4-byte header that follows nlmsghdr in every NETLINK_NETFILTER message.
Fields: nfgen_family u8 (AF_UNSPEC=0 for stats requests; AF_INET=2 or
AF_INET6=10 for dumps), version u8 (always NFNETLINK_V0=0), res_id __be16
(always big-endian regardless of host byte order — CPU index in
CT_GET_STATS_CPU replies; zero in requests). The __be16 encoding is a kernel
UAPI invariant: u16::from_be_bytes([buf[18], buf[19]]) is correct on all
supported targets including little-endian x86-64 and aarch64. Using
native-endian read produces wrong CPU indices.

## NLM_F_DUMP

A nlmsg_flags bitmask combination (NLM_F_REQUEST=0x01 | NLM_F_DUMP=0x0300 =
0x0301) that requests a full kernel table dump. The kernel responds with zero
or more NLM_F_MULTI-flagged reply messages terminated by NLMSG_DONE.
NLM_F_DUMP_INTR (bit-4 of nlmsg_flags) on any frame in the sequence signals
that the table was modified during the dump; accumulated state must be
discarded and the dump restarted. nft_exporter caps restarts at
ExporterConfig.netlink_dump_max_restarts (default 8) before activating the
stale-snapshot fallback.

## NLM_F_DUMP_INTR

A nlmsg_flags bit (0x0010) set by the kernel on any message in a dump sequence
when the underlying kernel data structure was modified concurrently. Can appear
on any RTM_NEW* or NLMSG_DONE frame — not only on the terminal frame.
nft_exporter checks this bit on every received frame; when seen, all
accumulated ReadModel state for the current dump is discarded and the dump is
restarted from the beginning. After ExporterConfig.netlink_dump_max_restarts
failed restarts, the collector returns CollectorError::DumpIntr and
ScrapeLifecycle activates the stale-snapshot fallback.

## nlattr

The 4-byte header for a netlink type-length-value attribute. Fields: nla_len
u16 (unpadded total size including this header), nla_type u16 (attribute type
constant; bit-15 = NLA_F_NESTED; bit-14 = NLA_F_NET_BYTEORDER; strip both
before matching). Payload starts at byte offset 4. Next attribute:
(nla_len+3)&~3 bytes after current attr start. Failing to apply NLA_ALIGN to
the advance offset is the most common netlink parse bug.

## nlmsghdr

The 16-byte header prefixed to every netlink message, encoded in native (host)
byte order on all supported targets. Fields: nlmsg_len u32 (total datagram
length including this header), nlmsg_type u16 (message type constant, e.g.
RTM_NEWLINK=16, NLMSG_DONE=3), nlmsg_flags u16 (NLM_F_REQUEST=0x01,
NLM_F_MULTI=0x02, NLM_F_DUMP_INTR=0x10, NLM_F_DUMP=0x0300), nlmsg_seq u32,
nlmsg_pid u32 (zero in requests). Traversal: NLMSG_ALIGN(nlmsg_len) =
(nlmsg_len+3)&~3. NLMSG_HDRLEN = 16.

## rtnl_link_stats64

A kernel struct (192 bytes on kernel < 5.18; 200 bytes on kernel >= 5.18)
carried in the IFLA_STATS64 (rta_type=23) netlink attribute of RTM_NEWLINK
responses. Contains 24 u64 interface counters at fixed byte offsets:
rx_packets@0, tx_packets@8, rx_bytes@16, tx_bytes@24, rx_errors@32,
tx_errors@40, rx_dropped@48, tx_dropped@56, plus detailed error counters
through offset 184, and rx_otherhost_dropped@192 (only valid when payload_len
>= 200). nft_exporter always uses IFLA_STATS64; IFLA_STATS (rta_type=7, u32
fields, 96 bytes) is never read because it overflows on 100 GbE interfaces
within hours.

## sock_diag

The NETLINK_SOCK_DIAG (protocol=4) subsystem that exposes per-socket
statistics to privileged userspace. nft_exporter issues
SOCK_DIAG_BY_FAMILY (nlmsg_type=20) dump requests with inet_diag_req_v2
payloads, iterating over AF_INET and AF_INET6 for TCP, UDP, and UDPLite.
Responses contain inet_diag_msg structs plus optional nlattr chains carrying
INET_DIAG_SKMEMINFO (socket memory drop counter) and INET_DIAG_INFO (TCP
retransmit count). All per-socket identity fields (idiag_inode, IP addresses,
ports) are discarded immediately after accumulation into SocketBucketStats.

## zerocopy

A crate providing FromBytes, IntoBytes, and Unaligned derive macros for
zero-copy casting of fixed kernel structs (nlmsghdr, nlattr, ifinfomsg,
nf_conntrack_stat, gnet_stats_basic, gnet_stats_queue) from &[u8] slices with
runtime alignment validation. nft_exporter uses the stable 0.8 branch
exclusively; the 0.9.0-alpha.0 branch is explicitly banned in cargo deny
configuration. See also: bytemuck.

---

## SAD (Security Association Database)

Kernel data structure holding active IPsec Security Associations (SAs). Each SA
defines a unidirectional IPsec transform (ESP or AH) between two peers. Queried
via XFRM_MSG_GETSA dump on NETLINK_XFRM. nft_exporter counts SAs aggregated by
(proto, mode) — never per-SA.

## SPD (Security Policy Database)

Kernel data structure holding IPsec Security Policies that govern which traffic
is protected. Each policy has a direction (in/fwd/out) and an action
(allow/block). Queried via XFRM_MSG_GETPOLICY dump. nft_exporter counts policies
aggregated by (dir, action).

## NETLINK_XFRM

Linux netlink protocol family number 6. Used by the kernel XFRM subsystem for
IPsec SA and SP management. Distinguished from NETLINK_ROUTE (0),
NETLINK_NETFILTER (12), NETLINK_SOCK_DIAG (4), and NETLINK_GENERIC (16).
Requires the xfrm_user kernel module or equivalent built-in.

## Runtime availability gate

A startup probe that determines whether an optional kernel subsystem is present
before opening scrape sockets. For the xfrm-ipsec collector, the gate issues
XFRM_MSG_GETSADINFO with a 500 ms timeout. EPROTONOSUPPORT, ENOENT, or EPERM
sets available=false; the collector emits only
nft_scrape_collector_available{collector="xfrm-ipsec"} 0 and returns without
error on each scrape cycle.

## xfrm_stat

The /proc/net/xfrm_stat virtual file exposing 26 XFRM kernel error counters
(e.g. XfrmInError, XfrmOutPolBlock) as plain key-value text. These counters are
already aggregated across CPUs by the kernel. They are the sole source for
nft_xfrm_stat_total; no equivalent NETLINK_XFRM message type exists for these
counters.

## NetlinkXfrmIpsecPort

Driven port in the nft_exporter hexagonal model (ADR-0002) for the xfrm-ipsec
bounded context. The adapter crate nft_exporter_adapter_xfrm implements this
port using rustix socket primitives and zerocopy struct parsing of
xfrm_usersa_info and xfrm_userpolicy_info frames.

## IPVS

IP Virtual Server (also known as Linux Virtual Server, LVS). A layer-4
load-balancing subsystem built into the Linux kernel, configured via the ip_vs
kernel module. Exposes virtual services (VIP:port or fwmark) and real servers
(RIP:rport) through a generic-netlink family named IPVS (version 1).

## IPVS_CMD_GET_SERVICE

Generic-netlink command (value 4) that returns the full list of IPVS virtual
services when sent with NLM_F_DUMP. Each reply frame carries
IPVS_SVC_ATTR_AF, IPVS_SVC_ATTR_PROTOCOL, IPVS_SVC_ATTR_ADDR,
IPVS_SVC_ATTR_PORT (or IPVS_SVC_ATTR_FWMARK), and nested
IPVS_SVC_ATTR_STATS64 counters.

## IPVS_CMD_GET_DEST

Generic-netlink command (value 8) that returns the real-server (destination)
list for a given virtual service. Sent as a unicast request per service with the
service key embedded. Each reply frame carries IPVS_DEST_ATTR_ADDR,
IPVS_DEST_ATTR_PORT, IPVS_DEST_ATTR_ACTIVE_CONNS, IPVS_DEST_ATTR_INACT_CONNS,
and nested IPVS_DEST_ATTR_STATS64.

## IPVS_STATS64_ATTR

Nested generic-netlink attribute set (IPVS_STATS_ATTR_CONNS, _INPKTS, _OUTPKTS,
_INBYTES, _OUTBYTES, _CPS, _INPPS, _OUTPPS, _INBPS, _OUTBPS) carried inside
IPVS_SVC_ATTR_STATS64 or IPVS_DEST_ATTR_STATS64. All fields are native-endian
u64. Available on kernel >= 3.15; supersedes the 32-bit IPVS_SVC_ATTR_STATS
variant.

## fwmark service

An IPVS virtual service identified by a firewall mark (u32) rather than a
VIP:port tuple. The mark is set by iptables or nftables rules before packets
reach the IPVS scheduler. In nft_exporter metric labels, fwmark services use
vip="" and the fwmark hex value as the port label.

## runtime-gated collector

A collector that checks for kernel subsystem availability at startup (or on
first scrape) and suppresses all domain metrics when the subsystem is absent,
without incrementing error counters. The IPVS collector uses
CTRL_CMD_GETFAMILY ENOENT detection as its gate; the ethtool collector uses the
same pattern (ADR-0011 section 8.1). The gate result is published as
`nft_scrape_collector_available{collector=<name>}`.

## NetlinkIpvsPort

The driving port (in hexagonal architecture terms) for the ipvs bounded context.
Implemented by IpvsAdapter as an AFIT async trait. The IpvsCollector strategy
depends on this port to issue IPVS_CMD_GET_INFO, IPVS_CMD_GET_SERVICE, and
IPVS_CMD_GET_DEST requests and receive IpvsSnapshot ReadModel values.

## WireguardCollector

A Collector strategy (ADR-0018) that queries the WireGuard generic-netlink
family (NETLINK_GENERIC, family name 'wireguard') via WG_CMD_GET_DEVICE
NLM_F_DUMP. Produces a WireguardSnapshot ReadModel per scrape containing
per-device and per-peer metric data. Runtime-gated: if CTRL_CMD_GETFAMILY
returns ENOENT the collector emits
nft_scrape_collector_available{collector="wireguard"}=0 and performs no further
netlink I/O until process restart.

## NetlinkWireguardPort

The DrivenPort for the WireGuard bounded context. Shares the NETLINK_GENERIC
socket family (GENL_ID_CTRL=16) with the EthtoolAdapter but uses a separate
`OnceLock<Option<u16>>` for the dynamically resolved 'wireguard' family ID.
Implements WG_CMD_GET_DEVICE dump-and-parse with NLM_F_DUMP_INTR restart
semantics per ADR-0011.

## WireguardSnapshot

The immutable ReadModel produced by WireguardCollector for one scrape epoch.
Contains an available flag (false when genl family absent), a list of
WgDeviceSnapshot entries (one per WireGuard interface), and a total peer count
for cardinality enforcement. Passed directly to MetricRegistryPort; never cached
across scrapes.

## WgPeerIdentityHash

A 16-character lowercase hex string used as the 'peer' Prometheus label value.
Computed as the lowercase hex of the first 8 bytes of SHA-256 over
the 32-byte WGPEER_A_PUBLIC_KEY. The
raw public key bytes are discarded after hash computation. Overridden by the
wireguard_peer_names operator configuration map when a matching entry exists.

## wireguard_max_peers

An ExporterConfig field (default 1000) that caps the total number of WireGuard
peer snapshots emitted across all devices per scrape. When exceeded,
WireguardCollector increments
nft_scrape_collector_error_total{collector="wireguard", reason="cardinality_overflow"}
and activates the stale-snapshot fallback. Prevents unbounded Prometheus series
growth on VPN gateway hosts.

## WG_CMD_GET_DEVICE

The WireGuard generic-netlink command (cmd=0, version=1) sent with
NLM_F_REQUEST | NLM_F_DUMP and an empty body to enumerate all WireGuard
interfaces. The kernel returns one multi-part response per interface with
WGDEVICE_A_* attributes including a nested WGDEVICE_A_PEERS list. Each peer is
a WGPEER_A_* attribute chain carrying byte counts, last-handshake timespec64,
keepalive interval, and optional endpoint sockaddr.

## nft_scrape_collector_available

A self-telemetry gauge with label collector that distinguishes a
runtime-unavailable subsystem from a collection failure. Value 1 means the
subsystem's kernel module is loaded and the generic-netlink family resolved
successfully. Value 0 means the family was not found (ENOENT) at startup; no
scrape I/O is attempted. Used by wireguard, xfrm-ipsec, ipvs, devlink, and
drop-monitor collectors; other collectors use nft_scrape_collector_success for
their health signal.

## devlink

Linux kernel generic-netlink family (CONFIG_NET_DEVLINK, kernel >= 4.6) that
exposes device-level information for SmartNICs and switch ASICs, including port
metadata and health reporter state. Accessed via the NETLINK_GENERIC socket
family after resolving the family id with CTRL_CMD_GETFAMILY("devlink").

## DevlinkSnapshot

Immutable ReadModel produced by DevlinkCollector per scrape epoch. Contains
lists of DevlinkDeviceEntry, DevlinkPortEntry, and DevlinkHealthReporterEntry.
Empty lists when collector_available is false (devlink genl family returned
ENOENT).

## DevlinkHealthReporter

A named kernel object within a devlink device that tracks error and recovery
event counts plus a current health state (healthy, error, auto_recover, dumping,
corrective_action, unavailable). Exported as
nft_devlink_health_reporter_error_total,
nft_devlink_health_reporter_recover_total, and nft_devlink_health_reporter_state.

## NetlinkDevlinkPort

Driving port (hexagonal architecture) in the Devlink bounded context. Async
trait with methods get_devices, get_ports, and get_health_reporters. Implemented
by DevlinkAdapter in the infrastructure layer.

## DEVLINK_CMD_HEALTH_REPORTER_GET

Generic-netlink command (value 66) that returns health reporter state for a
specific devlink device. Must be issued once per device (bus_name + dev_name
filter attributes required); a global NLM_F_DUMP without device filter returns
EINVAL on kernels before 5.18.

## DropMonitorCollector

A Collector strategy in the drop-monitor bounded context that subscribes to the
NET_DM generic-netlink family multicast group NET_DM_GRP_ALERT, aggregates
per-reason drop counters from NET_DM_CMD_ALERT notifications in summary mode,
and produces a DropMonitorSnapshot ReadModel. Runtime-gated: when
CTRL_CMD_GETFAMILY returns ENOENT (drop_monitor module absent), the collector
emits nft_scrape_collector_available{collector=drop-monitor}=0 and an empty
snapshot without failing the scrape.

## DropMonitorSnapshot

An immutable ReadModel produced by DropMonitorCollector for one scrape epoch.
Carries a list of DropReasonCounter value objects accumulated from
NET_DM_CMD_ALERT frames received during the interval, plus an availability flag
derived from CTRL_CMD_GETFAMILY resolution. When availability is not available,
the entries list is empty.

## DropReasonKey

A ValueObject (reason: string, origin: sw|hw) that uniquely identifies a
drop-reason series within a DropMonitorSnapshot. reason is sourced from
NET_DM_ATTR_REASON (software drops, kernel >= 5.17) or NET_DM_ATTR_HW_TRAP_NAME
(hardware drops). origin is derived from NET_DM_ATTR_ORIGIN u16. Forms the
label set for nft_drop_packets_total.

## NET_DM

The generic-netlink family name for the Linux drop_monitor subsystem
(net/core/drop_monitor.c). Registered at kernel module load time; absent when
the module is not loaded. Family is resolved via CTRL_CMD_GETFAMILY with
CTRL_ATTR_FAMILY_NAME='NET_DM'. Supports two monitoring modes: per-packet alert
mode (unsupported by this exporter) and summary mode
(NET_DM_ALERT_MODE_SUMMARY), which aggregates drop events by reason before
delivering NET_DM_CMD_ALERT notifications on the NET_DM_GRP_ALERT multicast
group.

## NetlinkDropMonitorPort

The DrivenPort async trait declared in the drop-monitor domain-core crate.
Implemented exclusively by DropMonitorAdapter. Exposes resolve_family(),
start_summary_monitor(), and drain_alerts() -> `Vec<DropReasonCounter>`. Allows
DropMonitorCollector to remain independent of netlink wire details.

## RTM_GETSTATS

NETLINK_ROUTE message type 94 (kernel >= 4.20). Requests extended
per-interface statistics via an if_stats_msg body with a filter_mask selecting
IFLA_STATS_LINK_64, IFLA_STATS_LINK_XSTATS, and IFLA_STATS_LINK_OFFLOAD_XSTATS
attribute groups. Responses carry RTM_NEWSTATS (93) frames.

## IFLA_STATS_LINK_XSTATS

Attribute type 2 in RTM_NEWSTATS responses. Contains driver-specific statistics
nested under a link_xstats_type discriminator. For Linux bridge devices the
payload includes BRIDGE_XSTATS_VLAN and BRIDGE_XSTATS_MCAST sub-attributes.

## IFLA_STATS_LINK_OFFLOAD_XSTATS

Attribute type 4 in RTM_NEWSTATS responses. Contains hardware-offload statistics
for switchdev and tc-offload capable drivers. Payload is an rtnl_hw_stats64
struct (64 bytes) with rx_packets, tx_packets, rx_bytes, tx_bytes, and
error/drop counters.

## if_stats_msg

16-byte fixed-struct body used in RTM_GETSTATS requests and RTM_NEWSTATS
responses. Fields: ifi_family (u8, AF_UNSPEC=0), pad1 (u8), pad2 (u16),
ifindex (u32, 0=all in dumps), filter_mask (u32, bitmask of IFLA_STATS_*
groups).

## BRIDGE_XSTATS_MCAST

Sub-attribute type 2 inside IFLA_STATS_LINK_XSTATS for bridge interfaces.
Payload is a br_mcast_stats blob carrying per-bridge multicast receive and
transmit byte counters. Only rx_bytes (offset 0, u64) and tx_bytes (offset 8,
u64) are exported; per-group counters are discarded per ADR-0005.

## RTM_GETRULE

NETLINK_ROUTE message type 82. Dumps the fib policy-routing rule table for a
given address family (AF_INET, AF_INET6, or AF_MPLS). The body is a
fib_rule_hdr struct. The rtnetlink-extended collector issues one dump per family
and counts total rules per family.

## RTM_GETNEXTHOP

NETLINK_ROUTE message type 118 (kernel >= 5.3). Dumps the nexthop object table.
The body is an nhmsg struct (nh_family=AF_UNSPEC for all-object dump). Returns
EINVAL on kernels < 5.3; the adapter treats this as
availability=unavailable_kernel_too_old and emits nft_nexthop_objects=0 without
error.

## nhmsg

8-byte fixed-struct body used in RTM_GETNEXTHOP requests. Fields: nh_family
(u8), nh_scope (u8), nh_protocol (u8), resvd (u8), nh_flags (u32). All fields
zero for a full dump.

## bridge FDB

Bridge Forwarding Database. The per-bridge MAC-address-to-port mapping table
maintained by the Linux bridge driver. FDB entries are accessed via
RTM_GETNEIGH with ndmsg.ndm_family=AF_BRIDGE (7). The rtnetlink-extended
collector counts total entries per bridge interface without storing MAC
addresses.

## nexthop object

A kernel nexthop object (kernel >= 5.3) that abstracts next-hop information
(gateway address, interface, weights for ECMP groups) for use by multiple
routing entries. Counted in aggregate by nft_nexthop_objects.

## ConntrackExpectation

A short-lived placeholder entry in the kernel conntrack expectation table,
created by a connection-tracking helper module (for example, ftp, sip, h323,
tftp) to pre-register a secondary flow before it arrives. Expectations are
stored under NFNL_SUBSYS_CTNETLINK_EXP (subsystem id 2) and are retrieved via
IPCTNL_MSG_EXP_GET (nlmsg_type=0x0200). The ConntrackExpectationsCollector
aggregates active expectations by (l4proto, helper) to produce the
ConntrackExpectationSummary ReadModel.

## ConntrackExpectationSummary

The immutable ReadModel produced by ConntrackExpectationsCollector for one
scrape epoch. Contains a list of ExpectationBucketCount entries aggregated by
(l4proto, helper) — at most 160 entries — plus zero-label global counters (new,
delete, new_failed) sourced from IPCTNL_MSG_EXP_GET_STATS_CPU. When the kernel
returns ENOENT or EPERM for the EXP_GET probe request, available=false and all
fields are zero.

## NetlinkConntrackExpectationsPort

The driven async port declared in nft_exporter_domain_ct_exp that the
ConntrackExpectationsCollector calls outward toward the
ConntrackExpectationsAdapter. Methods: dump_expectations
(IPCTNL_MSG_EXP_GET dump) and get_exp_stats_cpu
(IPCTNL_MSG_EXP_GET_STATS_CPU). Implemented exclusively in the
nft_exporter_adapter_ct_exp crate over the shared NETLINK_NETFILTER socket.

## NFNL_SUBSYS_CTNETLINK_EXP

The Linux netlink subsystem identifier for the conntrack expectations table,
with numeric value 2. Encoded in the high byte of nlmsg_type:
nlmsg_type = (2 << 8) | msg_type_low_byte. IPCTNL_MSG_EXP_GET (low byte 0)
-> 0x0200 for a full dump; IPCTNL_MSG_EXP_GET_STATS_CPU (low byte 3) -> 0x0203
for per-CPU stats. Distinct from NFNL_SUBSYS_CTNETLINK (value 1) which covers
the main conntrack table.
