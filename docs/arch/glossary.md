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
CTRL_ATTR_FAMILY_NAME='ethtool'). The resolved ID is cached in an OnceLock<u16>
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
