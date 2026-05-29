workspace "nft_exporter" "C4 architecture model for nft_exporter — a Rust 2024-edition static-musl Linux netlink Prometheus exporter running on monoio io_uring." {

    model {

        # ── External actors ─────────────────────────────────────────────────
        prometheusServer = person "Prometheus Server" "Scrapes GET /metrics on port 9456 at configurable scrape_interval. Prometheus Operator ServiceMonitor manages target discovery in Kubernetes." "External,Monitoring"

        alertmanager = softwareSystem "Alertmanager" "Receives alerts fired from Prometheus alerting rules against nft_* metric families." "External,Monitoring" {
            tags "External"
        }

        grafana = softwareSystem "Grafana" "Queries Prometheus for dashboards visualising nft_link_*, nft_tc_*, nft_conntrack_*, nft_rule_*, nft_socket_*, and nft_ethtool_* metric families." "External,Monitoring" {
            tags "External"
        }

        linuxKernel = softwareSystem "Linux Kernel" "Exposes NETLINK_ROUTE, NETLINK_NETFILTER (ctnetlink + nfnetlink), NETLINK_SOCK_DIAG, NETLINK_GENERIC (ethtool, ipvs, wireguard, devlink, NET_DM), NETLINK_XFRM socket families, plus /proc and /sys pseudo-filesystems (opt-in only via nlx-procfs). Sole source of truth for all collected metrics. Requires kernel >= 5.15 for DaemonSet deployment; >= 5.1 for io_uring path (FusionDriver falls back to epoll below 5.1 via MONOIO_DRIVER=legacy). CAP_NET_ADMIN required; nf_conntrack and nftables kernel modules must be active for those collectors." "External,Infrastructure" {
            tags "External"
        }

        # ── Primary software system ──────────────────────────────────────────
        nftExporter = softwareSystem "nft_exporter" "Single statically-linked musl binary. Reads 13 Linux kernel netlink/genetlink API families natively plus 8 opt-in procfs/sysfs collectors, aggregates kernel state into bounded-cardinality metric families, and exposes them as Prometheus text format 0.0.4 on HTTP port 9456. Runs as a Kubernetes DaemonSet (hostNetwork:true) or systemd service on each Linux node. Requires CAP_NET_ADMIN only. Runtime: monoio 0.2 FusionDriver (io_uring-first, epoll fallback). ADR-0023 (io_uring runtime), ADR-0024 (netlink io_uring data path), ADR-0025 (native-API-only default), ADR-0027 (opt-in procfs/sysfs)." {

            # ── Domain core crates ──────────────────────────────────────────

            nlxDomain = container "nlx-domain" "Pure domain core. Defines MetricSample value object (MetricKind, MetricValue), ReadModels for all netlink subsystems (LinkReadModel, AddressReadModel, RouteReadModel, NeighborReadModel, ConntrackFlow, NftChain, TcQdisc, SocketDiagEntry, NicStatSnapshot, XfrmSa, IpvsService, WireguardDevice, DevlinkDevice, DropReasonCounter, and extended rtnetlink/conntrack-expect variants), ScrapeLifecycle state machine, and DomainError. Zero infrastructure dependencies; tokio, mio, rustix, axum, prometheus-client are forbidden by hexagonal.rego and cargo deny." "Rust 2024 edition, thiserror, serde; zero runtime deps" {
                tags "Container,DomainCore"
            }

            nlxPorts = container "nlx-ports" "Shared kernel: all hexagonal port trait definitions. Driving ports: ScrapeTriggerPort (async fn scrape), HealthPort (async fn is_healthy), ReadinessPort (async fn is_ready). Driven ports: MetricRegistryPort (update_samples, encode_text), ConfigPort (scrape_timeout_ms, listen_addr, collector_enabled). Per-subsystem driven ports: NetlinkRtPort, NetlinkTcPort, NetlinkConntrackPort, NetlinkNftablesPort, NetlinkSockDiagPort, NetlinkEthtoolPort, NetlinkIpvsPort, NetlinkWireguardPort, NetlinkDevlinkPort, NetlinkDropMonitorPort, NetlinkXfrmPort, NetlinkRtExtendedPort, NetlinkConntrackExpectPort. Collector strategy trait (object-safe, Pin<Box<dyn Future>>, no Send bound for monoio thread-per-core compatibility). Depends only on nlx-domain." "Rust 2024 edition, AFIT traits, thiserror; depends only on nlx-domain" {
                tags "Container,DomainCore"
            }

            # ── Composition root / binary ───────────────────────────────────

            netlinkExporter = container "netlink_exporter (binary)" "Composition root. Parses CLI via clap 4 (CliArgs), loads ExporterConfig via nlx-config::load_config, initialises tracing-subscriber, builds CollectorRegistry from config enable flags (scrape.rs), runs startup probe_available() on each collector, starts drop_monitor multicast background listener before capability drop, drops Linux capabilities to CAP_NET_ADMIN only via caps crate (abort-on-failure, panic=abort release profile), builds PrometheusRegistryAdapter and MonoioHttpAdapter, wires inline HealthService (always-healthy) and ReadinessService (AtomicBool set after probes). ScrapeService implements ScrapeTriggerPort: sequential fan-out with per-collector monoio::time::timeout, AtomicU64 error counters, self-telemetry (nft_up, nft_build_info, nft_scrape_collector_*). Single monoio thread (monoio::RuntimeBuilder with FusionDriver, DefaultThreadPool 4 threads for spawn_blocking). No tokio, no axum." "Rust 2024 edition, monoio 0.2 FusionDriver, arc-swap 1.7, caps, clap 4, anyhow, tracing-subscriber" {
                tags "Container,DrivingAdapter"

                exporterApp = component "ExporterApp (main)" "Facade (GoF) application entry point. Wires all ports and adapters via monoio::RuntimeBuilder::new().with_entries(256).enable_timer().build(). Drops capabilities to CAP_NET_ADMIN only via caps crate before starting the accept loop. Sole entry point of the binary. Uses FusionDriver: probes io_uring_setup at startup; falls back to epoll if syscall unavailable or MONOIO_DRIVER=legacy." "Rust, main.rs, monoio 0.2 FusionDriver, caps" {
                    tags "Component,Facade"
                }

                scrapeService = component "ScrapeService" "Template Method (GoF) implementing ScrapeTriggerPort in the CollectionOrchestration bounded context. Enforces the invariant async scrape sequence: pre_scrape_hook -> collect_all (sequential fan-out via monoio::time::timeout per collector) -> post_process -> publish (MetricRegistryPort::update_samples atomic ArcSwap store) -> post_scrape_hook. Records nft_scrape_collector_success and nft_scrape_collector_error_total. AtomicU64 error counters; no Mutex." "Rust, monoio 0.2 JoinHandle, arc-swap 1.7 ArcSwap" {
                    tags "Component,TemplateMethod"
                }

                collectorRegistry = component "CollectorRegistry" "Abstract Factory (GoF) in CollectionOrchestration bounded context. Instantiates and holds enabled Collector strategy instances (Box<dyn Collector> trait objects in Arc<Vec<...>>) based on ExporterConfig.collector_enabled() flags. Registers both nlx-netlink (13 default-on) and nlx-procfs (8 default-off) collectors. New subsystem requires only a new concrete strategy registered here." "Rust" {
                    tags "Component,AbstractFactory"
                }

                healthService = component "HealthService" "Inline implementation of HealthPort. Always returns healthy after startup. Wired directly in composition root; no separate crate." "Rust" {
                    tags "Component,DrivenAdapter"
                }

                readinessService = component "ReadinessService" "Inline implementation of ReadinessPort. Backed by an AtomicBool set to true after all startup probes (probe_available) complete. HTTP /ready returns 200 only when ready=true." "Rust, core::sync::atomic::AtomicBool" {
                    tags "Component,DrivenAdapter"
                }

                systemdNotifyAdapter = component "SystemdNotifyAdapter" "Infrastructure adapter sending sd_notify READY=1 and WATCHDOG=1 to systemd watchdog on successful startup and health-check intervals. Still accurate under monoio runtime." "Rust, libsystemd" {
                    tags "Component,DrivenAdapter"
                }
            }

            # ── Driving adapter: HTTP ───────────────────────────────────────

            httpExposition = container "nlx-http (HTTP Exposition)" "Driving HTTP/1 adapter. Binds monoio::net::TcpListener on port 9456 (default). Accept-loop with exponential backoff (10 ms initial, 1 s cap) on errors; spawns one monoio task per connection. Hand-rolled HTTP/1 framing: accumulates headers up to 8 KiB scanning for CRLF sentinel, path-dispatches via parse_path. Routes: GET /metrics calls ScrapeTriggerPort::scrape then MetricRegistryPort::encode_text (Content-Type: text/plain; version=0.0.4; charset=utf-8); GET /healthz calls HealthPort::is_healthy; GET /ready calls ReadinessPort::is_ready. Uses owned-buffer BufResult model required by monoio io_uring. No axum, no hyper, no tower." "Rust, monoio 0.2 TcpListener + AsyncReadRent + AsyncWriteRentExt, port 9456; no axum, no hyper" {
                tags "Container,DrivingAdapter"

                monoioHttpAdapter = component "MonoioHttpAdapter" "Driving adapter (Exposition bounded context). Type-aliased as AxumHttpAdapter for backward compat. monoio::net::TcpListener accept loop; hand-rolled HTTP/1 path-dispatch to ScrapeTriggerPort, HealthPort, ReadinessPort. No axum Router, no tower middleware. ADR-0023." "Rust, monoio 0.2, nlx-http crate" {
                    tags "Component,DrivingAdapter"
                }
            }

            # ── Driven adapter: config ──────────────────────────────────────

            nlxConfig = container "nlx-config" "Driven adapter implementing ConfigPort. Loads ExporterConfig by merging: built-in defaults -> TOML file (path from NLX_CONFIG_PATH or --config) -> NLX_-prefixed env vars (__ nesting separator, e.g. NLX_COLLECTORS__ETHTOOL=true) -> CLI flag overrides. Fields: listen_addr (default 0.0.0.0:9456), scrape_timeout_ms (default 30000), netlink_dump_max_restarts (default 8), log_level, interface_include/exclude_regex, wireguard_max_peers, CollectorFlags (13 netlink default-on, 8 procfs default-off per ADR-0027). Config env prefix NLX_ — not NFT_EXPORTER_." "Rust, figment 0.10 (Toml + Env providers), clap 4 derive, serde, toml" {
                tags "Container,DrivenAdapter"

                envConfigAdapter = component "EnvConfigAdapter" "Infrastructure adapter implementing ConfigPort. Merges TOML file, NLX_-prefixed environment variables (e.g. NLX_LISTEN, NLX_SCRAPE_TIMEOUT, NLX_COLLECTORS__ETHTOOL), and CLI flag overrides via figment 0.10 layered providers into a validated ExporterConfig value object." "Rust, figment 0.10, clap 4, serde" {
                    tags "Component,DrivenAdapter"
                }
            }

            # ── Driven adapter: metric registry ─────────────────────────────

            metricRegistry = container "nlx-metrics (Metric Registry)" "Driven adapter implementing MetricRegistryPort. PrometheusRegistryAdapter hand-encodes Prometheus text format 0.0.4 from Vec<MetricSample> (groups by name, emits # HELP + # TYPE headers, deduplicates identical label-set series, renders NaN/+Inf/-Inf correctly, strips ASCII control chars from label values). Encoded body stored in ArcSwap<Arc<str>>: update_samples does one atomic store; encode_text does one wait-free load. No Mutex, no RwLock. No prometheus-client library in the dependency tree (ADR-0006 deviation: hand-rolled to support dynamic BTreeMap<String,String> labels). Lock-free model per ADR-0023." "Rust, arc-swap 1.7 ArcSwap<Arc<str>> RCU, thiserror, tracing; no prometheus-client" {
                tags "Container,DrivenAdapter"

                prometheusRegistryAdapter = component "PrometheusRegistryAdapter" "Composite (GoF) + Driven Adapter in Exposition bounded context. Hand-encodes Vec<MetricSample> to Prometheus text 0.0.4 (no prometheus-client library). Implements MetricRegistryPort::update_samples (atomic ArcSwap store) and encode_text (wait-free ArcSwap load). Supports dynamic BTreeMap<String,String> label sets." "Rust, arc-swap 1.7, nlx-metrics crate; hand-rolled text encoding" {
                    tags "Component,Composite,DrivenAdapter"
                }

                stdClockAdapter = component "StdClockAdapter" "Driven adapter implementing ClockPort. Wraps std::time::Instant for deterministic scrape duration measurement. Replaced by FakeClockAdapter in unit tests." "Rust" {
                    tags "Component,DrivenAdapter"
                }
            }

            # ── Driven adapters: netlink collectors (nlx-netlink) ───────────

            rtnetlinkCollectorContainer = container "Rtnetlink Collector" "Collects per-interface link stats64 counters, address counts by family, route counts by family and table, and neighbor counts by state. Issues RTM_GETLINK, RTM_GETADDR, RTM_GETROUTE, RTM_GETNEIGH via NETLINK_ROUTE. Produces LinkReadModel, AddressReadModel, RouteReadModel, NeighborReadModel. Data path: IORING_OP_SEND/RECV on monoio::spawn_blocking thread (ADR-0024). Default-enabled." "Rust, nlx-netlink; rustix 1.1, linux-raw-sys 0.12, zerocopy 0.8, io-uring 0.7; IORING_OP_SEND/RECV" {
                tags "Container,Collector"

                rtnetlinkCollector = component "RtnetlinkCollector" "Concrete Strategy (GoF) in Rtnetlink bounded context. Issues RTM_GETLINK, RTM_GETADDR, RTM_GETROUTE, RTM_GETNEIGH via NetlinkRtPort. Parses nlattr TLVs via wire.rs NlaIter (zero-copy). Produces LinkReadModel, AddressReadModel, RouteReadModel, NeighborReadModel." "Rust" {
                    tags "Component,ConcreteStrategy"
                }

                rtnetlinkAdapter = component "RtnetlinkAdapter" "Driven adapter implementing NetlinkRtPort. Opens AF_NETLINK NETLINK_ROUTE via rustix::net::socket_with, nl_pid=0, SO_RCVBUF >= 4 MiB. Drives IORING_OP_SEND/RECV via io-uring crate 0.7 (ring depth 32 SQEs) on monoio::spawn_blocking. Handles NLM_F_DUMP_INTR restarts and ENOBUFS SO_RCVBUF doubling up to 16 MiB. No rtnetlink crate (ADR-0011)." "Rust, rustix 1.1, linux-raw-sys 0.12, io-uring 0.7, zerocopy 0.8, bytemuck 1.25" {
                    tags "Component,DrivenAdapter"
                }
            }

            tcCollectorContainer = container "Traffic Control Collector" "Dumps qdisc bytes, packets, drops, overlimits, and backlog aggregated per (device, kind) across multi-queue child qdiscs. Issues RTM_GETQDISC and RTM_GETLINK via NETLINK_ROUTE; decodes TCA_STATS2 (gnet_stats_basic, gnet_stats_queue). Aggregates multi-queue child qdiscs to avoid duplicate time-series. Produces TcQdisc ReadModel. Default-enabled." "Rust, nlx-netlink; rustix 1.1, linux-raw-sys 0.12, zerocopy 0.8, io-uring 0.7; IORING_OP_SEND/RECV" {
                tags "Container,Collector"

                tcCollector = component "TcCollector" "Concrete Strategy (GoF) in TrafficControl bounded context. Issues RTM_GETQDISC, RTM_GETLINK via NetlinkTcPort. Decodes TCA_STATS2 attributes. Aggregates per (device, kind). Produces TcQdisc ReadModel." "Rust" {
                    tags "Component,ConcreteStrategy"
                }

                tcNetlinkAdapter = component "TcNetlinkAdapter" "Driven adapter implementing NetlinkTcPort. Issues RTM_GETQDISC over NETLINK_ROUTE with IORING_OP_SEND/RECV; decodes TCA_STATS2 (gnet_stats_basic, gnet_stats_queue) via direct wire protocol. No rtnetlink or netlink-packet-route crates (ADR-0011)." "Rust, rustix 1.1, linux-raw-sys 0.12, io-uring 0.7, byteorder 1.5" {
                    tags "Component,DrivenAdapter"
                }
            }

            conntrackCollectorContainer = container "Conntrack Collector" "Collects per-CPU conntrack statistics and global entry count via NETLINK_NETFILTER (protocol 12), subsystem NFNL_SUBSYS_CTNETLINK. Issues IPCTNL_MSG_CT_GET_STATS_CPU, IPCTNL_MSG_CT_GET_STATS, IPCTNL_MSG_CT_GET. Aggregates individual flow entries by (protocol, state, direction) into bounded cardinality summaries. Produces ConntrackSummary ReadModel. Default-enabled." "Rust, nlx-netlink; rustix 1.1, linux-raw-sys 0.12, zerocopy 0.8, io-uring 0.7; IORING_OP_SEND/RECV; no vendored patches" {
                tags "Container,Collector"

                conntrackCollector = component "ConntrackCollector" "Concrete Strategy (GoF) in Conntrack bounded context. Issues IPCTNL_MSG_CT_GET full dump and IPCTNL_MSG_CT_GET_STATS_CPU via NetlinkConntrackPort. Produces ConntrackSummary ReadModel. Raw NETLINK_NETFILTER wire; no vendored netlink-packet-netfilter (ADR-0011)." "Rust" {
                    tags "Component,ConcreteStrategy"
                }

                conntrackAggregator = component "ConntrackAggregator" "Domain Service in Conntrack bounded context. Groups raw ConntrackFlow entries by (protocol, state, direction) and sums byte/packet counters. Pure domain logic with no kernel or infra dependency." "Rust" {
                    tags "Component,DomainService"
                }

                conntrackAdapter = component "ConntrackAdapter" "Driven adapter implementing NetlinkConntrackPort. Issues IPCTNL_MSG_CT_GET and IPCTNL_MSG_CT_GET_STATS_CPU over NETLINK_NETFILTER using IORING_OP_SEND/RECV. Kernel-version-adaptive struct sizing for IPCTNL_MSG_CT_GET_STATS_CPU. Big-endian nfnetlink fields decoded via byteorder. No vendored netlink-packet-netfilter (ADR-0011)." "Rust, rustix 1.1, linux-raw-sys 0.12, io-uring 0.7, byteorder 1.5" {
                    tags "Component,DrivenAdapter"
                }
            }

            nftablesCollectorContainer = container "Nftables Collector" "Counts nftables tables, chains, and rules by address family and exports named counter object bytes/packets via NETLINK_NETFILTER NFNL_SUBSYS_NFTABLES. Issues NFT_MSG_GETTABLE, NFT_MSG_GETCHAIN, NFT_MSG_GETRULE, NFT_MSG_GETOBJ. Produces NftCounterSnapshot ReadModel. Default-enabled." "Rust, nlx-netlink; rustix 1.1, linux-raw-sys 0.12, zerocopy 0.8, io-uring 0.7; IORING_OP_SEND/RECV; no rustables" {
                tags "Container,Collector"

                nftablesCollector = component "NftablesCollector" "Concrete Strategy (GoF) in Nftables bounded context. Issues NFT_MSG_GETTABLE, NFT_MSG_GETCHAIN, NFT_MSG_GETRULE, NFT_MSG_GETOBJ via NetlinkNftablesPort. Enforces cardinality overflow guard on anonymous rules. Produces NftCounterSnapshot ReadModel." "Rust" {
                    tags "Component,ConcreteStrategy"
                }

                nftablesAdapter = component "NftablesAdapter" "Driven adapter implementing NetlinkNftablesPort. Issues NFT_MSG_GET* requests over NETLINK_NETFILTER NFNL_SUBSYS_NFTABLES using IORING_OP_SEND/RECV. Direct wire protocol via rustix + linux-raw-sys; no rustables crate, no C toolchain required, hermetic musl preserved (ADR-0011)." "Rust, rustix 1.1, linux-raw-sys 0.12, io-uring 0.7, byteorder 1.5" {
                    tags "Component,DrivenAdapter"
                }
            }

            sockDiagCollectorContainer = container "SockDiag Collector" "Aggregates TCP/UDP socket counts, receive/send queue bytes, drops (INET_DIAG_SKMEMINFO), and cumulative TCP retransmits (tcp_info). Issues SOCK_DIAG_BY_FAMILY with inet_diag_req_v2 for AF_INET and AF_INET6 via NETLINK_SOCK_DIAG. Produces SocketStateHistogram ReadModel. Default-enabled." "Rust, nlx-netlink; rustix 1.1, linux-raw-sys 0.12, zerocopy 0.8, io-uring 0.7; IORING_OP_SEND/RECV; no netlink-packet-sock-diag" {
                tags "Container,Collector"

                sockDiagCollector = component "SockDiagCollector" "Concrete Strategy (GoF) in SockDiag bounded context. Issues SOCK_DIAG_BY_FAMILY for AF_INET and AF_INET6 via NetlinkSockDiagPort. Decodes inet_diag_msg (state, rqueue, wqueue) and INET_DIAG_SKMEMINFO. Aggregates socket counts and queue bytes by (protocol, state). Produces SocketStateHistogram ReadModel." "Rust" {
                    tags "Component,ConcreteStrategy"
                }

                sockDiagAdapter = component "SockDiagAdapter" "Driven adapter implementing NetlinkSockDiagPort. Issues SOCK_DIAG_BY_FAMILY for AF_INET/AF_INET6 over NETLINK_SOCK_DIAG using IORING_OP_SEND/RECV. Direct wire protocol; no netlink-packet-sock-diag crate (ADR-0011)." "Rust, rustix 1.1, linux-raw-sys 0.12, io-uring 0.7, zerocopy 0.8" {
                    tags "Component,DrivenAdapter"
                }
            }

            ethtoolCollectorContainer = container "Ethtool Collector" "Dumps IEEE standard NIC statistics (eth-phy, eth-mac, eth-ctrl, rmon groups) for all interfaces via the ethtool generic netlink family. Issues ETHTOOL_MSG_STATS_GET. Produces NicStatSnapshot ReadModel. Requires kernel 5.12+ and driver support. Default-enabled." "Rust, nlx-netlink; rustix 1.1, linux-raw-sys 0.12, zerocopy 0.8, io-uring 0.7; NETLINK_GENERIC ethtool family; no ethtool crate, no genetlink crate" {
                tags "Container,Collector"

                ethtoolCollector = component "EthtoolCollector" "Concrete Strategy (GoF) in Ethtool bounded context. Issues ETHTOOL_MSG_STATS_GET (bitset, per-stat GRP_STAT groups: eth-phy, eth-mac, eth-ctrl, rmon) via NetlinkEthtoolPort. Gates on per-NIC EOPNOTSUPP probe. Produces NicStatSnapshot ReadModel." "Rust" {
                    tags "Component,ConcreteStrategy"
                }

                ethtoolAdapter = component "EthtoolAdapter" "Driven adapter implementing NetlinkEthtoolPort. Resolves ethtool genl family ID via CTRL_CMD_GETFAMILY (shared resolve_genl_family helper). Issues ETHTOOL_MSG_STATS_GET over NETLINK_GENERIC using IORING_OP_SEND/RECV. Direct wire protocol; no ethtool crate, no genetlink crate (ADR-0011)." "Rust, rustix 1.1, linux-raw-sys 0.12, io-uring 0.7, zerocopy 0.8" {
                    tags "Component,DrivenAdapter"
                }
            }

            xfrmIpsecCollectorContainer = container "Xfrm IPsec Collector" "Counts IPsec Security Associations by protocol and mode, Security Policies by direction and action, and exposes SAD/SPD hash bucket counts. Issues XFRM_MSG_GETSA, XFRM_MSG_GETPOLICY, XFRM_MSG_GETSADINFO, XFRM_MSG_GETSPDINFO via NETLINK_XFRM. No /proc reads (ADR-0025). Produces XfrmSnapshot ReadModel. Sets available=0 when xfrm_user is absent or EPERM at startup probe. Default-enabled." "Rust, nlx-netlink; rustix 1.1, linux-raw-sys 0.12, zerocopy 0.8, io-uring 0.7; NETLINK_XFRM only; no procfs" {
                tags "Container,Collector,runtime-gated"

                xfrmIpsecCollector = component "XfrmIpsecCollector" "Concrete Strategy (GoF) in xfrm-ipsec bounded context. Issues XFRM_MSG_GETSA, XFRM_MSG_GETPOLICY, XFRM_MSG_GETSADINFO, XFRM_MSG_GETSPDINFO via NetlinkXfrmPort. No /proc/net/xfrm_stat read (ADR-0025 native-API-only). Produces XfrmSnapshot ReadModel. Emits nft_scrape_collector_available{collector=xfrm-ipsec}." "Rust" {
                    tags "Component,ConcreteStrategy"
                }

                xfrmIpsecAdapter = component "XfrmIpsecAdapter" "Driven adapter implementing NetlinkXfrmPort. Opens NETLINK_XFRM (AF_NETLINK family=6) via rustix. Issues XFRM_MSG_GETSA, XFRM_MSG_GETPOLICY NLM_F_DUMP requests and XFRM_MSG_GETSADINFO, XFRM_MSG_GETSPDINFO unicast queries using IORING_OP_SEND/RECV. Zero-copy parses xfrm_usersa_info and xfrm_userpolicy_info frames. No /proc reads (ADR-0025)." "Rust, rustix 1.1, linux-raw-sys 0.12, io-uring 0.7, zerocopy 0.8, bytemuck 1.25" {
                    tags "Component,DrivenAdapter"
                }
            }

            ipvsCollectorContainer = container "IPVS Collector" "Exports IPVS virtual service and real-server statistics (connections, packets, bytes, EMA rates) via generic netlink family 'IPVS'. Resolves IPVS family via CTRL_CMD_GETFAMILY; issues IPVS_CMD_GET_SERVICE dump and per-service IPVS_CMD_GET_DEST. Decodes IPVS_SVC_ATTR_STATS64 and IPVS_DEST_ATTR_STATS64 nested attributes. Runtime-gated: ENOENT on family resolution sets available=false. Produces IpvsSnapshot ReadModel. Default-enabled." "Rust, nlx-netlink; rustix 1.1, linux-raw-sys 0.12, io-uring 0.7; NETLINK_GENERIC IPVS family" {
                tags "Container,Collector,runtime-gated"

                ipvsCollector = component "IpvsCollector" "Concrete Strategy (GoF) in ipvs bounded context. Translates IpvsSnapshot into nft_ipvs_* Prometheus metric families. Emits nft_scrape_collector_available{collector=ipvs}. Enforces ipvs_max_services and ipvs_max_dests_per_service cardinality guards." "Rust" {
                    tags "Component,ConcreteStrategy"
                }

                ipvsAdapter = component "IpvsAdapter" "Driven adapter implementing NetlinkIpvsPort. Resolves IPVS genl family via CTRL_CMD_GETFAMILY (shared resolve_genl_family helper). Issues IPVS_CMD_GET_INFO, IPVS_CMD_GET_SERVICE, IPVS_CMD_GET_DEST over NETLINK_GENERIC using IORING_OP_SEND/RECV." "Rust, rustix 1.1, linux-raw-sys 0.12, io-uring 0.7" {
                    tags "Component,DrivenAdapter"
                }
            }

            wireguardCollectorContainer = container "WireGuard Collector" "Exports WireGuard device presence, listen port, fwmark, and per-peer RX/TX bytes and last-handshake age. Resolves wireguard genl family via CTRL_CMD_GETFAMILY; runtime-gated on ENOENT. Issues WG_CMD_GET_DEVICE NLM_F_DUMP; enumerates interfaces via RTM_GETLINK. Parses WGDEVICE_A_* and WGPEER_A_* attributes. Produces WireguardDevice ReadModel. Default-enabled." "Rust, nlx-netlink; rustix 1.1, linux-raw-sys 0.12, io-uring 0.7; NETLINK_GENERIC wireguard family" {
                tags "Container,Collector,runtime-gated"

                wireguardCollector = component "WireguardCollector" "Concrete Strategy (GoF) in wireguard bounded context. Resolves 'wireguard' family ID at startup via CTRL_CMD_GETFAMILY (OnceLock cached); runtime-gated on ENOENT. Issues WG_CMD_GET_DEVICE dump; produces WireguardDevice ReadModel." "Rust" {
                    tags "Component,ConcreteStrategy"
                }

                netlinkWireguardAdapter = component "NetlinkWireguardAdapter" "Driven adapter implementing NetlinkWireguardPort. Resolves wireguard family ID via CTRL_CMD_GETFAMILY (OnceLock<Option<u16>>). Issues WG_CMD_GET_DEVICE dump with NLM_F_DUMP_INTR restart semantics over NETLINK_GENERIC using IORING_OP_SEND/RECV." "Rust, rustix 1.1, linux-raw-sys 0.12, io-uring 0.7" {
                    tags "Component,DrivenAdapter"
                }
            }

            devlinkCollectorContainer = container "Devlink Collector" "Exports devlink device count, port counts per device, and health reporter state/error/recovery counters via generic netlink family 'devlink'. Runtime-gated: CTRL_CMD_GETFAMILY returning ENOENT on hosts without CONFIG_NET_DEVLINK sets collector_available=false. Produces DevlinkDevice ReadModel. Default-enabled." "Rust, nlx-netlink; rustix 1.1, linux-raw-sys 0.12, io-uring 0.7; NETLINK_GENERIC devlink family" {
                tags "Container,Collector,runtime-gated"

                devlinkCollector = component "DevlinkCollector" "Concrete Strategy (GoF) in Devlink bounded context. Issues DEVLINK_CMD_GET, DEVLINK_CMD_PORT_GET, DEVLINK_CMD_HEALTH_REPORTER_GET (cmd id 52) via NetlinkDevlinkPort. Runtime-gated on genl family resolution. Produces DevlinkDevice ReadModel." "Rust" {
                    tags "Component,ConcreteStrategy"
                }

                devlinkAdapter = component "DevlinkAdapter" "Driven adapter implementing NetlinkDevlinkPort. Resolves devlink genl family id via CTRL_CMD_GETFAMILY (OnceLock<u16> cached). Issues DEVLINK_CMD_GET, DEVLINK_CMD_PORT_GET NLM_F_DUMP and per-device DEVLINK_CMD_HEALTH_REPORTER_GET (id=52) over NETLINK_GENERIC using IORING_OP_SEND/RECV. ENOENT on family resolution sets collector_available=false." "Rust, rustix 1.1, linux-raw-sys 0.12, io-uring 0.7" {
                    tags "Component,DrivenAdapter"
                }
            }

            dropMonitorCollectorContainer = container "Drop-Monitor Collector" "Accumulates real SW/HW packet drop totals from the NET_DM multicast ALERT stream and pulls per-scrape monitor-overflow counts via NET_DM_CMD_STATS_GET. Background listener (setup_and_spawn_listener) subscribes to NET_DM_GRP_ALERT multicast and populates Arc<DropCounters> shared with DropMonitorCollector. Runtime-gated on CTRL_CMD_GETFAMILY ENOENT. Produces DropReasonCounter ReadModel. Default-enabled." "Rust, nlx-netlink; rustix 1.1, linux-raw-sys 0.12, io-uring 0.7; NETLINK_GENERIC NET_DM family" {
                tags "Container,Collector,runtime-gated"

                dropMonitorCollector = component "DropMonitorCollector" "Concrete Strategy (GoF) in DropMonitor bounded context. Issues NET_DM_CMD_STATS_GET per scrape via NetlinkDropMonitorPort. Reads Arc<DropCounters> populated by the background multicast listener. Produces DropReasonCounter ReadModel via nft_drop_monitor_* metric families." "Rust, arc-swap" {
                    tags "Component,ConcreteStrategy"
                }

                dropMonitorAdapter = component "DropMonitorAdapter" "Driven adapter implementing NetlinkDropMonitorPort. setup_and_spawn_listener resolves NET_DM family via CTRL_CMD_GETFAMILY; subscribes to NET_DM_GRP_ALERT multicast group before capability drop; decodes NET_DM_CMD_ALERT nlattr chains extracting NET_DM_ATTR_REASON, NET_DM_ATTR_HW_TRAP_NAME, NET_DM_ATTR_STATS_DROPPED u64 native-endian. Shares Arc<DropCounters> with the collector." "Rust, rustix 1.1, linux-raw-sys 0.12, io-uring 0.7, arc-swap" {
                    tags "Component,DrivenAdapter"
                }
            }

            rtnetlinkExtendedCollectorContainer = container "Rtnetlink Extended Collector" "Exports bridge multicast xstats, hardware offload bytes, bridge FDB entry counts, FIB policy-rule counts, and nexthop object count. Issues RTM_GETSTATS, RTM_GETNEIGH/AF_BRIDGE, RTM_GETRULE, RTM_GETNEXTHOP via NETLINK_ROUTE. Runtime-gated on kernel >= 4.20. Produces RtnetlinkExtendedSnapshot ReadModel. Default-enabled." "Rust, nlx-netlink; rustix 1.1, linux-raw-sys 0.12, io-uring 0.7; NETLINK_ROUTE RTM_GETSTATS" {
                tags "Container,Collector,runtime-gated"

                rtnetlinkExtendedCollector = component "RtnetlinkExtendedCollector" "Concrete Strategy (GoF) in rtnetlink-extended bounded context. Issues RTM_GETSTATS, RTM_GETNEIGH/AF_BRIDGE, RTM_GETRULE, and RTM_GETNEXTHOP via NetlinkRtExtendedPort. Availability probe on startup. Produces RtnetlinkExtendedSnapshot ReadModel." "Rust" {
                    tags "Component,ConcreteStrategy"
                }

                rtnetlinkExtendedAdapter = component "RtnetlinkExtendedAdapter" "Driven adapter implementing NetlinkRtExtendedPort. Opens NETLINK_ROUTE socket; issues RTM_GETSTATS (if_stats_msg body, filter_mask=0x0B), RTM_GETNEIGH (AF_BRIDGE), RTM_GETRULE (AF_INET/AF_INET6/AF_MPLS), RTM_GETNEXTHOP (nhmsg body) using IORING_OP_SEND/RECV. Decodes BRIDGE_XSTATS_MCAST, rtnl_hw_stats64, fib_rule_hdr, and nhmsg payloads." "Rust, rustix 1.1, linux-raw-sys 0.12, io-uring 0.7, zerocopy 0.8, bytemuck 1.25" {
                    tags "Component,DrivenAdapter"
                }
            }

            conntrackExpectationsCollectorContainer = container "Conntrack-Expectations Collector" "Counts active conntrack expectations via NETLINK_NETFILTER subsystem NFNL_SUBSYS_CTNETLINK_EXP (id=2). Issues IPCTNL_MSG_EXP_GET dump (nlmsg_type=0x0200). Degrades gracefully (available=false) when ENOENT or EPERM. Produces ConntrackExpectationSummary ReadModel aggregated by (l4proto, helper). Default-enabled." "Rust, nlx-netlink; rustix 1.1, linux-raw-sys 0.12, io-uring 0.7; NETLINK_NETFILTER NFNL_SUBSYS_CTNETLINK_EXP=2" {
                tags "Container,Collector"

                conntrackExpectationsCollector = component "ConntrackExpectationsCollector" "Concrete Strategy (GoF) in conntrack-expectations bounded context. Issues IPCTNL_MSG_EXP_GET dump via NetlinkConntrackExpectPort. Runtime-gates on ENOENT/EPERM. Produces ConntrackExpectationSummary ReadModel." "Rust" {
                    tags "Component,ConcreteStrategy"
                }

                conntrackExpectationsAggregator = component "ConntrackExpectationsAggregator" "Domain Service in conntrack-expectations bounded context. Groups raw expectation entries by (l4proto, helper) and counts them. Enforces the 256-key cardinality overflow guard. Pure domain logic with no kernel or infra dependency." "Rust" {
                    tags "Component,DomainService"
                }

                conntrackExpectationsAdapter = component "ConntrackExpectationsAdapter" "Driven adapter implementing NetlinkConntrackExpectPort. Issues IPCTNL_MSG_EXP_GET over NETLINK_NETFILTER (protocol=12, NFNL_SUBSYS_CTNETLINK_EXP=2) using IORING_OP_SEND/RECV. Maps ENOENT/EPERM to availability=false." "Rust, rustix 1.1, linux-raw-sys 0.12, io-uring 0.7, byteorder 1.5" {
                    tags "Component,DrivenAdapter"
                }
            }

            # ── Driven adapters: procfs/sysfs collectors (nlx-procfs) ────────
            # All 8 collectors default-off per ADR-0027. The ONLY crate permitted
            # to read /proc or /sys. safe_read() and safe_read_dir() enforce a
            # fixed path-prefix allowlist and reject .. traversal.

            softnetCollector = container "Softnet Collector (opt-in)" "Exports per-CPU softirq receive-path health: processed, dropped, time_squeeze, received_rps, flow_limit_count counters and current backlog queue length gauge. Source: /proc/net/softnet_stat. Default-disabled (ADR-0027)." "Rust, nlx-procfs; std::fs via safe_read() allowlist; /proc/net/softnet_stat" {
                tags "Container,Collector,procfs-collector"
            }

            netstatCollector = container "Netstat Collector (opt-in)" "Exports Linux IP/TCP/UDP/ICMP MIB counters (approx. 150 series) from the paired-line procfs format covering Ip, Tcp, Udp, UdpLite, Icmp, TcpExt, IpExt, MPTcpExt. Source: /proc/net/snmp + /proc/net/netstat. Default-disabled (ADR-0027)." "Rust, nlx-procfs; std::fs via safe_read() allowlist; /proc/net/snmp, /proc/net/netstat" {
                tags "Container,Collector,procfs-collector"
            }

            softirqCollector = container "Softirq Collector (opt-in)" "Emits per-CPU NET_RX and NET_TX softirq invocation counters, using the CPU id from the column header rather than line index to handle offline CPUs correctly. Source: /proc/softirqs. Default-disabled (ADR-0027)." "Rust, nlx-procfs; std::fs via safe_read() allowlist; /proc/softirqs" {
                tags "Container,Collector,procfs-collector"
            }

            irqCollector = container "IRQ Collector (opt-in)" "Emits per-hardware-IRQ total interrupt counts summed across all online CPUs, with device label extracted from the action-name column. Source: /proc/interrupts. Default-disabled (ADR-0027)." "Rust, nlx-procfs; std::fs via safe_read() allowlist; /proc/interrupts" {
                tags "Container,Collector,procfs-collector"
            }

            sockstatCollector = container "Sockstat Collector (opt-in)" "Snapshots per-protocol socket allocation counts (inuse, orphan, TIME_WAIT, alloc, mem, fragment queue) from the procfs key-value paired-line format. Source: /proc/net/sockstat. Default-disabled (ADR-0027)." "Rust, nlx-procfs; std::fs via safe_read() allowlist; /proc/net/sockstat" {
                tags "Container,Collector,procfs-collector"
            }

            nicBqlCollector = container "NIC BQL Collector (opt-in)" "Aggregates Byte Queue Limits TX limit and inflight bytes across all TX queues per device to expose bufferbloat pressure without per-queue cardinality explosion. Source: /sys/class/net/<dev>/queues/tx-<N>/byte_queue_limits/limit + inflight. Default-disabled (ADR-0027)." "Rust, nlx-procfs; std::fs via safe_read() allowlist; /sys/class/net/" {
                tags "Container,Collector,procfs-collector"
            }

            nicPcieCollector = container "NIC PCIe Collector (opt-in)" "Exports PCIe link speed (GT/s), link width (lanes), and per-bit AER correctable/fatal/nonfatal error counters for physical-function NICs, skipping SR-IOV VFs. Source: /sys/class/net/<dev>/device/current_link_speed + current_link_width + aer_dev_*. Default-disabled (ADR-0027)." "Rust, nlx-procfs; std::fs via safe_read() allowlist; /sys/class/net/, /sys/bus/pci/devices/" {
                tags "Container,Collector,procfs-collector"
            }

            nicTempCollector = container "NIC Temp Collector (opt-in)" "Reads NIC hardware temperatures (millidegrees Celsius converted to Celsius) from the hwmon sysfs interface, labelling by chip name and sensor index. Source: /sys/class/net/<dev>/device/hwmon/hwmon<K>/temp<N>_input. Default-disabled (ADR-0027)." "Rust, nlx-procfs; std::fs via safe_read() allowlist; /sys/class/net/ hwmon" {
                tags "Container,Collector,procfs-collector"
            }

            # ── Inter-container relationships ────────────────────────────────

            # HTTP adapter drives the composition root ports
            httpExposition -> netlinkExporter "Triggers scrape via ScrapeTriggerPort::scrape (async fn)" "ScrapeTriggerPort"
            httpExposition -> netlinkExporter "Checks liveness via HealthPort::is_healthy" "HealthPort"
            httpExposition -> netlinkExporter "Checks readiness via ReadinessPort::is_ready" "ReadinessPort"

            # Composition root reads config
            netlinkExporter -> nlxConfig "Calls load_config(CliArgs) at startup; reads collector_enabled() flags to build CollectorRegistry" "direct function call"

            # Composition root drives each netlink collector (via Collector trait, monoio JoinHandle)
            netlinkExporter -> rtnetlinkCollectorContainer "Fans out scrape via Collector trait (monoio JoinHandle, timeout scrape_timeout_ms)" "Collector Strategy"
            netlinkExporter -> tcCollectorContainer "Fans out scrape via Collector trait (monoio JoinHandle, timeout scrape_timeout_ms)" "Collector Strategy"
            netlinkExporter -> conntrackCollectorContainer "Fans out scrape via Collector trait (monoio JoinHandle, timeout scrape_timeout_ms)" "Collector Strategy"
            netlinkExporter -> nftablesCollectorContainer "Fans out scrape via Collector trait (monoio JoinHandle, timeout scrape_timeout_ms)" "Collector Strategy"
            netlinkExporter -> sockDiagCollectorContainer "Fans out scrape via Collector trait (monoio JoinHandle, timeout scrape_timeout_ms)" "Collector Strategy"
            netlinkExporter -> ethtoolCollectorContainer "Fans out scrape via Collector trait (monoio JoinHandle, timeout scrape_timeout_ms)" "Collector Strategy"
            netlinkExporter -> xfrmIpsecCollectorContainer "Fans out scrape via Collector trait (monoio JoinHandle, timeout scrape_timeout_ms)" "Collector Strategy"
            netlinkExporter -> ipvsCollectorContainer "Fans out scrape via Collector trait (monoio JoinHandle, timeout scrape_timeout_ms)" "Collector Strategy"
            netlinkExporter -> wireguardCollectorContainer "Fans out scrape via Collector trait (monoio JoinHandle, timeout scrape_timeout_ms)" "Collector Strategy"
            netlinkExporter -> devlinkCollectorContainer "Fans out scrape via Collector trait (monoio JoinHandle, timeout scrape_timeout_ms)" "Collector Strategy"
            netlinkExporter -> dropMonitorCollectorContainer "Fans out scrape via Collector trait (monoio JoinHandle, timeout scrape_timeout_ms)" "Collector Strategy"
            netlinkExporter -> rtnetlinkExtendedCollectorContainer "Fans out scrape via Collector trait (monoio JoinHandle, timeout scrape_timeout_ms)" "Collector Strategy"
            netlinkExporter -> conntrackExpectationsCollectorContainer "Fans out scrape via Collector trait (monoio JoinHandle, timeout scrape_timeout_ms)" "Collector Strategy"

            # Composition root drives each procfs collector (default-off, same Collector trait)
            netlinkExporter -> softnetCollector "Fans out scrape via Collector trait when enabled (default-off, ADR-0027)" "Collector Strategy"
            netlinkExporter -> netstatCollector "Fans out scrape via Collector trait when enabled (default-off, ADR-0027)" "Collector Strategy"
            netlinkExporter -> softirqCollector "Fans out scrape via Collector trait when enabled (default-off, ADR-0027)" "Collector Strategy"
            netlinkExporter -> irqCollector "Fans out scrape via Collector trait when enabled (default-off, ADR-0027)" "Collector Strategy"
            netlinkExporter -> sockstatCollector "Fans out scrape via Collector trait when enabled (default-off, ADR-0027)" "Collector Strategy"
            netlinkExporter -> nicBqlCollector "Fans out scrape via Collector trait when enabled (default-off, ADR-0027)" "Collector Strategy"
            netlinkExporter -> nicPcieCollector "Fans out scrape via Collector trait when enabled (default-off, ADR-0027)" "Collector Strategy"
            netlinkExporter -> nicTempCollector "Fans out scrape via Collector trait when enabled (default-off, ADR-0027)" "Collector Strategy"

            # Composition root publishes samples to metric registry
            netlinkExporter -> metricRegistry "Publishes Vec<MetricSample> via MetricRegistryPort::update_samples (atomic ArcSwap store)" "MetricRegistryPort"

            # Collectors return ReadModels (used by ScrapeService fan-out)
            rtnetlinkCollectorContainer -> metricRegistry "Returns LinkReadModel, AddressReadModel, RouteReadModel, NeighborReadModel" "ReadModel"
            tcCollectorContainer -> metricRegistry "Returns TcQdisc ReadModel" "ReadModel"
            conntrackCollectorContainer -> metricRegistry "Returns ConntrackSummary ReadModel" "ReadModel"
            nftablesCollectorContainer -> metricRegistry "Returns NftCounterSnapshot ReadModel" "ReadModel"
            sockDiagCollectorContainer -> metricRegistry "Returns SocketStateHistogram ReadModel" "ReadModel"
            ethtoolCollectorContainer -> metricRegistry "Returns NicStatSnapshot ReadModel" "ReadModel"
            xfrmIpsecCollectorContainer -> metricRegistry "Returns XfrmSnapshot ReadModel" "ReadModel"
            ipvsCollectorContainer -> metricRegistry "Returns IpvsSnapshot ReadModel" "ReadModel"
            wireguardCollectorContainer -> metricRegistry "Returns WireguardDevice ReadModel" "ReadModel"
            devlinkCollectorContainer -> metricRegistry "Returns DevlinkDevice ReadModel" "ReadModel"
            dropMonitorCollectorContainer -> metricRegistry "Returns DropReasonCounter ReadModel" "ReadModel"
            rtnetlinkExtendedCollectorContainer -> metricRegistry "Returns RtnetlinkExtendedSnapshot ReadModel" "ReadModel"
            conntrackExpectationsCollectorContainer -> metricRegistry "Returns ConntrackExpectationSummary ReadModel" "ReadModel"
            softnetCollector -> metricRegistry "Returns softnet Vec<MetricSample> when enabled" "ReadModel"
            netstatCollector -> metricRegistry "Returns netstat Vec<MetricSample> when enabled" "ReadModel"
            softirqCollector -> metricRegistry "Returns softirq Vec<MetricSample> when enabled" "ReadModel"
            irqCollector -> metricRegistry "Returns irq Vec<MetricSample> when enabled" "ReadModel"
            sockstatCollector -> metricRegistry "Returns sockstat Vec<MetricSample> when enabled" "ReadModel"
            nicBqlCollector -> metricRegistry "Returns nic_bql Vec<MetricSample> when enabled" "ReadModel"
            nicPcieCollector -> metricRegistry "Returns nic_pcie Vec<MetricSample> when enabled" "ReadModel"
            nicTempCollector -> metricRegistry "Returns nic_temp Vec<MetricSample> when enabled" "ReadModel"

            # HTTP exposition reads encoded body from registry
            httpExposition -> metricRegistry "Reads Prometheus text 0.0.4 body via MetricRegistryPort::encode_text (wait-free ArcSwap load)" "MetricRegistryPort::encode_text"

            # Netlink adapters talk to the kernel via io_uring (ADR-0024)
            rtnetlinkCollectorContainer -> linuxKernel "RTM_GETLINK, RTM_GETADDR, RTM_GETROUTE, RTM_GETNEIGH via NETLINK_ROUTE; IORING_OP_SEND/RECV" "NETLINK_ROUTE"
            tcCollectorContainer -> linuxKernel "RTM_GETQDISC, RTM_GETLINK via NETLINK_ROUTE; IORING_OP_SEND/RECV" "NETLINK_ROUTE"
            conntrackCollectorContainer -> linuxKernel "IPCTNL_MSG_CT_GET_STATS_CPU, IPCTNL_MSG_CT_GET_STATS, IPCTNL_MSG_CT_GET via NETLINK_NETFILTER; IORING_OP_SEND/RECV" "NETLINK_NETFILTER (ctnetlink)"
            nftablesCollectorContainer -> linuxKernel "NFT_MSG_GETTABLE, NFT_MSG_GETCHAIN, NFT_MSG_GETRULE, NFT_MSG_GETOBJ via NETLINK_NETFILTER; IORING_OP_SEND/RECV" "NETLINK_NETFILTER (nfnetlink)"
            sockDiagCollectorContainer -> linuxKernel "SOCK_DIAG_BY_FAMILY AF_INET/AF_INET6 via NETLINK_SOCK_DIAG; IORING_OP_SEND/RECV" "NETLINK_SOCK_DIAG"
            ethtoolCollectorContainer -> linuxKernel "ETHTOOL_MSG_STATS_GET via NETLINK_GENERIC (ethtool family); IORING_OP_SEND/RECV" "NETLINK_GENERIC (ethtool)"
            xfrmIpsecCollectorContainer -> linuxKernel "XFRM_MSG_GETSA, XFRM_MSG_GETPOLICY, XFRM_MSG_GETSADINFO, XFRM_MSG_GETSPDINFO via NETLINK_XFRM; IORING_OP_SEND/RECV; no /proc" "NETLINK_XFRM"
            ipvsCollectorContainer -> linuxKernel "IPVS_CMD_GET_SERVICE, IPVS_CMD_GET_DEST via NETLINK_GENERIC (IPVS family); IORING_OP_SEND/RECV" "NETLINK_GENERIC (IPVS)"
            wireguardCollectorContainer -> linuxKernel "WG_CMD_GET_DEVICE via NETLINK_GENERIC (wireguard family); IORING_OP_SEND/RECV" "NETLINK_GENERIC (wireguard)"
            devlinkCollectorContainer -> linuxKernel "DEVLINK_CMD_GET, DEVLINK_CMD_PORT_GET, DEVLINK_CMD_HEALTH_REPORTER_GET via NETLINK_GENERIC (devlink family); IORING_OP_SEND/RECV" "NETLINK_GENERIC (devlink)"
            dropMonitorCollectorContainer -> linuxKernel "NET_DM_CMD_STATS_GET + NET_DM_GRP_ALERT multicast stream via NETLINK_GENERIC (NET_DM); background listener" "NETLINK_GENERIC (NET_DM)"
            rtnetlinkExtendedCollectorContainer -> linuxKernel "RTM_GETSTATS, RTM_GETNEIGH/AF_BRIDGE, RTM_GETRULE, RTM_GETNEXTHOP via NETLINK_ROUTE; IORING_OP_SEND/RECV" "NETLINK_ROUTE"
            conntrackExpectationsCollectorContainer -> linuxKernel "IPCTNL_MSG_EXP_GET via NETLINK_NETFILTER (NFNL_SUBSYS_CTNETLINK_EXP=2); IORING_OP_SEND/RECV" "NETLINK_NETFILTER (ctnetlink-exp)"

            # Procfs/sysfs collectors talk to kernel via /proc and /sys (ADR-0027 allowlist)
            softnetCollector -> linuxKernel "safe_read /proc/net/softnet_stat via allowlist" "procfs"
            netstatCollector -> linuxKernel "safe_read /proc/net/snmp + /proc/net/netstat via allowlist" "procfs"
            softirqCollector -> linuxKernel "safe_read /proc/softirqs via allowlist" "procfs"
            irqCollector -> linuxKernel "safe_read /proc/interrupts via allowlist" "procfs"
            sockstatCollector -> linuxKernel "safe_read /proc/net/sockstat via allowlist" "procfs"
            nicBqlCollector -> linuxKernel "safe_read /sys/class/net/<dev>/queues/tx-<N>/byte_queue_limits/ via allowlist" "sysfs"
            nicPcieCollector -> linuxKernel "safe_read /sys/class/net/<dev>/device/ PCIe attrs + /sys/bus/pci/devices/ via allowlist" "sysfs"
            nicTempCollector -> linuxKernel "safe_read /sys/class/net/<dev>/device/hwmon/ via allowlist" "sysfs"

            # Domain dependency edges
            rtnetlinkCollectorContainer -> nlxDomain "Parses raw nlattr TLVs into LinkReadModel, AddressReadModel, RouteReadModel, NeighborReadModel" "zerocopy/bytemuck zero-copy struct cast"
            tcCollectorContainer -> nlxDomain "Parses TCA_STATS2 into TcQdisc ReadModel" "zerocopy/bytemuck"
            conntrackCollectorContainer -> nlxDomain "Parses ctattr TLVs into ConntrackFlow domain values" "zerocopy/bytemuck"
            nftablesCollectorContainer -> nlxDomain "Parses nfnetlink nfattr into NftCounterSnapshot" "zerocopy/bytemuck"
            sockDiagCollectorContainer -> nlxDomain "Parses inet_diag_msg into SocketStateHistogram" "zerocopy/bytemuck"
            ethtoolCollectorContainer -> nlxDomain "Parses ethtool STATS_GET bitset into NicStatSnapshot" "zerocopy/bytemuck"
            xfrmIpsecCollectorContainer -> nlxDomain "Parses xfrm_usersa_info into XfrmSnapshot" "zerocopy/bytemuck"
            ipvsCollectorContainer -> nlxDomain "Parses IPVS_SVC_ATTR_STATS64 into IpvsSnapshot" "zerocopy/bytemuck"
            wireguardCollectorContainer -> nlxDomain "Parses WGDEVICE_A_* attrs into WireguardDevice ReadModel" "zerocopy/bytemuck"
            devlinkCollectorContainer -> nlxDomain "Parses devlink attrs into DevlinkDevice ReadModel" "zerocopy/bytemuck"
            dropMonitorCollectorContainer -> nlxDomain "Accumulates NET_DM_ATTR_REASON into DropReasonCounter ReadModel" "arc-swap Arc<DropCounters>"
            rtnetlinkExtendedCollectorContainer -> nlxDomain "Parses BRIDGE_XSTATS_MCAST, rtnl_hw_stats64 into RtnetlinkExtendedSnapshot" "zerocopy/bytemuck"
            conntrackExpectationsCollectorContainer -> nlxDomain "Parses ctattr EXP TLVs into ConntrackExpectationSummary" "zerocopy/bytemuck"

            # Ports dependency edges
            rtnetlinkCollectorContainer -> nlxPorts "Implements Collector strategy trait; NetlinkRtPort" "trait impl"
            tcCollectorContainer -> nlxPorts "Implements Collector strategy trait; NetlinkTcPort" "trait impl"
            conntrackCollectorContainer -> nlxPorts "Implements Collector strategy trait; NetlinkConntrackPort" "trait impl"
            nftablesCollectorContainer -> nlxPorts "Implements Collector strategy trait; NetlinkNftablesPort" "trait impl"
            sockDiagCollectorContainer -> nlxPorts "Implements Collector strategy trait; NetlinkSockDiagPort" "trait impl"
            ethtoolCollectorContainer -> nlxPorts "Implements Collector strategy trait; NetlinkEthtoolPort" "trait impl"
            xfrmIpsecCollectorContainer -> nlxPorts "Implements Collector strategy trait; NetlinkXfrmPort" "trait impl"
            ipvsCollectorContainer -> nlxPorts "Implements Collector strategy trait; NetlinkIpvsPort" "trait impl"
            wireguardCollectorContainer -> nlxPorts "Implements Collector strategy trait; NetlinkWireguardPort" "trait impl"
            devlinkCollectorContainer -> nlxPorts "Implements Collector strategy trait; NetlinkDevlinkPort" "trait impl"
            dropMonitorCollectorContainer -> nlxPorts "Implements Collector strategy trait; NetlinkDropMonitorPort" "trait impl"
            rtnetlinkExtendedCollectorContainer -> nlxPorts "Implements Collector strategy trait; NetlinkRtExtendedPort" "trait impl"
            conntrackExpectationsCollectorContainer -> nlxPorts "Implements Collector strategy trait; NetlinkConntrackExpectPort" "trait impl"
            softnetCollector -> nlxPorts "Implements Collector strategy trait (procfs path; std::fs)" "trait impl"
            netstatCollector -> nlxPorts "Implements Collector strategy trait (procfs path; std::fs)" "trait impl"
            softirqCollector -> nlxPorts "Implements Collector strategy trait (procfs path; std::fs)" "trait impl"
            irqCollector -> nlxPorts "Implements Collector strategy trait (procfs path; std::fs)" "trait impl"
            sockstatCollector -> nlxPorts "Implements Collector strategy trait (procfs path; std::fs)" "trait impl"
            nicBqlCollector -> nlxPorts "Implements Collector strategy trait (sysfs path; std::fs)" "trait impl"
            nicPcieCollector -> nlxPorts "Implements Collector strategy trait (sysfs path; std::fs)" "trait impl"
            nicTempCollector -> nlxPorts "Implements Collector strategy trait (sysfs path; std::fs)" "trait impl"
            metricRegistry -> nlxPorts "Implements MetricRegistryPort (update_samples + encode_text)" "trait impl"
            nlxConfig -> nlxPorts "Implements ConfigPort (scrape_timeout_ms, listen_addr, collector_enabled)" "trait impl"
            httpExposition -> nlxPorts "Calls ScrapeTriggerPort, HealthPort, ReadinessPort via Arc<dyn Trait>" "AFIT trait method calls"
        }

        # ── System-level relationships ───────────────────────────────────────
        prometheusServer -> nftExporter "Scrapes GET /metrics on port 9456 (Prometheus text 0.0.4)" "HTTP/OpenMetrics"
        prometheusServer -> alertmanager "Sends firing alerts" "HTTP"
        grafana -> prometheusServer "Queries metric time series" "PromQL/HTTP"

        # Prometheus calls the HTTP exposition directly (container level)
        prometheusServer -> httpExposition "GET /metrics port 9456" "HTTP/OpenMetrics"
    }

    views {

        # ── System Context view ─────────────────────────────────────────────
        systemContext nftExporter "SystemContext" {
            title "nft_exporter — System Context (monoio io_uring runtime, 13 netlink + 8 procfs collectors)"
            include *
            autolayout tb
        }

        # ── Container view ──────────────────────────────────────────────────
        container nftExporter "Containers" {
            title "nft_exporter — Container view (hexagonal layers; nlx-* crates)"
            include *
            autolayout tb
        }

        # ── Component view: Composition Root / Binary ───────────────────────
        component netlinkExporter "Components_CompositionRoot" {
            title "nft_exporter — Composition Root components (Facade + Template Method + Abstract Factory)"
            include *
            autolayout lr
        }

        # ── Component view: HTTP Exposition ─────────────────────────────────
        component httpExposition "Components_HttpExposition" {
            title "nft_exporter — HTTP Exposition components (monoio hand-rolled HTTP/1 driving adapter)"
            include *
            autolayout lr
        }

        # ── Component view: Conntrack Collector (richest internal structure) ─
        component conntrackCollectorContainer "Components_Conntrack" {
            title "nft_exporter — Conntrack Collector components (Strategy + Domain Service + Driven Adapter)"
            include *
            autolayout lr
        }

        # ── Component view: Metric Registry ─────────────────────────────────
        component metricRegistry "Components_MetricRegistry" {
            title "nft_exporter — Metric Registry components (hand-rolled Prometheus encoder, ArcSwap RCU)"
            include *
            autolayout lr
        }

        # ── Component view: Nftables Collector ──────────────────────────────
        component nftablesCollectorContainer "Components_Nftables" {
            title "nft_exporter — Nftables Collector components (Strategy + Driven Adapter, no rustables)"
            include *
            autolayout lr
        }

        # ── Component view: nlx-config ──────────────────────────────────────
        component nlxConfig "Components_Config" {
            title "nft_exporter — Config adapter components (NLX_ prefix, figment layered providers)"
            include *
            autolayout lr
        }

        # ── Styles ──────────────────────────────────────────────────────────
        styles {
            element "Person" {
                shape Person
                background #1168bd
                color #ffffff
            }

            element "External" {
                background #999999
                color #ffffff
            }

            element "Container" {
                background #438dd5
                color #ffffff
            }

            element "DrivingAdapter" {
                background #2e7d32
                color #ffffff
            }

            element "DrivenAdapter" {
                background #6a1b9a
                color #ffffff
            }

            element "DomainCore" {
                background #e65100
                color #ffffff
            }

            element "Collector" {
                background #00695c
                color #ffffff
            }

            element "procfs-collector" {
                background #33691e
                color #ffffff
            }

            element "Component" {
                background #85bbf0
                color #000000
            }

            element "ConcreteStrategy" {
                background #00897b
                color #ffffff
            }

            element "TemplateMethod" {
                background #e65100
                color #ffffff
            }

            element "AbstractFactory" {
                background #bf360c
                color #ffffff
            }

            element "Facade" {
                background #4527a0
                color #ffffff
            }

            element "DomainService" {
                background #f57f17
                color #000000
            }

            element "Composite" {
                background #6a1b9a
                color #ffffff
            }

            relationship "ScrapeTriggerPort" {
                color #2e7d32
                dashed false
            }

            relationship "HealthPort" {
                color #2e7d32
                dashed true
            }

            relationship "ReadinessPort" {
                color #2e7d32
                dashed true
            }

            relationship "MetricRegistryPort" {
                color #6a1b9a
                dashed false
            }

            relationship "NETLINK_ROUTE" {
                color #1565c0
            }

            relationship "NETLINK_NETFILTER (ctnetlink)" {
                color #880e4f
            }

            relationship "NETLINK_NETFILTER (nfnetlink)" {
                color #880e4f
            }

            relationship "NETLINK_NETFILTER (ctnetlink-exp)" {
                color #880e4f
            }

            relationship "NETLINK_SOCK_DIAG" {
                color #4a148c
            }

            relationship "NETLINK_GENERIC (ethtool)" {
                color #1b5e20
            }

            relationship "NETLINK_GENERIC (IPVS)" {
                color #1b5e20
            }

            relationship "NETLINK_GENERIC (wireguard)" {
                color #1b5e20
            }

            relationship "NETLINK_GENERIC (devlink)" {
                color #1b5e20
            }

            relationship "NETLINK_GENERIC (NET_DM)" {
                color #1b5e20
            }

            relationship "NETLINK_XFRM" {
                color #4a148c
            }

            relationship "procfs" {
                color #33691e
                dashed true
            }

            relationship "sysfs" {
                color #558b2f
                dashed true
            }

            relationship "Collector Strategy" {
                color #00695c
            }

            relationship "ReadModel" {
                color #00897b
                dashed true
            }
        }

        theme default
    }
}
