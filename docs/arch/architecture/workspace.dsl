workspace "nft_exporter" "C4 architecture model for nft_exporter — a Rust 2024-edition static-musl Linux netlink Prometheus exporter." {

    # DRIFT NOTE (2026-05-29): this C4 model predates the ADR-0023 runtime rewrite
    # and is materially out of sync with the implementation. Known divergences to
    # fix in a dedicated refresh: runtime is monoio + io_uring (NOT tokio/JoinSet);
    # HTTP is a hand-rolled monoio HTTP/1 server (NOT axum); netlink uses the
    # direct wire protocol with NO high-level crates (rustables/rtnetlink/ethtool/
    # netlink-packet-* are gone); config env prefix is NLX_ (NOT NFT_EXPORTER_);
    # there are 13 native collectors + 8 opt-in procfs/sysfs collectors (nlx-procfs,
    # ADR-0027: softnet, netstat, softirq, irq, sockstat, nic_bql, nic_pcie,
    # nic_temp) — NOT "six". The authoritative, in-sync artifacts are the ADRs and
    # docs/arch/schemas/metric_contract.cue (cue-vet clean).

    model {

        # ── External actors ─────────────────────────────────────────────────
        prometheusServer = person "Prometheus Server" "Scrapes GET /metrics on port 9456 at configurable scrape_interval. Prometheus Operator ServiceMonitor manages target discovery in Kubernetes." "External,Monitoring"

        alertmanager = softwareSystem "Alertmanager" "Receives alerts fired from Prometheus alerting rules against nft_* metric families." "External,Monitoring" {
            tags "External"
        }

        grafana = softwareSystem "Grafana" "Queries Prometheus for dashboards visualising nft_link_*, nft_tc_*, nft_conntrack_*, nft_rule_*, nft_socket_*, and nft_ethtool_* metric families." "External,Monitoring" {
            tags "External"
        }

        linuxKernel = softwareSystem "Linux Kernel Netlink" "Exposes NETLINK_ROUTE, NETLINK_NETFILTER (ctnetlink + nfnetlink), NETLINK_SOCK_DIAG, and NETLINK_GENERIC (ethtool) socket families. Sole source of truth for all collected metrics. Requires kernel >= 5.12, nf_conntrack module loaded, and nftables active." "External,Infrastructure" {
            tags "External"
        }

        # ── Primary software system ──────────────────────────────────────────
        nftExporter = softwareSystem "nft_exporter" "Single statically-linked musl binary. Reads six Linux kernel netlink/genetlink API families, aggregates kernel state into bounded-cardinality metric families, and exposes them as OpenMetrics text on HTTP port 9456. Runs as a Kubernetes DaemonSet (hostNetwork:true) or systemd service on each Linux node. Requires CAP_NET_ADMIN only." {

            # ── Containers ──────────────────────────────────────────────────

            httpExposition = container "HTTP Exposition Layer" "Serves /metrics (OpenMetrics text), /healthz (liveness), and /ready (readiness) over HTTP on port 9456. Implements ScrapeTriggerPort, HealthPort, and ReadinessPort driving ports." "Rust, axum 0.8, port 9456" {
                tags "Container,DrivingAdapter"

                # Components inside HTTP Exposition
                axumHttpAdapter = component "AxumHttpAdapter" "Driving adapter (Exposition bounded context). axum 0.8 Router with three routes: GET /metrics calls ScrapeTriggerPort, GET /healthz calls HealthPort, GET /ready calls ReadinessPort. Binds to 0.0.0.0:9456." "Rust, axum 0.8" {
                    tags "Component,DrivingAdapter"
                }

                exporterApp = component "ExporterApp" "Facade (GoF) application entry point. Wires all ports and adapters, opens netlink sockets, drops capabilities via caps crate, starts tokio runtime and axum server. Sole entry point of the binary." "Rust, main.rs" {
                    tags "Component,Facade"
                }

                envConfigAdapter = component "EnvConfigAdapter" "Infrastructure adapter implementing ConfigPort. Parses NFT_EXPORTER_* environment variables and CLI flags (clap 4.x) into ExporterConfig value objects." "Rust, clap 4.x, config-rs" {
                    tags "Component,DrivenAdapter"
                }

                systemdNotifyAdapter = component "SystemdNotifyAdapter" "Infrastructure adapter implementing NotifyPort. Sends sd_notify READY=1 and WATCHDOG=1 signals to systemd watchdog on successful startup and health-check intervals." "Rust, libsystemd" {
                    tags "Component,DrivenAdapter"
                }
            }

            collectionOrchestrator = container "Collection Orchestrator" "Coordinates the scrape lifecycle across all six subsystem collectors. Fans out concurrent collection via tokio::task::JoinSet, enforces per-subsystem timeout budgets (default 9800 ms), applies catch-unwind stale-snapshot policy on collector panic, and records scrape telemetry." "Rust, tokio 1.52, JoinSet" {
                tags "Container,DomainCore"

                # Components inside Collection Orchestrator
                scrapeLifecycle = component "ScrapeLifecycle" "Template Method (GoF) in CollectionOrchestration bounded context. Enforces the invariant async scrape sequence: pre_scrape_hook -> collect_all -> post_process -> publish -> post_scrape_hook. Records nft_scrape_collector_success and nft_scrape_collector_error_total." "Rust, tokio::task::JoinSet" {
                    tags "Component,TemplateMethod"
                }

                collectorRegistry = component "CollectorRegistry" "Abstract Factory (GoF) in CollectionOrchestration bounded context. Instantiates and holds enabled Collector strategy instances based on ExporterConfig. New subsystem requires only a new concrete strategy registered here." "Rust" {
                    tags "Component,AbstractFactory"
                }
            }

            rtnetlinkCollectorContainer = container "Rtnetlink Collector" "Collects Linux network-interface state (links, IP addresses, routing tables, ARP/NDP neighbor tables) by issuing RTM_GETLINK, RTM_GETADDR, RTM_GETROUTE, and RTM_GETNEIGH netlink requests. Produces LinkSnapshot, AddressSnapshot, RouteTableSnapshot, and NeighborSnapshot ReadModels." "Rust, rtnetlink 0.21, netlink-packet-route 0.30" {
                tags "Container,Collector"

                rtnetlinkCollector = component "RtnetlinkCollector" "Concrete Strategy (GoF) in Rtnetlink bounded context. Issues RTM_GETLINK, RTM_GETADDR, RTM_GETROUTE, RTM_GETNEIGH via NetlinkRtPort. Produces LinkSnapshot, AddressSnapshot, RouteTableSnapshot, NeighborSnapshot ReadModels." "Rust" {
                    tags "Component,ConcreteStrategy"
                }

                rtnetlinkAdapter = component "RtnetlinkAdapter" "Driven adapter implementing NetlinkRtPort. Opens NETLINK_ROUTE socket; issues RTM_GET* dump requests; streams RTM_NEW* reply messages as typed domain values." "Rust, rtnetlink 0.21, nft_exporter_adapter_rt" {
                    tags "Component,DrivenAdapter"
                }
            }

            tcCollectorContainer = container "Traffic Control Collector" "Collects Linux TC qdisc, class, and filter statistics by issuing RTM_GETQDISC, RTM_GETTCLASS, and RTM_GETTFILTER netlink requests with TCA_STATS2 attribute decoding. Produces TcTreeSnapshot ReadModel." "Rust, rtnetlink 0.21, netlink-packet-route 0.30" {
                tags "Container,Collector"

                tcCollector = component "TcCollector" "Concrete Strategy (GoF) in TrafficControl bounded context. Issues RTM_GETQDISC, RTM_GETTCLASS, RTM_GETTFILTER via NetlinkTcPort. Decodes TCA_STATS2 attributes. Produces TcTreeSnapshot ReadModel." "Rust" {
                    tags "Component,ConcreteStrategy"
                }

                tcNetlinkAdapter = component "TcNetlinkAdapter" "Driven adapter implementing NetlinkTcPort. Issues RTM_GETQDISC, RTM_GETTCLASS, RTM_GETTFILTER over NETLINK_ROUTE; decodes TCA_STATS2 (gnet_stats_basic, gnet_stats_queue) attributes." "Rust, nft_exporter_adapter_tc" {
                    tags "Component,DrivenAdapter"
                }
            }

            conntrackCollectorContainer = container "Conntrack Collector" "Collects Linux connection-tracking state from ctnetlink NFNL_SUBSYS_CTNETLINK. Aggregates individual flow entries by (protocol, state, direction) into bounded cardinality summaries. Produces ConntrackSummary ReadModel." "Rust, netlink-packet-netfilter 0.2 (vendored), netlink-packet-core 0.8.1" {
                tags "Container,Collector"

                conntrackCollector = component "ConntrackCollector" "Concrete Strategy (GoF) in Conntrack bounded context. Issues IPCTNL_MSG_CT_GET full dump and IPCTNL_MSG_CT_GET_STATS_CPU via NetlinkConntrackPort. Produces ConntrackSummary ReadModel." "Rust" {
                    tags "Component,ConcreteStrategy"
                }

                conntrackAggregator = component "ConntrackAggregator" "Domain Service in Conntrack bounded context. Groups raw ConntrackFlow entries by (protocol, state, direction) and sums byte/packet counters. Pure domain logic with no kernel or infra dependency." "Rust" {
                    tags "Component,DomainService"
                }

                conntrackAdapter = component "ConntrackAdapter" "Driven adapter implementing NetlinkConntrackPort. Issues IPCTNL_MSG_CT_GET and IPCTNL_MSG_CT_GET_STATS_CPU over NETLINK_NETFILTER; receives ctattr-encoded nfgenmsg replies. Uses vendored netlink-packet-netfilter 0.2 with patched IPCTNL_MSG_CT_GET_STATS_CPU codec." "Rust, nft_exporter_adapter_ct" {
                    tags "Component,DrivenAdapter"
                }
            }

            nftablesCollectorContainer = container "Nftables Collector" "Collects nftables rule counters, named counter objects, set element counts, chain metadata, and table metadata via nfnetlink NFNL_SUBSYS_NFTABLES. Produces NftCounterSnapshot ReadModel." "Rust, rustables 0.8.7, NETLINK_NETFILTER" {
                tags "Container,Collector"

                nftablesCollector = component "NftablesCollector" "Concrete Strategy (GoF) in Nftables bounded context. Issues NFT_MSG_GETRULE, NFT_MSG_GETCOUNTER, NFT_MSG_GETSET, NFT_MSG_GETCHAIN, NFT_MSG_GETTABLE via NetlinkNftablesPort. Enforces cardinality overflow guard on anonymous rules. Produces NftCounterSnapshot ReadModel." "Rust" {
                    tags "Component,ConcreteStrategy"
                }

                nftablesAdapter = component "NftablesAdapter" "Driven adapter implementing NetlinkNftablesPort. Issues NFT_MSG_GET* requests over NETLINK_NETFILTER NFNL_SUBSYS_NFTABLES; returns typed counter and metadata values. Wraps rustables 0.8." "Rust, rustables 0.8, nft_exporter_adapter_nft" {
                    tags "Component,DrivenAdapter"
                }
            }

            sockDiagCollectorContainer = container "SockDiag Collector" "Collects TCP, UDP, and UDPLite socket state distributions via SOCK_DIAG_BY_FAMILY (AF_INET, AF_INET6). Aggregates socket counts, queue bytes, and memory by (protocol, state). Produces SocketStateHistogram ReadModel." "Rust, netlink-packet-sock-diag 0.4.2" {
                tags "Container,Collector"

                sockDiagCollector = component "SockDiagCollector" "Concrete Strategy (GoF) in SockDiag bounded context. Issues SOCK_DIAG_BY_FAMILY for AF_INET and AF_INET6 via NetlinkSockDiagPort. Aggregates socket counts and queue bytes by (protocol, state). Produces SocketStateHistogram ReadModel." "Rust" {
                    tags "Component,ConcreteStrategy"
                }

                sockDiagAdapter = component "SockDiagAdapter" "Driven adapter implementing NetlinkSockDiagPort. Issues SOCK_DIAG_BY_FAMILY for AF_INET/AF_INET6; decodes inet_diag_msg (state, rqueue, wqueue) and INET_DIAG_SKMEMINFO." "Rust, netlink-packet-sock-diag 0.4, nft_exporter_adapter_sockdiag" {
                    tags "Component,DrivenAdapter"
                }
            }

            ethtoolCollectorContainer = container "Ethtool Collector" "Collects per-NIC statistics, link settings, PAUSE frame counts, FEC codeword counters, and RSS indirection table sizes via genetlink ETHTOOL family. Requires kernel 5.12+ and driver support. Produces NicStatSnapshot ReadModel." "Rust, ethtool 0.2.9, genetlink 0.2.6, NETLINK_GENERIC" {
                tags "Container,Collector"

                ethtoolCollector = component "EthtoolCollector" "Concrete Strategy (GoF) in Ethtool bounded context. Issues ETHTOOL_MSG_STATS_GET, LINKSETTINGS_GET, PAUSE_GET, FEC_GET, RSS_GET via NetlinkEthtoolPort. Gates on per-NIC EOPNOTSUPP probe. Produces NicStatSnapshot ReadModel." "Rust" {
                    tags "Component,ConcreteStrategy"
                }

                ethtoolAdapter = component "EthtoolAdapter" "Driven adapter implementing NetlinkEthtoolPort. Issues ETHTOOL_MSG_STATS_GET, ETHTOOL_MSG_LINKSETTINGS_GET, ETHTOOL_MSG_PAUSE_GET, ETHTOOL_MSG_FEC_GET, ETHTOOL_MSG_RSS_GET over the ETHTOOL genetlink family." "Rust, ethtool 0.2, nft_exporter_adapter_ethtool" {
                    tags "Component,DrivenAdapter"
                }
            }

            xfrmIpsecCollectorContainer = container "Xfrm IPsec Collector" "Runtime-gated IPsec observability collector. Issues XFRM_MSG_GETSA and XFRM_MSG_GETPOLICY dumps to count SAs and SPs by (proto,mode) and (dir,action). Queries XFRM_MSG_GETSADINFO and XFRM_MSG_GETSPDINFO for SAD/SPD hash watermarks. Parses /proc/net/xfrm_stat for 26 bounded XFRM error counters. Sets available=0 when xfrm_user is absent or EPERM at startup probe." "Rust / NETLINK_XFRM + procfs" {
                tags "Container,Collector,runtime-gated"

                xfrmIpsecCollector = component "XfrmIpsecCollector" "Concrete Strategy (GoF) in xfrm-ipsec bounded context. Issues XFRM_MSG_GETSA, XFRM_MSG_GETPOLICY, XFRM_MSG_GETSADINFO, XFRM_MSG_GETSPDINFO via NetlinkXfrmIpsecPort. Parses /proc/net/xfrm_stat. Produces XfrmSnapshot ReadModel. Emits nft_scrape_collector_available{collector=xfrm-ipsec}." "Rust" {
                    tags "Component,ConcreteStrategy"
                }

                xfrmIpsecAdapter = component "XfrmIpsecAdapter" "Driven adapter implementing NetlinkXfrmIpsecPort. Opens NETLINK_XFRM (family=6) AF_NETLINK raw socket via rustix. Issues XFRM_MSG_GETSA and XFRM_MSG_GETPOLICY NLM_F_DUMP requests. Zero-copy parses xfrm_usersa_info and xfrm_userpolicy_info frames. Reads /proc/net/xfrm_stat." "Rust, nft_exporter_adapter_xfrm" {
                    tags "Component,DrivenAdapter"
                }
            }

            ipvsCollectorContainer = container "IPVS Collector" "Resolves the IPVS generic-netlink family via CTRL_CMD_GETFAMILY; issues IPVS_CMD_GET_INFO, IPVS_CMD_GET_SERVICE dump, and per-service IPVS_CMD_GET_DEST requests; decodes IPVS_SVC_ATTR_STATS64 and IPVS_DEST_ATTR_STATS64 nested attributes into IpvsSnapshot ReadModel. Runtime-gated: ENOENT on family resolution sets available=false." "Rust / NETLINK_GENERIC" {
                tags "Container,Collector,runtime-gated"

                ipvsCollector = component "IpvsCollector" "Concrete Strategy (GoF) in ipvs bounded context. Translates IpvsSnapshot into nft_ipvs_* Prometheus metric families and emits nft_scrape_collector_available{collector=ipvs}. Enforces ipvs_max_services and ipvs_max_dests_per_service cardinality guards." "Rust" {
                    tags "Component,ConcreteStrategy"
                }

                ipvsAdapter = component "IpvsAdapter" "Driven adapter implementing NetlinkIpvsPort. Resolves IPVS genl family via CTRL_CMD_GETFAMILY; issues IPVS_CMD_GET_INFO, IPVS_CMD_GET_SERVICE, IPVS_CMD_GET_DEST over NETLINK_GENERIC." "Rust, nft_exporter_adapter_ipvs" {
                    tags "Component,DrivenAdapter"
                }
            }

            wireguardCollectorContainer = container "WireGuard Collector" "Resolves the wireguard generic-netlink family via CTRL_CMD_GETFAMILY; runtime-gated on ENOENT. Issues WG_CMD_GET_DEVICE NLM_F_DUMP per scrape; parses WGDEVICE_A_* and WGPEER_A_* attributes into WireguardSnapshot ReadModel. Peer identity bounded by SHA-256 truncated hash or operator name map." "Rust / NETLINK_GENERIC / WireGuard uapi" {
                tags "Container,Collector,runtime-gated"

                wireguardCollector = component "WireguardCollector" "Concrete Strategy (GoF) in wireguard bounded context. Resolves 'wireguard' family ID at startup via CTRL_CMD_GETFAMILY; runtime-gated on ENOENT. Issues WG_CMD_GET_DEVICE dump; produces WireguardSnapshot ReadModel." "Rust" {
                    tags "Component,ConcreteStrategy"
                }

                netlinkWireguardAdapter = component "NetlinkWireguardAdapter" "Driven adapter implementing NetlinkWireguardPort. Shares the NETLINK_GENERIC socket family. Uses a separate OnceLock<Option<u16>> for the dynamically resolved 'wireguard' family ID. Implements WG_CMD_GET_DEVICE dump-and-parse with NLM_F_DUMP_INTR restart semantics." "Rust, nft_exporter_adapter_wg" {
                    tags "Component,DrivenAdapter"
                }
            }

            devlinkCollectorContainer = container "Devlink Collector" "Collects devlink device, port, and health reporter metrics via the devlink genetlink family. Runtime-gated: CTRL_CMD_GETFAMILY returning ENOENT on hosts without CONFIG_NET_DEVLINK sets collector_available=false and emits no further requests. Produces DevlinkSnapshot ReadModel." "Rust, NETLINK_GENERIC (devlink)" {
                tags "Container,Collector,runtime-gated"

                devlinkCollector = component "DevlinkCollector" "Concrete Strategy (GoF) in Devlink bounded context. Issues DEVLINK_CMD_GET, DEVLINK_CMD_PORT_GET, DEVLINK_CMD_HEALTH_REPORTER_GET via NetlinkDevlinkPort. Runtime-gated on genl family resolution. Produces DevlinkSnapshot ReadModel." "Rust" {
                    tags "Component,ConcreteStrategy"
                }

                devlinkAdapter = component "DevlinkAdapter" "Driven adapter implementing NetlinkDevlinkPort. Resolves the devlink genl family id via CTRL_CMD_GETFAMILY (cached in OnceLock<u16>); issues NLM_F_DUMP requests for DEVLINK_CMD_GET and DEVLINK_CMD_PORT_GET; issues per-device DEVLINK_CMD_HEALTH_REPORTER_GET. ENOENT on family resolution sets collector_available=false." "Rust, nft_exporter_adapter_devlink" {
                    tags "Component,DrivenAdapter"
                }
            }

            dropMonitorCollectorContainer = container "Drop-Monitor Collector" "Collects per-reason kernel packet-drop counters via the NET_DM generic-netlink family. Runtime-gated: emits nft_scrape_collector_available=0 when the drop_monitor module is absent (CTRL_CMD_GETFAMILY ENOENT). In summary mode only; per-packet event mode is unsupported. Produces DropMonitorSnapshot ReadModel." "Rust, NETLINK_GENERIC (NET_DM)" {
                tags "Container,Collector,runtime-gated"

                dropMonitorCollector = component "DropMonitorCollector" "Concrete Strategy (GoF) in DropMonitor bounded context. Issues NET_DM_CMD_CONFIG (summary mode) and NET_DM_CMD_START via NetlinkDropMonitorPort. Consumes NET_DM_CMD_ALERT multicast frames and accumulates DropReasonCounter entries by (reason, origin). Produces DropMonitorSnapshot ReadModel." "Rust" {
                    tags "Component,ConcreteStrategy"
                }

                dropMonitorAdapter = component "DropMonitorAdapter" "Driven adapter implementing NetlinkDropMonitorPort. Resolves NET_DM family via CTRL_CMD_GETFAMILY; subscribes to NET_DM_GRP_ALERT multicast group; decodes NET_DM_CMD_ALERT nlattr chains extracting NET_DM_ATTR_REASON and NET_DM_ATTR_HW_TRAP_NAME and NET_DM_ATTR_STATS_DROPPED u64 native-endian." "Rust, nft_exporter_adapter_dm" {
                    tags "Component,DrivenAdapter"
                }
            }

            rtnetlinkExtendedCollectorContainer = container "Rtnetlink Extended Collector" "Collects extended per-interface link xstats (RTM_GETSTATS with IFLA_STATS_LINK_XSTATS and IFLA_STATS_LINK_OFFLOAD_XSTATS), bridge FDB entry counts (RTM_GETNEIGH AF_BRIDGE), fib policy-rule counts (RTM_GETRULE), and nexthop object counts (RTM_GETNEXTHOP) via NETLINK_ROUTE. Runtime-gated on kernel >= 4.20. Produces RtnetlinkExtendedSnapshot ReadModel." "Rust, NETLINK_ROUTE, nft_exporter_adapter_rt_extended" {
                tags "Container,Collector,runtime-gated"

                rtnetlinkExtendedCollector = component "RtnetlinkExtendedCollector" "Concrete Strategy (GoF) in rtnetlink-extended bounded context. Issues RTM_GETSTATS, RTM_GETNEIGH/AF_BRIDGE, RTM_GETRULE, and RTM_GETNEXTHOP via NetlinkRtnetlinkExtendedPort. Availability probe on startup. Produces RtnetlinkExtendedSnapshot ReadModel." "Rust" {
                    tags "Component,ConcreteStrategy"
                }

                rtnetlinkExtendedAdapter = component "RtnetlinkExtendedAdapter" "Driven adapter implementing NetlinkRtnetlinkExtendedPort. Opens NETLINK_ROUTE socket; issues RTM_GETSTATS (if_stats_msg body, filter_mask=0x0B), RTM_GETNEIGH (AF_BRIDGE), RTM_GETRULE (AF_INET/AF_INET6/AF_MPLS), and RTM_GETNEXTHOP (nhmsg body); decodes BRIDGE_XSTATS_MCAST, rtnl_hw_stats64, fib_rule_hdr, and nhmsg payloads." "Rust, nft_exporter_adapter_rt_extended" {
                    tags "Component,DrivenAdapter"
                }
            }

            conntrackExpectationsCollectorContainer = container "Conntrack-Expectations Collector" "Collects Linux conntrack expectation-table state from ctnetlink NFNL_SUBSYS_CTNETLINK_EXP (subsystem id 2). Issues IPCTNL_MSG_EXP_GET dump (nlmsg_type=0x0200) and IPCTNL_MSG_EXP_GET_STATS_CPU (nlmsg_type=0x0203). Runtime-gated: sets nft_scrape_collector_available=0 and returns empty ReadModel when kernel returns ENOENT or EPERM. Produces ConntrackExpectationSummary ReadModel aggregated by (l4proto, helper)." "Rust, NETLINK_NETFILTER (NFNL_SUBSYS_CTNETLINK_EXP=2)" {
                tags "Container,Collector"

                conntrackExpectationsCollector = component "ConntrackExpectationsCollector" "Concrete Strategy (GoF) in conntrack-expectations bounded context. Issues IPCTNL_MSG_EXP_GET dump and IPCTNL_MSG_EXP_GET_STATS_CPU via NetlinkConntrackExpectationsPort. Runtime-gates on ENOENT/EPERM. Produces ConntrackExpectationSummary ReadModel." "Rust" {
                    tags "Component,ConcreteStrategy"
                }

                conntrackExpectationsAggregator = component "ConntrackExpectationsAggregator" "Domain Service in conntrack-expectations bounded context. Groups raw expectation entries by (l4proto, helper) and counts them. Enforces the 256-key cardinality overflow guard. Pure domain logic with no kernel or infra dependency." "Rust" {
                    tags "Component,DomainService"
                }

                conntrackExpectationsAdapter = component "ConntrackExpectationsAdapter" "Driven adapter implementing NetlinkConntrackExpectationsPort. Issues IPCTNL_MSG_EXP_GET and IPCTNL_MSG_EXP_GET_STATS_CPU over the shared NETLINK_NETFILTER socket (protocol=12, NFNL_SUBSYS_CTNETLINK_EXP=2). Maps ENOENT/EPERM to availability=false." "Rust, nft_exporter_adapter_ct_exp" {
                    tags "Component,DrivenAdapter"
                }
            }

            metricRegistry = container "Metric Registry" "Accepts ReadModel samples from all collectors; encodes OpenMetrics text into Vec<u8>. Abstracts prometheus-client 0.24 from domain-core crates. Implements MetricRegistryPort driven port." "Rust, prometheus-client 0.24, OpenMetrics" {
                tags "Container,DrivenAdapter"

                prometheusRegistryAdapter = component "PrometheusRegistryAdapter" "Composite (GoF) + Driven Adapter in Exposition bounded context. AggregateMetricRegistry wrapping prometheus-client 0.24 Family instances. Implements MetricRegistryPort. Encodes the full metric set to OpenMetrics text via text_format::encode." "Rust, prometheus-client 0.24, nft_exporter_adapter_prom" {
                    tags "Component,Composite,DrivenAdapter"
                }

                stdClockAdapter = component "StdClockAdapter" "Driven adapter implementing ClockPort. Wraps std::time::Instant for deterministic scrape duration measurement. Replaced by FakeClockAdapter in unit tests." "Rust, nft_exporter_adapter_rt" {
                    tags "Component,DrivenAdapter"
                }
            }

            # ── Inter-container relationships ────────────────────────────────

            # HTTP adapter drives the orchestrator via ScrapeTriggerPort
            httpExposition -> collectionOrchestrator "Triggers scrape via ScrapeTriggerPort (async fn trigger_scrape)" "ScrapeTriggerPort"
            httpExposition -> collectionOrchestrator "Checks liveness via HealthPort (async fn health)" "HealthPort"
            httpExposition -> collectionOrchestrator "Checks readiness via ReadinessPort (async fn readiness)" "ReadinessPort"

            # Orchestrator drives each subsystem collector
            collectionOrchestrator -> rtnetlinkCollectorContainer "Fans out scrape via Collector trait (JoinSet, timeout 9800 ms)" "Collector Strategy"
            collectionOrchestrator -> tcCollectorContainer "Fans out scrape via Collector trait (JoinSet, timeout 9800 ms)" "Collector Strategy"
            collectionOrchestrator -> conntrackCollectorContainer "Fans out scrape via Collector trait (JoinSet, timeout 9800 ms)" "Collector Strategy"
            collectionOrchestrator -> nftablesCollectorContainer "Fans out scrape via Collector trait (JoinSet, timeout 9800 ms)" "Collector Strategy"
            collectionOrchestrator -> sockDiagCollectorContainer "Fans out scrape via Collector trait (JoinSet, timeout 9800 ms)" "Collector Strategy"
            collectionOrchestrator -> ethtoolCollectorContainer "Fans out scrape via Collector trait (JoinSet, timeout 9800 ms)" "Collector Strategy"
            collectionOrchestrator -> xfrmIpsecCollectorContainer "Fans out scrape via Collector trait (JoinSet, timeout 9800 ms)" "Collector Strategy"
            collectionOrchestrator -> ipvsCollectorContainer "Fans out scrape via Collector trait (JoinSet, timeout 9800 ms)" "Collector Strategy"
            collectionOrchestrator -> wireguardCollectorContainer "Fans out scrape via Collector trait (JoinSet, timeout 9800 ms)" "Collector Strategy"
            collectionOrchestrator -> devlinkCollectorContainer "Fans out scrape via Collector trait (JoinSet, timeout 9800 ms)" "Collector Strategy"
            collectionOrchestrator -> dropMonitorCollectorContainer "Fans out scrape via Collector trait (JoinSet, timeout 9800 ms)" "Collector Strategy"
            collectionOrchestrator -> rtnetlinkExtendedCollectorContainer "Fans out scrape via Collector trait (JoinSet, timeout 9800 ms)" "Collector Strategy"
            collectionOrchestrator -> conntrackExpectationsCollectorContainer "Fans out scrape via Collector trait (JoinSet, timeout 9800 ms)" "Collector Strategy"

            # Collectors publish ReadModels to metric registry
            collectionOrchestrator -> metricRegistry "Publishes MetricSnapshot via MetricRegistryPort" "MetricRegistryPort"
            rtnetlinkCollectorContainer -> metricRegistry "Returns LinkSnapshot, AddressSnapshot, RouteTableSnapshot, NeighborSnapshot" "ReadModel"
            tcCollectorContainer -> metricRegistry "Returns TcTreeSnapshot" "ReadModel"
            conntrackCollectorContainer -> metricRegistry "Returns ConntrackSummary" "ReadModel"
            nftablesCollectorContainer -> metricRegistry "Returns NftCounterSnapshot" "ReadModel"
            sockDiagCollectorContainer -> metricRegistry "Returns SocketStateHistogram" "ReadModel"
            ethtoolCollectorContainer -> metricRegistry "Returns NicStatSnapshot" "ReadModel"
            xfrmIpsecCollectorContainer -> metricRegistry "Returns XfrmSnapshot" "ReadModel"
            ipvsCollectorContainer -> metricRegistry "Returns IpvsSnapshot" "ReadModel"
            wireguardCollectorContainer -> metricRegistry "Returns WireguardSnapshot" "ReadModel"
            devlinkCollectorContainer -> metricRegistry "Returns DevlinkSnapshot" "ReadModel"
            dropMonitorCollectorContainer -> metricRegistry "Returns DropMonitorSnapshot" "ReadModel"
            rtnetlinkExtendedCollectorContainer -> metricRegistry "Returns RtnetlinkExtendedSnapshot" "ReadModel"
            conntrackExpectationsCollectorContainer -> metricRegistry "Returns ConntrackExpectationSummary" "ReadModel"

            # HTTP exposition reads encoded OpenMetrics text from registry
            httpExposition -> metricRegistry "Reads OpenMetrics text response body" "Vec<u8>"

            # Netlink adapters talk to the kernel
            rtnetlinkCollectorContainer -> linuxKernel "RTM_GETLINK, RTM_GETADDR, RTM_GETROUTE, RTM_GETNEIGH via NETLINK_ROUTE" "NETLINK_ROUTE"
            tcCollectorContainer -> linuxKernel "RTM_GETQDISC, RTM_GETTCLASS, RTM_GETTFILTER via NETLINK_ROUTE" "NETLINK_ROUTE"
            conntrackCollectorContainer -> linuxKernel "IPCTNL_MSG_CT_GET, IPCTNL_MSG_CT_GET_STATS_CPU via NETLINK_NETFILTER" "NETLINK_NETFILTER (ctnetlink)"
            nftablesCollectorContainer -> linuxKernel "NFT_MSG_GETRULE, NFT_MSG_GETCOUNTER, NFT_MSG_GETSET, NFT_MSG_GETCHAIN, NFT_MSG_GETTABLE via NETLINK_NETFILTER" "NETLINK_NETFILTER (nfnetlink)"
            sockDiagCollectorContainer -> linuxKernel "SOCK_DIAG_BY_FAMILY AF_INET/AF_INET6 via NETLINK_SOCK_DIAG" "NETLINK_SOCK_DIAG"
            ethtoolCollectorContainer -> linuxKernel "ETHTOOL_MSG_STATS_GET, LINKSETTINGS_GET, PAUSE_GET, FEC_GET, RSS_GET via NETLINK_GENERIC" "NETLINK_GENERIC (ethtool)"
            xfrmIpsecCollectorContainer -> linuxKernel "XFRM_MSG_GETSA, XFRM_MSG_GETPOLICY, XFRM_MSG_GETSADINFO, XFRM_MSG_GETSPDINFO via NETLINK_XFRM; /proc/net/xfrm_stat" "NETLINK_XFRM (family=6)"
            ipvsCollectorContainer -> linuxKernel "IPVS_CMD_GET_INFO, IPVS_CMD_GET_SERVICE, IPVS_CMD_GET_DEST via NETLINK_GENERIC" "NETLINK_GENERIC (IPVS)"
            wireguardCollectorContainer -> linuxKernel "WG_CMD_GET_DEVICE via NETLINK_GENERIC (wireguard family)" "NETLINK_GENERIC (wireguard)"
            devlinkCollectorContainer -> linuxKernel "DEVLINK_CMD_GET, DEVLINK_CMD_PORT_GET, DEVLINK_CMD_HEALTH_REPORTER_GET via NETLINK_GENERIC" "NETLINK_GENERIC (devlink)"
            dropMonitorCollectorContainer -> linuxKernel "NET_DM_CMD_CONFIG, NET_DM_CMD_START, NET_DM_GRP_ALERT multicast via NETLINK_GENERIC" "NETLINK_GENERIC (NET_DM)"
            rtnetlinkExtendedCollectorContainer -> linuxKernel "RTM_GETSTATS, RTM_GETNEIGH/AF_BRIDGE, RTM_GETRULE, RTM_GETNEXTHOP via NETLINK_ROUTE" "NETLINK_ROUTE"
            conntrackExpectationsCollectorContainer -> linuxKernel "IPCTNL_MSG_EXP_GET, IPCTNL_MSG_EXP_GET_STATS_CPU via NETLINK_NETFILTER (NFNL_SUBSYS_CTNETLINK_EXP=2)" "NETLINK_NETFILTER (ctnetlink-exp)"
        }

        # ── System-level relationships ───────────────────────────────────────
        prometheusServer -> nftExporter "Scrapes GET /metrics on port 9456 (OpenMetrics text)" "HTTP/OpenMetrics"
        prometheusServer -> alertmanager "Sends firing alerts" "HTTP"
        grafana -> prometheusServer "Queries metric time series" "PromQL/HTTP"

        # Prometheus calls the HTTP exposition directly (container level)
        prometheusServer -> httpExposition "GET /metrics port 9456" "HTTP/OpenMetrics"
    }

    views {

        # ── System Context view ─────────────────────────────────────────────
        systemContext nftExporter "SystemContext" {
            title "nft_exporter — System Context"
            include *
            autolayout tb
        }

        # ── Container view ──────────────────────────────────────────────────
        container nftExporter "Containers" {
            title "nft_exporter — Container view (hexagonal layers)"
            include *
            autolayout tb
        }

        # ── Component view: Collection Orchestrator ─────────────────────────
        component collectionOrchestrator "Components_Orchestrator" {
            title "nft_exporter — CollectionOrchestrator components (Template Method + Abstract Factory)"
            include *
            autolayout lr
        }

        # ── Component view: HTTP Exposition ─────────────────────────────────
        component httpExposition "Components_HttpExposition" {
            title "nft_exporter — HTTP Exposition components (Driving adapters + Facade)"
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
            title "nft_exporter — Metric Registry components (Composite Driven Adapter)"
            include *
            autolayout lr
        }

        # ── Component view: Nftables Collector ──────────────────────────────
        component nftablesCollectorContainer "Components_Nftables" {
            title "nft_exporter — Nftables Collector components (Strategy + Driven Adapter)"
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

            relationship "NETLINK_ROUTE" {
                color #1565c0
            }

            relationship "NETLINK_NETFILTER (ctnetlink)" {
                color #880e4f
            }

            relationship "NETLINK_NETFILTER (nfnetlink)" {
                color #880e4f
            }

            relationship "NETLINK_SOCK_DIAG" {
                color #4a148c
            }

            relationship "NETLINK_GENERIC (ethtool)" {
                color #1b5e20
            }
        }

        theme default
    }
}
