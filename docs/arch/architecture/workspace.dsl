workspace "nft_exporter" "C4 architecture model for nft_exporter — a Rust 2024-edition static-musl Linux netlink Prometheus exporter." {

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

            # Collectors publish ReadModels to metric registry
            collectionOrchestrator -> metricRegistry "Publishes MetricSnapshot via MetricRegistryPort" "MetricRegistryPort"
            rtnetlinkCollectorContainer -> metricRegistry "Returns LinkSnapshot, AddressSnapshot, RouteTableSnapshot, NeighborSnapshot" "ReadModel"
            tcCollectorContainer -> metricRegistry "Returns TcTreeSnapshot" "ReadModel"
            conntrackCollectorContainer -> metricRegistry "Returns ConntrackSummary" "ReadModel"
            nftablesCollectorContainer -> metricRegistry "Returns NftCounterSnapshot" "ReadModel"
            sockDiagCollectorContainer -> metricRegistry "Returns SocketStateHistogram" "ReadModel"
            ethtoolCollectorContainer -> metricRegistry "Returns NicStatSnapshot" "ReadModel"

            # HTTP exposition reads encoded OpenMetrics text from registry
            httpExposition -> metricRegistry "Reads OpenMetrics text response body" "Vec<u8>"

            # Netlink adapters talk to the kernel
            rtnetlinkCollectorContainer -> linuxKernel "RTM_GETLINK, RTM_GETADDR, RTM_GETROUTE, RTM_GETNEIGH via NETLINK_ROUTE" "NETLINK_ROUTE"
            tcCollectorContainer -> linuxKernel "RTM_GETQDISC, RTM_GETTCLASS, RTM_GETTFILTER via NETLINK_ROUTE" "NETLINK_ROUTE"
            conntrackCollectorContainer -> linuxKernel "IPCTNL_MSG_CT_GET, IPCTNL_MSG_CT_GET_STATS_CPU via NETLINK_NETFILTER" "NETLINK_NETFILTER (ctnetlink)"
            nftablesCollectorContainer -> linuxKernel "NFT_MSG_GETRULE, NFT_MSG_GETCOUNTER, NFT_MSG_GETSET, NFT_MSG_GETCHAIN, NFT_MSG_GETTABLE via NETLINK_NETFILTER" "NETLINK_NETFILTER (nfnetlink)"
            sockDiagCollectorContainer -> linuxKernel "SOCK_DIAG_BY_FAMILY AF_INET/AF_INET6 via NETLINK_SOCK_DIAG" "NETLINK_SOCK_DIAG"
            ethtoolCollectorContainer -> linuxKernel "ETHTOOL_MSG_STATS_GET, LINKSETTINGS_GET, PAUSE_GET, FEC_GET, RSS_GET via NETLINK_GENERIC" "NETLINK_GENERIC (ethtool)"
        }

        # ── System-level relationships ───────────────────────────────────────
        prometheusServer -> nftExporter "Scrapes GET /metrics on port 9456 (OpenMetrics text)" "HTTP/OpenMetrics"
        prometheusServer -> alertmanager "Sends firing alerts" "HTTP"
        grafana -> prometheusServer "Queries metric time series" "PromQL/HTTP"

        # Prometheus calls the HTTP exposition directly (container level)
        prometheusServer -> nftExporter.httpExposition "GET /metrics port 9456" "HTTP/OpenMetrics"
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
