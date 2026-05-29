Feature: IPVS (LVS) load-balancer metrics (ipvs subsystem)
  As a Prometheus operator running Linux Virtual Server
  I want nft_exporter to emit IPVS virtual-service and real-server metrics via the IPVS generic-netlink family
  So that I can observe per-service connection counts, throughput, and real-server health without per-connection cardinality

  Background:
    Given nft_exporter is running with the ipvs collector enabled
    And the ip_vs kernel module is loaded
    And the IPVS generic-netlink family "IPVS" resolves successfully via CTRL_CMD_GETFAMILY
    And the IPVS connection table size is 4096
    And a virtual service exists with proto="tcp", vip="192.0.2.10", port="80", scheduler="rr"
    And that service has two real servers: rip="10.0.0.1" rport="8080" and rip="10.0.0.2" rport="8080"
    And the service has accumulated 5000 total connections, 1000000 incoming bytes, 500000 outgoing bytes
    And each real server has 25 active connections and 5 inactive connections

  Scenario: nft_scrape_collector_available reports 1 when ip_vs module is present
    When a scrape executes
    Then the metric "nft_scrape_collector_available" with label collector="ipvs" has value 1

  Scenario: nft_ipvs_connection_table_size reports the kernel connection table capacity
    When a scrape executes
    Then the metric "nft_ipvs_connection_table_size" has value 4096

  Scenario: nft_ipvs_service_info emits one gauge per virtual service
    When a scrape executes
    Then the metric "nft_ipvs_service_info" with labels proto="tcp", vip="192.0.2.10", port="80", sched="rr" has value 1
    And no "nft_ipvs_service_info" series contains src_ip, dst_ip, src_port, dst_port, or flow_id labels

  Scenario: nft_ipvs_connections_total accumulates per-service connection counter from STATS64
    When a scrape executes
    Then the metric "nft_ipvs_connections_total" with labels proto="tcp", vip="192.0.2.10", port="80" has value 5000
    And the OpenMetrics type declaration for "nft_ipvs_connections_total" is "counter"

  Scenario: nft_ipvs_incoming_bytes_total reflects IPVS_STATS_ATTR_INBYTES for the service
    When a scrape executes
    Then the metric "nft_ipvs_incoming_bytes_total" with labels proto="tcp", vip="192.0.2.10", port="80" has value 1000000

  Scenario: nft_ipvs_outgoing_bytes_total reflects IPVS_STATS_ATTR_OUTBYTES for the service
    When a scrape executes
    Then the metric "nft_ipvs_outgoing_bytes_total" with labels proto="tcp", vip="192.0.2.10", port="80" has value 500000

  Scenario: nft_ipvs_incoming_packets_total and nft_ipvs_outgoing_packets_total are present
    When a scrape executes
    Then the metric "nft_ipvs_incoming_packets_total" with labels proto="tcp", vip="192.0.2.10", port="80" is present
    And the metric "nft_ipvs_outgoing_packets_total" with labels proto="tcp", vip="192.0.2.10", port="80" is present

  Scenario: EMA rate gauges are emitted for each virtual service
    When a scrape executes
    Then the metric "nft_ipvs_connections_per_second" with labels proto="tcp", vip="192.0.2.10", port="80" is present
    And the metric "nft_ipvs_incoming_bytes_per_second" with labels proto="tcp", vip="192.0.2.10", port="80" is present
    And the metric "nft_ipvs_outgoing_bytes_per_second" with labels proto="tcp", vip="192.0.2.10", port="80" is present
    And the OpenMetrics type declaration for "nft_ipvs_connections_per_second" is "gauge"

  Scenario: nft_ipvs_dest_active_connections emits per-real-server gauge
    When a scrape executes
    Then the metric "nft_ipvs_dest_active_connections" with labels proto="tcp", vip="192.0.2.10", port="80", rip="10.0.0.1", rport="8080" has value 25
    And the metric "nft_ipvs_dest_active_connections" with labels proto="tcp", vip="192.0.2.10", port="80", rip="10.0.0.2", rport="8080" has value 25

  Scenario: nft_ipvs_dest_inactive_connections emits per-real-server gauge
    When a scrape executes
    Then the metric "nft_ipvs_dest_inactive_connections" with labels proto="tcp", vip="192.0.2.10", port="80", rip="10.0.0.1", rport="8080" has value 5

  Scenario: nft_ipvs_dest_connections_total counter is emitted per destination
    When a scrape executes
    Then the metric "nft_ipvs_dest_connections_total" with labels proto="tcp", vip="192.0.2.10", port="80", rip="10.0.0.1", rport="8080" is present
    And the OpenMetrics type declaration for "nft_ipvs_dest_connections_total" is "counter"

  Scenario: nft_ipvs_dest_incoming_bytes_total and nft_ipvs_dest_outgoing_bytes_total are present per destination
    When a scrape executes
    Then the metric "nft_ipvs_dest_incoming_bytes_total" with labels proto="tcp", vip="192.0.2.10", port="80", rip="10.0.0.1", rport="8080" is present
    And the metric "nft_ipvs_dest_outgoing_bytes_total" with labels proto="tcp", vip="192.0.2.10", port="80", rip="10.0.0.2", rport="8080" is present

  Scenario: Firewall-mark services emit port as fwmark hex string and vip as empty string
    Given a fwmark virtual service exists with fwmark=0x64, proto="tcp", scheduler="lc"
    When a scrape executes
    Then the metric "nft_ipvs_service_info" with labels proto="tcp", vip="", port="0x64", sched="lc" has value 1
    And the metric "nft_ipvs_connections_total" with labels proto="tcp", vip="", port="0x64" is present

  Scenario: IPv6 virtual service labels use standard presentation form
    Given a virtual service exists with proto="tcp", vip="2001:db8::1", port="443", scheduler="rr"
    When a scrape executes
    Then the metric "nft_ipvs_service_info" with labels proto="tcp", vip="2001:db8::1", port="443", sched="rr" has value 1

  Scenario: Cardinality is bounded by ipvs_max_services configuration
    Given the IPVS table contains more than 512 virtual services
    When a scrape executes
    Then the metric "nft_scrape_collector_error_total" with labels collector="ipvs" and reason="cardinality_overflow" is incremented by 1
    And no "nft_ipvs_service_info" series is emitted beyond the cardinality ceiling

  Scenario: IPVS collector reports available=0 gracefully when ip_vs module is absent
    Given the ip_vs kernel module is not loaded
    And CTRL_CMD_GETFAMILY for "IPVS" returns ENOENT
    When a scrape executes
    Then the metric "nft_scrape_collector_available" with label collector="ipvs" has value 0
    And the metric "nft_scrape_collector_success" with label collector="ipvs" has value 1
    And no "nft_ipvs_connections_total" series is present in the response
    And no "nft_ipvs_service_info" series is present in the response
    And the metric "nft_scrape_collector_error_total" with label collector="ipvs" is not incremented

  Scenario: IPVS collector failure on permission error sets success to 0
    Given the ip_vs module is loaded but the NETLINK_GENERIC socket returns EPERM for IPVS_CMD_GET_SERVICE
    When a scrape executes
    Then the metric "nft_scrape_collector_success" with label collector="ipvs" has value 0
    And the metric "nft_scrape_collector_error_total" with labels collector="ipvs" and reason="netlink_permission_denied" is incremented by 1

  Scenario: UDP virtual service labels use proto="udp"
    Given a virtual service exists with proto="udp", vip="192.0.2.20", port="53", scheduler="rr"
    When a scrape executes
    Then the metric "nft_ipvs_service_info" with labels proto="udp", vip="192.0.2.20", port="53", sched="rr" has value 1
    And the metric "nft_ipvs_connections_total" with labels proto="udp", vip="192.0.2.20", port="53" is present
