Feature: Extended rtnetlink metrics (rtnetlink-extended subsystem)
  As a Prometheus operator
  I want nft_exporter to emit extended rtnetlink metrics via RTM_GETSTATS, RTM_GETNEIGH/AF_BRIDGE, RTM_GETRULE, and RTM_GETNEXTHOP
  So that I can observe per-interface xstats, bridge FDB cardinality, fib policy-rule counts, and nexthop object counts without per-prefix or per-MAC cardinality

  Background:
    Given nft_exporter is running with the rtnetlink-extended collector enabled
    And the Linux kernel version is at least 4.20
    And a bridge device "br0" is present with 150 FDB entries
    And "br0" reports BRIDGE_XSTATS_MCAST rx_bytes=8192 and tx_bytes=4096
    And the host has 3 AF_INET fib policy rules, 2 AF_INET6 fib policy rules, and 0 AF_MPLS fib policy rules
    And the kernel supports RTM_GETNEXTHOP and has 5 nexthop objects installed

  Scenario: nft_bridge_fdb_entries emits total FDB entry count per bridge interface
    When a scrape executes
    Then the metric "nft_bridge_fdb_entries" with label interface="br0" has value 150
    And no "nft_bridge_fdb_entries" series contains a mac_address, dst_ip, or src_ip label

  Scenario: nft_bridge_fdb_entries cardinality is bounded by bridge device count
    Given the host has 2 bridge devices "br0" and "br1"
    And "br1" has 20 FDB entries
    When a scrape executes
    Then the total number of "nft_bridge_fdb_entries" series is at most 32

  Scenario: nft_link_xstats_bridge_rx_multicast_bytes_total emits per-bridge multicast rx byte count
    When a scrape executes
    Then the metric "nft_link_xstats_bridge_rx_multicast_bytes_total" with label interface="br0" has value 8192

  Scenario: nft_link_xstats_bridge_tx_multicast_bytes_total emits per-bridge multicast tx byte count
    When a scrape executes
    Then the metric "nft_link_xstats_bridge_tx_multicast_bytes_total" with label interface="br0" has value 4096

  Scenario: nft_link_xstats_offload_rx_bytes_total is emitted when offload xstats are present
    Given "eth0" reports IFLA_STATS_LINK_OFFLOAD_XSTATS with rx_bytes=65536 and tx_bytes=32768
    When a scrape executes
    Then the metric "nft_link_xstats_offload_rx_bytes_total" with label interface="eth0" has value 65536
    And the metric "nft_link_xstats_offload_tx_bytes_total" with label interface="eth0" has value 32768

  Scenario: nft_link_xstats_offload_rx_bytes_total is absent for interfaces without offload xstats
    Given "eth1" reports no IFLA_STATS_LINK_OFFLOAD_XSTATS attribute in RTM_NEWSTATS
    When a scrape executes
    Then no "nft_link_xstats_offload_rx_bytes_total" series exists with label interface="eth1"

  Scenario: nft_fib_rules emits rule counts aggregated by address family
    When a scrape executes
    Then the metric "nft_fib_rules" with label family="inet" has value 3
    And the metric "nft_fib_rules" with label family="inet6" has value 2
    And the metric "nft_fib_rules" with label family="mpls" has value 0

  Scenario: nft_fib_rules cardinality is bounded by address-family count
    When a scrape executes
    Then the total number of "nft_fib_rules" series is at most 3

  Scenario: nft_nexthop_objects emits total nexthop object count without labels
    When a scrape executes
    Then the metric "nft_nexthop_objects" with no labels has value 5

  Scenario: nft_scrape_collector_available emits 1 when RTM_GETSTATS is supported
    When a scrape executes
    Then the metric "nft_scrape_collector_available" with label collector="rtnetlink-extended" has value 1

  Scenario: nft_scrape_collector_available emits 0 gracefully when RTM_GETSTATS is not supported
    Given the kernel version is older than 4.20
    And RTM_GETSTATS returns EINVAL for the availability probe
    When a scrape executes
    Then the metric "nft_scrape_collector_available" with label collector="rtnetlink-extended" has value 0
    And no "nft_link_xstats_bridge_rx_multicast_bytes_total" series is present
    And no "nft_link_xstats_bridge_tx_multicast_bytes_total" series is present
    And no "nft_link_xstats_offload_rx_bytes_total" series is present
    And no "nft_link_xstats_offload_tx_bytes_total" series is present
    And the metric "nft_scrape_collector_success" with label collector="rtnetlink-extended" has value 1
    And the metric "nft_scrape_collector_error_total" with label collector="rtnetlink-extended" is not incremented

  Scenario: nft_nexthop_objects emits 0 gracefully when RTM_GETNEXTHOP is not supported
    Given the kernel version is older than 5.3
    And RTM_GETNEXTHOP returns EINVAL
    When a scrape executes
    Then the metric "nft_nexthop_objects" with no labels has value 0
    And the metric "nft_scrape_collector_error_total" with label collector="rtnetlink-extended" is not incremented

  Scenario: AF_BRIDGE FDB entries do not produce per-MAC series
    Given "br0" has 150 FDB entries each with a distinct MAC address
    When a scrape executes
    Then the total number of "nft_bridge_fdb_entries" series is 1
    And no "nft_bridge_fdb_entries" series contains a mac_address label

  Scenario: Interface filter from ADR-0013 is applied to xstats and FDB metrics
    Given the exporter config sets interface_exclude_regex to "^veth"
    And a veth interface "veth0" is present with BRIDGE_XSTATS_MCAST data
    When a scrape executes
    Then no "nft_link_xstats_bridge_rx_multicast_bytes_total" series exists with label interface="veth0"
    And the metric "nft_link_filtered_total" with label collector="rtnetlink-extended" is incremented

  Scenario: rtnetlink-extended collector failure is isolated from other collectors
    Given the RTM_GETSTATS dump returns EPERM
    When a scrape executes
    Then the metric "nft_scrape_collector_success" with label collector="rtnetlink-extended" has value 0
    And the metric "nft_scrape_collector_error_total" with labels collector="rtnetlink-extended" and reason="netlink_permission_denied" is incremented by 1
    And the metric "nft_scrape_collector_success" with label collector="rtnetlink" has value 1
    And the metric "nft_up" has value 1

  Scenario: xstats metrics use counter type with _total suffix
    When a scrape executes
    Then the OpenMetrics type declaration for "nft_link_xstats_bridge_rx_multicast_bytes_total" is "counter"
    And the OpenMetrics type declaration for "nft_link_xstats_bridge_tx_multicast_bytes_total" is "counter"
    And the OpenMetrics type declaration for "nft_link_xstats_offload_rx_bytes_total" is "counter"
    And the OpenMetrics type declaration for "nft_link_xstats_offload_tx_bytes_total" is "counter"

  Scenario: FDB, FIB rule, and nexthop metrics use gauge type
    When a scrape executes
    Then the OpenMetrics type declaration for "nft_bridge_fdb_entries" is "gauge"
    And the OpenMetrics type declaration for "nft_fib_rules" is "gauge"
    And the OpenMetrics type declaration for "nft_nexthop_objects" is "gauge"
