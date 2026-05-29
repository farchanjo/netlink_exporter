Feature: Cardinality guard
  As a Prometheus operator
  I want the conntrack collector to enforce bounded cardinality
  So that N million flows in the kernel never produce N million time series

  Background:
    Given nft_exporter is running with the conntrack collector enabled
    And the kernel conntrack table contains 1,000,000 active flows

  Scenario: Conntrack with 1 million flows emits only bounded per-(proto,state) series
    When a scrape executes
    Then the metric "nft_conntrack_entries" is present in the response
    And the number of distinct "nft_conntrack_entries" series is at most 40
    And no single time series in "nft_conntrack_entries" uses a per-flow label (no src_ip, dst_ip, src_port, dst_port, or flow_id label)

  Scenario: Conntrack byte and packet counters are aggregated, not per-flow
    When a scrape executes
    Then the metric "nft_conntrack_bytes_total" is present with labels protocol and direction only
    And the number of distinct "nft_conntrack_bytes_total" series is at most 16
    And the metric "nft_conntrack_packets_total" is present with labels protocol and direction only
    And the number of distinct "nft_conntrack_packets_total" series is at most 16

  Scenario: ConntrackAggregator sums all bytes across flows of the same (proto, direction)
    Given the kernel reports 500,000 TCP flows in the "established" state
    And each flow has 1000 bytes in the original direction
    When a scrape executes
    Then the metric "nft_conntrack_bytes_total" with labels protocol="tcp" and direction="original" has value at least 500000000

  Scenario: Cardinality overflow on nftables anonymous rules triggers error metric
    Given the nftables ruleset contains more than 500 anonymous rules (rules with no comment)
    When a scrape executes
    Then the metric "nft_scrape_collector_error_total" with labels collector="nftables" and reason="cardinality_overflow" is incremented by 1
    And the metric "nft_rule_counter_bytes_total" is suppressed for anonymous rules beyond the 500-series limit

  Scenario: Route count does not emit per-destination-prefix series
    Given the kernel routing table contains 100,000 routes
    When a scrape executes
    Then the metric "nft_route_count" is present in the response
    And the number of distinct "nft_route_count" series is at most 480
    And no "nft_route_count" series contains a destination label or prefix label

  Scenario: Neighbor count does not emit per-IP or per-MAC series
    Given the kernel ARP table contains 50,000 neighbor entries
    When a scrape executes
    Then the metric "nft_neighbor_count" is present in the response
    And the number of distinct "nft_neighbor_count" series is at most 3072
    And no "nft_neighbor_count" series contains a mac_address or ip_address label

  Scenario: Socket count does not emit per-socket or per-port series
    Given the kernel has 200,000 open TCP sockets
    When a scrape executes
    Then the metric "nft_socket_count" is present in the response
    And the number of distinct "nft_socket_count" series is at most 24
    And no "nft_socket_count" series contains a port, inode, or socket_id label

  Scenario: Ethtool cardinality is bounded by interface count times fixed stat names
    Given 8 network interfaces are present, each reporting 100 ethtool statistics
    When a scrape executes
    Then the number of distinct "nft_ethtool_stat" series is at most 800
    And each "nft_ethtool_stat" series has labels interface and stat only
