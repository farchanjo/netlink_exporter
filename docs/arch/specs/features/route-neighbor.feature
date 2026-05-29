Feature: Route and neighbor metrics (rtnetlink subsystem)
  As a Prometheus operator
  I want nft_exporter to emit route and neighbor table metrics via rtnetlink
  So that I can observe routing state and ARP/NDP neighbor state without per-prefix or per-MAC cardinality

  Background:
    Given nft_exporter is running with the rtnetlink collector enabled
    And the Linux node has routing table "main" (table id 254) with 100 IPv4 routes of type "unicast" learned via protocol "kernel"
    And the ARP table has 20 IPv4 neighbor entries on "eth0", 15 in state "reachable" and 5 in state "stale"

  Scenario: nft_route_count emits aggregated counts keyed by (table, family, protocol, route_type)
    When a scrape executes
    Then the metric "nft_route_count" is present in the response
    And the series with labels table="main", family="inet", protocol="kernel", route_type="unicast" has value 100
    And no "nft_route_count" series contains a destination, prefix, or gateway label

  Scenario: Multiple route protocols are aggregated into separate series
    Given the routing table additionally contains 5 IPv4 routes of type "unicast" via protocol "static"
    When a scrape executes
    Then the metric "nft_route_count" with labels table="main", family="inet", protocol="static", route_type="unicast" has value 5
    And the metric "nft_route_count" with labels table="main", family="inet", protocol="kernel", route_type="unicast" has value 100

  Scenario: IPv6 routes are emitted as a separate family
    Given the routing table has 50 IPv6 routes of type "unicast" via protocol "kernel"
    When a scrape executes
    Then the metric "nft_route_count" with labels table="main", family="inet6", protocol="kernel", route_type="unicast" has value 50

  Scenario: nft_neighbor_count emits aggregated counts keyed by (interface, family, state)
    When a scrape executes
    Then the metric "nft_neighbor_count" is present in the response
    And the series with labels interface="eth0", family="inet", state="reachable" has value 15
    And the series with labels interface="eth0", family="inet", state="stale" has value 5
    And no "nft_neighbor_count" series contains an ip_address or mac_address label

  Scenario: NDP (IPv6 neighbor) entries are emitted with family inet6
    Given the NDP table has 10 IPv6 neighbor entries on "eth0" in state "reachable"
    When a scrape executes
    Then the metric "nft_neighbor_count" with labels interface="eth0", family="inet6", state="reachable" has value 10

  Scenario: Neighbor states cover the full set of kernel NUD states
    Given neighbor entries exist in states: permanent, noarp, reachable, stale, delay, probe, failed, none
    When a scrape executes
    Then the metric "nft_neighbor_count" is present for each of those states that has at least one entry

  Scenario: Route count does not regress to per-destination emission under large routing table
    Given the routing table "main" has 100,000 IPv4 unicast routes via protocol "bgp"
    When a scrape executes
    Then the total number of "nft_route_count" series is at most 480
    And the series with labels table="main", family="inet", protocol="bgp", route_type="unicast" has value 100000
