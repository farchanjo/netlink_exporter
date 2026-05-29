Feature: Link and address metrics (rtnetlink subsystem)
  As a Prometheus operator
  I want nft_exporter to emit link and address metrics via rtnetlink
  So that I can observe interface state, traffic counters, and IP address assignments

  Background:
    Given nft_exporter is running with the rtnetlink collector enabled
    And the Linux node has at least one network interface named "eth0"
    And "eth0" has operstate "up", link_type "ether", MTU 1500, and speed 10000 Mbps
    And "eth0" has one IPv4 address "192.168.1.10/24" with scope "global"
    And "eth0" has one IPv6 address "fd00::1/64" with scope "global"

  Scenario: nft_link_info is emitted with correct labels for each interface
    When a scrape executes
    Then the metric "nft_link_info" is present for interface "eth0"
    And the "nft_link_info" series for "eth0" carries labels:
      | label      | value    |
      | interface  | eth0     |
      | operstate  | up       |
      | link_type  | ether    |
    And the value of "nft_link_info" for "eth0" is 1

  Scenario: Link MTU gauge is emitted with correct value
    When a scrape executes
    Then the metric "nft_link_mtu_bytes" for interface "eth0" has value 1500

  Scenario: Link speed gauge is emitted in bits per second
    When a scrape executes
    Then the metric "nft_link_speed_bits" for interface "eth0" has value 10000000000

  Scenario: Link receive and transmit byte counters are present
    When a scrape executes
    Then the metric "nft_link_receive_bytes_total" is present for interface "eth0"
    And the metric "nft_link_transmit_bytes_total" is present for interface "eth0"
    And both counter values are greater than or equal to 0

  Scenario: Link packet counters are present
    When a scrape executes
    Then the metric "nft_link_receive_packets_total" is present for interface "eth0"
    And the metric "nft_link_transmit_packets_total" is present for interface "eth0"

  Scenario: Link error and drop counters are present
    When a scrape executes
    Then the metric "nft_link_receive_errors_total" is present for interface "eth0"
    And the metric "nft_link_transmit_errors_total" is present for interface "eth0"
    And the metric "nft_link_receive_dropped_total" is present for interface "eth0"
    And the metric "nft_link_transmit_dropped_total" is present for interface "eth0"

  Scenario: nft_address_info is emitted for each configured IP address
    When a scrape executes
    Then the metric "nft_address_info" is present for the IPv4 address on "eth0"
    And the "nft_address_info" series carries labels:
      | label         | value         |
      | interface     | eth0          |
      | family        | inet          |
      | address       | 192.168.1.10  |
      | prefix_length | 24            |
      | scope         | global        |
    And the value of "nft_address_info" for that address is 1
    And the metric "nft_address_info" is present for the IPv6 address on "eth0" with family="inet6"

  Scenario: nft_address_count is emitted per interface and family
    When a scrape executes
    Then the metric "nft_address_count" with labels interface="eth0" and family="inet" has value 1
    And the metric "nft_address_count" with labels interface="eth0" and family="inet6" has value 1

  Scenario: Link speed is -1 when the kernel reports an unknown speed
    Given "lo" loopback interface has no reported speed
    When a scrape executes
    Then the metric "nft_link_speed_bits" for interface "lo" has value -1

  Scenario: All link metrics are labeled with interface only (no MAC, no IP labels)
    When a scrape executes
    Then no series in "nft_link_receive_bytes_total" contains a mac_address or ip_address label
    And no series in "nft_link_transmit_bytes_total" contains a mac_address or ip_address label
