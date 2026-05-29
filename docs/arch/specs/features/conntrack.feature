Feature: Conntrack metrics (conntrack subsystem)
  As a Prometheus operator
  I want nft_exporter to emit conntrack metrics aggregated by (protocol, state, direction)
  So that I can observe connection tracking health without per-flow cardinality explosion

  Background:
    Given nft_exporter is running with the conntrack collector enabled
    And the nf_conntrack kernel module is loaded
    And the conntrack table has 200 TCP flows in state "established"
    And the conntrack table has 50 UDP flows in state "new"
    And nf_conntrack_max is set to 131072

  Scenario: nft_conntrack_entries emits aggregated gauge per (protocol, state)
    When a scrape executes
    Then the metric "nft_conntrack_entries" with labels protocol="tcp" and state="established" has value 200
    And the metric "nft_conntrack_entries" with labels protocol="udp" and state="new" has value 50
    And no "nft_conntrack_entries" series contains src_ip, dst_ip, src_port, dst_port, or flow_id labels

  Scenario: nft_conntrack_max_entries reflects nf_conntrack_max
    When a scrape executes
    Then the metric "nft_conntrack_max_entries" has value 131072

  Scenario: nft_conntrack_bytes_total is aggregated per (protocol, direction)
    Given the 200 TCP established flows each report 5000 bytes in the original direction
    When a scrape executes
    Then the metric "nft_conntrack_bytes_total" with labels protocol="tcp" and direction="original" has value at least 1000000
    And the metric "nft_conntrack_bytes_total" with labels protocol="tcp" and direction="reply" is present
    And no "nft_conntrack_bytes_total" series contains a per-flow label

  Scenario: nft_conntrack_packets_total is aggregated per (protocol, direction)
    When a scrape executes
    Then the metric "nft_conntrack_packets_total" with labels protocol="tcp" and direction="original" is present
    And the metric "nft_conntrack_packets_total" with labels protocol="udp" and direction="original" is present

  Scenario: nft_conntrack_insert_total is reported from per-CPU stats sum
    Given the kernel reports a cumulative insert count of 4500 across all CPUs
    When a scrape executes
    Then the metric "nft_conntrack_insert_total" has value 4500

  Scenario: nft_conntrack_drop_total is present
    When a scrape executes
    Then the metric "nft_conntrack_drop_total" is present in the response
    And the value is greater than or equal to 0

  Scenario: nft_conntrack_early_drop_total is present
    When a scrape executes
    Then the metric "nft_conntrack_early_drop_total" is present in the response

  Scenario: nft_conntrack_found_total is reported from per-CPU stats sum
    When a scrape executes
    Then the metric "nft_conntrack_found_total" is present in the response
    And the value is greater than or equal to 0

  Scenario: nft_conntrack_invalid_total is present
    When a scrape executes
    Then the metric "nft_conntrack_invalid_total" is present in the response

  Scenario: ICMP flows are aggregated under their own protocol label
    Given the conntrack table has 10 ICMP flows in state "established"
    When a scrape executes
    Then the metric "nft_conntrack_entries" with labels protocol="icmp" and state="established" has value 10

  Scenario: Conntrack collector failure sets nft_scrape_collector_success to 0
    Given the ctnetlink socket returns EPERM during the dump request
    When a scrape executes
    Then the metric "nft_scrape_collector_success" with label collector="conntrack" has value 0
    And the metric "nft_scrape_collector_error_total" with labels collector="conntrack" and reason="netlink_permission_denied" is incremented by 1
