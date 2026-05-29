Feature: Conntrack-expectations metrics (conntrack-expectations subsystem)
  As a Prometheus operator
  I want nft_exporter to emit conntrack expectation metrics aggregated by (l4proto, helper)
  So that I can observe helper-module expectation activity without per-expectation cardinality explosion

  Background:
    Given nft_exporter is running with the conntrack-expectations collector enabled
    And the nf_conntrack kernel module is loaded

  # ---------------------------------------------------------------------------
  # Subsystem present
  # ---------------------------------------------------------------------------

  Scenario: nft_conntrack_expectation_entries reflects active expectations per (l4proto, helper)
    Given the ctnetlink expectations table contains 12 entries with l4proto="tcp" and helper="ftp"
    And the ctnetlink expectations table contains 3 entries with l4proto="udp" and helper="tftp"
    When a scrape executes
    Then the metric "nft_conntrack_expectation_entries" with labels l4proto="tcp" and helper="ftp" has value 12
    And the metric "nft_conntrack_expectation_entries" with labels l4proto="udp" and helper="tftp" has value 3
    And no "nft_conntrack_expectation_entries" series contains src_ip, dst_ip, src_port, dst_port, or exp_id labels

  Scenario: nft_scrape_collector_available is 1 when the subsystem responds
    Given the IPCTNL_MSG_EXP_GET dump request returns at least one NLMSG_DONE frame
    When a scrape executes
    Then the metric "nft_scrape_collector_available" with label collector="conntrack-expectations" has value 1

  Scenario: nft_conntrack_expectation_new_total is reported from per-CPU stats sum
    Given the kernel reports a cumulative new-expectations count of 750 across all CPUs
    When a scrape executes
    Then the metric "nft_conntrack_expectation_new_total" has value 750

  Scenario: nft_conntrack_expectation_delete_total is present
    When a scrape executes
    Then the metric "nft_conntrack_expectation_delete_total" is present in the response
    And the value is greater than or equal to 0

  Scenario: nft_conntrack_expectation_new_failed_total is present
    When a scrape executes
    Then the metric "nft_conntrack_expectation_new_failed_total" is present in the response
    And the value is greater than or equal to 0

  Scenario: Expectations with no helper name are aggregated under helper=""
    Given the ctnetlink expectations table contains 5 entries without a CTA_EXPECT_HELPER_NAME attribute
    And those entries have l4proto="tcp"
    When a scrape executes
    Then the metric "nft_conntrack_expectation_entries" with labels l4proto="tcp" and helper="" has value 5

  Scenario: Bounded cardinality is enforced across all l4proto and helper combinations
    Given the ctnetlink expectations table contains entries spanning at most 8 l4proto values
    And at most 20 distinct helper name values
    When a scrape executes
    Then the total number of "nft_conntrack_expectation_entries" time series is at most 160

  # ---------------------------------------------------------------------------
  # Cardinality overflow guard
  # ---------------------------------------------------------------------------

  Scenario: Cardinality overflow guard activates when distinct (l4proto, helper) keys exceed 256
    Given the ctnetlink expectations table contains entries producing 257 distinct (l4proto, helper) key combinations
    When a scrape executes
    Then the metric "nft_scrape_collector_error_total" with labels collector="conntrack-expectations" and reason="cardinality_overflow" is incremented by 1
    And the metric "nft_scrape_collector_success" with label collector="conntrack-expectations" has value 0
    And no "nft_conntrack_expectation_entries" series is emitted for the overflowed scrape

  # ---------------------------------------------------------------------------
  # Subsystem absent (runtime gate)
  # ---------------------------------------------------------------------------

  Scenario: Collector reports available=0 gracefully when the subsystem is absent
    Given the IPCTNL_MSG_EXP_GET dump request returns ENOENT
    When a scrape executes
    Then the metric "nft_scrape_collector_available" with label collector="conntrack-expectations" has value 0
    And no "nft_conntrack_expectation_entries" series is emitted
    And no "nft_conntrack_expectation_new_total" series is emitted
    And the metric "nft_scrape_collector_success" with label collector="conntrack-expectations" has value 1

  Scenario: Collector reports available=0 gracefully when CAP_NET_ADMIN is missing for the expectations subsystem
    Given the IPCTNL_MSG_EXP_GET dump request returns EPERM
    When a scrape executes
    Then the metric "nft_scrape_collector_available" with label collector="conntrack-expectations" has value 0
    And the metric "nft_scrape_collector_success" with label collector="conntrack-expectations" has value 1

  # ---------------------------------------------------------------------------
  # Isolation from the conntrack collector
  # ---------------------------------------------------------------------------

  Scenario: Failure of the conntrack-expectations collector does not affect the conntrack collector
    Given the IPCTNL_MSG_EXP_GET dump request returns ENOENT
    And the nf_conntrack main table has 100 TCP established flows
    When a scrape executes
    Then the metric "nft_conntrack_entries" with labels protocol="tcp" and state="established" has value 100
    And the metric "nft_scrape_collector_success" with label collector="conntrack" has value 1

  Scenario: Conntrack-expectations collector can be disabled independently
    Given the exporter configuration has collectors.enabled not containing "conntrack-expectations"
    When a scrape executes
    Then no "nft_conntrack_expectation_entries" series is emitted
    And no "nft_scrape_collector_available" series with label collector="conntrack-expectations" is emitted
