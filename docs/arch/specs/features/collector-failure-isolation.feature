Feature: Collector failure isolation
  As a system operator
  I want a failing collector to be isolated
  So that healthy collectors still emit their metrics and the failure is observable

  Background:
    Given nft_exporter is running with all six collectors enabled
    And the previous scrape succeeded for all collectors

  Scenario: One collector error leaves other collectors' metrics present
    Given the nftables collector returns a netlink error during collection
    When a scrape executes
    Then the response body includes metrics from the rtnetlink collector
    And the response body includes metrics from the traffic_control collector
    And the response body includes metrics from the conntrack collector
    And the response body includes metrics from the sock_diag collector
    And the response body includes metrics from the ethtool collector
    And the response body does NOT include fresh nftables metrics

  Scenario: Failed collector sets nft_scrape_collector_success to 0
    Given the conntrack collector returns an error during collection
    When a scrape executes
    Then the metric "nft_scrape_collector_success" with label collector="conntrack" has value 0
    And the metric "nft_scrape_collector_success" with label collector="rtnetlink" has value 1

  Scenario: Failed collector increments nft_scrape_collector_error_total
    Given the sock_diag collector returns a netlink_permission_denied error
    When a scrape executes
    Then the metric "nft_scrape_collector_error_total" with labels collector="sock_diag" and reason="netlink_permission_denied" is incremented by 1

  Scenario: Collector panic is caught and isolated via catch-unwind
    Given the ethtool collector panics during collection
    When a scrape executes
    Then the metric "nft_scrape_collector_success" with label collector="ethtool" has value 0
    And the metric "nft_scrape_collector_error_total" with labels collector="ethtool" and reason="panic" is incremented by 1
    And the response body includes metrics from the rtnetlink collector
    And the response body includes metrics from the conntrack collector

  Scenario: Timed-out collector does not block remaining collectors
    Given the traffic_control collector exceeds the scrape timeout of 9800 ms
    When a scrape executes
    Then the metric "nft_scrape_collector_success" with label collector="traffic_control" has value 0
    And the metric "nft_scrape_collector_error_total" with labels collector="traffic_control" and reason="netlink_timeout" is incremented by 1
    And the overall scrape duration is less than 9800 ms plus a 200 ms tolerance
    And the response body includes metrics from the rtnetlink collector

  Scenario: Stale snapshot is served after a transient collector failure
    Given the conntrack collector succeeded on scrape N-1
    And the conntrack collector fails on scrape N
    When scrape N response is rendered
    Then the response body includes the conntrack metrics from scrape N-1
    And the metric "nft_exporter_snapshot_age_seconds" with label collector="conntrack" is greater than 0.0

  Scenario: Repeated collector failures increment error counter monotonically
    Given the rtnetlink collector fails on three consecutive scrapes
    When the third scrape completes
    Then the metric "nft_scrape_collector_error_total" with label collector="rtnetlink" has value at least 3
