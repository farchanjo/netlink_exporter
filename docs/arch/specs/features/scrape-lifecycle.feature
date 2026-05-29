Feature: Scrape lifecycle
  As a Prometheus server
  I want to pull GET /metrics from nft_exporter
  So that I receive a valid OpenMetrics exposition within the scrape timeout

  Background:
    Given nft_exporter is running and listening on port 9456
    And all six collectors are enabled: rtnetlink, traffic_control, conntrack, nftables, sock_diag, ethtool
    And the scrape timeout is configured to 9800 ms

  Scenario: Prometheus pull returns 200 with OpenMetrics text within timeout
    When Prometheus issues GET /metrics with Accept: application/openmetrics-text
    Then the HTTP response status is 200
    And the Content-Type header contains "application/openmetrics-text"
    And the response body includes the metric "nft_scrape_duration_seconds"
    And the response body includes the metric "nft_up"
    And the response body includes the metric "nft_build_info"
    And the total wall-clock time from request to response is less than 9800 ms

  Scenario: Scrape lifecycle records per-collector duration telemetry
    When a scrape completes successfully
    Then the metric "nft_scrape_collector_duration_seconds" is present for each label value in (rtnetlink, traffic_control, conntrack, nftables, sock_diag, ethtool)
    And each "nft_scrape_collector_duration_seconds" value is greater than 0.0

  Scenario: Scrape lifecycle records overall duration telemetry
    When a scrape completes successfully
    Then the metric "nft_scrape_duration_seconds" reports a value greater than 0.0
    And "nft_scrape_duration_seconds" is less than or equal to 9.8

  Scenario: Health endpoint returns 200 independently of scrape state
    When a client issues GET /healthz
    Then the HTTP response status is 200

  Scenario: Readiness endpoint returns 200 only after at least one successful scrape
    Given no scrape has completed yet
    When a client issues GET /ready
    Then the HTTP response status is 503
    When a scrape completes successfully
    And a client issues GET /ready
    Then the HTTP response status is 200

  Scenario: Second scrape pull while first is in progress returns 200
    Given a scrape is currently in progress
    When Prometheus issues a second GET /metrics
    Then the HTTP response status is 200
    And the response body contains at least the stale snapshot from the previous successful scrape

  Scenario: nft_up is 1 when all critical collectors succeed
    Given the rtnetlink, conntrack, and nftables collectors all succeed
    When a scrape completes
    Then the metric "nft_up" has value 1

  Scenario: nft_up is 0 when at least one critical collector fails
    Given the conntrack collector returns an error
    When a scrape completes
    Then the metric "nft_up" has value 0
