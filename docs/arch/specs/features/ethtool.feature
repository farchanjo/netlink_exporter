Feature: Ethtool metrics (ethtool subsystem)
  As a Prometheus operator
  I want nft_exporter to emit ethtool NIC statistics and link settings via ETHTOOL genetlink
  So that I can observe driver-level counters, link speed, PAUSE frames, and FEC codewords

  Background:
    Given nft_exporter is running with the ethtool collector enabled
    And the kernel version is at least 5.12
    And "eth0" supports the ETHTOOL genetlink family with ETHTOOL_MSG_STATS_GET
    And "eth0" reports link speed 10000 Mbps, duplex full, autoneg off, port fibre
    And "eth0" reports FEC with 2 active lanes

  Scenario: nft_ethtool_stat emits per-(interface, stat) gauges
    Given "eth0" reports an ethtool statistic "rx_packets" with value 987654
    When a scrape executes
    Then the metric "nft_ethtool_stat" with labels interface="eth0" and stat="rx_packets" has value 987654

  Scenario: nft_ethtool_stat uses only interface and stat labels
    When a scrape executes
    Then no "nft_ethtool_stat" series contains any label besides interface and stat

  Scenario: nft_ethtool_link_info is emitted with correct labels
    When a scrape executes
    Then the metric "nft_ethtool_link_info" with labels interface="eth0", speed="10000", duplex="full", autoneg="off", port="fibre" has value 1

  Scenario: nft_ethtool_pause_rx_total is emitted for interfaces with PAUSE support
    Given "eth0" reports 120 received PAUSE frames
    When a scrape executes
    Then the metric "nft_ethtool_pause_rx_total" with label interface="eth0" has value 120

  Scenario: nft_ethtool_pause_tx_total is emitted for interfaces with PAUSE support
    Given "eth0" reports 45 transmitted PAUSE frames
    When a scrape executes
    Then the metric "nft_ethtool_pause_tx_total" with label interface="eth0" has value 45

  Scenario: nft_ethtool_fec_corrected_total is emitted per lane when FEC is active
    Given FEC lane 0 reports 300 corrected codeword blocks and lane 1 reports 75
    When a scrape executes
    Then the metric "nft_ethtool_fec_corrected_total" with labels interface="eth0" and lane="0" has value 300
    And the metric "nft_ethtool_fec_corrected_total" with labels interface="eth0" and lane="1" has value 75

  Scenario: nft_ethtool_fec_corrected_total is not emitted when FEC is not active
    Given "eth1" has FEC disabled
    When a scrape executes
    Then no "nft_ethtool_fec_corrected_total" series exists with label interface="eth1"

  Scenario: EOPNOTSUPP from driver causes ethtool metrics to be skipped for that interface
    Given "eth2" returns EOPNOTSUPP for ETHTOOL_MSG_STATS_GET
    When a scrape executes
    Then no "nft_ethtool_stat" series exists with label interface="eth2"
    And the metric "nft_scrape_collector_error_total" with labels collector="ethtool" and reason="kernel_unsupported" is not incremented for the interface-level probe failure

  Scenario: Ethtool collector failure sets nft_scrape_collector_success to 0
    Given the ETHTOOL genetlink family resolution returns ENOENT
    When a scrape executes
    Then the metric "nft_scrape_collector_success" with label collector="ethtool" has value 0
    And the metric "nft_scrape_collector_error_total" with labels collector="ethtool" and reason="kernel_unsupported" is incremented by 1

  Scenario: Ethtool stats are emitted as gauges not counters because they reset on interface down
    When a scrape executes
    Then the OpenMetrics type declaration for "nft_ethtool_stat" is "gauge"

  Scenario: Multiple interfaces each emit their own nft_ethtool_link_info series
    Given "eth1" reports link speed 1000 Mbps, duplex full, autoneg on, port tp
    When a scrape executes
    Then the metric "nft_ethtool_link_info" with labels interface="eth0" is present
    And the metric "nft_ethtool_link_info" with labels interface="eth1" and speed="1000" and autoneg="on" is present
