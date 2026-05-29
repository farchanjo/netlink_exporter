Feature: Traffic control and qdisc metrics (traffic-control subsystem)
  As a Prometheus operator
  I want nft_exporter to emit TC qdisc, class, and filter metrics
  So that I can observe queuing discipline statistics decoded from TCA_STATS2 attributes

  Background:
    Given nft_exporter is running with the traffic_control collector enabled
    And "eth0" has a root qdisc of kind "htb" with handle "1:0" and parent "ffff:ffff"
    And "eth0" has an ingress qdisc of kind "ingress" with handle "ffff:0" and parent "ffff:ffff"
    And the "1:0" htb qdisc has one class with handle "1:10", parent "1:0", kind "htb"
    And the "1:0" qdisc has one filter of kind "flower" with handle "0x1", direction "egress"

  Scenario: nft_tc_qdisc_info is emitted with correct labels for each qdisc
    When a scrape executes
    Then the metric "nft_tc_qdisc_info" is present for interface "eth0" and handle "1:0"
    And the "nft_tc_qdisc_info" series carries labels:
      | label     | value   |
      | interface | eth0    |
      | handle    | 1:0     |
      | parent    | ffff:ffff |
      | kind      | htb     |
    And the value of "nft_tc_qdisc_info" for that qdisc is 1

  Scenario: nft_tc_qdisc_bytes_total is emitted from TCA_STATS2 gnet_stats_basic bytes
    When a scrape executes
    Then the metric "nft_tc_qdisc_bytes_total" with labels interface="eth0", handle="1:0", kind="htb" is present
    And the value is greater than or equal to 0

  Scenario: nft_tc_qdisc_packets_total is emitted from gnet_stats_basic packets
    When a scrape executes
    Then the metric "nft_tc_qdisc_packets_total" with labels interface="eth0", handle="1:0", kind="htb" is present

  Scenario: nft_tc_qdisc_drops_total is emitted from gnet_stats_queue drops
    When a scrape executes
    Then the metric "nft_tc_qdisc_drops_total" with labels interface="eth0", handle="1:0", kind="htb" is present

  Scenario: nft_tc_qdisc_overlimits_total is emitted per qdisc
    When a scrape executes
    Then the metric "nft_tc_qdisc_overlimits_total" with labels interface="eth0", handle="1:0", kind="htb" is present

  Scenario: nft_tc_qdisc_backlog_bytes is emitted as a gauge
    When a scrape executes
    Then the metric "nft_tc_qdisc_backlog_bytes" with labels interface="eth0", handle="1:0", kind="htb" is present
    And the value is greater than or equal to 0

  Scenario: nft_tc_class_bytes_total is emitted with handle, parent, and kind labels
    When a scrape executes
    Then the metric "nft_tc_class_bytes_total" with labels interface="eth0", handle="1:10", parent="1:0", kind="htb" is present

  Scenario: nft_tc_class_packets_total is emitted for each traffic class
    When a scrape executes
    Then the metric "nft_tc_class_packets_total" with labels interface="eth0", handle="1:10", parent="1:0", kind="htb" is present

  Scenario: nft_tc_class_drops_total is emitted for each traffic class
    When a scrape executes
    Then the metric "nft_tc_class_drops_total" with labels interface="eth0", handle="1:10", parent="1:0", kind="htb" is present

  Scenario: nft_tc_filter_packets_total is emitted with direction label
    When a scrape executes
    Then the metric "nft_tc_filter_packets_total" with labels interface="eth0", kind="flower", direction="egress" is present
    And the value is greater than or equal to 0

  Scenario: nft_tc_filter_bytes_total is emitted with direction label
    When a scrape executes
    Then the metric "nft_tc_filter_bytes_total" with labels interface="eth0", kind="flower", direction="egress" is present

  Scenario: Ingress qdisc is emitted with correct parent handle
    When a scrape executes
    Then the metric "nft_tc_qdisc_info" with labels interface="eth0", handle="ffff:0", kind="ingress" is present
    And the "parent" label value is "ffff:ffff"
