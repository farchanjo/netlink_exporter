Feature: Drop-monitor metrics (NET_DM subsystem)
  As a Prometheus operator
  I want nft_exporter to emit per-reason packet drop counters via the NET_DM generic-netlink family
  So that I can observe kernel software and hardware drop events aggregated by reason without per-packet cardinality

  Background:
    Given nft_exporter is running with the drop-monitor collector enabled
    And the kernel version is at least 5.17
    And the drop_monitor kernel module is loaded
    And the NET_DM genetlink family is registered with group NET_DM_GRP_ALERT
    And the exporter has issued NET_DM_CMD_CONFIG with summary alert mode
    And the exporter has issued NET_DM_CMD_START successfully

  Scenario: nft_drop_packets_total is emitted per (reason, origin) when drops are reported
    Given the kernel sends NET_DM_CMD_ALERT with reason="NET_DM_REASON_TC_INGRESS" origin="sw" dropped=500
    When a scrape executes
    Then the metric "nft_drop_packets_total" with labels reason="NET_DM_REASON_TC_INGRESS" and origin="sw" has value 500

  Scenario: nft_drop_packets_total accumulates across multiple alert frames in one scrape interval
    Given the kernel sends NET_DM_CMD_ALERT with reason="NET_DM_REASON_CONNTRACK" origin="sw" dropped=200
    And the kernel sends a second NET_DM_CMD_ALERT with reason="NET_DM_REASON_CONNTRACK" origin="sw" dropped=50
    When a scrape executes
    Then the metric "nft_drop_packets_total" with labels reason="NET_DM_REASON_CONNTRACK" and origin="sw" has value 250

  Scenario: hardware drop events are emitted with origin="hw"
    Given the kernel sends NET_DM_CMD_ALERT with hw_trap_name="blackhole_route" origin="hw" dropped=12
    When a scrape executes
    Then the metric "nft_drop_packets_total" with labels reason="blackhole_route" and origin="hw" has value 12

  Scenario: multiple distinct reasons each produce a separate series
    Given the kernel sends NET_DM_CMD_ALERT with reason="NET_DM_REASON_TC_INGRESS" origin="sw" dropped=300
    And the kernel sends NET_DM_CMD_ALERT with reason="NET_DM_REASON_IP_NOPROTO" origin="sw" dropped=10
    When a scrape executes
    Then the metric "nft_drop_packets_total" with labels reason="NET_DM_REASON_TC_INGRESS" and origin="sw" has value 300
    And the metric "nft_drop_packets_total" with labels reason="NET_DM_REASON_IP_NOPROTO" and origin="sw" has value 10

  Scenario: nft_drop_packets_total uses only reason and origin labels
    When a scrape executes
    Then no "nft_drop_packets_total" series contains any label besides reason and origin

  Scenario: nft_drop_packets_total does not contain per-packet or per-address labels
    When a scrape executes
    Then no "nft_drop_packets_total" series contains a label named "src_ip"
    And no "nft_drop_packets_total" series contains a label named "dst_ip"
    And no "nft_drop_packets_total" series contains a label named "src_port"
    And no "nft_drop_packets_total" series contains a label named "dst_port"
    And no "nft_drop_packets_total" series contains a label named "flow_id"

  Scenario: nft_scrape_collector_available is 1 when drop_monitor module is loaded
    When a scrape executes
    Then the metric "nft_scrape_collector_available" with label collector="drop-monitor" has value 1

  Scenario: collector reports available=0 gracefully when drop_monitor module is absent
    Given the drop_monitor kernel module is not loaded
    And CTRL_CMD_GETFAMILY for "NET_DM" returns ENOENT
    When a scrape executes
    Then the metric "nft_scrape_collector_available" with label collector="drop-monitor" has value 0
    And no "nft_drop_packets_total" series is emitted
    And the metric "nft_scrape_collector_success" with label collector="drop-monitor" has value 1

  Scenario: collector emits no nft_drop_packets_total series on kernel older than 5.17
    Given the drop_monitor module is loaded
    And the kernel version is older than 5.17
    And NET_DM_CMD_ALERT frames do not include NET_DM_ATTR_REASON strings
    When a scrape executes
    Then the metric "nft_scrape_collector_available" with label collector="drop-monitor" has value 1
    And no "nft_drop_packets_total" series is emitted

  Scenario: nft_drop_packets_total cardinality is bounded by the drop-reason enum
    Given the kernel sends NET_DM_CMD_ALERT frames with 80 distinct reason strings
    When a scrape executes
    Then the total number of "nft_drop_packets_total" series does not exceed 220

  Scenario: zero-drop intervals produce no series for that reason
    Given the kernel sent reason="NET_DM_REASON_TC_INGRESS" dropped=100 in the previous interval
    And the kernel sends no NET_DM_CMD_ALERT frames for reason="NET_DM_REASON_TC_INGRESS" in the current interval
    When a scrape executes
    Then no "nft_drop_packets_total" series with reason="NET_DM_REASON_TC_INGRESS" has value 0 emitted for this interval

  Scenario: drop-monitor collector failure isolates from other collectors
    Given NET_DM_CMD_START returns EPERM
    When a scrape executes
    Then the metric "nft_scrape_collector_success" with label collector="drop-monitor" has value 0
    And the metric "nft_scrape_collector_error_total" with labels collector="drop-monitor" and reason="netlink_permission_denied" is incremented by 1
    And the metric "nft_scrape_collector_success" with label collector="rtnetlink" has value 1
