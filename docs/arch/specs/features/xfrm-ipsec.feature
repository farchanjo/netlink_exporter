Feature: XFRM/IPsec metrics (xfrm-ipsec subsystem)
  As a Prometheus operator
  I want nft_exporter to emit IPsec SA count, SP count, SAD/SPD watermarks,
  and XFRM error counters via NETLINK_XFRM and /proc/net/xfrm_stat
  So that I can observe IPsec subsystem health without per-SA or per-SP cardinality explosion

  Background:
    Given nft_exporter is running with the xfrm-ipsec collector enabled
    And the xfrm_user kernel module is loaded
    And /proc/net/xfrm_stat is readable

  Scenario: nft_scrape_collector_available is 1 when xfrm_user is loaded
    When a scrape executes
    Then the metric "nft_scrape_collector_available" with label collector="xfrm-ipsec" has value 1

  Scenario: nft_xfrm_sa_count emits aggregated gauge by (proto, mode)
    Given the SAD contains 4 ESP tunnel-mode SAs and 2 AH transport-mode SAs
    When a scrape executes
    Then the metric "nft_xfrm_sa_count" with labels proto="esp" and mode="tunnel" has value 4
    And the metric "nft_xfrm_sa_count" with labels proto="ah" and mode="transport" has value 2
    And no "nft_xfrm_sa_count" series contains a per-SA label such as spi, src_ip, or dst_ip

  Scenario: nft_xfrm_sp_count emits aggregated gauge by (dir, action)
    Given the SPD contains 3 outbound allow policies and 1 inbound allow policy
    When a scrape executes
    Then the metric "nft_xfrm_sp_count" with labels dir="out" and action="allow" has value 3
    And the metric "nft_xfrm_sp_count" with labels dir="in" and action="allow" has value 1
    And no "nft_xfrm_sp_count" series contains a per-policy label such as src_prefix or dst_prefix

  Scenario: nft_xfrm_sad_hash_count and nft_xfrm_sad_hash_max reflect GETSADINFO
    Given XFRM_MSG_GETSADINFO reports sadhcnt=6 and sadhmcnt=1024
    When a scrape executes
    Then the metric "nft_xfrm_sad_hash_count" has value 6
    And the metric "nft_xfrm_sad_hash_max" has value 1024
    And both metrics have no labels other than those defined in the metric contract

  Scenario: nft_xfrm_spd_hash_count and nft_xfrm_spd_hash_max reflect GETSPDINFO
    Given XFRM_MSG_GETSPDINFO reports spdhcnt=4 and spdhmcnt=512
    When a scrape executes
    Then the metric "nft_xfrm_spd_hash_count" has value 4
    And the metric "nft_xfrm_spd_hash_max" has value 512

  Scenario: nft_xfrm_stat_total emits all /proc/net/xfrm_stat counters with bounded labels
    Given /proc/net/xfrm_stat reports XfrmInError=0 XfrmOutPolBlock=3 XfrmInNoStates=17
    When a scrape executes
    Then the metric "nft_xfrm_stat_total" with label counter="XfrmInError" has value 0
    And the metric "nft_xfrm_stat_total" with label counter="XfrmOutPolBlock" has value 3
    And the metric "nft_xfrm_stat_total" with label counter="XfrmInNoStates" has value 17
    And no "nft_xfrm_stat_total" series has a counter label outside the 26-entry kernel ABI set
    And the total number of "nft_xfrm_stat_total" series is exactly 26

  Scenario: collector reports available=0 gracefully when xfrm_user is absent
    Given the xfrm_user kernel module is not loaded
    And opening a NETLINK_XFRM socket returns EPROTONOSUPPORT
    When a scrape executes
    Then the metric "nft_scrape_collector_available" with label collector="xfrm-ipsec" has value 0
    And no "nft_xfrm_sa_count" series is present in the response
    And no "nft_xfrm_sp_count" series is present in the response
    And no "nft_xfrm_sad_hash_count" series is present in the response
    And no "nft_xfrm_spd_hash_count" series is present in the response
    And no "nft_xfrm_stat_total" series is present in the response
    And the metric "nft_scrape_collector_success" with label collector="xfrm-ipsec" has value 1
    And the metric "nft_scrape_collector_error_total" with labels collector="xfrm-ipsec" is not incremented

  Scenario: collector reports available=0 gracefully when EPERM is returned at startup
    Given the NETLINK_XFRM socket probe returns EPERM
    When a scrape executes
    Then the metric "nft_scrape_collector_available" with label collector="xfrm-ipsec" has value 0
    And no XFRM metric series other than nft_scrape_collector_available is emitted
    And the metric "nft_scrape_collector_success" with label collector="xfrm-ipsec" has value 1

  Scenario: bounded cardinality — sa_count label dimensions do not exceed product bound
    Given the SAD contains SAs with all combinations of proto in (esp, ah, comp) and mode in (tunnel, transport)
    When a scrape executes
    Then the total number of "nft_xfrm_sa_count" series does not exceed 16

  Scenario: bounded cardinality — sp_count label dimensions do not exceed product bound
    Given the SPD contains policies with all combinations of dir in (in, fwd, out) and action in (allow, block)
    When a scrape executes
    Then the total number of "nft_xfrm_sp_count" series does not exceed 6

  Scenario: xfrm-ipsec collector failure due to mid-scrape netlink error isolates to this collector
    Given the NETLINK_XFRM socket returns ENOBUFS during the XFRM_MSG_GETSA dump
    When a scrape executes
    Then the metric "nft_scrape_collector_success" with label collector="xfrm-ipsec" has value 0
    And the metric "nft_scrape_collector_error_total" with labels collector="xfrm-ipsec" and reason="netlink_truncated" is incremented by 1
    And the metric "nft_scrape_collector_success" with label collector="rtnetlink" has value 1
    And the metric "nft_scrape_collector_success" with label collector="conntrack" has value 1

  Scenario: empty SAD and SPD produce zero-value gauges not absent metrics
    Given the SAD contains 0 SAs
    And the SPD contains 0 policies
    When a scrape executes
    Then nft_scrape_collector_available with label collector="xfrm-ipsec" has value 1
    And "nft_xfrm_sad_hash_count" is present with value 0
    And "nft_xfrm_spd_hash_count" is present with value 0
    And no "nft_xfrm_sa_count" series is present
    And no "nft_xfrm_sp_count" series is present
