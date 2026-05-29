Feature: Nftables metrics (nftables subsystem)
  As a Prometheus operator
  I want nft_exporter to emit nftables counter, chain, and set metrics via nfnetlink
  So that I can observe firewall rule match rates and table topology

  Background:
    Given nft_exporter is running with the nftables collector enabled
    And an nftables table named "filter" of family "inet" exists
    And the "filter" table contains a chain named "input" of type "filter", hook "input", priority 0, policy "drop"
    And the "input" chain contains a rule with comment "allow-ssh" and counter expression tracking 500 packets and 30000 bytes
    And the "filter" table contains a named counter object "ssh-traffic" with 1000 packets and 60000 bytes
    And the "filter" table contains a named set "blocked-ips" of type "ipv4_addr" with 250 elements

  Scenario: nft_table_info is emitted for each nftables table
    When a scrape executes
    Then the metric "nft_table_info" with labels table="filter" and family="inet" has value 1

  Scenario: nft_chain_info is emitted with correct labels for each chain
    When a scrape executes
    Then the metric "nft_chain_info" with labels table="filter", chain="input", type="filter", hook="input", priority="0", policy="drop" has value 1

  Scenario: nft_rule_counter_bytes_total is emitted for rules with a non-empty comment
    When a scrape executes
    Then the metric "nft_rule_counter_bytes_total" with labels table="filter", chain="input", comment="allow-ssh" has value 30000

  Scenario: nft_rule_counter_packets_total is emitted for rules with a non-empty comment
    When a scrape executes
    Then the metric "nft_rule_counter_packets_total" with labels table="filter", chain="input", comment="allow-ssh" has value 500

  Scenario: Rules without a comment label are not emitted as per-rule time series
    Given the "input" chain contains an anonymous rule with counter but no comment
    When a scrape executes
    Then no "nft_rule_counter_bytes_total" series exists with an empty comment label for that rule

  Scenario: nft_named_counter_bytes_total is emitted for named counter objects
    When a scrape executes
    Then the metric "nft_named_counter_bytes_total" with labels table="filter" and name="ssh-traffic" has value 60000

  Scenario: nft_named_counter_packets_total is emitted for named counter objects
    When a scrape executes
    Then the metric "nft_named_counter_packets_total" with labels table="filter" and name="ssh-traffic" has value 1000

  Scenario: nft_set_elements reports the current element count for each named set
    When a scrape executes
    Then the metric "nft_set_elements" with labels table="filter", name="blocked-ips", type="ipv4_addr" has value 250

  Scenario: Multiple tables and families are emitted as separate nft_table_info series
    Given an additional nftables table named "nat" of family "ip" exists
    When a scrape executes
    Then the metric "nft_table_info" with labels table="filter" and family="inet" has value 1
    And the metric "nft_table_info" with labels table="nat" and family="ip" has value 1

  Scenario: Hook values are within the documented enum
    When a scrape executes
    Then all "nft_chain_info" series have a hook label value in (prerouting, input, forward, output, postrouting, ingress, egress)

  Scenario: Cardinality overflow on anonymous rules increments error counter and suppresses overflow series
    Given the "input" chain contains 600 anonymous rules each with a counter expression
    When a scrape executes
    Then the metric "nft_scrape_collector_error_total" with labels collector="nftables" and reason="cardinality_overflow" is incremented by 1
    And the total number of "nft_rule_counter_bytes_total" series from anonymous rules is at most 500

  Scenario: Nftables collector failure sets nft_scrape_collector_success to 0
    Given the nfnetlink socket returns EPERM during NFT_MSG_GETRULE
    When a scrape executes
    Then the metric "nft_scrape_collector_success" with label collector="nftables" has value 0
    And the metric "nft_scrape_collector_error_total" with labels collector="nftables" and reason="netlink_permission_denied" is incremented by 1
