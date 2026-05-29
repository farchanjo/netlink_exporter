Feature: Devlink metrics (devlink genetlink subsystem)
  As a Prometheus operator
  I want nft_exporter to emit devlink device health and port metrics via the devlink genetlink family
  So that I can observe SmartNIC and switch-ASIC health reporter errors, recovery counts, and state

  Background:
    Given nft_exporter is running with the devlink collector enabled
    And the devlink genetlink family resolves successfully on this host
    And the host has one devlink device with bus_name="pci" and dev_name="0000:03:00.0"
    And that device has one port with port_index=0 and port_type="eth"
    And that device exposes a health reporter named "fw_fatal"

  Scenario: nft_scrape_collector_available is 1 when the devlink family is present
    When a scrape executes
    Then the metric "nft_scrape_collector_available" with label collector="devlink" has value 1

  Scenario: nft_devlink_device_info is emitted with correct labels
    When a scrape executes
    Then the metric "nft_devlink_device_info" with labels bus_name="pci" and dev_name="0000:03:00.0" has value 1

  Scenario: nft_devlink_port_info is emitted with correct labels
    When a scrape executes
    Then the metric "nft_devlink_port_info" with labels bus_name="pci" and dev_name="0000:03:00.0" and port="0" has value 1

  Scenario: nft_devlink_health_reporter_error_total reflects cumulative error count
    Given the "fw_fatal" reporter on device "0000:03:00.0" reports 3 error events
    When a scrape executes
    Then the metric "nft_devlink_health_reporter_error_total" with labels bus_name="pci" and dev_name="0000:03:00.0" and reporter="fw_fatal" has value 3

  Scenario: nft_devlink_health_reporter_recover_total reflects cumulative recovery count
    Given the "fw_fatal" reporter on device "0000:03:00.0" reports 1 recovery event
    When a scrape executes
    Then the metric "nft_devlink_health_reporter_recover_total" with labels bus_name="pci" and dev_name="0000:03:00.0" and reporter="fw_fatal" has value 1

  Scenario: nft_devlink_health_reporter_state carries the state label and value 1
    Given the "fw_fatal" reporter state is "healthy"
    When a scrape executes
    Then the metric "nft_devlink_health_reporter_state" with labels bus_name="pci" and dev_name="0000:03:00.0" and reporter="fw_fatal" and state="healthy" has value 1

  Scenario: Unknown reporter state maps to label "unknown" and does not emit a raw integer
    Given the kernel reports reporter state value 99 for an unknown future state
    When a scrape executes
    Then the metric "nft_devlink_health_reporter_state" with labels reporter="fw_fatal" and state="unknown" is present
    And no "nft_devlink_health_reporter_state" series carries a numeric state label

  Scenario: Devlink collector reports available=0 gracefully when the subsystem is absent
    Given the devlink genetlink family is not registered on this host
    When a scrape executes
    Then the metric "nft_scrape_collector_available" with label collector="devlink" has value 0
    And no "nft_devlink_device_info" series exists
    And no "nft_devlink_port_info" series exists
    And no "nft_devlink_health_reporter_error_total" series exists
    And no "nft_devlink_health_reporter_recover_total" series exists
    And no "nft_devlink_health_reporter_state" series exists
    And the metric "nft_scrape_collector_success" with label collector="devlink" has value 1

  Scenario: Devlink collector does not increment error counters when subsystem is absent
    Given the devlink genetlink family is not registered on this host
    When a scrape executes
    Then the metric "nft_scrape_collector_error_total" with labels collector="devlink" and reason="genl_family_unresolved" is not incremented

  Scenario: Bounded cardinality — label set is restricted to bus_name, dev_name, reporter, and state
    When a scrape executes
    Then no "nft_devlink_health_reporter_error_total" series contains any label besides bus_name, dev_name, and reporter
    And no "nft_devlink_health_reporter_state" series contains any label besides bus_name, dev_name, reporter, and state
    And no "nft_devlink_port_info" series contains any label besides bus_name, dev_name, and port

  Scenario: Bounded cardinality — no per-flow or per-packet labels are emitted
    When a scrape executes
    Then no devlink metric series uses a label named "src_ip" or "dst_ip" or "socket_inode" or "flow_id"

  Scenario: Multiple health reporters on the same device each emit independent series
    Given the device "0000:03:00.0" exposes reporters "fw_fatal", "rx", and "tx"
    And reporter "rx" has error_count 10 and state "error"
    And reporter "tx" has error_count 0 and state "healthy"
    When a scrape executes
    Then the metric "nft_devlink_health_reporter_error_total" with labels reporter="rx" has value 10
    And the metric "nft_devlink_health_reporter_error_total" with labels reporter="tx" has value 0
    And the metric "nft_devlink_health_reporter_state" with labels reporter="rx" and state="error" has value 1
    And the metric "nft_devlink_health_reporter_state" with labels reporter="tx" and state="healthy" has value 1

  Scenario: Multiple devlink devices each emit independent series
    Given a second devlink device with bus_name="pci" and dev_name="0000:05:00.0" is present
    When a scrape executes
    Then the metric "nft_devlink_device_info" with labels bus_name="pci" and dev_name="0000:03:00.0" has value 1
    And the metric "nft_devlink_device_info" with labels bus_name="pci" and dev_name="0000:05:00.0" has value 1

  Scenario: Devlink collector failure due to netlink error sets nft_scrape_collector_success to 0
    Given the devlink family resolves but DEVLINK_CMD_GET returns EPERM
    When a scrape executes
    Then the metric "nft_scrape_collector_success" with label collector="devlink" has value 0
    And the metric "nft_scrape_collector_error_total" with labels collector="devlink" and reason="netlink_permission_denied" is incremented by 1
