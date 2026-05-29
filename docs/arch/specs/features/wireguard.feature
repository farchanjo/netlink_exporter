Feature: WireGuard metrics (wireguard subsystem)
  As a Prometheus operator
  I want nft_exporter to emit WireGuard tunnel metrics via the WireGuard generic-netlink family
  So that I can observe per-peer traffic, handshake freshness, and tunnel health without a sidecar

  Background:
    Given nft_exporter is running with the wireguard collector enabled
    And the host has the WireGuard kernel module loaded
    And the WireGuard generic-netlink family "wireguard" resolves successfully
    And there is one WireGuard interface "wg0" with listen_port 51820 and fwmark 0
    And "wg0" has two peers identified by truncated key hashes "a1b2c3d4e5f60718" and "deadbeefcafe0011"
    And peer "a1b2c3d4e5f60718" has rx_bytes 1048576, tx_bytes 524288
    And peer "a1b2c3d4e5f60718" has last_handshake 42 seconds ago, keepalive 25 seconds, endpoint present
    And peer "deadbeefcafe0011" has rx_bytes 0, tx_bytes 8192
    And peer "deadbeefcafe0011" has no completed handshake, no keepalive, no endpoint

  # -----------------------------------------------------------------------
  # Device info
  # -----------------------------------------------------------------------

  Scenario: nft_wireguard_device_info is emitted with correct labels
    When a scrape executes
    Then the metric "nft_wireguard_device_info" with labels interface="wg0", listen_port="51820", fwmark="0" has value 1

  Scenario: nft_wireguard_device_info uses only the three declared label dimensions
    When a scrape executes
    Then no "nft_wireguard_device_info" series contains any label besides interface, listen_port, and fwmark

  # -----------------------------------------------------------------------
  # Per-peer byte counters
  # -----------------------------------------------------------------------

  Scenario: nft_wireguard_peer_receive_bytes_total is emitted per peer
    When a scrape executes
    Then the metric "nft_wireguard_peer_receive_bytes_total" with labels interface="wg0" and peer="a1b2c3d4e5f60718" has value 1048576
    And the metric "nft_wireguard_peer_receive_bytes_total" with labels interface="wg0" and peer="deadbeefcafe0011" has value 0

  Scenario: nft_wireguard_peer_transmit_bytes_total is emitted per peer
    When a scrape executes
    Then the metric "nft_wireguard_peer_transmit_bytes_total" with labels interface="wg0" and peer="a1b2c3d4e5f60718" has value 524288
    And the metric "nft_wireguard_peer_transmit_bytes_total" with labels interface="wg0" and peer="deadbeefcafe0011" has value 8192

  Scenario: byte counter metrics are declared as counters not gauges
    When a scrape executes
    Then the OpenMetrics type declaration for "nft_wireguard_peer_receive_bytes_total" is "counter"
    And the OpenMetrics type declaration for "nft_wireguard_peer_transmit_bytes_total" is "counter"

  # -----------------------------------------------------------------------
  # Handshake age gauge
  # -----------------------------------------------------------------------

  Scenario: nft_wireguard_peer_last_handshake_seconds emits age in seconds for a peer with a handshake
    When a scrape executes at Unix time T
    Then the metric "nft_wireguard_peer_last_handshake_seconds" with labels interface="wg0" and peer="a1b2c3d4e5f60718" has value 42

  Scenario: nft_wireguard_peer_last_handshake_seconds emits +Inf for a peer that has never completed a handshake
    When a scrape executes
    Then the metric "nft_wireguard_peer_last_handshake_seconds" with labels interface="wg0" and peer="deadbeefcafe0011" has value +Inf

  # -----------------------------------------------------------------------
  # Persistent keepalive gauge
  # -----------------------------------------------------------------------

  Scenario: nft_wireguard_peer_persistent_keepalive_seconds reflects configured interval
    When a scrape executes
    Then the metric "nft_wireguard_peer_persistent_keepalive_seconds" with labels interface="wg0" and peer="a1b2c3d4e5f60718" has value 25

  Scenario: nft_wireguard_peer_persistent_keepalive_seconds emits 0 when keepalive is disabled
    When a scrape executes
    Then the metric "nft_wireguard_peer_persistent_keepalive_seconds" with labels interface="wg0" and peer="deadbeefcafe0011" has value 0

  # -----------------------------------------------------------------------
  # Endpoint presence gauge
  # -----------------------------------------------------------------------

  Scenario: nft_wireguard_peer_endpoint_present is 1 when the peer has a known endpoint
    When a scrape executes
    Then the metric "nft_wireguard_peer_endpoint_present" with labels interface="wg0" and peer="a1b2c3d4e5f60718" has value 1

  Scenario: nft_wireguard_peer_endpoint_present is 0 when the peer has no known endpoint
    When a scrape executes
    Then the metric "nft_wireguard_peer_endpoint_present" with labels interface="wg0" and peer="deadbeefcafe0011" has value 0

  # -----------------------------------------------------------------------
  # Availability gating — WireGuard module not loaded
  # -----------------------------------------------------------------------

  Scenario: Collector reports available=0 gracefully when the WireGuard module is not loaded
    Given the WireGuard generic-netlink family resolution returns ENOENT
    When a scrape executes
    Then the metric "nft_scrape_collector_available" with label collector="wireguard" has value 0
    And no "nft_wireguard_device_info" series is emitted
    And no "nft_wireguard_peer_receive_bytes_total" series is emitted
    And no "nft_wireguard_peer_transmit_bytes_total" series is emitted
    And no "nft_wireguard_peer_last_handshake_seconds" series is emitted
    And no "nft_wireguard_peer_endpoint_present" series is emitted
    And the metric "nft_scrape_collector_success" with label collector="wireguard" has value 1

  Scenario: Collector emits available=1 when the WireGuard module is loaded
    When a scrape executes
    Then the metric "nft_scrape_collector_available" with label collector="wireguard" has value 1

  Scenario: No netlink I/O is attempted when the WireGuard family was not resolved at startup
    Given the WireGuard generic-netlink family resolution returns ENOENT at startup
    When three consecutive scrapes execute
    Then the metric "nft_netlink_errors_total" with label family="NETLINK_GENERIC" is not incremented during any of the three scrapes

  # -----------------------------------------------------------------------
  # Peer identity label — truncated key hash
  # -----------------------------------------------------------------------

  Scenario: The peer label is a 16-character lowercase hex string derived from the public key
    When a scrape executes
    Then all "nft_wireguard_peer_receive_bytes_total" series have a peer label matching the pattern [0-9a-f]{16}

  Scenario: Operator-supplied peer name overrides the truncated hash label
    Given the operator has configured wireguard_peer_names with public_key_base64="<key_a>" mapped to "vpn-server-eu"
    And peer "a1b2c3d4e5f60718" corresponds to that public key
    When a scrape executes
    Then the metric "nft_wireguard_peer_receive_bytes_total" with labels interface="wg0" and peer="vpn-server-eu" is present
    And no "nft_wireguard_peer_receive_bytes_total" series with peer="a1b2c3d4e5f60718" is emitted for that peer

  Scenario: Peer name with invalid characters falls back to truncated hash at startup
    Given the operator has configured wireguard_peer_names with an entry whose value contains invalid characters
    When nft_exporter starts
    Then a WARN log is emitted for the invalid peer name entry
    And the corresponding peer uses the truncated key hash label

  # -----------------------------------------------------------------------
  # Cardinality guard
  # -----------------------------------------------------------------------

  Scenario: Collector activates stale-snapshot fallback when peer count exceeds wireguard_max_peers
    Given the host has WireGuard peers totalling more than wireguard_max_peers across all interfaces
    When a scrape executes
    Then the metric "nft_scrape_collector_error_total" with labels collector="wireguard" and reason="cardinality_overflow" is incremented by 1
    And the wireguard collector serves the previous stale snapshot for that scrape

  Scenario: peer label set is bounded — no raw IP addresses, no raw public keys
    When a scrape executes
    Then no "nft_wireguard_peer_receive_bytes_total" series has a peer label longer than 64 characters
    And no "nft_wireguard_peer_receive_bytes_total" series has a peer label matching the pattern [0-9a-fA-F]{64}

  # -----------------------------------------------------------------------
  # Multiple WireGuard interfaces
  # -----------------------------------------------------------------------

  Scenario: Multiple WireGuard interfaces each emit their own device_info series
    Given an additional WireGuard interface "wg1" with listen_port 51821 and fwmark 100
    When a scrape executes
    Then the metric "nft_wireguard_device_info" with labels interface="wg0" and listen_port="51820" is present
    And the metric "nft_wireguard_device_info" with labels interface="wg1" and listen_port="51821" and fwmark="100" is present

  Scenario: Peer metrics carry the correct interface label for each WireGuard interface
    Given an additional WireGuard interface "wg1" with one peer "0011223344556677"
    When a scrape executes
    Then the metric "nft_wireguard_peer_receive_bytes_total" with label interface="wg1" and peer="0011223344556677" is present
    And the metric "nft_wireguard_peer_receive_bytes_total" with label interface="wg1" does not include peers from "wg0"

  # -----------------------------------------------------------------------
  # Collector isolation — failure does not affect other collectors
  # -----------------------------------------------------------------------

  Scenario: WireGuard collector failure does not affect rtnetlink collector success
    Given the WireGuard generic-netlink family dump returns a kernel error EACCES
    When a scrape executes
    Then the metric "nft_scrape_collector_success" with label collector="wireguard" has value 0
    And the metric "nft_scrape_collector_success" with label collector="rtnetlink" has value 1
    And the metric "nft_up" has value 1
