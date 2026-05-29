Feature: Socket diagnostics metrics (sock-diag subsystem)
  As a Prometheus operator
  I want nft_exporter to emit socket state distribution metrics via SOCK_DIAG_BY_FAMILY
  So that I can observe TCP/UDP socket health aggregated by (protocol, state) without per-socket cardinality

  Background:
    Given nft_exporter is running with the sock_diag collector enabled
    And the kernel has 300 TCP sockets: 250 in state "established" and 50 in state "time_wait"
    And the kernel has 100 UDP sockets in state "unconnected"
    And the kernel has 5 UDPLite sockets in state "unconnected"

  Scenario: nft_socket_count emits aggregated gauge per (protocol, state)
    When a scrape executes
    Then the metric "nft_socket_count" with labels protocol="tcp" and state="established" has value 250
    And the metric "nft_socket_count" with labels protocol="tcp" and state="time_wait" has value 50
    And the metric "nft_socket_count" with labels protocol="udp" and state="unconnected" has value 100
    And the metric "nft_socket_count" with labels protocol="udplite" and state="unconnected" has value 5

  Scenario: nft_socket_count does not emit per-socket or per-port series
    When a scrape executes
    Then no "nft_socket_count" series contains a port, inode, or local_addr label

  Scenario: nft_socket_receive_queue_bytes is aggregated per (protocol, state)
    Given each of the 250 established TCP sockets has 1024 bytes in the receive queue
    When a scrape executes
    Then the metric "nft_socket_receive_queue_bytes" with labels protocol="tcp" and state="established" has value 256000

  Scenario: nft_socket_send_queue_bytes is aggregated per (protocol, state)
    Given each of the 250 established TCP sockets has 512 bytes in the send queue
    When a scrape executes
    Then the metric "nft_socket_send_queue_bytes" with labels protocol="tcp" and state="established" has value 128000

  Scenario: nft_socket_drops_total is aggregated per protocol across all states
    Given 10 TCP sockets report INET_DIAG_SKMEMINFO skmem_drop of 3 each
    When a scrape executes
    Then the metric "nft_socket_drops_total" with label protocol="tcp" has value at least 30

  Scenario: nft_socket_retransmits_total is present for TCP only
    When a scrape executes
    Then the metric "nft_socket_retransmits_total" with label protocol="tcp" is present
    And no "nft_socket_retransmits_total" series exists with protocol="udp"

  Scenario: IPv6 TCP sockets are counted in the same (protocol, state) bucket as IPv4
    Given 80 additional IPv6 TCP sockets are in state "established"
    When a scrape executes
    Then the metric "nft_socket_count" with labels protocol="tcp" and state="established" has value 330

  Scenario: UDP sockets do not emit states other than unconnected
    When a scrape executes
    Then no "nft_socket_count" series exists with labels protocol="udp" and state not equal to "unconnected"

  Scenario: Sock-diag collector failure sets nft_scrape_collector_success to 0
    Given the SOCK_DIAG_BY_FAMILY socket returns EPERM
    When a scrape executes
    Then the metric "nft_scrape_collector_success" with label collector="sock_diag" has value 0
    And the metric "nft_scrape_collector_error_total" with labels collector="sock_diag" and reason="netlink_permission_denied" is incremented by 1
