Feature: Remote integration test loop on vm.services (ADR-0012)
  As a CI pipeline
  I want to cross-compile nft_exporter to a static musl binary, deploy it to a
  remote Linux VM via the Merkle vault_spawn bridge, and validate live metric
  output against the CUE metric_contract schema
  So that changes to the direct AF_NETLINK wire protocol implementation are
  verified against a real kernel before merging

  Background:
    Given the musl cross-compile toolchain is installed via mise on the macOS host
    And the target is x86_64-unknown-linux-musl
    And the remote Linux VM runs kernel >= 4.20 with netlink-capable namespaces
    And the VM root credentials are stored in the Merkle vault (never revealed in plaintext)
    And the Merkle vault_spawn bridge is used for all credential-bearing file transfer
    And the ssh-mcp v7.0 skill is active with agent_id="nft_exporter_ci"
    And the ssh connection uses reuse=Auto (NEVER ssh_run for a repeat host)

  # ---------------------------------------------------------------------------
  # Phase 1: Cross-compile
  # ---------------------------------------------------------------------------

  Scenario: Static musl binary is produced with no dynamic library dependencies
    When "cargo build --target x86_64-unknown-linux-musl --release" completes
    Then the binary at "target/x86_64-unknown-linux-musl/release/nft_exporter" exists
    And "file nft_exporter" reports "ELF 64-bit LSB executable, statically linked"
    And "ldd nft_exporter" outputs "not a dynamic executable"
    And the binary size is less than 20 MiB

  # ---------------------------------------------------------------------------
  # Phase 2: Deploy to remote VM via Merkle vault_spawn bridge
  # ---------------------------------------------------------------------------

  Scenario: Binary is transferred to the remote VM without revealing credentials
    Given the Merkle vault has bound the Namespace containing the VM root SSH key
    When the binary is transferred using ssh_rsync (transport=auto) over the vault_spawn bridge
    Then the binary arrives at "/usr/local/bin/nft_exporter" on the remote VM
    And vault.reveal is never called during the transfer
    And no plaintext credential appears in any tool call argument or log line

  # ---------------------------------------------------------------------------
  # Phase 3: Live scrape execution on the remote VM
  # ---------------------------------------------------------------------------

  Scenario: Exporter starts on the remote Linux VM with minimal privileges
    Given the musl binary is deployed to the remote Linux host as root via the Merkle SSH secret
    When the exporter is launched with "CAP_NET_ADMIN" and "CAP_NET_RAW" capabilities
    And it binds an AF_NETLINK NETLINK_ROUTE socket (fd 0) for the rtnetlink collector
    And it binds an AF_NETLINK NETLINK_NETFILTER socket (fd 1) for the conntrack collector
    Then all capabilities except CAP_NET_ADMIN are dropped immediately after socket open
    And "nft_up" reports 1 within 5 seconds of startup
    And "nft_build_info" is present with a non-empty version label

  Scenario: nft_link_* metrics reflect real interface counters via direct netlink
    Given the musl binary is deployed to the remote Linux host (root via Merkle SSH secret)
    And the VM has at least one physical or virtual interface (e.g. "eth0") with operstate "up"
    When the exporter scrapes via direct netlink (RTM_GETLINK NLM_F_DUMP over rustix raw socket)
    Then "nft_link_receive_bytes_total" with label interface="eth0" is present and greater than 0
    And "nft_link_transmit_bytes_total" with label interface="eth0" is present and greater than 0
    And "nft_link_receive_packets_total" with label interface="eth0" is present
    And "nft_link_transmit_packets_total" with label interface="eth0" is present
    And "nft_link_receive_errors_total" with label interface="eth0" is present
    And "nft_link_transmit_errors_total" with label interface="eth0" is present
    And "nft_link_receive_dropped_total" with label interface="eth0" is present
    And "nft_link_transmit_dropped_total" with label interface="eth0" is present
    And "nft_link_mtu_bytes" with label interface="eth0" has value 1500
    And "nft_link_info" with label interface="eth0" carries operstate="up"
    And counter values are monotonically non-decreasing across two consecutive scrapes separated by 15 seconds

  Scenario: nft_link_speed_bits uses IFLA_STATS64 (192-byte struct) not IFLA_STATS (96-byte)
    Given the VM interface "eth0" is a 1 Gbps link
    When the exporter scrapes via RTM_GETLINK and reads IFLA_STATS64 (rta_type=23)
    Then "nft_link_speed_bits" with label interface="eth0" has value 1000000000
    And IFLA_STATS (rta_type=7) is never read by any collector

  # ---------------------------------------------------------------------------
  # Conntrack via ctnetlink — proc fallback must not fire
  # ---------------------------------------------------------------------------

  Scenario: Conntrack metrics are populated via ctnetlink even though /proc/net/nf_conntrack is empty
    Given the musl binary is deployed to the remote Linux host (root via Merkle SSH secret)
    And /proc/net/nf_conntrack is absent or returns zero entries on the remote VM
    And the nf_conntrack kernel module is loaded
    When the exporter issues IPCTNL_MSG_CT_GET_STATS_CPU (nlmsg_type=0x0105) over NETLINK_NETFILTER
    Then "nft_conntrack_insert_total" is present in the OpenMetrics response with value >= 0
    And "nft_conntrack_drop_total" is present with value >= 0
    And "nft_conntrack_early_drop_total" is present with value >= 0
    And "nft_conntrack_found_total" is present with value >= 0
    And "nft_conntrack_invalid_total" is present with value >= 0
    And "nft_conntrack_max_entries" is present with value > 0
    And no series originates from a /proc filesystem read

  Scenario: ctnetlink nf_conntrack_stat struct size is detected at runtime
    Given the remote Linux VM runs kernel >= 5.12
    When the exporter receives IPCTNL_MSG_CT_GET_STATS_CPU replies with payload_len=60
    Then "nft_conntrack_clash_resolve_total" is present with value >= 0
    And "nft_conntrack_chaintoolong_total" is present with value >= 0

  Scenario: ctnetlink nf_conntrack_stat struct size 52 bytes is handled on older kernels
    Given the remote Linux VM runs kernel < 5.10
    When the exporter receives IPCTNL_MSG_CT_GET_STATS_CPU replies with payload_len=52
    Then "nft_conntrack_clash_resolve_total" is absent from the response
    And "nft_conntrack_chaintoolong_total" is absent from the response
    And "nft_conntrack_insert_total" is still present with value >= 0

  Scenario: nfgenmsg.res_id is always read as big-endian regardless of host byte order
    When the exporter parses CT_GET_STATS_CPU reply frames
    Then CPU index is decoded as u16::from_be_bytes([buf[18], buf[19]])
    And native-endian read is never applied to res_id
    And summed per-CPU counters match the kernel global stats

  Scenario: nft_conntrack_entries aggregates TCP states from CTA_PROTOINFO_TCP_STATE
    Given the conntrack table has active TCP flows
    When the exporter issues IPCTNL_MSG_CT_GET dump
    Then "nft_conntrack_entries" series appear with state values from the set
      | state       |
      | none        |
      | syn_sent    |
      | syn_recv    |
      | established |
      | fin_wait    |
      | close_wait  |
      | last_ack    |
      | time_wait   |
      | close       |
      | listen      |
    And total series count for "nft_conntrack_entries" does not exceed 96
    And no series carries a per-flow identity label (no src_ip, dst_ip, src_port, dst_port, flow_id)

  # ---------------------------------------------------------------------------
  # High-cardinality interface filtering (veth* exclusion by default)
  # ---------------------------------------------------------------------------

  Scenario: High-cardinality veth* interfaces are excluded by default
    Given the musl binary is deployed to the remote Linux host (root via Merkle SSH secret)
    And the remote VM has 29 network interfaces of which the majority are veth pairs
    And ExporterConfig.interface_exclude_regex is set to "^veth"
    When the exporter scrapes via direct netlink
    Then no series for any interface whose name matches "^veth" is emitted
    And "nft_link_filtered_total" with label collector="rtnetlink" has value >= 25
    And "nft_link_info" is present only for non-veth interfaces (e.g. "eth0", "lo")
    And "nft_link_receive_bytes_total" is absent for any "veth*" interface name

  Scenario: Interface exclude wins when both include and exclude match
    Given ExporterConfig.interface_include_regex is set to ".*"
    And ExporterConfig.interface_exclude_regex is set to "^veth"
    And the VM has an interface named "veth0abc"
    When the exporter scrapes
    Then no series for "veth0abc" is emitted
    And "nft_link_filtered_total" with label collector="rtnetlink" is incremented for "veth0abc"

  Scenario: TC qdisc interface filtering mirrors rtnetlink filtering
    Given ExporterConfig.interface_exclude_regex is set to "^veth"
    And the VM has a qdisc attached to interface "veth1234"
    When the exporter scrapes the tc collector
    Then no "nft_tc_qdisc_info" series is emitted for "veth1234"
    And "nft_link_filtered_total" with label collector="traffic_control" is incremented

  Scenario: Include regex restricts to named physical interfaces only
    Given ExporterConfig.interface_include_regex is set to "^(eth|ens|enp)"
    And ExporterConfig.interface_exclude_regex is set to ""
    And the VM has interfaces "eth0", "lo", "veth0abc", "ens3"
    When the exporter scrapes
    Then series are present for "eth0" and "ens3"
    And no series are present for "lo" or "veth0abc"
    And "nft_link_filtered_total" with label collector="rtnetlink" has value 2

  # ---------------------------------------------------------------------------
  # OpenMetrics schema validation
  # ---------------------------------------------------------------------------

  Scenario: OpenMetrics response passes cue vet validation against metric_contract
    Given the exporter has completed two scrape intervals of 15 seconds each
    When the CI job scrapes GET /metrics
    Then the response Content-Type is "application/openmetrics-text; version=1.0.0; charset=utf-8"
    And every metric family name begins with "nft_"
    And "cue vet metric_contract.cue" exits 0 against the scraped response
    And no forbidden label (flow_id, src_ip, dst_ip, src_port, dst_port, socket_inode, mac_address) appears in any series

  Scenario: nft_up is 1 after two successful scrape intervals
    When the exporter completes two consecutive scrapes with all critical collectors succeeding
    Then "nft_up" has value 1
    And "nft_scrape_collector_success" with label collector="rtnetlink" has value 1
    And "nft_scrape_collector_success" with label collector="conntrack" has value 1
    And "nft_scrape_collector_success" with label collector="nftables" has value 1

  # ---------------------------------------------------------------------------
  # CI pipeline integration (ADR-0012 phase 3)
  # ---------------------------------------------------------------------------

  Scenario: GitLab CI stage integration:remote runs after unit:test and build:musl
    Given the GitLab CI DAG has stages: unit:test, build:musl, integration:remote
    And CI_INTEGRATION_VM_ENABLED is set to "true"
    When the integration:remote stage starts
    Then it provisions the remote VM via the vault_spawn bridge
    And transfers the musl binary via ssh_rsync (NEVER ssh_upload chain)
    And streams exporter logs via sub_open command://<session_id>/output (NEVER hot-polls)
    And always closes the sub with sub_close after the job regardless of outcome
    And tears down the remote VM after the job regardless of outcome

  Scenario: integration:remote stage is skipped when CI_INTEGRATION_VM_ENABLED is false
    Given CI_INTEGRATION_VM_ENABLED is unset or "false"
    When the GitLab CI pipeline runs
    Then the integration:remote stage is skipped with exit code 0
    And the build:musl stage artifact is still archived

  # ---------------------------------------------------------------------------
  # Stale-snapshot and error paths under live conditions
  # ---------------------------------------------------------------------------

  Scenario: NLM_F_DUMP_INTR restart cap activates stale-snapshot fallback
    Given the VM kernel modifies the routing table during an RTM_GETROUTE dump
    And NLM_F_DUMP_INTR appears on 9 consecutive restart attempts (exceeding the default cap of 8)
    When the exporter receives the ninth interrupted frame
    Then "nft_scrape_collector_error_total" with labels collector="rtnetlink" and reason="dump_intr" is incremented
    And "nft_exporter_snapshot_age_seconds" with label collector="rtnetlink" is greater than 15
    And the previous valid ReadModel snapshot is served for the /metrics response

  Scenario: ENOBUFS circuit-breaker doubles SO_RCVBUF on first occurrence
    Given the receive buffer is exhausted during a large RTM_GETLINK dump
    When ENOBUFS is returned on the first recvmsg call
    Then SO_RCVBUF is doubled (from 4 MiB to 8 MiB) via setsockopt
    And "nft_netlink_errors_total" with labels family="NETLINK_ROUTE" and errno="ENOBUFS" is incremented by 1
    And the dump is retried successfully with the larger buffer

  Scenario: ENOBUFS on second occurrence aborts and activates stale snapshot
    Given SO_RCVBUF was already doubled on a previous ENOBUFS
    When ENOBUFS is returned again on the same socket
    Then the collector aborts the current scrape
    And "nft_scrape_collector_success" with label collector="rtnetlink" has value 0
    And the stale ReadModel snapshot is served

  Scenario: NETLINK_GET_STRICT_CHK is silently ignored on kernels < 4.20
    Given the remote VM runs kernel 4.15
    When the exporter calls setsockopt(NETLINK_GET_STRICT_CHK, 1) on the NETLINK_ROUTE socket
    Then ENOPROTOOPT is received and silently suppressed
    And the exporter continues scraping without error
    And "nft_scrape_collector_success" with label collector="rtnetlink" has value 1
