# Threat Model — nft_exporter

## Scope and Assumptions

nft_exporter is a single statically-linked musl binary running as a Kubernetes
DaemonSet pod (hostNetwork:true, uid 65532) or as a systemd service (User=
nft-exporter). It holds CAP_NET_ADMIN after startup, drops all other
capabilities via the caps 0.5.6 crate immediately after all netlink socket file
descriptors are opened, and exposes one HTTP endpoint on port 9456.

The threat model uses the STRIDE framework. Assets are the netlink socket file
descriptors, the kernel-level capabilities held by the process, and the
Prometheus /metrics endpoint. The trust boundary is between the container/service
process and (a) the Linux kernel, (b) the Prometheus scraper in a different
namespace, and (c) any other process on the same host network stack.

All threats are rated on a two-axis scale:
**Impact** — Low (L) / Medium (M) / High (H).
**Likelihood** — Low (L) / Medium (M) / High (H).

---

## STRIDE Analysis

### S — Spoofing

#### S-1: Spoofed Prometheus scrape request

**Description.** Any process that can reach port 9456 on the node host network
can issue GET /metrics and receive the full metric export. A malicious actor on
the same host or cluster network could impersonate a legitimate Prometheus
server and collect telemetry data.

**Impact:** L. The endpoint is read-only and returns aggregated counters. No
secrets, credentials, or individual flow details are emitted.

**Likelihood:** M. In hostNetwork:true pods, port 9456 is accessible to all
processes sharing the host network namespace unless a NetworkPolicy restricts
ingress.

**Mitigations:**

1. **NetworkPolicy ingress restriction.** The recommended Kubernetes deployment
   includes a NetworkPolicy that allows ingress on port 9456 only from the
   Prometheus namespace (namespaceSelector + podSelector on the Prometheus
   operator service account). Denies all other sources.

2. **No authentication material in metrics.** The /metrics response never
   includes hostnames, IP addresses in label values, process identifiers, user
   data, or connection-level details. FlowKey (src_ip, dst_ip, src_port, dst_port)
   is never emitted as a label. Per-socket and per-route-prefix labels are
   forbidden by the cardinality policy (ADR-0005).

3. **Distroless runtime.** The gcr.io/distroless/static-debian12:nonroot image
   has no shell, no package manager, and no writable filesystem. An attacker
   cannot install a forwarding proxy or exfiltration tool after gaining access.

**Residual risk:** Low. The data exposed is intentionally public telemetry;
spoofing only affects who receives it.

---

### T — Tampering

#### T-1: Tampering with metric output via race condition in MetricSnapshot

**Description.** If the MetricSnapshot or the ReadModels it contains were
mutable, a concurrent scrape request could observe a partially-updated snapshot,
leading to inconsistent counter values in the OpenMetrics response.

**Impact:** M. Inconsistent counters cause false rate alerts in Prometheus.

**Likelihood:** L. MetricSnapshot is an owned immutable value constructed once
per scrape epoch and never mutated (architectural invariant documented in the
domain overview).

**Mitigations:**

1. **Immutable ReadModels.** Every ReadModel is a fully owned Rust struct with
   no interior mutability. The Collector trait returns `Box<dyn ReadModel>` by
   value. There is no shared mutable state between concurrent scrapes.

2. **Tokio task isolation.** Each scrape epoch spawns a new JoinSet of collector
   futures. The completed MetricSnapshot from the previous epoch is not shared
   with the new one; it is dropped after the response is written.

**Residual risk:** Negligible with current design.

#### T-2: Tampering with the binary on disk (supply-chain)

**Description.** An attacker who can write to /usr/local/bin/nft_exporter on the
host could replace the binary with a modified version that leaks data or provides
a backdoor.

**Impact:** H. A compromised binary has CAP_NET_ADMIN at startup.

**Likelihood:** L. Requires root or write access to the host filesystem, which
is a higher-privilege escalation beyond the scope of this threat model.

**Mitigations:**

1. **SLSA L3 provenance.** Every release binary is built in the CI pipeline with
   SLSA Level 3 provenance (hermetic build, isolated workers, signed attestation).
   Consumers can verify the provenance attestation before deployment.

2. **Cosign keyless OIDC signing.** The container image is signed with cosign
   using OIDC-federated identity from the CI provider. Image digest pinning in
   the DaemonSet manifest prevents silent substitution.

3. **SBOM and CVE scanning.** A syft SPDX-JSON SBOM is attached as an OCI
   referrer. Trivy and Grype scan the image on every CI run and block release on
   high-severity CVEs.

4. **readOnlyRootFilesystem: true.** The k8s security context prevents writing
   to any filesystem path inside the container at runtime.

**Residual risk:** Low (dependent on CI/CD security perimeter).

---

### R — Repudiation

#### R-1: Missing audit trail for capability drop

**Description.** If the capability drop step (caps crate after socket open)
fails silently, the process continues running with all inherited capabilities
but there is no record of the failure in the metrics or logs.

**Impact:** M. Silent capability retention expands the blast radius of a
process compromise.

**Likelihood:** L. The caps crate panics on capability set failure in the
current implementation; panic=abort causes immediate process termination.

**Mitigations:**

1. **Capability drop is fatal.** The call to `caps::clear(None, CapSet::Inheritable)`
   and `caps::set(None, CapSet::Permitted, &cap_set)` uses `expect()`. With
   `panic=abort` in the release profile, any failure terminates the process
   immediately and is recorded in the systemd journal or k8s pod events.

2. **Build info metric.** `nft_build_info{version, revision, rust_version, build_date}`
   provides a permanent record of the binary identity in every metrics scrape,
   enabling correlating an anomalous binary with its build provenance.

3. **Structured logging.** The tracing subscriber emits a JSON log line at INFO
   level recording the capability set after the drop step. Operators can verify
   this log line on startup.

**Residual risk:** Low.

---

### I — Information Disclosure

#### I-1: Metric exfiltration via unauthenticated /metrics endpoint

**Description.** The /metrics endpoint is unauthenticated by design (matching
the Prometheus ecosystem convention). Any actor with network access to port 9456
can retrieve aggregated network telemetry for the node, including interface
names, TC qdisc hierarchy, nftables table and chain names, conntrack aggregate
counts, and ethtool NIC statistics.

**Impact:** M. nftables table and chain names may reveal firewall policy
structure (for example, chain names like `block-country-cn` or `allow-mgmt`).
Interface names and ethtool statistics may reveal hardware topology.

**Likelihood:** M. Without NetworkPolicy, any pod in the cluster can reach the
DaemonSet on the host network.

**Mitigations:**

1. **NetworkPolicy ingress restriction** (same as S-1). Limit ingress to the
   Prometheus scraper service account only.

2. **Cardinality policy forbids sensitive label values.** FlowKey (IP addresses,
   ports), route prefixes, socket inodes, and MAC addresses are never emitted as
   Prometheus labels. The operator's intent is visible only at the chain/table
   name level.

3. **Distroless nonroot image.** The exporter runs as uid 65532 with no shell
   access. There is no interactive path for an attacker to pivot from metric
   read access to process or file system access.

4. **No TLS by design (documented).** TLS termination is delegated to the
   Prometheus Operator's mTLS scrape path (ServiceMonitor + Prometheus agent
   mTLS client certificate). Operators who require encryption should configure
   the Prometheus Operator scrape TLS settings rather than adding TLS to the
   exporter itself.

**Residual risk:** Low with NetworkPolicy applied; Medium without it.

#### I-2: Kernel memory exposure via netlink receive buffer

**Description.** A misconfigured SO_RCVBUF or a ENOBUFS condition on a netlink
socket could theoretically expose uninitialized kernel memory in error messages.

**Impact:** L. Linux netlink error messages are structured (nlmsgerr); they do
not contain arbitrary kernel memory.

**Likelihood:** L. The netlink protocol is well-specified; ENOBUFS results in a
truncated dump notification, not a buffer overrun.

**Mitigations:** The ConntrackAdapter and all other adapters handle ENOBUFS
by recording `nft_netlink_errors_total{family, errno=ENOBUFS}` and triggering
a circuit-breaker retry with backoff. No raw kernel memory is surfaced to the
HTTP response.

**Residual risk:** Negligible.

---

### D — Denial of Service

#### D-1: DoS via huge conntrack table

**Description.** On a node tracking millions of concurrent flows (for example,
a high-traffic NAT gateway), the IPCTNL_MSG_CT_GET full dump can produce
hundreds of megabytes of netlink data per scrape. Receiving, parsing, and
aggregating this data may exhaust RSS memory limits or cause the scrape to
exceed the 9800 ms timeout, triggering SLO-1 failures.

**Impact:** H. A sustained conntrack table growth above the scrape processing
capacity causes continuous scrape timeouts, degrading observability. In extreme
cases, the exporter process is OOMKilled by cgroups.

**Likelihood:** M. Nodes running as NAT gateways or L4 load balancers
routinely sustain large conntrack tables.

**Mitigations:**

1. **Per-scrape timeout budget.** ScrapeLifecycle wraps the ConntrackCollector
   future in `tokio::time::timeout(config.scrape_timeout_ms)`. A timeout
   activates the stale-snapshot fallback; `nft_scrape_collector_success
   {collector=conntrack}` drops to 0 and the alert fires within one scrape
   interval.

2. **Cardinality overflow guard.** ConntrackCollector aggregates flows into at
   most |protocol| x |state| x |direction| buckets (approximately 80 series)
   regardless of table size. Processing cost is O(table_entries) in time but
   O(1) in output cardinality.

3. **Configurable netlink receive buffer.** Operators on high-traffic nodes
   should increase `NFT_EXPORTER_NETLINK_RECV_BUF_BYTES` (default 4 MiB, max
   32 MiB) to reduce ENOBUFS retries. The value is bounded by the
   `net.core.rmem_max` kernel sysctl.

4. **Circuit breaker on ENOBUFS.** Three consecutive ENOBUFS errors on a
   netlink socket trigger a circuit-breaker that parks the collector for the
   next two scrape intervals, preventing tight retry loops from amplifying CPU
   usage.

5. **Memory limit.** The k8s DaemonSet manifest sets a memory limit (recommended
   128 MiB) to bound the RSS impact of a large dump. If the limit is hit, the
   pod is OOMKilled and restarted; `up{job="nft-exporter"}` drops to 0 and SLO-3
   fires.

**Residual risk:** Medium (dependent on conntrack table size operational policy).

#### D-2: DoS via rapid scrape rate (scrape amplification)

**Description.** If a misconfigured or malicious Prometheus instance issues GET
/metrics at a very high rate (for example, 1-second interval), each scrape
triggers a full JoinSet fan-out across all six collectors, consuming CPU and
netlink socket bandwidth.

**Impact:** M. Excessive scrape rate can saturate the netlink socket receive
path, starving other processes that use netlink on the same host.

**Likelihood:** L. Prometheus respects the scrape_interval configured in its
job definition; an attacker would need to control Prometheus configuration or
send raw HTTP requests directly.

**Mitigations:**

1. **NetworkPolicy ingress restriction** limits which pods can reach port 9456,
   preventing arbitrary HTTP clients from issuing scrape requests.

2. **Axum concurrency limits.** The axum server is configured with a maximum
   in-flight request limit. Requests beyond the limit receive HTTP 503 without
   triggering a scrape.

3. **Scrape deduplication (future).** A scrape-result cache keyed by epoch
   timestamp can serve repeated requests within the same scrape interval without
   re-issuing netlink dumps. This is not implemented in the initial release.

**Residual risk:** Low with NetworkPolicy applied.

---

### E — Privilege Escalation

#### E-1: Privilege escalation via CAP_NET_ADMIN after socket open

**Description.** The exporter starts with CAP_NET_ADMIN to open netlink sockets.
If capability drop fails or is bypassed (for example, by a Rust `unsafe` block
that forks before drop), the process retains CAP_NET_ADMIN for its lifetime,
enabling an attacker who exploits the process to modify network interfaces,
routing tables, iptables rules, and nftables rules.

**Impact:** H. CAP_NET_ADMIN allows an attacker to modify the node's network
configuration, potentially redirecting traffic or disabling firewall rules.

**Likelihood:** L. The capability drop is performed synchronously before the
tokio runtime and axum server start (no async tasks run before drop). The caps
crate uses direct `prctl`/`cap_set` syscalls.

**Mitigations:**

1. **Immediate post-socket-open capability drop.** All netlink socket file
   descriptors are opened in a synchronous pre-runtime phase. Immediately after
   the last socket is opened, `caps::clear` and `caps::set` remove all
   capabilities from Permitted, Inheritable, and Ambient sets. This occurs
   before the tokio runtime is created and before any async task can run.

2. **panic=abort on drop failure.** `expect()` on the caps calls combined with
   the `panic=abort` build profile terminates the process immediately if capability
   drop fails. There is no recovery path that leaves the process alive with
   capabilities retained.

3. **allowPrivilegeEscalation: false.** The k8s security context sets
   `allowPrivilegeEscalation: false` via seccomp and no-setuid/no-setgid
   enforcement. Child processes (if any were created) cannot regain capabilities.

4. **Custom seccomp profile.** The deploy/seccomp/nft-exporter.json profile
   allows only socket(AF_NETLINK), bind, recvmsg, sendmsg, epoll_wait, and
   futex. It denies execve, ptrace, mount, bpf, clone(CLONE_NEWUSER), and
   perf_event_open. An attacker who gains code execution inside the process
   cannot launch new executables or escalate further.

5. **No CAP_NET_RAW, no CAP_SYS_ADMIN by design.** The netlink-only collection
   path (ADR-0009) eliminates the need for raw packet sockets (CAP_NET_RAW) and
   the setns(CLONE_NEWNET) path (which would require CAP_SYS_ADMIN). The attack
   surface is strictly narrower than node_exporter.

6. **systemd hardening.** The unit file sets `NoNewPrivileges=true`,
   `ProtectSystem=strict`, `PrivateTmp=true`, `PrivateDevices=true`,
   `ProtectKernelTunables=true`, `ProtectControlGroups=true`,
   `RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK`,
   `MemoryDenyWriteExecute=true`, `LockPersonality=true`, and
   `SystemCallFilter=@system-service @network-io`.

**Residual risk:** Low.

#### E-2: Container escape via hostNetwork combined with CAP_NET_ADMIN

**Description.** Running with `hostNetwork: true` and CAP_NET_ADMIN is a
sensitive combination. If the process is compromised, the attacker is already on
the host network namespace and holds a capability that allows modifying network
state for all other pods and services on the node.

**Impact:** H. Full node network namespace control after process compromise.

**Likelihood:** L. Exploiting the exporter requires an RCE vulnerability in axum,
tokio, or the metric parsing path — all pure Rust code with memory-safety
guarantees.

**Mitigations:**

1. All mitigations from E-1 apply (capability drop, seccomp, panic=abort).

2. **Distroless nonroot image.** No shell, no package manager, no write path.
   An attacker cannot install tools or persist changes across container restarts.

3. **runAsNonRoot: true, runAsUser: 65532.** The process does not run as root,
   limiting the scope of actions even before the seccomp filter applies.

4. **Rust memory safety.** The entire binary except the caps and syscall crates
   is safe Rust with no `unsafe` blocks in domain-core or adapter crates (enforced
   by `#![forbid(unsafe_code)]` in domain-core crate roots). The attack surface
   for memory-corruption exploits is limited to the thin unsafe boundary in
   netlink-sys AsyncSocket and the libc binding in caps.

**Residual risk:** Medium (inherent to hostNetwork:true with any network-level
capability; this is the minimum required for the exporter's function).

---

## Threat Summary

| ID | Category | Threat | Impact | Likelihood | Residual Risk |
|---|---|---|---|---|---|
| S-1 | Spoofing | Spoofed scrape request | L | M | Low |
| T-1 | Tampering | Race condition in MetricSnapshot | M | L | Negligible |
| T-2 | Tampering | Binary replacement on host | H | L | Low |
| R-1 | Repudiation | Silent capability drop failure | M | L | Low |
| I-1 | Info Disclosure | Unauthenticated /metrics endpoint | M | M | Low (with NetworkPolicy) |
| I-2 | Info Disclosure | Kernel memory in netlink error | L | L | Negligible |
| D-1 | DoS | Huge conntrack table | H | M | Medium |
| D-2 | DoS | Rapid scrape rate amplification | M | L | Low |
| E-1 | Escalation | CAP_NET_ADMIN retained after open | H | L | Low |
| E-2 | Escalation | Container escape via hostNetwork | H | L | Medium |

The two residual Medium risks (D-1, E-2) are architectural constraints:
D-1 is bounded by operational conntrack sizing policy, and E-2 is inherent
to any exporter requiring host network namespace access. Both are accepted
risks documented here and mitigated to the extent possible within the
design constraints of a DaemonSet network metrics exporter.
