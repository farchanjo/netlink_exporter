# Operations Runbook — nft_exporter

This runbook covers deployment, capability configuration, troubleshooting, and
observability guidance for nft_exporter in both the Kubernetes DaemonSet and
the musl+systemd deployment targets.

---

## 1. Deployment

### 1.1 Kubernetes DaemonSet with Prometheus Operator

**Prerequisites.**

- Kubernetes >= 1.25 with Pod Security Admission (or equivalent PSP replacement).
- Prometheus Operator installed with ServiceMonitor CRD.
- The node kernel must have `nf_conntrack` and `nftables` modules loaded if the
  conntrack and nftables collectors are enabled.
- Kernel >= 5.12 required for the ethtool genetlink family; the collector gates
  on EOPNOTSUPP per NIC and degrades gracefully on older kernels.

**DaemonSet manifest (abridged).**

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: nft-exporter
  namespace: monitoring
spec:
  selector:
    matchLabels:
      app: nft-exporter
  updateStrategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 1
  template:
    metadata:
      labels:
        app: nft-exporter
      annotations:
        container.apparmor.security.beta.kubernetes.io/nft-exporter: runtime/default
    spec:
      hostNetwork: true
      dnsPolicy: ClusterFirstWithHostNet
      serviceAccountName: nft-exporter
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        seccompProfile:
          type: Localhost
          localhostProfile: nft-exporter.json
      containers:
        - name: nft-exporter
          image: ghcr.io/example/nft_exporter:latest@sha256:<digest>
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
              add: ["NET_ADMIN"]
          ports:
            - name: metrics
              containerPort: 9456
              protocol: TCP
          env:
            - name: NFT_EXPORTER_LISTEN
              value: "0.0.0.0:9456"
            - name: NFT_EXPORTER_SCRAPE_TIMEOUT_MS
              value: "9800"
            - name: NFT_EXPORTER_LOG_FORMAT
              value: "json"
          resources:
            requests:
              cpu: 10m
              memory: 32Mi
            limits:
              cpu: 500m
              memory: 128Mi
          livenessProbe:
            httpGet:
              path: /healthz
              port: 9456
            initialDelaySeconds: 5
            periodSeconds: 15
          readinessProbe:
            httpGet:
              path: /ready
              port: 9456
            initialDelaySeconds: 5
            periodSeconds: 10
      tolerations:
        - operator: Exists
```

**Notes on required capabilities.**

- `capabilities.drop: [ALL]` — drops all capabilities first.
- `capabilities.add: [NET_ADMIN]` — re-adds only CAP_NET_ADMIN.
- CAP_NET_ADMIN is required for: NETLINK_ROUTE qdisc/tc stats
  (RTM_GETQDISC/GETTCLASS/GETTFILTER), NETLINK_NETFILTER ctnetlink and
  nfnetlink full dumps, SOCK_DIAG_BY_FAMILY full socket stats.
- CAP_NET_RAW is **not** required and must not be added.
- CAP_SYS_ADMIN is **not** required and must not be added.

**ServiceMonitor.**

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: nft-exporter
  namespace: monitoring
spec:
  selector:
    matchLabels:
      app: nft-exporter
  endpoints:
    - port: metrics
      path: /metrics
      interval: 15s
      scrapeTimeout: 10s
      scheme: http
```

**NetworkPolicy.**

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: nft-exporter-ingress
  namespace: monitoring
spec:
  podSelector:
    matchLabels:
      app: nft-exporter
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: monitoring
          podSelector:
            matchLabels:
              app.kubernetes.io/name: prometheus
      ports:
        - port: 9456
          protocol: TCP
  policyTypes:
    - Ingress
```

**PodDisruptionBudget.**

```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: nft-exporter-pdb
  namespace: monitoring
spec:
  selector:
    matchLabels:
      app: nft-exporter
  minAvailable: "90%"
```

**Seccomp profile.** Place the custom profile at the kubelet seccomp path:
`/var/lib/kubelet/seccomp/nft-exporter.json`. The profile allows
socket(AF_NETLINK), bind, recvmsg, sendmsg, epoll_wait, futex, and denies
execve, ptrace, mount, bpf, clone(CLONE_NEWUSER), perf_event_open.

---

### 1.2 Static musl binary + systemd service

**Prerequisites.**

- Linux kernel >= 5.4 (minimum; >= 5.12 for ethtool genetlink).
- A dedicated system user: `useradd -r -s /sbin/nologin nft-exporter`.
- The nft-exporter user cannot hold capabilities permanently; systemd grants
  them via AmbientCapabilities.

**Install.**

```bash
# Install the static binary (from .deb, .rpm, or tarball)
install -o root -g root -m 0755 nft_exporter /usr/local/bin/nft_exporter

# Verify it is statically linked (no output means static)
ldd /usr/local/bin/nft_exporter || echo "statically linked"

# Optionally verify the SLSA provenance attestation
cosign verify-attestation \
  --type slsaprovenance \
  --certificate-identity-regexp "https://github.com/example/nft_exporter" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/example/nft_exporter:latest
```

**systemd unit file** at `/etc/systemd/system/nft-exporter.service`:

```ini
[Unit]
Description=nft_exporter — Linux netlink Prometheus exporter
Documentation=https://example.com/docs/arch/operations/runbook.md
After=network.target

[Service]
Type=notify
User=nft-exporter
Group=nft-exporter
ExecStart=/usr/local/bin/nft_exporter \
  --listen 0.0.0.0:9456 \
  --scrape-timeout-ms 9800 \
  --log-format json

# Capabilities — NET_ADMIN only; all others stripped
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
NoNewPrivileges=true

# Hardening
ProtectSystem=strict
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK
MemoryDenyWriteExecute=true
LockPersonality=true
SystemCallFilter=@system-service @network-io
SystemCallErrorNumber=EPERM

# Resource limits
MemoryMax=128M
CPUQuota=50%

# Watchdog (sd_notify WATCHDOG=1 sent by SystemdNotifyAdapter)
WatchdogSec=30s
Restart=on-failure
RestartSec=5s
StartLimitIntervalSec=60s
StartLimitBurst=5

[Install]
WantedBy=multi-user.target
```

**Enable and start.**

```bash
systemctl daemon-reload
systemctl enable --now nft-exporter
systemctl status nft-exporter
```

**Verify the exporter is running and collecting.**

```bash
# Check the liveness endpoint
curl -s http://localhost:9456/healthz

# Check the readiness endpoint (returns 200 after first scrape)
curl -s http://localhost:9456/ready

# Fetch a sample of the metrics output
curl -s http://localhost:9456/metrics | grep ^nft_up
curl -s http://localhost:9456/metrics | grep ^nft_scrape_duration_seconds
```

---

## 2. Required Linux Kernel Modules

| Collector | Required module | Check |
|---|---|---|
| Conntrack | `nf_conntrack` | `lsmod \| grep nf_conntrack` |
| Nftables | `nf_tables` | `lsmod \| grep nf_tables` |
| Rtnetlink | built-in | always available |
| TrafficControl | `sch_*` for qdisc stats | present when TC qdiscs are configured |
| SockDiag | built-in | always available |
| Ethtool | kernel >= 5.12, driver support | `ethtool -S <nic>` succeeds |

If `nf_conntrack` is not loaded, the ConntrackCollector returns ENOENT on the
NETLINK_NETFILTER socket. The exporter continues running; `nft_scrape_collector_
success{collector=conntrack}` drops to 0 and `nft_scrape_collector_error_total
{collector=conntrack, reason=kernel_unsupported}` increments each scrape.

---

## 3. Troubleshooting

### 3.1 Exporter does not start — permission denied on netlink socket

**Symptom.** The process exits immediately with a log line containing
`EPERM` or `permission denied` and an errno value from the netlink socket open.

**Diagnosis.**

```bash
# systemd
journalctl -u nft-exporter -n 50 --no-pager

# Kubernetes
kubectl logs -n monitoring -l app=nft-exporter --previous

# Verify the capability is present
grep CapAmb /proc/$(pgrep nft_exporter)/status | awk '{printf "%d\n", strtonum("0x"$2)}'
```

**Common causes and fixes.**

| Cause | Fix |
|---|---|
| CAP_NET_ADMIN not granted in k8s securityContext | Add `capabilities.add: [NET_ADMIN]` and remove `capabilities.drop: [ALL]` override |
| AmbientCapabilities not set in systemd unit | Confirm `AmbientCapabilities=CAP_NET_ADMIN` and `CapabilityBoundingSet=CAP_NET_ADMIN` are present |
| Pod Security Admission blocks NET_ADMIN | Use a `baseline` or custom policy; add an exemption for the nft-exporter namespace |
| AppArmor profile denies NETLINK_ROUTE | Check `dmesg \| grep DENIED` and update the AppArmor profile to allow `network netlink` |

### 3.2 Scrape timeout — `nft_scrape_duration_seconds` > 9 s

**Symptom.** Prometheus logs `context deadline exceeded` on the nft-exporter
target. `nft_scrape_duration_seconds` on the previous successful scrape was
near the timeout limit.

**Diagnosis.** Identify the slow collector:

```bash
curl -s http://localhost:9456/metrics \
  | grep nft_scrape_collector_duration_seconds
```

**Common causes and fixes.**

| Collector | Slow cause | Fix |
|---|---|---|
| conntrack | Large conntrack table (> 500k flows) | Increase `NFT_EXPORTER_SCRAPE_TIMEOUT_MS`; reduce `nf_conntrack_max`; enable flow offload via nft offload |
| rtnetlink | Large routing table (BGP full table) | RTM_GETROUTE dump is O(routes); consider disabling rtnetlink if not needed |
| ethtool | Many NICs with large stat dictionaries | Disable ethtool collector: `NFT_EXPORTER_COLLECTORS=rtnetlink,conntrack,nftables,sock_diag,traffic_control` |
| All | Overloaded node CPU | Increase `NFT_EXPORTER_SCRAPE_TIMEOUT_MS` to 15000; verify Prometheus `scrape_timeout` is set higher |

### 3.3 Collector error — `nft_scrape_collector_success` == 0

**Symptom.** A specific collector shows 0 on the success gauge:

```
nft_scrape_collector_success{collector="conntrack"} 0
```

**Diagnosis.** Check the error reason:

```bash
curl -s http://localhost:9456/metrics \
  | grep nft_scrape_collector_error_total
```

**Error reason reference.**

| Reason | Meaning | Fix |
|---|---|---|
| `netlink_permission_denied` | EPERM on the netlink socket | Check capability grant (see section 3.1) |
| `netlink_timeout` | Collector exceeded per-scrape timeout | See section 3.2 |
| `netlink_truncated` | ENOBUFS — receive buffer too small | Increase `NFT_EXPORTER_NETLINK_RECV_BUF_BYTES` and `net.core.rmem_max` |
| `cardinality_overflow` | Metric family exceeded the 50,000 series ceiling | Check label dimensions; reduce conntrack or ethtool stat cardinality |
| `parse_error` | Unexpected kernel message format | File a bug; capture `RUST_LOG=debug` output |
| `kernel_unsupported` | Required kernel module not loaded or kernel too old | Load the module or disable the collector |
| `panic` | Collector goroutine panic (caught by catch-unwind) | Check logs for panic backtrace; file a bug |

### 3.4 Stale snapshot detected

**Symptom.** `nft_exporter_snapshot_age_seconds{collector}` exceeds two scrape
intervals (for example, > 30 s at a 15-second scrape interval).

**Meaning.** The stale-snapshot fallback is active for this collector. The
exporter is returning data from a previous successful scrape. Recent kernel
state changes are not reflected in the metrics.

**Fix.** Treat as a persistent collector error. Follow section 3.3. The snapshot
age will reset to 0 on the next successful scrape for this collector.

### 3.5 Container OOMKilled

**Symptom.** The pod restarts frequently; `kubectl describe pod` shows
`OOMKilled` as the last termination reason.

**Diagnosis.**

```bash
# Current RSS
kubectl top pod -n monitoring -l app=nft-exporter

# Memory limit in DaemonSet
kubectl get ds nft-exporter -n monitoring \
  -o jsonpath='{.spec.template.spec.containers[0].resources.limits.memory}'
```

**Fix.** Increase the memory limit. Typical RSS for nft_exporter is 15–40 MiB
under normal conditions. On nodes with very large conntrack tables or many TC
classes, peak RSS during a scrape can reach 80 MiB. Set the limit to 256 MiB
if OOMKills persist. Alternatively disable the conntrack collector if the table
is not needed for observability.

---

## 4. Dashboards and Alerts Reference

### 4.1 Recommended Grafana dashboard panels

**Exporter health row.**

| Panel | Query | Description |
|---|---|---|
| Exporter up | `nft_up` | 1 = all critical collectors healthy |
| Scrape duration | `nft_scrape_duration_seconds` | End-to-end scrape latency |
| Per-collector success | `nft_scrape_collector_success` | Grid: 1 row per collector per node |
| Per-collector duration | `nft_scrape_collector_duration_seconds` | Identify slow collectors |
| Error rate | `rate(nft_scrape_collector_error_total[5m])` | Error rate by collector and reason |
| Snapshot age | `nft_exporter_snapshot_age_seconds` | Stale snapshot alert baseline |
| Open netlink sockets | `nft_netlink_socket_count` | Socket leak detection |
| Netlink error rate | `rate(nft_netlink_errors_total[5m])` | ENOBUFS and EPERM rates |
| Build info | `nft_build_info` | Version tracking label display |

**Network interfaces row.**

| Panel | Query |
|---|---|
| Interface rx/tx bytes rate | `rate(nft_link_receive_bytes_total[5m])` / `rate(nft_link_transmit_bytes_total[5m])` |
| Interface errors rate | `rate(nft_link_receive_errors_total[5m])` + `rate(nft_link_transmit_errors_total[5m])` |
| Interface drops rate | `rate(nft_link_receive_dropped_total[5m])` |
| MTU | `nft_link_mtu_bytes` |
| Interface operstate | `nft_link_info` by operstate label |

**Conntrack row.**

| Panel | Query |
|---|---|
| Conntrack entries by state | `nft_conntrack_entries` partitioned by state |
| Conntrack utilization | `nft_conntrack_entries / nft_conntrack_max_entries` |
| Drop rate | `rate(nft_conntrack_drop_total[5m])` |
| Early drop rate | `rate(nft_conntrack_early_drop_total[5m])` |
| Insert rate | `rate(nft_conntrack_insert_total[5m])` |

**nftables row.**

| Panel | Query |
|---|---|
| Rule counter byte rate (top 10) | `topk(10, rate(nft_rule_counter_bytes_total[5m]))` |
| Named counter byte rate | `rate(nft_named_counter_bytes_total[5m])` |
| Set element counts | `nft_set_elements` by table and name |
| Chain info | `nft_chain_info` label display (table, hook, policy) |

**Socket state row.**

| Panel | Query |
|---|---|
| TCP state distribution | `nft_socket_count{protocol="tcp"}` partitioned by state |
| TCP receive queue | `nft_socket_receive_queue_bytes{protocol="tcp"}` |
| TCP retransmit rate | `rate(nft_socket_retransmits_total[5m])` |

### 4.2 Critical alert rules reference

The following alert names correspond to the SLO definitions in
`docs/arch/slo/slo.md`. Full PromQL is provided there.

| Alert name | Severity | Condition |
|---|---|---|
| `NftExporterScrapeErrorBudgetBurnHigh` | page | Multi-burn-rate error budget exhaustion (SLO-1) |
| `NftExporterScrapeDurationWarning` | warning | p99 duration > 5 s sustained 5 min (SLO-2) |
| `NftExporterScrapeDurationCritical` | page | Duration > 8.5 s (near Prometheus timeout) (SLO-2) |
| `NftExporterDown` | page | `up == 0` for > 5 min (SLO-3) |
| `NftExporterAvailabilityBudgetBurn` | warning | 24-hour unavailability budget burn (SLO-3) |
| `NftConntrackNearCapacity` | warning | `nft_conntrack_entries / nft_conntrack_max_entries > 0.85` |
| `NftConntrackDropRateHigh` | page | `rate(nft_conntrack_drop_total[5m]) > 100` |
| `NftExporterSnapshotStale` | warning | `nft_exporter_snapshot_age_seconds > 30` for any collector |
| `NftNetlinkEnobufs` | warning | `rate(nft_netlink_errors_total{errno="ENOBUFS"}[5m]) > 1` |

### 4.3 Adjusting the netlink receive buffer

If `NftNetlinkEnobufs` fires, increase the socket receive buffer and raise the
kernel maximum:

```bash
# Raise the kernel maximum (persistent via /etc/sysctl.d/)
sysctl -w net.core.rmem_max=33554432

# Set the exporter buffer (env var or CLI flag)
# NFT_EXPORTER_NETLINK_RECV_BUF_BYTES=16777216  # 16 MiB
```

For the DaemonSet, use a `ConfigMap` or environment variable in the pod spec.
For the systemd service, add `Environment=NFT_EXPORTER_NETLINK_RECV_BUF_BYTES=16777216`
to the `[Service]` section.

---

## 5. Upgrade and Rollback

### 5.1 Kubernetes DaemonSet rolling upgrade

The DaemonSet uses `RollingUpdate` with `maxUnavailable: 1`. The
`PodDisruptionBudget` ensures at least 90% of nodes remain instrumented during
an upgrade.

```bash
# Update the image digest in the manifest and apply
kubectl set image daemonset/nft-exporter \
  nft-exporter=ghcr.io/example/nft_exporter:<new-tag>@sha256:<new-digest> \
  -n monitoring

# Monitor the rollout
kubectl rollout status daemonset/nft-exporter -n monitoring

# Rollback if needed
kubectl rollout undo daemonset/nft-exporter -n monitoring
```

### 5.2 systemd rollback

```bash
# Keep the previous binary alongside the new one
install -o root -g root -m 0755 nft_exporter_v1.2.0 \
  /usr/local/bin/nft_exporter_v1.2.0

# To roll back
systemctl stop nft-exporter
install -o root -g root -m 0755 nft_exporter_v1.2.0 \
  /usr/local/bin/nft_exporter
systemctl start nft-exporter
```

---

## 6. Configuration Reference

| Environment variable | CLI flag | Default | Valid range |
|---|---|---|---|
| `NFT_EXPORTER_LISTEN` | `--listen` | `0.0.0.0:9456` | Any valid SocketAddr |
| `NFT_EXPORTER_SCRAPE_TIMEOUT_MS` | `--scrape-timeout-ms` | `9800` | 1000–30000 |
| `NFT_EXPORTER_COLLECTORS` | `--collectors` | all six | comma-separated subset |
| `NFT_EXPORTER_LOG_LEVEL` | `--log-level` | `info` | trace,debug,info,warn,error |
| `NFT_EXPORTER_LOG_FORMAT` | `--log-format` | `json` | json,text |
| `NFT_EXPORTER_NETLINK_RECV_BUF_BYTES` | `--netlink-recv-buf-bytes` | `4194304` | 65536–33554432 |
| `TOKIO_WORKER_THREADS` | (none) | logical CPU count | >= 1 |

**Disable specific collectors** to reduce resource usage or suppress errors from
modules that are not loaded:

```bash
# Disable ethtool and traffic-control collectors
NFT_EXPORTER_COLLECTORS=rtnetlink,conntrack,nftables,sock_diag
```
