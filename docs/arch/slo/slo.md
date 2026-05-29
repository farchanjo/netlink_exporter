# Service Level Objectives — nft_exporter

This document defines the operational targets for nft_exporter. The structure
follows OpenSLO semantics: each objective names an SLI, defines the error
condition, sets a target ratio, and specifies the rolling window and alert
thresholds. Alerting rules reference `nft_up`, `nft_scrape_collector_success`,
and `nft_scrape_duration_seconds` from the exporter's self-metrics.

---

## SLO-1: Scrape Success Ratio

**SLI description.** The fraction of Prometheus scrape requests to GET /metrics
that complete with HTTP 200 and a valid OpenMetrics body. A scrape is a failure
when the HTTP response is non-200, when the response body is empty, or when
`nft_up == 0` on the scraped sample (indicating that at least one critical
collector — rtnetlink, conntrack, or nftables — returned an error).

**Error budget.** At most 0.1% of scrapes may fail in any rolling 30-day window.
This leaves an error budget of approximately 43 minutes of total failure time
per month at a 10-second scrape interval across a single-node deployment.

**Target.**

| Window | Target ratio | Max allowed errors |
|---|---|---|
| 1 hour (short burn) | >= 99.9% | <= 3 scrapes |
| 6 hours | >= 99.9% | <= 18 scrapes |
| 24 hours | >= 99.9% | <= 86 scrapes |
| 30 days | >= 99.9% | — (budget) |

**Alert thresholds (multi-window multi-burn-rate).**

- Page (high urgency): error rate > 14.4x budget burn rate sustained for 1 hour
  AND > 6x for 6 hours. Both conditions must hold simultaneously.
- Ticket (low urgency): error rate > 3x budget burn rate sustained for 72 hours.

**Prometheus recording rule (example).**

```
record: job:nft_scrape_success:ratio_rate5m
expr: >
  avg_over_time(nft_up[5m])
```

**PromQL alert fragment.**

```
alert: NftExporterScrapeErrorBudgetBurnHigh
expr: >
  (
    1 - job:nft_scrape_success:ratio_rate1h
  ) / (1 - 0.999) > 14.4
  and
  (
    1 - job:nft_scrape_success:ratio_rate6h
  ) / (1 - 0.999) > 6
for: 1m
labels:
  severity: page
annotations:
  summary: "nft_exporter scrape error budget burning fast on {{ $labels.instance }}"
  description: >
    Burn rate {{ $value | humanize }}x. Investigate collector failures via
    nft_scrape_collector_success and nft_scrape_collector_error_total.
```

**Mitigating actions.** Check `nft_scrape_collector_success` to identify which
collector is failing. Consult the per-collector error reason in
`nft_scrape_collector_error_total{collector, reason}`. Common causes: netlink
ENOBUFS on high-traffic nodes (increase `NFT_EXPORTER_NETLINK_RECV_BUF_BYTES`);
CAP_NET_ADMIN revoked (check pod security context); kernel module unloaded
(nf_conntrack or nftables).

---

## SLO-2: Scrape Duration p99 Budget

**SLI description.** The 99th-percentile wall-clock duration of the full scrape
across all enabled collectors, as reported by `nft_scrape_duration_seconds`.
This is the end-to-end latency seen by the Prometheus server from the moment it
issues GET /metrics to the moment the last byte of the OpenMetrics body is
written.

**Rationale.** Prometheus applies its own `scrape_timeout` (typically 10 seconds
for node-level exporters). The exporter's internal scrape timeout is configured
at 9800 ms by default (NFT_EXPORTER_SCRAPE_TIMEOUT_MS) to allow a safety margin
before Prometheus cancels the connection. p99 latency must stay well below the
Prometheus scrape_timeout.

**Target.**

| Window | p99 target | Absolute hard limit |
|---|---|---|
| 5-minute rolling | < 3.0 s | < 9.0 s (Prometheus scrape_timeout guard) |
| 1-hour rolling | < 3.0 s | — |
| 24-hour rolling | < 3.0 s | — |

**Alert thresholds.**

- Warning: `nft_scrape_duration_seconds` > 5.0 s for any single scrape on any
  node instance. Sustained for 5 consecutive minutes.
- Critical: `nft_scrape_duration_seconds` > 8.5 s for any single scrape. A value
  this close to the Prometheus `scrape_timeout` means the next scrape cycle will
  likely produce a context-deadline-exceeded error at Prometheus, triggering
  SLO-1 failures.

**PromQL alert fragments.**

```
alert: NftExporterScrapeDurationWarning
expr: nft_scrape_duration_seconds > 5.0
for: 5m
labels:
  severity: warning
annotations:
  summary: "nft_exporter scrape duration elevated on {{ $labels.instance }}"
  description: >
    Scrape duration {{ $value | humanizeDuration }}. Check which collector is
    slow via nft_scrape_collector_duration_seconds.

alert: NftExporterScrapeDurationCritical
expr: nft_scrape_duration_seconds > 8.5
for: 0m
labels:
  severity: page
annotations:
  summary: "nft_exporter scrape approaching Prometheus timeout on {{ $labels.instance }}"
  description: >
    Scrape duration {{ $value | humanizeDuration }} is near the 9.8 s internal
    budget. Prometheus will cancel the next scrape if this is not resolved.
```

**Mitigating actions.** Identify the slow collector via
`nft_scrape_collector_duration_seconds`. On conntrack contexts: a very large
conntrack table (nf_conntrack_count > 500,000) causes long dump time; reduce
`nft_conntrack_max` or enable flow offload. On ethtool contexts: a NIC with a
large stat dictionary and many interfaces slows the genetlink dump; disable the
ethtool collector if not needed via `NFT_EXPORTER_COLLECTORS`. On rtnetlink
contexts: a large routing table (ECMP, BGP full table) can extend RTM_GETROUTE
dump time; the route aggregation model bounds metric cardinality but not kernel
dump latency.

---

## SLO-3: Exporter Availability

**SLI description.** The fraction of 1-minute measurement windows in which the
nft_exporter process is alive and responsive on port 9456, as measured by the
Prometheus target `up` metric. A measurement window is unavailable when
`up{job="nft-exporter"}` == 0 for the entire minute (Prometheus marks a target
as down after a scrape timeout or connection refused).

**Error budget.** At most 0.1% of 1-minute windows may be unavailable in any
rolling 30-day window. This is approximately 43 minutes of total downtime per
month. The k8s DaemonSet deployment with `maxUnavailable=1` and
`PodDisruptionBudget minAvailable=N-1` constrains rolling restarts to at most
one unavailable node at a time, preserving availability across the fleet.

**Target.**

| Window | Target availability |
|---|---|
| 1 hour | >= 99.9% |
| 24 hours | >= 99.9% |
| 30 days | >= 99.9% |

**Alert thresholds.**

- Page: `up{job="nft-exporter"}` == 0 for > 5 minutes on any node instance
  (sustained process crash or node network partition).
- Ticket: total unavailable minutes across the fleet exceeds 10% of the monthly
  error budget in any 24-hour period (early budget exhaustion signal).

**PromQL alert fragments.**

```
alert: NftExporterDown
expr: up{job="nft-exporter"} == 0
for: 5m
labels:
  severity: page
annotations:
  summary: "nft_exporter is down on {{ $labels.instance }}"
  description: >
    nft_exporter has been unreachable on port 9456 for more than 5 minutes.
    Check the DaemonSet pod status and systemd journal.

alert: NftExporterAvailabilityBudgetBurn
expr: >
  (
    1 - avg_over_time(up{job="nft-exporter"}[24h])
  ) / (1 - 0.999) > 10
for: 0m
labels:
  severity: warning
annotations:
  summary: "nft_exporter availability budget burning on {{ $labels.instance }}"
  description: >
    24-hour unavailability ratio is {{ $value | humanizePercentage }} of the
    monthly error budget. Review DaemonSet crash loops and OOMKill events.
```

**Mitigating actions.** Inspect the DaemonSet pod events with
`kubectl describe pod -l app=nft-exporter`. Check for OOMKilled status
(increase memory limit; the exporter is typically < 30 MiB RSS). Verify
CAP_NET_ADMIN is granted and the node kernel has nf_conntrack loaded. Confirm
the scrape endpoint is reachable from the Prometheus namespace via NetworkPolicy.
For systemd deployments, inspect `journalctl -u nft-exporter -n 100`.

---

## Self-metric Reference

The following exporter self-metrics are the primary SLI data sources:

| Metric | Type | SLO |
|---|---|---|
| `nft_up` | gauge | SLO-1 (critical collector health) |
| `nft_scrape_duration_seconds` | gauge | SLO-2 (scrape duration) |
| `nft_scrape_collector_success{collector}` | gauge | SLO-1, SLO-2 (per-collector) |
| `nft_scrape_collector_duration_seconds{collector}` | gauge | SLO-2 (diagnosis) |
| `nft_scrape_collector_error_total{collector, reason}` | counter | SLO-1 (error attribution) |
| `nft_exporter_snapshot_age_seconds{collector}` | gauge | SLO-1 (stale snapshot detection) |
| `up{job="nft-exporter"}` | gauge | SLO-3 (process availability) |

Alert when `nft_exporter_snapshot_age_seconds` exceeds two scrape intervals for
any collector. This indicates the stale-snapshot fallback is active and the
affected collector is not producing fresh data.
