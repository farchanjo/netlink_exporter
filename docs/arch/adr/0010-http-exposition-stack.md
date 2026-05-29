---
status: accepted
date: 2026-05-28
deciders: [eonf]
consulted: []
informed: []
---

# Use axum 0.8 with GET /metrics, GET /healthz, GET /ready on port 9456

## Context and Problem Statement

The exporter must serve exactly three HTTP endpoints:

- `GET /metrics`: Prometheus scrape endpoint returning OpenMetrics text.
- `GET /healthz`: Kubernetes liveness probe; must respond 200 even when no scrape has completed.
- `GET /ready`: Kubernetes readiness probe; must respond 200 only after at least one successful scrape.

The HTTP server must share the same tokio runtime as the six netlink collectors; a separate blocking HTTP server would require a separate thread pool and cross-thread synchronization for the scrape trigger. The port must not conflict with other well-known Prometheus exporter ports.

## Considered Options

- axum 0.8 on port 9456 (chosen)
- hyper 1.x directly (no routing ergonomics for 3 routes)
- tiny_http (synchronous, cannot share tokio runtime with collectors)

## Decision Outcome

**Chosen option: axum 0.8.9 on port 9456.**

`axum 0.8.9` is declared in `nft_exporter_adapter_http` as the sole HTTP framework. It requires Rust >= 1.75 (compatible with the 1.87 MSRV declared in ADR-0003). axum shares the tokio runtime natively; `AxumHttpAdapter` is constructed within the same `tokio::runtime::Runtime::block_on` context as the collectors.

**Route definitions:**

```
GET /metrics  -> ScrapeTriggerPort::trigger_scrape()  -> 200 OpenMetrics text | 503 on ScrapeError
GET /healthz  -> HealthPort::health()                 -> 200 "ok"             | 503 on unhealthy
GET /ready    -> ReadinessPort::readiness()            -> 200 "ready"          | 503 on not ready
```

`Content-Type` on `/metrics` is `application/openmetrics-text; version=1.0.0; charset=utf-8` as required by the OpenMetrics spec and Prometheus >= 2.40 negotiation.

**Port selection**: default `0.0.0.0:9456`. Rationale: port 9100 is `node_exporter` (the most widely deployed Prometheus exporter); port 9105 is `stunnel-exporter` per the Prometheus default-port registry. Port 9456 is unallocated in the Prometheus community port registry as of 2026-05-28. The listen address is fully configurable via `NFT_EXPORTER_LISTEN` env var and `--listen` CLI flag (see `CliConfigPort`/`EnvConfigAdapter`) so operators can bind to a specific interface or a non-default port.

**Differentiated probes**: `HealthPort` and `ReadinessPort` are separate traits backed by different state. `HealthPort::health()` checks that the tokio event loop is alive and no task has been permanently hung (checked via a watchdog `AtomicBool` updated every 5 seconds by a background task). `ReadinessPort::readiness()` checks an `AtomicBool` that is set to `true` only after `ScrapeLifecycle` completes its first full scrape without all critical collectors failing. This differentiation enables Kubernetes to distinguish between a process that is running but not yet warmed up (not ready, but alive) and a process that has crashed (not healthy).

**systemd sd_notify integration**: `SystemdNotifyAdapter` (in `nft_exporter_adapter_http`) sends `READY=1` via `sd_notify(3)` after `axum::serve` binds the listening socket and `WATCHDOG=1` on each successful scrape. This integrates with `Type=notify` and `WatchdogSec=` in the systemd unit.

**Consequences:**

- Positive: axum's `Router` type provides compile-time route registration; adding a new endpoint (e.g., `/debug/pprof` for future profiling) requires only one `Router::route()` call with no structural changes.
- Positive: axum's `State<Arc<AppState>>` extension injects the `ScrapeLifecycle` reference into handlers without global state; unit tests can inject a mock `ScrapeLifecycle` via `axum::Router::with_state`.
- Positive: axum shares the tokio executor with the collectors; the scrape trigger does not require a channel or mutex to hand off to a separate HTTP thread.
- Positive: `Content-Type: application/openmetrics-text` satisfies Prometheus Operator `ServiceMonitor` negotiation without additional configuration.
- Negative: axum 0.8.x introduced breaking changes from 0.7.x (extractors, middleware API); the upgrade path from a hypothetical earlier axum version is non-trivial. Pinning to `0.8.9` in `Cargo.toml` (exact version) prevents accidental major-version drift.
- Negative: No TLS at the exporter layer. TLS termination is expected to be handled by the Kubernetes Ingress controller, a service mesh sidecar (Istio/Linkerd), or a reverse proxy in the systemd deployment. Adding TLS to axum directly would require certificate rotation logic and add `rustls` or `openssl` to the binary, both increasing the TCB.

**Rejected options:**

- *hyper 1.x directly*: hyper 1.x provides the underlying HTTP/1.1 and HTTP/2 implementation that axum builds on. Using it directly requires manual route matching, `Request<Incoming>` body handling, and response construction for each of the three endpoints. For three routes this is workable but adds ~200 lines of boilerplate relative to the three `Router::route()` calls in axum.
- *tiny_http*: tiny_http is synchronous and spawns a thread per connection. It cannot be integrated into the tokio runtime; calling `ScrapeTriggerPort::trigger_scrape()` (an async method) from a tiny_http handler would require `tokio::runtime::Handle::current().block_on(...)`, which panics if called from within a tokio context. A separate OS thread with its own runtime would be required, defeating the purpose of the shared runtime model.
