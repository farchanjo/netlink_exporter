//! Drop-monitor genetlink collector.
//!
//! Netlink family: `NETLINK_GENERIC` (16), family name `"NET_DM"`.
//! ADR refs: ADR-0011, ADR-0014, netlink-protocol.md §16.
//!
//! ## Runtime gate
//!
//! `probe_available()` calls `resolve_genl_family("NET_DM")`. `Ok(None)` means
//! the `drop_monitor` module is not loaded; `collect()` returns `Ok(vec![])`.
//!
//! ## Protocol (derived from linux/net/core/drop_monitor.c + uapi/linux/net_dropmon.h)
//!
//! Commands (genl family version = 2):
//!
//! | Cmd | Value | Flags | Description |
//! |-----|-------|-------|-------------|
//! | `NET_DM_CMD_CONFIG`    | 2 | `GENL_ADMIN_PERM` | Set alert mode, trunc/queue len |
//! | `NET_DM_CMD_START`     | 3 | `GENL_ADMIN_PERM` | Start SW/HW monitoring |
//! | `NET_DM_CMD_STOP`      | 4 | `GENL_ADMIN_PERM` | Stop SW/HW monitoring |
//! | `NET_DM_CMD_STATS_GET` | 8 | (none, unprivileged) | Pull aggregate drop counts |
//!
//! `NET_DM_CMD_STATS_GET` (unicast, no `NLM_F_DUMP`) replies with
//! `NET_DM_CMD_STATS_NEW` containing:
//!
//! - `NET_DM_ATTR_STATS`    (type=12, nested) → `NET_DM_ATTR_STATS_DROPPED` (type=0, u64) SW total
//! - `NET_DM_ATTR_HW_STATS` (type=13, nested) → `NET_DM_ATTR_STATS_DROPPED` (type=0, u64) HW total
//!
//! **No per-reason breakdown from STATS_GET.** Per-reason data lives only in
//! the `NET_DM_GRP_ALERT` multicast stream (PACKET-mode alerts). STATS_GET
//! is used here for a simple, lock-free, per-scrape pull that requires no
//! background task.
//!
//! ## Collection model
//!
//! On each `collect()` call:
//!
//! 1. Resolve `"NET_DM"` family (fast; cached kernel-side).
//! 2. Send `NET_DM_CMD_CONFIG` + `NET_DM_CMD_START` (idempotent; EBUSY/EALREADY ignored).
//! 3. Send `NET_DM_CMD_STATS_GET`; parse reply.
//! 4. Emit `nft_drop_packets_total{origin="sw", reason="total"}` and
//!    `nft_drop_packets_total{origin="hw", reason="total"}`.
//!
//! ## Cardinality
//!
//! Fixed: two label combinations `{origin="sw", reason="total"}` and
//! `{origin="hw", reason="total"}`.  Zero cardinality explosion.
//!
//! ## Monitoring prerequisites
//!
//! `NET_DM_CMD_STATS_GET` returns valid counters only after `NET_DM_CMD_START`
//! has been called at least once (by this exporter or by `dropwatch -l kas`).
//! `collect()` always attempts START before querying stats; idempotent starts
//! return kernel error `EBUSY` (16) which is silently ignored.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use nlx_domain::{error::DomainError, metric::MetricSample, model::drop_monitor::DropEvent};
use nlx_ports::{
    collector::{BoxFuture, Collector},
    driven::NetlinkDropMonitorPort,
    error::CollectError,
};
use tracing::{debug, warn};

use crate::{
    transport::NetlinkSocket,
    wire::{NLA_HDRLEN, align4, nested_attrs, parse_attrs, read_u32, read_u64},
};

const NETLINK_GENERIC: i32 = 16;

// ---------------------------------------------------------------------------
// NET_DM commands — from uapi/linux/net_dropmon.h (enum starting at 0).
// ---------------------------------------------------------------------------

/// `NET_DM_CMD_CONFIG` — configure alert mode. Requires `CAP_NET_ADMIN`.
const NET_DM_CMD_CONFIG: u8 = 2;
/// `NET_DM_CMD_START` — begin monitoring. Requires `CAP_NET_ADMIN`.
const NET_DM_CMD_START: u8 = 3;
/// `NET_DM_CMD_STATS_GET` — pull aggregate drop statistics. No privilege required.
const NET_DM_CMD_STATS_GET: u8 = 8;
/// `NET_DM_CMD_ALERT` — multicast drop alert (kernel→user on `NET_DM_GRP_ALERT`).
/// In SUMMARY mode the payload carries per-location SW drop counts (and, for HW
/// drops, `NET_DM_ATTR_HW_ENTRIES`). This is the ONLY source of real total drop
/// counts — `NET_DM_CMD_STATS_GET` returns the monitor's own overflow counter.
const NET_DM_CMD_ALERT: u8 = 1;

/// Generic netlink family version for `NET_DM` (family `.version = 2`).
const NET_DM_GENL_VERSION: u8 = 2;

// ---------------------------------------------------------------------------
// NET_DM attribute types — from uapi/linux/net_dropmon.h (enum net_dm_attr).
// ---------------------------------------------------------------------------

/// `NET_DM_ATTR_ALERT_MODE` (u8): summary=0, packet=1.
const NET_DM_ATTR_ALERT_MODE: u16 = 1;
/// `NET_DM_ATTR_STATS` (nested): contains `NET_DM_ATTR_STATS_DROPPED`.
const NET_DM_ATTR_STATS: u16 = 12;
/// `NET_DM_ATTR_HW_STATS` (nested): contains `NET_DM_ATTR_STATS_DROPPED`.
const NET_DM_ATTR_HW_STATS: u16 = 13;
/// `NET_DM_ATTR_HW_ENTRIES` (nested): list of `NET_DM_ATTR_HW_ENTRY` in an ALERT.
const NET_DM_ATTR_HW_ENTRIES: u16 = 17;
/// `NET_DM_ATTR_HW_ENTRY` (nested): one HW trap entry inside `HW_ENTRIES`.
const NET_DM_ATTR_HW_ENTRY: u16 = 18;
/// `NET_DM_ATTR_HW_TRAP_COUNT` (u32): drop count for one HW trap entry.
/// Value 19 in `enum net_dm_attr` (net_dropmon.h:85) — NOT 22 (FLOW_ACTION_COOKIE).
const NET_DM_ATTR_HW_TRAP_COUNT: u16 = 19;

/// Ancillary `net_dm_alert_msg` carried as `NLA_UNSPEC` (type 0) in an ALERT.
/// Layout: `u32 entries` then `entries × net_dm_drop_point`.
const NET_DM_ATTR_ALERT_UNSPEC: u16 = 0;
/// `struct net_dm_drop_point { __u8 pc[8]; __u32 count; }` — 12 bytes.
const NET_DM_DROP_POINT_LEN: usize = 12;

// ---------------------------------------------------------------------------
// NET_DM inner stats attributes — from uapi/linux/net_dropmon.h
// (enum starting at 0: NET_DM_ATTR_STATS_DROPPED = 0, but the first enum
// member is actually 0=DROPPED when counting from 0).
//
// The kernel code:
//   attr = nla_nest_start(msg, NET_DM_ATTR_STATS);
//   nla_put_u64_64bit(msg, NET_DM_ATTR_STATS_DROPPED, dropped, NET_DM_ATTR_PAD)
//
// `NET_DM_ATTR_STATS_DROPPED` is type 0 inside the nested STATS container
// (it is the first value in its own enum starting at 0).
// ---------------------------------------------------------------------------

/// `NET_DM_ATTR_STATS_DROPPED` (u64) — inner attr type 0 inside the STATS/HW_STATS nested.
const NET_DM_ATTR_STATS_DROPPED: u16 = 0;

/// Summary alert mode (kernel: `NET_DM_ALERT_MODE_SUMMARY = 0`).
///
/// From uapi/linux/net_dropmon.h:
/// ```c
/// enum net_dm_alert_mode {
///     NET_DM_ALERT_MODE_SUMMARY,   // = 0
///     NET_DM_ALERT_MODE_PACKET,    // = 1
/// };
/// ```
const NET_DM_ALERT_MODE_SUMMARY: u8 = 0;

/// Kernel errno `EBUSY` (16) — returned when `NET_DM_CMD_CONFIG` is sent while
/// monitoring is already active, or when `NET_DM_CMD_START` is called again.
/// Safe to ignore; the monitoring session started by a previous call is reused.
const EBUSY: i32 = 16;

/// Kernel errno `EALREADY` (114) — alternative "already monitoring" error on
/// some kernel versions.
const EALREADY: i32 = 114;

/// Kernel errno `EAGAIN` (11) — returned by `set_all_monitor_traces()` when the
/// trace state already equals the requested value (kernel:
/// "Trace state is already set to the requested value",
/// `net/core/drop_monitor.c:1227`). This is the actual error `NET_DM_CMD_START`
/// returns on the second and subsequent scrapes — NOT `EBUSY`/`EALREADY`. Safe
/// to ignore: monitoring is already active, which is the desired outcome.
const EAGAIN: i32 = 11;

// ---------------------------------------------------------------------------
// Lock-free shared drop counters (ADR-0020 hybrid model, ADR-0023 lock-free)
// ---------------------------------------------------------------------------

/// Running totals of real packet drops observed on the `NET_DM_GRP_ALERT`
/// multicast stream, accumulated by [`spawn_listener`] and read on every scrape
/// by [`DropMonitorCollector::collect`].
///
/// Lock-free: two `AtomicU64` counters, `Relaxed` ordering (monotonic counters,
/// best-effort telemetry). No `Mutex`/`RwLock` (ADR-0023).
#[derive(Debug, Default)]
pub struct DropCounters {
    /// Cumulative software drops (sum of `net_dm_drop_point.count` across ALERTs).
    pub sw: AtomicU64,
    /// Cumulative hardware drops (sum of `NET_DM_ATTR_HW_TRAP_COUNT` across ALERTs).
    pub hw: AtomicU64,
}

// ---------------------------------------------------------------------------
// Public collector struct
// ---------------------------------------------------------------------------

/// Adapter implementing [`NetlinkDropMonitorPort`] and [`Collector`] for
/// drop-monitor statistics (ADR-0020 hybrid model).
///
/// Two metric sources:
/// - `nft_drop_packets_total{origin}` — REAL drop totals read lock-free from the
///   shared [`DropCounters`] that [`spawn_listener`] fills from the multicast
///   `NET_DM_CMD_ALERT` stream.
/// - `nft_drop_monitor_unreported_total{origin}` — the monitor's own
///   queue-overflow counter pulled per-scrape via `NET_DM_CMD_STATS_GET`
///   (a monitor-health signal, NOT a drop total).
pub struct DropMonitorCollector {
    counters: Arc<DropCounters>,
}

impl Default for DropMonitorCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl DropMonitorCollector {
    /// Construct with a fresh, unshared counter set. The totals stay zero unless
    /// a listener is started on the same `Arc` — prefer [`Self::with_counters`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            counters: Arc::new(DropCounters::default()),
        }
    }

    /// Construct sharing the [`DropCounters`] populated by [`spawn_listener`].
    #[must_use]
    pub fn with_counters(counters: Arc<DropCounters>) -> Self {
        Self { counters }
    }
}

// ---------------------------------------------------------------------------
// NetlinkDropMonitorPort implementation
// ---------------------------------------------------------------------------

impl NetlinkDropMonitorPort for DropMonitorCollector {
    async fn dump_drop_events(&self) -> Result<Vec<DropEvent>, DomainError> {
        let mut sock = NetlinkSocket::open(NETLINK_GENERIC)
            .map_err(|e| DomainError::Collector(e.to_string()))?;

        let Some(family_id) = sock
            .resolve_genl_family("NET_DM")
            .await
            .map_err(|e| DomainError::Collector(e.to_string()))?
        else {
            debug!("NET_DM genetlink family not loaded");
            return Ok(vec![]);
        };

        // Ensure monitoring is active before querying stats.
        start_monitoring(&mut sock, family_id)
            .await
            .map_err(|e| DomainError::Collector(e.to_string()))?;

        fetch_stats(&mut sock, family_id)
            .await
            .map_err(|e| DomainError::Collector(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Collector implementation
// ---------------------------------------------------------------------------

impl Collector for DropMonitorCollector {
    fn name(&self) -> &str {
        "drop_monitor"
    }

    fn collect(&self) -> BoxFuture<'_, Result<Vec<MetricSample>, CollectError>> {
        Box::pin(async move {
            let mut out = Vec::with_capacity(4);

            // --- B: REAL drop totals from the multicast ALERT accumulator ---
            // Lock-free read of the counters filled by spawn_listener(). These
            // are the actual drop counts; collect() never fails on them, so the
            // collector reports success=1 whenever the subsystem is available.
            let sw_total = self.counters.sw.load(Ordering::Relaxed);
            let hw_total = self.counters.hw.load(Ordering::Relaxed);
            for (origin, total) in [("sw", sw_total), ("hw", hw_total)] {
                let mut labels = BTreeMap::new();
                labels.insert("origin".to_owned(), origin.to_owned());
                labels.insert("reason".to_owned(), "total".to_owned());
                out.push(MetricSample::counter(
                    "nft_drop_packets_total",
                    "Total packet drops observed via the NET_DM drop-monitor \
                     multicast ALERT stream since exporter start.",
                    labels,
                    total,
                ));
            }

            // --- A: monitor-overflow health via NET_DM_CMD_STATS_GET (best-effort) ---
            // NET_DM_ATTR_STATS_DROPPED counts drops the monitor itself could not
            // enqueue for reporting (per-CPU queue overflow) — a health signal,
            // NOT a drop total. Failure here is non-fatal: the real totals above
            // are already recorded.
            if let Some(events) = fetch_overflow_stats().await {
                for ev in events {
                    let mut labels = BTreeMap::new();
                    labels.insert("origin".to_owned(), ev.origin);
                    out.push(MetricSample::counter(
                        "nft_drop_monitor_unreported_total",
                        "Drops the kernel drop-monitor could not enqueue for \
                         reporting (per-CPU queue overflow); monitor-health \
                         signal, not a drop total.",
                        labels,
                        ev.dropped,
                    ));
                }
            }

            Ok(out)
        })
    }

    fn probe_available(&self) -> BoxFuture<'_, bool> {
        Box::pin(async move {
            let Ok(mut sock) = NetlinkSocket::open(NETLINK_GENERIC) else {
                return false;
            };
            matches!(sock.resolve_genl_family("NET_DM").await, Ok(Some(_)))
        })
    }
}

// ---------------------------------------------------------------------------
// Wire helpers
// ---------------------------------------------------------------------------

/// Build a 4-byte `genlmsghdr` prefix: `cmd`, `version=NET_DM_GENL_VERSION`, 2×reserved.
fn genl_hdr(cmd: u8) -> [u8; 4] {
    [cmd, NET_DM_GENL_VERSION, 0u8, 0u8]
}

/// Append one `nlattr` TLV to `buf`.
fn push_nla(buf: &mut Vec<u8>, ty: u16, payload: &[u8]) {
    let nla_len = (NLA_HDRLEN + payload.len()) as u16;
    buf.extend_from_slice(&nla_len.to_ne_bytes());
    buf.extend_from_slice(&ty.to_ne_bytes());
    buf.extend_from_slice(payload);
    let pad = align4(NLA_HDRLEN + payload.len()) - (NLA_HDRLEN + payload.len());
    buf.extend(std::iter::repeat_n(0u8, pad));
}

// ---------------------------------------------------------------------------
// Protocol operations
// ---------------------------------------------------------------------------

/// Send `NET_DM_CMD_CONFIG` (summary mode) then `NET_DM_CMD_START`.
///
/// Both commands require `CAP_NET_ADMIN`. Kernel errors `EBUSY` (16, CONFIG
/// while monitoring), `EAGAIN` (11, START when trace state already ON), and
/// `EALREADY` (114) are silently ignored — they all indicate monitoring is
/// already active, which is the desired outcome on every scrape after the first.
///
/// `NLM_F_ACK` (flag value 4) is OR-d into the flags by `request_single` on
/// top of `NLM_F_REQUEST`.  This ensures the kernel sends an acknowledgment
/// frame so the call site can confirm the command was accepted.
async fn start_monitoring(
    sock: &mut NetlinkSocket,
    family_id: u16,
) -> Result<(), crate::transport::NetlinkError> {
    use crate::transport::NetlinkError;

    // --- NET_DM_CMD_CONFIG: set SUMMARY alert mode ---
    // Payload: genlmsghdr(cmd=2,ver=2) + NLA(ALERT_MODE=0).
    let mut config_payload = genl_hdr(NET_DM_CMD_CONFIG).to_vec();
    push_nla(&mut config_payload, NET_DM_ATTR_ALERT_MODE, &[NET_DM_ALERT_MODE_SUMMARY]);

    // NLM_F_ACK = 4 so the kernel sends an ack/err frame we can read.
    match sock.request_single(family_id, 4, &config_payload).await {
        Ok(_) => {}
        Err(NetlinkError::KernelError { errno })
            if errno == EBUSY || errno == EALREADY || errno == EAGAIN =>
        {
            // Monitoring already active — CONFIG is rejected while monitoring is
            // running (kernel: "Cannot configure drop monitor during monitoring").
            // This is expected on the second and subsequent scrapes.
            debug!(errno, "NET_DM_CMD_CONFIG EBUSY/EALREADY/EAGAIN — monitoring already active");
        }
        Err(e) => return Err(e),
    }

    // --- NET_DM_CMD_START: enable SW monitoring ---
    // No extra attrs → kernel defaults to software-drops-only (backward compat).
    let start_payload = genl_hdr(NET_DM_CMD_START).to_vec();
    match sock.request_single(family_id, 4, &start_payload).await {
        Ok(_) => {}
        Err(NetlinkError::KernelError { errno })
            if errno == EBUSY || errno == EALREADY || errno == EAGAIN =>
        {
            debug!(errno, "NET_DM_CMD_START EBUSY/EALREADY/EAGAIN — already monitoring");
        }
        Err(e) => return Err(e),
    }

    Ok(())
}

/// Issue `NET_DM_CMD_STATS_GET` and parse the `NET_DM_CMD_STATS_NEW` reply.
///
/// The reply contains two nested attrs:
///
/// - `NET_DM_ATTR_STATS`    (type=12) → `NET_DM_ATTR_STATS_DROPPED` (type=0, u64) — SW total
/// - `NET_DM_ATTR_HW_STATS` (type=13) → `NET_DM_ATTR_STATS_DROPPED` (type=0, u64) — HW total
///
/// Both are returned as [`DropEvent`] entries with `origin="sw"/"hw"` and
/// `reason="total"`.
///
/// # Wire format
///
/// ```text
/// nlmsghdr (16 B)
///   └── genlmsghdr (4 B): cmd=NET_DM_CMD_STATS_NEW, ver=2
///         └── nlattr: type=NET_DM_ATTR_STATS (12), NLA_F_NESTED
///               └── nlattr: type=NET_DM_ATTR_STATS_DROPPED (0), payload=u64 (8 B)
///         └── nlattr: type=NET_DM_ATTR_HW_STATS (13), NLA_F_NESTED
///               └── nlattr: type=NET_DM_ATTR_STATS_DROPPED (0), payload=u64 (8 B)
/// ```
async fn fetch_stats(
    sock: &mut NetlinkSocket,
    family_id: u16,
) -> Result<Vec<DropEvent>, crate::transport::NetlinkError> {
    // Payload: genlmsghdr(cmd=8, ver=2), no attrs.
    let stats_payload = genl_hdr(NET_DM_CMD_STATS_GET).to_vec();

    // NLM_F_REQUEST only (flag 0) — no dump, no ack needed; `request_single`
    // OR-s NLM_F_REQUEST automatically.  Pass flags=0 so we don't request an
    // explicit ack frame (the reply IS the response).
    let reply = sock.request_single(family_id, 0, &stats_payload).await?;

    let Some(payload) = reply else {
        warn!("NET_DM_CMD_STATS_GET returned empty reply");
        return Ok(vec![]);
    };

    // Skip genlmsghdr (4 bytes): cmd + version + reserved[2].
    if payload.len() < 4 {
        warn!(len = payload.len(), "NET_DM_CMD_STATS_GET reply too short for genlmsghdr");
        return Ok(vec![]);
    }
    let attrs_buf = &payload[4..];

    let mut sw_dropped: u64 = 0;
    let mut hw_dropped: u64 = 0;

    for attr in parse_attrs(attrs_buf) {
        match attr.ty {
            NET_DM_ATTR_STATS => {
                for inner in nested_attrs(attr.payload) {
                    if inner.ty == NET_DM_ATTR_STATS_DROPPED {
                        sw_dropped = read_u64(inner.payload).unwrap_or(0);
                    }
                }
            }
            NET_DM_ATTR_HW_STATS => {
                for inner in nested_attrs(attr.payload) {
                    if inner.ty == NET_DM_ATTR_STATS_DROPPED {
                        hw_dropped = read_u64(inner.payload).unwrap_or(0);
                    }
                }
            }
            _ => {}
        }
    }

    debug!(sw_dropped, hw_dropped, "NET_DM_CMD_STATS_GET parsed");

    Ok(vec![
        DropEvent {
            reason: "total".to_owned(),
            origin: "sw".to_owned(),
            dropped: sw_dropped,
        },
        DropEvent {
            reason: "total".to_owned(),
            origin: "hw".to_owned(),
            dropped: hw_dropped,
        },
    ])
}

// ---------------------------------------------------------------------------
// Overflow-counter pull (ADR-0020 hybrid — monitor-health metric "A")
// ---------------------------------------------------------------------------

/// Best-effort pull of the monitor's per-CPU overflow counter via
/// `NET_DM_CMD_STATS_GET`. Returns `None` (logged at `debug`) on any error —
/// the real drop totals come from the multicast accumulator, so this query is a
/// non-fatal health signal only and must never fail the scrape.
async fn fetch_overflow_stats() -> Option<Vec<DropEvent>> {
    let mut sock = match NetlinkSocket::open(NETLINK_GENERIC) {
        Ok(s) => s,
        Err(e) => {
            debug!(error = %e, "NETLINK_GENERIC open failed; overflow metric skipped");
            return None;
        }
    };
    let family_id = match sock.resolve_genl_family("NET_DM").await {
        Ok(Some(id)) => id,
        Ok(None) => {
            debug!("NET_DM family not loaded; overflow metric skipped");
            return None;
        }
        Err(e) => {
            debug!(error = %e, "NET_DM resolve failed; overflow metric skipped");
            return None;
        }
    };
    match fetch_stats(&mut sock, family_id).await {
        Ok(events) => Some(events),
        Err(e) => {
            debug!(error = %e, "NET_DM_CMD_STATS_GET failed; overflow metric skipped");
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Summary-mode ALERT parser (ADR-0020 hybrid — real drop totals "B")
// ---------------------------------------------------------------------------

/// Parse a SUMMARY-mode `NET_DM_CMD_ALERT` attribute region (the bytes after the
/// 4-byte `genlmsghdr`). Returns `(sw_drops, hw_drops)` summed across this frame.
///
/// Wire format (kernel `net/core/drop_monitor.c`):
/// - SW: `NLA_UNSPEC` (type 0) → `net_dm_alert_msg { u32 entries; points[] }`;
///   each `net_dm_drop_point { u8 pc[8]; u32 count }` (12 B). Sum of `count`.
/// - HW: `NET_DM_ATTR_HW_ENTRIES` (17) → `NET_DM_ATTR_HW_ENTRY` (18) →
///   `NET_DM_ATTR_HW_TRAP_COUNT` (19, u32). Sum of `count`.
fn parse_summary_alert(attrs_buf: &[u8]) -> (u64, u64) {
    let mut sw: u64 = 0;
    let mut hw: u64 = 0;

    for attr in parse_attrs(attrs_buf) {
        match attr.ty {
            NET_DM_ATTR_ALERT_UNSPEC => {
                let p = attr.payload;
                if p.len() < 4 {
                    continue;
                }
                let entries = read_u32(&p[0..4]).unwrap_or(0) as usize;
                for i in 0..entries {
                    let off = 4 + i * NET_DM_DROP_POINT_LEN;
                    if off + NET_DM_DROP_POINT_LEN > p.len() {
                        break;
                    }
                    // count is the u32 after the 8-byte pc[] within each point.
                    let count = read_u32(&p[off + 8..off + 12]).unwrap_or(0);
                    sw = sw.saturating_add(u64::from(count));
                }
            }
            NET_DM_ATTR_HW_ENTRIES => {
                for entry in nested_attrs(attr.payload) {
                    if entry.ty == NET_DM_ATTR_HW_ENTRY {
                        for f in nested_attrs(entry.payload) {
                            if f.ty == NET_DM_ATTR_HW_TRAP_COUNT {
                                let count = read_u32(f.payload).unwrap_or(0);
                                hw = hw.saturating_add(u64::from(count));
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    (sw, hw)
}

// ---------------------------------------------------------------------------
// Multicast ALERT listener — background thread, lock-free atomics (ADR-0020)
// ---------------------------------------------------------------------------

/// Perform the privileged NET_DM listener setup, then spawn the recv-only
/// background thread.
///
/// **Capability ordering (ADR-0009 / ADR-0026).** The privileged setup —
/// `NET_DM_CMD_CONFIG`/`START` (need `CAP_NET_ADMIN`) and the `events`
/// multicast-group join (needs `CAP_SYS_ADMIN`, group flag
/// `GENL_MCAST_CAP_SYS_ADMIN`) — runs **on the caller thread**, which MUST be
/// invoked BEFORE the process drops capabilities. The spawned recv loop needs
/// no capabilities (it only receives on the already-joined socket).
///
/// Returns `Err` if setup fails; the caller logs and continues (totals stay 0,
/// the overflow-pull health metric still works). On non-Linux this is a no-op.
#[cfg(target_os = "linux")]
pub fn setup_and_spawn_listener(counters: Arc<DropCounters>) -> std::result::Result<(), String> {
    // Privileged phase — caller thread, pre cap-drop.
    let (fd, family_id) = setup_listener_socket()?;

    std::thread::Builder::new()
        .name("nft-dropmon".to_owned())
        .spawn(move || {
            // Recv-only phase — no capabilities required. Re-create the ring and
            // continue on transient recv errors so the listener self-heals.
            loop {
                if let Err(e) = recv_loop(&fd, family_id, &counters) {
                    tracing::error!(error = %e, "drop_monitor recv loop error; restarting in 5s");
                    std::thread::sleep(std::time::Duration::from_secs(5));
                }
            }
        })
        .map_err(|e| format!("spawn nft-dropmon thread: {e}"))?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::unnecessary_wraps, reason = "stub mirrors the Linux signature")]
pub fn setup_and_spawn_listener(_counters: Arc<DropCounters>) -> std::result::Result<(), String> {
    Ok(())
}

/// Build a complete `nlmsghdr`-framed request (`NLM_F_REQUEST | flags`).
#[cfg(target_os = "linux")]
fn build_nlmsg(msg_type: u16, flags: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
    let total = crate::transport::NLMSG_HDRLEN + payload.len();
    let mut b = Vec::with_capacity(align4(total));
    b.extend_from_slice(&(total as u32).to_ne_bytes());
    b.extend_from_slice(&msg_type.to_ne_bytes());
    b.extend_from_slice(&(0x0001u16 | flags).to_ne_bytes()); // NLM_F_REQUEST | flags
    b.extend_from_slice(&seq.to_ne_bytes());
    b.extend_from_slice(&0u32.to_ne_bytes()); // nl_pid = 0
    b.extend_from_slice(payload);
    b
}

/// Privileged setup (caller thread, pre cap-drop): open the genl socket, resolve
/// the family + `events` group, enable SUMMARY monitoring, and join the group —
/// all over io_uring. Returns the joined+configured fd and the family id.
#[cfg(target_os = "linux")]
fn setup_listener_socket() -> std::result::Result<(std::os::fd::OwnedFd, u16), String> {
    use std::os::fd::AsRawFd;

    let fd = NetlinkSocket::open_raw_fd(NETLINK_GENERIC).map_err(|e| e.to_string())?;
    let raw = fd.as_raw_fd();
    let mut ring = io_uring::IoUring::new(8).map_err(|e| format!("io_uring::new: {e}"))?;

    // 1. Resolve the NET_DM family id and the "events" multicast group id.
    let (family_id, group_id) = resolve_family_and_group(&mut ring, raw)?;

    // 2. Enable SUMMARY-mode monitoring via unicast CONFIG + START *before*
    //    joining the multicast group, so the unicast ACKs are not interleaved
    //    with multicast ALERT frames. Benign "already monitoring" errnos are
    //    tolerated (a previous run may have left monitoring on).
    let mut cfg = genl_hdr(NET_DM_CMD_CONFIG).to_vec();
    push_nla(&mut cfg, NET_DM_ATTR_ALERT_MODE, &[NET_DM_ALERT_MODE_SUMMARY]);
    unicast_ack(&mut ring, raw, family_id, &cfg, 1)?;
    let start = genl_hdr(NET_DM_CMD_START).to_vec();
    unicast_ack(&mut ring, raw, family_id, &start, 2)?;

    // 3. Join the multicast group over io_uring (CAP_SYS_ADMIN — pre cap-drop).
    join_mcast_group(&mut ring, raw, group_id)?;
    tracing::info!(
        family_id,
        group_id,
        "drop_monitor multicast listener joined (NET_DM_GRP_ALERT, summary mode)"
    );

    Ok((fd, family_id))
}

/// Recv-only loop (background thread, no capabilities): receive `NET_DM_CMD_ALERT`
/// frames over io_uring and accumulate SW/HW drop counts into the atomics.
#[cfg(target_os = "linux")]
fn recv_loop(
    fd: &std::os::fd::OwnedFd,
    family_id: u16,
    counters: &Arc<DropCounters>,
) -> std::result::Result<(), String> {
    use std::os::fd::AsRawFd;

    use crate::transport::{NLMSG_HDRLEN, NetlinkError, uring_recv};

    let raw = fd.as_raw_fd();
    let mut ring = io_uring::IoUring::new(32).map_err(|e| format!("io_uring::new: {e}"))?;
    let mut buf = vec![0u8; 64 * 1024];

    loop {
        let n = match uring_recv(&mut ring, raw, &mut buf) {
            Ok(n) => n,
            Err(NetlinkError::RecvBufOverflow) => {
                tracing::warn!("NET_DM ALERT recv ENOBUFS — a drop batch was lost");
                continue;
            }
            Err(e) => return Err(format!("recv: {e}")),
        };

        let data = &buf[..n.min(buf.len())];
        let mut pos = 0usize;
        while pos + NLMSG_HDRLEN <= data.len() {
            let nl = u32::from_ne_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]])
                as usize;
            let ty = u16::from_ne_bytes([data[pos + 4], data[pos + 5]]);
            if nl < NLMSG_HDRLEN || pos + nl > data.len() {
                break;
            }
            let mpayload = &data[pos + NLMSG_HDRLEN..pos + nl];
            // genl: nlmsg_type == family_id; first payload byte == genl cmd.
            if ty == family_id && mpayload.len() >= 4 && mpayload[0] == NET_DM_CMD_ALERT {
                let (sw, hw) = parse_summary_alert(&mpayload[4..]);
                if sw > 0 {
                    counters.sw.fetch_add(sw, Ordering::Relaxed);
                }
                if hw > 0 {
                    counters.hw.fetch_add(hw, Ordering::Relaxed);
                }
            }
            pos += align4(nl);
        }
    }
}

/// Send a unicast genl command with `NLM_F_ACK` and consume the ACK/ERROR frame.
/// Benign "already monitoring" errnos (`EBUSY`/`EAGAIN`/`EALREADY`) are ignored.
#[cfg(target_os = "linux")]
fn unicast_ack(
    ring: &mut io_uring::IoUring,
    raw: std::os::fd::RawFd,
    family_id: u16,
    genl_payload: &[u8],
    seq: u32,
) -> std::result::Result<(), String> {
    use crate::transport::{NLMSG_HDRLEN, uring_recv, uring_send};

    let msg = build_nlmsg(family_id, 0x0004, seq, genl_payload); // NLM_F_ACK
    uring_send(ring, raw, &msg).map_err(|e| e.to_string())?;

    let mut buf = vec![0u8; 8192];
    let n = uring_recv(ring, raw, &mut buf).map_err(|e| e.to_string())?;
    if n >= NLMSG_HDRLEN + 4 {
        let ty = u16::from_ne_bytes([buf[4], buf[5]]);
        if ty == 2 {
            // NLMSG_ERROR: errno is the first 4 bytes of the payload.
            let errno =
                i32::from_ne_bytes([buf[16], buf[17], buf[18], buf[19]]).abs();
            if errno != 0 && errno != EBUSY && errno != EAGAIN && errno != EALREADY {
                return Err(format!("ACK errno={errno}"));
            }
        }
    }
    Ok(())
}

/// Resolve `(family_id, events_group_id)` for NET_DM via `CTRL_CMD_GETFAMILY`.
#[cfg(target_os = "linux")]
fn resolve_family_and_group(
    ring: &mut io_uring::IoUring,
    raw: std::os::fd::RawFd,
) -> std::result::Result<(u16, u32), String> {
    use crate::transport::{NLMSG_HDRLEN, uring_recv, uring_send};
    use crate::wire::read_u16;

    const GENL_ID_CTRL: u16 = 0x10;
    const CTRL_CMD_GETFAMILY: u8 = 3;
    const CTRL_ATTR_FAMILY_ID: u16 = 1;
    const CTRL_ATTR_FAMILY_NAME: u16 = 2;
    const CTRL_ATTR_MCAST_GROUPS: u16 = 7;
    const CTRL_ATTR_MCAST_GRP_NAME: u16 = 1;
    const CTRL_ATTR_MCAST_GRP_ID: u16 = 2;

    // genlmsghdr(cmd=GETFAMILY, ver=1) + NLA(FAMILY_NAME="NET_DM\0").
    let mut genl = vec![CTRL_CMD_GETFAMILY, 1u8, 0u8, 0u8];
    push_nla(&mut genl, CTRL_ATTR_FAMILY_NAME, b"NET_DM\0");
    let msg = build_nlmsg(GENL_ID_CTRL, 0, 1, &genl);
    uring_send(ring, raw, &msg).map_err(|e| e.to_string())?;

    let mut buf = vec![0u8; 16 * 1024];
    let n = uring_recv(ring, raw, &mut buf).map_err(|e| e.to_string())?;
    let data = &buf[..n.min(buf.len())];
    if data.len() < NLMSG_HDRLEN + 4 {
        return Err("CTRL reply too short".to_owned());
    }
    let ty = u16::from_ne_bytes([data[4], data[5]]);
    if ty == 2 {
        let errno = i32::from_ne_bytes([data[16], data[17], data[18], data[19]]).abs();
        return Err(format!("CTRL_CMD_GETFAMILY errno={errno}"));
    }

    // payload after nlmsghdr = genlmsghdr(4) + attrs.
    let attrs = &data[NLMSG_HDRLEN + 4..];
    let mut family_id: Option<u16> = None;
    let mut group_id: Option<u32> = None;
    for attr in parse_attrs(attrs) {
        match attr.ty {
            CTRL_ATTR_FAMILY_ID => family_id = read_u16(attr.payload),
            CTRL_ATTR_MCAST_GROUPS => {
                for grp in nested_attrs(attr.payload) {
                    let mut gid: Option<u32> = None;
                    let mut gname: Option<String> = None;
                    for f in nested_attrs(grp.payload) {
                        match f.ty {
                            CTRL_ATTR_MCAST_GRP_ID => gid = read_u32(f.payload),
                            CTRL_ATTR_MCAST_GRP_NAME => {
                                let end = f
                                    .payload
                                    .iter()
                                    .position(|&b| b == 0)
                                    .unwrap_or(f.payload.len());
                                gname = Some(
                                    String::from_utf8_lossy(&f.payload[..end]).into_owned(),
                                );
                            }
                            _ => {}
                        }
                    }
                    if gname.as_deref() == Some("events") {
                        group_id = gid;
                    }
                }
            }
            _ => {}
        }
    }

    let fid = family_id.ok_or_else(|| "CTRL_ATTR_FAMILY_ID missing".to_owned())?;
    let gid = group_id.ok_or_else(|| "NET_DM 'events' multicast group not found".to_owned())?;
    Ok((fid, gid))
}

/// `SOL_NETLINK` socket level.
#[cfg(target_os = "linux")]
const SOL_NETLINK: u32 = 270;
/// `NETLINK_ADD_MEMBERSHIP` socket option.
#[cfg(target_os = "linux")]
const NETLINK_ADD_MEMBERSHIP: u32 = 1;

/// Join a generic-netlink multicast group via **io_uring**
/// `IORING_OP_URING_CMD` / `SOCKET_URING_OP_SETSOCKOPT` (kernel ≥ 6.7).
///
/// This keeps the entire NET_DM control + data path on io_uring (ADR-0024): the
/// group-join `setsockopt(NETLINK_ADD_MEMBERSHIP)` is submitted as an io_uring
/// op rather than a blocking syscall. On kernels < 6.7 (where the op returns
/// `EOPNOTSUPP`/`EINVAL`) it falls back to a blocking `libc::setsockopt`.
///
/// Requires `CAP_SYS_ADMIN`: the NET_DM `events` group is declared
/// `GENL_MCAST_CAP_SYS_ADMIN` (`net/core/drop_monitor.c:187`), so this must run
/// before the process drops capabilities (ADR-0009 / ADR-0026).
#[cfg(target_os = "linux")]
fn join_mcast_group(
    ring: &mut io_uring::IoUring,
    raw: std::os::fd::RawFd,
    group_id: u32,
) -> std::result::Result<(), String> {
    use io_uring::{opcode, types};

    let gid: u32 = group_id;
    let entry = opcode::SetSockOpt::new(
        types::Fd(raw),
        SOL_NETLINK,
        NETLINK_ADD_MEMBERSHIP,
        std::ptr::addr_of!(gid).cast::<libc::c_void>(),
        std::mem::size_of::<u32>() as u32,
    )
    .build()
    .user_data(7);

    // SAFETY: `gid` is a live local read by the kernel via `optval`; it is not
    // moved or dropped until the matching CQE is consumed below (single op in
    // flight, `submit_and_wait(1)` then immediate drain). `raw` is a valid fd.
    unsafe {
        ring.submission()
            .push(&entry)
            .map_err(|e| format!("SETSOCKOPT SQ push: {e:?}"))?;
    }
    ring.submit_and_wait(1)
        .map_err(|e| format!("SETSOCKOPT submit_and_wait: {e}"))?;

    let res = ring
        .completion()
        .next()
        .map(|c| c.result())
        .ok_or_else(|| "no CQE after SETSOCKOPT".to_owned())?;
    if res < 0 {
        let e = -res;
        if e == libc::EOPNOTSUPP || e == libc::EINVAL || e == libc::ENOSYS {
            debug!(errno = e, "io_uring SETSOCKOPT unsupported (kernel < 6.7); falling back");
            return join_mcast_group_libc(raw, group_id);
        }
        return Err(format!("io_uring NETLINK_ADD_MEMBERSHIP errno={e}"));
    }
    Ok(())
}

/// Blocking `setsockopt(NETLINK_ADD_MEMBERSHIP)` fallback for kernels < 6.7.
#[cfg(target_os = "linux")]
fn join_mcast_group_libc(
    raw: std::os::fd::RawFd,
    group_id: u32,
) -> std::result::Result<(), String> {
    let gid: libc::c_int = group_id as libc::c_int;
    // SAFETY: `raw` is a valid open AF_NETLINK fd; the constants are well-known
    // kernel ABI values; `addr_of!(gid)` is a valid 4-byte read pointer.
    let ret = unsafe {
        libc::setsockopt(
            raw,
            SOL_NETLINK as libc::c_int,
            NETLINK_ADD_MEMBERSHIP as libc::c_int,
            std::ptr::addr_of!(gid).cast::<libc::c_void>(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(format!(
            "NETLINK_ADD_MEMBERSHIP (libc): {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Parser for NET_DM_GRP_ALERT packet-mode frames (future use)
// ---------------------------------------------------------------------------

/// Parse one `NET_DM_CMD_ALERT` (summary-mode) or `NET_DM_CMD_PACKET_ALERT`
/// (packet-mode) frame payload (after `genlmsghdr`).
///
/// Summary-mode ALERT frames (`NET_DM_CMD_ALERT` = 1) carry a legacy
/// `net_dm_alert_msg` structure via `NLA_UNSPEC` plus optional `NET_DM_ATTR_HW_ENTRIES`
/// nested attrs for hardware drops.  They do NOT contain `NET_DM_ATTR_REASON`.
///
/// Packet-mode ALERT frames (`NET_DM_CMD_PACKET_ALERT` = 5) carry:
/// - `NET_DM_ATTR_ORIGIN` (u16): `0`=SW, `1`=HW
/// - `NET_DM_ATTR_REASON` (string, kernel ≥ 5.17): drop-reason name
/// - `NET_DM_ATTR_STATS` (nested): dropped count for this alert
/// - `NET_DM_ATTR_HW_TRAP_NAME` (string, HW only): hardware trap name
///
/// This function handles both; returns `None` when required fields are absent.
///
/// **Not called in the STATS_GET pull model.** Retained for the future multicast
/// subscriber integration (NET_DM_GRP_ALERT group, group index 1).
#[expect(dead_code, reason = "reserved for future NET_DM_GRP_ALERT multicast integration")]
pub(crate) fn parse_alert_frame(attrs_buf: &[u8]) -> Option<DropEvent> {
    // Attribute type constants used only in this function (from enum net_dm_attr).
    // Counting from UNSPEC=0: ORIGIN=14, HW_TRAP_NAME=16, REASON=23.
    const NET_DM_ATTR_ORIGIN: u16 = 14;
    const NET_DM_ATTR_HW_TRAP_NAME: u16 = 16;
    const NET_DM_ATTR_REASON: u16 = 23;
    const NET_DM_ORIGIN_SW: u16 = 0;

    let mut origin_raw: u16 = 0;
    let mut reason: Option<String> = None;
    let mut hw_trap: Option<String> = None;
    let mut dropped: u64 = 0;

    for attr in parse_attrs(attrs_buf) {
        match attr.ty {
            NET_DM_ATTR_ORIGIN => {
                origin_raw = crate::wire::read_u16(attr.payload).unwrap_or(0);
            }
            NET_DM_ATTR_REASON => {
                let end = attr
                    .payload
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(attr.payload.len());
                reason = Some(String::from_utf8_lossy(&attr.payload[..end]).into_owned());
            }
            NET_DM_ATTR_HW_TRAP_NAME => {
                let end = attr
                    .payload
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(attr.payload.len());
                hw_trap = Some(String::from_utf8_lossy(&attr.payload[..end]).into_owned());
            }
            NET_DM_ATTR_STATS => {
                for inner in nested_attrs(attr.payload) {
                    if inner.ty == NET_DM_ATTR_STATS_DROPPED {
                        dropped = dropped.saturating_add(read_u64(inner.payload).unwrap_or(0));
                    }
                }
            }
            _ => {}
        }
    }

    let origin_str = if origin_raw == NET_DM_ORIGIN_SW { "sw" } else { "hw" };

    let reason_str = if origin_raw == NET_DM_ORIGIN_SW {
        match reason {
            Some(r) => r,
            None => {
                // NET_DM_ATTR_REASON absent — summary-mode ALERT or kernel < 5.17.
                // Summary-mode ALERT frames carry per-PC drop counts in the legacy
                // net_dm_alert_msg struct (NLA_UNSPEC) without a reason string.
                warn!("NET_DM alert missing NET_DM_ATTR_REASON (summary-mode or kernel < 5.17)");
                return None;
            }
        }
    } else {
        hw_trap.unwrap_or_else(|| "unknown".to_owned())
    };

    Some(DropEvent {
        reason: reason_str,
        origin: origin_str.to_owned(),
        dropped,
    })
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{NLA_HDRLEN, align4};

    /// Build a minimal nlattr TLV.
    fn make_nla(ty: u16, payload: &[u8]) -> Vec<u8> {
        let nla_len = NLA_HDRLEN + payload.len();
        let padded = align4(nla_len);
        let mut out = Vec::with_capacity(padded);
        out.extend_from_slice(&(nla_len as u16).to_ne_bytes());
        out.extend_from_slice(&ty.to_ne_bytes());
        out.extend_from_slice(payload);
        out.resize(padded, 0u8);
        out
    }

    /// Build a nested nlattr: outer type wrapping an inner sequence.
    fn make_nested_nla(outer_ty: u16, inner: &[u8]) -> Vec<u8> {
        // NLA_F_NESTED = 0x8000 — mirrors what the kernel sends.
        make_nla(outer_ty | 0x8000, inner)
    }

    /// Synthesise a `NET_DM_CMD_STATS_NEW` reply payload (after nlmsghdr):
    /// genlmsghdr(4 B) + STATS nested + HW_STATS nested.
    fn make_stats_reply(sw: u64, hw: u64) -> Vec<u8> {
        // genlmsghdr: cmd=NET_DM_CMD_STATS_NEW(9), ver=2, reserved[2].
        let mut buf = vec![9u8, 2u8, 0u8, 0u8];

        // Inner STATS_DROPPED attr (type=0, u64).
        let inner_sw = make_nla(NET_DM_ATTR_STATS_DROPPED, &sw.to_ne_bytes());
        buf.extend_from_slice(&make_nested_nla(NET_DM_ATTR_STATS, &inner_sw));

        let inner_hw = make_nla(NET_DM_ATTR_STATS_DROPPED, &hw.to_ne_bytes());
        buf.extend_from_slice(&make_nested_nla(NET_DM_ATTR_HW_STATS, &inner_hw));

        buf
    }

    #[test]
    fn genl_hdr_bytes() {
        let hdr = genl_hdr(NET_DM_CMD_STATS_GET);
        assert_eq!(hdr[0], 8, "cmd must be NET_DM_CMD_STATS_GET");
        assert_eq!(hdr[1], NET_DM_GENL_VERSION, "version must be 2");
        assert_eq!(hdr[2], 0);
        assert_eq!(hdr[3], 0);
    }

    #[test]
    fn parse_stats_reply_sw_and_hw() {
        let reply = make_stats_reply(1234, 5678);
        // Simulate what fetch_stats does after receiving the reply.
        assert!(reply.len() >= 4, "reply must have genlmsghdr");
        let attrs_buf = &reply[4..];

        let mut sw_dropped = 0u64;
        let mut hw_dropped = 0u64;
        for attr in parse_attrs(attrs_buf) {
            match attr.ty {
                NET_DM_ATTR_STATS => {
                    for inner in nested_attrs(attr.payload) {
                        if inner.ty == NET_DM_ATTR_STATS_DROPPED {
                            sw_dropped = read_u64(inner.payload).unwrap_or(0);
                        }
                    }
                }
                NET_DM_ATTR_HW_STATS => {
                    for inner in nested_attrs(attr.payload) {
                        if inner.ty == NET_DM_ATTR_STATS_DROPPED {
                            hw_dropped = read_u64(inner.payload).unwrap_or(0);
                        }
                    }
                }
                _ => {}
            }
        }
        assert_eq!(sw_dropped, 1234, "SW dropped mismatch");
        assert_eq!(hw_dropped, 5678, "HW dropped mismatch");
    }

    #[test]
    fn parse_stats_reply_zeroes() {
        let reply = make_stats_reply(0, 0);
        let attrs_buf = &reply[4..];
        let mut sw = 0u64;
        let mut hw = 0u64;
        for attr in parse_attrs(attrs_buf) {
            match attr.ty {
                NET_DM_ATTR_STATS => {
                    for inner in nested_attrs(attr.payload) {
                        if inner.ty == NET_DM_ATTR_STATS_DROPPED {
                            sw = read_u64(inner.payload).unwrap_or(0);
                        }
                    }
                }
                NET_DM_ATTR_HW_STATS => {
                    for inner in nested_attrs(attr.payload) {
                        if inner.ty == NET_DM_ATTR_STATS_DROPPED {
                            hw = read_u64(inner.payload).unwrap_or(0);
                        }
                    }
                }
                _ => {}
            }
        }
        assert_eq!(sw, 0);
        assert_eq!(hw, 0);
    }

    #[test]
    fn parse_alert_frame_sw_with_reason() {
        // Packet-mode alert: ORIGIN=0(sw) + REASON="SKB_DROP_REASON_TCP_CSUM" + STATS.
        const NET_DM_ATTR_ORIGIN: u16 = 14;
        const NET_DM_ATTR_REASON: u16 = 23; // FLOW_ACTION_COOKIE=22, REASON=23

        let origin_bytes = 0u16.to_ne_bytes();
        let reason_str = b"SKB_DROP_REASON_TCP_CSUM\0";
        let dropped_bytes = 42u64.to_ne_bytes();
        let inner_dropped = make_nla(NET_DM_ATTR_STATS_DROPPED, &dropped_bytes);
        let stats_nla = make_nested_nla(NET_DM_ATTR_STATS, &inner_dropped);

        let mut buf = Vec::new();
        buf.extend_from_slice(&make_nla(NET_DM_ATTR_ORIGIN, &origin_bytes));
        buf.extend_from_slice(&make_nla(NET_DM_ATTR_REASON, reason_str));
        buf.extend_from_slice(&stats_nla);

        let ev = parse_alert_frame(&buf);
        assert!(ev.is_some(), "must parse a valid SW alert frame");
        let ev = ev.unwrap();
        assert_eq!(ev.origin, "sw");
        assert_eq!(ev.reason, "SKB_DROP_REASON_TCP_CSUM");
        assert_eq!(ev.dropped, 42);
    }

    #[test]
    fn parse_alert_frame_missing_reason_returns_none() {
        // SW origin but no REASON attr — must return None (summary mode or old kernel).
        const NET_DM_ATTR_ORIGIN: u16 = 14; // confirmed: ORIGIN is the 14th enum value
        let origin_bytes = 0u16.to_ne_bytes();
        let buf = make_nla(NET_DM_ATTR_ORIGIN, &origin_bytes);
        let ev = parse_alert_frame(&buf);
        assert!(ev.is_none(), "missing REASON for SW alert must yield None");
    }

    #[test]
    fn parse_alert_frame_hw_trap() {
        const NET_DM_ATTR_ORIGIN: u16 = 14;
        const NET_DM_ATTR_HW_TRAP_NAME: u16 = 16;

        let origin_bytes = 1u16.to_ne_bytes(); // HW
        let trap_name = b"blackhole\0";

        let mut buf = Vec::new();
        buf.extend_from_slice(&make_nla(NET_DM_ATTR_ORIGIN, &origin_bytes));
        buf.extend_from_slice(&make_nla(NET_DM_ATTR_HW_TRAP_NAME, trap_name));

        let ev = parse_alert_frame(&buf);
        assert!(ev.is_some());
        let ev = ev.unwrap();
        assert_eq!(ev.origin, "hw");
        assert_eq!(ev.reason, "blackhole");
        assert_eq!(ev.dropped, 0);
    }

    #[test]
    fn collector_name_is_drop_monitor() {
        assert_eq!(DropMonitorCollector::new().name(), "drop_monitor");
    }

    /// Build a SUMMARY-mode SW ALERT attribute region: NLA_UNSPEC(0) wrapping a
    /// `net_dm_alert_msg { u32 entries; net_dm_drop_point[] }`.
    fn make_sw_alert(counts: &[u32]) -> Vec<u8> {
        let mut alert = Vec::new();
        alert.extend_from_slice(&(counts.len() as u32).to_ne_bytes()); // entries
        for &c in counts {
            alert.extend_from_slice(&[0u8; 8]); // pc[8]
            alert.extend_from_slice(&c.to_ne_bytes()); // count
        }
        make_nla(NET_DM_ATTR_ALERT_UNSPEC, &alert)
    }

    #[test]
    fn parse_summary_alert_sums_sw_points() {
        // Three drop locations with counts 10, 20, 30 → sw=60, hw=0.
        let buf = make_sw_alert(&[10, 20, 30]);
        let (sw, hw) = parse_summary_alert(&buf);
        assert_eq!(sw, 60, "SW total must sum all drop-point counts");
        assert_eq!(hw, 0, "no HW entries → hw=0");
    }

    #[test]
    fn parse_summary_alert_empty_is_zero() {
        let buf = make_sw_alert(&[]);
        let (sw, hw) = parse_summary_alert(&buf);
        assert_eq!((sw, hw), (0, 0));
    }

    #[test]
    fn parse_summary_alert_sums_hw_entries() {
        // HW_ENTRIES → two HW_ENTRY, each with HW_TRAP_COUNT (5 and 7) → hw=12.
        let entry_a = make_nla(NET_DM_ATTR_HW_TRAP_COUNT, &5u32.to_ne_bytes());
        let entry_b = make_nla(NET_DM_ATTR_HW_TRAP_COUNT, &7u32.to_ne_bytes());
        let mut entries = Vec::new();
        entries.extend_from_slice(&make_nested_nla(NET_DM_ATTR_HW_ENTRY, &entry_a));
        entries.extend_from_slice(&make_nested_nla(NET_DM_ATTR_HW_ENTRY, &entry_b));
        let buf = make_nested_nla(NET_DM_ATTR_HW_ENTRIES, &entries);

        let (sw, hw) = parse_summary_alert(&buf);
        assert_eq!(sw, 0);
        assert_eq!(hw, 12, "HW total must sum all HW_TRAP_COUNT values");
    }

    #[test]
    fn drop_counters_accumulate_lock_free() {
        let c = DropCounters::default();
        c.sw.fetch_add(100, Ordering::Relaxed);
        c.sw.fetch_add(23, Ordering::Relaxed);
        c.hw.fetch_add(7, Ordering::Relaxed);
        assert_eq!(c.sw.load(Ordering::Relaxed), 123);
        assert_eq!(c.hw.load(Ordering::Relaxed), 7);
    }
}
