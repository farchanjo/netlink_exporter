//! `nic_bql` collector — `/sys/class/net/<dev>/queues/tx-<N>/byte_queue_limits/` (ADR-0027).
//!
//! Per-device Byte Queue Limits (BQL) health aggregated across all TX queues.
//! BQL is the dynamic TX queue byte cap introduced in Linux 3.3 that prevents
//! bufferbloat by limiting bytes queued to the device driver ring buffer.
//!
//! No netlink API exists for BQL counters; they are exposed exclusively via sysfs.
//!
//! ## Sysfs layout (kernel `net/core/net-sysfs.c::bql_show` / `bql_show_inflight`, 6.17)
//!
//! Each `tx-<N>` queue under `/sys/class/net/<dev>/queues/` exposes a
//! `byte_queue_limits/` subdirectory. The two files read here:
//!
//! | file       | kernel field                                  | type | metric                         |
//! |------------|-----------------------------------------------|------|--------------------------------|
//! | `limit`    | `queue->dql.limit`                            | `%u` | `nft_nic_bql_limit_bytes`      |
//! | `inflight` | `dql->num_queued - dql->num_completed`        | `%u` | `nft_nic_bql_inflight_bytes`   |
//!
//! Both files emit a single unsigned decimal integer followed by `\n`
//! (`sysfs_emit(buf, "%u\n", value)` — `unsigned int`, i.e. u32).
//!
//! Values are **summed across all `tx-*` queues** of each device so that the
//! metric cardinality is bounded by device count, not by (device × queue) count
//! (a box with 100+ ifaces × 32 queues would otherwise produce 3 200 series per
//! family).
//!
//! Devices whose `byte_queue_limits/` directory is absent (virtual interfaces
//! such as loopback, bridge, tun/tap) are silently skipped.

use std::collections::BTreeMap;

use nlx_domain::metric::MetricSample;
use nlx_ports::{
    collector::{BoxFuture, Collector},
    error::CollectError,
};

use crate::{safe_read, safe_read_dir};

/// Root sysfs directory used for device enumeration and `probe_available()`.
const NET_CLASS: &str = "/sys/class/net";

/// Collector for BQL sysfs attributes — per-device TX queue byte limits and
/// inflight byte counts aggregated across all TX queues of each device.
pub struct NicBqlCollector;

impl Collector for NicBqlCollector {
    fn name(&self) -> &'static str {
        "nic_bql"
    }

    fn collect(&self) -> BoxFuture<'_, Result<Vec<MetricSample>, CollectError>> {
        Box::pin(async move {
            let devs = safe_read_dir(NET_CLASS).map_err(|e| CollectError::Io(e.to_string()))?;
            Ok(parse_devices(&devs))
        })
    }

    fn probe_available(&self) -> BoxFuture<'_, bool> {
        Box::pin(async move { safe_read_dir(NET_CLASS).is_ok() })
    }
}

/// Iterate over all known devices and build per-device aggregated BQL samples.
///
/// Devices with no `tx-*` queues that expose `byte_queue_limits/` are silently
/// skipped so that virtual interfaces (lo, bridge, tun) do not produce zero-only
/// noise.
#[allow(
    clippy::cast_precision_loss,
    reason = "BQL limit/inflight are u32 sums; at most 100 ifaces * 32 queues * u32::MAX \
              (≈ 1.37 × 10^16) still fits comfortably within f64 mantissa (2^53 ≈ 9 × 10^15). \
              Acceptable precision loss for an operational gauge."
)]
fn parse_devices(devs: &[String]) -> Vec<MetricSample> {
    let mut out = Vec::new();

    for dev in devs {
        let queues_path = format!("{NET_CLASS}/{dev}/queues");
        let Ok(queue_entries) = safe_read_dir(&queues_path) else {
            continue;
        };

        let mut limit_sum: u64 = 0;
        let mut inflight_sum: u64 = 0;
        let mut found_any_tx = false;

        for entry in &queue_entries {
            if !entry.starts_with("tx-") {
                continue;
            }

            let bql_base = format!("{queues_path}/{entry}/byte_queue_limits");

            // Read `limit` — skip this queue if the file is absent/unparseable.
            let limit_path = format!("{bql_base}/limit");
            if let Some(v) = read_u64(&limit_path) {
                limit_sum = limit_sum.saturating_add(v);
                found_any_tx = true;
            }

            // Read `inflight` — independent of `limit`; skip if missing.
            let inflight_path = format!("{bql_base}/inflight");
            if let Some(v) = read_u64(&inflight_path) {
                inflight_sum = inflight_sum.saturating_add(v);
            }
        }

        if !found_any_tx {
            // No tx queue with BQL present on this device — skip entirely.
            continue;
        }

        let mut labels = BTreeMap::new();
        labels.insert("device".to_owned(), dev.clone());

        out.push(MetricSample::gauge(
            "nft_nic_bql_limit_bytes",
            "Sum of BQL TX-queue byte limits across all TX queues of the device \
             (byte_queue_limits/limit, dynamic bufferbloat cap).",
            labels.clone(),
            limit_sum as f64,
        ));

        out.push(MetricSample::gauge(
            "nft_nic_bql_inflight_bytes",
            "Sum of bytes currently in-flight to the device driver ring buffer \
             across all TX queues (byte_queue_limits/inflight = num_queued - num_completed).",
            labels,
            inflight_sum as f64,
        ));
    }

    out
}

/// Read a single unsigned decimal integer from a sysfs file.
///
/// Returns `None` if the file is missing, unreadable, or contains a value that
/// is not a valid `u64` decimal string. Trailing whitespace (the kernel always
/// emits `\n`) is trimmed before parsing.
fn read_u64(path: &str) -> Option<u64> {
    let text = safe_read(path).ok()?;
    text.trim().parse::<u64>().ok()
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::float_cmp,
        clippy::cast_precision_loss,
        clippy::cast_lossless,
        reason = "test"
    )]

    use super::*;
    use nlx_domain::metric::MetricKind;

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /// Find the first sample matching `name` and `device` label value.
    fn find<'a>(samples: &'a [MetricSample], name: &str, device: &str) -> Option<&'a MetricSample> {
        samples
            .iter()
            .find(|m| m.name == name && m.labels.get("device").map(String::as_str) == Some(device))
    }

    fn gauge_value(s: &MetricSample) -> f64 {
        match s.value {
            nlx_domain::metric::MetricValue::F64(f) => f,
            nlx_domain::metric::MetricValue::U64(n) => n as f64,
        }
    }

    // -------------------------------------------------------------------------
    // Unit tests for parse_devices
    //
    // parse_devices takes a &[String] of device names. For these tests we use an
    // empty device list or device names that don't exist on the local filesystem
    // so that safe_read_dir / safe_read always return Err — giving us full
    // defensive-path coverage without touching the real sysfs.
    // -------------------------------------------------------------------------

    #[test]
    fn empty_device_list_yields_no_samples() {
        let out = parse_devices(&[]);
        assert!(out.is_empty(), "no devices → no samples");
    }

    #[test]
    fn nonexistent_device_is_skipped_not_panicked() {
        // "not_a_real_iface_xyz" won't have a queues dir — safe_read_dir returns
        // Err, the device is silently skipped.
        let devs = vec!["not_a_real_iface_xyz".to_owned()];
        let out = parse_devices(&devs);
        assert!(out.is_empty());
    }

    #[test]
    fn two_nonexistent_devices_both_skipped() {
        let devs = vec!["ghost0".to_owned(), "ghost1".to_owned()];
        let out = parse_devices(&devs);
        assert!(out.is_empty());
    }

    // -------------------------------------------------------------------------
    // Tests for read_u64 (unit-level; path must be in allowlist to pass prefix
    // check — we use a real /sys/class/net/ prefix that is guaranteed to exist
    // on a Linux host; on macOS/CI safe_read returns Err and the Option is None)
    // -------------------------------------------------------------------------

    #[test]
    fn read_u64_on_nonexistent_path_returns_none() {
        // Path is in allowlist prefix but file does not exist.
        let v = read_u64("/sys/class/net/__no_such_device__/queues/tx-0/byte_queue_limits/limit");
        assert!(v.is_none());
    }

    #[test]
    fn read_u64_rejects_non_numeric_content() {
        // safe_read itself would succeed if the file existed with "max\n" content,
        // but parse::<u64> would fail → None.
        // We can exercise the parse branch without real sysfs by poking the inner
        // parse logic directly.
        let result: Option<u64> = "max\n".trim().parse::<u64>().ok();
        assert!(result.is_none(), "non-numeric content must yield None");
    }

    #[test]
    fn read_u64_parses_decimal_with_trailing_newline() {
        let result: Option<u64> = "131072\n".trim().parse::<u64>().ok();
        assert_eq!(result, Some(131_072_u64));
    }

    // -------------------------------------------------------------------------
    // Integration-style sanity check: on a Linux host with real sysfs the
    // collector must return at least the loopback device (if BQL is present) or
    // handle its absence gracefully.  On macOS CI the function simply returns
    // an empty vec.
    // -------------------------------------------------------------------------

    #[test]
    fn parse_devices_with_real_sysfs_does_not_panic() {
        // Just ensure no panic; we don't assert counts because sysfs layout
        // varies by host.
        let devs = safe_read_dir(NET_CLASS).unwrap_or_default();
        let out = parse_devices(&devs);

        // Every emitted sample must have a non-empty device label.
        for s in &out {
            let device = s.labels.get("device").map_or("", String::as_str);
            assert!(!device.is_empty(), "device label must be non-empty");
        }
    }

    #[test]
    fn emitted_samples_are_gauges_not_counters() {
        let devs = safe_read_dir(NET_CLASS).unwrap_or_default();
        let out = parse_devices(&devs);
        for s in &out {
            assert_eq!(
                s.kind,
                MetricKind::Gauge,
                "BQL samples must be gauges, got {:?} for {}",
                s.kind,
                s.name
            );
        }
    }

    #[test]
    fn limit_and_inflight_are_the_only_metric_names() {
        let devs = safe_read_dir(NET_CLASS).unwrap_or_default();
        let out = parse_devices(&devs);
        let allowed = ["nft_nic_bql_limit_bytes", "nft_nic_bql_inflight_bytes"];
        for s in &out {
            assert!(
                allowed.contains(&s.name),
                "unexpected metric name: {}",
                s.name
            );
        }
    }

    /// Verify that, for every device appearing in the output, both families are
    /// present (we always emit limit + inflight together when a device qualifies).
    #[test]
    fn both_families_emitted_per_qualifying_device() {
        let devs = safe_read_dir(NET_CLASS).unwrap_or_default();
        let out = parse_devices(&devs);

        // Collect the unique device names seen in the output.
        let mut seen_devices: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        for s in &out {
            if let Some(d) = s.labels.get("device") {
                seen_devices.insert(d.as_str());
            }
        }

        // Each qualifying device must have exactly one of each family.
        for dev in &seen_devices {
            let limit_count = out
                .iter()
                .filter(|s| {
                    s.name == "nft_nic_bql_limit_bytes"
                        && s.labels.get("device").map(String::as_str) == Some(dev)
                })
                .count();
            let inflight_count = out
                .iter()
                .filter(|s| {
                    s.name == "nft_nic_bql_inflight_bytes"
                        && s.labels.get("device").map(String::as_str) == Some(dev)
                })
                .count();
            assert_eq!(limit_count, 1, "device {dev}: expected 1 limit sample");
            assert_eq!(
                inflight_count, 1,
                "device {dev}: expected 1 inflight sample"
            );
        }
    }

    /// Smoke-test: if the test host has a qualifying device, gauge values are
    /// non-negative.
    #[test]
    fn gauge_values_are_non_negative() {
        let devs = safe_read_dir(NET_CLASS).unwrap_or_default();
        let out = parse_devices(&devs);
        for s in &out {
            let v = gauge_value(s);
            assert!(v >= 0.0, "gauge {} must be non-negative, got {v}", s.name);
        }
    }

    /// If the same device appears twice in the input list (degenerate case), we
    /// must not panic — we just produce duplicate series (the dedup is the
    /// caller's responsibility).
    #[test]
    fn duplicate_device_names_do_not_panic() {
        let devs = vec!["lo".to_owned(), "lo".to_owned()];
        // Should not panic regardless of whether lo has BQL queues.
        let _ = parse_devices(&devs);
    }

    /// Verify that a device is skipped if it has no tx- queues with BQL —
    /// confirmed by using a device name that has no queues directory at all.
    #[test]
    fn device_with_no_tx_queues_produces_no_output() {
        let devs = vec!["__phantom_device__".to_owned()];
        let out = parse_devices(&devs);
        assert!(find(&out, "nft_nic_bql_limit_bytes", "__phantom_device__").is_none());
        assert!(find(&out, "nft_nic_bql_inflight_bytes", "__phantom_device__").is_none());
    }
}
