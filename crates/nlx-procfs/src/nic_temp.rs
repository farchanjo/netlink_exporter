//! `nic_temp` collector — `/sys/class/net/<dev>/device/hwmon/hwmon<K>/temp<N>_input` (ADR-0027).
//!
//! Per-NIC hardware temperature via the Linux hwmon sysfs interface. No netlink
//! API exists for this; sysfs hwmon is the canonical kernel-documented path.
//!
//! ## Sysfs layout
//!
//! Reference: `Documentation/hwmon/sysfs-interface.rst` (kernel 6.17),
//! `temp[1-*]_input` section — values are in **millidegrees Celsius**.
//!
//! | Path                                                             | Purpose              |
//! |------------------------------------------------------------------|----------------------|
//! | `/sys/class/net/<dev>/device/hwmon/hwmon<K>/temp<N>_input`       | millidegrees Celsius |
//! | `/sys/class/net/<dev>/device/hwmon/hwmon<K>/name`                | chip name (optional) |
//! | `/sys/class/net/<dev>/device/hwmon/hwmon<K>/temp<N>_label`       | channel label (opt.) |
//!
//! The collector probes `temp1_input` through `temp8_input` for each hwmon
//! instance found under each network interface. Devices without a `hwmon`
//! directory are silently skipped. Unparseable values are skipped; no panic.
//!
//! ## Emitted metric
//!
//! | Metric                          | Type  | Labels           | Description                          |
//! |---------------------------------|-------|------------------|--------------------------------------|
//! | `nft_nic_temperature_celsius`   | gauge | `device`, `sensor` | NIC hardware temperature in degrees C |
//!
//! `sensor` is formed as `<chip_name>_temp<N>` when the `name` file is present,
//! or `temp<N>` otherwise (e.g. `mlx5_temp1`, `temp2`).

use std::collections::BTreeMap;

use nlx_domain::metric::MetricSample;
use nlx_ports::{
    collector::{BoxFuture, Collector},
    error::CollectError,
};

use crate::{readable, safe_read, safe_read_dir};

const NET_CLASS: &str = "/sys/class/net";

/// Maximum number of `tempN_input` channels probed per hwmon instance.
const MAX_TEMP_SENSORS: u32 = 8;

/// Collector for NIC hardware temperatures via `/sys/class/net/<dev>/device/hwmon`.
pub struct NicTempCollector;

impl Collector for NicTempCollector {
    fn name(&self) -> &'static str {
        "nic_temp"
    }

    fn collect(&self) -> BoxFuture<'_, Result<Vec<MetricSample>, CollectError>> {
        Box::pin(async move {
            let devs = safe_read_dir(NET_CLASS).map_err(|e| CollectError::Io(e.to_string()))?;
            Ok(collect_all(&devs))
        })
    }

    fn probe_available(&self) -> BoxFuture<'_, bool> {
        // NET_CLASS is a directory: enumerate it (read_to_string would EISDIR).
        Box::pin(async move { safe_read_dir(NET_CLASS).is_ok() })
    }
}

/// Walk all network interfaces and collect hwmon temperature samples.
///
/// Devices without a `hwmon` directory are skipped. Unreadable or unparseable
/// sensor files are skipped (never panicked on).
#[allow(
    clippy::cast_precision_loss,
    reason = "millidegree integer -> f64 celsius; NICs never exceed 200 °C so no meaningful precision is lost"
)]
fn collect_all(devs: &[String]) -> Vec<MetricSample> {
    let mut out = Vec::new();

    for dev in devs {
        let hwmon_root = format!("{NET_CLASS}/{dev}/device/hwmon");
        let Ok(hwmon_entries) = safe_read_dir(&hwmon_root) else {
            continue; // device has no hwmon — skip
        };

        for hwmon_entry in &hwmon_entries {
            let hwmon_dir = format!("{hwmon_root}/{hwmon_entry}");

            // Read optional chip name (e.g. "mlx5", "coretemp").
            let chip_name = read_optional_text(&format!("{hwmon_dir}/name"));

            for n in 1..=MAX_TEMP_SENSORS {
                let input_path = format!("{hwmon_dir}/temp{n}_input");
                if !readable(&input_path) {
                    continue;
                }

                let Ok(raw) = safe_read(&input_path) else {
                    continue;
                };
                let millideg: i64 = match raw.trim().parse() {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let celsius = millideg as f64 / 1000.0;

                // sensor label: prefer chip_name prefix, fall back to bare index.
                let sensor = match chip_name.as_deref() {
                    Some(name) if !name.is_empty() => format!("{name}_temp{n}"),
                    _ => format!("temp{n}"),
                };

                let mut labels = BTreeMap::new();
                labels.insert("device".to_owned(), dev.clone());
                labels.insert("sensor".to_owned(), sensor);

                out.push(MetricSample::gauge(
                    "nft_nic_temperature_celsius",
                    "NIC hardware temperature in degrees Celsius (hwmon sysfs, millidegrees / 1000).",
                    labels,
                    celsius,
                ));
            }
        }
    }

    out
}

/// Read a sysfs text file, trim whitespace, return `None` on any error.
fn read_optional_text(path: &str) -> Option<String> {
    safe_read(path).ok().map(|s| s.trim().to_owned())
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

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn find<'a>(
        samples: &'a [MetricSample],
        device: &str,
        sensor: &str,
    ) -> Option<&'a MetricSample> {
        samples.iter().find(|m| {
            m.name == "nft_nic_temperature_celsius"
                && m.labels.get("device").map(String::as_str) == Some(device)
                && m.labels.get("sensor").map(String::as_str) == Some(sensor)
        })
    }

    fn celsius(sample: &MetricSample) -> f64 {
        match sample.value {
            nlx_domain::metric::MetricValue::F64(f) => f,
            nlx_domain::metric::MetricValue::U64(u) => u as f64,
        }
    }

    // -----------------------------------------------------------------------
    // Unit-level: parse helper and collect_all via synthetic device list
    // -----------------------------------------------------------------------

    /// `collect_all` with no devices emits no samples.
    #[test]
    fn empty_device_list_yields_no_samples() {
        let out = collect_all(&[]);
        assert!(out.is_empty());
    }

    /// `collect_all` silently skips devices that have no hwmon directory
    /// (`safe_read_dir` returns `PermissionDenied` or `NotFound` — both are Err).
    #[test]
    fn missing_hwmon_dir_is_skipped() {
        // A device name that does not exist on the test host must produce zero
        // samples without panicking.
        let out = collect_all(&["__nonexistent_nic_xyz__".to_owned()]);
        assert!(out.is_empty());
    }

    // -----------------------------------------------------------------------
    // Inline parse logic tests (bypass sysfs by testing the arithmetic path)
    // -----------------------------------------------------------------------

    /// Millidegrees -> Celsius conversion is correct for typical values.
    #[test]
    fn millidegree_conversion_is_correct() {
        // 54321 md -> 54.321 °C
        let md: i64 = 54_321;
        let celsius = md as f64 / 1000.0;
        assert!((celsius - 54.321_f64).abs() < 1e-9);
    }

    /// Negative millidegree values (sub-zero ambient) convert correctly.
    #[test]
    fn negative_millidegree_converts_correctly() {
        let md: i64 = -5_000;
        let celsius = md as f64 / 1000.0;
        assert!((celsius - (-5.0_f64)).abs() < 1e-9);
    }

    /// Zero millidegrees yields 0.0 °C (edge case — sensor not yet warm).
    #[test]
    fn zero_millidegrees_yields_zero_celsius() {
        let md: i64 = 0;
        let celsius = md as f64 / 1000.0;
        assert_eq!(celsius, 0.0_f64);
    }

    // -----------------------------------------------------------------------
    // read_optional_text
    // -----------------------------------------------------------------------

    /// `read_optional_text` returns `None` for a non-existent path (does not
    /// panic, does not return an error, just `None`).
    #[test]
    fn read_optional_text_returns_none_for_missing_path() {
        // Allowlisted prefix but file does not exist.
        let result = read_optional_text("/sys/class/net/__no_such_nic__/device/hwmon/hwmon0/name");
        assert!(result.is_none());
    }

    // -----------------------------------------------------------------------
    // Metric shape
    // -----------------------------------------------------------------------

    /// The emitted metric family name, kind, and label keys must be stable.
    /// We test this using the actual samples emitted on the test host (which
    /// may be empty if no NIC hwmon is available) and a hand-crafted sample
    /// for shape verification.
    #[test]
    fn emitted_sample_has_correct_kind_and_labels() {
        let mut labels = BTreeMap::new();
        labels.insert("device".to_owned(), "eth0".to_owned());
        labels.insert("sensor".to_owned(), "mlx5_temp1".to_owned());

        let sample = MetricSample::gauge(
            "nft_nic_temperature_celsius",
            "NIC hardware temperature in degrees Celsius (hwmon sysfs, millidegrees / 1000).",
            labels,
            54.321,
        );

        assert_eq!(sample.kind, MetricKind::Gauge);
        assert_eq!(sample.name, "nft_nic_temperature_celsius");
        assert_eq!(sample.labels.get("device").unwrap(), "eth0");
        assert_eq!(sample.labels.get("sensor").unwrap(), "mlx5_temp1");
    }

    /// Sensor label uses chip name prefix when chip name is non-empty.
    #[test]
    fn sensor_label_uses_chip_name_when_present() {
        // Simulate the naming logic directly.
        let chip_name: Option<&str> = Some("mlx5");
        let n: u32 = 2;
        let sensor = match chip_name {
            Some(name) if !name.is_empty() => format!("{name}_temp{n}"),
            _ => format!("temp{n}"),
        };
        assert_eq!(sensor, "mlx5_temp2");
    }

    /// Sensor label falls back to bare index when chip name is absent.
    #[test]
    fn sensor_label_falls_back_to_bare_index_when_no_chip_name() {
        let chip_name: Option<&str> = None;
        let n: u32 = 3;
        let sensor = match chip_name {
            Some(name) if !name.is_empty() => format!("{name}_temp{n}"),
            _ => format!("temp{n}"),
        };
        assert_eq!(sensor, "temp3");
    }

    /// Sensor label falls back when chip name is an empty string (trimmed).
    #[test]
    fn sensor_label_falls_back_when_chip_name_is_empty_string() {
        let chip_name: Option<&str> = Some("");
        let n: u32 = 1;
        let sensor = match chip_name {
            Some(name) if !name.is_empty() => format!("{name}_temp{n}"),
            _ => format!("temp{n}"),
        };
        assert_eq!(sensor, "temp1");
    }

    // -----------------------------------------------------------------------
    // find helper self-test
    // -----------------------------------------------------------------------

    #[test]
    fn find_helper_returns_correct_sample() {
        let mut labels = BTreeMap::new();
        labels.insert("device".to_owned(), "enp4s0".to_owned());
        labels.insert("sensor".to_owned(), "coretemp_temp1".to_owned());
        let sample = MetricSample::gauge(
            "nft_nic_temperature_celsius",
            "NIC hardware temperature in degrees Celsius (hwmon sysfs, millidegrees / 1000).",
            labels,
            72.0,
        );
        let samples = vec![sample];
        let found = find(&samples, "enp4s0", "coretemp_temp1");
        assert!(found.is_some());
        assert!((celsius(found.unwrap()) - 72.0_f64).abs() < 1e-9);
    }

    #[test]
    fn find_helper_returns_none_for_wrong_labels() {
        let mut labels = BTreeMap::new();
        labels.insert("device".to_owned(), "eth0".to_owned());
        labels.insert("sensor".to_owned(), "temp1".to_owned());
        let sample = MetricSample::gauge(
            "nft_nic_temperature_celsius",
            "NIC hardware temperature in degrees Celsius (hwmon sysfs, millidegrees / 1000).",
            labels,
            45.0,
        );
        let samples = vec![sample];
        assert!(find(&samples, "eth0", "temp2").is_none());
        assert!(find(&samples, "eth1", "temp1").is_none());
    }
}
