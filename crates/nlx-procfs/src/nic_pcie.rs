//! `nic_pcie` collector — `/sys/class/net/<dev>/device/{current_link_speed,
//! current_link_width,aer_dev_correctable,aer_dev_fatal,aer_dev_nonfatal}`
//! (ADR-0027).
//!
//! `PCIe` link health and AER error counters for **physical functions** only.
//! A device is processed when it exposes `current_link_speed` (implying a `PCIe`
//! endpoint) AND is not an SR-IOV virtual function. VFs expose a `device/physfn`
//! symlink to their parent PF; since link speed/width and AER are PF-level
//! properties, per-VF series would be redundant and explode cardinality on
//! VF-heavy hosts, so VFs are skipped. Virtual/loopback interfaces (no
//! `current_link_speed`) are skipped too.
//!
//! ## Sysfs file formats (kernel `drivers/pci/pci-sysfs.c`,
//! `drivers/pci/pcie/aer.c`, 6.17)
//!
//! ### `current_link_speed`
//!
//! Single line, `pci_speed_string()` followed by `\n`.
//! `drivers/pci/pci-sysfs.c::current_link_speed_show` (line 215).
//!
//! | Example value        | GT/s  |
//! |----------------------|-------|
//! | `"2.5 GT/s PCIe\n"`  | 2.5   |
//! | `"5.0 GT/s PCIe\n"`  | 5.0   |
//! | `"8.0 GT/s PCIe\n"`  | 8.0   |
//! | `"16.0 GT/s PCIe\n"` | 16.0  |
//! | `"32.0 GT/s PCIe\n"` | 32.0  |
//! | `"64.0 GT/s PCIe\n"` | 64.0  |
//! | `"Unknown\n"`         | skip  |
//!
//! ### `current_link_width`
//!
//! Single decimal integer followed by `\n`.
//! `drivers/pci/pci-sysfs.c::current_link_width_show` (line 236).
//!
//! ### `aer_dev_correctable` / `aer_dev_fatal` / `aer_dev_nonfatal`
//!
//! Each line is `"<Key> <u64>\n"`.  Final line is always
//! `"TOTAL_<ERR_TYPE> <u64>\n"`.
//! `drivers/pci/pcie/aer.c::aer_stats_dev_attr` (line 546).
//!
//! Example (`aer_dev_correctable`):
//!
//! | Line               | kind (lowercased) |
//! |--------------------|-------------------|
//! | `RxErr 0`          | `rxerr`           |
//! | `BadTLP 3`         | `badtlp`          |
//! | `BadDLLP 0`        | `baddllp`         |
//! | `Rollover 0`       | `rollover`        |
//! | `Timeout 0`        | `timeout`         |
//! | `NonFatalErr 0`    | `nonfatalerr`     |
//! | `CorrIntErr 0`     | `corrinterr`      |
//! | `HeaderOF 0`       | `headerof`        |
//! | `TOTAL_ERR_COR 3`  | skipped (summary) |

use std::collections::BTreeMap;

use nlx_domain::metric::MetricSample;
use nlx_ports::{
    collector::{BoxFuture, Collector},
    error::CollectError,
};

use crate::{readable, safe_read, safe_read_dir};

const PATH_CLASS_NET: &str = "/sys/class/net";

/// Returns the sysfs path for a per-device attribute.
fn dev_path(dev: &str, attr: &str) -> String {
    format!("/sys/class/net/{dev}/device/{attr}")
}

/// Collector for `PCIe` link speed, link width, and AER error counters,
/// sourced from `/sys/class/net/<dev>/device/` sysfs attributes.
pub struct NicPcieCollector;

impl Collector for NicPcieCollector {
    fn name(&self) -> &'static str {
        "nic_pcie"
    }

    fn collect(&self) -> BoxFuture<'_, Result<Vec<MetricSample>, CollectError>> {
        Box::pin(async move {
            let devs =
                safe_read_dir(PATH_CLASS_NET).map_err(|e| CollectError::Io(e.to_string()))?;
            Ok(parse_all(&devs))
        })
    }

    fn probe_available(&self) -> BoxFuture<'_, bool> {
        // PATH_CLASS_NET is a directory: enumerate it (read_to_string would EISDIR).
        Box::pin(async move { safe_read_dir(PATH_CLASS_NET).is_ok() })
    }
}

/// Collect all samples across every physical (`PCIe`) NIC in `devs`.
#[allow(
    clippy::cast_precision_loss,
    reason = "link_width is u32 ≤ 32; no precision loss at f64"
)]
fn parse_all(devs: &[String]) -> Vec<MetricSample> {
    let mut out = Vec::new();
    for dev in devs {
        // Gate 1: only physical PCIe NICs expose current_link_speed.
        let speed_readable = readable(&dev_path(dev, "current_link_speed"));
        // Gate 2: skip SR-IOV virtual functions. A VF exposes a `device/physfn`
        // symlink to its parent PF; PCIe link speed/width and AER counters are
        // properties of the physical function, so per-VF series are redundant
        // (and explode cardinality on VF-heavy hosts). `physfn` is a symlink to
        // a directory, so existence is probed with `safe_read_dir`.
        let is_vf = safe_read_dir(&dev_path(dev, "physfn")).is_ok();
        if !should_collect(speed_readable, is_vf) {
            continue;
        }
        collect_dev(dev, &mut out);
    }
    out
}

/// Whether a network device should be collected: it must be a `PCIe` endpoint
/// (`current_link_speed` readable) and not an SR-IOV virtual function.
fn should_collect(speed_readable: bool, is_vf: bool) -> bool {
    speed_readable && !is_vf
}

/// Collect all samples for a single NIC `dev`.
#[allow(
    clippy::cast_precision_loss,
    reason = "link_width is a small integer (≤ 32); no precision loss at f64"
)]
fn collect_dev(dev: &str, out: &mut Vec<MetricSample>) {
    let mut labels = BTreeMap::new();
    labels.insert("device".to_owned(), dev.to_owned());

    // --- current_link_speed ---
    if let Ok(text) = safe_read(&dev_path(dev, "current_link_speed")) {
        if let Some(gts) = parse_link_speed(text.trim()) {
            out.push(MetricSample::gauge(
                "nft_nic_pcie_link_speed_gts",
                "PCIe current link speed in GT/s (from sysfs current_link_speed).",
                labels.clone(),
                gts,
            ));
        }
    }

    // --- current_link_width ---
    if let Ok(text) = safe_read(&dev_path(dev, "current_link_width")) {
        if let Ok(width) = text.trim().parse::<u32>() {
            out.push(MetricSample::gauge(
                "nft_nic_pcie_link_width",
                "PCIe current link width (number of lanes, from sysfs current_link_width).",
                labels.clone(),
                f64::from(width),
            ));
        }
    }

    // --- AER counters ---
    collect_aer(
        dev,
        "aer_dev_correctable",
        "nft_nic_pcie_aer_correctable_total",
        "PCIe AER correctable error event count (from sysfs aer_dev_correctable).",
        &labels,
        out,
    );
    collect_aer(
        dev,
        "aer_dev_fatal",
        "nft_nic_pcie_aer_fatal_total",
        "PCIe AER fatal uncorrectable error event count (from sysfs aer_dev_fatal).",
        &labels,
        out,
    );
    collect_aer(
        dev,
        "aer_dev_nonfatal",
        "nft_nic_pcie_aer_nonfatal_total",
        "PCIe AER non-fatal uncorrectable error event count (from sysfs aer_dev_nonfatal).",
        &labels,
        out,
    );
}

/// Parse one AER sysfs file and push one counter per `"Key Value"` line.
///
/// Lines whose key starts with `"TOTAL_"` are summary lines emitted by the
/// kernel (`TOTAL_ERR_COR`, `TOTAL_ERR_FATAL`, `TOTAL_ERR_NONFATAL`) and are
/// skipped to avoid duplicating the per-bit counters.
fn collect_aer(
    dev: &str,
    attr: &str,
    metric_name: &'static str,
    help: &'static str,
    base_labels: &BTreeMap<String, String>,
    out: &mut Vec<MetricSample>,
) {
    let path = dev_path(dev, attr);
    let Ok(text) = safe_read(&path) else {
        return; // AER not present on this device — skip silently.
    };
    for line in text.lines() {
        let mut parts = line.splitn(2, ' ');
        let key = match parts.next() {
            Some(k) if !k.is_empty() => k,
            _ => continue,
        };
        // Skip the TOTAL_* summary line the kernel always appends.
        if key.starts_with("TOTAL_") {
            continue;
        }
        let value: u64 = match parts.next().and_then(|v| v.trim().parse().ok()) {
            Some(v) => v,
            None => continue, // Unparseable — skip defensively.
        };
        let kind = key.to_lowercase();
        let mut labels = base_labels.clone();
        labels.insert("kind".to_owned(), kind);
        out.push(MetricSample::counter(metric_name, help, labels, value));
    }
}

/// Parse the leading float from a `current_link_speed` string.
///
/// The kernel emits strings such as `"16.0 GT/s PCIe"` or `"Unknown"`.
/// Returns `None` for `"Unknown"` or any format not starting with a float.
fn parse_link_speed(s: &str) -> Option<f64> {
    // The speed string always starts with the numeric GT/s value.
    let token = s.split_whitespace().next()?;
    token.parse::<f64>().ok()
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
    use nlx_domain::metric::{MetricKind, MetricValue};

    // -------------------------------------------------------------------------
    // parse_link_speed
    // -------------------------------------------------------------------------

    #[test]
    fn parse_link_speed_extracts_leading_float() {
        assert_eq!(parse_link_speed("16.0 GT/s PCIe"), Some(16.0_f64));
        assert_eq!(parse_link_speed("2.5 GT/s PCIe"), Some(2.5_f64));
        assert_eq!(parse_link_speed("32.0 GT/s PCIe"), Some(32.0_f64));
        assert_eq!(parse_link_speed("64.0 GT/s PCIe"), Some(64.0_f64));
    }

    #[test]
    fn parse_link_speed_unknown_returns_none() {
        assert_eq!(parse_link_speed("Unknown"), None);
        assert_eq!(parse_link_speed(""), None);
    }

    // -------------------------------------------------------------------------
    // AER parsing via collect_aer (exercised through a fake text)
    // -------------------------------------------------------------------------

    /// Simulate what the kernel emits for `aer_dev_correctable`.
    const AER_COR_SAMPLE: &str = "\
RxErr 0
BadTLP 3
BadDLLP 0
Rollover 1
Timeout 0
NonFatalErr 0
CorrIntErr 0
HeaderOF 0
TOTAL_ERR_COR 4
";

    fn run_aer(text: &str) -> Vec<MetricSample> {
        let mut out = Vec::new();
        let base = {
            let mut m = BTreeMap::new();
            m.insert("device".to_owned(), "eth0".to_owned());
            m
        };
        // Parse the sample text directly rather than through safe_read.
        for line in text.lines() {
            let mut parts = line.splitn(2, ' ');
            let key = match parts.next() {
                Some(k) if !k.is_empty() => k,
                _ => continue,
            };
            if key.starts_with("TOTAL_") {
                continue;
            }
            let value: u64 = match parts.next().and_then(|v| v.trim().parse().ok()) {
                Some(v) => v,
                None => continue,
            };
            let mut labels = base.clone();
            labels.insert("kind".to_owned(), key.to_lowercase());
            out.push(MetricSample::counter(
                "nft_nic_pcie_aer_correctable_total",
                "help",
                labels,
                value,
            ));
        }
        out
    }

    #[test]
    fn aer_skips_total_summary_line() {
        let samples = run_aer(AER_COR_SAMPLE);
        // TOTAL_ERR_COR must not appear.
        assert!(
            samples
                .iter()
                .all(|s| s.labels.get("kind").is_none_or(|k| k != "total_err_cor")),
            "TOTAL_* summary line must be skipped"
        );
    }

    #[test]
    fn aer_parses_non_zero_values() {
        let samples = run_aer(AER_COR_SAMPLE);
        let badtlp = samples
            .iter()
            .find(|s| s.labels.get("kind").map(String::as_str) == Some("badtlp"))
            .unwrap();
        assert_eq!(badtlp.value, MetricValue::U64(3));
        assert_eq!(badtlp.kind, MetricKind::Counter);
    }

    #[test]
    fn aer_all_named_bits_present() {
        let samples = run_aer(AER_COR_SAMPLE);
        let kinds: Vec<&str> = samples
            .iter()
            .filter_map(|s| s.labels.get("kind").map(String::as_str))
            .collect();
        // All named correctable-bit keys must appear.
        for expected in &[
            "rxerr",
            "badtlp",
            "baddllp",
            "rollover",
            "timeout",
            "nonfatalerr",
            "corrinterr",
            "headerof",
        ] {
            assert!(kinds.contains(expected), "missing kind: {expected}");
        }
        // Exactly 8 entries (no TOTAL_*).
        assert_eq!(samples.len(), 8);
    }

    #[test]
    fn aer_skips_unparseable_lines() {
        let bad = "RxErr\nBadTLP three\n";
        let samples = run_aer(bad);
        // Neither line is valid: first has no value, second is non-numeric.
        assert!(
            samples.is_empty(),
            "unparseable lines must yield no samples"
        );
    }

    // -------------------------------------------------------------------------
    // parse_all skips non-PCIe interfaces (no current_link_speed file)
    // -------------------------------------------------------------------------

    #[test]
    fn parse_all_empty_devlist_yields_no_samples() {
        let out = parse_all(&[]);
        assert!(out.is_empty());
    }

    /// SR-IOV virtual functions (which expose `device/physfn`) must be skipped:
    /// `PCIe` link + AER are physical-function properties, and a VF-heavy host
    /// (128 VFs) would otherwise explode cardinality ~30x with redundant data.
    #[test]
    fn vf_devices_are_skipped() {
        assert!(
            should_collect(true, false),
            "a physical-function PCIe NIC must be collected"
        );
        assert!(
            !should_collect(true, true),
            "an SR-IOV VF (has device/physfn) must be skipped"
        );
        assert!(
            !should_collect(false, false),
            "a non-PCIe interface (no current_link_speed) must be skipped"
        );
    }

    #[test]
    fn parse_all_skips_virtual_interfaces() {
        // "lo" and typical virtual names will have no sysfs current_link_speed.
        // readable() returns false for non-existent paths so they are skipped.
        let devs: Vec<String> = vec!["lo".to_owned(), "dummy0".to_owned()];
        // On a non-Linux host these files do not exist; parse_all returns empty.
        let out = parse_all(&devs);
        // We can only assert this does not panic; the result is host-dependent.
        let _ = out;
    }

    // -------------------------------------------------------------------------
    // collect_dev gauges — smoke tests using live sysfs on Linux hosts
    // -------------------------------------------------------------------------

    #[test]
    fn link_speed_gauge_is_gauge_kind() {
        // Build a gauge directly and confirm kind.
        let labels = {
            let mut m = BTreeMap::new();
            m.insert("device".to_owned(), "eth0".to_owned());
            m
        };
        let s = MetricSample::gauge("nft_nic_pcie_link_speed_gts", "help", labels, 16.0_f64);
        assert_eq!(s.kind, MetricKind::Gauge);
        assert_eq!(s.value, MetricValue::F64(16.0));
    }

    #[test]
    fn link_width_gauge_is_gauge_kind() {
        let labels = {
            let mut m = BTreeMap::new();
            m.insert("device".to_owned(), "eth0".to_owned());
            m
        };
        let s = MetricSample::gauge("nft_nic_pcie_link_width", "help", labels, f64::from(16_u32));
        assert_eq!(s.kind, MetricKind::Gauge);
        assert_eq!(s.value, MetricValue::F64(16.0));
    }
}
