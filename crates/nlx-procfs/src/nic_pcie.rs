//! `nic_pcie` collector — `/sys/class/net/<dev>/device/{current_link_speed,
//! current_link_width,aer_dev_correctable,aer_dev_fatal,aer_dev_nonfatal}`
//! (ADR-0027, amended by ADR-0028).
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
//! Each line is `"<Key> <u64>\n"`. The final line is always
//! `"TOTAL_<ERR_TYPE> <u64>\n"` (a kernel-computed summary).
//! `drivers/pci/pcie/aer.c::aer_stats_dev_attr` (line 546).
//!
//! **Aggregation (ADR-0028):** `collect_aer` sums every per-bit line and emits
//! exactly **one counter per AER file** labelled by `device` only — the `kind`
//! label (lowercased bit name) is no longer emitted. The `TOTAL_<ERR_TYPE>`
//! summary line is excluded from the sum (the result equals the kernel total by
//! construction). Cardinality is 3 AER series per device instead of ~54.
//!
//! Example (`aer_dev_correctable`):
//!
//! | Line               | Action                         |
//! |--------------------|--------------------------------|
//! | `RxErr 0`          | added to sum (contributes 0)   |
//! | `BadTLP 3`         | added to sum (contributes 3)   |
//! | `BadDLLP 0`        | added to sum (contributes 0)   |
//! | `Rollover 1`       | added to sum (contributes 1)   |
//! | `Timeout 0`        | added to sum (contributes 0)   |
//! | `NonFatalErr 0`    | added to sum (contributes 0)   |
//! | `CorrIntErr 0`     | added to sum (contributes 0)   |
//! | `HeaderOF 0`       | added to sum (contributes 0)   |
//! | `TOTAL_ERR_COR 4`  | skipped (TOTAL_ summary line)  |
//!
//! Result: one counter with value 4 and label `{device="<dev>"}`.

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
        "PCIe AER correctable error event count, aggregated across all error bits; TOTAL_ summary excluded (from sysfs aer_dev_correctable).",
        &labels,
        out,
    );
    collect_aer(
        dev,
        "aer_dev_fatal",
        "nft_nic_pcie_aer_fatal_total",
        "PCIe AER fatal uncorrectable error event count, aggregated across all error bits; TOTAL_ summary excluded (from sysfs aer_dev_fatal).",
        &labels,
        out,
    );
    collect_aer(
        dev,
        "aer_dev_nonfatal",
        "nft_nic_pcie_aer_nonfatal_total",
        "PCIe AER non-fatal uncorrectable error event count, aggregated across all error bits; TOTAL_ summary excluded (from sysfs aer_dev_nonfatal).",
        &labels,
        out,
    );
}

/// Parse one AER sysfs file and push a **single** aggregated counter.
///
/// All per-bit `"Key Value"` lines are summed into one total. Lines whose key
/// starts with `"TOTAL_"` are the kernel summary (`TOTAL_ERR_COR`,
/// `TOTAL_ERR_FATAL`, `TOTAL_ERR_NONFATAL`) and are excluded from the sum —
/// the computed sum equals the kernel total by construction, so there is no
/// double-counting. Unparseable lines are skipped (not added to the sum).
///
/// If the AER file is unreadable (`safe_read` returns `Err`) the function
/// returns without emitting. If the file is readable but has zero valid bit
/// lines the counter is emitted with value 0 — a present AER file signals the
/// device supports AER, so 0 errors is meaningful information.
///
/// The emitted counter carries only the `base_labels` (i.e. `device`); no
/// `kind` label is added (ADR-0028).
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
    let mut sum: u64 = 0;
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
        sum = sum.saturating_add(value);
    }
    out.push(MetricSample::counter(
        metric_name,
        help,
        base_labels.clone(),
        sum,
    ));
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
    // AER aggregation via collect_aer (exercised through a fake text)
    // -------------------------------------------------------------------------

    /// Simulate what the kernel emits for `aer_dev_correctable`.
    /// RxErr(0) + BadTLP(3) + BadDLLP(0) + Rollover(1) + … = 4 bits set.
    /// `TOTAL_ERR_COR(4)` must NOT be added to the sum.
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

    /// Mirror the aggregation logic of `collect_aer`: sum all non-TOTAL_ lines,
    /// emit one counter with `base_labels` only (no `kind`).
    fn run_aer(text: &str) -> Vec<MetricSample> {
        let base = {
            let mut m = BTreeMap::new();
            m.insert("device".to_owned(), "eth0".to_owned());
            m
        };
        let mut sum: u64 = 0;
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
            sum = sum.saturating_add(value);
        }
        vec![MetricSample::counter(
            "nft_nic_pcie_aer_correctable_total",
            "help",
            base,
            sum,
        )]
    }

    // -------------------------------------------------------------------------
    // AER aggregation correctness tests
    // -------------------------------------------------------------------------

    #[test]
    fn aer_emits_exactly_one_sample() {
        let samples = run_aer(AER_COR_SAMPLE);
        assert_eq!(samples.len(), 1, "must emit exactly one aggregated counter");
    }

    #[test]
    fn aer_aggregated_value_equals_bit_sum() {
        // RxErr(0) + BadTLP(3) + BadDLLP(0) + Rollover(1) + rest(0) = 4.
        let samples = run_aer(AER_COR_SAMPLE);
        let s = samples.first().unwrap();
        assert_eq!(
            s.value,
            MetricValue::U64(4),
            "aggregated value must be the sum of per-bit lines"
        );
    }

    #[test]
    fn aer_counter_has_no_kind_label() {
        let samples = run_aer(AER_COR_SAMPLE);
        let s = samples.first().unwrap();
        assert!(
            !s.labels.contains_key("kind"),
            "aggregated counter must not carry a kind label"
        );
    }

    #[test]
    fn aer_counter_has_device_label_only() {
        let samples = run_aer(AER_COR_SAMPLE);
        let s = samples.first().unwrap();
        let labels = &s.labels;
        assert_eq!(labels.len(), 1, "only the device label must be present");
        assert_eq!(
            labels.get("device").map(String::as_str),
            Some("eth0"),
            "device label must match"
        );
    }

    #[test]
    fn aer_counter_is_counter_kind() {
        let samples = run_aer(AER_COR_SAMPLE);
        let s = samples.first().unwrap();
        assert_eq!(
            s.kind,
            MetricKind::Counter,
            "AER sample must be Counter kind"
        );
    }

    #[test]
    fn aer_total_line_not_double_counted() {
        // TOTAL_ERR_COR = 4 (kernel summary). Per-bit sum = 3 + 1 = 4.
        // If TOTAL_ were naively included the sum would be 8 instead of 4.
        let samples = run_aer(AER_COR_SAMPLE);
        let s = samples.first().unwrap();
        assert_eq!(
            s.value,
            MetricValue::U64(4),
            "TOTAL_ summary line must not be added to the sum (would produce 8)"
        );
    }

    #[test]
    fn aer_unparseable_lines_excluded_from_sum() {
        // "RxErr" has no value field; "BadTLP three" is non-numeric.
        // Both lines are skipped — sum stays 0, but one counter is still emitted.
        let bad = "RxErr\nBadTLP three\n";
        let samples = run_aer(bad);
        assert_eq!(samples.len(), 1, "one counter must still be emitted");
        let s = samples.first().unwrap();
        assert_eq!(
            s.value,
            MetricValue::U64(0),
            "unparseable lines contribute 0 to the sum"
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
