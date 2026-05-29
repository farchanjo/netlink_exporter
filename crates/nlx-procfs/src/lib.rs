//! `nlx-procfs` — opt-in procfs/sysfs collectors (ADR-0027).
//!
//! This is the **only** crate in the workspace permitted to read `/proc` or
//! `/sys`. Every other crate is native-API-only (ADR-0025). The collectors here
//! cover Linux network signals that have **no netlink API** (stack pressure,
//! IP/TCP MIB, IRQ accounting, NIC hardware health) and are **disabled by
//! default** — operators opt in via config.
//!
//! ## Safety boundary
//!
//! All reads go through [`safe_read`], which enforces a fixed path-prefix
//! allowlist and rejects `..` traversal. The crate never writes. Parsers are
//! defensive: pseudo-file formats drift across kernels, so a missing column or
//! unrecognised line is skipped, never panicked on.

pub mod softnet;

/// Fixed allowlist of path prefixes this crate may read (ADR-0027).
///
/// Anything outside these prefixes is rejected by [`safe_read`]. Keeping the
/// list here makes the entire procfs/sysfs surface auditable in one place.
const ALLOWED_PREFIXES: &[&str] = &[
    "/proc/net/",
    "/proc/softirqs",
    "/proc/interrupts",
    "/proc/irq/",
    "/sys/class/net/",
    "/sys/bus/pci/devices/",
];

/// Read a procfs/sysfs pseudo-file — but only if `path` is under an allowlisted
/// prefix (see [`ALLOWED_PREFIXES`]) and contains no `..` traversal component.
///
/// # Errors
///
/// Returns [`std::io::ErrorKind::PermissionDenied`] when `path` is not
/// allowlisted, or the underlying I/O error when the read fails.
pub fn safe_read(path: &str) -> std::io::Result<String> {
    if path.contains("..") || !ALLOWED_PREFIXES.iter().any(|p| path.starts_with(p)) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("path not in procfs/sysfs allowlist (ADR-0027): {path}"),
        ));
    }
    std::fs::read_to_string(path)
}

/// `true` when an allowlisted path exists and is readable — used by collector
/// `probe_available()` to gate the `nft_scrape_collector_available` metric.
#[must_use]
pub fn readable(path: &str) -> bool {
    safe_read(path).is_ok()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test")]

    use super::*;

    #[test]
    fn safe_read_rejects_non_allowlisted_path() {
        let err = safe_read("/etc/passwd").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn safe_read_rejects_traversal() {
        let err = safe_read("/proc/net/../../etc/passwd").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn safe_read_allows_allowlisted_prefixes() {
        // These prefixes must be accepted by the allowlist check (the read
        // itself may still fail with NotFound on a non-Linux test host — that is
        // a different error kind than PermissionDenied).
        for p in [
            "/proc/net/softnet_stat",
            "/proc/softirqs",
            "/proc/interrupts",
            "/sys/class/net/eth0/device/numa_node",
        ] {
            match safe_read(p) {
                Ok(_) => {}
                Err(e) => assert_ne!(
                    e.kind(),
                    std::io::ErrorKind::PermissionDenied,
                    "allowlisted path {p} must not be denied by the allowlist"
                ),
            }
        }
    }
}
