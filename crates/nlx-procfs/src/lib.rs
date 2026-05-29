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

pub mod irq;
pub mod netstat;
pub mod nic_bql;
pub mod nic_pcie;
pub mod nic_temp;
pub mod sockstat;
pub mod softirq;
pub mod softnet;

/// Fixed allowlist of path roots this crate may read (ADR-0027).
///
/// A path is permitted when it is exactly one of these roots (a base directory
/// to enumerate, or a leaf pseudo-file) OR lives strictly beneath one (matched
/// at a `/` component boundary, so `/sys/class/net` and `/sys/class/net/eth0`
/// are allowed but `/sys/class/network` is not). Keeping the list here makes the
/// entire procfs/sysfs surface auditable in one place.
const ALLOWED_PREFIXES: &[&str] = &[
    "/proc/net",
    "/proc/softirqs",
    "/proc/interrupts",
    "/proc/irq",
    "/sys/class/net",
    "/sys/bus/pci/devices",
];

/// Allowlist + traversal check shared by [`safe_read`] and [`safe_read_dir`].
///
/// Rejects any `..` component and any path that is neither an allowlisted root
/// nor strictly beneath one (component-boundary match — not a naive prefix).
fn path_allowed(path: &str) -> bool {
    if path.contains("..") {
        return false;
    }
    ALLOWED_PREFIXES.iter().any(|root| {
        path == *root
            || path
                .strip_prefix(root)
                .is_some_and(|rest| rest.starts_with('/'))
    })
}

/// Read a procfs/sysfs pseudo-file — but only if `path` is under an allowlisted
/// prefix (see [`ALLOWED_PREFIXES`]) and contains no `..` traversal component.
///
/// # Errors
///
/// Returns [`std::io::ErrorKind::PermissionDenied`] when `path` is not
/// allowlisted, or the underlying I/O error when the read fails.
pub fn safe_read(path: &str) -> std::io::Result<String> {
    if !path_allowed(path) {
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

/// List the entry names of an allowlisted directory (sysfs enumeration, e.g.
/// `/sys/class/net`, `/proc/irq`). Same allowlist + `..` guard as [`safe_read`].
/// Entry names are returned sorted for deterministic output; non-UTF-8 names are
/// skipped.
///
/// # Errors
///
/// Returns [`std::io::ErrorKind::PermissionDenied`] when `path` is not
/// allowlisted, or the underlying I/O error when the directory read fails.
pub fn safe_read_dir(path: &str) -> std::io::Result<Vec<String>> {
    if !path_allowed(path) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("path not in procfs/sysfs allowlist (ADR-0027): {path}"),
        ));
    }
    let mut names: Vec<String> = std::fs::read_dir(path)?
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .collect();
    names.sort();
    Ok(names)
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
    fn allowlist_matches_root_and_children_at_boundary() {
        // Base roots (enumerated by the sysfs collectors) must be allowed.
        assert!(path_allowed("/sys/class/net"));
        assert!(path_allowed("/proc/irq"));
        // Children are allowed.
        assert!(path_allowed(
            "/sys/class/net/dx6p0/device/current_link_speed"
        ));
        assert!(path_allowed("/proc/net/snmp"));
        // Leaf pseudo-files allowed exactly.
        assert!(path_allowed("/proc/softirqs"));
        // A sibling that merely shares a textual prefix must NOT match (boundary).
        assert!(!path_allowed("/sys/class/network_fake"));
        assert!(!path_allowed("/proc/network"));
        // Traversal and unrelated paths rejected.
        assert!(!path_allowed("/etc/passwd"));
        assert!(!path_allowed("/sys/class/net/../../../etc/shadow"));
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
