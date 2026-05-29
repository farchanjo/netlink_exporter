//! Domain error type.

use thiserror::Error;

/// Top-level error type for domain operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DomainError {
    /// A netlink dump was interrupted by the kernel (`NLM_F_DUMP_INTR`).
    /// The caller should retry or serve a stale snapshot.
    #[error("netlink dump interrupted (NLM_F_DUMP_INTR); max restarts exceeded")]
    DumpIntr,

    /// The kernel returned an `ENOBUFS` receive-buffer overflow.
    #[error("netlink receive buffer overflow (ENOBUFS)")]
    RecvBufOverflow,

    /// A collector subsystem is not available in the current kernel configuration.
    #[error("collector {name} not available: {reason}")]
    CollectorUnavailable {
        /// Collector identifier (e.g., `"conntrack"`, `"ethtool"`).
        name: &'static str,
        /// Human-readable reason returned by the kernel probe.
        reason: String,
    },

    /// Generic collector-level error carrying a message.
    #[error("collector error: {0}")]
    Collector(String),
}
