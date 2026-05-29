//! Port-level error types shared across driven port traits.

use thiserror::Error;

/// Error returned by any [`crate::collector::Collector`] implementation.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CollectError {
    /// The collector's kernel subsystem is unavailable on this host.
    #[error("subsystem unavailable: {reason}")]
    Unavailable {
        /// Human-readable reason (e.g., `"EPROTONOSUPPORT"`, `"module not loaded"`).
        reason: String,
    },

    /// A netlink dump was interrupted (`NLM_F_DUMP_INTR`); max restarts exceeded.
    #[error("netlink dump interrupted: max restarts exceeded")]
    DumpIntr,

    /// Receive buffer overflow (`ENOBUFS`).
    #[error("netlink receive buffer overflow (ENOBUFS)")]
    RecvBufOverflow,

    /// A parse error while decoding a netlink message.
    #[error("parse error: {0}")]
    Parse(String),

    /// A scrape timeout was reached.
    #[error("scrape timeout after {millis}ms")]
    Timeout {
        /// Configured timeout in milliseconds.
        millis: u64,
    },

    /// An I/O error at the socket layer.
    #[error("netlink socket I/O error: {0}")]
    Io(String),
}
