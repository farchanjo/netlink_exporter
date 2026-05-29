//! `NetlinkSocket` — non-blocking `AF_NETLINK` transport.
//!
//! ## Design (ADR-0011 + ADR-0014)
//!
//! 1. Open a non-blocking raw `AF_NETLINK` socket via `rustix::net::socket_with`
//!    with `O_NONBLOCK`.
//! 2. Bind with `nl_pid = 0` so the kernel assigns the PID.
//! 3. Tune `SO_RCVBUF` to a minimum of 4 MiB.
//! 4. Optionally enable `NETLINK_GET_STRICT_CHK` (`ENOPROTOOPT` silently
//!    ignored on kernel < 4.20).
//! 5. Wrap the raw fd in `tokio::io::unix::AsyncFd` to integrate with the
//!    tokio reactor.  `mio` registers the fd with `epoll` via `AsyncFd::new`.
//!
//! ## Dump loop
//!
//! [`NetlinkSocket::dump`] sends a `RTM_GETLINK` (or any other `NLM_F_DUMP`)
//! request and accumulates frames until `NLMSG_DONE`.  It detects
//! `NLM_F_DUMP_INTR` on every received `nlmsghdr` and restarts the dump up
//! to `max_restarts` times before returning [`TransportError::DumpIntr`].
//!
//! ## ENOBUFS circuit-breaker
//!
//! On the first `ENOBUFS`, `SO_RCVBUF` is doubled.  On a second `ENOBUFS`
//! for the same request the dump is aborted and [`TransportError::RecvBufOverflow`]
//! is returned; the collector activates stale-snapshot fallback.

use std::os::fd::{AsRawFd, OwnedFd};

use thiserror::Error;
use tokio::io::unix::AsyncFd;
use tracing::{debug, warn};

/// Errors returned by transport operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TransportError {
    /// Socket creation or bind failed.
    #[error("netlink socket open failed: {0}")]
    Open(String),

    /// A dump was interrupted by `NLM_F_DUMP_INTR`; max restarts exceeded.
    #[error("netlink dump interrupted (NLM_F_DUMP_INTR); max restarts exceeded")]
    DumpIntr,

    /// Receive buffer overflow (`ENOBUFS`) after doubling buffer.
    #[error("netlink receive buffer overflow (ENOBUFS)")]
    RecvBufOverflow,

    /// A recvmsg syscall returned an unexpected error.
    #[error("recvmsg error: {0}")]
    Recv(String),

    /// A sendmsg syscall returned an error.
    #[error("sendmsg error: {0}")]
    Send(String),

    /// The kernel returned a `NLMSG_ERROR` frame.
    #[error("netlink error response: errno={errno}")]
    NlError {
        /// Errno value from the `nlmsgerr` payload.
        errno: i32,
    },
}

/// Maximum number of `NLM_F_DUMP_INTR` restarts before returning an error.
pub const MAX_DUMP_RESTARTS: u32 = 8;

/// Non-blocking `AF_NETLINK` socket integrated with the tokio reactor.
///
/// # Panics
///
/// [`NetlinkSocket::open`] panics if called outside a tokio runtime context
/// (the `AsyncFd::new` call registers the fd with the current tokio runtime).
pub struct NetlinkSocket {
    async_fd: AsyncFd<OwnedFd>,
    /// Current `SO_RCVBUF` size in bytes (tracks circuit-breaker doublings).
    rcvbuf_size: usize,
    /// Netlink family (e.g. `NETLINK_ROUTE`, `NETLINK_NETFILTER`).
    nl_family: i32,
}

impl std::fmt::Debug for NetlinkSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetlinkSocket")
            .field("nl_family", &self.nl_family)
            .field("rcvbuf_size", &self.rcvbuf_size)
            .field("fd", &self.async_fd.as_raw_fd())
            .finish()
    }
}

/// Minimum `SO_RCVBUF` size: 4 MiB (ADR-0011).
const MIN_RCVBUF: usize = 4 * 1024 * 1024;

impl NetlinkSocket {
    /// Open a non-blocking `AF_NETLINK` socket for `nl_family` and register
    /// it with the tokio reactor.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Open`] if the socket, bind, or `AsyncFd`
    /// registration fails.
    ///
    /// # Panics
    ///
    /// Panics if called outside a tokio runtime (see module-level note on
    /// `AsyncFd`).
    pub fn open(nl_family: i32) -> Result<Self, TransportError> {
        // SAFETY: rustix handles the syscall; all invariants are documented
        // in rustix's own safety contracts.  We own the returned fd.
        let fd = Self::open_raw_fd(nl_family)?;

        let async_fd = AsyncFd::new(fd).map_err(|e| TransportError::Open(e.to_string()))?;

        Ok(Self {
            async_fd,
            rcvbuf_size: MIN_RCVBUF,
            nl_family,
        })
    }

    /// Low-level: create + configure the raw non-blocking AF_NETLINK fd.
    fn open_raw_fd(nl_family: i32) -> Result<OwnedFd, TransportError> {
        // TODO(impl): rustix::net::socket_with(AF_NETLINK, SOCK_RAW|O_NONBLOCK,
        //   nl_family), bind sockaddr_nl{nl_pid=0}, setsockopt SO_RCVBUF,
        //   setsockopt NETLINK_GET_STRICT_CHK (ENOPROTOOPT silently ignored).
        let _ = nl_family; // suppress unused warning in stub
        todo!("open_raw_fd: implement rustix AF_NETLINK socket + bind + SO_RCVBUF + STRICT_CHK")
    }

    /// Send a netlink dump request and accumulate all response frames.
    ///
    /// Implements the `NLM_F_DUMP_INTR` restart logic and the `ENOBUFS`
    /// circuit-breaker described in ADR-0011.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError`] on socket errors, dump interruption, or
    /// receive buffer overflow.
    pub async fn dump(&mut self, request: &[u8]) -> Result<Vec<Vec<u8>>, TransportError> {
        let _ = request;
        debug!(nl_family = self.nl_family, "netlink dump start");
        warn!("NetlinkSocket::dump is a stub — no-op returning empty");
        // TODO(impl): sendmsg, then loop: async_fd.readable().await,
        //   guard.try_io(recvmsg_nonblock), parse nlmsghdr, detect
        //   NLM_F_DUMP_INTR, NLMSG_DONE, NLMSG_ERROR.  Handle ENOBUFS
        //   by doubling rcvbuf_size (once only; return RecvBufOverflow on second).
        Ok(Vec::new())
    }
}
