//! `NetlinkSocket` — non-blocking `AF_NETLINK` transport.
//!
//! ## Design (ADR-0011 + ADR-0014)
//!
//! 1. Open a non-blocking raw `AF_NETLINK` socket via `rustix::net::socket_with`
//!    with `SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC`.
//! 2. Bind with `nl_pid = 0` so the kernel assigns the port ID.
//! 3. Tune `SO_RCVBUF` to a minimum of 4 MiB.
//! 4. Optionally enable `NETLINK_GET_STRICT_CHK` (`ENOPROTOOPT` silently
//!    ignored on kernel < 4.20).
//! 5. Wrap the raw fd in `tokio::io::unix::AsyncFd` to integrate with the
//!    tokio reactor.  `mio` registers the fd with `epoll` via `AsyncFd::new`.
//!
//! ## Dump loop
//!
//! [`NetlinkSocket::dump`] sends a single `NLM_F_DUMP`-flagged request and
//! accumulates frames until `NLMSG_DONE`, returning the payload bytes from
//! every data frame.  It detects `NLM_F_DUMP_INTR` on every received
//! `nlmsghdr` and propagates [`NetlinkError::DumpIntr`] to the call site so
//! the collector can restart (cap retries there).
//!
//! ## ENOBUFS circuit-breaker
//!
//! On the first `ENOBUFS`, `SO_RCVBUF` is doubled (up to 16 MiB).  On a
//! second `ENOBUFS` for the same request the dump is aborted and
//! [`NetlinkError::RecvBufOverflow`] is returned.
//!
//! ## Linux-only
//!
//! All socket-level code is wrapped in `#[cfg(target_os = "linux")]`.  On
//! macOS the file compiles but constructing a `NetlinkSocket` returns
//! `NetlinkError::Open` immediately (no-op stub).  This lets `cargo check`
//! succeed cross-platform for CI while runtime remains Linux-only.

use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicU32, Ordering};

use thiserror::Error;
use tokio::io::unix::AsyncFd;
use tracing::{debug, trace, warn};

use crate::wire::{NLA_HDRLEN, align4, parse_attrs, read_u16};

// ---------------------------------------------------------------------------
// Sequence counter — monotonically increasing, process-global.
// ---------------------------------------------------------------------------
static SEQ: AtomicU32 = AtomicU32::new(1);

#[inline]
fn next_seq() -> u32 {
    SEQ.fetch_add(1, Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Wire constants
// ---------------------------------------------------------------------------

/// `nlmsghdr` size in bytes.
pub const NLMSG_HDRLEN: usize = 16;
/// Maximum `SO_RCVBUF` the circuit-breaker will grow to.
const MAX_RCVBUF: usize = 16 * 1024 * 1024;

// nlmsghdr control message types
const NLMSG_NOOP: u16 = 1;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLMSG_OVERRUN: u16 = 4;

// nlmsg_flags bits
const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_MULTI: u16 = 0x0002;
const NLM_F_DUMP_INTR: u16 = 0x0010;
const NLM_F_DUMP: u16 = 0x0300;

// Generic netlink (NETLINK_GENERIC)
const GENL_ID_CTRL: u16 = 0x10; // family ID used for CTRL_CMD_GETFAMILY
// genlmsghdr commands for controller
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;
const CTRL_ATTR_FAMILY_ID: u16 = 1;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors returned by transport operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum NetlinkError {
    /// Socket creation, bind, or `AsyncFd` registration failed.
    #[error("netlink socket open failed: {0}")]
    Open(String),

    /// A dump was interrupted by `NLM_F_DUMP_INTR`; caller should retry.
    ///
    /// The call site is responsible for capping the retry count.
    #[error("netlink dump interrupted (NLM_F_DUMP_INTR); retry required")]
    DumpIntr,

    /// Receive buffer overflow (`ENOBUFS`) after the circuit-breaker doubled
    /// the buffer.  Activate stale-snapshot fallback.
    #[error("netlink receive buffer overflow (ENOBUFS)")]
    RecvBufOverflow,

    /// A `recvmsg` syscall returned an unexpected error.
    #[error("recvmsg error: {0}")]
    Recv(String),

    /// A `sendmsg` syscall returned an error.
    #[error("sendmsg error: {0}")]
    Send(String),

    /// The kernel returned a `NLMSG_ERROR` frame with a non-zero errno.
    ///
    /// `ENOENT` (2) typically means the genetlink family is not loaded.
    #[error("netlink kernel error: errno={errno}")]
    KernelError {
        /// Positive errno (already negated from the kernel's `nlmsgerr.error`).
        errno: i32,
    },

    /// Frame parse error (truncated header, mismatched length, etc.).
    #[error("netlink frame parse error: {0}")]
    Parse(String),
}

/// Convenience alias used by collector authors.
pub type Result<T> = std::result::Result<T, NetlinkError>;

// ---------------------------------------------------------------------------
// NetlinkSocket
// ---------------------------------------------------------------------------

/// Non-blocking `AF_NETLINK` socket integrated with the tokio reactor via
/// [`AsyncFd`].
///
/// # Panics
///
/// [`NetlinkSocket::open`] panics if called outside a tokio runtime context
/// (the `AsyncFd::new` call registers the fd with the current tokio runtime).
pub struct NetlinkSocket {
    async_fd: AsyncFd<OwnedFd>,
    /// Current `SO_RCVBUF` size tracked for the ENOBUFS circuit-breaker.
    rcvbuf_size: usize,
    /// Netlink protocol constant (e.g. 0 = NETLINK_ROUTE, 16 = NETLINK_GENERIC).
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

/// Minimum `SO_RCVBUF` target: 4 MiB (ADR-0011 §Socket lifecycle).
pub const MIN_RCVBUF: usize = 4 * 1024 * 1024;

/// Maximum number of `NLM_F_DUMP_INTR` restarts the call site should allow
/// before returning `NetlinkError::DumpIntr` to the collector.
pub const MAX_DUMP_RESTARTS: u32 = 8;

impl NetlinkSocket {
    /// Open a non-blocking `AF_NETLINK` socket for `nl_family` and register
    /// it with the tokio reactor.
    ///
    /// Pass the raw protocol integer:
    ///
    /// | Family | Value |
    /// |---|---|
    /// | `NETLINK_ROUTE` | 0 |
    /// | `NETLINK_SOCK_DIAG` | 4 |
    /// | `NETLINK_XFRM` | 6 |
    /// | `NETLINK_NETFILTER` | 12 |
    /// | `NETLINK_GENERIC` | 16 |
    ///
    /// # Errors
    ///
    /// Returns [`NetlinkError::Open`] if the socket, bind, `setsockopt`, or
    /// `AsyncFd` registration fails.
    ///
    /// # Panics
    ///
    /// Panics if called outside a tokio runtime (see module-level note on
    /// `AsyncFd`).
    pub fn open(nl_family: i32) -> Result<Self> {
        let fd = Self::open_raw_fd(nl_family)?;
        let async_fd = AsyncFd::new(fd).map_err(|e| NetlinkError::Open(e.to_string()))?;
        Ok(Self {
            async_fd,
            rcvbuf_size: MIN_RCVBUF,
            nl_family,
        })
    }

    // -----------------------------------------------------------------------
    // Socket construction (Linux only)
    // -----------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    fn open_raw_fd(nl_family: i32) -> Result<OwnedFd> {
        use rustix::net::sockopt::set_socket_recv_buffer_size;
        use rustix::net::{
            AddressFamily, Protocol, SocketFlags, SocketType, netlink::SocketAddrNetlink,
        };

        // Translate the raw protocol integer to a rustix Protocol.
        // NETLINK_ROUTE = 0 is represented as None in rustix (NonZeroU32 required).
        // All other families are wrapped as NonZeroU32.
        let protocol: Option<Protocol> =
            std::num::NonZeroU32::new(nl_family as u32).map(Protocol::from_raw);

        let flags = SocketFlags::NONBLOCK | SocketFlags::CLOEXEC;
        let fd = rustix::net::socket_with(AddressFamily::NETLINK, SocketType::RAW, flags, protocol)
            .map_err(|e| NetlinkError::Open(format!("socket: {e}")))?;

        // Bind with nl_pid=0 so the kernel assigns the port ID.
        let addr = SocketAddrNetlink::new(0, 0);
        rustix::net::bind(&fd, &addr).map_err(|e| NetlinkError::Open(format!("bind: {e}")))?;

        // Tune SO_RCVBUF to at least 4 MiB.  The kernel doubles the requested
        // value internally; passing MIN_RCVBUF requests an effective buffer of
        // 2×MIN_RCVBUF in most kernels, which is acceptable.
        set_socket_recv_buffer_size(&fd, MIN_RCVBUF)
            .map_err(|e| NetlinkError::Open(format!("SO_RCVBUF: {e}")))?;

        // NETLINK_GET_STRICT_CHK (value 12 per linux-raw-sys) — best effort.
        // Available on kernel >= 4.20; silently ignore ENOPROTOOPT (92 on Linux).
        Self::try_set_strict_chk(&fd);

        Ok(fd)
    }

    /// Try to enable `NETLINK_GET_STRICT_CHK` via a raw `setsockopt` syscall.
    /// Silently ignores any error (ENOPROTOOPT on kernel < 4.20).
    ///
    /// There is no typed wrapper in rustix for `SOL_NETLINK` socket options,
    /// so we fall back to a raw libc call.
    #[cfg(target_os = "linux")]
    fn try_set_strict_chk(fd: &OwnedFd) {
        // SOL_NETLINK = 270, NETLINK_GET_STRICT_CHK = 12 (linux-raw-sys).
        // SAFETY: `fd` is a valid owned fd; SOL_NETLINK/NETLINK_GET_STRICT_CHK
        // are well-known constants; `addr_of!(value)` is valid for the 4-byte read.
        let raw = fd.as_raw_fd();
        let value: libc::c_int = 1;
        let ret = unsafe {
            libc::setsockopt(
                raw,
                270_i32, // SOL_NETLINK
                12_i32,  // NETLINK_GET_STRICT_CHK
                std::ptr::addr_of!(value).cast::<libc::c_void>(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret != 0 {
            // ENOPROTOOPT (92) is expected on kernel < 4.20; log but do not fail.
            let errno = std::io::Error::last_os_error();
            debug!(errno = ?errno, "NETLINK_GET_STRICT_CHK not available (kernel < 4.20)");
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[allow(clippy::unnecessary_wraps)]
    fn open_raw_fd(_nl_family: i32) -> Result<OwnedFd> {
        Err(NetlinkError::Open(
            "AF_NETLINK is only available on Linux".into(),
        ))
    }

    // -----------------------------------------------------------------------
    // Recv-buf growth (ENOBUFS circuit-breaker)
    // -----------------------------------------------------------------------

    /// Double `SO_RCVBUF` up to [`MAX_RCVBUF`].  Returns `Ok(new_size)` or an
    /// error if already at the cap.
    fn grow_rcvbuf(&mut self) -> Result<usize> {
        let new_size = self.rcvbuf_size.saturating_mul(2).min(MAX_RCVBUF);
        if new_size == self.rcvbuf_size {
            return Err(NetlinkError::RecvBufOverflow);
        }
        #[cfg(target_os = "linux")]
        rustix::net::sockopt::set_socket_recv_buffer_size(self.async_fd.get_ref(), new_size)
            .map_err(|e| NetlinkError::Recv(format!("SO_RCVBUF grow: {e}")))?;
        self.rcvbuf_size = new_size;
        debug!(new_size, "grew SO_RCVBUF");
        Ok(new_size)
    }

    // -----------------------------------------------------------------------
    // Frame building
    // -----------------------------------------------------------------------

    /// Build a complete `nlmsghdr + payload` datagram.
    ///
    /// `msg_type` and `flags` are provided by the caller; `NLM_F_REQUEST` is
    /// ORed in automatically.  `seq` is taken from the global counter.
    /// `nl_pid = 0` in the header (userspace sender, not the socket's port).
    fn build_request(msg_type: u16, flags: u16, payload: &[u8]) -> Vec<u8> {
        let total_len = NLMSG_HDRLEN + payload.len();
        let mut buf = Vec::with_capacity(align4(total_len));

        // nlmsghdr (16 bytes, native-endian)
        buf.extend_from_slice(&(total_len as u32).to_ne_bytes()); // nlmsg_len
        buf.extend_from_slice(&msg_type.to_ne_bytes()); // nlmsg_type
        buf.extend_from_slice(&(NLM_F_REQUEST | flags).to_ne_bytes()); // nlmsg_flags
        buf.extend_from_slice(&next_seq().to_ne_bytes()); // nlmsg_seq
        buf.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid = 0

        buf.extend_from_slice(payload);
        buf
    }

    // -----------------------------------------------------------------------
    // Send
    // -----------------------------------------------------------------------

    /// Send `data` on the socket, awaiting writability if needed.
    ///
    /// Loops on `EAGAIN`/`EWOULDBLOCK` by awaiting `AsyncFd::writable`.
    async fn send_all(&self, data: &[u8]) -> Result<()> {
        use rustix::net::SendFlags;

        loop {
            let mut guard = self
                .async_fd
                .writable()
                .await
                .map_err(|e| NetlinkError::Send(e.to_string()))?;

            match guard.try_io(|fd| {
                rustix::net::send(fd.get_ref(), data, SendFlags::empty())
                    .map_err(std::io::Error::from)
            }) {
                Ok(Ok(_n)) => return Ok(()),
                Ok(Err(e)) => return Err(NetlinkError::Send(e.to_string())),
                Err(_would_block) => continue, // AsyncFd says not ready yet
            }
        }
    }

    // -----------------------------------------------------------------------
    // Recv one datagram
    // -----------------------------------------------------------------------

    /// Receive one netlink datagram into `buf`, awaiting readability.
    ///
    /// Returns the number of bytes actually written into `buf`.  On Linux,
    /// uses `MSG_TRUNC` so we know the real datagram size even when `buf` is
    /// smaller (though with the default 4 MiB buffer this should never
    /// truncate in practice).
    ///
    /// # Errors
    ///
    /// Returns `NetlinkError::Recv` on syscall errors.
    /// Returns `NetlinkError::RecvBufOverflow` on `ENOBUFS`.
    async fn recv_datagram(&self, buf: &mut Vec<u8>) -> Result<usize> {
        use rustix::net::RecvFlags;

        // MSG_TRUNC is gated to Linux in rustix (not available on macOS).
        #[cfg(target_os = "linux")]
        let flags = RecvFlags::TRUNC;
        #[cfg(not(target_os = "linux"))]
        let flags = RecvFlags::empty();

        loop {
            let mut guard = self
                .async_fd
                .readable()
                .await
                .map_err(|e| NetlinkError::Recv(e.to_string()))?;

            // recv returns Result<(Buf::Output, actual_len), Errno>.
            // try_io requires std::io::Result so we convert via map_err.
            match guard.try_io(|fd| {
                rustix::net::recv(fd.get_ref(), &mut *buf, flags)
                    .map(|(_slice, actual_len)| actual_len)
                    .map_err(std::io::Error::from)
            }) {
                Ok(Ok(actual_len)) => return Ok(actual_len),
                Ok(Err(e)) => {
                    // ENOBUFS (errno 105 on Linux, 55 on macOS):
                    // raw_os_error() surfaces the platform errno.
                    if e.raw_os_error() == Some(libc::ENOBUFS) {
                        return Err(NetlinkError::RecvBufOverflow);
                    }
                    return Err(NetlinkError::Recv(e.to_string()));
                }
                Err(_would_block) => continue,
            }
        }
    }

    // -----------------------------------------------------------------------
    // Frame parsing
    // -----------------------------------------------------------------------

    /// Parse one or more `nlmsghdr`-framed messages from `datagram[..len]`.
    ///
    /// Returns:
    /// - `Ok(true)` when `NLMSG_DONE` is encountered (stop receiving).
    /// - `Ok(false)` when more datagrams are expected.
    /// - `Err(NetlinkError::DumpIntr)` when `NLM_F_DUMP_INTR` is seen.
    /// - `Err(NetlinkError::KernelError)` when `NLMSG_ERROR` with non-zero errno.
    ///
    /// Each data-frame payload (bytes after the 16-byte header) is appended to
    /// `out`.
    fn parse_datagram(datagram: &[u8], len: usize, out: &mut Vec<Vec<u8>>) -> Result<bool> {
        let mut pos = 0usize;
        let buf = &datagram[..len.min(datagram.len())];

        while pos + NLMSG_HDRLEN <= buf.len() {
            let hdr = &buf[pos..pos + NLMSG_HDRLEN];

            // nlmsghdr fields (all native-endian per §3.1)
            let nlmsg_len = u32::from_ne_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as usize;
            let nlmsg_type = u16::from_ne_bytes([hdr[4], hdr[5]]);
            let nlmsg_flags = u16::from_ne_bytes([hdr[6], hdr[7]]);
            // seq at [8..12], pid at [12..16] — not used here

            if nlmsg_len < NLMSG_HDRLEN {
                return Err(NetlinkError::Parse(format!(
                    "nlmsg_len {nlmsg_len} < NLMSG_HDRLEN"
                )));
            }
            if pos + nlmsg_len > buf.len() {
                // Truncated frame — stop.
                break;
            }

            let msg_payload = &buf[pos + NLMSG_HDRLEN..pos + nlmsg_len];

            // Check NLM_F_DUMP_INTR on every frame (§3.3).
            if nlmsg_flags & NLM_F_DUMP_INTR != 0 {
                warn!("NLM_F_DUMP_INTR detected — kernel data changed during dump");
                return Err(NetlinkError::DumpIntr);
            }

            match nlmsg_type {
                NLMSG_NOOP => {
                    trace!("NLMSG_NOOP — skip");
                }
                NLMSG_DONE => {
                    debug!("NLMSG_DONE — dump complete");
                    return Ok(true);
                }
                NLMSG_OVERRUN => {
                    warn!("NLMSG_OVERRUN — treat as ENOBUFS");
                    return Err(NetlinkError::RecvBufOverflow);
                }
                NLMSG_ERROR => {
                    // struct nlmsgerr: i32 error + nlmsghdr (16 bytes echoed).
                    // error field is at bytes 0..4 of msg_payload.
                    if msg_payload.len() < 4 {
                        return Err(NetlinkError::Parse("NLMSG_ERROR payload too short".into()));
                    }
                    let raw_errno = i32::from_ne_bytes([
                        msg_payload[0],
                        msg_payload[1],
                        msg_payload[2],
                        msg_payload[3],
                    ]);
                    if raw_errno != 0 {
                        // Kernel returns negated errno.
                        return Err(NetlinkError::KernelError {
                            errno: raw_errno.abs(),
                        });
                    }
                    // errno == 0 is a success ACK — treat as done.
                    return Ok(true);
                }
                _ => {
                    // Data frame: collect payload bytes after the header.
                    if nlmsg_flags & NLM_F_MULTI != 0 || !out.is_empty() {
                        out.push(msg_payload.to_vec());
                    } else {
                        // Single (non-multi) reply.
                        out.push(msg_payload.to_vec());
                    }
                }
            }

            // Advance to the next NLMSG_ALIGN(4)-padded frame.
            pos += align4(nlmsg_len);
        }

        Ok(false) // more datagrams expected
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /// Send a netlink dump request and accumulate all response frames.
    ///
    /// Builds a single `nlmsghdr` with `NLM_F_REQUEST | flags | NLM_F_DUMP`
    /// followed by `payload`, sends it, then loops reading datagrams until
    /// `NLMSG_DONE`.  Each data-frame payload (bytes after the 16-byte
    /// `nlmsghdr`) is collected into the returned `Vec`.
    ///
    /// # ENOBUFS handling
    ///
    /// On first `ENOBUFS`, the receive buffer is doubled and the entire
    /// request is retried from the beginning.  On a second `ENOBUFS` for the
    /// same call, [`NetlinkError::RecvBufOverflow`] is returned.
    ///
    /// # NLM_F_DUMP_INTR
    ///
    /// Returns [`NetlinkError::DumpIntr`] immediately.  The call site must
    /// retry; cap retries at [`MAX_DUMP_RESTARTS`].
    ///
    /// # Errors
    ///
    /// Returns [`NetlinkError`] on socket I/O, parse failure, or kernel error.
    pub async fn dump(
        &mut self,
        msg_type: u16,
        flags: u16,
        payload: &[u8],
    ) -> Result<Vec<Vec<u8>>> {
        let mut enobufs_retried = false;

        loop {
            let request = Self::build_request(msg_type, flags | NLM_F_DUMP, payload);
            debug!(nl_family = self.nl_family, msg_type, "netlink dump start");

            self.send_all(&request).await?;

            let mut out = Vec::new();
            let mut recv_buf = vec![0u8; self.rcvbuf_size];

            'recv: loop {
                // Resize buf if rcvbuf_size grew.
                if recv_buf.len() < self.rcvbuf_size {
                    recv_buf.resize(self.rcvbuf_size, 0u8);
                }

                let n = match self.recv_datagram(&mut recv_buf).await {
                    Ok(n) => n,
                    Err(NetlinkError::RecvBufOverflow) => {
                        if enobufs_retried {
                            return Err(NetlinkError::RecvBufOverflow);
                        }
                        enobufs_retried = true;
                        self.grow_rcvbuf()?;
                        break 'recv; // restart the whole dump
                    }
                    Err(e) => return Err(e),
                };

                match Self::parse_datagram(&recv_buf, n, &mut out) {
                    Ok(true) => return Ok(out),  // NLMSG_DONE
                    Ok(false) => continue 'recv, // more frames
                    Err(NetlinkError::DumpIntr) => return Err(NetlinkError::DumpIntr),
                    Err(e) => return Err(e),
                }
            }
            // Loop restart after ENOBUFS growth.
        }
    }

    /// Send a unicast (non-dump) netlink request and return the single reply
    /// payload.
    ///
    /// Useful for one-shot requests that return a single response message
    /// (e.g. `CTRL_CMD_GETFAMILY`).
    ///
    /// # Errors
    ///
    /// Returns [`NetlinkError`] on socket I/O, parse failure, or kernel error.
    pub async fn request_single(
        &mut self,
        msg_type: u16,
        flags: u16,
        payload: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        let request = Self::build_request(msg_type, flags, payload);
        self.send_all(&request).await?;

        let mut recv_buf = vec![0u8; self.rcvbuf_size];
        let n = self.recv_datagram(&mut recv_buf).await?;

        let mut out = Vec::new();
        Self::parse_datagram(&recv_buf, n, &mut out)?;
        Ok(out.into_iter().next())
    }

    // -----------------------------------------------------------------------
    // Generic netlink family resolution
    // -----------------------------------------------------------------------

    /// Resolve the dynamic family ID for a Generic Netlink family by name.
    ///
    /// Sends `CTRL_CMD_GETFAMILY` on the `NETLINK_GENERIC` bus and parses
    /// `CTRL_ATTR_FAMILY_ID` from the reply.
    ///
    /// Returns:
    /// - `Ok(Some(id))` when the family is registered.
    /// - `Ok(None)` when the kernel replies `ENOENT` (family / module not
    ///   loaded).  This is the runtime gate used by optional collectors
    ///   (ethtool, WireGuard, devlink, …).
    /// - `Err(_)` on any other error.
    ///
    /// # Errors
    ///
    /// Returns [`NetlinkError`] on socket I/O, parse failure, or non-ENOENT
    /// kernel error.
    pub async fn resolve_genl_family(&mut self, name: &str) -> Result<Option<u16>> {
        // genlmsghdr (4 bytes): cmd=CTRL_CMD_GETFAMILY(3), version=2, reserved=0
        let mut genl_payload = vec![CTRL_CMD_GETFAMILY, 2u8, 0u8, 0u8];

        // CTRL_ATTR_FAMILY_NAME (type=2): NUL-terminated family name as nlattr.
        let name_bytes = name.as_bytes();
        // nla_len = NLA_HDRLEN + name_bytes + 1 (NUL terminator)
        let nla_payload_len = name_bytes.len() + 1;
        let nla_total = NLA_HDRLEN + nla_payload_len;
        let nla_padded = align4(nla_total);

        genl_payload.extend_from_slice(&(nla_total as u16).to_ne_bytes()); // nla_len
        genl_payload.extend_from_slice(&CTRL_ATTR_FAMILY_NAME.to_ne_bytes()); // nla_type
        genl_payload.extend_from_slice(name_bytes);
        genl_payload.push(0u8); // NUL terminator
        // padding
        let pad = nla_padded - nla_total;
        genl_payload.extend(std::iter::repeat_n(0u8, pad));

        match self.request_single(GENL_ID_CTRL, 0, &genl_payload).await {
            Ok(Some(payload)) => {
                // Payload starts with genlmsghdr (4 bytes), then nlattr chain.
                if payload.len() < 4 {
                    return Err(NetlinkError::Parse(
                        "CTRL reply too short for genlmsghdr".into(),
                    ));
                }
                // Skip genlmsghdr (4 bytes) to reach nlattr chain.
                let attrs_buf = &payload[4..];
                for attr in parse_attrs(attrs_buf) {
                    if attr.ty == CTRL_ATTR_FAMILY_ID {
                        let id = read_u16(attr.payload).ok_or_else(|| {
                            NetlinkError::Parse("CTRL_ATTR_FAMILY_ID too short".into())
                        })?;
                        return Ok(Some(id));
                    }
                }
                Err(NetlinkError::Parse(
                    "CTRL_ATTR_FAMILY_ID not found in reply".into(),
                ))
            }
            Ok(None) => Err(NetlinkError::Parse(
                "CTRL_CMD_GETFAMILY returned empty reply".into(),
            )),
            Err(NetlinkError::KernelError { errno: 2 }) => {
                // ENOENT (2) — family not registered.
                debug!(family = name, "genetlink family not found (ENOENT)");
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }
}

// ---------------------------------------------------------------------------
// Backward-compat re-export for existing stubs that used `TransportError`.
// ---------------------------------------------------------------------------

/// Alias kept for existing stub callers; prefer [`NetlinkError`] in new code.
pub type TransportError = NetlinkError;

/// Maximum dump restarts (alias for backward compat with existing stub constant).
// Intentionally a distinct definition so the old name still resolves.
#[allow(dead_code)]
const _MAX_DUMP_RESTARTS_COMPAT: u32 = MAX_DUMP_RESTARTS;
