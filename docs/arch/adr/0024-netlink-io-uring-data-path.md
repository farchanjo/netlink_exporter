---
status: accepted
date: 2026-05-29
deciders: [eonf]
consulted: []
informed: []
---

# Drive the netlink data path with io_uring SEND/RECV

Refines ADR-0011 (direct wire) and ADR-0023 (monoio io_uring runtime).

## Context and Problem Statement

ADR-0023 adopted monoio as the io_uring-first runtime. monoio drives its own
executor and the HTTP accept loop through io_uring, but monoio 0.2 exposes no
usable readiness primitive for an arbitrary `AF_NETLINK` file descriptor
(`monoio::io::poll_io` merely re-exports `tokio::io`, which would pull tokio
back into the graph). The first monoio implementation therefore performed the
netlink dump with blocking `sendmsg`/`recvmsg` syscalls offloaded to
`monoio::spawn_blocking`.

That left io_uring driving only the runtime and HTTP — the netlink data path
(the exporter's actual hot path) still used classic blocking syscalls. The
project requires io_uring to be the engine for netlink itself.

## Considered Options

- Blocking `sendmsg`/`recvmsg` inside `spawn_blocking` — rejected: the netlink
  data path is not io_uring.
- monoio `PollFd` readiness for the netlink fd — rejected: monoio 0.2 has no
  real `PollFd`; the re-export reintroduces tokio.
- `IORING_OP_SENDMSG`/`IORING_OP_RECVMSG` with `msghdr` + `sockaddr_nl` —
  rejected for the common case: extra `msghdr`/`iovec` lifetime complexity with
  no benefit when the kernel is the implicit peer.
- `IORING_OP_SEND`/`IORING_OP_RECV` on the bound netlink socket (chosen).

## Decision Outcome

Chosen option: **the netlink send/receive data path uses `IORING_OP_SEND` and
`IORING_OP_RECV`** via the `io-uring` crate 0.7 on the bound `AF_NETLINK`
socket. On a socket bound with `sockaddr_nl { nl_pid: 0 }` the kernel is the
implicit peer, so `send(2)`/`recv(2)` semantics (and thus the SEND/RECV
opcodes) route to the kernel correctly — no `msghdr`/`sockaddr_nl` is required.

The submit/complete loop runs on a `monoio::spawn_blocking` thread (an
`io_uring::IoUring` ring with `submit_and_wait`) so the monoio HTTP reactor is
never blocked by a netlink dump. The public `NetlinkSocket` API
(`open`/`dump`/`request_single`/`resolve_genl_family`) is unchanged, so the 14
collectors are untouched. `NLM_F_MULTI`, `NLMSG_DONE`, `NLMSG_ERROR`, and
`NLM_F_DUMP_INTR` handling are preserved; only the syscall mechanism changed.

**Safety:** each `submission().push` is guarded by a `// SAFETY:` proof — the
SEND buffer (`&[u8]`) and RECV buffer (`&mut [u8]`) stay pinned and un-aliased
until the matching CQE is consumed; a single op is in flight per ring.

**Verification (vm.services, kernel 6.17):** `strace -c` during a scrape shows
`io_uring_enter` calls only and **zero** `sendmsg`/`recvmsg`/`sendto`/`recvfrom`
syscalls; `nft_link_*` matches `ip -s link` and `nft_conntrack_entries` equals
`nf_conntrack_count`.

**Consequences:** io_uring is now the engine for the netlink hot path as well as
the runtime/HTTP. A ring is currently created per `dump` call (queue depth 32);
a future optimisation is a pooled ring reused across scrapes. No `/proc`/`/sys`
read is introduced (ADR-0025). Lock-free invariant (ADR-0023) is retained.
