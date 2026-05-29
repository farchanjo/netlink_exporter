---
status: accepted
date: 2026-05-28
deciders: [eonf]
consulted: []
informed: []
---

# Require CAP_NET_ADMIN only; drop all other capabilities immediately after netlink socket open; reject CAP_NET_RAW and CAP_SYS_ADMIN by design

> **drop_monitor exception (ADR-0026):** When the `drop-monitor` collector is
> enabled, `CAP_SYS_ADMIN` is transiently required during the privileged setup
> phase to join the `NET_DM_GRP_ALERT` multicast group (`events`), which is
> declared `GENL_MCAST_CAP_SYS_ADMIN` in `net/core/drop_monitor.c:187`.  The
> join executes before the capability drop; the background recv thread spawned
> afterwards inherits no capabilities.  When `drop-monitor` is **disabled**
> (the default), `CAP_SYS_ADMIN` is never requested and the invariant below
> holds without exception.  See ADR-0026 for full capability ordering detail.

## Context and Problem Statement

The nft_exporter reads kernel state via six netlink API families. Two of those families (NETLINK_NETFILTER ctnetlink and `SOCK_DIAG_BY_FAMILY` with full stats) require elevated privileges. The wrong capability set choice could expose a significant privilege-escalation surface on every node in the cluster.

The team must select the minimum capability set required for all six collection paths, design a capability-drop policy, and document why stronger capabilities (`CAP_NET_RAW`, `CAP_SYS_ADMIN`) are explicitly not needed.

## Considered Options

- CAP_NET_ADMIN only + immediate drop after socket open (chosen)
- CAP_NET_ADMIN + CAP_NET_RAW + CAP_SYS_ADMIN (over-privileged)
- Run as root with no capability management

## Decision Outcome

**Chosen option: CAP_NET_ADMIN only, dropped immediately after socket open.**

**Why CAP_NET_ADMIN is sufficient**: All six netlink families are accessible via `socket(AF_NETLINK, SOCK_RAW, ...)` calls that require only `CAP_NET_ADMIN` on kernel >= 4.20 with `net.core.rmem_default` tunable access. `NETLINK_ROUTE` (RTM_GETQDISC, RTM_GETTCLASS, RTM_GETTFILTER), `NETLINK_NETFILTER` (IPCTNL_MSG_CT_GET, NFT_MSG_GETRULE), `NETLINK_SOCK_DIAG` (SOCK_DIAG_BY_FAMILY full stats including `INET_DIAG_SKMEMINFO`), and `NETLINK_GENERIC` (ETHTOOL family) all work with `CAP_NET_ADMIN` and no additional capabilities.

**Why CAP_NET_RAW is not required**: The netlink-only collection path uses `SOCK_RAW` over `AF_NETLINK`, not over `AF_PACKET` or `AF_INET`/`AF_INET6`. Raw packet capture would require `CAP_NET_RAW`; netlink socket raw type does not.

**Why CAP_SYS_ADMIN is not required**: Per-netns socket opening is handled by a dedicated `std::thread` (named `netns-opener`) that opens the netlink socket fd inside the target netns via fd inheritance, passes the fd to the tokio runtime over a `oneshot` channel, and exits. This avoids calling `setns(CLONE_NEWNET)`, which would require `CAP_SYS_ADMIN` (or `CAP_NET_ADMIN` with a new-enough kernel user-namespace policy). The fd-inheritance approach requires no additional capability.

**Capability drop implementation**: The `caps 0.5.6` crate is called in `ExporterApp::start()` immediately after all netlink socket fds are opened and before the tokio runtime starts accepting HTTP connections:

```rust
caps::clear(None, caps::CapSet::Permitted)?;
caps::clear(None, caps::CapSet::Effective)?;
caps::clear(None, caps::CapSet::Inheritable)?;
```

After this point the process has no capabilities in any set. The ambient set is never populated (ambient capabilities are a Linux >= 4.3 feature and would survive `execve`; clearing it is a defense-in-depth measure for the systemd deployment target where `AmbientCapabilities=CAP_NET_ADMIN` is set by the service manager before exec).

**Kubernetes pod security**: `capabilities.drop = ["ALL"]`, `capabilities.add = ["NET_ADMIN"]`, `allowPrivilegeEscalation = false`, `runAsNonRoot = true`, `runAsUser = 65532`, `readOnlyRootFilesystem = true`, `seccompProfile.type = RuntimeDefault`.

**systemd unit hardening**: `AmbientCapabilities=CAP_NET_ADMIN`, `CapabilityBoundingSet=CAP_NET_ADMIN`, `NoNewPrivileges=true`, `ProtectSystem=strict`, `PrivateTmp=true`, `PrivateDevices=true`, `ProtectKernelTunables=true`, `ProtectControlGroups=true`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK`, `MemoryDenyWriteExecute=true`, `LockPersonality=true`, `SystemCallFilter=@system-service @network-io`.

**Custom seccomp profile** (`deploy/seccomp/nft-exporter.json`): allows
`socket(AF_NETLINK)`, `bind`, `recvmsg`, `sendmsg`,
`io_uring_setup` (syscall 425), `io_uring_enter` (syscall 426),
`io_uring_register` (syscall 427), `futex`, `mmap`, `mprotect`, `read`,
`write`, `close`; denies `execve`, `execveat`, `ptrace`, `mount`, `bpf`,
`clone(CLONE_NEWUSER)`, `perf_event_open`.  `epoll_wait` is **not** in the
allowlist — the runtime is monoio io_uring, not epoll (ADR-0023).  The
Kubernetes `RuntimeDefault` seccomp profile denies `io_uring_setup` by
default; deploying the Localhost profile at
`/var/lib/kubelet/seccomp/nft-exporter.json` is therefore mandatory (see
`deploy/seccomp/nft-exporter.json` and ADR-0023 §seccomp).

**Consequences:**

- Positive: The capability bounding set contains exactly one capability; even if an attacker achieves arbitrary code execution inside the process, they cannot escalate beyond `CAP_NET_ADMIN`.
- Positive: Post-drop, the process has zero capabilities; network interface configuration, routing table modification, and firewall rule changes are all blocked from within the exporter process after socket initialization.
- Positive: The seccomp custom profile blocks the most common kernel exploit primitives (`execve`, `bpf`, `perf_event_open`, `clone(CLONE_NEWUSER)`) while permitting only the netlink I/O and tokio async primitives the exporter actually uses.
- Negative: The capability drop is irreversible and **fatal on failure** — if
  `caps::clear` returns an error the process aborts rather than continuing with
  elevated privileges.  If a future feature requires an additional capability,
  the corresponding socket must be opened before the drop in
  `ExporterApp::start()`.
- Negative: The custom seccomp profile must be maintained as the tokio and axum syscall surface evolves. CI runs `strace -f -e trace=all` in a test container and diffs against the allowed syscall set on each dependency update.

**Rejected options:**

- *CAP_NET_ADMIN + CAP_NET_RAW + CAP_SYS_ADMIN (over-privileged)*: `CAP_SYS_ADMIN` is the most dangerous Linux capability (equivalent to root for most purposes). `CAP_NET_RAW` allows raw packet injection into any network interface. Neither is required by the netlink-only collection path. Granting them would fail CIS Kubernetes Benchmark checks and violate the principle of least privilege.
- *Run as root with no capability management*: Running as uid 0 with a full capability set is explicitly prohibited by the Kubernetes admission controller (`runAsNonRoot: true` enforced by OPA Gatekeeper policy in the cluster). It also bypasses all Linux MAC and seccomp protections that key on capability checks.
