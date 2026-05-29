# Security Policy

## Threat Model

The full threat model for nft_exporter is documented at
`docs/arch/threat-model/threat-model.md`. It applies the STRIDE framework
across all assets and trust boundaries of the exporter process. The summary
table reproduced here is informational only; the authoritative analysis is in
that document.

| ID | Category | Threat | Residual Risk |
|---|---|---|---|
| S-1 | Spoofing | Spoofed Prometheus scrape request | Low (with NetworkPolicy) |
| T-1 | Tampering | Race condition in MetricSnapshot | Negligible |
| T-2 | Tampering | Binary replacement on host | Low |
| R-1 | Repudiation | Silent capability drop failure | Low |
| I-1 | Info Disclosure | Unauthenticated /metrics endpoint | Low (with NetworkPolicy) |
| I-2 | Info Disclosure | Kernel memory in netlink error | Negligible |
| D-1 | DoS | Huge conntrack table | Medium |
| D-2 | DoS | Rapid scrape rate amplification | Low |
| E-1 | Escalation | CAP_NET_ADMIN retained after socket open | Low |
| E-2 | Escalation | Container escape via hostNetwork | Medium |

The two residual Medium risks (D-1, E-2) are accepted architectural
constraints documented in the threat model. D-1 is bounded by operational
conntrack sizing policy. E-2 is inherent to any DaemonSet exporter that
requires host network namespace access.

---

## CAP_NET_ADMIN Scope

nft_exporter starts with `CAP_NET_ADMIN` (and transiently `CAP_SYS_ADMIN`
for the drop_monitor multicast group join — see ADR-0026 below) to open
AF_NETLINK sockets, then **fatally aborts if capabilities cannot be
dropped** after setup. The drop sequence is (see ADR-0009):

1. Open all netlink socket file descriptors synchronously (no async tasks
   running yet).
2. Start the `drop_monitor` multicast listener setup on the main thread
   (requires `CAP_NET_ADMIN` + transient `CAP_SYS_ADMIN` to join the
   `GENL_MCAST_CAP_SYS_ADMIN`-gated `NET_DM_GRP_ALERT` group). The
   background recv thread drops its own capability set to empty immediately
   on entry before receiving any frames (SEC-PRIV-002).
3. Call `caps::set(None, CapSet::Effective, &{CAP_NET_ADMIN})`,
   `caps::set(None, CapSet::Inheritable, &{})`,
   `caps::set(None, CapSet::Permitted, &{CAP_NET_ADMIN})` via the
   `caps 0.5.6` crate. This is called with `.expect()` — not
   `if let Err(…)`.
4. Start the monoio runtime and HTTP server.

Step 3 uses `.expect()`. The release profile sets `panic = "abort"`, so
any failure in the capability drop sequence terminates the process
immediately with no unwinding; there is no recovery path that leaves the
process alive with elevated capabilities retained. Unprivileged runs
(permitted cap set empty) return `Ok` early and pass through harmlessly.

After the drop, the main process has **only `CAP_NET_ADMIN`** in Permitted
and Effective sets. It cannot modify user namespaces, mount filesystems,
or perform other `CAP_SYS_ADMIN`-gated operations.

**Why `CAP_NET_ADMIN` only (main process after drop):** All six netlink
families (NETLINK_ROUTE, NETLINK_NETFILTER ctnetlink, NETLINK_NETFILTER
nfnetlink, NETLINK_SOCK_DIAG, NETLINK_GENERIC, NETLINK_XFRM) are
accessible with `CAP_NET_ADMIN` and nothing else. `CAP_NET_RAW` (raw
packet injection) is explicitly not required and never requested.

**`CAP_SYS_ADMIN` — transient only (ADR-0026):** The `NET_DM_GRP_ALERT`
generic-netlink multicast group is declared `GENL_MCAST_CAP_SYS_ADMIN`
in `net/core/drop_monitor.c:187`. Joining it requires `CAP_SYS_ADMIN`.
This join is performed on the main thread before the capability drop; the
background recv thread drops all capabilities to empty immediately on
entry. The process never holds `CAP_SYS_ADMIN` in the main thread after
the `drop_caps_to_net_admin()` call completes.

**Kubernetes pod security context:**

```yaml
capabilities:
  drop: ["ALL"]
  add: ["NET_ADMIN"]
allowPrivilegeEscalation: false
runAsNonRoot: true
runAsUser: 65532
readOnlyRootFilesystem: true
seccompProfile:
  type: Localhost
  localhostProfile: deploy/seccomp/nft-exporter.json
```

**Custom seccomp profile** (`deploy/seccomp/nft-exporter.json`) allows
only: `socket(AF_NETLINK)`, `bind`, `recvmsg`, `sendmsg`,
`io_uring_setup`, `io_uring_enter`, `io_uring_register`, `futex`. It
denies `execve`, `ptrace`, `mount`, `bpf`, `clone(CLONE_NEWUSER)`, and
`perf_event_open`. The monoio FusionDriver is io_uring-first (ADR-0023);
`epoll_wait` is not required on the primary I/O path.

**systemd hardening:** `NoNewPrivileges=true`, `ProtectSystem=strict`,
`PrivateTmp=true`, `PrivateDevices=true`, `ProtectKernelTunables=true`,
`ProtectControlGroups=true`,
`RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK`,
`MemoryDenyWriteExecute=true`, `LockPersonality=true`,
`SystemCallFilter=@system-service @network-io`.

---

## No Secrets in the Repository

No secret material — API keys, SSH private keys, tokens, passwords, TLS
certificates, or cloud credentials — may ever be committed to this
repository. This rule is unconditional and applies to all branches,
commits, tags, CI/CD configuration files, and GitHub Actions secrets.

**Credential management:** All secrets used by CI and local development
are stored in the Merkle vault and accessed exclusively via the
`vault_spawn` decode bridge. The SSH private key for integration test
VMs lives at `vault://netlink-exporter/ssh/vm-services-root`. It is
accessed via `vault.write_tempfile` with mode 0600 and revoked via
`vault.revoke_tempfile` in the job `after_script` block, regardless of
outcome. The plaintext private key is never present in CI logs, environment
variables, or conversation context.

If you discover that a secret has been accidentally committed, contact the
maintainers immediately using the vulnerability report process below and
assume the secret is compromised.

---

## Supply-Chain Security

Every release binary is built with SLSA Level 3 provenance in the CI
pipeline (hermetic build, isolated workers, signed attestation). Consumers
can verify the provenance attestation before deployment.

The container image is signed with cosign using OIDC-federated identity
from the CI provider. Image digest pinning in the DaemonSet manifest
prevents silent tag substitution. A syft SPDX-JSON SBOM is attached as an
OCI referrer. Trivy and Grype scan the image on every CI run and block
release on high-severity CVEs.

The runtime image is `gcr.io/distroless/static-debian12:nonroot` referenced
by `sha256` digest. It has no shell, no package manager, and no writable
filesystem.

---

## Reporting a Vulnerability

If you discover a security vulnerability, please **do not** open a public
GitHub issue.

Report vulnerabilities by email to **security@eonf.ltd**. Include:

- A description of the vulnerability and its potential impact.
- Steps to reproduce or a proof-of-concept.
- The version of nft_exporter (binary `--version` output or container image
  digest) affected.

You will receive an acknowledgment within 48 hours. We aim to provide an
initial assessment within 5 business days and a remediation timeline within
14 days of confirmed impact.

We follow responsible disclosure: we will coordinate a fix and a release
before any public disclosure. Credit will be given in the release notes
unless you prefer to remain anonymous.

---

## Out of Scope

The following are outside the scope of the nft_exporter security boundary:

- The Prometheus server, Alertmanager, or Grafana receiving /metrics data.
- The `vm.services` infrastructure used for integration testing.
- The host operating system and Kubernetes control plane.
- Vulnerabilities in upstream Rust crates that do not affect nft_exporter
  in its specific usage pattern (report these to the crate authors and to
  the RustSec advisory database).
