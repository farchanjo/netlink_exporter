//! XFRM `IPsec` collector.
//!
//! Netlink family: `NETLINK_XFRM` (6).
//! Messages used:
//!   - `XFRM_MSG_GETSA` (0x12 = 18) — SA dump → `nft_xfrm_sa_count`
//!   - `XFRM_MSG_GETPOLICY` (0x15 = 21) — Policy dump → `nft_xfrm_sp_count`
//!   - `XFRM_MSG_GETSADINFO` (0x23 = 35) — SAD hash counters + availability probe
//!   - `XFRM_MSG_GETSPDINFO` (0x25 = 37) — SPD hash counters
//!
//! **Message type derivation:** `XFRM_MSG_BASE = 0x10`; subsequent members of
//! the anonymous enum in `include/uapi/linux/xfrm.h` increment by one.  The
//! values used here are the exact enum ordinals from Linux 6.x+:
//!   ```text
//!   NEWSA=0x10, DELSA=0x11, GETSA=0x12, NEWPOLICY=0x13, DELPOLICY=0x14,
//!   GETPOLICY=0x15, … GETSADINFO=0x23, GETSPDINFO=0x25
//!   ```
//!
//! **Probe body:** `XFRM_MSG_GETSADINFO` requires a `u32` flags field in the
//! request body (`xfrm_msg_min[GETSADINFO] = sizeof(u32)`).  Sending an empty
//! body results in `EINVAL`.  We send `0xFFFFFFFF` (all flags set), which is
//! identical to what `iproute2 ip xfrm state count` does.
//!
//! **SADINFO/SPDINFO response format:**
//! The reply message body is: `u32 flags` (echoed) + zero or more NLAs.
//! - SADINFO NLAs: `XFRMA_SAD_CNT` (type 1, u32) and `XFRMA_SAD_HINFO`
//!   (type 2, struct `xfrmu_sadhinfo` = {sadhcnt: u32, sadhmcnt: u32}).
//! - SPDINFO NLAs: `XFRMA_SPD_INFO` (type 1, struct `xfrmu_spdinfo`, ignored),
//!   `XFRMA_SPD_HINFO` (type 2, {spdhcnt: u32, spdhmcnt: u32}).
//!
//! **SA/Policy dump frame layout:**
//! `XFRM_MSG_GETSA` dump responses contain `XFRM_MSG_NEWSA` frames.  Each
//! frame payload starts directly with `struct xfrm_usersa_info` (220 bytes):
//!   - `id.proto` at byte offset 76 (sel=56 + id.daddr=16 + id.spi=4)
//!   - `mode` at byte offset 214 (sel=56 + id=24 + saddr=16 + lft=64 +
//!     curlft=32 + stats=12 + seq=4 + reqid=4 + family=2)
//!
//! `XFRM_MSG_GETPOLICY` dump responses contain `XFRM_MSG_NEWPOLICY` frames
//! with `struct xfrm_userpolicy_info` (164 bytes):
//!
//!   - `dir` at byte offset 160 (sel=56 + lft=64 + curlft=32 + priority=4 + index=4)
//!   - `action` at byte offset 161
//!
//! **ADR-0023 NATIVE-API ONLY:** `/proc/net/xfrm_stat` has been **removed**.
//! The MIB error counters it exposes (`XfrmInError`, `XfrmOutError`, …) have no
//! netlink path — they are only available via procfs.  Per ADR-0023 §6
//! ("NATIVE API ONLY"), procfs reads are forbidden in exporter code.
//! The `nft_xfrm_stat_total` metric family is dropped from this collector.
//!
//! Wire reference: netlink-protocol.md §12.
//! ADR refs: ADR-0011, ADR-0023.
//!
//! ## Metrics produced
//!
//! | Metric | Labels | Type |
//! |--------|--------|------|
//! | `nft_xfrm_sa_count` | `{proto, mode}` | gauge |
//! | `nft_xfrm_sp_count` | `{dir, action}` | gauge |
//! | `nft_xfrm_sad_hash_count` | — | gauge |
//! | `nft_xfrm_sad_hash_max` | — | gauge |
//! | `nft_xfrm_spd_hash_count` | — | gauge |
//! | `nft_xfrm_spd_hash_max` | — | gauge |

use std::collections::BTreeMap;

use nlx_domain::{
    error::DomainError,
    metric::MetricSample,
    model::xfrm::{XfrmPolicy, XfrmSadInfo, XfrmSpdInfo, XfrmState},
};
use nlx_ports::{
    collector::{BoxFuture, Collector},
    driven::NetlinkXfrmPort,
    error::CollectError,
};
use tracing::{debug, warn};

use crate::{
    transport::{MAX_DUMP_RESTARTS, NetlinkError, NetlinkSocket},
    wire::parse_attrs,
};

// ---------------------------------------------------------------------------
// Wire constants (netlink-protocol.md §12)
// ---------------------------------------------------------------------------

/// `NETLINK_XFRM` protocol constant.
const NETLINK_XFRM: i32 = 6;

/// `XFRM_MSG_GETSA` — dump all Security Associations.
///
/// Value = `XFRM_MSG_BASE(0x10)` + 2 ordinals = **0x12** (18).
/// This is the 3rd enum member after NEWSA(0x10) and DELSA(0x11).
const XFRM_MSG_GETSA: u16 = 0x0012;

/// `XFRM_MSG_GETPOLICY` — dump all Security Policies.
///
/// Value = `XFRM_MSG_BASE(0x10)` + 5 ordinals = **0x15** (21).
const XFRM_MSG_GETPOLICY: u16 = 0x0015;

/// `XFRM_MSG_GETSADINFO` — unicast SAD hash info.
///
/// Value = `XFRM_MSG_BASE(0x10)` + 19 ordinals = **0x23** (35).
/// Request body: `u32 flags` (minimum required by `xfrm_msg_min`).
const XFRM_MSG_GETSADINFO: u16 = 0x0023;

/// `XFRM_MSG_GETSPDINFO` — unicast SPD hash info.
///
/// Value = `XFRM_MSG_BASE(0x10)` + 21 ordinals = **0x25** (37).
/// Request body: `u32 flags` (minimum required by `xfrm_msg_min`).
const XFRM_MSG_GETSPDINFO: u16 = 0x0025;

// ---------------------------------------------------------------------------
// Request body: u32 flags sent with GETSADINFO / GETSPDINFO
// ---------------------------------------------------------------------------

/// `flags` value sent in `XFRM_MSG_GETSADINFO` / `XFRM_MSG_GETSPDINFO`.
///
/// The kernel echoes this field back in the reply body prefix.
/// `0xFFFFFFFF` matches `iproute2 ip xfrm state count`.  The exact bit
/// values are not significant for a read-only probe/collector.
const XFRM_INFO_FLAGS: u32 = 0xFFFF_FFFF;

// ---------------------------------------------------------------------------
// xfrm_usersa_info offsets — body size = 220 bytes (§12.3)
// ---------------------------------------------------------------------------

/// Minimum body size of `xfrm_usersa_info`.
const XFRM_SA_INFO_MIN: usize = 220;

/// Byte offset of `id.proto` within `xfrm_usersa_info`.
///
/// Layout: `sel(56) + id.daddr(16) + id.spi(4) = 76`.
/// The `IPsec` protocol (50=ESP, 51=AH, 108=COMP) lives at `xfrm_usersa_info.id.proto`.
const SA_PROTO_OFFSET: usize = 76;

/// Byte offset of `mode` within `xfrm_usersa_info`.
///
/// Layout: `sel(56) + id(24) + saddr(16) + lft(64) + curlft(32) + stats(12) +
/// seq(4) + reqid(4) + family(2) = 214`.
const SA_MODE_OFFSET: usize = 214;

// ---------------------------------------------------------------------------
// xfrm_userpolicy_info offsets — body size = 164 bytes (§12.4)
// ---------------------------------------------------------------------------

/// Minimum body size of `xfrm_userpolicy_info`.
const XFRM_POLICY_INFO_MIN: usize = 164;

/// Byte offset of `dir` within `xfrm_userpolicy_info`.
///
/// Layout: `sel(56) + lft(64) + curlft(32) + priority(4) + index(4) = 160`.
const POLICY_DIR_OFFSET: usize = 160;

/// Byte offset of `action` within `xfrm_userpolicy_info`.
const POLICY_ACTION_OFFSET: usize = 161;

// ---------------------------------------------------------------------------
// SADINFO / SPDINFO NLA type constants
// ---------------------------------------------------------------------------

/// NLA type `XFRMA_SAD_HINFO` (2) — `struct xfrmu_sadhinfo` in SADINFO reply.
///
/// Kernel source: `include/uapi/linux/xfrm.h` line 347.
/// Enum: `XFRMA_SAD_UNSPEC=0, XFRMA_SAD_CNT=1, XFRMA_SAD_HINFO=2`.
/// Layout: `sadhcnt: u32` (current hash bucket count), `sadhmcnt: u32` (max).
const XFRMA_SAD_HINFO: u16 = 2;

/// NLA type `XFRMA_SPD_HINFO` (2) — `struct xfrmu_spdhinfo` in SPDINFO reply.
///
/// Kernel source: `include/uapi/linux/xfrm.h` line 361.
/// Enum: `XFRMA_SPD_UNSPEC=0, XFRMA_SPD_INFO=1, XFRMA_SPD_HINFO=2`.
/// Layout: `spdhcnt: u32` (current hash bucket count), `spdhmcnt: u32` (max).
const XFRMA_SPD_HINFO: u16 = 2;

/// Minimum payload size for `XFRMA_SAD_HINFO` / `XFRMA_SPD_HINFO`.
const XFRM_HASHINFO_MIN: usize = 8; // sadhcnt(4) + sadhmcnt(4)

// ---------------------------------------------------------------------------
// Label helpers (§12.3, §12.4)
// ---------------------------------------------------------------------------

fn proto_label(proto: u8) -> &'static str {
    match proto {
        50 => "esp",
        51 => "ah",
        108 => "comp",
        _ => "other",
    }
}

fn mode_label(mode: u8) -> &'static str {
    match mode {
        0 => "transport",
        1 => "tunnel",
        4 => "beet",
        _ => "other",
    }
}

fn dir_label(dir: u8) -> &'static str {
    // XFRM_POLICY_IN=0, XFRM_POLICY_OUT=1, XFRM_POLICY_FWD=2
    // (include/uapi/linux/xfrm.h:137-139). Note FWD=2, not OUT=2.
    match dir {
        0 => "in",
        1 => "out",
        2 => "fwd",
        _ => "other",
    }
}

fn action_label(action: u8) -> &'static str {
    match action {
        0 => "allow",
        _ => "block",
    }
}

// ---------------------------------------------------------------------------
// Collector
// ---------------------------------------------------------------------------

/// Adapter implementing [`NetlinkXfrmPort`] and [`Collector`] for XFRM
/// `IPsec` Security Associations and Policies.
pub struct XfrmCollector;

impl NetlinkXfrmPort for XfrmCollector {
    async fn dump_sa(&self) -> Result<Vec<XfrmState>, DomainError> {
        // The Collector::collect path is the sole consumer; port method
        // returns empty for completeness.
        Ok(Vec::new())
    }

    async fn dump_policies(&self) -> Result<Vec<XfrmPolicy>, DomainError> {
        Ok(Vec::new())
    }

    async fn get_sad_info(&self) -> Result<XfrmSadInfo, DomainError> {
        Ok(XfrmSadInfo {
            hash_count: 0,
            hash_max: 0,
        })
    }

    async fn get_spd_info(&self) -> Result<XfrmSpdInfo, DomainError> {
        Ok(XfrmSpdInfo {
            hash_count: 0,
            hash_max: 0,
        })
    }
}

impl Collector for XfrmCollector {
    fn name(&self) -> &'static str {
        "xfrm-ipsec"
    }

    fn collect(&self) -> BoxFuture<'_, Result<Vec<MetricSample>, CollectError>> {
        Box::pin(async move { collect_xfrm().await })
    }

    fn probe_available(&self) -> BoxFuture<'_, bool> {
        Box::pin(async move { probe_xfrm_available().await })
    }
}

// ---------------------------------------------------------------------------
// Availability probe (§12.2)
// ---------------------------------------------------------------------------

/// Probe whether the XFRM subsystem is available.
///
/// Opens `NETLINK_XFRM` and issues `XFRM_MSG_GETSADINFO` with the required
/// `u32 flags` body (kernel minimum = `sizeof(u32)`; empty body yields `EINVAL`).
/// Returns `false` when:
/// - The socket cannot be opened (`EPROTONOSUPPORT` → modules not loaded).
/// - The kernel replies with `EPERM` (errno 1) or `ENOENT` (errno 2) →
///   subsystem absent or policy-restricted.
/// - Any other kernel error → treat as unavailable.
///
/// A successful reply (any payload) means `xfrm_user` + `xfrm_algo` are loaded.
async fn probe_xfrm_available() -> bool {
    let mut sock = match NetlinkSocket::open(NETLINK_XFRM) {
        Ok(s) => s,
        Err(e) => {
            debug!(error = %e, "xfrm probe: socket open failed (xfrm_user not loaded?)");
            return false;
        }
    };

    // XFRM_MSG_GETSADINFO requires a u32 body (xfrm_msg_min = sizeof(u32)).
    // Sending an empty body yields EINVAL; send 0xFFFFFFFF matching iproute2.
    let flags_body = XFRM_INFO_FLAGS.to_ne_bytes();

    match sock
        .request_single(XFRM_MSG_GETSADINFO, 0, &flags_body)
        .await
    {
        Ok(_) => true,
        Err(NetlinkError::KernelError { errno: 1 | 2 }) => {
            // EPERM or ENOENT → subsystem absent or restricted.
            debug!("xfrm probe: GETSADINFO rejected (EPERM/ENOENT)");
            false
        }
        Err(e) => {
            debug!(error = %e, "xfrm probe: GETSADINFO failed");
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Core collection logic
// ---------------------------------------------------------------------------

#[allow(
    clippy::too_many_lines,
    reason = "cohesive parser/builder; splitting would obscure the wire layout"
)]
#[allow(
    clippy::cast_precision_loss,
    reason = "metric gauge/counter values are f64; precision loss on large counters is inherent to Prometheus exposition"
)]
async fn collect_xfrm() -> Result<Vec<MetricSample>, CollectError> {
    let mut sock =
        NetlinkSocket::open(NETLINK_XFRM).map_err(|e| CollectError::Io(e.to_string()))?;

    let mut samples = Vec::new();

    // ── XFRM_MSG_GETSA dump ─────────────────────────────────────────────────
    {
        let frames = dump_with_restarts(&mut sock, XFRM_MSG_GETSA).await?;

        // Accumulate counts by (proto_label, mode_label).
        let mut sa_map: BTreeMap<(&'static str, &'static str), u64> = BTreeMap::new();

        for frame in &frames {
            if frame.len() < XFRM_SA_INFO_MIN {
                // ERR-004: short frame — warn and skip this frame so that
                // the remaining dump entries and the subsequent GETSADINFO /
                // GETSPDINFO unicast queries are still executed.
                warn!(
                    len = frame.len(),
                    min = XFRM_SA_INFO_MIN,
                    "XFRM_MSG_GETSA frame too short; skipping"
                );
                continue;
            }
            // id.proto: sel(56) + id.daddr(16) + id.spi(4) = offset 76
            let proto = frame[SA_PROTO_OFFSET];
            // mode: sel(56) + id(24) + saddr(16) + lft(64) + curlft(32) + stats(12)
            //       + seq(4) + reqid(4) + family(2) = offset 214
            let mode = frame[SA_MODE_OFFSET];
            *sa_map
                .entry((proto_label(proto), mode_label(mode)))
                .or_insert(0) += 1;
        }

        for ((proto, mode), count) in sa_map {
            let mut lc = BTreeMap::new();
            lc.insert("proto".into(), proto.into());
            lc.insert("mode".into(), mode.into());
            samples.push(MetricSample::gauge(
                "nft_xfrm_sa_count",
                "Number of XFRM Security Associations by protocol and mode",
                lc,
                count as f64,
            ));
        }
    }

    // ── XFRM_MSG_GETPOLICY dump ─────────────────────────────────────────────
    {
        let frames = dump_with_restarts(&mut sock, XFRM_MSG_GETPOLICY).await?;

        // Accumulate counts by (dir_label, action_label).
        let mut policy_map: BTreeMap<(&'static str, &'static str), u64> = BTreeMap::new();

        for frame in &frames {
            if frame.len() < XFRM_POLICY_INFO_MIN {
                // ERR-004: short frame — warn and skip this frame so that
                // the remaining dump entries and the subsequent GETSADINFO /
                // GETSPDINFO unicast queries are still executed.
                warn!(
                    len = frame.len(),
                    min = XFRM_POLICY_INFO_MIN,
                    "XFRM_MSG_GETPOLICY frame too short; skipping"
                );
                continue;
            }
            // dir: sel(56) + lft(64) + curlft(32) + priority(4) + index(4) = offset 160
            let dir = frame[POLICY_DIR_OFFSET];
            // action: offset 161
            let action = frame[POLICY_ACTION_OFFSET];
            *policy_map
                .entry((dir_label(dir), action_label(action)))
                .or_insert(0) += 1;
        }

        for ((dir, action), count) in policy_map {
            let mut lc = BTreeMap::new();
            lc.insert("dir".into(), dir.into());
            lc.insert("action".into(), action.into());
            samples.push(MetricSample::gauge(
                "nft_xfrm_sp_count",
                "Number of XFRM Security Policies by direction and action",
                lc,
                count as f64,
            ));
        }
    }

    // ── XFRM_MSG_GETSADINFO (unicast) ───────────────────────────────────────
    //
    // Request body: u32 flags (required by xfrm_msg_min).
    // Reply body: [u32 flags (echoed)][NLA: XFRMA_SAD_CNT u32][NLA: XFRMA_SAD_HINFO {sadhcnt,sadhmcnt}]
    let flags_body = XFRM_INFO_FLAGS.to_ne_bytes();
    match sock
        .request_single(XFRM_MSG_GETSADINFO, 0, &flags_body)
        .await
    {
        Ok(Some(payload)) => {
            // Skip the 4-byte echoed flags prefix; NLAs start at byte 4.
            if let Some(nla_buf) = payload.get(4..) {
                let (mut sadhcnt, mut sad_hash_max) = (0u32, 0u32);
                for attr in parse_attrs(nla_buf) {
                    // XFRMA_SAD_CNT (1): u32 total SA count — informational,
                    // not exposed as a metric (we count from the dump directly).
                    if attr.ty == XFRMA_SAD_HINFO && attr.payload.len() >= XFRM_HASHINFO_MIN {
                        // struct xfrmu_sadhinfo: sadhcnt(u32) + sadhmcnt(u32)
                        if let (Some(hcnt_bytes), Some(hmcnt_bytes)) =
                            (attr.payload.get(0..4), attr.payload.get(4..8))
                        {
                            sadhcnt = u32::from_ne_bytes(hcnt_bytes.try_into().unwrap_or([0u8; 4]));
                            sad_hash_max =
                                u32::from_ne_bytes(hmcnt_bytes.try_into().unwrap_or([0u8; 4]));
                        }
                    }
                }
                samples.push(MetricSample::gauge(
                    "nft_xfrm_sad_hash_count",
                    "Current SAD hash entry count",
                    BTreeMap::new(),
                    f64::from(sadhcnt),
                ));
                samples.push(MetricSample::gauge(
                    "nft_xfrm_sad_hash_max",
                    "SAD hash bucket capacity",
                    BTreeMap::new(),
                    f64::from(sad_hash_max),
                ));
            }
        }
        Ok(None) => {}
        Err(NetlinkError::KernelError { errno: 1 | 2 }) => {
            // EPERM / ENOENT: subsystem absent; silently skip hash metrics.
            debug!("XFRM_MSG_GETSADINFO not available (EPERM/ENOENT)");
        }
        Err(e) => return Err(CollectError::Io(e.to_string())),
    }

    // ── XFRM_MSG_GETSPDINFO (unicast) ───────────────────────────────────────
    //
    // Request body: u32 flags (required by xfrm_msg_min).
    // Reply body: [u32 flags (echoed)][NLA: XFRMA_SPD_INFO struct][NLA: XFRMA_SPD_HINFO {spdhcnt,spdhmcnt}]
    match sock
        .request_single(XFRM_MSG_GETSPDINFO, 0, &flags_body)
        .await
    {
        Ok(Some(payload)) => {
            // Skip the 4-byte echoed flags prefix; NLAs start at byte 4.
            if let Some(nla_buf) = payload.get(4..) {
                let (mut spdhcnt, mut spd_hash_max) = (0u32, 0u32);
                for attr in parse_attrs(nla_buf) {
                    // XFRMA_SPD_INFO (1): xfrmu_spdinfo — not exposed as metrics.
                    if attr.ty == XFRMA_SPD_HINFO && attr.payload.len() >= XFRM_HASHINFO_MIN {
                        // struct xfrmu_spdhinfo: spdhcnt(u32) + spdhmcnt(u32)
                        if let (Some(hcnt_bytes), Some(hmcnt_bytes)) =
                            (attr.payload.get(0..4), attr.payload.get(4..8))
                        {
                            spdhcnt = u32::from_ne_bytes(hcnt_bytes.try_into().unwrap_or([0u8; 4]));
                            spd_hash_max =
                                u32::from_ne_bytes(hmcnt_bytes.try_into().unwrap_or([0u8; 4]));
                        }
                    }
                }
                samples.push(MetricSample::gauge(
                    "nft_xfrm_spd_hash_count",
                    "Current SPD hash entry count",
                    BTreeMap::new(),
                    f64::from(spdhcnt),
                ));
                samples.push(MetricSample::gauge(
                    "nft_xfrm_spd_hash_max",
                    "SPD hash bucket capacity",
                    BTreeMap::new(),
                    f64::from(spd_hash_max),
                ));
            }
        }
        Ok(None) => {}
        Err(NetlinkError::KernelError { errno: 1 | 2 }) => {
            debug!("XFRM_MSG_GETSPDINFO not available (EPERM/ENOENT)");
        }
        Err(e) => return Err(CollectError::Io(e.to_string())),
    }

    // nft_xfrm_stat_total omitted — no netlink path for MIB counters (ADR-0023).

    Ok(samples)
}

// ---------------------------------------------------------------------------
// Helper: dump with restart loop
// ---------------------------------------------------------------------------

/// Issue a `DUMP`-flagged request and retry on `NLM_F_DUMP_INTR` up to
/// [`MAX_DUMP_RESTARTS`] times.
///
/// The dump request body is empty: `XFRM_MSG_GETSA` and `XFRM_MSG_GETPOLICY`
/// accept an empty body on the dump path (`nlmsg_parse_deprecated(cb->nlh, 0,
/// ...)` with minimum=0).  Optional NLA filters (`XFRMA_ADDRESS_FILTER`,
/// `XFRMA_PROTO`) are not used here as we want all SAs/policies.
async fn dump_with_restarts(
    sock: &mut NetlinkSocket,
    msg_type: u16,
) -> Result<Vec<Vec<u8>>, CollectError> {
    for attempt in 0..MAX_DUMP_RESTARTS {
        match sock.dump(msg_type, 0, &[]).await {
            Ok(frames) => return Ok(frames),
            Err(NetlinkError::DumpIntr) => {
                debug!(attempt, msg_type, "XFRM dump interrupted; retrying");
            }
            Err(NetlinkError::RecvBufOverflow) => return Err(CollectError::RecvBufOverflow),
            Err(e) => return Err(CollectError::Io(e.to_string())),
        }
    }
    Err(CollectError::DumpIntr)
}

// /proc/net/xfrm_stat parser removed per ADR-0023 §NATIVE API ONLY.

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::cast_possible_truncation,
        clippy::similar_names,
        reason = "test"
    )]

    // parse_attrs is a private `use` in the parent module; access it directly
    // from the crate to avoid relying on parent-module private use visibility.
    use crate::wire::parse_attrs;

    use super::{
        XFRM_HASHINFO_MIN, XFRMA_SAD_HINFO, action_label, dir_label, mode_label, proto_label,
    };

    // ── TC-008: label helpers ────────────────────────────────────────────────

    #[test]
    fn proto_label_known_protocols() {
        assert_eq!(proto_label(50), "esp");
        assert_eq!(proto_label(51), "ah");
        assert_eq!(proto_label(108), "comp");
    }

    #[test]
    fn proto_label_unknown_falls_back() {
        assert_eq!(proto_label(0), "other");
        assert_eq!(proto_label(255), "other");
        assert_eq!(proto_label(17), "other"); // UDP is not an IPsec proto
    }

    #[test]
    fn mode_label_known_modes() {
        assert_eq!(mode_label(0), "transport");
        assert_eq!(mode_label(1), "tunnel");
        assert_eq!(mode_label(4), "beet");
    }

    #[test]
    fn mode_label_unknown_falls_back() {
        assert_eq!(mode_label(2), "other");
        assert_eq!(mode_label(3), "other");
        assert_eq!(mode_label(255), "other");
    }

    #[test]
    fn dir_label_xfrm_policy_directions() {
        // XFRM_POLICY_IN=0, XFRM_POLICY_OUT=1, XFRM_POLICY_FWD=2
        // include/uapi/linux/xfrm.h:137-139
        assert_eq!(dir_label(0), "in");
        assert_eq!(dir_label(1), "out");
        assert_eq!(dir_label(2), "fwd");
    }

    #[test]
    fn dir_label_unknown_falls_back() {
        assert_eq!(dir_label(3), "other");
        assert_eq!(dir_label(255), "other");
    }

    #[test]
    fn action_label_allow_and_block() {
        assert_eq!(action_label(0), "allow");
        assert_eq!(action_label(1), "block");
        assert_eq!(action_label(2), "block");
        assert_eq!(action_label(255), "block");
    }

    // ── M-30: synthetic GETSADINFO reply parse test ──────────────────────────
    //
    // Validates that XFRMA_SAD_HINFO is correctly recognised at NLA type 2
    // (not 3) and that sadhcnt / sadhmcnt are decoded from the right offsets.
    //
    // Wire layout of a synthetic GETSADINFO unicast reply payload (after the
    // netlink message header):
    //
    //   [0..4]   u32 flags (echoed) = 0xFFFF_FFFF (native-endian)
    //   [4..]    NLA sequence:
    //     NLA 1: XFRMA_SAD_CNT (type=1)  — 4-byte header + 4-byte u32 payload
    //       nla_len=8, nla_type=1, payload=42 (u32 native-endian)
    //     NLA 2: XFRMA_SAD_HINFO (type=2) — 4-byte header + 8-byte struct payload
    //       nla_len=12, nla_type=2, payload={sadhcnt=7, sadhmcnt=64} (u32 ne each)
    //
    // NLA header format (include/uapi/linux/netlink.h):
    //   u16 nla_len  (LE) — total length including 4-byte header
    //   u16 nla_type (LE) — attribute type; bits 14-15 reserved, masked by NlaIter
    //
    // Total payload: 4 (flags) + 8 (NLA1) + 12 (NLA2) = 24 bytes.
    // NLA1 stride = align4(8) = 8; NLA2 stride = align4(12) = 12.

    #[test]
    fn parse_getsadinfo_reply_hinfo_type2() {
        // flags: 0xFFFF_FFFF in native-endian
        let flags = 0xFFFF_FFFFu32.to_ne_bytes();

        // NLA 1: XFRMA_SAD_CNT (type=1), payload=42u32
        let nla1_len: u16 = 8; // 4 hdr + 4 payload
        let nla1_type: u16 = 1; // XFRMA_SAD_CNT
        let nla1_payload = 42u32.to_ne_bytes();

        // NLA 2: XFRMA_SAD_HINFO (type=2), payload={sadhcnt=7, sadhmcnt=64}
        let nla2_len: u16 = 12; // 4 hdr + 8 payload
        let nla2_type: u16 = 2; // XFRMA_SAD_HINFO — must be 2, not 3
        let sadhcnt = 7u32.to_ne_bytes();
        let sadhmcnt = 64u32.to_ne_bytes();

        let mut buf: Vec<u8> = Vec::with_capacity(24);
        buf.extend_from_slice(&flags);
        buf.extend_from_slice(&nla1_len.to_ne_bytes());
        buf.extend_from_slice(&nla1_type.to_ne_bytes());
        buf.extend_from_slice(&nla1_payload);
        buf.extend_from_slice(&nla2_len.to_ne_bytes());
        buf.extend_from_slice(&nla2_type.to_ne_bytes());
        buf.extend_from_slice(&sadhcnt);
        buf.extend_from_slice(&sadhmcnt);

        assert_eq!(buf.len(), 24);

        // Simulate the parse path in collect_xfrm: skip 4-byte flags prefix.
        let nla_buf = buf.get(4..).expect("nla_buf slice");
        let (mut parsed_sadhcnt, mut parsed_sadhmcnt) = (0u32, 0u32);
        for attr in parse_attrs(nla_buf) {
            if attr.ty == XFRMA_SAD_HINFO && attr.payload.len() >= XFRM_HASHINFO_MIN {
                if let (Some(hcnt), Some(hmcnt)) = (attr.payload.get(0..4), attr.payload.get(4..8))
                {
                    parsed_sadhcnt = u32::from_ne_bytes(hcnt.try_into().expect("hcnt 4 bytes"));
                    parsed_sadhmcnt = u32::from_ne_bytes(hmcnt.try_into().expect("hmcnt 4 bytes"));
                }
            }
        }

        // XFRMA_SAD_HINFO at type=2 must be matched (not skipped as type=3).
        assert_eq!(
            parsed_sadhcnt, 7,
            "sadhcnt must be parsed when XFRMA_SAD_HINFO=2"
        );
        assert_eq!(
            parsed_sadhmcnt, 64,
            "sadhmcnt must be parsed when XFRMA_SAD_HINFO=2"
        );
    }

    /// Regression guard: if `XFRMA_SAD_HINFO` were incorrectly 3, the NLA at
    /// type=2 would not match and both counts would stay at 0.
    #[test]
    fn parse_getsadinfo_reply_wrong_type3_yields_zero() {
        let flags = 0u32.to_ne_bytes();
        // NLA with type=3 (the old wrong value)
        let nla_len: u16 = 12;
        let wrong_type: u16 = 3;
        let sadhcnt = 99u32.to_ne_bytes();
        let sadhmcnt = 128u32.to_ne_bytes();

        let mut buf: Vec<u8> = Vec::with_capacity(16);
        buf.extend_from_slice(&flags);
        buf.extend_from_slice(&nla_len.to_ne_bytes());
        buf.extend_from_slice(&wrong_type.to_ne_bytes());
        buf.extend_from_slice(&sadhcnt);
        buf.extend_from_slice(&sadhmcnt);

        let nla_buf = buf.get(4..).expect("nla_buf");
        let (mut parsed_sadhcnt, mut parsed_sadhmcnt) = (0u32, 0u32);
        for attr in parse_attrs(nla_buf) {
            // XFRMA_SAD_HINFO is 2 — type=3 must NOT match.
            if attr.ty == XFRMA_SAD_HINFO && attr.payload.len() >= XFRM_HASHINFO_MIN {
                if let (Some(hcnt), Some(hmcnt)) = (attr.payload.get(0..4), attr.payload.get(4..8))
                {
                    parsed_sadhcnt = u32::from_ne_bytes(hcnt.try_into().expect("hcnt"));
                    parsed_sadhmcnt = u32::from_ne_bytes(hmcnt.try_into().expect("hmcnt"));
                }
            }
        }
        assert_eq!(parsed_sadhcnt, 0, "type=3 must not match XFRMA_SAD_HINFO=2");
        assert_eq!(
            parsed_sadhmcnt, 0,
            "type=3 must not match XFRMA_SAD_HINFO=2"
        );
    }
}
