//! XFRM IPsec collector.
//!
//! Netlink family: `NETLINK_XFRM` (6).
//! Messages used:
//!   - `XFRM_MSG_GETSA` (0x0007) — SA dump → `nft_xfrm_sa_count`
//!   - `XFRM_MSG_GETPOLICY` (0x0009) — Policy dump → `nft_xfrm_sp_count`
//!   - `XFRM_MSG_GETSADINFO` (0x0011) — SAD hash counters + availability probe
//!   - `XFRM_MSG_GETSPDINFO` (0x0012) — SPD hash counters
//!
//! **ADR-0023 NATIVE-API ONLY:** `/proc/net/xfrm_stat` has been **removed**.
//! The MIB error counters it exposes (XfrmInError, XfrmOutError, …) have no
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
use tracing::debug;

use crate::transport::{MAX_DUMP_RESTARTS, NetlinkError, NetlinkSocket};

// ---------------------------------------------------------------------------
// Wire constants (netlink-protocol.md §12)
// ---------------------------------------------------------------------------

/// `NETLINK_XFRM` protocol constant.
const NETLINK_XFRM: i32 = 6;

/// `XFRM_MSG_GETSA` — dump all Security Associations (§12.3).
const XFRM_MSG_GETSA: u16 = 0x0007;

/// `XFRM_MSG_GETPOLICY` — dump all Security Policies (§12.4).
const XFRM_MSG_GETPOLICY: u16 = 0x0009;

/// `XFRM_MSG_GETSADINFO` — unicast SAD hash info (§12.5).
const XFRM_MSG_GETSADINFO: u16 = 0x0011;

/// `XFRM_MSG_GETSPDINFO` — unicast SPD hash info (§12.6).
const XFRM_MSG_GETSPDINFO: u16 = 0x0012;

// ---------------------------------------------------------------------------
// xfrm_usersa_info offsets (§12.3) — body size = 220 bytes
// ---------------------------------------------------------------------------

/// Minimum body size of `xfrm_usersa_info` — all supported kernel versions.
const XFRM_SA_INFO_MIN: usize = 220;

/// Byte offset of `id.proto` within `xfrm_usersa_info` (§12.3).
const SA_PROTO_OFFSET: usize = 40;

/// Byte offset of `mode` within `xfrm_usersa_info` (§12.3).
const SA_MODE_OFFSET: usize = 184;

// ---------------------------------------------------------------------------
// xfrm_userpolicy_info offsets (§12.4) — body size = 164 bytes
// ---------------------------------------------------------------------------

/// Minimum body size of `xfrm_userpolicy_info`.
const XFRM_POLICY_INFO_MIN: usize = 164;

/// Byte offset of `dir` within `xfrm_userpolicy_info` (§12.4).
const POLICY_DIR_OFFSET: usize = 160;

/// Byte offset of `action` within `xfrm_userpolicy_info` (§12.4).
const POLICY_ACTION_OFFSET: usize = 161;

// ---------------------------------------------------------------------------
// xfrm_sadinfo / xfrm_spdinfo offsets (§12.5, §12.6)
// ---------------------------------------------------------------------------

/// Minimum body size of `xfrm_sadinfo` (8 bytes: sadhcnt u32 + sadhmcnt u32).
const XFRM_SADINFO_MIN: usize = 8;

/// Minimum body size of `xfrm_spdinfo` (8 bytes: spdhcnt u32 + spdhmcnt u32).
const XFRM_SPDINFO_MIN: usize = 8;

// /proc/net/xfrm_stat REMOVED — ADR-0023 §NATIVE API ONLY.
// The MIB error counters (XfrmInError, XfrmOutError, etc.) have no netlink
// path; procfs reads are forbidden in exporter code per ADR-0023.

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
        0 => "tunnel",
        1 => "transport",
        4 => "beet",
        _ => "other",
    }
}

fn dir_label(dir: u8) -> &'static str {
    match dir {
        0 => "in",
        1 => "fwd",
        2 => "out",
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
/// IPsec Security Associations and Policies.
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
    fn name(&self) -> &str {
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
/// Opens `NETLINK_XFRM` and issues `XFRM_MSG_GETSADINFO`.  Returns `false`
/// when the socket cannot be opened (`EPROTONOSUPPORT`) or when the kernel
/// replies with `EPERM` or `ENOENT`.
async fn probe_xfrm_available() -> bool {
    let mut sock = match NetlinkSocket::open(NETLINK_XFRM) {
        Ok(s) => s,
        Err(e) => {
            debug!(error = %e, "xfrm probe: socket open failed");
            return false;
        }
    };

    match sock.request_single(XFRM_MSG_GETSADINFO, 0, &[]).await {
        Ok(_) => true,
        Err(NetlinkError::KernelError { errno }) if errno == 1 || errno == 2 => {
            // errno=1 EPERM, errno=2 ENOENT → subsystem absent or restricted.
            debug!(errno, "xfrm probe: GETSADINFO rejected");
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
                return Err(CollectError::Parse(format!(
                    "XFRM_MSG_GETSA frame too short: {} < {XFRM_SA_INFO_MIN}",
                    frame.len()
                )));
            }
            let proto = frame[SA_PROTO_OFFSET];
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
                return Err(CollectError::Parse(format!(
                    "XFRM_MSG_GETPOLICY frame too short: {} < {XFRM_POLICY_INFO_MIN}",
                    frame.len()
                )));
            }
            let dir = frame[POLICY_DIR_OFFSET];
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
    match sock.request_single(XFRM_MSG_GETSADINFO, 0, &[]).await {
        Ok(Some(payload)) => {
            if payload.len() >= XFRM_SADINFO_MIN {
                // sadhcnt @ 0 (u32 LE native), sadhmcnt @ 4 (u32 LE native).
                let sadhcnt = u32::from_ne_bytes(
                    payload[0..4]
                        .try_into()
                        .map_err(|_| CollectError::Parse("sadinfo sadhcnt slice error".into()))?,
                );
                let sadhmcnt = u32::from_ne_bytes(
                    payload[4..8]
                        .try_into()
                        .map_err(|_| CollectError::Parse("sadinfo sadhmcnt slice error".into()))?,
                );

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
                    f64::from(sadhmcnt),
                ));
            }
        }
        Ok(None) => {}
        Err(NetlinkError::KernelError { errno }) if errno == 1 || errno == 2 => {
            // EPERM / ENOENT: subsystem absent; silently skip hash metrics.
            debug!(errno, "XFRM_MSG_GETSADINFO not available");
        }
        Err(e) => return Err(CollectError::Io(e.to_string())),
    }

    // ── XFRM_MSG_GETSPDINFO (unicast) ───────────────────────────────────────
    match sock.request_single(XFRM_MSG_GETSPDINFO, 0, &[]).await {
        Ok(Some(payload)) => {
            if payload.len() >= XFRM_SPDINFO_MIN {
                // spdhcnt @ 0 (u32 LE native), spdhmcnt @ 4 (u32 LE native).
                let spdhcnt = u32::from_ne_bytes(
                    payload[0..4]
                        .try_into()
                        .map_err(|_| CollectError::Parse("spdinfo spdhcnt slice error".into()))?,
                );
                let spdhmcnt = u32::from_ne_bytes(
                    payload[4..8]
                        .try_into()
                        .map_err(|_| CollectError::Parse("spdinfo spdhmcnt slice error".into()))?,
                );

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
                    f64::from(spdhmcnt),
                ));
            }
        }
        Ok(None) => {}
        Err(NetlinkError::KernelError { errno }) if errno == 1 || errno == 2 => {
            debug!(errno, "XFRM_MSG_GETSPDINFO not available");
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
async fn dump_with_restarts(
    sock: &mut NetlinkSocket,
    msg_type: u16,
) -> Result<Vec<Vec<u8>>, CollectError> {
    for attempt in 0..MAX_DUMP_RESTARTS {
        match sock.dump(msg_type, 0, &[]).await {
            Ok(frames) => return Ok(frames),
            Err(NetlinkError::DumpIntr) => {
                debug!(attempt, msg_type, "XFRM dump interrupted; retrying");
                continue;
            }
            Err(NetlinkError::RecvBufOverflow) => return Err(CollectError::RecvBufOverflow),
            Err(e) => return Err(CollectError::Io(e.to_string())),
        }
    }
    Err(CollectError::DumpIntr)
}

// /proc/net/xfrm_stat parser removed per ADR-0023 §NATIVE API ONLY.
