//! Devlink genetlink collector.
//!
//! Netlink family: `NETLINK_GENERIC` (16), family name `"devlink"`.
//! Messages used: `DEVLINK_CMD_GET` (1), `DEVLINK_CMD_PORT_GET` (5),
//!   `DEVLINK_CMD_HEALTH_REPORTER_GET` (52).
//! ADR refs: ADR-0011, ADR-0014, netlink-protocol.md §15.
//!
//! ## Runtime gate
//!
//! `probe_available()` calls `resolve_genl_family("devlink")`. `Ok(None)` means
//! `CONFIG_NET_DEVLINK` is not loaded; `collect()` returns `Ok(vec![])`.
//!
//! ## Health reporter GET
//!
//! Global `NLM_F_DUMP` without device filter returns `EINVAL` on kernel < 5.18
//! (G-29).  We issue one filtered dump per device obtained from `DEVLINK_CMD_GET`.

use std::collections::BTreeMap;

use nlx_domain::{
    error::DomainError,
    metric::MetricSample,
    model::devlink::{DevlinkDevice, DevlinkHealthReporter, DevlinkPort},
};
use nlx_ports::{
    collector::{BoxFuture, Collector},
    driven::NetlinkDevlinkPort,
    error::CollectError,
};
use tracing::debug;

use crate::{
    transport::NetlinkSocket,
    wire::{NLA_HDRLEN, align4, parse_attrs, read_u8, read_u32, read_u64},
};

const NETLINK_GENERIC: i32 = 16;

// devlink commands (version=1 for all, §15.2).
// Ordinals from enum devlink_command in
// include/uapi/linux/devlink.h (linux-6.17.13):
//   DEVLINK_CMD_GET                 = 1  (line 26)
//   DEVLINK_CMD_PORT_GET            = 5  (line 31 — 5th non-UNSPEC member)
//   DEVLINK_CMD_HEALTH_REPORTER_GET = 52 (verified via the running kernel's
//     own <linux/devlink.h> preprocessor expansion AND a live `devlink health
//     show` strace, which sends genl cmd 0x34 = 52. An earlier "fix" to 54 was
//     a miscount that produced EOPNOTSUPP (errno 95) on every health dump.)
const DEVLINK_CMD_GET: u8 = 1;
const DEVLINK_CMD_PORT_GET: u8 = 5;
const DEVLINK_CMD_HEALTH_REPORTER_GET: u8 = 52;
const DEVLINK_GENL_VERSION: u8 = 1;

// devlink attribute types (§15.3).
// Ordinals from enum devlink_attr in
// include/uapi/linux/devlink.h (linux-6.17.13):
//   DEVLINK_ATTR_BUS_NAME                     = 1   (line 413)
//   DEVLINK_ATTR_DEV_NAME                     = 2   (line 414)
//   DEVLINK_ATTR_PORT_INDEX                   = 3   (line 416)
//   DEVLINK_ATTR_HEALTH_REPORTER             = 114  (line 544)
//   DEVLINK_ATTR_HEALTH_REPORTER_NAME        = 115  (line 545)
//   DEVLINK_ATTR_HEALTH_REPORTER_STATE       = 116  (line 546)
//   DEVLINK_ATTR_HEALTH_REPORTER_ERR_COUNT   = 117  (line 547)
//   DEVLINK_ATTR_HEALTH_REPORTER_RECOVER_COUNT = 118 (line 548)
const DEVLINK_ATTR_BUS_NAME: u16 = 1;
const DEVLINK_ATTR_DEV_NAME: u16 = 2;
const DEVLINK_ATTR_PORT_INDEX: u16 = 3;
const DEVLINK_ATTR_HEALTH_REPORTER: u16 = 114;
const DEVLINK_ATTR_HEALTH_REPORTER_NAME: u16 = 115;
const DEVLINK_ATTR_HEALTH_REPORTER_STATE: u16 = 116;
const DEVLINK_ATTR_HEALTH_REPORTER_ERR_COUNT: u16 = 117;
const DEVLINK_ATTR_HEALTH_REPORTER_RECOVER_COUNT: u16 = 118;

/// Adapter implementing [`NetlinkDevlinkPort`] and [`Collector`] for devlink.
pub struct DevlinkCollector;

impl NetlinkDevlinkPort for DevlinkCollector {
    async fn dump_devices(&self) -> Result<Vec<DevlinkDevice>, DomainError> {
        let mut sock = NetlinkSocket::open(NETLINK_GENERIC)
            .map_err(|e| DomainError::Collector(e.to_string()))?;
        let Some(fid) = resolve(&mut sock).await? else {
            return Ok(vec![]);
        };
        dump_devices(&mut sock, fid).await
    }

    async fn dump_ports(&self) -> Result<Vec<DevlinkPort>, DomainError> {
        let mut sock = NetlinkSocket::open(NETLINK_GENERIC)
            .map_err(|e| DomainError::Collector(e.to_string()))?;
        let Some(fid) = resolve(&mut sock).await? else {
            return Ok(vec![]);
        };
        dump_ports(&mut sock, fid).await
    }

    async fn dump_health_reporters(&self) -> Result<Vec<DevlinkHealthReporter>, DomainError> {
        let mut sock = NetlinkSocket::open(NETLINK_GENERIC)
            .map_err(|e| DomainError::Collector(e.to_string()))?;
        let Some(fid) = resolve(&mut sock).await? else {
            return Ok(vec![]);
        };
        let devices = dump_devices(&mut sock, fid).await?;
        let mut all = Vec::new();
        for dev in &devices {
            let reporters = dump_health_reporters_for(&mut sock, fid, dev).await?;
            all.extend(reporters);
        }
        Ok(all)
    }
}

impl Collector for DevlinkCollector {
    fn name(&self) -> &'static str {
        "devlink"
    }

    #[allow(
        clippy::cast_precision_loss,
        reason = "metric gauge/counter values are f64; precision loss on large counters is inherent to Prometheus exposition"
    )]
    fn collect(&self) -> BoxFuture<'_, Result<Vec<MetricSample>, CollectError>> {
        Box::pin(async move {
            let mut sock = NetlinkSocket::open(NETLINK_GENERIC)
                .map_err(|e| CollectError::Io(e.to_string()))?;

            let family_id = sock
                .resolve_genl_family("devlink")
                .await
                .map_err(|e| CollectError::Io(e.to_string()))?;

            let Some(family_id) = family_id else {
                debug!("devlink genetlink family not loaded; skipping collect");
                return Ok(vec![]);
            };

            let devices = dump_devices(&mut sock, family_id)
                .await
                .map_err(|e| CollectError::Io(e.to_string()))?;

            let ports = dump_ports(&mut sock, family_id)
                .await
                .map_err(|e| CollectError::Io(e.to_string()))?;

            let mut out = Vec::new();

            // nft_devlink_devices gauge.
            {
                let mut labels = BTreeMap::new();
                labels.insert("count".to_owned(), devices.len().to_string());
                out.push(MetricSample::gauge(
                    "nft_devlink_devices",
                    "Number of devlink devices.",
                    BTreeMap::new(),
                    devices.len() as f64,
                ));
            }

            // nft_devlink_ports gauge per device.
            let mut port_counts: BTreeMap<(String, String), u64> = BTreeMap::new();
            for p in &ports {
                *port_counts
                    .entry((p.bus_name.clone(), p.dev_name.clone()))
                    .or_insert(0) += 1;
            }
            for ((bus, dev), count) in &port_counts {
                let mut labels = BTreeMap::new();
                labels.insert("bus".to_owned(), bus.clone());
                labels.insert("device".to_owned(), dev.clone());
                out.push(MetricSample::gauge(
                    "nft_devlink_ports",
                    "Number of devlink ports per device.",
                    labels,
                    *count as f64,
                ));
            }

            // Health reporters.
            for dev in &devices {
                let reporters = dump_health_reporters_for(&mut sock, family_id, dev)
                    .await
                    .map_err(|e| CollectError::Io(e.to_string()))?;
                for r in &reporters {
                    let mut labels = BTreeMap::new();
                    labels.insert("bus".to_owned(), r.bus_name.clone());
                    labels.insert("device".to_owned(), r.dev_name.clone());
                    labels.insert("reporter".to_owned(), r.name.clone());
                    // Consistent label keys across every series of these metrics:
                    // port="" for device-level reporters, the index for port-level.
                    labels.insert(
                        "port".to_owned(),
                        r.port.map_or_else(String::new, |p| p.to_string()),
                    );

                    out.push(MetricSample::gauge(
                        "nft_devlink_health_reporter_state",
                        "Devlink health reporter state (0=healthy).",
                        labels.clone(),
                        f64::from(r.state),
                    ));
                    out.push(MetricSample::counter(
                        "nft_devlink_health_reporter_error_total",
                        "Devlink health reporter cumulative error count.",
                        labels.clone(),
                        r.err_count,
                    ));
                    out.push(MetricSample::counter(
                        "nft_devlink_health_reporter_recover_total",
                        "Devlink health reporter cumulative recovery count.",
                        labels,
                        r.recover_count,
                    ));
                }
            }

            Ok(out)
        })
    }

    fn probe_available(&self) -> BoxFuture<'_, bool> {
        Box::pin(async move {
            let Ok(mut sock) = NetlinkSocket::open(NETLINK_GENERIC) else {
                return false;
            };
            matches!(sock.resolve_genl_family("devlink").await, Ok(Some(_)))
        })
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

async fn resolve(sock: &mut NetlinkSocket) -> Result<Option<u16>, DomainError> {
    sock.resolve_genl_family("devlink")
        .await
        .map_err(|e| DomainError::Collector(e.to_string()))
}

async fn dump_devices(
    sock: &mut NetlinkSocket,
    family_id: u16,
) -> Result<Vec<DevlinkDevice>, DomainError> {
    let payload = genl_payload(DEVLINK_CMD_GET);
    let frames = do_dump(sock, family_id, &payload).await?;
    let mut result = Vec::with_capacity(frames.len());
    for frame in &frames {
        if frame.len() < 4 {
            continue;
        }
        if let Some(dev) = parse_device(&frame[4..]) {
            result.push(dev);
        }
    }
    Ok(result)
}

async fn dump_ports(
    sock: &mut NetlinkSocket,
    family_id: u16,
) -> Result<Vec<DevlinkPort>, DomainError> {
    let payload = genl_payload(DEVLINK_CMD_PORT_GET);
    let frames = do_dump(sock, family_id, &payload).await?;
    let mut result = Vec::with_capacity(frames.len());
    for frame in &frames {
        if frame.len() < 4 {
            continue;
        }
        if let Some(port) = parse_port(&frame[4..]) {
            result.push(port);
        }
    }
    Ok(result)
}

async fn dump_health_reporters_for(
    sock: &mut NetlinkSocket,
    family_id: u16,
    dev: &DevlinkDevice,
) -> Result<Vec<DevlinkHealthReporter>, DomainError> {
    // Per-device filtered dump (G-29: global dump returns EINVAL on kernel < 5.18).
    let payload = health_reporter_payload(dev);
    // Match on the structured NetlinkError *before* converting to DomainError so
    // that errno=22 (EINVAL) is recognised exactly — string matching on
    // "errno=22" is ambiguous (also matches "errno=220", "errno=221", …).
    let frames = match do_dump_raw(sock, family_id, &payload).await {
        Ok(f) => f,
        Err(crate::transport::NetlinkError::KernelError { errno: 22 }) => {
            // EINVAL — kernel < 5.18 without device-filter support; skip.
            return Ok(vec![]);
        }
        Err(e) => return Err(DomainError::Collector(e.to_string())),
    };

    let mut result = Vec::with_capacity(frames.len());
    for frame in &frames {
        if frame.len() < 4 {
            continue;
        }
        if let Some(r) = parse_health_reporter(&frame[4..], dev) {
            result.push(r);
        }
    }
    Ok(result)
}

/// Inner dump loop returning the raw [`crate::transport::NetlinkError`] so
/// callers can match on structured variants (e.g. `KernelError { errno }`)
/// before converting to a domain error.
async fn do_dump_raw(
    sock: &mut NetlinkSocket,
    family_id: u16,
    payload: &[u8],
) -> Result<Vec<Vec<u8>>, crate::transport::NetlinkError> {
    let mut restarts = 0u32;
    loop {
        match sock.dump(family_id, 0, payload).await {
            Ok(frames) => return Ok(frames),
            Err(crate::transport::NetlinkError::DumpIntr) => {
                restarts += 1;
                if restarts >= crate::transport::MAX_DUMP_RESTARTS {
                    return Err(crate::transport::NetlinkError::Parse(
                        "devlink dump interrupted".into(),
                    ));
                }
            }
            Err(e) => return Err(e),
        }
    }
}

async fn do_dump(
    sock: &mut NetlinkSocket,
    family_id: u16,
    payload: &[u8],
) -> Result<Vec<Vec<u8>>, DomainError> {
    do_dump_raw(sock, family_id, payload).await.map_err(|e| {
        // When the restart limit is exhausted, do_dump_raw returns
        // Parse("devlink dump interrupted"). Convert all transport errors
        // uniformly to DomainError::Collector via Display.
        DomainError::Collector(e.to_string())
    })
}

// ---------------------------------------------------------------------------
// Wire builders
// ---------------------------------------------------------------------------

fn genl_payload(cmd: u8) -> Vec<u8> {
    vec![cmd, DEVLINK_GENL_VERSION, 0u8, 0u8]
}

#[allow(
    clippy::cast_possible_truncation,
    reason = "nlattr length fits u16 by construction; kernel rejects NLA payloads larger than 65535 bytes"
)]
fn push_nla(buf: &mut Vec<u8>, ty: u16, payload: &[u8]) {
    let nla_len = (NLA_HDRLEN + payload.len()) as u16;
    buf.extend_from_slice(&nla_len.to_ne_bytes());
    buf.extend_from_slice(&ty.to_ne_bytes());
    buf.extend_from_slice(payload);
    let pad = align4(NLA_HDRLEN + payload.len()) - (NLA_HDRLEN + payload.len());
    buf.extend(std::iter::repeat_n(0u8, pad));
}

fn push_nla_str(buf: &mut Vec<u8>, ty: u16, s: &str) {
    let mut bytes: Vec<u8> = s.bytes().collect();
    bytes.push(0); // NUL terminator
    push_nla(buf, ty, &bytes);
}

fn health_reporter_payload(dev: &DevlinkDevice) -> Vec<u8> {
    let mut buf = genl_payload(DEVLINK_CMD_HEALTH_REPORTER_GET);
    push_nla_str(&mut buf, DEVLINK_ATTR_BUS_NAME, &dev.bus_name);
    push_nla_str(&mut buf, DEVLINK_ATTR_DEV_NAME, &dev.dev_name);
    buf
}

// ---------------------------------------------------------------------------
// Parsers
// ---------------------------------------------------------------------------

fn parse_nul_string(payload: &[u8]) -> String {
    let end = payload
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(payload.len());
    String::from_utf8_lossy(&payload[..end]).into_owned()
}

fn parse_device(attrs_buf: &[u8]) -> Option<DevlinkDevice> {
    let mut bus_name = String::new();
    let mut dev_name = String::new();
    for attr in parse_attrs(attrs_buf) {
        match attr.ty {
            DEVLINK_ATTR_BUS_NAME => bus_name = parse_nul_string(attr.payload),
            DEVLINK_ATTR_DEV_NAME => dev_name = parse_nul_string(attr.payload),
            _ => {}
        }
    }
    if bus_name.is_empty() && dev_name.is_empty() {
        return None;
    }
    Some(DevlinkDevice { bus_name, dev_name })
}

fn parse_port(attrs_buf: &[u8]) -> Option<DevlinkPort> {
    let mut bus_name = String::new();
    let mut dev_name = String::new();
    let mut port_index: u32 = 0;
    for attr in parse_attrs(attrs_buf) {
        match attr.ty {
            DEVLINK_ATTR_BUS_NAME => bus_name = parse_nul_string(attr.payload),
            DEVLINK_ATTR_DEV_NAME => dev_name = parse_nul_string(attr.payload),
            DEVLINK_ATTR_PORT_INDEX => port_index = read_u32(attr.payload).unwrap_or(0),
            _ => {}
        }
    }
    if bus_name.is_empty() && dev_name.is_empty() {
        return None;
    }
    Some(DevlinkPort {
        bus_name,
        dev_name,
        port_index,
    })
}

fn parse_health_reporter(attrs_buf: &[u8], dev: &DevlinkDevice) -> Option<DevlinkHealthReporter> {
    // The reporter attributes may be flat or nested in DEVLINK_ATTR_HEALTH_REPORTER (114).
    let mut name = String::new();
    let mut state: u8 = 0;
    let mut err_count: u64 = 0;
    let mut recover_count: u64 = 0;
    // Port-level reporters (e.g. `vnic` on each port) carry DEVLINK_ATTR_PORT_INDEX
    // at the top level; absent for device-level reporters. Without this the
    // per-port reporters would all collapse to one duplicate series.
    let mut port: Option<u32> = None;

    let parse_inner = |attrs: &[u8],
                       name: &mut String,
                       state: &mut u8,
                       err_count: &mut u64,
                       recover_count: &mut u64| {
        for a in parse_attrs(attrs) {
            match a.ty {
                DEVLINK_ATTR_HEALTH_REPORTER_NAME => *name = parse_nul_string(a.payload),
                DEVLINK_ATTR_HEALTH_REPORTER_STATE => {
                    *state = read_u8(a.payload).unwrap_or(0);
                }
                DEVLINK_ATTR_HEALTH_REPORTER_ERR_COUNT => {
                    *err_count = read_u64(a.payload).unwrap_or(0);
                }
                DEVLINK_ATTR_HEALTH_REPORTER_RECOVER_COUNT => {
                    *recover_count = read_u64(a.payload).unwrap_or(0);
                }
                _ => {}
            }
        }
    };

    for attr in parse_attrs(attrs_buf) {
        if attr.ty == DEVLINK_ATTR_PORT_INDEX {
            port = read_u32(attr.payload);
        } else if attr.ty == DEVLINK_ATTR_HEALTH_REPORTER {
            // Nested container (G-31: bit 15 already stripped by NlaIter).
            parse_inner(
                attr.payload,
                &mut name,
                &mut state,
                &mut err_count,
                &mut recover_count,
            );
        } else {
            // Some kernels emit attrs flat.
            match attr.ty {
                DEVLINK_ATTR_HEALTH_REPORTER_NAME => name = parse_nul_string(attr.payload),
                DEVLINK_ATTR_HEALTH_REPORTER_STATE => {
                    state = read_u8(attr.payload).unwrap_or(0);
                }
                DEVLINK_ATTR_HEALTH_REPORTER_ERR_COUNT => {
                    err_count = read_u64(attr.payload).unwrap_or(0);
                }
                DEVLINK_ATTR_HEALTH_REPORTER_RECOVER_COUNT => {
                    recover_count = read_u64(attr.payload).unwrap_or(0);
                }
                _ => {}
            }
        }
    }

    if name.is_empty() {
        return None;
    }
    Some(DevlinkHealthReporter {
        bus_name: dev.bus_name.clone(),
        dev_name: dev.dev_name.clone(),
        name,
        state,
        err_count,
        recover_count,
        port,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::cast_possible_truncation,
        reason = "test"
    )]

    use super::*;

    // -----------------------------------------------------------------------
    // NLA frame builder (mirrors wire format used by the kernel):
    //   u16 LE nla_len (includes 4-byte header)
    //   u16 LE nla_type
    //   [payload bytes]
    //   [0..3 pad bytes to align4]
    // -----------------------------------------------------------------------

    fn nla_str(ty: u16, s: &str) -> Vec<u8> {
        let mut payload: Vec<u8> = s.bytes().collect();
        payload.push(0); // NUL terminator
        nla_bytes(ty, &payload)
    }

    fn nla_u8(ty: u16, v: u8) -> Vec<u8> {
        nla_bytes(ty, &[v])
    }

    fn nla_u32_ne(ty: u16, v: u32) -> Vec<u8> {
        nla_bytes(ty, &v.to_ne_bytes())
    }

    fn nla_u64_ne(ty: u16, v: u64) -> Vec<u8> {
        nla_bytes(ty, &v.to_ne_bytes())
    }

    fn nla_bytes(ty: u16, payload: &[u8]) -> Vec<u8> {
        let nla_len = (4 + payload.len()) as u16;
        let padded = ((nla_len as usize) + 3) & !3;
        let mut buf = Vec::with_capacity(padded);
        buf.extend_from_slice(&nla_len.to_ne_bytes());
        buf.extend_from_slice(&ty.to_ne_bytes());
        buf.extend_from_slice(payload);
        buf.resize(padded, 0u8);
        buf
    }

    // -----------------------------------------------------------------------
    // parse_device
    // -----------------------------------------------------------------------

    /// A minimal attrs buffer with `BUS_NAME=1` and `DEV_NAME=2` populated.
    /// Verifies the strings parse correctly and the correct constant values
    /// (`BUS_NAME=1`, `DEV_NAME=2`) are used.
    #[test]
    fn parse_device_basic() {
        let mut buf = Vec::new();
        buf.extend(nla_str(DEVLINK_ATTR_BUS_NAME, "pci")); // type 1
        buf.extend(nla_str(DEVLINK_ATTR_DEV_NAME, "0000:01:00.0")); // type 2

        let dev = parse_device(&buf).unwrap();
        assert_eq!(dev.bus_name, "pci");
        assert_eq!(dev.dev_name, "0000:01:00.0");
    }

    /// Unknown attribute types must be ignored; the parser must still succeed.
    #[test]
    fn parse_device_skips_unknown_attrs() {
        let mut buf = Vec::new();
        buf.extend(nla_str(DEVLINK_ATTR_BUS_NAME, "platform"));
        buf.extend(nla_u32_ne(99, 0xDEAD_BEEF)); // unknown — must be ignored
        buf.extend(nla_str(DEVLINK_ATTR_DEV_NAME, "arm-mlxbf2"));

        let dev = parse_device(&buf).unwrap();
        assert_eq!(dev.bus_name, "platform");
        assert_eq!(dev.dev_name, "arm-mlxbf2");
    }

    /// Empty attrs buffer (all-zero device) must return None.
    #[test]
    fn parse_device_empty_returns_none() {
        assert!(parse_device(&[]).is_none());
    }

    // -----------------------------------------------------------------------
    // parse_port
    // -----------------------------------------------------------------------

    /// `PORT_INDEX` is attribute type 3; verify constant and u32 native-endian
    /// parsing.
    #[test]
    fn parse_port_basic() {
        let mut buf = Vec::new();
        buf.extend(nla_str(DEVLINK_ATTR_BUS_NAME, "pci")); // type 1
        buf.extend(nla_str(DEVLINK_ATTR_DEV_NAME, "0000:03:00.0")); // type 2
        buf.extend(nla_u32_ne(DEVLINK_ATTR_PORT_INDEX, 7u32)); // type 3

        let port = parse_port(&buf).unwrap();
        assert_eq!(port.bus_name, "pci");
        assert_eq!(port.dev_name, "0000:03:00.0");
        assert_eq!(port.port_index, 7);
    }

    /// Missing `PORT_INDEX` should default to 0, not fail.
    #[test]
    fn parse_port_missing_index_defaults_zero() {
        let mut buf = Vec::new();
        buf.extend(nla_str(DEVLINK_ATTR_BUS_NAME, "pci"));
        buf.extend(nla_str(DEVLINK_ATTR_DEV_NAME, "0000:00:00.1"));

        let port = parse_port(&buf).unwrap();
        assert_eq!(port.port_index, 0);
    }

    /// Empty attrs buffer must return None (`bus_name` and `dev_name` both empty).
    #[test]
    fn parse_port_empty_returns_none() {
        assert!(parse_port(&[]).is_none());
    }

    // -----------------------------------------------------------------------
    // parse_health_reporter
    // -----------------------------------------------------------------------

    /// Flat (non-nested) layout: health reporter attrs at the top level.
    /// Verifies the corrected constants:
    ///   `DEVLINK_ATTR_HEALTH_REPORTER_NAME`         = 115
    ///   `DEVLINK_ATTR_HEALTH_REPORTER_STATE`        = 116
    ///   `DEVLINK_ATTR_HEALTH_REPORTER_ERR_COUNT`    = 117
    ///   `DEVLINK_ATTR_HEALTH_REPORTER_RECOVER_COUNT` = 118
    #[test]
    fn parse_health_reporter_flat_layout() {
        let dev = DevlinkDevice {
            bus_name: "pci".to_owned(),
            dev_name: "0000:05:00.0".to_owned(),
        };

        let mut buf = Vec::new();
        buf.extend(nla_str(DEVLINK_ATTR_HEALTH_REPORTER_NAME, "fw")); // type 115
        buf.extend(nla_u8(DEVLINK_ATTR_HEALTH_REPORTER_STATE, 1u8)); // type 116, state=1 (unhealthy)
        buf.extend(nla_u64_ne(DEVLINK_ATTR_HEALTH_REPORTER_ERR_COUNT, 42u64)); // type 117
        buf.extend(nla_u64_ne(DEVLINK_ATTR_HEALTH_REPORTER_RECOVER_COUNT, 3u64)); // type 118

        let r = parse_health_reporter(&buf, &dev).unwrap();
        assert_eq!(r.bus_name, "pci");
        assert_eq!(r.dev_name, "0000:05:00.0");
        assert_eq!(r.name, "fw");
        assert_eq!(r.state, 1);
        assert_eq!(r.err_count, 42);
        assert_eq!(r.recover_count, 3);
    }

    /// Nested layout: attrs wrapped in `DEVLINK_ATTR_HEALTH_REPORTER` (type 114).
    /// This is the standard kernel layout for `DEVLINK_CMD_HEALTH_REPORTER_GET` replies.
    #[test]
    fn parse_health_reporter_nested_layout() {
        let dev = DevlinkDevice {
            bus_name: "pci".to_owned(),
            dev_name: "0000:07:00.0".to_owned(),
        };

        // Build inner NLA payload (the reporter sub-attrs).
        let mut inner = Vec::new();
        inner.extend(nla_str(DEVLINK_ATTR_HEALTH_REPORTER_NAME, "tx")); // type 115
        inner.extend(nla_u8(DEVLINK_ATTR_HEALTH_REPORTER_STATE, 0u8)); // type 116, healthy
        inner.extend(nla_u64_ne(DEVLINK_ATTR_HEALTH_REPORTER_ERR_COUNT, 0u64)); // type 117
        inner.extend(nla_u64_ne(DEVLINK_ATTR_HEALTH_REPORTER_RECOVER_COUNT, 0u64)); // type 118

        // Wrap in the outer DEVLINK_ATTR_HEALTH_REPORTER container (type 114).
        let buf = nla_bytes(DEVLINK_ATTR_HEALTH_REPORTER, &inner);

        let r = parse_health_reporter(&buf, &dev).unwrap();
        assert_eq!(r.name, "tx");
        assert_eq!(r.state, 0);
        assert_eq!(r.err_count, 0);
        assert_eq!(r.recover_count, 0);
    }

    /// Device-level reporter (no `PORT_INDEX`) parses with `port == None`.
    #[test]
    fn parse_health_reporter_device_level_has_no_port() {
        let dev = DevlinkDevice {
            bus_name: "pci".to_owned(),
            dev_name: "0000:01:00.0".to_owned(),
        };
        let mut buf = Vec::new();
        buf.extend(nla_str(DEVLINK_ATTR_HEALTH_REPORTER_NAME, "fw"));
        buf.extend(nla_u8(DEVLINK_ATTR_HEALTH_REPORTER_STATE, 0));
        let r = parse_health_reporter(&buf, &dev).unwrap();
        assert_eq!(r.port, None, "device-level reporter must have no port");
    }

    /// Port-level reporter carries `DEVLINK_ATTR_PORT_INDEX` (3) → `port == Some(n)`.
    /// This is what keeps per-port `vnic` reporters from collapsing into one
    /// duplicate time series.
    #[test]
    fn parse_health_reporter_port_level_keeps_port_index() {
        let dev = DevlinkDevice {
            bus_name: "pci".to_owned(),
            dev_name: "0000:01:00.0".to_owned(),
        };
        let mut buf = Vec::new();
        buf.extend(nla_u32_ne(DEVLINK_ATTR_PORT_INDEX, 5)); // type 3
        buf.extend(nla_str(DEVLINK_ATTR_HEALTH_REPORTER_NAME, "vnic"));
        buf.extend(nla_u8(DEVLINK_ATTR_HEALTH_REPORTER_STATE, 0));
        let r = parse_health_reporter(&buf, &dev).unwrap();
        assert_eq!(r.name, "vnic");
        assert_eq!(
            r.port,
            Some(5),
            "port-level reporter must keep port index 5"
        );
    }

    /// Missing name attribute must yield None (name is required sentinel).
    #[test]
    fn parse_health_reporter_no_name_returns_none() {
        let dev = DevlinkDevice {
            bus_name: "pci".to_owned(),
            dev_name: "0000:09:00.0".to_owned(),
        };
        // Only state, no name.
        let buf = nla_u8(DEVLINK_ATTR_HEALTH_REPORTER_STATE, 0);
        assert!(parse_health_reporter(&buf, &dev).is_none());
    }

    // -----------------------------------------------------------------------
    // Constant-value assertions (TC-007 sanity: compile-time guard)
    // -----------------------------------------------------------------------

    /// Verify every corrected constant matches the kernel devlink.h ordinal.
    ///
    /// If these are ever changed back to the wrong values, this test fails.
    #[test]
    fn constant_values_match_kernel_header() {
        // enum devlink_command — linux-6.17.13 include/uapi/linux/devlink.h
        assert_eq!(DEVLINK_CMD_GET, 1u8, "DEVLINK_CMD_GET must be 1");
        assert_eq!(
            DEVLINK_CMD_PORT_GET, 5u8,
            "DEVLINK_CMD_PORT_GET must be 5 (line 31)"
        );
        // WC-009: HEALTH_REPORTER_GET = 52 (kernel <linux/devlink.h> + live
        // `devlink health show` strace both confirm genl cmd 0x34 = 52).
        assert_eq!(
            DEVLINK_CMD_HEALTH_REPORTER_GET, 52u8,
            "DEVLINK_CMD_HEALTH_REPORTER_GET must be 52"
        );

        // enum devlink_attr — linux-6.17.13 include/uapi/linux/devlink.h
        assert_eq!(
            DEVLINK_ATTR_BUS_NAME, 1u16,
            "DEVLINK_ATTR_BUS_NAME must be 1"
        );
        assert_eq!(
            DEVLINK_ATTR_DEV_NAME, 2u16,
            "DEVLINK_ATTR_DEV_NAME must be 2"
        );
        assert_eq!(
            DEVLINK_ATTR_PORT_INDEX, 3u16,
            "DEVLINK_ATTR_PORT_INDEX must be 3"
        );
        assert_eq!(
            DEVLINK_ATTR_HEALTH_REPORTER, 114u16,
            "DEVLINK_ATTR_HEALTH_REPORTER must be 114 (line 544)"
        );
        assert_eq!(
            DEVLINK_ATTR_HEALTH_REPORTER_NAME, 115u16,
            "DEVLINK_ATTR_HEALTH_REPORTER_NAME must be 115 (line 545)"
        );
        assert_eq!(
            DEVLINK_ATTR_HEALTH_REPORTER_STATE, 116u16,
            "DEVLINK_ATTR_HEALTH_REPORTER_STATE must be 116 (line 546)"
        );
        assert_eq!(
            DEVLINK_ATTR_HEALTH_REPORTER_ERR_COUNT, 117u16,
            "DEVLINK_ATTR_HEALTH_REPORTER_ERR_COUNT must be 117 (line 547)"
        );
        assert_eq!(
            DEVLINK_ATTR_HEALTH_REPORTER_RECOVER_COUNT, 118u16,
            "DEVLINK_ATTR_HEALTH_REPORTER_RECOVER_COUNT must be 118 (line 548)"
        );
    }
}
