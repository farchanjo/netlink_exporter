//! Devlink genetlink collector.
//!
//! Netlink family: `NETLINK_GENERIC` (16), family name `"devlink"`.
//! Messages used: `DEVLINK_CMD_GET` (1), `DEVLINK_CMD_PORT_GET` (7),
//!   `DEVLINK_CMD_HEALTH_REPORTER_GET` (66).
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
const DEVLINK_CMD_GET: u8 = 1;
const DEVLINK_CMD_PORT_GET: u8 = 7;
const DEVLINK_CMD_HEALTH_REPORTER_GET: u8 = 66;
const DEVLINK_GENL_VERSION: u8 = 1;

// devlink attribute types (§15.3).
const DEVLINK_ATTR_BUS_NAME: u16 = 1;
const DEVLINK_ATTR_DEV_NAME: u16 = 2;
const DEVLINK_ATTR_PORT_INDEX: u16 = 3;
const DEVLINK_ATTR_HEALTH_REPORTER: u16 = 57;
const DEVLINK_ATTR_HEALTH_REPORTER_NAME: u16 = 58;
const DEVLINK_ATTR_HEALTH_REPORTER_STATE: u16 = 59;
const DEVLINK_ATTR_HEALTH_REPORTER_ERR_COUNT: u16 = 60;
const DEVLINK_ATTR_HEALTH_REPORTER_RECOVER_COUNT: u16 = 61;

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
    fn name(&self) -> &str {
        "devlink"
    }

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
    let frames = match do_dump(sock, family_id, &payload).await {
        Ok(f) => f,
        Err(DomainError::Collector(ref msg)) if msg.contains("errno=22") => {
            // EINVAL — kernel < 5.18 without device filter support; skip.
            return Ok(vec![]);
        }
        Err(e) => return Err(e),
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

async fn do_dump(
    sock: &mut NetlinkSocket,
    family_id: u16,
    payload: &[u8],
) -> Result<Vec<Vec<u8>>, DomainError> {
    let mut restarts = 0u32;
    loop {
        match sock.dump(family_id, 0, payload).await {
            Ok(frames) => return Ok(frames),
            Err(crate::transport::NetlinkError::DumpIntr) => {
                restarts += 1;
                if restarts >= crate::transport::MAX_DUMP_RESTARTS {
                    return Err(DomainError::Collector("devlink dump interrupted".into()));
                }
            }
            Err(e) => return Err(DomainError::Collector(e.to_string())),
        }
    }
}

// ---------------------------------------------------------------------------
// Wire builders
// ---------------------------------------------------------------------------

fn genl_payload(cmd: u8) -> Vec<u8> {
    vec![cmd, DEVLINK_GENL_VERSION, 0u8, 0u8]
}

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
    // The reporter attributes may be flat or nested in DEVLINK_ATTR_HEALTH_REPORTER (57).
    let mut name = String::new();
    let mut state: u8 = 0;
    let mut err_count: u64 = 0;
    let mut recover_count: u64 = 0;

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
        if attr.ty == DEVLINK_ATTR_HEALTH_REPORTER {
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
    })
}
