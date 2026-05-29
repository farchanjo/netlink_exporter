//! Devlink genetlink read models.

use serde::{Deserialize, Serialize};

/// Devlink device (`DEVLINK_CMD_GET`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevlinkDevice {
    /// Bus name (e.g. `"pci"`).
    pub bus_name: String,
    /// Device name (e.g. `"0000:01:00.0"`).
    pub dev_name: String,
}

/// Devlink port (`DEVLINK_CMD_PORT_GET`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevlinkPort {
    /// Bus name.
    pub bus_name: String,
    /// Device name.
    pub dev_name: String,
    /// Port index (`DEVLINK_ATTR_PORT_INDEX` u32).
    pub port_index: u32,
}

/// Devlink health reporter (`DEVLINK_CMD_HEALTH_REPORTER_GET`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevlinkHealthReporter {
    /// Bus name.
    pub bus_name: String,
    /// Device name.
    pub dev_name: String,
    /// Reporter name (e.g. `"fw_fatal"`, `"rx"`, `"tx"`).
    pub name: String,
    /// Current state u8 (0=healthy, 1=error, …).
    pub state: u8,
    /// Cumulative error count (`DEVLINK_ATTR_HEALTH_REPORTER_ERR_COUNT`).
    pub err_count: u64,
    /// Cumulative recovery count (`DEVLINK_ATTR_HEALTH_REPORTER_RECOVER_COUNT`).
    pub recover_count: u64,
    /// Port index when this is a port-level reporter (`DEVLINK_ATTR_PORT_INDEX`),
    /// or `None` for a device-level reporter. Distinguishes otherwise-identical
    /// per-port reporters (e.g. `vnic`) that share bus/device/name.
    pub port: Option<u32>,
}
