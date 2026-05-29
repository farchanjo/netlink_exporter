//! Per-subsystem collector modules.
//!
//! Each module implements:
//! 1. The corresponding driven port trait from `nlx-ports::driven`.
//! 2. The [`nlx_ports::collector::Collector`] strategy trait.
//!
//! All collectors use [`crate::transport::NetlinkSocket`] for wire I/O.

pub mod conntrack;
pub mod conntrack_expect;
pub mod devlink;
pub mod drop_monitor;
pub mod ethtool;
pub mod ipvs;
pub mod nftables;
pub mod rt;
pub mod rt_extended;
pub mod sockdiag;
pub mod tc;
pub mod wireguard;
pub mod xfrm;
