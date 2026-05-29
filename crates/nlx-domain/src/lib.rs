//! # nlx-domain — Pure Domain Model
//!
//! **Hexagonal role: DOMAIN CORE.**
//!
//! This crate contains all domain concepts that exist independently of any
//! infrastructure. It MUST NOT import runtime crates (`tokio`, `mio`), network
//! I/O crates (`rustix`, `linux-raw-sys`), HTTP frameworks (`axum`), or metrics
//! registries (`prometheus-client`).
//!
//! Enforcement: `hexagonal.rego` (Rego deny), `cargo deny` bans, and ADR-0002
//! / ADR-0014.
//!
//! ## Module layout
//!
//! ```text
//! nlx-domain
//! ├── error        — domain error enum
//! ├── lifecycle    — ScrapeLifecycle state machine
//! ├── metric       — MetricSample value object
//! └── model        — ReadModels and value objects per netlink subsystem
//!     ├── link     — IfInfoMsg / LinkReadModel
//!     ├── address  — IfAddrMsg / AddressReadModel
//!     ├── route    — RtMsg / RouteReadModel
//!     ├── neighbor — NdMsg / NeighborReadModel
//!     ├── tc       — TcReadModel (qdisc, class, filter stats)
//!     ├── conntrack— ConntrackFlow, ConntrackStat
//!     ├── nftables — NftChain, NftRule, NftCounter
//!     ├── sockdiag — SockDiagEntry
//!     ├── ethtool  — EthtoolStats
//!     ├── ipvs     — IpvsService, IpvsDestination
//!     ├── wireguard— WireguardPeer
//!     ├── devlink  — DevlinkPort, DevlinkParam
//!     ├── drop_monitor — DropEvent
//!     └── xfrm     — XfrmState, XfrmPolicy
//! ```

#![deny(missing_docs)]

pub mod error;
pub mod lifecycle;
pub mod metric;
pub mod model;
