//! Interface address read model.

use serde::{Deserialize, Serialize};

/// Read model for one IP address assignment (`RTM_NEWADDR`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AddressReadModel {
    /// Interface index.
    pub if_index: u32,
    /// Interface name.
    pub if_name: String,
    /// Address family: `"inet"` or `"inet6"`.
    pub family: String,
    /// Presentation-form address string (IPv4 or IPv6).
    pub address: String,
    /// Prefix length in bits.
    pub prefix_len: u8,
    /// Scope string (`"global"`, `"link"`, `"host"`, `"site"`).
    pub scope: String,
    /// `IFA_F_PERMANENT` flag.
    pub permanent: bool,
    /// `IFA_F_DEPRECATED` flag.
    pub deprecated: bool,
    /// `IFA_F_TENTATIVE` flag.
    pub tentative: bool,
}
