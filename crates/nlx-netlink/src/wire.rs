//! Netlink wire-format helpers.
//!
//! Provides zero-allocation iterators and typed readers for the kernel
//! `nlattr` TLV wire format (ADR-0011, netlink-protocol.md §3.2).
//!
//! All multi-byte scalars in netlink headers are **native-endian** (LE on
//! x86-64 / aarch64).  Individual attribute payloads may be big-endian when
//! `NLA_F_NET_BYTEORDER` (bit 14) is set; the `read_u*_be` helpers handle
//! those.

/// `(len + 3) & !3` — round up to 4-byte boundary.
///
/// Mirrors the kernel `NLMSG_ALIGN` and `NLA_ALIGN` macros.
#[inline]
#[must_use]
pub const fn align4(len: usize) -> usize {
    (len.wrapping_add(3)) & !3
}

// ---------------------------------------------------------------------------
// NLA constants
// ---------------------------------------------------------------------------

/// 4-byte nlattr header: `u16 nla_len` + `u16 nla_type`.
pub const NLA_HDRLEN: usize = 4;

/// Mask to strip `NLA_F_NESTED` (bit 15) and `NLA_F_NET_BYTEORDER` (bit 14)
/// from `nla_type`, leaving the 13-bit effective type.
///
/// Per netlink-protocol.md §3.2:
/// > Strip flag bits before matching: `effective_type = nla_type & NLA_TYPE_MASK`.
pub const NLA_TYPE_MASK: u16 = 0x1FFF;

// ---------------------------------------------------------------------------
// nlattr iterator
// ---------------------------------------------------------------------------

/// A single parsed netlink attribute (TLV).
///
/// The `ty` field is already masked — flags stripped.
/// The `payload` slice points into the original buffer with zero copy.
#[derive(Debug, Clone, Copy)]
pub struct Nla<'a> {
    /// Effective attribute type (flags already stripped).
    pub ty: u16,
    /// Raw payload bytes (does **not** include the 4-byte nlattr header).
    pub payload: &'a [u8],
}

/// Iterator over a flat sequence of `nlattr` TLVs.
///
/// Constructed by [`parse_attrs`].  Each call to `next` yields one [`Nla`]
/// and advances past the NLA-aligned stride.
///
/// # Contract
///
/// Stops silently when:
/// - fewer than `NLA_HDRLEN` bytes remain, or
/// - `nla_len` is less than `NLA_HDRLEN` (malformed), or
/// - `nla_len` extends beyond the remaining buffer.
#[derive(Debug)]
pub struct NlaIter<'a> {
    buf: &'a [u8],
}

impl<'a> Iterator for NlaIter<'a> {
    type Item = Nla<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.len() < NLA_HDRLEN {
            return None;
        }

        // nla_len: u16 LE at offset 0 (total length including 4-byte header)
        let nla_len = u16::from_ne_bytes([self.buf[0], self.buf[1]]) as usize;
        if nla_len < NLA_HDRLEN || nla_len > self.buf.len() {
            return None;
        }

        // nla_type: u16 LE at offset 2 — strip NLA_F_NESTED (bit 15) and
        // NLA_F_NET_BYTEORDER (bit 14) before matching.
        let raw_type = u16::from_ne_bytes([self.buf[2], self.buf[3]]);
        let ty = raw_type & NLA_TYPE_MASK;

        // Payload starts immediately after the 4-byte header.
        let payload = &self.buf[NLA_HDRLEN..nla_len];

        // Advance by the NLA-aligned stride.
        let stride = align4(nla_len);
        self.buf = if stride >= self.buf.len() {
            &[]
        } else {
            &self.buf[stride..]
        };

        Some(Nla { ty, payload })
    }
}

/// Parse a flat `nlattr` sequence from `buf` and return an iterator of
/// `(effective_type, payload)` pairs.
///
/// `buf` should start at the first attribute (i.e. after any fixed-size
/// header such as `nlmsghdr` + subsystem header).
///
/// ```rust
/// use nlx_netlink::wire::parse_attrs;
///
/// // Build a minimal hand-crafted nlattr buffer: type=3, payload=0xABu8
/// let mut buf = vec![
///     0x05, 0x00, // nla_len = 5 (4 hdr + 1 payload)
///     0x03, 0x00, // nla_type = 3
///     0xAB,       // payload byte
///     0x00, 0x00, 0x00, // NLA_ALIGN padding
/// ];
/// let attrs: Vec<_> = parse_attrs(&buf).collect();
/// assert_eq!(attrs.len(), 1);
/// assert_eq!(attrs[0].ty, 3);
/// assert_eq!(attrs[0].payload, &[0xAB]);
/// ```
#[must_use]
pub fn parse_attrs(buf: &[u8]) -> NlaIter<'_> {
    NlaIter { buf }
}

/// Parse a nested `nlattr` container whose payload is itself an `nlattr`
/// sequence.
///
/// This is a thin alias over [`parse_attrs`]: since the `payload` field of a
/// parent attribute already strips the 4-byte header, simply pass it straight
/// in.
///
/// ```rust
/// use nlx_netlink::wire::{parse_attrs, nested_attrs};
///
/// // Outer attr type=7 (NLA_F_NESTED|7 in real kernel, already masked to 7).
/// // Inner attr type=1, payload=[0x01].
/// let inner_raw: &[u8] = &[
///     0x05, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
/// ];
/// // Pretend outer payload IS the inner bytes.
/// let inner_attrs: Vec<_> = nested_attrs(inner_raw).collect();
/// assert_eq!(inner_attrs.len(), 1);
/// assert_eq!(inner_attrs[0].ty, 1);
/// ```
#[must_use]
pub fn nested_attrs(payload: &[u8]) -> NlaIter<'_> {
    NlaIter { buf: payload }
}

// ---------------------------------------------------------------------------
// Typed scalar readers (native-endian)
// ---------------------------------------------------------------------------

/// Read a `u8` from a payload slice, returning `None` when length is
/// insufficient.
#[inline]
#[must_use]
pub fn read_u8(payload: &[u8]) -> Option<u8> {
    payload.first().copied()
}

/// Read a `u16` native-endian from a payload slice.
#[inline]
#[must_use]
pub fn read_u16(payload: &[u8]) -> Option<u16> {
    payload.get(..2).map(|b| u16::from_ne_bytes([b[0], b[1]]))
}

/// Read a `u32` native-endian from a payload slice.
#[inline]
#[must_use]
pub fn read_u32(payload: &[u8]) -> Option<u32> {
    payload
        .get(..4)
        .map(|b| u32::from_ne_bytes([b[0], b[1], b[2], b[3]]))
}

/// Read a `u64` native-endian from a payload slice.
#[inline]
#[must_use]
pub fn read_u64(payload: &[u8]) -> Option<u64> {
    payload
        .get(..8)
        .and_then(|b| b.try_into().ok())
        .map(u64::from_ne_bytes)
}

// ---------------------------------------------------------------------------
// Typed scalar readers (big-endian / NLA_F_NET_BYTEORDER)
// ---------------------------------------------------------------------------

/// Read a `u16` big-endian from a payload slice.
///
/// Use when the attribute has `NLA_F_NET_BYTEORDER` (bit 14) set in the
/// wire encoding, or when the protocol documents network byte order for this
/// field (e.g. conntrack `CTA_STATUS`, `res_id` in `nfgenmsg`).
#[inline]
#[must_use]
pub fn read_u16_be(payload: &[u8]) -> Option<u16> {
    payload.get(..2).map(|b| u16::from_be_bytes([b[0], b[1]]))
}

/// Read a `u32` big-endian from a payload slice.
#[inline]
#[must_use]
pub fn read_u32_be(payload: &[u8]) -> Option<u32> {
    payload
        .get(..4)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// Read a `u64` big-endian from a payload slice.
#[inline]
#[must_use]
pub fn read_u64_be(payload: &[u8]) -> Option<u64> {
    payload
        .get(..8)
        .and_then(|b| b.try_into().ok())
        .map(u64::from_be_bytes)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helpers to construct a minimal nlattr TLV in a `Vec<u8>`.
    fn make_nla(ty: u16, payload: &[u8]) -> Vec<u8> {
        let nla_len = NLA_HDRLEN + payload.len();
        let padded = align4(nla_len);
        let mut out = Vec::with_capacity(padded);
        // nla_len u16 LE
        out.extend_from_slice(&(nla_len as u16).to_ne_bytes());
        // nla_type u16 LE
        out.extend_from_slice(&ty.to_ne_bytes());
        out.extend_from_slice(payload);
        // padding
        out.resize(padded, 0u8);
        out
    }

    #[test]
    fn align4_rounds_correctly() {
        assert_eq!(align4(0), 0);
        assert_eq!(align4(1), 4);
        assert_eq!(align4(3), 4);
        assert_eq!(align4(4), 4);
        assert_eq!(align4(5), 8);
        assert_eq!(align4(8), 8);
        assert_eq!(align4(9), 12);
    }

    #[test]
    fn parse_attrs_single_u32() {
        let val: u32 = 0xDEAD_BEEF;
        let buf = make_nla(7, &val.to_ne_bytes());
        let attrs: Vec<_> = parse_attrs(&buf).collect();
        assert_eq!(attrs.len(), 1, "expected exactly one attr");
        assert_eq!(attrs[0].ty, 7);
        assert_eq!(read_u32(attrs[0].payload), Some(val));
    }

    #[test]
    fn parse_attrs_strips_nla_f_nested_bit() {
        // Type 3 with NLA_F_NESTED (0x8000) set — effective type must be 3.
        let buf = make_nla(0x8003u16, &[0xAB, 0xCD]);
        let attrs: Vec<_> = parse_attrs(&buf).collect();
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].ty, 3, "NLA_F_NESTED bit must be stripped");
    }

    #[test]
    fn parse_attrs_strips_nla_f_net_byteorder_bit() {
        // Type 5 with NLA_F_NET_BYTEORDER (0x4000) set — effective type must be 5.
        let buf = make_nla(0x4005u16, &[0xAA, 0xBB, 0xCC, 0xDD]);
        let attrs: Vec<_> = parse_attrs(&buf).collect();
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].ty, 5, "NLA_F_NET_BYTEORDER bit must be stripped");
    }

    #[test]
    fn parse_attrs_multiple() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&make_nla(1, &[0x11u8]));
        buf.extend_from_slice(&make_nla(2, &[0x22u8, 0x33u8]));
        buf.extend_from_slice(&make_nla(3, &0xDEAD_BEEFu32.to_ne_bytes()));

        let attrs: Vec<_> = parse_attrs(&buf).collect();
        assert_eq!(attrs.len(), 3);
        assert_eq!(attrs[0].ty, 1);
        assert_eq!(attrs[1].ty, 2);
        assert_eq!(attrs[2].ty, 3);
        assert_eq!(read_u8(attrs[0].payload), Some(0x11));
        assert_eq!(read_u32(attrs[2].payload), Some(0xDEAD_BEEF));
    }

    #[test]
    fn parse_attrs_empty_buf() {
        let attrs: Vec<_> = parse_attrs(&[]).collect();
        assert!(attrs.is_empty(), "empty buf yields no attrs");
    }

    #[test]
    fn parse_attrs_malformed_nla_len_too_small() {
        // nla_len = 3 < NLA_HDRLEN(4) — malformed, iterator must stop.
        let buf: &[u8] = &[0x03, 0x00, 0x01, 0x00, 0xAA, 0xAA, 0xAA, 0xAA];
        let attrs: Vec<_> = parse_attrs(buf).collect();
        assert!(attrs.is_empty(), "malformed attr must stop iteration");
    }

    #[test]
    fn parse_attrs_nla_len_beyond_buf() {
        // nla_len = 100 but buf only has 8 bytes.
        let buf: &[u8] = &[100, 0x00, 0x01, 0x00, 0xAA, 0xAA, 0xAA, 0xAA];
        let attrs: Vec<_> = parse_attrs(buf).collect();
        assert!(attrs.is_empty(), "nla_len beyond buf must stop iteration");
    }

    #[test]
    fn read_scalars_native_endian() {
        let val32: u32 = 0x0102_0304;
        let b = val32.to_ne_bytes();
        assert_eq!(read_u32(&b), Some(val32));

        let val64: u64 = 0x0102_0304_0506_0708;
        let b64 = val64.to_ne_bytes();
        assert_eq!(read_u64(&b64), Some(val64));
    }

    #[test]
    fn read_scalars_big_endian() {
        let val32: u32 = 0xDEAD_BEEF;
        let b = val32.to_be_bytes();
        assert_eq!(read_u32_be(&b), Some(val32));

        let val64: u64 = 0xFEED_FACE_CAFE_BABE;
        let b64 = val64.to_be_bytes();
        assert_eq!(read_u64_be(&b64), Some(val64));
    }

    #[test]
    fn nested_attrs_roundtrip() {
        // Build inner sequence, parse via nested_attrs.
        let inner = make_nla(42, &[1u8, 2u8, 3u8]);
        let attrs: Vec<_> = nested_attrs(&inner).collect();
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].ty, 42);
        assert_eq!(attrs[0].payload, &[1u8, 2u8, 3u8]);
    }
}
