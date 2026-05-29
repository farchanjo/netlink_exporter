//! `sockstat` collector — `/proc/net/sockstat` (ADR-0027).
//!
//! Per-protocol socket allocation snapshot. No netlink API exists for this
//! view; it is the canonical source for TCP orphan pressure, `TIME_WAIT` counts,
//! and fragmentation queue depth.
//!
//! ## Format (kernel `net/socket.c::socket_seq_show` +
//! `net/ipv4/proc.c::sockstat_seq_show`, 6.17)
//!
//! Each line has the form `Proto: key1 val1 key2 val2 ...`.
//! Unknown lines are skipped defensively.
//!
//! | proto    | key      | notes                                    |
//! |----------|----------|------------------------------------------|
//! | sockets  | used     | all allocated sockets system-wide        |
//! | tcp      | inuse    | sockets in use                           |
//! | tcp      | orphan   | orphaned TCP sockets (no user-space fd)  |
//! | tcp      | tw       | `TIME_WAIT` sockets                        |
//! | tcp      | alloc    | allocated (`proto_sockets_allocated`)      |
//! | tcp      | mem      | memory pages used by TCP send/recv bufs  |
//! | udp      | inuse    | UDP sockets in use                       |
//! | udp      | mem      | memory pages used by UDP sockets         |
//! | udplite  | inuse    | UDPLITE sockets in use                   |
//! | raw      | inuse    | RAW sockets in use                       |
//! | frag     | inuse    | IP fragment queue entries                |
//! | frag     | memory   | bytes consumed by fragment queue         |
//!
//! `mem` fields are in pages (multiply by `getconf PAGESIZE` to get bytes).

use std::collections::BTreeMap;

use nlx_domain::metric::MetricSample;
use nlx_ports::{
    collector::{BoxFuture, Collector},
    error::CollectError,
};

use crate::{readable, safe_read};

const PATH: &str = "/proc/net/sockstat";

/// Collector for `/proc/net/sockstat` (per-protocol socket allocation snapshot).
pub struct SockstatCollector;

impl Collector for SockstatCollector {
    fn name(&self) -> &'static str {
        "sockstat"
    }

    fn collect(&self) -> BoxFuture<'_, Result<Vec<MetricSample>, CollectError>> {
        Box::pin(async move {
            let text = safe_read(PATH).map_err(|e| CollectError::Io(e.to_string()))?;
            Ok(parse(&text))
        })
    }

    fn probe_available(&self) -> BoxFuture<'_, bool> {
        Box::pin(async move { readable(PATH) })
    }
}

/// Parse the full `sockstat` text into gauge samples (one per proto/key pair).
///
/// Each line is `Proto: key1 val1 [key2 val2 ...]`.  Malformed lines,
/// unrecognised token counts, or non-integer values are silently skipped so
/// that a future kernel adding new fields never breaks the collector.
#[allow(
    clippy::cast_precision_loss,
    reason = "sockstat values are small integers; no meaningful precision is lost casting i64->f64"
)]
fn parse(text: &str) -> Vec<MetricSample> {
    let mut out = Vec::new();

    for line in text.lines() {
        // Split on whitespace.  First token must end with ':'.
        let mut tokens = line.split_whitespace();
        let Some(proto_token) = tokens.next() else {
            continue;
        };
        // Strip trailing colon; skip lines without one.
        let proto = match proto_token.strip_suffix(':') {
            Some(p) => p.to_ascii_lowercase(),
            None => continue,
        };

        // Remaining tokens are alternating key/value pairs.
        // Collect into a Vec so we can walk pairs safely.
        let rest: Vec<&str> = tokens.collect();

        // Walk key/value pairs; odd-count remainder is silently ignored.
        let mut i = 0;
        while i + 1 < rest.len() {
            let key = rest[i];
            // Try decimal parse; non-integer values are skipped.
            let value: i64 = if let Ok(v) = rest[i + 1].parse() {
                v
            } else {
                i += 2;
                continue;
            };

            let mut labels = BTreeMap::new();
            labels.insert("protocol".to_owned(), proto.clone());
            labels.insert("key".to_owned(), key.to_owned());

            out.push(MetricSample::gauge(
                "nft_sockstat",
                "Socket allocation snapshot from /proc/net/sockstat. \
                 TCP/UDP mem values are in pages (multiply by page size to get bytes).",
                labels,
                value as f64,
            ));

            i += 2;
        }
    }

    out
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::float_cmp,
        clippy::cast_precision_loss,
        clippy::cast_lossless,
        reason = "test"
    )]

    use super::*;
    use nlx_domain::metric::MetricKind;

    /// Realistic sample matching kernel 6.17 `sockstat_seq_show` output.
    const SAMPLE: &str = "\
sockets: used 4867\n\
TCP: inuse 4098 orphan 0 tw 179 alloc 4174 mem 0\n\
UDP: inuse 12 mem 0\n\
UDPLITE: inuse 0\n\
RAW: inuse 4\n\
FRAG: inuse 0 memory 0\n\
";

    fn find<'a>(
        samples: &'a [MetricSample],
        protocol: &str,
        key: &str,
    ) -> Option<&'a MetricSample> {
        samples.iter().find(|m| {
            m.labels.get("protocol").map(String::as_str) == Some(protocol)
                && m.labels.get("key").map(String::as_str) == Some(key)
        })
    }

    fn gauge_val(s: &MetricSample) -> f64 {
        match s.value {
            nlx_domain::metric::MetricValue::F64(v) => v,
            nlx_domain::metric::MetricValue::U64(v) => v as f64,
        }
    }

    #[test]
    fn parses_all_expected_series() {
        let out = parse(SAMPLE);
        // 1 (sockets) + 5 (tcp) + 2 (udp) + 1 (udplite) + 1 (raw) + 2 (frag) = 12
        assert_eq!(out.len(), 12);
    }

    #[test]
    fn all_samples_are_gauges() {
        let out = parse(SAMPLE);
        for s in &out {
            assert_eq!(
                s.kind,
                MetricKind::Gauge,
                "expected gauge for {:?}",
                s.labels
            );
        }
    }

    #[test]
    fn sockets_used_value() {
        let out = parse(SAMPLE);
        let s = find(&out, "sockets", "used").unwrap();
        assert_eq!(gauge_val(s), 4867.0);
    }

    #[test]
    fn tcp_fields_correct() {
        let out = parse(SAMPLE);
        assert_eq!(gauge_val(find(&out, "tcp", "inuse").unwrap()), 4098.0);
        assert_eq!(gauge_val(find(&out, "tcp", "orphan").unwrap()), 0.0);
        assert_eq!(gauge_val(find(&out, "tcp", "tw").unwrap()), 179.0);
        assert_eq!(gauge_val(find(&out, "tcp", "alloc").unwrap()), 4174.0);
        assert_eq!(gauge_val(find(&out, "tcp", "mem").unwrap()), 0.0);
    }

    #[test]
    fn udp_fields_correct() {
        let out = parse(SAMPLE);
        assert_eq!(gauge_val(find(&out, "udp", "inuse").unwrap()), 12.0);
        assert_eq!(gauge_val(find(&out, "udp", "mem").unwrap()), 0.0);
    }

    #[test]
    fn frag_memory_key_parsed() {
        let out = parse(SAMPLE);
        // FRAG uses "memory" not "mem"
        assert!(find(&out, "frag", "memory").is_some());
        assert!(find(&out, "frag", "inuse").is_some());
    }

    #[test]
    fn protocol_names_are_lowercased() {
        let out = parse(SAMPLE);
        // All protocol labels must be lowercase regardless of kernel casing.
        for s in &out {
            let proto = s.labels.get("protocol").unwrap();
            assert_eq!(
                proto,
                &proto.to_ascii_lowercase(),
                "protocol label not lowercase"
            );
        }
    }

    #[test]
    fn malformed_line_without_colon_is_skipped() {
        let out = parse("no colon here\nsockets: used 1\n");
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn non_integer_value_is_skipped() {
        // "bad" is not a valid i64; that pair should be skipped, valid one kept.
        let out = parse("TCP: inuse bad orphan 3\n");
        assert_eq!(out.len(), 1);
        assert_eq!(gauge_val(find(&out, "tcp", "orphan").unwrap()), 3.0);
    }

    #[test]
    fn odd_trailing_token_is_ignored_not_panicked() {
        // "inuse 5 orphan" — odd count, last token has no value.
        let out = parse("TCP: inuse 5 orphan\n");
        assert_eq!(out.len(), 1);
        assert_eq!(gauge_val(find(&out, "tcp", "inuse").unwrap()), 5.0);
    }

    #[test]
    fn empty_input_yields_no_samples() {
        assert!(parse("").is_empty());
    }

    #[test]
    fn all_samples_have_metric_name_nft_sockstat() {
        let out = parse(SAMPLE);
        for s in &out {
            assert_eq!(s.name, "nft_sockstat");
        }
    }
}
