//! `netstat` collector — `/proc/net/snmp` + `/proc/net/netstat` (ADR-0027).
//!
//! Exports Linux IP/TCP/UDP/ICMP MIB counters that have no netlink equivalent.
//! Both files share the same **paired-line** format emitted by
//! `net/ipv4/proc.c:snmp_seq_show` and `netstat_seq_show` (kernel 6.17):
//!
//! ```text
//! Proto: FieldA FieldB FieldC …
//! Proto: 12     34     56     …
//! ```
//!
//! The `Proto:` token prefixes both the header and the data line.  Columns are
//! space-separated; the token itself is column 0 on each line.  For column *i*
//! (1-based after stripping the token), the field name is `header[i]` and the
//! value is `data[i]`.
//!
//! ## Sources and protos emitted
//!
//! | File                  | Proto token(s)                              |
//! |-----------------------|---------------------------------------------|
//! | `/proc/net/snmp`      | `Ip`, `Icmp`, `IcmpMsg`, `Tcp`, `Udp`, `UdpLite` |
//! | `/proc/net/netstat`   | `TcpExt`, `IpExt`, `MPTcpExt`              |
//!
//! `IcmpMsg` lines only appear when at least one ICMP type counter is non-zero.
//! `MPTcpExt` only appears when the MPTCP module is compiled in.  Both are
//! handled transparently by the paired-line parser.
//!
//! ## Special case: `Tcp MaxConn`
//!
//! `MaxConn` is RFC 2012 **signed** and the kernel prints it with `%ld`, so it
//! can be `-1` (unlimited).  The field is exposed as a gauge with `f64` to
//! represent `-1.0` faithfully; all other fields are also gauges (they are
//! monotonic-ish counters but some reset on net-namespace creation, matching
//! `node_exporter`'s choice of gauge type for this family).
//!
//! ## Metric family
//!
//! | Metric              | Kind  | Labels               |
//! |---------------------|-------|----------------------|
//! | `nft_netstat`       | gauge | `protocol`, `field`  |
//!
//! Approximately 150 series, bounded by the kernel MIB definitions in
//! `net/ipv4/proc.c` and `net/mptcp/mib.c`.
//!
//! ## Kernel references
//!
//! - `net/ipv4/proc.c:snmp_seq_show_ipstats` — `Ip:` paired lines
//! - `net/ipv4/proc.c:snmp_seq_show_tcp_udp` — `Tcp:`, `Udp:`, `UdpLite:` paired lines
//! - `net/ipv4/proc.c:icmp_put` — `Icmp:` paired lines
//! - `net/ipv4/proc.c:icmpmsg_put` — optional `IcmpMsg:` paired lines
//! - `net/ipv4/proc.c:netstat_seq_show` — `TcpExt:`, `IpExt:` paired lines
//! - `net/mptcp/mib.c:mptcp_seq_show` — `MPTcpExt:` paired lines

use std::collections::BTreeMap;

use nlx_domain::metric::MetricSample;
use nlx_ports::{
    collector::{BoxFuture, Collector},
    error::CollectError,
};

use crate::{readable, safe_read};

const PATH_SNMP: &str = "/proc/net/snmp";
const PATH_NETSTAT: &str = "/proc/net/netstat";

/// Collector for `/proc/net/snmp` and `/proc/net/netstat` (IP/TCP/UDP MIB counters).
pub struct NetstatCollector;

impl Collector for NetstatCollector {
    fn name(&self) -> &'static str {
        "netstat"
    }

    fn collect(&self) -> BoxFuture<'_, Result<Vec<MetricSample>, CollectError>> {
        Box::pin(async move {
            // Read both files independently; a missing file is not fatal.
            let snmp = safe_read(PATH_SNMP).map_err(|e| CollectError::Io(e.to_string()))?;
            let netstat = safe_read(PATH_NETSTAT).unwrap_or_default();

            let mut out = Vec::new();
            parse_paired_lines(&snmp, &mut out);
            parse_paired_lines(&netstat, &mut out);
            Ok(out)
        })
    }

    fn probe_available(&self) -> BoxFuture<'_, bool> {
        // The collector is available when at least the primary file is readable.
        Box::pin(async move { readable(PATH_SNMP) })
    }
}

/// Parse a file that uses the paired-line format:
///
/// ```text
/// Proto: FieldA FieldB …
/// Proto: 12     34     …
/// ```
///
/// Lines are consumed in pairs.  A header line is identified by the fact that
/// its second token (index 1) does **not** parse as an integer.  When a header
/// is found, the very next line is expected to be the matching data line with
/// the same proto token.  Unrecognised or unpaired lines are skipped silently.
#[allow(
    clippy::cast_precision_loss,
    reason = "MIB values are u64-range counters; precision loss above 2^53 is \
              acceptable for a monitoring gauge that will never reach that scale"
)]
fn parse_paired_lines(text: &str, out: &mut Vec<MetricSample>) {
    let mut lines = text.lines().peekable();

    while let Some(header_line) = lines.next() {
        let header_cols: Vec<&str> = header_line.split_whitespace().collect();

        // Need at least "Proto:" + one field name.
        if header_cols.len() < 2 {
            continue;
        }

        // The first token must end with ':' (e.g. "Tcp:").
        let proto_token = match header_cols.first() {
            Some(t) if t.ends_with(':') => t.trim_end_matches(':'),
            _ => continue,
        };

        // Confirm this is a header line: the second token must NOT parse as i64.
        // Data lines have numbers; header lines have field names.
        if header_cols
            .get(1)
            .and_then(|s| s.parse::<i64>().ok())
            .is_some()
        {
            // This is a data line without a preceding header — skip it.
            continue;
        }

        // Peek at the next line; it should be the data line for the same proto.
        let data_line = match lines.peek() {
            Some(l) => *l,
            None => continue,
        };
        let data_cols: Vec<&str> = data_line.split_whitespace().collect();

        // Validate: same proto token, same column count.
        let data_proto = match data_cols.first() {
            Some(t) if t.ends_with(':') => t.trim_end_matches(':'),
            _ => continue,
        };
        if data_proto != proto_token {
            continue;
        }
        if data_cols.len() != header_cols.len() {
            // Column mismatch — consume the data line and move on.
            let _ = lines.next();
            continue;
        }

        // Consume the data line.
        let _ = lines.next();

        // Pair columns: skip index 0 (the proto token) in both.
        let protocol = proto_token.to_owned();
        for (field_col, value_col) in header_cols.iter().skip(1).zip(data_cols.iter().skip(1)) {
            let value: f64 = match value_col.parse::<i64>() {
                Ok(v) => v as f64,
                Err(_) => {
                    // Could not parse value — skip this field defensively.
                    continue;
                }
            };

            let mut labels = BTreeMap::new();
            labels.insert("protocol".to_owned(), protocol.clone());
            labels.insert("field".to_owned(), (*field_col).to_owned());

            out.push(MetricSample::gauge(
                "nft_netstat",
                "Linux IP/TCP/UDP/ICMP MIB field value from /proc/net/snmp and /proc/net/netstat.",
                labels,
                value,
            ));
        }
    }
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

    /// Minimal realistic excerpt from `/proc/net/snmp` (kernel 6.17 format).
    /// Includes `Tcp MaxConn=-1` to exercise the signed-value path.
    const SAMPLE_SNMP: &str = "\
Ip: Forwarding DefaultTTL InReceives InHdrErrors InAddrErrors ForwDatagrams InUnknownProtos InDiscards InDelivers OutRequests OutDiscards OutNoRoutes ReasmTimeout ReasmReqds ReasmOKs ReasmFails FragOKs FragFails FragCreates OutTransmits
Ip: 1 64 12345 0 0 0 0 0 12300 9876 5 1 0 0 0 0 0 0 0 9876
Icmp: InMsgs InErrors InCsumErrors InDestUnreachs InTimeExcds InParmProbs InSrcQuenchs InRedirects InEchos InEchoReps InTimestamps InTimestampReps InAddrMasks InAddrMaskReps OutMsgs OutErrors OutRateLimitGlobal OutRateLimitHost OutDestUnreachs OutTimeExcds OutParmProbs OutSrcQuenchs OutRedirects OutEchos OutEchoReps OutTimestamps OutTimestampReps OutAddrMasks OutAddrMaskReps
Icmp: 10 2 0 8 0 0 0 0 0 0 0 0 0 0 9 0 0 0 7 0 0 0 0 0 0 0 0 0 0
Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts InCsumErrors
Tcp: 1 200 120000 -1 42 17 3 1 5 9988 9100 12 0 4 0
Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti MemErrors
Udp: 500 3 0 490 0 0 0 2 0
UdpLite: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti MemErrors
UdpLite: 0 0 0 0 0 0 0 0 0
";

    /// Minimal realistic excerpt from `/proc/net/netstat` (kernel 6.17 format).
    /// `TcpExt`/`IpExt` field lists are truncated to a representative subset —
    /// the header and data lines have matching column counts (as the real kernel
    /// always emits), which is what the paired-line parser requires.
    const SAMPLE_NETSTAT: &str = "\
TcpExt: SyncookiesSent SyncookiesRecv DelayedACKs ListenOverflows ListenDrops TCPLostRetransmit TCPTimeouts
TcpExt: 0 0 3400 0 0 8 11
IpExt: InNoRoutes InTruncatedPkts InMcastPkts OutMcastPkts InBcastPkts OutBcastPkts InOctets OutOctets InMcastOctets OutMcastOctets InBcastOctets OutBcastOctets InCsumErrors InNoECTPkts InECT1Pkts InECT0Pkts InCEPkts ReasmOverlaps
IpExt: 1 0 5 3 100 0 1234567 9876543 200 100 4000 0 0 12300 0 0 0 0
";

    fn find<'a>(
        samples: &'a [MetricSample],
        protocol: &str,
        field: &str,
    ) -> Option<&'a MetricSample> {
        samples.iter().find(|m| {
            m.labels.get("protocol").map(String::as_str) == Some(protocol)
                && m.labels.get("field").map(String::as_str) == Some(field)
        })
    }

    fn gauge_value(s: &MetricSample) -> f64 {
        match s.value {
            nlx_domain::metric::MetricValue::F64(f) => f,
            nlx_domain::metric::MetricValue::U64(u) => u as f64,
        }
    }

    #[test]
    fn parses_ip_field_from_snmp() {
        let mut out = Vec::new();
        parse_paired_lines(SAMPLE_SNMP, &mut out);
        let s = find(&out, "Ip", "InReceives").unwrap();
        assert_eq!(gauge_value(s), 12345.0);
    }

    #[test]
    fn parses_tcp_maxconn_minus_one() {
        let mut out = Vec::new();
        parse_paired_lines(SAMPLE_SNMP, &mut out);
        let s = find(&out, "Tcp", "MaxConn").unwrap();
        assert_eq!(gauge_value(s), -1.0);
    }

    #[test]
    fn parses_tcp_retranse_segs() {
        let mut out = Vec::new();
        parse_paired_lines(SAMPLE_SNMP, &mut out);
        let s = find(&out, "Tcp", "RetransSegs").unwrap();
        assert_eq!(gauge_value(s), 12.0);
    }

    #[test]
    fn parses_udp_indatagrams() {
        let mut out = Vec::new();
        parse_paired_lines(SAMPLE_SNMP, &mut out);
        let s = find(&out, "Udp", "InDatagrams").unwrap();
        assert_eq!(gauge_value(s), 500.0);
    }

    #[test]
    fn parses_udplite_zero_values() {
        let mut out = Vec::new();
        parse_paired_lines(SAMPLE_SNMP, &mut out);
        let s = find(&out, "UdpLite", "InDatagrams").unwrap();
        assert_eq!(gauge_value(s), 0.0);
    }

    #[test]
    fn parses_icmp_inmsgs() {
        let mut out = Vec::new();
        parse_paired_lines(SAMPLE_SNMP, &mut out);
        let s = find(&out, "Icmp", "InMsgs").unwrap();
        assert_eq!(gauge_value(s), 10.0);
    }

    #[test]
    fn parses_tcpext_from_netstat() {
        let mut out = Vec::new();
        parse_paired_lines(SAMPLE_NETSTAT, &mut out);
        let s = find(&out, "TcpExt", "ListenDrops").unwrap();
        assert_eq!(gauge_value(s), 0.0);
    }

    #[test]
    fn parses_ipext_from_netstat() {
        let mut out = Vec::new();
        parse_paired_lines(SAMPLE_NETSTAT, &mut out);
        let s = find(&out, "IpExt", "InOctets").unwrap();
        assert_eq!(gauge_value(s), 1_234_567.0);
    }

    #[test]
    fn all_samples_are_gauges() {
        let mut out = Vec::new();
        parse_paired_lines(SAMPLE_SNMP, &mut out);
        parse_paired_lines(SAMPLE_NETSTAT, &mut out);
        for s in &out {
            assert_eq!(s.kind, MetricKind::Gauge, "expected gauge for {}", s.name);
        }
    }

    #[test]
    fn all_samples_have_protocol_and_field_labels() {
        let mut out = Vec::new();
        parse_paired_lines(SAMPLE_SNMP, &mut out);
        parse_paired_lines(SAMPLE_NETSTAT, &mut out);
        for s in &out {
            assert!(s.labels.contains_key("protocol"), "missing protocol label");
            assert!(s.labels.contains_key("field"), "missing field label");
        }
    }

    #[test]
    fn metric_name_is_nft_netstat() {
        let mut out = Vec::new();
        parse_paired_lines(SAMPLE_SNMP, &mut out);
        for s in &out {
            assert_eq!(s.name, "nft_netstat");
        }
    }

    #[test]
    fn empty_input_yields_no_samples() {
        let mut out = Vec::new();
        parse_paired_lines("", &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn unpaired_header_is_skipped_gracefully() {
        // A header with no following data line (EOF) must not panic.
        let text = "Tcp: RtoAlgorithm RtoMin RtoMax\n";
        let mut out = Vec::new();
        parse_paired_lines(text, &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn mismatched_proto_on_data_line_is_skipped() {
        let text = "Tcp: RtoAlgorithm RtoMin\nUdp: 1 2\n";
        let mut out = Vec::new();
        parse_paired_lines(text, &mut out);
        // The header is "Tcp:" but the next line is "Udp:" — must be skipped.
        assert!(out.is_empty());
    }

    #[test]
    fn column_count_mismatch_is_skipped_gracefully() {
        let text = "Tcp: FieldA FieldB\nTcp: 1\n";
        let mut out = Vec::new();
        parse_paired_lines(text, &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn combining_both_files_produces_both_protos() {
        let mut out = Vec::new();
        parse_paired_lines(SAMPLE_SNMP, &mut out);
        parse_paired_lines(SAMPLE_NETSTAT, &mut out);
        let has_tcp = out
            .iter()
            .any(|s| s.labels.get("protocol").map(String::as_str) == Some("Tcp"));
        let has_tcpext = out
            .iter()
            .any(|s| s.labels.get("protocol").map(String::as_str) == Some("TcpExt"));
        assert!(has_tcp, "Tcp proto must be present from snmp");
        assert!(has_tcpext, "TcpExt proto must be present from netstat");
    }

    #[test]
    fn ip_forwarding_field_parsed() {
        // The Ip: header line starts "Ip: Forwarding DefaultTTL …".
        // Forwarding = 1 in the sample data.
        let mut out = Vec::new();
        parse_paired_lines(SAMPLE_SNMP, &mut out);
        let s = find(&out, "Ip", "Forwarding").unwrap();
        assert_eq!(gauge_value(s), 1.0);
    }
}
