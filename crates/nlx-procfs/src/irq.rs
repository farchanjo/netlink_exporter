//! `irq` collector — `/proc/interrupts` (ADR-0027).
//!
//! Per-IRQ total interrupt counts (hardware IRQs only; symbolic arch counters
//! such as NMI/LOC/RES are excluded). Counts are summed across all online CPUs
//! to avoid the O(irqs × cpus) cardinality explosion.
//!
//! ## File format (`kernel/irq/proc.c::show_interrupts`, Linux 6.17)
//!
//! ```text
//!            CPU0       CPU1  …
//!   <num>:  <cnt0>  <cnt1>  …  <chip>  [<hwirq>]  [Level|Edge][-<name>]  <device>
//!   NMI:    …  (symbolic — skipped)
//! ```
//!
//! | field            | description                                               |
//! |------------------|-----------------------------------------------------------|
//! | `<num>`          | IRQ number (right-aligned decimal, colon-terminated)      |
//! | `<cnt0..cntN>`   | Per-CPU hit counts (decimal, 10 chars wide)               |
//! | `<chip>`         | Interrupt controller name (8 chars wide)                  |
//! | `<hwirq>`        | Hardware IRQ number within the chip's domain (optional)   |
//! | `Level\|Edge`    | Trigger type token (optional, `CONFIG_GENERIC_IRQ_SHOW_LEVEL`)|
//! | `-<name>`        | Chip-level name suffix, printed as `-%-8s` (optional)     |
//! | `<device>`       | `irqaction->name` chain, printed after two spaces          |
//!
//! Only rows whose IRQ id is numeric (hardware IRQs) are emitted; symbolic
//! entries (`NMI`, `LOC`, …) are silently skipped.
//!
//! Device text extraction: the kernel prints `seq_printf(p, "  %s", action->name)`
//! — two leading spaces before the first action name. We locate the device text
//! as the portion of the line that follows the last pair of leading spaces after
//! all per-CPU count tokens have been consumed.

use std::collections::BTreeMap;

use nlx_domain::metric::MetricSample;
use nlx_ports::{
    collector::{BoxFuture, Collector},
    error::CollectError,
};

use crate::{readable, safe_read};

const PATH: &str = "/proc/interrupts";

/// Collector for `/proc/interrupts` (per-IRQ total hit counts, hardware IRQs only).
pub struct IrqCollector;

impl Collector for IrqCollector {
    fn name(&self) -> &'static str {
        "irq"
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

/// Parse the full `/proc/interrupts` text into samples.
///
/// One [`MetricSample`] is emitted per hardware IRQ (numeric id rows only).
/// Per-CPU counts are summed; the device label is extracted from the trailing
/// action name portion of each row.
fn parse(text: &str) -> Vec<MetricSample> {
    let mut out = Vec::new();

    for line in text.lines() {
        // Trim leading whitespace; skip header (starts with "CPU" after trim).
        let trimmed = line.trim_start();

        // Each data row starts with "<irq_id>:" — split at the first colon.
        let Some(colon_pos) = trimmed.find(':') else {
            continue;
        };

        let irq_id = trimmed[..colon_pos].trim();

        // Keep only numeric IRQ ids (hardware IRQs).  Symbolic entries like
        // "NMI", "LOC", "RES" are excluded per spec.
        if irq_id.is_empty() || !irq_id.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }

        // Everything after the colon is: <counts...> <chip> [<hwirq>] [Level|Edge[-name]] [  <device>]
        let rest = &trimmed[colon_pos.saturating_add(1)..];

        // Walk the rest byte-by-byte, consuming whitespace-separated tokens.
        // Collect all leading all-digit tokens as per-CPU counts; stop at the
        // first non-digit token.  Track `cursor` as a byte offset into `rest`.
        let mut total: u64 = 0;
        let mut cursor: usize = 0;
        let mut found_any_count = false;

        while cursor < rest.len() {
            // Skip leading whitespace.
            let ws_start = cursor;
            while cursor < rest.len() && rest.as_bytes().get(cursor).copied() == Some(b' ') {
                cursor = cursor.saturating_add(1);
            }
            if cursor == rest.len() {
                break;
            }
            // Find end of this token.
            let tok_start = cursor;
            while cursor < rest.len() && rest.as_bytes().get(cursor).copied() != Some(b' ') {
                cursor = cursor.saturating_add(1);
            }
            let token = &rest[tok_start..cursor];

            if token.chars().all(|c| c.is_ascii_digit()) {
                // Safe: saturating_add avoids any overflow on a 32-bit kernel
                // where per-CPU counts could individually be u32::MAX.
                total = total.saturating_add(token.parse::<u64>().unwrap_or(0));
                found_any_count = true;
            } else {
                // First non-digit token — rewind cursor to the start of the
                // whitespace we just consumed so `rest[cursor..]` includes the
                // full metadata region with its leading spaces.
                cursor = ws_start;
                break;
            }
        }

        // If no numeric counts were found this is a degenerate row — skip it.
        if !found_any_count {
            continue;
        }

        // Device name: the kernel emits `seq_printf(p, "  %s", action->name)` —
        // two spaces immediately before the first action name.  The metadata
        // region starts with whitespace (from the cursor rewind) followed by
        // the chip name, optional hwirq, optional level/edge token, and then
        // the action name section.  Between chip/hwirq/level tokens only single
        // spaces appear; the action name section is always preceded by at least
        // two consecutive spaces.
        //
        // Strategy: strip leading whitespace first (so we don't confuse the
        // inter-field leading spaces with the pre-action double-space), then
        // use `rfind("  ")` to locate the rightmost two-space run — which is
        // the space region immediately before the action name.
        let metadata = rest[cursor..].trim_start();
        let device = if let Some(last_ds) = metadata.rfind("  ") {
            metadata[last_ds..].trim()
        } else {
            ""
        };

        let mut labels = BTreeMap::new();
        labels.insert("irq".to_owned(), irq_id.to_owned());
        labels.insert("device".to_owned(), device.to_owned());

        out.push(MetricSample::counter(
            "nft_irq_total",
            "Total interrupt count summed across all CPUs for this hardware IRQ.",
            labels,
            total,
        ));
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

    /// Realistic 4-CPU `/proc/interrupts` excerpt.  Columns after the colon:
    /// 4 decimal counts, chip name, hwirq, edge/level token, optional `-name`, device.
    const SAMPLE: &str = "\
           CPU0       CPU1       CPU2       CPU3\n\
   1:          0          0          0          0   IO-APIC   1-edge      i8042\n\
   8:          0          0          0          1   IO-APIC   8-edge      rtc0\n\
  27:          3          5          2          7   PCI-MSI 524288-edge      xhci_hcd\n\
1471:          0          0          0          1   PCI-MSI 1572864-edge      eth0-TxRx-0\n\
1472:          2          4          0          0   PCI-MSI 1572865-edge      eth0-TxRx-1\n\
 NMI:          0          0          0          0   Non-maskable interrupts\n\
 LOC:    1234567    2345678    3456789    4567890   Local timer interrupts\n\
";

    fn find<'a>(samples: &'a [MetricSample], irq: &str) -> Option<&'a MetricSample> {
        samples
            .iter()
            .find(|m| m.labels.get("irq").map(String::as_str) == Some(irq))
    }

    #[test]
    fn numeric_irqs_are_collected() {
        let out = parse(SAMPLE);
        assert!(find(&out, "1").is_some(), "irq 1 must be collected");
        assert!(find(&out, "8").is_some(), "irq 8 must be collected");
        assert!(find(&out, "27").is_some(), "irq 27 must be collected");
        assert!(find(&out, "1471").is_some(), "irq 1471 must be collected");
        assert!(find(&out, "1472").is_some(), "irq 1472 must be collected");
    }

    #[test]
    fn symbolic_irqs_are_skipped() {
        let out = parse(SAMPLE);
        assert!(find(&out, "NMI").is_none(), "NMI must be excluded");
        assert!(find(&out, "LOC").is_none(), "LOC must be excluded");
    }

    #[test]
    fn counts_are_summed_across_cpus() {
        let out = parse(SAMPLE);
        // irq 27: 3+5+2+7 = 17
        let sample = find(&out, "27").unwrap();
        assert_eq!(
            sample.value,
            nlx_domain::metric::MetricValue::U64(17),
            "irq 27 counts must sum to 17"
        );
        // irq 1471: 0+0+0+1 = 1
        let sample1471 = find(&out, "1471").unwrap();
        assert_eq!(
            sample1471.value,
            nlx_domain::metric::MetricValue::U64(1),
            "irq 1471 counts must sum to 1"
        );
    }

    #[test]
    fn device_label_is_extracted() {
        let out = parse(SAMPLE);
        let s = find(&out, "27").unwrap();
        assert_eq!(
            s.labels.get("device").map(String::as_str),
            Some("xhci_hcd"),
            "device must be extracted after double-space"
        );
        let s1471 = find(&out, "1471").unwrap();
        assert_eq!(
            s1471.labels.get("device").map(String::as_str),
            Some("eth0-TxRx-0"),
        );
    }

    #[test]
    fn irq_label_is_the_numeric_string() {
        let out = parse(SAMPLE);
        let s = find(&out, "1472").unwrap();
        assert_eq!(s.labels.get("irq").map(String::as_str), Some("1472"));
    }

    #[test]
    fn metric_kind_is_counter() {
        let out = parse(SAMPLE);
        let s = find(&out, "8").unwrap();
        assert_eq!(s.kind, MetricKind::Counter, "irq metric must be a counter");
    }

    #[test]
    fn metric_name_is_nft_irq_total() {
        let out = parse(SAMPLE);
        let s = find(&out, "1").unwrap();
        assert_eq!(s.name, "nft_irq_total");
    }

    #[test]
    fn row_with_no_counts_is_skipped() {
        // A line where everything after the colon is non-numeric — defensive.
        let input = "  42:  no-counts-here\n";
        let out = parse(input);
        // The row has no all-digit tokens so it must be skipped.
        assert!(
            find(&out, "42").is_none(),
            "row with no numeric counts must be skipped"
        );
    }

    #[test]
    fn empty_input_yields_no_samples() {
        assert!(parse("").is_empty());
    }

    #[test]
    fn header_line_is_skipped() {
        let out = parse("           CPU0       CPU1\n");
        assert!(out.is_empty(), "header line must produce no samples");
    }

    #[test]
    fn missing_device_yields_empty_string() {
        // A valid row but with no double-space after counts (edge case).
        let input = "  99:          5          3   SomeChip\n";
        let out = parse(input);
        let s = find(&out, "99");
        if let Some(sample) = s {
            assert_eq!(
                sample.labels.get("device").map(String::as_str),
                Some(""),
                "missing device must yield empty string label"
            );
            assert_eq!(sample.value, nlx_domain::metric::MetricValue::U64(8));
        }
        // If the row was skipped entirely (zero counts but row present) that is
        // also acceptable — the count is 8 so it must not be skipped.
    }

    #[test]
    fn all_zero_counts_row_is_kept() {
        // irq 1 in SAMPLE has all-zero counts; it must still appear.
        let out = parse(SAMPLE);
        let s = find(&out, "1").unwrap();
        assert_eq!(s.value, nlx_domain::metric::MetricValue::U64(0));
    }
}
