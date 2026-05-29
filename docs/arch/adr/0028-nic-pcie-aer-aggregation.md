---
status: accepted
date: 2026-05-29
deciders: [eonf]
consulted: []
informed: []
---

# Aggregate nic_pcie AER counters to bound exposition cardinality

## Context and Problem Statement

ADR-0027 introduced the opt-in `nic_pcie` collector
(`crates/nlx-procfs/src/nic_pcie.rs`), which reads PCIe link health and
Advanced Error Reporting (AER) counters from
`/sys/class/net/<dev>/device/`. It already restricts itself to network
interfaces (it enumerates `/sys/class/net`, not all of
`/sys/bus/pci/devices`) and skips SR-IOV virtual functions via the
`device/physfn` symlink.

A live capture on a production host (buckbeak, 2026-05-29) exposed a
cardinality problem that the design review missed: the collector emitted
**3920 series — 34 % of the entire 11 537-series scrape**.

Root cause is the **AER per-bit `kind` label**, not the device count. The
kernel `aer_dev_{correctable,fatal,nonfatal}` files break each error type
down into individual error bits (one line per bit, e.g. `RxErr`, `BadTLP`,
`BadDLLP`, …). The collector emitted one counter per bit:

- `aer_dev_correctable` ≈ 8 bits
- `aer_dev_fatal` ≈ 23 bits
- `aer_dev_nonfatal` ≈ 23 bits

That is ~54 AER series per device. Across the host's 70 non-VF NIC PCIe
endpoints: `70 × (2 link + 54 AER) ≈ 3920`. The overwhelming majority are
**permanently-zero** error-bit counters on healthy links — high storage and
scrape cost for near-zero signal.

## Decision

The `nic_pcie` collector **aggregates each AER file into a single counter
per device** and **drops the `kind` label**:

- `nft_nic_pcie_aer_correctable_total{device}` — sum of all correctable
  error bits for the device.
- `nft_nic_pcie_aer_fatal_total{device}` — sum of all fatal bits.
- `nft_nic_pcie_aer_nonfatal_total{device}` — sum of all non-fatal bits.

Aggregation = **sum of every per-bit line** in the AER file, still skipping
the kernel's `TOTAL_<TYPE>` summary line (so the value is computed from the
bits and the summary is never double-counted; the result equals the kernel
total by construction).

`nft_nic_pcie_link_speed_gts{device}` and `nft_nic_pcie_link_width{device}`
are unchanged.

Resulting cardinality: **5 series per device** (2 link + 3 AER), i.e.
`~|non-VF NIC PCIe endpoints| × 5`. On buckbeak this is `70 × 5 = 350`
series — a **~90 % reduction** (3920 → 350).

## Consequences

- **Good**: the alertable signal is preserved. Operators alert on "is the
  AER error count for this device increasing?", which is exactly the
  aggregated total. The per-bit breakdown was debug-grade detail.
- **Good**: cardinality is now proportional to device count only, with a
  small constant factor — no hidden per-error-type fan-out.
- **Bad / mitigation**: the specific error bit (e.g. `BadTLP` vs `RxErr`)
  is no longer in Prometheus. When triaging a flapping link, read the raw
  sysfs file (`cat /sys/class/net/<dev>/device/aer_dev_correctable`),
  `lspci -vvv`, or `ethtool` directly on the host. This is a deliberate
  debug-detail-vs-cardinality trade.
- **Contract**: `docs/arch/schemas/metric_contract.cue` updates the three
  AER descriptors to `labels: ["device"]` and a `~|PFs|` cardinality bound.
- This ADR **amends ADR-0027** for the `nic_pcie` AER metrics only; the
  rest of ADR-0027 (isolation in `nlx-procfs`, allowlist, default-off,
  VF-skip, no duplication) stands.

## Validation

- `cargo test -p nlx-procfs` (pure crate — builds on macOS) covers the
  aggregation: a multi-bit AER sample sums to one counter, the `kind` label
  is absent, and the `TOTAL_<TYPE>` line is excluded from the sum.
- `cue vet` over `metric_contract.cue` after the label change.
- A live re-capture (redeploy on buckbeak) confirms the `nic_pcie` series
  count drops to `~5 ×` the device count with no duplicate series.
