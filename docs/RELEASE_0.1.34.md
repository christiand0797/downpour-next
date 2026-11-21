# Downpour Next 0.1.34

Portable Windows x64 build. Read-only security monitoring, local only, unsigned.

## IDN and lookalike names in the DNS cache view

`mіcrosoft.com` with a Cyrillic `і` is a different domain from `microsoft.com`. Name-based blocks and reputation lists
do not catch it, and it may not be listed anywhere yet. The Core confusable detector could already decode and fold such
names; nothing in the product used it.

The resolver-cache capture now assesses every cached name:

- `DomainConfusables.Describe` is the bounded inventory wrapper around the tested `Assess`. Empty, whitespace,
  over-253-character and unparseable names return nothing instead of throwing, so one hostile cache entry cannot fail
  the capture.
- A name carries context only when its decoded form is non-ASCII, mixes writing systems, or resembles one of the fixed
  protected brands. Plain ASCII names carry no extra payload.
- The DNS page adds an **IDN and Lookalike Names** panel: how many names resemble a protected brand, how many decoded
  in total, the original name, the decoded form and the Core verdict, with a `BRAND` / `MIXED` / `IDN` badge.
- `DnsInventoryClient` bounds every new field (1,024 characters each, at most 8 brands) and rejects a null brand list.

This is context, not a verdict. Nothing is blocked, resolved, flushed or rerouted, no alert or finding is raised, the
DGA risk score is unchanged, and no decoded name is written to disk — the assessment lives in the bounded pipe snapshot
only. Shared hosting, IDN registrars and international sites legitimately produce non-ASCII names, so the panel asks a
person to compare forms rather than claiming a compromise.

## Verification

- Debug build: 0 warnings, 0 errors. Full Debug suite: 1,508 passed, 0 failed (9 new in `DnsInventoryTests`).
- Release build from `2a26a4789cad29cf12476b913aa53da6203a215c`: 1,508 tests passed, five self-contained publishes.
- Package: 1,077 entries, 772,675,678 expanded bytes, 52 runtime components.
- Packaged route smoke: every route opened, the sensor pipe answered, the YARA helper loaded 179 rules and the benign
  fixture produced no match, and no new crash entry was written.
- Window smoke: maximized startup, resize/minimize/maximize styles, Restore and resize, CIS startup and owned-service
  shutdown passed.

## Digests

| Asset | Bytes | SHA-256 |
|---|---|---|
| `DownpourNext-win-x64-0.1.34.zip` | 306,519,738 | `c0bac04b65fb0f9176c62d8045681aa280dbaf987308deb4987e191f033447a5` |
| `DownpourNext-0.1.34-sbom.cdx.json` | — | `bd4ef099e6a21806242ccdd3fc187a4aaa871a2a0a3756d685047d746257d0f8` |
| `DownpourNext-0.1.34-SHA256SUMS.txt` | — | `42cf052ce915c5ab56117ee7d9e001e37227a19f351bfbe75988526283f14890` |

## Limits

- The panel has not been viewed at any width, and no real cached IDN name was confirmed on screen. The development
  machine's resolver cache was not inspected for lookalikes, so the empty state is the likely one in this build.
- The protected-brand list is a fixed, small list in Core. An unlisted brand is not covered.
- The binaries are unsigned. A GitHub digest proves the file you downloaded is the file that was uploaded; it does not
  prove who built it.
- A real in-app update exercising the update staging journal and locked-file rollback failure injection are still open.
