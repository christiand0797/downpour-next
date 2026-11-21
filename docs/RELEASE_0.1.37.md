# Downpour Next 0.1.37

Portable Windows x64 build. Read-only security monitoring, local only, unsigned.

## Weekly summary from the alert store

`WeeklyDigest` was a tested shape with no producer. The service now writes one Markdown file per ISO week:

`%LOCALAPPDATA%\DownpourNext\reports\weekly-<ISO year>-W<week>.md`

It runs at start + 2 minutes and then every 6 hours, and only after channel readability has been recorded for seven
days, so a fresh install is never described as a quiet week. The file is written to a temporary name and moved into
place, is readable only by the current user, and is capped at 40 lines / 32 KiB.

The facts are one SQL aggregate each from the alert store: alerts first/last seen in the window, open now and the age of
the oldest open finding, acknowledgements and suppressions this week, active suppressions and the matches they hid,
suppressions that expired in the window, evictions, sensors that cannot read their source, and the most active rule.

**What it refuses to claim.** `DigestInputs` now allows unknown counts. The store holds no weekly autostart history and
has no `Resolved` state, so those lines say *not recorded* instead of printing a zero that reads like "nothing
happened". The quiet-week sentence appears only when the autostart, hidden-match and sensor counts are all known and
zero. No channel measurement means readability is unknown, not zero blind sensors.

Settings → **Storage & cache** has a **Weekly summary** row that opens the reports folder, and says so when no report
exists yet. The folder is fixed, not user-selectable.

## Verification

- Debug build: 0 warnings, 0 errors. Full Debug suite: 1,531 passed, 0 failed (10 new in `WeeklyDigestTests`).
- Release build from `5eb0797a4a17c423d426fdbb778957a00055134f`: 1,531 tests passed, five self-contained publishes.
- Package: 1,077 entries, 772,762,002 expanded bytes, 52 runtime components.
- Packaged route smoke: every route opened, the sensor pipe answered, the YARA helper loaded 179 rules and the benign
  fixture produced no match, no new crash entry.
- Window smoke: maximized startup, resize/minimize/maximize styles, Restore and resize, CIS startup and owned-service
  shutdown passed.
- The packaged service run created `%LOCALAPPDATA%\DownpourNext\reports` and left it **empty**, which is the seven-day
  gate working: this machine's alert store has watched for less than a week.

## Digests

| Asset | Bytes | SHA-256 |
|---|---|---|
| `DownpourNext-win-x64-0.1.37.zip` | 306,550,418 | `f49c1dfdf4f34609cbd975bd4d8498c2d4dbfebf2ea80d16491d6d4049c3a3c4` |
| `DownpourNext-0.1.37-sbom.cdx.json` | — | `bc63bbf9084f1f1e4afb9823099f8a91806c838fd163f7afbe7724912c4308df` |
| `DownpourNext-0.1.37-SHA256SUMS.txt` | — | `0ec44e9a0d1d5b11fc459dbe815682bf4dcc54e0f2557573ca246c428e6f1623` |

## Limits

- No report content has been produced on this machine yet, because the store is younger than a week. The rendered
  Settings row and the report file were not viewed.
- The schedule is a start-time plus six-hour check, not a Monday-midnight timer.
- The output folder cannot be chosen by the user yet.
- The binaries are unsigned. A GitHub digest proves the file you downloaded is the file that was uploaded; it does not
  prove who built it.
- A real in-app update exercising the update staging journal and locked-file rollback failure injection are still open.
