# Downpour Next 0.1.33

Windows x64 portable development release. This build wires the update staging journal into the updater and its
standalone helper; no existing screen or detection rule changed.

- Source: `0736bc6eb085ef2381c73a3b2c2df6fee442383e` (binaries report `0.1.33+0736bc6eb085ef2381c73a3b2c2df6fee442383e`; the tag points at the following docs commit).
- Archive: 1,077 entries, 772,632,454 expanded bytes, 306,499,568 bytes zipped.
- ZIP SHA-256: `ce58c1a8f62da43233be542a6df04c8d417b3630778377d65c45f4e903d107fe`
- SBOM (CycloneDX, 52 runtime components) SHA-256: `bc0b1df7b1f5f7a9c47ed1efe403cd04727570df3381731646662d0c48c5dc27`
- SHA256SUMS SHA-256: `5b256c7b6b2628f7701f1408cb9d3d47c9768d37dca507228c3b46a7de2a47c0`

## What changed

- **Update staging journal (DN-074).** `UpdateJournalStore` persists the existing `UpdateStagingJournal` state machine
  to `%LOCALAPPDATA%\DownpourNext\updates\update-journal.json`, outside the portable folder. It records the target
  version, state, UTC time and one bounded message, with no install path, account name, host address or package
  content.
- The desktop writes `downloaded` only after the published ZIP digest matched, `verified` after extraction returned
  the per-file digests (a verification detail is mandatory), and `staged` after `manifest.json` and the standalone
  helper are in place. A failure on that path records `rolled back` best-effort before the staging folder is cleared.
- The standalone helper now reads the journal before replacing any file. It requires the newest record to be `staged`
  for the exact version in the manifest, then records `applied` after the restart or `rolled back` after restoring
  previous files where Windows permits. A missing, damaged or oversized journal fails closed and asks the user to
  check for updates again.
- Every transition is bounded (32 records, 300 characters per detail, 64 KiB file) and written to a temporary file
  that atomically replaces the journal. `UpdateStagingJournal` can now close an abandoned `downloaded` or `verified`
  cycle as `rolled back`; `applied` stays terminal.
- Because the 0.1.32 → 0.1.33 apply is performed by the already-installed older helper, that first update writes the
  journal but does not enforce it. The first helper that enforces the staged gate ships in this build.
- Everything shipped in 0.1.32 remains: the offline alert replay gate, per-process exploit mitigations, rule coverage,
  listener process attribution, the 58-source feed catalog, suppressions, retention/clock warnings and the existing
  read-only inventory routes.

## Verification

- Clean committed Release build: 0 warnings, 0 errors.
- Release test suite: 1,499 passed, 0 failed (includes 4 new `UpdateJournalWiringTests`).
- The desktop and update helper also compile clean in Debug outside the solution test build.
- Package script verified every executable's version and embedded source, the WinUI resource index, loose assets, the
  YARA-X native digest, the SBOM and every ZIP entry by SHA-256.
- Packaged route smoke: every route started, received owned-service telemetry and closed gracefully; the YARA helper
  loaded 179 rules and the benign fixture produced no match.
- Window smoke: maximized startup, resize/minimize/maximize styles, Restore, resize while restored and CIS-owned
  service shutdown all passed. No Downpour desktop, service or scanner was left running.

## Known limits

- No real in-app update has exercised the journal yet, and failure-injection for a locked package file is still open.
  The state machine, staged gate and recovery text are covered by tests only.
- The journal is local diagnostic state, not an authentication mechanism. It does not replace publisher signing or an
  independently authenticated update manifest; binaries and updater metadata remain unsigned.
- Clean-machine deployment, ARM64, elevated crash/reboot acceptance and GitHub-hosted CI (account billing) remain open.
