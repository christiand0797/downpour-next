# Update staging journal

A portable self-update replaces executables in the application folder. If the app, the helper or the machine stops
between "downloaded" and "applied", the next start must be able to say what happened instead of guessing. This journal
is that record.

## Where it lives

`%LOCALAPPDATA%\DownpourNext\updates\update-journal.json`, outside the portable install folder, so deleting or replacing
the package does not delete the history. It is local per-user state: version, state, UTC time and a bounded message. It
contains no install path, user name, machine name, host address or package content.

## States

`UpdateStagingJournal` (Core) defines the legal transitions:

| From | To | Meaning |
|---|---|---|
| — | `Downloaded` | The published SHA-256 matched the downloaded ZIP. |
| `Downloaded` | `Verified` | Extraction finished and every extracted file has a digest recorded; verification detail is mandatory. |
| `Verified` | `Staged` | `manifest.json` and the standalone helper are in place; nothing in the install folder was touched. |
| `Staged` | `Applied` | The helper replaced the files and restarted Downpour. Terminal. |
| `Downloaded`, `Verified`, `Staged` | `RolledBack` | The attempt was abandoned or failed before or during apply; the previous build is the one running. |
| `RolledBack` | `Downloaded` | A later check started a new cycle. |

`Applied` is terminal. A new version starts a new cycle rather than pretending an applied package moved backwards.

## Who writes what

- **Desktop** (`PortableUpdateInstaller`): starts a cycle only after `DownloadVerifiedPackageAsync` matched the release
  digest, records `Verified` after `UpdateArchive.ExtractToStage` returned the per-file hashes, records `Staged` after
  the manifest and helper copy. Any failure on that path records `RolledBack` best-effort, then clears the staging
  folder as before.
- **Helper** (`Downpour.UpdateHelper`): before replacing any file, it requires the newest record to be `Staged` for the
  exact `releaseVersion` from the signed-by-digest manifest. It records `Applied` after the restart, or `RolledBack`
  after restoring the previous files where Windows permits. An unreadable or missing journal fails closed with
  "check for updates again" rather than applying from an unknown state.
- **Desktop start**: when a previous `.downpour-update` folder needs attention, the existing error message now ends
  with the recovery sentence for the last journal state, for example "A package was staged but not applied; it is safe
  to apply after a fresh signature check."

## Bounds and failure behaviour

- At most 32 records, 300 characters per detail, 64 KiB for the whole file. The oldest records are dropped first.
- Writes go to a temporary file in the same directory and replace the journal atomically, so a crash cannot leave a
  half-written JSON document as the newest state.
- A missing file is an empty journal. Invalid JSON, an unknown schema version, an unknown state, a default timestamp
  or an out-of-bounds record is an error, not silently ignored.
- `Begin` closes an in-progress record as `RolledBack` with "Abandoned; a new update check started." before opening a
  new cycle, so a stale state cannot make the next attempt look like a continuation.

## What this does not do

- It is not a signature and does not authenticate the package. The ZIP digest comes from GitHub release metadata;
  publisher signing and independent provenance remain separate work (`docs/UPDATE_TRUST.md`).
- A helper shipped before 0.1.33 ignores the journal. The journal is adopted from the first update whose helper is
  0.1.33 or later, so the 0.1.32 → 0.1.33 update writes the record but is applied by the older helper.
- Deleting the file is not destructive to installed files, but the helper will then refuse a staged package and ask
  for a fresh update check.
- It does not survive a different Windows user account, because it is per-user state; the install folder is what moves
  with the portable package.

## Verification

`UpdateJournalWiringTests` covers the round trip, the mandatory verification detail, the staged gate, illegal
transitions, abandoned-cycle rollback, best-effort failure recording, record/detail trimming, damaged and oversized
files, and version validation. The Debug build is clean and the full suite passes. A real in-app update using the
journal has not been exercised yet; the next release records the first observation.
