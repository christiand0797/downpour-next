# Downpour Next 0.1.39

Portable Windows x64 build. Read-only security monitoring, local only, unsigned.

## A provable update rollback

The update helper replaced files and rolled back inline in `Program.Apply`. That meant the documented gap — what happens
when a package file cannot be replaced because another process holds it open — could only be reasoned about, never run.

`StagedUpdateApplier` in Core now owns that step:

1. **Plan and validate before writing.** Every relative path is resolved and checked against the install, staging and
   backup roots; duplicates and missing staged files are refused. Nothing is touched in this pass.
2. **Back up, then replace.** Each existing destination is copied to its backup path; the new bytes go to a temporary
   name in the same folder and are moved over the destination, so no reader sees a partly written file.
3. **Run the restart inside the protected region.** A build that applies but cannot start is rolled back with its files.
4. **Restore in reverse on any failure.** Backups are copied back, files that did not exist before are removed,
   temporary files are deleted, and every file that could not be restored is counted and named.

The helper keeps the requester and parent-process check, the service-exit wait, manifest size and path limits, per-file
SHA-256 verification, the staged-journal gate, the restart and the journal records.

**The journal now reports counts.** A rolled-back record says `Apply failed after replacing 1 file(s); restored 1.`
instead of "previous files restored where possible", and names up to three files it could not restore. A refusal before
the first write says nothing needed restoring.

## Verification

- Debug build: 0 warnings, 0 errors. Full Debug suite: 1,544 passed, 0 failed (6 new in `StagedUpdateApplierTests`).
- Release build from `62028ba59504e57f273d3b0c2f8779597a7e57ee`: 1,544 tests passed, five self-contained publishes;
  every executable reports `0.1.39+62028ba59504e57f273d3b0c2f8779597a7e57ee`.
- The locked-file test holds a destination open with `FileShare.None` after one file was already replaced: the apply
  stops there, the earlier file returns to its old bytes, the locked file is unchanged, and the report is
  1 replaced / 1 restored / 0 unrestored.
- Other new cases: nested paths with backups and no leftover temporary file, a file that cannot even be backed up being
  left alone and not counted, a failed restart restoring every replaced file, a file added by a failed attempt being
  removed, and `../escape.txt` or a missing staged file refused before anything changes.
- Package: 1,077 entries, 772,874,066 expanded bytes, 52 runtime components.
- Packaged route smoke: every route opened, the sensor pipe answered, the YARA helper loaded 179 rules and the benign
  fixture produced no match, no new crash entry; the owned desktop, service and scanner stopped.
- Window smoke: maximized startup, resize/minimize/maximize styles, Restore and resize, CIS startup and owned-service
  shutdown passed.

## Digests

| Asset | Bytes | SHA-256 |
|---|---|---|
| `DownpourNext-win-x64-0.1.39.zip` | 306,595,059 | `5b9e1239f2ccf9a755db62e86b0f2bd0d4c102a66398d57ecbd2db002bfa496e` |
| `DownpourNext-0.1.39-sbom.cdx.json` | 26,237 | `58867cdb111e5ae10d776b016844d391bfda00d36be86fbdb83aa72dac7fe3b7` |
| `DownpourNext-0.1.39-SHA256SUMS.txt` | 198 | `5586c3189005494ff759ba962f87cd25bfbec04e7266b048489daeeb69e2f494` |

## Limits

- **A real in-app update is still not exercised.** No published build has been applied over an installed older build by
  this code on this machine; the tests drive the same applier with synthetic packages and do not restart a real app.
- **The "could not be restored" branch has no test.** It is only reachable when restoring a file itself fails during
  rollback. The report and journal wording exist, but no test forces a restore to fail.
- The backup folder is removed only after a successful restart; a failed attempt leaves it under
  `.downpour-update\backup` inside the app folder until the next staged update clears the state directory.
- Binaries are unsigned. A GitHub digest proves the file you downloaded is the file that was uploaded; it does not prove
  who built it.
- Still blocked: release signing (offline key custody), ARM64 (no arm64 YARA-X module), hosted CI (billing), egress byte
  volume (ETW or administrator ESTATS) and metered feed scheduling (no documented session-0 signal).
