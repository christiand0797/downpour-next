# Update apply and rollback

The standalone update helper replaced files and rolled back inline, so the rollback could only be reasoned about, never
run. `StagedUpdateApplier` (DN-086) moves that step into Core so a locked file can stop it in a test.

## What the applier does

`StagedUpdateApplier.Apply(installRoot, stageRoot, backupRoot, relativeFiles, afterFilesApplied)`:

1. **Plans everything first.** Every relative path is resolved and checked with `UpdatePathPolicy.IsStrictChildPath`
   against the install, stage and backup roots; duplicates and missing staged files are refused. Nothing on disk is
   touched during this pass, so a bad manifest cannot leave a half-updated folder.
2. **Backs up, then replaces, one file at a time.** An existing destination is copied to the matching backup path
   (`overwrite: false`, because the staging folder is cleared before each attempt). The new content is copied to a
   temporary name in the destination folder and moved over the destination, so a reader never sees a partially written
   file.
3. **Runs the caller's post-apply step inside the protected region.** The helper passes the restart there. A build that
   applies but cannot start is rolled back with its files, instead of being left in place.
4. **Rolls back in reverse on any failure.** A recorded backup is copied back; a file with no backup did not exist
   before the attempt, so it is deleted. Temporary files are removed. Each file that cannot be restored is counted and
   named in the report rather than silently skipped.

The helper keeps what must stay in the helper: requester and parent-process check, service-exit wait, manifest size and
path limits, per-file SHA-256 verification, the staged-journal gate, the restart and the journal records.

## Journal detail now carries counts

The rollback record used to say "previous files restored where possible". It now says how many files were replaced and
how many were restored, and names up to three that were not:

- `Apply failed after replacing 1 file(s); restored 1.`
- or `… ; 2 could not be restored: a.dll, b.dll.`
- or, when the manifest was refused before the first write, `Apply failed before any installed file was replaced; nothing
  needed to be restored.`

## Tests (`StagedUpdateApplierTests`, 6)

| Test | What it proves |
|---|---|
| `ReplacesFilesAndKeepsThePreviousCopy` | Nested paths are replaced, backups hold the previous bytes, no temporary file is left behind. |
| `ALockedFileStopsTheApplyAndEarlierFilesAreRestored` | A destination held open with `FileShare.None` stops the apply at that file, the file replaced before it is restored to its old bytes, the locked file is unchanged, and the report says 1 replaced / 1 restored / 0 unrestored. |
| `AFileThatCannotBeBackedUpIsLeftUnchangedAndNotCounted` | When the first file cannot even be read for backup, nothing is replaced or restored and both files keep their old bytes. |
| `AFailedRestartRestoresEveryFileItReplaced` | A throwing post-apply step restores every replaced file, including one in a nested folder. |
| `AFailedApplyRemovesFilesThatDidNotExistBefore` | A file added by a failed attempt is deleted, and the file that stopped the update keeps its old bytes. |
| `AnUnsafePathOrMissingStagedFileIsRefusedBeforeAnythingChanges` | `../escape.txt` and a missing staged file both throw `InvalidDataException` with the already-written file untouched. |

Debug build: 0 warnings, 0 errors. Full Debug suite: 1,544 passed, 0 failed.

## Still not proven

- **A real in-app update.** No published build has been applied over an installed older build through this code path on
  this machine. The tests drive the same applier the helper calls, with synthetic packages and no restart of a real app.
- **The `NotRestored` branch.** It is only reachable when restoring a file itself fails (for example the file became
  locked during rollback). The report and journal wording are implemented, but no test forces a restore to fail.
- **Elevation and ACLs.** The portable build runs unelevated; a package extracted into a folder the account cannot write
  would fail earlier, in staging, which is unchanged by this slice.
