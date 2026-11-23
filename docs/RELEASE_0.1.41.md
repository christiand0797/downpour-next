# Downpour Next 0.1.41

Portable Windows x64 build. Read-only security monitoring, local only, unsigned.

## A rollback that cannot restore says so

The update helper replaces every package file through `StagedUpdateApplier`, and a failure restores each touched file in
reverse. That restore can itself be refused — another process opened the file while the restart step was failing. 0.1.39
counted those files, but nothing reached that branch and the dialog still said:

> Existing package files were restored where possible.

A sentence with no number is the same problem the journal had before 0.1.39. The counts now produce one factual sentence
in `StagedUpdateApplyReport.Describe()`:

- `Replaced 2 file(s) and restored 1; 1 could not be restored: a.txt.`
- `Replaced 2 file(s) and restored 2.`
- `No installed file had been replaced, so nothing needed to be restored.`

The helper's failure dialog and the journal's rolled-back record both call it, so the person and the file cannot read
different accounts of one failure. The dialog adds "Extract the portable package again before relying on this
installation" only when a file was not restored; an exception thrown before the applier runs reports that no package
file was replaced, which is what the helper's own manifest and digest checks guarantee.

## What the test now forces

`ARestoreThatItselfFailsIsCountedAndNamed` builds the failure a mixed installation would leave behind:

1. Two installed files, `a.txt` and `b.txt`, are replaced from the staging folder.
2. The post-apply step — the restart in the real helper — opens `a.txt` with `FileShare.None` and then throws.
3. The reverse rollback restores `b.txt` and is refused `a.txt`.

The report is 2 replaced / 1 restored / `a.txt` named, the message says `1 of 2`, and `a.txt` keeps the new bytes. The
test asserts that too, so a future change cannot quietly describe a mixed folder as a clean rollback. No temporary file
is left behind.

`ARefusalBeforeTheFirstWriteSaysNothingNeededRestoring` pins the other two sentences, so the wording that reaches the
dialog cannot drift from the counts.

## Verification

- Debug build: 0 warnings, 0 errors. Full Debug suite: 1,547 passed, 0 failed (2 new tests).
- Release build from `4644746b0bf62b0c592545ed5a72ff34a9867b7d`: 1,547 tests passed, five self-contained publishes;
  every executable reports `0.1.41+4644746b0bf62b0c592545ed5a72ff34a9867b7d`.
- Package: 1,077 entries, 772,881,118 expanded bytes, 52 runtime components.
- Packaged route smoke: every route opened, the sensor pipe answered, the YARA helper loaded 179 rules and the benign
  fixture produced no match, no new crash entry; the owned desktop, service and scanner stopped.
- Window smoke: maximized startup, resize/minimize/maximize styles, Restore and resize, CIS startup and owned-service
  shutdown passed.

## Digests

| Asset | Bytes | SHA-256 |
|---|---|---|
| `DownpourNext-win-x64-0.1.41.zip` | 306,599,535 | `0f1e2e2f5d7180e4604bbe3c4a2ada5edc444de29f866efb426b6f4c9352bd95` |
| `DownpourNext-0.1.41-sbom.cdx.json` | 26,237 | `10bcd97da285189c5f6879844e074eda7abad9be31b2a375492e860da22ce977` |
| `DownpourNext-0.1.41-SHA256SUMS.txt` | 198 | `aab0bc8217c69cfaed413d287db9620967e7cf555267eb432fce218194f9a1e9` |

## Limits

- **The dialog was not viewed.** The sentences are asserted by tests, but no one has seen the message box. Forcing it
  needs a disposable install and a deliberate failure; that is the next check for this path.
- **A real in-app update is still not exercised.** No published build has been applied over an installed older build
  through this code path on this machine. The tests drive the same applier the helper calls, without a restart of a real
  app.
- The rest of the update path is unchanged: the requester check, service-exit wait, manifest bounds, per-file SHA-256
  verification and the staged-journal gate all ran as before. Nothing about elevation, signing or ACLs changed.
- Binaries are unsigned. A GitHub digest proves the file you downloaded is the file that was uploaded; it does not prove
  who built it.
- No detection rule, route or stored datum changed in this release.
