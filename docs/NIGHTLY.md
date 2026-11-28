# Release channels and the nightly task

Downpour Next ships on two channels from the same commit:

| Channel | Tag | Audience | Published by |
| --- | --- | --- | --- |
| Stable | `v0.1.45` | Latest release | `tools/release/Cut-Release.ps1` |
| Nightly | `nightly-20261128` | Prerelease, never Latest | `tools/release/Invoke-Nightly.ps1` |

Both channels build the same portable x64 package and pass the same gates. A nightly is a verified
build of `main`; it is not a different code path and it is never promoted to Latest automatically.
Promotion is a stable cut from the same commit, so the artifacts people are told to trust always
come from `Cut-Release.ps1`.

## What the nightly does

1. Refuses a dirty tree, a non-`main` branch, or a clone whose `origin` is not
   `christiand0797/downpour-next`.
2. `git fetch origin main` and `merge --ff-only`. A diverged clone fails; nothing is discarded.
3. Skips when `HEAD` is the commit the previous nightly already published (unless `-Force`).
4. Runs `Build-Portable.ps1`: restore, Release build, full test suite, five published executables.
5. Runs `Package-Portable.ps1`: verifies every executable reports the built commit, writes the
   CycloneDX SBOM, the file manifest and the archive, then re-opens the archive and re-hashes every
   entry.
6. Runs `Test-Portable.ps1`: every route in `capabilities.json` opens, answers telemetry and closes
   with its owned service, the YARA helper scans a benign fixture, and the native window starts
   maximized, restores, resizes and closes gracefully.
7. Publishes `nightly-YYYYMMDD` as a **prerelease** at that exact commit, then compares the uploaded
   asset digests with the local files.
8. Deletes nightly releases older than seven days (tags included). Stable releases are never touched.
9. Writes `artifacts/nightly/<date>-report.md` with the commit, test count, digests and the next
   queued `WORK_QUEUE.json` tasks.

A failed test gate is rerun once, in full, against the same binaries. The first attempt's failing
tests are named in the log, the report and the release notes, and a failure that repeats stops the
nightly. This exists because the first build in a fresh clone can miss the suite's own wall-clock
budgets (the 200,000-domain index and the ten-second pipe connects) while Windows Defender scans two
gigabytes of new binaries: the first run of this task failed five timing tests and all five passed in
one second once the clone was warm. It is not a way past a real regression, and `-NoTestRetry`
disables it.

A failure stops at the failing gate and leaves the previous nightly and the stable release in place.
Each run writes its own `artifacts/nightly/logs/nightly-<date>-<time>.log` so a rerun cannot
interleave with the failed attempt; `artifacts/nightly/state.json` records the last commit, tag and
result. Unattended builds set `MSBUILDDISABLENODEREUSE=1` and `UseSharedCompilation=false`: this
clone's second build wedged inside the shared Roslyn compiler server with the process idle, and a
scheduled task has no console at which a person would notice. The cost is a slightly slower build.

## What it does not do

The schedule keeps the build, test, package, smoke and release loop running daily; it does not write
new features by itself. Code changes still come from a reviewed commit on `main`, and the nightly
ships them only after every gate passes. That is deliberate: an unattended process that edits its own
detection logic or action broker would be a supply-chain risk with no reviewer.

## Setup

```powershell
# Once: shallow clone of main at %USERPROFILE%\DownpourNext, then register the task.
pwsh ./tools/release/Register-NightlyTask.ps1 -Bootstrap

# Inspect it.
Get-ScheduledTask -TaskName DownpourNightly
Get-ScheduledTaskInfo -TaskName DownpourNightly

# Run it now instead of waiting for 03:30.
Start-ScheduledTask -TaskName DownpourNightly

# Remove it.
pwsh ./tools/release/Register-NightlyTask.ps1 -Unregister
```

The task runs as the signed-in user at **limited** privilege, only while that user is logged on. The
`gh` token stays in the user's keyring; no credential is stored in the task, the repository or the
package. The interactive logon is also what makes the native window smoke meaningful. The task
starts when the machine was unavailable at the scheduled time (`-StartWhenAvailable`), keeps running
on battery, and is limited to two hours.

The dedicated clone matters: the agent worktree this tooling is developed in is temporary, and a
scheduled task pointing into it would fail silently after cleanup. `-RepoPath` can point anywhere
that is a clone of `downpour-next` on `main`.

## Manual use

```powershell
# Normal nightly, honouring the unchanged-HEAD skip.
pwsh ./tools/release/Invoke-Nightly.ps1

# Rebuild and republish today's nightly even without new commits.
pwsh ./tools/release/Invoke-Nightly.ps1 -Force

# Local build and smoke only; no GitHub release.
pwsh ./tools/release/Invoke-Nightly.ps1 -NoPublish -Force

# Keep more history.
pwsh ./tools/release/Invoke-Nightly.ps1 -KeepDays 30
```

## Cutting a stable release

```powershell
# Notes are generated from commit subjects when docs/RELEASE_<version>.md is absent; review, then run.
pwsh ./tools/release/Cut-Release.ps1 -Version 0.1.45

# Package and smoke without pushing or publishing.
pwsh ./tools/release/Cut-Release.ps1 -Version 0.1.45 -NoPublish
```

`Cut-Release.ps1` refuses a dirty tree, an existing tag (local or remote) and a non-`main` branch
unless `-KeepWorktree` is explicit. It commits the version bump and notes, builds from that commit,
packages, smokes, tags, pushes the commit and tag, publishes as Latest, and verifies the uploaded
digests. If any gate fails, nothing is pushed and nothing is published.

## Reusable pieces

- `Package-Portable.ps1` — manifest, SBOM, archive verification, checksums, evidence JSON.
- `Test-Portable.ps1` — packaged route sweep, YARA helper and native window smoke.
- `tools/ci/run-gates.ps1` — restore/build/test/replay gate for a plain build (no packaging).

The old `artifacts/v<version>-package.ps1` copies were the same logic with a version pasted in; they
are no longer needed and are not part of the repository.
