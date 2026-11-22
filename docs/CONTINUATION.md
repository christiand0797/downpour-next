# Continuing Downpour Next work

Everything needed to resume without re-reading the whole conversation.

## Resume command

From the repository root, run this first; it prints the exact state:

```bash
git -C . log --oneline -3 && git status --porcelain && \
  dotnet build Downpour.slnx -c Debug -v q -nologo | tail -3 && \
  dotnet test Downpour.slnx -c Debug --no-build --nologo | grep -E "Passed!|Failed!"
```

Then pick the next unchecked item in `TODO.md` / the first open task in `WORK_QUEUE.json`. Commit one focused slice at a
time with the project's footer, push to `https://github.com/christiand0797/downpour-next.git`, and update
`SHARED_CONTEXT.md`, `WORK_QUEUE.json`, `TODO.md` and `AGENT_REGISTRY.json` in the same commit.

## Release loop

For a new version (the example cuts 0.1.38; substitute the version, the previous embedded hash and the commit):

```bash
# 1. bump
sed -i 's/0\.1\.37/0.1.38/g' Directory.Build.props   # also Assembly/FileVersion
git commit -am "chore: bump version to 0.1.38" && COMMIT=$(git rev-parse HEAD)
# 2. build (background it; it runs Release tests and five publishes)
nohup pwsh -NoProfile -File Build-Portable.ps1 > artifacts/build-0.1.38.log 2>&1 &
# 3. copy the version scripts and point them at the embedded commit, read from an executable
for s in package smoke window-smoke; do
  sed -e 's/0\.1\.37/0.1.38/g' -e "s/5eb0797a4a17c423d426fdbb778957a00055134f/$COMMIT/g" \
    artifacts/v0.1.37-$s.ps1 > artifacts/v0.1.38-$s.ps1
done
# 4. package, route smoke, window smoke (background each, poll the log)
pwsh -NoProfile -File artifacts/v0.1.38-package.ps1
pwsh -NoProfile -File artifacts/v0.1.38-smoke.ps1
pwsh -NoProfile -File artifacts/v0.1.38-window-smoke.ps1
# 5. notes, tag, publish, verify digests
gh release create v0.1.38 -R christiand0797/downpour-next --title "Downpour Next 0.1.38" \
  --target "$(git rev-parse HEAD)" --notes-file docs/RELEASE_0.1.38.md --latest \
  artifacts/DownpourNext-win-x64-0.1.38.zip artifacts/DownpourNext-0.1.38-sbom.cdx.json \
  artifacts/DownpourNext-0.1.38-SHA256SUMS.txt
gh release list -R christiand0797/downpour-next --limit 3
gh release view v0.1.38 -R christiand0797/downpour-next --json assets \
  --jq '.assets[] | "\(.name) \(.size) \(.digest)"'
```

The package script checks each executable's `ProductVersion` against the recorded commit. Build after the last commit
that touches source or docs: the SDK stamps HEAD into `ProductVersion` at compile time, so any commit landing while the
build runs changes the hash it expects. Read the hash from an executable (`(Get-Item …).VersionInfo.ProductVersion`) and
pin that in the scripts rather than assuming the bump commit. Commit the docs first and pass `--target "$(git rev-parse
HEAD)"` so the tag points at a pushed commit; the package script must keep pinning the embedded hash, not the tag.

## Current state (end of 0.1.39)

- Published: `v0.1.39` as Latest, built from `62028ba5`; ships the provable update rollback. ZIP 306,595,059 bytes sha256
  `5b9e1239…`, SBOM `58867cdb…`, SHA256SUMS `5586c318…`; 1,544 Release tests, 1,077 package entries, every packaged
  route (179 YARA rules) and the window smoke passed. Details in `docs/RELEASE_0.1.39.md`.
- Shipped in 0.1.39 (DN-086): `StagedUpdateApplier` (Core) validates every path and staged file before writing, backs up
  each destination, moves new bytes in through a temporary name, runs the restart inside the protected region and
  restores every touched file in reverse on failure. The journal records how many files were restored. A destination
  held open with `FileShare.None` now proves the earlier file is restored. A real in-app update is still not exercised.
  Details in `docs/UPDATE_ROLLBACK.md`.

- Published previously: `v0.1.38`, built from `7f0a88a0`; ships portable preferences. ZIP 306,576,286 bytes sha256
  `04761b06…`, SBOM `f1f26bc6…`, SHA256SUMS `fa2d6964…`; 1,538 Release tests, 1,077 package entries, every packaged
  route (179 YARA rules) and the window smoke passed. Details in `docs/RELEASE_0.1.38.md`.
- Shipped in 0.1.38 (DN-084): Settings → Storage & cache exports the eight appearance and alert switches as a
  passphrase-encrypted `.dpnb` file and imports them behind a change list. Suppressions, cases, feed credentials,
  machine/account detail and the two setup acknowledgements are excluded, and a wrong passphrase, foreign schema,
  unknown name or bad value refuses the whole document. Dialogs not clicked by hand. Details in
  `docs/PORTABLE_SETTINGS.md`.

- Published previously: `v0.1.37`, built from `5eb0797a`; ships the weekly summary. ZIP 306,550,418 bytes sha256
  `f49c1dfd…`, SBOM `bc63bbf9…`, SHA256SUMS `0ec44e9a…`; 1,531 Release tests, 1,077 package entries, every packaged
  route (179 YARA rules) and the window smoke passed. Details in `docs/RELEASE_0.1.37.md`.
- Published previously: `v0.1.36` built from `7d1d83d9`; ships the TCP listener cross-view. ZIP 306,526,663 bytes
  sha256 `3b679a9d…`, SBOM `803638f8…`, SHA256SUMS `6f0d7983…`; 1,522 Release tests.
- Shipped in 0.1.37 (DN-082): `WeeklyDigest` takes nullable counts, `SecurityAlertRepository.ReadWeeklyDigestFactsAsync`
  supplies one SQL aggregate per fact, and `WeeklyDigestWorker` writes one file per ISO week into the reports folder at
  start + 2 minutes and every 6 hours, gated on seven days of channel observation. Autostarts and resolved findings stay
  **Not recorded** because the store does not hold them. The packaged service run created the empty reports folder, which
  is the gate working; no report exists on this machine yet. Details in `docs/WEEKLY_DIGEST.md`.
- Shipped in 0.1.36 (DN-080): `NetworkInventoryProvider.DescribeListenerViewDisagreement` compares the managed listener
  list with the native owner table, reports one to ten one-sided endpoints as a consistency anomaly (never tampering)
  and stays silent above ten or when either table is empty. Read-only; nothing persisted. Whether this machine's views
  disagreed, and the warning on the Network page, were not inspected. Details in `docs/PORT_CROSSVIEW.md`.
- Shipped in 0.1.35 (DN-078): `OnboardingPlan.StateFrom` derives the setup state from the feed snapshot, the alert
  store's 24-hour observation window and two local acknowledgements, and the Dashboard shows one Setup step at a time
  and hides the card when ready. A genuine first-download failure says `FEEDS BLOCKED` and is worded as a real failure;
  an unanswered service or a future observation start never counts as progress. The acknowledgements record that the
  explanation was seen, not that elevation exists. The card was not viewed by hand. Details in `docs/ONBOARDING.md`.
- Shipped in 0.1.33 (DN-074): `UpdateJournalStore` records downloaded → verified → staged under
  `%LOCALAPPDATA%\DownpourNext\updates\update-journal.json` (32 records / 300-character details / 64 KiB, atomic
  replace). The desktop writes the transitions and the standalone helper refuses any package whose newest record is
  not staged for that exact version, then records applied or rolled back. A damaged journal fails closed. 1,499 tests;
  a real in-app update has not been exercised. Details in `docs/UPDATE_JOURNAL.md`.
- Shipped in 0.1.32: `AlertProjection` owns the event-to-alert identity in Core; `AlertReplayRunner` replays a
  synthetic 12-record corpus (10 expected alerts) through the current catalog, and `run-gates.ps1` stops on any
  missing, unexpected or severity-changed alert. A tampered corpus exited 1; restored exited 0. Full suite 1,495.
- Shipped in 0.1.31: `ProcessMitigationProvider` reads CFG/ACG/CIG/non-Microsoft DLL blocking/DEP/ASLR with
  `GetProcessMitigationPolicy`, keeps one row per image name (worst instance, instance count), ranks high-value images
  first, and counts processes that refuse the query. Hardening shows readable/refused counts, high-value gaps and the
  six most exposed images. DEP needs `PROCESS_QUERY_INFORMATION`, so only complete readings are reported; a live
  unelevated capture read 40 images and refused 128. Details in `docs/EXPLOIT_MITIGATIONS.md`.
- Wired earlier: rule coverage (which built-in rules cannot fire here), suppression list + Re-arm, event-log cursors
  (with cleared-log reset and lost-window warning), retention accounting, backward clock warning, alert explanation
  panel, service and driver cross-view checks, bounded TCP listener list with process attribution, and remote
  destination/listener session digests.
- Verified: 1,499 tests in the Debug and Release builds, packaged route smoke (every route, 179 YARA rules, no crash
  entries), window smoke, ZIP/SBOM hashes.
- Not verified by hand: a real in-app update using the journal (locked-file rollback is now proved by tests, but no
  installed build has been updated through the helper). The
  mitigation panel, the Alerts coverage panel and explanation panel, and the Network PROCESS column and
  listener/destination sections were also never viewed. The development machine's channel mix was not reviewed either.
- Blocked: egress byte volume (ETW/admin ESTATS), metered feed signal (session-0 support undocumented), ARM64, signing.
- Smoke lessons (DN-065): starting the packaged desktop with a hidden window style lets minimize-to-tray withdraw the
  window, so `MainWindowHandle` stays 0 and the close request is never sent. The harness launches visibly; do not
  reintroduce `-WindowStyle Hidden` for the desktop launch. A failed hidden run can leave a headless desktop behind;
  the smoke guard then refuses to start, so check `Get-Process Downpour.Desktop` and stop the stale pid before rerunning.
- No Core-only foundation from either round remains unwired; egress novelty is blocked on byte volume and
  metered scheduling on a session-0 signal.
- Previously flaky: `AmsiSessionTests.ContextCannotBeUninitializedDuringAnActiveScan` failed under load; its waits were
  raised to 30 s on 2026-11-20.

## Working rules already in force

- Read `SHARED_CONTEXT.md` and `WORK_QUEUE.json` first; claim a task before editing.
- Read-only defaults, no privileged actions, no broad IPC ACLs, no PowerShell subprocesses in the product.
- Keep `Contracts` free of WinUI/service dependencies; Windows adapters live in `Service`.
- Do not claim a route works because it exists. State which check ran and what was not checked.
- The `artex` subagent is installed in another session; it is not spawnable from the 0.1.26+ threads.
