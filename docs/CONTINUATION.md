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

For a new version (substitute the version and commit):

```bash
# 1. bump
sed -i 's/0\.1\.30/0.1.31/g' Directory.Build.props   # also Assembly/FileVersion
git commit -am "chore: bump version to 0.1.31" && COMMIT=$(git rev-parse HEAD)
# 2. build (background it; it runs Release tests and five publishes)
nohup pwsh -NoProfile -File Build-Portable.ps1 > artifacts/build-0.1.31.log 2>&1 &
# 3. copy the version scripts and point them at the commit
for s in package smoke window-smoke; do
  sed -e 's/0\.1\.30/0.1.31/g' -e "s/ceaf7586adcf35e480bd75b250068520461017a2/$COMMIT/g" \
    artifacts/v0.1.30-$s.ps1 > artifacts/v0.1.31-$s.ps1
done
# 4. package, route smoke, window smoke (background each, poll the log)
pwsh -NoProfile -File artifacts/v0.1.31-package.ps1
pwsh -NoProfile -File artifacts/v0.1.31-smoke.ps1
pwsh -NoProfile -File artifacts/v0.1.31-window-smoke.ps1
# 5. notes, tag, publish, verify digests
gh release create v0.1.31 -R christiand0797/downpour-next --title "Downpour Next 0.1.31" \
  --target "$(git rev-parse HEAD)" --notes-file docs/RELEASE_0.1.31.md --latest \
  artifacts/DownpourNext-win-x64-0.1.31.zip artifacts/DownpourNext-0.1.31-sbom.cdx.json \
  artifacts/DownpourNext-0.1.31-SHA256SUMS.txt
gh release list -R christiand0797/downpour-next --limit 3
gh release view v0.1.31 -R christiand0797/downpour-next --json assets \
  --jq '.assets[] | "\(.name) \(.size) \(.digest)"'
```

The package script checks each executable's `ProductVersion` against the recorded commit. Build after the last commit
that touches source or docs: the SDK stamps HEAD into `ProductVersion` at compile time, so any commit landing while the
build runs changes the hash it expects. Read the hash from an executable (`(Get-Item …).VersionInfo.ProductVersion`) and
pin that in the scripts rather than assuming the bump commit. Commit the docs first and pass `--target "$(git rev-parse
HEAD)"` so the tag points at a pushed commit; the package script must keep pinning the embedded hash, not the tag.

## Current state (end of 0.1.30)

- Published: `v0.1.30` (ZIP `4f80b4f5…`, 306,423,711 bytes; SBOM `9102a7f3…`) as Latest, built from `ceaf758`; the tag
  points at the following docs commit, so the package script must pin the embedded hash, not the tag.
- Shipped in 0.1.30: rule coverage. The event provider records which of the 7 allow-listed channels could be opened;
  the alert store keeps that per channel plus when observation started; `SecurityAlertSnapshot.Coverage` splits the 35
  built-in catalog rules into can-fire / cannot-fire / silent / unknown and names the blocked ones; the Alerts page
  shows a `RULE COVERAGE` panel. Silence is only claimed after a 30-day window, so a fresh store never calls a readable
  rule quiet.
- Wired earlier: suppression list + Re-arm, event-log cursors (with cleared-log reset and lost-window warning),
  retention accounting, backward clock warning, alert explanation panel, service and driver cross-view checks, bounded
  TCP listener list with process attribution, and remote destination/listener session digests.
- Verified: 1,484 tests in the Release build, packaged route smoke (every route, 179 YARA rules, no crash entries),
  window smoke, ZIP/SBOM hashes.
- Not verified by hand: the Alerts coverage panel and explanation panel, and the Network PROCESS column and
  listener/destination sections. The development machine's channel mix was not reviewed either.
- Blocked: egress byte volume (ETW/admin ESTATS), metered feed signal (session-0 support undocumented), ARM64, signing.
- Smoke lessons (DN-065): starting the packaged desktop with a hidden window style lets minimize-to-tray withdraw the
  window, so `MainWindowHandle` stays 0 and the close request is never sent. The harness launches visibly; do not
  reintroduce `-WindowStyle Hidden` for the desktop launch. A failed hidden run can leave a headless desktop behind;
  the smoke guard then refuses to start, so check `Get-Process Downpour.Desktop` and stop the stale pid before rerunning.
- Remaining Core-only foundations: mitigation posture, metered scheduling, replay diff corpus, onboarding, update
  journal, portable encrypted bundle, IDN confusables, weekly digest, egress novelty baseline, cross-view for ports.
- Previously flaky: `AmsiSessionTests.ContextCannotBeUninitializedDuringAnActiveScan` failed under load; its waits were
  raised to 30 s on 2026-11-20.

## Working rules already in force

- Read `SHARED_CONTEXT.md` and `WORK_QUEUE.json` first; claim a task before editing.
- Read-only defaults, no privileged actions, no broad IPC ACLs, no PowerShell subprocesses in the product.
- Keep `Contracts` free of WinUI/service dependencies; Windows adapters live in `Service`.
- Do not claim a route works because it exists. State which check ran and what was not checked.
- The `artex` subagent is installed in another session; it is not spawnable from the 0.1.26+ threads.
