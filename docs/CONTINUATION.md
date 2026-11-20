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
sed -i 's/0\.1\.29/0.1.30/g' Directory.Build.props   # also Assembly/FileVersion
git commit -am "chore: bump version to 0.1.30" && COMMIT=$(git rev-parse HEAD)
# 2. build (background it; it runs Release tests and five publishes)
nohup pwsh -NoProfile -File Build-Portable.ps1 > artifacts/build-0.1.30.log 2>&1 &
# 3. copy the version scripts and point them at the commit
for s in package smoke window-smoke; do
  sed -e 's/0\.1\.29/0.1.30/g' -e "s/c9421955e04fc9e6cfed37f9d4abc07f621fde40/$COMMIT/g" \
    artifacts/v0.1.29-$s.ps1 > artifacts/v0.1.30-$s.ps1
done
# 4. package, route smoke, window smoke (background each, poll the log)
pwsh -NoProfile -File artifacts/v0.1.30-package.ps1
pwsh -NoProfile -File artifacts/v0.1.30-smoke.ps1
pwsh -NoProfile -File artifacts/v0.1.30-window-smoke.ps1
# 5. notes, tag, publish, verify digests
gh release create v0.1.30 -R christiand0797/downpour-next --title "Downpour Next 0.1.30" \
  --notes-file docs/RELEASE_0.1.30.md --latest \
  artifacts/DownpourNext-win-x64-0.1.30.zip artifacts/DownpourNext-0.1.30-sbom.cdx.json \
  artifacts/DownpourNext-0.1.30-SHA256SUMS.txt
gh release view v0.1.30 -R christiand0797/downpour-next --json assets \
  --jq '.assets[] | "\(.name) \(.size) \(.digest)"'
```

The package script checks each executable's `ProductVersion` against the recorded commit. Build after the last commit
that touches source or docs: the SDK stamps HEAD into `ProductVersion` at compile time, so any commit landing while the
build runs changes the hash it expects. Read the hash from an executable (`(Get-Item …).VersionInfo.ProductVersion`) and
pin that in the scripts rather than assuming the bump commit.

## Current state (end of 0.1.29)

- Published: `v0.1.29` (ZIP `024c3902…`, 306,402,053 bytes; SBOM `ebee0668…`) as Latest, built from `c942195`; the tag
  points at the following docs commit, so the package script must pin the embedded hash, not the tag.
- Wired: suppression list + Re-arm, event-log cursors (with cleared-log reset and lost-window warning), retention
  accounting, backward clock warning, alert explanation panel, service and driver cross-view checks, bounded TCP
  listener list with process attribution, and remote destination/listener session digests.
- Verified: 1,481 tests in the Release build, packaged route smoke (every route, 179 YARA rules, no crash entries),
  window smoke, ZIP/SBOM hashes.
- Not verified by hand: the Network PROCESS column and listener/destination sections, and the Alerts explanation panel.
- Blocked: egress byte volume (ETW/admin ESTATS), metered feed signal (session-0 support undocumented), ARM64, signing.
- Smoke lessons (DN-065): starting the packaged desktop with a hidden window style lets minimize-to-tray withdraw the
  window, so `MainWindowHandle` stays 0 and the close request is never sent. The harness launches visibly; do not
  reintroduce `-WindowStyle Hidden` for the desktop launch. A failed hidden run can leave a headless desktop behind;
  the smoke guard then refuses to start, so check `Get-Process Downpour.Desktop` and stop the stale pid before rerunning.
- Remaining Core-only foundations: rule coverage/silence, mitigation posture, metered scheduling, replay diff corpus,
  onboarding, update journal, portable encrypted bundle, IDN confusables, weekly digest, cross-view for ports.
- Previously flaky: `AmsiSessionTests.ContextCannotBeUninitializedDuringAnActiveScan` failed under load; its waits were
  raised to 30 s on 2026-11-20.

## Working rules already in force

- Read `SHARED_CONTEXT.md` and `WORK_QUEUE.json` first; claim a task before editing.
- Read-only defaults, no privileged actions, no broad IPC ACLs, no PowerShell subprocesses in the product.
- Keep `Contracts` free of WinUI/service dependencies; Windows adapters live in `Service`.
- Do not claim a route works because it exists. State which check ran and what was not checked.
- The `artex` subagent is installed in another session; it is not spawnable from the 0.1.26+ threads.
