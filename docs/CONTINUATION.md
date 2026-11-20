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
sed -i 's/0\.1\.28/0.1.29/g' Directory.Build.props   # also Assembly/FileVersion
git commit -am "chore: bump version to 0.1.29" && COMMIT=$(git rev-parse HEAD)
# 2. build (background it; it runs Release tests and five publishes)
nohup pwsh -NoProfile -File Build-Portable.ps1 > artifacts/build-0.1.29.log 2>&1 &
# 3. copy the version scripts and point them at \$COMMIT
for s in package smoke window-smoke; do
  sed -e 's/0\.1\.28/0.1.29/g' -e "s/<previous-commit>/\$COMMIT/g" artifacts/v0.1.28-$s.ps1 > artifacts/v0.1.29-$s.ps1
done
# 4. package, route smoke, window smoke (background each, poll the log)
pwsh -NoProfile -File artifacts/v0.1.29-package.ps1
pwsh -NoProfile -File artifacts/v0.1.29-smoke.ps1
pwsh -NoProfile -File artifacts/v0.1.29-window-smoke.ps1
# 5. notes, tag, publish, verify digests
gh release create v0.1.29 -R christiand0797/downpour-next --title "Downpour Next 0.1.28" \
  --notes-file docs/RELEASE_0.1.28.md --latest \
  artifacts/DownpourNext-win-x64-0.1.28.zip artifacts/DownpourNext-0.1.28-sbom.cdx.json \
  artifacts/DownpourNext-0.1.28-SHA256SUMS.txt
gh release view v0.1.28 -R christiand0797/downpour-next --json assets \
  --jq '.assets[] | "\(.name) \(.size) \(.digest)"'
```

The package script checks each executable's `ProductVersion` against the recorded commit. Build after the last commit
that touches source or docs: the SDK stamps HEAD into `ProductVersion` at compile time, so any commit landing while the
build runs changes the hash it expects. Read the hash from an executable (`(Get-Item …).VersionInfo.ProductVersion`) and
pin that in the scripts rather than assuming the bump commit.

## Current state (end of 0.1.28)

- Published: `v0.1.28` (ZIP `4ed8cff0…`, 306,397,953 bytes; SBOM `bef0e4a9…`; SHA256SUMS `70997ec2…`). Binaries embed
  `55bd049`; the tag points at a later docs commit, so the package script must pin the embedded hash, not the tag.
- Wired: suppression list + Re-arm, event-log cursors (with cleared-log reset and lost-window warning), retention
  accounting, backward clock warning, alert explanation panel, service and driver cross-view checks, bounded TCP
  listener list with a session "new since page open" count, and a remote destination digest with baseline seeding.
- Verified: 1,481 tests (Debug), 1,479 in the 0.1.28 Release build, packaged route smoke (all routes, 179 YARA rules), window smoke.
- Unreleased after 0.1.28: listener process attribution (DN-066) adds an owning pid and bounded image name to each
  listener and a PROCESS column on the Network page. Needs a 0.1.29 cut to ship.
- Not verified by hand: the Alerts explanation panel and the new Network listener/destination sections.
- Blocked: egress byte volume (ETW/admin ESTATS), metered feed signal (session-0 support undocumented), ARM64, signing.
- Smoke lesson (DN-065): starting the packaged desktop with a hidden window style lets minimize-to-tray withdraw the
  window, so `MainWindowHandle` stays 0 and the close request is never sent. The harness launches the desktop visibly;
  do not reintroduce `-WindowStyle Hidden` for the desktop launch.
- Remaining Core-only foundations: rule coverage/silence, mitigation posture, metered scheduling, replay diff corpus,
  onboarding, update journal, portable encrypted bundle, IDN confusables, weekly digest, cross-view for ports.
- Previously flaky: `AmsiSessionTests.ContextCannotBeUninitializedDuringAnActiveScan` failed under load; its waits were raised to 30 s on 2026-11-20.

## Working rules already in force

- Read `SHARED_CONTEXT.md` and `WORK_QUEUE.json` first; claim a task before editing.
- Read-only defaults, no privileged actions, no broad IPC ACLs, no PowerShell subprocesses in the product.
- Keep `Contracts` free of WinUI/service dependencies; Windows adapters live in `Service`.
- Do not claim a route works because it exists. State which check ran and what was not checked.
- The `artex` subagent is installed in another session; it is not spawnable from the 0.1.26/0.1.27 threads.
