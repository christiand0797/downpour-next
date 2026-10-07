# Continuation handoff — 2026-10-07

v2 remains the only working repository; v29 is unchanged and read-only. This continuation completed two verified release milestones; full feature parity remains unfinished.

## Published outcome

Latest: [v0.1.17](https://github.com/christiand0797/downpour-next/releases/tag/v0.1.17), published 2026-10-07T21:08:25Z. Tag targets `e8ce959cc0c8238e3eed0b86e9a5894d36874485`. GitHub latest/tag/assets verification passed. ZIP: 259,783,061 bytes; SHA-256 `B035C921C7F9A1BF1DB7222448EEECD6C3C5E43932A6F60B9BC8C77FA843DBB2`. All 1,062 archive entries match staging; runtime inventory has 52 components. SBOM and checksum asset sizes/digests also match GitHub. Earlier v0.1.16 is retained and verified.

Detection fixes persist Sysmon review events, correct catalog labels, distinguish AMSI errors from clean scans, bound native lifetime/retry/dedup, and retain visible source-health failures. Settings uses actual process/firewall/USB policy switches and accurate privacy/action text. Release builds set portable mode before WinUI resource generation and derive current version from the assembly. CIS now shows measured source/alert/policy review and a bounded explicit package-file consistency check; scripted protection models are removed. This is partial CIS parity.

## Commits

- `badcf28`: detection/version fixes and regressions.
- `386688d`: source/feature/security reconciliation and initial handoff.
- `3f62c5d`: portable WinUI resource generation and compiled updater version.
- `1f7f539`: real process/firewall/USB Settings switches.
- `ffc241d`: accurate Settings privacy/action behavior; v0.1.16 package source.
- `5a5984a`: verified v0.1.16 package/security docs.
- `e8ce959`: measured CIS/contracts/integrity/regressions, version 0.1.17; latest package source.
- `1c4a7ec`: published release evidence and CIS/source docs.
- `793725a`: v0.1.17 package verification and rechecked CI blocker.
- Final handoff documentation commit follows these; its own ID is available in git log.

## Verification and commands

- Root `dotnet restore Downpour.slnx` passed. Final root Debug build: 0 warnings/errors; Debug tests: 893 passed, zero skipped/failed. This includes 23 preserved draft tests excluded from the package.
- Clean detached checkout under `artifacts/downpour-v016-build` at e8ce959: `dotnet build Downpour.slnx -c Release --no-restore -m:1` with the pinned YARA-X cache; 0 warnings/errors. `dotnet test Downpour.slnx -c Release --no-build --no-restore`: 870 passed, zero skipped/failed.
- Four Release x64 self-contained `dotnet publish` commands from BUILD_WINDOWS: Desktop with portable/WindowsAppSDKSelfContained/SelfContained and no trimming; Service/Scanner with pinned YARA-X cache; UpdateHelper with PublishSingleFile. All succeed; executable versions/source metadata are consistent.
- Ignored `artifacts/v0.1.17-smoke.ps1`: desktop startup, live schema-v1 system/alert pipes, exactly one owned service, graceful desktop/service shutdown, 179 YARA rules and benign scan pass. No privileged changes. All owned processes stopped.
- Ignored `artifacts/v0.1.17-package.ps1`: generate runtime inventory/file manifest/archive; compare every ZIP entry by size/SHA-256 and enforce updater bounds. Evidence in `artifacts/v0.1.17-evidence.json`.
- `dotnet run --project artifacts/v017-integration/Probe.csproj -c Release -- <fixed v0.1.17 staging>`: actual inspector matches 1,061 listed files (659,846,854 bytes hashed); live measured review/report passes with explicit partial health. Manifest SHA-256 `388D1ED35E690315F11163CA781A9B6C2E5012921E96564DF4858E29FE565735`.
- `git diff --check`, focused staging/commits, `git fetch origin`, ancestry verification, `git push origin main`, `gh release create` with notes-file/ZIP/SBOM/checksums and explicit code target; `gh api` latest/tag/asset verification pass. Remote evidence in `artifacts/v0.1.17-github-evidence.json`.

## Resolved failures and open limits

Initial route-count test failed because the separate draft added route 39. The regression now verifies all committed routes/status/uniqueness and permits extensions. Initial portable Desktop exited with missing WinUI theme resources: changing deployment mode only at publish reused an app-only PRI. Set mode before generation, clean/rebuild, and native launch passes. First CIS build caught a Core type leaking into Contracts; corrected to a small contract projection.

[Remote CI run 37684720863](https://github.com/christiand0797/downpour-next/actions/runs/37684720863) did not start: GitHub reports the account locked for a billing issue. Owner account resolution is required; local checks do not imply passing CI.

Unsigned releases/local manifest, same-user trust, independent server authentication, native route/picker/UAC/high-DPI/clean-machine acceptance, update failure/recovery, installed-service identity/signing, automatic admin elevation and broader parity remain open. See CONTINUATION_AUDIT.md, CIS.md and WORK_QUEUE.json. No whole-product completion claim.

## Next safe task and preserved drafts

Begin a narrow admin-elevation/installed-service boundary for DN-008/DN-010, with fixed typed operations and dedicated consent, denial, audit, timeout, race and recovery tests. Keep telemetry unelevated. Host isolation must satisfy all four AGENT_COORDINATION.md merge blockers; never enable an in-process-only expiry. CIS adaptive/deception work and other v29 workflows remain separate open work.

All pre-existing action/host-isolation/AntiStalker drafts remain unchanged and excluded from both releases. The capabilities index committed only owned CIS/Settings descriptions; its working-tree AntiStalker addition remains unstaged. Do not reset, restore, stash, clean or bulk-stage these drafts. Registry is idle at handoff with exact next-task notes; queue tasks remain in_progress where broader acceptance is incomplete.

## Exact owned file inventory

The following list is the committed change set from baseline a62d167 through 793725a, plus this handoff file. It excludes preserved draft files.

- M AGENT_REGISTRY.json
- A Directory.Build.props
- M README.md
- M SECURITY.md
- M SHARED_CONTEXT.md
- M TODO.md
- M WORK_QUEUE.json
- M capabilities.json
- M docs/ACTION_BROKER_THREAT_MODEL.md
- M docs/BUILD_WINDOWS.md
- M docs/CHANGELOG.md
- A docs/CIS.md
- A docs/CONTINUATION_AUDIT.md
- M docs/FEATURE_PARITY.md
- M docs/SECURITY_MODEL.md
- M docs/SETTINGS.md
- M parity-checklist.json
- M source-modules.json
- M src/Downpour.Contracts/CognitiveImmuneSystem.cs
- M src/Downpour.Contracts/ForensicBundle.cs
- M src/Downpour.Contracts/ServiceHealthSnapshot.cs
- D src/Downpour.Contracts/SwarmIntelligence.cs
- M src/Downpour.Core/CognitiveImmuneSystemCoordinator.cs
- M src/Downpour.Core/ForensicEvidenceCollector.cs
- A src/Downpour.Core/PackageIntegrityInspector.cs
- D src/Downpour.Core/SwarmSimulationEngine.cs
- M src/Downpour.Desktop/Downpour.Desktop.csproj
- M src/Downpour.Desktop/Pages/CognitiveImmuneSystemPage.xaml
- M src/Downpour.Desktop/Pages/CognitiveImmuneSystemPage.xaml.cs
- M src/Downpour.Desktop/Pages/SettingsPage.xaml
- M src/Downpour.Desktop/Pages/SettingsPage.xaml.cs
- M src/Downpour.Desktop/PortableUpdateInstaller.cs
- M src/Downpour.Service/AmsiIntegration.cs
- A src/Downpour.Service/AmsiSession.cs
- M src/Downpour.Service/ScriptBlockSource.cs
- M src/Downpour.Service/SecurityAlertRepository.cs
- M src/Downpour.Service/SecurityAlertSnapshotStore.cs
- M src/Downpour.Service/SigmaAmsiEventProcessor.cs
- M src/Downpour.Service/SigmaAmsiPushWorker.cs
- A src/Downpour.Service/SysmonAlertBatch.cs
- M src/Downpour.Service/SysmonProvider.cs
- M src/Downpour.Service/SysmonPushWorker.cs
- A tests/Downpour.Tests/AmsiSessionTests.cs
- M tests/Downpour.Tests/CapabilityRegistryTests.cs
- M tests/Downpour.Tests/CognitiveImmuneSystemCoordinatorTests.cs
- A tests/Downpour.Tests/DetectionHealthTests.cs
- A tests/Downpour.Tests/PackageIntegrityInspectorTests.cs
- D tests/Downpour.Tests/SwarmSimulationEngineTests.cs
- A tests/Downpour.Tests/SysmonAlertTests.cs
- A docs/CONTINUATION_HANDOFF_2026-10-07.md
