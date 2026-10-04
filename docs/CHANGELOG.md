# Downpour Next changelog

## v0.1.6 — local investigation export

- Added the Alerts page's user-selected JSON investigation export using the Windows save picker.
- Export contains up to 512 validated alert metadata rows and health warnings. It revalidates the alert snapshot, excludes event bodies/user content, HTML-escapes serialized values, and refuses output over 1 MiB.
- Release build: 0 warnings/errors; 65 tests passed. Archive: `DownpourNext-win-x64-d305c2a.zip`; SHA-256 `F9FA96476CD3FF082F0353EE9B4F0BD25198E8FE91894E76E7C5BC7222E0010B`.
- Download from [GitHub Releases](https://github.com/christiand0797/downpour-next/releases/tag/v0.1.6). This remains an unsigned portable development build and does not claim full v29 parity.

## v0.1.5 — persistent false-positive rules

- Added false-positive confirmation and re-arm actions in Alerts. Three explicit confirmations of the same fixed channel/provider/event-ID rule suppress matching current and future alerts. Re-arming removes the rule and reopens only rows that it auto-suppressed; individual suppression remains independent.
- Added retry-safe confirmation/re-arm request records, bounded to 10,000 rows / 30 days, and automatic alert DB migration from schema v1 to v2.
- Fingerprints use fixed catalog metadata only. Event message text is neither collected nor analyzed.
- Release build: 0 warnings/errors; 63 tests passed. Package: `DownpourNext-win-x64-85ba7d2.zip`, SHA-256 `E3578121CE3C22B2B54CC7C87B44D7D2F0782C0AF6CC85401DADD8705E86B396`.
- Download the unsigned portable development build from [GitHub Releases](https://github.com/christiand0797/downpour-next/releases/tag/v0.1.5). This release is not an installer or full v29 parity claim.

## v0.1.4 — persistent event alerts and local triage

- Added service-side SQLite persistence for allow-listed event observations with SHA-256 IDs based on event record identity, deduplication across repeated polling, 30-day retention, and a 10,000-alert cap.
- Added five-minute bucket deduplication for aggregated 4625 failed-logon bursts; occurrence counts track the observed maximum rather than adding every repeated poll.
- Added a dedicated Alerts route with source/record evidence, severity filters, and local acknowledge, suppress, and reopen controls. Suppression affects only one alert record.
- Added a separate 1 KiB strict-schema local control pipe with expected-state checks and idempotent request IDs. It cannot request OS changes or command execution.
- Release build: 0 warnings/errors; 59 tests passed. BAT smoke check started both executables and confirmed alert DB creation.
- Archive: `DownpourNext-win-x64-5427953.zip`; SHA-256: `A354894D66DA335DE205CE86F37407D538D7DB133AF3AED5D604F558FEC50A5A`; downloadable from [GitHub Releases](https://github.com/christiand0797/downpour-next/releases/tag/v0.1.4).
- This remains an unsigned portable development build. Broader v29 detection/correlation, Sigma/AMSI, Sysmon/ETW, system-changing actions, and installer are still outstanding.

## v0.1.3 — runnable Windows x64 package

- Added a self-contained portable Windows x64 package with `Downpour.Desktop.exe`, the bundled local sensor service, a BAT launcher, a CMD launcher, and a portable readme.
- Added the working read-only Windows Services inventory page with service state, startup type, search, and a separate bounded service IPC channel.
- The desktop EXE starts and connects to the bundled service in the tested local package. No separate .NET runtime is required.
- Release build: 0 warnings/errors. Test suite: 54 passed. Direct EXE smoke check kept the UI alive and found its bundled service process.
- Archive: `DownpourNext-win-x64-ce0bcd9.zip`; SHA-256: `915439E1ECAAABD60DE8D3FE1FC83FF7C2C68BBEEC6F3D14677F1D724DE5C9C7`.
- This is an unsigned portable development build, not an installer or a claim of full v29 parity. System-changing security and driver actions are not available yet.

## Unreleased

- Added persistent false-positive rule review: three explicit confirmations for the same fixed channel/provider/event-ID fingerprint suppress future matching alert rows; Re-arm removes that rule and reopens only rows it suppressed. Added schema-v1-to-v2 migration and retry-safe confirmation audit records. This never inspects event message text and does not perform OS actions.
- Added a service-side SQLite operation journal with schema versioning, transactional state/event writes, path-free object IDs, replay-safe event IDs, constrained transitions, restart-visible pending recovery, protected current-user/SYSTEM state directory, and append-only event triggers. It does not authorize or execute system actions.
- Restricted system, network, and driver telemetry pipes to the sensor service's current Windows account and LocalSystem; all servers remain one-way from service to desktop.
- Added `Start-Downpour-Next.bat` for direct desktop launch. The desktop launches the bundled sensor service when needed.
- Added service-backed Windows Event Log sensing for 35 fixed v29 event/channel pairs across seven channels, with bounded metadata-only IPC, per-source health, severity/search filters, and five-minute Security 4625 burst aggregation.
- Product parity includes explicit, audited, recoverable system actions; this is not intended to remain read-only. Before enabling them, add the isolated installed-service identity and a narrow verified action broker.

## v0.1.2-preview — 2026-10-04

Published at [GitHub Releases](https://github.com/christiand0797/downpour-next/releases/tag/v0.1.2-preview). Download `DownpourNext-win-x64-preview-v012.zip` to test the self-contained x64 bundle; SHA-256: `A8E51B054DE44956B9959B74F6E92878987470F41015273892EE24964E2EF5C3`.

- Launching `Downpour.Desktop.exe` now starts the bundled read-only sensor service when no instance is available and shuts down only the child process it owns when the window closes.
- Dashboard, Processes, Drivers, and Network clarify that the desktop app can be running while local sensor telemetry is offline. A healthy dashboard snapshot is labeled `ONLINE`; this describes local telemetry, not internet access.
- Process inventory now carries up to 512 bounded rows instead of eight. The provider filters the Windows PID 0 `Idle` pseudo-process so valid snapshots are not rejected.
- Oversized local snapshot pipe payloads are treated as unavailable data. The client never displays fabricated readings.
- Verification: Release build 0 warnings/errors; 22 tests pass; direct-EXE smoke check confirmed bundled-service startup and graceful shutdown. Portable ZIP: `DownpourNext-win-x64-preview-v012.zip`, SHA-256 `A8E51B054DE44956B9959B74F6E92878987470F41015273892EE24964E2EF5C3`.

## v0.1.1-preview

- Added a self-contained x64 portable desktop/service bundle with a CMD launcher and the advisory CISA KEV catalog.
- Added the crescent-and-storm UI, live CPU/memory gauges, local snapshot IPC, initial route inventory, and the first threat-intelligence cache.
- The full feature-parity map and security limitations are documented in [`FEATURE_PARITY.md`](FEATURE_PARITY.md) and [`SECURITY_MODEL.md`](SECURITY_MODEL.md).
