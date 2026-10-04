# Downpour Next changelog

## v0.1.4 — persistent event alerts and local triage

- Added service-side SQLite persistence for allow-listed event observations with SHA-256 IDs based on event record identity, deduplication across repeated polling, 30-day retention, and a 10,000-alert cap.
- Added five-minute bucket deduplication for aggregated 4625 failed-logon bursts; occurrence counts track the observed maximum rather than adding every repeated poll.
- Added a dedicated Alerts route with source/record evidence, severity filters, and local acknowledge, suppress, and reopen controls. Suppression affects only one alert record.
- Added a separate 1 KiB strict-schema local control pipe with expected-state checks and idempotent request IDs. It cannot request OS changes or command execution.
- Release build: 0 warnings/errors; 59 tests passed. Portable package and SHA-256 are recorded below after publishing.
- This remains an unsigned portable development build. Broader v29 detection/correlation, Sigma/AMSI, Sysmon/ETW, system-changing actions, and installer are still outstanding.

## v0.1.3 — runnable Windows x64 package

- Added a self-contained portable Windows x64 package with `Downpour.Desktop.exe`, the bundled local sensor service, a BAT launcher, a CMD launcher, and a portable readme.
- Added the working read-only Windows Services inventory page with service state, startup type, search, and a separate bounded service IPC channel.
- The desktop EXE starts and connects to the bundled service in the tested local package. No separate .NET runtime is required.
- Release build: 0 warnings/errors. Test suite: 54 passed. Direct EXE smoke check kept the UI alive and found its bundled service process.
- Archive: `DownpourNext-win-x64-ce0bcd9.zip`; SHA-256: `915439E1ECAAABD60DE8D3FE1FC83FF7C2C68BBEEC6F3D14677F1D724DE5C9C7`.
- This is an unsigned portable development build, not an installer or a claim of full v29 parity. System-changing security and driver actions are not available yet.

## Unreleased

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
