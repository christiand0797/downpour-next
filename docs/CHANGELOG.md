# Downpour Next changelog

## v0.1.2-preview — 2026-10-04

- Launching `Downpour.Desktop.exe` now starts the bundled read-only sensor service when no instance is available and shuts down only the child process it owns when the window closes.
- Dashboard, Processes, Drivers, and Network clarify that the desktop app can be running while local sensor telemetry is offline. A healthy dashboard snapshot is labeled `ONLINE`; this describes local telemetry, not internet access.
- Process inventory now carries up to 512 bounded rows instead of eight. The provider filters the Windows PID 0 `Idle` pseudo-process so valid snapshots are not rejected.
- Oversized local snapshot pipe payloads are treated as unavailable data. The client never displays fabricated readings.
- Verification: Release build 0 warnings/errors; 22 tests pass; direct-EXE smoke check confirmed bundled-service startup and graceful shutdown. Portable ZIP: `DownpourNext-win-x64-preview-v012.zip`, SHA-256 `A8E51B054DE44956B9959B74F6E92878987470F41015273892EE24964E2EF5C3`.

## v0.1.1-preview

- Added a self-contained x64 portable desktop/service bundle with a CMD launcher and the advisory CISA KEV catalog.
- Added the crescent-and-storm UI, live CPU/memory gauges, local snapshot IPC, initial route inventory, and the first threat-intelligence cache.
- The full feature-parity map and security limitations are documented in [`FEATURE_PARITY.md`](FEATURE_PARITY.md) and [`SECURITY_MODEL.md`](SECURITY_MODEL.md).
