# Downpour Next shared context

**Updated:** 2026-10-04 (America/Denver; 2026-10-04 14:31 UTC)

**Repository:** private [christiand0797/downpour-next](https://github.com/christiand0797/downpour-next)  
**Local path:** `C:\Users\purpl\Desktop\downpour v2`  
**Branch:** `main`  
**Latest checkpoint:** Inspect `git log -1 --oneline` on `main`; this slice is being verified before the checkpoint is committed/pushed.

The current slice expands process inventory to 512 bounded rows, filters Windows PID 0 from exported rows, starts the bundled read-only sensor service when the desktop EXE is launched directly, distinguishes application-running from sensor-service-offline UI states, and treats oversized IPC messages as unavailable. Verification so far: Release build 0 warnings/errors; 22 tests pass; packaged desktop auto-started its child service and graceful window close stopped that child. Refresh the hash and checkpoint details after the portable release package is committed.

## Goal

Build a native Windows successor that preserves Downpour v29's security capabilities and improves UI, performance, isolation, reliability, and maintainability. Full parity is not complete. Do not treat the route count as a parity claim.

## Current implementation

- .NET 10 solution with WinUI 3 desktop, contracts, core, and Windows service projects.
- The navigation registry contains all 33 source destinations plus the new Drivers route; the source module inventory contains 71 mapped modules.
- The full app shell has a clear night landscape, separate transparent cratered crescent, animated rain/stars/aurora, and occasional upper-sky lightning forks. Drizzle, storm, thunderstorm, and hurricane modes scale rain speed/visibility and wind/lightning; modes auto-shift until manually selected. The animated rain now has 280 layered drops. Animation pauses while the window is deactivated.
- Dashboard has real CPU/memory circular gauges, a rolling history graph, relative process bars, and truthful offline/unknown states.
- Service emits a schema-versioned, read-only snapshot over the `Downpour.SystemSnapshot.v1` named pipe. Snapshot fields: process count, up to 512 accessible processes sorted by working set, thread counts, system CPU, physical memory totals, active TCP connection count, and warnings. PID 0 is excluded; names are limited to 128 characters.
- The pipe is outbound-only and has a DACL for LocalSystem and authenticated local users. UI client is bounded to a two-second connect/read timeout.
- Processes page displays and filters up to the 512 largest accessible process rows from the live snapshot, with truthful total-versus-shown counts. The payload and process-name fields remain bounded. This is not equivalent to the original process behavior/injection detector.
- The desktop starts the bundled read-only sensor service when the app is launched directly, reuses an already-running service, and stops only a child service it owns when its window closes. Dashboard, Processes, Drivers, and Network states say when the desktop is running but its local sensor service is unavailable; the dashboard reports `ONLINE · OBSERVE ONLY` when telemetry connects. This local status does not claim internet connectivity. Source builds still require a separately launched service.
- Drivers route reads up to 512 loaded kernel modules from the service and classifies paths for review. It does not verify driver signatures or manage Driver Store packages. No install/update/reinstall/remove action is enabled.
- Network route reads up to 32 adapters and 256 active TCP endpoints over `Downpour.NetworkInventory.v1`; a 1 MiB client cap and 2-second timeout bound IPC. Per-interface counters produce sampled send/receive rates, and history preserves unavailable gaps. There is no PID attribution, packet capture, DNS history, or detection.
- Threat Intelligence now has a real advisory CISA KEV catalog route. The core client uses a fixed HTTPS endpoint with redirects disabled, a 15-second deadline, a 12 MiB response cap, strict JSON/CVE/date/field validation, duplicate rejection, and a searchable catalog. A versioned atomic cache stores only validated source payloads, revalidates payloads/digest on read, labels data older than 24 hours stale, and refuses data beyond seven days. A sibling digest detects cache corruption but is not a signature against an attacker who can rewrite the cache. The UI keeps cached data visible through a failed refresh with a clear stale/offline state. Local product matching, more feeds, EPSS/NVD, and Sigma/YARA remain outstanding; see `docs/THREAT_INTELLIGENCE.md`.
- Settings now has one consolidated route with persistent local preferences for weather visuals, reduced motion, and automatic storm cycling. Toggle handlers are attached only after XAML initialization following a user-reported Settings crash. Build/test and launch pass; native interactive confirmation is outstanding. See `docs/SETTINGS.md`.
- The old Downpour source was searched for driver behavior. It includes a KernelDriverAuditor, BYOVD name/path checks, and a new-driver baseline monitor; no driver package maintenance UI/workflow was found in the targeted code/module-map search. See `docs/DESIGN_REFERENCES.md`.
- TMOG informed graph semantics only, not page layout. CPU/memory and network samples are graphed without interpolating unavailable readings. Additional per-core, disk, GPU, thermal, energy, and history-replay views remain planned.
- Other security engines, scans, all but the initial CISA KEV feed, event monitors, security-policy settings, hardening, forensics, AEGIS layers, and response actions remain unported.
- Tests cover route-registry integrity, live system/driver/network providers, KEV feed parsing bounds/validation, missing-service behavior, and authenticated local IPC round-trips. UI/Core JSON uses pinned Newtonsoft.Json 13.0.4, disables type-name handling, and bounds local/IPC payloads.
- Windows CI and Dependabot are configured; package/action pins were reviewed. GitHub blocked the first workflow before job start because recent account payments failed or the spending limit needs to be increased. This account-level notice prevents verifying remote CI and Dependabot runs.

## How to run locally

Terminal 1:

```powershell
dotnet run --project src/Downpour.Service/Downpour.Service.csproj
```

Terminal 2:

```powershell
dotnet run --project src/Downpour.Desktop/Downpour.Desktop.csproj
```

Check: Dashboard should show an `ONLINE` observe-only connection and live system metrics. The Processes route shows up to 512 largest accessible processes and filters by name/PID. When telemetry is unavailable, UI labels `SERVICE OFFLINE` and keeps unknown readings as em dashes rather than fabricated zeroes; the portable desktop starts its bundled service automatically.

## Last verification

- `dotnet build Downpour.slnx -c Release`: passed with 0 warnings and 0 errors after service auto-start wiring and PID 0 filtering.
- `dotnet test Downpour.slnx -c Release`: 22 passed, 0 failed, including the oversized local-pipe message case.
- Packaged self-contained x64 desktop startup smoke test: direct EXE launch started its bundled `Downpour.Service.exe`; closing the app window stopped the child process. An earlier forced termination intentionally bypassed graceful cleanup; that smoke-test process was cleaned up before the successful graceful-close check.
- Refreshed portable package: `artifacts/DownpourNext-win-x64-preview-v012.zip`, SHA-256 `A8E51B054DE44956B9959B74F6E92878987470F41015273892EE24964E2EF5C3`; archive inspection confirmed desktop EXE, service EXE, and CMD launcher are present.
- Self-contained x64 desktop/service publish passed to `artifacts/DownpourNext-win-x64-settings-fix`; packaged EXE and launcher are present. The user-reported Settings failure aligns with a XAML/WinUI crash recorded by Windows Error Reporting; toggle handlers now attach after initialization. The new EXE remained running in the startup smoke check, but the Settings click path has not yet been interactively verified. ZIP: `artifacts/DownpourNext-win-x64-preview-settings-fix.zip`, SHA-256 `771F1EA78E6BEC9A6BD71982968F37BD56A11BE8C21DF46150F7A44D0A70F96A`. The bundle has no trusted signature and is not an installer.
- Manual named-pipe smoke test initially failed with `Access to the path is denied.` The ACL was updated with authenticated-reader synchronization/read-attributes/read-permissions rights, and a subsequent manual client received a valid schema-v1 snapshot. Four automated tests now pass, including the pipe integration test.
- WinUI packaged app was captured via `PrintWindow`; live CPU/memory gauges/history, clear landscape, separate moon, visible rain mode control, and denser animated precipitation render. Network page is provider/IPC tested; native route interaction and narrow/high-DPI review remain outstanding.
- GitHub private repo created and first commit pushed to `main`. GitHub connector returned 404 for the private repository, but the browser showed the created repository and `git push` succeeded.

## Immediate next actions

1. Verify the Settings route opens and saves preferences in a native interactive click-through; continue native route/layout review, especially responsive width on narrow windows.
2. Commit/push this verified autostart/status/process-inventory slice, then publish its refreshed portable preview for laptop testing.
3. Ingest additional independently allow-listed feeds and correlate with local software inventory.
4. Port Windows event telemetry, then implement normalized alerts/detection fixtures.
5. Port the original driver's BYOVD/signature/path audit semantics with current signed intelligence and independently validated evidence.
6. Design the driver package broker for verified install/update/reinstall/remove with backup/rollback, explicit elevation, and audited consent. No such action is safe to enable yet.
7. GitHub Actions remains configured but its first run was blocked by the account billing/spending-limit notice; this work was built/tested locally without relying on Actions.
8. Reconcile the complete module map, screens, configs, feeds, rules, workflows, storage, and action paths before declaring feature parity.

## Architecture and safety constraints

See `AGENTS.md`, `SECURITY.md`, `docs/SECURITY_MODEL.md`, `docs/FEATURE_PARITY.md`, and `docs/ARCHITECTURE_AND_MIGRATION.md`. The only enabled service behavior is observation. The pipe server endpoint is outbound-only, but the DACL grants authenticated local users the rights needed to open/read the endpoint. Do not enable system-changing actions without a reviewed allow-list, authorization policy, audit record, timeout, recovery path, and denial tests.


