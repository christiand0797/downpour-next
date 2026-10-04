# Downpour Next shared context

**Updated:** 2026-10-03 (America/Denver; 2026-10-04 00:09 UTC)  
**Repository:** private [christiand0797/downpour-next](https://github.com/christiand0797/downpour-next)  
**Local path:** `C:\Users\purpl\Desktop\downpour v2`  
**Branch:** `main`  
**Latest checkpoint:** Inspect `git log -1 --oneline` on `main`; it includes the implementation and handoff/security files described here.

Most recent local checkpoint: dashboard background/gauges/history and bounded, read-only loaded-driver inventory are implemented. Build succeeded with 0 warnings/errors; all 6 tests passed. The native packaged app was relaunched and visually captured after the gauge update. Gauge values and chart render; the rain/stars are visible. The crescent needs a contrast/position pass because it is too subtle in the current viewport.

## Goal

Build a native Windows successor that preserves Downpour v29's security capabilities and improves UI, performance, isolation, reliability, and maintainability. Full parity is not complete. Do not treat the route count as a parity claim.

## Current implementation

- .NET 10 solution with WinUI 3 desktop, contracts, core, and Windows service projects.
- The navigation registry contains all 33 source destinations plus the new Drivers route; the source module inventory contains 71 mapped modules.
- The full app shell has a generated night-rain/crescent background, a low-opacity animated rain layer, and twinkling stars. Animation pauses while the window is deactivated.
- Dashboard has real CPU/memory circular gauges, a rolling history graph, relative process bars, and truthful offline/unknown states.
- Service emits a schema-versioned, read-only snapshot over the `Downpour.SystemSnapshot.v1` named pipe. Snapshot fields: process count, top eight processes by working set, thread counts, system CPU, physical memory totals, active TCP connection count, and warnings.
- The pipe is outbound-only and has a DACL for LocalSystem and authenticated local users. UI client is bounded to a two-second connect/read timeout.
- Processes page displays and filters the top eight process rows from the live snapshot. This is not equivalent to the original process behavior/injection detector.
- Drivers route reads up to 512 loaded kernel modules from the service and classifies paths for review. It does not verify driver signatures or manage Driver Store packages. No install/update/reinstall/remove action is enabled.
- The old Downpour source was searched for driver behavior. It includes a KernelDriverAuditor, BYOVD name/path checks, and a new-driver baseline monitor; no driver package maintenance UI/workflow was found in the targeted code/module-map search. See `docs/DESIGN_REFERENCES.md`.
- TMOG informed graph semantics only, not page layout. CPU/memory samples are graphed without interpolating unavailable readings. Additional per-core, disk, network-throughput, GPU, thermal, energy, and history-replay views remain planned.
- All other security engines, scans, threat feeds, event monitors, settings persistence, hardening, forensics, AEGIS layers, and response actions remain unported.
- Tests cover route-registry integrity, a live Windows snapshot, missing-service behavior, and an authenticated local pipe round-trip.
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

Check: Dashboard should show an observe-only connection and live system metrics. The Processes route shows the largest eight processes and filters by name/PID. Without the service, the UI must show `OFFLINE` and em dashes rather than fabricated zeroes.

## Last verification

- `dotnet build Downpour.slnx -c Debug`: passed after full-background, dashboard graph, and driver inventory changes; 0 warnings, 0 errors.
- `dotnet test Downpour.slnx -c Debug --logger "console;verbosity=normal"`: 6 passed, 0 failed (registry integrity, live snapshot, driver inventory provider, unavailable service, system snapshot IPC, driver snapshot IPC).
- Manual named-pipe smoke test initially failed with `Access to the path is denied.` The ACL was updated with authenticated-reader synchronization/read-attributes/read-permissions rights, and a subsequent manual client received a valid schema-v1 snapshot. Four automated tests now pass, including the pipe integration test.
- WinUI packaged app was relaunched (PID 3536) and captured via `PrintWindow`; the responsive dashboard shows live CPU/memory gauges and resource history. Gauge arc rendering was adjusted and verified visually. Full-page route interaction and narrow/high-DPI review remain outstanding.
- GitHub private repo created and first commit pushed to `main`. GitHub connector returned 404 for the private repository, but the browser showed the created repository and `git push` succeeded.

## Immediate next actions

1. Improve full-window moon visibility and review route layouts at narrow/high-DPI sizes.
2. Port read-only network throughput/per-interface data and Windows event telemetry, then implement normalized alerts/detection fixtures.
3. Port the original driver's BYOVD/signature/path audit semantics with current signed intelligence and independently validated evidence.
4. Design the driver package broker for verified install/update/reinstall/remove with backup/rollback, explicit elevation, and audited consent. No such action is safe to enable yet.
5. GitHub Actions remains configured but its first run was blocked by the account billing/spending-limit notice; this work was built/tested locally without relying on Actions.
5. Reconcile the complete module map, screens, configs, feeds, rules, workflows, storage, and action paths before declaring feature parity.

## Architecture and safety constraints

See `AGENTS.md`, `SECURITY.md`, `docs/SECURITY_MODEL.md`, `docs/FEATURE_PARITY.md`, and `docs/ARCHITECTURE_AND_MIGRATION.md`. The only enabled service behavior is observation. The pipe server endpoint is outbound-only, but the DACL grants authenticated local users the rights needed to open/read the endpoint. Do not enable system-changing actions without a reviewed allow-list, authorization policy, audit record, timeout, recovery path, and denial tests.
