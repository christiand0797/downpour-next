# Downpour Next shared context

**Updated:** 2026-10-03 (America/Denver; 2026-10-04 00:09 UTC)  
**Repository:** private [christiand0797/downpour-next](https://github.com/christiand0797/downpour-next)  
**Local path:** `C:\Users\purpl\Desktop\downpour v2`  
**Branch:** `main`  
**Latest checkpoint:** Inspect `git log -1 --oneline` on `main`; it includes the implementation and handoff/security files described here.

## Goal

Build a native Windows successor that preserves Downpour v29's security capabilities and improves UI, performance, isolation, reliability, and maintainability. Full parity is not complete. Do not treat the route count as a parity claim.

## Current implementation

- .NET 10 solution with WinUI 3 desktop, contracts, core, and Windows service projects.
- The navigation registry contains all 33 source tab destinations; the source module inventory contains 71 mapped modules.
- Dashboard has the dark crescent/rain design and metrics cards.
- Service emits a schema-versioned, read-only snapshot over the `Downpour.SystemSnapshot.v1` named pipe. Snapshot fields: process count, top eight processes by working set, thread counts, system CPU, physical memory totals, active TCP connection count, and warnings.
- The pipe is outbound-only and has a DACL for LocalSystem and authenticated local users. UI client is bounded to a two-second connect/read timeout.
- Processes page displays and filters the top eight process rows from the live snapshot. This is not equivalent to the original process behavior/injection detector.
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

- `dotnet build Downpour.slnx -c Debug`: passed after package pins and live pipe code changes; 0 warnings, 0 errors.
- `dotnet test Downpour.slnx -c Debug --no-build --logger "console;verbosity=normal"`: 4 passed, 0 failed (registry integrity, live snapshot, unavailable service, authenticated pipe integration).
- Manual named-pipe smoke test initially failed with `Access to the path is denied.` The ACL was updated with authenticated-reader synchronization/read-attributes/read-permissions rights, and a subsequent manual client received a valid schema-v1 snapshot. Four automated tests now pass, including the pipe integration test.
- WinUI packaged launcher previously reported a responsive `Downpour` window; native visual/interaction validation remains outstanding.
- GitHub private repo created and first commit pushed to `main`. GitHub connector returned 404 for the private repository, but the browser showed the created repository and `git push` succeeded.

## Immediate next actions

1. Validate the UI dashboard/process route online and offline; native UI automation remains outstanding.
2. After resolving GitHub's account billing/spending-limit notice, inspect the first CI and Dependabot workflow runs.
3. Add bounded IPC payload parsing and validate the server identity; narrow the pipe ACL to the eventual service SID/user model.
4. Port read-only network/event telemetry, then implement normalized alerts and detection fixtures.
5. Reconcile the complete module map, screens, configs, feeds, rules, workflows, storage, and action paths before declaring feature parity.

## Architecture and safety constraints

See `AGENTS.md`, `SECURITY.md`, `docs/SECURITY_MODEL.md`, `docs/FEATURE_PARITY.md`, and `docs/ARCHITECTURE_AND_MIGRATION.md`. The only enabled service behavior is observation. The pipe server endpoint is outbound-only, but the DACL grants authenticated local users the rights needed to open/read the endpoint. Do not enable system-changing actions without a reviewed allow-list, authorization policy, audit record, timeout, recovery path, and denial tests.
