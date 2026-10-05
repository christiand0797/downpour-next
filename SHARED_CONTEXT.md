# Downpour Next shared context

**Updated:** 2026-10-04 (America/Denver; v0.1.11 local software review slice)

**Repository:** public [christiand0797/downpour-next](https://github.com/christiand0797/downpour-next)
**Local path:** `C:\Users\purpl\Desktop\downpour v2`  
**Branch:** `main`  
**Latest source checkpoint:** `23d44e7 Add verified in-app release updater` on `main`. The self-contained Windows x64 package is published at [v0.1.10](https://github.com/christiand0797/downpour-next/releases/tag/v0.1.10), asset `DownpourNext-win-x64-0.1.10.zip`, size 156,615,827 bytes, SHA-256 `FA9F4A17BD953BB53CD8D5F60F81A604DE12D88A50F66A76D0F1635E7396B7FA`. GitHub reports the same digest. Local runnable package is `DownpourNext-Portable/` in the repo root; 764 packaged files hash-match staging, with one stale legacy `PORTABLE-README.txt` extra preserved from the prior local folder. Release build has 0 warnings/errors; 97 tests pass; packaged app startup and graceful close/service shutdown passed. The user authorized public repo visibility for anonymous updates. Releases remain unsigned, portable, and not a full parity claim.

Portable validation: the archive contains 764 files including the Desktop EXE, bundled service EXE, BAT/CMD launchers, and portable readme. Every staged file hash matches the local `DownpourNext-Portable/` copy. The previous package's launched app was responsive; its local sensor service's named pipe returned a valid live system snapshot. v0.1.8 service smoke check opened 7/7 watchers, while polling read 6/7 channels on this machine. v0.1.9 adds the compiled EPSS lookup; a live API response was checked against the schema and contract tests cover malformed responses. Native UI click-through remains manual.

The v0.1.9 package was built from code commit `00b0786`; release metadata and handoff docs follow on `main`. The native export save-picker, correlation summary, EPSS lookup, and update button click-through remain manual verification items. v0.1.10 adds the update control beside the dashboard badge, strict fixed-repository/latest-stable parsing, bounded digest-checked download, safe ZIP extraction, staged apply after the desktop and bundled service exit, best-effort backup rollback, and restart. The GitHub SHA-256 is not a publisher signature; code signing/signed metadata is still needed for production. Manual update-button interaction and apply-failure recovery on another Windows installation remain pending.

The current implementation includes 512 bounded process rows, direct-EXE sensor auto-start, truthful service connectivity UI, oversized IPC handling, and a direct `.bat` launcher. Telemetry pipe DACLs now grant LocalSystem and the service's current user; same-user integration works and the named-pipe servers remain outbound-only. A self-contained x64 runtime is built into both `DownpourNext-Portable/` (local root folder) and ignored build artifacts. Product goal remains full functional v29 parity, including controlled/audited system-changing actions; observe-only behavior is a current stage, not the product goal.

## Goal

Build a native Windows successor that preserves Downpour v29's security capabilities and improves UI, performance, isolation, reliability, and maintainability. Full parity is not complete. Do not treat the route count as a parity claim.

## Current implementation

- .NET 10 solution with WinUI 3 desktop, contracts, core, and Windows service projects.
- The navigation registry contains all 33 source destinations plus Drivers and Security Events routes; the source module inventory contains 71 mapped modules.
- The full app shell has a clear night landscape, separate transparent cratered crescent, animated rain/stars/aurora, and occasional upper-sky lightning forks. Drizzle, storm, thunderstorm, and hurricane modes scale rain speed/visibility and wind/lightning; modes auto-shift until manually selected. The animated rain now has 280 layered drops. Animation pauses while the window is deactivated.
- Dashboard has real CPU/memory circular gauges, a rolling history graph, relative process bars, and truthful offline/unknown states.
- Service emits a schema-versioned, read-only snapshot over the `Downpour.SystemSnapshot.v1` named pipe. Snapshot fields: process count, up to 512 accessible processes sorted by working set, thread counts, system CPU, physical memory totals, active TCP connection count, and warnings. PID 0 is excluded; names are limited to 128 characters.
- The pipe is outbound-only; its DACL grants LocalSystem full control and only the service's current user SID the rights needed to open/read the endpoint. UI clients are bounded to a two-second connect/read timeout and 1 MiB payload.
- Processes page displays and filters up to the 512 largest accessible process rows from the live snapshot, with truthful total-versus-shown counts. The payload and process-name fields remain bounded. This is not equivalent to the original process behavior/injection detector.
- The desktop starts the bundled read-only sensor service when the app is launched directly, reuses an already-running service, and stops only a child service it owns when its window closes. Dashboard, Processes, Drivers, and Network states say when the desktop is running but its local sensor service is unavailable; the dashboard reports `ONLINE · OBSERVE ONLY` when telemetry connects. This local status does not claim internet connectivity. Source builds still require a separately launched service.
- Drivers route reads up to 512 loaded kernel modules from the service and classifies paths for review. It does not verify driver signatures or manage Driver Store packages. No install/update/reinstall/remove action is enabled.
- Network route reads up to 32 adapters and 256 active TCP endpoints over `Downpour.NetworkInventory.v1`; a 1 MiB client cap and 2-second timeout bound IPC. Per-interface counters produce sampled send/receive rates, and history preserves unavailable gaps. There is no PID attribution, packet capture, DNS history, or detection.
- Security Events route: service polls 35 fixed v29 event/channel pairs across seven Windows Event Log channels every 15 seconds and subscribes to future allow-listed records via seven `EventLogWatcher`s. A 512-record nonblocking queue coalesces events into ≤256-row batches; polling remains a fallback and visible warnings report unavailable subscriptions or queue loss. Client and service share a strict source/event catalog; IPC and per-channel reads are bounded. Event message bodies, script text, usernames, command lines, and event XML are not collected. Security 4625 failures are excluded from individual push records and aggregated across a five-minute query into one HIGH threshold observation at ten failures (count capped at 100). Service smoke check: 7/7 push subscriptions opened; polling could read 6/7 channels on this machine. See `docs/WINDOWS_EVENTS.md`.
- Alerts route: validated event observations from polling and push both project into a protected local SQLite database, stable IDs derive from source record identity, duplicate events upsert rather than adding rows, and retention is capped at 30 days/10,000. 4625 burst observations deduplicate by five-minute time bucket. Local acknowledge/suppress/reopen uses a strict bounded pipe with expected-state and replay checks; it changes only local review state. The latest 512 alerts are shown. Cross-channel service-install/log-clear time-proximity rules are available, with strict limitations. This is not full v29 detection correlation or response. Details in `docs/ALERTS.md`.
- Alert false-positive slice (DN-005 follow-on): alert DB schema v2 migrates schema v1; explicit user confirmations increment persistent rules keyed only by fixed event channel/provider/event ID. Three confirmations suppress matching new and existing alerts; Re-arm clears the rule and reopens only records it auto-suppressed. Confirmation/re-arm request IDs are durable and retry-safe. UI has explicit FP confirm and Re-arm actions. This is a local user review feature, not a confidence model or event-body detector.
- Investigation export slice (DN-005): Alerts page has a Windows save-picker action for a point-in-time JSON snapshot of the latest validated 512 alerts. The Core export builder revalidates the contract, emits only documented alert metadata/warnings, escapes HTML-sensitive text, and caps output at 1 MiB. No event body, username, command line, or file content is exported. Added tests for metadata field scope, malformed snapshot rejection, and size bounds. Native picker interaction still needs a click-through.
- Services route: native SCM enumeration is capped at 512 rows and 16 pages, service text is bounded, startup type uses query-only service access, and access denied/unknown/partial states remain explicit. A separate `Downpour.WindowsServiceInventory.v1` output-only pipe and bounded schema-validating Core client feed a searchable WinUI page with a 30-second refresh. No service start/stop/configuration actions exist. Debug and Release builds are clean; all 54 tests pass.
- The service initializes a versioned SQLite operation journal under `%LOCALAPPDATA%\DownpourNext\state`, with an explicit current-user + SYSTEM DACL, SQLite WAL/FULL durability, transactional operation projection/event appends, bounded typed state transitions, and restart-visible pending work. Schema v2 labels the service account SID correctly, restricts object IDs to generated tokens, binds begin retries to their original event, keeps failed/uncertain records pending, and blocks generic finalization of uncertain records. Journal records are path-free and the API performs no action. Local same-user malware/admin can still alter the DB; this is not tamper-proof. No retention UI/policy, action IPC, or quarantine action exists yet. See `docs/ACTION_JOURNAL.md`.
- Threat Intelligence includes advisory CISA KEV, explicit single-CVE FIRST EPSS enrichment, and the Vulnerabilities route's local installed-software inventory with cautious KEV product-name candidate matching. The inventory reads only uninstall-key display name/version/publisher and SystemComponent, with bounded rows/fields and current-user-restricted output-only IPC. Candidate matching requires vendor evidence and a meaningful product phrase at the end of an application name; it is a manual lead only, not affected-version analysis or a vulnerability verdict. No EPSS disk cache, bulk feed, NVD/CVSS/CPE, or Sigma/YARA yet; see `docs/THREAT_INTELLIGENCE.md`.
- The dashboard now has a user-started update control beside the online/offline status. It checks only the fixed GitHub repository's latest stable release, validates exact tag/page/asset and SHA-256 metadata, caps transfer and archive expansion, rejects redirects outside GitHub's release asset host, traversal, duplicates, and links, and stages before applying after the app closes its owned service. The same signed-in user runs the updater; it replaces package-owned paths, preserves user data under `%LOCALAPPDATA%`, attempts rollback on failure, and restarts. There is no silent periodic update. It remains unsigned: the GitHub digest is transport integrity data, not independently authenticated publisher provenance. See `docs/UPDATES.md`; code-signing/signed manifest and native update click-through remain open.
- Settings now has one consolidated route with persistent local preferences for weather visuals, reduced motion, and automatic storm cycling. Toggle handlers are attached only after XAML initialization following a user-reported Settings crash. Build/test and launch pass; native interactive confirmation is outstanding. See `docs/SETTINGS.md`.
- The old Downpour source was searched for driver behavior. It includes a KernelDriverAuditor, BYOVD name/path checks, and a new-driver baseline monitor; no driver package maintenance UI/workflow was found in the targeted code/module-map search. See `docs/DESIGN_REFERENCES.md`.
- TMOG informed graph semantics only, not page layout. CPU/memory and network samples are graphed without interpolating unavailable readings. Additional per-core, disk, GPU, thermal, energy, and history-replay views remain planned.
- Other security engines, scans, all but the initial CISA KEV feed, most event detections, security-policy settings, hardening, forensics, AEGIS layers, and response actions remain unported. The operation journal is only a prerequisite foundation; it does not make the product's action workflows functional yet.
- Tests cover route-registry integrity, live system/driver/network/event providers, KEV/event parsing bounds and validation, missing-service behavior, brute-force aggregation, and authenticated local IPC round-trips. UI/Core JSON uses pinned Newtonsoft.Json 13.0.4, disables type-name handling, and bounds local/IPC payloads.
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

- `dotnet build Downpour.slnx -c Release`: passed with 0 warnings and 0 errors after journal hardening.
- `dotnet test Downpour.slnx -c Release --no-build`: 51 passed, 0 failed; includes v1-to-v2 migration, strict object ID grammar, event retry binding, failure/recovery visibility, temporary-folder DACL checks, and existing event-monitor coverage.
- Packaged self-contained x64 desktop startup smoke test: direct EXE launch started its bundled `Downpour.Service.exe`; closing the app window stopped the child process. An earlier forced termination intentionally bypassed graceful cleanup; that smoke-test process was cleaned up before the successful graceful-close check.
- Refreshed portable package: `artifacts/DownpourNext-win-x64-preview-v012.zip`, SHA-256 `A8E51B054DE44956B9959B74F6E92878987470F41015273892EE24964E2EF5C3`; archive inspection confirmed desktop EXE, service EXE, and CMD launcher. Published as a GitHub prerelease asset; release page confirms the asset name, digest, and 148 MB size.
- Self-contained x64 desktop/service publish passed to `artifacts/DownpourNext-win-x64-settings-fix`; packaged EXE and launcher are present. The user-reported Settings failure aligns with a XAML/WinUI crash recorded by Windows Error Reporting; toggle handlers now attach after initialization. The new EXE remained running in the startup smoke check, but the Settings click path has not yet been interactively verified. ZIP: `artifacts/DownpourNext-win-x64-preview-settings-fix.zip`, SHA-256 `771F1EA78E6BEC9A6BD71982968F37BD56A11BE8C21DF46150F7A44D0A70F96A`. The bundle has no trusted signature and is not an installer.
- Manual named-pipe smoke test initially failed with `Access to the path is denied.` The ACL was tightened to the current user SID plus LocalSystem, with read-only client data rights, and the integration test verifies same-user access. A same-user process can still spoof a pipe until server identity verification is implemented.
- WinUI packaged app was captured via `PrintWindow`; live CPU/memory gauges/history, clear landscape, separate moon, visible rain mode control, and denser animated precipitation render. Network page is provider/IPC tested; native route interaction and narrow/high-DPI review remain outstanding.
- GitHub repository at `https://github.com/christiand0797/downpour-next` is public to support anonymous release checks/downloads; the user explicitly authorized exposing source and history. A credential-pattern scan of tracked commit diffs found no GitHub/AWS/private-key markers. Full secret-scanner audit remains advisable.

## Immediate next actions

1. Verify the Settings route opens and saves preferences in a native interactive click-through; continue native route/layout review, especially responsive width on narrow windows.
2. Continue DN-002 native route/layout review, especially the Settings click-through and narrow/high-DPI widths.
3. Ingest additional independently allow-listed feeds and correlate with local software inventory.
4. Finish the wider DN-005 parity work: v29 source/rule mapping, cross-source alert correlation, push event subscriptions, Sigma/AMSI analysis, Sysmon/ETW, and investigation/export flows.
6. Define a signed installer and dedicated restricted service identity before creating any action IPC. The current portable service runs as the interactive user and must remain observe-only.
7. Implement quarantine/restore only after client authentication, explicit consent, protected storage, audit-failure handling, and verifiable recovery are in place.
8. Port the original driver's BYOVD/signature/path audit semantics with current signed intelligence and independently validated evidence.
9. Design the driver package broker for verified install/update/reinstall/remove with package verification, export/rollback, explicit elevation, and audited consent. No such action is safe to enable yet.
10. GitHub Actions remains configured but its first run was blocked by the account billing/spending-limit notice; this work was built/tested locally without relying on Actions.
11. Reconcile the complete module map, screens, configs, feeds, rules, workflows, storage, and action paths before declaring feature parity.

## Architecture and safety constraints

See `AGENTS.md`, `SECURITY.md`, `docs/SECURITY_MODEL.md`, `docs/FEATURE_PARITY.md`, and `docs/ARCHITECTURE_AND_MIGRATION.md`. The only enabled service behavior is observation. The pipe server endpoint is outbound-only; access is limited to the current user SID and LocalSystem. Do not enable system-changing actions without a reviewed allow-list, authorization policy, audit record, timeout, recovery path, and denial tests.




