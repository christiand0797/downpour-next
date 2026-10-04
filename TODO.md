# Downpour Next TODO

This checklist tracks current implementation state; the detailed order, dependencies, and acceptance criteria are in [`WORK_QUEUE.json`](WORK_QUEUE.json).

## 2026-10-04 continuation checkpoint

- DN-004 live event push subscriptions are implemented in `SecurityEventProvider`, `SecurityEventPushWorker`, and bounded merge/status helpers; pushed allow-listed metadata joins the existing deduplicated alert projection while periodic polling remains fallback. Subscription failures and queue drops are visible. Individual 4625 push records are intentionally excluded in favor of the existing aggregate-only five-minute detector. Release build: 0 warnings/errors; 74 tests pass. Service smoke check: 7/7 watcher subscriptions opened, polling could read 6/7 channels. [v0.1.8](https://github.com/christiand0797/downpour-next/releases/tag/v0.1.8) package SHA-256 `472BCDB927686643976765550638D333795EE34D2A9D1C5D7833A022F28FABAD`; all 764 staged files match `DownpourNext-Portable/`. Commit `e0720df` is pushed. Actual event generation through each Windows channel remains an integration check.
- DN-005 cross-channel correlation is implemented and pushed in `29a0d4d`; [v0.1.7](https://github.com/christiand0797/downpour-next/releases/tag/v0.1.7) adds time-proximity-only patterns for System 7045/Security 4697 and Security 1102/System 104, with bounded one-to-one pairing, stable evidence IDs, suppression filtering, UI summary, and schema-v2 export. Release build: 0 warnings/errors; 70 tests pass. ZIP SHA-256 `106C09CB9DFCD4506000C709433991395AEF41FA13FBF1EAF57F4C42EA1963C5`; all 764 staged files match `DownpourNext-Portable/`. Correlation limitations are documented; native UI click-through remains outstanding.
- DN-005 investigation export is implemented in `src/Downpour.Core/AlertInvestigationExport.cs` and `AlertsPage`: export a point-in-time snapshot of up to 512 validated alert rows as bounded metadata-only JSON using the OS save picker. Contract/privacy tests pass; full Release build is clean with 65 tests passing. Source `d305c2a` is pushed; [v0.1.6](https://github.com/christiand0797/downpour-next/releases/tag/v0.1.6) package SHA-256 `F9FA96476CD3FF082F0353EE9B4F0BD25198E8FE91894E76E7C5BC7222E0010B`; the 764-file local `DownpourNext-Portable/` matches staging. App/service smoke test confirmed responsive UI and a live system snapshot pipe. Native save-picker click-through remains to be done.
- DN-005 continued with v29-style repeated false-positive handling. Alert DB schema v2 migrates v1 stores; alert fingerprints use only fixed channel/provider/event-ID metadata. Three explicit confirmations suppress future matching rows, and Re-arm clears the rule while reopening only alerts auto-suppressed by that rule. Retry IDs and confirmation history persist. Manual single-alert suppression remains separate. Release build/test: 0 warnings/errors and 63 tests passing. Source `85ba7d2` is pushed; [v0.1.5](https://github.com/christiand0797/downpour-next/releases/tag/v0.1.5) portable package SHA-256 `E3578121CE3C22B2B54CC7C87B44D7D2F0782C0AF6CC85401DADD8705E86B396`; local package is in `DownpourNext-Portable/`.
- Package smoke check from local `DownpourNext-Portable/Downpour.Desktop.exe` is running and responsive; bundled `service/Downpour.Service.exe` starts successfully. All 764 local portable files match the verified publish staging files by SHA-256.
- DN-005 first connected alert slice is built and published: SecurityEventSnapshot entries persist as stable-ID event alerts, duplicate polls update rather than duplicate, 4625 bursts group by five-minute buckets, and the service applies 30-day/10,000-row retention. Alerts has local acknowledge/suppress/reopen with expected-state and request-replay checks, a bounded strict control pipe, evidence references, and explicit offline/partial source health. Release build is clean; 59 tests pass. Download [v0.1.4](https://github.com/christiand0797/downpour-next/releases/tag/v0.1.4), SHA-256 `A354894D66DA335DE205CE86F37407D538D7DB133AF3AED5D604F558FEC50A5A`.
- `docs/ALERTS.md` records IDs, evidence, retention, transition semantics, and security limits. This is not cross-source v29 alert parity; Sigma/AMSI, Sysmon/ETW, investigation, and response remain queued.

- Built the current self-contained Windows x64 package into `DownpourNext-Portable/` in the repository folder. It includes `Downpour.Desktop.exe`, `service/Downpour.Service.exe`, both launchers, and a run/limitations readme. Release build: 0 warnings/errors; tests: 54/54; EXE smoke-check found the app still running and its bundled service started. Published the 156 MB ZIP to GitHub release [v0.1.3](https://github.com/christiand0797/downpour-next/releases/tag/v0.1.3), SHA-256 `915439E1ECAAABD60DE8D3FE1FC83FF7C2C68BBEEC6F3D14677F1D724DE5C9C7`. The release is portable, unsigned, and not an installer; read-only/system-changing scope is stated on the release page.

- Security Events is a real service-backed slice: 35 fixed v29 event/channel pairs across seven sources, 15-second service polling, bounded metadata-only IPC, per-source health, severity/search filters, and 4625 burst aggregation. `docs/WINDOWS_EVENTS.md` describes scope and missing detection parity. Source is pushed; no new preview release was created.
- Three parallel agents mapped v29 action priorities, reviewed the event work, and wired the Security Events route. Their findings are captured in DN-005/DN-007/DN-008 and `SHARED_CONTEXT.md`. Begin action work with durable audit/recovery foundations and narrow quarantine/restore operations; do not enable a broad arbitrary-command broker.
- Added a service-side SQLite journal foundation: protected user/SYSTEM state directory, schema v2 migration, transactional projection/event writes, fixed action/state enums, idempotent event IDs, legal transition checks, and restart-visible pending recovery. Tests cover ACLs, v1 migration, reopen, ordering, replay binding, rollback, recovery visibility, and bounds. This is not tamper-proof against same-user malware and does not authorize or perform any action. Details: [`ACTION_JOURNAL.md`](docs/ACTION_JOURNAL.md).
- Latest source checkpoint is `ce0bcd9`; package release is `v0.1.3`. The Services route now has bounded SCM inventory, query-only startup-type lookup, separate output-only IPC, a searchable page, and explicit partial/access-denied status. Release build is clean and 54 tests pass. No start/stop/configure controls are present.

- Desktop EXE now attempts to start the bundled read-only sensor service itself, reuses an existing service, and stops only a child service it owns on graceful window close. UI labels the app as running while clearly identifying unavailable local telemetry as `SERVICE OFFLINE`; a healthy snapshot is labeled `ONLINE`.
- Process inventory is expanded from 8 to up to 512 rows with bounded names/payloads. Windows PID 0 (`Idle`) is excluded because the snapshot contract requires a real process ID; malformed oversized pipe messages return an unavailable result instead of escaping the client.
- Verification: Release build 0 warnings/errors; `dotnet test Downpour.slnx -c Release`: 22 passed; self-contained x64 direct-launch smoke test confirmed service auto-start and graceful shutdown. Source commit `03ca465` is pushed and [v0.1.2-preview](https://github.com/christiand0797/downpour-next/releases/tag/v0.1.2-preview) contains the 148 MiB ZIP (SHA-256 `A8E51B054DE44956B9959B74F6E92878987470F41015273892EE24964E2EF5C3`).
- Remaining DN-002 work: native Settings/navigation click-through and narrow/high-DPI layout review. Full Downpour v29 parity is still in progress; see `SHARED_CONTEXT.md` and `docs/FEATURE_PARITY.md`.
- Telemetry pipe ACLs are narrowed from all authenticated local users to LocalSystem and the service's current account. Same-account snapshot/driver/network pipe integration tests pass. Commit `1e9af4b` pushed.
- Added `Start-Downpour-Next.bat` to launch the self-contained desktop EXE directly; the app starts its bundled sensor service. Source/docs commit `2f77f9a` pushed. Existing release bundle still includes its `.cmd` launcher; no new preview release was created.
- Product direction: implement full v29 parity and more, including authorized/audited actions. Read-only is only the current collection phase; sensitive changes must include explicit user authorization, previews, logs, and rollback/recovery where possible.

## Foundation

- [x] Create private GitHub repository and push the initial WinUI/.NET solution.
- [x] Inventory 33 source routes and 71 module-map entries.
- [x] Add dark crescent/rain dashboard shell and route-status pages.
- [x] Add schema-v1 read-only system/process snapshot contracts and Windows provider.
- [x] Add CI-testable registry and snapshot tests.
- [x] Fix named-pipe ACL and add a schema-v1 local pipe integration test; verify test discovery and behavior on this host.
- [x] Separate the clear static night landscape from the realistic crescent overlay, stars, and animated storm system.
- [x] Add drizzle, storm, thunderstorm, and hurricane modes with rain, wind, and lightning scaling; manual selection holds the chosen mode.
- [x] Add live CPU/memory gauges and a history graph that preserves missing-data gaps.
- [x] Add a dedicated read-only Drivers route with bounded live kernel-driver inventory and path review.
- [x] Add a read-only Network route with per-interface throughput/totals, active TCP endpoints, bounded IPC, and gap-preserving history.
- [x] Add read-only Windows Services inventory with service state/startup type, bounded IPC, search, freshness, and explicit permission/partial status.
- [ ] Visually and interactively validate online/offline dashboard, process, and driver pages on the native app.
- [x] Configure Windows CI and Dependabot; pin wildcard package dependencies.
- [ ] Resolve GitHub's account billing/spending-limit notice, then verify remote CI and Dependabot runs.

## Feature parity

- [ ] Reconcile source modules, config, background jobs, feeds, rules, persistent state, and actions with the module map.
- [ ] Port Windows event-log, ETW/Sysmon, registry, file, and device sensors; add connection process attribution and network detection.
- [ ] Port normalized detection pipeline, alert lifecycle, investigation, suppression, and reporting.
- [ ] Port file/PE/YARA scans, threat feeds, vulnerability checks, cache, and rule management.
- [x] Add initial bounded, advisory CISA KEV ingestion and searchable Threat Intelligence route; see [`docs/THREAT_INTELLIGENCE.md`](docs/THREAT_INTELLIGENCE.md).
- [x] Replace the generic Settings route with a single local preferences page for supported rain/motion/storm-cycle controls; see [`docs/SETTINGS.md`](docs/SETTINGS.md).
- [ ] Port all five AEGIS layers and advanced protection watchers.
- [ ] Port quarantine, rollback, remediation, hardening, firewall, Defender compatibility, parental controls, cleanup, VPN, remote access, and emergency response.
- [ ] Add local persistence, migration, backup/restore, audit/history, diagnostics, installer, upgrade, and uninstall workflows.
- [ ] Achieve and document feature parity before adding new security features.

## Product quality and self-security

- [ ] Security review of IPC, service identity, installer/service permissions, updates, feeds, storage, parsers, and response broker.
- [ ] Verify driver signatures/packages, add driver install/update/reinstall/remove with an audited recovery-first broker.
- [ ] Add fuzz/property tests for untrusted contracts, rule formats, manifests, and file metadata.
- [ ] Add accessible keyboard navigation, high contrast, reduced motion, DPI/responsive layout, and clear sensor freshness.
- [ ] Define performance budgets and compare against Downpour on the same Windows machine.
