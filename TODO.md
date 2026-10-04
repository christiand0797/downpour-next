# Downpour Next TODO

This checklist tracks current implementation state; the detailed order, dependencies, and acceptance criteria are in [`WORK_QUEUE.json`](WORK_QUEUE.json).

## Foundation

- [x] Create private GitHub repository and push the initial WinUI/.NET solution.
- [x] Inventory 33 source routes and 71 module-map entries.
- [x] Add dark crescent/rain dashboard shell and route-status pages.
- [x] Add schema-v1 read-only system/process snapshot contracts and Windows provider.
- [x] Add CI-testable registry and snapshot tests.
- [x] Fix named-pipe ACL and add a schema-v1 local pipe integration test; verify test discovery and behavior on this host.
- [x] Extend the whole-app background with a generated crescent/rain scene and restrained animated stars/rain.
- [x] Add live CPU/memory gauges and a history graph that preserves missing-data gaps.
- [x] Add a dedicated read-only Drivers route with bounded live kernel-driver inventory and path review.
- [ ] Visually and interactively validate online/offline dashboard, process, and driver pages on the native app.
- [x] Configure Windows CI and Dependabot; pin wildcard package dependencies.
- [ ] Resolve GitHub's account billing/spending-limit notice, then verify remote CI and Dependabot runs.

## Feature parity

- [ ] Reconcile source modules, config, background jobs, feeds, rules, persistent state, and actions with the module map.
- [ ] Port network, event-log, ETW/Sysmon, registry, file, and device sensors.
- [ ] Port normalized detection pipeline, alert lifecycle, investigation, suppression, and reporting.
- [ ] Port file/PE/YARA scans, threat feeds, vulnerability checks, cache, and rule management.
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
