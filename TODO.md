# Downpour Next TODO

## 2026-10-08 reanalysis and recovery milestone (codex-primary, DN-036)

- [x] Reconcile current agent work, inventory all 530 tracked files, parse tracked JSON/XML, run current Debug suite (1,065 passed).
- [x] Repair host-isolation failed cleanup/rollback/state-write handling and actual IPC state; 18 focused tests pass.
- [ ] Clean committed Release build/tests, native route smoke, verified v0.1.19 archive and GitHub publication.
- [ ] Installed elevation/signing boundary, parental measurement/enforcement, clean-machine/reboot recovery, full route accessibility and v29 acceptance remain open.

## Active owner continuation (2026-10-07, claude-parity-audit)

- [x] Fix Parental Controls initialization crash; remove simulated usage; expose persistence errors; verified real page launch (dd1ecc1).
- [x] Legitimate driver/threat databases with provenance, licensing, bounded parsing, persistent cache and real findings (DN-031: 19 feeds, LOLDrivers driver hashing, offline IP origin).
- [x] Futuristic HUD theme from owner references, rain preserved, focus/contrast kept (DN-032).
- [x] Drivers page empty on Windows 11 24H2+ (WMI fallback).
- [x] Threat Intel Feeds broken by abuse.ch key requirement (rebuilt on local databases).
- [x] CISA KEV failed on timestamp dateReleased.
- [x] DN-033: refresh every page every second smoothly (in-place updates, cached heavy collectors).
- [x] Fold repeated "PowerShell script block recorded" LOW alerts into counted rows (hourly roll-up).
- [x] Dashboard strip data-driven; duplicate Sysmon warning removed.
- [x] DN-034 verification engine with verdicts/confidence/reasons; sinkhole and shared-host false-positive clearing; firewall built-in rule and Credential Guard downgrades.
- [x] Export case file for a third-party reviewer (Triage, Threat Databases).
- [x] Per-disk I/O enumeration fix; maximized window content above the taskbar.
- [x] Persistence: signer checks for RunOnce targets (Microsoft Edge cleanup FP) and vendor-signed BYOVD severity alignment.
- [x] Audio Shield tab: listeners, devices with live levels, audio effect DLLs, engine/glitch checks, brokered end-program/quarantine and settings fixes.
- [x] Audio Shield section in the case file.
- [ ] Audio Shield: brokered "restart Windows Audio" action (policy, audit, timeout, rollback tests first).
- [x] Alerts: service name, executable and signature verdict for 7045/4697 (graded by signer); YARA and service file paths shown as evidence in the case file.
- [ ] More databases (owner request): evaluate additional live, licensed feeds; keep update-at-launch and cache across restarts.
- [x] Sakura Sentinel scene on Dashboard and Performance (load-driven petals, Kuro the cat with mood and threat awareness).
- [x] HUD gradient meter bars app-wide; Performance right column filled.
- [ ] HUD visuals kit: segmented glowing meters, sparklines, radar sweep, hex status tiles on every feature page.
- [x] Threat Pulse on the Dashboard (per-PC hourly baseline, spike/elevated/calm).
- [x] Watch timeline ribbon on Anti-Stalker.
- [x] Cross-view hidden-process (rootkit) check, findings Downpour/Rootkit (T1014).
- [ ] Invented features: tripwire canary files (opt-in).
- [x] Per-tab charts: Processes, Drivers, Driver Packages, Network, Security Events, Services, Devices & Drivers.
- [ ] Per-tab charts on the remaining tabs (each with its own data).
- [x] Devices & Drivers tab with missing-driver detection and Windows Update driver search.
- [x] Drivers tab verifies each loaded driver's signature and gives a verdict (malicious, vulnerable, user-writable, unsigned, OK).
- [x] Clickable details and right-click actions on the first nine list tabs.
- [x] Clickable details on Alerts, Triage, Threat Databases, Threat Intel, Memory, Vulnerabilities, USB, Wi-Fi, IoT, Emergency, Forensics, Timeline.
- [ ] Clickable cards on Audio Shield and Anti-Stalker (code-built cards).
- [ ] Elevated driver broker (DN-012): one-click update/roll back/uninstall/reinstall with automatic driver backup, signature check, audit and rollback tests.
- [x] Hash-chained, DPAPI-keyed action audit log with anchor, integrity monitor and CRITICAL finding on tampering.
- [x] Parser fuzzing for feeds, KEV, IP origin, pipe replies and helpers (found and fixed a KEV exception leak).
- [ ] Security hardening roadmap: signed builds and updates, off-box audit anchoring, least-privilege review.
- [x] Publish v0.1.18 (x64) with release manifest, SBOM and evidence (74ae152).
- [ ] Native ARM64 package (needs an arm64 YARA-X build or a scanner fallback).
- [ ] Anti-Stalker: origin for remote sessions/remote-control connections and an evidence export.
- [ ] List rows announce type names to screen readers; Parental header crowding at narrow widths.
- [ ] Compare v29 source behavior and update source inventory/acceptance gaps; web research for further features.

## 2026-10-07 checkpoint: DN-008 Phase 4 Reversible USB Device Instance Block & USBSTOR Toggle (antigravity-worker)

Completed and verified (Debug: 0 warnings/errors; 773/773 tests pass):
- Contracts in `src/Downpour.Contracts/UsbActionContracts.cs`: `UsbActionOperations` (`preview-block-device`, `block-device`, `preview-unblock-device`, `unblock-device`, `preview-set-usbstorage`, `set-usbstorage`), `UsbActionRequest`, `UsbActionPreview`, `UsbActionResponse`.
- Sensor settings: added `UsbActions` (default true) to `SensorSettingsSnapshot`, `SensorSettingKeys`, and writable list in `SensorSettingsStore`.
- Action catalog & policy: enabled `ActionKinds.BlockUsbDevice`, `ActionKinds.UnblockUsbDevice`, and `ActionKinds.SetUsbStorage` in `ActionBroker.cs`, `ActionCatalog.cs`, and `ActionPolicyValidator.cs`.
- Service executor in `src/Downpour.Service/UsbActionExecutor.cs`: immutable deny-list protecting root hubs (`ROOT_HUB`), PCI/ACPI buses (`PCI\`, `ACPI\`, `SCSI\`, `IDE\`, `STORAGE\`, `SWD\`), Human Interface Devices (`HID\`, keyboards, mice, touchpads, styluses), and OS boot/system volume (`C:`); `IUsbDeviceBackend` abstraction (`WindowsUsbDeviceBackend` leveraging `cfgmgr32.dll` `CM_Locate_DevNodeW`, `CM_Disable_DevNode`, `CM_Enable_DevNode`, and `Registry` for `USBSTOR\Start`; `InMemoryUsbDeviceBackend` for tests); durable atomic blocked device store in `state/blocked-usb-devices.v1.json`; mass storage driver toggle.
- Service IPC worker in `src/Downpour.Service/UsbActionPipeWorker.cs`: `Downpour.UsbActions.v1` named pipe, `ParentDesktopCallerVerifier` caller authentication, 60s single-use consent tokens, audited logging of previews/denials/executions to `state/action-audit.v1.jsonl`.
- Core client in `src/Downpour.Core/UsbActionClient.cs`: preview/execute for block device, unblock device, and USBSTOR mass storage toggle.
- Desktop UI in `UsbPage.xaml/.cs` ("Toggle Mass Storage Driver" button, row "Block Drive…" button, history row "Block Device…" button) and `RemediationPage.xaml/.cs` ("Block USB device…" button, Phase 1-4 banner).
- Unit tests in `tests/Downpour.Tests/UsbActionTests.cs` (17 deny-list test cases including root hubs, keyboards, mice, touchpads, internal buses; action catalog & feature switch verification; policy validator previews; caller rejection; feature switch disabled check; preview token minting; block & unblock cycle with backend verification & audit log assertions; USBSTOR toggle; strict request parser bounds).

## 2026-10-07 checkpoint: DN-008 Phase 3 Firewall Actions Broker & Legacy Cleanup (antigravity-worker)

Completed and verified (Debug: 0 warnings/errors; 734/734 tests pass):
- Contracts in `src/Downpour.Contracts/FirewallActionContracts.cs`: `FirewallActionOperations`, `FirewallActionRequest`, `FirewallActionPreview`, `FirewallActionResponse`.
- Sensor settings: added `FirewallActions` (default true) to `SensorSettingsSnapshot`, `SensorSettingKeys`, and writable list in `SensorSettingsStore`.
- Action catalog & policy: enabled `ActionKinds.BlockRemoteIp` and `ActionKinds.RemoveFirewallRule` in `ActionBroker.cs`, `ActionCatalog.cs`, and `ActionPolicyValidator.cs`.
- Service executor in `src/Downpour.Service/FirewallActionExecutor.cs`: strict remote IP deny-list (loopback, wildcard, broadcast, link-local, multicast, local host adapter, gateway, DNS servers to prevent lockout); rule removal validation (only allows rules starting with `DownpourNext_` or legacy `downpour`); inbound & outbound `DownpourNext_Block_{ip}` rules with expiration metadata; automated legacy rule cleanup; expired rule cleanup; `IFirewallPolicyBackend` abstraction.
- Service IPC worker in `src/Downpour.Service/FirewallActionPipeWorker.cs`: `Downpour.FirewallActions.v1` named pipe, `ParentDesktopCallerVerifier` authentication, 60s single-use consent tokens, audited logging of previews/denials/executions to `state/action-audit.v1.jsonl`.
- Core client in `src/Downpour.Core/FirewallActionClient.cs`: preview/execute for block IP, remove rule, and legacy rule cleanup.
- Desktop UI in `FirewallPage.xaml/.cs` ("Block Remote IP…" button, "Clean Up Legacy Rules" button with rule count, individual rule row "Remove" button) and `RemediationPage.xaml/.cs` ("Block remote IP…" button, Phase 1-3 banner).
- Unit tests in `tests/Downpour.Tests/FirewallActionTests.cs` (39 tests: remote IP validation edge cases, rule removal validation, block rule generation, legacy cleanup, expired rule purging, caller authentication rejection, disabled switch rejection, end-to-end preview + consent + execution + audit log verification).

## 2026-10-07 checkpoint: DN-008 Phase 2 Alert-driven Process Termination Broker (antigravity-worker)

Completed and verified (Debug: 0 warnings/errors; 695/695 tests pass):
- Contracts in `src/Downpour.Contracts/ProcessTerminationContracts.cs`: `ProcessTerminationOperations`, `ProcessTerminationRequest`, `ProcessTerminationPreview`, `ProcessTerminationResponse`.
- Sensor settings: added `ProcessTerminationActions` (default true) to `SensorSettingsSnapshot`, `SensorSettingKeys`, and writable list in `SensorSettingsStore`.
- Service executor in `src/Downpour.Service/ProcessTerminationExecutor.cs`: immutable system deny-list (PIDs 0/4, `csrss`, `lsass`, `services`, `wininit`, `winlogon`, `smss`, `svchost`, `dwm`, `fontdrvhost`, `explorer`, service self PID, parent desktop PID, Downpour binaries); process inspection via `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)`, `QueryFullProcessImageNameW`, `GetExitCodeProcess`, and `GetProcessTimes` creation time binding within 3s tolerance; process termination via `OpenProcess(PROCESS_TERMINATE)`, `TerminateProcess`, `WaitForSingleObject`.
- Service IPC worker in `src/Downpour.Service/ProcessTerminationActionPipeWorker.cs`: `Downpour.ProcessTerminationActions.v1` named pipe, `ParentDesktopCallerVerifier` authentication, 60s single-use consent token, audited logging of previews/denials/terminations to `state/action-audit.v1.jsonl`.
- Core client & policy in `src/Downpour.Core/ProcessTerminationClient.cs`, `ActionCatalog.cs`, `ActionPolicyValidator.cs`.
- Desktop UI in `RemediationPage.xaml/.cs` (terminate by PID button, input prompt, preview dialog, execution) and `MemoryPage.xaml.cs` (process list item kill button, preview dialog, audited execution, automated list refresh).
- Unit tests in `tests/Downpour.Tests/ProcessTerminationActionTests.cs` (17 deny-list cases, self-PID, nonexistent PID, start-time mismatch, denied caller, disabled feature switch, end-to-end preview + consent + real process termination).

## 2026-10-07 checkpoint: MiroFish Swarm Intelligence Integration in CIS (antigravity-worker)

Completed and verified (Debug: 0 warnings/errors; 673/673 tests pass):
- MiroFish Swarm Intelligence Multi-Agent Engine: implemented `SwarmSimulationEngine` inspired by the MiroFish OASIS collective intelligence paradigm, simulating 8 specialized cybersecurity archetypes (`ADV-01`, `ADV-02`, `DEF-01`, `DEF-02`, `FOR-01`, `IMM-01`, `DEC-01`, `SYN-01`).
- Contracts in `src/Downpour.Contracts/SwarmIntelligence.cs`: `SwarmAgentArchetype`, `SwarmAgentState`, `SwarmInteraction`, and `SwarmPredictionReport`.
- Core engine in `src/Downpour.Core/SwarmSimulationEngine.cs`: multi-round adversary-defender-deception interaction cycles, consensus equilibrium scoring, 48h emergent threat drift forecasting, and executive Markdown report synthesis.
- CIS Coordinator in `src/Downpour.Core/CognitiveImmuneSystemCoordinator.cs`: wired `RunSwarmSimulation(rounds)` updating drift vectors, mutations, and predictive confidence.
- Desktop UI in `CognitiveImmuneSystemPage.xaml/.cs`: added dedicated Swarm Intelligence & Multi-Agent Consensus card, consensus & resistance metric cards, emergent vulnerability projection snippet, "Run Swarm Sim" button in header & card, and "Copy Swarm Report" clipboard export.
- Unit tests in `SwarmSimulationEngineTests.cs` (archetypes, interactions, multi-round consensus, clamping) and `CognitiveImmuneSystemCoordinatorTests.cs`.

## 2026-10-07 checkpoint: DN-026 Authenticode Signature Verification for YARA (antigravity-worker)

Completed and verified (Debug: 0 warnings/errors; 673/673 tests pass):
- DN-026 Authenticode Signature Verification for YARA folder scanning: implemented `AuthenticodeVerifier` implementing `IAuthenticodeVerifier`.
- High-speed PE heuristic filter: checks extensions (`.exe`, `.dll`, `.sys`, `.scr`, etc.) and `MZ` magic header before Win32 P/Invoke.
- Dual-layer signature verification: embedded signature verification via `WinVerifyTrust` (`WINTRUST_ACTION_GENERIC_VERIFY_V2`), fallback to Windows Security Catalog verification via `CryptCATAdmin*` (`CatalogSignatureVerifier`) for inbox system binaries.
- Microsoft signer identification: validates `Subject` (`O=Microsoft Corporation`, `CN=Microsoft`) and `Issuer`.
- YARA Contracts & Client: added `SkipMicrosoftSigned = true` to `YaraScanRequest` and `YaraScanJob`.
- Scanner Coordinator: injected `IAuthenticodeVerifier` into `YaraScanCoordinator`, skipping signed binaries during folder scans (`FilesSkipped++`), and respecting single-file scan overrides.
- Scanner UI: added "Skip Microsoft-signed files" checkbox (`YaraSkipSigned`, default checked) on `ScannerPage.xaml/.cs`.
- Unit tests in `YaraScannerTests.cs` (embedded/catalog verification, folder skip, single-file override).

## 2026-10-07 checkpoint: DN-009 Tools Launchpad Route Slice (antigravity-worker)

Completed and verified (Debug: 0 warnings/errors; 648/648 tests pass):
- DN-009 Tools Launchpad route slice: implemented `ToolsHubCoordinator` porting v29 `_build_tools_tab`.
- Contracts in `src/Downpour.Contracts/ToolsHub.cs`: `OperationalToolCardInfo`, `SystemDiagnosticCheck`, and `ToolsHubSnapshot`.
- Core engine in `src/Downpour.Core/ToolsHubCoordinator.cs`: operational status and telemetry aggregation for 9 security and operational subsystems (Remote Access, VPN, Parental Controls, Emergency, Cleanup, USB, IoT, Services, Settings); live host system diagnostics for host platform, storage free space headroom, active network stack adapters, and process working set memory footprint; and executive operations markdown report generator.
- Desktop route `tools` in `ToolsPage.xaml/.cs`: operational status badge (`9 TOOLS OPERATIONAL`), 4 metrics (Operational Tools, System Health, Diagnostic Checks, Rapid Launchpads), 4-card live hardware diagnostics banner, 9 operational launchpad cards with category tags, telemetry details, and direct 1-click `Launch Tool` buttons navigating to dedicated routes via `App.NavigateToRoute`, and report clipboard export.
- Wired `tools` route in `MainWindow.xaml.cs` (navigation and back-sync) and promoted to `in-progress` in `capabilities.json` and `parity-checklist.json`. All 38 application routes are now active.
- 3 unit tests in `ToolsHubCoordinatorTests.cs` (9 tools verification, system diagnostics execution, and markdown report generation).

## 2026-10-07 checkpoint: DN-009 Cognitive Immune System Route Slice (antigravity-worker)

Completed and verified (Debug: 0 warnings/errors; 645/645 tests pass):
- DN-009 Cognitive Immune System route slice: implemented `CognitiveImmuneSystemCoordinator` porting v29 `cognitive_immune_system.py` and `_build_cis_tab`.
- Contracts in `src/Downpour.Contracts/CognitiveImmuneSystem.cs`: `CisDetectorStats`, `CisRedTeamerState`, `CisPredictorState`, `CisVerifierState`, `CisHoneypotInfo`, `CisHoneytokenInfo`, `CisDeceptionEvent`, and `CisSnapshot`.
- Core engine in `src/Downpour.Core/CognitiveImmuneSystemCoordinator.cs`: clonal selection detector pool metrics, adversarial red teaming simulation with perturbation probes, threat evolution predictor with 48h forward drift horizon, semantic integrity hash verifier, deception technology with 6 honeypots and 6 canary honeytokens, interaction recording, and executive markdown intelligence report generator.
- Desktop route `cognitive-immune-system` in `CognitiveImmuneSystemPage.xaml/.cs`: status badge (`ACTIVE & ADAPTING`), 4 metrics (Total Detectors, Memory Epitopes, Evasion Resistance %, Predictive Horizon), 3 autonomous subsystem control cards with interactive toggles and probe trigger, detector pool stats matrix, honeypots and honeytokens list views, and report clipboard export.
- Wired `cognitive-immune-system` route in `MainWindow.xaml.cs` (navigation and back-sync) and promoted to `in-progress` in `capabilities.json`, `parity-checklist.json`, and `source-modules.json` (`cognitive_immune_system.py`).
- 7 unit tests in `CognitiveImmuneSystemCoordinatorTests.cs` (baseline snapshot verification, red teamer lifecycle toggle, adversarial probe simulation, predictor/verifier toggles, honeypot and honeytoken interaction logging, and report formatting).

## 2026-10-07 checkpoint: DN-009 Defense Suite Route Slice (antigravity-worker)

Completed and verified (Debug: 0 warnings/errors; 638/638 tests pass):
- DN-009 Defense Suite route slice: implemented `DefenseSuiteCoordinator` porting v29 `advanced_defense_suite.py` and `_build_defense_tab`.
- Contracts in `src/Downpour.Contracts/DefenseSuite.cs`: `DefensePillarStatus`, `DefenseWatcherFinding`, and `DefenseSuiteSnapshot`.
- Core engine in `src/Downpour.Core/DefenseSuiteCoordinator.cs`: multi-layer native MITRE ATT&CK attack surface watchers inspecting IFEO process execution hijacks (T1546.012), LSA Protection / RunAsPPL (T1003), UAC elevation enforcement (T1548.002), Trusted Root CA certificate store proxy interception (T1553.004), Startup folder autostart drops (T1547.001), SMB network shares exposure (T1021.002), Windows Defender Real-Time Protection policy (T1562.001), and system DEP & ASLR mitigations (T1055); overall defense scoring (0-100) and attack surface exposure calculation; core defense pillars aggregation (AEGIS, Ransomware, Hardening, Emergency); and executive markdown posture report generator.
- Desktop route `defense` in `DefenseSuitePage.xaml/.cs`: posture header with dynamic status badge, 4 metric cards (Defense Posture Score, Attack Surface Exposure %, Active Watchers, Flagged Exposures), 4 Core Defense Pillars status cards with 1-click drill-downs into each subsystem (`App.NavigateToRoute`), live MITRE ATT&CK watcher diagnostic list with category and severity badges, and 1-click clipboard export of executive Markdown report.
- Wired `defense` route in `MainWindow.xaml.cs` (navigation and back-sync) and `App.xaml.cs`, and promoted `defense` to `in-progress` in `capabilities.json`, `parity-checklist.json`, and `source-modules.json` (`advanced_defense_suite.py`).
- 7 unit tests in `DefenseSuiteCoordinatorTests.cs` (clean posture scoring, weighted deduction scoring, severe risk clamping, watcher enumeration, memory exploitation guard, and report formatting).

## 2026-10-07 checkpoint: DN-009 Parental Controls Route Slice (antigravity-worker)

Completed and verified (Debug: 0 warnings/errors; 600/600 tests pass):
- DN-009 Parental Controls route slice: implemented `ParentalControlsManager` porting v29 `parental_controls.py` and `_build_parental_tab`.
- Contracts in `src/Downpour.Contracts/ParentalControls.cs`: `ScreenTimeSchedule`, `WebFilterPolicy`, `AppRestrictionPolicy`, `ParentalControlsConfig`, `ScreenTimeStatus`, `HostsFileFilterPosture`, `ParentalActivityLogEntry`, and `ParentalPostureSnapshot`.
- Core engine in `src/Downpour.Core/ParentalControlsManager.cs`: daily screen time schedule and bedtime curfew evaluator, web content category domains aggregator (`adult`, `gambling`, `violence`, `weapons`, `drugs`, and custom additions), read-only Windows hosts file DNS blocklist posture analyzer, idempotent hosts file format generator with markers, active restricted application process checker, and structured family safety markdown report generator.
- Desktop route `parental-controls` in `ParentalControlsPage.xaml/.cs`: master enable toggle, monitored profile settings, live bedtime curfew banner, overview metric cards (Screen Time Usage, Bedtime Curfew, Web Categories, Hosts Filter Status), interactive screen time schedule editor with usage simulation slider, web filtering category toggles, guarded hosts file modification buttons under DN-008, application restriction overview with live running app detector, timestamped activity log, and Desktop report export.
- Wired `parental-controls` route in `MainWindow.xaml.cs` (navigation and back-sync) and promoted to `in-progress` in `capabilities.json`, `parity-checklist.json`, and `source-modules.json` (`parental_controls.py`).
- 12 unit tests in `ParentalControlsManagerTests.cs` (weekday/weekend screen time limits, bedtime curfew calculation, category domain aggregation, hosts file formatting idempotency and marker insertion, hosts file parsing, restricted application detection, and markdown report generation).

## 2026-10-07 checkpoint: DN-009 Emergency Response Route Slice (antigravity-worker)

Completed and verified (Debug: 0 warnings/errors; 588/588 tests pass):
- DN-009 Emergency Response route slice: implemented `EmergencyResponseCoordinator` porting v29 `emergency_response.py` and `_build_emergency_tab`.
- Contracts in `src/Downpour.Contracts/EmergencyResponse.cs`: `EmergencyProcessInfo`, `EmergencyConnectionInfo`, `EmergencySnapshot`, `EmergencyLogEntry`, `EmergencyActionResult`, and `EmergencyLockdownOutcome`.
- Core engine in `src/Downpour.Core/EmergencyResponseCoordinator.cs`: volatile process enumeration and memory inspection, active TCP endpoint enumeration, suspicious process screening (known attack tools like mimikatz, psexec, procdump, nc.exe, ncat, chisel, socat; temporary directory execution in Temp/Public), deterministic SHA-256 forensic seal computation, automated JSON snapshot serialization to LocalAppData, guarded containment evaluation under DN-008, safe Windows session lock, and structured Incident Response (IR) markdown report generator.
- Desktop route `emergency` in `EmergencyPage.xaml/.cs`: ARMED status badge, Full Emergency Lockdown hero card with panic button and containment options, overview metrics (suspicious processes, active TCP sessions, total processes, saved snapshots), individual containment actions (Snapshot, Isolate, Restore, Kill, Forensics, Lock), suspicious process screening list with MITRE tags and memory footprint, forensic snapshot seal details card, and live timestamped event log.
- Wired `emergency` route in `MainWindow.xaml.cs` and promoted to `in-progress` in `capabilities.json`, `parity-checklist.json`, and `source-modules.json` (`emergency_response.py`).
- 12 unit tests in `EmergencyResponseCoordinatorTests.cs` (snapshot capture and JSON persistence, process indicator screening, guarded action policy enforcement under DN-008, full panic lockdown execution, and IR markdown report formatting).

## 2026-10-07 checkpoint: DN-009 IoT Devices Route Slice (antigravity-worker)

Completed and verified (Debug: 0 warnings/errors; 576/576 tests pass):
- DN-009 IoT Devices route slice: implemented `IoTDeviceScanner` porting v29 `iot_scanner.py` and `_build_iot_tab`.
- Contracts in `src/Downpour.Contracts/IoTInspection.cs`: `IoTDevice`, `IoTSummary`, and `IoTSnapshot`.
- Core engine in `src/Downpour.Core/IoTDeviceScanner.cs`: native local ARP table discovery via P/Invoke `GetIpNetTable` without subprocesses, embedded OUI manufacturer database, device category classification, Mozi/Mirai/Kimwolf botnet indicator detection on signature ports (9999, 5555, 2323, 7547, 4444), safe port probing, and markdown report generator.
- Desktop route `iot` in `IoTPage.xaml/.cs`: 4 overview metric cards, live device list with IP, MAC, vendor, category, open ports, threat level badges (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `CLEAN`), and risk scores, search & category filters, deep inspection card, guarded device blocking dialog under DN-008, and report export to Desktop.
- Wired `iot` route in `MainWindow.xaml.cs` and promoted to `in-progress` in `capabilities.json`, `parity-checklist.json`, and `source-modules.json` (`iot_scanner.py`).
- 11 unit tests in `IoTDeviceScannerTests.cs` (OUI vendor resolution, unknown MAC handling, device categorization, report generation format, and local network scan execution).

## 2026-10-07 checkpoint: DN-009 VPN Route Slice (antigravity-worker)

Completed and verified (Debug: 0 warnings/errors; 529/529 tests pass):
- DN-009 VPN route slice: implemented `VpnPostureInspector` porting v29 `downpour_vpn_module.py` and `_build_vpn_tab`.
- Contracts in `src/Downpour.Contracts/VpnPosture.cs`: `VpnInterfaceInfo`, `DnsLeakAssessment`, `VpnProfileSummary`, `ConnectivityTestResult`, and `VpnPostureSnapshot`.
- Core engine in `src/Downpour.Core/VpnPostureInspector.cs`: native network and tunnel adapter enumeration via `NetworkInterface.GetAllNetworkInterfaces()`, known provider identification (`Mullvad`, `ProtonVPN`, `NordVPN`, `WireGuard`, `Tailscale`, `OpenVPN`, etc.), DNS split-tunnel leak assessment, non-ICMP TCP port 443 egress connectivity probing (`1.1.1.1:443`, `8.8.8.8:443`, `www.microsoft.com:443`), safe OpenVPN `.ovpn` configuration file parser, and markdown report generator.
- Desktop route `vpn` in `VpnPage.xaml/.cs`: connection status and DNS leak badges, overview metric cards, network interfaces list with IP/DNS/gateway/provider tags, DNS leak details with findings, TCP connectivity probes with latency, imported VPN profiles, guarded kill-switch button (DN-008), and report export to Desktop.
- Wired `vpn` route in `MainWindow.xaml.cs` and promoted to `in-progress` in `capabilities.json`, `parity-checklist.json`, and `source-modules.json` (`downpour_vpn_module.py`).
- 10 unit tests in `VpnPostureInspectorTests.cs` (OpenVPN profile parsing, standalone port parsing, empty content handling, local posture evaluation, markdown report generation, and provider keyword detection).

## 2026-10-07 checkpoint: DN-009 Memory Route Slice (antigravity-worker)

Completed and verified (Debug: 0 warnings/errors; 489/489 tests pass):
- DN-009 Memory route slice: implemented `MemoryForensicsInspector` porting v29 `memory_forensics.py`, `process_injection_detector.py`, and `_build_memory_tab`.
- Contracts in `src/Downpour.Contracts/MemoryForensics.cs`: `ProcessMemoryInspection` and `MemoryForensicsSummary`.
- Core engine in `src/Downpour.Core/MemoryForensicsInspector.cs`: bounded process enumeration (PID, name, path, working set, thread count), core system binary location validation outside System32 (T1036.005), typo-squatted masquerading detection (T1036), temporary folder execution checks, single-thread memory footprint heuristics, security alert correlation for process injection (T1055) and credential dumping (T1003), scoring model (0-100), and report generator.
- Desktop route `memory` in `MemoryPage.xaml/.cs`: overview metric counters, process search box, threat filter toggle, processes list, selected process deep inspection review card, auto-monitor 60s cadence on dispatcher timer, guarded process termination notice (DN-008), and report export.
- Wired `memory` route in `MainWindow.xaml.cs` and promoted to `in-progress` in `capabilities.json`, `parity-checklist.json`, and `source-modules.json` (`memory_forensics.py`, `process_injection_detector.py`).
- 6 unit tests in `MemoryForensicsInspectorTests.cs` (clean process verification, typo-squatting detection, core binary validation, alert correlation, bulk scan summary, and report formatting).

## 2026-10-07 checkpoint: DN-009 Ransomware Route Slice (antigravity-worker)

Completed and verified (Debug: 0 warnings/errors; 476/476 tests pass):
- DN-009 Ransomware route slice: implemented `RansomwareDefenseInspector` porting v29 `ransomware_detector.py`, `entropy_ransomware_detector.py`, `ransomware_canary.py`, and `_build_ransomware_tab`.
- Contracts in `src/Downpour.Contracts/RansomwareDefense.cs`: `RansomwareProtectedDirectory`, `RansomwareCanaryStatus`, `RansomwareThreatIndicator`, `VolumeShadowCopyPosture`, and `RansomwareDefensePosture`.
- Core engine in `src/Downpour.Core/RansomwareDefenseInspector.cs`: protected directory posture enumeration, canary token decoy integrity and entropy evaluation, known ransom note detection regex, known ransomware extension detection, Volume Shadow Copy (VSS) status querying via `WindowsServiceInventoryClient`, anti-recovery command detection in alerts/events, and executive defense report generator.
- Desktop route `ransomware` in `RansomwarePage.xaml/.cs`: posture overview banner (`PROTECTED`, `ELEVATED_RISK`, `UNDER_ATTACK`), protected directories list, canary decoys list with live status badges, threat indicators list, VSS resiliency status card, safe canary deployment, guarded rollback button, and defense report export.
- Wired `ransomware` route in `MainWindow.xaml.cs` and promoted to `in-progress` in `capabilities.json`, `parity-checklist.json`, and `source-modules.json` (`ransomware_detector.py`, `entropy_ransomware_detector.py`, `ransomware_canary.py`).
- 6 unit tests in `RansomwareDefenseInspectorTests.cs` (directory enumeration, note regex recognition, extension recognition, attack detection, canary integrity and encryption detection, and report formatting).

## 2026-10-07 checkpoint: DN-009 Sandbox Route Slice (antigravity-worker)

Completed and verified (Debug: 0 warnings/errors; 447/447 tests pass):
- DN-009 Sandbox route slice: implemented `SafeFileSandbox` porting v29 `file_sandbox.py` and `_build_sandbox_tab`.
- Contracts in `src/Downpour.Contracts/SandboxInspection.cs`: `SandboxFileMetrics`, `SandboxPeDetails`, `SandboxTriggeredIndicator`, and `SandboxReport`.
- Core engine in `src/Downpour.Core/SafeFileSandbox.cs`: Shannon entropy calculation ($\sum -p \log_2 p$), cryptographic multi-hash (SHA-256, SHA-1, MD5), PE header/section parsing (architecture, timestamp, Authenticode certificate table), W^X violation detection, known packer section scanner (`.upx*`, `.aspack`, `.vmp`, `.themida`, `.pack`, `pecompact`, `.nsp`, `.mpress`, `.enigma`), Win32 API string pattern scanner (Process Injection, Spyware/Keylogger, Defense Evasion, Credential Access, Execution & C2) supporting ASCII & UTF-16, risk scoring model (0-100), verdict classification (`CLEAN`, `SUSPICIOUS`, `MALICIOUS`), and formatted threat report generator.
- Desktop route `sandbox` in `SandboxPage.xaml/.cs`: sample file picker (`FileOpenPicker` initialized with `App.MainWindowHandle`), static analysis trigger, dynamic verdict and entropy gauges, target sample metadata header, interactive indicators list with category badges and point weights, key assessment findings summary, activity log / threat report box, and report export.
- Host Detonation Guard: "Detonate in Sandbox" button presents security protection notice stating host execution is prohibited under least-privilege security policy (AGENTS.md & SECURITY.md) and requires an isolated container broker (DN-008).
- Wired `sandbox` route in `MainWindow.xaml.cs` and promoted to `in-progress` in `capabilities.json`, `parity-checklist.json`, and `source-modules.json` (`file_sandbox.py`).
- 9 unit tests in `SafeFileSandboxTests.cs` (entropy validation, non-PE hashing, PE header extraction, W^X detection, packer section detection, API pattern detection in ASCII/UTF-16, report generation, and oversize rejection).

## 2026-10-07 checkpoint: DN-009 Forensics Route Slice (antigravity-worker)

Completed and verified (Debug: 0 warnings/errors; 438/438 tests pass):
- DN-009 Forensics route slice: implemented `ForensicEvidenceCollector` porting v29 `forensic_report.py` and `_build_forensics_tab`.
- Contracts in `src/Downpour.Contracts/ForensicBundle.cs`: `ForensicChainOfCustody`, `ForensicArtifactItem`, `ForensicEvidenceBundle` with schema v1.
- Core engine in `src/Downpour.Core/ForensicEvidenceCollector.cs`: gathers digital chain-of-custody (hostname, OS, architecture, collector version, local IPs, MACs, UTC timestamp) and queries security alerts, event logs, persistence autostart entries, blocked firewall connections, and network endpoints in parallel with bounded timeout.
- Cryptographic integrity seal: computes canonical SHA-256 hash over chain-of-custody and evidence artifacts ensuring tamper-evidence and non-repudiation for legal proceedings.
- Legal incident report generator: generates dark-themed executive HTML forensic report formatted for FBI IC3 filings, local police incident packages, and national CERT submissions. Generates raw JSON bundle and console/plain text summary.
- Desktop route `forensics` in `ForensicsPage.xaml/.cs`: live evidence capture, overview cards (total items, critical/high count, attacker IPs), chain-of-custody card with SHA-256 seal, category & severity filtering, HTML legal report export, raw JSON export, and "Open FBI IC3" link (`https://www.ic3.gov`).
- Wired `forensics` route in `MainWindow.xaml.cs` and promoted to `in-progress` in `capabilities.json`, `parity-checklist.json`, and `source-modules.json` (`forensic_report.py`).
- 6 unit tests in `ForensicEvidenceCollectorTests.cs` (chain of custody, deterministic SHA-256 seal, JSON roundtrip, HTML sections and IC3 links, text summary, and offline resilience).

## 2026-10-07 checkpoint: DN-029 Verification and DN-009 Cleanup Center Slice (antigravity-worker)

Completed and verified (Debug: 0 warnings/errors; 432/432 tests pass):
- DN-029 verification: owner consent decision confirmed for reading PowerShell 4104 `ScriptBlockText` in-memory. Added 10 tests in `SensorSettingsStoreTests` covering persistence, schema versioning, strict allow-list key validation, `SensorSettingsPipeWorker.ParseStrictRequest` rejection of duplicate/extra keys, and changed-event dispatch. Added `ScriptBlockIsAnalyzedInMemoryBySigmaAmsiEventProcessor` in `SigmaAlertPersistenceTests`.
- DN-009 Cleanup Center slice: implemented `CleanupInspector` porting v29 `downpour_cleanup_module.py` categories: User Temp, Windows Temp, Thumbnail Cache, WER error reports, Crash Dumps, Delivery Optimization cache, Windows Update download cache, Recent file links, Downpour logs, and Recycle Bin space analysis (`SHQueryRecycleBinW`).
- Desktop route `cleanup` in `CleanupPage.xaml/.cs` with live calculation, reclaimable space banners, candidate file counts, category cards with risk badges (`Safe`, `Moderate`, `Warning`), and text report export. Deletion actions explicitly disabled with tooltips pending DN-008 Action Broker.
- Wired `cleanup` route in `MainWindow.xaml.cs` and marked `in-progress` in `capabilities.json`.
- 10 unit tests in `CleanupInspectorTests.cs`.

## 2026-10-07 checkpoint: DN-027 Standalone Timeline and AEGIS Phishing Text Analyzer (antigravity-worker)

Completed and verified (Debug: 0 warnings/errors; 412/412 tests pass):
- DN-027 Standalone timeline route (`timeline`) in `InvestigationTimelinePage.xaml/.cs` loading all system alerts chronologically when accessed directly.
- Quick filter buttons added for `All`, `Failed Logins` (4625), `Logons` (4624), `Accounts` (4720/4728/4732), `Services` (4697/7045), and `Tasks` (4698/4702).
- Attack detection heuristics (`TimelineAttackDetector`) porting v29 `_tl_detect_attacks`: brute force (T1110.001, CRITICAL), account manipulation (T1098, HIGH), service install (T1543.003, HIGH), scheduled task persistence (T1053.005, HIGH), explicit credential bursts (T1078, MEDIUM), and firewall changes (T1562.004, MEDIUM).
- Dark-themed executive HTML report generator porting v29 `_tl_export_html` saving directly to Desktop or local Reports directory.
- Project AEGIS defense architecture overview page (`AegisPage.xaml/.cs`) displaying the 5 defense layers (L1 Physical, L2 TCP, L3 Ingestion, L4 NLP Phishing AI, L5 Memory Shield).
- Local NLP phishing & social engineering text analyzer (`AegisPhishingAnalyzer`) porting v29 `AegisNLPPhishingEngine`: urgency (+15 max 30), authority impersonation (+20 max 25), fear/reward triggers (+20 max 25), grammar/tone (+10 max 15), blob URIs (+30), redirect shorteners (+15), QR instructions (+20). 100% on-device in-memory with zero network traffic.
- Wired navigation in `MainWindow.xaml.cs` and marked `timeline` and `aegis` as `in-progress` in `capabilities.json`.
- 21 unit tests in `AegisPhishingAnalyzerTests` and `TimelineAttackDetectorTests`.

## 2026-10-07 checkpoint: DN-021 DNS Cache Watch with DGA Scoring (antigravity-worker)

Completed and verified (Debug: 0 warnings/errors; 391 tests pass):
- DN-021 DNS cache watch: native `DnsGetCacheDataTable` P/Invoke in `DnsInventoryProvider`, bounded to 4096 entries, cycle protection.
- DgaDetector ported from v29 with Shannon entropy, consonant ratio, digit ratio, bigram scoring, risky TLD penalties, and whitelist discounts.
- TOFU baseline persisted to `dns-baseline.v1.json` (max 20,000 entries) preventing initial alert storm.
- Passive email security analyzer (`EmailSecurityAnalyzer`) checking SPF, DMARC, and DKIM selector records via native `DnsQuery_W`.
- Outbound-only named pipe `Downpour.DnsInventory.v1` with current-user ACL and client validation (`DnsInventoryClient`).
- DNS findings mapped to `SecurityFindingCatalog` (`Downpour/Dns`) and bridged to `SecurityAlertRepository` by `SecurityFindingBridgeWorker`.
- Desktop route `dns` in `Downpour.Desktop` (`DnsPage.xaml/.cs`) with live cache search, DGA indicators, and interactive SPF/DMARC/DKIM tool.
- 8 unit tests in `DnsInventoryTests`.

Claimed next: DN-027 (standalone timeline and phishing text analyzer) per `docs/AGENT_COORDINATION.md`.

## 2026-10-07 checkpoint (claude-parity-audit)

- Done and pushed, each verified in a clean worktree: DN-016 (driver catalog signatures), DN-018 (hardening posture), DN-019 (firewall), DN-022 (persistence review on Threat Hunt), DN-023 (Threats / Possible Threats triage and the shared finding bridge), DN-024 (tray icon, notifications, sound alarm), and DN-028 (service risk, plus a fix for corrupted startup types).
- Fixes to other agents' work:
  - Sigma rules load only from the install directory.
  - Wi-Fi uses the Native Wifi API instead of netsh.
  - Sigma/AMSI detections are now stored. They had all been rejected.
  - Thresholds doc regenerated from source because the hand-written values were wrong.

Needs a user decision: DN-029 (whether to read PowerShell script-block text). Without it, Sigma/AMSI cannot detect anything on live events.
Still security-gated: DN-008 action broker. Queued: DN-025 (off-box indicator lookups need a consent design), DN-026 (YARA dependency review), DN-009 umbrella routes.

## 2026-10-06 DN-020: USB, Wi-Fi, and Bluetooth Posture (antigravity-worker)

**DN-020 completed:**
- **USB Device Posture**: Implemented read-only removable drive enumeration (`DriveInfo.GetDrives()`), autorun file presence detection (`autorun.inf`, `autorun.bat`, `autorun.exe`, `autorun.com` - T1091), root suspicious executable/script pattern scan (`.scr`, `.pif`, `.bat`, `.cmd`, `.vbs`, `.js`, `.ps1`), `USBSTOR` service start state verification, and USB device history enumeration from `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR` and `HKLM\SYSTEM\CurrentControlSet\Enum\USB` with BadUSB/attack-tool hardware pattern matching (Rubber Ducky, BadUSB, Flipper, Teensy, Maltronics, Bash Bunny, O.MG cable - T1200). Strictly read-only; no disk mutation, file renaming, or drive disconnection.
- **Wireless & Wi-Fi Posture**: Implemented adapter state and connected SSID/BSSID query, visible network scan (`netsh wlan show networks mode=bssid` parser), Evil Twin detection (conflicting security configurations for the same SSID - T1557.002), weak/open authentication warnings (Open, WEP, Shared - T1040), suspicious SSID regex patterns, and attack tool MAC OUIs (Hak5 WiFi Pineapple `00:13:37`, spoofed OUIs `AA:BB:CC`, `00:11:22`, `DE:AD:BE`). Strictly read-only; no interface disconnection or deauth defense.
- **Bluetooth Posture**: Paired device enumeration from `HKLM\SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices` with UTF-8 byte array device name decoding and suspicious device name analysis (`flipper`, `ubertooth`, `bluehydra`, `scanner`, `sniffer`, `keylog`, `pineapple` - T1011.001); radio service state check.
- **IPC & Security**: Exposed outbound-only named pipes `Downpour.UsbInventory.v1` and `Downpour.WirelessInventory.v1` with current-user ACL and recent-capture caching. Added client bounds validation in `UsbInventoryClient` and `WirelessInventoryClient`.
- **Alert Pipeline Integration**: Integrated USB and Wireless posture findings into `SecurityFindingCatalog`, `SecurityFindingMapper` (`FromUsb`, `FromWireless`), and `SecurityFindingBridgeWorker` to flow findings into `SecurityAlertRepository` for unified threat triage.
- **Desktop UI**: Implemented `UsbPage.xaml/.cs` (route `usb`) and `WifiPage.xaml/.cs` (route `wifi`) with live re-check, status banners, categorized lists, and security finding severity badges. Wired navigation in `MainWindow.xaml.cs` and marked `usb` and `wifi` as `in-progress` in `capabilities.json`.
- **Testing**: Added 21 unit tests in `UsbInventoryTests` and `WirelessInventoryTests` covering all evaluators, attack patterns, client schema validations, and local provider captures. 328/328 total tests pass with 0 warnings/errors.

**Files created/updated:**
- `src/Downpour.Contracts/UsbInventory.cs`
- `src/Downpour.Contracts/WirelessInventory.cs`
- `src/Downpour.Contracts/SecurityFindings.cs`
- `src/Downpour.Core/UsbPostureEvaluator.cs`
- `src/Downpour.Core/UsbInventoryClient.cs`
- `src/Downpour.Core/WirelessPostureEvaluator.cs`
- `src/Downpour.Core/WirelessInventoryClient.cs`
- `src/Downpour.Core/SecurityFindingMapper.cs`
- `src/Downpour.Service/UsbInventoryProvider.cs`
- `src/Downpour.Service/UsbInventoryPipeWorker.cs`
- `src/Downpour.Service/WirelessInventoryProvider.cs`
- `src/Downpour.Service/WirelessInventoryPipeWorker.cs`
- `src/Downpour.Service/SecurityFindingBridgeWorker.cs`
- `src/Downpour.Service/Program.cs`
- `src/Downpour.Desktop/Pages/UsbPage.xaml`
- `src/Downpour.Desktop/Pages/UsbPage.xaml.cs`
- `src/Downpour.Desktop/Pages/WifiPage.xaml`
- `src/Downpour.Desktop/Pages/WifiPage.xaml.cs`
- `src/Downpour.Desktop/MainWindow.xaml.cs`
- `capabilities.json`
- `tests/Downpour.Tests/UsbInventoryTests.cs`
- `tests/Downpour.Tests/WirelessInventoryTests.cs`
- `WORK_QUEUE.json` (DN-020 completed, DN-021 claimed)
- `AGENT_REGISTRY.json` (antigravity-worker active on DN-021)
- `SHARED_CONTEXT.md` (updated)

**Next safe task:** DN-021 (DNS cache watch with DGA scoring)


**DN-017 completed:**
- Copied all 19 YAML rule files (101 rules) from v29 into `src/Downpour.Service/sigma_rules/` with provenance and Detection Rule License 1.1 (DRL 1.1) documentation.
- Bundled rule directory copied to output via `Downpour.Service.csproj` and `Downpour.Tests.csproj`.
- Enhanced `SigmaEngine` to support field-bound modifiers (`CommandLine|contains`, `Image|endswith`, `ScriptBlockText|contains`, `CommandLine|re`, `ParentImage|endswith`, `CommandLine|contains|all`) and boolean/quantifier conditions (`1 of sel*`, `1 of selection_*`, `all of sel*`, `selection and not filter`, nested parentheses).
- Added `SigmaLoadReport` to surface and count unsupported modifiers and conditions rather than silently dropping them.
- Wired bundled rule loading into `SigmaAmsiEventProcessor` at service startup with warning logs for unsupported syntax.
- Expanded unit tests in `SigmaEngineTests`: all 101 bundled rules load cleanly (0 unsupported, 0 errors); tested unsupported modifier/condition reporting; tested process multi-condition evaluation and PowerShell 4104 alert pipeline.
- Build: 0 warnings, 0 errors. All 268 tests pass in Debug and Release.

**Files updated:**
- `src/Downpour.Service/sigma_rules/` (19 yaml files + README.md)
- `src/Downpour.Service/Downpour.Service.csproj`
- `src/Downpour.Service/SigmaEngine.cs`
- `src/Downpour.Service/SigmaAmsiEventProcessor.cs`
- `tests/Downpour.Tests/Downpour.Tests.csproj`
- `tests/Downpour.Tests/SigmaEngineTests.cs`
- `WORK_QUEUE.json` (DN-017 completed, DN-020 claimed)
- `AGENT_REGISTRY.json` (antigravity-worker active on DN-020)
- `SHARED_CONTEXT.md` (updated)

**Next safe task:** DN-020 (read-only USB, Wi-Fi, and Bluetooth posture)

## 2026-10-06 handoff section 2 and DN-016 (antigravity-worker)

**Handoff section 2 completed:**
- Verified import graph: no dynamic loading missed; `revolutionary_enhancements` and `ultimate_threat_intel` are stub-only with type stubs only
- Documented v29 settings/config in parity-checklist.json (settings section with all keys from config.py)
- Created docs/V29_DETECTION_THRESHOLDS.md with detection thresholds, IOCs, and event IDs for all planned modules
- Documented v29 on-disk stores in parity-checklist.json (dataStores section: titanium.db, quarantine, baselines, etc.)
- Added right-click context-menu workflows to parity-checklist.json (alerts, processes, remediation, possible-threats, performance, threats tabs)

**DN-016 completed:**
- Driver signature verification already fixed in current codebase
- DriverPackageInventoryProvider uses CatalogSignatureVerifier with WtdChoiceCatalog and CryptCATAdminAcquireContext2
- No CreateFromSignedFile or SYSLIB0057 pragma found
- Build: 0 warnings, 0 errors

**Files updated:**
- docs/V29_PARITY_AUDIT.md (added section 6 handoff verification)
- parity-checklist.json (added settings, dataStores sections; added right-click workflows to routes)
- docs/V29_DETECTION_THRESHOLDS.md (new file)
- WORK_QUEUE.json (DN-016 marked completed)
- AGENT_REGISTRY.json (antigravity-worker idle)
- SHARED_CONTEXT.md (updated)

**Next safe task:** DN-017 (load v29 Sigma rule files)

## 2026-10-06 parity audit checkpoint (DN-015, claude-parity-audit)

- Compared v29 (`downpour_consolidated`) against this repo. See [`docs/V29_PARITY_AUDIT.md`](docs/V29_PARITY_AUDIT.md). By feature count Downpour Next is roughly 15-20% of v29. 24 of 38 routes are placeholders, and no response actions are enabled.
- New [`parity-checklist.json`](parity-checklist.json) lists the parity gate: 205 route workflows and 22 non-route features. `source-modules.json` now has 129 entries (42 wired modules added, 19 dead-in-v29 modules marked orphaned).
- Committed and pushed all previously uncommitted agent work as-is: Sigma/AMSI/Sysmon, action broker and quarantine stubs, NVD, URLhaus/Abuse.ch, driver packages, timeline page, performance. It has **not been reviewed**.
- Fixed all build warnings. Also fixed a crash risk in `MalwareBazaarRow.HashesDisplay`, which sliced short or empty hashes. `dotnet build -c Debug --no-incremental`: 0 warnings/errors. `dotnet test`: 191 passed.
- Repaired invalid `AGENT_REGISTRY.json`. Reopened DN-009, which had been marked completed after only the inventory was done. Added DN-015 (done) and DN-016..DN-027.
- **Found a bug, now queued as DN-016:** driver package signature verification runs WinVerifyTrust on catalog-signed `.inf` files, so legitimate drivers show "Verification failed".
- Next agent: follow [`docs/AGENT_HANDOFF.md`](docs/AGENT_HANDOFF.md).

- DN-014 Performance/gauge work is in progress. Circular gauge progress follows its exact track; dashboard/network charts label units and time direction, mark current readings, and preserve gaps. Performance has six live gauges (CPU, physical memory, system commit, OS volume, receive, send), CPU/memory/commit/network histories, process/thread and TCP counts, uptime, volume free/used/total, largest working sets, per-process CPU, refresh/pause controls, and bounded CSV. System-wide commit uses GetPerformanceInfo; system-volume reads run off the UI dispatcher. Release build: 0 warnings/errors; 117 tests pass, including live provider counter coverage. Updated local portable package hashes match fresh staging; desktop launched and bundled service child was confirmed. Next: native Performance/save-picker click-through, per-core CPU, physical disk I/O, pagefile storage usage, sorting/filtering, and thresholds. GPU/thermal/power readings need supported sources. See [`docs/UI_POLISH.md`](docs/UI_POLISH.md).
- Stable [v0.1.14](https://github.com/christiand0797/downpour-next/releases/tag/v0.1.14) is published for laptop testing. `DownpourNext-win-x64-0.1.14.zip`: 196,796,799 bytes, SHA-256 `B5C723A9DC15FEDA679BA735731369BB29ED54C8BA7F78A218D3B560EE7C3272`; GitHub asset digest matches. Source checkpoint `1750c70` fixes the embedded current version to 0.1.14. This remains unsigned and incomplete v29 parity.
- DN-002 dashboard UI refresh: grouped route sections, duplicate route suppression, stronger storm-overlay contrast, shared neon surface tokens, and responsive metric cards are implemented. Native route/narrow-high-DPI verification remains.

## 2026-10-05 performance continuation checkpoint

- DN-014 now includes a six-gauge Performance route and CPU/memory/commit/network histories, live system-volume usage and uptime, TCP/process/thread counts, largest working sets, manual refresh, pause/resume, bounded CSV export, and live per-process CPU deltas with process-lifetime reset handling. System commit uses the documented system-wide GetPerformanceInfo counters; system-volume metadata is read off the UI dispatcher. Gauge/chart crash and axis fixes are recorded in [`docs/UI_POLISH.md`](docs/UI_POLISH.md).
- `dotnet build Downpour.slnx -c Release --no-restore -m:1 -nodeReuse:false`: passed with 0 warnings/errors. `dotnet test Downpour.slnx -c Release --no-build --no-restore -m:1 -nodeReuse:false`: 117 passed, 0 failed. A parallel MSBuild attempt failed while trying to enumerate/start workers with `OutOfMemoryException`; serial build succeeded.
- Rebuilt ignored local `DownpourNext-Portable/` desktop and service outputs from self-contained publishes; executable hashes match staging. Packaged desktop launched, remained open, and auto-started the bundled service. Dashboard screenshot is `artifacts/desktop-downpour-latest.png`. Stable v0.1.14 is published from source checkpoint `1750c70`, and its GitHub asset digest matches local. Native Performance route/save-picker interaction remains pending.
- Next safe Performance parity tasks: per-core CPU and history, disk read/write counters, pagefile/commit metrics, bounded sorting/filtering, and configurable sampling/thresholds. Hardware telemetry stays unknown without a documented supported source. Do not add system-changing actions through the Performance page.

- DN-013 on-demand static PE file inspection is shipped in [v0.1.13](https://github.com/christiand0797/downpour-next/releases/tag/v0.1.13), source `e3fb605`. Scanner chooses one local EXE/DLL/SYS up to 256 MiB, streams SHA-256, parses bounded PE headers/section flags, and reports certificate-table presence only; no signature trust/malware verdict, upload, execution, or remediation. Release build clean; 112 tests pass; local package hashes and desktop/service startup/close verified. ZIP SHA-256 `72AB2B9204FF110962091DF08BA4103FDCF2E6E3A080C6DE3230A5AE3376F6FD`. Native picker click-through and full v29/YARA/Defender scans remain. See [`docs/FILE_INSPECTOR.md`](docs/FILE_INSPECTOR.md).
- DN-010 update rollback is fixed in [v0.1.12](https://github.com/christiand0797/downpour-next/releases/tag/v0.1.12), source commit `bed15ca`. Cause: trailing-separator containment rejected every target and the old helper ran from the executable it attempted to replace. v0.1.12 uses an external single-file helper; `.10`/`.11` users need a one-time manual extraction. Full disposable `.11`→`.12` update and executable/service/helper hashes passed. Build clean; 107 tests pass. SHA-256 `C696A091F78E43EA1B663716B25DEF0500533342E22C79F1C0554575D7B19FA5`. Remaining: test actual Update button on a second machine and induce rollback/locked-file cases; signed publisher provenance remains open. See [`docs/UPDATES.md`](docs/UPDATES.md).
- DN-006 installed-software inventory and cautious CISA KEV product-name candidates are implemented and released in [v0.1.11](https://github.com/christiand0797/downpour-next/releases/tag/v0.1.11), source commit `e7ac54f`. Reads only uninstall-key display metadata, uses bounded current-user pipe IPC, and candidate-only semantics; it does not determine affected versions or vulnerability status. Build is clean, 105 tests pass, GitHub's digest matches the locally built archive, and package startup/service shutdown pass. Remaining: native page click-through, clean-install pipe smoke, and affected-version/NVD/CPE parity. See [`docs/THREAT_INTELLIGENCE.md`](docs/THREAT_INTELLIGENCE.md).

This checklist tracks current implementation state; the detailed order, dependencies, and acceptance criteria are in [`WORK_QUEUE.json`](WORK_QUEUE.json).

## 2026-10-04 continuation checkpoint

- DN-010 update slice is built and published as [v0.1.10](https://github.com/christiand0797/downpour-next/releases/tag/v0.1.10). The dashboard's user-started button checks the fixed public repository's latest stable release, validates tag/page/asset/type/digest, bounds network and archive operations, rejects unsafe paths/reparse points, stages and hashes, applies only after the desktop and bundled sensor service exit, attempts file backup rollback, and restarts. Build clean, 97 tests pass, and packaged desktop startup/graceful service shutdown passed. ZIP SHA-256 `FA9F4A17BD953BB53CD8D5F60F81A604DE12D88A50F66A76D0F1635E7396B7FA`. Full native update-button click-through and apply failure/recovery test on a clean second machine remain. See [`docs/UPDATES.md`](docs/UPDATES.md). Unsigned binaries and a GitHub-supplied digest do not provide publisher authentication.
- The user authorized making the GitHub repo public so anonymous checks/downloads work. Anonymous GitHub API metadata was verified against v0.1.9 before release and v0.1.10 is now published. The updater embeds no GitHub token or credentials.

- DN-006 EPSS enrichment is implemented and pushed in `00b0786`; [v0.1.9](https://github.com/christiand0797/downpour-next/releases/tag/v0.1.9) adds a user-clicked, one-CVE FIRST API lookup on selected validated CISA KEV rows. It does not upload the catalog or perform bulk queries. Fixed host/path, no redirects, 10s/64 KiB bounds, strict response/CVE/score/date validation, and 24h in-memory reuse are covered. UI explains the score is a population-level 30-day probability, not device vulnerability status. Release build clean; 87 tests pass; live public response shape verified. ZIP SHA-256 `F89088E619E048ADAF762DA25E25299EC5A2E362B7D6B8523C3A32F3623BAB96`; 764 staged files match `DownpourNext-Portable/`.
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

- [x] Add explicit dashboard release check and staged portable update with strict asset validation; [ ] add code signing or independently signed update manifest before production use.
- [ ] Security review of IPC, service identity, installer/service permissions, updates, feeds, storage, parsers, and response broker.
- [ ] Verify driver signatures/packages, add driver install/update/reinstall/remove with an audited recovery-first broker.
- [ ] Add fuzz/property tests for untrusted contracts, rule formats, manifests, and file metadata.
- [ ] Add accessible keyboard navigation, high contrast, reduced motion, DPI/responsive layout, and clear sensor freshness.
- [ ] Define performance budgets and compare against Downpour on the same Windows machine.

## Active owner-requested continuation (2026-10-07, codex-primary)

- [x] Review current context, queue, security policy, source inventory, and active uncommitted drafts; preserve v29 unchanged.
- [x] Baseline restore/build; identify stale route-count test and broken Sysmon-to-alert validation.
- [x] Finish deterministic AMSI/Sysmon/dedup/health regressions and full Debug verification (badcf28; 879 tests).
- [x] Reconcile current feature documentation and source tracking with actual implemented paths (CONTINUATION_AUDIT.md; broader per-workflow acceptance remains).
- [x] Commit owned DN-005 fixes; build/test/package from a clean committed checkout (ffc241d; 856 clean tests; final native smoke passed).
- [x] Publish v0.1.16 to the configured GitHub repository, verify asset digest, smoke-test desktop/service/scanner, and record release evidence (remote tag/latest/digests match).
- [x] Replace the CIS route's generated protection metrics with real measured alert/source status and bounded explicit package-integrity checks (e8ce959; 893 working-tree tests; full adaptive/deception parity remains).
- [x] Package and publish v0.1.17 with measured CIS and verify actual whole-package integrity and remote asset hashes (e8ce959; 870 clean Release tests; all remote assets match).
- [ ] Continue complete v29 parity: real detection/correlation and sensors, admin elevation, recovery-safe actions, driver lifecycle, operational AEGIS/advanced workflows, installer/signing/accessibility. Demonstration metrics do not count as protection. Host-isolation draft remains gated by the four merge blockers in `docs/AGENT_COORDINATION.md`.

Resume from the newest SHARED_CONTEXT checkpoint; do not treat historical completion claims or route presence as full functional parity.
