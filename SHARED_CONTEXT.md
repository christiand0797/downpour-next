# Downpour Next shared context

**Updated:** 2026-10-07 (antigravity-worker: DN-009 Defense Suite slice completed, DN-009 Parental Controls slice completed, DN-009 Emergency slice completed, DN-009 IoT slice completed, DN-009 VPN slice completed, DN-009 Memory slice completed, DN-009 Ransomware slice completed, DN-009 Sandbox slice completed, DN-009 Forensics slice completed, DN-029 completed, DN-009 Cleanup Center slice completed; claude-parity-audit: DN-008 phase 1 quarantine live, DN-016/018/019/022/023/024/028 done)

**Repository:** public [christiand0797/downpour-next](https://github.com/christiand0797/downpour-next)
**Local path:** `C:\Users\purpl\Desktop\downpour v2`  
**Branch:** `main`  

## 2026-10-07 checkpoint: DN-009 Defense Suite Route Slice (antigravity-worker)

**DN-009 Defense Suite Route Slice completed:**
- **Defense Suite & Attack Surface Watchers Engine (`DefenseSuiteCoordinator`)**:
  - Implemented executive defense posture aggregator and read-only attack surface watchers porting v29 `advanced_defense_suite.py` and `_build_defense_tab`.
  - Multi-Layered MITRE ATT&CK Watchers:
    - IFEO Process Execution Hijack (T1546.012 / T1546.008): inspects `Image File Execution Options` registry key for debugger redirects and accessibility backdoor hijacking (`sethc.exe`, `utilman.exe`, `osk.exe`, etc.).
    - LSA Protection / RunAsPPL (T1003): verifies Protected Process Light (PPL) enforcement on `lsass.exe` to prevent unprivileged credential dumping (Mimikatz).
    - UAC Policy Enforcement (T1548.002): checks `EnableLUA` and `ConsentPromptBehaviorAdmin` to detect silent elevation or disabled UAC.
    - Trusted Root CA Store Monitor (T1553.004): scans LocalMachine Root certificate store for suspicious HTTPS interception proxies (`mitmproxy`, `portswigger`, `fiddlerroot`, `charles proxy`, `burp suite`).
    - Startup Folder Autostart Drops (T1547.001): inspects user and common startup directories for dropped scripts or executable binaries.
    - SMB Network Shares Exposure (T1021.002): inspects LanmanServer shares to flag non-administrative shares exposed to the network.
    - Windows Defender Real-Time Protection (T1562.001): verifies real-time monitoring policy is not disabled via registry.
    - System DEP & ASLR Mitigation (T1055): verifies hardware DEP and bottom-up ASLR system mitigation status.
  - Attack Surface Exposure & Defense Scoring:
    - Deductions weighted by finding severity (Critical: -25, High: -15, Medium: -8, Low: -3).
    - Defense Score clamped between 0 and 100; Attack Surface Exposure = 100 - DefenseScore.
  - Core Defense Pillars Aggregation:
    - Synthesizes posture across core subsystems: Project AEGIS, Ransomware Defense, Hardening & Firmware, Emergency Response.
  - Executive Markdown Posture Report Generator:
    - Generates executive posture audit report with pillar status table, watcher matrix with MITRE techniques, and prioritized remediation recommendations.
- **Desktop UI (`DefenseSuitePage.xaml/.cs`)**:
  - Real-time defense posture header with status badge (OPTIMAL POSTURE / MODERATE POSTURE / ELEVATED RISK).
  - 4 metric cards (Defense Posture Score, Attack Surface Exposure %, Active Defense Watchers, Flagged Exposures).
  - Core Defense Pillars cards with 1-click drill-down navigation buttons (`App.NavigateToRoute`) to `aegis`, `ransomware`, `hardening`, `emergency`.
  - Advanced Attack Surface Watchers list view displaying title, category, MITRE technique, clean/exposed badge, and observed details.
  - One-click "Export Posture Report" copying formatted Markdown report to clipboard.
- **Navigation & Parity Tracking**:
  - Wired route `defense` in `MainWindow.xaml.cs`.
  - Promoted route `defense` to `"in-progress"` in `capabilities.json`, `parity-checklist.json`, and `source-modules.json` (`advanced_defense_suite.py`).
- **Testing & Verification**:
  - Added unit tests in `DefenseSuiteCoordinatorTests.cs` (clean posture scoring, weighted deduction scoring, severe risk clamping, watcher enumeration, memory exploitation guard, and report formatting).
  - 638/638 solution tests pass cleanly with 0 warnings, 0 errors.

**Files created/updated:**
- `src/Downpour.Contracts/DefenseSuite.cs`
- `src/Downpour.Core/DefenseSuiteCoordinator.cs`
- `src/Downpour.Desktop/Pages/DefenseSuitePage.xaml`
- `src/Downpour.Desktop/Pages/DefenseSuitePage.xaml.cs`
- `src/Downpour.Desktop/App.xaml.cs`
- `src/Downpour.Desktop/MainWindow.xaml.cs`
- `capabilities.json`
- `parity-checklist.json`
- `source-modules.json`
- `tests/Downpour.Tests/DefenseSuiteCoordinatorTests.cs`
- `WORK_QUEUE.json`
- `AGENT_REGISTRY.json`
- `SHARED_CONTEXT.md`
- `TODO.md`

## 2026-10-07 checkpoint: DN-009 Parental Controls Route Slice (antigravity-worker)

**DN-009 Parental Controls Route Slice completed:**
- **Parental Controls & Family Safety Engine (`ParentalControlsManager`)**:
  - Implemented family safety manager porting v29 `parental_controls.py` and `_build_parental_tab`.
  - Screen Time Scheduling & Bedtime Curfew:
    - Daily screen time limit monitoring distinguishing weekday limits (default 120 min) and weekend limits (default 240 min).
    - Overnight and daytime bedtime curfew evaluation (default 21:00 to 07:00) with remaining minutes calculation and limit-exceeded tracking.
  - Web Content Filtering:
    - Pre-compiled category domain dictionaries for high-risk categories: `adult`, `gambling`, `violence`, `weapons`, and `drugs`.
    - Custom blocked domains support with URL protocol and path stripping.
    - Read-only inspection of Windows hosts file (`C:\Windows\System32\drivers\etc\hosts`) checking for Downpour DNS redirection rules without modifying system files.
    - Idempotent host file content generator with structured start and end markers (`# === DOWNPOUR NEXT - PARENTAL CONTROLS START ===`).
  - Application Restrictions:
    - Running process monitor checking for restricted executables (`discord.exe`, `steam.exe`, `epicgameslauncher.exe`, `robloxplayerbeta.exe`, `torrent.exe`, `utorrent.exe`).
  - Action Broker Least-Privilege Integration (DN-008):
    - System-changing hosts file writes and filter removals return clear guarded notices and require Action Broker authorization.
  - Family Safety Markdown Report Generator:
    - Formats comprehensive report including profile name, screen time metrics, active curfew, category filter state, blocked domain counts, running restricted apps, and activity audit log.
- **Desktop UI (`ParentalControlsPage.xaml/.cs`)**:
  - Master enable toggle and profile name configuration.
  - Live bedtime curfew banner (Open Access vs Curfew Active).
  - 4 overview metric cards (Screen Time Today, Bedtime Curfew, Web Categories, Hosts DNS Filter).
  - Screen Time Scheduling editor with weekday/weekend limits, bedtime inputs, and interactive usage simulation slider.
  - Web Content Filtering checklist with individual category toggles (Adult, Gambling, Violence, Weapons, Drugs).
  - Guarded Apply/Remove Web Filter buttons with DN-008 security dialogs.
  - Application Restrictions card showing configured apps and live detection status.
  - Timestamped activity and audit log with clear option.
  - Desktop report exporter.
- **Navigation & Parity Tracking**:
  - Wired route `parental-controls` in `MainWindow.xaml.cs` (navigation and back-sync).
  - Promoted `parental-controls` to `"in-progress"` in `capabilities.json`, `parity-checklist.json`, and `source-modules.json` (`parental_controls.py`).
- **Testing & Verification**:
  - 12 unit tests in `ParentalControlsManagerTests.cs` (weekday/weekend screen time limits, bedtime curfew calculation, category domain aggregation, hosts file formatting idempotency and marker insertion, hosts file parsing, restricted application detection, and markdown report generation).
  - 35/35 active route tests pass cleanly; 600/600 total tests pass.

**Files created/updated:**
- `src/Downpour.Contracts/ParentalControls.cs`
- `src/Downpour.Core/ParentalControlsManager.cs`
- `src/Downpour.Desktop/Pages/ParentalControlsPage.xaml`
- `src/Downpour.Desktop/Pages/ParentalControlsPage.xaml.cs`
- `src/Downpour.Desktop/MainWindow.xaml.cs`
- `capabilities.json`
- `parity-checklist.json`
- `source-modules.json`
- `tests/Downpour.Tests/ParentalControlsManagerTests.cs`
- `WORK_QUEUE.json`
- `AGENT_REGISTRY.json`
- `SHARED_CONTEXT.md`
- `TODO.md`

## 2026-10-07 checkpoint: DN-009 Emergency Response Route Slice (antigravity-worker)

**DN-009 Emergency Response Route Slice completed:**
- **Emergency Containment & Forensic Engine (`EmergencyResponseCoordinator`)**:
  - Implemented incident response coordinator porting v29 `emergency_response.py` and `_build_emergency_tab`.
  - Volatile System Snapshots:
    - Captures running processes with PID, Process Name, executable path, memory footprint (WorkingSet64), and start time.
    - Captures active TCP connection endpoints and states via managed `IPGlobalProperties`.
    - Computes a deterministic SHA-256 cryptographic forensic seal ensuring chain-of-custody tamper evidence.
    - Automatically persists JSON snapshots to `%LOCALAPPDATA%\DownpourNext\emergency_snapshots\emergency_snapshot_{id}_{timestamp}.json`.
  - Suspicious Process Screening:
    - Identifies known exploitation tools (`mimikatz`, `psexec`, `procdump`, `lazagne`, `nc.exe`, `netcat`, `ncat`, `chisel`, `socat`, `cobaltstrike`, `bloodhound`, `sharphound`, `rubeus`, `seatbelt`).
    - Detects execution from suspicious temporary paths (`%TEMP%`, `\AppData\Local\Temp\`, `\Users\Public\`).
    - Maps findings to MITRE ATT&CK techniques (T1003, T1036, T1059, T1572).
  - Least-Privilege Action Broker Integration (DN-008):
    - System-changing containment actions (Host Network Isolation, Process Termination, Adapter Restoration) return explicit `GuardedPendingAuthorization` status.
    - Read-only actions (Snapshot preservation, volatile forensics packaging, IR report export) execute immediately.
    - Workstation lock invokes native Windows `user32.dll` `LockWorkStation()` upon explicit confirmation.
  - Incident Response (IR) Report Generator:
    - Produces comprehensive Markdown report containing executive summary, cryptographic forensic seal, suspicious process table with MITRE tags, active TCP endpoints, DN-008 guard status, and audit log.
- **Desktop UI (`EmergencyPage.xaml/.cs`)**:
    - ARMED status badge and Panic Lockdown Hero Card with prominent red activation button and containment checklist.
    - 4 overview metric cards (Suspicious Processes, Active TCP Sessions, Running Processes, Saved Snapshots).
    - Individual Containment Actions bar (Snapshot, Isolate, Restore, Kill, Forensics, Lock Session).
    - Suspicious process screening ListView with PID, name, path, memory, and MITRE badges.
    - Forensic Evidence Seal card displaying Response ID, captured timestamp, host information, SHA-256 seal, and file path.
    - Live timestamped monospace Emergency Event Log with clear log option.
    - Desktop IR Report export.
- **Navigation & Parity Tracking**:
    - Wired route `emergency` into `MainWindow.xaml.cs` (navigation and back-sync).
    - Promoted route `emergency` to `"in-progress"` in `capabilities.json`, `parity-checklist.json`, and `source-modules.json` (`emergency_response.py`).
- **Testing & Verification**:
    - 12 unit tests in `EmergencyResponseCoordinatorTests.cs` (snapshot capture and JSON serialization, indicator screening, guarded action policy enforcement under DN-008, full lockdown execution, and IR markdown report formatting).
    - 33/33 active route tests pass cleanly.

**Files created/updated:**
- `src/Downpour.Contracts/EmergencyResponse.cs`
- `src/Downpour.Core/EmergencyResponseCoordinator.cs`
- `src/Downpour.Desktop/Pages/EmergencyPage.xaml`
- `src/Downpour.Desktop/Pages/EmergencyPage.xaml.cs`
- `src/Downpour.Desktop/MainWindow.xaml.cs`
- `capabilities.json`
- `parity-checklist.json`
- `source-modules.json`
- `tests/Downpour.Tests/EmergencyResponseCoordinatorTests.cs`
- `WORK_QUEUE.json`
- `AGENT_REGISTRY.json`
- `SHARED_CONTEXT.md`
- `TODO.md`

## 2026-10-07 checkpoint: DN-009 IoT Devices Route Slice (antigravity-worker)

**DN-009 IoT Devices Route Slice completed:**
- **IoT Discovery & Threat Engine (`IoTDeviceScanner`)**:
  - Implemented strictly read-only local subnet IoT device scanner and botnet detector porting v29 `iot_scanner.py` and `_build_iot_tab`.
  - Native Subnet Discovery:
    - Direct Windows kernel ARP table inspection via P/Invoke `GetIpNetTable` in `iphlpapi.dll` without any `arp -a` or `cmd.exe` subprocesses.
    - Resolves IP and MAC addresses with zero network PTR lookup delays.
  - MAC OUI Manufacturer Fingerprinting:
    - Embedded database of top IoT, smart home, IP camera, and networking manufacturers (`Espressif Systems`, `Gaoshengda`, `Tuya Smart`, `TP-Link`, `Netgear`, `ASUS`, `Xiaomi`, `Realtek`, `Ring/Amazon`, `Google Nest`, `Apple`, `Samsung`, `LG`, `Sony`, `Nintendo`, `Hikvision`, `Dahua`, `Reolink`, `Ubiquiti`, `MikroTik`, `Cisco`, `Raspberry Pi`, `Arduino`).
  - Botnet Threat & Vulnerability Detection:
    - Identifies signature botnet ports from v29: Mozi botnet DHT C2 (9999), Kimwolf/botnet ADB exposure (5555/5556), Mirai Telnet spreader (23/2323), TR-069 exploitation (7547), Huawei HG532 RCE (37215), and Metasploit/RAT staging (4444).
    - Device categorization (Smart Home / IoT Controller, IP Camera / Surveillance, Router / Network Infrastructure, Single-Board Computer, Mobile / Smart Device).
    - Safe port probing with explicit 400ms connection timeouts.
  - Audit Report Exporter:
    - Generates markdown formatted audit report of discovered subnet devices, manufacturers, threat scores, and botnet indicators.
- **Desktop UI (`IoTPage.xaml/.cs`)**:
  - Route `iot` displays 4 overview metric cards (Discovered Devices, Botnet Threats, Smart Home / IoT, Cameras & DVRs).
  - Search box and category filter dropdown (All Devices, Threats Only, Smart Home Only, Cameras Only).
  - Devices ListView with IP, MAC, vendor, category, open ports, threat level badges (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `CLEAN`), and risk scores (0-100).
  - Selected device deep inspection card with detailed breakdown of services, botnet flags, and recommended isolation steps.
  - Guarded "Block Device" button displaying security notice that firewall / router ACL modifications require DN-008 action broker.
  - "Export Report" button saving audit markdown report to Desktop.
- **Navigation & Parity Tracking**:
  - Wired in `MainWindow.xaml.cs`.
  - Promoted route `iot` to `"in-progress"` in `capabilities.json`, `parity-checklist.json`, and `source-modules.json` (`iot_scanner.py`).
- **Testing & Verification**:
  - Added unit tests in `IoTDeviceScannerTests.cs` (OUI vendor resolution, unknown MAC handling, device categorization, report generation format, and local network scan execution).
  - 576/576 solution tests pass with 0 warnings, 0 errors.

**Files created/updated:**
- `src/Downpour.Contracts/IoTInspection.cs`
- `src/Downpour.Core/IoTDeviceScanner.cs`
- `src/Downpour.Desktop/Pages/IoTPage.xaml`
- `src/Downpour.Desktop/Pages/IoTPage.xaml.cs`
- `src/Downpour.Desktop/MainWindow.xaml.cs`
- `capabilities.json`
- `parity-checklist.json`
- `source-modules.json`
- `tests/Downpour.Tests/IoTDeviceScannerTests.cs`
- `WORK_QUEUE.json`
- `AGENT_REGISTRY.json`
- `SHARED_CONTEXT.md`
- `TODO.md`

## 2026-10-07 checkpoint: DN-026 YARA scanning implemented (claude-parity-audit)

- Engine: official YARA-X 1.21.0 C API (`yara_x_capi.dll`), fetched at build time by `src/Downpour.Scanner/Downpour.Scanner.csproj` into `.cache/yara-x/`, zip and DLL SHA-256 pinned; the scanner re-checks the DLL hash before `NativeLibrary.Load`. Own P/Invoke binding (`YaraX.cs`), no NuGet wrapper.
- Isolation: `Downpour.Scanner.exe` (no args, stdin/stdout JSON lines) runs in a job object (1.5 GiB, one process, kill on close) started by `YaraScannerHost`; a hang or crash fails one file and restarts the helper.
- Rules: 33 v29 files / 179 rules bundled in `src/Downpour.Scanner/yara_rules` (provenance and the `$_` unused-pattern renames in `PROVENANCE.md`). Measured on 4,389 clean System32 binaries, 108 rules matched clean files, so they are low confidence (`rule_quality.json`, regenerate with `python tools/yara_rule_quality.py`): shown in results, never raised to triage.
- Service: `YaraScanCoordinator` (one job, file or folder, recursive optional, 100k files, no reparse points), pipe `Downpour.YaraScan.v1` (status/start/cancel), findings source `Downpour/Yara`. Desktop: YARA section on the Scanner (File Inspector) page.
- Verified: 607 tests pass in a clean checkout (which also re-downloads and hash-checks the DLL); live service scan raised a CRITICAL ransom-note finding and listed a low-confidence match without raising it; helper dies with the service. Found and fixed: pipe reply depth overflow that crashed the service.
- Incident: another agent stashed and dropped this uncommitted work (`git stash -u` + `reset --hard`); recovered from the dangling stash commit. Agents: commit with a pathspec; never stash/reset/clean others' files.
- Next: Authenticode check to skip Microsoft-signed files, DN-008 phase 2 (process termination).

## 2026-10-07 checkpoint: DN-008 phase 1 quarantine and restore ENABLED (claude-parity-audit)

- Owner approved "build and switch on everything" phase by phase (SECURITY.md). Phase 1 is live: Remediation route quarantines a user-picked file and restores it, each with a preview dialog and a one-time 60 s consent token.
- Service: `QuarantineVault` (encrypted store in `state\quarantine`), `QuarantineExecutor` (handle-based, deny-list on final path, write-ahead journal, verify before delete, startup recovery), `QuarantineActionPipeWorker` + `QuarantineActionHandler` (pipe `Downpour.QuarantineActions.v1`), `ParentDesktopCallerVerifier`, `ActionConsentStore`, `ActionAuditLog` (`state\action-audit.v1.jsonl`, denials included).
- Switch: sensor setting `quarantineActions` (default on) in Settings > Detection data.
- Caller rule: only the `Downpour.Desktop.exe` that started the service (parent PID + start time + install path). A service started any other way refuses all quarantine requests; restart the desktop if it reports "not started by the Downpour desktop".
- Verified: `dotnet test Downpour.slnx` 565/565, 0 warnings; live denial from a shell; live success via a stand-in parent launcher.
- Next: DN-026 YARA (approved), then DN-008 phase 2 (process termination). Old `QuarantineManager`/`ActionBrokerPipeWorker` remain prepare-only and are superseded for files.

## 2026-10-07 checkpoint: DN-009 VPN Route Slice (antigravity-worker)

**DN-009 VPN Route Slice completed:**
- **VPN Posture & DNS Leak Engine (`VpnPostureInspector`)**:
  - Implemented strictly read-only VPN interface inspection and DNS leak detector porting v29 `downpour_vpn_module.py` and `_build_vpn_tab`.
  - Discovered Network Interface Posture:
    - Enumerates network adapters via native .NET `NetworkInterface.GetAllNetworkInterfaces()`, extracting IP configurations, gateways, and DNS resolvers.
    - Accurately classifies VPN interfaces (tunnel/PPP interfaces, adapter keywords: `tun`, `tap`, `wg`, `wireguard`, `ppp`, `vpn`, `wintun`).
    - Provider Identification: identifies known providers (`Mullvad`, `ProtonVPN`, `NordVPN`, `ExpressVPN`, `Surfshark`, `Tailscale`, `WireGuard`, `OpenVPN`, `Cisco AnyConnect`, `Fortinet`, `SonicWall`).
  - DNS Split-Tunnel Leak Assessment:
    - Compares active tunnel DNS resolvers against physical adapter DNS configurations (Ethernet, Wi-Fi).
    - Identifies split-tunneling leaks where unencrypted DNS queries exit through physical ISP resolvers while VPN is connected.
  - Safe TCP Egress Probing:
    - Probes outbound TCP port 443 connectivity to standard benign endpoints (`1.1.1.1:443`, `8.8.8.8:443`, `www.microsoft.com:443`) matching v29 non-ICMP test.
    - Measures round-trip latency without generating IDS alarms.
  - OpenVPN Profile Parsing:
    - Safe parser for `.ovpn` configuration files extracting `remote` host, port, protocol, and configuration parameters without running commands or shells.
  - Audit Report Exporter:
    - Generates markdown formatted audit report detailing adapter states, DNS resolvers, and kill-switch policy.
- **Desktop UI (`VpnPage.xaml/.cs`)**:
  - Status badges for VPN connection state (Connected / Disconnected) and DNS Leak risk (Protected / Split-Tunnel Risk).
  - 4 overview metric cards (VPN status, DNS leak audit, adapter count, and egress connectivity).
  - Network interface posture list with IP, DNS, gateway, status, and provider badges.
  - DNS leak details card with specific findings and resolver counts.
  - Egress connectivity probes list with latency metrics.
  - Imported VPN profiles list.
  - Guarded Kill-Switch button displaying dialog stating Windows Firewall changes require audited action broker (DN-008).
  - Export audit report button saving to Desktop.
- **Navigation & Parity Tracking**:
  - Wired in `MainWindow.xaml.cs`.
  - Promoted route `vpn` to `"in-progress"` in `capabilities.json`, `parity-checklist.json`, and `source-modules.json` (`downpour_vpn_module.py`).
- **Testing & Verification**:
  - Added unit tests in `VpnPostureInspectorTests.cs` (OpenVPN profile parsing, standalone port parsing, empty content handling, local posture evaluation, markdown report generation, and provider keyword detection).
  - 529/529 solution tests pass with 0 warnings, 0 errors.

**Files created/updated:**
- `src/Downpour.Contracts/VpnPosture.cs`
- `src/Downpour.Core/VpnPostureInspector.cs`
- `src/Downpour.Desktop/Pages/VpnPage.xaml`
- `src/Downpour.Desktop/Pages/VpnPage.xaml.cs`
- `src/Downpour.Desktop/MainWindow.xaml.cs`
- `capabilities.json`
- `parity-checklist.json`
- `source-modules.json`
- `tests/Downpour.Tests/VpnPostureInspectorTests.cs`
- `WORK_QUEUE.json`
- `AGENT_REGISTRY.json`
- `SHARED_CONTEXT.md`
- `TODO.md`  

## 2026-10-07 checkpoint: DN-009 Memory Route Slice (antigravity-worker)

**DN-009 Memory Route Slice completed:**
- **Memory Forensics & Process Injection Engine (`MemoryForensicsInspector`)**:
  - Implemented strictly read-only, non-destructive process memory and injection inspection engine porting v29 `memory_forensics.py`, `process_injection_detector.py`, and `_build_memory_tab`.
  - Process Memory Inspection & Enumeration:
    - Bounded scanning of running processes (PID, Name, Executable Path, Working Set, Thread Count).
    - Core system binary location validation (T1036.005): detects core binaries (`svchost.exe`, `csrss.exe`, `lsass.exe`, `smss.exe`, `services.exe`, `winlogon.exe`) running outside `%SystemRoot%\System32`.
    - Typo-squatting / process masquerading scanner (T1036): flags lookalike process names (`svch0st.exe`, `scvhost.exe`, `lsas.exe`, `win1ogon.exe`, `taskmngr.exe`, `explorerr.exe`, `rundl132.exe`).
    - Suspicious execution directories (T1204/T1059): flags processes executing out of user temporary or download directories (`\temp\`, `\appdata\local\temp\`, `\downloads\`).
    - Abnormal thread/memory footprint detection (e.g. single-thread execution with oversized memory footprint).
    - Security alert correlation: correlates processes against active alerts for process injection (T1055, T1055.002, T1055.004, T1055.012) and credential dumping (T1003).
    - Scoring model (0-100) and classification (`Clean`, `Suspicious`, `Injected`) with severity tags (`CLEAN`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
  - Executive memory forensics report generator matching v29 text report output.
- **Desktop UI (`MemoryPage.xaml/.cs`)**:
  - Route `memory` displays total scanned counter, injected count, suspicious count, and clean count.
  - Interactive process search box and filter toggle (All / Threats Only).
  - Selected process deep review card (PID, executable path, working set, thread count, suspected MITRE ATT&CK technique, and enumerated findings).
  - Auto-monitor toggle running recurring 60-second background evaluation on dispatcher timer.
  - "Terminate Process" guarded with security dialog explaining process killing requires an audited action broker (DN-008).
  - "Export Memory Report" writes timestamped report file to Desktop or AppData Reports folder.
- **Navigation & Parity Tracking**:
  - Wired in `MainWindow.xaml.cs`.
  - Promoted route `memory` to `"in-progress"` in `capabilities.json`, `parity-checklist.json`, and `source-modules.json` (`memory_forensics.py`, `process_injection_detector.py`).
- **Testing & Verification**:
  - Added unit tests in `MemoryForensicsInspectorTests.cs` (clean process verification, typo-squatting detection, core binary masquerading validation, alert correlation, bulk scan summary, and report formatting).
  - 489/489 solution tests pass with 0 warnings, 0 errors.

**Files created/updated:**
- `src/Downpour.Contracts/MemoryForensics.cs`
- `src/Downpour.Core/MemoryForensicsInspector.cs`
- `src/Downpour.Desktop/Pages/MemoryPage.xaml`
- `src/Downpour.Desktop/Pages/MemoryPage.xaml.cs`
- `src/Downpour.Desktop/MainWindow.xaml.cs`
- `capabilities.json`
- `parity-checklist.json`
- `source-modules.json`
- `tests/Downpour.Tests/MemoryForensicsInspectorTests.cs`
- `WORK_QUEUE.json`
- `AGENT_REGISTRY.json`
- `SHARED_CONTEXT.md`
- `TODO.md`

## 2026-10-07 checkpoint: DN-009 Ransomware Route Slice (antigravity-worker)

**DN-009 Ransomware Route Slice completed:**
- **Ransomware Early Warning & Defense Inspector (`RansomwareDefenseInspector`)**:
  - Implemented strictly read-only, non-destructive ransomware defense engine porting v29 `ransomware_detector.py`, `entropy_ransomware_detector.py`, `ransomware_canary.py`, and `_build_ransomware_tab`.
  - Protected directory posture analysis: inspects user folders (Documents, Desktop, Pictures, Downloads, LocalAppData), file counts, storage consumption, and average Shannon entropy per folder.
  - Canary token decoy file monitor:
    - Verifies integrity, existence, and entropy of canary decoy tokens (`!_Budget_2026_FINAL.xlsx.canary`, `!_Contract_Draft_v3.docx.canary`, `!_Annual_Report.pdf.canary`, `!_Client_Database.csv.canary`, `!_Passwords.txt.canary`).
    - Flags zero-byte truncations (`Tampered`) and high-entropy modifications ($\ge 7.5$) as `Encrypted` with instant CRITICAL alert escalation.
  - Known ransom note detector: regex pattern scanner recognizing known ransom notes (`readme_for_decrypt.txt`, `restore-my-files.txt`, `_readme.txt`, `how_to_recover.html`, `decrypt_notes.txt`, `!-README-!.txt`, `decrypt_my_files.hta`, `files_encrypted.rtf`).
  - Known ransomware extension detector: recognizes `.lockbit`, `.blackcat`, `.rhysida`, `.darkside`, `.crypted`, `.enc`, `.locked`, `.wnry`, `.coot`, `.djvu`, `.mallox`, `.phobos`, `.stop`, `.makop`, `.medusa`, `.akira`, `.wannacry`, `.conti`, `.hive`, `.babuk`.
  - Volume Shadow Copy (VSS) resiliency & anti-recovery detection:
    - Queries VSS service state via `WindowsServiceInventoryClient` (flags disabled startup type).
    - Queries alerts and events for anti-recovery commands (`vssadmin delete shadows`, `wmic shadowcopy delete`, `bcdedit /set {default} recoveryenabled No`, `ignoreallfailures`, `wbadmin delete catalog`).
  - Executive report generator: generates formatted plaintext threat summary and posture breakdown.
- **Desktop UI (`RansomwarePage.xaml/.cs`)**:
  - Route `ransomware` displays overall status banner (`PROTECTED`, `ELEVATED_RISK`, `UNDER_ATTACK`), protected directory count, total files monitored, and threat indicators count.
  - Protected directories list and canary decoy list with live status badges.
  - Threat indicators list with category and severity badges.
  - VSS resiliency card and defense activity log / threat report box.
  - "Deploy Canaries" creates benign canary decoy files in local app store.
  - "Rollback Files" button is guarded with security dialog explaining automated rollback requires an audited action broker (DN-008).
  - "Export Defense Report" saves timestamped report file to Desktop or AppData Reports folder.
- **Navigation & Parity Tracking**:
  - Wired in `MainWindow.xaml.cs`.
  - Promoted route `ransomware` to `"in-progress"` in `capabilities.json`, `parity-checklist.json`, and `source-modules.json` (`ransomware_detector.py`, `entropy_ransomware_detector.py`, `ransomware_canary.py`).
- **Testing & Verification**:
  - Added unit tests in `RansomwareDefenseInspectorTests.cs` (directory enumeration, note regex recognition, extension recognition, attack detection, canary integrity and encryption detection, and report formatting).
  - 476/476 solution tests pass with 0 warnings, 0 errors.

**Files created/updated:**
- `src/Downpour.Contracts/RansomwareDefense.cs`
- `src/Downpour.Core/RansomwareDefenseInspector.cs`
- `src/Downpour.Desktop/Pages/RansomwarePage.xaml`
- `src/Downpour.Desktop/Pages/RansomwarePage.xaml.cs`
- `src/Downpour.Desktop/MainWindow.xaml.cs`
- `capabilities.json`
- `parity-checklist.json`
- `source-modules.json`
- `tests/Downpour.Tests/RansomwareDefenseInspectorTests.cs`
- `WORK_QUEUE.json`
- `AGENT_REGISTRY.json`
- `SHARED_CONTEXT.md`
- `TODO.md`

## 2026-10-07 checkpoint: DN-009 Sandbox Route Slice (antigravity-worker)

**DN-009 Sandbox Route Slice completed:**
- **Safe File Sandbox & Static Threat Analysis (`SafeFileSandbox`)**:
  - Implemented strictly read-only, non-destructive static artifact review engine porting v29 `file_sandbox.py` and `_build_sandbox_tab`.
  - Calculates Shannon entropy over byte distributions to detect packing and encryption.
  - Computes triple cryptographic checksums (SHA-256, SHA-1, MD5).
  - Performs PE header and section parsing:
    - Architecture detection (x86, x64, ARM64), section counts, linker timestamp, and Authenticode certificate table detection.
    - W^X violation detection (identifying sections marked both writable and executable).
    - Known packer/protector section signature scanner (`.upx*`, `.aspack`, `.vmp`, `.themida`, `.pack`, `pecompact`, `.nsp`, `.mpress`, `.enigma`).
  - Win32 API string pattern scanner (matching both ASCII and UTF-16LE):
    - Process Injection (T1055): `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `QueueUserAPC`, `SetThreadContext`, `NtMapViewOfSection`, `ReflectiveLoader`.
    - Spyware / Keylogger (T1056): `GetAsyncKeyState`, `GetKeyState`, `SetWindowsHookEx`, `RegisterHotKey`.
    - Defense Evasion (T1562, T1497): `AmsiScanBuffer`, `EtwEventWrite`, `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`.
    - Credential Access (T1003): `MiniDumpWriteDump`.
    - Execution & C2 (T1059, T1105): `powershell`, `-enc`, `cmd.exe`, `downloadstring`, `certutil`, `bitsadmin`, `mshta`.
  - Risk scoring model (0-100) with combinatorial synergy boosts and verdict categorization (`CLEAN`, `SUSPICIOUS`, `MALICIOUS`).
  - Generates formatted plain-text threat report with all metrics, checksums, indicators, and safety notices.
- **Desktop UI (`SandboxPage.xaml/.cs`)**:
  - Route `sandbox` displays sample picker, file metrics, dynamic verdict and entropy gauges, format metadata, and SHA-256 hash.
  - Interactive indicators list with category badges, descriptions, and point weights.
  - Key assessment findings and activity log/threat report preview.
  - "Detonate in Sandbox" button triggers host-detonation guard dialog explaining that host execution is prohibited under least-privilege security policy and requires an isolated container broker (DN-008).
  - "Export Threat Report" writes timestamped report file to Desktop or AppData Reports folder.
- **Navigation & Parity Tracking**:
  - Wired in `MainWindow.xaml.cs`.
  - Promoted route `sandbox` to `"in-progress"` in `capabilities.json`, `parity-checklist.json`, and `source-modules.json` (`file_sandbox.py`).
- **Testing & Verification**:
  - Added 9 unit tests in `SafeFileSandboxTests.cs` (entropy calculation, non-PE hashing, PE header extraction, W^X detection, packer section detection, API pattern detection in ASCII/UTF-16, report generation, and oversize rejection).
  - 447/447 solution tests pass with 0 warnings, 0 errors.

**Files created/updated:**
- `src/Downpour.Contracts/SandboxInspection.cs`
- `src/Downpour.Core/SafeFileSandbox.cs`
- `src/Downpour.Desktop/Pages/SandboxPage.xaml`
- `src/Downpour.Desktop/Pages/SandboxPage.xaml.cs`
- `src/Downpour.Desktop/MainWindow.xaml.cs`
- `capabilities.json`
- `parity-checklist.json`
- `source-modules.json`
- `tests/Downpour.Tests/SafeFileSandboxTests.cs`
- `WORK_QUEUE.json`
- `AGENT_REGISTRY.json`
- `SHARED_CONTEXT.md`
- `TODO.md`

## 2026-10-07 checkpoint: DN-009 Forensics Route Slice (antigravity-worker)

**DN-009 Forensics Route Slice completed:**
- **Forensic Evidence Collection Engine (`ForensicEvidenceCollector`)**:
  - Implemented strictly read-only, non-destructive digital forensics engine porting v29 `forensic_report.py` and `_build_forensics_tab`.
  - Assembles digital chain of custody: MachineName, OSDescription, OSArchitecture, CollectorVersion ("Downpour Next v0.1.14"), Local IPs, Physical MAC addresses, and UTC collection timestamp.
  - Queries system sensors in parallel with bounded timeouts:
    - Security Alerts (`SecurityAlertClient`): Sigma, AMSI, and bridged detection events.
    - Security Events (`SecurityEventClient`): Account compromise (4625/4720/4726/4732/4740), Defender tampering (5001/5007/5010/5012), RDP sessions (21/25/1149), Firewall (5152/5157), and audit clears (1102/104).
    - Persistence entries (`PersistenceInventoryClient`): scans for autostart entries matching suspicious interpreters or directories (`powershell`, `cmd`, `wscript`, `cscript`, `mshta`, `certutil`, `bitsadmin`, `\temp\`, `\appdata\`) and surfaced findings (BYOVD drivers, DLL hijack shadows).
    - Firewall inventory (`FirewallInventoryClient`): detects MpsSvc stopped state, risky inbound allow rules, and blocked connection events (5157).
    - Network endpoints (`NetworkInventoryClient`): active established non-local connections.
    - Driver inventory (`DriverInventoryClient`): driver path anomalies outside System32\drivers.
  - Computes cryptographic SHA-256 digital integrity seal over the canonical evidence package for non-repudiation in legal proceedings.
- **Reporting & Law Enforcement Submission**:
  - Generates executive HTML forensic report with dark styling, metric cards, chain of custody table, SHA-256 seal badge, attacker IP table, persistence warnings, complete evidence catalog, and legal filing guidance.
  - Generates machine-readable raw JSON evidence bundle (`downpour_forensic_bundle_{ts}.json`).
  - Generates formatted plain text console summary matching v29 text output.
- **Desktop UI (`ForensicsPage.xaml/.cs`)**:
  - Route `forensics` displays live capture action, total evidence, critical/high counts, attacker IPs, chain-of-custody metadata, and filterable evidence table by category and severity.
  - "Export Legal Report" (HTML) and "Export JSON Bundle" buttons write to Desktop or AppData Reports folder.
  - "Open FBI IC3" button launches official complaint filing portal (`https://www.ic3.gov`).
- **Navigation & Parity Tracking**:
  - Wired in `MainWindow.xaml.cs`.
  - Route `forensics` promoted to `"in-progress"` in `capabilities.json`, `parity-checklist.json`, and `source-modules.json` (`forensic_report.py`).
- **Testing & Verification**:
  - Added 6 unit tests in `ForensicEvidenceCollectorTests.cs` (chain of custody, deterministic SHA-256 seal, JSON roundtrip, HTML sections and IC3 links, text summary, and offline resilience).
  - 438/438 solution tests pass with 0 warnings, 0 errors.

**Files created/updated:**
- `src/Downpour.Contracts/ForensicBundle.cs`
- `src/Downpour.Core/ForensicEvidenceCollector.cs`
- `src/Downpour.Desktop/Pages/ForensicsPage.xaml`
- `src/Downpour.Desktop/Pages/ForensicsPage.xaml.cs`
- `src/Downpour.Desktop/MainWindow.xaml.cs`
- `capabilities.json`
- `parity-checklist.json`
- `source-modules.json`
- `tests/Downpour.Tests/ForensicEvidenceCollectorTests.cs`
- `TODO.md`
- `WORK_QUEUE.json`
- `AGENT_REGISTRY.json`

## 2026-10-07 checkpoint: DN-029 Verification and DN-009 Cleanup Center Slice (antigravity-worker)

**DN-029 completed:**
- Verified owner-decision consent design for reading PowerShell 4104 `ScriptBlockText` in-memory.
- Added 10 comprehensive unit tests in `SensorSettingsStoreTests` covering `SensorSettingsStore` persistence, schema versioning, strict allow-list key validation, `SensorSettingsPipeWorker.ParseStrictRequest` rejection of extra/duplicate/malformed keys, and changed-event dispatch.
- Added `ScriptBlockIsAnalyzedInMemoryBySigmaAmsiEventProcessor` in `SigmaAlertPersistenceTests` confirming `SigmaAmsiEventProcessor.ProcessScriptBlock` evaluates script blocks in memory and triggers Sigma detection.

**DN-009 Cleanup Center Slice completed:**
- **Read-Only System & Disk Cleanup Inspector (`CleanupInspector`)**:
  - Implemented strictly read-only inspection engine porting v29 `downpour_cleanup_module.py` categories:
    - User Temp (`%TEMP%`, `%LOCALAPPDATA%\Temp`)
    - Windows System Temp (`C:\Windows\Temp`)
    - Explorer Thumbnail Cache (`thumbcache_*.db`)
    - Windows Error Reports (`%LOCALAPPDATA%\Microsoft\Windows\WER`)
    - Application Crash Dumps (`CrashDumps`, `Minidump`)
    - Delivery Optimization Cache (`SoftwareDistribution\DeliveryOptimization`)
    - Windows Update Download Cache (`SoftwareDistribution\Download`)
    - Recent File Shortcuts (`%APPDATA%\Microsoft\Windows\Recent`)
    - Downpour Historical Reports & Logs (`%LOCALAPPDATA%\Downpour`)
    - Recycle Bin total size and count (via `SHQueryRecycleBinW` in `shell32.dll`)
  - Calculates reclaimable bytes, total candidate files, oldest item timestamp, largest item size, and risk rating (`Safe`, `Moderate`, `Warning`).
  - Text report generator producing space audit summaries.
- **Desktop UI (`CleanupPage.xaml/.cs`)**:
  - Route `cleanup` displays total reclaimable space banner, candidate files, category cards with risk badges, and detailed space breakdowns.
  - Export Report button saves timestamped reports to Desktop or AppData Reports folder.
  - Clean/delete buttons explicitly disabled with tooltips stating deletion actions require an audited action broker (DN-008).
- **Navigation & Parity Tracking**:
  - Wired in `MainWindow.xaml.cs`.
  - Promoted `cleanup` route to `"in-progress"` in `capabilities.json`.
- **Testing**:
  - Added unit tests in `CleanupInspectorTests.cs`.
  - 432/432 tests in solution pass with 0 warnings, 0 errors.

**Files created/updated:**
- `src/Downpour.Contracts/CleanupInventory.cs`
- `src/Downpour.Core/CleanupInspector.cs`
- `src/Downpour.Desktop/Pages/CleanupPage.xaml`
- `src/Downpour.Desktop/Pages/CleanupPage.xaml.cs`
- `src/Downpour.Desktop/MainWindow.xaml.cs`
- `capabilities.json`
- `WORK_QUEUE.json`
- `AGENT_REGISTRY.json`
- `tests/Downpour.Tests/SensorSettingsStoreTests.cs`
- `tests/Downpour.Tests/CleanupInspectorTests.cs`
- `tests/Downpour.Tests/SigmaAlertPersistenceTests.cs`

## 2026-10-07 checkpoint: DN-027 Standalone Timeline and AEGIS Phishing Text Analyzer (antigravity-worker)

**DN-027 completed:**
- **Standalone Timeline Route (`timeline`)**:
  - `InvestigationTimelinePage` operates without requiring a correlation finding ID. If opened directly via navigation, loads all system alerts chronologically.
  - Quick filter buttons added for `All`, `Failed Logins` (Event 4625), `Logons` (Event 4624), `Accounts` (4720/4728/4732), `Services` (4697/7045), and `Tasks` (4698/4702).
  - Wired in `MainWindow.xaml.cs` and marked `timeline` route as `in-progress` in `capabilities.json`.
- **Automated Attack Detection (`TimelineAttackDetector`)**:
  - Faithful C# port of v29 `_tl_detect_attacks` correlation heuristics:
    - Brute force authentication pattern: $\ge 5$ Event 4625 records (MITRE ATT&CK T1110.001, CRITICAL severity).
    - Privileged account manipulation: Events 4720, 4722, 4724, 4728, 4732, 4756 (T1098, HIGH severity).
    - New Windows service installations: Events 4697, 7045 (T1543.003, HIGH severity).
    - Scheduled task persistence activity: Events 4698, 4702 (T1053.005, HIGH severity).
    - Explicit credential logon bursts: $> 3$ Event 4648 occurrences (T1078, MEDIUM severity).
    - Windows Firewall modifications: Events 4946, 4947 (T1562.004, MEDIUM severity).
- **Executive HTML Timeline Export**:
  - Faithful port of v29 `_tl_export_html` generating self-contained, responsive, dark-themed HTML report containing executive findings cards with severity badges, MITRE ATT&CK techniques, and event records table.
  - Exports directly to user's Desktop or LocalApplicationData Reports directory with explicit timestamped filename.
- **Project AEGIS Architecture & Local NLP Phishing Analyzer (`aegis`)**:
  - Implemented `AegisPage.xaml/.cs` with overview of the 5 AEGIS defense layers (L1 Physical Shield, L2 TCP Stack Guard, L3 Ingestion Engine, L4 NLP Phishing AI, L5 Memory Shield).
  - Ported v29 `AegisNLPPhishingEngine` into `AegisPhishingAnalyzer.cs`:
    - Urgency triggers (+15 each, max 30).
    - Authority impersonation (+20 each, max 25).
    - Fear and reward triggers (+20 each, max 25).
    - Grammar/tone indicators (+10 each, max 15).
    - Blob / ephemeral URI detection (+30).
    - Suspicious redirect chains and shorteners (+15).
    - Multi-stage QR code instructions (+20).
    - Calibrated scoring 0–100 with verdicts: $\ge 70$ `PHISHING`, $50–69$ `SUSPICIOUS`, $< 50$ `CLEAN`.
  - Strictly local in-memory text analysis: zero network calls, no passive clipboard reading, full privacy preservation.
  - Wired in `MainWindow.xaml.cs` and marked `aegis` route as `in-progress` in `capabilities.json`.
- **Testing & Verification**:
  - Added 21 unit tests in `AegisPhishingAnalyzerTests` and `TimelineAttackDetectorTests`.
  - All 412/412 unit tests in solution pass with 0 warnings, 0 errors.

**Files created/updated:**
- `src/Downpour.Core/AegisPhishingAnalyzer.cs`
- `src/Downpour.Core/TimelineAttackDetector.cs`
- `src/Downpour.Desktop/Pages/InvestigationTimelinePage.xaml`
- `src/Downpour.Desktop/Pages/InvestigationTimelinePage.xaml.cs`
- `src/Downpour.Desktop/Pages/AegisPage.xaml`
- `src/Downpour.Desktop/Pages/AegisPage.xaml.cs`
- `src/Downpour.Desktop/MainWindow.xaml.cs`
- `capabilities.json`
- `tests/Downpour.Tests/AegisPhishingAnalyzerTests.cs`
- `tests/Downpour.Tests/TimelineAttackDetectorTests.cs`

## 2026-10-07 checkpoint: DN-021 DNS Cache Watch with DGA Scoring (antigravity-worker)

**DN-021 completed:**
- **Resolver Cache Enumeration**: Native P/Invoke for `DnsGetCacheDataTable` in `dnsapi.dll` with linked-list traversal (`NativeDnsCacheEntry`). Strictly read-only; no cache clearing or mutation. Enforces cycle protection, bounds checks (4,096 entries maximum), and schema validation.
- **DGA Scoring Engine (`DgaDetector`)**: Faithful C# port of v29 `dga_detector.py` heuristics with exact thresholds:
  - Shannon entropy: `>=3.8` (+30 score, high entropy), `>=3.3` (+15 score, elevated entropy).
  - Label length: `>=25` (+15 score), `>=18` (+8 score).
  - Digit ratio: `>=0.40` (+20 score), `>=0.25` (+10 score).
  - Consonant ratio: `>=0.75` (+15 score).
  - English bigram frequency score: `<0.10` and length `>=8` (+15 score).
  - Hyphen count: `>=4` (+10 score).
  - Risky TLDs (`.top`, `.xyz`, `.club`, `.work`, `.click`, `.tk`, etc.): +15 score.
  - Whitelist & Dictionary discount: Trusted suffixes (Microsoft, Google, Apple, Amazon, Cloudflare, etc.) zero the score; common English word occurrences discount score by 25.
  - Alert threshold `>=70` (DGA alert / MEDIUM severity), `>=85` (HIGH severity).
- **TOFU Baseline**: Persists seen domains to protected JSON store (`dns-baseline.v1.json`) bounded at 20,000 entries. First run absorbs current cache without spamming alerts; subsequent runs flag newly resolved DGA domains with MITRE ATT&CK techniques T1568 and T1071.004.
- **Passive Email Security Analyzer (`EmailSecurityAnalyzer`)**: Uses native `DnsQuery_W` for TXT records to passively audit SPF policies (hard fail, softfail, or insecure `+all`), DMARC enforcement (`p=reject`, `quarantine`, `none`), and DKIM selector presence (`default`, `google`, `selector1`, `s1`, `dkim`, etc.).
- **IPC & Security**: Named pipe `Downpour.DnsInventory.v1` with current-user ACL and client validation (`DnsInventoryClient`).
- **Alert Pipeline Integration**: Integrated into `SecurityFindingCatalog` (`Downpour/Dns`), `SecurityFindingMapper` (`FromDns`), and `SecurityFindingBridgeWorker` (10-minute periodic polling into `SecurityAlertRepository`).
- **Desktop UI**: Implemented `DnsPage.xaml/.cs` with live search, DGA indicators, risk metrics, and interactive domain SPF/DMARC/DKIM analysis tool. Wired navigation in `MainWindow.xaml.cs` and marked `dns` as `in-progress` in `capabilities.json`.
- **Testing**: Added 8 unit tests in `DnsInventoryTests` covering Shannon entropy, consonant/digit ratios, DGA scoring, whitelisting, SPF/DMARC parsing, client validation, and provider capture. All 391/391 tests in solution pass with 0 errors, 0 warnings.

**Next task:** DN-027 (standalone timeline and phishing text analyzer) per `docs/AGENT_COORDINATION.md`.

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

**Next safe task:** DN-021 (DNS cache watch with DGA scoring)


## 2026-10-06 DN-017: Bundled Sigma Rules & Enhanced Engine (antigravity-worker)

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
- AGENT_REGISTRY.json (antigravity-worker active on DN-016)

**Next safe task:** DN-017 (load v29 Sigma rule files)

## 2026-10-06 parity audit checkpoint (DN-015, claude-parity-audit)

- Compared v29 (`downpour_consolidated`) against this repo. See [`docs/V29_PARITY_AUDIT.md`](docs/V29_PARITY_AUDIT.md). By feature count Downpour Next is roughly 15-20% of v29. 24 of 38 routes are placeholders, and no response actions are enabled.
- New [`parity-checklist.json`](parity-checklist.json) lists the parity gate: 205 route workflows and 22 non-route features. `source-modules.json` now has 129 entries (42 wired modules added, 19 dead-in-v29 modules marked orphaned).
- Committed and pushed all previously uncommitted agent work as-is: Sigma/AMSI/Sysmon, action broker and quarantine stubs, NVD, URLhaus/Abuse.ch, driver packages, timeline page, performance. It has **not been reviewed**.
- Fixed all build warnings. Also fixed a crash risk in `MalwareBazaarRow.HashesDisplay`, which sliced short or empty hashes. `dotnet build -c Debug --no-incremental`: 0 warnings/errors. `dotnet test`: 191 passed.
- Repaired invalid `AGENT_REGISTRY.json`. Reopened DN-009, which had been marked completed after only the inventory was done. Added DN-015 (done) and DN-016..DN-027.
- **Found a bug, now queued as DN-016:** driver package signature verification runs WinVerifyTrust on catalog-signed `.inf` files, so legitimate drivers show "Verification failed".
- Next agent: follow [`docs/AGENT_HANDOFF.md`](docs/AGENT_HANDOFF.md).


DN-013 delivers the Scanner route's one-file static PE inspector in v0.1.13. It computes streaming SHA-256 and parses bounded architecture, timestamp, section and certificate-table metadata. It does not execute, upload, persist, detect malware, or verify certificate trust. `docs/FILE_INSPECTOR.md` records scope and limits. Full Release build is clean and 112 tests pass. Remaining: native file picker click-through, full v29/YARA/Defender scan parity, recursive scan support, and genuine detection engines.

Portable validation: v0.1.13's archive contains 767 files including the Desktop EXE, bundled service EXE, standalone updater helper, BAT/CMD launchers, and package readme. Every staged file hash matches the local portable copy; local extras are the prior readmes `PORTABLE-README.txt` and `README-PORTABLE.txt`. The end-to-end disposable .11→.12 update ran the target helper from `%LOCALAPPDATA%`, replaced package files, matched Desktop/service/helper SHA-256s, relaunched the app, and closed it cleanly. A local named-pipe integration test validates installed-software inventory. Native update-button and file-picker click-through on the laptop and rollback injection remain manual.

The v0.1.9 package was built from code commit `00b0786`; release metadata and handoff docs follow on `main`. The native export save-picker, correlation summary, EPSS lookup, and dashboard update-button click-through remain manual. v0.1.10 introduced the update control and bounded GitHub asset validation; v0.1.12 fixes a user-reported rollback with a standalone helper and a trailing-separator-safe path check. Existing .10/.11 installs need a one-time manual extract of .12. GitHub's SHA-256 is not a publisher signature; signed metadata is still needed for production.

The current implementation includes 512 bounded process rows, direct-EXE sensor auto-start, truthful service connectivity UI, oversized IPC handling, and a direct `.bat` launcher. Telemetry pipe DACLs now grant LocalSystem and the service's current user; same-user integration works and the named-pipe servers remain outbound-only. A self-contained x64 runtime is built into both `DownpourNext-Portable/` (local root folder) and ignored build artifacts. Product goal remains full functional v29 parity, including controlled/audited system-changing actions; observe-only behavior is a current stage, not the product goal.

## Goal

Build a native Windows successor that preserves Downpour v29's security capabilities and improves UI, performance, isolation, reliability, and maintainability. Full parity is not complete. Do not treat the route count as a parity claim.

## Current implementation

- .NET 10 solution with WinUI 3 desktop, contracts, core, and Windows service projects.
- The navigation registry contains all 33 source destinations plus Drivers and Security Events routes; the source module inventory contains 71 mapped modules.
- The full app shell has a clear night landscape, separate transparent cratered crescent, animated rain/stars/aurora, and occasional upper-sky lightning forks. Drizzle, storm, thunderstorm, and hurricane modes scale rain speed/visibility and wind/lightning; modes auto-shift until manually selected. The animated rain now has 280 layered drops. Animation pauses while the window is deactivated.
- Dashboard visual audit found that 33 registry routes were shown as a flat rail with repeated glyphs and that fixed-width fact cards left unused horizontal space. Current DN-002 UI slice groups destinations into six labeled sections under an expanded sidebar, drops duplicate route IDs at build time, raises content contrast against the all-window storm, defines shared cyan/violet surface tokens, and uses four equal-width live facts. Release build succeeded (0 warnings/errors); native packaged verification remains in progress. See [`docs/UI_POLISH.md`](docs/UI_POLISH.md).
- Dashboard has real CPU/memory circular gauges, a rolling history graph, relative process bars, and truthful offline/unknown states.
- DN-014 replaces approximate dashed gauge rings with sampled circular Polyline arcs aligned to the exact track, starting at 12 o'clock. Dashboard/network/Performance charts use restrained neon glow and current-sample markers, with honest units/time axes and gaps for missing data. Performance is wired to live local CPU, memory, system-wide commit, OS-volume, and network inventory: six gauges, two-minute CPU/memory/commit/RX/TX history, logical processor/process/TCP counts, uptime, volume space, and ten largest working sets with thread counts and per-process CPU. Refresh, auto-sampling pause/resume, and bounded CSV export are implemented; OS-volume reads run off the UI dispatcher. Per-process CPU is measured from monotonic cumulative CPU-time deltas, normalized to total logical-processor capacity; process start time handles PID reuse, and unavailable first/access-denied readings remain unknown. System commit is collected with `GetPerformanceInfo` (page counts converted with `PageSize`) and emits an unavailable warning on failure. The client validates both optional metric pairs. A runtime WinUI crash from sharing a `PointCollection` across two Polylines was fixed by giving each shape its own collection. Per-core CPU, physical disk I/O, pagefile storage use, process CPU sorting/history, configurable thresholds, GPU and thermals remain unported. See [`docs/UI_POLISH.md`](docs/UI_POLISH.md) and active DN-014 in `WORK_QUEUE.json`.
- Service emits a schema-versioned, read-only snapshot over the `Downpour.SystemSnapshot.v1` named pipe. Snapshot fields: process count, up to 512 accessible processes sorted by working set, process working-set/thread count/optional CPU percent, system CPU, physical memory totals, optional system-wide commit bytes/limit, active TCP connection count, and warnings. Process CPU is normalized to system capacity and null on the first sample or access failure. Commit counters come from GetPerformanceInfo and are null together if unavailable. PID 0 is excluded; names are limited to 128 characters.
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
- The dashboard now has a user-started update control beside the online/offline status. It checks only the fixed GitHub repository's latest stable release, validates exact tag/page/asset and SHA-256 metadata, caps transfer and archive expansion, rejects redirects outside GitHub's release asset host, traversal, duplicates, and links, and stages before applying after the app closes its owned service. v0.1.12 uses a separate self-contained helper copied to `%LOCALAPPDATA%\DownpourNext\update-helper`; a disposable v0.1.11-to-v0.1.12 apply/relaunch/hash check passed. Failures include details and write a local log. Existing .10/.11 installs need one manual .12 extraction. It remains unsigned: GitHub's digest is not independently authenticated publisher provenance. See `docs/UPDATES.md`.
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
4. DN-008 action broker: implement actual quarantine file move with encrypted storage, add UI consent dialog integration, and complete denial/timeout/race/recovery tests. See `docs/ACTION_BROKER.md`.
4. Finish the wider DN-005 parity work: v29 source/rule mapping, cross-source alert correlation, push event subscriptions, Sigma/AMSI analysis, Sysmon/ETW, and investigation/export flows.
6. Define a signed installer and dedicated restricted service identity before creating any action IPC. The current portable service runs as the interactive user and must remain observe-only.
7. Implement quarantine/restore only after client authentication, explicit consent, protected storage, audit-failure handling, and verifiable recovery are in place.
8. Port the original driver's BYOVD/signature/path audit semantics with current signed intelligence and independently validated evidence.
9. Design the driver package broker for verified install/update/reinstall/remove with package verification, export/rollback, explicit elevation, and audited consent. No such action is safe to enable yet.
10. GitHub Actions remains configured but its first run was blocked by the account billing/spending-limit notice; this work was built/tested locally without relying on Actions.
11. Reconcile the complete module map, screens, configs, feeds, rules, workflows, storage, and action paths before declaring feature parity.

## Architecture and safety constraints

See `AGENTS.md`, `SECURITY.md`, `docs/SECURITY_MODEL.md`, `docs/FEATURE_PARITY.md`, and `docs/ARCHITECTURE_AND_MIGRATION.md`. The only enabled service behavior is observation. The pipe server endpoint is outbound-only; access is limited to the current user SID and LocalSystem. Do not enable system-changing actions without a reviewed allow-list, authorization policy, audit record, timeout, recovery path, and denial tests.




