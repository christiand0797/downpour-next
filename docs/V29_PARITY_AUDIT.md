# v29 → Downpour Next parity audit

**Date:** 2026-10-06
**Compared:** `C:\Users\purpl\Desktop\downpour_consolidated` (v29 Titanium, `downpour_v29_titanium.py` 61,176 lines + 140 top-level modules) against this repo at `578f188` plus the uncommitted working tree.
**Method:** static extraction of every `_build_*_tab` method (labels and `command=` handlers), every background thread/`after()` loop, every top-level class, and a transitive import graph from `downpour_v29_titanium.py`; then grep and read of the C# source. Build and test: `dotnet test Downpour.slnx -c Debug` gave 191/191 passed, with 7 compiler warnings.

Legend: **Done** = data path works · **Partial** = some of the v29 workflow exists · **None** = only a placeholder `CapabilityPage` or no route at all.

---

## 1. Summary

| Area | v29 | Downpour Next |
|---|---|---|
| UI destinations (`_build_*_tab`) | 37 builders (34 distinct screens + 3 containers) | 38 routes: 1 prototype, 13 in-progress, **24 planned (placeholder only)** |
| Wired helper modules | ~90 reachable from main | inventory tracks 71; **42 wired modules are missing from `source-modules.json`** |
| Background jobs | 9 threads + ~50 scheduled `after()` loops | about 10 hosted services (inventory, events, Sigma/AMSI, Sysmon) |
| Response actions | kill, quarantine, block IP, isolate, firewall, USB block, revert, lockdown | none enabled (broker stubs return `RejectedNotImplemented`) |
| Detection content | 24 bundled + 19 file Sigma rules, 34 YARA files, 750+ signatures, IOC/DGA/LOLBin/beacon engines | small set of built-in Sigma rules. **The v29 `sigma_rules/` files are never loaded** (`LoadFromYamlFiles` has no callers). No YARA. |

**Conclusion:** Downpour Next is a solid, well-tested read-only foundation (inventory, events, KEV/EPSS/NVD, alerts). By feature count it is roughly 15–20% of v29. Nothing is lost silently, because the routes say "planned". However, the parity tracking files undercount what v29 does, so "every planned item finished" would still not mean parity.

---

## 2. Screen-by-screen gap matrix

| v29 screen (builder) | v29 workflows | Next status | Missing |
|---|---|---|---|
| Dashboard (`_build_dashboard`) | live threat feed with right-click actions (block IP, VirusTotal, GeoIP, rDNS, copy IOC, kill, quarantine, dismiss); security health grade; engine control "START ALL ENGINES"; gaming status; quick triage; privacy score and Privacy Mode | Partial | threat feed actions, engine control, privacy score/mode, gaming status, health grade |
| Processes | filterable tree, detail pane, process tree, watchlist, check IPs, open location, copy, mitigate | Partial | lineage tree, watchlist, per-process IP check, mitigation, security signals |
| Scanner | scan with file/threat/clean counters, scan log, YARA + hash scanning | Partial (single-file PE metadata) | recursive scan, YARA, hash/IOC match, verdicts, Defender integration |
| Threats | threat log, AUTO remediation toggle, Remediate All/Selected, Quarantine, Kill, Browser Scan, Block IP, **Isolate Host**, Mark FP, FP Blocklist, Export, Report | None (Alerts covers only event-ID alerts) | the whole threat-centric workflow |
| Possible Threats | verify→threats, dismiss, investigate, intel lookup | None | all |
| Remediation | history, auto-revert, revert selected, export, details | None | all (needs the action broker first) |
| Intel | IP/hash/URL check; **custom feed manager** (add/fetch/remove/import from file); feed statistics | Partial (KEV + EPSS; URLhaus/Abuse.ch uncommitted) | indicator lookup, custom feeds, feed stats, scheduled feed refresh and feed health |
| CVE dashboard | KEV tree, Windows/MS and 2024–26 filters, CVE detail, **apply mitigation**, kernel integrity, linked threat graph | Partial (KEV/EPSS; NVD uncommitted) | filters, mitigation, kernel integrity, threat graph |
| Audit → Hardening / Vuln scan / Compliance | hardening analyzer and score, NSA checks, fix log, zero-day scanner, "FIX ALL", live zero-day check, compliance score | None | all; `firmware_posture.py` checks (BitLocker/SecureBoot/TPM/LSA-PPL/HVCI/SMBv1) are a natural read-only first step |
| Performance | CPU/RAM/**GPU**/net/disk gauges, **CPU temperature**, per-core, top processes with **Kill / Analyze / Set Priority / Open location**, interfaces, partitions, 60s history, interval selector, CSV export | Done for read-only metrics | GPU, temperature, process actions, interval selector |
| Network | connections, network alerts, **packet capture**, **rogue DHCP check**, bandwidth, block IP, geolocate, OSINT (AbuseIPDB, GreyNoise, Onyphe, Pulsedive), port scan, kill owning process | Partial (interfaces + TCP) | everything except inventory |
| Services | "Smart services threat scanner" with risk scoring, filter, show clean | Partial (inventory only) | risk scoring |
| Timeline | load events, **detect attacks**, export HTML, quick filters, detail | Partial: `InvestigationTimelinePage` exists but only opens from Alerts, and the `timeline` route is still a placeholder | standalone route, attack detection, HTML export |
| Ransomware | monitoring toggle, protected directories, event log, file rollback, canaries | None | all |
| Memory | auto-monitor, injection events | None | all |
| Forensic(s) | collect evidence, generate report, FBI IC3 link | None | all |
| Hunt | target modes, run/stop, findings, actions | None | all |
| Sandbox | browse, timeout, block network, capture registry, detonate, static-only, report | None | all (detonation needs strong design review) |
| AEGIS | five active defence layers, live event log, **phishing text analyzer** | None | all; the phishing analyzer is a safe, pure-text first port |
| CIS | red teamer, threat evolution predictor, semantic integrity verifier, stats | None | all |
| DNS | DNS security center, cache watch / DGA, email SPF/DMARC/DKIM tool | None | all |
| Firewall | rule manager (filter, toggle, delete, copy), **blocked connections from Event 5157** | None | all; the 5157 read-only view is easy |
| Wi-Fi | current connection, network scan, security analysis | None | all |
| USB | device scan, history, whitelist add/remove/save, block, alert log, monitor loop | None | all |
| IoT | discovery, device details, botnet indicators (Mozi/Kimwolf) | None | all |
| Remote Access | exposure scan, action log | None | all |
| VPN | server list (protocol/country/speed filters), connect fastest, **kill switch**, import .ovpn, public IP, connectivity test | None | all |
| Parental | enable, screen time, web filtering, activity log | None | all |
| Emergency | **full emergency lockdown** (panic), individual actions, log | None | all |
| Cleanup | cache/temp, duplicates, large files, empty folders, startup items, disk usage, security cleanup, all previewed | None | all |
| Settings | general, **OSINT API keys**, rain intensity, **Revert All Changes**, TPM/BitLocker bypass toggle, thread workers, **SMTP email alerts**, **sound alarm**, **USB control**, Zero Trust score, DNS canary token, dark-web leak check, Pwned-password check, IR evidence collection | Partial (visual preferences only) | all security settings and tools |

## 3. Non-screen v29 features with no route or task

These are not represented in `capabilities.json` or `WORK_QUEUE.json`:

- **System tray icon** (minimize/restore/toggle) and **toast notifications**.
- **Email alerts (SMTP)** and **sound alarm** on critical alerts.
- **Floating widget** and **rain overlay window** (desktop overlays).
- **XInput gamepad controller** support and **gaming protection monitor** (`gaming_protection_monitor.py`).
- **Adaptive load loop** (resource throttling) and **heartbeat / tamper pill** (self-protection status).
- **Scheduled jobs:** feed update, feed health check, NSA hardening check, intel auto loop, re-analysis of scan threats, rootkit scan loop, DNS monitor loop, USB monitor loop, Wi-Fi refresh, network bandwidth loop.
- **Learning and suppression:** `ThreatLearningEngine` with background model training, `FalsePositiveDB` / `fp_suppression.py`, `KnownThreats`.
- **Detector classes inside main:** `RootkitDetector`, `BootkitDetector`, `PortScanDetector`, `AdvancedPersistentThreatDetector`, `AIEnhancedThreatDetector`, `IntelligentThreatDetector`, `SecurityAuditor`.
- **AEGIS subsystems:** `AegisVault`, `AegisMemoryDefense`, `AegisAntiDebug`, `AegisTorRouter`, `AegisWFPBlocker`, `AegisPhysicalShield`, `AegisTCPStackGuard`, `AegisIngestionEngine`, `AegisNLPPhishingEngine`.
- **History database** (`Database` class) and `forensic_report.py`.
- **OSINT integrations:** VirusTotal, AbuseIPDB, GreyNoise, Shodan, OTX, urlscan, Hybrid-Analysis, HIBP, Onyphe, Pulsedive.

## 4. Inventory corrections (`source-modules.json`)

### 4a. Wired in v29 but missing from the inventory (42)

Reachable from `downpour_v29_titanium.py` directly or through `sensor_hub` / `advanced_defense_suite`:

`advanced_defense_suite` (180 KB), `amsi_bypass_detector`, `anti_forensics_detector`, `beacon_detector`, `bluetooth_security_monitor`, `browser_security_monitor`, `cisa_kev`, `clipboard_monitor`, `code_integrity`, `cognitive_immune_system` (77 KB), `credential_guard_monitor`, `data_exfiltration_monitor`, `dll_hijack_detector`, `downpour_cleanup_module` (81 KB), `downpour_updater`, `dpapi_monitor`, `entropy_ransomware_detector`, `exploit_db`, `feed_transport`, `firewall_tamper_detector`, `forensic_report`, `fp_suppression`, `gaming_protection_monitor`, `keystroke_injection_detector`, `kev_checker`, `lateral_movement_detector`, `named_pipe_monitor`, `native_probes` (60 KB), `network_share_monitor`, `process_injection_detector`, `process_mitigation`, `quarantine_core` (40 KB), `scheduled_task_monitor`, `sensor_hub`, `shadow_copy_detector`, `shadow_copy_monitor`, `tls_certificate_monitor`, `trust_check`, `wifi_security_intelligence`, `wmi_persistence_detector`, `yara_rules_manager`, plus `etw_monitor` (loaded through `amsi_integration`).

Also untracked: directories `ultimate_threat_intel/`, `models/`, `yara_rules/` (34 files) and `sigma_rules/` (20 files).

### 4b. Listed as "Active / planned" but unreachable in v29

These have no import path from main. Before porting them, confirm the behavior is really wanted. Otherwise mark them `orphaned`:

`advanced_threat_engine`, `advanced_threat_analyzer`, `threat_detection_engine`, `ai_security_engine`, `ml_behavioral_analyzer`, `ml_optimization_engine`, `behavioral_analyzer`, `advanced_hardware_monitor`, `hardware_monitor_enhanced`, `enhanced_hardware_integration`, `enhanced_security_dashboard`, `enhanced_ui_components`, `device_adaptation_engine`, `backup_verifier`, `ioc_scanner` (only named in a docstring), `email_security` (main uses its own `_dns_adv_email_security`), `defender_enhancer`, `gpu_detector_fix`, `adaptive_security_bypass`.

Also unreachable and untracked, so a review should decide on each: `ad_attack_detector`, `boot_integrity_monitor`, `com_hijack_detector`, `dark_web_intel`, `dns_security_monitor`, `history_manager`, `intel_cache`, `print_spooler_monitor`, `privilege_escalation_detector`, `ransomware_canary`, `system_cleanup`, `token_manipulation_detector`.

### 4c. Doc errors in `FEATURE_PARITY.md`

- `advanced_gauge_system.py` is listed twice in the orphaned row.
- It reports 12 in-progress and 23 planned routes. `capabilities.json` has 38 routes: 13 in-progress, 24 planned, and 1 prototype.

## 5. Process and repository issues

1. **Uncommitted work at risk.** 36 untracked and about 30 modified files are not committed or pushed. They include the Sigma engine, Sysmon, AMSI, quarantine manager, NVD, URLhaus/Abuse.ch, driver packages, the action broker and 6 test files. GitHub `main` (`578f188`, 2026-10-04) does not contain them.
2. **`AGENT_REGISTRY.json` is invalid JSON.** It has duplicated trailing `] }` blocks starting at line 95. Tooling that parses it will fail.
3. **DN-009 is marked `completed`** although its title is "Port AEGIS, forensics, parental controls, cleanup, VPN, remote, and remaining routes". Only the module inventory was done. Reopen it or split it.
4. **"0 warnings" claims are stale.** The current Debug build has 7 warnings: CS8625/CS8603/CS8604 nullability, and SYSLIB0057 obsolete `X509Certificate2(string)` in `DriverPackageInventoryProvider.cs:188`.
5. **v29 Sigma rule files are not loaded.** `SigmaEngine.LoadFromYamlFiles` exists but has no callers.
6. **Policy wording.** AGENTS.md says "private repository". SHARED_CONTEXT says the repo is public by user authorization. Reconcile the wording.

The safety posture is correct: `QuarantineManager` and `DriverPackageBroker` both return `RejectedNotImplemented`, and no system-changing calls were found.

## 6. Suggested next tasks (in order)

1. Commit and push the current working tree in focused commits. Fix `AGENT_REGISTRY.json`.
2. Update `source-modules.json` with sections 4a and 4b. Add routes or tasks for section 3 (tray/notifications, alert channels, scheduled jobs, FP database).
3. Read-only quick wins that reuse existing infrastructure:
   - Firewall 5157 blocked-connection view
   - `firmware_posture` hardening checks
   - USB device history (registry)
   - Wi-Fi posture (WLAN API)
   - DNS cache with DGA scoring
   - scheduled-task, WMI and Run-key persistence views
   - load the `sigma_rules/` YAML files
   - AEGIS phishing text analyzer
   - standalone Timeline route
4. Threat/Possible-Threats/Remediation workflow on top of the alert repository and journal. This needs the false-positive store and indicator lookups with user-supplied OSINT API keys.
5. Only after the action broker security review: kill, quarantine, block IP, firewall rule edits, USB block, revert-all, lockdown. Each needs denial, audit, timeout and rollback tests.
