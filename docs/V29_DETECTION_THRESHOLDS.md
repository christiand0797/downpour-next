# v29 Detection Thresholds and Constants

**Generated:** 2026-10-06 (handoff section 2, step 3)
**Purpose:** Document detection thresholds, IOC lists, and event IDs used by v29 modules so Downpour Next ports can reproduce behavior.

## Firmware Posture (`firmware_posture.py`)

Checks performed (all read-only):
- BitLocker status: `manage-bde -status`
- Secure Boot: `Confirm-SecureBootUEFI` or registry `HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State`
- TPM: `Get-TPM` or registry `HKLM\SYSTEM\CurrentControlSet\Control\TPM`
- LSA Protection (LSA-PPL): registry `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL`
- Credential Guard: registry `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity`
- VBS/HVCI: registry `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity\Enabled`
- SMBv1: `Get-SmbServerConfiguration -EnableSMB1Protocol` or registry `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1`
- Patch level: Windows version and build number

No scoring thresholds - returns OK/FAILED/UNKNOWN per check.

## DGA Detector (`dga_detector.py`)

Thresholds:
- Entropy threshold: 3.5 (Shannon entropy)
- N-gram score threshold: 0.7 (Markov chain n-gram model)
- Length threshold: 15 characters minimum

## DNS Cache Watch (`dns_cache_watch.py`)

Thresholds:
- DGA score threshold: 0.75 (uses dga_detector)
- TOFU (Trust On First Use) baseline: first 5 minutes of monitoring
- Cache enumeration interval: 30 seconds

## C2 Beacon Detector (`c2_beacon_detector.py`)

Thresholds:
- Jitter threshold: CV < 0.3 (low jitter = suspicious regularity)
- Check-in interval: < 60 seconds or > 43200 seconds (12 hours) is suspicious
- Data ratio: bytes sent / bytes received > 10:1 is suspicious (exfiltration pattern)

## Hardening Checks (`system_hardening.py`)

Thresholds:
- NSA STIG compliance score: 0-100 (pass = 80+)
- Missing updates count: > 5 is WARNING, > 20 is CRITICAL
- Service configuration: non-standard startup types on critical services

## Process Monitor (`process_monitor.py`)

Thresholds:
- CPU percent: > 90% for > 60 seconds is suspicious
- Memory growth: > 100 MB increase in 60 seconds is suspicious
- Child process count: > 10 children in 60 seconds is suspicious

## Network Monitor (`network_monitor.py`)

Thresholds:
- Connection count: > 500 outbound connections is suspicious
- Port scan detection: > 20 ports to same host in 30 seconds
- DNS query rate: > 100 queries in 60 seconds

## Sigma Engine (`sigma_engine.py`)

Supported logsources:
- `process_creation`: Image, CommandLine, ParentImage, User
- `ps_script`: ScriptBlockText (PowerShell 4104)

Supported modifiers:
- `contains`, `startswith`, `endswith`, `re`
- `and`, `or`, `not`
- `1 of selection*`, `all of them`
- `contains|windash` (dash-prefixed word boundary)

Unsupported (skipped):
- Aggregation, correlation, near, timeframe

## YARA Engine (`yara_x_engine.py`)

Rules directory: `yara_rules/` (34 files)
Compile options: lenient (partial rule failures don't block load)
Scan timeout: 30 seconds per file

## AMSI Integration (`amsi_integration.py`)

Threat score thresholds:
- 0-49: Safe
- 50-74: Suspicious
- 75-100: Malicious

Pattern count: 22 patterns in script-block analyzer

## Sysmon Monitor (`sysmon_monitor.py`)

Monitored events:
- Process creation (1)
- Network connection (3)
- File create (11)
- Registry value set (13)
- Process creation (command line) (1 with CommandLine)
- DNS query (22)

## Firewall Tamper Detector (`firewall_tamper_detector.py`)

Thresholds:
- Rule count delta: > 10 rules removed/added in 60 seconds is suspicious
- Profile state change: Public/Private/Domain switching is alert

## USB Protection (`usb_protection.py`)

Thresholds:
- Device insertion rate: > 5 devices in 60 seconds is suspicious
- History retention: 90 days in registry `HKLM\SYSTEM\CurrentControlSet\Enum\USB`

## Persistence Watchers (`persistence_watchers.py`)

Baseline retention: 30 days
Alert on:
- New Run/RunOnce registry entries
- New scheduled tasks
- New WMI event subscriptions
- New service installations
- DLL hijack shadows in system directories

## LOLBins Detector (`lolbins_detector.py`)

Monitored binaries: ~80 Living Off The Land binaries
Alert patterns:
- Unusual parent-child relationships
- Execution from non-standard paths
- Command-line arguments matching MITRE techniques

## Notes for Downpour Next

- All thresholds should be configurable via settings
- Consider adaptive thresholds based on system baseline
- Log when thresholds are triggered (for tuning)
- Unknown states should be distinct from failures
- Keep all detection read-only until DN-008 security review
