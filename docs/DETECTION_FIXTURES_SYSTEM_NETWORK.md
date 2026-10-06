# Detection Fixtures & Thresholds: System, Network & Posture

> **Accuracy note (2026-10-06):** These are hand-written summaries. Named constants were cross-checked against the v29 source; prose values were not. Where this file disagrees with the generated [`V29_DETECTION_THRESHOLDS.md`](V29_DETECTION_THRESHOLDS.md), the generated file is authoritative. Known prose error: `dga_detector.py` consonant threshold is `0.6` (`__init__` default), not 0.75/0.20.


These constants, posture checks, event mappings, and network signatures are extracted from Downpour v29.

---

## 1. Firmware & Hardware Posture (`firmware_posture.py`)

- **Checks & Evaluation Criteria:**
  - **BitLocker:** Query `Win32_EncryptableVolume` where `DriveLetter = 'C:'`. ProtectionStatus `1` = Protected, `0` = Unprotected (Report `MEDIUM` or `HIGH` warning if unencrypted).
  - **Secure Boot:** Registry `HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State`: `UEFISecureBootEnabled = 1`. If `0`, report `HIGH` posture failure.
  - **TPM:** Query `Win32_Tpm`. Check `IsActivated_InitialValue = True`, `IsEnabled_InitialValue = True`, and `SpecVersion` starts with `2.0`.
  - **LSA-PPL (RunAsPPL):** Registry `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`: `RunAsPPL` = `1` (or `2` for PPL with audit). If missing or `0`, report `MEDIUM` credential-theft exposure.
  - **Credential Guard:** Registry `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard`: `EnableVirtualizationBasedSecurity = 1` and `RequirePlatformSecurityFeatures = 1` or `3`.
  - **VBS / HVCI:** Registry `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity`: `Enabled = 1`.
  - **SMBv1 Disabled:** Registry `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`: `SMB1 = 0`. If `1` or missing on legacy platforms, report `HIGH` vulnerability risk.
- **State Distinctions:**
  - `Unknown`: WMI/registry inaccessible, privilege missing, or hardware unsupported. Must remain visibly distinct from `Failed`.

---

## 2. Sysmon Event Catalog & MITRE Mapping (`sysmon_monitor.py`)

- **Sysmon Event IDs (1–26):**
  - `1`: Process Create (`T1059`, `T1059.001`, `T1059.003`, `T1059.005`)
  - `2`: File creation time changed (`T1070.006` Timestomp)
  - `3`: Network connection detected (`T1071`, `T1043`)
  - `5`: Process terminated (`T1089`)
  - `6`: Driver loaded (`T1014`, `T1068`)
  - `7`: Image loaded / DLL load (`T1073`, `T1574.002`)
  - `8`: CreateRemoteThread detected (`T1055.002`)
  - `9`: RawAccessRead detected (`T1005`, `T1006`)
  - `10`: Process accessed (`T1003.001` LSASS memory read)
  - `11`: File created (`T1105`)
  - `12` / `13` / `14`: Registry object created / value set / deleted (`T1112`)
  - `15`: File stream created / ADS (`T1564.004`)
  - `16`: Sysmon config state changed (`T1562.001`)
  - `17` / `18`: Named pipe created / connected (`T1570`)
  - `19` / `20` / `21`: WMI EventFilter / EventConsumer / Binding (`T1546.003`)
  - `22`: DNS query (`T1071.004`)
  - `23` / `26`: File deleted / archived (`T1070.004`)
  - `24`: Clipboard change (`T1115`)
  - `25`: Process tampering / process hollowing (`T1055.012`)

---

## 3. DNS Cache Watch & TOFU Baseline (`dns_cache_watch.py`)

- **Scoring & Alert Thresholds:**
  - `_ALERT_THRESHOLD = 70`: Score >= 70 triggers `MEDIUM` alert for abnormal resolver entry.
  - `_HIGH_THRESHOLD = 85`: Score >= 85 triggers `HIGH` alert with MITRE `T1071.004`.
- **Baseline Behavior:**
  - Trust On First Use (TOFU): Initial baseline captures existing resolver cache entries.
  - Subsequent runs evaluate delta against cached baseline. Max baseline storage bounded to `10,000` domains.

---

## 4. Known RAT Ports & Network Heuristics (`KnownThreats`)

- **Dedicated RAT Port Mapping:**
  - `4444`: Metasploit default handler
  - `4445`: Meterpreter alternate port
  - `5552`: Beast RAT
  - `1337`: Common backdoor / exploit payload port
  - `31337`: Back Orifice default
  - `6667`: IRC botnet command channel
  - `8000`: DarkComet / njRAT common port
  - `9999`: Poison Ivy default
- **Network Port Scan Heuristic:**
  - Source IP initiating connections to `>= 15` distinct destination ports within a `5-second` rolling window triggers port scan alert.
