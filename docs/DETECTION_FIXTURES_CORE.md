# Detection Fixtures & Thresholds: Core Detection Engines

These constants and scoring thresholds are extracted from Downpour v29 detection modules to ensure Downpour Next ports reproduce identical detection behavior and telemetry verdicts.

---

## 1. C2 Beacon Detector (`c2_beacon_detector.py`)

- **Timing Analysis (Coefficient of Variation / CV):**
  - `CV_THRESHOLD_LOW = 0.05`: Extremely regular interval (high beacon probability).
  - `CV_THRESHOLD_MEDIUM = 0.25`: Regular with jitter (typical beacon configuration).
  - `CV_THRESHOLD_HIGH = 0.50`: Irregular (likely legitimate human/software traffic).
  - `MIN_INTERVAL_SECONDS = 5.0`: Minimum connection interval considered.
  - `MIN_CONNECTIONS = 5`: Minimum observed connection events to compute jitter/CV.
- **DGA Analysis Thresholds:**
  - `DGA_ENTROPY_THRESHOLD = 3.5`: Shannon entropy threshold for suspicious domain names.
  - `DGA_LENGTH_THRESHOLD = 15`: Minimum domain label length for DGA heuristic evaluation.
  - Confidence calculation: `confidence = min(1.0, (entropy - DGA_ENTROPY_THRESHOLD) / 2.0)`
- **Reverse Shell Signatures:**
  - Command lines matching: `cmd.exe /c`, `powershell -nop -w hidden -e`, `nc.exe -e`, `bash -i >& /dev/tcp/`.

---

## 2. DGA Detector (`dga_detector.py`)

- **Shannon Entropy:**
  - Calculated over the primary domain label (excluding common TLDs: `.com`, `.org`, `.net`, `.edu`, `.gov`, `.co.uk`).
  - Score >= `3.8`: Flagged as high entropy.
- **Linguistic Metrics:**
  - `consonant_ratio`: Consonants / total alphabetical chars. Values > `0.75` or < `0.20` indicate non-natural language.
  - `consonant_run`: Max consecutive consonants > `4` flags anomaly.
  - `digit_ratio`: Digits / total domain length. Values > `0.25` flag anomaly.
  - `bigram_score`: English letter transition frequency lookup. Below `0.015` indicates random generation.
- **Verdict Threshold:**
  - `is_dga = True` when combined `confidence >= 0.70`.
  - Severity mapping: `confidence >= 0.85` → `HIGH`, `0.70 <= confidence < 0.85` → `MEDIUM`.

---

## 3. LOLBins Detector (`lolbins_detector.py`)

- **Tracked Binaries & MITRE Techniques:**
  - `certutil.exe`: `-urlcache`, `-split`, `-decode` (T1105 Ingress Tool Transfer / T1140 Deobfuscate).
  - `bitsadmin.exe`: `/transfer`, `/create`, `/addfile` (T1197 BITS Jobs).
  - `mshta.exe`: `vbscript:`, `javascript:`, `http://`, `https://` (T1218.005 Mshta).
  - `regsvr32.exe`: `/s`, `/u`, `/i:`, `scrobj.dll` (T1218.010 Regsvr32 / Squiblydoo).
  - `rundll32.exe`: `javascript:`, `url.dll`, `OpenURL` (T1218.011 Rundll32).
  - `wmic.exe`: `process call create`, `/node:` (T1047 WMI).
  - `powershell.exe` / `pwsh.exe`: `-enc`, `-encodedcommand`, `-w hidden`, `-ep bypass`, `downloadstring`, `iex` (T1059.001 PowerShell).
  - `cmd.exe`: `/c echo ... | certutil`, `& start` chains (T1059.003 Windows Command Shell).
  - `cscript.exe` / `wscript.exe`: executing from `\AppData\`, `\Temp\` (T1059.005 Visual Basic / JScript).
  - `msbuild.exe`: executing inline XML project files (T1127.001 MSBuild).
  - `installutil.exe`: uninstall method bypass (T1218.004 InstallUtil).
- **Correlation:** Parent-child validation flags office applications (`winword.exe`, `excel.exe`) spawning any LOLBin as `CRITICAL`.

---

## 4. Ransomware & Entropy Detectors (`ransomware_detector.py`, `entropy_ransomware_detector.py`)

- **Entropy Thresholds:**
  - `ENTROPY_THRESHOLD_HIGH = 7.5`: Near 8.0 indicates high-entropy encrypted ciphertext or packed payloads.
  - `ENTROPY_THRESHOLD_LOW = 3.0`: Baseline structured text.
  - `ENTROPY_DELTA_THRESHOLD = 2.0`: Sudden jump in file entropy between writes.
- **Activity Bursts:**
  - File modification burst: `> 20` file modifications in a `10-second` window across monitored user directories (`Documents`, `Desktop`, `Pictures`).
- **Canary & Honeytoken Files:**
  - Deployed in `%USERPROFILE%\Documents` and `%LOCALAPPDATA%` with unique tracking hashes.
  - Any write or delete event immediately generates a `CRITICAL` alert and initiates containment checks.
- **Shadow Copy & VSS Invocations:**
  - Command line triggers: `vssadmin delete shadows`, `wmic shadowcopy delete`, `wbadmin delete catalog`, `bdehdcfg -target`.

---

## 5. Botnet Detection (`kimwolf_botnet_detector.py`)

- **C2 & Threat IOCs:**
  - 150+ explicit network indicators (IP addresses and dynamic DNS domains).
  - Mirai / Mozi / Kimwolf known ports: `5555` (ADB/Kimwolf), `23` / `2323` (Telnet brute force), `7547` (TR-069 exploit), `37215` (Huawei UPnP), `52869` (Realtek SDK).
  - High-risk OUIs: Known vulnerable IoT vendor MAC prefixes.
- **Detection Logic:**
  - High-frequency SYN scans to destination ports on local subnets.
  - TCP handshake completion without application data exchange.

---

## 6. AMSI & Script-Block Analysis (`amsi_integration.py`, `sigma_engine.py`)

- **AMSI Return Codes:**
  - `AMSI_RESULT_CLEAN = 0`
  - `AMSI_RESULT_NOT_DETECTED = 1`
  - `AMSI_RESULT_BLOCKED_BY_ADMIN = 16384`
  - `AMSI_RESULT_DETECTED = 32768` (Threshold >= 32768 is malicious).
- **PowerShell Event IDs:**
  - `Event ID 4104`: Script block logging (evaluated by Sigma & AMSI).
  - `Event ID 4103`: Module logging.
- **Script Block Regex Patterns (22 patterns):**
  - AMSI patch bypasses: `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')`, `amsiInitFailed`.
  - Download cradles: `(New-Object System.Net.WebClient).DownloadString`, `Invoke-WebRequest -Uri ... | IEX`.
  - Obfuscation: Backtick sequences, large base64 strings with string formatting tokens.

---

## 7. Static PE Analyzer (`pe_analyzer.py`)

- **Section Entropy:**
  - Any section entropy `> 7.2` flags packed or encrypted code.
  - Standard section names checked: `.text`, `.data`, `.rdata`, `.rsrc`.
  - Suspicious section names: `.upx0`, `.upx1`, `.aspack`, `.themida`, `.vmp0`, `.enigma`.
- **Import Clustering Risk Scoring (0–100):**
  - Low (< 40): Standard system imports.
  - Medium (40–70): Process memory access or network APIs.
  - High (> 70): Process injection (`VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread`), keylogging (`SetWindowsHookEx`), or privilege manipulation (`AdjustTokenPrivileges`).
