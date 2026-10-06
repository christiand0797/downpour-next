# Detection Fixtures & Thresholds: Detection Monitors

> **Accuracy note (2026-10-06):** These are hand-written summaries. Named constants were cross-checked against the v29 source; prose values were not. Where this file disagrees with the generated [`V29_DETECTION_THRESHOLDS.md`](V29_DETECTION_THRESHOLDS.md), the generated file is authoritative. Known prose error: `dga_detector.py` consonant threshold is `0.6` (`__init__` default), not 0.75/0.20.


These constants, API flags, and pattern definitions are extracted from Downpour v29 detection monitors to guide native C# implementations.

---

## 1. Process Injection Detector (`process_injection_detector.py`)

- **Windows API Access Masks & Memory Flags:**
  - `PROCESS_VM_READ = 0x0010`
  - `PROCESS_VM_WRITE = 0x0020`
  - `PROCESS_VM_OPERATION = 0x0008`
  - `PROCESS_SUSPEND_RESUME = 0x0800`
  - `THREAD_SET_CONTEXT = 0x0010`
  - `PAGE_EXECUTE_READWRITE = 0x40` (W^X violation / shellcode buffer allocation)
  - `PAGE_EXECUTE_READ = 0x20`
  - `MEM_COMMIT = 0x1000`
- **Injection Classifications:**
  - `PROCESS_HOLLOWING`: `VirtualAllocEx` with `PAGE_EXECUTE_READWRITE` + unmapping original image + entry point redirect via `SetThreadContext`.
  - `THREAD_HIJACKING`: Suspended target thread + context pointer rewrite to allocated memory.
  - `REFLECTIVE_DLL`: Manual PE header parsing and section relocation without `LoadLibrary`.
  - `APC_INJECTION`: `QueueUserAPC` targeting alerting thread in target process.
- **Risk Thresholds:**
  - An unbacked executable memory region (`MEM_COMMIT` with execute permission not mapped to a disk image) raises risk score by `+60`.
  - Presence of PE header (`MZ` magic bytes `0x4D 0x5A`) in private memory raises risk score by `+80`.
  - Overall risk score `>= 70` triggers `HIGH` injection alert.

---

## 2. WMI Persistence Detector (`wmi_persistence_detector.py`)

- **WMI Classes Monitored:**
  - `root\subscription:__EventFilter`
  - `root\subscription:__EventConsumer` (`CommandLineEventConsumer`, `ActiveScriptEventConsumer`)
  - `root\subscription:__FilterToConsumerBinding`
- **Legitimate Filter Allow-List:**
  - `BVTFilter`, `SCM Event Log Filter`, `__InstanceCreationEvent`
- **Suspicious Consumer Indicators:**
  - Consumer executing script text directly (`ScriptText` property populated).
  - Executable path outside `%SystemRoot%\System32` or targeting LOLBins (`powershell.exe`, `wscript.exe`, `mshta.exe`).
  - Consumer name matches GUID or random hex pattern (`^[a-f0-9]{32}$`, `^[a-f0-9]{8}-`).
- **Sysmon Event IDs for WMI:**
  - `Event ID 19`: WmiEvent (WmiEventFilter activity detected).
  - `Event ID 20`: WmiEvent (WmiEventConsumer activity detected).
  - `Event ID 21`: WmiEvent (WmiEventConsumerToFilter activity detected).

---

## 3. Scheduled Task Monitor (`scheduled_task_monitor.py`)

- **Event Log Channel & IDs:**
  - Channel: `Microsoft-Windows-TaskScheduler/Operational`
  - `Event ID 106`: Task registered / created.
  - `Event ID 140`: Task updated.
  - `Event ID 141`: Task deleted.
  - `Event ID 200`: Action started.
- **Suspicious Task Heuristics:**
  - Task action points to temporary directories: `%TEMP%`, `%APPDATA%`, `C:\Users\Public\`.
  - Task configured with hidden attribute (`<Hidden>true</Hidden>`).
  - Trigger configured with high frequency (`PT1M` to `PT5M` repeat interval) or on workstation unlock / logon.
  - Registry task entry in `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree` lacking a corresponding `SD` (security descriptor) value.

---

## 4. DLL Search Order Hijack Detector (`dll_hijack_detector.py`)

- **Vulnerable Targets & Known Hijack Vectors:**
  - High-privilege processes running from writable directories.
  - Target DLLs searched in application directory before `System32`: `version.dll`, `dbghelp.dll`, `uxtheme.dll`, `dwmapi.dll`, `cryptbase.dll`.
- **Heuristic Rule:**
  - Any known system DLL residing in application root or user-writable path is flagged as `HIGH` severity search order hijack candidate.

---

## 5. AMSI Bypass & Defender Tampering (`amsi_bypass_detector.py`)

- **Memory Patch Byte Signatures:**
  - `AmsiScanBuffer` return 1 patch: `\xB8\x57\x00\x07\x80\xC3` (mov eax, 0x80070057; ret).
  - `AmsiInitialize` null context patch: `\x31\xC0\xC3` (xor eax, eax; ret).
- **Defender Tampering Registry Keys:**
  - `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`: `DisableAntiSpyware = 1`, `DisableRealtimeMonitoring = 1`.
  - `HKLM\SOFTWARE\Microsoft\Windows Defender\Features`: `TamperProtection = 0`.
  - Severity: `CRITICAL` alert with immediate notification.

---

## 6. Clipboard & Input Monitors (`clipboard_monitor.py`, `keystroke_injection_detector.py`)

- **Cryptocurrency Hijacking Regex Patterns:**
  - Bitcoin: `\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b`
  - Ethereum: `\b0x[a-fA-F0-9]{40}\b`
  - Monero: `\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b`
- **Keystroke Injection (BadUSB):**
  - Typing speed threshold: `> 800 characters per minute` sustained over 3 seconds.
  - Device identification: Newly connected USB HID keyboard lacking vendor WHQL certification.

---

## 7. Firewall Tamper Detector (`firewall_tamper_detector.py`)

- **Security Event Log IDs:**
  - `Event ID 5157`: Windows Filtering Platform blocked a connection (read-only audit).
  - `Event ID 4950`: Windows Firewall setting was changed.
  - `Event ID 4946` / `4947`: Rule added / modified.
  - `Event ID 4948`: Rule deleted.
- **Suspicious Port Allow Rules:**
  - New inbound rule allowing ports: `4444`, `1337`, `31337`, `6667`, `5552`.
