# Downpour Next

## Download a test build

Download the latest [Downpour Next Windows x64 portable release](https://github.com/christiand0797/downpour-next/releases/latest). Extract the full ZIP, then double-click `Start-Downpour-Next.bat`, `Start-Downpour-Next.cmd`, or `Downpour.Desktop.exe`. The `.bat` launcher runs the desktop EXE directly; the desktop automatically starts the bundled sensor service when needed and stops the child service when the app closes. The dashboard's **Update Downpour** button checks for a newer stable release and stages it for an automatic restart. v0.1.12 adds a separate update helper; v0.1.10 and v0.1.11 users must manually extract v0.1.12 once before in-app updates can complete. If the service is missing or cannot start, the app remains usable and labels sensor telemetry as offline with a reason. This unsigned build is not an installer; updater trust limitations are documented in [`docs/UPDATES.md`](docs/UPDATES.md). See [`docs/BUILD_WINDOWS.md`](docs/BUILD_WINDOWS.md) for requirements.

Downpour Next is the native Windows rebuild of Downpour. The target is complete feature parity with the current Python application, plus a more capable desktop experience. The implementation is deliberately staged: a visible route is not counted as a port until its sensors, analysis, settings, and response behavior are connected and verified.

## Current state

- Native WinUI 3 desktop shell with a dark, rain-and-crescent identity.
- One registry preserves all 33 Downpour destinations and adds a dedicated Drivers route; every route has an honest migration state.
- The app uses a clear moonless night landscape, a separate realistic crescent overlay, twinkling stars, animated rain, aurora, and occasional upper-sky lightning. The Dashboard cycles drizzle, storm, thunderstorm, and hurricane modes; every mode keeps rain active, scales its speed/visibility, and changes wind/lightning behavior.
- Dashboard, Processes, Drivers, and Network consume live read-only system/process, loaded-kernel-driver, adapter-throughput, and TCP endpoint data from the service. Network history shows gaps when samples are unavailable.
- Services and Security Events show bounded local read-only Windows service inventory and allow-listed event metadata. Alerts now persist unique event-ID findings and support local acknowledge/suppress/reopen triage; this changes review state only and performs no system-changing action.
- Vulnerabilities reads local uninstall-key display metadata and compares software names conservatively with CISA KEV. Rows are candidate leads only; the feature does not confirm affected versions or vulnerability status. See [`docs/THREAT_INTELLIGENCE.md`](docs/THREAT_INTELLIGENCE.md).
- File Inspector selects one local EXE/DLL/SYS, computes SHA-256, and reads bounded PE header metadata without executing or uploading the file. It does not detect malware or verify Authenticode trust. See [`docs/FILE_INSPECTOR.md`](docs/FILE_INSPECTOR.md).
- Sigma/AMSI analyze bounded PowerShell content under an explicit sensor setting; Sysmon metadata-only review events reach persisted alerts with visible source failures. Selected-file YARA-X scans run in an isolated helper; posture/investigation routes provide partial v29 coverage.
- Separate typed action brokers support confirmed quarantine/restore, process termination, temporary IP firewall rules and reversible USB controls, with policy, caller/consent checks and audit records. Windows permissions still apply; automatic admin elevation and host isolation remain unfinished.
- CIS now shows measured alert/source review and an explicit bounded package-file consistency check, replacing scripted protection models. Its unsigned local manifest is not publisher authentication. See [`docs/CIS.md`](docs/CIS.md).
- All 38 committed routes remain partial. Full operational AEGIS/CIS, driver lifecycle execution, broader response, installer/signing and complete native acceptance remain unfinished; see [`docs/CONTINUATION_AUDIT.md`](docs/CONTINUATION_AUDIT.md).

## Build

Requirements: Windows 10 version 2004 (build 19041) or newer, .NET 10 SDK, and the Windows App SDK 2.5.1 NuGet package. Open `Downpour.slnx` in Visual Studio with the WinUI workload, or use the .NET CLI. See [`docs/BUILD_WINDOWS.md`](docs/BUILD_WINDOWS.md) for the self-contained local Windows x64 build and portable launch steps. A signed installer is not available yet.

```powershell
dotnet restore Downpour.slnx
dotnet build Downpour.slnx -c Debug
dotnet run --project src/Downpour.Service/Downpour.Service.csproj
# In a second terminal:
dotnet run --project src/Downpour.Desktop/Downpour.Desktop.csproj
```

## Architecture

- `src/Downpour.Desktop`: WinUI 3 presentation, navigation, and dashboard.
- `src/Downpour.Service`: Windows API adapters, bounded sensors, persisted alerts/settings and typed consent/audit response brokers. Portable mode runs as the current user; no Windows service is installed.
- `src/Downpour.Core`: shared application logic and capability registry validation.
- `src/Downpour.Contracts`: typed records shared across process boundaries.
- `capabilities.json`: feature parity inventory mapped to the original source methods.
- `source-modules.json`: 129 reconciled module/content entries, including active, legacy, reference, orphaned, and declined dispositions.
- `docs/ARCHITECTURE_AND_MIGRATION.md`: detailed target architecture and staged parity plan.
- `docs/FEATURE_PARITY.md`: staged migration order and completion criteria.

The service and UI communicate through bounded, versioned contracts and current-user/SYSTEM-restricted pipes. The UI must remain responsive when sensors are unavailable. Every additional privileged action requires policy, auditable consent, denial, timeout and recovery acceptance before enablement. Signing, a separate installed-service identity and independent server authentication remain open.

## Feature parity rule

Do not mark a route `implemented` just because its screen exists. A port must include equivalent core behavior, a working data path, understandable error states, and coverage for the relevant workflows. Preserve the original feature set first; add new capabilities only after their safety and maintenance costs are understood.
