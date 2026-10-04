# Downpour Next

## Download a test build

Download the latest **Downpour Next portable preview** from [GitHub Releases](https://github.com/christiand0797/downpour-next/releases). Extract the full ZIP, then double-click `Start-Downpour-Next.cmd` or `Downpour.Desktop.exe`. The desktop automatically starts the bundled read-only sensor service when needed and stops the child service when the app closes. If the service is missing or cannot start, the app remains usable and labels sensor telemetry as offline with a reason. This unsigned preview is for local testing and is not an installer. See [`docs/BUILD_WINDOWS.md`](docs/BUILD_WINDOWS.md) for requirements and limitations.

Downpour Next is the native Windows rebuild of Downpour. The target is complete feature parity with the current Python application, plus a more capable desktop experience. The implementation is deliberately staged: a visible route is not counted as a port until its sensors, analysis, settings, and response behavior are connected and verified.

## Current state

- Native WinUI 3 desktop shell with a dark, rain-and-crescent identity.
- One registry preserves all 33 Downpour destinations and adds a dedicated Drivers route; every route has an honest migration state.
- The app uses a clear moonless night landscape, a separate realistic crescent overlay, twinkling stars, animated rain, aurora, and occasional upper-sky lightning. The Dashboard cycles drizzle, storm, thunderstorm, and hurricane modes; every mode keeps rain active, scales its speed/visibility, and changes wind/lightning behavior.
- Dashboard, Processes, Drivers, and Network consume live read-only system/process, loaded-kernel-driver, adapter-throughput, and TCP endpoint data from the service. Network history shows gaps when samples are unavailable.
- Windows service uses a restricted, outbound-only local named pipe and performs no system-changing actions.
- No original detection, scanning, remediation, or hardening engine has been ported yet.

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
- `src/Downpour.Service`: Windows service host for future sensors and policy-controlled response.
- `src/Downpour.Core`: shared application logic and capability registry validation.
- `src/Downpour.Contracts`: typed records shared across process boundaries.
- `capabilities.json`: feature parity inventory mapped to the original source methods.
- `source-modules.json`: all 71 entries in the original module map, including active, legacy, reference, orphaned, and declined dispositions.
- `docs/ARCHITECTURE_AND_MIGRATION.md`: detailed target architecture and staged parity plan.
- `docs/FEATURE_PARITY.md`: staged migration order and completion criteria.

The service and UI will communicate through versioned, typed contracts with least-privilege authorization. The UI must remain responsive when sensors are unavailable, and every privileged response action will require clear policy, audit logging, and a safe failure path.

## Feature parity rule

Do not mark a route `implemented` just because its screen exists. A port must include equivalent core behavior, a working data path, understandable error states, and coverage for the relevant workflows. Preserve the original feature set first; add new capabilities only after their safety and maintenance costs are understood.
