# Build and run Downpour Next on Windows

The portable x64 bundle contains the WinUI desktop app (`Downpour.Desktop.exe`), the read-only telemetry service, and both `Start-Downpour-Next.bat` and `Start-Downpour-Next.cmd` launchers. It does not require GitHub Actions or a .NET runtime on the target machine. It is not an installer and does not register a Windows service. Extract the full ZIP and launch either BAT/CMD launcher or the desktop EXE; the desktop starts the bundled sensor service automatically when needed.

## Build locally

From the repository root in PowerShell with the .NET 10 SDK and Windows App SDK restore access:

```powershell
dotnet restore Downpour.slnx
dotnet build Downpour.slnx -c Release
dotnet test Downpour.slnx -c Release
dotnet publish src/Downpour.Desktop/Downpour.Desktop.csproj -c Release -r win-x64 -p:WindowsPackageType=None -p:WindowsAppSDKSelfContained=true -p:SelfContained=true -p:PublishTrimmed=false -o artifacts/DownpourNext-win-x64
dotnet publish src/Downpour.Service/Downpour.Service.csproj -c Release -r win-x64 --self-contained true -o artifacts/DownpourNext-win-x64/service
Copy-Item Start-Downpour-Next.cmd artifacts/DownpourNext-win-x64/
Copy-Item Start-Downpour-Next.bat artifacts/DownpourNext-win-x64/
```

Trimming is disabled until the WinUI reflection and JSON paths have source-generated metadata and the Windows App SDK trim warnings have been resolved.

The UI/Core JSON path uses pinned Newtonsoft.Json 13.0.4, with JSON type-name handling disabled and local/IPC parsing bounded. During the first self-contained launch check, the System.Text.Json-based UI build exited in WinRT's generated `GlobalVtableLookup` with a `ComInterfaceEntry` `TypeLoadException`. After changing the UI/Core JSON path and rebuilding, the portable EXE remained running. This is a validated workaround in this environment; it is not a confirmed root-cause analysis for every Windows SDK/runtime combination.

## Run the portable build

Extract the full `DownpourNext-win-x64.zip`, then double-click `Start-Downpour-Next.bat`, `Start-Downpour-Next.cmd`, or `Downpour.Desktop.exe`. The BAT launcher starts the desktop directly; it auto-starts the bundled `service\Downpour.Service.exe` when needed. The CMD launcher starts the service first, then launches the desktop. A source-build started with `dotnet run` still requires starting `Downpour.Service` separately from the development instructions above.

The Settings route now attaches toggle handlers after its XAML controls are initialized, avoiding early toggle events during page construction. Build/test and desktop startup are verified; an interactive click-through of the Settings route remains to be checked on the target desktop session.

The bundle is x64 and unsigned at this stage. It is intended for local testing from a trusted source. A signed MSIX/installer, Windows service installation/upgrade/rollback, and release signing identity have not been implemented; do not treat this portable bundle as a production security product.

## Current local package

The latest verified package is built into `DownpourNext-Portable/` at the repository root, so `Downpour.Desktop.exe`, `service/Downpour.Service.exe`, and both launchers are available together locally. The matching downloadable archive is `DownpourNext-win-x64-5427953.zip`, built from source commit `5427953`. SHA-256: `A354894D66DA335DE205CE86F37407D538D7DB133AF3AED5D604F558FEC50A5A`. The same archive is attached to the GitHub release `v0.1.4`.
