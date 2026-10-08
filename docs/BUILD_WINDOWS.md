# Build and run Downpour Next on Windows

The portable x64 bundle contains the WinUI desktop app (`Downpour.Desktop.exe`), the read-only telemetry service, and both `Start-Downpour-Next.bat` and `Start-Downpour-Next.cmd` launchers. It does not require GitHub Actions or a .NET runtime on the target machine. It is not an installer and does not register a Windows service. Extract the full ZIP and launch either BAT/CMD launcher or the desktop EXE; the desktop starts the bundled sensor service automatically when needed. The dashboard can check and stage the latest stable release; update limitations and trust assumptions are documented in [`UPDATES.md`](UPDATES.md).

## Build locally

From the repository root in PowerShell with the .NET 10 SDK and Windows App SDK restore access:

```powershell
dotnet restore Downpour.slnx
dotnet build Downpour.slnx -c Release
dotnet test Downpour.slnx -c Release
dotnet publish src/Downpour.Desktop/Downpour.Desktop.csproj -c Release -r win-x64 -p:WindowsPackageType=None -p:WindowsAppSDKSelfContained=true -p:SelfContained=true -p:PublishTrimmed=false -o artifacts/DownpourNext-win-x64
dotnet publish src/Downpour.Service/Downpour.Service.csproj -c Release -r win-x64 --self-contained true -o artifacts/DownpourNext-win-x64/service
dotnet publish src/Downpour.Scanner/Downpour.Scanner.csproj -c Release -r win-x64 --self-contained true -o artifacts/DownpourNext-win-x64/service/scanner
dotnet publish src/Downpour.UpdateHelper/Downpour.UpdateHelper.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o artifacts/DownpourNext-win-x64/update-helper
Copy-Item Start-Downpour-Next.cmd artifacts/DownpourNext-win-x64/
Copy-Item Start-Downpour-Next.bat artifacts/DownpourNext-win-x64/
```

The YARA scanner (DN-026) needs `yara_x_capi.dll` from the official YARA-X v1.21.0 release. The `Downpour.Scanner` build downloads that release zip once into `.cache/yara-x/` (ignored by git), checks the zip and the DLL against the SHA-256 values pinned in `Downpour.Scanner.csproj`, and fails the build on any mismatch. At runtime the scanner checks the DLL hash again before loading it and never downloads anything. Offline builds can pass `-p:SkipYaraXFetch=true`; YARA scanning then reports itself unavailable.

Trimming is disabled until the WinUI reflection and JSON paths have source-generated metadata and the Windows App SDK trim warnings have been resolved.

Release sets `WindowsPackageType=None` and `WindowsAppSDKSelfContained=true` in the desktop project before WinUI resource generation. Keep that deployment mode consistent across build and publish: building in packaged mode and changing it only at publish can reuse an incomplete PRI and crash on missing WinUI theme resources. After changing deployment mode, clean the desktop Release output before rebuilding. The v0.1.16 package passed direct launch with the merged WinUI resource index; clean-machine deployment remains a separate acceptance check.

The UI/Core JSON path uses pinned Newtonsoft.Json 13.0.4, with JSON type-name handling disabled and local/IPC parsing bounded. During the first self-contained launch check, the System.Text.Json-based UI build exited in WinRT's generated `GlobalVtableLookup` with a `ComInterfaceEntry` `TypeLoadException`. After changing the UI/Core JSON path and rebuilding, the portable EXE remained running. This is a validated workaround in this environment; it is not a confirmed root-cause analysis for every Windows SDK/runtime combination.

## Run the portable build

Extract the full `DownpourNext-win-x64.zip`, then double-click `Start-Downpour-Next.bat`, `Start-Downpour-Next.cmd`, or `Downpour.Desktop.exe`. Both launchers start the desktop directly; it auto-starts the bundled `service\Downpour.Service.exe` when needed and shuts down the child it owns on close. A source-build started with `dotnet run` still requires starting `Downpour.Service` separately from the development instructions above.

The Settings route now attaches toggle handlers after its XAML controls are initialized, avoiding early toggle events during page construction. Build/test and desktop startup are verified; an interactive click-through of the Settings route remains to be checked on the target desktop session.

The bundle is x64 and unsigned at this stage. It is intended for local testing from a trusted source. A signed MSIX/installer, Windows service installation/upgrade/rollback, and release signing identity have not been implemented; do not treat this portable bundle as a production security product.

## Current local package

Newest verified staging is `artifacts/DownpourNext-win-x64-0.1.19/`, with archive `artifacts/DownpourNext-win-x64-0.1.19.zip` from code `a672449615987e2b73da8042e3eb2d7db3ff2af5`: 264,276,335 bytes, SHA-256 `265C1C9C56D01BEA5037341505660BC25FFFCD5EDB96DB4BE096C72E5C68CB5F`. All 1,073 entries hash-match staging (666,619,839 expanded bytes). Clean Release build and 1117 tests pass; packaged smoke (six routes, owned-service shutdown, YARA helper) passes. Published as v0.1.19. v0.1.16 below is retained historical release evidence.

The newest verified local package is `artifacts/DownpourNext-win-x64-0.1.16/`, with archive `artifacts/DownpourNext-win-x64-0.1.16.zip`, built from committed source `ffc241d2806ccdf616c738c2ad5453d962eb4280`. SHA-256: `36503A9AEB68F67E763F13F4DACFC76C7161163F04A1C146FB071CBF085059EA` (259,810,553 bytes). All 1,062 archive entries hash-match staging; expanded size is 660,142,004 bytes, within the updater's bounds. The package includes a CycloneDX inventory of 52 runtime NuGet/native components and a per-file SHA-256 manifest. Final desktop/service/scanner lifecycle and benign YARA smoke passed with 179 rules; no privileged action was exercised. Clean committed Release tests: 856 passed; working-tree tests including preserved drafts: 879 passed. Full route/picker/high-DPI/UAC, clean-machine, signed-install and update failure/recovery acceptance remain open. Older `DownpourNext-Portable/` and v0.1.15 local archives are historical builds. Publication evidence belongs in the newest SHARED_CONTEXT checkpoint.
