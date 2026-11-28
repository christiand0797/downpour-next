#Requires -Version 7.0
<#
.SYNOPSIS
    Runs the packaged route smoke and the native window smoke against a portable folder.

.DESCRIPTION
    Reads the route list from capabilities.json, starts the packaged desktop once per route with
    --open-route, verifies that it starts exactly one owned service that answers the system snapshot
    pipe, then closes it and verifies the owned service stopped and no new crash entry appeared.
    Afterwards the YARA helper is exercised and, unless -SkipWindow, the native window behaviour
    (maximized startup, resize styles, Restore, resize bounds, graceful close) is tested.

    Both modes refuse to run while a Downpour.Desktop or Downpour.Service process already exists, so a
    live install is never disturbed and a leaked process is reported instead of hidden.

.PARAMETER Version
    Product version; selects the default package folder and log folder.

.PARAMETER Label
    Names the log folder. Defaults to the version.

.PARAMETER PackagePath
    Portable folder. Defaults to artifacts\DownpourNext-win-x64-<Version>.

.PARAMETER Routes
    Override the route list, for example -Routes scheduled-tasks while iterating on one page. Every name
    must exist in capabilities.json.

.PARAMETER SkipWindow
    Skip the native window smoke.

.PARAMETER SkipScanner
    Skip the YARA helper check.

.EXAMPLE
    pwsh ./tools/release/Test-Portable.ps1 -Version 0.1.44
#>
[CmdletBinding()]
param(
    [string]$Version,
    [string]$Label,
    [string]$PackagePath,
    [string[]]$Routes,
    [switch]$SkipRoutes,
    [switch]$SkipWindow,
    [switch]$SkipScanner
)

$ErrorActionPreference = 'Stop'

$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$artifacts = Join-Path $repo 'artifacts'

function Fail {
    param([string]$Message)
    Write-Host "SMOKE FAILED: $Message" -ForegroundColor Red
    exit 1
}

if (-not $Version) {
    [xml]$props = Get-Content -LiteralPath (Join-Path $repo 'Directory.Build.props') -Raw
    $Version = @(
        $props.Project.PropertyGroup |
            ForEach-Object { $_.Version } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    ) | Select-Object -First 1
}
if (-not $Version) { Fail 'Could not read <Version> from Directory.Build.props.' }
$Version = ([string]$Version).Trim()
if (-not $Label) { $Label = $Version }

if (-not $PackagePath) { $PackagePath = Join-Path $artifacts "DownpourNext-win-x64-$Version" }
if (-not (Test-Path -LiteralPath $PackagePath -PathType Container)) { Fail "Portable folder not found: $PackagePath" }
$package = (Resolve-Path -LiteralPath $PackagePath).Path

$logs = Join-Path $artifacts "v$Label-smoke"
[IO.Directory]::CreateDirectory($logs) | Out-Null

if (Get-Process -Name Downpour.Desktop, Downpour.Service -ErrorAction SilentlyContinue) {
    Fail 'An existing Downpour process is running; this smoke never stops a process it did not start.'
}

function Read-Snapshot {
    param([string]$Name)
    $pipe = [IO.Pipes.NamedPipeClientStream]::new('.', $Name, [IO.Pipes.PipeDirection]::In, [IO.Pipes.PipeOptions]::Asynchronous)
    $deadline = [Threading.CancellationTokenSource]::new(30000)
    try {
        $pipe.ConnectAsync($deadline.Token).GetAwaiter().GetResult()
        $deadline.CancelAfter(10000)
        $reader = [IO.StreamReader]::new($pipe)
        $raw = $reader.ReadToEndAsync($deadline.Token).GetAwaiter().GetResult()
        if ($raw.Length -gt 1048576) { throw 'Snapshot exceeded the 1 MiB cap.' }
        return $raw | ConvertFrom-Json
    } finally {
        $pipe.Dispose()
        $deadline.Dispose()
    }
}

# --- Standalone service ----------------------------------------------------

if (-not $SkipRoutes) {
    $service = $null
    try {
        $service = Start-Process -FilePath (Join-Path $package 'service/Downpour.Service.exe') `
            -WorkingDirectory (Join-Path $package 'service') -WindowStyle Hidden -PassThru `
            -RedirectStandardOutput (Join-Path $logs 'service.stdout.log') `
            -RedirectStandardError (Join-Path $logs 'service.stderr.log')
        Start-Sleep -Seconds 3
        if ($service.HasExited) { Fail 'Packaged service exited during startup.' }
        $system = Read-Snapshot 'Downpour.SystemSnapshot.v1'
        $alerts = Read-Snapshot 'Downpour.SecurityAlerts.v1'
        if ($system.schemaVersion -ne 1 -or $alerts.schemaVersion -ne 1) { Fail 'Snapshot schema failed.' }
        Write-Host 'Standalone service alive; system and alert pipes returned schema v1.' -ForegroundColor DarkGray
        Write-Host ('Sensor health warnings: ' + @($alerts.warnings).Count) -ForegroundColor DarkGray
    } finally {
        if ($service -and -not $service.HasExited) { Stop-Process -Id $service.Id -Force }
    }
    Start-Sleep -Seconds 1

    $capabilities = Get-Content -LiteralPath (Join-Path $repo 'capabilities.json') -Raw | ConvertFrom-Json
    $known = @($capabilities.capabilities.routeId)
    $routes = if ($Routes) {
        foreach ($route in $Routes) {
            if ($known -notcontains $route) { Fail "Unknown route '$route'. Known routes: $($known -join ', ')" }
        }
        @($Routes)
    } else {
        @('processes') + @($known | Where-Object { $_ -ne 'processes' })
    }
    Write-Host "==> Route smoke: $($routes.Count) route$(if ($routes.Count -eq 1) { '' } else { 's' })" -ForegroundColor Cyan

    $crashLog = Join-Path $env:LOCALAPPDATA 'DownpourNext/logs/desktop-crash.log'
    $index = 0
    foreach ($route in $routes) {
        $index++
        $beforeCrashLength = if (Test-Path -LiteralPath $crashLog) { (Get-Item -LiteralPath $crashLog).Length } else { 0 }
        $desktop = $null
        $owned = @()
        try {
            $desktop = Start-Process -FilePath (Join-Path $package 'Downpour.Desktop.exe') `
                -WorkingDirectory $package -ArgumentList @('--open-route', $route) -PassThru
            $owned = @()
            for ($wait = 0; $wait -lt 30; $wait++) {
                Start-Sleep -Seconds 1
                $desktop.Refresh()
                if ($desktop.HasExited) { Fail "Packaged desktop exited with code $($desktop.ExitCode) on route '$route'." }
                $owned = @(
                    Get-CimInstance Win32_Process -Filter "Name='Downpour.Service.exe' AND ParentProcessId=$($desktop.Id)" |
                        Select-Object -ExpandProperty ProcessId
                )
                if ($owned.Count -eq 1) { break }
            }
            if ($owned.Count -ne 1) { Fail "Desktop did not start exactly one owned bundled service on route '$route'." }
            $snapshot = Read-Snapshot 'Downpour.SystemSnapshot.v1'
            if ($snapshot.schemaVersion -ne 1) { Fail "Auto-start service snapshot failed on route '$route'." }

            $desktop.Refresh()
            for ($windowWait = 0; $windowWait -lt 15 -and $desktop.MainWindowHandle -eq 0; $windowWait++) {
                Start-Sleep -Seconds 1
                $desktop.Refresh()
            }
            $windowHandle = $desktop.MainWindowHandle
            if ($windowHandle -eq 0) { Fail "The desktop never created a main window on route '$route'." }

            $closed = $desktop.CloseMainWindow()
            if (-not $closed -or -not $desktop.WaitForExit(20000)) {
                Fail "Desktop did not close gracefully: route=$route requestSent=$closed exited=$($desktop.HasExited)"
            }
            if ($desktop.ExitCode -ne 0) { Fail "Native desktop exit failed: route=$route code=$($desktop.ExitCode)" }
            Start-Sleep -Seconds 1
            if ($owned | Where-Object { Get-Process -Id $_ -ErrorAction SilentlyContinue }) {
                Fail "Owned service survived graceful desktop close on route '$route'."
            }
            $afterCrashLength = if (Test-Path -LiteralPath $crashLog) { (Get-Item -LiteralPath $crashLog).Length } else { 0 }
            if ($afterCrashLength -ne $beforeCrashLength) { Fail "New desktop crash log content during route '$route'." }
            Write-Host "  [$index/$($routes.Count)] $route" -ForegroundColor DarkGray
        } finally {
            if ($desktop -and -not $desktop.HasExited) { Stop-Process -Id $desktop.Id -Force }
            foreach ($processId in $owned) {
                if (Get-Process -Id $processId -ErrorAction SilentlyContinue) { Stop-Process -Id $processId -Force }
            }
        }
    }
    Write-Host 'Every packaged route opened, answered telemetry and closed cleanly.' -ForegroundColor DarkGray
}

# --- YARA helper -----------------------------------------------------------

if (-not $SkipScanner) {
    $scanner = [Diagnostics.Process]::new()
    $scanner.StartInfo = [Diagnostics.ProcessStartInfo]::new((Join-Path $package 'service/scanner/Downpour.Scanner.exe'))
    $scanner.StartInfo.UseShellExecute = $false
    $scanner.StartInfo.CreateNoWindow = $true
    $scanner.StartInfo.RedirectStandardInput = $true
    $scanner.StartInfo.RedirectStandardOutput = $true
    $scanner.StartInfo.RedirectStandardError = $true
    try {
        $scanner.Start() | Out-Null
        $ready = $scanner.StandardOutput.ReadLineAsync().WaitAsync([TimeSpan]::FromSeconds(15)).GetAwaiter().GetResult() | ConvertFrom-Json
        if ($ready.error -or $ready.ruleCount -le 0) { Fail 'Packaged YARA helper did not load rules.' }
        $fixture = Join-Path $logs 'benign-fixture.txt'
        [IO.File]::WriteAllText($fixture, 'The quick brown fox jumps over the lazy dog.')
        $request = @{ id = 1; path = $fixture } | ConvertTo-Json -Compress
        $scanner.StandardInput.WriteLine($request)
        $result = $scanner.StandardOutput.ReadLineAsync().WaitAsync([TimeSpan]::FromSeconds(15)).GetAwaiter().GetResult() | ConvertFrom-Json
        if ($result.id -ne 1 -or $result.status -eq 'error' -or @($result.matches).Count -ne 0) {
            Fail 'Benign scanner fixture failed.'
        }
        $scanner.StandardInput.Close()
        if (-not $scanner.WaitForExit(5000) -or $scanner.ExitCode -ne 0) { Fail 'Scanner did not exit cleanly.' }
        Write-Host ("YARA helper loaded $($ready.ruleCount) rules and scanned a benign fixture.") -ForegroundColor DarkGray
    } finally {
        if (-not $scanner.HasExited) { $scanner.Kill() }
        $scanner.Dispose()
    }
}

# --- Native window smoke ---------------------------------------------------

if (-not $SkipWindow) {
    Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class WindowProbe {
 [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
 [DllImport("user32.dll")] public static extern bool IsZoomed(IntPtr hwnd);
 [DllImport("user32.dll", EntryPoint="GetWindowLongPtrW")] public static extern IntPtr GetWindowLongPtr(IntPtr hwnd,int index);
 [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hwnd,int command);
 [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hwnd,out RECT rectangle);
 [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr hwnd,IntPtr after,int x,int y,int width,int height,uint flags);
}
"@
    $app = $null
    $owned = @()
    try {
        $app = Start-Process -FilePath (Join-Path $package 'Downpour.Desktop.exe') -WorkingDirectory $package `
            -WindowStyle Hidden -PassThru -ArgumentList @('--open-route', 'cognitive-immune-system')
        $deadline = [DateTime]::UtcNow.AddSeconds(30)
        do {
            Start-Sleep -Milliseconds 250
            $app.Refresh()
        } while (-not $app.HasExited -and $app.MainWindowHandle -eq 0 -and [DateTime]::UtcNow -lt $deadline)
        if ($app.HasExited -or $app.MainWindowHandle -eq 0) { Fail 'Main window unavailable for the window smoke.' }
        Start-Sleep -Seconds 3

        $hwnd = $app.MainWindowHandle
        if (-not [WindowProbe]::IsZoomed($hwnd)) { Fail 'Startup was not maximized.' }
        $style = [WindowProbe]::GetWindowLongPtr($hwnd, -16).ToInt64()
        if (($style -band 0x70000) -ne 0x70000) { Fail 'Resize/minimize/maximize window styles are missing.' }

        [WindowProbe]::ShowWindow($hwnd, 9) | Out-Null
        Start-Sleep -Milliseconds 500
        if ([WindowProbe]::IsZoomed($hwnd)) { Fail 'Restore did not leave maximized state.' }

        $before = [WindowProbe+RECT]::new()
        [WindowProbe]::GetWindowRect($hwnd, [ref]$before) | Out-Null
        if (-not [WindowProbe]::SetWindowPos($hwnd, [IntPtr]::Zero, 0, 0, 1017, 713, 6)) { Fail 'Native resize failed.' }
        Start-Sleep -Milliseconds 500

        $after = [WindowProbe+RECT]::new()
        [WindowProbe]::GetWindowRect($hwnd, [ref]$after) | Out-Null
        if ((($before.Right - $before.Left) -eq ($after.Right - $after.Left)) -and
            (($before.Bottom - $before.Top) -eq ($after.Bottom - $after.Top))) {
            Fail 'Resize did not change the window dimensions.'
        }
        if ([WindowProbe]::IsZoomed($hwnd)) { Fail 'The window forced itself back to maximized.' }

        $owned = @(
            Get-CimInstance Win32_Process -Filter "Name='Downpour.Service.exe' AND ParentProcessId=$($app.Id)" |
                Select-Object -ExpandProperty ProcessId
        )
        if ($owned.Count -ne 1) { Fail 'Expected exactly one owned sensor service in the window smoke.' }
        if (-not $app.CloseMainWindow() -or -not $app.WaitForExit(10000)) { Fail 'The window failed to close gracefully.' }
        if ($app.ExitCode -ne 0) { Fail "Native desktop exit failed: $($app.ExitCode)" }
        Start-Sleep -Seconds 1
        if ($owned | Where-Object { Get-Process -Id $_ -ErrorAction SilentlyContinue }) {
            Fail 'The owned service survived the desktop close.'
        }
        Write-Host 'Window smoke passed: maximized startup, Restore, resize, graceful close.' -ForegroundColor DarkGray
    } finally {
        if ($app -and -not $app.HasExited) { Stop-Process -Id $app.Id -Force }
        foreach ($processId in $owned) {
            if (Get-Process -Id $processId -ErrorAction SilentlyContinue) { Stop-Process -Id $processId -Force }
        }
    }
}

Write-Host 'Package smoke passed.' -ForegroundColor Green
