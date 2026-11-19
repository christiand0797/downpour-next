#Requires -Version 5.1
<#
.SYNOPSIS
    Restore, build, test and publish the portable Windows x64 build of Downpour Next.

.DESCRIPTION
    Run from anywhere inside the repository:

        .\Build-Portable.ps1

    The script performs, in order:

        1. Preflight checks (Windows, .NET SDK, solution present).
        2. Clean the desktop project's stale output so the WinUI resource index
           (PRI) is regenerated in portable mode.
        3. dotnet restore Downpour.slnx
        4. dotnet build   Downpour.slnx -c Release
        5. dotnet test    Downpour.slnx -c Release --no-build
        6. Five dotnet publish commands for the desktop, service, scanner,
           update helper and elevated fixer.
        7. Copy both launchers and verify every expected file exists.

    Output is an unpackaged, self-contained, unsigned portable folder:

        artifacts\DownpourNext-win-x64-<version>\

    Launch it with Start-Downpour-Next.cmd. The desktop starts the bundled
    service itself and stops the child it owns on close. Nothing is signed,
    installed, registered as a service, or uploaded.

    A transcript of the run is written under artifacts\.

.PARAMETER Configuration
    Build configuration. Release is the portable default. Debug is accepted
    for local diagnostics only; it is not a release artifact.

.PARAMETER SkipTests
    Skip the test step.

.PARAMETER SkipYaraXFetch
    Build offline: passes -p:SkipYaraXFetch=true. The pinned YARA-X DLL is not
    downloaded and the scanner reports YARA as unavailable at runtime. The
    build still succeeds; the YARA DLL check is skipped.

.PARAMETER NoClean
    Keep the existing desktop bin/obj output. Only use this when the previous
    build in that folder was already Release portable output; stale
    packaged-mode output can start with missing WinUI theme resources.

.EXAMPLE
    .\Build-Portable.ps1

.EXAMPLE
    .\Build-Portable.ps1 -SkipTests -SkipYaraXFetch

.NOTES
    x64 only: the pinned YARA-X 1.21.0 DLL is windows-x64.
#>
[CmdletBinding()]
param(
    [ValidateSet('Release', 'Debug')]
    [string]$Configuration = 'Release',

    [switch]$SkipTests,

    [switch]$SkipYaraXFetch,

    [switch]$NoClean
)

$ErrorActionPreference = 'Stop'

$runtime = 'win-x64'

function Write-Step {
    param([string]$Text)
    Write-Host ''
    Write-Host "==> $Text" -ForegroundColor Cyan
}

function Fail {
    param([string]$Message)
    Write-Host ''
    Write-Host "ERROR: $Message" -ForegroundColor Red
    exit 1
}

function Invoke-DotNet {
    param([string[]]$Arguments)
    Write-Host ('    dotnet ' + ($Arguments -join ' ')) -ForegroundColor DarkGray
    & dotnet @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw ("dotnet " + $Arguments[0] + " failed with exit code $LASTEXITCODE")
    }
}

function Assert-UnderPath {
    param([string]$Path, [string]$Parent, [string]$Label)
    $parentFull = [System.IO.Path]::GetFullPath($Parent).TrimEnd('\') + '\'
    $pathFull = [System.IO.Path]::GetFullPath($Path)
    if (-not $pathFull.StartsWith($parentFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        Fail "$Label resolves outside $Parent and will not be deleted: $pathFull"
    }
}

function Remove-IfExists {
    param([string]$Path, [string]$Parent, [string]$Label)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    Assert-UnderPath -Path $Path -Parent $Parent -Label $Label
    Remove-Item -LiteralPath $Path -Recurse -Force
    Write-Host "    removed $Path" -ForegroundColor DarkGray
}

# --- Preflight -------------------------------------------------------------

$repoRoot = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($repoRoot)) { $repoRoot = (Get-Location).ProviderPath }

if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    Fail 'This script builds a Windows portable package and must run on Windows.'
}

$solution = Join-Path $repoRoot 'Downpour.slnx'
if (-not (Test-Path -LiteralPath $solution)) {
    Fail "Downpour.slnx was not found in $repoRoot. Keep this script at the repository root."
}

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    Fail 'The .NET SDK (dotnet) is not on PATH. Install the .NET 10 SDK and reopen the terminal.'
}

$buildPropsPath = Join-Path $repoRoot 'Directory.Build.props'
[xml]$buildProps = Get-Content -LiteralPath $buildPropsPath -Raw
$version = @(
    $buildProps.Project.PropertyGroup |
        ForEach-Object { $_.Version } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
) | Select-Object -First 1
if (-not $version) { Fail 'Could not read <Version> from Directory.Build.props.' }
$version = ([string]$version).Trim()

$artifacts = Join-Path $repoRoot 'artifacts'
if (-not (Test-Path -LiteralPath $artifacts)) {
    New-Item -ItemType Directory -Path $artifacts | Out-Null
}

$stagingName = "DownpourNext-$runtime-$version"
if ($Configuration -ne 'Release') { $stagingName = "$stagingName-$($Configuration.ToLowerInvariant())" }
$staging = Join-Path $artifacts $stagingName
$logPath = Join-Path $artifacts ("build-portable-$version-" + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.log')

$transcriptStarted = $false
try {
    Start-Transcript -Path $logPath -Force | Out-Null
    $transcriptStarted = $true
} catch {
    Write-Warning "Could not start a transcript: $($_.Exception.Message)"
}

try {
    Write-Host ''
    Write-Host 'Downpour Next portable build' -ForegroundColor White
    Write-Host "  repository : $repoRoot"
    Write-Host "  version    : $version"
    Write-Host "  config     : $Configuration ($runtime)"
    Write-Host "  output     : $staging"

    if ($NoClean) {
        Write-Host ''
        Write-Host '==> Skipping desktop clean (-NoClean)' -ForegroundColor Cyan
    } else {
        Write-Step "Cleaning stale desktop $Configuration output"
        Remove-IfExists -Path (Join-Path $repoRoot "src\Downpour.Desktop\bin\$Configuration") -Parent $repoRoot -Label 'Desktop bin'
        Remove-IfExists -Path (Join-Path $repoRoot "src\Downpour.Desktop\obj\$Configuration") -Parent $repoRoot -Label 'Desktop obj'
    }

    Remove-IfExists -Path $staging -Parent $artifacts -Label 'Staging folder'

    $yaraArgs = @()
    if ($SkipYaraXFetch) { $yaraArgs = @('-p:SkipYaraXFetch=true') }

    Write-Step 'Restoring packages'
    Invoke-DotNet -Arguments @('restore', $solution, '--nologo')

    Write-Step "Building $Configuration"
    Invoke-DotNet -Arguments (@(
        'build', $solution, '-c', $Configuration, '--no-restore', '--nologo',
        '-p:WindowsPackageType=None', '-p:WindowsAppSDKSelfContained=true'
    ) + $yaraArgs)

    if ($SkipTests) {
        Write-Host ''
        Write-Host '==> Skipping tests (-SkipTests)' -ForegroundColor Cyan
    } else {
        Write-Step 'Running tests'
        Invoke-DotNet -Arguments @(
            'test', $solution, '-c', $Configuration, '--no-build', '--no-restore', '--nologo',
            '--blame-hang-timeout', '10m'
        )
    }

    Write-Step 'Publishing desktop'
    Invoke-DotNet -Arguments (@(
        'publish', (Join-Path $repoRoot 'src\Downpour.Desktop\Downpour.Desktop.csproj'),
        '-c', $Configuration, '-r', $runtime, '--nologo',
        '-p:WindowsPackageType=None', '-p:WindowsAppSDKSelfContained=true',
        '-p:SelfContained=true', '-p:PublishTrimmed=false',
        '-o', $staging
    ) + $yaraArgs)

    Write-Step 'Publishing service'
    Invoke-DotNet -Arguments (@(
        'publish', (Join-Path $repoRoot 'src\Downpour.Service\Downpour.Service.csproj'),
        '-c', $Configuration, '-r', $runtime, '--self-contained', 'true', '--nologo',
        '-o', (Join-Path $staging 'service')
    ) + $yaraArgs)

    Write-Step 'Publishing YARA scanner'
    Invoke-DotNet -Arguments (@(
        'publish', (Join-Path $repoRoot 'src\Downpour.Scanner\Downpour.Scanner.csproj'),
        '-c', $Configuration, '-r', $runtime, '--self-contained', 'true', '--nologo',
        '-o', (Join-Path $staging 'service\scanner')
    ) + $yaraArgs)

    Write-Step 'Publishing update helper'
    Invoke-DotNet -Arguments @(
        'publish', (Join-Path $repoRoot 'src\Downpour.UpdateHelper\Downpour.UpdateHelper.csproj'),
        '-c', $Configuration, '-r', $runtime, '--self-contained', 'true',
        '-p:PublishSingleFile=true', '--nologo',
        '-o', (Join-Path $staging 'update-helper')
    )

    Write-Step 'Publishing elevated fixer'
    Invoke-DotNet -Arguments @(
        'publish', (Join-Path $repoRoot 'src\Downpour.Fixer\Downpour.Fixer.csproj'),
        '-c', $Configuration, '-r', $runtime, '--self-contained', 'true',
        '-p:PublishSingleFile=true', '--nologo',
        '-o', (Join-Path $staging 'fixer')
    )

    Write-Step 'Copying launchers'
    foreach ($launcher in @('Start-Downpour-Next.cmd', 'Start-Downpour-Next.bat')) {
        Copy-Item -LiteralPath (Join-Path $repoRoot $launcher) -Destination (Join-Path $staging $launcher) -Force
    }

    Write-Step 'Verifying published files'
    $expected = @(
        'Downpour.Desktop.exe',
        'service\Downpour.Service.exe',
        'service\scanner\Downpour.Scanner.exe',
        'update-helper\Downpour.UpdateHelper.exe',
        'fixer\Downpour.Fixer.exe',
        'Start-Downpour-Next.cmd',
        'Start-Downpour-Next.bat'
    )
    $missing = @()
    foreach ($relative in $expected) {
        if (-not (Test-Path -LiteralPath (Join-Path $staging $relative))) { $missing += $relative }
    }

    $yaraDll = Join-Path $staging 'service\scanner\yara_x_capi.dll'
    if (-not (Test-Path -LiteralPath $yaraDll)) {
        if ($SkipYaraXFetch) {
            Write-Warning 'YARA-X DLL is absent (offline build); YARA scanning will report itself unavailable.'
        } else {
            $missing += 'service\scanner\yara_x_capi.dll'
        }
    }

    $yaraRules = Join-Path $staging 'service\scanner\yara_rules'
    if (Test-Path -LiteralPath $yaraRules) {
        $ruleCount = @(Get-ChildItem -LiteralPath $yaraRules -Filter '*.yar' -File).Count
        Write-Host "    yara rules : $ruleCount" -ForegroundColor DarkGray
    }

    if ($missing.Count -gt 0) {
        throw ('The published build is incomplete. Missing: ' + ($missing -join ', '))
    }

    $files = @(Get-ChildItem -LiteralPath $staging -Recurse -File)
    $totalMb = 0
    if ($files.Count -gt 0) {
        $totalMb = [math]::Round((($files | Measure-Object -Property Length -Sum).Sum / 1MB), 1)
    }

    Write-Host ''
    Write-Host 'Portable build ready.' -ForegroundColor Green
    Write-Host "  folder : $staging"
    Write-Host "  files  : $($files.Count) ($totalMb MB)"
    Write-Host "  launch : $(Join-Path $staging 'Start-Downpour-Next.cmd')"
    Write-Host ''
    Write-Host 'Unsigned build: no installer, no service registration, no code signing.' -ForegroundColor Yellow
    Write-Host "Transcript: $logPath"
} catch {
    Write-Host ''
    Write-Host "BUILD FAILED: $($_.Exception.Message)" -ForegroundColor Red
    if ($transcriptStarted) {
        try { Stop-Transcript | Out-Null } catch { }
    }
    exit 1
}

if ($transcriptStarted) {
    try { Stop-Transcript | Out-Null } catch { }
}
exit 0
