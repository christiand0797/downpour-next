<#
.SYNOPSIS
    Runs the repository's release gates without GitHub-hosted runners.

.DESCRIPTION
    Restores, builds and tests the solution, then optionally runs the packaged window smoke against an
    existing portable folder. Exits non-zero at the first failing gate so a self-hosted workflow fails
    exactly where a person would stop.

.PARAMETER Configuration
    Build configuration. Release is the release gate; Debug is accepted for quick checks.

.PARAMETER SkipBuild
    Reuse the current build output.

.PARAMETER SkipTests
    Skip the test gate (not recommended for a release).

.PARAMETER PackagePath
    Portable folder to smoke-test. When omitted, packaging is not exercised.

.EXAMPLE
    pwsh ./tools/ci/run-gates.ps1 -Configuration Release

.EXAMPLE
    pwsh ./tools/ci/run-gates.ps1 -PackagePath artifacts/DownpourNext-win-x64-0.1.23
#>
[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',
    [switch]$SkipBuild,
    [switch]$SkipTests,
    [string]$PackagePath
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Push-Location $root
try {
    if (-not $SkipBuild) {
        Write-Output "==> Restore"
        dotnet restore Downpour.slnx
        if ($LASTEXITCODE -ne 0) { throw "dotnet restore failed with exit code $LASTEXITCODE" }

        Write-Output "==> Build ($Configuration)"
        dotnet build Downpour.slnx -c $Configuration --no-restore -v:m
        if ($LASTEXITCODE -ne 0) { throw "dotnet build failed with exit code $LASTEXITCODE" }
    }

    if (-not $SkipTests) {
        Write-Output "==> Test ($Configuration)"
        dotnet test Downpour.slnx -c $Configuration --no-build
        if ($LASTEXITCODE -ne 0) { throw "dotnet test failed with exit code $LASTEXITCODE" }
    }

    if ($PackagePath) {
        $package = Resolve-Path -LiteralPath $PackagePath
        Write-Output "==> Packaged window smoke ($package)"
        $smoke = Join-Path $root 'artifacts/v0.1.23-window-smoke.ps1'
        if (-not (Test-Path -LiteralPath $smoke)) { throw 'The packaged window smoke script is missing.' }
        & pwsh -NoProfile -File $smoke
        if ($LASTEXITCODE -ne 0) { throw "Packaged smoke failed with exit code $LASTEXITCODE" }
    }

    Write-Output 'All requested gates passed.'
}
finally { Pop-Location }
