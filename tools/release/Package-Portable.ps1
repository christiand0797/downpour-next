#Requires -Version 7.0
<#
.SYNOPSIS
    Packages an already published portable folder with a manifest, SBOM, checksums and evidence record.

.DESCRIPTION
    Replaces the per-release package scripts that used to be copied into artifacts\. It reads the version
    from Directory.Build.props (or -Version), the commit from git (or -Commit), verifies that every
    published executable really came from that commit, then writes:

        release-manifest.json     every file, size and SHA-256 (inside the package)
        RELEASE-README.txt        what this package is and how it was validated
        <label>-sbom.cdx.json     CycloneDX runtime dependency inventory
        <label>-SHA256SUMS.txt    archive and SBOM digests
        v<label>-evidence.json    machine-readable record for the release cut

    The archive is re-opened and every entry is re-hashed; a mismatch aborts without publishing anything.

.PARAMETER Version
    Product version. Defaults to <Version> in Directory.Build.props.

.PARAMETER Commit
    Full source commit the package was built from. Defaults to HEAD.

.PARAMETER TestCount
    Number of Release tests that passed. Recorded in the readme and evidence; 0 means "not recorded".

.PARAMETER StagePath
    Published portable folder. Defaults to artifacts\DownpourNext-win-x64-<Version>.

.PARAMETER Label
    Names the SBOM, checksum and evidence files. Defaults to the version; the nightly uses
    nightly-YYYYMMDD so its assets never collide with a stable release of the same version.

.PARAMETER AllowExistingArchive
    Overwrite an existing archive instead of refusing.

.EXAMPLE
    pwsh ./tools/release/Package-Portable.ps1 -TestCount 1563

.EXAMPLE
    pwsh ./tools/release/Package-Portable.ps1 -Label nightly-20261128 -TestCount 1563
#>
[CmdletBinding()]
param(
    [string]$Version,
    [string]$Commit,
    [int]$TestCount = 0,
    [string]$StagePath,
    [string]$Label,
    [switch]$AllowExistingArchive
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem

$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$artifacts = Join-Path $repo 'artifacts'

function Fail {
    param([string]$Message)
    Write-Host "PACKAGE FAILED: $Message" -ForegroundColor Red
    exit 1
}

function Get-FileSha256 {
    param([string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
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

if (-not $Commit) {
    $Commit = (& git -C $repo rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $Commit -notmatch '^[0-9a-f]{40}$') { Fail 'Could not read HEAD from git.' }
}
if ($Commit -notmatch '^[0-9a-f]{40}$') { Fail "Commit must be a full 40-character SHA: $Commit" }
$shortCommit = $Commit.Substring(0, 12)

if (-not $Label) { $Label = $Version }
if ($Label -notmatch '^[A-Za-z0-9._-]+$') { Fail "Label contains unsupported characters: $Label" }

if (-not $StagePath) { $StagePath = Join-Path $artifacts "DownpourNext-win-x64-$Version" }
if (-not (Test-Path -LiteralPath $StagePath -PathType Container)) { Fail "Portable folder not found: $StagePath" }
$stage = (Resolve-Path -LiteralPath $StagePath).Path

$expectedFileVersion = if (($Version -split '\.').Count -eq 3) { "$Version.0" } else { $Version }

$executables = @(
    'Downpour.Desktop.exe',
    'service/Downpour.Service.exe',
    'service/scanner/Downpour.Scanner.exe',
    'update-helper/Downpour.UpdateHelper.exe',
    'fixer/Downpour.Fixer.exe'
)
foreach ($relative in $executables) {
    $path = Join-Path $stage $relative
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { Fail "Missing published executable: $relative" }
    $info = (Get-Item -LiteralPath $path).VersionInfo
    if ($info.FileVersion -ne $expectedFileVersion) {
        Fail "Stale executable: $relative has FileVersion $($info.FileVersion), expected $expectedFileVersion. Rebuild before packaging."
    }
    if (-not ([string]$info.ProductVersion).Contains($Commit)) {
        Fail "Stale executable: $relative was not built from $shortCommit ($($info.ProductVersion)). Rebuild before packaging."
    }
}

$pri = Join-Path $stage 'Downpour.Desktop.pri'
if (-not (Test-Path -LiteralPath $pri) -or (Get-Item -LiteralPath $pri).Length -lt 2000000) {
    Fail 'Portable WinUI theme resource index is missing or too small.'
}

foreach ($launcher in @('Start-Downpour-Next.bat', 'Start-Downpour-Next.cmd')) {
    Copy-Item -LiteralPath (Join-Path $repo $launcher) -Destination (Join-Path $stage $launcher) -Force
}

foreach ($asset in @('StormBackdrop.png', 'CrescentMoon.png', 'AppIcon.ico')) {
    $source = Join-Path $repo "src/Downpour.Desktop/Assets/$asset"
    $target = Join-Path $stage "Assets/$asset"
    if (-not (Test-Path -LiteralPath $target)) { Fail "Missing portable asset: $asset" }
    if ((Get-FileSha256 $source) -ne (Get-FileSha256 $target)) { Fail "Mismatched portable asset: $asset" }
}

# --- SBOM ------------------------------------------------------------------

$components = @{}
$dependencyManifests = @(Get-ChildItem -LiteralPath $stage -Recurse -Filter '*.deps.json' -File)
foreach ($project in @('Downpour.Fixer', 'Downpour.UpdateHelper')) {
    $embedded = @(
        Get-ChildItem -LiteralPath (Join-Path $repo "src/$project/bin/Release") -Recurse -Filter "$project.deps.json" -File -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match 'win-x64' } |
            Sort-Object LastWriteTime -Descending
    ) | Select-Object -First 1
    if (-not $embedded) { Fail "Missing embedded dependency manifest: $project" }
    $dependencyManifests += $embedded
}
foreach ($deps in $dependencyManifests) {
    $data = Get-Content -LiteralPath $deps.FullName -Raw | ConvertFrom-Json
    foreach ($property in $data.libraries.PSObject.Properties) {
        if ($property.Value.type -ne 'package') { continue }
        $split = $property.Name.LastIndexOf('/')
        $name = $property.Name.Substring(0, $split)
        $packageVersion = $property.Name.Substring($split + 1)
        $purl = "pkg:nuget/$name@$packageVersion"
        $component = [ordered]@{
            type     = 'library'
            'bom-ref'  = $purl
            name     = $name
            version  = $packageVersion
            purl     = $purl
        }
        if ($property.Value.sha512) {
            $digest = [Convert]::ToHexString(
                [Convert]::FromBase64String(($property.Value.sha512 -replace '^sha512-', ''))
            ).ToLowerInvariant()
            $component.hashes = @(@{ alg = 'SHA-512'; content = $digest })
        }
        $components[$purl] = $component
    }
}

$yaraDll = Join-Path $stage 'service/scanner/yara_x_capi.dll'
if (-not (Test-Path -LiteralPath $yaraDll -PathType Leaf)) {
    Fail 'YARA-X native library is missing; build without -SkipYaraXFetch before packaging.'
}
$native = Get-FileSha256 $yaraDll
if ($native -ne '8566a23d8df2bd76570caf36e5587e8bc8a1e6b32f84cf88f59d2b753bb8e4ab') {
    Fail "YARA-X native digest mismatch: $native"
}
$purl = 'pkg:github/VirusTotal/yara-x@1.21.0'
$components[$purl] = [ordered]@{
    type     = 'library'
    'bom-ref'  = $purl
    name     = 'YARA-X native C API'
    version  = '1.21.0'
    purl     = $purl
    hashes   = @(@{ alg = 'SHA-256'; content = $native })
}

$sbom = [ordered]@{
    bomFormat    = 'CycloneDX'
    specVersion  = '1.6'
    serialNumber = 'urn:uuid:' + ([guid]::NewGuid().ToString())
    version      = 1
    metadata     = @{
        timestamp = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        component = @{
            type    = 'application'
            name    = 'Downpour Next'
            version = $Version
            purl    = "pkg:github/christiand0797/downpour-next@$Version"
        }
    }
    components   = @($components.Values | Sort-Object purl)
}
$bomName = "DownpourNext-$Label-sbom.cdx.json"
$bomPath = Join-Path $stage $bomName
$sbom | ConvertTo-Json -Depth 15 | Set-Content -LiteralPath $bomPath -Encoding utf8
Copy-Item -LiteralPath $bomPath -Destination (Join-Path $artifacts $bomName) -Force

# --- README ----------------------------------------------------------------

$validation = if ($TestCount -gt 0) {
    "Release build, 0 warnings/errors, $TestCount tests passed."
} else {
    'Release build; test count was not recorded by this run.'
}
$readme = @"
Downpour Next $Version - Windows x64 portable development release

Extract the full archive, then launch Downpour.Desktop.exe or Start-Downpour-Next.bat. The desktop starts its bundled service and closes the service it owns when the desktop closes. No separate .NET installation is required. This package targets Windows x64; ARM deployment has not been verified.

Source: https://github.com/christiand0797/downpour-next/tree/$Commit
Validation: $validation

See the release page and docs/RELEASE_$Version.md in the repository for what changed and what remains open.

Every response action needs your confirmation and is audited; no remediation runs automatically. Binaries and updater metadata are unsigned. User state remains under LOCALAPPDATA/DownpourNext; elevated fixer backups, results and audit records use the protected ProgramData/DownpourNext/fixer folder. This package includes a CycloneDX runtime dependency inventory and a SHA-256 file manifest.
"@
[IO.File]::WriteAllText((Join-Path $stage 'RELEASE-README.txt'), $readme + [Environment]::NewLine)

# --- Manifest and archive --------------------------------------------------

$files = @(
    Get-ChildItem -LiteralPath $stage -Recurse -File |
        Where-Object { $_.Name -ne 'release-manifest.json' } |
        ForEach-Object {
            [ordered]@{
                path   = [IO.Path]::GetRelativePath($stage, $_.FullName).Replace('\', '/')
                bytes  = $_.Length
                sha256 = (Get-FileSha256 $_.FullName)
            }
        } |
        Sort-Object path
)
$manifest = [ordered]@{
    schemaVersion = 1
    version       = $Version
    sourceCommit  = $Commit
    files         = $files
}
$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $stage 'release-manifest.json') -Encoding utf8

$archiveName = "DownpourNext-win-x64-$Version.zip"
if ($Label -ne $Version) { $archiveName = "DownpourNext-$Label.zip" }
$zip = Join-Path $artifacts $archiveName
if ((Test-Path -LiteralPath $zip) -and -not $AllowExistingArchive) {
    Fail "Archive already exists and will not be overwritten: $zip"
}
if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
[IO.Compression.ZipFile]::CreateFromDirectory(
    $stage, $zip, [IO.Compression.CompressionLevel]::Optimal, $false
)

$archive = [IO.Compression.ZipFile]::OpenRead($zip)
try {
    $expected = @{}
    foreach ($file in $files) { $expected[$file.path] = $file }
    $manifestInfo = Get-Item -LiteralPath (Join-Path $stage 'release-manifest.json')
    $expected['release-manifest.json'] = @{ sha256 = (Get-FileSha256 $manifestInfo.FullName); bytes = $manifestInfo.Length }

    if ($archive.Entries.Count -ne $expected.Count -or $archive.Entries.Count -gt 2000) {
        Fail "Invalid archive entry count: $($archive.Entries.Count) entries for $($expected.Count) files."
    }
    $total = 0L
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $archive.Entries) {
        if (-not $seen.Add($entry.FullName) -or -not $expected.ContainsKey($entry.FullName)) {
            Fail "Unexpected or duplicate archive entry: $($entry.FullName)"
        }
        if ($entry.FullName.StartsWith('/') -or $entry.FullName.Contains(':') -or ($entry.FullName.Split('/') -contains '..')) {
            Fail "Unsafe archive path: $($entry.FullName)"
        }
        $total += $entry.Length
        $stream = $entry.Open()
        try {
            $digest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($stream)).ToLowerInvariant()
        } finally {
            $stream.Dispose()
        }
        if ($digest -ne $expected[$entry.FullName].sha256 -or $entry.Length -ne $expected[$entry.FullName].bytes) {
            Fail "Archive content mismatch: $($entry.FullName)"
        }
    }
    if ($total -gt 1GB -or (Get-Item -LiteralPath $zip).Length -gt 512MB) {
        Fail 'Archive exceeds updater bounds.'
    }
} finally {
    $archive.Dispose()
}

$zipHash = Get-FileSha256 $zip
$bomHash = Get-FileSha256 $bomPath
$sumsName = "DownpourNext-$Label-SHA256SUMS.txt"
$sumsPath = Join-Path $artifacts $sumsName
[IO.File]::WriteAllText($sumsPath, "$zipHash  $archiveName`n$bomHash  $bomName`n")

$evidence = [ordered]@{
    version            = $Version
    label              = $Label
    sourceCommit       = $Commit
    zip                = $zip
    zipBytes           = (Get-Item -LiteralPath $zip).Length
    zipSha256          = $zipHash
    sbom               = $bomPath
    sbomSha256         = $bomHash
    sums               = $sumsPath
    sumsSha256         = (Get-FileSha256 $sumsPath)
    files              = $expected.Count
    expandedBytes      = $total
    runtimeComponents  = $components.Count
    testCount          = $TestCount
    verifiedUtc        = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
}
$evidencePath = Join-Path $artifacts "v$Label-evidence.json"
$evidence | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $evidencePath -Encoding utf8

$evidence | ConvertTo-Json -Depth 6
Write-Host "Package ready: $zip" -ForegroundColor Green
