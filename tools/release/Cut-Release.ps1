#Requires -Version 7.0
<#
.SYNOPSIS
    Cuts, verifies and publishes a stable release from the current commit.

.DESCRIPTION
    The steps that used to be retyped by hand for every version, in one place and in the only safe order:

        1. Preflight: clean tree, version format, tag absent locally and on the remote.
        2. Write docs\RELEASE_<version>.md when it does not exist, from the commit subjects since
           the previous release tag.
        3. Bump <Version> in Directory.Build.props.
        4. Commit version + notes as "Release v<version>".
        5. Build-Portable.ps1 (Release, restore, build, test, publish five executables).
        6. Package-Portable.ps1 (manifest, SBOM, archive re-hash, checksums, evidence).
        7. Test-Portable.ps1 (every route, YARA helper, native window).
        8. Tag, push the commit and the tag, create the GitHub release as Latest.
        9. Compare every uploaded asset digest with the local file.

    Nothing is published unless the build, every test and both smokes pass. -NoPublish stops after the
    local package so a release can be inspected first; the commit and tag are still created.

.PARAMETER Version
    Three-part version to release, for example 0.1.45.

.PARAMETER SkipBuild
    Reuse the existing published folder (only when it was built from the current commit).

.PARAMETER SkipSmoke
    Skip the packaged route and window smoke. Not recommended for a release.

.PARAMETER NoPublish
    Do not push and do not create the GitHub release.

.PARAMETER NoPush
    Create the commit and tag locally, but do not push.

.PARAMETER KeepWorktree
    Commit on the current branch instead of refusing a non-main branch. The push still targets main.

.EXAMPLE
    pwsh ./tools/release/Cut-Release.ps1 -Version 0.1.45

.EXAMPLE
    pwsh ./tools/release/Cut-Release.ps1 -Version 0.1.45 -NoPublish
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$Version,

    [switch]$SkipBuild,
    [switch]$SkipSmoke,
    [switch]$NoPublish,
    [switch]$NoPush,
    [switch]$KeepWorktree
)

$ErrorActionPreference = 'Stop'
$env:GIT_TERMINAL_PROMPT = '0'

$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$artifacts = Join-Path $repo 'artifacts'
$remoteUrl = 'https://github.com/christiand0797/downpour-next.git'
$githubRepo = 'christiand0797/downpour-next'
$tag = "v$Version"
$notesRelative = "docs/RELEASE_$Version.md"
$notesPath = Join-Path $repo $notesRelative
$buildPropsPath = Join-Path $repo 'Directory.Build.props'
$buildLog = Join-Path $artifacts "build-release-$Version.log"

function Fail {
    param([string]$Message)
    Write-Host "RELEASE FAILED: $Message" -ForegroundColor Red
    exit 1
}

function Invoke-Git {
    param([string[]]$Arguments)
    $output = & git -C $repo @Arguments
    if ($LASTEXITCODE -ne 0) { Fail ("git " + ($Arguments -join ' ') + " failed with exit code $LASTEXITCODE") }
    return $output
}

function Get-TestCount {
    param([string]$LogPath)
    if (-not (Test-Path -LiteralPath $LogPath)) { return 0 }
    $text = Get-Content -LiteralPath $LogPath -Raw
    $matches = [regex]::Matches($text, 'Passed:\s+(\d+),\s+Skipped:')
    if ($matches.Count -eq 0) { return 0 }
    return [int]$matches[$matches.Count - 1].Groups[1].Value
}

# --- Preflight -------------------------------------------------------------

if (-not (Test-Path -LiteralPath (Join-Path $repo 'Downpour.slnx'))) { Fail "Not a Downpour repository: $repo" }
if (-not (Test-Path -LiteralPath $artifacts)) { New-Item -ItemType Directory -Path $artifacts | Out-Null }

$dirty = @(Invoke-Git @('status', '--porcelain'))
if ($dirty.Count -gt 0) {
    Fail ("The working tree has uncommitted changes; commit or stash them first.`n" + ($dirty -join "`n"))
}

& git -C $repo rev-parse --verify --quiet "refs/tags/$tag" | Out-Null
if ($LASTEXITCODE -eq 0) { Fail "Tag $tag already exists locally." }
$remoteTag = & git -C $repo ls-remote --tags $remoteUrl "refs/tags/$tag"
if ($LASTEXITCODE -ne 0) { Fail 'Could not query the remote for an existing tag.' }
if ($remoteTag) { Fail "Tag $tag already exists on the remote." }

$branch = (Invoke-Git @('rev-parse', '--abbrev-ref', 'HEAD')).Trim()
if ($branch -ne 'main' -and -not $KeepWorktree) {
    Fail "Releases are cut from main; HEAD is on '$branch'. Use -KeepWorktree only when the commit belongs on main."
}

$sourceCommit = (Invoke-Git @('rev-parse', 'HEAD')).Trim()
Write-Host "Cutting $tag from $sourceCommit on $branch" -ForegroundColor Cyan

# --- Notes -----------------------------------------------------------------

if (-not (Test-Path -LiteralPath $notesPath)) {
    $previousTag = & git -C $repo describe --tags --abbrev=0 --match 'v*' HEAD 2>$null
    $range = if ($previousTag) { "$previousTag..HEAD" } else { 'HEAD' }
    $subjects = @(& git -C $repo log --no-merges --pretty=format:'- %s' $range)
    if ($subjects.Count -eq 0) { $subjects = @('- No commits since the previous release tag.') }

    $notes = @"
# Downpour Next $Version

Released $(Get-Date -Format 'yyyy-MM-dd') from ``$sourceCommit``.

## Changes since $(if ($previousTag) { $previousTag } else { 'the first release' })

$($subjects -join "`n")

## Validation

Filled in by ``tools/release/Cut-Release.ps1`` when this file is generated: Release build with 0
warnings/errors, the full test suite, every packaged route, the YARA helper and the native window
smoke must pass before the release is published.

## Remaining work

See ``TODO.md`` for the open items this release does not close.
"@
    [IO.File]::WriteAllText($notesPath, $notes + [Environment]::NewLine)
    Write-Host "Wrote $notesRelative from commit subjects; review it before publishing." -ForegroundColor Yellow
}

# --- Version bump and commit ----------------------------------------------

$propsText = Get-Content -LiteralPath $buildPropsPath -Raw
$versionPattern = '<Version>[^<]+</Version>'
if ($propsText -notmatch $versionPattern) { Fail 'Directory.Build.props has no <Version> element.' }
$propsText = $propsText -replace $versionPattern, "<Version>$Version</Version>"
[IO.File]::WriteAllText($buildPropsPath, $propsText)

Invoke-Git @('add', 'Directory.Build.props', $notesRelative) | Out-Null
Invoke-Git @('commit', '-m', "Release $tag") | Out-Null
$sourceCommit = (Invoke-Git @('rev-parse', 'HEAD')).Trim()
Write-Host "Release commit $sourceCommit" -ForegroundColor Cyan

# --- Build -----------------------------------------------------------------

$testCount = 0
if ($SkipBuild) {
    Write-Host 'Skipping the build (-SkipBuild); the package must already match this commit.' -ForegroundColor Yellow
} else {
    Write-Host "==> Build-Portable.ps1 (log: $buildLog)" -ForegroundColor Cyan
    & pwsh -NoProfile -File (Join-Path $repo 'Build-Portable.ps1') -Configuration Release *>&1 |
        Tee-Object -FilePath $buildLog
    if ($LASTEXITCODE -ne 0) { Fail "Build-Portable.ps1 failed with exit code $LASTEXITCODE. See $buildLog" }
    $testCount = Get-TestCount -LogPath $buildLog
    if ($testCount -le 0) { Fail "The build log does not contain a passing test count. See $buildLog" }
    Write-Host "Release tests passed: $testCount" -ForegroundColor Green
}

# --- Package ---------------------------------------------------------------

Write-Host '==> Package-Portable.ps1' -ForegroundColor Cyan
$packageOutput = & pwsh -NoProfile -File (Join-Path $repo 'tools/release/Package-Portable.ps1') `
    -Version $Version -Commit $sourceCommit -TestCount $testCount *>&1
$packageOutput | Write-Host
if ($LASTEXITCODE -ne 0) { Fail "Packaging failed with exit code $LASTEXITCODE" }

$evidencePath = Join-Path $artifacts "v$Version-evidence.json"
if (-not (Test-Path -LiteralPath $evidencePath)) { Fail "Package evidence was not written: $evidencePath" }
$evidence = Get-Content -LiteralPath $evidencePath -Raw | ConvertFrom-Json
if ($evidence.sourceCommit -ne $sourceCommit) { Fail 'The package evidence names a different commit.' }

# --- Smoke -----------------------------------------------------------------

if ($SkipSmoke) {
    Write-Host 'Skipping the packaged smoke (-SkipSmoke).' -ForegroundColor Yellow
} else {
    Write-Host '==> Test-Portable.ps1' -ForegroundColor Cyan
    & pwsh -NoProfile -File (Join-Path $repo 'tools/release/Test-Portable.ps1') -Version $Version
    if ($LASTEXITCODE -ne 0) { Fail "Packaged smoke failed with exit code $LASTEXITCODE" }
}

# --- Tag, push, publish ----------------------------------------------------

Invoke-Git @('tag', '-a', $tag, '-F', $notesPath) | Out-Null
Write-Host "Tagged $tag" -ForegroundColor Cyan

if ($NoPush -or $NoPublish) {
    Write-Host 'Not pushing (-NoPush/-NoPublish).' -ForegroundColor Yellow
} else {
    Write-Host '==> Push commit and tag' -ForegroundColor Cyan
    Invoke-Git @('push', $remoteUrl, 'HEAD:main') | Out-Null
    Invoke-Git @('push', $remoteUrl, "refs/tags/$tag") | Out-Null
}

if ($NoPublish) {
    Write-Host 'Not publishing (-NoPublish).' -ForegroundColor Yellow
    Write-Host "Local package: $($evidence.zip)" -ForegroundColor Green
    exit 0
}

Write-Host '==> Create GitHub release' -ForegroundColor Cyan
$releaseTitle = "Downpour Next $Version"
& gh release create $tag -R $githubRepo --title $releaseTitle --notes-file $notesPath --latest `
    $evidence.zip $evidence.sbom $evidence.sums
if ($LASTEXITCODE -ne 0) { Fail "gh release create failed with exit code $LASTEXITCODE" }

Write-Host '==> Verify uploaded assets' -ForegroundColor Cyan
$releaseJson = & gh release view $tag -R $githubRepo --json assets
if ($LASTEXITCODE -ne 0) { Fail 'Could not read the published release.' }
$remoteAssets = ($releaseJson | ConvertFrom-Json).assets

$localAssets = @(
    @{ name = (Split-Path -Leaf $evidence.zip); path = $evidence.zip },
    @{ name = (Split-Path -Leaf $evidence.sbom); path = $evidence.sbom },
    @{ name = (Split-Path -Leaf $evidence.sums); path = $evidence.sums }
)
foreach ($local in $localAssets) {
    $remote = $remoteAssets | Where-Object { $_.name -eq $local.name }
    if (-not $remote) { Fail "Published release is missing asset $($local.name)" }
    $localHash = (Get-FileHash -LiteralPath $local.path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($remote.digest) {
        if ($remote.digest -ne "sha256:$localHash") {
            Fail "Uploaded asset digest mismatch for $($local.name): $($remote.digest) != sha256:$localHash"
        }
    } elseif ([int64]$remote.size -ne (Get-Item -LiteralPath $local.path).Length) {
        Fail "Uploaded asset size mismatch for $($local.name)"
    }
    Write-Host "  verified $($local.name)" -ForegroundColor DarkGray
}

Write-Host ''
Write-Host "Released $tag" -ForegroundColor Green
Write-Host "  commit : $sourceCommit"
Write-Host "  tests  : $testCount"
Write-Host "  archive: $($evidence.zip) ($($evidence.zipBytes) bytes)"
Write-Host "  sha256 : $($evidence.zipSha256)"
Write-Host "  notes  : $notesRelative"
