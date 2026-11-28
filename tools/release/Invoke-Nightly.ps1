#Requires -Version 7.0
<#
.SYNOPSIS
    Builds, verifies and publishes a nightly prerelease from main when there is new work to ship.

.DESCRIPTION
    Designed for Windows Task Scheduler (see Register-NightlyTask.ps1), but safe to run by hand.

        1. Refuse a dirty tree, a non-main branch or a repository that is not downpour-next.
        2. Fetch and fast-forward main. A diverged clone fails instead of discarding anything.
        3. Skip when HEAD is the commit the last nightly already published, unless -Force.
        4. Build-Portable.ps1, then Package-Portable.ps1 with the nightly-YYYYMMDD label.
        5. Test-Portable.ps1 (every route, YARA helper, native window).
        6. Publish prerelease nightly-YYYYMMDD at the built commit, never marked Latest.
        7. Delete nightly releases older than -KeepDays.
        8. Record state and write artifacts\nightly\<date>-report.md, including the next queued
           WORK_QUEUE tasks, so the morning starts with a real list instead of a guess.

    A failed step leaves the previous nightly and the stable release untouched. Logs and reports live
    under artifacts\nightly\, which is gitignored.

.PARAMETER RepoPath
    Repository to build. Defaults to this script's repository. The scheduled task points it at a
    dedicated clone so a worktree being cleaned up cannot break the schedule.

.PARAMETER Date
    Nightly label date (yyyyMMdd). Defaults to today.

.PARAMETER KeepDays
    Delete nightly releases older than this many days. Defaults to 7; 0 keeps everything.

.PARAMETER Force
    Rebuild and republish even when HEAD matches the last published nightly.

.PARAMETER SkipBuild
    Reuse the existing published folder (must already match HEAD).

.PARAMETER SkipSmoke
    Skip the packaged smoke. Not recommended.

.PARAMETER NoTestRetry
    Fail on the first failing test run. By default a failed test gate is rerun once in full and the
    first attempt's failures are recorded; a failure that repeats still stops the nightly.

.PARAMETER NoPublish
    Build, package and smoke locally without creating a GitHub release.

.EXAMPLE
    pwsh ./tools/release/Invoke-Nightly.ps1

.EXAMPLE
    pwsh ./tools/release/Invoke-Nightly.ps1 -RepoPath "$env:USERPROFILE\DownpourNext" -Force
#>
[CmdletBinding()]
param(
    [string]$RepoPath,
    [string]$Date = (Get-Date -Format 'yyyyMMdd'),
    [int]$KeepDays = 7,
    [switch]$Force,
    [switch]$SkipBuild,
    [switch]$SkipSmoke,
    [switch]$NoTestRetry,
    [switch]$NoPublish
)

$ErrorActionPreference = 'Stop'
$env:GIT_TERMINAL_PROMPT = '0'

$scriptRepo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$repo = if ($RepoPath) { (Resolve-Path -LiteralPath $RepoPath).Path } else { $scriptRepo }
$githubRepo = 'christiand0797/downpour-next'
$remoteUrl = "https://github.com/$githubRepo.git"
$tag = "nightly-$Date"

$artifacts = Join-Path $repo 'artifacts'
$nightlyDir = Join-Path $artifacts 'nightly'
$logDir = Join-Path $nightlyDir 'logs'
[IO.Directory]::CreateDirectory($logDir) | Out-Null
$logPath = Join-Path $logDir "nightly-$Date.log"
$statePath = Join-Path $nightlyDir 'state.json'
$reportPath = Join-Path $nightlyDir "$Date-report.md"

$state = [ordered]@{
    lastCommit = $null
    lastTag    = $null
    lastRunUtc = $null
    lastResult = 'never'
    lastError  = $null
}

function Write-Log {
    param([string]$Message)
    $line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Message"
    Write-Host $line
    Add-Content -LiteralPath $logPath -Value $line
}

function Fail {
    param([string]$Message)
    Write-Log "FAILED: $Message"
    $state.lastRunUtc = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $state.lastResult = 'failed'
    $state.lastError = $Message
    $state | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $statePath -Encoding utf8
    exit 1
}

function Invoke-Git {
    param([string[]]$Arguments)
    $output = & git -C $repo @Arguments
    if ($LASTEXITCODE -ne 0) { Fail ("git " + ($Arguments -join ' ') + " failed with exit code $LASTEXITCODE") }
    return $output
}

function Get-TestCount {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return 0 }
    $text = Get-Content -LiteralPath $Path -Raw
    $matches = [regex]::Matches($text, 'Passed:\s+(\d+),\s+Skipped:')
    if ($matches.Count -eq 0) { return 0 }
    return [int]$matches[$matches.Count - 1].Groups[1].Value
}

Write-Log "Downpour Next nightly $Date starting in $repo"

# --- Preflight and sync ----------------------------------------------------

if (-not (Test-Path -LiteralPath (Join-Path $repo 'Downpour.slnx'))) { Fail "Not a Downpour repository: $repo" }
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) { Fail 'The GitHub CLI (gh) is not on PATH.' }
if (-not (Get-Command git -ErrorAction SilentlyContinue)) { Fail 'git is not on PATH.' }

$origin = (& git -C $repo remote get-url origin 2>$null)
if ($LASTEXITCODE -ne 0 -or -not $origin -or $origin -notmatch 'downpour-next') {
    Fail "The repository's origin does not point at downpour-next: $origin"
}

$branch = (& git -C $repo rev-parse --abbrev-ref HEAD).Trim()
if ($branch -ne 'main') { Fail "The nightly builds main; HEAD is on '$branch'." }

$dirty = @(& git -C $repo status --porcelain)
if ($dirty.Count -gt 0) {
    Fail ("The nightly clone has uncommitted changes and will not discard them.`n" + ($dirty -join "`n"))
}

Write-Log 'Fetching origin/main'
& git -C $repo fetch --prune origin main | Out-Null
if ($LASTEXITCODE -ne 0) { Fail 'git fetch failed.' }
& git -C $repo merge --ff-only origin/main | Out-Null
if ($LASTEXITCODE -ne 0) { Fail 'main has diverged from origin/main; the nightly does not merge or rebase automatically.' }

$head = (& git -C $repo rev-parse HEAD).Trim()
$shortHead = $head.Substring(0, 12)
Write-Log "HEAD is $shortHead"

if (Test-Path -LiteralPath $statePath) {
    $previous = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    if ($previous.lastCommit) { $state.lastCommit = [string]$previous.lastCommit }
    if ($previous.lastTag) { $state.lastTag = [string]$previous.lastTag }
}

if ($state.lastCommit -eq $head -and -not $Force) {
    Write-Log "Skipping: $shortHead is already the last published nightly ($($state.lastTag))."
    $state.lastRunUtc = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $state.lastResult = 'skipped-no-changes'
    $state | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $statePath -Encoding utf8
    Get-Content -LiteralPath $statePath -Raw | Write-Host
    exit 0
}

# --- Build -----------------------------------------------------------------

$buildLog = Join-Path $logDir "build-$Date.log"
$retryLog = Join-Path $logDir "test-retry-$Date.log"
$testCount = 0
$firstAttemptFailures = @()
$testRetryUsed = $false
if ($SkipBuild) {
    Write-Log 'Skipping the build (-SkipBuild).'
} else {
    Write-Log "Building (log: $buildLog)"
    & pwsh -NoProfile -File (Join-Path $repo 'Build-Portable.ps1') -Configuration Release *>&1 |
        Tee-Object -FilePath $buildLog | ForEach-Object { Add-Content -LiteralPath $logPath -Value $_ }
    if ($LASTEXITCODE -ne 0) {
        $failureText = if (Test-Path -LiteralPath $buildLog) { Get-Content -LiteralPath $buildLog -Raw } else { '' }
        $failureMatch = [regex]::Match($failureText, 'Failed!\s+-\s+Failed:\s+(\d+),\s+Passed:\s+(\d+)')
        if (-not $failureMatch.Success) {
            Fail "Build-Portable.ps1 failed before the test gate. See $buildLog"
        }
        $firstAttemptFailures = @(
            [regex]::Matches($failureText, '\[xUnit\.net[^\]]*\]\s+(\S+)\s+\[FAIL\]') |
                ForEach-Object { $_.Groups[1].Value } |
                Sort-Object -Unique
        )
        $firstLine = ($failureText -split "`n" | Where-Object { $_ -match 'Failed!\s+-\s+Failed:' } | Select-Object -Last 1).Trim()
        if ($NoTestRetry) { Fail "The test gate failed and -NoTestRetry is set: $firstLine" }
        Write-Log "Test gate failed on attempt 1: $firstLine"
        Write-Log ('Failing tests: ' + ($firstAttemptFailures -join ', '))
        Write-Log 'Rerunning the full suite once against the same binaries (a cold clone can miss its timing budgets).'

        & dotnet test (Join-Path $repo 'Downpour.slnx') -c Release --no-build --no-restore --nologo `
            --blame-hang-timeout 10m *>&1 |
            Tee-Object -FilePath $retryLog | ForEach-Object { Add-Content -LiteralPath $logPath -Value $_ }
        if ($LASTEXITCODE -ne 0) {
            $retryText = Get-Content -LiteralPath $retryLog -Raw
            $retryFailures = @(
                [regex]::Matches($retryText, '\[xUnit\.net[^\]]*\]\s+(\S+)\s+\[FAIL\]') |
                    ForEach-Object { $_.Groups[1].Value } |
                    Sort-Object -Unique
            )
            Fail ('The test gate failed twice. First attempt: ' + ($firstAttemptFailures -join ', ') +
                '. Rerun: ' + ($retryFailures -join ', '))
        }
        $testCount = Get-TestCount -Path $retryLog
        if ($testCount -le 0) { Fail "The retry log has no passing test count. See $retryLog" }
        $testRetryUsed = $true
        Write-Log "Retry passed with $testCount tests. Republishing without the test gate."

        & pwsh -NoProfile -File (Join-Path $repo 'Build-Portable.ps1') -Configuration Release -SkipTests *>&1 |
            Tee-Object -FilePath (Join-Path $logDir "publish-$Date.log") |
            ForEach-Object { Add-Content -LiteralPath $logPath -Value $_ }
        if ($LASTEXITCODE -ne 0) { Fail "The publish after the retry failed with exit code $LASTEXITCODE" }
    } else {
        $testCount = Get-TestCount -Path $buildLog
        if ($testCount -le 0) { Fail "The build log has no passing test count. See $buildLog" }
        Write-Log "Release tests passed: $testCount"
    }
}

$buildProps = Get-Content -LiteralPath (Join-Path $repo 'Directory.Build.props') -Raw
if ($buildProps -notmatch '<Version>([^<]+)</Version>') { Fail 'Could not read <Version> from Directory.Build.props.' }
$version = $matches[1]

# --- Package ---------------------------------------------------------------

Write-Log "Packaging as nightly-$Date"
$packageOutput = & pwsh -NoProfile -File (Join-Path $repo 'tools/release/Package-Portable.ps1') `
    -Version $version -Commit $head -TestCount $testCount -Label "nightly-$Date" -AllowExistingArchive *>&1
$packageOutput | ForEach-Object { Write-Host $_; Add-Content -LiteralPath $logPath -Value $_ }
if ($LASTEXITCODE -ne 0) { Fail "Packaging failed with exit code $LASTEXITCODE" }

$evidencePath = Join-Path $artifacts "vnightly-$Date-evidence.json"
if (-not (Test-Path -LiteralPath $evidencePath)) { Fail "Package evidence was not written: $evidencePath" }
$evidence = Get-Content -LiteralPath $evidencePath -Raw | ConvertFrom-Json
if ($evidence.sourceCommit -ne $head) { Fail 'The package evidence names a different commit.' }

# --- Smoke -----------------------------------------------------------------

if ($SkipSmoke) {
    Write-Log 'Skipping the packaged smoke (-SkipSmoke).'
} else {
    Write-Log 'Running the packaged route, scanner and window smoke'
    & pwsh -NoProfile -File (Join-Path $repo 'tools/release/Test-Portable.ps1') `
        -Version $version -Label "nightly-$Date" -PackagePath (Join-Path $artifacts "DownpourNext-win-x64-$version") *>&1 |
        ForEach-Object { Write-Host $_; Add-Content -LiteralPath $logPath -Value $_ }
    if ($LASTEXITCODE -ne 0) { Fail "Packaged smoke failed with exit code $LASTEXITCODE" }
}

# --- Notes and publish -----------------------------------------------------

$commits = @(& git -C $repo log --no-merges --since='36 hours ago' --pretty=format:'- %s' HEAD)
if ($commits.Count -eq 0) { $commits = @('- No non-merge commits in the last 36 hours.') }

$notesPath = Join-Path $nightlyDir "$Date-notes.md"
$validation = if ($testCount -gt 0) { "$testCount Release tests passed" } else { 'the existing build was reused' }
$retrySentence = if ($testRetryUsed) {
    "A first test attempt failed (``$($firstAttemptFailures -join '``, ``')``); the full suite was rerun once and passed."
} else {
    ''
}
$notes = @"
# Downpour Next nightly $Date

Prerelease built from ``main`` at ``$head``.

## Commits in the last 36 hours

$($commits -join "`n")

## Validation

- Release build and $validation.
$retrySentence
- Every packaged route, the YARA helper and the native window smoke passed.
- Unsigned portable package; this is a prerelease, not the latest stable build.

Full history: https://github.com/$githubRepo/compare/$($state.lastCommit ?? 'main')...$head
"@

if ($NoPublish) {
    Write-Log 'Not publishing (-NoPublish); the local package and evidence are complete.'
} else {
    $existing = & gh release view $tag -R $githubRepo --json tagName 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Log "Release $tag already exists; uploading the rebuilt assets over it"
        & gh release upload $tag -R $githubRepo --clobber $evidence.zip $evidence.sbom $evidence.sums
        if ($LASTEXITCODE -ne 0) { Fail "gh release upload failed with exit code $LASTEXITCODE" }
    } else {
        Write-Log "Creating prerelease $tag at $shortHead"
        & gh release create $tag -R $githubRepo --title "Downpour Next nightly $Date" `
            --notes-file $notesPath --prerelease --target $head `
            $evidence.zip $evidence.sbom $evidence.sums
        if ($LASTEXITCODE -ne 0) { Fail "gh release create failed with exit code $LASTEXITCODE" }
    }

    Write-Log 'Verifying uploaded assets'
    $releaseJson = & gh release view $tag -R $githubRepo --json assets
    if ($LASTEXITCODE -ne 0) { Fail 'Could not read the published release.' }
    $remoteAssets = ($releaseJson | ConvertFrom-Json).assets
    foreach ($local in @(
        @{ name = (Split-Path -Leaf $evidence.zip); path = $evidence.zip },
        @{ name = (Split-Path -Leaf $evidence.sbom); path = $evidence.sbom },
        @{ name = (Split-Path -Leaf $evidence.sums); path = $evidence.sums }
    )) {
        $remote = $remoteAssets | Where-Object { $_.name -eq $local.name }
        if (-not $remote) { Fail "Published release is missing asset $($local.name)" }
        $localHash = (Get-FileHash -LiteralPath $local.path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($remote.digest) {
            if ($remote.digest -ne "sha256:$localHash") {
                Fail "Uploaded digest mismatch for $($local.name): $($remote.digest) != sha256:$localHash"
            }
        } elseif ([int64]$remote.size -ne (Get-Item -LiteralPath $local.path).Length) {
            Fail "Uploaded size mismatch for $($local.name)"
        }
    }
    Write-Log 'Uploaded assets match the local files.'

    if ($KeepDays -gt 0) {
        Write-Log "Pruning nightly releases older than $KeepDays days"
        $cutoff = [DateTime]::UtcNow.AddDays(-$KeepDays)
        $releases = & gh release list -R $githubRepo --limit 200 --json tagName,createdAt | ConvertFrom-Json
        foreach ($release in $releases) {
            if ($release.tagName -notmatch '^nightly-\d{8}$') { continue }
            if ([DateTime]$release.createdAt -ge $cutoff) { continue }
            Write-Log "Deleting old nightly $($release.tagName)"
            & gh release delete $release.tagName -R $githubRepo --yes --cleanup-tag | Out-Null
        }
    }
}

# --- Report ----------------------------------------------------------------

$queue = @()
$queuePath = Join-Path $repo 'WORK_QUEUE.json'
if (Test-Path -LiteralPath $queuePath) {
    $queueData = Get-Content -LiteralPath $queuePath -Raw | ConvertFrom-Json
    $queue = @($queueData.tasks | Where-Object { $_.status -eq 'queued' } | Select-Object -First 5)
}
$queueLines = if ($queue.Count -gt 0) {
    ($queue | ForEach-Object { "- ``$($_.id)`` $($_.title) ($($_.priority))" }) -join "`n"
} else {
    '- The queue has no queued tasks; choose the next enhancement in TODO.md.'
}

$report = @"
# Nightly $Date

- Result: **passed**
- Commit: ``$head``
- Version: $version
- Tests: $testCount$(if ($testRetryUsed) { " (passed on rerun; first attempt failed: $($firstAttemptFailures -join ', '))" })
- Archive: ``$(Split-Path -Leaf $evidence.zip)`` ($($evidence.zipBytes) bytes)
- SHA-256: ``$($evidence.zipSha256)``
- Release: $(if ($NoPublish) { 'not published (-NoPublish)' } else { "https://github.com/$githubRepo/releases/tag/$tag" })

## Next queued work

$queueLines

Logs: ``artifacts/nightly/logs/nightly-$Date.log``
"@
[IO.File]::WriteAllText($reportPath, $report + [Environment]::NewLine)

$state.lastCommit = $head
$state.lastTag = if ($NoPublish) { $state.lastTag } else { $tag }
$state.lastRunUtc = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
$state.lastResult = 'passed'
$state.lastError = $null
$state | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $statePath -Encoding utf8

Write-Log "Nightly $Date passed. Report: $reportPath"
exit 0
