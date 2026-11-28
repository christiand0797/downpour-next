#Requires -Version 7.0
<#
.SYNOPSIS
    Registers (or removes) the DownpourNightly Windows scheduled task.

.DESCRIPTION
    The task runs tools\release\Invoke-Nightly.ps1 once a day as the signed-in user, at limited
    privilege, only while that user is logged on. That is deliberate:

      * gh uses the user's own keyring, so no token is stored in the task or in the repository;
      * the native window smoke needs an interactive desktop;
      * nothing runs elevated, and no service or system setting is touched.

    It starts when the machine was unavailable at the scheduled time, keeps running on battery, and
    gives up after two hours. A dedicated shallow clone is used by default so a cleaned-up worktree
    cannot break the schedule; -Bootstrap creates it with the user's existing git credentials.

.PARAMETER RepoPath
    Repository the nightly builds. Defaults to %USERPROFILE%\DownpourNext.

.PARAMETER At
    Local time of day, 24-hour, for example 03:30. Defaults to 03:30.

.PARAMETER TaskName
    Scheduled task name. Defaults to DownpourNightly.

.PARAMETER Bootstrap
    Create the clone at RepoPath with a shallow main checkout when it does not exist.

.PARAMETER RunNow
    Start the task once after registering it.

.PARAMETER Unregister
    Remove the task instead of creating it.

.EXAMPLE
    pwsh ./tools/release/Register-NightlyTask.ps1 -Bootstrap

.EXAMPLE
    pwsh ./tools/release/Register-NightlyTask.ps1 -Unregister
#>
[CmdletBinding()]
param(
    [string]$RepoPath = (Join-Path $env:USERPROFILE 'DownpourNext'),
    [ValidatePattern('^\d{2}:\d{2}$')]
    [string]$At = '03:30',
    [string]$TaskName = 'DownpourNightly',
    [switch]$Bootstrap,
    [switch]$RunNow,
    [switch]$Unregister
)

$ErrorActionPreference = 'Stop'

$githubRepo = 'christiand0797/downpour-next'
$remoteUrl = "https://github.com/$githubRepo.git"

function Fail {
    param([string]$Message)
    Write-Host "TASK SETUP FAILED: $Message" -ForegroundColor Red
    exit 1
}

if ($Unregister) {
    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $existing) {
        Write-Host "Task $TaskName is not registered." -ForegroundColor Yellow
        exit 0
    }
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "Removed scheduled task $TaskName." -ForegroundColor Green
    exit 0
}

if (-not $Bootstrap -and -not (Test-Path -LiteralPath $RepoPath)) {
    Fail "Repository not found: $RepoPath. Pass -Bootstrap to create it, or -RepoPath to point at an existing clone."
}

if ($Bootstrap -and -not (Test-Path -LiteralPath (Join-Path $RepoPath '.git'))) {
    if (Test-Path -LiteralPath $RepoPath) { Fail "Path exists but is not a git clone: $RepoPath" }
    $parent = Split-Path -Parent $RepoPath
    if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent | Out-Null }
    Write-Host "Cloning $remoteUrl into $RepoPath (shallow, main)" -ForegroundColor Cyan
    & git clone --depth 1 --branch main $remoteUrl $RepoPath
    if ($LASTEXITCODE -ne 0) { Fail "git clone failed with exit code $LASTEXITCODE. Check that git can reach GitHub as this user." }
}

$RepoPath = (Resolve-Path -LiteralPath $RepoPath).Path
$script = Join-Path $RepoPath 'tools/release/Invoke-Nightly.ps1'
if (-not (Test-Path -LiteralPath $script)) {
    Fail "The nightly script is missing from $RepoPath. Pull main first; the tooling must be committed before the task can run it."
}

$origin = (& git -C $RepoPath remote get-url origin 2>$null)
if ($LASTEXITCODE -ne 0 -or -not $origin -or $origin -notmatch 'downpour-next') {
    Fail "The clone's origin does not point at downpour-next: $origin"
}

$pwshPath = (Get-Command pwsh).Source
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

$action = New-ScheduledTaskAction -Execute $pwshPath `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$script`" -RepoPath `"$RepoPath`"" `
    -WorkingDirectory $RepoPath

$trigger = New-ScheduledTaskTrigger -Daily -At $At

$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -DontStopOnIdleEnd `
    -StartWhenAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Hours 2) `
    -MultipleInstances IgnoreNew

$principal = New-ScheduledTaskPrincipal -UserId $identity -LogonType Interactive -RunLevel Limited

$description = 'Builds, verifies and publishes a Downpour Next nightly prerelease from main when it has new commits. Runs unelevated as the signed-in user so gh uses its own keyring and the window smoke has a desktop.'

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings `
    -Principal $principal -Description $description -Force | Out-Null

$task = Get-ScheduledTask -TaskName $TaskName
$info = Get-ScheduledTaskInfo -TaskName $TaskName
Write-Host ''
Write-Host "Registered $TaskName" -ForegroundColor Green
Write-Host "  runs    : daily at $At, only while $identity is signed in"
Write-Host "  command : $pwshPath"
Write-Host "  script  : $script"
Write-Host "  repo    : $RepoPath"
Write-Host "  state   : $($task.State); next run $($info.NextRunTime)"
Write-Host '  note    : limited privilege, starts when available, continues on battery, 2-hour limit'

if ($RunNow) {
    Write-Host ''
    Write-Host 'Starting the task once (verify with Get-ScheduledTaskInfo / artifacts\nightly).' -ForegroundColor Cyan
    Start-ScheduledTask -TaskName $TaskName
}
