param(
    [string]$RustyNetRoot = 'C:\Rustynet',
    [string]$StateRoot = 'C:\ProgramData\RustyNet',
    [switch]$ExerciseFullBlock,
    [switch]$ExerciseDns,
    [switch]$ExerciseIpv6,
    [int]$TimeoutSeconds = 90,
    [int]$DeadManSeconds = 180,
    [string]$OutputPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$script:SmokeFailureStep = 'init'
$script:DeadManTaskName = 'RustyNetKillswitchDeadMan'

# Defense-in-depth: the orchestrator only ever passes the canonical state root.
# Reject anything else so the helper can never be redirected at an injected
# path (mirrors Invoke-RustyNetWindowsTunnelSmoke.ps1).
if ($StateRoot -ne 'C:\ProgramData\RustyNet') {
    throw ('state root must be C:\ProgramData\RustyNet; received {0}' -f $StateRoot)
}

function New-FailClosedKillswitchReport {
    param([Parameter(Mandatory = $true)][string]$FailureReason)
    return [ordered]@{
        schema_version   = 1
        captured_at_utc  = (Get-Date).ToUniversalTime().ToString('o')
        platform         = 'windows'
        rustynet_root    = $RustyNetRoot
        state_root       = $StateRoot
        status           = 'fail'
        reason           = $FailureReason
        overall_ok       = $false
        daemon_exit_code = $null
        failure_step     = $script:SmokeFailureStep
        killswitch_report = $null
        notes            = @('killswitch-smoke-helper-trap')
    }
}

function Write-FailClosedKillswitchReportIfRequested {
    param([Parameter(Mandatory = $true)][string]$FailureReason)
    if (-not $OutputPath -or $OutputPath.Trim().Length -eq 0) {
        return
    }
    try {
        $outputDirectory = Split-Path -Parent $OutputPath
        if ($outputDirectory -and -not (Test-Path -LiteralPath $outputDirectory)) {
            New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
        }
        (New-FailClosedKillswitchReport -FailureReason $FailureReason | ConvertTo-Json -Depth 8) |
            Set-Content -Encoding utf8 -LiteralPath $OutputPath
    }
    catch {
        # Preserve the original failure as the dominant root cause.
    }
}

# Best-effort: restore the default allow-outbound policy so a wedged killswitch
# can never strand SSH. Runs locally, so it recovers connectivity even while an
# SSH session's outbound replies are being dropped.
function Restore-FirewallOutbound {
    try {
        & netsh.exe advfirewall set allprofiles firewallpolicy allowinbound,allowoutbound | Out-Null
    }
    catch {
        # Nothing else we can do here; the scheduled dead-man's-switch is the backstop.
    }
}

function Test-FirewallOutboundAllowed {
    try {
        $show = (& netsh.exe advfirewall show allprofiles | Out-String)
        return ($show -notmatch 'BlockOutbound')
    }
    catch {
        return $false
    }
}

# Dead-man's-switch: schedule a one-shot SYSTEM task that restores allow-outbound
# in $DeadManSeconds, so even a hard daemon crash mid-block (which bypasses the
# daemon's in-process Drop guard) cannot brick SSH on the guest. Armed BEFORE the
# killswitch is ever applied; a failure to arm it throws here, before any block,
# so we can never apply a killswitch we cannot guarantee to undo.
function Register-FirewallDeadMan {
    param([int]$Seconds)
    $delay = [Math]::Max(60, $Seconds)
    $runAt = (Get-Date).AddSeconds($delay)
    $st = $runAt.ToString('HH:mm')
    $restore = 'netsh advfirewall set allprofiles firewallpolicy allowinbound,allowoutbound'
    # /SD is omitted: the run time is only minutes out, so "today" is correct
    # except within a couple of minutes of midnight (acceptable for a lab smoke),
    # and omitting it sidesteps locale-specific date formatting.
    $out = (& schtasks.exe /Create /TN $script:DeadManTaskName /SC ONCE /ST $st `
            /RL HIGHEST /RU SYSTEM /TR ('cmd /c ' + $restore) /F 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) {
        throw ('failed to arm firewall dead-man''s-switch (schtasks exit {0}): {1}' -f $LASTEXITCODE, $out.Trim())
    }
}

function Unregister-FirewallDeadMan {
    try {
        & schtasks.exe /Delete /TN $script:DeadManTaskName /F 2>&1 | Out-Null
    }
    catch {
        # A leftover one-shot task only restores allow-outbound and then expires;
        # harmless if it lingers.
    }
}

trap {
    $failureReason = if ($_.Exception -and $_.Exception.Message) {
        $_.Exception.Message.Trim()
    }
    else {
        ($_ | Out-String).Trim()
    }
    if (-not $failureReason) {
        $failureReason = 'windows-killswitch-smoke-exception'
    }
    # Safety first: restore outbound locally in case we threw mid-block, then let
    # the dead-man's-switch keep covering us if that restore did not take.
    Restore-FirewallOutbound
    Write-FailClosedKillswitchReportIfRequested -FailureReason $failureReason
    Write-Error $_
    exit 1
}

# A real killswitch exercise (netsh policy + WFP filters + tunnel bring-up)
# requires administrator rights. Fail closed with a precise reason.
$script:SmokeFailureStep = 'admin-check'
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'windows-killswitch-smoke requires administrator rights (netsh policy + WFP + installtunnelservice)'
}

$script:SmokeFailureStep = 'locate-daemon'
$daemonPath = Join-Path $RustyNetRoot 'target\release\rustynetd.exe'
if (-not (Test-Path -LiteralPath $daemonPath)) {
    throw ('rustynetd.exe was not found under the Windows release output directory: {0}' -f $daemonPath)
}

$daemonArgs = [System.Collections.Generic.List[string]]::new()
$daemonArgs.Add('windows-killswitch-smoke')
if ($ExerciseFullBlock.IsPresent) { $daemonArgs.Add('--exercise-full-block') }
if ($ExerciseDns.IsPresent) { $daemonArgs.Add('--exercise-dns') }
if ($ExerciseIpv6.IsPresent) { $daemonArgs.Add('--exercise-ipv6') }

# Arm the dead-man's-switch BEFORE any killswitch can be applied.
$script:SmokeFailureStep = 'arm-deadman'
Register-FirewallDeadMan -Seconds $DeadManSeconds

$script:SmokeFailureStep = 'run-daemon'
$probeRoot = Join-Path $env:TEMP ('rustynet-killswitch-smoke-' + [guid]::NewGuid().ToString('N'))
$stdoutPath = Join-Path $probeRoot 'stdout.json'
$stderrPath = Join-Path $probeRoot 'stderr.log'
New-Item -ItemType Directory -Force -Path $probeRoot | Out-Null
$daemonExit = $null
$timedOut = $false
$stdoutText = ''
$stderrText = ''
try {
    $process = Start-Process `
        -FilePath $daemonPath `
        -ArgumentList $daemonArgs.ToArray() `
        -NoNewWindow `
        -PassThru `
        -RedirectStandardOutput $stdoutPath `
        -RedirectStandardError $stderrPath
    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        $timedOut = $true
    }
    else {
        $daemonExit = [int]$process.ExitCode
    }
    if (Test-Path -LiteralPath $stdoutPath) { $stdoutText = [string](Get-Content -Raw -LiteralPath $stdoutPath) }
    if (Test-Path -LiteralPath $stderrPath) { $stderrText = [string](Get-Content -Raw -LiteralPath $stderrPath) }
}
finally {
    # Whatever happened to the daemon, make sure outbound is restored locally and
    # only then retire the dead-man's-switch. If we cannot confirm the restore,
    # deliberately LEAVE the scheduled task armed so it fires.
    Restore-FirewallOutbound
    if (Test-FirewallOutboundAllowed) {
        Unregister-FirewallDeadMan
    }
    Remove-Item -LiteralPath $probeRoot -Recurse -Force -ErrorAction SilentlyContinue
}

if (-not $stdoutText) { $stdoutText = '' }
if (-not $stderrText) { $stderrText = '' }

# The daemon prints its killswitch-smoke report (overall_ok et al.) as JSON on
# stdout. On a hard failure before the report is rendered there is no JSON, so
# fail closed and carry the daemon's stderr as the dominant root cause.
$script:SmokeFailureStep = 'parse-daemon-report'
$killswitchReport = $null
$parseError = $null
if ($stdoutText.Trim().Length -gt 0) {
    try {
        $killswitchReport = $stdoutText | ConvertFrom-Json
    }
    catch {
        $parseError = $_.Exception.Message
    }
}

$overallOk = $false
if ($null -ne $killswitchReport -and ($killswitchReport.PSObject.Properties.Name -contains 'overall_ok')) {
    $overallOk = [bool]$killswitchReport.overall_ok
}

# A pass requires every signal to agree: the daemon was not killed for timing
# out, it exited 0, and its report asserts overall_ok. Anything else fails closed.
$status = if (-not $timedOut -and $daemonExit -eq 0 -and $overallOk) { 'pass' } else { 'fail' }

$stderrExcerpt = $stderrText.Trim()
if ($stderrExcerpt.Length -gt 400) { $stderrExcerpt = $stderrExcerpt.Substring(0, 400) }
$reason = ''
if ($status -ne 'pass') {
    if ($timedOut) {
        $reason = ('daemon timed out after {0}s and was killed; firewall was restored and the dead-man''s-switch covered the block window; stderr: {1}' -f $TimeoutSeconds, $stderrExcerpt)
    }
    elseif ($null -eq $killswitchReport) {
        $reason = if ($parseError) {
            ('daemon report was not valid JSON: {0}; stderr: {1}' -f $parseError, $stderrExcerpt)
        }
        else {
            ('daemon emitted no killswitch-smoke report; exit={0}; stderr: {1}' -f $daemonExit, $stderrExcerpt)
        }
    }
    else {
        $reason = ('killswitch did not apply/rollback cleanly (overall_ok={0}, exit={1})' -f $overallOk, $daemonExit)
    }
}

$failureStep = if ($status -eq 'pass') { '' } else { 'run-daemon' }
$report = [ordered]@{
    schema_version    = 1
    captured_at_utc   = (Get-Date).ToUniversalTime().ToString('o')
    platform          = 'windows'
    rustynet_root     = $RustyNetRoot
    state_root        = $StateRoot
    status            = $status
    reason            = $reason
    overall_ok        = $overallOk
    daemon_exit_code  = $daemonExit
    failure_step      = $failureStep
    killswitch_report = $killswitchReport
    notes             = @()
}

$json = $report | ConvertTo-Json -Depth 8
if ($OutputPath) {
    $outputDirectory = Split-Path -Parent $OutputPath
    if ($outputDirectory -and -not (Test-Path -LiteralPath $outputDirectory)) {
        New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
    }
    $json | Set-Content -Encoding utf8 -LiteralPath $OutputPath
}
$json | Write-Output

# Exit 0 on the normal path even when status=fail: the orchestrator's SSH capture
# wrapper throws on any non-zero helper exit, which would discard this JSON and
# hide the precise verdict. The JSON status/overall_ok fields carry the result
# and parse_windows_killswitch_smoke_output decides pass/fail. A non-zero exit is
# reserved for the fail-closed trap (a genuine helper exception).
