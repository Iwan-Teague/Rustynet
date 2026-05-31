param(
    [string]$RustyNetRoot = 'C:\Rustynet',
    [string]$StateRoot = 'C:\ProgramData\RustyNet',
    [string]$TunnelName,
    [string]$Address,
    [string]$MeshCidr,
    [int]$ListenPort,
    [switch]$Keep,
    [int]$TimeoutSeconds = 120,
    [string]$OutputPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$script:SmokeFailureStep = 'init'

# Defense-in-depth: the orchestrator only ever passes the canonical state root.
# Reject anything else so the helper can never be redirected at an injected
# path (mirrors Smoke-RustyNetWindowsServiceHost.ps1).
if ($StateRoot -ne 'C:\ProgramData\RustyNet') {
    throw ('state root must be C:\ProgramData\RustyNet; received {0}' -f $StateRoot)
}

function New-FailClosedTunnelSmokeReport {
    param([Parameter(Mandatory = $true)][string]$FailureReason)
    return [ordered]@{
        schema_version  = 1
        captured_at_utc = (Get-Date).ToUniversalTime().ToString('o')
        platform        = 'windows'
        rustynet_root   = $RustyNetRoot
        state_root      = $StateRoot
        status          = 'fail'
        reason          = $FailureReason
        overall_ok      = $false
        daemon_exit_code = $null
        failure_step    = $script:SmokeFailureStep
        tunnel_report   = $null
        notes           = @('tunnel-smoke-helper-trap')
    }
}

function Write-FailClosedTunnelSmokeReportIfRequested {
    param([Parameter(Mandatory = $true)][string]$FailureReason)
    if (-not $OutputPath -or $OutputPath.Trim().Length -eq 0) {
        return
    }
    try {
        $outputDirectory = Split-Path -Parent $OutputPath
        if ($outputDirectory -and -not (Test-Path -LiteralPath $outputDirectory)) {
            New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
        }
        (New-FailClosedTunnelSmokeReport -FailureReason $FailureReason | ConvertTo-Json -Depth 8) |
            Set-Content -Encoding utf8 -LiteralPath $OutputPath
    }
    catch {
        # Preserve the original failure as the dominant root cause.
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
        $failureReason = 'windows-tunnel-smoke-exception'
    }
    Write-FailClosedTunnelSmokeReportIfRequested -FailureReason $failureReason
    Write-Error $_
    exit 1
}

# A real tunnel bring-up (wireguard.exe /installtunnelservice + netsh address)
# requires administrator rights. Fail closed with a precise reason rather than
# letting the daemon emit an opaque privilege error mid-bring-up.
$script:SmokeFailureStep = 'admin-check'
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'windows-tunnel-smoke requires administrator rights (installtunnelservice + netsh)'
}

$script:SmokeFailureStep = 'locate-daemon'
$daemonPath = Join-Path $RustyNetRoot 'target\release\rustynetd.exe'
if (-not (Test-Path -LiteralPath $daemonPath)) {
    throw ('rustynetd.exe was not found under the Windows release output directory: {0}' -f $daemonPath)
}

# Build the subcommand args. Tunnel options are only forwarded when the caller
# overrides them, so the daemon remains the single source of truth for the
# default tunnel shape (rustynet0 / 100.64.0.1/32 / 100.64.0.0/10 / 51820).
$daemonArgs = [System.Collections.Generic.List[string]]::new()
$daemonArgs.Add('windows-tunnel-smoke')
if ($PSBoundParameters.ContainsKey('TunnelName')) { $daemonArgs.Add('--tunnel-name'); $daemonArgs.Add($TunnelName) }
if ($PSBoundParameters.ContainsKey('Address')) { $daemonArgs.Add('--address'); $daemonArgs.Add($Address) }
if ($PSBoundParameters.ContainsKey('MeshCidr')) { $daemonArgs.Add('--mesh-cidr'); $daemonArgs.Add($MeshCidr) }
if ($PSBoundParameters.ContainsKey('ListenPort')) { $daemonArgs.Add('--listen-port'); $daemonArgs.Add([string]$ListenPort) }
if ($Keep.IsPresent) { $daemonArgs.Add('--keep') }

# Bound the privileged bring-up with a timeout + kill (same proven pattern as
# Verify-RustyNetWindowsBootstrap.ps1) so a wedged WMI provider or a hung driver
# call can never hang the smoke indefinitely. NOTE: if the daemon is killed
# mid-bring-up it may leave a tunnel service installed; the timeout reason flags
# this so the operator can clean up.
$script:SmokeFailureStep = 'run-daemon'
$probeRoot = Join-Path $env:TEMP ('rustynet-tunnel-smoke-' + [guid]::NewGuid().ToString('N'))
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
    Remove-Item -LiteralPath $probeRoot -Recurse -Force -ErrorAction SilentlyContinue
}

if (-not $stdoutText) { $stdoutText = '' }
if (-not $stderrText) { $stderrText = '' }

# The daemon prints its tunnel-smoke report (overall_ok et al.) as JSON on
# stdout. On a hard failure before the report is rendered there is no JSON, so
# fail closed and carry the daemon's stderr as the dominant root cause.
$script:SmokeFailureStep = 'parse-daemon-report'
$tunnelReport = $null
$parseError = $null
if ($stdoutText.Trim().Length -gt 0) {
    try {
        $tunnelReport = $stdoutText | ConvertFrom-Json
    }
    catch {
        $parseError = $_.Exception.Message
    }
}

$overallOk = $false
if ($null -ne $tunnelReport -and ($tunnelReport.PSObject.Properties.Name -contains 'overall_ok')) {
    $overallOk = [bool]$tunnelReport.overall_ok
}

# A pass requires every signal to agree: the daemon was not killed for timing
# out, it exited 0, and its report asserts overall_ok. Anything else fails closed.
$status = if (-not $timedOut -and $daemonExit -eq 0 -and $overallOk) { 'pass' } else { 'fail' }

$stderrExcerpt = $stderrText.Trim()
if ($stderrExcerpt.Length -gt 400) { $stderrExcerpt = $stderrExcerpt.Substring(0, 400) }
$reason = ''
if ($status -ne 'pass') {
    if ($timedOut) {
        $reason = ('daemon timed out after {0}s and was killed; a tunnel service may have been left installed (manual cleanup may be required); stderr: {1}' -f $TimeoutSeconds, $stderrExcerpt)
    }
    elseif ($null -eq $tunnelReport) {
        $reason = if ($parseError) {
            ('daemon report was not valid JSON: {0}; stderr: {1}' -f $parseError, $stderrExcerpt)
        }
        else {
            ('daemon emitted no tunnel-smoke report; exit={0}; stderr: {1}' -f $daemonExit, $stderrExcerpt)
        }
    }
    else {
        $reason = ('tunnel did not come up cleanly (overall_ok={0}, exit={1})' -f $overallOk, $daemonExit)
    }
}

$failureStep = if ($status -eq 'pass') { '' } else { 'run-daemon' }
$report = [ordered]@{
    schema_version   = 1
    captured_at_utc  = (Get-Date).ToUniversalTime().ToString('o')
    platform         = 'windows'
    rustynet_root    = $RustyNetRoot
    state_root       = $StateRoot
    status           = $status
    reason           = $reason
    overall_ok       = $overallOk
    daemon_exit_code = $daemonExit
    failure_step     = $failureStep
    tunnel_report    = $tunnelReport
    notes            = @()
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

# Exit 0 on the normal path even when status=fail: the orchestrator's SSH
# capture wrapper throws on any non-zero helper exit, which would discard this
# JSON and hide the precise verdict. The JSON `status`/`overall_ok` fields carry
# the result and parse_windows_tunnel_smoke_output decides pass/fail. A non-zero
# exit is reserved for the fail-closed trap (a genuine helper exception).
