param(
    [string]$InstallRoot = 'C:\Program Files\RustyNet',
    [string]$StateRoot = 'C:\ProgramData\RustyNet',
    [string]$ServiceName = 'RustyNet',
    [string]$OutputPath = '',
    # Default behavior is the least-destructive uninstall: stop + remove the
    # SCM service and remove the daemon binary, but preserve the state root
    # under `C:\ProgramData\RustyNet\` (membership snapshots, signed
    # bundles, encrypted key custody). The state root carries operator-
    # owned trust material; reinstalling on top of a kept state root re-
    # adopts the prior identity. Pass `-PurgeStateRoot` to wipe it after
    # the service is removed.
    [switch]$PurgeStateRoot,
    # Default behavior keeps the install root directory itself even after
    # the binary is removed. Pass `-PurgeInstallRoot` to remove the
    # `C:\Program Files\RustyNet\` directory if it ends up empty.
    [switch]$PurgeInstallRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$script:UninstallFailureStep = 'init'

# Defense-in-depth: PS-side validators that mirror the install helper +
# orchestrator-side `validate_service_name` /
# `validate_windows_runtime_file_path` so a typo on the command line
# cannot redirect the destructive Remove-Item against an unreviewed
# path. Same charset + path-pin rules as Install-RustyNetWindowsService.ps1.
function Test-RustyNetServiceName {
    param([Parameter(Mandatory = $true)][string]$Name)
    if ([string]::IsNullOrEmpty($Name)) {
        throw 'service name must not be empty'
    }
    if ($Name.Length -gt 128) {
        throw ('service name exceeds 128 chars: {0} chars' -f $Name.Length)
    }
    if ($Name -notmatch '^[A-Za-z0-9_-]+$') {
        throw ('service name must be ASCII alphanumeric + `-` + `_`; rejected: {0}' -f $Name)
    }
}

function Test-RustyNetReviewedInstallRoot {
    param([Parameter(Mandatory = $true)][string]$Path)
    $expected = 'C:\Program Files\RustyNet'
    if ($Path -ne $expected) {
        throw ('install root must be {0}; received {1}' -f $expected, $Path)
    }
}

function Test-RustyNetReviewedStateRoot {
    param([Parameter(Mandatory = $true)][string]$Path)
    $expected = 'C:\ProgramData\RustyNet'
    if ($Path -ne $expected) {
        throw ('state root must be {0}; received {1}' -f $expected, $Path)
    }
}

# Run validators before the trap handler is registered so a malformed
# parameter fails loudly with the precise reason rather than collapsing
# to a generic 'uninstall-init-exception'.
Test-RustyNetServiceName -Name $ServiceName
Test-RustyNetReviewedInstallRoot -Path $InstallRoot
Test-RustyNetReviewedStateRoot -Path $StateRoot

function New-FailClosedUninstallReport {
    param([Parameter(Mandatory = $true)][string]$FailureReason)
    return [ordered]@{
        schema_version = 1
        captured_at_utc = (Get-Date).ToUniversalTime().ToString('o')
        platform = 'windows'
        install_root = $InstallRoot
        state_root = $StateRoot
        service_name = $ServiceName
        purge_state_root = [bool]$PurgeStateRoot
        purge_install_root = [bool]$PurgeInstallRoot
        status = 'fail'
        reason = $FailureReason
        service_present_before = $null
        service_present_after = $null
        service_status_before = ''
        service_stopped = $false
        service_deleted = $false
        daemon_binary_removed = $false
        env_file_removed = $false
        state_root_removed = $false
        install_root_removed = $false
        removed_paths = @()
        retained_paths = @()
        failure_step = $script:UninstallFailureStep
        notes = @('uninstall-helper-trap')
    }
}

function Write-FailClosedUninstallReportIfRequested {
    param([Parameter(Mandatory = $true)][string]$FailureReason)
    if (-not $OutputPath -or $OutputPath.Trim().Length -eq 0) {
        return
    }
    try {
        $outputDirectory = Split-Path -Parent $OutputPath
        if ($outputDirectory) {
            Ensure-Directory -Path $outputDirectory
        }
        (New-FailClosedUninstallReport -FailureReason $FailureReason | ConvertTo-Json -Depth 6) |
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
        $failureReason = 'windows-service-uninstall-exception'
    }
    Write-FailClosedUninstallReportIfRequested -FailureReason $failureReason
    Write-Error $_
    exit 1
}

function Ensure-Directory {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Force -Path $Path | Out-Null
    }
}

function Get-ServiceSnapshot {
    param([Parameter(Mandatory = $true)][string]$ServiceName)
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    return [ordered]@{
        present = [bool]$service
        status = if ($service) { [string]$service.Status } else { 'missing' }
    }
}

function Stop-RustyNetServiceIfRunning {
    param([Parameter(Mandatory = $true)][string]$ServiceName)
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $service) {
        return [ordered]@{ stopped = $false; was_running = $false }
    }
    if ($service.Status -eq 'Running' -or $service.Status -eq 'StartPending') {
        Stop-Service -Name $ServiceName -Force -ErrorAction Stop
        $deadline = (Get-Date).AddSeconds(30)
        while ((Get-Date) -lt $deadline) {
            $current = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if (-not $current -or $current.Status -eq 'Stopped') {
                return [ordered]@{ stopped = $true; was_running = $true }
            }
            Start-Sleep -Milliseconds 250
        }
        throw 'service did not transition to Stopped within 30s'
    }
    return [ordered]@{ stopped = $false; was_running = $false }
}

function Remove-RustyNetServiceRegistration {
    param([Parameter(Mandatory = $true)][string]$ServiceName)
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $service) {
        return $false
    }
    # Use sc.exe delete (not Remove-Service, which is PS6+ only) for PS5.1
    # compatibility. The argv has no spaces or quotes so the PS5.1
    # native-arg quoting bug that pushed New-Service over sc.exe create on
    # the install side does not apply here.
    $deleteOutput = (& sc.exe delete "$ServiceName" 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) {
        throw "sc.exe delete failed: $deleteOutput"
    }
    # SCM marks deleted services pending until all handles drop. Wait
    # briefly so the post-removal report observes service_present=false
    # rather than a stale cached entry.
    $deadline = (Get-Date).AddSeconds(10)
    while ((Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) -and ((Get-Date) -lt $deadline)) {
        Start-Sleep -Milliseconds 250
    }
    return $true
}

function Remove-RustyNetPathIfPresent {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$Recurse
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        return $false
    }
    if ($Recurse) {
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
    }
    else {
        Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
    }
    return $true
}

# --- Execution path ---------------------------------------------------

$daemonDest = Join-Path $InstallRoot 'rustynetd.exe'
$cliDest = Join-Path $InstallRoot 'rustynet.exe'
$configPath = Join-Path $StateRoot 'config\rustynetd.env'

$removedPaths = @()
$retainedPaths = @()
$notes = @()

$script:UninstallFailureStep = 'snapshot-service-pre'
$serviceBefore = Get-ServiceSnapshot -ServiceName $ServiceName

$script:UninstallFailureStep = 'stop-service'
$stopOutcome = Stop-RustyNetServiceIfRunning -ServiceName $ServiceName

# Remove killswitch firewall rules left by the daemon.  The daemon adds
# RustyNetKS-* rules when it applies the dataplane killswitch; if the
# service is stopped without a clean shutdown those rules persist.  A
# subsequent bootstrap would add duplicate rules, causing the daemon's
# killswitch verification to fail.  Remove all RustyNetKS-* and
# RustyNetDNS-* rules here so reinstalls start from a clean state.
$script:UninstallFailureStep = 'remove-killswitch-firewall-rules'
$null = Get-NetFirewallRule -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like 'RustyNetKS-*' -or $_.Name -like 'RustyNetDNS-*' } |
    Remove-NetFirewallRule -ErrorAction SilentlyContinue

$script:UninstallFailureStep = 'delete-service-registration'
$serviceDeleted = Remove-RustyNetServiceRegistration -ServiceName $ServiceName

$script:UninstallFailureStep = 'remove-daemon-binary'
$daemonRemoved = Remove-RustyNetPathIfPresent -Path $daemonDest
if ($daemonRemoved) { $removedPaths += $daemonDest }

$script:UninstallFailureStep = 'remove-cli-binary'
$cliRemoved = Remove-RustyNetPathIfPresent -Path $cliDest
if ($cliRemoved) { $removedPaths += $cliDest }

$script:UninstallFailureStep = 'remove-env-file'
$envFileRemoved = Remove-RustyNetPathIfPresent -Path $configPath
if ($envFileRemoved) { $removedPaths += $configPath }

$stateRootRemoved = $false
$script:UninstallFailureStep = 'evaluate-state-root'
if ($PurgeStateRoot) {
    $script:UninstallFailureStep = 'remove-state-root'
    $stateRootRemoved = Remove-RustyNetPathIfPresent -Path $StateRoot -Recurse
    if ($stateRootRemoved) { $removedPaths += $StateRoot }
}
elseif (Test-Path -LiteralPath $StateRoot) {
    $retainedPaths += $StateRoot
    $notes += 'state-root-retained'
}

$installRootRemoved = $false
$script:UninstallFailureStep = 'evaluate-install-root'
if ($PurgeInstallRoot -and (Test-Path -LiteralPath $InstallRoot)) {
    $remaining = Get-ChildItem -LiteralPath $InstallRoot -Force -ErrorAction SilentlyContinue
    if (-not $remaining) {
        $script:UninstallFailureStep = 'remove-install-root'
        $installRootRemoved = Remove-RustyNetPathIfPresent -Path $InstallRoot
        if ($installRootRemoved) { $removedPaths += $InstallRoot }
    }
    else {
        $retainedPaths += $InstallRoot
        $notes += 'install-root-not-empty-retained'
    }
}
elseif (Test-Path -LiteralPath $InstallRoot) {
    $retainedPaths += $InstallRoot
}

$script:UninstallFailureStep = 'snapshot-service-post'
$serviceAfter = Get-ServiceSnapshot -ServiceName $ServiceName

$status = 'pass'
$reason = ''
if ($serviceAfter.present) {
    $status = 'fail'
    $reason = 'service-still-present-after-delete'
}
elseif ($PurgeStateRoot -and (Test-Path -LiteralPath $StateRoot)) {
    $status = 'fail'
    $reason = 'state-root-still-present-after-purge'
}
elseif ((Test-Path -LiteralPath $daemonDest)) {
    $status = 'fail'
    $reason = 'daemon-binary-still-present-after-remove'
}

if (-not $serviceBefore.present) {
    $notes += 'service-absent-before-uninstall'
}
if (-not $daemonRemoved -and (Test-Path -LiteralPath $daemonDest)) {
    $notes += 'daemon-binary-not-removed'
}

$report = [ordered]@{
    schema_version = 1
    captured_at_utc = (Get-Date).ToUniversalTime().ToString('o')
    platform = 'windows'
    install_root = $InstallRoot
    state_root = $StateRoot
    service_name = $ServiceName
    purge_state_root = [bool]$PurgeStateRoot
    purge_install_root = [bool]$PurgeInstallRoot
    status = $status
    reason = $reason
    service_present_before = $serviceBefore.present
    service_status_before = $serviceBefore.status
    service_present_after = $serviceAfter.present
    service_status_after = $serviceAfter.status
    service_stopped = [bool]$stopOutcome.stopped
    service_was_running = [bool]$stopOutcome.was_running
    service_deleted = [bool]$serviceDeleted
    daemon_binary_removed = [bool]$daemonRemoved
    cli_binary_removed = [bool]$cliRemoved
    env_file_removed = [bool]$envFileRemoved
    state_root_removed = [bool]$stateRootRemoved
    install_root_removed = [bool]$installRootRemoved
    removed_paths = $removedPaths
    retained_paths = $retainedPaths
    failure_step = $script:UninstallFailureStep
    notes = $notes
}

$json = $report | ConvertTo-Json -Depth 6
if ($OutputPath) {
    $outputDirectory = Split-Path -Parent $OutputPath
    if ($outputDirectory) {
        Ensure-Directory -Path $outputDirectory
    }
    $json | Set-Content -Encoding utf8 -LiteralPath $OutputPath
}
$json | Write-Output

if ($status -ne 'pass') {
    exit 1
}
