param(
    [string]$RustyNetRoot = 'C:\Rustynet',
    [string]$StateRoot = 'C:\ProgramData\RustyNet',
    [string]$ServiceName = 'RustyNetSmoke',
    [string]$OutputPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$script:SmokeFailureStep = 'init'
$script:SmokeRuntimeSignals = $null

function New-FailClosedSmokeReport {
    param([Parameter(Mandatory = $true)][string]$FailureReason)
    return [ordered]@{
        schema_version = 1
        captured_at_utc = (Get-Date).ToUniversalTime().ToString('o')
        platform = 'windows'
        rustynet_root = $RustyNetRoot
        state_root = $StateRoot
        service_name = $ServiceName
        status = 'fail'
        reason = $FailureReason
        backend_label = ''
        runtime_supported = $false
        host_surface_validated = $false
        cleanup_status = 'failed'
        failure_step = $script:SmokeFailureStep
        runtime_signals = $script:SmokeRuntimeSignals
        notes = @('smoke-helper-trap')
    }
}

function Write-FailClosedSmokeReportIfRequested {
    param([Parameter(Mandatory = $true)][string]$FailureReason)
    if (-not $OutputPath -or $OutputPath.Trim().Length -eq 0) {
        return
    }
    try {
        $outputDirectory = Split-Path -Parent $OutputPath
        if ($outputDirectory) {
            Ensure-Directory -Path $outputDirectory
        }
        (New-FailClosedSmokeReport -FailureReason $FailureReason | ConvertTo-Json -Depth 6) |
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
        $failureReason = 'windows-service-host-smoke-exception'
    }
    Write-FailClosedSmokeReportIfRequested -FailureReason $failureReason
    Write-Error $_
    exit 1
}

function Ensure-Directory {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Force -Path $Path | Out-Null
    }
}

function Get-NativeCommandText {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [string[]]$Arguments = @()
    )
    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = (& $Path @Arguments 2>&1 | Out-String)
        if ($null -eq $output) {
            return ''
        }
        return [string]$output
    }
    finally {
        $ErrorActionPreference = $previousPreference
    }
}

function Test-RustyNetWindowsRuntimeSupport {
    param([Parameter(Mandatory = $true)][string]$DaemonPath)
    $helpText = Get-NativeCommandText -Path $DaemonPath -Arguments @('--help')
    $probeText = [string]$helpText
    $probeMode = 'help'
    $hasWindowsService = $probeText.IndexOf('--windows-service', [System.StringComparison]::OrdinalIgnoreCase) -ge 0
    $hasEnvFile = $probeText.IndexOf('--env-file', [System.StringComparison]::OrdinalIgnoreCase) -ge 0
    if (-not ($hasWindowsService -and $hasEnvFile)) {
        $usageText = Get-NativeCommandText -Path $DaemonPath
        if (-not [string]::IsNullOrWhiteSpace($usageText)) {
            $probeText = (($helpText.TrimEnd()) + "`r`n" + ($usageText.Trim())).Trim()
            $probeMode = 'help+bare'
            $hasWindowsService = $probeText.IndexOf('--windows-service', [System.StringComparison]::OrdinalIgnoreCase) -ge 0
            $hasEnvFile = $probeText.IndexOf('--env-file', [System.StringComparison]::OrdinalIgnoreCase) -ge 0
        }
    }
    return [ordered]@{
        has_windows_service = $hasWindowsService
        has_env_file = $hasEnvFile
        probe_mode = $probeMode
        probe_excerpt = if ($probeText.Length -gt 512) { $probeText.Substring(0, 512) } else { $probeText }
    }
}

function Test-PathPinnedToBinary {
    param(
        [string]$ImagePath,
        [string]$BinaryPath
    )
    if (-not $ImagePath -or -not $BinaryPath) {
        return $false
    }
    return $ImagePath.IndexOf($BinaryPath, [System.StringComparison]::OrdinalIgnoreCase) -ge 0
}

function Test-WireGuardDriverPresence {
    $canonicalExe = 'C:\Program Files\WireGuard\wireguard.exe'
    if (Test-Path -LiteralPath $canonicalExe) {
        return [ordered]@{ present = $true; path = $canonicalExe; detection = 'canonical-path' }
    }
    $inPath = (Get-Command wireguard.exe -ErrorAction SilentlyContinue)?.Source
    if ($inPath) {
        return [ordered]@{ present = $true; path = $inPath; detection = 'path-search' }
    }
    $wgSvc = Get-Service -Name WireGuardManager -ErrorAction SilentlyContinue
    if ($wgSvc) {
        return [ordered]@{ present = $true; path = ''; detection = 'service-manager' }
    }
    return [ordered]@{ present = $false; path = ''; detection = 'not-found' }
}

function Test-ImagePathContainsToken {
    param(
        [string]$ImagePath,
        [string]$Token
    )
    if (-not $ImagePath -or -not $Token) {
        return $false
    }
    return $ImagePath.IndexOf($Token, [System.StringComparison]::OrdinalIgnoreCase) -ge 0
}

function Get-ServiceImagePath {
    param([Parameter(Mandatory = $true)][string]$ServiceName)
    $serviceRegPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $ServiceName
    if (-not (Test-Path -LiteralPath $serviceRegPath)) {
        return ''
    }
    return [string](Get-ItemProperty -Path $serviceRegPath -Name ImagePath -ErrorAction SilentlyContinue).ImagePath
}

function Get-ServiceRuntimeState {
    param([Parameter(Mandatory = $true)][string]$ServiceName)
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    $serviceStatus = if ($service) { [string]$service.Status } else { 'missing' }
    $cimService = Get-CimInstance -ClassName Win32_Service -Filter ("Name='" + $ServiceName.Replace("'", "''") + "'") -ErrorAction SilentlyContinue
    $imagePath = Get-ServiceImagePath -ServiceName $ServiceName
    return [ordered]@{
        present = [bool]$service
        status = $serviceStatus
        state = if ($cimService) { [string]$cimService.State } else { 'missing' }
        start_mode = if ($cimService) { [string]$cimService.StartMode } else { '' }
        exit_code = if ($cimService) { [int]$cimService.ExitCode } else { $null }
        process_id = if ($cimService) { [int]$cimService.ProcessId } else { $null }
        image_path = $imagePath
    }
}

function Build-ReviewedDaemonArgsJson {
    return (@('--backend', 'windows-unsupported') | ConvertTo-Json -Compress)
}

function Write-SmokeEnvFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    @(
        '# RustyNet Windows service-host smoke configuration'
        '# This smoke path validates the reviewed --windows-service host surface only.'
        ('RUSTYNETD_DAEMON_ARGS_JSON=' + (Build-ReviewedDaemonArgsJson))
    ) | Out-File -Encoding ascii $Path
}

function Invoke-Sc {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    $output = (& sc.exe @Arguments 2>&1 | Out-String)
    return [ordered]@{
        exit_code = $LASTEXITCODE
        output = $output.Trim()
    }
}

function Remove-SmokeService {
    param([Parameter(Mandatory = $true)][string]$ServiceName)
    $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $existing) {
        return
    }

    if ($existing.Status -eq 'Running') {
        $stopResult = Invoke-Sc -Arguments @('stop', $ServiceName)
        if ($stopResult.exit_code -ne 0) {
            Start-Sleep -Seconds 1
        }
    }

    $deleteResult = Invoke-Sc -Arguments @('delete', $ServiceName)
    if ($deleteResult.exit_code -ne 0) {
        throw "sc.exe delete failed for ${ServiceName}: $($deleteResult.output)"
    }

    for ($attempt = 0; $attempt -lt 20; $attempt++) {
        if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
            return
        }
        Start-Sleep -Milliseconds 250
    }

    throw "service ${ServiceName} is still present after delete"
}

$smokeRoot = Join-Path (Join-Path $StateRoot 'config') 'smoke-host'
$serviceSmokeRoot = Join-Path $smokeRoot $ServiceName
$daemonPath = Join-Path $RustyNetRoot 'target\release\rustynetd.exe'
$configPath = Join-Path $serviceSmokeRoot 'rustynetd.env'
$quotedDaemon = '"' + $daemonPath + '"'
$quotedConfig = '"' + $configPath + '"'
$quotedServiceName = '"' + $ServiceName + '"'
$binPath = "$quotedDaemon --windows-service --service-name $quotedServiceName --env-file $quotedConfig"
$backendLabel = 'windows-unsupported'
$backendReason = 'windows-runtime-backend-explicitly-unsupported'
$runtimeSignals = [ordered]@{
    has_windows_service = $false
    has_env_file = $false
}
$runtimeFlagsPresent = $false
$serviceRuntime = [ordered]@{
    present = $false
    status = 'missing'
    state = 'missing'
    start_mode = ''
    exit_code = $null
    process_id = $null
    image_path = ''
}
$serviceImagePathUsesWindowsService = $false
$serviceImagePathUsesEnvFile = $false
$serviceEnvFilePinned = $false
$serviceBinaryPinned = $false
$serviceConfigured = $false
$startAttempted = $false
$startExitCode = $null
$startOutput = ''
$startError = ''
$cleanupStatus = 'not-run'
$cleanupError = ''
$status = 'fail'
$reason = ''
$notes = New-Object System.Collections.Generic.List[string]
$fatalError = ''
$wireGuardProbe = [ordered]@{ present = $false; path = ''; detection = 'not-checked' }

try {
    $script:SmokeFailureStep = 'ensure-smoke-root'
    Ensure-Directory -Path $serviceSmokeRoot
    $script:SmokeFailureStep = 'write-smoke-env-file'
    Write-SmokeEnvFile -Path $configPath

    if (-not (Test-Path -LiteralPath $daemonPath)) {
        throw 'rustynetd.exe was not found under the Windows release output directory'
    }

    $script:SmokeFailureStep = 'probe-runtime-support'
    $runtimeSignals = Test-RustyNetWindowsRuntimeSupport -DaemonPath $daemonPath
    $script:SmokeRuntimeSignals = $runtimeSignals
    $runtimeFlagsPresent = [bool]($runtimeSignals.has_windows_service -and $runtimeSignals.has_env_file)

    $script:SmokeFailureStep = 'check-wireguard-driver'
    $wireGuardProbe = Test-WireGuardDriverPresence

    $script:SmokeFailureStep = 'remove-preexisting-smoke-service'
    Remove-SmokeService -ServiceName $ServiceName

    $script:SmokeFailureStep = 'create-smoke-service'
    $createResult = Invoke-Sc -Arguments @(
        'create',
        $ServiceName,
        'binPath=',
        $binPath,
        'start=',
        'demand',
        'DisplayName=',
        'RustyNet Windows Service Host Smoke'
    )
    if ($createResult.exit_code -ne 0) {
        throw "sc.exe create failed: $($createResult.output)"
    }

    $script:SmokeFailureStep = 'describe-smoke-service'
    $descriptionResult = Invoke-Sc -Arguments @(
        'description',
        $ServiceName,
        'RustyNet temporary SCM smoke validation for the reviewed Windows service host'
    )
    if ($descriptionResult.exit_code -ne 0) {
        throw "sc.exe description failed: $($descriptionResult.output)"
    }

    $serviceConfigured = $true
    $startAttempted = $true
    $script:SmokeFailureStep = 'start-smoke-service'
    $startResult = Invoke-Sc -Arguments @('start', $ServiceName)
    $startExitCode = [int]$startResult.exit_code
    $startOutput = $startResult.output
    if ($startExitCode -ne 0) {
        $startError = $startOutput
    }
    Start-Sleep -Seconds 3
    $script:SmokeFailureStep = 'observe-smoke-service'
    $serviceRuntime = Get-ServiceRuntimeState -ServiceName $ServiceName
}
catch {
    $fatalError = $_.Exception.Message
}
finally {
    $script:SmokeFailureStep = 'cleanup-smoke-service'
    if (-not $serviceRuntime.present) {
        $serviceRuntime = Get-ServiceRuntimeState -ServiceName $ServiceName
    }

    try {
        Remove-SmokeService -ServiceName $ServiceName
        $cleanupStatus = 'removed'
    }
    catch {
        $cleanupStatus = 'failed'
        $cleanupError = $_.Exception.Message
    }
}

$imagePath = [string]$serviceRuntime.image_path
$serviceImagePathUsesWindowsService = Test-ImagePathContainsToken -ImagePath $imagePath -Token '--windows-service'
$serviceImagePathUsesEnvFile = Test-ImagePathContainsToken -ImagePath $imagePath -Token '--env-file'
$serviceEnvFilePinned = Test-ImagePathContainsToken -ImagePath $imagePath -Token $configPath
$serviceBinaryPinned = Test-PathPinnedToBinary -ImagePath $imagePath -BinaryPath $daemonPath
$hostSurfaceValidated = (
    (Test-Path -LiteralPath $daemonPath) -and
    (Test-Path -LiteralPath $configPath) -and
    $runtimeFlagsPresent -and
    $serviceConfigured -and
    $serviceRuntime.present -and
    $serviceBinaryPinned -and
    $serviceImagePathUsesWindowsService -and
    $serviceImagePathUsesEnvFile -and
    $serviceEnvFilePinned -and
    $startAttempted
)

if ($fatalError) {
    $notes.Add('fatal-error')
}
if (-not (Test-Path -LiteralPath $daemonPath)) {
    $notes.Add('daemon-binary-missing')
}
if (-not (Test-Path -LiteralPath $configPath)) {
    $notes.Add('config-missing')
}
if (-not $runtimeSignals.has_windows_service) {
    $notes.Add('windows-service-flag-missing')
}
if (-not $runtimeSignals.has_env_file) {
    $notes.Add('env-file-flag-missing')
}
if (-not $serviceConfigured) {
    $notes.Add('service-not-configured')
}
if (-not $serviceRuntime.present) {
    $notes.Add('service-state-not-observed')
}
if (-not $serviceBinaryPinned) {
    $notes.Add('service-binary-path-not-pinned')
}
if (-not $serviceImagePathUsesWindowsService) {
    $notes.Add('service-binpath-missing-windows-service-flag')
}
if (-not $serviceImagePathUsesEnvFile) {
    $notes.Add('service-binpath-missing-env-file-flag')
}
if (-not $serviceEnvFilePinned) {
    $notes.Add('service-env-file-not-pinned')
}
if (-not $startAttempted) {
    $notes.Add('service-start-not-attempted')
}
if ($startError) {
    $notes.Add('service-start-reported-error')
}
if ($cleanupStatus -ne 'removed') {
    $notes.Add('cleanup-incomplete')
}

if (-not (Test-Path -LiteralPath $daemonPath)) {
    $reason = 'windows-service-host-smoke-daemon-missing'
}
elseif (-not $runtimeFlagsPresent) {
    $reason = 'windows-runtime-service-host-not-yet-implemented'
}
elseif (-not (Test-Path -LiteralPath $configPath)) {
    $reason = 'windows-service-host-smoke-config-missing'
}
elseif ($fatalError) {
    $reason = 'windows-service-host-smoke-exception'
}
elseif (-not $serviceConfigured) {
    $reason = 'windows-service-host-smoke-service-config-failed'
}
elseif (-not $serviceRuntime.present) {
    $reason = 'windows-service-host-smoke-service-state-unobserved'
}
elseif (-not $serviceBinaryPinned) {
    $reason = 'windows-service-host-smoke-binary-not-pinned'
}
elseif (-not $serviceImagePathUsesWindowsService -or -not $serviceImagePathUsesEnvFile -or -not $serviceEnvFilePinned) {
    $reason = 'windows-service-host-smoke-binpath-not-reviewed'
}
elseif (-not $startAttempted) {
    $reason = 'windows-service-host-smoke-start-not-attempted'
}
elseif ($hostSurfaceValidated -and $backendLabel -eq 'windows-unsupported') {
    $status = 'blocked'
    $reason = $backendReason
}
elseif ($hostSurfaceValidated -and $serviceRuntime.status -eq 'Running') {
    $status = 'pass'
    $reason = ''
}
else {
    $reason = 'windows-service-host-smoke-validation-incomplete'
}

$report = [ordered]@{
    schema_version = 1
    captured_at_utc = (Get-Date).ToUniversalTime().ToString('o')
    platform = 'windows'
    rustynet_root = $RustyNetRoot
    state_root = $StateRoot
    smoke_root = $serviceSmokeRoot
    service_name = $ServiceName
    status = $status
    reason = $reason
    host_surface_validated = $hostSurfaceValidated
    runtime_supported = ($status -eq 'pass')
    backend_label = $backendLabel
    backend_reason = $backendReason
    daemon_path = $daemonPath
    daemon_present = Test-Path -LiteralPath $daemonPath
    config_path = $configPath
    config_present = Test-Path -LiteralPath $configPath
    runtime_flags_present = $runtimeFlagsPresent
    service_present = $serviceRuntime.present
    service_status = $serviceRuntime.status
    service_state = $serviceRuntime.state
    service_start_mode = $serviceRuntime.start_mode
    service_exit_code = $serviceRuntime.exit_code
    service_process_id = $serviceRuntime.process_id
    service_image_path = $imagePath
    service_binary_path_pinned = $serviceBinaryPinned
    service_image_path_uses_windows_service_flag = $serviceImagePathUsesWindowsService
    service_image_path_uses_env_file = $serviceImagePathUsesEnvFile
    service_env_file_pinned = $serviceEnvFilePinned
    start_attempted = $startAttempted
    start_exit_code = $startExitCode
    start_error = $startError
    start_output = $startOutput
    cleanup_status = $cleanupStatus
    cleanup_error = $cleanupError
    fatal_error = $fatalError
    wireguard_driver_present = $wireGuardProbe.present
    wireguard_driver_probe = $wireGuardProbe
    failure_step = $script:SmokeFailureStep
    runtime_signals = $runtimeSignals
    notes = $notes
}

$json = $report | ConvertTo-Json -Depth 8
if ($OutputPath) {
    $outputDirectory = Split-Path -Parent $OutputPath
    if ($outputDirectory) {
        Ensure-Directory -Path $outputDirectory
    }
    $json | Set-Content -Encoding utf8 -LiteralPath $OutputPath
}
$json | Write-Output

if ($status -eq 'fail' -or $cleanupStatus -eq 'failed') {
    exit 1
}
exit 0
