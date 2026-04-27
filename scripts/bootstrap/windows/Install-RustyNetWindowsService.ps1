param(
    [string]$RustyNetRoot = 'C:\Rustynet',
    [string]$InstallRoot = 'C:\Program Files\RustyNet',
    [string]$StateRoot = 'C:\ProgramData\RustyNet',
    [string]$ServiceName = 'RustyNet',
    [string]$OutputPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$script:InstallFailureStep = 'init'
$script:InstallRuntimeSignals = $null

function New-FailClosedInstallReport {
    param([Parameter(Mandatory = $true)][string]$FailureReason)
    return [ordered]@{
        schema_version = 1
        captured_at_utc = (Get-Date).ToUniversalTime().ToString('o')
        platform = 'windows'
        rustynet_root = $RustyNetRoot
        install_root = $InstallRoot
        state_root = $StateRoot
        service_name = $ServiceName
        status = 'fail'
        reason = $FailureReason
        backend_label = ''
        runtime_supported = $false
        service_verified = $false
        service_present = $false
        service_status = 'missing'
        failure_step = $script:InstallFailureStep
        runtime_signals = $script:InstallRuntimeSignals
        notes = @('install-helper-trap')
    }
}

function Write-FailClosedInstallReportIfRequested {
    param([Parameter(Mandatory = $true)][string]$FailureReason)
    if (-not $OutputPath -or $OutputPath.Trim().Length -eq 0) {
        return
    }
    try {
        $outputDirectory = Split-Path -Parent $OutputPath
        if ($outputDirectory) {
            Ensure-Directory -Path $outputDirectory
        }
        (New-FailClosedInstallReport -FailureReason $FailureReason | ConvertTo-Json -Depth 6) |
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
        $failureReason = 'windows-service-install-exception'
    }
    Write-FailClosedInstallReportIfRequested -FailureReason $failureReason
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

function Ensure-RustyNetRuntimeLayout {
    param(
        [Parameter(Mandatory = $true)][string]$InstallRoot,
        [Parameter(Mandatory = $true)][string]$StateRoot
    )
    foreach ($path in @(
            $InstallRoot,
            (Join-Path $InstallRoot 'bin'),
            $StateRoot,
            (Join-Path $StateRoot 'config'),
            (Join-Path $StateRoot 'logs'),
            (Join-Path $StateRoot 'trust'),
            (Join-Path $StateRoot 'keys'),
            (Join-Path $StateRoot 'membership'),
            (Join-Path $StateRoot 'secrets'),
            (Join-Path $StateRoot 'secrets\key-custody')
        )) {
        Ensure-Directory -Path $path
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
    # WireGuard for Windows installs wireguard.exe at this canonical path.
    # The wgnt kernel driver is packaged with this executable.
    $canonicalExe = 'C:\Program Files\WireGuard\wireguard.exe'
    if (Test-Path -LiteralPath $canonicalExe) {
        return [ordered]@{ present = $true; path = $canonicalExe; detection = 'canonical-path' }
    }
    # Fallback: wireguard.exe on PATH (e.g. chocolatey or custom install).
    $inPath = (Get-Command wireguard.exe -ErrorAction SilentlyContinue)?.Source
    if ($inPath) {
        return [ordered]@{ present = $true; path = $inPath; detection = 'path-search' }
    }
    # Fallback: WireGuard tunnel manager service registered by the installer.
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

function Get-LocalizedAccountNameFromSid {
    param([Parameter(Mandatory = $true)][string]$Sid)
    return (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value
}

function Get-ServiceIdentityName {
    param([Parameter(Mandatory = $true)][string]$ServiceName)
    return ('NT SERVICE\' + $ServiceName)
}

function Invoke-Sc {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    $output = (& sc.exe @Arguments 2>&1 | Out-String)
    return [ordered]@{
        exit_code = $LASTEXITCODE
        output = $output.Trim()
    }
}

function Ensure-ServiceSidTypeUnrestricted {
    param([Parameter(Mandatory = $true)][string]$ServiceName)
    $result = Invoke-Sc -Arguments @('sidtype', $ServiceName, 'unrestricted')
    if ($result.exit_code -ne 0) {
        throw "sc.exe sidtype failed: $($result.output)"
    }
}

function Repair-RustyNetRuntimeAcl {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$AdministratorsName,
        [Parameter(Mandatory = $true)][string]$LocalSystemName,
        [Parameter(Mandatory = $true)][string]$ServiceIdentity,
        [switch]$Directory
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }

    & icacls $Path /setowner $AdministratorsName | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "icacls /setowner failed for $Path"
    }
    & icacls $Path /inheritance:r | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "icacls /inheritance:r failed for $Path"
    }

    $serviceGrant = if ($Directory) { "$ServiceIdentity`:(OI)(CI)(M)" } else { "$ServiceIdentity`:M" }
    & icacls $Path /grant:r "$AdministratorsName`:F" "$LocalSystemName`:F" $serviceGrant | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "icacls /grant:r failed for $Path"
    }
}

function Build-ReviewedDaemonArgsJson {
    return (@('--backend', 'windows-unsupported') | ConvertTo-Json -Compress)
}

function Write-ReviewedEnvFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    @(
        '# Reviewed RustyNet Windows service host configuration'
        '# The current branch only provides windows-unsupported as an explicit fail-closed backend label.'
        ('RUSTYNETD_DAEMON_ARGS_JSON=' + (Build-ReviewedDaemonArgsJson))
    ) | Out-File -Encoding ascii $Path
}

$wireGuardProbe = [ordered]@{ present = $false; path = ''; detection = 'not-checked' }

$script:InstallFailureStep = 'ensure-runtime-layout'
Ensure-RustyNetRuntimeLayout -InstallRoot $InstallRoot -StateRoot $StateRoot

$script:InstallFailureStep = 'check-wireguard-driver'
$wireGuardProbe = Test-WireGuardDriverPresence

$script:InstallFailureStep = 'locate-build-artifacts'
$daemonCandidates = @(
    Join-Path $RustyNetRoot 'target\release\rustynetd.exe'
)
$cliCandidates = @(
    Join-Path $RustyNetRoot 'target\release\rustynet.exe',
    Join-Path $RustyNetRoot 'target\release\rustynet-cli.exe'
)

$daemonSource = $daemonCandidates[0]
if (-not $daemonSource) {
    throw 'rustynetd.exe was not found under the Windows release output directory'
}
if (-not (Test-Path -LiteralPath $daemonSource)) {
    throw 'rustynetd.exe was not found under the Windows release output directory'
}
$cliSource = $null
foreach ($candidate in $cliCandidates) {
    if (Test-Path -LiteralPath $candidate) {
        $cliSource = $candidate
        break
    }
}

$daemonDest = Join-Path $InstallRoot 'bin\rustynetd.exe'
$script:InstallFailureStep = 'copy-daemon-binary'
Copy-Item -LiteralPath $daemonSource -Destination $daemonDest -Force
if ($cliSource) {
    $script:InstallFailureStep = 'copy-cli-binary'
    Copy-Item -LiteralPath $cliSource -Destination (Join-Path $InstallRoot 'bin\rustynet.exe') -Force
}

$configPath = Join-Path $StateRoot 'config\rustynetd.env'
$script:InstallFailureStep = 'write-reviewed-env-file'
Write-ReviewedEnvFile -Path $configPath

$script:InstallFailureStep = 'probe-runtime-support'
$runtimeSignals = Test-RustyNetWindowsRuntimeSupport -DaemonPath $daemonDest
$script:InstallRuntimeSignals = $runtimeSignals
$serviceConfigError = ''
$serviceSidConfigured = $false
$runtimeAclApplied = $false
$serviceStartAttempted = $false
$startError = ''

if ($runtimeSignals.has_windows_service -and $runtimeSignals.has_env_file) {
    $quotedDaemon = '"' + $daemonDest + '"'
    $quotedConfig = '"' + $configPath + '"'
    $quotedServiceName = '"' + $ServiceName + '"'
    $binPath = "$quotedDaemon --windows-service --service-name $quotedServiceName --env-file $quotedConfig"
    try {
        $script:InstallFailureStep = 'configure-service-registration'
        $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($existing) {
            $scOutput = (& sc.exe config $ServiceName binPath= $binPath start= auto 2>&1 | Out-String)
            if ($LASTEXITCODE -ne 0) {
                throw "sc.exe config failed: $scOutput"
            }
        }
        else {
            $scOutput = (& sc.exe create $ServiceName binPath= $binPath start= auto DisplayName= 'RustyNet' 2>&1 | Out-String)
            if ($LASTEXITCODE -ne 0) {
                throw "sc.exe create failed: $scOutput"
            }
        }
        $descriptionOutput = (& sc.exe description $ServiceName 'RustyNet secure mesh runtime service host' 2>&1 | Out-String)
        if ($LASTEXITCODE -ne 0) {
            throw "sc.exe description failed: $descriptionOutput"
        }
        $script:InstallFailureStep = 'configure-service-sid'
        Ensure-ServiceSidTypeUnrestricted -ServiceName $ServiceName
        $serviceSidConfigured = $true

        $script:InstallFailureStep = 'repair-runtime-acls'
        $administratorsName = Get-LocalizedAccountNameFromSid -Sid 'S-1-5-32-544'
        $localSystemName = Get-LocalizedAccountNameFromSid -Sid 'S-1-5-18'
        $serviceIdentity = Get-ServiceIdentityName -ServiceName $ServiceName
        foreach ($directoryPath in @(
                $StateRoot,
                (Join-Path $StateRoot 'config'),
                (Join-Path $StateRoot 'logs'),
                (Join-Path $StateRoot 'trust'),
                (Join-Path $StateRoot 'keys'),
                (Join-Path $StateRoot 'membership'),
                (Join-Path $StateRoot 'secrets'),
                (Join-Path $StateRoot 'secrets\key-custody')
            )) {
            Repair-RustyNetRuntimeAcl -Path $directoryPath -AdministratorsName $administratorsName -LocalSystemName $localSystemName -ServiceIdentity $serviceIdentity -Directory
        }
        Repair-RustyNetRuntimeAcl -Path $configPath -AdministratorsName $administratorsName -LocalSystemName $localSystemName -ServiceIdentity $serviceIdentity
        $runtimeAclApplied = $true
    }
    catch {
        $serviceConfigError = $_.Exception.Message
    }

    if (-not $serviceConfigError) {
        $serviceStartAttempted = $true
        try {
            $script:InstallFailureStep = 'start-runtime-service'
            $service = Get-Service -Name $ServiceName -ErrorAction Stop
            if ($service.Status -eq 'Running') {
                Restart-Service -Name $ServiceName -ErrorAction Stop
            }
            else {
                Start-Service -Name $ServiceName -ErrorAction Stop
            }
        }
        catch {
            $startError = $_.Exception.Message
        }
        Start-Sleep -Seconds 3
    }
}

$script:InstallFailureStep = 'observe-runtime-service'
$serviceRuntime = Get-ServiceRuntimeState -ServiceName $ServiceName
$imagePath = [string]$serviceRuntime.image_path
$serviceImagePathUsesWindowsService = Test-ImagePathContainsToken -ImagePath $imagePath -Token '--windows-service'
$serviceImagePathUsesEnvFile = Test-ImagePathContainsToken -ImagePath $imagePath -Token '--env-file'
$serviceEnvFilePinned = Test-ImagePathContainsToken -ImagePath $imagePath -Token $configPath
$backendLabel = 'windows-unsupported'
$notes = @()
if ($serviceConfigError) {
    $notes += 'service-config-error'
}
if (-not $serviceSidConfigured) {
    $notes += 'service-sid-not-configured'
}
if (-not $runtimeAclApplied) {
    $notes += 'runtime-acl-not-applied'
}
if ($startError) {
    $notes += 'service-start-error'
}
if (-not $runtimeSignals.has_windows_service) {
    $notes += 'windows-service-flag-missing'
}
if (-not $runtimeSignals.has_env_file) {
    $notes += 'env-file-flag-missing'
}
if (-not $wireGuardProbe.present) {
    $notes += 'wireguard-driver-not-found'
}
if (-not $serviceRuntime.present) {
    $notes += 'service-missing'
}
elseif (-not $serviceImagePathUsesWindowsService) {
    $notes += 'service-binpath-missing-windows-service-flag'
}
elseif (-not $serviceImagePathUsesEnvFile) {
    $notes += 'service-binpath-missing-env-file-flag'
}
elseif (-not $serviceEnvFilePinned) {
    $notes += 'service-binpath-env-file-not-pinned'
}

$reason = ''
$status = 'fail'
if (-not (Test-Path -LiteralPath $daemonDest)) {
    $reason = 'install-artifacts-missing'
}
elseif (-not $runtimeSignals.has_windows_service -or -not $runtimeSignals.has_env_file) {
    $reason = 'windows-runtime-service-host-not-yet-implemented'
}
elseif ($serviceConfigError) {
    $reason = 'windows-service-install-failed'
}
elseif (-not (Test-Path -LiteralPath $configPath)) {
    $reason = 'config-missing'
}
elseif (-not $serviceRuntime.present) {
    $reason = 'windows-service-not-installed'
}
elseif (-not (Test-PathPinnedToBinary -ImagePath $imagePath -BinaryPath $daemonDest)) {
    $reason = 'windows-service-binary-path-not-pinned-to-install-root'
}
elseif (-not $serviceImagePathUsesWindowsService -or -not $serviceImagePathUsesEnvFile -or -not $serviceEnvFilePinned) {
    $reason = 'windows-service-host-path-not-reviewed'
}
elseif (-not $serviceSidConfigured) {
    $reason = 'windows-service-sid-not-configured'
}
elseif (-not $runtimeAclApplied) {
    $reason = 'windows-runtime-acl-not-applied'
}
elseif ($backendLabel -eq 'windows-unsupported') {
    $status = 'blocked'
    $reason = 'windows-runtime-backend-explicitly-unsupported'
}
elseif ($serviceRuntime.status -ne 'Running') {
    $reason = 'windows-service-not-running'
}
else {
    $status = 'pass'
}

$report = [ordered]@{
    schema_version = 1
    captured_at_utc = (Get-Date).ToUniversalTime().ToString('o')
    platform = 'windows'
    rustynet_root = $RustyNetRoot
    install_root = $InstallRoot
    state_root = $StateRoot
    service_name = $ServiceName
    status = $status
    reason = $reason
    backend_label = $backendLabel
    runtime_supported = $false
    service_verified = ($status -eq 'pass')
    cli_optional = $true
    start_attempted = $serviceStartAttempted
    start_error = $startError
    daemon_present = Test-Path -LiteralPath $daemonDest
    cli_present = [bool]$cliSource
    config_present = Test-Path -LiteralPath $configPath
    log_root_present = Test-Path -LiteralPath (Join-Path $StateRoot 'logs')
    trust_root_present = Test-Path -LiteralPath (Join-Path $StateRoot 'trust')
    secrets_root_present = Test-Path -LiteralPath (Join-Path $StateRoot 'secrets')
    service_sid_configured = $serviceSidConfigured
    runtime_acl_applied = $runtimeAclApplied
    service_present = $serviceRuntime.present
    service_status = $serviceRuntime.status
    service_state = $serviceRuntime.state
    service_start_mode = $serviceRuntime.start_mode
    service_exit_code = $serviceRuntime.exit_code
    service_process_id = $serviceRuntime.process_id
    service_image_path = $imagePath
    service_image_path_uses_windows_service_flag = $serviceImagePathUsesWindowsService
    service_image_path_uses_env_file = $serviceImagePathUsesEnvFile
    service_env_file_pinned = $serviceEnvFilePinned
    service_binary_path_pinned_to_install_root = Test-PathPinnedToBinary -ImagePath $imagePath -BinaryPath $daemonDest
    runtime_flags_present = [bool]($runtimeSignals.has_windows_service -and $runtimeSignals.has_env_file)
    wireguard_driver_present = $wireGuardProbe.present
    wireguard_driver_probe = $wireGuardProbe
    failure_step = $script:InstallFailureStep
    runtime_signals = $runtimeSignals
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
