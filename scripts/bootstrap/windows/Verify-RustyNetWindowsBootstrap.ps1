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
trap {
    Write-Error $_
    exit 1
}

function Get-HashOrEmpty {
    param([string]$Path)
    if (Test-Path -LiteralPath $Path) {
        return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash
    }
    return ''
}

function Test-CommandPresent {
    param([Parameter(Mandatory = $true)][string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Get-FirstExistingPath {
    param([string[]]$Candidates)
    return $Candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
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

function Invoke-Sc {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    $output = (& sc.exe @Arguments 2>&1 | Out-String)
    return [ordered]@{
        exit_code = $LASTEXITCODE
        output = $output.Trim()
    }
}

function Get-WindowsTargetFacts {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    $computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    $buildNumber = if ($os) { [int]$os.BuildNumber } else { 0 }
    return [ordered]@{
        caption = if ($os) { [string]$os.Caption } else { '' }
        version = if ($os) { [string]$os.Version } else { '' }
        build_number = $buildNumber
        architecture = if ($os) { [string]$os.OSArchitecture } elseif ($computer) { [string]$computer.SystemType } else { '' }
        windows_11_target = [bool]($buildNumber -ge 22000)
        elevated_admin = [bool]([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
}

function Get-ServiceSidType {
    param([Parameter(Mandatory = $true)][string]$ServiceName)
    $result = Invoke-Sc -Arguments @('qsidtype', $ServiceName)
    if ($result.exit_code -ne 0) {
        return ''
    }
    $match = [regex]::Match($result.output, 'SERVICE_SID_TYPE:\s+\d+\s+(\S+)')
    if ($match.Success) {
        return $match.Groups[1].Value
    }
    return $result.output
}

function Invoke-WindowsRuntimeBoundaryCheck {
    param(
        [Parameter(Mandatory = $true)][string]$DaemonPath,
        [Parameter(Mandatory = $true)][string]$StateRoot
    )
    if (-not (Test-Path -LiteralPath $DaemonPath)) {
        return $null
    }
    $output = (& $DaemonPath windows-runtime-boundary-check --state-root $StateRoot 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) {
        return [ordered]@{
            status = 'fail'
            reason = $output.Trim()
        }
    }
    try {
        $parsed = $output | ConvertFrom-Json -ErrorAction Stop
        return [ordered]@{
            status = 'pass'
            report = $parsed
        }
    }
    catch {
        return [ordered]@{
            status = 'fail'
            reason = ('invalid-runtime-boundary-json: ' + $_.Exception.Message)
            raw = $output.Trim()
        }
    }
}

function Get-ReviewedBackendState {
    param([Parameter(Mandatory = $true)][string]$ConfigPath)
    if (-not (Test-Path -LiteralPath $ConfigPath)) {
        return [ordered]@{
            present = $false
            daemon_args_json = ''
            backend_label = ''
            backend_reason = 'config-missing'
        }
    }
    $backendLine = Get-Content -LiteralPath $ConfigPath |
        Where-Object { $_ -match '^\s*RUSTYNETD_DAEMON_ARGS_JSON=' } |
        Select-Object -First 1
    if (-not $backendLine) {
        return [ordered]@{
            present = $true
            daemon_args_json = ''
            backend_label = ''
            backend_reason = 'windows-runtime-backend-not-configured'
        }
    }

    $daemonArgsJson = ($backendLine -split '=', 2)[1].Trim()
    try {
        $daemonArgs = $daemonArgsJson | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        return [ordered]@{
            present = $true
            daemon_args_json = $daemonArgsJson
            backend_label = ''
            backend_reason = 'windows-runtime-backend-not-recognized'
        }
    }

    $backendLabel = ''
    for ($index = 0; $index -lt $daemonArgs.Count; $index++) {
        if ($daemonArgs[$index] -eq '--backend' -and ($index + 1) -lt $daemonArgs.Count) {
            $backendLabel = [string]$daemonArgs[$index + 1]
            break
        }
    }

    $backendReason = ''
    if (-not $backendLabel) {
        $backendReason = 'windows-runtime-backend-not-configured'
    }
    elseif ($backendLabel -eq 'windows-unsupported') {
        $backendReason = 'windows-runtime-backend-explicitly-unsupported'
    }
    elseif ($backendLabel -in @(
            'linux-wireguard',
            'linux-wireguard-userspace-shared',
            'macos-wireguard',
            'macos-wireguard-userspace-shared'
        )) {
        $backendReason = 'windows-runtime-backend-not-supported'
    }
    else {
        $backendReason = 'windows-runtime-backend-not-recognized'
    }

    return [ordered]@{
        present = $true
        daemon_args_json = $daemonArgsJson
        backend_label = $backendLabel
        backend_reason = $backendReason
    }
}

$releaseRoot = Join-Path $RustyNetRoot 'target\release'
$daemonBuildPath = Join-Path $releaseRoot 'rustynetd.exe'
$cliBuildPath = Get-FirstExistingPath -Candidates @(
    (Join-Path $releaseRoot 'rustynet.exe'),
    (Join-Path $releaseRoot 'rustynet-cli.exe')
)
$daemonInstallPath = Join-Path $InstallRoot 'bin\rustynetd.exe'
$cliInstallPath = Get-FirstExistingPath -Candidates @(
    (Join-Path $InstallRoot 'bin\rustynet.exe'),
    (Join-Path $InstallRoot 'bin\rustynet-cli.exe')
)
$configPath = Join-Path $StateRoot 'config\rustynetd.env'
$logRoot = Join-Path $StateRoot 'logs'
$trustRoot = Join-Path $StateRoot 'trust'
$secretRoot = Join-Path $StateRoot 'secrets'
$keyCustodyRoot = Join-Path $secretRoot 'key-custody'
$hostKeyPath = 'C:\ProgramData\ssh\ssh_host_ed25519_key.pub'

$serviceRuntime = Get-ServiceRuntimeState -ServiceName $ServiceName
$serviceImagePath = [string]$serviceRuntime.image_path
$windowsFacts = Get-WindowsTargetFacts
$serviceSidType = Get-ServiceSidType -ServiceName $ServiceName
$runtimeFlagsPresent = $false
if (Test-Path -LiteralPath $daemonInstallPath) {
    $helpText = (& $daemonInstallPath --help 2>&1 | Out-String)
    if (($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 1) -and $helpText -match '--windows-service' -and $helpText -match '--env-file') {
        $runtimeFlagsPresent = $true
    }
}
$runtimeBoundary = Invoke-WindowsRuntimeBoundaryCheck -DaemonPath $daemonInstallPath -StateRoot $StateRoot

$backendState = Get-ReviewedBackendState -ConfigPath $configPath
$serviceImagePathUsesWindowsService = Test-ImagePathContainsToken -ImagePath $serviceImagePath -Token '--windows-service'
$serviceImagePathUsesEnvFile = Test-ImagePathContainsToken -ImagePath $serviceImagePath -Token '--env-file'
$serviceEnvFilePinned = Test-ImagePathContainsToken -ImagePath $serviceImagePath -Token $configPath
$serviceSidConfigured = [bool]($serviceSidType -match 'UNRESTRICTED')
$runtimeBoundaryPassed = [bool]($runtimeBoundary -and $runtimeBoundary.status -eq 'pass')

$checks = [ordered]@{
    git_present = Test-CommandPresent -Name 'git.exe'
    cargo_present = Test-CommandPresent -Name 'cargo.exe'
    rustup_present = Test-CommandPresent -Name 'rustup.exe'
    build_output_rustynetd = Test-Path -LiteralPath $daemonBuildPath
    build_output_rustynet_cli = [bool]$cliBuildPath
    install_root_present = Test-Path -LiteralPath $InstallRoot
    installed_rustynetd = Test-Path -LiteralPath $daemonInstallPath
    installed_rustynet_cli = [bool]$cliInstallPath
    installed_rustynetd_sha256 = Get-HashOrEmpty -Path $daemonInstallPath
    installed_rustynet_cli_sha256 = if ($cliInstallPath) { Get-HashOrEmpty -Path $cliInstallPath } else { '' }
    config_present = Test-Path -LiteralPath $configPath
    log_root_present = Test-Path -LiteralPath $logRoot
    trust_root_present = Test-Path -LiteralPath $trustRoot
    secrets_root_present = Test-Path -LiteralPath $secretRoot
    key_custody_root_present = Test-Path -LiteralPath $keyCustodyRoot
    service_present = $serviceRuntime.present
    service_running = [bool]($serviceRuntime.present -and $serviceRuntime.status -eq 'Running')
    service_status = $serviceRuntime.status
    service_state = $serviceRuntime.state
    service_start_mode = $serviceRuntime.start_mode
    service_exit_code = $serviceRuntime.exit_code
    service_process_id = $serviceRuntime.process_id
    service_image_path = $serviceImagePath
    service_binary_path_pinned_to_install_root = Test-PathPinnedToBinary -ImagePath $serviceImagePath -BinaryPath $daemonInstallPath
    service_image_path_uses_windows_service_flag = $serviceImagePathUsesWindowsService
    service_image_path_uses_env_file = $serviceImagePathUsesEnvFile
    service_env_file_pinned = $serviceEnvFilePinned
    openssh_host_key_present = Test-Path -LiteralPath $hostKeyPath
    runtime_flags_present = $runtimeFlagsPresent
    backend_label = $backendState.backend_label
    backend_reason = $backendState.backend_reason
    windows_11_target = $windowsFacts.windows_11_target
    windows_caption = $windowsFacts.caption
    windows_version = $windowsFacts.version
    windows_build_number = $windowsFacts.build_number
    windows_architecture = $windowsFacts.architecture
    elevated_admin = $windowsFacts.elevated_admin
    service_sid_type = $serviceSidType
    service_sid_configured = $serviceSidConfigured
    runtime_boundary_status = if ($runtimeBoundary) { [string]$runtimeBoundary.status } else { 'not-run' }
    runtime_boundary_validated = $runtimeBoundaryPassed
}

$notes = @()
if (-not $checks.installed_rustynetd) {
    $notes += 'daemon-binary-missing'
}
if (-not $checks.installed_rustynet_cli) {
    $notes += 'cli-binary-missing'
}
if (-not $checks.config_present) {
    $notes += 'config-missing'
}
if (-not $checks.log_root_present) {
    $notes += 'log-root-missing'
}
if (-not $checks.trust_root_present) {
    $notes += 'trust-root-missing'
}
if (-not $checks.secrets_root_present) {
    $notes += 'secrets-root-missing'
}
if (-not $checks.key_custody_root_present) {
    $notes += 'key-custody-root-missing'
}
if (-not $checks.runtime_flags_present) {
    $notes += 'windows-service-flags-missing'
}
if (-not $checks.windows_11_target) {
    $notes += 'windows-11-required'
}
if (-not $checks.elevated_admin) {
    $notes += 'admin-elevation-required'
}
if (-not $checks.service_present) {
    $notes += 'service-missing'
}
elseif (-not $checks.service_binary_path_pinned_to_install_root) {
    $notes += 'service-binary-path-not-pinned-to-install-root'
}
elseif (-not $checks.service_image_path_uses_windows_service_flag) {
    $notes += 'service-binpath-missing-windows-service-flag'
}
elseif (-not $checks.service_image_path_uses_env_file) {
    $notes += 'service-binpath-missing-env-file-flag'
}
elseif (-not $checks.service_env_file_pinned) {
    $notes += 'service-binpath-env-file-not-pinned'
}
if (-not $checks.openssh_host_key_present) {
    $notes += 'openssh-host-key-missing'
}
if (-not $checks.service_sid_configured) {
    $notes += 'service-sid-not-configured'
}
if (-not $checks.runtime_boundary_validated) {
    $notes += 'runtime-boundary-check-failed'
}
if (-not $checks.backend_label) {
    $notes += 'backend-label-missing'
}

$status = 'fail'
$reason = ''
$runtimeSupported = $false
$serviceVerified = $false
if (-not $checks.installed_rustynetd -or -not $checks.installed_rustynet_cli) {
    $reason = 'install-artifacts-missing'
}
elseif (-not $checks.runtime_flags_present) {
    $reason = 'windows-runtime-service-host-not-yet-implemented'
}
elseif (-not $checks.config_present) {
    $reason = 'config-missing'
}
elseif (-not $checks.log_root_present -or -not $checks.trust_root_present -or -not $checks.secrets_root_present -or -not $checks.key_custody_root_present) {
    $reason = 'windows-runtime-layout-incomplete'
}
elseif (-not $checks.windows_11_target) {
    $reason = 'windows-11-required'
}
elseif (-not $checks.elevated_admin) {
    $reason = 'windows-bootstrap-must-run-elevated'
}
elseif (-not $checks.service_present) {
    $reason = 'windows-service-not-installed'
}
elseif (-not $checks.service_binary_path_pinned_to_install_root) {
    $reason = 'windows-service-binary-path-not-pinned-to-install-root'
}
elseif (-not $checks.service_image_path_uses_windows_service_flag -or -not $checks.service_image_path_uses_env_file -or -not $checks.service_env_file_pinned) {
    $reason = 'windows-service-host-path-not-reviewed'
}
elseif (-not $checks.service_sid_configured) {
    $reason = 'windows-service-sid-not-configured'
}
elseif (-not $checks.runtime_boundary_validated) {
    if ($runtimeBoundary -and $runtimeBoundary.reason) {
        $reason = 'windows-runtime-boundary-check-failed'
    }
    else {
        $reason = 'windows-runtime-boundary-check-not-run'
    }
}
elseif (-not $checks.backend_label) {
    $reason = $checks.backend_reason
}
elseif ($checks.backend_reason -eq 'windows-runtime-backend-explicitly-unsupported') {
    $status = 'blocked'
    $reason = $checks.backend_reason
}
elseif ($checks.backend_reason) {
    $reason = $checks.backend_reason
}
elseif (-not $checks.service_running) {
    $reason = 'windows-service-not-running'
}
else {
    $status = 'pass'
    $runtimeSupported = $true
    $serviceVerified = $true
}

$report = [ordered]@{
    schema_version = 3
    captured_at_utc = (Get-Date).ToUniversalTime().ToString('o')
    platform = 'windows'
    rustynet_root = $RustyNetRoot
    install_root = $InstallRoot
    state_root = $StateRoot
    status = $status
    runtime_supported = $runtimeSupported
    service_verified = $serviceVerified
    reason = $reason
    backend_label = $checks.backend_label
    daemon_present = $checks.installed_rustynetd
    cli_present = $checks.installed_rustynet_cli
    config_present = $checks.config_present
    log_root_present = $checks.log_root_present
    trust_root_present = $checks.trust_root_present
    secrets_root_present = $checks.secrets_root_present
    key_custody_root_present = $checks.key_custody_root_present
    service_present = $checks.service_present
    service_status = $checks.service_status
    service_state = $checks.service_state
    service_start_mode = $checks.service_start_mode
    service_exit_code = $checks.service_exit_code
    service_process_id = $checks.service_process_id
    service_image_path = $checks.service_image_path
    service_binary_path_pinned_to_install_root = $checks.service_binary_path_pinned_to_install_root
    service_image_path_uses_windows_service_flag = $checks.service_image_path_uses_windows_service_flag
    service_image_path_uses_env_file = $checks.service_image_path_uses_env_file
    service_env_file_pinned = $checks.service_env_file_pinned
    openssh_host_key_present = $checks.openssh_host_key_present
    git_present = $checks.git_present
    cargo_present = $checks.cargo_present
    rustup_present = $checks.rustup_present
    runtime_flags_present = $checks.runtime_flags_present
    windows_11_target = $checks.windows_11_target
    windows_caption = $checks.windows_caption
    windows_version = $checks.windows_version
    windows_build_number = $checks.windows_build_number
    windows_architecture = $checks.windows_architecture
    elevated_admin = $checks.elevated_admin
    service_sid_type = $checks.service_sid_type
    service_sid_configured = $checks.service_sid_configured
    runtime_boundary_status = $checks.runtime_boundary_status
    runtime_boundary_validated = $checks.runtime_boundary_validated
    runtime_boundary = $runtimeBoundary
    notes = $notes
    checks = $checks
}

$json = $report | ConvertTo-Json -Depth 6
if ($OutputPath) {
    $json | Set-Content -Encoding utf8 -LiteralPath $OutputPath
}
$json | Write-Output
