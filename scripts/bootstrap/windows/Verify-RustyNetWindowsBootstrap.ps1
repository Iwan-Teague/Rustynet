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
$hostKeyPath = 'C:\ProgramData\ssh\ssh_host_ed25519_key.pub'

$serviceRuntime = Get-ServiceRuntimeState -ServiceName $ServiceName
$serviceImagePath = [string]$serviceRuntime.image_path
$runtimeFlagsPresent = $false
if (Test-Path -LiteralPath $daemonInstallPath) {
    $helpText = (& $daemonInstallPath --help 2>&1 | Out-String)
    if (($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 1) -and $helpText -match '--windows-service' -and $helpText -match '--env-file') {
        $runtimeFlagsPresent = $true
    }
}

$backendState = Get-ReviewedBackendState -ConfigPath $configPath
$serviceImagePathUsesWindowsService = Test-ImagePathContainsToken -ImagePath $serviceImagePath -Token '--windows-service'
$serviceImagePathUsesEnvFile = Test-ImagePathContainsToken -ImagePath $serviceImagePath -Token '--env-file'
$serviceEnvFilePinned = Test-ImagePathContainsToken -ImagePath $serviceImagePath -Token $configPath

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
if (-not $checks.runtime_flags_present) {
    $notes += 'windows-service-flags-missing'
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
elseif (-not $checks.service_present) {
    $reason = 'windows-service-not-installed'
}
elseif (-not $checks.service_binary_path_pinned_to_install_root) {
    $reason = 'windows-service-binary-path-not-pinned-to-install-root'
}
elseif (-not $checks.service_image_path_uses_windows_service_flag -or -not $checks.service_image_path_uses_env_file -or -not $checks.service_env_file_pinned) {
    $reason = 'windows-service-host-path-not-reviewed'
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
    schema_version = 2
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
    notes = $notes
    checks = $checks
}

$json = $report | ConvertTo-Json -Depth 6
if ($OutputPath) {
    $json | Set-Content -Encoding utf8 -LiteralPath $OutputPath
}
$json | Write-Output
