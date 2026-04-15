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
$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
$serviceStatus = if ($service) { [string]$service.Status } else { 'missing' }
$serviceImagePath = ''

if ($service) {
    $serviceRegPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $ServiceName
    if (Test-Path -LiteralPath $serviceRegPath) {
        $serviceImagePath = [string](Get-ItemProperty -Path $serviceRegPath -Name ImagePath -ErrorAction SilentlyContinue).ImagePath
    }
}

$runtimeFlagsPresent = $false
if (Test-Path -LiteralPath $daemonInstallPath) {
    $helpText = (& $daemonInstallPath --help 2>&1 | Out-String)
    if (($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 1) -and $helpText -match '--windows-service' -and $helpText -match '--env-file') {
        $runtimeFlagsPresent = $true
    }
}

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
    service_present = [bool]$service
    service_running = [bool]($service -and $service.Status -eq 'Running')
    service_status = $serviceStatus
    service_image_path = $serviceImagePath
    service_binary_path_pinned_to_install_root = Test-PathPinnedToBinary -ImagePath $serviceImagePath -BinaryPath $daemonInstallPath
    openssh_host_key_present = Test-Path -LiteralPath $hostKeyPath
    rustynetd_has_windows_service_flag = $runtimeFlagsPresent
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
if (-not $checks.rustynetd_has_windows_service_flag) {
    $notes += 'windows-service-flags-missing'
}
if (-not $checks.service_present) {
    $notes += 'service-missing'
}
elseif (-not $checks.service_running) {
    $notes += 'service-not-running'
}
elseif (-not $checks.service_binary_path_pinned_to_install_root) {
    $notes += 'service-binary-path-not-pinned-to-install-root'
}
if (-not $checks.openssh_host_key_present) {
    $notes += 'openssh-host-key-missing'
}

$reason = ''
if (-not $checks.installed_rustynetd -or -not $checks.installed_rustynet_cli) {
    $reason = 'install-artifacts-missing'
}
elseif (-not $checks.rustynetd_has_windows_service_flag) {
    $reason = 'windows-runtime-service-host-not-yet-implemented'
}
elseif (-not $checks.service_present) {
    $reason = 'windows-service-not-installed'
}
elseif (-not $checks.service_running) {
    $reason = 'windows-service-not-running'
}
elseif (-not $checks.service_binary_path_pinned_to_install_root) {
    $reason = 'windows-service-binary-path-not-pinned-to-install-root'
}
elseif (-not $checks.config_present) {
    $reason = 'config-missing'
}
elseif (-not $checks.log_root_present) {
    $reason = 'log-root-missing'
}
elseif (-not $checks.trust_root_present) {
    $reason = 'trust-root-missing'
}
elseif (-not $checks.openssh_host_key_present) {
    $reason = 'openssh-host-key-missing'
}

$status = 'fail'
$runtimeSupported = $checks.rustynetd_has_windows_service_flag
$serviceVerified = $false
if (-not $reason) {
    $status = 'pass'
    $runtimeSupported = $true
    $serviceVerified = $true
}

$report = [ordered]@{
    schema_version = 1
    captured_at_utc = (Get-Date).ToUniversalTime().ToString('o')
    platform = 'windows'
    rustynet_root = $RustyNetRoot
    install_root = $InstallRoot
    state_root = $StateRoot
    status = $status
    runtime_supported = $runtimeSupported
    service_verified = $serviceVerified
    reason = $reason
    daemon_present = $checks.installed_rustynetd
    cli_present = $checks.installed_rustynet_cli
    config_present = $checks.config_present
    log_root_present = $checks.log_root_present
    trust_root_present = $checks.trust_root_present
    service_present = $checks.service_present
    service_status = $checks.service_status
    openssh_host_key_present = $checks.openssh_host_key_present
    git_present = $checks.git_present
    cargo_present = $checks.cargo_present
    rustup_present = $checks.rustup_present
    runtime_flags_present = $checks.rustynetd_has_windows_service_flag
    notes = $notes
    checks = $checks
}

$json = $report | ConvertTo-Json -Depth 6
if ($OutputPath) {
    $json | Set-Content -Encoding utf8 -LiteralPath $OutputPath
}
$json | Write-Output
