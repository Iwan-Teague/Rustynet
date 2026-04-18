param(
    [string]$RustyNetRoot = 'C:\Rustynet',
    [string]$InstallRoot = 'C:\Program Files\RustyNet',
    [string]$StateRoot = 'C:\ProgramData\RustyNet',
    [string]$ServiceName = 'RustyNet'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
trap {
    Write-Error $_
    exit 1
}

function Ensure-Directory {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Force -Path $Path | Out-Null
    }
}

function Test-RustyNetWindowsRuntimeSupport {
    param([Parameter(Mandatory = $true)][string]$DaemonPath)
    $helpText = (& $DaemonPath --help 2>&1 | Out-String)
    $hasWindowsService = $helpText -match '--windows-service'
    $hasEnvFile = $helpText -match '--env-file'
    return [ordered]@{
        has_windows_service = $hasWindowsService
        has_env_file = $hasEnvFile
    }
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

Ensure-Directory -Path $InstallRoot
Ensure-Directory -Path (Join-Path $InstallRoot 'bin')
Ensure-Directory -Path $StateRoot
Ensure-Directory -Path (Join-Path $StateRoot 'config')
Ensure-Directory -Path (Join-Path $StateRoot 'logs')
Ensure-Directory -Path (Join-Path $StateRoot 'trust')
Ensure-Directory -Path (Join-Path $StateRoot 'keys')
Ensure-Directory -Path (Join-Path $StateRoot 'membership')
Ensure-Directory -Path (Join-Path $StateRoot 'secrets')
Ensure-Directory -Path (Join-Path $StateRoot 'secrets\key-custody')

$daemonCandidates = @(
    Join-Path $RustyNetRoot 'target\release\rustynetd.exe'
)
$cliCandidates = @(
    Join-Path $RustyNetRoot 'target\release\rustynet.exe',
    Join-Path $RustyNetRoot 'target\release\rustynet-cli.exe'
)

$daemonSource = Get-FirstExistingPath -Candidates $daemonCandidates
if (-not $daemonSource) {
    throw 'rustynetd.exe was not found under the Windows release output directory'
}
$cliSource = Get-FirstExistingPath -Candidates $cliCandidates

$daemonDest = Join-Path $InstallRoot 'bin\rustynetd.exe'
Copy-Item -LiteralPath $daemonSource -Destination $daemonDest -Force
if ($cliSource) {
    Copy-Item -LiteralPath $cliSource -Destination (Join-Path $InstallRoot 'bin\rustynet.exe') -Force
}

$configPath = Join-Path $StateRoot 'config\rustynetd.env'
Write-ReviewedEnvFile -Path $configPath

$runtimeSignals = Test-RustyNetWindowsRuntimeSupport -DaemonPath $daemonDest
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
        Ensure-ServiceSidTypeUnrestricted -ServiceName $ServiceName
        $serviceSidConfigured = $true

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
if (-not (Test-Path -LiteralPath $daemonDest) -or -not $cliSource) {
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
    notes = $notes
}

$report | ConvertTo-Json -Depth 6 | Write-Output
