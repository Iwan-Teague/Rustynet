param(
    [string]$RustyNetRoot = 'C:\Rustynet',
    [string]$InstallRoot = 'C:\Program Files\RustyNet',
    [string]$StateRoot = 'C:\ProgramData\RustyNet',
    [string]$ServiceName = 'RustyNet',
    [string]$OutputPath = '',
    # Operator override: pin the daemon to the explicit fail-closed
    # `windows-unsupported` backend even when WireGuard for Windows
    # is detected on the host. Useful for staging / dry-run hosts
    # where the operator wants the install pipeline to land but the
    # daemon should not yet attempt to bring up real tunnels.
    # Default behavior (auto-detect): if WireGuard for Windows is
    # installed, the env file selects `--backend windows-wireguard-nt`
    # so the daemon comes up on a working data-plane; if not, the
    # env file selects `--backend windows-unsupported` and the
    # daemon refuses to start until WireGuard for Windows is
    # installed.
    [switch]$ForceUnsupportedBackend
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$script:InstallFailureStep = 'init'
$script:InstallRuntimeSignals = $null

# Defense-in-depth: PS-side validators that mirror the Rust orchestrator's
# `validate_service_name` (see crates/rustynet-cli/src/vm_lab/mod.rs) and
# `validate_windows_runtime_file_path` (see crates/rustynetd/src/windows_paths.rs)
# so this helper fails closed even if a future caller bypasses the
# orchestrator-side check or runs the helper directly. The reviewed
# charset for service names is ASCII alphanumeric + `-` + `_`, non-empty,
# ≤128 chars (intersection of systemd unit naming + Windows SCM service
# naming rules). Reviewed install/state roots are pinned to
# `C:\Program Files\RustyNet` and `C:\ProgramData\RustyNet`; deviation
# rejects so the helper cannot install RustyNet under an unreviewed
# layout.
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
# to a generic 'install-init-exception'.
Test-RustyNetServiceName -Name $ServiceName
Test-RustyNetReviewedInstallRoot -Path $InstallRoot
Test-RustyNetReviewedStateRoot -Path $StateRoot

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
    $wgCommand = Get-Command wireguard.exe -ErrorAction SilentlyContinue
    $inPath = if ($wgCommand) { $wgCommand.Source } else { $null }
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

    if ($Directory) {
        # Inheritance MUST flow to children for Administrators and
        # LocalSystem too — otherwise files the SYSTEM-running daemon
        # creates under this directory inherit only the service-
        # identity grant, and the daemon (running as LocalSystem) is
        # then denied read/write/delete on its own files.  Observed
        # symptom: rustynetd's runtime-boundary check creates
        # boundary-check.passphrase.dpapi via DPAPI, then fails to
        # scrub+delete it with "Access is denied (os error 5)" because
        # the file's inherited ACL only had windows:(I)(F) +
        # RustyNet:(I)(M).
        $adminGrant = "$AdministratorsName`:(OI)(CI)(F)"
        $systemGrant = "$LocalSystemName`:(OI)(CI)(F)"
        $serviceGrant = "$ServiceIdentity`:(OI)(CI)(M)"
    } else {
        $adminGrant = "$AdministratorsName`:F"
        $systemGrant = "$LocalSystemName`:F"
        $serviceGrant = "$ServiceIdentity`:M"
    }
    & icacls $Path /grant:r $adminGrant $systemGrant $serviceGrant | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "icacls /grant:r failed for $Path"
    }
}

# Binary install-root files inherit Builtin Users (BU) read+execute from
# `C:\Program Files`. The W2.2 service-hardening verifier rejects any binary
# ACL that exposes a broader-than-reviewed Windows principal (WD/AU/BU). Lock
# the binary down to SYSTEM+Administrators full plus the service identity at
# read+execute only — the runtime never modifies its own image, so write
# access on the binary is denied even to the service principal.
function Repair-RustyNetServiceBinaryAcl {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$AdministratorsName,
        [Parameter(Mandatory = $true)][string]$LocalSystemName,
        [Parameter(Mandatory = $true)][string]$ServiceIdentity
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Repair-RustyNetServiceBinaryAcl: $Path does not exist"
    }

    & icacls $Path /setowner $AdministratorsName | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "icacls /setowner failed for $Path"
    }
    & icacls $Path /inheritance:r | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "icacls /inheritance:r failed for $Path"
    }
    & icacls $Path /grant:r "$AdministratorsName`:F" "$LocalSystemName`:F" "$ServiceIdentity`:RX" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "icacls /grant:r failed for binary $Path"
    }
}

# SCM recovery actions: restart the daemon up to three times after a 60s back-
# off. After a 24h failure-free window the counter resets. The W2.2 hardening
# verifier rejects services with zero failure actions because an unattended
# crash would otherwise leave the runtime fail-closed silently. sc.exe failure
# args are slash-separated tokens with no embedded spaces or quotes, so the
# PS5.1 native-arg quoting bug that pushed New-Service over sc.exe create does
# not apply here.
function Set-RustyNetServiceFailureActions {
    param([Parameter(Mandatory = $true)][string]$ServiceName)
    $result = Invoke-Sc -Arguments @(
        'failure',
        $ServiceName,
        'reset=', '86400',
        'actions=', 'restart/60000/restart/60000/restart/60000'
    )
    if ($result.exit_code -ne 0) {
        throw "sc.exe failure failed: $($result.output)"
    }
}

function Resolve-ReviewedBackendLabel {
    param(
        [Parameter(Mandatory = $true)]$WireGuardProbe,
        [Parameter(Mandatory = $true)][bool]$ForceUnsupported
    )
    # Decision matrix:
    #   - operator passed -ForceUnsupportedBackend: ALWAYS use the
    #     fail-closed label, irrespective of WireGuard presence.
    #     This is the staging / dry-run path.
    #   - WireGuard for Windows detected (canonical install path or
    #     PATH match or WireGuardManager service registered): use
    #     `windows-wireguard-nt` so the daemon brings up real
    #     tunnels via wireguard.exe / wg.exe.
    #   - WireGuard for Windows NOT detected: use
    #     `windows-unsupported` so the daemon refuses to start
    #     rather than failing later when it tries to call missing
    #     binaries. Operator gets a precise blocker instead of a
    #     mid-bringup crash.
    if ($ForceUnsupported) {
        return 'windows-unsupported'
    }
    if ($WireGuardProbe.present) {
        return 'windows-wireguard-nt'
    }
    return 'windows-unsupported'
}

function Build-ReviewedDaemonArgsJson {
    param([Parameter(Mandatory = $true)][string]$BackendLabel)
    if ($BackendLabel -ne 'windows-unsupported' -and
        $BackendLabel -ne 'windows-wireguard-nt') {
        # Defense-in-depth: the only two labels the daemon's
        # `parse_windows_backend_mode` accepts. A future caller
        # threading an unknown label through this function gets a
        # precise blocker rather than the daemon erroring at
        # startup with "invalid Windows backend value".
        throw ('Build-ReviewedDaemonArgsJson rejects unknown backend label: {0}' -f $BackendLabel)
    }
    # --auto-tunnel-enforce false: per-node bootstrap brings the
    # service host up before any mesh assignment bundle has been
    # distributed by `vm-lab-orchestrate-live-lab`.  Without this
    # flag the daemon refuses to start until the assignment file
    # exists, so install-release / restart-runtime / verify-runtime
    # cannot complete on a fresh node.  The mesh-join phases later
    # distribute and validate the assignment; this flag does NOT
    # bypass that — it only defers the startup gate to runtime.
    #
    # --trust-max-age-secs 86400: the trust evidence file is generated
    # by the access bootstrap phase and may be hours old by the time
    # install-release runs in a phase-by-phase walkthrough.  The
    # daemon's default DEFAULT_TRUST_MAX_AGE_SECS is 300 (5 min) which
    # is correct for production but rejects lab evidence with
    # "trust evidence is stale".  Mesh-join phases regenerate trust
    # evidence with a fresh signature; this lab-image flag widens the
    # window so the per-node service-host bring-up does not fail
    # closed in between.
    return (@(
        '--backend', $BackendLabel,
        '--auto-tunnel-enforce', 'false',
        '--trust-max-age-secs', '86400'
    ) | ConvertTo-Json -Compress)
}
# (--trust-max-age-secs is parsed by rustynetd's daemon command — added to
# the CLI flag set in 4b23484+follow-on; threads through DaemonConfig and
# is read by the trust preflight in run_daemon.)

function Write-ReviewedEnvFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$BackendLabel
    )
    $banner = if ($BackendLabel -eq 'windows-wireguard-nt') {
        '# Reviewed RustyNet Windows service host configuration. WireGuard for Windows detected; daemon will bring up tunnels via the wireguard.exe / wg.exe / netsh.exe toolchain.'
    } else {
        '# Reviewed RustyNet Windows service host configuration. WireGuard for Windows NOT detected (or operator passed -ForceUnsupportedBackend); the daemon will refuse to start until a reviewed backend is selected. Install WireGuard for Windows from https://www.wireguard.com/install/ and re-run the install helper to switch the daemon to windows-wireguard-nt.'
    }
    @(
        $banner
        ('RUSTYNETD_DAEMON_ARGS_JSON=' + (Build-ReviewedDaemonArgsJson -BackendLabel $BackendLabel))
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
    (Join-Path $RustyNetRoot 'target\release\rustynet.exe'),
    (Join-Path $RustyNetRoot 'target\release\rustynet-cli.exe')
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

$daemonDest = Join-Path $InstallRoot 'rustynetd.exe'
$script:InstallFailureStep = 'copy-daemon-binary'
Copy-Item -LiteralPath $daemonSource -Destination $daemonDest -Force
if ($cliSource) {
    $script:InstallFailureStep = 'copy-cli-binary'
    Copy-Item -LiteralPath $cliSource -Destination (Join-Path $InstallRoot 'rustynet.exe') -Force
}

$configPath = Join-Path $StateRoot 'config\rustynetd.env'
$script:InstallFailureStep = 'write-reviewed-env-file'
$backendLabel = Resolve-ReviewedBackendLabel `
    -WireGuardProbe $wireGuardProbe `
    -ForceUnsupported ([bool]$ForceUnsupportedBackend)
Write-Host ("[install-helper] selected backend label: {0} (wireguard.present={1}, force-unsupported={2})" -f
    $backendLabel, [bool]$wireGuardProbe.present, [bool]$ForceUnsupportedBackend)
Write-ReviewedEnvFile -Path $configPath -BackendLabel $backendLabel

$script:InstallFailureStep = 'probe-runtime-support'
$runtimeSignals = Test-RustyNetWindowsRuntimeSupport -DaemonPath $daemonDest
$script:InstallRuntimeSignals = $runtimeSignals
$serviceConfigError = ''
$serviceSidConfigured = $false
$runtimeAclApplied = $false
$serviceStartAttempted = $false
$startError = ''

if ($runtimeSignals.has_windows_service -and $runtimeSignals.has_env_file) {
    # Service binPath is built from a fixed daemon-flag template plus three operator-controlled
    # values: the install-root daemon path, the reviewed env-file path, and the service name.
    # PowerShell 5.1 mangles native-command quoting when sc.exe is invoked with an argv that
    # contains spaces and embedded double quotes (sc.exe sees the value tokenized and exits
    # 1639 ERROR_INVALID_COMMAND_LINE). Use the New-Service / Set-Service cmdlets instead so
    # binPath crosses into the SCM as a single SCM-API string with no shell tokenization in
    # between. Description and start mode go through the same cmdlet path.
    $quotedDaemon = '"' + $daemonDest + '"'
    $quotedConfig = '"' + $configPath + '"'
    $quotedServiceName = '"' + $ServiceName + '"'
    $binPath = "$quotedDaemon --windows-service --service-name $quotedServiceName --env-file $quotedConfig"
    $serviceDescription = 'RustyNet secure mesh runtime service host'
    try {
        $script:InstallFailureStep = 'configure-service-registration'
        $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($existing) {
            if ($existing.Status -eq 'Running') {
                Stop-Service -Name $ServiceName -Force -ErrorAction Stop
            }
            $deleteOutput = (& sc.exe delete $ServiceName 2>&1 | Out-String)
            if ($LASTEXITCODE -ne 0) {
                throw "sc.exe delete failed: $deleteOutput"
            }
            # SCM marks deleted services pending until all handles drop. Wait briefly so the
            # next New-Service does not collide with the still-cached entry.
            $deadline = (Get-Date).AddSeconds(10)
            while ((Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) -and ((Get-Date) -lt $deadline)) {
                Start-Sleep -Milliseconds 250
            }
        }
        New-Service -Name $ServiceName -BinaryPathName $binPath -DisplayName 'RustyNet' -Description $serviceDescription -StartupType Automatic -ErrorAction Stop | Out-Null
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

        $script:InstallFailureStep = 'repair-binary-acl'
        Repair-RustyNetServiceBinaryAcl -Path $daemonDest -AdministratorsName $administratorsName -LocalSystemName $localSystemName -ServiceIdentity $serviceIdentity
        $runtimeAclApplied = $true

        $script:InstallFailureStep = 'configure-failure-actions'
        Set-RustyNetServiceFailureActions -ServiceName $ServiceName
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
# $backendLabel was set at the top of the script by Resolve-ReviewedBackendLabel
# from the WireGuard probe and -ForceUnsupportedBackend.  Keep that value for
# the report — overwriting it to 'windows-unsupported' here was a leftover that
# made every install look blocked even when wireguard.exe was present and the
# env file pinned --backend windows-wireguard-nt.
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
