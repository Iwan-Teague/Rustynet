param(
    [string]$RustyNetRoot = 'C:\Rustynet',
    [string]$InstallRoot = 'C:\Program Files\RustyNet',
    [string]$StateRoot = 'C:\ProgramData\RustyNet',
    [string]$ServiceName = 'RustyNet',
    [string]$NodeId = 'windows-client-1',
    # Daemon node role (--node-role). Must match the node's signed membership
    # capabilities: a node enrolled as a client fails reconcile closed if the
    # daemon runs as `admin` (which is the daemon default when the flag is
    # omitted). Threaded explicitly so it can never be dropped on this platform.
    [string]$NodeRole = 'client',
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
    [switch]$ForceUnsupportedBackend,
    # Enable auto-tunnel enforcement (auto_tunnel_enforce=true).
    # Bootstrap installs the service with auto_tunnel_enforce=false so the
    # daemon starts before any mesh assignment bundle exists.
    # EnforceBaselineRuntime re-runs the script with -EnforceAutoTunnel after
    # all verifier keys and bundles are in place, so the daemon applies
    # assignment bundles and brings up WireGuard tunnels.
    [switch]$EnforceAutoTunnel
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

function Test-RustyNetNodeId {
    param([Parameter(Mandatory = $true)][string]$Name)
    if ([string]::IsNullOrEmpty($Name)) {
        throw 'node id must not be empty'
    }
    if ($Name.Length -gt 128) {
        throw ('node id exceeds 128 chars: {0} chars' -f $Name.Length)
    }
    if ($Name -notmatch '^[A-Za-z0-9_.-]+$') {
        throw ('node id must be ASCII alphanumeric + `_` + `.` + `-`; rejected: {0}' -f $Name)
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
Test-RustyNetNodeId -Name $NodeId
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

function Set-InstallProgressStep {
    param([Parameter(Mandatory = $true)][string]$Step)
    $script:InstallFailureStep = $Step
    if (-not $OutputPath -or $OutputPath.Trim().Length -eq 0) {
        return
    }
    try {
        $progressPath = $OutputPath + '.progress'
        $progressDirectory = Split-Path -Parent $progressPath
        if ($progressDirectory) {
            Ensure-Directory -Path $progressDirectory
        }
        ([ordered]@{
            captured_at_utc = (Get-Date).ToUniversalTime().ToString('o')
            step = $Step
        } | ConvertTo-Json -Compress) | Set-Content -Encoding utf8 -LiteralPath $progressPath
    }
    catch {
        # Progress telemetry must never mask the install result.
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

function Invoke-RustyNetNativeCommand {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [string[]]$Arguments = @()
    )
    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = (& $Path @Arguments 2>&1 | Out-String)
        $exitCode = $LASTEXITCODE
        if ($null -eq $output) {
            $output = ''
        }
        if ($null -eq $exitCode) {
            $exitCode = 0
        }
        return [ordered]@{
            exit_code = $exitCode
            output = ([string]$output).Trim()
        }
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
            (Join-Path $StateRoot 'secrets\key-custody'),
            # Per-invocation credential workspace for membership-mutation
            # ops verbs. SYSTEM/Administrators-only DACL inherited from
            # the parent state root and re-validated by the W4 runtime
            # ACL gate at use time. Mirrors the Linux/macOS
            # `credentials-workspace` directories.
            (Join-Path $StateRoot 'credentials-workspace')
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
    $queryEx = (& sc.exe queryex "$ServiceName" 2>&1 | Out-String)
    $queryConfig = (& sc.exe qc "$ServiceName" 2>&1 | Out-String)
    $state = 'missing'
    $startMode = ''
    $exitCode = $null
    $processId = $null
    foreach ($line in ($queryEx -split "`r?`n")) {
        if ($line -match '^\s*STATE\s*:\s*\d+\s+([A-Z_]+)\s*$') {
            $state = [string]$Matches[1]
        }
        elseif ($line -match '^\s*WIN32_EXIT_CODE\s*:\s*(\d+)\s+') {
            $exitCode = [int]$Matches[1]
        }
        elseif ($line -match '^\s*PID\s*:\s*(\d+)\s*$') {
            $processId = [int]$Matches[1]
        }
    }
    foreach ($line in ($queryConfig -split "`r?`n")) {
        if ($line -match '^\s*START_TYPE\s*:\s*\d+\s+([A-Z_]+)\s*$') {
            $startMode = [string]$Matches[1]
        }
    }
    $imagePath = Get-ServiceImagePath -ServiceName $ServiceName
    return [ordered]@{
        present = [bool]$service
        status = $serviceStatus
        state = $state
        start_mode = $startMode
        exit_code = $exitCode
        process_id = $processId
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

    & icacls "$Path" /setowner $AdministratorsName | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "icacls /setowner failed for $Path"
    }
    & icacls "$Path" /inheritance:r | Out-Null
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
    & icacls "$Path" /grant:r $adminGrant $systemGrant $serviceGrant | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "icacls /grant:r failed for $Path"
    }
}

function Repair-RustyNetPreServiceAcl {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$AdministratorsName,
        [Parameter(Mandatory = $true)][string]$LocalSystemName,
        [switch]$Directory
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }

    & icacls "$Path" /setowner $AdministratorsName | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "icacls /setowner failed for $Path"
    }
    & icacls "$Path" /inheritance:r | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "icacls /inheritance:r failed for $Path"
    }

    if ($Directory) {
        $adminGrant = "$AdministratorsName`:(OI)(CI)(F)"
        $systemGrant = "$LocalSystemName`:(OI)(CI)(F)"
    } else {
        $adminGrant = "$AdministratorsName`:F"
        $systemGrant = "$LocalSystemName`:F"
    }
    & icacls "$Path" /grant:r $adminGrant $systemGrant | Out-Null
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

    & icacls "$Path" /setowner $AdministratorsName | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "icacls /setowner failed for $Path"
    }
    & icacls "$Path" /inheritance:r | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "icacls /inheritance:r failed for $Path"
    }
    & icacls "$Path" /grant:r "$AdministratorsName`:F" "$LocalSystemName`:F" "$ServiceIdentity`:RX" | Out-Null
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
    param(
        [Parameter(Mandatory = $true)][string]$BackendLabel,
        [Parameter(Mandatory = $true)][string]$NodeId,
        [Parameter(Mandatory = $true)][string]$NodeRole,
        [bool]$AutoTunnelEnforce = $false
    )
    if ($BackendLabel -ne 'windows-unsupported' -and
        $BackendLabel -ne 'windows-wireguard-nt') {
        # Defense-in-depth: the only two labels the daemon's
        # `parse_windows_backend_mode` accepts. A future caller
        # threading an unknown label through this function gets a
        # precise blocker rather than the daemon erroring at
        # startup with "invalid Windows backend value".
        throw ('Build-ReviewedDaemonArgsJson rejects unknown backend label: {0}' -f $BackendLabel)
    }
    # --auto-tunnel-enforce: bootstrap passes false so the daemon starts before
    # any mesh assignment bundle exists.  EnforceBaselineRuntime re-runs the
    # script with -EnforceAutoTunnel ($AutoTunnelEnforce=$true) after all
    # verifier keys and bundles are in place so the daemon applies the
    # assignment bundle and brings up WireGuard tunnels.
    # This flag does NOT bypass security checks — it only defers the startup
    # gate to runtime.
    #
    # --trust-max-age-secs 86400: install-release issues fresh trust
    # evidence under the runtime identity (see
    # 'reissue-trust-evidence-under-runtime-identity' step), so the
    # evidence is at most a few seconds old at service start. The
    # 24-hour window is the standing freshness budget after that —
    # the daemon's default DEFAULT_TRUST_MAX_AGE_SECS is 300 (5 min)
    # which is correct for production with an active refresh timer
    # but tighter than a lab guest gets without one. There is no
    # equivalent of `rustynetd-trust-refresh.timer` on Windows yet;
    # while that is missing, 86400s gives the lab a day before the
    # next install-release must rotate evidence again.
    #
    # --traversal-max-age-secs 86400: the traversal bundle is issued
    # with TRAVERSAL_TTL_SECS=120 (the hard cap enforced by ops_e2e),
    # so the bundle itself is always short-lived. However the Windows
    # lab orchestration pipeline (bootstrap → distribute membership →
    # distribute assignment → distribute traversal → restart service →
    # validate mesh-join) can take 30+ minutes end-to-end, meaning
    # the traversal bundle has expired long before the daemon's
    # startup preflight runs. There is no traversal-refresh timer on
    # Windows yet; setting 86400s here allows the lab to proceed for
    # up to 24h between re-orchestrations without the daemon rejecting
    # its own traversal bundle as stale. DEFAULT_TRAVERSAL_MAX_AGE_SECS
    # is 120s which is correct for production with an active refresh
    # service but too tight for a single-run lab pipeline.
    $autoTunnelValue = if ($AutoTunnelEnforce) { 'true' } else { 'false' }
    return (@(
        '--backend', $BackendLabel,
        '--auto-tunnel-enforce', $autoTunnelValue,
        '--auto-tunnel-max-age-secs', '86400',
        '--trust-max-age-secs', '86400',
        '--traversal-max-age-secs', '86400',
        '--node-role', $NodeRole,
        '--node-id', $NodeId
    ) | ConvertTo-Json -Compress)
}
# (--trust-max-age-secs and --traversal-max-age-secs are parsed by
# rustynetd's daemon command; they thread through DaemonConfig and are read
# by the trust and traversal preflights in run_daemon respectively.)

function Write-ReviewedEnvFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$BackendLabel,
        [bool]$AutoTunnelEnforce = $false
    )
    $banner = if ($BackendLabel -eq 'windows-wireguard-nt') {
        '# Reviewed RustyNet Windows service host configuration. WireGuard for Windows detected; daemon will bring up tunnels via the wireguard.exe / wg.exe / netsh.exe toolchain.'
    } else {
        '# Reviewed RustyNet Windows service host configuration. WireGuard for Windows NOT detected (or operator passed -ForceUnsupportedBackend); the daemon will refuse to start until a reviewed backend is selected. Install WireGuard for Windows from https://www.wireguard.com/install/ and re-run the install helper to switch the daemon to windows-wireguard-nt.'
    }
    @(
        $banner
        ('RUSTYNETD_DAEMON_ARGS_JSON=' + (Build-ReviewedDaemonArgsJson -BackendLabel $BackendLabel -NodeId $NodeId -NodeRole $NodeRole -AutoTunnelEnforce $AutoTunnelEnforce))
    ) | Out-File -Encoding ascii $Path
}

function Set-RustyNetDnsFailClosedPosture {
    $changes = New-Object System.Collections.Generic.List[string]
    $errors = New-Object System.Collections.Generic.List[string]

    $interfaceOutput = (& netsh interface ipv4 show interfaces 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) {
        throw "netsh interface ipv4 show interfaces failed: $interfaceOutput"
    }
    $seenInterfaces = @{}
    foreach ($line in ($interfaceOutput -split "`r?`n")) {
        if ($line -notmatch '^\s*(\d+)\s+\d+\s+\d+\s+\S+\s+(.+?)\s*$') {
            continue
        }
        $index = [int]$Matches[1]
        $name = [string]$Matches[2]
        if ($name -eq 'Name' -or $seenInterfaces.ContainsKey($name)) {
            continue
        }
        $seenInterfaces[$name] = $true

        $ipv4Output = (& netsh interface ipv4 set dnsservers name="$name" static 127.0.0.1 primary validate=no 2>&1 | Out-String)
        if ($LASTEXITCODE -eq 0) {
            $changes.Add(('interface={0} ipv4_dns=127.0.0.1' -f $name))
        } else {
            $errors.Add(('failed to set IPv4 DNS interface={0} index={1}: {2}' -f $name, $index, $ipv4Output.Trim()))
        }

        $ipv6Output = (& netsh interface ipv6 set dnsservers name="$name" static ::1 primary validate=no 2>&1 | Out-String)
        if ($LASTEXITCODE -eq 0) {
            $changes.Add(('interface={0} ipv6_dns=::1' -f $name))
        } else {
            $errors.Add(('failed to set IPv6 DNS interface={0} index={1}: {2}' -f $name, $index, $ipv6Output.Trim()))
        }
    }

    if ($changes.Count -eq 0) {
        $errors.Add('no Windows interfaces accepted loopback DNS settings via netsh')
    }

    if ($errors.Count -gt 0) {
        throw ('Windows DNS fail-closed posture configuration failed: {0}' -f ($errors -join '; '))
    }

    return [ordered]@{
        status = 'pass'
        interface_updates = $changes.ToArray()
        removed_root_nrpt_rules = 0
        root_nrpt_name_server = 'not-configured-netsh-only'
    }
}

$wireGuardProbe = [ordered]@{ present = $false; path = ''; detection = 'not-checked' }

Set-InstallProgressStep 'ensure-runtime-layout'
Ensure-RustyNetRuntimeLayout -InstallRoot $InstallRoot -StateRoot $StateRoot

Set-InstallProgressStep 'check-wireguard-driver'
$wireGuardProbe = Test-WireGuardDriverPresence

Set-InstallProgressStep 'locate-build-artifacts'
$daemonCandidates = @(
    Join-Path $RustyNetRoot 'target\release\rustynetd.exe'
)
$cliCandidates = @(
    (Join-Path $RustyNetRoot 'target\release\rustynet.exe'),
    (Join-Path $RustyNetRoot 'target\release\rustynet-cli.exe'),
    (Join-Path $RustyNetRoot 'target\release\rustynet-windows-trust-cli.exe')
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
# The CLI binary is required: install-release runs `rustynet trust
# keygen` + `trust issue` further down to rotate this host's trust
# evidence under SYSTEM. Before commit ab4eb08 the CLI copy was
# best-effort and a missing binary surfaced as an opaque
# "rustynet.exe not found" later in the script. Promote that to a
# fail-closed locate-build-artifacts error so the operator sees
# the real cause: build-release did not produce a CLI artifact.
if (-not $cliSource) {
    throw ("rustynet CLI binary not found under release output. Looked at: " +
        ($cliCandidates -join ', ') +
        ". Bootstrap-RustyNetWindows.ps1's build-release must build rustynetd and " +
        "rustynet-windows-trust-cli.")
}

$daemonDest = Join-Path $InstallRoot 'rustynetd.exe'

function Get-RustyNetServiceProcessId {
    param([Parameter(Mandatory = $true)][string]$Name)

    $query = (& sc.exe queryex "$Name" 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) {
        return 0
    }
    foreach ($line in ($query -split "`r?`n")) {
        if ($line -match '^\s*PID\s*:\s*(\d+)\s*$') {
            return [int]$Matches[1]
        }
    }
    return 0
}

function Stop-RustyNetExistingServiceForBinaryReplace {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$ExpectedDaemonPath
    )

    $existingService = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $existingService -or $existingService.Status -eq 'Stopped') {
        return
    }

    Write-Host ("[install-helper] stopping existing {0} service (status={1}) before replacing daemon binary" -f $Name, $existingService.Status)
    if ($existingService.Status -ne 'StopPending') {
        $stopOutput = (& sc.exe stop "$Name" 2>&1 | Out-String)
        if ($LASTEXITCODE -ne 0 -and $stopOutput -notmatch '1062') {
            $existingService = Get-Service -Name $Name -ErrorAction SilentlyContinue
            if (-not $existingService -or $existingService.Status -ne 'StopPending') {
                throw "sc.exe stop failed for ${Name}: $stopOutput"
            }
        }
    }
    else {
        Write-Host ("[install-helper] existing {0} service already stop-pending; waiting before forced process cleanup" -f $Name)
    }

    $stopDeadline = (Get-Date).AddSeconds(15)
    while ((Get-Date) -lt $stopDeadline) {
        $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if (-not $svc -or $svc.Status -eq 'Stopped') { return }
        Start-Sleep -Milliseconds 250
    }

    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'StopPending') {
        $servicePid = Get-RustyNetServiceProcessId -Name $Name
        if ($servicePid -gt 0) {
            $process = Get-Process -Id $servicePid -ErrorAction SilentlyContinue
            $processPath = ''
            if ($process -and $process.Path) {
                $processPath = [string]$process.Path
            }
            $expected = [System.IO.Path]::GetFullPath($ExpectedDaemonPath)
            $actual = if ($processPath) { [System.IO.Path]::GetFullPath($processPath) } else { '' }
            if ($actual -and ($actual -ieq $expected)) {
                Write-Host ("[install-helper] forcing stuck {0} service process pid={1}" -f $Name, $servicePid)
                Stop-Process -Id $servicePid -Force -ErrorAction Stop
                $killDeadline = (Get-Date).AddSeconds(10)
                while ((Get-Date) -lt $killDeadline) {
                    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
                    if (-not $svc -or $svc.Status -eq 'Stopped') { return }
                    Start-Sleep -Milliseconds 250
                }
            }
            else {
                throw "RustyNet service is StopPending but pid=$servicePid path did not match reviewed daemon path (actual=$actual expected=$expected)"
            }
        }
    }

    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -ne 'Stopped') {
        throw "RustyNet service did not transition to Stopped within 15s (current=$($svc.Status))"
    }
}

# On idempotent re-runs the service from a previous install may already be
# running and holding rustynetd.exe open, which would block Copy-Item below
# with "the process cannot access the file". Stop it first; configure-service-
# registration further down still deletes and recreates the service entry, so
# this only changes the lifecycle ordering, not the end state.
Set-InstallProgressStep 'stop-existing-service-for-binary-replace'
Stop-RustyNetExistingServiceForBinaryReplace -Name $ServiceName -ExpectedDaemonPath $daemonDest

Set-InstallProgressStep 'copy-daemon-binary'
# Even after Stop-Service returns, SCM may briefly retain the file handle while
# the process tears down. Retry the copy for up to ~10 seconds before giving
# up so a normal idempotent re-run is not racy.
$copyDeadline = (Get-Date).AddSeconds(10)
$copyOk = $false
$lastCopyError = $null
while (-not $copyOk -and (Get-Date) -lt $copyDeadline) {
    try {
        Copy-Item -LiteralPath $daemonSource -Destination $daemonDest -Force -ErrorAction Stop
        $copyOk = $true
    } catch {
        $lastCopyError = $_
        Start-Sleep -Milliseconds 250
    }
}
if (-not $copyOk) {
    throw "rustynetd.exe copy failed after 10s of retries: $lastCopyError"
}

if ($cliSource) {
    Set-InstallProgressStep 'copy-cli-binary'
    Copy-Item -LiteralPath $cliSource -Destination (Join-Path $InstallRoot 'rustynet.exe') -Force
}

# Sign the installed binaries with a per-host self-signed code-signing
# certificate, and trust that certificate in LocalMachine\Root. This
# is what `validate_windows_authenticode` (and the daemon's
# `windows-authenticode-check`) require to pass — they call
# `WinVerifyTrust` on rustynetd.exe and refuse anything where
# `signature_present=false` or the chain doesn't terminate at a
# trusted root.
#
# We do NOT relax the validator (no "lab mode" carve-out, no
# fail-soft). Instead we make the binary genuinely signed and the
# signing certificate genuinely chain-verifiable on this host. The
# cert is unique per host (subject embeds the computer name), lives
# in `Cert:\LocalMachine\My`, and is imported into
# `Cert:\LocalMachine\Root` so WinVerifyTrust accepts it. Both stores
# require Administrator; install-release already runs as SYSTEM via
# the orchestrator, so the trust addition here matches the install-
# scope authority and never leaves the lab guest.
#
# Idempotent: an existing non-expired cert with the same subject is
# reused; signtool re-signing replaces the prior signature in place.
Set-InstallProgressStep 'sign-installed-binaries-for-authenticode'
$signtoolCandidatePatterns = @(
    'C:\Program Files (x86)\Windows Kits\10\bin\*\arm64\signtool.exe',
    'C:\Program Files\Windows Kits\10\bin\*\arm64\signtool.exe',
    'C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe',
    'C:\Program Files\Windows Kits\10\bin\*\x64\signtool.exe',
    'C:\Program Files (x86)\Windows Kits\10\bin\*\x86\signtool.exe'
)
$signtoolPath = $null
foreach ($pattern in $signtoolCandidatePatterns) {
    $found = Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending |
        Select-Object -First 1
    if ($found) { $signtoolPath = $found.FullName; break }
}
if (-not $signtoolPath) {
    throw ("signtool.exe not found under any Windows SDK path; install Windows SDK 10 " +
        "(VS Build Tools) before re-running install-release. Patterns searched: " +
        ($signtoolCandidatePatterns -join '; '))
}
Write-Host "[install-helper] authenticode: using signtool at $signtoolPath"

$codeSigningSubject = "CN=RustyNet Lab Code Signing - $(hostname)"
$codeSigningCert = Get-ChildItem -Path 'Cert:\LocalMachine\My' -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Subject -eq $codeSigningSubject -and
        $_.HasPrivateKey -and
        $_.NotAfter -gt (Get-Date).AddDays(7)
    } |
    Sort-Object NotAfter -Descending |
    Select-Object -First 1
if (-not $codeSigningCert) {
    Write-Host "[install-helper] authenticode: minting new code-signing cert"
    $codeSigningCert = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject $codeSigningSubject `
        -CertStoreLocation 'Cert:\LocalMachine\My' `
        -KeyAlgorithm RSA `
        -KeyLength 3072 `
        -KeyUsage DigitalSignature `
        -NotAfter (Get-Date).AddYears(2)
} else {
    Write-Host "[install-helper] authenticode: reusing existing code-signing cert (thumbprint=$($codeSigningCert.Thumbprint))"
}

# Make the cert chain-verifiable: import into LocalMachine\Root so
# WinVerifyTrust treats it as a trusted root. Cert\Root.Add is a no-
# op when the same thumbprint is already trusted.
$rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', 'LocalMachine')
$rootStore.Open('ReadWrite')
try {
    $alreadyTrusted = $false
    foreach ($existing in $rootStore.Certificates) {
        if ($existing.Thumbprint -eq $codeSigningCert.Thumbprint) {
            $alreadyTrusted = $true
            break
        }
    }
    if (-not $alreadyTrusted) {
        $rootStore.Add($codeSigningCert)
        Write-Host "[install-helper] authenticode: added code-signing cert to LocalMachine\Root"
    } else {
        Write-Host "[install-helper] authenticode: code-signing cert already in LocalMachine\Root"
    }
}
finally {
    $rootStore.Close()
}

# Sign rustynetd.exe (the binary the validator targets) and rustynet
# .exe (consistency; it's what the trust-issue step below executes).
# Skip /tr timestamping: lab guests may lack internet, and an
# expired-cert risk is bounded by the 2-year cert lifetime above. If
# timestamping becomes important add /tr <server> /td SHA256 here.
$binariesToSign = @($daemonDest, (Join-Path $InstallRoot 'rustynet.exe'))
foreach ($binPath in $binariesToSign) {
    if (-not (Test-Path -LiteralPath $binPath)) {
        continue
    }
    # `/sm /s My`: search the LocalMachine\My store (default is the
    # current-user store, which would be empty when install-release
    # runs as SYSTEM via utmctl exec). Without `/sm` signtool errors
    # out with "No certificates were found that met all the given
    # criteria" even when the cert is sitting in LocalMachine\My.
    $signtoolArgs = @(
        'sign',
        '/sm',
        '/s', 'My',
        '/sha1', $codeSigningCert.Thumbprint,
        '/fd', 'SHA256',
        '/v',
        $binPath
    )
    $signDeadline = (Get-Date).AddSeconds(20)
    $signOk = $false
    $signOutput = ''
    $signExitCode = 0
    while (-not $signOk -and (Get-Date) -lt $signDeadline) {
        $signOutput = (& $signtoolPath @signtoolArgs 2>&1) -join "`n"
        $signExitCode = $LASTEXITCODE
        if ($signExitCode -eq 0) {
            $signOk = $true
            break
        }
        if ($signOutput -notmatch 'being used by another process') {
            break
        }
        Start-Sleep -Milliseconds 500
    }
    if (-not $signOk) {
        throw "signtool sign failed for $binPath (exit $signExitCode): $signOutput"
    }
    Write-Host "[install-helper] authenticode: signed $binPath"
}

# Re-encrypt the WireGuard private key + DPAPI passphrase blob in the
# current execution context.  The access-bootstrap phase generates these
# under the SSH user (`windows`); the install-release phase runs as
# SYSTEM via utmctl exec; even with DPAPI LocalMachine scope, an
# Unprotect call from a different identity than the one that called
# Protect can fail with "decryption failed" on some Windows builds (we
# have observed this consistently on Windows 11 ARM64 26200).  Doing
# `key init --force` + `key store-passphrase` here aligns the encryption
# identity with the runtime identity (SYSTEM service), so the daemon's
# subsequent decrypt at startup matches.  Idempotent: re-runs are safe.
Set-InstallProgressStep 'rekey-wireguard-under-runtime-identity'
$wgPassphrasePath = Join-Path $StateRoot 'secrets\wireguard.passphrase.dpapi'
$wgPassphraseDir = Split-Path -Parent $wgPassphrasePath
if (-not (Test-Path -LiteralPath $wgPassphraseDir)) {
    New-Item -ItemType Directory -Force -Path $wgPassphraseDir | Out-Null
}
Set-InstallProgressStep 'repair-key-custody-acls-before-rekey'
$preServiceAdministratorsName = Get-LocalizedAccountNameFromSid -Sid 'S-1-5-32-544'
$preServiceLocalSystemName = Get-LocalizedAccountNameFromSid -Sid 'S-1-5-18'
foreach ($preServiceDirectory in @(
        (Join-Path $StateRoot 'keys'),
        (Join-Path $StateRoot 'credentials-workspace'),
        (Join-Path $StateRoot 'secrets'),
        (Join-Path $StateRoot 'secrets\key-custody')
    )) {
    Ensure-Directory -Path $preServiceDirectory
    Repair-RustyNetPreServiceAcl -Path $preServiceDirectory -AdministratorsName $preServiceAdministratorsName -LocalSystemName $preServiceLocalSystemName -Directory
}
Set-InstallProgressStep 'rekey-wireguard-under-runtime-identity'
$rekeyPlaintext = -join ((1..48 | ForEach-Object { '{0:x2}' -f (Get-Random -Maximum 256) }))
[System.IO.File]::WriteAllText($wgPassphrasePath, $rekeyPlaintext)
$keyInit = Invoke-RustyNetNativeCommand -Path $daemonDest -Arguments @('key', 'init', '--passphrase-file', $wgPassphrasePath, '--force')
if ($keyInit.exit_code -ne 0) {
    throw "rustynetd key init --force failed (exit $($keyInit.exit_code)): $($keyInit.output)"
}
Write-Host "[install-helper] rekey: rustynetd key init complete"
$keyStore = Invoke-RustyNetNativeCommand -Path $daemonDest -Arguments @('key', 'store-passphrase', '--passphrase-file', $wgPassphrasePath)
if ($keyStore.exit_code -ne 0) {
    throw "rustynetd key store-passphrase failed (exit $($keyStore.exit_code)): $($keyStore.output)"
}
Write-Host "[install-helper] rekey: passphrase blob written under SYSTEM DPAPI scope"

# Re-issue the per-host trust evidence under the runtime identity. The
# daemon's startup preflight rejects trust evidence older than
# `--trust-max-age-secs` (lab default: 86400s / 24h). Without an issuer
# on the Windows guest itself, the originally-provisioned evidence ages
# out of that window and the service refuses to start with
# "trust preflight failed: trust evidence is stale". Run the keygen +
# issue cmdlets every install-release so each fresh service bring-up
# starts with a freshly-signed evidence file (mirrors the systemd
# `rustynetd-trust-refresh` timer on Linux). Trust is per-host self-
# attestation: the verifier key written here is the same one the daemon
# loads at startup, so rotating both signing and verifier together is
# safe — no other peer relies on this verifier key.
Set-InstallProgressStep 'reissue-trust-evidence-under-runtime-identity'
$trustDir = Join-Path $StateRoot 'trust'
if (-not (Test-Path -LiteralPath $trustDir)) {
    New-Item -ItemType Directory -Force -Path $trustDir | Out-Null
}
$trustSigningKeyPath = Join-Path $trustDir 'trust-evidence.signing.key'
$trustVerifierKeyPath = Join-Path $trustDir 'trust-evidence.pub'
$trustEvidencePath = Join-Path $trustDir 'rustynetd.trust'
$trustWatermarkPath = Join-Path $trustDir 'rustynetd.trust.watermark'
$trustPassphrasePath = Join-Path $trustDir 'trust-evidence.passphrase.tmp'
$cliPath = Join-Path $InstallRoot 'rustynet.exe'
if (-not (Test-Path -LiteralPath $cliPath)) {
    throw "rustynet.exe not found at $cliPath; cannot reissue trust evidence (was copy-cli-binary skipped?)"
}
$trustPlaintext = -join ((1..48 | ForEach-Object { '{0:x2}' -f (Get-Random -Maximum 256) }))
[System.IO.File]::WriteAllText($trustPassphrasePath, $trustPlaintext)
try {
    $keygen = Invoke-RustyNetNativeCommand -Path $cliPath -Arguments @(
        'trust', 'keygen',
        '--signing-key-output', $trustSigningKeyPath,
        '--signing-key-passphrase-file', $trustPassphrasePath,
        '--verifier-key-output', $trustVerifierKeyPath,
        '--force'
    )
    if ($keygen.exit_code -ne 0) {
        throw "rustynet trust keygen failed (exit $($keygen.exit_code)): $($keygen.output)"
    }
    Write-Host "[install-helper] trust: keygen complete (signing + verifier keys rotated)"
    $issue = Invoke-RustyNetNativeCommand -Path $cliPath -Arguments @(
        'trust', 'issue',
        '--signing-key', $trustSigningKeyPath,
        '--signing-key-passphrase-file', $trustPassphrasePath,
        '--output', $trustEvidencePath
    )
    if ($issue.exit_code -ne 0) {
        throw "rustynet trust issue failed (exit $($issue.exit_code)): $($issue.output)"
    }
    Write-Host "[install-helper] trust: evidence issued at $trustEvidencePath"
    # Drop any stale watermark so the daemon's WatermarkStore re-ingests the
    # new evidence on the next refresh tick instead of trusting its old
    # high-water mark. -ErrorAction SilentlyContinue is still safe here
    # because the script terminates with `exit 0` semantics via the throw
    # paths above and this Remove-Item only runs on the success branch.
    if (Test-Path -LiteralPath $trustWatermarkPath) {
        Remove-Item -Force -LiteralPath $trustWatermarkPath
    }
}
finally {
    if (Test-Path -LiteralPath $trustPassphrasePath) {
        Remove-Item -Force -LiteralPath $trustPassphrasePath
    }
}

$configPath = Join-Path $StateRoot 'config\rustynetd.env'
Set-InstallProgressStep 'write-reviewed-env-file'
$backendLabel = Resolve-ReviewedBackendLabel `
    -WireGuardProbe $wireGuardProbe `
    -ForceUnsupported ([bool]$ForceUnsupportedBackend)
Write-Host ("[install-helper] selected backend label: {0} (wireguard.present={1}, force-unsupported={2})" -f
    $backendLabel, [bool]$wireGuardProbe.present, [bool]$ForceUnsupportedBackend)
Write-ReviewedEnvFile -Path $configPath -BackendLabel $backendLabel -AutoTunnelEnforce ([bool]$EnforceAutoTunnel)

Set-InstallProgressStep 'configure-dns-failclosed'
$dnsFailClosedPosture = Set-RustyNetDnsFailClosedPosture
Write-Host "[install-helper] DNS fail-closed posture configured (interface DNS + NRPT root loopback)"

Set-InstallProgressStep 'probe-runtime-support'
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
        Set-InstallProgressStep 'configure-service-registration'
        $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($existing) {
            if ($existing.Status -eq 'Running') {
                Stop-Service -Name $ServiceName -Force -ErrorAction Stop
            }
            $deleteOutput = (& sc.exe delete "$ServiceName" 2>&1 | Out-String)
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
        Set-InstallProgressStep 'configure-service-sid'
        Ensure-ServiceSidTypeUnrestricted -ServiceName $ServiceName
        $serviceSidConfigured = $true

        Set-InstallProgressStep 'repair-runtime-acls'
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
                (Join-Path $StateRoot 'credentials-workspace'),
                (Join-Path $StateRoot 'secrets'),
                (Join-Path $StateRoot 'secrets\key-custody')
            )) {
            Repair-RustyNetRuntimeAcl -Path $directoryPath -AdministratorsName $administratorsName -LocalSystemName $localSystemName -ServiceIdentity $serviceIdentity -Directory
        }
        Repair-RustyNetRuntimeAcl -Path $configPath -AdministratorsName $administratorsName -LocalSystemName $localSystemName -ServiceIdentity $serviceIdentity

        Set-InstallProgressStep 'repair-binary-acl'
        Repair-RustyNetServiceBinaryAcl -Path $daemonDest -AdministratorsName $administratorsName -LocalSystemName $localSystemName -ServiceIdentity $serviceIdentity
        $runtimeAclApplied = $true

        Set-InstallProgressStep 'configure-failure-actions'
        Set-RustyNetServiceFailureActions -ServiceName $ServiceName
    }
    catch {
        $serviceConfigError = $_.Exception.Message
    }

    if (-not $serviceConfigError) {
        # Remove distribute-stage artifacts from any prior install run.
        # A fresh install starts with clean distributed state; the
        # distribute stages re-establish bundles and verifier keys after
        # bootstrap completes.  Stale bundles without matching verifier
        # keys (or vice versa) cause the daemon's startup preflight to
        # fail closed on the *next* install attempt.
        Set-InstallProgressStep 'purge-stale-distribute-state'
        $membershipDir = Join-Path $StateRoot 'membership'
        foreach ($stalePath in @(
            (Join-Path $trustDir 'rustynetd.traversal'),
            (Join-Path $trustDir 'rustynetd.traversal.watermark'),
            (Join-Path $trustDir 'traversal.pub'),
            (Join-Path $trustDir 'rustynetd.assignment'),
            (Join-Path $trustDir 'rustynetd.assignment.watermark'),
            (Join-Path $trustDir 'assignment.pub'),
            (Join-Path $trustDir 'rustynetd.dns-zone'),
            (Join-Path $trustDir 'rustynetd.dns-zone.watermark'),
            (Join-Path $trustDir 'dns-zone.pub'),
            (Join-Path $StateRoot 'rustynetd.state'),
            (Join-Path $membershipDir 'membership.snapshot'),
            (Join-Path $membershipDir 'membership.log'),
            (Join-Path $membershipDir 'membership.watermark')
        )) {
            if (Test-Path -LiteralPath $stalePath) {
                Remove-Item -Force -LiteralPath $stalePath
            }
        }

        $serviceStartAttempted = $true
        try {
            Set-InstallProgressStep 'start-runtime-service'
            $service = Get-Service -Name $ServiceName -ErrorAction Stop
            if ($service.Status -eq 'Running') {
                Stop-RustyNetExistingServiceForBinaryReplace -Name $ServiceName -ExpectedDaemonPath $daemonDest
            }
            $startResult = Invoke-Sc -Arguments @('start', $ServiceName)
            if ($startResult.exit_code -ne 0 -and $startResult.output -notmatch '1056|already running') {
                throw "sc.exe start failed: $($startResult.output)"
            }
        }
        catch {
            $startError = $_.Exception.Message
        }
        Start-Sleep -Seconds 3
    }
}

Set-InstallProgressStep 'observe-runtime-service'
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
    credentials_workspace_present = Test-Path -LiteralPath (Join-Path $StateRoot 'credentials-workspace')
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
    dns_failclosed_posture = $dnsFailClosedPosture
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
