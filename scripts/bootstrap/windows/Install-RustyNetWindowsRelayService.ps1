param(
    [string]$RustyNetRoot = 'C:\Rustynet',
    [string]$InstallRoot = 'C:\Program Files\RustyNet',
    [string]$RelayRoot = 'C:\ProgramData\RustyNet\relay',
    [string]$ServiceName = 'RustyNetRelay',
    [string]$RelayId = 'relay-win-1',
    [string]$VerifierKeyPath = 'C:\ProgramData\RustyNet\relay\control.pub',
    [string]$ReplayStorePath = 'C:\ProgramData\RustyNet\relay\replay.store',
    # NOT 4500: Windows's built-in IKEEXT/IPsec Policy Agent service binds
    # UDP 4500 system-wide (IPsec NAT-Traversal) even for a loopback- or
    # address-specific bind request, so rustynet-relay's UdpSocket::bind
    # fails closed with WSAEACCES (os error 10013) on every real Windows
    # host at that port. Matches REVIEWED_WINDOWS_RELAY_BIND_PORT in
    # rustynetd/src/windows_service_hardening.rs — keep both in sync.
    [string]$Bind = '0.0.0.0:4600',
    [string]$PortRange = '50000-59999',
    [string]$HealthBind = '127.0.0.1:9100',
    # QH-28. Opt OUT of minting a self-signed code-signing certificate and
    # trusting it in LocalMachine\Root. Mirrors the daemon installer's switch,
    # and exists for the same reason: this script is reachable from the SHIPPED
    # binary, so its root-store write was landing on users' machines too.
    #
    # NOT via `rustynet ops install-windows-relay-service` — that verb is
    # `#[cfg(feature = "vm-lab")]` and is not compiled into release builds. The
    # shipped path is `rustynet role set`, which is ungated:
    # execute_role_plan -> execute_role_action -> DeployRelayService ->
    # execute_platform_relay_service_action -> execute_ops_install_windows_relay_service.
    # That caller passes RelaySelfSignedCodeSigning::Disallow, which is what
    # supplies this switch; the vm-lab verb passes Allow, because lab guests are
    # disposable and run binaries built from source.
    #
    # Inverted for the same reason as the daemon's — an opt-out is passed by the
    # callers that need it, whereas an opt-in would have to be threaded through
    # every lab and e2e caller and a new one would silently lose signing.
    [switch]$NoSelfSignedCodeSigning,
    [switch]$StartService,
    [string]$OutputPath = ''
)

# Bound once so the signing function can see it regardless of call scope.
$script:NoSelfSignedCodeSigningRequested = [bool]$NoSelfSignedCodeSigning

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$script:InstallFailureStep = 'init'

function Test-ReviewedRelayServiceName {
    param([Parameter(Mandatory = $true)][string]$Name)
    if ($Name -ne 'RustyNetRelay') {
        throw ('relay service name must be RustyNetRelay; received {0}' -f $Name)
    }
}

function Test-ReviewedInstallRoot {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ($Path -ne 'C:\Program Files\RustyNet') {
        throw ('install root must be C:\Program Files\RustyNet; received {0}' -f $Path)
    }
}

function Test-ReviewedRelayRoot {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ($Path -ne 'C:\ProgramData\RustyNet\relay') {
        throw ('relay root must be C:\ProgramData\RustyNet\relay; received {0}' -f $Path)
    }
}

function Test-ReviewedRelayRuntimePath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )
    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw "$Label must not be empty"
    }
    if ($Path.StartsWith('\\') -or $Path.StartsWith('\\.\pipe\')) {
        throw "$Label must be a local filesystem path under C:\ProgramData\RustyNet\relay"
    }
    $normalized = $Path.Replace('/', '\')
    if ($normalized -match '(^|\\)\.\.?($|\\)') {
        throw "$Label must not contain traversal segments: $Path"
    }
    $root = 'C:\ProgramData\RustyNet\relay'
    if (($normalized -ne $root) -and (-not $normalized.StartsWith("$root\"))) {
        throw "$Label must stay under $root; received $Path"
    }
}

function Test-RelayId {
    param([Parameter(Mandatory = $true)][string]$Value)
    if ($Value.Length -lt 1 -or $Value.Length -gt 16) {
        throw 'relay id must be 1-16 ASCII label chars'
    }
    if ($Value -notmatch '^[A-Za-z0-9_.-]+$') {
        throw ('relay id must be ASCII alphanumeric plus dot, dash, underscore; received {0}' -f $Value)
    }
}

function Test-Endpoint {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Label,
        [switch]$RequireLoopback
    )
    if ($Value -notmatch '^([0-9]{1,3}(\.[0-9]{1,3}){3}):([0-9]{1,5})$') {
        throw "$Label must be an IPv4:port endpoint; received $Value"
    }
    $ipAddress = $null
    if (-not [System.Net.IPAddress]::TryParse($Matches[1], [ref]$ipAddress)) {
        throw "$Label IPv4 address is invalid; received $Value"
    }
    $port = [int]$Matches[3]
    if ($port -lt 1 -or $port -gt 65535) {
        throw "$Label port out of range; received $Value"
    }
    if ($RequireLoopback -and (-not [System.Net.IPAddress]::IsLoopback($ipAddress))) {
        throw "$Label must use a loopback address; received $Value"
    }
}

function Test-PortRange {
    param([Parameter(Mandatory = $true)][string]$Value)
    if ($Value -notmatch '^([0-9]{1,5})-([0-9]{1,5})$') {
        throw ('port range must be start-end; received {0}' -f $Value)
    }
    $start = [int]$Matches[1]
    $end = [int]$Matches[2]
    if ($start -lt 1 -or $end -gt 65535 -or $start -ge $end) {
        throw ('port range must be within 1..65535 with start < end; received {0}' -f $Value)
    }
}

function Get-EndpointPort {
    param([Parameter(Mandatory = $true)][string]$Value)
    if ($Value -notmatch ':([0-9]{1,5})$') {
        throw "endpoint missing port: $Value"
    }
    return [int]$Matches[1]
}

function Ensure-Directory {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Force -Path $Path | Out-Null
    }
}

function Get-LocalizedAccountNameFromSid {
    param([Parameter(Mandatory = $true)][string]$Sid)
    $sidObject = New-Object System.Security.Principal.SecurityIdentifier($Sid)
    return $sidObject.Translate([System.Security.Principal.NTAccount]).Value
}

function Get-ServiceIdentityName {
    param([Parameter(Mandatory = $true)][string]$ServiceName)
    return "NT SERVICE\$ServiceName"
}

function Invoke-Sc {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    $output = (& sc.exe @Arguments 2>&1 | Out-String)
    return [ordered]@{
        exit_code = $LASTEXITCODE
        output = $output.Trim()
    }
}

# Architectures whose signtool.exe can actually EXECUTE on this machine, most
# preferred first. The full rationale lives above the same block in
# Install-RustyNetWindowsService.ps1; the resolver itself is duplicated verbatim
# rather than shared, because these scripts are SCP'd to the guest individually
# and cannot dot-source a common file.
#
# --- BEGIN shared signtool resolver -----------------------------------------
# Byte-identical in Install-RustyNetWindowsService.ps1 and
# Install-RustyNetWindowsRelayService.ps1, and pinned to stay that way by
# windows_installers_share_one_signtool_resolver in
# crates/rustynet-cli/src/ops_e2e.rs. Do not edit one copy alone: the daemon and
# the relay must be signed by the same signtool, and a comment asking for that is
# not a control.
function Get-ResolvedProcessorArchitecture {
    # PROCESSOR_ARCHITEW6432 is set when a 32-bit process runs on a 64-bit OS and
    # reports the NATIVE architecture; PROCESSOR_ARCHITECTURE would report the
    # emulated one. Prefer the native answer.
    $arch = $env:PROCESSOR_ARCHITEW6432
    if (-not $arch) { $arch = $env:PROCESSOR_ARCHITECTURE }
    return [string]$arch
}

function Get-RunnableSigntoolArchitectures {
    $arch = Get-ResolvedProcessorArchitecture
    switch ($arch) {
        # arm64 Windows runs arm64 natively and x64/x86 under emulation.
        'ARM64' { return @('arm64', 'x64', 'x86') }
        # x64 Windows runs x64 natively and x86 under WOW64. NOT arm64.
        'AMD64' { return @('x64', 'x86') }
        'x86'   { return @('x86') }
        # Fail closed rather than guessing. Defaulting to x64/x86 would, on a
        # genuine ARM32 host, select an image that cannot execute -- reintroducing
        # exactly the obscure exec failure this ordering exists to prevent.
        default {
            throw ("unsupported processor architecture for signtool selection: '" +
                $arch + "'; expected ARM64, AMD64 or x86")
        }
    }
}

function Resolve-RustyNetSigntoolPath {
    $roots = @(
        'C:\Program Files (x86)\Windows Kits\10\bin',
        'C:\Program Files\Windows Kits\10\bin'
    )
    # Enumerate version-shaped SDK directories only, newest first by NUMERIC
    # version. Globbing bin\*\ and sorting FullName lexicographically (the prior
    # form) let a stray directory such as 'zz-backup' outrank the real SDK, and
    # ordered 10.0.9041.0 ABOVE 10.0.26100.0 because the comparison was textual.
    $versionDirs = @()
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        $versionDirs += @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^10\.\d+\.\d+\.\d+$' })
    }
    $versionDirs = @($versionDirs | Sort-Object -Property { [version]$_.Name } -Descending)
    # Architecture is the OUTER loop: a runnable architecture matters more than a
    # newer SDK, because an unrunnable image cannot sign at all.
    foreach ($arch in (Get-RunnableSigntoolArchitectures)) {
        foreach ($versionDir in $versionDirs) {
            $candidate = Join-Path $versionDir.FullName (Join-Path $arch 'signtool.exe')
            if (Test-Path -LiteralPath $candidate) { return $candidate }
        }
    }
    return $null
}
# --- END shared signtool resolver -------------------------------------------

function Find-Signtool {
    $signtoolPath = Resolve-RustyNetSigntoolPath
    if (-not $signtoolPath) {
        throw ("signtool.exe not found under any Windows SDK path runnable on this " +
            "machine (resolved architecture: " + (Get-ResolvedProcessorArchitecture) +
            "); install Windows SDK 10 (VS Build Tools) before installing " +
            "RustyNetRelay.")
    }
    return $signtoolPath
}

function Sign-RelayBinaryForAuthenticode {
    param([Parameter(Mandatory = $true)][string]$Path)
    # Gated at function entry rather than at the call sites, so a future caller
    # cannot reintroduce the root-store write by forgetting the guard.
    if ($script:NoSelfSignedCodeSigningRequested) {
        Write-Host "[relay-install] authenticode: self-signed code signing disabled (-NoSelfSignedCodeSigning); no certificate minted and no root-store change"
        return
    }
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "relay binary does not exist for signing: $Path"
    }
    $signtoolPath = Find-Signtool
    $subject = "CN=RustyNet Relay Lab Code Signing - $(hostname)"
    $cert = Get-ChildItem -Path 'Cert:\LocalMachine\My' -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Subject -eq $subject -and
            $_.HasPrivateKey -and
            $_.NotAfter -gt (Get-Date).AddDays(7)
        } |
        Sort-Object NotAfter -Descending |
        Select-Object -First 1
    if (-not $cert) {
        $cert = New-SelfSignedCertificate `
            -Type CodeSigningCert `
            -Subject $subject `
            -CertStoreLocation 'Cert:\LocalMachine\My' `
            -KeyAlgorithm RSA `
            -KeyLength 3072 `
            -KeyUsage DigitalSignature `
            -NotAfter (Get-Date).AddYears(2)
    }

    $rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', 'LocalMachine')
    $rootStore.Open('ReadWrite')
    try {
        $alreadyTrusted = $false
        foreach ($existing in $rootStore.Certificates) {
            if ($existing.Thumbprint -eq $cert.Thumbprint) {
                $alreadyTrusted = $true
                break
            }
        }
        if (-not $alreadyTrusted) {
            $rootStore.Add($cert)
        }
    }
    finally {
        $rootStore.Close()
    }

    $signtoolArgs = @(
        'sign',
        '/sm',
        '/s', 'My',
        '/sha1', $cert.Thumbprint,
        '/fd', 'SHA256',
        '/v',
        $Path
    )
    $signOutput = (& $signtoolPath @signtoolArgs 2>&1) -join "`n"
    if ($LASTEXITCODE -ne 0) {
        throw "signtool sign failed for $Path (exit $LASTEXITCODE): $signOutput"
    }
}

function Repair-RelayRuntimeAcl {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$AdministratorsName,
        [Parameter(Mandatory = $true)][string]$LocalSystemName,
        [Parameter(Mandatory = $true)][string]$ServiceIdentity,
        [switch]$Directory,
        [switch]$ServiceReadOnly
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "ACL target does not exist: $Path"
    }
    & icacls "$Path" /setowner $AdministratorsName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls /setowner failed for $Path" }
    & icacls "$Path" /inheritance:r | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls /inheritance:r failed for $Path" }
    if ($Directory) {
        & icacls "$Path" /grant:r "$AdministratorsName`:(OI)(CI)(F)" "$LocalSystemName`:(OI)(CI)(F)" "$ServiceIdentity`:(OI)(CI)(M)" | Out-Null
    }
    elseif ($ServiceReadOnly) {
        & icacls "$Path" /grant:r "$AdministratorsName`:F" "$LocalSystemName`:F" "$ServiceIdentity`:R" | Out-Null
    }
    else {
        & icacls "$Path" /grant:r "$AdministratorsName`:F" "$LocalSystemName`:F" "$ServiceIdentity`:M" | Out-Null
    }
    if ($LASTEXITCODE -ne 0) { throw "icacls /grant:r failed for $Path" }
}

function Repair-RelayBinaryAcl {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$AdministratorsName,
        [Parameter(Mandatory = $true)][string]$LocalSystemName,
        [Parameter(Mandatory = $true)][string]$ServiceIdentity
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "relay binary does not exist: $Path"
    }
    & icacls "$Path" /setowner $AdministratorsName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls /setowner failed for $Path" }
    & icacls "$Path" /inheritance:r | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls /inheritance:r failed for $Path" }
    & icacls "$Path" /grant:r "$AdministratorsName`:F" "$LocalSystemName`:F" "$ServiceIdentity`:RX" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls /grant:r failed for binary $Path" }
}

function Set-RelayServiceFailureActions {
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

function Ensure-ServiceSidTypeUnrestricted {
    param([Parameter(Mandatory = $true)][string]$ServiceName)
    $result = Invoke-Sc -Arguments @('sidtype', $ServiceName, 'unrestricted')
    if ($result.exit_code -ne 0) {
        throw "sc.exe sidtype failed: $($result.output)"
    }
}

function New-FailClosedRelayInstallReport {
    param([Parameter(Mandatory = $true)][string]$Reason)
    return [ordered]@{
        schema_version = 1
        captured_at_utc = (Get-Date).ToUniversalTime().ToString('o')
        platform = 'windows'
        service_name = $ServiceName
        install_root = $InstallRoot
        relay_root = $RelayRoot
        status = 'fail'
        reason = $Reason
        failure_step = $script:InstallFailureStep
    }
}

function Write-RelayInstallReportIfRequested {
    param([Parameter(Mandatory = $true)][object]$Report)
    if (-not $OutputPath -or $OutputPath.Trim().Length -eq 0) {
        return
    }
    $outputDirectory = Split-Path -Parent $OutputPath
    if ($outputDirectory) {
        Ensure-Directory -Path $outputDirectory
    }
    ($Report | ConvertTo-Json -Depth 8) | Set-Content -Encoding utf8 -LiteralPath $OutputPath
}

trap {
    $failureReason = if ($_.Exception -and $_.Exception.Message) {
        $_.Exception.Message.Trim()
    }
    else {
        ($_ | Out-String).Trim()
    }
    if (-not $failureReason) {
        $failureReason = 'windows-relay-service-install-exception'
    }
    Write-RelayInstallReportIfRequested -Report (New-FailClosedRelayInstallReport -Reason $failureReason)
    Write-Error $_
    exit 1
}

Test-ReviewedRelayServiceName -Name $ServiceName
Test-ReviewedInstallRoot -Path $InstallRoot
Test-ReviewedRelayRoot -Path $RelayRoot
Test-ReviewedRelayRuntimePath -Path $VerifierKeyPath -Label 'verifier key path'
Test-ReviewedRelayRuntimePath -Path $ReplayStorePath -Label 'replay store path'
Test-RelayId -Value $RelayId
Test-Endpoint -Value $Bind -Label 'relay bind'
Test-Endpoint -Value $HealthBind -Label 'relay health bind' -RequireLoopback
Test-PortRange -Value $PortRange
if ((Get-EndpointPort -Value $Bind) -eq (Get-EndpointPort -Value $HealthBind)) {
    throw 'relay health bind port must not equal the relay UDP control bind port'
}

$script:InstallFailureStep = 'locate-build-artifacts'
$relaySource = Join-Path $RustyNetRoot 'target\release\rustynet-relay.exe'
if (-not (Test-Path -LiteralPath $relaySource)) {
    throw "rustynet-relay.exe was not found under release output: $relaySource"
}
if (-not (Test-Path -LiteralPath $VerifierKeyPath)) {
    throw "relay verifier key must exist before service install: $VerifierKeyPath"
}

$script:InstallFailureStep = 'prepare-runtime-layout'
Ensure-Directory -Path $InstallRoot
Ensure-Directory -Path $RelayRoot

$relayDest = Join-Path $InstallRoot 'rustynet-relay.exe'
$envFile = Join-Path $RelayRoot 'relay.env'

$script:InstallFailureStep = 'stop-existing-relay-service'
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing -and $existing.Status -ne 'Stopped') {
    Stop-Service -Name $ServiceName -Force -ErrorAction Stop
}

$script:InstallFailureStep = 'copy-relay-binary'
Copy-Item -LiteralPath $relaySource -Destination $relayDest -Force -ErrorAction Stop

$script:InstallFailureStep = 'sign-relay-binary-for-authenticode'
Sign-RelayBinaryForAuthenticode -Path $relayDest

$script:InstallFailureStep = 'write-relay-env-file'
$relayArgs = @(
    '--relay-id', $RelayId,
    '--bind', $Bind,
    '--verifier-key', $VerifierKeyPath,
    '--replay-store', $ReplayStorePath,
    '--port-range', $PortRange,
    '--health-bind', $HealthBind
)
$relayArgsJson = ConvertTo-Json -Compress -InputObject $relayArgs
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($envFile, "RUSTYNET_RELAY_ARGS_JSON=$relayArgsJson`n", $utf8NoBom)
if (-not (Test-Path -LiteralPath $ReplayStorePath)) {
    [System.IO.File]::WriteAllText($ReplayStorePath, '', [System.Text.Encoding]::ASCII)
}

$script:InstallFailureStep = 'configure-service-registration'
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    $deleteOutput = (& sc.exe delete "$ServiceName" 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) {
        throw "sc.exe delete failed: $deleteOutput"
    }
    $deadline = (Get-Date).AddSeconds(10)
    while ((Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) -and ((Get-Date) -lt $deadline)) {
        Start-Sleep -Milliseconds 250
    }
}
$quotedRelay = '"' + $relayDest + '"'
$quotedServiceName = '"' + $ServiceName + '"'
$quotedEnvFile = '"' + $envFile + '"'
$binPath = "$quotedRelay --windows-service --service-name $quotedServiceName --env-file $quotedEnvFile"
New-Service -Name $ServiceName -BinaryPathName $binPath -DisplayName 'RustyNet Relay' -Description 'RustyNet encrypted traversal relay service' -StartupType Automatic -ErrorAction Stop | Out-Null

$script:InstallFailureStep = 'configure-service-sid'
Ensure-ServiceSidTypeUnrestricted -ServiceName $ServiceName

$script:InstallFailureStep = 'repair-acls'
$administratorsName = Get-LocalizedAccountNameFromSid -Sid 'S-1-5-32-544'
$localSystemName = Get-LocalizedAccountNameFromSid -Sid 'S-1-5-18'
$serviceIdentity = Get-ServiceIdentityName -ServiceName $ServiceName
Repair-RelayRuntimeAcl -Path $RelayRoot -AdministratorsName $administratorsName -LocalSystemName $localSystemName -ServiceIdentity $serviceIdentity -Directory
Repair-RelayRuntimeAcl -Path $envFile -AdministratorsName $administratorsName -LocalSystemName $localSystemName -ServiceIdentity $serviceIdentity -ServiceReadOnly
Repair-RelayRuntimeAcl -Path $VerifierKeyPath -AdministratorsName $administratorsName -LocalSystemName $localSystemName -ServiceIdentity $serviceIdentity -ServiceReadOnly
Repair-RelayRuntimeAcl -Path $ReplayStorePath -AdministratorsName $administratorsName -LocalSystemName $localSystemName -ServiceIdentity $serviceIdentity
Repair-RelayBinaryAcl -Path $relayDest -AdministratorsName $administratorsName -LocalSystemName $localSystemName -ServiceIdentity $serviceIdentity

$script:InstallFailureStep = 'configure-failure-actions'
Set-RelayServiceFailureActions -ServiceName $ServiceName

$script:InstallFailureStep = 'verify-service-hardening'
$hardeningOutput = (& $relayDest windows-service-hardening-check 2>&1) -join "`n"
if ($LASTEXITCODE -ne 0) {
    throw "relay service hardening check failed: $hardeningOutput"
}

if ($StartService) {
    $script:InstallFailureStep = 'start-service'
    Start-Service -Name $ServiceName -ErrorAction Stop
}

$report = [ordered]@{
    schema_version = 1
    captured_at_utc = (Get-Date).ToUniversalTime().ToString('o')
    platform = 'windows'
    service_name = $ServiceName
    install_root = $InstallRoot
    relay_root = $RelayRoot
    status = 'pass'
    service_start_requested = [bool]$StartService
    env_file = $envFile
    verifier_key = $VerifierKeyPath
    replay_store = $ReplayStorePath
}
Write-RelayInstallReportIfRequested -Report $report
$report | ConvertTo-Json -Depth 8
