param(
    [string]$OutputRoot = 'C:\ProgramData\RustyNet\vm-lab\diagnostics',
    [string]$InstallRoot = 'C:\Program Files\RustyNet',
    [string]$ServiceName = 'RustyNet',
    [string]$StateRoot = 'C:\ProgramData\RustyNet'
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

function Write-Utf8File {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Content
    )
    $Content | Set-Content -Encoding utf8 -LiteralPath $Path
}

function Write-CommandOutput {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][scriptblock]$Script
    )
    try {
        $content = & $Script | Out-String
    }
    catch {
        $content = ($_ | Out-String)
    }
    Write-Utf8File -Path $Path -Content $content
}

function Write-JsonFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Value
    )
    $Value | ConvertTo-Json -Depth 8 | Set-Content -Encoding utf8 -LiteralPath $Path
}

function Get-HashEntries {
    param([string[]]$Paths)
    $entries = @()
    foreach ($path in $Paths) {
        if (Test-Path -LiteralPath $path) {
            try {
                $entries += [ordered]@{
                    path = $path
                    sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash
                }
            }
            catch {
                $entries += [ordered]@{
                    path = $path
                    sha256 = $null
                    error = [string]::Concat('hash-unavailable: ', $_.Exception.Message)
                }
            }
        }
    }
    return $entries
}

function Write-ReadableFileSnapshot {
    param(
        [Parameter(Mandatory = $true)][string]$SourcePath,
        [Parameter(Mandatory = $true)][string]$DestinationPath
    )
    if (-not (Test-Path -LiteralPath $SourcePath)) {
        return
    }
    try {
        Get-Content -LiteralPath $SourcePath -ErrorAction Stop | Set-Content -Encoding utf8 -LiteralPath $DestinationPath
    }
    catch {
        Write-Utf8File -Path $DestinationPath -Content ([string]::Concat('read-unavailable: ', $_.Exception.Message))
    }
}

function Write-AclSnapshot {
    param(
        [Parameter(Mandatory = $true)][string]$TargetPath,
        [Parameter(Mandatory = $true)][string]$OutputDirectory
    )
    if (-not (Test-Path -LiteralPath $TargetPath)) {
        return
    }
    $safeName = ($TargetPath -replace '[:\\/ ]', '_').Trim('_')
    Write-CommandOutput -Path (Join-Path $OutputDirectory ("acl_" + $safeName + '.txt')) -Script {
        & icacls $TargetPath
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

function Invoke-WindowsRuntimeBoundaryCheck {
    param(
        [Parameter(Mandatory = $true)][string]$DaemonPath,
        [Parameter(Mandatory = $true)][string]$StateRoot
    )
    if (-not (Test-Path -LiteralPath $DaemonPath)) {
        return [ordered]@{
            status = 'not-run'
            reason = 'daemon-missing'
        }
    }
    $output = (& $DaemonPath windows-runtime-boundary-check --state-root $StateRoot 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) {
        return [ordered]@{
            status = 'fail'
            reason = $output.Trim()
        }
    }
    try {
        return [ordered]@{
            status = 'pass'
            report = ($output | ConvertFrom-Json -ErrorAction Stop)
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

Ensure-Directory -Path $OutputRoot

$daemonInstallPath = Join-Path $InstallRoot 'bin\rustynetd.exe'
$configPath = Join-Path $StateRoot 'config\rustynetd.env'
$runtimeBoundary = Invoke-WindowsRuntimeBoundaryCheck -DaemonPath $daemonInstallPath -StateRoot $StateRoot
$windowsFacts = Get-WindowsTargetFacts

Write-CommandOutput -Path (Join-Path $OutputRoot 'services.txt') -Script {
    Get-Service | Sort-Object Name | Format-Table -AutoSize
}
Write-JsonFile -Path (Join-Path $OutputRoot 'windows_target_facts.json') -Value $windowsFacts
Write-CommandOutput -Path (Join-Path $OutputRoot 'net-ip.txt') -Script {
    Get-NetIPConfiguration | Format-List *
}
Write-CommandOutput -Path (Join-Path $OutputRoot 'routes.txt') -Script {
    Get-NetRoute | Sort-Object DestinationPrefix, RouteMetric | Format-Table -AutoSize
}
Write-CommandOutput -Path (Join-Path $OutputRoot 'dns.txt') -Script {
    Get-DnsClientServerAddress | Format-List *
}
Write-CommandOutput -Path (Join-Path $OutputRoot 'adapters.txt') -Script {
    Get-NetAdapter | Format-List *
}
Write-CommandOutput -Path (Join-Path $OutputRoot 'firewall.txt') -Script {
    Get-NetFirewallRule |
        Where-Object { $_.DisplayName -like '*RustyNet*' -or $_.DisplayName -like '*OpenSSH*' } |
        Format-Table -AutoSize
}
Write-CommandOutput -Path (Join-Path $OutputRoot 'ssh-services.txt') -Script {
    Get-Service -Name sshd, ssh-agent -ErrorAction SilentlyContinue | Format-List *
}
Write-CommandOutput -Path (Join-Path $OutputRoot 'ssh-listeners.txt') -Script {
    Get-NetTCPConnection -LocalPort 22 -State Listen -ErrorAction SilentlyContinue | Format-List *
}
Write-CommandOutput -Path (Join-Path $OutputRoot 'ssh-firewall-openssh.txt') -Script {
    Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue | Format-List *
}
Write-CommandOutput -Path (Join-Path $OutputRoot 'sshd-config-test.txt') -Script {
    & (Join-Path $env:WINDIR 'System32\OpenSSH\sshd.exe') -t 2>&1
}
Write-CommandOutput -Path (Join-Path $OutputRoot 'events-system.txt') -Script {
    Get-WinEvent -LogName System -MaxEvents 100 | Format-List TimeCreated, ProviderName, Id, LevelDisplayName, Message
}
Write-CommandOutput -Path (Join-Path $OutputRoot 'events-application.txt') -Script {
    Get-WinEvent -LogName Application -MaxEvents 100 | Format-List TimeCreated, ProviderName, Id, LevelDisplayName, Message
}
Write-CommandOutput -Path (Join-Path $OutputRoot 'computer-system.txt') -Script {
    Get-CimInstance -ClassName Win32_ComputerSystem | Format-List *
}
Write-CommandOutput -Path (Join-Path $OutputRoot 'operating-system.txt') -Script {
    Get-CimInstance -ClassName Win32_OperatingSystem | Format-List *
}

if (Test-Path -LiteralPath $daemonInstallPath) {
    Write-CommandOutput -Path (Join-Path $OutputRoot 'rustynetd-help.txt') -Script {
        & $daemonInstallPath --help 2>&1
    }
}
Write-JsonFile -Path (Join-Path $OutputRoot 'runtime-boundary-check.json') -Value $runtimeBoundary

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($service) {
    Write-CommandOutput -Path (Join-Path $OutputRoot 'service-qc.txt') -Script {
        & sc.exe qc $ServiceName
    }
    Write-CommandOutput -Path (Join-Path $OutputRoot 'service-queryex.txt') -Script {
        & sc.exe queryex $ServiceName
    }
    Write-CommandOutput -Path (Join-Path $OutputRoot 'service-qfailure.txt') -Script {
        & sc.exe qfailure $ServiceName
    }
    Write-CommandOutput -Path (Join-Path $OutputRoot 'service-qsidtype.txt') -Script {
        & sc.exe qsidtype $ServiceName
    }
    Write-CommandOutput -Path (Join-Path $OutputRoot 'service-cim.txt') -Script {
        Get-CimInstance -ClassName Win32_Service -Filter ("Name='" + $ServiceName.Replace("'", "''") + "'") | Format-List *
    }
}

Write-CommandOutput -Path (Join-Path $OutputRoot 'events-service-control-manager-rustynet.txt') -Script {
    Get-WinEvent -LogName System -MaxEvents 200 |
        Where-Object { $_.ProviderName -eq 'Service Control Manager' -and $_.Message -like "*$ServiceName*" } |
        Format-List TimeCreated, ProviderName, Id, LevelDisplayName, Message
}

$toolingLines = @()
foreach ($commandText in @(
    'git --version',
    'rustup --version',
    'cargo --version',
    'powershell.exe -Version'
)) {
    $toolingLines += "## $commandText"
    try {
        $toolingLines += (cmd.exe /c $commandText 2>&1 | Out-String).TrimEnd()
    }
    catch {
        $toolingLines += ($_ | Out-String).TrimEnd()
    }
    $toolingLines += ''
}
Write-Utf8File -Path (Join-Path $OutputRoot 'tooling.txt') -Content ($toolingLines -join "`r`n")

$hashEntries = Get-HashEntries -Paths @(
    (Join-Path $InstallRoot 'bin\rustynetd.exe'),
    (Join-Path $InstallRoot 'bin\rustynet.exe'),
    (Join-Path $InstallRoot 'bin\rustynet-cli.exe'),
    'C:\ProgramData\ssh\ssh_host_ed25519_key.pub',
    'C:\ProgramData\ssh\administrators_authorized_keys'
)
$hashEntries | ConvertTo-Json -Depth 4 | Set-Content -Encoding utf8 -LiteralPath (Join-Path $OutputRoot 'hashes.json')

foreach ($path in @(
    'C:\ProgramData\ssh\administrators_authorized_keys',
    'C:\ProgramData\ssh\ssh_host_ed25519_key',
    'C:\ProgramData\ssh\ssh_host_ed25519_key.pub',
    $InstallRoot,
    (Join-Path $InstallRoot 'bin'),
    $StateRoot,
    (Join-Path $StateRoot 'config'),
    (Join-Path $StateRoot 'logs'),
    (Join-Path $StateRoot 'trust'),
    (Join-Path $StateRoot 'keys'),
    (Join-Path $StateRoot 'membership'),
    (Join-Path $StateRoot 'secrets'),
    (Join-Path $StateRoot 'secrets\key-custody'),
    $configPath
)) {
    Write-AclSnapshot -TargetPath $path -OutputDirectory $OutputRoot
}

Write-ReadableFileSnapshot -SourcePath 'C:\ProgramData\ssh\sshd_config' -DestinationPath (Join-Path $OutputRoot 'sshd_config.txt')

$sshdService = Get-Service -Name 'sshd' -ErrorAction SilentlyContinue
$openSshFirewallRule = Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue
$sshListener = Get-NetTCPConnection -LocalPort 22 -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
$sshAccessState = [ordered]@{
    openssh_installed = (Test-Path -LiteralPath (Join-Path $env:WINDIR 'System32\OpenSSH\sshd.exe'))
    service_present = ($null -ne $sshdService)
    service_running = ($null -ne $sshdService -and $sshdService.Status -eq 'Running')
    firewall_rule_present = ($null -ne $openSshFirewallRule)
    firewall_rule_enabled = ($null -ne $openSshFirewallRule -and $openSshFirewallRule.Enabled -eq 'True' -and $openSshFirewallRule.Direction -eq 'Inbound' -and $openSshFirewallRule.Action -eq 'Allow')
    host_key_present = (Test-Path -LiteralPath 'C:\ProgramData\ssh\ssh_host_ed25519_key.pub')
    authorized_keys_present = (Test-Path -LiteralPath 'C:\ProgramData\ssh\administrators_authorized_keys')
    listener_ready = ($null -ne $sshListener)
}
$sshAccessState | ConvertTo-Json -Depth 4 | Set-Content -Encoding utf8 -LiteralPath (Join-Path $OutputRoot 'ssh_access_state.json')

$manifest = [ordered]@{
    schema_version = 2
    captured_at_utc = (Get-Date).ToUniversalTime().ToString('o')
    output_root = $OutputRoot
    install_root = $InstallRoot
    state_root = $StateRoot
    service_name = $ServiceName
    windows_target_facts = $windowsFacts
    runtime_boundary_status = $runtimeBoundary.status
    omitted_secret_material = @(
        (Join-Path $StateRoot 'config\rustynetd.env'),
        'C:\ProgramData\ssh\ssh_host_ed25519_key'
    )
    files = (Get-ChildItem -LiteralPath $OutputRoot -File | Sort-Object Name | Select-Object -ExpandProperty Name)
}
$manifest | ConvertTo-Json -Depth 4 | Set-Content -Encoding utf8 -LiteralPath (Join-Path $OutputRoot 'manifest.json')
Write-Output $OutputRoot
