param(
    [ValidateSet('prepare-transport','sync-source','build-release','install-release','restart-runtime','verify-runtime','collect-diagnostics','all')]
    [string]$Phase = 'all',
    [ValidateSet('git','archive')]
    [string]$SourceMode = 'git',
    [string]$RepoUrl = '',
    [string]$Branch = 'main',
    [string]$RustyNetRoot = 'C:\Rustynet',
    [string]$ArchiveZipPath = '',
    [string]$InstallRoot = 'C:\Program Files\RustyNet',
    [string]$StateRoot = 'C:\ProgramData\RustyNet',
    [string]$ServiceName = 'RustyNet',
    [string]$AutomationPublicKey = '',
    [string]$WingetConfigPath = '',
    [string]$VsConfigPath = '',
    [string]$ResultPath = '',
    [switch]$InstallPowerShell7,
    [switch]$SetDefaultShellToPowerShell,
    [switch]$SetDefaultShellToPowerShell7
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
trap {
    $failureReason = Format-TopLevelFailureReason -PhaseName $Phase -ErrorRecord $_
    Write-FailClosedPhaseResultIfRequested -FailureReason $failureReason
    Write-Error $_
    exit 1
}

if ($SetDefaultShellToPowerShell -and $SetDefaultShellToPowerShell7) {
    throw 'Specify only one of -SetDefaultShellToPowerShell or -SetDefaultShellToPowerShell7'
}

function Ensure-Directory {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Force -Path $Path | Out-Null
    }
}

function New-PrepareTransportFailureReport {
    param([Parameter(Mandatory = $true)][string]$Reason)

    return [ordered]@{
        openssh_installed = $false
        service_running = $false
        firewall_rule_enabled = $false
        authorized_keys_applied = $false
        host_key_present = $false
        listener_ready = $false
        default_shell_configured = $false
        status = 'fail'
        reason = $Reason
        host_key = ''
    }
}

function Format-TopLevelFailureReason {
    param(
        [Parameter(Mandatory = $true)][string]$PhaseName,
        [Parameter(Mandatory = $true)]$ErrorRecord
    )

    $detail = ''
    if ($null -ne $ErrorRecord.Exception -and $ErrorRecord.Exception.Message) {
        $detail = $ErrorRecord.Exception.Message.Trim()
    }
    if (-not $detail) {
        $detail = ($ErrorRecord | Out-String).Trim()
    }
    if (-not $detail) {
        $detail = 'unhandled-exception'
    }
    if ($PhaseName -eq 'prepare-transport') {
        return [string]::Concat('prepare-transport-exception: ', $detail)
    }
    return [string]::Concat($PhaseName, '-exception: ', $detail)
}

function Write-FailClosedPhaseResultIfRequested {
    param([Parameter(Mandatory = $true)][string]$FailureReason)

    $trimmedResultPath = $ResultPath.Trim()
    if ($Phase -ne 'prepare-transport' -or $trimmedResultPath.Length -eq 0) {
        return
    }
    try {
        $report = New-PrepareTransportFailureReport -Reason $FailureReason
        $parent = Split-Path -Path $trimmedResultPath -Parent
        if ($parent -and $parent.Trim().Length -gt 0) {
            Ensure-Directory -Path $parent
        }
        $report | ConvertTo-Json -Compress | Set-Content -LiteralPath $trimmedResultPath -Encoding utf8
    }
    catch {
        # Preserve the original failure as the dominant root cause.
    }
}

function Write-JsonPhaseResult {
    param([Parameter(Mandatory = $true)]$Value)

    $json = $Value | ConvertTo-Json -Compress
    $trimmedResultPath = $ResultPath.Trim()
    if ($trimmedResultPath.Length -gt 0) {
        $parent = Split-Path -Path $trimmedResultPath -Parent
        if ($parent -and $parent.Trim().Length -gt 0) {
            Ensure-Directory -Path $parent
        }
        Set-Content -LiteralPath $trimmedResultPath -Value $json -Encoding utf8
    }
    Write-Output $json
}

function Get-LocalizedAccountNameFromSid {
    param([Parameter(Mandatory = $true)][string]$Sid)
    try {
        return (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value
    }
    catch {
        throw "failed to translate Windows SID $Sid to a localized account name: $($_.Exception.Message)"
    }
}

function Require-Winget {
    if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) {
        throw 'winget.exe is not available; install App Installer or use a pre-baked Windows lab template'
    }
}

function Invoke-WingetInstall {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [string]$Override = ''
    )
    Require-Winget
    $args = @(
        'install',
        '--accept-package-agreements',
        '--accept-source-agreements',
        '--disable-interactivity',
        '-e',
        '--id',
        $Id
    )
    if ($Override -and $Override.Trim().Length -gt 0) {
        $args += @('--override', $Override)
    }
    & winget @args
    if ($LASTEXITCODE -ne 0) {
        throw "winget install failed for package id: $Id"
    }
}

function Ensure-PowerShell7 {
    $pwsh = 'C:\Program Files\PowerShell\7\pwsh.exe'
    if (Test-Path -LiteralPath $pwsh) {
        return
    }
    if (-not $InstallPowerShell7) {
        throw 'PowerShell 7 is not installed and -InstallPowerShell7 was not supplied'
    }
    Invoke-WingetInstall -Id 'Microsoft.PowerShell'
    if (-not (Test-Path -LiteralPath $pwsh)) {
        throw 'PowerShell 7 is still unavailable after winget installation attempt'
    }
}

function Resolve-SshdExecutablePath {
    $command = Get-Command sshd.exe -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }
    $candidates = @(
        'C:\Windows\System32\OpenSSH\sshd.exe',
        'C:\Program Files\OpenSSH-Win64\sshd.exe'
    )
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }
    return $null
}

function Resolve-DefaultShellPath {
    if ($SetDefaultShellToPowerShell7) {
        Ensure-PowerShell7
        return 'C:\Program Files\PowerShell\7\pwsh.exe'
    }
    if ($SetDefaultShellToPowerShell) {
        return 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    }
    return $null
}

function Ensure-OpenSshDefaultShell {
    $expectedShell = Resolve-DefaultShellPath
    if (-not $expectedShell) {
        return $true
    }
    New-Item -Path 'HKLM:\SOFTWARE\OpenSSH' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name 'DefaultShell' -PropertyType String -Value $expectedShell -Force | Out-Null
    $configured = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name 'DefaultShell' -ErrorAction Stop).DefaultShell
    return ([string]$configured -eq $expectedShell)
}

function Repair-SshProtectedFileAcl {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$AdministratorsName,
        [Parameter(Mandatory = $true)][string]$LocalSystemName
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
    & icacls $Path /grant:r "$AdministratorsName`:F" "$LocalSystemName`:F" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "icacls /grant:r failed for $Path"
    }
}

function Ensure-AuthorizedKeys {
    param(
        [Parameter(Mandatory = $true)][string]$PublicKey,
        [Parameter(Mandatory = $true)][string]$AdministratorsName,
        [Parameter(Mandatory = $true)][string]$LocalSystemName
    )

    $trimmedKey = $PublicKey.Trim()
    if (-not $trimmedKey) {
        return $false
    }
    $adminKeys = 'C:\ProgramData\ssh\administrators_authorized_keys'
    Set-Content -LiteralPath $adminKeys -Encoding ascii -Value ($trimmedKey + "`r`n")
    Repair-SshProtectedFileAcl -Path $adminKeys -AdministratorsName $AdministratorsName -LocalSystemName $LocalSystemName
    $actual = (Get-Content -LiteralPath $adminKeys -Raw -ErrorAction Stop).Trim()
    return ($actual -eq $trimmedKey)
}

function Ensure-OpenSshFirewallRule {
    $ruleName = 'OpenSSH-Server-In-TCP'
    $displayName = 'OpenSSH Server (RustyNet vm-lab)'

    $testRule = {
        param($Rule)
        if (-not $Rule) {
            return $false
        }
        $matchingPortFilter = $Rule |
            Get-NetFirewallPortFilter -ErrorAction SilentlyContinue |
            Where-Object { $_.Protocol -eq 'TCP' -and [string]$_.LocalPort -eq '22' } |
            Select-Object -First 1
        return ($Rule.Enabled -eq 'True' -and $Rule.Direction -eq 'Inbound' -and $Rule.Action -eq 'Allow' -and $null -ne $matchingPortFilter)
    }

    $rule = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
    if ($rule -and -not (& $testRule $rule)) {
        Remove-NetFirewallRule -Name $ruleName -ErrorAction Stop | Out-Null
        $rule = $null
    }
    if (-not $rule) {
        New-NetFirewallRule -Name $ruleName -DisplayName $displayName -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 | Out-Null
        $rule = Get-NetFirewallRule -Name $ruleName -ErrorAction Stop
    } else {
        Set-NetFirewallRule -Name $ruleName -Enabled True -Direction Inbound -Action Allow | Out-Null
        $rule = Get-NetFirewallRule -Name $ruleName -ErrorAction Stop
    }
    return (& $testRule $rule)
}

function Test-SshdConfiguration {
    param([Parameter(Mandatory = $true)][string]$SshdPath)

    $validationOutput = & $SshdPath -t 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        return @{
            Valid = $false
            Reason = 'invalid-sshd-config'
            Details = $validationOutput.Trim()
        }
    }
    return @{
        Valid = $true
        Reason = 'ok'
        Details = ''
    }
}

function Test-SshListenerReady {
    $listeners = @(Get-NetTCPConnection -LocalPort 22 -State Listen -ErrorAction SilentlyContinue)
    return ($listeners.Count -gt 0)
}

function Get-TransportHostKeyLine {
    $hostKeyPath = 'C:\ProgramData\ssh\ssh_host_ed25519_key.pub'
    if (Test-Path -LiteralPath $hostKeyPath) {
        return ((Get-Content -LiteralPath $hostKeyPath -Raw -ErrorAction Stop).Trim())
    }
    return ''
}

function Get-PrepareTransportReport {
    param([string]$PublicKey = '')

    $administratorsName = Get-LocalizedAccountNameFromSid -Sid 'S-1-5-32-544'
    $localSystemName = Get-LocalizedAccountNameFromSid -Sid 'S-1-5-18'
    $authorizedKeysPath = 'C:\ProgramData\ssh\administrators_authorized_keys'
    $report = New-PrepareTransportFailureReport -Reason 'prepare-transport-not-run'
    try {
        Ensure-Directory -Path 'C:\ProgramData\ssh'

        $sshCapability = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*'
        if (-not $sshCapability -or $sshCapability.State -ne 'Installed') {
            Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 | Out-Null
            $sshCapability = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*'
        }
        $report.openssh_installed = [bool]($sshCapability -and $sshCapability.State -eq 'Installed')
        if (-not $report.openssh_installed) {
            $report.reason = 'openssh-server-not-installed'
            return $report
        }

        $report.default_shell_configured = Ensure-OpenSshDefaultShell
        if (-not $report.default_shell_configured) {
            $report.reason = 'default-shell-not-configured'
            return $report
        }

        $trimmedPublicKey = $PublicKey.Trim()
        if ($trimmedPublicKey.Length -gt 0) {
            $report.authorized_keys_applied = Ensure-AuthorizedKeys -PublicKey $trimmedPublicKey -AdministratorsName $administratorsName -LocalSystemName $localSystemName
            if (-not $report.authorized_keys_applied) {
                $report.reason = 'authorized-keys-not-applied'
                return $report
            }
        } elseif (Test-Path -LiteralPath $authorizedKeysPath) {
            Repair-SshProtectedFileAcl -Path $authorizedKeysPath -AdministratorsName $administratorsName -LocalSystemName $localSystemName
        }

        foreach ($path in @('C:\ProgramData\ssh\sshd_config')) {
            Repair-SshProtectedFileAcl -Path $path -AdministratorsName $administratorsName -LocalSystemName $localSystemName
        }
        foreach ($path in @(Get-ChildItem -LiteralPath 'C:\ProgramData\ssh' -Filter 'ssh_host_*' -File -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)) {
            Repair-SshProtectedFileAcl -Path $path -AdministratorsName $administratorsName -LocalSystemName $localSystemName
        }

        $report.firewall_rule_enabled = Ensure-OpenSshFirewallRule
        if (-not $report.firewall_rule_enabled) {
            $report.reason = 'firewall-rule-not-enabled'
            return $report
        }

        $sshdPath = Resolve-SshdExecutablePath
        if (-not $sshdPath) {
            $report.reason = 'sshd-command-unavailable'
            return $report
        }

        $configValidation = Test-SshdConfiguration -SshdPath $sshdPath
        if (-not $configValidation.Valid) {
            $report.reason = [string]$configValidation.Reason
            return $report
        }

        Set-Service -Name sshd -StartupType Automatic
        $service = Get-Service -Name sshd -ErrorAction Stop
        if ($service.Status -eq 'Running') {
            Restart-Service -Name sshd -ErrorAction Stop
        } else {
            Start-Service -Name sshd -ErrorAction Stop
        }
        Start-Sleep -Seconds 2

        $service = Get-Service -Name sshd -ErrorAction Stop
        $report.service_running = ($service.Status -eq 'Running')
        if (-not $report.service_running) {
            $report.reason = 'sshd-service-not-running'
            return $report
        }

        $report.listener_ready = Test-SshListenerReady
        if (-not $report.listener_ready) {
            $report.reason = 'ssh-listener-not-ready'
            return $report
        }

        $report.host_key = Get-TransportHostKeyLine
        $report.host_key_present = ($report.host_key.Length -gt 0)
        if (-not $report.host_key_present) {
            $report.reason = 'host-key-unavailable'
            return $report
        }

        $report.status = 'pass'
        $report.reason = 'ok'
        return $report
    }
    catch {
        $report.reason = [string]::Concat('prepare-transport-exception: ', $_.Exception.Message)
        return $report
    }
}

function Resolve-WingetConfigurationPath {
    param([string]$ConfigPath = '')
    if ($ConfigPath -and $ConfigPath.Trim().Length -gt 0) {
        return $ConfigPath
    }
    return (Join-Path $PSScriptRoot 'RustyNetBootstrap.winget.yml')
}

function Resolve-VsConfigPath {
    param([string]$ConfigPath = '')
    if ($ConfigPath -and $ConfigPath.Trim().Length -gt 0) {
        return $ConfigPath
    }
    return (Join-Path $PSScriptRoot 'RustyNetBuildTools.vsconfig')
}

function Resolve-InstallHelperPath {
    $candidate = Join-Path $PSScriptRoot 'Install-RustyNetWindowsService.ps1'
    if (-not (Test-Path -LiteralPath $candidate)) {
        throw "Windows install helper not found: $candidate"
    }
    return $candidate
}

function Resolve-VerifyHelperPath {
    $candidate = Join-Path $PSScriptRoot 'Verify-RustyNetWindowsBootstrap.ps1'
    if (-not (Test-Path -LiteralPath $candidate)) {
        throw "Windows verify helper not found: $candidate"
    }
    return $candidate
}

function Resolve-DiagnosticsHelperPath {
    $candidate = Join-Path $PSScriptRoot 'Collect-RustyNetWindowsDiagnostics.ps1'
    if (-not (Test-Path -LiteralPath $candidate)) {
        throw "Windows diagnostics helper not found: $candidate"
    }
    return $candidate
}

function Ensure-WingetConfigurationDependencies {
    param([string]$ConfigPath = '')
    $candidate = Resolve-WingetConfigurationPath -ConfigPath $ConfigPath
    if (-not (Test-Path -LiteralPath $candidate)) {
        throw "WinGet configuration file not found: $candidate"
    }
    Require-Winget
    & winget configure --file $candidate --accept-configuration-agreements
    if ($LASTEXITCODE -ne 0) {
        throw 'winget configure failed for RustyNet bootstrap configuration'
    }
}

function Ensure-CargoOnPath {
    $cargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
    if (Test-Path -LiteralPath $cargoBin) {
        $env:PATH = "$cargoBin;$env:PATH"
    }
}

function Require-Command {
    param([Parameter(Mandatory = $true)][string]$Name)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "$Name is not available after bootstrap"
    }
}

function Ensure-BuildTools {
    param([string]$ConfigPath = '')
    if (Get-Command cl.exe -ErrorAction SilentlyContinue) {
        return
    }
    $effectiveConfig = Resolve-VsConfigPath -ConfigPath $ConfigPath
    if (-not (Test-Path -LiteralPath $effectiveConfig)) {
        throw "Visual Studio build tools config not found: $effectiveConfig"
    }
    Invoke-WingetInstall -Id 'Microsoft.VisualStudio.2022.BuildTools' -Override "--passive --wait --config `"$effectiveConfig`""
}

function Enter-VsBuildEnvironment {
    $candidates = @(
        'C:\Program Files\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat',
        'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat'
    )
    $devCmd = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if (-not $devCmd) {
        throw 'VsDevCmd.bat not found; Build Tools do not appear to be installed correctly'
    }
    foreach ($line in (cmd.exe /s /c "`"$devCmd`" -arch=x64 -host_arch=x64 >nul && set")) {
        if ($line -match '^(.*?)=(.*)$') {
            [System.Environment]::SetEnvironmentVariable($matches[1], $matches[2])
        }
    }
}

function Sync-SourceGit {
    if (-not $RepoUrl -or $RepoUrl.Trim().Length -eq 0) {
        throw 'Git source mode requires -RepoUrl'
    }
    Ensure-WingetConfigurationDependencies -ConfigPath $WingetConfigPath
    Ensure-CargoOnPath
    Require-Command -Name git.exe

    $parent = Split-Path -Parent $RustyNetRoot
    if ($parent -and $parent.Trim().Length -gt 0) {
        Ensure-Directory -Path $parent
    }
    if (-not (Test-Path -LiteralPath $RustyNetRoot)) {
        New-Item -ItemType Directory -Force -Path $RustyNetRoot | Out-Null
    }

    if (-not (Test-Path -LiteralPath (Join-Path $RustyNetRoot '.git'))) {
        if ((Get-ChildItem -LiteralPath $RustyNetRoot -Force | Measure-Object).Count -gt 0) {
            throw "RustyNet root exists but is not empty and not a git repository: $RustyNetRoot"
        }
        git clone --origin origin --branch $Branch --single-branch $RepoUrl $RustyNetRoot
        if ($LASTEXITCODE -ne 0) {
            throw "git clone failed for $RepoUrl"
        }
    }
    else {
        git -C $RustyNetRoot remote set-url origin $RepoUrl
        if ($LASTEXITCODE -ne 0) {
            throw "git remote set-url failed for $RepoUrl"
        }
        git -C $RustyNetRoot fetch origin $Branch --prune
        if ($LASTEXITCODE -ne 0) {
            throw "git fetch failed for branch $Branch"
        }
        git -C $RustyNetRoot checkout -B $Branch FETCH_HEAD
        if ($LASTEXITCODE -ne 0) {
            throw "git checkout failed for branch $Branch"
        }
        git -C $RustyNetRoot reset --hard FETCH_HEAD
        if ($LASTEXITCODE -ne 0) {
            throw "git reset failed for branch $Branch"
        }
        git -C $RustyNetRoot clean -fdx
        if ($LASTEXITCODE -ne 0) {
            throw "git clean failed for $RustyNetRoot"
        }
    }
}

function Sync-SourceArchive {
    if (-not $ArchiveZipPath -or $ArchiveZipPath.Trim().Length -eq 0) {
        throw 'Archive source mode requires -ArchiveZipPath'
    }
    if (-not (Test-Path -LiteralPath $ArchiveZipPath)) {
        throw "Archive ZIP not found: $ArchiveZipPath"
    }
    $parent = Split-Path -Parent $RustyNetRoot
    if ($parent -and $parent.Trim().Length -gt 0) {
        Ensure-Directory -Path $parent
    }
    if (Test-Path -LiteralPath $RustyNetRoot) {
        Remove-Item -LiteralPath $RustyNetRoot -Recurse -Force
    }
    Expand-Archive -LiteralPath $ArchiveZipPath -DestinationPath $RustyNetRoot -Force
}

function Build-RustyNet {
    Ensure-WingetConfigurationDependencies -ConfigPath $WingetConfigPath
    Ensure-CargoOnPath
    Ensure-BuildTools -ConfigPath $VsConfigPath
    Ensure-CargoOnPath
    Require-Command -Name cargo.exe
    Enter-VsBuildEnvironment

    if (-not (Test-Path -LiteralPath (Join-Path $RustyNetRoot 'Cargo.toml'))) {
        throw "RustyNet source tree is missing Cargo.toml: $RustyNetRoot"
    }

    Push-Location $RustyNetRoot
    try {
        cargo build --locked --release -p rustynetd -p rustynet-cli
        if ($LASTEXITCODE -ne 0) {
            throw 'cargo build failed for Windows build-release'
        }
    }
    finally {
        Pop-Location
    }
}

function Install-RustyNetRuntime {
    $helper = Resolve-InstallHelperPath
    $output = & $helper -RustyNetRoot $RustyNetRoot -InstallRoot $InstallRoot -StateRoot $StateRoot -ServiceName $ServiceName | Out-String
    if ($LASTEXITCODE -ne 0) {
        throw "Windows install helper failed for service: $ServiceName"
    }
    $trimmed = $output.Trim()
    if (-not $trimmed) {
        throw "Windows install helper produced no output for service: $ServiceName"
    }
    try {
        $parsed = $trimmed | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "Windows install helper emitted invalid JSON for service ${ServiceName}: $($_.Exception.Message)"
    }
    if ($parsed.status -ne 'pass') {
        $reason = if ($parsed.reason) { [string]$parsed.reason } else { 'install-failed' }
        throw "Windows install helper reported blocked status for service ${ServiceName}: $reason"
    }
    Write-Output $trimmed
}

function Restart-RustyNetRuntime {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $service) {
        throw "Windows runtime service is not installed: $ServiceName"
    }
    try {
        if ($service.Status -eq 'Running') {
            Restart-Service -Name $ServiceName -ErrorAction Stop
        }
        else {
            Start-Service -Name $ServiceName -ErrorAction Stop
        }
    }
    catch {
        Write-Output ("service-control-error=" + $_.Exception.Message)
    }
    Start-Sleep -Seconds 3
    Invoke-VerifyRuntime | Out-Null
}

function Invoke-VerifyRuntime {
    $helper = Resolve-VerifyHelperPath
    $output = & $helper -RustyNetRoot $RustyNetRoot -InstallRoot $InstallRoot -StateRoot $StateRoot -ServiceName $ServiceName | Out-String
    if ($LASTEXITCODE -ne 0) {
        throw "Windows verify helper failed for service: $ServiceName"
    }
    $trimmed = $output.Trim()
    if (-not $trimmed) {
        throw "Windows verify helper produced no output for service: $ServiceName"
    }
    try {
        $parsed = $trimmed | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "Windows verify helper emitted invalid JSON for service ${ServiceName}: $($_.Exception.Message)"
    }
    if ($parsed.status -ne 'pass') {
        $reason = if ($parsed.reason) { [string]$parsed.reason } else { 'verification-failed' }
        throw "Windows verify helper reported blocked status for service ${ServiceName}: $reason"
    }
    Write-Output $trimmed
}

function Invoke-CollectDiagnostics {
    $helper = Resolve-DiagnosticsHelperPath
    $outputRoot = Join-Path $StateRoot 'vm-lab\diagnostics'
    $output = & $helper -OutputRoot $outputRoot -InstallRoot $InstallRoot -ServiceName $ServiceName | Out-String
    if ($LASTEXITCODE -ne 0) {
        throw "Windows diagnostics helper failed for service: $ServiceName"
    }
    $trimmed = $output.Trim()
    if ($trimmed.Length -gt 0) {
        Write-Output $trimmed
    }
}

function Invoke-BootstrapAll {
    if ($SourceMode -eq 'git') {
        Sync-SourceGit
    }
    else {
        Sync-SourceArchive
    }
    Build-RustyNet
    Install-RustyNetRuntime
    Restart-RustyNetRuntime
    Invoke-VerifyRuntime
}

switch ($Phase) {
    'prepare-transport' {
        $report = Get-PrepareTransportReport -PublicKey $AutomationPublicKey
        Write-JsonPhaseResult -Value $report
    }
    'sync-source' {
        if ($SourceMode -eq 'git') {
            Sync-SourceGit
        }
        else {
            Sync-SourceArchive
        }
    }
    'build-release' {
        Build-RustyNet
    }
    'install-release' {
        Install-RustyNetRuntime
    }
    'restart-runtime' {
        Restart-RustyNetRuntime
    }
    'verify-runtime' {
        Invoke-VerifyRuntime
    }
    'collect-diagnostics' {
        Invoke-CollectDiagnostics
    }
    'all' {
        Invoke-BootstrapAll
    }
}
