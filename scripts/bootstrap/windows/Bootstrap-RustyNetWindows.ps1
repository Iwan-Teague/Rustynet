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
    [switch]$InstallPowerShell7,
    [switch]$SetDefaultShellToPowerShell7
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

function Ensure-OpenSshServer {
    param([string]$PublicKey = '')
    $sshCapability = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*'
    if (-not $sshCapability -or $sshCapability.State -ne 'Installed') {
        Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 | Out-Null
    }
    Start-Service sshd
    Set-Service -Name sshd -StartupType Automatic
    if (-not (Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (RustyNet vm-lab)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 | Out-Null
    }
    Ensure-Directory -Path 'C:\ProgramData\ssh'
    if ($SetDefaultShellToPowerShell7) {
        $pwsh = 'C:\Program Files\PowerShell\7\pwsh.exe'
        Ensure-PowerShell7
        New-Item -Path 'HKLM:\SOFTWARE\OpenSSH' -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name 'DefaultShell' -PropertyType String -Value $pwsh -Force | Out-Null
    }
    if ($PublicKey -and $PublicKey.Trim().Length -gt 0) {
        $adminKeys = 'C:\ProgramData\ssh\administrators_authorized_keys'
        $administratorsName = Get-LocalizedAccountNameFromSid -Sid 'S-1-5-32-544'
        $localSystemName = Get-LocalizedAccountNameFromSid -Sid 'S-1-5-18'
        Set-Content -LiteralPath $adminKeys -Encoding ascii -Value ($PublicKey.Trim() + "`r`n")
        & icacls $adminKeys /inheritance:r | Out-Null
        & icacls $adminKeys /grant:r "$administratorsName`:F" "$localSystemName`:F" | Out-Null
    }
}

function Write-TransportHostKey {
    $hostKeyPath = 'C:\ProgramData\ssh\ssh_host_ed25519_key.pub'
    if (Test-Path -LiteralPath $hostKeyPath) {
        Get-Content -LiteralPath $hostKeyPath
    }
    else {
        Write-Output 'host-key-unavailable'
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
    if ($trimmed.Length -gt 0) {
        Write-Output $trimmed
    }
}

function Restart-RustyNetRuntime {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $service) {
        throw "Windows runtime service is not installed: $ServiceName"
    }
    if ($service.Status -eq 'Running') {
        Restart-Service -Name $ServiceName -ErrorAction Stop
    }
    else {
        Start-Service -Name $ServiceName -ErrorAction Stop
    }
    $service.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
    $refreshed = Get-Service -Name $ServiceName -ErrorAction Stop
    if ($refreshed.Status -ne 'Running') {
        throw "Windows runtime service failed to reach Running state: $ServiceName ($($refreshed.Status))"
    }
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
        throw "Windows verify helper emitted invalid JSON for service $ServiceName: $($_.Exception.Message)"
    }
    if ($parsed.status -ne 'pass') {
        $reason = if ($parsed.reason) { [string]$parsed.reason } else { 'verification-failed' }
        throw "Windows verify helper reported blocked status for service $ServiceName: $reason"
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
        Ensure-OpenSshServer -PublicKey $AutomationPublicKey
        Write-TransportHostKey
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
