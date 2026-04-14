param(
    [string]$AutomationPublicKey = "",
    [switch]$SetDefaultShellToPowerShell
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$sshCapability = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*'
if (-not $sshCapability -or $sshCapability.State -ne 'Installed') {
    Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 | Out-Null
}

Start-Service sshd
Set-Service -Name sshd -StartupType Automatic

if (-not (Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (vm-lab)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 | Out-Null
}

New-Item -ItemType Directory -Force -Path 'C:\ProgramData\Rustynet\vm-lab' | Out-Null
New-Item -ItemType Directory -Force -Path 'C:\ProgramData\ssh' | Out-Null

if ($SetDefaultShellToPowerShell) {
    New-Item -Path 'HKLM:\SOFTWARE\OpenSSH' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name 'DefaultShell' -PropertyType String -Value 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -Force | Out-Null
}

if ($AutomationPublicKey -and $AutomationPublicKey.Trim().Length -gt 0) {
    $adminKeys = 'C:\ProgramData\ssh\administrators_authorized_keys'
    Set-Content -LiteralPath $adminKeys -Encoding ascii -Value ($AutomationPublicKey.Trim() + "`r`n")
    & icacls $adminKeys /inheritance:r | Out-Null
    & icacls $adminKeys /grant 'Administrators:F' 'SYSTEM:F' | Out-Null
}

$hostKeyPath = 'C:\ProgramData\ssh\ssh_host_ed25519_key.pub'
if (Test-Path -LiteralPath $hostKeyPath) {
    Get-Content -LiteralPath $hostKeyPath
} else {
    Write-Output 'host-key-unavailable'
}
