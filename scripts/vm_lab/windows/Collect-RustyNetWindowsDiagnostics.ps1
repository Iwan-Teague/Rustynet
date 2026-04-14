param(
    [string]$OutputRoot = 'C:\ProgramData\Rustynet\vm-lab\diagnostics'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null

Get-Service | Sort-Object Name | Format-Table -AutoSize | Out-File -Encoding utf8 (Join-Path $OutputRoot 'services.txt')
Get-NetIPConfiguration | Format-List * | Out-File -Encoding utf8 (Join-Path $OutputRoot 'net-ip.txt')
Get-NetRoute | Sort-Object DestinationPrefix, RouteMetric | Format-Table -AutoSize | Out-File -Encoding utf8 (Join-Path $OutputRoot 'routes.txt')
Get-DnsClientServerAddress | Format-List * | Out-File -Encoding utf8 (Join-Path $OutputRoot 'dns.txt')
Get-NetFirewallRule | Where-Object { $_.DisplayName -like '*RustyNet*' -or $_.DisplayName -like '*OpenSSH*' } | Format-Table -AutoSize | Out-File -Encoding utf8 (Join-Path $OutputRoot 'firewall.txt')
Get-WinEvent -LogName System -MaxEvents 100 | Format-List TimeCreated, ProviderName, Id, LevelDisplayName, Message | Out-File -Encoding utf8 (Join-Path $OutputRoot 'events-system.txt')
Get-WinEvent -LogName Application -MaxEvents 100 | Format-List TimeCreated, ProviderName, Id, LevelDisplayName, Message | Out-File -Encoding utf8 (Join-Path $OutputRoot 'events-application.txt')
@('git --version','rustup --version','cargo --version','powershell.exe -Version') | ForEach-Object {
    "## $_"
    cmd.exe /c $_ 2>&1
    ''
} | Out-File -Encoding utf8 (Join-Path $OutputRoot 'tooling.txt')

Write-Output $OutputRoot
