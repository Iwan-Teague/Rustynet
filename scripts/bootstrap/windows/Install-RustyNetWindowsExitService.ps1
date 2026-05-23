param(
    [string]$InstallRoot = 'C:\Program Files\RustyNet',
    [string]$StateRoot = 'C:\ProgramData\RustyNet'
)

# Track B Step 3 (B1.4) — RustyNet Windows exit-mode preflight.
#
# Pre-arms a Windows host for the `exit` role-preset transition by
# enabling IPv4 forwarding on every IP-bound interface via
# `Set-NetIPInterface -Forwarding Enabled`, then recording the
# resulting state into a reviewed install report under
# `<StateRoot>\install-evidence\rustynet-exit-install.json`.
#
# The runtime exit-serving lifecycle (NetNat, firewall killswitch,
# default-route programming) remains owned by the rustynetd Windows
# service. This script is install-time evidence the host is prepared,
# not a parallel exit data-plane — one hardened execution path per
# security-sensitive flow, per `AGENTS.md`.
#
# Fail-closed on any per-interface failure: the script exits with a
# non-zero code and the install report records `status=fail` with the
# precise step that failed. The companion uninstall script
# (`Uninstall-RustyNetWindowsExitService.ps1`) reverses the change
# when the operator transitions out of the exit preset.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

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

Test-RustyNetReviewedInstallRoot -Path $InstallRoot
Test-RustyNetReviewedStateRoot -Path $StateRoot

$evidenceDir = Join-Path -Path $StateRoot -ChildPath 'install-evidence'
$reportPath = Join-Path -Path $evidenceDir -ChildPath 'rustynet-exit-install.json'

if (-not (Test-Path -Path $evidenceDir)) {
    [void](New-Item -ItemType Directory -Path $evidenceDir -Force)
}

$enabledInterfaces = @()
$failures = @()
$interfaces = Get-NetIPInterface -AddressFamily IPv4 -ErrorAction Stop
foreach ($iface in $interfaces) {
    try {
        Set-NetIPInterface -InterfaceIndex $iface.ifIndex `
            -AddressFamily IPv4 `
            -Forwarding Enabled `
            -ErrorAction Stop | Out-Null
        $enabledInterfaces += @{
            interface_index = $iface.ifIndex
            interface_alias = $iface.InterfaceAlias
            forwarding = 'Enabled'
        }
    } catch {
        $failures += @{
            interface_index = $iface.ifIndex
            interface_alias = $iface.InterfaceAlias
            reason = $_.Exception.Message
        }
    }
}

$status = if ($failures.Count -gt 0) { 'fail' } else { 'ok' }

$report = [ordered]@{
    schema_version = 1
    captured_at_utc = (Get-Date).ToUniversalTime().ToString('o')
    platform = 'windows'
    install_root = $InstallRoot
    state_root = $StateRoot
    role = 'exit'
    action = 'install'
    status = $status
    interfaces_enabled = $enabledInterfaces
    failures = $failures
    notes = @('rustynet-exit-preflight')
}

$json = $report | ConvertTo-Json -Depth 6
Set-Content -Path $reportPath -Value $json -Encoding UTF8

if ($status -ne 'ok') {
    throw ("RustyNet Windows exit preflight failed for {0} interface(s); see {1}" -f $failures.Count, $reportPath)
}

Write-Output ("RustyNet Windows exit preflight enabled IPv4 forwarding on {0} interface(s); report at {1}" -f $enabledInterfaces.Count, $reportPath)
