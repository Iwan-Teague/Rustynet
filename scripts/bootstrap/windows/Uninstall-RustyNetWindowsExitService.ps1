param(
    [string]$InstallRoot = 'C:\Program Files\RustyNet',
    [string]$StateRoot = 'C:\ProgramData\RustyNet'
)

# Track B Step 3 (B1.4) — RustyNet Windows exit-mode preflight teardown.
#
# Reverses `Install-RustyNetWindowsExitService.ps1` by disabling IPv4
# forwarding on every interface and recording the resulting state to
# `<StateRoot>\install-evidence\rustynet-exit-uninstall.json`. Used by
# the role-transition planner when the operator transitions out of the
# `exit` preset on a Windows host. Fail-closed on any per-interface
# failure so the operator immediately sees that forwarding is partially
# active rather than silently leaving an exit-shaped host behind.

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
$reportPath = Join-Path -Path $evidenceDir -ChildPath 'rustynet-exit-uninstall.json'

if (-not (Test-Path -Path $evidenceDir)) {
    [void](New-Item -ItemType Directory -Path $evidenceDir -Force)
}

$disabledInterfaces = @()
$failures = @()
$interfaces = Get-NetIPInterface -AddressFamily IPv4 -ErrorAction Stop
foreach ($iface in $interfaces) {
    try {
        Set-NetIPInterface -InterfaceIndex $iface.ifIndex `
            -AddressFamily IPv4 `
            -Forwarding Disabled `
            -ErrorAction Stop | Out-Null
        $disabledInterfaces += @{
            interface_index = $iface.ifIndex
            interface_alias = $iface.InterfaceAlias
            forwarding = 'Disabled'
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
    action = 'uninstall'
    status = $status
    interfaces_disabled = $disabledInterfaces
    failures = $failures
    notes = @('rustynet-exit-preflight')
}

$json = $report | ConvertTo-Json -Depth 6
Set-Content -Path $reportPath -Value $json -Encoding UTF8

if ($status -ne 'ok') {
    throw ("RustyNet Windows exit preflight teardown failed for {0} interface(s); see {1}" -f $failures.Count, $reportPath)
}

Write-Output ("RustyNet Windows exit preflight disabled IPv4 forwarding on {0} interface(s); report at {1}" -f $disabledInterfaces.Count, $reportPath)
