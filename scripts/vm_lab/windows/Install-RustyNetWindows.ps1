param(
    [Parameter(Mandatory = $true)]
    [string]$RepoUrl,
    [string]$Branch = 'main',
    [string]$RustyNetRoot = 'C:\Rustynet',
    [switch]$InstallPowerShell7,
    [switch]$InstallRustup = $true,
    [string]$GitPackageId = 'Git.Git',
    [string]$PowerShellPackageId = 'Microsoft.PowerShell',
    [string]$RustupPackageId = 'Rustlang.Rustup'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
trap {
    Write-Error $_
    exit 1
}

$canonicalScript = Resolve-Path (Join-Path $PSScriptRoot '..\..\bootstrap\windows\Bootstrap-RustyNetWindows.ps1') -ErrorAction Stop

$sharedArgs = @(
    '-Branch', $Branch,
    '-RustyNetRoot', $RustyNetRoot,
    '-RepoUrl', $RepoUrl
)

if ($InstallPowerShell7) {
    $sharedArgs += '-InstallPowerShell7'
}

& $canonicalScript @sharedArgs -Phase sync-source -SourceMode git
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

& $canonicalScript @sharedArgs -Phase build-release
exit $LASTEXITCODE
