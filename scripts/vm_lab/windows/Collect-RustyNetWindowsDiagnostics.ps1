param(
    [string]$OutputRoot = 'C:\ProgramData\Rustynet\vm-lab\diagnostics'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
trap {
    Write-Error $_
    exit 1
}

$canonicalScript = Resolve-Path (Join-Path $PSScriptRoot '..\..\bootstrap\windows\Collect-RustyNetWindowsDiagnostics.ps1') -ErrorAction Stop

& $canonicalScript -OutputRoot $OutputRoot
exit $LASTEXITCODE
