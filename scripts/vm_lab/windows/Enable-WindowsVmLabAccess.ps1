param(
    [string]$AutomationPublicKey = "",
    [string]$ResultPath = "",
    [switch]$SetDefaultShellToPowerShell
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
trap {
    Write-Error $_
    exit 1
}

function Resolve-CanonicalBootstrapScript {
    $candidates = @(
        (Join-Path $PSScriptRoot 'Bootstrap-RustyNetWindows.ps1'),
        (Join-Path $PSScriptRoot '..\..\bootstrap\windows\Bootstrap-RustyNetWindows.ps1')
    )
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) {
            return (Resolve-Path -LiteralPath $candidate -ErrorAction Stop)
        }
    }
    throw 'Bootstrap-RustyNetWindows.ps1 is not available on this host path'
}

$canonicalScript = (Resolve-CanonicalBootstrapScript).Path
$trimmedAutomationPublicKey = $AutomationPublicKey.Trim()
$trimmedResultPath = $ResultPath.Trim()

if ($SetDefaultShellToPowerShell) {
    if ($trimmedAutomationPublicKey.Length -gt 0 -and $trimmedResultPath.Length -gt 0) {
        & $canonicalScript -Phase 'prepare-transport' -AutomationPublicKey $trimmedAutomationPublicKey -ResultPath $trimmedResultPath -SetDefaultShellToPowerShell
    }
    elseif ($trimmedAutomationPublicKey.Length -gt 0) {
        & $canonicalScript -Phase 'prepare-transport' -AutomationPublicKey $trimmedAutomationPublicKey -SetDefaultShellToPowerShell
    }
    elseif ($trimmedResultPath.Length -gt 0) {
        & $canonicalScript -Phase 'prepare-transport' -ResultPath $trimmedResultPath -SetDefaultShellToPowerShell
    }
    else {
        & $canonicalScript -Phase 'prepare-transport' -SetDefaultShellToPowerShell
    }
}
elseif ($trimmedAutomationPublicKey.Length -gt 0 -and $trimmedResultPath.Length -gt 0) {
    & $canonicalScript -Phase 'prepare-transport' -AutomationPublicKey $trimmedAutomationPublicKey -ResultPath $trimmedResultPath
}
elseif ($trimmedAutomationPublicKey.Length -gt 0) {
    & $canonicalScript -Phase 'prepare-transport' -AutomationPublicKey $trimmedAutomationPublicKey
}
elseif ($trimmedResultPath.Length -gt 0) {
    & $canonicalScript -Phase 'prepare-transport' -ResultPath $trimmedResultPath
}
else {
    & $canonicalScript -Phase 'prepare-transport'
}
exit $LASTEXITCODE
