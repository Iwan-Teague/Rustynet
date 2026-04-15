param(
    [string]$RustyNetRoot = 'C:\Rustynet',
    [string]$InstallRoot = 'C:\Program Files\RustyNet',
    [string]$StateRoot = 'C:\ProgramData\RustyNet',
    [string]$ServiceName = 'RustyNet'
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

function Test-RustyNetWindowsRuntimeSupport {
    param([Parameter(Mandatory = $true)][string]$DaemonPath)
    $helpText = (& $DaemonPath --help 2>&1 | Out-String)
    $hasWindowsService = $helpText -match '--windows-service'
    $hasEnvFile = $helpText -match '--env-file'
    return [ordered]@{
        has_windows_service = $hasWindowsService
        has_env_file = $hasEnvFile
    }
}

Ensure-Directory -Path $InstallRoot
Ensure-Directory -Path (Join-Path $InstallRoot 'bin')
Ensure-Directory -Path $StateRoot
Ensure-Directory -Path (Join-Path $StateRoot 'config')
Ensure-Directory -Path (Join-Path $StateRoot 'logs')
Ensure-Directory -Path (Join-Path $StateRoot 'trust')
Ensure-Directory -Path (Join-Path $StateRoot 'keys')
Ensure-Directory -Path (Join-Path $StateRoot 'membership')

$daemonCandidates = @(
    Join-Path $RustyNetRoot 'target\release\rustynetd.exe'
)
$cliCandidates = @(
    Join-Path $RustyNetRoot 'target\release\rustynet.exe',
    Join-Path $RustyNetRoot 'target\release\rustynet-cli.exe'
)

$daemonSource = $daemonCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $daemonSource) {
    throw 'rustynetd.exe was not found under the Windows release output directory'
}
$cliSource = $cliCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1

$daemonDest = Join-Path $InstallRoot 'bin\rustynetd.exe'
Copy-Item -LiteralPath $daemonSource -Destination $daemonDest -Force
if ($cliSource) {
    Copy-Item -LiteralPath $cliSource -Destination (Join-Path $InstallRoot 'bin\rustynet.exe') -Force
}

$configPath = Join-Path $StateRoot 'config\rustynetd.env'
if (-not (Test-Path -LiteralPath $configPath)) {
    @(
        '# Populate this file with Windows-specific RustyNet runtime environment'
        '# Windows runtime install will remain blocked until rustynetd exposes a real Windows service host and --env-file support'
    ) | Out-File -Encoding ascii $configPath
}

Test-RustyNetWindowsRuntimeSupport -DaemonPath $daemonDest
$runtimeSignals = Test-RustyNetWindowsRuntimeSupport -DaemonPath $daemonDest
if (-not $runtimeSignals.has_windows_service -or -not $runtimeSignals.has_env_file) {
    throw 'Blocked: windows-runtime-service-host-not-yet-implemented: rustynetd.exe does not advertise both --windows-service and --env-file support on the current branch. Refusing to create a fake Windows service wrapper; Windows runtime install remains blocked until rustynetd exposes a real Windows service/config host path.'
}

throw 'Blocked: windows-runtime-service-host-not-yet-implemented: Windows runtime service installation remains disabled on the current branch until rustynetd exposes a reviewed Windows service/config host path with dedicated tests. Refusing to create or update a Windows service wrapper from bootstrap.'
