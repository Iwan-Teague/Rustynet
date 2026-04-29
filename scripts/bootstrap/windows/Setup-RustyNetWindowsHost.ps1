param(
    [string]$RustyNetRoot = 'C:\Rustynet',
    [string]$WingetConfigPath = '',
    [string]$VsConfigPath = '',
    [switch]$SkipDefenderExclusions,
    [switch]$SkipBuildTools
)

# Setup-RustyNetWindowsHost.ps1
#
# Idempotent first-time setup for a Windows host that will participate in a
# RustyNet lab — either as a build node or as a peer the orchestrator
# bootstraps over SSH. Installs every dependency Bootstrap-RustyNetWindows.ps1
# expects, at the canonical paths the bootstrap helpers look for, and adds
# Defender exclusions so subsequent `cargo build` invocations are not
# silently throttled by real-time AV scanning.
#
# Run this ONCE per fresh Windows VM, as Administrator, from a desktop
# session (UAC will prompt for the VS Build Tools installer).
#
# Tools installed (canonical paths the bootstrap path checks first):
#   - WireGuard           C:\Program Files\WireGuard\{wireguard,wg}.exe
#   - Rustup + Rust       %USERPROFILE%\.cargo\bin\{cargo,rustc,rustup}.exe
#   - Git                 C:\Program Files\Git\cmd\git.exe
#   - VS Build Tools 2022 C:\Program Files\Microsoft Visual Studio\2022\BuildTools
#     (or the (x86) sibling, whichever the installer picks).
#
# Defender exclusions added (idempotent):
#   - $RustyNetRoot                          (default C:\Rustynet)
#   - %USERPROFILE%\.cargo
#   - C:\Windows\Temp\rustynet-stage         (orchestrator staging dir)
#   - C:\ProgramData\RustyNet                (daemon state root)
#   - C:\Program Files\RustyNet              (daemon install root)
#
# This script does not start the RustyNet service or join the host to a
# mesh; that work belongs to Install-RustyNetWindowsService.ps1 (run by the
# orchestrator's install_daemon path).

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Write-Step {
    param([Parameter(Mandatory = $true)][string]$Message)
    Write-Host ('[setup] ' + $Message)
}

function Test-IsAdministrator {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object System.Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdministrator)) {
    throw 'Setup-RustyNetWindowsHost.ps1 must be run from an elevated (Administrator) PowerShell.'
}

# ── Step 1: Defender exclusions ────────────────────────────────────────────
if (-not $SkipDefenderExclusions) {
    $exclusions = @(
        $RustyNetRoot,
        (Join-Path $env:USERPROFILE '.cargo'),
        'C:\Windows\Temp\rustynet-stage',
        'C:\ProgramData\RustyNet',
        'C:\Program Files\RustyNet'
    )
    foreach ($path in $exclusions) {
        Write-Step ('add Defender exclusion: ' + $path)
        try {
            Add-MpPreference -ExclusionPath $path -ErrorAction Stop
        }
        catch {
            # Add-MpPreference is additive: pre-existing duplicates are not
            # an error. Surface only genuine failures.
            $msg = $_.Exception.Message
            if ($msg -notmatch 'already exists' -and $msg -notmatch 'duplicate') {
                Write-Host ('[setup] WARNING: Add-MpPreference failed for ' + $path + ': ' + $msg)
            }
        }
    }
}
else {
    Write-Step '-SkipDefenderExclusions set; not modifying Windows Defender preferences.'
}

# ── Step 2: WireGuard, Rustup, Git via winget configure ───────────────────
$resolvedWingetConfig = if ($WingetConfigPath -and $WingetConfigPath.Trim().Length -gt 0) {
    $WingetConfigPath
}
else {
    Join-Path $PSScriptRoot 'RustyNetBootstrap.winget.yml'
}
if (-not (Test-Path -LiteralPath $resolvedWingetConfig)) {
    throw ('winget config file not found: ' + $resolvedWingetConfig)
}

if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) {
    throw 'winget.exe is not on PATH. Install Microsoft App Installer from the Store, or use a pre-baked Windows lab template.'
}

Write-Step ('winget configure --file ' + $resolvedWingetConfig)
& winget configure --file $resolvedWingetConfig --accept-configuration-agreements --disable-interactivity
if ($LASTEXITCODE -ne 0) {
    throw ('winget configure failed (exit ' + [string]$LASTEXITCODE + '). See the winget log for details.')
}

# ── Step 3: VS Build Tools ─────────────────────────────────────────────────
if (-not $SkipBuildTools) {
    $vsDevCmdCandidates = @(
        'C:\Program Files\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat',
        'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat'
    )
    $vsAlreadyInstalled = $vsDevCmdCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if ($vsAlreadyInstalled) {
        Write-Step ('VS Build Tools already installed at ' + $vsAlreadyInstalled)
    }
    else {
        $resolvedVsConfig = if ($VsConfigPath -and $VsConfigPath.Trim().Length -gt 0) {
            $VsConfigPath
        }
        else {
            Join-Path $PSScriptRoot 'RustyNetBuildTools.vsconfig'
        }
        if (-not (Test-Path -LiteralPath $resolvedVsConfig)) {
            throw ('VS Build Tools config not found: ' + $resolvedVsConfig)
        }
        Write-Step ('installing VS Build Tools 2022 (config ' + $resolvedVsConfig + '); UAC may prompt.')
        & winget install --accept-package-agreements --accept-source-agreements `
            --disable-interactivity -e --id 'Microsoft.VisualStudio.2022.BuildTools' `
            --override ('--passive --wait --config "' + $resolvedVsConfig + '"')
        if ($LASTEXITCODE -ne 0) {
            throw ('winget install Microsoft.VisualStudio.2022.BuildTools failed (exit ' + [string]$LASTEXITCODE + ').')
        }
    }
}
else {
    Write-Step '-SkipBuildTools set; not installing VS Build Tools.'
}

# ── Step 4: verify everything landed at the expected canonical paths ──────
$expectations = @(
    @{ Name = 'WireGuard.WireGuard'; Path = 'C:\Program Files\WireGuard\wireguard.exe' },
    @{ Name = 'WireGuard CLI';        Path = 'C:\Program Files\WireGuard\wg.exe' },
    @{ Name = 'Rustlang.Rustup';      Path = (Join-Path $env:USERPROFILE '.cargo\bin\rustup.exe') }
)
$missing = @()
foreach ($exp in $expectations) {
    if (Test-Path -LiteralPath $exp.Path) {
        Write-Step ('OK ' + $exp.Name + ' -> ' + $exp.Path)
    }
    else {
        $missing += ($exp.Name + ' (' + $exp.Path + ')')
    }
}

# Cargo/rustc need a full toolchain install via rustup.
$cargoExe = Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe'
$rustcExe = Join-Path $env:USERPROFILE '.cargo\bin\rustc.exe'
if (-not ((Test-Path -LiteralPath $cargoExe) -and (Test-Path -LiteralPath $rustcExe))) {
    $rustupExe = Join-Path $env:USERPROFILE '.cargo\bin\rustup.exe'
    if (Test-Path -LiteralPath $rustupExe) {
        Write-Step 'rustup found but cargo/rustc missing; running rustup default stable to install the toolchain.'
        & $rustupExe set profile minimal
        if ($LASTEXITCODE -ne 0) { throw 'rustup set profile minimal failed' }
        & $rustupExe default stable
        if ($LASTEXITCODE -ne 0) { throw 'rustup default stable failed' }
    }
}
foreach ($pair in @(@{Name='cargo'; Path=$cargoExe}, @{Name='rustc'; Path=$rustcExe})) {
    if (Test-Path -LiteralPath $pair.Path) {
        Write-Step ('OK ' + $pair.Name + ' -> ' + $pair.Path)
    }
    else {
        $missing += ($pair.Name + ' (' + $pair.Path + ')')
    }
}

# Git: winget puts it under Program Files\Git or Program Files (x86)\Git.
$gitCandidates = @(
    'C:\Program Files\Git\cmd\git.exe',
    'C:\Program Files (x86)\Git\cmd\git.exe'
)
$gitFound = $gitCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if ($gitFound) {
    Write-Step ('OK Git -> ' + $gitFound)
}
else {
    $missing += ('Git.Git (' + ($gitCandidates -join ' / ') + ')')
}

if ($missing.Count -gt 0) {
    $list = $missing -join '; '
    throw ('Setup completed winget configure successfully but the following dependencies were NOT found at their canonical paths: ' + $list + '. Re-run Setup-RustyNetWindowsHost.ps1 from an elevated desktop session, or install the missing package(s) manually before running the orchestrator.')
}

Write-Step 'Setup-RustyNetWindowsHost.ps1 completed successfully.'
