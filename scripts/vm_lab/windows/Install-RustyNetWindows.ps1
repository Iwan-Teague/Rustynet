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

function Require-Winget {
    if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) {
        throw 'winget.exe is not available; install App Installer or use a pre-baked Windows lab template'
    }
}

function Install-WingetPackage {
    param([Parameter(Mandatory = $true)][string]$Id)
    Require-Winget
    & winget install --accept-package-agreements --accept-source-agreements --disable-interactivity -e --id $Id
    if ($LASTEXITCODE -ne 0) {
        throw "winget install failed for package id: $Id"
    }
}

Install-WingetPackage -Id $GitPackageId
if ($InstallPowerShell7) {
    Install-WingetPackage -Id $PowerShellPackageId
}
if ($InstallRustup) {
    Install-WingetPackage -Id $RustupPackageId
}

if (Test-Path -LiteralPath "$env:USERPROFILE\.cargo\bin") {
    $env:PATH = "$env:USERPROFILE\.cargo\bin;" + $env:PATH
}

New-Item -ItemType Directory -Force -Path $RustyNetRoot | Out-Null

if (-not (Test-Path -LiteralPath $RustyNetRoot)) {
    throw "RustyNet root does not exist after create attempt: $RustyNetRoot"
}

if (-not (Test-Path -LiteralPath (Join-Path $RustyNetRoot '.git'))) {
    if ((Get-ChildItem -LiteralPath $RustyNetRoot -Force | Measure-Object).Count -gt 0) {
        throw "RustyNet root exists but is not empty and not a git repo: $RustyNetRoot"
    }
    git clone --branch $Branch --single-branch $RepoUrl $RustyNetRoot
} else {
    git -C $RustyNetRoot fetch origin $Branch --prune
    git -C $RustyNetRoot checkout -B $Branch FETCH_HEAD
    git -C $RustyNetRoot reset --hard FETCH_HEAD
    git -C $RustyNetRoot clean -fdx
}

Push-Location $RustyNetRoot
try {
    git rev-parse HEAD
    if (Get-Command cargo.exe -ErrorAction SilentlyContinue) {
        cargo --version
    } else {
        Write-Warning 'cargo.exe is not yet on PATH in this session; you may need a new SSH session after rustup install'
    }
}
finally {
    Pop-Location
}
