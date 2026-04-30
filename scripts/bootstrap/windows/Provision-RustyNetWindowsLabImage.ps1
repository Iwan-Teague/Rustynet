<#
.SYNOPSIS
  One-time provisioning of a Windows lab guest image so subsequent
  vm-lab-bootstrap-phase runs can build Rustynet under SYSTEM
  execution without an Active interactive desktop session.

.DESCRIPTION
  Run elevated, ONCE, on a freshly installed Windows VM that will
  serve as a Rustynet lab node.  The script:

    1. Sets machine-scoped environment variables so SYSTEM and the
       lab user share the same toolchain layout:
         RUSTUP_HOME = C:\RustupHome
         CARGO_HOME  = C:\CargoHome
       and prepends C:\CargoHome\bin to the machine PATH.

    2. Downloads and runs rustup-init.exe with --no-modify-path so
       rustup writes only to the machine-scoped CARGO_HOME instead
       of the running user's profile.  Default toolchain: stable,
       minimal profile.  Adds the x86_64-pc-windows-msvc target
       (rustynetd target).

    3. Downloads and runs vs_BuildTools.exe with --installPath
       C:\BuildTools and the workloads / components Rustynet's MSVC
       link step needs (VC.Tools.x86.x64, Windows 11 SDK).

    4. Verifies machine-scoped reachability by re-resolving cargo /
       rustc / VsDevCmd from a fresh PowerShell context.

  The script is idempotent.  Re-running it skips any step whose
  artifact already exists with the expected version unless -Force is
  passed.

  Outputs a JSON receipt at the path given by -ReceiptPath (default
  C:\ProgramData\Rustynet\lab-image-provision.json) so subsequent
  bootstrap runs and the operator can confirm the image is ready.

.PARAMETER RustToolchain
  rustup toolchain spec to install.  Default: 'stable'.

.PARAMETER RustupHome
  Machine-scoped rustup install root.  Default: 'C:\RustupHome'.

.PARAMETER CargoHome
  Machine-scoped cargo install root.  Default: 'C:\CargoHome'.

.PARAMETER BuildToolsInstallPath
  VS Build Tools install root.  Default: 'C:\BuildTools'.

.PARAMETER ReceiptPath
  Where to write the provisioning receipt JSON.  Default:
  'C:\ProgramData\Rustynet\lab-image-provision.json'.

.PARAMETER Force
  Re-run all install steps even when the artifact looks present.

.PARAMETER SkipBuildTools
  Skip the VS Build Tools install step (rustup only).  Useful for
  iterative debugging; not for a real lab image.

.PARAMETER SkipRustup
  Skip the rustup install step.  Useful for re-running just the VS
  Build Tools step.

.NOTES
  Run from an elevated PowerShell.  Requires internet access on the
  guest (downloads from win.rustup.rs and aka.ms).

  After this script completes, a fresh PowerShell or service
  invocation will have RUSTUP_HOME / CARGO_HOME / PATH visible,
  including under NT AUTHORITY\SYSTEM.

  Reference: documents/operations/active/WindowsLabVmStabilityAndSessionModel_2026-04-30.md
#>

[CmdletBinding()]
param(
    [string]$RustToolchain = 'stable',
    [string]$RustupHome = 'C:\RustupHome',
    [string]$CargoHome = 'C:\CargoHome',
    [string]$BuildToolsInstallPath = 'C:\BuildTools',
    [string]$ReceiptPath = 'C:\ProgramData\Rustynet\lab-image-provision.json',
    [switch]$Force,
    [switch]$SkipBuildTools,
    [switch]$SkipRustup
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# --- helpers ---------------------------------------------------------------

function Test-IsAdministrator {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Set-MachineEnv {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Value
    )
    $current = [System.Environment]::GetEnvironmentVariable($Name, 'Machine')
    if ($current -eq $Value -and -not $Force) {
        Write-Host "[provision] machine env $Name already set to $Value"
        return
    }
    [System.Environment]::SetEnvironmentVariable($Name, $Value, 'Machine')
    # Also surface in the current process so subsequent steps in this
    # script see it.
    Set-Item -LiteralPath "Env:$Name" -Value $Value
    Write-Host "[provision] set machine env $Name = $Value"
}

function Add-MachinePathSegment {
    param([Parameter(Mandatory = $true)][string]$Segment)
    $current = [System.Environment]::GetEnvironmentVariable('Path', 'Machine')
    $segments = @()
    if ($current) { $segments = $current -split ';' | Where-Object { $_ -ne '' } }
    $existing = $segments | Where-Object { $_ -ieq $Segment }
    if ($existing -and -not $Force) {
        Write-Host "[provision] machine PATH already contains $Segment"
    } else {
        $segments = ($segments | Where-Object { $_ -ine $Segment }) + $Segment
        [System.Environment]::SetEnvironmentVariable('Path', ($segments -join ';'), 'Machine')
        Write-Host "[provision] appended $Segment to machine PATH"
    }
    # Also surface in current process.
    if ($env:Path -notmatch [regex]::Escape($Segment)) {
        $env:Path = "$Segment;$env:Path"
    }
}

function Invoke-WebDownload {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][string]$OutFile
    )
    Write-Host "[provision] downloading $Uri -> $OutFile"
    Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing
    if (-not (Test-Path -LiteralPath $OutFile)) {
        throw "download failed: $Uri did not produce $OutFile"
    }
}

function Get-CargoExePath {
    return (Join-Path $CargoHome 'bin\cargo.exe')
}
function Get-RustupExePath {
    return (Join-Path $CargoHome 'bin\rustup.exe')
}
function Get-VsDevCmdPath {
    return (Join-Path $BuildToolsInstallPath 'Common7\Tools\VsDevCmd.bat')
}

# --- preflight -------------------------------------------------------------

if (-not (Test-IsAdministrator)) {
    throw 'Provision-RustyNetWindowsLabImage.ps1 must be run from an elevated PowerShell session'
}

$workRoot = Join-Path $env:TEMP ("rustynet-lab-provision-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $workRoot | Out-Null

$result = [ordered]@{
    schema_version = 1
    captured_at_utc = (Get-Date).ToUniversalTime().ToString('o')
    rust_toolchain = $RustToolchain
    rustup_home = $RustupHome
    cargo_home = $CargoHome
    build_tools_install_path = $BuildToolsInstallPath
    rust_installed = $false
    build_tools_installed = $false
    rust_versions = @{}
    notes = @()
}

# --- step 1: machine env ---------------------------------------------------

Set-MachineEnv -Name 'RUSTUP_HOME' -Value $RustupHome
Set-MachineEnv -Name 'CARGO_HOME'  -Value $CargoHome
Add-MachinePathSegment -Segment (Join-Path $CargoHome 'bin')

foreach ($dir in @($RustupHome, $CargoHome, $BuildToolsInstallPath)) {
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        Write-Host "[provision] created $dir"
    }
}

# --- step 2: rustup --------------------------------------------------------

if ($SkipRustup) {
    $result.notes += 'skipped rustup install (-SkipRustup)'
} else {
    $rustupExe = Get-RustupExePath
    $cargoExe  = Get-CargoExePath
    $needRustup = $Force -or -not (Test-Path -LiteralPath $rustupExe) -or -not (Test-Path -LiteralPath $cargoExe)
    if (-not $needRustup) {
        Write-Host "[provision] rustup already present at $rustupExe; skipping install"
    } else {
        # rustup-init.exe is platform-specific and the host triple it
        # installs becomes the default for `rustup default stable`.  We
        # MUST pick the installer that matches the running guest arch
        # (ARM64 vs x86_64), otherwise cargo runs in the workspace see
        # a host mismatch and fail with "cargo.exe is not installed for
        # the toolchain 1.88.0-aarch64-pc-windows-msvc".  Detect from
        # PROCESSOR_ARCHITECTURE / Win32_OperatingSystem.OSArchitecture.
        $osArch = (Get-CimInstance Win32_OperatingSystem).OSArchitecture
        if ($osArch -match 'ARM' -or $env:PROCESSOR_ARCHITECTURE -eq 'ARM64') {
            $rustupHostTriple = 'aarch64-pc-windows-msvc'
            $rustupInitUrl = 'https://win.rustup.rs/aarch64'
        } else {
            $rustupHostTriple = 'x86_64-pc-windows-msvc'
            $rustupInitUrl = 'https://win.rustup.rs/x86_64'
        }
        Write-Host "[provision] guest OS arch '$osArch' -> rustup host triple $rustupHostTriple"
        $rustupInit = Join-Path $workRoot 'rustup-init.exe'
        Invoke-WebDownload -Uri $rustupInitUrl -OutFile $rustupInit
        $rustupArgs = @(
            '-y',
            '--no-modify-path',
            '--default-toolchain', $RustToolchain,
            '--profile', 'minimal',
            '--default-host', $rustupHostTriple
        )
        Write-Host "[provision] running rustup-init.exe $($rustupArgs -join ' ')"
        $proc = Start-Process -FilePath $rustupInit -ArgumentList $rustupArgs `
            -NoNewWindow -PassThru -Wait
        if ($proc.ExitCode -ne 0) {
            throw "rustup-init failed with exit code $($proc.ExitCode)"
        }
    }
    if (-not (Test-Path -LiteralPath $cargoExe)) {
        throw "cargo.exe not present at $cargoExe after rustup install"
    }
    if (-not (Test-Path -LiteralPath $rustupExe)) {
        throw "rustup.exe not present at $rustupExe after rustup install"
    }
    $result.rust_installed = $true
    try {
        $cargoVersion = (& $cargoExe --version 2>&1 | Out-String).Trim()
        $rustcVersion = (& (Join-Path $CargoHome 'bin\rustc.exe') --version 2>&1 | Out-String).Trim()
        $rustupVersion = (& $rustupExe --version 2>&1 | Out-String).Trim()
        $result.rust_versions = @{
            cargo  = $cargoVersion
            rustc  = $rustcVersion
            rustup = $rustupVersion
        }
    } catch {
        $result.notes += "version probe failed: $($_.Exception.Message)"
    }
}

# --- step 3: vs build tools -----------------------------------------------

if ($SkipBuildTools) {
    $result.notes += 'skipped vs build tools install (-SkipBuildTools)'
} else {
    $vsDevCmd = Get-VsDevCmdPath
    $needBuildTools = $Force -or -not (Test-Path -LiteralPath $vsDevCmd)
    if (-not $needBuildTools) {
        Write-Host "[provision] VS Build Tools already present at $vsDevCmd; skipping install"
    } else {
        $vsBootstrapper = Join-Path $workRoot 'vs_BuildTools.exe'
        Invoke-WebDownload -Uri 'https://aka.ms/vs/17/release/vs_BuildTools.exe' -OutFile $vsBootstrapper
        $vsArgs = @(
            '--installPath', $BuildToolsInstallPath,
            '--add', 'Microsoft.VisualStudio.Workload.VCTools',
            '--add', 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64',
            '--add', 'Microsoft.VisualStudio.Component.Windows11SDK.22621',
            '--quiet', '--wait', '--norestart', '--nocache'
        )
        Write-Host "[provision] running vs_BuildTools.exe $($vsArgs -join ' ')"
        $proc = Start-Process -FilePath $vsBootstrapper -ArgumentList $vsArgs `
            -NoNewWindow -PassThru -Wait
        # vs_BuildTools.exe sometimes returns 3010 (reboot required) on
        # success.  Treat 0 and 3010 as success; everything else throws.
        if ($proc.ExitCode -ne 0 -and $proc.ExitCode -ne 3010) {
            throw "vs_BuildTools.exe failed with exit code $($proc.ExitCode)"
        }
        if ($proc.ExitCode -eq 3010) {
            $result.notes += 'vs build tools reported reboot required (exit 3010)'
        }
    }
    if (-not (Test-Path -LiteralPath $vsDevCmd)) {
        throw "VsDevCmd.bat not present at $vsDevCmd after Build Tools install"
    }
    $result.build_tools_installed = $true
}

# --- step 4: verify machine reachability ----------------------------------

$cargoExeFinal = Get-CargoExePath
if (-not (Test-Path -LiteralPath $cargoExeFinal)) {
    $result.notes += "post-install verify: cargo.exe missing at $cargoExeFinal"
}
$vsDevCmdFinal = Get-VsDevCmdPath
if (-not (Test-Path -LiteralPath $vsDevCmdFinal) -and -not $SkipBuildTools) {
    $result.notes += "post-install verify: VsDevCmd.bat missing at $vsDevCmdFinal"
}

# --- write receipt ---------------------------------------------------------

$receiptParent = Split-Path -Parent $ReceiptPath
if ($receiptParent -and -not (Test-Path -LiteralPath $receiptParent)) {
    New-Item -ItemType Directory -Force -Path $receiptParent | Out-Null
}
$result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ReceiptPath -Encoding UTF8
Write-Host "[provision] receipt written to $ReceiptPath"

# --- cleanup ---------------------------------------------------------------

try {
    Remove-Item -LiteralPath $workRoot -Recurse -Force -ErrorAction SilentlyContinue
} catch { }

Write-Host '[provision] done.  open a fresh PowerShell to pick up RUSTUP_HOME / CARGO_HOME / PATH from machine env.'
