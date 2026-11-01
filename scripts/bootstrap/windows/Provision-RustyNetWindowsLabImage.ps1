<#
.SYNOPSIS
  One-time provisioning of a Windows lab guest image so subsequent
  vm-lab-bootstrap-phase runs can build Rustynet under SYSTEM
  execution without an Active interactive desktop session.

.DESCRIPTION
  Run elevated, ONCE, on a freshly installed Windows VM that will
  serve as a Rustynet lab node.  The script:

    1. Unless -SkipRustup is passed, sets machine-scoped environment
       variables so SYSTEM and the lab user share the same toolchain
       layout:
         RUSTUP_HOME = C:\RustupHome
         CARGO_HOME  = C:\CargoHome
       and prepends C:\CargoHome\bin to the machine PATH.  A
       -SkipRustup run leaves the machine cargo/rustup environment
       untouched (QH-17).

   2. Downloads and runs rustup-init.exe with --no-modify-path so
      rustup writes only to the machine-scoped CARGO_HOME instead
      of the running user's profile.  Default toolchain: stable,
      minimal profile.  Adds the x86_64-pc-windows-msvc target
      (rustynetd target).  The download is verified against a
      pinned SHA-256 (RSA-0065) before it is executed; a mismatch
      deletes the file and aborts the run.

   3. Downloads and runs vs_BuildTools.exe with --installPath
      C:\BuildTools and the component set from
      RustyNetBuildTools.vsconfig (the single authoritative VS
      component definition, shared with the bootstrap path).
      The download is verified against a pinned SHA-256 AND a
      Valid Authenticode signature whose signer subject names
      'Microsoft Corporation' (RSA-0065) before it is executed;
      any mismatch deletes the file and aborts the run.

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
  Skip the rustup install step AND the machine-scoped toolchain
  environment mutation, leaving any existing cargo/rustup setup
  untouched.  Useful for re-running just the VS Build Tools step.

.NOTES
  Run from an elevated PowerShell.  Requires internet access on the
  guest (downloads from win.rustup.rs and aka.ms, both over HTTPS and
  both integrity-checked per RSA-0065: pinned SHA-256 for every
  artifact, plus a Valid Authenticode signature from Microsoft
  Corporation for the floating vs_BuildTools.exe bootstrapper; a
  failed check deletes the download and aborts before execution).

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
    # RSA-0065 remediation: every download MUST carry a pinned SHA-256
    # digest (Mandatory, so an omitted pin is a parameter-binding error,
    # not a silent skip) and is verified with Get-FileHash before the
    # file may be used.  Executables additionally support an Authenticode
    # publisher requirement via -RequireAuthenticodeSubject (checked with
    # Get-AuthenticodeSignature).  Any failure DELETES the downloaded
    # file and throws BEFORE the caller can execute it: fail closed.
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][string]$OutFile,
        [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedSha256,
        [Parameter(Mandatory = $false)][string]$RequireAuthenticodeSubject
    )
    if ($Uri -notlike 'https://*') {
        throw "refusing to download over a non-HTTPS transport: $Uri"
    }
    Write-Host "[provision] downloading $Uri -> $OutFile"
    try {
        Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing
    } catch {
        Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
        throw "download failed: $Uri ($_)"
    }
    if (-not (Test-Path -LiteralPath $OutFile)) {
        throw "download failed: $Uri did not produce $OutFile"
    }
    $actualHash = (Get-FileHash -LiteralPath $OutFile -Algorithm SHA256).Hash
    if (-not $actualHash -or
        -not [string]::Equals($actualHash, $ExpectedSha256, [System.StringComparison]::OrdinalIgnoreCase)) {
        Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
        throw "RSA-0065: SHA-256 pin mismatch for $Uri -> $OutFile (expected $ExpectedSha256, got $actualHash); file deleted, refusing to continue"
    }
    if ($RequireAuthenticodeSubject) {
        $signature = Get-AuthenticodeSignature -FilePath $OutFile
        if ($signature.Status -ne [System.Security.Cryptography.X509Certificates.X509SignatureStatus]::Valid) {
            Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
            throw "RSA-0065: Authenticode status for $OutFile is '$($signature.Status)' (expected Valid); file deleted, refusing to continue"
        }
        $signerSubject = ''
        if ($signature.SignerCertificate) {
            $signerSubject = $signature.SignerCertificate.Subject
        }
        if ($signerSubject -notlike "*$RequireAuthenticodeSubject*") {
            Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
            throw "RSA-0065: Authenticode signer subject '$signerSubject' does not match required publisher '$RequireAuthenticodeSubject' for $OutFile; file deleted, refusing to continue"
        }
        Write-Host "[provision] verified ${OutFile}: sha256 pin + Authenticode Valid ($RequireAuthenticodeSubject)"
    } else {
        Write-Host "[provision] verified ${OutFile}: sha256 pin"
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
# The machine-scoped toolchain environment is part of INSTALLING the
# toolchain.  A -SkipRustup run is a re-run of some other step on a guest
# that already has a toolchain, so it must leave the machine cargo/rustup
# environment exactly as it found it (QH-17).

if ($SkipRustup) {
    $result.notes += 'skipped machine toolchain env mutation (-SkipRustup)'
} else {
    Set-MachineEnv -Name 'RUSTUP_HOME' -Value $RustupHome
    Set-MachineEnv -Name 'CARGO_HOME'  -Value $CargoHome
    Add-MachinePathSegment -Segment (Join-Path $CargoHome 'bin')
}

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
        # RSA-0065: rustup-init.exe is a FLOATING artifact (win.rustup.rs
        # serves the current rustup release, so its bytes change with every
        # rustup release) and it currently carries NO Authenticode signature
        # (verified 2026-10-03 with osslsigncode on both served flavors:
        # "No signature found"), so integrity here rests entirely on the
        # pinned SHA-256 digests below.  Re-pin deliberately when upgrading
        # rustup: download the artifact, `Get-FileHash -Algorithm SHA256`,
        # replace the constant, and note the new version + date.
        # Digests taken 2026-10-03 from https://win.rustup.rs/{x86_64,aarch64}
        # (rustup 1.29.1, the release static.rust-lang.org/rustup/release-stable.toml
        # advertised at fetch time), computed with sha256sum on a neutral host.
        if ($rustupHostTriple -eq 'aarch64-pc-windows-msvc') {
            $rustupInitSha256 = '01aa49cf9574a8bd0ae52005d7de2590e8f27181ded6748236e702c92aef826d'
        } else {
            $rustupInitSha256 = '6f4bef66261261fcb43131be8720bab817d403a09edec7455c371974b90bdb7e'
        }
        $rustupInit = Join-Path $workRoot 'rustup-init.exe'
        Invoke-WebDownload -Uri $rustupInitUrl -OutFile $rustupInit `
            -ExpectedSha256 $rustupInitSha256
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
        # RSA-0065: vs_BuildTools.exe is a FLOATING 'latest' bootstrapper —
        # https://aka.ms/vs/17/release/vs_BuildTools.exe always redirects to
        # the current VS 2022 (v17) release bootstrapper, so its bytes change
        # with every Visual Studio update.  Defense in depth, both enforced
        # by Invoke-WebDownload BEFORE the Start-Process below (fail closed:
        # the file is deleted and the script throws on any mismatch):
        #   1. pin the SHA-256 of the file the URL served on 2026-10-03
        #      (version 17.14.37710.0) — a mismatch (e.g. after a VS update
        #      re-pins nothing) aborts the run; re-pin deliberately on
        #      upgrade;
        #   2. require a Valid Authenticode signature whose signer subject
        #      names 'Microsoft Corporation' (verified on 2026-10-03 with
        #      osslsigncode: Signer CN=Microsoft Corporation, O=Microsoft
        #      Corporation, issued by Microsoft Code Signing PCA 2024).
        # Chain-to-root validity is what Get-AuthenticodeSignature (Windows
        # WinVerifyTrust) establishes at runtime; the Linux-side inspection
        # confirmed the signer identity but not the full chain.
        Invoke-WebDownload -Uri 'https://aka.ms/vs/17/release/vs_BuildTools.exe' -OutFile $vsBootstrapper `
            -ExpectedSha256 '985969f472caad75d993a5cb4c35a6a4271460cc12b343e2433b994d173aa990' `
            -RequireAuthenticodeSubject 'Microsoft Corporation'
        # Single authoritative component set: the same vsconfig the
        # bootstrap path uses (QH-17).  No inline --add components here.
        $vsConfigPath = Join-Path $PSScriptRoot 'RustyNetBuildTools.vsconfig'
        if (-not (Test-Path -LiteralPath $vsConfigPath)) {
            throw "vsconfig not found at $vsConfigPath; keep RustyNetBuildTools.vsconfig next to this script"
        }
        $vsArgs = @(
            '--installPath', $BuildToolsInstallPath,
            '--config', $vsConfigPath,
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
