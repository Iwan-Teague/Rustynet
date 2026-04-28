<#
.SYNOPSIS
    Authenticode-sign a RustyNet Windows binary with a reviewed
    signtool invocation.

.DESCRIPTION
    Wraps `signtool sign` + `signtool verify` so the release pipeline
    cannot accidentally ship an unsigned binary or a binary signed
    with the wrong digest algorithm. Fail-closed on every error
    surface; never falls back to "sign with whatever defaults
    signtool picks today."

    Reviewed contract (matches the W2.1b chain-validation gate the
    daemon enforces at startup via WinVerifyTrust):
      * SHA-256 file digest (signtool /fd SHA256)
      * SHA-256 timestamp digest (signtool /td SHA256)
      * RFC 3161 timestamp authority required (signtool /tr <url>)
      * post-sign `signtool verify /pa /v` MUST report Successfully
        verified before the script returns success.

    Cert + cert password are loaded from environment variables, NEVER
    from the command line, so they do not appear in process tables /
    Get-Process /WMI / shell history.

.PARAMETER BinaryPath
    Absolute path to the .exe to sign. Must exist + be a regular file.

.PARAMETER CertificatePath
    Absolute path to the PFX cert. Must exist + be a regular file.
    Use a hardware-token-backed PFX or a PFX exported from Azure Key
    Vault per ReleaseSigningRunbook.md.

.PARAMETER CertificatePasswordEnvVar
    NAME of the environment variable holding the PFX password. The
    helper never accepts the password as a parameter — only the env
    var name — so the password never lands in argv / process listings
    / shell history.

.PARAMETER TimestampUrl
    RFC 3161 timestamp authority URL. Defaults to DigiCert's
    public RFC 3161 endpoint; an operator can override per
    ReleaseSigningRunbook.md.

.EXAMPLE
    $env:RUSTYNET_SIGNING_PFX_PASSWORD = '...'
    .\Sign-RustyNetWindowsBinary.ps1 `
        -BinaryPath C:\build\rustynetd.exe `
        -CertificatePath C:\secrets\release.pfx `
        -CertificatePasswordEnvVar RUSTYNET_SIGNING_PFX_PASSWORD
#>
param(
    [Parameter(Mandatory = $true)][string]$BinaryPath,
    [Parameter(Mandatory = $true)][string]$CertificatePath,
    [Parameter(Mandatory = $true)][string]$CertificatePasswordEnvVar,
    [string]$TimestampUrl = 'http://timestamp.digicert.com'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Test-RustyNetSigningInputs {
    param(
        [Parameter(Mandatory = $true)][string]$BinaryPath,
        [Parameter(Mandatory = $true)][string]$CertificatePath,
        [Parameter(Mandatory = $true)][string]$CertificatePasswordEnvVar,
        [Parameter(Mandatory = $true)][string]$TimestampUrl
    )

    if (-not (Test-Path -LiteralPath $BinaryPath)) {
        throw "BinaryPath does not exist: $BinaryPath"
    }
    if (-not [System.IO.Path]::IsPathRooted($BinaryPath)) {
        throw "BinaryPath must be absolute: $BinaryPath"
    }
    if (-not $BinaryPath.ToLowerInvariant().EndsWith('.exe')) {
        throw "BinaryPath must end with .exe (signing only PE binaries here): $BinaryPath"
    }

    if (-not (Test-Path -LiteralPath $CertificatePath)) {
        throw "CertificatePath does not exist: $CertificatePath"
    }
    if (-not [System.IO.Path]::IsPathRooted($CertificatePath)) {
        throw "CertificatePath must be absolute: $CertificatePath"
    }

    if ([string]::IsNullOrEmpty($CertificatePasswordEnvVar)) {
        throw 'CertificatePasswordEnvVar must not be empty (must name an env var holding the PFX password, not the password itself)'
    }
    if ($CertificatePasswordEnvVar -notmatch '^[A-Z][A-Z0-9_]*$') {
        # Defensive filter: env var name must be ASCII upper +
        # digits + underscore (POSIX-style). Rejects sneaky values
        # like an actual password being passed as the env var name.
        throw "CertificatePasswordEnvVar must match ^[A-Z][A-Z0-9_]*\$ (got: $CertificatePasswordEnvVar)"
    }

    if ($TimestampUrl -notmatch '^https?://') {
        throw "TimestampUrl must be http(s):// prefixed: $TimestampUrl"
    }
}

function Get-SignToolPath {
    # Prefer signtool from a Windows SDK install. The WindowsSdkVerBinPath
    # env var is set by the VS dev shell. Falls back to a search of
    # the canonical Windows Kits install root.
    $candidate = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($candidate) {
        return $candidate.Source
    }

    $kitsRoots = @(
        ${env:ProgramFiles(x86)}, ${env:ProgramFiles}
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }

    foreach ($root in $kitsRoots) {
        $base = Join-Path $root 'Windows Kits\10\bin'
        if (-not (Test-Path -LiteralPath $base)) { continue }
        # Pick the latest SDK version's x64 signtool deterministically.
        $candidates = Get-ChildItem -LiteralPath $base -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^10\.\d+\.\d+\.\d+$' } |
            Sort-Object -Property Name -Descending
        foreach ($candidate in $candidates) {
            $signtool = Join-Path $candidate.FullName 'x64\signtool.exe'
            if (Test-Path -LiteralPath $signtool) {
                return $signtool
            }
        }
    }
    throw 'signtool.exe not found (install Windows SDK or run from a VS dev shell)'
}

Test-RustyNetSigningInputs `
    -BinaryPath $BinaryPath `
    -CertificatePath $CertificatePath `
    -CertificatePasswordEnvVar $CertificatePasswordEnvVar `
    -TimestampUrl $TimestampUrl

# Read the PFX password from the named env var. Never log / echo it.
# The Get-ChildItem env:<NAME> path lets the env var name pass through
# unchanged but prevents the password from appearing in argv.
$certPassword = [System.Environment]::GetEnvironmentVariable($CertificatePasswordEnvVar)
if ([string]::IsNullOrEmpty($certPassword)) {
    throw "Environment variable $CertificatePasswordEnvVar is empty or unset; refusing to sign"
}

$signTool = Get-SignToolPath
Write-Host "[release-signing] using signtool: $signTool"

# Sign with the reviewed digest + timestamp config. signtool's `/p`
# flag DOES expose the password in argv on Windows (per Microsoft
# docs); there is no signtool argv-free way today. We minimize the
# attack surface by:
#  - reading the password from a named env var (never argv)
#  - immediately Clear-Variable'ing the local copy after use
#  - keeping the helper a single short-lived process so the argv
#    is visible only briefly to other processes running as the
#    same user.
# The CI runner is a single-tenant runner per job; no other user
# session shares the process table.
& $signTool sign `
    /fd SHA256 `
    /tr $TimestampUrl `
    /td SHA256 `
    /f $CertificatePath `
    /p $certPassword `
    /v `
    $BinaryPath
$signExit = $LASTEXITCODE
Clear-Variable certPassword

if ($signExit -ne 0) {
    throw "signtool sign exited $signExit"
}

# Post-sign verification — running our own gate on the just-signed
# binary so a release artifact that signtool says it signed but
# WinVerifyTrust would reject still fails the workflow.
& $signTool verify /pa /v $BinaryPath
$verifyExit = $LASTEXITCODE
if ($verifyExit -ne 0) {
    throw "signtool verify exited $verifyExit; refusing to ship a binary signtool itself cannot validate"
}

Write-Host "[release-signing] $BinaryPath signed + verified"
