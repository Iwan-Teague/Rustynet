#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Sign rustynetd.exe with a self-signed Authenticode certificate for lab use.

.DESCRIPTION
    Creates a self-signed code-signing certificate in LocalMachine\My, imports
    the CA into LocalMachine\Root so WinVerifyTrust returns Verified, and signs
    the installed rustynetd.exe binary. Intended for dev/lab builds only.

    The certificate is keyed with RSA-2048, SHA-256 digest, valid for 365 days.
    Re-running is idempotent: existing certs with the same subject are reused if
    still valid (>30 days remaining), otherwise a fresh one is created.

    After signing, `windows-authenticode-check` will return overall_ok=true and
    the orchestrator's validate_windows_authenticode stage will pass without
    --no-fail-on-authenticode.

.PARAMETER BinaryPath
    Path to the binary to sign. Defaults to the reviewed install path.

.PARAMETER CertSubject
    CN of the self-signed cert. Defaults to "RustyNet Lab Dev".

.EXAMPLE
    .\Sign-RustyNetDevBuild.ps1
    .\Sign-RustyNetDevBuild.ps1 -BinaryPath "C:\custom\rustynetd.exe"
#>
param(
    [string]$BinaryPath = "C:\Program Files\RustyNet\rustynetd.exe",
    [string]$CertSubject = "RustyNet Lab Dev"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step([string]$msg) { Write-Host "[sign] $msg" }

# --- 1. Locate or create the self-signed cert ---
$existingCerts = @(Get-ChildItem Cert:\LocalMachine\My |
    Where-Object {
        $_.Subject -eq "CN=$CertSubject" -and
        $_.NotAfter -gt (Get-Date).AddDays(30) -and
        $_.HasPrivateKey
    })

if ($existingCerts.Count -gt 0) {
    $cert = $existingCerts[0]
    Write-Step "Reusing existing cert: thumbprint=$($cert.Thumbprint) expires=$($cert.NotAfter)"
} else {
    Write-Step "Creating self-signed code-signing cert (CN=$CertSubject)"
    $cert = New-SelfSignedCertificate `
        -Subject "CN=$CertSubject" `
        -CertStoreLocation "Cert:\LocalMachine\My" `
        -KeySpec Signature `
        -KeyAlgorithm RSA `
        -KeyLength 2048 `
        -HashAlgorithm SHA256 `
        -Type CodeSigningCert `
        -NotAfter (Get-Date).AddDays(365)
    Write-Step "Created cert: thumbprint=$($cert.Thumbprint)"
}

# --- 2. Trust the cert so WinVerifyTrust returns Verified ---
$rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store(
    "Root", "LocalMachine"
)
$rootStore.Open("ReadWrite")
$alreadyTrusted = @($rootStore.Certificates | Where-Object {
    $_.Thumbprint -eq $cert.Thumbprint
})
if ($alreadyTrusted.Count -eq 0) {
    Write-Step "Adding cert to LocalMachine\Root so WinVerifyTrust accepts it"
    $rootStore.Add($cert)
} else {
    Write-Step "Cert already in LocalMachine\Root"
}
$rootStore.Close()

# --- 3. Sign the binary ---
if (-not (Test-Path $BinaryPath)) {
    Write-Error "Binary not found at: $BinaryPath"
    exit 1
}

Write-Step "Signing: $BinaryPath"
$result = Set-AuthenticodeSignature `
    -FilePath $BinaryPath `
    -Certificate $cert `
    -HashAlgorithm SHA256 `
    -TimestampServer $null `
    -Force

if ($result.Status -ne "Valid") {
    Write-Error "Set-AuthenticodeSignature failed: status=$($result.Status) message=$($result.StatusMessage)"
    exit 1
}

Write-Step "Signed OK: status=$($result.Status)"

# --- 4. Verify with Get-AuthenticodeSignature ---
$verify = Get-AuthenticodeSignature -FilePath $BinaryPath
Write-Step "Verification: status=$($verify.Status) signer='$($verify.SignerCertificate.Subject)'"

if ($verify.Status -ne "Valid") {
    Write-Error "Post-sign verification failed: $($verify.StatusMessage)"
    exit 1
}

Write-Host ""
Write-Host "Done. rustynetd.exe is now Authenticode-signed."
Write-Host "Run: rustynetd windows-authenticode-check"
Write-Host "Expected: overall_ok=true, chain_status=Verified"
