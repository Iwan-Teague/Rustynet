#requires -Version 5.1
<#
.SYNOPSIS
    Reconfigure the installed RustyNet Windows daemon service to ALSO serve the
    anchor bundle-pull loopback listener, with a fail-closed verify-before-serve
    gate.

.DESCRIPTION
    This is the Windows analogue of the macOS `deploy_macos_anchor_profile`
    helper (crates/rustynet-cli/src/vm_lab/mod.rs). It is the dedicated,
    reviewable installer the LIVE `validate_windows_anchor_bundle_pull` vm_lab
    stage drives.

    The anchor bundle-pull listener is a security boundary: it MUST bind
    loopback only (127.0.0.1:51822), MUST deny LAN binds
    (--anchor-bundle-pull-allow-lan false), and MUST reference a present,
    non-empty authority token whose owning node holds the `anchor.bundle_pull`
    membership capability. The daemon itself re-enforces every one of these at
    startup (validate_anchor_bundle_pull_addr / load_anchor_bundle_pull_token /
    snapshot_bytes_have_bundle_pull_capability), so this script is a
    defence-in-depth front gate: it REFUSES to mutate the service env-file and
    REFUSES to start when any reviewed invariant drifts.

    What it does, in order:
      1. Mint a self-contained genesis membership snapshot at the canonical
         Windows membership path whose single (genesis) node is THIS node and
         which therefore holds the full anchor capability set (including
         AnchorBundlePull) — so the daemon serves the loopback pull instead of
         returning "ERR forbidden after revocation". This mirrors the macOS
         elected-anchor path, which has `anchor.bundle_pull` in the snapshot the
         daemon serves before the anchor profile is deployed.
      2. Seed a 32-byte (64 hex char) authority token at the reviewed token path
         with a restrictive ACL, preserving any existing token content so peers
         that already hold it stay authorised.
      3. Append ONLY the three reviewed bundle-pull flags to the service's
         RUSTYNETD_DAEMON_ARGS_JSON in the reviewed env-file:
             --anchor-bundle-pull-addr 127.0.0.1:51822
             --anchor-bundle-pull-token-path <reviewed token path>
             --anchor-bundle-pull-allow-lan false
      4. VERIFY-BEFORE-SERVE: re-parse the resulting daemon-args JSON and assert
         the bind addr is exactly the reviewed loopback addr, allow-lan is
         exactly false, and the token path is present and non-empty BEFORE
         restarting the service. Any drift => throw, no restart.
      5. Restart the service and poll the loopback listener up to ~20 times.

    The script writes NOTHING outside the reviewed RustyNet roots and never
    constructs a shell command from untrusted input.

.PARAMETER NodeId
    The mesh node id of this Windows host (validated mesh id).

.PARAMETER ReportPath
    Optional. When set, a structured JSON evidence report is written here.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $NodeId,

    [Parameter(Mandatory = $false)]
    [string] $ReportPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Reviewed constants (mirror the rustynetd Windows path + bundle-pull
#    constants; loopback-only + LAN-deny is a security boundary). ──────────────
$ReviewedServiceName     = 'RustyNet'
$ReviewedInstallRoot     = 'C:\Program Files\RustyNet'
$ReviewedDaemonExe       = 'C:\Program Files\RustyNet\rustynetd.exe'
$ReviewedEnvFile         = 'C:\ProgramData\RustyNet\config\rustynetd.env'
$ReviewedMembershipRoot  = 'C:\ProgramData\RustyNet\membership'
$ReviewedSnapshotPath    = 'C:\ProgramData\RustyNet\membership\membership.snapshot'
$ReviewedLogPath         = 'C:\ProgramData\RustyNet\membership\membership.log'
$ReviewedWatermarkPath   = 'C:\ProgramData\RustyNet\membership\membership.watermark'
$ReviewedOwnerKeyPath    = 'C:\ProgramData\RustyNet\membership\membership.owner.key'
$ReviewedTokenPath       = 'C:\ProgramData\RustyNet\config\anchor-bundle-pull.token'
$ReviewedBundlePullAddr  = '127.0.0.1:51822'
$ReviewedAllowLan        = 'false'
$ReviewedBundlePullPort  = 51822
$DaemonArgsEnvName       = 'RUSTYNETD_DAEMON_ARGS_JSON'
$NetworkId               = 'windows-anchor-local'

function Test-ReviewedAnchorServiceName {
    param([string] $Value)
    if ($Value -ne $ReviewedServiceName) {
        throw "anchor service name must be $ReviewedServiceName; found $Value"
    }
}

function Test-MeshNodeId {
    param([string] $Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { throw 'node id must not be empty' }
    if ($Value.Length -gt 128) { throw 'node id too long' }
    foreach ($ch in $Value.ToCharArray()) {
        $isAllowed = ($ch -ge 'a' -and $ch -le 'z') -or `
                     ($ch -ge 'A' -and $ch -le 'Z') -or `
                     ($ch -ge '0' -and $ch -le '9') -or `
                     ($ch -eq '-') -or ($ch -eq '_') -or ($ch -eq '.')
        if (-not $isAllowed) {
            throw "node id must be ASCII alphanumeric + [-_.]: $Value"
        }
    }
}

function Test-ReviewedDaemonExe {
    if (-not (Test-Path -LiteralPath $ReviewedDaemonExe)) {
        throw "reviewed daemon binary missing at $ReviewedDaemonExe"
    }
}

# Verify-before-serve: assert the reviewed bundle-pull posture on a daemon-args
# array (loopback addr + allow-lan=false + present token-path) BEFORE the
# service is (re)started. Fail closed on any drift.
function Assert-ReviewedBundlePullArgs {
    param([string[]] $Args)
    $addr = $null; $allowLan = $null; $tokenPath = $null
    for ($i = 0; $i -lt $Args.Count; $i++) {
        switch ($Args[$i]) {
            '--anchor-bundle-pull-addr'       { $addr      = $Args[$i + 1] }
            '--anchor-bundle-pull-allow-lan'  { $allowLan  = $Args[$i + 1] }
            '--anchor-bundle-pull-token-path' { $tokenPath = $Args[$i + 1] }
        }
    }
    if ($addr -ne $ReviewedBundlePullAddr) {
        throw "anchor verify-before-serve failed: addr=$addr (expected loopback $ReviewedBundlePullAddr)"
    }
    if ($allowLan -ne $ReviewedAllowLan) {
        throw "anchor verify-before-serve failed: allow_lan=$allowLan (expected deny-LAN $ReviewedAllowLan)"
    }
    if ([string]::IsNullOrWhiteSpace($tokenPath)) {
        throw 'anchor verify-before-serve failed: token-path missing'
    }
    if ($tokenPath -ne $ReviewedTokenPath) {
        throw "anchor verify-before-serve failed: token-path=$tokenPath (expected $ReviewedTokenPath)"
    }
}

Test-ReviewedAnchorServiceName -Value $ReviewedServiceName
Test-MeshNodeId -Value $NodeId
Test-ReviewedDaemonExe

# ── Step 1: mint a self-contained genesis membership snapshot whose genesis
#    node is THIS node (gets the full anchor capability set incl.
#    AnchorBundlePull). `membership init` is fail-closed and signs internally. ──
New-Item -ItemType Directory -Force -Path $ReviewedMembershipRoot | Out-Null
$passFile = Join-Path $env:TEMP ('rn-anchor-pass-' + [guid]::NewGuid().ToString('N'))
[IO.File]::WriteAllText(
    $passFile,
    ([guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N')))
try {
    & $ReviewedDaemonExe membership init `
        --snapshot $ReviewedSnapshotPath `
        --log $ReviewedLogPath `
        --watermark $ReviewedWatermarkPath `
        --owner-signing-key $ReviewedOwnerKeyPath `
        --owner-signing-key-passphrase-file $passFile `
        --node-id $NodeId `
        --network-id $NetworkId `
        --force
    if ($LASTEXITCODE -ne 0) { throw "membership init failed (exit $LASTEXITCODE)" }
}
finally {
    if (Test-Path -LiteralPath $passFile) { Remove-Item -Force -LiteralPath $passFile }
}
if (-not (Test-Path -LiteralPath $ReviewedSnapshotPath)) {
    throw "membership init did not produce snapshot at $ReviewedSnapshotPath"
}

# ── Step 2: seed the authority token (preserve existing content; lock ACL). ──
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $ReviewedTokenPath) | Out-Null
if (-not (Test-Path -LiteralPath $ReviewedTokenPath)) {
    $bytes = New-Object 'System.Byte[]' 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $token = -join ($bytes | ForEach-Object { $_.ToString('x2') })
    [IO.File]::WriteAllText($ReviewedTokenPath, $token)
}
# Lock the token ACL to SYSTEM + Administrators only (no inheritance).
$acl = New-Object System.Security.AccessControl.FileSecurity
$acl.SetAccessRuleProtection($true, $false)
foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
    $id = New-Object System.Security.Principal.SecurityIdentifier($sid)
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $id, 'FullControl', 'Allow')
    $acl.AddAccessRule($rule)
}
Set-Acl -LiteralPath $ReviewedTokenPath -AclObject $acl
$tokenContent = (Get-Content -LiteralPath $ReviewedTokenPath -Raw).Trim()
if ($tokenContent.Length -lt 32) {
    throw 'seeded anchor bundle-pull token is shorter than 32 bytes (daemon would fail closed)'
}

# ── Step 3: append ONLY the bundle-pull flags to the service daemon-args. ──
if (-not (Test-Path -LiteralPath $ReviewedEnvFile)) {
    throw "reviewed env-file missing at $ReviewedEnvFile"
}
$envLines = Get-Content -LiteralPath $ReviewedEnvFile
$argsLine = $envLines | Where-Object { $_ -like "$DaemonArgsEnvName=*" } | Select-Object -First 1
if (-not $argsLine) {
    throw "$DaemonArgsEnvName not present in env-file; refuse to synthesize daemon args"
}
$jsonValue = $argsLine.Substring($DaemonArgsEnvName.Length + 1)
$daemonArgs = @($jsonValue | ConvertFrom-Json)
# Strip any pre-existing bundle-pull triplet so re-runs are idempotent.
$filtered = New-Object 'System.Collections.Generic.List[string]'
for ($i = 0; $i -lt $daemonArgs.Count; $i++) {
    $a = $daemonArgs[$i]
    if ($a -in @('--anchor-bundle-pull-addr', '--anchor-bundle-pull-token-path', '--anchor-bundle-pull-allow-lan')) {
        $i++  # skip the flag and its value
        continue
    }
    $filtered.Add([string]$a)
}
$filtered.Add('--anchor-bundle-pull-addr');       $filtered.Add($ReviewedBundlePullAddr)
$filtered.Add('--anchor-bundle-pull-token-path'); $filtered.Add($ReviewedTokenPath)
$filtered.Add('--anchor-bundle-pull-allow-lan');  $filtered.Add($ReviewedAllowLan)
$newArgs = $filtered.ToArray()

# ── Step 4: VERIFY-BEFORE-SERVE — assert reviewed posture before any restart. ──
Assert-ReviewedBundlePullArgs -Args $newArgs

# Re-serialize as a compact JSON array (daemon parses serde_json string array).
$newJson = ConvertTo-Json -InputObject $newArgs -Compress
$rewritten = $envLines | ForEach-Object {
    if ($_ -like "$DaemonArgsEnvName=*") { "$DaemonArgsEnvName=$newJson" } else { $_ }
}
Set-Content -LiteralPath $ReviewedEnvFile -Value $rewritten -Encoding ascii

# ── Step 5: restart the service and poll the loopback listener. ──
$svc = Get-Service -Name $ReviewedServiceName -ErrorAction Stop
if ($svc.Status -eq 'Running') {
    & sc.exe stop $ReviewedServiceName | Out-Null
    Start-Sleep -Seconds 2
}
& sc.exe start $ReviewedServiceName | Out-Null

$listenerUp = $false
for ($attempt = 0; $attempt -lt 20; $attempt++) {
    $conns = Get-NetTCPConnection -State Listen -LocalPort $ReviewedBundlePullPort -ErrorAction SilentlyContinue
    if ($conns) {
        foreach ($c in $conns) {
            if ($c.LocalAddress -eq '127.0.0.1' -or $c.LocalAddress -eq '::1') {
                $listenerUp = $true; break
            }
        }
    }
    if ($listenerUp) { break }
    Start-Sleep -Seconds 2
}
if (-not $listenerUp) {
    throw "anchor bundle-pull listener did not come up on $ReviewedBundlePullAddr"
}

$result = [ordered]@{
    schema_version          = 1
    stage                   = 'deploy_windows_anchor_service'
    status                  = 'pass'
    node_id                 = $NodeId
    bundle_pull_addr        = $ReviewedBundlePullAddr
    allow_lan               = $ReviewedAllowLan
    token_path              = $ReviewedTokenPath
    snapshot_path           = $ReviewedSnapshotPath
    verify_before_serve     = 'asserted'
    listener_up             = $true
}
if ($ReportPath) {
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $ReportPath) | Out-Null
    ($result | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath $ReportPath -Encoding ascii
}
Write-Output ($result | ConvertTo-Json -Depth 8 -Compress)
