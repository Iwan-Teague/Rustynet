<#
.SYNOPSIS
    Orchestrator-side wrapper that drives the reviewed Windows bootstrap
    (`scripts/bootstrap/windows/Bootstrap-RustyNetWindows.ps1`) from the
    cross-OS lab orchestrator (Phase 23).

.DESCRIPTION
    This script runs on the *target* Windows host. The orchestrator scp's
    it along with the source archive, then invokes it with the lab
    inputs. The wrapper:

      1. Validates every input against a strict allowlist (no shell
         construction with untrusted values).
      2. Extracts the source archive into the build directory
         (default: C:\Windows\Temp\rn_build).
      3. Invokes `Bootstrap-RustyNetWindows.ps1 -Phase install-release`
         from the extracted tree, supplying the orchestrator-provided
         service name and the per-node identifier.
      4. Polls for the RustyNet service to reach Running status (40 s
         × 1 s) so the next orchestrator stage (collect_pubkeys) does
         not race with the daemon's startup.

    Idempotency: every step is safe to re-run. The reviewed install
    helper stops a running service before replacing the binary,
    rotates trust evidence, then restarts; the wrapper itself wipes
    the build directory on each run so a fresh source tree always
    replaces the previous extraction.

    Fail-closed: `Set-StrictMode -Version Latest` plus
    `$ErrorActionPreference = 'Stop'` ensure any uncaught error
    aborts the wrapper. The trap below converts any thrown exception
    into a non-zero exit so the SSH invocation surfaces the failure
    to the orchestrator.

.PARAMETER NodeId
    Stable, per-node identifier (orchestrator-issued). Validated as
    `^[A-Za-z0-9._-]+$`, length ≤ 128.

.PARAMETER NetworkId
    Stable network identifier (orchestrator-issued). Validated as
    `^[A-Za-z0-9._-]+$`, length ≤ 128. Accepted for parity with the
    macOS/Linux wrappers; the Windows install helper threads this
    through to the daemon args env in a future revision.

.PARAMETER NodeRole
    Orchestrator role (`client | exit | entry | aux | extra |
    fifth_client`). Validated against an explicit allowlist. The
    Windows daemon currently advertises only `client` capabilities
    (see SecurityMinimumBar §6.D control 9); the wrapper preserves
    the orchestrator label for audit but the install helper itself
    does not branch on it yet.

.PARAMETER SshAllowCidrs
    Comma-separated CIDRs to allow through the SSH fail-open rule.
    Accepted for parity with the macOS/Linux wrappers; the Windows
    install helper does not currently apply a fail-closed-ssh-allow
    flag (no Windows-side firewall rule equivalent exists yet).

.PARAMETER SourceArchive
    Absolute path to the source archive scp'd by the orchestrator.

.PARAMETER BuildDir
    Absolute path to the per-run extraction directory.

.PARAMETER ServiceName
    Windows service name (Validated as `^[A-Za-z0-9_-]+$`, length ≤
    128 — matches the reviewed charset enforced by
    Install-RustyNetWindowsService.ps1::Test-RustyNetServiceName).
#>

#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$NodeId,
    [Parameter(Mandatory = $true)][string]$NetworkId,
    [Parameter(Mandatory = $true)][string]$NodeRole,
    [Parameter()][string]$SshAllowCidrs = '',
    [Parameter()][string]$SourceArchive = 'C:\Windows\Temp\rustynet_src.tar.gz',
    [Parameter()][string]$BuildDir = 'C:\Windows\Temp\rn_build',
    [Parameter()][string]$ServiceName = 'RustyNet',
    [Parameter()][int]$ServiceReadyTimeoutSecs = 40
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

trap {
    $detail = if ($_.Exception -and $_.Exception.Message) {
        $_.Exception.Message.Trim()
    } else {
        ($_ | Out-String).Trim()
    }
    if ([string]::IsNullOrEmpty($detail)) {
        $detail = 'rn_bootstrap_windows.ps1: unhandled exception'
    }
    Write-Error ("rn_bootstrap_windows.ps1: $detail")
    exit 1
}

# ── Input validation (strict allowlists) ─────────────────────────────────────
# Mirrors `Test-RustyNetNodeId` / `Test-RustyNetServiceName` in
# Install-RustyNetWindowsService.ps1. Reproduced here so the wrapper
# fails closed before scp'ing or running anything if the orchestrator
# threads in a malformed value.

function Assert-NonEmpty {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value
    )
    if ([string]::IsNullOrEmpty($Value)) {
        throw ('rn_bootstrap_windows.ps1: {0} must not be empty' -f $Label)
    }
}

function Assert-Identifier {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string]$Value
    )
    Assert-NonEmpty -Label $Label -Value $Value
    if ($Value.Length -gt 128) {
        throw ('rn_bootstrap_windows.ps1: {0} exceeds 128 chars' -f $Label)
    }
    if ($Value -notmatch '^[A-Za-z0-9._-]+$') {
        throw ('rn_bootstrap_windows.ps1: {0} must match ^[A-Za-z0-9._-]+$ (received: {1})' -f $Label, $Value)
    }
}

function Assert-ServiceName {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string]$Value
    )
    Assert-NonEmpty -Label $Label -Value $Value
    if ($Value.Length -gt 128) {
        throw ('rn_bootstrap_windows.ps1: {0} exceeds 128 chars' -f $Label)
    }
    if ($Value -notmatch '^[A-Za-z0-9_-]+$') {
        throw ('rn_bootstrap_windows.ps1: {0} must match ^[A-Za-z0-9_-]+$ (received: {1})' -f $Label, $Value)
    }
}

function Assert-NodeRole {
    param([Parameter(Mandatory = $true)][string]$Value)
    $allowed = @('client', 'exit', 'entry', 'aux', 'extra', 'fifth_client')
    if ($allowed -notcontains $Value) {
        throw ('rn_bootstrap_windows.ps1: -NodeRole must be one of {0} (received: {1})' -f
            ($allowed -join '|'), $Value)
    }
}

function Assert-SshAllowCidrs {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)
    if ([string]::IsNullOrEmpty($Value)) {
        return
    }
    if ($Value.Length -gt 1024) {
        throw 'rn_bootstrap_windows.ps1: -SshAllowCidrs exceeds 1024 chars'
    }
    if ($Value -notmatch '^[A-Fa-f0-9:./,]+$') {
        throw ('rn_bootstrap_windows.ps1: -SshAllowCidrs must contain only hex/colon/dot/slash/comma (received: {0})' -f $Value)
    }
}

function Assert-AbsolutePath {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string]$Value
    )
    Assert-NonEmpty -Label $Label -Value $Value
    if ($Value.Length -gt 260) {
        throw ('rn_bootstrap_windows.ps1: {0} exceeds 260 chars' -f $Label)
    }
    # Project style: write the `$null` literal on the LHS of the
    # equality check so an unset variable does not silently coerce to
    # `$null` under StrictMode.
    $isAbsolute = $false
    try {
        $isAbsolute = [System.IO.Path]::IsPathRooted($Value)
    } catch {
        throw ('rn_bootstrap_windows.ps1: {0} is not a valid path: {1}' -f $Label, $_.Exception.Message)
    }
    if (-not $isAbsolute) {
        throw ('rn_bootstrap_windows.ps1: {0} must be an absolute path (received: {1})' -f $Label, $Value)
    }
}

Assert-Identifier -Label '-NodeId' -Value $NodeId
Assert-Identifier -Label '-NetworkId' -Value $NetworkId
Assert-NodeRole -Value $NodeRole
Assert-SshAllowCidrs -Value $SshAllowCidrs
Assert-AbsolutePath -Label '-SourceArchive' -Value $SourceArchive
Assert-AbsolutePath -Label '-BuildDir' -Value $BuildDir
Assert-ServiceName -Label '-ServiceName' -Value $ServiceName

if ($ServiceReadyTimeoutSecs -lt 1 -or $ServiceReadyTimeoutSecs -gt 600) {
    throw ('rn_bootstrap_windows.ps1: -ServiceReadyTimeoutSecs must be in [1, 600] (received: {0})' -f $ServiceReadyTimeoutSecs)
}

# ── Source archive presence ─────────────────────────────────────────────────
if (-not (Test-Path -LiteralPath $SourceArchive)) {
    throw ('rn_bootstrap_windows.ps1: source archive missing at {0}' -f $SourceArchive)
}

# ── Extract source (always fresh) ───────────────────────────────────────────
# rm + mkdir is idempotent: every run starts from a clean $BuildDir so
# a stale build tree cannot mask a fresh source update. The reviewed
# Bootstrap-RustyNetWindows.ps1 wipes its own intermediate artifacts
# but does not own $BuildDir.
Write-Host ('rn_bootstrap_windows.ps1: extracting {0} -> {1}' -f $SourceArchive, $BuildDir)
if (Test-Path -LiteralPath $BuildDir) {
    Remove-Item -Recurse -Force -LiteralPath $BuildDir
}
New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null

# Windows 10+ ships `tar.exe` (BSD tar) in System32. Reject if missing
# so the wrapper fails fast rather than silently using a partial
# extract.
$tarExe = Get-Command 'tar.exe' -ErrorAction SilentlyContinue
if ($null -eq $tarExe) {
    throw 'rn_bootstrap_windows.ps1: tar.exe not found on PATH; Windows 10 1803+ is required'
}
& tar.exe -xzf $SourceArchive -C $BuildDir
if ($LASTEXITCODE -ne 0) {
    throw ('rn_bootstrap_windows.ps1: tar extraction failed with exit code {0}' -f $LASTEXITCODE)
}

# ── Locate the reviewed Bootstrap-RustyNetWindows.ps1 ───────────────────────
$bootstrapScript = Join-Path $BuildDir 'scripts\bootstrap\windows\Bootstrap-RustyNetWindows.ps1'
if (-not (Test-Path -LiteralPath $bootstrapScript)) {
    throw ('rn_bootstrap_windows.ps1: bootstrap script missing after extract: {0}' -f $bootstrapScript)
}
$installHelper = Join-Path $BuildDir 'scripts\bootstrap\windows\Install-RustyNetWindowsService.ps1'
if (-not (Test-Path -LiteralPath $installHelper)) {
    throw ('rn_bootstrap_windows.ps1: install helper missing after extract: {0}' -f $installHelper)
}

# ── Invoke the reviewed Windows bootstrap ───────────────────────────────────
# Bootstrap-RustyNetWindows.ps1 -Phase all drives the entire install
# lifecycle: prepare-transport, sync-source, build-release,
# install-release (which calls Install-RustyNetWindowsService.ps1 with
# the orchestrator's -NodeId), restart-runtime, verify-runtime.
#
# We pass `-SourceMode archive` and `-RustyNetRoot` so the source
# already extracted into $BuildDir is reused — without this the
# bootstrap would try to git-clone or download the source again.
#
# argv-only invocation: PowerShell binds each parameter through the
# named-arg surface (no string concatenation of operator-controlled
# values), so the daemon never sees a flattened command line.
$rustyNetRoot = $BuildDir
$installRoot = 'C:\Program Files\RustyNet'
$stateRoot = 'C:\ProgramData\RustyNet'

Write-Host ('rn_bootstrap_windows.ps1: invoking Bootstrap-RustyNetWindows.ps1 (NodeId={0}, NetworkId={1}, NodeRole={2}, ServiceName={3})' -f
    $NodeId, $NetworkId, $NodeRole, $ServiceName)

# The bootstrap entry point. Calling -Phase build-release +
# install-release directly (instead of -Phase all) so we skip
# prepare-transport (the orchestrator owns SSH) and sync-source (we
# already extracted the archive). The bootstrap then builds the
# binaries from $BuildDir and registers the service.
foreach ($phase in @('build-release', 'install-release')) {
    Write-Host ('rn_bootstrap_windows.ps1: phase={0}' -f $phase)
    & $bootstrapScript `
        -Phase $phase `
        -SourceMode archive `
        -RustyNetRoot $rustyNetRoot `
        -InstallRoot $installRoot `
        -StateRoot $stateRoot `
        -ServiceName $ServiceName
    if ($LASTEXITCODE -ne 0) {
        throw ('rn_bootstrap_windows.ps1: Bootstrap-RustyNetWindows.ps1 -Phase {0} failed with exit code {1}' -f
            $phase, $LASTEXITCODE)
    }
}

# Re-run install-release with -NodeId override (the Install helper's
# default is `windows-client-1`; the orchestrator-issued node id may
# differ). install-release is idempotent — re-running it stops the
# service, replaces binaries (no-op if unchanged), reregisters with
# the new daemon args env, then starts the service.
Write-Host ('rn_bootstrap_windows.ps1: install-release rerun with -NodeId={0}' -f $NodeId)
& $installHelper `
    -RustyNetRoot $rustyNetRoot `
    -InstallRoot $installRoot `
    -StateRoot $stateRoot `
    -ServiceName $ServiceName `
    -NodeId $NodeId
if ($LASTEXITCODE -ne 0) {
    throw ('rn_bootstrap_windows.ps1: Install-RustyNetWindowsService.ps1 rerun (NodeId={0}) failed with exit code {1}' -f
        $NodeId, $LASTEXITCODE)
}

# ── Poll for the RustyNet service to reach Running ──────────────────────────
# Mirrors the macOS wrapper's daemon-socket wait. The install helper
# starts the service before returning, but a freshly-installed daemon
# may still be initialising trust evidence + binding the privileged
# helper named pipe; the next orchestrator stage (collect_pubkeys)
# must not race with that.
Write-Host ('rn_bootstrap_windows.ps1: waiting for service {0} to reach Running ({1} s)' -f
    $ServiceName, $ServiceReadyTimeoutSecs)
$deadline = (Get-Date).AddSeconds($ServiceReadyTimeoutSecs)
while ((Get-Date) -lt $deadline) {
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($null -ne $svc -and $svc.Status -eq 'Running') {
        Write-Host ('rn_bootstrap_windows.ps1: service {0} is Running' -f $ServiceName)
        exit 0
    }
    Start-Sleep -Seconds 1
}
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($null -eq $svc) {
    throw ('rn_bootstrap_windows.ps1: service {0} not found after install completed' -f $ServiceName)
}
throw ('rn_bootstrap_windows.ps1: service {0} did not reach Running within {1} s (current status: {2})' -f
    $ServiceName, $ServiceReadyTimeoutSecs, $svc.Status)
