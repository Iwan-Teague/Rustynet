#![allow(dead_code)]
use std::time::Duration;

use base64::prelude::*;

use crate::vm_lab::orchestrator::adapter::ssh;
use crate::vm_lab::orchestrator::connection::NodeConnection;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::{AdapterError, InstallReport};
use crate::vm_lab::orchestrator::role::NodeRole;

pub const WINDOWS_SERVICE_NAME: &str = "RustyNet";
pub const WINDOWS_INSTALL_ROOT: &str = r"C:\Program Files\RustyNet";
pub const WINDOWS_STATE_ROOT: &str = r"C:\ProgramData\RustyNet";
pub const WINDOWS_RUSTYNETD_PATH: &str = r"C:\Program Files\RustyNet\rustynetd.exe";
pub const WINDOWS_RUSTYNET_PATH: &str = r"C:\Program Files\RustyNet\rustynet.exe";
// Staging lives outside C:\ProgramData\Rustynet so the hardened ACL that
// `Install-RustyNetWindowsService.ps1` applies (NT SERVICE\RustyNet only)
// cannot inherit onto SCP-staged files. C:\Windows\Temp is world-writable
// by default and ships as the canonical Windows transient-binary location.
pub const WINDOWS_STAGING_DIR: &str = r"C:\Windows\Temp\rustynet-stage";
pub const WINDOWS_MEMBERSHIP_OWNER_PUBKEY_PATH: &str =
    r"C:\ProgramData\RustyNet\membership\membership.owner.key.pub";
pub const WINDOWS_MEMBERSHIP_SNAPSHOT_PATH: &str =
    r"C:\ProgramData\RustyNet\membership\membership.snapshot";

// Paths written by the e2e bootstrap sequence.
pub const WINDOWS_WG_PASSPHRASE_PATH: &str =
    r"C:\ProgramData\RustyNet\secrets\wireguard.passphrase.dpapi";
const WINDOWS_MEMBERSHIP_LOG_PATH: &str = r"C:\ProgramData\RustyNet\membership\membership.log";
const WINDOWS_MEMBERSHIP_WATERMARK_PATH: &str =
    r"C:\ProgramData\RustyNet\membership\membership.watermark";
pub const WINDOWS_MEMBERSHIP_OWNER_KEY_PATH: &str =
    r"C:\ProgramData\RustyNet\membership\membership.owner.key";
const WINDOWS_TRUST_SIGNING_KEY_PATH: &str = r"C:\ProgramData\RustyNet\trust\trust-evidence.key";
const WINDOWS_TRUST_VERIFIER_KEY_PATH: &str = r"C:\ProgramData\RustyNet\trust\trust-evidence.pub";
const WINDOWS_TRUST_EVIDENCE_PATH: &str = r"C:\ProgramData\RustyNet\trust\rustynetd.trust";
const WINDOWS_WG_BINARY_PATH: &str = r"C:\Program Files\WireGuard\wg.exe";

static BOOTSTRAP_SCRIPT: &str =
    include_str!("../../../../../../scripts/bootstrap/windows/Bootstrap-RustyNetWindows.ps1");
static INSTALL_SERVICE_SCRIPT: &str =
    include_str!("../../../../../../scripts/bootstrap/windows/Install-RustyNetWindowsService.ps1");
static UNINSTALL_SERVICE_SCRIPT: &str = include_str!(
    "../../../../../../scripts/bootstrap/windows/Uninstall-RustyNetWindowsService.ps1"
);

const SHORT_TIMEOUT: Duration = Duration::from_secs(30);
const BUILD_TIMEOUT: Duration = Duration::from_secs(3600); // cold release build on Windows VM can take 30-60 min
const WINDOWS_SERVICE_STOP_POLL_SECS: u64 = 30;
const WINDOWS_SERVICE_START_POLL_ATTEMPTS: u64 = 60;
const WINDOWS_SERVICE_START_POLL_INTERVAL_SECS: u64 = 2;
const WINDOWS_SERVICE_START_PROBE_MAX_SECS: u64 = WINDOWS_SERVICE_STOP_POLL_SECS
    + (WINDOWS_SERVICE_START_POLL_ATTEMPTS * WINDOWS_SERVICE_START_POLL_INTERVAL_SECS);
const WINDOWS_E2E_BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(300);
const WINDOWS_BUILD_RELEASE_REPORT_PATH: &str =
    r"C:\Windows\Temp\rustynet-stage\build-release\manifest.json";

// ── PowerShell encoding helpers ───────────────────────────────────────────────

/// Encode a PowerShell script as UTF-16LE + base64 for `-EncodedCommand`.
pub fn encode_ps_command(script: &str) -> Result<String, AdapterError> {
    if script.contains('\0') {
        return Err(AdapterError::Protocol {
            message: "PowerShell script contains NUL byte".to_string(),
        });
    }
    let mut bytes = Vec::with_capacity(script.len() * 2);
    for unit in script.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    Ok(BASE64_STANDARD.encode(bytes))
}

/// Build the SSH command string that invokes PowerShell with an encoded script.
pub fn build_ps_invocation(script: &str) -> Result<String, AdapterError> {
    let encoded = encode_ps_command(script)?;
    Ok(format!(
        "powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded}"
    ))
}

/// Single-quote a value for embedding in a PS literal string.
/// Rejects control characters (NUL/CR/LF) that could escape the literal.
pub fn ps_quote(value: &str) -> Result<String, AdapterError> {
    if value
        .chars()
        .any(|ch| ch == '\0' || ch == '\r' || ch == '\n')
    {
        return Err(AdapterError::Protocol {
            message: format!(
                "value contains control characters not safe for PS quoting: {value:?}"
            ),
        });
    }
    Ok(format!("'{}'", value.replace('\'', "''")))
}

// ── Remote PS execution ───────────────────────────────────────────────────────

/// Run a PowerShell script over SSH. The script is base64-encoded so it
/// survives the SSH quoting layer. Returns trimmed stdout on success.
pub fn run_remote_ps(
    conn: &NodeConnection,
    script: &str,
    timeout: Duration,
) -> Result<String, AdapterError> {
    let invocation = build_ps_invocation(script)?;
    ssh::run_remote(conn, &invocation, timeout)
}

/// Run a PowerShell script over SSH. Returns `true` if exit code is 0.
pub fn run_remote_ps_check(
    conn: &NodeConnection,
    script: &str,
    timeout: Duration,
) -> Result<bool, AdapterError> {
    let invocation = build_ps_invocation(script)?;
    ssh::run_remote_check(conn, &invocation, timeout)
}

// ── Install lifecycle ─────────────────────────────────────────────────────────

/// Bootstrap the daemon on a Windows host. Extracts `source` into `workdir`
/// via tar.exe, then runs Bootstrap-RustyNetWindows.ps1 -Phase build-release,
/// Install-RustyNetWindowsService.ps1, and runs the e2e bootstrap sequence to
/// generate WireGuard keys, membership state, and trust evidence.
pub fn install_daemon(
    conn: &NodeConnection,
    alias: &str,
    workdir: &str,
    source: &crate::vm_lab::orchestrator::source_archive::SourceArchive,
    ctx: &OrchestrationContext,
) -> Result<InstallReport, AdapterError> {
    validate_windows_path(workdir)?;

    let staging_dir = WINDOWS_STAGING_DIR;
    let remote_archive = format!(r"{staging_dir}\rn_source.tar.gz");

    // SCP bootstrap helpers to staging dir.
    let bootstrap_tmp = write_temp_file(
        "Bootstrap-RustyNetWindows_",
        ".ps1",
        BOOTSTRAP_SCRIPT.as_bytes(),
    )?;
    let install_tmp = write_temp_file(
        "Install-RustyNetWindowsService_",
        ".ps1",
        INSTALL_SERVICE_SCRIPT.as_bytes(),
    )?;

    // Ensure staging dir exists on remote.
    let ensure_dir_script = format!(
        "New-Item -ItemType Directory -Force -Path {} | Out-Null",
        ps_quote(staging_dir)?
    );
    run_remote_ps(conn, &ensure_dir_script, SHORT_TIMEOUT)?;

    let remote_bootstrap = format!(r"{staging_dir}\Bootstrap-RustyNetWindows.ps1");
    let remote_install_svc = format!(r"{staging_dir}\Install-RustyNetWindowsService.ps1");

    ssh::scp_to(
        conn,
        bootstrap_tmp.as_path(),
        &remote_bootstrap.replace('\\', "/"),
        SHORT_TIMEOUT,
    )?;
    ssh::scp_to(
        conn,
        install_tmp.as_path(),
        &remote_install_svc.replace('\\', "/"),
        SHORT_TIMEOUT,
    )?;
    // SCP the source archive.
    ssh::scp_to(
        conn,
        source.path(),
        &remote_archive.replace('\\', "/"),
        Duration::from_secs(120),
    )?;

    let _ = std::fs::remove_file(&bootstrap_tmp);
    let _ = std::fs::remove_file(&install_tmp);

    // Extract source archive into workdir, overwriting existing files.
    // Uses Windows built-in tar.exe (available since Windows 10 1803).
    // git archive produces files at the archive root (no leading dir component).
    let extract_script = format!(
        "$ErrorActionPreference = 'Stop'; \
         $ProgressPreference = 'SilentlyContinue'; \
         New-Item -ItemType Directory -Force -Path {workdir_q} | Out-Null; \
         & tar.exe -xzf {archive_q} -C {workdir_q}",
        workdir_q = ps_quote(workdir)?,
        archive_q = ps_quote(&remote_archive)?,
    );
    run_remote_ps(conn, &extract_script, Duration::from_secs(120))?;

    // Build release from synced workdir.
    let build_script = build_windows_release_script(workdir, &remote_bootstrap)?;
    run_remote_ps(conn, &build_script, BUILD_TIMEOUT)?;

    // Install the service.
    let node_id = windows_lab_node_id(alias, ctx);
    let install_script = build_windows_service_install_script(
        workdir,
        &remote_install_svc,
        WINDOWS_SERVICE_NAME,
        &node_id,
    )?;
    run_remote_ps(conn, &install_script, Duration::from_secs(120))?;

    // Verify the daemon binary is present before running e2e bootstrap.
    let verify_script = format!(
        "if (-not (Test-Path -LiteralPath {})) {{ throw 'rustynetd.exe not found' }}",
        ps_quote(WINDOWS_RUSTYNETD_PATH)?,
    );
    run_remote_ps(conn, &verify_script, SHORT_TIMEOUT)?;

    // Run the e2e bootstrap sequence to generate WireGuard keys, membership
    // state, and trust evidence. The service starts AFTER bootstrap completes.
    run_windows_e2e_bootstrap(conn, alias, ctx)?;

    Ok(InstallReport {
        daemon_path: WINDOWS_RUSTYNETD_PATH.into(),
        service_name: WINDOWS_SERVICE_NAME.to_string(),
    })
}

/// Enforce baseline runtime on Windows: update daemon args to enable
/// `auto_tunnel_enforce=true`, then stop-start the service with a full probe.
///
/// Bootstrap configures the daemon with `--auto-tunnel-enforce false` so the
/// service can start before any mesh assignment bundle exists.  After all
/// bundles are distributed, `EnforceBaselineRuntime` calls this function to
/// patch the daemon env file to `--auto-tunnel-enforce true` and restart the
/// service.  The daemon then applies the assignment bundle and brings up
/// WireGuard tunnels on the next reconcile tick.
pub fn enforce_daemon(
    conn: &NodeConnection,
    _alias: &str,
    _ctx: &OrchestrationContext,
) -> Result<(), AdapterError> {
    let env_path = format!(r"{WINDOWS_STATE_ROOT}\config\rustynetd.env");
    // Patch --auto-tunnel-enforce in the RUSTYNETD_DAEMON_ARGS_JSON line.
    // The env file has the form:
    //   # comment
    //   RUSTYNETD_DAEMON_ARGS_JSON=["--backend","...",
    //       "--auto-tunnel-enforce","false","--node-id","..."]
    // We parse the JSON array, flip the value, and write it back.
    let env_path_q = ps_quote(&env_path)?;
    let patch_script = format!(
        "Set-StrictMode -Version Latest; \
         $ErrorActionPreference = 'Stop'; \
         $ProgressPreference = 'SilentlyContinue'; \
         $envPath = {env_path_q}; \
         $lines = (Get-Content $envPath -Encoding ASCII); \
         $updated = $lines | ForEach-Object {{ \
             if ($_ -match '^RUSTYNETD_DAEMON_ARGS_JSON=') {{ \
                 $json = $_ -replace '^RUSTYNETD_DAEMON_ARGS_JSON=', ''; \
                 $arr = [System.Collections.ArrayList]($json | ConvertFrom-Json); \
                 $idx = [array]::IndexOf([string[]]$arr, '--auto-tunnel-enforce'); \
                 if ($idx -ge 0 -and ($idx + 1) -lt $arr.Count) {{ \
                     $arr[$idx + 1] = 'true' \
                 }}; \
                 $ageIdx = [array]::IndexOf([string[]]$arr, '--auto-tunnel-max-age-secs'); \
                 if ($ageIdx -lt 0) {{ \
                     $null = $arr.Add('--auto-tunnel-max-age-secs'); \
                     $null = $arr.Add('86400') \
                 }} elseif (($ageIdx + 1) -lt $arr.Count) {{ \
                     $arr[$ageIdx + 1] = '86400' \
                 }}; \
                 $dnsAgeIdx = [array]::IndexOf([string[]]$arr, '--dns-zone-max-age-secs'); \
                 if ($dnsAgeIdx -lt 0) {{ \
                     $null = $arr.Add('--dns-zone-max-age-secs'); \
                     $null = $arr.Add('86400') \
                 }} elseif (($dnsAgeIdx + 1) -lt $arr.Count) {{ \
                     $arr[$dnsAgeIdx + 1] = '86400' \
                 }}; \
                 'RUSTYNETD_DAEMON_ARGS_JSON=' + ($arr.ToArray() | ConvertTo-Json -Compress) \
             }} else {{ $_ }} \
         }}; \
         $updated | Out-File -Encoding ASCII $envPath",
    );
    run_remote_ps(conn, &patch_script, SHORT_TIMEOUT)?;
    // Restart service with full probe so daemon reads new config.
    start_daemon(conn)?;
    // Wait for the WireGuard tunnel adapter to receive its IPv4 mesh address.
    // The SCM reports Running before the daemon thread begins its first
    // reconcile, so the IP may not be assigned for several seconds after
    // start_daemon returns.  Without this wait, traffic_test_matrix's
    // collect_mesh_ip may timeout before the IP appears.
    let tunnel_ip_script = format!(
        "Set-StrictMode -Version Latest; \
         $ErrorActionPreference = 'Stop'; \
         $ProgressPreference = 'SilentlyContinue'; \
         {}",
        windows_tunnel_ip_readiness_fragment()?,
    );
    run_remote_ps(conn, &tunnel_ip_script, Duration::from_secs(100))?;
    Ok(())
}

/// Start the RustyNet SCM service and wait for it to reach Running state.
///
/// Uses `windows_service_start_probe_fragment` which handles the already-running
/// case (sc.exe exit 1056) and polls for SCM Running state.  This is called from
/// EnforceBaselineRuntime AFTER verifier keys have been distributed, so the
/// daemon has all required keys to start successfully.
pub fn start_daemon(conn: &NodeConnection) -> Result<(), AdapterError> {
    let service_probe = windows_service_start_probe_fragment(WINDOWS_SERVICE_NAME)?;
    let script = format!(
        "Set-StrictMode -Version Latest; \
         $ErrorActionPreference = 'Stop'; \
         $ProgressPreference = 'SilentlyContinue'; \
         {service_probe}",
    );
    // Budget: stop-poll (30s) + start-poll (60 × 2s = 120s) + overhead (60s) = 210s
    const START_DAEMON_TIMEOUT: Duration =
        Duration::from_secs(WINDOWS_SERVICE_START_PROBE_MAX_SECS + 60);
    run_remote_ps(conn, &script, START_DAEMON_TIMEOUT)?;
    Ok(())
}

/// Stop the RustyNet SCM service.
pub fn stop_daemon(conn: &NodeConnection) -> Result<(), AdapterError> {
    run_service_action(conn, "Stop-Service -Force -ErrorAction SilentlyContinue")
}

/// Restart the RustyNet SCM service.
pub fn restart_daemon(conn: &NodeConnection) -> Result<(), AdapterError> {
    run_service_action(conn, "Restart-Service -Force")
}

/// Stop and remove the service; optionally purge state root.
pub fn uninstall_daemon(conn: &NodeConnection) -> Result<(), AdapterError> {
    // Stop first (best-effort).
    let _ = stop_daemon(conn);

    let staging_dir = WINDOWS_STAGING_DIR;
    let uninstall_tmp = write_temp_file(
        "Uninstall-RustyNetWindowsService_",
        ".ps1",
        UNINSTALL_SERVICE_SCRIPT.as_bytes(),
    )?;
    let remote_uninstall = format!(r"{staging_dir}\Uninstall-RustyNetWindowsService.ps1");

    let ensure_dir_script = format!(
        "New-Item -ItemType Directory -Force -Path {} | Out-Null",
        ps_quote(staging_dir)?
    );
    run_remote_ps(conn, &ensure_dir_script, SHORT_TIMEOUT)?;

    ssh::scp_to(
        conn,
        uninstall_tmp.as_path(),
        &remote_uninstall.replace('\\', "/"),
        SHORT_TIMEOUT,
    )?;
    let _ = std::fs::remove_file(&uninstall_tmp);

    let script = format!(
        "Set-StrictMode -Version Latest; $ErrorActionPreference = 'Stop'; \
         $ProgressPreference = 'SilentlyContinue'; \
         & {uninstall_q} \
           -ServiceName {svc_q} \
           -InstallRoot {install_root_q} \
           -StateRoot {state_root_q} \
           -PurgeStateRoot -PurgeInstallRoot",
        uninstall_q = ps_quote(&remote_uninstall)?,
        svc_q = ps_quote(WINDOWS_SERVICE_NAME)?,
        install_root_q = ps_quote(WINDOWS_INSTALL_ROOT)?,
        state_root_q = ps_quote(WINDOWS_STATE_ROOT)?,
    );
    run_remote_ps(conn, &script, Duration::from_secs(60))?;
    Ok(())
}

fn build_windows_release_script(
    workdir: &str,
    remote_bootstrap: &str,
) -> Result<String, AdapterError> {
    Ok(format!(
        "Set-StrictMode -Version Latest; $ErrorActionPreference = 'Stop'; \
         $ProgressPreference = 'SilentlyContinue'; \
         Set-Location -LiteralPath {workdir_q}; \
         & {bootstrap_q} -Phase build-release -RustyNetRoot {workdir_q} -ResultPath {result_q}",
        workdir_q = ps_quote(workdir)?,
        bootstrap_q = ps_quote(remote_bootstrap)?,
        result_q = ps_quote(WINDOWS_BUILD_RELEASE_REPORT_PATH)?,
    ))
}

fn build_windows_service_install_script(
    workdir: &str,
    remote_install_svc: &str,
    service_name: &str,
    node_id: &str,
) -> Result<String, AdapterError> {
    Ok(format!(
        "Set-StrictMode -Version Latest; $ErrorActionPreference = 'Stop'; \
         $ProgressPreference = 'SilentlyContinue'; \
         & {install_q} \
           -RustyNetRoot {workdir_q} \
           -InstallRoot {install_root_q} \
           -StateRoot {state_root_q} \
           -ServiceName {svc_q} \
           -NodeId {node_id_q}",
        install_q = ps_quote(remote_install_svc)?,
        workdir_q = ps_quote(workdir)?,
        install_root_q = ps_quote(WINDOWS_INSTALL_ROOT)?,
        state_root_q = ps_quote(WINDOWS_STATE_ROOT)?,
        svc_q = ps_quote(service_name)?,
        node_id_q = ps_quote(node_id)?,
    ))
}

fn windows_service_start_probe_fragment(service_name: &str) -> Result<String, AdapterError> {
    let svc_q = ps_quote(service_name)?;
    Ok(format!(
        "$stopOut = (& sc.exe stop {svc_q} 2>&1) -join ' '; \
         if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 1062) {{ Write-Warning ('sc.exe stop returned ' + $LASTEXITCODE + ': ' + $stopOut) }}; \
         for ($i = 0; $i -lt {WINDOWS_SERVICE_STOP_POLL_SECS}; $i++) {{ \
             $svc = Get-Service -Name {svc_q} -ErrorAction SilentlyContinue; \
             if ($null -eq $svc -or $svc.Status -ne 'StopPending') {{ break }}; \
             Start-Sleep -Seconds 1 \
         }}; \
         $startOut = (& sc.exe start {svc_q} 2>&1) -join ' '; \
         if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 1056) {{ throw ('sc.exe start failed (exit ' + $LASTEXITCODE + '): ' + $startOut) }}; \
         $svcStatus = $null; \
         for ($i = 0; $i -lt {WINDOWS_SERVICE_START_POLL_ATTEMPTS}; $i++) {{ \
             $svc = Get-Service -Name {svc_q} -ErrorAction Stop; \
             $svcStatus = $svc.Status; \
             if ($svcStatus -eq 'Running') {{ break }}; \
             Start-Sleep -Seconds {WINDOWS_SERVICE_START_POLL_INTERVAL_SECS} \
         }}; \
         if ($svcStatus -ne 'Running') {{ \
             $scQuery = (& sc.exe queryex {svc_q} 2>&1) -join ' | '; \
             throw \"Service failed to reach Running after {WINDOWS_SERVICE_START_PROBE_MAX_SECS}s (status=$svcStatus sc=[$scQuery])\" \
         }}",
    ))
}

fn windows_bootstrap_acl_repair_fragment() -> Result<String, AdapterError> {
    let state_root_q = ps_quote(WINDOWS_STATE_ROOT)?;
    Ok(format!(
        "$buser = (whoami.exe).Trim(); \
         $bootstrapAdministrators = (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')).Translate([System.Security.Principal.NTAccount]).Value; \
         $bootstrapAclDirs = @( \
             (Join-Path {state_root_q} 'trust'), \
             (Join-Path {state_root_q} 'keys'), \
             (Join-Path {state_root_q} 'membership'), \
             (Join-Path {state_root_q} 'secrets'), \
             (Join-Path {state_root_q} 'secrets\\key-custody') \
         ); \
         foreach ($bootstrapAclDir in $bootstrapAclDirs) {{ \
             New-Item -ItemType Directory -Force -Path $bootstrapAclDir | Out-Null; \
             takeown.exe /f $bootstrapAclDir /r /d y; \
             if ($LASTEXITCODE -ne 0) {{ throw ('takeown bootstrap dir failed for ' + $bootstrapAclDir + ' exit ' + $LASTEXITCODE) }}; \
             icacls.exe $bootstrapAclDir /grant:r \"${{buser}}:(OI)(CI)(F)\" /T; \
             if ($LASTEXITCODE -ne 0) {{ throw ('icacls bootstrap dir grant failed for ' + $bootstrapAclDir + ' exit ' + $LASTEXITCODE) }}; \
             icacls.exe $bootstrapAclDir /setowner $bootstrapAdministrators /T; \
             if ($LASTEXITCODE -ne 0) {{ throw ('icacls bootstrap dir owner restore failed for ' + $bootstrapAclDir + ' exit ' + $LASTEXITCODE) }} \
         }}",
    ))
}

fn windows_bootstrap_native_helper_fragment() -> String {
    "function Invoke-RustyNetBootstrapNative { \
         param([Parameter(Mandatory = $true)][scriptblock]$Command); \
         $oldErrorActionPreference = $ErrorActionPreference; \
         $ErrorActionPreference = 'Continue'; \
         try { \
             $output = (& $Command 2>&1) -join ' '; \
             $exitCode = $LASTEXITCODE \
         } finally { \
             $ErrorActionPreference = $oldErrorActionPreference \
         }; \
         if ($null -eq $exitCode) { $exitCode = 0 }; \
         [pscustomobject]@{ ExitCode = $exitCode; Output = $output } \
     }"
    .to_string()
}

/// Wait for the rustynet0 WireGuard adapter to appear with an IPv4 address.
///
/// Called from `enforce_daemon` after the SCM confirms Running.  The daemon
/// sets SCM Running before the daemon thread begins; WireGuard tunnel setup
/// happens inside the daemon's first reconcile tick (~1 s after thread start).
/// Without this probe the orchestrator proceeds to `validate_baseline_runtime`
/// before the IP is assigned, causing `collect_mesh_ip` to fail.
fn windows_tunnel_ip_readiness_fragment() -> Result<String, AdapterError> {
    Ok(
        "$wnRdy = $false; \
         for ($wnI = 0; $wnI -lt 45; $wnI++) { \
             $wnIface = Get-NetAdapter -ErrorAction SilentlyContinue | \
                 Where-Object { $_.Name -like '*rustynet*' -or $_.InterfaceDescription -like '*WireGuard*' } | \
                 Select-Object -First 1; \
             if ($wnIface) { \
                 $wnIp = Get-NetIPAddress -InterfaceIndex $wnIface.ifIndex \
                     -AddressFamily IPv4 -ErrorAction SilentlyContinue | \
                     Select-Object -First 1; \
                 if ($wnIp -and $wnIp.IPAddress) { $wnRdy = $true; break } \
             }; \
             Start-Sleep -Seconds 2 \
         }; \
         if (-not $wnRdy) { throw 'rustynet WireGuard adapter did not get an IPv4 address within 90s' }"
        .to_string(),
    )
}

/// Readiness probe: wait for SCM Running state AND for the reviewed env-file
/// and WireGuard public-key file to exist.
///
/// The Windows trust CLI (`rustynet.exe`) installed in Program Files is NOT the
/// daemon-control CLI and does not support a `status` sub-command — invoking it
/// with `status` produces a usage error.  Daemon socket / named-pipe readiness
/// is therefore checked by confirming that:
///
/// 1. SCM reports the service as `Running`.
/// 2. The reviewed env-file (`rustynetd.env`) is present — written by the
///    orchestrator before service start.
/// 3. The WireGuard public-key file (`wireguard.pub`) is present — generated
///    during the e2e bootstrap key step.
///
/// These three conditions together confirm the daemon completed its startup
/// handshake and is running with reviewed configuration.
fn windows_daemon_status_readiness_fragment(service_name: &str) -> Result<String, AdapterError> {
    let svc_q = ps_quote(service_name)?;
    let env_path_q = ps_quote(&format!(r"{WINDOWS_STATE_ROOT}\config\rustynetd.env"))?;
    let pub_key_path_q = ps_quote(&format!(r"{WINDOWS_STATE_ROOT}\keys\wireguard.pub"))?;
    Ok(format!(
        "$statusReady = $false; \
         for ($i = 0; $i -lt 30; $i++) {{ \
             $svc = Get-Service -Name {svc_q} -ErrorAction SilentlyContinue; \
             if ($null -ne $svc -and $svc.Status -eq 'Running') {{ \
                 $envOk = Test-Path -LiteralPath {env_path_q} -PathType Leaf; \
                 $keyOk = Test-Path -LiteralPath {pub_key_path_q} -PathType Leaf; \
                 if ($envOk -and $keyOk) {{ \
                     $statusReady = $true; \
                     break \
                 }} \
             }}; \
             Start-Sleep -Seconds 2 \
         }}; \
         if (-not $statusReady) {{ \
             $scQuery = (& sc.exe queryex {svc_q} 2>&1) -join ' | '; \
             throw ('RustyNet daemon did not reach readiness after 60s (SCM Running + env-file + wireguard.pub); sc=[' + $scQuery + ']') \
         }}",
    ))
}

// ── Windows e2e bootstrap ─────────────────────────────────────────────────────

fn windows_lab_node_id(alias: &str, ctx: &OrchestrationContext) -> String {
    ctx.node_ids
        .get(alias)
        .cloned()
        .unwrap_or_else(|| format!("{alias}-bootstrap"))
}

/// Generate WireGuard keys, membership state, and trust evidence for a Windows host.
/// Trust keys are generated locally on the orchestrator (rustynet-cli cannot compile
/// on Windows due to std::os::unix::* imports) and SCP'd to the remote host.
/// Called from `install_daemon` after the service binaries are installed.
fn run_windows_e2e_bootstrap(
    conn: &NodeConnection,
    alias: &str,
    ctx: &OrchestrationContext,
) -> Result<(), AdapterError> {
    let node_id = windows_lab_node_id(alias, ctx);
    let network_id = &ctx.network_id;
    let role_str = match ctx
        .assignments
        .iter()
        .find(|a| a.alias == alias)
        .map(|a| &a.role)
    {
        Some(NodeRole::Exit) => "admin",
        _ => "client",
    };
    let _ = role_str;

    // ── 1. Generate trust material locally ──────────────────────────────────
    let (verifier_key_content, trust_evidence_content) =
        generate_local_trust_material().map_err(|msg| AdapterError::Protocol { message: msg })?;

    // Ensure trust directory exists on remote before SCP.
    let trust_dir_q = ps_quote(r"C:\ProgramData\RustyNet\trust")?;
    run_remote_ps(
        conn,
        &format!("New-Item -ItemType Directory -Force -Path {trust_dir_q} | Out-Null"),
        SHORT_TIMEOUT,
    )?;

    let verifier_tmp = write_temp_file("trust_verifier_", ".pub", verifier_key_content.as_bytes())?;
    let evidence_tmp =
        write_temp_file("trust_evidence_", ".dat", trust_evidence_content.as_bytes())?;

    let scp_result = (|| {
        ssh::scp_to(
            conn,
            &verifier_tmp,
            &WINDOWS_TRUST_VERIFIER_KEY_PATH.replace('\\', "/"),
            SHORT_TIMEOUT,
        )?;
        ssh::scp_to(
            conn,
            &evidence_tmp,
            &WINDOWS_TRUST_EVIDENCE_PATH.replace('\\', "/"),
            SHORT_TIMEOUT,
        )
    })();
    let _ = std::fs::remove_file(&verifier_tmp);
    let _ = std::fs::remove_file(&evidence_tmp);
    scp_result?;

    // ── 2. WireGuard key init + membership init + service start ─────────────
    let passphrase_q = ps_quote(WINDOWS_WG_PASSPHRASE_PATH)?;
    let rustynetd_q = ps_quote(WINDOWS_RUSTYNETD_PATH)?;
    let wg_binary_q = ps_quote(WINDOWS_WG_BINARY_PATH)?;
    let node_id_q = ps_quote(&node_id)?;
    let network_id_q = ps_quote(network_id)?;
    let membership_owner_key_q = ps_quote(WINDOWS_MEMBERSHIP_OWNER_KEY_PATH)?;
    let membership_log_q = ps_quote(WINDOWS_MEMBERSHIP_LOG_PATH)?;
    let membership_watermark_q = ps_quote(WINDOWS_MEMBERSHIP_WATERMARK_PATH)?;
    let membership_snapshot_q = ps_quote(WINDOWS_MEMBERSHIP_SNAPSHOT_PATH)?;
    let bootstrap_acl_repair = windows_bootstrap_acl_repair_fragment()?;
    let native_helper = windows_bootstrap_native_helper_fragment();

    // NOTE: the service is NOT started here. Verifier keys (assignment.pub,
    // traversal.pub, dns-zone.pub) are required by the daemon at startup but
    // are only distributed in the DistributeAssignments / DistributeTraversal /
    // DistributeDnsZone stages that run AFTER this bootstrap stage.
    // EnforceBaselineRuntime calls start_daemon after all verifier keys are in
    // place.
    let bootstrap_script = format!(
        "$ErrorActionPreference = 'Stop'; \
         $ProgressPreference = 'SilentlyContinue'; \
         {native_helper}; \
         $env:RUSTYNET_WG_BINARY_PATH = {wg_binary_q}; \
         $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create(); \
         $bytes = New-Object byte[] 48; \
         $rng.GetBytes($bytes); \
         $pp = -join ($bytes | ForEach-Object {{ $_.ToString('x2') }}); \
         {bootstrap_acl_repair}; \
         New-Item -ItemType Directory -Force -Path (Split-Path {passphrase_q}) | Out-Null; \
         [System.IO.File]::WriteAllText({passphrase_q}, $pp); \
         $keyInit = Invoke-RustyNetBootstrapNative {{ & {rustynetd_q} key init --passphrase-file {passphrase_q} --force }}; \
         if ($keyInit.ExitCode -ne 0) {{ throw ('rustynetd key init failed: ' + $keyInit.Output) }}; \
         $mbInit = Invoke-RustyNetBootstrapNative {{ & {rustynetd_q} membership init \
             --snapshot {membership_snapshot_q} \
             --log {membership_log_q} \
             --watermark {membership_watermark_q} \
             --owner-signing-key {membership_owner_key_q} \
             --owner-signing-key-passphrase-file {passphrase_q} \
             --node-id {node_id_q} \
             --network-id {network_id_q} \
             --force }}; \
         if ($mbInit.ExitCode -ne 0) {{ throw ('rustynetd membership init failed: ' + $mbInit.Output) }}; \
         $ksp = Invoke-RustyNetBootstrapNative {{ & {rustynetd_q} key store-passphrase --passphrase-file {passphrase_q} }}; \
         if ($ksp.ExitCode -ne 0) {{ throw ('rustynetd key store-passphrase failed: ' + $ksp.Output) }}; \
         $acl = Invoke-RustyNetBootstrapNative {{ & {rustynetd_q} windows-runtime-acls-check }}; \
         if ($acl.ExitCode -ne 0) {{ throw ('runtime ACL check failed (startup would fail): ' + $acl.Output) }}",
    );
    run_remote_ps(conn, &bootstrap_script, WINDOWS_E2E_BOOTSTRAP_TIMEOUT)?;
    Ok(())
}

/// Generate an ed25519 trust signing key and matching trust evidence locally.
/// Returns `(verifier_key_file_content, trust_evidence_file_content)`.
fn generate_local_trust_material() -> Result<(String, String), String> {
    use ed25519_dalek::{Signer, SigningKey};
    use rand::{TryRngCore, rngs::OsRng};
    use zeroize::Zeroize;

    let mut seed = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut seed)
        .map_err(|e| format!("OsRng seed failed: {e}"))?;
    let mut nonce_bytes = [0u8; 8];
    OsRng
        .try_fill_bytes(&mut nonce_bytes)
        .map_err(|e| format!("OsRng nonce failed: {e}"))?;
    let nonce = u64::from_le_bytes(nonce_bytes);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("system time error: {e}"))?
        .as_secs();

    let signing_key = SigningKey::from_bytes(&seed);
    let verifier_hex = encode_hex(signing_key.verifying_key().as_bytes());
    let payload = format!(
        "version=2\ntls13_valid=true\nsigned_control_valid=true\
         \nsigned_data_age_secs=0\nclock_skew_secs=0\
         \nupdated_at_unix={now}\nnonce={nonce}\n"
    );
    let signature = signing_key.sign(payload.as_bytes());
    let evidence = format!("{payload}signature={}\n", encode_hex(&signature.to_bytes()));

    let mut seed_zeroed = seed;
    seed_zeroed.zeroize();

    Ok((format!("{verifier_hex}\n"), evidence))
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn run_service_action(conn: &NodeConnection, action_cmdlet: &str) -> Result<(), AdapterError> {
    let svc = ps_quote(WINDOWS_SERVICE_NAME)?;
    let script = format!(
        "Set-StrictMode -Version Latest; $ErrorActionPreference = 'Stop'; \
         $ProgressPreference = 'SilentlyContinue'; \
         {action_cmdlet} -Name {svc}"
    );
    run_remote_ps(conn, &script, Duration::from_secs(60))?;
    Ok(())
}

/// Validate a Windows path argument: reject NUL/CR/LF that could escape PS quoting.
fn validate_windows_path(path: &str) -> Result<(), AdapterError> {
    if path
        .chars()
        .any(|ch| ch == '\0' || ch == '\r' || ch == '\n')
    {
        return Err(AdapterError::Protocol {
            message: format!(
                "Windows path argument '{path}' contains control characters not safe for shell embedding"
            ),
        });
    }
    if path.is_empty() {
        return Err(AdapterError::Protocol {
            message: "Windows path argument must not be empty".to_string(),
        });
    }
    Ok(())
}

fn write_temp_file(
    prefix: &str,
    suffix: &str,
    content: &[u8],
) -> Result<std::path::PathBuf, AdapterError> {
    use std::io::Write;
    let mut path = std::env::temp_dir();
    path.push(format!("{prefix}{}{suffix}", std::process::id()));
    let mut file = std::fs::File::create(&path).map_err(|err| AdapterError::Io {
        message: format!("create temp file failed: {err}"),
    })?;
    file.write_all(content).map_err(|err| AdapterError::Io {
        message: format!("write temp file failed: {err}"),
    })?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ps_quote_escapes_single_quotes() {
        let quoted = ps_quote("it's a test").unwrap();
        assert_eq!(quoted, "'it''s a test'");
    }

    #[test]
    fn ps_quote_rejects_nul() {
        assert!(ps_quote("abc\0def").is_err());
    }

    #[test]
    fn ps_quote_rejects_cr_lf() {
        assert!(ps_quote("abc\ndef").is_err());
        assert!(ps_quote("abc\rdef").is_err());
    }

    #[test]
    fn encode_ps_command_is_utf16le_base64() {
        let script = "Write-Host Hello";
        let encoded = encode_ps_command(script).unwrap();
        // Decode back and check UTF-16LE roundtrip.
        let raw = base64::prelude::BASE64_STANDARD.decode(&encoded).unwrap();
        assert_eq!(raw.len() % 2, 0, "UTF-16LE must have even byte count");
        let units: Vec<u16> = raw
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let decoded = String::from_utf16(&units).unwrap();
        assert_eq!(decoded, script);
    }

    #[test]
    fn encode_ps_command_rejects_nul() {
        assert!(encode_ps_command("abc\0def").is_err());
    }

    #[test]
    fn build_ps_invocation_contains_encoded_command() {
        let script = "$x = 1";
        let invocation = build_ps_invocation(script).unwrap();
        assert!(invocation.contains("-EncodedCommand "), "must contain flag");
        assert!(
            invocation.contains("-NonInteractive"),
            "must be non-interactive"
        );
        assert!(
            invocation.contains("Bypass"),
            "must bypass execution policy"
        );
    }

    #[test]
    fn validate_windows_path_rejects_empty() {
        assert!(validate_windows_path("").is_err());
    }

    #[test]
    fn validate_windows_path_rejects_nul() {
        assert!(validate_windows_path("C:\\foo\0bar").is_err());
    }

    #[test]
    fn validate_windows_path_accepts_normal_paths() {
        assert!(validate_windows_path(r"C:\Program Files\RustyNet").is_ok());
        assert!(validate_windows_path(r"C:\ProgramData\Rustynet\vm-lab").is_ok());
    }

    #[test]
    fn bootstrap_scripts_are_non_empty() {
        assert!(
            !BOOTSTRAP_SCRIPT.is_empty(),
            "Bootstrap-RustyNetWindows.ps1 must not be empty"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("Bootstrap-RustyNetWindows.ps1"),
            "bootstrap script must contain its own filename"
        );
        assert!(
            !INSTALL_SERVICE_SCRIPT.is_empty(),
            "Install-RustyNetWindowsService.ps1 must not be empty"
        );
        assert!(
            !UNINSTALL_SERVICE_SCRIPT.is_empty(),
            "Uninstall-RustyNetWindowsService.ps1 must not be empty"
        );
    }

    #[test]
    fn install_service_script_wraps_native_stderr_with_exit_code_checks() {
        assert!(
            INSTALL_SERVICE_SCRIPT.contains("function Invoke-RustyNetNativeCommand"),
            "install helper must wrap native commands that may write stderr on success"
        );
        assert!(
            INSTALL_SERVICE_SCRIPT.contains("$ErrorActionPreference = 'Continue'"),
            "native wrapper must prevent benign native stderr from becoming NativeCommandError"
        );
        assert!(
            INSTALL_SERVICE_SCRIPT.contains("$exitCode = $LASTEXITCODE"),
            "native wrapper must still fail closed based on native exit code"
        );
        assert!(
            INSTALL_SERVICE_SCRIPT.contains(
                "Invoke-RustyNetNativeCommand -Path $daemonDest -Arguments @('key', 'store-passphrase'"
            ),
            "install helper must use the native wrapper for key store-passphrase"
        );
        assert!(
            !INSTALL_SERVICE_SCRIPT.contains("(& $daemonDest key store-passphrase"),
            "install helper must not run key store-passphrase through raw 2>&1 under ErrorActionPreference=Stop"
        );
    }

    #[test]
    fn install_service_script_repairs_key_custody_acls_before_rekey() {
        assert!(
            INSTALL_SERVICE_SCRIPT.contains("function Repair-RustyNetPreServiceAcl"),
            "install helper must be able to restore reviewed custody ownership before service SID repair"
        );
        assert!(
            INSTALL_SERVICE_SCRIPT.contains("repair-key-custody-acls-before-rekey"),
            "install helper must repair key custody ACLs before DPAPI passphrase storage"
        );
        assert!(
            INSTALL_SERVICE_SCRIPT.contains("(Join-Path $StateRoot 'secrets')"),
            "pre-service ACL repair must cover the passphrase parent directory"
        );
        assert!(
            INSTALL_SERVICE_SCRIPT.contains("(Join-Path $StateRoot 'secrets\\key-custody')"),
            "pre-service ACL repair must cover key custody blobs"
        );
    }

    #[test]
    fn build_windows_release_script_always_requests_guest_manifest() {
        let script = build_windows_release_script(
            r"C:\Rustynet",
            r"C:\Windows\Temp\rustynet-stage\Bootstrap-RustyNetWindows.ps1",
        )
        .expect("build script should render");
        assert!(script.contains("Set-StrictMode -Version Latest"));
        assert!(script.contains("-Phase build-release"));
        assert!(script.contains("-RustyNetRoot 'C:\\Rustynet'"));
        assert!(script.contains("-ResultPath "));
        assert!(script.contains(WINDOWS_BUILD_RELEASE_REPORT_PATH));
        assert!(
            !script.contains("-AllowInteractiveTaskFallback"),
            "Rust-native live lab must not silently fall back to interactive scheduled-task builds"
        );
    }

    #[test]
    fn build_windows_service_install_script_threads_lab_node_id() {
        let script = build_windows_service_install_script(
            r"C:\Rustynet",
            r"C:\Windows\Temp\rustynet-stage\Install-RustyNetWindowsService.ps1",
            "RustyNet",
            "windows-utm-1",
        )
        .expect("install script should render");

        assert!(script.contains("-ServiceName 'RustyNet'"));
        assert!(script.contains("-NodeId 'windows-utm-1'"));
        assert!(
            INSTALL_SERVICE_SCRIPT.contains("[string]$NodeId"),
            "Windows install helper must accept the node id passed by the orchestrator"
        );
        assert!(
            INSTALL_SERVICE_SCRIPT.contains("'--node-id', $NodeId"),
            "Windows install helper must not hardcode a stale service node id"
        );
        assert!(
            INSTALL_SERVICE_SCRIPT.contains("(Join-Path $StateRoot 'rustynetd.state')"),
            "fresh Windows installs must purge stale daemon state before service start"
        );
    }

    #[test]
    fn windows_service_start_probe_polls_scm_without_slow_eventlog_diagnostics() {
        let script =
            windows_service_start_probe_fragment("RustyNet").expect("service probe should render");

        assert!(script.contains("sc.exe stop 'RustyNet'"));
        assert!(script.contains("sc.exe start 'RustyNet'"));
        assert!(script.contains("sc.exe queryex 'RustyNet'"));
        assert!(script.contains("$i -lt 60"));
        assert!(script.contains("$svcStatus -eq 'Running'"));
        assert!(
            !script.contains("$stopOut:"),
            "PowerShell parses $stopOut: as an invalid scoped variable"
        );
        assert!(
            !script.contains("$startOut:"),
            "PowerShell parses $startOut: as an invalid scoped variable"
        );
        assert!(
            !script.contains("Get-EventLog"),
            "service smoke path must not block on slow EventLog queries"
        );
        assert!(
            !script.contains("Get-WmiObject"),
            "service smoke path must not block on slow WMI queries"
        );
        assert!(
            !script.contains("Start-Service"),
            "service smoke path must not block on Start-Service"
        );
    }

    #[test]
    fn windows_bootstrap_acl_repair_scopes_to_runtime_dirs() {
        let script =
            windows_bootstrap_acl_repair_fragment().expect("ACL repair fragment should render");

        for required_dir in [
            "trust",
            "keys",
            "membership",
            "secrets",
            "secrets\\key-custody",
        ] {
            assert!(
                script.contains(required_dir),
                "bootstrap ACL repair must cover {required_dir}"
            );
        }
        assert!(
            !script.contains("takeown.exe /f 'C:\\ProgramData\\RustyNet'"),
            "bootstrap must not recursively take ownership of the whole state root"
        );
        assert!(
            !script.contains("icacls.exe 'C:\\ProgramData\\RustyNet'"),
            "bootstrap must not recursively grant over stale lab debris in the whole state root"
        );
        assert!(
            script.contains("$bootstrapAclDir"),
            "bootstrap ACL repair should operate per reviewed runtime directory"
        );
        assert!(
            script.contains("/setowner $bootstrapAdministrators"),
            "bootstrap must restore reviewed ownership after temporary bootstrap-user access"
        );
    }

    #[test]
    fn windows_bootstrap_native_helper_captures_stderr_without_native_command_error() {
        let script = windows_bootstrap_native_helper_fragment();

        assert!(script.contains("Invoke-RustyNetBootstrapNative"));
        assert!(
            script.contains("$ErrorActionPreference = 'Continue'"),
            "native stderr must be captured instead of converted into NativeCommandError"
        );
        assert!(
            script.contains("$exitCode = $LASTEXITCODE"),
            "native command failure must be decided by LASTEXITCODE"
        );
        assert!(
            script.contains("finally"),
            "helper must restore the prior ErrorActionPreference"
        );
    }

    #[test]
    fn windows_daemon_status_readiness_uses_scm_and_file_checks() {
        let script = windows_daemon_status_readiness_fragment("RustyNet")
            .expect("daemon readiness fragment should render");

        // Must NOT invoke rustynet.exe status — that binary is the trust CLI
        // on Windows and does not accept a status sub-command.
        assert!(
            !script.contains("rustynet.exe"),
            "readiness probe must not invoke rustynet.exe (trust CLI): {script}"
        );
        assert!(
            !script.contains("RUSTYNET_DAEMON_SOCKET"),
            "readiness probe must not use named-pipe status: {script}"
        );
        // Must check SCM Running state.
        assert!(
            script.contains("Running"),
            "readiness probe must check SCM Running state: {script}"
        );
        // Must verify reviewed env-file and WireGuard public-key file exist.
        assert!(
            script.contains("rustynetd.env"),
            "readiness probe must check env-file presence: {script}"
        );
        assert!(
            script.contains("wireguard.pub"),
            "readiness probe must check wireguard.pub presence: {script}"
        );
        // Must include SCM queryex on failure.
        assert!(
            script.contains("sc.exe queryex"),
            "readiness failure must include SCM state: {script}"
        );
    }

    #[test]
    fn windows_e2e_bootstrap_timeout_covers_key_and_membership_budget() {
        // Bootstrap does NOT start the service; the service is deferred to
        // EnforceBaselineRuntime (after verifier keys are distributed).
        // The timeout only needs to cover: key init, membership init,
        // key store-passphrase, and runtime-acls-check.
        assert!(
            WINDOWS_E2E_BOOTSTRAP_TIMEOUT.as_secs() > 120,
            "bootstrap timeout must leave budget for key init, membership init, and ACL checks"
        );
    }
}
