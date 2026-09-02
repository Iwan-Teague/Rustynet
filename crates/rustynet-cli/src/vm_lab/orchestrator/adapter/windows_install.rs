#![allow(dead_code)]
use std::time::Duration;

use base64::prelude::*;

use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::adapter::ssh;
use crate::vm_lab::orchestrator::adapter::validated_args::ValidatedArg;
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
pub const WINDOWS_MEMBERSHIP_SIGNING_PASSPHRASE_PATH: &str =
    r"C:\ProgramData\RustyNet\secrets\signing_key_passphrase.dpapi";
pub const WINDOWS_CREDENTIALS_WORKSPACE_DIR: &str =
    r"C:\ProgramData\RustyNet\credentials-workspace";
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
static PROVISION_LAB_IMAGE_SCRIPT: &str = include_str!(
    "../../../../../../scripts/bootstrap/windows/Provision-RustyNetWindowsLabImage.ps1"
);
static VSCONFIG_FILE: &str =
    include_str!("../../../../../../scripts/bootstrap/windows/RustyNetBuildTools.vsconfig");

const SHORT_TIMEOUT: Duration = Duration::from_secs(30);
/// Default budget (seconds) for the cold Windows release build. A 2-vCPU guest
/// can legitimately need 30-60 minutes, so this default leaves generous
/// headroom; operators proving a slower cell can raise it without a rebuild
/// via `RUSTYNET_WINDOWS_BUILD_TIMEOUT_SECS` (see
/// [`WINDOWS_BUILD_TIMEOUT_ENV`] and [`windows_build_timeout_from_env`]).
const DEFAULT_WINDOWS_BUILD_TIMEOUT_SECS: u64 = 3600;
/// Environment variable overriding the Windows build-release timeout budget,
/// in whole seconds (`RUSTYNET_WINDOWS_BUILD_TIMEOUT_SECS=5400`). Invalid
/// values fail closed — there is no silent fallback to the default.
pub const WINDOWS_BUILD_TIMEOUT_ENV: &str = "RUSTYNET_WINDOWS_BUILD_TIMEOUT_SECS";
const WINDOWS_SERVICE_STOP_POLL_SECS: u64 = 30;
const WINDOWS_SERVICE_START_POLL_ATTEMPTS: u64 = 60;
const WINDOWS_SERVICE_START_POLL_INTERVAL_SECS: u64 = 2;
const WINDOWS_SERVICE_START_PROBE_MAX_SECS: u64 = WINDOWS_SERVICE_STOP_POLL_SECS
    + (WINDOWS_SERVICE_START_POLL_ATTEMPTS * WINDOWS_SERVICE_START_POLL_INTERVAL_SECS);
const WINDOWS_E2E_BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(300);
const WINDOWS_BUILD_RELEASE_REPORT_PATH: &str =
    r"C:\Windows\Temp\rustynet-stage\build-release\manifest.json";

// ── PowerShell encoding helpers ───────────────────────────────────────────────

/// Encode a `PowerShell` script as UTF-16LE + base64 for `-EncodedCommand`.
pub fn encode_ps_command(script: &str) -> Result<String, AdapterError> {
    if script.contains('\0') {
        return Err(AdapterError::Protocol {
            message: "PowerShell script contains NUL byte".to_owned(),
        });
    }
    let mut bytes = Vec::with_capacity(script.len() * 2);
    for unit in script.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    Ok(BASE64_STANDARD.encode(bytes))
}

/// Build the SSH command string that invokes `PowerShell` with an encoded script.
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

// ── QH-01: validated PowerShell script newtype ───────────────────────────────

/// A PowerShell payload that is safe to hand to the remote-PS sink family.
///
/// Like `RemoteCommand` on the POSIX side, the field is private and there is
/// no `From<String>`: construction always runs `ps_quote` (and, for
/// interpolated values, an interior allowlist). `Debug` prints the length
/// only. `as_str` exists solely for the PS sinks in this module.
pub(crate) struct PowerShellScript(String);

impl PowerShellScript {
    /// Wrap a single interpolated VALUE: reject subexpression `$(...)`,
    /// backticks, and quote characters outright (interior allowlist — a value
    /// must never carry executable PS syntax), then single-quote via
    /// `ps_quote`.
    pub(crate) fn from_single_value(label: &str, value: &str) -> Result<Self, AdapterError> {
        const FORBIDDEN: [char; 3] = ['`', '"', '\''];
        if value.contains("$(") || value.chars().any(|ch| FORBIDDEN.contains(&ch)) {
            return Err(AdapterError::Protocol {
                message: format!(
                    "{label}: interpolated PowerShell value contains forbidden \
                     syntax (substitution, backtick, or quote characters)"
                ),
            });
        }
        Ok(Self(ps_quote(value)?))
    }

    /// Build the standard validator-call script from an already-validated
    /// argv: `$out = & '<binary>' '<arg>' ... 2>&1; Write-Output $out`. Every
    /// element is `ps_quote`d; an empty argv is an error, not an empty script.
    pub(crate) fn from_call_argv(
        label: &str,
        argv: &[crate::vm_lab::orchestrator::adapter::validated_args::ValidatedArg],
    ) -> Result<Self, AdapterError> {
        if argv.is_empty() {
            return Err(AdapterError::Protocol {
                message: format!("{label}: validated argv must not be empty"),
            });
        }
        let mut rendered = String::from("$out = &");
        for arg in argv {
            let quoted = ps_quote(arg.value())?;
            rendered.push(' ');
            rendered.push_str(&quoted);
        }
        rendered.push_str(" 2>&1; Write-Output $out");
        Ok(Self(rendered))
    }

    // Deliberately NO whole-script constructor from a plain `String`: it
    // would accept any `format!` result (voiding the type boundary), and
    // `ps_quote` turns a script body into a single-quoted literal, which is
    // not how the `-EncodedCommand` sinks consume a script. The typed
    // renderer-output constructor below is the one whole-script way in.

    /// The typed renderer-output constructor (QH-01 Step 4d-i): a script
    /// rendered by `script_template::render_*` (the one PowerShell template
    /// on the renderer's path uses `Binding::PowerShellLiteral`) crosses this
    /// boundary by type, not by convention. The name makes the input type
    /// explicit — there is deliberately no `From<String>`.
    pub(crate) fn from_rendered(rendered: crate::vm_lab::script_template::RenderedScript) -> Self {
        Self(rendered.as_str().to_owned())
    }

    /// Sink-only accessor for the remote-PS sink family in THIS module.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for PowerShellScript {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PowerShellScript(len={})", self.0.len())
    }
}

// ── Remote PS execution ───────────────────────────────────────────────────────

/// Run a `PowerShell` script over SSH. The script is base64-encoded so it
/// survives the SSH quoting layer. Returns trimmed stdout on success.
pub fn run_remote_ps(
    conn: &NodeConnection,
    script: &str,
    timeout: Duration,
) -> Result<String, AdapterError> {
    let invocation = build_ps_invocation(script)?;
    ssh::run_remote(conn, &invocation, timeout)
}

/// Run a `PowerShell` script over SSH. Returns `true` if exit code is 0.
pub fn run_remote_ps_check(
    conn: &NodeConnection,
    script: &str,
    timeout: Duration,
) -> Result<bool, AdapterError> {
    let invocation = build_ps_invocation(script)?;
    ssh::run_remote_check(conn, &invocation, timeout)
}

// ── Windows build budget (QH-15) ─────────────────────────────────────────────

/// Resolve the Windows build-release timeout budget from `RUSTYNET_WINDOWS_BUILD_TIMEOUT_SECS`.
///
/// `None` / empty / whitespace-only selects the 3600s default. A value parses
/// as `u64` and is > 0 selects that many seconds. Anything else is a hard
/// error naming the variable — fail closed, never a silent fallback, so a
/// typo in the override cannot silently run the build on the wrong budget.
pub fn windows_build_timeout_from_env(raw: Option<&str>) -> Result<Duration, AdapterError> {
    let Some(raw) = raw.map(str::trim).filter(|raw| !raw.is_empty()) else {
        return Ok(Duration::from_secs(DEFAULT_WINDOWS_BUILD_TIMEOUT_SECS));
    };
    match raw.parse::<u64>() {
        Ok(secs) if secs > 0 => Ok(Duration::from_secs(secs)),
        _ => Err(AdapterError::Protocol {
            message: format!(
                "{WINDOWS_BUILD_TIMEOUT_ENV} must be a positive integer number of \
                 seconds (got {raw:?}); the Windows build-release budget was NOT \
                 applied and the default is not silently substituted"
            ),
        }),
    }
}

/// Read the live environment for the Windows build-release timeout budget.
fn windows_build_timeout() -> Result<Duration, AdapterError> {
    windows_build_timeout_from_env(std::env::var(WINDOWS_BUILD_TIMEOUT_ENV).ok().as_deref())
}

/// Relabel a budget timeout on the Windows build-release step so the ledger
/// never records "build exceeded its time budget" as a product defect (QH-15).
///
/// `ssh::run_remote` surfaces a deadline kill as `AdapterError::Ssh` whose
/// message contains `timed out after`; every other error — including a real
/// compile failure surfaced as `AdapterError::Command` and an SSH spawn
/// failure — passes through unchanged.
fn classify_windows_build_outcome(err: AdapterError, budget: Duration) -> AdapterError {
    match err {
        AdapterError::Ssh { message } if message.contains("timed out after") => {
            AdapterError::Protocol {
                message: format!(
                    "Windows build-release exceeded its timeout budget of {}s \
                     (set RUSTYNET_WINDOWS_BUILD_TIMEOUT_SECS to raise it). This is \
                     build infrastructure under-provisioning (QH-15), not a product \
                     defect; the build was killed at the budget and produced no verdict.",
                    budget.as_secs()
                ),
            }
        }
        other => other,
    }
}

// ── Install lifecycle ─────────────────────────────────────────────────────────

/// Bootstrap the daemon on a Windows host. Extracts `source` into `workdir`
/// via tar.exe, then runs Bootstrap-RustyNetWindows.ps1 -Phase build-release,
/// Install-RustyNetWindowsService.ps1, and runs the e2e bootstrap sequence to
/// generate `WireGuard` keys, membership state, and trust evidence.
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
    //
    // Clean stale `.cargo/` (offline-mode config) and `vendor/` (frozen crate
    // sources) from any prior run before extracting.  Those directories are
    // NOT in the source archive (only git-tracked files are), so without
    // explicit cleanup they survive across runs and pin the build to an
    // outdated vendored snapshot.
    let extract_script = format!(
        "$ErrorActionPreference = 'Stop'; \
         $ProgressPreference = 'SilentlyContinue'; \
         New-Item -ItemType Directory -Force -Path {workdir_q} | Out-Null; \
         Remove-Item -LiteralPath (Join-Path {workdir_q} '.cargo') -Recurse -Force -ErrorAction SilentlyContinue; \
         Remove-Item -LiteralPath (Join-Path {workdir_q} 'vendor') -Recurse -Force -ErrorAction SilentlyContinue; \
         & tar.exe -xzf {archive_q} -C {workdir_q}",
        workdir_q = ps_quote(workdir)?,
        archive_q = ps_quote(&remote_archive)?,
    );
    run_remote_ps(conn, &extract_script, Duration::from_secs(120))?;

    // If the operator has pre-vendored crates on the host at
    // /tmp/rustynet-vendor-flat.tar.gz (created with `cargo vendor` and
    // tarred with contents at the archive root), ship them across and
    // wire up an offline `.cargo/config.toml`.  This is required for
    // Windows lab VMs whose virtio NIC has working LAN connectivity
    // but no external internet egress (so `cargo build` cannot reach
    // crates.io).  When the tarball is absent the build falls back to
    // online crates.io, which is fine for VMs with full internet.
    let local_vendor = std::path::PathBuf::from("/tmp/rustynet-vendor-flat.tar.gz");
    if local_vendor.is_file() {
        let remote_vendor = format!(r"{staging_dir}\rn_vendor.tar.gz");
        ssh::scp_to(
            conn,
            local_vendor.as_path(),
            &remote_vendor.replace('\\', "/"),
            Duration::from_secs(600),
        )?;
        let vendor_extract_script = format!(
            "$ErrorActionPreference = 'Stop'; \
             $ProgressPreference = 'SilentlyContinue'; \
             $vendorDir = Join-Path {workdir_q} 'vendor'; \
             $cargoDir = Join-Path {workdir_q} '.cargo'; \
             New-Item -ItemType Directory -Force -Path $vendorDir | Out-Null; \
             New-Item -ItemType Directory -Force -Path $cargoDir | Out-Null; \
             & tar.exe -xzf {vendor_archive_q} -C $vendorDir; \
             $cargoConfig = Join-Path $cargoDir 'config.toml'; \
             $configBytes = [Text.Encoding]::ASCII.GetBytes(\"[source.crates-io]`nreplace-with = `\"vendored-sources`\"`n`n[source.vendored-sources]`ndirectory = `\"vendor`\"`n\"); \
             [IO.File]::WriteAllBytes($cargoConfig, $configBytes)",
            workdir_q = ps_quote(workdir)?,
            vendor_archive_q = ps_quote(&remote_vendor)?,
        );
        run_remote_ps(conn, &vendor_extract_script, Duration::from_secs(300))?;
    }

    // Build release from synced workdir. The budget is env-overridable
    // (QH-15) and a budget kill is relabeled as infrastructure
    // under-provisioning so the stage outcome is never read as a product
    // defect. CARGO_TARGET_DIR stays redirected-by-absence: the install
    // hardcodes `<workdir>\target\release\` and `target/` is deliberately
    // not wiped between runs on this path (warm cache).
    let build_script = build_windows_release_script(workdir, &remote_bootstrap)?;
    let build_timeout = windows_build_timeout()?;
    run_remote_ps(conn, &build_script, build_timeout)
        .map_err(|err| classify_windows_build_outcome(err, build_timeout))?;

    // Install the service.
    let node_id = windows_lab_node_id(alias, ctx);
    // Resolve the daemon node role from the assignment so the install script
    // passes --node-role. The daemon defaults to `admin` when the flag is
    // omitted, which fails reconcile closed for a client-enrolled node
    // (membership role mismatch); threading it explicitly prevents that drift.
    let node_role = ctx
        .assignments
        .iter()
        .find(|a| a.alias == alias)
        .map(|a| &a.role)
        .unwrap_or(&NodeRole::Client)
        .daemon_node_role_for_platform(&VmGuestPlatform::Windows)
        .map_err(|message| AdapterError::Protocol { message })?;
    let install_script = build_windows_service_install_script(
        workdir,
        &remote_install_svc,
        WINDOWS_SERVICE_NAME,
        &node_id,
        node_role,
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
        service_name: WINDOWS_SERVICE_NAME.to_owned(),
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
/// `WireGuard` tunnels on the next reconcile tick.
/// Build the remote PowerShell that patches `rustynetd.env` into enforce mode
/// (QH-24): flips `--auto-tunnel-enforce` to `true` in the
/// `RUSTYNETD_DAEMON_ARGS_JSON` line and threads the freshness ceilings.
///
/// The env file has the form:
///   # comment
///   RUSTYNETD_DAEMON_ARGS_JSON=["--backend","...",
///       "--auto-tunnel-enforce","false","--node-id","..."]
/// The JSON array is parsed, the value flipped, and the result written back.
///
/// The same patch threads `--traversal-stun-servers` with the guest's default
/// gateway on 3478 (C-STUN, BashOrchestratorRetirementProgram) — an empty
/// value disables srflx candidate gathering, and no Windows deploy path set
/// it anywhere. Gateway detection failure adds no flag (prior behaviour);
/// a live responder is optional (gathering fails soft on a bounded timeout).
///
/// Split out of `enforce_daemon` so the generated script is unit-testable
/// without a live `NodeConnection`. This is the fail-closed enforcement path:
/// until this patch runs the daemon is in non-enforcing mode
/// (`auto_tunnel_enforce=false` → reconcile applies an empty dataplane, no
/// mesh adapter), so a script that silently drops the flip — or regresses a
/// `true` back toward `false` — leaves the node bootstrapped but never
/// enforcing. Pinned by
/// `auto_tunnel_enforce_patch_script_flips_enforce_and_threads_max_ages`.
fn build_auto_tunnel_enforce_patch_script(env_path: &str) -> Result<String, AdapterError> {
    let env_path_q = ps_quote(env_path)?;
    Ok(format!(
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
                 $gw = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Select-Object -First 1).NextHop; \
                 if ($gw -match '^[0-9]{{1,3}}(\\.[0-9]{{1,3}}){{3}}$') {{ \
                     $stunIdx = [array]::IndexOf([string[]]$arr, '--traversal-stun-servers'); \
                     if ($stunIdx -lt 0) {{ \
                         $null = $arr.Add('--traversal-stun-servers'); \
                         $null = $arr.Add(($gw + ':3478')) \
                     }} elseif (($stunIdx + 1) -lt $arr.Count) {{ \
                         $arr[$stunIdx + 1] = ($gw + ':3478') \
                     }} \
                 }}; \
                 'RUSTYNETD_DAEMON_ARGS_JSON=' + ($arr.ToArray() | ConvertTo-Json -Compress) \
             }} else {{ $_ }} \
         }}; \
         $updated | Out-File -Encoding ASCII $envPath",
    ))
}

pub fn enforce_daemon(
    conn: &NodeConnection,
    _alias: &str,
    _ctx: &OrchestrationContext,
) -> Result<(), AdapterError> {
    let env_path = format!(r"{WINDOWS_STATE_ROOT}\config\rustynetd.env");
    // Patch --auto-tunnel-enforce in the RUSTYNETD_DAEMON_ARGS_JSON line.
    let patch_script = build_auto_tunnel_enforce_patch_script(&env_path)?;
    run_remote_ps(conn, &patch_script, SHORT_TIMEOUT)?;
    // The daemon was started during bootstrap with --auto-tunnel-enforce false and
    // is still running. sc.exe start no-ops on an already-running service (exit
    // 1056), so start_daemon alone would never reload the env we just patched and
    // the daemon would stay in non-enforcing mode (auto_tunnel_enforce=false ->
    // reconcile applies an empty dataplane, no mesh adapter). Stop it first
    // (Stop-Service is synchronous: the process is gone before we restart) so
    // start_daemon does a clean start that reads --auto-tunnel-enforce true and
    // applies the signed assignment on the first reconcile tick.
    stop_daemon(conn)?;
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

/// Start the `RustyNet` SCM service and wait for it to reach Running state.
///
/// Uses `windows_service_start_probe_fragment` which handles the already-running
/// case (sc.exe exit 1056) and polls for SCM Running state.  This is called from
/// `EnforceBaselineRuntime` AFTER verifier keys have been distributed, so the
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

/// Stop the `RustyNet` SCM service.
pub fn stop_daemon(conn: &NodeConnection) -> Result<(), AdapterError> {
    run_service_action(conn, "Stop-Service -Force -ErrorAction SilentlyContinue")
}

/// Restart the `RustyNet` SCM service.
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
    // Bootstrap-RustyNetWindows.ps1 is SCP'd standalone into the ephemeral
    // staging dir (see `install_daemon` above) — it does NOT carry its
    // `scripts\bootstrap\windows\` sibling files with it. Its winget/vsconfig
    // dependency-install step resolves those siblings relative to
    // `$PSScriptRoot` by default, which is the staging dir, so an unqualified
    // invocation fails with "WinGet configuration file not found". The
    // extracted source archive at `workdir` DOES have both files (they are
    // git-tracked), so point the script at that copy explicitly via its
    // `-WingetConfigPath`/`-VsConfigPath` parameters instead of relying on
    // the default same-directory lookup.
    let winget_config_path =
        format!(r"{workdir}\scripts\bootstrap\windows\RustyNetBootstrap.winget.yml");
    let vs_config_path =
        format!(r"{workdir}\scripts\bootstrap\windows\RustyNetBuildTools.vsconfig");
    Ok(format!(
        "Set-StrictMode -Version Latest; $ErrorActionPreference = 'Stop'; \
         $ProgressPreference = 'SilentlyContinue'; \
         Set-Location -LiteralPath {workdir_q}; \
         & {bootstrap_q} -Phase build-release -RustyNetRoot {workdir_q} \
           -WingetConfigPath {winget_q} -VsConfigPath {vsconfig_q} -ResultPath {result_q}",
        workdir_q = ps_quote(workdir)?,
        bootstrap_q = ps_quote(remote_bootstrap)?,
        winget_q = ps_quote(&winget_config_path)?,
        vsconfig_q = ps_quote(&vs_config_path)?,
        result_q = ps_quote(WINDOWS_BUILD_RELEASE_REPORT_PATH)?,
    ))
}

fn build_windows_service_install_script(
    workdir: &str,
    remote_install_svc: &str,
    service_name: &str,
    node_id: &str,
    node_role: &str,
) -> Result<String, AdapterError> {
    Ok(format!(
        "Set-StrictMode -Version Latest; $ErrorActionPreference = 'Stop'; \
         $ProgressPreference = 'SilentlyContinue'; \
         & {install_q} \
           -RustyNetRoot {workdir_q} \
           -InstallRoot {install_root_q} \
           -StateRoot {state_root_q} \
           -ServiceName {svc_q} \
           -NodeId {node_id_q} \
           -NodeRole {node_role_q}",
        install_q = ps_quote(remote_install_svc)?,
        workdir_q = ps_quote(workdir)?,
        install_root_q = ps_quote(WINDOWS_INSTALL_ROOT)?,
        state_root_q = ps_quote(WINDOWS_STATE_ROOT)?,
        svc_q = ps_quote(service_name)?,
        node_id_q = ps_quote(node_id)?,
        node_role_q = ps_quote(node_role)?,
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
    // Bootstrap helper fragment: defines reusable PowerShell functions
    // consumed by the e2e bootstrap script.
    //
    // - `Invoke-RustyNetBootstrapNative` runs a native command and
    //   captures its exit code + combined stdout/stderr.
    // - `New-RustyNetDpapiEnvelope` produces the reviewed `RNYDPAPI`
    //   envelope (magic + version + reserved + BE u32 length +
    //   protected) so PowerShell-side DPAPI ciphertexts decode against
    //   `decode_windows_dpapi_passphrase_blob`. Used by the Phase 27
    //   reviewer fold-in so the canonical `.dpapi` paths never see
    //   plaintext bytes on disk.
    // - `Write-RustyNetDpapiBlobAtomic` writes the envelope to a
    //   `.tmp` sibling and `Move-Item`s it onto the final path (atomic
    //   on NTFS). Forces a `Remove-Item -Force` first so an existing
    //   plaintext blob from a previous run cannot leave deleted-block
    //   journal entries that the new envelope appears to "amend".
    // - `Remove-RustyNetPlaintextTempFile` overwrites the file with
    //   zeros then deletes it, the closest NTFS-side equivalent of
    //   `shred` for the per-key plaintext tempfiles. The reviewed
    //   `credentials-workspace` parent has the same SY/BA-only DACL
    //   as `secrets\`, so the tempfile inherits that fence even
    //   before deletion.
    // - `Clear-RustyNetSensitiveString` zeroes a `[string]` variable
    //   so the in-process passphrase plaintext is overwritten when
    //   the bootstrap script exits.
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
     }; \
     function New-RustyNetDpapiEnvelope { \
         param([Parameter(Mandatory = $true)][byte[]]$ProtectedBytes); \
         if ($ProtectedBytes.Length -gt 4294967295) { throw 'protected blob exceeds u32 length' }; \
         $magic = [byte[]]@(0x52,0x4E,0x59,0x44,0x50,0x41,0x50,0x49); \
         $header = New-Object byte[] 14; \
         [Array]::Copy($magic, 0, $header, 0, 8); \
         $header[8] = 0x01; \
         $header[9] = 0x00; \
         $len = [uint32]$ProtectedBytes.Length; \
         $header[10] = [byte](($len -shr 24) -band 0xff); \
         $header[11] = [byte](($len -shr 16) -band 0xff); \
         $header[12] = [byte](($len -shr 8) -band 0xff); \
         $header[13] = [byte]($len -band 0xff); \
         $envelope = New-Object byte[] ($header.Length + $ProtectedBytes.Length); \
         [Array]::Copy($header, 0, $envelope, 0, $header.Length); \
         [Array]::Copy($ProtectedBytes, 0, $envelope, $header.Length, $ProtectedBytes.Length); \
         return ,$envelope \
     }; \
     function Write-RustyNetDpapiBlobAtomic { \
         param( \
             [Parameter(Mandatory = $true)][string]$Path, \
             [Parameter(Mandatory = $true)][byte[]]$Bytes \
         ); \
         $parent = Split-Path -Parent $Path; \
         if (-not (Test-Path -LiteralPath $parent -PathType Container)) { \
             throw ('DPAPI blob parent directory missing: ' + $parent) \
         }; \
         $leaf = Split-Path -Leaf $Path; \
         $tmpName = '.' + $leaf + '.' + [System.Diagnostics.Process]::GetCurrentProcess().Id + '.' + [System.Guid]::NewGuid().ToString('N') + '.tmp'; \
         $tmpPath = Join-Path $parent $tmpName; \
         if (Test-Path -LiteralPath $tmpPath) { Remove-Item -LiteralPath $tmpPath -Force }; \
         [System.IO.File]::WriteAllBytes($tmpPath, $Bytes); \
         if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force }; \
         Move-Item -LiteralPath $tmpPath -Destination $Path -Force \
     }; \
     function Remove-RustyNetPlaintextTempFile { \
         param([Parameter(Mandatory = $true)][string]$Path); \
         if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }; \
         try { \
             $len = (Get-Item -LiteralPath $Path -Force).Length; \
             if ($len -gt 0) { \
                 $zeros = New-Object byte[] $len; \
                 [System.IO.File]::WriteAllBytes($Path, $zeros); \
                 [Array]::Clear($zeros, 0, $zeros.Length) \
             } \
         } catch {}; \
         try { Remove-Item -LiteralPath $Path -Force } catch {} \
     }; \
     function Clear-RustyNetSensitiveString { \
         param([Parameter(Mandatory = $true)][string]$Name); \
         try { \
             $val = Get-Variable -Name $Name -Scope 1 -ValueOnly -ErrorAction Stop; \
             if ($val -is [string] -and $val.Length -gt 0) { \
                 $arr = $val.ToCharArray(); \
                 [Array]::Clear($arr, 0, $arr.Length); \
                 Set-Variable -Name $Name -Value '' -Scope 1 \
             } \
         } catch {} \
     }"
    .to_owned()
}

/// Wait for the rustynet0 `WireGuard` adapter to appear with an IPv4 address.
///
/// Called from `enforce_daemon` after the SCM confirms Running.  The daemon
/// sets SCM Running before the daemon thread begins; `WireGuard` tunnel setup
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
         if (-not $wnRdy) { throw 'rustynet WireGuard adapter did not get an IPv4 address within 90s' }".to_owned(),
    )
}

/// Readiness probe: wait for SCM Running state AND for the reviewed env-file
/// and `WireGuard` public-key file to exist.
///
/// The Windows trust CLI (`rustynet.exe`) installed in Program Files is NOT the
/// daemon-control CLI and does not support a `status` sub-command — invoking it
/// with `status` produces a usage error.  Daemon socket / named-pipe readiness
/// is therefore checked by confirming that:
///
/// 1. SCM reports the service as `Running`.
/// 2. The reviewed env-file (`rustynetd.env`) is present — written by the
///    orchestrator before service start.
/// 3. The `WireGuard` public-key file (`wireguard.pub`) is present — generated
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

/// Generate `WireGuard` keys, membership state, and trust evidence for a Windows host.
/// Trust keys are generated locally on the orchestrator (rustynet-cli cannot compile
/// on Windows due to `std::os::unix::`* imports) and SCP'd to the remote host.
/// Called from `install_daemon` after the service binaries are installed.
fn run_windows_e2e_bootstrap(
    conn: &NodeConnection,
    alias: &str,
    ctx: &OrchestrationContext,
) -> Result<(), AdapterError> {
    let node_id = windows_lab_node_id(alias, ctx);
    let network_id = &ctx.network_id;
    let role = ctx
        .assignments
        .iter()
        .find(|a| a.alias == alias)
        .map(|a| &a.role)
        .unwrap_or(&NodeRole::Client);
    let role_str = role
        .daemon_node_role_for_platform(&VmGuestPlatform::Windows)
        .map_err(|message| AdapterError::Protocol { message })?;
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
    let membership_passphrase_q = ps_quote(WINDOWS_MEMBERSHIP_SIGNING_PASSPHRASE_PATH)?;
    let credentials_workspace_q = ps_quote(WINDOWS_CREDENTIALS_WORKSPACE_DIR)?;
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
    //
    // ── Phase 27 reviewer fold-in (BLOCKER 1 + HIGH 1) ─────────────────────
    //
    // BLOCKER 1 (key separation, §3.4): the previous implementation used a
    // single `$pp` to encrypt BOTH the WireGuard private key AND the
    // membership owner-signing key. Compromise of either DPAPI envelope
    // would yield the plaintext for the other. We now generate two
    // statistically independent 48-byte hex passphrases from separate
    // RNGCryptoServiceProvider instances and never reuse plaintext
    // across the WG and signing paths.
    //
    // HIGH 1 (NTFS deleted-block recovery): the previous implementation
    // wrote plaintext to `wireguard.passphrase.dpapi` and
    // `signing_key_passphrase.dpapi` and then atomically renamed the
    // DPAPI-protected blob over the same path. The plaintext bytes
    // remained recoverable in NTFS journal entries indexed by the
    // `.dpapi`-named path. We now:
    //   1. Stage plaintext only to per-key tempfiles under
    //      `C:\ProgramData\RustyNet\credentials-workspace\` (SY/BA-only
    //      ACL inherited from `\ProgramData\RustyNet\`).
    //   2. Run `key init` / `membership init` against those tempfiles
    //      so the daemon can derive the KDFs from plaintext.
    //   3. Call `[System.Security.Cryptography.ProtectedData]::Protect`
    //      in-process on the plaintext bytes (LocalMachine scope).
    //   4. Wrap the protected bytes in the reviewed `RNYDPAPI` envelope
    //      (magic + version + reserved + BE u32 length + protected) so
    //      `decode_windows_dpapi_passphrase_blob` accepts it.
    //   5. Write the envelope directly to the canonical `.dpapi` path
    //      via `[System.IO.File]::WriteAllBytes` — the `.dpapi` path
    //      never sees plaintext bytes on disk.
    //   6. Overwrite the plaintext tempfile with zeros and delete it.
    //   7. Disable PSReadLine / transcripts during the bootstrap script
    //      so the plaintext never lands in a profile history file.
    let bootstrap_script = format!(
        "$ErrorActionPreference = 'Stop'; \
         $ProgressPreference = 'SilentlyContinue'; \
         Add-Type -AssemblyName System.Security; \
         try {{ if (Get-Module -Name PSReadLine) {{ Set-PSReadLineOption -HistorySaveStyle SaveNothing -ErrorAction SilentlyContinue }} }} catch {{}}; \
         {native_helper}; \
         $env:RUSTYNET_WG_BINARY_PATH = {wg_binary_q}; \
         {bootstrap_acl_repair}; \
         New-Item -ItemType Directory -Force -Path (Split-Path {passphrase_q}) | Out-Null; \
         New-Item -ItemType Directory -Force -Path (Split-Path {membership_passphrase_q}) | Out-Null; \
         New-Item -ItemType Directory -Force -Path {credentials_workspace_q} | Out-Null; \
         $wgRng = [System.Security.Cryptography.RandomNumberGenerator]::Create(); \
         $wgBytes = New-Object byte[] 24; \
         $wgRng.GetBytes($wgBytes); \
         $wgPp = -join ($wgBytes | ForEach-Object {{ $_.ToString('x2') }}); \
         $wgRng.Dispose(); \
         [Array]::Clear($wgBytes, 0, $wgBytes.Length); \
         $signingRng = [System.Security.Cryptography.RandomNumberGenerator]::Create(); \
         $signingBytes = New-Object byte[] 24; \
         $signingRng.GetBytes($signingBytes); \
         $signingPp = -join ($signingBytes | ForEach-Object {{ $_.ToString('x2') }}); \
         $signingRng.Dispose(); \
         [Array]::Clear($signingBytes, 0, $signingBytes.Length); \
         if ($wgPp -eq $signingPp) {{ throw 'fail-closed: WG + signing passphrases collided (RNG bug)' }}; \
         $wgPlaintextPath = Join-Path {credentials_workspace_q} ('wg-init.' + [System.Diagnostics.Process]::GetCurrentProcess().Id + '.' + [System.Guid]::NewGuid().ToString('N') + '.tmp'); \
         $signingPlaintextPath = Join-Path {credentials_workspace_q} ('signing-init.' + [System.Diagnostics.Process]::GetCurrentProcess().Id + '.' + [System.Guid]::NewGuid().ToString('N') + '.tmp'); \
         try {{ \
             $utf8NoBom = New-Object System.Text.UTF8Encoding $false; \
             [System.IO.File]::WriteAllText($wgPlaintextPath, $wgPp, $utf8NoBom); \
             [System.IO.File]::WriteAllText($signingPlaintextPath, $signingPp, $utf8NoBom); \
             $keyInit = Invoke-RustyNetBootstrapNative {{ & {rustynetd_q} key init --passphrase-file $wgPlaintextPath --force }}; \
             if ($keyInit.ExitCode -ne 0) {{ throw ('rustynetd key init failed: ' + $keyInit.Output) }}; \
             $mbInit = Invoke-RustyNetBootstrapNative {{ & {rustynetd_q} membership init \
                 --snapshot {membership_snapshot_q} \
                 --log {membership_log_q} \
                 --watermark {membership_watermark_q} \
                 --owner-signing-key {membership_owner_key_q} \
                 --owner-signing-key-passphrase-file $signingPlaintextPath \
                 --node-id {node_id_q} \
                 --network-id {network_id_q} \
                 --force }}; \
             if ($mbInit.ExitCode -ne 0) {{ throw ('rustynetd membership init failed: ' + $mbInit.Output) }}; \
             $wgPlain = [System.Text.Encoding]::UTF8.GetBytes($wgPp); \
             $signingPlain = [System.Text.Encoding]::UTF8.GetBytes($signingPp); \
             $wgProtected = [System.Security.Cryptography.ProtectedData]::Protect($wgPlain, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine); \
             $signingProtected = [System.Security.Cryptography.ProtectedData]::Protect($signingPlain, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine); \
             [Array]::Clear($wgPlain, 0, $wgPlain.Length); \
             [Array]::Clear($signingPlain, 0, $signingPlain.Length); \
             $wgEnvelope = New-RustyNetDpapiEnvelope -ProtectedBytes $wgProtected; \
             $signingEnvelope = New-RustyNetDpapiEnvelope -ProtectedBytes $signingProtected; \
             [Array]::Clear($wgProtected, 0, $wgProtected.Length); \
             [Array]::Clear($signingProtected, 0, $signingProtected.Length); \
             Write-RustyNetDpapiBlobAtomic -Path {passphrase_q} -Bytes $wgEnvelope; \
             Write-RustyNetDpapiBlobAtomic -Path {membership_passphrase_q} -Bytes $signingEnvelope; \
             [Array]::Clear($wgEnvelope, 0, $wgEnvelope.Length); \
             [Array]::Clear($signingEnvelope, 0, $signingEnvelope.Length); \
         }} finally {{ \
             try {{ Clear-RustyNetSensitiveString -Name 'wgPp' }} catch {{}}; \
             try {{ Clear-RustyNetSensitiveString -Name 'signingPp' }} catch {{}}; \
             Remove-RustyNetPlaintextTempFile -Path $wgPlaintextPath; \
             Remove-RustyNetPlaintextTempFile -Path $signingPlaintextPath; \
         }}; \
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
        "version=3\nsigned_control_valid=true\
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
///
/// Shared source of truth: the rule lives in the QH-01 seam module
/// (`validated_args.rs`) so every adapter validates the class identically.
pub(crate) use super::validated_args::validate_windows_path;

fn write_temp_file(
    prefix: &str,
    suffix: &str,
    content: &[u8],
) -> Result<std::path::PathBuf, AdapterError> {
    super::write_secure_temp_file(prefix, suffix, content)
}

// Single source of truth shared with `relay_validation` (the stage that
// checks the deployed service against these exact values) and the legacy
// bash-path `live_linux_relay_test` binary — importing rather than
// duplicating means a future change can't drift the deploy adapter out of
// sync with what the validator checks.
pub(crate) use rustynetd::windows_service_hardening::REVIEWED_WINDOWS_RELAY_SERVICE_NAME as WINDOWS_RELAY_SERVICE_NAME;
use rustynetd::windows_service_hardening::{
    REVIEWED_WINDOWS_RELAY_BIND_PORT, REVIEWED_WINDOWS_RELAY_HEALTH_PORT,
};
const WINDOWS_RUSTYNET_RELAY_PATH: &str = r"C:\Program Files\RustyNet\rustynet-relay.exe";
// Must stay under rustynet-relay's own reviewed root
// (`DEFAULT_WINDOWS_RELAY_ROOT` = `C:\ProgramData\RustyNet\relay` in
// `rustynet-relay/src/main.rs`) — every path the relay's Windows-service
// runtime-arg validator checks (verifier key, replay store, env-file, and
// each one's PARENT) must be this directory or a child of it, or the relay
// process fails closed at startup with a path-policy error.
const WINDOWS_RELAY_ROOT: &str = r"C:\ProgramData\RustyNet\relay";
const WINDOWS_RELAY_VERIFIER_KEY_PATH: &str = r"C:\ProgramData\RustyNet\relay\relay-verifier.pub";
const WINDOWS_RELAY_REPLAY_STORE_PATH: &str = r"C:\ProgramData\RustyNet\relay\relay.replay";
const WINDOWS_RELAY_ENV_FILE_PATH: &str = r"C:\ProgramData\RustyNet\relay\relay-service.env";
const WINDOWS_RELAY_ARGS_ENV_KEY: &str = "RUSTYNET_RELAY_ARGS_JSON";

/// Harden a Windows relay runtime path (directory or file, already created)
/// with a protected, SYSTEM+Administrators-only DACL — the exact ACL shape
/// `rustynet-relay`'s `evaluate_windows_relay_service_acl_sddl` requires:
/// `D:P` (protected, no inherited ACEs), no Everyone/Authenticated-Users/
/// Users grant, SY + BA present, owner SY or BA. Uses well-known SIDs
/// (`*S-1-5-18` = SYSTEM, `*S-1-5-32-544` = Administrators), never display
/// names, so it is correct on any locale.
fn harden_relay_acl_script(path_q: &str) -> String {
    format!(
        "$p = {path_q}; \
         $r = (icacls $p /inheritance:r 2>&1) -join ' '; \
         if ($LASTEXITCODE -ne 0) {{ throw ('icacls /inheritance:r failed for ' + $p + ': ' + $r) }}; \
         $r = (icacls $p /grant:r '*S-1-5-18:F' 2>&1) -join ' '; \
         if ($LASTEXITCODE -ne 0) {{ throw ('icacls grant SYSTEM failed for ' + $p + ': ' + $r) }}; \
         $r = (icacls $p /grant:r '*S-1-5-32-544:F' 2>&1) -join ' '; \
         if ($LASTEXITCODE -ne 0) {{ throw ('icacls grant Administrators failed for ' + $p + ': ' + $r) }}; \
         $r = (icacls $p /setowner '*S-1-5-18' 2>&1) -join ' '; \
         if ($LASTEXITCODE -ne 0) {{ throw ('icacls /setowner SYSTEM failed for ' + $p + ': ' + $r) }}",
    )
}

/// The relay's Windows-service argv, JSON-encoded — the exact contract
/// `rustynet-relay`'s `RUSTYNET_RELAY_ARGS_JSON` env-file variable expects
/// (`parse_windows_relay_service_args_from_text` decodes it as
/// `Vec<String>`). Mirrors the Linux systemd unit's `ExecStart` argv
/// (`scripts/systemd/rustynet-relay.service`) so the two platforms run the
/// relay with equivalent posture (same port range / session caps), modulo
/// Windows-appropriate paths.
fn relay_windows_service_args_json() -> Result<String, AdapterError> {
    let args = vec![
        "--relay-id".to_owned(),
        "relay-windows".to_owned(),
        "--bind".to_owned(),
        format!("127.0.0.1:{REVIEWED_WINDOWS_RELAY_BIND_PORT}"),
        "--verifier-key".to_owned(),
        WINDOWS_RELAY_VERIFIER_KEY_PATH.to_owned(),
        "--replay-store".to_owned(),
        WINDOWS_RELAY_REPLAY_STORE_PATH.to_owned(),
        "--port-range".to_owned(),
        "40000-49999".to_owned(),
        "--max-sessions-per-node".to_owned(),
        "8".to_owned(),
        "--max-total-sessions".to_owned(),
        "4096".to_owned(),
        "--health-bind".to_owned(),
        format!("127.0.0.1:{REVIEWED_WINDOWS_RELAY_HEALTH_PORT}"),
    ];
    serde_json::to_string(&args).map_err(|err| AdapterError::Protocol {
        message: format!("failed to encode relay Windows-service args: {err}"),
    })
}

/// Build the PS script that creates (idempotently) the relay SCM service,
/// pointed at the binary with `--windows-service --service-name <name>
/// --env-file <path>` — the arguments `rustynet-relay` requires to enter its
/// Windows-service dispatch path at all (live-lab evidence: without them,
/// `sc.exe create`/`start` succeed but the process never calls
/// `StartServiceCtrlDispatcher`, and SCM kills the start with error 1053,
/// "did not respond ... in a timely fashion").
///
/// Self-healing, not merely create-if-missing: an EXISTING service gets its
/// binPath reconfigured via `sc.exe config` to match the desired command
/// line every deploy, rather than being left as whatever it was created
/// with on a prior (possibly broken) run — the create-only version of this
/// script left a stale, mis-wired service registration on the guest after
/// the binPath contract changed, silently skipping the fix on redeploy.
///
/// `svc_q` is reused for the `Get-Service`/`sc.exe create`/`sc.exe config`
/// arguments AND for the failure messages — it must be concatenated as its
/// own token (`+`) into each `throw (...)` string, never interpolated
/// inside another single-quoted literal: `ps_quote` already wraps it in its
/// own `'...'`, and PowerShell does not support nesting an unescaped quoted
/// string inside another one of the same quote style (live-lab evidence:
/// this exact nesting bug also reached a real Windows guest and broke
/// `sc.exe create` with a `ParserError`).
fn relay_create_service_script(
    service_name: &str,
    binary_path: &str,
    env_file_path: &str,
) -> Result<String, AdapterError> {
    let svc_q = ps_quote(service_name)?;
    // The exe path and env-file path need embedded quoting (Windows binPath
    // parsing must know where the space-containing exe path ends and the
    // first flag begins), but PowerShell handing a variable with BARE `"`
    // characters to a native command via `&` lets Win32 argv parsing
    // (CommandLineToArgvW) treat each embedded `"..."` as a fresh token
    // boundary, silently re-splitting what was meant to be one binPath
    // argument into several — `sc.exe` then sees unrecognized bare tokens
    // and dumps its USAGE text instead of erroring on the real problem
    // (live-lab evidence: `sc.exe config` failed exactly this way once the
    // dispatch-args fix above added a multi-token binPath value). Escaping
    // the inner quotes as `\"` keeps them as literal characters within the
    // single argv token, matching the standard `sc.exe binPath=
    // "\"<exe>\" <args>"` idiom.
    let bin_cmdline = format!(
        "\\\"{binary_path}\\\" --windows-service --service-name {service_name} --env-file \\\"{env_file_path}\\\""
    );
    let bin_q = ps_quote(&bin_cmdline)?;
    Ok(format!(
        "$svc = Get-Service -Name {svc_q} -ErrorAction SilentlyContinue; \
         $bin = {bin_q}; \
         if ($null -eq $svc) {{ \
             $scOut = (& sc.exe create {svc_q} binPath= $bin start= auto 2>&1) -join ' '; \
             if ($LASTEXITCODE -ne 0) {{ throw ('sc.exe create ' + {svc_q} + ' failed: ' + $scOut) }} \
         }} else {{ \
             $scOut = (& sc.exe config {svc_q} binPath= $bin start= auto 2>&1) -join ' '; \
             if ($LASTEXITCODE -ne 0) {{ throw ('sc.exe config ' + {svc_q} + ' failed: ' + $scOut) }} \
         }}",
    ))
}

pub(crate) fn deploy_relay_service(conn: &NodeConnection) -> Result<(), AdapterError> {
    let short_timeout = Duration::from_secs(30);

    let assignment_pub_path = format!(r"{WINDOWS_STATE_ROOT}\trust\assignment.pub");
    // QH-01 Step 4c: single-cmdlet read rendered through the validated seam
    // (the path is windows-path-validated and ps-quoted before any command
    // string exists).
    let read_argv = [
        ValidatedArg::cli_token("Get-Content")?,
        ValidatedArg::cli_token("-LiteralPath")?,
        ValidatedArg::windows_path(&assignment_pub_path)?,
        ValidatedArg::cli_token("-Raw")?,
    ];
    let read_script =
        PowerShellScript::from_call_argv("windows read assignment pubkey", &read_argv)?;
    let assignment_hex = run_remote_ps(conn, read_script.as_str(), short_timeout)?
        .trim()
        .to_owned();
    if assignment_hex.is_empty() {
        return Err(AdapterError::Protocol {
            message: "assignment authority pubkey empty or missing; distributed verifier key required before relay deploy".to_owned(),
        });
    }
    let verifier_bytes =
        crate::vm_lab::orchestrator::adapter::verifier_key::decode_assignment_pubkey_hex(
            &assignment_hex,
        )
        .map_err(|message| AdapterError::Protocol { message })?;

    // 1. Create the relay's reviewed runtime root and harden it (protected,
    //    SYSTEM+Administrators-only DACL) BEFORE anything is placed inside —
    //    every file placed under it gets its own explicit hardening too
    //    (below), since the relay's ACL validator requires each individual
    //    file protected, not merely inheriting from an already-hardened
    //    parent (an inherited DACL reads "AI" in SDDL, not the required "P").
    let root_q = ps_quote(WINDOWS_RELAY_ROOT)?;
    let mkroot_script = format!(
        "New-Item -ItemType Directory -Force -Path {root_q} | Out-Null; {}",
        harden_relay_acl_script(&root_q)
    );
    run_remote_ps(conn, &mkroot_script, short_timeout)?;

    // 2. Ship + install the verifier key under the reviewed root, then harden.
    let tmp = write_temp_file("rn_relay_verifier_", ".pub", &verifier_bytes)?;
    let remote_tmp = format!(r"{WINDOWS_STAGING_DIR}\rn-relay-verifier.pub");
    let ship = ssh::scp_to(
        conn,
        tmp.as_path(),
        &remote_tmp.replace('\\', "/"),
        short_timeout,
    );
    let _ = std::fs::remove_file(&tmp);
    ship?;
    let verifier_q = ps_quote(WINDOWS_RELAY_VERIFIER_KEY_PATH)?;
    let install_verifier_script = format!(
        "Set-StrictMode -Version Latest; \
         $ErrorActionPreference = 'Stop'; \
         $ProgressPreference = 'SilentlyContinue'; \
         Move-Item -LiteralPath {src_q} -Destination {verifier_q} -Force; \
         {harden}",
        src_q = ps_quote(&remote_tmp)?,
        harden = harden_relay_acl_script(&verifier_q),
    );
    run_remote_ps(conn, &install_verifier_script, short_timeout)?;

    // 3. Pre-create an empty, hardened replay-store file. The relay's
    //    Windows-service runtime-arg validator checks the FILE's own ACL
    //    (not just its parent), so leaving it for the relay process to
    //    create at first run would produce an inherited (non-protected) DACL
    //    that fails the same check the verifier key must pass.
    let replay_q = ps_quote(WINDOWS_RELAY_REPLAY_STORE_PATH)?;
    let replay_store_script = format!(
        "if (-not (Test-Path -LiteralPath {replay_q})) {{ \
             New-Item -ItemType File -Force -Path {replay_q} | Out-Null \
         }}; \
         {harden}",
        harden = harden_relay_acl_script(&replay_q),
    );
    run_remote_ps(conn, &replay_store_script, short_timeout)?;

    // 4. Ship + install the Windows-service env-file (RUSTYNET_RELAY_ARGS_JSON)
    //    under the reviewed root, then harden — the argv `rustynet-relay`
    //    needs to actually enter its SCM dispatch path (see
    //    `relay_create_service_script`'s doc comment).
    let args_json = relay_windows_service_args_json()?;
    let env_file_contents = format!("{WINDOWS_RELAY_ARGS_ENV_KEY}={args_json}\r\n");
    let tmp_env = write_temp_file("rn_relay_env_", ".env", env_file_contents.as_bytes())?;
    let remote_tmp_env = format!(r"{WINDOWS_STAGING_DIR}\rn-relay-service.env");
    let ship_env = ssh::scp_to(
        conn,
        tmp_env.as_path(),
        &remote_tmp_env.replace('\\', "/"),
        short_timeout,
    );
    let _ = std::fs::remove_file(&tmp_env);
    ship_env?;
    let env_q = ps_quote(WINDOWS_RELAY_ENV_FILE_PATH)?;
    let install_env_script = format!(
        "Set-StrictMode -Version Latest; \
         $ErrorActionPreference = 'Stop'; \
         $ProgressPreference = 'SilentlyContinue'; \
         Move-Item -LiteralPath {src_q} -Destination {env_q} -Force; \
         {harden}",
        src_q = ps_quote(&remote_tmp_env)?,
        harden = harden_relay_acl_script(&env_q),
    );
    run_remote_ps(conn, &install_env_script, short_timeout)?;

    let create_svc_script = relay_create_service_script(
        WINDOWS_RELAY_SERVICE_NAME,
        WINDOWS_RUSTYNET_RELAY_PATH,
        WINDOWS_RELAY_ENV_FILE_PATH,
    )?;
    run_remote_ps(conn, &create_svc_script, short_timeout)?;

    let probe = windows_service_start_probe_fragment(WINDOWS_RELAY_SERVICE_NAME)?;
    let start_script = format!(
        "Set-StrictMode -Version Latest; \
         $ErrorActionPreference = 'Stop'; \
         $ProgressPreference = 'SilentlyContinue'; \
         {probe}",
    );
    run_remote_ps(
        conn,
        &start_script,
        Duration::from_secs(WINDOWS_SERVICE_START_PROBE_MAX_SECS + 60),
    )?;

    Ok(())
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

    /// QH-24 content pin for the Windows fail-closed enforcement path: the
    /// patch script must flip `--auto-tunnel-enforce` to `true` under
    /// StrictMode, thread both freshness ceilings, keep the C-STUN gateway
    /// threading, and write the result back. A regression that drops the
    /// flip — or writes anything but `true` — leaves the daemon in
    /// non-enforcing mode (empty dataplane, no mesh adapter) while every
    /// downstream stage believes it is enforcing.
    #[test]
    fn auto_tunnel_enforce_patch_script_flips_enforce_and_threads_max_ages() {
        let script =
            build_auto_tunnel_enforce_patch_script(r"C:\ProgramData\RustyNet\config\rustynetd.env")
                .expect("patch script should render");

        // Strict mode + Stop: a silent partial failure must terminate.
        assert!(
            script.contains("Set-StrictMode -Version Latest")
                && script.contains("$ErrorActionPreference = 'Stop'"),
            "the patch must run strict and fail loudly: {script}"
        );
        // The DAEMON_ARGS_JSON line is matched, stripped, parsed as JSON.
        assert!(
            script.contains("$_ -match '^RUSTYNETD_DAEMON_ARGS_JSON='")
                && script.contains("ConvertFrom-Json")
                && script.contains("ConvertTo-Json -Compress"),
            "the args line must be round-tripped through JSON: {script}"
        );
        // THE flip: the value following --auto-tunnel-enforce becomes 'true'.
        // This is the fail-closed posture of the whole path.
        assert!(
            script.contains("'--auto-tunnel-enforce'")
                && script.contains("$arr[$idx + 1] = 'true'"),
            "the patch must set --auto-tunnel-enforce to true: {script}"
        );
        assert!(
            !script.contains("'false'"),
            "the enforce patch must never be able to write 'false': {script}"
        );
        // Freshness ceilings: added when absent, refreshed when present.
        for flag in ["--auto-tunnel-max-age-secs", "--dns-zone-max-age-secs"] {
            assert!(
                script.contains(&format!("'{flag}'")) && script.contains("'86400'"),
                "freshness ceiling {flag} must be threaded: {script}"
            );
        }
        // C-STUN threading: gateway regex-guarded, port 3478.
        assert!(
            script.contains("'--traversal-stun-servers'") && script.contains("':3478'"),
            "the STUN gateway threading must be preserved: {script}"
        );
        assert!(
            script.contains("^[0-9]{1,3}(\\.[0-9]{1,3}){3}$"),
            "the gateway must be IPv4-regex-guarded before interpolation: {script}"
        );
        // The patched array is written back to the env file.
        assert!(
            script.contains("Out-File -Encoding ASCII $envPath"),
            "the patched args must be written back: {script}"
        );
        // The env path is the reviewed state-root config file, quoted.
        assert!(
            script.contains(&ps_quote(r"C:\ProgramData\RustyNet\config\rustynetd.env").unwrap()),
            "the rendered script must target the quoted env path: {script}"
        );
    }

    #[test]
    fn bootstrap_script_has_offline_build_fallback() {
        // Live-lab guests have no internet egress, so the Windows build must fall
        // back to --offline from the seeded cargo cache when the registry is
        // unreachable, mirroring the Linux/macOS bootstrap. Without it the build
        // dies trying to fetch a bench-only dep (criterion) with
        // "Could not resolve host: index.crates.io".
        assert!(
            BOOTSTRAP_SCRIPT.contains("$daemonBuildArgsOffline = $daemonBuildArgs + '--offline'"),
            "Windows daemon build must define an --offline fallback variant"
        );
        assert!(
            BOOTSTRAP_SCRIPT
                .contains("$trustCliBuildArgsOffline = $trustCliBuildArgs + '--offline'"),
            "Windows trust-CLI build must define an --offline fallback variant"
        );
        // The fallback must be invoked, not merely defined (both build paths).
        assert!(
            BOOTSTRAP_SCRIPT.matches("$daemonBuildArgsOffline").count() >= 2,
            "the daemon --offline fallback must be invoked, not just defined"
        );
    }

    #[test]
    fn relay_create_service_script_does_not_nest_a_quoted_literal_inside_another() {
        // Regression test for a real live-lab failure: PowerShell CLIXML
        // ParserError "Unexpected token 'RustyNetRelay' failed: '' in
        // expression or statement" from `sc.exe create 'RustyNetRelay'
        // binPath= ...` — caused by embedding the already-single-quoted
        // service name directly inside another single-quoted throw message
        // literal, e.g. `'sc.exe create 'RustyNetRelay' failed: '`.
        let script = relay_create_service_script(
            "RustyNetRelay",
            r"C:\Program Files\RustyNet\rustynet-relay.exe",
            r"C:\ProgramData\RustyNet\relay\relay-service.env",
        )
        .expect("script build should succeed for a plain service name");
        assert!(
            !script.contains("'sc.exe create 'RustyNetRelay' failed"),
            "must not nest the quoted service name inside another single-quoted \
             literal (invalid PowerShell): {script}"
        );
        assert!(
            script.contains("'sc.exe create ' + 'RustyNetRelay' + ' failed: '"),
            "the quoted service name must be concatenated as its own token via `+`: {script}"
        );
        // sc.exe create + Get-Service both still receive the correctly quoted
        // service name as a standalone argument.
        assert!(script.contains("Get-Service -Name 'RustyNetRelay'"));
        assert!(script.contains("sc.exe create 'RustyNetRelay' binPath="));
    }

    #[test]
    fn relay_create_service_script_escapes_a_service_name_containing_a_quote() {
        // ps_quote doubles embedded single quotes; confirm that survives the
        // concatenation unbroken for both the argument and message uses.
        let script = relay_create_service_script("Rusty'Net", r"C:\bin.exe", r"C:\env.env")
            .expect("script build should succeed for a name containing a quote");
        assert!(script.contains("'Rusty''Net'"));
    }

    #[test]
    fn relay_create_service_script_binpath_enters_windows_service_dispatch() {
        // Regression test for the follow-on live-lab failure once the quoting
        // bug above was fixed: `sc.exe create`/`start` succeeded, but SCM
        // killed the start with error 1053 ("did not respond ... in a timely
        // fashion") because binPath launched the bare exe with no arguments,
        // so `rustynet-relay` never entered its Windows-service dispatch path
        // (which requires `--windows-service --env-file <path>`).
        let script = relay_create_service_script(
            "RustyNetRelay",
            r"C:\Program Files\RustyNet\rustynet-relay.exe",
            r"C:\ProgramData\RustyNet\relay\relay-service.env",
        )
        .expect("script build should succeed");
        // Inner quotes must be backslash-escaped (`\"`), not bare (`"`) —
        // live-lab evidence: a bare-quoted multi-arg binPath value gets
        // re-split by Win32 argv parsing when PowerShell hands it to a
        // native command via `&`, and `sc.exe` dumps its USAGE text instead
        // of applying the config.
        assert!(
            script.contains(
                r#"'\"C:\Program Files\RustyNet\rustynet-relay.exe\" --windows-service --service-name RustyNetRelay --env-file \"C:\ProgramData\RustyNet\relay\relay-service.env\"'"#
            ),
            "binPath must invoke the exe with --windows-service + --env-file, with \
             backslash-escaped inner quotes so it survives as one argv token: {script}"
        );
    }

    #[test]
    fn relay_create_service_script_reconfigures_an_existing_service_instead_of_skipping() {
        // Regression test: a stale service left by a prior (broken) deploy
        // must have its binPath corrected on redeploy, not silently keep the
        // old wrong config just because Get-Service found it already exists.
        let script = relay_create_service_script(
            "RustyNetRelay",
            r"C:\Program Files\RustyNet\rustynet-relay.exe",
            r"C:\ProgramData\RustyNet\relay\relay-service.env",
        )
        .expect("script build should succeed");
        assert!(
            script.contains("sc.exe config 'RustyNetRelay' binPath="),
            "an existing service must be reconfigured via sc.exe config: {script}"
        );
        assert!(
            !script.contains("'sc.exe config 'RustyNetRelay' failed"),
            "the config-branch error message must not nest quotes either: {script}"
        );
    }

    #[test]
    fn relay_windows_service_args_json_includes_the_full_relay_contract() {
        let encoded = relay_windows_service_args_json().expect("args JSON encoding should succeed");
        let args: Vec<String> =
            serde_json::from_str(&encoded).expect("must round-trip as a JSON string array");
        // Mirrors the Linux systemd unit's ExecStart argv contract exactly —
        // rustynet-relay requires --verifier-key and --replay-store to start.
        for flag in [
            "--relay-id",
            "--bind",
            "--verifier-key",
            "--replay-store",
            "--port-range",
            "--max-sessions-per-node",
            "--max-total-sessions",
            "--health-bind",
        ] {
            assert!(args.iter().any(|a| a == flag), "missing {flag}: {args:?}");
        }
        assert!(args.contains(&WINDOWS_RELAY_VERIFIER_KEY_PATH.to_owned()));
        assert!(args.contains(&WINDOWS_RELAY_REPLAY_STORE_PATH.to_owned()));
        // Both runtime paths must live under the relay's own reviewed root,
        // or `rustynet-relay` fails closed on startup (path-policy gate).
        for path in [
            WINDOWS_RELAY_VERIFIER_KEY_PATH,
            WINDOWS_RELAY_REPLAY_STORE_PATH,
        ] {
            assert!(
                path.starts_with(WINDOWS_RELAY_ROOT),
                "{path} must be under the reviewed relay root {WINDOWS_RELAY_ROOT}"
            );
        }
        // Regression pin: NOT 4500/4501 — 4500 is Windows's reserved
        // IKEEXT/IPsec NAT-T port; binding it crashed the service on every
        // real live-lab attempt (WSAEACCES / os error 10013). Must match
        // rustynetd's REVIEWED_WINDOWS_RELAY_BIND_PORT /
        // REVIEWED_WINDOWS_RELAY_HEALTH_PORT — the exact values
        // `relay_validation` checks the deployed service against.
        assert!(args.contains(&"127.0.0.1:4600".to_owned()), "{args:?}");
        assert!(args.contains(&"127.0.0.1:9100".to_owned()), "{args:?}");
        assert!(!args.iter().any(|a| a.contains(":4500")), "{args:?}");
        assert!(!args.iter().any(|a| a.contains(":4501")), "{args:?}");
    }

    #[test]
    fn harden_relay_acl_script_uses_locale_independent_sids_and_protects_inheritance() {
        let script = harden_relay_acl_script("'C:\\ProgramData\\RustyNet\\relay'");
        assert!(script.contains("/inheritance:r"), "{script}");
        assert!(
            script.contains("*S-1-5-18:F"),
            "must grant SYSTEM by well-known SID, not display name: {script}"
        );
        assert!(
            script.contains("*S-1-5-32-544:F"),
            "must grant Administrators by well-known SID, not display name: {script}"
        );
        assert!(
            script.contains("/setowner '*S-1-5-18'"),
            "owner must be set to SYSTEM by SID: {script}"
        );
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
            BOOTSTRAP_SCRIPT.contains("Ensure-CargoBuildJobsForWindowsLab"),
            "bootstrap build-release must cap cargo parallelism by default for low-memory Windows lab guests"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("cargo_build_jobs"),
            "bootstrap build-release report must record effective cargo parallelism"
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

    /// QH-17: the lab-image provisioning script must not mutate the
    /// machine cargo/rustup environment when -SkipRustup is passed, and
    /// VS Build Tools component selection must come from the single
    /// authoritative vsconfig (no inline component list).
    #[test]
    fn provision_lab_image_script_respects_skip_rustup_and_single_vsconfig() {
        assert!(
            !PROVISION_LAB_IMAGE_SCRIPT.is_empty(),
            "Provision-RustyNetWindowsLabImage.ps1 must not be empty"
        );
        // Fix 1: the -SkipRustup guard must precede the machine env
        // mutation so a skip run leaves CARGO_HOME/RUSTUP_HOME/PATH
        // untouched.
        let guard = PROVISION_LAB_IMAGE_SCRIPT
            .find("if ($SkipRustup)")
            .expect("provision script must gate on -SkipRustup");
        let cargo_env = PROVISION_LAB_IMAGE_SCRIPT
            .find("Set-MachineEnv -Name 'CARGO_HOME'")
            .expect("provision script must set machine CARGO_HOME when installing");
        assert!(
            guard < cargo_env,
            "machine CARGO_HOME mutation must sit inside the -SkipRustup guard (QH-17)"
        );
        assert!(
            PROVISION_LAB_IMAGE_SCRIPT
                .contains("skipped machine toolchain env mutation (-SkipRustup)"),
            "skip run must record that the toolchain env was left untouched"
        );
        // Fix 2: component selection comes from the vsconfig, never an
        // inline --add list; exactly one SDK component id exists repo-wide.
        assert!(
            PROVISION_LAB_IMAGE_SCRIPT.contains("--config"),
            "provision script must pass --config <vsconfig> to vs_BuildTools.exe"
        );
        assert!(
            PROVISION_LAB_IMAGE_SCRIPT.contains("RustyNetBuildTools.vsconfig"),
            "provision script must reference the shared vsconfig"
        );
        assert!(
            !PROVISION_LAB_IMAGE_SCRIPT.contains("Windows11SDK"),
            "no inline SDK component id may remain in the provision script (QH-17)"
        );
        assert!(
            !PROVISION_LAB_IMAGE_SCRIPT.contains("'--add'"),
            "no inline --add component list may remain in the provision script (QH-17)"
        );
        assert!(
            VSCONFIG_FILE.contains("Microsoft.VisualStudio.Component.Windows11SDK.26100"),
            "vsconfig is the authoritative SDK component definition (.26100)"
        );
        assert!(
            !VSCONFIG_FILE.contains("22621"),
            "stale SDK id 22621 must not reappear (QH-17)"
        );
    }

    /// W-FIX-1 (CP-4 Windows bootstrap triage verdict, 2026-08-28).
    ///
    /// `winget configure` is an opt-in WinGet feature that ships disabled.
    /// The bootstrap hard-depends on it — it is what installs Git,
    /// PowerShell 7, rustup and WireGuard — so a fresh Windows guest failed
    /// bootstrap deterministically until the script started enabling the
    /// feature itself. Pin both halves of the fix (state collection and the
    /// enable-before-configure step) so neither can be dropped silently:
    /// PowerShell has no unit-test harness in this repository, and the
    /// content pin is the only regression guard the script has.
    #[test]
    fn bootstrap_script_enables_winget_configuration_feature_before_configuring() {
        assert!(
            BOOTSTRAP_SCRIPT.contains("function Get-WingetConfigurationFeatureState"),
            "bootstrap must probe whether the opt-in WinGet Configuration feature is enabled"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("winget_configuration_enabled"),
            "bootstrap tooling-state report must record the WinGet Configuration feature state"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("function Enable-WingetConfigurationFeature"),
            "bootstrap must enable the WinGet Configuration feature rather than assuming it"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("winget.exe configure --enable"),
            "bootstrap must run `winget configure --enable`; the bootstrap already runs elevated"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("Enable-WingetConfigurationFeature -State $state"),
            "Ensure-WingetConfigurationDependencies must enable the feature before `winget configure --file`"
        );
        assert!(
            BOOTSTRAP_SCRIPT
                .contains("WinGet Configuration feature is not enabled and could not be enabled"),
            "failing to enable the feature must fail closed with a named, actionable error"
        );

        // Ordering: the enable step has to precede the configure invocation
        // it exists to unblock, otherwise the fix is inert.
        let enable_call = BOOTSTRAP_SCRIPT
            .find("Enable-WingetConfigurationFeature -State $state")
            .expect("enable call must be present");
        let configure_call = BOOTSTRAP_SCRIPT
            .find("& winget configure --file $candidate")
            .expect("configure invocation must be present");
        assert!(
            enable_call < configure_call,
            "the WinGet Configuration enable step must run before `winget configure --file`"
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
    fn install_service_script_provisions_membership_credentials_workspace() {
        assert!(
            WINDOWS_CREDENTIALS_WORKSPACE_DIR.ends_with(r"credentials-workspace"),
            "credentials workspace path must be canonical: {WINDOWS_CREDENTIALS_WORKSPACE_DIR}"
        );
        assert!(
            INSTALL_SERVICE_SCRIPT.contains("(Join-Path $StateRoot 'credentials-workspace')"),
            "install helper must create and ACL-repair the membership credential workspace"
        );
        assert!(
            INSTALL_SERVICE_SCRIPT.contains("credentials_workspace_present"),
            "install report must expose credentials workspace presence"
        );
    }

    /// Returns the implementation slice of `windows_install.rs` — the
    /// source above the `#[cfg(test)] mod tests` marker. The
    /// source-pin tests below must check the implementation, not the
    /// test fixtures themselves; a naive `include_str!` would match
    /// patterns referenced in the test assertions (false-positive on
    /// the `assert!(!source.contains(...))` invariants).
    fn windows_install_impl_source() -> &'static str {
        let full = include_str!("windows_install.rs");
        full.split("#[cfg(test)]")
            .next()
            .expect("implementation slice must precede tests")
    }

    #[test]
    fn e2e_bootstrap_provisions_windows_membership_signing_passphrase_blob() {
        assert!(
            WINDOWS_MEMBERSHIP_SIGNING_PASSPHRASE_PATH
                .ends_with(r"secrets\signing_key_passphrase.dpapi"),
            "membership signing passphrase must use the reviewed DPAPI blob name: {WINDOWS_MEMBERSHIP_SIGNING_PASSPHRASE_PATH}"
        );
        let source = windows_install_impl_source();
        assert!(
            source.contains("WINDOWS_MEMBERSHIP_SIGNING_PASSPHRASE_PATH"),
            "Windows e2e bootstrap must carry the membership signing passphrase path"
        );
        assert!(
            source.contains("membership_passphrase_q"),
            "Windows e2e bootstrap must quote the membership signing passphrase path"
        );
        // Phase 27 reviewer fold-in (HIGH 1): the canonical
        // `.dpapi` paths must never see plaintext bytes on disk.
        // PowerShell now pre-encrypts the passphrase via DPAPI and
        // writes only the reviewed `RNYDPAPI` envelope to the
        // canonical path. Pin both the helper that builds the
        // envelope and the atomic-write helper that lands it on the
        // membership-signing path.
        assert!(
            source.contains("Write-RustyNetDpapiBlobAtomic -Path {membership_passphrase_q}"),
            "Windows e2e bootstrap must write the membership signing DPAPI envelope atomically to the canonical path"
        );
        assert!(
            source.contains("New-RustyNetDpapiEnvelope"),
            "Windows e2e bootstrap must wrap the DPAPI protected bytes in the reviewed RNYDPAPI envelope"
        );
        assert!(
            !source.contains("[System.IO.File]::WriteAllText({membership_passphrase_q}"),
            "Windows e2e bootstrap must NOT write plaintext to the membership signing .dpapi path (HIGH 1)"
        );
        assert!(
            !source.contains("[System.IO.File]::WriteAllText({passphrase_q}"),
            "Windows e2e bootstrap must NOT write plaintext to the WG .dpapi path (HIGH 1)"
        );
    }

    /// Phase 27 reviewer fold-in (BLOCKER 1, §3.4 key separation):
    /// the WG and signing passphrases MUST be derived from independent
    /// RNG instances and MUST never share plaintext source material.
    /// Pin the source-level invariants so a future refactor cannot
    /// silently revert to a shared `$pp`.
    #[test]
    fn e2e_bootstrap_uses_distinct_wg_and_signing_passphrases() {
        let source = windows_install_impl_source();
        assert!(
            source.contains(
                "$wgRng = [System.Security.Cryptography.RandomNumberGenerator]::Create()"
            ),
            "Windows e2e bootstrap must instantiate a dedicated RNG for the WG passphrase"
        );
        assert!(
            source.contains(
                "$signingRng = [System.Security.Cryptography.RandomNumberGenerator]::Create()"
            ),
            "Windows e2e bootstrap must instantiate a dedicated RNG for the membership signing passphrase"
        );
        assert!(
            source.contains("if ($wgPp -eq $signingPp)"),
            "Windows e2e bootstrap must fail closed if the WG and signing passphrases collide"
        );
        assert!(
            !source.contains("$pp = -join"),
            "Windows e2e bootstrap must NOT reuse a single $pp for WG + signing (BLOCKER 1)"
        );
    }

    /// Phase 27 reviewer fold-in (HIGH 1, NTFS deleted-block recovery):
    /// pin the helper-fragment invariants so the canonical `.dpapi`
    /// paths only ever receive DPAPI-protected bytes wrapped in the
    /// reviewed `RNYDPAPI` envelope.
    #[test]
    fn bootstrap_native_helper_defines_dpapi_envelope_and_shred() {
        let script = windows_bootstrap_native_helper_fragment();

        assert!(
            script.contains("function New-RustyNetDpapiEnvelope"),
            "bootstrap helper must define the RNYDPAPI envelope builder"
        );
        assert!(
            script.contains("function Write-RustyNetDpapiBlobAtomic"),
            "bootstrap helper must define an atomic blob writer"
        );
        assert!(
            script.contains("function Remove-RustyNetPlaintextTempFile"),
            "bootstrap helper must define the plaintext-shred routine"
        );
        assert!(
            script.contains("0x52,0x4E,0x59,0x44,0x50,0x41,0x50,0x49"),
            "RNYDPAPI envelope must embed the reviewed 8-byte magic (matches decode_windows_dpapi_passphrase_blob)"
        );
        // The Protect invocation itself lives at the call-site
        // (`run_windows_e2e_bootstrap`), pinned via the source-grep
        // test `e2e_bootstrap_provisions_windows_membership_signing_passphrase_blob`.
        let source = windows_install_impl_source();
        assert!(
            source.contains("[System.Security.Cryptography.ProtectedData]::Protect"),
            "bootstrap script must invoke ProtectedData::Protect on the in-memory plaintext (HIGH 1)"
        );
        // The ProtectedData type lives in System.Security.dll, which is NOT
        // auto-loaded under `powershell.exe -NoProfile -NonInteractive`; the
        // bootstrap must Add-Type it first or the call fails with TypeNotFound.
        assert!(
            source.contains("Add-Type -AssemblyName System.Security"),
            "bootstrap script must load System.Security before using ProtectedData"
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
        // Bootstrap-RustyNetWindows.ps1 is SCP'd standalone into the staging
        // dir without its scripts\bootstrap\windows\ siblings, so its default
        // $PSScriptRoot-relative winget/vsconfig lookup can never find them —
        // the call must point at the extracted source tree explicitly.
        assert!(
            script.contains(r"-WingetConfigPath 'C:\Rustynet\scripts\bootstrap\windows\RustyNetBootstrap.winget.yml'"),
            "must point WingetConfigPath at the extracted source tree, not $PSScriptRoot: {script}"
        );
        assert!(
            script.contains(
                r"-VsConfigPath 'C:\Rustynet\scripts\bootstrap\windows\RustyNetBuildTools.vsconfig'"
            ),
            "must point VsConfigPath at the extracted source tree, not $PSScriptRoot: {script}"
        );
    }

    #[test]
    fn build_windows_service_install_script_threads_node_id_and_role() {
        let script = build_windows_service_install_script(
            r"C:\Rustynet",
            r"C:\Windows\Temp\rustynet-stage\Install-RustyNetWindowsService.ps1",
            "RustyNet",
            "windows-utm-1",
            "client",
        )
        .expect("install script should render");

        assert!(script.contains("-ServiceName 'RustyNet'"));
        assert!(script.contains("-NodeId 'windows-utm-1'"));
        assert!(
            script.contains("-NodeRole 'client'"),
            "orchestrator must pass --node-role to the Windows install helper \
             (the daemon defaults to admin otherwise → membership role mismatch \
             fails reconcile closed for a client node — the N4 fix-3 bug)"
        );
        assert!(
            INSTALL_SERVICE_SCRIPT.contains("[string]$NodeId"),
            "Windows install helper must accept the node id passed by the orchestrator"
        );
        assert!(
            INSTALL_SERVICE_SCRIPT.contains("[string]$NodeRole"),
            "Windows install helper must accept the node role passed by the orchestrator"
        );
        // Parity: the reviewed install helper's daemon-arg builder must emit
        // every required launch flag, so this platform can never silently drop
        // one (the class of bug behind the N4 failures).
        for flag in crate::vm_lab::orchestrator::adapter::node_adapter::REQUIRED_DAEMON_LAUNCH_FLAGS
        {
            assert!(
                INSTALL_SERVICE_SCRIPT.contains(&format!("'{flag}'")),
                "Windows daemon-args builder is missing required launch flag {flag}"
            );
        }
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
        // The timeout only needs to cover: key init, membership init, the
        // PowerShell-side DPAPI protect + atomic envelope write for both
        // the WG and signing passphrases (Phase 27 reviewer fold-in: the
        // previous `key store-passphrase` invocations were replaced with
        // in-PowerShell `ProtectedData::Protect`), and runtime-acls-check.
        assert!(
            WINDOWS_E2E_BOOTSTRAP_TIMEOUT.as_secs() > 120,
            "bootstrap timeout must leave budget for key init, membership init, and ACL checks"
        );
    }

    // ── QH-15: Windows build budget is configurable and relabeled ───────────

    fn build_outcome_message(err: &AdapterError) -> &str {
        match err {
            AdapterError::Ssh { message } => message,
            AdapterError::Protocol { message } => message,
            AdapterError::Command { stderr, .. } => stderr,
            other => panic!("unexpected adapter error variant: {other:?}"),
        }
    }

    #[test]
    fn windows_build_timeout_defaults_when_env_unset_or_blank() {
        assert_eq!(
            windows_build_timeout_from_env(None).unwrap(),
            Duration::from_secs(DEFAULT_WINDOWS_BUILD_TIMEOUT_SECS),
            "unset env must select the 3600s default"
        );
        for blank in ["", "   ", "\t"] {
            assert_eq!(
                windows_build_timeout_from_env(Some(blank)).unwrap(),
                Duration::from_secs(DEFAULT_WINDOWS_BUILD_TIMEOUT_SECS),
                "blank env {blank:?} must select the default, not fail"
            );
        }
        assert_eq!(
            DEFAULT_WINDOWS_BUILD_TIMEOUT_SECS, 3600,
            "default budget must keep the historical 3600s headroom"
        );
    }

    #[test]
    fn windows_build_timeout_honors_positive_override() {
        assert_eq!(
            windows_build_timeout_from_env(Some("5400")).unwrap(),
            Duration::from_secs(5400),
            "a positive integer override must be honored verbatim"
        );
    }

    #[test]
    fn windows_build_timeout_fails_closed_on_invalid_override() {
        for bad in ["abc", "0", "-120", "1.5", "3600s"] {
            let err = windows_build_timeout_from_env(Some(bad))
                .expect_err("invalid override must fail closed");
            let message = build_outcome_message(&err);
            assert!(
                message.contains(WINDOWS_BUILD_TIMEOUT_ENV),
                "error must name the env var {WINDOWS_BUILD_TIMEOUT_ENV}: {message}"
            );
            assert!(
                !message.is_empty() && message.contains(bad),
                "error must quote the rejected value: {message}"
            );
        }
    }

    #[test]
    fn windows_build_budget_timeout_is_relabelled_not_read_as_product_defect() {
        let budget = Duration::from_secs(3600);
        let ssh_timeout = AdapterError::Ssh {
            message: "SSH spawn failed for win-lab: timed out after 3600 seconds".to_owned(),
        };
        let relabelled = classify_windows_build_outcome(ssh_timeout, budget);
        let message = build_outcome_message(&relabelled);
        assert!(
            message.contains("exceeded its timeout budget"),
            "budget kill must be relabelled as a timeout-budget event: {message}"
        );
        assert!(
            message.contains("not a product defect"),
            "relabelled outcome must state it is not a product defect: {message}"
        );
        assert!(
            message.contains(WINDOWS_BUILD_TIMEOUT_ENV),
            "relabelled outcome must name the override knob: {message}"
        );
        assert!(
            message.contains("3600"),
            "relabelled outcome must carry the budget in seconds: {message}"
        );
    }

    #[test]
    fn windows_build_genuine_failure_passes_through_unrelabelled() {
        // A real compile failure surfaces as Command with exit code + stderr.
        let failure = AdapterError::Command {
            exit_code: Some(101),
            stderr: "error[E0308]: mismatched types".to_owned(),
        };
        match classify_windows_build_outcome(failure, Duration::from_secs(3600)) {
            AdapterError::Command { exit_code, stderr } => {
                assert_eq!(exit_code, Some(101), "exit code must survive passthrough");
                assert_eq!(
                    stderr, "error[E0308]: mismatched types",
                    "stderr must survive passthrough verbatim"
                );
            }
            other => panic!("Command failure must pass through unchanged: {other:?}"),
        }
        // An SSH transport failure without the timeout marker also passes
        // through — only the budget kill is relabelled.
        let spawn_failure = AdapterError::Ssh {
            message: "SSH spawn failed for win-lab: connection refused".to_owned(),
        };
        match classify_windows_build_outcome(spawn_failure, Duration::from_secs(3600)) {
            AdapterError::Ssh { message } => assert!(
                message.contains("connection refused"),
                "non-timeout SSH failure must pass through: {message}"
            ),
            other => panic!("non-timeout SSH failure must pass through: {other:?}"),
        }
    }

    #[test]
    fn windows_bootstrap_defaults_cargo_build_jobs_to_guest_cpu_count() {
        // QH-15: the unset-default must derive from the guest's CPU count via
        // [Environment]::ProcessorCount, never the historical forced '1'.
        assert!(
            BOOTSTRAP_SCRIPT.contains("[Environment]::ProcessorCount"),
            "Ensure-CargoBuildJobsForWindowsLab must default to the guest CPU count"
        );
        assert!(
            !BOOTSTRAP_SCRIPT.contains("$env:CARGO_BUILD_JOBS = '1'"),
            "the forced single-threaded default must be gone from the bootstrap"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("Ensure-CargoBuildJobsForWindowsLab"),
            "the Ensure function itself must remain present"
        );
    }
}

#[cfg(test)]
mod powershell_script_seam_tests {
    use super::*;

    /// QH-01 Step 4d-i: `from_rendered` carries the renderer's bytes through
    /// unchanged. The one PowerShell template on the renderer's path is the
    /// Windows Exit evidence capture (`Binding::PowerShellLiteral`), so it is
    /// the representative output: byte-identical to the plain-`String` render,
    /// with the ps-quoted values and the StrictMode prefix pinned exactly.
    #[test]
    fn from_rendered_carries_the_renderer_output_byte_identically() {
        let rendered = crate::vm_lab::script_template::render_windows_exit_evidence_capture_script(
            r"C:\ProgramData\RustyNet\vm-lab\windows_exit",
            r"C:\ProgramData\RustyNet\bin\rustynetd.exe",
            "rn-win-exit-killswitch-probe",
        )
        .expect("const-valued capture script must render");
        let bytes = rendered.as_str().to_owned();
        let script = PowerShellScript::from_rendered(rendered);
        assert_eq!(script.as_str(), bytes);
        assert!(script.as_str().contains("Set-StrictMode -Version Latest"));
        assert!(
            script
                .as_str()
                .contains(r"'C:\ProgramData\RustyNet\vm-lab\windows_exit'"),
            "the artifact root must arrive ps-quoted, exactly as the renderer emitted it"
        );
        // And the Debug contract: length only, never the payload.
        let text = format!("{script:?}");
        assert_eq!(text, format!("PowerShellScript(len={})", bytes.len()));
        assert!(
            !text.contains("rustynetd"),
            "payload must not appear: {text}"
        );
    }

    #[test]
    fn from_single_value_quotes_a_plain_value() {
        let script = PowerShellScript::from_single_value("svc", "rustynet-relay").expect("plain");
        assert_eq!(script.as_str(), "'rustynet-relay'");
    }

    #[test]
    fn from_single_value_rejects_subexpression_substitution() {
        let err = PowerShellScript::from_single_value("svc", "a$(b)")
            .expect_err("substitution must be refused");
        assert!(err.to_string().contains("svc"));
        assert!(!err.to_string().contains("a$(b)"));
    }

    #[test]
    fn from_single_value_rejects_backticks_and_quotes() {
        assert!(PowerShellScript::from_single_value("svc", "a`nb").is_err());
        assert!(PowerShellScript::from_single_value("svc", "a\"b").is_err());
        assert!(PowerShellScript::from_single_value("svc", "a'b").is_err());
    }

    #[test]
    fn powershell_script_debug_prints_length_only() {
        let script =
            PowerShellScript::from_single_value("svc", "secret-body").expect("plain value");
        let rendered = format!("{script:?}");
        assert!(!rendered.contains("secret-body"), "{rendered}");
        assert!(rendered.contains("len="), "{rendered}");
    }

    #[test]
    fn assignment_pubkey_read_renders_argv_through_the_validated_seam() {
        let assignment_pub_path = format!(r"{WINDOWS_STATE_ROOT}\trust\assignment.pub");
        let read_argv = [
            ValidatedArg::cli_token("Get-Content").expect("token"),
            ValidatedArg::cli_token("-LiteralPath").expect("token"),
            ValidatedArg::windows_path(&assignment_pub_path).expect("path"),
            ValidatedArg::cli_token("-Raw").expect("token"),
        ];
        let script = PowerShellScript::from_call_argv("windows read assignment pubkey", &read_argv)
            .expect("render");
        assert_eq!(
            script.as_str(),
            format!(
                "$out = & 'Get-Content' '-LiteralPath' '{assignment_pub_path}' \
                 '-Raw' 2>&1; Write-Output $out"
            )
        );
    }

    #[test]
    fn assignment_pubkey_read_rejects_a_control_character_path_at_the_seam() {
        // windows_path rejects NUL/CR/LF outright (the characters that could
        // escape PS single-quote contexts); ps_quote contains everything else.
        let err = ValidatedArg::windows_path("C:\\bad\\path\nline").expect_err("must reject");
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn from_call_argv_contains_a_single_quote_injection_attempt() {
        // A single quote inside a validated value cannot break out: ps_quote
        // doubles it, so the rendered script stays one quoted argument.
        let script = PowerShellScript::from_call_argv(
            "windows containment probe",
            &[
                ValidatedArg::cli_token("Get-Content").expect("token"),
                ValidatedArg::cli_token("-LiteralPath").expect("token"),
                ValidatedArg::windows_path("C:\\bad'; Write-Host pwned").expect("path"),
                ValidatedArg::cli_token("-Raw").expect("token"),
            ],
        )
        .expect("render");
        assert!(
            script.as_str().contains("'C:\\bad''; Write-Host pwned'"),
            "the doubled quote must keep the value a single argument: {script:?}"
        );
    }
}
