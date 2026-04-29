#![allow(dead_code)]
use std::time::Duration;

use base64::prelude::*;

use crate::vm_lab::orchestrator::adapter::ssh;
use crate::vm_lab::orchestrator::connection::NodeConnection;
use crate::vm_lab::orchestrator::error::{AdapterError, InstallReport};

pub const WINDOWS_SERVICE_NAME: &str = "RustyNet";
pub const WINDOWS_INSTALL_ROOT: &str = r"C:\Program Files\RustyNet";
pub const WINDOWS_STATE_ROOT: &str = r"C:\ProgramData\RustyNet";
pub const WINDOWS_RUSTYNETD_PATH: &str = r"C:\Program Files\RustyNet\rustynetd.exe";
pub const WINDOWS_RUSTYNET_PATH: &str = r"C:\Program Files\RustyNet\rustynet.exe";
pub const WINDOWS_STAGING_DIR: &str = r"C:\ProgramData\Rustynet\vm-lab";
pub const WINDOWS_MEMBERSHIP_OWNER_PUBKEY_PATH: &str =
    r"C:\ProgramData\RustyNet\membership\membership.owner.key.pub";
pub const WINDOWS_MEMBERSHIP_SNAPSHOT_PATH: &str =
    r"C:\ProgramData\RustyNet\membership\membership.snapshot";

static BOOTSTRAP_SCRIPT: &str =
    include_str!("../../../../../../scripts/bootstrap/windows/Bootstrap-RustyNetWindows.ps1");
static INSTALL_SERVICE_SCRIPT: &str =
    include_str!("../../../../../../scripts/bootstrap/windows/Install-RustyNetWindowsService.ps1");
static UNINSTALL_SERVICE_SCRIPT: &str = include_str!(
    "../../../../../../scripts/bootstrap/windows/Uninstall-RustyNetWindowsService.ps1"
);

const SHORT_TIMEOUT: Duration = Duration::from_secs(30);
const BUILD_TIMEOUT: Duration = Duration::from_secs(1800); // cargo build on Windows takes longer

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

/// Bootstrap the daemon on a Windows host that already has the source tree
/// checked out at `workdir`. Runs:
///   Bootstrap-RustyNetWindows.ps1 -Phase build-release
///   Install-RustyNetWindowsService.ps1 -ServiceName RustyNet …
///   Restart-Service RustyNet (via SCM)
/// Returns `InstallReport` on success.
pub fn install_daemon(conn: &NodeConnection, workdir: &str) -> Result<InstallReport, AdapterError> {
    validate_windows_path(workdir)?;

    let staging_dir = WINDOWS_STAGING_DIR;

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

    let _ = std::fs::remove_file(&bootstrap_tmp);
    let _ = std::fs::remove_file(&install_tmp);

    // Build release from existing workdir.
    let build_script = format!(
        "Set-StrictMode -Version Latest; $ErrorActionPreference = 'Stop'; \
         $ProgressPreference = 'SilentlyContinue'; \
         Set-Location -LiteralPath {workdir_q}; \
         & {bootstrap_q} -Phase build-release -RustyNetRoot {workdir_q}",
        workdir_q = ps_quote(workdir)?,
        bootstrap_q = ps_quote(&remote_bootstrap)?,
    );
    run_remote_ps(conn, &build_script, BUILD_TIMEOUT)?;

    // Install the service.
    let install_script = format!(
        "Set-StrictMode -Version Latest; $ErrorActionPreference = 'Stop'; \
         $ProgressPreference = 'SilentlyContinue'; \
         & {install_q} \
           -RustyNetRoot {workdir_q} \
           -InstallRoot {install_root_q} \
           -StateRoot {state_root_q} \
           -ServiceName {svc_q}",
        install_q = ps_quote(&remote_install_svc)?,
        workdir_q = ps_quote(workdir)?,
        install_root_q = ps_quote(WINDOWS_INSTALL_ROOT)?,
        state_root_q = ps_quote(WINDOWS_STATE_ROOT)?,
        svc_q = ps_quote(WINDOWS_SERVICE_NAME)?,
    );
    run_remote_ps(conn, &install_script, Duration::from_secs(120))?;

    // Start the service.
    start_daemon(conn)?;

    // Verify the binary is present.
    let verify_script = format!(
        "if (-not (Test-Path -LiteralPath {})) {{ throw 'rustynetd.exe not found' }}",
        ps_quote(WINDOWS_RUSTYNETD_PATH)?
    );
    run_remote_ps(conn, &verify_script, SHORT_TIMEOUT)?;

    Ok(InstallReport {
        daemon_path: WINDOWS_RUSTYNETD_PATH.into(),
        service_name: WINDOWS_SERVICE_NAME.to_string(),
    })
}

/// Start the RustyNet SCM service.
pub fn start_daemon(conn: &NodeConnection) -> Result<(), AdapterError> {
    run_service_action(conn, "Start-Service")
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
}
