#![allow(clippy::result_large_err)]

//! Windows Service hardening verifier.
//!
//! Checks that the live `RustyNet` Windows service registration matches the
//! reviewed hardened profile (binary path under reviewed install root,
//! argv-only `--windows-service --env-file` invocation, restricted service
//! SID, non-interactive desktop, recovery action present, locked-down binary
//! ACL). The orchestrator dispatches the `windows-service-hardening-check`
//! subcommand on a remote Windows guest and parses the typed JSON report
//! produced here.
//!
//! The pure `evaluate_windows_service_hardening` function takes a typed
//! snapshot and returns a precise drift reason. The collector
//! (`collect_windows_service_hardening_snapshot`) is platform-gated: real on
//! Windows via the `windows-service` crate plus `inspect_file_sddl`, stub on
//! non-Windows hosts that returns a clear blocker error.

use crate::windows_paths::evaluate_windows_runtime_acl_sddl;
use serde::{Deserialize, Serialize};

pub const REVIEWED_WINDOWS_SERVICE_NAME: &str = "RustyNet";
pub const REVIEWED_WINDOWS_INSTALL_ROOT: &str = r"C:\Program Files\RustyNet";
pub const REVIEWED_WINDOWS_BINARY_FILE_NAME: &str = "rustynetd.exe";

/// Reviewed Windows SCM service name for the sibling rustynet-relay
/// daemon. Mirrors the default in
/// `scripts/bootstrap/windows/Install-RustyNetWindowsRelayService.ps1`.
/// Kept next to the daemon service constants so the live-lab
/// validator + the installer + `ops_install_windows_relay_service`
/// share one source of truth — a future rename surfaces as a compile
/// break in every call site.
pub const REVIEWED_WINDOWS_RELAY_SERVICE_NAME: &str = "RustyNetRelay";

/// Reviewed Windows relay datapath UDP port. The `rustynet-relay`
/// daemon binds UDP on 0.0.0.0:4500 by default — operators may widen
/// the bind address but the port stays pinned.
pub const REVIEWED_WINDOWS_RELAY_BIND_PORT: u16 = 4500;

/// Reviewed Windows relay health TCP port. The Windows installer
/// pins :9100 (distinct from the Linux + macOS default of 4501) to
/// avoid collisions with other 4500-range services that ship on
/// hardened Windows hosts.
pub const REVIEWED_WINDOWS_RELAY_HEALTH_PORT: u16 = 9100;

/// Allowed service SID types for the reviewed hardened profile. SID type
/// `None` is rejected because it removes the per-service SID isolation that
/// the reviewed install relies on.
const REVIEWED_SERVICE_SID_TYPES: &[&str] = &["unrestricted", "restricted"];

/// Allowed account names. Reviewed install runs as `LocalSystem`; service
/// accounts in the `NT SERVICE\` namespace are also accepted because they
/// represent dedicated virtual SIDs. Anything else (Administrator, custom
/// users) is rejected.
const REVIEWED_ACCOUNT_PREFIXES: &[&str] = &["nt service\\"];
const REVIEWED_ACCOUNT_NAMES: &[&str] = &["localsystem"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsServiceHardeningSnapshot {
    pub schema_version: u32,
    pub service_name: String,
    /// Raw `ImagePath` as stored in the SCM registration. Free-form for
    /// diagnostic carry-through; normative checks consume `binary_image_argv`.
    pub binary_image_path: String,
    /// Argv parsed from `binary_image_path`, with the executable as
    /// `argv[0]`. Empty if parsing failed.
    pub binary_image_argv: Vec<String>,
    pub start_name: String,
    /// Service SID type label: `none`, `unrestricted`, or `restricted`.
    pub service_sid_type: String,
    /// Service start type label: `auto_start`, `demand_start`, etc.
    pub start_type: String,
    /// True if the service registration carries `SERVICE_INTERACTIVE_PROCESS`.
    pub interactive_process: bool,
    /// Number of failure actions configured. Zero means the service has no
    /// recovery configuration, which the hardened profile rejects.
    pub failure_action_count: u32,
    /// SDDL of the binary file's DACL. Validated with the same
    /// `evaluate_windows_runtime_acl_sddl` evaluator W1.1 uses.
    pub binary_path_acl_sddl: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsServiceHardeningReport {
    pub schema_version: u32,
    pub overall_ok: bool,
    pub snapshot: WindowsServiceHardeningSnapshot,
    /// Empty when `overall_ok=true`; otherwise a list of every drift reason
    /// the evaluator produced for this snapshot. The orchestrator surfaces
    /// every reason in the live-lab failure record.
    pub drift_reasons: Vec<String>,
}

/// Pure evaluator over a snapshot. Returns `Ok(())` when the snapshot
/// satisfies every reviewed-profile rule; otherwise returns a `Vec<String>`
/// of every drift reason found.
pub fn evaluate_windows_service_hardening(
    snapshot: &WindowsServiceHardeningSnapshot,
) -> Result<(), Vec<String>> {
    let mut reasons: Vec<String> = Vec::new();

    if snapshot.schema_version != 1 {
        reasons.push(format!(
            "service hardening snapshot has unsupported schema_version={}",
            snapshot.schema_version
        ));
    }

    if snapshot.service_name != REVIEWED_WINDOWS_SERVICE_NAME {
        reasons.push(format!(
            "service name must be {REVIEWED_WINDOWS_SERVICE_NAME}; found {:?}",
            snapshot.service_name
        ));
    }

    if snapshot.binary_image_argv.is_empty() {
        reasons.push(format!(
            "service binary image path failed to parse into argv: {:?}",
            snapshot.binary_image_path
        ));
    } else {
        let exe_path = &snapshot.binary_image_argv[0];
        let lowered = exe_path.to_ascii_lowercase().replace('/', "\\");
        let install_root_lower = REVIEWED_WINDOWS_INSTALL_ROOT.to_ascii_lowercase();
        if !lowered.starts_with(&format!("{install_root_lower}\\")) {
            reasons.push(format!(
                "service binary path must live under {REVIEWED_WINDOWS_INSTALL_ROOT}; found {exe_path}"
            ));
        }
        if !lowered.ends_with(&format!(
            "\\{}",
            REVIEWED_WINDOWS_BINARY_FILE_NAME.to_ascii_lowercase()
        )) {
            reasons.push(format!(
                "service binary path must end with {REVIEWED_WINDOWS_BINARY_FILE_NAME}; found {exe_path}"
            ));
        }

        let argv_tail = &snapshot.binary_image_argv[1..];
        if !argv_tail.iter().any(|arg| arg == "--windows-service") {
            reasons.push(
                "service argv must include --windows-service so the SCM host path is taken"
                    .to_owned(),
            );
        }
        if !argv_tail.iter().any(|arg| arg == "--env-file") {
            reasons.push(
                "service argv must include --env-file so daemon args are read from the reviewed env-file (no inline daemon flags)".to_owned(),
            );
        }
        for arg in argv_tail {
            if arg.starts_with("--")
                && arg != "--windows-service"
                && arg != "--env-file"
                && arg != "--service-name"
            {
                reasons.push(format!(
                    "service argv must not include inline daemon flags; found {arg}"
                ));
            }
        }
    }

    let start_name_lower = snapshot.start_name.to_ascii_lowercase();
    let start_name_ok = REVIEWED_ACCOUNT_NAMES.contains(&start_name_lower.as_str())
        || REVIEWED_ACCOUNT_PREFIXES
            .iter()
            .any(|prefix| start_name_lower.starts_with(prefix));
    if !start_name_ok {
        reasons.push(format!(
            "service must run as LocalSystem or an NT SERVICE\\* virtual account; found {:?}",
            snapshot.start_name
        ));
    }

    let sid_type_lower = snapshot.service_sid_type.to_ascii_lowercase();
    if !REVIEWED_SERVICE_SID_TYPES.contains(&sid_type_lower.as_str()) {
        reasons.push(format!(
            "service SID type must be one of {:?}; found {:?}",
            REVIEWED_SERVICE_SID_TYPES, snapshot.service_sid_type
        ));
    }

    if snapshot.interactive_process {
        reasons.push(
            "service must not carry SERVICE_INTERACTIVE_PROCESS; the hardened profile is non-interactive".to_owned(),
        );
    }

    if snapshot.failure_action_count == 0 {
        reasons.push(
            "service must have at least one configured failure action so the SCM can recover the daemon after crash".to_owned(),
        );
    }

    if snapshot.binary_path_acl_sddl.trim().is_empty() {
        reasons.push("service binary ACL SDDL is empty; cannot verify lockdown".to_owned());
    } else if let Err(err) = evaluate_windows_runtime_acl_sddl(
        "service binary",
        snapshot.binary_path_acl_sddl.as_str(),
        false,
    ) {
        reasons.push(format!("service binary ACL drift: {err}"));
    }

    if reasons.is_empty() {
        Ok(())
    } else {
        Err(reasons)
    }
}

/// Combine snapshot + evaluation into a single report suitable for emission
/// over the orchestrator dispatch path.
pub fn build_windows_service_hardening_report(
    snapshot: WindowsServiceHardeningSnapshot,
) -> WindowsServiceHardeningReport {
    let drift_reasons = match evaluate_windows_service_hardening(&snapshot) {
        Ok(()) => Vec::new(),
        Err(reasons) => reasons,
    };
    WindowsServiceHardeningReport {
        schema_version: 1,
        overall_ok: drift_reasons.is_empty(),
        snapshot,
        drift_reasons,
    }
}

/// Best-effort argv split for a Windows `ImagePath` string. Handles a single
/// double-quoted executable path followed by space-separated args. Does not
/// implement full Windows command-line escaping; that is acceptable because
/// the reviewed install always emits a quoted exe followed by simple flag
/// tokens.
pub fn parse_windows_image_path_argv(image_path: &str) -> Vec<String> {
    let trimmed = image_path.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let mut argv: Vec<String> = Vec::new();
    let mut chars = trimmed.chars().peekable();
    let mut current = String::new();
    let mut in_quotes = false;
    while let Some(ch) = chars.next() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
            }
            ch if ch.is_whitespace() && !in_quotes => {
                if !current.is_empty() {
                    argv.push(std::mem::take(&mut current));
                }
                while matches!(chars.peek(), Some(next) if next.is_whitespace()) {
                    chars.next();
                }
            }
            _ => current.push(ch),
        }
    }
    if !current.is_empty() {
        argv.push(current);
    }
    argv
}

/// Collect the live snapshot. On Windows, queries the SCM via the
/// `windows-service` crate and inspects the binary file ACL via
/// `rustynet_windows_native::inspect_file_sddl`. On other platforms, returns
/// a clear blocker error so the subcommand still fails-closed without
/// pretending to verify.
pub fn collect_windows_service_hardening_snapshot()
-> Result<WindowsServiceHardeningSnapshot, String> {
    #[cfg(not(windows))]
    {
        Err(
            "windows-service-hardening-check is only available on Windows hosts; the snapshot collector requires Win32 SCM access".to_owned(),
        )
    }
    #[cfg(windows)]
    {
        windows_collector::collect()
    }
}

#[cfg(windows)]
mod windows_collector {
    use super::{
        REVIEWED_WINDOWS_SERVICE_NAME, WindowsServiceHardeningSnapshot,
        parse_windows_image_path_argv,
    };
    use rustynet_windows_native::inspect_file_sddl;
    use std::path::Path;
    use windows_service::service::{ServiceAccess, ServiceSidType, ServiceStartType};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    pub(super) fn collect() -> Result<WindowsServiceHardeningSnapshot, String> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|err| format!("open SCM failed: {err}"))?;
        let service = manager
            .open_service(
                REVIEWED_WINDOWS_SERVICE_NAME,
                ServiceAccess::QUERY_CONFIG | ServiceAccess::QUERY_STATUS,
            )
            .map_err(|err| format!("open service {REVIEWED_WINDOWS_SERVICE_NAME} failed: {err}"))?;
        let config = service
            .query_config()
            .map_err(|err| format!("query service config failed: {err}"))?;
        let sid_type = service
            .get_config_service_sid_info()
            .map_err(|err| format!("query service SID info failed: {err}"))?;
        let failure_actions = service
            .get_failure_actions()
            .map_err(|err| format!("query service failure actions failed: {err}"))?;
        let interactive_process = config
            .service_type
            .contains(windows_service::service::ServiceType::INTERACTIVE_PROCESS);
        let image_path = config.executable_path.to_string_lossy().to_string();
        let argv = parse_windows_image_path_argv(image_path.as_str());
        let start_name = config
            .account_name
            .as_ref()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "LocalSystem".to_string());
        let binary_path_acl_sddl = if let Some(exe) = argv.first() {
            inspect_file_sddl(Path::new(exe.as_str()))
                .map_err(|err| format!("inspect service binary ACL failed for {exe}: {err}"))?
        } else {
            String::new()
        };
        Ok(WindowsServiceHardeningSnapshot {
            schema_version: 1,
            service_name: REVIEWED_WINDOWS_SERVICE_NAME.to_string(),
            binary_image_path: image_path,
            binary_image_argv: argv,
            start_name,
            service_sid_type: service_sid_type_label(sid_type).to_string(),
            start_type: service_start_type_label(config.start_type).to_string(),
            interactive_process,
            failure_action_count: failure_actions
                .actions
                .as_ref()
                .map(|v| v.len() as u32)
                .unwrap_or(0),
            binary_path_acl_sddl,
        })
    }

    fn service_sid_type_label(value: ServiceSidType) -> &'static str {
        match value {
            ServiceSidType::None => "none",
            ServiceSidType::Unrestricted => "unrestricted",
            ServiceSidType::Restricted => "restricted",
        }
    }

    fn service_start_type_label(value: ServiceStartType) -> &'static str {
        match value {
            ServiceStartType::AutoStart => "auto_start",
            ServiceStartType::OnDemand => "demand_start",
            ServiceStartType::Disabled => "disabled",
            ServiceStartType::SystemStart => "system_start",
            ServiceStartType::BootStart => "boot_start",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reviewed_binary_acl_sddl() -> String {
        "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)".to_owned()
    }

    fn reviewed_snapshot() -> WindowsServiceHardeningSnapshot {
        WindowsServiceHardeningSnapshot {
            schema_version: 1,
            service_name: REVIEWED_WINDOWS_SERVICE_NAME.to_owned(),
            binary_image_path: format!(
                "\"{REVIEWED_WINDOWS_INSTALL_ROOT}\\{REVIEWED_WINDOWS_BINARY_FILE_NAME}\" --windows-service --env-file C:\\ProgramData\\RustyNet\\config\\rustynetd.env"
            ),
            binary_image_argv: vec![
                format!("{REVIEWED_WINDOWS_INSTALL_ROOT}\\{REVIEWED_WINDOWS_BINARY_FILE_NAME}"),
                "--windows-service".to_owned(),
                "--env-file".to_owned(),
                r"C:\ProgramData\RustyNet\config\rustynetd.env".to_owned(),
            ],
            start_name: "LocalSystem".to_owned(),
            service_sid_type: "unrestricted".to_owned(),
            start_type: "auto_start".to_owned(),
            interactive_process: false,
            failure_action_count: 3,
            binary_path_acl_sddl: reviewed_binary_acl_sddl(),
        }
    }

    #[test]
    fn evaluator_accepts_reviewed_snapshot() {
        evaluate_windows_service_hardening(&reviewed_snapshot())
            .expect("reviewed snapshot must validate");
    }

    #[test]
    fn evaluator_accepts_nt_service_account_with_restricted_sid() {
        let mut snapshot = reviewed_snapshot();
        snapshot.start_name = r"NT SERVICE\RustyNet".to_owned();
        snapshot.service_sid_type = "restricted".to_owned();
        evaluate_windows_service_hardening(&snapshot)
            .expect("NT SERVICE virtual account with restricted SID must validate");
    }

    #[test]
    fn evaluator_rejects_unsupported_schema_version() {
        let mut snapshot = reviewed_snapshot();
        snapshot.schema_version = 99;
        let reasons = evaluate_windows_service_hardening(&snapshot)
            .expect_err("unsupported schema_version must fail");
        assert!(
            reasons.iter().any(|r| r.contains("schema_version=99")),
            "unexpected reasons: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_wrong_service_name() {
        let mut snapshot = reviewed_snapshot();
        snapshot.service_name = "RogueService".to_owned();
        let reasons = evaluate_windows_service_hardening(&snapshot)
            .expect_err("wrong service name must fail");
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("service name must be RustyNet")),
            "unexpected reasons: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_binary_outside_reviewed_install_root() {
        let mut snapshot = reviewed_snapshot();
        snapshot.binary_image_argv[0] = r"C:\Tools\rustynetd.exe".to_owned();
        let reasons = evaluate_windows_service_hardening(&snapshot)
            .expect_err("binary outside install root must fail");
        assert!(
            reasons.iter().any(|r| r.contains("must live under")),
            "unexpected reasons: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_renamed_binary_file() {
        let mut snapshot = reviewed_snapshot();
        snapshot.binary_image_argv[0] =
            format!("{REVIEWED_WINDOWS_INSTALL_ROOT}\\rustynetd-renamed.exe");
        let reasons =
            evaluate_windows_service_hardening(&snapshot).expect_err("renamed binary must fail");
        assert!(
            reasons.iter().any(|r| r.contains("must end with")),
            "unexpected reasons: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_missing_windows_service_flag() {
        let mut snapshot = reviewed_snapshot();
        snapshot.binary_image_argv = vec![
            format!("{REVIEWED_WINDOWS_INSTALL_ROOT}\\{REVIEWED_WINDOWS_BINARY_FILE_NAME}"),
            "--env-file".to_owned(),
            r"C:\ProgramData\RustyNet\config\rustynetd.env".to_owned(),
        ];
        let reasons = evaluate_windows_service_hardening(&snapshot)
            .expect_err("missing --windows-service must fail");
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("must include --windows-service")),
            "unexpected reasons: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_missing_env_file_flag() {
        let mut snapshot = reviewed_snapshot();
        snapshot.binary_image_argv = vec![
            format!("{REVIEWED_WINDOWS_INSTALL_ROOT}\\{REVIEWED_WINDOWS_BINARY_FILE_NAME}"),
            "--windows-service".to_owned(),
        ];
        let reasons = evaluate_windows_service_hardening(&snapshot)
            .expect_err("missing --env-file must fail");
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("must include --env-file")),
            "unexpected reasons: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_inline_daemon_flags() {
        let mut snapshot = reviewed_snapshot();
        snapshot.binary_image_argv.push("--backend".to_owned());
        snapshot
            .binary_image_argv
            .push("windows-wireguard-nt".to_owned());
        let reasons = evaluate_windows_service_hardening(&snapshot)
            .expect_err("inline daemon flag must fail");
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("must not include inline daemon flags")),
            "unexpected reasons: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_unreviewed_account() {
        let mut snapshot = reviewed_snapshot();
        snapshot.start_name = ".\\Administrator".to_owned();
        let reasons = evaluate_windows_service_hardening(&snapshot)
            .expect_err("unreviewed account must fail");
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("LocalSystem or an NT SERVICE")),
            "unexpected reasons: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_sid_type_none() {
        let mut snapshot = reviewed_snapshot();
        snapshot.service_sid_type = "none".to_owned();
        let reasons = evaluate_windows_service_hardening(&snapshot)
            .expect_err("service SID type none must fail");
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("service SID type must be one of")),
            "unexpected reasons: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_interactive_process() {
        let mut snapshot = reviewed_snapshot();
        snapshot.interactive_process = true;
        let reasons = evaluate_windows_service_hardening(&snapshot)
            .expect_err("interactive process flag must fail");
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("SERVICE_INTERACTIVE_PROCESS")),
            "unexpected reasons: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_zero_failure_actions() {
        let mut snapshot = reviewed_snapshot();
        snapshot.failure_action_count = 0;
        let reasons = evaluate_windows_service_hardening(&snapshot)
            .expect_err("missing failure actions must fail");
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("at least one configured failure action")),
            "unexpected reasons: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_drifted_binary_acl() {
        let mut snapshot = reviewed_snapshot();
        snapshot.binary_path_acl_sddl = "O:BAG:BAD:(A;;FA;;;WD)".to_owned();
        let reasons = evaluate_windows_service_hardening(&snapshot)
            .expect_err("drifted binary ACL must fail");
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("service binary ACL drift")),
            "unexpected reasons: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_binary_acl_granting_everyone_principal_wd() {
        // WD = SDDL alias for "Everyone" — never permitted on the service
        // binary; would expose `rustynetd.exe` to any local user.
        let mut snapshot = reviewed_snapshot();
        snapshot.binary_path_acl_sddl =
            "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;WD)".to_owned();
        let reasons = evaluate_windows_service_hardening(&snapshot)
            .expect_err("WD principal in binary ACL must fail");
        assert!(
            reasons.iter().any(|r| r.contains("(WD)")),
            "expected the rejection to name the WD principal: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_binary_acl_granting_authenticated_users_principal_au() {
        // AU = SDDL alias for "Authenticated Users" — broader than the
        // reviewed SY+BA principal set on the service binary.
        let mut snapshot = reviewed_snapshot();
        snapshot.binary_path_acl_sddl =
            "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;AU)".to_owned();
        let reasons = evaluate_windows_service_hardening(&snapshot)
            .expect_err("AU principal in binary ACL must fail");
        assert!(
            reasons.iter().any(|r| r.contains("(AU)")),
            "expected the rejection to name the AU principal: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_binary_acl_granting_builtin_users_principal_bu() {
        // BU = SDDL alias for "Builtin\\Users" — broader than the reviewed
        // SY+BA principal set on the service binary.
        let mut snapshot = reviewed_snapshot();
        snapshot.binary_path_acl_sddl =
            "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;BU)".to_owned();
        let reasons = evaluate_windows_service_hardening(&snapshot)
            .expect_err("BU principal in binary ACL must fail");
        assert!(
            reasons.iter().any(|r| r.contains("(BU)")),
            "expected the rejection to name the BU principal: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_binary_acl_missing_localsystem_principal_sy() {
        // The reviewed profile requires LocalSystem (SY) access so the SCM
        // can launch the daemon under the service SID. An ACL that grants
        // only Builtin Administrators is rejected with a precise reason.
        let mut snapshot = reviewed_snapshot();
        snapshot.binary_path_acl_sddl = "O:BAG:BAD:P(A;;FA;;;BA)".to_owned();
        let reasons = evaluate_windows_service_hardening(&snapshot)
            .expect_err("binary ACL missing SY principal must fail");
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("must grant LocalSystem access")),
            "expected the rejection to require LocalSystem (SY): {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_binary_acl_missing_builtin_administrators_principal_ba() {
        // The reviewed profile requires Builtin Administrators (BA) access
        // so operators can audit and update the binary under
        // C:\Program Files\RustyNet during normal break-glass procedures.
        let mut snapshot = reviewed_snapshot();
        snapshot.binary_path_acl_sddl = "O:BAG:BAD:P(A;;FA;;;SY)".to_owned();
        let reasons = evaluate_windows_service_hardening(&snapshot)
            .expect_err("binary ACL missing BA principal must fail");
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("must grant Builtin Administrators access")),
            "expected the rejection to require Builtin Administrators (BA): {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_binary_acl_with_unreviewed_owner() {
        // Owner must be LocalSystem (SY), Builtin Administrators (BA), or
        // a service SID (S-1-5-80-*). Anything else (e.g. a regular user
        // SID or Everyone) is rejected.
        let mut snapshot = reviewed_snapshot();
        snapshot.binary_path_acl_sddl =
            "O:S-1-5-21-1234567890-1234567890-1234567890-1001G:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"
                .to_owned();
        let reasons =
            evaluate_windows_service_hardening(&snapshot).expect_err("unreviewed owner must fail");
        assert!(
            reasons.iter().any(|r| r.contains(
                "ACL owner must be LocalSystem, Builtin Administrators, or a service SID"
            )),
            "expected the rejection to require a reviewed owner: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_accepts_binary_acl_with_service_sid_owner() {
        // S-1-5-80-* owner is acceptable: this is the service SID for the
        // RustyNet virtual account, which appears when the service was
        // configured with SidType=Restricted or SidType=Unrestricted and
        // the lab-image install pinned the owner to that SID.
        let mut snapshot = reviewed_snapshot();
        snapshot.binary_path_acl_sddl =
            "O:S-1-5-80-1234567890-1234567890G:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)".to_owned();
        evaluate_windows_service_hardening(&snapshot).expect("service-SID owner must be accepted");
    }

    #[test]
    fn evaluator_rejects_interactive_localsystem_combination_specifically() {
        // The "interactive + LocalSystem" combination is the historical
        // Windows footgun (interactive SYSTEM session). The evaluator
        // already rejects interactive_process=true regardless of the
        // start_name, but this test pins the specific combination so a
        // future refactor cannot accidentally drop the
        // interactive_process check.
        let mut snapshot = reviewed_snapshot();
        snapshot.interactive_process = true;
        assert_eq!(snapshot.start_name, "LocalSystem");
        let reasons = evaluate_windows_service_hardening(&snapshot)
            .expect_err("interactive + LocalSystem must fail closed");
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("SERVICE_INTERACTIVE_PROCESS")),
            "expected the rejection to name SERVICE_INTERACTIVE_PROCESS: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_accepts_protected_dacl_with_no_inheritance_flag_p() {
        // The protected-DACL invariant (D:P) is enforced upstream by
        // evaluate_windows_protected_dacl_sddl. This test pins that the
        // reviewed_snapshot uses D:P (no inheritance from parent ACL).
        let snapshot = reviewed_snapshot();
        assert!(
            snapshot.binary_path_acl_sddl.contains("D:P"),
            "reviewed binary ACL must use a protected DACL (D:P)"
        );
        evaluate_windows_service_hardening(&snapshot).expect("D:P protected DACL must be accepted");
    }

    #[test]
    fn evaluator_rejects_empty_binary_acl() {
        let mut snapshot = reviewed_snapshot();
        snapshot.binary_path_acl_sddl = String::new();
        let reasons =
            evaluate_windows_service_hardening(&snapshot).expect_err("empty binary ACL must fail");
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("binary ACL SDDL is empty")),
            "unexpected reasons: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_aggregates_all_drift_reasons() {
        let mut snapshot = reviewed_snapshot();
        snapshot.start_name = ".\\Administrator".to_owned();
        snapshot.service_sid_type = "none".to_owned();
        snapshot.interactive_process = true;
        snapshot.failure_action_count = 0;
        let reasons =
            evaluate_windows_service_hardening(&snapshot).expect_err("multiple drifts must fail");
        assert!(reasons.len() >= 4, "expected >=4 reasons, got: {reasons:?}");
    }

    #[test]
    fn build_report_marks_overall_ok_for_reviewed_snapshot() {
        let report = build_windows_service_hardening_report(reviewed_snapshot());
        assert!(report.overall_ok);
        assert!(report.drift_reasons.is_empty());
    }

    #[test]
    fn build_report_marks_overall_not_ok_with_drift_reasons() {
        let mut snapshot = reviewed_snapshot();
        snapshot.start_name = ".\\Administrator".to_owned();
        let report = build_windows_service_hardening_report(snapshot);
        assert!(!report.overall_ok);
        assert!(!report.drift_reasons.is_empty());
    }

    #[test]
    fn parse_image_path_argv_handles_quoted_executable_with_spaces() {
        let argv = parse_windows_image_path_argv(
            "\"C:\\Program Files\\RustyNet\\rustynetd.exe\" --windows-service --env-file C:\\ProgramData\\RustyNet\\config\\rustynetd.env",
        );
        assert_eq!(
            argv,
            vec![
                r"C:\Program Files\RustyNet\rustynetd.exe".to_owned(),
                "--windows-service".to_owned(),
                "--env-file".to_owned(),
                r"C:\ProgramData\RustyNet\config\rustynetd.env".to_owned(),
            ]
        );
    }

    #[test]
    fn parse_image_path_argv_handles_unquoted_path_without_spaces() {
        let argv = parse_windows_image_path_argv(
            r"C:\bin\rustynetd.exe --windows-service --env-file env.txt",
        );
        assert_eq!(
            argv,
            vec![
                r"C:\bin\rustynetd.exe".to_owned(),
                "--windows-service".to_owned(),
                "--env-file".to_owned(),
                "env.txt".to_owned(),
            ]
        );
    }

    #[test]
    fn parse_image_path_argv_returns_empty_for_empty_input() {
        assert!(parse_windows_image_path_argv("").is_empty());
        assert!(parse_windows_image_path_argv("   ").is_empty());
    }

    #[test]
    fn report_serializes_with_snapshot_and_drift_reasons() {
        let report = build_windows_service_hardening_report(reviewed_snapshot());
        let json = serde_json::to_value(&report).expect("serialize report");
        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["overall_ok"], true);
        assert!(json["snapshot"].is_object());
        assert!(json["drift_reasons"].is_array());
    }

    #[test]
    fn report_round_trips_via_serde_json() {
        let original = build_windows_service_hardening_report(reviewed_snapshot());
        let serialized = serde_json::to_string(&original).expect("serialize");
        let restored: WindowsServiceHardeningReport =
            serde_json::from_str(serialized.as_str()).expect("deserialize");
        assert_eq!(restored, original);
    }

    #[cfg(not(windows))]
    #[test]
    fn collect_snapshot_returns_clear_blocker_off_windows() {
        let err = collect_windows_service_hardening_snapshot()
            .expect_err("non-Windows host must not pretend to verify");
        assert!(
            err.contains("only available on Windows"),
            "unexpected error: {err}"
        );
    }
}
