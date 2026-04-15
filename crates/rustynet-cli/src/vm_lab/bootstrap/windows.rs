use super::super::*;
use super::{BootstrapPhase, BootstrapPhaseContext, VmBootstrapProvider};

const WINDOWS_SERVICE_NAME: &str = "RustyNet";
const WINDOWS_INSTALL_ROOT: &str = r"C:\Program Files\RustyNet";
const WINDOWS_STATE_ROOT: &str = r"C:\ProgramData\RustyNet";

#[derive(Debug, Clone, PartialEq, Eq)]
struct WindowsHelperScriptSpec {
    helper_file_name: &'static str,
    remote_file_name: &'static str,
    args: Vec<String>,
}

pub(super) struct WindowsBootstrapProvider;

pub(super) static WINDOWS_BOOTSTRAP_PROVIDER: WindowsBootstrapProvider = WindowsBootstrapProvider;

fn build_bootstrap_script_invocation(
    phase: BootstrapPhase,
    target_label: &str,
    context: &BootstrapPhaseContext<'_>,
) -> Result<WindowsHelperScriptSpec, String> {
    let mut args = vec![
        "-Phase".to_string(),
        phase.as_str().to_string(),
        "-RustyNetRoot".to_string(),
        context.workdir.to_string(),
        "-Branch".to_string(),
        context.branch.to_string(),
    ];

    match phase {
        BootstrapPhase::SyncSource => {
            let repo_url = context.repo_url.ok_or_else(|| {
                format!(
                    "Windows bootstrap phase {} requires --repo-url for {}",
                    phase.as_str(),
                    target_label
                )
            })?;
            ensure_no_control_chars("repo URL", repo_url)?;
            args.push("-SourceMode".to_string());
            args.push("git".to_string());
            args.push("-RepoUrl".to_string());
            args.push(repo_url.to_string());
        }
        BootstrapPhase::BuildRelease => {}
        BootstrapPhase::InstallRelease
        | BootstrapPhase::RestartRuntime
        | BootstrapPhase::VerifyRuntime
        | BootstrapPhase::All => {
            return Err(format!(
                "bootstrap script invocation is not used for Windows phase {} on {}",
                phase.as_str(),
                target_label
            ));
        }
    }

    Ok(WindowsHelperScriptSpec {
        helper_file_name: WINDOWS_BOOTSTRAP_HELPER_FILE,
        remote_file_name: WINDOWS_BOOTSTRAP_HELPER_FILE,
        args,
    })
}

fn build_windows_service_install_invocation(
    context: &BootstrapPhaseContext<'_>,
) -> WindowsHelperScriptSpec {
    WindowsHelperScriptSpec {
        helper_file_name: WINDOWS_SERVICE_INSTALL_HELPER_FILE,
        remote_file_name: WINDOWS_SERVICE_INSTALL_HELPER_FILE,
        args: vec![
            "-RustyNetRoot".to_string(),
            context.workdir.to_string(),
            "-InstallRoot".to_string(),
            WINDOWS_INSTALL_ROOT.to_string(),
            "-StateRoot".to_string(),
            WINDOWS_STATE_ROOT.to_string(),
            "-ServiceName".to_string(),
            WINDOWS_SERVICE_NAME.to_string(),
        ],
    }
}

fn build_windows_verify_invocation(context: &BootstrapPhaseContext<'_>) -> WindowsHelperScriptSpec {
    WindowsHelperScriptSpec {
        helper_file_name: WINDOWS_VERIFY_HELPER_FILE,
        remote_file_name: WINDOWS_VERIFY_HELPER_FILE,
        args: vec![
            "-RustyNetRoot".to_string(),
            context.workdir.to_string(),
            "-InstallRoot".to_string(),
            WINDOWS_INSTALL_ROOT.to_string(),
            "-StateRoot".to_string(),
            WINDOWS_STATE_ROOT.to_string(),
            "-ServiceName".to_string(),
            WINDOWS_SERVICE_NAME.to_string(),
        ],
    }
}

fn build_windows_diagnostics_invocation(
    target: &RemoteTarget,
    phase: BootstrapPhase,
) -> Result<WindowsHelperScriptSpec, String> {
    let remote_root = target
        .remote_temp_dir
        .clone()
        .unwrap_or_else(|| default_remote_temp_dir_for_profile(target.platform_profile));
    ensure_no_control_chars("Windows diagnostics root", remote_root.as_str())?;
    let output_root = format!(
        r"{}\diagnostics\bootstrap-{}-{}-{}",
        remote_root.trim_end_matches(['\\', '/']),
        sanitize_label_for_path(target.label.as_str()),
        phase.as_str(),
        unique_suffix()
    );
    Ok(WindowsHelperScriptSpec {
        helper_file_name: WINDOWS_COLLECT_DIAGNOSTICS_HELPER_FILE,
        remote_file_name: WINDOWS_COLLECT_DIAGNOSTICS_HELPER_FILE,
        args: vec!["-OutputRoot".to_string(), output_root],
    })
}

fn build_windows_restart_runtime_script() -> Result<String, String> {
    Ok(format!(
        "Set-StrictMode -Version Latest; \
         $ErrorActionPreference = 'Stop'; \
         $serviceName = {service_name}; \
         $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; \
         if (-not $service) {{ throw \"Windows runtime service is not installed: $serviceName\" }}; \
         if ($service.Status -eq 'Running') {{ Restart-Service -Name $serviceName -ErrorAction Stop }} else {{ Start-Service -Name $serviceName -ErrorAction Stop }}; \
         $service.WaitForStatus('Running', [TimeSpan]::FromSeconds(30)); \
         $refreshed = Get-Service -Name $serviceName -ErrorAction Stop; \
         if ($refreshed.Status -ne 'Running') {{ throw \"Windows runtime service failed to reach Running state: $serviceName ($($refreshed.Status))\" }}",
        service_name = powershell_quote(WINDOWS_SERVICE_NAME)?,
    ))
}

fn parse_windows_verify_output(output: &str, target_label: &str) -> Result<(), String> {
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return Err(format!(
            "Windows verify helper produced no output for {}",
            target_label
        ));
    }
    let parsed: serde_json::Value = serde_json::from_str(trimmed).map_err(|err| {
        format!(
            "Windows verify helper did not emit valid JSON for {}: {err}",
            target_label
        )
    })?;

    let bool_field = |name: &str| {
        parsed
            .get(name)
            .and_then(|value| value.as_bool())
            .unwrap_or(false)
    };
    let service_status = parsed
        .get("service_status")
        .and_then(|value| value.as_str())
        .unwrap_or("missing");
    let mut failures = Vec::new();
    for field in [
        "daemon_present",
        "cli_present",
        "config_present",
        "log_root_present",
        "trust_root_present",
        "openssh_host_key_present",
    ] {
        if !bool_field(field) {
            failures.push(format!("{field}=false"));
        }
    }
    if !bool_field("runtime_flags_present") {
        failures.push("runtime_flags_present=false".to_string());
    }
    if !bool_field("service_present") {
        failures.push("service_present=false".to_string());
    } else if service_status != "Running" {
        failures.push(format!("service_status={service_status}"));
    }
    if !failures.is_empty() {
        let reason = parsed
            .get("reason")
            .and_then(|value| value.as_str())
            .filter(|value| !value.trim().is_empty());
        let notes = parsed
            .get("notes")
            .and_then(|value| value.as_array())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|value| value.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .filter(|notes| !notes.is_empty());
        let reason_suffix = reason
            .map(|reason| format!(" reason={reason}"))
            .unwrap_or_default();
        let note_suffix = notes
            .map(|notes| format!(" notes={notes}"))
            .unwrap_or_default();
        return Err(format!(
            "Windows verify helper reported {} for {}{}{}",
            failures.join(", "),
            target_label,
            reason_suffix,
            note_suffix
        ));
    }
    Ok(())
}

impl WindowsBootstrapProvider {
    fn helper_context<'a>(
        &self,
        target: &'a RemoteTarget,
        context: &'a BootstrapPhaseContext<'a>,
    ) -> RemoteFallbackContext<'a> {
        RemoteFallbackContext {
            target,
            ssh_user_override: context.ssh_user,
            ssh_identity_file: context.ssh_identity_file,
            known_hosts_path: context.known_hosts_path,
            timeout: context.timeout,
        }
    }

    fn invoke_helper_status(
        &self,
        target: &RemoteTarget,
        context: &BootstrapPhaseContext<'_>,
        invocation: WindowsHelperScriptSpec,
        label: &str,
    ) -> Result<(), String> {
        let helper_context = self.helper_context(target, context);
        let status = invoke_windows_helper_script_for_target(
            &helper_context,
            WindowsHelperInvocation {
                helper_file_name: invocation.helper_file_name,
                remote_file_name: invocation.remote_file_name,
                args: invocation.args.as_slice(),
            },
        )?;
        ensure_success_status(status, label)
    }

    fn capture_helper_output(
        &self,
        target: &RemoteTarget,
        context: &BootstrapPhaseContext<'_>,
        invocation: WindowsHelperScriptSpec,
        label: &str,
    ) -> Result<String, String> {
        let helper_context = self.helper_context(target, context);
        capture_windows_helper_script_output_for_target(
            &helper_context,
            invocation.helper_file_name,
            invocation.remote_file_name,
            invocation.args.as_slice(),
        )
        .map_err(|err| format!("{label} failed for {}: {err}", target.label))
    }

    fn collect_failure_diagnostics(
        &self,
        phase: BootstrapPhase,
        target: &RemoteTarget,
        context: &BootstrapPhaseContext<'_>,
    ) -> Result<String, String> {
        let invocation = build_windows_diagnostics_invocation(target, phase)?;
        let output =
            self.capture_helper_output(target, context, invocation, "Windows diagnostics helper")?;
        let output_root = output.trim();
        if output_root.is_empty() {
            return Err(format!(
                "Windows diagnostics helper produced no output for {}",
                target.label
            ));
        }
        Ok(output_root.to_string())
    }

    fn with_failure_diagnostics<F>(
        &self,
        phase: BootstrapPhase,
        target: &RemoteTarget,
        context: &BootstrapPhaseContext<'_>,
        operation: F,
    ) -> Result<(), String>
    where
        F: FnOnce() -> Result<(), String>,
    {
        operation().map_err(|err| {
            if err.contains("requires --repo-url") {
                return err;
            }
            match self.collect_failure_diagnostics(phase, target, context) {
                Ok(output_root) => format!(
                    "{err}; Windows diagnostics_output_root={output_root} target={}",
                    target.label
                ),
                Err(diag_err) => format!(
                    "{err}; Windows diagnostics collection also failed for {}: {diag_err}",
                    target.label
                ),
            }
        })
    }

    fn execute_single_phase(
        &self,
        phase: BootstrapPhase,
        target: &RemoteTarget,
        context: &BootstrapPhaseContext<'_>,
    ) -> Result<(), String> {
        match phase {
            BootstrapPhase::SyncSource => {
                let invocation =
                    build_bootstrap_script_invocation(phase, target.label.as_str(), context)?;
                self.invoke_helper_status(
                    target,
                    context,
                    invocation,
                    "Windows bootstrap sync-source",
                )
            }
            BootstrapPhase::BuildRelease => {
                let invocation =
                    build_bootstrap_script_invocation(phase, target.label.as_str(), context)?;
                self.invoke_helper_status(
                    target,
                    context,
                    invocation,
                    "Windows bootstrap build-release",
                )
            }
            BootstrapPhase::InstallRelease => {
                let invocation = build_windows_service_install_invocation(context);
                self.invoke_helper_status(
                    target,
                    context,
                    invocation,
                    "Windows service install helper",
                )
            }
            BootstrapPhase::RestartRuntime => {
                let status = run_remote_shell_command_for_target(
                    target,
                    context.ssh_user,
                    context.ssh_identity_file,
                    context.known_hosts_path,
                    build_windows_restart_runtime_script()?.as_str(),
                    context.timeout,
                )
                .map_err(|err| {
                    format!("Windows restart-runtime failed for {}: {err}", target.label)
                })?;
                ensure_success_status(status, "Windows restart-runtime")
            }
            BootstrapPhase::VerifyRuntime => {
                let output = self.capture_helper_output(
                    target,
                    context,
                    build_windows_verify_invocation(context),
                    "Windows verify helper",
                )?;
                parse_windows_verify_output(output.as_str(), target.label.as_str())
            }
            BootstrapPhase::All => {
                for subphase in [
                    BootstrapPhase::SyncSource,
                    BootstrapPhase::BuildRelease,
                    BootstrapPhase::InstallRelease,
                    BootstrapPhase::RestartRuntime,
                    BootstrapPhase::VerifyRuntime,
                ] {
                    self.execute_phase(subphase, target, context)?;
                }
                Ok(())
            }
        }
    }
}

impl VmBootstrapProvider for WindowsBootstrapProvider {
    fn platform(&self) -> VmGuestPlatform {
        VmGuestPlatform::Windows
    }

    fn execute_phase(
        &self,
        phase: BootstrapPhase,
        target: &RemoteTarget,
        context: &BootstrapPhaseContext<'_>,
    ) -> Result<(), String> {
        if target.platform_profile.platform != VmGuestPlatform::Windows {
            return Err(format!(
                "Windows bootstrap provider received non-Windows target: {}",
                target.label
            ));
        }

        if phase == BootstrapPhase::All {
            return self.execute_single_phase(phase, target, context);
        }

        self.with_failure_diagnostics(phase, target, context, || {
            self.execute_single_phase(phase, target, context)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_context<'a>(repo_url: Option<&'a str>) -> BootstrapPhaseContext<'a> {
        BootstrapPhaseContext {
            ssh_user: Some("Administrator"),
            ssh_identity_file: None,
            known_hosts_path: None,
            workdir: r"C:\Rustynet",
            repo_url,
            branch: "main",
            remote: "origin",
            timeout: std::time::Duration::from_secs(30),
        }
    }

    #[test]
    fn windows_bootstrap_invocation_uses_canonical_helper_and_repo_args() {
        let invocation = build_bootstrap_script_invocation(
            BootstrapPhase::SyncSource,
            "windows-utm-1",
            &sample_context(Some("https://example.invalid/Rustynet.git")),
        )
        .expect("sync-source invocation should build");
        assert_eq!(invocation.helper_file_name, WINDOWS_BOOTSTRAP_HELPER_FILE);
        assert_eq!(invocation.remote_file_name, WINDOWS_BOOTSTRAP_HELPER_FILE);
        assert_eq!(
            invocation.args,
            vec![
                "-Phase",
                "sync-source",
                "-RustyNetRoot",
                r"C:\Rustynet",
                "-Branch",
                "main",
                "-SourceMode",
                "git",
                "-RepoUrl",
                "https://example.invalid/Rustynet.git",
            ]
        );
    }

    #[test]
    fn windows_service_install_invocation_uses_canonical_helper_and_runtime_roots() {
        let invocation = build_windows_service_install_invocation(&sample_context(None));
        assert_eq!(
            invocation.helper_file_name,
            WINDOWS_SERVICE_INSTALL_HELPER_FILE
        );
        assert_eq!(
            invocation.args,
            vec![
                "-RustyNetRoot",
                r"C:\Rustynet",
                "-InstallRoot",
                WINDOWS_INSTALL_ROOT,
                "-StateRoot",
                WINDOWS_STATE_ROOT,
                "-ServiceName",
                WINDOWS_SERVICE_NAME,
            ]
        );
    }

    #[test]
    fn windows_verify_output_parser_rejects_missing_service() {
        let err = parse_windows_verify_output(
            r#"{
                "daemon_present": true,
                "cli_present": true,
                "config_present": true,
                "log_root_present": true,
                "trust_root_present": true,
                "service_present": false,
                "service_status": "missing",
                "openssh_host_key_present": true,
                "runtime_flags_present": false,
                "reason": "windows-runtime-service-host-not-yet-implemented",
                "notes": ["windows-service-flags-missing","service-missing"]
            }"#,
            "windows-utm-1",
        )
        .expect_err("missing service must fail closed");
        assert!(err.contains("service_present=false"));
        assert!(err.contains("runtime_flags_present=false"));
        assert!(err.contains("reason=windows-runtime-service-host-not-yet-implemented"));
        assert!(err.contains("windows-service-flags-missing"));
    }

    #[test]
    fn windows_restart_runtime_script_uses_powershell_service_control() {
        let script =
            build_windows_restart_runtime_script().expect("restart-runtime script should build");
        assert!(script.contains("Restart-Service -Name $serviceName -ErrorAction Stop"));
        assert!(script.contains("Start-Service -Name $serviceName -ErrorAction Stop"));
        assert!(!script.contains("systemctl"));
    }

    #[test]
    fn windows_diagnostics_invocation_uses_remote_temp_root_and_phase() {
        let target = RemoteTarget {
            label: "windows-utm-1".to_string(),
            ssh_target: "192.168.64.20".to_string(),
            ssh_user: Some("Administrator".to_string()),
            controller: None,
            platform_profile: default_platform_profile(VmGuestPlatform::Windows),
            rustynet_src_dir: Some(r"C:\Rustynet".to_string()),
            remote_temp_dir: Some(r"C:\ProgramData\Rustynet\vm-lab".to_string()),
        };
        let invocation =
            build_windows_diagnostics_invocation(&target, BootstrapPhase::InstallRelease)
                .expect("diagnostics invocation should build");
        assert_eq!(
            invocation.helper_file_name,
            WINDOWS_COLLECT_DIAGNOSTICS_HELPER_FILE
        );
        assert_eq!(invocation.args[0], "-OutputRoot");
        assert!(invocation.args[1].starts_with(
            r"C:\ProgramData\Rustynet\vm-lab\diagnostics\bootstrap-windows-utm-1-install-release-"
        ));
    }
}
