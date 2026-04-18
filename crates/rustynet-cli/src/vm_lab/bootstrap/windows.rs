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

fn phase_requires_proven_access(phase: BootstrapPhase) -> bool {
    matches!(
        phase,
        BootstrapPhase::InstallRelease
            | BootstrapPhase::RestartRuntime
            | BootstrapPhase::VerifyRuntime
    )
}

fn render_windows_access_gate_error(
    phase: BootstrapPhase,
    target_label: &str,
    cause: &str,
) -> String {
    format!(
        "Windows phase {} requires proven access for {}: {}",
        phase.as_str(),
        target_label,
        cause.trim()
    )
}

fn local_utm_result_file_supported_for_phase(phase: BootstrapPhase, target: &RemoteTarget) -> bool {
    matches!(
        windows_local_utm_execution_authority(target, false),
        Some(WindowsLocalUtmExecutionAuthority::StatusProbeResultFile)
    ) && matches!(
        phase,
        BootstrapPhase::InstallRelease | BootstrapPhase::VerifyRuntime
    )
}

fn format_windows_phase_failure_with_diagnostics(
    err: &str,
    target_label: &str,
    diagnostics: Result<String, String>,
) -> String {
    match diagnostics {
        Ok(output_root) => {
            format!("{err}; Windows diagnostics_output_root={output_root} target={target_label}")
        }
        Err(diag_err) => format!(
            "{err}; Windows diagnostics collection also failed for {target_label}: {diag_err}"
        ),
    }
}

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
        BootstrapPhase::SmokeServiceHost => {
            return Err(format!(
                "bootstrap script invocation is not used for Windows phase {} on {}",
                phase.as_str(),
                target_label
            ));
        }
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

fn build_windows_service_host_smoke_invocation(
    context: &BootstrapPhaseContext<'_>,
) -> WindowsHelperScriptSpec {
    WindowsHelperScriptSpec {
        helper_file_name: WINDOWS_SERVICE_HOST_SMOKE_HELPER_FILE,
        remote_file_name: WINDOWS_SERVICE_HOST_SMOKE_HELPER_FILE,
        args: vec![
            "-RustyNetRoot".to_string(),
            context.workdir.to_string(),
            "-StateRoot".to_string(),
            WINDOWS_STATE_ROOT.to_string(),
            "-ServiceName".to_string(),
            "RustyNetSmoke".to_string(),
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
         try {{ \
           if ($service.Status -eq 'Running') {{ Restart-Service -Name $serviceName -ErrorAction Stop }} else {{ Start-Service -Name $serviceName -ErrorAction Stop }} \
         }} catch {{ \
           Write-Output (\"service-control-error=\" + $_.Exception.Message) \
         }}; \
         Start-Sleep -Seconds 3; \
         $refreshed = Get-Service -Name $serviceName -ErrorAction Stop; \
         Write-Output (\"service-status=\" + [string]$refreshed.Status)",
        service_name = powershell_quote(WINDOWS_SERVICE_NAME)?,
    ))
}

fn parse_windows_runtime_report_output(
    output: &str,
    helper_label: &str,
    target_label: &str,
) -> Result<(), String> {
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return Err(format!(
            "{helper_label} produced no output for {}",
            target_label
        ));
    }
    let parsed: serde_json::Value = serde_json::from_str(trimmed).map_err(|err| {
        format!(
            "{helper_label} did not emit valid JSON for {}: {err}",
            target_label
        )
    })?;
    let status = parsed
        .get("status")
        .and_then(|value| value.as_str())
        .unwrap_or("fail");
    if status == "pass" {
        return Ok(());
    }
    let reason = parsed
        .get("reason")
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty());
    let service_status = parsed
        .get("service_status")
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty());
    let backend_label = parsed
        .get("backend_label")
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty());
    let start_error = parsed
        .get("start_error")
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
    let mut details = Vec::new();
    if let Some(reason) = reason {
        details.push(format!("reason={reason}"));
    }
    if let Some(service_status) = service_status {
        details.push(format!("service_status={service_status}"));
    }
    if let Some(backend_label) = backend_label {
        details.push(format!("backend_label={backend_label}"));
    }
    if let Some(start_error) = start_error {
        details.push(format!("start_error={start_error}"));
    }
    if let Some(notes) = notes {
        details.push(format!("notes={notes}"));
    }
    let detail_suffix = if details.is_empty() {
        String::new()
    } else {
        format!(" {}", details.join(" "))
    };
    Err(format!(
        "{helper_label} reported status={status} for {}{}",
        target_label, detail_suffix
    ))
}

fn parse_windows_service_host_smoke_output(output: &str, target_label: &str) -> Result<(), String> {
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return Err(format!(
            "Windows service-host smoke helper produced no output for {}",
            target_label
        ));
    }
    let parsed: serde_json::Value = serde_json::from_str(trimmed).map_err(|err| {
        format!(
            "Windows service-host smoke helper did not emit valid JSON for {}: {err}",
            target_label
        )
    })?;
    let status = parsed
        .get("status")
        .and_then(|value| value.as_str())
        .unwrap_or("fail");
    let reason = parsed
        .get("reason")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    let backend_label = parsed
        .get("backend_label")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    let host_surface_validated = parsed
        .get("host_surface_validated")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let cleanup_status = parsed
        .get("cleanup_status")
        .and_then(|value| value.as_str())
        .unwrap_or("");

    if !host_surface_validated {
        return Err(format!(
            "Windows service-host smoke helper reported status={status} reason={reason} host_surface_validated=false for {target_label}"
        ));
    }
    if cleanup_status != "removed" {
        return Err(format!(
            "Windows service-host smoke helper reported status={status} cleanup_status={cleanup_status} for {target_label}"
        ));
    }
    if status == "pass" {
        return Ok(());
    }
    if status == "blocked"
        && reason == "windows-runtime-backend-explicitly-unsupported"
        && backend_label == "windows-unsupported"
    {
        return Ok(());
    }

    Err(format!(
        "Windows service-host smoke helper reported status={status} reason={reason} backend_label={backend_label} for {target_label}"
    ))
}

fn build_windows_service_host_smoke_validation_script(
    remote_path: &str,
    args: &[String],
    remote_result_path: &str,
) -> Result<String, String> {
    let mut helper_args = args.to_vec();
    helper_args.push("-OutputPath".to_string());
    helper_args.push(remote_result_path.to_string());
    let helper_command = build_windows_helper_command(remote_path, helper_args.as_slice())?;
    Ok(format!(
        "Set-StrictMode -Version Latest; \
         $ErrorActionPreference = 'Stop'; \
         $resultPath = {result_path}; \
         $resultParent = Split-Path -Path $resultPath -Parent; \
         if ($resultParent -and -not (Test-Path -LiteralPath $resultParent)) {{ \
           New-Item -ItemType Directory -Path $resultParent -Force | Out-Null \
         }}; \
         if (Test-Path -LiteralPath $resultPath) {{ \
           Remove-Item -LiteralPath $resultPath -Force \
         }}; \
         {helper_command}; \
         if (-not (Test-Path -LiteralPath $resultPath)) {{ \
           throw ('Windows service-host smoke helper did not write result file: {{0}}' -f $resultPath) \
         }}; \
         $report = Get-Content -Raw -LiteralPath $resultPath -Encoding UTF8 | ConvertFrom-Json; \
         if (-not $report.host_surface_validated) {{ \
           throw 'Windows service-host smoke helper reported host_surface_validated=false' \
         }}; \
         if ($report.cleanup_status -ne 'removed') {{ \
           throw ('Windows service-host smoke helper left cleanup_status={{0}}' -f [string]$report.cleanup_status) \
         }}; \
         if ($report.status -eq 'pass') {{ exit 0 }}; \
         if ($report.status -eq 'blocked' -and $report.reason -eq 'windows-runtime-backend-explicitly-unsupported' -and $report.backend_label -eq 'windows-unsupported') {{ exit 0 }}; \
         throw ('Windows service-host smoke helper reported status={{0}} reason={{1}} backend_label={{2}}' -f [string]$report.status, [string]$report.reason, [string]$report.backend_label)",
        result_path = powershell_quote(remote_result_path)?,
        helper_command = helper_command,
    ))
}

fn build_windows_runtime_report_validation_script(
    remote_path: &str,
    args: &[String],
    remote_result_path: &str,
    helper_label: &str,
) -> Result<String, String> {
    ensure_no_control_chars("Windows runtime helper label", helper_label)?;
    let mut helper_args = args.to_vec();
    helper_args.push("-OutputPath".to_string());
    helper_args.push(remote_result_path.to_string());
    let helper_command = build_windows_helper_command(remote_path, helper_args.as_slice())?;
    Ok(format!(
        "Set-StrictMode -Version Latest; \
         $ErrorActionPreference = 'Stop'; \
         $ProgressPreference = 'SilentlyContinue'; \
         $validationRc = 1; \
         $validationMessage = ''; \
         $resultPath = {result_path}; \
         $resultParent = Split-Path -Path $resultPath -Parent; \
         if ($resultParent -and -not (Test-Path -LiteralPath $resultParent)) {{ \
           New-Item -ItemType Directory -Path $resultParent -Force | Out-Null \
         }}; \
         if (Test-Path -LiteralPath $resultPath) {{ \
           Remove-Item -LiteralPath $resultPath -Force \
         }}; \
         try {{ \
           {helper_command}; \
           if (-not (Test-Path -LiteralPath $resultPath)) {{ \
             $validationMessage = ('{helper_label} did not write result file: {{0}}' -f $resultPath) \
           }} else {{ \
             $body = Get-Content -Raw -LiteralPath $resultPath -Encoding UTF8; \
             if ([string]::IsNullOrWhiteSpace($body)) {{ \
               $validationMessage = ('{helper_label} wrote empty result file: {{0}}' -f $resultPath) \
             }} else {{ \
               $report = $body | ConvertFrom-Json; \
               if ($report.status -eq 'pass') {{ \
                 $validationRc = 0 \
               }} else {{ \
                 $validationMessage = ('{helper_label} reported status={{0}} reason={{1}} backend_label={{2}} service_status={{3}} start_error={{4}} result_path={{5}}' -f [string]$report.status, [string]$report.reason, [string]$report.backend_label, [string]$report.service_status, [string]$report.start_error, $resultPath) \
               }} \
             }} \
           }} \
         }} catch {{ \
           $validationMessage = (($_ | Out-String).Trim()) \
         }}; \
         if (-not [string]::IsNullOrWhiteSpace($validationMessage)) {{ Write-Output $validationMessage }}; \
         Write-Output ('__RUSTYNET_VM_LAB_RC__={{0}}' -f $validationRc); \
         exit 0",
        result_path = powershell_quote(remote_result_path)?,
        helper_command = helper_command,
        helper_label = helper_label,
    ))
}

fn build_windows_diagnostics_validation_script(
    remote_path: &str,
    args: &[String],
    output_root: &str,
) -> Result<String, String> {
    let helper_command = build_windows_helper_command(remote_path, args)?;
    Ok(format!(
        "Set-StrictMode -Version Latest; \
         $ErrorActionPreference = 'Stop'; \
         $outputRoot = {output_root}; \
         {helper_command}; \
         if (-not (Test-Path -LiteralPath $outputRoot)) {{ \
           throw ('Windows diagnostics helper did not create output root: {{0}}' -f $outputRoot) \
         }}; \
         $manifestPath = Join-Path $outputRoot 'manifest.json'; \
         if (-not (Test-Path -LiteralPath $manifestPath)) {{ \
           throw ('Windows diagnostics helper did not create manifest: {{0}}' -f $manifestPath) \
         }}; \
         $null = Get-Content -Raw -LiteralPath $manifestPath -Encoding UTF8 | ConvertFrom-Json; \
         exit 0",
        output_root = powershell_quote(output_root)?,
        helper_command = helper_command,
    ))
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

    fn run_helper_via_local_utm_result_file(
        &self,
        target: &RemoteTarget,
        context: &BootstrapPhaseContext<'_>,
        invocation: WindowsHelperScriptSpec,
        label: &str,
    ) -> Result<(), String> {
        let helper_context = self.helper_context(target, context);
        let (utm_name, _) = remote_target_local_utm(helper_context.target).ok_or_else(|| {
            format!(
                "{label} requested local UTM result-file mode for non-UTM target {}",
                target.label
            )
        })?;
        let local_path = windows_helper_script_local_path(invocation.helper_file_name);
        let remote_path = stage_windows_helper_script_from_path_with_phase(
            &helper_context,
            local_path.as_path(),
            invocation.remote_file_name,
            RemoteTransportPhase::AccessEstablishment,
        )?;
        let remote_result_name = format!(
            "{}.result.{}.json",
            sanitize_label_for_path(invocation.remote_file_name),
            unique_suffix()
        );
        let remote_result_path =
            windows_helper_script_remote_path(helper_context.target, remote_result_name.as_str())?;
        let validation_script = build_windows_runtime_report_validation_script(
            remote_path.as_str(),
            invocation.args.as_slice(),
            remote_result_path.as_str(),
            label,
        )?;
        let (status, output) = utm_exec_windows_raw_with_output(
            utm_name,
            validation_script.as_str(),
            helper_context.timeout,
        )
        .map_err(|err| format!("{label} failed for {}: {err}", target.label))?;
        let _ = best_effort_remove_windows_local_utm_guest_file(
            utm_name,
            remote_result_path.as_str(),
            Duration::from_secs(20),
        );
        let mut validation_rc = None::<i32>;
        let detail = output
            .lines()
            .map(str::trim)
            .filter_map(|line| {
                if line.is_empty() || line.starts_with("#< CLIXML") {
                    return None;
                }
                if let Some(value) = line.strip_prefix("__RUSTYNET_VM_LAB_RC__=") {
                    validation_rc = value.trim().parse::<i32>().ok();
                    return None;
                }
                Some(line)
            })
            .collect::<Vec<_>>()
            .join(" ");
        match validation_rc {
            Some(0) => Ok(()),
            Some(_) if !detail.is_empty() => Err(format!(
                "{label} failed for {}: {} (result_path={})",
                target.label, detail, remote_result_path
            )),
            Some(rc) => Err(format!(
                "{label} failed for {} with validation rc {} (result_path={})",
                target.label, rc, remote_result_path
            )),
            None if !status.success() => Err(format!(
                "{label} failed for {} with host status {} and missing validation rc marker (result_path={})",
                target.label,
                status_code(status),
                remote_result_path
            )),
            None if !detail.is_empty() => Err(format!(
                "{label} failed for {} without validation rc marker: {} (result_path={})",
                target.label, detail, remote_result_path
            )),
            None => Err(format!(
                "{label} failed for {} without validation rc marker (result_path={})",
                target.label, remote_result_path
            )),
        }
    }

    fn collect_failure_diagnostics(
        &self,
        phase: BootstrapPhase,
        target: &RemoteTarget,
        context: &BootstrapPhaseContext<'_>,
    ) -> Result<String, String> {
        if matches!(
            windows_local_utm_execution_authority(target, false),
            Some(WindowsLocalUtmExecutionAuthority::StatusProbeResultFile)
        ) {
            let helper_context = self.helper_context(target, context);
            let invocation = build_windows_diagnostics_invocation(target, phase)?;
            let remote_path = stage_windows_helper_script_from_path_with_phase(
                &helper_context,
                windows_diagnostics_helper_script_local_path().as_path(),
                invocation.remote_file_name,
                RemoteTransportPhase::AccessEstablishment,
            )?;
            let output_root = invocation
                .args
                .chunks(2)
                .find_map(|chunk| match chunk {
                    [flag, value] if flag == "-OutputRoot" => Some(value.as_str()),
                    _ => None,
                })
                .ok_or_else(|| {
                    format!(
                        "Windows diagnostics invocation did not provide -OutputRoot for {}",
                        target.label
                    )
                })?;
            let validation_script = build_windows_diagnostics_validation_script(
                remote_path.as_str(),
                invocation.args.as_slice(),
                output_root,
            )?;
            let status = run_remote_shell_command_for_target_with_phase(
                helper_context.target,
                helper_context.ssh_user_override,
                helper_context.ssh_identity_file,
                helper_context.known_hosts_path,
                validation_script.as_str(),
                helper_context.timeout,
                RemoteTransportPhase::AccessEstablishment,
            )
            .map_err(|err| {
                format!(
                    "Windows diagnostics helper failed for {}: {err}",
                    target.label
                )
            })?;
            if !status.success() {
                return Err(format!(
                    "Windows diagnostics helper failed for {} with status {} (output_root={output_root})",
                    target.label,
                    status_code(status)
                ));
            }
            return Ok(output_root.to_string());
        }
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
            format_windows_phase_failure_with_diagnostics(
                err.as_str(),
                target.label.as_str(),
                self.collect_failure_diagnostics(phase, target, context),
            )
        })
    }

    fn ensure_proven_access_for_phase(
        &self,
        phase: BootstrapPhase,
        target: &RemoteTarget,
        context: &BootstrapPhaseContext<'_>,
    ) -> Result<(), String> {
        if !phase_requires_proven_access(phase)
            || local_utm_result_file_supported_for_phase(phase, target)
        {
            return Ok(());
        }
        ensure_windows_runtime_access_ready_for_target(
            target,
            context.ssh_user,
            context.ssh_identity_file,
            context.known_hosts_path,
            context.timeout,
        )
        .map_err(|err| render_windows_access_gate_error(phase, target.label.as_str(), err.as_str()))
    }

    fn execute_single_phase(
        &self,
        phase: BootstrapPhase,
        target: &RemoteTarget,
        context: &BootstrapPhaseContext<'_>,
    ) -> Result<(), String> {
        self.ensure_proven_access_for_phase(phase, target, context)?;
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
            BootstrapPhase::SmokeServiceHost => {
                let invocation = build_windows_service_host_smoke_invocation(context);
                match windows_local_utm_execution_authority(target, false) {
                    Some(WindowsLocalUtmExecutionAuthority::StatusProbeResultFile) => {
                        let helper_context = self.helper_context(target, context);
                        let local_path = windows_service_host_smoke_helper_script_local_path();
                        let remote_path = stage_windows_helper_script_from_path_with_phase(
                            &helper_context,
                            local_path.as_path(),
                            invocation.remote_file_name,
                            RemoteTransportPhase::AccessEstablishment,
                        )?;
                        let remote_result_name = format!(
                            "{}.result.{}.json",
                            sanitize_label_for_path(invocation.remote_file_name),
                            unique_suffix()
                        );
                        let remote_result_path = windows_helper_script_remote_path(
                            helper_context.target,
                            remote_result_name.as_str(),
                        )?;
                        let validation_script = build_windows_service_host_smoke_validation_script(
                            remote_path.as_str(),
                            invocation.args.as_slice(),
                            remote_result_path.as_str(),
                        )?;
                        let status = run_remote_shell_command_for_target_with_phase(
                            helper_context.target,
                            helper_context.ssh_user_override,
                            helper_context.ssh_identity_file,
                            helper_context.known_hosts_path,
                            validation_script.as_str(),
                            helper_context.timeout,
                            RemoteTransportPhase::AccessEstablishment,
                        )
                        .map_err(|err| {
                            format!(
                                "Windows service-host smoke helper failed for {}: {err}",
                                target.label
                            )
                        })?;
                        let _ = best_effort_remove_windows_local_utm_guest_file(
                            remote_target_local_utm(helper_context.target)
                                .expect("validated local UTM target")
                                .0,
                            remote_result_path.as_str(),
                            Duration::from_secs(20),
                        );
                        ensure_success_status(status, "Windows service-host smoke helper")
                    }
                    _ => {
                        let output = self.capture_helper_output(
                            target,
                            context,
                            invocation,
                            "Windows service-host smoke helper",
                        )?;
                        parse_windows_service_host_smoke_output(
                            output.as_str(),
                            target.label.as_str(),
                        )
                    }
                }
            }
            BootstrapPhase::InstallRelease => {
                let invocation = build_windows_service_install_invocation(context);
                if local_utm_result_file_supported_for_phase(BootstrapPhase::InstallRelease, target)
                {
                    self.run_helper_via_local_utm_result_file(
                        target,
                        context,
                        invocation,
                        "Windows service install helper",
                    )
                } else {
                    let output = self.capture_helper_output(
                        target,
                        context,
                        invocation,
                        "Windows service install helper",
                    )?;
                    parse_windows_runtime_report_output(
                        output.as_str(),
                        "Windows service install helper",
                        target.label.as_str(),
                    )
                }
            }
            BootstrapPhase::RestartRuntime => {
                capture_remote_shell_command_for_target(
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
                let output = self.capture_helper_output(
                    target,
                    context,
                    build_windows_verify_invocation(context),
                    "Windows verify helper after restart-runtime",
                )?;
                parse_windows_runtime_report_output(
                    output.as_str(),
                    "Windows verify helper after restart-runtime",
                    target.label.as_str(),
                )
            }
            BootstrapPhase::VerifyRuntime => {
                let invocation = build_windows_verify_invocation(context);
                if local_utm_result_file_supported_for_phase(BootstrapPhase::VerifyRuntime, target)
                {
                    self.run_helper_via_local_utm_result_file(
                        target,
                        context,
                        invocation,
                        "Windows verify helper",
                    )
                } else {
                    let output = self.capture_helper_output(
                        target,
                        context,
                        invocation,
                        "Windows verify helper",
                    )?;
                    parse_windows_runtime_report_output(
                        output.as_str(),
                        "Windows verify helper",
                        target.label.as_str(),
                    )
                }
            }
            BootstrapPhase::All => {
                for subphase in [
                    BootstrapPhase::SyncSource,
                    BootstrapPhase::BuildRelease,
                    BootstrapPhase::SmokeServiceHost,
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
    fn windows_service_host_smoke_invocation_uses_canonical_helper_and_runtime_roots() {
        let invocation = build_windows_service_host_smoke_invocation(&sample_context(None));
        assert_eq!(
            invocation.helper_file_name,
            WINDOWS_SERVICE_HOST_SMOKE_HELPER_FILE
        );
        assert_eq!(
            invocation.args,
            vec![
                "-RustyNetRoot",
                r"C:\Rustynet",
                "-StateRoot",
                WINDOWS_STATE_ROOT,
                "-ServiceName",
                "RustyNetSmoke",
            ]
        );
    }

    #[test]
    fn windows_verify_output_parser_rejects_missing_service() {
        let err = parse_windows_runtime_report_output(
            r#"{
                "status": "fail",
                "reason": "windows-runtime-service-host-not-yet-implemented",
                "service_status": "missing",
                "notes": ["windows-service-flags-missing","service-missing"]
            }"#,
            "Windows verify helper",
            "windows-utm-1",
        )
        .expect_err("missing service must fail closed");
        assert!(err.contains("status=fail"));
        assert!(err.contains("reason=windows-runtime-service-host-not-yet-implemented"));
        assert!(err.contains("windows-service-flags-missing"));
    }

    #[test]
    fn windows_runtime_report_parser_surfaces_explicit_backend_blocker() {
        let err = parse_windows_runtime_report_output(
            r#"{
                "status": "blocked",
                "reason": "windows-runtime-backend-explicitly-unsupported",
                "service_status": "Stopped",
                "backend_label": "windows-unsupported",
                "notes": ["service-start-error"]
            }"#,
            "Windows service install helper",
            "windows-utm-1",
        )
        .expect_err("explicit backend blocker must fail closed");
        assert!(err.contains("status=blocked"));
        assert!(err.contains("reason=windows-runtime-backend-explicitly-unsupported"));
        assert!(err.contains("backend_label=windows-unsupported"));
    }

    #[test]
    fn windows_service_host_smoke_parser_accepts_explicit_backend_blocker() {
        parse_windows_service_host_smoke_output(
            r#"{
                "status": "blocked",
                "reason": "windows-runtime-backend-explicitly-unsupported",
                "backend_label": "windows-unsupported",
                "host_surface_validated": true,
                "cleanup_status": "removed"
            }"#,
            "windows-utm-1",
        )
        .expect("reviewed explicit backend blocker should count as smoke success");
    }

    #[test]
    fn windows_service_host_smoke_parser_rejects_unvalidated_host_surface() {
        let err = parse_windows_service_host_smoke_output(
            r#"{
                "status": "blocked",
                "reason": "windows-runtime-backend-explicitly-unsupported",
                "backend_label": "windows-unsupported",
                "host_surface_validated": false,
                "cleanup_status": "removed"
            }"#,
            "windows-utm-1",
        )
        .expect_err("unvalidated host surface must fail closed");
        assert!(err.contains("host_surface_validated=false"));
    }

    #[test]
    fn windows_restart_runtime_script_uses_powershell_service_control() {
        let script =
            build_windows_restart_runtime_script().expect("restart-runtime script should build");
        assert!(script.contains("Restart-Service -Name $serviceName -ErrorAction Stop"));
        assert!(script.contains("Start-Service -Name $serviceName -ErrorAction Stop"));
        assert!(script.contains("service-status="));
        assert!(!script.contains("WaitForStatus('Running'"));
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

    #[test]
    fn windows_runtime_phases_require_proven_access() {
        assert!(!phase_requires_proven_access(BootstrapPhase::SyncSource));
        assert!(!phase_requires_proven_access(BootstrapPhase::BuildRelease));
        assert!(!phase_requires_proven_access(
            BootstrapPhase::SmokeServiceHost
        ));
        assert!(phase_requires_proven_access(BootstrapPhase::InstallRelease));
        assert!(phase_requires_proven_access(BootstrapPhase::RestartRuntime));
        assert!(phase_requires_proven_access(BootstrapPhase::VerifyRuntime));
        assert!(!phase_requires_proven_access(BootstrapPhase::All));
    }

    #[test]
    fn local_utm_result_file_support_is_limited_to_install_and_verify() {
        let target = RemoteTarget {
            label: "windows-utm-1".to_string(),
            ssh_target: "192.168.64.14".to_string(),
            ssh_user: Some("Administrator".to_string()),
            controller: Some(VmController::LocalUtm {
                utm_name: "Windows".to_string(),
                bundle_path: std::path::PathBuf::from("/tmp/Windows.utm"),
            }),
            platform_profile: default_platform_profile(VmGuestPlatform::Windows),
            rustynet_src_dir: Some(r"C:\Rustynet".to_string()),
            remote_temp_dir: Some(r"C:\ProgramData\Rustynet\vm-lab".to_string()),
        };

        assert!(local_utm_result_file_supported_for_phase(
            BootstrapPhase::InstallRelease,
            &target
        ));
        assert!(local_utm_result_file_supported_for_phase(
            BootstrapPhase::VerifyRuntime,
            &target
        ));
        assert!(!local_utm_result_file_supported_for_phase(
            BootstrapPhase::RestartRuntime,
            &target
        ));
    }

    #[test]
    fn windows_diagnostics_validation_script_requires_manifest() {
        let script = build_windows_diagnostics_validation_script(
            r"C:\ProgramData\Rustynet\vm-lab\Collect-RustyNetWindowsDiagnostics.ps1",
            &[
                "-OutputRoot".to_string(),
                r"C:\ProgramData\Rustynet\vm-lab\diagnostics\run-1".to_string(),
            ],
            r"C:\ProgramData\Rustynet\vm-lab\diagnostics\run-1",
        )
        .expect("diagnostics validation script should build");

        assert!(script.contains("manifest.json"));
        assert!(script.contains("ConvertFrom-Json"));
        assert!(script.contains("did not create output root"));
    }

    #[test]
    fn windows_runtime_report_validation_script_uses_output_path_and_plaintext_errors() {
        let script = build_windows_runtime_report_validation_script(
            r"C:\ProgramData\Rustynet\vm-lab\Install-RustyNetWindowsService.ps1",
            &[
                "-RustyNetRoot".to_string(),
                r"C:\Rustynet".to_string(),
                "-InstallRoot".to_string(),
                r"C:\Program Files\RustyNet".to_string(),
            ],
            r"C:\ProgramData\Rustynet\vm-lab\install-report.json",
            "Windows service install helper",
        )
        .expect("runtime report validation script should build");

        assert!(script.contains("$ProgressPreference = 'SilentlyContinue'"));
        assert!(script.contains("-OutputPath"));
        assert!(script.contains("did not write result file"));
        assert!(script.contains("reported status={0} reason={1} backend_label={2}"));
        assert!(script.contains("Write-Output"));
        assert!(script.contains("__RUSTYNET_VM_LAB_RC__="));
    }

    #[test]
    fn windows_access_gate_error_carries_phase_and_root_cause() {
        let rendered = render_windows_access_gate_error(
            BootstrapPhase::VerifyRuntime,
            "windows-utm-1",
            "ssh-access-not-ready: ssh-host-key-not-ready: Host key verification failed.",
        );
        assert!(rendered.contains("phase verify-runtime"));
        assert!(rendered.contains("windows-utm-1"));
        assert!(rendered.contains("ssh-host-key-not-ready"));
    }

    #[test]
    fn windows_failure_diagnostics_formatter_preserves_output_root() {
        let rendered = format_windows_phase_failure_with_diagnostics(
            "Windows phase verify-runtime requires proven access for windows-utm-1: ssh-access-not-ready: ssh-auth-rejected",
            "windows-utm-1",
            Ok(r"C:\ProgramData\RustyNet\vm-lab\diagnostics\bootstrap-windows-utm-1-verify-runtime-1".to_string()),
        );
        assert!(rendered.contains("diagnostics_output_root="));
        assert!(rendered.contains("windows-utm-1"));
        assert!(rendered.contains("verify-runtime"));
    }
}
