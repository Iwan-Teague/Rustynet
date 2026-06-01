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
        BootstrapPhase::BuildRelease
            | BootstrapPhase::InstallRelease
            | BootstrapPhase::RestartRuntime
            | BootstrapPhase::VerifyRuntime
            | BootstrapPhase::TunnelSmoke
            | BootstrapPhase::KillswitchSmoke
            | BootstrapPhase::DnsSmoke
            | BootstrapPhase::Ipv6Smoke
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

fn local_utm_result_file_supported_for_phase(
    _phase: BootstrapPhase,
    _target: &RemoteTarget,
) -> bool {
    // Runtime phases run through pinned SSH after access is proven. UTM
    // result-file execution is still useful for initial access recovery,
    // but it is not reliable enough for post-bootstrap phase completion:
    // a healthy guest can write the result and still leave host-side UTM
    // file pulls sleeping until the phase timeout.
    false
}

fn build_windows_build_release_report_paths(
    target: &RemoteTarget,
) -> Result<(String, String, String), String> {
    let remote_root = windows_orchestration_root(target);
    ensure_no_control_chars("Windows build-release report root", remote_root.as_str())?;
    let report_root = format!(
        r"{}\build-release\bootstrap-{}-build-release-{}",
        remote_root.trim_end_matches(['\\', '/']),
        sanitize_label_for_path(target.label.as_str()),
        unique_suffix()
    );
    Ok((
        report_root.clone(),
        format!(r"{report_root}\manifest.json"),
        format!(r"{report_root}\probe.json"),
    ))
}

fn build_windows_bootstrap_build_release_result_script(
    remote_path: &str,
    args: &[String],
    remote_manifest_path: &str,
    remote_probe_path: &str,
) -> Result<String, String> {
    let mut helper_args = args.to_vec();
    helper_args.push("-ResultPath".to_owned());
    helper_args.push(remote_manifest_path.to_owned());
    let helper_command = build_windows_helper_command(remote_path, helper_args.as_slice())?;
    Ok(format!(
        "Set-StrictMode -Version Latest; \
         $ErrorActionPreference = 'Stop'; \
         $ProgressPreference = 'SilentlyContinue'; \
         $manifestPath = {manifest_path}; \
         $probePath = {probe_path}; \
         $reportRoot = Split-Path -Path $manifestPath -Parent; \
         $stdoutPath = Join-Path $reportRoot 'stdout.txt'; \
         $stderrPath = Join-Path $reportRoot 'stderr.txt'; \
         $exitCodePath = Join-Path $reportRoot 'exit_code.txt'; \
         $toolchainPath = Join-Path $reportRoot 'toolchain.txt'; \
         $markerPath = Join-Path $reportRoot 'complete.marker'; \
         $probeParent = Split-Path -Path $probePath -Parent; \
         if ($probeParent -and -not (Test-Path -LiteralPath $probeParent)) {{ \
           New-Item -ItemType Directory -Path $probeParent -Force | Out-Null \
         }}; \
         if (Test-Path -LiteralPath $probePath) {{ \
           Remove-Item -LiteralPath $probePath -Force -ErrorAction SilentlyContinue \
         }}; \
         $helperFailure = ''; \
         try {{ \
           {helper_command}; \
         }} catch {{ \
           $helperFailure = if ($_.Exception -and $_.Exception.Message) {{ $_.Exception.Message.Trim() }} else {{ ($_ | Out-String).Trim() }} \
         }}; \
         $body = ''; \
         $validationFailure = ''; \
         if (-not (Test-Path -LiteralPath $manifestPath)) {{ \
           if ([string]::IsNullOrWhiteSpace($helperFailure)) {{ \
             $validationFailure = ('Windows bootstrap build-release helper did not write manifest: {{0}}' -f $manifestPath) \
           }} else {{ \
             $validationFailure = $helperFailure \
           }} \
         }} elseif (-not (Test-Path -LiteralPath $markerPath)) {{ \
           if ([string]::IsNullOrWhiteSpace($helperFailure)) {{ \
             $validationFailure = ('Windows bootstrap build-release helper did not write complete.marker: {{0}}' -f $markerPath) \
           }} else {{ \
             $validationFailure = $helperFailure \
           }} \
         }} else {{ \
           try {{ \
             $body = Get-Content -Raw -LiteralPath $manifestPath -Encoding UTF8; \
             if ([string]::IsNullOrWhiteSpace($body)) {{ \
               throw ('Windows bootstrap build-release helper wrote empty manifest: {{0}}' -f $manifestPath) \
             }}; \
             $report = $body | ConvertFrom-Json -ErrorAction Stop; \
             foreach ($requiredField in @('phase', 'status', 'reason', 'report_root', 'stdout_path', 'stderr_path', 'exit_code_path', 'toolchain_path', 'manifest_path', 'complete_marker_path')) {{ \
               $value = $report.$requiredField; \
               if ($null -eq $value -or ([string]$value).Trim().Length -eq 0) {{ \
                 throw ('Windows bootstrap build-release manifest missing field: {{0}}' -f $requiredField) \
               }} \
             }}; \
             if ([string]$report.phase -ne 'build-release') {{ \
               throw ('Windows bootstrap build-release manifest reported unexpected phase: {{0}}' -f [string]$report.phase) \
             }}; \
             if ([string]$report.report_root -ne $reportRoot) {{ \
               throw ('Windows bootstrap build-release manifest reported unexpected report_root: {{0}}' -f [string]$report.report_root) \
             }}; \
             if ([string]$report.manifest_path -ne $manifestPath) {{ \
               throw ('Windows bootstrap build-release manifest reported unexpected manifest_path: {{0}}' -f [string]$report.manifest_path) \
             }}; \
             if ([string]$report.complete_marker_path -ne $markerPath) {{ \
               throw ('Windows bootstrap build-release manifest reported unexpected complete_marker_path: {{0}}' -f [string]$report.complete_marker_path) \
             }}; \
             foreach ($requiredPath in @($stdoutPath, $stderrPath, $exitCodePath, $toolchainPath, $markerPath)) {{ \
               if (-not (Test-Path -LiteralPath $requiredPath)) {{ \
                 throw ('Windows bootstrap build-release missing report file: {{0}}' -f $requiredPath) \
               }} \
             }}; \
           }} catch {{ \
             $validationFailure = if ($_.Exception -and $_.Exception.Message) {{ $_.Exception.Message.Trim() }} else {{ ($_ | Out-String).Trim() }} \
           }} \
         }}; \
         if (-not [string]::IsNullOrWhiteSpace($validationFailure)) {{ \
           $body = ([ordered]@{{ \
             phase = 'build-release'; \
             status = 'fail'; \
             reason = $validationFailure; \
             report_root = $reportRoot; \
             stdout_path = $stdoutPath; \
             stderr_path = $stderrPath; \
             exit_code_path = $exitCodePath; \
             toolchain_path = $toolchainPath; \
             manifest_path = $manifestPath; \
             complete_marker_path = $markerPath; \
             exit_code = 1; \
             stderr_tail = ''; \
             notes = @('build-release-wrapper-fallback') \
           }} | ConvertTo-Json -Compress) \
         }}; \
         Set-Content -LiteralPath $probePath -Value $body -Encoding UTF8; \
         Write-Output $body; \
         if (-not [string]::IsNullOrWhiteSpace($validationFailure)) {{ exit 1 }}",
        manifest_path = powershell_quote(remote_manifest_path)?,
        probe_path = powershell_quote(remote_probe_path)?,
        helper_command = helper_command,
    ))
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
        "-Phase".to_owned(),
        phase.as_str().to_owned(),
        "-RustyNetRoot".to_owned(),
        context.workdir.to_owned(),
        "-Branch".to_owned(),
        context.branch.to_owned(),
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
            args.push("-SourceMode".to_owned());
            args.push("git".to_owned());
            args.push("-RepoUrl".to_owned());
            args.push(repo_url.to_owned());
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
        | BootstrapPhase::TunnelSmoke
        | BootstrapPhase::KillswitchSmoke
        | BootstrapPhase::DnsSmoke
        | BootstrapPhase::Ipv6Smoke
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
            "-RustyNetRoot".to_owned(),
            context.workdir.to_owned(),
            "-InstallRoot".to_owned(),
            WINDOWS_INSTALL_ROOT.to_owned(),
            "-StateRoot".to_owned(),
            WINDOWS_STATE_ROOT.to_owned(),
            "-ServiceName".to_owned(),
            WINDOWS_SERVICE_NAME.to_owned(),
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
            "-RustyNetRoot".to_owned(),
            context.workdir.to_owned(),
            "-StateRoot".to_owned(),
            WINDOWS_STATE_ROOT.to_owned(),
            "-ServiceName".to_owned(),
            "RustyNetSmoke".to_owned(),
        ],
    }
}

fn build_windows_tunnel_smoke_invocation(
    context: &BootstrapPhaseContext<'_>,
) -> WindowsHelperScriptSpec {
    WindowsHelperScriptSpec {
        helper_file_name: WINDOWS_TUNNEL_SMOKE_HELPER_FILE,
        remote_file_name: WINDOWS_TUNNEL_SMOKE_HELPER_FILE,
        args: vec![
            "-RustyNetRoot".to_owned(),
            context.workdir.to_owned(),
            "-StateRoot".to_owned(),
            WINDOWS_STATE_ROOT.to_owned(),
        ],
    }
}

fn build_windows_killswitch_smoke_invocation(
    context: &BootstrapPhaseContext<'_>,
) -> WindowsHelperScriptSpec {
    // The standard phase run exercises apply/assert/rollback only (SSH-safe via
    // the killswitch's egress-allow rule). The full fail-closed block
    // (`-ExerciseFullBlock`) is deliberately NOT requested here; it cuts a LAN
    // SSH session until rollback and is reserved for an explicit operator run.
    WindowsHelperScriptSpec {
        helper_file_name: WINDOWS_KILLSWITCH_SMOKE_HELPER_FILE,
        remote_file_name: WINDOWS_KILLSWITCH_SMOKE_HELPER_FILE,
        args: vec![
            "-RustyNetRoot".to_owned(),
            context.workdir.to_owned(),
            "-StateRoot".to_owned(),
            WINDOWS_STATE_ROOT.to_owned(),
        ],
    }
}

fn build_windows_dns_smoke_invocation(
    context: &BootstrapPhaseContext<'_>,
) -> WindowsHelperScriptSpec {
    // N3 reuses the killswitch smoke harness with its DNS leg enabled: while the
    // killswitch is active, exercise the netsh port-53 LAN-block (apply / assert /
    // rollback). Still SSH-safe — the full fail-closed block is not requested, and
    // the DNS block is port-53 only.
    WindowsHelperScriptSpec {
        helper_file_name: WINDOWS_KILLSWITCH_SMOKE_HELPER_FILE,
        remote_file_name: WINDOWS_KILLSWITCH_SMOKE_HELPER_FILE,
        args: vec![
            "-RustyNetRoot".to_owned(),
            context.workdir.to_owned(),
            "-StateRoot".to_owned(),
            WINDOWS_STATE_ROOT.to_owned(),
            "-ExerciseDns".to_owned(),
        ],
    }
}

fn build_windows_ipv6_smoke_invocation(
    context: &BootstrapPhaseContext<'_>,
) -> WindowsHelperScriptSpec {
    // G8 reuses the killswitch smoke harness with its IPv6 leg enabled: while the
    // killswitch is active, confirm IPv6 egress leaks, apply the IPv6 LAN block,
    // confirm it is blocked, then roll back. SSH-safe — the IPv6 block is
    // LAN-IPv6 only (SSH is IPv4) and the full fail-closed block is not requested.
    WindowsHelperScriptSpec {
        helper_file_name: WINDOWS_KILLSWITCH_SMOKE_HELPER_FILE,
        remote_file_name: WINDOWS_KILLSWITCH_SMOKE_HELPER_FILE,
        args: vec![
            "-RustyNetRoot".to_owned(),
            context.workdir.to_owned(),
            "-StateRoot".to_owned(),
            WINDOWS_STATE_ROOT.to_owned(),
            "-ExerciseIpv6".to_owned(),
        ],
    }
}

fn build_windows_verify_invocation(
    context: &BootstrapPhaseContext<'_>,
    require_live_path: bool,
) -> WindowsHelperScriptSpec {
    let mut args = vec![
        "-RustyNetRoot".to_owned(),
        context.workdir.to_owned(),
        "-InstallRoot".to_owned(),
        WINDOWS_INSTALL_ROOT.to_owned(),
        "-StateRoot".to_owned(),
        WINDOWS_STATE_ROOT.to_owned(),
        "-ServiceName".to_owned(),
        WINDOWS_SERVICE_NAME.to_owned(),
    ];
    if require_live_path {
        args.push("-RequireLivePath".to_owned());
    }
    WindowsHelperScriptSpec {
        helper_file_name: WINDOWS_VERIFY_HELPER_FILE,
        remote_file_name: WINDOWS_VERIFY_HELPER_FILE,
        args,
    }
}

fn build_windows_diagnostics_invocation(
    target: &RemoteTarget,
    phase: BootstrapPhase,
) -> Result<WindowsHelperScriptSpec, String> {
    let remote_root = windows_orchestration_root(target);
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
        args: vec!["-OutputRoot".to_owned(), output_root],
    })
}

fn build_windows_restart_runtime_script() -> Result<String, String> {
    Ok(format!(
        "Set-StrictMode -Version Latest; \
         $ErrorActionPreference = 'Stop'; \
         $serviceName = {service_name}; \
         $expectedBinary = {expected_binary}; \
         function Get-RustyNetServicePid {{ \
           $query = (& sc.exe queryex $serviceName 2>&1 | Out-String); \
           foreach ($line in ($query -split \"`r?`n\")) {{ \
             if ($line -match '^\\s*PID\\s*:\\s*(\\d+)\\s*$') {{ return [int]$Matches[1] }} \
           }}; \
           return 0 \
         }}; \
         function Wait-RustyNetStopped([int]$Seconds) {{ \
           $deadline = (Get-Date).AddSeconds($Seconds); \
           while ((Get-Date) -lt $deadline) {{ \
             $current = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; \
             if (-not $current -or $current.Status -eq 'Stopped') {{ return $true }}; \
             Start-Sleep -Milliseconds 250 \
           }}; \
           return $false \
         }}; \
         function Stop-RustyNetServiceBounded {{ \
           $current = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; \
           if (-not $current) {{ throw \"Windows runtime service is not installed: $serviceName\" }}; \
           if ($current.Status -eq 'Stopped') {{ return }}; \
           if ($current.Status -ne 'StopPending') {{ \
             $stopOutput = (& sc.exe stop $serviceName 2>&1 | Out-String); \
             if ($LASTEXITCODE -ne 0 -and $stopOutput -notmatch '1062') {{ throw \"sc.exe stop failed: $stopOutput\" }} \
           }}; \
           if (Wait-RustyNetStopped 20) {{ return }}; \
           $current = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; \
           if ($current -and $current.Status -eq 'StopPending') {{ \
             $servicePid = Get-RustyNetServicePid; \
             if ($servicePid -le 0) {{ throw \"RustyNet service is StopPending with no process id\" }}; \
             $process = Get-Process -Id $servicePid -ErrorAction Stop; \
             $actual = [System.IO.Path]::GetFullPath([string]$process.Path); \
             $expected = [System.IO.Path]::GetFullPath($expectedBinary); \
             if ($actual -ine $expected) {{ throw \"refusing to kill StopPending service pid=$servicePid actual=$actual expected=$expected\" }}; \
             Stop-Process -Id $servicePid -Force -ErrorAction Stop; \
             if (Wait-RustyNetStopped 10) {{ return }} \
           }}; \
           $current = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; \
           if ($current -and $current.Status -ne 'Stopped') {{ throw \"RustyNet service did not stop; status=$($current.Status)\" }} \
         }}; \
         $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; \
         if (-not $service) {{ throw \"Windows runtime service is not installed: $serviceName\" }}; \
         try {{ \
           Stop-RustyNetServiceBounded; \
           $startOutput = (& sc.exe start $serviceName 2>&1 | Out-String); \
           if ($LASTEXITCODE -ne 0 -and $startOutput -notmatch '1056|already running') {{ throw \"sc.exe start failed: $startOutput\" }} \
         }} catch {{ \
           Write-Output (\"service-control-error=\" + $_.Exception.Message) \
         }}; \
         Start-Sleep -Seconds 3; \
         $refreshed = Get-Service -Name $serviceName -ErrorAction Stop; \
         Write-Output (\"service-status=\" + [string]$refreshed.Status)",
        service_name = powershell_quote(WINDOWS_SERVICE_NAME)?,
        expected_binary = powershell_quote(r"C:\Program Files\RustyNet\rustynetd.exe")?,
    ))
}

fn parse_windows_build_release_report_output(
    output: &str,
    target_label: &str,
) -> Result<(), String> {
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return Err(format!(
            "Windows bootstrap build-release produced no report for {target_label}"
        ));
    }
    let parsed: serde_json::Value = serde_json::from_str(trimmed).map_err(|err| {
        format!("Windows bootstrap build-release did not emit valid JSON for {target_label}: {err}")
    })?;
    let status = parsed
        .get("status")
        .and_then(|value| value.as_str())
        .unwrap_or("fail");
    let reason = parsed
        .get("reason")
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("windows-build-release-failed");
    let report_root = parsed
        .get("report_root")
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            format!(
                "Windows bootstrap build-release report was missing report_root for {target_label}"
            )
        })?;
    let exit_code = parsed
        .get("exit_code")
        .map_or_else(|| "unknown".to_owned(), std::string::ToString::to_string);
    let stderr_tail = parsed
        .get("stderr_tail")
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty());
    if status == "pass" {
        return Ok(());
    }
    let mut details = vec![
        format!("reason={reason}"),
        format!("report_root={report_root}"),
    ];
    details.push(format!("exit_code={exit_code}"));
    if let Some(scope) = parsed
        .get("toolchain_scope")
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty())
    {
        details.push(format!("toolchain_scope={scope}"));
    }
    if let Some(stderr_tail) = stderr_tail {
        details.push(format!("stderr_tail={stderr_tail}"));
    }
    Err(format!(
        "Windows bootstrap build-release reported status={status} for {} {}",
        target_label,
        details.join(" ")
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
            "{helper_label} produced no output for {target_label}"
        ));
    }
    let parsed: serde_json::Value = serde_json::from_str(trimmed).map_err(|err| {
        format!("{helper_label} did not emit valid JSON for {target_label}: {err}")
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
    let failure_step = parsed
        .get("failure_step")
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty());
    let runtime_probe_mode = parsed
        .get("runtime_signals")
        .and_then(|value| value.get("probe_mode"))
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty());
    let runtime_probe_excerpt = parsed
        .get("runtime_signals")
        .and_then(|value| value.get("probe_excerpt"))
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.chars().take(160).collect::<String>());
    let require_live_path = parsed
        .get("require_live_path")
        .and_then(|value| value.as_bool());
    let path_live_proven = parsed
        .get("path_live_proven")
        .and_then(|value| value.as_bool());
    let path_latest_live_handshake_unix = parsed
        .get("path_latest_live_handshake_unix")
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
    if let Some(failure_step) = failure_step {
        details.push(format!("failure_step={failure_step}"));
    }
    if let Some(runtime_probe_mode) = runtime_probe_mode {
        details.push(format!("runtime_probe_mode={runtime_probe_mode}"));
    }
    if let Some(runtime_probe_excerpt) = runtime_probe_excerpt {
        details.push(format!("runtime_probe_excerpt={runtime_probe_excerpt}"));
    }
    if let Some(require_live_path) = require_live_path {
        details.push(format!("require_live_path={require_live_path}"));
    }
    if let Some(path_live_proven) = path_live_proven {
        details.push(format!("path_live_proven={path_live_proven}"));
    }
    if let Some(path_latest_live_handshake_unix) = path_latest_live_handshake_unix {
        details.push(format!(
            "path_latest_live_handshake_unix={path_latest_live_handshake_unix}"
        ));
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
        "{helper_label} reported status={status} for {target_label}{detail_suffix}"
    ))
}

fn parse_windows_service_host_smoke_output(output: &str, target_label: &str) -> Result<(), String> {
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return Err(format!(
            "Windows service-host smoke helper produced no output for {target_label}"
        ));
    }
    let parsed: serde_json::Value = serde_json::from_str(trimmed).map_err(|err| {
        format!(
            "Windows service-host smoke helper did not emit valid JSON for {target_label}: {err}"
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
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let failure_step = parsed
        .get("failure_step")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    let runtime_probe_mode = parsed
        .get("runtime_signals")
        .and_then(|value| value.get("probe_mode"))
        .and_then(|value| value.as_str())
        .unwrap_or("");
    let runtime_probe_excerpt = parsed
        .get("runtime_signals")
        .and_then(|value| value.get("probe_excerpt"))
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.chars().take(160).collect::<String>())
        .unwrap_or_default();
    let cleanup_status = parsed
        .get("cleanup_status")
        .and_then(|value| value.as_str())
        .unwrap_or("");

    if !host_surface_validated {
        return Err(format!(
            "Windows service-host smoke helper reported status={status} reason={reason} host_surface_validated=false failure_step={failure_step} runtime_probe_mode={runtime_probe_mode} runtime_probe_excerpt={runtime_probe_excerpt} for {target_label}"
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
        "Windows service-host smoke helper reported status={status} reason={reason} backend_label={backend_label} failure_step={failure_step} runtime_probe_mode={runtime_probe_mode} runtime_probe_excerpt={runtime_probe_excerpt} for {target_label}"
    ))
}

/// Parse the JSON envelope emitted by `Invoke-RustyNetWindowsTunnelSmoke.ps1`.
///
/// The helper runs `rustynetd windows-tunnel-smoke` on the guest, captures the
/// daemon's own tunnel-smoke report, and wraps it in a fixed envelope that
/// surfaces `status` (`pass`/`fail`) and the daemon's `overall_ok` verdict at
/// the top level. A smoke passes only when the wrapper reports `status=pass`
/// **and** the daemon reported `overall_ok=true`; any other shape is a
/// fail-closed error that preserves the daemon's per-stage flags for triage.
fn parse_windows_tunnel_smoke_output(output: &str, target_label: &str) -> Result<(), String> {
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return Err(format!(
            "Windows tunnel smoke helper produced no output for {target_label}"
        ));
    }
    let parsed: serde_json::Value = serde_json::from_str(trimmed).map_err(|err| {
        format!("Windows tunnel smoke helper did not emit valid JSON for {target_label}: {err}")
    })?;
    let status = parsed
        .get("status")
        .and_then(|value| value.as_str())
        .unwrap_or("fail");
    let reason = parsed
        .get("reason")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    let failure_step = parsed
        .get("failure_step")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    let overall_ok = parsed
        .get("overall_ok")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let daemon_exit_code = parsed
        .get("daemon_exit_code")
        .and_then(serde_json::Value::as_i64);
    // Surface the daemon's per-stage flags (when present) so a failed smoke
    // names exactly which step regressed instead of a bare overall_ok=false.
    let report = parsed.get("tunnel_report");
    let report_flag = |key: &str| -> &'static str {
        match report
            .and_then(|value| value.get(key))
            .and_then(serde_json::Value::as_bool)
        {
            Some(true) => "true",
            Some(false) => "false",
            None => "unknown",
        }
    };
    let started = report_flag("started");
    let interface_present = report_flag("interface_present");
    let wg_show_ok = report_flag("wg_show_ok");
    let torn_down = report_flag("torn_down");

    if status == "pass" && overall_ok {
        return Ok(());
    }

    let exit_code = daemon_exit_code
        .map(|code| code.to_string())
        .unwrap_or_else(|| "unknown".to_owned());
    Err(format!(
        "Windows tunnel smoke helper reported status={status} overall_ok={overall_ok} reason={reason} failure_step={failure_step} daemon_exit_code={exit_code} started={started} interface_present={interface_present} wg_show_ok={wg_show_ok} torn_down={torn_down} for {target_label}"
    ))
}

/// Parse the JSON envelope emitted by `Invoke-RustyNetWindowsKillswitchSmoke.ps1`.
///
/// The helper runs `rustynetd windows-killswitch-smoke` on the guest, captures
/// the daemon's own killswitch-smoke report, and wraps it in a fixed envelope
/// that surfaces `status` (`pass`/`fail`) and the daemon's `overall_ok` verdict
/// at the top level. A smoke passes only when the wrapper reports `status=pass`
/// **and** the daemon reported `overall_ok=true`; any other shape is a
/// fail-closed error that preserves the daemon's per-stage flags for triage.
fn parse_windows_killswitch_smoke_output(output: &str, target_label: &str) -> Result<(), String> {
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return Err(format!(
            "Windows killswitch smoke helper produced no output for {target_label}"
        ));
    }
    let parsed: serde_json::Value = serde_json::from_str(trimmed).map_err(|err| {
        format!("Windows killswitch smoke helper did not emit valid JSON for {target_label}: {err}")
    })?;
    let status = parsed
        .get("status")
        .and_then(|value| value.as_str())
        .unwrap_or("fail");
    let reason = parsed
        .get("reason")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    let failure_step = parsed
        .get("failure_step")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    let overall_ok = parsed
        .get("overall_ok")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let daemon_exit_code = parsed
        .get("daemon_exit_code")
        .and_then(serde_json::Value::as_i64);
    // Surface the daemon's per-stage flags (when present) so a failed smoke names
    // exactly which control step regressed instead of a bare overall_ok=false.
    let report = parsed.get("killswitch_report");
    let report_flag = |key: &str| -> &'static str {
        match report
            .and_then(|value| value.get(key))
            .and_then(serde_json::Value::as_bool)
        {
            Some(true) => "true",
            Some(false) => "false",
            None => "unknown",
        }
    };
    let permit_absent_before = report_flag("permit_absent_before");
    let applied = report_flag("killswitch_applied");
    let asserted_active = report_flag("asserted_active");
    let permit_present = report_flag("permit_present_under_killswitch");
    let rolled_back = report_flag("rolled_back");
    let asserted_inactive = report_flag("asserted_inactive_after_rollback");
    let permit_absent_after = report_flag("permit_absent_after_rollback");
    let full_block_exercised = report_flag("full_block_exercised");
    let full_block_permit_removed = report_flag("full_block_permit_removed");
    let dns_exercised = report_flag("dns_protection_exercised");
    let dns_applied = report_flag("dns_protection_applied");
    let dns_asserted_active = report_flag("dns_protection_asserted_active");
    let dns_rolled_back = report_flag("dns_protection_rolled_back");
    let dns_asserted_inactive = report_flag("dns_protection_asserted_inactive");
    let ipv6_exercised = report_flag("ipv6_protection_exercised");
    let ipv6_baseline_egress_ok = report_flag("ipv6_baseline_egress_ok");
    let ipv6_control_applied = report_flag("ipv6_control_applied");
    let ipv6_egress_blocked = report_flag("ipv6_egress_blocked");
    let ipv6_control_rolled_back = report_flag("ipv6_control_rolled_back");
    let ipv6_egress_restored = report_flag("ipv6_egress_restored");
    let torn_down = report_flag("tunnel_torn_down");

    if status == "pass" && overall_ok {
        return Ok(());
    }

    let exit_code = daemon_exit_code
        .map(|code| code.to_string())
        .unwrap_or_else(|| "unknown".to_owned());
    Err(format!(
        "Windows killswitch smoke helper reported status={status} overall_ok={overall_ok} reason={reason} failure_step={failure_step} daemon_exit_code={exit_code} permit_absent_before={permit_absent_before} killswitch_applied={applied} asserted_active={asserted_active} permit_present_under_killswitch={permit_present} rolled_back={rolled_back} asserted_inactive_after_rollback={asserted_inactive} permit_absent_after_rollback={permit_absent_after} full_block_exercised={full_block_exercised} full_block_permit_removed={full_block_permit_removed} dns_protection_exercised={dns_exercised} dns_protection_applied={dns_applied} dns_protection_asserted_active={dns_asserted_active} dns_protection_rolled_back={dns_rolled_back} dns_protection_asserted_inactive={dns_asserted_inactive} ipv6_protection_exercised={ipv6_exercised} ipv6_baseline_egress_ok={ipv6_baseline_egress_ok} ipv6_control_applied={ipv6_control_applied} ipv6_egress_blocked={ipv6_egress_blocked} ipv6_control_rolled_back={ipv6_control_rolled_back} ipv6_egress_restored={ipv6_egress_restored} tunnel_torn_down={torn_down} for {target_label}"
    ))
}

#[cfg(test)]
fn build_windows_service_host_smoke_validation_script(
    remote_path: &str,
    args: &[String],
    remote_result_path: &str,
) -> Result<String, String> {
    let mut helper_args = args.to_vec();
    helper_args.push("-OutputPath".to_owned());
    helper_args.push(remote_result_path.to_owned());
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
         if ($report.status -eq 'pass') {{ return }}; \
         if ($report.status -eq 'blocked' -and $report.reason -eq 'windows-runtime-backend-explicitly-unsupported' -and $report.backend_label -eq 'windows-unsupported') {{ return }}; \
         throw ('Windows service-host smoke helper reported status={{0}} reason={{1}} backend_label={{2}}' -f [string]$report.status, [string]$report.reason, [string]$report.backend_label)",
        result_path = powershell_quote(remote_result_path)?,
        helper_command = helper_command,
    ))
}

#[cfg(test)]
fn build_windows_runtime_report_validation_script(
    remote_path: &str,
    args: &[String],
    remote_result_path: &str,
    helper_label: &str,
) -> Result<String, String> {
    ensure_no_control_chars("Windows runtime helper label", helper_label)?;
    let mut helper_args = args.to_vec();
    helper_args.push("-OutputPath".to_owned());
    helper_args.push(remote_result_path.to_owned());
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
         Write-Output ('__RUSTYNET_VM_LAB_RC__={{0}}' -f $validationRc)",
        result_path = powershell_quote(remote_result_path)?,
        helper_command = helper_command,
        helper_label = helper_label,
    ))
}

/// Typed view of the `manifest.json` written by
/// `scripts/bootstrap/windows/Collect-RustyNetWindowsDiagnostics.ps1`.
///
/// The helper now writes the same key set on both the success and the
/// top-level-failure code paths (`schema_version`, `captured_at_utc`,
/// `output_root`, `install_root`, `state_root`, `service_name`,
/// `status`, `reason`, `files`). Success carries `status = "pass"`,
/// `reason = ""`, and the actual collected file list; failure carries
/// `status = "fail"`, `reason = <error message>`, and an empty files
/// list. Optional success-only fields (`windows_target_facts`,
/// `runtime_boundary_status`, `omitted_secret_material`) are accepted
/// via `#[serde(default)]` so this view round-trips both branches.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[allow(dead_code)]
pub(crate) struct WindowsDiagnosticsManifestView {
    pub schema_version: u32,
    pub captured_at_utc: String,
    pub output_root: String,
    pub install_root: String,
    pub state_root: String,
    pub service_name: String,
    pub status: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub files: Vec<String>,
}

impl WindowsDiagnosticsManifestView {
    /// Parse a `manifest.json` body emitted by the Windows diagnostics
    /// helper. Returns `Err(String)` with a fail-closed message on any
    /// shape drift — including missing required fields, wrong primitive
    /// types, and a `status` value that is neither `"pass"` nor
    /// `"fail"`.
    #[allow(dead_code)]
    pub(crate) fn parse(body: &str) -> Result<Self, String> {
        let view: WindowsDiagnosticsManifestView = serde_json::from_str(body)
            .map_err(|err| format!("invalid windows diagnostics manifest shape: {err}"))?;
        match view.status.as_str() {
            "pass" | "fail" => {}
            other => {
                return Err(format!(
                    "windows diagnostics manifest status must be 'pass' or 'fail'; got {other:?}"
                ));
            }
        }
        if view.status == "fail" && view.reason.trim().is_empty() {
            return Err(
                "windows diagnostics manifest status=fail must carry a non-empty reason".to_owned(),
            );
        }
        Ok(view)
    }
}

/// Typed view of the report written by
/// `scripts/bootstrap/windows/Verify-RustyNetWindowsBootstrap.ps1`. The
/// helper emits the same `schema_version=3` on both the success path
/// (full runtime check report at the tail of the script) and the
/// top-level-failure trap (compact failure report from
/// `New-FailClosedVerifyReport`).
///
/// Both branches share the documented required fields below.
/// Success-only fields are accepted via `#[serde(default)]` so a typed
/// consumer can deserialize either branch through this view. The
/// `status` field must be `"pass"`, `"fail"`, or `"blocked"`; the latter
/// is used when the runtime is intentionally not supported on the
/// target (e.g. `windows-runtime-backend-explicitly-unsupported`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[allow(dead_code)]
pub(crate) struct WindowsVerifyReportView {
    pub schema_version: u32,
    pub captured_at_utc: String,
    pub platform: String,
    pub rustynet_root: String,
    pub install_root: String,
    pub state_root: String,
    pub service_name: String,
    pub status: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub backend_label: String,
    #[serde(default)]
    pub runtime_supported: bool,
    #[serde(default)]
    pub service_verified: bool,
    #[serde(default)]
    pub service_present: bool,
    #[serde(default)]
    pub service_status: String,
    #[serde(default)]
    pub require_live_path: bool,
    #[serde(default)]
    pub daemon_status_probe_status: String,
    #[serde(default)]
    pub daemon_netcheck_probe_status: String,
    #[serde(default)]
    pub path_live_proven: bool,
    #[serde(default)]
    pub path_latest_live_handshake_unix: String,
    #[serde(default)]
    pub failure_step: String,
    #[serde(default)]
    pub notes: Vec<String>,
}

impl WindowsVerifyReportView {
    /// Parse a Verify-RustyNetWindowsBootstrap report body. Fails closed
    /// when shape drift is detected:
    /// - invalid JSON
    /// - missing/wrong type on any required field
    /// - `schema_version` other than 3 (the contract the helper emits today)
    /// - status not in {pass, fail, blocked}
    /// - status=fail or status=blocked with empty reason
    #[allow(dead_code)]
    pub(crate) fn parse(body: &str) -> Result<Self, String> {
        let view: WindowsVerifyReportView = serde_json::from_str(body)
            .map_err(|err| format!("invalid windows verify report shape: {err}"))?;
        if view.schema_version != 3 {
            return Err(format!(
                "windows verify report schema_version must be 3; got {}",
                view.schema_version
            ));
        }
        match view.status.as_str() {
            "pass" | "fail" | "blocked" => {}
            other => {
                return Err(format!(
                    "windows verify report status must be 'pass', 'fail', or 'blocked'; got {other:?}"
                ));
            }
        }
        if (view.status == "fail" || view.status == "blocked") && view.reason.trim().is_empty() {
            return Err(format!(
                "windows verify report status='{}' must carry a non-empty reason",
                view.status
            ));
        }
        Ok(view)
    }
}

/// Typed view of the report written by
/// `scripts/bootstrap/windows/Install-RustyNetWindowsService.ps1`. The
/// helper emits `schema_version=1` on both the success branch (full
/// install report at the tail of the script) and the top-level-failure
/// trap (compact failure report from `New-FailClosedInstallReport`).
///
/// Both branches share the documented required fields below.
/// Success-only fields (`cli_optional`, `start_attempted`, `start_error`,
/// `daemon_present`, `cli_present`, `config_present`, `log_root_present`,
/// `trust_root_present`, `secrets_root_present`, `service_sid_configured`,
/// `runtime_acl_applied`, `service_state`, `service_start_mode`,
/// `service_exit_code`, `service_process_id`, `service_image_path`*,
/// `runtime_flags_present`, `wireguard_driver`*, `dns_failclosed_posture`)
/// are accepted via `#[serde(default)]` so a typed consumer can
/// deserialize either branch through this view. Unlike the Verify
/// helper, Install never emits the `blocked` status — the runtime
/// install path is always either `pass` or `fail`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[allow(dead_code)]
pub(crate) struct WindowsInstallReportView {
    pub schema_version: u32,
    pub captured_at_utc: String,
    pub platform: String,
    pub rustynet_root: String,
    pub install_root: String,
    pub state_root: String,
    pub service_name: String,
    pub status: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub backend_label: String,
    #[serde(default)]
    pub runtime_supported: bool,
    #[serde(default)]
    pub service_verified: bool,
    #[serde(default)]
    pub service_present: bool,
    #[serde(default)]
    pub service_status: String,
    #[serde(default)]
    pub failure_step: String,
    #[serde(default)]
    pub notes: Vec<String>,
}

impl WindowsInstallReportView {
    /// Parse an Install-RustyNetWindowsService report body. Fails closed
    /// when shape drift is detected:
    /// - invalid JSON
    /// - missing/wrong type on any required field
    /// - `schema_version` other than 1 (the contract the helper emits today)
    /// - status not in {pass, fail}
    /// - status=fail with empty reason
    #[allow(dead_code)]
    pub(crate) fn parse(body: &str) -> Result<Self, String> {
        let view: WindowsInstallReportView = serde_json::from_str(body)
            .map_err(|err| format!("invalid windows install report shape: {err}"))?;
        if view.schema_version != 1 {
            return Err(format!(
                "windows install report schema_version must be 1; got {}",
                view.schema_version
            ));
        }
        match view.status.as_str() {
            "pass" | "fail" => {}
            other => {
                return Err(format!(
                    "windows install report status must be 'pass' or 'fail'; got {other:?}"
                ));
            }
        }
        if view.status == "fail" && view.reason.trim().is_empty() {
            return Err(
                "windows install report status=fail must carry a non-empty reason".to_owned(),
            );
        }
        Ok(view)
    }
}

fn parse_runtime_helper_report_shape(helper_file_name: &str, body: &str) -> Result<(), String> {
    match helper_file_name {
        WINDOWS_SERVICE_INSTALL_HELPER_FILE => WindowsInstallReportView::parse(body).map(|_| ()),
        WINDOWS_VERIFY_HELPER_FILE => WindowsVerifyReportView::parse(body).map(|_| ()),
        other => Err(format!(
            "no typed Windows runtime report parser registered for helper {other}"
        )),
    }
}

/// Typed view of the JSON report written by
/// `scripts/bootstrap/windows/Bootstrap-RustyNetWindows.ps1` for the
/// `prepare-transport` phase. The helper builds the same field set on
/// both branches via `New-PrepareTransportFailureReport`, mutating
/// individual fields as the phase progresses; on the success path it
/// sets `status='pass'`, `reason='ok'`. The top-level trap
/// (`Write-FailClosedPhaseResultIfRequested`) emits the same field set
/// with `status='fail'` and a `reason` carrying the failure detail.
///
/// All fields are required because the helper writes the full shape on
/// every code path — there is no "missing on success" case here.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[allow(dead_code)]
pub(crate) struct WindowsPrepareTransportReportView {
    pub openssh_installed: bool,
    pub service_running: bool,
    pub firewall_rule_enabled: bool,
    pub authorized_keys_applied: bool,
    pub host_key_present: bool,
    pub listener_ready: bool,
    pub default_shell_configured: bool,
    pub status: String,
    pub reason: String,
    pub host_key: String,
}

impl WindowsPrepareTransportReportView {
    /// Parse a Bootstrap-RustyNetWindows prepare-transport report body.
    /// Fails closed when shape drift is detected:
    /// - invalid JSON
    /// - missing/wrong type on any field (every field is required)
    /// - status not in {pass, fail}
    /// - status=fail with empty reason
    /// - status=pass with `host_key_present=true` but empty `host_key`
    ///   (the success contract documented at line 1042-1047 of the
    ///   helper is: `host_key_present` implies a non-empty `host_key`)
    #[allow(dead_code)]
    pub(crate) fn parse(body: &str) -> Result<Self, String> {
        let view: WindowsPrepareTransportReportView = serde_json::from_str(body)
            .map_err(|err| format!("invalid windows prepare-transport report shape: {err}"))?;
        match view.status.as_str() {
            "pass" | "fail" => {}
            other => {
                return Err(format!(
                    "windows prepare-transport status must be 'pass' or 'fail'; got {other:?}"
                ));
            }
        }
        if view.status == "fail" && view.reason.trim().is_empty() {
            return Err(
                "windows prepare-transport status=fail must carry a non-empty reason".to_owned(),
            );
        }
        if view.host_key_present && view.host_key.trim().is_empty() {
            return Err(
                "windows prepare-transport host_key_present=true requires a non-empty host_key"
                    .to_owned(),
            );
        }
        Ok(view)
    }
}

/// Typed view of the JSON report written by
/// `scripts/bootstrap/windows/Bootstrap-RustyNetWindows.ps1` for the
/// `build-release` phase. The helper writes `schema_version=2` on
/// both branches via `Write-BuildReleaseReport`. Success and failure
/// share an identical field set — only `status` and `reason` (and
/// the `exit_code` + `stderr_tail` informational fields) differ.
///
/// The `toolchain_scope` field is critical for the lab-image
/// short-circuit invariant documented at lines 195-218 of the helper:
/// it classifies the resolved cargo/rustc path as `machine` (lab-image
/// install), `user` (per-user toolchain), or `unknown`/empty. Operator
/// confirmation that the SYSTEM short-circuit actually ran (not the
/// fallback interactive scheduled task) hinges on this field.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[allow(dead_code)]
pub(crate) struct WindowsBuildReleaseReportView {
    pub schema_version: u32,
    pub phase: String,
    pub captured_at_utc: String,
    pub status: String,
    pub reason: String,
    pub rustynet_root: String,
    pub report_root: String,
    pub stdout_path: String,
    pub stderr_path: String,
    pub exit_code_path: String,
    pub toolchain_path: String,
    pub toolchain_scope: String,
    #[serde(default)]
    pub cargo_build_jobs: String,
    pub manifest_path: String,
    pub complete_marker_path: String,
    pub exit_code: i32,
    #[serde(default)]
    pub stderr_tail: String,
    #[serde(default)]
    pub notes: Vec<String>,
}

impl WindowsBuildReleaseReportView {
    /// Parse a Bootstrap-RustyNetWindows build-release manifest body.
    /// Fails closed on shape drift:
    /// - invalid JSON
    /// - missing/wrong type on any required field
    /// - `schema_version` other than 2 (helper contract today)
    /// - phase != "build-release"
    /// - status not in {pass, fail}
    /// - status=fail with empty/whitespace reason
    /// - `toolchain_scope` not in {"", machine, user, unknown}
    /// - `exit_code=0` with status=fail (the helper invariant: a zero
    ///   exit cannot coexist with a failure)
    #[allow(dead_code)]
    pub(crate) fn parse(body: &str) -> Result<Self, String> {
        let view: WindowsBuildReleaseReportView = serde_json::from_str(body)
            .map_err(|err| format!("invalid windows build-release report shape: {err}"))?;
        if view.schema_version != 2 {
            return Err(format!(
                "windows build-release report schema_version must be 2; got {}",
                view.schema_version
            ));
        }
        if view.phase != "build-release" {
            return Err(format!(
                "windows build-release report phase must be 'build-release'; got {:?}",
                view.phase
            ));
        }
        match view.status.as_str() {
            "pass" | "fail" => {}
            other => {
                return Err(format!(
                    "windows build-release report status must be 'pass' or 'fail'; got {other:?}"
                ));
            }
        }
        if view.status == "fail" && view.reason.trim().is_empty() {
            return Err(
                "windows build-release report status=fail must carry a non-empty reason".to_owned(),
            );
        }
        match view.toolchain_scope.as_str() {
            "" | "machine" | "user" | "unknown" => {}
            other => {
                return Err(format!(
                    "windows build-release report toolchain_scope must be one of '', 'machine', 'user', 'unknown'; got {other:?}"
                ));
            }
        }
        if view.status == "fail" && view.exit_code == 0 {
            return Err(
                "windows build-release report status=fail with exit_code=0 is internally inconsistent".to_owned(),
            );
        }
        Ok(view)
    }
}

#[cfg(test)]
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
         $null = Get-Content -Raw -LiteralPath $manifestPath -Encoding UTF8 | ConvertFrom-Json",
        output_root = powershell_quote(output_root)?,
        helper_command = helper_command,
    ))
}

fn build_windows_diagnostics_result_file_script(
    remote_path: &str,
    args: &[String],
    output_root: &str,
    remote_result_path: &str,
) -> Result<String, String> {
    let helper_command = build_windows_helper_command(remote_path, args)?;
    Ok(format!(
        "Set-StrictMode -Version Latest; \
         $ErrorActionPreference = 'Stop'; \
         $ProgressPreference = 'SilentlyContinue'; \
         $outputRoot = {output_root}; \
         $resultPath = {result_path}; \
         $resultParent = Split-Path -Path $resultPath -Parent; \
         if ($resultParent -and -not (Test-Path -LiteralPath $resultParent)) {{ \
           New-Item -ItemType Directory -Path $resultParent -Force | Out-Null \
         }}; \
         if (Test-Path -LiteralPath $resultPath) {{ \
           Remove-Item -LiteralPath $resultPath -Force -ErrorAction SilentlyContinue \
         }}; \
         $report = $null; \
         $helperFailure = ''; \
         try {{ \
           {helper_command}; \
         }} catch {{ \
           $helperFailure = if ($_.Exception -and $_.Exception.Message) {{ $_.Exception.Message.Trim() }} else {{ ($_ | Out-String).Trim() }} \
         }}; \
         try {{ \
           if (-not (Test-Path -LiteralPath $outputRoot)) {{ \
             if ([string]::IsNullOrWhiteSpace($helperFailure)) {{ \
               throw ('Windows diagnostics helper did not create output root: {{0}}' -f $outputRoot) \
             }}; \
             throw $helperFailure \
           }}; \
           $manifestPath = Join-Path $outputRoot 'manifest.json'; \
           if (-not (Test-Path -LiteralPath $manifestPath)) {{ \
             if ([string]::IsNullOrWhiteSpace($helperFailure)) {{ \
               throw ('Windows diagnostics helper did not create manifest: {{0}}' -f $manifestPath) \
             }}; \
             throw $helperFailure \
           }}; \
           $null = Get-Content -Raw -LiteralPath $manifestPath -Encoding UTF8 | ConvertFrom-Json; \
           $report = [ordered]@{{ status = 'pass'; output_root = $outputRoot }} \
         }} catch {{ \
           $detail = if ($_.Exception -and $_.Exception.Message) {{ $_.Exception.Message.Trim() }} else {{ ($_ | Out-String).Trim() }}; \
           if (-not $detail) {{ $detail = 'windows-diagnostics-helper-failed' }}; \
           $report = [ordered]@{{ status = 'fail'; reason = $detail; output_root = $outputRoot }} \
         }}; \
         $report | ConvertTo-Json -Compress | Set-Content -LiteralPath $resultPath -Encoding UTF8; \
         if ($report.status -ne 'pass') {{ exit 1 }}",
        output_root = powershell_quote(output_root)?,
        result_path = powershell_quote(remote_result_path)?,
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
        self.capture_helper_output_with_phase(
            target,
            context,
            invocation,
            label,
            RemoteTransportPhase::AccessEstablishment,
        )
    }

    fn capture_helper_output_with_phase(
        &self,
        target: &RemoteTarget,
        context: &BootstrapPhaseContext<'_>,
        invocation: WindowsHelperScriptSpec,
        label: &str,
        phase: RemoteTransportPhase,
    ) -> Result<String, String> {
        let helper_context = self.helper_context(target, context);
        if phase == RemoteTransportPhase::PostBootstrap
            && matches!(
                invocation.helper_file_name,
                WINDOWS_SERVICE_INSTALL_HELPER_FILE | WINDOWS_VERIFY_HELPER_FILE
            )
        {
            return self.capture_runtime_helper_report_via_ssh_poll(
                target,
                &helper_context,
                invocation,
                label,
            );
        }
        capture_windows_helper_script_output_for_target_with_phase(
            &helper_context,
            invocation.helper_file_name,
            invocation.remote_file_name,
            invocation.args.as_slice(),
            phase,
        )
        .map_err(|err| format!("{label} failed for {}: {err}", target.label))
    }

    fn capture_runtime_helper_report_via_ssh_poll(
        &self,
        target: &RemoteTarget,
        helper_context: &RemoteFallbackContext<'_>,
        invocation: WindowsHelperScriptSpec,
        label: &str,
    ) -> Result<String, String> {
        let local_path = match invocation.helper_file_name {
            WINDOWS_SERVICE_INSTALL_HELPER_FILE => {
                windows_service_install_helper_script_local_path()
            }
            WINDOWS_VERIFY_HELPER_FILE => windows_verify_helper_script_local_path(),
            _ => windows_helper_script_local_path(invocation.helper_file_name),
        };
        let remote_path = stage_windows_helper_script_from_path_with_phase(
            helper_context,
            local_path.as_path(),
            invocation.remote_file_name,
            RemoteTransportPhase::PostBootstrap,
        )?;
        let remote_result_name = format!(
            "{}.result.{}.json",
            sanitize_label_for_path(invocation.remote_file_name),
            unique_suffix()
        );
        let remote_result_path =
            windows_helper_script_remote_path(helper_context.target, remote_result_name.as_str())?;
        let mut args = invocation.args.clone();
        args.push("-OutputPath".to_owned());
        args.push(remote_result_path.clone());
        let helper_command = build_windows_helper_command(remote_path.as_str(), args.as_slice())?;
        let result_script = format!(
            "Set-StrictMode -Version Latest; \
             $ErrorActionPreference = 'Stop'; \
             $ProgressPreference = 'SilentlyContinue'; \
             $resultPath = {result_path}; \
             $resultParent = Split-Path -Path $resultPath -Parent; \
             if ($resultParent -and -not (Test-Path -LiteralPath $resultParent)) {{ \
               New-Item -ItemType Directory -Path $resultParent -Force | Out-Null \
             }}; \
             if (Test-Path -LiteralPath $resultPath) {{ \
               Remove-Item -LiteralPath $resultPath -Force -ErrorAction SilentlyContinue \
             }}; \
             {helper_command}; \
             if (-not (Test-Path -LiteralPath $resultPath)) {{ \
               throw ('{label} did not write result file: {{0}}' -f $resultPath) \
             }}",
            result_path = powershell_quote(remote_result_path.as_str())?,
            helper_command = helper_command,
            label = label,
        );
        let ssh_script =
            remote_script_for_ssh_transport(helper_context.target, result_script.as_str())?;
        self.run_runtime_helper_ssh_report_command_with_poll(
            target,
            helper_context,
            ssh_script.as_str(),
            remote_result_path.as_str(),
            invocation.helper_file_name,
            label,
        )
    }

    fn run_runtime_helper_ssh_report_command_with_poll(
        &self,
        target: &RemoteTarget,
        helper_context: &RemoteFallbackContext<'_>,
        ssh_script: &str,
        remote_result_path: &str,
        helper_file_name: &str,
        label: &str,
    ) -> Result<String, String> {
        let ssh_user = helper_context
            .ssh_user_override
            .or(helper_context.target.ssh_user.as_deref());
        validate_target_user_combination(helper_context.target.ssh_target.as_str(), ssh_user)?;
        let mut command = std::process::Command::new("ssh");
        command.args([
            "-n",
            "-o",
            "LogLevel=ERROR",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "ConnectTimeout=15",
            "-o",
            "ServerAliveInterval=20",
            "-o",
            "ServerAliveCountMax=3",
            "-o",
            "IdentitiesOnly=yes",
        ]);
        append_ssh_transport_options(
            &mut command,
            helper_context.ssh_identity_file,
            helper_context.known_hosts_path,
        )?;
        if let Some(ssh_user) = ssh_user {
            command.arg("-l").arg(ssh_user);
        }
        command.arg("--").arg(&helper_context.target.ssh_target);
        command.arg(ssh_script);
        command.stdin(std::process::Stdio::null());
        command.stdout(std::process::Stdio::null());
        command.stderr(std::process::Stdio::null());
        let mut child = command
            .spawn()
            .map_err(|err| format!("spawn {label} SSH command failed: {err}"))?;
        let started_at = std::time::Instant::now();
        let mut last_report_read_error = format!("{label} report not read yet");
        loop {
            match self.read_runtime_helper_report_via_ssh(helper_context, remote_result_path) {
                Ok(report) => match parse_runtime_helper_report_shape(helper_file_name, &report) {
                    Ok(()) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Ok(report);
                    }
                    Err(err) => {
                        last_report_read_error = err;
                    }
                },
                Err(err) => {
                    last_report_read_error = err;
                }
            }
            if let Some(status) = child
                .try_wait()
                .map_err(|err| format!("wait for {label} SSH command failed: {err}"))?
            {
                let report =
                    self.read_runtime_helper_report_via_ssh(helper_context, remote_result_path)?;
                return parse_runtime_helper_report_shape(helper_file_name, &report)
                    .map(|()| report)
                    .map_err(|err| {
                        format!(
                            "{label} SSH command exited with status {}; report parse failed for {}: {err}",
                            status_code(status),
                            target.label
                        )
                    });
            }
            if started_at.elapsed() >= helper_context.timeout {
                let _ = child.kill();
                let _ = child.wait();
                if let Ok(report) =
                    self.read_runtime_helper_report_via_ssh(helper_context, remote_result_path)
                    && parse_runtime_helper_report_shape(helper_file_name, &report).is_ok()
                {
                    return Ok(report);
                }
                return Err(format!(
                    "{label} SSH command timed out after {} seconds for {}; last report read error: {}",
                    helper_context.timeout.as_secs(),
                    target.label,
                    last_report_read_error
                ));
            }
            std::thread::sleep(std::time::Duration::from_secs(3));
        }
    }

    fn read_runtime_helper_report_via_ssh(
        &self,
        helper_context: &RemoteFallbackContext<'_>,
        remote_result_path: &str,
    ) -> Result<String, String> {
        let script = format!(
            "Set-StrictMode -Version Latest; \
             $ErrorActionPreference = 'Stop'; \
             $reportPath = {result_path}; \
             if (-not (Test-Path -LiteralPath $reportPath)) {{ \
               throw ('Windows runtime helper report not found: {{0}}' -f $reportPath) \
             }}; \
             Get-Content -Raw -LiteralPath $reportPath -Encoding UTF8",
            result_path = powershell_quote(remote_result_path)?,
        );
        let ssh_script = remote_script_for_ssh_transport(helper_context.target, script.as_str())?;
        capture_remote_shell_command(
            helper_context.target.ssh_target.as_str(),
            helper_context
                .ssh_user_override
                .or(helper_context.target.ssh_user.as_deref()),
            helper_context.ssh_identity_file,
            helper_context.known_hosts_path,
            ssh_script.as_str(),
            helper_context.timeout.min(Duration::from_secs(30)),
        )
        .map_err(|err| {
            format!(
                "Windows runtime helper report read failed for {}: {err}",
                helper_context.target.label
            )
        })
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
        let output = execute_windows_local_utm_result_file_probe(
            utm_name,
            label,
            helper_context.timeout,
            remote_result_path.as_str(),
            |remote_result_path| {
                build_windows_result_file_helper_invocation_script(
                    remote_path.as_str(),
                    invocation.args.as_slice(),
                    remote_result_path,
                    label,
                )
            },
        )
        .map_err(|err| format!("{label} failed for {}: {err}", target.label))?;
        parse_windows_runtime_report_output(output.as_str(), label, target.label.as_str())
    }

    fn run_build_release_via_ssh_report(
        &self,
        target: &RemoteTarget,
        context: &BootstrapPhaseContext<'_>,
        invocation: WindowsHelperScriptSpec,
    ) -> Result<(), String> {
        let helper_context = self.helper_context(target, context);
        stage_windows_helper_support_files_with_phase(
            &helper_context,
            invocation.helper_file_name,
            RemoteTransportPhase::PostBootstrap,
        )?;
        let unique_bootstrap_name = format!("Bootstrap-RustyNetWindows.{}.ps1", unique_suffix());
        let remote_path = stage_windows_helper_script_from_path_with_phase(
            &helper_context,
            windows_bootstrap_helper_script_local_path().as_path(),
            unique_bootstrap_name.as_str(),
            RemoteTransportPhase::PostBootstrap,
        )?;
        let (_report_root, remote_manifest_path, remote_probe_path) =
            build_windows_build_release_report_paths(helper_context.target)?;
        let manifest_path = remote_manifest_path.clone();
        let result_script = build_windows_bootstrap_build_release_result_script(
            remote_path.as_str(),
            invocation.args.as_slice(),
            manifest_path.as_str(),
            remote_probe_path.as_str(),
        )?;
        let ssh_script =
            remote_script_for_ssh_transport(helper_context.target, result_script.as_str())?;
        let output = self.run_build_release_ssh_report_command_with_poll(
            &helper_context,
            ssh_script.as_str(),
            remote_probe_path.as_str(),
            remote_manifest_path.as_str(),
        )?;
        parse_windows_build_release_report_output(output.as_str(), target.label.as_str())
    }

    fn run_build_release_ssh_report_command_with_poll(
        &self,
        helper_context: &RemoteFallbackContext<'_>,
        ssh_script: &str,
        remote_probe_path: &str,
        remote_manifest_path: &str,
    ) -> Result<String, String> {
        let ssh_user = helper_context
            .ssh_user_override
            .or(helper_context.target.ssh_user.as_deref());
        validate_target_user_combination(helper_context.target.ssh_target.as_str(), ssh_user)?;
        let mut command = std::process::Command::new("ssh");
        command.args([
            "-n",
            "-o",
            "LogLevel=ERROR",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "ConnectTimeout=15",
            "-o",
            "ServerAliveInterval=20",
            "-o",
            "ServerAliveCountMax=3",
            "-o",
            "IdentitiesOnly=yes",
        ]);
        append_ssh_transport_options(
            &mut command,
            helper_context.ssh_identity_file,
            helper_context.known_hosts_path,
        )?;
        if let Some(ssh_user) = ssh_user {
            command.arg("-l").arg(ssh_user);
        }
        command.arg("--").arg(&helper_context.target.ssh_target);
        command.arg(ssh_script);
        command.stdin(std::process::Stdio::null());
        command.stdout(std::process::Stdio::null());
        command.stderr(std::process::Stdio::null());
        let mut child = command
            .spawn()
            .map_err(|err| format!("spawn Windows build-release SSH command failed: {err}"))?;
        let started_at = std::time::Instant::now();
        let mut last_report_read_error: String;
        loop {
            match self.read_build_release_report_via_ssh(
                helper_context,
                remote_probe_path,
                remote_manifest_path,
            ) {
                Ok(report) => match WindowsBuildReleaseReportView::parse(report.as_str()) {
                    Ok(_) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Ok(report);
                    }
                    Err(err) => {
                        last_report_read_error = err;
                    }
                },
                Err(err) => {
                    last_report_read_error = err;
                }
            }
            if let Some(status) = child.try_wait().map_err(|err| {
                format!("wait for Windows build-release SSH command failed: {err}")
            })? {
                let report = self.read_build_release_report_via_ssh(
                    helper_context,
                    remote_probe_path,
                    remote_manifest_path,
                )?;
                return parse_windows_build_release_report_output(
                    report.as_str(),
                    helper_context.target.label.as_str(),
                )
                .map(|()| report)
                .map_err(|err| {
                    format!(
                        "Windows build-release SSH command exited with status {}; report parse failed: {err}",
                        status_code(status)
                    )
                });
            }
            if started_at.elapsed() >= helper_context.timeout {
                let _ = child.kill();
                let _ = child.wait();
                if let Ok(report) = self.read_build_release_report_via_ssh(
                    helper_context,
                    remote_probe_path,
                    remote_manifest_path,
                ) && parse_windows_build_release_report_output(
                    report.as_str(),
                    helper_context.target.label.as_str(),
                )
                .is_ok()
                {
                    return Ok(report);
                }
                return Err(format!(
                    "Windows build-release SSH command timed out after {} seconds; last report read error: {}",
                    helper_context.timeout.as_secs(),
                    last_report_read_error
                ));
            }
            std::thread::sleep(std::time::Duration::from_secs(3));
        }
    }

    fn read_build_release_report_via_ssh(
        &self,
        helper_context: &RemoteFallbackContext<'_>,
        remote_probe_path: &str,
        remote_manifest_path: &str,
    ) -> Result<String, String> {
        let script = format!(
            "Set-StrictMode -Version Latest; \
             $ErrorActionPreference = 'Stop'; \
             $reportPath = {probe_path}; \
             if (-not (Test-Path -LiteralPath $reportPath)) {{ \
               $reportPath = {manifest_path} \
             }}; \
             if (-not (Test-Path -LiteralPath $reportPath)) {{ \
               throw ('Windows build-release report not found: {{0}}' -f $reportPath) \
             }}; \
             Get-Content -Raw -LiteralPath $reportPath -Encoding UTF8",
            probe_path = powershell_quote(remote_probe_path)?,
            manifest_path = powershell_quote(remote_manifest_path)?,
        );
        let ssh_script = remote_script_for_ssh_transport(helper_context.target, script.as_str())?;
        capture_remote_shell_command(
            helper_context.target.ssh_target.as_str(),
            helper_context
                .ssh_user_override
                .or(helper_context.target.ssh_user.as_deref()),
            helper_context.ssh_identity_file,
            helper_context.known_hosts_path,
            ssh_script.as_str(),
            helper_context.timeout.min(Duration::from_secs(30)),
        )
        .map_err(|err| {
            format!(
                "Windows bootstrap build-release fallback report read failed for {}: {err}",
                helper_context.target.label
            )
        })
    }

    fn collect_failure_diagnostics(
        &self,
        phase: BootstrapPhase,
        target: &RemoteTarget,
        context: &BootstrapPhaseContext<'_>,
    ) -> Result<String, String> {
        if phase_requires_proven_access(phase) {
            return Err(
                "post-bootstrap diagnostics use pinned SSH failure output; local UTM diagnostics disabled"
                    .to_owned(),
            );
        }
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
            let remote_result_name = format!(
                "{}.result.{}.json",
                sanitize_label_for_path(invocation.remote_file_name),
                unique_suffix()
            );
            let remote_result_path = windows_helper_script_remote_path(
                helper_context.target,
                remote_result_name.as_str(),
            )?;
            let output = execute_windows_local_utm_result_file_probe(
                remote_target_local_utm(helper_context.target)
                    .expect("validated local UTM target")
                    .0,
                "Windows diagnostics helper",
                helper_context.timeout,
                remote_result_path.as_str(),
                |remote_result_path| {
                    build_windows_diagnostics_result_file_script(
                        remote_path.as_str(),
                        invocation.args.as_slice(),
                        output_root,
                        remote_result_path,
                    )
                },
            )
            .map_err(|err| {
                format!(
                    "Windows diagnostics helper failed for {}: {err}",
                    target.label
                )
            })?;
            let parsed: serde_json::Value =
                serde_json::from_str(output.as_str()).map_err(|err| {
                    format!(
                        "Windows diagnostics helper returned invalid JSON for {}: {err}",
                        target.label
                    )
                })?;
            let status = parsed
                .get("status")
                .and_then(|value| value.as_str())
                .unwrap_or("fail");
            if status != "pass" {
                let reason = parsed
                    .get("reason")
                    .and_then(|value| value.as_str())
                    .unwrap_or("windows-diagnostics-helper-failed");
                return Err(format!(
                    "Windows diagnostics helper failed for {}: {} (output_root={output_root})",
                    target.label, reason
                ));
            }
            return Ok(output_root.to_owned());
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
        Ok(output_root.to_owned())
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
        if !phase_requires_proven_access(phase) {
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
                self.run_build_release_via_ssh_report(target, context, invocation)
            }
            BootstrapPhase::SmokeServiceHost => {
                let invocation = build_windows_service_host_smoke_invocation(context);
                match windows_local_utm_execution_authority(target, false) {
                    Some(WindowsLocalUtmExecutionAuthority::StatusProbeResultFile) => {
                        let helper_context = self.helper_context(target, context);
                        let (utm_name, _) = remote_target_local_utm(helper_context.target)
                            .expect("validated local UTM target");
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
                        let output = execute_windows_local_utm_result_file_probe(
                            utm_name,
                            "Windows service-host smoke helper",
                            helper_context.timeout,
                            remote_result_path.as_str(),
                            |remote_result_path| {
                                build_windows_result_file_helper_invocation_script(
                                    remote_path.as_str(),
                                    invocation.args.as_slice(),
                                    remote_result_path,
                                    "Windows service-host smoke helper",
                                )
                            },
                        )
                        .map_err(|err| {
                            format!(
                                "Windows service-host smoke helper failed for {}: {err}",
                                target.label
                            )
                        })?;
                        parse_windows_service_host_smoke_output(
                            output.as_str(),
                            target.label.as_str(),
                        )
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
                    let output = self.capture_helper_output_with_phase(
                        target,
                        context,
                        invocation,
                        "Windows service install helper",
                        RemoteTransportPhase::PostBootstrap,
                    )?;
                    parse_windows_runtime_report_output(
                        output.as_str(),
                        "Windows service install helper",
                        target.label.as_str(),
                    )
                }
            }
            BootstrapPhase::RestartRuntime => {
                let phase = if local_utm_result_file_supported_for_phase(
                    BootstrapPhase::RestartRuntime,
                    target,
                ) {
                    RemoteTransportPhase::AccessEstablishment
                } else {
                    RemoteTransportPhase::PostBootstrap
                };
                capture_remote_shell_command_for_target_with_phase(
                    target,
                    context.ssh_user,
                    context.ssh_identity_file,
                    context.known_hosts_path,
                    build_windows_restart_runtime_script()?.as_str(),
                    context.timeout,
                    phase,
                )
                .map_err(|err| {
                    format!("Windows restart-runtime failed for {}: {err}", target.label)
                })?;
                let output = self.capture_helper_output_with_phase(
                    target,
                    context,
                    build_windows_verify_invocation(context, false),
                    "Windows verify helper after restart-runtime",
                    RemoteTransportPhase::PostBootstrap,
                )?;
                parse_windows_runtime_report_output(
                    output.as_str(),
                    "Windows verify helper after restart-runtime",
                    target.label.as_str(),
                )
            }
            BootstrapPhase::VerifyRuntime => {
                let invocation = build_windows_verify_invocation(context, true);
                if local_utm_result_file_supported_for_phase(BootstrapPhase::VerifyRuntime, target)
                {
                    self.run_helper_via_local_utm_result_file(
                        target,
                        context,
                        invocation,
                        "Windows verify helper",
                    )
                } else {
                    let output = self.capture_helper_output_with_phase(
                        target,
                        context,
                        invocation,
                        "Windows verify helper",
                        RemoteTransportPhase::PostBootstrap,
                    )?;
                    parse_windows_runtime_report_output(
                        output.as_str(),
                        "Windows verify helper",
                        target.label.as_str(),
                    )
                }
            }
            BootstrapPhase::TunnelSmoke => {
                // Privileged single-node tunnel bring-up. Access is already
                // proven (phase_requires_proven_access), so this runs over the
                // pinned-SSH capture path — the local-UTM result-file path is
                // not available for the Apple-Virtualization Windows guest.
                let invocation = build_windows_tunnel_smoke_invocation(context);
                let output = self.capture_helper_output(
                    target,
                    context,
                    invocation,
                    "Windows tunnel smoke helper",
                )?;
                parse_windows_tunnel_smoke_output(output.as_str(), target.label.as_str())
            }
            BootstrapPhase::KillswitchSmoke => {
                // Privileged single-node killswitch exercise on the live tunnel.
                // Access is already proven (phase_requires_proven_access), so this
                // runs over the pinned-SSH capture path. The helper arms a
                // dead-man's-switch around the killswitch so a wedged apply cannot
                // strand SSH on the guest.
                let invocation = build_windows_killswitch_smoke_invocation(context);
                let output = self.capture_helper_output(
                    target,
                    context,
                    invocation,
                    "Windows killswitch smoke helper",
                )?;
                parse_windows_killswitch_smoke_output(output.as_str(), target.label.as_str())
            }
            BootstrapPhase::DnsSmoke => {
                // N3 DNS fail-closed in protected mode: the killswitch smoke with
                // its DNS leg enabled. Same pinned-SSH capture + dead-man's-switch
                // as the killswitch smoke; the same envelope/parser applies (the
                // verdict gates on overall_ok, which includes the DNS signals).
                let invocation = build_windows_dns_smoke_invocation(context);
                let output = self.capture_helper_output(
                    target,
                    context,
                    invocation,
                    "Windows DNS smoke helper",
                )?;
                parse_windows_killswitch_smoke_output(output.as_str(), target.label.as_str())
            }
            BootstrapPhase::Ipv6Smoke => {
                // G8 IPv6 fail-closed in protected mode: the killswitch smoke with
                // its IPv6 leg enabled. Same pinned-SSH capture + dead-man's-switch
                // + envelope/parser as the killswitch smoke (the verdict gates on
                // overall_ok, which includes the IPv6 signals).
                let invocation = build_windows_ipv6_smoke_invocation(context);
                let output = self.capture_helper_output(
                    target,
                    context,
                    invocation,
                    "Windows IPv6 smoke helper",
                )?;
                parse_windows_killswitch_smoke_output(output.as_str(), target.label.as_str())
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
    fn windows_tunnel_smoke_invocation_uses_canonical_helper_and_runtime_roots() {
        let invocation = build_windows_tunnel_smoke_invocation(&sample_context(None));
        assert_eq!(
            invocation.helper_file_name,
            WINDOWS_TUNNEL_SMOKE_HELPER_FILE
        );
        assert_eq!(
            invocation.remote_file_name,
            WINDOWS_TUNNEL_SMOKE_HELPER_FILE
        );
        assert_eq!(
            invocation.args,
            vec![
                "-RustyNetRoot",
                r"C:\Rustynet",
                "-StateRoot",
                WINDOWS_STATE_ROOT,
            ]
        );
    }

    #[test]
    fn windows_tunnel_smoke_parser_accepts_pass() {
        parse_windows_tunnel_smoke_output(
            r#"{
                "status": "pass",
                "overall_ok": true,
                "daemon_exit_code": 0,
                "tunnel_report": {
                    "tunnel_name": "rustynet0",
                    "started": true,
                    "interface_present": true,
                    "wg_show_ok": true,
                    "torn_down": true,
                    "overall_ok": true
                }
            }"#,
            "windows-utm-1",
        )
        .expect("a clean pass envelope must parse as success");
    }

    #[test]
    fn windows_tunnel_smoke_parser_rejects_overall_ok_false() {
        let err = parse_windows_tunnel_smoke_output(
            r#"{
                "status": "fail",
                "overall_ok": false,
                "reason": "tunnel did not come up cleanly (overall_ok=False, exit=1)",
                "daemon_exit_code": 1,
                "failure_step": "run-daemon",
                "tunnel_report": {
                    "started": true,
                    "interface_present": false,
                    "wg_show_ok": true,
                    "torn_down": true,
                    "overall_ok": false
                }
            }"#,
            "windows-utm-1",
        )
        .expect_err("overall_ok=false must fail closed");
        assert!(err.contains("status=fail"));
        assert!(err.contains("overall_ok=false"));
        assert!(err.contains("interface_present=false"));
        assert!(err.contains("daemon_exit_code=1"));
    }

    #[test]
    fn windows_tunnel_smoke_parser_rejects_status_pass_without_overall_ok() {
        // A pass status with overall_ok=false (or absent) is internally
        // inconsistent and must still fail closed — both signals must agree.
        let err = parse_windows_tunnel_smoke_output(
            r#"{ "status": "pass", "overall_ok": false, "daemon_exit_code": 0 }"#,
            "windows-utm-1",
        )
        .expect_err("status=pass without overall_ok must fail closed");
        assert!(err.contains("overall_ok=false"));
    }

    #[test]
    fn windows_tunnel_smoke_parser_rejects_missing_daemon_report() {
        let err = parse_windows_tunnel_smoke_output(
            r#"{
                "status": "fail",
                "overall_ok": false,
                "reason": "daemon emitted no tunnel-smoke report; exit=1; stderr: tunnel bring-up failed",
                "daemon_exit_code": 1,
                "failure_step": "run-daemon",
                "tunnel_report": null
            }"#,
            "windows-utm-1",
        )
        .expect_err("a missing daemon report must fail closed");
        assert!(err.contains("started=unknown"));
        assert!(err.contains("interface_present=unknown"));
        assert!(err.contains("wg_show_ok=unknown"));
    }

    #[test]
    fn windows_tunnel_smoke_parser_rejects_empty_output() {
        let err = parse_windows_tunnel_smoke_output("   ", "windows-utm-1")
            .expect_err("empty output must fail closed");
        assert!(err.contains("produced no output"));
    }

    #[test]
    fn windows_tunnel_smoke_helper_is_admin_gated_and_runs_the_subcommand() {
        let helper = include_str!(
            "../../../../../scripts/bootstrap/windows/Invoke-RustyNetWindowsTunnelSmoke.ps1"
        );
        // Privileged bring-up must be admin-gated and fail closed off the happy path.
        assert!(helper.contains("WindowsBuiltInRole]::Administrator"));
        assert!(helper.contains("trap {"));
        // It must invoke the daemon tunnel-smoke subcommand and gate on overall_ok.
        assert!(helper.contains("windows-tunnel-smoke"));
        assert!(helper.contains("overall_ok"));
        assert!(helper.contains("rustynetd.exe"));
        // Defense-in-depth: the canonical state root is enforced.
        assert!(helper.contains(r"state root must be C:\ProgramData\RustyNet"));
    }

    #[test]
    fn windows_killswitch_smoke_invocation_uses_canonical_helper_and_runtime_roots() {
        let invocation = build_windows_killswitch_smoke_invocation(&sample_context(None));
        assert_eq!(
            invocation.helper_file_name,
            WINDOWS_KILLSWITCH_SMOKE_HELPER_FILE
        );
        assert_eq!(
            invocation.remote_file_name,
            WINDOWS_KILLSWITCH_SMOKE_HELPER_FILE
        );
        assert_eq!(
            invocation.args,
            vec![
                "-RustyNetRoot",
                r"C:\Rustynet",
                "-StateRoot",
                WINDOWS_STATE_ROOT,
            ]
        );
        // The standard phase run must NOT request the SSH-cutting full block.
        assert!(
            !invocation
                .args
                .iter()
                .any(|arg| arg == "-ExerciseFullBlock")
        );
    }

    #[test]
    fn windows_killswitch_smoke_parser_accepts_pass() {
        parse_windows_killswitch_smoke_output(
            r#"{
                "status": "pass",
                "overall_ok": true,
                "daemon_exit_code": 0,
                "killswitch_report": {
                    "tunnel_name": "rustynet0",
                    "tunnel_started": true,
                    "permit_absent_before": true,
                    "killswitch_applied": true,
                    "asserted_active": true,
                    "permit_present_under_killswitch": true,
                    "rolled_back": true,
                    "asserted_inactive_after_rollback": true,
                    "permit_absent_after_rollback": true,
                    "full_block_exercised": false,
                    "tunnel_torn_down": true,
                    "overall_ok": true
                }
            }"#,
            "windows-utm-1",
        )
        .expect("a clean pass envelope must parse as success");
    }

    #[test]
    fn windows_killswitch_smoke_parser_rejects_overall_ok_false() {
        let err = parse_windows_killswitch_smoke_output(
            r#"{
                "status": "fail",
                "overall_ok": false,
                "reason": "killswitch did not apply/rollback cleanly (overall_ok=False, exit=1)",
                "daemon_exit_code": 1,
                "failure_step": "run-daemon",
                "killswitch_report": {
                    "permit_absent_before": true,
                    "killswitch_applied": true,
                    "asserted_active": false,
                    "permit_present_under_killswitch": true,
                    "rolled_back": true,
                    "permit_absent_after_rollback": true,
                    "tunnel_torn_down": true,
                    "overall_ok": false
                }
            }"#,
            "windows-utm-1",
        )
        .expect_err("overall_ok=false must fail closed");
        assert!(err.contains("status=fail"));
        assert!(err.contains("overall_ok=false"));
        assert!(err.contains("asserted_active=false"));
        assert!(err.contains("daemon_exit_code=1"));
    }

    #[test]
    fn windows_killswitch_smoke_parser_rejects_empty_output() {
        let err = parse_windows_killswitch_smoke_output("   ", "windows-utm-1")
            .expect_err("empty output must fail closed");
        assert!(err.contains("produced no output"));
    }

    #[test]
    fn windows_killswitch_smoke_helper_arms_deadman_and_runs_the_subcommand() {
        let helper = include_str!(
            "../../../../../scripts/bootstrap/windows/Invoke-RustyNetWindowsKillswitchSmoke.ps1"
        );
        // Privileged exercise must be admin-gated and fail closed off the happy path.
        assert!(helper.contains("WindowsBuiltInRole]::Administrator"));
        assert!(helper.contains("trap {"));
        // It must invoke the daemon killswitch-smoke subcommand and gate on overall_ok.
        assert!(helper.contains("windows-killswitch-smoke"));
        assert!(helper.contains("overall_ok"));
        assert!(helper.contains("rustynetd.exe"));
        // Defense-in-depth: the canonical state root is enforced.
        assert!(helper.contains(r"state root must be C:\ProgramData\RustyNet"));
        // The lockout safety net: a scheduled dead-man's-switch must be armed
        // before any killswitch is applied, and outbound restored on every path.
        assert!(helper.contains("schtasks.exe"));
        assert!(helper.contains("Register-FirewallDeadMan"));
        assert!(helper.contains("allowinbound,allowoutbound"));
        // N3: the harness forwards the DNS leg when requested.
        assert!(helper.contains("ExerciseDns"));
        assert!(helper.contains("--exercise-dns"));
        // G8: the harness forwards the IPv6 leg when requested.
        assert!(helper.contains("ExerciseIpv6"));
        assert!(helper.contains("--exercise-ipv6"));
    }

    #[test]
    fn windows_ipv6_smoke_invocation_reuses_killswitch_helper_with_exercise_ipv6() {
        let invocation = build_windows_ipv6_smoke_invocation(&sample_context(None));
        // G8 reuses the killswitch smoke helper, adding only the IPv6 leg.
        assert_eq!(
            invocation.helper_file_name,
            WINDOWS_KILLSWITCH_SMOKE_HELPER_FILE
        );
        assert!(invocation.args.iter().any(|arg| arg == "-ExerciseIpv6"));
        // It must NOT request the SSH-cutting full block.
        assert!(
            !invocation
                .args
                .iter()
                .any(|arg| arg == "-ExerciseFullBlock")
        );
    }

    #[test]
    fn windows_killswitch_smoke_parser_surfaces_ipv6_flags_on_failure() {
        let err = parse_windows_killswitch_smoke_output(
            r#"{
                "status": "fail",
                "overall_ok": false,
                "reason": "killswitch did not apply/rollback cleanly (overall_ok=False, exit=1)",
                "daemon_exit_code": 1,
                "killswitch_report": {
                    "killswitch_applied": true,
                    "asserted_active": true,
                    "rolled_back": true,
                    "ipv6_protection_exercised": true,
                    "ipv6_baseline_egress_ok": true,
                    "ipv6_control_applied": true,
                    "ipv6_egress_blocked": false,
                    "ipv6_control_rolled_back": true,
                    "ipv6_egress_restored": true,
                    "overall_ok": false
                }
            }"#,
            "windows-utm-1",
        )
        .expect_err("an IPv6-leg failure must fail closed");
        assert!(err.contains("ipv6_protection_exercised=true"));
        assert!(err.contains("ipv6_egress_blocked=false"));
    }

    #[test]
    fn windows_dns_smoke_invocation_reuses_killswitch_helper_with_exercise_dns() {
        let invocation = build_windows_dns_smoke_invocation(&sample_context(None));
        // N3 reuses the killswitch smoke helper, adding only the DNS leg.
        assert_eq!(
            invocation.helper_file_name,
            WINDOWS_KILLSWITCH_SMOKE_HELPER_FILE
        );
        assert!(invocation.args.iter().any(|arg| arg == "-ExerciseDns"));
        // It must NOT request the SSH-cutting full block.
        assert!(
            !invocation
                .args
                .iter()
                .any(|arg| arg == "-ExerciseFullBlock")
        );
    }

    #[test]
    fn windows_killswitch_smoke_parser_surfaces_dns_flags_on_failure() {
        let err = parse_windows_killswitch_smoke_output(
            r#"{
                "status": "fail",
                "overall_ok": false,
                "reason": "killswitch did not apply/rollback cleanly (overall_ok=False, exit=1)",
                "daemon_exit_code": 1,
                "killswitch_report": {
                    "killswitch_applied": true,
                    "asserted_active": true,
                    "rolled_back": true,
                    "dns_protection_exercised": true,
                    "dns_protection_applied": true,
                    "dns_protection_asserted_active": false,
                    "dns_protection_rolled_back": true,
                    "dns_protection_asserted_inactive": true,
                    "overall_ok": false
                }
            }"#,
            "windows-utm-1",
        )
        .expect_err("a DNS-leg failure must fail closed");
        assert!(err.contains("dns_protection_exercised=true"));
        assert!(err.contains("dns_protection_asserted_active=false"));
    }

    #[test]
    fn windows_verify_invocation_requires_live_path_only_for_final_verify() {
        let context = sample_context(None);
        let layout_only = build_windows_verify_invocation(&context, false);
        assert_eq!(layout_only.helper_file_name, WINDOWS_VERIFY_HELPER_FILE);
        assert_eq!(layout_only.remote_file_name, WINDOWS_VERIFY_HELPER_FILE);
        assert!(!layout_only.args.iter().any(|arg| arg == "-RequireLivePath"));

        let final_verify = build_windows_verify_invocation(&context, true);
        assert_eq!(final_verify.helper_file_name, WINDOWS_VERIFY_HELPER_FILE);
        assert_eq!(final_verify.remote_file_name, WINDOWS_VERIFY_HELPER_FILE);
        assert!(
            final_verify
                .args
                .iter()
                .any(|arg| arg == "-RequireLivePath")
        );
    }

    #[test]
    fn windows_verify_helper_daemon_probes_are_bounded_and_allowlisted() {
        let helper = include_str!(
            "../../../../../scripts/bootstrap/windows/Verify-RustyNetWindowsBootstrap.ps1"
        );
        assert!(helper.contains("function Invoke-DaemonControlCommand"));
        assert!(helper.contains("$Command -notin @('status', 'netcheck')"));
        assert!(helper.contains("-ArgumentList @($Command)"));
        assert!(helper.contains("$process.WaitForExit($TimeoutSeconds * 1000)"));
        assert!(helper.contains("Stop-Process -Id $process.Id -Force"));
    }

    #[test]
    fn windows_verify_output_parser_rejects_missing_service() {
        let err = parse_windows_runtime_report_output(
            r#"{
                "status": "fail",
                "reason": "windows-runtime-service-host-not-yet-implemented",
                "service_status": "missing",
                "failure_step": "probe-runtime-support",
                "notes": ["windows-service-flags-missing","service-missing"]
            }"#,
            "Windows verify helper",
            "windows-utm-1",
        )
        .expect_err("missing service must fail closed");
        assert!(err.contains("status=fail"));
        assert!(err.contains("reason=windows-runtime-service-host-not-yet-implemented"));
        assert!(err.contains("failure_step=probe-runtime-support"));
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
    fn windows_runtime_report_parser_surfaces_live_path_blocker() {
        let err = parse_windows_runtime_report_output(
            r#"{
                "status": "fail",
                "reason": "windows-path-live-not-proven",
                "service_status": "Running",
                "backend_label": "windows-wireguard-nt",
                "require_live_path": true,
                "path_live_proven": false,
                "path_latest_live_handshake_unix": "0",
                "notes": ["path-live-not-proven"]
            }"#,
            "Windows verify helper",
            "windows-utm-1",
        )
        .expect_err("RequireLivePath without live proof must fail closed");
        assert!(err.contains("status=fail"));
        assert!(err.contains("reason=windows-path-live-not-proven"));
        assert!(err.contains("require_live_path=true"));
        assert!(err.contains("path_live_proven=false"));
        assert!(err.contains("path_latest_live_handshake_unix=0"));
        assert!(err.contains("path-live-not-proven"));
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
                "failure_step": "probe-runtime-support",
                "cleanup_status": "removed"
            }"#,
            "windows-utm-1",
        )
        .expect_err("unvalidated host surface must fail closed");
        assert!(err.contains("host_surface_validated=false"));
        assert!(err.contains("failure_step=probe-runtime-support"));
    }

    #[test]
    fn windows_restart_runtime_script_uses_bounded_sc_service_control() {
        let script =
            build_windows_restart_runtime_script().expect("restart-runtime script should build");
        assert!(script.contains("Stop-RustyNetServiceBounded"));
        assert!(script.contains("sc.exe stop $serviceName"));
        assert!(script.contains("sc.exe start $serviceName"));
        assert!(script.contains("refusing to kill StopPending service"));
        assert!(script.contains("service-status="));
        assert!(!script.contains("Restart-Service"));
        assert!(!script.contains("WaitForStatus('Running'"));
        assert!(!script.contains("systemctl"));
    }

    #[test]
    fn windows_diagnostics_invocation_uses_remote_temp_root_and_phase() {
        let target = RemoteTarget {
            label: "windows-utm-1".to_owned(),
            ssh_target: "192.168.64.20".to_owned(),
            ssh_user: Some("Administrator".to_owned()),
            controller: None,
            platform_profile: default_platform_profile(VmGuestPlatform::Windows),
            rustynet_src_dir: Some(r"C:\Rustynet".to_owned()),
            remote_temp_dir: Some(r"C:\ProgramData\Rustynet\vm-lab".to_owned()),
            utm_staging_dir: Some(r"C:\Users\windows\rustynet-utm-stage".to_owned()),
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
        assert!(phase_requires_proven_access(BootstrapPhase::BuildRelease));
        assert!(!phase_requires_proven_access(
            BootstrapPhase::SmokeServiceHost
        ));
        assert!(phase_requires_proven_access(BootstrapPhase::InstallRelease));
        assert!(phase_requires_proven_access(BootstrapPhase::RestartRuntime));
        assert!(phase_requires_proven_access(BootstrapPhase::VerifyRuntime));
        assert!(!phase_requires_proven_access(BootstrapPhase::All));
    }

    #[test]
    fn local_utm_result_file_disabled_for_post_bootstrap_phases_on_windows_local_utm() {
        // Post-bootstrap phases use pinned SSH after access is proven.
        // Local UTM result-file pulls can block even after the guest has
        // written a complete report, so they are kept out of the normal
        // runtime phase path.
        let target = RemoteTarget {
            label: "windows-utm-1".to_owned(),
            ssh_target: "192.168.64.14".to_owned(),
            ssh_user: Some("Administrator".to_owned()),
            controller: Some(VmController::LocalUtm {
                utm_name: "Windows".to_owned(),
                bundle_path: std::path::PathBuf::from("/tmp/Windows.utm"),
            }),
            platform_profile: default_platform_profile(VmGuestPlatform::Windows),
            rustynet_src_dir: Some(r"C:\Rustynet".to_owned()),
            remote_temp_dir: Some(r"C:\ProgramData\Rustynet\vm-lab".to_owned()),
            utm_staging_dir: Some(r"C:\Users\windows\rustynet-utm-stage".to_owned()),
        };

        assert!(!local_utm_result_file_supported_for_phase(
            BootstrapPhase::BuildRelease,
            &target
        ));
        assert!(!local_utm_result_file_supported_for_phase(
            BootstrapPhase::InstallRelease,
            &target
        ));
        assert!(!local_utm_result_file_supported_for_phase(
            BootstrapPhase::RestartRuntime,
            &target
        ));
        assert!(!local_utm_result_file_supported_for_phase(
            BootstrapPhase::VerifyRuntime,
            &target
        ));
    }

    #[test]
    fn windows_capture_validation_scripts_do_not_exit_the_host_process() {
        let smoke_script = build_windows_service_host_smoke_validation_script(
            r"C:\ProgramData\RustyNet\vm-lab\Smoke-RustyNetWindowsServiceHost.ps1",
            &[
                "-RustyNetRoot".to_owned(),
                r"C:\Rustynet".to_owned(),
                "-StateRoot".to_owned(),
                r"C:\ProgramData\RustyNet".to_owned(),
            ],
            r"C:\ProgramData\RustyNet\vm-lab\smoke.json",
        )
        .expect("smoke validation script should render");
        assert!(!smoke_script.contains("exit 0"));

        let runtime_script = build_windows_runtime_report_validation_script(
            r"C:\ProgramData\RustyNet\vm-lab\Verify-RustyNetWindowsBootstrap.ps1",
            &[
                "-RustyNetRoot".to_owned(),
                r"C:\Rustynet".to_owned(),
                "-StateRoot".to_owned(),
                r"C:\ProgramData\RustyNet".to_owned(),
            ],
            r"C:\ProgramData\RustyNet\vm-lab\verify.json",
            "Windows verify helper",
        )
        .expect("runtime validation script should render");
        assert!(!runtime_script.contains("exit 0"));
        assert!(runtime_script.contains("__RUSTYNET_VM_LAB_RC__"));

        let diagnostics_script = build_windows_diagnostics_validation_script(
            r"C:\ProgramData\RustyNet\vm-lab\Collect-RustyNetWindowsDiagnostics.ps1",
            &[
                "-OutputRoot".to_owned(),
                r"C:\ProgramData\RustyNet\diag".to_owned(),
            ],
            r"C:\ProgramData\RustyNet\diag",
        )
        .expect("diagnostics validation script should render");
        assert!(!diagnostics_script.contains("exit 0"));
    }

    #[test]
    fn windows_diagnostics_validation_script_requires_manifest() {
        let script = build_windows_diagnostics_validation_script(
            r"C:\ProgramData\Rustynet\vm-lab\Collect-RustyNetWindowsDiagnostics.ps1",
            &[
                "-OutputRoot".to_owned(),
                r"C:\ProgramData\Rustynet\vm-lab\diagnostics\run-1".to_owned(),
            ],
            r"C:\ProgramData\Rustynet\vm-lab\diagnostics\run-1",
        )
        .expect("diagnostics validation script should build");

        assert!(script.contains("manifest.json"));
        assert!(script.contains("ConvertFrom-Json"));
        assert!(script.contains("did not create output root"));
    }

    // ----- WindowsDiagnosticsManifestView typed parser tests -----

    #[test]
    fn windows_diagnostics_manifest_parses_success_payload() {
        let body = r#"{
          "schema_version": 2,
          "captured_at_utc": "2026-05-15T11:00:00.000Z",
          "output_root": "C:\\ProgramData\\RustyNet\\vm-lab\\diagnostics\\run-1",
          "install_root": "C:\\Program Files\\RustyNet",
          "state_root": "C:\\ProgramData\\RustyNet",
          "service_name": "RustyNet",
          "windows_target_facts": {"caption": "Windows 11 Pro"},
          "runtime_boundary_status": "pass",
          "omitted_secret_material": ["C:\\ProgramData\\ssh\\ssh_host_ed25519_key"],
          "files": ["manifest.json", "services.txt", "hashes.json"],
          "status": "pass",
          "reason": ""
        }"#;
        let view = WindowsDiagnosticsManifestView::parse(body).expect("must parse");
        assert_eq!(view.schema_version, 2);
        assert_eq!(view.service_name, "RustyNet");
        assert_eq!(view.status, "pass");
        assert_eq!(view.reason, "");
        assert!(view.files.iter().any(|name| name == "manifest.json"));
    }

    #[test]
    fn windows_diagnostics_manifest_parses_failure_payload_with_reason() {
        let body = r#"{
          "schema_version": 2,
          "captured_at_utc": "2026-05-15T11:00:00.000Z",
          "output_root": "C:\\ProgramData\\RustyNet\\vm-lab\\diagnostics\\run-2",
          "install_root": "C:\\Program Files\\RustyNet",
          "state_root": "C:\\ProgramData\\RustyNet",
          "service_name": "RustyNet",
          "status": "fail",
          "reason": "diagnostics-collection-exception: access denied",
          "files": []
        }"#;
        let view = WindowsDiagnosticsManifestView::parse(body).expect("must parse");
        assert_eq!(view.status, "fail");
        assert!(view.reason.contains("access denied"));
        assert!(view.files.is_empty());
    }

    #[test]
    fn windows_diagnostics_manifest_rejects_unknown_status_value() {
        let body = r#"{
          "schema_version": 2,
          "captured_at_utc": "2026-05-15T11:00:00.000Z",
          "output_root": "C:\\out",
          "install_root": "C:\\Program Files\\RustyNet",
          "state_root": "C:\\ProgramData\\RustyNet",
          "service_name": "RustyNet",
          "status": "maybe",
          "files": []
        }"#;
        let err = WindowsDiagnosticsManifestView::parse(body)
            .expect_err("unknown status value must fail closed");
        assert!(err.contains("must be 'pass' or 'fail'"));
    }

    #[test]
    fn windows_diagnostics_manifest_rejects_fail_status_without_reason() {
        let body = r#"{
          "schema_version": 2,
          "captured_at_utc": "2026-05-15T11:00:00.000Z",
          "output_root": "C:\\out",
          "install_root": "C:\\Program Files\\RustyNet",
          "state_root": "C:\\ProgramData\\RustyNet",
          "service_name": "RustyNet",
          "status": "fail",
          "reason": "   ",
          "files": []
        }"#;
        let err = WindowsDiagnosticsManifestView::parse(body)
            .expect_err("status=fail with empty reason must fail closed");
        assert!(err.contains("non-empty reason"));
    }

    #[test]
    fn windows_diagnostics_manifest_rejects_missing_required_field() {
        // missing service_name
        let body = r#"{
          "schema_version": 2,
          "captured_at_utc": "2026-05-15T11:00:00.000Z",
          "output_root": "C:\\out",
          "install_root": "C:\\Program Files\\RustyNet",
          "state_root": "C:\\ProgramData\\RustyNet",
          "status": "pass",
          "files": []
        }"#;
        let err = WindowsDiagnosticsManifestView::parse(body)
            .expect_err("missing service_name must fail closed");
        assert!(err.contains("invalid windows diagnostics manifest shape"));
    }

    #[test]
    fn windows_diagnostics_manifest_rejects_wrong_field_type() {
        // schema_version as string instead of number
        let body = r#"{
          "schema_version": "two",
          "captured_at_utc": "2026-05-15T11:00:00.000Z",
          "output_root": "C:\\out",
          "install_root": "C:\\Program Files\\RustyNet",
          "state_root": "C:\\ProgramData\\RustyNet",
          "service_name": "RustyNet",
          "status": "pass",
          "files": []
        }"#;
        let err = WindowsDiagnosticsManifestView::parse(body)
            .expect_err("schema_version wrong type must fail closed");
        assert!(err.contains("invalid windows diagnostics manifest shape"));
    }

    #[test]
    fn windows_diagnostics_manifest_accepts_unknown_extra_fields() {
        // Forward-compatible: extras (e.g. windows_target_facts, custom
        // operator annotations) MUST NOT break the typed view.
        let body = r#"{
          "schema_version": 2,
          "captured_at_utc": "2026-05-15T11:00:00.000Z",
          "output_root": "C:\\out",
          "install_root": "C:\\Program Files\\RustyNet",
          "state_root": "C:\\ProgramData\\RustyNet",
          "service_name": "RustyNet",
          "status": "pass",
          "files": [],
          "future_field_added_by_a_later_helper_version": {"some": "value"}
        }"#;
        let view = WindowsDiagnosticsManifestView::parse(body).expect("must parse");
        assert_eq!(view.status, "pass");
    }

    #[test]
    fn windows_diagnostics_manifest_parse_is_idempotent() {
        let body = r#"{
          "schema_version": 2,
          "captured_at_utc": "2026-05-15T11:00:00.000Z",
          "output_root": "C:\\out",
          "install_root": "C:\\Program Files\\RustyNet",
          "state_root": "C:\\ProgramData\\RustyNet",
          "service_name": "RustyNet",
          "status": "pass",
          "files": ["manifest.json"]
        }"#;
        let a = WindowsDiagnosticsManifestView::parse(body).unwrap();
        let b = WindowsDiagnosticsManifestView::parse(body).unwrap();
        assert_eq!(a, b);
    }

    // ----- WindowsVerifyReportView typed parser tests -----

    #[test]
    fn windows_verify_report_parses_success_payload() {
        let body = r#"{
          "schema_version": 3,
          "captured_at_utc": "2026-05-15T12:00:00.000Z",
          "platform": "windows",
          "rustynet_root": "C:\\Rustynet",
          "install_root": "C:\\Program Files\\RustyNet",
          "state_root": "C:\\ProgramData\\RustyNet",
          "service_name": "RustyNet",
          "status": "pass",
          "reason": "",
          "backend_label": "windows-wireguard-nt",
          "runtime_supported": true,
          "service_verified": true,
          "service_present": true,
          "service_status": "Running",
          "require_live_path": true,
          "daemon_status_probe_status": "pass",
          "daemon_netcheck_probe_status": "pass",
          "path_live_proven": true,
          "path_latest_live_handshake_unix": "1710000000",
          "failure_step": "",
          "notes": []
        }"#;
        let view = WindowsVerifyReportView::parse(body).expect("must parse");
        assert_eq!(view.schema_version, 3);
        assert_eq!(view.status, "pass");
        assert!(view.runtime_supported);
        assert!(view.service_verified);
        assert!(view.require_live_path);
        assert_eq!(view.daemon_status_probe_status, "pass");
        assert_eq!(view.daemon_netcheck_probe_status, "pass");
        assert!(view.path_live_proven);
        assert_eq!(view.path_latest_live_handshake_unix, "1710000000");
    }

    #[test]
    fn windows_verify_report_parses_failure_payload_from_trap() {
        // Failure manifest emitted by New-FailClosedVerifyReport, after
        // the schema_version bump that brought it to parity with success.
        let body = r#"{
          "schema_version": 3,
          "captured_at_utc": "2026-05-15T12:00:00.000Z",
          "platform": "windows",
          "rustynet_root": "C:\\Rustynet",
          "install_root": "C:\\Program Files\\RustyNet",
          "state_root": "C:\\ProgramData\\RustyNet",
          "service_name": "RustyNet",
          "status": "fail",
          "reason": "verify-helper-init-exception: access denied",
          "backend_label": "",
          "runtime_supported": false,
          "service_verified": false,
          "service_present": false,
          "service_status": "missing",
          "failure_step": "init",
          "runtime_signals": null,
          "notes": ["verify-helper-trap"]
        }"#;
        let view = WindowsVerifyReportView::parse(body).expect("must parse");
        assert_eq!(view.status, "fail");
        assert!(view.reason.contains("access denied"));
        assert_eq!(view.notes, vec!["verify-helper-trap".to_owned()]);
    }

    #[test]
    fn windows_verify_report_parses_blocked_payload_for_unsupported_runtime() {
        let body = r#"{
          "schema_version": 3,
          "captured_at_utc": "2026-05-15T12:00:00.000Z",
          "platform": "windows",
          "rustynet_root": "C:\\Rustynet",
          "install_root": "C:\\Program Files\\RustyNet",
          "state_root": "C:\\ProgramData\\RustyNet",
          "service_name": "RustyNet",
          "status": "blocked",
          "reason": "windows-runtime-backend-explicitly-unsupported"
        }"#;
        let view = WindowsVerifyReportView::parse(body).expect("must parse");
        assert_eq!(view.status, "blocked");
        assert!(view.reason.contains("explicitly-unsupported"));
    }

    #[test]
    fn windows_verify_report_rejects_wrong_schema_version() {
        let body = r#"{
          "schema_version": 1,
          "captured_at_utc": "2026-05-15T12:00:00.000Z",
          "platform": "windows",
          "rustynet_root": "C:\\Rustynet",
          "install_root": "C:\\Program Files\\RustyNet",
          "state_root": "C:\\ProgramData\\RustyNet",
          "service_name": "RustyNet",
          "status": "pass"
        }"#;
        let err = WindowsVerifyReportView::parse(body)
            .expect_err("schema_version=1 must fail closed (helper emits 3)");
        assert!(err.contains("schema_version must be 3"));
    }

    #[test]
    fn windows_verify_report_rejects_unknown_status_value() {
        let body = r#"{
          "schema_version": 3,
          "captured_at_utc": "2026-05-15T12:00:00.000Z",
          "platform": "windows",
          "rustynet_root": "C:\\Rustynet",
          "install_root": "C:\\Program Files\\RustyNet",
          "state_root": "C:\\ProgramData\\RustyNet",
          "service_name": "RustyNet",
          "status": "warn"
        }"#;
        let err =
            WindowsVerifyReportView::parse(body).expect_err("unknown status must fail closed");
        assert!(err.contains("'pass', 'fail', or 'blocked'"));
    }

    #[test]
    fn windows_verify_report_rejects_fail_without_reason() {
        let body = r#"{
          "schema_version": 3,
          "captured_at_utc": "2026-05-15T12:00:00.000Z",
          "platform": "windows",
          "rustynet_root": "C:\\Rustynet",
          "install_root": "C:\\Program Files\\RustyNet",
          "state_root": "C:\\ProgramData\\RustyNet",
          "service_name": "RustyNet",
          "status": "fail",
          "reason": "   "
        }"#;
        let err = WindowsVerifyReportView::parse(body)
            .expect_err("status=fail with empty reason must fail closed");
        assert!(err.contains("non-empty reason"));
    }

    #[test]
    fn windows_verify_report_rejects_blocked_without_reason() {
        let body = r#"{
          "schema_version": 3,
          "captured_at_utc": "2026-05-15T12:00:00.000Z",
          "platform": "windows",
          "rustynet_root": "C:\\Rustynet",
          "install_root": "C:\\Program Files\\RustyNet",
          "state_root": "C:\\ProgramData\\RustyNet",
          "service_name": "RustyNet",
          "status": "blocked",
          "reason": ""
        }"#;
        let err = WindowsVerifyReportView::parse(body)
            .expect_err("status=blocked with empty reason must fail closed");
        assert!(err.contains("non-empty reason"));
    }

    #[test]
    fn windows_verify_report_rejects_missing_required_field() {
        // missing rustynet_root
        let body = r#"{
          "schema_version": 3,
          "captured_at_utc": "2026-05-15T12:00:00.000Z",
          "platform": "windows",
          "install_root": "C:\\Program Files\\RustyNet",
          "state_root": "C:\\ProgramData\\RustyNet",
          "service_name": "RustyNet",
          "status": "pass"
        }"#;
        let err = WindowsVerifyReportView::parse(body)
            .expect_err("missing rustynet_root must fail closed");
        assert!(err.contains("invalid windows verify report shape"));
    }

    #[test]
    fn windows_verify_report_accepts_forward_compatible_extra_fields() {
        let body = r#"{
          "schema_version": 3,
          "captured_at_utc": "2026-05-15T12:00:00.000Z",
          "platform": "windows",
          "rustynet_root": "C:\\Rustynet",
          "install_root": "C:\\Program Files\\RustyNet",
          "state_root": "C:\\ProgramData\\RustyNet",
          "service_name": "RustyNet",
          "status": "pass",
          "future_field_added_by_a_later_helper_version": {"some": "value"},
          "runtime_boundary": {"status": "pass"}
        }"#;
        let view = WindowsVerifyReportView::parse(body).expect("must parse");
        assert_eq!(view.status, "pass");
    }

    // ----- WindowsInstallReportView typed parser tests -----

    #[test]
    fn windows_install_report_parses_success_payload() {
        let body = r#"{
          "schema_version": 1,
          "captured_at_utc": "2026-05-15T13:00:00.000Z",
          "platform": "windows",
          "rustynet_root": "C:\\Rustynet",
          "install_root": "C:\\Program Files\\RustyNet",
          "state_root": "C:\\ProgramData\\RustyNet",
          "service_name": "RustyNet",
          "status": "pass",
          "reason": "",
          "backend_label": "windows-wireguard-nt",
          "runtime_supported": false,
          "service_verified": true,
          "cli_optional": true,
          "start_attempted": true,
          "start_error": "",
          "daemon_present": true,
          "cli_present": true,
          "config_present": true,
          "service_present": true,
          "service_status": "Running",
          "service_state": "Running",
          "service_start_mode": "Auto",
          "service_exit_code": 0,
          "service_process_id": 1234,
          "service_image_path": "C:\\Program Files\\RustyNet\\rustynetd.exe --windows-service ...",
          "notes": []
        }"#;
        let view = WindowsInstallReportView::parse(body).expect("must parse");
        assert_eq!(view.schema_version, 1);
        assert_eq!(view.status, "pass");
        assert!(view.service_verified);
        assert_eq!(view.service_status, "Running");
    }

    #[test]
    fn windows_install_report_parses_failure_payload_from_trap() {
        let body = r#"{
          "schema_version": 1,
          "captured_at_utc": "2026-05-15T13:00:00.000Z",
          "platform": "windows",
          "rustynet_root": "C:\\Rustynet",
          "install_root": "C:\\Program Files\\RustyNet",
          "state_root": "C:\\ProgramData\\RustyNet",
          "service_name": "RustyNet",
          "status": "fail",
          "reason": "install-helper-init-exception: invalid service name",
          "backend_label": "",
          "runtime_supported": false,
          "service_verified": false,
          "service_present": false,
          "service_status": "missing",
          "failure_step": "init",
          "runtime_signals": null,
          "notes": ["install-helper-trap"]
        }"#;
        let view = WindowsInstallReportView::parse(body).expect("must parse");
        assert_eq!(view.status, "fail");
        assert!(view.reason.contains("invalid service name"));
        assert_eq!(view.notes, vec!["install-helper-trap".to_owned()]);
    }

    #[test]
    fn windows_install_report_rejects_wrong_schema_version() {
        let body = r#"{
          "schema_version": 2,
          "captured_at_utc": "2026-05-15T13:00:00.000Z",
          "platform": "windows",
          "rustynet_root": "C:\\Rustynet",
          "install_root": "C:\\Program Files\\RustyNet",
          "state_root": "C:\\ProgramData\\RustyNet",
          "service_name": "RustyNet",
          "status": "pass"
        }"#;
        let err = WindowsInstallReportView::parse(body)
            .expect_err("schema_version=2 must fail closed (helper emits 1)");
        assert!(err.contains("schema_version must be 1"));
    }

    #[test]
    fn windows_install_report_rejects_blocked_status_value() {
        // Install never emits blocked — only pass or fail. Unlike Verify
        // which has a backend-explicitly-unsupported case, Install treats
        // any unsupported-runtime case as a regular failure.
        let body = r#"{
          "schema_version": 1,
          "captured_at_utc": "2026-05-15T13:00:00.000Z",
          "platform": "windows",
          "rustynet_root": "C:\\Rustynet",
          "install_root": "C:\\Program Files\\RustyNet",
          "state_root": "C:\\ProgramData\\RustyNet",
          "service_name": "RustyNet",
          "status": "blocked",
          "reason": "anything"
        }"#;
        let err = WindowsInstallReportView::parse(body)
            .expect_err("blocked status must fail closed for Install");
        assert!(err.contains("'pass' or 'fail'"));
    }

    #[test]
    fn windows_install_report_rejects_fail_without_reason() {
        let body = r#"{
          "schema_version": 1,
          "captured_at_utc": "2026-05-15T13:00:00.000Z",
          "platform": "windows",
          "rustynet_root": "C:\\Rustynet",
          "install_root": "C:\\Program Files\\RustyNet",
          "state_root": "C:\\ProgramData\\RustyNet",
          "service_name": "RustyNet",
          "status": "fail",
          "reason": "   "
        }"#;
        let err = WindowsInstallReportView::parse(body)
            .expect_err("status=fail with empty reason must fail closed");
        assert!(err.contains("non-empty reason"));
    }

    #[test]
    fn windows_install_report_rejects_missing_required_field() {
        // missing install_root
        let body = r#"{
          "schema_version": 1,
          "captured_at_utc": "2026-05-15T13:00:00.000Z",
          "platform": "windows",
          "rustynet_root": "C:\\Rustynet",
          "state_root": "C:\\ProgramData\\RustyNet",
          "service_name": "RustyNet",
          "status": "pass"
        }"#;
        let err = WindowsInstallReportView::parse(body)
            .expect_err("missing install_root must fail closed");
        assert!(err.contains("invalid windows install report shape"));
    }

    #[test]
    fn windows_install_report_rejects_wrong_field_type() {
        // service_name as bool instead of string
        let body = r#"{
          "schema_version": 1,
          "captured_at_utc": "2026-05-15T13:00:00.000Z",
          "platform": "windows",
          "rustynet_root": "C:\\Rustynet",
          "install_root": "C:\\Program Files\\RustyNet",
          "state_root": "C:\\ProgramData\\RustyNet",
          "service_name": true,
          "status": "pass"
        }"#;
        let err = WindowsInstallReportView::parse(body)
            .expect_err("service_name wrong type must fail closed");
        assert!(err.contains("invalid windows install report shape"));
    }

    #[test]
    fn windows_install_report_accepts_forward_compatible_extra_fields() {
        let body = r#"{
          "schema_version": 1,
          "captured_at_utc": "2026-05-15T13:00:00.000Z",
          "platform": "windows",
          "rustynet_root": "C:\\Rustynet",
          "install_root": "C:\\Program Files\\RustyNet",
          "state_root": "C:\\ProgramData\\RustyNet",
          "service_name": "RustyNet",
          "status": "pass",
          "future_install_field": {"nested": [1, 2, 3]},
          "wireguard_driver_probe": {"present": false},
          "dns_failclosed_posture": {"status": "pass"}
        }"#;
        let view = WindowsInstallReportView::parse(body).expect("must parse");
        assert_eq!(view.status, "pass");
    }

    #[test]
    fn windows_install_report_parse_is_idempotent() {
        let body = r#"{
          "schema_version": 1,
          "captured_at_utc": "2026-05-15T13:00:00.000Z",
          "platform": "windows",
          "rustynet_root": "C:\\Rustynet",
          "install_root": "C:\\Program Files\\RustyNet",
          "state_root": "C:\\ProgramData\\RustyNet",
          "service_name": "RustyNet",
          "status": "pass"
        }"#;
        let a = WindowsInstallReportView::parse(body).unwrap();
        let b = WindowsInstallReportView::parse(body).unwrap();
        assert_eq!(a, b);
    }

    // ----- WindowsPrepareTransportReportView typed parser tests -----

    #[test]
    fn windows_prepare_transport_report_parses_success_payload() {
        let body = r#"{
          "openssh_installed": true,
          "service_running": true,
          "firewall_rule_enabled": true,
          "authorized_keys_applied": true,
          "host_key_present": true,
          "listener_ready": true,
          "default_shell_configured": true,
          "status": "pass",
          "reason": "ok",
          "host_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExAMPLE host-id"
        }"#;
        let view = WindowsPrepareTransportReportView::parse(body).expect("must parse");
        assert_eq!(view.status, "pass");
        assert_eq!(view.reason, "ok");
        assert!(view.openssh_installed);
        assert!(view.host_key.starts_with("ssh-ed25519"));
    }

    #[test]
    fn windows_prepare_transport_report_parses_failure_payload_from_trap() {
        let body = r#"{
          "openssh_installed": false,
          "service_running": false,
          "firewall_rule_enabled": false,
          "authorized_keys_applied": false,
          "host_key_present": false,
          "listener_ready": false,
          "default_shell_configured": false,
          "status": "fail",
          "reason": "prepare-transport-exception: access denied",
          "host_key": ""
        }"#;
        let view = WindowsPrepareTransportReportView::parse(body).expect("must parse");
        assert_eq!(view.status, "fail");
        assert!(view.reason.contains("access denied"));
        assert!(view.host_key.is_empty());
    }

    #[test]
    fn windows_prepare_transport_report_parses_partial_progress_failure() {
        // Helper reports failure mid-progress: openssh + default_shell
        // got installed, but firewall_rule_enabled fell over before
        // host_key collection. Both success-progress booleans and the
        // canonical failure reason coexist.
        let body = r#"{
          "openssh_installed": true,
          "service_running": false,
          "firewall_rule_enabled": false,
          "authorized_keys_applied": true,
          "host_key_present": false,
          "listener_ready": false,
          "default_shell_configured": true,
          "status": "fail",
          "reason": "firewall-rule-not-enabled",
          "host_key": ""
        }"#;
        let view = WindowsPrepareTransportReportView::parse(body).expect("must parse");
        assert!(view.openssh_installed);
        assert!(view.default_shell_configured);
        assert_eq!(view.reason, "firewall-rule-not-enabled");
    }

    #[test]
    fn windows_prepare_transport_report_rejects_unknown_status_value() {
        let body = r#"{
          "openssh_installed": true,
          "service_running": true,
          "firewall_rule_enabled": true,
          "authorized_keys_applied": true,
          "host_key_present": true,
          "listener_ready": true,
          "default_shell_configured": true,
          "status": "warn",
          "reason": "ok",
          "host_key": "ssh-ed25519 AAA"
        }"#;
        let err = WindowsPrepareTransportReportView::parse(body)
            .expect_err("unknown status must fail closed");
        assert!(err.contains("'pass' or 'fail'"));
    }

    #[test]
    fn windows_prepare_transport_report_rejects_fail_with_empty_reason() {
        let body = r#"{
          "openssh_installed": false,
          "service_running": false,
          "firewall_rule_enabled": false,
          "authorized_keys_applied": false,
          "host_key_present": false,
          "listener_ready": false,
          "default_shell_configured": false,
          "status": "fail",
          "reason": "   ",
          "host_key": ""
        }"#;
        let err = WindowsPrepareTransportReportView::parse(body)
            .expect_err("status=fail with empty reason must fail closed");
        assert!(err.contains("non-empty reason"));
    }

    #[test]
    fn windows_prepare_transport_report_rejects_host_key_present_with_empty_host_key() {
        // Internal invariant: if the helper says host_key_present=true,
        // the host_key field must also be populated. The typed view
        // catches drift between the two fields.
        let body = r#"{
          "openssh_installed": true,
          "service_running": true,
          "firewall_rule_enabled": true,
          "authorized_keys_applied": true,
          "host_key_present": true,
          "listener_ready": true,
          "default_shell_configured": true,
          "status": "pass",
          "reason": "ok",
          "host_key": "   "
        }"#;
        let err = WindowsPrepareTransportReportView::parse(body)
            .expect_err("host_key_present=true with empty host_key must fail closed");
        assert!(err.contains("non-empty host_key"));
    }

    #[test]
    fn windows_prepare_transport_report_rejects_missing_required_field() {
        // missing listener_ready
        let body = r#"{
          "openssh_installed": true,
          "service_running": true,
          "firewall_rule_enabled": true,
          "authorized_keys_applied": true,
          "host_key_present": true,
          "default_shell_configured": true,
          "status": "pass",
          "reason": "ok",
          "host_key": "ssh-ed25519 AAA"
        }"#;
        let err = WindowsPrepareTransportReportView::parse(body)
            .expect_err("missing listener_ready must fail closed");
        assert!(err.contains("invalid windows prepare-transport report shape"));
    }

    #[test]
    fn windows_prepare_transport_report_rejects_wrong_field_type() {
        // status as number instead of string
        let body = r#"{
          "openssh_installed": true,
          "service_running": true,
          "firewall_rule_enabled": true,
          "authorized_keys_applied": true,
          "host_key_present": true,
          "listener_ready": true,
          "default_shell_configured": true,
          "status": 1,
          "reason": "ok",
          "host_key": "ssh-ed25519 AAA"
        }"#;
        let err = WindowsPrepareTransportReportView::parse(body)
            .expect_err("status wrong type must fail closed");
        assert!(err.contains("invalid windows prepare-transport report shape"));
    }

    #[test]
    fn windows_prepare_transport_report_parse_is_idempotent() {
        let body = r#"{
          "openssh_installed": true,
          "service_running": true,
          "firewall_rule_enabled": true,
          "authorized_keys_applied": true,
          "host_key_present": true,
          "listener_ready": true,
          "default_shell_configured": true,
          "status": "pass",
          "reason": "ok",
          "host_key": "ssh-ed25519 AAA"
        }"#;
        let a = WindowsPrepareTransportReportView::parse(body).unwrap();
        let b = WindowsPrepareTransportReportView::parse(body).unwrap();
        assert_eq!(a, b);
    }

    // ----- WindowsBuildReleaseReportView typed parser tests -----

    fn build_release_success_payload() -> &'static str {
        r#"{
          "schema_version": 2,
          "phase": "build-release",
          "captured_at_utc": "2026-05-15T14:00:00.000Z",
          "status": "pass",
          "reason": "ok",
          "rustynet_root": "C:\\Rustynet",
          "report_root": "C:\\ProgramData\\RustyNet\\vm-lab\\build-release",
          "stdout_path": "C:\\ProgramData\\RustyNet\\vm-lab\\build-release\\stdout.txt",
          "stderr_path": "C:\\ProgramData\\RustyNet\\vm-lab\\build-release\\stderr.txt",
          "exit_code_path": "C:\\ProgramData\\RustyNet\\vm-lab\\build-release\\exit_code.txt",
          "toolchain_path": "C:\\ProgramData\\RustyNet\\vm-lab\\build-release\\toolchain.txt",
          "toolchain_scope": "machine",
          "cargo_build_jobs": "1",
          "manifest_path": "C:\\ProgramData\\RustyNet\\vm-lab\\build-release\\manifest.json",
          "complete_marker_path": "C:\\ProgramData\\RustyNet\\vm-lab\\build-release\\complete.marker",
          "exit_code": 0,
          "stderr_tail": "",
          "notes": ["guest-authored-build-report"]
        }"#
    }

    #[test]
    fn windows_build_release_report_parses_success_payload() {
        let view = WindowsBuildReleaseReportView::parse(build_release_success_payload())
            .expect("must parse");
        assert_eq!(view.schema_version, 2);
        assert_eq!(view.phase, "build-release");
        assert_eq!(view.status, "pass");
        assert_eq!(view.toolchain_scope, "machine");
        assert_eq!(view.cargo_build_jobs, "1");
        assert_eq!(view.exit_code, 0);
    }

    #[test]
    fn windows_build_release_report_parses_failure_payload_with_stderr_tail() {
        let body = r#"{
          "schema_version": 2,
          "phase": "build-release",
          "captured_at_utc": "2026-05-15T14:00:00.000Z",
          "status": "fail",
          "reason": "cargo build exited with 101",
          "rustynet_root": "C:\\Rustynet",
          "report_root": "C:\\ProgramData\\RustyNet\\vm-lab\\build-release",
          "stdout_path": "C:\\out\\stdout.txt",
          "stderr_path": "C:\\out\\stderr.txt",
          "exit_code_path": "C:\\out\\exit_code.txt",
          "toolchain_path": "C:\\out\\toolchain.txt",
          "toolchain_scope": "unknown",
          "manifest_path": "C:\\out\\manifest.json",
          "complete_marker_path": "C:\\out\\complete.marker",
          "exit_code": 101,
          "stderr_tail": "error: linking with `link.exe` failed",
          "notes": ["guest-authored-build-report"]
        }"#;
        let view = WindowsBuildReleaseReportView::parse(body).expect("must parse");
        assert_eq!(view.status, "fail");
        assert_eq!(view.exit_code, 101);
        assert!(view.stderr_tail.contains("link.exe"));
    }

    #[test]
    fn windows_build_release_report_accepts_all_toolchain_scopes() {
        for scope in ["", "machine", "user", "unknown"] {
            let body = build_release_success_payload().replace(
                "\"toolchain_scope\": \"machine\"",
                &format!("\"toolchain_scope\": \"{scope}\""),
            );
            WindowsBuildReleaseReportView::parse(body.as_str())
                .unwrap_or_else(|err| panic!("scope {scope:?} should parse: {err}"));
        }
    }

    #[test]
    fn windows_build_release_report_rejects_unknown_toolchain_scope() {
        let body = build_release_success_payload().replace(
            "\"toolchain_scope\": \"machine\"",
            "\"toolchain_scope\": \"system-wide\"",
        );
        let err = WindowsBuildReleaseReportView::parse(body.as_str())
            .expect_err("unknown toolchain_scope must fail closed");
        assert!(err.contains("toolchain_scope"));
    }

    #[test]
    fn windows_build_release_report_rejects_wrong_schema_version() {
        let body = build_release_success_payload()
            .replace("\"schema_version\": 2", "\"schema_version\": 1");
        let err = WindowsBuildReleaseReportView::parse(body.as_str())
            .expect_err("schema_version=1 must fail closed");
        assert!(err.contains("schema_version must be 2"));
    }

    #[test]
    fn windows_build_release_report_rejects_wrong_phase_value() {
        let body = build_release_success_payload().replace(
            "\"phase\": \"build-release\"",
            "\"phase\": \"install-release\"",
        );
        let err = WindowsBuildReleaseReportView::parse(body.as_str())
            .expect_err("phase mismatch must fail closed");
        assert!(err.contains("phase must be 'build-release'"));
    }

    #[test]
    fn windows_build_release_report_rejects_unknown_status_value() {
        let body =
            build_release_success_payload().replace("\"status\": \"pass\"", "\"status\": \"warn\"");
        let err = WindowsBuildReleaseReportView::parse(body.as_str())
            .expect_err("unknown status must fail closed");
        assert!(err.contains("'pass' or 'fail'"));
    }

    #[test]
    fn windows_build_release_report_rejects_fail_with_empty_reason() {
        let body = build_release_success_payload()
            .replace("\"status\": \"pass\"", "\"status\": \"fail\"")
            .replace("\"reason\": \"ok\"", "\"reason\": \"   \"")
            .replace("\"exit_code\": 0", "\"exit_code\": 1");
        let err = WindowsBuildReleaseReportView::parse(body.as_str())
            .expect_err("status=fail with empty reason must fail closed");
        assert!(err.contains("non-empty reason"));
    }

    #[test]
    fn windows_build_release_report_rejects_fail_with_zero_exit_code() {
        // Internal invariant: a fail status with exit_code=0 indicates
        // the helper's status decision is internally inconsistent with
        // what cargo actually returned.
        let body = build_release_success_payload()
            .replace("\"status\": \"pass\"", "\"status\": \"fail\"")
            .replace(
                "\"reason\": \"ok\"",
                "\"reason\": \"unexpected fail with zero exit\"",
            );
        let err = WindowsBuildReleaseReportView::parse(body.as_str())
            .expect_err("status=fail with exit_code=0 must fail closed");
        assert!(err.contains("internally inconsistent"));
    }

    #[test]
    fn windows_build_release_report_rejects_missing_required_field() {
        // missing complete_marker_path
        let body = r#"{
          "schema_version": 2,
          "phase": "build-release",
          "captured_at_utc": "2026-05-15T14:00:00.000Z",
          "status": "pass",
          "reason": "ok",
          "rustynet_root": "C:\\Rustynet",
          "report_root": "C:\\out",
          "stdout_path": "C:\\out\\stdout.txt",
          "stderr_path": "C:\\out\\stderr.txt",
          "exit_code_path": "C:\\out\\exit_code.txt",
          "toolchain_path": "C:\\out\\toolchain.txt",
          "toolchain_scope": "machine",
          "manifest_path": "C:\\out\\manifest.json",
          "exit_code": 0
        }"#;
        let err = WindowsBuildReleaseReportView::parse(body)
            .expect_err("missing complete_marker_path must fail closed");
        assert!(err.contains("invalid windows build-release report shape"));
    }

    #[test]
    fn windows_build_release_report_rejects_wrong_field_type() {
        // exit_code as string instead of int
        let body =
            build_release_success_payload().replace("\"exit_code\": 0", "\"exit_code\": \"zero\"");
        let err = WindowsBuildReleaseReportView::parse(body.as_str())
            .expect_err("exit_code wrong type must fail closed");
        assert!(err.contains("invalid windows build-release report shape"));
    }

    #[test]
    fn windows_build_release_report_parse_is_idempotent() {
        let a = WindowsBuildReleaseReportView::parse(build_release_success_payload()).unwrap();
        let b = WindowsBuildReleaseReportView::parse(build_release_success_payload()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn windows_build_release_result_script_requires_complete_marker_and_report_files() {
        let script = build_windows_bootstrap_build_release_result_script(
            r"C:\ProgramData\Rustynet\vm-lab\Bootstrap-RustyNetWindows.ps1",
            &[
                "-Phase".to_owned(),
                "build-release".to_owned(),
                "-RustyNetRoot".to_owned(),
                r"C:\Rustynet".to_owned(),
            ],
            r"C:\ProgramData\Rustynet\vm-lab\build-release\run-1\manifest.json",
            r"C:\ProgramData\Rustynet\vm-lab\build-release\run-1\probe.json",
        )
        .expect("build-release result script should build");

        assert!(script.contains("-ResultPath"));
        assert!(script.contains("complete.marker"));
        assert!(script.contains("manifest missing field"));
        assert!(script.contains("missing report file"));
        assert!(script.contains("probe.json"));
        assert!(script.contains("Write-Output $body"));
    }

    #[test]
    fn windows_build_release_report_parser_surfaces_reason_and_report_root() {
        let err = parse_windows_build_release_report_output(
            r#"{
                "status": "fail",
                "reason": "cargo build failed for Windows build-release (exit_code=101)",
                "report_root": "C:\\ProgramData\\Rustynet\\vm-lab\\build-release\\bootstrap-windows-utm-1-build-release-1",
                "exit_code": 101,
                "stderr_tail": "error: linker `link.exe` not found"
            }"#,
            "windows-utm-1",
        )
        .expect_err("failing build-release report must fail closed");
        assert!(err.contains("reason=cargo build failed for Windows build-release"));
        assert!(err.contains(r"report_root=C:\ProgramData\Rustynet\vm-lab\build-release"));
        assert!(err.contains("stderr_tail=error: linker `link.exe` not found"));
    }

    #[test]
    fn windows_runtime_report_validation_script_uses_output_path_and_plaintext_errors() {
        let script = build_windows_runtime_report_validation_script(
            r"C:\ProgramData\Rustynet\vm-lab\Install-RustyNetWindowsService.ps1",
            &[
                "-RustyNetRoot".to_owned(),
                r"C:\Rustynet".to_owned(),
                "-InstallRoot".to_owned(),
                r"C:\Program Files\RustyNet".to_owned(),
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
            Ok(r"C:\ProgramData\RustyNet\vm-lab\diagnostics\bootstrap-windows-utm-1-verify-runtime-1".to_owned()),
        );
        assert!(rendered.contains("diagnostics_output_root="));
        assert!(rendered.contains("windows-utm-1"));
        assert!(rendered.contains("verify-runtime"));
    }
}
