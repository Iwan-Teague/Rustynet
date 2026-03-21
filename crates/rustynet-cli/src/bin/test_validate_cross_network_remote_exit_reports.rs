#![forbid(unsafe_code)]

use std::env;
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let temp_dir = TempDir::create()?;
    let source_file = temp_dir.path().join("source.txt");
    let log_file = temp_dir.path().join("report.log");
    fs::write(&source_file, "source\n").map_err(|err| {
        format!(
            "write source fixture failed ({}): {err}",
            source_file.display()
        )
    })?;
    fs::write(&log_file, "log\n")
        .map_err(|err| format!("write log fixture failed ({}): {err}", log_file.display()))?;

    let current_commit = git_rev_parse_head()?;
    let captured_at_unix = unix_now()?;

    let direct_report = generate_pass_report(
        "cross_network_direct_remote_exit",
        temp_dir.path(),
        &source_file,
        &log_file,
    )?;
    generate_pass_report(
        "cross_network_relay_remote_exit",
        temp_dir.path(),
        &source_file,
        &log_file,
    )?;
    generate_pass_report(
        "cross_network_failback_roaming",
        temp_dir.path(),
        &source_file,
        &log_file,
    )?;
    generate_pass_report(
        "cross_network_traversal_adversarial",
        temp_dir.path(),
        &source_file,
        &log_file,
    )?;
    generate_pass_report(
        "cross_network_remote_exit_dns",
        temp_dir.path(),
        &source_file,
        &log_file,
    )?;
    generate_pass_report(
        "cross_network_remote_exit_soak",
        temp_dir.path(),
        &source_file,
        &log_file,
    )?;

    let invalid_same_network = temp_dir.path().join("invalid_same_network.json");
    write_fixture(
        &invalid_same_network,
        &invalid_same_network_fixture(
            captured_at_unix,
            &current_commit,
            source_file.as_path(),
            log_file.as_path(),
        ),
    )?;

    let invalid_pass_with_failed_check =
        temp_dir.path().join("invalid_pass_with_failed_check.json");
    write_fixture(
        &invalid_pass_with_failed_check,
        &invalid_pass_with_failed_check_fixture(
            captured_at_unix,
            &current_commit,
            source_file.as_path(),
            log_file.as_path(),
        ),
    )?;

    let invalid_fail_without_summary = temp_dir.path().join("invalid_fail_without_summary.json");
    write_fixture(
        &invalid_fail_without_summary,
        &invalid_fail_without_summary_fixture(
            captured_at_unix,
            &current_commit,
            source_file.as_path(),
            log_file.as_path(),
        ),
    )?;

    let symlink_source = temp_dir.path().join("source-link.txt");
    create_symlink(&source_file, &symlink_source)?;

    let invalid_symlink_artifact = temp_dir.path().join("invalid_symlink_artifact.json");
    write_fixture(
        &invalid_symlink_artifact,
        &invalid_symlink_artifact_fixture(
            captured_at_unix,
            &current_commit,
            symlink_source.as_path(),
            log_file.as_path(),
        ),
    )?;

    let invalid_outside_artifact = temp_dir.path().join("invalid_outside_artifact.json");
    write_fixture(
        &invalid_outside_artifact,
        &invalid_outside_artifact_fixture(captured_at_unix, &current_commit, log_file.as_path()),
    )?;

    let valid_output = temp_dir.path().join("valid.md");
    run_cargo_ops(
        &[
            OsStr::new("ops"),
            OsStr::new("validate-cross-network-remote-exit-reports"),
            OsStr::new("--artifact-dir"),
            temp_dir.path().as_os_str(),
            OsStr::new("--output"),
            valid_output.as_os_str(),
        ],
        false,
    )?;

    expect_cargo_failure(
        &[
            OsStr::new("ops"),
            OsStr::new("validate-cross-network-remote-exit-reports"),
            OsStr::new("--reports"),
            invalid_same_network.as_os_str(),
        ],
        "expected invalid_same_network.json to fail validation",
    )?;
    expect_cargo_failure(
        &[
            OsStr::new("ops"),
            OsStr::new("validate-cross-network-remote-exit-reports"),
            OsStr::new("--reports"),
            invalid_pass_with_failed_check.as_os_str(),
        ],
        "expected invalid_pass_with_failed_check.json to fail validation",
    )?;
    expect_cargo_failure(
        &[
            OsStr::new("ops"),
            OsStr::new("validate-cross-network-remote-exit-reports"),
            OsStr::new("--reports"),
            invalid_fail_without_summary.as_os_str(),
        ],
        "expected invalid_fail_without_summary.json to fail validation",
    )?;
    expect_cargo_failure(
        &[
            OsStr::new("ops"),
            OsStr::new("validate-cross-network-remote-exit-reports"),
            OsStr::new("--reports"),
            invalid_symlink_artifact.as_os_str(),
        ],
        "expected invalid_symlink_artifact.json to fail validation",
    )?;
    expect_cargo_failure(
        &[
            OsStr::new("ops"),
            OsStr::new("validate-cross-network-remote-exit-reports"),
            OsStr::new("--reports"),
            invalid_outside_artifact.as_os_str(),
        ],
        "expected invalid_outside_artifact.json to fail validation",
    )?;
    expect_cargo_failure(
        &[
            OsStr::new("ops"),
            OsStr::new("validate-cross-network-remote-exit-reports"),
            OsStr::new("--reports"),
            direct_report.as_os_str(),
            OsStr::new("--expected-git-commit"),
            OsStr::new("0000000000000000000000000000000000000000"),
        ],
        "expected mismatched git commit to fail validation",
    )?;

    let valid_fail_report = temp_dir.path().join("valid_fail_status.json");
    run_cargo_ops(
        &[
            OsStr::new("ops"),
            OsStr::new("generate-cross-network-remote-exit-report"),
            OsStr::new("--suite"),
            OsStr::new("cross_network_direct_remote_exit"),
            OsStr::new("--report-path"),
            valid_fail_report.as_os_str(),
            OsStr::new("--log-path"),
            log_file.as_os_str(),
            OsStr::new("--status"),
            OsStr::new("fail"),
            OsStr::new("--failure-summary"),
            OsStr::new("synthetic failure"),
            OsStr::new("--environment"),
            OsStr::new("ci"),
            OsStr::new("--implementation-state"),
            OsStr::new("implemented"),
            OsStr::new("--source-artifact"),
            source_file.as_os_str(),
            OsStr::new("--client-host"),
            OsStr::new("client@example"),
            OsStr::new("--exit-host"),
            OsStr::new("exit@example"),
            OsStr::new("--client-network-id"),
            OsStr::new("net-a"),
            OsStr::new("--exit-network-id"),
            OsStr::new("net-b"),
            OsStr::new("--nat-profile"),
            OsStr::new("baseline_lan"),
            OsStr::new("--impairment-profile"),
            OsStr::new("none"),
            OsStr::new("--check"),
            OsStr::new("direct_remote_exit_success=fail"),
            OsStr::new("--check"),
            OsStr::new("remote_exit_no_underlay_leak=pass"),
            OsStr::new("--check"),
            OsStr::new("remote_exit_server_ip_bypass_is_narrow=pass"),
        ],
        true,
    )?;

    expect_cargo_failure(
        &[
            OsStr::new("ops"),
            OsStr::new("validate-cross-network-remote-exit-reports"),
            OsStr::new("--reports"),
            valid_fail_report.as_os_str(),
            OsStr::new("--expected-git-commit"),
            OsStr::new(&current_commit),
            OsStr::new("--require-pass-status"),
        ],
        "expected require-pass-status to reject failing report",
    )?;

    println!("Cross-network remote-exit report schema tests: PASS");
    Ok(())
}

fn generate_pass_report(
    suite: &str,
    temp_dir: &Path,
    source_file: &Path,
    log_file: &Path,
) -> Result<PathBuf, String> {
    let report_path = temp_dir.join(format!("{suite}_report.json"));
    let mut args: Vec<&OsStr> = vec![
        OsStr::new("ops"),
        OsStr::new("generate-cross-network-remote-exit-report"),
        OsStr::new("--suite"),
        OsStr::new(suite),
        OsStr::new("--report-path"),
        report_path.as_os_str(),
        OsStr::new("--log-path"),
        log_file.as_os_str(),
        OsStr::new("--status"),
        OsStr::new("pass"),
        OsStr::new("--environment"),
        OsStr::new("ci"),
        OsStr::new("--implementation-state"),
        OsStr::new("implemented"),
        OsStr::new("--source-artifact"),
        source_file.as_os_str(),
        OsStr::new("--client-host"),
        OsStr::new("client@example"),
        OsStr::new("--exit-host"),
        OsStr::new("exit@example"),
        OsStr::new("--client-network-id"),
        OsStr::new("net-a"),
        OsStr::new("--exit-network-id"),
        OsStr::new("net-b"),
        OsStr::new("--nat-profile"),
        OsStr::new("baseline_lan"),
        OsStr::new("--impairment-profile"),
        OsStr::new("none"),
    ];

    match suite {
        "cross_network_direct_remote_exit" => {
            args.extend([
                OsStr::new("--check"),
                OsStr::new("direct_remote_exit_success=pass"),
                OsStr::new("--check"),
                OsStr::new("remote_exit_no_underlay_leak=pass"),
                OsStr::new("--check"),
                OsStr::new("remote_exit_server_ip_bypass_is_narrow=pass"),
            ]);
        }
        "cross_network_relay_remote_exit" => {
            args.extend([
                OsStr::new("--relay-host"),
                OsStr::new("relay@example"),
                OsStr::new("--relay-network-id"),
                OsStr::new("net-c"),
                OsStr::new("--check"),
                OsStr::new("relay_remote_exit_success=pass"),
                OsStr::new("--check"),
                OsStr::new("remote_exit_no_underlay_leak=pass"),
                OsStr::new("--check"),
                OsStr::new("remote_exit_server_ip_bypass_is_narrow=pass"),
            ]);
        }
        "cross_network_failback_roaming" => {
            args.extend([
                OsStr::new("--relay-host"),
                OsStr::new("relay@example"),
                OsStr::new("--relay-network-id"),
                OsStr::new("net-c"),
                OsStr::new("--check"),
                OsStr::new("relay_to_direct_failback_success=pass"),
                OsStr::new("--check"),
                OsStr::new("endpoint_roam_recovery_success=pass"),
                OsStr::new("--check"),
                OsStr::new("remote_exit_no_underlay_leak=pass"),
            ]);
        }
        "cross_network_traversal_adversarial" => {
            args.extend([
                OsStr::new("--probe-host"),
                OsStr::new("probe@example"),
                OsStr::new("--check"),
                OsStr::new("forged_traversal_rejected=pass"),
                OsStr::new("--check"),
                OsStr::new("stale_traversal_rejected=pass"),
                OsStr::new("--check"),
                OsStr::new("replayed_traversal_rejected=pass"),
                OsStr::new("--check"),
                OsStr::new("rogue_endpoint_rejected=pass"),
                OsStr::new("--check"),
                OsStr::new("control_surface_exposure_blocked=pass"),
            ]);
        }
        "cross_network_remote_exit_dns" => {
            args.extend([
                OsStr::new("--check"),
                OsStr::new("managed_dns_resolution_success=pass"),
                OsStr::new("--check"),
                OsStr::new("remote_exit_dns_fail_closed=pass"),
                OsStr::new("--check"),
                OsStr::new("remote_exit_no_underlay_leak=pass"),
            ]);
        }
        "cross_network_remote_exit_soak" => {
            args.extend([
                OsStr::new("--check"),
                OsStr::new("long_soak_stable=pass"),
                OsStr::new("--check"),
                OsStr::new("remote_exit_no_underlay_leak=pass"),
                OsStr::new("--check"),
                OsStr::new("remote_exit_server_ip_bypass_is_narrow=pass"),
                OsStr::new("--check"),
                OsStr::new("cross_network_topology_heuristic=pass"),
                OsStr::new("--check"),
                OsStr::new("direct_remote_exit_ready=pass"),
                OsStr::new("--check"),
                OsStr::new("post_soak_bypass_ready=pass"),
                OsStr::new("--check"),
                OsStr::new("no_plaintext_passphrase_files=pass"),
            ]);
        }
        other => {
            return Err(format!(
                "unsupported suite in test fixture generator: {other}"
            ));
        }
    }

    run_cargo_ops(&args, true)?;
    Ok(report_path)
}

fn run_cargo_ops(args: &[&OsStr], suppress_stdout: bool) -> Result<(), String> {
    let mut command = Command::new("cargo");
    command.args([
        "run",
        "--quiet",
        "-p",
        "rustynet-cli",
        "--bin",
        "rustynet-cli",
        "--",
    ]);
    command.args(args);
    if suppress_stdout {
        command.stdout(Stdio::null());
    }
    let status = command
        .status()
        .map_err(|err| format!("failed to run cargo: {err}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("cargo run failed with status {status}"))
    }
}

fn expect_cargo_failure(args: &[&OsStr], message: &str) -> Result<(), String> {
    if run_cargo_ops(args, false).is_ok() {
        return Err(message.to_string());
    }
    Ok(())
}

fn write_fixture(path: &Path, body: &str) -> Result<(), String> {
    fs::write(path, body).map_err(|err| format!("write fixture failed ({}): {err}", path.display()))
}

fn create_symlink(source: &Path, link: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(source, link).map_err(|err| {
            format!(
                "create symlink failed ({} -> {}): {err}",
                link.display(),
                source.display()
            )
        })
    }

    #[cfg(not(unix))]
    {
        let _ = source;
        let _ = link;
        Err("symlink creation is only supported on unix".to_string())
    }
}

fn git_rev_parse_head() -> Result<String, String> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|err| format!("failed to run git rev-parse HEAD: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "git rev-parse HEAD failed with status {}",
            output.status
        ));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_string())
        .map_err(|err| format!("git rev-parse HEAD produced invalid utf-8: {err}"))
}

fn unix_now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|err| format!("system clock is before UNIX_EPOCH: {err}"))
}

fn json_string(value: &Path) -> String {
    json_escape(&value.display().to_string())
}

fn json_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 8);
    escaped.push('"');
    for ch in value.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\u{08}' => escaped.push_str("\\b"),
            '\u{0C}' => escaped.push_str("\\f"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            ch if ch < '\u{20}' => {
                let _ = write!(escaped, "\\u{:04x}", ch as u32);
            }
            ch => escaped.push(ch),
        }
    }
    escaped.push('"');
    escaped
}

fn invalid_same_network_fixture(
    captured_at_unix: u64,
    current_commit: &str,
    source_file: &Path,
    log_file: &Path,
) -> String {
    format!(
        concat!(
            "{{\n",
            "  \"schema_version\": 1,\n",
            "  \"phase\": \"phase10\",\n",
            "  \"suite\": \"cross_network_direct_remote_exit\",\n",
            "  \"environment\": \"ci\",\n",
            "  \"evidence_mode\": \"measured\",\n",
            "  \"captured_at_unix\": {captured_at_unix},\n",
            "  \"git_commit\": {git_commit},\n",
            "  \"status\": \"pass\",\n",
            "  \"participants\": {{\n",
            "    \"client_host\": \"client@example\",\n",
            "    \"exit_host\": \"exit@example\"\n",
            "  }},\n",
            "  \"network_context\": {{\n",
            "    \"client_network_id\": \"net-a\",\n",
            "    \"exit_network_id\": \"net-a\",\n",
            "    \"nat_profile\": \"baseline_lan\",\n",
            "    \"impairment_profile\": \"none\"\n",
            "  }},\n",
            "  \"checks\": {{\n",
            "    \"direct_remote_exit_success\": \"pass\",\n",
            "    \"remote_exit_no_underlay_leak\": \"pass\",\n",
            "    \"remote_exit_server_ip_bypass_is_narrow\": \"pass\"\n",
            "  }},\n",
            "  \"source_artifacts\": [\n",
            "    {source_file}\n",
            "  ],\n",
            "  \"log_artifacts\": [\n",
            "    {log_file}\n",
            "  ]\n",
            "}}\n"
        ),
        captured_at_unix = captured_at_unix,
        git_commit = json_escape(current_commit),
        source_file = json_string(source_file),
        log_file = json_string(log_file),
    )
}

fn invalid_pass_with_failed_check_fixture(
    captured_at_unix: u64,
    current_commit: &str,
    source_file: &Path,
    log_file: &Path,
) -> String {
    format!(
        concat!(
            "{{\n",
            "  \"schema_version\": 1,\n",
            "  \"phase\": \"phase10\",\n",
            "  \"suite\": \"cross_network_relay_remote_exit\",\n",
            "  \"environment\": \"ci\",\n",
            "  \"evidence_mode\": \"measured\",\n",
            "  \"captured_at_unix\": {captured_at_unix},\n",
            "  \"git_commit\": {git_commit},\n",
            "  \"status\": \"pass\",\n",
            "  \"participants\": {{\n",
            "    \"client_host\": \"client@example\",\n",
            "    \"exit_host\": \"exit@example\",\n",
            "    \"relay_host\": \"relay@example\"\n",
            "  }},\n",
            "  \"network_context\": {{\n",
            "    \"client_network_id\": \"net-a\",\n",
            "    \"exit_network_id\": \"net-b\",\n",
            "    \"relay_network_id\": \"net-c\",\n",
            "    \"nat_profile\": \"baseline_lan\",\n",
            "    \"impairment_profile\": \"none\"\n",
            "  }},\n",
            "  \"checks\": {{\n",
            "    \"relay_remote_exit_success\": \"fail\",\n",
            "    \"remote_exit_no_underlay_leak\": \"pass\",\n",
            "    \"remote_exit_server_ip_bypass_is_narrow\": \"pass\"\n",
            "  }},\n",
            "  \"source_artifacts\": [\n",
            "    {source_file}\n",
            "  ],\n",
            "  \"log_artifacts\": [\n",
            "    {log_file}\n",
            "  ]\n",
            "}}\n"
        ),
        captured_at_unix = captured_at_unix,
        git_commit = json_escape(current_commit),
        source_file = json_string(source_file),
        log_file = json_string(log_file),
    )
}

fn invalid_fail_without_summary_fixture(
    captured_at_unix: u64,
    current_commit: &str,
    source_file: &Path,
    log_file: &Path,
) -> String {
    format!(
        concat!(
            "{{\n",
            "  \"schema_version\": 1,\n",
            "  \"phase\": \"phase10\",\n",
            "  \"suite\": \"cross_network_traversal_adversarial\",\n",
            "  \"environment\": \"ci\",\n",
            "  \"evidence_mode\": \"measured\",\n",
            "  \"captured_at_unix\": {captured_at_unix},\n",
            "  \"git_commit\": {git_commit},\n",
            "  \"status\": \"fail\",\n",
            "  \"participants\": {{\n",
            "    \"client_host\": \"client@example\",\n",
            "    \"exit_host\": \"exit@example\",\n",
            "    \"probe_host\": \"probe@example\"\n",
            "  }},\n",
            "  \"network_context\": {{\n",
            "    \"client_network_id\": \"net-a\",\n",
            "    \"exit_network_id\": \"net-b\",\n",
            "    \"nat_profile\": \"baseline_lan\",\n",
            "    \"impairment_profile\": \"none\"\n",
            "  }},\n",
            "  \"checks\": {{\n",
            "    \"forged_traversal_rejected\": \"fail\",\n",
            "    \"stale_traversal_rejected\": \"pass\",\n",
            "    \"replayed_traversal_rejected\": \"pass\",\n",
            "    \"rogue_endpoint_rejected\": \"pass\",\n",
            "    \"control_surface_exposure_blocked\": \"pass\"\n",
            "  }},\n",
            "  \"source_artifacts\": [\n",
            "    {source_file}\n",
            "  ],\n",
            "  \"log_artifacts\": [\n",
            "    {log_file}\n",
            "  ]\n",
            "}}\n"
        ),
        captured_at_unix = captured_at_unix,
        git_commit = json_escape(current_commit),
        source_file = json_string(source_file),
        log_file = json_string(log_file),
    )
}

fn invalid_symlink_artifact_fixture(
    captured_at_unix: u64,
    current_commit: &str,
    symlink_source: &Path,
    log_file: &Path,
) -> String {
    format!(
        concat!(
            "{{\n",
            "  \"schema_version\": 1,\n",
            "  \"phase\": \"phase10\",\n",
            "  \"suite\": \"cross_network_direct_remote_exit\",\n",
            "  \"environment\": \"ci\",\n",
            "  \"evidence_mode\": \"measured\",\n",
            "  \"captured_at_unix\": {captured_at_unix},\n",
            "  \"git_commit\": {git_commit},\n",
            "  \"status\": \"pass\",\n",
            "  \"participants\": {{\n",
            "    \"client_host\": \"client@example\",\n",
            "    \"exit_host\": \"exit@example\"\n",
            "  }},\n",
            "  \"network_context\": {{\n",
            "    \"client_network_id\": \"net-a\",\n",
            "    \"exit_network_id\": \"net-b\",\n",
            "    \"nat_profile\": \"baseline_lan\",\n",
            "    \"impairment_profile\": \"none\"\n",
            "  }},\n",
            "  \"checks\": {{\n",
            "    \"direct_remote_exit_success\": \"pass\",\n",
            "    \"remote_exit_no_underlay_leak\": \"pass\",\n",
            "    \"remote_exit_server_ip_bypass_is_narrow\": \"pass\"\n",
            "  }},\n",
            "  \"source_artifacts\": [\n",
            "    {symlink_source}\n",
            "  ],\n",
            "  \"log_artifacts\": [\n",
            "    {log_file}\n",
            "  ]\n",
            "}}\n"
        ),
        captured_at_unix = captured_at_unix,
        git_commit = json_escape(current_commit),
        symlink_source = json_string(symlink_source),
        log_file = json_string(log_file),
    )
}

fn invalid_outside_artifact_fixture(
    captured_at_unix: u64,
    current_commit: &str,
    log_file: &Path,
) -> String {
    format!(
        concat!(
            "{{\n",
            "  \"schema_version\": 1,\n",
            "  \"phase\": \"phase10\",\n",
            "  \"suite\": \"cross_network_direct_remote_exit\",\n",
            "  \"environment\": \"ci\",\n",
            "  \"evidence_mode\": \"measured\",\n",
            "  \"captured_at_unix\": {captured_at_unix},\n",
            "  \"git_commit\": {git_commit},\n",
            "  \"status\": \"pass\",\n",
            "  \"participants\": {{\n",
            "    \"client_host\": \"client@example\",\n",
            "    \"exit_host\": \"exit@example\"\n",
            "  }},\n",
            "  \"network_context\": {{\n",
            "    \"client_network_id\": \"net-a\",\n",
            "    \"exit_network_id\": \"net-b\",\n",
            "    \"nat_profile\": \"baseline_lan\",\n",
            "    \"impairment_profile\": \"none\"\n",
            "  }},\n",
            "  \"checks\": {{\n",
            "    \"direct_remote_exit_success\": \"pass\",\n",
            "    \"remote_exit_no_underlay_leak\": \"pass\",\n",
            "    \"remote_exit_server_ip_bypass_is_narrow\": \"pass\"\n",
            "  }},\n",
            "  \"source_artifacts\": [\n",
            "    \"/etc/hosts\"\n",
            "  ],\n",
            "  \"log_artifacts\": [\n",
            "    {log_file}\n",
            "  ]\n",
            "}}\n"
        ),
        captured_at_unix = captured_at_unix,
        git_commit = json_escape(current_commit),
        log_file = json_string(log_file),
    )
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn create() -> Result<Self, String> {
        let base = env::temp_dir();
        let pid = std::process::id();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| format!("system clock is before UNIX_EPOCH: {err}"))?
            .as_nanos();

        for attempt in 0..1_000u64 {
            let path = base.join(format!(
                "rustynet-test-validate-cross-network-remote-exit-reports-{pid}-{now}-{attempt}"
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => {
                    return Err(format!(
                        "create temp directory failed ({}): {err}",
                        path.display()
                    ));
                }
            }
        }

        Err("failed to allocate unique temporary directory".to_string())
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
