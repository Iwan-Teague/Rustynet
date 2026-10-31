#![allow(dead_code)]
//! Cross-OS exit DNS fail-closed validation for the standard orchestrator.
//!
//! Detects the node's default egress interface, dispatches
//! `rustynetd linux-exit-dns-failclosed-capture` over the hardened
//! [`RemoteShellHost`] seam to produce six artifacts, pulls them back
//! locally, and evaluates them with the same directory-based evaluator
//! the bash live-suite uses — `evaluate_linux_exit_dns_failclosed_artifact_dir`
//! in `vm_lab` — which fails closed on missing artifacts, non-empty
//! block pcaps, vacuous probes, or leaked DNS responses.

use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::remote_shell::RemoteShellHost;
use crate::vm_lab::orchestrator::role_validation::discover_single_generated_nft_table;
use std::path::{Path, PathBuf};

/// Directory (under the run's report dir) that receives the pulled artifacts of
/// every exit-DNS fail-closed capture that failed or showed port-53 egress.
pub const EVIDENCE_SUBDIR: &str = "logs/exit_dns_failclosed_artifacts";

/// Informational artifact written by newer `rustynetd` builds: conntrack / ss /
/// resolvectl snapshots around each capture window. It is NEVER evaluated and its
/// absence (an older daemon binary) is not a failure; it exists so a failing
/// capture can be attributed to a process, destination and resolver state.
const OPTIONAL_CONTEXT_ARTIFACT: &str = "dns_block_context.txt";

const REQUIRED_ARTIFACTS: &[&str] = &[
    "firewall_block_rules.json",
    "udp_block_pcap.txt",
    "tcp_block_pcap.txt",
    "dns_block_probe.json",
    "tunnel_path_resolves.json",
    "linux_dns_failclosed_check.json",
];

pub fn exit_dns_failclosed_runtime_implemented(platform: VmGuestPlatform) -> bool {
    matches!(platform, VmGuestPlatform::Linux)
}

fn detect_linux_egress_interface(shell: &dyn RemoteShellHost) -> Result<String, String> {
    let out = shell
        .run_argv(&["ip", "route", "show", "default"], &[], &[])
        .map_err(|err| format!("failed to query default route for egress interface: {err}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if let Some(pos) = parts.iter().position(|p| *p == "dev")
            && let Some(iface) = parts.get(pos + 1)
        {
            return Ok(iface.to_string());
        }
    }
    Err("default egress interface not found in `ip route show default` output".to_owned())
}

/// Reduce an alias to a single safe path component.
fn evidence_component(alias: &str) -> String {
    let cleaned: String = alias
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() || cleaned.chars().all(|c| c == '.') {
        "unnamed".to_owned()
    } else {
        cleaned
    }
}

/// Copy every regular file of `local` into a FRESH per-attempt directory
/// `<base>/<component>/attempt-NNN` and return its path, or `None` when there was
/// nothing to copy (nothing is created then). `create_dir` fails on an existing
/// directory, so a re-run, a retry, or two aliases that sanitise to the same
/// component can never overwrite or mix with an earlier capture.
fn retain_artifacts(local: &Path, base: &Path, component: &str) -> Result<Option<PathBuf>, String> {
    let mut files = Vec::new();
    let entries = std::fs::read_dir(local)
        .map_err(|err| format!("read {} failed: {err}", local.display()))?;
    for entry in entries {
        let entry = entry.map_err(|err| format!("read dir entry failed: {err}"))?;
        if entry.path().is_file() {
            files.push(entry);
        }
    }
    if files.is_empty() {
        return Ok(None);
    }
    let parent = base.join(component);
    std::fs::create_dir_all(&parent)
        .map_err(|err| format!("create {} failed: {err}", parent.display()))?;
    let mut dest = None;
    for attempt in 1..=999u32 {
        let candidate = parent.join(format!("attempt-{attempt:03}"));
        match std::fs::create_dir(&candidate) {
            Ok(()) => {
                dest = Some(candidate);
                break;
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(format!("create {} failed: {err}", candidate.display())),
        }
    }
    let dest =
        dest.ok_or_else(|| format!("no free attempt-NNN slot under {}", parent.display()))?;
    for entry in files {
        std::fs::copy(entry.path(), dest.join(entry.file_name()))
            .map_err(|err| format!("copy {} failed: {err}", entry.path().display()))?;
    }
    Ok(Some(dest))
}

/// Exit-DNS fail-closed validation for one Linux exit.
///
/// `evidence_base` is `<report_dir>/` [`EVIDENCE_SUBDIR`]. EVERY run (pass or
/// fail) keeps its pulled artifacts (above all `tcp_block_pcap.txt` and
/// `dns_block_context.txt`) in a fresh `<evidence_base>/<alias>/attempt-NNN/`: a
/// flaky pass next to a fail is as useful as the fail, and the evaluator's own
/// "empty" rule (which accepts tcpdump banner lines) is deliberately not
/// re-implemented as a retention trigger. This only RETAINS evidence: the verdict
/// is exactly what [`evaluate_linux_exit_dns_failclosed_artifact_dir`] returns.
pub fn validate_linux_exit_dns_failclosed(
    shell: &dyn RemoteShellHost,
    daemon_path: &str,
    alias: &str,
    mesh_hostname: &str,
    evidence_base: &Path,
) -> Result<(), String> {
    // Held for the whole function so the pulled artifacts outlive the verdict
    // (the old code leaked this directory with `into_path()`).
    let local_tmp =
        tempfile::tempdir().map_err(|err| format!("failed to create local temp dir: {err}"))?;
    let result =
        capture_pull_and_evaluate(shell, daemon_path, alias, mesh_hostname, local_tmp.path());
    let retained = retain_artifacts(local_tmp.path(), evidence_base, &evidence_component(alias));
    match (result, retained) {
        // Retention NEVER changes a verdict; it only annotates a failure.
        (Err(e), Ok(Some(dest))) => Err(format!("{e} (artifacts retained in {})", dest.display())),
        (Err(e), Err(copy_err)) => Err(format!("{e} (evidence retention failed: {copy_err})")),
        (Err(e), Ok(None)) => Err(e),
        (Ok(()), Err(copy_err)) => {
            eprintln!("{alias}: exit DNS evidence retention failed: {copy_err}");
            Ok(())
        }
        (Ok(()), Ok(_)) => Ok(()),
    }
}

fn capture_pull_and_evaluate(
    shell: &dyn RemoteShellHost,
    daemon_path: &str,
    alias: &str,
    mesh_hostname: &str,
    local_tmp: &Path,
) -> Result<(), String> {
    let egress_iface = detect_linux_egress_interface(shell)?;
    let killswitch_table =
        discover_single_generated_nft_table(shell, "inet", "rustynet_g", "active killswitch")?;

    let remote_tmp_out = shell
        .run_argv(&["mktemp", "-d"], &[], &[])
        .map_err(|err| format!("failed to create remote temp dir: {err}"))?;
    let remote_tmp = String::from_utf8_lossy(&remote_tmp_out.stdout)
        .trim()
        .to_string();
    if remote_tmp.is_empty() {
        return Err("mktemp -d produced empty output".to_owned());
    }
    let remote_tmp_path = PathBuf::from(&remote_tmp);

    let cleanup = || {
        let _ = shell.run_argv(&["sudo", "-n", "rm", "-rf", &remote_tmp], &[], &[]);
    };

    let capture_argv: [&str; 12] = [
        "sudo",
        "-n",
        daemon_path,
        "linux-exit-dns-failclosed-capture",
        "--output",
        &remote_tmp,
        "--lan-iface",
        &egress_iface,
        "--mesh-hostname",
        mesh_hostname,
        "--killswitch-table",
        &killswitch_table,
    ];
    let capture_out = shell.run_argv(&capture_argv, &[], &[]).map_err(|e| {
        cleanup();
        format!("dispatch of linux-exit-dns-failclosed-capture failed: {e}")
    })?;
    if capture_out.code != 0 {
        let stdout = String::from_utf8_lossy(&capture_out.stdout);
        let stderr = String::from_utf8_lossy(&capture_out.stderr);
        cleanup();
        return Err(format!(
            "linux-exit-dns-failclosed-capture exited {}: {} {}",
            capture_out.code,
            stdout.trim(),
            stderr.trim()
        ));
    }

    for artifact in REQUIRED_ARTIFACTS {
        let remote_path = remote_tmp_path.join(artifact);
        let cat_argv: [&str; 4] = [
            "sudo",
            "-n",
            "cat",
            remote_path.to_str().unwrap_or(artifact),
        ];
        match shell.run_argv(&cat_argv, &[], &[]) {
            Ok(out) => {
                if out.code != 0 {
                    cleanup();
                    return Err(format!(
                        "failed to pull {artifact} from remote: cat exited {}",
                        out.code
                    ));
                }
                let local_path = local_tmp.join(artifact);
                std::fs::write(&local_path, &out.stdout).map_err(|err| {
                    cleanup();
                    format!("write local {artifact} failed: {err}")
                })?;
            }
            Err(e) => {
                cleanup();
                return Err(format!("failed to pull {artifact} from remote: {e}"));
            }
        }
    }

    // Informational context (never evaluated, never required): best effort, an
    // older daemon binary simply has no such file.
    let context_remote = remote_tmp_path.join(OPTIONAL_CONTEXT_ARTIFACT);
    if let Some(context_remote) = context_remote.to_str()
        && let Ok(out) = shell.run_argv(&["sudo", "-n", "cat", context_remote], &[], &[])
        && out.code == 0
    {
        let _ = std::fs::write(local_tmp.join(OPTIONAL_CONTEXT_ARTIFACT), &out.stdout);
    }

    cleanup();

    crate::vm_lab::evaluate_linux_exit_dns_failclosed_artifact_dir(alias, local_tmp).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use tempfile::tempdir;

    #[test]
    fn runtime_implemented_linux_only() {
        assert!(exit_dns_failclosed_runtime_implemented(
            VmGuestPlatform::Linux
        ));
        assert!(!exit_dns_failclosed_runtime_implemented(
            VmGuestPlatform::Macos
        ));
        assert!(!exit_dns_failclosed_runtime_implemented(
            VmGuestPlatform::Windows
        ));
    }

    use crate::vm_lab::orchestrator::remote_shell::{MockShellHost, RemoteExitStatus};

    const TEST_DAEMON: &str = "/usr/local/bin/rustynetd";
    const TEST_MESH_HOSTNAME: &str = "exit-1.rustynet";

    fn exit_ok(stdout: &str) -> RemoteExitStatus {
        RemoteExitStatus {
            code: 0,
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        }
    }

    fn program_killswitch_discovery(mock: &MockShellHost) {
        mock.program_run_response(
            &["sudo", "-n", "nft", "list", "tables"],
            exit_ok("table inet rustynet_g7\ntable inet rustynet_g7_dns\n"),
        );
    }

    fn write_reviewed_linux_exit_dns_artifacts(dir: &Path) {
        std::fs::create_dir_all(dir).expect("mkdir");
        std::fs::write(
            dir.join("firewall_block_rules.json"),
            r#"{
                "schema_version": 1,
                "overall_ok": true,
                "rules": [
                    {"name": "rustynet-dns-block-lan-udp", "action": "drop", "direction": "out", "enabled": "true"},
                    {"name": "rustynet-dns-block-lan-tcp", "action": "drop", "direction": "out", "enabled": "true"}
                ]
            }"#,
        )
        .expect("write firewall_block_rules");
        std::fs::write(dir.join("udp_block_pcap.txt"), "0 packets captured\n")
            .expect("write udp pcap");
        std::fs::write(dir.join("tcp_block_pcap.txt"), "").expect("write tcp pcap");
        std::fs::write(
            dir.join("dns_block_probe.json"),
            r#"{
                "schema_version": 1,
                "overall_ok": true,
                "probe_attempted": true,
                "probe_target": "192.168.1.1",
                "probe_query": "rustynet-dns-leak-probe.invalid",
                "udp_response_received": false,
                "tcp_response_received": false,
                "reason": "off-tunnel DNS probe received no UDP or TCP response"
            }"#,
        )
        .expect("write dns_block_probe");
        std::fs::write(
            dir.join("tunnel_path_resolves.json"),
            r#"{
                "schema_version": 1,
                "overall_ok": true,
                "resolved": true,
                "hostname": "exit-1.rustynet",
                "addresses": ["100.64.0.1"],
                "reason": "resolved through platform resolver"
            }"#,
        )
        .expect("write tunnel_path_resolves");
        std::fs::write(
            dir.join("linux_dns_failclosed_check.json"),
            r#"{
                "schema_version": 1,
                "overall_ok": true,
                "snapshot": {
                    "resolv_conf_path": "/etc/resolv.conf",
                    "resolv_conf_present": true,
                    "nameservers": ["127.0.0.53"],
                    "search_domains": [],
                    "loopback_resolver_advertised": true
                },
                "drift_reasons": []
            }"#,
        )
        .expect("write dns check");
    }

    #[test]
    fn validate_fails_closed_on_dispatch_error() {
        let mock = MockShellHost::new();
        let evidence = tempdir().expect("evidence tempdir");
        mock.program_run_response(
            &["ip", "route", "show", "default"],
            exit_ok("default via 192.168.1.1 dev enp0s1"),
        );
        program_killswitch_discovery(&mock);
        let err = validate_linux_exit_dns_failclosed(
            &mock,
            TEST_DAEMON,
            "deb-1",
            TEST_MESH_HOSTNAME,
            evidence.path(),
        )
        .expect_err("dispatch error must fail the stage");
        assert!(
            err.contains("mktemp"),
            "expected mktemp failure, got: {err}"
        );
    }

    #[test]
    fn validate_fails_closed_on_egress_detection_failure() {
        let mock = MockShellHost::new();
        let evidence = tempdir().expect("evidence tempdir");
        mock.program_run_response(&["ip", "route", "show", "default"], exit_ok(""));
        let err = validate_linux_exit_dns_failclosed(
            &mock,
            TEST_DAEMON,
            "deb-1",
            TEST_MESH_HOSTNAME,
            evidence.path(),
        )
        .expect_err("egress detection failure must fail the stage");
        assert!(
            err.contains("egress"),
            "expected egress detection error, got: {err}"
        );
    }

    #[test]
    fn validate_accepts_reviewed_artifacts() {
        let mock = MockShellHost::new();
        let evidence = tempdir().expect("evidence tempdir");
        let reviewed_dir = tempdir().expect("tempdir");
        write_reviewed_linux_exit_dns_artifacts(reviewed_dir.path());

        // egress detection
        mock.program_run_response(
            &["ip", "route", "show", "default"],
            exit_ok("default via 192.168.1.1 dev enp0s1\n"),
        );
        program_killswitch_discovery(&mock);
        // mktemp -d
        mock.program_run_response(&["mktemp", "-d"], exit_ok("/tmp/tmp.testdir\n"));
        // capture subcommand (after egress, remote dir)
        let capture_argv: [&str; 12] = [
            "sudo",
            "-n",
            TEST_DAEMON,
            "linux-exit-dns-failclosed-capture",
            "--output",
            "/tmp/tmp.testdir",
            "--lan-iface",
            "enp0s1",
            "--mesh-hostname",
            TEST_MESH_HOSTNAME,
            "--killswitch-table",
            "rustynet_g7",
        ];
        mock.program_run_response(&capture_argv, exit_ok(""));

        // cat each artifact
        for artifact in REQUIRED_ARTIFACTS {
            let cat_path = format!("/tmp/tmp.testdir/{artifact}");
            let cat_argv: [&str; 4] = ["sudo", "-n", "cat", &cat_path];
            let content =
                std::fs::read_to_string(reviewed_dir.path().join(artifact)).expect("read artifact");
            mock.program_run_response(&cat_argv, exit_ok(&content));
        }

        validate_linux_exit_dns_failclosed(
            &mock,
            TEST_DAEMON,
            "deb-1",
            TEST_MESH_HOSTNAME,
            evidence.path(),
        )
        .expect("reviewed artifacts must pass");
        assert!(
            evidence
                .path()
                .join("deb-1/attempt-001/tcp_block_pcap.txt")
                .is_file(),
            "a pass keeps its artifacts too (flaky pass next to a fail is evidence)"
        );
    }

    #[test]
    fn validate_fails_closed_on_missing_artifact() {
        let mock = MockShellHost::new();
        let evidence = tempdir().expect("evidence tempdir");
        let reviewed_dir = tempdir().expect("tempdir");
        write_reviewed_linux_exit_dns_artifacts(reviewed_dir.path());

        mock.program_run_response(
            &["ip", "route", "show", "default"],
            exit_ok("default via 192.168.1.1 dev enp0s1\n"),
        );
        program_killswitch_discovery(&mock);
        mock.program_run_response(&["mktemp", "-d"], exit_ok("/tmp/tmp.testdir\n"));
        let capture_argv: [&str; 12] = [
            "sudo",
            "-n",
            TEST_DAEMON,
            "linux-exit-dns-failclosed-capture",
            "--output",
            "/tmp/tmp.testdir",
            "--lan-iface",
            "enp0s1",
            "--mesh-hostname",
            TEST_MESH_HOSTNAME,
            "--killswitch-table",
            "rustynet_g7",
        ];
        mock.program_run_response(&capture_argv, exit_ok(""));

        for artifact in REQUIRED_ARTIFACTS {
            let cat_path = format!("/tmp/tmp.testdir/{artifact}");
            let cat_argv: [&str; 4] = ["sudo", "-n", "cat", &cat_path];
            if artifact == &"tunnel_path_resolves.json" {
                // omit response — un-programmed argv fails with Transport error
            } else {
                let content = std::fs::read_to_string(reviewed_dir.path().join(artifact))
                    .expect("read artifact");
                mock.program_run_response(&cat_argv, exit_ok(&content));
            }
        }

        let err = validate_linux_exit_dns_failclosed(
            &mock,
            TEST_DAEMON,
            "deb-1",
            TEST_MESH_HOSTNAME,
            evidence.path(),
        )
        .expect_err("missing artifact must fail the stage");
        assert!(
            err.contains("tunnel_path_resolves.json"),
            "expected missing tunnel_path_resolves error, got: {err}"
        );
    }

    #[test]
    fn validate_fails_closed_on_nonempty_udp_pcap() {
        let mock = MockShellHost::new();
        let evidence = tempdir().expect("evidence tempdir");
        let reviewed_dir = tempdir().expect("tempdir");
        write_reviewed_linux_exit_dns_artifacts(reviewed_dir.path());

        mock.program_run_response(
            &["ip", "route", "show", "default"],
            exit_ok("default via 192.168.1.1 dev enp0s1\n"),
        );
        program_killswitch_discovery(&mock);
        mock.program_run_response(&["mktemp", "-d"], exit_ok("/tmp/tmp.testdir\n"));
        let capture_argv: [&str; 12] = [
            "sudo",
            "-n",
            TEST_DAEMON,
            "linux-exit-dns-failclosed-capture",
            "--output",
            "/tmp/tmp.testdir",
            "--lan-iface",
            "enp0s1",
            "--mesh-hostname",
            TEST_MESH_HOSTNAME,
            "--killswitch-table",
            "rustynet_g7",
        ];
        mock.program_run_response(&capture_argv, exit_ok(""));

        for artifact in REQUIRED_ARTIFACTS {
            let cat_path = format!("/tmp/tmp.testdir/{artifact}");
            let cat_argv: [&str; 4] = ["sudo", "-n", "cat", &cat_path];
            if artifact == &"udp_block_pcap.txt" {
                mock.program_run_response(&cat_argv, exit_ok("12:34:56 UDP leaked\n"));
            } else {
                let content = std::fs::read_to_string(reviewed_dir.path().join(artifact))
                    .expect("read artifact");
                mock.program_run_response(&cat_argv, exit_ok(&content));
            }
        }

        let err = validate_linux_exit_dns_failclosed(
            &mock,
            TEST_DAEMON,
            "deb-1",
            TEST_MESH_HOSTNAME,
            evidence.path(),
        )
        .expect_err("nonempty pcap must fail the stage");
        assert!(
            err.contains("pcap") || err.contains("UDP"),
            "expected nonempty pcap error, got: {err}"
        );
    }

    const LEAKED_TCP_LINE: &str = "12:00:00 IP 10.0.0.2.40000 > 1.1.1.1.53: Flags [S], seq 1\n";
    const CONTEXT_BODY: &str = "=== before tcp window ===\n--- conntrack tcp/53 ---\nipv4 tcp ESTABLISHED src=10.0.0.2 dst=1.1.1.1 dport=53\n";

    /// Program a full capture whose `tcp_block_pcap.txt` is `tcp_pcap` and
    /// (optionally) whose daemon also produced `dns_block_context.txt`.
    fn program_capture(mock: &MockShellHost, tcp_pcap: &str, context: Option<&str>) {
        let reviewed_dir = tempdir().expect("tempdir");
        write_reviewed_linux_exit_dns_artifacts(reviewed_dir.path());
        mock.program_run_response(
            &["ip", "route", "show", "default"],
            exit_ok("default via 192.168.1.1 dev enp0s1\n"),
        );
        program_killswitch_discovery(mock);
        mock.program_run_response(&["mktemp", "-d"], exit_ok("/tmp/tmp.testdir\n"));
        let capture_argv: [&str; 12] = [
            "sudo",
            "-n",
            TEST_DAEMON,
            "linux-exit-dns-failclosed-capture",
            "--output",
            "/tmp/tmp.testdir",
            "--lan-iface",
            "enp0s1",
            "--mesh-hostname",
            TEST_MESH_HOSTNAME,
            "--killswitch-table",
            "rustynet_g7",
        ];
        mock.program_run_response(&capture_argv, exit_ok(""));
        for artifact in REQUIRED_ARTIFACTS {
            let cat_path = format!("/tmp/tmp.testdir/{artifact}");
            let cat_argv: [&str; 4] = ["sudo", "-n", "cat", &cat_path];
            if artifact == &"tcp_block_pcap.txt" {
                mock.program_run_response(&cat_argv, exit_ok(tcp_pcap));
            } else {
                let content = std::fs::read_to_string(reviewed_dir.path().join(artifact))
                    .expect("read artifact");
                mock.program_run_response(&cat_argv, exit_ok(&content));
            }
        }
        if let Some(context) = context {
            mock.program_run_response(
                &[
                    "sudo",
                    "-n",
                    "cat",
                    "/tmp/tmp.testdir/dns_block_context.txt",
                ],
                exit_ok(context),
            );
        }
    }

    /// ki-0001 witness: a TCP/53 line in the exit's capture fails the stage (the
    /// check is exactly as strict as before) AND the raw pcap plus the context
    /// snapshot survive in the report dir, so the emitting process/destination
    /// can be read afterwards. Old code: Err but the pcap only lived in a leaked
    /// `/tmp/.tmpXXXX` on the orchestrating host, never in the report dir.
    #[test]
    fn nonempty_tcp_pcap_still_fails_and_is_retained_in_the_report_dir() {
        let mock = MockShellHost::new();
        let evidence = tempdir().expect("evidence tempdir");
        program_capture(&mock, LEAKED_TCP_LINE, Some(CONTEXT_BODY));

        let err = validate_linux_exit_dns_failclosed(
            &mock,
            TEST_DAEMON,
            "deb-1",
            TEST_MESH_HOSTNAME,
            evidence.path(),
        )
        .expect_err("a TCP/53 line must fail the stage");
        assert!(
            err.contains("tcp_block_pcap.txt contains DNS egress evidence"),
            "verdict text must be unchanged: {err}"
        );
        let kept = evidence.path().join("deb-1/attempt-001");
        assert_eq!(
            std::fs::read_to_string(kept.join("tcp_block_pcap.txt")).expect("retained pcap"),
            LEAKED_TCP_LINE
        );
        assert_eq!(
            std::fs::read_to_string(kept.join("dns_block_context.txt")).expect("retained context"),
            CONTEXT_BODY
        );
        assert!(
            err.contains(&kept.display().to_string()),
            "the error must say where the artifacts went: {err}"
        );
    }

    /// Retention is evidence only: an older daemon without the context file must
    /// neither fail the capture nor change the verdict.
    #[test]
    fn missing_optional_context_file_does_not_change_the_verdict() {
        let mock = MockShellHost::new();
        let evidence = tempdir().expect("evidence tempdir");
        program_capture(&mock, LEAKED_TCP_LINE, None);
        let err = validate_linux_exit_dns_failclosed(
            &mock,
            TEST_DAEMON,
            "deb-1",
            TEST_MESH_HOSTNAME,
            evidence.path(),
        )
        .expect_err("still fails on the pcap, not on the missing context");
        assert!(err.contains("tcp_block_pcap.txt contains DNS egress evidence"));
        let kept = evidence.path().join("deb-1/attempt-001");
        assert!(kept.join("tcp_block_pcap.txt").is_file());
        assert!(!kept.join("dns_block_context.txt").exists());
    }

    /// A capture that fails for another reason (a missing artifact) still keeps
    /// whatever was pulled before the failure.
    #[test]
    fn failed_pull_retains_the_artifacts_pulled_so_far() {
        let mock = MockShellHost::new();
        let evidence = tempdir().expect("evidence tempdir");
        // Only the first artifacts are programmed: the pull dies partway.
        mock.program_run_response(
            &["ip", "route", "show", "default"],
            exit_ok("default via 192.168.1.1 dev enp0s1\n"),
        );
        program_killswitch_discovery(&mock);
        mock.program_run_response(&["mktemp", "-d"], exit_ok("/tmp/tmp.testdir\n"));
        let capture_argv: [&str; 12] = [
            "sudo",
            "-n",
            TEST_DAEMON,
            "linux-exit-dns-failclosed-capture",
            "--output",
            "/tmp/tmp.testdir",
            "--lan-iface",
            "enp0s1",
            "--mesh-hostname",
            TEST_MESH_HOSTNAME,
            "--killswitch-table",
            "rustynet_g7",
        ];
        mock.program_run_response(&capture_argv, exit_ok(""));
        mock.program_run_response(
            &[
                "sudo",
                "-n",
                "cat",
                "/tmp/tmp.testdir/firewall_block_rules.json",
            ],
            exit_ok("{}"),
        );
        let err = validate_linux_exit_dns_failclosed(
            &mock,
            TEST_DAEMON,
            "deb-1",
            TEST_MESH_HOSTNAME,
            evidence.path(),
        )
        .expect_err("partial pull must fail");
        assert!(err.contains("udp_block_pcap.txt"), "{err}");
        assert!(
            evidence
                .path()
                .join("deb-1/attempt-001")
                .join("firewall_block_rules.json")
                .is_file()
        );
    }

    /// F2: an early failure pulls nothing, so it must not claim retention nor
    /// create the directory.
    #[test]
    fn early_failure_claims_no_retention_and_creates_nothing() {
        let mock = MockShellHost::new();
        let evidence = tempdir().expect("evidence tempdir");
        mock.program_run_response(&["ip", "route", "show", "default"], exit_ok(""));
        let err = validate_linux_exit_dns_failclosed(
            &mock,
            TEST_DAEMON,
            "deb-1",
            TEST_MESH_HOSTNAME,
            evidence.path(),
        )
        .expect_err("egress detection failure");
        assert!(!err.contains("retained"), "{err}");
        assert!(!evidence.path().join("deb-1").exists());
    }

    /// F2: a re-run for the same alias (or an alias that sanitises to the same
    /// component) must keep the earlier failing capture, not overwrite it.
    #[test]
    fn rerun_never_overwrites_an_earlier_capture() {
        let evidence = tempdir().expect("evidence tempdir");
        for (alias, pcap) in [("a/b", LEAKED_TCP_LINE), ("a_b", "second\n")] {
            let mock = MockShellHost::new();
            program_capture(&mock, pcap, None);
            let _ = validate_linux_exit_dns_failclosed(
                &mock,
                TEST_DAEMON,
                alias,
                TEST_MESH_HOSTNAME,
                evidence.path(),
            )
            .expect_err("leak fails");
        }
        let first = evidence.path().join("a_b/attempt-001/tcp_block_pcap.txt");
        let second = evidence.path().join("a_b/attempt-002/tcp_block_pcap.txt");
        assert_eq!(
            std::fs::read_to_string(first).expect("first"),
            LEAKED_TCP_LINE
        );
        assert_eq!(std::fs::read_to_string(second).expect("second"), "second\n");
    }

    /// An odd/binary context file is evidence only: a clean capture stays a pass.
    #[test]
    fn garbage_context_file_does_not_change_a_clean_verdict() {
        let mock = MockShellHost::new();
        let evidence = tempdir().expect("evidence tempdir");
        program_capture(&mock, "", Some("\u{0}\u{1b}[31m not a table \u{fffd}\n"));
        validate_linux_exit_dns_failclosed(
            &mock,
            TEST_DAEMON,
            "deb-1",
            TEST_MESH_HOSTNAME,
            evidence.path(),
        )
        .expect("context content must never affect the verdict");
    }

    #[test]
    fn evidence_component_is_one_safe_path_segment() {
        assert_eq!(evidence_component("lenovo-exit-1"), "lenovo-exit-1");
        assert_eq!(evidence_component("../etc/passwd"), ".._etc_passwd");
        assert_eq!(evidence_component(".."), "unnamed");
        assert_eq!(evidence_component(""), "unnamed");
    }
}
