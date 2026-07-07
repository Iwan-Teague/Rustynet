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
use std::path::PathBuf;

use tempfile;

const DEFAULT_KILLSWITCH_TABLE: &str = "rustynet_g1";
const DEFAULT_MESH_HOSTNAME: &str = "exit-1.rustynet";

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

fn create_local_artifact_dir() -> Result<PathBuf, String> {
    #[allow(deprecated)]
    {
        Ok(tempfile::tempdir()
            .map_err(|err| format!("failed to create local temp dir: {err}"))?
            .into_path())
    }
}

pub fn validate_linux_exit_dns_failclosed(
    shell: &dyn RemoteShellHost,
    daemon_path: &str,
    alias: &str,
) -> Result<(), String> {
    let egress_iface = detect_linux_egress_interface(shell)?;

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
        let _ = shell.run_argv(&["rm", "-rf", &remote_tmp], &[], &[]);
    };

    let capture_argv: [&str; 8] = [
        daemon_path,
        "linux-exit-dns-failclosed-capture",
        "--output",
        &remote_tmp,
        "--lan-iface",
        &egress_iface,
        "--mesh-hostname",
        DEFAULT_MESH_HOSTNAME,
    ];
    let capture_result = shell.run_argv(&capture_argv, &[], &[]);
    if let Err(e) = &capture_result {
        let context = if e.to_string().len() > 200 {
            format!("{}…", &e.to_string()[..200])
        } else {
            e.to_string()
        };
        cleanup();
        return Err(format!(
            "dispatch of linux-exit-dns-failclosed-capture failed: {context}"
        ));
    }

    let local_tmp = create_local_artifact_dir()?;

    for artifact in REQUIRED_ARTIFACTS {
        let remote_path = remote_tmp_path.join(artifact);
        let cat_argv: [&str; 2] = ["cat", remote_path.to_str().unwrap_or(artifact)];
        match shell.run_argv(&cat_argv, &[], &[]) {
            Ok(out) => {
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

    cleanup();

    crate::vm_lab::evaluate_linux_exit_dns_failclosed_artifact_dir(alias, &local_tmp).map(|_| ())
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

    fn exit_ok(stdout: &str) -> RemoteExitStatus {
        RemoteExitStatus {
            code: 0,
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        }
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
        mock.program_run_response(
            &["ip", "route", "show", "default"],
            exit_ok("default via 192.168.1.1 dev enp0s1"),
        );
        let err = validate_linux_exit_dns_failclosed(&mock, TEST_DAEMON, "deb-1")
            .expect_err("dispatch error must fail the stage");
        assert!(
            err.contains("mktemp"),
            "expected mktemp failure, got: {err}"
        );
    }

    #[test]
    fn validate_fails_closed_on_egress_detection_failure() {
        let mock = MockShellHost::new();
        mock.program_run_response(&["ip", "route", "show", "default"], exit_ok(""));
        let err = validate_linux_exit_dns_failclosed(&mock, TEST_DAEMON, "deb-1")
            .expect_err("egress detection failure must fail the stage");
        assert!(
            err.contains("egress"),
            "expected egress detection error, got: {err}"
        );
    }

    #[test]
    fn validate_accepts_reviewed_artifacts() {
        let mock = MockShellHost::new();
        let reviewed_dir = tempdir().expect("tempdir");
        write_reviewed_linux_exit_dns_artifacts(reviewed_dir.path());

        // egress detection
        mock.program_run_response(
            &["ip", "route", "show", "default"],
            exit_ok("default via 192.168.1.1 dev enp0s1\n"),
        );
        // mktemp -d
        mock.program_run_response(&["mktemp", "-d"], exit_ok("/tmp/tmp.testdir\n"));
        // capture subcommand (after egress, remote dir)
        let capture_argv: [&str; 8] = [
            TEST_DAEMON,
            "linux-exit-dns-failclosed-capture",
            "--output",
            "/tmp/tmp.testdir",
            "--lan-iface",
            "enp0s1",
            "--mesh-hostname",
            DEFAULT_MESH_HOSTNAME,
        ];
        mock.program_run_response(&capture_argv, exit_ok(""));

        // cat each artifact
        for artifact in REQUIRED_ARTIFACTS {
            let cat_path = format!("/tmp/tmp.testdir/{artifact}");
            let cat_argv: [&str; 2] = ["cat", &cat_path];
            let content =
                std::fs::read_to_string(reviewed_dir.path().join(artifact)).expect("read artifact");
            mock.program_run_response(&cat_argv, exit_ok(&content));
        }

        validate_linux_exit_dns_failclosed(&mock, TEST_DAEMON, "deb-1")
            .expect("reviewed artifacts must pass");
    }

    #[test]
    fn validate_fails_closed_on_missing_artifact() {
        let mock = MockShellHost::new();
        let reviewed_dir = tempdir().expect("tempdir");
        write_reviewed_linux_exit_dns_artifacts(reviewed_dir.path());

        mock.program_run_response(
            &["ip", "route", "show", "default"],
            exit_ok("default via 192.168.1.1 dev enp0s1\n"),
        );
        mock.program_run_response(&["mktemp", "-d"], exit_ok("/tmp/tmp.testdir\n"));
        let capture_argv: [&str; 8] = [
            TEST_DAEMON,
            "linux-exit-dns-failclosed-capture",
            "--output",
            "/tmp/tmp.testdir",
            "--lan-iface",
            "enp0s1",
            "--mesh-hostname",
            DEFAULT_MESH_HOSTNAME,
        ];
        mock.program_run_response(&capture_argv, exit_ok(""));

        for artifact in REQUIRED_ARTIFACTS {
            let cat_path = format!("/tmp/tmp.testdir/{artifact}");
            let cat_argv: [&str; 2] = ["cat", &cat_path];
            if artifact == &"tunnel_path_resolves.json" {
                // omit response — un-programmed argv fails with Transport error
            } else {
                let content = std::fs::read_to_string(reviewed_dir.path().join(artifact))
                    .expect("read artifact");
                mock.program_run_response(&cat_argv, exit_ok(&content));
            }
        }

        let err = validate_linux_exit_dns_failclosed(&mock, TEST_DAEMON, "deb-1")
            .expect_err("missing artifact must fail the stage");
        assert!(
            err.contains("tunnel_path_resolves.json"),
            "expected missing tunnel_path_resolves error, got: {err}"
        );
    }

    #[test]
    fn validate_fails_closed_on_nonempty_udp_pcap() {
        let mock = MockShellHost::new();
        let reviewed_dir = tempdir().expect("tempdir");
        write_reviewed_linux_exit_dns_artifacts(reviewed_dir.path());

        mock.program_run_response(
            &["ip", "route", "show", "default"],
            exit_ok("default via 192.168.1.1 dev enp0s1\n"),
        );
        mock.program_run_response(&["mktemp", "-d"], exit_ok("/tmp/tmp.testdir\n"));
        let capture_argv: [&str; 8] = [
            TEST_DAEMON,
            "linux-exit-dns-failclosed-capture",
            "--output",
            "/tmp/tmp.testdir",
            "--lan-iface",
            "enp0s1",
            "--mesh-hostname",
            DEFAULT_MESH_HOSTNAME,
        ];
        mock.program_run_response(&capture_argv, exit_ok(""));

        for artifact in REQUIRED_ARTIFACTS {
            let cat_path = format!("/tmp/tmp.testdir/{artifact}");
            let cat_argv: [&str; 2] = ["cat", &cat_path];
            if artifact == &"udp_block_pcap.txt" {
                mock.program_run_response(&cat_argv, exit_ok("12:34:56 UDP leaked\n"));
            } else {
                let content = std::fs::read_to_string(reviewed_dir.path().join(artifact))
                    .expect("read artifact");
                mock.program_run_response(&cat_argv, exit_ok(&content));
            }
        }

        let err = validate_linux_exit_dns_failclosed(&mock, TEST_DAEMON, "deb-1")
            .expect_err("nonempty pcap must fail the stage");
        assert!(
            err.contains("pcap") || err.contains("UDP"),
            "expected nonempty pcap error, got: {err}"
        );
    }
}
