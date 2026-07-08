#![allow(dead_code)]
use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::remote_shell::RemoteShellHost;

pub fn blind_exit_runtime_implemented(platform: VmGuestPlatform) -> bool {
    matches!(platform, VmGuestPlatform::Linux | VmGuestPlatform::Macos)
}

pub fn validate_blind_exit_runtime(
    shell: &dyn RemoteShellHost,
    platform: VmGuestPlatform,
    alias: &str,
) -> Result<(), String> {
    let status_out = shell
        .run_argv(&["rustynet", "ops", "status"], &[], &[])
        .map_err(|e| format!("{alias}: failed to run rustynet ops status: {e}"))?;
    let status_str = String::from_utf8_lossy(&status_out.stdout);
    if !status_out.is_success() {
        return Err(format!(
            "{alias}: rustynet ops status exited non-zero: {}",
            status_str.trim()
        ));
    }
    let has_blind_exit_role = status_str
        .lines()
        .any(|l| l.contains("role: blind_exit") || l.contains("node_role: blind_exit"));
    if !has_blind_exit_role {
        return Err(format!(
            "{alias}: daemon does not report blind_exit role; status={}",
            status_str.trim()
        ));
    }

    match platform {
        VmGuestPlatform::Linux => {
            let out = shell
                .run_argv(&["sh", "-c", "iptables -t nat -L POSTROUTING 2>/dev/null || nft list ruleset 2>/dev/null"], &[], &[])
                .map_err(|e| format!("{alias}: failed to probe forwarding rules: {e}"))?;
            let stdout = String::from_utf8_lossy(&out.stdout);
            if stdout.trim().is_empty() {
                return Err(format!(
                    "{alias}: no nft/iptables forwarding rules found for blind_exit"
                ));
            }
        }
        VmGuestPlatform::Macos => {
            let out = shell
                .run_argv(
                    &[
                        "sh",
                        "-c",
                        "sudo pfctl -s nat 2>/dev/null || echo 'no-pf-nat'",
                    ],
                    &[],
                    &[],
                )
                .map_err(|e| format!("{alias}: failed to probe pf rules: {e}"))?;
            let stdout = String::from_utf8_lossy(&out.stdout);
            if stdout.contains("no-pf-nat") || stdout.trim().is_empty() {
                return Err(format!("{alias}: no pf NAT rules found for blind_exit"));
            }
        }
        VmGuestPlatform::Windows => {
            let out = shell
                .run_argv(&["powershell", "-Command", "Get-NetNat 2>$null"], &[], &[])
                .map_err(|e| format!("{alias}: failed to probe Windows NAT: {e}"))?;
            let stdout = String::from_utf8_lossy(&out.stdout);
            if stdout.trim().is_empty() {
                return Err(format!(
                    "{alias}: no Windows NAT rules found for blind_exit"
                ));
            }
        }
        _ => {}
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::orchestrator::remote_shell::{MockShellHost, RemoteExitStatus};

    fn program_status(shell: &MockShellHost, role_line: &str, code: i32) {
        shell.program_run_response(
            &["rustynet", "ops", "status"],
            RemoteExitStatus {
                code,
                stdout: role_line.as_bytes().to_vec(),
                stderr: Vec::new(),
            },
        );
    }

    #[test]
    fn runtime_implemented_linux_and_macos_not_windows() {
        assert!(blind_exit_runtime_implemented(VmGuestPlatform::Linux));
        assert!(blind_exit_runtime_implemented(VmGuestPlatform::Macos));
        assert!(!blind_exit_runtime_implemented(VmGuestPlatform::Windows));
    }

    #[test]
    fn fails_closed_when_status_command_errors() {
        let shell = MockShellHost::new();
        program_status(&shell, "error: daemon unreachable", 1);
        let err = validate_blind_exit_runtime(&shell, VmGuestPlatform::Linux, "node1")
            .expect_err("non-zero status exit should fail closed");
        assert!(err.contains("exited non-zero"), "{err}");
    }

    #[test]
    fn fails_closed_when_role_not_reported() {
        let shell = MockShellHost::new();
        program_status(&shell, "role: exit\npeers: 2\n", 0);
        let err = validate_blind_exit_runtime(&shell, VmGuestPlatform::Linux, "node1")
            .expect_err("missing blind_exit role should fail closed");
        assert!(err.contains("does not report blind_exit role"), "{err}");
    }

    #[test]
    fn linux_passes_when_forwarding_rules_present() {
        let shell = MockShellHost::new();
        program_status(&shell, "role: blind_exit\n", 0);
        shell.program_run_response(
            &[
                "sh",
                "-c",
                "iptables -t nat -L POSTROUTING 2>/dev/null || nft list ruleset 2>/dev/null",
            ],
            RemoteExitStatus {
                code: 0,
                stdout: b"table ip rustynet_nat_blind_exit { ... }".to_vec(),
                stderr: Vec::new(),
            },
        );
        validate_blind_exit_runtime(&shell, VmGuestPlatform::Linux, "node1")
            .expect("nat rules present should pass");
    }

    #[test]
    fn linux_fails_closed_when_no_forwarding_rules() {
        let shell = MockShellHost::new();
        program_status(&shell, "role: blind_exit\n", 0);
        shell.program_run_response(
            &[
                "sh",
                "-c",
                "iptables -t nat -L POSTROUTING 2>/dev/null || nft list ruleset 2>/dev/null",
            ],
            RemoteExitStatus {
                code: 0,
                stdout: Vec::new(),
                stderr: Vec::new(),
            },
        );
        let err = validate_blind_exit_runtime(&shell, VmGuestPlatform::Linux, "node1")
            .expect_err("empty nat/forwarding output should fail closed");
        assert!(err.contains("no nft/iptables forwarding rules"), "{err}");
    }

    #[test]
    fn macos_passes_when_pf_nat_rules_present() {
        let shell = MockShellHost::new();
        program_status(&shell, "node_role: blind_exit\n", 0);
        shell.program_run_response(
            &[
                "sh",
                "-c",
                "sudo pfctl -s nat 2>/dev/null || echo 'no-pf-nat'",
            ],
            RemoteExitStatus {
                code: 0,
                stdout: b"nat on en0 inet from 100.64.0.0/10 to any -> (en0)".to_vec(),
                stderr: Vec::new(),
            },
        );
        validate_blind_exit_runtime(&shell, VmGuestPlatform::Macos, "macos-node")
            .expect("pf nat rules present should pass");
    }

    #[test]
    fn macos_fails_closed_on_no_pf_nat_sentinel() {
        let shell = MockShellHost::new();
        program_status(&shell, "role: blind_exit\n", 0);
        shell.program_run_response(
            &[
                "sh",
                "-c",
                "sudo pfctl -s nat 2>/dev/null || echo 'no-pf-nat'",
            ],
            RemoteExitStatus {
                code: 0,
                stdout: b"no-pf-nat\n".to_vec(),
                stderr: Vec::new(),
            },
        );
        let err = validate_blind_exit_runtime(&shell, VmGuestPlatform::Macos, "macos-node")
            .expect_err("no-pf-nat sentinel should fail closed");
        assert!(err.contains("no pf NAT rules found"), "{err}");
    }

    #[test]
    fn macos_fails_closed_on_empty_pf_output() {
        let shell = MockShellHost::new();
        program_status(&shell, "role: blind_exit\n", 0);
        shell.program_run_response(
            &[
                "sh",
                "-c",
                "sudo pfctl -s nat 2>/dev/null || echo 'no-pf-nat'",
            ],
            RemoteExitStatus {
                code: 0,
                stdout: Vec::new(),
                stderr: Vec::new(),
            },
        );
        let err = validate_blind_exit_runtime(&shell, VmGuestPlatform::Macos, "macos-node")
            .expect_err("empty pf output should fail closed");
        assert!(err.contains("no pf NAT rules found"), "{err}");
    }

    #[test]
    fn windows_passes_when_netnat_present() {
        let shell = MockShellHost::new();
        program_status(&shell, "role: blind_exit\n", 0);
        shell.program_run_response(
            &["powershell", "-Command", "Get-NetNat 2>$null"],
            RemoteExitStatus {
                code: 0,
                stdout: b"Name : RustyNetNat".to_vec(),
                stderr: Vec::new(),
            },
        );
        validate_blind_exit_runtime(&shell, VmGuestPlatform::Windows, "win-node")
            .expect("netnat present should pass");
    }

    #[test]
    fn windows_fails_closed_when_no_netnat() {
        let shell = MockShellHost::new();
        program_status(&shell, "role: blind_exit\n", 0);
        shell.program_run_response(
            &["powershell", "-Command", "Get-NetNat 2>$null"],
            RemoteExitStatus {
                code: 0,
                stdout: Vec::new(),
                stderr: Vec::new(),
            },
        );
        let err = validate_blind_exit_runtime(&shell, VmGuestPlatform::Windows, "win-node")
            .expect_err("no NetNat output should fail closed");
        assert!(err.contains("no Windows NAT rules found"), "{err}");
    }
}
