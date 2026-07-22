#![allow(dead_code)]
use crate::vm_lab::orchestrator::remote_shell::RemoteShellHost;

pub fn admin_issue_runtime_implemented(_platform: crate::vm_lab::VmGuestPlatform) -> bool {
    true
}

pub fn validate_admin_issue(shell: &dyn RemoteShellHost, alias: &str) -> Result<(), String> {
    const MAX_ATTEMPTS: usize = 4;
    const RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(3);

    for attempt in 1..=MAX_ATTEMPTS {
        match shell.run_argv(&["/usr/local/bin/rustynet", "status"], &[], &[]) {
            Ok(out) if out.is_success() => {
                let status_str = String::from_utf8_lossy(&out.stdout);
                if status_str.lines().any(|l| l.contains("node_role=admin")) {
                    break;
                }
                if attempt >= MAX_ATTEMPTS {
                    return Err(format!(
                        "{alias}: daemon does not report admin role after {MAX_ATTEMPTS} attempts; status={}",
                        status_str.trim()
                    ));
                }
            }
            Ok(out) => {
                if attempt >= MAX_ATTEMPTS {
                    let status_str = String::from_utf8_lossy(&out.stdout);
                    return Err(format!(
                        "{alias}: rustynet status exited non-zero after {MAX_ATTEMPTS} attempts: {}",
                        status_str.trim()
                    ));
                }
            }
            Err(e) => {
                if attempt >= MAX_ATTEMPTS {
                    return Err(format!(
                        "{alias}: failed to run rustynet status after {MAX_ATTEMPTS} attempts: {e}"
                    ));
                }
            }
        }
        std::thread::sleep(RETRY_DELAY);
    }

    let peers_out = shell
        .run_argv(&["/usr/local/bin/rustynet", "peer-list"], &[], &[])
        .map_err(|e| format!("{alias}: failed to list peers: {e}"))?;
    if !peers_out.is_success() {
        return Err(format!(
            "{alias}: rustynet peer-list exited non-zero: {}",
            String::from_utf8_lossy(&peers_out.stdout).trim()
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::VmGuestPlatform;
    use crate::vm_lab::orchestrator::remote_shell::{MockShellHost, RemoteExitStatus};

    fn ok(stdout: &str) -> RemoteExitStatus {
        RemoteExitStatus {
            code: 0,
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        }
    }

    fn err(stdout: &str) -> RemoteExitStatus {
        RemoteExitStatus {
            code: 1,
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        }
    }

    #[test]
    fn runtime_implemented_on_every_platform() {
        assert!(admin_issue_runtime_implemented(VmGuestPlatform::Linux));
        assert!(admin_issue_runtime_implemented(VmGuestPlatform::Macos));
        assert!(admin_issue_runtime_implemented(VmGuestPlatform::Windows));
    }

    #[test]
    fn fails_closed_when_status_command_errors() {
        let shell = MockShellHost::new();
        for _ in 0..4 {
            shell.program_run_response(
                &["/usr/local/bin/rustynet", "status"],
                err("daemon unreachable"),
            );
        }
        let e = validate_admin_issue(&shell, "node1")
            .expect_err("non-zero status exit should fail closed");
        assert!(e.contains("exited non-zero"), "{e}");
    }

    #[test]
    fn fails_closed_when_role_not_reported() {
        let shell = MockShellHost::new();
        for _ in 0..4 {
            shell.program_run_response(
                &["/usr/local/bin/rustynet", "status"],
                ok("node_id=node1 node_role=client state=Running\n"),
            );
        }
        let e = validate_admin_issue(&shell, "node1")
            .expect_err("missing admin role should fail closed");
        assert!(e.contains("does not report admin role"), "{e}");
    }

    #[test]
    fn fails_closed_when_list_peers_errors() {
        let shell = MockShellHost::new();
        shell.program_run_response(
            &["/usr/local/bin/rustynet", "status"],
            ok("node_id=node1 node_role=admin state=Running\n"),
        );
        shell.program_run_response(
            &["/usr/local/bin/rustynet", "peer-list"],
            err("membership state unavailable"),
        );
        let e = validate_admin_issue(&shell, "node1")
            .expect_err("failing peer-list should fail closed");
        assert!(e.contains("peer-list exited non-zero"), "{e}");
    }

    #[test]
    fn passes_when_admin_role_and_peers_list_succeed() {
        let shell = MockShellHost::new();
        shell.program_run_response(
            &["/usr/local/bin/rustynet", "status"],
            ok("node_id=node1 node_role=admin state=Running exit_node=\n"),
        );
        shell.program_run_response(
            &["/usr/local/bin/rustynet", "peer-list"],
            ok("peer1\tclient\npeer2\texit\n"),
        );
        validate_admin_issue(&shell, "node1").expect("admin role + peers list should pass");
    }
}
