#![allow(dead_code)]
use crate::vm_lab::orchestrator::remote_shell::RemoteShellHost;

pub fn admin_issue_runtime_implemented(_platform: crate::vm_lab::VmGuestPlatform) -> bool {
    true
}

pub fn validate_admin_issue(shell: &dyn RemoteShellHost, alias: &str) -> Result<(), String> {
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
    let has_admin_role = status_str
        .lines()
        .any(|l| l.contains("role: admin") || l.contains("node_role: admin"));
    if !has_admin_role {
        return Err(format!(
            "{alias}: daemon does not report admin role; status={}",
            status_str.trim()
        ));
    }

    let peers_out = shell
        .run_argv(&["rustynet", "ops", "list-peers"], &[], &[])
        .map_err(|e| format!("{alias}: failed to list peers: {e}"))?;
    if !peers_out.is_success() {
        return Err(format!(
            "{alias}: rustynet ops list-peers exited non-zero: {}",
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
        shell.program_run_response(&["rustynet", "ops", "status"], err("daemon unreachable"));
        let e = validate_admin_issue(&shell, "node1")
            .expect_err("non-zero status exit should fail closed");
        assert!(e.contains("exited non-zero"), "{e}");
    }

    #[test]
    fn fails_closed_when_role_not_reported() {
        let shell = MockShellHost::new();
        shell.program_run_response(&["rustynet", "ops", "status"], ok("role: client\n"));
        let e = validate_admin_issue(&shell, "node1")
            .expect_err("missing admin role should fail closed");
        assert!(e.contains("does not report admin role"), "{e}");
    }

    #[test]
    fn fails_closed_when_list_peers_errors() {
        let shell = MockShellHost::new();
        shell.program_run_response(&["rustynet", "ops", "status"], ok("role: admin\n"));
        shell.program_run_response(
            &["rustynet", "ops", "list-peers"],
            err("membership state unavailable"),
        );
        let e = validate_admin_issue(&shell, "node1")
            .expect_err("failing list-peers should fail closed");
        assert!(e.contains("list-peers exited non-zero"), "{e}");
    }

    #[test]
    fn passes_when_admin_role_and_peers_list_succeed() {
        let shell = MockShellHost::new();
        shell.program_run_response(&["rustynet", "ops", "status"], ok("node_role: admin\n"));
        shell.program_run_response(
            &["rustynet", "ops", "list-peers"],
            ok("peer1\tclient\npeer2\texit\n"),
        );
        validate_admin_issue(&shell, "node1").expect("admin role + peers list should pass");
    }
}
