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
