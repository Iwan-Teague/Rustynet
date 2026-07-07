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
