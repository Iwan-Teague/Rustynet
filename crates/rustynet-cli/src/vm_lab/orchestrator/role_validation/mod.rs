#![allow(dead_code)]
//! Cross-OS role-validation primitives for the standard orchestrator.
//!
//! Each submodule folds a formerly Linux-only role-lifecycle test bin
//! into a platform-agnostic check driven through the orchestrator's
//! hardened [`RemoteShellHost`](crate::vm_lab::orchestrator::remote_shell)
//! seam, so the standard orchestrator's role-validation stages run the
//! same proof on Linux, macOS, and Windows.
//!
//! The `anchor` submodule validates the anchor capability-advertisement
//! surface (cross-OS); `relay` validates the relay service lifecycle.

pub mod admin_issue;
pub mod anchor;
pub mod authenticode;
pub mod blind_exit;
pub mod blind_exit_dataplane;
pub mod dns_failclosed;
pub mod exit_demotion_residue;
pub mod exit_dns_failclosed;
pub mod exit_nat_lifecycle;
pub mod ipv6_leak;
pub mod key_custody;
pub mod mesh_status;
pub mod relay;
pub mod runtime_acls;
pub mod security_audit;
pub mod service_hardening;

use crate::vm_lab::orchestrator::remote_shell::RemoteShellHost;

/// Discover exactly one generation-rotated nftables table (`prefix<N>`) in a
/// fixed family. Zero tables makes active-state proof vacuous; multiple tables
/// means stale security-sensitive residue. Both fail closed.
pub(crate) fn discover_single_generated_nft_table(
    shell: &dyn RemoteShellHost,
    family: &str,
    prefix: &str,
    label: &str,
) -> Result<String, String> {
    let out = shell
        .run_argv(&["sudo", "-n", "nft", "list", "tables"], &[], &[])
        .map_err(|err| format!("discover {label} failed: {err}"))?;
    if out.code != 0 {
        return Err(format!(
            "discover {label} exited {}; refusing vacuous proof",
            out.code
        ));
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut tables: Vec<String> = stdout
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            if fields.next() != Some("table") || fields.next() != Some(family) {
                return None;
            }
            let name = fields.next()?;
            let generation = name.strip_prefix(prefix)?;
            if generation.is_empty() || !generation.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            Some(name.to_owned())
        })
        .collect();
    tables.sort();
    tables.dedup();
    match tables.as_slice() {
        [table] => Ok(table.clone()),
        [] => Err(format!(
            "active node has no generation-rotated {label}; anti-vacuous guard failed"
        )),
        _ => Err(format!(
            "active node has multiple generation-rotated {label} tables (residual state): {}",
            tables.join(", ")
        )),
    }
}

#[cfg(test)]
mod generated_nft_table_tests {
    use super::*;
    use crate::vm_lab::orchestrator::remote_shell::{MockShellHost, RemoteExitStatus};

    fn exit_ok(stdout: &str) -> RemoteExitStatus {
        RemoteExitStatus {
            code: 0,
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        }
    }

    #[test]
    fn discovers_exact_family_prefix_and_numeric_generation() {
        let mock = MockShellHost::new();
        let argv = ["sudo", "-n", "nft", "list", "tables"];
        mock.program_run_response(
            &argv,
            exit_ok(
                "table inet rustynet_g12_dns\ntable inet rustynet_g12\n\
                 table ip rustynet_nat_g12\n",
            ),
        );
        assert_eq!(
            discover_single_generated_nft_table(&mock, "inet", "rustynet_g", "killswitch",)
                .unwrap(),
            "rustynet_g12"
        );
    }

    #[test]
    fn rejects_zero_or_multiple_matches() {
        let argv = ["sudo", "-n", "nft", "list", "tables"];
        let none = MockShellHost::new();
        none.program_run_response(&argv, exit_ok("table inet rustynet_boot\n"));
        assert!(discover_single_generated_nft_table(&none, "ip", "rustynet_nat_g", "NAT").is_err());

        let multiple = MockShellHost::new();
        multiple.program_run_response(
            &argv,
            exit_ok("table ip rustynet_nat_g2\ntable ip rustynet_nat_g9\n"),
        );
        let err = discover_single_generated_nft_table(&multiple, "ip", "rustynet_nat_g", "NAT")
            .unwrap_err();
        assert!(err.contains("multiple") && err.contains("residual state"));
    }
}
