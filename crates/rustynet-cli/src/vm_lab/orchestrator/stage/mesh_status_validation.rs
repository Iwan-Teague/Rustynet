#![allow(dead_code)]
use crate::vm_lab::LINUX_RUSTYNETD_PATH;
use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::adapter::macos_install::MACOS_RUSTYNETD_PATH;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::role_validation::mesh_status::{
    mesh_status_runtime_implemented, validate_linux_mesh_status, validate_macos_mesh_status,
    validate_windows_mesh_status,
};
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

const WINDOWS_RUSTYNETD_PATH: &str = r"C:\Program Files\RustyNet\rustynetd.exe";

const REPORTED_SKIPS_FILENAME: &str = "mesh_status_validation.reported_skips.json";

/// Prove every Linux node's daemon passes the mesh-status self-check —
/// the daemon's mesh-status view reports no drift (no stale state,
/// expected peer IDs present, within max-age bounds) — folding the
/// formerly bash-only check into the standard Rust orchestrator so a
/// `--node` run exercises it.
///
/// Runs after `key_custody_validation` and before the relay/traffic stages.
/// This is a per-node posture check, so it applies to every node regardless
/// of role. Accepted only on an explicit `overall_ok: true` (fail-closed).
/// A macOS / Windows node is **reported-skipped** — named in
/// `mesh_status_validation.reported_skips.json`, never a silent pass — on
/// the [`mesh_status_runtime_implemented`] posture gate.
pub struct MeshStatusValidationStage;

impl OrchestrationStage for MeshStatusValidationStage {
    fn id(&self) -> StageId {
        StageId::MeshStatusValidation
    }
    fn name(&self) -> &str {
        "mesh_status_validation"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::KeyCustodyValidation]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::PerNode
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        let aliases: Vec<String> = ctx.assignments.iter().map(|a| a.alias.clone()).collect();
        if aliases.is_empty() {
            return StageOutcome::Passed;
        }

        let mut failures: Vec<String> = Vec::new();
        let mut reported_skips: Vec<(String, String)> = Vec::new();
        for alias in &aliases {
            let adapter = match ctx.adapters.get(alias.as_str()) {
                Some(adapter) => adapter,
                None => {
                    failures.push(format!("{alias}: no adapter for mesh-status node"));
                    continue;
                }
            };
            let platform = adapter.platform();
            if !mesh_status_runtime_implemented(platform) {
                reported_skips.push((alias.clone(), format!("{platform:?}")));
                continue;
            }
            let shell = match adapter.shell_host() {
                Ok(shell) => shell,
                Err(e) => {
                    failures.push(format!("{alias}: shell host unavailable: {e}"));
                    continue;
                }
            };
            let daemon_path = match platform {
                VmGuestPlatform::Linux => LINUX_RUSTYNETD_PATH,
                VmGuestPlatform::Macos => MACOS_RUSTYNETD_PATH,
                VmGuestPlatform::Windows => WINDOWS_RUSTYNETD_PATH,
                _ => {
                    reported_skips.push((alias.clone(), format!("{platform:?}")));
                    continue;
                }
            };
            let result = match platform {
                VmGuestPlatform::Linux => validate_linux_mesh_status(&*shell, daemon_path, alias),
                VmGuestPlatform::Macos => validate_macos_mesh_status(&*shell, daemon_path, alias),
                VmGuestPlatform::Windows => {
                    validate_windows_mesh_status(&*shell, daemon_path, alias)
                }
                _ => unreachable!("non-desktop platform filtered above"),
            };
            if let Err(e) = result {
                failures.push(format!("{alias}: {e}"));
            }
        }

        if !reported_skips.is_empty() {
            write_reported_skips_note(ctx, &reported_skips);
        }
        outcome_for(&failures, &reported_skips)
    }
}

fn outcome_for(failures: &[String], reported_skips: &[(String, String)]) -> StageOutcome {
    if !failures.is_empty() {
        StageOutcome::Failed(failures.join("; "))
    } else if !reported_skips.is_empty() {
        StageOutcome::Skipped
    } else {
        StageOutcome::Passed
    }
}

fn reported_skips_json_bytes(reported_skips: &[(String, String)]) -> Vec<u8> {
    let skipped: Vec<serde_json::Value> = reported_skips
        .iter()
        .map(|(alias, platform)| serde_json::json!({ "alias": alias, "platform": platform }))
        .collect();
    let body = serde_json::json!({
        "stage": "mesh_status_validation",
        "reported_skipped_mesh_status": skipped,
        "reason": "Mesh-status check runs live on Linux through the Rust engine; \
                   non-Linux nodes are reported-skipped (named, never a silent pass)",
    });
    serde_json::to_vec_pretty(&body).unwrap_or_default()
}

fn write_reported_skips_note(ctx: &OrchestrationContext, reported_skips: &[(String, String)]) {
    let path = ctx.report_dir.join(REPORTED_SKIPS_FILENAME);
    let _ = std::fs::write(&path, reported_skips_json_bytes(reported_skips));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_no_failures_no_skips_is_passed() {
        assert_eq!(outcome_for(&[], &[]), StageOutcome::Passed);
    }

    #[test]
    fn outcome_reported_skip_only_is_skipped() {
        assert_eq!(
            outcome_for(&[], &[("mac-1".into(), "Macos".into())]),
            StageOutcome::Skipped
        );
    }

    #[test]
    fn outcome_failure_is_failed_even_with_skips() {
        assert!(matches!(
            outcome_for(
                &["deb-1: mesh status check failed".into()],
                &[("mac-1".into(), "Macos".into())]
            ),
            StageOutcome::Failed(_)
        ));
    }

    #[test]
    fn reported_skip_note_names_every_skipped_node() {
        let bytes = reported_skips_json_bytes(&[
            ("mac-1".into(), "Macos".into()),
            ("win-1".into(), "Windows".into()),
        ]);
        let s = String::from_utf8_lossy(&bytes);
        assert!(s.contains("mac-1") && s.contains("win-1"));
        assert!(s.contains("mesh_status_validation"));
    }
}
