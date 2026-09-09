#![allow(dead_code)]
use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::evidence::append_stage_evidence_line;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::role_validation::exit_nat_lifecycle::{
    exit_nat_lifecycle_runtime_implemented, validate_linux_exit_nat_lifecycle,
    validate_macos_exit_nat_lifecycle,
};
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

const REPORTED_SKIPS_FILENAME: &str = "exit_nat_lifecycle_validation.reported_skips.json";

/// Prove the exit node's NAT table is present during active exit service and
/// absent after daemon stop — a two-phase snapshot→stop→snapshot→merge→evaluate
/// lifecycle check folded into the standard Rust orchestrator.
///
/// Runs after `exit_dns_failclosed_validation` while the assigned exit is still
/// active. After proving stop-time teardown, it restarts/reactivates the exit so
/// the following demotion-residue proof starts from a non-vacuous active state.
pub struct ExitNatLifecycleValidationStage;

impl OrchestrationStage for ExitNatLifecycleValidationStage {
    fn id(&self) -> StageId {
        StageId::ExitNatLifecycleValidation
    }
    fn name(&self) -> &str {
        "exit_nat_lifecycle_validation"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::ExitDnsFailclosedValidation]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[NodeRole::Exit]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::Once
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        let alias = match ctx.assignments.iter().find(|a| a.role == NodeRole::Exit) {
            Some(assignment) => assignment.alias.clone(),
            None => {
                return StageOutcome::Failed(
                    "exit-nat-lifecycle: no Exit node in assignments".to_owned(),
                );
            }
        };
        let adapter = match ctx.adapters.get(alias.as_str()) {
            Some(adapter) => adapter,
            None => {
                return StageOutcome::Failed(format!(
                    "{alias}: no adapter for exit-nat-lifecycle node"
                ));
            }
        };
        let platform = adapter.platform();
        if !exit_nat_lifecycle_runtime_implemented(platform) {
            let reported_skips = vec![(alias, format!("{platform:?}"))];
            write_reported_skips_note(ctx, &reported_skips);
            return StageOutcome::Skipped(format!(
                "exit NAT lifecycle validation is not implemented for {platform:?}"
            ));
        }
        let shell = match adapter.shell_host() {
            Ok(shell) => shell,
            Err(e) => {
                return StageOutcome::Failed(format!("{alias}: shell host unavailable: {e}"));
            }
        };
        let daemon_path = match platform.lab_daemon_path() {
            Some(path) => path,
            None => {
                return StageOutcome::Failed(format!(
                    "{alias}: no rustynetd daemon path for platform {platform:?} \
                     (gate/dispatch desync: the runtime gate accepted a platform \
                     the adapter path table cannot serve)"
                ));
            }
        };
        let validation = match validation_kind_for(platform) {
            Some(kind) => kind,
            None => {
                return StageOutcome::Failed(format!(
                    "{alias}: exit NAT lifecycle gate accepted {platform:?} but no \
                     validator dispatches it (gate/dispatch desync)"
                ));
            }
        };
        let validation_result = match validation {
            ExitNatLifecycleValidationKind::Linux => {
                validate_linux_exit_nat_lifecycle(&*shell, daemon_path, &alias)
            }
            ExitNatLifecycleValidationKind::Macos => {
                validate_macos_exit_nat_lifecycle(&*shell, daemon_path, &alias)
            }
        };
        if let Err(e) = validation_result {
            return StageOutcome::Failed(format!("{alias}: {e}"));
        }

        // Lifecycle proof deliberately stops rustynetd. Restore the exact
        // active-exit precondition needed by exit-demotion-residue; failure to
        // restore is itself a hard lifecycle failure, never a silent skip.
        if let Err(e) = adapter.start_daemon() {
            return StageOutcome::Failed(format!(
                "{alias}: restart after NAT lifecycle proof failed: {e}"
            ));
        }
        if let Err(e) = adapter.activate_exit_serving() {
            return StageOutcome::Failed(format!(
                "{alias}: reactivate exit after NAT lifecycle proof failed: {e}"
            ));
        }
        if let Err(e) = adapter.assert_exit_actively_serving() {
            return StageOutcome::Failed(format!(
                "{alias}: reactivated exit failed active-serving assertion: {e}"
            ));
        }

        let failures = Vec::new();
        let reported_skips = Vec::new();
        // QH-83: the witness is written on the single pass path and a write
        // failure fails the stage — an unwitnessed NAT-lifecycle pass must
        // never be recorded (the runner would demote it).
        match outcome_for(&failures, &reported_skips) {
            StageOutcome::Passed => match write_exit_nat_lifecycle_witness(&ctx.report_dir, &alias)
            {
                Ok(()) => StageOutcome::Passed,
                Err(e) => {
                    StageOutcome::Failed(format!("exit nat lifecycle witness write failed: {e}"))
                }
            },
            other => other,
        }
    }
}

/// Writes the QH-83 witness line for an exit-NAT-lifecycle PASS: the exit
/// alias whose NAT lifecycle (prove → stop → restart → reactivate →
/// re-assert active serving) was actually proven, so a bare PASS can never be
/// recorded without the on-disk evidence behind it. An unwritable witness
/// fails the stage — fail closed.
fn write_exit_nat_lifecycle_witness(
    report_dir: &std::path::Path,
    exit_alias: &str,
) -> Result<(), String> {
    append_stage_evidence_line(
        report_dir,
        StageId::ExitNatLifecycleValidation.as_str(),
        &format!(
            "exit_nat_lifecycle=yes exit={exit_alias} daemon_restarted=true exit_reactivated=true"
        ),
    )
}

/// The validators the exit NAT lifecycle proof dispatches, per platform.
/// Extracted from `execute` so the dispatch table is unit-testable: the
/// former `_ => unreachable!("runtime implementation gate accepts desktop
/// platforms only")` arms panicked the stage thread whenever the runtime
/// gate and this table drifted (audit I1). An uncovered platform now maps
/// to `None` and the stage fails closed naming the desync instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExitNatLifecycleValidationKind {
    Linux,
    Macos,
}

fn validation_kind_for(platform: VmGuestPlatform) -> Option<ExitNatLifecycleValidationKind> {
    match platform {
        VmGuestPlatform::Linux => Some(ExitNatLifecycleValidationKind::Linux),
        VmGuestPlatform::Macos => Some(ExitNatLifecycleValidationKind::Macos),
        VmGuestPlatform::Windows | VmGuestPlatform::Ios | VmGuestPlatform::Android => None,
    }
}

fn outcome_for(failures: &[String], reported_skips: &[(String, String)]) -> StageOutcome {
    if !failures.is_empty() {
        StageOutcome::Failed(failures.join("; "))
    } else if !reported_skips.is_empty() {
        StageOutcome::Skipped(format!(
            "no node executed this validation; {} node(s) reported a runtime skip",
            reported_skips.len()
        ))
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
        "stage": "exit_nat_lifecycle_validation",
        "reported_skipped_exit_nat_lifecycle": skipped,
        "reason": "Exit NAT lifecycle check runs live on Linux through the Rust engine; \
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
    fn stage_evidence_is_scoped_to_assigned_exit() {
        assert_eq!(
            ExitNatLifecycleValidationStage.applies_to_roles(),
            &[NodeRole::Exit]
        );
    }

    #[test]
    fn outcome_no_failures_no_skips_is_passed() {
        assert_eq!(outcome_for(&[], &[]), StageOutcome::Passed);
    }

    #[test]
    fn outcome_reported_skip_only_is_skipped() {
        assert!(
            matches!(
                outcome_for(&[], &[("mac-1".into(), "Macos".into())]),
                StageOutcome::Skipped(_)
            ),
            "expected a skip; got {:?}",
            outcome_for(&[], &[("mac-1".into(), "Macos".into())])
        );
    }

    #[test]
    fn outcome_failure_is_failed_even_with_skips() {
        assert!(matches!(
            outcome_for(
                &["deb-1: exit NAT lifecycle check failed".into()],
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
        assert!(s.contains("exit_nat_lifecycle_validation"));
    }

    /// Mutation caught: restoring either `_ => unreachable!("runtime
    /// implementation gate accepts desktop platforms only")` dispatch arm
    /// (in `validation_kind_for` or the `lab_daemon_path` call site) makes
    /// this test panic on an uncovered platform instead of observing the
    /// fail-closed `None` mapping (audit I1).
    #[test]
    fn validation_kind_never_panics_on_ungated_platforms() {
        assert_eq!(
            validation_kind_for(VmGuestPlatform::Linux),
            Some(ExitNatLifecycleValidationKind::Linux)
        );
        assert_eq!(
            validation_kind_for(VmGuestPlatform::Macos),
            Some(ExitNatLifecycleValidationKind::Macos)
        );
        for uncovered in [
            VmGuestPlatform::Windows,
            VmGuestPlatform::Ios,
            VmGuestPlatform::Android,
        ] {
            assert_eq!(
                validation_kind_for(uncovered),
                None,
                "platform {uncovered:?} must map to None, never a panic"
            );
        }
    }

    // QH-83: the pass witness must name the exit alias and the lifecycle
    // restoration facts — a bare "pass" line would be appeasement, not
    // evidence. Mutation caught: dropping the witness write or demoting it
    // to best-effort.
    #[test]
    fn exit_nat_lifecycle_witness_line_names_the_exit_alias() {
        let dir = std::env::temp_dir().join(format!(
            "exnat_witness_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .subsec_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        write_exit_nat_lifecycle_witness(&dir, "exit-a").expect("witness write");
        let log = std::fs::read_to_string(
            crate::vm_lab::orchestrator::evidence::rust_native_stage_log_path(
                &dir,
                StageId::ExitNatLifecycleValidation.as_str(),
            ),
        )
        .expect("stage log");
        assert!(log.contains("exit_nat_lifecycle=yes"), "{log}");
        assert!(log.contains("exit=exit-a"), "{log}");
        assert!(log.contains("daemon_restarted=true"), "{log}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Fail-closed check: a witness write that cannot land must surface as an
    /// error the execute path turns into `Failed` — never a silent pass.
    #[test]
    fn exit_nat_lifecycle_witness_write_failure_is_propagated() {
        let dir = std::env::temp_dir().join(format!(
            "exnat_witness_blocker_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .subsec_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("test dir");
        std::fs::write(dir.join("logs"), b"not a directory").expect("blocker file");
        let err = write_exit_nat_lifecycle_witness(&dir, "exit-a")
            .expect_err("witness write must fail when the logs path is a regular file");
        assert!(!err.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
