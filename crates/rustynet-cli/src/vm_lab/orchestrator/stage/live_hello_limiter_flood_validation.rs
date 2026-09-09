#![allow(dead_code)]
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::evidence::append_stage_evidence_line;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

const REPORTED_SKIPS_FILENAME: &str = "hello_limiter_flood.reported_skips.json";

pub struct LiveHelloLimiterFloodValidationStage;

impl OrchestrationStage for LiveHelloLimiterFloodValidationStage {
    fn id(&self) -> StageId {
        StageId::LiveHelloLimiterFloodValidation
    }
    fn name(&self) -> &str {
        "live_hello_limiter_flood_validation"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::RelayValidation]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[NodeRole::Relay]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::PerNode
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        let relay_aliases: Vec<String> = ctx
            .assignments
            .iter()
            .filter(|a| a.role == NodeRole::Relay)
            .map(|a| a.alias.clone())
            .collect();
        if relay_aliases.is_empty() {
            return StageOutcome::Skipped(
                "no node in this topology is assigned the relay role".to_owned(),
            );
        }

        let mut failures: Vec<String> = Vec::new();
        let mut reported_skips: Vec<(String, String)> = Vec::new();
        for alias in &relay_aliases {
            let adapter = match ctx.adapters.get(alias.as_str()) {
                Some(adapter) => adapter,
                None => {
                    failures.push(format!("{alias}: no adapter"));
                    continue;
                }
            };
            let platform = adapter.platform();
            let relay_binary = match platform {
                crate::vm_lab::VmGuestPlatform::Linux => "rustynet-relay",
                crate::vm_lab::VmGuestPlatform::Macos => "rustynet-relay",
                crate::vm_lab::VmGuestPlatform::Windows => "rustynet-relay.exe",
                _ => {
                    reported_skips.push((alias.clone(), format!("{platform:?}")));
                    continue;
                }
            };
            let shell = match adapter.shell_host() {
                Ok(shell) => shell,
                Err(e) => {
                    failures.push(format!("{alias}: shell host unavailable: {e}"));
                    continue;
                }
            };
            let out = match shell.run_argv(&[relay_binary, "hello-limiter-audit"], &[], &[]) {
                Ok(out) => out,
                Err(e) => {
                    failures.push(format!("{alias}: hello-limiter-audit dispatch failed: {e}"));
                    continue;
                }
            };
            let stdout = String::from_utf8_lossy(&out.stdout);
            match crate::vm_lab::evaluate_hello_limiter_flood_report(alias, stdout.trim()) {
                Ok(summary) => {
                    // QH-83 evidence-on-pass: the per-node verdict must land
                    // in the stage's rust-native evidence log with the real
                    // datum (alias + evaluator summary); a write failure is a
                    // node failure, never a silent green.
                    if let Err(e) =
                        write_hello_limiter_witness(&ctx.report_dir, alias, summary.as_str())
                    {
                        failures.push(format!("{alias}: {e}"));
                    }
                }
                Err(e) => {
                    failures.push(format!("{alias}: {e}"));
                }
            }
        }

        if !reported_skips.is_empty() {
            let body = serde_json::json!({
                "stage": "live_hello_limiter_flood_validation",
                "reported_skips": reported_skips.iter().map(|(a, p)| serde_json::json!({"alias": a, "platform": p})).collect::<Vec<_>>(),
                "reason": "HelloLimiter flood audit runs on relay-hosting nodes via rustynet-relay hello-limiter-audit"
            });
            let _ = std::fs::write(
                ctx.report_dir.join(REPORTED_SKIPS_FILENAME),
                serde_json::to_vec_pretty(&body).unwrap_or_default(),
            );
        }

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
}

/// Append one single-line witness record (`<alias>: <summary>`) to the
/// stage's rust-native evidence log. Evaluator summaries are single-line by
/// contract, but any embedded newline is flattened first so a hostile or
/// multi-line report cannot forge extra evidence lines.
fn write_hello_limiter_witness(
    report_dir: &std::path::Path,
    alias: &str,
    summary: &str,
) -> Result<(), String> {
    let summary = summary.replace(['\n', '\r'], " ");
    let line = format!("{alias}: {summary}");
    append_stage_evidence_line(
        report_dir,
        StageId::LiveHelloLimiterFloodValidation.as_str(),
        &line,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::orchestrator::evidence::rust_native_stage_log_path;
    use std::collections::HashMap;

    fn empty_ctx() -> OrchestrationContext {
        OrchestrationContext {
            report_dir: std::env::temp_dir(),
            network_id: "test-net".to_owned(),
            assignments: vec![],
            node_ids: HashMap::new(),
            collected_pubkeys: HashMap::new(),
            collected_gossip_identities: HashMap::new(),
            membership_snapshot: None,
            mesh_ips: HashMap::new(),
            endpoints: HashMap::new(),
            reflexive_endpoints: HashMap::new(),
            lab_stun_servers: Vec::new(),
            linux_backend: None,
            orchestrator_dialect: None,
            substrate: None,
            substrate_record: None,
            inventory_path: None,
            macos_anchor_validators_elected: false,
            macos_role_transition_elected: false,
            macos_reboot_recovery_elected: false,
            relay_forwarding_validation_elected: false,
            ssh_allow_cidrs: String::new(),
            adapters: HashMap::new(),
            stage_outcomes: HashMap::new(),
            source_archive: None,
        }
    }

    #[test]
    fn stage_id_is_hello_limiter_flood() {
        assert_eq!(
            LiveHelloLimiterFloodValidationStage.id(),
            StageId::LiveHelloLimiterFloodValidation
        );
    }

    #[test]
    fn depends_on_relay_validation() {
        assert_eq!(
            LiveHelloLimiterFloodValidationStage.dependencies(),
            &[StageId::RelayValidation]
        );
    }

    #[test]
    fn empty_assignments_skips() {
        let mut ctx = empty_ctx();
        assert!(
            matches!(
                LiveHelloLimiterFloodValidationStage.execute(&mut ctx),
                StageOutcome::Skipped(_)
            ),
            "expected a skip; got {:?}",
            LiveHelloLimiterFloodValidationStage.execute(&mut ctx)
        );
    }
    #[test]
    fn hello_limiter_witness_line_carries_alias_and_summary() {
        // The witness record must carry the real per-node datum (alias +
        // evaluator summary) as exactly one line, with any embedded newline
        // flattened so it cannot forge a second evidence line.
        let report_dir = std::env::temp_dir().join(format!(
            "hello_limiter_witness_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&report_dir).expect("create temp report dir");
        write_hello_limiter_witness(&report_dir, "relay-1", "audit ok\nsecond line")
            .expect("witness write must succeed");
        let log = std::fs::read_to_string(rust_native_stage_log_path(
            &report_dir,
            StageId::LiveHelloLimiterFloodValidation.as_str(),
        ))
        .expect("evidence log must exist");
        assert!(
            log.contains("relay-1: audit ok second line"),
            "witness line must carry alias + flattened summary: {log:?}"
        );
        assert!(!log.contains("\nsecond"), "newline must be flattened");
        let _ = std::fs::remove_dir_all(&report_dir);
    }

    #[test]
    fn hello_limiter_witness_write_failure_is_propagated() {
        // A report_dir path that cannot host the evidence log (a regular
        // file occupies it) must surface as an error the stage turns into a
        // node failure, not a silent pass.
        let blocker = std::env::temp_dir().join(format!(
            "hello_limiter_witness_blocker_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        ));
        std::fs::write(&blocker, b"not a directory").expect("create blocker file");
        let err = write_hello_limiter_witness(&blocker, "relay-1", "audit ok")
            .expect_err("witness write into a file must fail");
        assert!(!err.is_empty(), "error must explain the failure: {err}");
        let _ = std::fs::remove_file(&blocker);
    }
}
