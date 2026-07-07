#![allow(dead_code)]
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
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
            return StageOutcome::Skipped;
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
                    eprintln!("{alias}: {summary}");
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
            StageOutcome::Skipped
        } else {
            StageOutcome::Passed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn empty_ctx() -> OrchestrationContext {
        OrchestrationContext {
            report_dir: std::env::temp_dir(),
            network_id: "test-net".to_owned(),
            assignments: vec![],
            node_ids: HashMap::new(),
            collected_pubkeys: HashMap::new(),
            membership_snapshot: None,
            mesh_ips: HashMap::new(),
            endpoints: HashMap::new(),
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
        assert_eq!(
            LiveHelloLimiterFloodValidationStage.execute(&mut ctx),
            StageOutcome::Skipped
        );
    }
}
