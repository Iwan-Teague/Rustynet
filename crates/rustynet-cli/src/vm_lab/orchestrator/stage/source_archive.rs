#![allow(dead_code)]
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::source_archive::SourceArchive;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

pub struct PrepareSourceArchiveStage;

impl OrchestrationStage for PrepareSourceArchiveStage {
    fn id(&self) -> StageId {
        StageId::PrepareSourceArchive
    }
    fn name(&self) -> &str {
        "prepare_source_archive"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::Preflight]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::Once
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        if ctx.source_archive.is_some() {
            return StageOutcome::Passed;
        }
        let archive_path = {
            let mut p = std::env::temp_dir();
            p.push(format!("rn_source_{}.tar.gz", std::process::id()));
            p
        };
        let status = std::process::Command::new("git")
            .args(["archive", "--format=tar.gz", "-o"])
            .arg(&archive_path)
            .arg("HEAD")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        match status {
            Ok(s) if s.success() => match SourceArchive::from_existing(archive_path) {
                Ok(archive) => {
                    ctx.source_archive = Some(archive);
                    StageOutcome::Passed
                }
                Err(e) => StageOutcome::Failed(format!("source archive validation failed: {e}")),
            },
            Ok(s) => StageOutcome::Failed(format!("git archive exited with {s}")),
            Err(e) => StageOutcome::Failed(format!("git archive spawn failed: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::orchestrator::source_archive::SourceArchive;
    use std::collections::HashMap;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn make_ctx_with_archive() -> (OrchestrationContext, NamedTempFile) {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "placeholder").unwrap();
        let archive = SourceArchive::from_existing(f.path().to_path_buf()).unwrap();
        let ctx = OrchestrationContext {
            assignments: vec![],
            adapters: HashMap::new(),
            source_archive: Some(archive),
            report_dir: std::env::temp_dir(),
            stage_outcomes: HashMap::new(),
            collected_pubkeys: HashMap::new(),
            network_id: "net".to_owned(),
            node_ids: HashMap::new(),
            ssh_allow_cidrs: String::new(),
            membership_snapshot: None,
            mesh_ips: HashMap::new(),
            endpoints: HashMap::new(),
        };
        (ctx, f)
    }

    #[test]
    fn already_present_archive_passes_immediately() {
        let (mut ctx, _f) = make_ctx_with_archive();
        let outcome = PrepareSourceArchiveStage.execute(&mut ctx);
        assert_eq!(outcome, StageOutcome::Passed);
    }
}
