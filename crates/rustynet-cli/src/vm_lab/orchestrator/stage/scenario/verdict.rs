//! The candidate-verifier verdict — `evidence_verdict.v1.json` (L0.5,
//! `LiveLabTestCoverageImplementationDesign_2026-08-19` §3.1.2).
//!
//! The independent candidate verifier writes this for EVERY terminal invocation,
//! including a rejection. It is the durable record the native finalizer reads
//! (it never recomputes or overrides it — L0.6) and that the monitor
//! cross-checks (a changed/missing artifact digest is stale, non-green — L0.7).
//! It carries no secrets: only digests, reason codes, and writer provenance.
//!
//! Publishing the verdict deliberately does NOT require the matrix row or final
//! marker — that removes the circular ordering the old design had (the marker
//! required the verdict and the verifier cross-checked the marker). The verdict
//! is produced from the immutable plan + scenario evidence alone; promotion
//! reads it afterwards.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::pass_certificate::Assessment;

/// The only accepted verdict schema version.
pub const EVIDENCE_VERDICT_SCHEMA_VERSION: u64 = 1;

/// `<report_dir>`-relative path of the candidate verdict.
pub const EVIDENCE_VERDICT_RELATIVE_PATH: &str = "state/evidence_verdict.v1.json";

/// Who writes the verdict, for provenance in the artifact.
const WRITER: &str = concat!(
    "rustynet-cli candidate-verifier/v",
    env!("CARGO_PKG_VERSION")
);

/// The terminal verdict. `Passed` supports a release claim only when bound to
/// the same run id + digests (L0.6); `Rejected` records a non-pass; `Unavailable`
/// means the verifier could not run at all (e.g. no `scenario.v1`) — never a pass.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Passed,
    Rejected,
    Unavailable,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Passed => "passed",
            Verdict::Rejected => "rejected",
            Verdict::Unavailable => "unavailable",
        }
    }
}

/// The candidate verdict document.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceVerdict {
    pub schema_version: u64,
    /// The run instance this verdict belongs to — a release-pass promotion binds
    /// on this (§3.1.2).
    pub run_instance_id: String,
    /// Digest of the resolved plan this verdict was computed against.
    pub plan_digest: String,
    /// Digest of the evidence contract the scenario was verified against.
    pub contract_digest: String,
    pub verdict: Verdict,
    /// Typed reason codes (the `ReasonCode` tokens, plus `failed` for a hard
    /// failure). Empty for a pass.
    pub reason_codes: Vec<String>,
    /// `reference -> sha256` of every artifact the verifier bound. The monitor
    /// re-checks these still match; a changed or missing input is stale evidence.
    pub artifact_digests: BTreeMap<String, String>,
    /// Writer binary + version, for provenance.
    pub writer: String,
    /// Human-readable detail (never a secret).
    pub detail: String,
}

impl EvidenceVerdict {
    /// Build a verdict from an [`Assessment`]. The run id / plan digest /
    /// contract digest come from the INDEPENDENT run state, and `artifact_digests`
    /// is the exact map the verifier bound while evaluating.
    pub fn from_assessment(
        assessment: &Assessment,
        run_instance_id: &str,
        plan_digest: &str,
        contract_digest: &str,
        artifact_digests: BTreeMap<String, String>,
    ) -> EvidenceVerdict {
        let (verdict, reason_codes, detail) = match assessment {
            Assessment::Passed(_) => (Verdict::Passed, Vec::new(), String::new()),
            Assessment::NotProven(reason, d) => (
                Verdict::Rejected,
                vec![reason.as_str().to_owned()],
                d.clone(),
            ),
            // A hard failure (invariant disproved / cleanup residue) rejects the
            // pass claim; the `failed` marker distinguishes it from a NotProven.
            Assessment::Failed(d) => (Verdict::Rejected, vec!["failed".to_owned()], d.clone()),
        };
        EvidenceVerdict {
            schema_version: EVIDENCE_VERDICT_SCHEMA_VERSION,
            run_instance_id: run_instance_id.to_owned(),
            plan_digest: plan_digest.to_owned(),
            contract_digest: contract_digest.to_owned(),
            verdict,
            reason_codes,
            artifact_digests,
            writer: WRITER.to_owned(),
            detail,
        }
    }

    /// An `Unavailable` verdict — the verifier could not run at all. Still
    /// written (every terminal invocation records one) and never a pass.
    pub fn unavailable(
        run_instance_id: &str,
        plan_digest: &str,
        contract_digest: &str,
        detail: &str,
    ) -> EvidenceVerdict {
        EvidenceVerdict {
            schema_version: EVIDENCE_VERDICT_SCHEMA_VERSION,
            run_instance_id: run_instance_id.to_owned(),
            plan_digest: plan_digest.to_owned(),
            contract_digest: contract_digest.to_owned(),
            verdict: Verdict::Unavailable,
            reason_codes: vec!["unavailable".to_owned()],
            artifact_digests: BTreeMap::new(),
            writer: WRITER.to_owned(),
            detail: detail.to_owned(),
        }
    }

    pub fn is_pass(&self) -> bool {
        self.verdict == Verdict::Passed
    }
}

/// Atomically write `evidence_verdict.v1.json` under `report_root` (tmp+rename).
pub fn write_evidence_verdict(report_root: &Path, verdict: &EvidenceVerdict) -> Result<(), String> {
    let path = report_root.join(EVIDENCE_VERDICT_RELATIVE_PATH);
    let parent = path
        .parent()
        .ok_or_else(|| format!("evidence_verdict path has no parent: {}", path.display()))?;
    std::fs::create_dir_all(parent).map_err(|e| {
        format!(
            "create state dir for evidence_verdict failed ({}): {e}",
            parent.display()
        )
    })?;
    let body = serde_json::to_vec_pretty(verdict)
        .map_err(|e| format!("serialize evidence_verdict: {e}"))?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, body)
        .map_err(|e| format!("write evidence_verdict tmp failed ({}): {e}", tmp.display()))?;
    std::fs::rename(&tmp, &path).map_err(|e| {
        format!(
            "rename evidence_verdict into place failed ({}): {e}",
            path.display()
        )
    })
}

/// Read `evidence_verdict.v1.json`. A missing file, malformed JSON, or unknown
/// schema version is an error — a promotion step that cannot read a valid
/// verdict fails closed rather than treating it as a pass.
pub fn read_evidence_verdict(report_root: &Path) -> Result<EvidenceVerdict, String> {
    let path = report_root.join(EVIDENCE_VERDICT_RELATIVE_PATH);
    let body = std::fs::read_to_string(&path)
        .map_err(|e| format!("read evidence_verdict {}: {e}", path.display()))?;
    let v: EvidenceVerdict = serde_json::from_str(&body)
        .map_err(|e| format!("parse evidence_verdict {}: {e}", path.display()))?;
    if v.schema_version != EVIDENCE_VERDICT_SCHEMA_VERSION {
        return Err(format!(
            "evidence_verdict {} has unsupported schema_version {} (expected {EVIDENCE_VERDICT_SCHEMA_VERSION})",
            path.display(),
            v.schema_version
        ));
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::orchestrator::error::ReasonCode;

    fn digests() -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        m.insert("state/x.txt".to_owned(), "abc".to_owned());
        m
    }

    #[test]
    fn a_not_proven_assessment_becomes_a_rejected_verdict_with_its_reason_code() {
        let a = Assessment::NotProven(ReasonCode::StaleEvidence, "wrong generation".to_owned());
        let v = EvidenceVerdict::from_assessment(&a, "run-1", "plan-d", "contract-d", digests());
        assert_eq!(v.verdict, Verdict::Rejected);
        assert_eq!(v.reason_codes, vec!["stale_evidence".to_owned()]);
        assert!(!v.is_pass());
        assert_eq!(v.run_instance_id, "run-1");
        assert_eq!(v.plan_digest, "plan-d");
    }

    #[test]
    fn a_failed_assessment_is_rejected_with_the_failed_marker() {
        let a = Assessment::Failed("cleanup residue".to_owned());
        let v = EvidenceVerdict::from_assessment(&a, "run-1", "p", "c", BTreeMap::new());
        assert_eq!(v.verdict, Verdict::Rejected);
        assert_eq!(v.reason_codes, vec!["failed".to_owned()]);
    }

    #[test]
    fn an_unavailable_verdict_is_never_a_pass() {
        let v = EvidenceVerdict::unavailable("run-1", "p", "c", "no scenario.v1");
        assert_eq!(v.verdict, Verdict::Unavailable);
        assert!(!v.is_pass());
    }

    #[test]
    fn a_verdict_round_trips_through_disk() {
        let a = Assessment::NotProven(ReasonCode::MissingWitness, "no witness".to_owned());
        let v = EvidenceVerdict::from_assessment(&a, "run-9", "pd", "cd", digests());
        let dir =
            std::env::temp_dir().join(format!("rustynet-verdict-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        write_evidence_verdict(&dir, &v).expect("write");
        let back = read_evidence_verdict(&dir).expect("read");
        assert_eq!(v, back);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_rejects_an_unknown_schema_version() {
        let dir =
            std::env::temp_dir().join(format!("rustynet-verdict-schema-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("state")).unwrap();
        std::fs::write(
            dir.join(EVIDENCE_VERDICT_RELATIVE_PATH),
            br#"{"schema_version":999,"run_instance_id":"r","plan_digest":"p","contract_digest":"c","verdict":"passed","reason_codes":[],"artifact_digests":{},"writer":"w","detail":""}"#,
        )
        .unwrap();
        let err = read_evidence_verdict(&dir).unwrap_err();
        assert!(err.contains("schema_version"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
