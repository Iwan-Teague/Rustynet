//! The live-lab **stage triage ledger** — a committed, per-`(stage, OS)` record
//! of what has already been tried against a failing stage.
//!
//! When a stage fails, the *symptom* is durably recorded
//! ([`live_lab_node_stage_results.csv`]'s `error_detail`) but the *attempted
//! remedy* is not. An agent picking the stage up later — or a second agent
//! working it concurrently — cannot learn what has been attempted, and so
//! re-derives or repeats it. This ledger closes that gap with two fields and
//! nothing more:
//!
//! - **what failed** — auto-stubbed by the `--node` engine from the
//!   `error_detail` it already writes, verbatim (an exact string is what makes
//!   "have I seen this failure before" answerable; a paraphrase is not);
//! - **our patch** — filled by the agent *before* the verification run.
//!
//! There is deliberately **no outcome field**. If a patch works the stage goes
//! green in the next run; if it fails, a new stub opens against a new commit,
//! which itself evidences that a patch landed in between. Outcome is therefore
//! a join against the run matrix, not stored state, and so it cannot drift from
//! reality. For the same reason there is no patch-commit field: because the
//! agent fills the stub before committing the fix, **the ledger row's own
//! commit is the patch commit** (`git log -- <ledger>` recovers it).
//!
//! Scope is the Rust `--node` engine only. The two orchestrators' stage
//! vocabularies do not overlap (`live_two_hop_validation` vs the frozen bash
//! archive's `linux_stage_two_hop`), so a blended history would be meaningless
//! — the same rationale that split the run matrices.
//!
//! See `documents/operations/active/LiveLabStageTriageLedgerPlan_2026-07-16.md`.
//!
//! [`live_lab_node_stage_results.csv`]: ../../../documents/operations/live_lab_node_stage_results.csv
//!
//! The `stage_triage_history`/`record_stage_patch` MCP tools that call into
//! this module are still pending (see the plan doc); until that wiring
//! lands, several `pub fn`s here have no caller anywhere in the workspace.
//! They are real, tested, working code — not placeholders — so `#[allow]`
//! them individually rather than deleting or silently stubbing them.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

/// Current record schema. Bump only with a migration for existing rows.
pub const TRIAGE_SCHEMA_VERSION: u32 = 1;

/// The only engine whose failures this ledger records (see module docs).
pub const TRIAGE_ENGINE_NODE: &str = "node";

/// Repository-relative location of the ledger.
pub const TRIAGE_LEDGER_RELATIVE_PATH: &str = "documents/operations/live_lab_stage_triage.jsonl";

/// One triage record: a stage failure and the patch attempted against it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StageTriageRecord {
    pub schema: u32,
    /// `{run_id}::{stage}` — the idempotency key.
    pub stub_id: String,
    pub ts_utc: String,
    /// Always [`TRIAGE_ENGINE_NODE`]; carried explicitly so a future engine
    /// cannot silently blend into this history.
    pub engine: String,
    pub run_id: String,
    /// The commit the FAILING run deployed — not the patch commit.
    pub run_commit: String,
    pub stage: String,
    /// `node` or `topology`. A topology-scoped stage reports once per
    /// participating node, which is why records collapse per `(run_id, stage)`.
    pub stage_scope: String,
    /// Every OS family that observed this failure.
    pub os_family: Vec<String>,
    /// Verbatim `error_detail` from the run.
    pub error: String,
    /// `None` until an agent records the attempt. A deliberate decision not to
    /// patch is expressed as a filled value (`"none: <reason>"`), not as
    /// `None` — so declining is visible and does not read as forgetting.
    pub patch: Option<String>,
}

impl StageTriageRecord {
    /// Whether this record still needs a patch description. The launch gate
    /// refuses to start a run while a stub for a planned stage is unfilled.
    #[allow(dead_code)] // pending MCP wiring, see module docs
    pub fn is_unfilled(&self) -> bool {
        self.patch
            .as_deref()
            .map(|patch| patch.trim().is_empty())
            .unwrap_or(true)
    }
}

/// The idempotency key for a `(run_id, stage)` failure.
pub fn stub_id(run_id: &str, stage: &str) -> String {
    format!("{run_id}::{stage}")
}

/// Absolute path to the committed ledger.
pub fn default_triage_ledger_path(workspace_root: &Path) -> PathBuf {
    workspace_root.join(TRIAGE_LEDGER_RELATIVE_PATH)
}

/// Read every record. A missing ledger is an empty history, not an error — the
/// first failure on a fresh clone must not be blocked by its own absence.
///
/// A malformed line fails loudly rather than being skipped: silently dropping
/// records would let the gate report "nothing unfilled" precisely when the
/// ledger is corrupt.
pub fn load_ledger(path: &Path) -> Result<Vec<StageTriageRecord>, String> {
    let body = match fs::read_to_string(path) {
        Ok(body) => body,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(format!(
                "read stage triage ledger failed ({}): {err}",
                path.display()
            ));
        }
    };
    let mut records = Vec::new();
    for (index, line) in body.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let record: StageTriageRecord = serde_json::from_str(line).map_err(|err| {
            format!(
                "parse stage triage ledger failed ({}:{}): {err}",
                path.display(),
                index + 1
            )
        })?;
        records.push(record);
    }
    Ok(records)
}

/// Append one stub, ignoring a `stub_id` already present.
///
/// Returns whether a record was written. Idempotency matters because evidence
/// finalization can run more than once for a run (interim then final, or a
/// resumed run); a duplicated stub would make one failure read as several
/// attempts.
pub fn append_stub(path: &Path, record: &StageTriageRecord) -> Result<bool, String> {
    if load_ledger(path)?
        .iter()
        .any(|existing| existing.stub_id == record.stub_id)
    {
        return Ok(false);
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "create stage triage ledger directory failed ({}): {err}",
                parent.display()
            )
        })?;
    }
    let mut line = serde_json::to_string(record)
        .map_err(|err| format!("serialize stage triage record failed: {err}"))?;
    line.push('\n');
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|err| {
            format!(
                "open stage triage ledger failed ({}): {err}",
                path.display()
            )
        })?;
    file.write_all(line.as_bytes()).map_err(|err| {
        format!(
            "append stage triage ledger failed ({}): {err}",
            path.display()
        )
    })?;
    Ok(true)
}

/// Record the patch attempted against a stub. Rewrites the ledger in place;
/// this is the one non-append mutation, and it only ever fills a `null`.
#[allow(dead_code)] // pending MCP wiring, see module docs
pub fn fill_patch(path: &Path, stub_id: &str, patch: &str) -> Result<(), String> {
    if patch.trim().is_empty() {
        return Err(
            "patch description must not be empty; to decline deliberately record \
             \"none: <reason>\""
                .to_owned(),
        );
    }
    let mut records = load_ledger(path)?;
    let record = records
        .iter_mut()
        .find(|record| record.stub_id == stub_id)
        .ok_or_else(|| format!("no stage triage stub with stub_id {stub_id:?}"))?;
    record.patch = Some(patch.trim().to_owned());
    let mut body = String::new();
    for record in &records {
        let line = serde_json::to_string(record)
            .map_err(|err| format!("serialize stage triage record failed: {err}"))?;
        body.push_str(&line);
        body.push('\n');
    }
    fs::write(path, body).map_err(|err| {
        format!(
            "rewrite stage triage ledger failed ({}): {err}",
            path.display()
        )
    })
}

/// Unfilled stubs for any of `planned_stages` — what the launch gate blocks on.
///
/// Scoped to the stages a run actually plans, so an unfilled stub for a stage
/// this run does not exercise never blocks it.
#[allow(dead_code)] // pending MCP wiring, see module docs
pub fn unfilled_for_planned_stages<'a>(
    records: &'a [StageTriageRecord],
    planned_stages: &[String],
) -> Vec<&'a StageTriageRecord> {
    records
        .iter()
        .filter(|record| record.is_unfilled() && planned_stages.contains(&record.stage))
        .collect()
}

/// Append one stub per FAILED stage from a run's node-stage rows.
///
/// Collapses per `(run_id, stage)`: a topology-scoped stage such as
/// `live_two_hop_validation` reports once per participating node, so a single
/// failure would otherwise emit four or five identical stubs and read as
/// several attempts. Every OS family that observed the failure is aggregated
/// into `os_family` instead.
///
/// Returns how many stubs were newly written. Existing `stub_id`s are left
/// alone — including their `patch`, so re-finalizing a run never erases an
/// agent's recorded attempt.
pub fn append_stubs_for_failed_stages(
    ledger_path: &Path,
    rows: &[std::collections::BTreeMap<String, String>],
) -> Result<usize, String> {
    use std::collections::BTreeMap;

    let get = |row: &BTreeMap<String, String>, key: &str| -> String {
        row.get(key).cloned().unwrap_or_default()
    };

    // stage -> accumulated stub, in first-seen order per stage name.
    let mut by_stage: BTreeMap<String, StageTriageRecord> = BTreeMap::new();
    for row in rows {
        if get(row, "status") != "fail" {
            continue;
        }
        let run_id = get(row, "run_id");
        let stage = get(row, "stage");
        if run_id.is_empty() || stage.is_empty() {
            continue;
        }
        let os_family = get(row, "os_family");
        by_stage
            .entry(stage.clone())
            .and_modify(|record| {
                if !os_family.is_empty() && !record.os_family.contains(&os_family) {
                    record.os_family.push(os_family.clone());
                }
            })
            .or_insert_with(|| StageTriageRecord {
                schema: TRIAGE_SCHEMA_VERSION,
                stub_id: stub_id(&run_id, &stage),
                // The run's own finish time — no clock call, so this stays
                // deterministic and testable.
                ts_utc: get(row, "run_finished_utc"),
                engine: TRIAGE_ENGINE_NODE.to_owned(),
                run_id,
                run_commit: get(row, "git_commit"),
                stage,
                stage_scope: get(row, "stage_scope"),
                os_family: if os_family.is_empty() {
                    Vec::new()
                } else {
                    vec![os_family]
                },
                error: get(row, "error_detail"),
                patch: None,
            });
    }

    let mut written = 0usize;
    for record in by_stage.values() {
        if append_stub(ledger_path, record)? {
            written += 1;
        }
    }
    Ok(written)
}

/// Every record for a stage, oldest first — the read path behind
/// `stage_triage_history`. `os` filters to records where that family observed
/// the failure.
#[allow(dead_code)] // pending MCP wiring, see module docs
pub fn history_for_stage<'a>(
    records: &'a [StageTriageRecord],
    stage: &str,
    os: Option<&str>,
) -> Vec<&'a StageTriageRecord> {
    records
        .iter()
        .filter(|record| record.stage == stage)
        .filter(|record| match os {
            Some(os) => record.os_family.iter().any(|family| family == os),
            None => true,
        })
        .collect()
}

/// The **push** half of the triage ledger: for every stage that FAILED in this
/// run's `rows`, render a human-facing block naming the prior fix attempts
/// already on file against that stage, so the agent picking the failure up is
/// made aware of them automatically instead of having to remember to query
/// `stage_triage_history`. Returns `None` when no prior *filled* attempt exists
/// for any failed stage (so the caller prints nothing).
///
/// "Prior attempt" = a ledger record for the same stage, from a *different*
/// run than the one that just failed, whose `patch` field is filled (a bare
/// unfilled stub is a prior failure with no recorded remedy — not an attempt to
/// surface). Records are shown oldest-first (ledger order).
///
/// This never fails a run: the caller treats an `Err` as a warning, matching
/// the ledger's "diagnostic aid, not evidence" invariant.
#[allow(dead_code)] // wired at the run-matrix finalization call site
pub fn render_prior_attempts_for_failed_stages(
    ledger_path: &Path,
    rows: &[std::collections::BTreeMap<String, String>],
) -> Result<Option<String>, String> {
    use std::collections::BTreeMap;

    let get = |row: &BTreeMap<String, String>, key: &str| row.get(key).cloned().unwrap_or_default();

    // stage -> the run_id it failed under in THIS run (first seen), so we can
    // exclude this run's own freshly-written stubs from "prior".
    let mut failed_stage_run: BTreeMap<String, String> = BTreeMap::new();
    for row in rows {
        if get(row, "status") != "fail" {
            continue;
        }
        let stage = get(row, "stage");
        if stage.is_empty() {
            continue;
        }
        let run_id = get(row, "run_id");
        failed_stage_run.entry(stage).or_insert(run_id);
    }
    if failed_stage_run.is_empty() {
        return Ok(None);
    }

    // A missing/unreadable ledger is not an error here — it just means no prior
    // history exists yet.
    if !ledger_path.exists() {
        return Ok(None);
    }
    let records = load_ledger(ledger_path)?;

    let mut blocks: Vec<String> = Vec::new();
    for (stage, this_run_id) in &failed_stage_run {
        let priors: Vec<&StageTriageRecord> = history_for_stage(&records, stage, None)
            .into_iter()
            .filter(|record| &record.run_id != this_run_id)
            .filter(|record| {
                record
                    .patch
                    .as_deref()
                    .is_some_and(|patch| !patch.trim().is_empty())
            })
            .collect();
        if priors.is_empty() {
            continue;
        }
        let mut block = format!(
            "  stage `{stage}` — {} prior fix attempt(s) already on file:\n",
            priors.len()
        );
        for record in &priors {
            let commit = record.run_commit.get(..12).unwrap_or(&record.run_commit);
            let os = if record.os_family.is_empty() {
                "?".to_owned()
            } else {
                record.os_family.join(",")
            };
            let error = record.error.trim();
            let patch = record.patch.as_deref().unwrap_or_default().trim();
            block.push_str(&format!(
                "    - [{commit} {os}] error: {error}\n      tried:  {patch}\n"
            ));
        }
        blocks.push(block);
    }

    if blocks.is_empty() {
        return Ok(None);
    }

    let mut out = String::from(
        "\n\u{2500}\u{2500} PRIOR TRIAGE ATTEMPTS \u{2500}\u{2500} do not repeat a failed fix; \
         see the `stage_triage_history` MCP tool for the full record \u{2500}\u{2500}\n",
    );
    for block in blocks {
        out.push_str(&block);
    }
    Ok(Some(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_ledger(name: &str) -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        // Unique per call: these tests run in parallel in one process, and a
        // shared path would let one clobber another's ledger.
        std::env::temp_dir().join(format!(
            "stage_triage_{}_{}_{}.jsonl",
            name,
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ))
    }

    fn record(run_id: &str, stage: &str, patch: Option<&str>) -> StageTriageRecord {
        StageTriageRecord {
            schema: TRIAGE_SCHEMA_VERSION,
            stub_id: stub_id(run_id, stage),
            ts_utc: "2026-07-16T12:17:17Z".to_owned(),
            engine: TRIAGE_ENGINE_NODE.to_owned(),
            run_id: run_id.to_owned(),
            run_commit: "bab155abd7cc797d7f235015eca2cec48e5ef272".to_owned(),
            stage: stage.to_owned(),
            stage_scope: "topology".to_owned(),
            os_family: vec!["rocky".to_owned(), "debian".to_owned()],
            error: "enforce-host failed for rocky@192.168.64.105:22 with status 1".to_owned(),
            patch: patch.map(str::to_owned),
        }
    }

    #[test]
    fn missing_ledger_is_an_empty_history_not_an_error() {
        let path = temp_ledger("missing");
        assert_eq!(load_ledger(path.as_path()).expect("load"), Vec::new());
    }

    #[test]
    fn append_round_trips_and_is_idempotent_on_stub_id() {
        let path = temp_ledger("idempotent");
        let stub = record("run-1", "live_two_hop_validation", None);
        assert!(append_stub(path.as_path(), &stub).expect("first append"));
        // Finalization can run more than once per run; a duplicate stub would
        // make one failure read as several attempts.
        assert!(
            !append_stub(path.as_path(), &stub).expect("second append"),
            "an existing stub_id must not append again"
        );
        let loaded = load_ledger(path.as_path()).expect("load");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0], stub);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn a_stub_without_a_patch_is_unfilled() {
        assert!(record("run-1", "s", None).is_unfilled());
        assert!(
            record("run-1", "s", Some("   ")).is_unfilled(),
            "whitespace is not a patch description"
        );
        assert!(!record("run-1", "s", Some("granted the entry exit_server")).is_unfilled());
        // Declining deliberately is a FILLED record: it must not read as the
        // agent having forgotten, or the environmental non-defects would wedge
        // the loop forever.
        assert!(!record("run-1", "s", Some("none: environmental — VM-reset hang")).is_unfilled());
    }

    #[test]
    fn fill_patch_sets_the_description_and_rejects_empty() {
        let path = temp_ledger("fill");
        let stub = record("run-1", "live_two_hop_validation", None);
        append_stub(path.as_path(), &stub).expect("append");
        assert!(
            fill_patch(path.as_path(), &stub.stub_id, "  ").is_err(),
            "an empty patch must be rejected, not silently accepted"
        );
        fill_patch(path.as_path(), &stub.stub_id, " granted Entry exit_server ").expect("fill");
        let loaded = load_ledger(path.as_path()).expect("load");
        assert_eq!(loaded.len(), 1, "fill must not duplicate the record");
        assert_eq!(
            loaded[0].patch.as_deref(),
            Some("granted Entry exit_server")
        );
        assert!(!loaded[0].is_unfilled());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn fill_patch_on_an_unknown_stub_is_an_error() {
        let path = temp_ledger("unknown");
        append_stub(path.as_path(), &record("run-1", "s", None)).expect("append");
        assert!(fill_patch(path.as_path(), "run-9::nope", "x").is_err());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn the_launch_gate_only_blocks_on_stages_this_run_plans() {
        let records = vec![
            record("run-1", "live_two_hop_validation", None),
            record("run-2", "live_managed_dns_validation", Some("filled")),
            record("run-3", "live_relay_validation", None),
        ];
        let planned = vec![
            "live_two_hop_validation".to_owned(),
            "live_managed_dns_validation".to_owned(),
        ];
        let blocking = unfilled_for_planned_stages(&records, &planned);
        assert_eq!(blocking.len(), 1);
        assert_eq!(blocking[0].stage, "live_two_hop_validation");
        // live_relay_validation is unfilled but NOT planned: a stage this run
        // does not exercise must never block it.
        assert!(blocking.iter().all(|r| r.stage != "live_relay_validation"));
    }

    #[test]
    fn history_filters_by_stage_and_os() {
        let mut other = record("run-2", "live_two_hop_validation", Some("p"));
        other.os_family = vec!["ubuntu".to_owned()];
        let records = vec![
            record("run-1", "live_two_hop_validation", None),
            other,
            record("run-3", "live_managed_dns_validation", None),
        ];
        assert_eq!(
            history_for_stage(&records, "live_two_hop_validation", None).len(),
            2
        );
        assert_eq!(
            history_for_stage(&records, "live_two_hop_validation", Some("rocky")).len(),
            1
        );
        assert_eq!(
            history_for_stage(&records, "live_two_hop_validation", Some("ubuntu")).len(),
            1
        );
        assert!(history_for_stage(&records, "live_two_hop_validation", Some("windows")).is_empty());
    }

    fn node_row(stage: &str, status: &str, os: &str) -> std::collections::BTreeMap<String, String> {
        [
            ("run_id", "livelab-1784216363-17b11ab"),
            ("run_finished_utc", "2026-07-16T15:12:00Z"),
            ("git_commit", "17b11abdeadbeef"),
            ("stage", stage),
            ("stage_scope", "topology"),
            ("status", status),
            ("os_family", os),
            (
                "error_detail",
                "root command failed for debian@192.168.64.4:22 with status 1",
            ),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect()
    }

    #[test]
    fn auto_stub_collapses_a_topology_failure_into_one_record() {
        let path = temp_ledger("collapse");
        // The real shape: two_hop is stage_scope=topology, so ONE failure
        // reports once per participating node. Without collapsing, this reads
        // as four separate attempts.
        let rows = vec![
            node_row("live_two_hop_validation", "fail", "debian"),
            node_row("live_two_hop_validation", "fail", "rocky"),
            node_row("live_two_hop_validation", "fail", "fedora"),
            node_row("live_two_hop_validation", "fail", "debian"),
            node_row("traffic_test_matrix", "pass", "debian"),
        ];
        let written = append_stubs_for_failed_stages(path.as_path(), &rows).expect("stub");
        assert_eq!(written, 1, "one failure = one stub, not one per node");
        let loaded = load_ledger(path.as_path()).expect("load");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].stage, "live_two_hop_validation");
        assert_eq!(
            loaded[0].os_family,
            vec!["debian", "rocky", "fedora"],
            "every OS that observed it is aggregated, de-duplicated, in first-seen order"
        );
        assert!(loaded[0].is_unfilled(), "a fresh stub awaits its patch");
        assert!(loaded[0].error.contains("192.168.64.4"));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn auto_stub_ignores_passing_stages_and_never_overwrites_a_recorded_patch() {
        let path = temp_ledger("no_clobber");
        let rows = vec![node_row("live_two_hop_validation", "fail", "debian")];
        append_stubs_for_failed_stages(path.as_path(), &rows).expect("stub");
        let id = load_ledger(path.as_path()).expect("load")[0]
            .stub_id
            .clone();
        fill_patch(path.as_path(), &id, "granted the Entry role exit_server").expect("fill");

        // Finalization can run again for the same run (interim -> final, or a
        // resume). It must not erase the agent's recorded attempt.
        let written = append_stubs_for_failed_stages(path.as_path(), &rows).expect("re-stub");
        assert_eq!(written, 0, "an existing stub must not be rewritten");
        let loaded = load_ledger(path.as_path()).expect("load");
        assert_eq!(loaded.len(), 1);
        assert_eq!(
            loaded[0].patch.as_deref(),
            Some("granted the Entry role exit_server"),
            "re-finalizing must never clobber a filled patch"
        );

        // Passing stages produce nothing at all.
        let clean = temp_ledger("clean");
        let passing = vec![node_row("traffic_test_matrix", "pass", "debian")];
        assert_eq!(
            append_stubs_for_failed_stages(clean.as_path(), &passing).expect("none"),
            0
        );
        assert!(load_ledger(clean.as_path()).expect("load").is_empty());
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&clean);
    }

    #[test]
    fn a_malformed_line_fails_loudly_rather_than_being_skipped() {
        let path = temp_ledger("malformed");
        fs::write(path.as_path(), "{\"not\":\"a record\"}\n").expect("write");
        // Skipping unparseable rows would let the launch gate report "nothing
        // unfilled" exactly when the ledger is corrupt.
        assert!(load_ledger(path.as_path()).is_err());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn prior_filled_attempts_are_pushed_for_a_refailed_stage() {
        let path = temp_ledger("prior-push");
        // A prior run recorded a FILLED attempt against stage `s`.
        assert!(
            append_stub(
                path.as_path(),
                &record("prior-run", "s", Some("granted Entry exit_server")),
            )
            .expect("append prior")
        );
        // An unrelated stage with only an unfilled stub must never surface.
        assert!(
            append_stub(path.as_path(), &record("prior-run", "other", None)).expect("append other")
        );

        // This run re-fails stage `s` (node_row's run_id differs from "prior-run").
        let rows = vec![
            node_row("s", "fail", "debian"),
            node_row("t", "pass", "debian"),
        ];
        let block = render_prior_attempts_for_failed_stages(path.as_path(), &rows)
            .expect("render ok")
            .expect("a prior filled attempt must be surfaced");
        assert!(
            block.contains("stage `s`"),
            "names the failed stage: {block}"
        );
        assert!(
            block.contains("granted Entry exit_server"),
            "shows the prior patch verbatim: {block}"
        );
        assert!(
            !block.contains("`other`"),
            "an unfilled/unrelated stage is not surfaced: {block}"
        );

        // A failed stage with no prior attempt on file surfaces nothing.
        assert!(
            render_prior_attempts_for_failed_stages(
                path.as_path(),
                &[node_row("brand_new_stage", "fail", "debian")],
            )
            .expect("render ok")
            .is_none(),
            "no prior attempt -> nothing pushed"
        );

        // Exclusion: a filled record from THIS SAME run is the current attempt,
        // not prior history, and must not be echoed back.
        assert!(
            append_stub(
                path.as_path(),
                &record("livelab-1784216363-17b11ab", "u", Some("current-attempt")),
            )
            .expect("append same-run")
        );
        assert!(
            render_prior_attempts_for_failed_stages(
                path.as_path(),
                &[node_row("u", "fail", "debian")],
            )
            .expect("render ok")
            .is_none(),
            "a filled record from this run is the current attempt, not prior history"
        );

        let _ = fs::remove_file(&path);
    }
}
