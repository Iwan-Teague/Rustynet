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
//! Wiring status of the plan's two MCP tools (plan §3.5), which differs per
//! tool and is worth stating exactly, because the two have different safety
//! properties:
//!
//! - **`stage_triage_history` (read) — live.** `rustynet-mcp-lab-state`
//!   implements it directly, re-parsing this JSONL rather than calling in here:
//!   `rustynet-mcp` does not depend on `rustynet-cli`, and this module is
//!   private and `vm-lab`-gated. A second *reader* is benign.
//! - **`record_stage_patch` (write) — backed here, MCP wrapper pending.** The
//!   write side must NOT be re-implemented in the MCP: [`fill_patch`] performs
//!   a locked, atomic whole-file rewrite, and a second independently written
//!   writer is precisely how one file acquires two different definitions of
//!   "serialized" (see `crate::append_lock`). The single writer is the
//!   `ops live-lab-record-stage-patch` verb
//!   ([`execute_ops_record_stage_patch`]); an MCP wrapper should shell out to
//!   it argv-only rather than touch the ledger itself.
//!
//! The launch gate ([`enforce_launch_gate`], plan §3.6/T3) is **wired and
//! enforcing**, fail-closed, at the `--node` orchestrator's launch point
//! (`vm_lab::orchestrator::native`), with no bypass flag. It carries one
//! temporary deviation from §3.6 — [`TRIAGE_GATE_HISTORICAL_WATERMARK_UTC`],
//! which defers the pre-existing backlog so the gate could be turned on without
//! either stopping all lab work or provoking fabricated dispositions. **That
//! constant is meant to be deleted**; its rustdoc carries the retirement steps,
//! and every launch prints how many stubs are still deferred so it cannot rot
//! unnoticed.

use crate::append_lock::{acquire_append_lock, lock_path_for};
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

/// `ops live-lab-record-stage-patch` — record the attempted remedy for a stub.
///
/// The stub is addressed either directly by `stub_id`, or by the
/// `(run_id, stage)` pair it is derived from (plan §3.5).
///
/// `ledger` is required rather than defaulted. This project routinely drives
/// several checkouts at once (the lab host box, per-job worktrees), and a
/// hidden default resolved from the build-time manifest directory would let a
/// fill land in a different checkout's ledger than the operator meant — the
/// same "which checkout holds this evidence" problem the fleet-evidence work
/// exists to close. An explicit path cannot be silently wrong.
///
/// **Known inconsistency, deliberately not "fixed" here.** The auto-stub path
/// does exactly what this rejects: `live_lab_run_matrix.rs` resolves the ledger
/// via `default_triage_ledger_path(workspace_root_path())`, and that root is
/// `env!("CARGO_MANIFEST_DIR")` — build-time-derived. A binary run outside its
/// build tree therefore writes (and `create_dir_all`s) a ledger nobody reads.
/// Changing it is a behaviour change to the evidence-finalization path and
/// wants its own live verification, so it is recorded rather than bundled in.
/// See `FleetEvidenceCollectionPlan_2026-07-28.md`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordStagePatchConfig {
    pub ledger: PathBuf,
    pub stub_id: Option<String>,
    pub run_id: Option<String>,
    pub stage: Option<String>,
    pub patch: String,
}

/// Resolve the addressed stub and fill it. Ambiguous or absent addressing is an
/// error: guessing which stub was meant would record an attempt against the
/// wrong failure, which is worse than recording none.
pub fn execute_ops_record_stage_patch(config: RecordStagePatchConfig) -> Result<String, String> {
    let stub = match (
        config.stub_id.as_deref(),
        config.run_id.as_deref(),
        config.stage.as_deref(),
    ) {
        (Some(id), None, None) => id.to_owned(),
        (None, Some(run_id), Some(stage)) => stub_id(run_id, stage),
        (Some(_), _, _) => {
            return Err("pass either --stub-id or --run-id with --stage, not both".to_owned());
        }
        (None, _, _) => {
            return Err(
                "addressing a stub requires --stub-id, or --run-id together with --stage"
                    .to_owned(),
            );
        }
    };
    fill_patch(
        config.ledger.as_path(),
        stub.as_str(),
        config.patch.as_str(),
    )?;
    Ok(format!(
        "recorded patch against stage triage stub {stub:?} in {}",
        config.ledger.display()
    ))
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
    // The parent must exist before the lock file can be created beside the
    // ledger, so this precedes the critical section.
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "create stage triage ledger directory failed ({}): {err}",
                parent.display()
            )
        })?;
    }
    // The dedupe read and the append are ONE critical section. Split, they are a
    // TOCTOU: two finalizers (interim then final, or a resumed run racing a
    // concurrent agent) both read a ledger lacking the stub_id, both conclude
    // they must write, and both append — a duplicate stub makes one failure read
    // as several attempts, which is exactly the signal this ledger exists to
    // give. The unserialized `write_all`s are the second hazard the lock closes.
    let _lock = acquire_append_lock(lock_path_for(path).as_path(), "stage triage ledger")?;
    if load_ledger(path)?
        .iter()
        .any(|existing| existing.stub_id == record.stub_id)
    {
        return Ok(false);
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
/// this is the one non-append mutation, and it only ever fills an unfilled stub.
///
/// Three properties this function must keep, each of which it was missing:
///
/// 1. **It refuses to overwrite a filled stub.** The whole value of the ledger
///    is that a second agent can see what a first already tried; silently
///    replacing that erases the only record of it. Declining to patch is
///    expressed as a filled `"none: <reason>"` (§3.3), so a filled stub is
///    always a deliberate answer and never a placeholder to clobber. Re-filling
///    is therefore an error, not an update.
/// 2. **It holds the same append lock as [`append_stub`].** This is a
///    read-modify-write of the WHOLE file, so without the lock it races the
///    engine's auto-stub (which fires at evidence finalization, possibly while
///    an agent is filling) and drops every record appended since its own read.
/// 3. **It replaces the ledger by tmp + rename, inside the lock**, rather than
///    with a bare `fs::write` that truncates in place. Scope of that guarantee,
///    stated exactly because "atomic" invites over-reading:
///    - **Process crash: covered.** A death mid-write leaves a stale-but-intact
///      ledger plus a stray `.tmp`, never a truncated ledger.
///    - **Power loss / kernel panic: NOT covered.** There is no `sync_all` on
///      the temporary file and no directory fsync, so the rename can reach disk
///      while the tmp's data blocks have not. Adding both would close it.
///    - **The fixed `.tmp` name is safe ONLY because of the lock in (2).** Two
///      writers inside the critical section can never share it; a writer that
///      skipped the lock would have one `fs::write` a partial body that the
///      other then `rename`s into place — corrupting the ledger rather than
///      merely truncating it, which is strictly worse than the bug this fixes.
///      Any future writer MUST take `lock_path_for(path)`; see the module docs
///      on why the MCP wrapper shells out instead of writing directly.
pub fn fill_patch(path: &Path, stub_id: &str, patch: &str) -> Result<(), String> {
    if patch.trim().is_empty() {
        return Err(
            "patch description must not be empty; to decline deliberately record \
             \"none: <reason>\""
                .to_owned(),
        );
    }
    // One critical section covering the read, the match and the rewrite —
    // the same lock `append_stub` takes, because these two mutate one file.
    let _lock = acquire_append_lock(lock_path_for(path).as_path(), "stage triage ledger")?;
    let mut records = load_ledger(path)?;
    let record = records
        .iter_mut()
        .find(|record| record.stub_id == stub_id)
        .ok_or_else(|| format!("no stage triage stub with stub_id {stub_id:?}"))?;
    if !record.is_unfilled() {
        return Err(format!(
            "stage triage stub {stub_id:?} is already filled: {:?}; refusing to overwrite \
             a recorded attempt (open a new stub by re-running the stage instead)",
            record.patch.as_deref().unwrap_or_default()
        ));
    }
    record.patch = Some(patch.trim().to_owned());
    let mut body = String::new();
    for record in &records {
        let line = serde_json::to_string(record)
            .map_err(|err| format!("serialize stage triage record failed: {err}"))?;
        body.push_str(&line);
        body.push('\n');
    }
    let tmp = {
        let mut value = path.as_os_str().to_os_string();
        value.push(".tmp");
        PathBuf::from(value)
    };
    fs::write(&tmp, body).map_err(|err| {
        format!(
            "write stage triage ledger tmp failed ({}): {err}",
            tmp.display()
        )
    })?;
    fs::rename(&tmp, path).map_err(|err| {
        format!(
            "replace stage triage ledger failed ({}): {err}",
            path.display()
        )
    })
}

/// Unfilled stubs for any of `planned_stages` — what the launch gate blocks on.
///
/// Scoped to the stages a run actually plans, so an unfilled stub for a stage
/// this run does not exercise never blocks it.
pub fn unfilled_for_planned_stages<'a>(
    records: &'a [StageTriageRecord],
    planned_stages: &[String],
) -> Vec<&'a StageTriageRecord> {
    records
        .iter()
        .filter(|record| record.is_unfilled() && planned_stages.contains(&record.stage))
        .collect()
}

// ─── LAUNCH GATE (plan §3.6 / T3) ────────────────────────────────────────────
//
// ##################################################################
// #  MANUAL ACTION REQUIRED LATER — THIS CONSTANT IS TEMPORARY.     #
// ##################################################################
//
/// Unfilled stubs created STRICTLY BEFORE this instant do not block a launch.
///
/// # Why this exists
///
/// The gate as specified in §3.6 blocks a run when any *planned* stage has an
/// unfilled stub. When the gate was built, **36 of the ledger's 51 stubs were
/// unfilled**, across 31 runs, and they included `preflight`, `bootstrap_hosts`
/// and `cleanup` — stages in every plan, including a focused mac/win cell under
/// `--skip-linux-live-suite`. Wiring §3.6 literally would therefore have blocked
/// *every* live-lab run until that historical backlog was written up, and
/// filling 31 runs' worth of stubs quickly to unblock the lab would have
/// produced exactly the fabricated dispositions this ledger exists to prevent.
///
/// So enforcement is **full strength for every stub created from now on**, and
/// deferred only for the historical backlog. There is deliberately **no bypass
/// flag** — see [`enforce_launch_gate`].
///
/// # HOW TO RETIRE THIS (the manual work this constant is standing in for)
///
/// 1. List what is still deferred. Every launch prints the count; to see them:
///    `rustynet ops live-lab-record-stage-patch` has no list mode, so use the
///    MCP `stage_triage_history` tool, or read the ledger directly:
///    `jq -r 'select(.patch == null) | "\(.ts_utc)  \(.stub_id)"' \
///       documents/operations/live_lab_stage_triage.jsonl | sort`
/// 2. Disposition each one — a real remedy, or a deliberate decline recorded as
///    `"none: <reason>"` (§3.3). Do this as you touch each stage during normal
///    lab work; a stub you are actively investigating is cheap to fill honestly,
///    which is how the ledger's 15 good entries were written. Do NOT bulk-fill.
///    `rustynet ops live-lab-record-stage-patch --ledger <path> --stub-id <id> --patch <text>`
/// 3. When the count printed at launch reaches zero, **delete this constant and
///    the `is_deferred_historical_stub` call in [`enforce_launch_gate`]**. The
///    gate then becomes byte-for-byte §3.6 as written, with no behaviour change
///    on that day — because with an empty backlog the filter is already a no-op.
/// 4. Record the retirement in `LiveLabStageTriageLedgerPlan_2026-07-16.md` §5.
///
/// Until step 3, this constant is the ONLY deviation from the signed-off plan.
pub const TRIAGE_GATE_HISTORICAL_WATERMARK_UTC: &str = "2026-07-28T00:00:00Z";

/// Whether `ts_utc` is the exact fixed-width RFC3339 Zulu shape the engine
/// writes (`YYYY-MM-DDTHH:MM:SSZ`). Only that shape may be compared as a string.
///
/// Fail-closed rationale: string ordering is chronological ONLY for this exact
/// shape. Any other shape — short, offset-bearing, fractional seconds — could
/// sort before the watermark and silently exempt a brand-new stub from the gate.
/// A stub whose timestamp is not this shape is therefore treated as NOT
/// historical, i.e. it blocks.
fn is_fixed_width_zulu_timestamp(ts_utc: &str) -> bool {
    let bytes = ts_utc.as_bytes();
    if bytes.len() != 20 || bytes[19] != b'Z' {
        return false;
    }
    for (index, byte) in bytes.iter().enumerate().take(19) {
        let ok = match index {
            4 | 7 => *byte == b'-',
            10 => *byte == b'T',
            13 | 16 => *byte == b':',
            _ => byte.is_ascii_digit(),
        };
        if !ok {
            return false;
        }
    }
    true
}

/// Whether this stub predates the watermark and is therefore deferred.
/// Anything not provably historical blocks (see [`is_fixed_width_zulu_timestamp`]).
fn is_deferred_historical_stub(record: &StageTriageRecord) -> bool {
    is_fixed_width_zulu_timestamp(record.ts_utc.as_str())
        && record.ts_utc.as_str() < TRIAGE_GATE_HISTORICAL_WATERMARK_UTC
}

/// Outcome of a passing gate check. Carries the deferred-backlog count so the
/// launch path can print it on EVERY run — the backlog must stay visible, or the
/// watermark above quietly becomes permanent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TriageGateReport {
    /// Unfilled stubs for planned stages that the watermark deferred.
    pub deferred_historical: usize,
}

/// Refuse to launch while a planned stage has an unfilled stub (plan §3.6/T3).
///
/// The thing being prevented is *verifying without having recorded what you are
/// verifying*: re-running a stage whose last failure has no recorded remedy
/// produces a result nobody can attribute to a change.
///
/// **There is no bypass flag, and none may be added.** A `--force` becomes the
/// default under deadline pressure, and CLAUDE.md §3 forbids a downgrade branch
/// in a hardened path. The sanctioned escape hatch already exists and is
/// honest: fill the stub with `"none: <reason>"`, which keeps the decision
/// visible instead of erasing it.
///
/// Fails closed on an unreadable or malformed ledger — [`load_ledger`]
/// propagates that rather than reading it as "nothing outstanding".
pub fn enforce_launch_gate(
    ledger_path: &Path,
    planned_stages: &[String],
) -> Result<TriageGateReport, String> {
    let records = load_ledger(ledger_path)?;
    let outstanding = unfilled_for_planned_stages(&records, planned_stages);
    let (deferred, blocking): (Vec<_>, Vec<_>) = outstanding
        .into_iter()
        .partition(|record| is_deferred_historical_stub(record));

    if blocking.is_empty() {
        return Ok(TriageGateReport {
            deferred_historical: deferred.len(),
        });
    }

    let mut detail = String::new();
    for record in &blocking {
        detail.push_str(&format!(
            "\n  - {} (stage {}, failed {})\n      error: {}",
            record.stub_id,
            record.stage,
            record.ts_utc,
            record.error.lines().next().unwrap_or("").trim()
        ));
    }
    Err(format!(
        "live-lab launch refused: {} planned stage(s) have a failure with no recorded remedy.\n\
         Record what you changed BEFORE re-running them, otherwise the run cannot be attributed \
         to anything.{detail}\n\n\
         Fill each with:\n  \
         rustynet ops live-lab-record-stage-patch --ledger {} --stub-id <stub_id> --patch <what you changed>\n\
         To decline deliberately, record the reason instead of a fix:\n  \
         ... --patch \"none: <reason>\"\n\
         There is no bypass flag by design (see enforce_launch_gate docs).",
        blocking.len(),
        ledger_path.display(),
    ))
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

    /// The dedupe read and the append must be ONE critical section.
    ///
    /// This is the negative control for the `append_stub` flock: every thread is
    /// held at a barrier until all of them are ready, so they all enter the
    /// `stub_id` dedupe read together. Serialized, exactly one observes an absent
    /// stub_id and writes. Unserialized, they all observe it absent and all
    /// append — so removing the lock makes this fail on the record count, not on
    /// a timing coincidence.
    #[test]
    fn concurrent_appends_of_one_stub_id_write_exactly_one_record() {
        use std::sync::{Arc, Barrier};

        const THREADS: usize = 8;
        let path = temp_ledger("concurrent");
        let barrier = Arc::new(Barrier::new(THREADS));

        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let path = path.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    // Same run_id + stage in every thread => one stub_id, so a
                    // correct implementation writes it once.
                    let stub = record("run-race", "live_two_hop_validation", None);
                    barrier.wait();
                    append_stub(path.as_path(), &stub).expect("append must not error")
                })
            })
            .collect();

        let wrote = handles
            .into_iter()
            .filter(|_| true)
            .map(|handle| handle.join().expect("thread panicked"))
            .filter(|written| *written)
            .count();

        let loaded = load_ledger(path.as_path()).expect("ledger must still parse");
        assert_eq!(
            loaded.len(),
            1,
            "{THREADS} concurrent appends of one stub_id must leave exactly one \
             record; found {} (duplicate stubs make one failure read as several \
             attempts, and interleaved writes can also corrupt a line)",
            loaded.len()
        );
        assert_eq!(
            wrote, 1,
            "exactly one caller may report having written the stub"
        );

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(crate::append_lock::lock_path_for(path.as_path()));
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

    /// A filled stub is always a deliberate answer — a decision not to patch is
    /// recorded as `"none: <reason>"`, never left `None` — so a second fill is
    /// an attempt to erase the only record of what a previous agent tried.
    #[test]
    fn fill_patch_refuses_to_overwrite_an_already_recorded_attempt() {
        let path = temp_ledger("no_overwrite");
        let stub = record("run-1", "live_two_hop_validation", None);
        append_stub(path.as_path(), &stub).expect("append");
        fill_patch(path.as_path(), &stub.stub_id, "first agent's attempt").expect("first fill");

        let err = fill_patch(path.as_path(), &stub.stub_id, "second agent's attempt")
            .expect_err("re-filling a recorded attempt must be an error, not an update");
        assert!(
            err.contains("already filled"),
            "the error must say the stub is already filled; got: {err}"
        );

        let loaded = load_ledger(path.as_path()).expect("load");
        assert_eq!(
            loaded[0].patch.as_deref(),
            Some("first agent's attempt"),
            "the original attempt must survive the refused overwrite"
        );
        let _ = fs::remove_file(&path);
    }

    /// `fill_patch` rewrites the WHOLE ledger from a prior read, so it must hold
    /// the same lock `append_stub` does.
    ///
    /// Negative control for that lock: every thread fills a DISTINCT stub, all
    /// released from a barrier together. Serialized, each read sees the previous
    /// fills and all `THREADS` survive.
    ///
    /// Unserialized it fails, but by which route depends on what was removed:
    /// - against the ORIGINAL unlocked `fs::write` implementation, every thread
    ///   rewrites from its own stale snapshot and the last writer wins, so this
    ///   trips the filled-count assertion (verified: 1 of 8 survived);
    /// - if only the lock is removed while tmp + rename is kept, threads race the
    ///   FIXED `.tmp` path and it trips earlier, on a rename `ENOENT` when one
    ///   thread renames the shared tmp out from under another.
    ///
    /// Either way it fails deterministically on a real defect rather than on a
    /// timing coincidence. It cannot go red for correct code short of the
    /// `append_lock` acquisition timeout.
    #[test]
    fn concurrent_fills_of_distinct_stubs_do_not_lose_each_other() {
        use std::sync::{Arc, Barrier};

        const THREADS: usize = 8;
        let path = temp_ledger("concurrent_fill");
        let stub_ids: Vec<String> = (0..THREADS)
            .map(|i| {
                let stub = record("run-race", &format!("stage_{i}"), None);
                append_stub(path.as_path(), &stub).expect("seed append");
                stub.stub_id
            })
            .collect();

        let barrier = Arc::new(Barrier::new(THREADS));
        let handles: Vec<_> = stub_ids
            .into_iter()
            .map(|id| {
                let path = path.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    fill_patch(path.as_path(), id.as_str(), "concurrent attempt")
                        .expect("fill must not error");
                })
            })
            .collect();
        for handle in handles {
            handle.join().expect("thread panicked");
        }

        let loaded = load_ledger(path.as_path()).expect("ledger must still parse");
        assert_eq!(
            loaded.len(),
            THREADS,
            "a lost-update must not drop stubs from the ledger"
        );
        let filled = loaded.iter().filter(|r| !r.is_unfilled()).count();
        assert_eq!(
            filled, THREADS,
            "all {THREADS} concurrent fills must survive; found {filled} — a \
             whole-file rewrite from a stale read silently discards the others"
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn record_stage_patch_requires_unambiguous_addressing() {
        let path = temp_ledger("addressing");
        let stub = record("run-1", "live_two_hop_validation", None);
        append_stub(path.as_path(), &stub).expect("append");

        let both = execute_ops_record_stage_patch(RecordStagePatchConfig {
            ledger: path.clone(),
            stub_id: Some(stub.stub_id.clone()),
            run_id: Some("run-1".to_owned()),
            stage: Some("live_two_hop_validation".to_owned()),
            patch: "x".to_owned(),
        });
        assert!(
            both.is_err(),
            "both addressing forms at once must be rejected"
        );

        let neither = execute_ops_record_stage_patch(RecordStagePatchConfig {
            ledger: path.clone(),
            stub_id: None,
            run_id: None,
            stage: None,
            patch: "x".to_owned(),
        });
        assert!(neither.is_err(), "no addressing at all must be rejected");

        // (run_id, stage) must resolve to the same stub as the stub_id form.
        execute_ops_record_stage_patch(RecordStagePatchConfig {
            ledger: path.clone(),
            stub_id: None,
            run_id: Some("run-1".to_owned()),
            stage: Some("live_two_hop_validation".to_owned()),
            patch: "addressed by run_id + stage".to_owned(),
        })
        .expect("pair addressing must resolve");
        let loaded = load_ledger(path.as_path()).expect("load");
        assert_eq!(
            loaded[0].patch.as_deref(),
            Some("addressed by run_id + stage")
        );
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

    /// The watermark defers the historical backlog; it must NOT defer anything
    /// created since. This is the whole security property of option D.
    #[test]
    fn launch_gate_blocks_a_current_stub_and_defers_a_historical_one() {
        let path = temp_ledger("gate_watermark");
        let planned = vec!["live_two_hop_validation".to_owned()];

        let mut historical = record("run-old", "live_two_hop_validation", None);
        historical.ts_utc = "2026-07-19T10:00:00Z".to_owned();
        assert!(
            historical.ts_utc.as_str() < TRIAGE_GATE_HISTORICAL_WATERMARK_UTC,
            "fixture must predate the watermark"
        );
        append_stub(path.as_path(), &historical).expect("append historical");

        // Backlog alone must not block, but must be REPORTED so it stays visible.
        let report = enforce_launch_gate(path.as_path(), &planned).expect("backlog must not block");
        assert_eq!(report.deferred_historical, 1);

        let mut current = record("run-new", "live_two_hop_validation", None);
        current.ts_utc = "2026-07-29T10:00:00Z".to_owned();
        append_stub(path.as_path(), &current).expect("append current");

        let err = enforce_launch_gate(path.as_path(), &planned)
            .expect_err("a stub created after the watermark must block the launch");
        assert!(
            err.contains("run-new::live_two_hop_validation"),
            "got: {err}"
        );
        assert!(
            !err.contains("run-old::live_two_hop_validation"),
            "the deferred historical stub must not be named as blocking; got: {err}"
        );

        // Filling the current stub releases the gate; the backlog stays deferred.
        fill_patch(path.as_path(), &current.stub_id, "none: not reproducible").expect("fill");
        let report = enforce_launch_gate(path.as_path(), &planned).expect("filled must not block");
        assert_eq!(report.deferred_historical, 1);
        let _ = fs::remove_file(&path);
    }

    /// String ordering is chronological ONLY for the fixed-width Zulu shape. A
    /// stub whose timestamp is any other shape must be treated as current (and
    /// so block), never silently sorted below the watermark and exempted.
    #[test]
    fn launch_gate_treats_an_unparseable_timestamp_as_blocking() {
        let path = temp_ledger("gate_bad_ts");
        let planned = vec!["live_two_hop_validation".to_owned()];
        let mut malformed = record("run-bad", "live_two_hop_validation", None);
        // Sorts lexicographically BEFORE the watermark, but is not the shape the
        // engine writes — under a naive string compare this would be exempted.
        malformed.ts_utc = "2026-07-19".to_owned();
        append_stub(path.as_path(), &malformed).expect("append");

        let err = enforce_launch_gate(path.as_path(), &planned)
            .expect_err("a non-fixed-width timestamp must not be exempted by the watermark");
        assert!(
            err.contains("run-bad::live_two_hop_validation"),
            "got: {err}"
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn fixed_width_zulu_timestamp_shape_is_exact() {
        assert!(is_fixed_width_zulu_timestamp("2026-07-16T12:17:17Z"));
        // Every rejection below could otherwise sort under the watermark.
        assert!(!is_fixed_width_zulu_timestamp("2026-07-16"));
        assert!(!is_fixed_width_zulu_timestamp("2026-07-16T12:17:17"));
        assert!(!is_fixed_width_zulu_timestamp("2026-07-16T12:17:17.5Z"));
        assert!(!is_fixed_width_zulu_timestamp("2026-07-16T12:17:17+01:00"));
        assert!(!is_fixed_width_zulu_timestamp("202X-07-16T12:17:17Z"));
        assert!(!is_fixed_width_zulu_timestamp(""));
    }

    /// A ledger that cannot be read must never pass the gate as "nothing
    /// outstanding" — the corrupt case is exactly when a stale fix is likeliest.
    #[test]
    fn launch_gate_fails_closed_on_a_malformed_ledger() {
        let path = temp_ledger("gate_corrupt");
        fs::write(path.as_path(), "{not json\n").expect("seed corrupt ledger");
        assert!(
            enforce_launch_gate(path.as_path(), &["live_two_hop_validation".to_owned()]).is_err(),
            "a malformed ledger must fail the gate closed"
        );
        let _ = fs::remove_file(&path);
    }

    /// A fresh clone has no ledger. That is an empty history, not a blocker.
    #[test]
    fn launch_gate_passes_on_a_missing_ledger() {
        let path = temp_ledger("gate_missing");
        let report = enforce_launch_gate(path.as_path(), &["live_two_hop_validation".to_owned()])
            .expect("a missing ledger must not block");
        assert_eq!(report.deferred_historical, 0);
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
