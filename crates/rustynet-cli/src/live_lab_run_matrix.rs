#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::append_lock::{acquire_append_lock, lock_path_for};
use crate::env_file::parse_env_value;
use crate::live_lab_results::read_parallel_stage_results;
use serde_json::Value;

const SETUP_MANIFEST_RELATIVE_PATH: &str = "state/setup_manifest.json";
const REPORT_STATE_RELATIVE_PATH: &str = "state/report_state.json";
const STAGES_RELATIVE_PATH: &str = "state/stages.tsv";
const NODES_RELATIVE_PATH: &str = "state/nodes.tsv";
const NODE_STAGE_PLAN_RELATIVE_PATH: &str = "state/node_stage_plan.json";
const NODE_STAGE_RESULTS_RELATIVE_PATH: &str = "state/live_lab_node_stage_results.csv";

/// QH-08 Option A: content pin for the source archive the
/// `prepare_source_archive` stage built. Written by
/// `orchestrator/stage/source_archive.rs`; the row builder below reads it to
/// populate the `source_archive_*` and `allow_dirty` columns. Absent for
/// legacy runs → blank columns.
pub(crate) const SOURCE_ARCHIVE_PROVENANCE_RELATIVE_PATH: &str =
    "state/source_archive_provenance.json";

const NODE_STAGE_COLUMNS: &[&str] = &[
    "run_id",
    "run_started_utc",
    "run_finished_utc",
    "git_commit",
    "git_dirty_state",
    "report_dir",
    "alias",
    "node_id",
    "platform",
    "os_family",
    "os_version",
    "role",
    "stage",
    "stage_scope",
    "status",
    "evidence_path",
    "error_detail",
];

pub(crate) const DEFAULT_MATRIX_COLUMNS: &[&str] = &[
    "run_id",
    "run_started_utc",
    "run_finished_utc",
    "git_commit",
    "git_branch",
    "git_dirty_state",
    "operator",
    "profile_path",
    "inventory_path",
    "report_dir",
    "run_command",
    "topology_summary",
    "overall_result",
    "first_failed_stage",
    "failure_digest_path",
    "evidence_bundle_path",
    "notes",
    "linux_present",
    "linux_client",
    "linux_admin",
    "linux_exit",
    "linux_blind_exit",
    "linux_relay",
    "linux_anchor",
    "macos_present",
    "macos_client",
    "macos_admin",
    "macos_exit",
    "macos_blind_exit",
    "macos_relay",
    "macos_anchor",
    "windows_present",
    "windows_client",
    "windows_admin",
    "windows_exit",
    "windows_blind_exit",
    "windows_relay",
    "windows_anchor",
    "linux_stage_bootstrap",
    "linux_stage_membership",
    "linux_stage_assignments",
    "linux_stage_baseline_runtime",
    "linux_stage_anchor",
    "linux_stage_admin",
    "linux_stage_blind_exit",
    "linux_stage_relay_service_lifecycle",
    "linux_stage_exit_handoff",
    "linux_stage_lan_toggle",
    "linux_stage_two_hop",
    "linux_stage_role_switch_matrix",
    "linux_stage_managed_dns",
    "linux_stage_traversal",
    "linux_stage_mixed_topology",
    "linux_stage_reboot_recovery",
    "linux_stage_extended_soak",
    "linux_stage_cross_network",
    "linux_stage_chaos",
    "linux_stage_cleanup",
    "macos_stage_bootstrap",
    "macos_stage_membership",
    "macos_stage_assignments",
    "macos_stage_baseline_runtime",
    "macos_stage_anchor",
    "macos_stage_admin",
    "macos_stage_blind_exit",
    "macos_stage_relay_service_lifecycle",
    "macos_stage_exit_handoff",
    "macos_stage_lan_toggle",
    "macos_stage_two_hop",
    "macos_stage_role_switch_matrix",
    "macos_stage_role_transition",
    "macos_stage_managed_dns",
    "macos_stage_traversal",
    "macos_stage_mixed_topology",
    "macos_stage_reboot_recovery",
    "macos_stage_extended_soak",
    "macos_stage_cross_network",
    "macos_stage_chaos",
    "macos_stage_cleanup",
    "windows_stage_bootstrap",
    "windows_stage_membership",
    "windows_stage_assignments",
    "windows_stage_baseline_runtime",
    "windows_stage_anchor",
    "windows_stage_admin",
    "windows_stage_blind_exit",
    "windows_stage_relay_service_lifecycle",
    "windows_stage_exit_handoff",
    "windows_stage_lan_toggle",
    "windows_stage_two_hop",
    "windows_stage_role_switch_matrix",
    "windows_stage_role_transition",
    "windows_stage_managed_dns",
    "windows_stage_traversal",
    "windows_stage_mixed_topology",
    "windows_stage_reboot_recovery",
    "windows_stage_extended_soak",
    "windows_stage_cross_network",
    "windows_stage_chaos",
    "windows_stage_cleanup",
    "linux_stage_dns_failclosed_check",
    "macos_stage_dns_failclosed_check",
    "windows_stage_dns_failclosed_check",
    "linux_stage_runtime_acls_check",
    "macos_stage_runtime_acls_check",
    "windows_stage_runtime_acls_check",
    "linux_stage_service_hardening_check",
    "macos_stage_service_hardening_check",
    "windows_stage_service_hardening_check",
    "linux_stage_key_custody_check",
    "macos_stage_key_custody_check",
    "windows_stage_key_custody_check",
    "linux_stage_gossip_peer_convergence",
    "linux_stage_mesh_status_check",
    "macos_stage_mesh_status_check",
    "windows_stage_mesh_status_check",
    "linux_stage_authenticode_check",
    "macos_stage_authenticode_check",
    "windows_stage_authenticode_check",
    "linux_stage_ipv6_leak_check",
    "macos_stage_ipv6_leak_check",
    "windows_stage_ipv6_leak_check",
    "linux_stage_exit_demotion_residue_check",
    "macos_stage_exit_demotion_residue_check",
    "windows_stage_exit_demotion_residue_check",
    "linux_stage_exit_dns_failclosed_check",
    "macos_stage_exit_dns_failclosed_check",
    "windows_stage_exit_dns_failclosed_check",
    "linux_stage_exit_nat_lifecycle_check",
    "macos_stage_exit_nat_lifecycle_check",
    "windows_stage_exit_nat_lifecycle_check",
    "linux_stage_blind_exit_dataplane_check",
    "macos_stage_blind_exit_dataplane_check",
    "windows_stage_blind_exit_dataplane_check",
    "linux_stage_secrets_not_in_logs",
    "macos_stage_secrets_not_in_logs",
    "windows_stage_secrets_not_in_logs",
    "linux_stage_key_custody",
    "macos_stage_key_custody",
    "windows_stage_key_custody",
    "linux_stage_enrollment_restart",
    "macos_stage_enrollment_restart",
    "windows_stage_enrollment_restart",
    "linux_stage_network_flap",
    "macos_stage_network_flap",
    "windows_stage_network_flap",
    "linux_stage_hello_limiter_flood",
    "macos_stage_hello_limiter_flood",
    "windows_stage_hello_limiter_flood",
    "cross_os_bootstrap",
    "cross_os_membership_convergence",
    "cross_os_peer_visibility",
    "cross_os_direct_path",
    "cross_os_relay_path",
    "cross_os_exit_path",
    "cross_os_dns",
    "cross_os_lan_toggle",
    "cross_os_role_switch",
    "cross_os_anchor_bundle_pull",
    "cross_os_anchor_enrollment",
    "windows_named_pipe_acl",
    "windows_dpapi_key_custody",
    "macos_keychain_key_custody",
    "macos_pf_killswitch",
    "linux_membership_revoke_applies",
    "linux_revoked_peer_denied_e2e",
    "linux_membership_signature_forgery",
    "linux_privileged_helper_allowlist",
    "linux_policy_default_deny",
    "linux_runtime_acls",
    "linux_service_hardening",
    "linux_authenticode",
    "linux_key_custody",
    "linux_membership_genesis",
    "linux_mesh_status",
    "linux_blind_exit_reversal_denied",
    "linux_gossip_revoked_readmit",
    "linux_enrollment_replay",
    "linux_hello_limiter_flood",
    "linux_relay_forwards_frame",
    "windows_membership_revoke_applies",
    "windows_membership_signature_forgery",
    "windows_gossip_revoked_readmit",
    "windows_enrollment_replay",
    "windows_hello_limiter_flood",
    "macos_membership_revoke_applies",
    "macos_membership_signature_forgery",
    "macos_gossip_revoked_readmit",
    "macos_enrollment_replay",
    "macos_hello_limiter_flood",
    "macos_runtime_acls",
    "macos_service_hardening",
    "macos_mesh_status",
    "macos_authenticode",
    "macos_privileged_helper_allowlist",
    "macos_policy_default_deny",
    "macos_revoked_peer_denied_e2e",
    "macos_blind_exit_reversal_denied",
    "windows_mesh_status",
    "windows_privileged_helper_allowlist",
    "windows_policy_default_deny",
    "windows_revoked_peer_denied_e2e",
    "windows_blind_exit_reversal_denied",
    "regression_reference_commit",
    "regression_notes",
    "linux_client_alias",
    "linux_client_node_id",
    "linux_client_target",
    "linux_admin_alias",
    "linux_admin_node_id",
    "linux_admin_target",
    "linux_exit_alias",
    "linux_exit_node_id",
    "linux_exit_target",
    "linux_blind_exit_alias",
    "linux_blind_exit_node_id",
    "linux_blind_exit_target",
    "linux_relay_alias",
    "linux_relay_node_id",
    "linux_relay_target",
    "linux_anchor_alias",
    "linux_anchor_node_id",
    "linux_anchor_target",
    "macos_client_alias",
    "macos_client_node_id",
    "macos_client_target",
    "macos_admin_alias",
    "macos_admin_node_id",
    "macos_admin_target",
    "macos_exit_alias",
    "macos_exit_node_id",
    "macos_exit_target",
    "macos_blind_exit_alias",
    "macos_blind_exit_node_id",
    "macos_blind_exit_target",
    "macos_relay_alias",
    "macos_relay_node_id",
    "macos_relay_target",
    "macos_anchor_alias",
    "macos_anchor_node_id",
    "macos_anchor_target",
    "windows_client_alias",
    "windows_client_node_id",
    "windows_client_target",
    "windows_admin_alias",
    "windows_admin_node_id",
    "windows_admin_target",
    "windows_exit_alias",
    "windows_exit_node_id",
    "windows_exit_target",
    "windows_blind_exit_alias",
    "windows_blind_exit_node_id",
    "windows_blind_exit_target",
    "windows_relay_alias",
    "windows_relay_node_id",
    "windows_relay_target",
    "windows_anchor_alias",
    "windows_anchor_node_id",
    "windows_anchor_target",
    "network_profile_id",
    "network_profile_digest",
    "network_management_mode",
    "network_scenario_substrate",
    "network_address_family",
    "network_internet_mode",
    "network_evidence_path",
    "row_role",
    "source_archive_sha256",
    "source_archive_bytes",
    "source_archive_source_mode",
    "allow_dirty",
    "source_archive_git_commit",
    "source_archive_git_dirty",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveLabRunMatrixStageOutcome {
    pub stage: String,
    pub status: String,
    pub artifacts: Vec<String>,
}

/// Which writer owns this row (Finding 2 of the 2026-07-03 live-lab
/// findings). One physical run has two writers: the bash EXIT trap fires
/// first (before the mac/win sidecar stages have run) and the outermost
/// supervisor writes the complete record afterwards. The run key
/// (report_dir, run_started_utc) plus this role give the RUN ownership of
/// its row: a Final write replaces any earlier rows for the same key, an
/// Interim write only lands when no row for the key exists yet (crash
/// visibility without clobbering).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveLabRunMatrixRowRole {
    Interim,
    Final,
}

impl LiveLabRunMatrixRowRole {
    fn as_str(self) -> &'static str {
        match self {
            LiveLabRunMatrixRowRole::Interim => "interim",
            LiveLabRunMatrixRowRole::Final => "final",
        }
    }
}

#[derive(Debug, Clone)]
pub struct LiveLabRunMatrixAppendConfig<'a> {
    pub command_name: &'a str,
    pub report_dir: &'a Path,
    pub profile_path: Option<&'a Path>,
    pub inventory_path: Option<&'a Path>,
    pub extra_stage_outcomes: &'a [LiveLabRunMatrixStageOutcome],
    pub notes: Option<String>,
    pub row_role: LiveLabRunMatrixRowRole,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveLabRunMatrixAppendResult {
    pub matrix_path: PathBuf,
    pub report_row_path: PathBuf,
    pub run_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StageRow {
    started_at: String,
    finished_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NodeRow {
    label: String,
    target: String,
    node_id: String,
    bootstrap_role: String,
    platform: String,
    os_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TargetEvidence {
    label: String,
    target: String,
    alias: String,
    platform: String,
    node_id: String,
    bootstrap_role: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StageEvidence {
    stage: String,
    status: String,
    artifacts: Vec<String>,
    /// QH-22: stage start, host-side, from `stages.tsv` column 6. Empty for
    /// the sources that carry no time (`orchestrate_result.json`,
    /// `extra_stage_outcomes`, and the conclusion barrier's synthesized
    /// outcomes). Fixed-width UTC (`YYYY-MM-DDTHH:MM:SSZ`), so lexical order
    /// IS chronological order — see `first_failed_stage`.
    started_at: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct NodeStagePlanFile {
    schema_version: u64,
    stages: Vec<NodeStagePlanEntry>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct NodeStagePlanEntry {
    stage: String,
    fanout: String,
    roles: Vec<String>,
}

/// The **legacy (bash orchestrator)** run matrix. Frozen historical archive,
/// read-only via the MCP `bash_archive` engine and the lab-monitor archive
/// view; NOTHING writes here anymore (the bash engine and its EXIT-trap writer
/// were deleted in W5.7). See [`default_live_lab_node_run_matrix_path`].
#[allow(dead_code)] // MUST-KEEP (BashRetirementPlan §3): read-only accessor for the frozen bash archive.
pub fn default_live_lab_run_matrix_path() -> PathBuf {
    workspace_root_path().join("documents/operations/live_lab_run_matrix.csv")
}

/// The **Rust `--node` engine** run matrix — the live evidence ledger.
///
/// The two engines get separate files because a single blended matrix is
/// actively misleading: a stage column reads `pass` without saying *which*
/// engine proved it. Concretely, `linux_stage_two_hop` showed 52 passes while
/// the `--node` engine had never once passed two-hop — every one of those
/// passes was the legacy bash orchestrator. Splitting the ledgers makes the
/// engine unambiguous by construction rather than by footnote.
///
/// **That split was only half the fix, and `linux_stage_two_hop` reproduced the same
/// false-green *inside* this ledger** — because three distinct stage ids aliased onto
/// the column, one of them `traffic_test_matrix` (mesh-ping) rather than a two-hop
/// proof. The alias is removed as of 2026-07-27 (QH-07), at the production source of
/// truth: the `logical` field on the `traffic_test_matrix` spec in
/// `live_lab_stage_registry.rs`. The two ids that still map to `two_hop`,
/// `live_two_hop_validation` and `live_two_hop`, are both genuine chained-exit proofs.
///
/// **The removal is FORWARD-ONLY: rows written before that commit are contaminated.**
/// Counted at commit `9cdd660f`, this 94-row file holds **35 `linux_stage_two_hop =
/// pass` rows** (against fail 27 / skip 23 / not_run 9) that are `traffic_test_matrix`
/// results, at a time when `live_two_hop_validation` had never passed even once —
/// its per-stage record is skip 222 / fail 81 / **pass 0**. Do not read a historical
/// `two_hop` pass as evidence the chained
/// exit path worked; go to `live_lab_node_stage_results.csv` for the per-stage truth,
/// or to the stage's own report (`live_two_hop_report.json`, whose `dataplane` block
/// carries the actual measurements). Note also that a quote-aware CSV parse is required
/// to read these columns at all — every row has commas inside quoted fields, so a naive
/// `awk -F,` shifts the stage block and silently reports the wrong column.
pub fn default_live_lab_node_run_matrix_path() -> PathBuf {
    workspace_root_path().join("documents/operations/live_lab_node_run_matrix.csv")
}

pub fn append_live_lab_run_matrix_row(
    config: LiveLabRunMatrixAppendConfig<'_>,
) -> Result<LiveLabRunMatrixAppendResult, String> {
    // W5.7: the Rust `--node` engine is the only writer — every row routes to
    // the node matrix unconditionally. The bash archive
    // (`default_live_lab_run_matrix_path`) is read-only history (MCP
    // `engine=bash_archive`); its EXIT-trap writer died with the bash engine.
    let matrix_path = default_live_lab_node_run_matrix_path();
    let schema = ensure_matrix_schema(matrix_path.as_path())?;
    let values = build_live_lab_run_matrix_values(&schema, &config)?;
    if config.row_role == LiveLabRunMatrixRowRole::Final {
        write_node_stage_result_ledgers(config.report_dir, &values)?;
    }
    let written = upsert_csv_row(matrix_path.as_path(), &schema, &values, config.row_role)?;
    let report_row_path = if written {
        write_report_local_row(config.report_dir, &schema, &values)?
    } else {
        // An Interim write that found the run key already owned (by a
        // Final row) must not clobber the report-local copy either.
        report_local_row_path(config.report_dir)
    };
    let run_id = values.get("run_id").cloned().unwrap_or_default();
    Ok(LiveLabRunMatrixAppendResult {
        matrix_path,
        report_row_path,
        run_id,
    })
}

pub fn default_live_lab_node_stage_matrix_path() -> PathBuf {
    workspace_root_path().join("documents/operations/live_lab_node_stage_results.csv")
}

fn write_node_stage_result_ledgers(
    report_dir: &Path,
    run_values: &BTreeMap<String, String>,
) -> Result<(), String> {
    let plan_path = report_dir.join(NODE_STAGE_PLAN_RELATIVE_PATH);
    let plan_body = fs::read_to_string(&plan_path).map_err(|err| {
        format!(
            "read node-stage plan failed ({}): {err}",
            plan_path.display()
        )
    })?;
    let plan: NodeStagePlanFile = serde_json::from_str(&plan_body).map_err(|err| {
        format!(
            "parse node-stage plan failed ({}): {err}",
            plan_path.display()
        )
    })?;
    if plan.schema_version != 1 {
        return Err(format!(
            "node-stage plan has unsupported schema_version={} ({})",
            plan.schema_version,
            plan_path.display()
        ));
    }

    let nodes = read_node_rows(report_dir.join(NODES_RELATIVE_PATH).as_path())?;
    if nodes.is_empty() {
        return Err("node-stage evidence requires at least one nodes.tsv row".to_owned());
    }
    let stages = read_stage_evidence(report_dir.join(STAGES_RELATIVE_PATH).as_path())?;
    let stage_summaries: BTreeMap<String, String> =
        read_tsv_rows(report_dir.join(STAGES_RELATIVE_PATH).as_path())?
            .into_iter()
            .filter(|row| row.len() >= 6)
            .map(|row| (row[0].clone(), row[5].clone()))
            .collect();

    let field = |name: &str| run_values.get(name).cloned().unwrap_or_default();
    let run_id = field("run_id");
    let run_started = field("run_started_utc");
    let report_dir_value = field("report_dir");
    if run_id.is_empty() || run_started.is_empty() || report_dir_value.is_empty() {
        return Err(
            "node-stage evidence requires non-empty run_id, run_started_utc, and report_dir"
                .to_owned(),
        );
    }

    let mut rows: Vec<BTreeMap<String, String>> = Vec::new();
    for node in &nodes {
        if node.platform.trim().is_empty() || node.os_version.trim().is_empty() {
            return Err(format!(
                "node-stage evidence for '{}' requires fetched platform + exact OS version in nodes.tsv",
                node.label
            ));
        }
        let os_family = normalize_os_family(&node.platform, &node.os_version)?;
        for planned in &plan.stages {
            if !planned.roles.is_empty()
                && !planned
                    .roles
                    .iter()
                    .any(|role| role == &node.bootstrap_role)
            {
                continue;
            }
            let Some(stage) = stages.iter().find(|stage| stage.stage == planned.stage) else {
                return Err(format!(
                    "node-stage evidence plan stage '{}' has no terminal stages.tsv row",
                    planned.stage
                ));
            };
            let stage_scope = node_stage_scope(planned)?;
            let summary = stage_summaries
                .get(&planned.stage)
                .cloned()
                .unwrap_or_default();
            let status = attributable_node_status(
                stage.status.as_str(),
                stage_scope,
                node.label.as_str(),
                summary.as_str(),
            );
            let mut row = BTreeMap::new();
            for (key, value) in [
                ("run_id", run_id.clone()),
                ("run_started_utc", run_started.clone()),
                ("run_finished_utc", field("run_finished_utc")),
                ("git_commit", field("git_commit")),
                ("git_dirty_state", field("git_dirty_state")),
                ("report_dir", report_dir_value.clone()),
                ("alias", node.label.clone()),
                ("node_id", node.node_id.clone()),
                ("platform", normalize_platform(&node.platform)),
                ("os_family", os_family.clone()),
                ("os_version", node.os_version.clone()),
                ("role", node.bootstrap_role.clone()),
                ("stage", planned.stage.clone()),
                ("stage_scope", stage_scope.to_owned()),
                ("status", status.to_owned()),
                (
                    "evidence_path",
                    stage.artifacts.first().cloned().unwrap_or_default(),
                ),
                (
                    "error_detail",
                    if matches!(status, "fail" | "not_proven") {
                        summary
                    } else {
                        String::new()
                    },
                ),
            ] {
                row.insert(key.to_owned(), value);
            }
            rows.push(row);
        }
    }
    if rows.is_empty() {
        return Err("node-stage evidence produced zero rows".to_owned());
    }

    let local_path = report_dir.join(NODE_STAGE_RESULTS_RELATIVE_PATH);
    write_node_stage_csv(&local_path, &rows)?;
    upsert_node_stage_csv(
        default_live_lab_node_stage_matrix_path().as_path(),
        &run_id,
        &report_dir_value,
        &rows,
    )?;

    // Open a triage stub for every stage that failed, carrying this run's
    // `error_detail` verbatim. The agent fills in the patch it is about to
    // test before the next run; see
    // `documents/operations/active/LiveLabStageTriageLedgerPlan_2026-07-16.md`.
    //
    // This is the right hook precisely because of where it sits: it already
    // has the run id, commit, per-node status and error, and it is reached
    // only for a FINAL row of a `--node` run — so the once-per-run and
    // engine-only scoping come for free rather than needing a second check.
    //
    // A triage-ledger problem must never fail a run whose evidence is already
    // written: the ledger is a diagnostic aid, not evidence. Report and carry
    // on.
    let triage_path =
        crate::live_lab_stage_triage::default_triage_ledger_path(workspace_root_path().as_path());
    if let Err(err) =
        crate::live_lab_stage_triage::append_stubs_for_failed_stages(triage_path.as_path(), &rows)
    {
        eprintln!("warning: stage triage stub append failed: {err}");
    }

    // Push the read side too: as soon as a stage fails, surface any prior fix
    // attempts already recorded against it, so the agent is made aware of them
    // automatically rather than having to remember to query
    // `stage_triage_history`. Like the append above, a lookup problem is a
    // warning — never a run failure (the ledger is a diagnostic aid, not
    // evidence).
    match crate::live_lab_stage_triage::render_prior_attempts_for_failed_stages(
        triage_path.as_path(),
        &rows,
    ) {
        Ok(Some(block)) => eprintln!("{block}"),
        Ok(None) => {}
        Err(err) => eprintln!("warning: stage triage prior-attempt lookup failed: {err}"),
    }
    Ok(())
}

fn node_stage_scope(planned: &NodeStagePlanEntry) -> Result<&'static str, String> {
    match (planned.roles.is_empty(), planned.fanout.as_str()) {
        (false, "per_node" | "once") | (true, "per_node") => Ok("node"),
        (true, "once") => Ok("topology"),
        (_, other) => Err(format!(
            "node-stage plan stage '{}' has unknown fanout '{other}'",
            planned.stage
        )),
    }
}

/// Map a fetched `(platform, os_version)` pair to a canonical OS family, or
/// reject it. This is the single authority for "is this an attributable
/// distro+version?" — the run-matrix finalizer uses it per node, and the native
/// orchestrator's OS-version collection uses it to fail loud early (rather than
/// recording a bare umbrella placeholder that would silently drop the whole
/// evidence append at finalization). Keep both call sites on this one function.
pub(crate) fn normalize_os_family(platform: &str, os_version: &str) -> Result<String, String> {
    let platform = normalize_platform(platform);
    let lower = os_version.to_ascii_lowercase();
    let family = if platform == "macos" || lower.contains("macos") {
        "macos"
    } else if platform == "windows" || lower.contains("windows") {
        "windows"
    } else if lower.contains("debian") {
        "debian"
    } else if lower.contains("rocky") {
        "rocky"
    } else if lower.contains("ubuntu") {
        "ubuntu"
    } else if lower.contains("fedora") {
        "fedora"
    } else {
        return Err(format!(
            "unrecognized OS family for fetched version '{os_version}' (platform={platform}); refusing Linux-umbrella evidence"
        ));
    };
    if !os_version.chars().any(|ch| ch.is_ascii_digit()) {
        return Err(format!(
            "fetched OS evidence lacks a version number: '{os_version}'"
        ));
    }
    Ok(family.to_owned())
}

/// `pub(crate)` so the producers of the summaries it parses can prove their
/// messages are actually attributable, rather than asserting it in prose. The
/// diagnostics collector's per-node error text is one such producer, and it
/// silently failed this for its whole life by quoting the alias.
pub(crate) fn attributable_node_status<'a>(
    status: &'a str,
    stage_scope: &str,
    alias: &str,
    summary: &str,
) -> &'a str {
    if status != "fail" || stage_scope != "node" {
        return status;
    }
    if summary.contains(&format!("{alias}:")) || summary.contains(&format!("{alias}/")) {
        "fail"
    } else {
        "not_proven"
    }
}

/// Write the PER-RUN stage-results artifact
/// (`state/live_lab_node_stage_results.csv` under the report dir).
///
/// The schema lives in two artifacts — this per-run file and the committed
/// aggregate ledger — so a header migration has to cover both or reading old runs
/// breaks. This half needs no row migration: the file belongs to exactly one run
/// and is rewritten whole, so an older header left by an earlier build is replaced
/// by the canonical one along with its rows. That is asserted by
/// `an_existing_per_run_file_with_an_old_header_is_rewritten_canonical`, because
/// "it truncates anyway" is the kind of assumption that stops being true when
/// someone makes this function append.
fn write_node_stage_csv(path: &Path, rows: &[BTreeMap<String, String>]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("node-stage CSV path has no parent: {}", path.display()))?;
    fs::create_dir_all(parent).map_err(|err| {
        format!(
            "create node-stage CSV directory failed ({}): {err}",
            parent.display()
        )
    })?;
    let mut body = format!("{}\n", NODE_STAGE_COLUMNS.join(","));
    for row in rows {
        body.push_str(&render_named_csv_row(NODE_STAGE_COLUMNS, row));
        body.push('\n');
    }
    fs::write(path, body)
        .map_err(|err| format!("write node-stage CSV failed ({}): {err}", path.display()))
}

fn render_named_csv_row(columns: &[&str], values: &BTreeMap<String, String>) -> String {
    columns
        .iter()
        .map(|column| csv_escape(values.get(*column).cloned().unwrap_or_default()))
        .collect::<Vec<_>>()
        .join(",")
}

/// Reconcile a stage-results file's header against the canonical
/// [`NODE_STAGE_COLUMNS`], returning the columns THAT FILE is written against.
///
/// Rows must be parsed positionally against their own header, not against the
/// canonical list: once a column is appended to the schema, a file written by an
/// earlier build has fewer fields, and reading it against the new list shifts
/// every value after the insertion point. That silent misalignment is worse than
/// a hard error, because the rows still parse.
///
/// Accepted:
///
/// * an exact match — the common case;
/// * an OLDER schema, i.e. a strict prefix of `NODE_STAGE_COLUMNS`. Columns are
///   only ever appended, so a shorter header is a previous version; its rows are
///   upgraded on write by padding the new trailing columns with empty values.
///
/// Rejected (fail closed, never guess): a header that reorders, renames, drops an
/// interior column, or carries a column this build does not know. Guessing an
/// alignment there would corrupt the committed ledger.
fn node_stage_header_columns(header: &str, path: &Path) -> Result<Vec<String>, String> {
    let found: Vec<String> = header.split(',').map(str::to_owned).collect();
    if found.len() > NODE_STAGE_COLUMNS.len() {
        return Err(format!(
            "node-stage matrix schema is NEWER than this build ({}): {} columns, expected at most {}. \
             Upgrade the binary rather than downgrading the ledger.",
            path.display(),
            found.len(),
            NODE_STAGE_COLUMNS.len()
        ));
    }
    let is_prefix = found
        .iter()
        .zip(NODE_STAGE_COLUMNS.iter())
        .all(|(have, want)| have == want);
    if !is_prefix {
        let mismatch = found
            .iter()
            .zip(NODE_STAGE_COLUMNS.iter())
            .position(|(have, want)| have != want)
            .unwrap_or(0);
        return Err(format!(
            "node-stage matrix schema mismatch ({}) at column {}: found {:?}, expected {:?}. \
             Only appended columns are migratable; a reordered or renamed column is not.",
            path.display(),
            mismatch + 1,
            found.get(mismatch).map(String::as_str).unwrap_or(""),
            NODE_STAGE_COLUMNS.get(mismatch).copied().unwrap_or("")
        ));
    }
    Ok(found)
}

/// Re-render one existing row from `file_columns` into the canonical schema,
/// padding appended columns with empty values.
fn migrate_node_stage_row(line: &str, file_columns: &[String]) -> Result<String, String> {
    let fields = parse_csv_record(line)?;
    let values: BTreeMap<String, String> = file_columns
        .iter()
        .cloned()
        .zip(fields.into_iter().chain(std::iter::repeat(String::new())))
        .collect();
    Ok(render_named_csv_row(NODE_STAGE_COLUMNS, &values))
}

fn upsert_node_stage_csv(
    path: &Path,
    run_id: &str,
    report_dir: &str,
    rows: &[BTreeMap<String, String>],
) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("node-stage matrix path has no parent: {}", path.display()))?;
    fs::create_dir_all(parent).map_err(|err| {
        format!(
            "create node-stage matrix directory failed ({}): {err}",
            parent.display()
        )
    })?;
    if !path.exists() {
        fs::write(path, format!("{}\n", NODE_STAGE_COLUMNS.join(","))).map_err(|err| {
            format!(
                "initialize node-stage matrix failed ({}): {err}",
                path.display()
            )
        })?;
    }
    let _lock = acquire_append_lock(lock_path_for(path).as_path(), "run-matrix")?;
    let body = fs::read_to_string(path)
        .map_err(|err| format!("read node-stage matrix failed ({}): {err}", path.display()))?;
    let mut lines = body.lines();
    let header = lines
        .next()
        .ok_or_else(|| format!("node-stage matrix is empty: {}", path.display()))?;
    // An older (shorter) header is read against ITS OWN columns and upgraded
    // below; anything else fails closed. See `node_stage_header_columns`.
    let file_columns = node_stage_header_columns(header, path)?;
    let upgrading = file_columns.len() != NODE_STAGE_COLUMNS.len();
    // Indices come from the FILE's header, not the canonical list: on an older
    // file the two can differ, and matching on the wrong index would replace the
    // wrong run's rows.
    let run_index = file_columns
        .iter()
        .position(|column| column == "run_id")
        .unwrap_or(0);
    let report_index = file_columns
        .iter()
        .position(|column| column == "report_dir")
        .unwrap_or(5);
    let mut retained = Vec::new();
    for line in lines.filter(|line| !line.trim().is_empty()) {
        let replace = parse_csv_record(line).is_ok_and(|fields| {
            fields.get(run_index).map(String::as_str) == Some(run_id)
                && fields.get(report_index).map(String::as_str) == Some(report_dir)
        });
        if replace {
            continue;
        }
        if upgrading {
            // Re-render under the canonical schema. A row that will not parse
            // cannot be realigned, so fail closed rather than write it back
            // verbatim under a wider header — that would silently misalign it.
            retained.push(migrate_node_stage_row(line, &file_columns).map_err(|err| {
                format!(
                    "migrate node-stage row failed ({}): {err}; row: {line}",
                    path.display()
                )
            })?);
        } else {
            retained.push(line.to_owned());
        }
    }
    let mut output = format!("{}\n", NODE_STAGE_COLUMNS.join(","));
    for line in retained {
        output.push_str(&line);
        output.push('\n');
    }
    for row in rows {
        output.push_str(&render_named_csv_row(NODE_STAGE_COLUMNS, row));
        output.push('\n');
    }
    let tmp = {
        let mut value = path.as_os_str().to_os_string();
        value.push(".tmp");
        PathBuf::from(value)
    };
    fs::write(&tmp, output).map_err(|err| {
        format!(
            "write node-stage matrix tmp failed ({}): {err}",
            tmp.display()
        )
    })?;
    fs::rename(&tmp, path).map_err(|err| {
        format!(
            "replace node-stage matrix failed ({}): {err}",
            path.display()
        )
    })
}

/// `pub(crate)` so the launch gate resolves the triage ledger through the SAME
/// expression the auto-stub writer uses (`:710`). If the gate and the stub
/// writer ever derived the root differently the gate would read a file nobody
/// writes and pass unconditionally — a silent no-op, the worst failure mode
/// available to a fail-closed check.
pub(crate) fn workspace_root_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root must be resolvable from rustynet-cli crate")
        .to_path_buf()
}

fn ensure_matrix_schema(path: &Path) -> Result<Vec<String>, String> {
    if !path.exists() {
        let parent = path
            .parent()
            .ok_or_else(|| format!("matrix path has no parent: {}", path.display()))?;
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "create live-lab run matrix directory failed ({}): {err}",
                parent.display()
            )
        })?;
        fs::write(path, format!("{}\n", DEFAULT_MATRIX_COLUMNS.join(","))).map_err(|err| {
            format!(
                "initialize live-lab run matrix failed ({}): {err}",
                path.display()
            )
        })?;
    }
    let body = fs::read_to_string(path).map_err(|err| {
        format!(
            "read live-lab run matrix failed ({}): {err}",
            path.display()
        )
    })?;
    let header = body
        .lines()
        .next()
        .ok_or_else(|| format!("live-lab run matrix is empty: {}", path.display()))?;
    let mut schema = parse_csv_record(header)?;
    let mut upgraded = false;
    for column in DEFAULT_MATRIX_COLUMNS {
        if !schema.iter().any(|existing| existing == column) {
            schema.push((*column).to_owned());
            upgraded = true;
        }
    }
    if upgraded {
        let rest = body
            .split_once('\n')
            .map(|(_, rest)| rest)
            .unwrap_or_default();
        let mut upgraded_body = format!("{}\n", schema.join(","));
        upgraded_body.push_str(rest);
        fs::write(path, upgraded_body).map_err(|err| {
            format!(
                "upgrade live-lab run matrix schema failed ({}): {err}",
                path.display()
            )
        })?;
    }
    for required in [
        "run_id",
        "git_commit",
        "git_dirty_state",
        "report_dir",
        "run_command",
        "overall_result",
    ] {
        if !schema.iter().any(|column| column == required) {
            return Err(format!(
                "live-lab run matrix missing required column {required}: {}",
                path.display()
            ));
        }
    }
    Ok(schema)
}

fn build_live_lab_run_matrix_values(
    schema: &[String],
    config: &LiveLabRunMatrixAppendConfig<'_>,
) -> Result<BTreeMap<String, String>, String> {
    let schema_set = schema.iter().cloned().collect::<BTreeSet<_>>();
    let setup_manifest = read_json_optional(
        config
            .report_dir
            .join(SETUP_MANIFEST_RELATIVE_PATH)
            .as_path(),
    )?;
    let report_state =
        read_json_optional(config.report_dir.join(REPORT_STATE_RELATIVE_PATH).as_path())?;
    let profile_path = config
        .profile_path
        .map(Path::to_path_buf)
        .or_else(|| json_string_path(&setup_manifest, &["profile", "path"]).map(PathBuf::from));
    let inventory_path = config
        .inventory_path
        .map(Path::to_path_buf)
        .or_else(|| json_string_path(&setup_manifest, &["inventory", "path"]).map(PathBuf::from));
    let profile_values = profile_path
        .as_deref()
        .filter(|path| path.is_file())
        .map(load_live_lab_profile_values)
        .transpose()?
        .unwrap_or_default();
    let node_rows = read_node_rows(config.report_dir.join(NODES_RELATIVE_PATH).as_path())?;
    let mut target_evidence = target_evidence_from_profile(&profile_values, &node_rows);
    if target_evidence.is_empty() {
        target_evidence =
            target_evidence_from_parity(config.report_dir.join("parity_input.json").as_path())?;
    }
    validate_target_evidence(&target_evidence, &node_rows)?;
    let mut stage_evidence =
        read_stage_evidence(config.report_dir.join(STAGES_RELATIVE_PATH).as_path())?;
    stage_evidence.extend(read_orchestrator_outcome_evidence(
        config
            .report_dir
            .join("orchestration/orchestrate_result.json")
            .as_path(),
    )?);
    stage_evidence.extend(
        config
            .extra_stage_outcomes
            .iter()
            .map(|outcome| StageEvidence {
                stage: outcome.stage.clone(),
                status: normalize_status(outcome.status.as_str()).to_owned(),
                // No time on this source; sorts last among failures (QH-22).
                started_at: String::new(),
                artifacts: outcome.artifacts.clone(),
            }),
    );
    dedupe_stage_evidence(&mut stage_evidence);
    apply_conclusion_barrier(&mut stage_evidence, config.report_dir)?;
    let unregistered_note = unregistered_stage_note(&stage_evidence);
    if let Some(ref defect) = unregistered_note {
        return Err(format!(
            "run evidence contains terminal stages outside the registry: {defect}"
        ));
    }

    let mut values = BTreeMap::new();
    set_if_present(
        &mut values,
        &schema_set,
        "run_id",
        build_run_id(&report_state, &setup_manifest, &stage_evidence),
    );
    set_if_present(
        &mut values,
        &schema_set,
        "run_started_utc",
        earliest_stage_time(&stage_evidence, config.report_dir, true).unwrap_or_default(),
    );
    set_if_present(
        &mut values,
        &schema_set,
        "run_finished_utc",
        earliest_stage_time(&stage_evidence, config.report_dir, false).unwrap_or_default(),
    );
    set_if_present(
        &mut values,
        &schema_set,
        "git_commit",
        json_string_path(&report_state, &["last_run", "git", "git_commit"])
            .or_else(|| json_string_path(&setup_manifest, &["git", "git_commit"]))
            .or_else(current_git_commit)
            .unwrap_or_else(|| "unknown".to_owned()),
    );
    set_if_present(
        &mut values,
        &schema_set,
        "git_branch",
        current_git_branch().unwrap_or_else(|| "unknown".to_owned()),
    );
    set_if_present(
        &mut values,
        &schema_set,
        "git_dirty_state",
        git_dirty_state(&report_state, &setup_manifest).unwrap_or_else(|| "unknown".to_owned()),
    );
    set_if_present(
        &mut values,
        &schema_set,
        "operator",
        std::env::var("USER").unwrap_or_else(|_| "unknown".to_owned()),
    );
    set_if_present(
        &mut values,
        &schema_set,
        "profile_path",
        profile_path
            .as_deref()
            .map(path_display)
            .unwrap_or_default(),
    );
    set_if_present(
        &mut values,
        &schema_set,
        "inventory_path",
        inventory_path
            .as_deref()
            .map(path_display)
            .unwrap_or_default(),
    );
    set_if_present(
        &mut values,
        &schema_set,
        "report_dir",
        path_display(config.report_dir),
    );
    set_if_present(
        &mut values,
        &schema_set,
        "run_command",
        config.command_name.to_owned(),
    );
    set_if_present(
        &mut values,
        &schema_set,
        "row_role",
        config.row_role.as_str().to_owned(),
    );
    set_if_present(
        &mut values,
        &schema_set,
        "topology_summary",
        render_topology_summary(&target_evidence),
    );
    set_if_present(
        &mut values,
        &schema_set,
        "overall_result",
        overall_result(&report_state, &stage_evidence),
    );
    set_if_present(
        &mut values,
        &schema_set,
        "first_failed_stage",
        first_failed_stage(&stage_evidence).unwrap_or_default(),
    );
    set_if_present(
        &mut values,
        &schema_set,
        "failure_digest_path",
        existing_path_string(config.report_dir.join("failure_digest.json").as_path())
            .or_else(|| existing_path_string(config.report_dir.join("failure_digest.md").as_path()))
            .unwrap_or_default(),
    );
    set_if_present(
        &mut values,
        &schema_set,
        "evidence_bundle_path",
        path_display(config.report_dir),
    );
    let notes = match (config.notes.as_deref(), unregistered_note.as_deref()) {
        (Some(notes), Some(warning)) => Some(format!("{notes}; {warning}")),
        (Some(notes), None) => Some(notes.to_owned()),
        (None, Some(warning)) => Some(warning.to_owned()),
        (None, None) => None,
    };
    if let Some(notes) = notes {
        set_if_present(&mut values, &schema_set, "notes", notes);
    }

    // Network-profile provenance (rulebook §10): the immutable per-run record
    // written by the orchestrator at launch. Absent for legacy runs → blank.
    let network_record = read_json_optional(
        config
            .report_dir
            .join("orchestration/network_profile.json")
            .as_path(),
    )?;
    for (column, key) in [
        ("network_profile_id", "id"),
        ("network_profile_digest", "digest"),
        ("network_management_mode", "management_mode"),
        ("network_scenario_substrate", "scenario_substrate"),
        ("network_address_family", "address_family"),
        ("network_internet_mode", "internet_mode"),
        ("network_evidence_path", "network_evidence_path"),
    ] {
        set_if_present(
            &mut values,
            &schema_set,
            column,
            json_string_path(&network_record, &[key]).unwrap_or_default(),
        );
    }

    // Source-archive provenance (QH-08 Option A): the content pin written by
    // the prepare_source_archive stage. Absent (stage skipped, legacy runs)
    // → blank columns, mirroring the network-record behavior above.
    let source_archive_provenance = read_json_optional(
        config
            .report_dir
            .join(SOURCE_ARCHIVE_PROVENANCE_RELATIVE_PATH)
            .as_path(),
    )?;
    for (column, key) in [
        ("source_archive_sha256", "sha256"),
        ("source_archive_source_mode", "source_mode"),
        ("source_archive_git_commit", "git_commit"),
    ] {
        set_if_present(
            &mut values,
            &schema_set,
            column,
            json_string_path(&source_archive_provenance, &[key]).unwrap_or_default(),
        );
    }
    set_if_present(
        &mut values,
        &schema_set,
        "source_archive_bytes",
        source_archive_provenance
            .as_ref()
            .and_then(|record| record.get("bytes"))
            .and_then(Value::as_u64)
            .map(|bytes| bytes.to_string())
            .unwrap_or_default(),
    );
    set_if_present(
        &mut values,
        &schema_set,
        "allow_dirty",
        json_bool_path(&source_archive_provenance, &["allow_dirty"])
            .map(|allowed| allowed.to_string())
            .unwrap_or_default(),
    );
    set_if_present(
        &mut values,
        &schema_set,
        "source_archive_git_dirty",
        json_bool_path(&source_archive_provenance, &["git_dirty"])
            .map(|dirty| dirty.to_string())
            .unwrap_or_default(),
    );

    populate_target_identity_values(&mut values, &schema_set, &target_evidence);
    populate_stage_values(
        &mut values,
        &schema_set,
        config.report_dir,
        &target_evidence,
        &stage_evidence,
    );
    populate_role_result_values(
        &mut values,
        &schema_set,
        config.report_dir,
        &target_evidence,
        &stage_evidence,
    );
    Ok(values)
}

/// Finding 3's conclusion barrier: every stage the run's manifest planned
/// (enabled, non-synthetic) that recorded NO outcome gets an explicit
/// `aborted` row instead of silently vanishing. Only `full` runs conclude
/// this way — a setup-only / validate-only / dry run legitimately records
/// nothing for the stages it never intended to reach. Pre-manifest report
/// dirs (or unreadable manifests) change nothing.
fn apply_conclusion_barrier(
    stages: &mut Vec<StageEvidence>,
    report_dir: &Path,
) -> Result<(), String> {
    let manifest = match crate::live_lab_stage_manifest::read_stage_manifest(report_dir) {
        Ok(Some(manifest)) => manifest,
        Ok(None) => return Ok(()),
        Err(err) => {
            return Err(format!(
                "read stage manifest for conclusion barrier failed: {err}"
            ));
        }
    };
    if manifest.run_mode != "full" {
        return Ok(());
    }
    let recorded: BTreeSet<String> = stages
        .iter()
        .map(|stage| strip_node_alias_prefix(stage.stage.as_str()).to_owned())
        .collect();
    for planned in manifest
        .stages
        .iter()
        .filter(|stage| stage.enabled && !stage.synthetic && !stage.barrier_exempt)
    {
        if !recorded.contains(planned.name.as_str()) {
            stages.push(StageEvidence {
                started_at: String::new(),
                stage: planned.name.clone(),
                status: "aborted".to_owned(),
                artifacts: Vec::new(),
            });
        }
    }
    Ok(())
}

/// Recorder validation (Finding 1C): a recorded stage name the registry
/// does not know is exactly the silent-drift class the registry exists to
/// kill — surface it in the row's notes so it reads as a defect, not
/// nothing. Non-fatal: evidence is still recorded.
fn unregistered_stage_note(stages: &[StageEvidence]) -> Option<String> {
    let mut unknown: Vec<&str> = stages
        .iter()
        .map(|stage| stage.stage.as_str())
        .filter(|name| crate::live_lab_stage_registry::find_stage(name).is_none())
        .collect();
    if unknown.is_empty() {
        return None;
    }
    unknown.sort_unstable();
    unknown.dedup();
    Some(format!("unregistered_stages: {}", unknown.join(",")))
}

fn set_if_present(
    values: &mut BTreeMap<String, String>,
    schema: &BTreeSet<String>,
    key: &str,
    value: String,
) {
    if schema.contains(key) {
        values.insert(key.to_owned(), value);
    }
}

fn read_json_optional(path: &Path) -> Result<Option<Value>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let body =
        fs::read(path).map_err(|err| format!("read JSON failed ({}): {err}", path.display()))?;
    serde_json::from_slice(&body)
        .map(Some)
        .map_err(|err| format!("parse JSON failed ({}): {err}", path.display()))
}

fn json_string_path(value: &Option<Value>, path: &[&str]) -> Option<String> {
    let mut current = value.as_ref()?;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_str().map(ToOwned::to_owned)
}

fn json_bool_path(value: &Option<Value>, path: &[&str]) -> Option<bool> {
    let mut current = value.as_ref()?;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_bool()
}

fn path_display(path: &Path) -> String {
    path.canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .display()
        .to_string()
}

fn existing_path_string(path: &Path) -> Option<String> {
    path.exists().then(|| path_display(path))
}

fn current_git_commit() -> Option<String> {
    git_stdout(&["rev-parse", "HEAD"])
}

fn current_git_branch() -> Option<String> {
    git_stdout(&["rev-parse", "--abbrev-ref", "HEAD"])
}

/// Pathspecs the dirty-state check excludes because the orchestrator writes
/// them BY DESIGN during a run: the evidence ledgers it appends to, the
/// gate/stage timing telemetry, and the live-VM inventory it refreshes with
/// live guest IPs during readiness. Their churn must never make a run that
/// started from a clean, committed tree record ITSELF as `dirty:worktree`.
/// Shared by `current_git_dirty_state` (this module) and
/// `vm_lab::git_worktree_is_dirty` so the two cannot drift.
///
/// QH-34: `documents/operations/active/vm_lab_inventory.json` was missing from
/// this list, so every run that performed its readiness inventory refresh
/// reported `dirty:worktree` regardless of how the tree started — a provenance
/// flag that is always set carries no information. A hand-edited inventory is
/// accepted as unflagged by this fix; the alternative (sampling dirty-state
/// before the run mutates anything, also implemented via
/// `run_start_git_tree_clean`) is tracked separately.
pub(crate) const GIT_DIRTY_STATE_EXCLUDE_PATHSPECS: &[&str] = &[
    ":(exclude)documents/operations/live_lab_run_matrix.csv",
    ":(exclude)documents/operations/live_lab_node_run_matrix.csv",
    ":(exclude)documents/operations/live_lab_node_stage_results.csv",
    ":(exclude)documents/operations/live_lab_stage_triage.jsonl",
    ":(exclude)documents/operations/gate_timings.csv",
    ":(exclude)documents/operations/live_lab_stage_timings.csv",
    ":(exclude)documents/operations/active/vm_lab_inventory.json",
];

fn current_git_dirty_state() -> Option<String> {
    // Exclude the orchestrator's OWN evidence ledgers (see
    // `GIT_DIRTY_STATE_EXCLUDE_PATHSPECS`): this run appends to them by design
    // (the run-matrix row, per-stage results, triage and gate/stage timings),
    // so their churn must not make a clean-tree run record ITSELF as
    // `dirty:worktree`. Without this, no `--node` run can satisfy the
    // NodeEngineAcceptanceSpec §5.4 clean-flip-candidate stability bar. Any real
    // code (or other tracked-file) change still surfaces and still reads dirty.
    let mut args: Vec<&str> = vec!["status", "--porcelain", "--", "."];
    args.extend_from_slice(GIT_DIRTY_STATE_EXCLUDE_PATHSPECS);
    git_stdout(&args).map(|stdout| {
        if stdout.trim().is_empty() {
            "clean".to_owned()
        } else {
            "dirty:worktree".to_owned()
        }
    })
}

fn git_stdout(args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .current_dir(workspace_root_path())
        .args(args)
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// Resolve the row's `git_dirty_state`, preferring the EARLIEST sample available.
///
/// QH-34: the orchestrator refreshes `documents/operations/active/vm_lab_inventory.json`
/// with live guest IPs during readiness, so every sample taken after that point —
/// `last_run.git.git_tree_clean` (written at finalization), the setup manifest's, and
/// this module's own render-time `current_git_dirty_state` fallback — sees the
/// orchestrator's own write and reports dirt on a run that started from a clean,
/// committed tree. `report_state.run_start_git_tree_clean` is sampled before readiness
/// runs and is therefore the only reading that answers the question the column is for:
/// did the OPERATOR start this run with uncommitted edits? Prefer it; fall back to the
/// later samples only when it is absent (a state file written before the field existed,
/// or a run whose start-of-run `git status` failed).
fn git_dirty_state(report_state: &Option<Value>, setup_manifest: &Option<Value>) -> Option<String> {
    json_bool_path(report_state, &["run_start_git_tree_clean"])
        .or_else(|| json_bool_path(report_state, &["last_run", "git", "git_tree_clean"]))
        .or_else(|| json_bool_path(setup_manifest, &["git", "git_tree_clean"]))
        .map(|clean| {
            if clean {
                "clean".to_owned()
            } else {
                "dirty:recorded".to_owned()
            }
        })
        .or_else(current_git_dirty_state)
}

fn build_run_id(
    report_state: &Option<Value>,
    setup_manifest: &Option<Value>,
    stages: &[StageEvidence],
) -> String {
    let commit = json_string_path(report_state, &["last_run", "git", "git_commit"])
        .or_else(|| json_string_path(setup_manifest, &["git", "git_commit"]))
        .or_else(current_git_commit)
        .unwrap_or_else(|| "unknown".to_owned());
    let short = commit.chars().take(12).collect::<String>();
    let stamp = earliest_stage_time_from_rows(stages, true)
        .unwrap_or_else(|| unix_now().to_string())
        .replace([':', '-', 'T', 'Z'], "");
    format!("livelab-{stamp}-{short}")
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn load_live_lab_profile_values(path: &Path) -> Result<BTreeMap<String, String>, String> {
    let body = fs::read_to_string(path)
        .map_err(|err| format!("read live-lab profile failed ({}): {err}", path.display()))?;
    let mut values = BTreeMap::new();
    for (index, raw_line) in body.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, raw_value) = line.split_once('=').ok_or_else(|| {
            format!(
                "invalid live-lab profile line {} in {}: expected KEY=VALUE",
                index + 1,
                path.display()
            )
        })?;
        let value = parse_env_value(raw_value).map_err(|err| {
            format!(
                "invalid live-lab profile value for {} in {}: {err}",
                key.trim(),
                path.display()
            )
        })?;
        values.insert(key.trim().to_owned(), value);
    }
    Ok(values)
}

fn read_tsv_rows(path: &Path) -> Result<Vec<Vec<String>>, String> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let body = fs::read_to_string(path)
        .map_err(|err| format!("read TSV failed ({}): {err}", path.display()))?;
    Ok(body
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.split('\t').map(ToOwned::to_owned).collect())
        .collect())
}

fn read_node_rows(path: &Path) -> Result<Vec<NodeRow>, String> {
    Ok(read_tsv_rows(path)?
        .into_iter()
        .filter(|row| row.len() >= 4)
        .map(|row| NodeRow {
            label: row[0].clone(),
            target: row[1].clone(),
            node_id: row[2].clone(),
            bootstrap_role: row[3].clone(),
            platform: row.get(4).cloned().unwrap_or_default(),
            os_version: row.get(5).cloned().unwrap_or_default(),
        })
        .collect())
}

fn read_stage_evidence(path: &Path) -> Result<Vec<StageEvidence>, String> {
    Ok(read_tsv_rows(path)?
        .into_iter()
        .filter(|row| row.len() >= 8)
        .map(|row| StageEvidence {
            stage: row[0].clone(),
            status: normalize_status(row[2].as_str()).to_owned(),
            artifacts: vec![row[4].clone()],
            // Column 6 is `started_at` (`live_lab_stage_recorder::to_tsv`);
            // the `len() >= 8` filter above guarantees it is present.
            started_at: row[6].clone(),
        })
        .collect())
}

fn read_orchestrator_outcome_evidence(path: &Path) -> Result<Vec<StageEvidence>, String> {
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let body = fs::read_to_string(path).map_err(|err| {
        format!(
            "read orchestrate_result.json failed ({}): {err}",
            path.display()
        )
    })?;
    let value: serde_json::Value = serde_json::from_str(body.as_str()).map_err(|err| {
        format!(
            "parse orchestrate_result.json failed ({}): {err}",
            path.display()
        )
    })?;
    let Some(outcomes) = value.get("outcomes").and_then(|value| value.as_array()) else {
        return Ok(Vec::new());
    };
    Ok(outcomes
        .iter()
        .filter_map(|outcome| {
            let stage = outcome.get("stage")?.as_str()?.to_owned();
            let status = outcome
                .get("status")
                .and_then(|value| value.as_str())
                .map(normalize_status)
                .unwrap_or("unknown")
                .to_owned();
            let artifacts = outcome
                .get("artifacts")
                .and_then(|value| value.as_array())
                .map(|values| {
                    values
                        .iter()
                        .filter_map(|value| value.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            Some(StageEvidence {
                started_at: String::new(),
                stage,
                status,
                artifacts,
            })
        })
        .collect())
}

fn stage_rows_for_times(path: &Path) -> Vec<StageRow> {
    read_tsv_rows(path)
        .unwrap_or_default()
        .into_iter()
        .filter(|row| row.len() >= 8)
        .map(|row| StageRow {
            started_at: row[6].clone(),
            finished_at: row[7].clone(),
        })
        .collect()
}

fn target_evidence_from_profile(
    profile: &BTreeMap<String, String>,
    nodes: &[NodeRow],
) -> Vec<TargetEvidence> {
    let mut targets = Vec::new();
    for label in ["exit", "client", "entry", "aux", "extra", "fifth_client"] {
        let prefix = label.to_ascii_uppercase();
        let Some(target) = profile.get(format!("{prefix}_TARGET").as_str()) else {
            continue;
        };
        if target.trim().is_empty() {
            continue;
        }
        let platform = profile
            .get(format!("{prefix}_PLATFORM").as_str())
            .map(|value| normalize_platform(value))
            .unwrap_or_else(|| "unknown".to_owned());
        let alias = profile
            .get(format!("{prefix}_UTM_NAME").as_str())
            .filter(|value| !value.trim().is_empty())
            .cloned()
            .unwrap_or_else(|| label.to_owned());
        let node = nodes.iter().find(|node| node.label == label);
        targets.push(TargetEvidence {
            label: label.to_owned(),
            target: target.clone(),
            alias,
            platform,
            node_id: node.map(|node| node.node_id.clone()).unwrap_or_default(),
            bootstrap_role: node
                .map(|node| node.bootstrap_role.clone())
                .unwrap_or_else(|| default_bootstrap_role(label).to_owned()),
        });
    }
    targets
}

fn target_evidence_from_parity(path: &Path) -> Result<Vec<TargetEvidence>, String> {
    let Some(report) = read_json_optional(path)? else {
        return Ok(Vec::new());
    };
    let Some(nodes) = report
        .get("node_statuses")
        .and_then(|value| value.as_object())
    else {
        return Ok(Vec::new());
    };
    let mut targets = nodes
        .iter()
        .map(|(alias, node)| {
            let alias_value = node
                .get("alias")
                .and_then(|value| value.as_str())
                .filter(|value| !value.trim().is_empty())
                .unwrap_or(alias.as_str())
                .to_owned();
            TargetEvidence {
                label: alias_value.clone(),
                target: node
                    .get("target")
                    .and_then(|value| value.as_str())
                    .unwrap_or("")
                    .to_owned(),
                alias: alias_value.clone(),
                platform: node
                    .get("platform")
                    .and_then(|value| value.as_str())
                    .map(normalize_platform)
                    .unwrap_or_else(|| "unknown".to_owned()),
                node_id: node
                    .get("node_id")
                    .and_then(|value| value.as_str())
                    .filter(|value| !value.trim().is_empty())
                    .unwrap_or("")
                    .to_owned(),
                bootstrap_role: node
                    .get("role")
                    .and_then(|value| value.as_str())
                    .filter(|value| !value.trim().is_empty())
                    .unwrap_or("client")
                    .to_owned(),
            }
        })
        .collect::<Vec<_>>();
    targets.sort_by(|a, b| a.alias.cmp(&b.alias));
    Ok(targets)
}

fn validate_target_evidence(targets: &[TargetEvidence], nodes: &[NodeRow]) -> Result<(), String> {
    if targets.is_empty() || nodes.is_empty() {
        return Ok(());
    }
    for target in targets {
        let node = nodes
            .iter()
            .find(|node| node.label == target.label || node.label == target.alias)
            .ok_or_else(|| {
                format!(
                    "target evidence alias '{}' has no matching nodes.tsv row",
                    target.alias
                )
            })?;
        if target.target.trim().is_empty() || target.node_id.trim().is_empty() {
            return Err(format!(
                "target evidence for '{}' is missing target or node_id",
                target.alias
            ));
        }
        if target.target != node.target
            || target.node_id != node.node_id
            || target.bootstrap_role != node.bootstrap_role
        {
            return Err(format!(
                "target evidence mismatch for '{}': parity=({}, {}, {}) nodes.tsv=({}, {}, {})",
                target.alias,
                target.target,
                target.node_id,
                target.bootstrap_role,
                node.target,
                node.node_id,
                node.bootstrap_role
            ));
        }
    }
    Ok(())
}

fn normalize_platform(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "mac" | "macos" | "mac_os" | "osx" | "darwin" => "macos".to_owned(),
        "win" | "windows" | "windows10" | "windows_10" | "windows11" | "windows_11" => {
            "windows".to_owned()
        }
        "linux" | "debian" => "linux".to_owned(),
        other => other.to_owned(),
    }
}

fn default_bootstrap_role(label: &str) -> &'static str {
    if label == "exit" { "admin" } else { "client" }
}

fn role_slots_for_target(target: &TargetEvidence, relay_label: Option<&str>) -> Vec<&'static str> {
    let mut roles = Vec::new();
    match target.bootstrap_role.as_str() {
        "exit" => {
            if target.platform == "macos" {
                roles.push("blind_exit");
                roles.push("exit");
                roles.push("anchor");
            } else {
                roles.push("admin");
                roles.push("exit");
                roles.push("anchor");
            }
        }
        "anchor" => {
            roles.push("admin");
            roles.push("anchor");
        }
        "relay" => {
            roles.push("client");
            roles.push("relay");
        }
        "client" | "entry" | "aux" | "extra" => roles.push("client"),
        _ if target.label == "exit" => {
            roles.push("admin");
            roles.push("exit");
            roles.push("anchor");
        }
        _ => roles.push("client"),
    }
    if relay_label == Some(target.label.as_str()) {
        roles.push("relay");
    }
    roles.sort_unstable();
    roles.dedup();
    roles
}

fn relay_label(targets: &[TargetEvidence]) -> Option<&str> {
    if targets.iter().any(|target| target.label == "entry") {
        Some("entry")
    } else if targets.iter().any(|target| target.label == "aux") {
        Some("aux")
    } else {
        None
    }
}

fn populate_target_identity_values(
    values: &mut BTreeMap<String, String>,
    schema: &BTreeSet<String>,
    targets: &[TargetEvidence],
) {
    let relay_label = relay_label(targets);
    for target in targets {
        if ["linux", "macos", "windows"].contains(&target.platform.as_str()) {
            set_status(
                values,
                schema,
                format!("{}_present", target.platform).as_str(),
                "pass",
            );
        }
        for role in role_slots_for_target(target, relay_label) {
            let prefix = format!("{}_{}", target.platform, role);
            set_if_present(
                values,
                schema,
                format!("{prefix}_alias").as_str(),
                target.alias.clone(),
            );
            set_if_present(
                values,
                schema,
                format!("{prefix}_node_id").as_str(),
                target.node_id.clone(),
            );
            set_if_present(
                values,
                schema,
                format!("{prefix}_target").as_str(),
                target.target.clone(),
            );
        }
    }
}

/// Some validators run once per node in a multi-node role (e.g. two Linux
/// peers under `run_linux_daemon_validators_for_aliases`) and the caller
/// disambiguates by prefixing the stage id with `"{alias}::"`, e.g.
/// `"debian-headless-1::validate_linux_hello_limiter_flood"`. The fixed-name
/// classifiers below (`direct_platform_stage`, `logical_stage_name`,
/// `set_special_stage_values`, `populate_cross_os_values`) all match on the
/// bare `"validate_..."` name, so an alias-qualified name silently fell
/// through their catch-all `_ => {}` arm -- the check's own CSV column stayed
/// at its default ("not_run") even when the validator genuinely failed,
/// while `first_failed_stage` (populated separately, alias-preserving) still
/// correctly named the failure. Strip the alias prefix before classifying so
/// the column reflects reality too.
fn strip_node_alias_prefix(stage: &str) -> &str {
    stage.rsplit("::").next().unwrap_or(stage)
}

fn populate_stage_values(
    values: &mut BTreeMap<String, String>,
    schema: &BTreeSet<String>,
    report_dir: &Path,
    targets: &[TargetEvidence],
    stages: &[StageEvidence],
) {
    for stage in stages {
        let status = normalize_status(stage.status.as_str());
        let unaliased = strip_node_alias_prefix(stage.stage.as_str());
        // W-FIX-3. A run-scoped stage describes the RUN, not any OS's nodes,
        // so it may not address a per-OS `{platform}_stage_*` column or a
        // `cross_os_*` column. Its own one-off `special` column (if it has
        // one) is still written, by the unconditional second pass below —
        // that column IS the stage, so it is attribution, not aliasing.
        //
        // This is the fix for the roll-up defect recorded in
        // `WindowsNodeBootstrapTriageVerdict_2026-08-28.md` §0(c): `preflight`
        // shares the `bootstrap` logical column with the node-scoped
        // `bootstrap_hosts`, so a run that died at `preflight` wrote `fail`
        // into `linux_stage_bootstrap`, `macos_stage_bootstrap` and
        // `windows_stage_bootstrap` at once, while `bootstrap_hosts` itself
        // was `skip` on every node. `merge_status` then correctly kept the
        // `fail` — the merge was never wrong, the feed was. Suppressing the
        // write leaves those columns at their never-reached value
        // (`not_run` by default, or the real `skip` that `bootstrap_hosts`
        // records when it is skip-cascaded), and the run's failure is carried
        // by `overall_result` + `first_failed_stage` exactly as before.
        if crate::live_lab_stage_registry::is_run_scoped(unaliased) {
            continue;
        }
        if let Some((platform, logical_stage)) = direct_platform_stage(unaliased) {
            set_status(
                values,
                schema,
                format!("{platform}_stage_{logical_stage}").as_str(),
                status,
            );
            set_special_stage_values(values, schema, platform, unaliased, status);
            populate_cross_os_values(values, schema, unaliased, status, targets);
            continue;
        }
        if let Some(logical_stage) = logical_stage_name(unaliased) {
            let worker_results = read_parallel_stage_results(report_dir, stage.stage.as_str());
            if worker_results.is_empty() {
                for platform in platforms_for_stage(unaliased, targets) {
                    set_status(
                        values,
                        schema,
                        format!("{platform}_stage_{logical_stage}").as_str(),
                        status,
                    );
                }
            } else {
                for worker in worker_results {
                    if let Some(target) = targets.iter().find(|target| target.label == worker.label)
                    {
                        let worker_status = if worker.rc == 0 { "pass" } else { "fail" };
                        set_status(
                            values,
                            schema,
                            format!("{}_stage_{logical_stage}", target.platform).as_str(),
                            worker_status,
                        );
                    }
                }
            }
        }
        populate_cross_os_values(values, schema, unaliased, status, targets);
    }

    // Second pass: call set_special_stage_values unconditionally so mac/win
    // parity-tier validation stages (e.g. validate_macos_runtime_acls) populate
    // their one-off columns even when the stage name doesn't match
    // direct_platform_stage or logical_stage_name.
    let fallback_platform = targets
        .first()
        .map(|t| t.platform.as_str())
        .unwrap_or("linux");
    for stage in stages {
        let status = normalize_status(stage.status.as_str());
        let unaliased = strip_node_alias_prefix(stage.stage.as_str());
        set_special_stage_values(values, schema, fallback_platform, unaliased, status);
    }

    populate_security_audit_control_values(values, schema, report_dir, stages);
}

/// Populate the twenty-four `{platform}_{audit_id}` security columns from the
/// `security_audit_validation` stage's per-control artifact.
///
/// The aggregate stage status cannot address these columns — one status cannot
/// carry eight independent control verdicts — so on the `--node` engine they sat
/// at `not_run` for every recorded run even while the controls were being
/// exercised and passing. A column is written ONLY from a real per-control
/// verdict; a platform with no node in the run is never written at all, so it
/// keeps its `not_run` default, which is then the truth rather than an artefact.
///
/// Multi-node resolution is [`set_status`]'s existing worst-wins merge: `fail`
/// and `blocked` both outrank `pass`, so one node failing a control, or one node
/// on which the control could not be exercised, prevents that platform's column
/// from reading green.
fn populate_security_audit_control_values(
    values: &mut BTreeMap<String, String>,
    schema: &BTreeSet<String>,
    report_dir: &Path,
    stages: &[StageEvidence],
) {
    // The stage must be present AND actually dispatched. Presence alone is not
    // enough: a skip-cascaded stage still appears in `stages.tsv` with status
    // `skipped`, and its `execute` never runs, so it never rewrites the
    // artifact. On a reused report directory (resume / rerun-stage / run-only)
    // a name-only guard would then read the PREVIOUS invocation's artifact as
    // this run's evidence and record `pass` for controls this run never
    // exercised. Same green-washing failure as the conditional write, reached
    // by a different door.
    let dispatched = stages.iter().any(|stage| {
        strip_node_alias_prefix(stage.stage.as_str()) == "security_audit_validation"
            && matches!(
                normalize_status(stage.status.as_str()),
                "pass" | "fail" | "blocked" | "aborted" | "timed_out" | "not_proven"
            )
    });
    if !dispatched {
        return;
    }
    for control in read_security_audit_controls(report_dir) {
        set_status(
            values,
            schema,
            format!("{}_{}", control.platform, control.audit_id).as_str(),
            control.status.as_str(),
        );
    }
}

struct SecurityAuditControl {
    platform: String,
    audit_id: String,
    status: String,
}

/// Read the per-control artifact. A missing, unreadable, or malformed file
/// yields no rows: the columns then stay at their `not_run` default rather than
/// inheriting a guessed status. Rows missing any of the three required fields
/// are dropped individually for the same reason.
fn read_security_audit_controls(report_dir: &Path) -> Vec<SecurityAuditControl> {
    let path = report_dir
        .join(crate::vm_lab::orchestrator::stage::security_audit_validation::PER_CONTROL_FILENAME);
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return Vec::new();
    };
    // Reject an unrecognised schema rather than guessing at a shape this build
    // does not know. A report directory can be written by one binary and
    // recorded by another (host-launched runs, reused report dirs), and every
    // sibling evaluator in this family hard-rejects a version it does not
    // support. Dropping to zero rows leaves the columns `not_run`, which is the
    // safe direction.
    let version = parsed
        .get(crate::vm_lab::orchestrator::stage::security_audit_validation::PER_CONTROL_SCHEMA_VERSION_FIELD)
        .and_then(|v| v.as_u64());
    if version
        != Some(
            crate::vm_lab::orchestrator::stage::security_audit_validation::PER_CONTROL_SCHEMA_VERSION,
        )
    {
        return Vec::new();
    }
    let Some(controls) = parsed.get("controls").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    controls
        .iter()
        .filter_map(|entry| {
            Some(SecurityAuditControl {
                platform: entry.get("platform")?.as_str()?.to_owned(),
                audit_id: entry.get("audit_id")?.as_str()?.to_owned(),
                status: entry.get("status")?.as_str()?.to_owned(),
            })
        })
        .collect()
}

fn populate_role_result_values(
    values: &mut BTreeMap<String, String>,
    schema: &BTreeSet<String>,
    _report_dir: &Path,
    targets: &[TargetEvidence],
    stages: &[StageEvidence],
) {
    let relay_label = relay_label(targets);
    for stage in stages {
        let status = normalize_status(stage.status.as_str());
        if let Some((platform, role)) = direct_platform_role(stage.stage.as_str()) {
            set_status(
                values,
                schema,
                format!("{platform}_{role}").as_str(),
                status,
            );
        }
        match stage.stage.as_str() {
            "anchor_validation" => {
                set_target_role_statuses(values, schema, targets, status, |role| role == "anchor");
            }
            "deploy_relay_service" | "relay_validation" => {
                set_target_role_statuses(values, schema, targets, status, |role| role == "relay");
            }
            "exit_handoff" | "active_exit" => {
                set_target_role_statuses(values, schema, targets, status, |role| role == "exit");
            }
            "admin_issue" => {
                set_target_role_statuses(values, schema, targets, status, |role| role == "admin");
            }
            "blind_exit" | "blind_exit_dataplane_validation" => {
                set_target_role_statuses(values, schema, targets, status, |role| {
                    role == "blind_exit"
                });
            }
            "traffic_test_matrix" => {
                set_target_role_statuses(values, schema, targets, status, |role| role == "client");
            }
            "live_anchor" => {
                if let Some(exit) = targets.iter().find(|target| target.label == "exit") {
                    set_status(
                        values,
                        schema,
                        format!("{}_anchor", exit.platform).as_str(),
                        status,
                    );
                }
            }
            "live_relay" => {
                if let Some(label) = relay_label
                    && let Some(relay) = targets.iter().find(|target| target.label == label)
                {
                    set_status(
                        values,
                        schema,
                        format!("{}_relay", relay.platform).as_str(),
                        status,
                    );
                }
            }
            "live_exit_handoff" => {
                if let Some(exit) = targets.iter().find(|target| target.label == "exit") {
                    set_status(
                        values,
                        schema,
                        format!("{}_exit", exit.platform).as_str(),
                        status,
                    );
                }
            }
            _ => {}
        }
    }
}

fn set_target_role_statuses(
    values: &mut BTreeMap<String, String>,
    schema: &BTreeSet<String>,
    targets: &[TargetEvidence],
    status: &str,
    include_role: impl Fn(&str) -> bool,
) {
    let relay_label = relay_label(targets);
    for target in targets {
        for role in role_slots_for_target(target, relay_label) {
            if include_role(role) {
                set_status(
                    values,
                    schema,
                    format!("{}_{}", target.platform, role).as_str(),
                    status,
                );
            }
        }
    }
}

// The stage-classification tables that used to live here as four
// hand-maintained match blocks are now data in `live_lab_stage_registry`
// (the single stage vocabulary owner). The original match bodies survive
// verbatim as oracles in this file's test module, with an equivalence test
// pinning the registry against them for the full recorded vocabulary.

fn direct_platform_stage(stage: &str) -> Option<(&'static str, &'static str)> {
    crate::live_lab_stage_registry::direct_platform_stage(stage)
}

fn direct_platform_role(stage: &str) -> Option<(&'static str, &'static str)> {
    crate::live_lab_stage_registry::direct_platform_role(stage)
}

fn logical_stage_name(stage: &str) -> Option<&'static str> {
    crate::live_lab_stage_registry::logical_stage_name(stage)
}

fn platforms_for_stage(stage: &str, targets: &[TargetEvidence]) -> Vec<String> {
    use crate::live_lab_stage_registry::PlatformRule;
    match crate::live_lab_stage_registry::platform_rule(stage) {
        PlatformRule::AllPlatforms => unique_platforms(targets),
        PlatformRule::ExitTarget => targets
            .iter()
            .find(|target| target.label == "exit")
            .map(|target| vec![target.platform.clone()])
            .unwrap_or_default(),
        PlatformRule::RelayTarget => relay_label(targets)
            .and_then(|label| targets.iter().find(|target| target.label == label))
            .map(|target| vec![target.platform.clone()])
            .unwrap_or_default(),
        PlatformRule::LinuxOnly => unique_platforms(targets)
            .into_iter()
            .filter(|platform| platform == "linux")
            .collect(),
    }
}

fn unique_platforms(targets: &[TargetEvidence]) -> Vec<String> {
    targets
        .iter()
        .filter(|target| ["linux", "macos", "windows"].contains(&target.platform.as_str()))
        .map(|target| target.platform.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn populate_cross_os_values(
    values: &mut BTreeMap<String, String>,
    schema: &BTreeSet<String>,
    stage: &str,
    status: &str,
    targets: &[TargetEvidence],
) {
    let stage = strip_node_alias_prefix(stage);
    // W-FIX-3, defence in depth. `populate_stage_values` already skips
    // run-scoped stages before reaching here, but a `cross_os_*` column is an
    // OS-interop claim by definition, so the suppression belongs at the
    // writer too: any future caller inherits it without having to remember.
    if crate::live_lab_stage_registry::is_run_scoped(stage) {
        return;
    }
    let platform_count = unique_platforms(targets).len();
    if platform_count < 2 && !stage.contains("windows") && !stage.contains("macos") {
        return;
    }
    if let Some(column) = crate::live_lab_stage_registry::cross_os_column(stage) {
        set_status(values, schema, column, status);
    }
}

fn set_special_stage_values(
    values: &mut BTreeMap<String, String>,
    schema: &BTreeSet<String>,
    platform: &str,
    stage: &str,
    status: &str,
) {
    // `platform` is retained for signature stability with historical
    // callers; the one-off column is fully determined by the stage name.
    let _ = platform;
    let stage = strip_node_alias_prefix(stage);
    if let Some(column) = crate::live_lab_stage_registry::special_column(stage) {
        set_status(values, schema, column, status);
    }
}

fn set_status(
    values: &mut BTreeMap<String, String>,
    schema: &BTreeSet<String>,
    key: &str,
    value: &str,
) {
    if !schema.contains(key) {
        return;
    }
    let merged = values
        .get(key)
        .map(|existing| merge_status(existing, value))
        .unwrap_or_else(|| normalize_status(value).to_owned());
    values.insert(key.to_owned(), merged);
}

fn merge_status(existing: &str, next: &str) -> String {
    let existing = normalize_status(existing);
    let next = normalize_status(next);
    if status_rank(next) >= status_rank(existing) {
        next.to_owned()
    } else {
        existing.to_owned()
    }
}

/// Precedence when several stages merge into one logical CSV column.
///
/// **`skip` outranks `pass` deliberately (QH-37).** Several stages share one
/// column, and the merge keeps the highest rank, so a column is a summary of a
/// SET. With `pass` on top, one passing stage hid any number of skipped ones:
/// `linux_stage_cross_network` read `pass` on every run where 2 of its 11
/// stages ran and 9 skipped, and `managed_dns` read `pass` on 44 runs where the
/// bundle distribution passed while the actual DNS validation never executed.
/// Measured across the committed ledger, not inferred. A partially-skipped set
/// must not read green, for the same reason `fail` already dominates: the column
/// is read as evidence that the thing was proven.
///
/// This is the aggregate-merge sibling of the alias contamination CLAUDE.md
/// §12.3 warns about. It changes how historical rows are INTERPRETED, never the
/// stored data — the committed rows remain evidence of what the tooling said at
/// the time, and must not be retro-edited.
///
/// Known latent gap, deliberately NOT fixed here: `not_proven` — a node-scope
/// fail that could not be attributed to a specific node (`:794`) — is not in
/// `normalize_status`, so it falls to `unknown` (rank 2) and would also be
/// masked by a pass. It co-occurs with `pass` in **zero** merged columns today,
/// and closing it means changing `normalize_status`, which is also a WRITE path
/// (`:1125`, `:1562`, `:1881`). That is a data-format change and does not belong
/// bundled into this one. Recorded in QH-37.
fn status_rank(status: &str) -> u8 {
    match normalize_status(status) {
        "fail" => 8,
        // Same rank as `fail`: it is a failure that could not be pinned on a
        // specific node, so it must never be outranked by a pass.
        "not_proven" => 8,
        "timed_out" => 7,
        "aborted" => 6,
        "blocked" => 5,
        // unknown/malformed ABOVE pass: an unrecognized status is a
        // data-integrity non-pass (a torn write or tampered token) and must
        // never be masked by a co-occurring pass in a merge (§2.2 "malformed/
        // unknown ... never satisfy a ... release claim"). Ranked with `blocked`
        // — a non-pass that is not itself a specific stage failure.
        "unknown" => 5,
        // skip ABOVE pass — see the note above.
        "skip" => 4,
        "pass" => 3,
        "reused" => 2,
        "not_run" => 1,
        "na" => 0,
        _ => 0,
    }
}

fn normalize_status(status: &str) -> &str {
    match status.trim().to_ascii_lowercase().as_str() {
        "passed" | "pass" | "success" | "succeeded" => "pass",
        "failed" | "fail" | "error" => "fail",
        "skipped" | "skip" => "skip",
        // Written by `attributable_node_status` into the PER-NODE ledger: a
        // node-scope fail whose summary does not name this alias, so the run
        // failed but this node cannot be blamed for it. Recognised here so it
        // survives as itself rather than degrading to `unknown`.
        "not_proven" => "not_proven",
        "reused" | "reuse" => "reused",
        "blocked" => "blocked",
        // Finding 3: the conclusion barrier's terminal states — a planned
        // stage that evaporated (aborted) or exceeded its watchdog
        // (timed_out) is distinguishable from fail and from never-planned.
        "aborted" | "abort" => "aborted",
        "timed_out" | "timedout" | "timeout" => "timed_out",
        "not_run" | "not-run" | "not run" => "not_run",
        "n/a" | "na" => "na",
        _ => "unknown",
    }
}

fn dedupe_stage_evidence(stages: &mut Vec<StageEvidence>) {
    let mut by_stage = BTreeMap::<String, StageEvidence>::new();
    for stage in stages.drain(..) {
        by_stage
            .entry(stage.stage.clone())
            .and_modify(|existing| {
                if let Some(merged) = merged_start_time(existing, &stage) {
                    existing.started_at = merged;
                }
                existing.status = merge_status(existing.status.as_str(), stage.status.as_str());
                existing.artifacts.extend(stage.artifacts.clone());
                existing.artifacts.sort();
                existing.artifacts.dedup();
            })
            .or_insert(stage);
    }
    stages.extend(by_stage.into_values());
}

/// The start time that belongs with the MERGED status of two records for the
/// same stage — earliest start among the records carrying the *winning* status.
///
/// Taking the earliest time unconditionally is wrong, and not theoretically:
/// `artifacts/live_lab/20260411T190200Z_handoff_retry_working_tree/state/stages.tsv`
/// records `live_role_switch_matrix` three times — `pass@18:26:41Z`,
/// `fail@18:34:52Z`, `fail@18:42:26Z`. The merged status is `fail`; the earliest
/// time overall belongs to the attempt that PASSED. Pairing them would name the
/// stage as the run's first failure using a timestamp from a successful run,
/// and could order it ahead of the genuine root cause.
///
/// So the time follows the status: a higher-ranking incoming status carries its
/// own time in, an equal-ranking one takes the earlier of the two, and a
/// lower-ranking one leaves the winner's time alone.
/// `None` means "leave the existing start alone" — NOT "blank it". The
/// distinction is load-bearing: an earlier revision returned the merged value
/// unconditionally and the caller `unwrap_or_default()`d it, so a
/// higher-ranking record that carried NO time silently erased a real one.
///
/// That mattered because the sources are asymmetric. `stages.tsv` carries
/// times; `orchestrate_result.json` and `extra_stage_outcomes` never do, and
/// they are always merged second. A timeless record is a second REPORT of the
/// same attempt, not a second ATTEMPT — it can restate the outcome but it
/// cannot re-date the stage. Erasing the time made the failure sort LAST under
/// the empty-last rule and pointed triage at a later stage: QH-22's own
/// misdirection, reintroduced by its fix.
fn merged_start_time(existing: &StageEvidence, incoming: &StageEvidence) -> Option<String> {
    let existing_rank = status_rank(existing.status.as_str());
    let incoming_rank = status_rank(incoming.status.as_str());
    match incoming_rank.cmp(&existing_rank) {
        // The incoming status wins, and brings its own time WHEN IT HAS ONE.
        std::cmp::Ordering::Greater => {
            (!is_blank(incoming.started_at.as_str())).then(|| incoming.started_at.clone())
        }
        // The existing status wins; its time stands.
        std::cmp::Ordering::Less => None,
        // Same status class — genuinely the same kind of outcome, so the
        // earlier of the two starts is the one that outcome began at.
        std::cmp::Ordering::Equal => {
            let pick =
                earlier_non_empty(existing.started_at.as_str(), incoming.started_at.as_str());
            (!pick.is_empty()).then_some(pick)
        }
    }
}

/// A stamp is "blank" if it is empty OR whitespace-only. `sanitize` maps tab,
/// newline and CR to spaces (`live_lab_stage_recorder`), and the bash arm
/// interpolates the value unvalidated, so a whitespace-only stamp is
/// producible — and ' ' (0x20) sorts BELOW '2' (0x32), so treating it as a
/// real time would let a garbage stamp win the first-failure race outright.
fn is_blank(stamp: &str) -> bool {
    stamp.trim().is_empty()
}

/// Earlier of two fixed-width UTC stamps, treating empty as "no information"
/// rather than as an early time.
fn earlier_non_empty(a: &str, b: &str) -> String {
    match (is_blank(a), is_blank(b)) {
        (true, true) => String::new(),
        (true, false) => b.to_owned(),
        (false, true) => a.to_owned(),
        (false, false) => a.min(b).to_owned(),
    }
}

/// Statuses that mean "this run did not prove what it set out to prove".
///
/// `not_proven` is ranked WITH `fail` by [`status_rank`] (571b3036) so it fails
/// closed in a merged column — but both consumers tested the literal string
/// `"fail"`, so an equal-ranking `not_proven` arriving second WON the merge and
/// then satisfied neither test: the run reported not-failed and named no first
/// failure. The hardening had converted "masked by a pass" into "erases the
/// fail", which is strictly worse. One predicate, so the two cannot drift.
///
/// Measured before widening: `not_proven` appears in 0 of 14,695 recorded stage
/// rows, so no existing verdict changes.
fn is_failure_status(status: &str) -> bool {
    matches!(normalize_status(status), "fail" | "not_proven")
}

fn overall_result(report_state: &Option<Value>, stages: &[StageEvidence]) -> String {
    // Terminal stage failure always dominates a claimed report-state pass.
    if stages
        .iter()
        .any(|stage| is_failure_status(stage.status.as_str()))
    {
        return "fail".to_owned();
    }
    // Finding 3: a run whose planned stages evaporated must not read as a
    // clean pass, even when the (Linux-side) report state says the suite it
    // ran passed — the conclusion barrier's synthesized outcomes demote it.
    let has_aborted = stages
        .iter()
        .any(|stage| stage.status == "aborted" || stage.status == "timed_out");
    let has_incomplete = stages.iter().any(|stage| {
        matches!(
            normalize_status(stage.status.as_str()),
            "skip" | "not_run" | "reused" | "unknown"
        )
    });
    if let Some(true) = json_bool_path(report_state, &["run_complete"]) {
        if json_bool_path(report_state, &["run_passed"]) == Some(true) {
            if has_aborted {
                return "aborted".to_owned();
            }
            if has_incomplete {
                return "partial".to_owned();
            }
            return "pass".to_owned();
        }
        return "fail".to_owned();
    }
    if has_aborted {
        "aborted".to_owned()
    } else if has_incomplete {
        "partial".to_owned()
    } else if stages.iter().any(|stage| stage.status == "pass") {
        "pass".to_owned()
    } else {
        "unknown".to_owned()
    }
}

/// The run's first failure, in CHRONOLOGICAL order (QH-22).
///
/// This used to be `.find(|s| s.status == "fail")` over a vec that
/// `dedupe_stage_evidence` rebuilt from a `BTreeMap`, i.e. the ALPHABETICALLY
/// first failure, under a name that reads as chronological. It named `cleanup`
/// — a downstream artifact-collector bug — on a run whose actual root cause was
/// `preflight` failing four seconds earlier, and triage started at the wrong
/// stage.
///
/// The key matches `live_lab_evidence_verifier`'s (equal fail-set, verified):
/// an empty `started_at` sorts LAST, so a stage carrying no time can never
/// outrank one that does; ties fall back to the name, which keeps the result
/// deterministic and — when two stages share a second — reproduces the old
/// alphabetical answer exactly.
///
/// Lexical comparison is chronological ONLY because every producer emits
/// fixed-width UTC (`iso8601_utc_from_unix`, unconditional 20 chars). Verified
/// across the corpus: 12,016 of 12,016 non-empty stamps conform, and no `fail`
/// row has an empty one. A producer that ever emitted an offset or local time
/// would break this silently.
///
/// The clock is the DRIVING HOST's, never a guest's, so guest clock skew cannot
/// reorder this. The remaining assumption is that the host clock does not step
/// mid-run (`unix_now` is `SystemTime::now`).
///
/// FORWARD-ONLY. Rows written before this change hold the ALPHABETICALLY first
/// failure and were not rewritten, exactly as QH-37's alias removal was
/// forward-only. 90 of the 106 rows extant at the fix are in that state, so the
/// column carries mixed semantics across the boundary commit: do not compare
/// this field across it, and do not read a pre-fix row as chronological.
fn first_failed_stage(stages: &[StageEvidence]) -> Option<String> {
    stages
        .iter()
        .filter(|stage| is_failure_status(stage.status.as_str()))
        .min_by(|a, b| {
            is_blank(a.started_at.as_str())
                .cmp(&is_blank(b.started_at.as_str()))
                .then_with(|| a.started_at.trim().cmp(b.started_at.trim()))
                .then_with(|| a.stage.cmp(&b.stage))
        })
        .map(|stage| stage.stage.clone())
}

fn render_topology_summary(targets: &[TargetEvidence]) -> String {
    targets
        .iter()
        .map(|target| {
            format!(
                "{}:{}:{}:{}",
                target.label, target.platform, target.alias, target.node_id
            )
        })
        .collect::<Vec<_>>()
        .join(";")
}

fn earliest_stage_time(
    stages: &[StageEvidence],
    report_dir: &Path,
    started: bool,
) -> Option<String> {
    earliest_stage_time_from_rows(stages, started).or_else(|| {
        let rows = stage_rows_for_times(report_dir.join(STAGES_RELATIVE_PATH).as_path());
        let mut times = rows
            .iter()
            .map(|row| {
                if started {
                    &row.started_at
                } else {
                    &row.finished_at
                }
            })
            .filter(|value| !value.trim().is_empty())
            .cloned()
            .collect::<Vec<_>>();
        times.sort();
        if started {
            times.into_iter().next()
        } else {
            times.into_iter().next_back()
        }
    })
}

/// DELIBERATELY INERT — always `None`, so both callers fall back to their own
/// path (`earliest_stage_time` re-reads `stages.tsv`; `build_run_id` stamps
/// `unix_now`).
///
/// QH-22 gave `StageEvidence` a `started_at`, which makes this implementable
/// for the first time. It is still not implemented, on purpose: it feeds
/// `run_started_utc` / `run_finished_utc` — the ledger's upsert key AND the
/// verifier's row-lookup key — and `build_run_id`, the ledger's primary
/// identifier, whose stamp would change shape from a unix second count to a
/// compacted UTC string. Every existing `run_id` has the former shape. That is
/// a separate behavioural change with its own evidence burden; do not fold it
/// into a triage-ordering fix.
fn earliest_stage_time_from_rows(_stages: &[StageEvidence], _started: bool) -> Option<String> {
    None
}

/// Insert or replace this run's row under the append lock (Finding 2:
/// upsert-by-run-key). The natural key is (report_dir, run_started_utc);
/// a Final row replaces every earlier row for the key, an Interim row
/// lands only when the key is not yet owned. A degenerate key (either
/// component empty) falls back to plain append — never guess ownership.
/// Returns whether the row was written.
fn upsert_csv_row(
    path: &Path,
    schema: &[String],
    values: &BTreeMap<String, String>,
    row_role: LiveLabRunMatrixRowRole,
) -> Result<bool, String> {
    // Serialize the read→match→rewrite against concurrent live-lab runs
    // touching the same shared matrix. Held (RAII) until this fn returns.
    let _lock = acquire_append_lock(lock_path_for(path).as_path(), "run-matrix")?;
    let body = fs::read_to_string(path).map_err(|err| {
        format!(
            "read live-lab run matrix failed ({}): {err}",
            path.display()
        )
    })?;
    let mut lines = body.lines();
    let header = lines
        .next()
        .ok_or_else(|| format!("live-lab run matrix is empty: {}", path.display()))?;
    let header_columns = parse_csv_record(header)?;
    let column_index = |name: &str| header_columns.iter().position(|column| column == name);
    let report_dir_index = column_index("report_dir");
    let started_index = column_index("run_started_utc");
    let key_report_dir = values.get("report_dir").map(String::as_str).unwrap_or("");
    let key_started = values
        .get("run_started_utc")
        .map(String::as_str)
        .unwrap_or("");
    let degenerate_key = key_report_dir.is_empty() || key_started.is_empty();

    let mut retained: Vec<&str> = Vec::new();
    let mut key_owned = false;
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let matches_key = !degenerate_key
            && match parse_csv_record(line) {
                Ok(fields) => {
                    let field = |index: Option<usize>| {
                        index
                            .and_then(|index| fields.get(index))
                            .map(String::as_str)
                            .unwrap_or("")
                    };
                    field(report_dir_index) == key_report_dir && field(started_index) == key_started
                }
                // A malformed row is never treated as a match — and never
                // destroyed.
                Err(_) => false,
            };
        if matches_key {
            key_owned = true;
            if row_role == LiveLabRunMatrixRowRole::Final {
                // Replaced by the new Final row below.
                continue;
            }
        }
        retained.push(line);
    }
    if row_role == LiveLabRunMatrixRowRole::Interim && key_owned {
        // A row (interim from a retry, or the supervisor's final) already
        // owns this run key; the trap's optimistic record must not land.
        return Ok(false);
    }

    let mut out = String::with_capacity(body.len() + 1024);
    out.push_str(header);
    out.push('\n');
    for line in retained {
        out.push_str(line);
        out.push('\n');
    }
    out.push_str(render_csv_row(schema, values).as_str());
    out.push('\n');
    let tmp_path = {
        let mut os = path.as_os_str().to_os_string();
        os.push(".tmp");
        PathBuf::from(os)
    };
    fs::write(tmp_path.as_path(), out).map_err(|err| {
        format!(
            "write live-lab run matrix tmp failed ({}): {err}",
            tmp_path.display()
        )
    })?;
    fs::rename(tmp_path.as_path(), path).map_err(|err| {
        format!(
            "replace live-lab run matrix failed ({}): {err}",
            path.display()
        )
    })?;
    Ok(true)
}
fn report_local_row_path(report_dir: &Path) -> PathBuf {
    report_dir.join("state/live_lab_run_matrix_row.csv")
}

fn write_report_local_row(
    report_dir: &Path,
    schema: &[String],
    values: &BTreeMap<String, String>,
) -> Result<PathBuf, String> {
    let path = report_local_row_path(report_dir);
    let parent = path
        .parent()
        .ok_or_else(|| format!("matrix row path has no parent: {}", path.display()))?;
    fs::create_dir_all(parent).map_err(|err| {
        format!(
            "create report-local matrix row directory failed ({}): {err}",
            parent.display()
        )
    })?;
    let body = format!("{}\n{}\n", schema.join(","), render_csv_row(schema, values));
    fs::write(&path, body).map_err(|err| {
        format!(
            "write report-local matrix row failed ({}): {err}",
            path.display()
        )
    })?;
    Ok(path)
}

fn render_csv_row(schema: &[String], values: &BTreeMap<String, String>) -> String {
    schema
        .iter()
        .map(|column| {
            csv_escape(
                values
                    .get(column)
                    .cloned()
                    .unwrap_or_else(|| default_cell_value(column)),
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn default_cell_value(column: &str) -> String {
    if column == "run_id"
        || column == "run_started_utc"
        || column == "run_finished_utc"
        || column == "git_commit"
        || column == "git_branch"
        || column == "git_dirty_state"
        || column == "operator"
        || column == "profile_path"
        || column == "inventory_path"
        || column == "report_dir"
        || column == "run_command"
        || column == "topology_summary"
        || column == "first_failed_stage"
        || column == "failure_digest_path"
        || column == "evidence_bundle_path"
        || column == "notes"
        || column == "regression_reference_commit"
        || column == "regression_notes"
        || column.ends_with("_alias")
        || column.ends_with("_node_id")
        || column.ends_with("_target")
    {
        String::new()
    } else if column == "overall_result" {
        "unknown".to_owned()
    } else {
        "not_run".to_owned()
    }
}

fn csv_escape(value: String) -> String {
    let value = neutralize_csv_formula(value);
    if value.contains(',') || value.contains('"') || value.contains('\n') || value.contains('\r') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value
    }
}

/// RSA-0055: neutralize spreadsheet formula injection. A CSV cell that begins
/// with `=`, `+`, `-`, `@`, TAB or CR is interpreted as a formula by Excel /
/// Google Sheets / LibreOffice when the matrix is opened — an attacker-supplied
/// `notes` / `run_command` / topology value could exfiltrate data or run a
/// command. Prefix such cells with a single quote (the OWASP-recommended
/// neutralization), which renders as literal text and is stripped on display.
fn neutralize_csv_formula(value: String) -> String {
    match value.as_bytes().first() {
        Some(b'=' | b'+' | b'-' | b'@' | b'\t' | b'\r') => format!("'{value}"),
        _ => value,
    }
}

/// A stage status that produced no verdict.
///
/// Reuses the recorder's own grouping (see `stage_status_is_absent`, and the
/// `"skip" | "not_run" | "reused" | "unknown"` set already used in this module)
/// rather than inventing a second, parallel notion of "did not run". **None of
/// these is `pass`** — promoting an absent result to a passing one is exactly how
/// a two-machine split would manufacture false parity: host A skips Windows, host
/// B skips macOS, and a naive union reports everything green.
pub(crate) fn stage_status_has_no_verdict(status: &str) -> bool {
    matches!(
        status.trim().to_ascii_lowercase().as_str(),
        "skip" | "skipped" | "not_run" | "reused" | "unknown" | ""
    )
}

/// One node's result for one stage, as recorded by a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StageResultRow {
    pub(crate) run_id: String,
    pub(crate) git_commit: String,
    pub(crate) git_dirty_state: String,
    pub(crate) alias: String,
    pub(crate) platform: String,
    pub(crate) role: String,
    pub(crate) stage: String,
    pub(crate) status: String,
    pub(crate) report_dir: String,
    pub(crate) error_detail: String,
}

/// Read the normalised stage-results ledger.
///
/// Header is matched **by name**, not by position: the ledger is append-only and
/// column order is not a contract worth betting evidence on.
pub(crate) fn read_stage_result_rows(path: &Path) -> Result<Vec<StageResultRow>, String> {
    let body = fs::read_to_string(path)
        .map_err(|err| format!("read stage results failed ({}): {err}", path.display()))?;
    parse_stage_result_csv(body.as_str())
}

/// Parse the stage ledger from memory — the same ledger fetched from a REMOTE
/// host over SSH must parse identically to a local file, so both share this.
pub(crate) fn parse_stage_result_csv(body: &str) -> Result<Vec<StageResultRow>, String> {
    let mut lines = body.lines();
    let Some(header_line) = lines.next() else {
        return Err("stage results is empty (no header row)".to_owned());
    };
    let header = parse_csv_record(header_line)?;
    let index_of = |name: &str| -> Result<usize, String> {
        header
            .iter()
            .position(|column| column == name)
            .ok_or_else(|| format!("stage results is missing the {name} column"))
    };
    let (i_run, i_commit, i_dirty, i_alias, i_platform, i_role, i_stage, i_status, i_report) = (
        index_of("run_id")?,
        index_of("git_commit")?,
        index_of("git_dirty_state")?,
        index_of("alias")?,
        index_of("platform")?,
        index_of("role")?,
        index_of("stage")?,
        index_of("status")?,
        index_of("report_dir")?,
    );
    let i_error = index_of("error_detail")?;

    let mut rows = Vec::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let record = parse_csv_record(line)?;
        let get = |index: usize| record.get(index).cloned().unwrap_or_default();
        rows.push(StageResultRow {
            run_id: get(i_run),
            git_commit: get(i_commit),
            git_dirty_state: get(i_dirty),
            alias: get(i_alias),
            platform: get(i_platform),
            role: get(i_role),
            stage: get(i_stage),
            status: get(i_status),
            report_dir: get(i_report),
            error_detail: get(i_error),
        });
    }
    Ok(rows)
}

pub(crate) fn parse_csv_record(line: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut field = String::new();
    let mut chars = line.chars().peekable();
    let mut quoted = false;
    while let Some(ch) = chars.next() {
        match ch {
            '"' if quoted && chars.peek() == Some(&'"') => {
                let _ = chars.next();
                field.push('"');
            }
            '"' => quoted = !quoted,
            ',' if !quoted => {
                out.push(field);
                field = String::new();
            }
            _ => field.push(ch),
        }
    }
    if quoted {
        return Err("unterminated quoted CSV header field".to_owned());
    }
    out.push(field);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_MATRIX_COLUMNS, GIT_DIRTY_STATE_EXCLUDE_PATHSPECS, LiveLabRunMatrixAppendConfig,
        LiveLabRunMatrixStageOutcome, NodeRow, StageEvidence, TargetEvidence, Value,
        build_live_lab_run_matrix_values, csv_escape, git_dirty_state, normalize_os_family,
        parse_csv_record, populate_cross_os_values, populate_role_result_values,
        populate_stage_values, render_csv_row, set_special_stage_values, validate_target_evidence,
    };
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::Path;
    use std::process::Command;

    /// QH-34: the dirty-state exclude list must cover the live-VM inventory,
    /// which the orchestrator refreshes with live guest IPs during readiness.
    /// A run that touches ONLY that file (the common clean-tree case) must not
    /// be recorded as `dirty:worktree`, so the exclude lives in the single
    /// shared source both call sites read.
    #[test]
    fn dirty_state_excludes_cover_the_live_vm_inventory_and_evidence_ledgers() {
        for expected in [
            ":(exclude)documents/operations/live_lab_run_matrix.csv",
            ":(exclude)documents/operations/live_lab_node_run_matrix.csv",
            ":(exclude)documents/operations/live_lab_node_stage_results.csv",
            ":(exclude)documents/operations/live_lab_stage_triage.jsonl",
            ":(exclude)documents/operations/gate_timings.csv",
            ":(exclude)documents/operations/live_lab_stage_timings.csv",
            ":(exclude)documents/operations/active/vm_lab_inventory.json",
        ] {
            assert!(
                GIT_DIRTY_STATE_EXCLUDE_PATHSPECS.contains(&expected),
                "dirty-state exclude list is missing {expected}"
            );
        }
    }

    /// QH-34, end-to-end over real git semantics: in a scratch repo laid out
    /// like the workspace, a change to ONLY
    /// `documents/operations/active/vm_lab_inventory.json` produces an EMPTY
    /// dirty-state check (the run reads clean), while any other tracked-file
    /// change still produces a NON-empty one.
    #[test]
    fn inventory_only_change_is_not_reported_dirty_but_other_changes_still_are() {
        let repo = tempfile::tempdir().expect("tempdir");
        let git = |args: &[&str]| {
            let output = Command::new("git")
                .current_dir(repo.path())
                .args(args)
                .output()
                .expect("git should be invocable");
            assert!(
                output.status.success(),
                "git {args:?} failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8_lossy(&output.stdout).to_string()
        };
        git(&["init", "--quiet"]);
        git(&["config", "user.email", "test@example.invalid"]);
        git(&["config", "user.name", "QH-34 Test"]);

        let inventory = repo
            .path()
            .join("documents/operations/active/vm_lab_inventory.json");
        std::fs::create_dir_all(inventory.parent().expect("inventory parent"))
            .expect("create inventory dir");
        std::fs::write(&inventory, r#"{"version":1}"#).expect("write inventory");
        // A stand-in "real" tracked file, representing code under review.
        let code = repo.path().join("crates/example/src/lib.rs");
        std::fs::create_dir_all(code.parent().expect("code parent")).expect("create code dir");
        std::fs::write(&code, "pub fn example() {}\n").expect("write code");
        git(&["add", "."]);
        git(&["commit", "--quiet", "-m", "baseline"]);

        // Baseline: clean tree reports nothing.
        let mut args: Vec<&str> = vec!["status", "--porcelain", "--", "."];
        args.extend_from_slice(GIT_DIRTY_STATE_EXCLUDE_PATHSPECS);
        assert_eq!(git(&args), "", "clean baseline must read clean");

        // The orchestrator's readiness inventory refresh, in isolation.
        std::fs::write(&inventory, r#"{"version":2,"ips":{"a":"10.0.0.1"}}"#)
            .expect("rewrite inventory");
        assert_eq!(
            git(&args),
            "",
            "an inventory-only change must NOT read dirty (QH-34)"
        );

        // A real tracked-file change still surfaces.
        std::fs::write(&code, "pub fn example() -> u32 { 1 }\n").expect("rewrite code");
        assert_ne!(
            git(&args),
            "",
            "a non-excluded tracked-file change must still read dirty"
        );
    }

    #[test]
    fn normalize_os_family_rejects_bare_platform_umbrella_placeholders() {
        // Regression (ledger 2026-07-11): a transient OS-version SSH probe used
        // to degrade to a bare platform placeholder, and normalize_os_family
        // must keep rejecting it so umbrella evidence never lands in the matrix.
        assert!(
            normalize_os_family("linux", "linux").is_err(),
            "bare 'linux' umbrella must be rejected"
        );
        // macos/windows placeholders name a family but carry no version number.
        assert!(
            normalize_os_family("macos", "macos").is_err(),
            "bare 'macos' placeholder lacks a version and must be rejected"
        );
        assert!(
            normalize_os_family("windows", "windows").is_err(),
            "bare 'windows' placeholder lacks a version and must be rejected"
        );
    }

    #[test]
    fn normalize_os_family_accepts_real_fetched_distro_versions() {
        assert_eq!(
            normalize_os_family("linux", "Debian GNU/Linux 12 (bookworm) (x86_64)").unwrap(),
            "debian"
        );
        assert_eq!(
            normalize_os_family("linux", "Fedora Linux 40 (Server Edition) (aarch64)").unwrap(),
            "fedora"
        );
        assert_eq!(
            normalize_os_family("macos", "macOS 14.5 (arm64)").unwrap(),
            "macos"
        );
        assert_eq!(
            normalize_os_family("windows", "Windows [Version 10.0.22631.3737]").unwrap(),
            "windows"
        );
    }

    /// The MCP server keeps its OWN copy of the coverage-column list, and
    /// nothing kept the two in sync.
    ///
    /// `rustynet-mcp/src/bin/lab_state.rs` declares `CANONICAL_COVERAGE_COLUMNS`
    /// by hand. It is not derived from `DEFAULT_MATRIX_COLUMNS` and cannot be:
    /// `rustynet-mcp` does not depend on `rustynet-cli`. So the only available
    /// guard is to read the other crate's source and compare — the same shape as
    /// the shared-installer test in `ops_e2e`.
    ///
    /// What this prevents: a coverage column renamed or removed here while the
    /// MCP list keeps the old name. `find_untested_work` resolves its columns
    /// against the CSV header and treats an unresolvable one as `idx = None`,
    /// which forces every row to `""` and classifies the column NEVER-RUN. So the
    /// drift does not error — it silently reports a covered column as untested,
    /// and points agents at work that is already done.
    ///
    /// One-directional on purpose, but NOT for the reason it looks like. The MCP
    /// list is not a curated subset: 47 coverage-pattern columns in this schema
    /// are absent from it (`linux_stage_admin`, every `*_blind_exit`, every
    /// `*_check`, ...), and those are simply the newer additions — the list is
    /// accumulated drift. The MCP surfaces them anyway, because
    /// `coverage_columns_from_header` pattern-matches `_stage_` and `cross_os_`
    /// against the live header.
    ///
    /// The list only matters as a FALLBACK FLOOR for a header not yet
    /// schema-upgraded, so equality is the wrong relation to assert. The residual
    /// gap is worth stating rather than denying: against a stale header those 47
    /// are invisible rather than reported NEVER-RUN, which is the very failure
    /// the floor exists to prevent.
    #[test]
    fn the_mcp_coverage_column_list_stays_a_subset_of_this_schema() {
        let mcp_source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .expect("crate manifest should live under crates/rustynet-cli")
            .join("crates/rustynet-mcp/src/bin/lab_state.rs");
        let body = std::fs::read_to_string(&mcp_source)
            .unwrap_or_else(|err| panic!("lab_state.rs should be readable: {err}"));

        const DECL: &str = "const CANONICAL_COVERAGE_COLUMNS: &[&str] = &[";
        let start = body
            .find(DECL)
            .expect("lab_state.rs must still declare CANONICAL_COVERAGE_COLUMNS");
        let rest = &body[start + DECL.len()..];
        // Anchored at column 0. A bare `];` search terminates early on any `];`
        // inside a comment, and rustfmt indents in-array comments — so requiring
        // the line start makes that impossible. Without it, a comment mentioning
        // `DEFAULT_MATRIX_COLUMNS[..];` truncated the slice and silently dropped
        // the whole trailing `cross_os_*` block from the comparison.
        let end = rest
            .find("\n];")
            .expect("CANONICAL_COVERAGE_COLUMNS must terminate at line start");

        // EVERY non-blank, non-comment line must parse as a bare quoted entry.
        // A `filter_map` here silently discards whatever it cannot read, which
        // made the guard defeatable by an ordinary trailing comment:
        // `"linux_stage_bootstrap_DRIFT", // renamed` simply vanished from the
        // extraction and the drift went unreported. Panicking means a rustfmt
        // reflow or a changed declaration shape fails loudly instead of quietly
        // shrinking what is checked. Note a multi-entry reflow (`"a", "b",`) does
        // NOT panic — it parses as one entry named `a", "b` and is caught by the
        // subset assertion below instead. Loud either way, but not always by the
        // same route.
        let mut mcp_columns: Vec<&str> = Vec::new();
        for line in rest[..end].lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with("//") {
                continue;
            }
            let column = line
                .trim_end_matches(',')
                .strip_prefix('"')
                .and_then(|value| value.strip_suffix('"'))
                .unwrap_or_else(|| {
                    panic!(
                        "CANONICAL_COVERAGE_COLUMNS line is not a bare quoted entry: \
                         {line:?}. Extraction must never skip what it cannot read."
                    )
                });
            mcp_columns.push(column);
        }

        // The subset relation cannot see DELETION — an empty list is trivially a
        // subset of anything. The panic above stops the EXTRACTOR dropping lines
        // it reads; it does nothing about the LIST itself losing entries, and an
        // earlier version of this test removed a count threshold on exactly that
        // confusion. Emptying `CANONICAL_COVERAGE_COLUMNS` then passed.
        //
        // This list is `find_untested_work`'s fallback floor for a header that has
        // not been schema-upgraded, and a floor that can be emptied without a test
        // noticing is not a floor. `>=` rather than `==` so additions do not churn
        // the number.
        assert!(
            mcp_columns.len() >= 74,
            "CANONICAL_COVERAGE_COLUMNS shrank to {} entries (floor: 74). A subset \
             assertion cannot catch deletion, so the count is asserted separately.",
            mcp_columns.len()
        );

        let schema: BTreeSet<&str> = DEFAULT_MATRIX_COLUMNS.iter().copied().collect();
        let missing: Vec<&str> = mcp_columns
            .iter()
            .copied()
            .filter(|column| !schema.contains(column))
            .collect();
        assert!(
            missing.is_empty(),
            "lab_state.rs CANONICAL_COVERAGE_COLUMNS names columns absent from \
             DEFAULT_MATRIX_COLUMNS: {missing:?}. find_untested_work resolves \
             columns by header name and treats an unresolvable one as never-run, \
             so this drift silently reports covered work as untested."
        );
    }

    #[test]
    fn every_registry_stage_column_reference_exists_in_the_csv_schema() {
        // EXTENSIBILITY GATE: a StageSpec that references a CSV column absent
        // from DEFAULT_MATRIX_COLUMNS has its value SILENTLY DROPPED by
        // set_status (which returns early on an unknown key, line ~1467). This
        // makes that a loud test failure, so adding a new stage with a new
        // `special`/`cross_os`/`{platform}_stage_{logical}`/`{platform}_{role}`
        // column cannot silently vanish from the run matrix. A shared `logical`
        // column can be elected onto any platform its `platform_rule` allows,
        // so every such platform's column must exist.
        use crate::live_lab_stage_registry::{PlatformRule, STAGES};
        let schema: BTreeSet<&'static str> = DEFAULT_MATRIX_COLUMNS.iter().copied().collect();
        let platforms_for_rule = |rule: PlatformRule| -> &'static [&'static str] {
            match rule {
                PlatformRule::LinuxOnly => &["linux"],
                // AllPlatforms / ExitTarget / RelayTarget can each land on any OS.
                _ => &["linux", "macos", "windows"],
            }
        };
        let mut missing: Vec<(&'static str, String)> = Vec::new();
        for spec in STAGES {
            // Synthetic aggregates never record an outcome, so they never
            // populate a column.
            if spec.synthetic {
                continue;
            }
            let mut required: Vec<String> = Vec::new();
            if let Some(col) = spec.special {
                required.push(col.to_owned());
            }
            if let Some(col) = spec.cross_os {
                required.push(col.to_owned());
            }
            if let Some((platform, logical)) = spec.direct_platform {
                required.push(format!("{platform}_stage_{logical}"));
            }
            if let Some((platform, role)) = spec.role {
                required.push(format!("{platform}_{role}"));
            }
            if let Some(logical) = spec.logical {
                for platform in platforms_for_rule(spec.platform_rule) {
                    required.push(format!("{platform}_stage_{logical}"));
                }
            }
            for col in required {
                if !schema.contains(col.as_str()) {
                    missing.push((spec.name, col));
                }
            }
        }
        assert!(
            missing.is_empty(),
            "StageSpec column refs absent from DEFAULT_MATRIX_COLUMNS \
             (set_status would SILENTLY DROP them): {missing:?}"
        );
    }

    #[test]
    fn tier0_revocation_stages_map_to_dedicated_csv_columns() {
        let schema: BTreeSet<String> = DEFAULT_MATRIX_COLUMNS
            .iter()
            .map(|c| (*c).to_owned())
            .collect();
        let mut values = BTreeMap::new();
        set_special_stage_values(
            &mut values,
            &schema,
            "linux",
            "validate_linux_membership_revoke_applies",
            "pass",
        );
        set_special_stage_values(
            &mut values,
            &schema,
            "linux",
            "validate_linux_revoked_peer_denied_e2e",
            "fail",
        );
        assert_eq!(
            values
                .get("linux_membership_revoke_applies")
                .map(String::as_str),
            Some("pass")
        );
        assert_eq!(
            values
                .get("linux_revoked_peer_denied_e2e")
                .map(String::as_str),
            Some("fail")
        );
    }

    #[test]
    fn daemon_security_validator_stages_map_to_dedicated_csv_columns() {
        let schema: BTreeSet<String> = DEFAULT_MATRIX_COLUMNS
            .iter()
            .map(|c| (*c).to_owned())
            .collect();
        let mut values = BTreeMap::new();
        for (stage, column) in [
            (
                "validate_linux_membership_signature_forgery",
                "linux_membership_signature_forgery",
            ),
            (
                "validate_linux_privileged_helper_allowlist",
                "linux_privileged_helper_allowlist",
            ),
            (
                "validate_linux_policy_default_deny",
                "linux_policy_default_deny",
            ),
            ("validate_linux_runtime_acls", "linux_runtime_acls"),
            (
                "validate_linux_service_hardening",
                "linux_service_hardening",
            ),
            ("validate_linux_authenticode", "linux_authenticode"),
            ("validate_linux_key_custody", "linux_key_custody"),
            (
                "validate_linux_membership_genesis",
                "linux_membership_genesis",
            ),
            ("validate_linux_mesh_status", "linux_mesh_status"),
        ] {
            set_special_stage_values(&mut values, &schema, "linux", stage, "pass");
            assert_eq!(
                values.get(column).map(String::as_str),
                Some("pass"),
                "stage {stage} did not populate column {column}"
            );
        }
    }

    #[test]
    fn tier1_security_stages_map_to_dedicated_csv_columns() {
        let schema: BTreeSet<String> = DEFAULT_MATRIX_COLUMNS
            .iter()
            .map(|c| (*c).to_owned())
            .collect();
        let mut values = BTreeMap::new();
        for (stage, column) in [
            (
                "validate_linux_blind_exit_reversal_denied",
                "linux_blind_exit_reversal_denied",
            ),
            (
                "validate_linux_gossip_revoked_readmit",
                "linux_gossip_revoked_readmit",
            ),
            (
                "validate_linux_enrollment_replay",
                "linux_enrollment_replay",
            ),
            (
                "validate_linux_hello_limiter_flood",
                "linux_hello_limiter_flood",
            ),
        ] {
            set_special_stage_values(&mut values, &schema, "linux", stage, "pass");
            assert_eq!(
                values.get(column).map(String::as_str),
                Some("pass"),
                "stage {stage} did not populate column {column}"
            );
        }
    }

    #[test]
    fn node_alias_prefixed_stage_name_still_populates_its_csv_column() {
        // Regression: run_linux_daemon_validators_for_aliases prefixes stage
        // names with "{alias}::" to disambiguate a multi-node role (see
        // vm_lab/mod.rs). Before this fix, that prefixed name matched no arm
        // in set_special_stage_values (not even its own `_ if starts_with`
        // catch-all), so a real failure never reached the CSV column and it
        // stayed "not_run" while first_failed_stage (a separate,
        // alias-preserving path) correctly named the failure -- producing an
        // inconsistent row: a named failure with no failing column anywhere.
        let schema: BTreeSet<String> = DEFAULT_MATRIX_COLUMNS
            .iter()
            .map(|c| (*c).to_owned())
            .collect();
        let mut values = BTreeMap::new();
        set_special_stage_values(
            &mut values,
            &schema,
            "linux",
            "debian-headless-1::validate_linux_hello_limiter_flood",
            "fail",
        );
        assert_eq!(
            values.get("linux_hello_limiter_flood").map(String::as_str),
            Some("fail")
        );
    }

    #[test]
    fn node_alias_prefixed_cross_os_stage_name_still_populates_its_csv_column() {
        let schema: BTreeSet<String> = DEFAULT_MATRIX_COLUMNS
            .iter()
            .map(|c| (*c).to_owned())
            .collect();
        let mut values = BTreeMap::new();
        let targets = vec![
            TargetEvidence {
                label: "exit".to_owned(),
                target: "exit".to_owned(),
                alias: "exit-1".to_owned(),
                platform: "linux".to_owned(),
                node_id: "n1".to_owned(),
                bootstrap_role: "exit".to_owned(),
            },
            TargetEvidence {
                label: "client".to_owned(),
                target: "client".to_owned(),
                alias: "client-1".to_owned(),
                platform: "macos".to_owned(),
                node_id: "n2".to_owned(),
                bootstrap_role: "client".to_owned(),
            },
        ];
        populate_cross_os_values(
            &mut values,
            &schema,
            "debian-headless-1::validate_linux_anchor_bundle_pull",
            "fail",
            &targets,
        );
        assert_eq!(
            values
                .get("cross_os_anchor_bundle_pull")
                .map(String::as_str),
            Some("fail")
        );
    }

    #[test]
    fn role_transition_stages_populate_their_own_dedicated_csv_columns() {
        // Regression: validate_macos_role_transition / validate_windows_role_transition
        // were registered stages with no direct_platform mapping, so a real pass/fail
        // never landed in any tracked run-matrix column -- find_untested_work-style
        // coverage queries (which read dedicated per-stage columns) had no visibility
        // into this stage at all, in either direction.
        let schema: BTreeSet<String> = DEFAULT_MATRIX_COLUMNS
            .iter()
            .map(|c| (*c).to_owned())
            .collect();
        let targets = vec![TargetEvidence {
            label: "windows".to_owned(),
            target: "windows".to_owned(),
            alias: "windows-utm-1".to_owned(),
            platform: "windows".to_owned(),
            node_id: "windows-client-1".to_owned(),
            bootstrap_role: "client".to_owned(),
        }];
        let report_dir = tempfile::tempdir().expect("tempdir");
        let mut values = BTreeMap::new();
        populate_stage_values(
            &mut values,
            &schema,
            report_dir.path(),
            &targets,
            &[StageEvidence {
                started_at: String::new(),
                stage: "validate_windows_role_transition".to_owned(),
                status: "pass".to_owned(),
                artifacts: Vec::new(),
            }],
        );
        assert_eq!(
            values
                .get("windows_stage_role_transition")
                .map(String::as_str),
            Some("pass"),
            "validate_windows_role_transition must populate windows_stage_role_transition: {values:?}"
        );

        let mut values = BTreeMap::new();
        populate_stage_values(
            &mut values,
            &schema,
            report_dir.path(),
            &targets,
            &[StageEvidence {
                started_at: String::new(),
                stage: "validate_macos_role_transition".to_owned(),
                status: "fail".to_owned(),
                artifacts: Vec::new(),
            }],
        );
        assert_eq!(
            values
                .get("macos_stage_role_transition")
                .map(String::as_str),
            Some("fail"),
            "validate_macos_role_transition must populate macos_stage_role_transition: {values:?}"
        );
    }

    /// The three per-OS targets used by the W-FIX-3 tests below.
    fn tri_os_targets() -> Vec<TargetEvidence> {
        ["linux", "macos", "windows"]
            .into_iter()
            .map(|platform| TargetEvidence {
                label: platform.to_owned(),
                target: platform.to_owned(),
                alias: format!("{platform}-1"),
                platform: platform.to_owned(),
                node_id: format!("{platform}-node-1"),
                bootstrap_role: "client".to_owned(),
            })
            .collect()
    }

    fn stage_evidence(stage: &str, status: &str) -> StageEvidence {
        StageEvidence {
            started_at: String::new(),
            stage: stage.to_owned(),
            status: status.to_owned(),
            artifacts: Vec::new(),
        }
    }

    /// W-FIX-3. Reproduces `livelab-1784489499-db3ff1aaafe6`: the run died at
    /// the run-scoped `preflight` (topology: "lab requires exactly 1 Exit
    /// node, found 0") and `bootstrap_hosts` was `skip` on every node — yet
    /// the recorded row read `linux_stage_bootstrap=fail`,
    /// `macos_stage_bootstrap=fail` AND `windows_stage_bootstrap=fail`,
    /// inflating the failure count on all three OSes at once.
    ///
    /// `preflight` shares the `bootstrap` logical column with the node-scoped
    /// `bootstrap_hosts`, so its run-scoped `fail` was merged in by
    /// `merge_status` — which ranks `fail` above `skip` correctly; the merge
    /// was never the bug. The column FEED was.
    #[test]
    fn a_run_scoped_preflight_failure_leaves_every_per_os_bootstrap_column_never_reached() {
        let schema: BTreeSet<String> = DEFAULT_MATRIX_COLUMNS
            .iter()
            .map(|c| (*c).to_owned())
            .collect();
        let targets = tri_os_targets();
        let report_dir = tempfile::tempdir().expect("tempdir");
        let mut values = BTreeMap::new();
        let stages = [
            stage_evidence("preflight", "fail"),
            stage_evidence("bootstrap_hosts", "skip"),
        ];
        populate_stage_values(&mut values, &schema, report_dir.path(), &targets, &stages);

        for platform in ["linux", "macos", "windows"] {
            let column = format!("{platform}_stage_bootstrap");
            assert_eq!(
                values.get(&column).map(String::as_str),
                Some("skip"),
                "{column} must reflect bootstrap_hosts' own skip, not preflight's \
                 run-scoped fail: {values:?}"
            );
        }
        assert_eq!(
            values.get("cross_os_bootstrap").map(String::as_str),
            Some("skip"),
            "cross_os_bootstrap is an OS-interop claim; a run-scoped preflight \
             failure is not evidence against it: {values:?}"
        );
        // The failure is not lost — it moves to the run-level columns, which
        // are populated alias-preserving and were never fed by the per-OS
        // merge. The row still reads as failed; it just stops blaming all
        // three OSes for it.
        assert_eq!(
            super::overall_result(&None, &stages),
            "fail",
            "the run-level verdict must still carry the preflight failure"
        );
        assert_eq!(
            super::first_failed_stage(&stages).as_deref(),
            Some("preflight"),
            "first_failed_stage must still name the run-scoped failure"
        );
    }

    /// Same defect, the harder shape: `bootstrap_hosts` never recorded at all
    /// (the run died before the stage was even reached). The per-OS columns
    /// must then be left entirely UNWRITTEN so the renderer's `not_run`
    /// default stands — a run-scoped failure must not manufacture a per-OS
    /// verdict out of nothing.
    #[test]
    fn a_run_scoped_failure_writes_no_per_os_column_when_the_stage_never_ran() {
        let schema: BTreeSet<String> = DEFAULT_MATRIX_COLUMNS
            .iter()
            .map(|c| (*c).to_owned())
            .collect();
        let targets = tri_os_targets();
        let report_dir = tempfile::tempdir().expect("tempdir");
        let mut values = BTreeMap::new();
        populate_stage_values(
            &mut values,
            &schema,
            report_dir.path(),
            &targets,
            &[
                stage_evidence("preflight", "fail"),
                stage_evidence("prepare_source_archive", "skip"),
            ],
        );

        for platform in ["linux", "macos", "windows"] {
            let column = format!("{platform}_stage_bootstrap");
            assert_eq!(
                values.get(&column),
                None,
                "{column} must stay unwritten (rendering as the not_run default) \
                 when only run-scoped stages have outcomes: {values:?}"
            );
            assert_eq!(
                super::default_cell_value(column.as_str()),
                "not_run",
                "the never-reached value this column renders as"
            );
        }
        assert_eq!(
            values.get("cross_os_bootstrap"),
            None,
            "cross_os_bootstrap must stay unwritten too: {values:?}"
        );
    }

    /// The other half of the contract: suppressing the run-scoped feed must
    /// not blunt a REAL per-OS failure. `bootstrap_windows_host` carries
    /// `direct_platform: ("windows", "bootstrap")`, so its failure reds
    /// exactly one OS and leaves the other two alone.
    #[test]
    fn a_genuine_per_os_bootstrap_failure_still_reds_only_that_os() {
        let schema: BTreeSet<String> = DEFAULT_MATRIX_COLUMNS
            .iter()
            .map(|c| (*c).to_owned())
            .collect();
        let targets = tri_os_targets();
        let report_dir = tempfile::tempdir().expect("tempdir");
        let mut values = BTreeMap::new();
        populate_stage_values(
            &mut values,
            &schema,
            report_dir.path(),
            &targets,
            &[
                stage_evidence("preflight", "pass"),
                stage_evidence("bootstrap_hosts", "pass"),
                stage_evidence("bootstrap_windows_host", "fail"),
            ],
        );

        assert_eq!(
            values.get("windows_stage_bootstrap").map(String::as_str),
            Some("fail"),
            "the OS whose bootstrap genuinely failed must read fail: {values:?}"
        );
        for platform in ["linux", "macos"] {
            let column = format!("{platform}_stage_bootstrap");
            assert_eq!(
                values.get(&column).map(String::as_str),
                Some("pass"),
                "{column} must be unaffected by another OS's bootstrap failure: {values:?}"
            );
        }
    }

    /// The defect was never bootstrap-only. `cross_network_substrate_setup`
    /// and `cross_network_preflight` are the same shape one column over: both
    /// are run-scoped preconditions sharing the `cross_network` logical column
    /// with eleven node-exercising CN stages, so a substrate that failed to
    /// provision reddened `linux_/macos_/windows_stage_cross_network` as
    /// though each OS's cross-network capability had been tested and failed.
    #[test]
    fn a_run_scoped_cross_network_failure_does_not_red_any_per_os_cross_network_column() {
        let schema: BTreeSet<String> = DEFAULT_MATRIX_COLUMNS
            .iter()
            .map(|c| (*c).to_owned())
            .collect();
        let targets = tri_os_targets();
        let report_dir = tempfile::tempdir().expect("tempdir");

        for run_scoped_stage in ["cross_network_substrate_setup", "cross_network_preflight"] {
            let mut values = BTreeMap::new();
            populate_stage_values(
                &mut values,
                &schema,
                report_dir.path(),
                &targets,
                &[stage_evidence(run_scoped_stage, "fail")],
            );
            for platform in ["linux", "macos", "windows"] {
                let column = format!("{platform}_stage_cross_network");
                assert_eq!(
                    values.get(&column),
                    None,
                    "{run_scoped_stage} is run-scoped and must not write {column}: {values:?}"
                );
            }
        }

        // ... while a genuinely node-exercising CN stage still fills them.
        let mut values = BTreeMap::new();
        populate_stage_values(
            &mut values,
            &schema,
            report_dir.path(),
            &targets,
            &[stage_evidence("cross_network_nat_matrix", "fail")],
        );
        for platform in ["linux", "macos", "windows"] {
            let column = format!("{platform}_stage_cross_network");
            assert_eq!(
                values.get(&column).map(String::as_str),
                Some("fail"),
                "a node-exercising CN stage must still populate {column}: {values:?}"
            );
        }
    }

    /// Pins the run-scoped SET against the orchestrator's own fanout, so the
    /// registry flag cannot drift from execution reality. The criterion is
    /// `StageGroup::Pre` + `StageFanout::Once`: a Pre stage that fans out per
    /// node has a genuine per-node verdict and stays attributable, while a Pre
    /// stage that runs once is a precondition on the lab as a whole. A newly
    /// added Pre/Once stage fails this test until it is flagged.
    ///
    /// Only names the Rust `--node` engine actually dispatches can be checked
    /// this way; bash-dialect Pre names (`prime_remote_access`,
    /// `macos_preflight_check`) have no `StageId` and no live producer, so
    /// they are outside the pairing.
    #[test]
    fn run_scoped_matches_orchestrator_fanout_for_every_dispatched_pre_stage() {
        use crate::live_lab_stage_registry::{STAGES, StageGroup};
        use crate::vm_lab::orchestrator::plan::PlanBuilder;
        use crate::vm_lab::orchestrator::stage::StageFanout;

        // The real plan, with EVERY opt-in suite enabled so no stage escapes
        // the pairing by living in a suite the default plan omits. The fanout
        // read here is therefore the one execution actually uses.
        let cross_network =
            crate::vm_lab::orchestrator::stage::cross_network::CrossNetworkOptions {
                enable_suite: true,
                ..Default::default()
            };
        let plan = PlanBuilder::new()
            .with_enable_chaos_suite(true)
            .with_enable_negative_control(true)
            .with_cross_network_options(cross_network)
            .build();
        let fanouts: BTreeMap<String, StageFanout> = plan
            .iter()
            .map(|stage| (stage.name().to_owned(), stage.fanout()))
            .collect();

        let mut checked = 0_usize;
        for spec in STAGES {
            let Some(fanout) = fanouts.get(spec.name).cloned() else {
                continue;
            };
            checked += 1;
            let expected = spec.group == StageGroup::Pre && fanout == StageFanout::Once;
            assert_eq!(
                spec.run_scoped, expected,
                "{} : run_scoped={} but group={:?} / fanout={:?} imply {}",
                spec.name, spec.run_scoped, spec.group, fanout, expected
            );
        }
        assert!(
            checked >= 20,
            "the fanout pairing checked only {checked} stages; the lookup has \
             probably stopped resolving and the guard is vacuous"
        );
        // The set this currently resolves to, named so a change is visible in
        // the diff rather than absorbed silently by the rule above.
        let flagged: Vec<&str> = STAGES
            .iter()
            .filter(|spec| spec.run_scoped)
            .map(|spec| spec.name)
            .collect();
        assert_eq!(
            flagged,
            vec![
                "preflight",
                "prepare_source_archive",
                "cross_network_substrate_setup",
                "cross_network_preflight",
            ]
        );
    }

    #[test]
    fn macos_win_parity_tier_stages_map_to_dedicated_csv_columns() {
        let schema: BTreeSet<String> = DEFAULT_MATRIX_COLUMNS
            .iter()
            .map(|c| (*c).to_owned())
            .collect();
        let mut values = BTreeMap::new();
        // macOS Tier-1 (DaemonProbeOp parity)
        for (stage, column) in [
            ("validate_macos_runtime_acls", "macos_runtime_acls"),
            (
                "validate_macos_service_hardening",
                "macos_service_hardening",
            ),
            ("validate_macos_mesh_status", "macos_mesh_status"),
            ("validate_macos_authenticode", "macos_authenticode"),
        ] {
            set_special_stage_values(&mut values, &schema, "macos", stage, "pass");
            assert_eq!(
                values.get(column).map(String::as_str),
                Some("pass"),
                "stage {stage} did not populate column {column}"
            );
        }
        // macOS Tier-2 (Tier2 pure-Rust protocol)
        for (stage, column) in [
            (
                "validate_macos_membership_revoke_applies",
                "macos_membership_revoke_applies",
            ),
            (
                "validate_macos_membership_signature_forgery",
                "macos_membership_signature_forgery",
            ),
            (
                "validate_macos_gossip_revoked_readmit",
                "macos_gossip_revoked_readmit",
            ),
            (
                "validate_macos_enrollment_replay",
                "macos_enrollment_replay",
            ),
            (
                "validate_macos_hello_limiter_flood",
                "macos_hello_limiter_flood",
            ),
        ] {
            set_special_stage_values(&mut values, &schema, "macos", stage, "pass");
            assert_eq!(
                values.get(column).map(String::as_str),
                Some("pass"),
                "stage {stage} did not populate column {column}"
            );
        }
        // macOS Tier-3/4 (protocol parity)
        for (stage, column) in [
            (
                "validate_macos_privileged_helper_allowlist",
                "macos_privileged_helper_allowlist",
            ),
            (
                "validate_macos_policy_default_deny",
                "macos_policy_default_deny",
            ),
            (
                "validate_macos_revoked_peer_denied_e2e",
                "macos_revoked_peer_denied_e2e",
            ),
            (
                "validate_macos_blind_exit_reversal_denied",
                "macos_blind_exit_reversal_denied",
            ),
        ] {
            set_special_stage_values(&mut values, &schema, "macos", stage, "pass");
            assert_eq!(
                values.get(column).map(String::as_str),
                Some("pass"),
                "stage {stage} did not populate column {column}"
            );
        }
        // Windows Tier-1/3/4 (DaemonProbeOp + protocol parity)
        for (stage, column) in [
            ("validate_windows_mesh_status", "windows_mesh_status"),
            (
                "validate_windows_privileged_helper_allowlist",
                "windows_privileged_helper_allowlist",
            ),
            (
                "validate_windows_policy_default_deny",
                "windows_policy_default_deny",
            ),
            (
                "validate_windows_revoked_peer_denied_e2e",
                "windows_revoked_peer_denied_e2e",
            ),
            (
                "validate_windows_blind_exit_reversal_denied",
                "windows_blind_exit_reversal_denied",
            ),
            // Tier-2 Windows columns also verify mapped names
            (
                "validate_windows_membership_revoke_applies",
                "windows_membership_revoke_applies",
            ),
            (
                "validate_windows_hello_limiter_flood",
                "windows_hello_limiter_flood",
            ),
        ] {
            set_special_stage_values(&mut values, &schema, "windows", stage, "pass");
            assert_eq!(
                values.get(column).map(String::as_str),
                Some("pass"),
                "stage {stage} did not populate column {column}"
            );
        }
        // Verify fail status round-trips
        let mut fail_values = BTreeMap::new();
        set_special_stage_values(
            &mut fail_values,
            &schema,
            "macos",
            "validate_macos_runtime_acls",
            "fail",
        );
        assert_eq!(
            fail_values.get("macos_runtime_acls").map(String::as_str),
            Some("fail")
        );
        // Verify unknown stage does not create spurious columns
        let mut noop_values = BTreeMap::new();
        set_special_stage_values(
            &mut noop_values,
            &schema,
            "linux",
            "bogus_unknown_stage",
            "pass",
        );
        assert_eq!(noop_values.len(), 0);
    }

    #[test]
    fn macos_exit_stages_mark_exit_role_not_blind_exit() {
        let schema: BTreeSet<String> = DEFAULT_MATRIX_COLUMNS
            .iter()
            .map(|c| (*c).to_owned())
            .collect();
        let mut values = BTreeMap::new();
        let stages = [
            "activate_macos_exit_role",
            "capture_macos_exit_evidence_artifacts",
            "validate_macos_exit_nat_lifecycle",
            "validate_macos_exit_dns_failclosed",
        ]
        .into_iter()
        .map(|stage| StageEvidence {
            started_at: String::new(),
            stage: stage.to_owned(),
            status: "pass".to_owned(),
            artifacts: Vec::new(),
        })
        .collect::<Vec<_>>();

        populate_role_result_values(&mut values, &schema, Path::new("."), &[], &stages);

        assert_eq!(values.get("macos_exit").map(String::as_str), Some("pass"));
        assert_eq!(values.get("macos_blind_exit").map(String::as_str), None);
    }

    #[test]
    fn macos_blind_exit_stage_marks_blind_exit_role() {
        let schema: BTreeSet<String> = DEFAULT_MATRIX_COLUMNS
            .iter()
            .map(|c| (*c).to_owned())
            .collect();
        let mut values = BTreeMap::new();
        let stages = [StageEvidence {
            started_at: String::new(),
            stage: "validate_macos_blind_exit".to_owned(),
            status: "pass".to_owned(),
            artifacts: Vec::new(),
        }];

        populate_role_result_values(&mut values, &schema, Path::new("."), &[], &stages);

        assert_eq!(
            values.get("macos_blind_exit").map(String::as_str),
            Some("pass")
        );
        assert_eq!(values.get("macos_exit").map(String::as_str), None);
    }

    #[test]
    fn baseline_pass_does_not_claim_role_specific_proof() {
        let schema: BTreeSet<String> = DEFAULT_MATRIX_COLUMNS
            .iter()
            .map(|column| (*column).to_owned())
            .collect();
        let targets = vec![TargetEvidence {
            label: "relay".to_owned(),
            target: "10.0.0.2".to_owned(),
            alias: "relay-1".to_owned(),
            platform: "linux".to_owned(),
            node_id: "relay-node".to_owned(),
            bootstrap_role: "relay".to_owned(),
        }];
        let baseline = [StageEvidence {
            started_at: String::new(),
            stage: "validate_baseline_runtime".to_owned(),
            status: "pass".to_owned(),
            artifacts: Vec::new(),
        }];
        let mut values = BTreeMap::new();
        populate_role_result_values(&mut values, &schema, Path::new("."), &targets, &baseline);
        assert_eq!(values.get("linux_relay"), None);
        assert_eq!(values.get("linux_client"), None);

        let role_proof = [StageEvidence {
            started_at: String::new(),
            stage: "relay_validation".to_owned(),
            status: "pass".to_owned(),
            artifacts: Vec::new(),
        }];
        populate_role_result_values(&mut values, &schema, Path::new("."), &targets, &role_proof);
        assert_eq!(values.get("linux_relay").map(String::as_str), Some("pass"));
    }

    #[test]
    fn orchestrator_outcomes_feed_matrix_after_worker_reload() {
        let root = temp_dir("orchestrator-outcomes");
        fs::create_dir_all(root.join("state")).expect("state dir");
        fs::create_dir_all(root.join("orchestration")).expect("orchestration dir");
        fs::write(
            root.join("state/stages.tsv"),
            "preflight\thard\tpass\t0\tlogs/preflight.log\tverify\t2026-07-03T18:24:21Z\t2026-07-03T18:24:21Z\n",
        )
        .expect("stages");
        fs::write(
            root.join("orchestration/orchestrate_result.json"),
            r#"{
  "overall_status": "partial",
  "outcomes": [
    {"stage": "activate_macos_exit_role", "status": "pass", "artifacts": []},
    {"stage": "validate_macos_exit_nat_lifecycle", "status": "pass", "artifacts": []},
    {"stage": "validate_macos_exit_dns_failclosed", "status": "pass", "artifacts": []}
  ]
}"#,
        )
        .expect("orchestrate result");
        let schema = DEFAULT_MATRIX_COLUMNS
            .iter()
            .map(|column| (*column).to_owned())
            .collect::<Vec<_>>();

        let values = build_live_lab_run_matrix_values(
            &schema,
            &LiveLabRunMatrixAppendConfig {
                command_name: "vm-lab-orchestrate-live-lab",
                report_dir: &root,
                profile_path: None,
                inventory_path: None,
                extra_stage_outcomes: &[],
                notes: None,
                row_role: super::LiveLabRunMatrixRowRole::Final,
            },
        )
        .expect("values");

        assert_eq!(
            values.get("overall_result").map(String::as_str),
            Some("pass")
        );
        assert_eq!(values.get("macos_exit").map(String::as_str), Some("pass"));
        assert_eq!(
            values.get("macos_stage_exit_handoff").map(String::as_str),
            Some("pass")
        );
        assert_ne!(
            values.get("macos_blind_exit").map(String::as_str),
            Some("pass")
        );
        let _ = fs::remove_dir_all(root);
    }

    /// QH-08 Option A: the provenance JSON the prepare_source_archive stage
    /// writes must land in the built run-matrix row, and its absence must
    /// leave every source-archive column blank (legacy/skipped runs).
    #[test]
    fn source_archive_provenance_populates_row_columns() {
        let root = temp_dir("source-archive-provenance");
        fs::create_dir_all(root.join("state")).expect("state dir");
        fs::write(
            root.join(super::SOURCE_ARCHIVE_PROVENANCE_RELATIVE_PATH),
            r#"{
  "schema_version": 1,
  "archive_file": "rn_source_1.tar.gz",
  "sha256": "abc123",
  "bytes": 4567,
  "source_mode": "working-tree",
  "allow_dirty": true,
  "git_commit": "deadbee",
  "git_dirty": true
}"#,
        )
        .expect("provenance");
        let schema = DEFAULT_MATRIX_COLUMNS
            .iter()
            .map(|column| (*column).to_owned())
            .collect::<Vec<_>>();

        let values = build_live_lab_run_matrix_values(
            &schema,
            &LiveLabRunMatrixAppendConfig {
                command_name: "vm-lab-orchestrate-live-lab",
                report_dir: &root,
                profile_path: None,
                inventory_path: None,
                extra_stage_outcomes: &[],
                notes: None,
                row_role: super::LiveLabRunMatrixRowRole::Final,
            },
        )
        .expect("values");

        assert_eq!(
            values.get("source_archive_sha256").map(String::as_str),
            Some("abc123")
        );
        assert_eq!(
            values.get("source_archive_bytes").map(String::as_str),
            Some("4567")
        );
        assert_eq!(
            values
                .get("source_archive_source_mode")
                .map(String::as_str),
            Some("working-tree")
        );
        assert_eq!(values.get("allow_dirty").map(String::as_str), Some("true"));
        assert_eq!(
            values
                .get("source_archive_git_commit")
                .map(String::as_str),
            Some("deadbee")
        );
        assert_eq!(
            values
                .get("source_archive_git_dirty")
                .map(String::as_str),
            Some("true")
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn absent_source_archive_provenance_leaves_row_columns_blank() {
        let root = temp_dir("no-source-archive-provenance");
        fs::create_dir_all(root.join("state")).expect("state dir");
        let schema = DEFAULT_MATRIX_COLUMNS
            .iter()
            .map(|column| (*column).to_owned())
            .collect::<Vec<_>>();

        let values = build_live_lab_run_matrix_values(
            &schema,
            &LiveLabRunMatrixAppendConfig {
                command_name: "vm-lab-orchestrate-live-lab",
                report_dir: &root,
                profile_path: None,
                inventory_path: None,
                extra_stage_outcomes: &[],
                notes: None,
                row_role: super::LiveLabRunMatrixRowRole::Final,
            },
        )
        .expect("values");

        for column in [
            "source_archive_sha256",
            "source_archive_bytes",
            "source_archive_source_mode",
            "allow_dirty",
            "source_archive_git_commit",
            "source_archive_git_dirty",
        ] {
            assert_eq!(
                values.get(column).map(String::as_str).unwrap_or(""),
                "",
                "absent provenance must leave {column} blank"
            );
        }
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn rsa0055_csv_escape_neutralizes_formula_injection() {
        // Cells beginning with =,+,-,@,TAB,CR must be prefixed with ' so a
        // spreadsheet renders them as text, not a formula.
        for payload in [
            "=cmd|'/c calc'!A1",
            "+1+1",
            "-2+3",
            "@SUM(A1)",
            "\tx",
            "\rx",
        ] {
            let escaped = csv_escape(payload.to_owned());
            assert!(
                escaped.starts_with('\'') || escaped.starts_with("\"'"),
                "formula cell must be neutralized: {payload:?} -> {escaped:?}"
            );
        }
        // Benign cells are untouched.
        assert_eq!(
            csv_escape("debian-headless-1".to_owned()),
            "debian-headless-1"
        );
        assert_eq!(csv_escape("Pass".to_owned()), "Pass");
        // A comma still triggers RFC4180 quoting (and a leading '=' inside is neutralized first).
        assert_eq!(csv_escape("=a,b".to_owned()), "\"'=a,b\"");
    }
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!("rustynet-run-matrix-{name}-{stamp}"))
    }

    fn write_fixture_report(root: &Path) -> PathBuf {
        let state = root.join("state");
        fs::create_dir_all(&state).expect("state dir");
        let profile = root.join("profile.env");
        fs::write(
            &profile,
            "EXIT_TARGET=\"debian@exit\"\nCLIENT_TARGET=\"debian@client\"\nSSH_IDENTITY_FILE=\"/tmp/id\"\nEXIT_PLATFORM=\"linux\"\nEXIT_REMOTE_SHELL=\"posix\"\nEXIT_GUEST_EXEC_MODE=\"linux_bash\"\nEXIT_SERVICE_MANAGER=\"systemd\"\nEXIT_UTM_NAME=\"debian-exit\"\nCLIENT_PLATFORM=\"windows\"\nCLIENT_REMOTE_SHELL=\"powershell\"\nCLIENT_GUEST_EXEC_MODE=\"windows_powershell\"\nCLIENT_SERVICE_MANAGER=\"windows_service\"\nCLIENT_UTM_NAME=\"windows-client\"\n",
        )
        .expect("profile");
        fs::write(
            state.join("setup_manifest.json"),
            format!(
                r#"{{
  "profile": {{"path": "{}"}},
  "git": {{"git_commit": "0123456789abcdef0123456789abcdef01234567", "git_tree_clean": true}}
}}"#,
                profile.display()
            ),
        )
        .expect("manifest");
        fs::write(
            state.join("report_state.json"),
            r#"{"run_complete": true, "run_passed": true}"#,
        )
        .expect("state");
        fs::write(
            state.join("nodes.tsv"),
            "exit\tdebian@exit\texit-1\tadmin\nclient\tdebian@client\tclient-1\tclient\n",
        )
        .expect("nodes");
        fs::write(
            state.join("stages.tsv"),
            "bootstrap_hosts\thard\tpass\t0\t/tmp/bootstrap.log\tbootstrap\t2026-05-27T10:00:00Z\t2026-05-27T10:01:00Z\nvalidate_baseline_runtime\thard\tpass\t0\t/tmp/baseline.log\tbaseline\t2026-05-27T10:02:00Z\t2026-05-27T10:03:00Z\n",
        )
        .expect("stages");
        let parallel = state.join("parallel-bootstrap_hosts");
        fs::create_dir_all(&parallel).expect("parallel");
        fs::write(
            parallel.join("results.tsv"),
            "bootstrap_hosts\texit\tdebian@exit\texit-1\tadmin\t0\t2026-05-27T10:00:00Z\t2026-05-27T10:00:10Z\t/tmp/exit.log\t\t\t\t\nbootstrap_hosts\tclient\tdebian@client\tclient-1\tclient\t0\t2026-05-27T10:00:00Z\t2026-05-27T10:00:10Z\t/tmp/client.log\t\t\t\t\n",
        )
        .expect("worker");
        profile
    }

    #[test]
    fn append_csv_row_serializes_concurrent_appends() {
        use std::sync::Arc;
        use std::thread;

        let root = temp_dir("concurrent-append");
        fs::create_dir_all(&root).expect("root");
        let csv = root.join("matrix.csv");
        let schema: Vec<String> = vec!["run_id".to_string()];
        fs::write(&csv, format!("{}\n", schema.join(","))).expect("seed header");

        const WRITERS: usize = 16;
        let csv = Arc::new(csv);
        let schema = Arc::new(schema);
        let handles: Vec<_> = (0..WRITERS)
            .map(|i| {
                let csv = Arc::clone(&csv);
                let schema = Arc::clone(&schema);
                thread::spawn(move || {
                    let mut values = BTreeMap::new();
                    values.insert("run_id".to_string(), format!("row-{i:02}"));
                    super::upsert_csv_row(
                        csv.as_path(),
                        schema.as_slice(),
                        &values,
                        super::LiveLabRunMatrixRowRole::Final,
                    )
                    .expect("append under lock");
                })
            })
            .collect();
        for handle in handles {
            handle.join().expect("writer thread");
        }

        let body = fs::read_to_string(csv.as_path()).expect("read back");
        let lines: Vec<&str> = body.lines().collect();
        // Header + exactly WRITERS data rows: no row lost, none interleaved.
        assert_eq!(
            lines.len(),
            WRITERS + 1,
            "expected header + {WRITERS} rows, got {body:?}"
        );
        assert_eq!(lines[0], "run_id");
        let mut seen: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        for line in &lines[1..] {
            assert!(
                line.starts_with("row-"),
                "garbled/interleaved row: {line:?}"
            );
            seen.insert(line);
        }
        assert_eq!(seen.len(), WRITERS, "every unique row present exactly once");

        let _ = fs::remove_dir_all(root.as_path());
    }

    #[test]
    fn target_evidence_requires_exact_target_node_id_and_role_match() {
        let nodes = vec![NodeRow {
            label: "debian-exit".to_owned(),
            target: "debian@192.0.2.10".to_owned(),
            node_id: "exit-node-1".to_owned(),
            bootstrap_role: "exit".to_owned(),
            platform: "linux".to_owned(),
            os_version: "Debian GNU/Linux 13 (trixie) (aarch64)".to_owned(),
        }];
        let valid = TargetEvidence {
            label: "debian-exit".to_owned(),
            target: "debian@192.0.2.10".to_owned(),
            alias: "debian-exit".to_owned(),
            platform: "linux".to_owned(),
            node_id: "exit-node-1".to_owned(),
            bootstrap_role: "exit".to_owned(),
        };
        validate_target_evidence(std::slice::from_ref(&valid), &nodes).expect("exact match");

        for invalid in [
            TargetEvidence {
                target: "debian@192.0.2.11".to_owned(),
                ..valid.clone()
            },
            TargetEvidence {
                node_id: "wrong-id".to_owned(),
                ..valid.clone()
            },
            TargetEvidence {
                bootstrap_role: "client".to_owned(),
                ..valid.clone()
            },
        ] {
            assert!(validate_target_evidence(std::slice::from_ref(&invalid), &nodes).is_err());
        }
    }

    #[test]
    fn csv_render_escapes_quotes_and_commas() {
        let schema = vec!["a".to_owned(), "b".to_owned()];
        let mut values = BTreeMap::new();
        values.insert("a".to_owned(), "hello, \"world\"".to_owned());
        values.insert("b".to_owned(), "ok".to_owned());
        let row = render_csv_row(&schema, &values);
        assert_eq!(row, "\"hello, \"\"world\"\"\",ok");
        assert_eq!(
            parse_csv_record(row.as_str()).expect("parse"),
            vec!["hello, \"world\"".to_owned(), "ok".to_owned()]
        );
    }

    #[test]
    fn matrix_values_follow_current_schema_and_fill_known_columns() {
        let root = temp_dir("fixture");
        let profile = write_fixture_report(&root);
        let schema = [
            "run_id",
            "git_commit",
            "git_dirty_state",
            "report_dir",
            "run_command",
            "overall_result",
            "linux_present",
            "linux_stage_bootstrap",
            "windows_stage_bootstrap",
            "linux_admin_alias",
            "windows_client_alias",
            "future_added_column",
        ]
        .into_iter()
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
        let extra = vec![LiveLabRunMatrixStageOutcome {
            stage: "bootstrap_windows_host".to_owned(),
            status: "pass".to_owned(),
            artifacts: Vec::new(),
        }];
        let values = build_live_lab_run_matrix_values(
            &schema,
            &LiveLabRunMatrixAppendConfig {
                command_name: "vm-lab-run-live-lab",
                report_dir: &root,
                profile_path: Some(profile.as_path()),
                inventory_path: None,
                extra_stage_outcomes: extra.as_slice(),
                notes: None,
                row_role: super::LiveLabRunMatrixRowRole::Final,
            },
        )
        .expect("values");
        assert_eq!(
            values["git_commit"],
            "0123456789abcdef0123456789abcdef01234567"
        );
        assert_eq!(values["git_dirty_state"], "clean");
        assert_eq!(values["overall_result"], "pass");
        assert_eq!(values["linux_present"], "pass");
        assert_eq!(values["linux_stage_bootstrap"], "pass");
        assert_eq!(values["windows_stage_bootstrap"], "pass");
        assert_eq!(values["linux_admin_alias"], "debian-exit");
        assert_eq!(values["windows_client_alias"], "windows-client");
        assert!(!values.contains_key("future_added_column"));
        let _ = fs::remove_dir_all(root);
    }

    /// QH-34: the run-start sample is authoritative for `git_dirty_state`.
    ///
    /// The later samples see the orchestrator's own mid-run refresh of
    /// `vm_lab_inventory.json`, so they answer a different question than the
    /// column asks. Pin both directions of disagreement so a future change
    /// cannot quietly demote the run-start reading back to a tiebreaker.
    #[test]
    fn git_dirty_state_prefers_the_run_start_sample_over_later_ones() {
        let dirty_at_start: Option<Value> = Some(serde_json::json!({
            "run_start_git_tree_clean": false,
            "last_run": {"git": {"git_tree_clean": true}},
        }));
        let clean_setup: Option<Value> = Some(serde_json::json!({
            "git": {"git_tree_clean": true},
        }));
        assert_eq!(
            git_dirty_state(&dirty_at_start, &clean_setup).as_deref(),
            Some("dirty:recorded"),
            "a tree already dirty at run start must stay flagged even though \
             the end-of-run samples read clean"
        );

        let clean_at_start: Option<Value> = Some(serde_json::json!({
            "run_start_git_tree_clean": true,
            "last_run": {"git": {"git_tree_clean": false}},
        }));
        assert_eq!(
            git_dirty_state(&clean_at_start, &None).as_deref(),
            Some("clean"),
            "a run that started clean must not be flagged for the orchestrator's \
             own mid-run inventory refresh"
        );

        // No run-start field (a state file written before QH-34, or a run whose
        // start-of-run `git status` failed): the later samples still apply.
        let legacy: Option<Value> = Some(serde_json::json!({
            "last_run": {"git": {"git_tree_clean": false}},
        }));
        assert_eq!(
            git_dirty_state(&legacy, &None).as_deref(),
            Some("dirty:recorded"),
            "the end-of-run sample must remain the fallback when no run-start \
             reading was recorded"
        );
    }

    #[test]
    fn rust_native_stage_outcomes_populate_matrix_coverage_cells() {
        let root = temp_dir("rust-native");
        let state = root.join("state");
        fs::create_dir_all(&state).expect("state dir");
        fs::write(
            state.join("report_state.json"),
            r#"{"run_complete": true, "run_passed": true}"#,
        )
        .expect("state");
        fs::write(
            root.join("parity_input.json"),
            r#"{
  "node_statuses": {
    "linux-exit": {"alias": "linux-exit", "platform": "linux", "role": "exit", "validator_results": []},
    "windows-client": {"alias": "windows-client", "platform": "windows", "role": "client", "validator_results": []}
  }
}"#,
        )
        .expect("parity");
        let stages = [
            "preflight",
            "prepare_source_archive",
            "verify_ssh_reachability",
            "cleanup_hosts",
            "bootstrap_hosts",
            "collect_pubkeys",
            "membership_init",
            "distribute_membership",
            "anchor_validation",
            "distribute_assignments",
            "distribute_traversal",
            "distribute_dns_zone",
            "enforce_baseline_runtime",
            "validate_baseline_runtime",
            "deploy_relay_service",
            "relay_validation",
            "traffic_test_matrix",
            // QH-07: `two_hop` coverage below must come from a real chained-exit
            // stage. Until 2026-07-27 this list named only `traffic_test_matrix`
            // and the `two_hop` assertion still passed — because that stage was
            // aliased onto the column. The alias was the defect, so that pass was
            // the bug proving itself. Naming the actual stage keeps the coverage
            // instead of deleting it, and makes the assertion mean what it says.
            //
            // Do NOT read this test as a guard against re-aliasing. It caught the
            // removal once, in transition, and is now insensitive to it: with both
            // stages in this list, restoring `logical: Some("two_hop")` on
            // `traffic_test_matrix` leaves it GREEN, because `merge_status` keeps
            // `pass` over `pass` and both stages report `pass` here. Verified by
            // mutation. The guard is
            // `live_lab_stage_registry::tests::traffic_test_matrix_feeds_no_two_hop_rollup_but_keeps_cross_os`,
            // which is the only test that fails on a BOTH-SIDES re-alias. A
            // registry-only re-alias also reds `registry_matches_historical_logical_stage_name`,
            // because the oracle would then disagree — measured: 2 failed, not 1.
            "live_two_hop_validation",
            "role_switch_matrix",
            "exit_handoff",
            "active_exit",
            "cleanup",
        ]
        .into_iter()
        .map(|stage| LiveLabRunMatrixStageOutcome {
            stage: stage.to_owned(),
            status: "pass".to_owned(),
            artifacts: Vec::new(),
        })
        .collect::<Vec<_>>();
        let schema = DEFAULT_MATRIX_COLUMNS
            .iter()
            .map(|column| (*column).to_owned())
            .collect::<Vec<_>>();

        let values = build_live_lab_run_matrix_values(
            &schema,
            &LiveLabRunMatrixAppendConfig {
                command_name: "vm-lab-orchestrate-live-lab",
                report_dir: &root,
                profile_path: None,
                inventory_path: None,
                extra_stage_outcomes: stages.as_slice(),
                notes: None,
                row_role: super::LiveLabRunMatrixRowRole::Final,
            },
        )
        .expect("values");

        assert_eq!(
            values.get("linux_present").map(String::as_str),
            Some("pass")
        );
        assert_eq!(
            values.get("windows_present").map(String::as_str),
            Some("pass")
        );
        assert_eq!(values.get("linux_exit").map(String::as_str), Some("pass"));
        assert_eq!(
            values.get("windows_client").map(String::as_str),
            Some("pass")
        );
        for platform in ["linux", "windows"] {
            for stage in [
                "bootstrap",
                "membership",
                "assignments",
                "baseline_runtime",
                "anchor",
                "relay_service_lifecycle",
                "exit_handoff",
                "two_hop",
                "role_switch_matrix",
                "managed_dns",
                "traversal",
                "cleanup",
            ] {
                let column = format!("{platform}_stage_{stage}");
                assert_eq!(
                    values.get(column.as_str()).map(String::as_str),
                    Some("pass"),
                    "{column} must be populated from rust-native StageId evidence"
                );
            }
        }
        for column in [
            "cross_os_bootstrap",
            "cross_os_peer_visibility",
            "cross_os_relay_path",
            "cross_os_exit_path",
            "cross_os_role_switch",
            "cross_os_anchor_bundle_pull",
        ] {
            assert_eq!(
                values.get(column).map(String::as_str),
                Some("pass"),
                "{column} must be populated from rust-native StageId evidence"
            );
        }
        // QH-43: these three are deliberately UNFED. Their only feeders were
        // host->guest distribution pushes, which cannot establish guest-to-guest
        // reachability -- the orchestrator host owns every lab bridge, so the push
        // succeeds across a total severance. `not_run` is now the truth: nothing
        // measures them. This fixture previously asserted `pass` for all three on
        // the strength of those pushes, which is exactly the false green QH-43
        // removes. They are owed real validators (blocked on QH-41).
        for column in [
            "cross_os_direct_path",
            "cross_os_membership_convergence",
            "cross_os_dns",
        ] {
            assert_eq!(
                values.get(column).map(String::as_str),
                None,
                "{column} must NOT be populated: its feeders were pushes, not reachability \
                 proofs (QH-43). A `pass` here means a distribution stage was re-mapped."
            );
        }
        let _ = fs::remove_dir_all(root);
    }
}

#[cfg(test)]
mod registry_equivalence_tests {
    //! Pins the registry-backed classification against verbatim copies of
    //! the four historical match tables this file used to own. If a registry
    //! edit changes the classification of any name in the recorded
    //! vocabulary, these tests fail — turning silent drift into a diff.
    //!
    //! Known, deliberate deltas (NOT covered by the oracles):
    //!   * alias names (`distribute_windows_bundles`) — the phantom now
    //!     resolves to `distribute_windows_membership` where the old tables
    //!     returned None; that healing is the point of the alias table.
    //!   * QH-07, 2026-07-27 — `traffic_test_matrix` returned `Some("two_hop")`
    //!     historically and now returns None. The oracle below was edited in
    //!     lockstep with the registry, which is this module's intended
    //!     workflow: it is a change DETECTOR, not an archive.
    //!
    //! Read the guarantee precisely, because the QH-07 delta narrows it: these
    //! tests prove the registry and the oracle AGREE. They do not prove that
    //! historical behaviour is preserved, and they cannot detect a change made
    //! to both sides at once — a re-alias of `traffic_test_matrix` onto
    //! `two_hop` in the registry AND here would leave all six of them green.
    //! That specific regression is guarded only by
    //! `live_lab_stage_registry::tests::traffic_test_matrix_feeds_no_two_hop_rollup_but_keeps_cross_os`.

    use super::{TargetEvidence, platforms_for_stage};
    use crate::live_lab_stage_registry;

    fn oracle_direct_platform_stage(stage: &str) -> Option<(&'static str, &'static str)> {
        match stage {
            "bootstrap_windows_host" => Some(("windows", "bootstrap")),
            "validate_windows_client_install" => Some(("windows", "baseline_runtime")),
            "amend_membership_for_windows" | "distribute_windows_membership" => {
                Some(("windows", "membership"))
            }
            "issue_windows_assignment" | "distribute_windows_assignment" => {
                Some(("windows", "assignments"))
            }
            "validate_windows_mesh_join" => Some(("windows", "mixed_topology")),
            "validate_windows_relay_service_lifecycle" => {
                Some(("windows", "relay_service_lifecycle"))
            }
            "validate_windows_anchor_bundle_pull" => Some(("windows", "anchor")),
            "capture_windows_exit_evidence_artifacts"
            | "promote_windows_exit_active"
            | "pull_windows_exit_evidence_artifacts"
            | "validate_windows_exit_nat_lifecycle" => Some(("windows", "exit_handoff")),
            "validate_windows_dns_failclosed" | "validate_windows_exit_dns_failclosed" => {
                Some(("windows", "managed_dns"))
            }
            "validate_windows_role_transition" => Some(("windows", "role_transition")),
            "bootstrap_macos_host" => Some(("macos", "bootstrap")),
            "collect_macos_pubkey" | "validate_macos_mesh_join" => {
                Some(("macos", "mixed_topology"))
            }
            "amend_membership_for_macos" | "distribute_macos_bundles" => {
                Some(("macos", "membership"))
            }
            "validate_macos_relay_service_lifecycle" => Some(("macos", "relay_service_lifecycle")),
            "validate_macos_anchor_bundle_pull" => Some(("macos", "anchor")),
            "capture_macos_exit_evidence_artifacts"
            | "validate_macos_exit_nat_lifecycle"
            | "validate_macos_ipv6_leak" => Some(("macos", "exit_handoff")),
            "validate_macos_exit_dns_failclosed" => Some(("macos", "managed_dns")),
            "validate_macos_role_transition" => Some(("macos", "role_transition")),
            "gossip_convergence_validation" => Some(("linux", "gossip_peer_convergence")),
            "validate_linux_relay_service_lifecycle" => Some(("linux", "relay_service_lifecycle")),
            "validate_linux_anchor_bundle_pull" => Some(("linux", "anchor")),
            "validate_linux_exit_nat_lifecycle"
            | "validate_linux_ipv6_leak"
            | "validate_linux_exit_demotion_residue" => Some(("linux", "exit_handoff")),
            "validate_linux_dns_failclosed" | "validate_linux_exit_dns_failclosed" => {
                Some(("linux", "managed_dns"))
            }
            _ => None,
        }
    }

    fn oracle_direct_platform_role(stage: &str) -> Option<(&'static str, &'static str)> {
        match stage {
            "validate_windows_client_install"
            | "validate_windows_runtime_acls"
            | "validate_windows_named_pipe_acls"
            | "validate_windows_service_hardening"
            | "validate_windows_key_custody" => Some(("windows", "client")),
            "capture_windows_exit_evidence_artifacts"
            | "promote_windows_exit_active"
            | "pull_windows_exit_evidence_artifacts"
            | "validate_windows_exit_nat_lifecycle"
            | "validate_windows_exit_dns_failclosed"
            | "validate_windows_exit_killswitch_precedence" => Some(("windows", "exit")),
            "validate_windows_relay_service_lifecycle" => Some(("windows", "relay")),
            "validate_windows_anchor_bundle_pull" => Some(("windows", "anchor")),
            "validate_windows_admin_issue" => Some(("windows", "admin")),
            "validate_macos_mesh_join" => Some(("macos", "client")),
            "activate_macos_exit_role"
            | "capture_macos_exit_evidence_artifacts"
            | "validate_macos_exit_nat_lifecycle"
            | "validate_macos_exit_dns_failclosed"
            | "validate_macos_exit_killswitch_precedence"
            | "validate_macos_ipv6_leak" => Some(("macos", "exit")),
            "validate_macos_blind_exit" => Some(("macos", "blind_exit")),
            "validate_macos_relay_service_lifecycle" => Some(("macos", "relay")),
            "validate_macos_anchor_bundle_pull" => Some(("macos", "anchor")),
            "validate_linux_exit_nat_lifecycle"
            | "validate_linux_ipv6_leak"
            | "validate_linux_exit_demotion_residue" => Some(("linux", "exit")),
            "validate_linux_relay_service_lifecycle" => Some(("linux", "relay")),
            "validate_linux_anchor_bundle_pull" => Some(("linux", "anchor")),
            _ => None,
        }
    }

    fn oracle_logical_stage_name(stage: &str) -> Option<&'static str> {
        match stage {
            "preflight"
            | "prepare_source_archive"
            | "verify_ssh_reachability"
            | "prime_remote_access"
            | "cleanup_hosts"
            | "bootstrap_hosts"
            | "collect_pubkeys" => Some("bootstrap"),
            "membership_init"
            | "distribute_membership"
            | "membership_setup"
            | "distribute_membership_state" => Some("membership"),
            "distribute_assignments" | "issue_and_distribute_assignments" => Some("assignments"),
            "distribute_traversal" => Some("traversal"),
            "distribute_dns_zone" => Some("managed_dns"),
            "enforce_baseline_runtime" | "validate_baseline_runtime" => Some("baseline_runtime"),
            "anchor_validation" | "live_anchor" => Some("anchor"),
            "deploy_relay_service" | "relay_validation" | "live_relay" => {
                Some("relay_service_lifecycle")
            }
            "exit_handoff" | "active_exit" | "live_exit_handoff" => Some("exit_handoff"),
            "admin_issue" => Some("admin"),
            "blind_exit" => Some("blind_exit"),
            // QH-07: `traffic_test_matrix` deliberately maps to NO roll-up column.
            //
            // It used to map to `two_hop`, which made the column a false-green:
            // `traffic_test_matrix` proves only that the mesh pings (every pair
            // reachable), whereas the two-hop column is read as proof of the chained
            // exit path. Against the per-stage ledger the divergence is total —
            // `live_two_hop_validation` is skip 222 / fail 81 / **pass 0**, while
            // `traffic_test_matrix` is pass 185 — so a `pass` in that column never
            // meant two-hop worked. Reporting into no column is strictly more honest
            // than reporting into the wrong one. It is NOT free, though: see the
            // spec comment in `live_lab_stage_registry.rs` for what a single-platform
            // run stops writing. The per-stage results are unaffected and remain in
            // `live_lab_node_stage_results.csv`.
            //
            // Deliberately NOT re-aliased to another column: adding one is a schema
            // migration (fixed header list, ~39 references, plus 94 + 549 existing
            // rows that predate any new header) and is tracked separately.
            "role_switch_matrix" => Some("role_switch_matrix"),
            "live_lan_toggle" => Some("lan_toggle"),
            "live_two_hop" => Some("two_hop"),
            "live_role_switch_matrix" => Some("role_switch_matrix"),
            "live_managed_dns" => Some("managed_dns"),
            "live_mixed_topology" => Some("mixed_topology"),
            "live_reboot_recovery" => Some("reboot_recovery"),
            "live_secrets_not_in_logs" => Some("secrets_not_in_logs"),
            "live_key_custody" => Some("key_custody"),
            "live_enrollment_restart" => Some("enrollment_restart"),
            "live_network_flap" => Some("network_flap"),
            "live_network_flap_validation" => Some("network_flap"),
            "live_hello_limiter_flood_validation" => Some("hello_limiter_flood"),
            "extended_soak" => Some("extended_soak"),
            "dns_failclosed_validation" => Some("dns_failclosed_check"),
            "runtime_acls_validation" => Some("runtime_acls_check"),
            "service_hardening_validation" => Some("service_hardening_check"),
            "key_custody_validation" => Some("key_custody_check"),
            "mesh_status_validation" => Some("mesh_status_check"),
            "authenticode_validation" => Some("authenticode_check"),
            "ipv6_leak_validation" => Some("ipv6_leak_check"),
            "exit_demotion_residue_validation" => Some("exit_demotion_residue_check"),
            "exit_dns_failclosed_validation" => Some("exit_dns_failclosed_check"),
            "exit_nat_lifecycle_validation" => Some("exit_nat_lifecycle_check"),
            "blind_exit_dataplane_validation" => Some("blind_exit_dataplane_check"),
            "live_two_hop_validation" => Some("two_hop"),
            "live_managed_dns_validation" => Some("managed_dns"),
            "live_reboot_recovery_validation" => Some("reboot_recovery"),
            "live_secrets_not_in_logs_validation" => Some("secrets_not_in_logs"),
            "live_key_custody_validation" => Some("key_custody"),
            "live_enrollment_restart_validation" => Some("enrollment_restart"),
            "live_lan_toggle_validation" => Some("lan_toggle"),
            "live_mixed_topology_validation" => Some("mixed_topology"),
            "cleanup" => Some("cleanup"),
            stage if stage.starts_with("cross_network_") => Some("cross_network"),
            stage if stage.starts_with("chaos_") => Some("chaos"),
            stage if stage.contains("reboot") => Some("reboot_recovery"),
            _ => None,
        }
    }

    fn oracle_is_rust_native(stage: &str) -> bool {
        // RNQ-16: the expected-membership oracle derives from the typed
        // authority (`StageId`) instead of a hand-maintained historical copy
        // that had to be edited in lockstep with every stage addition. The
        // prefix fallback mirrors the registry's rule for unknown
        // `chaos_`/`cross_network_` names.
        use crate::vm_lab::orchestrator::stage::StageId;
        StageId::try_from(stage).is_ok()
            || stage.starts_with("chaos_")
            || stage.starts_with("cross_network_")
    }

    fn oracle_cross_os_column(stage: &str) -> Option<&'static str> {
        match stage {
            "preflight"
            | "prepare_source_archive"
            | "verify_ssh_reachability"
            | "cleanup_hosts"
            | "bootstrap_hosts"
            | "collect_pubkeys" => Some("cross_os_bootstrap"),
            "live_mixed_topology" | "validate_windows_mesh_join" | "validate_macos_mesh_join" => {
                Some("cross_os_peer_visibility")
            }
            "live_exit_handoff"
            | "exit_handoff"
            | "active_exit"
            | "promote_windows_exit_active" => Some("cross_os_exit_path"),
            "live_relay"
            | "deploy_relay_service"
            | "relay_validation"
            | "validate_windows_relay_service_lifecycle"
            | "validate_macos_relay_service_lifecycle" => Some("cross_os_relay_path"),
            "live_lan_toggle" => Some("cross_os_lan_toggle"),
            "live_role_switch_matrix" | "role_switch_matrix" => Some("cross_os_role_switch"),
            "live_managed_dns"
            | "validate_windows_dns_failclosed"
            | "validate_macos_exit_dns_failclosed" => Some("cross_os_dns"),
            "traffic_test_matrix" => Some("cross_os_peer_visibility"),
            "anchor_validation" => Some("cross_os_anchor_bundle_pull"),
            "validate_windows_anchor_bundle_pull"
            | "validate_macos_anchor_bundle_pull"
            | "validate_linux_anchor_bundle_pull" => Some("cross_os_anchor_bundle_pull"),
            _ => None,
        }
    }

    fn oracle_special_column(stage: &str) -> Option<&'static str> {
        match stage {
            "validate_windows_named_pipe_acls" => Some("windows_named_pipe_acl"),
            "validate_windows_key_custody" => Some("windows_dpapi_key_custody"),
            "validate_macos_key_custody" => Some("macos_keychain_key_custody"),
            "validate_macos_exit_killswitch_precedence" => Some("macos_pf_killswitch"),
            "validate_linux_membership_revoke_applies" => Some("linux_membership_revoke_applies"),
            "validate_linux_revoked_peer_denied_e2e" => Some("linux_revoked_peer_denied_e2e"),
            "validate_linux_membership_signature_forgery" => {
                Some("linux_membership_signature_forgery")
            }
            "validate_linux_privileged_helper_allowlist" => {
                Some("linux_privileged_helper_allowlist")
            }
            "validate_linux_policy_default_deny" => Some("linux_policy_default_deny"),
            "validate_linux_runtime_acls" => Some("linux_runtime_acls"),
            "validate_linux_service_hardening" => Some("linux_service_hardening"),
            "validate_linux_authenticode" => Some("linux_authenticode"),
            "validate_linux_key_custody" => Some("linux_key_custody"),
            "validate_linux_membership_genesis" => Some("linux_membership_genesis"),
            "validate_linux_mesh_status" => Some("linux_mesh_status"),
            "validate_linux_blind_exit_reversal_denied" => Some("linux_blind_exit_reversal_denied"),
            "validate_linux_gossip_revoked_readmit" => Some("linux_gossip_revoked_readmit"),
            "validate_linux_enrollment_replay" => Some("linux_enrollment_replay"),
            "validate_linux_hello_limiter_flood" => Some("linux_hello_limiter_flood"),
            "validate_linux_relay_forwards_frame" => Some("linux_relay_forwards_frame"),
            "validate_windows_membership_revoke_applies" => {
                Some("windows_membership_revoke_applies")
            }
            "validate_windows_membership_signature_forgery" => {
                Some("windows_membership_signature_forgery")
            }
            "validate_windows_gossip_revoked_readmit" => Some("windows_gossip_revoked_readmit"),
            "validate_windows_enrollment_replay" => Some("windows_enrollment_replay"),
            "validate_windows_hello_limiter_flood" => Some("windows_hello_limiter_flood"),
            "validate_macos_membership_revoke_applies" => Some("macos_membership_revoke_applies"),
            "validate_macos_membership_signature_forgery" => {
                Some("macos_membership_signature_forgery")
            }
            "validate_macos_gossip_revoked_readmit" => Some("macos_gossip_revoked_readmit"),
            "validate_macos_enrollment_replay" => Some("macos_enrollment_replay"),
            "validate_macos_hello_limiter_flood" => Some("macos_hello_limiter_flood"),
            "validate_macos_runtime_acls" => Some("macos_runtime_acls"),
            "validate_macos_service_hardening" => Some("macos_service_hardening"),
            "validate_macos_mesh_status" => Some("macos_mesh_status"),
            "validate_macos_authenticode" => Some("macos_authenticode"),
            "validate_macos_privileged_helper_allowlist" => {
                Some("macos_privileged_helper_allowlist")
            }
            "validate_macos_policy_default_deny" => Some("macos_policy_default_deny"),
            "validate_macos_revoked_peer_denied_e2e" => Some("macos_revoked_peer_denied_e2e"),
            "validate_macos_blind_exit_reversal_denied" => Some("macos_blind_exit_reversal_denied"),
            "validate_windows_mesh_status" => Some("windows_mesh_status"),
            "validate_windows_privileged_helper_allowlist" => {
                Some("windows_privileged_helper_allowlist")
            }
            "validate_windows_policy_default_deny" => Some("windows_policy_default_deny"),
            "validate_windows_revoked_peer_denied_e2e" => Some("windows_revoked_peer_denied_e2e"),
            "validate_windows_blind_exit_reversal_denied" => {
                Some("windows_blind_exit_reversal_denied")
            }
            _ => None,
        }
    }

    /// Every canonical registry name plus the historical prefix/fallback
    /// cases and a set of unknowns. Aliases are deliberately excluded (see
    /// module doc).
    fn probe_names() -> Vec<&'static str> {
        let mut names: Vec<&'static str> = live_lab_stage_registry::all_stage_names().collect();
        names.extend([
            "chaos_totally_new_scenario",
            "post_upgrade_reboot_check",
            "cross_network_vxlan_ssh_e2e",
            "no_such_stage_ever",
            "debian-headless-1::validate_linux_hello_limiter_flood",
            "debian-headless-4::validate_linux_blind_exit_dataplane",
        ]);
        names
    }

    #[test]
    fn registry_matches_historical_direct_platform_stage() {
        for name in probe_names() {
            let bare = name.rsplit("::").next().unwrap_or(name);
            assert_eq!(
                super::direct_platform_stage(bare),
                oracle_direct_platform_stage(bare),
                "direct_platform_stage diverged for {bare}"
            );
        }
    }

    #[test]
    fn registry_matches_historical_direct_platform_role() {
        for name in probe_names() {
            let bare = name.rsplit("::").next().unwrap_or(name);
            assert_eq!(
                super::direct_platform_role(bare),
                oracle_direct_platform_role(bare),
                "direct_platform_role diverged for {bare}"
            );
        }
    }

    #[test]
    fn registry_matches_historical_logical_stage_name() {
        for name in probe_names() {
            let bare = name.rsplit("::").next().unwrap_or(name);
            assert_eq!(
                super::logical_stage_name(bare),
                oracle_logical_stage_name(bare),
                "logical_stage_name diverged for {bare}"
            );
        }
    }

    /// QH-07: a direct pin on the mapping THIS writer feeds the `two_hop`
    /// column through. The registry guard
    /// (`traffic_test_matrix_feeds_no_two_hop_rollup_but_keeps_cross_os`) owns
    /// the authority, and the equivalence test above only checks that the
    /// registry and the historical oracle AGREE — so a change that moved both
    /// sides at once would leave both green. This test fails independently of
    /// either: `traffic_test_matrix` must roll up to no column, while the two
    /// genuine chained-exit synonyms keep feeding `two_hop`.
    #[test]
    fn traffic_test_matrix_feeds_no_column_while_both_two_hop_synonyms_do() {
        assert_eq!(
            super::logical_stage_name("traffic_test_matrix"),
            None,
            "traffic_test_matrix proves mesh-ping reachability, not the chained \
             exit path; feeding the two_hop column from it is the false-green \
             defect QH-07 records"
        );
        for synonym in ["live_two_hop", "live_two_hop_validation"] {
            assert_eq!(
                super::logical_stage_name(synonym),
                Some("two_hop"),
                "{synonym} is a genuine chained-exit proof and must keep feeding \
                 the two_hop column; dropping it would orphan the column's only \
                 honest feeders"
            );
        }
    }

    #[test]
    fn rust_native_vocabulary_is_the_stage_id_authority() {
        use crate::vm_lab::orchestrator::stage::StageId;
        // RNQ-16 characterization: every typed stage is rust-native by
        // definition (registry + oracle both derive from StageId now).
        for id in StageId::ALL {
            assert!(
                live_lab_stage_registry::is_rust_native_stage_name(id.as_str()),
                "StageId member must be rust-native: {}",
                id.as_str()
            );
        }
        // Independent negatives: bash-dialect-only names must NOT be claimed
        // by the Rust vocabulary. These fail if someone adds the bash name to
        // StageId instead of the canonical Rust name.
        for bash_only in [
            "membership_setup",
            "distribute_membership_state",
            "issue_and_distribute_assignments",
            "prime_remote_access",
            "local_full_gate_suite",
            "fresh_install_os_matrix_report",
            "live_relay",
            "live_mixed_topology",
            "upgrade_admin_node_membership",
        ] {
            assert!(
                !live_lab_stage_registry::is_rust_native_stage_name(bash_only),
                "bash-only stage must not be rust-native: {bash_only}"
            );
        }
        // Prefix fallback preserved: unknown chaos_/cross_network_ names stay in
        // the Rust suite families by construction. Pinned with names that are
        // deliberately absent from both the registry and `StageId` — this used
        // to be pinned with `cross_network_daemon_path`, which was deleted with
        // the rest of the CN-5 bash tail and would now pass for the wrong
        // reason once someone re-registered it.
        assert!(live_lab_stage_registry::is_rust_native_stage_name(
            "cross_network_unregistered_probe"
        ));
        assert!(live_lab_stage_registry::is_rust_native_stage_name(
            "chaos_unregistered_probe"
        ));
    }

    #[test]
    fn registry_matches_historical_rust_native_and_cross_os_and_special() {
        for name in probe_names() {
            let bare = name.rsplit("::").next().unwrap_or(name);
            assert_eq!(
                live_lab_stage_registry::is_rust_native_stage_name(bare),
                oracle_is_rust_native(bare),
                "is_rust_native diverged for {bare}"
            );
            assert_eq!(
                live_lab_stage_registry::cross_os_column(bare),
                oracle_cross_os_column(bare),
                "cross_os_column diverged for {bare}"
            );
            assert_eq!(
                live_lab_stage_registry::special_column(bare),
                oracle_special_column(bare),
                "special_column diverged for {bare}"
            );
        }
    }

    #[test]
    fn registry_matches_historical_platform_resolution() {
        fn target(label: &str, platform: &str) -> TargetEvidence {
            TargetEvidence {
                label: label.to_owned(),
                target: format!("{label}@10.0.0.1"),
                alias: label.to_owned(),
                platform: platform.to_owned(),
                node_id: format!("node-{label}"),
                bootstrap_role: label.to_owned(),
            }
        }
        // `relay_label` elects "entry" (or "aux") as the relay target, so
        // the fixture uses the real label vocabulary.
        let mixed = vec![
            target("admin", "linux"),
            target("exit", "macos"),
            target("entry", "windows"),
            target("client", "linux"),
        ];
        for name in probe_names() {
            let bare = name.rsplit("::").next().unwrap_or(name);
            let expected: Vec<String> = if bare == "gossip_convergence_validation" {
                // First rust-native stage that is LINUX-ONLY by product
                // constraint rather than lab convenience: the gossip transport
                // is unix-only, so the daemon refuses a configured secret
                // elsewhere. The blanket "rust-native implies all three
                // platforms" rule below does not hold for it, and emitting
                // macos/windows columns that can only ever read `skip` would be
                // noise rather than evidence.
                vec!["linux".into()]
            } else if matches!(
                bare,
                "deploy_macos_anchor_profile"
                    | "validate_macos_anchor_bundle_pull"
                    | "validate_macos_anchor_port_mapping_authority"
            ) {
                // MAC-D3: the three macOS anchor validators are rust-native
                // stages now, but they are platform-gated behind an ELECTED
                // macOS anchor. This fixture has no anchor node at all, so on
                // macos/windows they can only ever read `skip` — same
                // noise-not-evidence rule as the gossip special case above.
                vec!["linux".into()]
            } else if oracle_is_rust_native(bare) {
                vec!["linux".into(), "macos".into(), "windows".into()]
            } else {
                match bare {
                    "live_anchor" | "live_exit_handoff" => vec!["macos".into()],
                    "live_relay" => vec!["windows".into()],
                    "live_mixed_topology" => {
                        vec!["linux".into(), "macos".into(), "windows".into()]
                    }
                    _ if bare.starts_with("cross_network_") => {
                        vec!["linux".into(), "macos".into(), "windows".into()]
                    }
                    _ => vec!["linux".into()],
                }
            };
            assert_eq!(
                platforms_for_stage(bare, &mixed),
                expected,
                "platforms_for_stage diverged for {bare}"
            );
        }
    }
}

#[cfg(test)]
mod upsert_tests {
    //! Finding 2: the run — not the code path — owns its matrix row.
    //! (report_dir, run_started_utc) is the natural key; interim rows are
    //! crash-visibility records that a final row replaces.

    use super::{LiveLabRunMatrixRowRole, parse_csv_record, upsert_csv_row};
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::PathBuf;

    fn schema() -> Vec<String> {
        [
            "run_id",
            "run_started_utc",
            "report_dir",
            "overall_result",
            "row_role",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }

    fn row_values(
        run_id: &str,
        started: &str,
        report_dir: &str,
        result: &str,
        role: LiveLabRunMatrixRowRole,
    ) -> BTreeMap<String, String> {
        let mut values = BTreeMap::new();
        values.insert("run_id".to_owned(), run_id.to_owned());
        values.insert("run_started_utc".to_owned(), started.to_owned());
        values.insert("report_dir".to_owned(), report_dir.to_owned());
        values.insert("overall_result".to_owned(), result.to_owned());
        values.insert("row_role".to_owned(), role.as_str().to_owned());
        values
    }

    fn temp_matrix(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "upsert_matrix_{name}_{}_{}.csv",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0)
        ));
        fs::write(&path, format!("{}\n", schema().join(","))).expect("seed matrix header");
        path
    }

    fn data_rows(path: &PathBuf) -> Vec<Vec<String>> {
        let body = fs::read_to_string(path).expect("read matrix");
        body.lines()
            .skip(1)
            .filter(|line| !line.trim().is_empty())
            .map(|line| parse_csv_record(line).expect("parse row"))
            .collect()
    }

    #[test]
    fn final_row_replaces_interim_row_for_same_run_key() {
        let path = temp_matrix("final_replaces");
        let schema = schema();
        let interim = row_values(
            "run-a",
            "2026-07-03T10:00:00Z",
            "/tmp/report-a",
            "pass", // the trap's systematically optimistic verdict
            LiveLabRunMatrixRowRole::Interim,
        );
        assert!(
            upsert_csv_row(&path, &schema, &interim, LiveLabRunMatrixRowRole::Interim)
                .expect("interim write")
        );
        let complete = row_values(
            "run-a",
            "2026-07-03T10:00:00Z",
            "/tmp/report-a",
            "fail", // the supervisor saw the sidecar failures
            LiveLabRunMatrixRowRole::Final,
        );
        assert!(
            upsert_csv_row(&path, &schema, &complete, LiveLabRunMatrixRowRole::Final)
                .expect("final write")
        );
        let rows = data_rows(&path);
        assert_eq!(rows.len(), 1, "one row per run: {rows:?}");
        assert_eq!(rows[0][3], "fail");
        assert_eq!(rows[0][4], "final");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn interim_never_lands_on_an_owned_run_key() {
        let path = temp_matrix("interim_skips");
        let schema = schema();
        let complete = row_values(
            "run-a",
            "2026-07-03T10:00:00Z",
            "/tmp/report-a",
            "fail",
            LiveLabRunMatrixRowRole::Final,
        );
        assert!(
            upsert_csv_row(&path, &schema, &complete, LiveLabRunMatrixRowRole::Final)
                .expect("final write")
        );
        let stale_trap = row_values(
            "run-a",
            "2026-07-03T10:00:00Z",
            "/tmp/report-a",
            "pass",
            LiveLabRunMatrixRowRole::Interim,
        );
        assert!(
            !upsert_csv_row(
                &path,
                &schema,
                &stale_trap,
                LiveLabRunMatrixRowRole::Interim
            )
            .expect("interim attempt"),
            "interim write must be skipped when the key is owned"
        );
        let rows = data_rows(&path);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0][3], "fail");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn distinct_run_keys_do_not_interfere() {
        let path = temp_matrix("distinct_keys");
        let schema = schema();
        for (run, started, dir) in [
            ("run-a", "2026-07-03T10:00:00Z", "/tmp/report-a"),
            ("run-b", "2026-07-03T11:00:00Z", "/tmp/report-b"),
            // same dir, different start = a later reuse of the report dir
            ("run-c", "2026-07-03T12:00:00Z", "/tmp/report-a"),
        ] {
            let values = row_values(run, started, dir, "pass", LiveLabRunMatrixRowRole::Final);
            assert!(
                upsert_csv_row(&path, &schema, &values, LiveLabRunMatrixRowRole::Final)
                    .expect("write")
            );
        }
        assert_eq!(data_rows(&path).len(), 3);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn degenerate_key_falls_back_to_plain_append() {
        let path = temp_matrix("degenerate");
        let schema = schema();
        // No run_started_utc (e.g. a run that recorded no stages): ownership
        // cannot be established, so both writes append — never guess.
        let first = row_values(
            "run-a",
            "",
            "/tmp/report-a",
            "unknown",
            LiveLabRunMatrixRowRole::Interim,
        );
        let second = row_values(
            "run-a",
            "",
            "/tmp/report-a",
            "unknown",
            LiveLabRunMatrixRowRole::Final,
        );
        assert!(
            upsert_csv_row(&path, &schema, &first, LiveLabRunMatrixRowRole::Interim)
                .expect("first write")
        );
        assert!(
            upsert_csv_row(&path, &schema, &second, LiveLabRunMatrixRowRole::Final)
                .expect("second write")
        );
        assert_eq!(data_rows(&path).len(), 2);
        let _ = fs::remove_file(&path);
    }
}

#[cfg(test)]
mod conclusion_barrier_tests {
    //! Finding 3: planned stages must not evaporate without a recorded
    //! ending. The barrier synthesizes `aborted` for manifest-enabled,
    //! non-exempt stages with no outcome — and overall_result demotes a
    //! "passing" run whose plan has holes.

    use super::{
        NODE_STAGE_COLUMNS, NodeStagePlanEntry, StageEvidence, apply_conclusion_barrier,
        attributable_node_status, node_stage_scope, normalize_os_family, overall_result,
        parse_csv_record, render_named_csv_row, upsert_node_stage_csv, write_node_stage_csv,
    };
    use crate::live_lab_stage_manifest::{build_stage_manifest, write_stage_manifest};
    use crate::live_lab_stage_registry::TargetSelectors;
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::PathBuf;

    fn temp_report_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "barrier_{name}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&dir).expect("temp report dir");
        dir
    }

    fn test_plan() -> std::collections::HashSet<String> {
        [
            "preflight",
            "bootstrap_hosts",
            "membership_init",
            "distribute_membership",
            "live_managed_dns",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect()
    }

    fn evidence(stage: &str, status: &str) -> StageEvidence {
        StageEvidence {
            started_at: String::new(),
            stage: stage.to_owned(),
            status: status.to_owned(),
            artifacts: Vec::new(),
        }
    }

    /// Every barrier-eligible enabled stage recorded → nothing synthesized.
    /// (Linux-only selectors keep the eligible set small enough to
    /// enumerate exactly: the shared pipeline + the non-audit live suite.)
    fn fully_recorded_evidence() -> Vec<StageEvidence> {
        let manifest =
            build_stage_manifest("test", "full", &TargetSelectors::default(), &test_plan());
        manifest
            .stages
            .iter()
            .filter(|stage| stage.enabled && !stage.synthetic && !stage.barrier_exempt)
            .map(|stage| evidence(stage.name.as_str(), "pass"))
            .collect()
    }

    #[test]
    fn barrier_synthesizes_aborted_for_planned_unrecorded_stages() {
        let dir = temp_report_dir("synthesizes");
        let manifest =
            build_stage_manifest("test", "full", &TargetSelectors::default(), &test_plan());
        write_stage_manifest(dir.as_path(), &manifest).expect("write manifest");

        // The run recorded everything except live_managed_dns.
        let mut stages: Vec<StageEvidence> = fully_recorded_evidence()
            .into_iter()
            .filter(|stage| stage.stage != "live_managed_dns")
            .collect();
        apply_conclusion_barrier(&mut stages, dir.as_path()).expect("barrier");
        let synthesized: Vec<&StageEvidence> = stages
            .iter()
            .filter(|stage| stage.status == "aborted")
            .collect();
        assert_eq!(synthesized.len(), 1, "{synthesized:?}");
        assert_eq!(synthesized[0].stage, "live_managed_dns");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn barrier_is_silent_when_every_planned_stage_recorded() {
        let dir = temp_report_dir("complete");
        let manifest =
            build_stage_manifest("test", "full", &TargetSelectors::default(), &test_plan());
        write_stage_manifest(dir.as_path(), &manifest).expect("write manifest");
        let mut stages = fully_recorded_evidence();
        let before = stages.len();
        apply_conclusion_barrier(&mut stages, dir.as_path()).expect("barrier");
        assert_eq!(stages.len(), before);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn barrier_respects_run_mode_exemptions_and_node_composites() {
        let dir = temp_report_dir("modes");
        // setup_only: recording nothing for the live suite is legitimate.
        let manifest = build_stage_manifest(
            "test",
            "setup_only",
            &TargetSelectors::default(),
            &test_plan(),
        );
        write_stage_manifest(dir.as_path(), &manifest).expect("write manifest");
        let mut stages = vec![evidence("preflight", "pass")];
        apply_conclusion_barrier(&mut stages, dir.as_path()).expect("barrier");
        assert_eq!(stages.len(), 1, "setup_only must not synthesize");
        let _ = fs::remove_dir_all(&dir);

        // Missing manifest (pre-manifest report dirs): no-op.
        let dir = temp_report_dir("no_manifest");
        let mut stages = vec![evidence("preflight", "pass")];
        apply_conclusion_barrier(&mut stages, dir.as_path()).expect("barrier");
        assert_eq!(stages.len(), 1);
        let _ = fs::remove_dir_all(&dir);

        // Node-scoped composites count as recordings of the bare stage.
        let dir = temp_report_dir("composites");
        let manifest =
            build_stage_manifest("test", "full", &TargetSelectors::default(), &test_plan());
        write_stage_manifest(dir.as_path(), &manifest).expect("write manifest");
        let mut stages = fully_recorded_evidence();
        // Replace the flat record with a node-scoped one.
        stages.retain(|stage| stage.stage != "live_anchor");
        stages.push(evidence("debian-headless-1::live_anchor", "pass"));
        apply_conclusion_barrier(&mut stages, dir.as_path()).expect("barrier");
        assert!(
            !stages
                .iter()
                .any(|stage| stage.stage == "live_anchor" && stage.status == "aborted"),
            "a node-scoped record must satisfy the barrier for the bare stage"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn barrier_never_marks_exempt_or_disabled_stages() {
        let dir = temp_report_dir("exempt");
        // Chaos + audit families stay quiet even though a full manifest
        // exists: chaos is disabled by default selectors, audits are
        // barrier-exempt (conditional dispatch).
        let manifest =
            build_stage_manifest("test", "full", &TargetSelectors::default(), &test_plan());
        write_stage_manifest(dir.as_path(), &manifest).expect("write manifest");
        let mut stages = fully_recorded_evidence();
        apply_conclusion_barrier(&mut stages, dir.as_path()).expect("barrier");
        assert!(
            !stages.iter().any(|stage| {
                stage.status == "aborted"
                    && (stage.stage.starts_with("chaos_")
                        || stage.stage.starts_with("validate_linux_")
                        || stage.stage == "extended_soak"
                        || stage.stage == "local_full_gate_suite")
            }),
            "exempt/disabled stages must not be marked aborted"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn overall_result_demotes_runs_with_aborted_stages() {
        use serde_json::json;
        // Linux suite said pass, but a planned stage evaporated.
        let state = Some(json!({"run_complete": true, "run_passed": true}));
        let stages = vec![
            evidence("preflight", "pass"),
            evidence("live_relay", "aborted"),
        ];
        assert_eq!(overall_result(&state, &stages), "aborted");
        // A real fail still dominates.
        let stages = vec![
            evidence("preflight", "fail"),
            evidence("live_relay", "aborted"),
        ];
        assert_eq!(overall_result(&None, &stages), "fail");
        // No report state: aborted beats pass.
        let stages = vec![
            evidence("preflight", "pass"),
            evidence("live_relay", "aborted"),
        ];
        assert_eq!(overall_result(&None, &stages), "aborted");
        // Clean pass unchanged.
        let state = Some(json!({"run_complete": true, "run_passed": true}));
        assert_eq!(
            overall_result(&state, &[evidence("preflight", "pass")]),
            "pass"
        );

        // A stale/tampered report-state pass can never override stage failure.
        let state = Some(json!({"run_complete": true, "run_passed": true}));
        assert_eq!(
            overall_result(&state, &[evidence("preflight", "fail")]),
            "fail"
        );

        // Focused/reused evidence is honest partial proof, never comprehensive.
        assert_eq!(
            overall_result(&state, &[evidence("preflight", "reused")]),
            "partial"
        );
    }

    #[test]
    fn conclusion_barrier_rejects_corrupt_manifest() {
        let dir = temp_report_dir("corrupt-manifest");
        let path = dir.join(crate::live_lab_stage_manifest::STAGE_MANIFEST_RELATIVE_PATH);
        fs::create_dir_all(path.parent().expect("manifest parent")).expect("manifest dir");
        fs::write(&path, b"{not-json").expect("corrupt manifest");
        let mut stages = vec![evidence("preflight", "pass")];
        assert!(apply_conclusion_barrier(&mut stages, dir.as_path()).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn status_vocabulary_recognizes_terminal_states() {
        use super::{normalize_status, status_rank};
        assert_eq!(normalize_status("aborted"), "aborted");
        assert_eq!(normalize_status("timed_out"), "timed_out");
        assert_eq!(normalize_status("timeout"), "timed_out");
        // Worst-wins ordering: fail > timed_out > aborted > blocked > skip > pass.
        assert!(status_rank("fail") > status_rank("timed_out"));
        assert!(status_rank("timed_out") > status_rank("aborted"));
        assert!(status_rank("aborted") > status_rank("blocked"));
        assert!(status_rank("blocked") > status_rank("skip"));
        assert!(status_rank("skip") > status_rank("pass"));
    }

    /// QH-37. A logical column summarises a SET of stages, so one pass must not
    /// speak for stages that never ran.
    #[test]
    fn skip_outranks_pass_so_a_partially_skipped_column_never_reads_green() {
        use super::merge_status;
        assert_eq!(merge_status("pass", "skip"), "skip");
        // Order-independent: the merge folds in arrival order, and a column that
        // read green only because the passes happened to arrive last would be
        // the same bug wearing a different hat.
        assert_eq!(merge_status("skip", "pass"), "skip");
    }

    /// The exact shape that made this defect visible: `cross_network` has 11
    /// contributing stages, of which only `cross_network_preflight` and
    /// `cross_network_nat_classification` run on a single-network lab. Every
    /// committed row showing `linux_stage_cross_network=pass` is this set.
    #[test]
    fn the_measured_cross_network_shape_folds_to_skip_not_pass() {
        use super::merge_status;
        let observed = [
            "pass", "skip", "skip", "skip", "skip", "skip", "pass", "skip", "skip",
        ];
        let folded = observed.iter().fold(String::new(), |acc, next| {
            if acc.is_empty() {
                (*next).to_owned()
            } else {
                merge_status(&acc, next)
            }
        });
        assert_eq!(
            folded, "skip",
            "2-of-11 must not render as a pass; that is what QH-37 records"
        );
    }

    /// `fail` must still dominate everything, including the new skip rank —
    /// raising skip must not accidentally let a partially-skipped set hide a
    /// real failure.
    #[test]
    fn fail_still_dominates_skip_and_pass() {
        use super::merge_status;
        assert_eq!(merge_status("skip", "fail"), "fail");
        assert_eq!(merge_status("fail", "skip"), "fail");
        assert_eq!(merge_status("pass", "fail"), "fail");
    }

    /// `not_proven` is a fail that could not be pinned on a specific node.
    ///
    /// It is written ONLY into the per-node ledger today
    /// (`attributable_node_status`, whose single production caller is
    /// `write_node_stage_result_ledgers`), so it never reaches this merge — I
    /// measured 0 occurrences in the run-matrix CSV against 74 in the per-stage
    /// CSV. This pins the behaviour anyway, so that if a later change ever does
    /// route it here it fails closed instead of silently degrading to `unknown`
    /// (rank 2) and being outranked by a pass.
    #[test]
    fn not_proven_is_ranked_with_fail_and_survives_normalisation() {
        use super::{merge_status, normalize_status, status_rank};
        assert_eq!(
            normalize_status("not_proven"),
            "not_proven",
            "must not degrade to `unknown`; it is a failure, not an unrecognised token"
        );
        assert_eq!(status_rank("not_proven"), status_rank("fail"));
        assert_eq!(merge_status("pass", "not_proven"), "not_proven");
        assert_eq!(merge_status("not_proven", "pass"), "not_proven");
        assert_eq!(merge_status("skip", "not_proven"), "not_proven");
    }

    #[test]
    fn an_unknown_status_is_never_masked_by_a_co_occurring_pass() {
        use super::{merge_status, status_rank};
        // §2.2: a malformed/unrecognized status is a data-integrity non-pass and
        // must outrank a pass in a merge, or a torn/tampered token would be
        // silently swallowed by a co-occurring pass.
        assert!(status_rank("unknown") > status_rank("pass"));
        assert_eq!(merge_status("pass", "unknown"), "unknown");
        assert_eq!(merge_status("unknown", "pass"), "unknown");
        // A real, specific failure still outranks an unknown.
        assert_eq!(merge_status("unknown", "fail"), "fail");
    }

    #[test]
    fn exact_os_family_normalization_rejects_linux_umbrella() {
        for (platform, version, expected) in [
            ("linux", "Debian GNU/Linux 13 (trixie) (aarch64)", "debian"),
            ("linux", "Rocky Linux 10.2 (Red Quartz) (aarch64)", "rocky"),
            ("linux", "Ubuntu 26.04 LTS (aarch64)", "ubuntu"),
            (
                "linux",
                "Fedora Linux 44 (Server Edition) (aarch64)",
                "fedora",
            ),
            ("macos", "macOS 26.5 (arm64)", "macos"),
            ("windows", "Windows [Version 10.0.26100] AMD64", "windows"),
        ] {
            assert_eq!(normalize_os_family(platform, version).unwrap(), expected);
        }
        assert!(normalize_os_family("linux", "Linux 6.12.0").is_err());
        assert!(normalize_os_family("linux", "linux").is_err());
    }

    #[test]
    fn failed_per_node_stage_never_falsely_fails_unidentified_nodes() {
        let summary = "rocky-utm-1: tcpdump missing";
        assert_eq!(
            attributable_node_status("fail", "node", "rocky-utm-1", summary),
            "fail"
        );
        assert_eq!(
            attributable_node_status("fail", "node", "debian-headless-2", summary),
            "not_proven"
        );
        assert_eq!(
            attributable_node_status("pass", "node", "debian-headless-2", ""),
            "pass"
        );
    }

    #[test]
    fn role_scoped_once_stage_is_node_evidence() {
        let exit_stage = NodeStagePlanEntry {
            stage: "exit_dns_failclosed_validation".to_owned(),
            fanout: "once".to_owned(),
            roles: vec!["exit".to_owned()],
        };
        assert_eq!(node_stage_scope(&exit_stage).unwrap(), "node");

        let topology_stage = NodeStagePlanEntry {
            stage: "traffic_test_matrix".to_owned(),
            fanout: "once".to_owned(),
            roles: Vec::new(),
        };
        assert_eq!(node_stage_scope(&topology_stage).unwrap(), "topology");
    }

    /// An older, shorter header must be READ correctly and UPGRADED on write.
    ///
    /// The schema lives in two artifacts, so this covers the aggregate half. The
    /// old row is built from the old column list itself, so this test keeps
    /// working when a column is appended (which is the event it exists for).
    #[test]
    fn an_old_header_aggregate_is_read_and_upgraded_on_write() {
        let root = temp_report_dir("node-stage-migrate");
        let path = root.join("node-stage.csv");

        // Previous schema = canonical minus the appended trailing column.
        let old_columns: Vec<&str> = NODE_STAGE_COLUMNS[..NODE_STAGE_COLUMNS.len() - 1].to_vec();
        let appended = *NODE_STAGE_COLUMNS.last().expect("a canonical column");
        let mut old_row = BTreeMap::new();
        for column in &old_columns {
            old_row.insert((*column).to_owned(), format!("old-{column}"));
        }
        let body = format!(
            "{}\n{}\n",
            old_columns.join(","),
            render_named_csv_row(&old_columns, &old_row)
        );
        fs::write(&path, body).expect("seed an old-header ledger");

        let mut new_row = BTreeMap::new();
        for (key, value) in [
            ("run_id", "run-new"),
            ("report_dir", "/tmp/report-new"),
            ("alias", "rocky-utm-1"),
            ("status", "pass"),
        ] {
            new_row.insert(key.to_owned(), value.to_owned());
        }
        upsert_node_stage_csv(&path, "run-new", "/tmp/report-new", &[new_row])
            .expect("an older header must migrate, not error");

        let out = fs::read_to_string(&path).expect("read migrated ledger");
        let mut lines = out.lines();
        assert_eq!(
            lines.next().expect("header"),
            NODE_STAGE_COLUMNS.join(","),
            "the header must be upgraded to the canonical schema"
        );

        let rows: Vec<Vec<String>> = lines
            .filter(|line| !line.trim().is_empty())
            .map(|line| parse_csv_record(line).expect("row parses"))
            .collect();
        assert_eq!(rows.len(), 2, "the pre-existing row must survive migration");
        for row in &rows {
            assert_eq!(
                row.len(),
                NODE_STAGE_COLUMNS.len(),
                "every row must be widened to the canonical width"
            );
        }

        // Alignment is the whole point: each old value must still sit under its
        // own column, and the appended column must be empty rather than shifted.
        let index = |name: &str| {
            NODE_STAGE_COLUMNS
                .iter()
                .position(|column| *column == name)
                .expect("canonical column")
        };
        let migrated = rows
            .iter()
            .find(|row| row[index("run_id")] == "old-run_id")
            .expect("the migrated old row");
        for column in &old_columns {
            assert_eq!(
                migrated[index(column)],
                format!("old-{column}"),
                "column {column} must not shift during migration"
            );
        }
        assert_eq!(
            migrated[index(appended)],
            "",
            "the appended column must be empty for a row written before it existed"
        );

        let _ = fs::remove_dir_all(root);
    }

    /// Only APPENDED columns are migratable. A reordered header, or one from a
    /// newer build, must fail closed — guessing an alignment would corrupt the
    /// committed ledger silently.
    #[test]
    fn a_non_appended_node_stage_header_change_fails_closed() {
        let root = temp_report_dir("node-stage-badhdr");

        let mut swapped: Vec<&str> = NODE_STAGE_COLUMNS.to_vec();
        swapped.swap(1, 2);
        let reordered = root.join("reordered.csv");
        fs::write(&reordered, format!("{}\n", swapped.join(","))).expect("seed reordered");
        let err = upsert_node_stage_csv(&reordered, "r", "/d", &[BTreeMap::new()])
            .expect_err("a reordered header must be rejected");
        assert!(
            err.contains("schema mismatch"),
            "must name the mismatch, got: {err}"
        );

        let newer = root.join("newer.csv");
        let mut wider: Vec<&str> = NODE_STAGE_COLUMNS.to_vec();
        wider.push("column_from_the_future");
        fs::write(&newer, format!("{}\n", wider.join(","))).expect("seed newer");
        let err = upsert_node_stage_csv(&newer, "r", "/d", &[BTreeMap::new()])
            .expect_err("a newer schema must be rejected");
        assert!(
            err.contains("NEWER than this build"),
            "must say the binary is behind, got: {err}"
        );

        let _ = fs::remove_dir_all(root);
    }

    /// The per-run half of the same schema. It is rewritten whole, so an old
    /// header left by an earlier build is replaced — asserted rather than assumed,
    /// because that stops holding the moment someone makes this function append.
    #[test]
    fn an_existing_per_run_file_with_an_old_header_is_rewritten_canonical() {
        let root = temp_report_dir("node-stage-perrun");
        let path = root.join("state/live_lab_node_stage_results.csv");
        fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        let old_columns: Vec<&str> = NODE_STAGE_COLUMNS[..NODE_STAGE_COLUMNS.len() - 1].to_vec();
        fs::write(&path, format!("{}\nstale,row\n", old_columns.join(","))).expect("seed");

        let mut row = BTreeMap::new();
        row.insert("run_id".to_owned(), "run-1".to_owned());
        row.insert("status".to_owned(), "pass".to_owned());
        write_node_stage_csv(&path, &[row]).expect("write per-run CSV");

        let out = fs::read_to_string(&path).expect("read");
        assert_eq!(
            out.lines().next().expect("header"),
            NODE_STAGE_COLUMNS.join(","),
            "the per-run artifact must carry the canonical header after a write"
        );
        assert!(
            !out.contains("stale,row"),
            "the per-run file is owned by one run and rewritten whole"
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn normalized_node_stage_csv_upserts_one_run_without_duplicates() {
        let root = temp_report_dir("node-stage-upsert");
        let path = root.join("node-stage.csv");
        let row = |status: &str| {
            let mut values = BTreeMap::new();
            for (key, value) in [
                ("run_id", "run-1"),
                ("report_dir", "/tmp/report-1"),
                ("alias", "rocky-utm-1"),
                ("os_family", "rocky"),
                ("os_version", "Rocky Linux 10.2 (aarch64)"),
                ("stage", "bootstrap_hosts"),
                ("status", status),
            ] {
                values.insert(key.to_owned(), value.to_owned());
            }
            values
        };
        upsert_node_stage_csv(&path, "run-1", "/tmp/report-1", &[row("fail")])
            .expect("initial append");
        upsert_node_stage_csv(&path, "run-1", "/tmp/report-1", &[row("pass")])
            .expect("replace same run");
        let body = std::fs::read_to_string(&path).expect("node-stage CSV");
        assert_eq!(body.lines().count(), 2, "header + one replacement row");
        assert!(body.contains("rocky-utm-1") && body.contains(",pass,"));
        let _ = std::fs::remove_dir_all(root);
    }

    use std::collections::BTreeSet;
    use std::path::Path as StdPath;

    use crate::live_lab_run_matrix::{
        DEFAULT_MATRIX_COLUMNS, dedupe_stage_evidence, first_failed_stage,
        populate_security_audit_control_values,
    };

    fn security_audit_stage(status: &str) -> Vec<StageEvidence> {
        vec![StageEvidence {
            started_at: String::new(),
            stage: "security_audit_validation".to_owned(),
            status: status.to_owned(),
            artifacts: Vec::new(),
        }]
    }

    fn write_per_control(dir: &StdPath, controls: serde_json::Value) {
        std::fs::write(
            dir.join("security_audit_validation.per_control.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "stage": "security_audit_validation",
                "schema_version": 1,
                "controls": controls,
            }))
            .expect("serialize"),
        )
        .expect("write per-control artifact");
    }

    fn control_values(dir: &StdPath, stages: &[StageEvidence]) -> BTreeMap<String, String> {
        let schema: BTreeSet<String> = DEFAULT_MATRIX_COLUMNS
            .iter()
            .map(|c| (*c).to_owned())
            .collect();
        let mut values = BTreeMap::new();
        populate_security_audit_control_values(&mut values, &schema, dir, stages);
        values
    }

    #[test]
    fn per_control_artifact_populates_the_platform_security_columns() {
        let root = temp_report_dir("sec-audit-controls");
        write_per_control(
            &root,
            serde_json::json!([
                {"alias": "deb-1", "platform": "linux", "audit_id": "policy_default_deny", "status": "pass"},
                {"alias": "deb-1", "platform": "linux", "audit_id": "enrollment_replay", "status": "pass"},
            ]),
        );
        let values = control_values(&root, &security_audit_stage("pass"));
        assert_eq!(
            values.get("linux_policy_default_deny").map(String::as_str),
            Some("pass")
        );
        assert_eq!(
            values.get("linux_enrollment_replay").map(String::as_str),
            Some("pass")
        );
        // A platform with no node in the run is never written, so it keeps its
        // `not_run` default rather than inheriting another platform's verdict.
        assert!(!values.contains_key("macos_policy_default_deny"));
        assert!(!values.contains_key("windows_policy_default_deny"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn one_failing_node_prevents_its_platform_column_reading_green() {
        let root = temp_report_dir("sec-audit-worst-wins");
        write_per_control(
            &root,
            serde_json::json!([
                {"alias": "deb-1", "platform": "linux", "audit_id": "policy_default_deny", "status": "pass"},
                {"alias": "deb-2", "platform": "linux", "audit_id": "policy_default_deny", "status": "fail"},
            ]),
        );
        let values = control_values(&root, &security_audit_stage("fail"));
        assert_eq!(
            values.get("linux_policy_default_deny").map(String::as_str),
            Some("fail"),
            "a pass on one node must not outrank a fail on another"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn an_unexercised_control_records_blocked_not_pass_and_not_not_run() {
        // The audits run all-eight rather than fail-fast precisely so an
        // unreached control gets a verdict. `blocked` outranks `pass`, and it
        // is distinct from `not_run`, which asserts no node of that platform
        // was in the run at all.
        let root = temp_report_dir("sec-audit-blocked");
        write_per_control(
            &root,
            serde_json::json!([
                {"alias": "deb-1", "platform": "linux", "audit_id": "policy_default_deny", "status": "pass"},
                {"alias": "deb-1", "platform": "linux", "audit_id": "gossip_revoked_readmit", "status": "blocked"},
            ]),
        );
        let values = control_values(&root, &security_audit_stage("fail"));
        assert_eq!(
            values
                .get("linux_gossip_revoked_readmit")
                .map(String::as_str),
            Some("blocked")
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn an_empty_artifact_erases_a_previous_invocations_claim() {
        // Report directories are legitimately reused (resume / rerun-stage /
        // run-only). A rerun in which nothing was exercised writes an EMPTY
        // controls array, and that must clear the earlier claim rather than
        // leaving it to be read as this run's evidence.
        let root = temp_report_dir("sec-audit-reuse");
        write_per_control(
            &root,
            serde_json::json!([
                {"alias": "deb-1", "platform": "linux", "audit_id": "policy_default_deny", "status": "pass"},
            ]),
        );
        assert_eq!(
            control_values(&root, &security_audit_stage("pass"))
                .get("linux_policy_default_deny")
                .map(String::as_str),
            Some("pass")
        );
        write_per_control(&root, serde_json::json!([]));
        assert!(
            control_values(&root, &security_audit_stage("fail")).is_empty(),
            "a zero-verdict rerun must not inherit the previous invocation's pass"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn an_unrecognised_schema_version_writes_no_column() {
        let root = temp_report_dir("sec-audit-schema");
        std::fs::write(
            root.join("security_audit_validation.per_control.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "stage": "security_audit_validation",
                "schema_version": 999,
                "controls": [
                    {"alias": "deb-1", "platform": "linux",
                     "audit_id": "policy_default_deny", "status": "pass"}
                ],
            }))
            .expect("serialize"),
        )
        .expect("write");
        assert!(
            control_values(&root, &security_audit_stage("pass")).is_empty(),
            "an unknown schema must be rejected, not guessed at"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_missing_or_malformed_artifact_writes_no_column() {
        let root = temp_report_dir("sec-audit-missing");
        // Missing entirely.
        assert!(control_values(&root, &security_audit_stage("fail")).is_empty());
        // Present but malformed: must not panic, must not guess.
        std::fs::write(
            root.join("security_audit_validation.per_control.json"),
            b"{ not json",
        )
        .expect("write");
        assert!(control_values(&root, &security_audit_stage("fail")).is_empty());
        let _ = std::fs::remove_dir_all(root);
    }

    fn ev(stage: &str, status: &str, started_at: &str) -> StageEvidence {
        StageEvidence {
            stage: stage.to_owned(),
            status: status.to_owned(),
            artifacts: Vec::new(),
            started_at: started_at.to_owned(),
        }
    }

    #[test]
    fn first_failed_stage_is_chronological_not_alphabetical() {
        // The documented misdirection: `cleanup` (a downstream artifact-collector
        // bug) was named while `preflight` had failed four seconds earlier, so
        // triage started at the wrong stage. Alphabetically `cleanup` wins;
        // chronologically `preflight` does.
        let stages = [
            ev("cleanup", "fail", "2026-07-25T18:52:23Z"),
            ev("preflight", "fail", "2026-07-25T18:52:19Z"),
        ];
        assert_eq!(
            first_failed_stage(&stages).as_deref(),
            Some("preflight"),
            "the EARLIER failure must be named, not the alphabetically first"
        );
    }

    #[test]
    fn a_timestamped_failure_outranks_an_untimestamped_one() {
        // Sources without a time (orchestrate_result.json, extra_stage_outcomes)
        // must never outrank a stage that actually recorded one, regardless of
        // name order.
        let stages = [
            ev("aaa_no_time", "fail", ""),
            ev("zzz_timed", "fail", "2026-07-25T18:52:19Z"),
        ];
        assert_eq!(
            first_failed_stage(&stages).as_deref(),
            Some("zzz_timed"),
            "an empty started_at must sort LAST, not first"
        );
    }

    #[test]
    fn untimestamped_failures_fall_back_to_a_deterministic_name_order() {
        let stages = [ev("zzz", "fail", ""), ev("aaa", "fail", "")];
        assert_eq!(first_failed_stage(&stages).as_deref(), Some("aaa"));
    }

    #[test]
    fn a_same_second_tie_is_deterministic_and_matches_the_old_answer() {
        // Stamps are 1-second granularity, so ties are possible. The name
        // tiebreak keeps the result stable AND reproduces the previous
        // alphabetical answer exactly when times are equal.
        let stages = [
            ev("zzz", "fail", "2026-07-25T18:52:19Z"),
            ev("aaa", "fail", "2026-07-25T18:52:19Z"),
        ];
        assert_eq!(first_failed_stage(&stages).as_deref(), Some("aaa"));
    }

    #[test]
    fn passing_stages_are_never_selected_however_early() {
        let stages = [
            ev("early_pass", "pass", "2026-07-25T18:00:00Z"),
            ev("late_fail", "fail", "2026-07-25T19:00:00Z"),
        ];
        assert_eq!(first_failed_stage(&stages).as_deref(), Some("late_fail"));
        assert_eq!(first_failed_stage(&[ev("ok", "pass", "")]), None);
    }

    #[test]
    fn dedupe_pairs_the_merged_status_with_the_winning_attempts_start() {
        // Real fixture, byte-for-byte from
        // artifacts/live_lab/20260411T190200Z_handoff_retry_working_tree/state/stages.tsv:
        // the same stage recorded pass, then fail, then fail. Taking the earliest
        // time unconditionally pairs the merged `fail` with 18:26:41Z -- the start
        // of the attempt that PASSED.
        let mut stages = vec![
            ev("live_role_switch_matrix", "pass", "2026-04-11T18:26:41Z"),
            ev("live_role_switch_matrix", "fail", "2026-04-11T18:34:52Z"),
            ev("live_role_switch_matrix", "fail", "2026-04-11T18:42:26Z"),
        ];
        dedupe_stage_evidence(&mut stages);
        assert_eq!(stages.len(), 1);
        assert_eq!(stages[0].status, "fail");
        assert_eq!(
            stages[0].started_at, "2026-04-11T18:34:52Z",
            "the merged fail must carry the first FAILING attempt's start, \
             never the passing attempt's"
        );
    }

    #[test]
    fn dedupe_keeps_the_earlier_start_among_equal_status_records() {
        let mut stages = vec![
            ev("s", "fail", "2026-04-11T18:42:26Z"),
            ev("s", "fail", "2026-04-11T18:34:52Z"),
        ];
        dedupe_stage_evidence(&mut stages);
        assert_eq!(stages[0].started_at, "2026-04-11T18:34:52Z");
    }

    #[test]
    fn dedupe_keeps_a_real_start_when_an_equal_status_record_has_none() {
        let mut stages = vec![ev("s", "fail", "2026-04-11T18:34:52Z"), ev("s", "fail", "")];
        dedupe_stage_evidence(&mut stages);
        assert_eq!(stages[0].started_at, "2026-04-11T18:34:52Z");
    }

    #[test]
    fn a_timeless_higher_ranking_record_cannot_erase_a_real_start() {
        // THE branch the first round of tests missed. stages.tsv carries times;
        // orchestrate_result.json and extra_stage_outcomes never do, and they are
        // always merged second. A `pass` restated as `fail` by a timeless source
        // must keep its recorded start -- blanking it sends the failure to the
        // BACK of the empty-last ordering, which is QH-22's misdirection again.
        let mut stages = vec![ev("s", "pass", "2026-07-25T18:00:00Z"), ev("s", "fail", "")];
        dedupe_stage_evidence(&mut stages);
        assert_eq!(stages[0].status, "fail");
        assert_eq!(
            stages[0].started_at, "2026-07-25T18:00:00Z",
            "a timeless report restates the outcome; it cannot re-date the stage"
        );
    }

    #[test]
    fn the_timeless_restatement_still_wins_the_first_failure_race() {
        // End to end: the whole point of keeping the start is the ORDERING.
        let mut stages = vec![
            ev("preflight", "pass", "2026-07-25T18:00:00Z"),
            ev("preflight", "fail", ""),
            ev("cleanup", "fail", "2026-07-25T19:00:00Z"),
        ];
        dedupe_stage_evidence(&mut stages);
        assert_eq!(
            first_failed_stage(&stages).as_deref(),
            Some("preflight"),
            "preflight failed first and its start is known; it must not sort last"
        );
    }

    #[test]
    fn a_whitespace_only_stamp_is_treated_as_no_time_not_as_an_early_one() {
        // ' ' (0x20) sorts below '2' (0x32), so a garbage stamp would otherwise
        // win the race outright. sanitize() maps tab/newline/CR to spaces, so
        // this shape is producible.
        let stages = [
            ev("blank_stamp", "fail", "   "),
            ev("real", "fail", "2026-07-25T19:00:00Z"),
        ];
        assert_eq!(first_failed_stage(&stages).as_deref(), Some("real"));
    }

    #[test]
    fn a_merged_not_proven_cannot_erase_a_failure() {
        // status_rank ranks not_proven WITH fail, and merge_status uses >=, so a
        // not_proven arriving second wins the merge. Both consumers used to test
        // the literal "fail", so the run then reported NOT-failed and named no
        // first failure -- the hardening had turned "masked by a pass" into
        // "erases the fail".
        let mut stages = vec![
            ev("s", "fail", "2026-07-25T18:00:00Z"),
            ev("s", "not_proven", "2026-07-25T18:00:00Z"),
        ];
        dedupe_stage_evidence(&mut stages);
        assert_eq!(super::overall_result(&None, &stages), "fail");
        assert_eq!(first_failed_stage(&stages).as_deref(), Some("s"));
    }

    #[test]
    fn a_skip_cascaded_stage_does_not_ingest_a_previous_invocations_artifact() {
        // The stage skip-cascades when a dependency skips. Its `execute` never
        // runs, so it never rewrites the artifact -- but the stage name IS still
        // present in stages.tsv with status `skipped`. On a reused report dir a
        // name-only guard would read the prior invocation's artifact as this
        // run's evidence and record `pass` for controls never exercised.
        let root = temp_report_dir("sec-audit-skip-cascade");
        write_per_control(
            &root,
            serde_json::json!([
                {"alias": "deb-1", "platform": "linux", "audit_id": "policy_default_deny", "status": "pass"},
            ]),
        );
        for status in ["skip", "skipped", "not_run"] {
            assert!(
                control_values(&root, &security_audit_stage(status)).is_empty(),
                "a `{status}` stage must not ingest a stale artifact"
            );
        }
        // A stage that really did dispatch still ingests normally.
        assert_eq!(
            control_values(&root, &security_audit_stage("fail"))
                .get("linux_policy_default_deny")
                .map(String::as_str),
            Some("pass")
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn controls_are_ignored_when_the_stage_did_not_dispatch() {
        // A stale artifact left in a report directory must not manufacture
        // evidence for a run whose plan never included the stage.
        let root = temp_report_dir("sec-audit-undispatched");
        write_per_control(
            &root,
            serde_json::json!([
                {"alias": "deb-1", "platform": "linux", "audit_id": "policy_default_deny", "status": "pass"},
            ]),
        );
        let other = vec![StageEvidence {
            started_at: String::new(),
            stage: "cleanup".to_owned(),
            status: "pass".to_owned(),
            artifacts: Vec::new(),
        }];
        assert!(control_values(&root, &other).is_empty());
        let _ = std::fs::remove_dir_all(root);
    }
}

#[test]
fn node_and_legacy_run_matrices_are_distinct_ledgers() {
    // The engines must never share a ledger. A blended matrix reports a
    // stage column as `pass` without saying which engine proved it: the
    // legacy bash orchestrator passed two-hop 52 times while the Rust
    // --node engine had never passed it once, and a single file made those
    // indistinguishable.
    let legacy = default_live_lab_run_matrix_path();
    let node = default_live_lab_node_run_matrix_path();
    assert_ne!(legacy, node, "engines must not share a run matrix");
    assert!(
        legacy.ends_with("documents/operations/live_lab_run_matrix.csv"),
        "legacy archive path moved: {}",
        legacy.display()
    );
    assert!(
        node.ends_with("documents/operations/live_lab_node_run_matrix.csv"),
        "--node ledger path moved: {}",
        node.display()
    );
}
