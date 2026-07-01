#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

#[cfg(unix)]
use nix::fcntl::{Flock, FlockArg};

use crate::env_file::parse_env_value;
use crate::live_lab_results::read_parallel_stage_results;
use serde_json::Value;

const SETUP_MANIFEST_RELATIVE_PATH: &str = "state/setup_manifest.json";
const REPORT_STATE_RELATIVE_PATH: &str = "state/report_state.json";
const STAGES_RELATIVE_PATH: &str = "state/stages.tsv";
const NODES_RELATIVE_PATH: &str = "state/nodes.tsv";

const DEFAULT_MATRIX_COLUMNS: &[&str] = &[
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
    "linux_stage_chaos",
    "linux_stage_cleanup",
    "macos_stage_bootstrap",
    "macos_stage_membership",
    "macos_stage_assignments",
    "macos_stage_baseline_runtime",
    "macos_stage_anchor",
    "macos_stage_relay_service_lifecycle",
    "macos_stage_exit_handoff",
    "macos_stage_lan_toggle",
    "macos_stage_two_hop",
    "macos_stage_role_switch_matrix",
    "macos_stage_managed_dns",
    "macos_stage_traversal",
    "macos_stage_mixed_topology",
    "macos_stage_reboot_recovery",
    "macos_stage_extended_soak",
    "macos_stage_chaos",
    "macos_stage_cleanup",
    "windows_stage_bootstrap",
    "windows_stage_membership",
    "windows_stage_assignments",
    "windows_stage_baseline_runtime",
    "windows_stage_anchor",
    "windows_stage_relay_service_lifecycle",
    "windows_stage_exit_handoff",
    "windows_stage_lan_toggle",
    "windows_stage_two_hop",
    "windows_stage_role_switch_matrix",
    "windows_stage_managed_dns",
    "windows_stage_traversal",
    "windows_stage_mixed_topology",
    "windows_stage_reboot_recovery",
    "windows_stage_extended_soak",
    "windows_stage_chaos",
    "windows_stage_cleanup",
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
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveLabRunMatrixStageOutcome {
    pub stage: String,
    pub status: String,
    pub artifacts: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct LiveLabRunMatrixAppendConfig<'a> {
    pub command_name: &'a str,
    pub report_dir: &'a Path,
    pub profile_path: Option<&'a Path>,
    pub inventory_path: Option<&'a Path>,
    pub extra_stage_outcomes: &'a [LiveLabRunMatrixStageOutcome],
    pub notes: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendOrchestratorRunToMatrixConfig {
    pub report_dir: PathBuf,
    pub profile_path: Option<PathBuf>,
    pub inventory_path: Option<PathBuf>,
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
}

pub fn default_live_lab_run_matrix_path() -> PathBuf {
    workspace_root_path().join("documents/operations/live_lab_run_matrix.csv")
}

pub fn execute_ops_append_orchestrator_run_to_matrix(
    config: AppendOrchestratorRunToMatrixConfig,
) -> Result<LiveLabRunMatrixAppendResult, String> {
    let report_dir = config.report_dir.as_path();

    // Read run_note from run_summary.json if present
    let run_summary_path = report_dir.join("run_summary.json");
    let run_note = if run_summary_path.is_file() {
        let body = std::fs::read_to_string(&run_summary_path)
            .map_err(|e| format!("read run_summary.json: {e}"))?;
        let val: serde_json::Value =
            serde_json::from_str(&body).map_err(|e| format!("parse run_summary.json: {e}"))?;
        val.get("run_note")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    } else {
        None
    };

    // Read first failure context from failure_digest.json if present
    let first_failure_note = {
        let digest_path = report_dir.join("failure_digest.json");
        if digest_path.is_file() {
            let body = std::fs::read_to_string(&digest_path)
                .map_err(|e| format!("read failure_digest.json: {e}"))?;
            let val: serde_json::Value = serde_json::from_str(&body)
                .map_err(|e| format!("parse failure_digest.json: {e}"))?;
            if let Some(first) = val.get("first_failure").filter(|v| !v.is_null()) {
                let stage = first
                    .get("stage")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let reason = first
                    .get("primary_failure_reason")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .or_else(|| first.get("message").and_then(|v| v.as_str()))
                    .filter(|s| !s.is_empty())
                    .unwrap_or("see log");
                Some(format!("first_failed: {stage}; {reason}"))
            } else {
                None
            }
        } else {
            None
        }
    };

    // Combine notes: run_note, then failure detail if any
    let notes = match (run_note, first_failure_note) {
        (Some(n), Some(f)) => Some(format!("{n}; {f}")),
        (Some(n), None) => Some(n),
        (None, Some(f)) => Some(f),
        (None, None) => None,
    };

    append_live_lab_run_matrix_row(LiveLabRunMatrixAppendConfig {
        command_name: "live-linux-lab-orchestrator",
        report_dir,
        profile_path: config.profile_path.as_deref(),
        inventory_path: config.inventory_path.as_deref(),
        extra_stage_outcomes: &[],
        notes,
    })
}

pub fn append_live_lab_run_matrix_row(
    config: LiveLabRunMatrixAppendConfig<'_>,
) -> Result<LiveLabRunMatrixAppendResult, String> {
    let matrix_path = default_live_lab_run_matrix_path();
    let schema = ensure_matrix_schema(matrix_path.as_path())?;
    let values = build_live_lab_run_matrix_values(&schema, &config)?;
    append_csv_row(matrix_path.as_path(), &schema, &values)?;
    let report_row_path = write_report_local_row(config.report_dir, &schema, &values)?;
    let run_id = values.get("run_id").cloned().unwrap_or_default();
    Ok(LiveLabRunMatrixAppendResult {
        matrix_path,
        report_row_path,
        run_id,
    })
}

fn workspace_root_path() -> PathBuf {
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
    let mut stage_evidence =
        read_stage_evidence(config.report_dir.join(STAGES_RELATIVE_PATH).as_path())?;
    stage_evidence.extend(
        config
            .extra_stage_outcomes
            .iter()
            .map(|outcome| StageEvidence {
                stage: outcome.stage.clone(),
                status: normalize_status(outcome.status.as_str()).to_owned(),
                artifacts: outcome.artifacts.clone(),
            }),
    );
    dedupe_stage_evidence(&mut stage_evidence);

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
    if let Some(ref notes) = config.notes {
        set_if_present(&mut values, &schema_set, "notes", notes.clone());
    }

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
    git_stdout(["rev-parse", "HEAD"])
}

fn current_git_branch() -> Option<String> {
    git_stdout(["rev-parse", "--abbrev-ref", "HEAD"])
}

fn current_git_dirty_state() -> Option<String> {
    git_stdout(["status", "--porcelain"]).map(|stdout| {
        if stdout.trim().is_empty() {
            "clean".to_owned()
        } else {
            "dirty:worktree".to_owned()
        }
    })
}

fn git_stdout<const N: usize>(args: [&str; N]) -> Option<String> {
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

fn git_dirty_state(report_state: &Option<Value>, setup_manifest: &Option<Value>) -> Option<String> {
    json_bool_path(report_state, &["last_run", "git", "git_tree_clean"])
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
                target: String::new(),
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
                    .unwrap_or(alias_value.as_str())
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

fn populate_stage_values(
    values: &mut BTreeMap<String, String>,
    schema: &BTreeSet<String>,
    report_dir: &Path,
    targets: &[TargetEvidence],
    stages: &[StageEvidence],
) {
    for stage in stages {
        let status = normalize_status(stage.status.as_str());
        if let Some((platform, logical_stage)) = direct_platform_stage(stage.stage.as_str()) {
            set_status(
                values,
                schema,
                format!("{platform}_stage_{logical_stage}").as_str(),
                status,
            );
            set_special_stage_values(values, schema, platform, stage.stage.as_str(), status);
            populate_cross_os_values(values, schema, stage.stage.as_str(), status, targets);
            continue;
        }
        if let Some(logical_stage) = logical_stage_name(stage.stage.as_str()) {
            let worker_results = read_parallel_stage_results(report_dir, stage.stage.as_str());
            if worker_results.is_empty() {
                for platform in platforms_for_stage(stage.stage.as_str(), targets) {
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
        populate_cross_os_values(values, schema, stage.stage.as_str(), status, targets);
    }
}

fn populate_role_result_values(
    values: &mut BTreeMap<String, String>,
    schema: &BTreeSet<String>,
    report_dir: &Path,
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
            "bootstrap_hosts" | "validate_baseline_runtime" => {
                set_target_role_statuses(values, schema, targets, status, |_| true);
            }
            "anchor_validation" => {
                set_target_role_statuses(values, schema, targets, status, |role| role == "anchor");
            }
            "deploy_relay_service" | "relay_validation" => {
                set_target_role_statuses(values, schema, targets, status, |role| role == "relay");
            }
            "exit_handoff" | "active_exit" => {
                set_target_role_statuses(values, schema, targets, status, |role| role == "exit");
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
    for stage in [
        "validate_baseline_runtime",
        "bootstrap_hosts",
        "enforce_baseline_runtime",
    ] {
        let worker_results = if stages.iter().any(|evidence| evidence.stage == stage) {
            read_parallel_stage_results(report_dir, stage)
        } else {
            Vec::new()
        };
        for worker in worker_results {
            if let Some(target) = targets.iter().find(|target| target.label == worker.label) {
                let status = if worker.rc == 0 { "pass" } else { "fail" };
                match worker.role.as_str() {
                    "admin" => set_status(
                        values,
                        schema,
                        format!("{}_admin", target.platform).as_str(),
                        status,
                    ),
                    "client" => set_status(
                        values,
                        schema,
                        format!("{}_client", target.platform).as_str(),
                        status,
                    ),
                    _ => {}
                }
            }
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

fn direct_platform_stage(stage: &str) -> Option<(&'static str, &'static str)> {
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
        "validate_windows_relay_service_lifecycle" => Some(("windows", "relay_service_lifecycle")),
        "validate_windows_anchor_bundle_pull" => Some(("windows", "anchor")),
        "promote_windows_exit_active" | "validate_windows_exit_nat_lifecycle" => {
            Some(("windows", "exit_handoff"))
        }
        "validate_windows_dns_failclosed" | "validate_windows_exit_dns_failclosed" => {
            Some(("windows", "managed_dns"))
        }
        "bootstrap_macos_host" => Some(("macos", "bootstrap")),
        "collect_macos_pubkey" | "validate_macos_mesh_join" => Some(("macos", "mixed_topology")),
        "amend_membership_for_macos" | "distribute_macos_bundles" => Some(("macos", "membership")),
        "validate_macos_relay_service_lifecycle" => Some(("macos", "relay_service_lifecycle")),
        "validate_macos_anchor_bundle_pull" => Some(("macos", "anchor")),
        "capture_macos_exit_evidence_artifacts"
        | "validate_macos_exit_nat_lifecycle"
        | "validate_macos_ipv6_leak" => Some(("macos", "exit_handoff")),
        "validate_macos_exit_dns_failclosed" => Some(("macos", "managed_dns")),
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

fn direct_platform_role(stage: &str) -> Option<(&'static str, &'static str)> {
    match stage {
        "validate_windows_client_install"
        | "validate_windows_runtime_acls"
        | "validate_windows_named_pipe_acls"
        | "validate_windows_service_hardening"
        | "validate_windows_key_custody" => Some(("windows", "client")),
        "promote_windows_exit_active"
        | "validate_windows_exit_nat_lifecycle"
        | "validate_windows_exit_dns_failclosed"
        | "validate_windows_exit_killswitch_precedence" => Some(("windows", "exit")),
        "validate_windows_relay_service_lifecycle" => Some(("windows", "relay")),
        "validate_windows_anchor_bundle_pull" => Some(("windows", "anchor")),
        "validate_macos_mesh_join" => Some(("macos", "client")),
        "validate_macos_exit_nat_lifecycle"
        | "validate_macos_exit_dns_failclosed"
        | "validate_macos_exit_killswitch_precedence"
        | "validate_macos_ipv6_leak" => Some(("macos", "blind_exit")),
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

fn logical_stage_name(stage: &str) -> Option<&'static str> {
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
        "traffic_test_matrix" => Some("two_hop"),
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
        "extended_soak" => Some("extended_soak"),
        "cleanup" => Some("cleanup"),
        stage if stage.starts_with("chaos_") => Some("chaos"),
        stage if stage.contains("reboot") => Some("reboot_recovery"),
        _ => None,
    }
}

fn platforms_for_stage(stage: &str, targets: &[TargetEvidence]) -> Vec<String> {
    match stage {
        stage if is_rust_native_stage_name(stage) => unique_platforms(targets),
        "live_anchor" | "live_exit_handoff" => targets
            .iter()
            .find(|target| target.label == "exit")
            .map(|target| vec![target.platform.clone()])
            .unwrap_or_default(),
        "live_relay" => relay_label(targets)
            .and_then(|label| targets.iter().find(|target| target.label == label))
            .map(|target| vec![target.platform.clone()])
            .unwrap_or_default(),
        "live_mixed_topology" => unique_platforms(targets),
        stage if stage.starts_with("cross_network_") => unique_platforms(targets),
        _ => unique_platforms(targets)
            .into_iter()
            .filter(|platform| platform == "linux")
            .collect(),
    }
}

fn is_rust_native_stage_name(stage: &str) -> bool {
    matches!(
        stage,
        "preflight"
            | "prepare_source_archive"
            | "verify_ssh_reachability"
            | "cleanup_hosts"
            | "bootstrap_hosts"
            | "collect_pubkeys"
            | "membership_init"
            | "distribute_membership"
            | "anchor_validation"
            | "distribute_assignments"
            | "distribute_traversal"
            | "distribute_dns_zone"
            | "enforce_baseline_runtime"
            | "validate_baseline_runtime"
            | "deploy_relay_service"
            | "relay_validation"
            | "traffic_test_matrix"
            | "role_switch_matrix"
            | "exit_handoff"
            | "active_exit"
            | "cleanup"
    )
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
    let platform_count = unique_platforms(targets).len();
    if platform_count < 2 && !stage.contains("windows") && !stage.contains("macos") {
        return;
    }
    match stage {
        "preflight"
        | "prepare_source_archive"
        | "verify_ssh_reachability"
        | "cleanup_hosts"
        | "bootstrap_hosts"
        | "collect_pubkeys" => set_status(values, schema, "cross_os_bootstrap", status),
        "membership_init" | "distribute_membership" => {
            set_status(values, schema, "cross_os_membership_convergence", status)
        }
        "distribute_traversal" => set_status(values, schema, "cross_os_direct_path", status),
        "live_mixed_topology" | "validate_windows_mesh_join" | "validate_macos_mesh_join" => {
            set_status(values, schema, "cross_os_peer_visibility", status);
        }
        "live_exit_handoff" | "exit_handoff" | "active_exit" | "promote_windows_exit_active" => {
            set_status(values, schema, "cross_os_exit_path", status);
        }
        "live_relay"
        | "deploy_relay_service"
        | "relay_validation"
        | "validate_windows_relay_service_lifecycle"
        | "validate_macos_relay_service_lifecycle" => {
            set_status(values, schema, "cross_os_relay_path", status);
        }
        "live_lan_toggle" => set_status(values, schema, "cross_os_lan_toggle", status),
        "live_role_switch_matrix" | "role_switch_matrix" => {
            set_status(values, schema, "cross_os_role_switch", status)
        }
        "live_managed_dns"
        | "distribute_dns_zone"
        | "validate_windows_dns_failclosed"
        | "validate_macos_exit_dns_failclosed" => {
            set_status(values, schema, "cross_os_dns", status)
        }
        "traffic_test_matrix" => set_status(values, schema, "cross_os_peer_visibility", status),
        "anchor_validation" => set_status(values, schema, "cross_os_anchor_bundle_pull", status),
        "validate_windows_anchor_bundle_pull"
        | "validate_macos_anchor_bundle_pull"
        | "validate_linux_anchor_bundle_pull" => {
            set_status(values, schema, "cross_os_anchor_bundle_pull", status);
        }
        _ => {}
    }
}

fn set_special_stage_values(
    values: &mut BTreeMap<String, String>,
    schema: &BTreeSet<String>,
    platform: &str,
    stage: &str,
    status: &str,
) {
    match stage {
        "validate_windows_named_pipe_acls" => {
            set_status(values, schema, "windows_named_pipe_acl", status)
        }
        "validate_windows_key_custody" => {
            set_status(values, schema, "windows_dpapi_key_custody", status)
        }
        "validate_macos_key_custody" => {
            set_status(values, schema, "macos_keychain_key_custody", status)
        }
        "validate_macos_exit_killswitch_precedence" => {
            set_status(values, schema, "macos_pf_killswitch", status)
        }
        "validate_linux_membership_revoke_applies" => {
            set_status(values, schema, "linux_membership_revoke_applies", status)
        }
        "validate_linux_revoked_peer_denied_e2e" => {
            set_status(values, schema, "linux_revoked_peer_denied_e2e", status)
        }
        "validate_linux_membership_signature_forgery" => {
            set_status(values, schema, "linux_membership_signature_forgery", status)
        }
        "validate_linux_privileged_helper_allowlist" => {
            set_status(values, schema, "linux_privileged_helper_allowlist", status)
        }
        "validate_linux_policy_default_deny" => {
            set_status(values, schema, "linux_policy_default_deny", status)
        }
        "validate_linux_runtime_acls" => set_status(values, schema, "linux_runtime_acls", status),
        "validate_linux_service_hardening" => {
            set_status(values, schema, "linux_service_hardening", status)
        }
        "validate_linux_authenticode" => set_status(values, schema, "linux_authenticode", status),
        "validate_linux_key_custody" => set_status(values, schema, "linux_key_custody", status),
        "validate_linux_membership_genesis" => {
            set_status(values, schema, "linux_membership_genesis", status)
        }
        "validate_linux_mesh_status" => set_status(values, schema, "linux_mesh_status", status),
        _ if stage.starts_with("validate_") => {
            let _ = platform;
        }
        _ => {}
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

fn status_rank(status: &str) -> u8 {
    match normalize_status(status) {
        "fail" => 6,
        "blocked" => 5,
        "pass" => 4,
        "skip" => 3,
        "unknown" => 2,
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
        "blocked" => "blocked",
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
                existing.status = merge_status(existing.status.as_str(), stage.status.as_str());
                existing.artifacts.extend(stage.artifacts.clone());
                existing.artifacts.sort();
                existing.artifacts.dedup();
            })
            .or_insert(stage);
    }
    stages.extend(by_stage.into_values());
}

fn overall_result(report_state: &Option<Value>, stages: &[StageEvidence]) -> String {
    if let Some(true) = json_bool_path(report_state, &["run_complete"]) {
        if json_bool_path(report_state, &["run_passed"]) == Some(true) {
            return "pass".to_owned();
        }
        return "fail".to_owned();
    }
    if stages.iter().any(|stage| stage.status == "fail") {
        "fail".to_owned()
    } else if stages.iter().any(|stage| stage.status == "pass") {
        "pass".to_owned()
    } else {
        "unknown".to_owned()
    }
}

fn first_failed_stage(stages: &[StageEvidence]) -> Option<String> {
    stages
        .iter()
        .find(|stage| stage.status == "fail")
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

fn earliest_stage_time_from_rows(_stages: &[StageEvidence], _started: bool) -> Option<String> {
    None
}

/// RAII guard for the shared run-matrix CSV append lock. Unix uses a persistent
/// lock file held under an exclusive advisory `flock` (kernel-released when the
/// descriptor closes, including on process death); non-unix uses an `O_EXCL`
/// lock file whose existence IS the lock. Two disjoint-node live-lab runs can
/// finish near-simultaneously and each append one row; without serialization
/// their read→normalize→append sequences interleave and clobber rows.
struct MatrixAppendLock {
    // Only the non-unix (O_EXCL) path tracks the lock-file path for removal;
    // the unix path holds a persistent file and releases via the flock fd.
    #[cfg(not(unix))]
    path: PathBuf,
    #[cfg(unix)]
    _flock: Flock<File>,
    #[cfg(not(unix))]
    _handle: File,
}

impl Drop for MatrixAppendLock {
    fn drop(&mut self) {
        // Non-unix: the O_EXCL lock file's existence IS the lock, so remove it
        // to release. Unix: the advisory flock is released automatically when
        // `_flock`'s descriptor closes (including on process death), and the
        // lock file is intentionally PERSISTENT. Removing it on unix would open
        // a split-inode race under high contention: with the name unlinked, two
        // acquirers can each create a distinct inode and flock their own copy,
        // both entering the critical section and clobbering the append.
        #[cfg(not(unix))]
        let _ = fs::remove_file(&self.path);
    }
}

fn matrix_lock_path_for(path: &Path) -> PathBuf {
    let mut out = path.as_os_str().to_os_string();
    out.push(".lock");
    PathBuf::from(out)
}

/// Acquire the exclusive run-matrix append lock, failing closed on timeout or a
/// non-recoverable I/O error. Unix uses an advisory `flock` (auto-released on
/// crash); the lock file itself may legitimately survive a crash, so mutual
/// exclusion comes from the `flock`, not the file's existence.
#[cfg(unix)]
fn acquire_matrix_append_lock(lock_path: &Path) -> Result<MatrixAppendLock, String> {
    const MAX_WAIT: Duration = Duration::from_secs(10);
    const WAIT_MS: u64 = 10;
    let deadline = Instant::now() + MAX_WAIT;

    loop {
        // create(true) (NOT create_new): a lock file may legitimately survive a
        // crash; mutual exclusion comes from the advisory flock below.
        let mut options = OpenOptions::new();
        options.write(true).create(true).mode(0o600);
        match options.open(lock_path) {
            Ok(file) => match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
                Ok(flock) => {
                    return Ok(MatrixAppendLock { _flock: flock });
                }
                Err((_returned, _errno)) => {
                    // Held by another live descriptor (EWOULDBLOCK). A dead
                    // holder's flock is already released, so this loops only for
                    // genuine live contention.
                    if Instant::now() >= deadline {
                        return Err(format!(
                            "acquire run-matrix append lock timed out ({})",
                            lock_path.display()
                        ));
                    }
                    sleep(Duration::from_millis(WAIT_MS));
                }
            },
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                // Wrong-owned lock file (e.g. left by a root-run op); we own the
                // directory, so unlink and recreate under our own UID.
                if fs::remove_file(lock_path).is_err() || Instant::now() >= deadline {
                    return Err(format!(
                        "acquire run-matrix append lock failed: wrong-owned lock ({})",
                        lock_path.display()
                    ));
                }
                sleep(Duration::from_millis(WAIT_MS));
            }
            Err(err) => {
                return Err(format!(
                    "open run-matrix append lock failed ({}): {err}",
                    lock_path.display()
                ));
            }
        }
    }
}

/// Non-unix fallback: `O_EXCL` lock file as a mutex (mirrors the
/// `rustynetd::resilience` non-unix path). Advisory-lock hardening
/// (auto-release on process death) is unix-only.
#[cfg(not(unix))]
fn acquire_matrix_append_lock(lock_path: &Path) -> Result<MatrixAppendLock, String> {
    const MAX_WAIT: Duration = Duration::from_secs(10);
    const WAIT_MS: u64 = 10;
    let deadline = Instant::now() + MAX_WAIT;

    loop {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        match options.open(lock_path) {
            Ok(mut handle) => {
                let stamp = format!("pid={}\n", std::process::id());
                let _ = handle.write_all(stamp.as_bytes());
                let _ = handle.sync_all();
                return Ok(MatrixAppendLock {
                    path: lock_path.to_path_buf(),
                    _handle: handle,
                });
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                if Instant::now() >= deadline {
                    return Err(format!(
                        "acquire run-matrix append lock timed out ({})",
                        lock_path.display()
                    ));
                }
                sleep(Duration::from_millis(WAIT_MS));
            }
            Err(err) => {
                return Err(format!(
                    "open run-matrix append lock failed ({}): {err}",
                    lock_path.display()
                ));
            }
        }
    }
}

fn append_csv_row(
    path: &Path,
    schema: &[String],
    values: &BTreeMap<String, String>,
) -> Result<(), String> {
    // Serialize the read→normalize→append against concurrent live-lab runs
    // appending to the same shared matrix. Held (RAII) until this fn returns.
    let _lock = acquire_matrix_append_lock(matrix_lock_path_for(path).as_path())?;
    let mut body = fs::read_to_string(path).map_err(|err| {
        format!(
            "read live-lab run matrix failed ({}): {err}",
            path.display()
        )
    })?;
    if !body.ends_with('\n') {
        body.push('\n');
        fs::write(path, body).map_err(|err| {
            format!(
                "normalize live-lab run matrix newline failed ({}): {err}",
                path.display()
            )
        })?;
    }
    let mut file = OpenOptions::new().append(true).open(path).map_err(|err| {
        format!(
            "open live-lab run matrix failed ({}): {err}",
            path.display()
        )
    })?;
    writeln!(file, "{}", render_csv_row(schema, values)).map_err(|err| {
        format!(
            "append live-lab run matrix failed ({}): {err}",
            path.display()
        )
    })
}

fn write_report_local_row(
    report_dir: &Path,
    schema: &[String],
    values: &BTreeMap<String, String>,
) -> Result<PathBuf, String> {
    let path = report_dir.join("state/live_lab_run_matrix_row.csv");
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

fn parse_csv_record(line: &str) -> Result<Vec<String>, String> {
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
        DEFAULT_MATRIX_COLUMNS, LiveLabRunMatrixAppendConfig, LiveLabRunMatrixStageOutcome,
        build_live_lab_run_matrix_values, csv_escape, parse_csv_record, render_csv_row,
        set_special_stage_values,
    };
    use std::collections::{BTreeMap, BTreeSet};

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
    use std::path::{Path, PathBuf};
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
                    super::append_csv_row(csv.as_path(), schema.as_slice(), &values)
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
            "cross_os_membership_convergence",
            "cross_os_peer_visibility",
            "cross_os_direct_path",
            "cross_os_relay_path",
            "cross_os_exit_path",
            "cross_os_dns",
            "cross_os_role_switch",
            "cross_os_anchor_bundle_pull",
        ] {
            assert_eq!(
                values.get(column).map(String::as_str),
                Some("pass"),
                "{column} must be populated from rust-native StageId evidence"
            );
        }
        let _ = fs::remove_dir_all(root);
    }
}
