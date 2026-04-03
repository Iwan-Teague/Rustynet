#![forbid(unsafe_code)]

use std::collections::{BTreeMap, HashSet};
use std::fmt::Write as _;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::env_file::{format_env_assignment, parse_env_value};
use base64::prelude::*;
use serde_json::{Value, json};
use tar::Builder;

const DEFAULT_UTMCTL_PATH: &str = "/Applications/UTM.app/Contents/MacOS/utmctl";
const DEFAULT_VM_LAB_INVENTORY_PATH: &str = "documents/operations/active/vm_lab_inventory.json";
const DEFAULT_LIVE_LAB_ORCHESTRATOR_PATH: &str = "scripts/e2e/live_linux_lab_orchestrator.sh";
const DEFAULT_CROSS_NETWORK_DIRECT_SCRIPT: &str =
    "scripts/e2e/live_linux_cross_network_direct_remote_exit_test.sh";
const DEFAULT_CROSS_NETWORK_RELAY_SCRIPT: &str =
    "scripts/e2e/live_linux_cross_network_relay_remote_exit_test.sh";
const DEFAULT_CROSS_NETWORK_FAILBACK_SCRIPT: &str =
    "scripts/e2e/live_linux_cross_network_failback_roaming_test.sh";
const DEFAULT_START_TIMEOUT_SECS: u64 = 60;
const DEFAULT_SYNC_TIMEOUT_SECS: u64 = 900;
const DEFAULT_RUN_TIMEOUT_SECS: u64 = 1800;
const DEFAULT_LIVE_LAB_TIMEOUT_SECS: u64 = 86_400;
const DEFAULT_PREFLIGHT_TIMEOUT_SECS: u64 = 120;
const DEFAULT_COLLECT_TIMEOUT_SECS: u64 = 300;
const DEFAULT_ARTIFACT_ROOT: &str = "artifacts/vm_lab";
const DEFAULT_LIVE_LAB_PROFILE_ROOT: &str = "profiles/live_lab";
const DEFAULT_LIVE_LAB_REPORT_ROOT: &str = "artifacts/live_lab";
const DEFAULT_PRECHECK_COMMANDS: &[&str] = &["git", "cargo", "systemctl"];
const POLL_INTERVAL_MILLIS: u64 = 100;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmLabListConfig {
    pub inventory_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmLabStartConfig {
    pub inventory_path: PathBuf,
    pub vm_aliases: Vec<String>,
    pub select_all: bool,
    pub utmctl_path: PathBuf,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmLabSyncRepoConfig {
    pub inventory_path: PathBuf,
    pub vm_aliases: Vec<String>,
    pub raw_targets: Vec<String>,
    pub select_all: bool,
    pub repo_url: Option<String>,
    pub local_source_dir: Option<PathBuf>,
    pub dest_dir: String,
    pub branch: String,
    pub remote: String,
    pub ssh_user: Option<String>,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmLabExecConfig {
    pub inventory_path: PathBuf,
    pub vm_aliases: Vec<String>,
    pub raw_targets: Vec<String>,
    pub select_all: bool,
    pub workdir: String,
    pub program: String,
    pub argv: Vec<String>,
    pub ssh_user: Option<String>,
    pub sudo: bool,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmLabSyncBootstrapConfig {
    pub inventory_path: PathBuf,
    pub vm_aliases: Vec<String>,
    pub raw_targets: Vec<String>,
    pub select_all: bool,
    pub require_same_network: bool,
    pub repo_url: Option<String>,
    pub local_source_dir: Option<PathBuf>,
    pub dest_dir: String,
    pub branch: String,
    pub remote: String,
    pub workdir: String,
    pub program: String,
    pub argv: Vec<String>,
    pub ssh_user: Option<String>,
    pub sudo: bool,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmLabWriteLiveLabProfileConfig {
    pub inventory_path: PathBuf,
    pub output_path: PathBuf,
    pub exit_vm: Option<String>,
    pub exit_target: Option<String>,
    pub client_vm: Option<String>,
    pub client_target: Option<String>,
    pub entry_vm: Option<String>,
    pub entry_target: Option<String>,
    pub aux_vm: Option<String>,
    pub aux_target: Option<String>,
    pub extra_vm: Option<String>,
    pub extra_target: Option<String>,
    pub fifth_client_vm: Option<String>,
    pub fifth_client_target: Option<String>,
    pub require_same_network: bool,
    pub ssh_identity_file: PathBuf,
    pub ssh_known_hosts_file: Option<PathBuf>,
    pub ssh_allow_cidrs: Option<String>,
    pub network_id: Option<String>,
    pub traversal_ttl_secs: Option<u64>,
    pub cross_network_nat_profiles: Option<String>,
    pub cross_network_required_nat_profiles: Option<String>,
    pub cross_network_impairment_profile: Option<String>,
    pub backend: Option<String>,
    pub source_mode: Option<String>,
    pub repo_ref: Option<String>,
    pub report_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmLabRunLiveLabConfig {
    pub profile_path: PathBuf,
    pub script_path: PathBuf,
    pub dry_run: bool,
    pub skip_gates: bool,
    pub skip_soak: bool,
    pub skip_cross_network: bool,
    pub source_mode: Option<String>,
    pub repo_ref: Option<String>,
    pub report_dir: Option<PathBuf>,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmLabIterationValidationStep {
    FmtCheck,
    CargoCheckPackage {
        package: String,
    },
    CargoCheckBin {
        package: String,
        bin: String,
    },
    CargoTestPackage {
        package: String,
        filter: Option<String>,
    },
    CargoTestBin {
        package: String,
        bin: String,
        filter: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmLabIterateLiveLabConfig {
    pub inventory_path: PathBuf,
    pub profile_output_path: Option<PathBuf>,
    pub exit_vm: Option<String>,
    pub exit_target: Option<String>,
    pub client_vm: Option<String>,
    pub client_target: Option<String>,
    pub entry_vm: Option<String>,
    pub entry_target: Option<String>,
    pub aux_vm: Option<String>,
    pub aux_target: Option<String>,
    pub extra_vm: Option<String>,
    pub extra_target: Option<String>,
    pub fifth_client_vm: Option<String>,
    pub fifth_client_target: Option<String>,
    pub require_same_network: bool,
    pub ssh_identity_file: PathBuf,
    pub ssh_known_hosts_file: Option<PathBuf>,
    pub ssh_allow_cidrs: Option<String>,
    pub network_id: Option<String>,
    pub traversal_ttl_secs: Option<u64>,
    pub backend: Option<String>,
    pub source_mode: Option<String>,
    pub repo_ref: Option<String>,
    pub report_dir: Option<PathBuf>,
    pub script_path: PathBuf,
    pub dry_run: bool,
    pub timeout_secs: u64,
    pub require_clean_tree: bool,
    pub require_local_head: bool,
    pub validation_steps: Vec<VmLabIterationValidationStep>,
    pub collect_failure_diagnostics: bool,
    pub failed_log_tail_lines: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmLabValidateLiveLabProfileConfig {
    pub profile_path: PathBuf,
    pub expected_backend: Option<String>,
    pub expected_source_mode: Option<String>,
    pub require_five_node: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmLabDiagnoseLiveLabFailureConfig {
    pub inventory_path: PathBuf,
    pub profile_path: PathBuf,
    pub report_dir: PathBuf,
    pub stage: Option<String>,
    pub output_dir: Option<PathBuf>,
    pub collect_artifacts: bool,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmLabDiffLiveLabRunsConfig {
    pub old_report_dir: PathBuf,
    pub new_report_dir: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmLabBootstrapPhaseConfig {
    pub inventory_path: PathBuf,
    pub vm_aliases: Vec<String>,
    pub raw_targets: Vec<String>,
    pub select_all: bool,
    pub require_same_network: bool,
    pub phase: String,
    pub repo_url: Option<String>,
    pub local_source_dir: Option<PathBuf>,
    pub dest_dir: Option<String>,
    pub branch: String,
    pub remote: String,
    pub ssh_user: Option<String>,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmLabPreflightConfig {
    pub inventory_path: PathBuf,
    pub vm_aliases: Vec<String>,
    pub raw_targets: Vec<String>,
    pub select_all: bool,
    pub known_hosts_path: Option<PathBuf>,
    pub require_same_network: bool,
    pub require_commands: Vec<String>,
    pub min_free_kib: u64,
    pub require_rustynet_installed: bool,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmLabCheckKnownHostsConfig {
    pub inventory_path: PathBuf,
    pub vm_aliases: Vec<String>,
    pub raw_targets: Vec<String>,
    pub select_all: bool,
    pub known_hosts_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmLabStatusConfig {
    pub inventory_path: PathBuf,
    pub vm_aliases: Vec<String>,
    pub raw_targets: Vec<String>,
    pub select_all: bool,
    pub ssh_user: Option<String>,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmLabStopConfig {
    pub inventory_path: PathBuf,
    pub vm_aliases: Vec<String>,
    pub select_all: bool,
    pub utmctl_path: PathBuf,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmLabRestartConfig {
    pub inventory_path: PathBuf,
    pub vm_aliases: Vec<String>,
    pub raw_targets: Vec<String>,
    pub select_all: bool,
    pub utmctl_path: PathBuf,
    pub service: Option<String>,
    pub ssh_user: Option<String>,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmLabCollectArtifactsConfig {
    pub inventory_path: PathBuf,
    pub vm_aliases: Vec<String>,
    pub raw_targets: Vec<String>,
    pub select_all: bool,
    pub ssh_user: Option<String>,
    pub output_dir: PathBuf,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmLabWriteTopologyConfig {
    pub inventory_path: PathBuf,
    pub output_path: PathBuf,
    pub vm_aliases: Vec<String>,
    pub select_all: bool,
    pub require_same_network: bool,
    pub suite: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmLabIssueDistributeStateConfig {
    pub inventory_path: PathBuf,
    pub topology_path: PathBuf,
    pub authority_vm: String,
    pub ssh_user: Option<String>,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmLabRunSuiteConfig {
    pub inventory_path: PathBuf,
    pub suite: String,
    pub topology_path: Option<PathBuf>,
    pub profile_path: Option<PathBuf>,
    pub ssh_identity_file: PathBuf,
    pub vm_aliases: Vec<String>,
    pub select_all: bool,
    pub dry_run: bool,
    pub nat_profile: Option<String>,
    pub impairment_profile: Option<String>,
    pub report_dir: Option<PathBuf>,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum VmController {
    LocalUtm {
        utm_name: String,
        bundle_path: PathBuf,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VmInventoryEntry {
    alias: String,
    ssh_target: String,
    ssh_user: Option<String>,
    os: Option<String>,
    last_known_ip: Option<String>,
    parent_device: Option<String>,
    last_known_network: Option<String>,
    network_group: Option<String>,
    node_id: Option<String>,
    lab_role: Option<String>,
    mesh_ip: Option<String>,
    exit_capable: Option<bool>,
    relay_capable: Option<bool>,
    rustynet_src_dir: Option<String>,
    controller: Option<VmController>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RemoteTarget {
    label: String,
    ssh_target: String,
    ssh_user: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StartTarget {
    alias: String,
    utm_name: String,
    bundle_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RoleTarget {
    label: String,
    normalized_target: String,
    network_group: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct KnownHostsTarget {
    label: String,
    host_candidates: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VmLabTopology {
    suite: String,
    roles: BTreeMap<String, String>,
    nodes: BTreeMap<String, VmLabTopologyNode>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VmLabTopologyNode {
    alias: String,
    normalized_target: String,
    node_id: String,
    lab_role: String,
    network_id: String,
    mesh_ip: Option<String>,
    last_known_ip: Option<String>,
    exit_capable: bool,
    relay_capable: bool,
    rustynet_src_dir: Option<String>,
}

#[derive(Debug)]
struct SuiteCommand {
    command: Command,
    rendered: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RepoSyncSource {
    Git {
        repo_url: String,
        branch: String,
        remote: String,
    },
    LocalSource {
        source_dir: PathBuf,
    },
}

#[derive(Debug)]
struct LocalSourceArchive {
    path: PathBuf,
}

impl Drop for LocalSourceArchive {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.path.as_path());
    }
}

#[derive(Debug)]
struct LocalSourceBundleExtras {
    temp_root: PathBuf,
    vendor_dir: Option<PathBuf>,
    cargo_config_path: Option<PathBuf>,
}

impl Drop for LocalSourceBundleExtras {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(self.temp_root.as_path());
    }
}

pub fn default_utmctl_path() -> PathBuf {
    PathBuf::from(DEFAULT_UTMCTL_PATH)
}

fn workspace_root_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root must be resolvable from rustynet-cli crate")
        .to_path_buf()
}

pub fn default_inventory_path() -> PathBuf {
    workspace_root_path().join(DEFAULT_VM_LAB_INVENTORY_PATH)
}

pub fn default_live_lab_orchestrator_path() -> PathBuf {
    workspace_root_path().join(DEFAULT_LIVE_LAB_ORCHESTRATOR_PATH)
}

pub fn default_cross_network_direct_script_path() -> PathBuf {
    workspace_root_path().join(DEFAULT_CROSS_NETWORK_DIRECT_SCRIPT)
}

pub fn default_cross_network_relay_script_path() -> PathBuf {
    workspace_root_path().join(DEFAULT_CROSS_NETWORK_RELAY_SCRIPT)
}

pub fn default_cross_network_failback_script_path() -> PathBuf {
    workspace_root_path().join(DEFAULT_CROSS_NETWORK_FAILBACK_SCRIPT)
}

pub fn default_artifact_root() -> PathBuf {
    workspace_root_path().join(DEFAULT_ARTIFACT_ROOT)
}

pub fn default_live_lab_profile_root() -> PathBuf {
    workspace_root_path().join(DEFAULT_LIVE_LAB_PROFILE_ROOT)
}

pub fn default_live_lab_report_root() -> PathBuf {
    workspace_root_path().join(DEFAULT_LIVE_LAB_REPORT_ROOT)
}

pub fn default_known_hosts_path() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
        .join(".ssh/known_hosts")
}

impl VmLabIterationValidationStep {
    fn label(&self) -> String {
        match self {
            Self::FmtCheck => "fmt".to_string(),
            Self::CargoCheckPackage { package } => format!("check:{package}"),
            Self::CargoCheckBin { package, bin } => format!("check-bin:{package}:{bin}"),
            Self::CargoTestPackage { package, filter } => match filter {
                Some(filter) => format!("test:{package}:{filter}"),
                None => format!("test:{package}"),
            },
            Self::CargoTestBin {
                package,
                bin,
                filter,
            } => match filter {
                Some(filter) => format!("test-bin:{package}:{bin}:{filter}"),
                None => format!("test-bin:{package}:{bin}"),
            },
        }
    }
}

pub fn parse_vm_lab_iteration_validation_step_spec(
    value: &str,
) -> Result<VmLabIterationValidationStep, String> {
    ensure_no_control_chars("validation step", value)?;
    let parts = value.split(':').collect::<Vec<_>>();
    match parts.as_slice() {
        ["fmt"] => Ok(VmLabIterationValidationStep::FmtCheck),
        ["check", package] => {
            ensure_no_control_chars("validation package", package)?;
            Ok(VmLabIterationValidationStep::CargoCheckPackage {
                package: (*package).to_string(),
            })
        }
        ["check-bin", package, bin] => {
            ensure_no_control_chars("validation package", package)?;
            ensure_no_control_chars("validation binary", bin)?;
            Ok(VmLabIterationValidationStep::CargoCheckBin {
                package: (*package).to_string(),
                bin: (*bin).to_string(),
            })
        }
        ["test", package] => {
            ensure_no_control_chars("validation package", package)?;
            Ok(VmLabIterationValidationStep::CargoTestPackage {
                package: (*package).to_string(),
                filter: None,
            })
        }
        ["test", package, filter] => {
            ensure_no_control_chars("validation package", package)?;
            ensure_no_control_chars("validation test filter", filter)?;
            Ok(VmLabIterationValidationStep::CargoTestPackage {
                package: (*package).to_string(),
                filter: Some((*filter).to_string()),
            })
        }
        ["test-bin", package, bin] => {
            ensure_no_control_chars("validation package", package)?;
            ensure_no_control_chars("validation binary", bin)?;
            Ok(VmLabIterationValidationStep::CargoTestBin {
                package: (*package).to_string(),
                bin: (*bin).to_string(),
                filter: None,
            })
        }
        ["test-bin", package, bin, filter] => {
            ensure_no_control_chars("validation package", package)?;
            ensure_no_control_chars("validation binary", bin)?;
            ensure_no_control_chars("validation test filter", filter)?;
            Ok(VmLabIterationValidationStep::CargoTestBin {
                package: (*package).to_string(),
                bin: (*bin).to_string(),
                filter: Some((*filter).to_string()),
            })
        }
        _ => Err(format!(
            "unsupported validation step: {value} (expected fmt|check:<package>|check-bin:<package>:<bin>|test:<package>[:filter]|test-bin:<package>:<bin>[:filter])"
        )),
    }
}

pub fn execute_ops_vm_lab_list(config: VmLabListConfig) -> Result<String, String> {
    let inventory = load_inventory(config.inventory_path.as_path())?;
    let mut lines = vec![format!(
        "vm_lab_inventory path={}",
        config.inventory_path.display()
    )];
    for entry in inventory {
        let controller_summary = match entry.controller {
            Some(VmController::LocalUtm {
                ref utm_name,
                ref bundle_path,
            }) => format!(
                "controller=local_utm utm_name={} bundle_path={}",
                utm_name,
                bundle_path.display()
            ),
            None => "controller=none".to_string(),
        };
        lines.push(format!(
            "alias={} ssh_target={} ssh_user={} os={} last_known_ip={} parent_device={} last_known_network={} network_group={} node_id={} lab_role={} mesh_ip={} exit_capable={} relay_capable={} rustynet_src_dir={} {}",
            entry.alias,
            entry.ssh_target,
            entry
                .ssh_user
                .unwrap_or_else(|| "<ssh-default>".to_string()),
            entry.os.unwrap_or_else(|| "<unknown>".to_string()),
            entry
                .last_known_ip
                .unwrap_or_else(|| "<unknown>".to_string()),
            entry
                .parent_device
                .unwrap_or_else(|| "<unknown>".to_string()),
            entry
                .last_known_network
                .unwrap_or_else(|| "<unknown>".to_string()),
            entry
                .network_group
                .unwrap_or_else(|| "<unset>".to_string()),
            entry.node_id.unwrap_or_else(|| "<unset>".to_string()),
            entry.lab_role.unwrap_or_else(|| "<unset>".to_string()),
            entry.mesh_ip.unwrap_or_else(|| "<unset>".to_string()),
            entry
                .exit_capable
                .map(|value| value.to_string())
                .unwrap_or_else(|| "<unset>".to_string()),
            entry
                .relay_capable
                .map(|value| value.to_string())
                .unwrap_or_else(|| "<unset>".to_string()),
            entry
                .rustynet_src_dir
                .unwrap_or_else(|| "<unset>".to_string()),
            controller_summary
        ));
    }
    Ok(lines.join("\n"))
}

pub fn execute_ops_vm_lab_start(config: VmLabStartConfig) -> Result<String, String> {
    let targets = resolve_start_targets(
        config.inventory_path.as_path(),
        config.vm_aliases.as_slice(),
        config.select_all,
    )?;
    let utmctl_path = config.utmctl_path;
    if !utmctl_path.is_file() {
        return Err(format!(
            "utmctl binary is not present: {}",
            utmctl_path.display()
        ));
    }
    let timeout = timeout_or_default(config.timeout_secs, DEFAULT_START_TIMEOUT_SECS);
    let mut results = Vec::new();
    for target in &targets {
        transition_local_utm_vm(
            utmctl_path.as_path(),
            target.utm_name.as_str(),
            target.bundle_path.as_path(),
            "start",
            true,
            timeout,
        )
        .map_err(|err| format!("{} start failed: {err}", target.alias))?;
        results.push(format!(
            "{} started via utm_name={} bundle_path={}",
            target.alias,
            target.utm_name,
            target.bundle_path.display()
        ));
    }
    Ok(results.join("\n"))
}

pub fn execute_ops_vm_lab_sync_repo(config: VmLabSyncRepoConfig) -> Result<String, String> {
    let targets = resolve_remote_targets(
        config.inventory_path.as_path(),
        config.vm_aliases.as_slice(),
        config.select_all,
        config.raw_targets.as_slice(),
    )?;
    ensure_no_control_chars("destination directory", config.dest_dir.as_str())?;
    if let Some(ssh_user) = config.ssh_user.as_deref() {
        ensure_no_control_chars("SSH user", ssh_user)?;
    }
    let timeout = timeout_or_default(config.timeout_secs, DEFAULT_SYNC_TIMEOUT_SECS);
    let source = resolve_repo_sync_source(
        config.repo_url.as_deref(),
        config.local_source_dir.as_deref(),
        config.branch.as_str(),
        config.remote.as_str(),
    )?;
    let results = sync_repo_targets(
        &targets,
        config.ssh_user.as_deref(),
        source,
        config.dest_dir.as_str(),
        timeout,
    )?;
    Ok(results.join("\n"))
}

pub fn execute_ops_vm_lab_run(
    config: VmLabExecConfig,
    action_label: &str,
) -> Result<String, String> {
    let targets = resolve_remote_targets(
        config.inventory_path.as_path(),
        config.vm_aliases.as_slice(),
        config.select_all,
        config.raw_targets.as_slice(),
    )?;
    ensure_no_control_chars("workdir", config.workdir.as_str())?;
    ensure_no_control_chars("program", config.program.as_str())?;
    for arg in &config.argv {
        ensure_no_control_chars("command arg", arg.as_str())?;
    }
    if let Some(ssh_user) = config.ssh_user.as_deref() {
        ensure_no_control_chars("SSH user", ssh_user)?;
    }
    let timeout = timeout_or_default(config.timeout_secs, DEFAULT_RUN_TIMEOUT_SECS);
    let remote_script = build_remote_argv_script(
        config.workdir.as_str(),
        config.program.as_str(),
        config.argv.as_slice(),
        config.sudo,
    )?;
    let mut results = Vec::new();
    for target in &targets {
        let effective_user = config.ssh_user.as_deref().or(target.ssh_user.as_deref());
        let status = run_remote_shell_command(
            target.ssh_target.as_str(),
            effective_user,
            remote_script.as_str(),
            timeout,
        )
        .map_err(|err| format!("{} {} failed: {err}", target.label, action_label))?;
        if !status.success() {
            return Err(format!(
                "{} {} failed with status {}",
                target.label,
                action_label,
                status_code(status)
            ));
        }
        results.push(format!(
            "{} {} workdir={} program={} sudo={} ssh_target={} ssh_user={}",
            target.label,
            action_label,
            config.workdir,
            config.program,
            config.sudo,
            target.ssh_target,
            effective_user.unwrap_or("<ssh-default>"),
        ));
    }
    Ok(results.join("\n"))
}

pub fn execute_ops_vm_lab_sync_bootstrap(
    config: VmLabSyncBootstrapConfig,
) -> Result<String, String> {
    if config.require_same_network {
        ensure_remote_selection_declares_single_network(
            config.inventory_path.as_path(),
            config.vm_aliases.as_slice(),
            config.select_all,
            config.raw_targets.as_slice(),
        )?;
    }

    let sync_result = execute_ops_vm_lab_sync_repo(VmLabSyncRepoConfig {
        inventory_path: config.inventory_path.clone(),
        vm_aliases: config.vm_aliases.clone(),
        raw_targets: config.raw_targets.clone(),
        select_all: config.select_all,
        repo_url: config.repo_url.clone(),
        local_source_dir: config.local_source_dir.clone(),
        dest_dir: config.dest_dir.clone(),
        branch: config.branch.clone(),
        remote: config.remote.clone(),
        ssh_user: config.ssh_user.clone(),
        timeout_secs: config.timeout_secs,
    })?;

    let run_result = execute_ops_vm_lab_run(
        VmLabExecConfig {
            inventory_path: config.inventory_path,
            vm_aliases: config.vm_aliases,
            raw_targets: config.raw_targets,
            select_all: config.select_all,
            workdir: config.workdir,
            program: config.program,
            argv: config.argv,
            ssh_user: config.ssh_user,
            sudo: config.sudo,
            timeout_secs: config.timeout_secs,
        },
        "bootstrapped",
    )?;

    Ok(format!("{sync_result}\n{run_result}"))
}

fn resolve_repo_sync_source(
    repo_url: Option<&str>,
    local_source_dir: Option<&Path>,
    branch: &str,
    remote: &str,
) -> Result<RepoSyncSource, String> {
    match (repo_url, local_source_dir) {
        (Some(_), Some(_)) => Err(
            "specify either --repo-url or --local-source-dir for vm-lab sync, not both".to_string(),
        ),
        (None, None) => {
            Err("specify one of --repo-url or --local-source-dir for vm-lab sync".to_string())
        }
        (Some(repo_url), None) => {
            ensure_no_control_chars("repo URL", repo_url)?;
            ensure_no_control_chars("branch", branch)?;
            ensure_no_control_chars("remote", remote)?;
            Ok(RepoSyncSource::Git {
                repo_url: repo_url.to_string(),
                branch: branch.to_string(),
                remote: remote.to_string(),
            })
        }
        (None, Some(local_source_dir)) => {
            ensure_local_directory_path(local_source_dir, "local source dir")?;
            Ok(RepoSyncSource::LocalSource {
                source_dir: local_source_dir.to_path_buf(),
            })
        }
    }
}

fn sync_repo_targets(
    targets: &[RemoteTarget],
    ssh_user_override: Option<&str>,
    source: RepoSyncSource,
    dest_dir: &str,
    timeout: Duration,
) -> Result<Vec<String>, String> {
    ensure_no_control_chars("destination directory", dest_dir)?;
    let mut results = Vec::new();
    match source {
        RepoSyncSource::Git {
            repo_url,
            branch,
            remote,
        } => {
            let repo_sync_script = build_repo_sync_script(
                repo_url.as_str(),
                dest_dir,
                branch.as_str(),
                remote.as_str(),
            )?;
            for target in targets {
                let effective_user = ssh_user_override.or(target.ssh_user.as_deref());
                let status = run_remote_shell_command(
                    target.ssh_target.as_str(),
                    effective_user,
                    repo_sync_script.as_str(),
                    timeout,
                )
                .map_err(|err| format!("{} repo sync failed: {err}", target.label))?;
                if !status.success() {
                    return Err(format!(
                        "{} repo sync failed with status {}",
                        target.label,
                        status_code(status)
                    ));
                }
                results.push(format!(
                    "{} synced repo={} branch={} dest_dir={} ssh_target={} ssh_user={}",
                    target.label,
                    repo_url,
                    branch,
                    dest_dir,
                    target.ssh_target,
                    effective_user.unwrap_or("<ssh-default>"),
                ));
            }
        }
        RepoSyncSource::LocalSource { source_dir } => {
            let archive = prepare_local_source_archive(source_dir.as_path(), timeout)?;
            for target in targets {
                let effective_user = ssh_user_override.or(target.ssh_user.as_deref());
                sync_local_source_archive_to_target(
                    archive.path.as_path(),
                    target.ssh_target.as_str(),
                    effective_user,
                    dest_dir,
                    timeout,
                )
                .map_err(|err| format!("{} local source sync failed: {err}", target.label))?;
                results.push(format!(
                    "{} synced local_source_dir={} dest_dir={} ssh_target={} ssh_user={}",
                    target.label,
                    source_dir.display(),
                    dest_dir,
                    target.ssh_target,
                    effective_user.unwrap_or("<ssh-default>"),
                ));
            }
        }
    }
    Ok(results)
}

pub fn execute_ops_vm_lab_write_live_lab_profile(
    config: VmLabWriteLiveLabProfileConfig,
) -> Result<String, String> {
    let exit_target = resolve_role_target(
        config.inventory_path.as_path(),
        "exit",
        config.exit_vm.as_deref(),
        config.exit_target.as_deref(),
    )?;
    let client_target = resolve_role_target(
        config.inventory_path.as_path(),
        "client",
        config.client_vm.as_deref(),
        config.client_target.as_deref(),
    )?;
    let entry_target = resolve_optional_role_target(
        config.inventory_path.as_path(),
        "entry",
        config.entry_vm.as_deref(),
        config.entry_target.as_deref(),
    )?;
    let aux_target = resolve_optional_role_target(
        config.inventory_path.as_path(),
        "aux",
        config.aux_vm.as_deref(),
        config.aux_target.as_deref(),
    )?;
    let extra_target = resolve_optional_role_target(
        config.inventory_path.as_path(),
        "extra",
        config.extra_vm.as_deref(),
        config.extra_target.as_deref(),
    )?;
    let fifth_client_target = resolve_optional_role_target(
        config.inventory_path.as_path(),
        "fifth_client",
        config.fifth_client_vm.as_deref(),
        config.fifth_client_target.as_deref(),
    )?;

    let role_targets = [
        Some(exit_target.clone()),
        Some(client_target.clone()),
        entry_target.clone(),
        aux_target.clone(),
        extra_target.clone(),
        fifth_client_target.clone(),
    ];
    if config.require_same_network {
        ensure_role_targets_share_network(role_targets.as_slice())?;
    }

    ensure_local_regular_file_path(config.ssh_identity_file.as_path(), "SSH identity file")?;
    if let Some(path) = config.ssh_known_hosts_file.as_deref() {
        ensure_local_regular_file_path(path, "SSH known_hosts file")?;
    }
    if let Some(value) = config.ssh_allow_cidrs.as_deref() {
        ensure_no_control_chars("SSH allow CIDRs", value)?;
    }
    if let Some(value) = config.network_id.as_deref() {
        ensure_no_control_chars("network_id", value)?;
    }
    if let Some(value) = config.cross_network_nat_profiles.as_deref() {
        ensure_no_control_chars("cross-network NAT profiles", value)?;
    }
    if let Some(value) = config.cross_network_required_nat_profiles.as_deref() {
        ensure_no_control_chars("cross-network required NAT profiles", value)?;
    }
    if let Some(value) = config.cross_network_impairment_profile.as_deref() {
        ensure_no_control_chars("cross-network impairment profile", value)?;
    }
    if let Some(value) = config.backend.as_deref() {
        ensure_no_control_chars("backend", value)?;
    }
    if let Some(value) = config.source_mode.as_deref() {
        ensure_no_control_chars("source mode", value)?;
    }
    if let Some(value) = config.repo_ref.as_deref() {
        ensure_no_control_chars("repo ref", value)?;
    }

    let mut lines = vec![
        "# Generated by rustynet-cli ops vm-lab-write-live-lab-profile".to_string(),
        format_env_assignment("EXIT_TARGET", exit_target.normalized_target.as_str())?,
        format_env_assignment("CLIENT_TARGET", client_target.normalized_target.as_str())?,
        format_env_assignment(
            "SSH_IDENTITY_FILE",
            config.ssh_identity_file.display().to_string().as_str(),
        )?,
    ];
    if let Some(target) = entry_target {
        lines.push(format_env_assignment(
            "ENTRY_TARGET",
            target.normalized_target.as_str(),
        )?);
    }
    if let Some(target) = aux_target {
        lines.push(format_env_assignment(
            "AUX_TARGET",
            target.normalized_target.as_str(),
        )?);
    }
    if let Some(target) = extra_target {
        lines.push(format_env_assignment(
            "EXTRA_TARGET",
            target.normalized_target.as_str(),
        )?);
    }
    if let Some(target) = fifth_client_target {
        lines.push(format_env_assignment(
            "FIFTH_CLIENT_TARGET",
            target.normalized_target.as_str(),
        )?);
    }
    if let Some(path) = config.ssh_known_hosts_file.as_deref() {
        lines.push(format_env_assignment(
            "SSH_KNOWN_HOSTS_FILE",
            path.display().to_string().as_str(),
        )?);
    }
    if let Some(value) = config.ssh_allow_cidrs.as_deref() {
        lines.push(format_env_assignment("SSH_ALLOW_CIDRS", value)?);
    }
    if let Some(value) = config.network_id.as_deref() {
        lines.push(format_env_assignment("NETWORK_ID", value)?);
    }
    if let Some(ttl) = config.traversal_ttl_secs {
        lines.push(format_env_assignment(
            "TRAVERSAL_TTL_SECS",
            ttl.to_string().as_str(),
        )?);
    }
    if let Some(value) = config.cross_network_nat_profiles.as_deref() {
        lines.push(format_env_assignment("CROSS_NETWORK_NAT_PROFILES", value)?);
    }
    if let Some(value) = config.cross_network_required_nat_profiles.as_deref() {
        lines.push(format_env_assignment(
            "CROSS_NETWORK_REQUIRED_NAT_PROFILES",
            value,
        )?);
    }
    if let Some(value) = config.cross_network_impairment_profile.as_deref() {
        lines.push(format_env_assignment(
            "CROSS_NETWORK_IMPAIRMENT_PROFILE",
            value,
        )?);
    }
    if let Some(value) = config.backend.as_deref() {
        lines.push(format_env_assignment("RUSTYNET_BACKEND", value)?);
    }
    if let Some(value) = config.source_mode.as_deref() {
        lines.push(format_env_assignment("SOURCE_MODE", value)?);
    }
    if let Some(value) = config.repo_ref.as_deref() {
        lines.push(format_env_assignment("REPO_REF", value)?);
    }
    if let Some(path) = config.report_dir.as_deref() {
        lines.push(format_env_assignment(
            "REPORT_DIR",
            path.display().to_string().as_str(),
        )?);
    }
    lines.push(String::new());

    let parent = config
        .output_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or_else(|| {
            format!(
                "profile output path must have a parent directory: {}",
                config.output_path.display()
            )
        })?;
    fs::create_dir_all(parent).map_err(|err| {
        format!(
            "create profile directory failed ({}): {err}",
            parent.display()
        )
    })?;
    fs::write(&config.output_path, lines.join("\n")).map_err(|err| {
        format!(
            "write live-lab profile failed ({}): {err}",
            config.output_path.display()
        )
    })?;

    Ok(format!(
        "wrote live-lab profile={} exit={} client={}",
        config.output_path.display(),
        exit_target.normalized_target,
        client_target.normalized_target
    ))
}

pub fn execute_ops_vm_lab_run_live_lab(config: VmLabRunLiveLabConfig) -> Result<String, String> {
    ensure_local_regular_file_path(config.profile_path.as_path(), "live-lab profile")?;
    ensure_local_regular_file_path(config.script_path.as_path(), "live-lab script")?;
    if let Some(value) = config.source_mode.as_deref() {
        ensure_no_control_chars("source mode", value)?;
    }
    if let Some(value) = config.repo_ref.as_deref() {
        ensure_no_control_chars("repo ref", value)?;
    }

    let timeout = timeout_or_default(config.timeout_secs, DEFAULT_LIVE_LAB_TIMEOUT_SECS);
    let mut command = Command::new("bash");
    command.arg(config.script_path.as_path());
    command.arg("--profile").arg(config.profile_path.as_path());
    if config.dry_run {
        command.arg("--dry-run");
    }
    if config.skip_gates {
        command.arg("--skip-gates");
    }
    if config.skip_soak {
        command.arg("--skip-soak");
    }
    if config.skip_cross_network {
        command.arg("--skip-cross-network");
    }
    if let Some(value) = config.source_mode.as_deref() {
        command.arg("--source-mode").arg(value);
    }
    if let Some(value) = config.repo_ref.as_deref() {
        command.arg("--repo-ref").arg(value);
    }
    if let Some(path) = config.report_dir.as_deref() {
        command.arg("--report-dir").arg(path.as_os_str());
    }

    let status = run_status_with_timeout_passthrough(&mut command, timeout)
        .map_err(|err| format!("live-lab run failed: {err}"))?;
    if !status.success() {
        return Err(format!(
            "live-lab run failed with status {}",
            status_code(status)
        ));
    }

    Ok(format!(
        "ran live-lab script={} profile={}",
        config.script_path.display(),
        config.profile_path.display()
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LiveLabStageSummary {
    overall_status: String,
    first_failed_stage: Option<String>,
    key_report_path: PathBuf,
    key_log_path: Option<PathBuf>,
    likely_reason: Option<String>,
    failed_log_tail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LiveLabStageRecord {
    name: String,
    severity: String,
    status: String,
    rc: String,
    log_path: PathBuf,
    description: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LiveLabProfile {
    values: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LiveLabProfileTarget {
    role: String,
    target: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IterationPreflightSelection {
    vm_aliases: Vec<String>,
    raw_targets: Vec<String>,
}

pub fn execute_ops_vm_lab_iterate_live_lab(
    config: VmLabIterateLiveLabConfig,
) -> Result<String, String> {
    if config.validation_steps.is_empty() {
        return Err(
            "specify at least one --validation-step for vm-lab-iterate-live-lab".to_string(),
        );
    }

    let dirty_worktree = if config.require_clean_tree || config.require_local_head {
        Some(git_worktree_is_dirty()?)
    } else {
        None
    };
    let (resolved_source_mode, resolved_repo_ref) = resolve_iteration_source_selection(
        config.source_mode.as_deref(),
        config.repo_ref.as_deref(),
        config.require_clean_tree,
        config.require_local_head,
        dirty_worktree.unwrap_or(false),
    )?;

    let profile_output_path = config
        .profile_output_path
        .clone()
        .unwrap_or_else(default_live_lab_iteration_profile_path);
    let report_dir = config
        .report_dir
        .clone()
        .unwrap_or_else(default_live_lab_iteration_report_dir);
    let script_path = config.script_path.clone();
    let timeout_secs = config.timeout_secs;

    for step in &config.validation_steps {
        execute_vm_lab_iteration_validation_step(step, timeout_secs)?;
    }

    let profile_result =
        execute_ops_vm_lab_write_live_lab_profile(VmLabWriteLiveLabProfileConfig {
            inventory_path: config.inventory_path.clone(),
            output_path: profile_output_path.clone(),
            exit_vm: config.exit_vm.clone(),
            exit_target: config.exit_target.clone(),
            client_vm: config.client_vm.clone(),
            client_target: config.client_target.clone(),
            entry_vm: config.entry_vm.clone(),
            entry_target: config.entry_target.clone(),
            aux_vm: config.aux_vm.clone(),
            aux_target: config.aux_target.clone(),
            extra_vm: config.extra_vm.clone(),
            extra_target: config.extra_target.clone(),
            fifth_client_vm: config.fifth_client_vm.clone(),
            fifth_client_target: config.fifth_client_target.clone(),
            require_same_network: config.require_same_network,
            ssh_identity_file: config.ssh_identity_file.clone(),
            ssh_known_hosts_file: config.ssh_known_hosts_file.clone(),
            ssh_allow_cidrs: config.ssh_allow_cidrs.clone(),
            network_id: config.network_id.clone(),
            traversal_ttl_secs: config.traversal_ttl_secs,
            cross_network_nat_profiles: None,
            cross_network_required_nat_profiles: None,
            cross_network_impairment_profile: None,
            backend: Some(
                config
                    .backend
                    .clone()
                    .unwrap_or_else(|| "linux-wireguard-userspace-shared".to_string()),
            ),
            source_mode: Some(resolved_source_mode.clone()),
            repo_ref: resolved_repo_ref.clone(),
            report_dir: Some(report_dir.clone()),
        })?;

    let preflight_selection = collect_iteration_preflight_selection(&config)?;
    execute_ops_vm_lab_preflight(VmLabPreflightConfig {
        inventory_path: config.inventory_path.clone(),
        vm_aliases: preflight_selection.vm_aliases,
        raw_targets: preflight_selection.raw_targets,
        select_all: false,
        known_hosts_path: config.ssh_known_hosts_file.clone(),
        require_same_network: config.require_same_network,
        require_commands: vec!["git".to_string(), "cargo".to_string()],
        min_free_kib: 1_048_576,
        require_rustynet_installed: true,
        timeout_secs,
    })?;

    let live_lab_result = execute_ops_vm_lab_run_live_lab(VmLabRunLiveLabConfig {
        profile_path: profile_output_path.clone(),
        script_path,
        dry_run: config.dry_run,
        skip_gates: true,
        skip_soak: true,
        skip_cross_network: true,
        source_mode: Some(resolved_source_mode),
        repo_ref: resolved_repo_ref,
        report_dir: Some(report_dir.clone()),
        timeout_secs,
    });

    let summary = summarize_live_lab_report(
        report_dir.as_path(),
        config.collect_failure_diagnostics,
        config.failed_log_tail_lines,
    )?;
    let summary_text = render_live_lab_iteration_summary(
        profile_output_path.as_path(),
        report_dir.as_path(),
        profile_result.as_str(),
        &summary,
    );

    match live_lab_result {
        Ok(_) => Ok(summary_text),
        Err(err) => Err(format!("{summary_text}\nrun_error={err}")),
    }
}

pub fn execute_ops_vm_lab_validate_live_lab_profile(
    config: VmLabValidateLiveLabProfileConfig,
) -> Result<String, String> {
    let profile = load_live_lab_profile(config.profile_path.as_path())?;
    ensure_local_regular_file_path(
        Path::new(profile.required("SSH_IDENTITY_FILE")?.as_str()),
        "SSH identity file",
    )?;
    if let Some(path) = profile.optional("SSH_KNOWN_HOSTS_FILE") {
        ensure_local_regular_file_path(Path::new(path.as_str()), "SSH known_hosts file")?;
    }
    let source_mode = profile.optional("SOURCE_MODE");
    let backend = profile.optional("RUSTYNET_BACKEND");
    if let Some(expected_backend) = config.expected_backend.as_deref()
        && backend.as_deref() != Some(expected_backend)
    {
        return Err(format!(
            "live-lab profile backend mismatch: expected {expected_backend}, got {}",
            backend.as_deref().unwrap_or("none")
        ));
    }
    if let Some(expected_source_mode) = config.expected_source_mode.as_deref()
        && source_mode.as_deref() != Some(expected_source_mode)
    {
        return Err(format!(
            "live-lab profile source mode mismatch: expected {expected_source_mode}, got {}",
            source_mode.as_deref().unwrap_or("none")
        ));
    }
    if let Some(mode) = source_mode.as_deref() {
        validate_live_lab_source_mode(mode)?;
        if mode == "ref" && profile.optional("REPO_REF").is_none() {
            return Err("live-lab profile SOURCE_MODE=ref requires REPO_REF".to_string());
        }
    }
    if config.require_five_node {
        for key in ["ENTRY_TARGET", "AUX_TARGET", "EXTRA_TARGET"] {
            if profile.optional(key).is_none() {
                return Err(format!(
                    "live-lab profile must define {key} for the reduced five-node topology"
                ));
            }
        }
    }

    let targets = profile.configured_targets()?;
    let mut lines = vec![
        format!("profile_path={}", config.profile_path.display()),
        format!("target_count={}", targets.len()),
        format!("backend={}", backend.as_deref().unwrap_or("none")),
        format!("source_mode={}", source_mode.as_deref().unwrap_or("none")),
        format!(
            "repo_ref={}",
            profile.optional("REPO_REF").as_deref().unwrap_or("none")
        ),
        format!(
            "report_dir={}",
            profile.optional("REPORT_DIR").as_deref().unwrap_or("none")
        ),
    ];
    for target in &targets {
        lines.push(format!("target.{}={}", target.role, target.target));
    }
    Ok(lines.join("\n"))
}

pub fn execute_ops_vm_lab_diagnose_live_lab_failure(
    config: VmLabDiagnoseLiveLabFailureConfig,
) -> Result<String, String> {
    let profile = load_live_lab_profile(config.profile_path.as_path())?;
    let summary = summarize_live_lab_report(config.report_dir.as_path(), false, 1)?;
    let stage = if let Some(stage) = config.stage.as_deref() {
        stage.to_string()
    } else {
        summary
            .first_failed_stage
            .clone()
            .ok_or_else(|| "live-lab report does not contain a failed stage".to_string())?
    };
    let stage_records = parse_live_lab_stage_records(config.report_dir.as_path())?;
    let stage_record = stage_records
        .iter()
        .find(|record| record.name == stage)
        .ok_or_else(|| {
            format!(
                "stage {stage} is not present in {}",
                config.report_dir.display()
            )
        })?;
    let diagnostics_dir = config.output_dir.clone().unwrap_or_else(|| {
        config
            .report_dir
            .join("diagnostics")
            .join(sanitize_label_for_path(stage.as_str()))
    });
    fs::create_dir_all(diagnostics_dir.as_path()).map_err(|err| {
        format!(
            "create diagnostics dir failed ({}): {err}",
            diagnostics_dir.display()
        )
    })?;

    let targets = profile.configured_targets()?;
    let raw_targets = targets
        .iter()
        .map(|target| target.target.clone())
        .collect::<Vec<_>>();
    let status_output = execute_ops_vm_lab_status(VmLabStatusConfig {
        inventory_path: config.inventory_path.clone(),
        vm_aliases: Vec::new(),
        raw_targets: raw_targets.clone(),
        select_all: false,
        ssh_user: None,
        timeout_secs: config.timeout_secs,
    })?;
    let status_path = diagnostics_dir.join("vm_lab_status.json");
    fs::write(status_path.as_path(), status_output.as_bytes()).map_err(|err| {
        format!(
            "write vm-lab status output failed ({}): {err}",
            status_path.display()
        )
    })?;

    let artifacts_dir = if config.collect_artifacts {
        let artifacts_dir = diagnostics_dir.join("artifacts");
        execute_ops_vm_lab_collect_artifacts(VmLabCollectArtifactsConfig {
            inventory_path: config.inventory_path.clone(),
            vm_aliases: Vec::new(),
            raw_targets,
            select_all: false,
            ssh_user: None,
            output_dir: artifacts_dir.clone(),
            timeout_secs: config.timeout_secs,
        })?;
        Some(artifacts_dir)
    } else {
        None
    };

    let targets_json = targets
        .iter()
        .map(|target| {
            json!({
                "role": target.role,
                "target": target.target,
            })
        })
        .collect::<Vec<_>>();
    let summary_json = json!({
        "report_dir": config.report_dir,
        "profile_path": config.profile_path,
        "stage": stage,
        "stage_description": stage_record.description,
        "key_report_path": summary.key_report_path.clone(),
        "key_log_path": summary.key_log_path.clone(),
        "likely_reason": summary.likely_reason.clone(),
        "target_count": targets.len(),
        "targets": targets_json,
        "status_output_path": status_path.clone(),
        "artifacts_dir": artifacts_dir.clone(),
    });
    let summary_path = diagnostics_dir.join("diagnostics_summary.json");
    fs::write(
        summary_path.as_path(),
        serde_json::to_vec_pretty(&summary_json)
            .map_err(|err| format!("serialize live-lab diagnostics summary failed: {err}"))?,
    )
    .map_err(|err| {
        format!(
            "write diagnostics summary failed ({}): {err}",
            summary_path.display()
        )
    })?;

    let mut lines = vec![
        format!("report_dir={}", config.report_dir.display()),
        format!("profile_path={}", config.profile_path.display()),
        format!("stage={}", stage_record.name),
        format!("stage_description={}", stage_record.description),
        format!("key_report_path={}", summary.key_report_path.display()),
        format!(
            "key_log_path={}",
            summary
                .key_log_path
                .as_deref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "none".to_string())
        ),
        format!("diagnostics_dir={}", diagnostics_dir.display()),
        format!("status_output_path={}", status_path.display()),
        format!(
            "artifacts_dir={}",
            artifacts_dir
                .as_deref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "none".to_string())
        ),
        format!("target_count={}", targets.len()),
    ];
    for target in targets {
        lines.push(format!("target.{}={}", target.role, target.target));
    }
    Ok(lines.join("\n"))
}

pub fn execute_ops_vm_lab_diff_live_lab_runs(
    config: VmLabDiffLiveLabRunsConfig,
) -> Result<String, String> {
    let old_summary = summarize_live_lab_report(config.old_report_dir.as_path(), false, 1)?;
    let new_summary = summarize_live_lab_report(config.new_report_dir.as_path(), false, 1)?;
    let old_records = parse_live_lab_stage_records(config.old_report_dir.as_path())?;
    let new_records = parse_live_lab_stage_records(config.new_report_dir.as_path())?;
    let old_map = old_records
        .iter()
        .map(|record| (record.name.clone(), record))
        .collect::<BTreeMap<_, _>>();
    let new_map = new_records
        .iter()
        .map(|record| (record.name.clone(), record))
        .collect::<BTreeMap<_, _>>();
    let ordered_names = old_records
        .iter()
        .map(|record| record.name.clone())
        .chain(
            new_records
                .iter()
                .map(|record| record.name.clone())
                .filter(|name| !old_map.contains_key(name)),
        )
        .collect::<Vec<_>>();

    let mut first_divergent_stage = None;
    let mut changes = Vec::new();
    for name in ordered_names {
        let old_status = old_map.get(&name).map(|record| record.status.as_str());
        let new_status = new_map.get(&name).map(|record| record.status.as_str());
        let old_rc = old_map.get(&name).map(|record| record.rc.as_str());
        let new_rc = new_map.get(&name).map(|record| record.rc.as_str());
        if old_status != new_status || old_rc != new_rc {
            if first_divergent_stage.is_none() {
                first_divergent_stage = Some(name.clone());
            }
            changes.push(format!(
                "{}:{}:{} -> {}:{}",
                name,
                old_status.unwrap_or("missing"),
                old_rc.unwrap_or("missing"),
                new_status.unwrap_or("missing"),
                new_rc.unwrap_or("missing")
            ));
        }
    }

    let mut lines = vec![
        format!("old_report_dir={}", config.old_report_dir.display()),
        format!("new_report_dir={}", config.new_report_dir.display()),
        format!("old_overall_status={}", old_summary.overall_status),
        format!("new_overall_status={}", new_summary.overall_status),
        format!(
            "old_first_failed_stage={}",
            old_summary.first_failed_stage.as_deref().unwrap_or("none")
        ),
        format!(
            "new_first_failed_stage={}",
            new_summary.first_failed_stage.as_deref().unwrap_or("none")
        ),
        format!(
            "first_divergent_stage={}",
            first_divergent_stage.as_deref().unwrap_or("none")
        ),
        format!("changed_stage_count={}", changes.len()),
    ];
    if let Some(reason) = old_summary.likely_reason.as_deref() {
        lines.push(format!("old_likely_reason={reason}"));
    }
    if let Some(reason) = new_summary.likely_reason.as_deref() {
        lines.push(format!("new_likely_reason={reason}"));
    }
    for change in changes {
        lines.push(format!("stage_change={change}"));
    }
    Ok(lines.join("\n"))
}

fn resolve_iteration_source_selection(
    configured_source_mode: Option<&str>,
    configured_repo_ref: Option<&str>,
    require_clean_tree: bool,
    require_local_head: bool,
    dirty_worktree: bool,
) -> Result<(String, Option<String>), String> {
    if (require_clean_tree || require_local_head) && dirty_worktree {
        return Err("git worktree must be clean for this live-lab iteration".to_string());
    }
    if require_local_head {
        if let Some(source_mode) = configured_source_mode
            && source_mode != "local-head"
        {
            return Err(format!(
                "--require-local-head is incompatible with --source-mode {source_mode}"
            ));
        }
        if let Some(repo_ref) = configured_repo_ref
            && repo_ref != "HEAD"
        {
            return Err(format!(
                "--require-local-head is incompatible with --repo-ref {repo_ref} (expected HEAD)"
            ));
        }
        return Ok(("local-head".to_string(), Some("HEAD".to_string())));
    }
    Ok((
        configured_source_mode.unwrap_or("working-tree").to_string(),
        configured_repo_ref.map(str::to_string),
    ))
}

fn git_worktree_is_dirty() -> Result<bool, String> {
    let mut command = Command::new("git");
    command.current_dir(workspace_root_path());
    command.args(["status", "--short"]);
    let output = run_output_with_timeout(
        &mut command,
        timeout_or_default(30, DEFAULT_RUN_TIMEOUT_SECS),
    )?;
    if !output.status.success() {
        return Err(format!(
            "git status failed with status {}",
            status_code(output.status)
        ));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|err| format!("git status returned non-UTF-8 output: {err}"))?;
    Ok(!stdout.trim().is_empty())
}

impl LiveLabProfile {
    fn required(&self, key: &str) -> Result<String, String> {
        self.values
            .get(key)
            .cloned()
            .ok_or_else(|| format!("live-lab profile is missing required key {key}"))
    }

    fn optional(&self, key: &str) -> Option<String> {
        self.values.get(key).cloned()
    }

    fn configured_targets(&self) -> Result<Vec<LiveLabProfileTarget>, String> {
        let mut targets = vec![
            LiveLabProfileTarget {
                role: "exit".to_string(),
                target: self.required("EXIT_TARGET")?,
            },
            LiveLabProfileTarget {
                role: "client".to_string(),
                target: self.required("CLIENT_TARGET")?,
            },
        ];
        for (key, role) in [
            ("ENTRY_TARGET", "entry"),
            ("AUX_TARGET", "aux"),
            ("EXTRA_TARGET", "extra"),
            ("FIFTH_CLIENT_TARGET", "fifth_client"),
        ] {
            if let Some(target) = self.optional(key) {
                targets.push(LiveLabProfileTarget {
                    role: role.to_string(),
                    target,
                });
            }
        }
        Ok(targets)
    }
}

fn load_live_lab_profile(path: &Path) -> Result<LiveLabProfile, String> {
    ensure_local_regular_file_path(path, "live-lab profile")?;
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
        let key = key.trim();
        ensure_live_lab_profile_key(key)?;
        if values.contains_key(key) {
            return Err(format!(
                "duplicate live-lab profile key {} in {}",
                key,
                path.display()
            ));
        }
        let value = parse_env_value(raw_value).map_err(|err| {
            format!(
                "invalid live-lab profile value for {} in {}: {}",
                key,
                path.display(),
                err
            )
        })?;
        values.insert(key.to_string(), value);
    }
    let profile = LiveLabProfile { values };
    ensure_ssh_target("EXIT_TARGET", profile.required("EXIT_TARGET")?.as_str())?;
    ensure_ssh_target("CLIENT_TARGET", profile.required("CLIENT_TARGET")?.as_str())?;
    let _ = profile.required("SSH_IDENTITY_FILE")?;
    Ok(profile)
}

fn ensure_live_lab_profile_key(key: &str) -> Result<(), String> {
    if key.is_empty()
        || !key
            .chars()
            .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
    {
        return Err(format!("invalid live-lab profile key: {key}"));
    }
    Ok(())
}

fn validate_live_lab_source_mode(value: &str) -> Result<(), String> {
    match value {
        "working-tree" | "local-head" | "origin-main" | "ref" => Ok(()),
        _ => Err(format!(
            "unsupported live-lab profile source mode: {value} (expected working-tree|local-head|origin-main|ref)"
        )),
    }
}

fn parse_live_lab_stage_records(report_dir: &Path) -> Result<Vec<LiveLabStageRecord>, String> {
    let report_dir = if report_dir.is_absolute() {
        report_dir.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|err| format!("resolve current directory failed: {err}"))?
            .join(report_dir)
    };
    let stages_path = report_dir.join("state/stages.tsv");
    let stages_body = fs::read_to_string(&stages_path).map_err(|err| {
        format!(
            "read live-lab stages failed ({}): {err}",
            stages_path.display()
        )
    })?;
    let mut records = Vec::new();
    for line in stages_body.lines().filter(|line| !line.trim().is_empty()) {
        let columns = line.split('\t').collect::<Vec<_>>();
        if columns.len() < 6 {
            continue;
        }
        records.push(LiveLabStageRecord {
            name: columns[0].to_string(),
            severity: columns[1].to_string(),
            status: columns[2].to_string(),
            rc: columns[3].to_string(),
            log_path: resolve_report_relative_path(columns[4], report_dir.as_path())?,
            description: columns[5].to_string(),
        });
    }
    Ok(records)
}

fn execute_vm_lab_iteration_validation_step(
    step: &VmLabIterationValidationStep,
    timeout_secs: u64,
) -> Result<(), String> {
    let timeout = timeout_or_default(timeout_secs, DEFAULT_RUN_TIMEOUT_SECS);
    let mut command = Command::new("cargo");
    command.current_dir(workspace_root_path());
    match step {
        VmLabIterationValidationStep::FmtCheck => {
            command.args(["fmt", "--all", "--", "--check"]);
        }
        VmLabIterationValidationStep::CargoCheckPackage { package } => {
            command.args(["check", "-p", package.as_str()]);
        }
        VmLabIterationValidationStep::CargoCheckBin { package, bin } => {
            command.args(["check", "-p", package.as_str(), "--bin", bin.as_str()]);
        }
        VmLabIterationValidationStep::CargoTestPackage { package, filter } => {
            command.args(["test", "-p", package.as_str()]);
            if let Some(filter) = filter.as_deref() {
                command.arg(filter);
            }
            command.args(["--", "--nocapture"]);
        }
        VmLabIterationValidationStep::CargoTestBin {
            package,
            bin,
            filter,
        } => {
            command.args(["test", "-p", package.as_str(), "--bin", bin.as_str()]);
            if let Some(filter) = filter.as_deref() {
                command.arg(filter);
            }
            command.args(["--", "--nocapture"]);
        }
    }
    let step_label = step.label();
    let status = run_status_with_timeout_passthrough(&mut command, timeout)
        .map_err(|err| format!("validation step {step_label} failed: {err}"))?;
    ensure_success_status(status, &format!("validation step {step_label}"))
}

fn collect_iteration_preflight_selection(
    config: &VmLabIterateLiveLabConfig,
) -> Result<IterationPreflightSelection, String> {
    let mut seen = HashSet::new();
    let mut vm_aliases = Vec::new();
    let mut raw_targets = Vec::new();

    let mut push_role = |role_label: &str,
                         alias: Option<&String>,
                         raw_target: Option<&String>|
     -> Result<(), String> {
        match (alias, raw_target) {
            (Some(alias), None) => {
                resolve_role_target_from_inventory(
                    config.inventory_path.as_path(),
                    role_label,
                    alias.as_str(),
                )?;
                if seen.insert(format!("vm:{alias}")) {
                    vm_aliases.push(alias.clone());
                }
            }
            (None, Some(raw_target)) => {
                let target = resolve_role_target_from_raw(role_label, raw_target.as_str())?;
                if seen.insert(format!("target:{}", target.normalized_target)) {
                    raw_targets.push(target.normalized_target);
                }
            }
            (None, None) => {}
            (Some(_), Some(_)) => {
                return Err(format!(
                    "{role_label} target must use either --{role_label}-vm or --{role_label}-target, not both"
                ));
            }
        }
        Ok(())
    };

    push_role("exit", config.exit_vm.as_ref(), config.exit_target.as_ref())?;
    push_role(
        "client",
        config.client_vm.as_ref(),
        config.client_target.as_ref(),
    )?;
    push_role(
        "entry",
        config.entry_vm.as_ref(),
        config.entry_target.as_ref(),
    )?;
    push_role("aux", config.aux_vm.as_ref(), config.aux_target.as_ref())?;
    push_role(
        "extra",
        config.extra_vm.as_ref(),
        config.extra_target.as_ref(),
    )?;
    push_role(
        "fifth_client",
        config.fifth_client_vm.as_ref(),
        config.fifth_client_target.as_ref(),
    )?;

    if vm_aliases.is_empty() && raw_targets.is_empty() {
        return Err("live-lab iteration requires at least exit and client targets".to_string());
    }
    Ok(IterationPreflightSelection {
        vm_aliases,
        raw_targets,
    })
}

fn default_live_lab_iteration_profile_path() -> PathBuf {
    default_live_lab_profile_root().join(format!(
        "generated_vm_lab_iteration_{}.env",
        unique_suffix()
    ))
}

fn default_live_lab_iteration_report_dir() -> PathBuf {
    default_live_lab_report_root().join(format!("iteration_{}", unique_suffix()))
}

fn summarize_live_lab_report(
    report_dir: &Path,
    collect_failure_diagnostics: bool,
    failed_log_tail_lines: usize,
) -> Result<LiveLabStageSummary, String> {
    let report_dir = if report_dir.is_absolute() {
        report_dir.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|err| format!("resolve current directory failed: {err}"))?
            .join(report_dir)
    };
    let stages_path = report_dir.join("state/stages.tsv");
    let failure_digest_path = report_dir.join("failure_digest.md");
    let stages_body = fs::read_to_string(&stages_path).map_err(|err| {
        format!(
            "read live-lab stages failed ({}): {err}",
            stages_path.display()
        )
    })?;
    let mut first_failed_stage = None;
    let mut key_log_path = None;
    for line in stages_body.lines().filter(|line| !line.trim().is_empty()) {
        let columns = line.split('\t').collect::<Vec<_>>();
        if columns.len() < 5 {
            continue;
        }
        if columns[2] == "fail" {
            first_failed_stage = Some(columns[0].to_string());
            key_log_path = Some(resolve_report_relative_path(
                columns[4],
                report_dir.as_path(),
            )?);
            break;
        }
    }
    let likely_reason = key_log_path
        .as_deref()
        .map(extract_iteration_likely_reason)
        .filter(|reason| !reason.is_empty());
    let failed_log_tail = if collect_failure_diagnostics {
        key_log_path
            .as_deref()
            .map(|path| tail_log_lines(path, failed_log_tail_lines))
            .transpose()?
    } else {
        None
    };
    Ok(LiveLabStageSummary {
        overall_status: if first_failed_stage.is_some() {
            "fail".to_string()
        } else {
            "pass".to_string()
        },
        first_failed_stage,
        key_report_path: failure_digest_path,
        key_log_path,
        likely_reason,
        failed_log_tail,
    })
}

fn resolve_report_relative_path(value: &str, report_dir: &Path) -> Result<PathBuf, String> {
    let path = Path::new(value);
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    let cwd = std::env::current_dir()
        .map_err(|err| format!("resolve current directory failed: {err}"))?;
    let cwd_joined = cwd.join(path);
    if cwd_joined.exists() {
        Ok(cwd_joined)
    } else {
        Ok(report_dir.join(path))
    }
}

fn extract_iteration_likely_reason(log_path: &Path) -> String {
    let Ok(body) = fs::read_to_string(log_path) else {
        return "see full log".to_string();
    };
    let mut candidates = Vec::new();
    for raw_line in body.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with("[stage:")
            && (line.contains("] START") || line.contains("] PASS") || line.contains("] FAIL"))
        {
            continue;
        }
        if line.starts_with("[parallel:") || line.starts_with("----- ") {
            continue;
        }
        candidates.push(line.to_string());
    }
    if candidates.is_empty() {
        return "see full log".to_string();
    }
    for line in candidates.iter().rev() {
        let lowered = line.to_ascii_lowercase();
        if lowered.contains("error:")
            || lowered.contains("fail")
            || lowered.contains("timed out")
            || lowered.contains("timeout")
            || lowered.contains("permission denied")
            || lowered.contains("missing")
            || lowered.contains("invalid")
            || lowered.contains("mismatch")
            || lowered.contains("does not exist")
            || lowered.contains("no such")
            || lowered.contains("unreachable")
        {
            return line.clone();
        }
    }
    candidates
        .last()
        .cloned()
        .unwrap_or_else(|| "see full log".to_string())
}

fn tail_log_lines(path: &Path, max_lines: usize) -> Result<String, String> {
    let body = fs::read_to_string(path)
        .map_err(|err| format!("read failed log tail failed ({}): {err}", path.display()))?;
    let lines = body
        .lines()
        .map(str::trim_end)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    let start = lines.len().saturating_sub(max_lines.max(1));
    Ok(lines[start..].join("\n"))
}

fn render_live_lab_iteration_summary(
    profile_output_path: &Path,
    report_dir: &Path,
    profile_result: &str,
    summary: &LiveLabStageSummary,
) -> String {
    let mut lines = vec![
        format!("profile_result={profile_result}"),
        format!("profile_path={}", profile_output_path.display()),
        format!("report_dir={}", report_dir.display()),
        format!("overall_status={}", summary.overall_status),
        format!(
            "first_failed_stage={}",
            summary.first_failed_stage.as_deref().unwrap_or("none")
        ),
        format!("key_report_path={}", summary.key_report_path.display()),
        format!(
            "key_log_path={}",
            summary
                .key_log_path
                .as_deref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "none".to_string())
        ),
    ];
    if let Some(reason) = summary.likely_reason.as_deref() {
        lines.push(format!("likely_reason={reason}"));
    }
    if let Some(tail) = summary.failed_log_tail.as_deref() {
        lines.push("diagnostic_log_tail<<EOF".to_string());
        lines.push(tail.to_string());
        lines.push("EOF".to_string());
    }
    lines.join("\n")
}

pub fn execute_ops_vm_lab_check_known_hosts(
    config: VmLabCheckKnownHostsConfig,
) -> Result<String, String> {
    ensure_local_regular_file_path(config.known_hosts_path.as_path(), "known_hosts file")?;
    let inventory = load_inventory(config.inventory_path.as_path())?;
    let selected_targets = resolve_known_hosts_targets(
        inventory.as_slice(),
        config.vm_aliases.as_slice(),
        config.select_all,
        config.raw_targets.as_slice(),
    )?;
    let mut lines = Vec::new();
    let mut missing = Vec::new();
    for target in selected_targets {
        let matched = find_known_hosts_match(
            config.known_hosts_path.as_path(),
            target.host_candidates.as_slice(),
        )?;
        if let Some(candidate) = matched {
            lines.push(format!(
                "label={} status=present matched={} candidates={}",
                target.label,
                candidate,
                target.host_candidates.join(",")
            ));
        } else {
            missing.push(target.label.clone());
            lines.push(format!(
                "label={} status=missing candidates={}",
                target.label,
                target.host_candidates.join(",")
            ));
        }
    }
    if missing.is_empty() {
        Ok(lines.join("\n"))
    } else {
        Err(format!(
            "{}\nmissing pinned known_hosts entries for: {}",
            lines.join("\n"),
            missing.join(", ")
        ))
    }
}

pub fn execute_ops_vm_lab_preflight(config: VmLabPreflightConfig) -> Result<String, String> {
    if config.require_same_network {
        ensure_remote_selection_declares_single_network(
            config.inventory_path.as_path(),
            config.vm_aliases.as_slice(),
            config.select_all,
            config.raw_targets.as_slice(),
        )?;
    }
    if let Some(path) = config.known_hosts_path.as_deref() {
        execute_ops_vm_lab_check_known_hosts(VmLabCheckKnownHostsConfig {
            inventory_path: config.inventory_path.clone(),
            vm_aliases: config.vm_aliases.clone(),
            raw_targets: config.raw_targets.clone(),
            select_all: config.select_all,
            known_hosts_path: path.to_path_buf(),
        })?;
    }

    let targets = resolve_remote_targets(
        config.inventory_path.as_path(),
        config.vm_aliases.as_slice(),
        config.select_all,
        config.raw_targets.as_slice(),
    )?;
    let required_commands = if config.require_commands.is_empty() {
        DEFAULT_PRECHECK_COMMANDS
            .iter()
            .map(|value| value.to_string())
            .collect::<Vec<_>>()
    } else {
        config.require_commands.clone()
    };
    for command_name in &required_commands {
        ensure_inventory_alias(command_name)?;
    }
    let timeout = timeout_or_default(config.timeout_secs, DEFAULT_PREFLIGHT_TIMEOUT_SECS);
    let mut results = Vec::new();
    let mut failures = 0usize;

    for target in &targets {
        let effective_user = target.ssh_user.as_deref();
        match capture_remote_shell_command(
            target.ssh_target.as_str(),
            effective_user,
            build_preflight_script(
                required_commands.as_slice(),
                config.min_free_kib,
                config.require_rustynet_installed,
            )?
            .as_str(),
            timeout,
        ) {
            Ok(output) => {
                let values = parse_key_value_output(output.as_str());
                let free_kib = values
                    .get("free_kib")
                    .and_then(|value| value.parse::<u64>().ok())
                    .unwrap_or_default();
                let sudo_ok = values.get("sudo_ok").map(String::as_str) == Some("true");
                let rustynet_installed =
                    values.get("rustynet_installed").map(String::as_str) == Some("true");
                let mut missing_commands = Vec::new();
                for command_name in &required_commands {
                    let key = format!("cmd.{command_name}");
                    if values.get(key.as_str()).map(String::as_str) != Some("present") {
                        missing_commands.push(command_name.clone());
                    }
                }
                let mut problems = Vec::new();
                if !sudo_ok {
                    problems.push("sudo-n".to_string());
                }
                if free_kib < config.min_free_kib {
                    problems.push(format!("free_kib<{min}", min = config.min_free_kib));
                }
                if config.require_rustynet_installed && !rustynet_installed {
                    problems.push("rustynet-missing".to_string());
                }
                if !missing_commands.is_empty() {
                    problems.push(format!("missing-commands={}", missing_commands.join(",")));
                }
                if !problems.is_empty() {
                    failures += 1;
                }
                results.push(json!({
                    "label": target.label,
                    "ssh_target": target.ssh_target,
                    "ssh_user": effective_user,
                    "hostname": values.get("hostname"),
                    "os": values.get("os"),
                    "free_kib": free_kib,
                    "sudo_ok": sudo_ok,
                    "rustynet_installed": rustynet_installed,
                    "commands": required_commands.iter().map(|command_name| {
                        let key = format!("cmd.{command_name}");
                        (
                            command_name.clone(),
                            values.get(key.as_str()).cloned().unwrap_or_else(|| "missing".to_string())
                        )
                    }).collect::<BTreeMap<_, _>>(),
                    "status": if problems.is_empty() { "pass" } else { "fail" },
                    "problems": problems,
                }));
            }
            Err(err) => {
                failures += 1;
                results.push(json!({
                    "label": target.label,
                    "ssh_target": target.ssh_target,
                    "ssh_user": effective_user,
                    "status": "fail",
                    "error": err,
                }));
            }
        }
    }

    let payload = serde_json::to_string_pretty(&json!({
        "summary": {
            "targets": targets.len(),
            "passed": targets.len().saturating_sub(failures),
            "failed": failures,
        },
        "results": results,
    }))
    .map_err(|err| format!("serialize preflight report failed: {err}"))?;
    if failures == 0 {
        Ok(payload)
    } else {
        Err(payload)
    }
}

pub fn execute_ops_vm_lab_status(config: VmLabStatusConfig) -> Result<String, String> {
    let targets = resolve_remote_targets(
        config.inventory_path.as_path(),
        config.vm_aliases.as_slice(),
        config.select_all,
        config.raw_targets.as_slice(),
    )?;
    let timeout = timeout_or_default(config.timeout_secs, DEFAULT_PREFLIGHT_TIMEOUT_SECS);
    let mut results = Vec::new();
    let mut failures = 0usize;
    let rustynet_status_script = privileged_rustynet_cli_script("status");
    let rustynet_netcheck_script = privileged_rustynet_cli_script("netcheck");
    let sections = [
        ("hostname", "hostname"),
        (
            "service_active",
            "if command -v systemctl >/dev/null 2>&1; then systemctl is-active rustynetd.service; else echo systemctl-unavailable; fi",
        ),
        ("rustynet_status", rustynet_status_script.as_str()),
        ("rustynet_netcheck", rustynet_netcheck_script.as_str()),
        (
            "latest_handshakes",
            "if command -v wg >/dev/null 2>&1; then if sudo -n true >/dev/null 2>&1; then sudo -n wg show all latest-handshakes 2>&1; else wg show all latest-handshakes 2>&1; fi; else echo wg-not-installed; fi",
        ),
        (
            "ip_addr",
            "if command -v ip >/dev/null 2>&1; then ip -brief addr; else echo ip-unavailable; fi",
        ),
    ];
    let capture_script = build_section_capture_script(sections.as_slice());

    for target in &targets {
        let effective_user = config.ssh_user.as_deref().or(target.ssh_user.as_deref());
        match capture_remote_shell_command(
            target.ssh_target.as_str(),
            effective_user,
            capture_script.as_str(),
            timeout,
        ) {
            Ok(output) => {
                results.push(json!({
                    "label": target.label,
                    "ssh_target": target.ssh_target,
                    "ssh_user": effective_user,
                    "sections": parse_section_capture(output.as_str()),
                }));
            }
            Err(err) => {
                failures += 1;
                results.push(json!({
                    "label": target.label,
                    "ssh_target": target.ssh_target,
                    "ssh_user": effective_user,
                    "error": err,
                }));
            }
        }
    }

    let payload = serde_json::to_string_pretty(&json!({
        "summary": {
            "targets": targets.len(),
            "failed": failures,
        },
        "results": results,
    }))
    .map_err(|err| format!("serialize vm-lab status failed: {err}"))?;
    if failures == 0 {
        Ok(payload)
    } else {
        Err(payload)
    }
}

pub fn execute_ops_vm_lab_stop(config: VmLabStopConfig) -> Result<String, String> {
    let targets = resolve_start_targets(
        config.inventory_path.as_path(),
        config.vm_aliases.as_slice(),
        config.select_all,
    )?;
    let utmctl_path = config.utmctl_path;
    if !utmctl_path.is_file() {
        return Err(format!(
            "utmctl binary is not present: {}",
            utmctl_path.display()
        ));
    }
    let timeout = timeout_or_default(config.timeout_secs, DEFAULT_START_TIMEOUT_SECS);
    let mut results = Vec::new();
    for target in &targets {
        transition_local_utm_vm(
            utmctl_path.as_path(),
            target.utm_name.as_str(),
            target.bundle_path.as_path(),
            "stop",
            false,
            timeout,
        )
        .map_err(|err| format!("{} stop failed: {err}", target.alias))?;
        results.push(format!(
            "{} stopped via utm_name={} bundle_path={}",
            target.alias,
            target.utm_name,
            target.bundle_path.display()
        ));
    }
    Ok(results.join("\n"))
}

pub fn execute_ops_vm_lab_restart(config: VmLabRestartConfig) -> Result<String, String> {
    if let Some(service) = config.service.as_deref() {
        ensure_no_control_chars("service", service)?;
        return execute_ops_vm_lab_run(
            VmLabExecConfig {
                inventory_path: config.inventory_path,
                vm_aliases: config.vm_aliases,
                raw_targets: config.raw_targets,
                select_all: config.select_all,
                workdir: "/".to_string(),
                program: "systemctl".to_string(),
                argv: vec!["restart".to_string(), service.to_string()],
                ssh_user: config.ssh_user,
                sudo: true,
                timeout_secs: config.timeout_secs,
            },
            "restarted",
        );
    }

    let stop_result = execute_ops_vm_lab_stop(VmLabStopConfig {
        inventory_path: config.inventory_path.clone(),
        vm_aliases: config.vm_aliases.clone(),
        select_all: config.select_all,
        utmctl_path: config.utmctl_path.clone(),
        timeout_secs: config.timeout_secs,
    })?;
    let start_result = execute_ops_vm_lab_start(VmLabStartConfig {
        inventory_path: config.inventory_path,
        vm_aliases: config.vm_aliases,
        select_all: config.select_all,
        utmctl_path: config.utmctl_path,
        timeout_secs: config.timeout_secs,
    })?;
    Ok(format!("{stop_result}\n{start_result}"))
}

pub fn execute_ops_vm_lab_collect_artifacts(
    config: VmLabCollectArtifactsConfig,
) -> Result<String, String> {
    let targets = resolve_remote_targets(
        config.inventory_path.as_path(),
        config.vm_aliases.as_slice(),
        config.select_all,
        config.raw_targets.as_slice(),
    )?;
    let timeout = timeout_or_default(config.timeout_secs, DEFAULT_COLLECT_TIMEOUT_SECS);
    let output_root = config.output_dir;
    fs::create_dir_all(output_root.as_path()).map_err(|err| {
        format!(
            "create artifact output dir failed ({}): {err}",
            output_root.display()
        )
    })?;
    let rustynet_status_script = privileged_rustynet_cli_script("status");
    let rustynet_netcheck_script = privileged_rustynet_cli_script("netcheck");
    let sections = [
        ("hostname", "hostname"),
        ("rustynet_status", rustynet_status_script.as_str()),
        ("rustynet_netcheck", rustynet_netcheck_script.as_str()),
        (
            "service_status",
            "if command -v systemctl >/dev/null 2>&1; then systemctl status rustynetd.service --no-pager -n 80 2>&1; else echo systemctl-unavailable; fi",
        ),
        (
            "journalctl_rustynetd",
            "if command -v journalctl >/dev/null 2>&1; then if sudo -n true >/dev/null 2>&1; then sudo -n journalctl -u rustynetd.service --no-pager -n 200 2>&1; else journalctl -u rustynetd.service --no-pager -n 200 2>&1; fi; else echo journalctl-unavailable; fi",
        ),
        (
            "latest_handshakes",
            "if command -v wg >/dev/null 2>&1; then if sudo -n true >/dev/null 2>&1; then sudo -n wg show all latest-handshakes 2>&1; else wg show all latest-handshakes 2>&1; fi; else echo wg-not-installed; fi",
        ),
        (
            "ip_addr",
            "if command -v ip >/dev/null 2>&1; then ip -brief addr; else echo ip-unavailable; fi",
        ),
        (
            "ip_route",
            "if command -v ip >/dev/null 2>&1; then ip route; else echo ip-unavailable; fi",
        ),
        (
            "assignment_bundle",
            "if [ -f /var/lib/rustynet/rustynetd.assignment ]; then if sudo -n true >/dev/null 2>&1; then sudo -n cat /var/lib/rustynet/rustynetd.assignment 2>&1; else cat /var/lib/rustynet/rustynetd.assignment 2>&1; fi; else echo assignment-bundle-missing; fi",
        ),
        (
            "traversal_bundle",
            "if [ -f /var/lib/rustynet/rustynetd.traversal ]; then if sudo -n true >/dev/null 2>&1; then sudo -n cat /var/lib/rustynet/rustynetd.traversal 2>&1; else cat /var/lib/rustynet/rustynetd.traversal 2>&1; fi; else echo traversal-bundle-missing; fi",
        ),
    ];
    let capture_script = build_section_capture_script(sections.as_slice());
    let mut lines = Vec::new();
    let mut failures = Vec::new();

    for target in &targets {
        let effective_user = config.ssh_user.as_deref().or(target.ssh_user.as_deref());
        let target_dir = output_root.join(sanitize_label_for_path(target.label.as_str()));
        fs::create_dir_all(target_dir.as_path()).map_err(|err| {
            format!(
                "create target artifact dir failed ({}): {err}",
                target_dir.display()
            )
        })?;
        match capture_remote_shell_command(
            target.ssh_target.as_str(),
            effective_user,
            capture_script.as_str(),
            timeout,
        ) {
            Ok(output) => {
                let sections = parse_section_capture(output.as_str());
                for (name, body) in &sections {
                    fs::write(target_dir.join(format!("{name}.txt")), body.as_bytes()).map_err(
                        |err| format!("write artifact failed ({} {}): {err}", target.label, name),
                    )?;
                }
                let metadata = json!({
                    "label": target.label,
                    "ssh_target": target.ssh_target,
                    "ssh_user": effective_user,
                    "artifacts": sections.keys().cloned().collect::<Vec<_>>(),
                });
                fs::write(
                    target_dir.join("metadata.json"),
                    serde_json::to_vec_pretty(&metadata)
                        .map_err(|err| format!("serialize metadata failed: {err}"))?,
                )
                .map_err(|err| format!("write metadata failed ({}): {err}", target.label))?;
                lines.push(format!(
                    "{} collected artifacts into {}",
                    target.label,
                    target_dir.display()
                ));
            }
            Err(err) => {
                failures.push(format!("{} ({err})", target.label));
            }
        }
    }

    if failures.is_empty() {
        Ok(lines.join("\n"))
    } else {
        Err(format!(
            "{}\nartifact collection failed for: {}",
            lines.join("\n"),
            failures.join(", ")
        ))
    }
}

pub fn execute_ops_vm_lab_write_topology(
    config: VmLabWriteTopologyConfig,
) -> Result<String, String> {
    let inventory = load_inventory(config.inventory_path.as_path())?;
    let selected =
        select_inventory_entries(&inventory, config.vm_aliases.as_slice(), config.select_all)?;
    if config.require_same_network {
        ensure_inventory_entries_share_network(selected.as_slice())?;
    }
    let topology = build_vm_lab_topology(selected.as_slice(), config.suite.as_str())?;
    let parent = config
        .output_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or_else(|| {
            format!(
                "topology output path must have a parent directory: {}",
                config.output_path.display()
            )
        })?;
    fs::create_dir_all(parent).map_err(|err| {
        format!(
            "create topology output dir failed ({}): {err}",
            parent.display()
        )
    })?;
    fs::write(
        &config.output_path,
        serde_json::to_vec_pretty(&topology)
            .map_err(|err| format!("serialize topology failed: {err}"))?,
    )
    .map_err(|err| {
        format!(
            "write topology failed ({}): {err}",
            config.output_path.display()
        )
    })?;

    Ok(format!(
        "wrote vm-lab topology={} suite={}",
        config.output_path.display(),
        normalized_suite_name(config.suite.as_str())?
    ))
}

pub fn execute_ops_vm_lab_issue_and_distribute_state(
    config: VmLabIssueDistributeStateConfig,
) -> Result<String, String> {
    let topology = load_vm_lab_topology(config.topology_path.as_path())?;
    let inventory = load_inventory(config.inventory_path.as_path())?;
    let timeout = timeout_or_default(config.timeout_secs, DEFAULT_RUN_TIMEOUT_SECS);
    let authority_entry = inventory
        .iter()
        .find(|entry| entry.alias == config.authority_vm)
        .cloned()
        .ok_or_else(|| {
            format!(
                "authority VM alias not found in inventory: {}",
                config.authority_vm
            )
        })?;
    let authority_target = RemoteTarget {
        label: authority_entry.alias.clone(),
        ssh_target: authority_entry.ssh_target.clone(),
        ssh_user: config.ssh_user.clone().or(authority_entry.ssh_user.clone()),
    };

    let artifact_dir =
        std::env::temp_dir().join(format!("rustynet-vm-lab-state-{}", unique_suffix()));
    fs::create_dir_all(artifact_dir.as_path()).map_err(|err| {
        format!(
            "create vm-lab temporary state dir failed ({}): {err}",
            artifact_dir.display()
        )
    })?;

    let nodes_spec = build_nodes_spec(
        topology.nodes.values().collect::<Vec<_>>().as_slice(),
        inventory.as_slice(),
        timeout,
        config.ssh_user.as_deref(),
    )?;
    let allow_spec = build_allow_spec(topology.nodes.values().collect::<Vec<_>>().as_slice());
    let assignments_spec = build_assignments_spec(&topology)?;
    let traversal_ttl_secs = 120u64;

    let assignment_env_path = artifact_dir.join("assignment.env");
    let traversal_env_path = artifact_dir.join("traversal.env");
    fs::write(
        assignment_env_path.as_path(),
        build_assignment_issue_env(
            nodes_spec.as_str(),
            allow_spec.as_str(),
            assignments_spec.as_str(),
        )?,
    )
    .map_err(|err| format!("write assignment env failed: {err}"))?;
    fs::write(
        traversal_env_path.as_path(),
        build_traversal_issue_env(nodes_spec.as_str(), allow_spec.as_str(), traversal_ttl_secs)?,
    )
    .map_err(|err| format!("write traversal env failed: {err}"))?;

    let remote_assignment_env = format!("/tmp/rn-vm-lab-assignment-{}.env", unique_suffix());
    let remote_traversal_env = format!("/tmp/rn-vm-lab-traversal-{}.env", unique_suffix());
    ensure_success_status(
        scp_to_remote(
            assignment_env_path.as_path(),
            authority_target.ssh_target.as_str(),
            authority_target.ssh_user.as_deref(),
            remote_assignment_env.as_str(),
            timeout,
        )
        .map_err(|err| format!("copy assignment env to authority failed: {err}"))?,
        "copy assignment env to authority",
    )?;
    ensure_success_status(
        scp_to_remote(
            traversal_env_path.as_path(),
            authority_target.ssh_target.as_str(),
            authority_target.ssh_user.as_deref(),
            remote_traversal_env.as_str(),
            timeout,
        )
        .map_err(|err| format!("copy traversal env to authority failed: {err}"))?,
        "copy traversal env to authority",
    )?;

    let authority_issue_script = format!(
        "set -eu; \
if sudo -n true >/dev/null 2>&1; then SUDO='sudo -n'; else SUDO=''; fi; \
$SUDO mkdir -p /run/rustynet/assignment-issue /run/rustynet/traversal-issue; \
$SUDO rustynet ops e2e-issue-assignment-bundles-from-env --env-file {assignment_env}; \
$SUDO rustynet ops e2e-issue-traversal-bundles-from-env --env-file {traversal_env}; \
$SUDO rm -f {assignment_env} {traversal_env}",
        assignment_env = shell_quote(remote_assignment_env.as_str()),
        traversal_env = shell_quote(remote_traversal_env.as_str()),
    );
    let issue_status = run_remote_shell_command(
        authority_target.ssh_target.as_str(),
        authority_target.ssh_user.as_deref(),
        authority_issue_script.as_str(),
        timeout,
    )
    .map_err(|err| format!("issue state on authority failed: {err}"))?;
    if !issue_status.success() {
        return Err(format!(
            "issue state on authority failed with status {}",
            status_code(issue_status)
        ));
    }

    let assignment_pub_local = artifact_dir.join("rn-assignment.pub");
    let traversal_pub_local = artifact_dir.join("rn-traversal.pub");
    capture_remote_file_to_local(
        authority_target.ssh_target.as_str(),
        authority_target.ssh_user.as_deref(),
        "/run/rustynet/assignment-issue/rn-assignment.pub",
        assignment_pub_local.as_path(),
        timeout,
    )?;
    capture_remote_file_to_local(
        authority_target.ssh_target.as_str(),
        authority_target.ssh_user.as_deref(),
        "/run/rustynet/traversal-issue/rn-traversal.pub",
        traversal_pub_local.as_path(),
        timeout,
    )?;

    let mut lines = vec![format!(
        "issued signed assignment/traversal state via authority={} artifacts={}",
        authority_target.label,
        artifact_dir.display()
    )];

    for node in topology.nodes.values() {
        let inventory_entry = inventory
            .iter()
            .find(|entry| entry.alias == node.alias)
            .cloned()
            .ok_or_else(|| format!("topology node missing from inventory: {}", node.alias))?;
        let target = RemoteTarget {
            label: inventory_entry.alias.clone(),
            ssh_target: inventory_entry.ssh_target.clone(),
            ssh_user: config.ssh_user.clone().or(inventory_entry.ssh_user.clone()),
        };
        let assignment_local =
            artifact_dir.join(format!("rn-assignment-{}.assignment", node.node_id));
        let traversal_local = artifact_dir.join(format!("rn-traversal-{}.traversal", node.node_id));
        capture_remote_file_to_local(
            authority_target.ssh_target.as_str(),
            authority_target.ssh_user.as_deref(),
            format!(
                "/run/rustynet/assignment-issue/rn-assignment-{}.assignment",
                node.node_id
            )
            .as_str(),
            assignment_local.as_path(),
            timeout,
        )?;
        capture_remote_file_to_local(
            authority_target.ssh_target.as_str(),
            authority_target.ssh_user.as_deref(),
            format!(
                "/run/rustynet/traversal-issue/rn-traversal-{}.traversal",
                node.node_id
            )
            .as_str(),
            traversal_local.as_path(),
            timeout,
        )?;

        let refresh_env_path = artifact_dir.join(format!("assignment-refresh-{}.env", node.alias));
        fs::write(
            refresh_env_path.as_path(),
            build_assignment_refresh_env(
                node.node_id.as_str(),
                nodes_spec.as_str(),
                allow_spec.as_str(),
                assignment_exit_node_id(&topology, node.alias.as_str())?,
            )?,
        )
        .map_err(|err| {
            format!(
                "write assignment refresh env failed ({}): {err}",
                node.alias
            )
        })?;

        install_state_artifacts_on_target(
            &target,
            assignment_pub_local.as_path(),
            assignment_local.as_path(),
            traversal_pub_local.as_path(),
            traversal_local.as_path(),
            refresh_env_path.as_path(),
            timeout,
        )?;
        lines.push(format!(
            "{} installed assignment/traversal artifacts node_id={}",
            target.label, node.node_id
        ));
    }

    Ok(lines.join("\n"))
}

pub fn execute_ops_vm_lab_run_suite(config: VmLabRunSuiteConfig) -> Result<String, String> {
    let topology = if let Some(path) = config.topology_path.as_deref() {
        load_vm_lab_topology(path)?
    } else {
        let inventory = load_inventory(config.inventory_path.as_path())?;
        let selected =
            select_inventory_entries(&inventory, config.vm_aliases.as_slice(), config.select_all)?;
        let value = build_vm_lab_topology(selected.as_slice(), config.suite.as_str())?;
        parse_vm_lab_topology(value)?
    };
    ensure_local_regular_file_path(config.ssh_identity_file.as_path(), "SSH identity file")?;
    let suite_name = normalized_suite_name(config.suite.as_str())?;
    let report_dir = config.report_dir.unwrap_or_else(|| {
        default_artifact_root().join(format!("{}-{}", suite_name, unique_suffix()))
    });
    fs::create_dir_all(report_dir.as_path()).map_err(|err| {
        format!(
            "create suite report dir failed ({}): {err}",
            report_dir.display()
        )
    })?;

    let mut suite_command = build_suite_command(
        suite_name.as_str(),
        &topology,
        config.ssh_identity_file.as_path(),
        config.nat_profile.as_deref(),
        config.impairment_profile.as_deref(),
        report_dir.as_path(),
    )?;
    if config.dry_run {
        return Ok(suite_command.rendered);
    }

    let status = run_status_with_timeout_passthrough(
        &mut suite_command.command,
        timeout_or_default(config.timeout_secs, DEFAULT_LIVE_LAB_TIMEOUT_SECS),
    )
    .map_err(|err| format!("vm-lab suite run failed: {err}"))?;
    if !status.success() {
        return Err(format!(
            "vm-lab suite run failed with status {} command={}",
            status_code(status),
            suite_command.rendered
        ));
    }
    Ok(format!(
        "ran vm-lab suite={} report_dir={}",
        suite_name,
        report_dir.display()
    ))
}

pub fn execute_ops_vm_lab_bootstrap_phase(
    config: VmLabBootstrapPhaseConfig,
) -> Result<String, String> {
    if config.require_same_network {
        ensure_remote_selection_declares_single_network(
            config.inventory_path.as_path(),
            config.vm_aliases.as_slice(),
            config.select_all,
            config.raw_targets.as_slice(),
        )?;
    }
    let phase = normalized_bootstrap_phase(config.phase.as_str())?;
    let timeout = timeout_or_default(config.timeout_secs, DEFAULT_RUN_TIMEOUT_SECS);
    let targets = resolve_remote_targets(
        config.inventory_path.as_path(),
        config.vm_aliases.as_slice(),
        config.select_all,
        config.raw_targets.as_slice(),
    )?;
    let inventory = load_inventory(config.inventory_path.as_path())?;
    let mut workdirs = BTreeMap::new();
    for target in &targets {
        let inventory_entry = inventory.iter().find(|entry| entry.alias == target.label);
        let workdir = config
            .dest_dir
            .clone()
            .or_else(|| inventory_entry.and_then(|entry| entry.rustynet_src_dir.clone()))
            .ok_or_else(|| {
                format!(
                    "bootstrap phase {} requires --dest-dir or rustynet_src_dir inventory metadata for {}",
                    phase, target.label
                )
            })?;
        workdirs.insert(target.label.clone(), workdir);
    }

    let mut lines = Vec::new();
    if phase == "sync-source" || phase == "all" {
        let sync_dest_dir = workdirs
            .values()
            .next()
            .cloned()
            .ok_or_else(|| "no targets selected for bootstrap phase".to_string())?;
        if workdirs.values().any(|workdir| workdir != &sync_dest_dir) {
            return Err(
                "bootstrap sync-source/all requires a single destination directory across selected targets"
                    .to_string(),
            );
        }
        let sync_source = resolve_repo_sync_source(
            config.repo_url.as_deref(),
            config.local_source_dir.as_deref(),
            config.branch.as_str(),
            config.remote.as_str(),
        )?;
        lines.extend(sync_repo_targets(
            &targets,
            config.ssh_user.as_deref(),
            sync_source,
            sync_dest_dir.as_str(),
            timeout,
        )?);
        if phase == "sync-source" {
            return Ok(lines.join("\n"));
        }
    }

    let phases: &[&str] = if phase == "all" {
        &[
            "build-release",
            "install-release",
            "restart-runtime",
            "verify-runtime",
        ]
    } else {
        &[phase.as_str()]
    };

    for target in &targets {
        let workdir = workdirs
            .get(target.label.as_str())
            .ok_or_else(|| format!("missing bootstrap workdir for {}", target.label))?;
        let effective_user = config.ssh_user.as_deref().or(target.ssh_user.as_deref());
        let context = BootstrapPhaseContext {
            ssh_user: effective_user,
            workdir: workdir.as_str(),
            repo_url: config.repo_url.as_deref(),
            branch: config.branch.as_str(),
            remote: config.remote.as_str(),
            timeout,
        };
        for phase_name in phases {
            execute_bootstrap_phase_for_target(phase_name, target, &context)?;
            lines.push(format!(
                "{} completed bootstrap phase={} workdir={}",
                target.label, phase_name, workdir
            ));
        }
    }

    Ok(lines.join("\n"))
}

fn resolve_start_targets(
    inventory_path: &Path,
    aliases: &[String],
    select_all: bool,
) -> Result<Vec<StartTarget>, String> {
    let inventory = load_inventory(inventory_path)?;
    let chosen = select_inventory_entries(&inventory, aliases, select_all)?;
    let mut results = Vec::new();
    for entry in chosen {
        let Some(controller) = entry.controller else {
            return Err(format!(
                "VM alias {} does not declare a local start controller; only local UTM-backed entries can be started here",
                entry.alias
            ));
        };
        match controller {
            VmController::LocalUtm {
                utm_name,
                bundle_path,
            } => results.push(StartTarget {
                alias: entry.alias,
                utm_name,
                bundle_path,
            }),
        }
    }
    Ok(results)
}

fn resolve_remote_targets(
    inventory_path: &Path,
    aliases: &[String],
    select_all: bool,
    raw_targets: &[String],
) -> Result<Vec<RemoteTarget>, String> {
    let mut resolved = Vec::new();
    let mut seen = HashSet::new();

    if select_all || !aliases.is_empty() {
        let inventory = load_inventory(inventory_path)?;
        for entry in select_inventory_entries(&inventory, aliases, select_all)? {
            let key = format!(
                "{}|{}",
                entry.ssh_user.as_deref().unwrap_or(""),
                entry.ssh_target
            );
            if seen.insert(key) {
                resolved.push(RemoteTarget {
                    label: entry.alias,
                    ssh_target: entry.ssh_target,
                    ssh_user: entry.ssh_user,
                });
            }
        }
    }

    for raw_target in raw_targets {
        ensure_ssh_target("target", raw_target)?;
        let key = format!("|{raw_target}");
        if seen.insert(key) {
            resolved.push(RemoteTarget {
                label: raw_target.clone(),
                ssh_target: raw_target.clone(),
                ssh_user: None,
            });
        }
    }

    if resolved.is_empty() {
        return Err("specify at least one inventory alias/--all or explicit --target".to_string());
    }

    Ok(resolved)
}

fn resolve_role_target(
    inventory_path: &Path,
    role_label: &str,
    alias: Option<&str>,
    raw_target: Option<&str>,
) -> Result<RoleTarget, String> {
    match (alias, raw_target) {
        (Some(_), Some(_)) => Err(format!(
            "{role_label} target must use either --{role_label}-vm or --{role_label}-target, not both"
        )),
        (None, None) => Err(format!(
            "{role_label} target is required; specify --{role_label}-vm or --{role_label}-target"
        )),
        (Some(alias), None) => {
            resolve_role_target_from_inventory(inventory_path, role_label, alias)
        }
        (None, Some(raw_target)) => resolve_role_target_from_raw(role_label, raw_target),
    }
}

fn resolve_optional_role_target(
    inventory_path: &Path,
    role_label: &str,
    alias: Option<&str>,
    raw_target: Option<&str>,
) -> Result<Option<RoleTarget>, String> {
    match (alias, raw_target) {
        (None, None) => Ok(None),
        _ => resolve_role_target(inventory_path, role_label, alias, raw_target).map(Some),
    }
}

fn resolve_role_target_from_inventory(
    inventory_path: &Path,
    role_label: &str,
    alias: &str,
) -> Result<RoleTarget, String> {
    ensure_inventory_alias(alias)?;
    let inventory = load_inventory(inventory_path)?;
    let entry = inventory
        .into_iter()
        .find(|entry| entry.alias == alias)
        .ok_or_else(|| format!("unknown VM alias for {role_label} target: {alias}"))?;
    let normalized_target = normalized_ssh_target(
        entry.ssh_target.as_str(),
        entry.ssh_user.as_deref(),
        role_label,
    )?;
    Ok(RoleTarget {
        label: entry.alias,
        normalized_target,
        network_group: entry.network_group,
    })
}

fn resolve_role_target_from_raw(role_label: &str, raw_target: &str) -> Result<RoleTarget, String> {
    ensure_ssh_target(role_label, raw_target)?;
    if !raw_target.contains('@') {
        return Err(format!(
            "{role_label} raw target must include an explicit SSH user (user@host): {raw_target}"
        ));
    }
    Ok(RoleTarget {
        label: raw_target.to_string(),
        normalized_target: raw_target.to_string(),
        network_group: None,
    })
}

fn normalized_ssh_target(
    ssh_target: &str,
    ssh_user: Option<&str>,
    label: &str,
) -> Result<String, String> {
    ensure_ssh_target(label, ssh_target)?;
    if ssh_target.contains('@') {
        return Ok(ssh_target.to_string());
    }
    let ssh_user = ssh_user.ok_or_else(|| {
        format!(
            "{label} target requires ssh_user metadata because ssh_target lacks user@host form: {ssh_target}"
        )
    })?;
    ensure_ssh_user(ssh_user)?;
    Ok(format!("{ssh_user}@{ssh_target}"))
}

fn select_inventory_entries(
    inventory: &[VmInventoryEntry],
    aliases: &[String],
    select_all: bool,
) -> Result<Vec<VmInventoryEntry>, String> {
    let requested = if select_all {
        inventory
            .iter()
            .map(|entry| entry.alias.clone())
            .collect::<Vec<_>>()
    } else {
        aliases.to_vec()
    };
    if requested.is_empty() {
        return Err("specify at least one --vm alias or use --all".to_string());
    }
    let mut selected = Vec::new();
    let mut seen_aliases = HashSet::new();
    for alias in requested {
        if !seen_aliases.insert(alias.clone()) {
            continue;
        }
        let entry = inventory
            .iter()
            .find(|candidate| candidate.alias == alias)
            .cloned()
            .ok_or_else(|| format!("unknown VM alias: {alias}"))?;
        selected.push(entry);
    }
    Ok(selected)
}

fn ensure_remote_selection_declares_single_network(
    inventory_path: &Path,
    aliases: &[String],
    select_all: bool,
    raw_targets: &[String],
) -> Result<String, String> {
    if !raw_targets.is_empty() {
        return Err(
            "require-same-network only supports inventory-backed targets; raw --target values do not declare network metadata"
                .to_string(),
        );
    }
    let inventory = load_inventory(inventory_path)?;
    let selected = select_inventory_entries(&inventory, aliases, select_all)?;
    ensure_inventory_entries_share_network(selected.as_slice())
}

fn ensure_inventory_entries_share_network(entries: &[VmInventoryEntry]) -> Result<String, String> {
    let mut chosen_group: Option<String> = None;
    for entry in entries {
        let group = entry.network_group.as_deref().ok_or_else(|| {
            format!(
                "VM alias {} is missing network_group metadata required for same-network validation",
                entry.alias
            )
        })?;
        match chosen_group.as_deref() {
            None => chosen_group = Some(group.to_string()),
            Some(existing) if existing == group => {}
            Some(existing) => {
                return Err(format!(
                    "selected VMs span multiple network groups: {} is on {} but expected {}",
                    entry.alias, group, existing
                ));
            }
        }
    }
    chosen_group.ok_or_else(|| "no inventory-backed targets were selected".to_string())
}

fn ensure_role_targets_share_network(targets: &[Option<RoleTarget>]) -> Result<String, String> {
    let mut chosen_group: Option<String> = None;
    for target in targets {
        let Some(target) = target.as_ref() else {
            continue;
        };
        let group = target.network_group.as_deref().ok_or_else(|| {
            format!(
                "target {} is missing inventory-backed network_group metadata required for same-network validation",
                target.label
            )
        })?;
        match chosen_group.as_deref() {
            None => chosen_group = Some(group.to_string()),
            Some(existing) if existing == group => {}
            Some(existing) => {
                return Err(format!(
                    "selected role targets span multiple network groups: {} is on {} but expected {}",
                    target.label, group, existing
                ));
            }
        }
    }
    chosen_group
        .ok_or_else(|| "same-network validation requires at least one resolved target".to_string())
}

fn load_inventory(path: &Path) -> Result<Vec<VmInventoryEntry>, String> {
    let body = fs::read_to_string(path)
        .map_err(|err| format!("read vm inventory failed ({}): {err}", path.display()))?;
    let value = serde_json::from_str::<Value>(body.as_str())
        .map_err(|err| format!("parse vm inventory failed ({}): {err}", path.display()))?;
    let object = value
        .as_object()
        .ok_or_else(|| format!("vm inventory must be a JSON object: {}", path.display()))?;
    let version = object
        .get("version")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            format!(
                "vm inventory is missing numeric version: {}",
                path.display()
            )
        })?;
    if version != 1 {
        return Err(format!(
            "unsupported vm inventory version {} in {}",
            version,
            path.display()
        ));
    }
    let entries = object
        .get("entries")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("vm inventory is missing entries array: {}", path.display()))?;
    if entries.is_empty() {
        return Err(format!("vm inventory has no entries: {}", path.display()));
    }

    let mut parsed = Vec::with_capacity(entries.len());
    let mut seen_aliases = HashSet::new();
    for entry in entries {
        let parsed_entry = parse_inventory_entry(entry)?;
        if !seen_aliases.insert(parsed_entry.alias.clone()) {
            return Err(format!(
                "vm inventory contains duplicate alias: {}",
                parsed_entry.alias
            ));
        }
        parsed.push(parsed_entry);
    }
    Ok(parsed)
}

fn parse_inventory_entry(value: &Value) -> Result<VmInventoryEntry, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "vm inventory entry must be an object".to_string())?;
    let alias = required_string_field(object, "alias")?;
    ensure_inventory_alias(alias.as_str())?;
    let ssh_target = required_string_field(object, "ssh_target")?;
    ensure_ssh_target("ssh_target", ssh_target.as_str())?;
    let ssh_user = optional_string_field(object, "ssh_user")?;
    if let Some(user) = ssh_user.as_deref() {
        ensure_ssh_user(user)?;
    }
    let os = optional_string_field(object, "os")?;
    if let Some(value) = os.as_deref() {
        ensure_no_control_chars("os", value)?;
    }
    let last_known_ip = optional_string_field(object, "last_known_ip")?;
    if let Some(value) = last_known_ip.as_deref() {
        ensure_no_control_chars("last_known_ip", value)?;
    }
    let parent_device = optional_string_field(object, "parent_device")?;
    if let Some(value) = parent_device.as_deref() {
        ensure_no_control_chars("parent_device", value)?;
    }
    let last_known_network = optional_string_field(object, "last_known_network")?;
    if let Some(value) = last_known_network.as_deref() {
        ensure_no_control_chars("last_known_network", value)?;
    }
    let network_group = optional_string_field(object, "network_group")?;
    if let Some(value) = network_group.as_deref() {
        ensure_no_control_chars("network_group", value)?;
    }
    let node_id = optional_string_field(object, "node_id")?;
    if let Some(value) = node_id.as_deref() {
        ensure_inventory_alias(value)?;
    }
    let lab_role = optional_string_field(object, "lab_role")?;
    if let Some(value) = lab_role.as_deref() {
        ensure_inventory_alias(value)?;
    }
    let mesh_ip = optional_string_field(object, "mesh_ip")?;
    if let Some(value) = mesh_ip.as_deref() {
        ensure_no_control_chars("mesh_ip", value)?;
    }
    let exit_capable = optional_bool_field(object, "exit_capable")?;
    let relay_capable = optional_bool_field(object, "relay_capable")?;
    let rustynet_src_dir = optional_string_field(object, "rustynet_src_dir")?;
    if let Some(value) = rustynet_src_dir.as_deref() {
        ensure_no_control_chars("rustynet_src_dir", value)?;
    }
    let controller = match object.get("controller") {
        None | Some(Value::Null) => None,
        Some(value) => Some(parse_controller(value)?),
    };
    Ok(VmInventoryEntry {
        alias,
        ssh_target,
        ssh_user,
        os,
        last_known_ip,
        parent_device,
        last_known_network,
        network_group,
        node_id,
        lab_role,
        mesh_ip,
        exit_capable,
        relay_capable,
        rustynet_src_dir,
        controller,
    })
}

fn parse_controller(value: &Value) -> Result<VmController, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "vm controller must be an object".to_string())?;
    let controller_type = required_string_field(object, "type")?;
    match controller_type.as_str() {
        "local_utm" => {
            let utm_name = required_string_field(object, "utm_name")?;
            ensure_no_control_chars("utm_name", utm_name.as_str())?;
            let bundle_path_raw = required_string_field(object, "bundle_path")?;
            let bundle_path = PathBuf::from(bundle_path_raw.as_str());
            if !bundle_path.is_absolute() {
                return Err(format!(
                    "local_utm bundle_path must be absolute: {}",
                    bundle_path.display()
                ));
            }
            Ok(VmController::LocalUtm {
                utm_name,
                bundle_path,
            })
        }
        _ => Err(format!("unsupported vm controller type: {controller_type}")),
    }
}

fn required_string_field(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<String, String> {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .ok_or_else(|| format!("vm inventory entry is missing string field: {key}"))
}

fn optional_string_field(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<String>, String> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                Ok(None)
            } else {
                Ok(Some(trimmed.to_string()))
            }
        }
        _ => Err(format!(
            "vm inventory field must be a string when present: {key}"
        )),
    }
}

fn optional_bool_field(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<bool>, String> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        _ => Err(format!(
            "vm inventory field must be a boolean when present: {key}"
        )),
    }
}

fn ensure_inventory_alias(value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err("vm alias must not be empty".to_string());
    }
    let allowed = |ch: char| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.');
    if !value.chars().all(allowed) {
        return Err(format!("vm alias contains unsupported characters: {value}"));
    }
    Ok(())
}

fn ensure_ssh_target(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    if value.chars().any(char::is_whitespace) {
        return Err(format!("{label} must not contain whitespace: {value}"));
    }
    ensure_no_control_chars(label, value)
}

fn ensure_ssh_user(value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err("SSH user must not be empty".to_string());
    }
    if value.chars().any(char::is_whitespace) {
        return Err(format!("SSH user must not contain whitespace: {value}"));
    }
    ensure_no_control_chars("SSH user", value)
}

fn build_repo_sync_script(
    repo_url: &str,
    dest_dir: &str,
    branch: &str,
    remote: &str,
) -> Result<String, String> {
    ensure_no_control_chars("repo URL", repo_url)?;
    ensure_no_control_chars("destination directory", dest_dir)?;
    ensure_no_control_chars("branch", branch)?;
    ensure_no_control_chars("remote", remote)?;
    let parent = Path::new(dest_dir)
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or_else(|| format!("destination directory must have a parent: {dest_dir}"))?;
    let parent = parent
        .to_str()
        .ok_or_else(|| format!("destination directory parent is not valid UTF-8: {dest_dir}"))?;
    let dest_git_dir = format!("{dest_dir}/.git");
    Ok(format!(
        "set -eu; mkdir -p {parent}; \
if [ -e {dest_dir} ] && [ ! -d {dest_dir} ]; then \
printf '%s\\n' 'destination path exists but is not a directory: {dest_dir_literal}' >&2; \
exit 1; \
fi; \
if [ -d {dest_dir} ] && [ ! -d {dest_git_dir} ]; then \
backup_path={dest_dir}.prep.$(date -u +%Y%m%dT%H%M%S).$$; \
mv -- {dest_dir} \"$backup_path\"; \
fi; \
if [ -d {dest_git_dir} ]; then \
git -C {dest_dir} remote set-url {remote} {repo_url}; \
git -C {dest_dir} fetch --prune {remote}; \
else \
git clone --origin {remote} --branch {branch} -- {repo_url} {dest_dir}; \
fi; \
git -C {dest_dir} checkout --force {branch}; \
git -C {dest_dir} reset --hard {remote}/{branch}",
        parent = shell_quote(parent),
        dest_git_dir = shell_quote(dest_git_dir.as_str()),
        dest_dir = shell_quote(dest_dir),
        dest_dir_literal = dest_dir,
        remote = shell_quote(remote),
        repo_url = shell_quote(repo_url),
        branch = shell_quote(branch),
    ))
}

fn build_local_source_extract_script(
    dest_dir: &str,
    remote_archive_path: &str,
) -> Result<String, String> {
    ensure_no_control_chars("destination directory", dest_dir)?;
    ensure_no_control_chars("remote archive path", remote_archive_path)?;
    let parent = Path::new(dest_dir)
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or_else(|| format!("destination directory must have a parent: {dest_dir}"))?;
    let parent = parent
        .to_str()
        .ok_or_else(|| format!("destination directory parent is not valid UTF-8: {dest_dir}"))?;
    Ok(format!(
        "set -eu; mkdir -p {parent}; \
if [ -e {dest_dir} ] && [ ! -d {dest_dir} ]; then \
printf '%s\\n' 'destination path exists but is not a directory: {dest_dir_literal}' >&2; \
rm -f -- {remote_archive}; \
exit 1; \
fi; \
if [ -d {dest_dir} ]; then \
backup_path={dest_dir}.prep.$(date -u +%Y%m%dT%H%M%S).$$; \
mv -- {dest_dir} \"$backup_path\"; \
fi; \
mkdir -p {dest_dir}; \
tar -xf {remote_archive} -C {dest_dir}; \
rm -f -- {remote_archive}",
        parent = shell_quote(parent),
        dest_dir = shell_quote(dest_dir),
        dest_dir_literal = dest_dir,
        remote_archive = shell_quote(remote_archive_path),
    ))
}

fn prepare_local_source_archive(
    source_dir: &Path,
    timeout: Duration,
) -> Result<LocalSourceArchive, String> {
    ensure_local_directory_path(source_dir, "local source dir")?;
    let archive_path =
        std::env::temp_dir().join(format!("rustynet-vm-lab-source-{}.tar", unique_suffix()));
    let extras = prepare_local_source_bundle_extras(source_dir, timeout)?;
    if let Err(git_err) =
        write_git_worktree_archive(source_dir, archive_path.as_path(), timeout, extras.as_ref())
    {
        if let Err(raw_err) =
            write_raw_directory_archive(source_dir, archive_path.as_path(), extras.as_ref())
        {
            let _ = fs::remove_file(archive_path.as_path());
            return Err(format!(
                "local source archive failed via git-managed path ({git_err}); raw directory fallback also failed ({raw_err})"
            ));
        }
    }
    Ok(LocalSourceArchive { path: archive_path })
}

fn write_raw_directory_archive(
    source_dir: &Path,
    archive_path: &Path,
    extras: Option<&LocalSourceBundleExtras>,
) -> Result<(), String> {
    let file = fs::File::create(archive_path).map_err(|err| {
        format!(
            "create raw local source archive failed ({}): {err}",
            archive_path.display()
        )
    })?;
    let mut archive = Builder::new(file);
    let mut included = 0usize;
    append_raw_local_source_tree(&mut archive, source_dir, source_dir, &mut included)?;
    append_local_source_bundle_extras(&mut archive, extras, &mut included)?;
    if included == 0 {
        let _ = fs::remove_file(archive_path);
        return Err(format!(
            "local source dir did not yield any syncable files: {}",
            source_dir.display()
        ));
    }
    archive.finish().map_err(|err| {
        format!(
            "finalize raw local source archive failed ({}): {err}",
            archive_path.display()
        )
    })
}

fn write_git_worktree_archive(
    source_dir: &Path,
    archive_path: &Path,
    timeout: Duration,
    extras: Option<&LocalSourceBundleExtras>,
) -> Result<(), String> {
    let mut list_command = Command::new("git");
    list_command.arg("-C").arg(source_dir).args([
        "ls-files",
        "-z",
        "--cached",
        "--others",
        "--exclude-standard",
    ]);
    let output = run_output_with_timeout(&mut list_command, timeout)?;
    if !output.status.success() {
        return Err(format!(
            "collect local source file list failed with status {}",
            status_code(output.status)
        ));
    }

    let mut archive = Builder::new(fs::File::create(archive_path).map_err(|err| {
        format!(
            "create local source archive failed ({}): {err}",
            archive_path.display()
        )
    })?);
    let mut included = 0usize;
    let mut seen = HashSet::new();
    for raw_path in output.stdout.split(|byte| *byte == 0) {
        if raw_path.is_empty() {
            continue;
        }
        let relative = std::str::from_utf8(raw_path)
            .map_err(|err| format!("local source file list contained non-utf8 path: {err}"))?;
        if relative.is_empty() || !seen.insert(relative.to_string()) {
            continue;
        }
        let relative_path = Path::new(relative);
        let absolute_path = source_dir.join(relative_path);
        if !absolute_path.exists() {
            continue;
        }
        archive
            .append_path_with_name(absolute_path.as_path(), relative_path)
            .map_err(|err| {
                format!(
                    "append local source path failed ({}): {err}",
                    relative_path.display()
                )
            })?;
        included += 1;
    }
    append_local_source_bundle_extras(&mut archive, extras, &mut included)?;
    if included == 0 {
        return Err(format!(
            "local source dir did not yield any syncable files: {}",
            source_dir.display()
        ));
    }
    archive.finish().map_err(|err| {
        format!(
            "finalize local source archive failed ({}): {err}",
            archive_path.display()
        )
    })
}

fn prepare_local_source_bundle_extras(
    source_dir: &Path,
    timeout: Duration,
) -> Result<Option<LocalSourceBundleExtras>, String> {
    let manifest_path = source_dir.join("Cargo.toml");
    if !manifest_path.is_file() {
        return Ok(None);
    }

    let temp_root =
        std::env::temp_dir().join(format!("rustynet-vm-lab-bundle-{}", unique_suffix()));
    fs::create_dir_all(temp_root.as_path()).map_err(|err| {
        format!(
            "create local source bundle dir failed ({}): {err}",
            temp_root.display()
        )
    })?;
    let vendor_dir = temp_root.join("vendor");
    let mut command = Command::new("cargo");
    command
        .current_dir(temp_root.as_path())
        .arg("vendor")
        .arg("--locked")
        .arg("--offline")
        .arg("--versioned-dirs")
        .arg("--manifest-path")
        .arg(manifest_path.as_os_str())
        .arg("vendor");
    let output = run_output_with_timeout(&mut command, timeout)?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(output.stderr.as_slice())
            .trim()
            .to_string();
        let _ = fs::remove_dir_all(temp_root.as_path());
        return Err(format!(
            "prepare vendored cargo dependencies failed with status {}{}",
            status_code(output.status),
            if stderr.is_empty() {
                String::new()
            } else {
                format!(": {stderr}")
            }
        ));
    }

    let cargo_config_dir = temp_root.join(".cargo");
    fs::create_dir_all(cargo_config_dir.as_path()).map_err(|err| {
        format!(
            "create vendored cargo config dir failed ({}): {err}",
            cargo_config_dir.display()
        )
    })?;
    let cargo_config_path = cargo_config_dir.join("config.toml");
    let vendor_stdout = String::from_utf8(output.stdout)
        .map_err(|err| format!("vendored cargo config was not valid UTF-8: {err}"))?;
    fs::write(
        cargo_config_path.as_path(),
        build_vendored_cargo_config(vendor_stdout.as_str()).as_bytes(),
    )
    .map_err(|err| {
        format!(
            "write vendored cargo config failed ({}): {err}",
            cargo_config_path.display()
        )
    })?;

    Ok(Some(LocalSourceBundleExtras {
        temp_root,
        vendor_dir: Some(vendor_dir),
        cargo_config_path: Some(cargo_config_path),
    }))
}

fn build_vendored_cargo_config(vendor_stdout: &str) -> String {
    let mut config = vendor_stdout.trim().to_string();
    if !config.ends_with('\n') {
        config.push('\n');
    }
    config.push_str("\n[net]\noffline = true\n");
    config
}

fn append_local_source_bundle_extras(
    archive: &mut Builder<fs::File>,
    extras: Option<&LocalSourceBundleExtras>,
    included: &mut usize,
) -> Result<(), String> {
    let Some(extras) = extras else {
        return Ok(());
    };
    if let Some(vendor_dir) = extras.vendor_dir.as_deref() {
        append_directory_tree_to_archive(archive, vendor_dir, Path::new("vendor"), included)?;
    }
    if let Some(cargo_config_path) = extras.cargo_config_path.as_deref() {
        archive
            .append_path_with_name(cargo_config_path, Path::new(".cargo/config.toml"))
            .map_err(|err| {
                format!(
                    "append vendored cargo config failed ({}): {err}",
                    cargo_config_path.display()
                )
            })?;
        *included += 1;
    }
    Ok(())
}

fn append_raw_local_source_tree(
    archive: &mut Builder<fs::File>,
    source_root: &Path,
    current_dir: &Path,
    included: &mut usize,
) -> Result<(), String> {
    let entries = fs::read_dir(current_dir).map_err(|err| {
        format!(
            "read local source dir failed ({}): {err}",
            current_dir.display()
        )
    })?;
    for entry in entries {
        let entry = entry.map_err(|err| {
            format!(
                "read local source dir entry failed ({}): {err}",
                current_dir.display()
            )
        })?;
        let path = entry.path();
        let relative = path.strip_prefix(source_root).map_err(|err| {
            format!(
                "strip local source prefix failed ({}): {err}",
                path.display()
            )
        })?;
        if should_skip_raw_local_source_path(relative) {
            continue;
        }
        let file_type = entry.file_type().map_err(|err| {
            format!(
                "read local source entry type failed ({}): {err}",
                path.display()
            )
        })?;
        if file_type.is_dir() {
            append_raw_local_source_tree(archive, source_root, path.as_path(), included)?;
            continue;
        }
        archive
            .append_path_with_name(path.as_path(), relative)
            .map_err(|err| {
                format!(
                    "append raw local source path failed ({}): {err}",
                    relative.display()
                )
            })?;
        *included += 1;
    }
    Ok(())
}

fn append_directory_tree_to_archive(
    archive: &mut Builder<fs::File>,
    source_root: &Path,
    archive_root: &Path,
    included: &mut usize,
) -> Result<(), String> {
    let entries = fs::read_dir(source_root).map_err(|err| {
        format!(
            "read archive source dir failed ({}): {err}",
            source_root.display()
        )
    })?;
    for entry in entries {
        let entry = entry.map_err(|err| {
            format!(
                "read archive source dir entry failed ({}): {err}",
                source_root.display()
            )
        })?;
        let path = entry.path();
        let archive_path = archive_root.join(entry.file_name());
        let file_type = entry.file_type().map_err(|err| {
            format!(
                "read archive source entry type failed ({}): {err}",
                path.display()
            )
        })?;
        if file_type.is_dir() {
            append_directory_tree_to_archive(
                archive,
                path.as_path(),
                archive_path.as_path(),
                included,
            )?;
            continue;
        }
        archive
            .append_path_with_name(path.as_path(), archive_path.as_path())
            .map_err(|err| {
                format!(
                    "append archive source path failed ({}): {err}",
                    archive_path.display()
                )
            })?;
        *included += 1;
    }
    Ok(())
}

fn should_skip_raw_local_source_path(relative: &Path) -> bool {
    if relative.file_name().and_then(|name| name.to_str()) == Some(".DS_Store") {
        return true;
    }
    let first = relative.iter().next().and_then(|part| part.to_str());
    matches!(first, Some(".git" | "target" | "artifacts"))
}

fn sync_local_source_archive_to_target(
    archive_path: &Path,
    target: &str,
    ssh_user: Option<&str>,
    dest_dir: &str,
    timeout: Duration,
) -> Result<(), String> {
    ensure_local_regular_file_path(archive_path, "local source archive")?;
    // These guest images accept SFTP writes into the SSH user's home directory
    // reliably, while absolute /tmp uploads are rejected on some hosts.
    let remote_archive = format!(".rn-vm-lab-source-{}.tar", unique_suffix());
    ensure_success_status(
        scp_to_remote(
            archive_path,
            target,
            ssh_user,
            remote_archive.as_str(),
            timeout,
        )?,
        "copy local source archive to remote",
    )?;
    let extract_script = build_local_source_extract_script(dest_dir, remote_archive.as_str())?;
    let status = run_remote_shell_command(target, ssh_user, extract_script.as_str(), timeout)?;
    ensure_success_status(status, "extract local source archive on remote")
}

fn build_remote_argv_script(
    workdir: &str,
    program: &str,
    argv: &[String],
    sudo: bool,
) -> Result<String, String> {
    ensure_no_control_chars("workdir", workdir)?;
    ensure_no_control_chars("program", program)?;
    let mut command = String::new();
    if sudo {
        command.push_str("sudo -n -- ");
    } else {
        command.push_str("exec ");
    }
    command.push_str(shell_quote(program).as_str());
    for arg in argv {
        ensure_no_control_chars("command arg", arg.as_str())?;
        command.push(' ');
        command.push_str(shell_quote(arg.as_str()).as_str());
    }
    if sudo {
        command = format!("exec {command}");
    }
    Ok(format!("set -eu; cd {}; {}", shell_quote(workdir), command))
}

fn run_remote_shell_command(
    target: &str,
    ssh_user: Option<&str>,
    remote_script: &str,
    timeout: Duration,
) -> Result<ExitStatus, String> {
    validate_target_user_combination(target, ssh_user)?;
    let mut command = Command::new("ssh");
    command.args([
        "-n",
        "-o",
        "LogLevel=ERROR",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "ConnectTimeout=15",
        "-o",
        "ServerAliveInterval=20",
        "-o",
        "ServerAliveCountMax=3",
        "-o",
        "IdentitiesOnly=yes",
    ]);
    if let Some(ssh_user) = ssh_user {
        command.arg("-l").arg(ssh_user);
    }
    command.arg("--").arg(target).arg(remote_script);
    run_status_with_timeout(&mut command, timeout)
}

fn capture_remote_shell_command(
    target: &str,
    ssh_user: Option<&str>,
    remote_script: &str,
    timeout: Duration,
) -> Result<String, String> {
    validate_target_user_combination(target, ssh_user)?;
    let mut command = Command::new("ssh");
    command.args([
        "-n",
        "-o",
        "LogLevel=ERROR",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "ConnectTimeout=15",
        "-o",
        "ServerAliveInterval=20",
        "-o",
        "ServerAliveCountMax=3",
        "-o",
        "IdentitiesOnly=yes",
    ]);
    if let Some(ssh_user) = ssh_user {
        command.arg("-l").arg(ssh_user);
    }
    command.arg("--").arg(target).arg(remote_script);
    let output = run_output_with_timeout(&mut command, timeout)?;
    if !output.status.success() {
        return Err(format!(
            "remote command exited with status {}",
            status_code(output.status)
        ));
    }
    String::from_utf8(output.stdout)
        .map_err(|err| format!("remote output was not valid UTF-8: {err}"))
}

fn scp_to_remote(
    src: &Path,
    target: &str,
    ssh_user: Option<&str>,
    dst: &str,
    timeout: Duration,
) -> Result<ExitStatus, String> {
    validate_target_user_combination(target, ssh_user)?;
    ensure_no_control_chars("remote destination path", dst)?;
    let mut command = Command::new("scp");
    command.args([
        "-q",
        "-o",
        "LogLevel=ERROR",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "ConnectTimeout=15",
        "-o",
        "IdentitiesOnly=yes",
    ]);
    if let Some(ssh_user) = ssh_user {
        command.arg("-o").arg(format!("User={ssh_user}"));
    }
    command
        .arg("--")
        .arg(src.as_os_str())
        .arg(format!("{target}:{dst}"));
    run_status_with_timeout(&mut command, timeout)
}

fn run_status_with_timeout(command: &mut Command, timeout: Duration) -> Result<ExitStatus, String> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|err| format!("spawn failed: {err}"))?;
    let started_at = Instant::now();
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|err| format!("wait failed: {err}"))?
        {
            return Ok(status);
        }
        if started_at.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("timed out after {} seconds", timeout.as_secs()));
        }
        thread::sleep(Duration::from_millis(POLL_INTERVAL_MILLIS));
    }
}

fn run_output_with_timeout(
    command: &mut Command,
    timeout: Duration,
) -> Result<std::process::Output, String> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("spawn failed: {err}"))?;
    let started_at = Instant::now();
    loop {
        if child
            .try_wait()
            .map_err(|err| format!("wait failed: {err}"))?
            .is_some()
        {
            return child
                .wait_with_output()
                .map_err(|err| format!("collect output failed: {err}"));
        }
        if started_at.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("timed out after {} seconds", timeout.as_secs()));
        }
        thread::sleep(Duration::from_millis(POLL_INTERVAL_MILLIS));
    }
}

fn run_status_with_timeout_passthrough(
    command: &mut Command,
    timeout: Duration,
) -> Result<ExitStatus, String> {
    let mut child = command
        .spawn()
        .map_err(|err| format!("spawn failed: {err}"))?;
    let started_at = Instant::now();
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|err| format!("wait failed: {err}"))?
        {
            return Ok(status);
        }
        if started_at.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("timed out after {} seconds", timeout.as_secs()));
        }
        thread::sleep(Duration::from_millis(POLL_INTERVAL_MILLIS));
    }
}

fn transition_local_utm_vm(
    utmctl_path: &Path,
    utm_name: &str,
    bundle_path: &Path,
    action: &str,
    expected_process_present: bool,
    timeout: Duration,
) -> Result<(), String> {
    let mut command = Command::new(utmctl_path);
    command.arg(action).arg(utm_name);
    let status = run_status_with_timeout(&mut command, timeout)?;
    if !status.success() {
        return Err(format!(
            "{action} exited with status {}",
            status_code(status)
        ));
    }
    wait_for_local_utm_process_state(bundle_path, expected_process_present, timeout)
}

fn wait_for_local_utm_process_state(
    bundle_path: &Path,
    expected_present: bool,
    timeout: Duration,
) -> Result<(), String> {
    let started_at = Instant::now();
    loop {
        let observed = local_utm_process_present(bundle_path, timeout)?;
        if observed == expected_present {
            return Ok(());
        }
        if started_at.elapsed() >= timeout {
            return Err(format!(
                "timed out waiting for local UTM process presence={} for {}",
                expected_present,
                bundle_path.display()
            ));
        }
        thread::sleep(Duration::from_millis(POLL_INTERVAL_MILLIS));
    }
}

fn local_utm_process_present(bundle_path: &Path, timeout: Duration) -> Result<bool, String> {
    let mut command = Command::new("ps");
    command.args(["ax", "-o", "command"]);
    let output = run_output_with_timeout(&mut command, timeout)?;
    if !output.status.success() {
        return Err(format!(
            "ps exited with status {}",
            status_code(output.status)
        ));
    }
    let ps_output = String::from_utf8(output.stdout)
        .map_err(|err| format!("ps returned non-UTF-8 output: {err}"))?;
    Ok(local_utm_process_present_in_ps_output(
        ps_output.as_str(),
        bundle_path,
    ))
}

fn local_utm_process_present_in_ps_output(ps_output: &str, bundle_path: &Path) -> bool {
    let needle = bundle_path.display().to_string();
    ps_output
        .lines()
        .any(|line| line.contains("QEMULauncher") && line.contains(needle.as_str()))
}

fn timeout_or_default(value: u64, default_secs: u64) -> Duration {
    let secs = if value == 0 { default_secs } else { value };
    Duration::from_secs(secs)
}

fn status_code(status: ExitStatus) -> i32 {
    match status.code() {
        Some(code) => code,
        None => {
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;

                match status.signal() {
                    Some(signal) => 128 + signal,
                    None => 1,
                }
            }
            #[cfg(not(unix))]
            {
                1
            }
        }
    }
}

fn ensure_success_status(status: ExitStatus, label: &str) -> Result<(), String> {
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "{label} failed with status {}",
            status_code(status)
        ))
    }
}

fn ensure_no_control_chars(label: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    if value
        .chars()
        .any(|ch| ch == '\0' || ch == '\n' || ch == '\r')
    {
        return Err(format!("{label} contains unsupported control characters"));
    }
    Ok(())
}

fn ensure_local_regular_file_path(path: &Path, label: &str) -> Result<(), String> {
    let metadata = fs::metadata(path)
        .map_err(|err| format!("{label} metadata read failed ({}): {err}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!(
            "{label} must be a regular file: {}",
            path.display()
        ));
    }
    Ok(())
}

fn ensure_local_directory_path(path: &Path, label: &str) -> Result<(), String> {
    let metadata = fs::metadata(path)
        .map_err(|err| format!("{label} metadata read failed ({}): {err}", path.display()))?;
    if !metadata.is_dir() {
        return Err(format!("{label} must be a directory: {}", path.display()));
    }
    Ok(())
}

fn shell_quote(value: &str) -> String {
    let mut out = String::from("'");
    for ch in value.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

fn validate_target_user_combination(target: &str, ssh_user: Option<&str>) -> Result<(), String> {
    if ssh_user.is_some() && target.contains('@') {
        return Err(format!(
            "explicit SSH user override cannot be combined with user@host target: {target}"
        ));
    }
    Ok(())
}

fn unique_suffix() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

fn sanitize_label_for_path(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "target".to_string()
    } else {
        out
    }
}

fn ssh_target_host(value: &str) -> String {
    let without_user = value
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(value);
    without_user
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(without_user)
        .to_string()
}

fn resolve_known_hosts_targets(
    inventory: &[VmInventoryEntry],
    aliases: &[String],
    select_all: bool,
    raw_targets: &[String],
) -> Result<Vec<KnownHostsTarget>, String> {
    let mut results = Vec::new();
    let mut seen = HashSet::new();
    if select_all || !aliases.is_empty() {
        for entry in select_inventory_entries(inventory, aliases, select_all)? {
            let mut candidates = vec![ssh_target_host(entry.ssh_target.as_str())];
            if let Some(last_known_ip) = entry.last_known_ip.as_deref()
                && !candidates
                    .iter()
                    .any(|candidate| candidate == last_known_ip)
            {
                candidates.push(last_known_ip.to_string());
            }
            if seen.insert(entry.alias.clone()) {
                results.push(KnownHostsTarget {
                    label: entry.alias,
                    host_candidates: candidates,
                });
            }
        }
    }
    for raw_target in raw_targets {
        ensure_ssh_target("target", raw_target)?;
        let label = raw_target.clone();
        if seen.insert(label.clone()) {
            results.push(KnownHostsTarget {
                label,
                host_candidates: vec![ssh_target_host(raw_target)],
            });
        }
    }
    if results.is_empty() {
        return Err("specify at least one inventory alias/--all or explicit --target".to_string());
    }
    Ok(results)
}

fn find_known_hosts_match(path: &Path, candidates: &[String]) -> Result<Option<String>, String> {
    for candidate in candidates {
        let status = Command::new("ssh-keygen")
            .arg("-F")
            .arg(candidate)
            .arg("-f")
            .arg(path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|err| format!("ssh-keygen lookup failed for {candidate}: {err}"))?;
        if status.success() {
            return Ok(Some(candidate.clone()));
        }
    }
    Ok(None)
}

fn build_preflight_script(
    required_commands: &[String],
    _min_free_kib: u64,
    require_rustynet_installed: bool,
) -> Result<String, String> {
    let mut script = String::from(
        "set -eu; \
printf 'hostname=%s\\n' \"$(hostname)\"; \
printf 'os=%s\\n' \"$(uname -srm)\"; \
printf 'free_kib=%s\\n' \"$(df -Pk / | awk 'NR==2 {print $4}')\"; \
if sudo -n true >/dev/null 2>&1; then printf 'sudo_ok=true\\n'; else printf 'sudo_ok=false\\n'; fi; ",
    );
    if require_rustynet_installed {
        script.push_str(
            "if command -v rustynet >/dev/null 2>&1; then printf 'rustynet_installed=true\\n'; else printf 'rustynet_installed=false\\n'; fi; ",
        );
    } else {
        script.push_str("printf 'rustynet_installed=skipped\\n'; ");
    }
    for command_name in required_commands {
        ensure_inventory_alias(command_name)?;
        let _ = write!(
            script,
            "if command -v {cmd} >/dev/null 2>&1; then printf 'cmd.{cmd}=present\\n'; else printf 'cmd.{cmd}=missing\\n'; fi; ",
            cmd = shell_quote(command_name)
        );
    }
    Ok(script)
}

fn privileged_rustynet_cli_script(subcommand: &str) -> String {
    format!(
        "if command -v rustynet >/dev/null 2>&1; then if sudo -n true >/dev/null 2>&1; then sudo -n env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet {subcommand} 2>&1; else RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet {subcommand} 2>&1; fi; else echo rustynet-not-installed; fi"
    )
}

fn parse_key_value_output(output: &str) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    for line in output.lines() {
        if let Some((key, value)) = line.split_once('=') {
            values.insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    values
}

fn build_section_capture_script(sections: &[(&str, &str)]) -> String {
    let mut script = String::from("set +e; ");
    for (name, body) in sections {
        let _ = write!(
            script,
            "printf '%s\\n' '__VM_LAB_SECTION__{name}'; {{ {body}; }} 2>&1 || true; printf '%s\\n' '__VM_LAB_SECTION_END__'; "
        );
    }
    script
}

fn parse_section_capture(output: &str) -> BTreeMap<String, String> {
    let mut sections = BTreeMap::new();
    let mut current_name: Option<String> = None;
    let mut current_body = String::new();
    for line in output.lines() {
        if let Some(name) = line.strip_prefix("__VM_LAB_SECTION__") {
            current_name = Some(name.to_string());
            current_body.clear();
            continue;
        }
        if line == "__VM_LAB_SECTION_END__" {
            if let Some(name) = current_name.take() {
                sections.insert(name, current_body.trim_end().to_string());
            }
            current_body.clear();
            continue;
        }
        if current_name.is_some() {
            current_body.push_str(line);
            current_body.push('\n');
        }
    }
    sections
}

fn normalized_suite_name(value: &str) -> Result<String, String> {
    let normalized = value.trim().to_ascii_lowercase().replace('_', "-");
    match normalized.as_str() {
        "direct-remote-exit" | "relay-remote-exit" | "failback-roaming" | "full-live-lab" => {
            Ok(normalized)
        }
        _ => Err(format!(
            "unsupported vm-lab suite: {value} (expected direct-remote-exit|relay-remote-exit|failback-roaming|full-live-lab)"
        )),
    }
}

fn build_vm_lab_topology(entries: &[VmInventoryEntry], suite: &str) -> Result<Value, String> {
    let suite_name = normalized_suite_name(suite)?;
    let mut roles = BTreeMap::new();
    let mut nodes = Vec::new();
    for entry in entries {
        let normalized_target = normalized_ssh_target(
            entry.ssh_target.as_str(),
            entry.ssh_user.as_deref(),
            entry.alias.as_str(),
        )?;
        let node_id = entry.node_id.clone().ok_or_else(|| {
            format!(
                "inventory entry {} is missing node_id required for topology generation",
                entry.alias
            )
        })?;
        let lab_role = entry.lab_role.clone().ok_or_else(|| {
            format!(
                "inventory entry {} is missing lab_role required for topology generation",
                entry.alias
            )
        })?;
        let network_id = entry
            .network_group
            .clone()
            .or_else(|| entry.last_known_network.clone())
            .ok_or_else(|| {
                format!(
                    "inventory entry {} is missing network_group/last_known_network required for topology generation",
                    entry.alias
                )
            })?;
        if roles
            .insert(lab_role.clone(), entry.alias.clone())
            .is_some()
        {
            return Err(format!(
                "multiple selected entries declare lab_role={lab_role}; topology roles must be unique"
            ));
        }
        nodes.push(json!({
            "alias": entry.alias,
            "normalized_target": normalized_target,
            "node_id": node_id,
            "lab_role": lab_role,
            "network_id": network_id,
            "mesh_ip": entry.mesh_ip,
            "last_known_ip": entry.last_known_ip,
            "exit_capable": entry.exit_capable.unwrap_or(false),
            "relay_capable": entry.relay_capable.unwrap_or(false),
            "rustynet_src_dir": entry.rustynet_src_dir,
        }));
    }

    let topology = json!({
        "version": 1,
        "generated_at_unix": SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
        "suite": suite_name,
        "roles": roles,
        "nodes": nodes,
    });
    let parsed = parse_vm_lab_topology(topology.clone())?;
    validate_vm_lab_topology(&parsed)?;
    Ok(topology)
}

fn load_vm_lab_topology(path: &Path) -> Result<VmLabTopology, String> {
    let body = fs::read_to_string(path)
        .map_err(|err| format!("read vm-lab topology failed ({}): {err}", path.display()))?;
    let value = serde_json::from_str::<Value>(body.as_str())
        .map_err(|err| format!("parse vm-lab topology failed ({}): {err}", path.display()))?;
    let topology = parse_vm_lab_topology(value)?;
    validate_vm_lab_topology(&topology)?;
    Ok(topology)
}

fn parse_vm_lab_topology(value: Value) -> Result<VmLabTopology, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "vm-lab topology must be a JSON object".to_string())?;
    let version = object
        .get("version")
        .and_then(Value::as_u64)
        .ok_or_else(|| "vm-lab topology is missing numeric version".to_string())?;
    if version != 1 {
        return Err(format!("unsupported vm-lab topology version: {version}"));
    }
    let suite = object
        .get("suite")
        .and_then(Value::as_str)
        .ok_or_else(|| "vm-lab topology is missing suite".to_string())?
        .to_string();
    let suite = normalized_suite_name(suite.as_str())?;
    let roles_object = object
        .get("roles")
        .and_then(Value::as_object)
        .ok_or_else(|| "vm-lab topology is missing roles object".to_string())?;
    let mut roles = BTreeMap::new();
    for (key, value) in roles_object {
        let alias = value
            .as_str()
            .ok_or_else(|| format!("vm-lab topology role {key} must be a string alias"))?;
        roles.insert(key.clone(), alias.to_string());
    }
    let node_array = object
        .get("nodes")
        .and_then(Value::as_array)
        .ok_or_else(|| "vm-lab topology is missing nodes array".to_string())?;
    let mut nodes = BTreeMap::new();
    for node_value in node_array {
        let node_object = node_value
            .as_object()
            .ok_or_else(|| "vm-lab topology node must be an object".to_string())?;
        let alias = required_string_field(node_object, "alias")?;
        let normalized_target = required_string_field(node_object, "normalized_target")?;
        let node_id = required_string_field(node_object, "node_id")?;
        let lab_role = required_string_field(node_object, "lab_role")?;
        let network_id = required_string_field(node_object, "network_id")?;
        let mesh_ip = optional_string_field(node_object, "mesh_ip")?;
        let last_known_ip = optional_string_field(node_object, "last_known_ip")?;
        let exit_capable = optional_bool_field(node_object, "exit_capable")?.unwrap_or(false);
        let relay_capable = optional_bool_field(node_object, "relay_capable")?.unwrap_or(false);
        let rustynet_src_dir = optional_string_field(node_object, "rustynet_src_dir")?;
        nodes.insert(
            alias.clone(),
            VmLabTopologyNode {
                alias,
                normalized_target,
                node_id,
                lab_role,
                network_id,
                mesh_ip,
                last_known_ip,
                exit_capable,
                relay_capable,
                rustynet_src_dir,
            },
        );
    }
    Ok(VmLabTopology {
        suite,
        roles,
        nodes,
    })
}

fn validate_vm_lab_topology(topology: &VmLabTopology) -> Result<(), String> {
    match topology.suite.as_str() {
        "direct-remote-exit" => {
            let client = topology_role_node(topology, &["client"])?;
            let exit = topology_role_node(topology, &["exit"])?;
            ensure_distinct_topology_networks([client, exit].as_slice())?;
        }
        "relay-remote-exit" | "failback-roaming" => {
            let client = topology_role_node(topology, &["client"])?;
            let exit = topology_role_node(topology, &["exit"])?;
            let relay = topology_role_node(topology, &["relay", "entry"])?;
            ensure_distinct_topology_networks([client, exit, relay].as_slice())?;
        }
        "full-live-lab" => {
            let _ = topology_role_node(topology, &["client"])?;
            let _ = topology_role_node(topology, &["exit"])?;
            let _ = topology_role_node(topology, &["entry", "relay"])?;
            let _ = topology_role_node(topology, &["aux"])?;
        }
        _ => {}
    }
    Ok(())
}

fn topology_role_node<'a>(
    topology: &'a VmLabTopology,
    role_candidates: &[&str],
) -> Result<&'a VmLabTopologyNode, String> {
    for role in role_candidates {
        if let Some(alias) = topology.roles.get(*role) {
            return topology.nodes.get(alias).ok_or_else(|| {
                format!("vm-lab topology role {role} points to missing alias {alias}")
            });
        }
    }
    Err(format!(
        "vm-lab topology is missing required role; expected one of {}",
        role_candidates.join(", ")
    ))
}

fn topology_optional_role_node<'a>(
    topology: &'a VmLabTopology,
    role_candidates: &[&str],
) -> Result<Option<&'a VmLabTopologyNode>, String> {
    for role in role_candidates {
        if let Some(alias) = topology.roles.get(*role) {
            return topology.nodes.get(alias).map(Some).ok_or_else(|| {
                format!("vm-lab topology role {role} points to missing alias {alias}")
            });
        }
    }
    Ok(None)
}

fn ensure_distinct_topology_networks(nodes: &[&VmLabTopologyNode]) -> Result<(), String> {
    let mut seen = HashSet::new();
    for node in nodes {
        if !seen.insert(node.network_id.clone()) {
            return Err(format!(
                "suite {} requires distinct network_id values but duplicate network {} was found",
                nodes
                    .first()
                    .map(|_| "cross-network")
                    .unwrap_or("cross-network"),
                node.network_id
            ));
        }
    }
    Ok(())
}

fn build_nodes_spec(
    nodes: &[&VmLabTopologyNode],
    inventory: &[VmInventoryEntry],
    timeout: Duration,
    ssh_user_override: Option<&str>,
) -> Result<String, String> {
    let mut parts = Vec::new();
    for node in nodes {
        let inventory_entry = inventory
            .iter()
            .find(|entry| entry.alias == node.alias)
            .cloned()
            .ok_or_else(|| format!("topology alias missing from inventory: {}", node.alias))?;
        let target = RemoteTarget {
            label: inventory_entry.alias.clone(),
            ssh_target: inventory_entry.ssh_target.clone(),
            ssh_user: ssh_user_override
                .map(ToString::to_string)
                .or(inventory_entry.ssh_user.clone()),
        };
        let pubkey_hex = collect_public_key_hex_for_target(&target, timeout)?;
        let underlay_ip = node
            .last_known_ip
            .clone()
            .or_else(|| {
                let host = ssh_target_host(node.normalized_target.as_str());
                host.parse::<IpAddr>().ok().map(|_| host)
            })
            .ok_or_else(|| {
                format!(
                    "node {} is missing last_known_ip and its SSH target is not a literal IP; cannot build authoritative NODES_SPEC endpoint",
                    node.alias
                )
            })?;
        parts.push(format!(
            "{}|{}:51820|{}",
            node.node_id, underlay_ip, pubkey_hex
        ));
    }
    Ok(parts.join(";"))
}

fn collect_public_key_hex_for_target(
    target: &RemoteTarget,
    timeout: Duration,
) -> Result<String, String> {
    let output = capture_remote_shell_command(
        target.ssh_target.as_str(),
        target.ssh_user.as_deref(),
        "set -eu; if sudo -n true >/dev/null 2>&1; then sudo -n cat /var/lib/rustynet/keys/wireguard.pub; else cat /var/lib/rustynet/keys/wireguard.pub; fi",
        timeout,
    )
    .map_err(|err| format!("collect pubkey failed for {}: {err}", target.label))?;
    decode_wireguard_pubkey_to_hex(output.trim())
        .map_err(|err| format!("decode pubkey failed for {}: {err}", target.label))
}

fn decode_wireguard_pubkey_to_hex(value: &str) -> Result<String, String> {
    let decoded = BASE64_STANDARD
        .decode(value.as_bytes())
        .map_err(|err| format!("base64 decode failed: {err}"))?;
    if decoded.len() != 32 {
        return Err(format!(
            "expected 32-byte WireGuard public key, got {} bytes",
            decoded.len()
        ));
    }
    let mut out = String::with_capacity(decoded.len() * 2);
    for byte in decoded {
        let _ = write!(out, "{byte:02x}");
    }
    Ok(out)
}

fn build_allow_spec(nodes: &[&VmLabTopologyNode]) -> String {
    let mut pairs = Vec::new();
    for source in nodes {
        for target in nodes {
            if source.node_id != target.node_id {
                pairs.push(format!("{}|{}", source.node_id, target.node_id));
            }
        }
    }
    pairs.join(";")
}

fn build_assignments_spec(topology: &VmLabTopology) -> Result<String, String> {
    let mut assignments = Vec::new();
    for node in topology.nodes.values() {
        let upstream = assignment_exit_node_id(topology, node.alias.as_str())?;
        assignments.push(format!(
            "{}|{}",
            node.node_id,
            upstream.as_deref().unwrap_or("-")
        ));
    }
    Ok(assignments.join(";"))
}

fn assignment_exit_node_id(
    topology: &VmLabTopology,
    alias: &str,
) -> Result<Option<String>, String> {
    let node = topology
        .nodes
        .get(alias)
        .ok_or_else(|| format!("vm-lab topology alias not found: {alias}"))?;
    let exit = topology_optional_role_node(topology, &["exit"])?;
    let relay = topology_optional_role_node(topology, &["relay", "entry"])?;
    match node.lab_role.as_str() {
        "exit" => Ok(None),
        "relay" | "entry" => Ok(exit.map(|node| node.node_id.clone())),
        "client" | "aux" | "extra" | "fifth_client" | "probe" => Ok(relay
            .map(|node| node.node_id.clone())
            .or_else(|| exit.map(|node| node.node_id.clone()))),
        _ => Ok(exit.map(|node| node.node_id.clone())),
    }
}

fn build_assignment_issue_env(
    nodes_spec: &str,
    allow_spec: &str,
    assignments_spec: &str,
) -> Result<String, String> {
    let lines = [
        format_env_assignment("NODES_SPEC", nodes_spec)?,
        format_env_assignment("ALLOW_SPEC", allow_spec)?,
        format_env_assignment("ASSIGNMENTS_SPEC", assignments_spec)?,
        String::new(),
    ];
    Ok(lines.join("\n"))
}

fn build_traversal_issue_env(
    nodes_spec: &str,
    allow_spec: &str,
    traversal_ttl_secs: u64,
) -> Result<String, String> {
    let lines = [
        format_env_assignment("NODES_SPEC", nodes_spec)?,
        format_env_assignment("ALLOW_SPEC", allow_spec)?,
        format_env_assignment(
            "TRAVERSAL_TTL_SECS",
            traversal_ttl_secs.to_string().as_str(),
        )?,
        String::new(),
    ];
    Ok(lines.join("\n"))
}

fn build_assignment_refresh_env(
    target_node_id: &str,
    nodes_spec: &str,
    allow_spec: &str,
    exit_node_id: Option<String>,
) -> Result<String, String> {
    let mut lines = vec![
        format_env_assignment("RUSTYNET_ASSIGNMENT_TARGET_NODE_ID", target_node_id)?,
        format_env_assignment("RUSTYNET_ASSIGNMENT_NODES", nodes_spec)?,
        format_env_assignment("RUSTYNET_ASSIGNMENT_ALLOW", allow_spec)?,
        format_env_assignment(
            "RUSTYNET_ASSIGNMENT_SIGNING_SECRET",
            "/etc/rustynet/assignment.signing.secret",
        )?,
        format_env_assignment(
            "RUSTYNET_ASSIGNMENT_SIGNING_SECRET_PASSPHRASE_FILE",
            "/run/credentials/rustynetd-assignment-refresh.service/signing_key_passphrase",
        )?,
        format_env_assignment("RUSTYNET_ASSIGNMENT_TTL_SECS", "300")?,
        format_env_assignment("RUSTYNET_ASSIGNMENT_MIN_REMAINING_SECS", "180")?,
    ];
    if let Some(exit_node_id) = exit_node_id {
        lines.push(format_env_assignment(
            "RUSTYNET_ASSIGNMENT_EXIT_NODE_ID",
            exit_node_id.as_str(),
        )?);
    }
    lines.push(String::new());
    Ok(lines.join("\n"))
}

fn capture_remote_file_to_local(
    target: &str,
    ssh_user: Option<&str>,
    remote_path: &str,
    local_path: &Path,
    timeout: Duration,
) -> Result<(), String> {
    let output = capture_remote_shell_command(
        target,
        ssh_user,
        format!(
            "set -eu; if sudo -n true >/dev/null 2>&1; then sudo -n cat {}; else cat {}; fi",
            shell_quote(remote_path),
            shell_quote(remote_path)
        )
        .as_str(),
        timeout,
    )?;
    fs::write(local_path, output.as_bytes()).map_err(|err| {
        format!(
            "write local capture failed ({}): {err}",
            local_path.display()
        )
    })
}

fn install_state_artifacts_on_target(
    target: &RemoteTarget,
    assignment_pub: &Path,
    assignment_bundle: &Path,
    traversal_pub: &Path,
    traversal_bundle: &Path,
    refresh_env: &Path,
    timeout: Duration,
) -> Result<(), String> {
    ensure_success_status(
        scp_to_remote(
            assignment_pub,
            target.ssh_target.as_str(),
            target.ssh_user.as_deref(),
            "/tmp/rn-assignment.pub",
            timeout,
        )?,
        "copy assignment verifier to remote",
    )?;
    ensure_success_status(
        scp_to_remote(
            assignment_bundle,
            target.ssh_target.as_str(),
            target.ssh_user.as_deref(),
            "/tmp/rn-assignment.bundle",
            timeout,
        )?,
        "copy assignment bundle to remote",
    )?;
    ensure_success_status(
        scp_to_remote(
            traversal_pub,
            target.ssh_target.as_str(),
            target.ssh_user.as_deref(),
            "/tmp/rn-traversal.pub",
            timeout,
        )?,
        "copy traversal verifier to remote",
    )?;
    ensure_success_status(
        scp_to_remote(
            traversal_bundle,
            target.ssh_target.as_str(),
            target.ssh_user.as_deref(),
            "/tmp/rn-traversal.bundle",
            timeout,
        )?,
        "copy traversal bundle to remote",
    )?;
    ensure_success_status(
        scp_to_remote(
            refresh_env,
            target.ssh_target.as_str(),
            target.ssh_user.as_deref(),
            "/tmp/rn-assignment-refresh.env",
            timeout,
        )?,
        "copy assignment refresh env to remote",
    )?;
    let install_script = "set -eu; \
if sudo -n true >/dev/null 2>&1; then SUDO='sudo -n'; else SUDO=''; fi; \
$SUDO install -m 0644 -o root -g root /tmp/rn-assignment.pub /etc/rustynet/assignment.pub; \
$SUDO install -m 0640 -o root -g rustynetd /tmp/rn-assignment.bundle /var/lib/rustynet/rustynetd.assignment; \
$SUDO rm -f /var/lib/rustynet/rustynetd.assignment.watermark; \
$SUDO install -m 0644 -o root -g root /tmp/rn-traversal.pub /etc/rustynet/traversal.pub; \
$SUDO install -m 0640 -o root -g rustynetd /tmp/rn-traversal.bundle /var/lib/rustynet/rustynetd.traversal; \
$SUDO rm -f /var/lib/rustynet/rustynetd.traversal.watermark; \
$SUDO install -m 0600 -o root -g root /tmp/rn-assignment-refresh.env /etc/rustynet/assignment-refresh.env; \
$SUDO rm -f /tmp/rn-assignment.pub /tmp/rn-assignment.bundle /tmp/rn-traversal.pub /tmp/rn-traversal.bundle /tmp/rn-assignment-refresh.env";
    let status = run_remote_shell_command(
        target.ssh_target.as_str(),
        target.ssh_user.as_deref(),
        install_script,
        timeout,
    )
    .map_err(|err| format!("install state artifacts failed for {}: {err}", target.label))?;
    if !status.success() {
        return Err(format!(
            "install state artifacts failed for {} with status {}",
            target.label,
            status_code(status)
        ));
    }
    Ok(())
}

fn build_suite_command(
    suite: &str,
    topology: &VmLabTopology,
    ssh_identity_file: &Path,
    nat_profile: Option<&str>,
    impairment_profile: Option<&str>,
    report_dir: &Path,
) -> Result<SuiteCommand, String> {
    let nat_profile = nat_profile.unwrap_or("baseline_lan");
    let impairment_profile = impairment_profile.unwrap_or("none");
    let mut command = Command::new("bash");
    let rendered = match suite {
        "direct-remote-exit" => {
            let script = default_cross_network_direct_script_path();
            let client = topology_role_node(topology, &["client"])?;
            let exit = topology_role_node(topology, &["exit"])?;
            let report_path = report_dir.join("cross_network_direct_remote_exit_report.json");
            let log_path = report_dir.join("cross_network_direct_remote_exit.log");
            command
                .arg(script.as_path())
                .arg("--ssh-identity-file")
                .arg(ssh_identity_file)
                .arg("--client-host")
                .arg(client.normalized_target.as_str())
                .arg("--exit-host")
                .arg(exit.normalized_target.as_str())
                .arg("--client-node-id")
                .arg(client.node_id.as_str())
                .arg("--exit-node-id")
                .arg(exit.node_id.as_str())
                .arg("--client-network-id")
                .arg(client.network_id.as_str())
                .arg("--exit-network-id")
                .arg(exit.network_id.as_str())
                .arg("--nat-profile")
                .arg(nat_profile)
                .arg("--impairment-profile")
                .arg(impairment_profile)
                .arg("--report-path")
                .arg(report_path.as_path())
                .arg("--log-path")
                .arg(log_path.as_path());
            render_command_for_display(&command)
        }
        "relay-remote-exit" => {
            let script = default_cross_network_relay_script_path();
            let client = topology_role_node(topology, &["client"])?;
            let exit = topology_role_node(topology, &["exit"])?;
            let relay = topology_role_node(topology, &["relay", "entry"])?;
            let report_path = report_dir.join("cross_network_relay_remote_exit_report.json");
            let log_path = report_dir.join("cross_network_relay_remote_exit.log");
            command
                .arg(script.as_path())
                .arg("--ssh-identity-file")
                .arg(ssh_identity_file)
                .arg("--client-host")
                .arg(client.normalized_target.as_str())
                .arg("--exit-host")
                .arg(exit.normalized_target.as_str())
                .arg("--relay-host")
                .arg(relay.normalized_target.as_str())
                .arg("--client-node-id")
                .arg(client.node_id.as_str())
                .arg("--exit-node-id")
                .arg(exit.node_id.as_str())
                .arg("--relay-node-id")
                .arg(relay.node_id.as_str())
                .arg("--client-network-id")
                .arg(client.network_id.as_str())
                .arg("--exit-network-id")
                .arg(exit.network_id.as_str())
                .arg("--relay-network-id")
                .arg(relay.network_id.as_str())
                .arg("--nat-profile")
                .arg(nat_profile)
                .arg("--impairment-profile")
                .arg(impairment_profile)
                .arg("--report-path")
                .arg(report_path.as_path())
                .arg("--log-path")
                .arg(log_path.as_path());
            render_command_for_display(&command)
        }
        "failback-roaming" => {
            let script = default_cross_network_failback_script_path();
            let client = topology_role_node(topology, &["client"])?;
            let exit = topology_role_node(topology, &["exit"])?;
            let relay = topology_role_node(topology, &["relay", "entry"])?;
            let report_path = report_dir.join("cross_network_failback_roaming_report.json");
            let log_path = report_dir.join("cross_network_failback_roaming.log");
            command
                .arg(script.as_path())
                .arg("--ssh-identity-file")
                .arg(ssh_identity_file)
                .arg("--client-host")
                .arg(client.normalized_target.as_str())
                .arg("--exit-host")
                .arg(exit.normalized_target.as_str())
                .arg("--relay-host")
                .arg(relay.normalized_target.as_str())
                .arg("--client-node-id")
                .arg(client.node_id.as_str())
                .arg("--exit-node-id")
                .arg(exit.node_id.as_str())
                .arg("--relay-node-id")
                .arg(relay.node_id.as_str())
                .arg("--client-network-id")
                .arg(client.network_id.as_str())
                .arg("--exit-network-id")
                .arg(exit.network_id.as_str())
                .arg("--relay-network-id")
                .arg(relay.network_id.as_str())
                .arg("--nat-profile")
                .arg(nat_profile)
                .arg("--impairment-profile")
                .arg(impairment_profile)
                .arg("--report-path")
                .arg(report_path.as_path())
                .arg("--log-path")
                .arg(log_path.as_path());
            render_command_for_display(&command)
        }
        "full-live-lab" => {
            let script = default_live_lab_orchestrator_path();
            let exit = topology_role_node(topology, &["exit"])?;
            let client = topology_role_node(topology, &["client"])?;
            let entry = topology_role_node(topology, &["entry", "relay"])?;
            let aux = topology_role_node(topology, &["aux"])?;
            let extra = topology_optional_role_node(topology, &["extra"])?;
            let fifth_client = topology_optional_role_node(topology, &["fifth_client"])?;
            let profile_path = report_dir.join("vm_lab_live_lab.env");
            let mut lines = vec![
                format_env_assignment("EXIT_TARGET", exit.normalized_target.as_str())?,
                format_env_assignment("CLIENT_TARGET", client.normalized_target.as_str())?,
                format_env_assignment("ENTRY_TARGET", entry.normalized_target.as_str())?,
                format_env_assignment("AUX_TARGET", aux.normalized_target.as_str())?,
                format_env_assignment(
                    "SSH_IDENTITY_FILE",
                    ssh_identity_file.display().to_string().as_str(),
                )?,
            ];
            if let Some(extra) = extra {
                lines.push(format_env_assignment(
                    "EXTRA_TARGET",
                    extra.normalized_target.as_str(),
                )?);
            }
            if let Some(fifth_client) = fifth_client {
                lines.push(format_env_assignment(
                    "FIFTH_CLIENT_TARGET",
                    fifth_client.normalized_target.as_str(),
                )?);
            }
            lines.push(format_env_assignment("SOURCE_MODE", "local-head")?);
            lines.push(format_env_assignment(
                "REPORT_DIR",
                report_dir.display().to_string().as_str(),
            )?);
            lines.push(String::new());
            fs::write(profile_path.as_path(), lines.join("\n")).map_err(|err| {
                format!(
                    "write full live-lab profile failed ({}): {err}",
                    profile_path.display()
                )
            })?;
            command
                .arg(script.as_path())
                .arg("--profile")
                .arg(profile_path.as_path());
            render_command_for_display(&command)
        }
        _ => return Err(format!("unsupported vm-lab suite command: {suite}")),
    };
    Ok(SuiteCommand { command, rendered })
}

fn render_command_for_display(command: &Command) -> String {
    let mut rendered = String::new();
    rendered.push_str(command.get_program().to_string_lossy().as_ref());
    for arg in command.get_args() {
        rendered.push(' ');
        rendered.push_str(shell_quote(arg.to_string_lossy().as_ref()).as_str());
    }
    rendered
}

fn normalized_bootstrap_phase(value: &str) -> Result<String, String> {
    let normalized = value.trim().to_ascii_lowercase().replace('_', "-");
    match normalized.as_str() {
        "sync-source" | "build-release" | "install-release" | "restart-runtime"
        | "verify-runtime" | "all" => Ok(normalized),
        _ => Err(format!(
            "unsupported vm-lab bootstrap phase: {value} (expected sync-source|build-release|install-release|restart-runtime|verify-runtime|all)"
        )),
    }
}

struct BootstrapPhaseContext<'a> {
    ssh_user: Option<&'a str>,
    workdir: &'a str,
    repo_url: Option<&'a str>,
    branch: &'a str,
    remote: &'a str,
    timeout: Duration,
}

fn execute_bootstrap_phase_for_target(
    phase: &str,
    target: &RemoteTarget,
    context: &BootstrapPhaseContext<'_>,
) -> Result<(), String> {
    match phase {
        "sync-source" => {
            let repo_url = context.repo_url.ok_or_else(|| {
                format!(
                    "bootstrap phase sync-source requires --repo-url for {}",
                    target.label
                )
            })?;
            let status = run_remote_shell_command(
                target.ssh_target.as_str(),
                context.ssh_user,
                build_repo_sync_script(repo_url, context.workdir, context.branch, context.remote)?
                    .as_str(),
                context.timeout,
            )
            .map_err(|err| format!("sync-source failed for {}: {err}", target.label))?;
            if !status.success() {
                return Err(format!(
                    "sync-source failed for {} with status {}",
                    target.label,
                    status_code(status)
                ));
            }
        }
        "build-release" => {
            let tmpdir = format!("{}/.tmp", context.workdir);
            let status = run_remote_shell_command(
                target.ssh_target.as_str(),
                context.ssh_user,
                format!(
                    "set -eu; cd {workdir}; mkdir -p {tmpdir}; TMPDIR={tmpdir} exec cargo build --locked --release -p rustynetd -p rustynet-cli",
                    workdir = shell_quote(context.workdir),
                    tmpdir = shell_quote(tmpdir.as_str()),
                )
                .as_str(),
                context.timeout,
            )
            .map_err(|err| format!("build-release failed for {}: {err}", target.label))?;
            if !status.success() {
                return Err(format!(
                    "build-release failed for {} with status {}",
                    target.label,
                    status_code(status)
                ));
            }
        }
        "install-release" => {
            let script = format!(
                "set -eu; cd {workdir}; \
if sudo -n true >/dev/null 2>&1; then SUDO='sudo -n'; else SUDO=''; fi; \
$SUDO install -m 0755 target/release/rustynetd /usr/local/bin/rustynetd; \
$SUDO install -m 0755 target/release/rustynet-cli /usr/local/bin/rustynet",
                workdir = shell_quote(context.workdir),
            );
            let status = run_remote_shell_command(
                target.ssh_target.as_str(),
                context.ssh_user,
                script.as_str(),
                context.timeout,
            )
            .map_err(|err| format!("install-release failed for {}: {err}", target.label))?;
            if !status.success() {
                return Err(format!(
                    "install-release failed for {} with status {}",
                    target.label,
                    status_code(status)
                ));
            }
        }
        "restart-runtime" => {
            let status = run_remote_shell_command(
                target.ssh_target.as_str(),
                context.ssh_user,
                "set -eu; if sudo -n true >/dev/null 2>&1; then sudo -n systemctl restart rustynetd.service; else systemctl restart rustynetd.service; fi",
                context.timeout,
            )
            .map_err(|err| format!("restart-runtime failed for {}: {err}", target.label))?;
            if !status.success() {
                return Err(format!(
                    "restart-runtime failed for {} with status {}",
                    target.label,
                    status_code(status)
                ));
            }
        }
        "verify-runtime" => {
            let status_script = privileged_rustynet_cli_script("status");
            let netcheck_script = privileged_rustynet_cli_script("netcheck");
            let status = run_remote_shell_command(
                target.ssh_target.as_str(),
                context.ssh_user,
                format!("set -eu; {status_script} >/dev/null; {netcheck_script} >/dev/null")
                    .as_str(),
                context.timeout,
            )
            .map_err(|err| format!("verify-runtime failed for {}: {err}", target.label))?;
            if !status.success() {
                return Err(format!(
                    "verify-runtime failed for {} with status {}",
                    target.label,
                    status_code(status)
                ));
            }
        }
        "all" => {
            execute_bootstrap_phase_for_target("sync-source", target, context)?;
            execute_bootstrap_phase_for_target("build-release", target, context)?;
            execute_bootstrap_phase_for_target("install-release", target, context)?;
            execute_bootstrap_phase_for_target("restart-runtime", target, context)?;
            execute_bootstrap_phase_for_target("verify-runtime", target, context)?;
        }
        _ => {
            return Err(format!(
                "unsupported bootstrap phase for execution: {phase}"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        LiveLabProfile, LiveLabStageSummary, VmLabIterationValidationStep,
        VmLabValidateLiveLabProfileConfig, VmLabWriteLiveLabProfileConfig,
        build_assignment_refresh_env, build_local_source_extract_script, build_remote_argv_script,
        build_repo_sync_script, build_suite_command, build_vendored_cargo_config,
        build_vm_lab_topology, default_inventory_path, default_live_lab_iteration_profile_path,
        default_live_lab_iteration_report_dir, default_live_lab_orchestrator_path,
        default_utmctl_path, ensure_inventory_entries_share_network,
        execute_ops_vm_lab_diff_live_lab_runs, execute_ops_vm_lab_validate_live_lab_profile,
        execute_ops_vm_lab_write_live_lab_profile, load_inventory, load_live_lab_profile,
        local_utm_process_present_in_ps_output, parse_live_lab_stage_records,
        parse_vm_lab_iteration_validation_step_spec, parse_vm_lab_topology,
        privileged_rustynet_cli_script, render_live_lab_iteration_summary,
        resolve_iteration_source_selection, resolve_remote_targets, resolve_repo_sync_source,
        resolve_start_targets, summarize_live_lab_report,
    };
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn write_temp_inventory(body: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be valid")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rustynet-vm-lab-{unique}.dir"));
        fs::create_dir_all(&dir).expect("temp dir should exist");
        let path = dir.join("inventory.json");
        fs::write(&path, body).expect("inventory should be written");
        path
    }

    fn cleanup_temp_inventory(path: &Path) {
        if let Some(parent) = path.parent() {
            let _ = fs::remove_dir_all(parent);
        }
    }

    fn write_temp_report_dir() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be valid")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rustynet-live-lab-report-{unique}.dir"));
        fs::create_dir_all(dir.join("state")).expect("state dir should exist");
        fs::create_dir_all(dir.join("logs")).expect("logs dir should exist");
        dir
    }

    fn write_temp_live_lab_profile(body: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be valid")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rustynet-live-lab-profile-{unique}.dir"));
        fs::create_dir_all(&dir).expect("temp dir should exist");
        let identity = dir.join("id_ed25519");
        fs::write(&identity, "dummy-key").expect("identity file should write");
        let known_hosts = dir.join("known_hosts");
        fs::write(&known_hosts, "example ssh-ed25519 AAAA\n").expect("known hosts should write");
        let profile_path = dir.join("profile.env");
        let rendered = body
            .replace("$IDENTITY_FILE", identity.display().to_string().as_str())
            .replace(
                "$KNOWN_HOSTS_FILE",
                known_hosts.display().to_string().as_str(),
            );
        fs::write(&profile_path, rendered).expect("profile should write");
        profile_path
    }

    #[test]
    fn default_utmctl_path_matches_expected_bundle_location() {
        assert_eq!(
            default_utmctl_path().display().to_string(),
            "/Applications/UTM.app/Contents/MacOS/utmctl"
        );
    }

    #[test]
    fn default_inventory_path_targets_repo_inventory_file() {
        assert!(
            default_inventory_path()
                .display()
                .to_string()
                .ends_with("documents/operations/active/vm_lab_inventory.json")
        );
    }

    #[test]
    fn default_live_lab_orchestrator_path_targets_repo_script() {
        assert!(
            default_live_lab_orchestrator_path()
                .display()
                .to_string()
                .ends_with("scripts/e2e/live_linux_lab_orchestrator.sh")
        );
    }

    #[test]
    fn load_inventory_accepts_local_and_remote_entries() {
        let path = write_temp_inventory(
            r#"{
  "version": 1,
  "entries": [
    {
      "alias": "debian-headless-1",
      "ssh_target": "debian-headless-1",
      "ssh_user": "debian",
      "os": "Debian/Linux",
      "last_known_ip": "192.168.64.20",
      "parent_device": "iwan's MacBook Air",
      "last_known_network": "utm-shared-192.168.64.0/24",
      "network_group": "utm-shared-192.168.64.0/24",
      "controller": {
        "type": "local_utm",
        "utm_name": "debian headless 1",
        "bundle_path": "/Users/example/Library/Containers/com.utmapp.UTM/Data/Documents/debian headless 1.utm"
      }
    },
    {
      "alias": "remote-debian-1",
      "ssh_target": "debian@192.168.18.51"
    }
  ]
}"#,
        );
        let inventory = load_inventory(path.as_path()).expect("inventory should load");
        assert_eq!(inventory.len(), 2);
        assert_eq!(inventory[0].alias, "debian-headless-1");
        assert_eq!(
            inventory[0].network_group.as_deref(),
            Some("utm-shared-192.168.64.0/24")
        );
        assert_eq!(inventory[1].ssh_target, "debian@192.168.18.51");
        cleanup_temp_inventory(path.as_path());
    }

    #[test]
    fn load_inventory_parses_role_and_capability_metadata() {
        let path = write_temp_inventory(
            r#"{
  "version": 1,
  "entries": [
    {
      "alias": "exit-vm",
      "ssh_target": "exit-host",
      "ssh_user": "debian",
      "node_id": "exit-1",
      "lab_role": "exit",
      "mesh_ip": "100.64.0.1",
      "exit_capable": true,
      "relay_capable": false,
      "rustynet_src_dir": "/home/debian/Rustynet"
    }
  ]
}"#,
        );
        let inventory = load_inventory(path.as_path()).expect("inventory should load");
        assert_eq!(inventory[0].node_id.as_deref(), Some("exit-1"));
        assert_eq!(inventory[0].lab_role.as_deref(), Some("exit"));
        assert_eq!(inventory[0].mesh_ip.as_deref(), Some("100.64.0.1"));
        assert_eq!(inventory[0].exit_capable, Some(true));
        assert_eq!(inventory[0].relay_capable, Some(false));
        assert_eq!(
            inventory[0].rustynet_src_dir.as_deref(),
            Some("/home/debian/Rustynet")
        );
        cleanup_temp_inventory(path.as_path());
    }

    #[test]
    fn resolve_remote_targets_supports_inventory_aliases_and_raw_targets() {
        let path = write_temp_inventory(
            r#"{
  "version": 1,
  "entries": [
    {
      "alias": "debian-headless-1",
      "ssh_target": "debian-headless-1",
      "ssh_user": "debian"
    },
    {
      "alias": "remote-debian-1",
      "ssh_target": "debian@192.168.18.51"
    }
  ]
}"#,
        );
        let targets = resolve_remote_targets(
            path.as_path(),
            &["debian-headless-1".to_string()],
            false,
            &["root@192.168.18.52".to_string()],
        )
        .expect("targets should resolve");
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].label, "debian-headless-1");
        assert_eq!(targets[0].ssh_user.as_deref(), Some("debian"));
        assert_eq!(targets[1].ssh_target, "root@192.168.18.52");
        cleanup_temp_inventory(path.as_path());
    }

    #[test]
    fn resolve_start_targets_rejects_non_local_entries() {
        let path = write_temp_inventory(
            r#"{
  "version": 1,
  "entries": [
    {
      "alias": "remote-debian-1",
      "ssh_target": "debian@192.168.18.51"
    }
  ]
}"#,
        );
        let err = resolve_start_targets(path.as_path(), &["remote-debian-1".to_string()], false)
            .expect_err("remote-only entries must not start locally");
        assert!(err.contains("does not declare a local start controller"));
        cleanup_temp_inventory(path.as_path());
    }

    #[test]
    fn repo_sync_script_is_deterministic_and_quoted() {
        let script = build_repo_sync_script(
            "git@github.com:iwanteague/Rustyfin.git",
            "/home/debian/Rustyfin",
            "main",
            "origin",
        )
        .expect("sync script should build");
        assert!(script.contains("git clone --origin 'origin' --branch 'main'"));
        assert!(script.contains("git -C '/home/debian/Rustyfin' reset --hard 'origin'/'main'"));
        assert!(script.contains("'git@github.com:iwanteague/Rustyfin.git'"));
        assert!(script.contains(
            "if [ -d '/home/debian/Rustyfin' ] && [ ! -d '/home/debian/Rustyfin/.git' ]; then"
        ));
        assert!(
            script
                .contains("backup_path='/home/debian/Rustyfin'.prep.$(date -u +%Y%m%dT%H%M%S).$$;")
        );
        assert!(script.contains("mv -- '/home/debian/Rustyfin' \"$backup_path\";"));
    }

    #[test]
    fn local_source_extract_script_is_deterministic_and_quoted() {
        let script = build_local_source_extract_script(
            "/home/debian/Rustynet.offline",
            "/tmp/rn-vm-lab-source-123.tar",
        )
        .expect("extract script should build");
        assert!(script.contains(
            "tar -xf '/tmp/rn-vm-lab-source-123.tar' -C '/home/debian/Rustynet.offline';"
        ));
        assert!(script.contains("mv -- '/home/debian/Rustynet.offline' \"$backup_path\";"));
        assert!(script.contains("rm -f -- '/tmp/rn-vm-lab-source-123.tar'"));
    }

    #[test]
    fn resolve_repo_sync_source_rejects_ambiguous_inputs() {
        let err = resolve_repo_sync_source(
            Some("https://example.invalid/repo.git"),
            Some(Path::new("/tmp")),
            "main",
            "origin",
        )
        .expect_err("sync source must reject ambiguous configuration");
        assert!(err.contains("either --repo-url or --local-source-dir"));
    }

    #[test]
    fn vendored_cargo_config_enforces_offline_mode() {
        let config = build_vendored_cargo_config(
            r#"[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
"#,
        );
        assert!(config.contains(r#"directory = "vendor""#));
        assert!(config.contains("[net]\noffline = true"));
    }

    #[test]
    fn bootstrap_script_quotes_arguments_and_sudo() {
        let script = build_remote_argv_script(
            "/home/debian/Rustyfin",
            "cargo",
            &["build".to_string(), "--release".to_string()],
            true,
        )
        .expect("run script should build");
        assert!(script.starts_with("set -eu; cd '/home/debian/Rustyfin'; exec sudo -n -- 'cargo'"));
        assert!(script.contains("'build' '--release'"));
    }

    #[test]
    fn bootstrap_script_rejects_control_characters() {
        let err = build_remote_argv_script(
            "/home/debian/Rustyfin",
            "cargo",
            &["bad\narg".to_string()],
            false,
        )
        .expect_err("control characters must fail");
        assert!(err.contains("unsupported control characters"));
    }

    #[test]
    fn privileged_rustynet_cli_script_uses_sudo_env_when_available() {
        let script = privileged_rustynet_cli_script("status");
        assert!(script.contains(
            "sudo -n env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet status"
        ));
        assert!(
            script.contains(
                "RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet status 2>&1"
            )
        );
    }

    #[test]
    fn same_network_validation_rejects_mixed_groups() {
        let path = write_temp_inventory(
            r#"{
  "version": 1,
  "entries": [
    {
      "alias": "vm-a",
      "ssh_target": "debian@192.168.18.51",
      "network_group": "lan-a"
    },
    {
      "alias": "vm-b",
      "ssh_target": "debian@192.168.64.20",
      "network_group": "lan-b"
    }
  ]
}"#,
        );
        let inventory = load_inventory(path.as_path()).expect("inventory should load");
        let err = ensure_inventory_entries_share_network(inventory.as_slice())
            .expect_err("mixed groups must fail");
        assert!(err.contains("multiple network groups"));
        cleanup_temp_inventory(path.as_path());
    }

    #[test]
    fn live_lab_profile_writer_renders_inventory_backed_targets() {
        let inventory = write_temp_inventory(
            r#"{
  "version": 1,
  "entries": [
    {
      "alias": "exit-vm",
      "ssh_target": "exit-host",
      "ssh_user": "debian",
      "network_group": "lan-a"
    },
    {
      "alias": "client-vm",
      "ssh_target": "client-host",
      "ssh_user": "debian",
      "network_group": "lan-a"
    }
  ]
}"#,
        );
        let output = inventory
            .parent()
            .expect("inventory temp parent")
            .join("live_lab.env");
        let identity = inventory
            .parent()
            .expect("inventory temp parent")
            .join("id_ed25519");
        let known_hosts = inventory
            .parent()
            .expect("inventory temp parent")
            .join("known_hosts");
        fs::write(&identity, "dummy-key").expect("identity should be written");
        fs::write(&known_hosts, "example ssh-ed25519 AAAA").expect("known_hosts should be written");

        let result = execute_ops_vm_lab_write_live_lab_profile(VmLabWriteLiveLabProfileConfig {
            inventory_path: inventory.clone(),
            output_path: output.clone(),
            exit_vm: Some("exit-vm".to_string()),
            exit_target: None,
            client_vm: Some("client-vm".to_string()),
            client_target: None,
            entry_vm: None,
            entry_target: None,
            aux_vm: None,
            aux_target: None,
            extra_vm: None,
            extra_target: None,
            fifth_client_vm: None,
            fifth_client_target: None,
            require_same_network: true,
            ssh_identity_file: identity.clone(),
            ssh_known_hosts_file: Some(known_hosts.clone()),
            ssh_allow_cidrs: Some("192.168.18.0/24".to_string()),
            network_id: Some("vm-lab".to_string()),
            traversal_ttl_secs: Some(120),
            cross_network_nat_profiles: None,
            cross_network_required_nat_profiles: None,
            cross_network_impairment_profile: None,
            backend: Some("linux-wireguard-userspace-shared".to_string()),
            source_mode: Some("local-head".to_string()),
            repo_ref: Some("HEAD".to_string()),
            report_dir: None,
        })
        .expect("profile should be written");
        assert!(result.contains("wrote live-lab profile"));
        let body = fs::read_to_string(&output).expect("profile should be readable");
        assert!(body.contains("EXIT_TARGET=\"debian@exit-host\""));
        assert!(body.contains("CLIENT_TARGET=\"debian@client-host\""));
        assert!(body.contains("SSH_IDENTITY_FILE="));
        assert!(body.contains("RUSTYNET_BACKEND=\"linux-wireguard-userspace-shared\""));
        assert!(body.contains("SOURCE_MODE=\"local-head\""));
        cleanup_temp_inventory(inventory.as_path());
    }

    #[test]
    fn parse_validation_step_supports_fmt_and_package_specs() {
        assert_eq!(
            parse_vm_lab_iteration_validation_step_spec("fmt").expect("fmt should parse"),
            VmLabIterationValidationStep::FmtCheck
        );
        assert_eq!(
            parse_vm_lab_iteration_validation_step_spec("check:rustynetd")
                .expect("check package should parse"),
            VmLabIterationValidationStep::CargoCheckPackage {
                package: "rustynetd".to_string()
            }
        );
        assert_eq!(
            parse_vm_lab_iteration_validation_step_spec(
                "test-bin:rustynet-cli:live_linux_lan_toggle_test:lan_toggle"
            )
            .expect("test bin should parse"),
            VmLabIterationValidationStep::CargoTestBin {
                package: "rustynet-cli".to_string(),
                bin: "live_linux_lan_toggle_test".to_string(),
                filter: Some("lan_toggle".to_string())
            }
        );
    }

    #[test]
    fn parse_validation_step_rejects_unsupported_specs() {
        let err = parse_vm_lab_iteration_validation_step_spec("cargo test -p rustynetd")
            .expect_err("generic shell-like specs must fail");
        assert!(err.contains("unsupported validation step"));
    }

    #[test]
    fn iteration_default_paths_target_live_lab_roots() {
        let profile_path = default_live_lab_iteration_profile_path();
        let report_dir = default_live_lab_iteration_report_dir();
        assert!(
            profile_path
                .display()
                .to_string()
                .contains("profiles/live_lab/")
        );
        assert!(profile_path.display().to_string().ends_with(".env"));
        assert!(
            report_dir
                .display()
                .to_string()
                .contains("artifacts/live_lab/")
        );
        assert!(report_dir.display().to_string().contains("iteration_"));
    }

    #[test]
    fn summarize_live_lab_report_extracts_first_failed_stage_and_log_tail() {
        let report_dir = write_temp_report_dir();
        let log_path = report_dir.join("logs/enforce_baseline_runtime.log");
        fs::write(
            report_dir.join("state/stages.tsv"),
            format!(
                "preflight\thard\tpass\t0\t{}/logs/preflight.log\tverify local prerequisites\t2026-04-03T20:00:00Z\t2026-04-03T20:00:01Z\n\
enforce_baseline_runtime\thard\tfail\t1\t{}/logs/enforce_baseline_runtime.log\tenforce baseline runtime\t2026-04-03T20:10:00Z\t2026-04-03T20:10:05Z\n",
                report_dir.display(),
                report_dir.display()
            ),
        )
        .expect("stages should write");
        fs::write(
            &log_path,
            "[stage:enforce_baseline_runtime] START\nstatus okay\nerror: daemon is in restricted-safe mode\nfinal detail\n",
        )
        .expect("log should write");
        fs::write(report_dir.join("failure_digest.md"), "# digest\n").expect("digest should write");

        let summary =
            summarize_live_lab_report(report_dir.as_path(), true, 2).expect("summary should build");
        assert_eq!(summary.overall_status, "fail");
        assert_eq!(
            summary.first_failed_stage.as_deref(),
            Some("enforce_baseline_runtime")
        );
        assert_eq!(summary.key_log_path.as_deref(), Some(log_path.as_path()));
        assert_eq!(
            summary.likely_reason.as_deref(),
            Some("error: daemon is in restricted-safe mode")
        );
        assert_eq!(
            summary.failed_log_tail.as_deref(),
            Some("error: daemon is in restricted-safe mode\nfinal detail")
        );

        let rendered = render_live_lab_iteration_summary(
            Path::new("/tmp/profile.env"),
            report_dir.as_path(),
            "wrote live-lab profile=/tmp/profile.env",
            &summary,
        );
        assert!(rendered.contains("first_failed_stage=enforce_baseline_runtime"));
        assert!(rendered.contains("key_report_path="));
        assert!(rendered.contains("diagnostic_log_tail<<EOF"));

        let _ = fs::remove_dir_all(report_dir);
    }

    #[test]
    fn summarize_live_lab_report_handles_success_without_failed_stage() {
        let report_dir = write_temp_report_dir();
        fs::write(
            report_dir.join("state/stages.tsv"),
            format!(
                "preflight\thard\tpass\t0\t{}/logs/preflight.log\tverify local prerequisites\t2026-04-03T20:00:00Z\t2026-04-03T20:00:01Z\n",
                report_dir.display()
            ),
        )
        .expect("stages should write");
        fs::write(report_dir.join("failure_digest.md"), "# digest\n").expect("digest should write");

        let summary = summarize_live_lab_report(report_dir.as_path(), false, 5)
            .expect("summary should build");
        assert_eq!(
            summary,
            LiveLabStageSummary {
                overall_status: "pass".to_string(),
                first_failed_stage: None,
                key_report_path: report_dir.join("failure_digest.md"),
                key_log_path: None,
                likely_reason: None,
                failed_log_tail: None,
            }
        );

        let _ = fs::remove_dir_all(report_dir);
    }

    #[test]
    fn live_lab_profile_loader_parses_targets_and_metadata() {
        let profile_path = write_temp_live_lab_profile(
            "# Generated by test\n\
EXIT_TARGET=\"debian@exit-host\"\n\
CLIENT_TARGET=\"debian@client-host\"\n\
ENTRY_TARGET=\"debian@entry-host\"\n\
AUX_TARGET=\"debian@aux-host\"\n\
EXTRA_TARGET=\"debian@extra-host\"\n\
SSH_IDENTITY_FILE=\"$IDENTITY_FILE\"\n\
SSH_KNOWN_HOSTS_FILE=\"$KNOWN_HOSTS_FILE\"\n\
RUSTYNET_BACKEND=\"linux-wireguard-userspace-shared\"\n\
SOURCE_MODE=\"working-tree\"\n\
REPORT_DIR=\"artifacts/live_lab/test\"\n",
        );

        let profile = load_live_lab_profile(profile_path.as_path()).expect("profile should parse");
        assert_eq!(
            profile,
            LiveLabProfile {
                values: BTreeMap::from([
                    ("AUX_TARGET".to_string(), "debian@aux-host".to_string()),
                    (
                        "CLIENT_TARGET".to_string(),
                        "debian@client-host".to_string()
                    ),
                    ("ENTRY_TARGET".to_string(), "debian@entry-host".to_string()),
                    ("EXIT_TARGET".to_string(), "debian@exit-host".to_string()),
                    ("EXTRA_TARGET".to_string(), "debian@extra-host".to_string()),
                    (
                        "REPORT_DIR".to_string(),
                        "artifacts/live_lab/test".to_string()
                    ),
                    (
                        "RUSTYNET_BACKEND".to_string(),
                        "linux-wireguard-userspace-shared".to_string()
                    ),
                    ("SOURCE_MODE".to_string(), "working-tree".to_string()),
                    (
                        "SSH_IDENTITY_FILE".to_string(),
                        profile_path
                            .parent()
                            .expect("profile parent should exist")
                            .join("id_ed25519")
                            .display()
                            .to_string()
                    ),
                    (
                        "SSH_KNOWN_HOSTS_FILE".to_string(),
                        profile_path
                            .parent()
                            .expect("profile parent should exist")
                            .join("known_hosts")
                            .display()
                            .to_string()
                    ),
                ]),
            }
        );
        let targets = profile.configured_targets().expect("targets should render");
        assert_eq!(targets.len(), 5);
        assert_eq!(targets[0].role, "exit");
        assert_eq!(targets[1].role, "client");

        let _ = fs::remove_dir_all(profile_path.parent().expect("profile dir should exist"));
    }

    #[test]
    fn live_lab_profile_loader_rejects_duplicate_keys() {
        let profile_path = write_temp_live_lab_profile(
            "EXIT_TARGET=\"debian@exit-host\"\n\
CLIENT_TARGET=\"debian@client-host\"\n\
SSH_IDENTITY_FILE=\"$IDENTITY_FILE\"\n\
EXIT_TARGET=\"debian@other-exit\"\n",
        );
        let err = load_live_lab_profile(profile_path.as_path()).expect_err("duplicates must fail");
        assert!(err.contains("duplicate live-lab profile key EXIT_TARGET"));
        let _ = fs::remove_dir_all(profile_path.parent().expect("profile dir should exist"));
    }

    #[test]
    fn validate_live_lab_profile_enforces_five_node_and_backend() {
        let profile_path = write_temp_live_lab_profile(
            "EXIT_TARGET=\"debian@exit-host\"\n\
CLIENT_TARGET=\"debian@client-host\"\n\
ENTRY_TARGET=\"debian@entry-host\"\n\
AUX_TARGET=\"debian@aux-host\"\n\
EXTRA_TARGET=\"debian@extra-host\"\n\
SSH_IDENTITY_FILE=\"$IDENTITY_FILE\"\n\
SSH_KNOWN_HOSTS_FILE=\"$KNOWN_HOSTS_FILE\"\n\
RUSTYNET_BACKEND=\"linux-wireguard-userspace-shared\"\n\
SOURCE_MODE=\"local-head\"\n\
REPO_REF=\"HEAD\"\n",
        );
        let summary =
            execute_ops_vm_lab_validate_live_lab_profile(VmLabValidateLiveLabProfileConfig {
                profile_path: profile_path.clone(),
                expected_backend: Some("linux-wireguard-userspace-shared".to_string()),
                expected_source_mode: Some("local-head".to_string()),
                require_five_node: true,
            })
            .expect("validation should pass");
        assert!(summary.contains("target.entry=debian@entry-host"));
        assert!(summary.contains("target.extra=debian@extra-host"));
        let _ = fs::remove_dir_all(profile_path.parent().expect("profile dir should exist"));
    }

    #[test]
    fn parse_live_lab_stage_records_preserves_stage_order_and_status() {
        let report_dir = write_temp_report_dir();
        fs::write(
            report_dir.join("state/stages.tsv"),
            format!(
                "preflight\thard\tpass\t0\t{}/logs/preflight.log\tverify local prerequisites\t2026-04-03T20:00:00Z\t2026-04-03T20:00:01Z\n\
live_two_hop\thard\tfail\t1\t{}/logs/live_two_hop.log\trun live two-hop validation\t2026-04-03T20:10:00Z\t2026-04-03T20:10:05Z\n",
                report_dir.display(),
                report_dir.display()
            ),
        )
        .expect("stages should write");
        let stages =
            parse_live_lab_stage_records(report_dir.as_path()).expect("stages should parse");
        assert_eq!(stages.len(), 2);
        assert_eq!(stages[1].name, "live_two_hop");
        assert_eq!(stages[1].status, "fail");
        assert!(
            stages[1]
                .log_path
                .display()
                .to_string()
                .ends_with("live_two_hop.log")
        );
        let _ = fs::remove_dir_all(report_dir);
    }

    #[test]
    fn diff_live_lab_runs_reports_first_divergent_stage() {
        let old_report_dir = write_temp_report_dir();
        let new_report_dir = write_temp_report_dir();
        fs::write(
            old_report_dir.join("state/stages.tsv"),
            format!(
                "preflight\thard\tpass\t0\t{}/logs/preflight.log\tverify local prerequisites\t2026-04-03T20:00:00Z\t2026-04-03T20:00:01Z\n\
live_two_hop\thard\tfail\t1\t{}/logs/live_two_hop.log\trun live two-hop validation\t2026-04-03T20:10:00Z\t2026-04-03T20:10:05Z\n",
                old_report_dir.display(),
                old_report_dir.display()
            ),
        )
        .expect("old stages should write");
        fs::write(
            new_report_dir.join("state/stages.tsv"),
            format!(
                "preflight\thard\tpass\t0\t{}/logs/preflight.log\tverify local prerequisites\t2026-04-03T20:00:00Z\t2026-04-03T20:00:01Z\n\
live_two_hop\thard\tpass\t0\t{}/logs/live_two_hop.log\trun live two-hop validation\t2026-04-03T20:10:00Z\t2026-04-03T20:10:05Z\n\
live_lan_toggle\thard\tfail\t1\t{}/logs/live_lan_toggle.log\trun LAN access toggle validation\t2026-04-03T20:12:00Z\t2026-04-03T20:12:05Z\n",
                new_report_dir.display(),
                new_report_dir.display(),
                new_report_dir.display()
            ),
        )
        .expect("new stages should write");
        fs::write(old_report_dir.join("failure_digest.md"), "# digest\n")
            .expect("old digest should write");
        fs::write(new_report_dir.join("failure_digest.md"), "# digest\n")
            .expect("new digest should write");
        fs::write(
            old_report_dir.join("logs/live_two_hop.log"),
            "error: old failure\n",
        )
        .expect("old log should write");
        fs::write(
            new_report_dir.join("logs/live_lan_toggle.log"),
            "error: new failure\n",
        )
        .expect("new log should write");

        let diff = execute_ops_vm_lab_diff_live_lab_runs(super::VmLabDiffLiveLabRunsConfig {
            old_report_dir: old_report_dir.clone(),
            new_report_dir: new_report_dir.clone(),
        })
        .expect("diff should pass");
        assert!(diff.contains("first_divergent_stage=live_two_hop"));
        assert!(diff.contains("stage_change=live_two_hop:fail:1 -> pass:0"));
        assert!(diff.contains("new_first_failed_stage=live_lan_toggle"));

        let _ = fs::remove_dir_all(old_report_dir);
        let _ = fs::remove_dir_all(new_report_dir);
    }

    #[test]
    fn resolve_iteration_source_selection_enforces_local_head_and_clean_tree() {
        let resolved = resolve_iteration_source_selection(None, None, false, true, false)
            .expect("local-head guard should resolve");
        assert_eq!(
            resolved,
            ("local-head".to_string(), Some("HEAD".to_string()))
        );

        let err =
            resolve_iteration_source_selection(Some("working-tree"), None, false, true, false)
                .expect_err("non-local-head source mode must fail");
        assert!(err.contains("--require-local-head"));

        let err = resolve_iteration_source_selection(None, None, true, false, true)
            .expect_err("dirty tree must fail");
        assert!(err.contains("git worktree must be clean"));
    }

    #[test]
    fn build_vm_lab_topology_requires_cross_network_roles() {
        let path = write_temp_inventory(
            r#"{
  "version": 1,
  "entries": [
    {
      "alias": "exit-vm",
      "ssh_target": "exit-host",
      "ssh_user": "debian",
      "node_id": "exit-1",
      "lab_role": "exit",
      "network_group": "net-a"
    },
    {
      "alias": "client-vm",
      "ssh_target": "client-host",
      "ssh_user": "debian",
      "node_id": "client-1",
      "lab_role": "client",
      "network_group": "net-b"
    },
    {
      "alias": "relay-vm",
      "ssh_target": "relay-host",
      "ssh_user": "debian",
      "node_id": "relay-1",
      "lab_role": "relay",
      "network_group": "net-c"
    }
  ]
}"#,
        );
        let inventory = load_inventory(path.as_path()).expect("inventory should load");
        let topology = build_vm_lab_topology(inventory.as_slice(), "relay-remote-exit")
            .expect("topology should build");
        let parsed = parse_vm_lab_topology(topology).expect("topology should parse");
        assert_eq!(
            parsed.roles.get("client").map(String::as_str),
            Some("client-vm")
        );
        assert_eq!(
            parsed.roles.get("relay").map(String::as_str),
            Some("relay-vm")
        );
        cleanup_temp_inventory(path.as_path());
    }

    #[test]
    fn local_utm_process_present_parser_matches_qemu_bundle_path() {
        let bundle = Path::new(
            "/Users/example/Library/Containers/com.utmapp.UTM/Data/Documents/debian headless 1.utm",
        );
        let ps_output = "\
123 /Applications/UTM.app/Contents/XPCServices/QEMUHelper.xpc/Contents/MacOS/QEMULauncher /Applications/UTM.app/Contents/Frameworks/qemu-aarch64-softmmu.framework/Versions/A/qemu-aarch64-softmmu -name debian headless 1 -drive if=pflash,file=/Users/example/Library/Containers/com.utmapp.UTM/Data/Documents/debian headless 1.utm/Data/efi_vars.fd
456 /usr/libexec/other-process
";
        assert!(local_utm_process_present_in_ps_output(ps_output, bundle));
        assert!(!local_utm_process_present_in_ps_output(
            "789 /usr/libexec/other-process\n",
            bundle
        ));
    }

    #[test]
    fn assignment_refresh_env_includes_exit_node_when_present() {
        let env = build_assignment_refresh_env(
            "client-1",
            "client-1|192.168.1.20:51820|abcd;exit-1|192.168.1.10:51820|def0",
            "client-1|exit-1;exit-1|client-1",
            Some("exit-1".to_string()),
        )
        .expect("env should build");
        assert!(env.contains("RUSTYNET_ASSIGNMENT_EXIT_NODE_ID=\"exit-1\""));
        assert!(env.contains("RUSTYNET_ASSIGNMENT_TARGET_NODE_ID=\"client-1\""));
    }

    #[test]
    fn build_suite_command_renders_direct_suite_arguments() {
        let topology = parse_vm_lab_topology(json!({
            "version": 1,
            "suite": "direct-remote-exit",
            "roles": {
                "exit": "exit-vm",
                "client": "client-vm"
            },
            "nodes": [
                {
                    "alias": "exit-vm",
                    "normalized_target": "debian@exit-host",
                    "node_id": "exit-1",
                    "lab_role": "exit",
                    "network_id": "net-a",
                    "exit_capable": true,
                    "relay_capable": false
                },
                {
                    "alias": "client-vm",
                    "normalized_target": "debian@client-host",
                    "node_id": "client-1",
                    "lab_role": "client",
                    "network_id": "net-b",
                    "exit_capable": false,
                    "relay_capable": false
                }
            ]
        }))
        .expect("topology should parse");
        let command = build_suite_command(
            "direct-remote-exit",
            &topology,
            Path::new("/Users/iwanteague/.ssh/rustynet_lab_ed25519"),
            Some("baseline_lan"),
            Some("none"),
            Path::new("/tmp/vm-lab-report"),
        )
        .expect("suite command should build");
        assert!(
            command
                .rendered
                .contains("live_linux_cross_network_direct_remote_exit_test.sh")
        );
        assert!(command.rendered.contains("--client-host"));
        assert!(command.rendered.contains("debian@client-host"));
        assert!(command.rendered.contains("--exit-network-id"));
    }
}
