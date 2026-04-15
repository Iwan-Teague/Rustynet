#![forbid(unsafe_code)]

mod bootstrap;

use std::collections::{BTreeMap, HashSet};
use std::fmt::Write as _;
use std::fs;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::env_file::{format_env_assignment, parse_env_value};
use crate::live_lab_results::{LiveLabWorkerResult, read_parallel_stage_results};
use base64::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tar::Builder;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

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
const DEFAULT_UTM_IP_DISCOVERY_TIMEOUT_SECS: u64 = 5;
const DEFAULT_RESTART_READY_TIMEOUT_SECS: u64 = 300;
const DEFAULT_ARTIFACT_ROOT: &str = "artifacts/vm_lab";
const DEFAULT_LIVE_LAB_PROFILE_ROOT: &str = "profiles/live_lab";
const DEFAULT_LIVE_LAB_REPORT_ROOT: &str = "artifacts/live_lab";
const WINDOWS_BOOTSTRAP_HELPER_ROOT: &str = "scripts/bootstrap/windows";
const WINDOWS_COMPAT_VM_LAB_HELPER_ROOT: &str = "scripts/vm_lab/windows";
const WINDOWS_BOOTSTRAP_HELPER_FILE: &str = "Bootstrap-RustyNetWindows.ps1";
const WINDOWS_BOOTSTRAP_WINGET_CONFIG_FILE: &str = "RustyNetBootstrap.winget.yml";
const WINDOWS_BOOTSTRAP_VSCONFIG_FILE: &str = "RustyNetBuildTools.vsconfig";
const WINDOWS_ENABLE_ACCESS_HELPER_FILE: &str = "Enable-WindowsVmLabAccess.ps1";
const WINDOWS_SERVICE_INSTALL_HELPER_FILE: &str = "Install-RustyNetWindowsService.ps1";
const WINDOWS_VERIFY_HELPER_FILE: &str = "Verify-RustyNetWindowsBootstrap.ps1";
const WINDOWS_COLLECT_DIAGNOSTICS_HELPER_FILE: &str = "Collect-RustyNetWindowsDiagnostics.ps1";
const SETUP_MANIFEST_RELATIVE_PATH: &str = "state/setup_manifest.json";
const REPORT_STATE_RELATIVE_PATH: &str = "state/report_state.json";
const RELEASE_GATE_COMPLETENESS_RELATIVE_PATH: &str = "state/release_gate_completeness.json";
const VM_LAB_WRAPPER_SOURCE_RELATIVE_PATH: &str = "crates/rustynet-cli/src/vm_lab/mod.rs";
const DEFAULT_PRECHECK_COMMANDS: &[&str] = &["git", "cargo", "systemctl"];
const POLL_INTERVAL_MILLIS: u64 = 100;
static UNIQUE_COUNTER: AtomicU64 = AtomicU64::new(0);
const FULL_RELEASE_GATE_REQUIRED_STAGES: &[&str] = &[
    "live_role_switch_matrix",
    "live_exit_handoff",
    "live_two_hop",
    "live_lan_toggle",
    "live_managed_dns",
    "fresh_install_os_matrix_report",
    "local_full_gate_suite",
    "extended_soak",
    "cross_network_nat_matrix",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmLabListConfig {
    pub inventory_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmLabDiscoverLocalUtmConfig {
    pub inventory_path: Option<PathBuf>,
    pub utm_documents_root: Option<PathBuf>,
    pub utmctl_path: Option<PathBuf>,
    pub ssh_identity_file: Option<PathBuf>,
    pub known_hosts_path: Option<PathBuf>,
    pub ssh_port: u16,
    pub timeout_secs: u64,
    pub update_inventory_live_ips: bool,
    pub report_dir: Option<PathBuf>,
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
    pub ssh_identity_file: Option<PathBuf>,
    pub known_hosts_path: Option<PathBuf>,
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
    pub ssh_identity_file: Option<PathBuf>,
    pub known_hosts_path: Option<PathBuf>,
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
    pub ssh_identity_file: Option<PathBuf>,
    pub known_hosts_path: Option<PathBuf>,
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
    pub skip_setup: bool,
    pub skip_gates: bool,
    pub skip_soak: bool,
    pub skip_cross_network: bool,
    pub source_mode: Option<String>,
    pub repo_ref: Option<String>,
    pub report_dir: Option<PathBuf>,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmLabSetupLiveLabConfig {
    pub inventory_path: PathBuf,
    pub profile_path: Option<PathBuf>,
    pub profile_output_path: Option<PathBuf>,
    pub exit_vm: Option<String>,
    pub client_vm: Option<String>,
    pub entry_vm: Option<String>,
    pub aux_vm: Option<String>,
    pub extra_vm: Option<String>,
    pub fifth_client_vm: Option<String>,
    pub ssh_identity_file: PathBuf,
    pub known_hosts_path: Option<PathBuf>,
    pub require_same_network: bool,
    pub script_path: PathBuf,
    pub report_dir: PathBuf,
    pub source_mode: Option<String>,
    pub repo_ref: Option<String>,
    pub resume_from: Option<String>,
    pub rerun_stage: Option<String>,
    pub max_parallel_node_workers: Option<usize>,
    pub timeout_secs: u64,
    pub dry_run: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmLabOrchestrateLiveLabConfig {
    pub inventory_path: PathBuf,
    pub profile_path: Option<PathBuf>,
    pub profile_output_path: Option<PathBuf>,
    pub exit_vm: Option<String>,
    pub client_vm: Option<String>,
    pub entry_vm: Option<String>,
    pub aux_vm: Option<String>,
    pub extra_vm: Option<String>,
    pub fifth_client_vm: Option<String>,
    pub ssh_identity_file: PathBuf,
    pub known_hosts_path: Option<PathBuf>,
    pub require_same_network: bool,
    pub script_path: PathBuf,
    pub report_dir: PathBuf,
    pub source_mode: Option<String>,
    pub repo_ref: Option<String>,
    pub max_parallel_node_workers: Option<usize>,
    pub skip_gates: bool,
    pub skip_soak: bool,
    pub skip_cross_network: bool,
    pub utm_documents_root: Option<PathBuf>,
    pub utmctl_path: Option<PathBuf>,
    pub ssh_port: u16,
    pub discovery_timeout_secs: u64,
    pub ready_timeout_secs: u64,
    pub timeout_secs: u64,
    pub collect_artifacts_on_failure: bool,
    pub skip_diagnose_on_failure: bool,
    pub stop_after_ready: bool,
    pub dry_run: bool,
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
    pub skip_gates: bool,
    pub skip_soak: bool,
    pub skip_cross_network: bool,
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
    pub ssh_identity_file: Option<PathBuf>,
    pub known_hosts_path: Option<PathBuf>,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmLabPreflightConfig {
    pub inventory_path: PathBuf,
    pub vm_aliases: Vec<String>,
    pub raw_targets: Vec<String>,
    pub select_all: bool,
    pub ssh_identity_file: Option<PathBuf>,
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
    pub ssh_identity_file: Option<PathBuf>,
    pub known_hosts_path: Option<PathBuf>,
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
    pub wait_ready: bool,
    pub ssh_port: u16,
    pub ready_timeout_secs: u64,
    pub ssh_user: Option<String>,
    pub ssh_identity_file: Option<PathBuf>,
    pub known_hosts_path: Option<PathBuf>,
    pub timeout_secs: u64,
    pub json_output: bool,
    pub report_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmLabCollectArtifactsConfig {
    pub inventory_path: PathBuf,
    pub vm_aliases: Vec<String>,
    pub raw_targets: Vec<String>,
    pub select_all: bool,
    pub ssh_user: Option<String>,
    pub ssh_identity_file: Option<PathBuf>,
    pub known_hosts_path: Option<PathBuf>,
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
    pub ssh_identity_file: Option<PathBuf>,
    pub known_hosts_path: Option<PathBuf>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum VmGuestPlatform {
    Linux,
    Macos,
    Windows,
    Ios,
    Android,
}

impl VmGuestPlatform {
    fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "linux" | "debian" | "ubuntu" | "fedora" | "mint" => Ok(Self::Linux),
            "macos" | "mac_os" | "osx" | "mac" | "darwin" => Ok(Self::Macos),
            "windows" | "windows11" | "windows_11" | "win11" | "windows10" | "windows_10" => {
                Ok(Self::Windows)
            }
            "ios" | "iphoneos" | "ipad_os" | "ipados" => Ok(Self::Ios),
            "android" => Ok(Self::Android),
            other => Err(format!("unsupported vm guest platform: {other}")),
        }
    }

    fn infer(
        explicit: Option<Self>,
        os_name: Option<&str>,
        alias: &str,
        utm_name: Option<&str>,
    ) -> Self {
        if let Some(platform) = explicit {
            return platform;
        }

        let mut haystacks = vec![alias.to_ascii_lowercase()];
        if let Some(value) = os_name {
            haystacks.push(value.to_ascii_lowercase());
        }
        if let Some(value) = utm_name {
            haystacks.push(value.to_ascii_lowercase());
        }

        if haystacks.iter().any(|value| {
            value.contains("windows") || value.contains("win11") || value.contains("win10")
        }) {
            Self::Windows
        } else if haystacks.iter().any(|value| {
            value.contains("macos")
                || value.contains("mac os")
                || value.contains("os x")
                || value.contains("darwin")
        }) {
            Self::Macos
        } else if haystacks.iter().any(|value| {
            value.contains("ios") || value.contains("iphone") || value.contains("ipad")
        }) {
            Self::Ios
        } else if haystacks.iter().any(|value| value.contains("android")) {
            Self::Android
        } else {
            Self::Linux
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Macos => "macos",
            Self::Windows => "windows",
            Self::Ios => "ios",
            Self::Android => "android",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum VmRemoteShell {
    Posix,
    Powershell,
    Unsupported,
}

impl VmRemoteShell {
    fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "posix" | "bash" | "sh" => Ok(Self::Posix),
            "powershell" | "pwsh" => Ok(Self::Powershell),
            "unsupported" | "none" => Ok(Self::Unsupported),
            other => Err(format!("unsupported vm remote shell: {other}")),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Posix => "posix",
            Self::Powershell => "powershell",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum VmGuestExecMode {
    LinuxBash,
    MacosPosix,
    WindowsPowershell,
    Unsupported,
}

impl VmGuestExecMode {
    fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "linux_bash" | "bash" => Ok(Self::LinuxBash),
            "macos_posix" | "macos_shell" | "zsh" => Ok(Self::MacosPosix),
            "windows_powershell" | "powershell" => Ok(Self::WindowsPowershell),
            "unsupported" | "none" => Ok(Self::Unsupported),
            other => Err(format!("unsupported vm guest exec mode: {other}")),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::LinuxBash => "linux_bash",
            Self::MacosPosix => "macos_posix",
            Self::WindowsPowershell => "windows_powershell",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum VmServiceManager {
    Systemd,
    Launchd,
    WindowsService,
    Unsupported,
}

impl VmServiceManager {
    fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "systemd" => Ok(Self::Systemd),
            "launchd" => Ok(Self::Launchd),
            "windows_service" | "service" => Ok(Self::WindowsService),
            "unsupported" | "none" => Ok(Self::Unsupported),
            other => Err(format!("unsupported vm service manager: {other}")),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Systemd => "systemd",
            Self::Launchd => "launchd",
            Self::WindowsService => "windows_service",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VmPlatformProfile {
    platform: VmGuestPlatform,
    remote_shell: VmRemoteShell,
    guest_exec_mode: VmGuestExecMode,
    service_manager: VmServiceManager,
}

fn controller_utm_name(controller: Option<&VmController>) -> Option<&str> {
    match controller {
        Some(VmController::LocalUtm { utm_name, .. }) => Some(utm_name.as_str()),
        None => None,
    }
}

fn default_platform_profile(platform: VmGuestPlatform) -> VmPlatformProfile {
    match platform {
        VmGuestPlatform::Linux => VmPlatformProfile {
            platform,
            remote_shell: VmRemoteShell::Posix,
            guest_exec_mode: VmGuestExecMode::LinuxBash,
            service_manager: VmServiceManager::Systemd,
        },
        VmGuestPlatform::Macos => VmPlatformProfile {
            platform,
            remote_shell: VmRemoteShell::Posix,
            guest_exec_mode: VmGuestExecMode::MacosPosix,
            service_manager: VmServiceManager::Launchd,
        },
        VmGuestPlatform::Windows => VmPlatformProfile {
            platform,
            remote_shell: VmRemoteShell::Powershell,
            guest_exec_mode: VmGuestExecMode::WindowsPowershell,
            service_manager: VmServiceManager::WindowsService,
        },
        VmGuestPlatform::Ios | VmGuestPlatform::Android => VmPlatformProfile {
            platform,
            remote_shell: VmRemoteShell::Unsupported,
            guest_exec_mode: VmGuestExecMode::Unsupported,
            service_manager: VmServiceManager::Unsupported,
        },
    }
}

fn effective_platform_profile(
    explicit_platform: Option<VmGuestPlatform>,
    explicit_remote_shell: Option<VmRemoteShell>,
    explicit_guest_exec_mode: Option<VmGuestExecMode>,
    explicit_service_manager: Option<VmServiceManager>,
    os_name: Option<&str>,
    alias: &str,
    controller: Option<&VmController>,
) -> VmPlatformProfile {
    let platform = VmGuestPlatform::infer(
        explicit_platform,
        os_name,
        alias,
        controller_utm_name(controller),
    );
    let defaults = default_platform_profile(platform);
    VmPlatformProfile {
        platform,
        remote_shell: explicit_remote_shell.unwrap_or(defaults.remote_shell),
        guest_exec_mode: explicit_guest_exec_mode.unwrap_or(defaults.guest_exec_mode),
        service_manager: explicit_service_manager.unwrap_or(defaults.service_manager),
    }
}

fn default_rustynet_src_dir_for_profile(
    profile: VmPlatformProfile,
    ssh_user: Option<&str>,
) -> String {
    match profile.platform {
        VmGuestPlatform::Linux => match ssh_user {
            Some("root") => "/root/Rustynet".to_string(),
            Some(user) => format!("/home/{user}/Rustynet"),
            None => "/home/debian/Rustynet".to_string(),
        },
        VmGuestPlatform::Macos => match ssh_user {
            Some("root") => "/var/root/Rustynet".to_string(),
            Some(user) => format!("/Users/{user}/Rustynet"),
            None => "/Users/Shared/Rustynet".to_string(),
        },
        VmGuestPlatform::Windows => r"C:\Rustynet".to_string(),
        VmGuestPlatform::Ios => "/var/mobile/Rustynet-unsupported".to_string(),
        VmGuestPlatform::Android => "/data/local/tmp/Rustynet-unsupported".to_string(),
    }
}

fn default_remote_temp_dir_for_profile(profile: VmPlatformProfile) -> String {
    match profile.platform {
        VmGuestPlatform::Linux => "/var/tmp".to_string(),
        VmGuestPlatform::Macos => "/private/var/tmp".to_string(),
        VmGuestPlatform::Windows => r"C:\ProgramData\Rustynet\vm-lab".to_string(),
        VmGuestPlatform::Ios => "/var/mobile/tmp/rustynet-unsupported".to_string(),
        VmGuestPlatform::Android => "/data/local/tmp/rustynet-unsupported".to_string(),
    }
}

fn windows_helper_script_local_path(file_name: &str) -> PathBuf {
    let canonical = workspace_root_path()
        .join(WINDOWS_BOOTSTRAP_HELPER_ROOT)
        .join(file_name);
    if canonical.is_file() {
        canonical
    } else {
        workspace_root_path()
            .join(WINDOWS_COMPAT_VM_LAB_HELPER_ROOT)
            .join(file_name)
    }
}

fn windows_bootstrap_helper_script_local_path() -> PathBuf {
    windows_helper_script_local_path(WINDOWS_BOOTSTRAP_HELPER_FILE)
}

fn windows_service_install_helper_script_local_path() -> PathBuf {
    windows_helper_script_local_path(WINDOWS_SERVICE_INSTALL_HELPER_FILE)
}

fn windows_verify_helper_script_local_path() -> PathBuf {
    windows_helper_script_local_path(WINDOWS_VERIFY_HELPER_FILE)
}

fn windows_diagnostics_helper_script_local_path() -> PathBuf {
    windows_helper_script_local_path(WINDOWS_COLLECT_DIAGNOSTICS_HELPER_FILE)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VmInventoryEntry {
    alias: String,
    ssh_target: String,
    ssh_user: Option<String>,
    ssh_password: Option<String>,
    include_in_all: Option<bool>,
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
    remote_temp_dir: Option<String>,
    rustynet_src_dir: Option<String>,
    platform: Option<VmGuestPlatform>,
    remote_shell: Option<VmRemoteShell>,
    guest_exec_mode: Option<VmGuestExecMode>,
    service_manager: Option<VmServiceManager>,
    controller: Option<VmController>,
}

impl VmInventoryEntry {
    fn platform_profile(&self) -> VmPlatformProfile {
        effective_platform_profile(
            self.platform,
            self.remote_shell,
            self.guest_exec_mode,
            self.service_manager,
            self.os.as_deref(),
            self.alias.as_str(),
            self.controller.as_ref(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RemoteTarget {
    label: String,
    ssh_target: String,
    ssh_user: Option<String>,
    controller: Option<VmController>,
    platform_profile: VmPlatformProfile,
    rustynet_src_dir: Option<String>,
    remote_temp_dir: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StartTarget {
    alias: String,
    utm_name: String,
    bundle_path: PathBuf,
    ssh_user: Option<String>,
    last_known_ip: Option<String>,
    mesh_ip: Option<String>,
    platform_profile: VmPlatformProfile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct LocalUtmReadyState {
    alias: String,
    utm_name: String,
    process_present: bool,
    live_ip: Option<String>,
    ssh_port_status: String,
    ssh_auth_status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ProbeState<T> {
    Ok { value: T },
    Fallback { value: T, reason: String },
    Missing { reason: String },
    Error { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum PortStatus {
    Open,
    Refused,
    TimedOut,
    Unreachable,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct VmLabReadiness {
    powered: bool,
    networked: bool,
    tcp_ready: bool,
    auth_ready: bool,
    execution_ready: bool,
    reason_codes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum VmLabCommandOverallStatus {
    Pass,
    Fail,
    Partial,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum VmLabStageStatus {
    Pass,
    Fail,
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct VmLabStageOutcome {
    stage: String,
    status: VmLabStageStatus,
    summary: String,
    artifacts: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct VmLabCommandResult {
    command: String,
    overall_status: VmLabCommandOverallStatus,
    report_dir: String,
    outcomes: Vec<VmLabStageOutcome>,
    warnings: Vec<String>,
    next_actions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct LocalUtmDiscoveryEntry {
    alias: String,
    readiness: VmLabReadiness,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct LocalUtmDiscoveryReport {
    entries: Vec<LocalUtmDiscoveryEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LocalUtmSelectedReadinessEntry {
    alias: String,
    reason_codes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LocalUtmSelectedReadinessSummary {
    ready_aliases: Vec<String>,
    unready_entries: Vec<LocalUtmSelectedReadinessEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LiveLabSetupSelection {
    profile_path: PathBuf,
    profile_generated: bool,
    profile_generation_summary: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LiveLabFileBinding {
    path: String,
    sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LiveLabGitProvenance {
    git_commit: String,
    git_tree_clean: bool,
    source_mode: String,
    repo_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LiveLabSetupModeFlags {
    require_same_network: Option<bool>,
    dry_run: bool,
    max_parallel_node_workers: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LiveLabRunModeFlags {
    dry_run: bool,
    skip_setup: bool,
    skip_gates: bool,
    skip_soak: bool,
    skip_cross_network: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LiveLabSetupManifest {
    version: u32,
    created_at_unix: u64,
    report_dir_path: String,
    report_dir_sha256: String,
    profile: LiveLabFileBinding,
    profile_semantic_sha256: String,
    script: LiveLabFileBinding,
    inventory: Option<LiveLabFileBinding>,
    wrapper_source: LiveLabFileBinding,
    wrapper_version: String,
    git: LiveLabGitProvenance,
    setup_flags: LiveLabSetupModeFlags,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LiveLabRunProvenance {
    invoked_at_unix: u64,
    profile: LiveLabFileBinding,
    profile_semantic_sha256: String,
    script: LiveLabFileBinding,
    wrapper_source: LiveLabFileBinding,
    wrapper_version: String,
    git: LiveLabGitProvenance,
    run_flags: LiveLabRunModeFlags,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LiveLabReportState {
    version: u32,
    created_at_unix: u64,
    updated_at_unix: u64,
    report_dir_path: String,
    report_dir_sha256: String,
    setup_manifest_sha256: String,
    setup_complete: bool,
    run_complete: bool,
    run_passed: bool,
    full_release_gate_requested: bool,
    full_release_evidence_complete: bool,
    last_run: Option<LiveLabRunProvenance>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ReleaseGateCompletenessReport {
    requested: bool,
    status: String,
    required_stages: Vec<String>,
    observed_pass_stages: Vec<String>,
    missing_or_non_pass_stages: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LiveLabStageReviewContext<'a> {
    report_dir: &'a Path,
    stage_record: &'a LiveLabStageRecord,
    summary: &'a LiveLabStageSummary,
    strategy: &'a str,
    local_bundle: &'a LiveLabStageLocalBundle,
    remote_probe_dir: Option<&'a Path>,
    notes: &'a [String],
    warnings: &'a [String],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RemoteFallbackContext<'a> {
    target: &'a RemoteTarget,
    ssh_user_override: Option<&'a str>,
    ssh_identity_file: Option<&'a Path>,
    known_hosts_path: Option<&'a Path>,
    timeout: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StateArtifactInstallPaths<'a> {
    assignment_pub: &'a Path,
    assignment_bundle: &'a Path,
    traversal_pub: &'a Path,
    traversal_bundle: &'a Path,
    refresh_env: &'a Path,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RoleTarget {
    label: String,
    normalized_target: String,
    network_group: Option<String>,
    utm_name: Option<String>,
    platform_profile: VmPlatformProfile,
    rustynet_src_dir: Option<String>,
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

pub fn default_lab_ssh_identity_path() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
        .join(".ssh/rustynet_lab_ed25519")
}

fn default_live_lab_setup_profile_path(report_dir: &Path) -> PathBuf {
    report_dir.join("setup_live_lab_profile.env")
}

fn default_utm_documents_root() -> Result<PathBuf, String> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is required to discover local UTM documents".to_string())?;
    Ok(home.join("Library/Containers/com.utmapp.UTM/Data/Documents"))
}

fn setup_stage_names() -> &'static [&'static str] {
    &[
        "preflight",
        "prepare_source_archive",
        "verify_ssh_reachability",
        "prime_remote_access",
        "cleanup_hosts",
        "bootstrap_hosts",
        "collect_pubkeys",
        "membership_setup",
        "distribute_membership_state",
        "issue_and_distribute_assignments",
        "issue_and_distribute_traversal",
        "issue_and_distribute_dns_zone",
        "enforce_baseline_runtime",
        "validate_baseline_runtime",
    ]
}

fn normalize_manifest_path(path: &Path) -> String {
    path.canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .display()
        .to_string()
}

fn sha256_hex_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn file_sha256_hex(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path)
        .map_err(|err| format!("read for sha256 failed ({}): {err}", path.display()))?;
    Ok(sha256_hex_bytes(bytes.as_slice()))
}

fn semantic_live_lab_profile_sha256(path: &Path) -> Result<String, String> {
    let profile = load_live_lab_profile(path)?;
    let body = serde_json::to_vec(&profile.values)
        .map_err(|err| format!("serialize live-lab profile semantic digest failed: {err}"))?;
    Ok(sha256_hex_bytes(body.as_slice()))
}

fn report_dir_sha256(report_dir: &Path) -> String {
    sha256_hex_bytes(normalize_manifest_path(report_dir).as_bytes())
}

fn file_binding(path: &Path) -> Result<LiveLabFileBinding, String> {
    Ok(LiveLabFileBinding {
        path: normalize_manifest_path(path),
        sha256: file_sha256_hex(path)?,
    })
}

fn optional_file_binding(path: Option<&Path>) -> Result<Option<LiveLabFileBinding>, String> {
    path.map(file_binding).transpose()
}

fn git_head_commit() -> Result<String, String> {
    let mut command = Command::new("git");
    command.current_dir(workspace_root_path());
    command.args(["rev-parse", "HEAD"]);
    let output = run_output_with_timeout(
        &mut command,
        timeout_or_default(30, DEFAULT_RUN_TIMEOUT_SECS),
    )?;
    if !output.status.success() {
        return Err(format!(
            "git rev-parse HEAD failed with status {}",
            status_code(output.status)
        ));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|err| format!("git rev-parse HEAD returned non-UTF-8 output: {err}"))?;
    let commit = stdout.trim().to_ascii_lowercase();
    if commit.len() != 40
        || !commit
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
    {
        return Err(format!(
            "git rev-parse HEAD returned invalid commit: {commit}"
        ));
    }
    Ok(commit)
}

fn current_git_provenance(
    source_mode: &str,
    repo_ref: Option<&str>,
) -> Result<LiveLabGitProvenance, String> {
    Ok(LiveLabGitProvenance {
        git_commit: git_head_commit()?,
        git_tree_clean: !git_worktree_is_dirty()?,
        source_mode: source_mode.to_string(),
        repo_ref: repo_ref.map(ToOwned::to_owned),
    })
}

fn current_wrapper_source_binding() -> Result<LiveLabFileBinding, String> {
    file_binding(&workspace_root_path().join(VM_LAB_WRAPPER_SOURCE_RELATIVE_PATH))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LiveLabSetupManifestInput {
    report_dir: PathBuf,
    profile_path: PathBuf,
    script_path: PathBuf,
    inventory_path: Option<PathBuf>,
    source_mode: String,
    repo_ref: Option<String>,
    require_same_network: Option<bool>,
    dry_run: bool,
    max_parallel_node_workers: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LiveLabSetupManifestExpectation {
    report_dir: PathBuf,
    profile_path: PathBuf,
    script_path: PathBuf,
    inventory_path: Option<PathBuf>,
    source_mode: String,
    repo_ref: Option<String>,
    require_same_network: Option<bool>,
    dry_run: Option<bool>,
    max_parallel_node_workers: Option<usize>,
}

fn validate_file_binding(
    label: &str,
    actual: &LiveLabFileBinding,
    current: &LiveLabFileBinding,
) -> Result<(), String> {
    if actual.path != current.path || actual.sha256 != current.sha256 {
        return Err(format!(
            "setup manifest {label} provenance mismatch: actual={} current={}",
            serde_json::to_string(actual)
                .unwrap_or_else(|_| format!("<{label}-actual-serialize-error>")),
            serde_json::to_string(current)
                .unwrap_or_else(|_| format!("<{label}-current-serialize-error>"))
        ));
    }
    Ok(())
}

fn report_dir_contains_regular_entries(report_dir: &Path) -> Result<bool, String> {
    if !report_dir.exists() {
        return Ok(false);
    }
    if !report_dir.is_dir() {
        return Err(format!(
            "report directory path is not a directory: {}",
            report_dir.display()
        ));
    }
    let mut pending = vec![report_dir.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(&dir)
            .map_err(|err| format!("read report directory failed ({}): {err}", dir.display()))?
        {
            let entry = entry.map_err(|err| {
                format!("iterate report directory failed ({}): {err}", dir.display())
            })?;
            let file_type = entry.file_type().map_err(|err| {
                format!(
                    "read report directory entry type failed ({}): {err}",
                    entry.path().display()
                )
            })?;
            if file_type.is_dir() {
                pending.push(entry.path());
            } else {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn ensure_report_dir_fresh(report_dir: &Path, command_name: &str) -> Result<(), String> {
    if !report_dir.exists() {
        return Ok(());
    }
    if report_dir_contains_regular_entries(report_dir)? {
        return Err(format!(
            "{command_name} refuses to reuse non-empty report dir {}; use a new report dir or the matching provenance-bound resume path",
            report_dir.display()
        ));
    }
    Ok(())
}

fn build_setup_manifest(input: &LiveLabSetupManifestInput) -> Result<LiveLabSetupManifest, String> {
    Ok(LiveLabSetupManifest {
        version: 2,
        created_at_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| format!("clock failure while building setup manifest: {err}"))?
            .as_secs(),
        report_dir_path: normalize_manifest_path(input.report_dir.as_path()),
        report_dir_sha256: report_dir_sha256(input.report_dir.as_path()),
        profile: file_binding(input.profile_path.as_path())?,
        profile_semantic_sha256: semantic_live_lab_profile_sha256(input.profile_path.as_path())?,
        script: file_binding(input.script_path.as_path())?,
        inventory: optional_file_binding(input.inventory_path.as_deref())?,
        wrapper_source: current_wrapper_source_binding()?,
        wrapper_version: env!("CARGO_PKG_VERSION").to_string(),
        git: current_git_provenance(input.source_mode.as_str(), input.repo_ref.as_deref())?,
        setup_flags: LiveLabSetupModeFlags {
            require_same_network: input.require_same_network,
            dry_run: input.dry_run,
            max_parallel_node_workers: input.max_parallel_node_workers,
        },
    })
}

fn write_setup_manifest(report_dir: &Path, manifest: &LiveLabSetupManifest) -> Result<(), String> {
    let path = report_dir.join(SETUP_MANIFEST_RELATIVE_PATH);
    let parent = path
        .parent()
        .ok_or_else(|| format!("setup manifest path has no parent: {}", path.display()))?;
    fs::create_dir_all(parent).map_err(|err| {
        format!(
            "create setup manifest directory failed ({}): {err}",
            parent.display()
        )
    })?;
    let body = serde_json::to_vec_pretty(manifest)
        .map_err(|err| format!("serialize setup manifest failed: {err}"))?;
    fs::write(&path, body)
        .map_err(|err| format!("write setup manifest failed ({}): {err}", path.display()))
}

fn read_setup_manifest(report_dir: &Path) -> Result<LiveLabSetupManifest, String> {
    let path = report_dir.join(SETUP_MANIFEST_RELATIVE_PATH);
    let body = fs::read(&path)
        .map_err(|err| format!("read setup manifest failed ({}): {err}", path.display()))?;
    serde_json::from_slice(&body)
        .map_err(|err| format!("parse setup manifest failed ({}): {err}", path.display()))
}

fn setup_manifest_sha256(report_dir: &Path) -> Result<String, String> {
    file_sha256_hex(&report_dir.join(SETUP_MANIFEST_RELATIVE_PATH))
}

fn write_report_state(report_dir: &Path, state: &LiveLabReportState) -> Result<(), String> {
    let path = report_dir.join(REPORT_STATE_RELATIVE_PATH);
    let parent = path
        .parent()
        .ok_or_else(|| format!("report state path has no parent: {}", path.display()))?;
    fs::create_dir_all(parent).map_err(|err| {
        format!(
            "create report state directory failed ({}): {err}",
            parent.display()
        )
    })?;
    let body = serde_json::to_vec_pretty(state)
        .map_err(|err| format!("serialize report state failed: {err}"))?;
    fs::write(&path, body)
        .map_err(|err| format!("write report state failed ({}): {err}", path.display()))
}

fn read_report_state(report_dir: &Path) -> Result<LiveLabReportState, String> {
    let path = report_dir.join(REPORT_STATE_RELATIVE_PATH);
    let body = fs::read(&path)
        .map_err(|err| format!("read report state failed ({}): {err}", path.display()))?;
    serde_json::from_slice(&body)
        .map_err(|err| format!("parse report state failed ({}): {err}", path.display()))
}

fn initial_report_state(
    report_dir: &Path,
    _manifest: &LiveLabSetupManifest,
) -> Result<LiveLabReportState, String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| format!("clock failure while building report state: {err}"))?
        .as_secs();
    Ok(LiveLabReportState {
        version: 1,
        created_at_unix: now,
        updated_at_unix: now,
        report_dir_path: normalize_manifest_path(report_dir),
        report_dir_sha256: report_dir_sha256(report_dir),
        setup_manifest_sha256: setup_manifest_sha256(report_dir)?,
        setup_complete: false,
        run_complete: false,
        run_passed: false,
        full_release_gate_requested: false,
        full_release_evidence_complete: false,
        last_run: None,
    })
}

fn update_report_state_setup_complete(report_dir: &Path) -> Result<(), String> {
    let mut state = read_report_state(report_dir)?;
    state.updated_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| format!("clock failure while updating setup state: {err}"))?
        .as_secs();
    state.setup_manifest_sha256 = setup_manifest_sha256(report_dir)?;
    state.setup_complete = true;
    state.run_complete = false;
    state.run_passed = false;
    state.full_release_gate_requested = false;
    state.full_release_evidence_complete = false;
    state.last_run = None;
    write_report_state(report_dir, &state)
}

fn build_run_provenance(
    profile_path: &Path,
    script_path: &Path,
    source_mode: &str,
    repo_ref: Option<&str>,
    flags: &LiveLabRunModeFlags,
) -> Result<LiveLabRunProvenance, String> {
    Ok(LiveLabRunProvenance {
        invoked_at_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| format!("clock failure while building run provenance: {err}"))?
            .as_secs(),
        profile: file_binding(profile_path)?,
        profile_semantic_sha256: semantic_live_lab_profile_sha256(profile_path)?,
        script: file_binding(script_path)?,
        wrapper_source: current_wrapper_source_binding()?,
        wrapper_version: env!("CARGO_PKG_VERSION").to_string(),
        git: current_git_provenance(source_mode, repo_ref)?,
        run_flags: flags.clone(),
    })
}

fn update_report_state_after_run(
    report_dir: &Path,
    run_provenance: LiveLabRunProvenance,
    run_passed: bool,
    full_release_gate_requested: bool,
    full_release_evidence_complete: bool,
) -> Result<(), String> {
    let mut state = read_report_state(report_dir)?;
    state.updated_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| format!("clock failure while updating run state: {err}"))?
        .as_secs();
    state.setup_manifest_sha256 = setup_manifest_sha256(report_dir)?;
    state.setup_complete = live_lab_setup_complete(report_dir)?;
    state.run_complete = true;
    state.run_passed = run_passed;
    state.full_release_gate_requested = full_release_gate_requested;
    state.full_release_evidence_complete = full_release_evidence_complete;
    state.last_run = Some(run_provenance);
    write_report_state(report_dir, &state)
}

fn validate_setup_manifest(
    report_dir: &Path,
    expected: &LiveLabSetupManifestExpectation,
) -> Result<(), String> {
    let actual = read_setup_manifest(report_dir)?;
    if actual.version != 2 {
        return Err(format!(
            "unsupported setup manifest version {} in {}",
            actual.version,
            report_dir.join(SETUP_MANIFEST_RELATIVE_PATH).display()
        ));
    }
    let expected_report_dir_path = normalize_manifest_path(expected.report_dir.as_path());
    let expected_report_dir_sha256 = report_dir_sha256(expected.report_dir.as_path());
    if actual.report_dir_path != expected_report_dir_path
        || actual.report_dir_sha256 != expected_report_dir_sha256
    {
        return Err(format!(
            "setup manifest report-dir provenance mismatch: actual={{\"path\":\"{}\",\"sha256\":\"{}\"}} current={{\"path\":\"{}\",\"sha256\":\"{}\"}}",
            actual.report_dir_path,
            actual.report_dir_sha256,
            expected_report_dir_path,
            expected_report_dir_sha256
        ));
    }
    let current_profile = file_binding(expected.profile_path.as_path())?;
    validate_file_binding("profile", &actual.profile, &current_profile)?;
    let current_profile_semantic_sha256 =
        semantic_live_lab_profile_sha256(expected.profile_path.as_path())?;
    if actual.profile_semantic_sha256 != current_profile_semantic_sha256 {
        return Err(format!(
            "setup manifest profile semantic provenance mismatch: actual={} current={}",
            actual.profile_semantic_sha256, current_profile_semantic_sha256
        ));
    }
    let current_script = file_binding(expected.script_path.as_path())?;
    validate_file_binding("script", &actual.script, &current_script)?;
    let current_inventory_binding = match expected.inventory_path.as_deref() {
        Some(path) => Some(file_binding(path)?),
        None => actual
            .inventory
            .as_ref()
            .map(|binding| file_binding(Path::new(binding.path.as_str())))
            .transpose()?,
    };
    match (&actual.inventory, &current_inventory_binding) {
        (Some(actual_binding), Some(current_binding)) => {
            validate_file_binding("inventory", actual_binding, current_binding)?
        }
        (None, None) => {}
        (Some(_), None) | (None, Some(_)) => {
            return Err("setup manifest inventory provenance mismatch".to_string());
        }
    }
    let current_wrapper_source = current_wrapper_source_binding()?;
    validate_file_binding(
        "wrapper_source",
        &actual.wrapper_source,
        &current_wrapper_source,
    )?;
    if actual.wrapper_version != env!("CARGO_PKG_VERSION") {
        return Err(format!(
            "setup manifest wrapper version mismatch: actual={} current={}",
            actual.wrapper_version,
            env!("CARGO_PKG_VERSION")
        ));
    }
    let current_git =
        current_git_provenance(expected.source_mode.as_str(), expected.repo_ref.as_deref())?;
    if actual.git != current_git {
        return Err(format!(
            "setup manifest git provenance mismatch: actual={} current={}",
            serde_json::to_string(&actual.git)
                .unwrap_or_else(|_| "<git-serialize-error>".to_string()),
            serde_json::to_string(&current_git)
                .unwrap_or_else(|_| "<git-serialize-error>".to_string())
        ));
    }
    if let Some(value) = expected.require_same_network
        && actual.setup_flags.require_same_network != Some(value)
    {
        return Err(format!(
            "setup manifest require_same_network mismatch: actual={} current={value}",
            actual
                .setup_flags
                .require_same_network
                .map(|flag| flag.to_string())
                .unwrap_or_else(|| "none".to_string())
        ));
    }
    if let Some(value) = expected.dry_run
        && actual.setup_flags.dry_run != value
    {
        return Err(format!(
            "setup manifest dry_run mismatch: actual={} current={value}",
            actual.setup_flags.dry_run
        ));
    }
    if let Some(value) = expected.max_parallel_node_workers
        && actual.setup_flags.max_parallel_node_workers != Some(value)
    {
        return Err(format!(
            "setup manifest max_parallel_node_workers mismatch: actual={} current={value}",
            actual
                .setup_flags
                .max_parallel_node_workers
                .map(|v| v.to_string())
                .unwrap_or_else(|| "none".to_string())
        ));
    }
    Ok(())
}

fn validate_report_state(report_dir: &Path) -> Result<LiveLabReportState, String> {
    let state = read_report_state(report_dir)?;
    if state.version != 1 {
        return Err(format!(
            "unsupported report state version {} in {}",
            state.version,
            report_dir.join(REPORT_STATE_RELATIVE_PATH).display()
        ));
    }
    let expected_report_dir_path = normalize_manifest_path(report_dir);
    let expected_report_dir_sha256 = report_dir_sha256(report_dir);
    if state.report_dir_path != expected_report_dir_path
        || state.report_dir_sha256 != expected_report_dir_sha256
    {
        return Err(format!(
            "report state report-dir provenance mismatch: actual={{\"path\":\"{}\",\"sha256\":\"{}\"}} current={{\"path\":\"{}\",\"sha256\":\"{}\"}}",
            state.report_dir_path,
            state.report_dir_sha256,
            expected_report_dir_path,
            expected_report_dir_sha256
        ));
    }
    let expected_setup_manifest_sha256 = setup_manifest_sha256(report_dir)?;
    if state.setup_manifest_sha256 != expected_setup_manifest_sha256 {
        return Err(format!(
            "report state setup manifest provenance mismatch: actual={} current={}",
            state.setup_manifest_sha256, expected_setup_manifest_sha256
        ));
    }
    Ok(state)
}

fn resolve_setup_selection_from_existing_manifest(
    report_dir: &Path,
) -> Result<LiveLabSetupSelection, String> {
    let manifest = read_setup_manifest(report_dir)?;
    let profile_path = PathBuf::from(manifest.profile.path);
    ensure_local_regular_file_path(profile_path.as_path(), "existing live-lab profile")?;
    execute_ops_vm_lab_validate_live_lab_profile(VmLabValidateLiveLabProfileConfig {
        profile_path: profile_path.clone(),
        expected_backend: None,
        expected_source_mode: None,
        require_five_node: false,
    })?;
    Ok(LiveLabSetupSelection {
        profile_path,
        profile_generated: false,
        profile_generation_summary: None,
    })
}

fn resolve_run_setup_reuse(
    report_dir: &Path,
    profile_path: &Path,
    script_path: &Path,
    source_mode: &str,
    repo_ref: Option<&str>,
    skip_setup: bool,
) -> Result<bool, String> {
    if !report_dir.exists() {
        if skip_setup {
            return Err(format!(
                "vm-lab-run-live-lab --skip-setup requires an existing provenance-bound setup report dir: {}",
                report_dir.display()
            ));
        }
        return Ok(false);
    }
    let has_regular_entries = report_dir_contains_regular_entries(report_dir)?;
    if !has_regular_entries {
        if skip_setup {
            return Err(format!(
                "vm-lab-run-live-lab --skip-setup requires a populated provenance-bound setup report dir: {}",
                report_dir.display()
            ));
        }
        return Ok(false);
    }
    let expectation = LiveLabSetupManifestExpectation {
        report_dir: report_dir.to_path_buf(),
        profile_path: profile_path.to_path_buf(),
        script_path: script_path.to_path_buf(),
        inventory_path: None,
        source_mode: source_mode.to_string(),
        repo_ref: repo_ref.map(ToOwned::to_owned),
        require_same_network: None,
        dry_run: None,
        max_parallel_node_workers: None,
    };
    validate_setup_manifest(report_dir, &expectation)?;
    let report_state = validate_report_state(report_dir)?;
    if !report_state.setup_complete {
        return Err(format!(
            "report dir {} cannot be reused because setup is not complete",
            report_dir.display()
        ));
    }
    if report_state.run_complete || report_state.last_run.is_some() {
        return Err(format!(
            "report dir {} already contains run provenance; use a fresh report dir for a new run",
            report_dir.display()
        ));
    }
    if !live_lab_setup_complete(report_dir)? {
        return Err(format!(
            "report dir {} is missing completed setup stage evidence",
            report_dir.display()
        ));
    }
    if live_lab_report_has_non_setup_stage_records(report_dir)? {
        return Err(format!(
            "report dir {} already contains non-setup stage records and cannot be reused for a fresh run",
            report_dir.display()
        ));
    }
    Ok(true)
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

pub fn execute_ops_vm_lab_discover_local_utm(
    config: VmLabDiscoverLocalUtmConfig,
) -> Result<String, String> {
    let documents_root = match config.utm_documents_root.as_deref() {
        Some(path) => resolve_path(path)?,
        None => default_utm_documents_root()?,
    };
    if !documents_root.is_dir() {
        return Err(format!(
            "UTM documents root must be an existing directory: {}",
            documents_root.display()
        ));
    }

    let discovered_bundle_paths = discover_local_utm_bundle_paths(documents_root.as_path())?;
    if discovered_bundle_paths.is_empty() {
        return Err(format!(
            "no UTM bundle directories found under {}",
            documents_root.display()
        ));
    }

    let utmctl_path = config
        .utmctl_path
        .as_deref()
        .map(resolve_path)
        .transpose()?
        .unwrap_or_else(default_utmctl_path);
    let timeout = timeout_or_default(config.timeout_secs, DEFAULT_UTM_IP_DISCOVERY_TIMEOUT_SECS);
    let ssh_port = if config.ssh_port == 0 {
        22
    } else {
        config.ssh_port
    };

    let (inventory, inventory_error) = match config.inventory_path.as_deref() {
        Some(path) if path.exists() => match load_inventory(path) {
            Ok(entries) => (entries, None),
            Err(err) => (Vec::new(), Some(err)),
        },
        Some(path) => (
            Vec::new(),
            Some(format!("inventory path does not exist: {}", path.display())),
        ),
        None => (Vec::new(), None),
    };

    let mut entries = Vec::new();
    let mut matched_inventory_count = 0usize;
    let mut process_present_count = 0usize;
    let mut live_ip_count = 0usize;
    let mut ssh_port_open_count = 0usize;
    let mut ready_count = 0usize;
    let mut ready_inventory_states = Vec::new();

    for bundle_path in discovered_bundle_paths {
        let utm_name = bundle_path
            .file_stem()
            .and_then(|value| value.to_str())
            .ok_or_else(|| {
                format!(
                    "discovered UTM bundle has no valid UTF-8 bundle name: {}",
                    bundle_path.display()
                )
            })?
            .to_string();
        let inventory_match = inventory.iter().find(|entry| {
            matches_local_utm_inventory_entry(entry, bundle_path.as_path(), utm_name.as_str())
        });
        let process_probe = local_utm_process_present_with_probes(
            utmctl_path.as_path(),
            Path::new("ps"),
            utm_name.as_str(),
            bundle_path.as_path(),
            timeout,
        );
        let process_present = process_probe.as_ref().copied().unwrap_or(false);
        if process_present {
            process_present_count += 1;
        }
        let process_state = match process_probe {
            Ok(value) => ProbeState::Ok { value },
            Err(err) => ProbeState::Error { reason: err },
        };

        let mut discovery_notes = Vec::new();
        let mut live_ip_source = "unavailable".to_string();
        let mut live_ip = None;
        let mut authoritative_ssh_target = None;
        let mut authoritative_target_present = false;
        let mut advisory_ssh_target = None;
        let mut ssh_target_source = "unavailable".to_string();
        let mut ssh_user = None;
        let mut inventory_alias = None;
        let mut inventory_node_id = None;
        let mut inventory_lab_role = None;
        let mut inventory_ssh_target = None;
        let mut inventory_ssh_user = None;
        let mut inventory_last_known_ip = None;
        let mut inventory_mesh_ip = None;
        let mut inventory_controller_bundle_path = None;
        let mut inventory_controller_utm_name = None;
        let discovery_platform_profile = if let Some(entry) = inventory_match {
            matched_inventory_count += 1;
            inventory_alias = Some(entry.alias.clone());
            inventory_node_id = entry.node_id.clone();
            inventory_lab_role = entry.lab_role.clone();
            inventory_ssh_target = Some(entry.ssh_target.clone());
            inventory_ssh_user = entry.ssh_user.clone();
            inventory_last_known_ip = entry.last_known_ip.clone();
            inventory_mesh_ip = entry.mesh_ip.clone();
            if let Some(VmController::LocalUtm {
                utm_name: entry_utm_name,
                bundle_path: entry_bundle_path,
            }) = entry.controller.as_ref()
            {
                inventory_controller_bundle_path = Some(entry_bundle_path.display().to_string());
                inventory_controller_utm_name = Some(entry_utm_name.clone());
            }
            let resolved_target =
                resolved_inventory_ssh_target_with_utmctl(entry, utmctl_path.as_path());
            authoritative_ssh_target = Some(resolved_target.clone());
            authoritative_target_present = true;
            ssh_target_source = "inventory".to_string();
            ssh_user = entry.ssh_user.clone();
            if let Some(ip) = resolve_local_utm_live_host(entry, utmctl_path.as_path()) {
                live_ip_source = "utmctl".to_string();
                live_ip = Some(ip);
            } else if let Some(ip) = entry.last_known_ip.as_deref() {
                live_ip_source = "inventory.last_known_ip".to_string();
                live_ip = Some(ip.to_string());
                discovery_notes
                    .push("utmctl-ip-address-unavailable-using-inventory-fallback".to_string());
            }
            Some(entry.platform_profile())
        } else {
            let inferred_platform =
                VmGuestPlatform::infer(None, None, utm_name.as_str(), Some(utm_name.as_str()));
            let profile = default_platform_profile(inferred_platform);
            if let Some(ip) = resolve_local_utm_live_host_by_name(
                utm_name.as_str(),
                None,
                None,
                utmctl_path.as_path(),
            ) {
                live_ip_source = "utmctl".to_string();
                live_ip = Some(ip);
            }
            if let Some(ip) = live_ip.clone() {
                ssh_target_source =
                    format!("platform-aware-unmatched-{}", inferred_platform.as_str());
                advisory_ssh_target =
                    unmatched_local_utm_advisory_target(inferred_platform, ip.as_str());
                if inferred_platform == VmGuestPlatform::Linux {
                    ssh_user = Some("debian".to_string());
                } else {
                    discovery_notes.push(
                        "windows-utm-discovered-without-inventory-no-linux-user-assumed"
                            .to_string(),
                    );
                }
            }
            Some(profile)
        };

        let live_ip_state = match live_ip.clone() {
            Some(ip) if live_ip_source == "utmctl" => ProbeState::Ok { value: ip },
            Some(ip) if live_ip_source == "inventory.last_known_ip" => ProbeState::Fallback {
                value: ip,
                reason: "utmctl-ip-address-unavailable".to_string(),
            },
            Some(ip) => ProbeState::Fallback {
                value: ip,
                reason: format!("live-ip-source={live_ip_source}"),
            },
            None => ProbeState::Missing {
                reason: "live-ip-unavailable".to_string(),
            },
        };
        if matches!(
            live_ip_state,
            ProbeState::Ok { .. } | ProbeState::Fallback { .. }
        ) {
            live_ip_count += 1;
        }

        let mut ssh_port_status = "skipped".to_string();
        let mut ssh_port_error = None;
        if let Some(ip) = live_ip.as_deref() {
            match probe_tcp_port_status(ip, ssh_port, timeout) {
                Ok((status, error)) => {
                    ssh_port_status = status;
                    ssh_port_error = error;
                }
                Err(err) => {
                    ssh_port_status = "unknown".to_string();
                    ssh_port_error = Some(err);
                }
            }
        }
        let ssh_port_state = match ssh_port_status.as_str() {
            "open" => ProbeState::Ok {
                value: PortStatus::Open,
            },
            "skipped" => ProbeState::Missing {
                reason: "no-live-ip".to_string(),
            },
            "unknown" => ProbeState::Error {
                reason: ssh_port_error
                    .clone()
                    .unwrap_or_else(|| "tcp-port-probe-failed".to_string()),
            },
            value => ProbeState::Fallback {
                value: port_status_from_probe(value),
                reason: ssh_port_error
                    .clone()
                    .unwrap_or_else(|| format!("ssh-port-status={value}")),
            },
        };
        let ssh_auth_state = match (
            live_ip.as_deref(),
            ssh_user.as_deref(),
            authoritative_ssh_target
                .as_deref()
                .or(advisory_ssh_target.as_deref()),
        ) {
            (None, _, _) => ProbeState::Missing {
                reason: "no-live-ip".to_string(),
            },
            (_, None, _) => ProbeState::Missing {
                reason: "no-ssh-user".to_string(),
            },
            (_, _, None) => ProbeState::Missing {
                reason: "no-ssh-target".to_string(),
            },
            (_, _, Some(_)) if ssh_port_status != "open" => ProbeState::Missing {
                reason: format!("ssh-port-status={ssh_port_status}"),
            },
            (Some(_), Some(ssh_user), Some(ssh_target)) => {
                match ssh_auth_probe_command(
                    discovery_platform_profile
                        .unwrap_or_else(|| default_platform_profile(VmGuestPlatform::Linux)),
                ) {
                    Ok(probe_command) => match run_remote_shell_command(
                        ssh_target,
                        Some(ssh_user),
                        config.ssh_identity_file.as_deref(),
                        config.known_hosts_path.as_deref(),
                        probe_command,
                        timeout,
                    ) {
                        Ok(status) if status.success() => ProbeState::Ok {
                            value: "ok".to_string(),
                        },
                        Ok(status) => ProbeState::Fallback {
                            value: format!("failed-exit-{}", status_code(status)),
                            reason: "ssh-auth-command-failed".to_string(),
                        },
                        Err(err) => ProbeState::Error { reason: err },
                    },
                    Err(err) => ProbeState::Error { reason: err },
                }
            }
        };
        let readiness = build_utm_readiness(
            &process_state,
            &live_ip_state,
            &ssh_port_state,
            &ssh_auth_state,
            authoritative_target_present,
        );
        if ssh_port_status == "open" {
            ssh_port_open_count += 1;
        }
        let ready = process_present
            && matches!(
                live_ip_state,
                ProbeState::Ok { .. } | ProbeState::Fallback { .. }
            )
            && ssh_port_status == "open"
            && authoritative_target_present;
        if ready {
            ready_count += 1;
            if inventory_match.is_some() {
                ready_inventory_states.push(LocalUtmReadyState {
                    alias: inventory_alias.clone().unwrap_or_else(|| utm_name.clone()),
                    utm_name: utm_name.clone(),
                    process_present,
                    live_ip: live_ip.clone(),
                    ssh_port_status: ssh_port_status.clone(),
                    ssh_auth_status: match &ssh_auth_state {
                        ProbeState::Ok { value } | ProbeState::Fallback { value, .. } => {
                            value.clone()
                        }
                        ProbeState::Missing { reason } | ProbeState::Error { reason } => {
                            reason.clone()
                        }
                    },
                });
            }
        }

        entries.push(json!({
            "alias": inventory_alias.clone().unwrap_or_else(|| utm_name.clone()),
            "bundle_path": bundle_path.display().to_string(),
            "utm_name": utm_name,
            "controller": {
                "type": "local_utm",
                "bundle_path": bundle_path.display().to_string(),
            },
            "inventory_match": inventory_match.is_some(),
            "inventory_alias": inventory_alias,
            "inventory_node_id": inventory_node_id,
            "inventory_lab_role": inventory_lab_role,
            "inventory_ssh_target": inventory_ssh_target,
            "inventory_ssh_user": inventory_ssh_user,
            "inventory_last_known_ip": inventory_last_known_ip,
            "inventory_mesh_ip": inventory_mesh_ip,
            "inventory_controller_bundle_path": inventory_controller_bundle_path,
            "inventory_controller_utm_name": inventory_controller_utm_name,
            "live_ip": live_ip,
            "live_ip_source": live_ip_source,
            "ssh_target": authoritative_ssh_target.clone().or(advisory_ssh_target.clone()),
            "authoritative_ssh_target": authoritative_ssh_target,
            "advisory_ssh_target": advisory_ssh_target,
            "ssh_target_source": ssh_target_source,
            "ssh_user": ssh_user,
            "ssh_port": ssh_port,
            "ssh_port_status": ssh_port_status,
            "ssh_port_error": ssh_port_error,
            "utm_process_present": process_present,
            "ready": ready,
            "process_state": process_state,
            "live_ip_state": live_ip_state,
            "ssh_port_state": ssh_port_state,
            "ssh_auth_state": ssh_auth_state,
            "readiness": readiness,
            "notes": discovery_notes,
        }));
    }

    let overall_status = if ready_count == entries.len() {
        "complete"
    } else {
        "partial"
    };
    let inventory_update = if config.update_inventory_live_ips {
        let inventory_path = config.inventory_path.as_deref().ok_or_else(|| {
            "vm-lab-discover-local-utm --update-inventory-live-ips requires --inventory".to_string()
        })?;
        Some(if matched_inventory_count == 0 {
            format!(
                "inventory live IP update skipped because no inventory-matched local UTM bundles were discovered in {}",
                inventory_path.display()
            )
        } else if ready_inventory_states.len() != matched_inventory_count {
            format!(
                "inventory live IP update skipped because only {}/{} inventory-matched local UTM bundles were execution-ready",
                ready_inventory_states.len(),
                matched_inventory_count
            )
        } else {
            persist_local_utm_ready_states_to_inventory(
                inventory_path,
                ready_inventory_states.as_slice(),
            )?
        })
    } else {
        None
    };
    let payload = json!({
        "schema_version": 1,
        "mode": "vm_lab_local_utm_discovery",
        "collected_at_utc": collected_at_utc_now(),
        "utm_documents_root": documents_root.display().to_string(),
        "inventory_path": config
            .inventory_path
            .as_ref()
            .map(|path| path.display().to_string()),
        "utmctl_path": utmctl_path.display().to_string(),
        "ssh_port": ssh_port,
        "summary": {
            "status": overall_status,
            "bundle_count": entries.len(),
            "inventory_matched_count": matched_inventory_count,
            "process_present_count": process_present_count,
            "live_ip_count": live_ip_count,
            "ssh_port_open_count": ssh_port_open_count,
            "ready_count": ready_count,
        },
        "inventory_error": inventory_error,
        "inventory_update": inventory_update,
        "entries": entries,
    });
    let rendered = serde_json::to_string_pretty(&payload)
        .map_err(|err| format!("serialize local UTM discovery report failed: {err}"))?;
    if let Some(report_dir) = config.report_dir.as_deref() {
        write_orchestration_artifact(
            report_dir.join("vm_lab_discover_local_utm.json").as_path(),
            rendered.as_str(),
        )?;
    }
    Ok(rendered)
}

pub fn execute_ops_vm_lab_discover_local_utm_summary(
    config: VmLabDiscoverLocalUtmConfig,
) -> Result<String, String> {
    let summary_report_dir = config.report_dir.clone();
    let report = execute_ops_vm_lab_discover_local_utm(config)?;
    let report: Value = serde_json::from_str(report.as_str())
        .map_err(|err| format!("parse local UTM discovery report failed: {err}"))?;
    let rendered = render_local_utm_discovery_summary(
        report
            .as_object()
            .ok_or_else(|| "local UTM discovery report must be a JSON object".to_string())?,
    )?;
    if let Some(report_dir) = summary_report_dir.as_deref() {
        write_orchestration_artifact(
            report_dir
                .join("vm_lab_discover_local_utm_summary.txt")
                .as_path(),
            rendered.as_str(),
        )?;
    }
    Ok(rendered)
}

fn render_local_utm_discovery_summary(
    report: &serde_json::Map<String, Value>,
) -> Result<String, String> {
    let summary = report
        .get("summary")
        .and_then(Value::as_object)
        .ok_or_else(|| "local UTM discovery report is missing summary data".to_string())?;
    let entries = report
        .get("entries")
        .and_then(Value::as_array)
        .ok_or_else(|| "local UTM discovery report is missing entries data".to_string())?;

    let summary_string = |key: &str| -> Result<String, String> {
        summary
            .get(key)
            .and_then(Value::as_str)
            .map(ToString::to_string)
            .ok_or_else(|| format!("local UTM discovery summary is missing string field: {key}"))
    };
    let summary_u64 = |key: &str| -> Result<u64, String> {
        summary
            .get(key)
            .and_then(Value::as_u64)
            .ok_or_else(|| format!("local UTM discovery summary is missing numeric field: {key}"))
    };
    let report_string = |key: &str| -> Option<String> {
        report
            .get(key)
            .and_then(Value::as_str)
            .map(ToString::to_string)
    };
    let entry_string = |entry: &Value, key: &str| -> Option<String> {
        entry
            .get(key)
            .and_then(Value::as_str)
            .map(ToString::to_string)
    };

    let mut lines = vec![
        format!("discovery_summary.status={}", summary_string("status")?),
        format!(
            "discovery_summary.bundle_count={}",
            summary_u64("bundle_count")?
        ),
        format!(
            "discovery_summary.inventory_matched_count={}",
            summary_u64("inventory_matched_count")?
        ),
        format!(
            "discovery_summary.live_ip_count={}",
            summary_u64("live_ip_count")?
        ),
        format!(
            "discovery_summary.ssh_port_open_count={}",
            summary_u64("ssh_port_open_count")?
        ),
        format!(
            "discovery_summary.ready_count={}",
            summary_u64("ready_count")?
        ),
    ];

    if let Some(value) = report_string("utm_documents_root") {
        lines.push(format!("discovery_summary.utm_documents_root={value}"));
    }
    if let Some(value) = report_string("inventory_path") {
        lines.push(format!("discovery_summary.inventory_path={value}"));
    }
    if let Some(value) = report_string("utmctl_path") {
        lines.push(format!("discovery_summary.utmctl_path={value}"));
    }
    if let Some(value) = report.get("inventory_error").and_then(Value::as_str)
        && !value.trim().is_empty()
    {
        lines.push(format!("discovery_summary.inventory_error={value}"));
    }
    if let Some(value) = report.get("inventory_update").and_then(Value::as_str)
        && !value.trim().is_empty()
    {
        lines.push(format!("discovery_summary.inventory_update={value}"));
    }

    for (index, entry) in entries.iter().enumerate() {
        let prefix = format!("node[{index}]");
        lines.push(format!(
            "{prefix}.alias={}",
            entry_string(entry, "alias").unwrap_or_else(|| "<unknown>".to_string())
        ));
        if let Some(value) = entry_string(entry, "inventory_alias") {
            lines.push(format!("{prefix}.inventory_alias={value}"));
        }
        if let Some(value) = entry_string(entry, "inventory_node_id") {
            lines.push(format!("{prefix}.node_id={value}"));
        }
        if let Some(value) = entry_string(entry, "inventory_lab_role") {
            lines.push(format!("{prefix}.role={value}"));
        }
        if let Some(value) = entry_string(entry, "inventory_ssh_target") {
            lines.push(format!("{prefix}.inventory_ssh_target={value}"));
        }
        if let Some(value) = entry_string(entry, "inventory_last_known_ip") {
            lines.push(format!("{prefix}.inventory_last_known_ip={value}"));
        }
        if let Some(value) = entry_string(entry, "inventory_mesh_ip") {
            lines.push(format!("{prefix}.inventory_mesh_ip={value}"));
        }
        if let Some(value) = entry_string(entry, "live_ip") {
            lines.push(format!("{prefix}.live_ip={value}"));
        }
        if let Some(value) = entry_string(entry, "ssh_target") {
            lines.push(format!("{prefix}.ssh_target={value}"));
        }
        if let Some(value) = entry_string(entry, "ssh_port_status") {
            lines.push(format!("{prefix}.ssh_port_status={value}"));
        }
        if let Some(readiness) = entry.get("readiness").and_then(Value::as_object) {
            for key in [
                "powered",
                "networked",
                "tcp_ready",
                "auth_ready",
                "execution_ready",
            ] {
                if let Some(value) = readiness.get(key).and_then(Value::as_bool) {
                    lines.push(format!("{prefix}.readiness.{key}={value}"));
                }
            }
            if let Some(reason_codes) = readiness.get("reason_codes").and_then(Value::as_array) {
                let joined = reason_codes
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(",");
                if !joined.is_empty() {
                    lines.push(format!("{prefix}.readiness.reason_codes={joined}"));
                }
            }
        }
        lines.push(format!(
            "{prefix}.ready={}",
            entry.get("ready").and_then(Value::as_bool).unwrap_or(false)
        ));
        if let Some(notes) = entry.get("notes").and_then(Value::as_array) {
            let notes = notes
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .collect::<Vec<_>>();
            if !notes.is_empty() {
                lines.push(format!("{prefix}.notes={}", notes.join(", ")));
            }
        }
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
        if target.platform_profile.platform == VmGuestPlatform::Windows {
            let bootstrap_target = remote_target_from_start_target(target);
            let host_key_line = bootstrap_windows_access_for_target(
                &bootstrap_target,
                None,
                None,
                None,
                None,
                22,
                timeout,
            )
            .map_err(|err| format!("{} Windows access bootstrap failed: {err}", target.alias))?;
            results.push(format!(
                "{} windows-access-bootstrap host_key={}",
                target.alias, host_key_line
            ));
        }
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
    ensure_optional_local_regular_file_path(
        config.ssh_identity_file.as_deref(),
        "SSH identity file",
    )?;
    ensure_optional_local_regular_file_path(
        config.known_hosts_path.as_deref(),
        "SSH known_hosts file",
    )?;
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
        config.ssh_identity_file.as_deref(),
        config.known_hosts_path.as_deref(),
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
    ensure_optional_local_regular_file_path(
        config.ssh_identity_file.as_deref(),
        "SSH identity file",
    )?;
    ensure_optional_local_regular_file_path(
        config.known_hosts_path.as_deref(),
        "SSH known_hosts file",
    )?;
    let timeout = timeout_or_default(config.timeout_secs, DEFAULT_RUN_TIMEOUT_SECS);
    let mut results = Vec::new();
    for target in &targets {
        let remote_script = build_remote_argv_script_for_target(
            target,
            config.workdir.as_str(),
            config.program.as_str(),
            config.argv.as_slice(),
            config.sudo,
        )?;
        let effective_user = config.ssh_user.as_deref();
        let status = run_remote_shell_command_for_target(
            target,
            effective_user,
            config.ssh_identity_file.as_deref(),
            config.known_hosts_path.as_deref(),
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
            effective_user
                .or(target.ssh_user.as_deref())
                .unwrap_or("<ssh-default>"),
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
        ssh_identity_file: config.ssh_identity_file.clone(),
        known_hosts_path: config.known_hosts_path.clone(),
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
            ssh_identity_file: config.ssh_identity_file,
            known_hosts_path: config.known_hosts_path,
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
    ssh_identity_file: Option<&Path>,
    known_hosts_path: Option<&Path>,
    source: RepoSyncSource,
    dest_dir: &str,
    timeout: Duration,
) -> Result<Vec<String>, String> {
    ensure_no_control_chars("destination directory", dest_dir)?;
    if targets.iter().any(|target| {
        matches!(
            target.platform_profile.platform,
            VmGuestPlatform::Ios | VmGuestPlatform::Android
        )
    }) {
        return Err(
            "iOS and Android targets are scaffolding-only for vm-lab repo sync right now"
                .to_string(),
        );
    }
    let mut results = Vec::new();
    match source {
        RepoSyncSource::Git {
            repo_url,
            branch,
            remote,
        } => {
            for target in targets {
                let repo_sync_script = build_repo_sync_script_for_target(
                    target,
                    repo_url.as_str(),
                    dest_dir,
                    branch.as_str(),
                    remote.as_str(),
                )?;
                let status = run_remote_shell_command_for_target(
                    target,
                    ssh_user_override,
                    ssh_identity_file,
                    known_hosts_path,
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
                    ssh_user_override
                        .or(target.ssh_user.as_deref())
                        .unwrap_or("<ssh-default>"),
                ));
            }
        }
        RepoSyncSource::LocalSource { source_dir } => {
            let posix_archive = if targets.iter().any(|target| {
                matches!(
                    repo_sync_dispatch_kind_for_target(target, RepoSyncMode::LocalSource),
                    Ok(RepoSyncDispatchKind::PosixLocalArchive)
                )
            }) {
                Some(prepare_local_source_archive(source_dir.as_path(), timeout)?)
            } else {
                None
            };
            let windows_archive = if targets.iter().any(|target| {
                matches!(
                    repo_sync_dispatch_kind_for_target(target, RepoSyncMode::LocalSource),
                    Ok(RepoSyncDispatchKind::WindowsZipLocalArchive)
                )
            }) {
                Some(prepare_local_source_zip_archive(
                    source_dir.as_path(),
                    timeout,
                )?)
            } else {
                None
            };
            for target in targets {
                let archive =
                    match repo_sync_dispatch_kind_for_target(target, RepoSyncMode::LocalSource)? {
                        RepoSyncDispatchKind::WindowsZipLocalArchive => windows_archive
                            .as_ref()
                            .ok_or_else(|| {
                                format!(
                                    "missing Windows ZIP local source archive for {}",
                                    target.label
                                )
                            })?
                            .path
                            .as_path(),
                        RepoSyncDispatchKind::PosixLocalArchive => posix_archive
                            .as_ref()
                            .ok_or_else(|| {
                                format!("missing POSIX local source archive for {}", target.label)
                            })?
                            .path
                            .as_path(),
                        other => {
                            return Err(format!(
                                "local source sync dispatch mismatch for {}: {other:?}",
                                target.label
                            ));
                        }
                    };
                sync_local_source_archive_to_target(
                    archive,
                    target,
                    ssh_user_override,
                    ssh_identity_file,
                    known_hosts_path,
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
                    ssh_user_override
                        .or(target.ssh_user.as_deref())
                        .unwrap_or("<ssh-default>"),
                ));
            }
        }
    }
    Ok(results)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RepoSyncMode {
    Git,
    LocalSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RepoSyncDispatchKind {
    PosixGit,
    WindowsPowershellGit,
    PosixLocalArchive,
    WindowsZipLocalArchive,
}

fn repo_sync_dispatch_kind_for_target(
    target: &RemoteTarget,
    mode: RepoSyncMode,
) -> Result<RepoSyncDispatchKind, String> {
    match (mode, target.platform_profile.platform) {
        (RepoSyncMode::Git, VmGuestPlatform::Linux) => Ok(RepoSyncDispatchKind::PosixGit),
        (RepoSyncMode::Git, VmGuestPlatform::Windows) => {
            Ok(RepoSyncDispatchKind::WindowsPowershellGit)
        }
        (RepoSyncMode::Git, other) => Err(format!(
            "repo sync is not implemented for platform={} target={}",
            other.as_str(),
            target.label
        )),
        (RepoSyncMode::LocalSource, VmGuestPlatform::Linux | VmGuestPlatform::Macos) => {
            Ok(RepoSyncDispatchKind::PosixLocalArchive)
        }
        (RepoSyncMode::LocalSource, VmGuestPlatform::Windows) => {
            Ok(RepoSyncDispatchKind::WindowsZipLocalArchive)
        }
        (RepoSyncMode::LocalSource, VmGuestPlatform::Ios | VmGuestPlatform::Android) => {
            Err(format!(
                "local source sync is intentionally scaffold-only for platform={} target={}",
                target.platform_profile.platform.as_str(),
                target.label
            ))
        }
    }
}

fn append_target_platform_metadata(
    lines: &mut Vec<String>,
    env_prefix: &str,
    target: &RoleTarget,
) -> Result<(), String> {
    let prefix = env_prefix.to_ascii_uppercase();
    lines.push(format_env_assignment(
        format!("{}_PLATFORM", prefix).as_str(),
        target.platform_profile.platform.as_str(),
    )?);
    lines.push(format_env_assignment(
        format!("{}_REMOTE_SHELL", prefix).as_str(),
        target.platform_profile.remote_shell.as_str(),
    )?);
    lines.push(format_env_assignment(
        format!("{}_GUEST_EXEC_MODE", prefix).as_str(),
        target.platform_profile.guest_exec_mode.as_str(),
    )?);
    lines.push(format_env_assignment(
        format!("{}_SERVICE_MANAGER", prefix).as_str(),
        target.platform_profile.service_manager.as_str(),
    )?);
    lines.push(format_env_assignment(
        format!("{}_RUSTYNET_SRC_DIR", prefix).as_str(),
        target.rustynet_src_dir.as_deref().unwrap_or(""),
    )?);
    Ok(())
}

fn append_empty_target_platform_metadata(
    lines: &mut Vec<String>,
    env_prefix: &str,
) -> Result<(), String> {
    let prefix = env_prefix.to_ascii_uppercase();
    lines.push(format_env_assignment(
        format!("{}_PLATFORM", prefix).as_str(),
        "",
    )?);
    lines.push(format_env_assignment(
        format!("{}_REMOTE_SHELL", prefix).as_str(),
        "",
    )?);
    lines.push(format_env_assignment(
        format!("{}_GUEST_EXEC_MODE", prefix).as_str(),
        "",
    )?);
    lines.push(format_env_assignment(
        format!("{}_SERVICE_MANAGER", prefix).as_str(),
        "",
    )?);
    lines.push(format_env_assignment(
        format!("{}_RUSTYNET_SRC_DIR", prefix).as_str(),
        "",
    )?);
    Ok(())
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
    let (resolved_source_mode, resolved_repo_ref) = resolve_iteration_source_selection(
        config.source_mode.as_deref(),
        config.repo_ref.as_deref(),
        false,
        false,
        false,
    )?;

    let mut lines = vec![
        "# Generated by rustynet-cli ops vm-lab-write-live-lab-profile".to_string(),
        format_env_assignment("EXIT_TARGET", exit_target.normalized_target.as_str())?,
        format_env_assignment("CLIENT_TARGET", client_target.normalized_target.as_str())?,
        format_env_assignment(
            "SSH_IDENTITY_FILE",
            config.ssh_identity_file.display().to_string().as_str(),
        )?,
    ];
    if let Some(utm_name) = exit_target.utm_name.as_deref() {
        lines.push(format_env_assignment("EXIT_UTM_NAME", utm_name)?);
    }
    append_target_platform_metadata(&mut lines, "EXIT", &exit_target)?;
    if let Some(utm_name) = client_target.utm_name.as_deref() {
        lines.push(format_env_assignment("CLIENT_UTM_NAME", utm_name)?);
    }
    append_target_platform_metadata(&mut lines, "CLIENT", &client_target)?;
    if let Some(target) = entry_target {
        lines.push(format_env_assignment(
            "ENTRY_TARGET",
            target.normalized_target.as_str(),
        )?);
        if let Some(utm_name) = target.utm_name.as_deref() {
            lines.push(format_env_assignment("ENTRY_UTM_NAME", utm_name)?);
        }
        append_target_platform_metadata(&mut lines, "ENTRY", &target)?;
    } else {
        append_empty_target_platform_metadata(&mut lines, "ENTRY")?;
    }
    if let Some(target) = aux_target {
        lines.push(format_env_assignment(
            "AUX_TARGET",
            target.normalized_target.as_str(),
        )?);
        if let Some(utm_name) = target.utm_name.as_deref() {
            lines.push(format_env_assignment("AUX_UTM_NAME", utm_name)?);
        }
        append_target_platform_metadata(&mut lines, "AUX", &target)?;
    } else {
        append_empty_target_platform_metadata(&mut lines, "AUX")?;
    }
    if let Some(target) = extra_target {
        lines.push(format_env_assignment(
            "EXTRA_TARGET",
            target.normalized_target.as_str(),
        )?);
        if let Some(utm_name) = target.utm_name.as_deref() {
            lines.push(format_env_assignment("EXTRA_UTM_NAME", utm_name)?);
        }
        append_target_platform_metadata(&mut lines, "EXTRA", &target)?;
    } else {
        append_empty_target_platform_metadata(&mut lines, "EXTRA")?;
    }
    match fifth_client_target {
        Some(target) => {
            lines.push(format_env_assignment(
                "FIFTH_CLIENT_TARGET",
                target.normalized_target.as_str(),
            )?);
            if let Some(utm_name) = target.utm_name.as_deref() {
                lines.push(format_env_assignment("FIFTH_CLIENT_UTM_NAME", utm_name)?);
            }
            append_target_platform_metadata(&mut lines, "FIFTH_CLIENT", &target)?;
        }
        None => {
            // Keep five-node profiles explicitly non-interactive by declaring the
            // optional sixth-node slots as intentionally empty.
            lines.push(format_env_assignment("FIFTH_CLIENT_TARGET", "")?);
            lines.push(format_env_assignment("FIFTH_CLIENT_UTM_NAME", "")?);
            append_empty_target_platform_metadata(&mut lines, "FIFTH_CLIENT")?;
        }
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
    lines.push(format_env_assignment(
        "SOURCE_MODE",
        resolved_source_mode.as_str(),
    )?);
    if let Some(value) = resolved_repo_ref.as_deref() {
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

fn default_inventory_alias_for_lab_roles(
    inventory_path: &Path,
    role_labels: &[&str],
) -> Result<Option<String>, String> {
    let inventory = load_inventory(inventory_path)?;
    let matches = inventory
        .into_iter()
        .filter(|entry| {
            entry
                .lab_role
                .as_deref()
                .map(|value| role_labels.contains(&value))
                .unwrap_or(false)
        })
        .map(|entry| entry.alias)
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [] => Ok(None),
        [alias] => Ok(Some(alias.clone())),
        _ => Err(format!(
            "multiple inventory entries match lab roles {}: {}",
            role_labels.join(","),
            matches.join(", ")
        )),
    }
}

fn push_unique_alias(aliases: &mut Vec<String>, alias: Option<String>) {
    if let Some(alias) = alias
        && !aliases.iter().any(|existing| existing == &alias)
    {
        aliases.push(alias);
    }
}

fn resolve_live_lab_vm_aliases(
    inventory_path: &Path,
    exit_vm: Option<&str>,
    client_vm: Option<&str>,
    entry_vm: Option<&str>,
    aux_vm: Option<&str>,
    extra_vm: Option<&str>,
    fifth_client_vm: Option<&str>,
) -> Result<Vec<String>, String> {
    let mut aliases = Vec::new();
    push_unique_alias(
        &mut aliases,
        match exit_vm {
            Some(value) => Some(value.to_string()),
            None => default_inventory_alias_for_lab_roles(inventory_path, &["exit"])?,
        },
    );
    push_unique_alias(
        &mut aliases,
        match client_vm {
            Some(value) => Some(value.to_string()),
            None => default_inventory_alias_for_lab_roles(inventory_path, &["client"])?,
        },
    );
    push_unique_alias(
        &mut aliases,
        match entry_vm {
            Some(value) => Some(value.to_string()),
            None => default_inventory_alias_for_lab_roles(inventory_path, &["entry", "relay"])?,
        },
    );
    push_unique_alias(
        &mut aliases,
        match aux_vm {
            Some(value) => Some(value.to_string()),
            None => default_inventory_alias_for_lab_roles(inventory_path, &["aux"])?,
        },
    );
    push_unique_alias(
        &mut aliases,
        match extra_vm {
            Some(value) => Some(value.to_string()),
            None => default_inventory_alias_for_lab_roles(inventory_path, &["extra"])?,
        },
    );
    push_unique_alias(
        &mut aliases,
        match fifth_client_vm {
            Some(value) => Some(value.to_string()),
            None => default_inventory_alias_for_lab_roles(inventory_path, &["fifth_client"])?,
        },
    );
    if aliases.is_empty() {
        return Err(
            "could not resolve any live-lab VM aliases from explicit flags or inventory lab_role metadata"
                .to_string(),
        );
    }
    Ok(aliases)
}

fn parse_vm_lab_command_result(text: &str) -> Result<VmLabCommandResult, String> {
    serde_json::from_str(text).map_err(|err| format!("parse vm-lab command result failed: {err}"))
}

fn selected_local_utm_readiness_from_report(
    report_text: &str,
    selected_aliases: &[String],
) -> Result<LocalUtmSelectedReadinessSummary, String> {
    let report: LocalUtmDiscoveryReport = serde_json::from_str(report_text)
        .map_err(|err| format!("parse local UTM discovery report failed: {err}"))?;
    let entries_by_alias = report
        .entries
        .into_iter()
        .map(|entry| {
            let alias = entry.alias.clone();
            (alias, entry)
        })
        .collect::<BTreeMap<_, _>>();

    let mut ready_aliases = Vec::new();
    let mut unready_entries = Vec::new();
    let mut missing_aliases = Vec::new();
    for alias in selected_aliases {
        let Some(entry) = entries_by_alias.get(alias.as_str()) else {
            missing_aliases.push(alias.clone());
            continue;
        };
        if entry.readiness.execution_ready {
            ready_aliases.push(alias.clone());
        } else {
            unready_entries.push(LocalUtmSelectedReadinessEntry {
                alias: alias.clone(),
                reason_codes: entry.readiness.reason_codes.clone(),
            });
        }
    }
    if !missing_aliases.is_empty() {
        return Err(format!(
            "local UTM discovery did not report the selected aliases: {}",
            missing_aliases.join(", ")
        ));
    }
    Ok(LocalUtmSelectedReadinessSummary {
        ready_aliases,
        unready_entries,
    })
}

fn render_selected_local_utm_readiness(summary: &LocalUtmSelectedReadinessSummary) -> String {
    let ready = if summary.ready_aliases.is_empty() {
        "none".to_string()
    } else {
        summary.ready_aliases.join(", ")
    };
    let unready = if summary.unready_entries.is_empty() {
        "none".to_string()
    } else {
        summary
            .unready_entries
            .iter()
            .map(|entry| {
                if entry.reason_codes.is_empty() {
                    entry.alias.clone()
                } else {
                    format!("{} ({})", entry.alias, entry.reason_codes.join(","))
                }
            })
            .collect::<Vec<_>>()
            .join("; ")
    };
    format!("ready={ready}; unready={unready}")
}

fn not_execution_ready_aliases(summary: &LocalUtmSelectedReadinessSummary) -> Vec<String> {
    summary
        .unready_entries
        .iter()
        .map(|entry| entry.alias.clone())
        .collect()
}

fn stage_outcome(
    stage: &str,
    status: VmLabStageStatus,
    summary: impl Into<String>,
    artifacts: Vec<PathBuf>,
) -> VmLabStageOutcome {
    VmLabStageOutcome {
        stage: stage.to_string(),
        status,
        summary: summary.into(),
        artifacts: artifacts
            .into_iter()
            .map(|path| path.display().to_string())
            .collect(),
    }
}

fn append_unique_stage_outcomes(
    outcomes: &mut Vec<VmLabStageOutcome>,
    additional: &[VmLabStageOutcome],
) {
    let mut seen = outcomes
        .iter()
        .map(|outcome| outcome.stage.clone())
        .collect::<HashSet<_>>();
    for outcome in additional {
        if seen.insert(outcome.stage.clone()) {
            outcomes.push(outcome.clone());
        }
    }
}

fn write_orchestration_artifact(path: &Path, contents: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "create orchestration artifact dir failed ({}): {err}",
                parent.display()
            )
        })?;
    }
    fs::write(path, contents).map_err(|err| {
        format!(
            "write orchestration artifact failed ({}): {err}",
            path.display()
        )
    })
}

fn orchestrated_command_status(
    outcomes: &[VmLabStageOutcome],
    warnings: &[String],
) -> VmLabCommandOverallStatus {
    if outcomes
        .iter()
        .any(|outcome| outcome.status == VmLabStageStatus::Fail)
    {
        VmLabCommandOverallStatus::Fail
    } else if !warnings.is_empty()
        || outcomes
            .iter()
            .any(|outcome| outcome.status == VmLabStageStatus::Skipped)
    {
        VmLabCommandOverallStatus::Partial
    } else {
        VmLabCommandOverallStatus::Pass
    }
}

fn finalize_vm_lab_orchestration_result(
    command: &str,
    report_dir: &Path,
    orchestration_dir: &Path,
    outcomes: Vec<VmLabStageOutcome>,
    warnings: Vec<String>,
    next_actions: Vec<String>,
) -> Result<String, String> {
    let overall_status = orchestrated_command_status(outcomes.as_slice(), warnings.as_slice());
    let rendered = serialize_vm_lab_command_result(&VmLabCommandResult {
        command: command.to_string(),
        overall_status: overall_status.clone(),
        report_dir: report_dir.display().to_string(),
        outcomes,
        warnings,
        next_actions,
    })?;
    write_orchestration_artifact(
        orchestration_dir.join("orchestrate_result.json").as_path(),
        rendered.as_str(),
    )?;
    match overall_status {
        VmLabCommandOverallStatus::Fail => Err(rendered),
        VmLabCommandOverallStatus::Pass | VmLabCommandOverallStatus::Partial => Ok(rendered),
    }
}

fn build_vm_lab_command_result_output(
    command: &str,
    report_dir: Option<&Path>,
    fallback_report_dir: &Path,
    artifact_filename: &str,
    outcomes: Vec<VmLabStageOutcome>,
    warnings: Vec<String>,
    next_actions: Vec<String>,
) -> Result<(String, VmLabCommandOverallStatus), String> {
    let overall_status = orchestrated_command_status(outcomes.as_slice(), warnings.as_slice());
    let rendered = serialize_vm_lab_command_result(&VmLabCommandResult {
        command: command.to_string(),
        overall_status: overall_status.clone(),
        report_dir: report_dir_label(report_dir, fallback_report_dir),
        outcomes,
        warnings,
        next_actions,
    })?;
    if let Some(report_dir) = report_dir {
        write_orchestration_artifact(
            report_dir.join(artifact_filename).as_path(),
            rendered.as_str(),
        )?;
    }
    Ok((rendered, overall_status))
}

fn resolve_setup_live_lab_selection(
    config: &VmLabSetupLiveLabConfig,
) -> Result<LiveLabSetupSelection, String> {
    if let Some(profile_path) = config.profile_path.as_deref() {
        execute_ops_vm_lab_validate_live_lab_profile(VmLabValidateLiveLabProfileConfig {
            profile_path: profile_path.to_path_buf(),
            expected_backend: None,
            expected_source_mode: None,
            require_five_node: false,
        })?;
        let profile = load_live_lab_profile(profile_path)?;
        ensure_live_lab_profile_linux_only(&profile, "vm-lab-setup-live-lab")?;
        return Ok(LiveLabSetupSelection {
            profile_path: profile_path.to_path_buf(),
            profile_generated: false,
            profile_generation_summary: None,
        });
    }

    let profile_path = config
        .profile_output_path
        .clone()
        .unwrap_or_else(|| default_live_lab_setup_profile_path(config.report_dir.as_path()));
    let exit_vm = match config.exit_vm.clone() {
        Some(value) => Some(value),
        None => default_inventory_alias_for_lab_roles(config.inventory_path.as_path(), &["exit"])?,
    };
    let client_vm = match config.client_vm.clone() {
        Some(value) => Some(value),
        None => {
            default_inventory_alias_for_lab_roles(config.inventory_path.as_path(), &["client"])?
        }
    };
    let entry_vm = match config.entry_vm.clone() {
        Some(value) => Some(value),
        None => default_inventory_alias_for_lab_roles(
            config.inventory_path.as_path(),
            &["entry", "relay"],
        )?,
    };
    let aux_vm = match config.aux_vm.clone() {
        Some(value) => Some(value),
        None => default_inventory_alias_for_lab_roles(config.inventory_path.as_path(), &["aux"])?,
    };
    let extra_vm = match config.extra_vm.clone() {
        Some(value) => Some(value),
        None => default_inventory_alias_for_lab_roles(config.inventory_path.as_path(), &["extra"])?,
    };
    let fifth_client_vm = match config.fifth_client_vm.clone() {
        Some(value) => Some(value),
        None => default_inventory_alias_for_lab_roles(
            config.inventory_path.as_path(),
            &["fifth_client"],
        )?,
    };
    let profile_summary =
        execute_ops_vm_lab_write_live_lab_profile(VmLabWriteLiveLabProfileConfig {
            inventory_path: config.inventory_path.clone(),
            output_path: profile_path.clone(),
            exit_vm,
            exit_target: None,
            client_vm,
            client_target: None,
            entry_vm,
            entry_target: None,
            aux_vm,
            aux_target: None,
            extra_vm,
            extra_target: None,
            fifth_client_vm,
            fifth_client_target: None,
            require_same_network: config.require_same_network,
            ssh_identity_file: config.ssh_identity_file.clone(),
            ssh_known_hosts_file: config.known_hosts_path.clone(),
            ssh_allow_cidrs: None,
            network_id: None,
            traversal_ttl_secs: None,
            cross_network_nat_profiles: None,
            cross_network_required_nat_profiles: None,
            cross_network_impairment_profile: None,
            backend: None,
            source_mode: config.source_mode.clone(),
            repo_ref: config.repo_ref.clone(),
            report_dir: Some(config.report_dir.clone()),
        })?;
    execute_ops_vm_lab_validate_live_lab_profile(VmLabValidateLiveLabProfileConfig {
        profile_path: profile_path.clone(),
        expected_backend: None,
        expected_source_mode: None,
        require_five_node: false,
    })?;
    let profile = load_live_lab_profile(profile_path.as_path())?;
    ensure_live_lab_profile_linux_only(&profile, "vm-lab-setup-live-lab")?;
    Ok(LiveLabSetupSelection {
        profile_path,
        profile_generated: true,
        profile_generation_summary: Some(profile_summary),
    })
}

fn render_vm_lab_command_result(
    command: &str,
    report_dir: &Path,
    summary: &LiveLabStageSummary,
    records: &[LiveLabStageRecord],
    warnings: Vec<String>,
    next_actions: Vec<String>,
    overall_status_override: Option<VmLabCommandOverallStatus>,
) -> Result<String, String> {
    let overall_status =
        overall_status_override.unwrap_or_else(|| command_status_from_summary(summary));
    serialize_vm_lab_command_result(&VmLabCommandResult {
        command: command.to_string(),
        overall_status,
        report_dir: report_dir.display().to_string(),
        outcomes: stage_outcomes_from_records(records),
        warnings,
        next_actions,
    })
}

pub fn execute_ops_vm_lab_setup_live_lab(
    config: VmLabSetupLiveLabConfig,
) -> Result<String, String> {
    ensure_local_regular_file_path(config.script_path.as_path(), "live-lab script")?;
    ensure_local_regular_file_path(config.ssh_identity_file.as_path(), "SSH identity file")?;
    ensure_optional_local_regular_file_path(
        config.known_hosts_path.as_deref(),
        "SSH known_hosts file",
    )?;
    if let Some(stage) = config.resume_from.as_deref()
        && !setup_stage_names().contains(&stage)
    {
        return Err(format!(
            "unsupported --resume-from stage for vm-lab-setup-live-lab: {stage}"
        ));
    }
    if let Some(stage) = config.rerun_stage.as_deref()
        && !setup_stage_names().contains(&stage)
    {
        return Err(format!(
            "unsupported --rerun-stage for vm-lab-setup-live-lab: {stage}"
        ));
    }
    if config.resume_from.is_some() && config.rerun_stage.is_some() {
        return Err(
            "vm-lab-setup-live-lab accepts either --resume-from or --rerun-stage, not both"
                .to_string(),
        );
    }
    let report_dir = resolve_absolute_path(config.report_dir.as_path())?;
    let setup_reuse_requested = config.resume_from.is_some() || config.rerun_stage.is_some();
    if setup_reuse_requested {
        if !report_dir.exists() {
            return Err(format!(
                "vm-lab-setup-live-lab resume/rerun requires an existing report dir: {}",
                report_dir.display()
            ));
        }
        if !report_dir_contains_regular_entries(report_dir.as_path())? {
            return Err(format!(
                "vm-lab-setup-live-lab resume/rerun requires an existing provenance-bound report dir with setup state: {}",
                report_dir.display()
            ));
        }
    } else {
        ensure_report_dir_fresh(report_dir.as_path(), "vm-lab-setup-live-lab")?;
    }
    fs::create_dir_all(report_dir.as_path()).map_err(|err| {
        format!(
            "create setup report directory failed ({}): {err}",
            report_dir.display()
        )
    })?;
    let (resolved_source_mode, resolved_repo_ref) = resolve_iteration_source_selection(
        config.source_mode.as_deref(),
        config.repo_ref.as_deref(),
        false,
        false,
        false,
    )?;
    let selection = if setup_reuse_requested {
        let selection = match config.profile_path.as_deref() {
            Some(profile_path) => {
                execute_ops_vm_lab_validate_live_lab_profile(VmLabValidateLiveLabProfileConfig {
                    profile_path: profile_path.to_path_buf(),
                    expected_backend: None,
                    expected_source_mode: None,
                    require_five_node: false,
                })?;
                LiveLabSetupSelection {
                    profile_path: profile_path.to_path_buf(),
                    profile_generated: false,
                    profile_generation_summary: None,
                }
            }
            None => resolve_setup_selection_from_existing_manifest(report_dir.as_path())?,
        };
        let expectation = LiveLabSetupManifestExpectation {
            report_dir: report_dir.clone(),
            profile_path: selection.profile_path.clone(),
            script_path: config.script_path.clone(),
            inventory_path: Some(config.inventory_path.clone()),
            source_mode: resolved_source_mode.clone(),
            repo_ref: resolved_repo_ref.clone(),
            require_same_network: Some(config.require_same_network),
            dry_run: Some(config.dry_run),
            max_parallel_node_workers: config.max_parallel_node_workers,
        };
        validate_setup_manifest(report_dir.as_path(), &expectation)?;
        let report_state = validate_report_state(report_dir.as_path())?;
        if report_state.run_complete || report_state.last_run.is_some() {
            return Err(format!(
                "report dir {} already contains run provenance and cannot be reused for setup",
                report_dir.display()
            ));
        }
        if live_lab_report_has_non_setup_stage_records(report_dir.as_path())? {
            return Err(format!(
                "report dir {} already contains non-setup stage records and cannot be reused for setup",
                report_dir.display()
            ));
        }
        selection
    } else {
        let mut selection_config = config.clone();
        selection_config.report_dir = report_dir.clone();
        let selection = resolve_setup_live_lab_selection(&selection_config)?;
        let manifest = build_setup_manifest(&LiveLabSetupManifestInput {
            report_dir: report_dir.clone(),
            profile_path: selection.profile_path.clone(),
            script_path: config.script_path.clone(),
            inventory_path: Some(config.inventory_path.clone()),
            source_mode: resolved_source_mode.clone(),
            repo_ref: resolved_repo_ref.clone(),
            require_same_network: Some(config.require_same_network),
            dry_run: config.dry_run,
            max_parallel_node_workers: config.max_parallel_node_workers,
        })?;
        write_setup_manifest(report_dir.as_path(), &manifest)?;
        let report_state = initial_report_state(report_dir.as_path(), &manifest)?;
        write_report_state(report_dir.as_path(), &report_state)?;
        selection
    };
    let timeout = timeout_or_default(config.timeout_secs, DEFAULT_LIVE_LAB_TIMEOUT_SECS);
    let mut command = Command::new("bash");
    command.arg(config.script_path.as_path());
    command
        .arg("--profile")
        .arg(selection.profile_path.as_path());
    command.arg("--report-dir").arg(report_dir.as_path());
    command.arg("--setup-only");
    if config.dry_run {
        command.arg("--dry-run");
    }
    command
        .arg("--source-mode")
        .arg(resolved_source_mode.as_str());
    if let Some(value) = resolved_repo_ref.as_deref() {
        command.arg("--repo-ref").arg(value);
    }
    if let Some(stage) = config.resume_from.as_deref() {
        command.arg("--resume-from").arg(stage);
        command.arg("--preserve-report-state");
    }
    if let Some(stage) = config.rerun_stage.as_deref() {
        command.arg("--rerun-stage").arg(stage);
        command.arg("--preserve-report-state");
    }
    if let Some(max_parallel_node_workers) = config.max_parallel_node_workers {
        command
            .arg("--max-parallel-node-workers")
            .arg(max_parallel_node_workers.to_string());
    }

    let status = run_status_with_timeout_passthrough(&mut command, timeout)
        .map_err(|err| format!("live-lab setup failed: {err}"))?;
    validate_live_lab_run_artifacts(report_dir.as_path())?;
    let summary = summarize_live_lab_report(report_dir.as_path(), false, 1)?;
    let records = parse_live_lab_stage_records(report_dir.as_path())?;
    let mut warnings = Vec::new();
    if selection.profile_generated {
        warnings.push(format!(
            "generated profile at {}",
            selection.profile_path.display()
        ));
    }
    if let Some(profile_summary) = selection.profile_generation_summary {
        warnings.push(profile_summary);
    }
    let state_update_error = if status.success() {
        match update_report_state_setup_complete(report_dir.as_path()) {
            Ok(()) => None,
            Err(err) => {
                warnings.push(err.clone());
                Some(err)
            }
        }
    } else {
        None
    };
    let next_actions = if status.success() && state_update_error.is_none() {
        vec![format!(
            "Run vm-lab-run-live-lab with --profile {} --report-dir {}",
            selection.profile_path.display(),
            report_dir.display()
        )]
    } else if state_update_error.is_some() {
        vec![format!(
            "Re-run vm-lab-setup-live-lab for report dir {} after fixing report-state persistence",
            report_dir.display()
        )]
    } else {
        vec![format!(
            "Run vm-lab-diagnose-live-lab-failure with --profile {} --report-dir {}",
            selection.profile_path.display(),
            report_dir.display()
        )]
    };
    let rendered = render_vm_lab_command_result(
        "vm-lab-setup-live-lab",
        report_dir.as_path(),
        &summary,
        &records,
        warnings,
        next_actions,
        state_update_error
            .as_ref()
            .map(|_| VmLabCommandOverallStatus::Fail),
    )?;
    if status.success() && state_update_error.is_none() {
        Ok(rendered)
    } else {
        Err(rendered)
    }
}

pub fn execute_ops_vm_lab_run_live_lab(config: VmLabRunLiveLabConfig) -> Result<String, String> {
    ensure_local_regular_file_path(config.profile_path.as_path(), "live-lab profile")?;
    ensure_local_regular_file_path(config.script_path.as_path(), "live-lab script")?;
    let profile = load_live_lab_profile(config.profile_path.as_path())?;
    ensure_live_lab_profile_linux_only(&profile, "vm-lab-run-live-lab")?;
    if let Some(value) = config.source_mode.as_deref() {
        ensure_no_control_chars("source mode", value)?;
    }
    if let Some(value) = config.repo_ref.as_deref() {
        ensure_no_control_chars("repo ref", value)?;
    }
    let (resolved_source_mode, resolved_repo_ref) = resolve_iteration_source_selection(
        config.source_mode.as_deref(),
        config.repo_ref.as_deref(),
        false,
        false,
        false,
    )?;

    let report_dir = match config.report_dir.clone() {
        Some(path) => path,
        None => profile
            .optional("REPORT_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                default_live_lab_report_root().join(format!("run_{}", unique_suffix()))
            }),
    };
    let report_dir = resolve_absolute_path(report_dir.as_path())?;
    let can_continue_from_setup = resolve_run_setup_reuse(
        report_dir.as_path(),
        config.profile_path.as_path(),
        config.script_path.as_path(),
        resolved_source_mode.as_str(),
        resolved_repo_ref.as_deref(),
        config.skip_setup,
    )?;
    if !can_continue_from_setup {
        ensure_report_dir_fresh(report_dir.as_path(), "vm-lab-run-live-lab")?;
        fs::create_dir_all(report_dir.as_path()).map_err(|err| {
            format!(
                "create live-lab report directory failed ({}): {err}",
                report_dir.display()
            )
        })?;
        let manifest = build_setup_manifest(&LiveLabSetupManifestInput {
            report_dir: report_dir.clone(),
            profile_path: config.profile_path.clone(),
            script_path: config.script_path.clone(),
            inventory_path: None,
            source_mode: resolved_source_mode.clone(),
            repo_ref: resolved_repo_ref.clone(),
            require_same_network: None,
            dry_run: config.dry_run,
            max_parallel_node_workers: None,
        })?;
        write_setup_manifest(report_dir.as_path(), &manifest)?;
        let report_state = initial_report_state(report_dir.as_path(), &manifest)?;
        write_report_state(report_dir.as_path(), &report_state)?;
    }
    let timeout = timeout_or_default(config.timeout_secs, DEFAULT_LIVE_LAB_TIMEOUT_SECS);
    let mut command = Command::new("bash");
    command.arg(config.script_path.as_path());
    command.arg("--profile").arg(config.profile_path.as_path());
    command.arg("--report-dir").arg(report_dir.as_path());
    if config.dry_run {
        command.arg("--dry-run");
    }
    if config.skip_setup || can_continue_from_setup {
        command.arg("--skip-setup");
        command.arg("--preserve-report-state");
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
    command
        .arg("--source-mode")
        .arg(resolved_source_mode.as_str());
    if let Some(value) = resolved_repo_ref.as_deref() {
        command.arg("--repo-ref").arg(value);
    }

    let status = run_status_with_timeout_passthrough(&mut command, timeout)
        .map_err(|err| format!("live-lab run failed: {err}"))?;
    validate_live_lab_run_artifacts(report_dir.as_path())?;
    let summary = summarize_live_lab_report(report_dir.as_path(), false, 1)?;
    let records = parse_live_lab_stage_records(report_dir.as_path())?;
    let release_gate_report = build_release_gate_completeness_report(
        &records,
        full_release_gate_requested(&profile, &config),
    );
    write_release_gate_completeness(report_dir.as_path(), &release_gate_report)?;
    let mut warnings = Vec::new();
    if can_continue_from_setup && !config.skip_setup {
        warnings.push(
            "auto-detected completed setup stages in report dir; continued with test stages only"
                .to_string(),
        );
    }
    let completeness_error = if release_gate_report.requested
        && !release_gate_report.missing_or_non_pass_stages.is_empty()
    {
        let message = format!(
            "full release-gate mode requested, but required stages were missing or not pass: {}",
            release_gate_report.missing_or_non_pass_stages.join(", ")
        );
        warnings.push(message.clone());
        Some(message)
    } else {
        None
    };
    let run_passed = status.success() && completeness_error.is_none();
    let full_release_evidence_complete =
        run_passed && release_gate_report.requested && release_gate_report.status == "complete";
    let state_update_error = match build_run_provenance(
        config.profile_path.as_path(),
        config.script_path.as_path(),
        resolved_source_mode.as_str(),
        resolved_repo_ref.as_deref(),
        &LiveLabRunModeFlags {
            dry_run: config.dry_run,
            skip_setup: config.skip_setup || can_continue_from_setup,
            skip_gates: config.skip_gates,
            skip_soak: config.skip_soak,
            skip_cross_network: config.skip_cross_network,
        },
    )
    .and_then(|run_provenance| {
        update_report_state_after_run(
            report_dir.as_path(),
            run_provenance,
            run_passed,
            release_gate_report.requested,
            full_release_evidence_complete,
        )
    }) {
        Ok(()) => None,
        Err(err) => {
            warnings.push(err.clone());
            Some(err)
        }
    };
    let next_actions = if status.success() && completeness_error.is_none() {
        Vec::new()
    } else if let Some(message) = completeness_error.as_ref() {
        vec![
            message.clone(),
            format!(
                "Inspect {} for the required stage set and rerun without skip flags",
                report_dir
                    .join(RELEASE_GATE_COMPLETENESS_RELATIVE_PATH)
                    .display()
            ),
        ]
    } else {
        vec![format!(
            "Run vm-lab-diagnose-live-lab-failure with --profile {} --report-dir {}",
            config.profile_path.display(),
            report_dir.display()
        )]
    };
    let rendered = render_vm_lab_command_result(
        "vm-lab-run-live-lab",
        report_dir.as_path(),
        &summary,
        &records,
        warnings,
        next_actions,
        state_update_error
            .as_ref()
            .map(|_| VmLabCommandOverallStatus::Fail)
            .or_else(|| {
                completeness_error
                    .as_ref()
                    .filter(|_| status.success())
                    .map(|_| VmLabCommandOverallStatus::Fail)
            }),
    )?;
    if status.success() && completeness_error.is_none() && state_update_error.is_none() {
        Ok(rendered)
    } else {
        Err(rendered)
    }
}

pub fn execute_ops_vm_lab_orchestrate_live_lab(
    config: VmLabOrchestrateLiveLabConfig,
) -> Result<String, String> {
    ensure_local_regular_file_path(config.script_path.as_path(), "live-lab script")?;
    ensure_local_regular_file_path(config.ssh_identity_file.as_path(), "SSH identity file")?;
    ensure_optional_local_regular_file_path(
        config.known_hosts_path.as_deref(),
        "SSH known_hosts file",
    )?;

    let report_dir = resolve_absolute_path(config.report_dir.as_path())?;
    ensure_report_dir_fresh(report_dir.as_path(), "vm-lab-orchestrate-live-lab")?;
    fs::create_dir_all(report_dir.as_path()).map_err(|err| {
        format!(
            "create orchestration report directory failed ({}): {err}",
            report_dir.display()
        )
    })?;
    let orchestration_dir = report_dir.join("orchestration");
    fs::create_dir_all(orchestration_dir.as_path()).map_err(|err| {
        format!(
            "create orchestration state directory failed ({}): {err}",
            orchestration_dir.display()
        )
    })?;
    let inventory_path = resolve_absolute_path(config.inventory_path.as_path())?;
    let selected_aliases = resolve_live_lab_vm_aliases(
        inventory_path.as_path(),
        config.exit_vm.as_deref(),
        config.client_vm.as_deref(),
        config.entry_vm.as_deref(),
        config.aux_vm.as_deref(),
        config.extra_vm.as_deref(),
        config.fifth_client_vm.as_deref(),
    )?;
    let effective_profile_path = match config.profile_path.clone() {
        Some(path) => resolve_absolute_path(path.as_path())?,
        None => config
            .profile_output_path
            .clone()
            .map(|path| resolve_absolute_path(path.as_path()))
            .transpose()?
            .unwrap_or_else(|| default_live_lab_setup_profile_path(report_dir.as_path())),
    };
    let discovery_timeout = timeout_or_default(
        config.discovery_timeout_secs,
        DEFAULT_UTM_IP_DISCOVERY_TIMEOUT_SECS,
    )
    .as_secs();
    let ready_timeout = timeout_or_default(
        config.ready_timeout_secs,
        DEFAULT_RESTART_READY_TIMEOUT_SECS,
    )
    .as_secs();

    let mut outcomes = Vec::new();
    let mut warnings = Vec::new();
    let mut next_actions = Vec::new();
    let mut diagnosis_artifact = None::<PathBuf>;

    let discover_config = VmLabDiscoverLocalUtmConfig {
        inventory_path: Some(inventory_path.clone()),
        utm_documents_root: config.utm_documents_root.clone(),
        utmctl_path: config.utmctl_path.clone(),
        ssh_identity_file: Some(config.ssh_identity_file.clone()),
        known_hosts_path: config.known_hosts_path.clone(),
        ssh_port: config.ssh_port,
        timeout_secs: discovery_timeout,
        update_inventory_live_ips: true,
        report_dir: None,
    };
    let initial_discovery = execute_ops_vm_lab_discover_local_utm(discover_config.clone())?;
    let initial_discovery_path = orchestration_dir.join("discover_initial.json");
    write_orchestration_artifact(initial_discovery_path.as_path(), initial_discovery.as_str())?;
    let initial_readiness =
        selected_local_utm_readiness_from_report(initial_discovery.as_str(), &selected_aliases)?;
    let mut final_readiness = initial_readiness.clone();
    let mut final_readiness_artifact = initial_discovery_path.clone();
    let unready_aliases = not_execution_ready_aliases(&initial_readiness);
    outcomes.push(stage_outcome(
        "discover_local_utm",
        VmLabStageStatus::Pass,
        format!(
            "selected aliases readiness: {}",
            render_selected_local_utm_readiness(&initial_readiness)
        ),
        vec![initial_discovery_path.clone()],
    ));

    if !unready_aliases.is_empty() {
        warnings.push(format!(
            "selected local UTM VMs were not execution-ready and required restart: {}",
            unready_aliases.join(", ")
        ));
        if config.dry_run {
            outcomes.push(stage_outcome(
                "restart_unready_vms",
                VmLabStageStatus::Skipped,
                format!(
                    "dry-run: would restart aliases {}",
                    unready_aliases.join(", ")
                ),
                vec![initial_discovery_path.clone()],
            ));
        } else {
            let restart_output = execute_ops_vm_lab_restart(VmLabRestartConfig {
                inventory_path: inventory_path.clone(),
                vm_aliases: unready_aliases.clone(),
                raw_targets: Vec::new(),
                select_all: false,
                utmctl_path: config
                    .utmctl_path
                    .clone()
                    .unwrap_or_else(default_utmctl_path),
                service: None,
                wait_ready: true,
                ssh_port: config.ssh_port,
                ready_timeout_secs: ready_timeout,
                ssh_user: None,
                ssh_identity_file: Some(config.ssh_identity_file.clone()),
                known_hosts_path: config.known_hosts_path.clone(),
                timeout_secs: config.timeout_secs,
                json_output: false,
                report_dir: Some(orchestration_dir.clone()),
            });
            let restart_path = orchestration_dir.join("restart_unready_vms.txt");
            match restart_output {
                Ok(output) => {
                    write_orchestration_artifact(restart_path.as_path(), output.as_str())?;
                    outcomes.push(stage_outcome(
                        "restart_unready_vms",
                        VmLabStageStatus::Pass,
                        format!("restarted aliases {}", unready_aliases.join(", ")),
                        vec![restart_path.clone()],
                    ));
                }
                Err(err) => {
                    write_orchestration_artifact(restart_path.as_path(), err.as_str())?;
                    outcomes.push(stage_outcome(
                        "restart_unready_vms",
                        VmLabStageStatus::Fail,
                        format!("restart failed for aliases {}", unready_aliases.join(", ")),
                        vec![initial_discovery_path.clone(), restart_path],
                    ));
                    next_actions.push(format!(
                        "Inspect {} and {}",
                        initial_discovery_path.display(),
                        orchestration_dir.join("restart_unready_vms.txt").display()
                    ));
                    return finalize_vm_lab_orchestration_result(
                        "vm-lab-orchestrate-live-lab",
                        report_dir.as_path(),
                        orchestration_dir.as_path(),
                        outcomes,
                        warnings,
                        next_actions,
                    );
                }
            }

            let rediscovery = execute_ops_vm_lab_discover_local_utm(discover_config)?;
            let rediscovery_path = orchestration_dir.join("discover_post_restart.json");
            write_orchestration_artifact(rediscovery_path.as_path(), rediscovery.as_str())?;
            let post_restart_readiness =
                selected_local_utm_readiness_from_report(rediscovery.as_str(), &selected_aliases)?;
            final_readiness = post_restart_readiness.clone();
            final_readiness_artifact = rediscovery_path.clone();
            let still_unready = not_execution_ready_aliases(&post_restart_readiness);
            let rediscovery_status = if still_unready.is_empty() {
                VmLabStageStatus::Pass
            } else {
                VmLabStageStatus::Fail
            };
            outcomes.push(stage_outcome(
                "rediscover_local_utm",
                rediscovery_status.clone(),
                format!(
                    "selected aliases readiness after restart: {}",
                    render_selected_local_utm_readiness(&post_restart_readiness)
                ),
                vec![rediscovery_path.clone()],
            ));
            if rediscovery_status == VmLabStageStatus::Fail {
                next_actions.push(format!(
                    "Inspect {} for remaining readiness blockers",
                    rediscovery_path.display()
                ));
                return finalize_vm_lab_orchestration_result(
                    "vm-lab-orchestrate-live-lab",
                    report_dir.as_path(),
                    orchestration_dir.as_path(),
                    outcomes,
                    warnings,
                    next_actions,
                );
            }
        }
    }

    if config.stop_after_ready {
        let readiness_complete = final_readiness.unready_entries.is_empty();
        if !readiness_complete {
            warnings.push(format!(
                "stop-after-ready ended before all selected aliases became execution-ready: {}",
                render_selected_local_utm_readiness(&final_readiness)
            ));
            next_actions.push(
                "Rerun without --dry-run or inspect the discovery artifacts for readiness blockers"
                    .to_string(),
            );
        } else {
            next_actions.push(format!(
                "Run ops vm-lab-setup-live-lab using report dir {}",
                report_dir.display()
            ));
        }
        outcomes.push(stage_outcome(
            "stop_after_ready",
            if readiness_complete {
                VmLabStageStatus::Pass
            } else {
                VmLabStageStatus::Skipped
            },
            format!(
                "selected aliases readiness: {}",
                render_selected_local_utm_readiness(&final_readiness)
            ),
            vec![final_readiness_artifact],
        ));
        return finalize_vm_lab_orchestration_result(
            "vm-lab-orchestrate-live-lab",
            report_dir.as_path(),
            orchestration_dir.as_path(),
            outcomes,
            warnings,
            next_actions,
        );
    }

    let setup_config = VmLabSetupLiveLabConfig {
        inventory_path: inventory_path.clone(),
        profile_path: config.profile_path.clone(),
        profile_output_path: config.profile_output_path.clone().or_else(|| {
            if config.profile_path.is_some() {
                None
            } else {
                Some(effective_profile_path.clone())
            }
        }),
        exit_vm: config.exit_vm.clone(),
        client_vm: config.client_vm.clone(),
        entry_vm: config.entry_vm.clone(),
        aux_vm: config.aux_vm.clone(),
        extra_vm: config.extra_vm.clone(),
        fifth_client_vm: config.fifth_client_vm.clone(),
        ssh_identity_file: config.ssh_identity_file.clone(),
        known_hosts_path: config.known_hosts_path.clone(),
        require_same_network: config.require_same_network,
        script_path: config.script_path.clone(),
        report_dir: report_dir.clone(),
        source_mode: config.source_mode.clone(),
        repo_ref: config.repo_ref.clone(),
        resume_from: None,
        rerun_stage: None,
        max_parallel_node_workers: config.max_parallel_node_workers,
        timeout_secs: config.timeout_secs,
        dry_run: config.dry_run,
    };
    let setup_result_path = orchestration_dir.join("setup_result.json");
    match execute_ops_vm_lab_setup_live_lab(setup_config) {
        Ok(rendered) => {
            write_orchestration_artifact(setup_result_path.as_path(), rendered.as_str())?;
            let result = parse_vm_lab_command_result(rendered.as_str())?;
            append_unique_stage_outcomes(&mut outcomes, result.outcomes.as_slice());
            warnings.extend(result.warnings);
        }
        Err(err) => {
            write_orchestration_artifact(setup_result_path.as_path(), err.as_str())?;
            match parse_vm_lab_command_result(err.as_str()) {
                Ok(result) => {
                    append_unique_stage_outcomes(&mut outcomes, result.outcomes.as_slice());
                    warnings.extend(result.warnings);
                    next_actions.extend(result.next_actions);
                }
                Err(parse_err) => {
                    warnings.push(parse_err);
                    outcomes.push(stage_outcome(
                        "vm_lab_setup_live_lab",
                        VmLabStageStatus::Fail,
                        err,
                        vec![setup_result_path.clone()],
                    ));
                }
            }
            if !config.skip_diagnose_on_failure
                && effective_profile_path.is_file()
                && report_dir.join("state/stages.tsv").exists()
            {
                let diagnose_result = execute_ops_vm_lab_diagnose_live_lab_failure(
                    VmLabDiagnoseLiveLabFailureConfig {
                        inventory_path: inventory_path.clone(),
                        profile_path: effective_profile_path.clone(),
                        report_dir: report_dir.clone(),
                        stage: None,
                        output_dir: None,
                        collect_artifacts: config.collect_artifacts_on_failure,
                        timeout_secs: config.timeout_secs,
                    },
                );
                let diagnose_path = orchestration_dir.join("diagnose_result.json");
                match diagnose_result {
                    Ok(rendered) => {
                        write_orchestration_artifact(diagnose_path.as_path(), rendered.as_str())?;
                        let result = parse_vm_lab_command_result(rendered.as_str())?;
                        diagnosis_artifact = Some(PathBuf::from(result.report_dir.clone()));
                        outcomes.push(stage_outcome(
                            "diagnose_live_lab_failure",
                            VmLabStageStatus::Pass,
                            "collected failure diagnostics after setup failure",
                            result
                                .outcomes
                                .into_iter()
                                .flat_map(|outcome| outcome.artifacts)
                                .map(PathBuf::from)
                                .collect(),
                        ));
                        warnings.extend(result.warnings);
                    }
                    Err(err) => {
                        write_orchestration_artifact(diagnose_path.as_path(), err.as_str())?;
                        warnings.push(format!(
                            "diagnose-on-failure after setup failure did not complete: {err}"
                        ));
                    }
                }
            }
            if next_actions.is_empty() {
                if let Some(path) = diagnosis_artifact.as_deref() {
                    next_actions.push(format!("Inspect diagnostics under {}", path.display()));
                } else {
                    next_actions.push(format!(
                        "Inspect {} and rerun vm-lab-diagnose-live-lab-failure if needed",
                        report_dir.display()
                    ));
                }
            }
            return finalize_vm_lab_orchestration_result(
                "vm-lab-orchestrate-live-lab",
                report_dir.as_path(),
                orchestration_dir.as_path(),
                outcomes,
                warnings,
                next_actions,
            );
        }
    }

    let run_config = VmLabRunLiveLabConfig {
        profile_path: effective_profile_path.clone(),
        script_path: config.script_path.clone(),
        dry_run: config.dry_run,
        skip_setup: false,
        skip_gates: config.skip_gates,
        skip_soak: config.skip_soak,
        skip_cross_network: config.skip_cross_network,
        source_mode: config.source_mode.clone(),
        repo_ref: config.repo_ref.clone(),
        report_dir: Some(report_dir.clone()),
        timeout_secs: config.timeout_secs,
    };
    let run_result_path = orchestration_dir.join("run_result.json");
    match execute_ops_vm_lab_run_live_lab(run_config) {
        Ok(rendered) => {
            write_orchestration_artifact(run_result_path.as_path(), rendered.as_str())?;
            let result = parse_vm_lab_command_result(rendered.as_str())?;
            append_unique_stage_outcomes(&mut outcomes, result.outcomes.as_slice());
            warnings.extend(result.warnings);
            finalize_vm_lab_orchestration_result(
                "vm-lab-orchestrate-live-lab",
                report_dir.as_path(),
                orchestration_dir.as_path(),
                outcomes,
                warnings,
                next_actions,
            )
        }
        Err(err) => {
            write_orchestration_artifact(run_result_path.as_path(), err.as_str())?;
            match parse_vm_lab_command_result(err.as_str()) {
                Ok(result) => {
                    append_unique_stage_outcomes(&mut outcomes, result.outcomes.as_slice());
                    warnings.extend(result.warnings);
                    next_actions.extend(result.next_actions);
                }
                Err(parse_err) => {
                    warnings.push(parse_err);
                    outcomes.push(stage_outcome(
                        "vm_lab_run_live_lab",
                        VmLabStageStatus::Fail,
                        err,
                        vec![run_result_path.clone()],
                    ));
                }
            }
            if !config.skip_diagnose_on_failure && report_dir.join("state/stages.tsv").exists() {
                let diagnose_result = execute_ops_vm_lab_diagnose_live_lab_failure(
                    VmLabDiagnoseLiveLabFailureConfig {
                        inventory_path,
                        profile_path: effective_profile_path,
                        report_dir: report_dir.clone(),
                        stage: None,
                        output_dir: None,
                        collect_artifacts: config.collect_artifacts_on_failure,
                        timeout_secs: config.timeout_secs,
                    },
                );
                let diagnose_path = orchestration_dir.join("diagnose_result.json");
                match diagnose_result {
                    Ok(rendered) => {
                        write_orchestration_artifact(diagnose_path.as_path(), rendered.as_str())?;
                        let result = parse_vm_lab_command_result(rendered.as_str())?;
                        diagnosis_artifact = Some(PathBuf::from(result.report_dir.clone()));
                        outcomes.push(stage_outcome(
                            "diagnose_live_lab_failure",
                            VmLabStageStatus::Pass,
                            "collected failure diagnostics after run failure",
                            result
                                .outcomes
                                .into_iter()
                                .flat_map(|outcome| outcome.artifacts)
                                .map(PathBuf::from)
                                .collect(),
                        ));
                        warnings.extend(result.warnings);
                    }
                    Err(err) => {
                        write_orchestration_artifact(diagnose_path.as_path(), err.as_str())?;
                        warnings.push(format!(
                            "diagnose-on-failure after run failure did not complete: {err}"
                        ));
                    }
                }
            }
            if next_actions.is_empty() {
                if let Some(path) = diagnosis_artifact.as_deref() {
                    next_actions.push(format!("Inspect diagnostics under {}", path.display()));
                } else {
                    next_actions.push(format!(
                        "Inspect {} and rerun vm-lab-diagnose-live-lab-failure if needed",
                        report_dir.display()
                    ));
                }
            }
            finalize_vm_lab_orchestration_result(
                "vm-lab-orchestrate-live-lab",
                report_dir.as_path(),
                orchestration_dir.as_path(),
                outcomes,
                warnings,
                next_actions,
            )
        }
    }
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
    utm_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedLiveLabTarget {
    role: String,
    profile_target: String,
    remote_target: RemoteTarget,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LiveLabStageLocalBundle {
    report_context_dir: PathBuf,
    copied_paths: Vec<PathBuf>,
    worker_results: Vec<LiveLabWorkerResult>,
    worker_results_json_path: Option<PathBuf>,
    worker_results_markdown_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LiveLabStageRemoteProbeSummary {
    remote_probe_dir: Option<PathBuf>,
    notes: Vec<String>,
    warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LiveLabStageForensicsBundle {
    strategy: String,
    report_context_dir: PathBuf,
    summary_json_path: PathBuf,
    review_markdown_path: PathBuf,
    remote_probe_dir: Option<PathBuf>,
    copied_paths: Vec<PathBuf>,
    worker_results_json_path: Option<PathBuf>,
    worker_results_markdown_path: Option<PathBuf>,
    notes: Vec<String>,
    warnings: Vec<String>,
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

    let live_lab_result = execute_ops_vm_lab_run_live_lab(VmLabRunLiveLabConfig {
        profile_path: profile_output_path.clone(),
        script_path,
        dry_run: config.dry_run,
        skip_setup: false,
        skip_gates: config.skip_gates,
        skip_soak: config.skip_soak,
        skip_cross_network: config.skip_cross_network,
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

    ensure_live_lab_profile_platform_metadata(&profile)?;
    ensure_live_lab_profile_linux_only(&profile, "vm-lab-validate-live-lab-profile")?;

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
    let report_dir = resolve_absolute_path(config.report_dir.as_path())?;
    let profile = load_live_lab_profile(config.profile_path.as_path())?;
    ensure_live_lab_profile_linux_only(&profile, "vm-lab-diagnose-live-lab-failure")?;
    let summary = summarize_live_lab_report(report_dir.as_path(), false, 1)?;
    let stage = if let Some(stage) = config.stage.as_deref() {
        stage.to_string()
    } else {
        summary
            .first_failed_stage
            .clone()
            .ok_or_else(|| "live-lab report does not contain a failed stage".to_string())?
    };
    let stage_records = parse_live_lab_stage_records(report_dir.as_path())?;
    let stage_record = stage_records
        .iter()
        .find(|record| record.name == stage)
        .cloned()
        .or_else(|| infer_live_lab_stage_record(report_dir.as_path(), stage.as_str()).ok())
        .ok_or_else(|| format!("stage {stage} is not present in {}", report_dir.display()))?;
    let diagnostics_dir = config.output_dir.clone().unwrap_or_else(|| {
        report_dir
            .join("diagnostics")
            .join(sanitize_label_for_path(stage.as_str()))
    });
    fs::create_dir_all(diagnostics_dir.as_path()).map_err(|err| {
        format!(
            "create diagnostics dir failed ({}): {err}",
            diagnostics_dir.display()
        )
    })?;

    let targets = resolve_live_lab_profile_targets(config.inventory_path.as_path(), &profile)?;
    let ssh_identity_file = profile.optional("SSH_IDENTITY_FILE").map(PathBuf::from);
    let ssh_known_hosts_file = profile.optional("SSH_KNOWN_HOSTS_FILE").map(PathBuf::from);
    let timeout = timeout_or_default(config.timeout_secs, DEFAULT_COLLECT_TIMEOUT_SECS);
    let mut warnings = Vec::new();
    let status_targets = targets
        .iter()
        .map(|target| target.remote_target.clone())
        .collect::<Vec<_>>();
    let status_output = match execute_vm_lab_status_for_targets(
        status_targets.as_slice(),
        None,
        ssh_identity_file.as_deref(),
        ssh_known_hosts_file.as_deref(),
        timeout,
    ) {
        Ok(output) => output,
        Err(output) => {
            warnings.push(
                "vm-lab-status reported probe failures; inspect vm_lab_status.json for partial results"
                    .to_string(),
            );
            output
        }
    };
    let status_path = diagnostics_dir.join("vm_lab_status.json");
    fs::write(status_path.as_path(), status_output.as_bytes()).map_err(|err| {
        format!(
            "write vm-lab status output failed ({}): {err}",
            status_path.display()
        )
    })?;

    let artifacts_dir = if config.collect_artifacts {
        let artifacts_dir = diagnostics_dir.join("artifacts");
        if let Err(err) = execute_vm_lab_collect_artifacts_for_targets(
            status_targets.as_slice(),
            None,
            ssh_identity_file.as_deref(),
            ssh_known_hosts_file.as_deref(),
            artifacts_dir.as_path(),
            timeout,
        ) {
            warnings.push(
                "artifact collection reported probe failures; inspect artifacts/collection_error.txt for details"
                    .to_string(),
            );
            fs::create_dir_all(artifacts_dir.as_path()).map_err(|create_err| {
                format!(
                    "create artifact diagnostics dir failed ({}): {create_err}",
                    artifacts_dir.display()
                )
            })?;
            let error_path = artifacts_dir.join("collection_error.txt");
            fs::write(error_path.as_path(), err.as_bytes()).map_err(|write_err| {
                format!(
                    "write artifact collection error failed ({}): {write_err}",
                    error_path.display()
                )
            })?;
        }
        Some(artifacts_dir)
    } else {
        None
    };
    let stage_forensics = collect_live_lab_stage_forensics(
        report_dir.as_path(),
        &stage_record,
        &summary,
        diagnostics_dir.as_path(),
        targets.as_slice(),
        timeout,
    )?;
    warnings.extend(stage_forensics.warnings.iter().cloned());

    let targets_json = targets
        .iter()
        .map(|target| {
            json!({
                "role": target.role,
                "target": target.profile_target,
                "ssh_target": target.remote_target.ssh_target,
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
        "warnings": warnings.clone(),
        "stage_forensics": {
            "strategy": stage_forensics.strategy.clone(),
            "report_context_dir": stage_forensics.report_context_dir.clone(),
            "summary_json_path": stage_forensics.summary_json_path.clone(),
            "review_markdown_path": stage_forensics.review_markdown_path.clone(),
            "remote_probe_dir": stage_forensics.remote_probe_dir.clone(),
            "worker_results_json_path": stage_forensics.worker_results_json_path.clone(),
            "worker_results_markdown_path": stage_forensics.worker_results_markdown_path.clone(),
            "copied_paths": stage_forensics.copied_paths.clone(),
            "notes": stage_forensics.notes.clone(),
        },
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
    validate_live_lab_diagnostics_artifacts(diagnostics_dir.as_path())?;
    serialize_vm_lab_command_result(&VmLabCommandResult {
        command: "vm-lab-diagnose-live-lab-failure".to_string(),
        overall_status: VmLabCommandOverallStatus::Pass,
        report_dir: diagnostics_dir.display().to_string(),
        outcomes: vec![VmLabStageOutcome {
            stage: stage_record.name,
            status: VmLabStageStatus::Pass,
            summary: stage_record.description,
            artifacts: vec![
                status_path.display().to_string(),
                summary_path.display().to_string(),
                stage_forensics.summary_json_path.display().to_string(),
                stage_forensics.review_markdown_path.display().to_string(),
            ],
        }],
        warnings,
        next_actions: vec![format!(
            "Inspect {} for the AI-focused review bundle",
            stage_forensics.review_markdown_path.display()
        )],
    })
}

fn infer_live_lab_stage_record(
    report_dir: &Path,
    stage: &str,
) -> Result<LiveLabStageRecord, String> {
    let log_path = report_dir.join("logs").join(format!("{stage}.log"));
    let parallel_stage_dir = report_dir.join("state").join(format!("parallel-{stage}"));
    if !log_path.is_file() && !parallel_stage_dir.is_dir() {
        return Err(format!(
            "stage {stage} is not present in {}",
            report_dir.display()
        ));
    }

    let description_prefix = format!("[stage:{stage}] START ");
    let description = fs::read_to_string(log_path.as_path())
        .ok()
        .and_then(|body| {
            body.lines().find_map(|line| {
                line.trim()
                    .strip_prefix(description_prefix.as_str())
                    .map(|value| value.trim().to_string())
            })
        })
        .unwrap_or_else(|| stage.replace('_', " "));

    Ok(LiveLabStageRecord {
        name: stage.to_string(),
        severity: "unknown".to_string(),
        status: "incomplete".to_string(),
        rc: String::new(),
        log_path,
        description,
    })
}

fn collect_live_lab_stage_forensics(
    report_dir: &Path,
    stage_record: &LiveLabStageRecord,
    summary: &LiveLabStageSummary,
    diagnostics_dir: &Path,
    targets: &[ResolvedLiveLabTarget],
    timeout: Duration,
) -> Result<LiveLabStageForensicsBundle, String> {
    let strategy = live_lab_stage_forensics_strategy(stage_record.name.as_str()).to_string();
    let local_bundle =
        collect_live_lab_stage_local_bundle(report_dir, stage_record, summary, diagnostics_dir)?;
    let mut notes = live_lab_stage_forensics_notes(stage_record.name.as_str());
    let mut warnings = Vec::new();
    let remote_probe = match stage_record.name.as_str() {
        "validate_baseline_runtime" => {
            collect_validate_baseline_runtime_remote_probe(diagnostics_dir, targets, timeout)?
        }
        _ => LiveLabStageRemoteProbeSummary {
            remote_probe_dir: None,
            notes: Vec::new(),
            warnings: Vec::new(),
        },
    };
    notes.extend(remote_probe.notes.iter().cloned());
    warnings.extend(remote_probe.warnings.iter().cloned());

    let review_markdown_path = diagnostics_dir.join("stage_forensics_review.md");
    let review_markdown = render_live_lab_stage_forensics_review(LiveLabStageReviewContext {
        report_dir,
        stage_record,
        summary,
        strategy: strategy.as_str(),
        local_bundle: &local_bundle,
        remote_probe_dir: remote_probe.remote_probe_dir.as_deref(),
        notes: notes.as_slice(),
        warnings: warnings.as_slice(),
    });
    fs::write(review_markdown_path.as_path(), review_markdown.as_bytes()).map_err(|err| {
        format!(
            "write stage forensics review failed ({}): {err}",
            review_markdown_path.display()
        )
    })?;

    let summary_json_path = diagnostics_dir.join("stage_forensics_summary.json");
    let summary_json = json!({
        "stage": stage_record.name,
        "strategy": strategy.clone(),
        "report_context_dir": local_bundle.report_context_dir.clone(),
        "copied_paths": local_bundle.copied_paths.clone(),
        "worker_result_count": local_bundle.worker_results.len(),
        "failed_worker_count": local_bundle.worker_results.iter().filter(|result| result.rc != 0).count(),
        "worker_results_json_path": local_bundle.worker_results_json_path.clone(),
        "worker_results_markdown_path": local_bundle.worker_results_markdown_path.clone(),
        "remote_probe_dir": remote_probe.remote_probe_dir.clone(),
        "notes": notes.clone(),
        "warnings": warnings.clone(),
        "review_markdown_path": review_markdown_path.clone(),
    });
    fs::write(
        summary_json_path.as_path(),
        serde_json::to_vec_pretty(&summary_json)
            .map_err(|err| format!("serialize stage forensics summary failed: {err}"))?,
    )
    .map_err(|err| {
        format!(
            "write stage forensics summary failed ({}): {err}",
            summary_json_path.display()
        )
    })?;

    let mut copied_paths = local_bundle.copied_paths.clone();
    copied_paths.push(summary_json_path.clone());
    copied_paths.push(review_markdown_path.clone());

    Ok(LiveLabStageForensicsBundle {
        strategy,
        report_context_dir: local_bundle.report_context_dir,
        summary_json_path,
        review_markdown_path,
        remote_probe_dir: remote_probe.remote_probe_dir,
        copied_paths,
        worker_results_json_path: local_bundle.worker_results_json_path,
        worker_results_markdown_path: local_bundle.worker_results_markdown_path,
        notes,
        warnings,
    })
}

fn collect_live_lab_stage_local_bundle(
    report_dir: &Path,
    stage_record: &LiveLabStageRecord,
    summary: &LiveLabStageSummary,
    diagnostics_dir: &Path,
) -> Result<LiveLabStageLocalBundle, String> {
    let report_context_dir = diagnostics_dir.join("report_context");
    fs::create_dir_all(report_context_dir.as_path()).map_err(|err| {
        format!(
            "create stage report context dir failed ({}): {err}",
            report_context_dir.display()
        )
    })?;

    let mut copied_paths = Vec::new();
    let mut seen_sources = HashSet::new();
    copy_stage_bundle_file(
        summary.key_report_path.as_path(),
        report_context_dir.join("failure_digest.md").as_path(),
        &mut seen_sources,
        &mut copied_paths,
    )?;
    copy_stage_bundle_file(
        report_dir.join("failure_digest.json").as_path(),
        report_context_dir.join("failure_digest.json").as_path(),
        &mut seen_sources,
        &mut copied_paths,
    )?;
    copy_stage_bundle_file(
        report_dir.join("run_summary.md").as_path(),
        report_context_dir.join("run_summary.md").as_path(),
        &mut seen_sources,
        &mut copied_paths,
    )?;
    copy_stage_bundle_file(
        report_dir.join("run_summary.json").as_path(),
        report_context_dir.join("run_summary.json").as_path(),
        &mut seen_sources,
        &mut copied_paths,
    )?;
    copy_stage_bundle_file(
        report_dir.join("state/stages.tsv").as_path(),
        report_context_dir.join("state/stages.tsv").as_path(),
        &mut seen_sources,
        &mut copied_paths,
    )?;
    copy_stage_bundle_file(
        stage_record.log_path.as_path(),
        report_context_dir
            .join("logs")
            .join(
                stage_record
                    .log_path
                    .file_name()
                    .unwrap_or_else(|| std::ffi::OsStr::new("stage.log")),
            )
            .as_path(),
        &mut seen_sources,
        &mut copied_paths,
    )?;

    let parallel_stage_dir = report_dir
        .join("state")
        .join(format!("parallel-{}", stage_record.name));
    let copied_parallel_dir = report_context_dir
        .join("state")
        .join(format!("parallel-{}", stage_record.name));
    if parallel_stage_dir.is_dir() {
        copy_stage_bundle_dir(
            parallel_stage_dir.as_path(),
            copied_parallel_dir.as_path(),
            &mut seen_sources,
            &mut copied_paths,
        )?;
    }

    let worker_results = read_parallel_stage_results(report_dir, stage_record.name.as_str());
    let (worker_results_json_path, worker_results_markdown_path) = if worker_results.is_empty() {
        (None, None)
    } else {
        let json_path = diagnostics_dir.join("stage_worker_results.json");
        let markdown_path = diagnostics_dir.join("stage_worker_results.md");
        write_live_lab_worker_results_summary(
            worker_results.as_slice(),
            json_path.as_path(),
            markdown_path.as_path(),
        )?;
        copied_paths.push(json_path.clone());
        copied_paths.push(markdown_path.clone());
        (Some(json_path), Some(markdown_path))
    };

    Ok(LiveLabStageLocalBundle {
        report_context_dir,
        copied_paths,
        worker_results,
        worker_results_json_path,
        worker_results_markdown_path,
    })
}

fn write_live_lab_worker_results_summary(
    worker_results: &[LiveLabWorkerResult],
    json_path: &Path,
    markdown_path: &Path,
) -> Result<(), String> {
    let results_json = worker_results
        .iter()
        .map(|result| {
            json!({
                "stage_name": result.stage_name,
                "label": result.label,
                "target": result.target,
                "node_id": result.node_id,
                "role": result.role,
                "rc": result.rc,
                "started_at": result.started_at,
                "finished_at": result.finished_at,
                "log_path": result.log_path,
                "snapshot_path": result.snapshot_path,
                "route_policy_path": result.route_policy_path,
                "dns_state_path": result.dns_state_path,
                "primary_failure_reason": result.primary_failure_reason,
            })
        })
        .collect::<Vec<_>>();
    let summary_json = json!({
        "worker_count": worker_results.len(),
        "failed_worker_count": worker_results.iter().filter(|result| result.rc != 0).count(),
        "results": results_json,
    });
    fs::write(
        json_path,
        serde_json::to_vec_pretty(&summary_json)
            .map_err(|err| format!("serialize worker results summary failed: {err}"))?,
    )
    .map_err(|err| {
        format!(
            "write worker results summary failed ({}): {err}",
            json_path.display()
        )
    })?;

    let mut lines = vec![
        "# Live-Lab Worker Results".to_string(),
        String::new(),
        format!("- worker_count={}", worker_results.len()),
        format!(
            "- failed_worker_count={}",
            worker_results
                .iter()
                .filter(|result| result.rc != 0)
                .count()
        ),
    ];
    for result in worker_results {
        let reason = if result.primary_failure_reason.trim().is_empty() {
            "none"
        } else {
            result.primary_failure_reason.as_str()
        };
        lines.push(format!(
            "- label={} role={} node_id={} rc={} reason={} log_path={} snapshot_path={} route_policy_path={} dns_state_path={}",
            result.label,
            result.role,
            result.node_id,
            result.rc,
            reason,
            result.log_path,
            result.snapshot_path,
            result.route_policy_path,
            result.dns_state_path
        ));
    }
    fs::write(markdown_path, lines.join("\n").as_bytes()).map_err(|err| {
        format!(
            "write worker results markdown failed ({}): {err}",
            markdown_path.display()
        )
    })?;
    Ok(())
}

fn collect_windows_diagnostics_for_target(
    target: &ResolvedLiveLabTarget,
    target_dir: &Path,
    timeout: Duration,
) -> Result<(Vec<String>, Vec<String>), String> {
    let helper_local_path = windows_diagnostics_helper_script_local_path();
    let remote_root = windows_helper_script_remote_path(
        &target.remote_target,
        &format!(
            "diagnostics\\{}",
            sanitize_label_for_path(target.role.as_str())
        ),
    )?;
    let context = RemoteFallbackContext {
        target: &target.remote_target,
        ssh_user_override: None,
        ssh_identity_file: None,
        known_hosts_path: None,
        timeout,
    };
    let output = capture_windows_helper_script_output_from_path(
        &context,
        helper_local_path.as_path(),
        WINDOWS_COLLECT_DIAGNOSTICS_HELPER_FILE,
        &["-OutputRoot".to_string(), remote_root.clone()],
    )?;
    let helper_output_root = output.trim();
    if helper_output_root.is_empty() {
        return Err(format!(
            "Windows diagnostics helper did not emit an output root for {}",
            target.role
        ));
    }
    if helper_output_root != remote_root {
        return Err(format!(
            "Windows diagnostics helper emitted unexpected output root for {}: expected {}, got {}",
            target.role, remote_root, helper_output_root
        ));
    }

    let output_files = [
        "services.txt",
        "net-ip.txt",
        "routes.txt",
        "dns.txt",
        "firewall.txt",
        "events-system.txt",
        "events-application.txt",
        "tooling.txt",
    ];
    let mut copied_paths = Vec::new();
    for file_name in output_files {
        let remote_file = windows_guest_path_join(helper_output_root, file_name)?;
        let local_file = target_dir.join(file_name);
        let status = if let Some(VmController::LocalUtm { utm_name, .. }) =
            target.remote_target.controller.as_ref()
        {
            utm_pull_raw(
                utm_name.as_str(),
                remote_file.as_str(),
                local_file.as_path(),
                timeout,
            )?
        } else {
            scp_from_remote(
                &target.remote_target,
                None,
                None,
                None,
                remote_file.as_str(),
                local_file.as_path(),
                timeout,
            )?
        };
        ensure_success_status(
            status,
            format!("copy Windows diagnostics file {file_name}").as_str(),
        )?;
        copied_paths.push(local_file);
    }

    let metadata_path = target_dir.join("metadata.json");
    let metadata = json!({
        "role": target.role,
        "target": target.profile_target,
        "ssh_target": target.remote_target.ssh_target,
        "platform": target.remote_target.platform_profile.platform.as_str(),
        "remote_shell": target.remote_target.platform_profile.remote_shell.as_str(),
        "guest_exec_mode": target.remote_target.platform_profile.guest_exec_mode.as_str(),
        "service_manager": target.remote_target.platform_profile.service_manager.as_str(),
        "remote_output_root": helper_output_root,
        "helper_script": WINDOWS_COLLECT_DIAGNOSTICS_HELPER_FILE,
        "copied_paths": copied_paths,
    });
    fs::write(
        metadata_path.as_path(),
        serde_json::to_vec_pretty(&metadata)
            .map_err(|err| format!("serialize Windows diagnostics metadata failed: {err}"))?,
    )
    .map_err(|err| {
        format!(
            "write Windows diagnostics metadata failed ({}): {err}",
            metadata_path.display()
        )
    })?;

    Ok((
        vec![format!(
            "Windows diagnostics helper collected services, network, route, DNS, firewall, event-log, and tooling state for {} via {}",
            target.role, WINDOWS_COLLECT_DIAGNOSTICS_HELPER_FILE
        )],
        Vec::new(),
    ))
}

fn collect_validate_baseline_runtime_remote_probe(
    diagnostics_dir: &Path,
    targets: &[ResolvedLiveLabTarget],
    timeout: Duration,
) -> Result<LiveLabStageRemoteProbeSummary, String> {
    let remote_probe_dir = diagnostics_dir.join("remote_validate_baseline_runtime");
    fs::create_dir_all(remote_probe_dir.as_path()).map_err(|err| {
        format!(
            "create baseline remote probe dir failed ({}): {err}",
            remote_probe_dir.display()
        )
    })?;
    let mut warnings = Vec::new();
    let mut results = Vec::new();
    let mut notes = Vec::new();

    for target in targets {
        let target_dir = remote_probe_dir.join(sanitize_label_for_path(target.role.as_str()));
        fs::create_dir_all(target_dir.as_path()).map_err(|err| {
            format!(
                "create baseline target probe dir failed ({}): {err}",
                target_dir.display()
            )
        })?;
        match target.remote_target.platform_profile.platform {
            VmGuestPlatform::Linux | VmGuestPlatform::Macos => {
                let rustynet_status_script = privileged_rustynet_cli_script("status");
                let rustynet_netcheck_script = privileged_rustynet_cli_script("netcheck");
                let sections = [
                    ("hostname", "hostname"),
                    (
                        "service_active",
                        "if command -v systemctl >/dev/null 2>&1; then systemctl is-active rustynetd.service 2>&1; else echo systemctl-unavailable; fi",
                    ),
                    ("rustynet_status", rustynet_status_script.as_str()),
                    ("rustynet_netcheck", rustynet_netcheck_script.as_str()),
                    (
                        "daemon_socket",
                        "if [ -S /run/rustynet/rustynetd.sock ]; then echo daemon_socket=present; else echo daemon_socket=missing; fi",
                    ),
                    (
                        "route_get_1_1_1_1",
                        "if command -v ip >/dev/null 2>&1; then ip -4 route get 1.1.1.1 2>&1; else echo ip-unavailable; fi",
                    ),
                    (
                        "plaintext_passphrase_check",
                        "if test ! -e /var/lib/rustynet/keys/wireguard.passphrase && test ! -e /etc/rustynet/wireguard.passphrase && test ! -e /etc/rustynet/signing_key_passphrase; then echo no-plaintext-passphrase-files; else echo plaintext-passphrase-files-present; fi",
                    ),
                    (
                        "plaintext_passphrase_paths",
                        "for path in /var/lib/rustynet/keys/wireguard.passphrase /etc/rustynet/wireguard.passphrase /etc/rustynet/signing_key_passphrase; do if [ -e \"$path\" ]; then ls -ld \"$path\" 2>&1; else printf '%s missing\\n' \"$path\"; fi; done",
                    ),
                    (
                        "runtime_state_paths",
                        "for path in /run/rustynet/rustynetd.sock /var/lib/rustynet/rustynetd.assignment /var/lib/rustynet/rustynetd.traversal /var/lib/rustynet/rustynetd.dns-zone /var/lib/rustynet/rustynetd.trust; do if [ -e \"$path\" ] || [ -S \"$path\" ]; then ls -ld \"$path\" 2>&1; else printf '%s missing\\n' \"$path\"; fi; done",
                    ),
                    (
                        "time_state",
                        "if command -v timedatectl >/dev/null 2>&1; then timedatectl status 2>&1; else date -u '+%Y-%m-%dT%H:%M:%SZ'; fi",
                    ),
                    (
                        "journalctl_rustynetd_tail",
                        "if command -v journalctl >/dev/null 2>&1; then if sudo -n true >/dev/null 2>&1; then sudo -n journalctl -u rustynetd.service --no-pager -n 80 2>&1; else journalctl -u rustynetd.service --no-pager -n 80 2>&1; fi; else echo journalctl-unavailable; fi",
                    ),
                ];
                let capture_script = build_section_capture_script(sections.as_slice());
                match capture_remote_shell_command_for_target(
                    &target.remote_target,
                    None,
                    None,
                    None,
                    capture_script.as_str(),
                    timeout,
                ) {
                    Ok(output) => {
                        let sections = parse_section_capture(output.as_str());
                        for (name, body) in &sections {
                            fs::write(target_dir.join(format!("{name}.txt")), body.as_bytes())
                                .map_err(|err| {
                                    format!(
                                        "write baseline stage probe failed ({} {}): {err}",
                                        target.role, name
                                    )
                                })?;
                        }
                        let metadata_path = target_dir.join("metadata.json");
                        let metadata = json!({
                            "role": target.role,
                            "target": target.profile_target,
                            "ssh_target": target.remote_target.ssh_target,
                            "platform": target.remote_target.platform_profile.platform.as_str(),
                            "sections": sections.keys().cloned().collect::<Vec<_>>(),
                        });
                        fs::write(
                            metadata_path.as_path(),
                            serde_json::to_vec_pretty(&metadata).map_err(|err| {
                                format!("serialize baseline probe metadata failed: {err}")
                            })?,
                        )
                        .map_err(|err| {
                            format!(
                                "write baseline probe metadata failed ({}): {err}",
                                metadata_path.display()
                            )
                        })?;
                        results.push(json!({
                            "role": target.role,
                            "target": target.profile_target,
                            "ssh_target": target.remote_target.ssh_target,
                            "platform": target.remote_target.platform_profile.platform.as_str(),
                            "target_dir": target_dir,
                            "error": Value::Null,
                        }));
                    }
                    Err(err) => {
                        warnings.push(format!(
                            "baseline runtime probe failed for {} ({}): {err}",
                            target.role, target.profile_target
                        ));
                        let error_path = target_dir.join("error.txt");
                        fs::write(error_path.as_path(), err.as_bytes()).map_err(|write_err| {
                            format!(
                                "write baseline probe error failed ({}): {write_err}",
                                error_path.display()
                            )
                        })?;
                        results.push(json!({
                            "role": target.role,
                            "target": target.profile_target,
                            "ssh_target": target.remote_target.ssh_target,
                            "platform": target.remote_target.platform_profile.platform.as_str(),
                            "target_dir": target_dir,
                            "error": err,
                        }));
                    }
                }
            }
            VmGuestPlatform::Windows => {
                match collect_windows_diagnostics_for_target(target, target_dir.as_path(), timeout)
                {
                    Ok((target_notes, target_warnings)) => {
                        notes.extend(target_notes);
                        warnings.extend(target_warnings);
                        results.push(json!({
                            "role": target.role,
                            "target": target.profile_target,
                            "ssh_target": target.remote_target.ssh_target,
                            "platform": target.remote_target.platform_profile.platform.as_str(),
                            "target_dir": target_dir,
                            "error": Value::Null,
                        }));
                    }
                    Err(err) => {
                        warnings.push(format!(
                            "Windows baseline runtime diagnostics failed for {} ({}): {err}",
                            target.role, target.profile_target
                        ));
                        let error_path = target_dir.join("error.txt");
                        fs::write(error_path.as_path(), err.as_bytes()).map_err(|write_err| {
                            format!(
                                "write Windows baseline probe error failed ({}): {write_err}",
                                error_path.display()
                            )
                        })?;
                        results.push(json!({
                            "role": target.role,
                            "target": target.profile_target,
                            "ssh_target": target.remote_target.ssh_target,
                            "platform": target.remote_target.platform_profile.platform.as_str(),
                            "target_dir": target_dir,
                            "error": err,
                        }));
                    }
                }
            }
            VmGuestPlatform::Ios | VmGuestPlatform::Android => {
                return Err(format!(
                    "baseline runtime diagnostics are not implemented for platform {} ({})",
                    target.remote_target.platform_profile.platform.as_str(),
                    target.role
                ));
            }
        }
    }

    let summary_path = remote_probe_dir.join("summary.json");
    fs::write(
        summary_path.as_path(),
        serde_json::to_vec_pretty(&json!({
            "target_count": targets.len(),
            "failed_probes": warnings.len(),
            "results": results,
        }))
        .map_err(|err| format!("serialize baseline remote probe summary failed: {err}"))?,
    )
    .map_err(|err| {
        format!(
            "write baseline remote probe summary failed ({}): {err}",
            summary_path.display()
        )
    })?;

    let mut summary_notes = vec![
        "Baseline runtime forensics include focused remote probes for rustynet status, daemon socket presence, route selection, plaintext-passphrase absence, runtime state files, time state, and the last 80 journal lines from rustynetd.".to_string(),
    ];
    summary_notes.extend(notes);

    Ok(LiveLabStageRemoteProbeSummary {
        remote_probe_dir: Some(remote_probe_dir),
        notes: summary_notes,
        warnings,
    })
}

fn render_live_lab_stage_forensics_review(context: LiveLabStageReviewContext<'_>) -> String {
    let LiveLabStageReviewContext {
        report_dir,
        stage_record,
        summary,
        strategy,
        local_bundle,
        remote_probe_dir,
        notes,
        warnings,
    } = context;
    let mut lines = vec![
        "# Live-Lab Stage Forensics".to_string(),
        String::new(),
        format!("- report_dir={}", report_dir.display()),
        format!("- stage={}", stage_record.name),
        format!("- stage_description={}", stage_record.description),
        format!("- stage_strategy={strategy}"),
        format!("- stage_status={}", stage_record.status),
        format!("- stage_rc={}", stage_record.rc),
        format!("- key_report_path={}", summary.key_report_path.display()),
        format!("- stage_log_path={}", stage_record.log_path.display()),
        format!(
            "- report_context_dir={}",
            local_bundle.report_context_dir.display()
        ),
        format!("- copied_path_count={}", local_bundle.copied_paths.len()),
    ];
    if let Some(reason) = summary.likely_reason.as_deref() {
        lines.push(format!("- likely_reason={reason}"));
    }
    if let Some(key_log_path) = summary.key_log_path.as_deref() {
        lines.push(format!("- key_log_path={}", key_log_path.display()));
    }
    if let Some(remote_probe_dir) = remote_probe_dir {
        lines.push(format!("- remote_probe_dir={}", remote_probe_dir.display()));
    }
    if let Some(path) = local_bundle.worker_results_json_path.as_deref() {
        lines.push(format!("- worker_results_json_path={}", path.display()));
    }
    if let Some(path) = local_bundle.worker_results_markdown_path.as_deref() {
        lines.push(format!("- worker_results_markdown_path={}", path.display()));
    }

    if !notes.is_empty() {
        lines.push(String::new());
        lines.push("## Notes".to_string());
        for note in notes {
            lines.push(format!("- {note}"));
        }
    }

    if !warnings.is_empty() {
        lines.push(String::new());
        lines.push("## Warnings".to_string());
        for warning in warnings {
            lines.push(format!("- {warning}"));
        }
    }

    if !local_bundle.worker_results.is_empty() {
        lines.push(String::new());
        lines.push("## Worker Results".to_string());
        for result in &local_bundle.worker_results {
            let reason = if result.primary_failure_reason.trim().is_empty() {
                "none"
            } else {
                result.primary_failure_reason.as_str()
            };
            lines.push(format!(
                "- label={} role={} node_id={} rc={} reason={} log_path={} snapshot_path={} route_policy_path={} dns_state_path={}",
                result.label,
                result.role,
                result.node_id,
                result.rc,
                reason,
                result.log_path,
                result.snapshot_path,
                result.route_policy_path,
                result.dns_state_path
            ));
        }
    }

    lines.push(String::new());
    lines.push("## Copied Report Context".to_string());
    for path in &local_bundle.copied_paths {
        lines.push(format!("- {}", path.display()));
    }

    lines.join("\n")
}

fn live_lab_stage_forensics_strategy(stage_name: &str) -> &'static str {
    match stage_name {
        "validate_baseline_runtime" => "validate-baseline-runtime",
        _ => "generic-stage-context",
    }
}

fn live_lab_stage_forensics_notes(stage_name: &str) -> Vec<String> {
    match stage_name {
        "validate_baseline_runtime" => vec![
            "Expected rustynet status fields: transport_socket_identity_state=authoritative_backend_shared_transport, transport_socket_identity_error=none, encrypted_key_store=true, auto_tunnel_enforce=true, membership_active_nodes=5.".to_string(),
            "Expected client routing on non-exit nodes: exit_node=exit-1 and `ip -4 route get 1.1.1.1` selects `dev rustynet0`.".to_string(),
            "Expected plaintext-passphrase hygiene result: no-plaintext-passphrase-files.".to_string(),
        ],
        _ => vec![
            "The report_context bundle includes the report summary, the failing stage log, and any parallel-stage evidence copied from the original report directory.".to_string(),
        ],
    }
}

fn copy_stage_bundle_file(
    source: &Path,
    destination: &Path,
    seen_sources: &mut HashSet<PathBuf>,
    copied_paths: &mut Vec<PathBuf>,
) -> Result<(), String> {
    if !source.exists() || !source.is_file() {
        return Ok(());
    }
    if !seen_sources.insert(source.to_path_buf()) {
        return Ok(());
    }
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "create stage bundle dir failed ({}): {err}",
                parent.display()
            )
        })?;
    }
    fs::copy(source, destination).map_err(|err| {
        format!(
            "copy stage bundle file failed ({} -> {}): {err}",
            source.display(),
            destination.display()
        )
    })?;
    copied_paths.push(destination.to_path_buf());
    Ok(())
}

fn copy_stage_bundle_dir(
    source: &Path,
    destination: &Path,
    seen_sources: &mut HashSet<PathBuf>,
    copied_paths: &mut Vec<PathBuf>,
) -> Result<(), String> {
    if !source.exists() || !source.is_dir() {
        return Ok(());
    }
    if !seen_sources.insert(source.to_path_buf()) {
        return Ok(());
    }
    copy_dir_recursive(source, destination)?;
    copied_paths.push(destination.to_path_buf());
    Ok(())
}

fn copy_dir_recursive(source: &Path, destination: &Path) -> Result<(), String> {
    fs::create_dir_all(destination).map_err(|err| {
        format!(
            "create copied directory failed ({}): {err}",
            destination.display()
        )
    })?;
    for entry in fs::read_dir(source)
        .map_err(|err| format!("read directory failed ({}): {err}", source.display()))?
    {
        let entry = entry
            .map_err(|err| format!("read directory entry failed ({}): {err}", source.display()))?;
        let entry_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let file_type = entry
            .file_type()
            .map_err(|err| format!("read file type failed ({}): {err}", entry_path.display()))?;
        if file_type.is_dir() {
            copy_dir_recursive(entry_path.as_path(), destination_path.as_path())?;
        } else if file_type.is_file() {
            if let Some(parent) = destination_path.parent() {
                fs::create_dir_all(parent).map_err(|err| {
                    format!(
                        "create copied file parent failed ({}): {err}",
                        parent.display()
                    )
                })?;
            }
            fs::copy(entry_path.as_path(), destination_path.as_path()).map_err(|err| {
                format!(
                    "copy directory entry failed ({} -> {}): {err}",
                    entry_path.display(),
                    destination_path.display()
                )
            })?;
        }
    }
    Ok(())
}

fn resolve_path(path: &Path) -> Result<PathBuf, String> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::env::current_dir()
            .map_err(|err| format!("resolve current directory failed: {err}"))
            .map(|cwd| cwd.join(path))
    }
}

fn resolve_absolute_path(path: &Path) -> Result<PathBuf, String> {
    resolve_path(path)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn collected_at_utc_now() -> String {
    Command::new("date")
        .arg("-u")
        .arg("+%FT%TZ")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| format!("unix:{}", unix_now()))
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
        return Ok(("local-head".to_string(), None));
    }
    let source_mode = configured_source_mode.unwrap_or("working-tree");
    validate_live_lab_source_mode(source_mode)?;
    let repo_ref = if source_mode == "ref" {
        let value = configured_repo_ref
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "source-mode=ref requires --repo-ref".to_string())?;
        Some(value.to_string())
    } else {
        None
    };
    Ok((source_mode.to_string(), repo_ref))
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
                utm_name: self
                    .optional("EXIT_UTM_NAME")
                    .filter(|value| !value.trim().is_empty()),
            },
            LiveLabProfileTarget {
                role: "client".to_string(),
                target: self.required("CLIENT_TARGET")?,
                utm_name: self
                    .optional("CLIENT_UTM_NAME")
                    .filter(|value| !value.trim().is_empty()),
            },
        ];
        for (key, utm_key, role) in [
            ("ENTRY_TARGET", "ENTRY_UTM_NAME", "entry"),
            ("AUX_TARGET", "AUX_UTM_NAME", "aux"),
            ("EXTRA_TARGET", "EXTRA_UTM_NAME", "extra"),
            (
                "FIFTH_CLIENT_TARGET",
                "FIFTH_CLIENT_UTM_NAME",
                "fifth_client",
            ),
        ] {
            if let Some(target) = self.optional(key)
                && !target.trim().is_empty()
            {
                targets.push(LiveLabProfileTarget {
                    role: role.to_string(),
                    target,
                    utm_name: self
                        .optional(utm_key)
                        .filter(|value| !value.trim().is_empty()),
                });
            }
        }
        Ok(targets)
    }
}

fn live_lab_profile_target_platform_profile(
    profile: &LiveLabProfile,
    role: &str,
) -> Result<Option<VmPlatformProfile>, String> {
    let prefix = role.to_ascii_uppercase();
    let target_key = format!("{}_TARGET", prefix);
    let Some(target) = profile.optional(target_key.as_str()) else {
        return Ok(None);
    };
    if target.trim().is_empty() {
        return Ok(None);
    }

    let platform = VmGuestPlatform::parse(
        profile
            .required(format!("{}_PLATFORM", prefix).as_str())?
            .as_str(),
    )
    .map_err(|err| format!("{prefix}_PLATFORM: {err}"))?;
    let remote_shell = VmRemoteShell::parse(
        profile
            .required(format!("{}_REMOTE_SHELL", prefix).as_str())?
            .as_str(),
    )
    .map_err(|err| format!("{prefix}_REMOTE_SHELL: {err}"))?;
    let guest_exec_mode = VmGuestExecMode::parse(
        profile
            .required(format!("{}_GUEST_EXEC_MODE", prefix).as_str())?
            .as_str(),
    )
    .map_err(|err| format!("{prefix}_GUEST_EXEC_MODE: {err}"))?;
    let service_manager = VmServiceManager::parse(
        profile
            .required(format!("{}_SERVICE_MANAGER", prefix).as_str())?
            .as_str(),
    )
    .map_err(|err| format!("{prefix}_SERVICE_MANAGER: {err}"))?;

    Ok(Some(VmPlatformProfile {
        platform,
        remote_shell,
        guest_exec_mode,
        service_manager,
    }))
}

fn configured_live_lab_target_platform_profiles(
    profile: &LiveLabProfile,
) -> Result<Vec<(String, String, VmPlatformProfile)>, String> {
    let mut targets = Vec::new();
    for target in profile.configured_targets()? {
        let Some(platform_profile) =
            live_lab_profile_target_platform_profile(profile, target.role.as_str())?
        else {
            return Err(format!(
                "live-lab profile target {} is missing platform metadata",
                target.role
            ));
        };
        targets.push((target.role, target.target, platform_profile));
    }
    Ok(targets)
}

fn ensure_live_lab_profile_platform_metadata(profile: &LiveLabProfile) -> Result<(), String> {
    let _ = configured_live_lab_target_platform_profiles(profile)?;
    Ok(())
}

fn ensure_live_lab_profile_linux_only(
    profile: &LiveLabProfile,
    command_name: &str,
) -> Result<(), String> {
    let blocked = configured_live_lab_target_platform_profiles(profile)?
        .into_iter()
        .filter(|(_, _, platform_profile)| {
            platform_profile.platform != VmGuestPlatform::Linux
                || platform_profile.remote_shell != VmRemoteShell::Posix
                || platform_profile.guest_exec_mode != VmGuestExecMode::LinuxBash
                || platform_profile.service_manager != VmServiceManager::Systemd
        })
        .map(|(role, target, platform_profile)| {
            format!(
                "role={role} target={target} platform={} remote_shell={} guest_exec_mode={} service_manager={}",
                platform_profile.platform.as_str(),
                platform_profile.remote_shell.as_str(),
                platform_profile.guest_exec_mode.as_str(),
                platform_profile.service_manager.as_str(),
            )
        })
        .collect::<Vec<_>>();
    if blocked.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{command_name} requires platform=linux remote_shell=posix guest_exec_mode=linux_bash service_manager=systemd in the current Linux live-lab shell orchestrator; blocked targets: {}",
            blocked.join("; ")
        ))
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

fn resolve_live_lab_profile_targets(
    inventory_path: &Path,
    profile: &LiveLabProfile,
) -> Result<Vec<ResolvedLiveLabTarget>, String> {
    let inventory = load_inventory(inventory_path)?;
    let mut resolved = Vec::new();
    for target in profile.configured_targets()? {
        let remote_target = resolve_live_lab_profile_remote_target(inventory.as_slice(), &target)?;
        resolved.push(ResolvedLiveLabTarget {
            role: target.role.clone(),
            profile_target: target.target.clone(),
            remote_target,
        });
    }
    Ok(resolved)
}

fn resolve_live_lab_profile_remote_target(
    inventory: &[VmInventoryEntry],
    profile_target: &LiveLabProfileTarget,
) -> Result<RemoteTarget, String> {
    if let Some(utm_name) = profile_target.utm_name.as_deref() {
        let entry = inventory
            .iter()
            .find(|entry| {
                matches!(
                    entry.controller.as_ref(),
                    Some(VmController::LocalUtm {
                        utm_name: entry_utm_name,
                        ..
                    }) if entry_utm_name == utm_name
                )
            })
            .ok_or_else(|| {
                format!(
                    "live-lab profile target {} references UTM controller {} that is not present in inventory",
                    profile_target.role, utm_name
                )
            })?;
        let mut remote_target = remote_target_from_inventory_entry(entry, None);
        remote_target.label = profile_target.role.clone();
        if remote_target.ssh_user.is_none() {
            remote_target.ssh_user =
                ssh_target_user(profile_target.target.as_str()).map(str::to_string);
        }
        return Ok(remote_target);
    }

    if let Some(entry) = inventory.iter().find(|entry| {
        resolved_inventory_ssh_target(entry) == profile_target.target
            || normalized_ssh_target(
                entry.ssh_target.as_str(),
                entry.ssh_user.as_deref(),
                profile_target.role.as_str(),
            )
            .map(|candidate| candidate == profile_target.target)
            .unwrap_or(false)
    }) {
        let mut remote_target = remote_target_from_inventory_entry(entry, None);
        remote_target.label = profile_target.role.clone();
        return Ok(remote_target);
    }

    Ok(remote_target_from_raw_target(
        profile_target.role.clone(),
        profile_target.target.clone(),
    ))
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

fn port_status_from_probe(value: &str) -> PortStatus {
    match value {
        "open" => PortStatus::Open,
        "refused" => PortStatus::Refused,
        "timed_out" => PortStatus::TimedOut,
        "unreachable" => PortStatus::Unreachable,
        _ => PortStatus::Unknown,
    }
}

fn build_utm_readiness(
    process_state: &ProbeState<bool>,
    live_ip_state: &ProbeState<String>,
    ssh_port_state: &ProbeState<PortStatus>,
    ssh_auth_state: &ProbeState<String>,
    authoritative_target_present: bool,
) -> VmLabReadiness {
    let powered = matches!(process_state, ProbeState::Ok { value: true });
    let networked = matches!(live_ip_state, ProbeState::Ok { .. });
    let tcp_ready = matches!(
        ssh_port_state,
        ProbeState::Ok {
            value: PortStatus::Open
        }
    );
    let auth_ready = matches!(
        ssh_auth_state,
        ProbeState::Ok { value } if value == "ok" || value == "ready"
    );
    let mut reason_codes = Vec::new();
    if !powered {
        reason_codes.push("process-not-ready".to_string());
    }
    if !networked {
        reason_codes.push("live-ip-not-authoritative".to_string());
    }
    if !tcp_ready {
        reason_codes.push("ssh-tcp-not-open".to_string());
    }
    if !auth_ready {
        reason_codes.push("ssh-auth-not-ready".to_string());
    }
    if !authoritative_target_present {
        reason_codes.push("no-authoritative-ssh-target".to_string());
    }
    VmLabReadiness {
        powered,
        networked,
        tcp_ready,
        auth_ready,
        execution_ready: powered
            && networked
            && tcp_ready
            && auth_ready
            && authoritative_target_present,
        reason_codes,
    }
}

fn stage_status_from_record(record: &LiveLabStageRecord) -> VmLabStageStatus {
    match record.status.as_str() {
        "pass" => VmLabStageStatus::Pass,
        "fail" => VmLabStageStatus::Fail,
        _ => VmLabStageStatus::Skipped,
    }
}

fn command_status_from_summary(summary: &LiveLabStageSummary) -> VmLabCommandOverallStatus {
    match summary.overall_status.as_str() {
        "pass" => VmLabCommandOverallStatus::Pass,
        "pass_with_warnings" => VmLabCommandOverallStatus::Partial,
        _ => VmLabCommandOverallStatus::Fail,
    }
}

fn stage_outcomes_from_records(records: &[LiveLabStageRecord]) -> Vec<VmLabStageOutcome> {
    records
        .iter()
        .map(|record| VmLabStageOutcome {
            stage: record.name.clone(),
            status: stage_status_from_record(record),
            summary: record.description.clone(),
            artifacts: vec![record.log_path.display().to_string()],
        })
        .collect()
}

fn serialize_vm_lab_command_result(result: &VmLabCommandResult) -> Result<String, String> {
    serde_json::to_string_pretty(result)
        .map_err(|err| format!("serialize vm-lab command result failed: {err}"))
}

fn maybe_write_report_artifact(
    report_dir: Option<&Path>,
    filename: &str,
    contents: &str,
) -> Result<Option<PathBuf>, String> {
    let Some(report_dir) = report_dir else {
        return Ok(None);
    };
    let path = report_dir.join(filename);
    write_orchestration_artifact(path.as_path(), contents)?;
    Ok(Some(path))
}

fn report_dir_label(report_dir: Option<&Path>, fallback: &Path) -> String {
    report_dir
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| fallback.display().to_string())
}

fn validate_live_lab_run_artifacts(report_dir: &Path) -> Result<(), String> {
    if !report_dir.is_dir() {
        return Err(format!(
            "live-lab report directory does not exist: {}",
            report_dir.display()
        ));
    }
    for artifact in [
        report_dir.join("run_summary.json"),
        report_dir.join("run_summary.md"),
        report_dir.join("state/stages.tsv"),
        report_dir.join("state/nodes.tsv"),
    ] {
        if !artifact.exists() {
            return Err(format!(
                "required live-lab artifact is missing: {}",
                artifact.display()
            ));
        }
    }

    let records = parse_live_lab_stage_records(report_dir)?;
    if records.is_empty() {
        return Err(format!(
            "live-lab report contains no stage records: {}",
            report_dir.join("state/stages.tsv").display()
        ));
    }
    for record in &records {
        if !record.log_path.exists() {
            return Err(format!(
                "stage log declared in stages.tsv is missing: {}",
                record.log_path.display()
            ));
        }
    }
    if records.iter().any(|record| record.status == "fail")
        && !report_dir.join("failure_digest.md").exists()
        && !report_dir.join("failure_digest.json").exists()
    {
        return Err(format!(
            "run contains failed stages but no failure digest exists under {}",
            report_dir.display()
        ));
    }
    Ok(())
}

fn live_lab_profile_has_full_release_gate_topology(profile: &LiveLabProfile) -> bool {
    ["ENTRY_TARGET", "AUX_TARGET", "EXTRA_TARGET"]
        .iter()
        .all(|key| {
            profile
                .optional(key)
                .map(|value| !value.trim().is_empty())
                .unwrap_or(false)
        })
}

fn full_release_gate_requested(profile: &LiveLabProfile, config: &VmLabRunLiveLabConfig) -> bool {
    !config.skip_gates
        && !config.skip_soak
        && !config.skip_cross_network
        && live_lab_profile_has_full_release_gate_topology(profile)
}

fn build_release_gate_completeness_report(
    records: &[LiveLabStageRecord],
    requested: bool,
) -> ReleaseGateCompletenessReport {
    let observed_pass_stages = records
        .iter()
        .filter(|record| record.status == "pass")
        .map(|record| record.name.clone())
        .collect::<Vec<_>>();
    let observed_pass_set = observed_pass_stages
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    let required_stages = FULL_RELEASE_GATE_REQUIRED_STAGES
        .iter()
        .map(|stage| (*stage).to_string())
        .collect::<Vec<_>>();
    let missing_or_non_pass_stages = if requested {
        FULL_RELEASE_GATE_REQUIRED_STAGES
            .iter()
            .filter(|stage| !observed_pass_set.contains(**stage))
            .map(|stage| (*stage).to_string())
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let status = if !requested {
        "not_requested"
    } else if missing_or_non_pass_stages.is_empty() {
        "complete"
    } else {
        "incomplete"
    };
    ReleaseGateCompletenessReport {
        requested,
        status: status.to_string(),
        required_stages,
        observed_pass_stages,
        missing_or_non_pass_stages,
    }
}

fn write_release_gate_completeness(
    report_dir: &Path,
    report: &ReleaseGateCompletenessReport,
) -> Result<(), String> {
    let path = report_dir.join(RELEASE_GATE_COMPLETENESS_RELATIVE_PATH);
    let parent = path.parent().ok_or_else(|| {
        format!(
            "release-gate completeness path has no parent: {}",
            path.display()
        )
    })?;
    fs::create_dir_all(parent).map_err(|err| {
        format!(
            "create release-gate completeness directory failed ({}): {err}",
            parent.display()
        )
    })?;
    let body = serde_json::to_vec_pretty(report)
        .map_err(|err| format!("serialize release-gate completeness failed: {err}"))?;
    fs::write(&path, body).map_err(|err| {
        format!(
            "write release-gate completeness failed ({}): {err}",
            path.display()
        )
    })
}

fn validate_live_lab_diagnostics_artifacts(diagnostics_dir: &Path) -> Result<(), String> {
    for artifact in [
        diagnostics_dir.join("diagnostics_summary.json"),
        diagnostics_dir.join("vm_lab_status.json"),
        diagnostics_dir.join("stage_forensics_summary.json"),
        diagnostics_dir.join("stage_forensics_review.md"),
    ] {
        if !artifact.exists() {
            return Err(format!(
                "required live-lab diagnostics artifact is missing: {}",
                artifact.display()
            ));
        }
    }
    Ok(())
}

fn live_lab_setup_complete(report_dir: &Path) -> Result<bool, String> {
    if !report_dir.join("state/stages.tsv").exists() {
        return Ok(false);
    }
    let records = parse_live_lab_stage_records(report_dir)?;
    Ok(records
        .iter()
        .find(|record| record.name == "validate_baseline_runtime")
        .map(|record| record.status == "pass")
        .unwrap_or(false))
}

fn live_lab_report_has_non_setup_stage_records(report_dir: &Path) -> Result<bool, String> {
    if !report_dir.join("state/stages.tsv").exists() {
        return Ok(false);
    }
    let setup_stages = setup_stage_names().iter().copied().collect::<HashSet<_>>();
    let records = parse_live_lab_stage_records(report_dir)?;
    Ok(records
        .iter()
        .any(|record| !setup_stages.contains(record.name.as_str())))
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
    ensure_optional_local_regular_file_path(
        config.ssh_identity_file.as_deref(),
        "SSH identity file",
    )?;
    ensure_optional_local_regular_file_path(
        config.known_hosts_path.as_deref(),
        "SSH known_hosts file",
    )?;

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
        match capture_remote_shell_command_for_target(
            target,
            None,
            config.ssh_identity_file.as_deref(),
            config.known_hosts_path.as_deref(),
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
    ensure_optional_local_regular_file_path(
        config.ssh_identity_file.as_deref(),
        "SSH identity file",
    )?;
    ensure_optional_local_regular_file_path(
        config.known_hosts_path.as_deref(),
        "SSH known_hosts file",
    )?;
    execute_vm_lab_status_for_targets(
        targets.as_slice(),
        config.ssh_user.as_deref(),
        config.ssh_identity_file.as_deref(),
        config.known_hosts_path.as_deref(),
        timeout,
    )
}

fn execute_vm_lab_status_for_targets(
    targets: &[RemoteTarget],
    ssh_user_override: Option<&str>,
    ssh_identity_file: Option<&Path>,
    known_hosts_path: Option<&Path>,
    timeout: Duration,
) -> Result<String, String> {
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

    for target in targets {
        let effective_user = ssh_user_override.or(target.ssh_user.as_deref());
        match capture_remote_shell_command_for_target(
            target,
            ssh_user_override,
            ssh_identity_file,
            known_hosts_path,
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
    let fallback_report_dir = config
        .report_dir
        .clone()
        .or_else(|| config.inventory_path.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."));
    let report_dir = config.report_dir.as_deref();
    if let Some(service) = config.service.as_deref() {
        ensure_no_control_chars("service", service)?;
        if config.wait_ready {
            return Err(
                "--wait-ready is only supported for local UTM VM restarts, not --service restarts"
                    .to_string(),
            );
        }
        let result = execute_ops_vm_lab_run(
            VmLabExecConfig {
                inventory_path: config.inventory_path,
                vm_aliases: config.vm_aliases,
                raw_targets: config.raw_targets,
                select_all: config.select_all,
                workdir: "/".to_string(),
                program: "systemctl".to_string(),
                argv: vec!["restart".to_string(), service.to_string()],
                ssh_user: config.ssh_user,
                ssh_identity_file: config.ssh_identity_file,
                known_hosts_path: config.known_hosts_path,
                sudo: true,
                timeout_secs: config.timeout_secs,
            },
            "restarted",
        );
        let text = match &result {
            Ok(output) => output.clone(),
            Err(err) => err.clone(),
        };
        let raw_artifact =
            maybe_write_report_artifact(report_dir, "vm_lab_restart_service.txt", text.as_str())?;
        let (rendered, overall_status) = build_vm_lab_command_result_output(
            "vm-lab-restart",
            report_dir,
            fallback_report_dir.as_path(),
            "vm_lab_restart_result.json",
            vec![stage_outcome(
                "restart_service",
                if result.is_ok() {
                    VmLabStageStatus::Pass
                } else {
                    VmLabStageStatus::Fail
                },
                if result.is_ok() {
                    format!("restarted service {service}")
                } else {
                    format!("restart service {service} failed")
                },
                raw_artifact.into_iter().collect(),
            )],
            Vec::new(),
            if result.is_ok() {
                Vec::new()
            } else {
                vec![format!(
                    "Inspect {} for the service restart failure",
                    report_dir
                        .map(|path| path.join("vm_lab_restart_service.txt"))
                        .unwrap_or_else(|| fallback_report_dir.join("vm_lab_restart_service.txt"))
                        .display()
                )]
            },
        )?;
        if config.json_output {
            return match overall_status {
                VmLabCommandOverallStatus::Fail => Err(rendered),
                VmLabCommandOverallStatus::Pass | VmLabCommandOverallStatus::Partial => {
                    Ok(rendered)
                }
            };
        }
        return result;
    }

    ensure_optional_local_regular_file_path(
        config.ssh_identity_file.as_deref(),
        "SSH identity file",
    )?;
    ensure_optional_local_regular_file_path(
        config.known_hosts_path.as_deref(),
        "SSH known_hosts file",
    )?;
    let inventory_path = config.inventory_path.clone();
    let utmctl_path = config.utmctl_path.clone();
    let ready_targets = if config.wait_ready {
        Some(resolve_start_targets(
            inventory_path.as_path(),
            config.vm_aliases.as_slice(),
            config.select_all,
        )?)
    } else {
        None
    };
    let stop_result = execute_ops_vm_lab_stop(VmLabStopConfig {
        inventory_path: inventory_path.clone(),
        vm_aliases: config.vm_aliases.clone(),
        select_all: config.select_all,
        utmctl_path: utmctl_path.clone(),
        timeout_secs: config.timeout_secs,
    });
    let stop_text = match &stop_result {
        Ok(output) => output.clone(),
        Err(err) => err.clone(),
    };
    let stop_artifact =
        maybe_write_report_artifact(report_dir, "vm_lab_restart_stop.txt", stop_text.as_str())?;
    let stop_result = match stop_result {
        Ok(output) => output,
        Err(err) => {
            let (rendered, overall_status) = build_vm_lab_command_result_output(
                "vm-lab-restart",
                report_dir,
                fallback_report_dir.as_path(),
                "vm_lab_restart_result.json",
                vec![stage_outcome(
                    "stop_local_utm_vms",
                    VmLabStageStatus::Fail,
                    "failed to stop selected local UTM VMs",
                    stop_artifact.into_iter().collect(),
                )],
                Vec::new(),
                vec!["Inspect the stop artifact and UTM controller state".to_string()],
            )?;
            return if config.json_output {
                match overall_status {
                    VmLabCommandOverallStatus::Fail => Err(rendered),
                    VmLabCommandOverallStatus::Pass | VmLabCommandOverallStatus::Partial => {
                        Ok(rendered)
                    }
                }
            } else {
                Err(err)
            };
        }
    };
    let start_result = execute_ops_vm_lab_start(VmLabStartConfig {
        inventory_path,
        vm_aliases: config.vm_aliases,
        select_all: config.select_all,
        utmctl_path: utmctl_path.clone(),
        timeout_secs: config.timeout_secs,
    });
    let start_text = match &start_result {
        Ok(output) => output.clone(),
        Err(err) => err.clone(),
    };
    let start_artifact =
        maybe_write_report_artifact(report_dir, "vm_lab_restart_start.txt", start_text.as_str())?;
    let start_result = match start_result {
        Ok(output) => output,
        Err(err) => {
            let (rendered, overall_status) = build_vm_lab_command_result_output(
                "vm-lab-restart",
                report_dir,
                fallback_report_dir.as_path(),
                "vm_lab_restart_result.json",
                vec![
                    stage_outcome(
                        "stop_local_utm_vms",
                        VmLabStageStatus::Pass,
                        "stopped selected local UTM VMs",
                        stop_artifact.into_iter().collect(),
                    ),
                    stage_outcome(
                        "start_local_utm_vms",
                        VmLabStageStatus::Fail,
                        "failed to start selected local UTM VMs",
                        start_artifact.into_iter().collect(),
                    ),
                ],
                Vec::new(),
                vec!["Inspect the start artifact and UTM controller state".to_string()],
            )?;
            return if config.json_output {
                match overall_status {
                    VmLabCommandOverallStatus::Fail => Err(rendered),
                    VmLabCommandOverallStatus::Pass | VmLabCommandOverallStatus::Partial => {
                        Ok(rendered)
                    }
                }
            } else {
                Err(err)
            };
        }
    };
    if !config.wait_ready {
        let text = format!("{stop_result}\n{start_result}");
        let combined_artifact =
            maybe_write_report_artifact(report_dir, "vm_lab_restart.txt", text.as_str())?;
        let (rendered, overall_status) = build_vm_lab_command_result_output(
            "vm-lab-restart",
            report_dir,
            fallback_report_dir.as_path(),
            "vm_lab_restart_result.json",
            vec![
                stage_outcome(
                    "stop_local_utm_vms",
                    VmLabStageStatus::Pass,
                    "stopped selected local UTM VMs",
                    stop_artifact.into_iter().collect(),
                ),
                stage_outcome(
                    "start_local_utm_vms",
                    VmLabStageStatus::Pass,
                    "started selected local UTM VMs",
                    start_artifact
                        .into_iter()
                        .chain(combined_artifact.into_iter())
                        .collect(),
                ),
            ],
            Vec::new(),
            vec!["Run vm-lab-discover-local-utm-summary to verify readiness".to_string()],
        )?;
        return if config.json_output {
            match overall_status {
                VmLabCommandOverallStatus::Fail => Err(rendered),
                VmLabCommandOverallStatus::Pass | VmLabCommandOverallStatus::Partial => {
                    Ok(rendered)
                }
            }
        } else {
            Ok(text)
        };
    }

    let ready_states = wait_for_local_utm_targets_ready(
        ready_targets
            .as_deref()
            .expect("wait-ready path precomputes restart targets"),
        utmctl_path.as_path(),
        config.ssh_port,
        config.ssh_identity_file.as_deref(),
        config.known_hosts_path.as_deref(),
        timeout_or_default(
            config.ready_timeout_secs,
            DEFAULT_RESTART_READY_TIMEOUT_SECS,
        ),
    );
    let ready_states = match ready_states {
        Ok(states) => states,
        Err(err) => {
            let raw_artifact = maybe_write_report_artifact(
                report_dir,
                "vm_lab_restart_wait_ready.txt",
                err.as_str(),
            )?;
            let (rendered, overall_status) = build_vm_lab_command_result_output(
                "vm-lab-restart",
                report_dir,
                fallback_report_dir.as_path(),
                "vm_lab_restart_result.json",
                vec![
                    stage_outcome(
                        "stop_local_utm_vms",
                        VmLabStageStatus::Pass,
                        "stopped selected local UTM VMs",
                        stop_artifact.into_iter().collect(),
                    ),
                    stage_outcome(
                        "start_local_utm_vms",
                        VmLabStageStatus::Pass,
                        "started selected local UTM VMs",
                        start_artifact.into_iter().collect(),
                    ),
                    stage_outcome(
                        "wait_ready",
                        VmLabStageStatus::Fail,
                        "timed out waiting for selected local UTM VMs to become execution-ready",
                        raw_artifact.into_iter().collect(),
                    ),
                ],
                Vec::new(),
                vec!["Inspect the wait-ready artifact for the last observed VM states".to_string()],
            )?;
            return if config.json_output {
                match overall_status {
                    VmLabCommandOverallStatus::Fail => Err(rendered),
                    VmLabCommandOverallStatus::Pass | VmLabCommandOverallStatus::Partial => {
                        Ok(rendered)
                    }
                }
            } else {
                Err(err)
            };
        }
    };
    let ready_report = render_local_utm_ready_states(ready_states.as_slice());
    let ready_text_artifact = maybe_write_report_artifact(
        report_dir,
        "vm_lab_restart_ready_states.txt",
        ready_report.as_str(),
    )?;
    let ready_states_json = serde_json::to_string_pretty(&ready_states)
        .map_err(|err| format!("serialize local UTM ready states failed: {err}"))?;
    let ready_json_artifact = maybe_write_report_artifact(
        report_dir,
        "vm_lab_restart_ready_states.json",
        ready_states_json.as_str(),
    )?;
    let inventory_report = persist_local_utm_ready_states_to_inventory(
        config.inventory_path.as_path(),
        ready_states.as_slice(),
    );
    let inventory_report = match inventory_report {
        Ok(report) => report,
        Err(err) => {
            let raw_artifact = maybe_write_report_artifact(
                report_dir,
                "vm_lab_restart_inventory_update.txt",
                err.as_str(),
            )?;
            let (rendered, overall_status) = build_vm_lab_command_result_output(
                "vm-lab-restart",
                report_dir,
                fallback_report_dir.as_path(),
                "vm_lab_restart_result.json",
                vec![
                    stage_outcome(
                        "stop_local_utm_vms",
                        VmLabStageStatus::Pass,
                        "stopped selected local UTM VMs",
                        stop_artifact.into_iter().collect(),
                    ),
                    stage_outcome(
                        "start_local_utm_vms",
                        VmLabStageStatus::Pass,
                        "started selected local UTM VMs",
                        start_artifact.into_iter().collect(),
                    ),
                    stage_outcome(
                        "wait_ready",
                        VmLabStageStatus::Pass,
                        "selected local UTM VMs became execution-ready",
                        ready_text_artifact
                            .clone()
                            .into_iter()
                            .chain(ready_json_artifact.clone().into_iter())
                            .collect(),
                    ),
                    stage_outcome(
                        "update_inventory_live_ips",
                        VmLabStageStatus::Fail,
                        "failed to persist discovered live IPs into inventory",
                        raw_artifact.into_iter().collect(),
                    ),
                ],
                Vec::new(),
                vec!["Inspect the inventory update artifact and inventory JSON".to_string()],
            )?;
            return if config.json_output {
                match overall_status {
                    VmLabCommandOverallStatus::Fail => Err(rendered),
                    VmLabCommandOverallStatus::Pass | VmLabCommandOverallStatus::Partial => {
                        Ok(rendered)
                    }
                }
            } else {
                Err(err)
            };
        }
    };
    let inventory_artifact = maybe_write_report_artifact(
        report_dir,
        "vm_lab_restart_inventory_update.txt",
        inventory_report.as_str(),
    )?;
    let text = format!("{stop_result}\n{start_result}\n{ready_report}\n{inventory_report}");
    let combined_artifact =
        maybe_write_report_artifact(report_dir, "vm_lab_restart.txt", text.as_str())?;
    let (rendered, overall_status) = build_vm_lab_command_result_output(
        "vm-lab-restart",
        report_dir,
        fallback_report_dir.as_path(),
        "vm_lab_restart_result.json",
        vec![
            stage_outcome(
                "stop_local_utm_vms",
                VmLabStageStatus::Pass,
                "stopped selected local UTM VMs",
                stop_artifact.into_iter().collect(),
            ),
            stage_outcome(
                "start_local_utm_vms",
                VmLabStageStatus::Pass,
                "started selected local UTM VMs",
                start_artifact.into_iter().collect(),
            ),
            stage_outcome(
                "wait_ready",
                VmLabStageStatus::Pass,
                "selected local UTM VMs became execution-ready",
                ready_text_artifact
                    .into_iter()
                    .chain(ready_json_artifact.into_iter())
                    .collect(),
            ),
            stage_outcome(
                "update_inventory_live_ips",
                VmLabStageStatus::Pass,
                inventory_report.clone(),
                inventory_artifact
                    .into_iter()
                    .chain(combined_artifact.into_iter())
                    .collect(),
            ),
        ],
        Vec::new(),
        Vec::new(),
    )?;
    if config.json_output {
        return match overall_status {
            VmLabCommandOverallStatus::Fail => Err(rendered),
            VmLabCommandOverallStatus::Pass | VmLabCommandOverallStatus::Partial => Ok(rendered),
        };
    }
    Ok(text)
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
    ensure_optional_local_regular_file_path(
        config.ssh_identity_file.as_deref(),
        "SSH identity file",
    )?;
    ensure_optional_local_regular_file_path(
        config.known_hosts_path.as_deref(),
        "SSH known_hosts file",
    )?;
    let output_root = config.output_dir;
    fs::create_dir_all(output_root.as_path()).map_err(|err| {
        format!(
            "create artifact output dir failed ({}): {err}",
            output_root.display()
        )
    })?;
    execute_vm_lab_collect_artifacts_for_targets(
        targets.as_slice(),
        config.ssh_user.as_deref(),
        config.ssh_identity_file.as_deref(),
        config.known_hosts_path.as_deref(),
        output_root.as_path(),
        timeout,
    )
}

fn execute_vm_lab_collect_artifacts_for_targets(
    targets: &[RemoteTarget],
    ssh_user_override: Option<&str>,
    ssh_identity_file: Option<&Path>,
    known_hosts_path: Option<&Path>,
    output_root: &Path,
    timeout: Duration,
) -> Result<String, String> {
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

    for target in targets {
        let effective_user = ssh_user_override.or(target.ssh_user.as_deref());
        let target_dir = output_root.join(sanitize_label_for_path(target.label.as_str()));
        fs::create_dir_all(target_dir.as_path()).map_err(|err| {
            format!(
                "create target artifact dir failed ({}): {err}",
                target_dir.display()
            )
        })?;
        match capture_remote_shell_command_for_target(
            target,
            ssh_user_override,
            ssh_identity_file,
            known_hosts_path,
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
    ensure_optional_local_regular_file_path(
        config.ssh_identity_file.as_deref(),
        "SSH identity file",
    )?;
    ensure_optional_local_regular_file_path(
        config.known_hosts_path.as_deref(),
        "SSH known_hosts file",
    )?;
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
    let authority_target =
        remote_target_from_inventory_entry(&authority_entry, config.ssh_user.as_deref());

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
        config.ssh_identity_file.as_deref(),
        config.known_hosts_path.as_deref(),
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
        scp_to_remote_for_target(
            &authority_target,
            config.ssh_user.as_deref(),
            config.ssh_identity_file.as_deref(),
            config.known_hosts_path.as_deref(),
            assignment_env_path.as_path(),
            remote_assignment_env.as_str(),
            timeout,
        )
        .map_err(|err| format!("copy assignment env to authority failed: {err}"))?,
        "copy assignment env to authority",
    )?;
    ensure_success_status(
        scp_to_remote_for_target(
            &authority_target,
            config.ssh_user.as_deref(),
            config.ssh_identity_file.as_deref(),
            config.known_hosts_path.as_deref(),
            traversal_env_path.as_path(),
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
    let issue_status = run_remote_shell_command_for_target(
        &authority_target,
        config.ssh_user.as_deref(),
        config.ssh_identity_file.as_deref(),
        config.known_hosts_path.as_deref(),
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
        &authority_target,
        config.ssh_user.as_deref(),
        config.ssh_identity_file.as_deref(),
        config.known_hosts_path.as_deref(),
        "/run/rustynet/assignment-issue/rn-assignment.pub",
        assignment_pub_local.as_path(),
        timeout,
    )?;
    capture_remote_file_to_local(
        &authority_target,
        config.ssh_user.as_deref(),
        config.ssh_identity_file.as_deref(),
        config.known_hosts_path.as_deref(),
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
        let target =
            remote_target_from_inventory_entry(&inventory_entry, config.ssh_user.as_deref());
        let assignment_local =
            artifact_dir.join(format!("rn-assignment-{}.assignment", node.node_id));
        let traversal_local = artifact_dir.join(format!("rn-traversal-{}.traversal", node.node_id));
        capture_remote_file_to_local(
            &authority_target,
            config.ssh_user.as_deref(),
            config.ssh_identity_file.as_deref(),
            config.known_hosts_path.as_deref(),
            format!(
                "/run/rustynet/assignment-issue/rn-assignment-{}.assignment",
                node.node_id
            )
            .as_str(),
            assignment_local.as_path(),
            timeout,
        )?;
        capture_remote_file_to_local(
            &authority_target,
            config.ssh_user.as_deref(),
            config.ssh_identity_file.as_deref(),
            config.known_hosts_path.as_deref(),
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
            &StateArtifactInstallPaths {
                assignment_pub: assignment_pub_local.as_path(),
                assignment_bundle: assignment_local.as_path(),
                traversal_pub: traversal_pub_local.as_path(),
                traversal_bundle: traversal_local.as_path(),
                refresh_env: refresh_env_path.as_path(),
            },
            config.ssh_identity_file.as_deref(),
            config.known_hosts_path.as_deref(),
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
    let inventory = load_inventory(config.inventory_path.as_path())?;
    let topology = if let Some(path) = config.topology_path.as_deref() {
        load_vm_lab_topology(path)?
    } else {
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
        inventory.as_slice(),
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
    let phase = bootstrap::BootstrapPhase::parse(config.phase.as_str())?;
    let timeout = timeout_or_default(config.timeout_secs, DEFAULT_RUN_TIMEOUT_SECS);
    ensure_optional_local_regular_file_path(
        config.ssh_identity_file.as_deref(),
        "SSH identity file",
    )?;
    ensure_optional_local_regular_file_path(
        config.known_hosts_path.as_deref(),
        "SSH known_hosts file",
    )?;
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
                    phase.as_str(),
                    target.label
                )
            })?;
        workdirs.insert(target.label.clone(), workdir);
    }

    let mut lines = Vec::new();
    if matches!(
        phase,
        bootstrap::BootstrapPhase::SyncSource | bootstrap::BootstrapPhase::All
    ) {
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
            targets.as_slice(),
            config.ssh_user.as_deref(),
            config.ssh_identity_file.as_deref(),
            config.known_hosts_path.as_deref(),
            sync_source,
            sync_dest_dir.as_str(),
            timeout,
        )?);
        if phase == bootstrap::BootstrapPhase::SyncSource {
            return Ok(lines.join("\n"));
        }
    }

    let phases = if phase == bootstrap::BootstrapPhase::All {
        vec![
            bootstrap::BootstrapPhase::BuildRelease,
            bootstrap::BootstrapPhase::InstallRelease,
            bootstrap::BootstrapPhase::RestartRuntime,
            bootstrap::BootstrapPhase::VerifyRuntime,
        ]
    } else {
        vec![phase]
    };

    for target in &targets {
        let workdir = workdirs
            .get(target.label.as_str())
            .ok_or_else(|| format!("missing bootstrap workdir for {}", target.label))?;
        let effective_user = config.ssh_user.as_deref().or(target.ssh_user.as_deref());
        let context = bootstrap::BootstrapPhaseContext {
            ssh_user: effective_user,
            ssh_identity_file: config.ssh_identity_file.as_deref(),
            known_hosts_path: config.known_hosts_path.as_deref(),
            workdir: workdir.as_str(),
            repo_url: config.repo_url.as_deref(),
            branch: config.branch.as_str(),
            remote: config.remote.as_str(),
            timeout,
        };
        for phase_name in &phases {
            if *phase_name == bootstrap::BootstrapPhase::SyncSource
                && target.platform_profile.platform != VmGuestPlatform::Windows
            {
                continue;
            }
            execute_bootstrap_phase_for_target(phase_name.as_str(), target, &context)?;
            lines.push(format!(
                "{} completed bootstrap phase={} workdir={}",
                target.label,
                phase_name.as_str(),
                workdir
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
        let platform_profile = entry.platform_profile();
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
            } => {
                results.push(StartTarget {
                    alias: entry.alias,
                    utm_name,
                    bundle_path,
                    ssh_user: entry.ssh_user,
                    last_known_ip: entry.last_known_ip,
                    mesh_ip: entry.mesh_ip,
                    platform_profile,
                });
            }
        }
    }
    Ok(results)
}

fn wait_for_local_utm_targets_ready(
    targets: &[StartTarget],
    utmctl_path: &Path,
    ssh_port: u16,
    ssh_identity_file: Option<&Path>,
    known_hosts_path: Option<&Path>,
    timeout: Duration,
) -> Result<Vec<LocalUtmReadyState>, String> {
    let started_at = Instant::now();
    let ssh_port = if ssh_port == 0 { 22 } else { ssh_port };
    let probe_timeout = Duration::from_secs(5).min(timeout);

    loop {
        let states = targets
            .iter()
            .map(|target| {
                observe_local_utm_target_ready(
                    target,
                    utmctl_path,
                    ssh_port,
                    ssh_identity_file,
                    known_hosts_path,
                    probe_timeout,
                )
            })
            .collect::<Vec<_>>();
        if states.iter().all(local_utm_ready_state_is_ready) {
            return Ok(states);
        }
        if started_at.elapsed() >= timeout {
            return Err(format!(
                "timed out waiting for restarted local UTM VMs to become ready\n{}",
                render_local_utm_ready_states(states.as_slice())
            ));
        }
        thread::sleep(Duration::from_secs(2));
    }
}

fn ssh_auth_probe_command(profile: VmPlatformProfile) -> Result<&'static str, String> {
    match profile.remote_shell {
        VmRemoteShell::Posix => Ok("true"),
        VmRemoteShell::Powershell => Ok(
            "powershell.exe -NoLogo -NoProfile -NonInteractive -Command \"$PSVersionTable.PSVersion.ToString() | Out-Null; exit 0\"",
        ),
        VmRemoteShell::Unsupported => Err(format!(
            "vm-lab SSH readiness probing is not yet implemented for platform {}",
            profile.platform.as_str()
        )),
    }
}

fn unmatched_local_utm_advisory_target(platform: VmGuestPlatform, live_ip: &str) -> Option<String> {
    match platform {
        VmGuestPlatform::Linux => Some(rewrite_ssh_target_host("debian@", live_ip)),
        VmGuestPlatform::Macos
        | VmGuestPlatform::Windows
        | VmGuestPlatform::Ios
        | VmGuestPlatform::Android => Some(live_ip.to_string()),
    }
}

fn observe_local_utm_target_ready(
    target: &StartTarget,
    utmctl_path: &Path,
    ssh_port: u16,
    ssh_identity_file: Option<&Path>,
    known_hosts_path: Option<&Path>,
    timeout: Duration,
) -> LocalUtmReadyState {
    let process_present = local_utm_process_present_with_probes(
        utmctl_path,
        Path::new("ps"),
        target.utm_name.as_str(),
        target.bundle_path.as_path(),
        timeout,
    )
    .unwrap_or(false);
    let live_ip = resolve_local_utm_live_host_by_name(
        target.utm_name.as_str(),
        target.last_known_ip.as_deref(),
        target.mesh_ip.as_deref(),
        utmctl_path,
    );
    let ssh_port_status = match live_ip.as_deref() {
        Some(ip) => probe_tcp_port_status(ip, ssh_port, timeout)
            .map(|(status, _)| status)
            .unwrap_or_else(|_| "unknown".to_string()),
        None => "unavailable".to_string(),
    };
    let ssh_auth_status = match (live_ip.as_deref(), target.ssh_user.as_deref()) {
        (None, _) => "skipped-no-live-ip".to_string(),
        (_, None) => "skipped-no-ssh-user".to_string(),
        (_, Some(_)) if ssh_port_status != "open" => "skipped-port-not-open".to_string(),
        (Some(ip), Some(ssh_user)) => match ssh_auth_probe_command(target.platform_profile) {
            Ok(probe_command) => match run_remote_shell_command(
                ip,
                Some(ssh_user),
                ssh_identity_file,
                known_hosts_path,
                probe_command,
                timeout,
            ) {
                Ok(status) if status.success() => "ok".to_string(),
                Ok(status) => format!("failed-exit-{}", status_code(status)),
                Err(err) => format!("error:{err}"),
            },
            Err(err) => format!("error:{err}"),
        },
    };
    LocalUtmReadyState {
        alias: target.alias.clone(),
        utm_name: target.utm_name.clone(),
        process_present,
        live_ip,
        ssh_port_status,
        ssh_auth_status,
    }
}

fn local_utm_ready_state_is_ready(state: &LocalUtmReadyState) -> bool {
    state.process_present
        && state.live_ip.is_some()
        && state.ssh_port_status == "open"
        && state.ssh_auth_status == "ok"
}

fn render_local_utm_ready_states(states: &[LocalUtmReadyState]) -> String {
    states
        .iter()
        .map(|state| {
            format!(
                "{} ready process_present={} live_ip={} ssh_port_status={} ssh_auth_status={}",
                state.alias,
                state.process_present,
                state.live_ip.as_deref().unwrap_or("unavailable"),
                state.ssh_port_status,
                state.ssh_auth_status
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn persist_local_utm_ready_states_to_inventory(
    inventory_path: &Path,
    states: &[LocalUtmReadyState],
) -> Result<String, String> {
    let original = fs::read_to_string(inventory_path).map_err(|err| {
        format!(
            "read vm inventory for live IP update failed ({}): {err}",
            inventory_path.display()
        )
    })?;
    let mut document: Value = serde_json::from_str(original.as_str()).map_err(|err| {
        format!(
            "parse vm inventory for live IP update failed ({}): {err}",
            inventory_path.display()
        )
    })?;
    let object = document.as_object_mut().ok_or_else(|| {
        format!(
            "vm inventory root must be an object: {}",
            inventory_path.display()
        )
    })?;
    let entries = object
        .get_mut("entries")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| {
            format!(
                "vm inventory is missing entries array: {}",
                inventory_path.display()
            )
        })?;

    let updates = states
        .iter()
        .filter_map(|state| {
            state
                .live_ip
                .as_ref()
                .map(|live_ip| (state.alias.as_str(), live_ip.as_str()))
        })
        .collect::<BTreeMap<_, _>>();
    if updates.is_empty() {
        return Ok(format!(
            "inventory not updated because no authoritative live IPs were observed in {}",
            inventory_path.display()
        ));
    }

    let mut updated_aliases = Vec::new();
    let mut missing_aliases = Vec::new();
    for (alias, live_ip) in &updates {
        let Some(entry_value) = entries.iter_mut().find(|entry| {
            entry
                .as_object()
                .and_then(|object| object.get("alias"))
                .and_then(Value::as_str)
                == Some(*alias)
        }) else {
            missing_aliases.push((*alias).to_string());
            continue;
        };
        let entry = entry_value.as_object_mut().ok_or_else(|| {
            format!(
                "vm inventory entry for alias {} must be an object: {}",
                alias,
                inventory_path.display()
            )
        })?;
        let current_ssh_target = required_string_field(entry, "ssh_target")?;
        let new_ssh_target = rewrite_ssh_target_host(current_ssh_target.as_str(), live_ip);
        ensure_ssh_target("ssh_target", new_ssh_target.as_str())?;
        ensure_no_control_chars("last_known_ip", live_ip)?;
        entry.insert(
            "ssh_target".to_string(),
            Value::String(new_ssh_target.clone()),
        );
        entry.insert(
            "last_known_ip".to_string(),
            Value::String((*live_ip).to_string()),
        );
        if let Some(existing_live_ips) = entry.get_mut("live_ips") {
            let mut ordered = vec![(*live_ip).to_string()];
            if let Some(values) = existing_live_ips.as_array() {
                for value in values.iter().filter_map(Value::as_str) {
                    if !ordered.iter().any(|existing| existing == value) {
                        ordered.push(value.to_string());
                    }
                }
            }
            *existing_live_ips =
                Value::Array(ordered.into_iter().map(Value::String).collect::<Vec<_>>());
        }
        updated_aliases.push(format!(
            "{} ssh_target={} last_known_ip={}",
            alias, new_ssh_target, live_ip
        ));
    }
    if !missing_aliases.is_empty() {
        return Err(format!(
            "cannot update vm inventory {}; aliases not found: {}",
            inventory_path.display(),
            missing_aliases.join(", ")
        ));
    }

    let rendered = serde_json::to_string_pretty(&document)
        .map_err(|err| format!("serialize updated vm inventory failed: {err}"))?;
    write_text_file_atomically(inventory_path, rendered.as_str())?;
    load_inventory(inventory_path)?;
    Ok(format!(
        "updated inventory live IPs in {}: {}",
        inventory_path.display(),
        updated_aliases.join("; ")
    ))
}

fn write_text_file_atomically(path: &Path, contents: &str) -> Result<(), String> {
    let parent = path.parent().ok_or_else(|| {
        format!(
            "cannot atomically write file without parent directory: {}",
            path.display()
        )
    })?;
    fs::create_dir_all(parent).map_err(|err| {
        format!(
            "create parent directory for atomic write failed ({}): {err}",
            parent.display()
        )
    })?;
    let temp_path = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("inventory"),
        unique_suffix()
    ));
    let normalized_contents = if contents.ends_with('\n') {
        contents.to_string()
    } else {
        format!("{contents}\n")
    };
    fs::write(temp_path.as_path(), normalized_contents.as_bytes()).map_err(|err| {
        format!(
            "write temporary file for atomic write failed ({}): {err}",
            temp_path.display()
        )
    })?;
    fs::rename(temp_path.as_path(), path).map_err(|err| {
        let _ = fs::remove_file(temp_path.as_path());
        format!(
            "replace file during atomic write failed ({} -> {}): {err}",
            temp_path.display(),
            path.display()
        )
    })
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
                resolved.push(remote_target_from_inventory_entry(&entry, None));
            }
        }
    }

    for raw_target in raw_targets {
        ensure_ssh_target("target", raw_target)?;
        let key = format!("|{raw_target}");
        if seen.insert(key) {
            resolved.push(remote_target_from_raw_target(
                raw_target.clone(),
                raw_target.clone(),
            ));
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
    let resolved_target = resolved_inventory_ssh_target(&entry);
    let normalized_target = normalized_ssh_target(
        resolved_target.as_str(),
        entry.ssh_user.as_deref(),
        role_label,
    )?;
    let platform_profile = entry.platform_profile();
    let utm_name = entry
        .controller
        .as_ref()
        .map(|VmController::LocalUtm { utm_name, .. }| utm_name.clone());
    Ok(RoleTarget {
        label: entry.alias,
        normalized_target,
        network_group: entry.network_group,
        utm_name,
        platform_profile,
        rustynet_src_dir: entry.rustynet_src_dir.clone().or_else(|| {
            Some(default_rustynet_src_dir_for_profile(
                platform_profile,
                entry.ssh_user.as_deref(),
            ))
        }),
    })
}

fn resolve_role_target_from_raw(role_label: &str, raw_target: &str) -> Result<RoleTarget, String> {
    ensure_ssh_target(role_label, raw_target)?;
    if !raw_target.contains('@') {
        return Err(format!(
            "{role_label} raw target must include an explicit SSH user (user@host): {raw_target}"
        ));
    }
    let platform_profile = default_platform_profile(VmGuestPlatform::Linux);
    let ssh_user = ssh_target_user(raw_target).map(str::to_string);
    Ok(RoleTarget {
        label: raw_target.to_string(),
        normalized_target: raw_target.to_string(),
        network_group: None,
        utm_name: None,
        platform_profile,
        rustynet_src_dir: Some(default_rustynet_src_dir_for_profile(
            platform_profile,
            ssh_user.as_deref(),
        )),
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

fn remote_target_from_inventory_entry(
    entry: &VmInventoryEntry,
    ssh_user_override: Option<&str>,
) -> RemoteTarget {
    let platform_profile = entry.platform_profile();
    let ssh_user = ssh_user_override
        .map(ToString::to_string)
        .or_else(|| entry.ssh_user.clone());
    RemoteTarget {
        label: entry.alias.clone(),
        ssh_target: resolved_inventory_ssh_target(entry),
        ssh_user: ssh_user.clone(),
        controller: entry.controller.clone(),
        platform_profile,
        rustynet_src_dir: entry.rustynet_src_dir.clone().or_else(|| {
            Some(default_rustynet_src_dir_for_profile(
                platform_profile,
                ssh_user.as_deref(),
            ))
        }),
        remote_temp_dir: entry
            .remote_temp_dir
            .clone()
            .or_else(|| Some(default_remote_temp_dir_for_profile(platform_profile))),
    }
}

fn remote_target_from_raw_target(label: String, ssh_target: String) -> RemoteTarget {
    let platform_profile = default_platform_profile(VmGuestPlatform::Linux);
    let ssh_user = ssh_target_user(ssh_target.as_str()).map(str::to_string);
    RemoteTarget {
        label,
        ssh_target,
        ssh_user: ssh_user.clone(),
        controller: None,
        platform_profile,
        rustynet_src_dir: Some(default_rustynet_src_dir_for_profile(
            platform_profile,
            ssh_user.as_deref(),
        )),
        remote_temp_dir: Some(default_remote_temp_dir_for_profile(platform_profile)),
    }
}

fn remote_target_from_start_target(target: &StartTarget) -> RemoteTarget {
    RemoteTarget {
        label: target.alias.clone(),
        ssh_target: target
            .last_known_ip
            .clone()
            .or_else(|| target.mesh_ip.clone())
            .unwrap_or_else(|| target.utm_name.clone()),
        ssh_user: target.ssh_user.clone(),
        controller: Some(VmController::LocalUtm {
            utm_name: target.utm_name.clone(),
            bundle_path: target.bundle_path.clone(),
        }),
        platform_profile: target.platform_profile,
        rustynet_src_dir: None,
        remote_temp_dir: None,
    }
}

fn resolved_inventory_ssh_target(entry: &VmInventoryEntry) -> String {
    resolved_inventory_ssh_target_with_utmctl(entry, default_utmctl_path().as_path())
}

fn resolved_inventory_ssh_target_with_utmctl(
    entry: &VmInventoryEntry,
    utmctl_path: &Path,
) -> String {
    resolve_local_utm_live_host(entry, utmctl_path)
        .map(|host| rewrite_ssh_target_host(entry.ssh_target.as_str(), host.as_str()))
        .unwrap_or_else(|| entry.ssh_target.clone())
}

fn resolve_local_utm_live_host(entry: &VmInventoryEntry, utmctl_path: &Path) -> Option<String> {
    let utm_name = match entry.controller.as_ref()? {
        VmController::LocalUtm { utm_name, .. } => utm_name,
    };
    resolve_local_utm_live_host_by_name(
        utm_name.as_str(),
        entry.last_known_ip.as_deref(),
        entry.mesh_ip.as_deref(),
        utmctl_path,
    )
}

fn resolve_local_utm_live_host_by_name(
    utm_name: &str,
    last_known_ip: Option<&str>,
    mesh_ip: Option<&str>,
    utmctl_path: &Path,
) -> Option<String> {
    if !utmctl_path.is_file() {
        return None;
    }
    let mut command = Command::new(utmctl_path);
    command.arg("ip-address").arg(utm_name);
    let output = run_output_with_timeout(
        &mut command,
        Duration::from_secs(DEFAULT_UTM_IP_DISCOVERY_TIMEOUT_SECS),
    )
    .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8(output.stdout).ok()?;
    select_live_ssh_host_from_utm_output(stdout.as_str(), last_known_ip, mesh_ip)
}

fn matches_local_utm_inventory_entry(
    entry: &VmInventoryEntry,
    bundle_path: &Path,
    utm_name: &str,
) -> bool {
    let Some(VmController::LocalUtm {
        utm_name: inventory_utm_name,
        bundle_path: inventory_bundle_path,
    }) = entry.controller.as_ref()
    else {
        return false;
    };
    if inventory_utm_name == utm_name {
        return true;
    }
    match (
        fs::canonicalize(bundle_path),
        fs::canonicalize(inventory_bundle_path.as_path()),
    ) {
        (Ok(observed), Ok(expected)) => observed == expected,
        _ => false,
    }
}

fn probe_tcp_port_status(
    ip: &str,
    port: u16,
    timeout: Duration,
) -> Result<(String, Option<String>), String> {
    let parsed_ip = ip
        .trim()
        .parse::<IpAddr>()
        .map_err(|err| format!("invalid SSH probe IP {ip:?}: {err}"))?;
    let socket = SocketAddr::new(parsed_ip, port);
    match TcpStream::connect_timeout(&socket, timeout) {
        Ok(_) => Ok(("open".to_string(), None)),
        Err(err) => Ok(("closed".to_string(), Some(format!("{err}")))),
    }
}

fn discover_local_utm_bundle_paths(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut bundles = Vec::new();
    discover_local_utm_bundle_paths_recursive(root, &mut bundles)?;
    bundles.sort();
    bundles.dedup();
    Ok(bundles)
}

fn discover_local_utm_bundle_paths_recursive(
    current: &Path,
    bundles: &mut Vec<PathBuf>,
) -> Result<(), String> {
    let mut entries = fs::read_dir(current)
        .map_err(|err| {
            format!(
                "read UTM documents directory failed ({}): {err}",
                current.display()
            )
        })?
        .filter_map(Result::ok)
        .collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|err| format!("read file type failed ({}): {err}", path.display()))?;
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            if path.extension().and_then(|value| value.to_str()) == Some("utm") {
                bundles.push(fs::canonicalize(path.as_path()).map_err(|err| {
                    format!("canonicalize UTM bundle failed ({}): {err}", path.display())
                })?);
            } else {
                discover_local_utm_bundle_paths_recursive(path.as_path(), bundles)?;
            }
        }
    }
    Ok(())
}

fn select_live_ssh_host_from_utm_output(
    output: &str,
    last_known_ip: Option<&str>,
    mesh_ip: Option<&str>,
) -> Option<String> {
    let candidates = output
        .lines()
        .filter_map(|line| line.trim().parse::<IpAddr>().ok())
        .collect::<Vec<_>>();
    select_preferred_live_ssh_ip(candidates.as_slice(), last_known_ip, mesh_ip)
        .map(|ip| ip.to_string())
}

fn select_preferred_live_ssh_ip(
    candidates: &[IpAddr],
    last_known_ip: Option<&str>,
    mesh_ip: Option<&str>,
) -> Option<IpAddr> {
    let last_known_ip = last_known_ip.and_then(|value| value.parse::<IpAddr>().ok());
    let mesh_ip = mesh_ip.and_then(|value| value.parse::<IpAddr>().ok());
    candidates
        .iter()
        .copied()
        .filter(|candidate| is_viable_live_ssh_ip(*candidate))
        .filter(|candidate| Some(*candidate) != mesh_ip)
        .max_by_key(|candidate| live_ssh_ip_score(*candidate, last_known_ip))
}

fn is_viable_live_ssh_ip(candidate: IpAddr) -> bool {
    match candidate {
        IpAddr::V4(addr) => !(addr.is_unspecified() || addr.is_loopback() || addr.is_multicast()),
        IpAddr::V6(addr) => {
            !(addr.is_unspecified()
                || addr.is_loopback()
                || addr.is_multicast()
                || addr.is_unicast_link_local())
        }
    }
}

fn live_ssh_ip_score(candidate: IpAddr, last_known_ip: Option<IpAddr>) -> i32 {
    let mut score = 0;
    if Some(candidate) == last_known_ip {
        score += 100;
    }
    if let Some(last_known_ip) = last_known_ip
        && std::mem::discriminant(&candidate) == std::mem::discriminant(&last_known_ip)
    {
        score += 40;
    }
    match candidate {
        IpAddr::V4(addr) => {
            score += 30;
            if addr.is_private() {
                score += 20;
            }
            if ipv4_is_shared_address_space(addr) {
                score -= 10;
            }
        }
        IpAddr::V6(addr) => {
            if !addr.is_unique_local() {
                score += 5;
            }
        }
    }
    score
}

fn ipv4_is_shared_address_space(addr: std::net::Ipv4Addr) -> bool {
    let octets = addr.octets();
    octets[0] == 100 && (octets[1] & 0b1100_0000) == 0b0100_0000
}

fn rewrite_ssh_target_host(ssh_target: &str, new_host: &str) -> String {
    let formatted_host = if new_host.contains(':') {
        format!("[{new_host}]")
    } else {
        new_host.to_string()
    };
    match ssh_target.rsplit_once('@') {
        Some((user, _)) => format!("{user}@{formatted_host}"),
        None => formatted_host,
    }
}

fn literal_ip_host_from_ssh_target(ssh_target: &str) -> Option<String> {
    let host = ssh_target_host(ssh_target);
    host.parse::<IpAddr>().ok().map(|_| host)
}

fn select_inventory_entries(
    inventory: &[VmInventoryEntry],
    aliases: &[String],
    select_all: bool,
) -> Result<Vec<VmInventoryEntry>, String> {
    let requested = if select_all {
        inventory
            .iter()
            .filter(|entry| entry.include_in_all.unwrap_or(true))
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
    let ssh_password = optional_string_field(object, "ssh_password")?;
    if let Some(value) = ssh_password.as_deref() {
        ensure_no_control_chars("ssh_password", value)?;
    }
    let include_in_all = optional_bool_field(object, "include_in_all")?;
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
    let remote_temp_dir = optional_string_field(object, "remote_temp_dir")?;
    if let Some(value) = remote_temp_dir.as_deref() {
        ensure_no_control_chars("remote_temp_dir", value)?;
    }
    let rustynet_src_dir = optional_string_field(object, "rustynet_src_dir")?;
    if let Some(value) = rustynet_src_dir.as_deref() {
        ensure_no_control_chars("rustynet_src_dir", value)?;
    }
    let platform = match optional_string_field(object, "platform")? {
        Some(value) => {
            Some(VmGuestPlatform::parse(value.as_str()).map_err(|err| format!("platform: {err}"))?)
        }
        None => None,
    };
    let remote_shell = match optional_string_field(object, "remote_shell")? {
        Some(value) => Some(
            VmRemoteShell::parse(value.as_str()).map_err(|err| format!("remote_shell: {err}"))?,
        ),
        None => None,
    };
    let guest_exec_mode = match optional_string_field(object, "guest_exec_mode")? {
        Some(value) => Some(
            VmGuestExecMode::parse(value.as_str())
                .map_err(|err| format!("guest_exec_mode: {err}"))?,
        ),
        None => None,
    };
    let service_manager = match optional_string_field(object, "service_manager")? {
        Some(value) => Some(
            VmServiceManager::parse(value.as_str())
                .map_err(|err| format!("service_manager: {err}"))?,
        ),
        None => None,
    };
    let controller = match object.get("controller") {
        None | Some(Value::Null) => None,
        Some(value) => Some(parse_controller(value)?),
    };
    Ok(VmInventoryEntry {
        alias,
        ssh_target,
        ssh_user,
        ssh_password,
        include_in_all,
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
        remote_temp_dir,
        rustynet_src_dir,
        platform,
        remote_shell,
        guest_exec_mode,
        service_manager,
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

fn build_windows_repo_sync_script(
    repo_url: &str,
    dest_dir: &str,
    branch: &str,
    remote: &str,
) -> Result<String, String> {
    ensure_no_control_chars("repo URL", repo_url)?;
    ensure_no_control_chars("destination directory", dest_dir)?;
    ensure_no_control_chars("branch", branch)?;
    ensure_no_control_chars("remote", remote)?;
    Ok(format!(
        "Set-StrictMode -Version Latest; \
         $ErrorActionPreference = 'Stop'; \
         $dest = {dest}; \
         $parent = Split-Path -Parent $dest; \
         if ($parent -and -not (Test-Path -LiteralPath $parent)) {{ New-Item -ItemType Directory -Force -Path $parent | Out-Null }}; \
         if (-not (Test-Path -LiteralPath $dest)) {{ git clone --origin {remote_name} --branch {branch_name} --single-branch {repo} $dest | Out-Null }} \
         elseif (Test-Path -LiteralPath (Join-Path $dest '.git')) {{ \
             git -C $dest remote set-url {remote_name} {repo}; \
             git -C $dest fetch {remote_name} {branch_name} --prune; \
             git -C $dest checkout -B {branch_name} FETCH_HEAD; \
             git -C $dest reset --hard FETCH_HEAD; \
             git -C $dest clean -fdx \
         }} else {{ throw \"destination exists but is not a git repository: $dest\" }}",
        dest = powershell_quote(dest_dir)?,
        remote_name = powershell_quote(remote)?,
        branch_name = powershell_quote(branch)?,
        repo = powershell_quote(repo_url)?,
    ))
}

fn build_repo_sync_script_for_target(
    target: &RemoteTarget,
    repo_url: &str,
    dest_dir: &str,
    branch: &str,
    remote: &str,
) -> Result<String, String> {
    match repo_sync_dispatch_kind_for_target(target, RepoSyncMode::Git)? {
        RepoSyncDispatchKind::PosixGit => {
            build_repo_sync_script(repo_url, dest_dir, branch, remote)
        }
        RepoSyncDispatchKind::WindowsPowershellGit => {
            build_windows_repo_sync_script(repo_url, dest_dir, branch, remote)
        }
        other => Err(format!(
            "repo sync dispatch mismatch for {}: {other:?}",
            target.label
        )),
    }
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

fn build_windows_local_source_extract_script(
    dest_dir: &str,
    remote_archive_path: &str,
) -> Result<String, String> {
    ensure_no_control_chars("destination directory", dest_dir)?;
    ensure_no_control_chars("remote archive path", remote_archive_path)?;
    Ok(format!(
        "Set-StrictMode -Version Latest; \
         $ErrorActionPreference = 'Stop'; \
         $dest = {dest}; \
         $archive = {archive}; \
         $parent = Split-Path -Parent $dest; \
         if ($parent -and -not (Test-Path -LiteralPath $parent)) {{ New-Item -ItemType Directory -Force -Path $parent | Out-Null }}; \
         if (Test-Path -LiteralPath $dest) {{ Remove-Item -LiteralPath $dest -Recurse -Force }}; \
         New-Item -ItemType Directory -Force -Path $dest | Out-Null; \
         Expand-Archive -LiteralPath $archive -DestinationPath $dest -Force; \
         Remove-Item -LiteralPath $archive -Force;",
        dest = powershell_quote(dest_dir)?,
        archive = powershell_quote(remote_archive_path)?,
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
        && let Err(raw_err) =
            write_raw_directory_archive(source_dir, archive_path.as_path(), extras.as_ref())
    {
        let _ = fs::remove_file(archive_path.as_path());
        return Err(format!(
            "local source archive failed via git-managed path ({git_err}); raw directory fallback also failed ({raw_err})"
        ));
    }
    Ok(LocalSourceArchive { path: archive_path })
}

fn prepare_local_source_zip_archive(
    source_dir: &Path,
    timeout: Duration,
) -> Result<LocalSourceArchive, String> {
    ensure_local_directory_path(source_dir, "local source dir")?;
    let archive_path =
        std::env::temp_dir().join(format!("rustynet-vm-lab-source-{}.zip", unique_suffix()));
    let extras = prepare_local_source_bundle_extras(source_dir, timeout)?;
    if let Err(git_err) =
        write_git_worktree_zip_archive(source_dir, archive_path.as_path(), timeout, extras.as_ref())
        && let Err(raw_err) =
            write_raw_directory_zip_archive(source_dir, archive_path.as_path(), extras.as_ref())
    {
        let _ = fs::remove_file(archive_path.as_path());
        return Err(format!(
            "local ZIP source archive failed via git-managed path ({git_err}); raw directory fallback also failed ({raw_err})"
        ));
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

fn write_raw_directory_zip_archive(
    source_dir: &Path,
    archive_path: &Path,
    extras: Option<&LocalSourceBundleExtras>,
) -> Result<(), String> {
    let file = fs::File::create(archive_path).map_err(|err| {
        format!(
            "create raw local ZIP source archive failed ({}): {err}",
            archive_path.display()
        )
    })?;
    let mut zip = ZipWriter::new(file);
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .unix_permissions(0o644);
    let mut included = 0usize;
    append_raw_local_source_tree_to_zip(&mut zip, &options, source_dir, source_dir, &mut included)?;
    append_local_source_bundle_extras_to_zip(&mut zip, &options, extras, &mut included)?;
    if included == 0 {
        let _ = fs::remove_file(archive_path);
        return Err(format!(
            "local source dir did not yield any syncable files for ZIP archive: {}",
            source_dir.display()
        ));
    }
    zip.finish().map_err(|err| {
        format!(
            "finalize raw local ZIP source archive failed ({}): {err}",
            archive_path.display()
        )
    })?;
    Ok(())
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

fn write_git_worktree_zip_archive(
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
            "collect local ZIP source file list failed with status {}",
            status_code(output.status)
        ));
    }

    let file = fs::File::create(archive_path).map_err(|err| {
        format!(
            "create local ZIP source archive failed ({}): {err}",
            archive_path.display()
        )
    })?;
    let mut zip = ZipWriter::new(file);
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .unix_permissions(0o644);
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
        if !absolute_path.is_file() {
            continue;
        }
        append_file_to_zip(
            &mut zip,
            &options,
            absolute_path.as_path(),
            relative_path,
            &mut included,
        )?;
    }
    append_local_source_bundle_extras_to_zip(&mut zip, &options, extras, &mut included)?;
    if included == 0 {
        return Err(format!(
            "local source dir did not yield any syncable files for ZIP archive: {}",
            source_dir.display()
        ));
    }
    zip.finish().map_err(|err| {
        format!(
            "finalize local ZIP source archive failed ({}): {err}",
            archive_path.display()
        )
    })?;
    Ok(())
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
        if stderr.contains("--offline was specified")
            || stderr.contains("failed to download")
            || stderr.contains("failed to sync")
        {
            let _ = fs::remove_dir_all(temp_root.as_path());
            return Ok(None);
        }
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

fn append_local_source_bundle_extras_to_zip(
    zip: &mut ZipWriter<fs::File>,
    options: &SimpleFileOptions,
    extras: Option<&LocalSourceBundleExtras>,
    included: &mut usize,
) -> Result<(), String> {
    let Some(extras) = extras else {
        return Ok(());
    };
    if let Some(vendor_dir) = extras.vendor_dir.as_deref() {
        append_directory_tree_to_zip(zip, options, vendor_dir, Path::new("vendor"), included)?;
    }
    if let Some(cargo_config_path) = extras.cargo_config_path.as_deref() {
        append_file_to_zip(
            zip,
            options,
            cargo_config_path,
            Path::new(".cargo/config.toml"),
            included,
        )?;
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

fn append_raw_local_source_tree_to_zip(
    zip: &mut ZipWriter<fs::File>,
    options: &SimpleFileOptions,
    source_root: &Path,
    current_dir: &Path,
    included: &mut usize,
) -> Result<(), String> {
    let entries = fs::read_dir(current_dir).map_err(|err| {
        format!(
            "read local ZIP source dir failed ({}): {err}",
            current_dir.display()
        )
    })?;
    for entry in entries {
        let entry = entry.map_err(|err| {
            format!(
                "read local ZIP source dir entry failed ({}): {err}",
                current_dir.display()
            )
        })?;
        let path = entry.path();
        let relative = path.strip_prefix(source_root).map_err(|err| {
            format!(
                "strip local ZIP source prefix failed ({}): {err}",
                path.display()
            )
        })?;
        if should_skip_raw_local_source_path(relative) {
            continue;
        }
        let file_type = entry.file_type().map_err(|err| {
            format!(
                "read local ZIP source entry type failed ({}): {err}",
                path.display()
            )
        })?;
        if file_type.is_dir() {
            append_raw_local_source_tree_to_zip(
                zip,
                options,
                source_root,
                path.as_path(),
                included,
            )?;
            continue;
        }
        append_file_to_zip(zip, options, path.as_path(), relative, included)?;
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

fn append_directory_tree_to_zip(
    zip: &mut ZipWriter<fs::File>,
    options: &SimpleFileOptions,
    source_root: &Path,
    archive_root: &Path,
    included: &mut usize,
) -> Result<(), String> {
    let entries = fs::read_dir(source_root).map_err(|err| {
        format!(
            "read ZIP archive source dir failed ({}): {err}",
            source_root.display()
        )
    })?;
    for entry in entries {
        let entry = entry.map_err(|err| {
            format!(
                "read ZIP archive source dir entry failed ({}): {err}",
                source_root.display()
            )
        })?;
        let path = entry.path();
        let archive_path = archive_root.join(entry.file_name());
        let file_type = entry.file_type().map_err(|err| {
            format!(
                "read ZIP archive source entry type failed ({}): {err}",
                path.display()
            )
        })?;
        if file_type.is_dir() {
            append_directory_tree_to_zip(
                zip,
                options,
                path.as_path(),
                archive_path.as_path(),
                included,
            )?;
            continue;
        }
        append_file_to_zip(
            zip,
            options,
            path.as_path(),
            archive_path.as_path(),
            included,
        )?;
    }
    Ok(())
}

fn append_file_to_zip(
    zip: &mut ZipWriter<fs::File>,
    options: &SimpleFileOptions,
    source_path: &Path,
    archive_path: &Path,
    included: &mut usize,
) -> Result<(), String> {
    let name = archive_path
        .to_str()
        .ok_or_else(|| {
            format!(
                "path is not valid UTF-8 for ZIP archive: {}",
                archive_path.display()
            )
        })?
        .replace('\\', "/");
    zip.start_file(name, *options).map_err(|err| {
        format!(
            "start ZIP file entry failed ({}): {err}",
            archive_path.display()
        )
    })?;
    let mut input = fs::File::open(source_path).map_err(|err| {
        format!(
            "open ZIP source file failed ({}): {err}",
            source_path.display()
        )
    })?;
    std::io::copy(&mut input, zip)
        .map_err(|err| format!("write ZIP entry failed ({}): {err}", archive_path.display()))?;
    *included += 1;
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
    target: &RemoteTarget,
    ssh_user_override: Option<&str>,
    ssh_identity_file: Option<&Path>,
    known_hosts_path: Option<&Path>,
    dest_dir: &str,
    timeout: Duration,
) -> Result<(), String> {
    ensure_local_regular_file_path(archive_path, "local source archive")?;
    if target.platform_profile.platform == VmGuestPlatform::Windows {
        let remote_archive = format!(
            r"C:\ProgramData\Rustynet\vm-lab\rn-vm-lab-source-{}.zip",
            unique_suffix()
        );
        ensure_success_status(
            scp_to_remote_for_target(
                target,
                ssh_user_override,
                ssh_identity_file,
                known_hosts_path,
                archive_path,
                remote_archive.as_str(),
                timeout,
            )?,
            "copy local ZIP source archive to Windows remote",
        )?;
        let extract_script =
            build_windows_local_source_extract_script(dest_dir, remote_archive.as_str())?;
        let status = run_remote_shell_command_for_target(
            target,
            ssh_user_override,
            ssh_identity_file,
            known_hosts_path,
            extract_script.as_str(),
            timeout,
        )?;
        return ensure_success_status(status, "extract local ZIP source archive on Windows remote");
    }
    // These guest images accept SFTP writes into the SSH user's home directory
    // reliably, while absolute /tmp uploads are rejected on some hosts.
    let remote_archive = if remote_target_local_utm(target).is_some() {
        let ssh_user = remote_target_effective_user(target, ssh_user_override)?;
        format!(
            "{}/.rn-vm-lab-source-{}.tar",
            remote_target_home(ssh_user.as_str()),
            unique_suffix()
        )
    } else {
        format!(".rn-vm-lab-source-{}.tar", unique_suffix())
    };
    ensure_success_status(
        scp_to_remote_for_target(
            target,
            ssh_user_override,
            ssh_identity_file,
            known_hosts_path,
            archive_path,
            remote_archive.as_str(),
            timeout,
        )?,
        "copy local source archive to remote",
    )?;
    let extract_script = build_local_source_extract_script(dest_dir, remote_archive.as_str())?;
    let status = run_remote_shell_command_for_target(
        target,
        ssh_user_override,
        ssh_identity_file,
        known_hosts_path,
        extract_script.as_str(),
        timeout,
    )?;
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

fn ensure_optional_local_regular_file_path(path: Option<&Path>, label: &str) -> Result<(), String> {
    if let Some(path) = path {
        ensure_local_regular_file_path(path, label)?;
    }
    Ok(())
}

fn append_ssh_transport_options(
    command: &mut Command,
    ssh_identity_file: Option<&Path>,
    known_hosts_path: Option<&Path>,
) -> Result<(), String> {
    ensure_optional_local_regular_file_path(ssh_identity_file, "SSH identity file")?;
    ensure_optional_local_regular_file_path(known_hosts_path, "SSH known_hosts file")?;
    if let Some(path) = ssh_identity_file {
        command.arg("-i").arg(path);
    }
    if let Some(path) = known_hosts_path {
        command
            .arg("-o")
            .arg(format!("UserKnownHostsFile={}", path.display()));
    }
    Ok(())
}

fn remote_target_local_utm(target: &RemoteTarget) -> Option<(&str, &Path)> {
    match target.controller.as_ref() {
        Some(VmController::LocalUtm {
            utm_name,
            bundle_path,
        }) => Some((utm_name.as_str(), bundle_path.as_path())),
        None => None,
    }
}

fn remote_target_effective_user(
    target: &RemoteTarget,
    ssh_user_override: Option<&str>,
) -> Result<String, String> {
    if let Some(ssh_user) = ssh_user_override {
        ensure_ssh_user(ssh_user)?;
        return Ok(ssh_user.to_string());
    }
    if let Some(ssh_user) = target.ssh_user.as_deref() {
        ensure_ssh_user(ssh_user)?;
        return Ok(ssh_user.to_string());
    }
    if let Some(ssh_user) = ssh_target_user(target.ssh_target.as_str()) {
        ensure_ssh_user(ssh_user)?;
        return Ok(ssh_user.to_string());
    }
    Err(format!(
        "UTM-backed target {} requires an explicit ssh_user or user@host SSH target",
        target.label
    ))
}

fn remote_target_home(ssh_user: &str) -> String {
    if ssh_user == "root" {
        "/root".to_string()
    } else {
        format!("/home/{ssh_user}")
    }
}

fn utmctl_binary_path() -> Result<PathBuf, String> {
    let path = default_utmctl_path();
    if !path.is_file() {
        return Err(format!("utmctl binary is not present: {}", path.display()));
    }
    Ok(path)
}

fn utm_push_raw(
    utm_name: &str,
    src: &Path,
    dst: &str,
    timeout: Duration,
) -> Result<ExitStatus, String> {
    ensure_local_regular_file_path(src, "UTM push source file")?;
    ensure_no_control_chars("UTM push destination path", dst)?;
    let utmctl_path = utmctl_binary_path()?;
    let stdin = fs::File::open(src)
        .map_err(|err| format!("open UTM push source failed ({}): {err}", src.display()))?;
    let mut command = Command::new(utmctl_path);
    command.arg("file").arg("push").arg(utm_name).arg(dst);
    command.stdin(Stdio::from(stdin));
    command.stdout(Stdio::null());
    command.stderr(Stdio::null());
    run_status_with_timeout_preserve(&mut command, timeout)
}

fn utm_pull_raw(
    utm_name: &str,
    src: &str,
    dst: &Path,
    timeout: Duration,
) -> Result<ExitStatus, String> {
    ensure_no_control_chars("UTM pull source path", src)?;
    let utmctl_path = utmctl_binary_path()?;
    let parent = dst.parent().filter(|path| !path.as_os_str().is_empty());
    if let Some(parent) = parent {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "create UTM pull destination dir failed ({}): {err}",
                parent.display()
            )
        })?;
    }
    let stdout = fs::File::create(dst).map_err(|err| {
        format!(
            "create UTM pull destination failed ({}): {err}",
            dst.display()
        )
    })?;
    let mut command = Command::new(utmctl_path);
    command.arg("file").arg("pull").arg(utm_name).arg(src);
    command.stdin(Stdio::null());
    command.stdout(Stdio::from(stdout));
    command.stderr(Stdio::null());
    run_status_with_timeout_preserve(&mut command, timeout)
}

fn utm_exec_root_raw(
    utm_name: &str,
    command_script: &str,
    timeout: Duration,
) -> Result<ExitStatus, String> {
    ensure_no_control_chars("UTM exec command", command_script)?;
    let utmctl_path = utmctl_binary_path()?;
    let mut command = Command::new(utmctl_path);
    command
        .arg("exec")
        .arg(utm_name)
        .arg("--cmd")
        .arg("/bin/bash")
        .arg("-lc")
        .arg(command_script);
    run_status_with_timeout(&mut command, timeout)
}

fn utm_cleanup_exec_files(
    utm_name: &str,
    remote_script: &str,
    remote_wrapper: &str,
    remote_output: &str,
    remote_rc: &str,
) {
    let cleanup = format!(
        "rm -f {} {} {} {}",
        shell_quote(remote_script),
        shell_quote(remote_wrapper),
        shell_quote(remote_output),
        shell_quote(remote_rc),
    );
    let _ = utm_exec_root_raw(utm_name, cleanup.as_str(), Duration::from_secs(20));
}

fn execute_utm_remote_script_as_user(
    utm_name: &str,
    ssh_user: &str,
    home: &str,
    remote_script: &str,
    timeout: Duration,
) -> Result<(i32, String), String> {
    ensure_ssh_user(ssh_user)?;
    ensure_no_control_chars("UTM exec home", home)?;
    if remote_script.chars().any(|ch| ch == '\0') {
        return Err("UTM remote script contains unsupported NUL byte".to_string());
    }

    let temp_root = std::env::temp_dir().join(format!("rustynet-vm-lab-utm-{}", unique_suffix()));
    fs::create_dir_all(temp_root.as_path()).map_err(|err| {
        format!(
            "create local UTM helper dir failed ({}): {err}",
            temp_root.display()
        )
    })?;
    let local_script = temp_root.join("command.sh");
    let local_wrapper = temp_root.join("wrapper.sh");
    let local_output = temp_root.join("output.txt");
    let local_rc = temp_root.join("rc.txt");
    fs::write(
        local_script.as_path(),
        format!("#!/usr/bin/env bash\nset -euo pipefail\n{remote_script}\n").as_bytes(),
    )
    .map_err(|err| {
        let _ = fs::remove_dir_all(temp_root.as_path());
        format!(
            "write local UTM command script failed ({}): {err}",
            local_script.display()
        )
    })?;
    fs::write(
        local_wrapper.as_path(),
        br#"#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 5 ]]; then
  echo "usage: rn-utm-wrapper.sh <user> <home> <command-script> <output-path> <rc-path>" >&2
  exit 2
fi

user="$1"
home="$2"
command_script="$3"
output_path="$4"
rc_path="$5"
rc=0

if [[ "$user" == "root" ]]; then
  chmod 700 "$command_script"
  if /usr/bin/env HOME="$home" USER=root LOGNAME=root PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin \
    /bin/bash "$command_script" >"$output_path" 2>&1
  then
    rc=0
  else
    rc=$?
  fi
else
  chmod 755 "$command_script"
  if runuser -u "$user" -- env HOME="$home" USER="$user" LOGNAME="$user" PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin \
    /bin/bash "$command_script" >"$output_path" 2>&1
  then
    rc=0
  else
    rc=$?
  fi
fi

printf '%s\n' "$rc" > "$rc_path"
sync "$output_path" "$rc_path" >/dev/null 2>&1 || sync >/dev/null 2>&1 || true
exit 0
"#,
    )
    .map_err(|err| {
        let _ = fs::remove_dir_all(temp_root.as_path());
        format!(
            "write local UTM wrapper script failed ({}): {err}",
            local_wrapper.display()
        )
    })?;

    let remote_base = format!("/var/tmp/rn-utm-exec.{}", unique_suffix());
    let remote_command_path = format!("{remote_base}.sh");
    let remote_wrapper_path = format!("{remote_base}.wrapper.sh");
    let remote_output_path = format!("{remote_base}.out");
    let remote_rc_path = format!("{remote_base}.rc");

    let push_timeout = timeout.min(Duration::from_secs(60));
    for (path, destination, label) in [
        (
            local_script.as_path(),
            remote_command_path.as_str(),
            "command",
        ),
        (
            local_wrapper.as_path(),
            remote_wrapper_path.as_str(),
            "wrapper",
        ),
    ] {
        let status = utm_push_raw(utm_name, path, destination, push_timeout).map_err(|err| {
            let _ = fs::remove_dir_all(temp_root.as_path());
            format!("UTM push {label} script failed: {err}")
        })?;
        if !status.success() {
            let _ = fs::remove_dir_all(temp_root.as_path());
            return Err(format!(
                "UTM push {label} script failed with status {}",
                status_code(status)
            ));
        }
    }

    let host_status = {
        let utmctl_path = utmctl_binary_path()?;
        let mut command = Command::new(utmctl_path);
        command
            .arg("exec")
            .arg(utm_name)
            .arg("--cmd")
            .arg("/bin/bash")
            .arg(remote_wrapper_path.as_str())
            .arg(ssh_user)
            .arg(home)
            .arg(remote_command_path.as_str())
            .arg(remote_output_path.as_str())
            .arg(remote_rc_path.as_str());
        run_status_with_timeout(&mut command, timeout + Duration::from_secs(30))?
    };
    if !host_status.success() {
        utm_cleanup_exec_files(
            utm_name,
            remote_command_path.as_str(),
            remote_wrapper_path.as_str(),
            remote_output_path.as_str(),
            remote_rc_path.as_str(),
        );
        let _ = fs::remove_dir_all(temp_root.as_path());
        return Err(format!(
            "UTM exec wrapper failed with status {}",
            status_code(host_status)
        ));
    }

    let max_rc_attempts = timeout.as_secs().max(10);
    let mut rc = None;
    for attempt in 1..=max_rc_attempts {
        let rc_status = utm_pull_raw(
            utm_name,
            remote_rc_path.as_str(),
            local_rc.as_path(),
            push_timeout,
        )?;
        if rc_status.success()
            && let Ok(rc_text) = fs::read_to_string(local_rc.as_path())
            && let Ok(parsed_rc) = rc_text.trim().parse::<i32>()
        {
            rc = Some(parsed_rc);
            break;
        }
        if attempt < max_rc_attempts {
            thread::sleep(Duration::from_secs(1));
        }
    }
    let rc = if let Some(rc) = rc {
        rc
    } else {
        utm_cleanup_exec_files(
            utm_name,
            remote_command_path.as_str(),
            remote_wrapper_path.as_str(),
            remote_output_path.as_str(),
            remote_rc_path.as_str(),
        );
        let _ = fs::remove_dir_all(temp_root.as_path());
        return Err(format!(
            "parse local UTM exit-code failed ({}): cannot parse integer from empty string",
            local_rc.display()
        ));
    };
    let output_status = utm_pull_raw(
        utm_name,
        remote_output_path.as_str(),
        local_output.as_path(),
        push_timeout,
    )?;
    if !output_status.success() {
        utm_cleanup_exec_files(
            utm_name,
            remote_command_path.as_str(),
            remote_wrapper_path.as_str(),
            remote_output_path.as_str(),
            remote_rc_path.as_str(),
        );
        let _ = fs::remove_dir_all(temp_root.as_path());
        return Err(format!(
            "UTM exec output pull failed with status {}",
            status_code(output_status)
        ));
    }

    let output_bytes = fs::read(local_output.as_path()).map_err(|err| {
        utm_cleanup_exec_files(
            utm_name,
            remote_command_path.as_str(),
            remote_wrapper_path.as_str(),
            remote_output_path.as_str(),
            remote_rc_path.as_str(),
        );
        let _ = fs::remove_dir_all(temp_root.as_path());
        format!(
            "read local UTM output file failed ({}): {err}",
            local_output.display()
        )
    })?;
    let output = String::from_utf8(output_bytes).map_err(|err| {
        utm_cleanup_exec_files(
            utm_name,
            remote_command_path.as_str(),
            remote_wrapper_path.as_str(),
            remote_output_path.as_str(),
            remote_rc_path.as_str(),
        );
        let _ = fs::remove_dir_all(temp_root.as_path());
        format!("UTM remote output was not valid UTF-8: {err}")
    })?;

    utm_cleanup_exec_files(
        utm_name,
        remote_command_path.as_str(),
        remote_wrapper_path.as_str(),
        remote_output_path.as_str(),
        remote_rc_path.as_str(),
    );
    let _ = fs::remove_dir_all(temp_root.as_path());
    Ok((rc, output))
}

fn synthetic_exit_status(code: i32) -> ExitStatus {
    let normalized = code.clamp(0, 255);
    ExitStatus::from_raw(normalized << 8)
}

fn format_remote_capture_exit_error(rc: i32, output: &str) -> String {
    let trimmed = output.trim();
    if trimmed.is_empty() {
        format!("remote command exited with status {rc}")
    } else {
        format!("remote command exited with status {rc}: {trimmed}")
    }
}

fn format_remote_capture_parse_error(base: &str, output: &str) -> String {
    let trimmed = output.trim();
    if trimmed.is_empty() {
        base.to_string()
    } else {
        format!("{base}: {trimmed}")
    }
}

fn fallback_remote_shell_command_to_ssh(
    target: &RemoteTarget,
    ssh_user_override: Option<&str>,
    ssh_identity_file: Option<&Path>,
    known_hosts_path: Option<&Path>,
    remote_script: &str,
    timeout: Duration,
    utm_error: &str,
) -> Result<ExitStatus, String> {
    let ssh_script = remote_script_for_ssh_transport(target, remote_script)?;
    run_remote_shell_command(
        target.ssh_target.as_str(),
        ssh_user_override.or(target.ssh_user.as_deref()),
        ssh_identity_file,
        known_hosts_path,
        ssh_script.as_str(),
        timeout,
    )
    .map_err(|ssh_err| {
        format!(
            "UTM transport failed for {} ({utm_error}); SSH fallback failed: {ssh_err}",
            target.label
        )
    })
}

fn fallback_capture_remote_shell_command_to_ssh(
    target: &RemoteTarget,
    ssh_user_override: Option<&str>,
    ssh_identity_file: Option<&Path>,
    known_hosts_path: Option<&Path>,
    remote_script: &str,
    timeout: Duration,
    utm_error: &str,
) -> Result<String, String> {
    let ssh_script = remote_script_for_ssh_transport(target, remote_script)?;
    capture_remote_shell_command(
        target.ssh_target.as_str(),
        ssh_user_override.or(target.ssh_user.as_deref()),
        ssh_identity_file,
        known_hosts_path,
        ssh_script.as_str(),
        timeout,
    )
    .map_err(|ssh_err| {
        format!(
            "UTM transport failed for {} ({utm_error}); SSH fallback failed: {ssh_err}",
            target.label
        )
    })
}

fn fallback_scp_to_remote(
    context: &RemoteFallbackContext<'_>,
    src: &Path,
    dst: &str,
    utm_error: &str,
) -> Result<ExitStatus, String> {
    scp_to_remote(
        src,
        context.target.ssh_target.as_str(),
        context
            .ssh_user_override
            .or(context.target.ssh_user.as_deref()),
        context.ssh_identity_file,
        context.known_hosts_path,
        dst,
        context.timeout,
    )
    .map_err(|ssh_err| {
        format!(
            "UTM transport failed for {} ({utm_error}); SSH fallback failed: {ssh_err}",
            context.target.label
        )
    })
}

fn run_remote_shell_command_for_target(
    target: &RemoteTarget,
    ssh_user_override: Option<&str>,
    ssh_identity_file: Option<&Path>,
    known_hosts_path: Option<&Path>,
    remote_script: &str,
    timeout: Duration,
) -> Result<ExitStatus, String> {
    if let Some((utm_name, _)) = remote_target_local_utm(target) {
        return match target.platform_profile.platform {
            VmGuestPlatform::Linux => {
                let ssh_user = remote_target_effective_user(target, ssh_user_override)?;
                let home = remote_target_home(ssh_user.as_str());
                let (rc, _) = match execute_utm_remote_script_as_user(
                    utm_name,
                    ssh_user.as_str(),
                    home.as_str(),
                    remote_script,
                    timeout,
                ) {
                    Ok(result) => result,
                    Err(err) => {
                        return fallback_remote_shell_command_to_ssh(
                            target,
                            ssh_user_override,
                            ssh_identity_file,
                            known_hosts_path,
                            remote_script,
                            timeout,
                            err.as_str(),
                        );
                    }
                };
                Ok(synthetic_exit_status(rc))
            }
            VmGuestPlatform::Windows => {
                match utm_exec_windows_raw(utm_name, remote_script, timeout) {
                    Ok(status) => Ok(status),
                    Err(err) => fallback_remote_shell_command_to_ssh(
                        target,
                        ssh_user_override,
                        ssh_identity_file,
                        known_hosts_path,
                        remote_script,
                        timeout,
                        err.as_str(),
                    ),
                }
            }
            VmGuestPlatform::Macos => fallback_remote_shell_command_to_ssh(
                target,
                ssh_user_override,
                ssh_identity_file,
                known_hosts_path,
                remote_script,
                timeout,
                "local UTM guest exec is not yet implemented for macOS targets",
            ),
            VmGuestPlatform::Ios | VmGuestPlatform::Android => Err(format!(
                "local UTM guest exec is not supported for platform {} ({})",
                target.platform_profile.platform.as_str(),
                target.label
            )),
        };
    }
    let ssh_script = remote_script_for_ssh_transport(target, remote_script)?;
    run_remote_shell_command(
        target.ssh_target.as_str(),
        ssh_user_override.or(target.ssh_user.as_deref()),
        ssh_identity_file,
        known_hosts_path,
        ssh_script.as_str(),
        timeout,
    )
}

fn capture_remote_shell_command_for_target(
    target: &RemoteTarget,
    ssh_user_override: Option<&str>,
    ssh_identity_file: Option<&Path>,
    known_hosts_path: Option<&Path>,
    remote_script: &str,
    timeout: Duration,
) -> Result<String, String> {
    if let Some((utm_name, _)) = remote_target_local_utm(target) {
        return match target.platform_profile.platform {
            VmGuestPlatform::Linux => {
                let ssh_user = remote_target_effective_user(target, ssh_user_override)?;
                let home = remote_target_home(ssh_user.as_str());
                let (rc, output) = match execute_utm_remote_script_as_user(
                    utm_name,
                    ssh_user.as_str(),
                    home.as_str(),
                    remote_script,
                    timeout,
                ) {
                    Ok(result) => result,
                    Err(err) => {
                        return fallback_capture_remote_shell_command_to_ssh(
                            target,
                            ssh_user_override,
                            ssh_identity_file,
                            known_hosts_path,
                            remote_script,
                            timeout,
                            err.as_str(),
                        );
                    }
                };
                if rc != 0 {
                    return Err(format!("remote command exited with status {rc}"));
                }
                Ok(output)
            }
            VmGuestPlatform::Windows => {
                match execute_utm_remote_powershell_capture(utm_name, remote_script, timeout) {
                    Ok((rc, output)) => {
                        if rc != 0 {
                            Err(format_remote_capture_exit_error(rc, output.as_str()))
                        } else {
                            Ok(output)
                        }
                    }
                    Err(err) => fallback_capture_remote_shell_command_to_ssh(
                        target,
                        ssh_user_override,
                        ssh_identity_file,
                        known_hosts_path,
                        remote_script,
                        timeout,
                        err.as_str(),
                    ),
                }
            }
            VmGuestPlatform::Macos => fallback_capture_remote_shell_command_to_ssh(
                target,
                ssh_user_override,
                ssh_identity_file,
                known_hosts_path,
                remote_script,
                timeout,
                "local UTM guest exec is not yet implemented for macOS targets",
            ),
            VmGuestPlatform::Ios | VmGuestPlatform::Android => Err(format!(
                "local UTM guest exec is not supported for platform {} ({})",
                target.platform_profile.platform.as_str(),
                target.label
            )),
        };
    }
    let ssh_script = remote_script_for_ssh_transport(target, remote_script)?;
    capture_remote_shell_command(
        target.ssh_target.as_str(),
        ssh_user_override.or(target.ssh_user.as_deref()),
        ssh_identity_file,
        known_hosts_path,
        ssh_script.as_str(),
        timeout,
    )
}

fn scp_to_remote_for_target(
    target: &RemoteTarget,
    ssh_user_override: Option<&str>,
    ssh_identity_file: Option<&Path>,
    known_hosts_path: Option<&Path>,
    src: &Path,
    dst: &str,
    timeout: Duration,
) -> Result<ExitStatus, String> {
    let dst = remote_copy_destination_for_target(target, dst);
    if let Some((utm_name, _)) = remote_target_local_utm(target) {
        return match target.platform_profile.platform {
            VmGuestPlatform::Linux => {
                let ssh_user = remote_target_effective_user(target, ssh_user_override)?;
                let fallback_context = RemoteFallbackContext {
                    target,
                    ssh_user_override,
                    ssh_identity_file,
                    known_hosts_path,
                    timeout,
                };
                let status = match utm_push_raw(utm_name, src, dst.as_str(), timeout) {
                    Ok(status) if status.success() => status,
                    Ok(status) => {
                        return fallback_scp_to_remote(
                            &fallback_context,
                            src,
                            dst.as_str(),
                            format!("UTM push failed with status {}", status_code(status)).as_str(),
                        );
                    }
                    Err(err) => {
                        return fallback_scp_to_remote(
                            &fallback_context,
                            src,
                            dst.as_str(),
                            err.as_str(),
                        );
                    }
                };
                if ssh_user != "root" {
                    let chown_status = utm_exec_root_raw(
                        utm_name,
                        format!(
                            "chown {}:{} {}",
                            shell_quote(ssh_user.as_str()),
                            shell_quote(ssh_user.as_str()),
                            shell_quote(dst.as_str()),
                        )
                        .as_str(),
                        Duration::from_secs(20),
                    )?;
                    if !chown_status.success() {
                        return Ok(chown_status);
                    }
                }
                Ok(status)
            }
            VmGuestPlatform::Windows => {
                let fallback_context = RemoteFallbackContext {
                    target,
                    ssh_user_override,
                    ssh_identity_file,
                    known_hosts_path,
                    timeout,
                };
                match utm_push_raw(utm_name, src, dst.as_str(), timeout) {
                    Ok(status) if status.success() => Ok(status),
                    Ok(status) => fallback_scp_to_remote(
                        &fallback_context,
                        src,
                        dst.as_str(),
                        format!("UTM push failed with status {}", status_code(status)).as_str(),
                    ),
                    Err(err) => {
                        fallback_scp_to_remote(&fallback_context, src, dst.as_str(), err.as_str())
                    }
                }
            }
            VmGuestPlatform::Macos => {
                let fallback_context = RemoteFallbackContext {
                    target,
                    ssh_user_override,
                    ssh_identity_file,
                    known_hosts_path,
                    timeout,
                };
                fallback_scp_to_remote(
                    &fallback_context,
                    src,
                    dst.as_str(),
                    "local UTM file push is not yet implemented for macOS targets",
                )
            }
            VmGuestPlatform::Ios | VmGuestPlatform::Android => Err(format!(
                "local UTM file copy is not supported for platform {} ({})",
                target.platform_profile.platform.as_str(),
                target.label
            )),
        };
    }
    let ssh_user = ssh_user_override.or(target.ssh_user.as_deref());
    scp_to_remote(
        src,
        target.ssh_target.as_str(),
        ssh_user,
        ssh_identity_file,
        known_hosts_path,
        dst.as_str(),
        timeout,
    )
}

fn run_remote_shell_command(
    target: &str,
    ssh_user: Option<&str>,
    ssh_identity_file: Option<&Path>,
    known_hosts_path: Option<&Path>,
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
    append_ssh_transport_options(&mut command, ssh_identity_file, known_hosts_path)?;
    if let Some(ssh_user) = ssh_user {
        command.arg("-l").arg(ssh_user);
    }
    command.arg("--").arg(target).arg(remote_script);
    run_status_with_timeout(&mut command, timeout)
}

fn capture_remote_shell_command(
    target: &str,
    ssh_user: Option<&str>,
    ssh_identity_file: Option<&Path>,
    known_hosts_path: Option<&Path>,
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
    append_ssh_transport_options(&mut command, ssh_identity_file, known_hosts_path)?;
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
    ssh_identity_file: Option<&Path>,
    known_hosts_path: Option<&Path>,
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
    append_ssh_transport_options(&mut command, ssh_identity_file, known_hosts_path)?;
    if let Some(ssh_user) = ssh_user {
        command.arg("-o").arg(format!("User={ssh_user}"));
    }
    command
        .arg("--")
        .arg(src.as_os_str())
        .arg(format!("{target}:{dst}"));
    run_status_with_timeout(&mut command, timeout)
}

fn scp_from_remote(
    target: &RemoteTarget,
    ssh_user: Option<&str>,
    ssh_identity_file: Option<&Path>,
    known_hosts_path: Option<&Path>,
    src: &str,
    dst: &Path,
    timeout: Duration,
) -> Result<ExitStatus, String> {
    validate_target_user_combination(target.ssh_target.as_str(), ssh_user)?;
    ensure_no_control_chars("remote source path", src)?;
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
    append_ssh_transport_options(&mut command, ssh_identity_file, known_hosts_path)?;
    if let Some(ssh_user) = ssh_user {
        command.arg("-o").arg(format!("User={ssh_user}"));
    }
    if let Some(parent) = dst.parent().filter(|path| !path.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "create remote scp destination dir failed ({}): {err}",
                parent.display()
            )
        })?;
    }
    command
        .arg("--")
        .arg(format!(
            "{}:{}",
            target.ssh_target,
            remote_copy_source_for_target(target, src)
        ))
        .arg(dst.as_os_str());
    run_status_with_timeout(&mut command, timeout)
}

fn run_status_with_timeout(command: &mut Command, timeout: Duration) -> Result<ExitStatus, String> {
    command.stdin(Stdio::null());
    command.stdout(Stdio::null());
    command.stderr(Stdio::null());
    run_status_with_timeout_preserve(command, timeout)
}

fn run_status_with_timeout_preserve(
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

fn run_output_with_timeout(
    command: &mut Command,
    timeout: Duration,
) -> Result<std::process::Output, String> {
    command.stdin(Stdio::null());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    run_output_with_timeout_preserve(command, timeout)
}

fn run_output_with_timeout_preserve(
    command: &mut Command,
    timeout: Duration,
) -> Result<std::process::Output, String> {
    let mut child = command
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
    transition_local_utm_vm_with_process_probe(
        utmctl_path,
        Path::new("ps"),
        utm_name,
        bundle_path,
        action,
        expected_process_present,
        timeout,
    )
}

fn transition_local_utm_vm_with_process_probe(
    utmctl_path: &Path,
    ps_path: &Path,
    utm_name: &str,
    bundle_path: &Path,
    action: &str,
    expected_process_present: bool,
    timeout: Duration,
) -> Result<(), String> {
    let observed = local_utm_process_present_with_probes(
        utmctl_path,
        ps_path,
        utm_name,
        bundle_path,
        timeout,
    )?;
    if observed == expected_process_present {
        return Ok(());
    }

    let mut command = Command::new(utmctl_path);
    command.arg(action).arg(utm_name);
    let status = match run_status_with_timeout(&mut command, timeout) {
        Ok(status) => status,
        Err(err) => {
            match wait_for_local_utm_process_state_with_probes(
                utmctl_path,
                ps_path,
                utm_name,
                bundle_path,
                expected_process_present,
                transition_reconciliation_timeout(timeout),
            ) {
                Ok(()) => return Ok(()),
                Err(probe_err) => {
                    return Err(format!(
                        "{err}; follow-up process-state probe failed: {probe_err}"
                    ));
                }
            }
        }
    };
    if !status.success() {
        match wait_for_local_utm_process_state_with_probes(
            utmctl_path,
            ps_path,
            utm_name,
            bundle_path,
            expected_process_present,
            transition_reconciliation_timeout(timeout),
        ) {
            Ok(()) => return Ok(()),
            Err(probe_err) => {
                return Err(format!(
                    "{action} exited with status {}; follow-up process-state probe failed: {probe_err}",
                    status_code(status)
                ));
            }
        }
    }
    wait_for_local_utm_process_state_with_probes(
        utmctl_path,
        ps_path,
        utm_name,
        bundle_path,
        expected_process_present,
        timeout,
    )
}

fn wait_for_local_utm_process_state_with_probes(
    utmctl_path: &Path,
    ps_path: &Path,
    utm_name: &str,
    bundle_path: &Path,
    expected_present: bool,
    timeout: Duration,
) -> Result<(), String> {
    let started_at = Instant::now();
    loop {
        let observed = local_utm_process_present_with_probes(
            utmctl_path,
            ps_path,
            utm_name,
            bundle_path,
            timeout,
        )?;
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

fn local_utm_process_present_with_probes(
    utmctl_path: &Path,
    ps_path: &Path,
    utm_name: &str,
    bundle_path: &Path,
    timeout: Duration,
) -> Result<bool, String> {
    match local_utm_process_present_with_utmctl_list(utmctl_path, utm_name, timeout) {
        Ok(Some(present)) => return Ok(present),
        Ok(None) => {}
        Err(utmctl_err) => {
            return local_utm_process_present_with_ps(ps_path, bundle_path, timeout).map_err(
                |ps_err| {
                    format!(
                        "utmctl process probe failed: {utmctl_err}; ps process probe failed: {ps_err}"
                    )
                },
            );
        }
    }
    local_utm_process_present_with_ps(ps_path, bundle_path, timeout)
}

fn local_utm_process_present_with_utmctl_list(
    utmctl_path: &Path,
    utm_name: &str,
    timeout: Duration,
) -> Result<Option<bool>, String> {
    if !utmctl_path.is_file() {
        return Ok(None);
    }
    let mut command = Command::new(utmctl_path);
    command.arg("list");
    let output = run_output_with_timeout(&mut command, timeout)?;
    if !output.status.success() {
        return Ok(None);
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|err| format!("utmctl list returned non-UTF-8 output: {err}"))?;
    Ok(parse_local_utm_list_started_status(
        stdout.as_str(),
        utm_name,
    ))
}

fn local_utm_process_present_with_ps(
    ps_path: &Path,
    bundle_path: &Path,
    timeout: Duration,
) -> Result<bool, String> {
    let mut command = Command::new(ps_path);
    command.args(["axww", "-o", "command"]);
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

fn parse_local_utm_list_started_status(list_output: &str, utm_name: &str) -> Option<bool> {
    list_output.lines().find_map(|line| {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("UUID") {
            return None;
        }

        let mut parts = trimmed.split_whitespace();
        let _uuid = parts.next()?;
        let status = parts.next()?;
        let name_start = trimmed.find(status)? + status.len();
        let name = trimmed[name_start..].trim();
        if name != utm_name {
            return None;
        }

        Some(status == "started")
    })
}

fn transition_reconciliation_timeout(_timeout: Duration) -> Duration {
    Duration::from_secs(15)
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

fn powershell_quote(value: &str) -> Result<String, String> {
    ensure_no_control_chars("PowerShell literal", value)?;
    Ok(format!("'{}'", value.replace('\'', "''")))
}

fn encode_powershell_command(script: &str) -> Result<String, String> {
    if script.chars().any(|ch| ch == '\0') {
        return Err("PowerShell script contains unsupported NUL byte".to_string());
    }
    let mut bytes = Vec::with_capacity(script.len() * 2);
    for unit in script.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    Ok(BASE64_STANDARD.encode(bytes))
}

fn build_ssh_powershell_encoded_invocation(script: &str) -> Result<String, String> {
    let encoded = encode_powershell_command(script)?;
    Ok(format!(
        "powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded}"
    ))
}

fn build_remote_argv_powershell_script(
    workdir: &str,
    program: &str,
    argv: &[String],
) -> Result<String, String> {
    ensure_no_control_chars("workdir", workdir)?;
    ensure_no_control_chars("program", program)?;
    let mut script = String::new();
    script.push_str("Set-StrictMode -Version Latest; ");
    script.push_str("$ErrorActionPreference = 'Stop'; ");
    script.push_str(format!("Set-Location -LiteralPath {}; ", powershell_quote(workdir)?).as_str());
    script.push_str(format!("& {}", powershell_quote(program)?).as_str());
    for arg in argv {
        ensure_no_control_chars("command arg", arg.as_str())?;
        script.push(' ');
        script.push_str(powershell_quote(arg.as_str())?.as_str());
    }
    script
        .push_str("; if ($LASTEXITCODE -ne $null -and $LASTEXITCODE -ne 0) { exit $LASTEXITCODE }");
    Ok(script)
}

fn build_remote_argv_script_for_target(
    target: &RemoteTarget,
    workdir: &str,
    program: &str,
    argv: &[String],
    sudo: bool,
) -> Result<String, String> {
    match target.platform_profile.remote_shell {
        VmRemoteShell::Posix => build_remote_argv_script(workdir, program, argv, sudo),
        VmRemoteShell::Powershell => {
            if sudo {
                return Err(format!(
                    "sudo is not supported for Windows targets: {}",
                    target.label
                ));
            }
            build_remote_argv_powershell_script(workdir, program, argv)
        }
        VmRemoteShell::Unsupported => Err(format!(
            "vm-lab remote shell is not yet implemented for platform {} ({})",
            target.platform_profile.platform.as_str(),
            target.label
        )),
    }
}

fn remote_script_for_ssh_transport(
    target: &RemoteTarget,
    remote_script: &str,
) -> Result<String, String> {
    match target.platform_profile.remote_shell {
        VmRemoteShell::Posix => Ok(remote_script.to_string()),
        VmRemoteShell::Powershell => build_ssh_powershell_encoded_invocation(remote_script),
        VmRemoteShell::Unsupported => Err(format!(
            "SSH transport is not yet implemented for platform {} ({})",
            target.platform_profile.platform.as_str(),
            target.label
        )),
    }
}

fn remote_copy_destination_for_target(target: &RemoteTarget, dst: &str) -> String {
    match target.platform_profile.platform {
        VmGuestPlatform::Linux
        | VmGuestPlatform::Macos
        | VmGuestPlatform::Ios
        | VmGuestPlatform::Android => dst.to_string(),
        VmGuestPlatform::Windows => dst.replace('\\', "/"),
    }
}

fn remote_copy_source_for_target(target: &RemoteTarget, src: &str) -> String {
    match target.platform_profile.platform {
        VmGuestPlatform::Linux
        | VmGuestPlatform::Macos
        | VmGuestPlatform::Ios
        | VmGuestPlatform::Android => src.to_string(),
        VmGuestPlatform::Windows => src.replace('\\', "/"),
    }
}

fn windows_guest_path_join(root: &str, file_name: &str) -> Result<String, String> {
    ensure_no_control_chars("Windows guest root", root)?;
    ensure_no_control_chars("Windows guest file name", file_name)?;
    let trimmed = root.trim_end_matches(['\\', '/']);
    Ok(format!(r"{trimmed}\{file_name}"))
}

fn windows_helper_script_remote_path(
    target: &RemoteTarget,
    file_name: &str,
) -> Result<String, String> {
    let remote_root = target
        .remote_temp_dir
        .clone()
        .unwrap_or_else(|| default_remote_temp_dir_for_profile(target.platform_profile));
    let remote_root = remote_root.as_str();
    windows_guest_path_join(remote_root, file_name)
}

fn utm_exec_windows_raw(
    utm_name: &str,
    powershell_script: &str,
    timeout: Duration,
) -> Result<ExitStatus, String> {
    ensure_no_control_chars("UTM exec command", powershell_script)?;
    let encoded = encode_powershell_command(powershell_script)?;
    let utmctl_path = utmctl_binary_path()?;
    let mut command = Command::new(utmctl_path);
    command
        .arg("exec")
        .arg(utm_name)
        .arg("--cmd")
        .arg(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
        .arg("-NoLogo")
        .arg("-NoProfile")
        .arg("-NonInteractive")
        .arg("-ExecutionPolicy")
        .arg("Bypass")
        .arg("-EncodedCommand")
        .arg(encoded);
    run_status_with_timeout(&mut command, timeout)
}

fn execute_utm_remote_powershell_capture(
    utm_name: &str,
    powershell_script: &str,
    timeout: Duration,
) -> Result<(i32, String), String> {
    if powershell_script.chars().any(|ch| ch == '\0') {
        return Err("UTM remote PowerShell script contains unsupported NUL byte".to_string());
    }

    let suffix = unique_suffix();
    let remote_root = format!(r"C:\ProgramData\Rustynet\vm-lab\{suffix}");
    let remote_output = format!(r"{remote_root}\stdout.txt");
    let remote_rc = format!(r"{remote_root}\rc.txt");
    let wrapped_script = build_utm_windows_capture_wrapper_script(
        remote_root.as_str(),
        remote_output.as_str(),
        remote_rc.as_str(),
        powershell_script,
    )?;
    let status = utm_exec_windows_raw(utm_name, wrapped_script.as_str(), timeout)?;
    if !status.success() {
        return Err(format!(
            "UTM Windows PowerShell wrapper exited with status {}",
            status_code(status)
        ));
    }

    let temp_root = std::env::temp_dir().join(format!("rustynet-vm-lab-win-{}", unique_suffix()));
    fs::create_dir_all(temp_root.as_path()).map_err(|err| {
        format!(
            "create temporary output dir failed ({}): {err}",
            temp_root.display()
        )
    })?;
    let local_output = temp_root.join("stdout.txt");
    let local_rc = temp_root.join("rc.txt");

    let pull_output_status = utm_pull_raw(
        utm_name,
        remote_output.as_str(),
        local_output.as_path(),
        timeout,
    )?;
    if !pull_output_status.success() {
        let _ = fs::remove_dir_all(temp_root.as_path());
        return Err(format!(
            "UTM Windows stdout pull failed with status {}",
            status_code(pull_output_status)
        ));
    }

    let output = fs::read_to_string(local_output.as_path()).map_err(|err| {
        format!(
            "read UTM Windows stdout failed ({}): {err}",
            local_output.display()
        )
    })?;
    let max_rc_attempts = timeout.as_secs().max(10);
    let mut rc = None;
    let mut last_rc_text = None;
    for attempt in 1..=max_rc_attempts {
        let pull_rc_status =
            utm_pull_raw(utm_name, remote_rc.as_str(), local_rc.as_path(), timeout)?;
        if pull_rc_status.success()
            && let Ok(rc_text) = fs::read_to_string(local_rc.as_path())
        {
            let trimmed_rc = rc_text.trim().to_string();
            if let Ok(parsed_rc) = trimmed_rc.parse::<i32>() {
                rc = Some(parsed_rc);
                break;
            }
            last_rc_text = Some(trimmed_rc);
        }
        if attempt < max_rc_attempts {
            thread::sleep(Duration::from_secs(1));
        }
    }
    let rc = rc.ok_or_else(|| {
        let base = match last_rc_text.as_deref() {
            Some(value) if !value.is_empty() => {
                format!("parse UTM Windows rc failed: invalid integer '{value}'")
            }
            _ => "parse UTM Windows rc failed: cannot parse integer from empty string".to_string(),
        };
        format_remote_capture_parse_error(base.as_str(), output.as_str())
    })?;

    let cleanup = format!(
        "Remove-Item -LiteralPath {} -Recurse -Force -ErrorAction SilentlyContinue",
        powershell_quote(remote_root.as_str())?
    );
    let _ = utm_exec_windows_raw(utm_name, cleanup.as_str(), Duration::from_secs(20));
    let _ = fs::remove_dir_all(temp_root.as_path());

    Ok((rc, output))
}

fn build_utm_windows_capture_wrapper_script(
    remote_root: &str,
    remote_output: &str,
    remote_rc: &str,
    powershell_script: &str,
) -> Result<String, String> {
    let encoded_body = encode_powershell_command(powershell_script)?;
    Ok(format!(
        "Set-StrictMode -Version Latest; \
         $ErrorActionPreference = 'Stop'; \
         New-Item -ItemType Directory -Force -Path {root} | Out-Null; \
         $rc = 0; \
         try {{ \
           $body = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String({encoded_body})); \
           $scriptBlock = [ScriptBlock]::Create($body); \
           & $scriptBlock *>{output}; \
           if ($LASTEXITCODE -ne $null) {{ $rc = [int]$LASTEXITCODE }} \
         }} catch {{ \
           ($_ | Out-String) | Set-Content -Encoding utf8 -LiteralPath {output}; \
           $rc = 1 \
         }}; \
         Set-Content -Encoding ascii -LiteralPath {rc} -Value $rc",
        root = powershell_quote(remote_root)?,
        encoded_body = powershell_quote(encoded_body.as_str())?,
        output = powershell_quote(remote_output)?,
        rc = powershell_quote(remote_rc)?,
    ))
}

fn stage_windows_helper_script_from_path(
    context: &RemoteFallbackContext<'_>,
    local_path: &Path,
    remote_file_name: &str,
) -> Result<String, String> {
    ensure_local_regular_file_path(local_path, "Windows helper script")?;
    let remote_path = windows_helper_script_remote_path(context.target, remote_file_name)?;
    let status = scp_to_remote_for_target(
        context.target,
        context.ssh_user_override,
        context.ssh_identity_file,
        context.known_hosts_path,
        local_path,
        remote_path.as_str(),
        context.timeout,
    )?;
    if !status.success() {
        return Err(format!(
            "stage Windows helper script failed with status {} ({})",
            status_code(status),
            local_path.display()
        ));
    }
    Ok(remote_path)
}

fn stage_windows_helper_script(
    context: &RemoteFallbackContext<'_>,
    helper_file_name: &str,
    remote_file_name: &str,
) -> Result<String, String> {
    let local_path = windows_helper_script_local_path(helper_file_name);
    stage_windows_helper_script_from_path(context, local_path.as_path(), remote_file_name)
}

fn stage_windows_helper_support_files(
    context: &RemoteFallbackContext<'_>,
    helper_file_name: &str,
) -> Result<(), String> {
    if helper_file_name != WINDOWS_BOOTSTRAP_HELPER_FILE {
        return Ok(());
    }
    for support_file_name in [
        WINDOWS_BOOTSTRAP_WINGET_CONFIG_FILE,
        WINDOWS_BOOTSTRAP_VSCONFIG_FILE,
        WINDOWS_SERVICE_INSTALL_HELPER_FILE,
        WINDOWS_VERIFY_HELPER_FILE,
        WINDOWS_COLLECT_DIAGNOSTICS_HELPER_FILE,
    ] {
        let local_path = windows_helper_script_local_path(support_file_name);
        stage_windows_helper_script_from_path(context, local_path.as_path(), support_file_name)?;
    }
    Ok(())
}

fn build_windows_helper_invocation_script(
    remote_path: &str,
    args: &[String],
) -> Result<String, String> {
    let mut script = format!(
        "Set-StrictMode -Version Latest; $ErrorActionPreference = 'Stop'; & {}",
        powershell_quote(remote_path)?
    );
    for arg in args {
        ensure_no_control_chars("Windows helper arg", arg.as_str())?;
        script.push(' ');
        script.push_str(powershell_quote(arg.as_str())?.as_str());
    }
    script.push_str("; if (-not $?) { throw 'Windows helper invocation failed' }; if ($LASTEXITCODE -ne $null -and [int]$LASTEXITCODE -ne 0) { throw (\"Windows helper invocation failed with exit code {0}\" -f [int]$LASTEXITCODE) }");
    Ok(script)
}

struct WindowsHelperInvocation<'a> {
    helper_file_name: &'a str,
    remote_file_name: &'a str,
    args: &'a [String],
}

fn capture_windows_helper_script_output_for_target(
    context: &RemoteFallbackContext<'_>,
    helper_file_name: &str,
    remote_file_name: &str,
    args: &[String],
) -> Result<String, String> {
    let local_path = windows_helper_script_local_path(helper_file_name);
    capture_windows_helper_script_output_from_path(
        context,
        local_path.as_path(),
        remote_file_name,
        args,
    )
}

fn capture_windows_helper_script_output_from_path(
    context: &RemoteFallbackContext<'_>,
    local_path: &Path,
    remote_file_name: &str,
    args: &[String],
) -> Result<String, String> {
    let remote_path = stage_windows_helper_script_from_path(context, local_path, remote_file_name)?;
    let script = build_windows_helper_invocation_script(remote_path.as_str(), args)?;
    capture_remote_shell_command_for_target(
        context.target,
        context.ssh_user_override,
        context.ssh_identity_file,
        context.known_hosts_path,
        script.as_str(),
        context.timeout,
    )
}

fn invoke_windows_helper_script_for_target(
    context: &RemoteFallbackContext<'_>,
    invocation: WindowsHelperInvocation<'_>,
) -> Result<ExitStatus, String> {
    stage_windows_helper_support_files(context, invocation.helper_file_name)?;
    let local_path = match invocation.helper_file_name {
        WINDOWS_BOOTSTRAP_HELPER_FILE => windows_bootstrap_helper_script_local_path(),
        WINDOWS_SERVICE_INSTALL_HELPER_FILE => windows_service_install_helper_script_local_path(),
        WINDOWS_VERIFY_HELPER_FILE => windows_verify_helper_script_local_path(),
        WINDOWS_COLLECT_DIAGNOSTICS_HELPER_FILE => windows_diagnostics_helper_script_local_path(),
        _ => windows_helper_script_local_path(invocation.helper_file_name),
    };
    let remote_path = stage_windows_helper_script(
        context,
        local_path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or(invocation.helper_file_name),
        invocation.remote_file_name,
    )?;
    let script = build_windows_helper_invocation_script(remote_path.as_str(), invocation.args)?;
    if remote_target_local_utm(context.target).is_some()
        && context.target.platform_profile.platform == VmGuestPlatform::Windows
    {
        let (utm_name, _) = remote_target_local_utm(context.target)
            .ok_or_else(|| "local UTM target lookup failed for Windows helper".to_string())?;
        return match execute_utm_remote_powershell_capture(
            utm_name,
            script.as_str(),
            context.timeout,
        ) {
            Ok((0, _)) => Ok(synthetic_exit_status(0)),
            Ok((rc, output)) => Err(format_remote_capture_exit_error(rc, output.as_str())),
            Err(utm_err) => match fallback_capture_remote_shell_command_to_ssh(
                context.target,
                context.ssh_user_override,
                context.ssh_identity_file,
                context.known_hosts_path,
                script.as_str(),
                context.timeout,
                utm_err.as_str(),
            ) {
                Ok(_) => Ok(synthetic_exit_status(0)),
                Err(err) => Err(err),
            },
        };
    }
    run_remote_shell_command_for_target(
        context.target,
        context.ssh_user_override,
        context.ssh_identity_file,
        context.known_hosts_path,
        script.as_str(),
        context.timeout,
    )
}

fn render_known_hosts_line(host: &str, port: u16, public_key_line: &str) -> Result<String, String> {
    ensure_no_control_chars("known_hosts host", host)?;
    ensure_no_control_chars("known_hosts key", public_key_line)?;
    let mut parts = public_key_line.split_whitespace();
    let key_type = parts
        .next()
        .ok_or_else(|| "Windows SSH host key line is missing key type".to_string())?;
    let key_data = parts
        .next()
        .ok_or_else(|| "Windows SSH host key line is missing key payload".to_string())?;
    let host_field = if port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    };
    Ok(format!("{host_field} {key_type} {key_data}"))
}

fn append_known_hosts_entry(path: &Path, rendered_line: &str) -> Result<(), String> {
    ensure_no_control_chars("known_hosts entry", rendered_line)?;
    let mut existing = if path.exists() {
        fs::read_to_string(path)
            .map_err(|err| format!("read known_hosts file failed ({}): {err}", path.display()))?
    } else {
        String::new()
    };
    if existing
        .lines()
        .any(|line| line.trim() == rendered_line.trim())
    {
        return Ok(());
    }
    if !existing.is_empty() && !existing.ends_with('\n') {
        existing.push('\n');
    }
    existing.push_str(rendered_line.trim_end());
    existing.push('\n');
    write_text_file_atomically(path, existing.as_str())
}

fn bootstrap_windows_access_for_target(
    target: &RemoteTarget,
    ssh_user_override: Option<&str>,
    ssh_identity_file: Option<&Path>,
    known_hosts_path: Option<&Path>,
    automation_public_key: Option<&str>,
    ssh_port: u16,
    timeout: Duration,
) -> Result<String, String> {
    if target.platform_profile.platform != VmGuestPlatform::Windows {
        return Err(format!(
            "Windows access bootstrap requested for non-Windows target: {}",
            target.label
        ));
    }

    let mut args = Vec::new();
    if let Some(public_key) = automation_public_key {
        ensure_no_control_chars("automation public key", public_key)?;
        args.push("-AutomationPublicKey".to_string());
        args.push(public_key.to_string());
    }

    let context = RemoteFallbackContext {
        target,
        ssh_user_override,
        ssh_identity_file,
        known_hosts_path,
        timeout,
    };
    let host_key_line = capture_windows_helper_script_output_for_target(
        &context,
        WINDOWS_ENABLE_ACCESS_HELPER_FILE,
        WINDOWS_ENABLE_ACCESS_HELPER_FILE,
        args.as_slice(),
    )?;
    let host_key_line = host_key_line.trim();
    if host_key_line.is_empty() {
        return Err(format!(
            "Windows access bootstrap helper did not emit a host key for {}",
            target.label
        ));
    }
    if host_key_line == "host-key-unavailable" {
        return Err(format!(
            "Windows access bootstrap helper reported host-key-unavailable for {}",
            target.label
        ));
    }

    if let Some(path) = known_hosts_path {
        let host = ssh_target_host(target.ssh_target.as_str());
        let rendered = render_known_hosts_line(host.as_str(), ssh_port, host_key_line)?;
        append_known_hosts_entry(path, rendered.as_str())?;
    }

    Ok(host_key_line.to_string())
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
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let counter = UNIQUE_COUNTER.fetch_add(1, Ordering::Relaxed) as u128;
    (now << 16) ^ counter
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

fn ssh_target_user(value: &str) -> Option<&str> {
    value.rsplit_once('@').map(|(user, _)| user)
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
            let mut candidates = Vec::new();
            let live_host = ssh_target_host(resolved_inventory_ssh_target(&entry).as_str());
            if !live_host.is_empty() {
                candidates.push(live_host);
            }
            let inventory_host = ssh_target_host(entry.ssh_target.as_str());
            if !inventory_host.is_empty()
                && !candidates
                    .iter()
                    .any(|candidate| candidate == &inventory_host)
            {
                candidates.push(inventory_host);
            }
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
        let resolved_target = resolved_inventory_ssh_target(entry);
        let normalized_target = normalized_ssh_target(
            resolved_target.as_str(),
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
            "last_known_ip": literal_ip_host_from_ssh_target(normalized_target.as_str())
                .or_else(|| entry.last_known_ip.clone()),
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
    ssh_identity_file: Option<&Path>,
    known_hosts_path: Option<&Path>,
) -> Result<String, String> {
    let mut parts = Vec::new();
    for node in nodes {
        let inventory_entry = inventory
            .iter()
            .find(|entry| entry.alias == node.alias)
            .cloned()
            .ok_or_else(|| format!("topology alias missing from inventory: {}", node.alias))?;
        let target = remote_target_from_inventory_entry(&inventory_entry, ssh_user_override);
        let pubkey_hex = collect_public_key_hex_for_target(
            &target,
            ssh_identity_file,
            known_hosts_path,
            timeout,
        )?;
        let underlay_ip = literal_ip_host_from_ssh_target(node.normalized_target.as_str())
            .or_else(|| node.last_known_ip.clone())
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
    ssh_identity_file: Option<&Path>,
    known_hosts_path: Option<&Path>,
    timeout: Duration,
) -> Result<String, String> {
    let output = capture_remote_shell_command_for_target(
        target,
        None,
        ssh_identity_file,
        known_hosts_path,
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
    target: &RemoteTarget,
    ssh_user_override: Option<&str>,
    ssh_identity_file: Option<&Path>,
    known_hosts_path: Option<&Path>,
    remote_path: &str,
    local_path: &Path,
    timeout: Duration,
) -> Result<(), String> {
    let output = capture_remote_shell_command_for_target(
        target,
        ssh_user_override,
        ssh_identity_file,
        known_hosts_path,
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
    paths: &StateArtifactInstallPaths<'_>,
    ssh_identity_file: Option<&Path>,
    known_hosts_path: Option<&Path>,
    timeout: Duration,
) -> Result<(), String> {
    ensure_success_status(
        scp_to_remote_for_target(
            target,
            None,
            ssh_identity_file,
            known_hosts_path,
            paths.assignment_pub,
            "/tmp/rn-assignment.pub",
            timeout,
        )?,
        "copy assignment verifier to remote",
    )?;
    ensure_success_status(
        scp_to_remote_for_target(
            target,
            None,
            ssh_identity_file,
            known_hosts_path,
            paths.assignment_bundle,
            "/tmp/rn-assignment.bundle",
            timeout,
        )?,
        "copy assignment bundle to remote",
    )?;
    ensure_success_status(
        scp_to_remote_for_target(
            target,
            None,
            ssh_identity_file,
            known_hosts_path,
            paths.traversal_pub,
            "/tmp/rn-traversal.pub",
            timeout,
        )?,
        "copy traversal verifier to remote",
    )?;
    ensure_success_status(
        scp_to_remote_for_target(
            target,
            None,
            ssh_identity_file,
            known_hosts_path,
            paths.traversal_bundle,
            "/tmp/rn-traversal.bundle",
            timeout,
        )?,
        "copy traversal bundle to remote",
    )?;
    ensure_success_status(
        scp_to_remote_for_target(
            target,
            None,
            ssh_identity_file,
            known_hosts_path,
            paths.refresh_env,
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
    let status = run_remote_shell_command_for_target(
        target,
        None,
        ssh_identity_file,
        known_hosts_path,
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

fn suite_topology_nodes<'a>(
    topology: &'a VmLabTopology,
    suite: &str,
) -> Result<Vec<&'a VmLabTopologyNode>, String> {
    match suite {
        "direct-remote-exit" => Ok(vec![
            topology_role_node(topology, &["client"])?,
            topology_role_node(topology, &["exit"])?,
        ]),
        "relay-remote-exit" | "failback-roaming" => Ok(vec![
            topology_role_node(topology, &["client"])?,
            topology_role_node(topology, &["exit"])?,
            topology_role_node(topology, &["relay", "entry"])?,
        ]),
        "full-live-lab" => {
            let mut nodes = vec![
                topology_role_node(topology, &["exit"])?,
                topology_role_node(topology, &["client"])?,
                topology_role_node(topology, &["entry", "relay"])?,
                topology_role_node(topology, &["aux"])?,
            ];
            if let Some(extra) = topology_optional_role_node(topology, &["extra"])? {
                nodes.push(extra);
            }
            if let Some(fifth_client) = topology_optional_role_node(topology, &["fifth_client"])? {
                nodes.push(fifth_client);
            }
            Ok(nodes)
        }
        _ => Err(format!("unsupported vm-lab suite: {suite}")),
    }
}

fn ensure_suite_topology_linux_only(
    suite: &str,
    topology: &VmLabTopology,
    inventory: &[VmInventoryEntry],
) -> Result<(), String> {
    let nodes = suite_topology_nodes(topology, suite)?;
    let mut blocked = Vec::new();
    for node in nodes {
        let inventory_entry = inventory
            .iter()
            .find(|entry| entry.alias == node.alias)
            .ok_or_else(|| {
                format!(
                    "vm-lab topology alias {} is missing from inventory; cannot verify suite platform compatibility",
                    node.alias
                )
            })?;
        let platform_profile = inventory_entry.platform_profile();
        if platform_profile.platform != VmGuestPlatform::Linux {
            blocked.push(format!(
                "role={} alias={} target={} platform={} remote_shell={} guest_exec_mode={} service_manager={}",
                node.lab_role,
                node.alias,
                node.normalized_target,
                platform_profile.platform.as_str(),
                platform_profile.remote_shell.as_str(),
                platform_profile.guest_exec_mode.as_str(),
                platform_profile.service_manager.as_str(),
            ));
        }
    }
    if blocked.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "vm-lab suite {} is not yet supported for Windows targets in the Linux live-lab shell orchestrator; blocked targets: {}",
            suite,
            blocked.join("; ")
        ))
    }
}

fn build_suite_command(
    suite: &str,
    topology: &VmLabTopology,
    inventory: &[VmInventoryEntry],
    ssh_identity_file: &Path,
    nat_profile: Option<&str>,
    impairment_profile: Option<&str>,
    report_dir: &Path,
) -> Result<SuiteCommand, String> {
    let nat_profile = nat_profile.unwrap_or("baseline_lan");
    let impairment_profile = impairment_profile.unwrap_or("none");
    ensure_suite_topology_linux_only(suite, topology, inventory)?;
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

fn execute_legacy_posix_bootstrap_phase_for_target(
    phase: bootstrap::BootstrapPhase,
    target: &RemoteTarget,
    context: &bootstrap::BootstrapPhaseContext<'_>,
) -> Result<(), String> {
    if target.platform_profile.platform != VmGuestPlatform::Linux {
        return Err(format!(
            "legacy POSIX bootstrap executor only supports Linux targets: {}",
            target.label
        ));
    }
    match phase {
        bootstrap::BootstrapPhase::SyncSource => {
            let repo_url = context.repo_url.ok_or_else(|| {
                format!(
                    "bootstrap phase {} requires --repo-url for {}",
                    phase.as_str(),
                    target.label
                )
            })?;
            let status = run_remote_shell_command_for_target(
                target,
                context.ssh_user,
                context.ssh_identity_file,
                context.known_hosts_path,
                build_repo_sync_script(repo_url, context.workdir, context.branch, context.remote)?
                    .as_str(),
                context.timeout,
            )
            .map_err(|err| format!("{} failed for {}: {err}", phase.as_str(), target.label))?;
            if !status.success() {
                return Err(format!(
                    "{} failed for {} with status {}",
                    phase.as_str(),
                    target.label,
                    status_code(status)
                ));
            }
        }
        bootstrap::BootstrapPhase::BuildRelease => {
            let tmpdir = format!("{}/.tmp", context.workdir);
            let status = run_remote_shell_command_for_target(
                target,
                context.ssh_user,
                context.ssh_identity_file,
                context.known_hosts_path,
                format!(
                    "set -eu; cd {workdir}; mkdir -p {tmpdir}; \
toolchain_name=''; \
if command -v rustup >/dev/null 2>&1; then \
  toolchain_name=\"$(rustup toolchain list 2>/dev/null | awk 'NR==1 {{ print $1; exit }}' | sed 's/ (default)$//')\"; \
fi; \
cargo_bin='cargo'; \
toolchain_bin=''; \
if [ -n \"$toolchain_name\" ] && [ -d \"$HOME/.rustup/toolchains/$toolchain_name/bin\" ]; then \
  toolchain_bin=\"$HOME/.rustup/toolchains/$toolchain_name/bin\"; \
  cargo_bin=\"$toolchain_bin/cargo\"; \
fi; \
if [ -n \"$toolchain_bin\" ]; then \
  export PATH=\"$toolchain_bin:$PATH\"; \
  export RUSTC=\"$toolchain_bin/rustc\"; \
fi; \
TMPDIR={tmpdir} RUSTUP_SKIP_UPDATE_CHECK=yes exec \"$cargo_bin\" build --locked --release -p rustynetd -p rustynet-cli",
                    workdir = shell_quote(context.workdir),
                    tmpdir = shell_quote(tmpdir.as_str()),
                )
                .as_str(),
                context.timeout,
            )
            .map_err(|err| format!("{} failed for {}: {err}", phase.as_str(), target.label))?;
            if !status.success() {
                return Err(format!(
                    "{} failed for {} with status {}",
                    phase.as_str(),
                    target.label,
                    status_code(status)
                ));
            }
        }
        bootstrap::BootstrapPhase::InstallRelease => {
            let script = format!(
                "set -eu; cd {workdir}; \
if sudo -n true >/dev/null 2>&1; then SUDO='sudo -n'; else SUDO=''; fi; \
$SUDO install -m 0755 target/release/rustynetd /usr/local/bin/rustynetd; \
$SUDO install -m 0755 target/release/rustynet-cli /usr/local/bin/rustynet",
                workdir = shell_quote(context.workdir),
            );
            let status = run_remote_shell_command_for_target(
                target,
                context.ssh_user,
                context.ssh_identity_file,
                context.known_hosts_path,
                script.as_str(),
                context.timeout,
            )
            .map_err(|err| format!("{} failed for {}: {err}", phase.as_str(), target.label))?;
            if !status.success() {
                return Err(format!(
                    "{} failed for {} with status {}",
                    phase.as_str(),
                    target.label,
                    status_code(status)
                ));
            }
        }
        bootstrap::BootstrapPhase::RestartRuntime => {
            let status = run_remote_shell_command_for_target(
                target,
                context.ssh_user,
                context.ssh_identity_file,
                context.known_hosts_path,
                "set -eu; if sudo -n true >/dev/null 2>&1; then sudo -n systemctl restart rustynetd.service; else systemctl restart rustynetd.service; fi",
                context.timeout,
            )
            .map_err(|err| format!("{} failed for {}: {err}", phase.as_str(), target.label))?;
            if !status.success() {
                return Err(format!(
                    "{} failed for {} with status {}",
                    phase.as_str(),
                    target.label,
                    status_code(status)
                ));
            }
        }
        bootstrap::BootstrapPhase::VerifyRuntime => {
            let status_script = privileged_rustynet_cli_script("status");
            let netcheck_script = privileged_rustynet_cli_script("netcheck");
            let status = run_remote_shell_command_for_target(
                target,
                context.ssh_user,
                context.ssh_identity_file,
                context.known_hosts_path,
                format!("set -eu; {status_script} >/dev/null; {netcheck_script} >/dev/null")
                    .as_str(),
                context.timeout,
            )
            .map_err(|err| format!("{} failed for {}: {err}", phase.as_str(), target.label))?;
            if !status.success() {
                return Err(format!(
                    "{} failed for {} with status {}",
                    phase.as_str(),
                    target.label,
                    status_code(status)
                ));
            }
        }
        bootstrap::BootstrapPhase::All => {
            execute_legacy_posix_bootstrap_phase_for_target(
                bootstrap::BootstrapPhase::SyncSource,
                target,
                context,
            )?;
            execute_legacy_posix_bootstrap_phase_for_target(
                bootstrap::BootstrapPhase::BuildRelease,
                target,
                context,
            )?;
            execute_legacy_posix_bootstrap_phase_for_target(
                bootstrap::BootstrapPhase::InstallRelease,
                target,
                context,
            )?;
            execute_legacy_posix_bootstrap_phase_for_target(
                bootstrap::BootstrapPhase::RestartRuntime,
                target,
                context,
            )?;
            execute_legacy_posix_bootstrap_phase_for_target(
                bootstrap::BootstrapPhase::VerifyRuntime,
                target,
                context,
            )?;
        }
    }
    Ok(())
}

fn execute_bootstrap_phase_for_target(
    phase: &str,
    target: &RemoteTarget,
    context: &bootstrap::BootstrapPhaseContext<'_>,
) -> Result<(), String> {
    bootstrap::execute_bootstrap_phase_for_target(phase, target, context)
}

#[cfg(test)]
mod tests {
    use super::{
        LiveLabStageRecord, LiveLabStageSummary, PortStatus, ProbeState, RepoSyncDispatchKind,
        RepoSyncMode, VmGuestExecMode, VmGuestPlatform, VmInventoryEntry,
        VmLabDiscoverLocalUtmConfig, VmLabIterationValidationStep, VmLabRunLiveLabConfig,
        VmLabSetupLiveLabConfig, VmLabValidateLiveLabProfileConfig, VmLabWriteLiveLabProfileConfig,
        VmRemoteShell, VmServiceManager, build_assignment_refresh_env,
        build_local_source_extract_script, build_remote_argv_script,
        build_remote_argv_script_for_target, build_repo_sync_script,
        build_repo_sync_script_for_target, build_ssh_powershell_encoded_invocation,
        build_suite_command, build_utm_readiness, build_vendored_cargo_config,
        build_vm_lab_topology, build_windows_local_source_extract_script,
        collect_live_lab_stage_local_bundle, default_inventory_path,
        default_live_lab_iteration_profile_path, default_live_lab_iteration_report_dir,
        default_live_lab_orchestrator_path, default_platform_profile, default_utmctl_path,
        discover_local_utm_bundle_paths, encode_powershell_command,
        ensure_inventory_entries_share_network, execute_ops_vm_lab_diff_live_lab_runs,
        execute_ops_vm_lab_discover_local_utm, execute_ops_vm_lab_discover_local_utm_summary,
        execute_ops_vm_lab_validate_live_lab_profile, execute_ops_vm_lab_write_live_lab_profile,
        live_lab_stage_forensics_notes, load_inventory, load_live_lab_profile,
        local_utm_process_present_in_ps_output, local_utm_process_present_with_ps,
        parse_live_lab_stage_records, parse_local_utm_list_started_status,
        parse_vm_lab_iteration_validation_step_spec, parse_vm_lab_topology,
        persist_local_utm_ready_states_to_inventory, privileged_rustynet_cli_script,
        remote_copy_destination_for_target, remote_script_for_ssh_transport,
        render_live_lab_iteration_summary, render_live_lab_stage_forensics_review,
        repo_sync_dispatch_kind_for_target, resolve_iteration_source_selection,
        resolve_live_lab_vm_aliases, resolve_remote_targets, resolve_repo_sync_source,
        resolve_start_targets, resolved_inventory_ssh_target_with_utmctl, rewrite_ssh_target_host,
        select_inventory_entries, select_live_ssh_host_from_utm_output,
        selected_local_utm_readiness_from_report, ssh_auth_probe_command,
        summarize_live_lab_report, transition_local_utm_vm_with_process_probe,
        validate_live_lab_run_artifacts, windows_bootstrap_helper_script_local_path,
        windows_diagnostics_helper_script_local_path, windows_helper_script_remote_path,
        windows_service_install_helper_script_local_path, windows_verify_helper_script_local_path,
        workspace_root_path,
    };
    use serde_json::json;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    fn write_temp_inventory(body: &str) -> PathBuf {
        let unique = super::unique_suffix();
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

    fn resolve_platform_remote_target(platform: &str) -> (PathBuf, super::RemoteTarget) {
        let (alias, ssh_target, ssh_user, remote_temp_dir) = match platform {
            "linux" => ("linux-utm-1", "debian@192.168.64.10", "debian", "/var/tmp"),
            "windows" => (
                "windows-utm-1",
                "192.168.64.20",
                "Administrator",
                r"C:\ProgramData\Rustynet\vm-lab",
            ),
            "macos" => (
                "macos-utm-1",
                "macos@192.168.64.30",
                "macos",
                "/private/var/tmp",
            ),
            "ios" => (
                "ios-sim-1",
                "ios@192.168.64.40",
                "mobile",
                "/var/mobile/tmp",
            ),
            "android" => (
                "android-emulator-1",
                "android@192.168.64.50",
                "shell",
                "/data/local/tmp",
            ),
            other => panic!("unsupported test platform: {other}"),
        };
        let remote_temp_dir = remote_temp_dir.replace('\\', "\\\\");
        let path = write_temp_inventory(&format!(
            r#"{{
  "version": 1,
  "entries": [
    {{
      "alias": "{alias}",
      "ssh_target": "{ssh_target}",
      "ssh_user": "{ssh_user}",
      "platform": "{platform}",
      "remote_temp_dir": "{remote_temp_dir}",
      "controller": {{
        "type": "local_utm",
        "utm_name": "{alias}",
        "bundle_path": "/tmp/{alias}.utm"
      }}
    }}
  ]
}}"#,
        ));
        let raw_targets: Vec<String> = Vec::new();
        let target = resolve_remote_targets(
            path.as_path(),
            &[alias.to_string()],
            false,
            raw_targets.as_slice(),
        )
        .expect("target should resolve")
        .into_iter()
        .next()
        .expect("resolved target should exist");
        (path, target)
    }

    fn resolve_windows_remote_target() -> (PathBuf, super::RemoteTarget) {
        resolve_platform_remote_target("windows")
    }

    fn write_temp_executable(body: &str) -> PathBuf {
        let unique = super::unique_suffix();
        let dir = std::env::temp_dir().join(format!("rustynet-vm-lab-bin-{unique}.dir"));
        fs::create_dir_all(&dir).expect("temp executable dir should exist");
        let path = dir.join("mock-bin.sh");
        fs::write(&path, body).expect("temp executable should be written");
        let mut permissions = fs::metadata(&path)
            .expect("temp executable metadata should read")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&path, permissions).expect("temp executable should be chmodded");
        path
    }

    fn write_temp_report_dir() -> PathBuf {
        let unique = super::unique_suffix();
        let dir = std::env::temp_dir().join(format!("rustynet-live-lab-report-{unique}.dir"));
        fs::create_dir_all(dir.join("state")).expect("state dir should exist");
        fs::create_dir_all(dir.join("logs")).expect("logs dir should exist");
        dir
    }

    fn write_temp_live_lab_profile(body: &str) -> PathBuf {
        let unique = super::unique_suffix();
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
        let rendered = append_default_live_lab_platform_metadata(rendered.as_str());
        fs::write(&profile_path, rendered).expect("profile should write");
        profile_path
    }

    fn append_default_live_lab_platform_metadata(rendered: &str) -> String {
        let mut rendered = rendered.to_string();
        for role in ["EXIT", "CLIENT", "ENTRY", "AUX", "EXTRA", "FIFTH_CLIENT"] {
            let target_key = format!("{role}_TARGET=");
            let platform_key = format!("{role}_PLATFORM=");
            if rendered.contains(target_key.as_str()) && !rendered.contains(platform_key.as_str()) {
                rendered.push_str(&format!(
                    "\n{role}_PLATFORM=\"linux\"\n{role}_REMOTE_SHELL=\"posix\"\n{role}_GUEST_EXEC_MODE=\"linux_bash\"\n{role}_SERVICE_MANAGER=\"systemd\"\n{role}_RUSTYNET_SRC_DIR=\"/home/debian/Rustynet\"\n"
                ));
            }
        }
        rendered
    }

    fn write_temp_stage_rows(report_dir: &Path, rows: &[(&str, &str)]) {
        let mut rendered = String::new();
        for (index, (name, status)) in rows.iter().enumerate() {
            let log_path = report_dir.join("logs").join(format!("{name}.log"));
            fs::write(&log_path, format!("{name} {status}\n")).expect("stage log should write");
            rendered.push_str(&format!(
                "{name}\thard\t{status}\t{}\t{}\t{name} stage\t2026-04-12T00:00:{index:02}Z\t2026-04-12T00:00:{end:02}Z\n",
                if *status == "pass" { 0 } else { 1 },
                log_path.display(),
                end = index + 1,
            ));
        }
        fs::write(report_dir.join("state/stages.tsv"), rendered).expect("stages should write");
    }

    fn cleanup_temp_path(path: &Path) {
        if let Some(parent) = path.parent() {
            let _ = fs::remove_dir_all(parent);
        }
    }

    fn build_test_setup_manifest(
        report_dir: &Path,
        profile_path: &Path,
        script_path: &Path,
        inventory_path: Option<&Path>,
    ) -> super::LiveLabSetupManifest {
        super::build_setup_manifest(&super::LiveLabSetupManifestInput {
            report_dir: report_dir.to_path_buf(),
            profile_path: profile_path.to_path_buf(),
            script_path: script_path.to_path_buf(),
            inventory_path: inventory_path.map(Path::to_path_buf),
            source_mode: "local-head".to_string(),
            repo_ref: Some("HEAD".to_string()),
            require_same_network: Some(true),
            dry_run: false,
            max_parallel_node_workers: None,
        })
        .expect("manifest should build")
    }

    fn write_setup_only_report_state(report_dir: &Path, manifest: &super::LiveLabSetupManifest) {
        super::write_setup_manifest(report_dir, manifest).expect("manifest should write");
        let state =
            super::initial_report_state(report_dir, manifest).expect("report state should build");
        super::write_report_state(report_dir, &state).expect("report state should write");
        write_temp_stage_rows(report_dir, &[("validate_baseline_runtime", "pass")]);
        super::update_report_state_setup_complete(report_dir)
            .expect("setup-complete state should write");
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
        assert_eq!(inventory[0].ssh_password.as_deref(), None);
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
        assert_eq!(inventory[0].ssh_password.as_deref(), None);
        assert_eq!(
            inventory[0].rustynet_src_dir.as_deref(),
            Some("/home/debian/Rustynet")
        );
        cleanup_temp_inventory(path.as_path());
    }

    #[test]
    fn load_inventory_parses_ssh_password_metadata() {
        let path = write_temp_inventory(
            r#"{
                "version": 1,
                "entries": [
                    {
                        "alias": "debian-headless-1",
                        "ssh_target": "debian-headless-1",
                        "ssh_user": "debian",
                        "ssh_password": "tempo",
                        "os": "Debian/Linux"
                    }
                ]
            }"#,
        );
        let inventory = load_inventory(path.as_path()).expect("inventory should load");
        assert_eq!(inventory[0].ssh_user.as_deref(), Some("debian"));
        assert_eq!(inventory[0].ssh_password.as_deref(), Some("tempo"));
        cleanup_temp_inventory(path.as_path());
    }

    #[test]
    fn load_inventory_parses_windows_platform_metadata() {
        let path = write_temp_inventory(
            r#"{
                "version": 1,
                "entries": [
                    {
                        "alias": "windows-utm-1",
                        "ssh_target": "192.168.64.20",
                        "ssh_user": "Administrator",
                        "os": "Windows 11",
                        "platform": "windows",
                        "remote_shell": "powershell",
                        "guest_exec_mode": "windows_powershell",
                        "service_manager": "windows_service",
                        "remote_temp_dir": "C:\\ProgramData\\Rustynet\\vm-lab",
                        "rustynet_src_dir": "C:\\Rustynet"
                    }
                ]
            }"#,
        );
        let inventory = load_inventory(path.as_path()).expect("inventory should load");
        assert_eq!(inventory[0].platform, Some(VmGuestPlatform::Windows));
        assert_eq!(inventory[0].remote_shell, Some(VmRemoteShell::Powershell));
        assert_eq!(
            inventory[0].guest_exec_mode,
            Some(VmGuestExecMode::WindowsPowershell)
        );
        assert_eq!(
            inventory[0].service_manager,
            Some(VmServiceManager::WindowsService)
        );
        assert_eq!(
            inventory[0].remote_temp_dir.as_deref(),
            Some(r"C:\ProgramData\Rustynet\vm-lab")
        );
        assert_eq!(
            inventory[0].rustynet_src_dir.as_deref(),
            Some(r"C:\Rustynet")
        );
        assert_eq!(
            inventory[0].platform_profile().platform,
            VmGuestPlatform::Windows
        );
        cleanup_temp_inventory(path.as_path());
    }

    #[test]
    fn select_inventory_entries_skips_all_excluded_rows() {
        let inventory = vec![
            VmInventoryEntry {
                alias: "debian-headless-1".to_string(),
                ssh_target: "debian-headless-1".to_string(),
                ssh_user: Some("debian".to_string()),
                ssh_password: None,
                include_in_all: Some(true),
                os: None,
                last_known_ip: None,
                parent_device: None,
                last_known_network: None,
                network_group: None,
                node_id: None,
                lab_role: None,
                mesh_ip: None,
                exit_capable: None,
                relay_capable: None,
                remote_temp_dir: None,
                rustynet_src_dir: None,
                platform: None,
                remote_shell: None,
                guest_exec_mode: None,
                service_manager: None,
                controller: None,
            },
            VmInventoryEntry {
                alias: "debian-lan-11".to_string(),
                ssh_target: "debian-lan-11".to_string(),
                ssh_user: Some("debian".to_string()),
                ssh_password: Some("tempo".to_string()),
                include_in_all: Some(false),
                os: None,
                last_known_ip: None,
                parent_device: None,
                last_known_network: None,
                network_group: None,
                node_id: None,
                lab_role: None,
                mesh_ip: None,
                exit_capable: None,
                relay_capable: None,
                remote_temp_dir: None,
                rustynet_src_dir: None,
                platform: None,
                remote_shell: None,
                guest_exec_mode: None,
                service_manager: None,
                controller: None,
            },
        ];
        let selected = select_inventory_entries(inventory.as_slice(), &[], true)
            .expect("selection should succeed");
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].alias, "debian-headless-1");
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
        assert_eq!(targets[0].platform_profile.platform, VmGuestPlatform::Linux);
        assert_eq!(targets[1].ssh_target, "root@192.168.18.52");
        assert_eq!(targets[1].platform_profile.platform, VmGuestPlatform::Linux);
        cleanup_temp_inventory(path.as_path());
    }

    #[test]
    fn live_ssh_host_selector_prefers_underlay_ipv4_over_mesh_ip() {
        let selected = select_live_ssh_host_from_utm_output(
            "192.168.64.8\n100.64.0.1\n",
            Some("192.168.64.3"),
            Some("100.64.0.1"),
        )
        .expect("live SSH host should resolve");
        assert_eq!(selected, "192.168.64.8");
    }

    #[test]
    fn resolved_inventory_ssh_target_uses_live_local_utm_ip() {
        let utmctl = write_temp_executable(
            "#!/bin/sh\nif [ \"$1\" = \"ip-address\" ] && [ \"$2\" = \"debian-headless-1\" ]; then\n  printf '192.168.64.8\\n100.64.0.1\\n'\n  exit 0\nfi\nexit 1\n",
        );
        let entry = VmInventoryEntry {
            alias: "debian-headless-1".to_string(),
            ssh_target: "192.168.64.3".to_string(),
            ssh_user: Some("debian".to_string()),
            ssh_password: None,
            include_in_all: Some(true),
            os: None,
            last_known_ip: Some("192.168.64.3".to_string()),
            parent_device: None,
            last_known_network: None,
            network_group: None,
            node_id: None,
            lab_role: None,
            mesh_ip: Some("100.64.0.1".to_string()),
            exit_capable: None,
            relay_capable: None,
            remote_temp_dir: None,
            rustynet_src_dir: None,
            platform: None,
            remote_shell: None,
            guest_exec_mode: None,
            service_manager: None,
            controller: Some(super::VmController::LocalUtm {
                utm_name: "debian-headless-1".to_string(),
                bundle_path: PathBuf::from("/tmp/debian-headless-1.utm"),
            }),
        };
        let resolved = resolved_inventory_ssh_target_with_utmctl(&entry, utmctl.as_path());
        assert_eq!(resolved, "192.168.64.8");
        let _ = fs::remove_dir_all(
            utmctl
                .parent()
                .expect("temp executable parent should exist"),
        );
    }

    #[test]
    fn discover_local_utm_bundle_paths_recurses_into_nested_documents() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be valid")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("rustynet-vm-lab-utm-root-{unique}.dir"));
        fs::create_dir_all(root.join("nested").join("alpha.utm"))
            .expect("nested bundle should exist");
        fs::create_dir_all(root.join("beta.utm")).expect("top-level bundle should exist");
        fs::create_dir_all(root.join("nested").join("ignored"))
            .expect("nested directory should exist");

        let bundles = discover_local_utm_bundle_paths(root.as_path())
            .expect("bundle discovery should succeed");
        assert_eq!(bundles.len(), 2);
        assert!(
            bundles
                .iter()
                .any(|path| path.ends_with(Path::new("alpha.utm")))
        );
        assert!(
            bundles
                .iter()
                .any(|path| path.ends_with(Path::new("beta.utm")))
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn execute_ops_vm_lab_discover_local_utm_reports_live_bundle_status() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be valid")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("rustynet-vm-lab-utm-root-{unique}.dir"));
        let bundle = root.join("nested").join("alpha.utm");
        fs::create_dir_all(&bundle).expect("bundle should exist");

        let inventory = write_temp_inventory(&format!(
            r#"{{
  "version": 1,
  "entries": [
    {{
      "alias": "alpha",
      "ssh_target": "alpha-host",
      "ssh_user": "debian",
      "node_id": "alpha-1",
      "lab_role": "exit",
      "last_known_ip": "192.168.64.20",
      "mesh_ip": "100.64.0.1",
      "controller": {{
        "type": "local_utm",
        "utm_name": "alpha",
        "bundle_path": "{}"
      }}
    }}
  ]
}}"#,
            bundle.display()
        ));

        let utmctl = write_temp_executable(
            "#!/bin/sh\nif [ \"$1\" = \"ip-address\" ] && [ \"$2\" = \"alpha\" ]; then\n  printf '192.168.64.8\\n100.64.0.1\\n'\n  exit 0\nfi\nexit 1\n",
        );
        let ssh_port = 65_534;

        let report = execute_ops_vm_lab_discover_local_utm(VmLabDiscoverLocalUtmConfig {
            inventory_path: Some(inventory.clone()),
            utm_documents_root: Some(root.clone()),
            utmctl_path: Some(utmctl.clone()),
            ssh_identity_file: None,
            known_hosts_path: None,
            ssh_port,
            timeout_secs: 2,
            update_inventory_live_ips: false,
            report_dir: None,
        })
        .expect("discovery report should be produced");
        let parsed: serde_json::Value =
            serde_json::from_str(report.as_str()).expect("discovery report should parse as JSON");
        assert_eq!(parsed["mode"].as_str(), Some("vm_lab_local_utm_discovery"));
        assert_eq!(parsed["summary"]["bundle_count"].as_u64(), Some(1));
        assert_eq!(
            parsed["summary"]["inventory_matched_count"].as_u64(),
            Some(1)
        );
        assert_eq!(parsed["summary"]["live_ip_count"].as_u64(), Some(1));
        assert_eq!(parsed["summary"]["ssh_port_open_count"].as_u64(), Some(0));
        assert_eq!(parsed["summary"]["ready_count"].as_u64(), Some(0));
        assert_eq!(parsed["summary"]["status"].as_str(), Some("partial"));
        assert_eq!(parsed["entries"][0]["utm_name"].as_str(), Some("alpha"));
        assert_eq!(
            parsed["entries"][0]["inventory_match"].as_bool(),
            Some(true)
        );
        assert_eq!(
            parsed["entries"][0]["live_ip"].as_str(),
            Some("192.168.64.8")
        );
        assert_eq!(
            parsed["entries"][0]["ssh_port_status"].as_str(),
            Some("closed")
        );
        assert_eq!(parsed["entries"][0]["ssh_user"].as_str(), Some("debian"));
        assert_eq!(
            parsed["entries"][0]["ssh_target_source"].as_str(),
            Some("inventory")
        );

        let _ = fs::remove_dir_all(
            inventory
                .parent()
                .expect("temp inventory parent should exist"),
        );
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(
            utmctl
                .parent()
                .expect("temp executable parent should exist"),
        );
    }

    #[test]
    fn execute_ops_vm_lab_discover_local_utm_summary_renders_setup_view() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be valid")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("rustynet-vm-lab-utm-root-{unique}.dir"));
        let bundle = root.join("nested").join("alpha.utm");
        fs::create_dir_all(&bundle).expect("bundle should exist");

        let inventory = write_temp_inventory(&format!(
            r#"{{
  "version": 1,
  "entries": [
    {{
      "alias": "alpha",
      "ssh_target": "alpha-host",
      "ssh_user": "debian",
      "last_known_ip": "192.168.64.20",
      "mesh_ip": "100.64.0.1",
      "controller": {{
        "type": "local_utm",
        "utm_name": "alpha",
        "bundle_path": "{}"
      }}
    }}
  ]
}}"#,
            bundle.display()
        ));

        let utmctl = write_temp_executable(
            "#!/bin/sh\nif [ \"$1\" = \"ip-address\" ] && [ \"$2\" = \"alpha\" ]; then\n  printf '192.168.64.8\\n100.64.0.1\\n'\n  exit 0\nfi\nexit 1\n",
        );

        let report = execute_ops_vm_lab_discover_local_utm_summary(VmLabDiscoverLocalUtmConfig {
            inventory_path: Some(inventory.clone()),
            utm_documents_root: Some(root.clone()),
            utmctl_path: Some(utmctl.clone()),
            ssh_identity_file: None,
            known_hosts_path: None,
            ssh_port: 65_534,
            timeout_secs: 2,
            update_inventory_live_ips: false,
            report_dir: None,
        })
        .expect("summary report should be produced");

        assert!(report.contains("discovery_summary.status=partial"));
        assert!(report.contains("discovery_summary.bundle_count=1"));
        assert!(report.contains("discovery_summary.ready_count=0"));
        assert!(report.contains("node[0].alias=alpha"));
        assert!(report.contains("node[0].inventory_ssh_target=alpha-host"));
        assert!(report.contains("node[0].inventory_last_known_ip=192.168.64.20"));
        assert!(report.contains("node[0].live_ip=192.168.64.8"));
        assert!(report.contains("node[0].ssh_target=192.168.64.8"));
        assert!(report.contains("node[0].ssh_port_status=closed"));
        assert!(report.contains("node[0].ready=false"));
        assert!(!report.contains("inventory_error="));

        let _ = fs::remove_dir_all(
            inventory
                .parent()
                .expect("temp inventory parent should exist"),
        );
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(
            utmctl
                .parent()
                .expect("temp executable parent should exist"),
        );
    }

    #[test]
    fn ssh_auth_probe_command_selects_platform_specific_probe() {
        assert_eq!(
            ssh_auth_probe_command(default_platform_profile(VmGuestPlatform::Linux))
                .expect("linux probe should exist"),
            "true"
        );
        assert_eq!(
            ssh_auth_probe_command(default_platform_profile(VmGuestPlatform::Windows))
                .expect("windows probe should exist"),
            "powershell.exe -NoLogo -NoProfile -NonInteractive -Command \"$PSVersionTable.PSVersion.ToString() | Out-Null; exit 0\""
        );
    }

    #[test]
    fn platform_scaffold_distinguishes_desktop_and_mobile_profiles() {
        let macos = default_platform_profile(VmGuestPlatform::Macos);
        assert_eq!(macos.remote_shell, VmRemoteShell::Posix);
        assert_eq!(macos.guest_exec_mode, VmGuestExecMode::MacosPosix);
        assert_eq!(macos.service_manager, VmServiceManager::Launchd);

        let ios = default_platform_profile(VmGuestPlatform::Ios);
        assert_eq!(ios.remote_shell, VmRemoteShell::Unsupported);
        assert_eq!(ios.guest_exec_mode, VmGuestExecMode::Unsupported);
        assert_eq!(ios.service_manager, VmServiceManager::Unsupported);

        let android = default_platform_profile(VmGuestPlatform::Android);
        assert_eq!(android.remote_shell, VmRemoteShell::Unsupported);
        assert_eq!(android.guest_exec_mode, VmGuestExecMode::Unsupported);
        assert_eq!(android.service_manager, VmServiceManager::Unsupported);
    }

    #[test]
    fn powershell_encoding_helper_emits_utf16le_base64() {
        assert_eq!(
            encode_powershell_command("A").expect("encoding should succeed"),
            "QQA="
        );
        assert!(
            build_ssh_powershell_encoded_invocation("A")
                .expect("SSH wrapper should build")
                .contains("-EncodedCommand QQA=")
        );
    }

    #[test]
    fn windows_transport_dispatch_selection_uses_powershell_for_windows_targets() {
        let (inventory, target) = resolve_windows_remote_target();
        let remote_script = build_remote_argv_script_for_target(
            &target,
            r"C:\Rustynet",
            "rustynet",
            &["status".to_string()],
            false,
        )
        .expect("Windows PowerShell script should build");
        assert!(remote_script.contains("Set-Location -LiteralPath 'C:\\Rustynet'"));
        assert!(remote_script.contains("& 'rustynet' 'status'"));

        let ssh_script = remote_script_for_ssh_transport(&target, remote_script.as_str())
            .expect("SSH wrapper should encode the Windows script");
        assert!(ssh_script.starts_with(
            "powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand "
        ));
        cleanup_temp_inventory(inventory.as_path());
    }

    #[test]
    fn windows_utm_copy_path_selection_normalizes_backslashes() {
        let (inventory, target) = resolve_windows_remote_target();
        assert_eq!(
            remote_copy_destination_for_target(
                &target,
                r"C:\ProgramData\Rustynet\vm-lab\Enable-WindowsVmLabAccess.ps1"
            ),
            "C:/ProgramData/Rustynet/vm-lab/Enable-WindowsVmLabAccess.ps1"
        );
        cleanup_temp_inventory(inventory.as_path());
    }

    #[test]
    fn windows_repo_sync_script_selection_uses_powershell_for_windows_targets() {
        let (inventory, target) = resolve_windows_remote_target();
        let script = build_repo_sync_script_for_target(
            &target,
            "git@github.com:iwanteague/Rustyfin.git",
            r"C:\Rustynet",
            "main",
            "origin",
        )
        .expect("Windows repo sync script should build");
        assert!(script.contains("Set-StrictMode -Version Latest"));
        assert!(script.contains("git clone --origin 'origin' --branch 'main' --single-branch"));
        assert!(script.contains("$dest = 'C:\\Rustynet';"));
        assert!(script.contains("git -C $dest remote set-url 'origin'"));
        assert!(script.contains("git -C $dest reset --hard FETCH_HEAD"));
        assert!(!script.contains("set -eu;"));
        cleanup_temp_inventory(inventory.as_path());
    }

    #[test]
    fn mixed_platform_repo_sync_dispatch_is_platform_explicit() {
        let (linux_inventory, linux_target) = resolve_platform_remote_target("linux");
        let (windows_inventory, windows_target) = resolve_windows_remote_target();

        assert_eq!(
            repo_sync_dispatch_kind_for_target(&linux_target, RepoSyncMode::Git)
                .expect("linux git repo sync should dispatch"),
            RepoSyncDispatchKind::PosixGit
        );
        assert_eq!(
            repo_sync_dispatch_kind_for_target(&windows_target, RepoSyncMode::Git)
                .expect("windows git repo sync should dispatch"),
            RepoSyncDispatchKind::WindowsPowershellGit
        );
        assert_eq!(
            repo_sync_dispatch_kind_for_target(&linux_target, RepoSyncMode::LocalSource)
                .expect("linux local-source sync should dispatch"),
            RepoSyncDispatchKind::PosixLocalArchive
        );
        assert_eq!(
            repo_sync_dispatch_kind_for_target(&windows_target, RepoSyncMode::LocalSource)
                .expect("windows local-source sync should dispatch"),
            RepoSyncDispatchKind::WindowsZipLocalArchive
        );

        cleanup_temp_inventory(linux_inventory.as_path());
        cleanup_temp_inventory(windows_inventory.as_path());
    }

    #[test]
    fn mixed_platform_repo_sync_scripts_do_not_cross_dispatch() {
        let (linux_inventory, linux_target) = resolve_platform_remote_target("linux");
        let (windows_inventory, windows_target) = resolve_windows_remote_target();

        let linux_script = build_repo_sync_script_for_target(
            &linux_target,
            "git@github.com:iwanteague/Rustyfin.git",
            "/home/debian/Rustynet",
            "main",
            "origin",
        )
        .expect("linux repo sync script should build");
        assert!(linux_script.starts_with("set -eu;"));
        assert!(!linux_script.contains("Set-StrictMode -Version Latest;"));

        let windows_script = build_repo_sync_script_for_target(
            &windows_target,
            "git@github.com:iwanteague/Rustyfin.git",
            r"C:\Rustynet",
            "main",
            "origin",
        )
        .expect("windows repo sync script should build");
        assert!(windows_script.contains("Set-StrictMode -Version Latest;"));
        assert!(!windows_script.contains("set -eu;"));

        cleanup_temp_inventory(linux_inventory.as_path());
        cleanup_temp_inventory(windows_inventory.as_path());
    }

    #[test]
    fn helper_script_staging_path_construction_uses_remote_temp_dir() {
        let (inventory, target) = resolve_windows_remote_target();
        assert_eq!(
            windows_helper_script_remote_path(&target, "Enable-WindowsVmLabAccess.ps1")
                .expect("remote helper path should build"),
            r"C:\ProgramData\Rustynet\vm-lab\Enable-WindowsVmLabAccess.ps1"
        );
        cleanup_temp_inventory(inventory.as_path());
    }

    #[test]
    fn windows_diagnostics_helper_selection_uses_windows_script_path() {
        assert!(
            windows_diagnostics_helper_script_local_path().ends_with(Path::new(
                "scripts/bootstrap/windows/Collect-RustyNetWindowsDiagnostics.ps1"
            ))
        );
    }

    #[test]
    fn windows_bootstrap_helper_selection_uses_canonical_script_path() {
        assert!(
            windows_bootstrap_helper_script_local_path().ends_with(Path::new(
                "scripts/bootstrap/windows/Bootstrap-RustyNetWindows.ps1"
            ))
        );
    }

    #[test]
    fn windows_service_install_helper_selection_uses_canonical_script_path() {
        assert!(
            windows_service_install_helper_script_local_path().ends_with(Path::new(
                "scripts/bootstrap/windows/Install-RustyNetWindowsService.ps1"
            ))
        );
    }

    #[test]
    fn windows_verify_helper_selection_uses_canonical_script_path() {
        assert!(
            windows_verify_helper_script_local_path().ends_with(Path::new(
                "scripts/bootstrap/windows/Verify-RustyNetWindowsBootstrap.ps1"
            ))
        );
    }

    #[test]
    fn windows_compatibility_shims_remain_under_vm_lab_root() {
        let install_shim =
            workspace_root_path().join("scripts/vm_lab/windows/Install-RustyNetWindows.ps1");
        let diagnostics_shim = workspace_root_path()
            .join("scripts/vm_lab/windows/Collect-RustyNetWindowsDiagnostics.ps1");
        assert!(
            install_shim.is_file(),
            "missing Windows install compatibility shim: {}",
            install_shim.display()
        );
        assert!(
            diagnostics_shim.is_file(),
            "missing Windows diagnostics compatibility shim: {}",
            diagnostics_shim.display()
        );
    }

    #[test]
    fn utm_windows_capture_wrapper_script_encodes_body_before_scriptblock_creation() {
        let wrapper = super::build_utm_windows_capture_wrapper_script(
            r"C:\ProgramData\Rustynet\vm-lab\capture",
            r"C:\ProgramData\Rustynet\vm-lab\capture\stdout.txt",
            r"C:\ProgramData\Rustynet\vm-lab\capture\rc.txt",
            "Write-Output 'hello from { braces }'; exit 7",
        )
        .expect("wrapper script should build");
        assert!(wrapper.contains("FromBase64String"));
        assert!(wrapper.contains("[ScriptBlock]::Create($body)"));
        assert!(!wrapper.contains("hello from { braces }"));
    }

    #[test]
    fn bootstrap_phase_registry_preserves_underscore_phase_compatibility() {
        assert_eq!(
            super::bootstrap::BootstrapPhase::parse("build_release")
                .expect("underscored phase name should normalize")
                .as_str(),
            "build-release"
        );
    }

    #[test]
    fn bootstrap_phase_registry_routes_linux_to_legacy_executor() {
        let (inventory, target) = resolve_platform_remote_target("linux");
        let context = super::bootstrap::BootstrapPhaseContext {
            ssh_user: target.ssh_user.as_deref(),
            ssh_identity_file: None,
            known_hosts_path: None,
            workdir: "/home/debian/Rustynet",
            repo_url: None,
            branch: "main",
            remote: "origin",
            timeout: Duration::from_secs(1),
        };
        let err =
            super::bootstrap::execute_bootstrap_phase_for_target("sync-source", &target, &context)
                .expect_err("linux legacy executor should require repo_url");
        assert!(err.contains("bootstrap phase sync-source requires --repo-url"));
        cleanup_temp_inventory(inventory.as_path());
    }

    #[test]
    fn bootstrap_phase_registry_routes_windows_to_windows_provider() {
        let (inventory, target) = resolve_windows_remote_target();
        let context = super::bootstrap::BootstrapPhaseContext {
            ssh_user: target.ssh_user.as_deref(),
            ssh_identity_file: None,
            known_hosts_path: None,
            workdir: r"C:\Rustynet",
            repo_url: None,
            branch: "main",
            remote: "origin",
            timeout: Duration::from_secs(1),
        };
        let err = super::bootstrap::execute_bootstrap_phase_for_target("all", &target, &context)
            .expect_err("windows provider should require repo_url before attempting all");
        assert!(err.contains("Windows bootstrap phase sync-source requires --repo-url"));
        cleanup_temp_inventory(inventory.as_path());
    }

    #[test]
    fn bootstrap_phase_registry_rejects_macos_and_mobile_scaffolds() {
        for (platform, phase, expected) in [
            (
                "macos",
                "sync-source",
                "not yet implemented for macOS targets in the provider layer",
            ),
            (
                "ios",
                "sync-source",
                "intentionally scaffold-only for platform ios",
            ),
            (
                "android",
                "sync-source",
                "intentionally scaffold-only for platform android",
            ),
        ] {
            let (inventory, target) = resolve_platform_remote_target(platform);
            let context = super::bootstrap::BootstrapPhaseContext {
                ssh_user: target.ssh_user.as_deref(),
                ssh_identity_file: None,
                known_hosts_path: None,
                workdir: "/tmp/rustynet-unsupported",
                repo_url: None,
                branch: "main",
                remote: "origin",
                timeout: Duration::from_secs(1),
            };
            let err =
                super::bootstrap::execute_bootstrap_phase_for_target(phase, &target, &context)
                    .expect_err("scaffold-only platforms must fail closed");
            assert!(
                err.contains(expected),
                "unexpected error for {platform}: {err}"
            );
            cleanup_temp_inventory(inventory.as_path());
        }
    }

    #[test]
    fn platform_scaffold_inventory_parsing_accepts_macos_ios_and_android() {
        let path = write_temp_inventory(
            r#"{
                "version": 1,
                "entries": [
                    {
                        "alias": "macos-utm-1",
                        "ssh_target": "macos@192.168.64.30",
                        "platform": "macos"
                    },
                    {
                        "alias": "ios-sim-1",
                        "ssh_target": "ios@192.168.64.40",
                        "platform": "ios"
                    },
                    {
                        "alias": "android-emulator-1",
                        "ssh_target": "android@192.168.64.50",
                        "platform": "android"
                    }
                ]
            }"#,
        );
        let inventory = load_inventory(path.as_path()).expect("inventory should load");
        assert_eq!(inventory[0].platform, Some(VmGuestPlatform::Macos));
        assert_eq!(inventory[1].platform, Some(VmGuestPlatform::Ios));
        assert_eq!(inventory[2].platform, Some(VmGuestPlatform::Android));
        cleanup_temp_inventory(path.as_path());
    }

    #[test]
    fn mobile_platforms_fail_closed_for_vm_lab_transport_scaffold() {
        let (ios_inventory, ios_target) = resolve_platform_remote_target("ios");
        let ios_err = build_remote_argv_script_for_target(
            &ios_target,
            "/var/mobile",
            "rustynet",
            &["status".to_string()],
            false,
        )
        .expect_err("ios transport should remain unsupported");
        assert!(ios_err.contains("platform ios"));
        cleanup_temp_inventory(ios_inventory.as_path());

        let (android_inventory, android_target) = resolve_platform_remote_target("android");
        let android_err = remote_script_for_ssh_transport(&android_target, "echo nope")
            .expect_err("android SSH transport should remain unsupported");
        assert!(android_err.contains("platform android"));
        cleanup_temp_inventory(android_inventory.as_path());
    }

    #[test]
    fn execute_ops_vm_lab_discover_local_utm_marks_windows_unmatched_without_debian_guess() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be valid")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("rustynet-vm-lab-utm-root-{unique}.dir"));
        let bundle = root.join("nested").join("windows-utm-1.utm");
        fs::create_dir_all(&bundle).expect("bundle should exist");

        let inventory_body = r#"{{
  "version": 1,
  "entries": [
    {{
      "alias": "other-linux-vm",
      "ssh_target": "other-linux-host",
      "ssh_user": "debian",
      "platform": "linux"
    }}
  ]
}}"#
        .to_string();
        let inventory = write_temp_inventory(inventory_body.as_str());

        let utmctl = write_temp_executable(
            "#!/bin/sh\nif [ \"$1\" = \"ip-address\" ] && [ \"$2\" = \"windows-utm-1\" ]; then\n  printf '192.168.64.20\\n100.64.0.1\\n'\n  exit 0\nfi\nexit 1\n",
        );

        let report = execute_ops_vm_lab_discover_local_utm(VmLabDiscoverLocalUtmConfig {
            inventory_path: Some(inventory.clone()),
            utm_documents_root: Some(root.clone()),
            utmctl_path: Some(utmctl.clone()),
            ssh_identity_file: None,
            known_hosts_path: None,
            ssh_port: 65_534,
            timeout_secs: 2,
            update_inventory_live_ips: false,
            report_dir: None,
        })
        .expect("discovery report should be produced");
        let parsed: serde_json::Value =
            serde_json::from_str(report.as_str()).expect("discovery report should parse as JSON");
        assert_eq!(
            parsed["entries"][0]["ssh_target_source"].as_str(),
            Some("platform-aware-unmatched-windows")
        );
        assert_eq!(
            parsed["entries"][0]["advisory_ssh_target"].as_str(),
            Some("192.168.64.20")
        );
        assert_eq!(parsed["entries"][0]["ssh_user"].as_str(), None);
        assert!(
            !parsed["entries"][0]["ssh_target"]
                .as_str()
                .unwrap_or("")
                .contains("debian@")
        );
        assert!(
            parsed["entries"][0]["notes"]
                .as_array()
                .expect("notes should be an array")
                .iter()
                .any(|note| note.as_str()
                    == Some("windows-utm-discovered-without-inventory-no-linux-user-assumed"))
        );

        cleanup_temp_inventory(inventory.as_path());
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(
            utmctl
                .parent()
                .expect("temp executable parent should exist"),
        );
    }

    #[test]
    fn selected_local_utm_readiness_tracks_unready_aliases_with_reasons() {
        let report = json!({
            "entries": [
                {
                    "alias": "exit-vm",
                    "readiness": {
                        "powered": true,
                        "networked": true,
                        "tcp_ready": true,
                        "auth_ready": true,
                        "execution_ready": true,
                        "reason_codes": []
                    }
                },
                {
                    "alias": "client-vm",
                    "readiness": {
                        "powered": true,
                        "networked": true,
                        "tcp_ready": true,
                        "auth_ready": false,
                        "execution_ready": false,
                        "reason_codes": ["ssh-auth-not-ready"]
                    }
                }
            ]
        });
        let aliases = vec!["exit-vm".to_string(), "client-vm".to_string()];
        let summary = selected_local_utm_readiness_from_report(
            serde_json::to_string(&report)
                .expect("discovery report should serialize")
                .as_str(),
            aliases.as_slice(),
        )
        .expect("selected readiness should parse");
        assert_eq!(summary.ready_aliases, vec!["exit-vm".to_string()]);
        assert_eq!(summary.unready_entries.len(), 1);
        assert_eq!(summary.unready_entries[0].alias, "client-vm");
        assert_eq!(
            summary.unready_entries[0].reason_codes,
            vec!["ssh-auth-not-ready".to_string()]
        );
    }

    #[test]
    fn resolve_live_lab_vm_aliases_uses_inventory_role_defaults() {
        let inventory = write_temp_inventory(
            r#"{
  "version": 1,
  "entries": [
    {"alias": "exit-vm", "ssh_target": "debian@192.168.64.3", "lab_role": "exit"},
    {"alias": "client-vm", "ssh_target": "debian@192.168.64.4", "lab_role": "client"},
    {"alias": "entry-vm", "ssh_target": "debian@192.168.64.5", "lab_role": "entry"},
    {"alias": "aux-vm", "ssh_target": "debian@192.168.64.6", "lab_role": "aux"},
    {"alias": "extra-vm", "ssh_target": "debian@192.168.64.7", "lab_role": "extra"}
  ]
}"#,
        );
        let aliases =
            resolve_live_lab_vm_aliases(inventory.as_path(), None, None, None, None, None, None)
                .expect("role defaults should resolve");
        assert_eq!(
            aliases,
            vec![
                "exit-vm".to_string(),
                "client-vm".to_string(),
                "entry-vm".to_string(),
                "aux-vm".to_string(),
                "extra-vm".to_string()
            ]
        );
        cleanup_temp_inventory(inventory.as_path());
    }

    #[test]
    fn rewrite_ssh_target_host_preserves_user_and_formats_ipv6() {
        assert_eq!(
            rewrite_ssh_target_host("debian@192.168.64.3", "192.168.64.8"),
            "debian@192.168.64.8"
        );
        assert_eq!(
            rewrite_ssh_target_host("debian@example", "fd00::10"),
            "debian@[fd00::10]"
        );
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
    fn resolve_start_targets_carries_platform_profile() {
        let path = write_temp_inventory(
            r#"{
  "version": 1,
  "entries": [
    {
      "alias": "windows-utm-1",
      "ssh_target": "192.168.64.20",
      "ssh_user": "Administrator",
      "platform": "windows",
      "controller": {
        "type": "local_utm",
        "utm_name": "windows-utm-1",
        "bundle_path": "/tmp/windows-utm-1.utm"
      }
    }
  ]
}"#,
        );
        let targets = resolve_start_targets(path.as_path(), &["windows-utm-1".to_string()], false)
            .expect("windows start target should resolve");
        assert_eq!(targets.len(), 1);
        assert_eq!(
            targets[0].platform_profile.platform,
            VmGuestPlatform::Windows
        );
        assert_eq!(
            targets[0].platform_profile.remote_shell,
            VmRemoteShell::Powershell
        );
        cleanup_temp_inventory(path.as_path());
    }

    #[test]
    fn persist_local_utm_ready_states_to_inventory_updates_ip_fields() {
        let path = write_temp_inventory(
            r#"{
  "version": 1,
  "entries": [
    {
      "alias": "debian-headless-1",
      "ssh_target": "192.168.64.20",
      "ssh_user": "debian",
      "last_known_ip": "192.168.64.20",
      "live_ips": [
        "192.168.64.20",
        "fd00::1"
      ],
      "controller": {
        "type": "local_utm",
        "utm_name": "debian-headless-1",
        "bundle_path": "/tmp/debian-headless-1.utm"
      }
    }
  ]
}"#,
        );
        let report = persist_local_utm_ready_states_to_inventory(
            path.as_path(),
            &[super::LocalUtmReadyState {
                alias: "debian-headless-1".to_string(),
                utm_name: "debian-headless-1".to_string(),
                process_present: true,
                live_ip: Some("192.168.64.8".to_string()),
                ssh_port_status: "open".to_string(),
                ssh_auth_status: "ok".to_string(),
            }],
        )
        .expect("inventory live IP update should succeed");
        assert!(report.contains("192.168.64.8"));
        let body = fs::read_to_string(path.as_path()).expect("updated inventory should read");
        assert!(body.contains("\"ssh_target\": \"192.168.64.8\""));
        assert!(body.contains("\"last_known_ip\": \"192.168.64.8\""));
        assert!(body.contains("\"live_ips\": [\n        \"192.168.64.8\","));
        assert!(body.contains("\"fd00::1\""));
        assert!(body.ends_with('\n'));
        assert!(body.find("\"alias\"").unwrap() < body.find("\"ssh_target\"").unwrap());
        assert!(body.find("\"ssh_target\"").unwrap() < body.find("\"ssh_user\"").unwrap());
        assert!(body.find("\"ssh_user\"").unwrap() < body.find("\"last_known_ip\"").unwrap());
        cleanup_temp_inventory(path.as_path());
    }

    #[test]
    fn execute_ops_vm_lab_discover_local_utm_skips_inventory_update_until_all_ready() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be valid")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("rustynet-vm-lab-utm-root-{unique}.dir"));
        let bundle = root.join("nested").join("alpha.utm");
        fs::create_dir_all(&bundle).expect("bundle should exist");

        let inventory = write_temp_inventory(&format!(
            r#"{{
  "version": 1,
  "entries": [
    {{
      "alias": "alpha",
      "ssh_target": "alpha-host",
      "ssh_user": "debian",
      "last_known_ip": "192.168.64.20",
      "mesh_ip": "100.64.0.1",
      "controller": {{
        "type": "local_utm",
        "utm_name": "alpha",
        "bundle_path": "{}"
      }}
    }}
  ]
}}"#,
            bundle.display()
        ));

        let original = fs::read_to_string(inventory.as_path()).expect("inventory should read");
        let utmctl = write_temp_executable(
            "#!/bin/sh\nif [ \"$1\" = \"ip-address\" ] && [ \"$2\" = \"alpha\" ]; then\n  printf '192.168.64.8\\n100.64.0.1\\n'\n  exit 0\nfi\nexit 1\n",
        );
        let report = execute_ops_vm_lab_discover_local_utm(VmLabDiscoverLocalUtmConfig {
            inventory_path: Some(inventory.clone()),
            utm_documents_root: Some(root.clone()),
            utmctl_path: Some(utmctl.clone()),
            ssh_identity_file: None,
            known_hosts_path: None,
            ssh_port: 65_534,
            timeout_secs: 2,
            update_inventory_live_ips: true,
            report_dir: None,
        })
        .expect("discovery report should be produced");
        let parsed: serde_json::Value =
            serde_json::from_str(report.as_str()).expect("discovery report should parse as JSON");
        assert_eq!(
            parsed["inventory_update"].as_str(),
            Some(
                "inventory live IP update skipped because only 0/1 inventory-matched local UTM bundles were execution-ready"
            )
        );
        let updated = fs::read_to_string(inventory.as_path()).expect("inventory should reread");
        assert_eq!(original, updated);

        cleanup_temp_inventory(inventory.as_path());
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(
            utmctl
                .parent()
                .expect("temp executable parent should exist"),
        );
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
    fn windows_local_source_extract_script_uses_expand_archive() {
        let script = build_windows_local_source_extract_script(
            r"C:\Rustynet.offline",
            r"C:\ProgramData\Rustynet\vm-lab\rn-vm-lab-source-123.zip",
        )
        .expect("Windows extract script should build");
        assert!(script.contains("$dest = 'C:\\Rustynet.offline';"));
        assert!(
            script.contains(
                "$archive = 'C:\\ProgramData\\Rustynet\\vm-lab\\rn-vm-lab-source-123.zip';"
            )
        );
        assert!(
            script.contains("Expand-Archive -LiteralPath $archive -DestinationPath $dest -Force;")
        );
        assert!(script.contains("Remove-Item -LiteralPath $archive -Force;"));
        assert!(!script.contains("tar -xf"));
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
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be valid")
            .as_nanos();
        let exit_utm_name = format!("windows-utm-test-exit-{unique}");
        let client_utm_name = format!("debian-headless-test-client-{unique}");
        let inventory = write_temp_inventory(
            format!(
                r#"{{
  "version": 1,
  "entries": [
    {{
      "alias": "exit-vm",
      "ssh_target": "192.168.64.20",
      "ssh_user": "Administrator",
      "platform": "windows",
      "remote_temp_dir": "C:\\ProgramData\\Rustynet\\vm-lab",
      "network_group": "lan-a",
      "controller": {{
        "type": "local_utm",
        "utm_name": "{exit_utm_name}",
        "bundle_path": "/Users/example/Library/Containers/com.utmapp.UTM/Data/Documents/windows-utm-1.utm"
      }}
    }},
    {{
      "alias": "client-vm",
      "ssh_target": "client-host",
      "ssh_user": "debian",
      "network_group": "lan-a",
      "controller": {{
        "type": "local_utm",
        "utm_name": "{client_utm_name}",
        "bundle_path": "/Users/example/Library/Containers/com.utmapp.UTM/Data/Documents/debian-headless-2.utm"
      }}
    }}
  ]
}}"#,
            )
            .as_str(),
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
        assert!(body.contains("EXIT_TARGET=\"Administrator@192.168.64.20\""));
        assert!(body.contains("CLIENT_TARGET=\"debian@client-host\""));
        assert!(body.contains(format!("EXIT_UTM_NAME=\"{exit_utm_name}\"").as_str()));
        assert!(body.contains(format!("CLIENT_UTM_NAME=\"{client_utm_name}\"").as_str()));
        assert!(body.contains("EXIT_PLATFORM=\"windows\""));
        assert!(body.contains("EXIT_REMOTE_SHELL=\"powershell\""));
        assert!(body.contains("EXIT_GUEST_EXEC_MODE=\"windows_powershell\""));
        assert!(body.contains("EXIT_SERVICE_MANAGER=\"windows_service\""));
        assert!(body.contains("EXIT_RUSTYNET_SRC_DIR=\"C:\\\\Rustynet\""));
        assert!(body.contains("CLIENT_PLATFORM=\"linux\""));
        assert!(body.contains("CLIENT_REMOTE_SHELL=\"posix\""));
        assert!(body.contains("CLIENT_GUEST_EXEC_MODE=\"linux_bash\""));
        assert!(body.contains("CLIENT_SERVICE_MANAGER=\"systemd\""));
        assert!(body.contains("FIFTH_CLIENT_TARGET=\"\""));
        assert!(body.contains("FIFTH_CLIENT_UTM_NAME=\"\""));
        assert!(body.contains("FIFTH_CLIENT_PLATFORM=\"\""));
        assert!(body.contains("FIFTH_CLIENT_REMOTE_SHELL=\"\""));
        assert!(body.contains("FIFTH_CLIENT_GUEST_EXEC_MODE=\"\""));
        assert!(body.contains("FIFTH_CLIENT_SERVICE_MANAGER=\"\""));
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
    fn collect_stage_local_bundle_copies_report_context_and_worker_results() {
        let report_dir = write_temp_report_dir();
        let diagnostics_dir = report_dir.join("diagnostics/validate_baseline_runtime");
        let stage_log = report_dir.join("logs/validate_baseline_runtime.log");
        let parallel_dir = report_dir.join("state/parallel-validate_baseline_runtime");
        fs::create_dir_all(parallel_dir.join("evidence/client"))
            .expect("parallel dir should exist");
        fs::write(
            report_dir.join("state/stages.tsv"),
            format!(
                "preflight\thard\tpass\t0\t{}/logs/preflight.log\tverify local prerequisites\t2026-04-03T20:00:00Z\t2026-04-03T20:00:01Z\n\
validate_baseline_runtime\thard\tfail\t1\t{}/logs/validate_baseline_runtime.log\tvalidate one-hop routing and no-plaintext-passphrase state\t2026-04-03T20:10:00Z\t2026-04-03T20:10:05Z\n",
                report_dir.display(),
                report_dir.display()
            ),
        )
        .expect("stages should write");
        fs::write(report_dir.join("failure_digest.md"), "# digest\n").expect("digest should write");
        fs::write(report_dir.join("failure_digest.json"), "{}\n")
            .expect("digest json should write");
        fs::write(report_dir.join("run_summary.md"), "# summary\n").expect("summary should write");
        fs::write(report_dir.join("run_summary.json"), "{}\n").expect("summary json should write");
        fs::write(&stage_log, "error: route missing\n").expect("stage log should write");
        fs::write(
            parallel_dir.join("results.tsv"),
            format!(
                "validate_baseline_runtime\tclient\tdebian@client\tclient-1\tclient\t1\t2026-04-03T20:10:00Z\t2026-04-03T20:10:05Z\t{}/state/parallel-validate_baseline_runtime/client.log\t{}/state/parallel-validate_baseline_runtime/evidence/client/snapshot.txt\t{}/state/parallel-validate_baseline_runtime/evidence/client/route_policy.txt\t{}/state/parallel-validate_baseline_runtime/evidence/client/dns_state.txt\troute missing\n",
                report_dir.display(),
                report_dir.display(),
                report_dir.display(),
                report_dir.display()
            ),
        )
        .expect("results should write");
        fs::write(parallel_dir.join("client.log"), "route missing\n")
            .expect("client log should write");
        fs::write(
            parallel_dir.join("evidence/client/snapshot.txt"),
            "snapshot\n",
        )
        .expect("snapshot should write");
        fs::write(
            parallel_dir.join("evidence/client/route_policy.txt"),
            "route policy\n",
        )
        .expect("route policy should write");
        fs::write(
            parallel_dir.join("evidence/client/dns_state.txt"),
            "dns state\n",
        )
        .expect("dns state should write");

        let summary = summarize_live_lab_report(report_dir.as_path(), false, 1)
            .expect("summary should build");
        let stage_record = LiveLabStageRecord {
            name: "validate_baseline_runtime".to_string(),
            severity: "hard".to_string(),
            status: "fail".to_string(),
            rc: "1".to_string(),
            log_path: stage_log.clone(),
            description: "validate one-hop routing and no-plaintext-passphrase state".to_string(),
        };
        let bundle = collect_live_lab_stage_local_bundle(
            report_dir.as_path(),
            &stage_record,
            &summary,
            diagnostics_dir.as_path(),
        )
        .expect("bundle should collect");

        assert_eq!(bundle.worker_results.len(), 1);
        assert!(
            bundle
                .report_context_dir
                .join("state/parallel-validate_baseline_runtime/results.tsv")
                .is_file()
        );
        assert!(
            bundle
                .report_context_dir
                .join("logs/validate_baseline_runtime.log")
                .is_file()
        );
        assert!(
            bundle
                .worker_results_json_path
                .as_deref()
                .expect("worker results json path should exist")
                .is_file()
        );
        let worker_markdown = fs::read_to_string(
            bundle
                .worker_results_markdown_path
                .as_deref()
                .expect("worker results markdown path should exist"),
        )
        .expect("worker markdown should read");
        assert!(worker_markdown.contains("route missing"));
        assert!(worker_markdown.contains("client-1"));

        let _ = fs::remove_dir_all(report_dir);
    }

    #[test]
    fn stage_forensics_review_highlights_baseline_expectations() {
        let report_dir = write_temp_report_dir();
        let diagnostics_dir = report_dir.join("diagnostics/validate_baseline_runtime");
        fs::create_dir_all(&diagnostics_dir).expect("diagnostics dir should exist");
        let stage_log = report_dir.join("logs/validate_baseline_runtime.log");
        fs::write(report_dir.join("failure_digest.md"), "# digest\n").expect("digest should write");
        fs::write(&stage_log, "error: route missing\n").expect("stage log should write");

        let local_bundle = super::LiveLabStageLocalBundle {
            report_context_dir: diagnostics_dir.join("report_context"),
            copied_paths: vec![diagnostics_dir.join("report_context/failure_digest.md")],
            worker_results: Vec::new(),
            worker_results_json_path: None,
            worker_results_markdown_path: None,
        };
        let stage_record = LiveLabStageRecord {
            name: "validate_baseline_runtime".to_string(),
            severity: "hard".to_string(),
            status: "fail".to_string(),
            rc: "1".to_string(),
            log_path: stage_log,
            description: "validate one-hop routing and no-plaintext-passphrase state".to_string(),
        };
        let summary = LiveLabStageSummary {
            overall_status: "fail".to_string(),
            first_failed_stage: Some("validate_baseline_runtime".to_string()),
            key_report_path: report_dir.join("failure_digest.md"),
            key_log_path: Some(report_dir.join("logs/validate_baseline_runtime.log")),
            likely_reason: Some("error: route missing".to_string()),
            failed_log_tail: None,
        };
        let review = render_live_lab_stage_forensics_review(super::LiveLabStageReviewContext {
            report_dir: report_dir.as_path(),
            stage_record: &stage_record,
            summary: &summary,
            strategy: "validate-baseline-runtime",
            local_bundle: &local_bundle,
            remote_probe_dir: Some(
                report_dir
                    .join("remote_validate_baseline_runtime")
                    .as_path(),
            ),
            notes: live_lab_stage_forensics_notes("validate_baseline_runtime").as_slice(),
            warnings: &["warning example".to_string()],
        });
        assert!(
            review
                .contains("transport_socket_identity_state=authoritative_backend_shared_transport")
        );
        assert!(review.contains("no-plaintext-passphrase-files"));
        assert!(review.contains("remote_probe_dir="));
        assert!(review.contains("warning example"));

        let _ = fs::remove_dir_all(report_dir);
    }

    #[test]
    fn utm_readiness_requires_auth_for_execution_ready() {
        let readiness = build_utm_readiness(
            &ProbeState::Ok { value: true },
            &ProbeState::Ok {
                value: "192.168.64.3".to_string(),
            },
            &ProbeState::Ok {
                value: PortStatus::Open,
            },
            &ProbeState::Missing {
                reason: "auth-probe-not-configured".to_string(),
            },
            true,
        );
        assert!(readiness.powered);
        assert!(readiness.networked);
        assert!(readiness.tcp_ready);
        assert!(!readiness.auth_ready);
        assert!(!readiness.execution_ready);
        assert!(
            readiness
                .reason_codes
                .contains(&"ssh-auth-not-ready".to_string())
        );
    }

    #[test]
    fn validate_live_lab_run_artifacts_requires_failure_digest_for_failed_runs() {
        let report_dir = write_temp_report_dir();
        fs::create_dir_all(report_dir.join("state")).expect("state dir should exist");
        fs::write(report_dir.join("run_summary.json"), "{}\n")
            .expect("run summary json should write");
        fs::write(report_dir.join("run_summary.md"), "# summary\n")
            .expect("run summary md should write");
        fs::write(
            report_dir.join("state/stages.tsv"),
            format!(
                "validate_baseline_runtime\thard\tfail\t1\t{}\tbaseline failed\t2026-01-01T00:00:00Z\t2026-01-01T00:00:01Z\n",
                report_dir
                    .join("logs/validate_baseline_runtime.log")
                    .display()
            ),
        )
        .expect("stages should write");
        fs::write(
            report_dir.join("state/nodes.tsv"),
            "exit\tdebian@192.168.64.3\texit-1\texit\n",
        )
        .expect("nodes should write");
        fs::create_dir_all(report_dir.join("logs")).expect("logs dir should exist");
        fs::write(
            report_dir.join("logs/validate_baseline_runtime.log"),
            "error\n",
        )
        .expect("stage log should write");

        let err = validate_live_lab_run_artifacts(report_dir.as_path())
            .expect_err("failed run without digest must fail validation");
        assert!(err.contains("failure digest"));

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
FIFTH_CLIENT_TARGET=\"\"\n\
SSH_IDENTITY_FILE=\"$IDENTITY_FILE\"\n\
SSH_KNOWN_HOSTS_FILE=\"$KNOWN_HOSTS_FILE\"\n\
RUSTYNET_BACKEND=\"linux-wireguard-userspace-shared\"\n\
SOURCE_MODE=\"working-tree\"\n\
REPORT_DIR=\"artifacts/live_lab/test\"\n",
        );

        let profile = load_live_lab_profile(profile_path.as_path()).expect("profile should parse");
        assert_eq!(
            profile.optional("EXIT_TARGET").as_deref(),
            Some("debian@exit-host")
        );
        assert_eq!(
            profile.optional("CLIENT_TARGET").as_deref(),
            Some("debian@client-host")
        );
        assert_eq!(profile.optional("EXIT_PLATFORM").as_deref(), Some("linux"));
        assert_eq!(
            profile.optional("CLIENT_PLATFORM").as_deref(),
            Some("linux")
        );
        assert_eq!(
            profile.optional("EXIT_REMOTE_SHELL").as_deref(),
            Some("posix")
        );
        let targets = profile.configured_targets().expect("targets should render");
        assert_eq!(targets.len(), 5);
        assert_eq!(targets[0].role, "exit");
        assert_eq!(targets[1].role, "client");

        let _ = fs::remove_dir_all(profile_path.parent().expect("profile dir should exist"));
    }

    #[test]
    fn resolve_live_lab_profile_targets_uses_inventory_utm_metadata() {
        let inventory_path = write_temp_inventory(
            r#"{
  "version": 1,
  "entries": [
    {
      "alias": "debian-headless-1",
      "ssh_target": "192.168.64.3",
      "ssh_user": "debian",
      "controller": {
        "type": "local_utm",
        "utm_name": "debian-headless-1",
        "bundle_path": "/tmp/debian-headless-1.utm"
      }
    },
    {
      "alias": "debian-headless-2",
      "ssh_target": "192.168.64.4",
      "ssh_user": "debian",
      "controller": {
        "type": "local_utm",
        "utm_name": "debian-headless-2",
        "bundle_path": "/tmp/debian-headless-2.utm"
      }
    }
  ]
}"#,
        );
        let profile_path = write_temp_live_lab_profile(
            "# Generated by test\n\
EXIT_TARGET=\"debian@192.168.64.8\"\n\
EXIT_UTM_NAME=\"debian-headless-1\"\n\
CLIENT_TARGET=\"debian@192.168.64.4\"\n\
CLIENT_UTM_NAME=\"debian-headless-2\"\n\
SSH_IDENTITY_FILE=\"$IDENTITY_FILE\"\n",
        );

        let profile = load_live_lab_profile(profile_path.as_path()).expect("profile should parse");
        let targets = super::resolve_live_lab_profile_targets(inventory_path.as_path(), &profile)
            .expect("targets should resolve");
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].role, "exit");
        assert_eq!(targets[0].profile_target, "debian@192.168.64.8");
        assert_eq!(targets[0].remote_target.label, "exit");
        assert_eq!(targets[0].remote_target.ssh_user.as_deref(), Some("debian"));
        assert!(matches!(
            targets[0].remote_target.controller,
            Some(super::VmController::LocalUtm { .. })
        ));
        assert_eq!(targets[1].role, "client");
        assert!(matches!(
            targets[1].remote_target.controller,
            Some(super::VmController::LocalUtm { .. })
        ));

        cleanup_temp_inventory(inventory_path.as_path());
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
    fn validate_live_lab_profile_requires_platform_metadata_for_configured_targets() {
        let unique = super::unique_suffix();
        let dir = std::env::temp_dir().join(format!("rustynet-live-lab-profile-{unique}.dir"));
        fs::create_dir_all(&dir).expect("temp dir should exist");
        let identity = dir.join("id_ed25519");
        fs::write(&identity, "dummy-key").expect("identity file should write");
        let profile_path = dir.join("profile.env");
        fs::write(
            &profile_path,
            format!(
                "EXIT_TARGET=\"debian@exit-host\"\nCLIENT_TARGET=\"debian@client-host\"\nSSH_IDENTITY_FILE=\"{}\"\n",
                identity.display()
            ),
        )
        .expect("profile should write");

        let err = execute_ops_vm_lab_validate_live_lab_profile(VmLabValidateLiveLabProfileConfig {
            profile_path: profile_path.clone(),
            expected_backend: None,
            expected_source_mode: None,
            require_five_node: false,
        })
        .expect_err("missing platform metadata must fail closed");

        assert!(err.contains("missing required key EXIT_PLATFORM"));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn validate_live_lab_profile_rejects_non_linux_stage_targets() {
        let profile_path = write_temp_live_lab_profile(
            "EXIT_TARGET=\"Administrator@windows-exit\"\nCLIENT_TARGET=\"debian@client-host\"\nSSH_IDENTITY_FILE=\"$IDENTITY_FILE\"\nEXIT_PLATFORM=\"windows\"\nEXIT_REMOTE_SHELL=\"powershell\"\nEXIT_GUEST_EXEC_MODE=\"windows_powershell\"\nEXIT_SERVICE_MANAGER=\"windows_service\"\nEXIT_RUSTYNET_SRC_DIR=\"C:\\\\Rustynet\"\n",
        );

        let err = execute_ops_vm_lab_validate_live_lab_profile(VmLabValidateLiveLabProfileConfig {
            profile_path: profile_path.clone(),
            expected_backend: None,
            expected_source_mode: None,
            require_five_node: false,
        })
        .expect_err("non-linux live-lab targets must fail closed");

        assert!(err.contains(
            "requires platform=linux remote_shell=posix guest_exec_mode=linux_bash service_manager=systemd"
        ));
        assert!(err.contains("platform=windows"));

        cleanup_temp_path(profile_path.as_path());
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
        assert_eq!(resolved, ("local-head".to_string(), None));

        let resolved = resolve_iteration_source_selection(
            Some("working-tree"),
            Some("HEAD"),
            false,
            false,
            false,
        )
        .expect("working-tree selection should ignore repo ref");
        assert_eq!(resolved, ("working-tree".to_string(), None));

        let resolved =
            resolve_iteration_source_selection(Some("ref"), Some("HEAD"), false, false, false)
                .expect("ref selection should preserve repo ref");
        assert_eq!(resolved, ("ref".to_string(), Some("HEAD".to_string())));

        let err =
            resolve_iteration_source_selection(Some("working-tree"), None, false, true, false)
                .expect_err("non-local-head source mode must fail");
        assert!(err.contains("--require-local-head"));

        let err = resolve_iteration_source_selection(None, None, true, false, true)
            .expect_err("dirty tree must fail");
        assert!(err.contains("git worktree must be clean"));

        let err = resolve_iteration_source_selection(Some("ref"), None, false, false, false)
            .expect_err("ref mode must require an explicit ref");
        assert!(err.contains("source-mode=ref requires --repo-ref"));
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
    fn parse_local_utm_list_started_status_finds_matching_vm() {
        let list_output = "\
UUID                                 Status   Name
21589998-AC14-41A8-A146-006AC70501D3 stopped  debian-headless-1
FDC31AD5-CF13-404E-9D9A-0035999D607A started  debian-headless-2
";

        assert_eq!(
            parse_local_utm_list_started_status(list_output, "debian-headless-1"),
            Some(false)
        );
        assert_eq!(
            parse_local_utm_list_started_status(list_output, "debian-headless-2"),
            Some(true)
        );
        assert_eq!(
            parse_local_utm_list_started_status(list_output, "missing-vm"),
            None
        );
    }

    #[test]
    fn local_utm_process_present_uses_wide_ps_output() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be valid")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rustynet-vm-lab-ps-{unique}.dir"));
        fs::create_dir_all(&dir).expect("temp dir should exist");
        let bundle = dir.join("alpha.utm");
        fs::create_dir_all(&bundle).expect("bundle dir should exist");
        let args_log = dir.join("ps-args.log");
        let ps = dir.join("ps");
        fs::write(
            &ps,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" > \"{}\"\nprintf '123 /Applications/UTM.app/Contents/XPCServices/QEMUHelper.xpc/Contents/MacOS/QEMULauncher -drive if=pflash,file={}/Data/efi_vars.fd\\n'\n",
                args_log.display(),
                bundle.display()
            ),
        )
        .expect("ps script should write");
        let mut permissions = fs::metadata(&ps)
            .expect("ps script metadata should read")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&ps, permissions).expect("ps script should be executable");

        let present = local_utm_process_present_with_ps(
            ps.as_path(),
            bundle.as_path(),
            Duration::from_secs(5),
        )
        .expect("process probe should succeed");

        assert!(present);
        assert_eq!(
            fs::read_to_string(&args_log)
                .expect("ps args log should read")
                .trim(),
            "axww -o command"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn transition_local_utm_vm_skips_stop_when_vm_is_already_stopped() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be valid")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rustynet-vm-lab-transition-{unique}.dir"));
        fs::create_dir_all(&dir).expect("temp dir should exist");
        let bundle = dir.join("alpha.utm");
        fs::create_dir_all(&bundle).expect("bundle dir should exist");
        let utmctl_log = dir.join("utmctl.log");
        let utmctl = dir.join("utmctl");
        fs::write(
            &utmctl,
            format!(
                "#!/bin/sh\nif [ \"$1\" = \"list\" ]; then\n  exit 1\nfi\nprintf '%s %s\\n' \"$1\" \"$2\" >> \"{}\"\nexit 0\n",
                utmctl_log.display()
            ),
        )
        .expect("utmctl script should write");
        let mut utmctl_permissions = fs::metadata(&utmctl)
            .expect("utmctl script metadata should read")
            .permissions();
        utmctl_permissions.set_mode(0o755);
        fs::set_permissions(&utmctl, utmctl_permissions)
            .expect("utmctl script should be executable");

        let ps = dir.join("ps");
        fs::write(
            &ps,
            "#!/bin/sh\nprintf '789 /usr/libexec/other-process\\n'\n",
        )
        .expect("ps script should write");
        let mut ps_permissions = fs::metadata(&ps)
            .expect("ps script metadata should read")
            .permissions();
        ps_permissions.set_mode(0o755);
        fs::set_permissions(&ps, ps_permissions).expect("ps script should be executable");

        transition_local_utm_vm_with_process_probe(
            utmctl.as_path(),
            ps.as_path(),
            "alpha",
            bundle.as_path(),
            "stop",
            false,
            Duration::from_secs(5),
        )
        .expect("stopped VM transition should no-op successfully");

        assert_eq!(fs::read_to_string(&utmctl_log).unwrap_or_default(), "");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn transition_local_utm_vm_skips_stop_when_utmctl_probe_spawn_fails_but_ps_reports_stopped() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be valid")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rustynet-vm-lab-transition-{unique}.dir"));
        fs::create_dir_all(&dir).expect("temp dir should exist");
        let bundle = dir.join("alpha.utm");
        fs::create_dir_all(&bundle).expect("bundle dir should exist");
        let utmctl_log = dir.join("utmctl.log");
        let utmctl = dir.join("utmctl");
        fs::write(&utmctl, "#!/bin/sh\nexit 0\n").expect("utmctl placeholder should write");
        let mut utmctl_permissions = fs::metadata(&utmctl)
            .expect("utmctl placeholder metadata should read")
            .permissions();
        utmctl_permissions.set_mode(0o644);
        fs::set_permissions(&utmctl, utmctl_permissions)
            .expect("utmctl placeholder permissions should write");

        let ps = dir.join("ps");
        fs::write(
            &ps,
            "#!/bin/sh\nprintf '789 /usr/libexec/other-process\\n'\n",
        )
        .expect("ps script should write");
        let mut ps_permissions = fs::metadata(&ps)
            .expect("ps script metadata should read")
            .permissions();
        ps_permissions.set_mode(0o755);
        fs::set_permissions(&ps, ps_permissions).expect("ps script should be executable");

        transition_local_utm_vm_with_process_probe(
            utmctl.as_path(),
            ps.as_path(),
            "alpha",
            bundle.as_path(),
            "stop",
            false,
            Duration::from_secs(5),
        )
        .expect("stopped VM transition should fall back to ps when utmctl cannot spawn");

        assert_eq!(fs::read_to_string(&utmctl_log).unwrap_or_default(), "");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn transition_local_utm_vm_accepts_timeout_when_vm_reaches_stopped_state() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be valid")
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("rustynet-vm-lab-timeout-transition-{unique}.dir"));
        fs::create_dir_all(&dir).expect("temp dir should exist");
        let bundle = dir.join("alpha.utm");
        fs::create_dir_all(&bundle).expect("bundle dir should exist");
        let state_file = dir.join("vm-state");
        fs::write(&state_file, "started\n").expect("state file should write");
        let stop_requested = dir.join("stop-requested");
        let poll_count = dir.join("poll-count");
        fs::write(&poll_count, "0\n").expect("poll count should write");

        let utmctl = dir.join("utmctl");
        fs::write(
            &utmctl,
            format!(
                "#!/bin/sh\nSTATE_FILE=\"{}\"\nSTOP_REQUESTED=\"{}\"\nPOLL_COUNT=\"{}\"\ncase \"$1\" in\n  list)\n    if [ -f \"$STOP_REQUESTED\" ]; then\n      count=$(cat \"$POLL_COUNT\")\n      count=$((count + 1))\n      printf '%s\\n' \"$count\" > \"$POLL_COUNT\"\n      if [ \"$count\" -ge 2 ]; then\n        printf 'stopped\\n' > \"$STATE_FILE\"\n      fi\n    fi\n    state=$(cat \"$STATE_FILE\")\n    printf 'UUID                                 Status   Name\\n00000000-0000-0000-0000-000000000000 %s alpha\\n' \"$state\"\n    exit 0\n    ;;\n  stop)\n    : > \"$STOP_REQUESTED\"\n    sleep 2\n    exit 0\n    ;;\n  *)\n    exit 1\n    ;;\nesac\n",
                state_file.display(),
                stop_requested.display(),
                poll_count.display(),
            ),
        )
        .expect("utmctl script should write");
        let mut utmctl_permissions = fs::metadata(&utmctl)
            .expect("utmctl script metadata should read")
            .permissions();
        utmctl_permissions.set_mode(0o755);
        fs::set_permissions(&utmctl, utmctl_permissions)
            .expect("utmctl script should be executable");

        let ps = dir.join("ps");
        fs::write(
            &ps,
            "#!/bin/sh\nprintf '789 /usr/libexec/other-process\\n'\n",
        )
        .expect("ps script should write");
        let mut ps_permissions = fs::metadata(&ps)
            .expect("ps script metadata should read")
            .permissions();
        ps_permissions.set_mode(0o755);
        fs::set_permissions(&ps, ps_permissions).expect("ps script should be executable");

        transition_local_utm_vm_with_process_probe(
            utmctl.as_path(),
            ps.as_path(),
            "alpha",
            bundle.as_path(),
            "stop",
            false,
            Duration::from_secs(5),
        )
        .expect("timed out stop should succeed once state is stopped");

        assert_eq!(
            fs::read_to_string(&state_file)
                .expect("state file should read")
                .trim(),
            "stopped"
        );

        let _ = fs::remove_dir_all(&dir);
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
        let inventory_path = write_temp_inventory(
            r#"{
  "version": 1,
  "entries": [
    {
      "alias": "exit-vm",
      "ssh_target": "debian@exit-host",
      "ssh_user": "debian",
      "platform": "linux"
    },
    {
      "alias": "client-vm",
      "ssh_target": "debian@client-host",
      "ssh_user": "debian",
      "platform": "linux"
    }
  ]
}"#,
        );
        let inventory = load_inventory(inventory_path.as_path()).expect("inventory should load");
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
            inventory.as_slice(),
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

        cleanup_temp_inventory(inventory_path.as_path());
    }

    #[test]
    fn build_suite_command_rejects_windows_targets_for_linux_only_suites() {
        let inventory_path = write_temp_inventory(
            r#"{
  "version": 1,
  "entries": [
    {
      "alias": "exit-vm",
      "ssh_target": "debian@exit-host",
      "ssh_user": "debian",
      "platform": "linux"
    },
    {
      "alias": "client-vm",
      "ssh_target": "Administrator@windows-host",
      "ssh_user": "Administrator",
      "platform": "windows",
      "remote_shell": "powershell",
      "guest_exec_mode": "windows_powershell",
      "service_manager": "windows_service",
      "remote_temp_dir": "C:\\ProgramData\\Rustynet\\vm-lab"
    }
  ]
}"#,
        );
        let inventory = load_inventory(inventory_path.as_path()).expect("inventory should load");
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
                    "normalized_target": "Administrator@windows-host",
                    "node_id": "client-1",
                    "lab_role": "client",
                    "network_id": "net-b",
                    "exit_capable": false,
                    "relay_capable": false
                }
            ]
        }))
        .expect("topology should parse");

        let err = build_suite_command(
            "direct-remote-exit",
            &topology,
            inventory.as_slice(),
            Path::new("/Users/iwanteague/.ssh/rustynet_lab_ed25519"),
            Some("baseline_lan"),
            Some("none"),
            Path::new("/tmp/vm-lab-report"),
        )
        .expect_err("windows targets must be blocked from linux live-lab shell helpers");

        assert!(err.contains("blocked targets"));
        assert!(err.contains("platform=windows"));

        cleanup_temp_inventory(inventory_path.as_path());
    }

    #[test]
    fn execute_ops_vm_lab_run_live_lab_rejects_windows_profile_before_linux_shell_helper() {
        let profile_path = write_temp_live_lab_profile(
            "EXIT_TARGET=\"Administrator@windows-exit\"\nCLIENT_TARGET=\"Administrator@windows-client\"\nSSH_IDENTITY_FILE=\"$IDENTITY_FILE\"\nEXIT_PLATFORM=\"windows\"\nEXIT_REMOTE_SHELL=\"powershell\"\nEXIT_GUEST_EXEC_MODE=\"windows_powershell\"\nEXIT_SERVICE_MANAGER=\"windows_service\"\nEXIT_RUSTYNET_SRC_DIR=\"C:\\\\Rustynet\"\nCLIENT_PLATFORM=\"windows\"\nCLIENT_REMOTE_SHELL=\"powershell\"\nCLIENT_GUEST_EXEC_MODE=\"windows_powershell\"\nCLIENT_SERVICE_MANAGER=\"windows_service\"\nCLIENT_RUSTYNET_SRC_DIR=\"C:\\\\Rustynet\"\n",
        );
        let unique = super::unique_suffix();
        let script_dir = std::env::temp_dir().join(format!("rustynet-vm-lab-run-{unique}.dir"));
        fs::create_dir_all(&script_dir).expect("script dir should exist");
        let script_path = script_dir.join("mock-live-lab.sh");
        let marker_path = script_dir.join("executed.marker");
        fs::write(
            &script_path,
            format!(
                "#!/bin/sh\nprintf 'executed\\n' > {}\nexit 0\n",
                marker_path.display()
            ),
        )
        .expect("script should write");
        let mut permissions = fs::metadata(&script_path)
            .expect("script metadata should read")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script_path, permissions).expect("script should be executable");

        let report_dir =
            std::env::temp_dir().join(format!("rustynet-vm-lab-run-report-{unique}.dir"));
        let result = super::execute_ops_vm_lab_run_live_lab(VmLabRunLiveLabConfig {
            profile_path: profile_path.clone(),
            script_path: script_path.clone(),
            dry_run: false,
            skip_setup: false,
            skip_gates: false,
            skip_soak: false,
            skip_cross_network: false,
            source_mode: None,
            repo_ref: None,
            report_dir: Some(report_dir.clone()),
            timeout_secs: 30,
        });

        let err = result.expect_err("windows profile must be blocked before shell invocation");
        assert!(err.contains(
            "requires platform=linux remote_shell=posix guest_exec_mode=linux_bash service_manager=systemd"
        ));
        assert!(err.contains("platform=windows"));
        assert!(
            !marker_path.exists(),
            "shell helper should not have executed"
        );

        let _ = fs::remove_dir_all(script_dir);
        let _ = fs::remove_dir_all(report_dir);
        cleanup_temp_path(profile_path.as_path());
    }

    #[test]
    fn execute_ops_vm_lab_setup_live_lab_rejects_windows_profile_before_linux_shell_helper() {
        let profile_path = write_temp_live_lab_profile(
            "EXIT_TARGET=\"Administrator@windows-exit\"\nCLIENT_TARGET=\"Administrator@windows-client\"\nSSH_IDENTITY_FILE=\"$IDENTITY_FILE\"\nEXIT_PLATFORM=\"windows\"\nEXIT_REMOTE_SHELL=\"powershell\"\nEXIT_GUEST_EXEC_MODE=\"windows_powershell\"\nEXIT_SERVICE_MANAGER=\"windows_service\"\nEXIT_RUSTYNET_SRC_DIR=\"C:\\\\Rustynet\"\nCLIENT_PLATFORM=\"windows\"\nCLIENT_REMOTE_SHELL=\"powershell\"\nCLIENT_GUEST_EXEC_MODE=\"windows_powershell\"\nCLIENT_SERVICE_MANAGER=\"windows_service\"\nCLIENT_RUSTYNET_SRC_DIR=\"C:\\\\Rustynet\"\n",
        );
        let profile_dir = profile_path
            .parent()
            .expect("profile dir should exist")
            .to_path_buf();
        let identity_path = profile_dir.join("id_ed25519");
        let inventory_path = write_temp_inventory(
            r#"{
  "version": 1,
  "entries": [
    {
      "alias": "dummy-linux",
      "ssh_target": "debian@192.168.64.10",
      "ssh_user": "debian",
      "platform": "linux"
    }
  ]
}"#,
        );
        let unique = super::unique_suffix();
        let script_dir = std::env::temp_dir().join(format!("rustynet-vm-lab-setup-{unique}.dir"));
        fs::create_dir_all(&script_dir).expect("script dir should exist");
        let script_path = script_dir.join("mock-live-lab.sh");
        let marker_path = script_dir.join("executed.marker");
        fs::write(
            &script_path,
            format!(
                "#!/bin/sh\nprintf 'executed\\n' > {}\nexit 0\n",
                marker_path.display()
            ),
        )
        .expect("script should write");
        let mut permissions = fs::metadata(&script_path)
            .expect("script metadata should read")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script_path, permissions).expect("script should be executable");

        let report_dir =
            std::env::temp_dir().join(format!("rustynet-vm-lab-setup-report-{unique}.dir"));
        let result = super::execute_ops_vm_lab_setup_live_lab(VmLabSetupLiveLabConfig {
            inventory_path: inventory_path.clone(),
            profile_path: Some(profile_path.clone()),
            profile_output_path: None,
            exit_vm: None,
            client_vm: None,
            entry_vm: None,
            aux_vm: None,
            extra_vm: None,
            fifth_client_vm: None,
            ssh_identity_file: identity_path,
            known_hosts_path: None,
            require_same_network: false,
            script_path: script_path.clone(),
            report_dir: report_dir.clone(),
            source_mode: None,
            repo_ref: None,
            resume_from: None,
            rerun_stage: None,
            max_parallel_node_workers: None,
            timeout_secs: 30,
            dry_run: false,
        });

        let err =
            result.expect_err("windows profile must be blocked before setup shell invocation");
        assert!(err.contains(
            "requires platform=linux remote_shell=posix guest_exec_mode=linux_bash service_manager=systemd"
        ));
        assert!(err.contains("platform=windows"));
        assert!(
            !marker_path.exists(),
            "shell helper should not have executed"
        );

        let _ = fs::remove_dir_all(script_dir);
        let _ = fs::remove_dir_all(report_dir);
        cleanup_temp_inventory(inventory_path.as_path());
        cleanup_temp_path(profile_path.as_path());
    }

    #[test]
    fn execute_ops_vm_lab_diagnose_live_lab_failure_rejects_windows_profile_before_diagnostics() {
        let profile_path = write_temp_live_lab_profile(
            "EXIT_TARGET=\"Administrator@windows-exit\"\nCLIENT_TARGET=\"debian@client-host\"\nSSH_IDENTITY_FILE=\"$IDENTITY_FILE\"\nEXIT_PLATFORM=\"windows\"\nEXIT_REMOTE_SHELL=\"powershell\"\nEXIT_GUEST_EXEC_MODE=\"windows_powershell\"\nEXIT_SERVICE_MANAGER=\"windows_service\"\nEXIT_RUSTYNET_SRC_DIR=\"C:\\\\Rustynet\"\n",
        );
        let inventory_path = write_temp_inventory(
            r#"{
  "version": 1,
  "entries": []
}"#,
        );
        let report_dir = write_temp_report_dir();
        let output_dir = report_dir.join("diagnostics-output");

        let err = super::execute_ops_vm_lab_diagnose_live_lab_failure(
            super::VmLabDiagnoseLiveLabFailureConfig {
                inventory_path: inventory_path.clone(),
                profile_path: profile_path.clone(),
                report_dir: report_dir.clone(),
                stage: None,
                output_dir: Some(output_dir.clone()),
                collect_artifacts: true,
                timeout_secs: 30,
            },
        )
        .expect_err("windows live-lab diagnostics must fail closed before collection starts");

        assert!(err.contains(
            "requires platform=linux remote_shell=posix guest_exec_mode=linux_bash service_manager=systemd"
        ));
        assert!(err.contains("platform=windows"));
        assert!(
            !output_dir.exists(),
            "diagnostics output should not be created before the Linux-only guard passes"
        );

        let _ = fs::remove_dir_all(report_dir);
        cleanup_temp_inventory(inventory_path.as_path());
        cleanup_temp_path(profile_path.as_path());
    }

    #[test]
    fn validate_setup_manifest_rejects_mismatched_source_mode() {
        let report_dir = write_temp_report_dir();
        let profile_path = write_temp_live_lab_profile(
            "REPORT_DIR=\"/tmp/example\"\nEXIT_TARGET=\"debian@exit\"\nCLIENT_TARGET=\"debian@client\"\nSSH_IDENTITY_FILE=\"$IDENTITY_FILE\"\n",
        );
        let script_path = write_temp_executable("#!/bin/sh\nexit 0\n");

        let manifest = build_test_setup_manifest(
            report_dir.as_path(),
            profile_path.as_path(),
            script_path.as_path(),
            None,
        );
        super::write_setup_manifest(report_dir.as_path(), &manifest)
            .expect("manifest should write");

        let err = super::validate_setup_manifest(
            report_dir.as_path(),
            &super::LiveLabSetupManifestExpectation {
                report_dir: report_dir.clone(),
                profile_path: profile_path.clone(),
                script_path: script_path.clone(),
                inventory_path: None,
                source_mode: "archive".to_string(),
                repo_ref: Some("HEAD".to_string()),
                require_same_network: Some(true),
                dry_run: Some(false),
                max_parallel_node_workers: None,
            },
        )
        .expect_err("mismatched source mode must fail closed");

        assert!(err.contains("git provenance mismatch"));

        let _ = fs::remove_dir_all(report_dir);
        cleanup_temp_path(profile_path.as_path());
        cleanup_temp_path(script_path.as_path());
    }

    #[test]
    fn resolve_run_setup_reuse_allows_matching_auto_continue() {
        let report_dir = write_temp_report_dir();
        let profile_path = write_temp_live_lab_profile(
            "REPORT_DIR=\"/tmp/example\"\nEXIT_TARGET=\"debian@exit\"\nCLIENT_TARGET=\"debian@client\"\nSSH_IDENTITY_FILE=\"$IDENTITY_FILE\"\n",
        );
        let script_path = write_temp_executable("#!/bin/sh\nexit 0\n");

        let manifest = build_test_setup_manifest(
            report_dir.as_path(),
            profile_path.as_path(),
            script_path.as_path(),
            None,
        );
        write_setup_only_report_state(report_dir.as_path(), &manifest);

        let continue_from_setup = super::resolve_run_setup_reuse(
            report_dir.as_path(),
            profile_path.as_path(),
            script_path.as_path(),
            "local-head",
            Some("HEAD"),
            false,
        )
        .expect("matching manifest should allow setup reuse");

        assert!(continue_from_setup);
        let report_state = super::validate_report_state(report_dir.as_path())
            .expect("report state should validate");
        assert!(report_state.setup_complete);
        assert!(!report_state.run_complete);

        let _ = fs::remove_dir_all(report_dir);
        cleanup_temp_path(profile_path.as_path());
        cleanup_temp_path(script_path.as_path());
    }

    #[test]
    fn resolve_run_setup_reuse_rejects_commit_mismatch() {
        let report_dir = write_temp_report_dir();
        let profile_path = write_temp_live_lab_profile(
            "REPORT_DIR=\"/tmp/example\"\nEXIT_TARGET=\"debian@exit\"\nCLIENT_TARGET=\"debian@client\"\nSSH_IDENTITY_FILE=\"$IDENTITY_FILE\"\n",
        );
        let script_path = write_temp_executable("#!/bin/sh\nexit 0\n");

        let mut manifest = build_test_setup_manifest(
            report_dir.as_path(),
            profile_path.as_path(),
            script_path.as_path(),
            None,
        );
        manifest.git.git_commit = "0000000000000000000000000000000000000000".to_string();
        write_setup_only_report_state(report_dir.as_path(), &manifest);

        let err = super::resolve_run_setup_reuse(
            report_dir.as_path(),
            profile_path.as_path(),
            script_path.as_path(),
            "local-head",
            Some("HEAD"),
            true,
        )
        .expect_err("commit mismatch must fail closed");

        assert!(err.contains("git provenance mismatch"));

        let _ = fs::remove_dir_all(report_dir);
        cleanup_temp_path(profile_path.as_path());
        cleanup_temp_path(script_path.as_path());
    }

    #[test]
    fn resolve_run_setup_reuse_rejects_dirty_tree_mismatch() {
        let report_dir = write_temp_report_dir();
        let profile_path = write_temp_live_lab_profile(
            "REPORT_DIR=\"/tmp/example\"\nEXIT_TARGET=\"debian@exit\"\nCLIENT_TARGET=\"debian@client\"\nSSH_IDENTITY_FILE=\"$IDENTITY_FILE\"\n",
        );
        let script_path = write_temp_executable("#!/bin/sh\nexit 0\n");

        let mut manifest = build_test_setup_manifest(
            report_dir.as_path(),
            profile_path.as_path(),
            script_path.as_path(),
            None,
        );
        manifest.git.git_tree_clean = !manifest.git.git_tree_clean;
        write_setup_only_report_state(report_dir.as_path(), &manifest);

        let err = super::resolve_run_setup_reuse(
            report_dir.as_path(),
            profile_path.as_path(),
            script_path.as_path(),
            "local-head",
            Some("HEAD"),
            true,
        )
        .expect_err("dirty-tree mismatch must fail closed");

        assert!(err.contains("git provenance mismatch"));

        let _ = fs::remove_dir_all(report_dir);
        cleanup_temp_path(profile_path.as_path());
        cleanup_temp_path(script_path.as_path());
    }

    #[test]
    fn resolve_run_setup_reuse_rejects_profile_topology_mismatch() {
        let report_dir = write_temp_report_dir();
        let profile_path = write_temp_live_lab_profile(
            "REPORT_DIR=\"/tmp/example\"\nEXIT_TARGET=\"debian@exit\"\nCLIENT_TARGET=\"debian@client\"\nSSH_IDENTITY_FILE=\"$IDENTITY_FILE\"\nENTRY_TARGET=\"debian@entry-a\"\n",
        );
        let script_path = write_temp_executable("#!/bin/sh\nexit 0\n");

        let manifest = build_test_setup_manifest(
            report_dir.as_path(),
            profile_path.as_path(),
            script_path.as_path(),
            None,
        );
        write_setup_only_report_state(report_dir.as_path(), &manifest);
        fs::write(
            profile_path.as_path(),
            fs::read_to_string(profile_path.as_path())
                .expect("profile should read")
                .replace("entry-a", "entry-b"),
        )
        .expect("profile should rewrite");

        let err = super::resolve_run_setup_reuse(
            report_dir.as_path(),
            profile_path.as_path(),
            script_path.as_path(),
            "local-head",
            Some("HEAD"),
            true,
        )
        .expect_err("profile topology mismatch must fail closed");

        assert!(err.contains("profile provenance mismatch"));

        let _ = fs::remove_dir_all(report_dir);
        cleanup_temp_path(profile_path.as_path());
        cleanup_temp_path(script_path.as_path());
    }

    #[test]
    fn resolve_run_setup_reuse_rejects_missing_manifest() {
        let report_dir = write_temp_report_dir();
        let profile_path = write_temp_live_lab_profile(
            "REPORT_DIR=\"/tmp/example\"\nEXIT_TARGET=\"debian@exit\"\nCLIENT_TARGET=\"debian@client\"\nSSH_IDENTITY_FILE=\"$IDENTITY_FILE\"\n",
        );
        let script_path = write_temp_executable("#!/bin/sh\nexit 0\n");

        write_temp_stage_rows(
            report_dir.as_path(),
            &[("validate_baseline_runtime", "pass")],
        );

        let err = super::resolve_run_setup_reuse(
            report_dir.as_path(),
            profile_path.as_path(),
            script_path.as_path(),
            "local-head",
            Some("HEAD"),
            true,
        )
        .expect_err("missing manifest must fail closed");

        assert!(err.contains("read setup manifest failed"));

        let _ = fs::remove_dir_all(report_dir);
        cleanup_temp_path(profile_path.as_path());
        cleanup_temp_path(script_path.as_path());
    }

    #[test]
    fn resolve_run_setup_reuse_rejects_malformed_manifest() {
        let report_dir = write_temp_report_dir();
        let profile_path = write_temp_live_lab_profile(
            "REPORT_DIR=\"/tmp/example\"\nEXIT_TARGET=\"debian@exit\"\nCLIENT_TARGET=\"debian@client\"\nSSH_IDENTITY_FILE=\"$IDENTITY_FILE\"\n",
        );
        let script_path = write_temp_executable("#!/bin/sh\nexit 0\n");

        fs::write(
            report_dir.join(super::SETUP_MANIFEST_RELATIVE_PATH),
            "{not-json\n",
        )
        .expect("manifest should write");

        let err = super::resolve_run_setup_reuse(
            report_dir.as_path(),
            profile_path.as_path(),
            script_path.as_path(),
            "local-head",
            Some("HEAD"),
            true,
        )
        .expect_err("malformed manifest must fail closed");

        assert!(err.contains("parse setup manifest failed"));

        let _ = fs::remove_dir_all(report_dir);
        cleanup_temp_path(profile_path.as_path());
        cleanup_temp_path(script_path.as_path());
    }

    #[test]
    fn resolve_run_setup_reuse_rejects_missing_report_state() {
        let report_dir = write_temp_report_dir();
        let profile_path = write_temp_live_lab_profile(
            "REPORT_DIR=\"/tmp/example\"\nEXIT_TARGET=\"debian@exit\"\nCLIENT_TARGET=\"debian@client\"\nSSH_IDENTITY_FILE=\"$IDENTITY_FILE\"\n",
        );
        let script_path = write_temp_executable("#!/bin/sh\nexit 0\n");

        let manifest = build_test_setup_manifest(
            report_dir.as_path(),
            profile_path.as_path(),
            script_path.as_path(),
            None,
        );
        super::write_setup_manifest(report_dir.as_path(), &manifest)
            .expect("manifest should write");
        write_temp_stage_rows(
            report_dir.as_path(),
            &[("validate_baseline_runtime", "pass")],
        );

        let err = super::resolve_run_setup_reuse(
            report_dir.as_path(),
            profile_path.as_path(),
            script_path.as_path(),
            "local-head",
            Some("HEAD"),
            true,
        )
        .expect_err("missing report state must fail closed");

        assert!(err.contains("read report state failed"));

        let _ = fs::remove_dir_all(report_dir);
        cleanup_temp_path(profile_path.as_path());
        cleanup_temp_path(script_path.as_path());
    }

    #[test]
    fn resolve_run_setup_reuse_rejects_prior_run_state() {
        let report_dir = write_temp_report_dir();
        let profile_path = write_temp_live_lab_profile(
            "REPORT_DIR=\"/tmp/example\"\nEXIT_TARGET=\"debian@exit\"\nCLIENT_TARGET=\"debian@client\"\nSSH_IDENTITY_FILE=\"$IDENTITY_FILE\"\n",
        );
        let script_path = write_temp_executable("#!/bin/sh\nexit 0\n");

        let manifest = build_test_setup_manifest(
            report_dir.as_path(),
            profile_path.as_path(),
            script_path.as_path(),
            None,
        );
        write_setup_only_report_state(report_dir.as_path(), &manifest);
        let run_provenance = super::build_run_provenance(
            profile_path.as_path(),
            script_path.as_path(),
            "local-head",
            Some("HEAD"),
            &super::LiveLabRunModeFlags {
                dry_run: false,
                skip_setup: true,
                skip_gates: false,
                skip_soak: false,
                skip_cross_network: false,
            },
        )
        .expect("run provenance should build");
        super::update_report_state_after_run(
            report_dir.as_path(),
            run_provenance,
            false,
            false,
            false,
        )
        .expect("run state should write");

        let err = super::resolve_run_setup_reuse(
            report_dir.as_path(),
            profile_path.as_path(),
            script_path.as_path(),
            "local-head",
            Some("HEAD"),
            true,
        )
        .expect_err("prior run state must fail closed");

        assert!(err.contains("already contains run provenance"));

        let _ = fs::remove_dir_all(report_dir);
        cleanup_temp_path(profile_path.as_path());
        cleanup_temp_path(script_path.as_path());
    }

    #[test]
    fn ensure_report_dir_fresh_rejects_non_empty_directory() {
        let report_dir = write_temp_report_dir();
        fs::write(report_dir.join("orchestration.log"), "occupied\n")
            .expect("occupied marker should write");

        let err =
            super::ensure_report_dir_fresh(report_dir.as_path(), "vm-lab-orchestrate-live-lab")
                .expect_err("non-empty report dir must fail closed");

        assert!(err.contains("refuses to reuse non-empty report dir"));

        let _ = fs::remove_dir_all(report_dir);
    }

    #[test]
    fn build_release_gate_completeness_report_marks_subset_runs_not_requested() {
        let records = vec![
            LiveLabStageRecord {
                name: "live_role_switch_matrix".to_string(),
                severity: "hard".to_string(),
                status: "pass".to_string(),
                rc: "0".to_string(),
                log_path: PathBuf::from("/tmp/live_role_switch_matrix.log"),
                description: "role switch".to_string(),
            },
            LiveLabStageRecord {
                name: "live_two_hop".to_string(),
                severity: "hard".to_string(),
                status: "pass".to_string(),
                rc: "0".to_string(),
                log_path: PathBuf::from("/tmp/live_two_hop.log"),
                description: "two hop".to_string(),
            },
        ];

        let report = super::build_release_gate_completeness_report(&records, false);

        assert!(!report.requested);
        assert_eq!(report.status, "not_requested");
        assert!(report.missing_or_non_pass_stages.is_empty());
        assert_eq!(report.observed_pass_stages.len(), 2);
    }

    #[test]
    fn write_release_gate_completeness_writes_incomplete_requested_artifact() {
        let report_dir = write_temp_report_dir();
        let report = super::build_release_gate_completeness_report(
            &[LiveLabStageRecord {
                name: "live_role_switch_matrix".to_string(),
                severity: "hard".to_string(),
                status: "pass".to_string(),
                rc: "0".to_string(),
                log_path: PathBuf::from("/tmp/live_role_switch_matrix.log"),
                description: "role switch".to_string(),
            }],
            true,
        );

        super::write_release_gate_completeness(report_dir.as_path(), &report)
            .expect("release-gate completeness should write");

        let artifact_path = report_dir.join(super::RELEASE_GATE_COMPLETENESS_RELATIVE_PATH);
        let parsed: serde_json::Value = serde_json::from_slice(
            &fs::read(&artifact_path).expect("release-gate completeness should read"),
        )
        .expect("artifact should parse");

        assert_eq!(parsed["requested"].as_bool(), Some(true));
        assert_eq!(parsed["status"].as_str(), Some("incomplete"));
        assert!(
            parsed["missing_or_non_pass_stages"]
                .as_array()
                .expect("missing stage array should exist")
                .iter()
                .any(|value| value.as_str() == Some("cross_network_nat_matrix"))
        );

        let _ = fs::remove_dir_all(report_dir);
    }

    #[test]
    fn build_release_gate_completeness_report_marks_complete_when_all_required_stages_pass() {
        let records = super::FULL_RELEASE_GATE_REQUIRED_STAGES
            .iter()
            .map(|stage| LiveLabStageRecord {
                name: (*stage).to_string(),
                severity: "hard".to_string(),
                status: "pass".to_string(),
                rc: "0".to_string(),
                log_path: PathBuf::from(format!("/tmp/{stage}.log")),
                description: format!("{stage} stage"),
            })
            .collect::<Vec<_>>();

        let report = super::build_release_gate_completeness_report(&records, true);

        assert!(report.requested);
        assert_eq!(report.status, "complete");
        assert!(report.missing_or_non_pass_stages.is_empty());
        assert_eq!(
            report.observed_pass_stages.len(),
            super::FULL_RELEASE_GATE_REQUIRED_STAGES.len()
        );
    }
}
