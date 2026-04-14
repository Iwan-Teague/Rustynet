#![forbid(unsafe_code)]

mod env_file;
mod live_lab_results;
mod ops_cross_network_reports;
mod ops_e2e;
mod ops_fresh_install_os_matrix;
mod ops_install_systemd;
mod ops_live_lab_failure_digest;
mod ops_live_lab_orchestrator;
mod ops_network_discovery;
mod ops_peer_store;
mod ops_phase1;
mod ops_phase9;
mod ops_write_daemon_env;
mod vm_lab;

use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::fs;
use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::env_file::{format_env_assignment, parse_env_value};
use ed25519_dalek::{Signer, SigningKey};
use nix::unistd::{Gid, Group, Uid, User, chown};
use rand::{TryRngCore, rngs::OsRng};
use rustynet_control::membership::{
    MembershipApprover, MembershipApproverRole, MembershipApproverStatus, MembershipNode,
    MembershipNodeStatus, MembershipOperation, MembershipReplayCache, MembershipUpdateRecord,
    SignedMembershipUpdate, append_membership_log_entry, apply_signed_update, decode_signed_update,
    decode_update_record, encode_signed_update, encode_update_record, load_membership_log,
    load_membership_snapshot, persist_membership_snapshot, replay_membership_snapshot_and_log,
    sign_update_record, write_membership_audit_log,
};
use rustynet_control::{
    AutoTunnelBundleRequest, ControlPlaneCore, EndpointHintBundleRequest, EndpointHintCandidate,
    EndpointHintCandidateType, NodeMetadata,
};
use rustynet_crypto::{
    KeyCustodyPermissionPolicy, read_encrypted_key_file, write_encrypted_key_file,
};
use rustynet_dns_zone::{
    canonicalize_dns_relative_name, canonicalize_dns_zone_name, parse_dns_zone_verifying_key,
    parse_signed_dns_zone_bundle_wire, verify_signed_dns_zone_bundle as verify_dns_zone_bundle,
};
use rustynet_local_security::{
    validate_owner_only_socket, validate_root_managed_shared_runtime_socket,
};
use rustynet_policy::{PolicyRule, PolicySet, Protocol, RuleAction};
use rustynetd::daemon::{
    DEFAULT_AUTO_TUNNEL_MAX_AGE_SECS, DEFAULT_DNS_RESOLVER_BIND_ADDR, DEFAULT_DNS_ZONE_NAME,
    DEFAULT_MEMBERSHIP_LOG_PATH, DEFAULT_MEMBERSHIP_SNAPSHOT_PATH, DEFAULT_SOCKET_PATH,
    DEFAULT_TRAVERSAL_BUNDLE_PATH, DEFAULT_TRAVERSAL_MAX_AGE_SECS,
    DEFAULT_TRAVERSAL_VERIFIER_KEY_PATH, DEFAULT_TRAVERSAL_WATERMARK_PATH,
    DEFAULT_TRUST_VERIFIER_KEY_PATH, DEFAULT_WG_ENCRYPTED_PRIVATE_KEY_PATH, DEFAULT_WG_INTERFACE,
    DEFAULT_WG_KEY_PASSPHRASE_PATH, DEFAULT_WG_PUBLIC_KEY_PATH,
    DEFAULT_WG_RUNTIME_PRIVATE_KEY_PATH, verify_signed_assignment_state_artifact,
    verify_signed_traversal_state_artifact, verify_signed_trust_state_artifact,
};
use rustynetd::ipc::{IpcCommand, IpcResponse, validate_cidr};
use rustynetd::key_material::{
    initialize_encrypted_key_material, migrate_existing_private_key_material,
    read_passphrase_file_explicit, remove_file_if_present, store_passphrase_in_os_secure_store,
};
use serde_json::{Value, json};
use zeroize::{Zeroize, Zeroizing};

const DEFAULT_TRUST_MAX_AGE_SECS: u64 = 300;
const DEFAULT_SIGNED_STATE_MAX_CLOCK_SKEW_SECS: u64 = 90;
const LOCAL_TRAVERSAL_REFRESH_TTL_SECS: u64 = 120;
const LOCAL_TRAVERSAL_CONVERGENCE_REFRESH_INTERVAL_SECS: u64 = 10;
const PINNED_RUNTIME_RUSTYNET_BIN: &str = "/usr/local/bin/rustynet";
const DNS_ZONE_RECORDS_MANIFEST_MAX_BYTES: usize = 256 * 1024;
const DNS_ZONE_RECORDS_MANIFEST_MAX_LINES: usize = 16_384;
const DNS_ZONE_RECORDS_MANIFEST_MAX_LINE_BYTES: usize = 4_096;
const DNS_ZONE_RECORDS_MANIFEST_MAX_KEY_BYTES: usize = 128;
const DNS_ZONE_RECORDS_MANIFEST_MAX_VALUE_BYTES: usize = 1_536;
const DNS_ZONE_RECORDS_MANIFEST_MAX_KEY_DEPTH: usize = 5;
const DNS_ZONE_RECORDS_MANIFEST_MAX_RECORD_COUNT: usize = 1_024;
const DNS_ZONE_RECORDS_MANIFEST_MAX_ALIAS_COUNT: usize = 8;

fn fill_os_random_bytes(bytes: &mut [u8], label: &str) -> Result<(), String> {
    OsRng
        .try_fill_bytes(bytes)
        .map_err(|err| format!("os randomness unavailable for {label}: {err}"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CliCommand {
    Status,
    Login,
    Netcheck,
    StateRefresh,
    OperatorMenu,
    ExitNodeSelect(String),
    ExitNodeOff,
    LanAccessOn,
    LanAccessOff,
    DnsInspect,
    DnsZoneIssue(Box<DnsZoneIssueCommand>),
    DnsZoneVerify {
        bundle_path: PathBuf,
        verifier_key_path: PathBuf,
        expected_zone_name: Option<String>,
        expected_subject_node_id: Option<String>,
    },
    RouteAdvertise(String),
    Traversal(Box<TraversalCommand>),
    KeyRotate,
    KeyRevoke,
    Assignment(Box<AssignmentCommand>),
    Membership(Box<MembershipCommand>),
    Trust(Box<TrustCommand>),
    Ops(Box<OpsCommand>),
    Help,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TraversalCommand {
    Issue(Box<TraversalIssueCommand>),
    Verify(TraversalVerifyCommand),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MembershipCommand {
    Status {
        paths: MembershipPaths,
    },
    Propose {
        config: ProposalConfig,
    },
    SignUpdate {
        record_path: PathBuf,
        approver_id: String,
        signing_key_path: PathBuf,
        signing_key_passphrase_path: PathBuf,
        output_path: PathBuf,
        merge_from: Option<PathBuf>,
    },
    VerifyUpdate {
        signed_update_path: PathBuf,
        paths: MembershipPaths,
        now_unix: u64,
        dry_run: bool,
    },
    ApplyUpdate {
        signed_update_path: PathBuf,
        paths: MembershipPaths,
        now_unix: u64,
        dry_run: bool,
    },
    VerifyLog {
        paths: MembershipPaths,
        now_unix: u64,
        audit_output_path: PathBuf,
    },
    GenerateEvidence {
        paths: MembershipPaths,
        now_unix: u64,
        output_dir: PathBuf,
        environment: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AssignmentCommand {
    Issue(Box<AssignmentIssueCommand>),
    Verify(AssignmentVerifyCommand),
    InitSigningSecret {
        output_path: PathBuf,
        signing_secret_passphrase_path: PathBuf,
        length_bytes: usize,
        force: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AssignmentIssueCommand {
    signing_secret_path: PathBuf,
    signing_secret_passphrase_path: PathBuf,
    target_node_id: String,
    output_path: PathBuf,
    verifier_key_output_path: Option<PathBuf>,
    nodes: Vec<AssignmentNodeSpec>,
    allow_pairs: Vec<AssignmentAllowPair>,
    mesh_cidr: String,
    exit_node_id: Option<String>,
    lan_routes: Vec<String>,
    generated_at_unix: u64,
    ttl_secs: u64,
    nonce: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AssignmentVerifyCommand {
    bundle_path: PathBuf,
    verifier_key_path: PathBuf,
    watermark_path: PathBuf,
    expected_node_id: Option<String>,
    max_age_secs: u64,
    max_clock_skew_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DnsZoneIssueCommand {
    signing_secret_path: PathBuf,
    signing_secret_passphrase_path: PathBuf,
    subject_node_id: String,
    output_path: PathBuf,
    verifier_key_output_path: Option<PathBuf>,
    nodes: Vec<AssignmentNodeSpec>,
    allow_pairs: Vec<AssignmentAllowPair>,
    zone_name: String,
    records_path: PathBuf,
    generated_at_unix: u64,
    ttl_secs: u64,
    nonce: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DnsZoneRecordSpec {
    label: String,
    target_node_id: String,
    ttl_secs: u64,
    aliases: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TraversalIssueCommand {
    signing_secret_path: PathBuf,
    signing_secret_passphrase_path: PathBuf,
    source_node_id: String,
    target_node_id: String,
    output_path: PathBuf,
    verifier_key_output_path: Option<PathBuf>,
    nodes: Vec<AssignmentNodeSpec>,
    allow_pairs: Vec<AssignmentAllowPair>,
    candidates: Vec<TraversalCandidateSpec>,
    generated_at_unix: u64,
    ttl_secs: u64,
    nonce: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TraversalVerifyCommand {
    bundle_path: PathBuf,
    verifier_key_path: PathBuf,
    watermark_path: PathBuf,
    expected_source_node_id: Option<String>,
    max_age_secs: u64,
    max_clock_skew_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TraversalCandidateSpec {
    candidate_type: EndpointHintCandidateType,
    endpoint: String,
    relay_id: Option<String>,
    priority: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TrustCommand {
    Keygen {
        signing_key_path: PathBuf,
        signing_key_passphrase_path: PathBuf,
        verifier_key_output_path: PathBuf,
        force: bool,
    },
    ExportVerifierKey {
        signing_key_path: PathBuf,
        signing_key_passphrase_path: PathBuf,
        output_path: PathBuf,
    },
    Issue {
        signing_key_path: PathBuf,
        signing_key_passphrase_path: PathBuf,
        output_path: PathBuf,
        updated_at_unix: u64,
        nonce: u64,
    },
    Verify {
        evidence_path: PathBuf,
        verifier_key_path: PathBuf,
        watermark_path: PathBuf,
        max_age_secs: u64,
        max_clock_skew_secs: u64,
    },
}

mod ops_ci_release_perf;

#[derive(Debug, Clone, PartialEq, Eq)]
enum OpsCommand {
    VerifyRuntimeBinaryCustody,
    WriteDaemonEnv {
        config_path: PathBuf,
        egress_interface: Option<String>,
    },
    RefreshTrust,
    RefreshSignedTrust,
    BootstrapTunnelCustody,
    RefreshAssignment,
    StateRefreshIfSocketPresent,
    CollectPhase1MeasuredInput,
    RunPhase1Baseline,
    PrepareAdvisoryDb {
        config: ops_ci_release_perf::PrepareAdvisoryDbConfig,
    },
    RunPhase1CiGates,
    RunPhase9CiGates,
    RunPhase10CiGates,
    RunMembershipCiGates,
    RunSupplyChainIntegrityGates,
    RunSecurityRegressionGates,
    RunActiveNetworkSecurityGates,
    RunPhase10Hp2Gates,
    GenerateReleaseSbom,
    CreateReleaseProvenance {
        config: ops_ci_release_perf::CreateReleaseProvenanceConfig,
    },
    RunPhase3Baseline,
    RunFuzzSmoke,
    CheckNoUnsafeRustSources {
        config: ops_phase1::CheckNoUnsafeRustSourcesConfig,
    },
    CheckDependencyExceptions {
        config: ops_phase1::CheckDependencyExceptionsConfig,
    },
    CheckPerfRegression {
        config: ops_phase1::CheckPerfRegressionConfig,
    },
    CheckSecretsHygiene {
        config: ops_phase1::CheckSecretsHygieneConfig,
    },
    CollectPhase9RawEvidence,
    GeneratePhase9Artifacts,
    VerifyPhase9Readiness,
    VerifyPhase9Evidence,
    GeneratePhase10Artifacts,
    VerifyPhase10Readiness,
    VerifyPhase10Provenance,
    WritePhase10Hp2TraversalReports {
        config: ops_phase9::WritePhase10Hp2TraversalReportsConfig,
    },
    VerifyPhase6PlatformReadiness,
    VerifyPhase6ParityEvidence,
    VerifyRequiredTestOutput {
        config: ops_phase9::VerifyRequiredTestOutputConfig,
    },
    GenerateCrossNetworkRemoteExitReport {
        config: ops_cross_network_reports::GenerateCrossNetworkRemoteExitReportConfig,
    },
    ValidateCrossNetworkRemoteExitReports {
        config: ops_cross_network_reports::ValidateCrossNetworkRemoteExitReportsConfig,
    },
    ValidateCrossNetworkNatMatrix {
        config: ops_cross_network_reports::ValidateCrossNetworkNatMatrixConfig,
    },
    ReadCrossNetworkReportFields {
        config: ops_cross_network_reports::ReadCrossNetworkReportFieldsConfig,
    },
    ClassifyCrossNetworkTopology {
        config: ops_cross_network_reports::ClassifyCrossNetworkTopologyConfig,
    },
    ChooseCrossNetworkRoamAlias {
        config: ops_cross_network_reports::ChooseCrossNetworkRoamAliasConfig,
    },
    ValidateIpv4Address {
        config: ops_cross_network_reports::ValidateIpv4AddressConfig,
    },
    WriteCrossNetworkSoakMonitorSummary {
        config: ops_cross_network_reports::WriteCrossNetworkSoakMonitorSummaryConfig,
    },
    CheckLocalFileMode {
        config: ops_live_lab_orchestrator::CheckLocalFileModeConfig,
    },
    RedactForensicsText,
    WriteCrossNetworkForensicsManifest {
        config: ops_live_lab_orchestrator::WriteCrossNetworkForensicsManifestConfig,
    },
    WriteLiveLabStageArtifactIndex {
        config: ops_live_lab_orchestrator::WriteLiveLabStageArtifactIndexConfig,
    },
    Sha256File {
        config: ops_live_lab_orchestrator::Sha256FileConfig,
    },
    ValidateCrossNetworkForensicsBundle {
        config: ops_live_lab_orchestrator::ValidateCrossNetworkForensicsBundleConfig,
    },
    WriteCrossNetworkPreflightReport {
        config: ops_live_lab_orchestrator::WriteCrossNetworkPreflightReportConfig,
    },
    WriteLiveLinuxRebootRecoveryReport {
        config: ops_live_lab_orchestrator::WriteLiveLinuxRebootRecoveryReportConfig,
    },
    WriteLiveLinuxLabRunSummary {
        config: ops_live_lab_orchestrator::WriteLiveLinuxLabRunSummaryConfig,
    },
    ScanIpv4PortRange {
        config: ops_live_lab_orchestrator::ScanIpv4PortRangeConfig,
    },
    UpdateRoleSwitchHostResult {
        config: ops_live_lab_orchestrator::UpdateRoleSwitchHostResultConfig,
    },
    WriteRoleSwitchMatrixReport {
        config: ops_live_lab_orchestrator::WriteRoleSwitchMatrixReportConfig,
    },
    WriteLiveLinuxServerIpBypassReport {
        config: ops_live_lab_orchestrator::WriteLiveLinuxServerIpBypassReportConfig,
    },
    WriteLiveLinuxControlSurfaceReport {
        config: ops_live_lab_orchestrator::WriteLiveLinuxControlSurfaceReportConfig,
    },
    RewriteAssignmentPeerEndpointIp {
        config: ops_live_lab_orchestrator::RewriteAssignmentPeerEndpointIpConfig,
    },
    RewriteAssignmentMeshCidr {
        config: ops_live_lab_orchestrator::RewriteAssignmentMeshCidrConfig,
    },
    WriteLiveLinuxEndpointHijackReport {
        config: ops_live_lab_orchestrator::WriteLiveLinuxEndpointHijackReportConfig,
    },
    WriteRealWireguardExitnodeE2eReport {
        config: ops_live_lab_orchestrator::WriteRealWireguardExitnodeE2eReportConfig,
    },
    WriteRealWireguardNoLeakUnderLoadReport {
        config: ops_live_lab_orchestrator::WriteRealWireguardNoLeakUnderLoadReportConfig,
    },
    VerifyNoLeakDataplaneReport {
        config: ops_live_lab_orchestrator::VerifyNoLeakDataplaneReportConfig,
    },
    E2eDnsQuery {
        config: ops_live_lab_orchestrator::E2eDnsQueryConfig,
    },
    E2eHttpProbeServer {
        config: ops_live_lab_orchestrator::E2eHttpProbeServerConfig,
    },
    E2eHttpProbeClient {
        config: ops_live_lab_orchestrator::E2eHttpProbeClientConfig,
    },
    ReadJsonField {
        config: ops_live_lab_orchestrator::ReadJsonFieldConfig,
    },
    ExtractManagedDnsExpectedIp {
        config: ops_live_lab_orchestrator::ExtractManagedDnsExpectedIpConfig,
    },
    WriteActiveNetworkSignedStateTamperReport {
        config: ops_live_lab_orchestrator::WriteActiveNetworkSignedStateTamperReportConfig,
    },
    WriteActiveNetworkRoguePathHijackReport {
        config: ops_live_lab_orchestrator::WriteActiveNetworkRoguePathHijackReportConfig,
    },
    ValidateNetworkDiscoveryBundle {
        config: ops_network_discovery::ValidateNetworkDiscoveryBundleConfig,
    },
    GenerateLiveLinuxLabFailureDigest {
        config: ops_live_lab_failure_digest::GenerateLiveLinuxLabFailureDigestConfig,
    },
    VmLabList {
        config: vm_lab::VmLabListConfig,
    },
    VmLabDiscoverLocalUtm {
        config: vm_lab::VmLabDiscoverLocalUtmConfig,
    },
    VmLabDiscoverLocalUtmSummary {
        config: vm_lab::VmLabDiscoverLocalUtmConfig,
    },
    VmLabStart {
        config: vm_lab::VmLabStartConfig,
    },
    VmLabSyncRepo {
        config: vm_lab::VmLabSyncRepoConfig,
    },
    VmLabSyncBootstrap {
        config: vm_lab::VmLabSyncBootstrapConfig,
    },
    VmLabRun {
        config: vm_lab::VmLabExecConfig,
    },
    VmLabBootstrap {
        config: vm_lab::VmLabExecConfig,
    },
    VmLabWriteLiveLabProfile {
        config: vm_lab::VmLabWriteLiveLabProfileConfig,
    },
    VmLabSetupLiveLab {
        config: vm_lab::VmLabSetupLiveLabConfig,
    },
    VmLabOrchestrateLiveLab {
        config: vm_lab::VmLabOrchestrateLiveLabConfig,
    },
    VmLabValidateLiveLabProfile {
        config: vm_lab::VmLabValidateLiveLabProfileConfig,
    },
    VmLabDiagnoseLiveLabFailure {
        config: vm_lab::VmLabDiagnoseLiveLabFailureConfig,
    },
    VmLabDiffLiveLabRuns {
        config: vm_lab::VmLabDiffLiveLabRunsConfig,
    },
    VmLabIterateLiveLab {
        config: vm_lab::VmLabIterateLiveLabConfig,
    },
    VmLabRunLiveLab {
        config: vm_lab::VmLabRunLiveLabConfig,
    },
    VmLabCheckKnownHosts {
        config: vm_lab::VmLabCheckKnownHostsConfig,
    },
    VmLabPreflight {
        config: vm_lab::VmLabPreflightConfig,
    },
    VmLabStatus {
        config: vm_lab::VmLabStatusConfig,
    },
    VmLabStop {
        config: vm_lab::VmLabStopConfig,
    },
    VmLabRestart {
        config: vm_lab::VmLabRestartConfig,
    },
    VmLabCollectArtifacts {
        config: vm_lab::VmLabCollectArtifactsConfig,
    },
    VmLabWriteTopology {
        config: vm_lab::VmLabWriteTopologyConfig,
    },
    VmLabIssueAndDistributeState {
        config: vm_lab::VmLabIssueDistributeStateConfig,
    },
    VmLabRunSuite {
        config: vm_lab::VmLabRunSuiteConfig,
    },
    VmLabBootstrapPhase {
        config: vm_lab::VmLabBootstrapPhaseConfig,
    },
    RebindLinuxFreshInstallOsMatrixInputs {
        config: ops_fresh_install_os_matrix::RebindLinuxFreshInstallOsMatrixInputsConfig,
    },
    GenerateLinuxFreshInstallOsMatrixReport {
        config: ops_fresh_install_os_matrix::GenerateLinuxFreshInstallOsMatrixReportConfig,
    },
    VerifyLinuxFreshInstallOsMatrixReadiness {
        config: ops_fresh_install_os_matrix::VerifyLinuxFreshInstallOsMatrixReadinessConfig,
    },
    WriteFreshInstallOsMatrixReadinessFixtures {
        config: ops_fresh_install_os_matrix::WriteFreshInstallOsMatrixReadinessFixturesConfig,
    },
    WriteUnsignedReleaseProvenance {
        config: ops_phase9::WriteUnsignedReleaseProvenanceConfig,
    },
    SignReleaseArtifact,
    VerifyReleaseArtifact,
    CollectPlatformProbe,
    GeneratePlatformParityReport,
    CollectPlatformParityBundle,
    InstallSystemd,
    PrepareSystemDirs,
    RestartRuntimeService,
    StopRuntimeService,
    ShowRuntimeServiceStatus,
    StartAssignmentRefreshService,
    CheckAssignmentRefreshAvailability,
    InstallTrustMaterial {
        verifier_source: PathBuf,
        trust_source: PathBuf,
        verifier_dest: PathBuf,
        trust_dest: PathBuf,
        daemon_group: String,
    },
    ApplyManagedDnsRouting,
    ClearManagedDnsRouting,
    DisconnectCleanup,
    ApplyBlindExitLockdown,
    InitMembership,
    SecureRemove {
        path: PathBuf,
    },
    EnsureSigningPassphraseMaterial,
    EnsureLocalTrustMaterial {
        signing_key_passphrase_path: PathBuf,
    },
    MaterializeSigningPassphrase {
        output_path: PathBuf,
    },
    MaterializeSigningPassphraseTemp,
    SetAssignmentRefreshExitNode {
        env_path: PathBuf,
        exit_node_id: Option<String>,
    },
    ForceLocalAssignmentRefreshNow,
    ApplyLanAccessCoupling {
        enable: bool,
        lan_routes: Vec<String>,
        assignment_refresh_env_path: PathBuf,
    },
    ApplyRoleCoupling {
        target_role: String,
        preferred_exit_node_id: Option<String>,
        enable_exit_advertise: bool,
        assignment_refresh_env_path: PathBuf,
        skip_client_exit_route_convergence_wait: bool,
    },
    PeerStoreValidate {
        config_dir: PathBuf,
        peers_file: PathBuf,
    },
    PeerStoreList {
        config_dir: PathBuf,
        peers_file: PathBuf,
        role: Option<String>,
        node_id: Option<String>,
    },
    RunDebianTwoNodeE2e {
        config: ops_e2e::DebianTwoNodeE2eConfig,
    },
    E2eBootstrapHost {
        role: String,
        node_id: String,
        network_id: String,
        src_dir: PathBuf,
        ssh_allow_cidrs: String,
        skip_apt: bool,
    },
    E2eEnforceHost {
        role: String,
        node_id: String,
        src_dir: PathBuf,
        ssh_allow_cidrs: String,
    },
    E2eMembershipAdd {
        client_node_id: String,
        client_pubkey_hex: String,
        owner_approver_id: String,
    },
    E2eIssueAssignments {
        exit_node_id: String,
        client_node_id: String,
        exit_endpoint: String,
        client_endpoint: String,
        exit_pubkey_hex: String,
        client_pubkey_hex: String,
        artifact_dir: Option<PathBuf>,
    },
    E2eIssueAssignmentBundlesFromEnv {
        config: ops_e2e::E2eIssueAssignmentBundlesFromEnvConfig,
    },
    E2eIssueTraversalBundlesFromEnv {
        config: ops_e2e::E2eIssueTraversalBundlesFromEnvConfig,
    },
    E2eIssueDnsZoneBundlesFromEnv {
        config: ops_e2e::E2eIssueDnsZoneBundlesFromEnvConfig,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AssignmentNodeSpec {
    node_id: String,
    endpoint: String,
    public_key: [u8; 32],
    owner: String,
    hostname: String,
    os: String,
    tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AssignmentAllowPair {
    source_node_id: String,
    destination_node_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MembershipPaths {
    snapshot_path: PathBuf,
    log_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProposalConfig {
    paths: MembershipPaths,
    output_path: PathBuf,
    operation: MembershipOperation,
    target: String,
    update_id: String,
    reason_code: String,
    policy_context: Option<String>,
    expires_in_secs: u64,
}

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let command = parse_command(&args);
    match execute(command) {
        Ok(output) => println!("{output}"),
        Err(err) => {
            println!("error: {err}");
            std::process::exit(1);
        }
    }
}

fn parse_command(args: &[String]) -> CliCommand {
    match args {
        [cmd] if cmd == "status" => CliCommand::Status,
        [cmd] if cmd == "login" => CliCommand::Login,
        [cmd] if cmd == "netcheck" => CliCommand::Netcheck,
        [cmd, subcmd] if cmd == "state" && subcmd == "refresh" => CliCommand::StateRefresh,
        [cmd, subcmd] if cmd == "operator" && subcmd == "menu" => CliCommand::OperatorMenu,
        [cmd, subcmd, node] if cmd == "exit-node" && subcmd == "select" => {
            CliCommand::ExitNodeSelect(node.clone())
        }
        [cmd, subcmd] if cmd == "exit-node" && subcmd == "off" => CliCommand::ExitNodeOff,
        [cmd, subcmd] if cmd == "lan-access" && subcmd == "on" => CliCommand::LanAccessOn,
        [cmd, subcmd] if cmd == "lan-access" && subcmd == "off" => CliCommand::LanAccessOff,
        [cmd, subcmd] if cmd == "dns" && subcmd == "inspect" => CliCommand::DnsInspect,
        [cmd, subcmd, action, rest @ ..] if cmd == "dns" && subcmd == "zone" => {
            match parse_dns_zone_command(action, rest) {
                Ok(command) => command,
                Err(_) => CliCommand::Help,
            }
        }
        [cmd, rest @ ..] if cmd == "traversal" => match parse_traversal_command(rest) {
            Ok(command) => CliCommand::Traversal(Box::new(command)),
            Err(_) => CliCommand::Help,
        },
        [cmd, subcmd, cidr] if cmd == "route" && subcmd == "advertise" => {
            CliCommand::RouteAdvertise(cidr.clone())
        }
        [cmd, subcmd] if cmd == "key" && subcmd == "rotate" => CliCommand::KeyRotate,
        [cmd, subcmd] if cmd == "key" && subcmd == "revoke" => CliCommand::KeyRevoke,
        [cmd, rest @ ..] if cmd == "assignment" => match parse_assignment_command(rest) {
            Ok(command) => CliCommand::Assignment(Box::new(command)),
            Err(_) => CliCommand::Help,
        },
        [cmd, rest @ ..] if cmd == "membership" => match parse_membership_command(rest) {
            Ok(command) => CliCommand::Membership(Box::new(command)),
            Err(_) => CliCommand::Help,
        },
        [cmd, rest @ ..] if cmd == "trust" => match parse_trust_command(rest) {
            Ok(command) => CliCommand::Trust(Box::new(command)),
            Err(_) => CliCommand::Help,
        },
        [cmd, rest @ ..] if cmd == "ops" => match parse_ops_command(rest) {
            Ok(command) => CliCommand::Ops(Box::new(command)),
            Err(_) => CliCommand::Help,
        },
        _ => CliCommand::Help,
    }
}

fn parse_ops_command(args: &[String]) -> Result<OpsCommand, String> {
    if args.is_empty() {
        return Err("ops subcommand is required".to_string());
    }
    let subcommand = args[0].as_str();
    let parser = match OptionParser::parse(&args[1..]) {
        Ok(parser) => parser,
        Err(err) => {
            if subcommand == "prepare-advisory-db" {
                OptionParser::empty()
            } else {
                return Err(err);
            }
        }
    };
    match subcommand {
        "verify-runtime-binary-custody" => {
            if args.len() != 1 {
                return Err("ops verify-runtime-binary-custody does not accept options".to_string());
            }
            Ok(OpsCommand::VerifyRuntimeBinaryCustody)
        }
        "write-daemon-env" => {
            let config_path = parser.required_path("--config-path")?;
            let egress_interface = parser.value("--egress-interface");
            Ok(OpsCommand::WriteDaemonEnv {
                config_path,
                egress_interface,
            })
        }
        "refresh-trust" => {
            if args.len() != 1 {
                return Err("ops refresh-trust does not accept options".to_string());
            }
            Ok(OpsCommand::RefreshTrust)
        }
        "refresh-signed-trust" => {
            if args.len() != 1 {
                return Err("ops refresh-signed-trust does not accept options".to_string());
            }
            Ok(OpsCommand::RefreshSignedTrust)
        }
        "bootstrap-wireguard-custody" => {
            if args.len() != 1 {
                return Err("ops bootstrap-wireguard-custody does not accept options".to_string());
            }
            Ok(OpsCommand::BootstrapTunnelCustody)
        }
        "refresh-assignment" => {
            if args.len() != 1 {
                return Err("ops refresh-assignment does not accept options".to_string());
            }
            Ok(OpsCommand::RefreshAssignment)
        }
        "state-refresh-if-socket-present" => {
            if args.len() != 1 {
                return Err(
                    "ops state-refresh-if-socket-present does not accept options".to_string(),
                );
            }
            Ok(OpsCommand::StateRefreshIfSocketPresent)
        }
        "collect-phase1-measured-input" => {
            if args.len() != 1 {
                return Err("ops collect-phase1-measured-input does not accept options".to_string());
            }
            Ok(OpsCommand::CollectPhase1MeasuredInput)
        }
        "run-phase1-baseline" => {
            if args.len() != 1 {
                return Err("ops run-phase1-baseline does not accept options".to_string());
            }
            Ok(OpsCommand::RunPhase1Baseline)
        }
        "prepare-advisory-db" => {
            if args.len() != 2 {
                return Err("usage: ops prepare-advisory-db <advisory_db_path>".to_string());
            }
            Ok(OpsCommand::PrepareAdvisoryDb {
                config: ops_ci_release_perf::PrepareAdvisoryDbConfig {
                    target_db: PathBuf::from(args[1].as_str()),
                },
            })
        }
        "run-phase1-ci-gates" => {
            if args.len() != 1 {
                return Err("ops run-phase1-ci-gates does not accept options".to_string());
            }
            Ok(OpsCommand::RunPhase1CiGates)
        }
        "run-phase9-ci-gates" => {
            if args.len() != 1 {
                return Err("ops run-phase9-ci-gates does not accept options".to_string());
            }
            Ok(OpsCommand::RunPhase9CiGates)
        }
        "run-phase10-ci-gates" => {
            if args.len() != 1 {
                return Err("ops run-phase10-ci-gates does not accept options".to_string());
            }
            Ok(OpsCommand::RunPhase10CiGates)
        }
        "run-membership-ci-gates" => {
            if args.len() != 1 {
                return Err("ops run-membership-ci-gates does not accept options".to_string());
            }
            Ok(OpsCommand::RunMembershipCiGates)
        }
        "run-supply-chain-integrity-gates" => {
            if args.len() != 1 {
                return Err(
                    "ops run-supply-chain-integrity-gates does not accept options".to_string(),
                );
            }
            Ok(OpsCommand::RunSupplyChainIntegrityGates)
        }
        "run-security-regression-gates" => {
            if args.len() != 1 {
                return Err("ops run-security-regression-gates does not accept options".to_string());
            }
            Ok(OpsCommand::RunSecurityRegressionGates)
        }
        "run-active-network-security-gates" => {
            if args.len() != 1 {
                return Err(
                    "ops run-active-network-security-gates does not accept options".to_string(),
                );
            }
            Ok(OpsCommand::RunActiveNetworkSecurityGates)
        }
        "run-phase10-hp2-gates" => {
            if args.len() != 1 {
                return Err("ops run-phase10-hp2-gates does not accept options".to_string());
            }
            Ok(OpsCommand::RunPhase10Hp2Gates)
        }
        "generate-release-sbom" => {
            if args.len() != 1 {
                return Err("ops generate-release-sbom does not accept options".to_string());
            }
            Ok(OpsCommand::GenerateReleaseSbom)
        }
        "create-release-provenance" => {
            if args.len() != 4 {
                return Err(
                    "usage: ops create-release-provenance <artifact-path> <track> <output-json>"
                        .to_string(),
                );
            }
            Ok(OpsCommand::CreateReleaseProvenance {
                config: ops_ci_release_perf::CreateReleaseProvenanceConfig {
                    artifact_path: PathBuf::from(args[1].as_str()),
                    track: args[2].clone(),
                    output_json: PathBuf::from(args[3].as_str()),
                },
            })
        }
        "run-phase3-baseline" => {
            if args.len() != 1 {
                return Err("ops run-phase3-baseline does not accept options".to_string());
            }
            Ok(OpsCommand::RunPhase3Baseline)
        }
        "run-fuzz-smoke" => {
            if args.len() != 1 {
                return Err("ops run-fuzz-smoke does not accept options".to_string());
            }
            Ok(OpsCommand::RunFuzzSmoke)
        }
        "check-no-unsafe-rust-sources" => Ok(OpsCommand::CheckNoUnsafeRustSources {
            config: ops_phase1::CheckNoUnsafeRustSourcesConfig {
                root: parser
                    .value("--root")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from(ops_phase1::DEFAULT_UNSAFE_SCAN_ROOT_PATH)),
            },
        }),
        "check-dependency-exceptions" => Ok(OpsCommand::CheckDependencyExceptions {
            config: ops_phase1::CheckDependencyExceptionsConfig {
                path: parser
                    .value("--path")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| {
                        PathBuf::from(ops_phase1::DEFAULT_DEPENDENCY_EXCEPTIONS_PATH)
                    }),
            },
        }),
        "check-perf-regression" => Ok(OpsCommand::CheckPerfRegression {
            config: ops_phase1::CheckPerfRegressionConfig {
                phase1_report_path: parser
                    .value("--phase1-report")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| {
                        PathBuf::from(ops_phase1::DEFAULT_PHASE1_PERF_REGRESSION_PHASE1_REPORT_PATH)
                    }),
                phase3_report_path: parser
                    .value("--phase3-report")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| {
                        PathBuf::from(ops_phase1::DEFAULT_PHASE1_PERF_REGRESSION_PHASE3_REPORT_PATH)
                    }),
            },
        }),
        "check-secrets-hygiene" => Ok(OpsCommand::CheckSecretsHygiene {
            config: ops_phase1::CheckSecretsHygieneConfig {
                root: parser
                    .value("--root")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| {
                        PathBuf::from(ops_phase1::DEFAULT_SECRETS_HYGIENE_SCAN_ROOT_PATH)
                    }),
            },
        }),
        "collect-phase9-raw-evidence" => {
            if args.len() != 1 {
                return Err("ops collect-phase9-raw-evidence does not accept options".to_string());
            }
            Ok(OpsCommand::CollectPhase9RawEvidence)
        }
        "generate-phase9-artifacts" => {
            if args.len() != 1 {
                return Err("ops generate-phase9-artifacts does not accept options".to_string());
            }
            Ok(OpsCommand::GeneratePhase9Artifacts)
        }
        "verify-phase9-readiness" => {
            if args.len() != 1 {
                return Err("ops verify-phase9-readiness does not accept options".to_string());
            }
            Ok(OpsCommand::VerifyPhase9Readiness)
        }
        "verify-phase9-evidence" => {
            if args.len() != 1 {
                return Err("ops verify-phase9-evidence does not accept options".to_string());
            }
            Ok(OpsCommand::VerifyPhase9Evidence)
        }
        "generate-phase10-artifacts" => {
            if args.len() != 1 {
                return Err("ops generate-phase10-artifacts does not accept options".to_string());
            }
            Ok(OpsCommand::GeneratePhase10Artifacts)
        }
        "verify-phase10-readiness" => {
            if args.len() != 1 {
                return Err("ops verify-phase10-readiness does not accept options".to_string());
            }
            Ok(OpsCommand::VerifyPhase10Readiness)
        }
        "verify-phase10-provenance" => {
            if args.len() != 1 {
                return Err("ops verify-phase10-provenance does not accept options".to_string());
            }
            Ok(OpsCommand::VerifyPhase10Provenance)
        }
        "write-phase10-hp2-traversal-reports" => Ok(OpsCommand::WritePhase10Hp2TraversalReports {
            config: ops_phase9::WritePhase10Hp2TraversalReportsConfig {
                source_dir: parser.required_path("--source-dir")?,
                environment: parser.required("--environment")?,
                path_selection_log: parser.required_path("--path-selection-log")?,
                probe_security_log: parser.required_path("--probe-security-log")?,
            },
        }),
        "verify-phase6-platform-readiness" => {
            if args.len() != 1 {
                return Err(
                    "ops verify-phase6-platform-readiness does not accept options".to_string(),
                );
            }
            Ok(OpsCommand::VerifyPhase6PlatformReadiness)
        }
        "verify-phase6-parity-evidence" => {
            if args.len() != 1 {
                return Err("ops verify-phase6-parity-evidence does not accept options".to_string());
            }
            Ok(OpsCommand::VerifyPhase6ParityEvidence)
        }
        "verify-required-test-output" => Ok(OpsCommand::VerifyRequiredTestOutput {
            config: ops_phase9::VerifyRequiredTestOutputConfig {
                output_path: parser.required_path("--output")?,
                package: parser.required("--package")?,
                test_filter: parser.required("--test-filter")?,
            },
        }),
        "generate-cross-network-remote-exit-report" => {
            let source_artifacts = collect_repeated_option_values(&args[1..], "--source-artifact")
                .into_iter()
                .map(PathBuf::from)
                .collect::<Vec<_>>();
            let log_artifacts = collect_repeated_option_values(&args[1..], "--log-artifact")
                .into_iter()
                .map(PathBuf::from)
                .collect::<Vec<_>>();
            let check_overrides = collect_repeated_option_values(&args[1..], "--check");
            Ok(OpsCommand::GenerateCrossNetworkRemoteExitReport {
                config: ops_cross_network_reports::GenerateCrossNetworkRemoteExitReportConfig {
                    suite: parser.required("--suite")?,
                    report_path: parser.required_path("--report-path")?,
                    log_path: parser.required_path("--log-path")?,
                    status: parser.required("--status")?,
                    failure_summary: parser.value("--failure-summary").unwrap_or_default(),
                    environment: parser
                        .value("--environment")
                        .unwrap_or_else(|| "live_linux_skeleton".to_string()),
                    implementation_state: parser
                        .value("--implementation-state")
                        .unwrap_or_else(|| "not_implemented".to_string()),
                    source_artifacts,
                    log_artifacts,
                    client_host: parser.value("--client-host"),
                    exit_host: parser.value("--exit-host"),
                    relay_host: parser.value("--relay-host"),
                    probe_host: parser.value("--probe-host"),
                    client_network_id: parser.value("--client-network-id"),
                    exit_network_id: parser.value("--exit-network-id"),
                    relay_network_id: parser.value("--relay-network-id"),
                    nat_profile: parser
                        .value("--nat-profile")
                        .unwrap_or_else(|| "baseline_lan".to_string()),
                    impairment_profile: parser
                        .value("--impairment-profile")
                        .unwrap_or_else(|| "none".to_string()),
                    check_overrides,
                    path_status_line: parser.value("--path-status-line"),
                    path_evidence_report: parser.optional_path("--path-evidence-report"),
                },
            })
        }
        "validate-cross-network-remote-exit-reports" => {
            let reports = parser
                .value("--reports")
                .map(split_csv)
                .unwrap_or_default()
                .into_iter()
                .map(PathBuf::from)
                .collect::<Vec<_>>();
            Ok(OpsCommand::ValidateCrossNetworkRemoteExitReports {
                config: ops_cross_network_reports::ValidateCrossNetworkRemoteExitReportsConfig {
                    reports,
                    artifact_dir: parser.optional_path("--artifact-dir"),
                    output: parser.optional_path("--output"),
                    max_evidence_age_seconds: parser.parse_u64_or_default(
                        "--max-evidence-age-seconds",
                        ops_cross_network_reports::default_max_evidence_age_seconds(),
                    )?,
                    expected_git_commit: parser.value("--expected-git-commit"),
                    require_pass_status: parser.has_flag("--require-pass-status"),
                },
            })
        }
        "validate-cross-network-nat-matrix" => {
            let reports = parser
                .value("--reports")
                .map(split_csv)
                .unwrap_or_default()
                .into_iter()
                .map(PathBuf::from)
                .collect::<Vec<_>>();
            let required_nat_profiles = parser
                .value("--required-nat-profiles")
                .map(split_csv)
                .unwrap_or_else(|| split_csv("baseline_lan".to_string()));
            Ok(OpsCommand::ValidateCrossNetworkNatMatrix {
                config: ops_cross_network_reports::ValidateCrossNetworkNatMatrixConfig {
                    reports,
                    artifact_dir: parser.optional_path("--artifact-dir"),
                    required_nat_profiles,
                    max_evidence_age_seconds: parser.parse_u64_or_default(
                        "--max-evidence-age-seconds",
                        ops_cross_network_reports::default_max_evidence_age_seconds(),
                    )?,
                    expected_git_commit: parser.value("--expected-git-commit"),
                    require_pass_status: parser.has_flag("--require-pass-status"),
                    output: parser.optional_path("--output"),
                },
            })
        }
        "read-cross-network-report-fields" => {
            let checks = collect_repeated_option_values(&args[1..], "--check");
            let network_fields = collect_repeated_option_values(&args[1..], "--network-field");
            Ok(OpsCommand::ReadCrossNetworkReportFields {
                config: ops_cross_network_reports::ReadCrossNetworkReportFieldsConfig {
                    report_path: parser.required_path("--report-path")?,
                    include_status: parser.has_flag("--include-status"),
                    checks,
                    network_fields,
                    default_value: parser
                        .value("--default-value")
                        .unwrap_or_else(|| "fail".to_string()),
                },
            })
        }
        "classify-cross-network-topology" => {
            let ipv4_prefix = parser
                .value("--ipv4-prefix")
                .map(|value| {
                    value
                        .parse::<u8>()
                        .map_err(|err| format!("invalid value for --ipv4-prefix: {err}"))
                })
                .transpose()?
                .unwrap_or(24);
            let ipv6_prefix = parser
                .value("--ipv6-prefix")
                .map(|value| {
                    value
                        .parse::<u8>()
                        .map_err(|err| format!("invalid value for --ipv6-prefix: {err}"))
                })
                .transpose()?
                .unwrap_or(64);
            Ok(OpsCommand::ClassifyCrossNetworkTopology {
                config: ops_cross_network_reports::ClassifyCrossNetworkTopologyConfig {
                    ip_a: parser.required("--ip-a")?,
                    ip_b: parser.required("--ip-b")?,
                    ipv4_prefix,
                    ipv6_prefix,
                },
            })
        }
        "choose-cross-network-roam-alias" => {
            let used_ips = collect_repeated_option_values(&args[1..], "--used-ip");
            let ipv4_prefix = parser
                .value("--ipv4-prefix")
                .map(|value| {
                    value
                        .parse::<u8>()
                        .map_err(|err| format!("invalid value for --ipv4-prefix: {err}"))
                })
                .transpose()?
                .unwrap_or(24);
            let ipv6_prefix = parser
                .value("--ipv6-prefix")
                .map(|value| {
                    value
                        .parse::<u8>()
                        .map_err(|err| format!("invalid value for --ipv6-prefix: {err}"))
                })
                .transpose()?
                .unwrap_or(64);
            Ok(OpsCommand::ChooseCrossNetworkRoamAlias {
                config: ops_cross_network_reports::ChooseCrossNetworkRoamAliasConfig {
                    exit_ip: parser.required("--exit-ip")?,
                    used_ips,
                    ipv4_prefix,
                    ipv6_prefix,
                },
            })
        }
        "validate-ipv4-address" => Ok(OpsCommand::ValidateIpv4Address {
            config: ops_cross_network_reports::ValidateIpv4AddressConfig {
                ip: parser.required("--ip")?,
            },
        }),
        "write-cross-network-soak-monitor-summary" => {
            let parse_u64 = |key: &str| -> Result<u64, String> {
                parser
                    .required(key)?
                    .parse::<u64>()
                    .map_err(|err| format!("invalid value for {key}: {err}"))
            };
            Ok(OpsCommand::WriteCrossNetworkSoakMonitorSummary {
                config: ops_cross_network_reports::WriteCrossNetworkSoakMonitorSummaryConfig {
                    path: parser.required_path("--path")?,
                    samples: parse_u64("--samples")?,
                    failing_samples: parse_u64("--failing-samples")?,
                    max_consecutive_failures_observed: parse_u64(
                        "--max-consecutive-failures-observed",
                    )?,
                    elapsed_secs: parse_u64("--elapsed-secs")?,
                    required_soak_duration_secs: parse_u64("--required-soak-duration-secs")?,
                    allowed_failing_samples: parse_u64("--allowed-failing-samples")?,
                    allowed_max_consecutive_failures: parse_u64(
                        "--allowed-max-consecutive-failures",
                    )?,
                    direct_remote_exit_ready: parser.required("--direct-remote-exit-ready")?,
                    post_soak_bypass_ready: parser.required("--post-soak-bypass-ready")?,
                    no_plaintext_passphrase_files: parser
                        .required("--no-plaintext-passphrase-files")?,
                    direct_samples: parse_u64("--direct-samples")?,
                    relay_samples: parse_u64("--relay-samples")?,
                    fail_closed_samples: parse_u64("--fail-closed-samples")?,
                    other_path_samples: parse_u64("--other-path-samples")?,
                    path_transition_count: parse_u64("--path-transition-count")?,
                    status_mismatch_samples: parse_u64("--status-mismatch-samples")?,
                    route_mismatch_samples: parse_u64("--route-mismatch-samples")?,
                    endpoint_mismatch_samples: parse_u64("--endpoint-mismatch-samples")?,
                    dns_alarm_bad_samples: parse_u64("--dns-alarm-bad-samples")?,
                    transport_identity_failures: parse_u64("--transport-identity-failures")?,
                    endpoint_change_events_start: parse_u64("--endpoint-change-events-start")?,
                    endpoint_change_events_end: parse_u64("--endpoint-change-events-end")?,
                    endpoint_change_events_delta: parse_u64("--endpoint-change-events-delta")?,
                    first_non_direct_reason: parser.required("--first-non-direct-reason")?,
                    last_path_mode: parser.required("--last-path-mode")?,
                    last_path_reason: parser.required("--last-path-reason")?,
                    first_failure_reason: parser.required("--first-failure-reason")?,
                    long_soak_stable: parser.required("--long-soak-stable")?,
                },
            })
        }
        "check-local-file-mode" => Ok(OpsCommand::CheckLocalFileMode {
            config: ops_live_lab_orchestrator::CheckLocalFileModeConfig {
                path: parser.required_path("--path")?,
                policy: parser.required("--policy")?,
                label: parser
                    .value("--label")
                    .unwrap_or_else(|| "file".to_string()),
            },
        }),
        "redact-forensics-text" => {
            if args.len() != 1 {
                return Err("ops redact-forensics-text does not accept options".to_string());
            }
            Ok(OpsCommand::RedactForensicsText)
        }
        "write-cross-network-forensics-manifest" => {
            Ok(OpsCommand::WriteCrossNetworkForensicsManifest {
                config: ops_live_lab_orchestrator::WriteCrossNetworkForensicsManifestConfig {
                    stage: parser.required("--stage")?,
                    collected_at_utc: parser.required("--collected-at-utc")?,
                    stage_dir: parser.required_path("--stage-dir")?,
                    output: parser.required_path("--output")?,
                },
            })
        }
        "write-live-lab-stage-artifact-index" => Ok(OpsCommand::WriteLiveLabStageArtifactIndex {
            config: ops_live_lab_orchestrator::WriteLiveLabStageArtifactIndexConfig {
                stage_name: parser.required("--stage-name")?,
                stage_dir: parser.required_path("--stage-dir")?,
                output: parser.required_path("--output")?,
            },
        }),
        "sha256-file" => Ok(OpsCommand::Sha256File {
            config: ops_live_lab_orchestrator::Sha256FileConfig {
                path: parser.required_path("--path")?,
            },
        }),
        "validate-cross-network-forensics-bundle" => {
            Ok(OpsCommand::ValidateCrossNetworkForensicsBundle {
                config: ops_live_lab_orchestrator::ValidateCrossNetworkForensicsBundleConfig {
                    stage_name: parser.required("--stage-name")?,
                    nodes_tsv: parser.required_path("--nodes-tsv")?,
                    stage_dir: parser.required_path("--stage-dir")?,
                    output: parser.required_path("--output")?,
                },
            })
        }
        "write-cross-network-preflight-report" => {
            let parse_u64 = |key: &str| -> Result<u64, String> {
                parser
                    .required(key)?
                    .parse::<u64>()
                    .map_err(|err| format!("invalid value for {key}: {err}"))
            };
            Ok(OpsCommand::WriteCrossNetworkPreflightReport {
                config: ops_live_lab_orchestrator::WriteCrossNetworkPreflightReportConfig {
                    nodes_tsv: parser.required_path("--nodes-tsv")?,
                    stage_dir: parser.required_path("--stage-dir")?,
                    output: parser.required_path("--output")?,
                    reference_unix: parse_u64("--reference-unix")?,
                    max_clock_skew_secs: parse_u64("--max-clock-skew-secs")?,
                    discovery_max_age_secs: parse_u64("--discovery-max-age-secs")?,
                    signed_artifact_max_age_secs: parse_u64("--signed-artifact-max-age-secs")?,
                },
            })
        }
        "write-live-linux-reboot-recovery-report" => {
            Ok(OpsCommand::WriteLiveLinuxRebootRecoveryReport {
                config: ops_live_lab_orchestrator::WriteLiveLinuxRebootRecoveryReportConfig {
                    report_path: parser.required_path("--report-path")?,
                    observations_path: parser.required_path("--observations-path")?,
                    exit_pre: parser.required("--exit-pre")?,
                    exit_post: parser.required("--exit-post")?,
                    client_pre: parser.required("--client-pre")?,
                    client_post: parser.required("--client-post")?,
                    exit_return: parser.required("--exit-return")?,
                    exit_boot_change: parser.required("--exit-boot-change")?,
                    post_exit_dns_refresh: parser.required("--post-exit-dns-refresh")?,
                    post_exit_twohop: parser.required("--post-exit-twohop")?,
                    client_return: parser.required("--client-return")?,
                    client_boot_change: parser.required("--client-boot-change")?,
                    post_client_dns_refresh: parser.required("--post-client-dns-refresh")?,
                    post_client_twohop: parser.required("--post-client-twohop")?,
                    salvage_twohop: parser.required("--salvage-twohop")?,
                },
            })
        }
        "write-live-linux-lab-run-summary" => {
            let parse_u64 = |key: &str| -> Result<u64, String> {
                parser
                    .required(key)?
                    .parse::<u64>()
                    .map_err(|err| format!("invalid value for {key}: {err}"))
            };
            Ok(OpsCommand::WriteLiveLinuxLabRunSummary {
                config: ops_live_lab_orchestrator::WriteLiveLinuxLabRunSummaryConfig {
                    nodes_tsv: parser.required_path("--nodes-tsv")?,
                    stages_tsv: parser.required_path("--stages-tsv")?,
                    summary_json: parser.required_path("--summary-json")?,
                    summary_md: parser.required_path("--summary-md")?,
                    run_id: parser.required("--run-id")?,
                    network_id: parser.required("--network-id")?,
                    report_dir: parser.required("--report-dir")?,
                    overall_status: parser.required("--overall-status")?,
                    started_at_local: parser.required("--started-at-local")?,
                    started_at_utc: parser.required("--started-at-utc")?,
                    started_at_unix: parse_u64("--started-at-unix")?,
                    finished_at_local: parser.required("--finished-at-local")?,
                    finished_at_utc: parser.required("--finished-at-utc")?,
                    finished_at_unix: parse_u64("--finished-at-unix")?,
                    elapsed_secs: parse_u64("--elapsed-secs")?,
                    elapsed_human: parser.required("--elapsed-human")?,
                },
            })
        }
        "scan-ipv4-port-range" => {
            let parse_u8_or_default = |key: &str, default: u8| -> Result<u8, String> {
                parser
                    .value(key)
                    .map(|value| {
                        value
                            .parse::<u8>()
                            .map_err(|err| format!("invalid value for {key}: {err}"))
                    })
                    .transpose()?
                    .map_or(Ok(default), Ok)
            };
            let parse_u16_or_default = |key: &str, default: u16| -> Result<u16, String> {
                parser
                    .value(key)
                    .map(|value| {
                        value
                            .parse::<u16>()
                            .map_err(|err| format!("invalid value for {key}: {err}"))
                    })
                    .transpose()?
                    .map_or(Ok(default), Ok)
            };
            let parse_u64_or_default = |key: &str, default: u64| -> Result<u64, String> {
                parser
                    .value(key)
                    .map(|value| {
                        value
                            .parse::<u64>()
                            .map_err(|err| format!("invalid value for {key}: {err}"))
                    })
                    .transpose()?
                    .map_or(Ok(default), Ok)
            };
            Ok(OpsCommand::ScanIpv4PortRange {
                config: ops_live_lab_orchestrator::ScanIpv4PortRangeConfig {
                    network_prefix: parser.required("--network-prefix")?,
                    start_host: parse_u8_or_default("--start-host", 1)?,
                    end_host: parse_u8_or_default("--end-host", 254)?,
                    port: parse_u16_or_default("--port", 22)?,
                    timeout_ms: parse_u64_or_default("--timeout-ms", 80)?,
                    output_key: parser
                        .value("--output-key")
                        .unwrap_or_else(|| "hosts=".to_string()),
                },
            })
        }
        "update-role-switch-host-result" => Ok(OpsCommand::UpdateRoleSwitchHostResult {
            config: ops_live_lab_orchestrator::UpdateRoleSwitchHostResultConfig {
                hosts_json_path: parser.required_path("--hosts-json-path")?,
                os_id: parser.required("--os-id")?,
                temp_role: parser.required("--temp-role")?,
                switch_execution: parser.required("--switch-execution")?,
                post_switch_reconcile: parser.required("--post-switch-reconcile")?,
                policy_still_enforced: parser.required("--policy-still-enforced")?,
                least_privilege_preserved: parser.required("--least-privilege-preserved")?,
            },
        }),
        "write-role-switch-matrix-report" => {
            let captured_at_unix = parser
                .required("--captured-at-unix")?
                .parse::<u64>()
                .map_err(|err| format!("invalid value for --captured-at-unix: {err}"))?;
            Ok(OpsCommand::WriteRoleSwitchMatrixReport {
                config: ops_live_lab_orchestrator::WriteRoleSwitchMatrixReportConfig {
                    hosts_json_path: parser.required_path("--hosts-json-path")?,
                    report_path: parser.required_path("--report-path")?,
                    source_path: parser.required_path("--source-path")?,
                    git_commit: parser.required("--git-commit")?,
                    captured_at_unix,
                    overall_status: parser.required("--overall-status")?,
                },
            })
        }
        "write-live-linux-server-ip-bypass-report" => {
            let probe_port = parser
                .required("--probe-port")?
                .parse::<u16>()
                .map_err(|err| format!("invalid value for --probe-port: {err}"))?;
            let captured_at_unix = parser
                .value("--captured-at-unix")
                .map(|value| {
                    value
                        .parse::<u64>()
                        .map_err(|err| format!("invalid value for --captured-at-unix: {err}"))
                })
                .transpose()?
                .unwrap_or(0);
            Ok(OpsCommand::WriteLiveLinuxServerIpBypassReport {
                config: ops_live_lab_orchestrator::WriteLiveLinuxServerIpBypassReportConfig {
                    report_path: parser.required_path("--report-path")?,
                    allowed_management_cidrs: parser.required("--allowed-management-cidrs")?,
                    probe_from_client_status: parser.required("--probe-from-client-status")?,
                    probe_ip: parser.required("--probe-ip")?,
                    probe_port,
                    client_internet_route: parser.required("--client-internet-route")?,
                    client_probe_route: parser.required("--client-probe-route")?,
                    client_table_51820: parser.required("--client-table-51820")?,
                    client_endpoints: parser.required("--client-endpoints")?,
                    probe_self_test: parser.required("--probe-self-test")?,
                    probe_from_client_output: parser.required("--probe-from-client-output")?,
                    captured_at_utc: parser.value("--captured-at-utc").unwrap_or_default(),
                    captured_at_unix,
                },
            })
        }
        "write-live-linux-control-surface-report" => {
            let captured_at_unix = parser
                .value("--captured-at-unix")
                .map(|value| {
                    value
                        .parse::<u64>()
                        .map_err(|err| format!("invalid value for --captured-at-unix: {err}"))
                })
                .transpose()?
                .unwrap_or(0);
            let host_labels = collect_repeated_option_values(&args[1..], "--host-label");
            Ok(OpsCommand::WriteLiveLinuxControlSurfaceReport {
                config: ops_live_lab_orchestrator::WriteLiveLinuxControlSurfaceReportConfig {
                    report_path: parser.required_path("--report-path")?,
                    dns_bind_addr: parser.required("--dns-bind-addr")?,
                    remote_dns_probe_status: parser.required("--remote-dns-probe-status")?,
                    remote_dns_probe_output: parser.required("--remote-dns-probe-output")?,
                    work_dir: parser.required_path("--work-dir")?,
                    host_labels,
                    captured_at_utc: parser.value("--captured-at-utc").unwrap_or_default(),
                    captured_at_unix,
                },
            })
        }
        "rewrite-assignment-peer-endpoint-ip" => Ok(OpsCommand::RewriteAssignmentPeerEndpointIp {
            config: ops_live_lab_orchestrator::RewriteAssignmentPeerEndpointIpConfig {
                assignment_path: parser.required_path("--assignment-path")?,
                endpoint_ip: parser.required("--endpoint-ip")?,
            },
        }),
        "rewrite-assignment-mesh-cidr" => Ok(OpsCommand::RewriteAssignmentMeshCidr {
            config: ops_live_lab_orchestrator::RewriteAssignmentMeshCidrConfig {
                assignment_path: parser.required_path("--assignment-path")?,
                mesh_cidr: parser.required("--mesh-cidr")?,
            },
        }),
        "write-live-linux-endpoint-hijack-report" => {
            let captured_at_unix = parser
                .value("--captured-at-unix")
                .map(|value| {
                    value
                        .parse::<u64>()
                        .map_err(|err| format!("invalid value for --captured-at-unix: {err}"))
                })
                .transpose()?
                .unwrap_or(0);
            Ok(OpsCommand::WriteLiveLinuxEndpointHijackReport {
                config: ops_live_lab_orchestrator::WriteLiveLinuxEndpointHijackReportConfig {
                    report_path: parser.required_path("--report-path")?,
                    rogue_endpoint_ip: parser.required("--rogue-endpoint-ip")?,
                    baseline_status: parser.required("--baseline-status")?,
                    baseline_netcheck: parser.required("--baseline-netcheck")?,
                    baseline_endpoints: parser.required("--baseline-endpoints")?,
                    status_after_hijack: parser.required("--status-after-hijack")?,
                    netcheck_after_hijack: parser.required("--netcheck-after-hijack")?,
                    endpoints_after_hijack: parser.required("--endpoints-after-hijack")?,
                    status_after_recovery: parser.required("--status-after-recovery")?,
                    endpoints_after_recovery: parser.required("--endpoints-after-recovery")?,
                    captured_at_utc: parser.value("--captured-at-utc").unwrap_or_default(),
                    captured_at_unix,
                },
            })
        }
        "write-real-wireguard-exitnode-e2e-report" => {
            let captured_at_unix = parser
                .value("--captured-at-unix")
                .map(|value| {
                    value
                        .parse::<u64>()
                        .map_err(|err| format!("invalid value for --captured-at-unix: {err}"))
                })
                .transpose()?
                .unwrap_or(0);
            Ok(OpsCommand::WriteRealWireguardExitnodeE2eReport {
                config: ops_live_lab_orchestrator::WriteRealWireguardExitnodeE2eReportConfig {
                    report_path: parser.required_path("--report-path")?,
                    exit_status: parser.required("--exit-status")?,
                    lan_off_status: parser.required("--lan-off-status")?,
                    lan_on_status: parser.required("--lan-on-status")?,
                    dns_up_status: parser.required("--dns-up-status")?,
                    kill_switch_status: parser.required("--kill-switch-status")?,
                    dns_down_status: parser.required("--dns-down-status")?,
                    environment: parser
                        .value("--environment")
                        .unwrap_or_else(|| "lab-netns".to_string()),
                    captured_at_utc: parser.value("--captured-at-utc").unwrap_or_default(),
                    captured_at_unix,
                },
            })
        }
        "write-real-wireguard-no-leak-under-load-report" => {
            let captured_at_unix = parser
                .value("--captured-at-unix")
                .map(|value| {
                    value
                        .parse::<u64>()
                        .map_err(|err| format!("invalid value for --captured-at-unix: {err}"))
                })
                .transpose()?
                .unwrap_or(0);
            Ok(OpsCommand::WriteRealWireguardNoLeakUnderLoadReport {
                config: ops_live_lab_orchestrator::WriteRealWireguardNoLeakUnderLoadReportConfig {
                    report_path: parser.required_path("--report-path")?,
                    load_pcap: parser.required_path("--load-pcap")?,
                    down_pcap: parser.required_path("--down-pcap")?,
                    tunnel_up_status: parser.required("--tunnel-up-status")?,
                    load_ping_status: parser.required("--load-ping-status")?,
                    tunnel_down_block_status: parser.required("--tunnel-down-block-status")?,
                    environment: parser
                        .value("--environment")
                        .unwrap_or_else(|| "lab-netns".to_string()),
                    captured_at_utc: parser.value("--captured-at-utc").unwrap_or_default(),
                    captured_at_unix,
                },
            })
        }
        "verify-no-leak-dataplane-report" => Ok(OpsCommand::VerifyNoLeakDataplaneReport {
            config: ops_live_lab_orchestrator::VerifyNoLeakDataplaneReportConfig {
                report_path: parser.required_path("--report-path")?,
            },
        }),
        "e2e-dns-query" => Ok(OpsCommand::E2eDnsQuery {
            config: ops_live_lab_orchestrator::E2eDnsQueryConfig {
                server: parser.required("--server")?,
                port: parser
                    .required("--port")?
                    .parse::<u16>()
                    .map_err(|err| format!("invalid value for --port: {err}"))?,
                qname: parser.required("--qname")?,
                timeout_ms: parser.parse_u64_or_default("--timeout-ms", 1000)?,
                fail_on_no_response: parser.has_flag("--fail-on-no-response"),
            },
        }),
        "e2e-http-probe-server" => Ok(OpsCommand::E2eHttpProbeServer {
            config: ops_live_lab_orchestrator::E2eHttpProbeServerConfig {
                bind_ip: parser.required("--bind-ip")?,
                port: parser
                    .required("--port")?
                    .parse::<u16>()
                    .map_err(|err| format!("invalid value for --port: {err}"))?,
                response_body: parser
                    .value("--response-body")
                    .unwrap_or_else(|| "probe-ok".to_string()),
            },
        }),
        "e2e-http-probe-client" => Ok(OpsCommand::E2eHttpProbeClient {
            config: ops_live_lab_orchestrator::E2eHttpProbeClientConfig {
                host: parser.required("--host")?,
                port: parser
                    .required("--port")?
                    .parse::<u16>()
                    .map_err(|err| format!("invalid value for --port: {err}"))?,
                timeout_ms: parser.parse_u64_or_default("--timeout-ms", 2000)?,
                expect_marker: parser
                    .value("--expect-marker")
                    .unwrap_or_else(|| "probe-ok".to_string()),
            },
        }),
        "read-json-field" => Ok(OpsCommand::ReadJsonField {
            config: ops_live_lab_orchestrator::ReadJsonFieldConfig {
                payload: parser.required("--payload")?,
                field: parser.required("--field")?,
            },
        }),
        "extract-managed-dns-expected-ip" => Ok(OpsCommand::ExtractManagedDnsExpectedIp {
            config: ops_live_lab_orchestrator::ExtractManagedDnsExpectedIpConfig {
                fqdn: parser.required("--fqdn")?,
                inspect_output: parser.required("--inspect-output")?,
            },
        }),
        "write-active-network-signed-state-tamper-report" => {
            let captured_at_unix = parser
                .value("--captured-at-unix")
                .map(|value| {
                    value
                        .parse::<u64>()
                        .map_err(|err| format!("invalid value for --captured-at-unix: {err}"))
                })
                .transpose()?
                .unwrap_or(0);
            Ok(OpsCommand::WriteActiveNetworkSignedStateTamperReport {
                config:
                    ops_live_lab_orchestrator::WriteActiveNetworkSignedStateTamperReportConfig {
                        report_path: parser.required_path("--report-path")?,
                        baseline_status: parser.required("--baseline-status")?,
                        tamper_reject_status: parser.required("--tamper-reject-status")?,
                        fail_closed_status: parser.required("--fail-closed-status")?,
                        netcheck_fail_closed_status: parser
                            .required("--netcheck-fail-closed-status")?,
                        recovery_status: parser.required("--recovery-status")?,
                        exit_host: parser.required("--exit-host")?,
                        client_host: parser.required("--client-host")?,
                        status_after_tamper: parser.required("--status-after-tamper")?,
                        netcheck_after_tamper: parser.required("--netcheck-after-tamper")?,
                        status_after_recovery: parser.required("--status-after-recovery")?,
                        captured_at_utc: parser.value("--captured-at-utc").unwrap_or_default(),
                        captured_at_unix,
                    },
            })
        }
        "write-active-network-rogue-path-hijack-report" => {
            let captured_at_unix = parser
                .value("--captured-at-unix")
                .map(|value| {
                    value
                        .parse::<u64>()
                        .map_err(|err| format!("invalid value for --captured-at-unix: {err}"))
                })
                .transpose()?
                .unwrap_or(0);
            Ok(OpsCommand::WriteActiveNetworkRoguePathHijackReport {
                config: ops_live_lab_orchestrator::WriteActiveNetworkRoguePathHijackReportConfig {
                    report_path: parser.required_path("--report-path")?,
                    baseline_status: parser.required("--baseline-status")?,
                    hijack_reject_status: parser.required("--hijack-reject-status")?,
                    fail_closed_status: parser.required("--fail-closed-status")?,
                    netcheck_fail_closed_status: parser
                        .required("--netcheck-fail-closed-status")?,
                    no_rogue_endpoint_status: parser.required("--no-rogue-endpoint-status")?,
                    recovery_status: parser.required("--recovery-status")?,
                    recovery_endpoint_status: parser.required("--recovery-endpoint-status")?,
                    rogue_endpoint_ip: parser.required("--rogue-endpoint-ip")?,
                    exit_host: parser.required("--exit-host")?,
                    client_host: parser.required("--client-host")?,
                    endpoints_before: parser.required("--endpoints-before")?,
                    endpoints_after_hijack: parser.required("--endpoints-after-hijack")?,
                    endpoints_after_recovery: parser.required("--endpoints-after-recovery")?,
                    status_after_hijack: parser.required("--status-after-hijack")?,
                    netcheck_after_hijack: parser.required("--netcheck-after-hijack")?,
                    status_after_recovery: parser.required("--status-after-recovery")?,
                    captured_at_utc: parser.value("--captured-at-utc").unwrap_or_default(),
                    captured_at_unix,
                },
            })
        }
        "validate-network-discovery-bundle" => {
            let mut bundles = Vec::new();
            let mut seen = HashSet::new();
            for bundle in collect_repeated_option_values(&args[1..], "--bundle") {
                if seen.insert(bundle.clone()) {
                    bundles.push(PathBuf::from(bundle));
                }
            }
            if let Some(csv_bundles) = parser.value("--bundles") {
                for bundle in split_csv(csv_bundles) {
                    if seen.insert(bundle.clone()) {
                        bundles.push(PathBuf::from(bundle));
                    }
                }
            }
            Ok(OpsCommand::ValidateNetworkDiscoveryBundle {
                config: ops_network_discovery::ValidateNetworkDiscoveryBundleConfig {
                    bundles,
                    max_age_seconds: parser.parse_u64_or_default("--max-age-seconds", 900)?,
                    require_verifier_keys: parser.has_flag("--require-verifier-keys"),
                    require_daemon_active: parser.has_flag("--require-daemon-active"),
                    require_socket_present: parser.has_flag("--require-socket-present"),
                    output: parser.optional_path("--output"),
                },
            })
        }
        "generate-live-linux-lab-failure-digest" => {
            Ok(OpsCommand::GenerateLiveLinuxLabFailureDigest {
                config: ops_live_lab_failure_digest::GenerateLiveLinuxLabFailureDigestConfig {
                    nodes_tsv: parser.required_path("--nodes-tsv")?,
                    stages_tsv: parser.required_path("--stages-tsv")?,
                    report_dir: parser.required_path("--report-dir")?,
                    run_id: parser.required("--run-id")?,
                    network_id: parser.required("--network-id")?,
                    overall_status: parser.required("--overall-status")?,
                    output_json: parser.required_path("--output-json")?,
                    output_md: parser.required_path("--output-md")?,
                },
            })
        }
        "vm-lab-list" => Ok(OpsCommand::VmLabList {
            config: vm_lab::VmLabListConfig {
                inventory_path: parser
                    .path_or_default("--inventory", vm_lab::default_inventory_path()),
            },
        }),
        "vm-lab-discover-local-utm" => Ok(OpsCommand::VmLabDiscoverLocalUtm {
            config: vm_lab::VmLabDiscoverLocalUtmConfig {
                inventory_path: parser.optional_path("--inventory"),
                utm_documents_root: parser.optional_path("--utm-documents-root"),
                utmctl_path: parser.optional_path("--utmctl-path"),
                ssh_identity_file: Some(parser.path_or_default(
                    "--ssh-identity-file",
                    vm_lab::default_lab_ssh_identity_path(),
                )),
                known_hosts_path: Some(
                    parser
                        .path_or_default("--known-hosts-file", vm_lab::default_known_hosts_path()),
                ),
                ssh_port: u16::try_from(parser.parse_u64_or_default("--ssh-port", 22)?)
                    .map_err(|_| "invalid value for --ssh-port: must fit in u16".to_string())?,
                timeout_secs: parser.parse_u64_or_default("--timeout-secs", 5)?,
                update_inventory_live_ips: parser.has_flag("--update-inventory-live-ips"),
                report_dir: parser.optional_path("--report-dir"),
            },
        }),
        "vm-lab-discover-local-utm-summary" => Ok(OpsCommand::VmLabDiscoverLocalUtmSummary {
            config: vm_lab::VmLabDiscoverLocalUtmConfig {
                inventory_path: parser.optional_path("--inventory"),
                utm_documents_root: parser.optional_path("--utm-documents-root"),
                utmctl_path: parser.optional_path("--utmctl-path"),
                ssh_identity_file: Some(parser.path_or_default(
                    "--ssh-identity-file",
                    vm_lab::default_lab_ssh_identity_path(),
                )),
                known_hosts_path: Some(
                    parser
                        .path_or_default("--known-hosts-file", vm_lab::default_known_hosts_path()),
                ),
                ssh_port: u16::try_from(parser.parse_u64_or_default("--ssh-port", 22)?)
                    .map_err(|_| "invalid value for --ssh-port: must fit in u16".to_string())?,
                timeout_secs: parser.parse_u64_or_default("--timeout-secs", 5)?,
                update_inventory_live_ips: parser.has_flag("--update-inventory-live-ips"),
                report_dir: parser.optional_path("--report-dir"),
            },
        }),
        "vm-lab-start" => {
            let mut vm_aliases = collect_repeated_option_values(&args[1..], "--vm");
            if let Some(csv_vms) = parser.value("--vms") {
                vm_aliases.extend(split_csv(csv_vms));
            }
            Ok(OpsCommand::VmLabStart {
                config: vm_lab::VmLabStartConfig {
                    inventory_path: parser
                        .path_or_default("--inventory", vm_lab::default_inventory_path()),
                    vm_aliases,
                    select_all: parser.has_flag("--all"),
                    utmctl_path: parser
                        .path_or_default("--utmctl-path", vm_lab::default_utmctl_path()),
                    timeout_secs: parser.parse_u64_or_default("--timeout-secs", 60)?,
                },
            })
        }
        "vm-lab-sync-repo" => {
            let mut vm_aliases = collect_repeated_option_values(&args[1..], "--vm");
            if let Some(csv_vms) = parser.value("--vms") {
                vm_aliases.extend(split_csv(csv_vms));
            }
            let mut raw_targets = collect_repeated_option_values(&args[1..], "--target");
            if let Some(csv_targets) = parser.value("--targets") {
                raw_targets.extend(split_csv(csv_targets));
            }
            Ok(OpsCommand::VmLabSyncRepo {
                config: vm_lab::VmLabSyncRepoConfig {
                    inventory_path: parser
                        .path_or_default("--inventory", vm_lab::default_inventory_path()),
                    vm_aliases,
                    raw_targets,
                    select_all: parser.has_flag("--all"),
                    repo_url: parser.value("--repo-url"),
                    local_source_dir: parser.optional_path("--local-source-dir"),
                    dest_dir: parser.required("--dest-dir")?,
                    branch: parser
                        .value("--branch")
                        .unwrap_or_else(|| "main".to_string()),
                    remote: parser
                        .value("--remote")
                        .unwrap_or_else(|| "origin".to_string()),
                    ssh_user: parser.value("--ssh-user"),
                    ssh_identity_file: parser.optional_path("--ssh-identity-file"),
                    known_hosts_path: parser.optional_path("--known-hosts-file"),
                    timeout_secs: parser.parse_u64_or_default("--timeout-secs", 900)?,
                },
            })
        }
        "vm-lab-sync-bootstrap" => {
            let mut vm_aliases = collect_repeated_option_values(&args[1..], "--vm");
            if let Some(csv_vms) = parser.value("--vms") {
                vm_aliases.extend(split_csv(csv_vms));
            }
            let mut raw_targets = collect_repeated_option_values(&args[1..], "--target");
            if let Some(csv_targets) = parser.value("--targets") {
                raw_targets.extend(split_csv(csv_targets));
            }
            let argv = collect_repeated_option_values_allow_leading_dash(&args[1..], "--arg")?;
            let dest_dir = parser.required("--dest-dir")?;
            Ok(OpsCommand::VmLabSyncBootstrap {
                config: vm_lab::VmLabSyncBootstrapConfig {
                    inventory_path: parser
                        .path_or_default("--inventory", vm_lab::default_inventory_path()),
                    vm_aliases,
                    raw_targets,
                    select_all: parser.has_flag("--all"),
                    require_same_network: parser.has_flag("--require-same-network"),
                    repo_url: parser.value("--repo-url"),
                    local_source_dir: parser.optional_path("--local-source-dir"),
                    workdir: parser
                        .value("--workdir")
                        .unwrap_or_else(|| dest_dir.clone()),
                    dest_dir,
                    branch: parser
                        .value("--branch")
                        .unwrap_or_else(|| "main".to_string()),
                    remote: parser
                        .value("--remote")
                        .unwrap_or_else(|| "origin".to_string()),
                    program: parser.required("--program")?,
                    argv,
                    ssh_user: parser.value("--ssh-user"),
                    ssh_identity_file: parser.optional_path("--ssh-identity-file"),
                    known_hosts_path: parser.optional_path("--known-hosts-file"),
                    sudo: parser.has_flag("--sudo"),
                    timeout_secs: parser.parse_u64_or_default("--timeout-secs", 1800)?,
                },
            })
        }
        "vm-lab-run" | "vm-lab-bootstrap" => {
            let mut vm_aliases = collect_repeated_option_values(&args[1..], "--vm");
            if let Some(csv_vms) = parser.value("--vms") {
                vm_aliases.extend(split_csv(csv_vms));
            }
            let mut raw_targets = collect_repeated_option_values(&args[1..], "--target");
            if let Some(csv_targets) = parser.value("--targets") {
                raw_targets.extend(split_csv(csv_targets));
            }
            let argv = collect_repeated_option_values_allow_leading_dash(&args[1..], "--arg")?;
            let config = vm_lab::VmLabExecConfig {
                inventory_path: parser
                    .path_or_default("--inventory", vm_lab::default_inventory_path()),
                vm_aliases,
                raw_targets,
                select_all: parser.has_flag("--all"),
                workdir: parser.required("--workdir")?,
                program: parser.required("--program")?,
                argv,
                ssh_user: parser.value("--ssh-user"),
                ssh_identity_file: parser.optional_path("--ssh-identity-file"),
                known_hosts_path: parser.optional_path("--known-hosts-file"),
                sudo: parser.has_flag("--sudo"),
                timeout_secs: parser.parse_u64_or_default("--timeout-secs", 1800)?,
            };
            if subcommand == "vm-lab-run" {
                Ok(OpsCommand::VmLabRun { config })
            } else {
                Ok(OpsCommand::VmLabBootstrap { config })
            }
        }
        "vm-lab-write-live-lab-profile" => {
            Ok(OpsCommand::VmLabWriteLiveLabProfile {
                config: vm_lab::VmLabWriteLiveLabProfileConfig {
                    inventory_path: parser
                        .path_or_default("--inventory", vm_lab::default_inventory_path()),
                    output_path: parser.required_path("--output")?,
                    exit_vm: parser.value("--exit-vm"),
                    exit_target: parser.value("--exit-target"),
                    client_vm: parser.value("--client-vm"),
                    client_target: parser.value("--client-target"),
                    entry_vm: parser.value("--entry-vm"),
                    entry_target: parser.value("--entry-target"),
                    aux_vm: parser.value("--aux-vm"),
                    aux_target: parser.value("--aux-target"),
                    extra_vm: parser.value("--extra-vm"),
                    extra_target: parser.value("--extra-target"),
                    fifth_client_vm: parser.value("--fifth-client-vm"),
                    fifth_client_target: parser.value("--fifth-client-target"),
                    require_same_network: parser.has_flag("--require-same-network"),
                    ssh_identity_file: parser.required_path("--ssh-identity-file")?,
                    ssh_known_hosts_file: parser.optional_path("--ssh-known-hosts-file"),
                    ssh_allow_cidrs: parser.value("--ssh-allow-cidrs"),
                    network_id: parser.value("--network-id"),
                    traversal_ttl_secs: match parser.value("--traversal-ttl-secs") {
                        Some(value) => Some(value.parse::<u64>().map_err(|err| {
                            format!("invalid value for --traversal-ttl-secs: {err}")
                        })?),
                        None => None,
                    },
                    cross_network_nat_profiles: parser.value("--cross-network-nat-profiles"),
                    cross_network_required_nat_profiles: parser
                        .value("--cross-network-required-nat-profiles"),
                    cross_network_impairment_profile: parser
                        .value("--cross-network-impairment-profile"),
                    backend: parser.value("--backend"),
                    source_mode: parser.value("--source-mode"),
                    repo_ref: parser.value("--repo-ref"),
                    report_dir: parser.optional_path("--report-dir"),
                },
            })
        }
        "vm-lab-setup-live-lab" => Ok(OpsCommand::VmLabSetupLiveLab {
            config: vm_lab::VmLabSetupLiveLabConfig {
                inventory_path: parser
                    .path_or_default("--inventory", vm_lab::default_inventory_path()),
                profile_path: parser.optional_path("--profile"),
                profile_output_path: parser.optional_path("--profile-output"),
                exit_vm: parser.value("--exit-vm"),
                client_vm: parser.value("--client-vm"),
                entry_vm: parser.value("--entry-vm"),
                aux_vm: parser.value("--aux-vm"),
                extra_vm: parser.value("--extra-vm"),
                fifth_client_vm: parser.value("--fifth-client-vm"),
                ssh_identity_file: parser.required_path("--ssh-identity-file")?,
                known_hosts_path: parser.optional_path("--known-hosts-file"),
                require_same_network: parser.has_flag("--require-same-network"),
                script_path: parser
                    .path_or_default("--script", vm_lab::default_live_lab_orchestrator_path()),
                report_dir: parser.required_path("--report-dir")?,
                source_mode: parser.value("--source-mode"),
                repo_ref: parser.value("--repo-ref"),
                resume_from: parser.value("--resume-from"),
                rerun_stage: parser.value("--rerun-stage"),
                max_parallel_node_workers: match parser.value("--max-parallel-node-workers") {
                    Some(value) => Some(value.parse::<usize>().map_err(|err| {
                        format!("invalid value for --max-parallel-node-workers: {err}")
                    })?),
                    None => None,
                },
                timeout_secs: parser.parse_u64_or_default("--timeout-secs", 86_400)?,
                dry_run: parser.has_flag("--dry-run"),
            },
        }),
        "vm-lab-orchestrate-live-lab" => Ok(OpsCommand::VmLabOrchestrateLiveLab {
            config: vm_lab::VmLabOrchestrateLiveLabConfig {
                inventory_path: parser
                    .path_or_default("--inventory", vm_lab::default_inventory_path()),
                profile_path: parser.optional_path("--profile"),
                profile_output_path: parser.optional_path("--profile-output"),
                exit_vm: parser.value("--exit-vm"),
                client_vm: parser.value("--client-vm"),
                entry_vm: parser.value("--entry-vm"),
                aux_vm: parser.value("--aux-vm"),
                extra_vm: parser.value("--extra-vm"),
                fifth_client_vm: parser.value("--fifth-client-vm"),
                ssh_identity_file: parser.required_path("--ssh-identity-file")?,
                known_hosts_path: parser.optional_path("--known-hosts-file"),
                require_same_network: parser.has_flag("--require-same-network"),
                script_path: parser
                    .path_or_default("--script", vm_lab::default_live_lab_orchestrator_path()),
                report_dir: parser.required_path("--report-dir")?,
                source_mode: parser.value("--source-mode"),
                repo_ref: parser.value("--repo-ref"),
                max_parallel_node_workers: match parser.value("--max-parallel-node-workers") {
                    Some(value) => Some(value.parse::<usize>().map_err(|err| {
                        format!("invalid value for --max-parallel-node-workers: {err}")
                    })?),
                    None => None,
                },
                skip_gates: parser.has_flag("--skip-gates"),
                skip_soak: parser.has_flag("--skip-soak"),
                skip_cross_network: parser.has_flag("--skip-cross-network"),
                utm_documents_root: parser.optional_path("--utm-documents-root"),
                utmctl_path: parser.optional_path("--utmctl-path"),
                ssh_port: u16::try_from(parser.parse_u64_or_default("--ssh-port", 22)?)
                    .map_err(|_| "invalid value for --ssh-port: must fit in u16".to_string())?,
                discovery_timeout_secs: parser
                    .parse_u64_or_default("--discovery-timeout-secs", 5)?,
                ready_timeout_secs: parser
                    .parse_u64_or_default("--wait-ready-timeout-secs", 300)?,
                timeout_secs: parser.parse_u64_or_default("--timeout-secs", 86_400)?,
                collect_artifacts_on_failure: parser.has_flag("--collect-artifacts-on-failure"),
                skip_diagnose_on_failure: parser.has_flag("--skip-diagnose-on-failure"),
                stop_after_ready: parser.has_flag("--stop-after-ready"),
                dry_run: parser.has_flag("--dry-run"),
            },
        }),
        "vm-lab-validate-live-lab-profile" => Ok(OpsCommand::VmLabValidateLiveLabProfile {
            config: vm_lab::VmLabValidateLiveLabProfileConfig {
                profile_path: parser.required_path("--profile")?,
                expected_backend: parser.value("--expected-backend"),
                expected_source_mode: parser.value("--expected-source-mode"),
                require_five_node: parser.has_flag("--require-five-node"),
            },
        }),
        "vm-lab-diagnose-live-lab-failure" => Ok(OpsCommand::VmLabDiagnoseLiveLabFailure {
            config: vm_lab::VmLabDiagnoseLiveLabFailureConfig {
                inventory_path: parser
                    .path_or_default("--inventory", vm_lab::default_inventory_path()),
                profile_path: parser.required_path("--profile")?,
                report_dir: parser.required_path("--report-dir")?,
                stage: parser.value("--stage"),
                output_dir: parser.optional_path("--output-dir"),
                collect_artifacts: parser.has_flag("--collect-artifacts"),
                timeout_secs: parser.parse_u64_or_default("--timeout-secs", 300)?,
            },
        }),
        "vm-lab-diff-live-lab-runs" => Ok(OpsCommand::VmLabDiffLiveLabRuns {
            config: vm_lab::VmLabDiffLiveLabRunsConfig {
                old_report_dir: parser.required_path("--old-report-dir")?,
                new_report_dir: parser.required_path("--new-report-dir")?,
            },
        }),
        "vm-lab-iterate-live-lab" => {
            let validation_steps = collect_repeated_option_values(&args[1..], "--validation-step")
                .into_iter()
                .map(|value| vm_lab::parse_vm_lab_iteration_validation_step_spec(value.as_str()))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(OpsCommand::VmLabIterateLiveLab {
                config: vm_lab::VmLabIterateLiveLabConfig {
                    inventory_path: parser
                        .path_or_default("--inventory", vm_lab::default_inventory_path()),
                    profile_output_path: parser.optional_path("--profile-output"),
                    exit_vm: parser.value("--exit-vm"),
                    exit_target: parser.value("--exit-target"),
                    client_vm: parser.value("--client-vm"),
                    client_target: parser.value("--client-target"),
                    entry_vm: parser.value("--entry-vm"),
                    entry_target: parser.value("--entry-target"),
                    aux_vm: parser.value("--aux-vm"),
                    aux_target: parser.value("--aux-target"),
                    extra_vm: parser.value("--extra-vm"),
                    extra_target: parser.value("--extra-target"),
                    fifth_client_vm: parser.value("--fifth-client-vm"),
                    fifth_client_target: parser.value("--fifth-client-target"),
                    require_same_network: parser.has_flag("--require-same-network"),
                    ssh_identity_file: parser.required_path("--ssh-identity-file")?,
                    ssh_known_hosts_file: parser.optional_path("--ssh-known-hosts-file"),
                    ssh_allow_cidrs: parser.value("--ssh-allow-cidrs"),
                    network_id: parser.value("--network-id"),
                    traversal_ttl_secs: match parser.value("--traversal-ttl-secs") {
                        Some(value) => Some(value.parse::<u64>().map_err(|err| {
                            format!("invalid value for --traversal-ttl-secs: {err}")
                        })?),
                        None => None,
                    },
                    backend: parser.value("--backend"),
                    source_mode: parser.value("--source-mode"),
                    repo_ref: parser.value("--repo-ref"),
                    report_dir: parser.optional_path("--report-dir"),
                    script_path: parser
                        .path_or_default("--script", vm_lab::default_live_lab_orchestrator_path()),
                    dry_run: parser.has_flag("--dry-run"),
                    timeout_secs: parser.parse_u64_or_default("--timeout-secs", 86_400)?,
                    skip_gates: parser.has_flag("--skip-gates"),
                    skip_soak: parser.has_flag("--skip-soak"),
                    skip_cross_network: parser.has_flag("--skip-cross-network"),
                    require_clean_tree: parser.has_flag("--require-clean-tree"),
                    require_local_head: parser.has_flag("--require-local-head"),
                    validation_steps,
                    collect_failure_diagnostics: parser.has_flag("--collect-failure-diagnostics"),
                    failed_log_tail_lines: parser
                        .parse_u64_or_default("--failed-log-tail-lines", 40)?
                        as usize,
                },
            })
        }
        "vm-lab-run-live-lab" => Ok(OpsCommand::VmLabRunLiveLab {
            config: vm_lab::VmLabRunLiveLabConfig {
                profile_path: parser.required_path("--profile")?,
                script_path: parser
                    .path_or_default("--script", vm_lab::default_live_lab_orchestrator_path()),
                dry_run: parser.has_flag("--dry-run"),
                skip_setup: parser.has_flag("--skip-setup"),
                skip_gates: parser.has_flag("--skip-gates"),
                skip_soak: parser.has_flag("--skip-soak"),
                skip_cross_network: parser.has_flag("--skip-cross-network"),
                source_mode: parser.value("--source-mode"),
                repo_ref: parser.value("--repo-ref"),
                report_dir: parser.optional_path("--report-dir"),
                timeout_secs: parser.parse_u64_or_default("--timeout-secs", 86_400)?,
            },
        }),
        "vm-lab-check-known-hosts" => {
            let mut vm_aliases = collect_repeated_option_values(&args[1..], "--vm");
            if let Some(csv_vms) = parser.value("--vms") {
                vm_aliases.extend(split_csv(csv_vms));
            }
            let mut raw_targets = collect_repeated_option_values(&args[1..], "--target");
            if let Some(csv_targets) = parser.value("--targets") {
                raw_targets.extend(split_csv(csv_targets));
            }
            Ok(OpsCommand::VmLabCheckKnownHosts {
                config: vm_lab::VmLabCheckKnownHostsConfig {
                    inventory_path: parser
                        .path_or_default("--inventory", vm_lab::default_inventory_path()),
                    vm_aliases,
                    raw_targets,
                    select_all: parser.has_flag("--all"),
                    known_hosts_path: parser
                        .path_or_default("--known-hosts-file", vm_lab::default_known_hosts_path()),
                },
            })
        }
        "vm-lab-preflight" => {
            let mut vm_aliases = collect_repeated_option_values(&args[1..], "--vm");
            if let Some(csv_vms) = parser.value("--vms") {
                vm_aliases.extend(split_csv(csv_vms));
            }
            let mut raw_targets = collect_repeated_option_values(&args[1..], "--target");
            if let Some(csv_targets) = parser.value("--targets") {
                raw_targets.extend(split_csv(csv_targets));
            }
            let mut require_commands =
                collect_repeated_option_values(&args[1..], "--require-command");
            if let Some(csv_commands) = parser.value("--require-commands") {
                require_commands.extend(split_csv(csv_commands));
            }
            Ok(OpsCommand::VmLabPreflight {
                config: vm_lab::VmLabPreflightConfig {
                    inventory_path: parser
                        .path_or_default("--inventory", vm_lab::default_inventory_path()),
                    vm_aliases,
                    raw_targets,
                    select_all: parser.has_flag("--all"),
                    ssh_identity_file: parser.optional_path("--ssh-identity-file"),
                    known_hosts_path: parser.optional_path("--known-hosts-file"),
                    require_same_network: parser.has_flag("--require-same-network"),
                    require_commands,
                    min_free_kib: parser.parse_u64_or_default("--min-free-kib", 1_048_576)?,
                    require_rustynet_installed: parser.has_flag("--require-rustynet-installed"),
                    timeout_secs: parser.parse_u64_or_default("--timeout-secs", 120)?,
                },
            })
        }
        "vm-lab-status" => {
            let mut vm_aliases = collect_repeated_option_values(&args[1..], "--vm");
            if let Some(csv_vms) = parser.value("--vms") {
                vm_aliases.extend(split_csv(csv_vms));
            }
            let mut raw_targets = collect_repeated_option_values(&args[1..], "--target");
            if let Some(csv_targets) = parser.value("--targets") {
                raw_targets.extend(split_csv(csv_targets));
            }
            Ok(OpsCommand::VmLabStatus {
                config: vm_lab::VmLabStatusConfig {
                    inventory_path: parser
                        .path_or_default("--inventory", vm_lab::default_inventory_path()),
                    vm_aliases,
                    raw_targets,
                    select_all: parser.has_flag("--all"),
                    ssh_user: parser.value("--ssh-user"),
                    ssh_identity_file: parser.optional_path("--ssh-identity-file"),
                    known_hosts_path: parser.optional_path("--known-hosts-file"),
                    timeout_secs: parser.parse_u64_or_default("--timeout-secs", 120)?,
                },
            })
        }
        "vm-lab-stop" | "vm-lab-shutdown" => {
            let mut vm_aliases = collect_repeated_option_values(&args[1..], "--vm");
            if let Some(csv_vms) = parser.value("--vms") {
                vm_aliases.extend(split_csv(csv_vms));
            }
            Ok(OpsCommand::VmLabStop {
                config: vm_lab::VmLabStopConfig {
                    inventory_path: parser
                        .path_or_default("--inventory", vm_lab::default_inventory_path()),
                    vm_aliases,
                    select_all: parser.has_flag("--all"),
                    utmctl_path: parser
                        .path_or_default("--utmctl-path", vm_lab::default_utmctl_path()),
                    timeout_secs: parser.parse_u64_or_default("--timeout-secs", 60)?,
                },
            })
        }
        "vm-lab-restart" => {
            let mut vm_aliases = collect_repeated_option_values(&args[1..], "--vm");
            if let Some(csv_vms) = parser.value("--vms") {
                vm_aliases.extend(split_csv(csv_vms));
            }
            let mut raw_targets = collect_repeated_option_values(&args[1..], "--target");
            if let Some(csv_targets) = parser.value("--targets") {
                raw_targets.extend(split_csv(csv_targets));
            }
            Ok(OpsCommand::VmLabRestart {
                config: vm_lab::VmLabRestartConfig {
                    inventory_path: parser
                        .path_or_default("--inventory", vm_lab::default_inventory_path()),
                    vm_aliases,
                    raw_targets,
                    select_all: parser.has_flag("--all"),
                    utmctl_path: parser
                        .path_or_default("--utmctl-path", vm_lab::default_utmctl_path()),
                    service: parser.value("--service"),
                    wait_ready: parser.has_flag("--wait-ready"),
                    ssh_port: u16::try_from(parser.parse_u64_or_default("--ssh-port", 22)?)
                        .map_err(|_| "invalid value for --ssh-port: must fit in u16".to_string())?,
                    ready_timeout_secs: parser
                        .parse_u64_or_default("--wait-ready-timeout-secs", 300)?,
                    ssh_user: parser.value("--ssh-user"),
                    ssh_identity_file: parser.optional_path("--ssh-identity-file"),
                    known_hosts_path: parser.optional_path("--known-hosts-file"),
                    timeout_secs: parser.parse_u64_or_default("--timeout-secs", 120)?,
                    json_output: parser.has_flag("--json"),
                    report_dir: parser.optional_path("--report-dir"),
                },
            })
        }
        "vm-lab-collect-artifacts" => {
            let mut vm_aliases = collect_repeated_option_values(&args[1..], "--vm");
            if let Some(csv_vms) = parser.value("--vms") {
                vm_aliases.extend(split_csv(csv_vms));
            }
            let mut raw_targets = collect_repeated_option_values(&args[1..], "--target");
            if let Some(csv_targets) = parser.value("--targets") {
                raw_targets.extend(split_csv(csv_targets));
            }
            Ok(OpsCommand::VmLabCollectArtifacts {
                config: vm_lab::VmLabCollectArtifactsConfig {
                    inventory_path: parser
                        .path_or_default("--inventory", vm_lab::default_inventory_path()),
                    vm_aliases,
                    raw_targets,
                    select_all: parser.has_flag("--all"),
                    ssh_user: parser.value("--ssh-user"),
                    ssh_identity_file: parser.optional_path("--ssh-identity-file"),
                    known_hosts_path: parser.optional_path("--known-hosts-file"),
                    output_dir: parser.required_path("--output-dir")?,
                    timeout_secs: parser.parse_u64_or_default("--timeout-secs", 300)?,
                },
            })
        }
        "vm-lab-write-topology" => {
            let mut vm_aliases = collect_repeated_option_values(&args[1..], "--vm");
            if let Some(csv_vms) = parser.value("--vms") {
                vm_aliases.extend(split_csv(csv_vms));
            }
            Ok(OpsCommand::VmLabWriteTopology {
                config: vm_lab::VmLabWriteTopologyConfig {
                    inventory_path: parser
                        .path_or_default("--inventory", vm_lab::default_inventory_path()),
                    output_path: parser.required_path("--output")?,
                    vm_aliases,
                    select_all: parser.has_flag("--all"),
                    require_same_network: parser.has_flag("--require-same-network"),
                    suite: parser.required("--suite")?,
                },
            })
        }
        "vm-lab-issue-and-distribute-state" => Ok(OpsCommand::VmLabIssueAndDistributeState {
            config: vm_lab::VmLabIssueDistributeStateConfig {
                inventory_path: parser
                    .path_or_default("--inventory", vm_lab::default_inventory_path()),
                topology_path: parser.required_path("--topology")?,
                authority_vm: parser.required("--authority-vm")?,
                ssh_user: parser.value("--ssh-user"),
                ssh_identity_file: parser.optional_path("--ssh-identity-file"),
                known_hosts_path: parser.optional_path("--known-hosts-file"),
                timeout_secs: parser.parse_u64_or_default("--timeout-secs", 1800)?,
            },
        }),
        "vm-lab-run-suite" => {
            let mut vm_aliases = collect_repeated_option_values(&args[1..], "--vm");
            if let Some(csv_vms) = parser.value("--vms") {
                vm_aliases.extend(split_csv(csv_vms));
            }
            Ok(OpsCommand::VmLabRunSuite {
                config: vm_lab::VmLabRunSuiteConfig {
                    inventory_path: parser
                        .path_or_default("--inventory", vm_lab::default_inventory_path()),
                    suite: parser.required("--suite")?,
                    topology_path: parser.optional_path("--topology"),
                    profile_path: parser.optional_path("--profile"),
                    ssh_identity_file: parser.required_path("--ssh-identity-file")?,
                    vm_aliases,
                    select_all: parser.has_flag("--all"),
                    dry_run: parser.has_flag("--dry-run"),
                    nat_profile: parser.value("--nat-profile"),
                    impairment_profile: parser.value("--impairment-profile"),
                    report_dir: parser.optional_path("--report-dir"),
                    timeout_secs: parser.parse_u64_or_default("--timeout-secs", 86_400)?,
                },
            })
        }
        "vm-lab-bootstrap-phase" => {
            let mut vm_aliases = collect_repeated_option_values(&args[1..], "--vm");
            if let Some(csv_vms) = parser.value("--vms") {
                vm_aliases.extend(split_csv(csv_vms));
            }
            let mut raw_targets = collect_repeated_option_values(&args[1..], "--target");
            if let Some(csv_targets) = parser.value("--targets") {
                raw_targets.extend(split_csv(csv_targets));
            }
            Ok(OpsCommand::VmLabBootstrapPhase {
                config: vm_lab::VmLabBootstrapPhaseConfig {
                    inventory_path: parser
                        .path_or_default("--inventory", vm_lab::default_inventory_path()),
                    vm_aliases,
                    raw_targets,
                    select_all: parser.has_flag("--all"),
                    require_same_network: parser.has_flag("--require-same-network"),
                    phase: parser.required("--phase")?,
                    repo_url: parser.value("--repo-url"),
                    local_source_dir: parser.optional_path("--local-source-dir"),
                    dest_dir: parser.value("--dest-dir"),
                    branch: parser
                        .value("--branch")
                        .unwrap_or_else(|| "main".to_string()),
                    remote: parser
                        .value("--remote")
                        .unwrap_or_else(|| "origin".to_string()),
                    ssh_user: parser.value("--ssh-user"),
                    ssh_identity_file: parser.optional_path("--ssh-identity-file"),
                    known_hosts_path: parser.optional_path("--known-hosts-file"),
                    timeout_secs: parser.parse_u64_or_default("--timeout-secs", 1800)?,
                },
            })
        }
        "rebind-linux-fresh-install-os-matrix-inputs" => {
            Ok(OpsCommand::RebindLinuxFreshInstallOsMatrixInputs {
                config: ops_fresh_install_os_matrix::RebindLinuxFreshInstallOsMatrixInputsConfig {
                    dest_dir: parser.required_path("--dest-dir")?,
                    bootstrap_log: parser.required_path("--bootstrap-log")?,
                    baseline_log: parser.required_path("--baseline-log")?,
                    two_hop_report: parser.required_path("--two-hop-report")?,
                    role_switch_report: parser.required_path("--role-switch-report")?,
                    lan_toggle_report: parser.required_path("--lan-toggle-report")?,
                    exit_handoff_report: parser.required_path("--exit-handoff-report")?,
                },
            })
        }
        "generate-linux-fresh-install-os-matrix-report" => {
            Ok(OpsCommand::GenerateLinuxFreshInstallOsMatrixReport {
                config:
                    ops_fresh_install_os_matrix::GenerateLinuxFreshInstallOsMatrixReportConfig {
                        output: parser.required_path("--output")?,
                        environment: parser.required("--environment")?,
                        source_mode: parser.required("--source-mode")?,
                        expected_git_commit_file: parser
                            .required_path("--expected-git-commit-file")?,
                        git_status_file: parser.required_path("--git-status-file")?,
                        bootstrap_log: parser.required_path("--bootstrap-log")?,
                        baseline_log: parser.required_path("--baseline-log")?,
                        two_hop_report: parser.required_path("--two-hop-report")?,
                        role_switch_report: parser.required_path("--role-switch-report")?,
                        lan_toggle_report: parser.required_path("--lan-toggle-report")?,
                        exit_handoff_report: parser.required_path("--exit-handoff-report")?,
                        exit_node_id: parser.required("--exit-node-id")?,
                        client_node_id: parser.required("--client-node-id")?,
                        ubuntu_node_id: parser.required("--ubuntu-node-id")?,
                        fedora_node_id: parser.required("--fedora-node-id")?,
                        mint_node_id: parser.required("--mint-node-id")?,
                        debian_os_version: parser
                            .value("--debian-os-version")
                            .unwrap_or_else(|| "Debian 13".to_string()),
                        ubuntu_os_version: parser
                            .value("--ubuntu-os-version")
                            .unwrap_or_else(|| "Ubuntu".to_string()),
                        fedora_os_version: parser
                            .value("--fedora-os-version")
                            .unwrap_or_else(|| "Fedora".to_string()),
                        mint_os_version: parser
                            .value("--mint-os-version")
                            .unwrap_or_else(|| "Linux Mint".to_string()),
                    },
            })
        }
        "verify-linux-fresh-install-os-matrix-readiness" => {
            Ok(OpsCommand::VerifyLinuxFreshInstallOsMatrixReadiness {
                config:
                    ops_fresh_install_os_matrix::VerifyLinuxFreshInstallOsMatrixReadinessConfig {
                        report_path: parser.required_path("--report-path")?,
                        max_age_seconds: parser
                            .parse_u64_or_default("--max-age-seconds", 604800)?,
                        profile: parser
                            .value("--profile")
                            .unwrap_or_else(|| "cross_platform".to_string()),
                        expected_git_commit: parser
                            .value("--expected-git-commit")
                            .unwrap_or_default(),
                    },
            })
        }
        "write-fresh-install-os-matrix-readiness-fixtures" => {
            let now_unix_raw = parser.required("--now-unix")?;
            let now_unix = now_unix_raw
                .parse::<u64>()
                .map_err(|err| format!("invalid value for --now-unix: {err}"))?;
            Ok(OpsCommand::WriteFreshInstallOsMatrixReadinessFixtures {
                config:
                    ops_fresh_install_os_matrix::WriteFreshInstallOsMatrixReadinessFixturesConfig {
                        output_dir: parser.required_path("--output-dir")?,
                        head_commit: parser.required("--head-commit")?,
                        stale_commit: parser.required("--stale-commit")?,
                        now_unix,
                    },
            })
        }
        "write-unsigned-release-provenance" => Ok(OpsCommand::WriteUnsignedReleaseProvenance {
            config: ops_phase9::WriteUnsignedReleaseProvenanceConfig {
                input_path: parser.required_path("--input")?,
                output_path: parser.required_path("--output")?,
            },
        }),
        "sign-release-artifact" => {
            if args.len() != 1 {
                return Err("ops sign-release-artifact does not accept options".to_string());
            }
            Ok(OpsCommand::SignReleaseArtifact)
        }
        "verify-release-artifact" => {
            if args.len() != 1 {
                return Err("ops verify-release-artifact does not accept options".to_string());
            }
            Ok(OpsCommand::VerifyReleaseArtifact)
        }
        "collect-platform-probe" => {
            if args.len() != 1 {
                return Err("ops collect-platform-probe does not accept options".to_string());
            }
            Ok(OpsCommand::CollectPlatformProbe)
        }
        "generate-platform-parity-report" => {
            if args.len() != 1 {
                return Err(
                    "ops generate-platform-parity-report does not accept options".to_string(),
                );
            }
            Ok(OpsCommand::GeneratePlatformParityReport)
        }
        "collect-platform-parity-bundle" => {
            if args.len() != 1 {
                return Err(
                    "ops collect-platform-parity-bundle does not accept options".to_string()
                );
            }
            Ok(OpsCommand::CollectPlatformParityBundle)
        }
        "install-systemd" => {
            if args.len() != 1 {
                return Err("ops install-systemd does not accept options".to_string());
            }
            Ok(OpsCommand::InstallSystemd)
        }
        "prepare-system-dirs" => {
            if args.len() != 1 {
                return Err("ops prepare-system-dirs does not accept options".to_string());
            }
            Ok(OpsCommand::PrepareSystemDirs)
        }
        "restart-runtime-service" => {
            if args.len() != 1 {
                return Err("ops restart-runtime-service does not accept options".to_string());
            }
            Ok(OpsCommand::RestartRuntimeService)
        }
        "stop-runtime-service" => {
            if args.len() != 1 {
                return Err("ops stop-runtime-service does not accept options".to_string());
            }
            Ok(OpsCommand::StopRuntimeService)
        }
        "show-runtime-service-status" => {
            if args.len() != 1 {
                return Err("ops show-runtime-service-status does not accept options".to_string());
            }
            Ok(OpsCommand::ShowRuntimeServiceStatus)
        }
        "start-assignment-refresh-service" => {
            if args.len() != 1 {
                return Err(
                    "ops start-assignment-refresh-service does not accept options".to_string(),
                );
            }
            Ok(OpsCommand::StartAssignmentRefreshService)
        }
        "check-assignment-refresh-availability" => {
            if args.len() != 1 {
                return Err(
                    "ops check-assignment-refresh-availability does not accept options".to_string(),
                );
            }
            Ok(OpsCommand::CheckAssignmentRefreshAvailability)
        }
        "install-trust-material" => Ok(OpsCommand::InstallTrustMaterial {
            verifier_source: parser.required_path("--verifier-source")?,
            trust_source: parser.required_path("--trust-source")?,
            verifier_dest: parser.required_path("--verifier-dest")?,
            trust_dest: parser.required_path("--trust-dest")?,
            daemon_group: parser
                .value("--daemon-group")
                .unwrap_or_else(|| "rustynetd".to_string()),
        }),
        "apply-managed-dns-routing" => {
            if args.len() != 1 {
                return Err("ops apply-managed-dns-routing does not accept options".to_string());
            }
            Ok(OpsCommand::ApplyManagedDnsRouting)
        }
        "clear-managed-dns-routing" => {
            if args.len() != 1 {
                return Err("ops clear-managed-dns-routing does not accept options".to_string());
            }
            Ok(OpsCommand::ClearManagedDnsRouting)
        }
        "disconnect-cleanup" => {
            if args.len() != 1 {
                return Err("ops disconnect-cleanup does not accept options".to_string());
            }
            Ok(OpsCommand::DisconnectCleanup)
        }
        "apply-blind-exit-lockdown" => {
            if args.len() != 1 {
                return Err("ops apply-blind-exit-lockdown does not accept options".to_string());
            }
            Ok(OpsCommand::ApplyBlindExitLockdown)
        }
        "init-membership" => {
            if args.len() != 1 {
                return Err("ops init-membership does not accept options".to_string());
            }
            Ok(OpsCommand::InitMembership)
        }
        "secure-remove" => Ok(OpsCommand::SecureRemove {
            path: parser.required_path("--path")?,
        }),
        "ensure-signing-passphrase-material" => {
            if args.len() != 1 {
                return Err(
                    "ops ensure-signing-passphrase-material does not accept options".to_string(),
                );
            }
            Ok(OpsCommand::EnsureSigningPassphraseMaterial)
        }
        "ensure-local-trust-material" => Ok(OpsCommand::EnsureLocalTrustMaterial {
            signing_key_passphrase_path: parser.required_path("--signing-key-passphrase-file")?,
        }),
        "materialize-signing-passphrase" => Ok(OpsCommand::MaterializeSigningPassphrase {
            output_path: parser.required_path("--output")?,
        }),
        "materialize-signing-passphrase-temp" => {
            if args.len() != 1 {
                return Err(
                    "ops materialize-signing-passphrase-temp does not accept options".to_string(),
                );
            }
            Ok(OpsCommand::MaterializeSigningPassphraseTemp)
        }
        "set-assignment-refresh-exit-node" => Ok(OpsCommand::SetAssignmentRefreshExitNode {
            env_path: parser.path_or_default(
                "--env-path",
                PathBuf::from(DEFAULT_ASSIGNMENT_REFRESH_ENV_PATH),
            ),
            exit_node_id: parser.value("--exit-node-id").and_then(|value| {
                if value.trim().is_empty() {
                    None
                } else {
                    Some(value)
                }
            }),
        }),
        "force-local-assignment-refresh-now" => {
            if args.len() != 1 {
                return Err(
                    "ops force-local-assignment-refresh-now does not accept options".to_string(),
                );
            }
            Ok(OpsCommand::ForceLocalAssignmentRefreshNow)
        }
        "apply-lan-access-coupling" => {
            let enable = parse_bool_value(
                "--enable",
                parser
                    .value("--enable")
                    .unwrap_or_else(|| "false".to_string())
                    .as_str(),
            )?;
            let lan_routes = parser
                .value("--lan-routes")
                .map(split_csv)
                .unwrap_or_default();
            if enable && lan_routes.is_empty() {
                return Err(
                    "ops apply-lan-access-coupling requires --lan-routes when --enable true"
                        .to_string(),
                );
            }
            Ok(OpsCommand::ApplyLanAccessCoupling {
                enable,
                lan_routes,
                assignment_refresh_env_path: parser.path_or_default(
                    "--env-path",
                    PathBuf::from(DEFAULT_ASSIGNMENT_REFRESH_ENV_PATH),
                ),
            })
        }
        "apply-role-coupling" => Ok(OpsCommand::ApplyRoleCoupling {
            target_role: parser.required("--target-role")?,
            preferred_exit_node_id: parser.value("--preferred-exit-node-id").and_then(|value| {
                if value.trim().is_empty() {
                    None
                } else {
                    Some(value)
                }
            }),
            enable_exit_advertise: parse_bool_value(
                "--enable-exit-advertise",
                parser
                    .value("--enable-exit-advertise")
                    .unwrap_or_else(|| "false".to_string())
                    .as_str(),
            )?,
            assignment_refresh_env_path: parser.path_or_default(
                "--env-path",
                PathBuf::from(DEFAULT_ASSIGNMENT_REFRESH_ENV_PATH),
            ),
            skip_client_exit_route_convergence_wait: parser
                .has_flag("--skip-client-exit-route-convergence-wait"),
        }),
        "peer-store-validate" => Ok(OpsCommand::PeerStoreValidate {
            config_dir: parser.required_path("--config-dir")?,
            peers_file: parser.required_path("--peers-file")?,
        }),
        "peer-store-list" => Ok(OpsCommand::PeerStoreList {
            config_dir: parser.required_path("--config-dir")?,
            peers_file: parser.required_path("--peers-file")?,
            role: parser.value("--role"),
            node_id: parser.value("--node-id"),
        }),
        "run-debian-two-node-e2e" => Ok(OpsCommand::RunDebianTwoNodeE2e {
            config: ops_e2e::DebianTwoNodeE2eConfig {
                exit_host: parser.required("--exit-host")?,
                client_host: parser.required("--client-host")?,
                ssh_user: parser
                    .value("--ssh-user")
                    .unwrap_or_else(|| "root".to_string()),
                ssh_port: parser
                    .value("--ssh-port")
                    .unwrap_or_else(|| "22".to_string())
                    .parse::<u16>()
                    .map_err(|err| format!("invalid --ssh-port value: {err}"))?,
                ssh_identity: parser.optional_path("--ssh-identity"),
                ssh_known_hosts_file: parser.optional_path("--ssh-known-hosts-file"),
                ssh_allow_cidrs: parser.required("--ssh-allow-cidrs")?,
                ssh_sudo_mode: ops_e2e::SshSudoMode::parse(
                    parser
                        .value("--ssh-sudo")
                        .unwrap_or_else(|| "auto".to_string())
                        .as_str(),
                )?,
                sudo_password_file: parser.optional_path("--sudo-password-file"),
                exit_node_id: parser
                    .value("--exit-node-id")
                    .unwrap_or_else(|| "exit-node".to_string()),
                client_node_id: parser
                    .value("--client-node-id")
                    .unwrap_or_else(|| "client-node".to_string()),
                network_id: parser
                    .value("--network-id")
                    .unwrap_or_else(|| "local-net".to_string()),
                remote_root: parser
                    .optional_path("--remote-root")
                    .unwrap_or_else(|| PathBuf::from("/opt/rustynet-clean")),
                repo_ref: parser
                    .value("--repo-ref")
                    .unwrap_or_else(|| "HEAD".to_string()),
                skip_apt: parser.has_flag("--skip-apt"),
                report_path: parser.optional_path("--report-path").unwrap_or_else(|| {
                    PathBuf::from("artifacts/phase10/debian_two_node_remote_validation.md")
                }),
            },
        }),
        "e2e-bootstrap-host" => Ok(OpsCommand::E2eBootstrapHost {
            role: parser.required("--role")?,
            node_id: parser.required("--node-id")?,
            network_id: parser.required("--network-id")?,
            src_dir: parser.required_path("--src-dir")?,
            ssh_allow_cidrs: parser.required("--ssh-allow-cidrs")?,
            skip_apt: parser.has_flag("--skip-apt"),
        }),
        "e2e-enforce-host" => Ok(OpsCommand::E2eEnforceHost {
            role: parser.required("--role")?,
            node_id: parser.required("--node-id")?,
            src_dir: parser.required_path("--src-dir")?,
            ssh_allow_cidrs: parser.required("--ssh-allow-cidrs")?,
        }),
        "e2e-membership-add" => Ok(OpsCommand::E2eMembershipAdd {
            client_node_id: parser.required("--client-node-id")?,
            client_pubkey_hex: parser.required("--client-pubkey-hex")?,
            owner_approver_id: parser.required("--owner-approver-id")?,
        }),
        "e2e-issue-assignments" => Ok(OpsCommand::E2eIssueAssignments {
            exit_node_id: parser.required("--exit-node-id")?,
            client_node_id: parser.required("--client-node-id")?,
            exit_endpoint: parser.required("--exit-endpoint")?,
            client_endpoint: parser.required("--client-endpoint")?,
            exit_pubkey_hex: parser.required("--exit-pubkey-hex")?,
            client_pubkey_hex: parser.required("--client-pubkey-hex")?,
            artifact_dir: parser.optional_path("--artifact-dir"),
        }),
        "e2e-issue-assignment-bundles-from-env" => {
            Ok(OpsCommand::E2eIssueAssignmentBundlesFromEnv {
                config: ops_e2e::E2eIssueAssignmentBundlesFromEnvConfig {
                    env_file: parser.required_path("--env-file")?,
                    issue_dir: parser
                        .optional_path("--issue-dir")
                        .unwrap_or_else(|| PathBuf::from("/run/rustynet/assignment-issue")),
                },
            })
        }
        "e2e-issue-traversal-bundles-from-env" => Ok(OpsCommand::E2eIssueTraversalBundlesFromEnv {
            config: ops_e2e::E2eIssueTraversalBundlesFromEnvConfig {
                env_file: parser.required_path("--env-file")?,
                issue_dir: parser
                    .optional_path("--issue-dir")
                    .unwrap_or_else(|| PathBuf::from("/run/rustynet/traversal-issue")),
            },
        }),
        "e2e-issue-dns-zone-bundles-from-env" => Ok(OpsCommand::E2eIssueDnsZoneBundlesFromEnv {
            config: ops_e2e::E2eIssueDnsZoneBundlesFromEnvConfig {
                env_file: parser.required_path("--env-file")?,
                issue_dir: parser
                    .optional_path("--issue-dir")
                    .unwrap_or_else(|| PathBuf::from("/run/rustynet/dns-zone-issue")),
            },
        }),
        _ => Err(format!("unknown ops subcommand: {subcommand}")),
    }
}

fn parse_membership_command(args: &[String]) -> Result<MembershipCommand, String> {
    if args.is_empty() {
        return Err("membership subcommand is required".to_string());
    }
    let subcommand = args[0].as_str();
    let parser = OptionParser::parse(&args[1..])?;
    let paths = parser.membership_paths();
    let now_unix = parser.parse_u64_or_default("--now", unix_now())?;

    match subcommand {
        "status" => Ok(MembershipCommand::Status { paths }),
        "verify-log" => {
            let audit_output_path = parser.path_or_default(
                "--audit-output",
                PathBuf::from("artifacts/membership/membership_audit_integrity.log"),
            );
            Ok(MembershipCommand::VerifyLog {
                paths,
                now_unix,
                audit_output_path,
            })
        }
        "generate-evidence" => Ok(MembershipCommand::GenerateEvidence {
            paths,
            now_unix,
            output_dir: parser
                .path_or_default("--output-dir", PathBuf::from("artifacts/membership")),
            environment: parser
                .value("--environment")
                .unwrap_or_else(|| "unknown".to_string()),
        }),
        "propose-add" => {
            let node_id = parser.required("--node-id")?;
            let node_pubkey_hex = parser.required("--node-pubkey")?;
            let owner = parser.required("--owner")?;
            let roles = parser
                .value("--roles")
                .map(split_csv)
                .unwrap_or_else(|| vec!["tag:members".to_string()]);
            let operation = MembershipOperation::AddNode(MembershipNode {
                node_id: node_id.clone(),
                node_pubkey_hex,
                owner,
                status: MembershipNodeStatus::Active,
                roles,
                joined_at_unix: now_unix,
                updated_at_unix: now_unix,
            });
            Ok(MembershipCommand::Propose {
                config: proposal_config(&parser, paths, operation, node_id)?,
            })
        }
        "propose-remove" => {
            let node_id = parser.required("--node-id")?;
            Ok(MembershipCommand::Propose {
                config: proposal_config(
                    &parser,
                    paths,
                    MembershipOperation::RemoveNode {
                        node_id: node_id.clone(),
                    },
                    node_id,
                )?,
            })
        }
        "propose-revoke" => {
            let node_id = parser.required("--node-id")?;
            Ok(MembershipCommand::Propose {
                config: proposal_config(
                    &parser,
                    paths,
                    MembershipOperation::RevokeNode {
                        node_id: node_id.clone(),
                    },
                    node_id,
                )?,
            })
        }
        "propose-restore" => {
            let node_id = parser.required("--node-id")?;
            Ok(MembershipCommand::Propose {
                config: proposal_config(
                    &parser,
                    paths,
                    MembershipOperation::RestoreNode {
                        node_id: node_id.clone(),
                    },
                    node_id,
                )?,
            })
        }
        "propose-rotate-key" => {
            let node_id = parser.required("--node-id")?;
            let new_pubkey_hex = parser.required("--new-pubkey")?;
            Ok(MembershipCommand::Propose {
                config: proposal_config(
                    &parser,
                    paths,
                    MembershipOperation::RotateNodeKey {
                        node_id: node_id.clone(),
                        new_pubkey_hex,
                    },
                    node_id,
                )?,
            })
        }
        "propose-set-quorum" => {
            let threshold = parser.parse_u8_required("--threshold")?;
            Ok(MembershipCommand::Propose {
                config: proposal_config(
                    &parser,
                    paths,
                    MembershipOperation::SetQuorum { threshold },
                    "quorum".to_string(),
                )?,
            })
        }
        "propose-rotate-approver" => {
            let approver_id = parser.required("--approver-id")?;
            let approver_pubkey_hex = parser.required("--approver-pubkey")?;
            let role = match parser.required("--role")?.as_str() {
                "owner" => MembershipApproverRole::Owner,
                "guardian" => MembershipApproverRole::Guardian,
                _ => return Err("invalid --role: expected owner|guardian".to_string()),
            };
            let status = match parser.value("--status").as_deref().unwrap_or("active") {
                "active" => MembershipApproverStatus::Active,
                "revoked" => MembershipApproverStatus::Revoked,
                _ => return Err("invalid --status: expected active|revoked".to_string()),
            };
            let operation = MembershipOperation::RotateApprover(MembershipApprover {
                approver_id: approver_id.clone(),
                approver_pubkey_hex,
                role,
                status,
                created_at_unix: now_unix,
            });
            Ok(MembershipCommand::Propose {
                config: proposal_config(&parser, paths, operation, approver_id)?,
            })
        }
        "sign-update" => Ok(MembershipCommand::SignUpdate {
            record_path: parser.required_path("--record")?,
            approver_id: parser.required("--approver-id")?,
            signing_key_path: parser.required_path("--signing-key")?,
            signing_key_passphrase_path: parser.required_path("--signing-key-passphrase-file")?,
            output_path: parser.required_path("--output")?,
            merge_from: parser.optional_path("--merge-from"),
        }),
        "verify-update" => Ok(MembershipCommand::VerifyUpdate {
            signed_update_path: parser.required_path("--signed-update")?,
            paths,
            now_unix,
            dry_run: parser.has_flag("--dry-run"),
        }),
        "apply-update" => Ok(MembershipCommand::ApplyUpdate {
            signed_update_path: parser.required_path("--signed-update")?,
            paths,
            now_unix,
            dry_run: parser.has_flag("--dry-run"),
        }),
        _ => Err(format!("unknown membership subcommand: {subcommand}")),
    }
}

fn parse_assignment_command(args: &[String]) -> Result<AssignmentCommand, String> {
    if args.is_empty() {
        return Err("assignment subcommand is required".to_string());
    }
    let subcommand = args[0].as_str();
    let parser = OptionParser::parse(&args[1..])?;
    match subcommand {
        "issue" => {
            let target_node_id = parser.required("--target-node-id")?;
            let output_path = parser.required_path("--output")?;
            let signing_secret_path = parser.required_path("--signing-secret")?;
            let signing_secret_passphrase_path =
                parser.required_path("--signing-secret-passphrase-file")?;
            let verifier_key_output_path = parser.optional_path("--verifier-key-output");
            let nodes = parse_assignment_nodes(parser.required("--nodes")?.as_str())?;
            let allow_pairs = parse_assignment_allow_pairs(parser.required("--allow")?.as_str())?;
            let mesh_cidr = parser
                .value("--mesh-cidr")
                .unwrap_or_else(|| "100.64.0.0/10".to_string());
            let exit_node_id = parser.value("--exit-node-id");
            let lan_routes = parser
                .value("--lan-routes")
                .map(split_csv)
                .unwrap_or_default();
            let generated_at_unix = parser.parse_u64_or_default("--generated-at", unix_now())?;
            let ttl_secs = parser.parse_u64_or_default("--ttl-secs", 300)?;
            let nonce = parser.parse_u64_or_default("--nonce", generate_assignment_nonce())?;

            validate_assignment_issue_config(
                nodes.as_slice(),
                allow_pairs.as_slice(),
                target_node_id.as_str(),
                exit_node_id.as_deref(),
            )?;

            Ok(AssignmentCommand::Issue(Box::new(AssignmentIssueCommand {
                signing_secret_path,
                signing_secret_passphrase_path,
                target_node_id,
                output_path,
                verifier_key_output_path,
                nodes,
                allow_pairs,
                mesh_cidr,
                exit_node_id,
                lan_routes,
                generated_at_unix,
                ttl_secs,
                nonce,
            })))
        }
        "verify" => Ok(AssignmentCommand::Verify(AssignmentVerifyCommand {
            bundle_path: parser.required_path("--bundle")?,
            verifier_key_path: parser.required_path("--verifier-key")?,
            watermark_path: parser.required_path("--watermark")?,
            expected_node_id: parser.value("--expected-node-id"),
            max_age_secs: parser
                .parse_u64_or_default("--max-age-secs", DEFAULT_AUTO_TUNNEL_MAX_AGE_SECS)?,
            max_clock_skew_secs: parser.parse_u64_or_default(
                "--max-clock-skew-secs",
                DEFAULT_SIGNED_STATE_MAX_CLOCK_SKEW_SECS,
            )?,
        })),
        "init-signing-secret" => {
            let output_path = parser.required_path("--output")?;
            let signing_secret_passphrase_path =
                parser.required_path("--signing-secret-passphrase-file")?;
            let length_bytes = parser.parse_u64_or_default("--length-bytes", 32)?;
            if length_bytes < 32 {
                return Err("signing secret length must be >= 32 bytes".to_string());
            }
            if length_bytes > 4096 {
                return Err("signing secret length must be <= 4096 bytes".to_string());
            }
            Ok(AssignmentCommand::InitSigningSecret {
                output_path,
                signing_secret_passphrase_path,
                length_bytes: length_bytes as usize,
                force: parser.has_flag("--force"),
            })
        }
        _ => Err(format!("unknown assignment subcommand: {subcommand}")),
    }
}

fn parse_trust_command(args: &[String]) -> Result<TrustCommand, String> {
    if args.is_empty() {
        return Err("trust subcommand is required".to_string());
    }
    let subcommand = args[0].as_str();
    let parser = OptionParser::parse(&args[1..])?;
    match subcommand {
        "keygen" => Ok(TrustCommand::Keygen {
            signing_key_path: parser.required_path("--signing-key-output")?,
            signing_key_passphrase_path: parser.required_path("--signing-key-passphrase-file")?,
            verifier_key_output_path: parser.required_path("--verifier-key-output")?,
            force: parser.has_flag("--force"),
        }),
        "export-verifier-key" => Ok(TrustCommand::ExportVerifierKey {
            signing_key_path: parser.required_path("--signing-key")?,
            signing_key_passphrase_path: parser.required_path("--signing-key-passphrase-file")?,
            output_path: parser.required_path("--output")?,
        }),
        "issue" => Ok(TrustCommand::Issue {
            signing_key_path: parser.required_path("--signing-key")?,
            signing_key_passphrase_path: parser.required_path("--signing-key-passphrase-file")?,
            output_path: parser.required_path("--output")?,
            updated_at_unix: parser.parse_u64_or_default("--updated-at-unix", unix_now())?,
            nonce: parser.parse_u64_or_default("--nonce", generate_assignment_nonce())?,
        }),
        "verify" => Ok(TrustCommand::Verify {
            evidence_path: parser.required_path("--evidence")?,
            verifier_key_path: parser.required_path("--verifier-key")?,
            watermark_path: parser.required_path("--watermark")?,
            max_age_secs: parser
                .parse_u64_or_default("--max-age-secs", DEFAULT_TRUST_MAX_AGE_SECS)?,
            max_clock_skew_secs: parser.parse_u64_or_default(
                "--max-clock-skew-secs",
                DEFAULT_SIGNED_STATE_MAX_CLOCK_SKEW_SECS,
            )?,
        }),
        _ => Err(format!("unknown trust subcommand: {subcommand}")),
    }
}

fn parse_dns_zone_command(action: &str, args: &[String]) -> Result<CliCommand, String> {
    let parser = OptionParser::parse(args)?;
    match action {
        "issue" => Ok(CliCommand::DnsZoneIssue(Box::new(DnsZoneIssueCommand {
            signing_secret_path: parser.required_path("--signing-secret")?,
            signing_secret_passphrase_path: parser
                .required_path("--signing-secret-passphrase-file")?,
            subject_node_id: parser.required("--subject-node-id")?,
            output_path: parser.required_path("--output")?,
            verifier_key_output_path: parser.optional_path("--verifier-key-output"),
            nodes: parse_assignment_nodes(parser.required("--nodes")?.as_str())?,
            allow_pairs: parse_assignment_allow_pairs(parser.required("--allow")?.as_str())?,
            zone_name: parser
                .value("--zone-name")
                .unwrap_or_else(|| "rustynet".to_string()),
            records_path: parser.required_path("--records-manifest")?,
            generated_at_unix: parser.parse_u64_or_default("--generated-at", unix_now())?,
            ttl_secs: parser.parse_u64_or_default("--ttl-secs", 300)?,
            nonce: parser.parse_u64_or_default("--nonce", generate_assignment_nonce())?,
        }))),
        "verify" => Ok(CliCommand::DnsZoneVerify {
            bundle_path: parser.required_path("--bundle")?,
            verifier_key_path: parser.required_path("--verifier-key")?,
            expected_zone_name: parser.value("--expected-zone-name"),
            expected_subject_node_id: parser.value("--expected-subject-node-id"),
        }),
        _ => Err(format!("unknown dns zone subcommand: {action}")),
    }
}

fn parse_traversal_command(args: &[String]) -> Result<TraversalCommand, String> {
    if args.is_empty() {
        return Err("traversal subcommand is required".to_string());
    }
    let subcommand = args[0].as_str();
    let parser = OptionParser::parse(&args[1..])?;
    match subcommand {
        "issue" => Ok(TraversalCommand::Issue(Box::new(TraversalIssueCommand {
            signing_secret_path: parser.required_path("--signing-secret")?,
            signing_secret_passphrase_path: parser
                .required_path("--signing-secret-passphrase-file")?,
            source_node_id: parser.required("--source-node-id")?,
            target_node_id: parser.required("--target-node-id")?,
            output_path: parser.required_path("--output")?,
            verifier_key_output_path: parser.optional_path("--verifier-key-output"),
            nodes: parse_assignment_nodes(&parser.required("--nodes")?)?,
            allow_pairs: parse_assignment_allow_pairs(&parser.required("--allow")?)?,
            candidates: parse_traversal_candidates(&parser.required("--candidates")?)?,
            generated_at_unix: parser.parse_u64_or_default("--generated-at", unix_now())?,
            ttl_secs: parser.parse_u64_or_default("--ttl-secs", 120)?,
            nonce: parser.parse_u64_or_default("--nonce", generate_assignment_nonce())?,
        }))),
        "verify" => Ok(TraversalCommand::Verify(TraversalVerifyCommand {
            bundle_path: parser.required_path("--bundle")?,
            verifier_key_path: parser.required_path("--verifier-key")?,
            watermark_path: parser.required_path("--watermark")?,
            expected_source_node_id: parser.value("--expected-source-node-id"),
            max_age_secs: parser
                .parse_u64_or_default("--max-age-secs", DEFAULT_TRAVERSAL_MAX_AGE_SECS)?,
            max_clock_skew_secs: parser.parse_u64_or_default(
                "--max-clock-skew-secs",
                DEFAULT_SIGNED_STATE_MAX_CLOCK_SKEW_SECS,
            )?,
        })),
        _ => Err(format!("unknown traversal subcommand: {subcommand}")),
    }
}

fn proposal_config(
    parser: &OptionParser,
    paths: MembershipPaths,
    operation: MembershipOperation,
    target: String,
) -> Result<ProposalConfig, String> {
    Ok(ProposalConfig {
        paths,
        output_path: parser.required_path("--output")?,
        operation,
        target,
        update_id: parser
            .value("--update-id")
            .unwrap_or_else(generate_update_id),
        reason_code: parser
            .value("--reason")
            .unwrap_or_else(|| "operator_request".to_string()),
        policy_context: parser.value("--policy-context"),
        expires_in_secs: parser.parse_u64_or_default("--expires-in", 300)?,
    })
}

fn execute(command: CliCommand) -> Result<String, String> {
    match command {
        CliCommand::Help => Ok(help_text()),
        CliCommand::Login => Ok("login: open auth URL and complete device enrollment".to_string()),
        CliCommand::OperatorMenu => execute_operator_menu(),
        CliCommand::StateRefresh => execute_state_refresh(),
        CliCommand::DnsZoneIssue(command) => execute_dns_zone_issue(*command),
        CliCommand::DnsZoneVerify {
            bundle_path,
            verifier_key_path,
            expected_zone_name,
            expected_subject_node_id,
        } => execute_dns_zone_verify(
            bundle_path,
            verifier_key_path,
            expected_zone_name,
            expected_subject_node_id,
        ),
        CliCommand::Traversal(command) => execute_traversal(*command),
        CliCommand::Assignment(command) => execute_assignment(*command),
        CliCommand::Membership(command) => execute_membership(*command),
        CliCommand::Trust(command) => execute_trust(*command),
        CliCommand::Ops(command) => execute_ops(*command),
        other => {
            let ipc_command = to_ipc_command(other);
            match send_command(ipc_command) {
                Ok(response) => {
                    if response.ok {
                        Ok(response.message)
                    } else {
                        Err(response.message)
                    }
                }
                Err(err) => Err(format!("daemon unreachable: {err}")),
            }
        }
    }
}

fn execute_state_refresh() -> Result<String, String> {
    let response = send_command(IpcCommand::StateRefresh)?;
    if !response.ok {
        return Err(response.message);
    }
    reconcile_persisted_lan_blackhole_routes_after_refresh()?;
    Ok(response.message)
}

fn execute_traversal(command: TraversalCommand) -> Result<String, String> {
    match command {
        TraversalCommand::Issue(command) => execute_traversal_issue(*command),
        TraversalCommand::Verify(command) => execute_traversal_verify(command),
    }
}

fn execute_assignment(command: AssignmentCommand) -> Result<String, String> {
    match command {
        AssignmentCommand::Issue(issue) => {
            let AssignmentIssueCommand {
                signing_secret_path,
                signing_secret_passphrase_path,
                target_node_id,
                output_path,
                verifier_key_output_path,
                nodes,
                allow_pairs,
                mesh_cidr,
                exit_node_id,
                lan_routes,
                generated_at_unix,
                ttl_secs,
                nonce,
            } = *issue;
            let signing_secret = load_assignment_signing_secret(
                &signing_secret_path,
                &signing_secret_passphrase_path,
            )?;

            let policy = PolicySet {
                rules: allow_pairs
                    .iter()
                    .map(|pair| PolicyRule {
                        src: format!("node:{}", pair.source_node_id),
                        dst: format!("node:{}", pair.destination_node_id),
                        protocol: Protocol::Any,
                        action: RuleAction::Allow,
                    })
                    .collect::<Vec<_>>(),
            };

            let core = ControlPlaneCore::new(signing_secret, policy);
            for node in nodes {
                core.nodes
                    .upsert(NodeMetadata {
                        node_id: node.node_id,
                        hostname: node.hostname,
                        os: node.os,
                        tags: node.tags,
                        owner: node.owner,
                        endpoint: node.endpoint,
                        last_seen_unix: generated_at_unix,
                        public_key: node.public_key,
                    })
                    .map_err(|err| format!("register node failed: {err}"))?;
            }

            let bundle = core
                .signed_auto_tunnel_bundle(AutoTunnelBundleRequest {
                    node_id: target_node_id.clone(),
                    generated_at_unix,
                    ttl_secs,
                    nonce,
                    mesh_cidr,
                    exit_node_id: exit_node_id.clone(),
                    lan_routes,
                })
                .map_err(|err| format!("issue assignment bundle failed: {err}"))?;

            let wire = ControlPlaneCore::signed_auto_tunnel_bundle_to_wire(&bundle);
            write_text_file(&output_path, &wire)?;

            let verifier_key_hex = core.assignment_verifier_key_hex();
            if let Some(verifier_path) = verifier_key_output_path.as_ref() {
                write_text_file(verifier_path, &format!("{verifier_key_hex}\n"))?;
            }

            Ok(format!(
                "assignment bundle issued: target={} output={} generated_at_unix={} expires_at_unix={} verifier_key_output={}",
                target_node_id,
                output_path.display(),
                bundle.generated_at_unix,
                bundle.expires_at_unix,
                verifier_key_output_path
                    .as_ref()
                    .map(|path| path.display().to_string())
                    .unwrap_or_else(|| "<not_written>".to_string())
            ))
        }
        AssignmentCommand::Verify(command) => execute_assignment_verify(command),
        AssignmentCommand::InitSigningSecret {
            output_path,
            signing_secret_passphrase_path,
            length_bytes,
            force,
        } => {
            let mut secret = vec![0u8; length_bytes];
            fill_os_random_bytes(secret.as_mut_slice(), "assignment signing secret")?;
            persist_encrypted_secret_material(
                &output_path,
                secret.as_slice(),
                &signing_secret_passphrase_path,
                "assignment signing secret",
                force,
            )?;
            secret.zeroize();
            Ok(format!(
                "assignment signing secret initialized: output={} length_bytes={}",
                output_path.display(),
                length_bytes
            ))
        }
    }
}

fn execute_dns_zone_issue(command: DnsZoneIssueCommand) -> Result<String, String> {
    let DnsZoneIssueCommand {
        signing_secret_path,
        signing_secret_passphrase_path,
        subject_node_id,
        output_path,
        verifier_key_output_path,
        nodes,
        allow_pairs,
        zone_name,
        records_path,
        generated_at_unix,
        ttl_secs,
        nonce,
    } = command;
    ensure_regular_file_no_symlink(&records_path, "dns zone records manifest")?;
    let records = load_dns_zone_records_manifest(&records_path)?;
    let signing_secret =
        load_assignment_signing_secret(&signing_secret_path, &signing_secret_passphrase_path)?;

    let policy = PolicySet {
        rules: allow_pairs
            .iter()
            .map(|pair| PolicyRule {
                src: format!("node:{}", pair.source_node_id),
                dst: format!("node:{}", pair.destination_node_id),
                protocol: Protocol::Any,
                action: RuleAction::Allow,
            })
            .collect::<Vec<_>>(),
    };

    let core = ControlPlaneCore::new(signing_secret, policy);
    for node in nodes {
        core.nodes
            .upsert(NodeMetadata {
                node_id: node.node_id,
                hostname: node.hostname,
                os: node.os,
                tags: node.tags,
                owner: node.owner,
                endpoint: node.endpoint,
                last_seen_unix: generated_at_unix,
                public_key: node.public_key,
            })
            .map_err(|err| format!("register node failed: {err}"))?;
    }

    let bundle = core
        .signed_dns_zone_bundle(rustynet_control::SignedDnsZoneBundleRequest {
            zone_name,
            subject_node_id: subject_node_id.clone(),
            generated_at_unix,
            ttl_secs,
            nonce,
            records: records
                .into_iter()
                .map(|record| rustynet_control::DnsRecordRequest {
                    label: record.label,
                    target_node_id: record.target_node_id,
                    ttl_secs: record.ttl_secs,
                    rr_type: rustynet_control::DnsRecordType::A,
                    target_addr_kind: rustynet_control::DnsTargetAddrKind::MeshIpv4,
                    aliases: record.aliases,
                })
                .collect(),
        })
        .map_err(|err| format!("issue dns zone bundle failed: {err}"))?;

    let wire = ControlPlaneCore::signed_dns_zone_bundle_to_wire(&bundle);
    write_text_file(&output_path, &wire)?;

    let verifier_key_hex = core.dns_zone_verifier_key_hex();
    if let Some(verifier_path) = verifier_key_output_path.as_ref() {
        write_text_file(verifier_path, &format!("{verifier_key_hex}\n"))?;
    }

    Ok(format!(
        "dns zone bundle issued: zone_name={} subject_node_id={} output={} generated_at_unix={} expires_at_unix={} record_count={} verifier_key_output={}",
        bundle.zone_name,
        bundle.subject_node_id,
        output_path.display(),
        bundle.generated_at_unix,
        bundle.expires_at_unix,
        bundle.records.len(),
        verifier_key_output_path
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "<not_written>".to_string())
    ))
}

fn execute_traversal_issue(command: TraversalIssueCommand) -> Result<String, String> {
    let TraversalIssueCommand {
        signing_secret_path,
        signing_secret_passphrase_path,
        source_node_id,
        target_node_id,
        output_path,
        verifier_key_output_path,
        nodes,
        allow_pairs,
        candidates,
        generated_at_unix,
        ttl_secs,
        nonce,
    } = command;
    let signing_secret =
        load_assignment_signing_secret(&signing_secret_path, &signing_secret_passphrase_path)?;

    let policy = PolicySet {
        rules: allow_pairs
            .iter()
            .map(|pair| PolicyRule {
                src: format!("node:{}", pair.source_node_id),
                dst: format!("node:{}", pair.destination_node_id),
                protocol: Protocol::Any,
                action: RuleAction::Allow,
            })
            .collect::<Vec<_>>(),
    };

    let core = ControlPlaneCore::new(signing_secret, policy);
    for node in nodes {
        core.nodes
            .upsert(NodeMetadata {
                node_id: node.node_id,
                hostname: node.hostname,
                os: node.os,
                tags: node.tags,
                owner: node.owner,
                endpoint: node.endpoint,
                last_seen_unix: generated_at_unix,
                public_key: node.public_key,
            })
            .map_err(|err| format!("register node failed: {err}"))?;
    }

    let bundle = core
        .signed_endpoint_hint_bundle(EndpointHintBundleRequest {
            source_node_id: source_node_id.clone(),
            target_node_id: target_node_id.clone(),
            generated_at_unix,
            ttl_secs,
            nonce,
            candidates: candidates
                .into_iter()
                .map(|candidate| EndpointHintCandidate {
                    candidate_type: candidate.candidate_type,
                    endpoint: candidate.endpoint,
                    relay_id: candidate.relay_id,
                    priority: candidate.priority,
                })
                .collect(),
        })
        .map_err(|err| format!("issue traversal bundle failed: {err}"))?;

    let wire = ControlPlaneCore::signed_endpoint_hint_bundle_to_wire(&bundle);
    write_text_file(&output_path, &wire)?;

    let verifier_key_hex = core.endpoint_hint_verifier_key_hex();
    if let Some(verifier_path) = verifier_key_output_path.as_ref() {
        write_text_file(verifier_path, &format!("{verifier_key_hex}\n"))?;
    }

    Ok(format!(
        "traversal bundle issued: source_node_id={} target_node_id={} output={} generated_at_unix={} expires_at_unix={} verifier_key_output={}",
        source_node_id,
        target_node_id,
        output_path.display(),
        bundle.generated_at_unix,
        bundle.expires_at_unix,
        verifier_key_output_path
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "<not_written>".to_string())
    ))
}

fn execute_assignment_verify(command: AssignmentVerifyCommand) -> Result<String, String> {
    let AssignmentVerifyCommand {
        bundle_path,
        verifier_key_path,
        watermark_path,
        expected_node_id,
        max_age_secs,
        max_clock_skew_secs,
    } = command;
    ensure_regular_file_no_symlink(&bundle_path, "assignment bundle")?;
    ensure_regular_file_no_symlink(&verifier_key_path, "assignment verifier key")?;
    ensure_regular_file_no_symlink(&watermark_path, "assignment watermark")?;

    let report = verify_signed_assignment_state_artifact(
        &bundle_path,
        &verifier_key_path,
        &watermark_path,
        max_age_secs,
        max_clock_skew_secs,
        expected_node_id.as_deref(),
    )?;
    Ok(format!(
        "assignment verification passed: node_id={} generated_at_unix={} nonce={} peer_count={} route_count={} selected_exit_node={} payload_digest_sha256={}",
        report.node_id,
        report.generated_at_unix,
        report.nonce,
        report.peer_count,
        report.route_count,
        report.selected_exit_node.as_deref().unwrap_or("none"),
        report.payload_digest_sha256
    ))
}

fn execute_traversal_verify(command: TraversalVerifyCommand) -> Result<String, String> {
    let TraversalVerifyCommand {
        bundle_path,
        verifier_key_path,
        watermark_path,
        expected_source_node_id,
        max_age_secs,
        max_clock_skew_secs,
    } = command;
    ensure_regular_file_no_symlink(&bundle_path, "traversal bundle")?;
    ensure_regular_file_no_symlink(&verifier_key_path, "traversal verifier key")?;
    ensure_regular_file_no_symlink(&watermark_path, "traversal watermark")?;

    let report = verify_signed_traversal_state_artifact(
        &bundle_path,
        &verifier_key_path,
        &watermark_path,
        max_age_secs,
        max_clock_skew_secs,
        expected_source_node_id.as_deref(),
    )?;
    Ok(format!(
        "traversal verification passed: generated_at_unix={} expires_at_unix={} nonce={} bundle_count={} sources={} targets={} payload_digest_sha256={}",
        report.generated_at_unix,
        report.expires_at_unix,
        report.nonce,
        report.bundle_count,
        report.source_node_ids.join(","),
        report.target_node_ids.join(","),
        report.payload_digest_sha256
    ))
}

fn execute_dns_zone_verify(
    bundle_path: PathBuf,
    verifier_key_path: PathBuf,
    expected_zone_name: Option<String>,
    expected_subject_node_id: Option<String>,
) -> Result<String, String> {
    ensure_regular_file_no_symlink(&bundle_path, "dns zone bundle")?;
    ensure_regular_file_no_symlink(&verifier_key_path, "dns zone verifier key")?;

    let bundle_wire = fs::read_to_string(&bundle_path)
        .map_err(|err| format!("read dns zone bundle failed: {err}"))?;
    let bundle = parse_signed_dns_zone_bundle_wire(&bundle_wire)
        .map_err(|err| format!("dns zone bundle parse failed: {err}"))?;

    let verifier_contents = fs::read_to_string(&verifier_key_path)
        .map_err(|err| format!("read dns zone verifier key failed: {err}"))?;
    let verifying_key = parse_dns_zone_verifying_key(&verifier_contents)
        .map_err(|err| format!("dns zone verifier key parse failed: {err}"))?;
    verify_dns_zone_bundle(&bundle, &verifying_key)
        .map_err(|err| format!("dns zone verification failed: {err}"))?;

    if let Some(expected_zone_name) = expected_zone_name {
        let normalized = canonicalize_dns_zone_name(&expected_zone_name)
            .map_err(|err| format!("expected zone name is invalid: {err}"))?;
        if bundle.zone_name != normalized {
            return Err(format!(
                "dns zone bundle zone_name mismatch: expected {}, got {}",
                normalized, bundle.zone_name
            ));
        }
    }
    if let Some(expected_subject_node_id) = expected_subject_node_id
        && bundle.subject_node_id != expected_subject_node_id
    {
        return Err(format!(
            "dns zone bundle subject_node_id mismatch: expected {}, got {}",
            expected_subject_node_id, bundle.subject_node_id
        ));
    }

    Ok(format!(
        "dns zone verification passed: zone_name={} subject_node_id={} generated_at_unix={} expires_at_unix={} record_count={}",
        bundle.zone_name,
        bundle.subject_node_id,
        bundle.generated_at_unix,
        bundle.expires_at_unix,
        bundle.records.len()
    ))
}

fn execute_operator_menu() -> Result<String, String> {
    let stdin = io::stdin();
    loop {
        println!();
        println!("Rustynet Operator Menu");
        println!("  1) Status");
        println!("  2) Netcheck");
        println!("  3) Exit node off");
        println!("  4) Advertise default exit route (0.0.0.0/0)");
        println!("  5) LAN access on");
        println!("  6) LAN access off");
        println!("  0) Exit");
        print!("Choose an option: ");
        io::stdout()
            .flush()
            .map_err(|err| format!("flush stdout failed: {err}"))?;

        let mut choice = String::new();
        stdin
            .read_line(&mut choice)
            .map_err(|err| format!("read menu input failed: {err}"))?;
        if choice.is_empty() {
            return Ok("operator menu exited (stdin closed)".to_string());
        }

        match choice.trim() {
            "1" => render_operator_action("status", send_command(IpcCommand::Status)),
            "2" => render_operator_action("netcheck", send_command(IpcCommand::Netcheck)),
            "3" => render_operator_action("exit-node off", send_command(IpcCommand::ExitNodeOff)),
            "4" => render_operator_action(
                "route advertise 0.0.0.0/0",
                send_command(IpcCommand::RouteAdvertise("0.0.0.0/0".to_string())),
            ),
            "5" => render_operator_action("lan-access on", send_command(IpcCommand::LanAccessOn)),
            "6" => render_operator_action("lan-access off", send_command(IpcCommand::LanAccessOff)),
            "0" => return Ok("operator menu exited".to_string()),
            _ => println!("unknown option"),
        }
    }
}

fn render_operator_action(action: &str, result: Result<IpcResponse, String>) {
    match result {
        Ok(response) if response.ok => println!("{action}: {}", response.message),
        Ok(response) => println!("{action}: failed: {}", response.message),
        Err(err) => println!("{action}: daemon unreachable: {err}"),
    }
}

fn execute_membership(command: MembershipCommand) -> Result<String, String> {
    match command {
        MembershipCommand::Status { paths } => {
            let (_, _, state) = load_current_membership_state(&paths, unix_now())?;
            let active_nodes = state.active_nodes().into_iter().collect::<Vec<_>>();
            let root = state.state_root_hex().map_err(|err| err.to_string())?;
            Ok(format!(
                "membership status: network_id={} epoch={} quorum_threshold={} active_nodes={} state_root={}",
                state.network_id,
                state.epoch,
                state.quorum_threshold,
                active_nodes.join(","),
                root
            ))
        }
        MembershipCommand::Propose { config } => {
            let (_, _, state) = load_current_membership_state(&config.paths, unix_now())?;
            let prev_root = state.state_root_hex().map_err(|err| err.to_string())?;
            let mut candidate = state.clone();
            // Reducer legality is checked using state transition during apply later.
            // For propose, compute candidate root using deterministic transition helper.
            candidate =
                rustynet_control::membership::preview_next_state(&candidate, &config.operation)
                    .map_err(|err| err.to_string())?;
            let new_root = candidate.state_root_hex().map_err(|err| err.to_string())?;
            let created_at_unix = unix_now();
            let expires_at_unix = created_at_unix.saturating_add(config.expires_in_secs);
            if expires_at_unix <= created_at_unix {
                return Err("invalid expiry window: --expires-in must be > 0".to_string());
            }
            let record = MembershipUpdateRecord {
                network_id: state.network_id,
                update_id: config.update_id,
                operation: config.operation,
                target: config.target,
                prev_state_root: prev_root,
                new_state_root: new_root,
                epoch_prev: state.epoch,
                epoch_new: state.epoch.saturating_add(1),
                created_at_unix,
                expires_at_unix,
                reason_code: config.reason_code,
                policy_context: config.policy_context,
            };
            let payload = encode_update_record(&record).map_err(|err| err.to_string())?;
            write_text_file(&config.output_path, &payload)?;
            Ok(format!(
                "membership proposal written: {} operation={} target={} epoch_new={}",
                config.output_path.display(),
                record.operation.operation_name_for_cli(),
                record.target,
                record.epoch_new
            ))
        }
        MembershipCommand::SignUpdate {
            record_path,
            approver_id,
            signing_key_path,
            signing_key_passphrase_path,
            output_path,
            merge_from,
        } => {
            let record_payload = fs::read_to_string(&record_path)
                .map_err(|err| format!("read record failed: {err}"))?;
            let record = decode_update_record(&record_payload).map_err(|err| err.to_string())?;
            let signing_key = load_signing_key(&signing_key_path, &signing_key_passphrase_path)?;
            let signature = sign_update_record(&record, approver_id.as_str(), &signing_key)
                .map_err(|err| format!("sign update failed: {err}"))?;

            let mut signatures = if let Some(path) = merge_from {
                let signed_payload = fs::read_to_string(&path)
                    .map_err(|err| format!("read merge-from update failed: {err}"))?;
                let existing =
                    decode_signed_update(&signed_payload).map_err(|err| err.to_string())?;
                if existing.record != record {
                    return Err(
                        "merge-from update record mismatch: payloads must be identical".to_string(),
                    );
                }
                existing.approver_signatures
            } else {
                Vec::new()
            };

            if signatures
                .iter()
                .any(|entry| entry.approver_id == approver_id)
            {
                return Err("duplicate approver signature is not allowed".to_string());
            }
            signatures.push(signature);

            let signed = SignedMembershipUpdate {
                record,
                approver_signatures: signatures,
            };
            let envelope = encode_signed_update(&signed).map_err(|err| err.to_string())?;
            write_text_file(&output_path, &envelope)?;
            Ok(format!(
                "membership signed update written: {} signatures={}",
                output_path.display(),
                signed.approver_signatures.len()
            ))
        }
        MembershipCommand::VerifyUpdate {
            signed_update_path,
            paths,
            now_unix,
            dry_run,
        } => {
            let (_, entries, state) = load_current_membership_state(&paths, now_unix)?;
            let signed_payload = fs::read_to_string(&signed_update_path)
                .map_err(|err| format!("read signed update failed: {err}"))?;
            let signed = decode_signed_update(&signed_payload).map_err(|err| err.to_string())?;
            let mut replay_cache = replay_cache_from_entries(&entries)?;
            let next = apply_signed_update(&state, &signed, now_unix, &mut replay_cache)
                .map_err(|err| err.to_string())?;
            let next_root = next.state_root_hex().map_err(|err| err.to_string())?;
            let mode = if dry_run { "dry-run" } else { "verify" };
            Ok(format!(
                "membership update {mode} passed: epoch_new={} state_root={next_root}",
                next.epoch
            ))
        }
        MembershipCommand::ApplyUpdate {
            signed_update_path,
            paths,
            now_unix,
            dry_run,
        } => {
            let (_, entries, state) = load_current_membership_state(&paths, now_unix)?;
            let signed_payload = fs::read_to_string(&signed_update_path)
                .map_err(|err| format!("read signed update failed: {err}"))?;
            let signed = decode_signed_update(&signed_payload).map_err(|err| err.to_string())?;
            let mut replay_cache = replay_cache_from_entries(&entries)?;
            let next = apply_signed_update(&state, &signed, now_unix, &mut replay_cache)
                .map_err(|err| err.to_string())?;
            if dry_run {
                return Ok(format!(
                    "membership apply dry-run passed: epoch_new={}",
                    next.epoch
                ));
            }
            append_membership_log_entry(&paths.log_path, &signed).map_err(|err| err.to_string())?;
            persist_membership_snapshot(&paths.snapshot_path, &next)
                .map_err(|err| err.to_string())?;
            Ok(format!(
                "membership update applied: snapshot={} log={} epoch_new={}",
                paths.snapshot_path.display(),
                paths.log_path.display(),
                next.epoch
            ))
        }
        MembershipCommand::VerifyLog {
            paths,
            now_unix,
            audit_output_path,
        } => {
            let (_, entries, state) = load_current_membership_state(&paths, now_unix)?;
            write_membership_audit_log(&audit_output_path, &entries)
                .map_err(|err| err.to_string())?;
            Ok(format!(
                "membership log verification passed: entries={} epoch={} audit={}",
                entries.len(),
                state.epoch,
                audit_output_path.display()
            ))
        }
        MembershipCommand::GenerateEvidence {
            paths,
            now_unix,
            output_dir,
            environment,
        } => emit_membership_evidence(paths, now_unix, output_dir, environment),
    }
}

fn execute_trust(command: TrustCommand) -> Result<String, String> {
    match command {
        TrustCommand::Keygen {
            signing_key_path,
            signing_key_passphrase_path,
            verifier_key_output_path,
            force,
        } => {
            let mut seed = [0u8; 32];
            fill_os_random_bytes(&mut seed, "trust signing key")?;
            persist_encrypted_secret_material(
                &signing_key_path,
                &seed,
                &signing_key_passphrase_path,
                "trust signing key",
                force,
            )?;
            let signing_key = SigningKey::from_bytes(&seed);
            seed.zeroize();
            let verifier_key_hex = hex_bytes(signing_key.verifying_key().as_bytes());
            write_text_file(&verifier_key_output_path, &format!("{verifier_key_hex}\n"))?;
            Ok(format!(
                "trust signing key initialized: signing_key={} verifier_key_output={}",
                signing_key_path.display(),
                verifier_key_output_path.display()
            ))
        }
        TrustCommand::ExportVerifierKey {
            signing_key_path,
            signing_key_passphrase_path,
            output_path,
        } => {
            let signing_key = load_signing_key(&signing_key_path, &signing_key_passphrase_path)?;
            let verifier_key_hex = hex_bytes(signing_key.verifying_key().as_bytes());
            write_text_file(&output_path, &format!("{verifier_key_hex}\n"))?;
            Ok(format!(
                "trust verifier key exported: signing_key={} output={}",
                signing_key_path.display(),
                output_path.display()
            ))
        }
        TrustCommand::Issue {
            signing_key_path,
            signing_key_passphrase_path,
            output_path,
            updated_at_unix,
            nonce,
        } => {
            let signing_key = load_signing_key(&signing_key_path, &signing_key_passphrase_path)?;
            let payload = format!(
                "version=2\ntls13_valid=true\nsigned_control_valid=true\nsigned_data_age_secs=0\nclock_skew_secs=0\nupdated_at_unix={updated_at_unix}\nnonce={nonce}\n"
            );
            let signature = signing_key.sign(payload.as_bytes());
            let body = format!("{payload}signature={}\n", hex_bytes(&signature.to_bytes()));
            write_text_file(&output_path, &body)?;
            Ok(format!(
                "trust evidence issued: output={} updated_at_unix={} nonce={}",
                output_path.display(),
                updated_at_unix,
                nonce
            ))
        }
        TrustCommand::Verify {
            evidence_path,
            verifier_key_path,
            watermark_path,
            max_age_secs,
            max_clock_skew_secs,
        } => execute_trust_verify(
            evidence_path,
            verifier_key_path,
            watermark_path,
            max_age_secs,
            max_clock_skew_secs,
        ),
    }
}

fn execute_trust_verify(
    evidence_path: PathBuf,
    verifier_key_path: PathBuf,
    watermark_path: PathBuf,
    max_age_secs: u64,
    max_clock_skew_secs: u64,
) -> Result<String, String> {
    ensure_regular_file_no_symlink(&evidence_path, "trust evidence")?;
    ensure_regular_file_no_symlink(&verifier_key_path, "trust verifier key")?;
    ensure_regular_file_no_symlink(&watermark_path, "trust watermark")?;

    let report = verify_signed_trust_state_artifact(
        &evidence_path,
        &verifier_key_path,
        &watermark_path,
        max_age_secs,
        max_clock_skew_secs,
    )?;
    Ok(format!(
        "trust verification passed: updated_at_unix={} nonce={} tls13_valid={} signed_control_valid={} signed_data_age_secs={} clock_skew_secs={} payload_digest_sha256={}",
        report.updated_at_unix,
        report.nonce,
        report.tls13_valid,
        report.signed_control_valid,
        report.signed_data_age_secs,
        report.clock_skew_secs,
        report.payload_digest_sha256
    ))
}

fn execute_ops(command: OpsCommand) -> Result<String, String> {
    match command {
        OpsCommand::VerifyRuntimeBinaryCustody => execute_ops_verify_runtime_binary_custody(),
        OpsCommand::WriteDaemonEnv {
            config_path,
            egress_interface,
        } => ops_write_daemon_env::execute_ops_write_daemon_env(config_path, egress_interface),
        OpsCommand::RefreshTrust => execute_ops_refresh_trust(),
        OpsCommand::RefreshSignedTrust => execute_ops_refresh_signed_trust(),
        OpsCommand::BootstrapTunnelCustody => execute_ops_bootstrap_wireguard_custody(),
        OpsCommand::RefreshAssignment => execute_ops_refresh_assignment(),
        OpsCommand::StateRefreshIfSocketPresent => execute_ops_state_refresh_if_socket_present(),
        OpsCommand::CollectPhase1MeasuredInput => {
            ops_phase1::execute_ops_collect_phase1_measured_input()
        }
        OpsCommand::RunPhase1Baseline => ops_phase1::execute_ops_run_phase1_baseline(),
        OpsCommand::PrepareAdvisoryDb { config } => {
            ops_ci_release_perf::execute_ops_prepare_advisory_db(config)
        }
        OpsCommand::RunPhase1CiGates => ops_ci_release_perf::execute_ops_run_phase1_ci_gates(),
        OpsCommand::RunPhase9CiGates => ops_ci_release_perf::execute_ops_run_phase9_ci_gates(),
        OpsCommand::RunPhase10CiGates => ops_ci_release_perf::execute_ops_run_phase10_ci_gates(),
        OpsCommand::RunMembershipCiGates => {
            ops_ci_release_perf::execute_ops_run_membership_ci_gates()
        }
        OpsCommand::RunSupplyChainIntegrityGates => {
            ops_ci_release_perf::execute_ops_run_supply_chain_integrity_gates()
        }
        OpsCommand::RunSecurityRegressionGates => {
            ops_ci_release_perf::execute_ops_run_security_regression_gates()
        }
        OpsCommand::RunActiveNetworkSecurityGates => {
            let config = ops_ci_release_perf::active_network_security_config_from_env()?;
            ops_ci_release_perf::execute_ops_run_active_network_security_gates(config)
        }
        OpsCommand::RunPhase10Hp2Gates => {
            ops_ci_release_perf::execute_ops_run_phase10_hp2_gates()
        }
        OpsCommand::GenerateReleaseSbom => ops_ci_release_perf::execute_ops_generate_release_sbom(),
        OpsCommand::CreateReleaseProvenance { config } => {
            ops_ci_release_perf::execute_ops_create_release_provenance(config)
        }
        OpsCommand::RunPhase3Baseline => ops_ci_release_perf::execute_ops_run_phase3_baseline(),
        OpsCommand::RunFuzzSmoke => ops_ci_release_perf::execute_ops_run_fuzz_smoke(),
        OpsCommand::CheckNoUnsafeRustSources { config } => {
            ops_phase1::execute_ops_check_no_unsafe_rust_sources(config)
        }
        OpsCommand::CheckDependencyExceptions { config } => {
            ops_phase1::execute_ops_check_dependency_exceptions(config)
        }
        OpsCommand::CheckPerfRegression { config } => {
            ops_phase1::execute_ops_check_perf_regression(config)
        }
        OpsCommand::CheckSecretsHygiene { config } => {
            ops_phase1::execute_ops_check_secrets_hygiene(config)
        }
        OpsCommand::CollectPhase9RawEvidence => {
            ops_phase9::execute_ops_collect_phase9_raw_evidence()
        }
        OpsCommand::GeneratePhase9Artifacts => ops_phase9::execute_ops_generate_phase9_artifacts(),
        OpsCommand::VerifyPhase9Readiness => ops_phase9::execute_ops_verify_phase9_readiness(),
        OpsCommand::VerifyPhase9Evidence => ops_phase9::execute_ops_verify_phase9_evidence(),
        OpsCommand::GeneratePhase10Artifacts => {
            ops_phase9::execute_ops_generate_phase10_artifacts()
        }
        OpsCommand::VerifyPhase10Readiness => ops_phase9::execute_ops_verify_phase10_readiness(),
        OpsCommand::VerifyPhase10Provenance => ops_phase9::execute_ops_verify_phase10_provenance(),
        OpsCommand::WritePhase10Hp2TraversalReports { config } => {
            ops_phase9::execute_ops_write_phase10_hp2_traversal_reports(config)
        }
        OpsCommand::VerifyPhase6PlatformReadiness => {
            ops_phase9::execute_ops_verify_phase6_platform_readiness()
        }
        OpsCommand::VerifyPhase6ParityEvidence => {
            ops_phase9::execute_ops_verify_phase6_parity_evidence()
        }
        OpsCommand::VerifyRequiredTestOutput { config } => {
            ops_phase9::execute_ops_verify_required_test_output(config)
        }
        OpsCommand::GenerateCrossNetworkRemoteExitReport { config } => {
            ops_cross_network_reports::execute_ops_generate_cross_network_remote_exit_report(config)
        }
        OpsCommand::ValidateCrossNetworkRemoteExitReports { config } => {
            ops_cross_network_reports::execute_ops_validate_cross_network_remote_exit_reports(
                config,
            )
        }
        OpsCommand::ValidateCrossNetworkNatMatrix { config } => {
            ops_cross_network_reports::execute_ops_validate_cross_network_nat_matrix(config)
        }
        OpsCommand::ReadCrossNetworkReportFields { config } => {
            ops_cross_network_reports::execute_ops_read_cross_network_report_fields(config)
        }
        OpsCommand::ClassifyCrossNetworkTopology { config } => {
            ops_cross_network_reports::execute_ops_classify_cross_network_topology(config)
        }
        OpsCommand::ChooseCrossNetworkRoamAlias { config } => {
            ops_cross_network_reports::execute_ops_choose_cross_network_roam_alias(config)
        }
        OpsCommand::ValidateIpv4Address { config } => {
            ops_cross_network_reports::execute_ops_validate_ipv4_address(config)
        }
        OpsCommand::WriteCrossNetworkSoakMonitorSummary { config } => {
            ops_cross_network_reports::execute_ops_write_cross_network_soak_monitor_summary(config)
        }
        OpsCommand::CheckLocalFileMode { config } => {
            ops_live_lab_orchestrator::execute_ops_check_local_file_mode(config)
        }
        OpsCommand::RedactForensicsText => {
            ops_live_lab_orchestrator::execute_ops_redact_forensics_text()
        }
        OpsCommand::WriteCrossNetworkForensicsManifest { config } => {
            ops_live_lab_orchestrator::execute_ops_write_cross_network_forensics_manifest(config)
        }
        OpsCommand::WriteLiveLabStageArtifactIndex { config } => {
            ops_live_lab_orchestrator::execute_ops_write_live_lab_stage_artifact_index(config)
        }
        OpsCommand::Sha256File { config } => {
            ops_live_lab_orchestrator::execute_ops_sha256_file(config)
        }
        OpsCommand::ValidateCrossNetworkForensicsBundle { config } => {
            ops_live_lab_orchestrator::execute_ops_validate_cross_network_forensics_bundle(config)
        }
        OpsCommand::WriteCrossNetworkPreflightReport { config } => {
            ops_live_lab_orchestrator::execute_ops_write_cross_network_preflight_report(config)
        }
        OpsCommand::WriteLiveLinuxRebootRecoveryReport { config } => {
            ops_live_lab_orchestrator::execute_ops_write_live_linux_reboot_recovery_report(config)
        }
        OpsCommand::WriteLiveLinuxLabRunSummary { config } => {
            ops_live_lab_orchestrator::execute_ops_write_live_linux_lab_run_summary(config)
        }
        OpsCommand::ScanIpv4PortRange { config } => {
            ops_live_lab_orchestrator::execute_ops_scan_ipv4_port_range(config)
        }
        OpsCommand::UpdateRoleSwitchHostResult { config } => {
            ops_live_lab_orchestrator::execute_ops_update_role_switch_host_result(config)
        }
        OpsCommand::WriteRoleSwitchMatrixReport { config } => {
            ops_live_lab_orchestrator::execute_ops_write_role_switch_matrix_report(config)
        }
        OpsCommand::WriteLiveLinuxServerIpBypassReport { config } => {
            ops_live_lab_orchestrator::execute_ops_write_live_linux_server_ip_bypass_report(config)
        }
        OpsCommand::WriteLiveLinuxControlSurfaceReport { config } => {
            ops_live_lab_orchestrator::execute_ops_write_live_linux_control_surface_report(config)
        }
        OpsCommand::RewriteAssignmentPeerEndpointIp { config } => {
            ops_live_lab_orchestrator::execute_ops_rewrite_assignment_peer_endpoint_ip(config)
        }
        OpsCommand::RewriteAssignmentMeshCidr { config } => {
            ops_live_lab_orchestrator::execute_ops_rewrite_assignment_mesh_cidr(config)
        }
        OpsCommand::WriteLiveLinuxEndpointHijackReport { config } => {
            ops_live_lab_orchestrator::execute_ops_write_live_linux_endpoint_hijack_report(config)
        }
        OpsCommand::WriteRealWireguardExitnodeE2eReport { config } => {
            ops_live_lab_orchestrator::execute_ops_write_real_wireguard_exitnode_e2e_report(config)
        }
        OpsCommand::WriteRealWireguardNoLeakUnderLoadReport { config } => {
            ops_live_lab_orchestrator::execute_ops_write_real_wireguard_no_leak_under_load_report(
                config,
            )
        }
        OpsCommand::VerifyNoLeakDataplaneReport { config } => {
            ops_live_lab_orchestrator::execute_ops_verify_no_leak_dataplane_report(config)
        }
        OpsCommand::E2eDnsQuery { config } => {
            ops_live_lab_orchestrator::execute_ops_e2e_dns_query(config)
        }
        OpsCommand::E2eHttpProbeServer { config } => {
            ops_live_lab_orchestrator::execute_ops_e2e_http_probe_server(config)
        }
        OpsCommand::E2eHttpProbeClient { config } => {
            ops_live_lab_orchestrator::execute_ops_e2e_http_probe_client(config)
        }
        OpsCommand::ReadJsonField { config } => {
            ops_live_lab_orchestrator::execute_ops_read_json_field(config)
        }
        OpsCommand::ExtractManagedDnsExpectedIp { config } => {
            ops_live_lab_orchestrator::execute_ops_extract_managed_dns_expected_ip(config)
        }
        OpsCommand::WriteActiveNetworkSignedStateTamperReport { config } => {
            ops_live_lab_orchestrator::execute_ops_write_active_network_signed_state_tamper_report(
                config,
            )
        }
        OpsCommand::WriteActiveNetworkRoguePathHijackReport { config } => {
            ops_live_lab_orchestrator::execute_ops_write_active_network_rogue_path_hijack_report(
                config,
            )
        }
        OpsCommand::ValidateNetworkDiscoveryBundle { config } => {
            ops_network_discovery::execute_ops_validate_network_discovery_bundle(config)
        }
        OpsCommand::GenerateLiveLinuxLabFailureDigest { config } => {
            ops_live_lab_failure_digest::execute_ops_generate_live_linux_lab_failure_digest(config)
        }
        OpsCommand::VmLabList { config } => vm_lab::execute_ops_vm_lab_list(config),
        OpsCommand::VmLabDiscoverLocalUtm { config } => {
            vm_lab::execute_ops_vm_lab_discover_local_utm(config)
        }
        OpsCommand::VmLabDiscoverLocalUtmSummary { config } => {
            vm_lab::execute_ops_vm_lab_discover_local_utm_summary(config)
        }
        OpsCommand::VmLabStart { config } => vm_lab::execute_ops_vm_lab_start(config),
        OpsCommand::VmLabSyncRepo { config } => vm_lab::execute_ops_vm_lab_sync_repo(config),
        OpsCommand::VmLabSyncBootstrap { config } => {
            vm_lab::execute_ops_vm_lab_sync_bootstrap(config)
        }
        OpsCommand::VmLabRun { config } => vm_lab::execute_ops_vm_lab_run(config, "ran"),
        OpsCommand::VmLabBootstrap { config } => {
            vm_lab::execute_ops_vm_lab_run(config, "bootstrapped")
        }
        OpsCommand::VmLabWriteLiveLabProfile { config } => {
            vm_lab::execute_ops_vm_lab_write_live_lab_profile(config)
        }
        OpsCommand::VmLabSetupLiveLab { config } => {
            vm_lab::execute_ops_vm_lab_setup_live_lab(config)
        }
        OpsCommand::VmLabOrchestrateLiveLab { config } => {
            vm_lab::execute_ops_vm_lab_orchestrate_live_lab(config)
        }
        OpsCommand::VmLabValidateLiveLabProfile { config } => {
            vm_lab::execute_ops_vm_lab_validate_live_lab_profile(config)
        }
        OpsCommand::VmLabDiagnoseLiveLabFailure { config } => {
            vm_lab::execute_ops_vm_lab_diagnose_live_lab_failure(config)
        }
        OpsCommand::VmLabDiffLiveLabRuns { config } => {
            vm_lab::execute_ops_vm_lab_diff_live_lab_runs(config)
        }
        OpsCommand::VmLabIterateLiveLab { config } => {
            vm_lab::execute_ops_vm_lab_iterate_live_lab(config)
        }
        OpsCommand::VmLabRunLiveLab { config } => vm_lab::execute_ops_vm_lab_run_live_lab(config),
        OpsCommand::VmLabCheckKnownHosts { config } => {
            vm_lab::execute_ops_vm_lab_check_known_hosts(config)
        }
        OpsCommand::VmLabPreflight { config } => vm_lab::execute_ops_vm_lab_preflight(config),
        OpsCommand::VmLabStatus { config } => vm_lab::execute_ops_vm_lab_status(config),
        OpsCommand::VmLabStop { config } => vm_lab::execute_ops_vm_lab_stop(config),
        OpsCommand::VmLabRestart { config } => vm_lab::execute_ops_vm_lab_restart(config),
        OpsCommand::VmLabCollectArtifacts { config } => {
            vm_lab::execute_ops_vm_lab_collect_artifacts(config)
        }
        OpsCommand::VmLabWriteTopology { config } => {
            vm_lab::execute_ops_vm_lab_write_topology(config)
        }
        OpsCommand::VmLabIssueAndDistributeState { config } => {
            vm_lab::execute_ops_vm_lab_issue_and_distribute_state(config)
        }
        OpsCommand::VmLabRunSuite { config } => vm_lab::execute_ops_vm_lab_run_suite(config),
        OpsCommand::VmLabBootstrapPhase { config } => {
            vm_lab::execute_ops_vm_lab_bootstrap_phase(config)
        }
        OpsCommand::RebindLinuxFreshInstallOsMatrixInputs { config } => {
            ops_fresh_install_os_matrix::execute_ops_rebind_linux_fresh_install_os_matrix_inputs(
                config,
            )
        }
        OpsCommand::GenerateLinuxFreshInstallOsMatrixReport { config } => {
            ops_fresh_install_os_matrix::execute_ops_generate_linux_fresh_install_os_matrix_report(
                config,
            )
        }
        OpsCommand::VerifyLinuxFreshInstallOsMatrixReadiness { config } => {
            ops_fresh_install_os_matrix::execute_ops_verify_linux_fresh_install_os_matrix_readiness(
                config,
            )
        }
        OpsCommand::WriteFreshInstallOsMatrixReadinessFixtures { config } => {
            ops_fresh_install_os_matrix::execute_ops_write_fresh_install_os_matrix_readiness_fixtures(
                config,
            )
        }
        OpsCommand::WriteUnsignedReleaseProvenance { config } => {
            ops_phase9::execute_ops_write_unsigned_release_provenance(config)
        }
        OpsCommand::SignReleaseArtifact => ops_phase9::execute_ops_sign_release_artifact(),
        OpsCommand::VerifyReleaseArtifact => ops_phase9::execute_ops_verify_release_artifact(),
        OpsCommand::CollectPlatformProbe => execute_ops_collect_platform_probe(),
        OpsCommand::GeneratePlatformParityReport => execute_ops_generate_platform_parity_report(),
        OpsCommand::CollectPlatformParityBundle => execute_ops_collect_platform_parity_bundle(),
        OpsCommand::InstallSystemd => ops_install_systemd::execute_ops_install_systemd(),
        OpsCommand::PrepareSystemDirs => execute_ops_prepare_system_dirs(),
        OpsCommand::RestartRuntimeService => execute_ops_restart_runtime_service(),
        OpsCommand::StopRuntimeService => execute_ops_stop_runtime_service(),
        OpsCommand::ShowRuntimeServiceStatus => execute_ops_show_runtime_service_status(),
        OpsCommand::StartAssignmentRefreshService => execute_ops_start_assignment_refresh_service(),
        OpsCommand::CheckAssignmentRefreshAvailability => {
            execute_ops_check_assignment_refresh_availability()
        }
        OpsCommand::InstallTrustMaterial {
            verifier_source,
            trust_source,
            verifier_dest,
            trust_dest,
            daemon_group,
        } => execute_ops_install_trust_material(
            verifier_source,
            trust_source,
            verifier_dest,
            trust_dest,
            daemon_group,
        ),
        OpsCommand::ApplyManagedDnsRouting => execute_ops_apply_managed_dns_routing(),
        OpsCommand::ClearManagedDnsRouting => execute_ops_clear_managed_dns_routing(),
        OpsCommand::DisconnectCleanup => execute_ops_disconnect_cleanup(),
        OpsCommand::ApplyBlindExitLockdown => execute_ops_apply_blind_exit_lockdown(),
        OpsCommand::InitMembership => execute_ops_init_membership(),
        OpsCommand::SecureRemove { path } => execute_ops_secure_remove(path),
        OpsCommand::EnsureSigningPassphraseMaterial => {
            execute_ops_ensure_signing_passphrase_material()
        }
        OpsCommand::EnsureLocalTrustMaterial {
            signing_key_passphrase_path,
        } => execute_ops_ensure_local_trust_material(signing_key_passphrase_path),
        OpsCommand::MaterializeSigningPassphrase { output_path } => {
            execute_ops_materialize_signing_passphrase(output_path)
        }
        OpsCommand::MaterializeSigningPassphraseTemp => {
            execute_ops_materialize_signing_passphrase_temp()
        }
        OpsCommand::SetAssignmentRefreshExitNode {
            env_path,
            exit_node_id,
        } => execute_ops_set_assignment_refresh_exit_node(env_path, exit_node_id),
        OpsCommand::ForceLocalAssignmentRefreshNow => {
            execute_ops_force_local_assignment_refresh_now()
        }
        OpsCommand::ApplyLanAccessCoupling {
            enable,
            lan_routes,
            assignment_refresh_env_path,
        } => execute_ops_apply_lan_access_coupling(enable, lan_routes, assignment_refresh_env_path),
        OpsCommand::ApplyRoleCoupling {
            target_role,
            preferred_exit_node_id,
            enable_exit_advertise,
            assignment_refresh_env_path,
            skip_client_exit_route_convergence_wait,
        } => execute_ops_apply_role_coupling(
            target_role,
            preferred_exit_node_id,
            enable_exit_advertise,
            assignment_refresh_env_path,
            skip_client_exit_route_convergence_wait,
        ),
        OpsCommand::PeerStoreValidate {
            config_dir,
            peers_file,
        } => ops_peer_store::execute_ops_peer_store_validate(config_dir, peers_file),
        OpsCommand::PeerStoreList {
            config_dir,
            peers_file,
            role,
            node_id,
        } => ops_peer_store::execute_ops_peer_store_list(config_dir, peers_file, role, node_id),
        OpsCommand::RunDebianTwoNodeE2e { config } => {
            ops_e2e::execute_ops_run_debian_two_node_e2e(config)
        }
        OpsCommand::E2eBootstrapHost {
            role,
            node_id,
            network_id,
            src_dir,
            ssh_allow_cidrs,
            skip_apt,
        } => ops_e2e::execute_ops_e2e_bootstrap_host(
            role,
            node_id,
            network_id,
            src_dir,
            ssh_allow_cidrs,
            skip_apt,
        ),
        OpsCommand::E2eEnforceHost {
            role,
            node_id,
            src_dir,
            ssh_allow_cidrs,
        } => ops_e2e::execute_ops_e2e_enforce_host(role, node_id, src_dir, ssh_allow_cidrs),
        OpsCommand::E2eMembershipAdd {
            client_node_id,
            client_pubkey_hex,
            owner_approver_id,
        } => ops_e2e::execute_ops_e2e_membership_add(
            client_node_id,
            client_pubkey_hex,
            owner_approver_id,
        ),
        OpsCommand::E2eIssueAssignments {
            exit_node_id,
            client_node_id,
            exit_endpoint,
            client_endpoint,
            exit_pubkey_hex,
            client_pubkey_hex,
            artifact_dir,
        } => ops_e2e::execute_ops_e2e_issue_assignments(
            exit_node_id,
            client_node_id,
            exit_endpoint,
            client_endpoint,
            exit_pubkey_hex,
            client_pubkey_hex,
            artifact_dir,
        ),
        OpsCommand::E2eIssueAssignmentBundlesFromEnv { config } => {
            ops_e2e::execute_ops_e2e_issue_assignment_bundles_from_env(config)
        }
        OpsCommand::E2eIssueTraversalBundlesFromEnv { config } => {
            ops_e2e::execute_ops_e2e_issue_traversal_bundles_from_env(config)
        }
        OpsCommand::E2eIssueDnsZoneBundlesFromEnv { config } => {
            ops_e2e::execute_ops_e2e_issue_dns_zone_bundles_from_env(config)
        }
    }
}

fn execute_ops_refresh_trust() -> Result<String, String> {
    require_root_execution()?;
    enforce_pinned_runtime_binary_custody("trust-refresh")?;

    if !parse_env_bool_with_default("RUSTYNET_TRUST_AUTO_REFRESH", "true")? {
        return Ok("[trust-refresh] auto-refresh disabled; skipping.".to_string());
    }

    let trust_evidence_path = env_path_or_default(
        "RUSTYNET_TRUST_EVIDENCE",
        "/var/lib/rustynet/rustynetd.trust",
    )?;
    let trust_signer_key_path = env_path_or_default(
        "RUSTYNET_TRUST_SIGNER_KEY",
        "/etc/rustynet/trust-evidence.key",
    )?;
    let trust_signing_key_passphrase_path =
        env_required_path("RUSTYNET_TRUST_SIGNING_KEY_PASSPHRASE_FILE")?;
    let daemon_group = env_string_or_default("RUSTYNET_DAEMON_GROUP", "rustynetd")?;
    refresh_trust_record_with_inputs(
        SigningPassphraseHostProfile::Linux,
        trust_evidence_path.as_path(),
        trust_signer_key_path.as_path(),
        trust_signing_key_passphrase_path.as_path(),
        daemon_group.as_str(),
    )
}

fn execute_ops_refresh_signed_trust() -> Result<String, String> {
    let config = signing_passphrase_ops_config_from_env()?;
    if matches!(config.host_profile, SigningPassphraseHostProfile::Linux) {
        require_root_execution()?;
    }

    let node_role = env_optional_string("RUSTYNET_NODE_ROLE")?
        .unwrap_or_else(|| "admin".to_string())
        .to_ascii_lowercase();
    if node_role != "admin" && node_role != "blind_exit" {
        return Err(format!(
            "refresh-signed-trust requires node role admin or blind_exit; got {node_role}"
        ));
    }

    let trust_evidence_path = env_path_or_default(
        "RUSTYNET_TRUST_EVIDENCE",
        "/var/lib/rustynet/rustynetd.trust",
    )?;
    let trust_signer_key_path =
        env_path_or_default("RUSTYNET_TRUST_SIGNER_KEY", DEFAULT_TRUST_SIGNER_KEY_PATH)?;
    if !trust_signer_key_path.exists() {
        return Err(format!(
            "signer key not found at {}",
            trust_signer_key_path.display()
        ));
    }
    let daemon_group = env_string_or_default("RUSTYNET_DAEMON_GROUP", "rustynetd")?;

    ensure_signing_passphrase_material_ops(&config)?;
    let passphrase_tmp =
        create_secure_temp_file(std::env::temp_dir().as_path(), "trust-passphrase.")?;
    if let Err(err) = materialize_signing_passphrase_ops(&config, passphrase_tmp.as_path()) {
        let _ = secure_remove_file(passphrase_tmp.as_path());
        return Err(err);
    }

    let refresh_result = refresh_trust_record_with_inputs(
        config.host_profile,
        trust_evidence_path.as_path(),
        trust_signer_key_path.as_path(),
        passphrase_tmp.as_path(),
        daemon_group.as_str(),
    );
    let cleanup_result = secure_remove_file(passphrase_tmp.as_path());
    match (refresh_result, cleanup_result) {
        (Ok(message), Ok(())) => Ok(message),
        (Err(err), Ok(())) => Err(err),
        (Ok(_), Err(cleanup_err)) => Err(cleanup_err),
        (Err(err), Err(cleanup_err)) => Err(format!("{err}; cleanup failed: {cleanup_err}")),
    }
}

fn refresh_trust_record_with_inputs(
    host_profile: SigningPassphraseHostProfile,
    trust_evidence_path: &Path,
    trust_signer_key_path: &Path,
    trust_signing_key_passphrase_path: &Path,
    daemon_group: &str,
) -> Result<String, String> {
    let target_dir = trust_evidence_path.parent().ok_or_else(|| {
        format!(
            "trust evidence path has no parent: {}",
            trust_evidence_path.display()
        )
    })?;

    let (owner_uid, owner_gid, trust_mode) = match host_profile {
        SigningPassphraseHostProfile::Linux => {
            validate_root_owned_encrypted_signing_file(trust_signer_key_path, "trust signer key")?;
            validate_root_owned_passphrase_file(
                trust_signing_key_passphrase_path,
                "trust signer key passphrase file",
            )?;
            let trust_group_gid = group_gid_required(daemon_group)?;
            let trust_mode = 0o640;
            ensure_directory_exists(target_dir, 0o750, Uid::from_raw(0), trust_group_gid)?;
            (Uid::from_raw(0), trust_group_gid, trust_mode)
        }
        SigningPassphraseHostProfile::Macos => {
            validate_encrypted_secret_file_security(trust_signer_key_path, "trust signer key")?;
            validate_encrypted_secret_file_security(
                trust_signing_key_passphrase_path,
                "trust signer key passphrase file",
            )?;
            ensure_directory_with_mode_owner(target_dir, 0o700, None, None)?;
            (Uid::effective(), Gid::effective(), 0o600)
        }
    };

    let record_tmp = create_secure_temp_file(target_dir, "rustynetd-trust-record.")?;
    let issue_result = execute_trust(TrustCommand::Issue {
        signing_key_path: trust_signer_key_path.to_path_buf(),
        signing_key_passphrase_path: trust_signing_key_passphrase_path.to_path_buf(),
        output_path: record_tmp.clone(),
        updated_at_unix: unix_now(),
        nonce: generate_assignment_nonce(),
    });
    if let Err(err) = issue_result {
        let _ = remove_file_if_present(&record_tmp);
        return Err(err);
    }

    if let Err(err) = publish_file_with_owner_mode(
        &record_tmp,
        trust_evidence_path,
        owner_uid,
        owner_gid,
        trust_mode,
        "trust evidence",
    ) {
        let _ = remove_file_if_present(&record_tmp);
        return Err(err);
    }

    Ok(format!(
        "[trust-refresh] refreshed signed trust evidence at {}",
        trust_evidence_path.display()
    ))
}

fn execute_ops_refresh_assignment() -> Result<String, String> {
    require_root_execution()?;
    enforce_pinned_runtime_binary_custody("assignment-refresh")?;

    if !parse_env_bool_with_default("RUSTYNET_ASSIGNMENT_AUTO_REFRESH", "false")? {
        return Ok("[assignment-refresh] auto-refresh disabled; skipping.".to_string());
    }

    let target_node_id = env_optional_string("RUSTYNET_ASSIGNMENT_TARGET_NODE_ID")?
        .or_else(|| std::env::var("RUSTYNET_NODE_ID").ok())
        .ok_or_else(|| {
            "assignment target node id is required (RUSTYNET_ASSIGNMENT_TARGET_NODE_ID or RUSTYNET_NODE_ID)".to_string()
        })?;
    if !is_valid_node_id(target_node_id.as_str()) {
        return Err(format!(
            "target node id contains unsupported characters: {target_node_id}",
        ));
    }

    let nodes_spec = env_required_nonempty("RUSTYNET_ASSIGNMENT_NODES", "assignment node map")?;
    let allow_spec = env_required_nonempty("RUSTYNET_ASSIGNMENT_ALLOW", "assignment allow rules")?;
    let exit_node_id = env_optional_string("RUSTYNET_ASSIGNMENT_EXIT_NODE_ID")?;
    if let Some(exit_node_id_value) = exit_node_id.as_deref()
        && !is_valid_node_id(exit_node_id_value)
    {
        return Err(format!(
            "exit node id contains unsupported characters: {exit_node_id_value}",
        ));
    }
    let lan_routes = env_optional_string("RUSTYNET_ASSIGNMENT_LAN_ROUTES")?
        .map(split_csv)
        .unwrap_or_default();
    if !lan_routes.is_empty() {
        validate_assignment_refresh_lan_routes(lan_routes.as_slice())?;
        if exit_node_id.is_none() {
            return Err(
                "RUSTYNET_ASSIGNMENT_LAN_ROUTES requires RUSTYNET_ASSIGNMENT_EXIT_NODE_ID"
                    .to_string(),
            );
        }
    }

    let signing_secret_path = env_path_or_default(
        "RUSTYNET_ASSIGNMENT_SIGNING_SECRET",
        "/etc/rustynet/assignment.signing.secret",
    )?;
    let signing_secret_passphrase_path =
        env_required_path("RUSTYNET_ASSIGNMENT_SIGNING_SECRET_PASSPHRASE_FILE")?;
    let bundle_path = env_path_or_default(
        "RUSTYNET_ASSIGNMENT_OUTPUT",
        "/var/lib/rustynet/rustynetd.assignment",
    )?;
    let verifier_key_path = env_path_or_default(
        "RUSTYNET_ASSIGNMENT_VERIFIER_KEY_OUTPUT",
        "/etc/rustynet/assignment.pub",
    )?;
    let ttl_secs = parse_env_u64_with_default("RUSTYNET_ASSIGNMENT_TTL_SECS", 300)?;
    if !(60..=86_400).contains(&ttl_secs) {
        return Err(format!(
            "assignment ttl must be an integer in range 60-86400 seconds: {ttl_secs}",
        ));
    }
    let min_remaining_secs =
        parse_env_u64_with_default("RUSTYNET_ASSIGNMENT_MIN_REMAINING_SECS", 180)?;
    let daemon_group = env_string_or_default("RUSTYNET_DAEMON_GROUP", "rustynetd")?;

    validate_root_owned_encrypted_signing_file(&signing_secret_path, "assignment signing secret")?;
    validate_root_owned_passphrase_file(
        &signing_secret_passphrase_path,
        "assignment signing secret passphrase file",
    )?;
    refresh_local_traversal_bundle_from_specs(
        target_node_id.as_str(),
        nodes_spec.as_str(),
        allow_spec.as_str(),
        daemon_group.as_str(),
    )?;

    let now_unix = unix_now();
    if bundle_path.exists()
        && let Some(current_expires_at) =
            read_bundle_u64_field_optional(&bundle_path, "expires_at_unix")?
        && current_expires_at > now_unix.saturating_add(min_remaining_secs)
    {
        let remaining_secs = current_expires_at.saturating_sub(now_unix);
        return Ok(format!(
            "[assignment-refresh] current assignment expires in {remaining_secs}s; skip refresh.",
        ));
    }

    let bundle_group_gid = group_gid_required(daemon_group.as_str())?;

    let bundle_dir = bundle_path.parent().ok_or_else(|| {
        format!(
            "assignment bundle output path has no parent: {}",
            bundle_path.display()
        )
    })?;
    let verifier_dir = verifier_key_path.parent().ok_or_else(|| {
        format!(
            "assignment verifier key output path has no parent: {}",
            verifier_key_path.display()
        )
    })?;
    ensure_directory_exists(bundle_dir, 0o750, Uid::from_raw(0), bundle_group_gid)?;
    ensure_directory_exists(verifier_dir, 0o750, Uid::from_raw(0), bundle_group_gid)?;

    let bundle_tmp = create_secure_temp_file(bundle_dir, "rustynetd.assignment.tmp.")?;
    let verifier_tmp = create_secure_temp_file(verifier_dir, "assignment.pub.tmp.")?;

    let nodes = parse_assignment_nodes(nodes_spec.as_str())?;
    let allow_pairs = parse_assignment_allow_pairs(allow_spec.as_str())?;
    validate_assignment_issue_config(
        nodes.as_slice(),
        allow_pairs.as_slice(),
        target_node_id.as_str(),
        exit_node_id.as_deref(),
    )?;

    let issue_result =
        execute_assignment(AssignmentCommand::Issue(Box::new(AssignmentIssueCommand {
            signing_secret_path,
            signing_secret_passphrase_path,
            target_node_id,
            output_path: bundle_tmp.clone(),
            verifier_key_output_path: Some(verifier_tmp.clone()),
            nodes,
            allow_pairs,
            mesh_cidr: "100.64.0.0/10".to_string(),
            exit_node_id,
            lan_routes,
            generated_at_unix: unix_now(),
            ttl_secs,
            nonce: generate_assignment_nonce(),
        })));
    if let Err(err) = issue_result {
        let _ = remove_file_if_present(&bundle_tmp);
        let _ = remove_file_if_present(&verifier_tmp);
        return Err(err);
    }

    let generated_at_unix = read_bundle_u64_field_required(&bundle_tmp, "generated_at_unix")?;
    let expires_at_unix = read_bundle_u64_field_required(&bundle_tmp, "expires_at_unix")?;
    if generated_at_unix >= expires_at_unix {
        let _ = remove_file_if_present(&bundle_tmp);
        let _ = remove_file_if_present(&verifier_tmp);
        return Err("issued assignment bundle has invalid expiry window".to_string());
    }

    if let Err(err) = publish_file_with_owner_mode(
        &bundle_tmp,
        &bundle_path,
        Uid::from_raw(0),
        bundle_group_gid,
        0o640,
        "assignment bundle",
    ) {
        let _ = remove_file_if_present(&bundle_tmp);
        let _ = remove_file_if_present(&verifier_tmp);
        return Err(err);
    }

    if let Err(err) = publish_file_with_owner_mode(
        &verifier_tmp,
        &verifier_key_path,
        Uid::from_raw(0),
        Gid::from_raw(0),
        0o644,
        "assignment verifier key",
    ) {
        let _ = remove_file_if_present(&verifier_tmp);
        return Err(err);
    }

    Ok(format!(
        "[assignment-refresh] refreshed signed assignment bundle at {} (generated_at_unix={} expires_at_unix={})",
        bundle_path.display(),
        generated_at_unix,
        expires_at_unix
    ))
}

fn execute_ops_state_refresh_if_socket_present() -> Result<String, String> {
    require_root_execution()?;

    let socket_path = env_path_or_default("RUSTYNET_SOCKET", DEFAULT_DAEMON_SOCKET_PATH)?;
    let socket_present = socket_exists_and_is_socket(socket_path.as_path(), "daemon socket")?;
    if !socket_present {
        return Ok(format!(
            "state refresh skipped: daemon socket is absent ({})",
            socket_path.display()
        ));
    }

    let response = send_command_with_socket(IpcCommand::StateRefresh, socket_path.clone())?;
    if response.ok {
        Ok(response.message)
    } else {
        Err(response.message)
    }
}

fn execute_ops_verify_runtime_binary_custody() -> Result<String, String> {
    enforce_pinned_runtime_binary_custody("runtime-binary-custody")?;
    Ok(format!(
        "runtime binary custody verification passed: {PINNED_RUNTIME_RUSTYNET_BIN}"
    ))
}

fn enforce_pinned_runtime_binary_custody(context: &str) -> Result<(), String> {
    let pinned_path = Path::new(PINNED_RUNTIME_RUSTYNET_BIN);
    let metadata = fs::symlink_metadata(pinned_path).map_err(|err| {
        format!(
            "[{context}] required executable not found: {} ({err})",
            pinned_path.display()
        )
    })?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "[{context}] pinned binary must not be a symlink: {}",
            pinned_path.display()
        ));
    }
    if !metadata.file_type().is_file() {
        return Err(format!(
            "[{context}] pinned binary must be a regular file: {}",
            pinned_path.display()
        ));
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o111 == 0 {
        return Err(format!(
            "[{context}] pinned binary is not executable: {}",
            pinned_path.display()
        ));
    }
    if metadata.uid() != 0 {
        return Err(format!(
            "[{context}] pinned binary must be root-owned: {}",
            pinned_path.display()
        ));
    }
    if mode & 0o022 != 0 {
        return Err(format!(
            "[{context}] pinned binary must not be group/world writable: {} ({:03o})",
            pinned_path.display(),
            mode
        ));
    }

    let current_exe = std::env::current_exe()
        .map_err(|err| format!("[{context}] resolve current executable failed: {err}"))?;
    let current_canonical = fs::canonicalize(current_exe.as_path()).unwrap_or(current_exe);
    let pinned_canonical = fs::canonicalize(pinned_path).map_err(|err| {
        format!(
            "[{context}] canonicalize pinned binary failed ({}): {err}",
            pinned_path.display()
        )
    })?;
    if current_canonical != pinned_canonical {
        return Err(format!(
            "[{context}] unexpected executable path: expected {} got {}",
            pinned_canonical.display(),
            current_canonical.display()
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Phase6Platform {
    Linux,
    Macos,
    Windows,
}

impl Phase6Platform {
    fn as_str(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Macos => "macos",
            Self::Windows => "windows",
        }
    }

    fn raw_filename(self) -> &'static str {
        match self {
            Self::Linux => "platform_parity_linux.json",
            Self::Macos => "platform_parity_macos.json",
            Self::Windows => "platform_parity_windows.json",
        }
    }

    fn probe_source_env_var(self) -> &'static str {
        match self {
            Self::Linux => "RUSTYNET_PHASE6_LINUX_PROBE_SOURCE",
            Self::Macos => "RUSTYNET_PHASE6_MACOS_PROBE_SOURCE",
            Self::Windows => "RUSTYNET_PHASE6_WINDOWS_PROBE_SOURCE",
        }
    }

    fn all() -> [Self; 3] {
        [Self::Linux, Self::Macos, Self::Windows]
    }
}

fn execute_ops_collect_platform_probe() -> Result<String, String> {
    let out_path = collect_platform_probe_artifact()?;
    Ok(format!("wrote platform probe: {}", out_path.display()))
}

fn execute_ops_generate_platform_parity_report() -> Result<String, String> {
    let out_path = generate_platform_parity_report_artifact()?;
    phase6_validate_platform_parity_report(out_path.as_path())?;
    ops_phase9::write_phase6_parity_evidence_attestation(out_path.as_path())?;
    ops_phase9::execute_ops_verify_phase6_parity_evidence()?;
    Ok(format!(
        "wrote platform parity report: {}",
        out_path.display()
    ))
}

fn execute_ops_collect_platform_parity_bundle() -> Result<String, String> {
    let raw_dir = env_path_or_default(
        "RUSTYNET_PHASE6_PARITY_RAW_DIR",
        DEFAULT_PHASE6_PARITY_RAW_DIR,
    )?;
    let inbox_dir = env_path_or_default(
        "RUSTYNET_PHASE6_PARITY_INBOX_DIR",
        DEFAULT_PHASE6_PARITY_INBOX_DIR,
    )?;

    fs::create_dir_all(&raw_dir).map_err(|err| {
        format!(
            "create parity raw directory failed ({}): {err}",
            raw_dir.display()
        )
    })?;
    fs::create_dir_all(&inbox_dir).map_err(|err| {
        format!(
            "create parity inbox directory failed ({}): {err}",
            inbox_dir.display()
        )
    })?;

    let now_unix = unix_now();
    for platform in Phase6Platform::all() {
        let inbox_path = inbox_dir.join(platform.raw_filename());
        phase6_stage_probe_from_source_env(platform, inbox_path.as_path(), now_unix)?;
    }

    collect_platform_probe_artifact()?;

    for platform in Phase6Platform::all() {
        let raw_path = raw_dir.join(platform.raw_filename());
        let inbox_path = inbox_dir.join(platform.raw_filename());
        phase6_sync_platform_probe_from_inbox(
            platform,
            raw_path.as_path(),
            inbox_path.as_path(),
            now_unix,
        )?;
    }

    let report_path = generate_platform_parity_report_artifact()?;
    phase6_validate_platform_parity_report(report_path.as_path())?;
    ops_phase9::write_phase6_parity_evidence_attestation(report_path.as_path())?;
    ops_phase9::execute_ops_verify_phase6_parity_evidence()?;

    Ok("phase6 platform parity bundle generated from probes".to_string())
}

#[derive(Debug, Clone)]
struct Phase6ProbeMetadata {
    payload: Value,
    probe_time_unix: u64,
    is_fresh: bool,
}

fn phase6_load_probe_metadata(
    path: &Path,
    platform: Phase6Platform,
    now_unix: u64,
) -> Result<Option<Phase6ProbeMetadata>, String> {
    if !path.exists() {
        return Ok(None);
    }

    let payload = read_json_value(path, "platform parity probe")?;
    let payload_obj = payload.as_object().ok_or_else(|| {
        format!(
            "platform parity probe must be JSON object: {}",
            path.display()
        )
    })?;
    if payload_obj
        .get("evidence_mode")
        .and_then(Value::as_str)
        .is_none_or(|mode| mode != "measured")
    {
        return Err(format!(
            "platform parity probe must set evidence_mode=measured: {}",
            path.display()
        ));
    }

    let payload_platform = payload_obj
        .get("platform")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or_default()
        .to_ascii_lowercase();
    if payload_platform != platform.as_str() {
        return Err(format!(
            "platform parity probe platform mismatch: expected {} got {} ({})",
            platform.as_str(),
            if payload_platform.is_empty() {
                "<missing>"
            } else {
                payload_platform.as_str()
            },
            path.display()
        ));
    }

    let probe_time_unix = payload_obj
        .get("probe_time_unix")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            format!(
                "platform parity probe requires positive integer probe_time_unix: {}",
                path.display()
            )
        })?;
    if probe_time_unix == 0 {
        return Err(format!(
            "platform parity probe requires positive integer probe_time_unix: {}",
            path.display()
        ));
    }
    if probe_time_unix > now_unix.saturating_add(300) {
        return Err(format!(
            "platform parity probe probe_time_unix is too far in the future: {}",
            path.display()
        ));
    }

    Ok(Some(Phase6ProbeMetadata {
        payload,
        probe_time_unix,
        is_fresh: now_unix.saturating_sub(probe_time_unix) <= PHASE6_MAX_EVIDENCE_AGE_SECS,
    }))
}

fn phase6_stage_probe_from_source_env(
    platform: Phase6Platform,
    inbox_path: &Path,
    now_unix: u64,
) -> Result<(), String> {
    let Some(source_path) =
        env_optional_string(platform.probe_source_env_var())?.map(PathBuf::from)
    else {
        return Ok(());
    };

    phase6_stage_probe_from_source(platform, source_path.as_path(), inbox_path, now_unix)
}

fn phase6_stage_probe_from_source(
    platform: Phase6Platform,
    source_path: &Path,
    inbox_path: &Path,
    now_unix: u64,
) -> Result<(), String> {
    let metadata =
        phase6_load_probe_metadata(source_path, platform, now_unix)?.ok_or_else(|| {
            format!(
                "phase6 external platform probe missing: {}",
                source_path.display()
            )
        })?;
    if !metadata.is_fresh {
        return Err(format!(
            "phase6 external platform probe is stale; recollect probe evidence: {}",
            source_path.display()
        ));
    }

    write_json_pretty_file(inbox_path, &metadata.payload)?;
    Ok(())
}

fn phase6_sync_platform_probe_from_inbox(
    platform: Phase6Platform,
    raw_path: &Path,
    inbox_path: &Path,
    now_unix: u64,
) -> Result<(), String> {
    let raw_metadata = phase6_load_probe_metadata(raw_path, platform, now_unix)?;
    let inbox_metadata = phase6_load_probe_metadata(inbox_path, platform, now_unix)?;

    let should_import_inbox = match (&raw_metadata, &inbox_metadata) {
        (None, Some(inbox)) => inbox.is_fresh,
        (Some(raw), Some(inbox)) => {
            inbox.is_fresh && (!raw.is_fresh || inbox.probe_time_unix > raw.probe_time_unix)
        }
        _ => false,
    };

    if should_import_inbox {
        let inbox_payload = inbox_metadata
            .as_ref()
            .expect("inbox metadata must exist when import is selected");
        write_json_pretty_file(raw_path, &inbox_payload.payload)?;
    }

    if raw_path.exists() {
        return Ok(());
    }

    Err(format!(
        "missing platform parity probe for {}: expected {} or {}",
        platform.as_str(),
        raw_path.display(),
        inbox_path.display()
    ))
}

fn collect_platform_probe_artifact() -> Result<PathBuf, String> {
    let raw_dir = env_path_or_default(
        "RUSTYNET_PHASE6_PARITY_RAW_DIR",
        DEFAULT_PHASE6_PARITY_RAW_DIR,
    )?;
    fs::create_dir_all(&raw_dir).map_err(|err| {
        format!(
            "create parity raw directory failed ({}): {err}",
            raw_dir.display()
        )
    })?;

    let platform = phase6_detect_probe_platform()?;

    let (
        route_hook_ready,
        dns_hook_ready,
        firewall_hook_ready,
        route_probe_cmd,
        dns_probe_cmd,
        firewall_probe_cmd,
    ) = match platform {
        Phase6Platform::Linux => {
            let route_probe_cmd = "ip -o route show default".to_string();
            let route_hook_ready =
                phase6_command_succeeds("ip", &["-o", "route", "show", "default"]);

            let (dns_hook_ready, dns_probe_cmd) = if phase6_command_available("resolvectl") {
                (
                    phase6_command_succeeds("resolvectl", &["status"]),
                    "resolvectl status".to_string(),
                )
            } else {
                (
                    phase6_nonempty_file(Path::new("/etc/resolv.conf")),
                    "test -s /etc/resolv.conf".to_string(),
                )
            };

            let (firewall_hook_ready, firewall_probe_cmd) = if phase6_command_available("nft") {
                (
                    phase6_command_succeeds("nft", &["list", "tables"]),
                    "nft list tables".to_string(),
                )
            } else if phase6_command_available("iptables") {
                (
                    phase6_command_succeeds("iptables", &["-S"]),
                    "iptables -S".to_string(),
                )
            } else {
                (false, "nft|iptables unavailable".to_string())
            };

            (
                route_hook_ready,
                dns_hook_ready,
                firewall_hook_ready,
                route_probe_cmd,
                dns_probe_cmd,
                firewall_probe_cmd,
            )
        }
        Phase6Platform::Macos => {
            let contract_ready = phase6_macos_start_contract_ready()?;
            let route_hook_ready = contract_ready
                && phase6_root_owned_command_ready("route", "route")
                && phase6_root_owned_command_ready("ifconfig", "ifconfig")
                && phase6_root_owned_command_ready("launchctl", "launchctl");
            let dns_hook_ready = contract_ready
                && phase6_root_owned_command_ready("scutil", "scutil")
                && phase6_root_owned_command_ready("launchctl", "launchctl");
            let firewall_hook_ready = contract_ready
                && phase6_root_owned_command_ready("pfctl", "pfctl")
                && phase6_root_owned_command_ready("launchctl", "launchctl");
            (
                route_hook_ready,
                dns_hook_ready,
                firewall_hook_ready,
                "root-owned route/ifconfig/launchctl + hardened macOS start contract".to_string(),
                "root-owned scutil/launchctl + hardened macOS start contract".to_string(),
                "root-owned pfctl/launchctl + hardened macOS start contract".to_string(),
            )
        }
        Phase6Platform::Windows => (
            phase6_command_succeeds(
                "powershell.exe",
                &[
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -First 1 | Out-Null",
                ],
            ),
            phase6_command_succeeds(
                "powershell.exe",
                &[
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "Get-DnsClientServerAddress | Out-Null",
                ],
            ),
            phase6_command_succeeds(
                "powershell.exe",
                &[
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "Get-NetFirewallProfile | Out-Null",
                ],
            ),
            "powershell.exe Get-NetRoute".to_string(),
            "powershell.exe Get-DnsClientServerAddress".to_string(),
            "powershell.exe Get-NetFirewallProfile".to_string(),
        ),
    };

    let leak_source = phase6_leak_report_source(platform)?;
    let leak_matrix_passed = phase6_leak_report_passed(Path::new(leak_source.as_str()));

    let out_path = raw_dir.join(platform.raw_filename());
    let payload = json!({
        "evidence_mode": "measured",
        "platform": platform.as_str(),
        "route_hook_ready": route_hook_ready,
        "dns_hook_ready": dns_hook_ready,
        "firewall_hook_ready": firewall_hook_ready,
        "leak_matrix_passed": leak_matrix_passed,
        "probe_time_unix": unix_now(),
        "probe_host": phase6_probe_host(),
        "probe_sources": {
            "route": route_probe_cmd,
            "dns": dns_probe_cmd,
            "firewall": firewall_probe_cmd,
            "leak_report": leak_source,
        },
    });
    write_json_pretty_file(&out_path, &payload)?;

    let strict_mode = env_string_or_default("RUSTYNET_PHASE6_PARITY_STRICT", "1")?;
    if strict_mode == "1"
        && (!route_hook_ready || !dns_hook_ready || !firewall_hook_ready || !leak_matrix_passed)
    {
        return Err(format!(
            "platform parity probe recorded failing controls in {}",
            out_path.display()
        ));
    }

    Ok(out_path)
}

fn generate_platform_parity_report_artifact() -> Result<PathBuf, String> {
    let raw_dir = env_path_or_default(
        "RUSTYNET_PHASE6_PARITY_RAW_DIR",
        DEFAULT_PHASE6_PARITY_RAW_DIR,
    )?;
    let out_path = env_path_or_default(
        "RUSTYNET_PHASE6_PARITY_OUT",
        DEFAULT_PHASE6_PARITY_REPORT_PATH,
    )?;
    let environment = env_required_nonempty(
        "RUSTYNET_PHASE6_PARITY_ENVIRONMENT",
        "phase6 parity environment",
    )?;

    let mut results = Vec::new();
    let mut source_artifacts = Vec::new();
    for platform in Phase6Platform::all() {
        let source = raw_dir.join(platform.raw_filename());
        if !source.exists() {
            return Err(format!(
                "missing raw platform parity input: {}",
                source.display()
            ));
        }
        let payload = read_json_value(&source, "raw platform parity payload")?;
        if !payload.is_object() {
            return Err(format!(
                "raw platform parity payload must be object: {}",
                source.display()
            ));
        }

        let result = json!({
            "platform": platform.as_str(),
            "route_hook_ready": phase6_require_bool_field(&payload, "route_hook_ready", &source)?,
            "dns_hook_ready": phase6_require_bool_field(&payload, "dns_hook_ready", &source)?,
            "firewall_hook_ready": phase6_require_bool_field(&payload, "firewall_hook_ready", &source)?,
            "leak_matrix_passed": phase6_require_bool_field(&payload, "leak_matrix_passed", &source)?,
        });
        results.push(result);
        source_artifacts.push(source.display().to_string());
    }

    let report = json!({
        "evidence_mode": "measured",
        "captured_at_unix": unix_now(),
        "environment": environment,
        "source_artifacts": source_artifacts,
        "platform_results": results,
    });
    write_json_pretty_file(&out_path, &report)?;
    Ok(out_path)
}

fn phase6_detect_probe_platform() -> Result<Phase6Platform, String> {
    if let Some(override_platform) = env_optional_string("RUSTYNET_PHASE6_PLATFORM_OVERRIDE")? {
        return match override_platform.to_ascii_lowercase().as_str() {
            "linux" => Ok(Phase6Platform::Linux),
            "macos" => Ok(Phase6Platform::Macos),
            "windows" => Ok(Phase6Platform::Windows),
            _ => Err(format!(
                "unsupported platform override: {override_platform}",
            )),
        };
    }

    match detect_host_profile() {
        "linux" => Ok(Phase6Platform::Linux),
        "macos" => Ok(Phase6Platform::Macos),
        other => Err(format!("unsupported platform for parity probe: {other}")),
    }
}

fn phase6_leak_report_source(platform: Phase6Platform) -> Result<String, String> {
    let default_source = env_optional_string("RUSTYNET_PHASE6_LEAK_REPORT")?
        .unwrap_or_else(|| DEFAULT_PHASE10_LEAK_REPORT_PATH.to_string());
    let platform_source = match platform {
        Phase6Platform::Linux => env_optional_string("RUSTYNET_PHASE6_LEAK_REPORT_LINUX")?,
        Phase6Platform::Macos => env_optional_string("RUSTYNET_PHASE6_LEAK_REPORT_MACOS")?,
        Phase6Platform::Windows => env_optional_string("RUSTYNET_PHASE6_LEAK_REPORT_WINDOWS")?,
    };
    Ok(platform_source.unwrap_or(default_source))
}

fn phase6_leak_report_passed(path: &Path) -> bool {
    if !path.exists() {
        return false;
    }
    let payload = match read_json_value(path, "phase6 leak report") {
        Ok(payload) => payload,
        Err(_) => return false,
    };
    payload
        .get("status")
        .and_then(Value::as_str)
        .is_some_and(|status| status == "pass")
        && payload
            .get("evidence_mode")
            .and_then(Value::as_str)
            .is_some_and(|mode| mode == "measured")
}

fn phase6_probe_host() -> String {
    if let Ok(hostname) = std::env::var("HOSTNAME")
        && !hostname.trim().is_empty()
    {
        return hostname;
    }
    let output = Command::new("hostname")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output();
    if let Ok(output) = output {
        let hostname = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !hostname.is_empty() {
            return hostname;
        }
    }
    "unknown".to_string()
}

const PHASE6_MACOS_REQUIRED_START_PATTERNS: &[(&str, &str)] = &[
    (
        "validate_macos_passphrase_source_contract",
        "missing macOS passphrase source contract enforcement in start.sh",
    ),
    (
        "configure_macos_binary_path_env",
        "missing macOS privileged binary custody enforcement in start.sh",
    ),
    (
        "rustynet ops bootstrap-wireguard-custody",
        "missing Rust-backed macOS WireGuard custody bootstrap in start.sh",
    ),
    (
        "rustynet ops restart-runtime-service",
        "missing Rust-backed macOS launchd restart path in start.sh",
    ),
    (
        "RUSTYNET_WG_KEY_PASSPHRASE=\"${WG_KEY_PASSPHRASE_PATH}\"",
        "missing macOS passphrase placeholder path wiring in start.sh",
    ),
    (
        "RUSTYNET_WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT=\"${WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT}\"",
        "missing macOS keychain account wiring in start.sh",
    ),
    (
        "RUSTYNET_MACOS_WG_PASSPHRASE_KEYCHAIN_SERVICE=\"${MACOS_WG_PASSPHRASE_KEYCHAIN_SERVICE}\"",
        "missing macOS keychain service wiring in start.sh",
    ),
];

const PHASE6_MACOS_FORBIDDEN_START_PATTERNS: &[(&str, &str)] = &[(
    "install_macos_unprivileged_wireguard_tools",
    "insecure macOS unprivileged WireGuard fallback is still present in start.sh",
)];

fn phase6_workspace_root() -> Result<PathBuf, String> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| "failed to resolve workspace root for phase6 parity probe".to_string())
}

fn phase6_macos_start_contract_ready() -> Result<bool, String> {
    let start_path = phase6_workspace_root()?.join("start.sh");
    let body = fs::read_to_string(&start_path).map_err(|err| {
        format!(
            "read macOS start contract failed ({}): {err}",
            start_path.display()
        )
    })?;
    phase6_validate_macos_start_contract_text(&body)?;
    Ok(true)
}

fn phase6_validate_macos_start_contract_text(body: &str) -> Result<(), String> {
    for (pattern, message) in PHASE6_MACOS_REQUIRED_START_PATTERNS {
        if !body.contains(pattern) {
            return Err((*message).to_string());
        }
    }
    for (pattern, message) in PHASE6_MACOS_FORBIDDEN_START_PATTERNS {
        if body.contains(pattern) {
            return Err((*message).to_string());
        }
    }
    Ok(())
}

fn phase6_root_owned_command_ready(command_name: &str, label: &str) -> bool {
    resolve_absolute_command_path(command_name)
        .and_then(|path| validate_root_owned_executable_path(path.as_path(), label))
        .is_ok()
}

fn phase6_command_available(command: &str) -> bool {
    if command.contains('/') {
        return Path::new(command).is_file();
    }

    let Some(path_env) = std::env::var_os("PATH") else {
        return false;
    };
    for directory in std::env::split_paths(&path_env) {
        let candidate = directory.join(command);
        if candidate.is_file() {
            return true;
        }
    }
    false
}

fn phase6_command_succeeds(command: &str, args: &[&str]) -> bool {
    if !phase6_command_available(command) {
        return false;
    }
    Command::new(command)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn phase6_nonempty_file(path: &Path) -> bool {
    fs::metadata(path)
        .map(|metadata| metadata.is_file() && metadata.len() > 0)
        .unwrap_or(false)
}

fn write_json_pretty_file(path: &Path, payload: &Value) -> Result<(), String> {
    let mut body = serde_json::to_string_pretty(payload)
        .map_err(|err| format!("serialize json failed: {err}"))?;
    body.push('\n');
    write_text_file(path, &body)
}

fn read_json_value(path: &Path, label: &str) -> Result<Value, String> {
    let body = fs::read_to_string(path)
        .map_err(|err| format!("read {label} failed ({}): {err}", path.display()))?;
    serde_json::from_str(body.as_str())
        .map_err(|err| format!("parse {label} failed ({}): {err}", path.display()))
}

fn phase6_require_bool_field(payload: &Value, key: &str, source: &Path) -> Result<bool, String> {
    payload
        .get(key)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("{} requires boolean field: {key}", source.display()))
}

pub(crate) fn phase6_validate_platform_parity_report(report_path: &Path) -> Result<(), String> {
    if !report_path.exists() {
        return Err(format!(
            "missing platform parity report: {}",
            report_path.display()
        ));
    }
    let report = read_json_value(report_path, "platform parity report")?;
    let report_obj = report
        .as_object()
        .ok_or_else(|| "platform parity report must be a JSON object".to_string())?;

    if report_obj
        .get("evidence_mode")
        .and_then(Value::as_str)
        .is_none_or(|value| value != "measured")
    {
        return Err("platform parity report must set evidence_mode=measured".to_string());
    }

    let captured_at_unix = report_obj
        .get("captured_at_unix")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            "platform parity report requires positive integer captured_at_unix".to_string()
        })?;
    if captured_at_unix == 0 {
        return Err(
            "platform parity report requires positive integer captured_at_unix".to_string(),
        );
    }

    let now_unix = unix_now();
    if captured_at_unix > now_unix.saturating_add(300) {
        return Err("platform parity report captured_at_unix is too far in the future".to_string());
    }
    if now_unix.saturating_sub(captured_at_unix) > PHASE6_MAX_EVIDENCE_AGE_SECS {
        return Err(
            "platform parity report is stale; regenerate with fresh measurements".to_string(),
        );
    }

    let environment = report_obj
        .get("environment")
        .and_then(Value::as_str)
        .ok_or_else(|| "platform parity report requires non-empty environment".to_string())?;
    if environment.trim().is_empty() {
        return Err("platform parity report requires non-empty environment".to_string());
    }

    if report_obj.contains_key("gate_passed") {
        return Err("platform parity report must not include gate_passed toggle".to_string());
    }

    let source_artifacts = report_obj
        .get("source_artifacts")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            "platform parity report requires non-empty source_artifacts list".to_string()
        })?;
    if source_artifacts.is_empty() {
        return Err("platform parity report requires non-empty source_artifacts list".to_string());
    }

    let required_platforms = Phase6Platform::all()
        .iter()
        .map(|platform| platform.as_str().to_string())
        .collect::<HashSet<_>>();
    let mut source_by_platform = HashMap::new();

    for source in source_artifacts {
        let source_str = source.as_str().ok_or_else(|| {
            "platform parity report has invalid source_artifacts entry".to_string()
        })?;
        if source_str.trim().is_empty() {
            return Err("platform parity report has invalid source_artifacts entry".to_string());
        }
        let mut source_path = PathBuf::from(source_str);
        if !source_path.is_absolute() {
            source_path = PathBuf::from(".").join(source_path);
        }
        if !source_path.exists() {
            return Err(format!(
                "platform parity source artifact missing: {source_str}"
            ));
        }

        let source_payload = read_json_value(&source_path, "platform parity source artifact")?;
        let source_obj = source_payload.as_object().ok_or_else(|| {
            format!("platform parity source artifact must be JSON object: {source_str}")
        })?;
        if source_obj
            .get("evidence_mode")
            .and_then(Value::as_str)
            .is_none_or(|mode| mode != "measured")
        {
            return Err(format!(
                "platform parity source artifact must set evidence_mode=measured: {source_str}"
            ));
        }

        let source_platform = source_obj
            .get("platform")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                format!("platform parity source artifact missing platform field: {source_str}")
            })?
            .trim()
            .to_ascii_lowercase();
        if source_platform.is_empty() {
            return Err(format!(
                "platform parity source artifact missing platform field: {source_str}"
            ));
        }
        if !required_platforms.contains(&source_platform) {
            return Err(format!(
                "platform parity source artifact has unsupported platform: {source_str}"
            ));
        }
        if source_by_platform.contains_key(&source_platform) {
            return Err(format!(
                "duplicate platform parity source artifact for platform: {source_platform}"
            ));
        }

        let probe_time_unix = source_obj
            .get("probe_time_unix")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                format!(
                    "platform parity source artifact requires positive integer probe_time_unix: {source_str}"
                )
            })?;
        if probe_time_unix == 0 {
            return Err(format!(
                "platform parity source artifact requires positive integer probe_time_unix: {source_str}"
            ));
        }
        if probe_time_unix > now_unix.saturating_add(300) {
            return Err(format!(
                "platform parity source artifact probe_time_unix is too far in the future: {source_str}"
            ));
        }
        if now_unix.saturating_sub(probe_time_unix) > PHASE6_MAX_EVIDENCE_AGE_SECS {
            return Err(format!(
                "platform parity source artifact is stale; recollect probe evidence: {source_str}"
            ));
        }

        let probe_host = source_obj
            .get("probe_host")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                format!(
                    "platform parity source artifact requires non-empty probe_host: {source_str}"
                )
            })?;
        if probe_host.trim().is_empty() {
            return Err(format!(
                "platform parity source artifact requires non-empty probe_host: {source_str}"
            ));
        }

        let probe_sources = source_obj
            .get("probe_sources")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                format!(
                    "platform parity source artifact requires probe_sources object: {source_str}"
                )
            })?;
        for key in ["route", "dns", "firewall", "leak_report"] {
            let value = probe_sources
                .get(key)
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    format!(
                        "platform parity source artifact missing probe source '{key}': {source_str}"
                    )
                })?;
            if value.trim().is_empty() {
                return Err(format!(
                    "platform parity source artifact missing probe source '{key}': {source_str}"
                ));
            }
        }

        source_by_platform.insert(source_platform, source_payload);
    }

    let platform_results = report_obj
        .get("platform_results")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            "platform parity report requires non-empty platform_results list".to_string()
        })?;
    if platform_results.is_empty() {
        return Err("platform parity report requires non-empty platform_results list".to_string());
    }

    let mut seen = HashSet::new();
    for result in platform_results {
        let result_obj = result.as_object().ok_or_else(|| {
            "platform parity report has invalid platform_results entry".to_string()
        })?;
        let platform = result_obj
            .get("platform")
            .and_then(Value::as_str)
            .ok_or_else(|| "platform parity report entry missing platform".to_string())?
            .trim()
            .to_ascii_lowercase();
        if !required_platforms.contains(&platform) {
            return Err(format!("unexpected platform in parity report: {platform}"));
        }
        seen.insert(platform.clone());
        let Some(source_payload) = source_by_platform.get(&platform) else {
            return Err(format!(
                "platform parity report missing source artifact for platform: {platform}"
            ));
        };
        for key in [
            "route_hook_ready",
            "dns_hook_ready",
            "firewall_hook_ready",
            "leak_matrix_passed",
        ] {
            let value = result_obj
                .get(key)
                .and_then(Value::as_bool)
                .ok_or_else(|| {
                    format!("platform parity requirement failed for {platform}: {key} must be true")
                })?;
            if !value {
                return Err(format!(
                    "platform parity requirement failed for {platform}: {key} must be true"
                ));
            }
            let source_value = source_payload.get(key).and_then(Value::as_bool).ok_or_else(|| {
                format!(
                    "platform parity source requirement failed for {platform}: {key} must be true"
                )
            })?;
            if !source_value {
                return Err(format!(
                    "platform parity source requirement failed for {platform}: {key} must be true"
                ));
            }
        }
    }

    if seen != required_platforms {
        let mut missing = required_platforms
            .difference(&seen)
            .cloned()
            .collect::<Vec<_>>();
        missing.sort();
        return Err(format!(
            "platform parity report missing platforms: {}",
            missing.join(", ")
        ));
    }

    Ok(())
}

const DEFAULT_SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH: &str =
    "/etc/rustynet/credentials/signing_key_passphrase.cred";
const DEFAULT_MEMBERSHIP_OWNER_SIGNING_KEY_PATH: &str = "/etc/rustynet/membership.owner.key";
const DEFAULT_MEMBERSHIP_WATERMARK_PATH: &str = "/var/lib/rustynet/membership.watermark";
const DEFAULT_TRUST_SIGNER_KEY_PATH: &str = "/etc/rustynet/trust-evidence.key";
const DEFAULT_ASSIGNMENT_SIGNING_SECRET_PATH: &str = "/etc/rustynet/assignment.signing.secret";
const DEFAULT_MACOS_PASSPHRASE_KEYCHAIN_SERVICE: &str = "rustynet.signing_passphrase";
const DEFAULT_ASSIGNMENT_REFRESH_ENV_PATH: &str = "/etc/rustynet/assignment-refresh.env";
const DEFAULT_AUTO_TUNNEL_BUNDLE_PATH: &str = "/var/lib/rustynet/rustynetd.assignment";
const DEFAULT_AUTO_TUNNEL_WATERMARK_PATH: &str = "/var/lib/rustynet/rustynetd.assignment.watermark";
const DEFAULT_DAEMON_SOCKET_PATH: &str = "/run/rustynet/rustynetd.sock";
const DEFAULT_SYSTEMD_ENV_PATH: &str = "/etc/default/rustynetd";
const MANAGED_DNS_ROUTING_INTERFACE_WAIT_SECS: u64 = 20;
const DEFAULT_PHASE6_PARITY_RAW_DIR: &str = "artifacts/release/raw";
const DEFAULT_PHASE6_PARITY_INBOX_DIR: &str = "artifacts/release/inbox";
const DEFAULT_PHASE6_PARITY_REPORT_PATH: &str = "artifacts/release/platform_parity_report.json";
const DEFAULT_PHASE10_LEAK_REPORT_PATH: &str = "artifacts/phase10/leak_test_report.json";
const DEFAULT_RUNTIME_SYSTEMD_SERVICE: &str = "rustynetd.service";
const DEFAULT_ASSIGNMENT_REFRESH_SYSTEMD_SERVICE: &str = "rustynetd-assignment-refresh.service";
const DEFAULT_DISCONNECT_ROUTE_TABLE: &str = "51820";
const DEFAULT_MACOS_LAUNCHD_DAEMON_LABEL: &str = "com.rustynet.rustynetd";
const DEFAULT_MACOS_LAUNCHD_HELPER_LABEL: &str = "com.rustynet.rustynetd-privileged";
const DEFAULT_MACOS_LAUNCHD_HELPER_PLIST_PATH: &str =
    "/Library/LaunchDaemons/com.rustynet.rustynetd-privileged.plist";
const DEFAULT_PRIVILEGED_HELPER_SOCKET_PATH: &str = "/run/rustynet/rustynetd-privileged.sock";
const MACOS_RUNTIME_SOCKET_WAIT_SECS: u64 = 5;
const PHASE6_MAX_EVIDENCE_AGE_SECS: u64 = 31 * 24 * 60 * 60;
const DEFAULT_WG_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH: &str =
    concat!("/etc/rustynet/credentials/", "wg", "_key_passphrase.cred");
const DEFAULT_LEGACY_LINUX_WG_PRIVATE_KEY_PATH: &str = "/etc/rustynet/wireguard.key";
const DEFAULT_MACOS_WG_PASSPHRASE_KEYCHAIN_SERVICE: &str =
    concat!("rustynet.", "wg", "_passphrase");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SigningPassphraseHostProfile {
    Linux,
    Macos,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SigningPassphraseOpsConfig {
    host_profile: SigningPassphraseHostProfile,
    signing_credential_blob_path: PathBuf,
    membership_owner_signing_key_path: PathBuf,
    trust_signer_key_path: PathBuf,
    assignment_signing_secret_path: PathBuf,
    macos_keychain_service: String,
    macos_keychain_account: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TunnelCustodyOpsConfig {
    host_profile: SigningPassphraseHostProfile,
    runtime_private_key_path: PathBuf,
    encrypted_private_key_path: PathBuf,
    public_key_path: PathBuf,
    passphrase_path: PathBuf,
    passphrase_credential_blob_path: PathBuf,
    macos_keychain_service: String,
    macos_keychain_account: String,
    allow_init: bool,
}

fn execute_ops_secure_remove(path: PathBuf) -> Result<String, String> {
    if !path.is_absolute() {
        return Err(format!("path must be absolute: {}", path.display()));
    }
    secure_remove_file(path.as_path())?;
    Ok(format!("secure remove complete: {}", path.display()))
}

fn execute_ops_apply_managed_dns_routing() -> Result<String, String> {
    require_root_execution()?;
    if !cfg!(target_os = "linux") {
        return Err("apply-managed-dns-routing is supported on Linux only".to_string());
    }

    ensure_systemd_resolved_active()?;
    let interface = managed_dns_interface_name_from_env()?;
    wait_for_managed_dns_interface(
        interface.as_str(),
        Duration::from_secs(MANAGED_DNS_ROUTING_INTERFACE_WAIT_SECS),
    )?;
    let zone_name = managed_dns_zone_name_from_env()?;
    let resolver_bind_addr = managed_dns_resolver_bind_addr_from_env()?;
    let resolver_arg = managed_dns_resolver_server_arg(resolver_bind_addr)?;
    let routing_zone = format!("~{zone_name}");

    run_resolvectl_action(&["dns", interface.as_str(), resolver_arg.as_str()])?;
    run_resolvectl_action(&[
        "domain",
        interface.as_str(),
        routing_zone.as_str(),
        zone_name.as_str(),
    ])?;
    run_resolvectl_action(&["default-route", interface.as_str(), "no"])?;
    run_resolvectl_action(&["status", interface.as_str()])?;

    Ok(format!(
        "managed DNS routing applied: interface={interface} zone={zone_name} resolver={resolver_bind_addr}"
    ))
}

fn execute_ops_clear_managed_dns_routing() -> Result<String, String> {
    require_root_execution()?;
    if !cfg!(target_os = "linux") {
        return Err("clear-managed-dns-routing is supported on Linux only".to_string());
    }

    let interface = managed_dns_interface_name_from_env()?;
    if let Err(err) = ensure_systemd_resolved_active() {
        if managed_dns_routing_already_absent(err.as_str()) {
            return Ok(format!(
                "managed DNS routing already cleared: interface={interface}"
            ));
        }
        return Err(err);
    }
    let revert_output = run_command_capture("resolvectl", &["revert", interface.as_str()])
        .map_err(|err| format!("execute resolvectl revert {interface} failed: {err}"))?;
    if !revert_output.status.success() {
        let detail = command_failure_detail(&revert_output);
        if managed_dns_routing_already_absent(detail.as_str()) {
            return Ok(format!(
                "managed DNS routing already cleared: interface={interface}"
            ));
        }
        return Err(format!("resolvectl revert {interface} failed: {detail}"));
    }

    Ok(format!(
        "managed DNS routing cleared: interface={interface}"
    ))
}

fn managed_dns_routing_already_absent(detail: &str) -> bool {
    detail.contains("Failed to resolve interface") || detail.contains("No such device")
}

fn execute_ops_restart_runtime_service() -> Result<String, String> {
    require_root_execution()?;
    if cfg!(target_os = "linux") {
        let restart_output =
            run_command_capture("systemctl", &["restart", DEFAULT_RUNTIME_SYSTEMD_SERVICE])?;
        if !restart_output.status.success() {
            return Err(format!(
                "restart {} failed: {}",
                DEFAULT_RUNTIME_SYSTEMD_SERVICE,
                command_failure_detail(&restart_output)
            ));
        }

        let active_output = run_command_capture(
            "systemctl",
            &["is-active", "--quiet", DEFAULT_RUNTIME_SYSTEMD_SERVICE],
        )?;
        if !active_output.status.success() {
            return Err(format!(
                "runtime service is not active after restart: {DEFAULT_RUNTIME_SYSTEMD_SERVICE}"
            ));
        }

        return Ok(format!(
            "runtime service restarted: {DEFAULT_RUNTIME_SYSTEMD_SERVICE}"
        ));
    }

    if cfg!(target_os = "macos") {
        return execute_ops_restart_runtime_service_macos();
    }

    Err("restart-runtime-service is supported on Linux and macOS only".to_string())
}

fn execute_ops_stop_runtime_service() -> Result<String, String> {
    require_root_execution()?;
    if cfg!(target_os = "linux") {
        let stop_output =
            run_command_capture("systemctl", &["stop", DEFAULT_RUNTIME_SYSTEMD_SERVICE])?;
        if !stop_output.status.success() {
            return Err(format!(
                "stop {} failed: {}",
                DEFAULT_RUNTIME_SYSTEMD_SERVICE,
                command_failure_detail(&stop_output)
            ));
        }

        let active_output = run_command_capture(
            "systemctl",
            &["is-active", "--quiet", DEFAULT_RUNTIME_SYSTEMD_SERVICE],
        )?;
        if active_output.status.success() {
            return Err(format!(
                "runtime service remains active after stop: {DEFAULT_RUNTIME_SYSTEMD_SERVICE}"
            ));
        }

        return Ok(format!(
            "runtime service stopped: {DEFAULT_RUNTIME_SYSTEMD_SERVICE}"
        ));
    }

    if cfg!(target_os = "macos") {
        return execute_ops_stop_runtime_service_macos();
    }

    Err("stop-runtime-service is supported on Linux and macOS only".to_string())
}

fn execute_ops_show_runtime_service_status() -> Result<String, String> {
    require_root_execution()?;
    if cfg!(target_os = "linux") {
        let status_output = run_command_capture(
            "systemctl",
            &[
                "--no-pager",
                "--full",
                "status",
                DEFAULT_RUNTIME_SYSTEMD_SERVICE,
            ],
        )?;
        if !status_output.status.success() {
            return Err(format!(
                "status {} failed: {}",
                DEFAULT_RUNTIME_SYSTEMD_SERVICE,
                command_failure_detail(&status_output)
            ));
        }

        let stdout = String::from_utf8_lossy(&status_output.stdout)
            .trim()
            .to_string();
        if !stdout.is_empty() {
            return Ok(stdout);
        }
        let stderr = String::from_utf8_lossy(&status_output.stderr)
            .trim()
            .to_string();
        if !stderr.is_empty() {
            return Ok(stderr);
        }
        return Ok(format!(
            "runtime service status available: {DEFAULT_RUNTIME_SYSTEMD_SERVICE}"
        ));
    }

    if cfg!(target_os = "macos") {
        return execute_ops_show_runtime_service_status_macos();
    }

    Err("show-runtime-service-status is supported on Linux and macOS only".to_string())
}

fn execute_ops_start_assignment_refresh_service() -> Result<String, String> {
    require_root_execution()?;
    if !cfg!(target_os = "linux") {
        return Err("start-assignment-refresh-service is supported on Linux only".to_string());
    }

    let start_output = run_command_capture(
        "systemctl",
        &["start", DEFAULT_ASSIGNMENT_REFRESH_SYSTEMD_SERVICE],
    )?;
    if !start_output.status.success() {
        return Err(format!(
            "start {} failed: {}",
            DEFAULT_ASSIGNMENT_REFRESH_SYSTEMD_SERVICE,
            command_failure_detail(&start_output)
        ));
    }

    Ok(format!(
        "assignment refresh service started: {DEFAULT_ASSIGNMENT_REFRESH_SYSTEMD_SERVICE}"
    ))
}

fn execute_ops_check_assignment_refresh_availability() -> Result<String, String> {
    require_root_execution()?;
    if !cfg!(target_os = "linux") {
        return Err("check-assignment-refresh-availability is supported on Linux only".to_string());
    }

    let env_path = env_path_or_default(
        "RUSTYNET_ASSIGNMENT_REFRESH_ENV_PATH",
        DEFAULT_ASSIGNMENT_REFRESH_ENV_PATH,
    )?;
    ensure_regular_file_no_symlink(env_path.as_path(), "assignment refresh env file")?;

    let cat_output = run_command_capture(
        "systemctl",
        &["cat", DEFAULT_ASSIGNMENT_REFRESH_SYSTEMD_SERVICE],
    )?;
    if !cat_output.status.success() {
        return Err(format!(
            "assignment refresh service unavailable ({}): {}",
            DEFAULT_ASSIGNMENT_REFRESH_SYSTEMD_SERVICE,
            command_failure_detail(&cat_output)
        ));
    }

    Ok(format!(
        "assignment refresh available: env={} service={}",
        env_path.display(),
        DEFAULT_ASSIGNMENT_REFRESH_SYSTEMD_SERVICE
    ))
}

fn execute_ops_force_local_assignment_refresh_now() -> Result<String, String> {
    require_root_execution()?;
    if !cfg!(target_os = "linux") {
        return Err("force-local-assignment-refresh-now is supported on Linux only".to_string());
    }
    force_local_assignment_refresh_now_ops()?;
    Ok("forced local assignment refresh completed".to_string())
}

fn execute_ops_install_trust_material(
    verifier_source: PathBuf,
    trust_source: PathBuf,
    verifier_dest: PathBuf,
    trust_dest: PathBuf,
    daemon_group: String,
) -> Result<String, String> {
    for (path, label) in [
        (verifier_source.as_path(), "verifier source"),
        (trust_source.as_path(), "trust source"),
        (verifier_dest.as_path(), "verifier destination"),
        (trust_dest.as_path(), "trust destination"),
    ] {
        if !path.is_absolute() {
            return Err(format!("{label} path must be absolute: {}", path.display()));
        }
    }
    ensure_regular_file_no_symlink(&verifier_source, "trust verifier source")?;
    ensure_regular_file_no_symlink(&trust_source, "trust evidence source")?;

    let daemon_group = daemon_group.trim().to_string();
    if daemon_group.is_empty() {
        return Err("daemon group must not be empty".to_string());
    }

    let host_profile = match env_string_or_default("RUSTYNET_HOST_PROFILE", detect_host_profile())?
        .to_ascii_lowercase()
        .as_str()
    {
        "linux" => SigningPassphraseHostProfile::Linux,
        "macos" | "darwin" => SigningPassphraseHostProfile::Macos,
        other => {
            return Err(format!(
                "unsupported host profile for trust material install: {other}"
            ));
        }
    };

    let (owner_uid, verifier_group_gid, verifier_mode, trust_group_gid, trust_mode, trust_group) =
        match host_profile {
            SigningPassphraseHostProfile::Linux => {
                if !cfg!(target_os = "linux") {
                    return Err(
                        "linux host profile for install-trust-material is supported on Linux only"
                            .to_string(),
                    );
                }
                require_root_execution()?;
                let owner_uid = Uid::from_raw(0);
                let verifier_group_gid = Gid::from_raw(0);
                let (trust_group_gid, trust_mode, trust_group) =
                    match Group::from_name(daemon_group.as_str()).map_err(|err| {
                        format!("resolve daemon group {daemon_group} failed: {err}")
                    })? {
                        Some(group) => (group.gid, 0o640, daemon_group.clone()),
                        None => (Gid::from_raw(0), 0o644, "root".to_string()),
                    };
                (
                    owner_uid,
                    verifier_group_gid,
                    0o644,
                    trust_group_gid,
                    trust_mode,
                    trust_group,
                )
            }
            SigningPassphraseHostProfile::Macos => {
                if !cfg!(target_os = "macos") {
                    return Err(
                        "macos host profile for install-trust-material is supported on macOS only"
                            .to_string(),
                    );
                }
                (
                    Uid::effective(),
                    Gid::effective(),
                    0o644,
                    Gid::effective(),
                    0o600,
                    Gid::effective().as_raw().to_string(),
                )
            }
        };

    install_trust_material_file(
        verifier_source.as_path(),
        verifier_dest.as_path(),
        owner_uid,
        verifier_group_gid,
        verifier_mode,
        "trust verifier key",
    )?;
    install_trust_material_file(
        trust_source.as_path(),
        trust_dest.as_path(),
        owner_uid,
        trust_group_gid,
        trust_mode,
        "trust evidence",
    )?;

    Ok(format!(
        "trust material installed: verifier={} trust={} trust_group={} trust_mode={:03o}",
        verifier_dest.display(),
        trust_dest.display(),
        trust_group,
        trust_mode
    ))
}

fn install_trust_material_file(
    source_path: &Path,
    destination_path: &Path,
    owner: Uid,
    group: Gid,
    mode: u32,
    label: &str,
) -> Result<(), String> {
    if let Ok(destination_metadata) = fs::symlink_metadata(destination_path) {
        if destination_metadata.file_type().is_symlink() {
            return Err(format!(
                "{label} destination must not be a symlink: {}",
                destination_path.display()
            ));
        }
        if !destination_metadata.file_type().is_file() {
            return Err(format!(
                "{label} destination must be a regular file: {}",
                destination_path.display()
            ));
        }
    }

    let destination_parent = destination_path.parent().ok_or_else(|| {
        format!(
            "{label} destination has no parent directory: {}",
            destination_path.display()
        )
    })?;
    let destination_parent_metadata = fs::symlink_metadata(destination_parent).map_err(|err| {
        format!(
            "inspect {label} destination parent failed ({}): {err}",
            destination_parent.display()
        )
    })?;
    if destination_parent_metadata.file_type().is_symlink() {
        return Err(format!(
            "{label} destination parent must not be a symlink: {}",
            destination_parent.display()
        ));
    }
    if !destination_parent_metadata.file_type().is_dir() {
        return Err(format!(
            "{label} destination parent must be a directory: {}",
            destination_parent.display()
        ));
    }

    let temp_path = create_secure_temp_file(destination_parent, "rustynet.ops.trust-material.")?;
    if let Err(err) = fs::copy(source_path, temp_path.as_path()) {
        let _ = remove_file_if_present(temp_path.as_path());
        return Err(format!(
            "copy {label} source {} failed: {err}",
            source_path.display()
        ));
    }
    if let Err(err) = publish_file_with_owner_mode(
        temp_path.as_path(),
        destination_path,
        owner,
        group,
        mode,
        label,
    ) {
        let _ = remove_file_if_present(temp_path.as_path());
        return Err(err);
    }
    Ok(())
}

fn execute_ops_disconnect_cleanup() -> Result<String, String> {
    require_root_execution()?;
    if cfg!(target_os = "macos") {
        return execute_ops_disconnect_cleanup_macos();
    }
    if !cfg!(target_os = "linux") {
        return Err("disconnect-cleanup is supported on Linux and macOS only".to_string());
    }

    let interface = env_string_or_default("RUSTYNET_WG_INTERFACE", DEFAULT_WG_INTERFACE)?
        .trim()
        .to_string();
    validate_managed_dns_interface_name(interface.as_str())?;

    let mut errors = Vec::new();
    let mut service_was_active = false;
    let mut service_stopped = false;
    let mut interface_present = false;
    let mut interface_removed = false;
    let mut routes_flushed = false;
    let mut policy_rules_removed = 0usize;
    let mut nft_tables_removed = 0usize;
    let mut ipv6_restored = false;

    match run_command_capture(
        "systemctl",
        &["is-active", "--quiet", DEFAULT_RUNTIME_SYSTEMD_SERVICE],
    ) {
        Ok(output) => {
            if output.status.success() {
                service_was_active = true;
                match run_command_capture("systemctl", &["stop", DEFAULT_RUNTIME_SYSTEMD_SERVICE]) {
                    Ok(stop_output) => {
                        if stop_output.status.success() {
                            service_stopped = true;
                        } else {
                            errors.push(format!(
                                "stop {} failed: {}",
                                DEFAULT_RUNTIME_SYSTEMD_SERVICE,
                                command_failure_detail(&stop_output)
                            ));
                        }
                    }
                    Err(err) => errors.push(err),
                }
            }
        }
        Err(err) => errors.push(err),
    }

    match run_command_capture("ip", &["link", "show", "dev", interface.as_str()]) {
        Ok(show_output) => {
            if show_output.status.success() {
                interface_present = true;
                match run_command_capture("ip", &["link", "del", "dev", interface.as_str()]) {
                    Ok(delete_output) => {
                        if delete_output.status.success() {
                            interface_removed = true;
                        } else {
                            errors.push(format!(
                                "remove interface {} failed: {}",
                                interface,
                                command_failure_detail(&delete_output)
                            ));
                        }
                    }
                    Err(err) => errors.push(err),
                }
            } else {
                let detail = command_failure_detail(&show_output);
                if !is_interface_absent_detail(detail.as_str()) {
                    errors.push(format!("inspect interface {interface} failed: {detail}"));
                }
            }
        }
        Err(err) => errors.push(err),
    }

    match run_command_capture(
        "ip",
        &["route", "show", "table", DEFAULT_DISCONNECT_ROUTE_TABLE],
    ) {
        Ok(routes_output) => {
            if !routes_output.status.success() {
                errors.push(format!(
                    "inspect route table {} failed: {}",
                    DEFAULT_DISCONNECT_ROUTE_TABLE,
                    command_failure_detail(&routes_output)
                ));
            } else {
                let has_routes = !String::from_utf8_lossy(&routes_output.stdout)
                    .trim()
                    .is_empty();
                if has_routes {
                    match run_command_capture(
                        "ip",
                        &["route", "flush", "table", DEFAULT_DISCONNECT_ROUTE_TABLE],
                    ) {
                        Ok(flush_output) => {
                            if flush_output.status.success() {
                                routes_flushed = true;
                            } else {
                                errors.push(format!(
                                    "flush route table {} failed: {}",
                                    DEFAULT_DISCONNECT_ROUTE_TABLE,
                                    command_failure_detail(&flush_output)
                                ));
                            }
                        }
                        Err(err) => errors.push(err),
                    }
                }
            }
        }
        Err(err) => errors.push(err),
    }

    loop {
        match run_command_capture("ip", &["rule", "list"]) {
            Ok(rule_output) => {
                if !rule_output.status.success() {
                    errors.push(format!(
                        "list ip rules failed: {}",
                        command_failure_detail(&rule_output)
                    ));
                    break;
                }
                let rules = String::from_utf8_lossy(&rule_output.stdout);
                if !contains_ip_rule_lookup_table(rules.as_ref(), DEFAULT_DISCONNECT_ROUTE_TABLE) {
                    break;
                }
                match run_command_capture(
                    "ip",
                    &["rule", "del", "table", DEFAULT_DISCONNECT_ROUTE_TABLE],
                ) {
                    Ok(delete_output) => {
                        if delete_output.status.success() {
                            policy_rules_removed += 1;
                        } else {
                            errors.push(format!(
                                "remove policy rule lookup {} failed: {}",
                                DEFAULT_DISCONNECT_ROUTE_TABLE,
                                command_failure_detail(&delete_output)
                            ));
                            break;
                        }
                    }
                    Err(err) => {
                        errors.push(err);
                        break;
                    }
                }
            }
            Err(err) => {
                errors.push(err);
                break;
            }
        }
    }

    if command_available("nft") {
        match run_command_capture("nft", &["list", "tables"]) {
            Ok(tables_output) => {
                if !tables_output.status.success() {
                    errors.push(format!(
                        "enumerate nft tables failed: {}",
                        command_failure_detail(&tables_output)
                    ));
                } else {
                    let tables = String::from_utf8_lossy(&tables_output.stdout);
                    for line in tables.lines() {
                        let fields = line.split_whitespace().collect::<Vec<_>>();
                        if fields.len() != 3 || fields[0] != "table" {
                            continue;
                        }
                        let family = fields[1];
                        let table_name = fields[2];
                        let managed = (family == "inet" && table_name.starts_with("rustynet_g"))
                            || (family == "ip" && table_name.starts_with("rustynet_nat_g"));
                        if !managed {
                            continue;
                        }
                        match run_command_capture("nft", &["delete", "table", family, table_name]) {
                            Ok(delete_output) => {
                                if delete_output.status.success() {
                                    nft_tables_removed += 1;
                                } else {
                                    errors.push(format!(
                                        "delete nft table {} {} failed: {}",
                                        family,
                                        table_name,
                                        command_failure_detail(&delete_output)
                                    ));
                                }
                            }
                            Err(err) => errors.push(err),
                        }
                    }
                }
            }
            Err(err) => errors.push(err),
        }
    }

    match run_command_capture("sysctl", &["-w", "net.ipv6.conf.all.disable_ipv6=0"]) {
        Ok(sysctl_output) => {
            if sysctl_output.status.success() {
                ipv6_restored = true;
            } else {
                errors.push(format!(
                    "restore IPv6 sysctl failed: {}",
                    command_failure_detail(&sysctl_output)
                ));
            }
        }
        Err(err) => errors.push(err),
    }

    if !errors.is_empty() {
        return Err(format!(
            "disconnect cleanup completed with residual-state errors: {}",
            errors.join(" | ")
        ));
    }

    Ok(format!(
        "disconnect cleanup complete: service_was_active={service_was_active} service_stopped={service_stopped} interface_present={interface_present} interface_removed={interface_removed} routes_flushed={routes_flushed} policy_rules_removed={policy_rules_removed} nft_tables_removed={nft_tables_removed} ipv6_restored={ipv6_restored}"
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MacosRuntimeServiceContext {
    daemon_uid: u32,
    daemon_domain: String,
    daemon_label: String,
    helper_label: String,
    daemon_target: String,
    helper_target: String,
    daemon_plist_path: PathBuf,
    helper_plist_path: PathBuf,
    daemon_socket_path: PathBuf,
    helper_socket_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MacosLaunchdRestartConfig {
    service: MacosRuntimeServiceContext,
    daemon_gid: u32,
    runtime_base: PathBuf,
    log_base: PathBuf,
    daemon_log_path: PathBuf,
    helper_log_path: PathBuf,
    helper_program_arguments: Vec<String>,
    daemon_program_arguments: Vec<String>,
    helper_environment: Vec<(String, String)>,
    daemon_environment: Vec<(String, String)>,
}

fn execute_ops_restart_runtime_service_macos() -> Result<String, String> {
    let config = macos_launchd_restart_config_from_env()?;
    let daemon_uid = Uid::from_raw(config.service.daemon_uid);
    let daemon_gid = Gid::from_raw(config.daemon_gid);

    ensure_directory_with_mode_owner(
        config.runtime_base.as_path(),
        0o700,
        Some(daemon_uid),
        Some(daemon_gid),
    )?;
    ensure_directory_with_mode_owner(
        config.log_base.as_path(),
        0o700,
        Some(daemon_uid),
        Some(daemon_gid),
    )?;

    let daemon_plist_parent = config
        .service
        .daemon_plist_path
        .parent()
        .ok_or_else(|| {
            format!(
                "daemon launchd plist path has no parent: {}",
                config.service.daemon_plist_path.display()
            )
        })?
        .to_path_buf();
    ensure_directory_with_mode_owner(
        daemon_plist_parent.as_path(),
        0o700,
        Some(daemon_uid),
        Some(daemon_gid),
    )?;

    ensure_directory_with_mode_owner(
        Path::new("/Library/LaunchDaemons"),
        0o755,
        Some(Uid::from_raw(0)),
        Some(Gid::from_raw(0)),
    )?;

    let helper_group = Group::from_name("wheel")
        .map_err(|err| format!("resolve group wheel failed: {err}"))?
        .map(|group| group.gid)
        .unwrap_or_else(|| Gid::from_raw(0));

    write_launchd_plist(
        config.service.helper_plist_path.as_path(),
        build_helper_launchd_plist(&config).as_str(),
        Uid::from_raw(0),
        helper_group,
        "macOS privileged helper launchd plist",
    )?;
    write_launchd_plist(
        config.service.daemon_plist_path.as_path(),
        build_daemon_launchd_plist(&config).as_str(),
        daemon_uid,
        daemon_gid,
        "macOS daemon launchd plist",
    )?;

    launchctl_bootout_unit(
        "system",
        config.service.helper_label.as_str(),
        config.service.helper_plist_path.as_path(),
    )?;
    launchctl_bootout_unit(
        config.service.daemon_domain.as_str(),
        config.service.daemon_label.as_str(),
        config.service.daemon_plist_path.as_path(),
    )?;

    run_launchctl_action(
        &[
            "bootstrap",
            "system",
            config.service.helper_plist_path.to_string_lossy().as_ref(),
        ],
        "launchd helper bootstrap",
    )?;
    run_launchctl_action(
        &["kickstart", "-k", config.service.helper_target.as_str()],
        "launchd helper kickstart",
    )?;
    run_launchctl_action(
        &[
            "bootstrap",
            config.service.daemon_domain.as_str(),
            config.service.daemon_plist_path.to_string_lossy().as_ref(),
        ],
        "launchd daemon bootstrap",
    )?;
    run_launchctl_action(
        &["kickstart", "-k", config.service.daemon_target.as_str()],
        "launchd daemon kickstart",
    )?;

    wait_for_unix_socket(
        config.service.helper_socket_path.as_path(),
        "privileged helper socket",
        Duration::from_secs(MACOS_RUNTIME_SOCKET_WAIT_SECS),
    )?;
    wait_for_unix_socket(
        config.service.daemon_socket_path.as_path(),
        "daemon socket",
        Duration::from_secs(MACOS_RUNTIME_SOCKET_WAIT_SECS),
    )
    .map_err(|err| {
        let tail =
            tail_utf8_lines(config.daemon_log_path.as_path(), 40).unwrap_or_else(|_| String::new());
        if tail.is_empty() {
            err
        } else {
            format!("{err}; recent daemon log:\n{tail}")
        }
    })?;

    Ok(format!(
        "runtime service restarted: host=macos daemon_target={} helper_target={} daemon_socket={} helper_socket={}",
        config.service.daemon_target,
        config.service.helper_target,
        config.service.daemon_socket_path.display(),
        config.service.helper_socket_path.display()
    ))
}

fn macos_launchd_restart_config_from_env() -> Result<MacosLaunchdRestartConfig, String> {
    let service = macos_runtime_service_context_from_env()?;
    let daemon_gid = macos_daemon_gid_from_env(service.daemon_uid)?;

    let runtime_base = env_required_path("RUSTYNET_MACOS_RUNTIME_BASE")?;
    let log_base = env_required_path("RUSTYNET_MACOS_LOG_BASE")?;
    let daemon_log_path = env_required_path("RUSTYNET_MACOS_DAEMON_LOG_PATH")?;
    let helper_log_path = env_required_path("RUSTYNET_MACOS_HELPER_LOG_PATH")?;
    if !daemon_log_path.starts_with(log_base.as_path()) {
        return Err(format!(
            "daemon log path must remain under log base: {}",
            daemon_log_path.display()
        ));
    }
    if !helper_log_path.starts_with(log_base.as_path()) {
        return Err(format!(
            "helper log path must remain under log base: {}",
            helper_log_path.display()
        ));
    }

    let daemon_binary_path =
        binary_path_from_env_or_command("RUSTYNET_DAEMON_BINARY_PATH", "rustynetd", "rustynetd")?;
    let wg_binary_path = binary_path_from_env_or_command("RUSTYNET_WG_BINARY_PATH", "wg", "wg")?;
    let wireguard_go_binary_path = binary_path_from_env_or_command(
        "RUSTYNET_WIREGUARD_GO_BINARY_PATH",
        "wireguard-go",
        "wireguard-go",
    )?;
    let ifconfig_binary_path =
        binary_path_from_env_or_command("RUSTYNET_IFCONFIG_BINARY_PATH", "ifconfig", "ifconfig")?;
    let route_binary_path =
        binary_path_from_env_or_command("RUSTYNET_ROUTE_BINARY_PATH", "route", "route")?;
    let pfctl_binary_path =
        binary_path_from_env_or_command("RUSTYNET_PFCTL_BINARY_PATH", "pfctl", "pfctl")?;
    let kill_binary_path =
        binary_path_from_env_or_command("RUSTYNET_KILL_BINARY_PATH", "kill", "kill")?;

    let keychain_account = required_macos_tunnel_keychain_account(
        env_string_or_default("RUSTYNET_WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT", "")?.as_str(),
    )?;
    let keychain_service = env_required_nonempty(
        "RUSTYNET_MACOS_WG_PASSPHRASE_KEYCHAIN_SERVICE",
        "macOS tunnel keychain service",
    )?;
    if keychain_service.trim().is_empty() {
        return Err("macOS tunnel keychain service must not be empty".to_string());
    }

    let wg_passphrase_path = env_required_path("RUSTYNET_WG_KEY_PASSPHRASE")?;
    validate_macos_wg_passphrase_placeholder_path(wg_passphrase_path.as_path())?;

    let helper_timeout_ms =
        parse_env_u64_with_default("RUSTYNET_PRIVILEGED_HELPER_TIMEOUT_MS", 2000)?;

    let auto_tunnel_enforce = parse_bool_value(
        "RUSTYNET_AUTO_TUNNEL_ENFORCE",
        env_string_or_default("RUSTYNET_AUTO_TUNNEL_ENFORCE", "false")?.as_str(),
    )?;
    let fail_closed_ssh_allow = parse_bool_value(
        "RUSTYNET_FAIL_CLOSED_SSH_ALLOW",
        env_string_or_default("RUSTYNET_FAIL_CLOSED_SSH_ALLOW", "false")?.as_str(),
    )?;
    let wg_interface = env_string_or_default("RUSTYNET_WG_INTERFACE", DEFAULT_WG_INTERFACE)?
        .trim()
        .to_string();
    validate_managed_dns_interface_name(wg_interface.as_str())?;
    let wg_listen_port = env_string_or_default("RUSTYNET_WG_LISTEN_PORT", "51820")?
        .parse::<u16>()
        .map_err(|err| format!("invalid wireguard listen port: {err}"))?;
    if wg_listen_port == 0 {
        return Err("wireguard listen port must be between 1 and 65535".to_string());
    }

    let helper_program_arguments = vec![
        daemon_binary_path.display().to_string(),
        "privileged-helper".to_string(),
        "--socket".to_string(),
        service.helper_socket_path.display().to_string(),
        "--allowed-uid".to_string(),
        service.daemon_uid.to_string(),
        "--allowed-gid".to_string(),
        daemon_gid.to_string(),
        "--timeout-ms".to_string(),
        helper_timeout_ms.to_string(),
    ];

    let daemon_program_arguments = vec![
        daemon_binary_path.display().to_string(),
        "daemon".to_string(),
        "--node-id".to_string(),
        env_required_nonempty("RUSTYNET_NODE_ID", "node id")?,
        "--node-role".to_string(),
        env_required_nonempty("RUSTYNET_NODE_ROLE", "node role")?,
        "--socket".to_string(),
        service.daemon_socket_path.display().to_string(),
        "--state".to_string(),
        env_required_path("RUSTYNET_STATE")?.display().to_string(),
        "--trust-evidence".to_string(),
        env_required_path("RUSTYNET_TRUST_EVIDENCE")?
            .display()
            .to_string(),
        "--trust-verifier-key".to_string(),
        env_required_path("RUSTYNET_TRUST_VERIFIER_KEY")?
            .display()
            .to_string(),
        "--trust-watermark".to_string(),
        env_required_path("RUSTYNET_TRUST_WATERMARK")?
            .display()
            .to_string(),
        "--membership-snapshot".to_string(),
        env_required_path("RUSTYNET_MEMBERSHIP_SNAPSHOT")?
            .display()
            .to_string(),
        "--membership-log".to_string(),
        env_required_path("RUSTYNET_MEMBERSHIP_LOG")?
            .display()
            .to_string(),
        "--membership-watermark".to_string(),
        env_required_path("RUSTYNET_MEMBERSHIP_WATERMARK")?
            .display()
            .to_string(),
        "--auto-tunnel-enforce".to_string(),
        if auto_tunnel_enforce {
            "true".to_string()
        } else {
            "false".to_string()
        },
        "--auto-tunnel-bundle".to_string(),
        env_required_path("RUSTYNET_AUTO_TUNNEL_BUNDLE")?
            .display()
            .to_string(),
        "--auto-tunnel-verifier-key".to_string(),
        env_required_path("RUSTYNET_AUTO_TUNNEL_VERIFIER_KEY")?
            .display()
            .to_string(),
        "--auto-tunnel-watermark".to_string(),
        env_required_path("RUSTYNET_AUTO_TUNNEL_WATERMARK")?
            .display()
            .to_string(),
        "--auto-tunnel-max-age-secs".to_string(),
        parse_env_u64_with_default(
            "RUSTYNET_AUTO_TUNNEL_MAX_AGE_SECS",
            DEFAULT_AUTO_TUNNEL_MAX_AGE_SECS,
        )?
        .to_string(),
        "--traversal-bundle".to_string(),
        env_required_path("RUSTYNET_TRAVERSAL_BUNDLE")?
            .display()
            .to_string(),
        "--traversal-verifier-key".to_string(),
        env_required_path("RUSTYNET_TRAVERSAL_VERIFIER_KEY")?
            .display()
            .to_string(),
        "--traversal-watermark".to_string(),
        env_required_path("RUSTYNET_TRAVERSAL_WATERMARK")?
            .display()
            .to_string(),
        "--traversal-max-age-secs".to_string(),
        parse_env_u64_with_default(
            "RUSTYNET_TRAVERSAL_MAX_AGE_SECS",
            DEFAULT_TRAVERSAL_MAX_AGE_SECS,
        )?
        .to_string(),
        "--backend".to_string(),
        env_required_nonempty("RUSTYNET_BACKEND", "backend mode")?,
        "--wg-interface".to_string(),
        wg_interface,
        "--wg-listen-port".to_string(),
        wg_listen_port.to_string(),
        "--wg-private-key".to_string(),
        env_required_path("RUSTYNET_WG_PRIVATE_KEY")?
            .display()
            .to_string(),
        "--wg-encrypted-private-key".to_string(),
        env_required_path("RUSTYNET_WG_ENCRYPTED_PRIVATE_KEY")?
            .display()
            .to_string(),
        "--wg-key-passphrase".to_string(),
        wg_passphrase_path.display().to_string(),
        "--wg-public-key".to_string(),
        env_required_path("RUSTYNET_WG_PUBLIC_KEY")?
            .display()
            .to_string(),
        "--egress-interface".to_string(),
        env_string_or_default("RUSTYNET_EGRESS_INTERFACE", "")?,
        "--dataplane-mode".to_string(),
        env_required_nonempty("RUSTYNET_DATAPLANE_MODE", "dataplane mode")?,
        "--privileged-helper-socket".to_string(),
        service.helper_socket_path.display().to_string(),
        "--privileged-helper-timeout-ms".to_string(),
        helper_timeout_ms.to_string(),
        "--reconcile-interval-ms".to_string(),
        parse_env_u64_with_default("RUSTYNET_RECONCILE_INTERVAL_MS", 1000)?.to_string(),
        "--max-reconcile-failures".to_string(),
        parse_env_u64_with_default("RUSTYNET_MAX_RECONCILE_FAILURES", 5)?.to_string(),
        "--fail-closed-ssh-allow".to_string(),
        if fail_closed_ssh_allow {
            "true".to_string()
        } else {
            "false".to_string()
        },
        "--fail-closed-ssh-allow-cidrs".to_string(),
        env_string_or_default("RUSTYNET_FAIL_CLOSED_SSH_ALLOW_CIDRS", "")?,
    ];

    let helper_environment = vec![
        (
            "RUSTYNET_WG_BINARY_PATH".to_string(),
            wg_binary_path.display().to_string(),
        ),
        (
            "RUSTYNET_WIREGUARD_GO_BINARY_PATH".to_string(),
            wireguard_go_binary_path.display().to_string(),
        ),
        (
            "RUSTYNET_IFCONFIG_BINARY_PATH".to_string(),
            ifconfig_binary_path.display().to_string(),
        ),
        (
            "RUSTYNET_ROUTE_BINARY_PATH".to_string(),
            route_binary_path.display().to_string(),
        ),
        (
            "RUSTYNET_PFCTL_BINARY_PATH".to_string(),
            pfctl_binary_path.display().to_string(),
        ),
        (
            "RUSTYNET_KILL_BINARY_PATH".to_string(),
            kill_binary_path.display().to_string(),
        ),
    ];

    let mut daemon_environment = helper_environment.clone();
    daemon_environment.push((
        "RUSTYNET_WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT".to_string(),
        keychain_account,
    ));
    daemon_environment.push((
        "RUSTYNET_MACOS_WG_PASSPHRASE_KEYCHAIN_SERVICE".to_string(),
        keychain_service,
    ));
    daemon_environment.push((
        "RUSTYNET_WG_KEY_PASSPHRASE_CREDENTIAL_PATH".to_string(),
        wg_passphrase_path.display().to_string(),
    ));

    Ok(MacosLaunchdRestartConfig {
        service,
        daemon_gid,
        runtime_base,
        log_base,
        daemon_log_path,
        helper_log_path,
        helper_program_arguments,
        daemon_program_arguments,
        helper_environment,
        daemon_environment,
    })
}

fn macos_daemon_gid_from_env(daemon_uid: u32) -> Result<u32, String> {
    if let Some(raw) = env_optional_string("RUSTYNET_MACOS_DAEMON_GID")? {
        return raw
            .parse::<u32>()
            .map_err(|err| format!("invalid daemon gid value '{raw}': {err}"));
    }
    if let Some(raw) = env_optional_string("SUDO_GID")? {
        return raw
            .parse::<u32>()
            .map_err(|err| format!("invalid sudo gid value '{raw}': {err}"));
    }
    let user = User::from_uid(Uid::from_raw(daemon_uid))
        .map_err(|err| format!("resolve daemon uid {daemon_uid} failed: {err}"))?
        .ok_or_else(|| format!("daemon uid {daemon_uid} does not exist"))?;
    Ok(user.gid.as_raw())
}

fn binary_path_from_env_or_command(
    env_key: &str,
    command_name: &str,
    label: &str,
) -> Result<PathBuf, String> {
    let path = if let Some(raw) = env_optional_string(env_key)? {
        let candidate = PathBuf::from(raw);
        if !candidate.is_absolute() {
            return Err(format!(
                "{label} binary path must be absolute: {}",
                candidate.display()
            ));
        }
        candidate
    } else {
        resolve_absolute_command_path(command_name)?
    };
    validate_root_owned_executable_path(path.as_path(), label)?;
    Ok(path)
}

fn resolve_absolute_command_path(command_name: &str) -> Result<PathBuf, String> {
    if command_name.trim().is_empty() {
        return Err("command name must not be empty".to_string());
    }
    if command_name.contains('/') {
        let path = PathBuf::from(command_name);
        if !path.is_absolute() {
            return Err(format!("command path must be absolute: {}", path.display()));
        }
        return Ok(path);
    }
    let path_env = std::env::var_os("PATH").ok_or_else(|| "PATH is not set".to_string())?;
    for base in std::env::split_paths(path_env.as_os_str()) {
        let candidate = base.join(command_name);
        if let Ok(metadata) = fs::metadata(candidate.as_path())
            && metadata.is_file()
            && (metadata.mode() & 0o111) != 0
        {
            return Ok(candidate);
        }
    }
    Err(format!(
        "unable to resolve absolute path for command: {command_name}"
    ))
}

fn validate_root_owned_executable_path(path: &Path, label: &str) -> Result<(), String> {
    if !path.is_absolute() {
        return Err(format!(
            "{label} binary path must be absolute: {}",
            path.display()
        ));
    }
    let metadata = fs::metadata(path)
        .map_err(|err| format!("inspect {label} binary failed ({}): {err}", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(format!(
            "{label} binary path must reference a regular file: {}",
            path.display()
        ));
    }
    if metadata.uid() != 0 {
        return Err(format!(
            "{label} binary must be root-owned for privileged runtime safety: {}",
            path.display()
        ));
    }
    let mode = metadata.mode() & 0o777;
    if (mode & 0o022) != 0 {
        return Err(format!(
            "{label} binary permissions too broad ({mode:03o}); group/other write is not allowed: {}",
            path.display()
        ));
    }
    if (mode & 0o111) == 0 {
        return Err(format!(
            "{label} binary must be executable: {}",
            path.display()
        ));
    }
    Ok(())
}

fn validate_macos_wg_passphrase_placeholder_path(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err(format!(
            "macOS passphrase placeholder path must be absolute: {}",
            path.display()
        ));
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(format!(
                    "persistent passphrase placeholder path must not be a symlink: {}",
                    path.display()
                ));
            }
            if metadata.file_type().is_file() {
                return Err(format!(
                    "persistent plaintext passphrase file is not allowed on macOS: {}",
                    path.display()
                ));
            }
            return Err(format!(
                "passphrase placeholder path is occupied and cannot be used: {}",
                path.display()
            ));
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(format!(
                "inspect macOS passphrase placeholder path failed ({}): {err}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn build_helper_launchd_plist(config: &MacosLaunchdRestartConfig) -> String {
    render_launchd_plist(
        config.service.helper_label.as_str(),
        config.helper_program_arguments.as_slice(),
        config.helper_environment.as_slice(),
        config.helper_log_path.as_path(),
        config.helper_log_path.as_path(),
    )
}

fn build_daemon_launchd_plist(config: &MacosLaunchdRestartConfig) -> String {
    render_launchd_plist(
        config.service.daemon_label.as_str(),
        config.daemon_program_arguments.as_slice(),
        config.daemon_environment.as_slice(),
        config.daemon_log_path.as_path(),
        config.daemon_log_path.as_path(),
    )
}

fn render_launchd_plist(
    label: &str,
    program_arguments: &[String],
    environment: &[(String, String)],
    stdout_path: &Path,
    stderr_path: &Path,
) -> String {
    let program_args_xml = render_launchd_string_array(program_arguments, "    ");
    let environment_xml = render_launchd_environment_dict(environment, "  ");
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\">\n\
<dict>\n\
  <key>Label</key>\n\
  <string>{}</string>\n\
  <key>ProgramArguments</key>\n\
  <array>\n\
{}\n\
  </array>\n\
{}\n\
  <key>RunAtLoad</key>\n\
  <true/>\n\
  <key>KeepAlive</key>\n\
  <true/>\n\
  <key>StandardOutPath</key>\n\
  <string>{}</string>\n\
  <key>StandardErrorPath</key>\n\
  <string>{}</string>\n\
</dict>\n\
</plist>\n",
        launchd_xml_escape(label),
        program_args_xml,
        environment_xml,
        launchd_xml_escape(stdout_path.to_string_lossy().as_ref()),
        launchd_xml_escape(stderr_path.to_string_lossy().as_ref()),
    )
}

fn render_launchd_string_array(values: &[String], indent: &str) -> String {
    values
        .iter()
        .map(|value| {
            format!(
                "{indent}<string>{}</string>",
                launchd_xml_escape(value.as_str())
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn render_launchd_environment_dict(values: &[(String, String)], indent: &str) -> String {
    if values.is_empty() {
        return String::new();
    }
    let child_indent = format!("{indent}  ");
    let mut rows = Vec::new();
    rows.push(format!("{indent}<key>EnvironmentVariables</key>"));
    rows.push(format!("{indent}<dict>"));
    for (key, value) in values {
        rows.push(format!(
            "{child_indent}<key>{}</key>",
            launchd_xml_escape(key.as_str())
        ));
        rows.push(format!(
            "{child_indent}<string>{}</string>",
            launchd_xml_escape(value.as_str())
        ));
    }
    rows.push(format!("{indent}</dict>"));
    rows.join("\n")
}

fn launchd_xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn write_launchd_plist(
    destination_path: &Path,
    body: &str,
    owner: Uid,
    group: Gid,
    label: &str,
) -> Result<(), String> {
    let parent = destination_path.parent().ok_or_else(|| {
        format!(
            "{label} destination path has no parent directory: {}",
            destination_path.display()
        )
    })?;
    if let Ok(parent_metadata) = fs::symlink_metadata(parent)
        && parent_metadata.file_type().is_symlink()
    {
        return Err(format!(
            "{label} destination parent must not be a symlink: {}",
            parent.display()
        ));
    }

    let temp_path = create_secure_temp_file(parent, "rustynet.ops.launchd.")?;
    if let Err(err) = write_private_bytes_to_file(temp_path.as_path(), body.as_bytes()) {
        let _ = remove_file_if_present(temp_path.as_path());
        return Err(err);
    }
    if let Err(err) = publish_file_with_owner_mode(
        temp_path.as_path(),
        destination_path,
        owner,
        group,
        0o644,
        label,
    ) {
        let _ = remove_file_if_present(temp_path.as_path());
        return Err(err);
    }
    Ok(())
}

fn run_launchctl_action(args: &[&str], label: &str) -> Result<(), String> {
    let output = run_command_capture("launchctl", args)?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "{} failed: {}",
        label,
        command_failure_detail(&output)
    ))
}

fn wait_for_unix_socket(path: &Path, label: &str, timeout: Duration) -> Result<(), String> {
    if !path.is_absolute() {
        return Err(format!("{label} path must be absolute: {}", path.display()));
    }
    let deadline = Instant::now() + timeout;
    loop {
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(format!("{label} must not be a symlink: {}", path.display()));
                }
                if metadata.file_type().is_socket() {
                    return Ok(());
                }
                return Err(format!("{label} must be a unix socket: {}", path.display()));
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(format!(
                    "inspect {label} failed ({}): {err}",
                    path.display()
                ));
            }
        }
        if Instant::now() >= deadline {
            return Err(format!("timed out waiting for {label}: {}", path.display()));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn tail_utf8_lines(path: &Path, max_lines: usize) -> Result<String, String> {
    if max_lines == 0 {
        return Ok(String::new());
    }
    let body = fs::read_to_string(path)
        .map_err(|err| format!("read daemon log failed ({}): {err}", path.display()))?;
    let lines = body.lines().collect::<Vec<_>>();
    let start = lines.len().saturating_sub(max_lines);
    Ok(lines[start..].join("\n"))
}

fn execute_ops_stop_runtime_service_macos() -> Result<String, String> {
    let context = macos_runtime_service_context_from_env()?;
    launchctl_bootout_unit(
        context.daemon_domain.as_str(),
        context.daemon_label.as_str(),
        context.daemon_plist_path.as_path(),
    )?;
    launchctl_bootout_unit(
        "system",
        context.helper_label.as_str(),
        context.helper_plist_path.as_path(),
    )?;
    remove_socket_if_present(context.daemon_socket_path.as_path(), "daemon socket")?;
    remove_socket_if_present(
        context.helper_socket_path.as_path(),
        "privileged helper socket",
    )?;
    Ok(format!(
        "runtime service stopped: daemon_target={} helper_target={} daemon_socket={} helper_socket={}",
        context.daemon_target,
        context.helper_target,
        context.daemon_socket_path.display(),
        context.helper_socket_path.display()
    ))
}

fn execute_ops_show_runtime_service_status_macos() -> Result<String, String> {
    let context = macos_runtime_service_context_from_env()?;

    let daemon_loaded =
        run_command_capture("launchctl", &["print", context.daemon_target.as_str()])?
            .status
            .success();
    let helper_loaded =
        run_command_capture("launchctl", &["print", context.helper_target.as_str()])?
            .status
            .success();
    let daemon_socket_present =
        socket_exists_and_is_socket(context.daemon_socket_path.as_path(), "daemon socket")?;
    let helper_socket_present = socket_exists_and_is_socket(
        context.helper_socket_path.as_path(),
        "privileged helper socket",
    )?;

    Ok(format!(
        "runtime service status (macos):\ndaemon_target={} loaded={}\nhelper_target={} loaded={}\ndaemon_socket={} present={}\nhelper_socket={} present={}",
        context.daemon_target,
        daemon_loaded,
        context.helper_target,
        helper_loaded,
        context.daemon_socket_path.display(),
        daemon_socket_present,
        context.helper_socket_path.display(),
        helper_socket_present,
    ))
}

fn execute_ops_disconnect_cleanup_macos() -> Result<String, String> {
    let context = macos_runtime_service_context_from_env()?;
    let interface = env_string_or_default("RUSTYNET_WG_INTERFACE", DEFAULT_WG_INTERFACE)?
        .trim()
        .to_string();
    validate_managed_dns_interface_name(interface.as_str())?;

    let mut errors = Vec::new();
    let mut service_stopped = false;
    let mut wireguard_go_killed = 0usize;
    let mut pf_anchors_flushed = 0usize;

    match execute_ops_stop_runtime_service_macos() {
        Ok(_) => {
            service_stopped = true;
        }
        Err(err) => errors.push(err),
    }

    match run_command_capture("ps", &["-ax", "-o", "pid=", "-o", "command="]) {
        Ok(ps_output) => {
            if !ps_output.status.success() {
                errors.push(format!(
                    "enumerate process list failed: {}",
                    command_failure_detail(&ps_output)
                ));
            } else {
                let ps_body = String::from_utf8_lossy(&ps_output.stdout);
                match parse_wireguard_go_pids_from_ps(ps_body.as_ref(), interface.as_str()) {
                    Ok(pids) => {
                        for pid in pids {
                            let pid_raw = pid.to_string();
                            match run_command_capture("kill", &["-TERM", pid_raw.as_str()]) {
                                Ok(kill_output) => {
                                    if kill_output.status.success() {
                                        wireguard_go_killed += 1;
                                    } else {
                                        let detail = command_failure_detail(&kill_output);
                                        if !detail.contains("No such process") {
                                            errors.push(format!(
                                                "terminate wireguard-go pid {pid} failed: {detail}"
                                            ));
                                        }
                                    }
                                }
                                Err(err) => errors.push(err),
                            }
                        }
                    }
                    Err(err) => errors.push(err),
                }
            }
        }
        Err(err) => errors.push(err),
    }

    match run_command_capture("pfctl", &["-s", "Anchors"]) {
        Ok(anchor_output) => {
            if !anchor_output.status.success() {
                errors.push(format!(
                    "enumerate PF anchors failed: {}",
                    command_failure_detail(&anchor_output)
                ));
            } else {
                let body = String::from_utf8_lossy(&anchor_output.stdout);
                for anchor in parse_managed_pf_anchors(body.as_ref()) {
                    match run_command_capture("pfctl", &["-a", anchor.as_str(), "-F", "all"]) {
                        Ok(flush_output) => {
                            if flush_output.status.success() {
                                pf_anchors_flushed += 1;
                            } else {
                                errors.push(format!(
                                    "flush PF anchor {} failed: {}",
                                    anchor,
                                    command_failure_detail(&flush_output)
                                ));
                            }
                        }
                        Err(err) => errors.push(err),
                    }
                }
            }
        }
        Err(err) => errors.push(err),
    }

    if !errors.is_empty() {
        return Err(format!(
            "disconnect cleanup completed with residual-state errors: {}",
            errors.join(" | ")
        ));
    }

    Ok(format!(
        "disconnect cleanup complete: host=macos service_stopped={} daemon_target={} helper_target={} wireguard_go_killed={} pf_anchors_flushed={}",
        service_stopped,
        context.daemon_target,
        context.helper_target,
        wireguard_go_killed,
        pf_anchors_flushed
    ))
}

fn parse_managed_pf_anchors(body: &str) -> Vec<String> {
    let mut anchors = body
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("com.apple/rustynet_g"))
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    anchors.sort();
    anchors.dedup();
    anchors
}

fn parse_wireguard_go_pids_from_ps(ps_output: &str, interface: &str) -> Result<Vec<i32>, String> {
    let mut pids = Vec::new();
    for line in ps_output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut fields = trimmed.split_whitespace();
        let Some(pid_token) = fields.next() else {
            continue;
        };
        let pid = pid_token
            .parse::<i32>()
            .map_err(|_| format!("invalid pid token in ps output: {pid_token}"))?;
        if pid <= 0 {
            return Err(format!("invalid pid value in ps output: {pid}"));
        }
        let command_tokens = fields.collect::<Vec<_>>();
        if command_tokens
            .windows(2)
            .any(|window| window[0].ends_with("wireguard-go") && window[1] == interface)
        {
            pids.push(pid);
        }
    }
    pids.sort_unstable();
    pids.dedup();
    Ok(pids)
}

fn macos_runtime_service_context_from_env() -> Result<MacosRuntimeServiceContext, String> {
    let daemon_uid = macos_daemon_uid_from_env()?;
    let daemon_domain = macos_launchd_domain_for_uid(daemon_uid);
    let daemon_label = env_string_or_default(
        "RUSTYNET_MACOS_LAUNCHD_DAEMON_LABEL",
        DEFAULT_MACOS_LAUNCHD_DAEMON_LABEL,
    )?;
    validate_launchd_label(daemon_label.as_str(), "daemon launchd label")?;
    let helper_label = env_string_or_default(
        "RUSTYNET_MACOS_LAUNCHD_HELPER_LABEL",
        DEFAULT_MACOS_LAUNCHD_HELPER_LABEL,
    )?;
    validate_launchd_label(helper_label.as_str(), "helper launchd label")?;

    let daemon_plist_path = resolve_macos_daemon_plist_path(daemon_uid, daemon_label.as_str())?;
    let helper_plist_path = env_path_or_default(
        "RUSTYNET_MACOS_LAUNCHD_HELPER_PLIST",
        DEFAULT_MACOS_LAUNCHD_HELPER_PLIST_PATH,
    )?;
    let daemon_socket_path = env_path_or_default("RUSTYNET_SOCKET", DEFAULT_DAEMON_SOCKET_PATH)?;
    let helper_socket_path = env_path_or_default(
        "RUSTYNET_PRIVILEGED_HELPER_SOCKET",
        DEFAULT_PRIVILEGED_HELPER_SOCKET_PATH,
    )?;

    Ok(MacosRuntimeServiceContext {
        daemon_uid,
        daemon_domain: daemon_domain.clone(),
        daemon_label: daemon_label.clone(),
        helper_label: helper_label.clone(),
        daemon_target: format!("{daemon_domain}/{daemon_label}"),
        helper_target: format!("system/{helper_label}"),
        daemon_plist_path,
        helper_plist_path,
        daemon_socket_path,
        helper_socket_path,
    })
}

fn macos_daemon_uid_from_env() -> Result<u32, String> {
    let raw_uid = match env_optional_string("RUSTYNET_MACOS_DAEMON_UID")? {
        Some(value) => value,
        None => env_optional_string("SUDO_UID")?
            .unwrap_or_else(|| Uid::effective().as_raw().to_string()),
    };
    let daemon_uid = raw_uid
        .parse::<u32>()
        .map_err(|err| format!("invalid daemon uid value '{raw_uid}': {err}"))?;
    if daemon_uid == 0 {
        return Err("daemon uid must be a non-root user on macOS".to_string());
    }
    Ok(daemon_uid)
}

fn macos_launchd_domain_for_uid(uid: u32) -> String {
    let gui_domain = format!("gui/{uid}");
    match run_command_capture("launchctl", &["print", gui_domain.as_str()]) {
        Ok(output) if output.status.success() => gui_domain,
        _ => format!("user/{uid}"),
    }
}

fn validate_launchd_label(label: &str, field_name: &str) -> Result<(), String> {
    if label.trim().is_empty() {
        return Err(format!("{field_name} must not be empty"));
    }
    if !label
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
    {
        return Err(format!("{field_name} contains invalid characters"));
    }
    Ok(())
}

fn resolve_macos_daemon_plist_path(daemon_uid: u32, daemon_label: &str) -> Result<PathBuf, String> {
    if let Some(explicit_path) = env_optional_string("RUSTYNET_MACOS_LAUNCHD_DAEMON_PLIST")? {
        let path = PathBuf::from(explicit_path);
        if !path.is_absolute() {
            return Err(format!(
                "daemon launchd plist path must be absolute: {}",
                path.display()
            ));
        }
        return Ok(path);
    }

    let user = User::from_uid(Uid::from_raw(daemon_uid))
        .map_err(|err| format!("resolve daemon uid {daemon_uid} failed: {err}"))?
        .ok_or_else(|| format!("daemon uid {daemon_uid} does not exist"))?;
    Ok(user
        .dir
        .join("Library/LaunchAgents")
        .join(format!("{daemon_label}.plist")))
}

fn launchctl_bootout_unit(domain: &str, label: &str, plist_path: &Path) -> Result<(), String> {
    if !plist_path.is_absolute() {
        return Err(format!(
            "launchd plist path must be absolute: {}",
            plist_path.display()
        ));
    }
    let target = format!("{domain}/{label}");
    let plist_arg = plist_path.to_string_lossy().to_string();

    let target_output = run_command_capture("launchctl", &["bootout", target.as_str()])?;
    if target_output.status.success() {
        return Ok(());
    }

    let domain_output = run_command_capture("launchctl", &["bootout", domain, plist_arg.as_str()])?;
    if domain_output.status.success() {
        return Ok(());
    }

    let print_output = run_command_capture("launchctl", &["print", target.as_str()])?;
    if !print_output.status.success() {
        return Ok(());
    }

    Err(format!(
        "failed to unload launchd unit {}: {}",
        target,
        command_failure_detail(&domain_output)
    ))
}

fn socket_exists_and_is_socket(path: &Path, label: &str) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(format!("{label} must not be a symlink: {}", path.display()));
            }
            if !metadata.file_type().is_socket() {
                return Err(format!("{label} must be a unix socket: {}", path.display()));
            }
            Ok(true)
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(format!(
            "inspect {label} failed ({}): {err}",
            path.display()
        )),
    }
}

fn remove_socket_if_present(path: &Path, label: &str) -> Result<bool, String> {
    if !path.is_absolute() {
        return Err(format!("{label} path must be absolute: {}", path.display()));
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(format!("{label} must not be a symlink: {}", path.display()));
            }
            if !metadata.file_type().is_socket() {
                return Err(format!("{label} must be a unix socket: {}", path.display()));
            }
            fs::remove_file(path)
                .map_err(|err| format!("remove {label} failed ({}): {err}", path.display()))?;
            Ok(true)
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(format!(
            "inspect {label} failed ({}): {err}",
            path.display()
        )),
    }
}

fn run_command_capture(program: &str, args: &[&str]) -> Result<std::process::Output, String> {
    Command::new(program)
        .args(args)
        .output()
        .map_err(|err| format!("invoke {} {} failed: {err}", program, args.join(" ")))
}

fn command_failure_detail(output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if !stderr.is_empty() {
        return stderr;
    }
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if !stdout.is_empty() {
        return stdout;
    }
    format!("exit status {}", output.status)
}

fn is_interface_absent_detail(detail: &str) -> bool {
    let normalized = detail.to_ascii_lowercase();
    normalized.contains("cannot find device")
        || normalized.contains("does not exist")
        || normalized.contains("no such device")
}

fn contains_ip_rule_lookup_table(body: &str, table: &str) -> bool {
    body.lines().any(|line| {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        fields
            .windows(2)
            .any(|window| window[0] == "lookup" && window[1] == table)
    })
}

fn command_available(program: &str) -> bool {
    match Command::new(program)
        .arg("--help")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
    {
        Ok(_) => true,
        Err(err) => err.kind() != io::ErrorKind::NotFound,
    }
}

fn execute_ops_ensure_signing_passphrase_material() -> Result<String, String> {
    let config = signing_passphrase_ops_config_from_env()?;
    ensure_signing_passphrase_material_ops(&config)?;
    Ok("signing passphrase material verified".to_string())
}

fn execute_ops_ensure_local_trust_material(
    signing_key_passphrase_path: PathBuf,
) -> Result<String, String> {
    if !signing_key_passphrase_path.is_absolute() {
        return Err(format!(
            "signing key passphrase file path must be absolute: {}",
            signing_key_passphrase_path.display()
        ));
    }
    ensure_regular_file_no_symlink(
        signing_key_passphrase_path.as_path(),
        "signing key passphrase file",
    )?;

    let config = signing_passphrase_ops_config_from_env()?;
    if matches!(config.host_profile, SigningPassphraseHostProfile::Linux) {
        require_root_execution()?;
    }

    let trust_signer_key_path = config.trust_signer_key_path;
    let trust_verifier_key_path = env_path_or_default(
        "RUSTYNET_TRUST_VERIFIER_KEY",
        DEFAULT_TRUST_VERIFIER_KEY_PATH,
    )?;

    let verifier_parent = trust_verifier_key_path.parent().ok_or_else(|| {
        format!(
            "trust verifier key path has no parent directory: {}",
            trust_verifier_key_path.display()
        )
    })?;
    let verifier_parent_metadata = fs::symlink_metadata(verifier_parent).map_err(|err| {
        format!(
            "inspect trust verifier parent directory failed ({}): {err}",
            verifier_parent.display()
        )
    })?;
    if verifier_parent_metadata.file_type().is_symlink() {
        return Err(format!(
            "trust verifier parent directory must not be a symlink: {}",
            verifier_parent.display()
        ));
    }
    if !verifier_parent_metadata.file_type().is_dir() {
        return Err(format!(
            "trust verifier parent path must be a directory: {}",
            verifier_parent.display()
        ));
    }

    let (signing_key, initialized_signer) = if trust_signer_key_path.exists() {
        (
            load_signing_key(
                trust_signer_key_path.as_path(),
                signing_key_passphrase_path.as_path(),
            )?,
            false,
        )
    } else {
        let mut seed = [0u8; 32];
        fill_os_random_bytes(&mut seed, "trust signing key")?;
        let signing_key = SigningKey::from_bytes(&seed);
        let persist_result = persist_encrypted_secret_material(
            trust_signer_key_path.as_path(),
            &seed,
            signing_key_passphrase_path.as_path(),
            "trust signing key",
            false,
        );
        seed.zeroize();
        persist_result?;
        (signing_key, true)
    };
    let verifier_key_hex = hex_bytes(signing_key.verifying_key().as_bytes());
    let verifier_payload = format!("{verifier_key_hex}\n");

    let verifier_tmp = create_secure_temp_file(verifier_parent, "trust-verifier.tmp.")?;
    if let Err(err) =
        write_private_bytes_to_file(verifier_tmp.as_path(), verifier_payload.as_bytes())
    {
        let _ = remove_file_if_present(verifier_tmp.as_path());
        return Err(err);
    }

    let (owner, group) = match config.host_profile {
        SigningPassphraseHostProfile::Linux => (Uid::from_raw(0), Gid::from_raw(0)),
        SigningPassphraseHostProfile::Macos => (Uid::effective(), Gid::effective()),
    };
    if let Err(err) = publish_file_with_owner_mode(
        verifier_tmp.as_path(),
        trust_verifier_key_path.as_path(),
        owner,
        group,
        0o644,
        "trust verifier key",
    ) {
        let _ = remove_file_if_present(verifier_tmp.as_path());
        return Err(err);
    }

    Ok(format!(
        "local trust material ensured: signing_key={} verifier_key={} initialized_signer={}",
        trust_signer_key_path.display(),
        trust_verifier_key_path.display(),
        initialized_signer
    ))
}

fn execute_ops_materialize_signing_passphrase(output_path: PathBuf) -> Result<String, String> {
    if !output_path.is_absolute() {
        return Err(format!(
            "output path must be absolute: {}",
            output_path.display()
        ));
    }
    let config = signing_passphrase_ops_config_from_env()?;
    ensure_signing_passphrase_material_ops(&config)?;
    materialize_signing_passphrase_ops(&config, output_path.as_path())?;
    Ok(format!(
        "signing passphrase materialized at {}",
        output_path.display()
    ))
}

fn execute_ops_materialize_signing_passphrase_temp() -> Result<String, String> {
    let config = signing_passphrase_ops_config_from_env()?;
    ensure_signing_passphrase_material_ops(&config)?;
    let temp_output =
        create_secure_temp_file(std::env::temp_dir().as_path(), "signing-passphrase.")?;
    if let Err(err) = materialize_signing_passphrase_ops(&config, temp_output.as_path()) {
        let _ = secure_remove_file(temp_output.as_path());
        return Err(err);
    }
    Ok(temp_output.display().to_string())
}

fn execute_ops_bootstrap_wireguard_custody() -> Result<String, String> {
    let config = wireguard_custody_ops_config_from_env()?;
    if matches!(config.host_profile, SigningPassphraseHostProfile::Linux) {
        require_root_execution()?;
    }

    ensure_parent_directory_for_wireguard_path(
        config.runtime_private_key_path.as_path(),
        config.host_profile,
    )?;
    ensure_parent_directory_for_wireguard_path(
        config.encrypted_private_key_path.as_path(),
        config.host_profile,
    )?;
    ensure_parent_directory_for_wireguard_path(
        config.public_key_path.as_path(),
        config.host_profile,
    )?;
    if matches!(config.host_profile, SigningPassphraseHostProfile::Linux) {
        ensure_parent_directory_for_wireguard_path(
            config.passphrase_credential_blob_path.as_path(),
            config.host_profile,
        )?;
    }

    if config.encrypted_private_key_path.exists() {
        validate_encrypted_secret_file_security(
            config.encrypted_private_key_path.as_path(),
            "tunnel encrypted private key",
        )?;
    }
    if config.public_key_path.exists() {
        ensure_regular_file_no_symlink(config.public_key_path.as_path(), "tunnel public key")?;
    }
    if config.passphrase_credential_blob_path.exists() {
        ensure_regular_file_no_symlink(
            config.passphrase_credential_blob_path.as_path(),
            "tunnel passphrase credential blob",
        )?;
    }

    let encrypted_present = config.encrypted_private_key_path.exists();
    let public_present = config.public_key_path.exists();
    let credential_present = config.passphrase_credential_blob_path.exists();
    let legacy_plaintext_private_key_path = Path::new(DEFAULT_LEGACY_LINUX_WG_PRIVATE_KEY_PATH);
    let legacy_plaintext_passphrase_path = Path::new("/etc/rustynet/wireguard.passphrase");

    if matches!(config.host_profile, SigningPassphraseHostProfile::Linux)
        && !config.runtime_private_key_path.exists()
        && legacy_plaintext_private_key_path.exists()
    {
        return Err(format!(
            "legacy plaintext tunnel private key detected at {}; implicit migration is disabled. Move it to canonical runtime path {} and rerun, or rotate/reinitialize keys explicitly",
            legacy_plaintext_private_key_path.display(),
            config.runtime_private_key_path.display()
        ));
    }

    if matches!(config.host_profile, SigningPassphraseHostProfile::Linux)
        && encrypted_present
        && !credential_present
    {
        return Err(format!(
            "encrypted key exists but credential blob is missing ({}); restore the encrypted credential blob from backup or perform explicit key rotation",
            config.passphrase_credential_blob_path.display()
        ));
    }

    if encrypted_present && public_present {
        match config.host_profile {
            SigningPassphraseHostProfile::Linux => {
                if credential_present {
                    validate_root_owned_private_file(
                        config.passphrase_credential_blob_path.as_path(),
                        "tunnel passphrase credential blob",
                    )?;
                    let removed_runtime_plaintext =
                        secure_remove_if_present(config.passphrase_path.as_path())?;
                    let removed_legacy_plaintext =
                        secure_remove_if_present(legacy_plaintext_passphrase_path)?;
                    let removed_legacy_plaintext_private_key =
                        secure_remove_if_present(legacy_plaintext_private_key_path)?;
                    return Ok(format!(
                        "tunnel custody already initialized: encrypted_private_key={} public_key={} credential_blob={} removed_runtime_plaintext_passphrase={} removed_legacy_plaintext_passphrase={} removed_legacy_plaintext_private_key={}",
                        config.encrypted_private_key_path.display(),
                        config.public_key_path.display(),
                        config.passphrase_credential_blob_path.display(),
                        removed_runtime_plaintext,
                        removed_legacy_plaintext,
                        removed_legacy_plaintext_private_key
                    ));
                }
            }
            SigningPassphraseHostProfile::Macos => {
                let account =
                    required_macos_tunnel_keychain_account(config.macos_keychain_account.as_str())?;
                if macos_generic_password_exists(
                    config.macos_keychain_service.as_str(),
                    account.as_str(),
                )? {
                    let removed_runtime_plaintext =
                        secure_remove_if_present(config.passphrase_path.as_path())?;
                    return Ok(format!(
                        "tunnel custody already initialized on macOS: encrypted_private_key={} public_key={} keychain_service={} keychain_account={} removed_runtime_plaintext_passphrase={}",
                        config.encrypted_private_key_path.display(),
                        config.public_key_path.display(),
                        config.macos_keychain_service,
                        account,
                        removed_runtime_plaintext
                    ));
                }
                if config.passphrase_path.exists() {
                    store_passphrase_in_os_secure_store(
                        config.passphrase_path.as_path(),
                        Some(account.as_str()),
                    )?;
                    secure_remove_if_present(config.passphrase_path.as_path())?;
                    return Ok(format!(
                        "tunnel passphrase migrated to macOS keychain custody: keychain_service={} keychain_account={} encrypted_private_key={} public_key={}",
                        config.macos_keychain_service,
                        account,
                        config.encrypted_private_key_path.display(),
                        config.public_key_path.display()
                    ));
                }
                return Err(format!(
                    "encrypted key exists but macOS keychain passphrase item is missing (service={}, account={}); restore keychain entry or rotate keys",
                    config.macos_keychain_service, account
                ));
            }
        }
    }

    if !config.allow_init {
        return Err(
            "encrypted tunnel key material is missing and initialization is not approved; set RUSTYNET_WG_CUSTODY_ALLOW_INIT=true".to_string(),
        );
    }

    let passphrase_tmp =
        create_secure_temp_file(std::env::temp_dir().as_path(), "tunnel-passphrase.")?;
    let mut random_bytes = [0u8; 48];
    fill_os_random_bytes(&mut random_bytes, "tunnel passphrase")?;
    let mut passphrase_hex = Zeroizing::new(hex_bytes(&random_bytes));
    random_bytes.zeroize();
    passphrase_hex.push('\n');
    if let Err(err) =
        write_private_bytes_to_file(passphrase_tmp.as_path(), passphrase_hex.as_bytes())
    {
        let _ = secure_remove_file(passphrase_tmp.as_path());
        return Err(err);
    }

    let bootstrap_result = (|| -> Result<String, String> {
        let source_private_key_path = if config.runtime_private_key_path.exists() {
            Some(config.runtime_private_key_path.clone())
        } else {
            None
        };

        let operation = if let Some(source_private_key_path) = source_private_key_path {
            validate_private_key_source_file(
                source_private_key_path.as_path(),
                config.host_profile,
                "tunnel plaintext private key source",
            )?;
            migrate_existing_private_key_material(
                source_private_key_path.as_path(),
                config.runtime_private_key_path.as_path(),
                config.encrypted_private_key_path.as_path(),
                config.public_key_path.as_path(),
                passphrase_tmp.as_path(),
                Some(passphrase_tmp.as_path()),
                true,
            )?;
            "migrated"
        } else {
            initialize_encrypted_key_material(
                config.runtime_private_key_path.as_path(),
                config.encrypted_private_key_path.as_path(),
                config.public_key_path.as_path(),
                passphrase_tmp.as_path(),
                Some(passphrase_tmp.as_path()),
                true,
            )?;
            "initialized"
        };

        match config.host_profile {
            SigningPassphraseHostProfile::Linux => {
                provision_linux_tunnel_passphrase_credential_blob(
                    passphrase_tmp.as_path(),
                    config.passphrase_credential_blob_path.as_path(),
                )?;
                let removed_runtime_plaintext =
                    secure_remove_if_present(config.passphrase_path.as_path())?;
                let removed_legacy_plaintext =
                    secure_remove_if_present(legacy_plaintext_passphrase_path)?;
                let removed_legacy_plaintext_private_key =
                    secure_remove_if_present(legacy_plaintext_private_key_path)?;
                Ok(format!(
                    "tunnel custody {operation}: encrypted_private_key={} public_key={} credential_blob={} removed_runtime_plaintext_passphrase={} removed_legacy_plaintext_passphrase={} removed_legacy_plaintext_private_key={}",
                    config.encrypted_private_key_path.display(),
                    config.public_key_path.display(),
                    config.passphrase_credential_blob_path.display(),
                    removed_runtime_plaintext,
                    removed_legacy_plaintext,
                    removed_legacy_plaintext_private_key
                ))
            }
            SigningPassphraseHostProfile::Macos => {
                let account =
                    required_macos_tunnel_keychain_account(config.macos_keychain_account.as_str())?;
                store_passphrase_in_os_secure_store(
                    passphrase_tmp.as_path(),
                    Some(account.as_str()),
                )?;
                let removed_runtime_plaintext =
                    secure_remove_if_present(config.passphrase_path.as_path())?;
                Ok(format!(
                    "tunnel custody {operation} on macOS: encrypted_private_key={} public_key={} keychain_service={} keychain_account={} removed_runtime_plaintext_passphrase={}",
                    config.encrypted_private_key_path.display(),
                    config.public_key_path.display(),
                    config.macos_keychain_service,
                    account,
                    removed_runtime_plaintext
                ))
            }
        }
    })();

    let cleanup_result = secure_remove_file(passphrase_tmp.as_path());
    match (bootstrap_result, cleanup_result) {
        (Ok(message), Ok(())) => Ok(message),
        (Err(err), Ok(())) => Err(err),
        (Ok(_), Err(cleanup_err)) => Err(cleanup_err),
        (Err(err), Err(cleanup_err)) => Err(format!("{err}; cleanup failed: {cleanup_err}")),
    }
}

fn execute_ops_set_assignment_refresh_exit_node(
    env_path: PathBuf,
    exit_node_id: Option<String>,
) -> Result<String, String> {
    require_root_execution()?;
    if !env_path.is_absolute() {
        return Err(format!(
            "assignment refresh env path must be absolute: {}",
            env_path.display()
        ));
    }
    if cfg!(target_os = "linux") {
        // Expected runtime for assignment-refresh coupling mutation.
    } else {
        return Err("set-assignment-refresh-exit-node is supported on Linux only".to_string());
    }
    if let Some(exit_node_id_value) = exit_node_id.as_deref()
        && !is_valid_assignment_refresh_exit_node_id(exit_node_id_value)
    {
        return Err(format!(
            "invalid exit node id (allowed: letters, numbers, dot, underscore, hyphen): {exit_node_id_value}"
        ));
    }

    ensure_regular_file_no_symlink(&env_path, "assignment refresh env file")?;
    let existing = fs::read_to_string(&env_path)
        .map_err(|err| format!("read assignment refresh env failed: {err}"))?;
    let rewritten =
        rewrite_assignment_refresh_exit_node(existing.as_str(), exit_node_id.as_deref());

    let parent = env_path.parent().ok_or_else(|| {
        format!(
            "assignment refresh env path has no parent: {}",
            env_path.display()
        )
    })?;
    let tmp = create_secure_temp_file(parent, "assignment-refresh.env.tmp.")?;
    if let Err(err) = write_private_bytes_to_file(tmp.as_path(), rewritten.as_bytes()) {
        let _ = remove_file_if_present(&tmp);
        return Err(err);
    }
    if let Err(err) = publish_file_with_owner_mode(
        &tmp,
        &env_path,
        Uid::from_raw(0),
        Gid::from_raw(0),
        0o600,
        "assignment refresh env",
    ) {
        let _ = remove_file_if_present(&tmp);
        return Err(err);
    }

    Ok(match exit_node_id {
        Some(exit_node_id_value) => format!(
            "assignment refresh exit node set: {} ({exit_node_id_value})",
            env_path.display()
        ),
        None => format!(
            "assignment refresh exit node cleared: {}",
            env_path.display()
        ),
    })
}

fn execute_ops_apply_lan_access_coupling(
    enable: bool,
    lan_routes: Vec<String>,
    assignment_refresh_env_path: PathBuf,
) -> Result<String, String> {
    require_root_execution()?;
    if !cfg!(target_os = "linux") {
        return Err("apply-lan-access-coupling is supported on Linux only".to_string());
    }
    if !assignment_refresh_env_path.is_absolute() {
        return Err(format!(
            "assignment refresh env path must be absolute: {}",
            assignment_refresh_env_path.display()
        ));
    }
    if enable || !lan_routes.is_empty() {
        validate_assignment_refresh_lan_routes(lan_routes.as_slice())?;
    }

    let assignment_refresh_available =
        assignment_refresh_available_ops(assignment_refresh_env_path.as_path())?;
    if !assignment_refresh_available {
        return Err(format!(
            "assignment refresh is unavailable ({}); LAN access coupling is fail-closed",
            assignment_refresh_env_path.display()
        ));
    }

    ensure_regular_file_no_symlink(&assignment_refresh_env_path, "assignment refresh env file")?;
    let existing = fs::read_to_string(&assignment_refresh_env_path)
        .map_err(|err| format!("read assignment refresh env failed: {err}"))?;
    let previous_lan_routes =
        assignment_refresh_env_value(existing.as_str(), "RUSTYNET_ASSIGNMENT_LAN_ROUTES")?
            .map(split_csv)
            .unwrap_or_default();
    let previous_lan_block_routes =
        assignment_refresh_env_value(existing.as_str(), "RUSTYNET_ASSIGNMENT_LAN_BLOCK_ROUTES")?
            .map(split_csv)
            .unwrap_or_default();
    let disable_blackhole_routes = disable_lan_blackhole_routes(
        lan_routes.as_slice(),
        previous_lan_block_routes.as_slice(),
        previous_lan_routes.as_slice(),
    );

    let socket_path = env_path_or_default("RUSTYNET_SOCKET", DEFAULT_DAEMON_SOCKET_PATH)?;
    let status = send_command_with_socket(IpcCommand::Status, socket_path.clone())?;
    if !status.ok {
        return Err(format!(
            "query daemon status failed before LAN access coupling: {}",
            status.message
        ));
    }
    let node_role = status_field(status.message.as_str(), "node_role")
        .ok_or_else(|| "daemon status missing node_role".to_string())?;
    if node_role == "blind_exit" {
        return Err("LAN access coupling is not permitted for blind_exit role".to_string());
    }
    let selected_exit_node = status_field(status.message.as_str(), "exit_node")
        .ok_or_else(|| "daemon status missing exit_node".to_string())?;
    if enable && (selected_exit_node.is_empty() || selected_exit_node == "none") {
        return Err("select an exit node before enabling LAN access".to_string());
    }

    let persisted_exit_node =
        assignment_refresh_env_value(existing.as_str(), "RUSTYNET_ASSIGNMENT_EXIT_NODE_ID")?;
    if enable {
        match persisted_exit_node.as_deref() {
            Some(exit_node_id) if exit_node_id == selected_exit_node => {}
            Some(exit_node_id) => {
                return Err(format!(
                    "assignment refresh exit node mismatch: daemon selected {selected_exit_node} but env persists {exit_node_id}"
                ));
            }
            None => {
                return Err(
                    "assignment refresh env is missing RUSTYNET_ASSIGNMENT_EXIT_NODE_ID; re-select the exit node first"
                        .to_string(),
                );
            }
        }
    }

    let rewritten = rewrite_assignment_refresh_lan_block_routes(
        rewrite_assignment_refresh_lan_routes(
            existing.as_str(),
            if enable { lan_routes.as_slice() } else { &[] },
        )
        .as_str(),
        if enable {
            lan_routes.as_slice()
        } else {
            disable_blackhole_routes.as_slice()
        },
    );
    let parent = assignment_refresh_env_path.parent().ok_or_else(|| {
        format!(
            "assignment refresh env path has no parent: {}",
            assignment_refresh_env_path.display()
        )
    })?;
    let tmp = create_secure_temp_file(parent, "assignment-refresh.env.tmp.")?;
    if let Err(err) = write_private_bytes_to_file(tmp.as_path(), rewritten.as_bytes()) {
        let _ = remove_file_if_present(&tmp);
        return Err(err);
    }
    if let Err(err) = publish_file_with_owner_mode(
        &tmp,
        &assignment_refresh_env_path,
        Uid::from_raw(0),
        Gid::from_raw(0),
        0o600,
        "assignment refresh env",
    ) {
        let _ = remove_file_if_present(&tmp);
        return Err(err);
    }

    if !enable {
        apply_lan_blackhole_routes(disable_blackhole_routes.as_slice(), true)?;
    }
    force_local_assignment_refresh_now_ops()?;
    wait_for_daemon_status_field(
        socket_path.as_path(),
        "lan_access",
        if enable { "on" } else { "off" },
        Duration::from_secs(20),
    )?;
    if enable {
        apply_lan_blackhole_routes(lan_routes.as_slice(), false)?;
    } else {
        // Reinstall the fail-closed blackhole after the refresh path, because
        // the dataplane generation rebuild can replace table 51820 contents.
        apply_lan_blackhole_routes(disable_blackhole_routes.as_slice(), true)?;
    }

    Ok(if enable {
        format!(
            "LAN access coupling enabled with {} via {}",
            lan_routes.join(","),
            assignment_refresh_env_path.display()
        )
    } else {
        format!(
            "LAN access coupling disabled via {}",
            assignment_refresh_env_path.display()
        )
    })
}

fn disable_lan_blackhole_routes(
    requested_lan_routes: &[String],
    previous_lan_block_routes: &[String],
    previous_lan_routes: &[String],
) -> Vec<String> {
    if requested_lan_routes.is_empty() {
        if previous_lan_block_routes.is_empty() {
            previous_lan_routes.to_vec()
        } else {
            previous_lan_block_routes.to_vec()
        }
    } else {
        requested_lan_routes.to_vec()
    }
}

fn reconcile_persisted_lan_blackhole_routes_after_refresh() -> Result<(), String> {
    let assignment_refresh_env_path = env_path_or_default(
        "RUSTYNET_ASSIGNMENT_REFRESH_ENV_PATH",
        DEFAULT_ASSIGNMENT_REFRESH_ENV_PATH,
    )?;
    if !assignment_refresh_env_path.exists() {
        return Ok(());
    }

    ensure_regular_file_no_symlink(
        assignment_refresh_env_path.as_path(),
        "assignment refresh env file",
    )?;
    let existing = fs::read_to_string(&assignment_refresh_env_path)
        .map_err(|err| format!("read assignment refresh env failed: {err}"))?;
    let lan_block_routes =
        assignment_refresh_env_value(existing.as_str(), "RUSTYNET_ASSIGNMENT_LAN_BLOCK_ROUTES")?
            .map(split_csv)
            .unwrap_or_default();
    if lan_block_routes.is_empty() {
        return Ok(());
    }

    let status = send_command(IpcCommand::Status)?;
    if !status.ok {
        return Err(format!(
            "query daemon status failed after state refresh: {}",
            status.message
        ));
    }
    let lan_access = status_field(status.message.as_str(), "lan_access").unwrap_or_default();
    let exit_node = status_field(status.message.as_str(), "exit_node").unwrap_or_default();
    if lan_access == "off" && !exit_node.is_empty() && exit_node != "none" {
        apply_lan_blackhole_routes(lan_block_routes.as_slice(), true)?;
    } else {
        apply_lan_blackhole_routes(lan_block_routes.as_slice(), false)?;
    }
    Ok(())
}

fn execute_ops_apply_role_coupling(
    target_role: String,
    preferred_exit_node_id: Option<String>,
    enable_exit_advertise: bool,
    assignment_refresh_env_path: PathBuf,
    skip_client_exit_route_convergence_wait: bool,
) -> Result<String, String> {
    require_root_execution()?;
    if !cfg!(target_os = "linux") {
        return Err("apply-role-coupling is supported on Linux only".to_string());
    }
    if !assignment_refresh_env_path.is_absolute() {
        return Err(format!(
            "assignment refresh env path must be absolute: {}",
            assignment_refresh_env_path.display()
        ));
    }
    if target_role != "admin" && target_role != "client" {
        return Err(format!(
            "unsupported target role for coupling: {target_role} (expected admin|client)"
        ));
    }
    if let Some(exit_node_id) = preferred_exit_node_id.as_deref()
        && !is_valid_assignment_refresh_exit_node_id(exit_node_id)
    {
        return Err(format!(
            "invalid preferred exit node id (allowed: letters, numbers, dot, underscore, hyphen): {exit_node_id}"
        ));
    }

    let mut warnings = Vec::new();
    let assignment_refresh_available =
        assignment_refresh_available_ops(assignment_refresh_env_path.as_path())?;
    if !assignment_refresh_available {
        return Err(format!(
            "assignment refresh is unavailable ({}); role coupling is fail-closed",
            assignment_refresh_env_path.display()
        ));
    }
    if target_role == "client" {
        if let Err(err) = execute_ops_set_assignment_refresh_exit_node(
            assignment_refresh_env_path.clone(),
            preferred_exit_node_id.clone(),
        ) {
            return Err(format!("set assignment refresh exit node failed: {err}"));
        }
    } else if let Err(err) =
        execute_ops_set_assignment_refresh_exit_node(assignment_refresh_env_path.clone(), None)
    {
        return Err(format!("clear assignment refresh exit node failed: {err}"));
    }

    if let Err(err) = force_local_assignment_refresh_now_ops() {
        return Err(format!("forced local assignment refresh failed: {err}"));
    }

    if target_role == "client"
        && let Some(expected_exit_node) = preferred_exit_node_id.as_deref()
    {
        if skip_client_exit_route_convergence_wait {
            warnings
                .push("skipped client exit route convergence wait after role coupling".to_string());
        } else {
            let socket_path = env_path_or_default("RUSTYNET_SOCKET", DEFAULT_DAEMON_SOCKET_PATH)?;
            if let Err(err) = wait_for_client_exit_route_convergence(
                socket_path.as_path(),
                assignment_refresh_env_path.as_path(),
                expected_exit_node,
                Duration::from_secs(30),
            ) {
                return Err(format!(
                    "client exit route convergence failed after role coupling: {err}"
                ));
            }
        }
    }

    if target_role == "admin"
        && enable_exit_advertise
        && let Err(err) =
            send_role_coupling_ipc(IpcCommand::RouteAdvertise("0.0.0.0/0".to_string()))
    {
        warnings.push(format!("advertise default exit route failed: {err}"));
    }

    if warnings.is_empty() {
        Ok(format!(
            "role coupling applied for target role {target_role}"
        ))
    } else {
        Ok(format!(
            "role coupling applied for target role {target_role} with warnings: {}",
            warnings.join(" | ")
        ))
    }
}

fn execute_ops_prepare_system_dirs() -> Result<String, String> {
    let host_profile =
        env_string_or_default("RUSTYNET_HOST_PROFILE", detect_host_profile())?.to_ascii_lowercase();
    let is_linux = host_profile == "linux";
    let is_macos = host_profile == "macos" || host_profile == "darwin";
    if !is_linux && !is_macos {
        return Err(format!(
            "unsupported host profile for prepare-system-dirs: {host_profile}"
        ));
    }
    if is_linux {
        require_root_execution()?;
    }

    let mut directories = HashSet::new();
    if is_linux {
        directories.insert(PathBuf::from("/etc/rustynet"));
        directories.insert(PathBuf::from("/run/rustynet"));
        directories.insert(PathBuf::from("/var/lib/rustynet"));
    }
    if is_macos {
        insert_absolute_directory_from_env(
            "RUSTYNET_MACOS_STATE_BASE",
            &mut directories,
            "macOS state base",
        )?;
        insert_absolute_directory_from_env(
            "RUSTYNET_MACOS_RUNTIME_BASE",
            &mut directories,
            "macOS runtime base",
        )?;
        insert_absolute_directory_from_env(
            "RUSTYNET_MACOS_LOG_BASE",
            &mut directories,
            "macOS log base",
        )?;
    }

    for key in [
        "RUSTYNET_STATE",
        "RUSTYNET_TRUST_EVIDENCE",
        "RUSTYNET_TRUST_VERIFIER_KEY",
        "RUSTYNET_TRUST_WATERMARK",
        "RUSTYNET_AUTO_TUNNEL_BUNDLE",
        "RUSTYNET_AUTO_TUNNEL_VERIFIER_KEY",
        "RUSTYNET_AUTO_TUNNEL_WATERMARK",
        "RUSTYNET_DNS_ZONE_BUNDLE",
        "RUSTYNET_DNS_ZONE_VERIFIER_KEY",
        "RUSTYNET_DNS_ZONE_WATERMARK",
        "RUSTYNET_TRAVERSAL_BUNDLE",
        "RUSTYNET_TRAVERSAL_VERIFIER_KEY",
        "RUSTYNET_TRAVERSAL_WATERMARK",
        "RUSTYNET_WG_PRIVATE_KEY",
        "RUSTYNET_WG_ENCRYPTED_PRIVATE_KEY",
        "RUSTYNET_WG_KEY_PASSPHRASE",
        "RUSTYNET_WG_KEY_PASSPHRASE_CREDENTIAL_BLOB",
        "RUSTYNET_SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB",
        "RUSTYNET_WG_PUBLIC_KEY",
        "RUSTYNET_MEMBERSHIP_SNAPSHOT",
        "RUSTYNET_MEMBERSHIP_LOG",
        "RUSTYNET_MEMBERSHIP_WATERMARK",
        "RUSTYNET_MEMBERSHIP_OWNER_SIGNING_KEY",
        "RUSTYNET_PRIVILEGED_HELPER_SOCKET",
    ] {
        insert_parent_dir_from_env_path(key, &mut directories)?;
    }

    let mut ordered = directories.into_iter().collect::<Vec<_>>();
    ordered.sort();
    for directory in ordered.as_slice() {
        if is_linux {
            ensure_directory_with_mode_owner(
                directory.as_path(),
                0o700,
                Some(Uid::from_raw(0)),
                Some(Gid::from_raw(0)),
            )?;
        } else {
            ensure_directory_with_mode_owner(directory.as_path(), 0o700, None, None)?;
        }
    }

    Ok(format!(
        "prepared {} runtime directory path(s) for {}",
        ordered.len(),
        host_profile
    ))
}

fn managed_dns_interface_name_from_env() -> Result<String, String> {
    let interface = env_string_or_default("RUSTYNET_WG_INTERFACE", DEFAULT_WG_INTERFACE)?
        .trim()
        .to_string();
    validate_managed_dns_interface_name(interface.as_str())?;
    Ok(interface)
}

fn validate_managed_dns_interface_name(interface: &str) -> Result<(), String> {
    if interface.is_empty() || interface.len() > 15 {
        return Err(
            "managed DNS routing interface name length must be between 1 and 15".to_string(),
        );
    }
    if !interface
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
    {
        return Err("managed DNS routing interface contains invalid characters".to_string());
    }
    Ok(())
}

fn managed_dns_zone_name_from_env() -> Result<String, String> {
    let zone_name = env_string_or_default("RUSTYNET_DNS_ZONE_NAME", DEFAULT_DNS_ZONE_NAME)?;
    canonicalize_dns_zone_name(zone_name.as_str())
        .map_err(|err| format!("invalid managed DNS zone name: {err}"))
}

fn managed_dns_resolver_bind_addr_from_env() -> Result<SocketAddr, String> {
    let raw = env_string_or_default(
        "RUSTYNET_DNS_RESOLVER_BIND_ADDR",
        DEFAULT_DNS_RESOLVER_BIND_ADDR,
    )?;
    let addr = raw
        .parse::<SocketAddr>()
        .map_err(|err| format!("invalid managed DNS resolver bind addr: {err}"))?;
    if !addr.ip().is_loopback() {
        return Err("managed DNS resolver bind addr must be loopback".to_string());
    }
    Ok(addr)
}

fn managed_dns_resolver_server_arg(addr: SocketAddr) -> Result<String, String> {
    match addr {
        SocketAddr::V4(v4) if v4.ip().is_loopback() => Ok(format!("{}:{}", v4.ip(), v4.port())),
        SocketAddr::V6(_) => Err(
            "managed DNS routing currently requires an IPv4 loopback resolver bind addr"
                .to_string(),
        ),
        _ => Err("managed DNS resolver bind addr must be loopback".to_string()),
    }
}

fn ensure_systemd_resolved_active() -> Result<(), String> {
    let output = Command::new("systemctl")
        .arg("is-active")
        .arg("--quiet")
        .arg("systemd-resolved.service")
        .output()
        .map_err(|err| {
            format!("invoke systemctl is-active systemd-resolved.service failed: {err}")
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if stderr.is_empty() {
            return Err(
                "systemd-resolved.service must be active for managed DNS routing".to_string(),
            );
        }
        return Err(format!(
            "systemd-resolved.service must be active for managed DNS routing: {stderr}"
        ));
    }
    Ok(())
}

fn wait_for_managed_dns_interface(interface: &str, timeout: Duration) -> Result<(), String> {
    let interface_path = Path::new("/sys/class/net").join(interface);
    let deadline = Instant::now() + timeout;
    loop {
        if interface_path.exists() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "managed DNS routing interface did not appear within {}s: {}",
                timeout.as_secs(),
                interface
            ));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn run_resolvectl_action(args: &[&str]) -> Result<(), String> {
    let output = Command::new("resolvectl")
        .args(args)
        .output()
        .map_err(|err| format!("invoke resolvectl {} failed: {err}", args.join(" ")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let detail = if stderr.is_empty() {
            format!("status {}", output.status)
        } else {
            stderr
        };
        return Err(format!("resolvectl {} failed: {}", args.join(" "), detail));
    }
    Ok(())
}

fn execute_ops_apply_blind_exit_lockdown() -> Result<String, String> {
    require_root_execution()?;
    if !cfg!(target_os = "linux") {
        return Err("apply-blind-exit-lockdown is supported on Linux only".to_string());
    }

    let assignment_signing_secret_path = env_path_or_default(
        "RUSTYNET_ASSIGNMENT_SIGNING_SECRET",
        DEFAULT_ASSIGNMENT_SIGNING_SECRET_PATH,
    )?;
    let assignment_refresh_env_path = env_path_or_default(
        "RUSTYNET_ASSIGNMENT_REFRESH_ENV_PATH",
        DEFAULT_ASSIGNMENT_REFRESH_ENV_PATH,
    )?;
    let systemd_env_path =
        env_path_or_default("RUSTYNET_SYSTEMD_ENV_PATH", DEFAULT_SYSTEMD_ENV_PATH)?;

    let mut removed = Vec::new();
    if secure_remove_root_owned_file_if_present(
        assignment_signing_secret_path.as_path(),
        "assignment signing secret",
    )? {
        removed.push(assignment_signing_secret_path.display().to_string());
    }
    if secure_remove_root_owned_file_if_present(
        assignment_refresh_env_path.as_path(),
        "assignment refresh env file",
    )? {
        removed.push(assignment_refresh_env_path.display().to_string());
    }

    let mut warnings = Vec::new();
    if let Err(err) = set_assignment_auto_refresh_disabled(systemd_env_path.as_path()) {
        warnings.push(err);
    }
    if let Err(err) = disable_assignment_refresh_timer() {
        warnings.push(err);
    }

    let mut summary = format!(
        "blind-exit lockdown applied: removed_sensitive_files={}",
        removed.len()
    );
    if !removed.is_empty() {
        summary.push_str(" [");
        summary.push_str(removed.join(", ").as_str());
        summary.push(']');
    }
    if !warnings.is_empty() {
        summary.push_str(" warnings=");
        summary.push_str(warnings.join(" | ").as_str());
    }
    Ok(summary)
}

fn execute_ops_init_membership() -> Result<String, String> {
    let config = signing_passphrase_ops_config_from_env()?;
    if matches!(config.host_profile, SigningPassphraseHostProfile::Linux) {
        require_root_execution()?;
    }

    let node_role = env_string_or_default("RUSTYNET_NODE_ROLE", "client")?.to_ascii_lowercase();
    if node_role != "admin" && node_role != "client" && node_role != "blind_exit" {
        return Err(format!(
            "unsupported node role for membership init: {node_role} (expected admin|client|blind_exit)"
        ));
    }
    if node_role == "blind_exit"
        && !matches!(config.host_profile, SigningPassphraseHostProfile::Linux)
    {
        return Err("blind_exit role is supported on Linux only".to_string());
    }

    let snapshot_path = env_path_or_default(
        "RUSTYNET_MEMBERSHIP_SNAPSHOT",
        DEFAULT_MEMBERSHIP_SNAPSHOT_PATH,
    )?;
    let log_path = env_path_or_default("RUSTYNET_MEMBERSHIP_LOG", DEFAULT_MEMBERSHIP_LOG_PATH)?;
    let watermark_path = env_path_or_default(
        "RUSTYNET_MEMBERSHIP_WATERMARK",
        DEFAULT_MEMBERSHIP_WATERMARK_PATH,
    )?;
    let owner_signing_key_path = env_path_or_default(
        "RUSTYNET_MEMBERSHIP_OWNER_SIGNING_KEY",
        DEFAULT_MEMBERSHIP_OWNER_SIGNING_KEY_PATH,
    )?;
    let node_id = env_required_nonempty("RUSTYNET_NODE_ID", "membership node id")?;
    if !is_valid_assignment_refresh_exit_node_id(node_id.as_str()) {
        return Err(format!(
            "membership node id contains unsupported characters: {node_id}"
        ));
    }
    let network_id = env_string_or_default("RUSTYNET_NETWORK_ID", "local-net")?;
    if network_id.trim().is_empty() {
        return Err("membership network id must not be empty".to_string());
    }
    let rustynetd_bin = env_string_or_default("RUSTYNET_RUSTYNETD_BIN", "rustynetd")?;
    if rustynetd_bin.trim().is_empty() {
        return Err("RUSTYNET_RUSTYNETD_BIN must not be empty".to_string());
    }

    for path in [
        &snapshot_path,
        &log_path,
        &watermark_path,
        &owner_signing_key_path,
    ] {
        ensure_parent_directory_for_membership_path(path, config.host_profile)?;
    }

    if snapshot_path.exists() {
        ensure_regular_file_no_symlink(&snapshot_path, "membership snapshot")?;
    }
    if log_path.exists() {
        ensure_regular_file_no_symlink(&log_path, "membership log")?;
    }

    if snapshot_path.exists() && log_path.exists() {
        let removed_owner_key = maybe_remove_blind_exit_owner_signing_key(
            node_role.as_str(),
            config.host_profile,
            owner_signing_key_path.as_path(),
        )?;
        return Ok(format!(
            "membership files already present: snapshot={} log={} owner_signing_key_removed={removed_owner_key}",
            snapshot_path.display(),
            log_path.display(),
        ));
    }

    ensure_signing_passphrase_material_ops(&config)?;
    let passphrase_tmp =
        create_secure_temp_file(std::env::temp_dir().as_path(), "membership-passphrase.")?;
    if let Err(err) = materialize_signing_passphrase_ops(&config, passphrase_tmp.as_path()) {
        let _ = secure_remove_file(passphrase_tmp.as_path());
        return Err(err);
    }

    let output = Command::new(rustynetd_bin.as_str())
        .arg("membership")
        .arg("init")
        .arg("--snapshot")
        .arg(snapshot_path.as_os_str())
        .arg("--log")
        .arg(log_path.as_os_str())
        .arg("--watermark")
        .arg(watermark_path.as_os_str())
        .arg("--owner-signing-key")
        .arg(owner_signing_key_path.as_os_str())
        .arg("--owner-signing-key-passphrase-file")
        .arg(passphrase_tmp.as_os_str())
        .arg("--node-id")
        .arg(node_id.as_str())
        .arg("--network-id")
        .arg(network_id.as_str())
        .arg("--force")
        .output()
        .map_err(|err| format!("execute rustynetd membership init failed: {err}"))?;

    let cleanup_result = secure_remove_file(passphrase_tmp.as_path());
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let detail = if !stderr.is_empty() { stderr } else { stdout };
        return Err(format!("rustynetd membership init failed: {detail}"));
    }
    cleanup_result?;

    let removed_owner_key = maybe_remove_blind_exit_owner_signing_key(
        node_role.as_str(),
        config.host_profile,
        owner_signing_key_path.as_path(),
    )?;

    Ok(format!(
        "membership initialized: node_id={} snapshot={} log={} owner_signing_key_removed={removed_owner_key}",
        node_id,
        snapshot_path.display(),
        log_path.display()
    ))
}

fn ensure_parent_directory_for_membership_path(
    path: &Path,
    host_profile: SigningPassphraseHostProfile,
) -> Result<(), String> {
    let parent = path.parent().ok_or_else(|| {
        format!(
            "membership path has no parent directory: {}",
            path.display()
        )
    })?;
    match host_profile {
        SigningPassphraseHostProfile::Linux => ensure_directory_with_mode_owner(
            parent,
            0o700,
            Some(Uid::from_raw(0)),
            Some(Gid::from_raw(0)),
        ),
        SigningPassphraseHostProfile::Macos => {
            ensure_directory_with_mode_owner(parent, 0o700, None, None)
        }
    }
}

fn maybe_remove_blind_exit_owner_signing_key(
    node_role: &str,
    host_profile: SigningPassphraseHostProfile,
    owner_signing_key_path: &Path,
) -> Result<bool, String> {
    if node_role != "blind_exit" {
        return Ok(false);
    }
    if !owner_signing_key_path.exists() {
        return Ok(false);
    }
    match host_profile {
        SigningPassphraseHostProfile::Linux => secure_remove_root_owned_file_if_present(
            owner_signing_key_path,
            "membership owner signing key",
        ),
        SigningPassphraseHostProfile::Macos => {
            secure_remove_file(owner_signing_key_path)?;
            Ok(true)
        }
    }
}

fn ensure_parent_directory_for_wireguard_path(
    path: &Path,
    host_profile: SigningPassphraseHostProfile,
) -> Result<(), String> {
    let parent = path.parent().ok_or_else(|| {
        format!(
            "tunnel key path has no parent directory: {}",
            path.display()
        )
    })?;
    match host_profile {
        SigningPassphraseHostProfile::Linux => ensure_directory_with_mode_owner(
            parent,
            0o700,
            Some(Uid::from_raw(0)),
            Some(Gid::from_raw(0)),
        ),
        SigningPassphraseHostProfile::Macos => {
            ensure_directory_with_mode_owner(parent, 0o700, None, None)
        }
    }
}

fn secure_remove_if_present(path: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            secure_remove_file(path)?;
            Ok(true)
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(format!("inspect {} failed: {err}", path.display())),
    }
}

fn validate_root_owned_private_file(path: &Path, label: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|err| format!("inspect {label} failed ({}): {err}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!("{label} must not be a symlink: {}", path.display()));
    }
    if !metadata.file_type().is_file() {
        return Err(format!(
            "{label} must be a regular file: {}",
            path.display()
        ));
    }
    if metadata.uid() != 0 {
        return Err(format!("{label} must be root-owned: {}", path.display()));
    }
    let mode = metadata.mode() & 0o777;
    if (mode & 0o077) != 0 {
        return Err(format!(
            "{label} permissions too broad ({mode:03o}); expected owner-only (0600): {}",
            path.display()
        ));
    }
    Ok(())
}

fn validate_private_key_source_file(
    path: &Path,
    host_profile: SigningPassphraseHostProfile,
    label: &str,
) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|err| format!("inspect {label} failed ({}): {err}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!("{label} must not be a symlink: {}", path.display()));
    }
    if !metadata.file_type().is_file() {
        return Err(format!(
            "{label} must be a regular file: {}",
            path.display()
        ));
    }
    let mode = metadata.mode() & 0o777;
    if (mode & 0o077) != 0 {
        return Err(format!(
            "{label} permissions too broad ({mode:03o}); expected owner-only (0600): {}",
            path.display()
        ));
    }
    match host_profile {
        SigningPassphraseHostProfile::Linux => {
            if metadata.uid() != 0 {
                return Err(format!("{label} must be root-owned: {}", path.display()));
            }
        }
        SigningPassphraseHostProfile::Macos => {
            let expected_uid = Uid::effective().as_raw();
            if metadata.uid() != expected_uid {
                return Err(format!(
                    "{label} owner mismatch: expected uid {expected_uid}, found {} ({})",
                    metadata.uid(),
                    path.display()
                ));
            }
        }
    }
    Ok(())
}

fn required_macos_tunnel_keychain_account(account: &str) -> Result<String, String> {
    let normalized = account.trim();
    if normalized.is_empty() {
        return Err(
            "macOS tunnel keychain account is required (RUSTYNET_WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT)"
                .to_string(),
        );
    }
    if normalized.len() > 128 {
        return Err("macOS tunnel keychain account exceeds max length (128)".to_string());
    }
    if !normalized
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
    {
        return Err(
            "macOS tunnel keychain account contains invalid characters; allowed: [A-Za-z0-9._-]"
                .to_string(),
        );
    }
    Ok(normalized.to_string())
}

fn macos_generic_password_exists(service: &str, account: &str) -> Result<bool, String> {
    let normalized_service = service.trim();
    if normalized_service.is_empty() {
        return Err(
            "macOS tunnel keychain service is required (RUSTYNET_MACOS_WG_PASSPHRASE_KEYCHAIN_SERVICE)"
                .to_string(),
        );
    }
    let status = Command::new("security")
        .arg("find-generic-password")
        .arg("-s")
        .arg(normalized_service)
        .arg("-a")
        .arg(account)
        .status()
        .map_err(|err| format!("invoke security keychain query failed: {err}"))?;
    Ok(status.success())
}

fn provision_linux_tunnel_passphrase_credential_blob(
    passphrase_source_path: &Path,
    credential_blob_path: &Path,
) -> Result<(), String> {
    require_root_execution()?;
    let parent = credential_blob_path.parent().ok_or_else(|| {
        format!(
            "credential blob path has no parent: {}",
            credential_blob_path.display()
        )
    })?;
    ensure_directory_exists(parent, 0o700, Uid::from_raw(0), Gid::from_raw(0))?;
    if credential_blob_path.exists() {
        ensure_regular_file_no_symlink(credential_blob_path, "tunnel passphrase credential blob")?;
    }

    let credential_name = format!("{}{}", "wg", "_key_passphrase");
    let status = Command::new("systemd-creds")
        .arg("encrypt")
        .arg(format!("--name={credential_name}"))
        .arg(passphrase_source_path.as_os_str())
        .arg(credential_blob_path.as_os_str())
        .status()
        .map_err(|err| format!("invoke systemd-creds encrypt failed: {err}"))?;
    if !status.success() {
        return Err(format!("systemd-creds encrypt failed with status {status}"));
    }
    chown(
        credential_blob_path,
        Some(Uid::from_raw(0)),
        Some(Gid::from_raw(0)),
    )
    .map_err(|err| {
        format!(
            "set credential blob owner failed ({}): {err}",
            credential_blob_path.display()
        )
    })?;
    fs::set_permissions(credential_blob_path, fs::Permissions::from_mode(0o600)).map_err(
        |err| {
            format!(
                "set credential blob mode failed ({}): {err}",
                credential_blob_path.display()
            )
        },
    )?;
    Ok(())
}

fn disable_assignment_refresh_timer() -> Result<(), String> {
    let status = Command::new("systemctl")
        .arg("disable")
        .arg("--now")
        .arg("rustynetd-assignment-refresh.timer")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|err| format!("disable assignment-refresh timer invocation failed: {err}"))?;
    if !status.success() {
        return Err(format!(
            "disable assignment-refresh timer returned non-zero status: {status}"
        ));
    }
    Ok(())
}

fn set_assignment_auto_refresh_disabled(systemd_env_path: &Path) -> Result<(), String> {
    let metadata = match fs::symlink_metadata(systemd_env_path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(format!(
                "inspect rustynet systemd env failed ({}): {err}",
                systemd_env_path.display()
            ));
        }
    };
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "rustynet systemd env must not be a symlink: {}",
            systemd_env_path.display()
        ));
    }
    if !metadata.file_type().is_file() {
        return Err(format!(
            "rustynet systemd env must be a regular file: {}",
            systemd_env_path.display()
        ));
    }
    if metadata.uid() != 0 {
        return Err(format!(
            "rustynet systemd env must be root-owned: {}",
            systemd_env_path.display()
        ));
    }

    let body = fs::read_to_string(systemd_env_path)
        .map_err(|err| format!("read rustynet systemd env failed: {err}"))?;
    let rewritten =
        rewrite_env_key_value(body.as_str(), "RUSTYNET_ASSIGNMENT_AUTO_REFRESH", "false");
    if rewritten == body {
        return Ok(());
    }

    let owner = Uid::from_raw(metadata.uid());
    let group = Gid::from_raw(metadata.gid());
    let mode = metadata.mode() & 0o777;
    write_atomic_text_file_with_owner_mode(systemd_env_path, rewritten.as_str(), owner, group, mode)
}

fn write_atomic_text_file_with_owner_mode(
    target_path: &Path,
    body: &str,
    owner: Uid,
    group: Gid,
    mode: u32,
) -> Result<(), String> {
    let parent = target_path.parent().ok_or_else(|| {
        format!(
            "target file has no parent directory: {}",
            target_path.display()
        )
    })?;
    if let Ok(parent_metadata) = fs::symlink_metadata(parent)
        && parent_metadata.file_type().is_symlink()
    {
        return Err(format!(
            "target parent must not be a symlink: {}",
            parent.display()
        ));
    }
    let tmp = create_secure_temp_file(parent, "rustynet.ops.tmp.")?;
    if let Err(err) = write_private_bytes_to_file(tmp.as_path(), body.as_bytes()) {
        let _ = remove_file_if_present(&tmp);
        return Err(err);
    }
    if let Err(err) =
        publish_file_with_owner_mode(&tmp, target_path, owner, group, mode, "systemd env file")
    {
        let _ = remove_file_if_present(&tmp);
        return Err(err);
    }
    Ok(())
}

fn secure_remove_root_owned_file_if_present(path: &Path, label: &str) -> Result<bool, String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(err) => {
            return Err(format!(
                "inspect {label} failed ({}): {err}",
                path.display()
            ));
        }
    };
    if metadata.file_type().is_symlink() {
        return Err(format!("{label} must not be a symlink: {}", path.display()));
    }
    if !metadata.file_type().is_file() {
        return Err(format!(
            "{label} must be a regular file: {}",
            path.display()
        ));
    }
    if metadata.uid() != 0 {
        return Err(format!("{label} must be root-owned: {}", path.display()));
    }
    secure_remove_file(path)?;
    Ok(true)
}

fn rewrite_env_key_value(body: &str, key: &str, value: &str) -> String {
    let assignment = format_env_assignment(key, value)
        .unwrap_or_else(|err| panic!("invalid env assignment for {key}: {err}"));
    let mut rewritten_lines = Vec::new();
    let mut inserted = false;
    let prefix = format!("{key}=");
    for line in body.lines() {
        if line.starts_with(prefix.as_str()) {
            if !inserted {
                rewritten_lines.push(assignment.clone());
                inserted = true;
            }
            continue;
        }
        rewritten_lines.push(line.to_string());
    }
    if !inserted {
        rewritten_lines.push(assignment);
    }
    if rewritten_lines.is_empty() {
        return String::new();
    }
    format!("{}\n", rewritten_lines.join("\n"))
}

fn insert_absolute_directory_from_env(
    env_key: &str,
    out: &mut HashSet<PathBuf>,
    label: &str,
) -> Result<(), String> {
    if let Some(raw) = env_optional_string(env_key)? {
        let directory = PathBuf::from(raw);
        if !directory.is_absolute() {
            return Err(format!(
                "{label} from {env_key} must be an absolute path: {}",
                directory.display()
            ));
        }
        out.insert(directory);
    }
    Ok(())
}

fn insert_parent_dir_from_env_path(
    env_key: &str,
    out: &mut HashSet<PathBuf>,
) -> Result<(), String> {
    if let Some(raw) = env_optional_string(env_key)? {
        let path = PathBuf::from(raw);
        if !path.is_absolute() {
            return Err(format!(
                "{env_key} must be an absolute path: {}",
                path.display()
            ));
        }
        let parent = path
            .parent()
            .ok_or_else(|| format!("{env_key} has no parent directory: {}", path.display()))?;
        out.insert(parent.to_path_buf());
    }
    Ok(())
}

fn ensure_directory_with_mode_owner(
    path: &Path,
    mode: u32,
    owner: Option<Uid>,
    group: Option<Gid>,
) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(format!(
                    "directory path must not be a symlink: {}",
                    path.display()
                ));
            }
            if !metadata.file_type().is_dir() {
                return Err(format!(
                    "directory path must be a directory: {}",
                    path.display()
                ));
            }
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(path).map_err(|create_err| {
                format!("create directory {} failed: {create_err}", path.display())
            })?;
        }
        Err(err) => {
            return Err(format!(
                "inspect directory {} failed: {err}",
                path.display()
            ));
        }
    }
    if let Some(owner_uid) = owner {
        chown(path, Some(owner_uid), group).map_err(|err| {
            format!(
                "set directory owner/group failed ({}): {err}",
                path.display()
            )
        })?;
    }
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|err| format!("set directory mode failed ({}): {err}", path.display()))?;
    Ok(())
}

fn assignment_refresh_available_ops(env_path: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(env_path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(format!(
                    "assignment refresh env file must not be a symlink: {}",
                    env_path.display()
                ));
            }
            if !metadata.file_type().is_file() {
                return Err(format!(
                    "assignment refresh env path must be a regular file: {}",
                    env_path.display()
                ));
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => {
            return Err(format!(
                "inspect assignment refresh env failed ({}): {err}",
                env_path.display()
            ));
        }
    }

    let status = Command::new("systemctl")
        .arg("cat")
        .arg("rustynetd-assignment-refresh.service")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|err| format!("invoke systemctl cat failed: {err}"))?;
    Ok(status.success())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LocalTraversalRefreshConfig {
    local_node_id: String,
    nodes_spec: String,
    allow_spec: String,
}

fn ensure_safe_signed_state_spec(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    let allowed = |ch: char| {
        ch.is_ascii_alphanumeric()
            || matches!(
                ch,
                '.' | '_' | ':' | '/' | ',' | '@' | '+' | '=' | '-' | '|' | ';'
            )
    };
    if !value.chars().all(allowed) {
        return Err(format!("{label} contains unsupported characters: {value}"));
    }
    Ok(())
}

fn local_traversal_refresh_env_body(
    local_node_id: &str,
    nodes_spec: &str,
    allow_spec: &str,
) -> Result<String, String> {
    if !is_valid_assignment_refresh_exit_node_id(local_node_id) {
        return Err(format!(
            "assignment refresh target node id contains unsupported characters: {local_node_id}"
        ));
    }
    ensure_safe_signed_state_spec("assignment refresh nodes spec", nodes_spec)?;
    ensure_safe_signed_state_spec("assignment refresh allow spec", allow_spec)?;
    let local_allow_prefix = format!("{local_node_id}|");
    if !allow_spec
        .split(';')
        .map(str::trim)
        .any(|entry| entry.starts_with(local_allow_prefix.as_str()))
    {
        return Err(format!(
            "assignment refresh allow spec does not authorize traversal sources for local node {local_node_id}"
        ));
    }

    let ttl_text = LOCAL_TRAVERSAL_REFRESH_TTL_SECS.to_string();
    let env_body = format!(
        "{}\n{}\n{}\n",
        format_env_assignment("NODES_SPEC", nodes_spec)
            .map_err(|err| format!("encode traversal refresh NODES_SPEC failed: {err}"))?,
        format_env_assignment("ALLOW_SPEC", allow_spec)
            .map_err(|err| format!("encode traversal refresh ALLOW_SPEC failed: {err}"))?,
        format_env_assignment("TRAVERSAL_TTL_SECS", ttl_text.as_str())
            .map_err(|err| format!("encode traversal refresh TRAVERSAL_TTL_SECS failed: {err}"))?,
    );
    Ok(env_body)
}

fn local_traversal_refresh_config_from_assignment_env(
    body: &str,
) -> Result<LocalTraversalRefreshConfig, String> {
    let local_node_id = assignment_refresh_env_value(body, "RUSTYNET_ASSIGNMENT_TARGET_NODE_ID")?
        .ok_or_else(|| {
        "assignment refresh env is missing RUSTYNET_ASSIGNMENT_TARGET_NODE_ID".to_string()
    })?;
    let nodes_spec = assignment_refresh_env_value(body, "RUSTYNET_ASSIGNMENT_NODES")?
        .ok_or_else(|| "assignment refresh env is missing RUSTYNET_ASSIGNMENT_NODES".to_string())?;
    let allow_spec = assignment_refresh_env_value(body, "RUSTYNET_ASSIGNMENT_ALLOW")?
        .ok_or_else(|| "assignment refresh env is missing RUSTYNET_ASSIGNMENT_ALLOW".to_string())?;
    local_traversal_refresh_env_body(
        local_node_id.as_str(),
        nodes_spec.as_str(),
        allow_spec.as_str(),
    )?;

    Ok(LocalTraversalRefreshConfig {
        local_node_id,
        nodes_spec,
        allow_spec,
    })
}

fn refresh_local_traversal_bundle_from_specs(
    local_node_id: &str,
    nodes_spec: &str,
    allow_spec: &str,
    daemon_group: &str,
) -> Result<(), String> {
    let temp_root = std::env::temp_dir();
    let issue_dir =
        create_secure_temp_directory(temp_root.as_path(), "rustynet.traversal-refresh.issue.")?;
    let env_file = issue_dir.join("traversal-refresh.env");
    let result = (|| -> Result<(), String> {
        let env_body = local_traversal_refresh_env_body(local_node_id, nodes_spec, allow_spec)?;
        write_private_bytes_to_file(&env_file, env_body.as_bytes())?;
        ops_e2e::execute_ops_e2e_issue_traversal_bundles_from_env(
            ops_e2e::E2eIssueTraversalBundlesFromEnvConfig {
                env_file: env_file.clone(),
                issue_dir: issue_dir.clone(),
            },
        )?;

        let verifier_source = issue_dir.join("rn-traversal.pub");
        let bundle_source = issue_dir.join(format!("rn-traversal-{local_node_id}.traversal"));
        let verifier_dest = env_path_or_default(
            "RUSTYNET_TRAVERSAL_VERIFIER_KEY",
            DEFAULT_TRAVERSAL_VERIFIER_KEY_PATH,
        )?;
        let bundle_dest =
            env_path_or_default("RUSTYNET_TRAVERSAL_BUNDLE", DEFAULT_TRAVERSAL_BUNDLE_PATH)?;
        let watermark_dest = env_path_or_default(
            "RUSTYNET_TRAVERSAL_WATERMARK",
            DEFAULT_TRAVERSAL_WATERMARK_PATH,
        )?;
        let daemon_gid = Group::from_name(daemon_group)
            .map_err(|err| format!("resolve daemon group {daemon_group} failed: {err}"))?
            .ok_or_else(|| format!("daemon group not found: {daemon_group}"))?
            .gid;

        install_trust_material_file(
            verifier_source.as_path(),
            verifier_dest.as_path(),
            Uid::from_raw(0),
            Gid::from_raw(0),
            0o644,
            "traversal verifier key",
        )?;
        install_trust_material_file(
            bundle_source.as_path(),
            bundle_dest.as_path(),
            Uid::from_raw(0),
            daemon_gid,
            0o640,
            "traversal bundle",
        )?;
        remove_file_if_present(watermark_dest.as_path())?;
        Ok(())
    })();

    let _ = fs::remove_file(&env_file);
    let _ = fs::remove_dir_all(&issue_dir);
    result
}

fn refresh_local_traversal_bundle_from_assignment_env(
    assignment_refresh_env_path: &Path,
) -> Result<(), String> {
    ensure_regular_file_no_symlink(assignment_refresh_env_path, "assignment refresh env file")?;
    let assignment_env = fs::read_to_string(assignment_refresh_env_path).map_err(|err| {
        format!(
            "read assignment refresh env failed ({}): {err}",
            assignment_refresh_env_path.display()
        )
    })?;
    let refresh_config =
        local_traversal_refresh_config_from_assignment_env(assignment_env.as_str())?;
    let daemon_group = env_string_or_default("RUSTYNET_DAEMON_GROUP", "rustynetd")?;
    refresh_local_traversal_bundle_from_specs(
        refresh_config.local_node_id.as_str(),
        refresh_config.nodes_spec.as_str(),
        refresh_config.allow_spec.as_str(),
        daemon_group.as_str(),
    )
}

fn force_local_assignment_refresh_now_ops() -> Result<(), String> {
    let assignment_refresh_env_path = env_path_or_default(
        "RUSTYNET_ASSIGNMENT_REFRESH_ENV_PATH",
        DEFAULT_ASSIGNMENT_REFRESH_ENV_PATH,
    )?;
    let bundle_path = env_path_or_default(
        "RUSTYNET_AUTO_TUNNEL_BUNDLE",
        DEFAULT_AUTO_TUNNEL_BUNDLE_PATH,
    )?;
    let watermark_path = env_path_or_default(
        "RUSTYNET_AUTO_TUNNEL_WATERMARK",
        DEFAULT_AUTO_TUNNEL_WATERMARK_PATH,
    )?;
    let socket_path = env_path_or_default("RUSTYNET_SOCKET", DEFAULT_DAEMON_SOCKET_PATH)?;

    refresh_local_traversal_bundle_from_assignment_env(assignment_refresh_env_path.as_path())?;
    remove_file_if_present(bundle_path.as_path())?;
    remove_file_if_present(watermark_path.as_path())?;
    let _ = run_systemctl_action("reset-failed", "rustynetd-privileged-helper.service");
    let _ = run_systemctl_action("reset-failed", "rustynetd.service");
    run_systemctl_action("start", "rustynetd-assignment-refresh.service")?;
    run_systemctl_action("restart", "rustynetd.service")?;
    wait_for_socket_path(socket_path.as_path(), Duration::from_secs(20))?;
    wait_for_runtime_ready_after_restart(socket_path.as_path(), Duration::from_secs(30))?;
    Ok(())
}

fn wait_for_runtime_ready_after_restart(
    socket_path: &Path,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    let mut last_observation: String;
    loop {
        let status_output = Command::new(PINNED_RUNTIME_RUSTYNET_BIN)
            .env("RUSTYNET_DAEMON_SOCKET", socket_path)
            .arg("status")
            .output()
            .map_err(|err| format!("invoke rustynet status failed: {err}"))?;
        let stdout = String::from_utf8_lossy(&status_output.stdout)
            .trim()
            .to_string();
        if status_output.status.success() && daemon_runtime_ready_from_status_text(&stdout) {
            return Ok(());
        }
        last_observation = if !stdout.is_empty() {
            stdout
        } else {
            command_failure_detail(&status_output)
        };
        if Instant::now() >= deadline {
            return Err(format!(
                "daemon did not become runtime-ready after restart: {last_observation}"
            ));
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn daemon_runtime_ready_from_status_text(status_text: &str) -> bool {
    fn field_value<'a>(status_text: &'a str, key: &str) -> Option<&'a str> {
        status_text.split_whitespace().find_map(|field| {
            field
                .strip_prefix(key)
                .and_then(|value| value.strip_prefix('='))
        })
    }

    matches!(
        field_value(status_text, "restricted_safe_mode"),
        Some("false")
    ) && !matches!(field_value(status_text, "state"), Some("FailClosed"))
        && matches!(field_value(status_text, "bootstrap_error"), Some("none"))
        && matches!(
            field_value(status_text, "last_reconcile_error"),
            Some("none")
        )
}

fn run_systemctl_action(action: &str, unit: &str) -> Result<(), String> {
    let status = Command::new("systemctl")
        .arg(action)
        .arg(unit)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|err| format!("invoke systemctl {action} {unit} failed: {err}"))?;
    if !status.success() {
        return Err(format!(
            "systemctl {action} {unit} failed with status {status}"
        ));
    }
    Ok(())
}

fn wait_for_socket_path(path: &Path, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                if metadata.file_type().is_socket() {
                    return Ok(());
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(format!(
                    "inspect socket path {} failed: {err}",
                    path.display()
                ));
            }
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "daemon socket did not become ready: {}",
                path.display()
            ));
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn send_role_coupling_ipc(command: IpcCommand) -> Result<(), String> {
    let response = send_command(command)?;
    if response.ok {
        Ok(())
    } else {
        Err(response.message)
    }
}

fn signing_passphrase_ops_config_from_env() -> Result<SigningPassphraseOpsConfig, String> {
    let host_profile = match env_string_or_default("RUSTYNET_HOST_PROFILE", detect_host_profile())?
        .to_ascii_lowercase()
        .as_str()
    {
        "linux" => SigningPassphraseHostProfile::Linux,
        "macos" | "darwin" => SigningPassphraseHostProfile::Macos,
        other => {
            return Err(format!(
                "unsupported host profile for signing passphrase ops: {other}"
            ));
        }
    };

    Ok(SigningPassphraseOpsConfig {
        host_profile,
        signing_credential_blob_path: env_path_or_default(
            "RUSTYNET_SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB",
            DEFAULT_SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH,
        )?,
        membership_owner_signing_key_path: env_path_or_default(
            "RUSTYNET_MEMBERSHIP_OWNER_SIGNING_KEY",
            DEFAULT_MEMBERSHIP_OWNER_SIGNING_KEY_PATH,
        )?,
        trust_signer_key_path: env_path_or_default(
            "RUSTYNET_TRUST_SIGNER_KEY",
            DEFAULT_TRUST_SIGNER_KEY_PATH,
        )?,
        assignment_signing_secret_path: env_path_or_default(
            "RUSTYNET_ASSIGNMENT_SIGNING_SECRET",
            DEFAULT_ASSIGNMENT_SIGNING_SECRET_PATH,
        )?,
        macos_keychain_service: env_string_or_default(
            "RUSTYNET_MACOS_PASSPHRASE_KEYCHAIN_SERVICE",
            DEFAULT_MACOS_PASSPHRASE_KEYCHAIN_SERVICE,
        )?,
        macos_keychain_account: env_string_or_default(
            "RUSTYNET_SIGNING_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT",
            "",
        )?,
    })
}

fn wireguard_custody_ops_config_from_env() -> Result<TunnelCustodyOpsConfig, String> {
    let host_profile = match env_string_or_default("RUSTYNET_HOST_PROFILE", detect_host_profile())?
        .to_ascii_lowercase()
        .as_str()
    {
        "linux" => SigningPassphraseHostProfile::Linux,
        "macos" | "darwin" => SigningPassphraseHostProfile::Macos,
        other => {
            return Err(format!(
                "unsupported host profile for tunnel custody ops: {other}"
            ));
        }
    };

    Ok(TunnelCustodyOpsConfig {
        host_profile,
        runtime_private_key_path: env_path_or_default(
            "RUSTYNET_WG_PRIVATE_KEY",
            DEFAULT_WG_RUNTIME_PRIVATE_KEY_PATH,
        )?,
        encrypted_private_key_path: env_path_or_default(
            "RUSTYNET_WG_ENCRYPTED_PRIVATE_KEY",
            DEFAULT_WG_ENCRYPTED_PRIVATE_KEY_PATH,
        )?,
        public_key_path: env_path_or_default("RUSTYNET_WG_PUBLIC_KEY", DEFAULT_WG_PUBLIC_KEY_PATH)?,
        passphrase_path: env_path_or_default(
            "RUSTYNET_WG_KEY_PASSPHRASE",
            DEFAULT_WG_KEY_PASSPHRASE_PATH,
        )?,
        passphrase_credential_blob_path: env_path_or_default(
            "RUSTYNET_WG_KEY_PASSPHRASE_CREDENTIAL_BLOB",
            DEFAULT_WG_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH,
        )?,
        macos_keychain_service: env_string_or_default(
            "RUSTYNET_MACOS_WG_PASSPHRASE_KEYCHAIN_SERVICE",
            DEFAULT_MACOS_WG_PASSPHRASE_KEYCHAIN_SERVICE,
        )?,
        macos_keychain_account: env_string_or_default(
            "RUSTYNET_WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT",
            "",
        )?,
        allow_init: parse_env_bool_with_default("RUSTYNET_WG_CUSTODY_ALLOW_INIT", "false")?,
    })
}

fn detect_host_profile() -> &'static str {
    if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "unsupported"
    }
}

fn ensure_signing_passphrase_material_ops(
    config: &SigningPassphraseOpsConfig,
) -> Result<(), String> {
    match config.host_profile {
        SigningPassphraseHostProfile::Linux => ensure_signing_passphrase_material_linux(config),
        SigningPassphraseHostProfile::Macos => ensure_signing_passphrase_material_macos(config),
    }
}

fn ensure_signing_passphrase_material_linux(
    config: &SigningPassphraseOpsConfig,
) -> Result<(), String> {
    require_root_execution()?;
    if config.signing_credential_blob_path.exists() {
        ensure_regular_file_no_symlink(
            &config.signing_credential_blob_path,
            "signing passphrase credential blob",
        )?;
        return Ok(());
    }

    let mut existing_signing_material = false;
    for path in [
        &config.membership_owner_signing_key_path,
        &config.trust_signer_key_path,
        &config.assignment_signing_secret_path,
    ] {
        if fs::symlink_metadata(path).is_ok() {
            existing_signing_material = true;
            break;
        }
    }
    if existing_signing_material {
        return Err(format!(
            "signing credential blob is missing ({}) while encrypted signing material exists",
            config.signing_credential_blob_path.display()
        ));
    }

    let parent = config
        .signing_credential_blob_path
        .parent()
        .ok_or_else(|| {
            format!(
                "signing credential blob path has no parent: {}",
                config.signing_credential_blob_path.display()
            )
        })?;
    ensure_directory_exists(parent, 0o700, Uid::from_raw(0), Gid::from_raw(0))?;

    let tmp_passphrase =
        create_secure_temp_file(std::env::temp_dir().as_path(), "signing-passphrase.")?;
    let mut random_bytes = [0u8; 48];
    fill_os_random_bytes(&mut random_bytes, "signing credential passphrase")?;
    let mut passphrase_hex = Zeroizing::new(hex_bytes(&random_bytes));
    random_bytes.zeroize();
    passphrase_hex.push('\n');
    if let Err(err) =
        write_private_bytes_to_file(tmp_passphrase.as_path(), passphrase_hex.as_bytes())
    {
        let _ = secure_remove_file(tmp_passphrase.as_path());
        return Err(err);
    }

    let encrypt_status = Command::new("systemd-creds")
        .arg("encrypt")
        .arg("--name=signing_key_passphrase")
        .arg(tmp_passphrase.as_os_str())
        .arg(config.signing_credential_blob_path.as_os_str())
        .status()
        .map_err(|err| format!("invoke systemd-creds encrypt failed: {err}"))?;
    let cleanup_result = secure_remove_file(tmp_passphrase.as_path());
    if !encrypt_status.success() {
        return Err(format!(
            "systemd-creds encrypt failed with status {encrypt_status}"
        ));
    }
    cleanup_result?;

    chown(
        config.signing_credential_blob_path.as_path(),
        Some(Uid::from_raw(0)),
        Some(Gid::from_raw(0)),
    )
    .map_err(|err| {
        format!(
            "set credential blob owner failed ({}): {err}",
            config.signing_credential_blob_path.display()
        )
    })?;
    fs::set_permissions(
        config.signing_credential_blob_path.as_path(),
        fs::Permissions::from_mode(0o600),
    )
    .map_err(|err| {
        format!(
            "set credential blob mode failed ({}): {err}",
            config.signing_credential_blob_path.display()
        )
    })?;
    Ok(())
}

fn ensure_signing_passphrase_material_macos(
    config: &SigningPassphraseOpsConfig,
) -> Result<(), String> {
    if config.macos_keychain_account.trim().is_empty() {
        return Err(
            "macOS keychain account is required (RUSTYNET_SIGNING_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT)"
                .to_string(),
        );
    }
    let status = Command::new("security")
        .arg("find-generic-password")
        .arg("-s")
        .arg(config.macos_keychain_service.as_str())
        .arg("-a")
        .arg(config.macos_keychain_account.as_str())
        .status()
        .map_err(|err| format!("invoke security keychain query failed: {err}"))?;
    if !status.success() {
        return Err(format!(
            "macOS keychain passphrase item missing (service={}, account={})",
            config.macos_keychain_service, config.macos_keychain_account
        ));
    }
    Ok(())
}

fn materialize_signing_passphrase_ops(
    config: &SigningPassphraseOpsConfig,
    output_path: &Path,
) -> Result<(), String> {
    match config.host_profile {
        SigningPassphraseHostProfile::Linux => {
            materialize_signing_passphrase_linux(config, output_path)
        }
        SigningPassphraseHostProfile::Macos => {
            materialize_signing_passphrase_macos(config, output_path)
        }
    }
}

fn materialize_signing_passphrase_linux(
    config: &SigningPassphraseOpsConfig,
    output_path: &Path,
) -> Result<(), String> {
    require_root_execution()?;
    let parent = output_path.parent().ok_or_else(|| {
        format!(
            "signing passphrase output path has no parent: {}",
            output_path.display()
        )
    })?;
    let temp_dir = create_secure_temp_directory(parent, "signing-passphrase.decrypt.")?;
    let temp_output = temp_dir.join("passphrase");
    let decrypt_status = Command::new("systemd-creds")
        .arg("decrypt")
        .arg("--name=signing_key_passphrase")
        .arg(config.signing_credential_blob_path.as_os_str())
        .arg(temp_output.as_os_str())
        .status()
        .map_err(|err| format!("invoke systemd-creds decrypt failed: {err}"))?;
    if !decrypt_status.success() {
        let _ = secure_remove_file(temp_output.as_path());
        let _ = fs::remove_dir(temp_dir.as_path());
        return Err(format!(
            "systemd-creds decrypt failed with status {decrypt_status}"
        ));
    }
    match fs::symlink_metadata(output_path) {
        Ok(metadata) => {
            if metadata.file_type().is_dir() {
                let _ = secure_remove_file(temp_output.as_path());
                let _ = fs::remove_dir(temp_dir.as_path());
                return Err(format!(
                    "signing passphrase output must not be a directory: {}",
                    output_path.display()
                ));
            }
            secure_remove_file(output_path)?;
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            let _ = secure_remove_file(temp_output.as_path());
            let _ = fs::remove_dir(temp_dir.as_path());
            return Err(format!(
                "inspect signing passphrase output failed ({}): {err}",
                output_path.display()
            ));
        }
    }
    if let Err(err) = publish_file_with_owner_mode(
        temp_output.as_path(),
        output_path,
        Uid::from_raw(0),
        Gid::from_raw(0),
        0o600,
        "signing passphrase output",
    ) {
        let _ = secure_remove_file(temp_output.as_path());
        let _ = fs::remove_dir(temp_dir.as_path());
        return Err(err);
    }
    fs::remove_dir(temp_dir.as_path()).map_err(|err| {
        format!(
            "remove temporary signing passphrase directory {} failed: {err}",
            temp_dir.display()
        )
    })?;
    Ok(())
}

fn materialize_signing_passphrase_macos(
    config: &SigningPassphraseOpsConfig,
    output_path: &Path,
) -> Result<(), String> {
    let output = Command::new("security")
        .arg("find-generic-password")
        .arg("-s")
        .arg(config.macos_keychain_service.as_str())
        .arg("-a")
        .arg(config.macos_keychain_account.as_str())
        .arg("-w")
        .output()
        .map_err(|err| format!("invoke security keychain read failed: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "failed to materialize passphrase from keychain (service={}, account={})",
            config.macos_keychain_service, config.macos_keychain_account
        ));
    }
    let passphrase = Zeroizing::new(output.stdout);
    write_private_bytes_to_file(output_path, passphrase.as_slice())?;
    Ok(())
}

fn write_private_bytes_to_file(path: &Path, body: &[u8]) -> Result<(), String> {
    if !path.is_absolute() {
        return Err(format!("path must be absolute: {}", path.display()));
    }
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            return Err(format!("path must not be a symlink: {}", path.display()));
        }
        if !metadata.file_type().is_file() {
            return Err(format!("path must be a regular file: {}", path.display()));
        }
    }
    let mut options = OpenOptions::new();
    options.write(true).truncate(true).create(true).mode(0o600);
    let mut file = options
        .open(path)
        .map_err(|err| format!("open {} failed: {err}", path.display()))?;
    file.write_all(body)
        .map_err(|err| format!("write {} failed: {err}", path.display()))?;
    file.sync_all()
        .map_err(|err| format!("sync {} failed: {err}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|err| format!("set mode {} failed: {err}", path.display()))?;
    Ok(())
}

fn secure_remove_file(path: &Path) -> Result<(), String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(format!("inspect {} failed: {err}", path.display())),
    };

    if metadata.file_type().is_symlink() {
        return fs::remove_file(path)
            .map_err(|err| format!("remove symlink {} failed: {err}", path.display()));
    }
    if !metadata.file_type().is_file() {
        return Err(format!(
            "secure remove requires a regular file: {}",
            path.display()
        ));
    }

    scrub_file_contents(path)?;
    fs::remove_file(path).map_err(|err| format!("remove {} failed: {err}", path.display()))
}

fn scrub_file_contents(path: &Path) -> Result<(), String> {
    let metadata = fs::metadata(path)
        .map_err(|err| format!("inspect file {} failed: {err}", path.display()))?;
    let mut file = OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|err| format!("open {} failed: {err}", path.display()))?;
    let mut remaining = metadata.len();
    let zero_chunk = [0u8; 8192];
    while remaining > 0 {
        let write_len = usize::try_from(std::cmp::min(remaining, zero_chunk.len() as u64))
            .map_err(|_| "internal length conversion failed".to_string())?;
        file.write_all(&zero_chunk[..write_len])
            .map_err(|err| format!("scrub write {} failed: {err}", path.display()))?;
        remaining = remaining.saturating_sub(write_len as u64);
    }
    file.sync_all()
        .map_err(|err| format!("sync {} failed: {err}", path.display()))?;
    file.set_len(0)
        .map_err(|err| format!("truncate {} failed: {err}", path.display()))?;
    file.sync_all()
        .map_err(|err| format!("sync {} after truncate failed: {err}", path.display()))?;
    Ok(())
}

fn ensure_regular_file_no_symlink(path: &Path, label: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|err| format!("inspect {label} failed ({}): {err}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!("{label} must not be a symlink: {}", path.display()));
    }
    if !metadata.file_type().is_file() {
        return Err(format!(
            "{label} must be a regular file: {}",
            path.display()
        ));
    }
    Ok(())
}

fn is_valid_assignment_refresh_exit_node_id(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
}

fn rewrite_assignment_refresh_exit_node(body: &str, exit_node_id: Option<&str>) -> String {
    let mut rewritten_lines = Vec::new();
    let mut inserted = false;
    for line in body.lines() {
        if line.starts_with("RUSTYNET_ASSIGNMENT_EXIT_NODE_ID=") {
            if !inserted {
                if let Some(exit_node_id_value) = exit_node_id {
                    rewritten_lines.push(
                        format_env_assignment(
                            "RUSTYNET_ASSIGNMENT_EXIT_NODE_ID",
                            exit_node_id_value,
                        )
                        .unwrap_or_else(|err| {
                            panic!(
                                "invalid assignment refresh exit node value {exit_node_id_value}: {err}"
                            )
                        }),
                    );
                }
                inserted = true;
            }
            continue;
        }
        rewritten_lines.push(line.to_string());
    }
    if !inserted && let Some(exit_node_id_value) = exit_node_id {
        rewritten_lines.push(
            format_env_assignment("RUSTYNET_ASSIGNMENT_EXIT_NODE_ID", exit_node_id_value)
                .unwrap_or_else(|err| {
                    panic!("invalid assignment refresh exit node value {exit_node_id_value}: {err}")
                }),
        );
    }
    if rewritten_lines.is_empty() {
        return String::new();
    }
    format!("{}\n", rewritten_lines.join("\n"))
}

fn assignment_refresh_env_value(body: &str, key: &str) -> Result<Option<String>, String> {
    let prefix = format!("{key}=");
    for line in body.lines() {
        let trimmed = line.trim();
        if let Some(raw_value) = trimmed.strip_prefix(prefix.as_str()) {
            return parse_env_value(raw_value).map(Some);
        }
    }
    Ok(None)
}

fn rewrite_assignment_refresh_lan_routes(body: &str, lan_routes: &[String]) -> String {
    let mut rewritten_lines = Vec::new();
    let mut inserted = false;
    for line in body.lines() {
        if line.starts_with("RUSTYNET_ASSIGNMENT_LAN_ROUTES=") {
            if !inserted && !lan_routes.is_empty() {
                rewritten_lines.push(
                    format_env_assignment(
                        "RUSTYNET_ASSIGNMENT_LAN_ROUTES",
                        lan_routes.join(",").as_str(),
                    )
                    .unwrap_or_else(|err| panic!("invalid assignment refresh LAN routes: {err}")),
                );
            }
            inserted = true;
            continue;
        }
        rewritten_lines.push(line.to_string());
    }
    if !inserted && !lan_routes.is_empty() {
        rewritten_lines.push(
            format_env_assignment(
                "RUSTYNET_ASSIGNMENT_LAN_ROUTES",
                lan_routes.join(",").as_str(),
            )
            .unwrap_or_else(|err| panic!("invalid assignment refresh LAN routes: {err}")),
        );
    }
    if rewritten_lines.is_empty() {
        return String::new();
    }
    format!("{}\n", rewritten_lines.join("\n"))
}

fn rewrite_assignment_refresh_lan_block_routes(body: &str, lan_routes: &[String]) -> String {
    let mut rewritten_lines = Vec::new();
    let mut inserted = false;
    for line in body.lines() {
        if line.starts_with("RUSTYNET_ASSIGNMENT_LAN_BLOCK_ROUTES=") {
            if !inserted && !lan_routes.is_empty() {
                rewritten_lines.push(
                    format_env_assignment(
                        "RUSTYNET_ASSIGNMENT_LAN_BLOCK_ROUTES",
                        lan_routes.join(",").as_str(),
                    )
                    .unwrap_or_else(|err| {
                        panic!("invalid assignment refresh LAN block routes: {err}")
                    }),
                );
            }
            inserted = true;
            continue;
        }
        rewritten_lines.push(line.to_string());
    }
    if !inserted && !lan_routes.is_empty() {
        rewritten_lines.push(
            format_env_assignment(
                "RUSTYNET_ASSIGNMENT_LAN_BLOCK_ROUTES",
                lan_routes.join(",").as_str(),
            )
            .unwrap_or_else(|err| panic!("invalid assignment refresh LAN block routes: {err}")),
        );
    }
    if rewritten_lines.is_empty() {
        return String::new();
    }
    format!("{}\n", rewritten_lines.join("\n"))
}

fn require_root_execution() -> Result<(), String> {
    if Uid::effective().is_root() {
        return Ok(());
    }
    Err("run as root".to_string())
}

fn parse_env_bool_with_default(key: &str, default: &str) -> Result<bool, String> {
    let value = env_string_or_default(key, default)?;
    parse_bool_value(key, value.as_str())
}

fn parse_bool_value(key: &str, value: &str) -> Result<bool, String> {
    match value {
        "true" | "TRUE" | "yes" | "YES" | "1" | "on" | "ON" => Ok(true),
        "false" | "FALSE" | "no" | "NO" | "0" | "off" | "OFF" | "" => Ok(false),
        _ => Err(format!("invalid boolean value for {key}: {value}")),
    }
}

fn validate_assignment_refresh_lan_routes(lan_routes: &[String]) -> Result<(), String> {
    if lan_routes.is_empty() {
        return Err("at least one LAN route CIDR is required".to_string());
    }
    let mut seen = HashSet::new();
    for cidr in lan_routes {
        if cidr.trim() != cidr || cidr.is_empty() {
            return Err(format!("LAN route cidr must not be empty: {cidr:?}"));
        }
        if !validate_cidr(cidr.as_str()) {
            return Err(format!("invalid LAN route cidr: {cidr}"));
        }
        if !seen.insert(cidr.as_str()) {
            return Err(format!("duplicate LAN route cidr: {cidr}"));
        }
    }
    Ok(())
}

fn status_field(status_line: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    status_line
        .split_whitespace()
        .find_map(|field| field.strip_prefix(prefix.as_str()).map(ToString::to_string))
}

fn wait_for_daemon_status_field(
    socket_path: &Path,
    key: &str,
    expected_value: &str,
    timeout: Duration,
) -> Result<(), String> {
    let start = Instant::now();
    while start.elapsed() <= timeout {
        let status = send_command_with_socket(IpcCommand::Status, socket_path.to_path_buf())?;
        if status.ok
            && status_field(status.message.as_str(), key).as_deref() == Some(expected_value)
        {
            return Ok(());
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    Err(format!(
        "timed out waiting for daemon status field {key}={expected_value}"
    ))
}

fn route_uses_rustynet0(route_line: &str) -> bool {
    route_line.contains("dev rustynet0")
}

fn wait_for_client_exit_route_convergence(
    socket_path: &Path,
    assignment_refresh_env_path: &Path,
    expected_exit_node: &str,
    timeout: Duration,
) -> Result<(), String> {
    let start = Instant::now();
    let mut next_refresh_at =
        Instant::now() + Duration::from_secs(LOCAL_TRAVERSAL_CONVERGENCE_REFRESH_INTERVAL_SECS);
    let mut last_status = String::new();
    let mut last_route = String::new();
    while start.elapsed() <= timeout {
        if Instant::now() >= next_refresh_at {
            refresh_local_traversal_bundle_from_assignment_env(assignment_refresh_env_path)?;
            if socket_exists_and_is_socket(socket_path, "daemon socket")? {
                let _ =
                    send_command_with_socket(IpcCommand::StateRefresh, socket_path.to_path_buf());
            }
            next_refresh_at = Instant::now()
                + Duration::from_secs(LOCAL_TRAVERSAL_CONVERGENCE_REFRESH_INTERVAL_SECS);
        }
        let status = send_command_with_socket(IpcCommand::Status, socket_path.to_path_buf())?;
        if status.ok {
            last_status = status.message.clone();
            let route_output = run_command_capture("ip", &["-4", "route", "get", "1.1.1.1"])?;
            last_route = String::from_utf8_lossy(&route_output.stdout)
                .trim()
                .to_string();
            if status_field(status.message.as_str(), "exit_node")
                == Some(expected_exit_node.to_string())
                && daemon_runtime_ready_from_status_text(status.message.as_str())
                && route_output.status.success()
                && route_uses_rustynet0(last_route.as_str())
            {
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    Err(format!(
        "timed out waiting for client exit route convergence to {expected_exit_node}: status={last_status} route={last_route}"
    ))
}

fn apply_lan_blackhole_routes(
    lan_routes: &[String],
    install_blackhole: bool,
) -> Result<(), String> {
    for cidr in lan_routes {
        let is_ipv6 = cidr.contains(':');
        let mut command = Command::new("ip");
        if is_ipv6 {
            command.arg("-6");
        } else {
            command.arg("-4");
        }
        command.arg("route");
        if install_blackhole {
            command.arg("replace").arg("blackhole").arg(cidr.as_str());
        } else {
            command.arg("del").arg(cidr.as_str());
        }
        let output = command
            .arg("table")
            .arg("51820")
            .output()
            .map_err(|err| format!("invoke ip route update for {cidr} failed: {err}"))?;
        if output.status.success() {
            continue;
        }
        if !install_blackhole {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("No such process") || stderr.contains("No such file") {
                continue;
            }
        }
        return Err(format!(
            "ip route update failed for {cidr}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

fn parse_env_u64_with_default(key: &str, default: u64) -> Result<u64, String> {
    match env_optional_string(key)? {
        Some(value) => value
            .parse::<u64>()
            .map_err(|err| format!("invalid integer value for {key}: {err}")),
        None => Ok(default),
    }
}

fn env_optional_string(key: &str) -> Result<Option<String>, String> {
    match std::env::var(key) {
        Ok(value) => {
            if value.trim().is_empty() {
                Ok(None)
            } else {
                Ok(Some(value))
            }
        }
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(format!("environment variable {key} contains non-utf8 data"))
        }
    }
}

fn env_string_or_default(key: &str, default: &str) -> Result<String, String> {
    Ok(env_optional_string(key)?.unwrap_or_else(|| default.to_string()))
}

fn env_required_nonempty(key: &str, label: &str) -> Result<String, String> {
    env_optional_string(key)?.ok_or_else(|| format!("{label} is required ({key})"))
}

fn env_path_or_default(key: &str, default: &str) -> Result<PathBuf, String> {
    if let Some(raw) = env_optional_string(key)? {
        let configured_path = PathBuf::from(raw);
        if !configured_path.is_absolute() {
            return Err(format!(
                "path must be absolute: {}",
                configured_path.display()
            ));
        }
        return Ok(configured_path);
    }

    let default_path = PathBuf::from(default);
    if default_path.is_absolute() {
        return Ok(default_path);
    }
    let cwd = std::env::current_dir()
        .map_err(|err| format!("resolve current directory failed: {err}"))?;
    Ok(cwd.join(default_path))
}

fn env_required_path(key: &str) -> Result<PathBuf, String> {
    let path =
        PathBuf::from(env_optional_string(key)?.ok_or_else(|| format!("{key} is required"))?);
    if !path.is_absolute() {
        return Err(format!("path must be absolute: {}", path.display()));
    }
    Ok(path)
}

fn is_valid_node_id(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | ':' | '-'))
}

fn validate_root_owned_encrypted_signing_file(path: &Path, label: &str) -> Result<(), String> {
    validate_encrypted_secret_file_security(path, label)?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|err| format!("inspect {label} failed ({}): {err}", path.display()))?;
    if metadata.uid() != 0 {
        return Err(format!("{label} must be owned by root: {}", path.display()));
    }
    Ok(())
}

fn validate_root_owned_passphrase_file(path: &Path, label: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|err| format!("inspect {label} failed ({}): {err}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!("{label} must not be a symlink: {}", path.display()));
    }
    if !metadata.file_type().is_file() {
        return Err(format!(
            "{label} must reference a regular file: {}",
            path.display()
        ));
    }
    if metadata.uid() != 0 {
        return Err(format!("{label} must be owned by root: {}", path.display()));
    }
    let mode = metadata.mode() & 0o777;
    let disallowed_mode_mask = if path.starts_with("/run/credentials/") {
        0o037
    } else {
        0o077
    };
    if (mode & disallowed_mode_mask) != 0 {
        let expected = if path.starts_with("/run/credentials/") {
            "owner-only or systemd credential mode"
        } else {
            "owner-only (0600)"
        };
        return Err(format!(
            "{label} permissions too broad ({mode:03o}); expected {expected}: {}",
            path.display()
        ));
    }
    Ok(())
}

fn group_gid_required(group_name: &str) -> Result<Gid, String> {
    match Group::from_name(group_name)
        .map_err(|err| format!("resolve group {group_name} failed: {err}"))?
    {
        Some(group) => Ok(group.gid),
        None => Err(format!(
            "required group '{group_name}' is missing; run systemd install/bootstrap first"
        )),
    }
}

fn ensure_directory_exists(path: &Path, mode: u32, owner: Uid, group: Gid) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(format!(
                    "directory must not be a symlink: {}",
                    path.display()
                ));
            }
            if !metadata.file_type().is_dir() {
                return Err(format!("path must be a directory: {}", path.display()));
            }
            return Ok(());
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(format!(
                "inspect directory {} failed: {err}",
                path.display()
            ));
        }
    }

    fs::create_dir_all(path)
        .map_err(|err| format!("create directory {} failed: {err}", path.display()))?;
    chown(path, Some(owner), Some(group))
        .map_err(|err| format!("set directory owner {} failed: {err}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|err| format!("set directory mode {} failed: {err}", path.display()))?;
    Ok(())
}

fn create_secure_temp_file(dir: &Path, prefix: &str) -> Result<PathBuf, String> {
    let mut random_bytes = [0u8; 8];
    for _ in 0..32 {
        fill_os_random_bytes(&mut random_bytes, "temporary file name")?;
        let candidate = dir.join(format!("{prefix}{}", hex_bytes(&random_bytes)));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        match options.open(&candidate) {
            Ok(_) => return Ok(candidate),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(format!(
                    "create temporary file {} failed: {err}",
                    candidate.display()
                ));
            }
        }
    }
    Err(format!(
        "unable to allocate secure temporary file in {}",
        dir.display()
    ))
}

fn create_secure_temp_directory(dir: &Path, prefix: &str) -> Result<PathBuf, String> {
    let mut random_bytes = [0u8; 8];
    for _ in 0..32 {
        fill_os_random_bytes(&mut random_bytes, "temporary directory name")?;
        let candidate = dir.join(format!("{prefix}{}", hex_bytes(&random_bytes)));
        match fs::create_dir(candidate.as_path()) {
            Ok(()) => {
                fs::set_permissions(candidate.as_path(), fs::Permissions::from_mode(0o700))
                    .map_err(|err| {
                        format!(
                            "set temporary directory mode {} failed: {err}",
                            candidate.display()
                        )
                    })?;
                return Ok(candidate);
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(format!(
                    "create temporary directory {} failed: {err}",
                    candidate.display()
                ));
            }
        }
    }
    Err(format!(
        "unable to allocate secure temporary directory in {}",
        dir.display()
    ))
}

fn publish_file_with_owner_mode(
    source_tmp_path: &Path,
    destination_path: &Path,
    owner: Uid,
    group: Gid,
    mode: u32,
    label: &str,
) -> Result<(), String> {
    chown(source_tmp_path, Some(owner), Some(group)).map_err(|err| {
        format!(
            "set {label} owner {} failed: {err}",
            source_tmp_path.display()
        )
    })?;
    fs::set_permissions(source_tmp_path, fs::Permissions::from_mode(mode)).map_err(|err| {
        format!(
            "set {label} mode {} failed: {err}",
            source_tmp_path.display()
        )
    })?;
    fs::rename(source_tmp_path, destination_path).map_err(|err| {
        format!(
            "publish {label} to {} failed: {err}",
            destination_path.display()
        )
    })?;
    Ok(())
}

fn read_bundle_u64_field_optional(path: &Path, key: &str) -> Result<Option<u64>, String> {
    let body =
        fs::read_to_string(path).map_err(|err| format!("read {} failed: {err}", path.display()))?;
    Ok(parse_bundle_u64_field(body.as_str(), key))
}

fn read_bundle_u64_field_required(path: &Path, key: &str) -> Result<u64, String> {
    read_bundle_u64_field_optional(path, key)?
        .ok_or_else(|| format!("issued assignment bundle missing {key} field"))
}

fn parse_bundle_u64_field(body: &str, key: &str) -> Option<u64> {
    let prefix = format!("{key}=");
    for line in body.lines() {
        if let Some(value) = line.strip_prefix(prefix.as_str()) {
            let normalized = value
                .chars()
                .filter(|ch| !ch.is_ascii_whitespace())
                .collect::<String>();
            return normalized.parse::<u64>().ok();
        }
    }
    None
}

fn replay_cache_from_entries(
    entries: &[rustynet_control::membership::MembershipLogEntry],
) -> Result<MembershipReplayCache, String> {
    let mut replay_cache = MembershipReplayCache::default();
    for entry in entries {
        replay_cache
            .observe(
                entry.signed_update.record.update_id.as_str(),
                entry.signed_update.record.epoch_new,
            )
            .map_err(|err| err.to_string())?;
    }
    Ok(replay_cache)
}

fn load_current_membership_state(
    paths: &MembershipPaths,
    now_unix: u64,
) -> Result<
    (
        rustynet_control::membership::MembershipState,
        Vec<rustynet_control::membership::MembershipLogEntry>,
        rustynet_control::membership::MembershipState,
    ),
    String,
> {
    let snapshot = load_membership_snapshot(&paths.snapshot_path).map_err(|err| err.to_string())?;
    let entries = load_membership_log(&paths.log_path).map_err(|err| err.to_string())?;
    let state = replay_membership_snapshot_and_log(&snapshot, &entries, now_unix)
        .map_err(|err| err.to_string())?;
    Ok((snapshot, entries, state))
}

fn emit_membership_evidence(
    paths: MembershipPaths,
    now_unix: u64,
    output_dir: PathBuf,
    environment: String,
) -> Result<String, String> {
    if environment.trim().is_empty() {
        return Err("environment must not be empty".to_string());
    }

    let (_, entries, state) = load_current_membership_state(&paths, now_unix)?;
    fs::create_dir_all(&output_dir).map_err(|err| format!("create output dir failed: {err}"))?;

    let captured_at_unix = unix_now();
    let active_node_count = state.active_nodes().len();
    let state_root = state.state_root_hex().map_err(|err| err.to_string())?;
    let conformance_path = output_dir.join("membership_conformance_report.json");
    let negative_path = output_dir.join("membership_negative_tests_report.json");
    let recovery_path = output_dir.join("membership_recovery_report.json");
    let audit_path = output_dir.join("membership_audit_integrity.log");

    write_membership_audit_log(&audit_path, &entries).map_err(|err| err.to_string())?;

    let tampered_log_detected = detect_tampered_log(&paths.log_path, &output_dir)?;
    let tampered_snapshot_detected = detect_tampered_snapshot(&paths.snapshot_path, &output_dir)?;

    let conformance = format!(
        "{{\n  \"phase\": \"membership\",\n  \"evidence_mode\": \"measured\",\n  \"environment\": \"{}\",\n  \"captured_at_unix\": {},\n  \"status\": \"pass\",\n  \"network_id\": \"{}\",\n  \"epoch\": {},\n  \"entries\": {},\n  \"active_node_count\": {},\n  \"state_root\": \"{}\",\n  \"snapshot_path\": \"{}\",\n  \"log_path\": \"{}\"\n}}\n",
        escape_json(&environment),
        captured_at_unix,
        escape_json(&state.network_id),
        state.epoch,
        entries.len(),
        active_node_count,
        escape_json(&state_root),
        escape_json(&paths.snapshot_path.display().to_string()),
        escape_json(&paths.log_path.display().to_string()),
    );
    write_text_file(&conformance_path, &conformance)?;

    let negative_status = if tampered_log_detected && tampered_snapshot_detected {
        "pass"
    } else {
        "fail"
    };
    let negative = format!(
        "{{\n  \"phase\": \"membership\",\n  \"evidence_mode\": \"measured\",\n  \"environment\": \"{}\",\n  \"captured_at_unix\": {},\n  \"status\": \"{}\",\n  \"tampered_log_detected\": {},\n  \"tampered_snapshot_detected\": {}\n}}\n",
        escape_json(&environment),
        captured_at_unix,
        negative_status,
        tampered_log_detected,
        tampered_snapshot_detected,
    );
    write_text_file(&negative_path, &negative)?;

    let recovery = format!(
        "{{\n  \"phase\": \"membership\",\n  \"evidence_mode\": \"measured\",\n  \"environment\": \"{}\",\n  \"captured_at_unix\": {},\n  \"status\": \"{}\",\n  \"audit_path\": \"{}\",\n  \"entries\": {},\n  \"epoch\": {},\n  \"state_root\": \"{}\"\n}}\n",
        escape_json(&environment),
        captured_at_unix,
        if negative_status == "pass" {
            "pass"
        } else {
            "fail"
        },
        escape_json(&audit_path.display().to_string()),
        entries.len(),
        state.epoch,
        escape_json(&state_root),
    );
    write_text_file(&recovery_path, &recovery)?;

    if negative_status != "pass" {
        return Err(
            "membership evidence generation failed: tampering checks did not fail closed"
                .to_string(),
        );
    }

    Ok(format!(
        "membership evidence generated: output_dir={} entries={} epoch={}",
        output_dir.display(),
        entries.len(),
        state.epoch
    ))
}

fn detect_tampered_log(source_path: &Path, output_dir: &Path) -> Result<bool, String> {
    let tampered_path = output_dir.join("membership.log.tampered");
    fs::copy(source_path, &tampered_path).map_err(|err| format!("copy log failed: {err}"))?;
    let original = fs::read_to_string(&tampered_path).map_err(|err| err.to_string())?;
    let tampered = if let Some((head, tail)) = original.split_once("entry=") {
        format!("{head}entry=999{tail}")
    } else if let Some((version_line, remainder)) = original.split_once('\n') {
        if !version_line.starts_with("version=") {
            fs::remove_file(&tampered_path).ok();
            return Err("membership log missing version line".to_string());
        }
        format!("version=255\n{remainder}")
    } else if original.starts_with("version=") {
        "version=255\n".to_string()
    } else {
        fs::remove_file(&tampered_path).ok();
        return Err("membership log missing version line".to_string());
    };
    fs::write(&tampered_path, tampered).map_err(|err| err.to_string())?;
    let detected = load_membership_log(&tampered_path).is_err();
    fs::remove_file(&tampered_path).ok();
    Ok(detected)
}

fn detect_tampered_snapshot(source_path: &Path, output_dir: &Path) -> Result<bool, String> {
    let tampered_path = output_dir.join("membership.snapshot.tampered");
    fs::copy(source_path, &tampered_path).map_err(|err| format!("copy snapshot failed: {err}"))?;
    let original = fs::read_to_string(&tampered_path).map_err(|err| err.to_string())?;
    let mut replaced = false;
    let mut tampered_lines = Vec::new();
    for line in original.lines() {
        if line.starts_with("digest=") && !replaced {
            tampered_lines.push("digest=00".to_string());
            replaced = true;
        } else {
            tampered_lines.push(line.to_string());
        }
    }
    if !replaced {
        fs::remove_file(&tampered_path).ok();
        return Err("membership snapshot missing digest line".to_string());
    }
    fs::write(&tampered_path, tampered_lines.join("\n") + "\n").map_err(|err| err.to_string())?;
    let detected = load_membership_snapshot(&tampered_path).is_err();
    fs::remove_file(&tampered_path).ok();
    Ok(detected)
}

fn escape_json(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(ch),
        }
    }
    out
}

fn write_text_file(path: &Path, body: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| format!("create parent failed: {err}"))?;
    }
    fs::write(path, body).map_err(|err| format!("write file failed: {err}"))
}

fn encrypted_secret_permission_policy(path: &Path) -> KeyCustodyPermissionPolicy {
    let mut policy = KeyCustodyPermissionPolicy::default();
    if matches!(path.parent(), Some(parent) if parent == Path::new("/etc/rustynet")) {
        // Encrypted signing artifacts currently coexist with daemon-readable verifier
        // material under /etc/rustynet on Linux.
        policy.required_directory_mode = 0o750;
    }
    policy
}

fn load_signing_key(path: &Path, passphrase_path: &Path) -> Result<SigningKey, String> {
    let secret = load_encrypted_secret_material(path, passphrase_path, "signing key")?;
    if secret.len() != 32 {
        return Err("decrypted signing key must be exactly 32 bytes".to_string());
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(secret.as_slice());
    let key = SigningKey::from_bytes(&bytes);
    bytes.zeroize();
    Ok(key)
}

fn validate_encrypted_secret_file_security(path: &Path, label: &str) -> Result<(), String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|err| format!("inspect {label} failed: {err}"))?;
    if metadata.file_type().is_symlink() {
        return Err(format!("{label} path must not be a symlink"));
    }
    if !metadata.file_type().is_file() {
        return Err(format!("{label} path must reference a regular file"));
    }

    let mode = metadata.mode() & 0o777;
    if (mode & 0o077) != 0 {
        return Err(format!(
            "{label} file permissions must be owner-only (0600); found {mode:03o}",
        ));
    }

    let expected_uid = Uid::effective().as_raw();
    let owner_uid = metadata.uid();
    if owner_uid != expected_uid {
        return Err(format!(
            "{label} file owner mismatch: expected uid {expected_uid}, found {owner_uid}"
        ));
    }
    Ok(())
}

fn load_encrypted_secret_material(
    path: &Path,
    passphrase_path: &Path,
    label: &str,
) -> Result<Zeroizing<Vec<u8>>, String> {
    if !passphrase_path.is_absolute() {
        return Err(format!(
            "{label} passphrase file path must be absolute: {}",
            passphrase_path.display()
        ));
    }
    validate_encrypted_secret_file_security(path, label)?;
    let passphrase = read_passphrase_file_explicit(passphrase_path).map_err(|err| {
        format!(
            "{label} passphrase source invalid ({}): {err}",
            passphrase_path.display()
        )
    })?;
    let parent = path
        .parent()
        .ok_or_else(|| format!("{label} path has no parent: {}", path.display()))?;
    let permission_policy = encrypted_secret_permission_policy(path);
    let secret = read_encrypted_key_file(parent, path, passphrase.as_str(), permission_policy)
        .map_err(|err| format!("decrypt {label} failed ({}): {err}", path.display()))?;
    Ok(Zeroizing::new(secret))
}

fn persist_encrypted_secret_material(
    path: &Path,
    secret: &[u8],
    passphrase_path: &Path,
    label: &str,
    force: bool,
) -> Result<(), String> {
    if !passphrase_path.is_absolute() {
        return Err(format!(
            "{label} passphrase file path must be absolute: {}",
            passphrase_path.display()
        ));
    }
    if path.exists() {
        let metadata =
            fs::symlink_metadata(path).map_err(|err| format!("inspect {label} failed: {err}"))?;
        if metadata.file_type().is_symlink() {
            return Err(format!("{label} path must not be a symlink"));
        }
        if !metadata.file_type().is_file() {
            return Err(format!("{label} path must reference a regular file"));
        }
        if !force {
            return Err(format!(
                "{label} already exists at {}; use --force to overwrite",
                path.display()
            ));
        }
        remove_file_if_present(path)?;
    }
    let passphrase = read_passphrase_file_explicit(passphrase_path).map_err(|err| {
        format!(
            "{label} passphrase source invalid ({}): {err}",
            passphrase_path.display()
        )
    })?;
    let parent = path
        .parent()
        .ok_or_else(|| format!("{label} path has no parent: {}", path.display()))?;
    let permission_policy = encrypted_secret_permission_policy(path);
    write_encrypted_key_file(parent, path, secret, passphrase.as_str(), permission_policy).map_err(
        |err| {
            format!(
                "persist encrypted {label} failed ({}): {err}",
                path.display()
            )
        },
    )
}

fn decode_hex_to_32(encoded: &str) -> Result<[u8; 32], String> {
    let trimmed = encoded.trim();
    if trimmed.len() != 64 {
        return Err("signing key must be 32-byte hex".to_string());
    }
    let mut out = [0u8; 32];
    let raw = trimmed.as_bytes();
    let mut index = 0usize;
    while index < 32 {
        let hi = decode_hex_nibble(raw[index * 2])?;
        let lo = decode_hex_nibble(raw[index * 2 + 1])?;
        out[index] = (hi << 4) | lo;
        index += 1;
    }
    Ok(out)
}

fn decode_hex_nibble(value: u8) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err("invalid hex character in signing key".to_string()),
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn split_csv(value: String) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn collect_repeated_option_values(args: &[String], key: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut index = 0usize;
    while index < args.len() {
        if index + 1 < args.len() && !args[index + 1].starts_with("--") {
            if args[index] == key {
                values.push(args[index + 1].clone());
            }
            index += 2;
        } else {
            index += 1;
        }
    }
    values
}

fn collect_repeated_option_values_allow_leading_dash(
    args: &[String],
    key: &str,
) -> Result<Vec<String>, String> {
    let mut values = Vec::new();
    let mut index = 0usize;
    while index < args.len() {
        if args[index] == key {
            if index + 1 >= args.len() {
                return Err(format!("missing value for repeated option: {key}"));
            }
            values.push(args[index + 1].clone());
            index += 2;
            continue;
        }
        if index + 1 < args.len() && !args[index + 1].starts_with("--") {
            index += 2;
        } else {
            index += 1;
        }
    }
    Ok(values)
}

fn parse_assignment_nodes(encoded: &str) -> Result<Vec<AssignmentNodeSpec>, String> {
    let mut nodes = Vec::new();
    for raw in encoded
        .split(';')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        let fields = raw.split('|').collect::<Vec<_>>();
        if fields.len() < 3 || fields.len() > 7 {
            return Err("invalid --nodes entry format; expected node_id|endpoint|public_key_hex[|owner|hostname|os|tags_csv]".to_string());
        }

        let node_id = fields[0].trim();
        if node_id.is_empty() {
            return Err("node_id must not be empty in --nodes".to_string());
        }
        let endpoint = fields[1].trim();
        endpoint
            .parse::<std::net::SocketAddr>()
            .map_err(|_| format!("invalid endpoint for node {node_id}: {endpoint}"))?;
        let public_key = decode_hex_to_32(fields[2].trim())
            .map_err(|err| format!("invalid public key for node {node_id}: {err}"))?;
        let owner = fields
            .get(3)
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| node_id.to_string());
        let hostname = fields
            .get(4)
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| node_id.to_string());
        let os = fields
            .get(5)
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "linux".to_string());
        let tags = fields
            .get(6)
            .map(|value| split_csv((*value).to_string()))
            .unwrap_or_default();

        nodes.push(AssignmentNodeSpec {
            node_id: node_id.to_string(),
            endpoint: endpoint.to_string(),
            public_key,
            owner,
            hostname,
            os,
            tags,
        });
    }
    if nodes.is_empty() {
        return Err("at least one node is required in --nodes".to_string());
    }
    Ok(nodes)
}

fn parse_assignment_allow_pairs(encoded: &str) -> Result<Vec<AssignmentAllowPair>, String> {
    let mut pairs = Vec::new();
    for raw in encoded
        .split(';')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        let fields = raw.split('|').collect::<Vec<_>>();
        if fields.len() != 2 {
            return Err(
                "invalid --allow entry format; expected source_node_id|destination_node_id"
                    .to_string(),
            );
        }
        let source_node_id = fields[0].trim();
        let destination_node_id = fields[1].trim();
        if source_node_id.is_empty() || destination_node_id.is_empty() {
            return Err("allow pair node ids must not be empty".to_string());
        }
        pairs.push(AssignmentAllowPair {
            source_node_id: source_node_id.to_string(),
            destination_node_id: destination_node_id.to_string(),
        });
    }
    if pairs.is_empty() {
        return Err("at least one allow pair is required in --allow".to_string());
    }
    Ok(pairs)
}

fn parse_traversal_candidates(encoded: &str) -> Result<Vec<TraversalCandidateSpec>, String> {
    let mut candidates = Vec::new();
    for raw in encoded
        .split(';')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        let fields = raw.split('|').map(str::trim).collect::<Vec<_>>();
        if fields.len() < 3 || fields.len() > 4 {
            return Err(
                "invalid --candidates entry format; expected type|endpoint|priority[|relay_id]"
                    .to_string(),
            );
        }
        let candidate_type = match fields[0] {
            "host" => EndpointHintCandidateType::Host,
            "srflx" => EndpointHintCandidateType::ServerReflexive,
            "relay" => EndpointHintCandidateType::Relay,
            other => {
                return Err(format!(
                    "unsupported candidate type {other}; expected host|srflx|relay"
                ));
            }
        };
        let endpoint = fields[1].to_string();
        endpoint
            .parse::<SocketAddr>()
            .map_err(|_| format!("invalid traversal candidate endpoint: {endpoint}"))?;
        let priority = fields[2]
            .parse::<u16>()
            .map_err(|err| format!("invalid traversal candidate priority: {err}"))?;
        let relay_id = fields
            .get(3)
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        if matches!(candidate_type, EndpointHintCandidateType::Relay) && relay_id.is_none() {
            return Err("relay traversal candidates require relay_id".to_string());
        }
        if !matches!(candidate_type, EndpointHintCandidateType::Relay) && relay_id.is_some() {
            return Err("relay_id is only valid for relay traversal candidates".to_string());
        }
        candidates.push(TraversalCandidateSpec {
            candidate_type,
            endpoint,
            relay_id,
            priority,
        });
    }
    if candidates.is_empty() {
        return Err("at least one traversal candidate is required in --candidates".to_string());
    }
    Ok(candidates)
}

fn load_dns_zone_records_manifest(path: &Path) -> Result<Vec<DnsZoneRecordSpec>, String> {
    let contents = fs::read_to_string(path)
        .map_err(|err| format!("read dns zone records manifest failed: {err}"))?;
    if contents.len() > DNS_ZONE_RECORDS_MANIFEST_MAX_BYTES {
        return Err(format!(
            "dns zone records manifest exceeds maximum size ({DNS_ZONE_RECORDS_MANIFEST_MAX_BYTES} bytes)"
        ));
    }

    let mut fields = std::collections::BTreeMap::<String, String>::new();
    let mut line_count = 0usize;
    for raw_line in contents.lines() {
        line_count = line_count.saturating_add(1);
        if line_count > DNS_ZONE_RECORDS_MANIFEST_MAX_LINES {
            return Err(format!(
                "dns zone records manifest exceeds maximum line count ({DNS_ZONE_RECORDS_MANIFEST_MAX_LINES})"
            ));
        }
        if raw_line.is_empty() {
            return Err("dns zone records manifest must not contain blank lines".to_string());
        }
        if raw_line.len() > DNS_ZONE_RECORDS_MANIFEST_MAX_LINE_BYTES {
            return Err(format!(
                "dns zone records manifest line exceeds maximum size ({DNS_ZONE_RECORDS_MANIFEST_MAX_LINE_BYTES} bytes)"
            ));
        }
        let (raw_key, raw_value) = raw_line
            .split_once('=')
            .ok_or_else(|| "invalid dns zone records manifest line".to_string())?;
        let key = raw_key.trim();
        let value = raw_value.trim();
        if key.is_empty() {
            return Err("dns zone records manifest key must not be empty".to_string());
        }
        if key != raw_key || value != raw_value {
            return Err(format!(
                "dns zone records manifest field must not contain leading or trailing whitespace: {key}"
            ));
        }
        if key.len() > DNS_ZONE_RECORDS_MANIFEST_MAX_KEY_BYTES {
            return Err(format!(
                "dns zone records manifest key exceeds maximum size ({DNS_ZONE_RECORDS_MANIFEST_MAX_KEY_BYTES} bytes)"
            ));
        }
        if value.len() > DNS_ZONE_RECORDS_MANIFEST_MAX_VALUE_BYTES {
            return Err(format!(
                "dns zone records manifest value exceeds maximum size ({DNS_ZONE_RECORDS_MANIFEST_MAX_VALUE_BYTES} bytes)"
            ));
        }
        if key.split('.').count() > DNS_ZONE_RECORDS_MANIFEST_MAX_KEY_DEPTH {
            return Err(format!(
                "dns zone records manifest key depth exceeds maximum depth ({DNS_ZONE_RECORDS_MANIFEST_MAX_KEY_DEPTH})"
            ));
        }
        if !is_allowed_dns_zone_records_manifest_key(key) {
            return Err(format!(
                "unsupported dns zone records manifest field: {key}"
            ));
        }
        if fields.insert(key.to_string(), value.to_string()).is_some() {
            return Err(format!("duplicate dns zone records manifest field: {key}"));
        }
    }

    if fields.is_empty() {
        return Err("dns zone records manifest is empty".to_string());
    }
    if fields.get("version").map(String::as_str) != Some("1") {
        return Err("unsupported dns zone records manifest version".to_string());
    }

    let record_count = parse_dns_zone_records_manifest_usize_field(&fields, "record_count")?;
    if record_count == 0 || record_count > DNS_ZONE_RECORDS_MANIFEST_MAX_RECORD_COUNT {
        return Err(format!(
            "dns zone records manifest record_count must be in range 1..={DNS_ZONE_RECORDS_MANIFEST_MAX_RECORD_COUNT}"
        ));
    }

    let mut expected_field_count = 2usize;
    let mut records = Vec::with_capacity(record_count);
    for index in 0..record_count {
        let label = canonicalize_dns_relative_name(required_dns_zone_records_manifest_field(
            &fields, index, "label",
        )?)
        .map_err(|err| format!("dns zone record {index} label is invalid: {err}"))?;
        let target_node_id =
            required_dns_zone_records_manifest_field(&fields, index, "target_node_id")?
                .trim()
                .to_string();
        if target_node_id.is_empty() {
            return Err(format!(
                "dns zone record {index} target_node_id must not be empty"
            ));
        }
        let ttl_secs =
            parse_dns_zone_records_manifest_indexed_u64_field(&fields, index, "ttl_secs")?;
        if ttl_secs == 0 || ttl_secs > 300 {
            return Err(format!(
                "dns zone record {index} ttl_secs must be in range 1..=300"
            ));
        }
        let alias_count =
            parse_dns_zone_records_manifest_indexed_usize_field(&fields, index, "alias_count")?;
        if alias_count > DNS_ZONE_RECORDS_MANIFEST_MAX_ALIAS_COUNT {
            return Err(format!(
                "dns zone record {index} alias_count exceeds maximum ({DNS_ZONE_RECORDS_MANIFEST_MAX_ALIAS_COUNT})"
            ));
        }
        expected_field_count = expected_field_count
            .checked_add(4)
            .and_then(|value| value.checked_add(alias_count))
            .ok_or_else(|| "dns zone records manifest field count overflow".to_string())?;

        let mut aliases = Vec::with_capacity(alias_count);
        let mut seen_aliases = HashSet::new();
        for alias_index in 0..alias_count {
            let alias = canonicalize_dns_relative_name(required_dns_zone_records_manifest_alias(
                &fields,
                index,
                alias_index,
            )?)
            .map_err(|err| {
                format!("dns zone record {index} alias {alias_index} is invalid: {err}")
            })?;
            if !seen_aliases.insert(alias.clone()) {
                return Err(format!(
                    "dns zone record {index} contains duplicate aliases"
                ));
            }
            aliases.push(alias);
        }

        records.push(DnsZoneRecordSpec {
            label,
            target_node_id,
            ttl_secs,
            aliases,
        });
    }

    if fields.len() != expected_field_count {
        return Err(format!(
            "dns zone records manifest field count mismatch: expected {expected_field_count}, found {}",
            fields.len()
        ));
    }

    Ok(records)
}

fn required_dns_zone_records_manifest_field<'a>(
    fields: &'a std::collections::BTreeMap<String, String>,
    index: usize,
    field: &str,
) -> Result<&'a str, String> {
    let key = format!("record.{index}.{field}");
    fields
        .get(&key)
        .map(String::as_str)
        .ok_or_else(|| format!("missing {key}"))
}

fn required_dns_zone_records_manifest_alias(
    fields: &std::collections::BTreeMap<String, String>,
    record_index: usize,
    alias_index: usize,
) -> Result<&str, String> {
    let key = format!("record.{record_index}.alias.{alias_index}");
    fields
        .get(&key)
        .map(String::as_str)
        .ok_or_else(|| format!("missing {key}"))
}

fn parse_dns_zone_records_manifest_usize_field(
    fields: &std::collections::BTreeMap<String, String>,
    key: &str,
) -> Result<usize, String> {
    fields
        .get(key)
        .ok_or_else(|| format!("missing {key}"))?
        .parse::<usize>()
        .map_err(|_| format!("invalid {key}"))
}

fn parse_dns_zone_records_manifest_indexed_usize_field(
    fields: &std::collections::BTreeMap<String, String>,
    index: usize,
    field: &str,
) -> Result<usize, String> {
    required_dns_zone_records_manifest_field(fields, index, field)?
        .parse::<usize>()
        .map_err(|_| format!("invalid record.{index}.{field}"))
}

fn parse_dns_zone_records_manifest_indexed_u64_field(
    fields: &std::collections::BTreeMap<String, String>,
    index: usize,
    field: &str,
) -> Result<u64, String> {
    required_dns_zone_records_manifest_field(fields, index, field)?
        .parse::<u64>()
        .map_err(|_| format!("invalid record.{index}.{field}"))
}

fn is_allowed_dns_zone_records_manifest_key(key: &str) -> bool {
    matches!(key, "version" | "record_count")
        || dns_zone_records_manifest_indexed_key(key).is_some()
}

fn dns_zone_records_manifest_indexed_key(key: &str) -> Option<()> {
    let mut parts = key.split('.');
    if parts.next()? != "record" {
        return None;
    }
    parts.next()?.parse::<usize>().ok()?;
    match parts.next()? {
        "label" | "target_node_id" | "ttl_secs" | "alias_count" if parts.next().is_none() => {
            Some(())
        }
        "alias" => {
            parts.next()?.parse::<usize>().ok()?;
            if parts.next().is_some() {
                return None;
            }
            Some(())
        }
        _ => None,
    }
}

fn validate_assignment_issue_config(
    nodes: &[AssignmentNodeSpec],
    allow_pairs: &[AssignmentAllowPair],
    target_node_id: &str,
    exit_node_id: Option<&str>,
) -> Result<(), String> {
    let mut node_ids = HashSet::new();
    for node in nodes {
        if !node_ids.insert(node.node_id.clone()) {
            return Err(format!("duplicate node id in --nodes: {}", node.node_id));
        }
    }
    if !node_ids.contains(target_node_id) {
        return Err(format!(
            "target node {target_node_id} is not present in --nodes",
        ));
    }
    match exit_node_id {
        Some(exit_node_id) if !node_ids.contains(exit_node_id) => {
            return Err(format!(
                "exit node {exit_node_id} is not present in --nodes",
            ));
        }
        _ => {}
    }
    let mut allow_pair_set = HashSet::new();
    for pair in allow_pairs {
        if !node_ids.contains(&pair.source_node_id) {
            return Err(format!(
                "allow rule source node {} is not present in --nodes",
                pair.source_node_id
            ));
        }
        if !node_ids.contains(&pair.destination_node_id) {
            return Err(format!(
                "allow rule destination node {} is not present in --nodes",
                pair.destination_node_id
            ));
        }
        let marker = format!("{}|{}", pair.source_node_id, pair.destination_node_id);
        if !allow_pair_set.insert(marker) {
            return Err(format!(
                "duplicate allow rule {} -> {}",
                pair.source_node_id, pair.destination_node_id
            ));
        }
    }
    Ok(())
}

fn load_assignment_signing_secret(path: &Path, passphrase_path: &Path) -> Result<Vec<u8>, String> {
    let secret =
        load_encrypted_secret_material(path, passphrase_path, "assignment signing secret")?;
    if secret.len() < 32 {
        return Err("assignment signing secret must be at least 32 bytes".to_string());
    }
    Ok(secret.to_vec())
}

fn generate_update_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    format!("update-{nanos}-{}", std::process::id())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn generate_assignment_nonce() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    (nanos & u128::from(u64::MAX)) as u64
}

trait MembershipOperationName {
    fn operation_name_for_cli(&self) -> &'static str;
}

impl MembershipOperationName for MembershipOperation {
    fn operation_name_for_cli(&self) -> &'static str {
        match self {
            MembershipOperation::AddNode(_) => "add_node",
            MembershipOperation::RemoveNode { .. } => "remove_node",
            MembershipOperation::RevokeNode { .. } => "revoke_node",
            MembershipOperation::RestoreNode { .. } => "restore_node",
            MembershipOperation::RotateNodeKey { .. } => "rotate_node_key",
            MembershipOperation::RotateApprover(_) => "rotate_approver",
            MembershipOperation::SetQuorum { .. } => "set_quorum",
        }
    }
}

struct OptionParser {
    values: HashMap<String, String>,
    flags: HashSet<String>,
}

impl OptionParser {
    fn empty() -> Self {
        Self {
            values: HashMap::new(),
            flags: HashSet::new(),
        }
    }

    fn parse(args: &[String]) -> Result<Self, String> {
        let mut values = HashMap::new();
        let mut flags = HashSet::new();
        let mut index = 0usize;
        while index < args.len() {
            let key = args[index].clone();
            if !key.starts_with("--") {
                return Err(format!("invalid option token: {key}"));
            }
            if index + 1 < args.len() && !args[index + 1].starts_with("--") {
                values.insert(key, args[index + 1].clone());
                index += 2;
            } else {
                flags.insert(key);
                index += 1;
            }
        }
        Ok(Self { values, flags })
    }

    fn required(&self, key: &str) -> Result<String, String> {
        self.values
            .get(key)
            .cloned()
            .ok_or_else(|| format!("missing required option: {key}"))
    }

    fn required_path(&self, key: &str) -> Result<PathBuf, String> {
        self.required(key).map(PathBuf::from)
    }

    fn optional_path(&self, key: &str) -> Option<PathBuf> {
        self.values.get(key).map(PathBuf::from)
    }

    fn value(&self, key: &str) -> Option<String> {
        self.values.get(key).cloned()
    }

    fn has_flag(&self, key: &str) -> bool {
        self.flags.contains(key)
    }

    fn parse_u64_or_default(&self, key: &str, default: u64) -> Result<u64, String> {
        if let Some(value) = self.values.get(key) {
            return value
                .parse::<u64>()
                .map_err(|err| format!("invalid value for {key}: {err}"));
        }
        Ok(default)
    }

    fn parse_u8_required(&self, key: &str) -> Result<u8, String> {
        let value = self.required(key)?;
        value
            .parse::<u8>()
            .map_err(|err| format!("invalid value for {key}: {err}"))
    }

    fn path_or_default(&self, key: &str, default: PathBuf) -> PathBuf {
        self.values.get(key).map(PathBuf::from).unwrap_or(default)
    }

    fn membership_paths(&self) -> MembershipPaths {
        MembershipPaths {
            snapshot_path: self
                .values
                .get("--snapshot")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(DEFAULT_MEMBERSHIP_SNAPSHOT_PATH)),
            log_path: self
                .values
                .get("--log")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(DEFAULT_MEMBERSHIP_LOG_PATH)),
        }
    }
}

fn to_ipc_command(command: CliCommand) -> IpcCommand {
    match command {
        CliCommand::Status => IpcCommand::Status,
        CliCommand::Netcheck => IpcCommand::Netcheck,
        CliCommand::StateRefresh => IpcCommand::StateRefresh,
        CliCommand::ExitNodeSelect(node) => IpcCommand::ExitNodeSelect(node),
        CliCommand::ExitNodeOff => IpcCommand::ExitNodeOff,
        CliCommand::LanAccessOn => IpcCommand::LanAccessOn,
        CliCommand::LanAccessOff => IpcCommand::LanAccessOff,
        CliCommand::DnsInspect => IpcCommand::DnsInspect,
        CliCommand::RouteAdvertise(cidr) => IpcCommand::RouteAdvertise(cidr),
        CliCommand::KeyRotate => IpcCommand::KeyRotate,
        CliCommand::KeyRevoke => IpcCommand::KeyRevoke,
        CliCommand::Login
        | CliCommand::Help
        | CliCommand::OperatorMenu
        | CliCommand::DnsZoneIssue(_)
        | CliCommand::DnsZoneVerify { .. }
        | CliCommand::Traversal(_)
        | CliCommand::Assignment(_)
        | CliCommand::Membership(_)
        | CliCommand::Trust(_)
        | CliCommand::Ops(_) => IpcCommand::Unknown("unsupported".to_string()),
    }
}

fn daemon_socket_path() -> PathBuf {
    std::env::var("RUSTYNET_DAEMON_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_SOCKET_PATH))
}

fn rustynetd_service_uid_for_socket(path: &Path) -> Option<u32> {
    if !path.starts_with("/run/rustynet") {
        return None;
    }
    User::from_name("rustynetd")
        .ok()
        .flatten()
        .map(|user| user.uid.as_raw())
}

fn rustynetd_service_gid_for_socket(path: &Path) -> Option<u32> {
    if !path.starts_with("/run/rustynet") {
        return None;
    }
    Group::from_name("rustynetd")
        .ok()
        .flatten()
        .map(|group| group.gid.as_raw())
}

fn validate_control_socket_security(path: &Path, label: &str) -> Result<(), String> {
    let expected_uid = Uid::effective().as_raw();
    let mut allowed_owner_uids = vec![expected_uid, 0];
    if let Some(service_uid) = rustynetd_service_uid_for_socket(path)
        && !allowed_owner_uids.contains(&service_uid)
    {
        allowed_owner_uids.push(service_uid);
    }
    if let Some(service_gid) = rustynetd_service_gid_for_socket(path) {
        return validate_root_managed_shared_runtime_socket(
            path,
            label,
            &allowed_owner_uids,
            &allowed_owner_uids,
            service_gid,
        );
    }
    validate_owner_only_socket(path, label, &allowed_owner_uids, &allowed_owner_uids)
}

fn send_command(command: IpcCommand) -> Result<IpcResponse, String> {
    send_command_with_socket(command, daemon_socket_path())
}

fn send_command_with_socket(
    command: IpcCommand,
    socket_path: PathBuf,
) -> Result<IpcResponse, String> {
    validate_control_socket_security(socket_path.as_path(), "daemon socket")?;
    let mut stream = UnixStream::connect(&socket_path)
        .map_err(|err| format!("connect {} failed: {err}", socket_path.display()))?;

    stream
        .write_all(format!("{}\n", command.as_wire()).as_bytes())
        .map_err(|err| format!("write failed: {err}"))?;

    let mut line = String::new();
    let mut reader = BufReader::new(&stream);
    reader
        .read_line(&mut line)
        .map_err(|err| format!("read failed: {err}"))?;

    Ok(IpcResponse::from_wire(&line))
}

fn help_text() -> String {
    [
        "commands:",
        "  status",
        "  login",
        "  netcheck",
        "  state refresh",
        "  operator menu",
        "  exit-node select <node>",
        "  exit-node off",
        "  lan-access on|off",
        "  dns inspect",
        "  dns zone issue --signing-secret <path> --signing-secret-passphrase-file <path> --subject-node-id <id> --nodes <node_specs> --allow <allow_specs> --records-manifest <path> --output <path> [--zone-name <name>] [--ttl-secs <secs>] [--generated-at <unix>] [--nonce <n>] [--verifier-key-output <path>]",
        "  dns zone verify --bundle <path> --verifier-key <path> [--expected-zone-name <name>] [--expected-subject-node-id <id>]",
        "  traversal issue --signing-secret <path> --signing-secret-passphrase-file <path> --source-node-id <id> --target-node-id <id> --nodes <node_specs> --allow <allow_specs> --candidates <type|endpoint|priority[|relay_id];...> --output <path> [--ttl-secs <secs>] [--generated-at <unix>] [--nonce <n>] [--verifier-key-output <path>]",
        "  traversal verify --bundle <path> --verifier-key <path> --watermark <path> [--expected-source-node-id <id>] [--max-age-secs <secs>] [--max-clock-skew-secs <secs>]",
        "  route advertise <cidr>",
        "  key rotate",
        "  key revoke",
        "  assignment issue --target-node-id <id> --nodes <node_specs> --allow <allow_specs> --signing-secret <path> --signing-secret-passphrase-file <path> --output <path> [--verifier-key-output <path>] [--mesh-cidr <cidr>] [--exit-node-id <id>] [--lan-routes <csv>] [--ttl-secs <secs>] [--generated-at <unix>] [--nonce <n>]",
        "  assignment verify --bundle <path> --verifier-key <path> --watermark <path> [--expected-node-id <id>] [--max-age-secs <secs>] [--max-clock-skew-secs <secs>]",
        "  assignment init-signing-secret --output <path> --signing-secret-passphrase-file <path> [--length-bytes <n>] [--force]",
        "    node_specs format: node_id|endpoint|public_key_hex[|owner|hostname|os|tags_csv];... ",
        "    allow_specs format: source_node_id|destination_node_id;...",
        "  membership status [--snapshot <path>] [--log <path>]",
        "  membership propose-add --node-id <id> --node-pubkey <hex> --owner <owner> --output <path> [--roles <csv>] [--reason <code>] [--policy-context <ctx>] [--expires-in <secs>] [--update-id <id>] [--snapshot <path>] [--log <path>]",
        "  membership propose-remove --node-id <id> --output <path> [--reason <code>] [--expires-in <secs>] [--snapshot <path>] [--log <path>]",
        "  membership propose-revoke --node-id <id> --output <path> [--reason <code>] [--expires-in <secs>] [--snapshot <path>] [--log <path>]",
        "  membership propose-restore --node-id <id> --output <path> [--reason <code>] [--expires-in <secs>] [--snapshot <path>] [--log <path>]",
        "  membership propose-rotate-key --node-id <id> --new-pubkey <hex> --output <path> [--reason <code>] [--expires-in <secs>] [--snapshot <path>] [--log <path>]",
        "  membership propose-set-quorum --threshold <n> --output <path> [--reason <code>] [--expires-in <secs>] [--snapshot <path>] [--log <path>]",
        "  membership propose-rotate-approver --approver-id <id> --approver-pubkey <hex> --role <owner|guardian> --status <active|revoked> --output <path> [--reason <code>] [--expires-in <secs>] [--snapshot <path>] [--log <path>]",
        "  membership sign-update --record <path> --approver-id <id> --signing-key <path> --signing-key-passphrase-file <path> --output <path> [--merge-from <signed-update-path>]",
        "  membership verify-update --signed-update <path> [--snapshot <path>] [--log <path>] [--now <unix>] [--dry-run]",
        "  membership apply-update --signed-update <path> [--snapshot <path>] [--log <path>] [--now <unix>] [--dry-run]",
        "  membership verify-log [--snapshot <path>] [--log <path>] [--audit-output <path>] [--now <unix>]",
        "  membership generate-evidence [--snapshot <path>] [--log <path>] [--output-dir <dir>] [--environment <label>] [--now <unix>]",
        "  trust keygen --signing-key-output <path> --signing-key-passphrase-file <path> --verifier-key-output <path> [--force]",
        "  trust export-verifier-key --signing-key <path> --signing-key-passphrase-file <path> --output <path>",
        "  trust issue --signing-key <path> --signing-key-passphrase-file <path> --output <path> [--updated-at-unix <unix>] [--nonce <n>]",
        "  trust verify --evidence <path> --verifier-key <path> --watermark <path> [--max-age-secs <secs>] [--max-clock-skew-secs <secs>]",
        "  ops refresh-trust",
        "  ops verify-runtime-binary-custody",
        "  ops refresh-signed-trust",
        "  ops bootstrap-wireguard-custody",
        "  ops refresh-assignment",
        "  ops state-refresh-if-socket-present",
        "  ops collect-phase1-measured-input",
        "  ops run-phase1-baseline",
        "  ops check-no-unsafe-rust-sources [--root <path>]",
        "  ops check-dependency-exceptions [--path <path>]",
        "  ops check-perf-regression [--phase1-report <path>] [--phase3-report <path>]",
        "  ops check-secrets-hygiene [--root <path>]",
        "  ops collect-phase9-raw-evidence",
        "  ops generate-phase9-artifacts",
        "  ops verify-phase9-readiness",
        "  ops verify-phase9-evidence",
        "  ops generate-phase10-artifacts",
        "  ops verify-phase10-readiness",
        "  ops verify-phase10-provenance",
        "  ops write-phase10-hp2-traversal-reports --source-dir <path> --environment <label> --path-selection-log <path> --probe-security-log <path>",
        "  ops verify-phase6-platform-readiness",
        "  ops verify-phase6-parity-evidence",
        "  ops verify-required-test-output --output <path> --package <name> --test-filter <pattern>",
        "  ops generate-cross-network-remote-exit-report --suite <suite> --report-path <path> --log-path <path> --status <pass|fail> [--failure-summary <text>] [--environment <label>] [--implementation-state <label>] [--source-artifact <path>]... [--log-artifact <path>]... [--client-host <host>] [--exit-host <host>] [--relay-host <host>] [--probe-host <host>] [--client-network-id <id>] [--exit-network-id <id>] [--relay-network-id <id>] [--nat-profile <profile>] [--impairment-profile <profile>] [--path-status-line <status-text>] [--path-evidence-report <path>] [--check <name=pass|fail>]...",
        "  ops validate-cross-network-remote-exit-reports [--reports <path[,path...]>] [--artifact-dir <path>] [--output <path>] [--max-evidence-age-seconds <secs>] [--expected-git-commit <sha>] [--require-pass-status]",
        "  ops validate-cross-network-nat-matrix [--reports <path[,path...]>] [--artifact-dir <path>] [--required-nat-profiles <profile[,profile...]>] [--output <path>] [--max-evidence-age-seconds <secs>] [--expected-git-commit <sha>] [--require-pass-status]",
        "  ops read-cross-network-report-fields --report-path <path> [--include-status] [--check <name>]... [--network-field <name>]... [--default-value <text>]",
        "  ops classify-cross-network-topology --ip-a <ip> --ip-b <ip> [--ipv4-prefix <n>] [--ipv6-prefix <n>]",
        "  ops choose-cross-network-roam-alias --exit-ip <ip> [--used-ip <ip>]... [--ipv4-prefix <n>] [--ipv6-prefix <n>]",
        "  ops validate-ipv4-address --ip <ipv4>",
        "  ops write-cross-network-soak-monitor-summary --path <path> --samples <n> --failing-samples <n> --max-consecutive-failures-observed <n> --elapsed-secs <n> --required-soak-duration-secs <n> --allowed-failing-samples <n> --allowed-max-consecutive-failures <n> --direct-remote-exit-ready <pass|fail> --post-soak-bypass-ready <pass|fail> --no-plaintext-passphrase-files <pass|fail> --direct-samples <n> --relay-samples <n> --fail-closed-samples <n> --other-path-samples <n> --path-transition-count <n> --status-mismatch-samples <n> --route-mismatch-samples <n> --endpoint-mismatch-samples <n> --dns-alarm-bad-samples <n> --transport-identity-failures <n> --endpoint-change-events-start <n> --endpoint-change-events-end <n> --endpoint-change-events-delta <n> --first-non-direct-reason <text> --last-path-mode <text> --last-path-reason <text> --first-failure-reason <text> --long-soak-stable <pass|fail>",
        "  ops check-local-file-mode --path <path> --policy <owner-only|no-group-world-write> [--label <text>]",
        "  ops redact-forensics-text",
        "  ops write-cross-network-forensics-manifest --stage <name> --collected-at-utc <utc> --stage-dir <path> --output <path>",
        "  ops sha256-file --path <path>",
        "  ops write-cross-network-preflight-report --nodes-tsv <path> --stage-dir <path> --output <path> --reference-unix <unix> --max-clock-skew-secs <secs> --discovery-max-age-secs <secs> --signed-artifact-max-age-secs <secs>",
        "  ops write-live-linux-reboot-recovery-report --report-path <path> --observations-path <path> --exit-pre <id> --exit-post <id> --client-pre <id> --client-post <id> --exit-return <pass|fail|skipped> --exit-boot-change <pass|fail|skipped> --post-exit-dns-refresh <pass|fail|skipped> --post-exit-twohop <pass|fail|skipped> --client-return <pass|fail|skipped> --client-boot-change <pass|fail|skipped> --post-client-dns-refresh <pass|fail|skipped> --post-client-twohop <pass|fail|skipped> --salvage-twohop <pass|fail|skipped>",
        "  ops write-live-linux-lab-run-summary --nodes-tsv <path> --stages-tsv <path> --summary-json <path> --summary-md <path> --run-id <id> --network-id <id> --report-dir <path> --overall-status <status> --started-at-local <text> --started-at-utc <text> --started-at-unix <unix> --finished-at-local <text> --finished-at-utc <text> --finished-at-unix <unix> --elapsed-secs <secs> --elapsed-human <text>",
        "  ops scan-ipv4-port-range --network-prefix <a.b.c> [--start-host <n>] [--end-host <n>] [--port <n>] [--timeout-ms <n>] [--output-key <text>]",
        "  ops update-role-switch-host-result --hosts-json-path <path> --os-id <id> --temp-role <role> --switch-execution <pass|fail> --post-switch-reconcile <pass|fail> --policy-still-enforced <pass|fail> --least-privilege-preserved <pass|fail>",
        "  ops write-role-switch-matrix-report --hosts-json-path <path> --report-path <path> --source-path <path> --git-commit <sha> --captured-at-unix <unix> --overall-status <pass|fail>",
        "  ops write-live-linux-server-ip-bypass-report --report-path <path> --allowed-management-cidrs <cidr[,cidr...]> --probe-from-client-status <pass|fail> --probe-ip <ipv4> --probe-port <port> --client-internet-route <text> --client-probe-route <text> --client-table-51820 <text> --client-endpoints <text> --probe-self-test <text> --probe-from-client-output <text> [--captured-at-utc <utc>] [--captured-at-unix <unix>]",
        "  ops write-live-linux-control-surface-report --report-path <path> --dns-bind-addr <host:port> --remote-dns-probe-status <pass|fail|skipped> --remote-dns-probe-output <text> --work-dir <path> --host-label <label> [--host-label <label>]... [--captured-at-utc <utc>] [--captured-at-unix <unix>]",
        "  ops rewrite-assignment-peer-endpoint-ip --assignment-path <path> --endpoint-ip <ipv4>",
        "  ops rewrite-assignment-mesh-cidr --assignment-path <path> --mesh-cidr <ipv4-cidr>",
        "  ops write-live-linux-endpoint-hijack-report --report-path <path> --rogue-endpoint-ip <ipv4> --baseline-status <text> --baseline-netcheck <text> --baseline-endpoints <text> --status-after-hijack <text> --netcheck-after-hijack <text> --endpoints-after-hijack <text> --status-after-recovery <text> --endpoints-after-recovery <text> [--captured-at-utc <utc>] [--captured-at-unix <unix>]",
        "  ops write-real-wireguard-exitnode-e2e-report --report-path <path> --exit-status <pass|fail> --lan-off-status <pass|fail> --lan-on-status <pass|fail> --dns-up-status <pass|fail> --kill-switch-status <pass|fail> --dns-down-status <pass|fail> [--environment <label>] [--captured-at-utc <utc>] [--captured-at-unix <unix>]",
        "  ops write-real-wireguard-no-leak-under-load-report --report-path <path> --load-pcap <path> --down-pcap <path> --tunnel-up-status <pass|fail> --load-ping-status <pass|fail> --tunnel-down-block-status <pass|fail> [--environment <label>] [--captured-at-utc <utc>] [--captured-at-unix <unix>]",
        "  ops verify-no-leak-dataplane-report --report-path <path>",
        "  ops e2e-dns-query --server <ip> --port <port> --qname <name> [--timeout-ms <ms>] [--fail-on-no-response]",
        "  ops e2e-http-probe-server --bind-ip <ipv4> --port <port> [--response-body <text>]",
        "  ops e2e-http-probe-client --host <ip> --port <port> [--timeout-ms <ms>] [--expect-marker <text>]",
        "  ops read-json-field --payload <json> --field <name>",
        "  ops extract-managed-dns-expected-ip --fqdn <name> --inspect-output <text>",
        "  ops write-active-network-signed-state-tamper-report --report-path <path> --baseline-status <pass|fail> --tamper-reject-status <pass|fail> --fail-closed-status <pass|fail> --netcheck-fail-closed-status <pass|fail> --recovery-status <pass|fail> --exit-host <host> --client-host <host> --status-after-tamper <text> --netcheck-after-tamper <text> --status-after-recovery <text> [--captured-at-utc <utc>] [--captured-at-unix <unix>]",
        "  ops write-active-network-rogue-path-hijack-report --report-path <path> --baseline-status <pass|fail> --hijack-reject-status <pass|fail> --fail-closed-status <pass|fail> --netcheck-fail-closed-status <pass|fail> --no-rogue-endpoint-status <pass|fail> --recovery-status <pass|fail> --recovery-endpoint-status <pass|fail> --rogue-endpoint-ip <ipv4> --exit-host <host> --client-host <host> --endpoints-before <text> --endpoints-after-hijack <text> --endpoints-after-recovery <text> --status-after-hijack <text> --netcheck-after-hijack <text> --status-after-recovery <text> [--captured-at-utc <utc>] [--captured-at-unix <unix>]",
        "  ops validate-network-discovery-bundle [--bundle <path>]... [--bundles <path[,path...]>] [--max-age-seconds <secs>] [--require-verifier-keys] [--require-daemon-active] [--require-socket-present] [--output <path>]",
        "  ops generate-live-linux-lab-failure-digest --nodes-tsv <path> --stages-tsv <path> --report-dir <path> --run-id <id> --network-id <id> --overall-status <status> --output-json <path> --output-md <path>",
        "  ops vm-lab-list [--inventory <path>]",
        "  ops vm-lab-discover-local-utm [--inventory <path>] [--utm-documents-root <path>] [--utmctl-path <path>] [--ssh-identity-file <path>] [--known-hosts-file <path>] [--ssh-port <port>] [--timeout-secs <secs>] [--update-inventory-live-ips] [--report-dir <path>]",
        "  ops vm-lab-discover-local-utm-summary [--inventory <path>] [--utm-documents-root <path>] [--utmctl-path <path>] [--ssh-identity-file <path>] [--known-hosts-file <path>] [--ssh-port <port>] [--timeout-secs <secs>] [--update-inventory-live-ips] [--report-dir <path>]",
        "  ops vm-lab-start [--inventory <path>] [--vm <alias>]... [--vms <alias[,alias...]>] [--all] [--utmctl-path <absolute-path>] [--timeout-secs <secs>]",
        "  ops vm-lab-sync-repo [--inventory <path>] [--vm <alias>]... [--vms <alias[,alias...]>] [--all] [--target <ssh-target>]... [--targets <ssh-target[,ssh-target...]>] (--repo-url <url> | --local-source-dir <path>) --dest-dir <absolute-path> [--branch <name>] [--remote <name>] [--ssh-user <user>] [--ssh-identity-file <path>] [--known-hosts-file <path>] [--timeout-secs <secs>]",
        "  ops vm-lab-sync-bootstrap [--inventory <path>] [--vm <alias>]... [--vms <alias[,alias...]>] [--all] [--target <ssh-target>]... [--targets <ssh-target[,ssh-target...]>] [--require-same-network] (--repo-url <url> | --local-source-dir <path>) --dest-dir <absolute-path> [--workdir <absolute-path>] [--branch <name>] [--remote <name>] --program <path|name> [--arg <value>]... [--ssh-user <user>] [--ssh-identity-file <path>] [--known-hosts-file <path>] [--sudo] [--timeout-secs <secs>]",
        "  ops vm-lab-run [--inventory <path>] [--vm <alias>]... [--vms <alias[,alias...]>] [--all] [--target <ssh-target>]... [--targets <ssh-target[,ssh-target...]>] --workdir <absolute-path> --program <path|name> [--arg <value>]... [--ssh-user <user>] [--ssh-identity-file <path>] [--known-hosts-file <path>] [--sudo] [--timeout-secs <secs>]",
        "  ops vm-lab-bootstrap [--inventory <path>] [--vm <alias>]... [--vms <alias[,alias...]>] [--all] [--target <ssh-target>]... [--targets <ssh-target[,ssh-target...]>] --workdir <absolute-path> --program <path|name> [--arg <value>]... [--ssh-user <user>] [--ssh-identity-file <path>] [--known-hosts-file <path>] [--sudo] [--timeout-secs <secs>]",
        "  ops vm-lab-write-live-lab-profile [--inventory <path>] --output <path> --ssh-identity-file <path> [--ssh-known-hosts-file <path>] (--exit-vm <alias>|--exit-target <user@host>) (--client-vm <alias>|--client-target <user@host>) [--entry-vm <alias>|--entry-target <user@host>] [--aux-vm <alias>|--aux-target <user@host>] [--extra-vm <alias>|--extra-target <user@host>] [--fifth-client-vm <alias>|--fifth-client-target <user@host>] [--require-same-network] [--ssh-allow-cidrs <cidrs>] [--network-id <id>] [--traversal-ttl-secs <secs>] [--cross-network-nat-profiles <csv>] [--cross-network-required-nat-profiles <csv>] [--cross-network-impairment-profile <profile>] [--backend <mode>] [--source-mode <mode>] [--repo-ref <ref>] [--report-dir <path>]",
        "  ops vm-lab-setup-live-lab [--inventory <path>] [--profile <path>] [--profile-output <path>] --report-dir <path> --ssh-identity-file <path> [--known-hosts-file <path>] [--exit-vm <alias>] [--client-vm <alias>] [--entry-vm <alias>] [--aux-vm <alias>] [--extra-vm <alias>] [--fifth-client-vm <alias>] [--require-same-network] [--script <path>] [--source-mode <mode>] [--repo-ref <ref>] [--resume-from <stage>] [--rerun-stage <stage>] [--max-parallel-node-workers <n>] [--timeout-secs <secs>] [--dry-run]",
        "  ops vm-lab-orchestrate-live-lab [--inventory <path>] [--profile <path>] [--profile-output <path>] --report-dir <path> --ssh-identity-file <path> [--known-hosts-file <path>] [--exit-vm <alias>] [--client-vm <alias>] [--entry-vm <alias>] [--aux-vm <alias>] [--extra-vm <alias>] [--fifth-client-vm <alias>] [--require-same-network] [--script <path>] [--source-mode <mode>] [--repo-ref <ref>] [--max-parallel-node-workers <n>] [--skip-gates] [--skip-soak] [--skip-cross-network] [--utm-documents-root <path>] [--utmctl-path <path>] [--ssh-port <port>] [--discovery-timeout-secs <secs>] [--wait-ready-timeout-secs <secs>] [--timeout-secs <secs>] [--collect-artifacts-on-failure] [--skip-diagnose-on-failure] [--stop-after-ready] [--dry-run]",
        "  ops vm-lab-validate-live-lab-profile --profile <path> [--expected-backend <mode>] [--expected-source-mode <mode>] [--require-five-node]",
        "  ops vm-lab-diagnose-live-lab-failure [--inventory <path>] --profile <path> --report-dir <path> [--stage <name>] [--output-dir <path>] [--collect-artifacts] [--timeout-secs <secs>]",
        "  ops vm-lab-diff-live-lab-runs --old-report-dir <path> --new-report-dir <path>",
        "  ops vm-lab-iterate-live-lab [--inventory <path>] [--profile-output <path>] --ssh-identity-file <path> [--ssh-known-hosts-file <path>] (--exit-vm <alias>|--exit-target <user@host>) (--client-vm <alias>|--client-target <user@host>) [--entry-vm <alias>|--entry-target <user@host>] [--aux-vm <alias>|--aux-target <user@host>] [--extra-vm <alias>|--extra-target <user@host>] [--fifth-client-vm <alias>|--fifth-client-target <user@host>] [--require-same-network] [--ssh-allow-cidrs <cidrs>] [--network-id <id>] [--traversal-ttl-secs <secs>] [--backend <mode>] [--source-mode <mode>] [--repo-ref <ref>] [--report-dir <path>] [--script <path>] [--dry-run] [--skip-gates] [--skip-soak] [--skip-cross-network] [--require-clean-tree] [--require-local-head] --validation-step <fmt|check:<package>|check-bin:<package>:<bin>|test:<package>[:filter]|test-bin:<package>:<bin>[:filter]>... [--collect-failure-diagnostics] [--failed-log-tail-lines <n>] [--timeout-secs <secs>]",
        "  ops vm-lab-run-live-lab --profile <path> [--script <path>] [--dry-run] [--skip-setup] [--skip-gates] [--skip-soak] [--skip-cross-network] [--source-mode <mode>] [--repo-ref <ref>] [--report-dir <path>] [--timeout-secs <secs>]",
        "  ops vm-lab-check-known-hosts [--inventory <path>] [--vm <alias>]... [--vms <alias[,alias...]>] [--all] [--target <ssh-target>]... [--targets <ssh-target[,ssh-target...]>] [--known-hosts-file <path>]",
        "  ops vm-lab-preflight [--inventory <path>] [--vm <alias>]... [--vms <alias[,alias...]>] [--all] [--target <ssh-target>]... [--targets <ssh-target[,ssh-target...]>] [--ssh-identity-file <path>] [--known-hosts-file <path>] [--require-same-network] [--require-command <name>]... [--require-commands <name[,name...]>] [--min-free-kib <kib>] [--require-rustynet-installed] [--timeout-secs <secs>]",
        "  ops vm-lab-status [--inventory <path>] [--vm <alias>]... [--vms <alias[,alias...]>] [--all] [--target <ssh-target>]... [--targets <ssh-target[,ssh-target...]>] [--ssh-user <user>] [--ssh-identity-file <path>] [--known-hosts-file <path>] [--timeout-secs <secs>]",
        "  ops vm-lab-stop [--inventory <path>] [--vm <alias>]... [--vms <alias[,alias...]>] [--all] [--utmctl-path <absolute-path>] [--timeout-secs <secs>]",
        "  ops vm-lab-shutdown [--inventory <path>] [--vm <alias>]... [--vms <alias[,alias...]>] [--all] [--utmctl-path <absolute-path>] [--timeout-secs <secs>]",
        "  ops vm-lab-restart [--inventory <path>] [--vm <alias>]... [--vms <alias[,alias...]>] [--all] [--target <ssh-target>]... [--targets <ssh-target[,ssh-target...]>] [--service <name>] [--wait-ready] [--ssh-port <port>] [--wait-ready-timeout-secs <secs>] [--ssh-user <user>] [--ssh-identity-file <path>] [--known-hosts-file <path>] [--utmctl-path <absolute-path>] [--timeout-secs <secs>] [--json] [--report-dir <path>]",
        "  ops vm-lab-collect-artifacts [--inventory <path>] [--vm <alias>]... [--vms <alias[,alias...]>] [--all] [--target <ssh-target>]... [--targets <ssh-target[,ssh-target...]>] --output-dir <path> [--ssh-user <user>] [--ssh-identity-file <path>] [--known-hosts-file <path>] [--timeout-secs <secs>]",
        "  ops vm-lab-write-topology [--inventory <path>] --suite <direct-remote-exit|relay-remote-exit|failback-roaming|full-live-lab> --output <path> [--vm <alias>]... [--vms <alias[,alias...]>] [--all] [--require-same-network]",
        "  ops vm-lab-issue-and-distribute-state [--inventory <path>] --topology <path> --authority-vm <alias> [--ssh-user <user>] [--ssh-identity-file <path>] [--known-hosts-file <path>] [--timeout-secs <secs>]",
        "  ops vm-lab-run-suite [--inventory <path>] --suite <direct-remote-exit|relay-remote-exit|failback-roaming|full-live-lab> [--topology <path>] [--vm <alias>]... [--vms <alias[,alias...]>] [--all] --ssh-identity-file <path> [--nat-profile <profile>] [--impairment-profile <profile>] [--report-dir <path>] [--dry-run] [--timeout-secs <secs>]",
        "  ops vm-lab-bootstrap-phase [--inventory <path>] --phase <sync-source|build-release|install-release|restart-runtime|verify-runtime|all> [--vm <alias>]... [--vms <alias[,alias...]>] [--all] [--target <ssh-target>]... [--targets <ssh-target[,ssh-target...]>] [--require-same-network] [--repo-url <url> | --local-source-dir <path>] [--dest-dir <absolute-path>] [--branch <name>] [--remote <name>] [--ssh-user <user>] [--ssh-identity-file <path>] [--known-hosts-file <path>] [--timeout-secs <secs>]",
        "  ops rebind-linux-fresh-install-os-matrix-inputs --dest-dir <path> --bootstrap-log <path> --baseline-log <path> --two-hop-report <path> --role-switch-report <path> --lan-toggle-report <path> --exit-handoff-report <path>",
        "  ops generate-linux-fresh-install-os-matrix-report --output <path> --environment <label> --source-mode <mode> --expected-git-commit-file <path> --git-status-file <path> --bootstrap-log <path> --baseline-log <path> --two-hop-report <path> --role-switch-report <path> --lan-toggle-report <path> --exit-handoff-report <path> --exit-node-id <id> --client-node-id <id> --ubuntu-node-id <id> --fedora-node-id <id> --mint-node-id <id> [--debian-os-version <label>] [--ubuntu-os-version <label>] [--fedora-os-version <label>] [--mint-os-version <label>]",
        "  ops verify-linux-fresh-install-os-matrix-readiness --report-path <path> [--max-age-seconds <secs>] [--profile <cross_platform|linux>] [--expected-git-commit <sha>]",
        "  ops write-fresh-install-os-matrix-readiness-fixtures --output-dir <path> --head-commit <sha> --stale-commit <sha> --now-unix <unix>",
        "  ops write-unsigned-release-provenance --input <path> --output <path>",
        "  ops sign-release-artifact",
        "  ops verify-release-artifact",
        "  ops collect-platform-probe",
        "  ops generate-platform-parity-report",
        "  ops collect-platform-parity-bundle",
        "  ops install-systemd",
        "  ops prepare-system-dirs",
        "  ops restart-runtime-service",
        "  ops stop-runtime-service",
        "  ops show-runtime-service-status",
        "  ops start-assignment-refresh-service",
        "  ops check-assignment-refresh-availability",
        "  ops install-trust-material --verifier-source <absolute-path> --trust-source <absolute-path> --verifier-dest <absolute-path> --trust-dest <absolute-path> [--daemon-group <group>]",
        "  ops apply-managed-dns-routing",
        "  ops clear-managed-dns-routing",
        "  ops disconnect-cleanup",
        "  ops apply-blind-exit-lockdown",
        "  ops init-membership",
        "  ops secure-remove --path <absolute-path>",
        "  ops ensure-signing-passphrase-material",
        "  ops ensure-local-trust-material --signing-key-passphrase-file <absolute-path>",
        "  ops materialize-signing-passphrase --output <absolute-path>",
        "  ops materialize-signing-passphrase-temp",
        "  ops set-assignment-refresh-exit-node [--env-path <absolute-path>] [--exit-node-id <id>]",
        "  ops force-local-assignment-refresh-now",
        "  ops apply-lan-access-coupling --enable <true|false> [--lan-routes <cidr[,cidr...]>] [--env-path <absolute-path>]",
        "  ops apply-role-coupling --target-role <admin|client> [--preferred-exit-node-id <id>] [--enable-exit-advertise <true|false>] [--env-path <absolute-path>] [--skip-client-exit-route-convergence-wait]",
        "  ops peer-store-validate --config-dir <absolute-path> --peers-file <absolute-path>",
        "  ops peer-store-list --config-dir <absolute-path> --peers-file <absolute-path> [--role <role>] [--node-id <id>]",
        "  ops run-debian-two-node-e2e --exit-host <host|user@host> --client-host <host|user@host> --ssh-allow-cidrs <cidr[,cidr...]> [--ssh-user <user>] [--ssh-sudo <auto|always|never>] [--sudo-password-file <path>] [--ssh-port <port>] [--ssh-identity <path>] [--ssh-known-hosts-file <path>] [--exit-node-id <id>] [--client-node-id <id>] [--network-id <id>] [--remote-root <abs-path>] [--repo-ref <git-ref>] [--skip-apt] [--report-path <path>]",
        "  ops e2e-bootstrap-host --role <role> --node-id <id> --network-id <id> --src-dir <absolute-path> --ssh-allow-cidrs <cidr[,cidr...]> [--skip-apt]",
        "  ops e2e-enforce-host --role <role> --node-id <id> --src-dir <absolute-path> --ssh-allow-cidrs <cidr[,cidr...]>",
        "  ops e2e-membership-add --client-node-id <id> --client-pubkey-hex <hex> --owner-approver-id <id>",
        "  ops e2e-issue-assignments --exit-node-id <id> --client-node-id <id> --exit-endpoint <host:port> --client-endpoint <host:port> --exit-pubkey-hex <hex> --client-pubkey-hex <hex> [--artifact-dir <absolute-path>]",
        "  ops e2e-issue-assignment-bundles-from-env --env-file <absolute-path> [--issue-dir <absolute-path>]",
        "  ops e2e-issue-traversal-bundles-from-env --env-file <absolute-path> [--issue-dir <absolute-path>]",
        "  ops e2e-issue-dns-zone-bundles-from-env --env-file <absolute-path> [--issue-dir <absolute-path>]",
        "  Windows UTM targets use PowerShell helper scripts for access bootstrap, repo sync, install, and diagnostics; Linux UTM targets continue to use the existing shell path.",
    ]
    .join("\n")
}

#[cfg(test)]
mod tests {
    use super::{
        CliCommand, PHASE6_MAX_EVIDENCE_AGE_SECS, Phase6Platform, contains_ip_rule_lookup_table,
        detect_tampered_log, execute, help_text, is_interface_absent_detail, launchd_xml_escape,
        load_dns_zone_records_manifest, load_signing_key, managed_dns_resolver_server_arg,
        managed_dns_routing_already_absent, parse_bool_value, parse_bundle_u64_field,
        parse_command, parse_managed_pf_anchors, parse_wireguard_go_pids_from_ps,
        persist_encrypted_secret_material, phase6_stage_probe_from_source,
        phase6_sync_platform_probe_from_inbox, phase6_validate_macos_start_contract_text,
        phase6_validate_platform_parity_report, read_json_value, render_launchd_plist,
        required_macos_tunnel_keychain_account, rewrite_assignment_refresh_exit_node,
        rewrite_assignment_refresh_lan_routes, rewrite_env_key_value, to_ipc_command, unix_now,
        validate_control_socket_security, write_json_pretty_file,
    };
    use rustynetd::ipc::IpcCommand;
    use serde_json::Value;
    use std::fs;

    #[test]
    fn parse_supports_phase10_route_advertise_command() {
        let command = parse_command(&[
            "route".to_string(),
            "advertise".to_string(),
            "192.168.1.0/24".to_string(),
        ]);
        assert!(format!("{command:?}").contains("RouteAdvertise"));
    }

    #[test]
    fn managed_dns_routing_already_absent_treats_missing_interface_as_idempotent() {
        assert!(managed_dns_routing_already_absent(
            "Failed to resolve interface \"rustynet0\": No such device"
        ));
        assert!(managed_dns_routing_already_absent(
            "resolvectl revert rustynet0 failed: No such device"
        ));
        assert!(!managed_dns_routing_already_absent(
            "Failed to contact systemd-resolved"
        ));
    }

    #[test]
    fn parse_supports_dns_zone_commands() {
        let issue = parse_command(&[
            "dns".to_string(),
            "zone".to_string(),
            "issue".to_string(),
            "--signing-secret".to_string(),
            "/tmp/signing.secret".to_string(),
            "--signing-secret-passphrase-file".to_string(),
            "/tmp/signing.pass".to_string(),
            "--subject-node-id".to_string(),
            "node-a".to_string(),
            "--nodes".to_string(),
            "node-a|192.0.2.1:51820|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            "--allow".to_string(),
            "node-a|node-a".to_string(),
            "--records-manifest".to_string(),
            "/tmp/dns-records.manifest".to_string(),
            "--output".to_string(),
            "/tmp/dns-zone.bundle".to_string(),
        ]);
        assert!(format!("{issue:?}").contains("DnsZoneIssue"));

        let verify = parse_command(&[
            "dns".to_string(),
            "zone".to_string(),
            "verify".to_string(),
            "--bundle".to_string(),
            "/tmp/dns-zone.bundle".to_string(),
            "--verifier-key".to_string(),
            "/tmp/dns-zone.pub".to_string(),
        ]);
        assert!(format!("{verify:?}").contains("DnsZoneVerify"));
    }

    #[test]
    fn parse_supports_signed_state_verify_commands() {
        let assignment_verify = parse_command(&[
            "assignment".to_string(),
            "verify".to_string(),
            "--bundle".to_string(),
            "/tmp/rustynetd.assignment".to_string(),
            "--verifier-key".to_string(),
            "/tmp/assignment.pub".to_string(),
            "--watermark".to_string(),
            "/tmp/rustynetd.assignment.watermark".to_string(),
        ]);
        assert!(format!("{assignment_verify:?}").contains("Verify"));

        let traversal_verify = parse_command(&[
            "traversal".to_string(),
            "verify".to_string(),
            "--bundle".to_string(),
            "/tmp/rustynetd.traversal".to_string(),
            "--verifier-key".to_string(),
            "/tmp/traversal.pub".to_string(),
            "--watermark".to_string(),
            "/tmp/rustynetd.traversal.watermark".to_string(),
        ]);
        assert!(format!("{traversal_verify:?}").contains("Traversal"));

        let trust_verify = parse_command(&[
            "trust".to_string(),
            "verify".to_string(),
            "--evidence".to_string(),
            "/tmp/rustynetd.trust".to_string(),
            "--verifier-key".to_string(),
            "/tmp/trust-evidence.pub".to_string(),
            "--watermark".to_string(),
            "/tmp/rustynetd.trust.watermark".to_string(),
        ]);
        assert!(format!("{trust_verify:?}").contains("Trust"));
    }

    #[test]
    fn parse_supports_key_commands() {
        let rotate = parse_command(&["key".to_string(), "rotate".to_string()]);
        assert!(format!("{rotate:?}").contains("KeyRotate"));

        let revoke = parse_command(&["key".to_string(), "revoke".to_string()]);
        assert!(format!("{revoke:?}").contains("KeyRevoke"));
    }

    #[test]
    fn dns_zone_records_manifest_rejects_unknown_fields() {
        let base = std::env::temp_dir().join(format!(
            "rustynet-dns-zone-records-manifest-{}-{}",
            std::process::id(),
            super::generate_assignment_nonce()
        ));
        fs::create_dir_all(&base).expect("temp dir should exist");
        let path = base.join("records.manifest");
        fs::write(
            &path,
            "version=1\nrecord_count=1\nrecord.0.label=app\nrecord.0.target_node_id=node-a\nrecord.0.ttl_secs=60\nrecord.0.alias_count=1\nrecord.0.alias.0=ssh\nrecord.0.unexpected=true\n",
        )
        .expect("records manifest should be written");
        let err = load_dns_zone_records_manifest(&path).expect_err("unknown fields must fail");
        assert!(err.contains("unsupported dns zone records manifest field"));
        let _ = fs::remove_file(path);
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn dns_zone_records_manifest_rejects_sparse_alias_indices() {
        let base = std::env::temp_dir().join(format!(
            "rustynet-dns-zone-records-manifest-sparse-{}-{}",
            std::process::id(),
            super::generate_assignment_nonce()
        ));
        fs::create_dir_all(&base).expect("temp dir should exist");
        let path = base.join("records.manifest");
        fs::write(
            &path,
            "version=1\nrecord_count=1\nrecord.0.label=app\nrecord.0.target_node_id=node-a\nrecord.0.ttl_secs=60\nrecord.0.alias_count=1\nrecord.0.alias.1=ssh\n",
        )
        .expect("records manifest should be written");
        let err =
            load_dns_zone_records_manifest(&path).expect_err("sparse alias indices must fail");
        assert!(err.contains("missing record.0.alias.0"));
        let _ = fs::remove_file(path);
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn dns_zone_records_manifest_rejects_duplicate_aliases() {
        let base = std::env::temp_dir().join(format!(
            "rustynet-dns-zone-records-manifest-duplicate-{}-{}",
            std::process::id(),
            super::generate_assignment_nonce()
        ));
        fs::create_dir_all(&base).expect("temp dir should exist");
        let path = base.join("records.manifest");
        fs::write(
            &path,
            "version=1\nrecord_count=1\nrecord.0.label=app\nrecord.0.target_node_id=node-a\nrecord.0.ttl_secs=60\nrecord.0.alias_count=2\nrecord.0.alias.0=ssh\nrecord.0.alias.1=ssh\n",
        )
        .expect("records manifest should be written");
        let err = load_dns_zone_records_manifest(&path).expect_err("duplicate aliases must fail");
        assert!(err.contains("duplicate aliases"));
        let _ = fs::remove_file(path);
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn dns_zone_records_manifest_loads_valid_manifest() {
        let base = std::env::temp_dir().join(format!(
            "rustynet-dns-zone-records-manifest-valid-{}-{}",
            std::process::id(),
            super::generate_assignment_nonce()
        ));
        fs::create_dir_all(&base).expect("temp dir should exist");
        let path = base.join("records.manifest");
        fs::write(
            &path,
            "version=1\nrecord_count=1\nrecord.0.label=App\nrecord.0.target_node_id=node-a\nrecord.0.ttl_secs=60\nrecord.0.alias_count=2\nrecord.0.alias.0=SSH\nrecord.0.alias.1=gateway\n",
        )
        .expect("records manifest should be written");
        let records = load_dns_zone_records_manifest(&path).expect("valid manifest should load");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].label, "app");
        assert_eq!(
            records[0].aliases,
            vec!["ssh".to_string(), "gateway".to_string()]
        );
        let _ = fs::remove_file(path);
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn parse_supports_phase6_parity_ops_commands() {
        let probe = parse_command(&["ops".to_string(), "collect-platform-probe".to_string()]);
        assert!(format!("{probe:?}").contains("CollectPlatformProbe"));

        let report = parse_command(&[
            "ops".to_string(),
            "generate-platform-parity-report".to_string(),
        ]);
        assert!(format!("{report:?}").contains("GeneratePlatformParityReport"));

        let bundle = parse_command(&[
            "ops".to_string(),
            "collect-platform-parity-bundle".to_string(),
        ]);
        assert!(format!("{bundle:?}").contains("CollectPlatformParityBundle"));

        let verify_readiness = parse_command(&[
            "ops".to_string(),
            "verify-phase6-platform-readiness".to_string(),
        ]);
        assert!(format!("{verify_readiness:?}").contains("VerifyPhase6PlatformReadiness"));
    }

    #[test]
    fn phase6_parity_validation_rejects_false_readiness_control() {
        let base = std::env::temp_dir().join(format!(
            "rustynet-phase6-validate-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time before unix epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).expect("create temp validation dir");

        let write_json = |path: &std::path::Path, payload: serde_json::Value| {
            let mut body = serde_json::to_string_pretty(&payload).expect("serialize json");
            body.push('\n');
            std::fs::write(path, body).expect("write json payload");
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_secs();

        let mut sources = Vec::new();
        for platform in ["linux", "macos", "windows"] {
            let source = base.join(format!("platform_parity_{platform}.json"));
            let route_ok = platform != "macos";
            write_json(
                source.as_path(),
                serde_json::json!({
                    "evidence_mode": "measured",
                    "platform": platform,
                    "route_hook_ready": route_ok,
                    "dns_hook_ready": true,
                    "firewall_hook_ready": true,
                    "leak_matrix_passed": true,
                    "probe_time_unix": now,
                    "probe_host": format!("host-{platform}"),
                    "probe_sources": {
                        "route": "route probe",
                        "dns": "dns probe",
                        "firewall": "firewall probe",
                        "leak_report": "/tmp/leak.json",
                    },
                }),
            );
            sources.push(source.display().to_string());
        }

        let report_path = base.join("platform_parity_report.json");
        write_json(
            report_path.as_path(),
            serde_json::json!({
                "evidence_mode": "measured",
                "captured_at_unix": now,
                "environment": "ci",
                "source_artifacts": sources,
                "platform_results": [
                    {"platform": "linux", "route_hook_ready": true, "dns_hook_ready": true, "firewall_hook_ready": true, "leak_matrix_passed": true},
                    {"platform": "macos", "route_hook_ready": false, "dns_hook_ready": true, "firewall_hook_ready": true, "leak_matrix_passed": true},
                    {"platform": "windows", "route_hook_ready": true, "dns_hook_ready": true, "firewall_hook_ready": true, "leak_matrix_passed": true}
                ],
            }),
        );

        let error = phase6_validate_platform_parity_report(report_path.as_path())
            .expect_err("expected fail-closed parity validation error");
        assert!(error.contains("route_hook_ready must be true"));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn phase6_sync_platform_probe_from_inbox_prefers_fresh_inbox_over_stale_raw() {
        let base = std::env::temp_dir().join(format!(
            "rustynet-phase6-sync-fresh-inbox-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time before unix epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).expect("create temp dir");
        let raw_path = base.join("platform_parity_linux.json");
        let inbox_path = base.join("platform_parity_linux.inbox.json");
        let now = unix_now();
        let stale_probe_time = now.saturating_sub(PHASE6_MAX_EVIDENCE_AGE_SECS + 10);
        let fresh_probe_time = now.saturating_sub(5);

        write_json_pretty_file(
            raw_path.as_path(),
            &serde_json::json!({
                "evidence_mode": "measured",
                "platform": "linux",
                "route_hook_ready": true,
                "dns_hook_ready": true,
                "firewall_hook_ready": true,
                "leak_matrix_passed": true,
                "probe_time_unix": stale_probe_time,
                "probe_host": "stale-linux-host",
                "probe_sources": {
                    "route": "ip -o route show default",
                    "dns": "resolvectl status",
                    "firewall": "nft list tables",
                    "leak_report": "artifacts/phase10/leak_test_report.json",
                },
            }),
        )
        .expect("write stale raw probe");
        write_json_pretty_file(
            inbox_path.as_path(),
            &serde_json::json!({
                "evidence_mode": "measured",
                "platform": "linux",
                "route_hook_ready": true,
                "dns_hook_ready": true,
                "firewall_hook_ready": true,
                "leak_matrix_passed": true,
                "probe_time_unix": fresh_probe_time,
                "probe_host": "fresh-linux-host",
                "probe_sources": {
                    "route": "ip -o route show default",
                    "dns": "resolvectl status",
                    "firewall": "nft list tables",
                    "leak_report": "artifacts/phase10/leak_test_report.json",
                },
            }),
        )
        .expect("write inbox probe");

        phase6_sync_platform_probe_from_inbox(
            Phase6Platform::Linux,
            raw_path.as_path(),
            inbox_path.as_path(),
            now,
        )
        .expect("fresh inbox probe should replace stale raw probe");

        let synced = read_json_value(raw_path.as_path(), "synced parity probe")
            .expect("synced raw probe should be readable");
        assert_eq!(
            synced
                .get("probe_host")
                .and_then(Value::as_str)
                .expect("probe_host should exist"),
            "fresh-linux-host"
        );
        assert_eq!(
            synced
                .get("probe_time_unix")
                .and_then(Value::as_u64)
                .expect("probe_time_unix should exist"),
            fresh_probe_time
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn phase6_sync_platform_probe_from_inbox_keeps_fresh_raw_when_inbox_is_stale() {
        let base = std::env::temp_dir().join(format!(
            "rustynet-phase6-sync-keep-raw-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time before unix epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).expect("create temp dir");
        let raw_path = base.join("platform_parity_windows.json");
        let inbox_path = base.join("platform_parity_windows.inbox.json");
        let now = unix_now();
        let fresh_probe_time = now.saturating_sub(5);
        let stale_probe_time = now.saturating_sub(PHASE6_MAX_EVIDENCE_AGE_SECS + 10);

        write_json_pretty_file(
            raw_path.as_path(),
            &serde_json::json!({
                "evidence_mode": "measured",
                "platform": "windows",
                "route_hook_ready": true,
                "dns_hook_ready": true,
                "firewall_hook_ready": true,
                "leak_matrix_passed": true,
                "probe_time_unix": fresh_probe_time,
                "probe_host": "fresh-windows-host",
                "probe_sources": {
                    "route": "powershell.exe Get-NetRoute",
                    "dns": "powershell.exe Get-DnsClientServerAddress",
                    "firewall": "powershell.exe Get-NetFirewallProfile",
                    "leak_report": "artifacts/phase10/leak_test_report.json",
                },
            }),
        )
        .expect("write fresh raw probe");
        write_json_pretty_file(
            inbox_path.as_path(),
            &serde_json::json!({
                "evidence_mode": "measured",
                "platform": "windows",
                "route_hook_ready": true,
                "dns_hook_ready": true,
                "firewall_hook_ready": true,
                "leak_matrix_passed": true,
                "probe_time_unix": stale_probe_time,
                "probe_host": "stale-windows-host",
                "probe_sources": {
                    "route": "powershell.exe Get-NetRoute",
                    "dns": "powershell.exe Get-DnsClientServerAddress",
                    "firewall": "powershell.exe Get-NetFirewallProfile",
                    "leak_report": "artifacts/phase10/leak_test_report.json",
                },
            }),
        )
        .expect("write stale inbox probe");

        phase6_sync_platform_probe_from_inbox(
            Phase6Platform::Windows,
            raw_path.as_path(),
            inbox_path.as_path(),
            now,
        )
        .expect("stale inbox probe must not override fresh raw probe");

        let synced = read_json_value(raw_path.as_path(), "synced parity probe")
            .expect("raw probe should still be readable");
        assert_eq!(
            synced
                .get("probe_host")
                .and_then(Value::as_str)
                .expect("probe_host should exist"),
            "fresh-windows-host"
        );
        assert_eq!(
            synced
                .get("probe_time_unix")
                .and_then(Value::as_u64)
                .expect("probe_time_unix should exist"),
            fresh_probe_time
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn phase6_stage_probe_from_source_rejects_stale_probe() {
        let base = std::env::temp_dir().join(format!(
            "rustynet-phase6-stage-stale-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time before unix epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).expect("create temp dir");
        let source_path = base.join("platform_parity_windows.source.json");
        let inbox_path = base.join("platform_parity_windows.inbox.json");
        let now = unix_now();
        let stale_probe_time = now.saturating_sub(PHASE6_MAX_EVIDENCE_AGE_SECS + 10);

        write_json_pretty_file(
            source_path.as_path(),
            &serde_json::json!({
                "evidence_mode": "measured",
                "platform": "windows",
                "route_hook_ready": true,
                "dns_hook_ready": true,
                "firewall_hook_ready": true,
                "leak_matrix_passed": true,
                "probe_time_unix": stale_probe_time,
                "probe_host": "stale-windows-host",
                "probe_sources": {
                    "route": "powershell.exe Get-NetRoute",
                    "dns": "powershell.exe Get-DnsClientServerAddress",
                    "firewall": "powershell.exe Get-NetFirewallProfile",
                    "leak_report": "C:/Temp/leak_test_report.json",
                },
            }),
        )
        .expect("write stale probe");

        let error = phase6_stage_probe_from_source(
            Phase6Platform::Windows,
            source_path.as_path(),
            inbox_path.as_path(),
            now,
        )
        .expect_err("stale external probe must be rejected");
        assert!(error.contains("stale"));
        assert!(!inbox_path.exists());

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn phase6_stage_probe_from_source_writes_fresh_probe_to_inbox() {
        let base = std::env::temp_dir().join(format!(
            "rustynet-phase6-stage-fresh-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time before unix epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).expect("create temp dir");
        let source_path = base.join("platform_parity_windows.source.json");
        let inbox_path = base.join("platform_parity_windows.inbox.json");
        let now = unix_now();
        let fresh_probe_time = now.saturating_sub(5);

        write_json_pretty_file(
            source_path.as_path(),
            &serde_json::json!({
                "evidence_mode": "measured",
                "platform": "windows",
                "route_hook_ready": true,
                "dns_hook_ready": true,
                "firewall_hook_ready": true,
                "leak_matrix_passed": true,
                "probe_time_unix": fresh_probe_time,
                "probe_host": "fresh-windows-host",
                "probe_sources": {
                    "route": "powershell.exe Get-NetRoute",
                    "dns": "powershell.exe Get-DnsClientServerAddress",
                    "firewall": "powershell.exe Get-NetFirewallProfile",
                    "leak_report": "C:/Temp/leak_test_report.json",
                },
            }),
        )
        .expect("write fresh probe");

        phase6_stage_probe_from_source(
            Phase6Platform::Windows,
            source_path.as_path(),
            inbox_path.as_path(),
            now,
        )
        .expect("fresh external probe must be staged");

        let staged = read_json_value(inbox_path.as_path(), "staged parity probe")
            .expect("staged probe should be readable");
        assert_eq!(
            staged
                .get("probe_host")
                .and_then(Value::as_str)
                .expect("probe_host should exist"),
            "fresh-windows-host"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn phase6_sync_platform_probe_from_inbox_rejects_future_dated_probe() {
        let base = std::env::temp_dir().join(format!(
            "rustynet-phase6-sync-future-inbox-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time before unix epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).expect("create temp dir");
        let raw_path = base.join("platform_parity_windows.json");
        let inbox_path = base.join("platform_parity_windows.inbox.json");
        let now = unix_now();
        let future_probe_time = now.saturating_add(301);

        write_json_pretty_file(
            inbox_path.as_path(),
            &serde_json::json!({
                "evidence_mode": "measured",
                "platform": "windows",
                "route_hook_ready": true,
                "dns_hook_ready": true,
                "firewall_hook_ready": true,
                "leak_matrix_passed": true,
                "probe_time_unix": future_probe_time,
                "probe_host": "future-windows-host",
                "probe_sources": {
                    "route": "powershell.exe Get-NetRoute",
                    "dns": "powershell.exe Get-DnsClientServerAddress",
                    "firewall": "powershell.exe Get-NetFirewallProfile",
                    "leak_report": "C:/Temp/leak_test_report.json",
                },
            }),
        )
        .expect("write future probe");

        let error = phase6_sync_platform_probe_from_inbox(
            Phase6Platform::Windows,
            raw_path.as_path(),
            inbox_path.as_path(),
            now,
        )
        .expect_err("future-dated probe must be rejected");
        assert!(error.contains("too far in the future"));

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn phase6_macos_start_contract_matches_current_hardened_path() {
        let start_sh = include_str!("../../../start.sh");
        phase6_validate_macos_start_contract_text(start_sh)
            .expect("current start.sh must satisfy macOS hardened contract");
    }

    #[test]
    fn parse_supports_operator_menu_command() {
        let menu = parse_command(&["operator".to_string(), "menu".to_string()]);
        assert!(format!("{menu:?}").contains("OperatorMenu"));
    }

    #[test]
    fn parse_supports_membership_commands() {
        let command = parse_command(&[
            "membership".to_string(),
            "status".to_string(),
            "--snapshot".to_string(),
            "/tmp/membership.snapshot".to_string(),
            "--log".to_string(),
            "/tmp/membership.log".to_string(),
        ]);
        assert!(format!("{command:?}").contains("Membership"));
    }

    #[test]
    fn parse_supports_membership_evidence_generation() {
        let command = parse_command(&[
            "membership".to_string(),
            "generate-evidence".to_string(),
            "--output-dir".to_string(),
            "artifacts/membership".to_string(),
            "--environment".to_string(),
            "ci-netns".to_string(),
        ]);
        assert!(format!("{command:?}").contains("GenerateEvidence"));
    }

    #[test]
    fn parse_supports_assignment_issue_command() {
        let command = parse_command(&[
            "assignment".to_string(),
            "issue".to_string(),
            "--target-node-id".to_string(),
            "client-40".to_string(),
            "--nodes".to_string(),
            "client-40|192.0.2.40:51820|11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff;exit-37|192.0.2.37:51820|aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899".to_string(),
            "--allow".to_string(),
            "client-40|exit-37".to_string(),
            "--signing-secret".to_string(),
            "/tmp/assignment.secret".to_string(),
            "--signing-secret-passphrase-file".to_string(),
            "/tmp/signing.passphrase".to_string(),
            "--output".to_string(),
            "/tmp/assignment.bundle".to_string(),
        ]);
        assert!(format!("{command:?}").contains("Assignment"));
    }

    #[test]
    fn parse_supports_ops_commands() {
        let trust = parse_command(&["ops".to_string(), "refresh-trust".to_string()]);
        assert!(format!("{trust:?}").contains("RefreshTrust"));

        let verify_runtime_binary_custody = parse_command(&[
            "ops".to_string(),
            "verify-runtime-binary-custody".to_string(),
        ]);
        assert!(
            format!("{verify_runtime_binary_custody:?}").contains("VerifyRuntimeBinaryCustody")
        );

        let signed_trust = parse_command(&["ops".to_string(), "refresh-signed-trust".to_string()]);
        assert!(format!("{signed_trust:?}").contains("RefreshSignedTrust"));

        let bootstrap_wg =
            parse_command(&["ops".to_string(), "bootstrap-wireguard-custody".to_string()]);
        assert!(format!("{bootstrap_wg:?}").contains("BootstrapTunnelCustody"));

        let assignment = parse_command(&["ops".to_string(), "refresh-assignment".to_string()]);
        assert!(format!("{assignment:?}").contains("RefreshAssignment"));

        let collect_phase1 = parse_command(&[
            "ops".to_string(),
            "collect-phase1-measured-input".to_string(),
        ]);
        assert!(format!("{collect_phase1:?}").contains("CollectPhase1MeasuredInput"));

        let run_phase1 = parse_command(&["ops".to_string(), "run-phase1-baseline".to_string()]);
        assert!(format!("{run_phase1:?}").contains("RunPhase1Baseline"));

        let prepare_advisory_db = parse_command(&[
            "ops".to_string(),
            "prepare-advisory-db".to_string(),
            "/tmp/rustynet-advisory-db".to_string(),
        ]);
        assert!(format!("{prepare_advisory_db:?}").contains("PrepareAdvisoryDb"));

        let check_no_unsafe = parse_command(&[
            "ops".to_string(),
            "check-no-unsafe-rust-sources".to_string(),
            "--root".to_string(),
            "crates".to_string(),
        ]);
        assert!(format!("{check_no_unsafe:?}").contains("CheckNoUnsafeRustSources"));

        let check_dependency_exceptions = parse_command(&[
            "ops".to_string(),
            "check-dependency-exceptions".to_string(),
            "--path".to_string(),
            "documents/operations/dependency_exceptions.json".to_string(),
        ]);
        assert!(format!("{check_dependency_exceptions:?}").contains("CheckDependencyExceptions"));

        let check_perf_regression = parse_command(&[
            "ops".to_string(),
            "check-perf-regression".to_string(),
            "--phase1-report".to_string(),
            "artifacts/perf/phase1/baseline.json".to_string(),
            "--phase3-report".to_string(),
            "artifacts/perf/phase3/mesh_baseline.json".to_string(),
        ]);
        assert!(format!("{check_perf_regression:?}").contains("CheckPerfRegression"));

        let check_secrets_hygiene = parse_command(&[
            "ops".to_string(),
            "check-secrets-hygiene".to_string(),
            "--root".to_string(),
            ".".to_string(),
        ]);
        assert!(format!("{check_secrets_hygiene:?}").contains("CheckSecretsHygiene"));

        let collect_phase9_raw =
            parse_command(&["ops".to_string(), "collect-phase9-raw-evidence".to_string()]);
        assert!(format!("{collect_phase9_raw:?}").contains("CollectPhase9RawEvidence"));

        let generate_phase9 =
            parse_command(&["ops".to_string(), "generate-phase9-artifacts".to_string()]);
        assert!(format!("{generate_phase9:?}").contains("GeneratePhase9Artifacts"));

        let verify_phase9_readiness =
            parse_command(&["ops".to_string(), "verify-phase9-readiness".to_string()]);
        assert!(format!("{verify_phase9_readiness:?}").contains("VerifyPhase9Readiness"));

        let verify_phase9 =
            parse_command(&["ops".to_string(), "verify-phase9-evidence".to_string()]);
        assert!(format!("{verify_phase9:?}").contains("VerifyPhase9Evidence"));

        let generate_phase10 =
            parse_command(&["ops".to_string(), "generate-phase10-artifacts".to_string()]);
        assert!(format!("{generate_phase10:?}").contains("GeneratePhase10Artifacts"));

        let verify_phase10_readiness =
            parse_command(&["ops".to_string(), "verify-phase10-readiness".to_string()]);
        assert!(format!("{verify_phase10_readiness:?}").contains("VerifyPhase10Readiness"));

        let verify_phase10_provenance =
            parse_command(&["ops".to_string(), "verify-phase10-provenance".to_string()]);
        assert!(format!("{verify_phase10_provenance:?}").contains("VerifyPhase10Provenance"));

        let write_phase10_hp2_reports = parse_command(&[
            "ops".to_string(),
            "write-phase10-hp2-traversal-reports".to_string(),
            "--source-dir".to_string(),
            "artifacts/phase10/source".to_string(),
            "--environment".to_string(),
            "ci".to_string(),
            "--path-selection-log".to_string(),
            "artifacts/phase10/source/traversal_path_selection_tests.log".to_string(),
            "--probe-security-log".to_string(),
            "artifacts/phase10/source/traversal_probe_security_tests.log".to_string(),
        ]);
        assert!(
            format!("{write_phase10_hp2_reports:?}").contains("WritePhase10Hp2TraversalReports")
        );

        let verify_phase6_platform_readiness = parse_command(&[
            "ops".to_string(),
            "verify-phase6-platform-readiness".to_string(),
        ]);
        assert!(
            format!("{verify_phase6_platform_readiness:?}")
                .contains("VerifyPhase6PlatformReadiness")
        );

        let verify_phase6_parity = parse_command(&[
            "ops".to_string(),
            "verify-phase6-parity-evidence".to_string(),
        ]);
        assert!(format!("{verify_phase6_parity:?}").contains("VerifyPhase6ParityEvidence"));

        let verify_required_test_output = parse_command(&[
            "ops".to_string(),
            "verify-required-test-output".to_string(),
            "--output".to_string(),
            "/tmp/rustynet-required-test.log".to_string(),
            "--package".to_string(),
            "rustynetd".to_string(),
            "--test-filter".to_string(),
            "daemon::tests::sample".to_string(),
        ]);
        assert!(format!("{verify_required_test_output:?}").contains("VerifyRequiredTestOutput"));

        let generate_cross_network_report = parse_command(&[
            "ops".to_string(),
            "generate-cross-network-remote-exit-report".to_string(),
            "--suite".to_string(),
            "cross_network_direct_remote_exit".to_string(),
            "--report-path".to_string(),
            "artifacts/phase10/cross_network_direct_remote_exit_report.json".to_string(),
            "--log-path".to_string(),
            "artifacts/phase10/source/cross_network_direct_remote_exit.log".to_string(),
            "--status".to_string(),
            "fail".to_string(),
            "--path-status-line".to_string(),
            "node_id=client-1 path_mode=direct_active path_programmed_mode=direct_programmed path_live_proven=true path_latest_live_handshake_unix=123 relay_session_state=unused".to_string(),
            "--path-evidence-report".to_string(),
            "artifacts/phase10/child_report.json".to_string(),
            "--source-artifact".to_string(),
            "scripts/e2e/live_linux_cross_network_direct_remote_exit_test.sh".to_string(),
            "--source-artifact".to_string(),
            "artifacts/phase10/some-extra-source.txt".to_string(),
            "--check".to_string(),
            "direct_remote_exit_success=pass".to_string(),
            "--check".to_string(),
            "remote_exit_no_underlay_leak=fail".to_string(),
        ]);
        assert!(
            format!("{generate_cross_network_report:?}")
                .contains("GenerateCrossNetworkRemoteExitReport")
        );
        assert!(
            format!("{generate_cross_network_report:?}").contains("path_status_line: Some"),
            "{generate_cross_network_report:?}"
        );
        assert!(
            format!("{generate_cross_network_report:?}")
                .contains("path_evidence_report: Some(\"artifacts/phase10/child_report.json\")"),
            "{generate_cross_network_report:?}"
        );

        let validate_cross_network_reports = parse_command(&[
            "ops".to_string(),
            "validate-cross-network-remote-exit-reports".to_string(),
            "--artifact-dir".to_string(),
            "artifacts/phase10".to_string(),
            "--max-evidence-age-seconds".to_string(),
            "600".to_string(),
            "--expected-git-commit".to_string(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            "--require-pass-status".to_string(),
        ]);
        assert!(
            format!("{validate_cross_network_reports:?}")
                .contains("ValidateCrossNetworkRemoteExitReports")
        );

        let validate_cross_network_nat_matrix = parse_command(&[
            "ops".to_string(),
            "validate-cross-network-nat-matrix".to_string(),
            "--artifact-dir".to_string(),
            "artifacts/phase10".to_string(),
            "--required-nat-profiles".to_string(),
            "baseline_lan,hard_nat".to_string(),
            "--max-evidence-age-seconds".to_string(),
            "600".to_string(),
            "--expected-git-commit".to_string(),
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
            "--require-pass-status".to_string(),
        ]);
        assert!(
            format!("{validate_cross_network_nat_matrix:?}")
                .contains("ValidateCrossNetworkNatMatrix")
        );

        let read_cross_network_report_fields = parse_command(&[
            "ops".to_string(),
            "read-cross-network-report-fields".to_string(),
            "--report-path".to_string(),
            "artifacts/phase10/cross_network_direct_remote_exit_report.json".to_string(),
            "--include-status".to_string(),
            "--check".to_string(),
            "direct_remote_exit_success".to_string(),
            "--network-field".to_string(),
            "client_underlay_ip".to_string(),
            "--default-value".to_string(),
            "unknown".to_string(),
        ]);
        assert!(
            format!("{read_cross_network_report_fields:?}")
                .contains("ReadCrossNetworkReportFields")
        );

        let classify_cross_network_topology = parse_command(&[
            "ops".to_string(),
            "classify-cross-network-topology".to_string(),
            "--ip-a".to_string(),
            "192.0.2.10".to_string(),
            "--ip-b".to_string(),
            "192.0.3.10".to_string(),
            "--ipv4-prefix".to_string(),
            "24".to_string(),
            "--ipv6-prefix".to_string(),
            "64".to_string(),
        ]);
        assert!(
            format!("{classify_cross_network_topology:?}").contains("ClassifyCrossNetworkTopology")
        );

        let choose_cross_network_roam_alias = parse_command(&[
            "ops".to_string(),
            "choose-cross-network-roam-alias".to_string(),
            "--exit-ip".to_string(),
            "192.0.2.10".to_string(),
            "--used-ip".to_string(),
            "192.0.2.11".to_string(),
            "--used-ip".to_string(),
            "192.0.2.12".to_string(),
            "--ipv4-prefix".to_string(),
            "24".to_string(),
            "--ipv6-prefix".to_string(),
            "64".to_string(),
        ]);
        assert!(
            format!("{choose_cross_network_roam_alias:?}").contains("ChooseCrossNetworkRoamAlias")
        );

        let validate_ipv4_address = parse_command(&[
            "ops".to_string(),
            "validate-ipv4-address".to_string(),
            "--ip".to_string(),
            "203.0.113.10".to_string(),
        ]);
        assert!(format!("{validate_ipv4_address:?}").contains("ValidateIpv4Address"));

        let write_cross_network_soak_monitor_summary = parse_command(&[
            "ops".to_string(),
            "write-cross-network-soak-monitor-summary".to_string(),
            "--path".to_string(),
            "artifacts/phase10/source/cross_network_remote_exit_soak_monitor_summary.json"
                .to_string(),
            "--samples".to_string(),
            "100".to_string(),
            "--failing-samples".to_string(),
            "0".to_string(),
            "--max-consecutive-failures-observed".to_string(),
            "0".to_string(),
            "--elapsed-secs".to_string(),
            "600".to_string(),
            "--required-soak-duration-secs".to_string(),
            "600".to_string(),
            "--allowed-failing-samples".to_string(),
            "2".to_string(),
            "--allowed-max-consecutive-failures".to_string(),
            "1".to_string(),
            "--direct-remote-exit-ready".to_string(),
            "pass".to_string(),
            "--post-soak-bypass-ready".to_string(),
            "pass".to_string(),
            "--no-plaintext-passphrase-files".to_string(),
            "pass".to_string(),
            "--direct-samples".to_string(),
            "100".to_string(),
            "--relay-samples".to_string(),
            "0".to_string(),
            "--fail-closed-samples".to_string(),
            "0".to_string(),
            "--other-path-samples".to_string(),
            "0".to_string(),
            "--path-transition-count".to_string(),
            "0".to_string(),
            "--status-mismatch-samples".to_string(),
            "0".to_string(),
            "--route-mismatch-samples".to_string(),
            "0".to_string(),
            "--endpoint-mismatch-samples".to_string(),
            "0".to_string(),
            "--dns-alarm-bad-samples".to_string(),
            "0".to_string(),
            "--transport-identity-failures".to_string(),
            "0".to_string(),
            "--endpoint-change-events-start".to_string(),
            "1".to_string(),
            "--endpoint-change-events-end".to_string(),
            "1".to_string(),
            "--endpoint-change-events-delta".to_string(),
            "0".to_string(),
            "--first-non-direct-reason".to_string(),
            "none".to_string(),
            "--last-path-mode".to_string(),
            "direct_active".to_string(),
            "--last-path-reason".to_string(),
            "fresh_handshake_observed".to_string(),
            "--first-failure-reason".to_string(),
            "none".to_string(),
            "--long-soak-stable".to_string(),
            "pass".to_string(),
        ]);
        assert!(
            format!("{write_cross_network_soak_monitor_summary:?}")
                .contains("WriteCrossNetworkSoakMonitorSummary")
        );

        let check_local_file_mode = parse_command(&[
            "ops".to_string(),
            "check-local-file-mode".to_string(),
            "--path".to_string(),
            "/tmp/known_hosts".to_string(),
            "--policy".to_string(),
            "no-group-world-write".to_string(),
            "--label".to_string(),
            "pinned SSH known_hosts file".to_string(),
        ]);
        assert!(format!("{check_local_file_mode:?}").contains("CheckLocalFileMode"));

        let redact_forensics_text =
            parse_command(&["ops".to_string(), "redact-forensics-text".to_string()]);
        assert!(format!("{redact_forensics_text:?}").contains("RedactForensicsText"));

        let write_cross_network_forensics_manifest = parse_command(&[
            "ops".to_string(),
            "write-cross-network-forensics-manifest".to_string(),
            "--stage".to_string(),
            "cross_network_direct_remote_exit".to_string(),
            "--collected-at-utc".to_string(),
            "20260321T100000Z".to_string(),
            "--stage-dir".to_string(),
            "artifacts/phase10/forensics".to_string(),
            "--output".to_string(),
            "artifacts/phase10/forensics/manifest.json".to_string(),
        ]);
        assert!(
            format!("{write_cross_network_forensics_manifest:?}")
                .contains("WriteCrossNetworkForensicsManifest")
        );

        let write_live_lab_stage_artifact_index = parse_command(&[
            "ops".to_string(),
            "write-live-lab-stage-artifact-index".to_string(),
            "--stage-name".to_string(),
            "cross_network_direct_remote_exit".to_string(),
            "--stage-dir".to_string(),
            "artifacts/live_lab/forensics/cross_network_direct_remote_exit".to_string(),
            "--output".to_string(),
            "artifacts/live_lab/forensics/cross_network_direct_remote_exit/artifact_index.json"
                .to_string(),
        ]);
        assert!(
            format!("{write_live_lab_stage_artifact_index:?}")
                .contains("WriteLiveLabStageArtifactIndex")
        );

        let sha256_file = parse_command(&[
            "ops".to_string(),
            "sha256-file".to_string(),
            "--path".to_string(),
            "artifacts/phase10/discovery-a.json".to_string(),
        ]);
        assert!(format!("{sha256_file:?}").contains("Sha256File"));

        let validate_cross_network_forensics_bundle = parse_command(&[
            "ops".to_string(),
            "validate-cross-network-forensics-bundle".to_string(),
            "--stage-name".to_string(),
            "cross_network_direct_remote_exit".to_string(),
            "--nodes-tsv".to_string(),
            "artifacts/live_lab/state/nodes.tsv".to_string(),
            "--stage-dir".to_string(),
            "artifacts/live_lab/forensics/cross_network_direct_remote_exit".to_string(),
            "--output".to_string(),
            "artifacts/live_lab/forensics/cross_network_direct_remote_exit/bundle_validation.json"
                .to_string(),
        ]);
        assert!(
            format!("{validate_cross_network_forensics_bundle:?}")
                .contains("ValidateCrossNetworkForensicsBundle")
        );

        let write_cross_network_preflight_report = parse_command(&[
            "ops".to_string(),
            "write-cross-network-preflight-report".to_string(),
            "--nodes-tsv".to_string(),
            "artifacts/live_lab/state/nodes.tsv".to_string(),
            "--stage-dir".to_string(),
            "artifacts/live_lab/parallel-cross-network-preflight".to_string(),
            "--output".to_string(),
            "artifacts/live_lab/cross_network_preflight_report.json".to_string(),
            "--reference-unix".to_string(),
            "1772984762".to_string(),
            "--max-clock-skew-secs".to_string(),
            "10".to_string(),
            "--discovery-max-age-secs".to_string(),
            "900".to_string(),
            "--signed-artifact-max-age-secs".to_string(),
            "900".to_string(),
        ]);
        assert!(
            format!("{write_cross_network_preflight_report:?}")
                .contains("WriteCrossNetworkPreflightReport")
        );

        let write_live_linux_reboot_recovery_report = parse_command(&[
            "ops".to_string(),
            "write-live-linux-reboot-recovery-report".to_string(),
            "--report-path".to_string(),
            "artifacts/live_lab/live_linux_reboot_recovery_report.json".to_string(),
            "--observations-path".to_string(),
            "artifacts/live_lab/live_linux_reboot_recovery_observations.txt".to_string(),
            "--exit-pre".to_string(),
            "a".to_string(),
            "--exit-post".to_string(),
            "b".to_string(),
            "--client-pre".to_string(),
            "c".to_string(),
            "--client-post".to_string(),
            "d".to_string(),
            "--exit-return".to_string(),
            "pass".to_string(),
            "--exit-boot-change".to_string(),
            "pass".to_string(),
            "--post-exit-dns-refresh".to_string(),
            "pass".to_string(),
            "--post-exit-twohop".to_string(),
            "pass".to_string(),
            "--client-return".to_string(),
            "pass".to_string(),
            "--client-boot-change".to_string(),
            "pass".to_string(),
            "--post-client-dns-refresh".to_string(),
            "pass".to_string(),
            "--post-client-twohop".to_string(),
            "pass".to_string(),
            "--salvage-twohop".to_string(),
            "skipped".to_string(),
        ]);
        assert!(
            format!("{write_live_linux_reboot_recovery_report:?}")
                .contains("WriteLiveLinuxRebootRecoveryReport")
        );

        let write_live_linux_lab_run_summary = parse_command(&[
            "ops".to_string(),
            "write-live-linux-lab-run-summary".to_string(),
            "--nodes-tsv".to_string(),
            "artifacts/live_lab/state/nodes.tsv".to_string(),
            "--stages-tsv".to_string(),
            "artifacts/live_lab/state/stages.tsv".to_string(),
            "--summary-json".to_string(),
            "artifacts/live_lab/run_summary.json".to_string(),
            "--summary-md".to_string(),
            "artifacts/live_lab/run_summary.md".to_string(),
            "--run-id".to_string(),
            "20260321T100000Z".to_string(),
            "--network-id".to_string(),
            "lab-net".to_string(),
            "--report-dir".to_string(),
            "artifacts/live_lab".to_string(),
            "--overall-status".to_string(),
            "pass".to_string(),
            "--started-at-local".to_string(),
            "2026-03-21 10:00:00 UTC".to_string(),
            "--started-at-utc".to_string(),
            "2026-03-21T10:00:00Z".to_string(),
            "--started-at-unix".to_string(),
            "1772983200".to_string(),
            "--finished-at-local".to_string(),
            "2026-03-21 10:10:00 UTC".to_string(),
            "--finished-at-utc".to_string(),
            "2026-03-21T10:10:00Z".to_string(),
            "--finished-at-unix".to_string(),
            "1772983800".to_string(),
            "--elapsed-secs".to_string(),
            "600".to_string(),
            "--elapsed-human".to_string(),
            "10m 0s".to_string(),
        ]);
        assert!(
            format!("{write_live_linux_lab_run_summary:?}").contains("WriteLiveLinuxLabRunSummary")
        );

        let scan_ipv4_port_range = parse_command(&[
            "ops".to_string(),
            "scan-ipv4-port-range".to_string(),
            "--network-prefix".to_string(),
            "192.168.18".to_string(),
            "--start-host".to_string(),
            "1".to_string(),
            "--end-host".to_string(),
            "254".to_string(),
            "--port".to_string(),
            "22".to_string(),
            "--timeout-ms".to_string(),
            "80".to_string(),
            "--output-key".to_string(),
            "ssh_port22_hosts=".to_string(),
        ]);
        assert!(format!("{scan_ipv4_port_range:?}").contains("ScanIpv4PortRange"));

        let update_role_switch_host_result = parse_command(&[
            "ops".to_string(),
            "update-role-switch-host-result".to_string(),
            "--hosts-json-path".to_string(),
            "artifacts/phase10/role_switch_hosts.json".to_string(),
            "--os-id".to_string(),
            "debian13".to_string(),
            "--temp-role".to_string(),
            "admin".to_string(),
            "--switch-execution".to_string(),
            "pass".to_string(),
            "--post-switch-reconcile".to_string(),
            "pass".to_string(),
            "--policy-still-enforced".to_string(),
            "pass".to_string(),
            "--least-privilege-preserved".to_string(),
            "pass".to_string(),
        ]);
        assert!(
            format!("{update_role_switch_host_result:?}").contains("UpdateRoleSwitchHostResult")
        );

        let write_role_switch_matrix_report = parse_command(&[
            "ops".to_string(),
            "write-role-switch-matrix-report".to_string(),
            "--hosts-json-path".to_string(),
            "artifacts/phase10/role_switch_hosts.json".to_string(),
            "--report-path".to_string(),
            "artifacts/phase10/role_switch_matrix_report.json".to_string(),
            "--source-path".to_string(),
            "artifacts/phase10/source/role_switch_matrix.md".to_string(),
            "--git-commit".to_string(),
            "abcdefabcdefabcdefabcdefabcdefabcdefabcd".to_string(),
            "--captured-at-unix".to_string(),
            "1772983200".to_string(),
            "--overall-status".to_string(),
            "pass".to_string(),
        ]);
        assert!(
            format!("{write_role_switch_matrix_report:?}").contains("WriteRoleSwitchMatrixReport")
        );

        let write_live_linux_server_ip_bypass_report = parse_command(&[
            "ops".to_string(),
            "write-live-linux-server-ip-bypass-report".to_string(),
            "--report-path".to_string(),
            "artifacts/phase10/live_linux_server_ip_bypass_report.json".to_string(),
            "--allowed-management-cidrs".to_string(),
            "192.168.18.0/24".to_string(),
            "--probe-from-client-status".to_string(),
            "pass".to_string(),
            "--probe-ip".to_string(),
            "192.168.18.51".to_string(),
            "--probe-port".to_string(),
            "18080".to_string(),
            "--client-internet-route".to_string(),
            "1.1.1.1 dev rustynet0".to_string(),
            "--client-probe-route".to_string(),
            "192.168.18.51 dev enp0s3".to_string(),
            "--client-table-51820".to_string(),
            "default dev rustynet0".to_string(),
            "--client-endpoints".to_string(),
            "peer=192.168.18.51:51820".to_string(),
            "--probe-self-test".to_string(),
            "probe-ok".to_string(),
            "--probe-from-client-output".to_string(),
            "blocked".to_string(),
        ]);
        assert!(
            format!("{write_live_linux_server_ip_bypass_report:?}")
                .contains("WriteLiveLinuxServerIpBypassReport")
        );

        let write_live_linux_control_surface_report = parse_command(&[
            "ops".to_string(),
            "write-live-linux-control-surface-report".to_string(),
            "--report-path".to_string(),
            "artifacts/phase10/live_linux_control_surface_exposure_report.json".to_string(),
            "--dns-bind-addr".to_string(),
            "127.0.0.1:53535".to_string(),
            "--remote-dns-probe-status".to_string(),
            "pass".to_string(),
            "--remote-dns-probe-output".to_string(),
            "{}".to_string(),
            "--work-dir".to_string(),
            "artifacts/phase10/source/control_surface".to_string(),
            "--host-label".to_string(),
            "client".to_string(),
            "--host-label".to_string(),
            "exit".to_string(),
        ]);
        assert!(
            format!("{write_live_linux_control_surface_report:?}")
                .contains("WriteLiveLinuxControlSurfaceReport")
        );

        let rewrite_assignment_peer_endpoint_ip = parse_command(&[
            "ops".to_string(),
            "rewrite-assignment-peer-endpoint-ip".to_string(),
            "--assignment-path".to_string(),
            "/var/lib/rustynet/rustynetd.assignment".to_string(),
            "--endpoint-ip".to_string(),
            "203.0.113.10".to_string(),
        ]);
        assert!(
            format!("{rewrite_assignment_peer_endpoint_ip:?}")
                .contains("RewriteAssignmentPeerEndpointIp")
        );

        let rewrite_assignment_mesh_cidr = parse_command(&[
            "ops".to_string(),
            "rewrite-assignment-mesh-cidr".to_string(),
            "--assignment-path".to_string(),
            "/var/lib/rustynet/rustynetd.assignment".to_string(),
            "--mesh-cidr".to_string(),
            "100.65.0.0/10".to_string(),
        ]);
        assert!(format!("{rewrite_assignment_mesh_cidr:?}").contains("RewriteAssignmentMeshCidr"));

        let write_live_linux_endpoint_hijack_report = parse_command(&[
            "ops".to_string(),
            "write-live-linux-endpoint-hijack-report".to_string(),
            "--report-path".to_string(),
            "artifacts/phase10/live_linux_endpoint_hijack_report.json".to_string(),
            "--rogue-endpoint-ip".to_string(),
            "203.0.113.10".to_string(),
            "--baseline-status".to_string(),
            "state=ExitActive restricted_safe_mode=false".to_string(),
            "--baseline-netcheck".to_string(),
            "path_mode=direct_active".to_string(),
            "--baseline-endpoints".to_string(),
            "peer-a=192.168.18.51:51820".to_string(),
            "--status-after-hijack".to_string(),
            "state=FailClosed restricted_safe_mode=true".to_string(),
            "--netcheck-after-hijack".to_string(),
            "path_mode=fail_closed".to_string(),
            "--endpoints-after-hijack".to_string(),
            "peer-a=192.168.18.51:51820".to_string(),
            "--status-after-recovery".to_string(),
            "state=ExitActive restricted_safe_mode=false".to_string(),
            "--endpoints-after-recovery".to_string(),
            "peer-a=192.168.18.51:51820".to_string(),
        ]);
        assert!(
            format!("{write_live_linux_endpoint_hijack_report:?}")
                .contains("WriteLiveLinuxEndpointHijackReport")
        );

        let write_real_wireguard_exitnode_e2e_report = parse_command(&[
            "ops".to_string(),
            "write-real-wireguard-exitnode-e2e-report".to_string(),
            "--report-path".to_string(),
            "artifacts/phase10/netns_e2e_report.json".to_string(),
            "--exit-status".to_string(),
            "pass".to_string(),
            "--lan-off-status".to_string(),
            "pass".to_string(),
            "--lan-on-status".to_string(),
            "pass".to_string(),
            "--dns-up-status".to_string(),
            "pass".to_string(),
            "--kill-switch-status".to_string(),
            "pass".to_string(),
            "--dns-down-status".to_string(),
            "pass".to_string(),
            "--environment".to_string(),
            "lab-netns".to_string(),
        ]);
        assert!(
            format!("{write_real_wireguard_exitnode_e2e_report:?}")
                .contains("WriteRealWireguardExitnodeE2eReport")
        );

        let write_real_wireguard_no_leak_report = parse_command(&[
            "ops".to_string(),
            "write-real-wireguard-no-leak-under-load-report".to_string(),
            "--report-path".to_string(),
            "artifacts/phase10/no_leak_dataplane_report.json".to_string(),
            "--load-pcap".to_string(),
            "/tmp/load.pcap".to_string(),
            "--down-pcap".to_string(),
            "/tmp/down.pcap".to_string(),
            "--tunnel-up-status".to_string(),
            "pass".to_string(),
            "--load-ping-status".to_string(),
            "pass".to_string(),
            "--tunnel-down-block-status".to_string(),
            "pass".to_string(),
            "--environment".to_string(),
            "lab-netns".to_string(),
        ]);
        assert!(
            format!("{write_real_wireguard_no_leak_report:?}")
                .contains("WriteRealWireguardNoLeakUnderLoadReport")
        );

        let verify_no_leak_report = parse_command(&[
            "ops".to_string(),
            "verify-no-leak-dataplane-report".to_string(),
            "--report-path".to_string(),
            "artifacts/phase10/no_leak_dataplane_report.json".to_string(),
        ]);
        assert!(format!("{verify_no_leak_report:?}").contains("VerifyNoLeakDataplaneReport"));

        let e2e_dns_query = parse_command(&[
            "ops".to_string(),
            "e2e-dns-query".to_string(),
            "--server".to_string(),
            "127.0.0.1".to_string(),
            "--port".to_string(),
            "53535".to_string(),
            "--qname".to_string(),
            "exit.rustynet".to_string(),
            "--timeout-ms".to_string(),
            "1000".to_string(),
            "--fail-on-no-response".to_string(),
        ]);
        assert!(format!("{e2e_dns_query:?}").contains("E2eDnsQuery"));

        let e2e_http_probe_server = parse_command(&[
            "ops".to_string(),
            "e2e-http-probe-server".to_string(),
            "--bind-ip".to_string(),
            "192.168.18.51".to_string(),
            "--port".to_string(),
            "18080".to_string(),
            "--response-body".to_string(),
            "probe-ok".to_string(),
        ]);
        assert!(format!("{e2e_http_probe_server:?}").contains("E2eHttpProbeServer"));

        let e2e_http_probe_client = parse_command(&[
            "ops".to_string(),
            "e2e-http-probe-client".to_string(),
            "--host".to_string(),
            "192.168.18.51".to_string(),
            "--port".to_string(),
            "18080".to_string(),
            "--timeout-ms".to_string(),
            "2000".to_string(),
            "--expect-marker".to_string(),
            "probe-ok".to_string(),
        ]);
        assert!(format!("{e2e_http_probe_client:?}").contains("E2eHttpProbeClient"));

        let read_json_field = parse_command(&[
            "ops".to_string(),
            "read-json-field".to_string(),
            "--payload".to_string(),
            "{\"rcode\":0}".to_string(),
            "--field".to_string(),
            "rcode".to_string(),
        ]);
        assert!(format!("{read_json_field:?}").contains("ReadJsonField"));

        let extract_dns_expected_ip = parse_command(&[
            "ops".to_string(),
            "extract-managed-dns-expected-ip".to_string(),
            "--fqdn".to_string(),
            "exit.rustynet".to_string(),
            "--inspect-output".to_string(),
            "fqdn=exit.rustynet expected_ip=100.64.0.1".to_string(),
        ]);
        assert!(format!("{extract_dns_expected_ip:?}").contains("ExtractManagedDnsExpectedIp"));

        let write_active_network_signed_state_tamper_report = parse_command(&[
            "ops".to_string(),
            "write-active-network-signed-state-tamper-report".to_string(),
            "--report-path".to_string(),
            "artifacts/phase10/signed_state_tamper_e2e_report.json".to_string(),
            "--baseline-status".to_string(),
            "pass".to_string(),
            "--tamper-reject-status".to_string(),
            "pass".to_string(),
            "--fail-closed-status".to_string(),
            "pass".to_string(),
            "--netcheck-fail-closed-status".to_string(),
            "pass".to_string(),
            "--recovery-status".to_string(),
            "pass".to_string(),
            "--exit-host".to_string(),
            "192.168.18.49".to_string(),
            "--client-host".to_string(),
            "192.168.18.50".to_string(),
            "--status-after-tamper".to_string(),
            "state=FailClosed".to_string(),
            "--netcheck-after-tamper".to_string(),
            "path_mode=fail_closed".to_string(),
            "--status-after-recovery".to_string(),
            "state=ExitActive".to_string(),
        ]);
        assert!(
            format!("{write_active_network_signed_state_tamper_report:?}")
                .contains("WriteActiveNetworkSignedStateTamperReport")
        );

        let write_active_network_rogue_path_hijack_report = parse_command(&[
            "ops".to_string(),
            "write-active-network-rogue-path-hijack-report".to_string(),
            "--report-path".to_string(),
            "artifacts/phase10/rogue_path_hijack_e2e_report.json".to_string(),
            "--baseline-status".to_string(),
            "pass".to_string(),
            "--hijack-reject-status".to_string(),
            "pass".to_string(),
            "--fail-closed-status".to_string(),
            "pass".to_string(),
            "--netcheck-fail-closed-status".to_string(),
            "pass".to_string(),
            "--no-rogue-endpoint-status".to_string(),
            "pass".to_string(),
            "--recovery-status".to_string(),
            "pass".to_string(),
            "--recovery-endpoint-status".to_string(),
            "pass".to_string(),
            "--rogue-endpoint-ip".to_string(),
            "203.0.113.10".to_string(),
            "--exit-host".to_string(),
            "192.168.18.49".to_string(),
            "--client-host".to_string(),
            "192.168.18.50".to_string(),
            "--endpoints-before".to_string(),
            "peer-a=192.168.18.49:51820".to_string(),
            "--endpoints-after-hijack".to_string(),
            "peer-a=192.168.18.49:51820".to_string(),
            "--endpoints-after-recovery".to_string(),
            "peer-a=192.168.18.49:51820".to_string(),
            "--status-after-hijack".to_string(),
            "state=FailClosed".to_string(),
            "--netcheck-after-hijack".to_string(),
            "path_mode=fail_closed".to_string(),
            "--status-after-recovery".to_string(),
            "state=ExitActive".to_string(),
        ]);
        assert!(
            format!("{write_active_network_rogue_path_hijack_report:?}")
                .contains("WriteActiveNetworkRoguePathHijackReport")
        );

        let validate_network_discovery_bundle = parse_command(&[
            "ops".to_string(),
            "validate-network-discovery-bundle".to_string(),
            "--bundle".to_string(),
            "artifacts/phase10/discovery-a.json".to_string(),
            "--bundle".to_string(),
            "artifacts/phase10/discovery-b.json".to_string(),
            "--bundles".to_string(),
            "artifacts/phase10/discovery-c.json,artifacts/phase10/discovery-b.json".to_string(),
            "--max-age-seconds".to_string(),
            "600".to_string(),
            "--require-verifier-keys".to_string(),
            "--require-daemon-active".to_string(),
            "--require-socket-present".to_string(),
            "--output".to_string(),
            "artifacts/phase10/discovery-validation.md".to_string(),
        ]);
        assert!(
            format!("{validate_network_discovery_bundle:?}")
                .contains("ValidateNetworkDiscoveryBundle")
        );

        let generate_live_lab_failure_digest = parse_command(&[
            "ops".to_string(),
            "generate-live-linux-lab-failure-digest".to_string(),
            "--nodes-tsv".to_string(),
            "artifacts/live_lab/test/state/nodes.tsv".to_string(),
            "--stages-tsv".to_string(),
            "artifacts/live_lab/test/state/stages.tsv".to_string(),
            "--report-dir".to_string(),
            "artifacts/live_lab/test".to_string(),
            "--run-id".to_string(),
            "20260321T120000Z".to_string(),
            "--network-id".to_string(),
            "rn-live-lab-20260321T120000Z".to_string(),
            "--overall-status".to_string(),
            "fail".to_string(),
            "--output-json".to_string(),
            "artifacts/live_lab/test/failure_digest.json".to_string(),
            "--output-md".to_string(),
            "artifacts/live_lab/test/failure_digest.md".to_string(),
        ]);
        assert!(
            format!("{generate_live_lab_failure_digest:?}")
                .contains("GenerateLiveLinuxLabFailureDigest")
        );

        let rebind_fresh_install_inputs = parse_command(&[
            "ops".to_string(),
            "rebind-linux-fresh-install-os-matrix-inputs".to_string(),
            "--dest-dir".to_string(),
            "artifacts/phase10/source/fresh_install_os_matrix".to_string(),
            "--bootstrap-log".to_string(),
            "artifacts/live_lab/test/logs/bootstrap.log".to_string(),
            "--baseline-log".to_string(),
            "artifacts/live_lab/test/logs/baseline.log".to_string(),
            "--two-hop-report".to_string(),
            "artifacts/live_lab/test/live_linux_two_hop_report.json".to_string(),
            "--role-switch-report".to_string(),
            "artifacts/live_lab/test/live_linux_role_switch_matrix_report.json".to_string(),
            "--lan-toggle-report".to_string(),
            "artifacts/live_lab/test/live_linux_lan_toggle_report.json".to_string(),
            "--exit-handoff-report".to_string(),
            "artifacts/live_lab/test/live_linux_exit_handoff_report.json".to_string(),
        ]);
        assert!(
            format!("{rebind_fresh_install_inputs:?}")
                .contains("RebindLinuxFreshInstallOsMatrixInputs")
        );

        let generate_fresh_install_report = parse_command(&[
            "ops".to_string(),
            "generate-linux-fresh-install-os-matrix-report".to_string(),
            "--output".to_string(),
            "artifacts/phase10/fresh_install_os_matrix_report.json".to_string(),
            "--environment".to_string(),
            "live-linux-lab".to_string(),
            "--source-mode".to_string(),
            "local-head".to_string(),
            "--expected-git-commit-file".to_string(),
            "artifacts/live_lab/test/state/expected_git_commit.txt".to_string(),
            "--git-status-file".to_string(),
            "artifacts/live_lab/test/state/git_status.txt".to_string(),
            "--bootstrap-log".to_string(),
            "artifacts/live_lab/test/logs/bootstrap.log".to_string(),
            "--baseline-log".to_string(),
            "artifacts/live_lab/test/logs/baseline.log".to_string(),
            "--two-hop-report".to_string(),
            "artifacts/live_lab/test/live_linux_two_hop_report.json".to_string(),
            "--role-switch-report".to_string(),
            "artifacts/live_lab/test/live_linux_role_switch_matrix_report.json".to_string(),
            "--lan-toggle-report".to_string(),
            "artifacts/live_lab/test/live_linux_lan_toggle_report.json".to_string(),
            "--exit-handoff-report".to_string(),
            "artifacts/live_lab/test/live_linux_exit_handoff_report.json".to_string(),
            "--exit-node-id".to_string(),
            "exit-1".to_string(),
            "--client-node-id".to_string(),
            "client-1".to_string(),
            "--ubuntu-node-id".to_string(),
            "ubuntu-1".to_string(),
            "--fedora-node-id".to_string(),
            "fedora-1".to_string(),
            "--mint-node-id".to_string(),
            "mint-1".to_string(),
        ]);
        assert!(
            format!("{generate_fresh_install_report:?}")
                .contains("GenerateLinuxFreshInstallOsMatrixReport")
        );

        let verify_fresh_install_report = parse_command(&[
            "ops".to_string(),
            "verify-linux-fresh-install-os-matrix-readiness".to_string(),
            "--report-path".to_string(),
            "artifacts/phase10/fresh_install_os_matrix_report.json".to_string(),
            "--max-age-seconds".to_string(),
            "604800".to_string(),
            "--profile".to_string(),
            "linux".to_string(),
            "--expected-git-commit".to_string(),
            "abcdefabcdefabcdefabcdefabcdefabcdefabcd".to_string(),
        ]);
        assert!(
            format!("{verify_fresh_install_report:?}")
                .contains("VerifyLinuxFreshInstallOsMatrixReadiness")
        );

        let write_fresh_install_fixtures = parse_command(&[
            "ops".to_string(),
            "write-fresh-install-os-matrix-readiness-fixtures".to_string(),
            "--output-dir".to_string(),
            "/tmp/rustynet-fresh-install-fixtures".to_string(),
            "--head-commit".to_string(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            "--stale-commit".to_string(),
            "1111111111111111111111111111111111111111".to_string(),
            "--now-unix".to_string(),
            "1773300000".to_string(),
        ]);
        assert!(
            format!("{write_fresh_install_fixtures:?}")
                .contains("WriteFreshInstallOsMatrixReadinessFixtures")
        );

        let write_unsigned_release_provenance = parse_command(&[
            "ops".to_string(),
            "write-unsigned-release-provenance".to_string(),
            "--input".to_string(),
            "artifacts/release/rustynetd.provenance.json".to_string(),
            "--output".to_string(),
            "artifacts/release/unsigned.provenance.json".to_string(),
        ]);
        assert!(
            format!("{write_unsigned_release_provenance:?}")
                .contains("WriteUnsignedReleaseProvenance")
        );

        let sign_release_artifact =
            parse_command(&["ops".to_string(), "sign-release-artifact".to_string()]);
        assert!(format!("{sign_release_artifact:?}").contains("SignReleaseArtifact"));

        let verify_release_artifact =
            parse_command(&["ops".to_string(), "verify-release-artifact".to_string()]);
        assert!(format!("{verify_release_artifact:?}").contains("VerifyReleaseArtifact"));

        let installer = parse_command(&["ops".to_string(), "install-systemd".to_string()]);
        assert!(format!("{installer:?}").contains("InstallSystemd"));

        let prepare_dirs = parse_command(&["ops".to_string(), "prepare-system-dirs".to_string()]);
        assert!(format!("{prepare_dirs:?}").contains("PrepareSystemDirs"));

        let restart_runtime =
            parse_command(&["ops".to_string(), "restart-runtime-service".to_string()]);
        assert!(format!("{restart_runtime:?}").contains("RestartRuntimeService"));

        let stop_runtime = parse_command(&["ops".to_string(), "stop-runtime-service".to_string()]);
        assert!(format!("{stop_runtime:?}").contains("StopRuntimeService"));

        let runtime_status =
            parse_command(&["ops".to_string(), "show-runtime-service-status".to_string()]);
        assert!(format!("{runtime_status:?}").contains("ShowRuntimeServiceStatus"));

        let start_assignment_refresh = parse_command(&[
            "ops".to_string(),
            "start-assignment-refresh-service".to_string(),
        ]);
        assert!(format!("{start_assignment_refresh:?}").contains("StartAssignmentRefreshService"));

        let check_assignment_refresh = parse_command(&[
            "ops".to_string(),
            "check-assignment-refresh-availability".to_string(),
        ]);
        assert!(
            format!("{check_assignment_refresh:?}").contains("CheckAssignmentRefreshAvailability")
        );

        let install_trust_material = parse_command(&[
            "ops".to_string(),
            "install-trust-material".to_string(),
            "--verifier-source".to_string(),
            "/tmp/trust.pub".to_string(),
            "--trust-source".to_string(),
            "/tmp/rustynetd.trust".to_string(),
            "--verifier-dest".to_string(),
            "/etc/rustynet/trust-evidence.pub".to_string(),
            "--trust-dest".to_string(),
            "/var/lib/rustynet/rustynetd.trust".to_string(),
            "--daemon-group".to_string(),
            "rustynetd".to_string(),
        ]);
        assert!(format!("{install_trust_material:?}").contains("InstallTrustMaterial"));

        let apply_managed_dns =
            parse_command(&["ops".to_string(), "apply-managed-dns-routing".to_string()]);
        assert!(format!("{apply_managed_dns:?}").contains("ApplyManagedDnsRouting"));

        let clear_managed_dns =
            parse_command(&["ops".to_string(), "clear-managed-dns-routing".to_string()]);
        assert!(format!("{clear_managed_dns:?}").contains("ClearManagedDnsRouting"));

        let disconnect_cleanup =
            parse_command(&["ops".to_string(), "disconnect-cleanup".to_string()]);
        assert!(format!("{disconnect_cleanup:?}").contains("DisconnectCleanup"));

        let blind_exit_lockdown =
            parse_command(&["ops".to_string(), "apply-blind-exit-lockdown".to_string()]);
        assert!(format!("{blind_exit_lockdown:?}").contains("ApplyBlindExitLockdown"));

        let init_membership = parse_command(&["ops".to_string(), "init-membership".to_string()]);
        assert!(format!("{init_membership:?}").contains("InitMembership"));

        let secure_remove = parse_command(&[
            "ops".to_string(),
            "secure-remove".to_string(),
            "--path".to_string(),
            "/tmp/secret.txt".to_string(),
        ]);
        assert!(format!("{secure_remove:?}").contains("SecureRemove"));

        let ensure_signing = parse_command(&[
            "ops".to_string(),
            "ensure-signing-passphrase-material".to_string(),
        ]);
        assert!(format!("{ensure_signing:?}").contains("EnsureSigningPassphraseMaterial"));

        let ensure_local_trust = parse_command(&[
            "ops".to_string(),
            "ensure-local-trust-material".to_string(),
            "--signing-key-passphrase-file".to_string(),
            "/tmp/signing-passphrase".to_string(),
        ]);
        assert!(format!("{ensure_local_trust:?}").contains("EnsureLocalTrustMaterial"));

        let materialize_signing = parse_command(&[
            "ops".to_string(),
            "materialize-signing-passphrase".to_string(),
            "--output".to_string(),
            "/tmp/signing-passphrase".to_string(),
        ]);
        assert!(format!("{materialize_signing:?}").contains("MaterializeSigningPassphrase"));

        let materialize_signing_temp = parse_command(&[
            "ops".to_string(),
            "materialize-signing-passphrase-temp".to_string(),
        ]);
        assert!(
            format!("{materialize_signing_temp:?}").contains("MaterializeSigningPassphraseTemp")
        );

        let set_exit = parse_command(&[
            "ops".to_string(),
            "set-assignment-refresh-exit-node".to_string(),
            "--env-path".to_string(),
            "/etc/rustynet/assignment-refresh.env".to_string(),
            "--exit-node-id".to_string(),
            "exit-40".to_string(),
        ]);
        assert!(format!("{set_exit:?}").contains("SetAssignmentRefreshExitNode"));

        let force_assignment_refresh = parse_command(&[
            "ops".to_string(),
            "force-local-assignment-refresh-now".to_string(),
        ]);
        assert!(format!("{force_assignment_refresh:?}").contains("ForceLocalAssignmentRefreshNow"));

        let state_refresh_if_socket_present = parse_command(&[
            "ops".to_string(),
            "state-refresh-if-socket-present".to_string(),
        ]);
        assert!(
            format!("{state_refresh_if_socket_present:?}").contains("StateRefreshIfSocketPresent")
        );

        let lan_coupling = parse_command(&[
            "ops".to_string(),
            "apply-lan-access-coupling".to_string(),
            "--enable".to_string(),
            "true".to_string(),
            "--lan-routes".to_string(),
            "192.168.1.0/24".to_string(),
        ]);
        assert!(format!("{lan_coupling:?}").contains("ApplyLanAccessCoupling"));

        let role_coupling = parse_command(&[
            "ops".to_string(),
            "apply-role-coupling".to_string(),
            "--target-role".to_string(),
            "client".to_string(),
            "--preferred-exit-node-id".to_string(),
            "exit-40".to_string(),
            "--enable-exit-advertise".to_string(),
            "false".to_string(),
            "--skip-client-exit-route-convergence-wait".to_string(),
        ]);
        assert!(format!("{role_coupling:?}").contains("ApplyRoleCoupling"));
        assert!(
            format!("{role_coupling:?}").contains("skip_client_exit_route_convergence_wait: true")
        );

        let peer_store_validate = parse_command(&[
            "ops".to_string(),
            "peer-store-validate".to_string(),
            "--config-dir".to_string(),
            "/tmp/rustynet-config".to_string(),
            "--peers-file".to_string(),
            "/tmp/rustynet-config/peers.db".to_string(),
        ]);
        assert!(format!("{peer_store_validate:?}").contains("PeerStoreValidate"));

        let peer_store_list = parse_command(&[
            "ops".to_string(),
            "peer-store-list".to_string(),
            "--config-dir".to_string(),
            "/tmp/rustynet-config".to_string(),
            "--peers-file".to_string(),
            "/tmp/rustynet-config/peers.db".to_string(),
            "--role".to_string(),
            "admin".to_string(),
            "--node-id".to_string(),
            "exit-1".to_string(),
        ]);
        assert!(format!("{peer_store_list:?}").contains("PeerStoreList"));

        let remote_e2e = parse_command(&[
            "ops".to_string(),
            "run-debian-two-node-e2e".to_string(),
            "--exit-host".to_string(),
            "192.168.18.37".to_string(),
            "--client-host".to_string(),
            "192.168.18.40".to_string(),
            "--ssh-allow-cidrs".to_string(),
            "192.168.18.2/32".to_string(),
        ]);
        assert!(format!("{remote_e2e:?}").contains("RunDebianTwoNodeE2e"));

        let bootstrap = parse_command(&[
            "ops".to_string(),
            "e2e-bootstrap-host".to_string(),
            "--role".to_string(),
            "admin".to_string(),
            "--node-id".to_string(),
            "exit-node".to_string(),
            "--network-id".to_string(),
            "local-net".to_string(),
            "--src-dir".to_string(),
            "/opt/rustynet-clean/src".to_string(),
            "--ssh-allow-cidrs".to_string(),
            "192.168.18.2/32".to_string(),
        ]);
        assert!(format!("{bootstrap:?}").contains("E2eBootstrapHost"));

        let enforce = parse_command(&[
            "ops".to_string(),
            "e2e-enforce-host".to_string(),
            "--role".to_string(),
            "client".to_string(),
            "--node-id".to_string(),
            "client-node".to_string(),
            "--src-dir".to_string(),
            "/opt/rustynet-clean/src".to_string(),
            "--ssh-allow-cidrs".to_string(),
            "192.168.18.2/32".to_string(),
        ]);
        assert!(format!("{enforce:?}").contains("E2eEnforceHost"));

        let membership = parse_command(&[
            "ops".to_string(),
            "e2e-membership-add".to_string(),
            "--client-node-id".to_string(),
            "client-node".to_string(),
            "--client-pubkey-hex".to_string(),
            "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff".to_string(),
            "--owner-approver-id".to_string(),
            "exit-node-owner".to_string(),
        ]);
        assert!(format!("{membership:?}").contains("E2eMembershipAdd"));

        let assignments = parse_command(&[
            "ops".to_string(),
            "e2e-issue-assignments".to_string(),
            "--exit-node-id".to_string(),
            "exit-node".to_string(),
            "--client-node-id".to_string(),
            "client-node".to_string(),
            "--exit-endpoint".to_string(),
            "192.168.18.37:51820".to_string(),
            "--client-endpoint".to_string(),
            "192.168.18.40:51820".to_string(),
            "--exit-pubkey-hex".to_string(),
            "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899".to_string(),
            "--client-pubkey-hex".to_string(),
            "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff".to_string(),
            "--artifact-dir".to_string(),
            "/run/rustynet/e2e-issue-artifacts.test".to_string(),
        ]);
        assert!(format!("{assignments:?}").contains("E2eIssueAssignments"));
        assert!(format!("{assignments:?}").contains("e2e-issue-artifacts.test"));

        let assignments_from_env = parse_command(&[
            "ops".to_string(),
            "e2e-issue-assignment-bundles-from-env".to_string(),
            "--env-file".to_string(),
            "/tmp/rn-assign.env".to_string(),
            "--issue-dir".to_string(),
            "/run/rustynet/assignment-issue".to_string(),
        ]);
        assert!(format!("{assignments_from_env:?}").contains("E2eIssueAssignmentBundlesFromEnv"));

        let traversal_from_env = parse_command(&[
            "ops".to_string(),
            "e2e-issue-traversal-bundles-from-env".to_string(),
            "--env-file".to_string(),
            "/tmp/rn-traversal.env".to_string(),
            "--issue-dir".to_string(),
            "/run/rustynet/traversal-issue".to_string(),
        ]);
        assert!(format!("{traversal_from_env:?}").contains("E2eIssueTraversalBundlesFromEnv"));

        let dns_zone_from_env = parse_command(&[
            "ops".to_string(),
            "e2e-issue-dns-zone-bundles-from-env".to_string(),
            "--env-file".to_string(),
            "/tmp/rn-dns.env".to_string(),
            "--issue-dir".to_string(),
            "/run/rustynet/dns-zone-issue".to_string(),
        ]);
        assert!(format!("{dns_zone_from_env:?}").contains("E2eIssueDnsZoneBundlesFromEnv"));

        let vm_lab_list = parse_command(&["ops".to_string(), "vm-lab-list".to_string()]);
        assert!(format!("{vm_lab_list:?}").contains("VmLabList"));

        let vm_lab_discover_local_utm = parse_command(&[
            "ops".to_string(),
            "vm-lab-discover-local-utm".to_string(),
            "--inventory".to_string(),
            "/tmp/vm_lab_inventory.json".to_string(),
            "--utm-documents-root".to_string(),
            "/Users/iwan/Library/Containers/com.utmapp.UTM/Data/Documents".to_string(),
            "--utmctl-path".to_string(),
            "/Applications/UTM.app/Contents/MacOS/utmctl".to_string(),
            "--ssh-port".to_string(),
            "2222".to_string(),
            "--timeout-secs".to_string(),
            "15".to_string(),
            "--update-inventory-live-ips".to_string(),
            "--report-dir".to_string(),
            "/tmp/vm-lab-discovery".to_string(),
        ]);
        assert!(format!("{vm_lab_discover_local_utm:?}").contains("VmLabDiscoverLocalUtm"));
        assert!(format!("{vm_lab_discover_local_utm:?}").contains("2222"));
        assert!(
            format!("{vm_lab_discover_local_utm:?}").contains("update_inventory_live_ips: true")
        );
        assert!(format!("{vm_lab_discover_local_utm:?}").contains("/tmp/vm-lab-discovery"));

        let vm_lab_discover_local_utm_summary = parse_command(&[
            "ops".to_string(),
            "vm-lab-discover-local-utm-summary".to_string(),
            "--inventory".to_string(),
            "/tmp/vm_lab_inventory.json".to_string(),
            "--update-inventory-live-ips".to_string(),
        ]);
        assert!(
            format!("{vm_lab_discover_local_utm_summary:?}")
                .contains("VmLabDiscoverLocalUtmSummary")
        );
        assert!(
            format!("{vm_lab_discover_local_utm_summary:?}")
                .contains("update_inventory_live_ips: true")
        );

        let vm_lab_start = parse_command(&[
            "ops".to_string(),
            "vm-lab-start".to_string(),
            "--inventory".to_string(),
            "/tmp/vm_lab_inventory.json".to_string(),
            "--vm".to_string(),
            "debian-headless-1".to_string(),
            "--vm".to_string(),
            "debian-headless-3".to_string(),
            "--timeout-secs".to_string(),
            "120".to_string(),
        ]);
        assert!(format!("{vm_lab_start:?}").contains("VmLabStart"));
        assert!(format!("{vm_lab_start:?}").contains("debian-headless-3"));

        let vm_lab_sync = parse_command(&[
            "ops".to_string(),
            "vm-lab-sync-repo".to_string(),
            "--inventory".to_string(),
            "/tmp/vm_lab_inventory.json".to_string(),
            "--vm".to_string(),
            "debian-headless-2".to_string(),
            "--target".to_string(),
            "root@192.168.18.51".to_string(),
            "--repo-url".to_string(),
            "git@github.com:iwanteague/Rustyfin.git".to_string(),
            "--dest-dir".to_string(),
            "/home/debian/Rustyfin".to_string(),
            "--branch".to_string(),
            "main".to_string(),
            "--ssh-user".to_string(),
            "root".to_string(),
        ]);
        assert!(format!("{vm_lab_sync:?}").contains("VmLabSyncRepo"));
        assert!(format!("{vm_lab_sync:?}").contains("Rustyfin"));
        assert!(format!("{vm_lab_sync:?}").contains("root@192.168.18.51"));

        let vm_lab_sync_local = parse_command(&[
            "ops".to_string(),
            "vm-lab-sync-repo".to_string(),
            "--vm".to_string(),
            "debian-headless-1".to_string(),
            "--local-source-dir".to_string(),
            "/Users/iwanteague/Desktop/Rustynet".to_string(),
            "--dest-dir".to_string(),
            "/home/debian/Rustynet".to_string(),
        ]);
        assert!(format!("{vm_lab_sync_local:?}").contains("VmLabSyncRepo"));
        assert!(format!("{vm_lab_sync_local:?}").contains("/Users/iwanteague/Desktop/Rustynet"));

        let vm_lab_sync_bootstrap = parse_command(&[
            "ops".to_string(),
            "vm-lab-sync-bootstrap".to_string(),
            "--inventory".to_string(),
            "/tmp/vm_lab_inventory.json".to_string(),
            "--vm".to_string(),
            "debian-headless-1".to_string(),
            "--require-same-network".to_string(),
            "--repo-url".to_string(),
            "git@github.com:iwanteague/Rustyfin.git".to_string(),
            "--dest-dir".to_string(),
            "/home/debian/Rustyfin".to_string(),
            "--program".to_string(),
            "cargo".to_string(),
            "--arg".to_string(),
            "build".to_string(),
            "--arg".to_string(),
            "--release".to_string(),
        ]);
        assert!(format!("{vm_lab_sync_bootstrap:?}").contains("VmLabSyncBootstrap"));
        assert!(format!("{vm_lab_sync_bootstrap:?}").contains("require_same_network: true"));

        let vm_lab_sync_bootstrap_local = parse_command(&[
            "ops".to_string(),
            "vm-lab-sync-bootstrap".to_string(),
            "--vm".to_string(),
            "debian-headless-1".to_string(),
            "--local-source-dir".to_string(),
            "/Users/iwanteague/Desktop/Rustynet".to_string(),
            "--dest-dir".to_string(),
            "/home/debian/Rustynet".to_string(),
            "--program".to_string(),
            "sh".to_string(),
            "--arg".to_string(),
            "-lc".to_string(),
            "--arg".to_string(),
            "pwd".to_string(),
        ]);
        assert!(format!("{vm_lab_sync_bootstrap_local:?}").contains("VmLabSyncBootstrap"));
        assert!(
            format!("{vm_lab_sync_bootstrap_local:?}")
                .contains("/Users/iwanteague/Desktop/Rustynet")
        );

        let vm_lab_run = parse_command(&[
            "ops".to_string(),
            "vm-lab-run".to_string(),
            "--vm".to_string(),
            "debian-headless-2".to_string(),
            "--target".to_string(),
            "debian@192.168.18.52".to_string(),
            "--workdir".to_string(),
            "/home/debian/Rustyfin".to_string(),
            "--program".to_string(),
            "cargo".to_string(),
            "--arg".to_string(),
            "build".to_string(),
            "--arg".to_string(),
            "--release".to_string(),
            "--sudo".to_string(),
        ]);
        assert!(format!("{vm_lab_run:?}").contains("VmLabRun"));
        assert!(format!("{vm_lab_run:?}").contains("debian@192.168.18.52"));
        assert!(format!("{vm_lab_run:?}").contains("--release"));

        let vm_lab_bootstrap = parse_command(&[
            "ops".to_string(),
            "vm-lab-bootstrap".to_string(),
            "--all".to_string(),
            "--workdir".to_string(),
            "/home/debian/Rustyfin".to_string(),
            "--program".to_string(),
            "cargo".to_string(),
            "--arg".to_string(),
            "build".to_string(),
        ]);
        assert!(format!("{vm_lab_bootstrap:?}").contains("VmLabBootstrap"));
        assert!(format!("{vm_lab_bootstrap:?}").contains("VmLabBootstrap"));

        let vm_lab_profile = parse_command(&[
            "ops".to_string(),
            "vm-lab-write-live-lab-profile".to_string(),
            "--output".to_string(),
            "/tmp/live_lab.env".to_string(),
            "--ssh-identity-file".to_string(),
            "/Users/iwanteague/.ssh/rustynet_lab_ed25519".to_string(),
            "--exit-vm".to_string(),
            "debian-headless-1".to_string(),
            "--backend".to_string(),
            "linux-wireguard-userspace-shared".to_string(),
            "--client-target".to_string(),
            "debian@192.168.18.52".to_string(),
            "--require-same-network".to_string(),
        ]);
        assert!(format!("{vm_lab_profile:?}").contains("VmLabWriteLiveLabProfile"));
        assert!(format!("{vm_lab_profile:?}").contains("debian-headless-1"));
        assert!(format!("{vm_lab_profile:?}").contains("linux-wireguard-userspace-shared"));

        let vm_lab_setup = parse_command(&[
            "ops".to_string(),
            "vm-lab-setup-live-lab".to_string(),
            "--report-dir".to_string(),
            "artifacts/live_lab/setup_test".to_string(),
            "--ssh-identity-file".to_string(),
            "/Users/iwanteague/.ssh/rustynet_lab_ed25519".to_string(),
            "--inventory".to_string(),
            "/tmp/vm_lab_inventory.json".to_string(),
            "--require-same-network".to_string(),
            "--resume-from".to_string(),
            "bootstrap_hosts".to_string(),
            "--max-parallel-node-workers".to_string(),
            "2".to_string(),
        ]);
        assert!(format!("{vm_lab_setup:?}").contains("VmLabSetupLiveLab"));
        assert!(format!("{vm_lab_setup:?}").contains("bootstrap_hosts"));

        let vm_lab_orchestrate = parse_command(&[
            "ops".to_string(),
            "vm-lab-orchestrate-live-lab".to_string(),
            "--report-dir".to_string(),
            "artifacts/live_lab/orchestrate_test".to_string(),
            "--ssh-identity-file".to_string(),
            "/Users/iwanteague/.ssh/rustynet_lab_ed25519".to_string(),
            "--inventory".to_string(),
            "/tmp/vm_lab_inventory.json".to_string(),
            "--require-same-network".to_string(),
            "--wait-ready-timeout-secs".to_string(),
            "180".to_string(),
            "--collect-artifacts-on-failure".to_string(),
            "--stop-after-ready".to_string(),
        ]);
        assert!(format!("{vm_lab_orchestrate:?}").contains("VmLabOrchestrateLiveLab"));
        assert!(format!("{vm_lab_orchestrate:?}").contains("ready_timeout_secs: 180"));
        assert!(format!("{vm_lab_orchestrate:?}").contains("collect_artifacts_on_failure: true"));
        assert!(format!("{vm_lab_orchestrate:?}").contains("stop_after_ready: true"));

        let vm_lab_validate_profile = parse_command(&[
            "ops".to_string(),
            "vm-lab-validate-live-lab-profile".to_string(),
            "--profile".to_string(),
            "profiles/live_lab/generated_vm_lab.env".to_string(),
            "--expected-backend".to_string(),
            "linux-wireguard-userspace-shared".to_string(),
            "--require-five-node".to_string(),
        ]);
        assert!(format!("{vm_lab_validate_profile:?}").contains("VmLabValidateLiveLabProfile"));

        let vm_lab_diagnose = parse_command(&[
            "ops".to_string(),
            "vm-lab-diagnose-live-lab-failure".to_string(),
            "--profile".to_string(),
            "profiles/live_lab/generated_vm_lab.env".to_string(),
            "--report-dir".to_string(),
            "artifacts/live_lab/iteration_1".to_string(),
            "--collect-artifacts".to_string(),
        ]);
        assert!(format!("{vm_lab_diagnose:?}").contains("VmLabDiagnoseLiveLabFailure"));

        let vm_lab_diff = parse_command(&[
            "ops".to_string(),
            "vm-lab-diff-live-lab-runs".to_string(),
            "--old-report-dir".to_string(),
            "artifacts/live_lab/old".to_string(),
            "--new-report-dir".to_string(),
            "artifacts/live_lab/new".to_string(),
        ]);
        assert!(format!("{vm_lab_diff:?}").contains("VmLabDiffLiveLabRuns"));

        let vm_lab_iteration = parse_command(&[
            "ops".to_string(),
            "vm-lab-iterate-live-lab".to_string(),
            "--ssh-identity-file".to_string(),
            "/Users/iwanteague/.ssh/rustynet_lab_ed25519".to_string(),
            "--exit-vm".to_string(),
            "debian-headless-1".to_string(),
            "--client-target".to_string(),
            "debian@192.168.18.52".to_string(),
            "--validation-step".to_string(),
            "fmt".to_string(),
            "--validation-step".to_string(),
            "check:rustynetd".to_string(),
            "--validation-step".to_string(),
            "test-bin:rustynet-cli:live_linux_lan_toggle_test".to_string(),
            "--skip-cross-network".to_string(),
            "--require-clean-tree".to_string(),
            "--require-local-head".to_string(),
            "--collect-failure-diagnostics".to_string(),
        ]);
        assert!(format!("{vm_lab_iteration:?}").contains("VmLabIterateLiveLab"));
        assert!(format!("{vm_lab_iteration:?}").contains("CargoCheckPackage"));
        assert!(format!("{vm_lab_iteration:?}").contains("CargoTestBin"));
        assert!(format!("{vm_lab_iteration:?}").contains("skip_cross_network: true"));

        let vm_lab_live_lab = parse_command(&[
            "ops".to_string(),
            "vm-lab-run-live-lab".to_string(),
            "--profile".to_string(),
            "/tmp/live_lab.env".to_string(),
            "--dry-run".to_string(),
            "--skip-setup".to_string(),
            "--skip-gates".to_string(),
        ]);
        assert!(format!("{vm_lab_live_lab:?}").contains("VmLabRunLiveLab"));
        assert!(format!("{vm_lab_live_lab:?}").contains("dry_run: true"));
        assert!(format!("{vm_lab_live_lab:?}").contains("skip_setup: true"));

        let vm_lab_known_hosts = parse_command(&[
            "ops".to_string(),
            "vm-lab-check-known-hosts".to_string(),
            "--inventory".to_string(),
            "/tmp/vm_lab_inventory.json".to_string(),
            "--vm".to_string(),
            "debian-headless-1".to_string(),
            "--known-hosts-file".to_string(),
            "/Users/iwanteague/.ssh/known_hosts".to_string(),
        ]);
        assert!(format!("{vm_lab_known_hosts:?}").contains("VmLabCheckKnownHosts"));

        let vm_lab_preflight = parse_command(&[
            "ops".to_string(),
            "vm-lab-preflight".to_string(),
            "--all".to_string(),
            "--require-command".to_string(),
            "git".to_string(),
            "--require-command".to_string(),
            "cargo".to_string(),
            "--require-rustynet-installed".to_string(),
        ]);
        assert!(format!("{vm_lab_preflight:?}").contains("VmLabPreflight"));
        assert!(format!("{vm_lab_preflight:?}").contains("require_rustynet_installed: true"));

        let vm_lab_status = parse_command(&[
            "ops".to_string(),
            "vm-lab-status".to_string(),
            "--target".to_string(),
            "debian@192.168.18.53".to_string(),
        ]);
        assert!(format!("{vm_lab_status:?}").contains("VmLabStatus"));

        let vm_lab_stop = parse_command(&[
            "ops".to_string(),
            "vm-lab-stop".to_string(),
            "--vm".to_string(),
            "debian-headless-1".to_string(),
        ]);
        assert!(format!("{vm_lab_stop:?}").contains("VmLabStop"));

        let vm_lab_shutdown = parse_command(&[
            "ops".to_string(),
            "vm-lab-shutdown".to_string(),
            "--all".to_string(),
        ]);
        assert!(format!("{vm_lab_shutdown:?}").contains("VmLabStop"));

        let vm_lab_restart = parse_command(&[
            "ops".to_string(),
            "vm-lab-restart".to_string(),
            "--target".to_string(),
            "debian@192.168.18.54".to_string(),
            "--service".to_string(),
            "rustynetd.service".to_string(),
        ]);
        assert!(format!("{vm_lab_restart:?}").contains("VmLabRestart"));
        assert!(format!("{vm_lab_restart:?}").contains("rustynetd.service"));

        let vm_lab_restart_wait_ready = parse_command(&[
            "ops".to_string(),
            "vm-lab-restart".to_string(),
            "--vm".to_string(),
            "debian-headless-1".to_string(),
            "--wait-ready".to_string(),
            "--ssh-port".to_string(),
            "2222".to_string(),
            "--wait-ready-timeout-secs".to_string(),
            "45".to_string(),
            "--json".to_string(),
            "--report-dir".to_string(),
            "/tmp/vm-lab-restart".to_string(),
        ]);
        let vm_lab_restart_wait_ready = format!("{vm_lab_restart_wait_ready:?}");
        assert!(vm_lab_restart_wait_ready.contains("VmLabRestart"));
        assert!(vm_lab_restart_wait_ready.contains("wait_ready: true"));
        assert!(vm_lab_restart_wait_ready.contains("ssh_port: 2222"));
        assert!(vm_lab_restart_wait_ready.contains("ready_timeout_secs: 45"));
        assert!(vm_lab_restart_wait_ready.contains("json_output: true"));
        assert!(vm_lab_restart_wait_ready.contains("/tmp/vm-lab-restart"));

        let vm_lab_collect_artifacts = parse_command(&[
            "ops".to_string(),
            "vm-lab-collect-artifacts".to_string(),
            "--all".to_string(),
            "--output-dir".to_string(),
            "/tmp/vm-lab-artifacts".to_string(),
        ]);
        assert!(format!("{vm_lab_collect_artifacts:?}").contains("VmLabCollectArtifacts"));

        let vm_lab_write_topology = parse_command(&[
            "ops".to_string(),
            "vm-lab-write-topology".to_string(),
            "--suite".to_string(),
            "relay-remote-exit".to_string(),
            "--output".to_string(),
            "/tmp/vm-lab-topology.json".to_string(),
            "--all".to_string(),
        ]);
        assert!(format!("{vm_lab_write_topology:?}").contains("VmLabWriteTopology"));

        let vm_lab_issue_state = parse_command(&[
            "ops".to_string(),
            "vm-lab-issue-and-distribute-state".to_string(),
            "--topology".to_string(),
            "/tmp/vm-lab-topology.json".to_string(),
            "--authority-vm".to_string(),
            "debian-headless-1".to_string(),
        ]);
        assert!(format!("{vm_lab_issue_state:?}").contains("VmLabIssueAndDistributeState"));

        let vm_lab_run_suite = parse_command(&[
            "ops".to_string(),
            "vm-lab-run-suite".to_string(),
            "--suite".to_string(),
            "direct-remote-exit".to_string(),
            "--ssh-identity-file".to_string(),
            "/Users/iwanteague/.ssh/rustynet_lab_ed25519".to_string(),
            "--dry-run".to_string(),
            "--all".to_string(),
        ]);
        assert!(format!("{vm_lab_run_suite:?}").contains("VmLabRunSuite"));
        assert!(format!("{vm_lab_run_suite:?}").contains("dry_run: true"));

        let vm_lab_bootstrap_phase = parse_command(&[
            "ops".to_string(),
            "vm-lab-bootstrap-phase".to_string(),
            "--phase".to_string(),
            "all".to_string(),
            "--repo-url".to_string(),
            "git@github.com:iwanteague/Rustynet.git".to_string(),
            "--dest-dir".to_string(),
            "/home/debian/Rustynet".to_string(),
            "--all".to_string(),
        ]);
        assert!(format!("{vm_lab_bootstrap_phase:?}").contains("VmLabBootstrapPhase"));
        assert!(format!("{vm_lab_bootstrap_phase:?}").contains("phase: \"all\""));

        let vm_lab_bootstrap_phase_local = parse_command(&[
            "ops".to_string(),
            "vm-lab-bootstrap-phase".to_string(),
            "--phase".to_string(),
            "sync-source".to_string(),
            "--local-source-dir".to_string(),
            "/Users/iwanteague/Desktop/Rustynet".to_string(),
            "--dest-dir".to_string(),
            "/home/debian/Rustynet".to_string(),
            "--vm".to_string(),
            "debian-headless-1".to_string(),
        ]);
        assert!(format!("{vm_lab_bootstrap_phase_local:?}").contains("VmLabBootstrapPhase"));
        assert!(
            format!("{vm_lab_bootstrap_phase_local:?}")
                .contains("/Users/iwanteague/Desktop/Rustynet")
        );
    }

    #[test]
    fn parse_supports_state_refresh_command() {
        let command = parse_command(&["state".to_string(), "refresh".to_string()]);
        assert_eq!(command, CliCommand::StateRefresh);
        let ipc = to_ipc_command(command);
        assert_eq!(ipc, IpcCommand::StateRefresh);
    }

    #[test]
    fn help_text_lists_vm_lab_setup_and_skip_setup() {
        let help = help_text();
        assert!(help.contains("ops vm-lab-setup-live-lab"));
        assert!(help.contains("ops vm-lab-orchestrate-live-lab"));
        assert!(help.contains("ops vm-lab-run-live-lab --profile <path>"));
        assert!(help.contains("[--skip-setup]"));
    }

    #[test]
    fn parse_reboot_recovery_report_requires_dns_refresh_checks() {
        let missing_dns_refresh_checks = parse_command(&[
            "ops".to_string(),
            "write-live-linux-reboot-recovery-report".to_string(),
            "--report-path".to_string(),
            "artifacts/live_lab/live_linux_reboot_recovery_report.json".to_string(),
            "--observations-path".to_string(),
            "artifacts/live_lab/live_linux_reboot_recovery_observations.txt".to_string(),
            "--exit-pre".to_string(),
            "a".to_string(),
            "--exit-post".to_string(),
            "b".to_string(),
            "--client-pre".to_string(),
            "c".to_string(),
            "--client-post".to_string(),
            "d".to_string(),
            "--exit-return".to_string(),
            "pass".to_string(),
            "--exit-boot-change".to_string(),
            "pass".to_string(),
            "--post-exit-twohop".to_string(),
            "pass".to_string(),
            "--client-return".to_string(),
            "pass".to_string(),
            "--client-boot-change".to_string(),
            "pass".to_string(),
            "--post-client-twohop".to_string(),
            "pass".to_string(),
            "--salvage-twohop".to_string(),
            "skipped".to_string(),
        ]);
        assert_eq!(format!("{missing_dns_refresh_checks:?}"), "Help");
    }

    #[test]
    fn rewrite_assignment_refresh_exit_node_updates_and_clears() {
        let existing = "RUSTYNET_ASSIGNMENT_TARGET_NODE_ID=\"node-40\"\nRUSTYNET_ASSIGNMENT_EXIT_NODE_ID=\"old\"\nRUSTYNET_ASSIGNMENT_ALLOW=\"a|b\"\n";
        let updated = rewrite_assignment_refresh_exit_node(existing, Some("exit-new"));
        assert!(updated.contains("RUSTYNET_ASSIGNMENT_EXIT_NODE_ID=\"exit-new\""));
        assert!(!updated.contains("RUSTYNET_ASSIGNMENT_EXIT_NODE_ID=\"old\""));

        let cleared = rewrite_assignment_refresh_exit_node(existing, None);
        assert!(!cleared.contains("RUSTYNET_ASSIGNMENT_EXIT_NODE_ID="));
    }

    #[test]
    fn rewrite_assignment_refresh_lan_routes_updates_and_clears() {
        let existing = "RUSTYNET_ASSIGNMENT_TARGET_NODE_ID=\"node-40\"\nRUSTYNET_ASSIGNMENT_LAN_ROUTES=\"10.0.0.0/24\"\nRUSTYNET_ASSIGNMENT_ALLOW=\"a|b\"\n";
        let updated = rewrite_assignment_refresh_lan_routes(
            existing,
            &[String::from("192.168.1.0/24"), String::from("fd00::/64")],
        );
        assert!(updated.contains("RUSTYNET_ASSIGNMENT_LAN_ROUTES=\"192.168.1.0/24,fd00::/64\""));
        assert!(!updated.contains("RUSTYNET_ASSIGNMENT_LAN_ROUTES=\"10.0.0.0/24\""));

        let cleared = rewrite_assignment_refresh_lan_routes(existing, &[]);
        assert!(!cleared.contains("RUSTYNET_ASSIGNMENT_LAN_ROUTES="));
    }

    #[test]
    fn disable_lan_blackhole_routes_prefers_requested_routes_and_falls_back_to_previous() {
        assert_eq!(
            super::disable_lan_blackhole_routes(
                &[String::from("192.168.1.0/24")],
                &[String::from("172.16.0.0/16")],
                &[String::from("10.0.0.0/24")]
            ),
            vec![String::from("192.168.1.0/24")]
        );
        assert_eq!(
            super::disable_lan_blackhole_routes(
                &[],
                &[String::from("172.16.0.0/16")],
                &[String::from("10.0.0.0/24")]
            ),
            vec![String::from("172.16.0.0/16")]
        );
        assert_eq!(
            super::disable_lan_blackhole_routes(&[], &[], &[String::from("10.0.0.0/24")]),
            vec![String::from("10.0.0.0/24")]
        );
    }

    #[test]
    fn rewrite_assignment_refresh_lan_block_routes_updates_and_clears() {
        let existing = "RUSTYNET_ASSIGNMENT_TARGET_NODE_ID=\"node-40\"\nRUSTYNET_ASSIGNMENT_LAN_BLOCK_ROUTES=\"10.0.0.0/24\"\nRUSTYNET_ASSIGNMENT_ALLOW=\"a|b\"\n";
        let updated = super::rewrite_assignment_refresh_lan_block_routes(
            existing,
            &[String::from("192.168.1.0/24"), String::from("fd00::/64")],
        );
        assert!(
            updated.contains("RUSTYNET_ASSIGNMENT_LAN_BLOCK_ROUTES=\"192.168.1.0/24,fd00::/64\"")
        );
        assert!(!updated.contains("RUSTYNET_ASSIGNMENT_LAN_BLOCK_ROUTES=\"10.0.0.0/24\""));

        let cleared = super::rewrite_assignment_refresh_lan_block_routes(existing, &[]);
        assert!(!cleared.contains("RUSTYNET_ASSIGNMENT_LAN_BLOCK_ROUTES="));
    }

    #[test]
    fn local_traversal_refresh_config_uses_assignment_env_specs() {
        let env = concat!(
            "RUSTYNET_ASSIGNMENT_TARGET_NODE_ID=\"client-40\"\n",
            "RUSTYNET_ASSIGNMENT_NODES=\"client-40|192.168.18.40:51820|abc;exit-49|192.168.18.49:51820|def\"\n",
            "RUSTYNET_ASSIGNMENT_ALLOW=\"client-40|exit-49;exit-49|client-40\"\n",
        );

        let config = super::local_traversal_refresh_config_from_assignment_env(env)
            .expect("valid assignment env should produce traversal refresh config");
        assert_eq!(config.local_node_id, "client-40");
        assert_eq!(
            config.nodes_spec,
            "client-40|192.168.18.40:51820|abc;exit-49|192.168.18.49:51820|def"
        );
        assert_eq!(config.allow_spec, "client-40|exit-49;exit-49|client-40");
        let env_body = super::local_traversal_refresh_env_body(
            config.local_node_id.as_str(),
            config.nodes_spec.as_str(),
            config.allow_spec.as_str(),
        )
        .expect("refresh env body should be derived");
        assert!(env_body.contains(
            "NODES_SPEC=\"client-40|192.168.18.40:51820|abc;exit-49|192.168.18.49:51820|def\""
        ));
        assert!(env_body.contains("ALLOW_SPEC=\"client-40|exit-49;exit-49|client-40\""));
        assert!(env_body.contains(&format!(
            "TRAVERSAL_TTL_SECS=\"{}\"",
            super::LOCAL_TRAVERSAL_REFRESH_TTL_SECS
        )));
    }

    #[test]
    fn local_traversal_refresh_config_rejects_missing_local_allow_source() {
        let env = concat!(
            "RUSTYNET_ASSIGNMENT_TARGET_NODE_ID=\"client-40\"\n",
            "RUSTYNET_ASSIGNMENT_NODES=\"client-40|192.168.18.40:51820|abc;exit-49|192.168.18.49:51820|def\"\n",
            "RUSTYNET_ASSIGNMENT_ALLOW=\"exit-49|client-40\"\n",
        );

        let err = super::local_traversal_refresh_config_from_assignment_env(env)
            .expect_err("missing local traversal source must fail closed");
        assert!(err.contains("does not authorize traversal sources for local node client-40"));
    }

    #[test]
    fn rewrite_env_key_value_replaces_or_appends() {
        let existing = "RUSTYNET_NODE_ID=\"node-40\"\nRUSTYNET_ASSIGNMENT_AUTO_REFRESH=\"true\"\nRUSTYNET_STATE=\"/var/lib/rustynet/rustynetd.state\"\n";
        let rewritten =
            rewrite_env_key_value(existing, "RUSTYNET_ASSIGNMENT_AUTO_REFRESH", "false");
        assert!(rewritten.contains("RUSTYNET_ASSIGNMENT_AUTO_REFRESH=\"false\""));
        assert!(!rewritten.contains("RUSTYNET_ASSIGNMENT_AUTO_REFRESH=\"true\""));

        let without_key = "RUSTYNET_NODE_ID=\"node-40\"\n";
        let appended =
            rewrite_env_key_value(without_key, "RUSTYNET_ASSIGNMENT_AUTO_REFRESH", "false");
        assert!(appended.contains("RUSTYNET_ASSIGNMENT_AUTO_REFRESH=\"false\""));
    }

    #[test]
    fn rewrite_env_key_value_quotes_structured_values() {
        let rewritten = rewrite_env_key_value(
            "",
            "RUSTYNET_ASSIGNMENT_NODES",
            "client-50|192.168.18.50:51820|abc;exit-49|192.168.18.49:51820|def",
        );
        assert_eq!(
            rewritten,
            "RUSTYNET_ASSIGNMENT_NODES=\"client-50|192.168.18.50:51820|abc;exit-49|192.168.18.49:51820|def\"\n"
        );
    }

    #[test]
    fn managed_dns_resolver_server_arg_accepts_ipv4_loopback() {
        let server = managed_dns_resolver_server_arg(
            "127.0.0.1:53535"
                .parse()
                .expect("ipv4 loopback resolver addr should parse"),
        )
        .expect("ipv4 loopback resolver addr should be accepted");
        assert_eq!(server, "127.0.0.1:53535");
    }

    #[test]
    fn managed_dns_resolver_server_arg_rejects_ipv6_loopback() {
        let err = managed_dns_resolver_server_arg(
            "[::1]:53535"
                .parse()
                .expect("ipv6 loopback resolver addr should parse"),
        )
        .expect_err("ipv6 loopback resolver addr should be rejected");
        assert!(err.contains("IPv4 loopback"));
    }

    #[test]
    fn contains_ip_rule_lookup_table_matches_expected_rule() {
        let body = "0:\tfrom all lookup local\n32765:\tfrom all lookup 51820\n32766:\tfrom all lookup main\n";
        assert!(contains_ip_rule_lookup_table(body, "51820"));
        assert!(!contains_ip_rule_lookup_table(body, "60000"));
    }

    #[test]
    fn parse_managed_pf_anchors_filters_and_deduplicates() {
        let body = "com.apple/rustynet_g100\ncom.apple/rustynet_g100\ncom.apple/rustynet_nat_g5\ncom.apple/rustynet_g200\n";
        let anchors = parse_managed_pf_anchors(body);
        assert_eq!(
            anchors,
            vec![
                "com.apple/rustynet_g100".to_string(),
                "com.apple/rustynet_g200".to_string()
            ]
        );
    }

    #[test]
    fn parse_wireguard_go_pids_matches_interface_exactly() {
        let ps_body = " 101 /usr/local/bin/wireguard-go rustynet0\n 202 /usr/local/bin/wireguard-go rustynet1\n 303 /usr/bin/other-process rustynet0\n";
        let pids =
            parse_wireguard_go_pids_from_ps(ps_body, "rustynet0").expect("parse should succeed");
        assert_eq!(pids, vec![101]);
    }

    #[test]
    fn launchd_xml_escape_escapes_reserved_characters() {
        let escaped = launchd_xml_escape("a<&>\"'b");
        assert_eq!(escaped, "a&lt;&amp;&gt;&quot;&apos;b");
    }

    #[test]
    fn render_launchd_plist_includes_expected_structure() {
        let plist = render_launchd_plist(
            "com.rustynet.test",
            &[
                "/usr/local/bin/rustynetd".to_string(),
                "daemon".to_string(),
                "--node-id".to_string(),
                "node-1".to_string(),
            ],
            &[(
                "RUSTYNET_WG_BINARY_PATH".to_string(),
                "/usr/bin/wg".to_string(),
            )],
            std::path::Path::new("/tmp/rustynetd.log"),
            std::path::Path::new("/tmp/rustynetd.log"),
        );
        assert!(plist.contains("<key>Label</key>"));
        assert!(plist.contains("com.rustynet.test"));
        assert!(plist.contains("<key>ProgramArguments</key>"));
        assert!(plist.contains("<key>EnvironmentVariables</key>"));
        assert!(plist.contains("RUSTYNET_WG_BINARY_PATH"));
    }

    #[test]
    fn interface_absent_detail_detection_is_case_insensitive() {
        assert!(is_interface_absent_detail(
            "Cannot find device \"rustynet0\""
        ));
        assert!(is_interface_absent_detail("No such device"));
        assert!(!is_interface_absent_detail("operation not permitted"));
    }

    #[test]
    fn macos_keychain_account_validation_rejects_invalid_values() {
        assert!(required_macos_tunnel_keychain_account("tunnel-passphrase-node").is_ok());
        assert!(required_macos_tunnel_keychain_account("").is_err());
        assert!(required_macos_tunnel_keychain_account("bad account with spaces").is_err());
    }

    #[test]
    fn parse_bool_value_matches_systemd_script_contract() {
        assert!(parse_bool_value("TEST_BOOL", "true").expect("true should parse"));
        assert!(!parse_bool_value("TEST_BOOL", "off").expect("off should parse"));
        assert!(!parse_bool_value("TEST_BOOL", "").expect("empty should parse"));
        assert!(parse_bool_value("TEST_BOOL", "bogus").is_err());
    }

    #[test]
    fn parse_bundle_field_ignores_whitespace() {
        let body = "version=1\nexpires_at_unix=  12345  \n";
        assert_eq!(parse_bundle_u64_field(body, "expires_at_unix"), Some(12345));
        assert_eq!(parse_bundle_u64_field(body, "generated_at_unix"), None);
    }

    #[cfg(unix)]
    #[test]
    fn signing_key_loader_rejects_group_readable_file() {
        use std::os::unix::fs::PermissionsExt;

        let unique = format!(
            "rustynet-cli-signing-key-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let dir = std::env::temp_dir().join(format!("{unique}.dir"));
        std::fs::create_dir_all(&dir).expect("test dir should exist");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .expect("test dir permissions should be strict");
        let path = dir.join("signing.key.enc");
        let passphrase_path = dir.join("passphrase.txt");
        std::fs::write(&passphrase_path, "00112233445566778899aabbccddeeff\n")
            .expect("passphrase file should exist");
        std::fs::set_permissions(&passphrase_path, std::fs::Permissions::from_mode(0o600))
            .expect("passphrase permissions should be set");
        persist_encrypted_secret_material(
            &path,
            &[0x11; 32],
            &passphrase_path,
            "signing key",
            false,
        )
        .expect("encrypted signing key should be written");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))
            .expect("permissions should be set");

        let result = load_signing_key(&path, &passphrase_path);
        assert!(result.is_err());
        let message = result.expect_err("weak file permissions must fail");
        assert!(message.contains("owner-only"));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn signing_key_loader_rejects_symlink_path() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let unique = format!(
            "rustynet-cli-signing-key-symlink-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let dir = std::env::temp_dir().join(format!("{unique}.dir"));
        std::fs::create_dir_all(&dir).expect("test dir should exist");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .expect("test dir permissions should be strict");
        let target = dir.join("signing.target.key.enc");
        let link = dir.join("signing.key.enc");
        let passphrase_path = dir.join("passphrase.txt");
        std::fs::write(&passphrase_path, "00112233445566778899aabbccddeeff\n")
            .expect("passphrase file should exist");
        std::fs::set_permissions(&passphrase_path, std::fs::Permissions::from_mode(0o600))
            .expect("passphrase permissions should be set");
        persist_encrypted_secret_material(
            &target,
            &[0x22; 32],
            &passphrase_path,
            "signing key",
            false,
        )
        .expect("encrypted signing key should be written");
        symlink(&target, &link).expect("symlink should be created");

        let result = load_signing_key(&link, &passphrase_path);
        assert!(result.is_err());
        let message = result.expect_err("symlink key path must fail");
        assert!(message.contains("must not be a symlink"));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn signing_key_loader_accepts_owner_only_file() {
        use std::os::unix::fs::PermissionsExt;

        let unique = format!(
            "rustynet-cli-signing-key-ok-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let dir = std::env::temp_dir().join(format!("{unique}.dir"));
        std::fs::create_dir_all(&dir).expect("test dir should exist");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .expect("test dir permissions should be strict");
        let path = dir.join("signing.key.enc");
        let passphrase_path = dir.join("passphrase.txt");
        std::fs::write(&passphrase_path, "00112233445566778899aabbccddeeff\n")
            .expect("passphrase file should exist");
        std::fs::set_permissions(&passphrase_path, std::fs::Permissions::from_mode(0o600))
            .expect("passphrase permissions should be set");
        persist_encrypted_secret_material(
            &path,
            &[0x33; 32],
            &passphrase_path,
            "signing key",
            false,
        )
        .expect("encrypted signing key should be written");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("permissions should be set");

        let result = load_signing_key(&path, &passphrase_path);
        assert!(result.is_ok());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn secure_remove_file_rejects_directory() {
        let unique = format!(
            "rustynet-cli-secure-remove-dir-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let dir = std::env::temp_dir().join(format!("{unique}.dir"));
        std::fs::create_dir_all(&dir).expect("test dir should exist");

        let err =
            super::secure_remove_file(&dir).expect_err("secure remove must reject directories");
        assert!(err.contains("regular file"));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn secure_remove_file_removes_target_file() {
        use std::os::unix::fs::PermissionsExt;

        let unique = format!(
            "rustynet-cli-secure-remove-file-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let dir = std::env::temp_dir().join(format!("{unique}.dir"));
        std::fs::create_dir_all(&dir).expect("test dir should exist");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .expect("test dir permissions should be strict");
        let path = dir.join("secret.tmp");
        std::fs::write(&path, b"temporary-secret").expect("secret file should exist");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("secret file mode should be owner-only");

        super::secure_remove_file(&path).expect("secure remove should succeed");
        assert!(!path.exists(), "secure remove should delete the file");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn create_secure_temp_file_sets_owner_only_mode() {
        use std::os::unix::fs::PermissionsExt;

        let unique = format!(
            "rustynet-cli-secure-temp-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let dir = std::env::temp_dir().join(format!("{unique}.dir"));
        std::fs::create_dir_all(&dir).expect("test dir should exist");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .expect("test dir permissions should be strict");

        let temp = super::create_secure_temp_file(&dir, "secrets-test.")
            .expect("secure temp file allocation should succeed");
        let mode = std::fs::metadata(&temp)
            .expect("temporary file metadata should be readable")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "secure temp files must be owner-only");

        super::secure_remove_file(&temp).expect("cleanup should succeed");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn install_trust_material_file_rejects_symlink_destination() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let unique = format!(
            "rustynet-cli-trust-material-symlink-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let dir = std::env::temp_dir().join(format!("{unique}.dir"));
        std::fs::create_dir_all(&dir).expect("test dir should exist");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .expect("test dir permissions should be strict");

        let source = dir.join("trust.source");
        std::fs::write(&source, b"version=1\n").expect("source should be written");
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o600))
            .expect("source mode should be strict");

        let destination_target = dir.join("trust.dest.target");
        std::fs::write(&destination_target, b"old\n").expect("target file should exist");
        let destination = dir.join("trust.dest");
        symlink(&destination_target, &destination).expect("destination symlink should exist");

        let err = super::install_trust_material_file(
            source.as_path(),
            destination.as_path(),
            nix::unistd::Uid::effective(),
            nix::unistd::Gid::effective(),
            0o600,
            "trust evidence",
        )
        .expect_err("symlink destination must fail");
        assert!(err.contains("must not be a symlink"));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn install_trust_material_file_copies_with_expected_mode() {
        use std::os::unix::fs::PermissionsExt;

        let unique = format!(
            "rustynet-cli-trust-material-copy-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let dir = std::env::temp_dir().join(format!("{unique}.dir"));
        std::fs::create_dir_all(&dir).expect("test dir should exist");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .expect("test dir permissions should be strict");

        let source = dir.join("trust.source");
        std::fs::write(&source, b"version=1\nupdated_at_unix=1\n")
            .expect("source should be written");
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o600))
            .expect("source mode should be strict");

        let destination = dir.join("trust.dest");
        super::install_trust_material_file(
            source.as_path(),
            destination.as_path(),
            nix::unistd::Uid::effective(),
            nix::unistd::Gid::effective(),
            0o640,
            "trust evidence",
        )
        .expect("file install should succeed");

        let copied = std::fs::read(&destination).expect("destination should be readable");
        assert_eq!(copied, b"version=1\nupdated_at_unix=1\n");
        let mode = std::fs::metadata(&destination)
            .expect("destination metadata should be readable")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o640, "destination mode should match requested mode");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn daemon_runtime_ready_status_requires_non_restricted_non_failed_state() {
        assert!(super::daemon_runtime_ready_from_status_text(
            "node_id=daemon-local state=DataplaneApplied restricted_safe_mode=false bootstrap_error=none last_reconcile_error=none"
        ));
        assert!(!super::daemon_runtime_ready_from_status_text(
            "node_id=daemon-local state=FailClosed restricted_safe_mode=true bootstrap_error=error last_reconcile_error=error"
        ));
        assert!(!super::daemon_runtime_ready_from_status_text(
            "node_id=daemon-local state=DataplaneApplied restricted_safe_mode=false bootstrap_error=none last_reconcile_error=backend error"
        ));
    }

    #[test]
    fn route_uses_rustynet0_requires_tunnel_device() {
        assert!(super::route_uses_rustynet0(
            "1.1.1.1 dev rustynet0 table 51820 src 100.68.223.117 uid 0"
        ));
        assert!(!super::route_uses_rustynet0(
            "1.1.1.1 via 192.168.64.1 dev enp0s1 src 192.168.64.24 uid 0"
        ));
    }

    #[test]
    fn status_field_extracts_exit_node() {
        let status =
            "node_id=client-1 state=ExitActive exit_node=client-2 restricted_safe_mode=false";
        assert_eq!(
            super::status_field(status, "exit_node").as_deref(),
            Some("client-2")
        );
        assert_eq!(super::status_field(status, "missing"), None);
    }

    #[test]
    fn execute_reports_error_when_daemon_is_unreachable() {
        let output = execute(parse_command(&["status".to_string()]));
        assert!(output.is_err());
        let message = output.expect_err("daemon-unreachable path should fail");
        assert!(message.starts_with("daemon unreachable:"));
    }

    #[cfg(unix)]
    #[test]
    fn detect_tampered_log_handles_empty_membership_log() {
        use std::os::unix::fs::PermissionsExt;

        let unique = format!(
            "rustynet-cli-membership-log-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let source_log = std::env::temp_dir().join(format!("{unique}.log"));
        let output_dir = std::env::temp_dir().join(format!("{unique}.out"));

        std::fs::write(&source_log, "version=1\n").expect("source log should exist");
        std::fs::set_permissions(&source_log, std::fs::Permissions::from_mode(0o600))
            .expect("source log permissions should be owner-only");
        std::fs::create_dir_all(&output_dir).expect("output dir should exist");

        let detected =
            detect_tampered_log(&source_log, &output_dir).expect("tamper detection should run");
        assert!(
            detected,
            "empty log tampering should be detected fail-closed"
        );

        let _ = std::fs::remove_file(source_log);
        let _ = std::fs::remove_dir_all(output_dir);
    }

    #[cfg(unix)]
    #[test]
    fn control_socket_validator_rejects_regular_file_path() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!(
            "rustynet-cli-control-socket-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("test dir should exist");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .expect("test dir permissions should be strict");
        let path = dir.join("rustynetd.sock");
        std::fs::write(&path, b"not-a-socket").expect("regular file should be written");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("regular file permissions should be owner-only");

        let err = validate_control_socket_security(&path, "daemon socket")
            .expect_err("regular file must not validate as a socket");
        assert!(err.contains("must be a Unix socket"));

        let _ = std::fs::remove_dir_all(dir);
    }
}
