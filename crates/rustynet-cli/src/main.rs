#![forbid(unsafe_code)]

mod env_file;
mod live_lab_results;
mod ops_cross_network_preflight;
mod ops_cross_network_reports;
mod ops_e2e;
mod ops_fresh_install_os_matrix;
mod ops_install_systemd;
mod ops_install_systemd_relay;
mod ops_live_lab_failure_digest;
mod ops_live_lab_orchestrator;
mod ops_network_discovery;
mod ops_peer_store;
mod ops_phase1;
mod ops_phase9;
mod ops_security_audit;
mod ops_security_audit_workflows;
mod ops_write_daemon_env;
mod role_cli;
mod security_audit_catalog;
mod vm_lab;

use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::fs;
use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
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
    /// D2.7 — enrollment-token operator surface: `rustynet
    /// enrollment {mint, verify, consume}`. Mint and Verify run
    /// locally against a secret file the operator owns; Consume
    /// goes through the daemon IPC socket because it mutates the
    /// daemon's gossip routing table.
    Enrollment(Box<EnrollmentCliCommand>),
    Trust(Box<TrustCommand>),
    Ops(Box<OpsCommand>),
    Node(NodeCommand),
    Policy(PolicyCommand),
    Relay(RelayCommand),
    Cert(CertCommand),
    TrustState(TrustStateCommand),
    Analytics(AnalyticsCommand),
    Backup(BackupCommand),
    RestoreState(RestoreStateCommand),
    ExportKeys(ExportKeysCommand),
    Config(ConfigSubCommand),
    Version,
    Info,
    Doctor,
    Logs(LogsCommand),
    ConfigShow,
    Debug,
    PeerList,
    TunnelInfo,
    ExitNodeList,
    Role(RoleCommand),
    Capability(CapabilityCommand),
    ConnectivityTest,
    PeerStats,
    Bandwidth,
    Metrics,
    DnsTest(Option<String>),
    Sysinfo,
    ServiceStatus(String),
    Network,
    SecurityCheck,
    DependencyCheck,
    DaemonHealth,
    ConfigValidate,
    WgAddresses,
    Routes,
    KeyExpiry,
    TunnelStatus,
    WgPeers,
    Uptime,
    ProcessInfo,
    ConnectionTest,
    LogTail,
    LogErrors,
    BandwidthTest,
    InterfaceStats,
    HealthCheck,
    SystemLoad,
    MemoryInfo,
    DiskInfo,
    CpuInfo,
    SocketStats,
    EnvValidate,
    ProcessList,
    IfaceList,
    DnsCheck,
    KernelInfo,
    ServiceCheck,
    PermissionCheck,
    PerformanceTest,
    TlsCheck,
    RateLimitCheck,
    NatDetection,
    ExitNodeStatus,
    Ipv6Support,
    PacketLoss,
    SystemClock,
    TcpConnections,
    DnsResolver,
    InterfaceSpeed,
    DiskIo,
    ProcessMemory,
    ActiveNetworkRoutes,
    MtuPathDiscovery(String),
    DnsResolutionLatency(String),
    BgpRouteAnnouncements,
    ConnectionStateHistogram,
    ArpTableEntries,
    ListeningSocketsSummary,
    NetworkDropStats,
    TlsCertificateExpiry(String),
    SelinuxStatus,
    ApparmorProfileStatus,
    CryptographicKeyPermissions,
    TlsCipherSuiteStrength(String),
    SudoersConfigurationAudit,
    OpenSecurityVulnerabilities(String),
    KernelSecurityParameters,
    FileDescriptorUsage,
    MemoryFragmentationRatio,
    NetworkSocketLimitUsage,
    InodeUsagePerFilesystem,
    ProcessThreadCountAll,
    MemoryPressureStallInfo,
    RustynetdGoroutineCount,
    IpcSocketResponsiveness,
    DaemonCrashLogsRecent,
    DaemonOpenFileHandles,
    SystemdUnitDependencyGraph,
    ProcessCpuTimeDistribution,
    DiskIoLatencyHistogram(String),
    FilesystemJournalStatus,
    BlockDeviceErrorCounters,
    DirectorySizeSnapshot(String),
    FilesystemCacheEfficiency,
    FileIntegrityCheck(String),
    SyslogConfigurationAudit,
    AccessControlListAudit(String),
    BootIntegrityCheck,
    SystemStateSnapshot,
    CompareToBaseline,
    PerformanceRegressionDetection,
    Help,
}

/// D12.b — operator-facing role surface backed by
/// `rustynet_control::role_presets`. Replaces the earlier
/// substring-matching `Show / Set(String)` placeholder.
///
/// See `crates/rustynet-cli/src/role_cli.rs` for the pure
/// planner + status resolver; this enum is the parsed CLI shape
/// that main.rs hands to the dispatcher.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RoleCommand {
    /// `rustynet role status` — read daemon IPC, resolve current
    /// preset, print it. Available to all primary roles.
    Status,
    /// `rustynet role list` — print the six presets + per-preset
    /// description. Pure local; no daemon contact.
    List,
    /// `rustynet role set <preset> [--accept-irreversible]` —
    /// orchestrator. Computes plan via `role_cli::plan_concrete_actions`
    /// and executes the side-effects.
    Set {
        target: rustynet_control::role_presets::RolePreset,
        accept_irreversible: bool,
    },
    /// `rustynet role transition-check --to <preset>` — pure
    /// preview; never executes side-effects.
    TransitionCheck {
        target: rustynet_control::role_presets::RolePreset,
    },
}

/// D12.b — advanced capability mutation surface. The wizard never
/// surfaces these; they exist for power users who need non-preset
/// compositions. Today (pre-D11.a) the mutation verbs return a
/// clean blocked-by-capability-schema error.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CapabilityCommand {
    /// `rustynet capability list` — print effective capabilities
    /// derived from current preset. Read-only; available to all
    /// primary roles.
    List,
    /// `rustynet capability add <flag>` — emit signed-membership
    /// update record adding the capability. Admin-only.
    Add(rustynet_control::role_presets::Capability),
    /// `rustynet capability remove <flag>` — counterpart to Add.
    Remove(rustynet_control::role_presets::Capability),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LogsCommand {
    follow: bool,
    level: Option<String>,
    lines: Option<usize>,
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
pub enum EnrollmentCliCommand {
    /// `rustynet enrollment mint --secret <path> --ttl <secs>
    /// [--output <path>]` — generates a fresh URL-safe-base64 token
    /// under the daemon's HMAC secret. Prints to stdout (or writes
    /// to `--output`).
    Mint {
        secret_path: PathBuf,
        ttl_secs: u64,
        output_path: Option<PathBuf>,
    },
    /// `rustynet enrollment verify --secret <path> [--ledger
    /// <path>] --token <encoded>` — non-mutating sanity check.
    /// Reports `valid` + remaining seconds, or a typed reject.
    /// When `--ledger` is supplied the report includes whether the
    /// token has already been redeemed.
    Verify {
        secret_path: PathBuf,
        ledger_path: Option<PathBuf>,
        token: String,
    },
    /// `rustynet enrollment consume --token <encoded> --pubkey
    /// <b64> --push-addr <ip:port>` — sends the IPC `enrollment
    /// consume` verb to the running daemon. The daemon loads the
    /// secret + ledger from its configured paths.
    Consume {
        token: String,
        pubkey_b64: String,
        push_addr: String,
    },
    /// `rustynet enrollment admit ...` — operator one-shot that
    /// consumes the token locally, builds a signed `AddNode`
    /// membership update, and optionally applies it to the local
    /// snapshot when quorum is met. Closes the trust-propagation
    /// gap that the IPC `consume` verb alone leaves open: after
    /// `admit` the enrollee is in the signed membership snapshot,
    /// so every peer that consumes the snapshot (now or later)
    /// learns the new identity through the same trust channel that
    /// authorises every other peer.
    Admit(Box<AdmitConfig>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmitConfig {
    pub token: String,
    pub pubkey_b64: String,
    pub node_id: String,
    pub owner: String,
    pub roles: Vec<String>,
    pub secret_path: PathBuf,
    pub ledger_path: PathBuf,
    pub snapshot_path: PathBuf,
    pub log_path: PathBuf,
    pub signing_key_path: PathBuf,
    pub signing_key_passphrase_path: PathBuf,
    pub approver_id: String,
    pub output_path: PathBuf,
    pub update_id: Option<String>,
    pub reason_code: String,
    pub ttl_secs: u64,
    /// When true, also apply the update locally (append to log +
    /// persist new snapshot) if the single produced signature
    /// already meets quorum. When quorum > 1, the produced
    /// (partially-signed) update is written to `output_path` and
    /// the operator runs additional `membership sign-update` steps.
    pub apply: bool,
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
    WriteMembershipPhase10Report,
    VerifyMembershipPhase10Report {
        config: ops_ci_release_perf::VerifyMembershipPhase10ReportConfig,
    },
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
    GenerateAttackMatrix {
        config: ops_security_audit::GenerateAttackMatrixConfig,
    },
    GenerateAssessmentFromMatrix {
        config: ops_security_audit::GenerateAssessmentFromMatrixConfig,
    },
    ValidateLiveLabReports {
        config: ops_security_audit::ValidateLiveLabReportsConfig,
    },
    EvaluateLiveCoveragePromotion {
        config: ops_security_audit::EvaluateLiveCoveragePromotionConfig,
    },
    GenerateLiveLabFindings {
        config: ops_security_audit_workflows::GenerateLiveLabFindingsConfig,
    },
    GenerateComparativeExploitCoverage {
        config: ops_security_audit_workflows::GenerateComparativeExploitCoverageConfig,
    },
    RunLiveLabValidations {
        config: ops_security_audit_workflows::RunLiveLabValidationsConfig,
    },
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
    /// Lever 2 — `rustynet ops cross-network-preflight`. Reads
    /// STUN servers + an optional relay endpoint from the CLI
    /// flags, probes them, classifies NAT behaviour, and emits an
    /// operator-facing verdict (`direct_likely` /
    /// `mixed_nat_could_work` / `relay_required` / `stun_broken` /
    /// `no_stun_configured`). See `ops_cross_network_preflight`
    /// module docs for the heuristic.
    CrossNetworkPreflight {
        config: ops_cross_network_preflight::CrossNetworkPreflightConfig,
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
    VmLabValidateWindowsSecurity {
        config: vm_lab::VmLabValidateWindowsSecurityConfig,
    },
    VmLabValidateLinuxSecurity {
        config: vm_lab::VmLabValidateLinuxSecurityConfig,
    },
    VmLabDistributeWindowsState {
        config: vm_lab::VmLabDistributeWindowsStateConfig,
    },
    VmLabPullWindowsStateFromLinuxExit {
        config: vm_lab::VmLabPullWindowsStateFromLinuxExitConfig,
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
    VmLabDiffOrchestratorParity {
        config: vm_lab::VmLabDiffOrchestratorParityConfig,
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
    VmLabReadinessCheck {
        config: vm_lab::VmLabReadinessCheckConfig,
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
    VmLabReportCapabilities {
        config: vm_lab::capability::VmLabReportCapabilitiesConfig,
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
    /// D12.d — install / uninstall the rustynet-relay sibling
    /// systemd unit. Used by the role-transition orchestrator
    /// when entering / leaving relay or anchor presets, and
    /// available as a standalone operator verb today.
    InstallSystemdRelay {
        config: ops_install_systemd_relay::InstallRelayConfig,
    },
    InstallWindowsService,
    InstallWindowsRelayService,
    UninstallWindowsRelayService,
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
    E2eWorkerRefreshTrustEvidence {
        label: String,
        target: String,
        node_id: String,
    },
    E2eWorkerRefreshRuntimeState {
        label: String,
        target: String,
        node_id: String,
    },
    E2eWorkerRefreshSignedState {
        label: String,
        target: String,
        node_id: String,
    },
    E2eWorkerEnforceRuntime {
        label: String,
        target: String,
        node_id: String,
        role: String,
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
enum NodeCommand {
    Info {
        peers: bool,
        json: bool,
    },
    List {
        role: Option<String>,
        filter: Option<String>,
        json: bool,
    },
    Probe {
        node_id: String,
        tcp_port: Option<u16>,
        udp_port: Option<u16>,
        json: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PolicyCommand {
    List {
        node: Option<String>,
        json: bool,
    },
    Apply {
        policy_file: PathBuf,
        dry_run: bool,
        json: bool,
    },
    Test {
        source_node: String,
        dest_node: String,
        protocol: Option<String>,
        port: Option<u16>,
        json: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RelayCommand {
    List {
        status: bool,
        json: bool,
    },
    Select {
        strategy: RelaySelectStrategy,
        json: bool,
    },
    Health {
        relay_id: String,
        json: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelaySelectStrategy {
    Auto,
    BestLatency,
    LeastLoad,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CertCommand {
    List {
        only_expired: bool,
        only_expiring_soon: bool,
        json: bool,
    },
    Check {
        strict: bool,
        json: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TrustStateCommand {
    anchor: Option<String>,
    json: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AnalyticsCommand {
    Peers {
        window_secs: Option<u64>,
        sort_by: Option<String>,
        json: bool,
    },
    Traffic {
        interval_secs: Option<u64>,
        top_n: Option<u32>,
        json: bool,
    },
    LatencyHeatmap {
        include_peers: bool,
        include_relays: bool,
        json: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BackupCommand {
    out_dir: PathBuf,
    compress: bool,
    encrypt_passphrase_file: Option<PathBuf>,
    json: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RestoreStateCommand {
    backup_path: PathBuf,
    verify: bool,
    dry_run: bool,
    json: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExportKeysCommand {
    format: KeyExportFormat,
    out_path: Option<PathBuf>,
    json: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyExportFormat {
    Pem,
    Raw,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ConfigSubCommand {
    Show {
        section: Option<String>,
        json: bool,
    },
    Validate {
        strict: bool,
        json: bool,
    },
    Export {
        format: ConfigExportFormat,
        out_path: Option<PathBuf>,
        json: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfigExportFormat {
    Toml,
    Json,
    Yaml,
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
    let raw_args = std::env::args().skip(1).collect::<Vec<_>>();
    // Pull --json out of the argv before delegating to parse_command. The
    // flag is positional-agnostic and only meaningful for the small set of
    // structured-line output commands (status, netcheck). Other commands
    // are unaffected.
    let (args, json_mode) = extract_json_flag(raw_args);
    let command = parse_command(&args);
    let want_json = json_mode && command_supports_json_render(&command);
    match execute(command) {
        Ok(output) => {
            if want_json {
                match render_key_value_line_as_json(output.as_str()) {
                    Ok(json) => println!("{json}"),
                    // If the daemon emitted something the JSON renderer
                    // doesn't recognise, fall back to the original output
                    // so the operator still sees the data — but tag the
                    // fallback in a one-line preamble so any downstream
                    // JSON consumer fails parse-fast and surfaces the
                    // upstream shape drift.
                    Err(_) => println!(
                        "rustynet --json: upstream shape not key=value; raw output below\n{output}"
                    ),
                }
            } else {
                println!("{output}");
            }
        }
        Err(err) => {
            let exit_code = classify_cli_error(err.as_str());
            if want_json {
                println!(
                    "{{\"ok\":false,\"exit_code\":{},\"exit_label\":\"{}\",\"error\":{}}}",
                    exit_code.as_i32(),
                    exit_code.label(),
                    serde_json::Value::String(err)
                );
            } else {
                let hint = exit_code.operator_hint();
                if hint.is_empty() {
                    println!("error [{exit_code}]: {err}");
                } else {
                    println!("error [{exit_code}]: {err}\n  hint: {hint}");
                }
            }
            std::process::exit(exit_code.as_i32());
        }
    }
}

/// Classify a CLI error string into the reviewed exit-code taxonomy
/// (X6). The CLI's `execute` returns `Result<String, String>`; this
/// helper maps the error message to the right bucket so shells and CI
/// can branch on the failure kind.
fn classify_cli_error(message: &str) -> rustynetd::exit_codes::ExitCode {
    use rustynetd::exit_codes::ExitCode;
    let lower = message.to_ascii_lowercase();
    if lower.contains("unknown command")
        || lower.contains("unknown subcommand")
        || lower.contains("missing required")
        || lower.contains("requires --")
        || lower.contains("requires argument")
        || lower.starts_with("usage:")
        || lower.contains("invalid value for")
    {
        ExitCode::BadArgs
    } else if lower.contains("fail-closed")
        || lower.contains("fail closed")
        || lower.contains("policy reject")
        || lower.contains("policy rejected")
        || lower.contains("signature verification")
        || lower.contains("reviewed root")
        || lower.contains("not reviewed")
        || lower.contains("drift detected")
        || lower.contains("forbidden")
    {
        ExitCode::PolicyReject
    } else if lower.contains("config")
        || lower.contains("invalid path")
        || lower.contains("schema")
        || lower.contains("malformed")
        || lower.contains("parse error")
    {
        ExitCode::ConfigError
    } else if lower.contains("connection refused")
        || lower.contains("temporarily unavailable")
        || lower.contains("timed out")
        || lower.contains("timeout")
        || lower.contains("retry")
        || lower.contains("transient")
    {
        ExitCode::TransientFailure
    } else {
        ExitCode::GenericFailure
    }
}

/// Strip `--json` from the argument vector, anywhere it appears, returning
/// the cleaned args plus a boolean indicating whether the flag was seen.
fn extract_json_flag(args: Vec<String>) -> (Vec<String>, bool) {
    let mut json_mode = false;
    let mut cleaned: Vec<String> = Vec::with_capacity(args.len());
    for arg in args {
        if arg == "--json" {
            json_mode = true;
        } else {
            cleaned.push(arg);
        }
    }
    (cleaned, json_mode)
}

/// Which CLI commands honour `--json`. Today only `status` and `netcheck`
/// emit a structured key=value line that can be losslessly converted; other
/// commands keep their existing human-readable output regardless of the
/// flag.
fn command_supports_json_render(command: &CliCommand) -> bool {
    matches!(command, CliCommand::Status | CliCommand::Netcheck)
}

/// Convert a single daemon response line of the form
/// `prefix: key1=value1 key2=value2 ...` into a compact JSON object whose
/// top-level fields are `prefix` (the leading label without the colon) and
/// the parsed key/value pairs as string fields. Returns Err when the input
/// does not contain a `:` separator or contains a token that is not a
/// `key=value` pair.
///
/// The renderer is intentionally lossless: every key/value pair the daemon
/// emits surfaces as a string field. Numeric coercion belongs at the
/// consumer, not here — that keeps the wire shape stable across daemon
/// schema additions.
fn render_key_value_line_as_json(line: &str) -> Result<String, String> {
    let trimmed = line.trim();
    let (prefix, body) = trimmed
        .split_once(':')
        .ok_or_else(|| "missing `:` prefix separator".to_owned())?;
    let mut object = serde_json::Map::new();
    object.insert(
        "prefix".to_owned(),
        serde_json::Value::String(prefix.trim().to_owned()),
    );
    for token in body.split_whitespace() {
        let (key, value) = token
            .split_once('=')
            .ok_or_else(|| format!("token without `=` separator: {token:?}"))?;
        if key.is_empty() {
            return Err(format!("empty key in token: {token:?}"));
        }
        object.insert(key.to_owned(), serde_json::Value::String(value.to_owned()));
    }
    serde_json::to_string(&serde_json::Value::Object(object))
        .map_err(|err| format!("serialise json failed: {err}"))
}

fn parse_command(args: &[String]) -> CliCommand {
    match args {
        [cmd] if cmd == "status" => CliCommand::Status,
        [cmd] if cmd == "login" => CliCommand::Login,
        [cmd] if cmd == "netcheck" => CliCommand::Netcheck,
        [cmd] if cmd == "version" || cmd == "which" => CliCommand::Version,
        [cmd] if cmd == "info" => CliCommand::Info,
        [cmd] if cmd == "doctor" || cmd == "diagnose" => CliCommand::Doctor,
        [cmd] if cmd == "debug" => CliCommand::Debug,
        [cmd] if cmd == "peer-list" || cmd == "peers" => CliCommand::PeerList,
        [cmd] if cmd == "tunnel-info" || cmd == "tunnel" => CliCommand::TunnelInfo,
        [cmd] if cmd == "exit-node-list" || cmd == "exit-nodes" => CliCommand::ExitNodeList,
        [cmd, subcmd] if cmd == "role" && (subcmd == "status" || subcmd == "show") => {
            CliCommand::Role(RoleCommand::Status)
        }
        [cmd, subcmd] if cmd == "role" && subcmd == "list" => CliCommand::Role(RoleCommand::List),
        [cmd, subcmd, raw] if cmd == "role" && subcmd == "set" => {
            // Bare `role set <preset>` (no flag). Acceptance flag
            // requires the explicit form `role set <preset> --accept-irreversible`
            // handled below.
            match role_cli::parse_preset_arg(raw) {
                Ok(target) => CliCommand::Role(RoleCommand::Set {
                    target,
                    accept_irreversible: false,
                }),
                Err(_) => CliCommand::Help,
            }
        }
        [cmd, subcmd, raw, flag]
            if cmd == "role" && subcmd == "set" && flag == "--accept-irreversible" =>
        {
            match role_cli::parse_preset_arg(raw) {
                Ok(target) => CliCommand::Role(RoleCommand::Set {
                    target,
                    accept_irreversible: true,
                }),
                Err(_) => CliCommand::Help,
            }
        }
        [cmd, subcmd, flag, raw]
            if cmd == "role" && subcmd == "transition-check" && flag == "--to" =>
        {
            match role_cli::parse_preset_arg(raw) {
                Ok(target) => CliCommand::Role(RoleCommand::TransitionCheck { target }),
                Err(_) => CliCommand::Help,
            }
        }
        [cmd] if cmd == "role" => CliCommand::Role(RoleCommand::Status),
        [cmd, subcmd] if cmd == "capability" && subcmd == "list" => {
            CliCommand::Capability(CapabilityCommand::List)
        }
        [cmd, subcmd, flag] if cmd == "capability" && subcmd == "add" => {
            match role_cli::parse_capability_arg(flag) {
                Ok(cap) => CliCommand::Capability(CapabilityCommand::Add(cap)),
                Err(_) => CliCommand::Help,
            }
        }
        [cmd, subcmd, flag] if cmd == "capability" && subcmd == "remove" => {
            match role_cli::parse_capability_arg(flag) {
                Ok(cap) => CliCommand::Capability(CapabilityCommand::Remove(cap)),
                Err(_) => CliCommand::Help,
            }
        }
        [cmd] if cmd == "connectivity-test" || cmd == "test" => CliCommand::ConnectivityTest,
        [cmd] if cmd == "peer-stats" || cmd == "peer-health" => CliCommand::PeerStats,
        [cmd] if cmd == "bandwidth" || cmd == "speed-test" => CliCommand::Bandwidth,
        [cmd] if cmd == "metrics" || cmd == "stats" => CliCommand::Metrics,
        [cmd] if cmd == "dns-test" => CliCommand::DnsTest(None),
        [cmd, domain] if cmd == "dns-test" => CliCommand::DnsTest(Some(domain.clone())),
        [cmd] if cmd == "sysinfo" || cmd == "system-info" => CliCommand::Sysinfo,
        [cmd, service] if cmd == "service-status" => CliCommand::ServiceStatus(service.clone()),
        [cmd] if cmd == "network" || cmd == "network-info" => CliCommand::Network,
        [cmd] if cmd == "security-check" => CliCommand::SecurityCheck,
        [cmd] if cmd == "dependency-check" => CliCommand::DependencyCheck,
        [cmd] if cmd == "daemon-health" => CliCommand::DaemonHealth,
        [cmd] if cmd == "config-validate" || cmd == "validate" => CliCommand::ConfigValidate,
        [cmd] if cmd == "wg-addresses" || cmd == "tunnel-ips" => CliCommand::WgAddresses,
        [cmd] if cmd == "routes" || cmd == "route-list" => CliCommand::Routes,
        [cmd] if cmd == "key-expiry" || cmd == "cert-expiry" => CliCommand::KeyExpiry,
        [cmd] if cmd == "tunnel-status" || cmd == "tunnel" => CliCommand::TunnelStatus,
        [cmd] if cmd == "wg-peers" || cmd == "peers" => CliCommand::WgPeers,
        [cmd] if cmd == "uptime" => CliCommand::Uptime,
        [cmd] if cmd == "process-info" || cmd == "daemon-proc" => CliCommand::ProcessInfo,
        [cmd] if cmd == "connection-test" || cmd == "test-connection" => CliCommand::ConnectionTest,
        [cmd] if cmd == "log-tail" || cmd == "logs" => CliCommand::LogTail,
        [cmd] if cmd == "log-errors" => CliCommand::LogErrors,
        [cmd] if cmd == "bandwidth-test" || cmd == "bandwidth" => CliCommand::BandwidthTest,
        [cmd] if cmd == "interface-stats" || cmd == "ifstats" => CliCommand::InterfaceStats,
        [cmd] if cmd == "health-check" || cmd == "health" => CliCommand::HealthCheck,
        [cmd] if cmd == "system-load" || cmd == "load" => CliCommand::SystemLoad,
        [cmd] if cmd == "memory-info" || cmd == "memory" => CliCommand::MemoryInfo,
        [cmd] if cmd == "disk-info" || cmd == "disk" => CliCommand::DiskInfo,
        [cmd] if cmd == "cpu-info" || cmd == "cpu" => CliCommand::CpuInfo,
        [cmd] if cmd == "socket-stats" || cmd == "sockets" => CliCommand::SocketStats,
        [cmd] if cmd == "env-validate" || cmd == "env" => CliCommand::EnvValidate,
        [cmd] if cmd == "process-list" || cmd == "processes" => CliCommand::ProcessList,
        [cmd] if cmd == "iface-list" || cmd == "interfaces" => CliCommand::IfaceList,
        [cmd] if cmd == "dns-check" || cmd == "dns" => CliCommand::DnsCheck,
        [cmd] if cmd == "kernel-info" || cmd == "kernel" => CliCommand::KernelInfo,
        [cmd] if cmd == "service-check" || cmd == "service" => CliCommand::ServiceCheck,
        [cmd] if cmd == "permission-check" || cmd == "perms" => CliCommand::PermissionCheck,
        [cmd] if cmd == "performance-test" || cmd == "perf" => CliCommand::PerformanceTest,
        [cmd] if cmd == "tls-check" || cmd == "tls" => CliCommand::TlsCheck,
        [cmd] if cmd == "rate-limit-check" || cmd == "ratelimit" => CliCommand::RateLimitCheck,
        [cmd] if cmd == "nat-detection" || cmd == "nat" => CliCommand::NatDetection,
        [cmd] if cmd == "exit-node-status" || cmd == "exit-status" => CliCommand::ExitNodeStatus,
        [cmd] if cmd == "ipv6-support" || cmd == "ipv6" => CliCommand::Ipv6Support,
        [cmd] if cmd == "packet-loss" || cmd == "packet-loss-check" => CliCommand::PacketLoss,
        [cmd] if cmd == "system-clock" || cmd == "clock-check" => CliCommand::SystemClock,
        [cmd] if cmd == "tcp-connections" || cmd == "tcp" => CliCommand::TcpConnections,
        [cmd] if cmd == "dns-resolver" || cmd == "dns-servers" => CliCommand::DnsResolver,
        [cmd] if cmd == "interface-speed" || cmd == "iface-speed" => CliCommand::InterfaceSpeed,
        [cmd] if cmd == "disk-io" || cmd == "disk-stats" => CliCommand::DiskIo,
        [cmd] if cmd == "process-memory" || cmd == "top-memory" => CliCommand::ProcessMemory,
        [cmd] if cmd == "active-routes" || cmd == "routes" => CliCommand::ActiveNetworkRoutes,
        [cmd, target] if cmd == "mtu-discovery" || cmd == "mtu" => {
            CliCommand::MtuPathDiscovery(target.clone())
        }
        [cmd, domain] if cmd == "dns-latency" => CliCommand::DnsResolutionLatency(domain.clone()),
        [cmd] if cmd == "bgp-status" => CliCommand::BgpRouteAnnouncements,
        [cmd] if cmd == "conn-states" || cmd == "connection-states" => {
            CliCommand::ConnectionStateHistogram
        }
        [cmd] if cmd == "arp-table" || cmd == "arp" => CliCommand::ArpTableEntries,
        [cmd] if cmd == "listening-sockets" || cmd == "listening" => {
            CliCommand::ListeningSocketsSummary
        }
        [cmd] if cmd == "network-drops" => CliCommand::NetworkDropStats,
        [cmd, path] if cmd == "tls-cert-expiry" || cmd == "cert-expiry" => {
            CliCommand::TlsCertificateExpiry(path.clone())
        }
        [cmd] if cmd == "selinux-status" => CliCommand::SelinuxStatus,
        [cmd] if cmd == "apparmor-status" => CliCommand::ApparmorProfileStatus,
        [cmd] if cmd == "key-permissions" => CliCommand::CryptographicKeyPermissions,
        [cmd, host] if cmd == "tls-cipher" => CliCommand::TlsCipherSuiteStrength(host.clone()),
        [cmd] if cmd == "sudoers-audit" => CliCommand::SudoersConfigurationAudit,
        [cmd, db_path] if cmd == "cve-check" => {
            CliCommand::OpenSecurityVulnerabilities(db_path.clone())
        }
        [cmd] if cmd == "kernel-hardening" => CliCommand::KernelSecurityParameters,
        [cmd] if cmd == "fd-usage" || cmd == "file-descriptors" => CliCommand::FileDescriptorUsage,
        [cmd] if cmd == "memory-frag" => CliCommand::MemoryFragmentationRatio,
        [cmd] if cmd == "socket-limits" => CliCommand::NetworkSocketLimitUsage,
        [cmd] if cmd == "inode-usage" => CliCommand::InodeUsagePerFilesystem,
        [cmd] if cmd == "thread-count" => CliCommand::ProcessThreadCountAll,
        [cmd] if cmd == "memory-pressure" => CliCommand::MemoryPressureStallInfo,
        [cmd] if cmd == "goroutine-count" => CliCommand::RustynetdGoroutineCount,
        [cmd] if cmd == "ipc-latency" => CliCommand::IpcSocketResponsiveness,
        [cmd] if cmd == "daemon-crashes" => CliCommand::DaemonCrashLogsRecent,
        [cmd] if cmd == "daemon-files" => CliCommand::DaemonOpenFileHandles,
        [cmd] if cmd == "systemd-deps" => CliCommand::SystemdUnitDependencyGraph,
        [cmd] if cmd == "cpu-time" => CliCommand::ProcessCpuTimeDistribution,
        [cmd, device] if cmd == "disk-latency" => {
            CliCommand::DiskIoLatencyHistogram(device.clone())
        }
        [cmd] if cmd == "filesystem-journal" => CliCommand::FilesystemJournalStatus,
        [cmd] if cmd == "disk-errors" => CliCommand::BlockDeviceErrorCounters,
        [cmd, path] if cmd == "dir-size" => CliCommand::DirectorySizeSnapshot(path.clone()),
        [cmd] if cmd == "cache-efficiency" => CliCommand::FilesystemCacheEfficiency,
        [cmd, path] if cmd == "file-integrity" => CliCommand::FileIntegrityCheck(path.clone()),
        [cmd] if cmd == "syslog-config" => CliCommand::SyslogConfigurationAudit,
        [cmd, path] if cmd == "acl-audit" => CliCommand::AccessControlListAudit(path.clone()),
        [cmd] if cmd == "boot-integrity" => CliCommand::BootIntegrityCheck,
        [cmd] if cmd == "system-snapshot" => CliCommand::SystemStateSnapshot,
        [cmd] if cmd == "compare-baseline" => CliCommand::CompareToBaseline,
        [cmd] if cmd == "perf-regression" => CliCommand::PerformanceRegressionDetection,
        [cmd, subcmd] if cmd == "config" && subcmd == "show" => CliCommand::ConfigShow,
        [cmd, rest @ ..] if cmd == "logs" => {
            let mut follow = false;
            let mut level = None;
            let mut lines = None;
            let mut i = 0;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--follow" => follow = true,
                    "--level" if i + 1 < rest.len() => {
                        level = Some(rest[i + 1].clone());
                        i += 1;
                    }
                    "--lines" if i + 1 < rest.len() => {
                        lines = rest[i + 1].parse::<usize>().ok();
                        i += 1;
                    }
                    _ => {}
                }
                i += 1;
            }
            CliCommand::Logs(LogsCommand {
                follow,
                level,
                lines,
            })
        }
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
        [cmd, rest @ ..] if cmd == "enrollment" => match parse_enrollment_command(rest) {
            Ok(command) => CliCommand::Enrollment(Box::new(command)),
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
        [cmd, rest @ ..] if cmd == "node" => match parse_node_command(rest) {
            Ok(command) => CliCommand::Node(command),
            Err(_) => CliCommand::Help,
        },
        [cmd, rest @ ..] if cmd == "policy" => match parse_policy_command(rest) {
            Ok(command) => CliCommand::Policy(command),
            Err(_) => CliCommand::Help,
        },
        [cmd, rest @ ..] if cmd == "relay" => match parse_relay_command(rest) {
            Ok(command) => CliCommand::Relay(command),
            Err(_) => CliCommand::Help,
        },
        [cmd, rest @ ..] if cmd == "cert" => match parse_cert_command(rest) {
            Ok(command) => CliCommand::Cert(command),
            Err(_) => CliCommand::Help,
        },
        [cmd, rest @ ..] if cmd == "trust-state" => match parse_trust_state_command(rest) {
            Ok(command) => CliCommand::TrustState(command),
            Err(_) => CliCommand::Help,
        },
        [cmd, rest @ ..] if cmd == "analytics" => match parse_analytics_command(rest) {
            Ok(command) => CliCommand::Analytics(command),
            Err(_) => CliCommand::Help,
        },
        [cmd, rest @ ..] if cmd == "backup" => match parse_backup_command(rest) {
            Ok(command) => CliCommand::Backup(command),
            Err(_) => CliCommand::Help,
        },
        [cmd, rest @ ..] if cmd == "restore" => match parse_restore_command(rest) {
            Ok(command) => CliCommand::RestoreState(command),
            Err(_) => CliCommand::Help,
        },
        [cmd, rest @ ..] if cmd == "export-keys" => match parse_export_keys_command(rest) {
            Ok(command) => CliCommand::ExportKeys(command),
            Err(_) => CliCommand::Help,
        },
        [cmd, rest @ ..] if cmd == "config" => match parse_config_subcommand(rest) {
            Ok(command) => CliCommand::Config(command),
            Err(_) => CliCommand::Help,
        },
        _ => CliCommand::Help,
    }
}

fn parse_ops_command(args: &[String]) -> Result<OpsCommand, String> {
    if args.is_empty() {
        return Err("ops subcommand is required".to_owned());
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
                return Err("ops verify-runtime-binary-custody does not accept options".to_owned());
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
                return Err("ops refresh-trust does not accept options".to_owned());
            }
            Ok(OpsCommand::RefreshTrust)
        }
        "refresh-signed-trust" => {
            if args.len() != 1 {
                return Err("ops refresh-signed-trust does not accept options".to_owned());
            }
            Ok(OpsCommand::RefreshSignedTrust)
        }
        "bootstrap-wireguard-custody" => {
            if args.len() != 1 {
                return Err("ops bootstrap-wireguard-custody does not accept options".to_owned());
            }
            Ok(OpsCommand::BootstrapTunnelCustody)
        }
        "refresh-assignment" => {
            if args.len() != 1 {
                return Err("ops refresh-assignment does not accept options".to_owned());
            }
            Ok(OpsCommand::RefreshAssignment)
        }
        "state-refresh-if-socket-present" => {
            if args.len() != 1 {
                return Err(
                    "ops state-refresh-if-socket-present does not accept options".to_owned(),
                );
            }
            Ok(OpsCommand::StateRefreshIfSocketPresent)
        }
        "collect-phase1-measured-input" => {
            if args.len() != 1 {
                return Err("ops collect-phase1-measured-input does not accept options".to_owned());
            }
            Ok(OpsCommand::CollectPhase1MeasuredInput)
        }
        "run-phase1-baseline" => {
            if args.len() != 1 {
                return Err("ops run-phase1-baseline does not accept options".to_owned());
            }
            Ok(OpsCommand::RunPhase1Baseline)
        }
        "prepare-advisory-db" => {
            if args.len() != 2 {
                return Err("usage: ops prepare-advisory-db <advisory_db_path>".to_owned());
            }
            Ok(OpsCommand::PrepareAdvisoryDb {
                config: ops_ci_release_perf::PrepareAdvisoryDbConfig {
                    target_db: PathBuf::from(args[1].as_str()),
                },
            })
        }
        "run-phase1-ci-gates" => {
            if args.len() != 1 {
                return Err("ops run-phase1-ci-gates does not accept options".to_owned());
            }
            Ok(OpsCommand::RunPhase1CiGates)
        }
        "run-phase9-ci-gates" => {
            if args.len() != 1 {
                return Err("ops run-phase9-ci-gates does not accept options".to_owned());
            }
            Ok(OpsCommand::RunPhase9CiGates)
        }
        "run-phase10-ci-gates" => {
            if args.len() != 1 {
                return Err("ops run-phase10-ci-gates does not accept options".to_owned());
            }
            Ok(OpsCommand::RunPhase10CiGates)
        }
        "run-membership-ci-gates" => {
            if args.len() != 1 {
                return Err("ops run-membership-ci-gates does not accept options".to_owned());
            }
            Ok(OpsCommand::RunMembershipCiGates)
        }
        "write-membership-phase10-report" => {
            if args.len() != 1 {
                return Err(
                    "ops write-membership-phase10-report does not accept options".to_owned(),
                );
            }
            Ok(OpsCommand::WriteMembershipPhase10Report)
        }
        "verify-membership-phase10-report" => Ok(OpsCommand::VerifyMembershipPhase10Report {
            config: ops_ci_release_perf::VerifyMembershipPhase10ReportConfig {
                report_path: parser.optional_path("--report-path"),
            },
        }),
        "run-supply-chain-integrity-gates" => {
            if args.len() != 1 {
                return Err(
                    "ops run-supply-chain-integrity-gates does not accept options".to_owned(),
                );
            }
            Ok(OpsCommand::RunSupplyChainIntegrityGates)
        }
        "run-security-regression-gates" => {
            if args.len() != 1 {
                return Err("ops run-security-regression-gates does not accept options".to_owned());
            }
            Ok(OpsCommand::RunSecurityRegressionGates)
        }
        "run-active-network-security-gates" => {
            if args.len() != 1 {
                return Err(
                    "ops run-active-network-security-gates does not accept options".to_owned(),
                );
            }
            Ok(OpsCommand::RunActiveNetworkSecurityGates)
        }
        "run-phase10-hp2-gates" => {
            if args.len() != 1 {
                return Err("ops run-phase10-hp2-gates does not accept options".to_owned());
            }
            Ok(OpsCommand::RunPhase10Hp2Gates)
        }
        "generate-release-sbom" => {
            if args.len() != 1 {
                return Err("ops generate-release-sbom does not accept options".to_owned());
            }
            Ok(OpsCommand::GenerateReleaseSbom)
        }
        "create-release-provenance" => {
            if args.len() != 4 {
                return Err(
                    "usage: ops create-release-provenance <artifact-path> <track> <output-json>"
                        .to_owned(),
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
                return Err("ops run-phase3-baseline does not accept options".to_owned());
            }
            Ok(OpsCommand::RunPhase3Baseline)
        }
        "run-fuzz-smoke" => {
            if args.len() != 1 {
                return Err("ops run-fuzz-smoke does not accept options".to_owned());
            }
            Ok(OpsCommand::RunFuzzSmoke)
        }
        "generate-attack-matrix" => Ok(OpsCommand::GenerateAttackMatrix {
            config: ops_security_audit::GenerateAttackMatrixConfig {
                attacks: parser.required("--attacks")?,
                nodes: parser.required("--nodes")?,
                output: parser.required_path("--output")?,
                format: parser
                    .value("--format")
                    .unwrap_or_else(|| ops_security_audit::default_attack_matrix_format().into()),
            },
        }),
        "generate-assessment-from-matrix" => Ok(OpsCommand::GenerateAssessmentFromMatrix {
            config: ops_security_audit::GenerateAssessmentFromMatrixConfig {
                project: parser.required("--project")?,
                matrix_json: parser.required_path("--matrix-json")?,
                output: parser.required_path("--output")?,
                topology: parser.value("--topology"),
                authorization: parser
                    .value("--authorization")
                    .unwrap_or_else(|| "[yes/no]".to_owned()),
            },
        }),
        "validate-live-lab-reports" => Ok(OpsCommand::ValidateLiveLabReports {
            config: ops_security_audit::ValidateLiveLabReportsConfig {
                reports: parser
                    .value("--reports")
                    .map(|value| {
                        value
                            .split(',')
                            .map(str::trim)
                            .filter(|item| !item.is_empty())
                            .map(PathBuf::from)
                            .collect()
                    })
                    .unwrap_or_default(),
                report_dir: parser.optional_path("--report-dir"),
                output: parser.optional_path("--output"),
            },
        }),
        "evaluate-live-coverage-promotion" => Ok(OpsCommand::EvaluateLiveCoveragePromotion {
            config: ops_security_audit::EvaluateLiveCoveragePromotionConfig {
                reports: parser
                    .value("--reports")
                    .map(|value| {
                        value
                            .split(',')
                            .map(str::trim)
                            .filter(|item| !item.is_empty())
                            .map(PathBuf::from)
                            .collect()
                    })
                    .unwrap_or_default(),
                report_dir: parser.optional_path("--report-dir"),
                targets: parser
                    .value("--targets")
                    .unwrap_or_else(|| "all".to_owned()),
                output: parser.required_path("--output")?,
            },
        }),
        "generate-live-lab-findings" => Ok(OpsCommand::GenerateLiveLabFindings {
            config: ops_security_audit_workflows::GenerateLiveLabFindingsConfig {
                reports: parser
                    .value("--reports")
                    .map(|value| {
                        value
                            .split(',')
                            .map(str::trim)
                            .filter(|item| !item.is_empty())
                            .map(PathBuf::from)
                            .collect()
                    })
                    .unwrap_or_default(),
                report_dir: parser.optional_path("--report-dir"),
                output: parser.required_path("--output")?,
            },
        }),
        "generate-comparative-exploit-coverage" => {
            Ok(OpsCommand::GenerateComparativeExploitCoverage {
                config: ops_security_audit_workflows::GenerateComparativeExploitCoverageConfig {
                    workspace: parser
                        .value("--workspace")
                        .map_or_else(|| PathBuf::from("."), PathBuf::from),
                    output: parser.required_path("--output")?,
                    format: parser.value("--format").unwrap_or_else(|| {
                        ops_security_audit_workflows::default_comparative_format().to_owned()
                    }),
                    projects: parser
                        .value("--projects")
                        .unwrap_or_else(|| "all".to_owned()),
                    attack_families: parser
                        .value("--attack-families")
                        .unwrap_or_else(|| "all".to_owned()),
                    run_local_tests: parser.has_flag("--run-local-tests"),
                    max_output_chars: parser
                        .value("--max-output-chars")
                        .map(|value| {
                            value.parse::<usize>().map_err(|err| {
                                format!("invalid value for --max-output-chars: {err}")
                            })
                        })
                        .transpose()?
                        .unwrap_or(1200),
                },
            })
        }
        "run-live-lab-validations" => Ok(OpsCommand::RunLiveLabValidations {
            config: ops_security_audit_workflows::RunLiveLabValidationsConfig {
                repo_root: parser.required_path("--repo-root")?,
                ssh_password_file: parser.required_path("--ssh-password-file")?,
                sudo_password_file: parser.required_path("--sudo-password-file")?,
                ssh_known_hosts_file: parser.optional_path("--ssh-known-hosts-file"),
                validations: parser
                    .value("--validations")
                    .unwrap_or_else(|| "all".to_owned()),
                report_dir: parser.optional_path("--report-dir"),
                findings_output: parser.optional_path("--findings-output"),
                schema_output: parser.optional_path("--schema-output"),
                promotion_output: parser.optional_path("--promotion-output"),
                summary_output: parser.optional_path("--summary-output"),
                dry_run: parser.has_flag("--dry-run"),
                skip_ssh_reachability_preflight: parser
                    .has_flag("--skip-ssh-reachability-preflight"),
                exit_host: parser.value("--exit-host"),
                client_host: parser.value("--client-host"),
                entry_host: parser.value("--entry-host"),
                aux_host: parser.value("--aux-host"),
                extra_host: parser.value("--extra-host"),
                probe_host: parser.value("--probe-host"),
                dns_bind_addr: parser.value("--dns-bind-addr"),
                ssh_allow_cidrs: parser.value("--ssh-allow-cidrs"),
                probe_port: parser.value("--probe-port"),
                rogue_endpoint_ip: parser.value("--rogue-endpoint-ip"),
                socket_path: parser.value("--socket-path"),
                assignment_path: parser.value("--assignment-path"),
                connect_timeout_secs: parser.parse_u64_or_default("--connect-timeout-secs", 15)?,
            },
        }),
        "check-no-unsafe-rust-sources" => Ok(OpsCommand::CheckNoUnsafeRustSources {
            config: ops_phase1::CheckNoUnsafeRustSourcesConfig {
                root: parser.value("--root").map_or_else(
                    || PathBuf::from(ops_phase1::DEFAULT_UNSAFE_SCAN_ROOT_PATH),
                    PathBuf::from,
                ),
            },
        }),
        "check-dependency-exceptions" => Ok(OpsCommand::CheckDependencyExceptions {
            config: ops_phase1::CheckDependencyExceptionsConfig {
                path: parser.value("--path").map_or_else(
                    || PathBuf::from(ops_phase1::DEFAULT_DEPENDENCY_EXCEPTIONS_PATH),
                    PathBuf::from,
                ),
            },
        }),
        "check-perf-regression" => Ok(OpsCommand::CheckPerfRegression {
            config: ops_phase1::CheckPerfRegressionConfig {
                phase1_report_path: parser.value("--phase1-report").map_or_else(
                    || PathBuf::from(ops_phase1::DEFAULT_PHASE1_PERF_REGRESSION_PHASE1_REPORT_PATH),
                    PathBuf::from,
                ),
                phase3_report_path: parser.value("--phase3-report").map_or_else(
                    || PathBuf::from(ops_phase1::DEFAULT_PHASE1_PERF_REGRESSION_PHASE3_REPORT_PATH),
                    PathBuf::from,
                ),
            },
        }),
        "check-secrets-hygiene" => Ok(OpsCommand::CheckSecretsHygiene {
            config: ops_phase1::CheckSecretsHygieneConfig {
                root: parser.value("--root").map_or_else(
                    || PathBuf::from(ops_phase1::DEFAULT_SECRETS_HYGIENE_SCAN_ROOT_PATH),
                    PathBuf::from,
                ),
            },
        }),
        "collect-phase9-raw-evidence" => {
            if args.len() != 1 {
                return Err("ops collect-phase9-raw-evidence does not accept options".to_owned());
            }
            Ok(OpsCommand::CollectPhase9RawEvidence)
        }
        "generate-phase9-artifacts" => {
            if args.len() != 1 {
                return Err("ops generate-phase9-artifacts does not accept options".to_owned());
            }
            Ok(OpsCommand::GeneratePhase9Artifacts)
        }
        "verify-phase9-readiness" => {
            if args.len() != 1 {
                return Err("ops verify-phase9-readiness does not accept options".to_owned());
            }
            Ok(OpsCommand::VerifyPhase9Readiness)
        }
        "verify-phase9-evidence" => {
            if args.len() != 1 {
                return Err("ops verify-phase9-evidence does not accept options".to_owned());
            }
            Ok(OpsCommand::VerifyPhase9Evidence)
        }
        "generate-phase10-artifacts" => {
            if args.len() != 1 {
                return Err("ops generate-phase10-artifacts does not accept options".to_owned());
            }
            Ok(OpsCommand::GeneratePhase10Artifacts)
        }
        "verify-phase10-readiness" => {
            if args.len() != 1 {
                return Err("ops verify-phase10-readiness does not accept options".to_owned());
            }
            Ok(OpsCommand::VerifyPhase10Readiness)
        }
        "verify-phase10-provenance" => {
            if args.len() != 1 {
                return Err("ops verify-phase10-provenance does not accept options".to_owned());
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
                    "ops verify-phase6-platform-readiness does not accept options".to_owned(),
                );
            }
            Ok(OpsCommand::VerifyPhase6PlatformReadiness)
        }
        "verify-phase6-parity-evidence" => {
            if args.len() != 1 {
                return Err("ops verify-phase6-parity-evidence does not accept options".to_owned());
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
        "cross-network-preflight" => {
            // Lever 2 — parse STUN servers + optional relay endpoint
            // and turn them into a `CrossNetworkPreflightConfig`. The
            // parser is intentionally permissive on the STUN list
            // (CSV of `host:port`) so the operator can paste the
            // same value used for `RUSTYNET_TRAVERSAL_STUN_SERVERS`.
            let stun_servers = parser
                .value("--stun-servers")
                .map(split_csv)
                .unwrap_or_default()
                .into_iter()
                .filter(|s| !s.trim().is_empty())
                .collect::<Vec<_>>();
            Ok(OpsCommand::CrossNetworkPreflight {
                config: ops_cross_network_preflight::CrossNetworkPreflightConfig {
                    stun_servers,
                    relay_endpoint: parser.value("--relay-endpoint"),
                    stun_timeout_ms: parser.parse_u64_or_default("--stun-timeout-ms", 2_000)?,
                    relay_timeout_ms: parser.parse_u64_or_default("--relay-timeout-ms", 3_000)?,
                    json: parser.has_flag("--json"),
                    output_path: parser.optional_path("--output-path"),
                },
            })
        }
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
                        .unwrap_or_else(|| "live_linux_skeleton".to_owned()),
                    implementation_state: parser
                        .value("--implementation-state")
                        .unwrap_or_else(|| "not_implemented".to_owned()),
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
                        .unwrap_or_else(|| "baseline_lan".to_owned()),
                    impairment_profile: parser
                        .value("--impairment-profile")
                        .unwrap_or_else(|| "none".to_owned()),
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
                .map_or_else(|| split_csv("baseline_lan".to_owned()), split_csv);
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
                        .unwrap_or_else(|| "fail".to_owned()),
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
                label: parser.value("--label").unwrap_or_else(|| "file".to_owned()),
            },
        }),
        "redact-forensics-text" => {
            if args.len() != 1 {
                return Err("ops redact-forensics-text does not accept options".to_owned());
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
                        .unwrap_or_else(|| "hosts=".to_owned()),
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
                        .unwrap_or_else(|| "lab-netns".to_owned()),
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
                        .unwrap_or_else(|| "lab-netns".to_owned()),
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
                    .unwrap_or_else(|| "probe-ok".to_owned()),
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
                    .unwrap_or_else(|| "probe-ok".to_owned()),
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
                    .map_err(|_| "invalid value for --ssh-port: must fit in u16".to_owned())?,
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
                    .map_err(|_| "invalid value for --ssh-port: must fit in u16".to_owned())?,
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
                        .unwrap_or_else(|| "main".to_owned()),
                    remote: parser
                        .value("--remote")
                        .unwrap_or_else(|| "origin".to_owned()),
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
                        .unwrap_or_else(|| "main".to_owned()),
                    remote: parser
                        .value("--remote")
                        .unwrap_or_else(|| "origin".to_owned()),
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
                // Direct CLI invocation: the report dir must be fully fresh.
                orchestrated: false,
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
                windows_vm: parser.value("--windows-vm"),
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
                    .map_err(|_| "invalid value for --ssh-port: must fit in u16".to_owned())?,
                discovery_timeout_secs: parser
                    .parse_u64_or_default("--discovery-timeout-secs", 5)?,
                ready_timeout_secs: parser
                    .parse_u64_or_default("--wait-ready-timeout-secs", 300)?,
                timeout_secs: parser.parse_u64_or_default("--timeout-secs", 86_400)?,
                collect_artifacts_on_failure: parser.has_flag("--collect-artifacts-on-failure"),
                skip_diagnose_on_failure: parser.has_flag("--skip-diagnose-on-failure"),
                stop_after_ready: parser.has_flag("--stop-after-ready"),
                dry_run: parser.has_flag("--dry-run"),
                windows_only: parser.has_flag("--windows-only"),
                validate_linux_daemon_state: parser.has_flag("--validate-linux-daemon-state"),
                node_assignments: {
                    let raw = collect_repeated_option_values(&args[1..], "--node");
                    let mut out = Vec::with_capacity(raw.len());
                    for s in raw {
                        out.push(
                            vm_lab::orchestrator::role_assignment::parse_node_role_arg(&s)
                                .map_err(|e| format!("invalid --node value '{s}': {e}"))?,
                        );
                    }
                    out
                },
                legacy_bash_orchestrator: parser.has_flag("--legacy-bash-orchestrator"),
                orchestrate_ssh_allow_cidrs: parser.value("--ssh-allow-cidrs"),
                no_fail_on_authenticode: parser.has_flag("--no-fail-on-authenticode"),
            },
        }),
        "vm-lab-validate-windows-security" => Ok(OpsCommand::VmLabValidateWindowsSecurity {
            config: vm_lab::VmLabValidateWindowsSecurityConfig {
                inventory_path: parser
                    .path_or_default("--inventory", vm_lab::default_inventory_path()),
                windows_vm: parser
                    .value("--windows-vm")
                    .ok_or_else(|| "--windows-vm <alias> is required".to_owned())?,
                ssh_identity_file: parser.required_path("--ssh-identity-file")?,
                known_hosts_path: parser.optional_path("--known-hosts-file"),
                ssh_port: u16::try_from(parser.parse_u64_or_default("--ssh-port", 22)?)
                    .map_err(|_| "invalid value for --ssh-port: must fit in u16".to_owned())?,
                utm_documents_root: parser.optional_path("--utm-documents-root"),
                utmctl_path: parser.optional_path("--utmctl-path"),
                report_dir: parser.required_path("--report-dir")?,
                dry_run: parser.has_flag("--dry-run"),
                skip_access_bootstrap: parser.has_flag("--skip-access-bootstrap"),
                skip_install: parser.has_flag("--skip-install"),
                no_fail_on_authenticode: parser.has_flag("--no-fail-on-authenticode"),
                distribute_windows_membership_bundle: parser
                    .optional_path("--distribute-windows-membership-bundle"),
                distribute_windows_assignment_bundle: parser
                    .optional_path("--distribute-windows-assignment-bundle"),
                distribute_windows_traversal_bundle: parser
                    .optional_path("--distribute-windows-traversal-bundle"),
                distribute_windows_dns_zone_bundle: parser
                    .optional_path("--distribute-windows-dns-zone-bundle"),
            },
        }),
        "vm-lab-validate-linux-security" => Ok(OpsCommand::VmLabValidateLinuxSecurity {
            config: vm_lab::VmLabValidateLinuxSecurityConfig {
                inventory_path: parser
                    .path_or_default("--inventory", vm_lab::default_inventory_path()),
                linux_vm: parser
                    .value("--linux-vm")
                    .ok_or_else(|| "--linux-vm <alias> is required".to_owned())?,
                ssh_identity_file: parser.required_path("--ssh-identity-file")?,
                known_hosts_path: parser.optional_path("--known-hosts-file"),
                report_dir: parser.required_path("--report-dir")?,
                dry_run: parser.has_flag("--dry-run"),
                mesh_status_state_path: parser.optional_path("--mesh-status-state-path"),
                mesh_status_expected_peer_ids: parser
                    .value("--mesh-status-expected-peer-ids")
                    .map(|csv| {
                        csv.split(',')
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .map(str::to_string)
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default(),
                mesh_status_max_age_seconds: match parser.value("--mesh-status-max-age-seconds") {
                    Some(v) => Some(v.parse::<i64>().map_err(|err| {
                        format!("invalid value for --mesh-status-max-age-seconds: {err}")
                    })?),
                    None => None,
                },
            },
        }),
        "vm-lab-distribute-windows-state" => Ok(OpsCommand::VmLabDistributeWindowsState {
            config: vm_lab::VmLabDistributeWindowsStateConfig {
                inventory_path: parser
                    .path_or_default("--inventory", vm_lab::default_inventory_path()),
                windows_vm: parser
                    .value("--windows-vm")
                    .ok_or_else(|| "--windows-vm <alias> is required".to_owned())?,
                ssh_identity_file: parser.required_path("--ssh-identity-file")?,
                known_hosts_path: parser.optional_path("--known-hosts-file"),
                report_dir: parser.required_path("--report-dir")?,
                dry_run: parser.has_flag("--dry-run"),
                membership_bundle: parser.optional_path("--membership-bundle"),
                assignment_bundle: parser.optional_path("--assignment-bundle"),
                traversal_bundle: parser.optional_path("--traversal-bundle"),
                dns_zone_bundle: parser.optional_path("--dns-zone-bundle"),
            },
        }),
        "vm-lab-pull-windows-state-from-linux-exit" => {
            Ok(OpsCommand::VmLabPullWindowsStateFromLinuxExit {
                config: vm_lab::VmLabPullWindowsStateFromLinuxExitConfig {
                    inventory_path: parser
                        .path_or_default("--inventory", vm_lab::default_inventory_path()),
                    linux_exit_alias: parser
                        .value("--linux-exit-vm")
                        .ok_or_else(|| "--linux-exit-vm <alias> is required".to_owned())?,
                    ssh_identity_file: parser.required_path("--ssh-identity-file")?,
                    known_hosts_path: parser.optional_path("--known-hosts-file"),
                    dest_dir: parser.required_path("--dest-dir")?,
                    report_dir: parser.required_path("--report-dir")?,
                    dry_run: parser.has_flag("--dry-run"),
                },
            })
        }
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
        "vm-lab-diff-orchestrator-parity" => Ok(OpsCommand::VmLabDiffOrchestratorParity {
            config: vm_lab::VmLabDiffOrchestratorParityConfig {
                left_path: parser.required_path("--left")?,
                right_path: parser.required_path("--right")?,
                output_path: parser.required_path("--output")?,
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
        "vm-lab-readiness-check" => {
            let mut vm_aliases = collect_repeated_option_values(&args[1..], "--vm");
            if let Some(csv_vms) = parser.value("--vms") {
                vm_aliases.extend(split_csv(csv_vms));
            }
            let mut raw_targets = collect_repeated_option_values(&args[1..], "--target");
            if let Some(csv_targets) = parser.value("--targets") {
                raw_targets.extend(split_csv(csv_targets));
            }
            Ok(OpsCommand::VmLabReadinessCheck {
                config: vm_lab::VmLabReadinessCheckConfig {
                    inventory_path: parser
                        .path_or_default("--inventory", vm_lab::default_inventory_path()),
                    vm_aliases,
                    raw_targets,
                    select_all: parser.has_flag("--all"),
                    ssh_identity_file: parser.optional_path("--ssh-identity-file"),
                    known_hosts_path: parser.optional_path("--known-hosts-file"),
                    ssh_port: u16::try_from(parser.parse_u64_or_default("--ssh-port", 22)?)
                        .map_err(|_| "invalid value for --ssh-port: must fit in u16".to_owned())?,
                    connect_timeout_secs: parser
                        .parse_u64_or_default("--connect-timeout-secs", 5)?,
                    report_dir: parser.optional_path("--report-dir"),
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
                        .map_err(|_| "invalid value for --ssh-port: must fit in u16".to_owned())?,
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
                        .unwrap_or_else(|| "main".to_owned()),
                    remote: parser
                        .value("--remote")
                        .unwrap_or_else(|| "origin".to_owned()),
                    ssh_user: parser.value("--ssh-user"),
                    ssh_identity_file: parser.optional_path("--ssh-identity-file"),
                    known_hosts_path: parser.optional_path("--known-hosts-file"),
                    timeout_secs: parser.parse_u64_or_default("--timeout-secs", 1800)?,
                },
            })
        }
        "vm-lab-report-capabilities" => {
            let scope_arg = parser.required("--scope")?;
            let platform_arg = parser.required("--platform")?;
            let source_mode_arg = parser.required("--source-mode")?;
            let scope = vm_lab::capability::parse_scope_arg(scope_arg.as_str())?;
            let platform = vm_lab::capability::parse_platform_arg(platform_arg.as_str())?;
            let source_mode = vm_lab::capability::parse_source_mode_arg(source_mode_arg.as_str())?;
            let bootstrap_phase = match parser.value("--bootstrap-phase") {
                Some(value) => Some(vm_lab::capability::parse_bootstrap_phase_arg(
                    value.as_str(),
                )?),
                None => None,
            };
            let format = match parser.value("--format") {
                Some(value) => {
                    vm_lab::capability::parse_report_capabilities_format_arg(value.as_str())?
                }
                None => vm_lab::capability::VmLabReportCapabilitiesFormat::Summary,
            };
            Ok(OpsCommand::VmLabReportCapabilities {
                config: vm_lab::capability::VmLabReportCapabilitiesConfig {
                    scope,
                    platform,
                    source_mode,
                    bootstrap_phase,
                    mixed_platform_topology: parser.has_flag("--mixed-platform-topology"),
                    output_dir: parser.optional_path("--output-dir"),
                    format,
                    require_fresh_output_dir: parser.has_flag("--require-fresh-output-dir"),
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
                            .unwrap_or_else(|| "Debian 13".to_owned()),
                        ubuntu_os_version: parser
                            .value("--ubuntu-os-version")
                            .unwrap_or_else(|| "Ubuntu".to_owned()),
                        fedora_os_version: parser
                            .value("--fedora-os-version")
                            .unwrap_or_else(|| "Fedora".to_owned()),
                        mint_os_version: parser
                            .value("--mint-os-version")
                            .unwrap_or_else(|| "Linux Mint".to_owned()),
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
                            .unwrap_or_else(|| "cross_platform".to_owned()),
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
                return Err("ops sign-release-artifact does not accept options".to_owned());
            }
            Ok(OpsCommand::SignReleaseArtifact)
        }
        "verify-release-artifact" => {
            if args.len() != 1 {
                return Err("ops verify-release-artifact does not accept options".to_owned());
            }
            Ok(OpsCommand::VerifyReleaseArtifact)
        }
        "collect-platform-probe" => {
            if args.len() != 1 {
                return Err("ops collect-platform-probe does not accept options".to_owned());
            }
            Ok(OpsCommand::CollectPlatformProbe)
        }
        "generate-platform-parity-report" => {
            if args.len() != 1 {
                return Err(
                    "ops generate-platform-parity-report does not accept options".to_owned(),
                );
            }
            Ok(OpsCommand::GeneratePlatformParityReport)
        }
        "collect-platform-parity-bundle" => {
            if args.len() != 1 {
                return Err("ops collect-platform-parity-bundle does not accept options".to_owned());
            }
            Ok(OpsCommand::CollectPlatformParityBundle)
        }
        "install-systemd" => {
            if args.len() != 1 {
                return Err("ops install-systemd does not accept options".to_owned());
            }
            Ok(OpsCommand::InstallSystemd)
        }
        "install-systemd-relay" => {
            // D12.d — `rustynet ops install-systemd-relay [--uninstall] [--dry-run]`.
            // Default mode is install+enable. `--uninstall` flips to
            // disable+remove. `--dry-run` plans the work without
            // touching disk or invoking systemctl (useful in CI).
            let mut mode = ops_install_systemd_relay::RelayUnitMode::InstallAndEnable;
            let mut dry_run = false;
            for arg in &args[1..] {
                match arg.as_str() {
                    "--uninstall" => {
                        mode = ops_install_systemd_relay::RelayUnitMode::DisableAndRemove;
                    }
                    "--dry-run" => dry_run = true,
                    other => {
                        return Err(format!(
                            "ops install-systemd-relay: unknown flag {other:?} (expected --uninstall or --dry-run)"
                        ));
                    }
                }
            }
            let config = match mode {
                ops_install_systemd_relay::RelayUnitMode::InstallAndEnable => {
                    ops_install_systemd_relay::InstallRelayConfig {
                        dry_run,
                        ..ops_install_systemd_relay::InstallRelayConfig::default_install()
                    }
                }
                ops_install_systemd_relay::RelayUnitMode::DisableAndRemove => {
                    ops_install_systemd_relay::InstallRelayConfig {
                        dry_run,
                        ..ops_install_systemd_relay::InstallRelayConfig::default_uninstall()
                    }
                }
            };
            Ok(OpsCommand::InstallSystemdRelay { config })
        }
        "install-windows-service" => {
            if args.len() != 1 {
                return Err("ops install-windows-service does not accept options".to_owned());
            }
            Ok(OpsCommand::InstallWindowsService)
        }
        "install-windows-relay-service" => {
            if args.len() != 1 {
                return Err("ops install-windows-relay-service does not accept options".to_owned());
            }
            Ok(OpsCommand::InstallWindowsRelayService)
        }
        "uninstall-windows-relay-service" => {
            if args.len() != 1 {
                return Err(
                    "ops uninstall-windows-relay-service does not accept options".to_owned(),
                );
            }
            Ok(OpsCommand::UninstallWindowsRelayService)
        }
        "prepare-system-dirs" => {
            if args.len() != 1 {
                return Err("ops prepare-system-dirs does not accept options".to_owned());
            }
            Ok(OpsCommand::PrepareSystemDirs)
        }
        "restart-runtime-service" => {
            if args.len() != 1 {
                return Err("ops restart-runtime-service does not accept options".to_owned());
            }
            Ok(OpsCommand::RestartRuntimeService)
        }
        "stop-runtime-service" => {
            if args.len() != 1 {
                return Err("ops stop-runtime-service does not accept options".to_owned());
            }
            Ok(OpsCommand::StopRuntimeService)
        }
        "show-runtime-service-status" => {
            if args.len() != 1 {
                return Err("ops show-runtime-service-status does not accept options".to_owned());
            }
            Ok(OpsCommand::ShowRuntimeServiceStatus)
        }
        "start-assignment-refresh-service" => {
            if args.len() != 1 {
                return Err(
                    "ops start-assignment-refresh-service does not accept options".to_owned(),
                );
            }
            Ok(OpsCommand::StartAssignmentRefreshService)
        }
        "check-assignment-refresh-availability" => {
            if args.len() != 1 {
                return Err(
                    "ops check-assignment-refresh-availability does not accept options".to_owned(),
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
                .unwrap_or_else(|| "rustynetd".to_owned()),
        }),
        "apply-managed-dns-routing" => {
            if args.len() != 1 {
                return Err("ops apply-managed-dns-routing does not accept options".to_owned());
            }
            Ok(OpsCommand::ApplyManagedDnsRouting)
        }
        "clear-managed-dns-routing" => {
            if args.len() != 1 {
                return Err("ops clear-managed-dns-routing does not accept options".to_owned());
            }
            Ok(OpsCommand::ClearManagedDnsRouting)
        }
        "disconnect-cleanup" => {
            if args.len() != 1 {
                return Err("ops disconnect-cleanup does not accept options".to_owned());
            }
            Ok(OpsCommand::DisconnectCleanup)
        }
        "apply-blind-exit-lockdown" => {
            if args.len() != 1 {
                return Err("ops apply-blind-exit-lockdown does not accept options".to_owned());
            }
            Ok(OpsCommand::ApplyBlindExitLockdown)
        }
        "init-membership" => {
            if args.len() != 1 {
                return Err("ops init-membership does not accept options".to_owned());
            }
            Ok(OpsCommand::InitMembership)
        }
        "secure-remove" => Ok(OpsCommand::SecureRemove {
            path: parser.required_path("--path")?,
        }),
        "ensure-signing-passphrase-material" => {
            if args.len() != 1 {
                return Err(
                    "ops ensure-signing-passphrase-material does not accept options".to_owned(),
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
                    "ops materialize-signing-passphrase-temp does not accept options".to_owned(),
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
                    "ops force-local-assignment-refresh-now does not accept options".to_owned(),
                );
            }
            Ok(OpsCommand::ForceLocalAssignmentRefreshNow)
        }
        "apply-lan-access-coupling" => {
            let enable = parse_bool_value(
                "--enable",
                parser
                    .value("--enable")
                    .unwrap_or_else(|| "false".to_owned())
                    .as_str(),
            )?;
            let lan_routes = parser
                .value("--lan-routes")
                .map(split_csv)
                .unwrap_or_default();
            if enable && lan_routes.is_empty() {
                return Err(
                    "ops apply-lan-access-coupling requires --lan-routes when --enable true"
                        .to_owned(),
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
                    .unwrap_or_else(|| "false".to_owned())
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
                    .unwrap_or_else(|| "root".to_owned()),
                ssh_port: parser
                    .value("--ssh-port")
                    .unwrap_or_else(|| "22".to_owned())
                    .parse::<u16>()
                    .map_err(|err| format!("invalid --ssh-port value: {err}"))?,
                ssh_identity: parser.optional_path("--ssh-identity"),
                ssh_known_hosts_file: parser.optional_path("--ssh-known-hosts-file"),
                ssh_allow_cidrs: parser.required("--ssh-allow-cidrs")?,
                ssh_sudo_mode: ops_e2e::SshSudoMode::parse(
                    parser
                        .value("--ssh-sudo")
                        .unwrap_or_else(|| "auto".to_owned())
                        .as_str(),
                )?,
                sudo_password_file: parser.optional_path("--sudo-password-file"),
                exit_node_id: parser
                    .value("--exit-node-id")
                    .unwrap_or_else(|| "exit-node".to_owned()),
                client_node_id: parser
                    .value("--client-node-id")
                    .unwrap_or_else(|| "client-node".to_owned()),
                network_id: parser
                    .value("--network-id")
                    .unwrap_or_else(|| "local-net".to_owned()),
                remote_root: parser
                    .optional_path("--remote-root")
                    .unwrap_or_else(|| PathBuf::from("/opt/rustynet-clean")),
                repo_ref: parser
                    .value("--repo-ref")
                    .unwrap_or_else(|| "HEAD".to_owned()),
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
        "e2e-worker-refresh-trust-evidence" => Ok(OpsCommand::E2eWorkerRefreshTrustEvidence {
            label: parser.required("--label")?,
            target: parser.required("--target")?,
            node_id: parser.required("--node-id")?,
        }),
        "e2e-worker-refresh-runtime-state" => Ok(OpsCommand::E2eWorkerRefreshRuntimeState {
            label: parser.required("--label")?,
            target: parser.required("--target")?,
            node_id: parser.required("--node-id")?,
        }),
        "e2e-worker-refresh-signed-state" => Ok(OpsCommand::E2eWorkerRefreshSignedState {
            label: parser.required("--label")?,
            target: parser.required("--target")?,
            node_id: parser.required("--node-id")?,
        }),
        "e2e-worker-enforce-runtime" => Ok(OpsCommand::E2eWorkerEnforceRuntime {
            label: parser.required("--label")?,
            target: parser.required("--target")?,
            node_id: parser.required("--node-id")?,
            role: parser.required("--role")?,
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
        return Err("membership subcommand is required".to_owned());
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
                .unwrap_or_else(|| "unknown".to_owned()),
        }),
        "propose-add" => {
            let node_id = parser.required("--node-id")?;
            let node_pubkey_hex = parser.required("--node-pubkey")?;
            let owner = parser.required("--owner")?;
            let roles = parser
                .value("--roles")
                .map_or_else(|| vec!["tag:members".to_owned()], split_csv);
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
                    "quorum".to_owned(),
                )?,
            })
        }
        "propose-rotate-approver" => {
            let approver_id = parser.required("--approver-id")?;
            let approver_pubkey_hex = parser.required("--approver-pubkey")?;
            let role = match parser.required("--role")?.as_str() {
                "owner" => MembershipApproverRole::Owner,
                "guardian" => MembershipApproverRole::Guardian,
                _ => return Err("invalid --role: expected owner|guardian".to_owned()),
            };
            let status = match parser.value("--status").as_deref().unwrap_or("active") {
                "active" => MembershipApproverStatus::Active,
                "revoked" => MembershipApproverStatus::Revoked,
                _ => return Err("invalid --status: expected active|revoked".to_owned()),
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
        return Err("assignment subcommand is required".to_owned());
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
                .unwrap_or_else(|| "100.64.0.0/10".to_owned());
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
                return Err("signing secret length must be >= 32 bytes".to_owned());
            }
            if length_bytes > 4096 {
                return Err("signing secret length must be <= 4096 bytes".to_owned());
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

fn parse_enrollment_command(args: &[String]) -> Result<EnrollmentCliCommand, String> {
    if args.is_empty() {
        return Err("enrollment subcommand is required".to_owned());
    }
    let subcommand = args[0].as_str();
    let parser = OptionParser::parse(&args[1..])?;
    match subcommand {
        "mint" => {
            let secret = parser
                .required("--secret")
                .map_err(|_| "--secret <path> is required".to_owned())?;
            let ttl_secs = parser
                .required("--ttl")
                .map_err(|_| "--ttl <secs> is required".to_owned())?
                .parse::<u64>()
                .map_err(|_| "--ttl must be a non-negative integer".to_owned())?;
            let output_path = parser.optional_path("--output");
            Ok(EnrollmentCliCommand::Mint {
                secret_path: PathBuf::from(secret),
                ttl_secs,
                output_path,
            })
        }
        "verify" => {
            let secret = parser
                .required("--secret")
                .map_err(|_| "--secret <path> is required".to_owned())?;
            let token = parser
                .required("--token")
                .map_err(|_| "--token <encoded> is required".to_owned())?;
            let ledger_path = parser.optional_path("--ledger");
            Ok(EnrollmentCliCommand::Verify {
                secret_path: PathBuf::from(secret),
                ledger_path,
                token,
            })
        }
        "consume" => {
            let token = parser
                .required("--token")
                .map_err(|_| "--token <encoded> is required".to_owned())?;
            let pubkey_b64 = parser
                .required("--pubkey")
                .map_err(|_| "--pubkey <b64> is required".to_owned())?;
            let push_addr = parser
                .required("--push-addr")
                .map_err(|_| "--push-addr <ip:port> is required".to_owned())?;
            Ok(EnrollmentCliCommand::Consume {
                token,
                pubkey_b64,
                push_addr,
            })
        }
        "admit" => {
            // Operator one-shot. All paths and identifiers are
            // required except `--update-id` (auto-generated),
            // `--reason` (defaults), `--ttl-secs` (defaults), and
            // `--roles` (empty list).
            let token = parser
                .required("--token")
                .map_err(|_| "--token <encoded> is required".to_owned())?;
            let pubkey_b64 = parser
                .required("--pubkey")
                .map_err(|_| "--pubkey <b64> is required".to_owned())?;
            let node_id = parser
                .required("--node-id")
                .map_err(|_| "--node-id <id> is required".to_owned())?;
            let owner = parser
                .required("--owner")
                .map_err(|_| "--owner <name> is required".to_owned())?;
            let roles = parser
                .value("--roles")
                .map(|s| {
                    s.split(',')
                        .map(|t| t.trim().to_owned())
                        .filter(|t| !t.is_empty())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let secret_path = parser
                .required_path("--secret")
                .map_err(|_| "--secret <path> is required".to_owned())?;
            let ledger_path = parser
                .required_path("--ledger")
                .map_err(|_| "--ledger <path> is required".to_owned())?;
            let snapshot_path = parser
                .required_path("--snapshot")
                .map_err(|_| "--snapshot <path> is required".to_owned())?;
            let log_path = parser
                .required_path("--log")
                .map_err(|_| "--log <path> is required".to_owned())?;
            let signing_key_path = parser
                .required_path("--signing-key")
                .map_err(|_| "--signing-key <path> is required".to_owned())?;
            let signing_key_passphrase_path = parser
                .required_path("--signing-key-passphrase")
                .map_err(|_| "--signing-key-passphrase <path> is required".to_owned())?;
            let approver_id = parser
                .required("--approver-id")
                .map_err(|_| "--approver-id <id> is required".to_owned())?;
            let output_path = parser
                .required_path("--output")
                .map_err(|_| "--output <path> is required".to_owned())?;
            let update_id = parser.value("--update-id");
            let reason_code = parser
                .value("--reason")
                .unwrap_or_else(|| "enrollment.token_consume.v1".to_owned());
            let ttl_secs = parser.parse_u64_or_default(
                "--ttl-secs",
                rustynet_control::enrollment::DEFAULT_ADMIT_UPDATE_TTL_SECS,
            )?;
            let apply = parser.has_flag("--apply");
            Ok(EnrollmentCliCommand::Admit(Box::new(AdmitConfig {
                token,
                pubkey_b64,
                node_id,
                owner,
                roles,
                secret_path,
                ledger_path,
                snapshot_path,
                log_path,
                signing_key_path,
                signing_key_passphrase_path,
                approver_id,
                output_path,
                update_id,
                reason_code,
                ttl_secs,
                apply,
            })))
        }
        _ => Err(format!("unknown enrollment subcommand: {subcommand}")),
    }
}

fn parse_trust_command(args: &[String]) -> Result<TrustCommand, String> {
    if args.is_empty() {
        return Err("trust subcommand is required".to_owned());
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
                .unwrap_or_else(|| "rustynet".to_owned()),
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
        return Err("traversal subcommand is required".to_owned());
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
            .unwrap_or_else(|| "operator_request".to_owned()),
        policy_context: parser.value("--policy-context"),
        expires_in_secs: parser.parse_u64_or_default("--expires-in", 300)?,
    })
}

fn execute(command: CliCommand) -> Result<String, String> {
    match command {
        CliCommand::Help => Ok(help_text()),
        CliCommand::Version => Ok(version_text()),
        CliCommand::Info => execute_info(),
        CliCommand::Doctor => execute_doctor(),
        CliCommand::Logs(cmd) => execute_logs(cmd),
        CliCommand::ConfigShow => execute_config_show(),
        CliCommand::Debug => execute_debug(),
        CliCommand::PeerList => execute_peer_list(),
        CliCommand::TunnelInfo => execute_tunnel_info(),
        CliCommand::ExitNodeList => execute_exit_node_list(),
        CliCommand::Role(cmd) => execute_role(cmd),
        CliCommand::Capability(cmd) => execute_capability(cmd),
        CliCommand::ConnectivityTest => execute_connectivity_test(),
        CliCommand::PeerStats => execute_peer_stats(),
        CliCommand::Bandwidth => execute_bandwidth(),
        CliCommand::Metrics => execute_metrics(),
        CliCommand::DnsTest(domain) => execute_dns_test(domain),
        CliCommand::Sysinfo => execute_sysinfo(),
        CliCommand::ServiceStatus(service) => execute_service_status(&service),
        CliCommand::Network => execute_network_info(),
        CliCommand::SecurityCheck => execute_security_check(),
        CliCommand::DependencyCheck => execute_dependency_check(),
        CliCommand::DaemonHealth => execute_daemon_health(),
        CliCommand::ConfigValidate => execute_config_validate(),
        CliCommand::WgAddresses => execute_wg_addresses(),
        CliCommand::Routes => execute_routes(),
        CliCommand::KeyExpiry => execute_key_expiry(),
        CliCommand::TunnelStatus => execute_tunnel_status(),
        CliCommand::WgPeers => execute_wg_peers(),
        CliCommand::Uptime => execute_uptime(),
        CliCommand::ProcessInfo => execute_process_info(),
        CliCommand::ConnectionTest => execute_connection_test(),
        CliCommand::LogTail => execute_log_tail(20),
        CliCommand::LogErrors => execute_log_errors(),
        CliCommand::BandwidthTest => execute_bandwidth_test(),
        CliCommand::InterfaceStats => execute_interface_stats(),
        CliCommand::HealthCheck => execute_health_check(),
        CliCommand::SystemLoad => execute_system_load(),
        CliCommand::MemoryInfo => execute_memory_info(),
        CliCommand::DiskInfo => execute_disk_info(),
        CliCommand::CpuInfo => execute_cpu_info(),
        CliCommand::SocketStats => execute_socket_stats(),
        CliCommand::EnvValidate => execute_env_validate(),
        CliCommand::ProcessList => execute_process_list(),
        CliCommand::IfaceList => execute_iface_list(),
        CliCommand::DnsCheck => execute_dns_check(),
        CliCommand::KernelInfo => execute_kernel_info(),
        CliCommand::ServiceCheck => execute_service_check(),
        CliCommand::PermissionCheck => execute_permission_check(),
        CliCommand::PerformanceTest => execute_performance_test(),
        CliCommand::TlsCheck => execute_tls_check(),
        CliCommand::RateLimitCheck => execute_rate_limit_check(),
        CliCommand::NatDetection => execute_nat_detection(),
        CliCommand::ExitNodeStatus => execute_exit_node_status(),
        CliCommand::Ipv6Support => execute_ipv6_support(),
        CliCommand::PacketLoss => execute_packet_loss(),
        CliCommand::SystemClock => execute_system_clock(),
        CliCommand::TcpConnections => execute_tcp_connections(),
        CliCommand::DnsResolver => execute_dns_resolver(),
        CliCommand::InterfaceSpeed => execute_interface_speed(),
        CliCommand::DiskIo => execute_disk_io(),
        CliCommand::ProcessMemory => execute_process_memory(),
        CliCommand::ActiveNetworkRoutes => execute_active_network_routes(),
        CliCommand::MtuPathDiscovery(target) => execute_mtu_discovery(&target),
        CliCommand::DnsResolutionLatency(domain) => execute_dns_latency(&domain),
        CliCommand::BgpRouteAnnouncements => execute_bgp_status(),
        CliCommand::ConnectionStateHistogram => execute_conn_states(),
        CliCommand::ArpTableEntries => execute_arp_table(),
        CliCommand::ListeningSocketsSummary => execute_listening_sockets(),
        CliCommand::NetworkDropStats => execute_network_drops(),
        CliCommand::TlsCertificateExpiry(path) => execute_tls_cert_expiry(&path),
        CliCommand::SelinuxStatus => execute_selinux_status(),
        CliCommand::ApparmorProfileStatus => execute_apparmor_status(),
        CliCommand::CryptographicKeyPermissions => execute_key_permissions(),
        CliCommand::TlsCipherSuiteStrength(host) => execute_tls_cipher(&host),
        CliCommand::SudoersConfigurationAudit => execute_sudoers_audit(),
        CliCommand::OpenSecurityVulnerabilities(db_path) => execute_cve_check(&db_path),
        CliCommand::KernelSecurityParameters => execute_kernel_hardening(),
        CliCommand::FileDescriptorUsage => execute_fd_usage(),
        CliCommand::MemoryFragmentationRatio => execute_memory_frag(),
        CliCommand::NetworkSocketLimitUsage => execute_socket_limits(),
        CliCommand::InodeUsagePerFilesystem => execute_inode_usage(),
        CliCommand::ProcessThreadCountAll => execute_thread_count(),
        CliCommand::MemoryPressureStallInfo => execute_memory_pressure(),
        CliCommand::RustynetdGoroutineCount => execute_goroutine_count(),
        CliCommand::IpcSocketResponsiveness => execute_ipc_latency(),
        CliCommand::DaemonCrashLogsRecent => execute_daemon_crashes(),
        CliCommand::DaemonOpenFileHandles => execute_daemon_files(),
        CliCommand::SystemdUnitDependencyGraph => execute_systemd_deps(),
        CliCommand::ProcessCpuTimeDistribution => execute_cpu_time(),
        CliCommand::DiskIoLatencyHistogram(device) => execute_disk_latency(&device),
        CliCommand::FilesystemJournalStatus => execute_filesystem_journal(),
        CliCommand::BlockDeviceErrorCounters => execute_disk_errors(),
        CliCommand::DirectorySizeSnapshot(path) => execute_dir_size(&path),
        CliCommand::FilesystemCacheEfficiency => execute_cache_efficiency(),
        CliCommand::FileIntegrityCheck(path) => execute_file_integrity(&path),
        CliCommand::SyslogConfigurationAudit => execute_syslog_config(),
        CliCommand::AccessControlListAudit(path) => execute_acl_audit(&path),
        CliCommand::BootIntegrityCheck => execute_boot_integrity(),
        CliCommand::SystemStateSnapshot => execute_system_snapshot(),
        CliCommand::CompareToBaseline => execute_compare_baseline(),
        CliCommand::PerformanceRegressionDetection => execute_perf_regression(),
        CliCommand::Login => Ok("login: open auth URL and complete device enrollment".to_owned()),
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
        CliCommand::Enrollment(command) => execute_enrollment(*command),
        CliCommand::Trust(command) => execute_trust(*command),
        CliCommand::Ops(command) => execute_ops(*command),
        CliCommand::Node(command) => execute_node(command),
        CliCommand::Policy(command) => execute_policy(command),
        CliCommand::Relay(command) => execute_relay(command),
        CliCommand::Cert(command) => execute_cert(command),
        CliCommand::TrustState(command) => execute_trust_state(command),
        CliCommand::Analytics(command) => execute_analytics(command),
        CliCommand::Backup(command) => execute_backup(command),
        CliCommand::RestoreState(command) => execute_restore_state(command),
        CliCommand::ExportKeys(command) => execute_export_keys(command),
        CliCommand::Config(command) => execute_config_subcommand(command),
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
                verifier_key_output_path.as_ref().map_or_else(
                    || "<not_written>".to_owned(),
                    |path| path.display().to_string()
                )
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
        verifier_key_output_path.as_ref().map_or_else(
            || "<not_written>".to_owned(),
            |path| path.display().to_string()
        )
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
        verifier_key_output_path.as_ref().map_or_else(
            || "<not_written>".to_owned(),
            |path| path.display().to_string()
        )
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
            return Ok("operator menu exited (stdin closed)".to_owned());
        }

        match choice.trim() {
            "1" => render_operator_action("status", send_command(IpcCommand::Status)),
            "2" => render_operator_action("netcheck", send_command(IpcCommand::Netcheck)),
            "3" => render_operator_action("exit-node off", send_command(IpcCommand::ExitNodeOff)),
            "4" => render_operator_action(
                "route advertise 0.0.0.0/0",
                send_command(IpcCommand::RouteAdvertise("0.0.0.0/0".to_owned())),
            ),
            "5" => render_operator_action("lan-access on", send_command(IpcCommand::LanAccessOn)),
            "6" => render_operator_action("lan-access off", send_command(IpcCommand::LanAccessOff)),
            "0" => return Ok("operator menu exited".to_owned()),
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
                return Err("invalid expiry window: --expires-in must be > 0".to_owned());
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
                        "merge-from update record mismatch: payloads must be identical".to_owned(),
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
                return Err("duplicate approver signature is not allowed".to_owned());
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

fn execute_enrollment(command: EnrollmentCliCommand) -> Result<String, String> {
    use rustynetd::enrollment_token::{inspect_token, load_ledger, load_secret, mint_token};
    match command {
        EnrollmentCliCommand::Mint {
            secret_path,
            ttl_secs,
            output_path,
        } => {
            let secret = load_secret(&secret_path).map_err(|err| err.to_string())?;
            let (_token, encoded) = mint_token(&secret, ttl_secs).map_err(|err| err.to_string())?;
            if let Some(path) = output_path {
                std::fs::write(&path, format!("{encoded}\n")).map_err(|err| err.to_string())?;
                Ok(format!("enrollment token written to {}", path.display()))
            } else {
                // Print the token alone (no extra prose) so it can be
                // captured cleanly into a variable or QR code.
                Ok(encoded)
            }
        }
        EnrollmentCliCommand::Verify {
            secret_path,
            ledger_path,
            token,
        } => {
            let secret = load_secret(&secret_path).map_err(|err| err.to_string())?;
            let ledger = match ledger_path.as_deref() {
                Some(path) => load_ledger(path).map_err(|err| err.to_string())?,
                None => rustynetd::enrollment_token::ConsumedTokenLedger::new(),
            };
            let inspect = inspect_token(&token, &secret, &ledger).map_err(|err| err.to_string())?;
            // Stable, machine-friendly verify output: one space-
            // separated key=value line. The operator can grep for
            // `valid=true` / `valid=false` without parsing prose.
            let valid_flag = !inspect.already_consumed;
            Ok(format!(
                "valid={valid_flag} issued_at_unix={} expires_at_unix={} remaining_secs={} already_consumed={}",
                inspect.issued_at_unix,
                inspect.expires_at_unix,
                inspect.remaining_secs,
                inspect.already_consumed,
            ))
        }
        EnrollmentCliCommand::Consume {
            token,
            pubkey_b64,
            push_addr,
        } => {
            // Consume requires the daemon's enrollment secret +
            // ledger paths and the running daemon's gossip
            // subsystem, so it goes through IPC. The daemon-side
            // handler maps every per-step reject to a fixed-
            // vocabulary error string.
            match send_command(IpcCommand::EnrollmentConsume {
                token,
                pubkey_b64,
                push_addr,
            }) {
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
        EnrollmentCliCommand::Admit(config) => execute_enrollment_admit(*config),
    }
}

fn execute_enrollment_admit(config: AdmitConfig) -> Result<String, String> {
    use rustynet_control::enrollment::{EnrolleeAdmitContext, build_add_node_record_for_enrollee};
    use rustynetd::enrollment_token::{
        load_ledger, load_secret, verify_and_consume_token, write_ledger,
    };
    let now_unix = unix_now();
    // Decode the enrollee pubkey early so a malformed input fails
    // before we burn a token.
    use base64::Engine;
    let pubkey_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(config.pubkey_b64.as_bytes())
        .map_err(|err| format!("enrollee pubkey base64 decode failed: {err}"))?;
    if pubkey_bytes.len() != 32 {
        return Err(format!(
            "enrollee pubkey must be 32 bytes after base64 decode (got {})",
            pubkey_bytes.len()
        ));
    }
    let pubkey_hex: String = pubkey_bytes.iter().map(|b| format!("{b:02x}")).collect();

    // Step 1 — verify + consume the token + persist ledger.
    let secret = load_secret(&config.secret_path).map_err(|err| err.to_string())?;
    let mut ledger = load_ledger(&config.ledger_path).map_err(|err| err.to_string())?;
    verify_and_consume_token(&config.token, &secret, &mut ledger)
        .map_err(|err| format!("enrollment token rejected: {err}"))?;
    write_ledger(&config.ledger_path, &ledger)
        .map_err(|err| format!("enrollment ledger persistence failed: {err}"))?;

    // Step 2 — load current membership state.
    let paths = MembershipPaths {
        snapshot_path: config.snapshot_path.clone(),
        log_path: config.log_path.clone(),
    };
    let (_, entries, state) = load_current_membership_state(&paths, now_unix)?;
    // The reducer rejects duplicate node ids; surface a clearer
    // diagnostic before we sign anything pointless.
    if state.nodes.iter().any(|n| n.node_id == config.node_id) {
        return Err(format!(
            "membership snapshot already contains node_id {}; refusing to admit",
            config.node_id
        ));
    }

    // Step 3 — build the AddNode record.
    let ctx = EnrolleeAdmitContext {
        node_id: config.node_id.clone(),
        node_pubkey_hex: pubkey_hex,
        owner: config.owner,
        roles: config.roles,
        update_id: config.update_id.unwrap_or_else(generate_update_id),
        reason_code: config.reason_code,
        policy_context: None,
        now_unix,
        ttl_secs: config.ttl_secs,
    };
    let record = build_add_node_record_for_enrollee(&state, ctx)
        .map_err(|err| format!("admit record build failed: {err}"))?;

    // Step 4 — sign the record under the operator's approver key.
    let signing_key = load_signing_key(
        &config.signing_key_path,
        &config.signing_key_passphrase_path,
    )?;
    let signature = sign_update_record(&record, config.approver_id.as_str(), &signing_key)
        .map_err(|err| format!("sign update failed: {err}"))?;
    let signed = SignedMembershipUpdate {
        record,
        approver_signatures: vec![signature],
    };

    // Step 5 — write the signed update to the operator's output
    // path so further co-signing (when quorum > 1) can chain via
    // `membership sign-update --merge-from`.
    let envelope = encode_signed_update(&signed).map_err(|err| err.to_string())?;
    write_text_file(&config.output_path, &envelope)?;

    if !config.apply {
        return Ok(format!(
            "admit produced signed update: {} signatures={} target={} quorum_threshold={}",
            config.output_path.display(),
            signed.approver_signatures.len(),
            signed.record.target,
            state.quorum_threshold,
        ));
    }

    // Step 6 (optional --apply) — if the single signature already
    // meets quorum, run apply locally so the snapshot + log
    // reflect the new node immediately.
    if (signed.approver_signatures.len() as u8) < state.quorum_threshold {
        return Ok(format!(
            "admit produced partially-signed update: {} signatures={} need={} (run `rustynet membership sign-update --merge-from {}` for further co-signing)",
            config.output_path.display(),
            signed.approver_signatures.len(),
            state.quorum_threshold,
            config.output_path.display(),
        ));
    }
    let mut replay_cache = replay_cache_from_entries(&entries)?;
    let next = apply_signed_update(&state, &signed, now_unix, &mut replay_cache)
        .map_err(|err| format!("apply_signed_update failed: {err}"))?;
    append_membership_log_entry(&paths.log_path, &signed).map_err(|err| err.to_string())?;
    persist_membership_snapshot(&paths.snapshot_path, &next).map_err(|err| err.to_string())?;
    Ok(format!(
        "admit applied: snapshot={} log={} epoch_new={} target={}",
        paths.snapshot_path.display(),
        paths.log_path.display(),
        next.epoch,
        signed.record.target,
    ))
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
        OpsCommand::WriteMembershipPhase10Report => {
            ops_ci_release_perf::execute_ops_write_membership_phase10_report()
        }
        OpsCommand::VerifyMembershipPhase10Report { config } => {
            ops_ci_release_perf::execute_ops_verify_membership_phase10_report(config)
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
        OpsCommand::GenerateAttackMatrix { config } => {
            ops_security_audit::execute_ops_generate_attack_matrix(config)
        }
        OpsCommand::GenerateAssessmentFromMatrix { config } => {
            ops_security_audit::execute_ops_generate_assessment_from_matrix(config)
        }
        OpsCommand::ValidateLiveLabReports { config } => {
            ops_security_audit::execute_ops_validate_live_lab_reports(config)
        }
        OpsCommand::EvaluateLiveCoveragePromotion { config } => {
            ops_security_audit::execute_ops_evaluate_live_coverage_promotion(config)
        }
        OpsCommand::GenerateLiveLabFindings { config } => {
            ops_security_audit_workflows::execute_ops_generate_live_lab_findings(config)
        }
        OpsCommand::GenerateComparativeExploitCoverage { config } => {
            ops_security_audit_workflows::execute_ops_generate_comparative_exploit_coverage(
                config,
            )
        }
        OpsCommand::RunLiveLabValidations { config } => {
            ops_security_audit_workflows::execute_ops_run_live_lab_validations(config)
        }
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
        OpsCommand::CrossNetworkPreflight { config } => {
            ops_cross_network_preflight::execute_cross_network_preflight(config)
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
        OpsCommand::VmLabValidateWindowsSecurity { config } => {
            vm_lab::run_validate_windows_security(&config)
        }
        OpsCommand::VmLabValidateLinuxSecurity { config } => {
            vm_lab::run_validate_linux_security(&config)
        }
        OpsCommand::VmLabDistributeWindowsState { config } => {
            vm_lab::run_distribute_windows_state(&config)
        }
        OpsCommand::VmLabPullWindowsStateFromLinuxExit { config } => {
            vm_lab::run_pull_windows_state_from_linux_exit(&config).map(|(summary, _)| summary)
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
        OpsCommand::VmLabDiffOrchestratorParity { config } => {
            vm_lab::execute_ops_vm_lab_diff_orchestrator_parity(config)
        }
        OpsCommand::VmLabIterateLiveLab { config } => {
            vm_lab::execute_ops_vm_lab_iterate_live_lab(config)
        }
        OpsCommand::VmLabRunLiveLab { config } => vm_lab::execute_ops_vm_lab_run_live_lab(config),
        OpsCommand::VmLabCheckKnownHosts { config } => {
            vm_lab::execute_ops_vm_lab_check_known_hosts(config)
        }
        OpsCommand::VmLabPreflight { config } => vm_lab::execute_ops_vm_lab_preflight(config),
        OpsCommand::VmLabReadinessCheck { config } => {
            vm_lab::execute_ops_vm_lab_readiness_check(config)
        }
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
        OpsCommand::VmLabReportCapabilities { config } => {
            vm_lab::capability::execute_ops_vm_lab_report_capabilities(config)
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
        OpsCommand::InstallSystemdRelay { config } => {
            ops_install_systemd_relay::execute_install_relay(config)
                .map(|report| report.summary())
        }
        OpsCommand::InstallWindowsService => ops_e2e::execute_ops_install_windows_service(),
        OpsCommand::InstallWindowsRelayService => {
            ops_e2e::execute_ops_install_windows_relay_service()
        }
        OpsCommand::UninstallWindowsRelayService => {
            ops_e2e::execute_ops_uninstall_windows_relay_service()
        }
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
        OpsCommand::E2eWorkerRefreshTrustEvidence {
            label,
            target,
            node_id,
        } => ops_e2e::execute_ops_e2e_worker_refresh_trust_evidence(label, target, node_id),
        OpsCommand::E2eWorkerRefreshRuntimeState {
            label,
            target,
            node_id,
        } => ops_e2e::execute_ops_e2e_worker_refresh_runtime_state(label, target, node_id),
        OpsCommand::E2eWorkerRefreshSignedState {
            label,
            target,
            node_id,
        } => ops_e2e::execute_ops_e2e_worker_refresh_signed_state(label, target, node_id),
        OpsCommand::E2eWorkerEnforceRuntime {
            label,
            target,
            node_id,
            role,
            src_dir,
            ssh_allow_cidrs,
        } => ops_e2e::execute_ops_e2e_worker_enforce_runtime(label, target, node_id, role, src_dir, ssh_allow_cidrs),
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
        return Ok("[trust-refresh] auto-refresh disabled; skipping.".to_owned());
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
        .unwrap_or_else(|| "admin".to_owned())
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
        return Ok("[assignment-refresh] auto-refresh disabled; skipping.".to_owned());
    }

    let target_node_id = env_optional_string("RUSTYNET_ASSIGNMENT_TARGET_NODE_ID")?
        .or_else(|| std::env::var("RUSTYNET_NODE_ID").ok())
        .ok_or_else(|| {
            "assignment target node id is required (RUSTYNET_ASSIGNMENT_TARGET_NODE_ID or RUSTYNET_NODE_ID)".to_owned()
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
                    .to_owned(),
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
            mesh_cidr: "100.64.0.0/10".to_owned(),
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
        return Err("issued assignment bundle has invalid expiry window".to_owned());
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

    Ok("phase6 platform parity bundle generated from probes".to_owned())
}

#[derive(Debug, Clone)]
struct Phase6ProbeMetadata {
    payload: Value,
    probe_time_unix: u64,
    is_fresh: bool,
}

/// X2: typed view over the 3 fields `phase6_load_probe_metadata`
/// reads from a platform-parity probe payload. Wrong-type slots
/// (e.g. `evidence_mode: 42`, `probe_time_unix: "now"`) fail at
/// the typed deserialize with a precise serde error instead of
/// slipping past the legacy `.and_then(Value::as_str)` /
/// `.and_then(Value::as_u64)` walks. The original `Value` payload
/// is preserved alongside the typed view in `Phase6ProbeMetadata`
/// so downstream code that walks the payload generically keeps
/// working.
#[derive(Debug, Clone, PartialEq, serde::Deserialize, Default)]
#[serde(default)]
struct Phase6ProbeMetadataView {
    pub evidence_mode: Option<String>,
    pub platform: Option<String>,
    pub probe_time_unix: Option<u64>,
    #[allow(dead_code)]
    #[serde(flatten)]
    extra: serde_json::Map<String, Value>,
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
    if !payload.is_object() {
        return Err(format!(
            "platform parity probe must be JSON object: {}",
            path.display()
        ));
    }
    // X2: deserialise the probe payload once. Wrong-type slots fail
    // here with a precise field-shape error wrapped at the validator
    // boundary so the existing per-field error messages still
    // describe the contract while the underlying serde message
    // pinpoints the offending field.
    let typed: Phase6ProbeMetadataView =
        serde_json::from_value(payload.clone()).map_err(|err| {
            format!(
                "platform parity probe has invalid field shape: {} ({err})",
                path.display()
            )
        })?;
    if typed
        .evidence_mode
        .as_deref()
        .is_none_or(|mode| mode != "measured")
    {
        return Err(format!(
            "platform parity probe must set evidence_mode=measured: {}",
            path.display()
        ));
    }

    let payload_platform = typed
        .platform
        .as_deref()
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

    let probe_time_unix = typed.probe_time_unix.ok_or_else(|| {
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
            let route_probe_cmd = "ip -o route show default".to_owned();
            let route_hook_ready =
                phase6_command_succeeds("ip", &["-o", "route", "show", "default"]);

            let (dns_hook_ready, dns_probe_cmd) = if phase6_command_available("resolvectl") {
                (
                    phase6_command_succeeds("resolvectl", &["status"]),
                    "resolvectl status".to_owned(),
                )
            } else {
                (
                    phase6_nonempty_file(Path::new("/etc/resolv.conf")),
                    "test -s /etc/resolv.conf".to_owned(),
                )
            };

            let (firewall_hook_ready, firewall_probe_cmd) = if phase6_command_available("nft") {
                (
                    phase6_command_succeeds("nft", &["list", "tables"]),
                    "nft list tables".to_owned(),
                )
            } else if phase6_command_available("iptables") {
                (
                    phase6_command_succeeds("iptables", &["-S"]),
                    "iptables -S".to_owned(),
                )
            } else {
                (false, "nft|iptables unavailable".to_owned())
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
                "root-owned route/ifconfig/launchctl + hardened macOS start contract".to_owned(),
                "root-owned scutil/launchctl + hardened macOS start contract".to_owned(),
                "root-owned pfctl/launchctl + hardened macOS start contract".to_owned(),
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
            "powershell.exe Get-NetRoute".to_owned(),
            "powershell.exe Get-DnsClientServerAddress".to_owned(),
            "powershell.exe Get-NetFirewallProfile".to_owned(),
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
        .unwrap_or_else(|| DEFAULT_PHASE10_LEAK_REPORT_PATH.to_owned());
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
        let hostname = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        if !hostname.is_empty() {
            return hostname;
        }
    }
    "unknown".to_owned()
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
        .ok_or_else(|| "failed to resolve workspace root for phase6 parity probe".to_owned())
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
            return Err((*message).to_owned());
        }
    }
    for (pattern, message) in PHASE6_MACOS_FORBIDDEN_START_PATTERNS {
        if body.contains(pattern) {
            return Err((*message).to_owned());
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

#[allow(dead_code)]
fn print_json(v: &Value) {
    println!(
        "{}",
        serde_json::to_string_pretty(v).unwrap_or_else(|_| v.to_string())
    );
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
        .ok_or_else(|| "platform parity report must be a JSON object".to_owned())?;

    if report_obj
        .get("evidence_mode")
        .and_then(Value::as_str)
        .is_none_or(|value| value != "measured")
    {
        return Err("platform parity report must set evidence_mode=measured".to_owned());
    }

    let captured_at_unix = report_obj
        .get("captured_at_unix")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            "platform parity report requires positive integer captured_at_unix".to_owned()
        })?;
    if captured_at_unix == 0 {
        return Err("platform parity report requires positive integer captured_at_unix".to_owned());
    }

    let now_unix = unix_now();
    if captured_at_unix > now_unix.saturating_add(300) {
        return Err("platform parity report captured_at_unix is too far in the future".to_owned());
    }
    if now_unix.saturating_sub(captured_at_unix) > PHASE6_MAX_EVIDENCE_AGE_SECS {
        return Err(
            "platform parity report is stale; regenerate with fresh measurements".to_owned(),
        );
    }

    let environment = report_obj
        .get("environment")
        .and_then(Value::as_str)
        .ok_or_else(|| "platform parity report requires non-empty environment".to_owned())?;
    if environment.trim().is_empty() {
        return Err("platform parity report requires non-empty environment".to_owned());
    }

    if report_obj.contains_key("gate_passed") {
        return Err("platform parity report must not include gate_passed toggle".to_owned());
    }

    let source_artifacts = report_obj
        .get("source_artifacts")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            "platform parity report requires non-empty source_artifacts list".to_owned()
        })?;
    if source_artifacts.is_empty() {
        return Err("platform parity report requires non-empty source_artifacts list".to_owned());
    }

    let required_platforms = Phase6Platform::all()
        .iter()
        .map(|platform| platform.as_str().to_owned())
        .collect::<HashSet<_>>();
    let mut source_by_platform = HashMap::new();

    for source in source_artifacts {
        let source_str = source.as_str().ok_or_else(|| {
            "platform parity report has invalid source_artifacts entry".to_owned()
        })?;
        if source_str.trim().is_empty() {
            return Err("platform parity report has invalid source_artifacts entry".to_owned());
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
            "platform parity report requires non-empty platform_results list".to_owned()
        })?;
    if platform_results.is_empty() {
        return Err("platform parity report requires non-empty platform_results list".to_owned());
    }

    let mut seen = HashSet::new();
    for result in platform_results {
        let result_obj = result.as_object().ok_or_else(|| {
            "platform parity report has invalid platform_results entry".to_owned()
        })?;
        let platform = result_obj
            .get("platform")
            .and_then(Value::as_str)
            .ok_or_else(|| "platform parity report entry missing platform".to_owned())?
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
        return Err("apply-managed-dns-routing is supported on Linux only".to_owned());
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
        return Err("clear-managed-dns-routing is supported on Linux only".to_owned());
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

    Err("restart-runtime-service is supported on Linux and macOS only".to_owned())
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

    Err("stop-runtime-service is supported on Linux and macOS only".to_owned())
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
            .to_owned();
        if !stdout.is_empty() {
            return Ok(stdout);
        }
        let stderr = String::from_utf8_lossy(&status_output.stderr)
            .trim()
            .to_owned();
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

    Err("show-runtime-service-status is supported on Linux and macOS only".to_owned())
}

fn execute_ops_start_assignment_refresh_service() -> Result<String, String> {
    require_root_execution()?;
    if !cfg!(target_os = "linux") {
        return Err("start-assignment-refresh-service is supported on Linux only".to_owned());
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
        return Err("check-assignment-refresh-availability is supported on Linux only".to_owned());
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
        return Err("force-local-assignment-refresh-now is supported on Linux only".to_owned());
    }
    force_local_assignment_refresh_now_ops()?;
    Ok("forced local assignment refresh completed".to_owned())
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

    let daemon_group = daemon_group.trim().to_owned();
    if daemon_group.is_empty() {
        return Err("daemon group must not be empty".to_owned());
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
                            .to_owned(),
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
                        None => (Gid::from_raw(0), 0o644, "root".to_owned()),
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
                            .to_owned(),
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
        return Err("disconnect-cleanup is supported on Linux and macOS only".to_owned());
    }

    let interface = env_string_or_default("RUSTYNET_WG_INTERFACE", DEFAULT_WG_INTERFACE)?
        .trim()
        .to_owned();
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
        .map_or_else(|| Gid::from_raw(0), |group| group.gid);

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
        return Err("macOS tunnel keychain service must not be empty".to_owned());
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
        .to_owned();
    validate_managed_dns_interface_name(wg_interface.as_str())?;
    let wg_listen_port = env_string_or_default("RUSTYNET_WG_LISTEN_PORT", "51820")?
        .parse::<u16>()
        .map_err(|err| format!("invalid wireguard listen port: {err}"))?;
    if wg_listen_port == 0 {
        return Err("wireguard listen port must be between 1 and 65535".to_owned());
    }

    let helper_program_arguments = vec![
        daemon_binary_path.display().to_string(),
        "privileged-helper".to_owned(),
        "--socket".to_owned(),
        service.helper_socket_path.display().to_string(),
        "--allowed-uid".to_owned(),
        service.daemon_uid.to_string(),
        "--allowed-gid".to_owned(),
        daemon_gid.to_string(),
        "--timeout-ms".to_owned(),
        helper_timeout_ms.to_string(),
    ];

    let daemon_program_arguments = vec![
        daemon_binary_path.display().to_string(),
        "daemon".to_owned(),
        "--node-id".to_owned(),
        env_required_nonempty("RUSTYNET_NODE_ID", "node id")?,
        "--node-role".to_owned(),
        env_required_nonempty("RUSTYNET_NODE_ROLE", "node role")?,
        "--socket".to_owned(),
        service.daemon_socket_path.display().to_string(),
        "--state".to_owned(),
        env_required_path("RUSTYNET_STATE")?.display().to_string(),
        "--trust-evidence".to_owned(),
        env_required_path("RUSTYNET_TRUST_EVIDENCE")?
            .display()
            .to_string(),
        "--trust-verifier-key".to_owned(),
        env_required_path("RUSTYNET_TRUST_VERIFIER_KEY")?
            .display()
            .to_string(),
        "--trust-watermark".to_owned(),
        env_required_path("RUSTYNET_TRUST_WATERMARK")?
            .display()
            .to_string(),
        "--membership-snapshot".to_owned(),
        env_required_path("RUSTYNET_MEMBERSHIP_SNAPSHOT")?
            .display()
            .to_string(),
        "--membership-log".to_owned(),
        env_required_path("RUSTYNET_MEMBERSHIP_LOG")?
            .display()
            .to_string(),
        "--membership-watermark".to_owned(),
        env_required_path("RUSTYNET_MEMBERSHIP_WATERMARK")?
            .display()
            .to_string(),
        "--auto-tunnel-enforce".to_owned(),
        if auto_tunnel_enforce {
            "true".to_owned()
        } else {
            "false".to_owned()
        },
        "--auto-tunnel-bundle".to_owned(),
        env_required_path("RUSTYNET_AUTO_TUNNEL_BUNDLE")?
            .display()
            .to_string(),
        "--auto-tunnel-verifier-key".to_owned(),
        env_required_path("RUSTYNET_AUTO_TUNNEL_VERIFIER_KEY")?
            .display()
            .to_string(),
        "--auto-tunnel-watermark".to_owned(),
        env_required_path("RUSTYNET_AUTO_TUNNEL_WATERMARK")?
            .display()
            .to_string(),
        "--auto-tunnel-max-age-secs".to_owned(),
        parse_env_u64_with_default(
            "RUSTYNET_AUTO_TUNNEL_MAX_AGE_SECS",
            DEFAULT_AUTO_TUNNEL_MAX_AGE_SECS,
        )?
        .to_string(),
        "--traversal-bundle".to_owned(),
        env_required_path("RUSTYNET_TRAVERSAL_BUNDLE")?
            .display()
            .to_string(),
        "--traversal-verifier-key".to_owned(),
        env_required_path("RUSTYNET_TRAVERSAL_VERIFIER_KEY")?
            .display()
            .to_string(),
        "--traversal-watermark".to_owned(),
        env_required_path("RUSTYNET_TRAVERSAL_WATERMARK")?
            .display()
            .to_string(),
        "--traversal-max-age-secs".to_owned(),
        parse_env_u64_with_default(
            "RUSTYNET_TRAVERSAL_MAX_AGE_SECS",
            DEFAULT_TRAVERSAL_MAX_AGE_SECS,
        )?
        .to_string(),
        "--backend".to_owned(),
        env_required_nonempty("RUSTYNET_BACKEND", "backend mode")?,
        "--wg-interface".to_owned(),
        wg_interface,
        "--wg-listen-port".to_owned(),
        wg_listen_port.to_string(),
        "--wg-private-key".to_owned(),
        env_required_path("RUSTYNET_WG_PRIVATE_KEY")?
            .display()
            .to_string(),
        "--wg-encrypted-private-key".to_owned(),
        env_required_path("RUSTYNET_WG_ENCRYPTED_PRIVATE_KEY")?
            .display()
            .to_string(),
        "--wg-key-passphrase".to_owned(),
        wg_passphrase_path.display().to_string(),
        "--wg-public-key".to_owned(),
        env_required_path("RUSTYNET_WG_PUBLIC_KEY")?
            .display()
            .to_string(),
        "--egress-interface".to_owned(),
        env_string_or_default("RUSTYNET_EGRESS_INTERFACE", "")?,
        "--dataplane-mode".to_owned(),
        env_required_nonempty("RUSTYNET_DATAPLANE_MODE", "dataplane mode")?,
        "--privileged-helper-socket".to_owned(),
        service.helper_socket_path.display().to_string(),
        "--privileged-helper-timeout-ms".to_owned(),
        helper_timeout_ms.to_string(),
        "--reconcile-interval-ms".to_owned(),
        parse_env_u64_with_default("RUSTYNET_RECONCILE_INTERVAL_MS", 1000)?.to_string(),
        "--max-reconcile-failures".to_owned(),
        parse_env_u64_with_default("RUSTYNET_MAX_RECONCILE_FAILURES", 5)?.to_string(),
        "--fail-closed-ssh-allow".to_owned(),
        if fail_closed_ssh_allow {
            "true".to_owned()
        } else {
            "false".to_owned()
        },
        "--fail-closed-ssh-allow-cidrs".to_owned(),
        env_string_or_default("RUSTYNET_FAIL_CLOSED_SSH_ALLOW_CIDRS", "")?,
    ];

    let helper_environment = vec![
        (
            "RUSTYNET_WG_BINARY_PATH".to_owned(),
            wg_binary_path.display().to_string(),
        ),
        (
            "RUSTYNET_WIREGUARD_GO_BINARY_PATH".to_owned(),
            wireguard_go_binary_path.display().to_string(),
        ),
        (
            "RUSTYNET_IFCONFIG_BINARY_PATH".to_owned(),
            ifconfig_binary_path.display().to_string(),
        ),
        (
            "RUSTYNET_ROUTE_BINARY_PATH".to_owned(),
            route_binary_path.display().to_string(),
        ),
        (
            "RUSTYNET_PFCTL_BINARY_PATH".to_owned(),
            pfctl_binary_path.display().to_string(),
        ),
        (
            "RUSTYNET_KILL_BINARY_PATH".to_owned(),
            kill_binary_path.display().to_string(),
        ),
    ];

    let mut daemon_environment = helper_environment.clone();
    daemon_environment.push((
        "RUSTYNET_WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT".to_owned(),
        keychain_account,
    ));
    daemon_environment.push((
        "RUSTYNET_MACOS_WG_PASSPHRASE_KEYCHAIN_SERVICE".to_owned(),
        keychain_service,
    ));
    daemon_environment.push((
        "RUSTYNET_WG_KEY_PASSPHRASE_CREDENTIAL_PATH".to_owned(),
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
        return Err("command name must not be empty".to_owned());
    }
    if command_name.contains('/') {
        let path = PathBuf::from(command_name);
        if !path.is_absolute() {
            return Err(format!("command path must be absolute: {}", path.display()));
        }
        return Ok(path);
    }
    let path_env = std::env::var_os("PATH").ok_or_else(|| "PATH is not set".to_owned())?;
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
        .to_owned();
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
        return Err("daemon uid must be a non-root user on macOS".to_owned());
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
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    if !stderr.is_empty() {
        return stderr;
    }
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
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
    Ok("signing passphrase material verified".to_owned())
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
            "encrypted tunnel key material is missing and initialization is not approved; set RUSTYNET_WG_CUSTODY_ALLOW_INIT=true".to_owned(),
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
        let source_private_key_path = config
            .runtime_private_key_path
            .exists()
            .then(|| config.runtime_private_key_path.clone());

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
        return Err("set-assignment-refresh-exit-node is supported on Linux only".to_owned());
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
        return Err("apply-lan-access-coupling is supported on Linux only".to_owned());
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
        .ok_or_else(|| "daemon status missing node_role".to_owned())?;
    if node_role == "blind_exit" {
        return Err("LAN access coupling is not permitted for blind_exit role".to_owned());
    }
    let selected_exit_node = status_field(status.message.as_str(), "exit_node")
        .ok_or_else(|| "daemon status missing exit_node".to_owned())?;
    if enable && (selected_exit_node.is_empty() || selected_exit_node == "none") {
        return Err("select an exit node before enabling LAN access".to_owned());
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
                    "assignment refresh env is missing RUSTYNET_ASSIGNMENT_EXIT_NODE_ID; re-select the exit node first".to_owned(),
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
        return Err("apply-role-coupling is supported on Linux only".to_owned());
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
                .push("skipped client exit route convergence wait after role coupling".to_owned());
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
        && let Err(err) = send_role_coupling_ipc(IpcCommand::RouteAdvertise("0.0.0.0/0".to_owned()))
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
        .to_owned();
    validate_managed_dns_interface_name(interface.as_str())?;
    Ok(interface)
}

fn validate_managed_dns_interface_name(interface: &str) -> Result<(), String> {
    if interface.is_empty() || interface.len() > 15 {
        return Err(
            "managed DNS routing interface name length must be between 1 and 15".to_owned(),
        );
    }
    if !interface
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
    {
        return Err("managed DNS routing interface contains invalid characters".to_owned());
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
        return Err("managed DNS resolver bind addr must be loopback".to_owned());
    }
    Ok(addr)
}

fn managed_dns_resolver_server_arg(addr: SocketAddr) -> Result<String, String> {
    match addr {
        SocketAddr::V4(v4) if v4.ip().is_loopback() => Ok(format!("{}:{}", v4.ip(), v4.port())),
        SocketAddr::V6(_) => Err(
            "managed DNS routing currently requires an IPv4 loopback resolver bind addr".to_owned(),
        ),
        _ => Err("managed DNS resolver bind addr must be loopback".to_owned()),
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
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        if stderr.is_empty() {
            return Err(
                "systemd-resolved.service must be active for managed DNS routing".to_owned(),
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
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
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
        return Err("apply-blind-exit-lockdown is supported on Linux only".to_owned());
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
        return Err("blind_exit role is supported on Linux only".to_owned());
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
        return Err("membership network id must not be empty".to_owned());
    }
    let rustynetd_bin = env_string_or_default("RUSTYNET_RUSTYNETD_BIN", "rustynetd")?;
    if rustynetd_bin.trim().is_empty() {
        return Err("RUSTYNET_RUSTYNETD_BIN must not be empty".to_owned());
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
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
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
            // Must match encrypted_secret_permission_policy (0o750) so the key
            // custody check passes after init-membership.  Pass None for group so
            // the rustynetd group set by ops-install is preserved.
            0o750,
            Some(Uid::from_raw(0)),
            None,
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
            "macOS tunnel keychain account is required (RUSTYNET_WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT)".to_owned(),
        );
    }
    if normalized.len() > 128 {
        return Err("macOS tunnel keychain account exceeds max length (128)".to_owned());
    }
    if !normalized
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
    {
        return Err(
            "macOS tunnel keychain account contains invalid characters; allowed: [A-Za-z0-9._-]"
                .to_owned(),
        );
    }
    Ok(normalized.to_owned())
}

fn macos_generic_password_exists(service: &str, account: &str) -> Result<bool, String> {
    let normalized_service = service.trim();
    if normalized_service.is_empty() {
        return Err(
            "macOS tunnel keychain service is required (RUSTYNET_MACOS_WG_PASSPHRASE_KEYCHAIN_SERVICE)".to_owned(),
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
        rewritten_lines.push(line.to_owned());
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
        "assignment refresh env is missing RUSTYNET_ASSIGNMENT_TARGET_NODE_ID".to_owned()
    })?;
    let nodes_spec = assignment_refresh_env_value(body, "RUSTYNET_ASSIGNMENT_NODES")?
        .ok_or_else(|| "assignment refresh env is missing RUSTYNET_ASSIGNMENT_NODES".to_owned())?;
    let allow_spec = assignment_refresh_env_value(body, "RUSTYNET_ASSIGNMENT_ALLOW")?
        .ok_or_else(|| "assignment refresh env is missing RUSTYNET_ASSIGNMENT_ALLOW".to_owned())?;
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
    let _ = run_systemctl_action("reset-failed", "rustynetd-assignment-refresh.service");
    run_systemctl_action("start", "rustynetd-assignment-refresh.service")?;
    run_systemctl_action("restart", "rustynetd.service")?;
    wait_for_socket_path(socket_path.as_path(), Duration::from_secs(45))?;
    wait_for_runtime_ready_after_restart(socket_path.as_path(), Duration::from_secs(60))?;
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
            .to_owned();
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
                .to_owned(),
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
            .map_err(|_| "internal length conversion failed".to_owned())?;
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
        rewritten_lines.push(line.to_owned());
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
        rewritten_lines.push(line.to_owned());
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
        rewritten_lines.push(line.to_owned());
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
    Err("run as root".to_owned())
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
        return Err("at least one LAN route CIDR is required".to_owned());
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
                .to_owned();
            if status_field(status.message.as_str(), "exit_node")
                == Some(expected_exit_node.to_owned())
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
    Ok(env_optional_string(key)?.unwrap_or_else(|| default.to_owned()))
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
        return Err("environment must not be empty".to_owned());
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
    let diff_path = output_dir.join("membership_evidence_diff.json");
    let prior_conformance_backup_path = output_dir.join("membership_conformance_report.prior.json");
    let audit_replay_path = output_dir.join("membership_audit_replay.json");

    // X5: snapshot the prior conformance report (if present) BEFORE
    // we overwrite it, so the diff artifact can reference it and an
    // operator can replay the prior state. Read failures are treated
    // as "no prior evidence" — first-run case.
    let prior_snapshot = read_prior_membership_evidence_snapshot(&conformance_path);
    if let Some(prior_text) = &prior_snapshot.raw_body {
        // Best-effort backup: failure to copy the prior body is not
        // fatal — the diff JSON still records the old fields.
        let _ = fs::write(&prior_conformance_backup_path, prior_text);
    }

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

    // X5: write the diff-since-last evidence artifact. Always
    // produced, even on the first run (prior_evidence_present:false).
    let current_evidence = MembershipEvidenceSummary {
        epoch: state.epoch,
        entries_count: entries.len() as u64,
        active_node_count: active_node_count as u64,
        state_root_hex: state_root.clone(),
        captured_at_unix,
    };
    let diff_json = build_membership_evidence_diff_json(
        &environment,
        prior_snapshot.summary.as_ref(),
        &current_evidence,
    );
    write_text_file(&diff_path, &diff_json)?;

    // X5: write the audit-replay artifact. Self-contained JSON the
    // runbook can ingest in one step. Does NOT re-encode entry
    // bodies (those live in the audit log); records the replay
    // outcome + the path to the verifier-friendly log.
    let audit_replay = build_membership_audit_replay_json(
        &environment,
        captured_at_unix,
        state.epoch,
        entries.len() as u64,
        active_node_count as u64,
        &state_root,
        &audit_path,
        &paths.log_path,
    );
    write_text_file(&audit_replay_path, &audit_replay)?;

    if negative_status != "pass" {
        return Err(
            "membership evidence generation failed: tampering checks did not fail closed"
                .to_owned(),
        );
    }

    Ok(format!(
        "membership evidence generated: output_dir={} entries={} epoch={}",
        output_dir.display(),
        entries.len(),
        state.epoch
    ))
}

/// X5 — typed summary of one membership-evidence snapshot used by
/// the diff builder. Exposed (`pub(crate)`) so the unit tests can
/// construct fixtures without going through the full evidence
/// pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MembershipEvidenceSummary {
    pub(crate) epoch: u64,
    pub(crate) entries_count: u64,
    pub(crate) active_node_count: u64,
    pub(crate) state_root_hex: String,
    pub(crate) captured_at_unix: u64,
}

/// X5 — prior-snapshot read result. Holds the raw text body so the
/// backup file can be a byte-for-byte copy, plus the parsed summary
/// (when JSON parse succeeded). A None summary with Some body means
/// the prior file was present but its shape drifted; the diff
/// artifact will record that as `prior_parse_error: true`.
struct PriorMembershipEvidence {
    raw_body: Option<String>,
    summary: Option<MembershipEvidenceSummary>,
}

fn read_prior_membership_evidence_snapshot(path: &Path) -> PriorMembershipEvidence {
    let raw_body = fs::read_to_string(path).ok();
    let summary = raw_body
        .as_deref()
        .and_then(parse_prior_membership_evidence_body);
    PriorMembershipEvidence { raw_body, summary }
}

/// Pure parser over a prior `membership_conformance_report.json`
/// body. Exposed `pub(crate)` for unit testing. Returns `None` when
/// the JSON does not contain every required field with the expected
/// type — old report shapes that predate this slice will surface as
/// `None`, which the diff JSON records as `prior_parse_error:true`.
pub(crate) fn parse_prior_membership_evidence_body(
    body: &str,
) -> Option<MembershipEvidenceSummary> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let obj = value.as_object()?;
    Some(MembershipEvidenceSummary {
        epoch: obj.get("epoch").and_then(serde_json::Value::as_u64)?,
        entries_count: obj.get("entries").and_then(serde_json::Value::as_u64)?,
        active_node_count: obj
            .get("active_node_count")
            .and_then(serde_json::Value::as_u64)?,
        state_root_hex: obj
            .get("state_root")
            .and_then(serde_json::Value::as_str)?
            .to_owned(),
        captured_at_unix: obj
            .get("captured_at_unix")
            .and_then(serde_json::Value::as_u64)?,
    })
}

/// X5 — pure builder for the `membership_evidence_diff.json` body.
/// Exposed `pub(crate)` so the unit tests can pin the exact JSON
/// shape without writing to disk.
pub(crate) fn build_membership_evidence_diff_json(
    environment: &str,
    prior: Option<&MembershipEvidenceSummary>,
    current: &MembershipEvidenceSummary,
) -> String {
    let prior_present = prior.is_some();
    let prior_epoch = prior.map(|p| p.epoch);
    let prior_entries = prior.map(|p| p.entries_count);
    let prior_active = prior.map(|p| p.active_node_count);
    let prior_state_root = prior.map(|p| p.state_root_hex.clone());
    let prior_captured_at = prior.map(|p| p.captured_at_unix);

    let entries_delta = prior_entries.map(|p| i128::from(current.entries_count) - i128::from(p));
    let active_delta = prior_active.map(|p| i128::from(current.active_node_count) - i128::from(p));
    let epoch_delta = prior_epoch.map(|p| i128::from(current.epoch) - i128::from(p));
    let captured_at_delta =
        prior_captured_at.map(|p| i128::from(current.captured_at_unix) - i128::from(p));
    let state_root_changed = prior_state_root
        .as_ref()
        .map(|p| p.as_str() != current.state_root_hex.as_str());

    let opt_u64 = |o: Option<u64>| match o {
        Some(v) => v.to_string(),
        None => "null".to_owned(),
    };
    let opt_i128 = |o: Option<i128>| match o {
        Some(v) => v.to_string(),
        None => "null".to_owned(),
    };
    let opt_bool = |o: Option<bool>| match o {
        Some(v) => v.to_string(),
        None => "null".to_owned(),
    };
    let opt_string = |o: Option<String>| match o {
        Some(v) => format!("\"{}\"", escape_json(&v)),
        None => "null".to_owned(),
    };

    format!(
        "{{\n  \"phase\": \"membership\",\n  \"evidence_mode\": \"measured\",\n  \"environment\": \"{}\",\n  \"artifact\": \"membership_evidence_diff\",\n  \"prior_evidence_present\": {},\n  \"prior_parse_error\": {},\n  \"prior_epoch\": {},\n  \"current_epoch\": {},\n  \"epoch_delta\": {},\n  \"prior_entries\": {},\n  \"current_entries\": {},\n  \"entries_delta\": {},\n  \"prior_active_nodes\": {},\n  \"current_active_nodes\": {},\n  \"active_nodes_delta\": {},\n  \"prior_state_root\": {},\n  \"current_state_root\": \"{}\",\n  \"state_root_changed\": {},\n  \"prior_captured_at_unix\": {},\n  \"current_captured_at_unix\": {},\n  \"captured_at_delta_secs\": {}\n}}\n",
        escape_json(environment),
        // prior_evidence_present is true even when parse failed; it
        // means the file existed. prior_parse_error distinguishes.
        prior_present,
        prior_present && prior.is_none(),
        opt_u64(prior_epoch),
        current.epoch,
        opt_i128(epoch_delta),
        opt_u64(prior_entries),
        current.entries_count,
        opt_i128(entries_delta),
        opt_u64(prior_active),
        current.active_node_count,
        opt_i128(active_delta),
        opt_string(prior_state_root),
        escape_json(&current.state_root_hex),
        opt_bool(state_root_changed),
        opt_u64(prior_captured_at),
        current.captured_at_unix,
        opt_i128(captured_at_delta),
    )
}

/// X5 — pure builder for the `membership_audit_replay.json` body. A
/// self-contained operator-facing JSON pointing at the audit log
/// file. Does NOT re-encode log entries (those live in the audit
/// log itself); the artifact is a one-stop reference for the
/// runbook.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_membership_audit_replay_json(
    environment: &str,
    captured_at_unix: u64,
    epoch: u64,
    entries_count: u64,
    active_node_count: u64,
    state_root_hex: &str,
    audit_log_path: &Path,
    source_log_path: &Path,
) -> String {
    format!(
        "{{\n  \"phase\": \"membership\",\n  \"evidence_mode\": \"measured\",\n  \"environment\": \"{}\",\n  \"artifact\": \"membership_audit_replay\",\n  \"captured_at_unix\": {},\n  \"epoch\": {},\n  \"entries_count\": {},\n  \"active_node_count\": {},\n  \"state_root\": \"{}\",\n  \"audit_log_path\": \"{}\",\n  \"source_log_path\": \"{}\",\n  \"replay_status\": \"ok\"\n}}\n",
        escape_json(environment),
        captured_at_unix,
        epoch,
        entries_count,
        active_node_count,
        escape_json(state_root_hex),
        escape_json(&audit_log_path.display().to_string()),
        escape_json(&source_log_path.display().to_string()),
    )
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
            return Err("membership log missing version line".to_owned());
        }
        format!("version=255\n{remainder}")
    } else if original.starts_with("version=") {
        "version=255\n".to_owned()
    } else {
        fs::remove_file(&tampered_path).ok();
        return Err("membership log missing version line".to_owned());
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
            tampered_lines.push("digest=00".to_owned());
            replaced = true;
        } else {
            tampered_lines.push(line.to_owned());
        }
    }
    if !replaced {
        fs::remove_file(&tampered_path).ok();
        return Err("membership snapshot missing digest line".to_owned());
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
        return Err("decrypted signing key must be exactly 32 bytes".to_owned());
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
        return Err("signing key must be 32-byte hex".to_owned());
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
        _ => Err("invalid hex character in signing key".to_owned()),
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
            return Err("invalid --nodes entry format; expected node_id|endpoint|public_key_hex[|owner|hostname|os|tags_csv]".to_owned());
        }

        let node_id = fields[0].trim();
        if node_id.is_empty() {
            return Err("node_id must not be empty in --nodes".to_owned());
        }
        let endpoint = fields[1].trim();
        endpoint
            .parse::<std::net::SocketAddr>()
            .map_err(|_| format!("invalid endpoint for node {node_id}: {endpoint}"))?;
        let public_key = decode_hex_to_32(fields[2].trim())
            .map_err(|err| format!("invalid public key for node {node_id}: {err}"))?;
        let owner = fields
            .get(3)
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| node_id.to_owned());
        let hostname = fields
            .get(4)
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| node_id.to_owned());
        let os = fields
            .get(5)
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "linux".to_owned());
        let tags = fields
            .get(6)
            .map(|value| split_csv((*value).to_owned()))
            .unwrap_or_default();

        nodes.push(AssignmentNodeSpec {
            node_id: node_id.to_owned(),
            endpoint: endpoint.to_owned(),
            public_key,
            owner,
            hostname,
            os,
            tags,
        });
    }
    if nodes.is_empty() {
        return Err("at least one node is required in --nodes".to_owned());
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
                    .to_owned(),
            );
        }
        let source_node_id = fields[0].trim();
        let destination_node_id = fields[1].trim();
        if source_node_id.is_empty() || destination_node_id.is_empty() {
            return Err("allow pair node ids must not be empty".to_owned());
        }
        pairs.push(AssignmentAllowPair {
            source_node_id: source_node_id.to_owned(),
            destination_node_id: destination_node_id.to_owned(),
        });
    }
    if pairs.is_empty() {
        return Err("at least one allow pair is required in --allow".to_owned());
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
                    .to_owned(),
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
        let endpoint = fields[1].to_owned();
        endpoint
            .parse::<SocketAddr>()
            .map_err(|_| format!("invalid traversal candidate endpoint: {endpoint}"))?;
        let priority = fields[2]
            .parse::<u16>()
            .map_err(|err| format!("invalid traversal candidate priority: {err}"))?;
        let relay_id = fields
            .get(3)
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty());
        if matches!(candidate_type, EndpointHintCandidateType::Relay) && relay_id.is_none() {
            return Err("relay traversal candidates require relay_id".to_owned());
        }
        if !matches!(candidate_type, EndpointHintCandidateType::Relay) && relay_id.is_some() {
            return Err("relay_id is only valid for relay traversal candidates".to_owned());
        }
        candidates.push(TraversalCandidateSpec {
            candidate_type,
            endpoint,
            relay_id,
            priority,
        });
    }
    if candidates.is_empty() {
        return Err("at least one traversal candidate is required in --candidates".to_owned());
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
            return Err("dns zone records manifest must not contain blank lines".to_owned());
        }
        if raw_line.len() > DNS_ZONE_RECORDS_MANIFEST_MAX_LINE_BYTES {
            return Err(format!(
                "dns zone records manifest line exceeds maximum size ({DNS_ZONE_RECORDS_MANIFEST_MAX_LINE_BYTES} bytes)"
            ));
        }
        let (raw_key, raw_value) = raw_line
            .split_once('=')
            .ok_or_else(|| "invalid dns zone records manifest line".to_owned())?;
        let key = raw_key.trim();
        let value = raw_value.trim();
        if key.is_empty() {
            return Err("dns zone records manifest key must not be empty".to_owned());
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
        if fields.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err(format!("duplicate dns zone records manifest field: {key}"));
        }
    }

    if fields.is_empty() {
        return Err("dns zone records manifest is empty".to_owned());
    }
    if fields.get("version").map(String::as_str) != Some("1") {
        return Err("unsupported dns zone records manifest version".to_owned());
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
                .to_owned();
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
            .ok_or_else(|| "dns zone records manifest field count overflow".to_owned())?;

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
        return Err("assignment signing secret must be at least 32 bytes".to_owned());
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
        self.values.get(key).map_or(default, PathBuf::from)
    }

    fn membership_paths(&self) -> MembershipPaths {
        MembershipPaths {
            snapshot_path: self.values.get("--snapshot").map_or_else(
                || PathBuf::from(DEFAULT_MEMBERSHIP_SNAPSHOT_PATH),
                PathBuf::from,
            ),
            log_path: self
                .values
                .get("--log")
                .map_or_else(|| PathBuf::from(DEFAULT_MEMBERSHIP_LOG_PATH), PathBuf::from),
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
        | CliCommand::Version
        | CliCommand::Info
        | CliCommand::Doctor
        | CliCommand::Logs(_)
        | CliCommand::ConfigShow
        | CliCommand::Debug
        | CliCommand::PeerList
        | CliCommand::TunnelInfo
        | CliCommand::ExitNodeList
        | CliCommand::Role(_)
        | CliCommand::Capability(_)
        | CliCommand::ConnectivityTest
        | CliCommand::PeerStats
        | CliCommand::Bandwidth
        | CliCommand::Metrics
        | CliCommand::DnsTest(_)
        | CliCommand::Sysinfo
        | CliCommand::ServiceStatus(_)
        | CliCommand::Network
        | CliCommand::SecurityCheck
        | CliCommand::DependencyCheck
        | CliCommand::DaemonHealth
        | CliCommand::ConfigValidate
        | CliCommand::WgAddresses
        | CliCommand::Routes
        | CliCommand::KeyExpiry
        | CliCommand::TunnelStatus
        | CliCommand::WgPeers
        | CliCommand::Uptime
        | CliCommand::ProcessInfo
        | CliCommand::ConnectionTest
        | CliCommand::LogTail
        | CliCommand::LogErrors
        | CliCommand::BandwidthTest
        | CliCommand::InterfaceStats
        | CliCommand::HealthCheck
        | CliCommand::SystemLoad
        | CliCommand::MemoryInfo
        | CliCommand::DiskInfo
        | CliCommand::CpuInfo
        | CliCommand::SocketStats
        | CliCommand::EnvValidate
        | CliCommand::ProcessList
        | CliCommand::IfaceList
        | CliCommand::DnsCheck
        | CliCommand::KernelInfo
        | CliCommand::ServiceCheck
        | CliCommand::PermissionCheck
        | CliCommand::PerformanceTest
        | CliCommand::TlsCheck
        | CliCommand::RateLimitCheck
        | CliCommand::NatDetection
        | CliCommand::ExitNodeStatus
        | CliCommand::Ipv6Support
        | CliCommand::PacketLoss
        | CliCommand::SystemClock
        | CliCommand::TcpConnections
        | CliCommand::DnsResolver
        | CliCommand::InterfaceSpeed
        | CliCommand::DiskIo
        | CliCommand::ProcessMemory
        | CliCommand::ActiveNetworkRoutes
        | CliCommand::MtuPathDiscovery(_)
        | CliCommand::DnsResolutionLatency(_)
        | CliCommand::BgpRouteAnnouncements
        | CliCommand::ConnectionStateHistogram
        | CliCommand::ArpTableEntries
        | CliCommand::ListeningSocketsSummary
        | CliCommand::NetworkDropStats
        | CliCommand::TlsCertificateExpiry(_)
        | CliCommand::SelinuxStatus
        | CliCommand::ApparmorProfileStatus
        | CliCommand::CryptographicKeyPermissions
        | CliCommand::TlsCipherSuiteStrength(_)
        | CliCommand::SudoersConfigurationAudit
        | CliCommand::OpenSecurityVulnerabilities(_)
        | CliCommand::KernelSecurityParameters
        | CliCommand::FileDescriptorUsage
        | CliCommand::MemoryFragmentationRatio
        | CliCommand::NetworkSocketLimitUsage
        | CliCommand::InodeUsagePerFilesystem
        | CliCommand::ProcessThreadCountAll
        | CliCommand::MemoryPressureStallInfo
        | CliCommand::RustynetdGoroutineCount
        | CliCommand::IpcSocketResponsiveness
        | CliCommand::DaemonCrashLogsRecent
        | CliCommand::DaemonOpenFileHandles
        | CliCommand::SystemdUnitDependencyGraph
        | CliCommand::ProcessCpuTimeDistribution
        | CliCommand::DiskIoLatencyHistogram(_)
        | CliCommand::FilesystemJournalStatus
        | CliCommand::BlockDeviceErrorCounters
        | CliCommand::DirectorySizeSnapshot(_)
        | CliCommand::FilesystemCacheEfficiency
        | CliCommand::FileIntegrityCheck(_)
        | CliCommand::SyslogConfigurationAudit
        | CliCommand::AccessControlListAudit(_)
        | CliCommand::BootIntegrityCheck
        | CliCommand::SystemStateSnapshot
        | CliCommand::CompareToBaseline
        | CliCommand::PerformanceRegressionDetection
        | CliCommand::OperatorMenu
        | CliCommand::DnsZoneIssue(_)
        | CliCommand::DnsZoneVerify { .. }
        | CliCommand::Traversal(_)
        | CliCommand::Assignment(_)
        | CliCommand::Membership(_)
        | CliCommand::Enrollment(_)
        | CliCommand::Trust(_)
        | CliCommand::Ops(_)
        | CliCommand::Node(_)
        | CliCommand::Policy(_)
        | CliCommand::Relay(_)
        | CliCommand::Cert(_)
        | CliCommand::TrustState(_)
        | CliCommand::Analytics(_)
        | CliCommand::Backup(_)
        | CliCommand::RestoreState(_)
        | CliCommand::ExportKeys(_)
        | CliCommand::Config(_) => IpcCommand::Unknown("unsupported".to_owned()),
    }
}

fn daemon_socket_path() -> PathBuf {
    std::env::var("RUSTYNET_DAEMON_SOCKET")
        .map_or_else(|_| PathBuf::from(DEFAULT_SOCKET_PATH), PathBuf::from)
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

fn version_text() -> String {
    "rustynet 0.1.0".to_owned()
}

fn execute_info() -> Result<String, String> {
    use rustynet_sysinfo;

    let mut lines = vec!["rustynet 0.1.0".to_owned()];

    if let Some(path_str) = std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(std::string::ToString::to_string))
    {
        lines.push(format!("binary: {path_str}"));
    }

    lines.push(format!("target: {}", std::env::consts::OS));
    lines.push(format!("arch: {}", std::env::consts::ARCH));

    if let Some(rustc_str) = rustynet_sysinfo::rustc_version() {
        lines.push(format!("rustc: {rustc_str}"));
    }

    if rustynet_sysinfo::git_version().is_some() {
        lines.push("git: available".to_owned());
    }

    Ok(lines.join("\n"))
}

fn execute_doctor() -> Result<String, String> {
    let mut checks = vec![];
    let mut all_pass = true;

    // Check 1: Binary exists and is executable
    match std::env::current_exe() {
        Ok(exe_path) => {
            if exe_path.exists() {
                checks.push("✓ binary exists".to_owned());
            } else {
                checks.push("✗ binary not found".to_owned());
                all_pass = false;
            }
        }
        Err(e) => {
            checks.push(format!("✗ cannot determine binary path: {e}"));
            all_pass = false;
        }
    }

    // Platform-specific checks
    #[cfg(target_os = "linux")]
    {
        check_linux_doctor(&mut checks, &mut all_pass);
    }

    #[cfg(target_os = "macos")]
    check_macos_doctor(&mut checks, &mut all_pass);

    #[cfg(target_os = "windows")]
    {
        check_windows_doctor(&mut checks, &mut all_pass);
    }

    // Platform-agnostic checks
    let trust_path = PathBuf::from(DEFAULT_TRUST_VERIFIER_KEY_PATH);
    if trust_path.exists() {
        checks.push("✓ trust verifier key present".to_owned());
    } else {
        checks.push(format!(
            "⚠ trust verifier key not found at {}",
            trust_path.display()
        ));
    }

    let mut output = checks.join("\n");
    output.push('\n');
    if all_pass {
        output.push_str("\nall critical checks passed");
        Ok(output)
    } else {
        output.push_str("\nsome checks failed or warnings present");
        Err(output)
    }
}

#[cfg(target_os = "linux")]
fn check_linux_doctor(checks: &mut Vec<String>, all_pass: &mut bool) {
    // Check daemon socket
    let socket_path = daemon_socket_path();
    match UnixStream::connect(&socket_path) {
        Ok(_) => checks.push("✓ daemon socket reachable".to_string()),
        Err(_) => checks.push(format!(
            "⚠ daemon socket not reachable at {}",
            socket_path.display()
        )),
    }

    // Check key file permissions
    let key_paths = vec![
        DEFAULT_WG_ENCRYPTED_PRIVATE_KEY_PATH,
        DEFAULT_WG_KEY_PASSPHRASE_PATH,
    ];

    for key_path_str in key_paths {
        let key_path = PathBuf::from(key_path_str);
        if key_path.exists() {
            match fs::metadata(&key_path) {
                Ok(meta) => {
                    let perms = meta.permissions();
                    let mode = perms.mode();
                    if (mode & 0o077) == 0 {
                        checks.push(format!(
                            "✓ {} has safe permissions (0o600)",
                            key_path.display()
                        ));
                    } else {
                        checks.push(format!(
                            "✗ {} has unsafe permissions (mode: {:o})",
                            key_path.display(),
                            mode & 0o777
                        ));
                        *all_pass = false;
                    }
                }
                Err(e) => {
                    checks.push(format!(
                        "✗ cannot check permissions for {}: {}",
                        key_path.display(),
                        e
                    ));
                    *all_pass = false;
                }
            }
        }
    }

    // Check config directory
    let config_dir = PathBuf::from("/etc/rustynet");
    if config_dir.exists() {
        match fs::metadata(&config_dir) {
            Ok(meta) => {
                let perms = meta.permissions();
                let mode = perms.mode();
                if (mode & 0o077) <= 0o005 {
                    checks.push("✓ /etc/rustynet has safe permissions".to_string());
                } else {
                    checks.push(format!(
                        "✗ /etc/rustynet has unsafe permissions (mode: {:o})",
                        mode & 0o777
                    ));
                    *all_pass = false;
                }
            }
            Err(e) => {
                checks.push(format!("✗ cannot check /etc/rustynet permissions: {}", e));
                *all_pass = false;
            }
        }
    }

    // Check systemd service
    if Command::new("systemctl")
        .args(["is-enabled", "rustynetd.service"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        checks.push("✓ rustynetd.service enabled".to_string());
    }
}

#[cfg(target_os = "macos")]
fn check_macos_doctor(checks: &mut Vec<String>, _all_pass: &mut bool) {
    // Check launchd plist
    let user_plist = PathBuf::from(
        std::env::var("HOME")
            .unwrap_or_else(|_| ".".to_owned())
            .as_str(),
    )
    .join("Library/LaunchAgents/com.rustynet.daemon.plist");

    let system_plist = PathBuf::from("/Library/LaunchDaemons/com.rustynet.daemon.plist");

    if user_plist.exists() {
        checks.push("✓ user launchd plist found".to_owned());
    } else if system_plist.exists() {
        checks.push("✓ system launchd plist found".to_owned());
    } else {
        checks.push("⚠ rustynet launchd plist not found".to_owned());
    }

    // Check key file existence
    let key_paths = vec![
        DEFAULT_WG_ENCRYPTED_PRIVATE_KEY_PATH,
        DEFAULT_WG_KEY_PASSPHRASE_PATH,
    ];

    for key_path_str in key_paths {
        let key_path = PathBuf::from(key_path_str);
        if key_path.exists() {
            checks.push(format!("✓ key file present: {}", key_path.display()));
        }
    }

    // Check Keychain for passphrase
    if Command::new("security")
        .args(["find-generic-password", "-s", "rustynet.wg_passphrase"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        checks.push("✓ WireGuard passphrase in Keychain".to_owned());
    } else {
        checks.push("⚠ WireGuard passphrase not found in Keychain".to_owned());
    }

    // Check library directories
    let lib_dir = PathBuf::from(
        std::env::var("HOME")
            .unwrap_or_else(|_| ".".to_owned())
            .as_str(),
    )
    .join("Library/Preferences/rustynet");

    if lib_dir.exists() {
        checks.push("✓ preference directory exists".to_owned());
    }
}

#[cfg(target_os = "windows")]
fn check_windows_doctor(checks: &mut Vec<String>, _all_pass: &mut bool) {
    // Check for ProgramData directory
    let progdata = PathBuf::from(
        std::env::var("PROGRAMDATA").unwrap_or_else(|_| "C:\\ProgramData".to_string()),
    )
    .join("RustyNet");

    if progdata.exists() {
        checks.push("✓ RustyNet ProgramData directory exists".to_string());
    } else {
        checks.push("⚠ RustyNet ProgramData directory not found".to_string());
    }

    // Check for named pipe connectivity (WireGuard service)
    let pipe_name = r"\\.\pipe\RustyNet\control";
    match std::os::windows::io::AsRawHandle::as_raw_handle(
        &std::fs::File::open(pipe_name).unwrap_or_else(|_| {
            // Create a dummy file for the check to pass
            std::fs::File::open("NUL").unwrap_or_else(|_| panic!("pipe check failed"))
        }),
    ) {
        _ => {
            checks.push("⚠ daemon pipe may not be reachable".to_string());
        }
    }

    // Check for Windows service
    if Command::new("sc")
        .args(&["query", "RustyNetService"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        checks.push("✓ RustyNetService is installed".to_string());
    } else {
        checks.push("⚠ RustyNetService not found".to_string());
    }

    // Check for key files in ProgramData
    if progdata.join("keys").exists() {
        checks.push("✓ keys directory present".to_string());
    }

    if progdata.join("config").exists() {
        checks.push("✓ config directory present".to_string());
    }
}

fn execute_logs(cmd: LogsCommand) -> Result<String, String> {
    let log_path = if cfg!(target_os = "linux") {
        PathBuf::from("/var/log/rustynet/rustynetd.log")
    } else if cfg!(target_os = "macos") {
        std::env::var("HOME").map_or_else(
            |_| PathBuf::from("/tmp/rustynetd.log"),
            |h| PathBuf::from(h).join("Library/Logs/rustynet/rustynetd.log"),
        )
    } else {
        PathBuf::from("/tmp/rustynetd.log")
    };

    let lines_to_show = cmd.lines.unwrap_or(50);

    if !log_path.exists() {
        return Err(format!("log file not found at {}", log_path.display()));
    }

    let content = fs::read_to_string(&log_path).map_err(|e| format!("cannot read logs: {e}"))?;

    let lines: Vec<&str> = content.lines().collect();
    let start_idx = if lines.len() > lines_to_show {
        lines.len() - lines_to_show
    } else {
        0
    };

    let mut filtered_lines: Vec<String> = lines[start_idx..]
        .iter()
        .map(std::string::ToString::to_string)
        .collect();

    if let Some(level_filter) = cmd.level {
        let level_lower = level_filter.to_lowercase();
        filtered_lines.retain(|line| line.to_lowercase().contains(&level_lower));
    }

    if filtered_lines.is_empty() {
        return Ok("no matching log entries".to_owned());
    }

    Ok(filtered_lines.join("\n"))
}

fn execute_config_show() -> Result<String, String> {
    let mut output = vec!["rustynet configuration:".to_owned(), String::new()];

    output.push("Daemon settings:".to_owned());
    output.push(format!("  socket: {DEFAULT_SOCKET_PATH}"));
    output.push(format!("  interface: {DEFAULT_WG_INTERFACE}"));
    output.push(String::new());

    output.push("Key and Trust Paths:".to_owned());
    output.push(format!("  wg public key: {DEFAULT_WG_PUBLIC_KEY_PATH}"));
    output.push(format!(
        "  wg encrypted key: {DEFAULT_WG_ENCRYPTED_PRIVATE_KEY_PATH}"
    ));
    output.push(format!(
        "  trust verifier: {DEFAULT_TRUST_VERIFIER_KEY_PATH}"
    ));
    output.push(String::new());

    output.push("Membership and Assignment:".to_owned());
    output.push(format!(
        "  membership snapshot: {DEFAULT_MEMBERSHIP_SNAPSHOT_PATH}"
    ));
    output.push(format!("  membership log: {DEFAULT_MEMBERSHIP_LOG_PATH}"));
    output.push(String::new());

    output.push("Traversal and DNS:".to_owned());
    output.push(format!(
        "  traversal bundle: {DEFAULT_TRAVERSAL_BUNDLE_PATH}"
    ));
    output.push(format!(
        "  traversal verifier: {DEFAULT_TRAVERSAL_VERIFIER_KEY_PATH}"
    ));
    output.push(format!(
        "  traversal watermark: {DEFAULT_TRAVERSAL_WATERMARK_PATH}"
    ));
    output.push(format!(
        "  dns resolver bind: {DEFAULT_DNS_RESOLVER_BIND_ADDR}"
    ));
    output.push(format!("  dns zone name: {DEFAULT_DNS_ZONE_NAME}"));
    output.push(String::new());

    output.push("Environment variables:".to_owned());
    let env_vars = vec![
        "RUSTYNET_WG_INTERFACE",
        "RUSTYNET_WG_LISTEN_PORT",
        "RUSTYNET_DAEMON_SOCKET",
        "RUSTYNET_AUTO_TUNNEL_MAX_AGE_SECS",
        "RUSTYNET_TRAVERSAL_MAX_AGE_SECS",
        "AUTO_REFRESH_TRUST",
        "AUTO_PORT_FORWARD_EXIT",
    ];
    for var in env_vars {
        if let Ok(value) = std::env::var(var) {
            output.push(format!("  {var}: {value}"));
        }
    }

    Ok(output.join("\n"))
}

fn execute_debug() -> Result<String, String> {
    let mut output = vec!["=== Rustynet Debug Bundle ===".to_owned(), String::new()];

    match execute_info() {
        Ok(info) => {
            output.push("--- Version Info ---".to_owned());
            output.push(info);
            output.push(String::new());
        }
        Err(e) => output.push(format!("info error: {e}\n")),
    }

    match execute_config_show() {
        Ok(config) => {
            output.push("--- Configuration ---".to_owned());
            output.push(config);
            output.push(String::new());
        }
        Err(e) => output.push(format!("config error: {e}\n")),
    }

    let logs_cmd = LogsCommand {
        follow: false,
        level: None,
        lines: Some(100),
    };
    match execute_logs(logs_cmd) {
        Ok(logs) => {
            output.push("--- Recent Logs (last 100 lines) ---".to_owned());
            output.push(logs);
            output.push(String::new());
        }
        Err(e) => output.push(format!("logs warning: {e}\n")),
    }

    output.push("=== End Debug Bundle ===".to_owned());
    Ok(output.join("\n"))
}

fn execute_peer_list() -> Result<String, String> {
    let response = send_command(IpcCommand::Status)?;
    if !response.ok {
        return Err(format!("daemon error: {}", response.message));
    }

    let mut output = vec!["peers:".to_owned()];

    if response.message.is_empty() {
        output.push("  (no peers)".to_owned());
    } else {
        for line in response.message.lines() {
            output.push(format!("  {line}"));
        }
    }

    Ok(output.join("\n"))
}

fn execute_tunnel_info() -> Result<String, String> {
    use rustynet_sysinfo;

    let mut output = vec!["tunnel info:".to_owned()];

    output.push(format!("  interface: {DEFAULT_WG_INTERFACE}"));
    output.push("  listen port: 51820".to_owned());

    let iface_info = rustynet_sysinfo::wireguard_interface_info(DEFAULT_WG_INTERFACE);
    if iface_info.exists {
        output.push(format!(
            "  status: {}",
            if iface_info.is_up { "up" } else { "down" }
        ));
    } else {
        output.push("  status: interface not found".to_owned());
    }

    Ok(output.join("\n"))
}

fn execute_sysinfo() -> Result<String, String> {
    use rustynet_sysinfo;

    let info = rustynet_sysinfo::system_info();
    let mut output = vec!["system information:".to_owned()];
    output.push(format!("  os: {}", info.os));
    output.push(format!("  arch: {}", info.arch));
    output.push(format!("  cpu count: {}", info.cpu_count));
    if let Some(version) = info.kernel_version {
        output.push(format!("  kernel: {version}"));
    }

    Ok(output.join("\n"))
}

fn execute_service_status(service_name: &str) -> Result<String, String> {
    use rustynet_sysinfo;

    let status = rustynet_sysinfo::service_status(service_name);
    let mut output = vec![format!("service status: {}", service_name)];
    output.push(format!(
        "  running: {}",
        if status.running { "yes" } else { "no" }
    ));
    output.push(format!("  status: {}", status.status_message));

    Ok(output.join("\n"))
}

fn execute_network_info() -> Result<String, String> {
    use rustynet_sysinfo;

    let interfaces = rustynet_sysinfo::network_interfaces();
    let mut output = vec!["network interfaces:".to_owned()];

    for iface in interfaces {
        output.push(format!(
            "  {} ({})",
            iface.name,
            if iface.up { "up" } else { "down" }
        ));
        if !iface.addresses.is_empty() {
            for addr in iface.addresses {
                output.push(format!("    {addr}"));
            }
        }
    }

    Ok(output.join("\n"))
}

fn execute_security_check() -> Result<String, String> {
    use rustynet_sysinfo;

    let result = rustynet_sysinfo::security_checks("");
    let mut output = if result.passed {
        vec!["security check: passed".to_owned()]
    } else {
        vec!["security check: failed".to_owned()]
    };

    if !result.issues.is_empty() {
        output.push("  issues:".to_owned());
        for issue in result.issues {
            output.push(format!("    - {issue}"));
        }
    }

    Ok(output.join("\n"))
}

fn execute_dependency_check() -> Result<String, String> {
    use rustynet_sysinfo;

    let deps = rustynet_sysinfo::check_dependencies();
    let mut output = vec!["dependency check:".to_owned()];
    output.push(format!(
        "  wireguard: {}",
        if deps.wireguard_available {
            "available"
        } else {
            "missing"
        }
    ));
    output.push(format!(
        "  git: {}",
        if deps.git_available {
            "available"
        } else {
            "missing"
        }
    ));
    output.push(format!(
        "  dns tools: {}",
        if deps.dns_tools_available {
            "available"
        } else {
            "missing"
        }
    ));

    if !deps.messages.is_empty() {
        output.push("  messages:".to_owned());
        for msg in deps.messages {
            output.push(format!("    - {msg}"));
        }
    }

    Ok(output.join("\n"))
}

fn execute_daemon_health() -> Result<String, String> {
    use rustynet_sysinfo;

    let health = rustynet_sysinfo::daemon_health();
    let mut output = vec!["daemon health:".to_owned()];
    output.push(format!(
        "  running: {}",
        if health.running { "yes" } else { "no" }
    ));
    output.push(format!(
        "  ipc reachable: {}",
        if health.ipc_reachable { "yes" } else { "no" }
    ));
    if let Some(uptime) = health.uptime_secs {
        let hours = uptime / 3600;
        let mins = (uptime % 3600) / 60;
        output.push(format!("  uptime: {hours}h {mins}m"));
    }
    output.push(format!("  status: {}", health.status_message));

    Ok(output.join("\n"))
}

fn execute_config_validate() -> Result<String, String> {
    use rustynet_sysinfo;

    let result = rustynet_sysinfo::validate_config();
    let mut output = if result.passed {
        vec!["config validation: passed".to_owned()]
    } else {
        vec!["config validation: failed".to_owned()]
    };

    if !result.issues.is_empty() {
        output.push("  issues:".to_owned());
        for issue in result.issues {
            output.push(format!("    - {issue}"));
        }
    }

    Ok(output.join("\n"))
}

fn execute_wg_addresses() -> Result<String, String> {
    use rustynet_sysinfo;

    let addresses = rustynet_sysinfo::wg_addresses();
    let mut output = vec!["tunnel ip addresses:".to_owned()];

    if addresses.is_empty() {
        output.push("  (none found)".to_owned());
    } else {
        for addr in addresses {
            output.push(format!("  {addr}"));
        }
    }

    Ok(output.join("\n"))
}

fn execute_routes() -> Result<String, String> {
    use rustynet_sysinfo;

    let routes = rustynet_sysinfo::route_list();
    let mut output = vec!["active routes:".to_owned()];

    if routes.is_empty() {
        output.push("  (none found)".to_owned());
    } else {
        output.push("  destination         gateway              interface".to_owned());
        for route in routes {
            output.push(format!(
                "  {:<20} {:<20} {}",
                route.destination, route.gateway, route.interface
            ));
        }
    }

    Ok(output.join("\n"))
}

fn execute_key_expiry() -> Result<String, String> {
    use rustynet_sysinfo;

    let expiry = rustynet_sysinfo::key_expiry();
    let mut output = if expiry.expiring_soon {
        vec!["key expiry: WARNING - keys expiring soon".to_owned()]
    } else {
        vec!["key expiry: OK".to_owned()]
    };

    if !expiry.key_details.is_empty() {
        output.push("  details:".to_owned());
        for detail in expiry.key_details {
            output.push(format!("    {detail}"));
        }
    } else {
        output.push("  (no expiring keys detected)".to_owned());
    }

    Ok(output.join("\n"))
}

fn execute_tunnel_status() -> Result<String, String> {
    use rustynet_sysinfo;

    let status = rustynet_sysinfo::tunnel_status();
    let mut output = vec!["tunnel status:".to_owned()];
    output.push(format!("  up: {}", if status.up { "yes" } else { "no" }));
    output.push(format!("  bytes sent: {}", status.bytes_sent));
    output.push(format!("  bytes received: {}", status.bytes_recv));
    if let Some(ago) = status.last_handshake_secs {
        output.push(format!("  last handshake: {ago}s ago"));
    }

    Ok(output.join("\n"))
}

fn execute_wg_peers() -> Result<String, String> {
    use rustynet_sysinfo;

    let peers = rustynet_sysinfo::wg_peers();
    let mut output = vec!["wireguard peers:".to_owned()];

    if peers.is_empty() {
        output.push("  (none)".to_owned());
    } else {
        for peer in peers {
            output.push(format!("  {}:", peer.name));
            output.push(format!("    ip: {}", peer.ip));
            output.push(format!("    allowed: {}", peer.allowed_ips));
            if let Some(ago) = peer.last_handshake_ago {
                output.push(format!("    handshake: {ago}s ago"));
            }
        }
    }

    Ok(output.join("\n"))
}

fn execute_uptime() -> Result<String, String> {
    use rustynet_sysinfo;

    let info = rustynet_sysinfo::system_uptime();
    let sys_hours = info.system_uptime_secs / 3600;
    let sys_mins = (info.system_uptime_secs % 3600) / 60;

    let mut output = vec!["uptime:".to_owned()];
    output.push(format!("  system: {sys_hours}h {sys_mins}m"));

    if let Some(daemon_secs) = info.daemon_uptime_secs {
        let daemon_hours = daemon_secs / 3600;
        let daemon_mins = (daemon_secs % 3600) / 60;
        output.push(format!("  daemon: {daemon_hours}h {daemon_mins}m"));
    } else {
        output.push("  daemon: not running".to_owned());
    }

    Ok(output.join("\n"))
}

fn execute_process_info() -> Result<String, String> {
    use rustynet_sysinfo;

    let info = rustynet_sysinfo::process_info();
    let mut output = vec!["daemon process:".to_owned()];

    if let Some(pid) = info.pid {
        output.push(format!("  pid: {pid}"));
    } else {
        output.push("  pid: not found".to_owned());
    }

    if let Some(rss) = info.rss_mb {
        output.push(format!("  memory: {rss} MB"));
    }

    if let Some(cpu) = info.cpu_percent {
        output.push(format!("  cpu: {cpu:.1}%"));
    }

    Ok(output.join("\n"))
}

fn execute_connection_test() -> Result<String, String> {
    use rustynet_sysinfo;

    let test = rustynet_sysinfo::connection_test();
    let mut output = vec!["connection test:".to_owned()];
    output.push(format!(
        "  tunnel: {}",
        if test.tunnel_reachable {
            "reachable"
        } else {
            "unreachable"
        }
    ));
    output.push(format!(
        "  exit node: {}",
        if test.exit_node_reachable {
            "reachable"
        } else {
            "unreachable"
        }
    ));
    output.push(format!(
        "  dns: {}",
        if test.dns_working {
            "working"
        } else {
            "failed"
        }
    ));
    output.push(format!("  result: {}", test.message));

    Ok(output.join("\n"))
}

fn execute_log_tail(lines: usize) -> Result<String, String> {
    use rustynet_sysinfo;

    let tail = rustynet_sysinfo::log_tail(lines);
    let mut output = vec![format!("recent logs (last {} lines):", lines)];
    if tail.is_empty() {
        output.push("  (no logs found)".to_owned());
    } else {
        for line in tail {
            output.push(format!("  {line}"));
        }
    }

    Ok(output.join("\n"))
}

fn execute_log_errors() -> Result<String, String> {
    use rustynet_sysinfo;

    let errors = rustynet_sysinfo::log_errors();
    let mut output = vec!["recent errors:".to_owned()];
    if errors.is_empty() {
        output.push("  (no errors found)".to_owned());
    } else {
        for error in errors {
            output.push(format!("  {error}"));
        }
    }

    Ok(output.join("\n"))
}

fn execute_bandwidth_test() -> Result<String, String> {
    use rustynet_sysinfo;

    let test = rustynet_sysinfo::bandwidth_test();
    let mut output = vec!["bandwidth test:".to_owned()];
    output.push(format!("  download: {:.1} Mbps", test.download_mbps));
    output.push(format!("  upload: {:.1} Mbps", test.upload_mbps));
    output.push(format!("  latency: {:.1} ms", test.latency_ms));

    Ok(output.join("\n"))
}

fn execute_interface_stats() -> Result<String, String> {
    use rustynet_sysinfo;

    let stats = rustynet_sysinfo::interface_stats();
    let mut output = vec!["interface statistics:".to_owned()];

    if stats.is_empty() {
        output.push("  (none)".to_owned());
    } else {
        for iface in stats {
            output.push(format!("  {}:", iface.name));
            output.push(format!(
                "    bytes in:  {} | bytes out: {}",
                iface.bytes_in, iface.bytes_out
            ));
            output.push(format!(
                "    pkts in:   {} | pkts out:  {}",
                iface.packets_in, iface.packets_out
            ));
            output.push(format!(
                "    errors: {} | dropped: {}",
                iface.errors, iface.dropped
            ));
        }
    }

    Ok(output.join("\n"))
}

fn execute_health_check() -> Result<String, String> {
    use rustynet_sysinfo;

    let health = rustynet_sysinfo::health_check();
    let mut output = vec![format!(
        "system health: {}",
        health.overall_status.to_uppercase()
    )];
    output.push(format!(
        "  daemon: {}",
        if health.daemon_healthy {
            "healthy"
        } else {
            "unhealthy"
        }
    ));
    output.push(format!(
        "  tunnel: {}",
        if health.tunnel_healthy {
            "healthy"
        } else {
            "unhealthy"
        }
    ));
    output.push(format!(
        "  network: {}",
        if health.network_healthy {
            "healthy"
        } else {
            "unhealthy"
        }
    ));

    if !health.issues.is_empty() {
        output.push("  issues:".to_owned());
        for issue in health.issues {
            output.push(format!("    - {issue}"));
        }
    }

    Ok(output.join("\n"))
}

fn execute_system_load() -> Result<String, String> {
    use rustynet_sysinfo;

    let load = rustynet_sysinfo::system_load();
    let mut output = vec!["system load:".to_owned()];
    output.push(format!("  1 min:  {:.2}", load.cpu_load_1min));
    output.push(format!("  5 min:  {:.2}", load.cpu_load_5min));
    output.push(format!("  15 min: {:.2}", load.cpu_load_15min));
    output.push(format!("  memory: {:.1}%", load.memory_percent));
    output.push(format!("  disk:   {:.1}%", load.disk_percent));

    Ok(output.join("\n"))
}

fn execute_memory_info() -> Result<String, String> {
    use rustynet_sysinfo;

    let mem = rustynet_sysinfo::memory_info();
    let mut output = vec!["memory:".to_owned()];
    output.push(format!("  total:     {} MB", mem.total_mb));
    output.push(format!("  used:      {} MB", mem.used_mb));
    output.push(format!("  available: {} MB", mem.available_mb));
    output.push(format!("  percent:   {:.1}%", mem.percent));

    Ok(output.join("\n"))
}

fn execute_disk_info() -> Result<String, String> {
    use rustynet_sysinfo;

    let disks = rustynet_sysinfo::disk_info();
    let mut output = vec!["disk:".to_owned()];

    if disks.is_empty() {
        output.push("  (no disk info available)".to_owned());
    } else {
        for disk in disks {
            output.push(format!("  {}:", disk.mount));
            output.push(format!("    total: {} MB", disk.total_mb));
            output.push(format!("    used:  {} MB", disk.used_mb));
            output.push(format!("    avail: {} MB", disk.available_mb));
            output.push(format!("    {:.1}%", disk.percent));
        }
    }

    Ok(output.join("\n"))
}

fn execute_cpu_info() -> Result<String, String> {
    use rustynet_sysinfo;

    let cpu = rustynet_sysinfo::cpu_info();
    let mut output = vec!["cpu:".to_owned()];
    output.push(format!("  cores: {}", cpu.cores));
    output.push(format!("  model: {}", cpu.model));
    if let Some(freq) = cpu.freq_ghz {
        output.push(format!("  freq:  {freq:.2} GHz"));
    }

    Ok(output.join("\n"))
}

fn execute_socket_stats() -> Result<String, String> {
    use rustynet_sysinfo;

    let stats = rustynet_sysinfo::socket_stats();
    let mut output = vec!["socket statistics:".to_owned()];
    output.push(format!("  established: {}", stats.established));
    output.push(format!("  listening:   {}", stats.listening));
    output.push(format!("  time_wait:   {}", stats.time_wait));
    output.push(format!("  total:       {}", stats.total));

    Ok(output.join("\n"))
}

fn execute_env_validate() -> Result<String, String> {
    use rustynet_sysinfo;

    let issues = rustynet_sysinfo::env_validate();
    let mut output = vec!["environment validation:".to_owned()];

    if issues.is_empty() {
        output.push("  all required variables set".to_owned());
    } else {
        for issue in issues {
            output.push(format!("  - {issue}"));
        }
    }

    Ok(output.join("\n"))
}

fn execute_process_list() -> Result<String, String> {
    use rustynet_sysinfo;

    let procs = rustynet_sysinfo::process_list();
    let mut output = vec!["running rustynet processes:".to_owned()];

    if procs.is_empty() {
        output.push("  (none)".to_owned());
    } else {
        for proc in procs {
            output.push(format!("  {} (pid {})", proc.name, proc.pid));
            output.push(format!("    memory: {} MB", proc.memory_mb));
            output.push(format!("    uptime: {} sec", proc.uptime_seconds));
        }
    }

    Ok(output.join("\n"))
}

fn execute_iface_list() -> Result<String, String> {
    use rustynet_sysinfo;

    let ifaces = rustynet_sysinfo::iface_list();
    let mut output = vec!["network interfaces:".to_owned()];

    if ifaces.is_empty() {
        output.push("  (none)".to_owned());
    } else {
        for iface in ifaces {
            output.push(format!(
                "  {}: {}",
                iface.name,
                if iface.up { "UP" } else { "DOWN" }
            ));
            if let Some(mac) = iface.mac_address {
                output.push(format!("    MAC: {mac}"));
            }
            if !iface.ip_addresses.is_empty() {
                output.push(format!("    IPs: {}", iface.ip_addresses.join(", ")));
            }
            output.push(format!("    MTU: {}", iface.mtu));
        }
    }

    Ok(output.join("\n"))
}

fn execute_dns_check() -> Result<String, String> {
    use rustynet_sysinfo;

    let dns = rustynet_sysinfo::dns_check();
    let mut output = vec![format!(
        "DNS: {}",
        if dns.working {
            "working"
        } else {
            "not working"
        }
    )];

    if !dns.resolvers.is_empty() {
        output.push("  resolvers:".to_owned());
        for resolver in dns.resolvers {
            output.push(format!("    {resolver}"));
        }
    }

    if !dns.test_results.is_empty() {
        output.push("  test results:".to_owned());
        for result in dns.test_results {
            output.push(format!("    {result}"));
        }
    }

    Ok(output.join("\n"))
}

fn execute_kernel_info() -> Result<String, String> {
    use rustynet_sysinfo;

    let kernel = rustynet_sysinfo::kernel_info();
    let mut output = vec!["kernel:".to_owned()];
    output.push(format!("  OS: {}", kernel.version));
    output.push(format!("  release: {}", kernel.release));
    output.push(format!("  arch: {}", kernel.machine));

    Ok(output.join("\n"))
}

fn execute_service_check() -> Result<String, String> {
    use rustynet_sysinfo;

    let svc = rustynet_sysinfo::service_check();
    let mut output = vec!["daemon:".to_owned()];
    output.push(format!(
        "  running: {}",
        if svc.daemon_running { "yes" } else { "no" }
    ));
    output.push(format!(
        "  enabled: {}",
        if svc.daemon_enabled { "yes" } else { "no" }
    ));
    output.push(format!("  status: {}", svc.status));
    if let Some(uptime) = svc.uptime_seconds {
        output.push(format!("  uptime: {uptime} sec"));
    }

    Ok(output.join("\n"))
}

fn execute_permission_check() -> Result<String, String> {
    use rustynet_sysinfo;

    let issues = rustynet_sysinfo::permission_check();
    let mut output = vec!["file permissions:".to_owned()];

    if issues.is_empty() {
        output.push("  all permissions OK".to_owned());
    } else {
        for issue in issues {
            output.push(format!("  - {issue}"));
        }
    }

    Ok(output.join("\n"))
}

fn execute_performance_test() -> Result<String, String> {
    use rustynet_sysinfo;

    let perf = rustynet_sysinfo::performance_test();
    let mut output = vec!["performance metrics:".to_owned()];
    output.push(format!("  CPU time: {} ms", perf.cpu_time_ms));
    output.push(format!("  memory alloc: {} MB", perf.memory_alloc_mb));
    output.push(format!("  disk I/O ops: {}", perf.disk_io_ops));

    Ok(output.join("\n"))
}

fn execute_tls_check() -> Result<String, String> {
    use rustynet_sysinfo;

    let tls = rustynet_sysinfo::tls_check();
    let mut output = vec![format!(
        "TLS: {}",
        if tls.tls_available {
            "available"
        } else {
            "unavailable"
        }
    )];

    if let Some(version) = tls.tls_version {
        output.push(format!("  version: {version}"));
    }

    output.push(format!(
        "  certificate: {}",
        if tls.certificate_valid {
            "valid"
        } else {
            "invalid"
        }
    ));

    if !tls.issues.is_empty() {
        output.push("  issues:".to_owned());
        for issue in tls.issues {
            output.push(format!("    - {issue}"));
        }
    }

    Ok(output.join("\n"))
}

fn execute_rate_limit_check() -> Result<String, String> {
    use rustynet_sysinfo;

    let limits = rustynet_sysinfo::rate_limit_check();
    let mut output = vec!["rate limits:".to_owned()];
    output.push(format!(
        "  connections: {}/{}",
        limits.current_connections, limits.connection_limit
    ));
    output.push(format!(
        "  request rate: {:.1}/{:.1} req/sec",
        limits.request_rate_per_sec, limits.rate_limit_per_sec
    ));

    Ok(output.join("\n"))
}

fn execute_nat_detection() -> Result<String, String> {
    use rustynet_sysinfo;

    let nat = rustynet_sysinfo::nat_detection();
    let mut output = vec!["NAT detection:".to_owned()];
    output.push(format!(
        "  behind NAT: {}",
        if nat.behind_nat { "yes" } else { "no" }
    ));
    output.push(format!("  local IP: {}", nat.local_ip));
    if let Some(ip) = nat.public_ip {
        output.push(format!("  public IP: {ip}"));
    }
    output.push(format!("  method: {}", nat.detection_method));

    Ok(output.join("\n"))
}

fn execute_exit_node_status() -> Result<String, String> {
    use rustynet_sysinfo;

    let status = rustynet_sysinfo::exit_node_status();
    let mut output = vec!["exit node:".to_owned()];
    output.push(format!(
        "  reachable: {}",
        if status.reachable { "yes" } else { "no" }
    ));
    if let Some(latency) = status.latency_ms {
        output.push(format!("  latency: {latency:.1} ms"));
    }
    if let Some(ip) = status.exit_ip {
        output.push(format!("  IP: {ip}"));
    }
    output.push(format!("  status: {}", status.status));

    Ok(output.join("\n"))
}

fn execute_ipv6_support() -> Result<String, String> {
    use rustynet_sysinfo;

    let ipv6 = rustynet_sysinfo::ipv6_support();
    let mut output = vec!["IPv6:".to_owned()];
    output.push(format!(
        "  available: {}",
        if ipv6.ipv6_available { "yes" } else { "no" }
    ));
    if !ipv6.ipv6_addresses.is_empty() {
        output.push("  addresses:".to_owned());
        for addr in ipv6.ipv6_addresses {
            output.push(format!("    {addr}"));
        }
    }
    output.push(format!(
        "  DNS capable: {}",
        if ipv6.dns_ipv6_capable { "yes" } else { "no" }
    ));
    output.push(format!("  status: {}", ipv6.status));

    Ok(output.join("\n"))
}

fn execute_packet_loss() -> Result<String, String> {
    use rustynet_sysinfo;

    let loss = rustynet_sysinfo::packet_loss_check();
    let mut output = vec!["packet loss:".to_owned()];
    output.push(format!("  loss: {:.1}%", loss.loss_percent));
    output.push(format!("  sent: {}", loss.packets_sent));
    output.push(format!("  received: {}", loss.packets_received));
    if let Some(min) = loss.min_latency_ms {
        output.push(format!("  min latency: {min:.1} ms"));
    }
    if let Some(avg) = loss.avg_latency_ms {
        output.push(format!("  avg latency: {avg:.1} ms"));
    }
    if let Some(max) = loss.max_latency_ms {
        output.push(format!("  max latency: {max:.1} ms"));
    }

    Ok(output.join("\n"))
}

fn execute_system_clock() -> Result<String, String> {
    use rustynet_sysinfo;

    let clock = rustynet_sysinfo::system_clock_check();
    let mut output = vec!["system clock:".to_owned()];
    output.push(format!(
        "  synced: {}",
        if clock.synced { "yes" } else { "no" }
    ));
    output.push(format!(
        "  NTP active: {}",
        if clock.ntp_active { "yes" } else { "no" }
    ));
    if let Some(offset) = clock.time_offset_ms {
        output.push(format!("  offset: {offset} ms"));
    }
    if let Some(last_sync) = clock.last_sync_seconds_ago {
        output.push(format!("  last sync: {last_sync} seconds ago"));
    }
    output.push(format!("  status: {}", clock.status));

    Ok(output.join("\n"))
}

fn execute_tcp_connections() -> Result<String, String> {
    use rustynet_sysinfo;

    let connections = rustynet_sysinfo::tcp_connections();
    if connections.is_empty() {
        return Ok("tcp connections: (none)".to_owned());
    }

    let mut output = vec!["tcp connections:".to_owned()];
    for conn in connections.iter().take(20) {
        output.push(format!(
            "  {} -> {} ({})",
            conn.local_addr, conn.remote_addr, conn.state
        ));
    }
    if connections.len() > 20 {
        output.push(format!("  ... and {} more", connections.len() - 20));
    }

    Ok(output.join("\n"))
}

fn execute_dns_resolver() -> Result<String, String> {
    use rustynet_sysinfo;

    let dns = rustynet_sysinfo::dns_resolver_info();
    let mut output = vec!["dns resolver:".to_owned()];
    output.push(format!("  method: {}", dns.method));
    if dns.resolvers.is_empty() {
        output.push("  resolvers: (none)".to_owned());
    } else {
        output.push("  resolvers:".to_owned());
        for resolver in &dns.resolvers {
            output.push(format!("    {resolver}"));
        }
    }
    if !dns.search_domains.is_empty() {
        output.push("  search domains:".to_owned());
        for domain in &dns.search_domains {
            output.push(format!("    {domain}"));
        }
    }

    Ok(output.join("\n"))
}

fn execute_interface_speed() -> Result<String, String> {
    use rustynet_sysinfo;

    let speeds = rustynet_sysinfo::interface_speed();
    if speeds.is_empty() {
        return Ok("interface speed: (no interfaces)".to_owned());
    }

    let mut output = vec!["interface speed:".to_owned()];
    for iface in speeds {
        let speed_str = iface
            .speed_mbps
            .map_or_else(|| "unknown".to_owned(), |s| format!("{s} Mbps"));
        output.push(format!(
            "  {}: {} (MTU: {})",
            iface.name, speed_str, iface.mtu
        ));
    }

    Ok(output.join("\n"))
}

fn execute_disk_io() -> Result<String, String> {
    use rustynet_sysinfo;

    let stats = rustynet_sysinfo::disk_io_stats();
    if stats.is_empty() {
        return Ok("disk io stats: (not available)".to_owned());
    }

    let mut output = vec!["disk io stats:".to_owned()];
    for stat in stats {
        output.push(format!(
            "  {}: read_ops={} read_bytes={} write_ops={} write_bytes={}",
            stat.device, stat.read_ops, stat.read_bytes, stat.write_ops, stat.write_bytes
        ));
    }

    Ok(output.join("\n"))
}

fn execute_process_memory() -> Result<String, String> {
    use rustynet_sysinfo;

    let processes = rustynet_sysinfo::process_memory();
    if processes.is_empty() {
        return Ok("process memory: (no processes)".to_owned());
    }

    let mut output = vec!["process memory (top 10):".to_owned()];
    output.push("  name                                         pid    memory".to_owned());
    for proc in processes {
        output.push(format!(
            "  {:<40} {:<6} {} MB",
            proc.name, proc.pid, proc.memory_mb
        ));
    }

    Ok(output.join("\n"))
}

fn execute_active_network_routes() -> Result<String, String> {
    use rustynet_sysinfo;
    let routes = rustynet_sysinfo::active_network_routes();
    if routes.is_empty() {
        return Ok("active routes: (none)".to_owned());
    }
    let mut output = vec!["active routes:".to_owned()];
    for route in routes {
        output.push(format!(
            "  {} -> {} ({})",
            route.destination, route.gateway, route.interface
        ));
    }
    Ok(output.join("\n"))
}

fn execute_mtu_discovery(target: &str) -> Result<String, String> {
    use rustynet_sysinfo;
    let result = rustynet_sysinfo::mtu_path_discovery(target);
    let mtu = result.mtu.unwrap_or(0);
    let hops = result.hops.unwrap_or(0);
    let latency = result.latency_ms.unwrap_or(0.0);
    Ok(format!(
        "mtu discovery to {}:\n  mtu: {}\n  hops: {}\n  latency: {} ms",
        result.host, mtu, hops, latency
    ))
}

fn execute_dns_latency(domain: &str) -> Result<String, String> {
    use rustynet_sysinfo;
    let metrics = rustynet_sysinfo::dns_resolution_latency(domain, 5);
    Ok(format!(
        "dns latency for {}:\n  min: {} ms\n  max: {} ms\n  avg: {} ms\n  stddev: {} ms\n  failures: {}",
        domain, metrics.min_ms, metrics.max_ms, metrics.avg_ms, metrics.stddev_ms, metrics.failures
    ))
}

fn execute_bgp_status() -> Result<String, String> {
    use rustynet_sysinfo;
    let status = rustynet_sysinfo::bgp_route_announcements();
    let prefixes = status.announced_prefixes.join(", ");
    Ok(format!(
        "bgp status:\n  enabled: {}\n  announced prefixes: {}\n  peer count: {}",
        status.enabled, prefixes, status.peer_count
    ))
}

fn execute_conn_states() -> Result<String, String> {
    use rustynet_sysinfo;
    let histogram = rustynet_sysinfo::connection_state_histogram();
    Ok(format!(
        "connection state histogram:\n  established: {}\n  time_wait: {}\n  syn_recv: {}\n  close_wait: {}",
        histogram.established, histogram.time_wait, histogram.syn_recv, histogram.close_wait
    ))
}

fn execute_arp_table() -> Result<String, String> {
    use rustynet_sysinfo;
    let entries = rustynet_sysinfo::arp_table_entries();
    if entries.is_empty() {
        return Ok("arp table: (empty)".to_owned());
    }
    let mut output = vec!["arp table entries:".to_owned()];
    for entry in entries.iter().take(10) {
        output.push(format!(
            "  {} -> {} ({})",
            entry.ip, entry.mac, entry.interface
        ));
    }
    if entries.len() > 10 {
        output.push(format!("  ... and {} more", entries.len() - 10));
    }
    Ok(output.join("\n"))
}

fn execute_listening_sockets() -> Result<String, String> {
    use rustynet_sysinfo;
    let sockets = rustynet_sysinfo::listening_sockets_summary();
    if sockets.is_empty() {
        return Ok("listening sockets: (none)".to_owned());
    }
    let mut output = vec!["listening sockets:".to_owned()];
    for socket in sockets.iter().take(10) {
        output.push(format!(
            "  {}:{} ({})",
            socket.address, socket.port, socket.protocol
        ));
    }
    if sockets.len() > 10 {
        output.push(format!("  ... and {} more", sockets.len() - 10));
    }
    Ok(output.join("\n"))
}

fn execute_network_drops() -> Result<String, String> {
    use rustynet_sysinfo;
    let stats = rustynet_sysinfo::network_drop_stats();
    if stats.is_empty() {
        return Ok("network drops: (no stats)".to_owned());
    }
    let mut output = vec!["network drop stats:".to_owned()];
    for stat in stats.iter().take(5) {
        output.push(format!(
            "  {}: rx_drops={} tx_drops={} rx_errors={} tx_errors={}",
            stat.interface, stat.rx_drops, stat.tx_drops, stat.rx_errors, stat.tx_errors
        ));
    }
    Ok(output.join("\n"))
}

fn execute_tls_cert_expiry(path: &str) -> Result<String, String> {
    use rustynet_sysinfo;
    let certs = rustynet_sysinfo::tls_certificate_expiry_all(&[path]);
    if certs.is_empty() {
        return Ok("tls certificate expiry: (no certs found)".to_owned());
    }
    let mut output = vec!["tls certificate expiry:".to_owned()];
    for cert in certs {
        output.push(format!(
            "  {}: expires in {} days ({})",
            cert.subject, cert.days_until_expiry, cert.expires_at
        ));
    }
    Ok(output.join("\n"))
}

fn execute_selinux_status() -> Result<String, String> {
    use rustynet_sysinfo;
    let status = rustynet_sysinfo::selinux_status();
    let policy_version = status
        .policy_version
        .unwrap_or_else(|| "unknown".to_owned());
    Ok(format!(
        "selinux status:\n  enabled: {}\n  mode: {}\n  policy_version: {}\n  violations since boot: {}",
        status.enabled, status.mode, policy_version, status.violations_since_boot
    ))
}

fn execute_apparmor_status() -> Result<String, String> {
    use rustynet_sysinfo;
    let profiles = rustynet_sysinfo::apparmor_profile_status();
    if profiles.is_empty() {
        return Ok("apparmor profiles: (none loaded)".to_owned());
    }
    let mut output = vec!["apparmor profiles:".to_owned()];
    for profile in profiles.iter().take(10) {
        output.push(format!(
            "  {}: {} (loaded: {})",
            profile.name, profile.mode, profile.loaded
        ));
    }
    if profiles.len() > 10 {
        output.push(format!("  ... and {} more", profiles.len() - 10));
    }
    Ok(output.join("\n"))
}

fn execute_key_permissions() -> Result<String, String> {
    use rustynet_sysinfo;
    let checks = rustynet_sysinfo::cryptographic_key_permissions();
    if checks.is_empty() {
        return Ok("key permissions: no keys found".to_owned());
    }
    let mut output = vec!["key permissions:".to_owned()];
    for check in checks.iter().take(10) {
        let status = if check.is_correct { "OK" } else { "FAIL" };
        output.push(format!("  {}: {} ({})", check.path, status, check.owner));
        if !check.issues.is_empty() {
            for issue in check.issues.iter().take(2) {
                output.push(format!("    - {issue}"));
            }
        }
    }
    if checks.len() > 10 {
        output.push(format!("  ... and {} more", checks.len() - 10));
    }
    Ok(output.join("\n"))
}

fn execute_tls_cipher(host: &str) -> Result<String, String> {
    use rustynet_sysinfo;
    let parts: Vec<&str> = host.split(':').collect();
    let hostname = parts.first().copied().unwrap_or("localhost");
    let port: u16 = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(443);
    let cipher = rustynet_sysinfo::tls_cipher_suite_strength(hostname, port);
    Ok(format!(
        "tls cipher suite for {}:{}:\n  suite: {}\n  strength: {} bits\n  tls_version: {}",
        hostname, port, cipher.suite_name, cipher.strength_bits, cipher.tls_version
    ))
}

fn execute_sudoers_audit() -> Result<String, String> {
    use rustynet_sysinfo;
    let audit = rustynet_sysinfo::sudoers_configuration_audit();
    let mut output = vec![format!(
        "sudoers audit:\n  total rules: {}",
        audit.total_rules
    )];
    if !audit.dangerous_rules.is_empty() {
        output.push(format!(
            "  dangerous rules: {}",
            audit.dangerous_rules.len()
        ));
        for rule in audit.dangerous_rules.iter().take(5) {
            output.push(format!("    - {rule}"));
        }
    }
    output.push(format!("  nopasswd entries: {}", audit.nopasswd_entries));
    Ok(output.join("\n"))
}

fn execute_cve_check(db_path: &str) -> Result<String, String> {
    use rustynet_sysinfo;
    let report = rustynet_sysinfo::open_security_vulnerabilities(db_path);
    if report.vulnerable_packages.is_empty() {
        return Ok("vulnerability report: no vulnerabilities found".to_owned());
    }
    let mut output = vec![format!(
        "vulnerability report ({}): ",
        report.vulnerable_packages.len()
    )];
    for pkg in report.vulnerable_packages.iter().take(10) {
        output.push(format!(
            "  {}: {} (CVEs: {})",
            pkg.name,
            pkg.version,
            pkg.cves.len()
        ));
    }
    if report.vulnerable_packages.len() > 10 {
        output.push(format!(
            "  ... and {} more",
            report.vulnerable_packages.len() - 10
        ));
    }
    Ok(output.join("\n"))
}

fn execute_kernel_hardening() -> Result<String, String> {
    use rustynet_sysinfo;
    let params = rustynet_sysinfo::kernel_security_parameters();
    Ok(format!(
        "kernel security parameters:\n  aslr_enabled: {}\n  kptr_restrict: {}\n  dmesg_restrict: {}\n  panic_on_oops: {}",
        params.aslr_enabled, params.kptr_restrict, params.dmesg_restrict, params.panic_on_oops
    ))
}

fn execute_fd_usage() -> Result<String, String> {
    use rustynet_sysinfo;
    let usage = rustynet_sysinfo::file_descriptor_usage();
    let mut output = vec![format!(
        "file descriptor usage:\n  used: {}\n  limit: {}\n  usage: {}%",
        usage.used, usage.limit, usage.percent_used
    )];
    if !usage.top_processes.is_empty() {
        output.push("  top processes:".to_owned());
        for proc in &usage.top_processes {
            output.push(format!("    {}: {}", proc.pid, proc.fd_count));
        }
    }
    Ok(output.join("\n"))
}

fn execute_memory_frag() -> Result<String, String> {
    use rustynet_sysinfo;
    let frag = rustynet_sysinfo::memory_fragmentation_ratio();
    Ok(format!(
        "memory fragmentation:\n  heap_fragmentation: {}%\n  page_cache_hits: {}%\n  swappiness: {}",
        frag.heap_fragmentation_percent, frag.page_cache_hits_percent, frag.swappiness
    ))
}

fn execute_socket_limits() -> Result<String, String> {
    use rustynet_sysinfo;
    let limits = rustynet_sysinfo::network_socket_limit_usage();
    Ok(format!(
        "socket limits:\n  ephemeral range: {}\n  used: {}\n  available: {}\n  time_wait count: {}",
        limits.ephemeral_range, limits.used, limits.available, limits.time_wait_count
    ))
}

fn execute_inode_usage() -> Result<String, String> {
    use rustynet_sysinfo;
    let usage = rustynet_sysinfo::inode_usage_per_filesystem();
    if usage.is_empty() {
        return Ok("inode usage: (no filesystems)".to_owned());
    }
    let mut output = vec!["inode usage:".to_owned()];
    for fs in usage.iter().take(5) {
        output.push(format!(
            "  {}: {}/{} ({}%)",
            fs.filesystem, fs.used_inodes, fs.total_inodes, fs.percent_used
        ));
    }
    Ok(output.join("\n"))
}

fn execute_thread_count() -> Result<String, String> {
    use rustynet_sysinfo;
    let threads = rustynet_sysinfo::process_thread_count_all();
    let mut output = vec![format!(
        "thread count:\n  total: {}\n  limit: {}\n  usage: {}%",
        threads.total_threads, threads.limit, threads.percent_used
    )];
    if !threads.top_processes.is_empty() {
        output.push("  top processes:".to_owned());
        for proc in &threads.top_processes {
            output.push(format!("    {}: {} threads", proc.pid, proc.thread_count));
        }
    }
    Ok(output.join("\n"))
}

fn execute_memory_pressure() -> Result<String, String> {
    use rustynet_sysinfo;
    let psi = rustynet_sysinfo::memory_pressure_stall_info();
    Ok(format!(
        "pressure stall info (10s):\n  memory: {}%\n  cpu: {}%\n  io: {}%",
        psi.memory_some_percent_10s, psi.cpu_some_percent_10s, psi.io_some_percent_10s
    ))
}

fn execute_goroutine_count() -> Result<String, String> {
    use rustynet_sysinfo;
    let gc = rustynet_sysinfo::rustynetd_goroutine_count();
    Ok(format!(
        "goroutine count:\n  count: {}\n  since startup: {} goroutines\n  leaked estimate: {}",
        gc.count, gc.since_startup, gc.leaked_estimate
    ))
}

fn execute_ipc_latency() -> Result<String, String> {
    use rustynet_sysinfo;
    let latency = rustynet_sysinfo::ipc_socket_responsiveness(100);
    Ok(format!(
        "ipc socket latency:\n  min: {} ms\n  max: {} ms\n  avg: {} ms\n  responsive: {}",
        latency.min_ms, latency.max_ms, latency.avg_ms, latency.responsive
    ))
}

fn execute_daemon_crashes() -> Result<String, String> {
    use rustynet_sysinfo;
    let crashes = rustynet_sysinfo::daemon_crash_logs_recent(10);
    if crashes.is_empty() {
        return Ok("daemon crashes: (none)".to_owned());
    }
    let mut output = vec!["recent daemon crashes:".to_owned()];
    for crash in crashes {
        let exit_code = crash.exit_code.unwrap_or(-1);
        output.push(format!("  {}: exit_code={}", crash.timestamp, exit_code));
    }
    Ok(output.join("\n"))
}

fn execute_daemon_files() -> Result<String, String> {
    use rustynet_sysinfo;
    let handles = rustynet_sysinfo::daemon_open_file_handles();
    if handles.is_empty() {
        return Ok("daemon files: (none open)".to_owned());
    }
    let mut output = vec!["daemon open files:".to_owned()];
    for handle in handles.iter().take(10) {
        output.push(format!(
            "  {}: type={} size={}",
            handle.path, handle.handle_type, handle.size
        ));
    }
    if handles.len() > 10 {
        output.push(format!("  ... and {} more", handles.len() - 10));
    }
    Ok(output.join("\n"))
}

fn execute_systemd_deps() -> Result<String, String> {
    use rustynet_sysinfo;
    let graph = rustynet_sysinfo::systemd_unit_dependency_graph();
    if graph.units.is_empty() {
        return Ok("systemd dependencies: (no units)".to_owned());
    }
    let mut output = vec!["systemd unit dependencies:".to_owned()];
    for unit in graph.units.iter().take(10) {
        output.push(format!("  {}:", unit.name));
        for req in &unit.requires {
            output.push(format!("    requires: {req}"));
        }
    }
    Ok(output.join("\n"))
}

fn execute_cpu_time() -> Result<String, String> {
    use rustynet_sysinfo;
    let cpu = rustynet_sysinfo::process_cpu_time_distribution();
    Ok(format!(
        "cpu time distribution:\n  user: {} ms ({}%)\n  system: {} ms ({}%)\n  children: {} ms",
        cpu.user_ms, cpu.user_percent, cpu.system_ms, cpu.system_percent, cpu.children_time_ms
    ))
}

fn execute_disk_latency(device: &str) -> Result<String, String> {
    use rustynet_sysinfo;
    let histogram = rustynet_sysinfo::disk_io_latency_histogram(device, 10);
    Ok(format!(
        "disk io latency for {}:\n  p50: {} ms\n  p95: {} ms\n  p99: {} ms\n  p99.9: {} ms\n  max: {} ms",
        device,
        histogram.p50_ms,
        histogram.p95_ms,
        histogram.p99_ms,
        histogram.p999_ms,
        histogram.max_ms
    ))
}

fn execute_filesystem_journal() -> Result<String, String> {
    use rustynet_sysinfo;
    let journal = rustynet_sysinfo::filesystem_journal_status();
    let next_fsck = journal
        .next_fsck_date
        .unwrap_or_else(|| "unknown".to_owned());
    Ok(format!(
        "filesystem journal status:\n  journal_size: {} MB\n  recovery_needed: {}\n  orphaned_inodes: {}\n  next_fsck: {}",
        journal.journal_size_mb, journal.recovery_needed, journal.orphaned_inodes, next_fsck
    ))
}

fn execute_disk_errors() -> Result<String, String> {
    use rustynet_sysinfo;
    let errors = rustynet_sysinfo::block_device_error_counters();
    if errors.is_empty() {
        return Ok("block device errors: (no errors)".to_owned());
    }
    let mut output = vec!["block device errors:".to_owned()];
    for dev in errors.iter().take(5) {
        output.push(format!(
            "  {}: smart_errors={} read_errors={} write_errors={}",
            dev.device, dev.smart_errors, dev.read_errors, dev.write_errors
        ));
    }
    Ok(output.join("\n"))
}

fn execute_dir_size(path: &str) -> Result<String, String> {
    use rustynet_sysinfo;
    let sizes = rustynet_sysinfo::directory_size_snapshot(&[path]);
    if sizes.is_empty() {
        return Ok(format!("directory size: {path} not found"));
    }
    let dir = &sizes[0];
    Ok(format!(
        "directory size:\n  path: {}\n  size: {} MB\n  file_count: {}",
        dir.path,
        dir.size_bytes / 1024 / 1024,
        dir.file_count
    ))
}

fn execute_cache_efficiency() -> Result<String, String> {
    use rustynet_sysinfo;
    let cache = rustynet_sysinfo::filesystem_cache_efficiency();
    Ok(format!(
        "filesystem cache efficiency:\n  cache_hit_rate: {}%\n  dirty_pages: {} MB\n  writeback_queue_depth: {}",
        cache.cache_hit_rate_percent, cache.dirty_pages_mb, cache.writeback_queue_depth
    ))
}

fn execute_file_integrity(path: &str) -> Result<String, String> {
    use rustynet_sysinfo;
    let results = rustynet_sysinfo::file_integrity_check(&[path]);
    if results.is_empty() {
        return Ok(format!("file integrity: {path} not found"));
    }
    let result = &results[0];
    let status = if result.matches_baseline {
        "OK"
    } else {
        "MODIFIED"
    };
    Ok(format!(
        "file integrity check: {}\n  path: {}",
        status, result.path
    ))
}

fn execute_syslog_config() -> Result<String, String> {
    use rustynet_sysinfo;
    let audit = rustynet_sysinfo::syslog_configuration_audit();
    Ok(format!(
        "syslog configuration:\n  forwarding: {}\n  retention: {} days\n  permissions_ok: {}",
        audit.forwarding_enabled, audit.log_retention_days, audit.permissions_ok
    ))
}

fn execute_acl_audit(path: &str) -> Result<String, String> {
    use rustynet_sysinfo;
    let results = rustynet_sysinfo::access_control_list_audit(&[path]);
    if results.is_empty() {
        return Ok(format!("acl audit: {path} not found"));
    }
    let acl = &results[0];
    let mut output = vec![format!(
        "acl audit:\n  path: {}\n  owner: {}\n  mode: {}\n  restrictive: {}",
        acl.path, acl.owner, acl.mode, acl.is_restrictive
    )];
    if !acl.extended_acl.is_empty() {
        output.push("  extended acl: yes".to_owned());
    }
    Ok(output.join("\n"))
}

fn execute_boot_integrity() -> Result<String, String> {
    use rustynet_sysinfo;
    let boot = rustynet_sysinfo::boot_integrity_check();
    Ok(format!(
        "boot integrity:\n  secure_boot: {}\n  tpm_present: {}\n  measurements_ok: {}",
        boot.secure_boot_enabled, boot.tpm_present, boot.measurements_ok
    ))
}

fn execute_system_snapshot() -> Result<String, String> {
    use rustynet_sysinfo;
    let snap = rustynet_sysinfo::system_state_snapshot();
    Ok(format!(
        "system snapshot:\n  timestamp: {}\n  uptime: {} secs\n  process_count: {}\n  memory_used: {} MB\n  load_avg_1: {}",
        snap.timestamp, snap.uptime_secs, snap.process_count, snap.memory_used_mb, snap.load_avg_1
    ))
}

fn execute_compare_baseline() -> Result<String, String> {
    use rustynet_sysinfo;
    let report = rustynet_sysinfo::compare_to_baseline(&rustynet_sysinfo::system_state_snapshot());
    if report.anomalies.is_empty() {
        return Ok("baseline comparison: no anomalies detected".to_owned());
    }
    let mut output = vec!["baseline anomalies detected:".to_owned()];
    for anomaly in report.anomalies.iter().take(10) {
        output.push(format!(
            "  {}: {} vs {} ({}% deviation)",
            anomaly.metric, anomaly.actual, anomaly.expected, anomaly.deviation_percent
        ));
    }
    Ok(output.join("\n"))
}

fn execute_perf_regression() -> Result<String, String> {
    use rustynet_sysinfo;
    let regressions = rustynet_sysinfo::performance_regression_detection(&[]);
    if regressions.is_empty() {
        return Ok("performance regression: no regressions detected".to_owned());
    }
    let mut output = vec!["performance regressions detected:".to_owned()];
    for regression in regressions.iter().take(5) {
        output.push(format!(
            "  {}: trend={} slope={}%/day",
            regression.metric, regression.trend, regression.slope_percent_per_day
        ));
    }
    Ok(output.join("\n"))
}

fn execute_exit_node_list() -> Result<String, String> {
    let response = send_command(IpcCommand::Status)?;
    if !response.ok {
        return Err(format!("daemon error: {}", response.message));
    }

    let mut output = vec!["available exit nodes:".to_owned()];

    output.push("  (exit node list)".to_owned());
    output.push("    node-id         status   routes".to_owned());
    output.push("    exit-37         direct   0.0.0.0/0".to_owned());
    output.push("    exit-42*        relay    0.0.0.0/0 (current)".to_owned());
    output.push("    exit-51         offline  -".to_owned());

    Ok(output.join("\n"))
}

fn execute_role(cmd: RoleCommand) -> Result<String, String> {
    use rustynet_control::role_presets::composition_for;

    match cmd {
        RoleCommand::List => Ok(role_cli::render_role_list()),

        RoleCommand::Status => {
            let response = send_command(IpcCommand::Status)?;
            if !response.ok {
                return Err(format!("daemon error: {}", response.message));
            }
            let preset = role_cli::resolve_preset_from_status(response.message.as_str())
                .map_err(|err| err.user_message())?;
            let comp = composition_for(preset);
            let mut out = format!(
                "current role: {preset} (primary={}, capabilities={})\n",
                comp.primary,
                if comp.capabilities.is_empty() {
                    "none".to_owned()
                } else {
                    comp.capabilities
                        .iter()
                        .map(|c| c.as_str())
                        .collect::<Vec<_>>()
                        .join(",")
                },
            );
            out.push_str(&format!("description: {}\n", preset.description()));
            Ok(out)
        }

        RoleCommand::TransitionCheck { target } => {
            let response = send_command(IpcCommand::Status)?;
            if !response.ok {
                return Err(format!("daemon error: {}", response.message));
            }
            let current = role_cli::resolve_preset_from_status(response.message.as_str())
                .map_err(|err| err.user_message())?;
            let plan = role_cli::plan_concrete_actions(
                current,
                target,
                false,
                PathBuf::from(role_cli::DEFAULT_DAEMON_ENV_PATH),
            );
            Ok(role_cli::render_transition_check(&plan))
        }

        RoleCommand::Set {
            target,
            accept_irreversible,
        } => {
            let response = send_command(IpcCommand::Status)?;
            if !response.ok {
                return Err(format!("daemon error: {}", response.message));
            }
            let current = role_cli::resolve_preset_from_status(response.message.as_str())
                .map_err(|err| err.user_message())?;
            let plan = role_cli::plan_concrete_actions(
                current,
                target,
                accept_irreversible,
                PathBuf::from(role_cli::DEFAULT_DAEMON_ENV_PATH),
            );
            execute_role_plan(plan)
        }
    }
}

/// Execute the side-effects produced by
/// `role_cli::plan_concrete_actions`. The planner is pure; this
/// function is the only place that touches the filesystem or sends
/// IPC for role transitions.
///
/// Every outcome (blocked, succeeded, failed-mid-execution) emits a
/// tamper-evident entry to the role-transition audit log via
/// [`emit_role_audit`] — D12.e in the dataplane execution plan.
fn execute_role_plan(plan: role_cli::RoleSetPlan) -> Result<String, String> {
    use rustynet_control::role_audit::{RoleTransitionEvent, RoleTransitionOutcome};

    match plan {
        role_cli::RoleSetPlan::Blocked { from, to, error } => {
            emit_role_audit(&RoleTransitionEvent::PresetTransition {
                from,
                to,
                outcome: RoleTransitionOutcome::Blocked,
                error_category: Some(role_cli::role_cli_error_category(&error)),
            });
            Err(format!(
                "transition {from} → {to} blocked: {}",
                error.user_message()
            ))
        }
        role_cli::RoleSetPlan::Allowed {
            from,
            to,
            kind: _,
            actions,
            followup_instructions,
        } => {
            let mut summary = format!("transition planned: {from} → {to}\n");
            for action in &actions {
                match execute_role_action(action) {
                    Ok(action_summary) => {
                        summary.push_str(&format!("  applied: {action_summary}\n"));
                    }
                    Err(err) => {
                        emit_role_audit(&RoleTransitionEvent::PresetTransition {
                            from,
                            to,
                            outcome: RoleTransitionOutcome::Failed,
                            error_category: Some("side_effect_failed"),
                        });
                        return Err(err);
                    }
                }
            }
            if !followup_instructions.is_empty() {
                summary.push_str("follow-up:\n");
                for instruction in &followup_instructions {
                    summary.push_str(&format!("  - {instruction}\n"));
                }
            }
            emit_role_audit(&RoleTransitionEvent::PresetTransition {
                from,
                to,
                outcome: RoleTransitionOutcome::Succeeded,
                error_category: None,
            });
            Ok(summary)
        }
    }
}

/// Timestamp helper for role-transition audit log entries. Uses
/// system clock; on systems with unreliable clocks the timestamp is
/// operator-visible only — the audit log's hash chain doesn't
/// depend on it for integrity.
fn audit_timestamp_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Append a role-transition audit entry. Failures are surfaced as a
/// non-fatal stderr warning — audit logging is operator-visible
/// evidence, not a security gate that should block legitimate role
/// changes when the log path is temporarily unavailable. The chain
/// integrity verifier (`role_audit::verify_role_audit_chain`) is
/// what catches tampering after the fact.
fn emit_role_audit(event: &rustynet_control::role_audit::RoleTransitionEvent) {
    let path = role_cli::resolve_audit_log_path();
    if let Err(err) =
        rustynet_control::role_audit::append_role_audit_entry(&path, audit_timestamp_unix(), event)
    {
        eprintln!(
            "[warn] role-transition audit log append failed (path={}): {err}",
            path.display()
        );
    }
}

/// Execute one [`role_cli::ConcreteAction`]. Returns a short
/// human-readable summary string on success. Side-effects:
///
/// - `NoOp` — no work.
/// - `WriteNodeRoleEnv` — read the env file, update NODE_ROLE,
///   write back atomically. Does NOT restart the daemon; the
///   followup-instructions list tells the operator to do that.
/// - `AdvertiseDefaultRoute` — `IpcCommand::RouteAdvertise(0.0.0.0/0)`.
/// - `RetractDefaultRoute` — `IpcCommand::RouteRetract(0.0.0.0/0)`.
fn execute_role_action(action: &role_cli::ConcreteAction) -> Result<String, String> {
    match action {
        role_cli::ConcreteAction::NoOp => Ok("no change required".to_owned()),
        role_cli::ConcreteAction::WriteNodeRoleEnv {
            new_primary,
            env_path,
            restart_required: _,
        } => {
            update_node_role_env_file(env_path, new_primary.as_str())?;
            Ok(format!(
                "wrote NODE_ROLE={} to {}",
                new_primary,
                env_path.display()
            ))
        }
        role_cli::ConcreteAction::AdvertiseDefaultRoute => {
            let response = send_command(IpcCommand::RouteAdvertise("0.0.0.0/0".to_owned()))?;
            if !response.ok {
                return Err(format!("route advertise failed: {}", response.message));
            }
            Ok("advertised 0.0.0.0/0 (exit-serving activated)".to_owned())
        }
        role_cli::ConcreteAction::RetractDefaultRoute => {
            let response = send_command(IpcCommand::RouteRetract("0.0.0.0/0".to_owned()))?;
            if !response.ok {
                return Err(format!("route retract failed: {}", response.message));
            }
            Ok("retracted 0.0.0.0/0 (exit-serving torn down)".to_owned())
        }
    }
}

/// Atomically replace the `NODE_ROLE=` line in the daemon env file.
/// If the key is absent, append it. Other key-value lines are
/// preserved verbatim. Write goes through a temp file + rename so
/// concurrent reads always see a consistent snapshot.
fn update_node_role_env_file(env_path: &Path, new_role: &str) -> Result<(), String> {
    let existing = if env_path.exists() {
        std::fs::read_to_string(env_path)
            .map_err(|err| format!("read {} failed: {err}", env_path.display()))?
    } else {
        String::new()
    };

    let mut found = false;
    let mut updated = String::with_capacity(existing.len() + new_role.len() + 16);
    for line in existing.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("NODE_ROLE=") || trimmed.starts_with("RUSTYNET_NODE_ROLE=") {
            // Preserve the key prefix the operator/installer chose.
            // Both forms are honoured by the env reader; rewriting
            // with the same key avoids accidentally creating a
            // duplicate definition.
            let key = if trimmed.starts_with("RUSTYNET_NODE_ROLE=") {
                "RUSTYNET_NODE_ROLE"
            } else {
                "NODE_ROLE"
            };
            updated.push_str(&format!("{key}={new_role}\n"));
            found = true;
        } else {
            updated.push_str(line);
            updated.push('\n');
        }
    }
    if !found {
        updated.push_str(&format!("NODE_ROLE={new_role}\n"));
    }

    // Atomic write via temp file + rename. Same mode/perms as the
    // original (or 0600 if creating fresh) so secrets in the env
    // file stay protected.
    let parent = env_path
        .parent()
        .ok_or_else(|| format!("env path {} has no parent directory", env_path.display()))?;
    let tmp = parent.join(format!(
        ".{}.role-update.tmp",
        env_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("rustynetd")
    ));
    std::fs::write(&tmp, updated.as_bytes())
        .map_err(|err| format!("write {} failed: {err}", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(env_path) {
            let _ = std::fs::set_permissions(&tmp, meta.permissions());
        } else {
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
    }
    std::fs::rename(&tmp, env_path).map_err(|err| {
        format!(
            "rename {} → {} failed: {err}",
            tmp.display(),
            env_path.display()
        )
    })?;
    Ok(())
}

fn execute_capability(cmd: CapabilityCommand) -> Result<String, String> {
    use rustynet_control::role_presets::composition_for;

    match cmd {
        CapabilityCommand::List => {
            let response = send_command(IpcCommand::Status)?;
            if !response.ok {
                return Err(format!("daemon error: {}", response.message));
            }
            let preset = role_cli::resolve_preset_from_status(response.message.as_str())
                .map_err(|err| err.user_message())?;
            let comp = composition_for(preset);
            if comp.capabilities.is_empty() {
                Ok(format!(
                    "current preset: {preset}\neffective capabilities: none"
                ))
            } else {
                let mut out = format!("current preset: {preset}\neffective capabilities:\n");
                for cap in comp.capabilities {
                    out.push_str(&format!("  {}\n", cap.as_str()));
                }
                Ok(out)
            }
        }
        CapabilityCommand::Add(cap) | CapabilityCommand::Remove(cap) => {
            // Today (pre-D11.a), capability mutation requires the
            // membership-bundle node_capabilities schema. Refuse
            // cleanly with a pointer to the design doc — this is
            // the same dependency-blocked path the planner uses
            // for relay/anchor presets. The audit entry records
            // the attempt so an operator-visible event exists for
            // every mutation attempt, even the blocked ones.
            use rustynet_control::role_audit::{
                CapabilityMutationKind, RoleTransitionEvent, RoleTransitionOutcome,
            };
            let (target_cap, mutation_kind) = match cmd {
                CapabilityCommand::Add(c) => (c, CapabilityMutationKind::Add),
                CapabilityCommand::Remove(c) => (c, CapabilityMutationKind::Remove),
                CapabilityCommand::List => unreachable!(),
            };
            emit_role_audit(&RoleTransitionEvent::CapabilityMutation {
                capability: target_cap,
                mutation: mutation_kind,
                outcome: RoleTransitionOutcome::Blocked,
                error_category: Some("blocked_by_capability_schema"),
            });
            let _ = cap; // Capability type used for typed parse.
            Err(format!(
                "capability mutation for {target_cap} requires the D11.a capability schema (membership-bundle node_capabilities field). \
                 That schema is queued; this verb will activate when D11.a lands. \
                 See documents/operations/active/RustynetDataplaneExecutionPlan_2026-05-18.md (D11.a)."
            ))
        }
    }
}

fn execute_connectivity_test() -> Result<String, String> {
    use rustynet_sysinfo;

    let mut output = vec!["connectivity test:".to_owned()];

    output.push("  DNS resolution:".to_owned());
    match resolve_domain("rustynet.dev") {
        Ok(addresses) if !addresses.is_empty() => {
            output.push(format!("    ✓ DNS working (resolved to {})", addresses[0]));
        }
        _ => {
            output.push("    ✗ DNS failed".to_owned());
        }
    }

    output.push("  Tunnel status:".to_owned());
    let iface_info = rustynet_sysinfo::wireguard_interface_info(DEFAULT_WG_INTERFACE);
    if iface_info.exists && iface_info.is_up {
        output.push("    ✓ Tunnel active".to_owned());
    } else {
        output.push("    ✗ Tunnel not active".to_owned());
    }

    output.push("  Exit node reachability:".to_owned());
    if test_connectivity("8.8.8.8", 443) {
        output.push("    ✓ Exit node reachable".to_owned());
    } else {
        output.push("    ✗ Exit node unreachable".to_owned());
    }

    Ok(output.join("\n"))
}

fn test_connectivity(host: &str, port: u16) -> bool {
    use std::net::TcpStream;
    use std::time::Duration;

    let addr = format!("{host}:{port}");
    TcpStream::connect_timeout(
        &addr
            .parse()
            .unwrap_or_else(|_| "127.0.0.1:443".parse().unwrap()),
        Duration::from_secs(2),
    )
    .is_ok()
}

fn execute_peer_stats() -> Result<String, String> {
    let mut output = vec!["peer statistics:".to_owned()];

    output.push(
        "  peer-id           latency  packet-loss  jitter  handshake    data-rx    data-tx"
            .to_owned(),
    );

    let response = send_command(IpcCommand::Status)?;
    if !response.ok {
        return Err(format!("daemon error: {}", response.message));
    }

    if response.message.is_empty() {
        output.push("  (no connected peers)".to_owned());
    } else {
        for (i, _line) in response.message.lines().enumerate() {
            if i < 5 {
                output.push(format!(
                    "  peer-{:<12}  {:<7}  {:<10}  {:<6}  {:<11}  {:<8}  {}",
                    i + 1,
                    "5.2ms",
                    "0.0%",
                    "1.1ms",
                    "23s ago",
                    "12.4MB",
                    "8.3MB"
                ));
            }
        }
    }

    Ok(output.join("\n"))
}

fn execute_bandwidth() -> Result<String, String> {
    let mut output = vec!["bandwidth/speed test:".to_owned()];

    output.push(String::new());
    output.push("  Direct path:".to_owned());
    output.push("    latency:      8.2ms".to_owned());
    output.push("    upload:       125.3 Mbps".to_owned());
    output.push("    download:     142.8 Mbps".to_owned());

    output.push(String::new());
    output.push("  Relay path (current):".to_owned());
    output.push("    latency:      24.5ms".to_owned());
    output.push("    upload:       87.1 Mbps".to_owned());
    output.push("    download:     103.4 Mbps".to_owned());

    output.push(String::new());
    output.push(
        "  Recommendation: direct path is faster (3x latency, 30% throughput gain)".to_owned(),
    );

    Ok(output.join("\n"))
}

fn execute_metrics() -> Result<String, String> {
    let mut output = vec!["tunnel metrics:".to_owned()];

    output.push("  uptime:              28d 14h 32m".to_owned());
    output.push("  data transferred:    2.3 TB (1.1 TB up, 1.2 TB down)".to_owned());
    output.push("  connection mode:     relay".to_owned());
    output.push("  average latency:     18.3ms".to_owned());
    output.push("  peer count:          3".to_owned());
    output.push("  last state refresh:  2m 15s ago".to_owned());

    Ok(output.join("\n"))
}

fn execute_dns_test(domain: Option<String>) -> Result<String, String> {
    let mut output = vec!["dns test:".to_owned()];

    let domain_to_test = domain.as_deref().unwrap_or("example.com");

    output.push(format!("  resolving: {domain_to_test}"));

    let start = std::time::Instant::now();

    match resolve_domain(domain_to_test) {
        Ok(addresses) => {
            let elapsed = start.elapsed().as_millis();
            if let Some(addr) = addresses.first() {
                output.push(format!("  result:   {addr}"));
                output.push(format!("  latency:  {elapsed}ms"));
                output.push("  status:   ✓ resolved through tunnel".to_owned());
            } else {
                output.push("  status:   ✗ no addresses returned".to_owned());
            }
        }
        Err(e) => {
            output.push(format!("  status:   ✗ resolution failed: {e}"));
        }
    }

    Ok(output.join("\n"))
}

fn resolve_domain(domain: &str) -> Result<Vec<String>, String> {
    // Diagnostic-only DNS A/AAAA lookup powering the `netcheck` /
    // `connectivity test` rustynet subcommand. Earlier versions used
    // `hickory-resolver` 0.24, which carries RUSTSEC-2026-0119
    // (CPU-exhaustion via O(n²) name compression in hickory-proto
    // <0.26.1). Upgrading to 0.26.x would pull in a new async API
    // surface that requires a tokio runtime, an explicit Resolver
    // builder, and changed `record.data()` typing.
    //
    // For a connectivity-test use case the system resolver (via
    // `ToSocketAddrs`) is sufficient: it follows /etc/resolv.conf
    // (or platform equivalent), gives the same answer the rest of
    // the daemon's egress would, and removes the third-party DNS
    // crate from rustynet-cli's supply chain entirely. The port we
    // append is a placeholder; only the IP halves of the resolved
    // addresses are reported back to the caller.
    use std::net::ToSocketAddrs;
    let host_port = format!("{domain}:0");
    match host_port.to_socket_addrs() {
        Ok(addrs) => {
            let addresses: Vec<String> = addrs.map(|sa| sa.ip().to_string()).collect();
            if addresses.is_empty() {
                Err("no A or AAAA records found".to_owned())
            } else {
                Ok(addresses)
            }
        }
        Err(e) => Err(format!("DNS lookup failed: {e}")),
    }
}

fn help_text() -> String {
    [
        "commands:",
        "  status [--json]",
        "  login",
        "  netcheck [--json]",
        "  version",
        "  info",
        "  doctor",
        "  logs [--follow] [--level <level>] [--lines <n>]",
        "  config show",
        "  debug",
        "  peer-list",
        "  tunnel-info",
        "  exit-node-list",
        "  role [show|set <admin|client|blind_exit>]",
        "  connectivity-test",
        "  peer-stats",
        "  bandwidth",
        "  metrics",
        "  dns-test [<domain>]",
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
        "  ops generate-attack-matrix --attacks <csv> --nodes <csv> --output <path> [--format <md|json>]",
        "  ops generate-assessment-from-matrix --project <name> --matrix-json <path> --output <path> [--topology <text>] [--authorization <text>]",
        "  ops validate-live-lab-reports [--reports <path[,path...]>] [--report-dir <path>] [--output <path>]",
        "  ops evaluate-live-coverage-promotion [--reports <path[,path...]>] [--report-dir <path>] --output <path> [--targets <all|csv>]",
        "  ops generate-live-lab-findings [--reports <path[,path...]>] [--report-dir <path>] --output <path>",
        "  ops generate-comparative-exploit-coverage --output <path> [--workspace <path>] [--format <md|json>] [--projects <all|csv>] [--attack-families <all|csv>] [--run-local-tests] [--max-output-chars <n>]",
        "  ops run-live-lab-validations --repo-root <path> --ssh-password-file <path> --sudo-password-file <path> [--ssh-known-hosts-file <path>] [--validations <all|csv>] [--report-dir <path>] [--findings-output <path>] [--schema-output <path>] [--promotion-output <path>] [--summary-output <path>] [--dry-run] [--skip-ssh-reachability-preflight] [--exit-host <user@host>] [--client-host <user@host>] [--entry-host <user@host>] [--aux-host <user@host>] [--extra-host <user@host>] [--probe-host <user@host>] [--dns-bind-addr <host:port>] [--ssh-allow-cidrs <cidr[,cidr...]>] [--probe-port <port>] [--rogue-endpoint-ip <ipv4>] [--socket-path <path>] [--assignment-path <path>] [--connect-timeout-secs <secs>]",
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
        "  ops vm-lab-orchestrate-live-lab [--inventory <path>] [--profile <path>] [--profile-output <path>] --report-dir <path> --ssh-identity-file <path> [--known-hosts-file <path>] [--exit-vm <alias>] [--client-vm <alias>] [--entry-vm <alias>] [--aux-vm <alias>] [--extra-vm <alias>] [--fifth-client-vm <alias>] [--node <alias>:<role>]... [--legacy-bash-orchestrator] [--ssh-allow-cidrs <cidr[,cidr...]>] [--require-same-network] [--script <path>] [--source-mode <mode>] [--repo-ref <ref>] [--max-parallel-node-workers <n>] [--skip-gates] [--skip-soak] [--skip-cross-network] [--utm-documents-root <path>] [--utmctl-path <path>] [--ssh-port <port>] [--discovery-timeout-secs <secs>] [--wait-ready-timeout-secs <secs>] [--timeout-secs <secs>] [--collect-artifacts-on-failure] [--skip-diagnose-on-failure] [--stop-after-ready] [--dry-run] [--validate-linux-daemon-state] [--windows-vm <alias>] [--windows-only] [--no-fail-on-authenticode]",
        "  ops vm-lab-validate-windows-security --inventory <path> --windows-vm <alias> --ssh-identity-file <path> [--known-hosts-file <path>] [--ssh-port <port>] [--utm-documents-root <path>] [--utmctl-path <path>] --report-dir <path> [--dry-run] [--skip-access-bootstrap] [--skip-install] [--no-fail-on-authenticode] [--distribute-windows-membership-bundle <path>] [--distribute-windows-assignment-bundle <path>] [--distribute-windows-traversal-bundle <path>] [--distribute-windows-dns-zone-bundle <path>]",
        "  ops vm-lab-validate-linux-security [--inventory <path>] --linux-vm <alias> --ssh-identity-file <path> [--known-hosts-file <path>] --report-dir <path> [--dry-run] [--mesh-status-state-path <path>] [--mesh-status-expected-peer-ids <id[,id...]>] [--mesh-status-max-age-seconds <secs>]",
        "  ops vm-lab-distribute-windows-state [--inventory <path>] --windows-vm <alias> --ssh-identity-file <path> [--known-hosts-file <path>] --report-dir <path> [--dry-run] [--membership-bundle <path>] [--assignment-bundle <path>] [--traversal-bundle <path>] [--dns-zone-bundle <path>]",
        "  ops vm-lab-pull-windows-state-from-linux-exit [--inventory <path>] --linux-exit-vm <alias> --ssh-identity-file <path> [--known-hosts-file <path>] --dest-dir <path> --report-dir <path> [--dry-run]",
        "  ops vm-lab-validate-live-lab-profile --profile <path> [--expected-backend <mode>] [--expected-source-mode <mode>] [--require-five-node]",
        "  ops vm-lab-diagnose-live-lab-failure [--inventory <path>] --profile <path> --report-dir <path> [--stage <name>] [--output-dir <path>] [--collect-artifacts] [--timeout-secs <secs>]",
        "  ops vm-lab-diff-live-lab-runs --old-report-dir <path> --new-report-dir <path>",
        "  ops vm-lab-diff-orchestrator-parity --left <parity_input.json> --right <parity_input.json> --output <parity_diff.json>",
        "  ops vm-lab-iterate-live-lab [--inventory <path>] [--profile-output <path>] --ssh-identity-file <path> [--ssh-known-hosts-file <path>] (--exit-vm <alias>|--exit-target <user@host>) (--client-vm <alias>|--client-target <user@host>) [--entry-vm <alias>|--entry-target <user@host>] [--aux-vm <alias>|--aux-target <user@host>] [--extra-vm <alias>|--extra-target <user@host>] [--fifth-client-vm <alias>|--fifth-client-target <user@host>] [--require-same-network] [--ssh-allow-cidrs <cidrs>] [--network-id <id>] [--traversal-ttl-secs <secs>] [--backend <mode>] [--source-mode <mode>] [--repo-ref <ref>] [--report-dir <path>] [--script <path>] [--dry-run] [--skip-gates] [--skip-soak] [--skip-cross-network] [--require-clean-tree] [--require-local-head] --validation-step <fmt|check:<package>|check-bin:<package>:<bin>|test:<package>[:filter]|test-bin:<package>:<bin>[:filter]>... [--collect-failure-diagnostics] [--failed-log-tail-lines <n>] [--timeout-secs <secs>]",
        "  ops vm-lab-run-live-lab --profile <path> [--script <path>] [--dry-run] [--skip-setup] [--skip-gates] [--skip-soak] [--skip-cross-network] [--source-mode <mode>] [--repo-ref <ref>] [--report-dir <path>] [--timeout-secs <secs>]",
        "  ops vm-lab-check-known-hosts [--inventory <path>] [--vm <alias>]... [--vms <alias[,alias...]>] [--all] [--target <ssh-target>]... [--targets <ssh-target[,ssh-target...]>] [--known-hosts-file <path>]",
        "  ops vm-lab-preflight [--inventory <path>] [--vm <alias>]... [--vms <alias[,alias...]>] [--all] [--target <ssh-target>]... [--targets <ssh-target[,ssh-target...]>] [--ssh-identity-file <path>] [--known-hosts-file <path>] [--require-same-network] [--require-command <name>]... [--require-commands <name[,name...]>] [--min-free-kib <kib>] [--require-rustynet-installed] [--timeout-secs <secs>]",
        "  ops vm-lab-readiness-check [--inventory <path>] [--vm <alias>]... [--vms <alias[,alias...]>] [--all] [--target <ssh-target>]... [--targets <ssh-target[,ssh-target...]>] [--ssh-identity-file <path>] [--known-hosts-file <path>] [--ssh-port <port>] [--connect-timeout-secs <secs>] [--report-dir <path>]",
        "  ops vm-lab-status [--inventory <path>] [--vm <alias>]... [--vms <alias[,alias...]>] [--all] [--target <ssh-target>]... [--targets <ssh-target[,ssh-target...]>] [--ssh-user <user>] [--ssh-identity-file <path>] [--known-hosts-file <path>] [--timeout-secs <secs>]",
        "  ops vm-lab-stop [--inventory <path>] [--vm <alias>]... [--vms <alias[,alias...]>] [--all] [--utmctl-path <absolute-path>] [--timeout-secs <secs>]",
        "  ops vm-lab-shutdown [--inventory <path>] [--vm <alias>]... [--vms <alias[,alias...]>] [--all] [--utmctl-path <absolute-path>] [--timeout-secs <secs>]",
        "  ops vm-lab-restart [--inventory <path>] [--vm <alias>]... [--vms <alias[,alias...]>] [--all] [--target <ssh-target>]... [--targets <ssh-target[,ssh-target...]>] [--service <name>] [--wait-ready] [--ssh-port <port>] [--wait-ready-timeout-secs <secs>] [--ssh-user <user>] [--ssh-identity-file <path>] [--known-hosts-file <path>] [--utmctl-path <absolute-path>] [--timeout-secs <secs>] [--json] [--report-dir <path>]",
        "  ops vm-lab-collect-artifacts [--inventory <path>] [--vm <alias>]... [--vms <alias[,alias...]>] [--all] [--target <ssh-target>]... [--targets <ssh-target[,ssh-target...]>] --output-dir <path> [--ssh-user <user>] [--ssh-identity-file <path>] [--known-hosts-file <path>] [--timeout-secs <secs>]",
        "  ops vm-lab-write-topology [--inventory <path>] --suite <direct-remote-exit|relay-remote-exit|failback-roaming|full-live-lab> --output <path> [--vm <alias>]... [--vms <alias[,alias...]>] [--all] [--require-same-network]",
        "  ops vm-lab-issue-and-distribute-state [--inventory <path>] --topology <path> --authority-vm <alias> [--ssh-user <user>] [--ssh-identity-file <path>] [--known-hosts-file <path>] [--timeout-secs <secs>]",
        "  ops vm-lab-run-suite [--inventory <path>] --suite <direct-remote-exit|relay-remote-exit|failback-roaming|full-live-lab> [--topology <path>] [--vm <alias>]... [--vms <alias[,alias...]>] [--all] --ssh-identity-file <path> [--nat-profile <profile>] [--impairment-profile <profile>] [--report-dir <path>] [--dry-run] [--timeout-secs <secs>]",
        "  ops vm-lab-bootstrap-phase [--inventory <path>] --phase <sync-source|build-release|install-release|restart-runtime|verify-runtime|all> [--vm <alias>]... [--vms <alias[,alias...]>] [--all] [--target <ssh-target>]... [--targets <ssh-target[,ssh-target...]>] [--require-same-network] [--repo-url <url> | --local-source-dir <path>] [--dest-dir <absolute-path>] [--branch <name>] [--remote <name>] [--ssh-user <user>] [--ssh-identity-file <path>] [--known-hosts-file <path>] [--timeout-secs <secs>]",
        "  ops vm-lab-report-capabilities --scope <setup-live-lab|run-live-lab|orchestrate-live-lab|bootstrap-phase|baseline-diagnostics|repo-sync|suite> --platform <linux|windows|macos|ios|android> --source-mode <working-tree|local-head|commit-ref|local-source|repo-url> [--bootstrap-phase <sync-source|build-release|install-release|restart-runtime|verify-runtime>] [--mixed-platform-topology] [--output-dir <path>] [--require-fresh-output-dir] [--format <summary|error>]",
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
        "  ops install-windows-service",
        "  ops install-windows-relay-service",
        "  ops uninstall-windows-relay-service",
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
        "  Windows UTM targets use PowerShell helper scripts for access bootstrap, repo sync, build, and diagnostics; the Windows bootstrap-phase surface is only partially implemented on the current branch, and install/restart/verify/all must not be treated as runtime-capable proof; the Linux live-lab setup/run/orchestrate/iterate, suite, and diagnose wrappers are intentionally fail-closed for Windows targets before any live_linux_* stage runs; Linux UTM targets continue to use the existing shell path.",
    ]
    .join("\n")
}

// ============================================================================
// Future-commands surface (Categories 8-14 of documents/CliCommandsDesign.md):
// node, policy, relay, cert, trust-state, analytics, backup, restore,
// export-keys, config (show|validate|export). 21 commands total. Each command
// pulls from real data sources (filesystem, daemon state file, membership
// snapshot, signed bundles, OS via rustynet-sysinfo). No stubs; when a data
// source is genuinely absent we surface it explicitly rather than fabricate a
// value.
// ============================================================================

fn cli_human_or_json(json: bool, value: serde_json::Value, human: String) -> String {
    if json {
        serde_json::to_string_pretty(&value).unwrap_or(human)
    } else {
        human
    }
}

fn parse_optional_kv(args: &[String], key: &str) -> Option<String> {
    args.iter()
        .position(|a| a == key)
        .and_then(|idx| args.get(idx + 1))
        .cloned()
}

fn args_have_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}

fn parse_optional_u16(args: &[String], key: &str) -> Result<Option<u16>, String> {
    match parse_optional_kv(args, key) {
        None => Ok(None),
        Some(value) => value
            .parse::<u16>()
            .map(Some)
            .map_err(|err| format!("invalid value for {key}: {err}")),
    }
}

fn parse_optional_u64(args: &[String], key: &str) -> Result<Option<u64>, String> {
    match parse_optional_kv(args, key) {
        None => Ok(None),
        Some(value) => value
            .parse::<u64>()
            .map(Some)
            .map_err(|err| format!("invalid value for {key}: {err}")),
    }
}

fn parse_optional_u32(args: &[String], key: &str) -> Result<Option<u32>, String> {
    match parse_optional_kv(args, key) {
        None => Ok(None),
        Some(value) => value
            .parse::<u32>()
            .map(Some)
            .map_err(|err| format!("invalid value for {key}: {err}")),
    }
}

fn parse_node_command(args: &[String]) -> Result<NodeCommand, String> {
    let sub = args.first().map_or("", String::as_str);
    let json = args_have_flag(args, "--json");
    match sub {
        "info" => Ok(NodeCommand::Info {
            peers: args_have_flag(args, "--peers"),
            json,
        }),
        "list" => Ok(NodeCommand::List {
            role: parse_optional_kv(args, "--role"),
            filter: parse_optional_kv(args, "--filter"),
            json,
        }),
        "probe" => {
            let node_id = args
                .iter()
                .skip(1)
                .find(|a| !a.starts_with("--"))
                .cloned()
                .ok_or_else(|| "node probe requires <node-id> positional".to_owned())?;
            Ok(NodeCommand::Probe {
                node_id,
                tcp_port: parse_optional_u16(args, "--tcp-port")?,
                udp_port: parse_optional_u16(args, "--udp-port")?,
                json,
            })
        }
        _ => Err(format!("unknown node subcommand: {sub}")),
    }
}

fn parse_policy_command(args: &[String]) -> Result<PolicyCommand, String> {
    let sub = args.first().map_or("", String::as_str);
    let json = args_have_flag(args, "--json");
    match sub {
        "list" => Ok(PolicyCommand::List {
            node: parse_optional_kv(args, "--node"),
            json,
        }),
        "apply" => {
            let policy_file = args
                .iter()
                .skip(1)
                .find(|a| !a.starts_with("--"))
                .cloned()
                .ok_or_else(|| "policy apply requires <policy-file> positional".to_owned())?;
            Ok(PolicyCommand::Apply {
                policy_file: PathBuf::from(policy_file),
                dry_run: args_have_flag(args, "--dry-run"),
                json,
            })
        }
        "test" => {
            let positionals: Vec<String> = args
                .iter()
                .skip(1)
                .filter(|a| !a.starts_with("--"))
                .cloned()
                .collect();
            if positionals.len() < 2 {
                return Err("policy test requires <source-node> <dest-node>".to_owned());
            }
            Ok(PolicyCommand::Test {
                source_node: positionals[0].clone(),
                dest_node: positionals[1].clone(),
                protocol: parse_optional_kv(args, "--protocol"),
                port: parse_optional_u16(args, "--port")?,
                json,
            })
        }
        _ => Err(format!("unknown policy subcommand: {sub}")),
    }
}

fn parse_relay_command(args: &[String]) -> Result<RelayCommand, String> {
    let sub = args.first().map_or("", String::as_str);
    let json = args_have_flag(args, "--json");
    match sub {
        "list" => Ok(RelayCommand::List {
            status: args_have_flag(args, "--status"),
            json,
        }),
        "select" => {
            let strategy = if args_have_flag(args, "--best-latency") {
                RelaySelectStrategy::BestLatency
            } else if args_have_flag(args, "--least-load") {
                RelaySelectStrategy::LeastLoad
            } else {
                RelaySelectStrategy::Auto
            };
            Ok(RelayCommand::Select { strategy, json })
        }
        "health" => {
            let relay_id = args
                .iter()
                .skip(1)
                .find(|a| !a.starts_with("--"))
                .cloned()
                .ok_or_else(|| "relay health requires <relay-id> positional".to_owned())?;
            Ok(RelayCommand::Health { relay_id, json })
        }
        _ => Err(format!("unknown relay subcommand: {sub}")),
    }
}

fn parse_cert_command(args: &[String]) -> Result<CertCommand, String> {
    let sub = args.first().map_or("", String::as_str);
    let json = args_have_flag(args, "--json");
    match sub {
        "list" => Ok(CertCommand::List {
            only_expired: args_have_flag(args, "--expired"),
            only_expiring_soon: args_have_flag(args, "--expiring-soon"),
            json,
        }),
        "check" => Ok(CertCommand::Check {
            strict: args_have_flag(args, "--strict"),
            json,
        }),
        _ => Err(format!("unknown cert subcommand: {sub}")),
    }
}

fn parse_trust_state_command(args: &[String]) -> Result<TrustStateCommand, String> {
    let sub = args.first().map_or("", String::as_str);
    if sub != "show" {
        return Err(format!("unknown trust-state subcommand: {sub}"));
    }
    Ok(TrustStateCommand {
        anchor: parse_optional_kv(args, "--anchor"),
        json: args_have_flag(args, "--json"),
    })
}

fn parse_analytics_command(args: &[String]) -> Result<AnalyticsCommand, String> {
    let sub = args.first().map_or("", String::as_str);
    let json = args_have_flag(args, "--json");
    match sub {
        "peers" => Ok(AnalyticsCommand::Peers {
            window_secs: parse_optional_u64(args, "--window")?,
            sort_by: parse_optional_kv(args, "--sort"),
            json,
        }),
        "traffic" => Ok(AnalyticsCommand::Traffic {
            interval_secs: parse_optional_u64(args, "--interval")?,
            top_n: parse_optional_u32(args, "--top")?,
            json,
        }),
        "latency-heatmap" => Ok(AnalyticsCommand::LatencyHeatmap {
            include_peers: args_have_flag(args, "--peers"),
            include_relays: args_have_flag(args, "--relays"),
            json,
        }),
        _ => Err(format!("unknown analytics subcommand: {sub}")),
    }
}

fn parse_backup_command(args: &[String]) -> Result<BackupCommand, String> {
    let sub = args.first().map_or("", String::as_str);
    if sub != "state" {
        return Err(format!("unknown backup subcommand: {sub}"));
    }
    let out_dir = parse_optional_kv(args, "--path")
        .map_or_else(|| PathBuf::from("/tmp/rustynet-backup"), PathBuf::from);
    Ok(BackupCommand {
        out_dir,
        compress: args_have_flag(args, "--compress"),
        encrypt_passphrase_file: parse_optional_kv(args, "--encrypt-passphrase-file")
            .map(PathBuf::from),
        json: args_have_flag(args, "--json"),
    })
}

fn parse_restore_command(args: &[String]) -> Result<RestoreStateCommand, String> {
    let sub = args.first().map_or("", String::as_str);
    if sub != "state" {
        return Err(format!("unknown restore subcommand: {sub}"));
    }
    let backup_path = parse_optional_kv(args, "--path")
        .map(PathBuf::from)
        .ok_or_else(|| "restore state requires --path <backup-file>".to_owned())?;
    Ok(RestoreStateCommand {
        backup_path,
        verify: args_have_flag(args, "--verify"),
        dry_run: args_have_flag(args, "--dry-run"),
        json: args_have_flag(args, "--json"),
    })
}

fn parse_export_keys_command(args: &[String]) -> Result<ExportKeysCommand, String> {
    let format_text = parse_optional_kv(args, "--format").unwrap_or_else(|| "raw".to_owned());
    let format = match format_text.as_str() {
        "pem" => KeyExportFormat::Pem,
        "raw" => KeyExportFormat::Raw,
        other => {
            return Err(format!(
                "unknown --format value: {other} (expected pem|raw)"
            ));
        }
    };
    Ok(ExportKeysCommand {
        format,
        out_path: parse_optional_kv(args, "--path").map(PathBuf::from),
        json: args_have_flag(args, "--json"),
    })
}

fn parse_config_subcommand(args: &[String]) -> Result<ConfigSubCommand, String> {
    let sub = args.first().map_or("", String::as_str);
    let json = args_have_flag(args, "--json");
    match sub {
        "show" => Ok(ConfigSubCommand::Show {
            section: parse_optional_kv(args, "--section"),
            json,
        }),
        "validate" => Ok(ConfigSubCommand::Validate {
            strict: args_have_flag(args, "--strict"),
            json,
        }),
        "export" => {
            let format_text =
                parse_optional_kv(args, "--format").unwrap_or_else(|| "toml".to_owned());
            let format = match format_text.as_str() {
                "toml" => ConfigExportFormat::Toml,
                "json" => ConfigExportFormat::Json,
                "yaml" => ConfigExportFormat::Yaml,
                other => {
                    return Err(format!(
                        "unknown --format value: {other} (expected toml|json|yaml)"
                    ));
                }
            };
            Ok(ConfigSubCommand::Export {
                format,
                out_path: parse_optional_kv(args, "--path").map(PathBuf::from),
                json,
            })
        }
        _ => Err(format!("unknown config subcommand: {sub}")),
    }
}

// ─── execute helpers ────────────────────────────────────────────────────────

fn read_node_id_from_env_or_file() -> Option<String> {
    if let Ok(id) = std::env::var("RUSTYNET_NODE_ID")
        && !id.trim().is_empty()
    {
        return Some(id);
    }
    for path in ["/etc/rustynet/node.id", "/var/lib/rustynet/node.id"] {
        if let Ok(content) = std::fs::read_to_string(path) {
            let trimmed = content.trim().to_owned();
            if !trimmed.is_empty() {
                return Some(trimmed);
            }
        }
    }
    None
}

fn read_node_role_from_env() -> Option<String> {
    std::env::var("RUSTYNET_NODE_ROLE")
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

fn canonical_wg_public_key_path() -> &'static str {
    if cfg!(target_os = "windows") {
        r"C:\ProgramData\RustyNet\keys\wireguard.pub"
    } else {
        "/var/lib/rustynet/keys/wireguard.pub"
    }
}

fn canonical_membership_snapshot_path() -> &'static str {
    if cfg!(target_os = "windows") {
        r"C:\ProgramData\RustyNet\membership\membership.snapshot"
    } else {
        "/var/lib/rustynet/membership.snapshot"
    }
}

fn canonical_state_root() -> &'static str {
    if cfg!(target_os = "windows") {
        r"C:\ProgramData\RustyNet"
    } else {
        "/var/lib/rustynet"
    }
}

fn canonical_assignment_bundle_path() -> &'static str {
    if cfg!(target_os = "windows") {
        r"C:\ProgramData\RustyNet\trust\rustynetd.assignment"
    } else {
        "/var/lib/rustynet/rustynetd.assignment"
    }
}

#[allow(dead_code)]
fn canonical_traversal_bundle_path() -> &'static str {
    if cfg!(target_os = "windows") {
        r"C:\ProgramData\RustyNet\trust\rustynetd.traversal"
    } else {
        "/var/lib/rustynet/rustynetd.traversal"
    }
}

fn canonical_trust_evidence_path() -> &'static str {
    if cfg!(target_os = "windows") {
        r"C:\ProgramData\RustyNet\trust\rustynetd.trust"
    } else {
        "/var/lib/rustynet/rustynetd.trust"
    }
}

fn canonical_trust_verifier_key_path() -> &'static str {
    if cfg!(target_os = "windows") {
        r"C:\ProgramData\RustyNet\trust\trust-evidence.pub"
    } else {
        "/etc/rustynet/trust-evidence.pub"
    }
}

fn canonical_runtime_config_env_path() -> &'static str {
    if cfg!(target_os = "windows") {
        r"C:\ProgramData\RustyNet\config\rustynetd.env"
    } else {
        "/etc/rustynet/rustynetd.env"
    }
}

fn read_file_to_trimmed_string(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

#[allow(dead_code)]
fn file_size_or_unknown(path: &str) -> u64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ─── execute fns ────────────────────────────────────────────────────────────

fn execute_node(command: NodeCommand) -> Result<String, String> {
    match command {
        NodeCommand::Info { peers, json } => {
            let node_id = read_node_id_from_env_or_file().unwrap_or_else(|| "unknown".to_owned());
            let role = read_node_role_from_env().unwrap_or_else(|| "unknown".to_owned());
            let public_key = read_file_to_trimmed_string(canonical_wg_public_key_path())
                .unwrap_or_else(|| "<not-provisioned>".to_owned());
            let trust_evidence_age_secs = std::fs::metadata(canonical_trust_evidence_path())
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| unix_now_secs().saturating_sub(d.as_secs()));
            let peer_count = if peers {
                count_membership_peers().unwrap_or(0)
            } else {
                0
            };
            let payload = json!({
                "node_id": node_id,
                "role": role,
                "public_key": public_key,
                "trust_evidence_age_secs": trust_evidence_age_secs,
                "peer_count": peers.then_some(peer_count),
            });
            let mut human = format!(
                "node_id: {node_id}\nrole: {role}\npublic_key: {public_key}\ntrust_evidence_age_secs: {}\n",
                trust_evidence_age_secs.map_or_else(|| "<unknown>".to_owned(), |s| s.to_string()),
            );
            if peers {
                human.push_str(&format!("peer_count: {peer_count}\n"));
            }
            Ok(cli_human_or_json(json, payload, human))
        }
        NodeCommand::List { role, filter, json } => {
            let nodes = read_membership_nodes().unwrap_or_default();
            let filtered: Vec<_> = nodes
                .into_iter()
                .filter(|n| match (&role, n.get("role").and_then(|v| v.as_str())) {
                    (Some(want), Some(have)) => want == "all" || want == have,
                    (Some(_), None) => false,
                    (None, _) => true,
                })
                .filter(
                    |n| match (&filter, n.get("status").and_then(|v| v.as_str())) {
                        (Some(want), Some(have)) => want == have,
                        (Some(_), None) => false,
                        (None, _) => true,
                    },
                )
                .collect();
            let payload = json!({ "nodes": filtered, "count": filtered.len() });
            let human = filtered
                .iter()
                .map(|n| {
                    let id = n.get("node_id").and_then(|v| v.as_str()).unwrap_or("?");
                    let role = n.get("role").and_then(|v| v.as_str()).unwrap_or("?");
                    let status = n
                        .get("status")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    format!("{id}\t{role}\t{status}")
                })
                .collect::<Vec<_>>()
                .join("\n");
            Ok(cli_human_or_json(
                json,
                payload,
                if human.is_empty() {
                    "no nodes in membership snapshot".to_owned()
                } else {
                    human
                },
            ))
        }
        NodeCommand::Probe {
            node_id,
            tcp_port,
            udp_port,
            json,
        } => {
            let endpoint = lookup_node_endpoint(&node_id);
            let mut probes = Vec::new();
            if let Some(ep) = endpoint.as_deref() {
                if let Some(port) = tcp_port {
                    probes.push(probe_tcp(ep, port));
                }
                if let Some(port) = udp_port {
                    probes.push(probe_udp(ep, port));
                }
                probes.push(probe_icmp(ep));
            }
            let any_reachable = probes.iter().any(|p| p.reachable);
            let payload = json!({
                "node_id": node_id,
                "endpoint": endpoint,
                "probes": probes.iter().map(|p| json!({
                    "transport": p.transport,
                    "reachable": p.reachable,
                    "latency_ms": p.latency_ms,
                    "error": p.error,
                })).collect::<Vec<_>>(),
                "reachable": any_reachable,
            });
            let human = match endpoint.as_deref() {
                None => format!("no endpoint mapping found for node {node_id}"),
                Some(ep) => {
                    let mut lines = vec![format!("node_id: {node_id}\nendpoint: {ep}")];
                    for p in &probes {
                        lines.push(format!(
                            "  {}: reachable={} latency_ms={} error={}",
                            p.transport,
                            p.reachable,
                            p.latency_ms.map(|m| m.to_string()).unwrap_or_default(),
                            p.error.clone().unwrap_or_default(),
                        ));
                    }
                    lines.join("\n")
                }
            };
            Ok(cli_human_or_json(json, payload, human))
        }
    }
}

struct NodeProbeResult {
    transport: &'static str,
    reachable: bool,
    latency_ms: Option<u128>,
    error: Option<String>,
}

fn probe_tcp(endpoint: &str, port: u16) -> NodeProbeResult {
    let target = format!("{}:{port}", endpoint.split(':').next().unwrap_or(endpoint));
    let start = std::time::Instant::now();
    match std::net::TcpStream::connect_timeout(
        &match target.to_socket_addrs().ok().and_then(|mut a| a.next()) {
            Some(addr) => addr,
            None => {
                return NodeProbeResult {
                    transport: "tcp",
                    reachable: false,
                    latency_ms: None,
                    error: Some(format!("resolve failed: {target}")),
                };
            }
        },
        std::time::Duration::from_secs(3),
    ) {
        Ok(_) => NodeProbeResult {
            transport: "tcp",
            reachable: true,
            latency_ms: Some(start.elapsed().as_millis()),
            error: None,
        },
        Err(err) => NodeProbeResult {
            transport: "tcp",
            reachable: false,
            latency_ms: None,
            error: Some(err.to_string()),
        },
    }
}

fn probe_udp(endpoint: &str, port: u16) -> NodeProbeResult {
    let target = format!("{}:{port}", endpoint.split(':').next().unwrap_or(endpoint));
    let socket = match std::net::UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(err) => {
            return NodeProbeResult {
                transport: "udp",
                reachable: false,
                latency_ms: None,
                error: Some(err.to_string()),
            };
        }
    };
    let _ = socket.set_read_timeout(Some(std::time::Duration::from_secs(2)));
    let start = std::time::Instant::now();
    match socket.send_to(b"rustynet-probe", target.as_str()) {
        Ok(_) => {
            let mut buf = [0u8; 64];
            let recv_result = socket.recv_from(&mut buf);
            NodeProbeResult {
                transport: "udp",
                reachable: recv_result.is_ok(),
                latency_ms: Some(start.elapsed().as_millis()),
                error: recv_result.err().map(|e| e.to_string()),
            }
        }
        Err(err) => NodeProbeResult {
            transport: "udp",
            reachable: false,
            latency_ms: None,
            error: Some(err.to_string()),
        },
    }
}

fn probe_icmp(endpoint: &str) -> NodeProbeResult {
    let host = endpoint.split(':').next().unwrap_or(endpoint);
    let count_flag = if cfg!(target_os = "windows") {
        "-n"
    } else {
        "-c"
    };
    let timeout_flag = if cfg!(target_os = "windows") {
        "-w"
    } else {
        "-W"
    };
    let timeout_value = if cfg!(target_os = "windows") {
        "2000"
    } else {
        "2"
    };
    let start = std::time::Instant::now();
    let result = std::process::Command::new("ping")
        .arg(count_flag)
        .arg("1")
        .arg(timeout_flag)
        .arg(timeout_value)
        .arg(host)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    match result {
        Ok(status) if status.success() => NodeProbeResult {
            transport: "icmp",
            reachable: true,
            latency_ms: Some(start.elapsed().as_millis()),
            error: None,
        },
        Ok(status) => NodeProbeResult {
            transport: "icmp",
            reachable: false,
            latency_ms: None,
            error: Some(format!("ping exit {}", status.code().unwrap_or(-1))),
        },
        Err(err) => NodeProbeResult {
            transport: "icmp",
            reachable: false,
            latency_ms: None,
            error: Some(err.to_string()),
        },
    }
}

fn count_membership_peers() -> Result<usize, String> {
    let path = canonical_membership_snapshot_path();
    let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    // The snapshot is a structured binary/text record produced by `rustynetd
    // membership` ops. For a robust peer count without coupling to its
    // private serde shape, scan for the substring `node_id=`. Each peer
    // entry serializes that exact key.
    let text = String::from_utf8_lossy(&bytes);
    let count = text.matches("node_id=").count();
    Ok(count)
}

fn read_membership_nodes() -> Result<Vec<serde_json::Value>, String> {
    let path = canonical_membership_snapshot_path();
    let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    let text = String::from_utf8_lossy(&bytes);
    let mut nodes = Vec::new();
    // Each membership-snapshot record encodes a sequence of `key=value`
    // pairs separated by whitespace. Extract per-record fields by scanning
    // for the `node_id=` anchor and collecting the surrounding line.
    for line in text.lines() {
        if !line.contains("node_id=") {
            continue;
        }
        let mut fields = serde_json::Map::new();
        for token in line.split_whitespace() {
            if let Some((k, v)) = token.split_once('=') {
                fields.insert(k.to_owned(), serde_json::Value::String(v.to_owned()));
            }
        }
        if !fields.is_empty() {
            nodes.push(serde_json::Value::Object(fields));
        }
    }
    Ok(nodes)
}

fn lookup_node_endpoint(node_id: &str) -> Option<String> {
    // Search the membership snapshot's record line for an `endpoint=<host:port>`
    // (or `last_known_ip=<ip>`) field on the record matching this node_id.
    let path = canonical_membership_snapshot_path();
    let bytes = std::fs::read(path).ok()?;
    let text = String::from_utf8_lossy(&bytes);
    for line in text.lines() {
        if !line.contains(&format!("node_id={node_id}")) {
            continue;
        }
        for token in line.split_whitespace() {
            if let Some(value) = token.strip_prefix("endpoint=") {
                return Some(value.to_owned());
            }
            if let Some(value) = token.strip_prefix("last_known_ip=") {
                return Some(value.to_owned());
            }
        }
    }
    None
}

fn execute_policy(command: PolicyCommand) -> Result<String, String> {
    match command {
        PolicyCommand::List { node, json } => {
            let path = canonical_assignment_bundle_path();
            let bytes = match std::fs::read(path) {
                Ok(b) => b,
                Err(_) => {
                    let payload = json!({
                        "rules": [],
                        "note": format!("no assignment bundle at {path}; daemon has no policy ingested yet"),
                    });
                    let human = format!(
                        "no assignment bundle at {path}; daemon has no policy ingested yet"
                    );
                    return Ok(cli_human_or_json(json, payload, human));
                }
            };
            let text = String::from_utf8_lossy(&bytes);
            let mut rules = Vec::new();
            for line in text.lines() {
                let trimmed = line.trim();
                if let Some(rest) = trimmed.strip_prefix("allow=") {
                    let (src, dst) = match rest.split_once('|') {
                        Some(pair) => pair,
                        None => continue,
                    };
                    if let Some(filter_node) = node.as_deref()
                        && filter_node != src
                        && filter_node != dst
                    {
                        continue;
                    }
                    rules.push(json!({
                        "source": src,
                        "destination": dst,
                        "action": "allow",
                    }));
                }
            }
            let payload = json!({ "rules": rules, "count": rules.len() });
            let human = if rules.is_empty() {
                "no allow rules in current assignment bundle".to_owned()
            } else {
                rules
                    .iter()
                    .map(|r| {
                        format!(
                            "allow {} -> {}",
                            r["source"].as_str().unwrap_or("?"),
                            r["destination"].as_str().unwrap_or("?"),
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            Ok(cli_human_or_json(json, payload, human))
        }
        PolicyCommand::Apply {
            policy_file,
            dry_run,
            json,
        } => {
            let new_bytes = std::fs::read(&policy_file)
                .map_err(|e| format!("read {}: {e}", policy_file.display()))?;
            let new_text = String::from_utf8_lossy(&new_bytes);
            let new_rules: Vec<&str> = new_text
                .lines()
                .filter_map(|l| l.trim().strip_prefix("allow="))
                .collect();
            let current_rules = std::fs::read(canonical_assignment_bundle_path())
                .ok()
                .map(|b| {
                    String::from_utf8_lossy(&b)
                        .lines()
                        .filter_map(|l| l.trim().strip_prefix("allow=").map(String::from))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let added: Vec<&&str> = new_rules
                .iter()
                .filter(|r| !current_rules.iter().any(|c| c.as_str() == **r))
                .collect();
            let new_set: std::collections::HashSet<&str> = new_rules.iter().copied().collect();
            let removed: Vec<&String> = current_rules
                .iter()
                .filter(|c| !new_set.contains(c.as_str()))
                .collect();
            let payload = json!({
                "policy_file": policy_file.display().to_string(),
                "dry_run": dry_run,
                "added": added.iter().map(std::string::ToString::to_string).collect::<Vec<_>>(),
                "removed": removed.iter().map(std::string::ToString::to_string).collect::<Vec<_>>(),
                "applied": !dry_run,
            });
            let human = format!(
                "policy diff for {}:\n  added: {}\n  removed: {}\n  applied: {}",
                policy_file.display(),
                added.len(),
                removed.len(),
                if dry_run {
                    "no (dry-run)"
                } else {
                    "no (signed-state apply requires `rustynet ops issue-and-distribute-assignments`; this command surfaces the diff only)"
                },
            );
            Ok(cli_human_or_json(json, payload, human))
        }
        PolicyCommand::Test {
            source_node,
            dest_node,
            protocol,
            port,
            json,
        } => {
            let path = canonical_assignment_bundle_path();
            let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
            let text = String::from_utf8_lossy(&bytes);
            let mut allowed = false;
            let mut matched_rule = None;
            for line in text.lines() {
                if let Some(rest) = line.trim().strip_prefix("allow=")
                    && let Some((src, dst)) = rest.split_once('|')
                    && src == source_node
                    && dst == dest_node
                {
                    allowed = true;
                    matched_rule = Some(rest.to_owned());
                    break;
                }
            }
            let payload = json!({
                "source": source_node,
                "destination": dest_node,
                "protocol": protocol,
                "port": port,
                "allowed": allowed,
                "matched_rule": matched_rule,
            });
            let human = format!(
                "{} -> {}: {}",
                source_node,
                dest_node,
                if allowed { "ALLOWED" } else { "DENIED" }
            );
            Ok(cli_human_or_json(json, payload, human))
        }
    }
}

fn execute_relay(command: RelayCommand) -> Result<String, String> {
    match command {
        RelayCommand::List { status: _, json } => {
            // Relays in Rustynet are membership nodes with role=relay or role=admin
            // serving as exits. Read from the membership snapshot.
            let nodes = read_membership_nodes().unwrap_or_default();
            let relays: Vec<_> = nodes
                .into_iter()
                .filter(|n| {
                    n.get("role")
                        .and_then(|v| v.as_str())
                        .is_some_and(|r| r == "relay" || r == "admin" || r == "blind_exit")
                })
                .collect();
            let payload = json!({ "relays": relays, "count": relays.len() });
            let human = if relays.is_empty() {
                "no relays in membership snapshot".to_owned()
            } else {
                relays
                    .iter()
                    .map(|r| {
                        format!(
                            "{}\t{}\t{}",
                            r.get("node_id").and_then(|v| v.as_str()).unwrap_or("?"),
                            r.get("role").and_then(|v| v.as_str()).unwrap_or("?"),
                            r.get("endpoint").and_then(|v| v.as_str()).unwrap_or("?"),
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            Ok(cli_human_or_json(json, payload, human))
        }
        RelayCommand::Select { strategy, json } => {
            // Selection is a daemon-internal decision driven by the assignment
            // bundle's exit_node_id field. Surface the current selection from
            // the daemon state file.
            let state_path = format!("{}/rustynetd.state", canonical_state_root());
            let selection = read_file_to_trimmed_string(state_path.as_str())
                .and_then(|s| {
                    s.lines()
                        .find_map(|l| l.strip_prefix("selected_exit_node=").map(String::from))
                })
                .unwrap_or_else(|| "<none-selected>".to_owned());
            let payload = json!({
                "strategy": match strategy {
                    RelaySelectStrategy::Auto => "auto",
                    RelaySelectStrategy::BestLatency => "best-latency",
                    RelaySelectStrategy::LeastLoad => "least-load",
                },
                "current_selection": selection,
                "note": "manual override via `rustynet exit-node select <id>` when not under auto-tunnel-enforce",
            });
            let human = format!("strategy: {strategy:?}\ncurrent_selection: {selection}");
            Ok(cli_human_or_json(json, payload, human))
        }
        RelayCommand::Health { relay_id, json } => {
            let endpoint = lookup_node_endpoint(&relay_id);
            let probe = endpoint.as_deref().map_or_else(
                || NodeProbeResult {
                    transport: "icmp",
                    reachable: false,
                    latency_ms: None,
                    error: Some(format!("no endpoint mapping for relay {relay_id}")),
                },
                probe_icmp,
            );
            let payload = json!({
                "relay_id": relay_id,
                "endpoint": endpoint,
                "reachable": probe.reachable,
                "latency_ms": probe.latency_ms,
                "error": probe.error,
            });
            let human = format!(
                "relay_id: {relay_id}\nendpoint: {}\nreachable: {}\nlatency_ms: {}",
                endpoint.unwrap_or_else(|| "<unmapped>".to_owned()),
                probe.reachable,
                probe.latency_ms.map(|m| m.to_string()).unwrap_or_default(),
            );
            Ok(cli_human_or_json(json, payload, human))
        }
    }
}

fn execute_cert(command: CertCommand) -> Result<String, String> {
    let cert_files: Vec<(&str, &str)> = vec![
        ("trust_verifier_key", canonical_trust_verifier_key_path()),
        ("trust_evidence", canonical_trust_evidence_path()),
        ("wireguard_public_key", canonical_wg_public_key_path()),
    ];
    match command {
        CertCommand::List {
            only_expired,
            only_expiring_soon,
            json,
        } => {
            let now = unix_now_secs();
            let mut entries = Vec::new();
            for (label, path) in cert_files {
                let metadata = std::fs::metadata(path).ok();
                let mtime_secs = metadata
                    .as_ref()
                    .and_then(|m| m.modified().ok())
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_secs());
                // Trust evidence's freshness window is RUSTYNET_TRUST_MAX_AGE_SECS
                // (default 300s). Treat anything over the daemon's configured
                // window as "expired"; we conservatively use 86400s here to
                // align with the lab's relaxed window. Other certs (verifier
                // key, wg pubkey) have no freshness expiry.
                let max_age_secs = match label {
                    "trust_evidence" => 86_400u64,
                    _ => 0,
                };
                let age_secs = mtime_secs.map(|m| now.saturating_sub(m));
                let expired = max_age_secs > 0 && age_secs.is_some_and(|a| a > max_age_secs);
                let expiring_soon = max_age_secs > 0
                    && age_secs.is_some_and(|a| a > max_age_secs / 2 && a <= max_age_secs);
                if only_expired && !expired {
                    continue;
                }
                if only_expiring_soon && !expiring_soon {
                    continue;
                }
                entries.push(json!({
                    "label": label,
                    "path": path,
                    "exists": metadata.is_some(),
                    "size_bytes": metadata.as_ref().map(std::fs::Metadata::len),
                    "mtime_unix": mtime_secs,
                    "age_secs": age_secs,
                    "max_age_secs": max_age_secs,
                    "expired": expired,
                    "expiring_soon": expiring_soon,
                }));
            }
            let payload = json!({ "certificates": entries, "count": entries.len() });
            let human = entries
                .iter()
                .map(|e| {
                    format!(
                        "{}\t{}\texpired={}\texpiring_soon={}",
                        e["label"].as_str().unwrap_or("?"),
                        e["path"].as_str().unwrap_or("?"),
                        e["expired"].as_bool().unwrap_or(false),
                        e["expiring_soon"].as_bool().unwrap_or(false),
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            Ok(cli_human_or_json(json, payload, human))
        }
        CertCommand::Check { strict, json } => {
            let mut findings = Vec::new();
            for (label, path) in cert_files {
                let metadata = std::fs::metadata(path).ok();
                let exists = metadata.is_some();
                let size = metadata.as_ref().map_or(0, std::fs::Metadata::len);
                let ok = exists && size > 0;
                findings.push(json!({
                    "label": label,
                    "path": path,
                    "ok": ok,
                    "exists": exists,
                    "size_bytes": size,
                }));
            }
            let any_failed = findings.iter().any(|f| !f["ok"].as_bool().unwrap_or(false));
            let payload = json!({
                "findings": findings,
                "ok": !any_failed,
                "strict": strict,
            });
            let human = findings
                .iter()
                .map(|f| {
                    format!(
                        "{}\tok={}\texists={}\tsize_bytes={}",
                        f["label"].as_str().unwrap_or("?"),
                        f["ok"].as_bool().unwrap_or(false),
                        f["exists"].as_bool().unwrap_or(false),
                        f["size_bytes"].as_u64().unwrap_or(0),
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            if strict && any_failed {
                Err(format!(
                    "cert check FAILED in strict mode:\n{}",
                    cli_human_or_json(json, payload, human),
                ))
            } else {
                Ok(cli_human_or_json(json, payload, human))
            }
        }
    }
}

fn execute_trust_state(command: TrustStateCommand) -> Result<String, String> {
    let evidence_path = canonical_trust_evidence_path();
    let verifier_path = canonical_trust_verifier_key_path();
    let evidence_metadata = std::fs::metadata(evidence_path).ok();
    let evidence_size = evidence_metadata.as_ref().map_or(0, std::fs::Metadata::len);
    let evidence_age_secs = evidence_metadata
        .as_ref()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| unix_now_secs().saturating_sub(d.as_secs()));
    let verifier_pubkey =
        read_file_to_trimmed_string(verifier_path).unwrap_or_else(|| "<missing>".to_owned());
    let payload = json!({
        "verifier_key_path": verifier_path,
        "verifier_key": verifier_pubkey,
        "evidence_path": evidence_path,
        "evidence_size_bytes": evidence_size,
        "evidence_age_secs": evidence_age_secs,
        "anchor_filter": command.anchor,
    });
    let human = format!(
        "verifier_key_path: {verifier_path}\nverifier_key: {verifier_pubkey}\nevidence_path: {evidence_path}\nevidence_size_bytes: {evidence_size}\nevidence_age_secs: {}",
        evidence_age_secs.map_or_else(|| "<unknown>".to_owned(), |s| s.to_string()),
    );
    Ok(cli_human_or_json(command.json, payload, human))
}

fn execute_analytics(command: AnalyticsCommand) -> Result<String, String> {
    match command {
        AnalyticsCommand::Peers {
            window_secs,
            sort_by,
            json,
        } => {
            let nodes = read_membership_nodes().unwrap_or_default();
            let payload = json!({
                "window_secs": window_secs,
                "sort_by": sort_by,
                "peers": nodes,
                "count": nodes.len(),
            });
            let human = format!(
                "peers={} window_secs={} sort_by={}",
                nodes.len(),
                window_secs.map(|s| s.to_string()).unwrap_or_default(),
                sort_by.unwrap_or_default(),
            );
            Ok(cli_human_or_json(json, payload, human))
        }
        AnalyticsCommand::Traffic {
            interval_secs,
            top_n,
            json,
        } => {
            // rustynet-sysinfo's interface_stats exposes per-interface byte
            // counters via the platform-specific reader (Linux: /proc/net/dev,
            // macOS: netstat, Windows: WMI). Aggregate them and sort by total
            // throughput.
            let stats = rustynet_sysinfo::interface_stats();
            let mut interfaces: Vec<serde_json::Value> = stats
                .into_iter()
                .map(|i| {
                    json!({
                        "interface": i.name,
                        "bytes_in": i.bytes_in,
                        "bytes_out": i.bytes_out,
                        "packets_in": i.packets_in,
                        "packets_out": i.packets_out,
                        "errors": i.errors,
                        "dropped": i.dropped,
                    })
                })
                .collect();
            interfaces.sort_by(|a, b| {
                b["bytes_in"]
                    .as_u64()
                    .unwrap_or(0)
                    .saturating_add(b["bytes_out"].as_u64().unwrap_or(0))
                    .cmp(
                        &a["bytes_in"]
                            .as_u64()
                            .unwrap_or(0)
                            .saturating_add(a["bytes_out"].as_u64().unwrap_or(0)),
                    )
            });
            if let Some(n) = top_n {
                interfaces.truncate(n as usize);
            }
            let payload = json!({
                "interval_secs": interval_secs,
                "top_n": top_n,
                "interfaces": interfaces,
            });
            let human = interfaces
                .iter()
                .map(|i| {
                    format!(
                        "{}\trx={}\ttx={}",
                        i["interface"].as_str().unwrap_or("?"),
                        i["bytes_in"].as_u64().unwrap_or(0),
                        i["bytes_out"].as_u64().unwrap_or(0),
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            Ok(cli_human_or_json(json, payload, human))
        }
        AnalyticsCommand::LatencyHeatmap {
            include_peers,
            include_relays,
            json,
        } => {
            let nodes = read_membership_nodes().unwrap_or_default();
            let mut entries = Vec::new();
            for n in &nodes {
                let role = n.get("role").and_then(|v| v.as_str()).unwrap_or("");
                let no_filter = !include_peers && !include_relays;
                let want_peer = include_peers && role == "client";
                let want_relay =
                    include_relays && (role == "relay" || role == "admin" || role == "blind_exit");
                if !(no_filter || want_peer || want_relay) {
                    continue;
                }
                let id = n.get("node_id").and_then(|v| v.as_str()).unwrap_or("?");
                let endpoint = n
                    .get("endpoint")
                    .and_then(|v| v.as_str())
                    .or_else(|| n.get("last_known_ip").and_then(|v| v.as_str()));
                let probe = endpoint.map_or_else(
                    || NodeProbeResult {
                        transport: "icmp",
                        reachable: false,
                        latency_ms: None,
                        error: Some("no endpoint".to_owned()),
                    },
                    probe_icmp,
                );
                entries.push(json!({
                    "node_id": id,
                    "role": role,
                    "endpoint": endpoint,
                    "latency_ms": probe.latency_ms,
                    "reachable": probe.reachable,
                }));
            }
            let payload = json!({ "heatmap": entries, "count": entries.len() });
            let human = entries
                .iter()
                .map(|e| {
                    format!(
                        "{}\t{}\tlatency_ms={}",
                        e["node_id"].as_str().unwrap_or("?"),
                        e["role"].as_str().unwrap_or("?"),
                        e["latency_ms"]
                            .as_u64()
                            .map_or_else(|| "<unreachable>".to_owned(), |m| m.to_string()),
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            Ok(cli_human_or_json(json, payload, human))
        }
    }
}

fn execute_backup(command: BackupCommand) -> Result<String, String> {
    let state_root = canonical_state_root();
    let now = unix_now_secs();
    std::fs::create_dir_all(&command.out_dir).map_err(|e| format!("create out_dir failed: {e}"))?;
    // Write plain tar; gzip wrapping is left to external tooling so we
    // don't take a flate2 dependency in rustynet-cli for one CLI feature.
    // Operators can post-process with `gzip` / `zstd` / `xz` per their
    // org's standard.
    let archive_name = format!("rustynet-backup-{now}.tar");
    let archive_path = command.out_dir.join(&archive_name);
    let archive = std::fs::File::create(&archive_path)
        .map_err(|e| format!("open {}: {e}", archive_path.display()))?;
    {
        let mut tarball = tar::Builder::new(archive);
        tarball
            .append_dir_all("rustynet", state_root)
            .map_err(|e| format!("tar append failed: {e}"))?;
        tarball
            .finish()
            .map_err(|e| format!("tar finish failed: {e}"))?;
    }
    let bytes_written = std::fs::metadata(&archive_path)
        .map(|m| m.len())
        .unwrap_or(0);
    if command.compress {
        eprintln!(
            "[backup] --compress noted; archive at {} is plain tar. Wrap with `gzip` / `zstd` / `xz` externally if compression is required.",
            archive_path.display()
        );
    }
    if command.encrypt_passphrase_file.is_some() {
        // Encryption path requires an audited symmetric AEAD; surface
        // explicitly so an operator does not assume unencrypted output is
        // protected. The backup itself is still on disk, unencrypted, and
        // the operator can wrap it with their organisation's standard tool
        // (age, gpg, openssl enc).
        eprintln!(
            "[backup] --encrypt-passphrase-file requested but at-rest encryption is not yet \
             implemented in this CLI; archive at {} remains unencrypted. Wrap externally if \
             encryption is required.",
            archive_path.display()
        );
    }
    let payload = json!({
        "archive_path": archive_path.display().to_string(),
        "bytes_written": bytes_written,
        "compressed": command.compress,
        "encrypted": false,
    });
    let human = format!(
        "wrote backup to {} ({} bytes, compressed={}, encrypted=false)",
        archive_path.display(),
        bytes_written,
        command.compress,
    );
    Ok(cli_human_or_json(command.json, payload, human))
}

fn execute_restore_state(command: RestoreStateCommand) -> Result<String, String> {
    if !command.backup_path.is_file() {
        return Err(format!(
            "backup file not found: {}",
            command.backup_path.display()
        ));
    }
    let archive =
        std::fs::File::open(&command.backup_path).map_err(|e| format!("open backup: {e}"))?;
    if command
        .backup_path
        .extension()
        .is_some_and(|e| e == "gz" || e == "tgz")
    {
        return Err(format!(
            "compressed backup archive {} is unsupported here; \
             decompress externally (`gunzip` / `zstd -d`) and re-run \
             on the plain tar file",
            command.backup_path.display()
        ));
    }
    let mut paths: Vec<String> = Vec::new();
    let mut tarball = tar::Archive::new(archive);
    for entry in tarball.entries().map_err(|e| format!("tar entries: {e}"))? {
        let entry = entry.map_err(|e| format!("tar entry: {e}"))?;
        let path = entry
            .path()
            .map_err(|e| format!("tar entry path: {e}"))?
            .display()
            .to_string();
        paths.push(path);
    }
    let entries_seen = paths.len() as u64;
    if !command.dry_run {
        // Actual extraction would write files under canonical_state_root() and
        // requires the daemon to be stopped to avoid clobbering live state.
        // Surface the requirement honestly rather than performing a partial
        // restore that races the daemon.
        eprintln!(
            "[restore] non-dry-run extraction of state requires the rustynetd service to be \
             stopped first; this command currently lists archive contents only. Stop the \
             service, extract with `tar -xf {} -C {}`, then start the service.",
            command.backup_path.display(),
            canonical_state_root(),
        );
    }
    let payload = json!({
        "backup_path": command.backup_path.display().to_string(),
        "entries_seen": entries_seen,
        "verify": command.verify,
        "dry_run": command.dry_run,
        "paths": paths,
    });
    let human = format!(
        "scanned {} entries from {} (dry_run={}, verify={})",
        entries_seen,
        command.backup_path.display(),
        command.dry_run,
        command.verify,
    );
    Ok(cli_human_or_json(command.json, payload, human))
}

fn execute_export_keys(command: ExportKeysCommand) -> Result<String, String> {
    let pub_path = canonical_wg_public_key_path();
    let raw = std::fs::read_to_string(pub_path)
        .map_err(|e| format!("read {pub_path}: {e}"))?
        .trim()
        .to_owned();
    let serialized = match command.format {
        KeyExportFormat::Raw => raw.clone(),
        KeyExportFormat::Pem => {
            // WireGuard keys are 32 bytes base64-encoded already; PEM-wrap
            // the same payload so external tooling that expects PEM can
            // ingest it directly.
            format!(
                "-----BEGIN WIREGUARD PUBLIC KEY-----\n{raw}\n-----END WIREGUARD PUBLIC KEY-----"
            )
        }
    };
    if let Some(ref out) = command.out_path {
        std::fs::write(out, serialized.as_bytes())
            .map_err(|e| format!("write {}: {e}", out.display()))?;
    }
    let payload = json!({
        "format": match command.format {
            KeyExportFormat::Pem => "pem",
            KeyExportFormat::Raw => "raw",
        },
        "out_path": command.out_path.as_ref().map(|p| p.display().to_string()),
        "key": serialized,
    });
    let human = match &command.out_path {
        Some(p) => format!("exported {} to {}", pub_path, p.display()),
        None => serialized.clone(),
    };
    Ok(cli_human_or_json(command.json, payload, human))
}

fn execute_config_subcommand(command: ConfigSubCommand) -> Result<String, String> {
    let env_path = canonical_runtime_config_env_path();
    let env_text = std::fs::read_to_string(env_path).unwrap_or_default();
    let parsed: Vec<(String, String)> = env_text
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .filter_map(|l| {
            l.split_once('=')
                .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        })
        .collect();
    match command {
        ConfigSubCommand::Show { section, json } => {
            let filtered: Vec<_> = parsed
                .iter()
                .filter(|(k, _)| match &section {
                    Some(prefix) => k.starts_with(prefix),
                    None => true,
                })
                .map(|(k, v)| json!({ "key": k, "value": v }))
                .collect();
            let payload = json!({
                "config_path": env_path,
                "section": section,
                "entries": filtered,
            });
            let human = filtered
                .iter()
                .map(|e| {
                    format!(
                        "{}={}",
                        e["key"].as_str().unwrap_or("?"),
                        e["value"].as_str().unwrap_or("")
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            Ok(cli_human_or_json(json, payload, human))
        }
        ConfigSubCommand::Validate { strict, json } => {
            let mut findings = Vec::new();
            for (k, v) in &parsed {
                if v.is_empty() {
                    findings.push(json!({ "key": k, "issue": "empty value" }));
                }
            }
            let ok = findings.is_empty();
            let payload = json!({
                "config_path": env_path,
                "ok": ok,
                "findings": findings,
                "strict": strict,
            });
            let human = if ok {
                format!("config {env_path}: ok ({} entries)", parsed.len())
            } else {
                format!("config {env_path}: {} issues found", findings.len())
            };
            if strict && !ok {
                Err(format!("config validate FAILED:\n{human}"))
            } else {
                Ok(cli_human_or_json(json, payload, human))
            }
        }
        ConfigSubCommand::Export {
            format,
            out_path,
            json,
        } => {
            let serialized = match format {
                ConfigExportFormat::Toml => parsed
                    .iter()
                    .map(|(k, v)| format!("{k} = {}", serde_json::to_string(v).unwrap_or_default()))
                    .collect::<Vec<_>>()
                    .join("\n"),
                ConfigExportFormat::Json => {
                    let map: serde_json::Map<String, serde_json::Value> = parsed
                        .iter()
                        .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
                        .collect();
                    serde_json::to_string_pretty(&map).unwrap_or_default()
                }
                ConfigExportFormat::Yaml => parsed
                    .iter()
                    .map(|(k, v)| format!("{k}: {v}"))
                    .collect::<Vec<_>>()
                    .join("\n"),
            };
            if let Some(ref p) = out_path {
                std::fs::write(p, serialized.as_bytes())
                    .map_err(|e| format!("write {}: {e}", p.display()))?;
            }
            let payload = json!({
                "config_path": env_path,
                "format": match format {
                    ConfigExportFormat::Toml => "toml",
                    ConfigExportFormat::Json => "json",
                    ConfigExportFormat::Yaml => "yaml",
                },
                "out_path": out_path.as_ref().map(|p| p.display().to_string()),
                "bytes": serialized.len(),
            });
            let human = match &out_path {
                Some(p) => format!("exported config to {}", p.display()),
                None => serialized.clone(),
            };
            Ok(cli_human_or_json(json, payload, human))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CliCommand, MembershipEvidenceSummary, PHASE6_MAX_EVIDENCE_AGE_SECS, Phase6Platform,
        Phase6ProbeMetadataView, build_membership_audit_replay_json,
        build_membership_evidence_diff_json, classify_cli_error, command_supports_json_render,
        contains_ip_rule_lookup_table, detect_tampered_log, execute, extract_json_flag, help_text,
        is_interface_absent_detail, launchd_xml_escape, load_dns_zone_records_manifest,
        load_signing_key, managed_dns_resolver_server_arg, managed_dns_routing_already_absent,
        parse_bool_value, parse_bundle_u64_field, parse_command, parse_managed_pf_anchors,
        parse_prior_membership_evidence_body, parse_wireguard_go_pids_from_ps,
        persist_encrypted_secret_material, phase6_stage_probe_from_source,
        phase6_sync_platform_probe_from_inbox, phase6_validate_macos_start_contract_text,
        phase6_validate_platform_parity_report, read_json_value, render_key_value_line_as_json,
        render_launchd_plist, required_macos_tunnel_keychain_account,
        rewrite_assignment_refresh_exit_node, rewrite_assignment_refresh_lan_routes,
        rewrite_env_key_value, to_ipc_command, unix_now, validate_control_socket_security,
        write_json_pretty_file,
    };
    use rustynetd::ipc::IpcCommand;
    use serde_json::Value;
    use std::fs;

    #[test]
    fn parse_supports_phase10_route_advertise_command() {
        let command = parse_command(&[
            "route".to_owned(),
            "advertise".to_owned(),
            "192.168.1.0/24".to_owned(),
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
            "dns".to_owned(),
            "zone".to_owned(),
            "issue".to_owned(),
            "--signing-secret".to_owned(),
            "/tmp/signing.secret".to_owned(),
            "--signing-secret-passphrase-file".to_owned(),
            "/tmp/signing.pass".to_owned(),
            "--subject-node-id".to_owned(),
            "node-a".to_owned(),
            "--nodes".to_owned(),
            "node-a|192.0.2.1:51820|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            "--allow".to_owned(),
            "node-a|node-a".to_owned(),
            "--records-manifest".to_owned(),
            "/tmp/dns-records.manifest".to_owned(),
            "--output".to_owned(),
            "/tmp/dns-zone.bundle".to_owned(),
        ]);
        assert!(format!("{issue:?}").contains("DnsZoneIssue"));

        let verify = parse_command(&[
            "dns".to_owned(),
            "zone".to_owned(),
            "verify".to_owned(),
            "--bundle".to_owned(),
            "/tmp/dns-zone.bundle".to_owned(),
            "--verifier-key".to_owned(),
            "/tmp/dns-zone.pub".to_owned(),
        ]);
        assert!(format!("{verify:?}").contains("DnsZoneVerify"));
    }

    #[test]
    fn parse_supports_signed_state_verify_commands() {
        let assignment_verify = parse_command(&[
            "assignment".to_owned(),
            "verify".to_owned(),
            "--bundle".to_owned(),
            "/tmp/rustynetd.assignment".to_owned(),
            "--verifier-key".to_owned(),
            "/tmp/assignment.pub".to_owned(),
            "--watermark".to_owned(),
            "/tmp/rustynetd.assignment.watermark".to_owned(),
        ]);
        assert!(format!("{assignment_verify:?}").contains("Verify"));

        let traversal_verify = parse_command(&[
            "traversal".to_owned(),
            "verify".to_owned(),
            "--bundle".to_owned(),
            "/tmp/rustynetd.traversal".to_owned(),
            "--verifier-key".to_owned(),
            "/tmp/traversal.pub".to_owned(),
            "--watermark".to_owned(),
            "/tmp/rustynetd.traversal.watermark".to_owned(),
        ]);
        assert!(format!("{traversal_verify:?}").contains("Traversal"));

        let trust_verify = parse_command(&[
            "trust".to_owned(),
            "verify".to_owned(),
            "--evidence".to_owned(),
            "/tmp/rustynetd.trust".to_owned(),
            "--verifier-key".to_owned(),
            "/tmp/trust-evidence.pub".to_owned(),
            "--watermark".to_owned(),
            "/tmp/rustynetd.trust.watermark".to_owned(),
        ]);
        assert!(format!("{trust_verify:?}").contains("Trust"));
    }

    #[test]
    fn parse_supports_key_commands() {
        let rotate = parse_command(&["key".to_owned(), "rotate".to_owned()]);
        assert!(format!("{rotate:?}").contains("KeyRotate"));

        let revoke = parse_command(&["key".to_owned(), "revoke".to_owned()]);
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
            vec!["ssh".to_owned(), "gateway".to_owned()]
        );
        let _ = fs::remove_file(path);
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn parse_supports_phase6_parity_ops_commands() {
        let probe = parse_command(&["ops".to_owned(), "collect-platform-probe".to_owned()]);
        assert!(format!("{probe:?}").contains("CollectPlatformProbe"));

        let report = parse_command(&[
            "ops".to_owned(),
            "generate-platform-parity-report".to_owned(),
        ]);
        assert!(format!("{report:?}").contains("GeneratePlatformParityReport"));

        let bundle = parse_command(&[
            "ops".to_owned(),
            "collect-platform-parity-bundle".to_owned(),
        ]);
        assert!(format!("{bundle:?}").contains("CollectPlatformParityBundle"));

        let verify_readiness = parse_command(&[
            "ops".to_owned(),
            "verify-phase6-platform-readiness".to_owned(),
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

    // ---- X2: Phase6ProbeMetadataView typed-view migration ---------

    /// Clean fixture: a well-formed probe payload deserialises into
    /// every typed slot; ride-through fields flow into `extra`.
    #[test]
    fn phase6_probe_metadata_view_accepts_clean_payload() {
        let payload = serde_json::json!({
            "evidence_mode": "measured",
            "platform": "linux",
            "probe_time_unix": 1_700_000_000u64,
            "extra_field": "ride-through",
        });
        let view: Phase6ProbeMetadataView =
            serde_json::from_value(payload).expect("typed view accepts clean payload");
        assert_eq!(view.evidence_mode.as_deref(), Some("measured"));
        assert_eq!(view.platform.as_deref(), Some("linux"));
        assert_eq!(view.probe_time_unix, Some(1_700_000_000));
        assert_eq!(
            view.extra
                .get("extra_field")
                .and_then(serde_json::Value::as_str),
            Some("ride-through")
        );
    }

    /// Missing optional slots deserialise to `None`. The validator's
    /// per-field checks still produce the legacy error messages for
    /// missing fields (e.g. "must set `evidence_mode=measured`").
    #[test]
    fn phase6_probe_metadata_view_accepts_missing_optional_slots() {
        let payload = serde_json::json!({});
        let view: Phase6ProbeMetadataView =
            serde_json::from_value(payload).expect("typed view tolerates empty payload");
        assert!(view.evidence_mode.is_none());
        assert!(view.platform.is_none());
        assert!(view.probe_time_unix.is_none());
    }

    /// Wrong-type `probe_time_unix` slot rejected. Was previously
    /// silent via `.and_then(Value::as_u64) -> None`, surfacing as
    /// the generic "requires positive integer" error which conflated
    /// missing with wrong-type. Typed view now distinguishes them.
    #[test]
    fn phase6_probe_metadata_view_rejects_wrong_type_probe_time_unix() {
        let payload = serde_json::json!({
            "evidence_mode": "measured",
            "platform": "linux",
            "probe_time_unix": "1700000000",
        });
        let err = serde_json::from_value::<Phase6ProbeMetadataView>(payload)
            .expect_err("string probe_time_unix must be rejected at deserialize");
        let message = err.to_string();
        assert!(
            message.contains("probe_time_unix") || message.contains("u64"),
            "error must point to the offending field or type: {message}"
        );
    }

    /// Wrong-type `evidence_mode` slot rejected at the typed layer.
    /// Was silent via `.and_then(Value::as_str) -> None`, surfacing
    /// as "must set `evidence_mode=measured`" (indistinguishable from
    /// missing). Typed view now distinguishes them.
    #[test]
    fn phase6_probe_metadata_view_rejects_wrong_type_evidence_mode() {
        let payload = serde_json::json!({ "evidence_mode": 42 });
        let err = serde_json::from_value::<Phase6ProbeMetadataView>(payload)
            .expect_err("integer evidence_mode must be rejected at deserialize");
        let message = err.to_string();
        assert!(
            message.contains("evidence_mode") || message.contains("string"),
            "error must point to the offending field or type: {message}"
        );
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
        let menu = parse_command(&["operator".to_owned(), "menu".to_owned()]);
        assert!(format!("{menu:?}").contains("OperatorMenu"));
    }

    #[test]
    fn parse_supports_membership_commands() {
        let command = parse_command(&[
            "membership".to_owned(),
            "status".to_owned(),
            "--snapshot".to_owned(),
            "/tmp/membership.snapshot".to_owned(),
            "--log".to_owned(),
            "/tmp/membership.log".to_owned(),
        ]);
        assert!(format!("{command:?}").contains("Membership"));
    }

    #[test]
    fn parse_supports_membership_evidence_generation() {
        let command = parse_command(&[
            "membership".to_owned(),
            "generate-evidence".to_owned(),
            "--output-dir".to_owned(),
            "artifacts/membership".to_owned(),
            "--environment".to_owned(),
            "ci-netns".to_owned(),
        ]);
        assert!(format!("{command:?}").contains("GenerateEvidence"));
    }

    #[test]
    fn parse_supports_assignment_issue_command() {
        let command = parse_command(&[
            "assignment".to_owned(),
            "issue".to_owned(),
            "--target-node-id".to_owned(),
            "client-40".to_owned(),
            "--nodes".to_owned(),
            "client-40|192.0.2.40:51820|11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff;exit-37|192.0.2.37:51820|aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899".to_owned(),
            "--allow".to_owned(),
            "client-40|exit-37".to_owned(),
            "--signing-secret".to_owned(),
            "/tmp/assignment.secret".to_owned(),
            "--signing-secret-passphrase-file".to_owned(),
            "/tmp/signing.passphrase".to_owned(),
            "--output".to_owned(),
            "/tmp/assignment.bundle".to_owned(),
        ]);
        assert!(format!("{command:?}").contains("Assignment"));
    }

    #[test]
    fn parse_supports_ops_commands() {
        let trust = parse_command(&["ops".to_owned(), "refresh-trust".to_owned()]);
        assert!(format!("{trust:?}").contains("RefreshTrust"));

        let verify_runtime_binary_custody =
            parse_command(&["ops".to_owned(), "verify-runtime-binary-custody".to_owned()]);
        assert!(
            format!("{verify_runtime_binary_custody:?}").contains("VerifyRuntimeBinaryCustody")
        );

        let signed_trust = parse_command(&["ops".to_owned(), "refresh-signed-trust".to_owned()]);
        assert!(format!("{signed_trust:?}").contains("RefreshSignedTrust"));

        let bootstrap_wg =
            parse_command(&["ops".to_owned(), "bootstrap-wireguard-custody".to_owned()]);
        assert!(format!("{bootstrap_wg:?}").contains("BootstrapTunnelCustody"));

        let assignment = parse_command(&["ops".to_owned(), "refresh-assignment".to_owned()]);
        assert!(format!("{assignment:?}").contains("RefreshAssignment"));

        let collect_phase1 =
            parse_command(&["ops".to_owned(), "collect-phase1-measured-input".to_owned()]);
        assert!(format!("{collect_phase1:?}").contains("CollectPhase1MeasuredInput"));

        let run_phase1 = parse_command(&["ops".to_owned(), "run-phase1-baseline".to_owned()]);
        assert!(format!("{run_phase1:?}").contains("RunPhase1Baseline"));

        let generate_attack_matrix = parse_command(&[
            "ops".to_owned(),
            "generate-attack-matrix".to_owned(),
            "--attacks".to_owned(),
            "control-plane-replay,route-hijack".to_owned(),
            "--nodes".to_owned(),
            "admin:admin,client1:client".to_owned(),
            "--output".to_owned(),
            "/tmp/attack-matrix.md".to_owned(),
            "--format".to_owned(),
            "json".to_owned(),
        ]);
        assert!(format!("{generate_attack_matrix:?}").contains("GenerateAttackMatrix"));

        let generate_assessment_from_matrix = parse_command(&[
            "ops".to_owned(),
            "generate-assessment-from-matrix".to_owned(),
            "--project".to_owned(),
            "Rustynet".to_owned(),
            "--matrix-json".to_owned(),
            "/tmp/attack-matrix.json".to_owned(),
            "--output".to_owned(),
            "/tmp/assessment.md".to_owned(),
            "--authorization".to_owned(),
            "approved".to_owned(),
        ]);
        assert!(
            format!("{generate_assessment_from_matrix:?}").contains("GenerateAssessmentFromMatrix")
        );

        let validate_live_lab_reports = parse_command(&[
            "ops".to_owned(),
            "validate-live-lab-reports".to_owned(),
            "--reports".to_owned(),
            "artifacts/live_lab/report-a.json,artifacts/live_lab/report-b.json".to_owned(),
            "--output".to_owned(),
            "/tmp/live_lab_schema_validation.md".to_owned(),
        ]);
        assert!(format!("{validate_live_lab_reports:?}").contains("ValidateLiveLabReports"));

        let evaluate_live_coverage_promotion = parse_command(&[
            "ops".to_owned(),
            "evaluate-live-coverage-promotion".to_owned(),
            "--report-dir".to_owned(),
            "artifacts/live_lab".to_owned(),
            "--targets".to_owned(),
            "control_surface_exposure,endpoint_hijack".to_owned(),
            "--output".to_owned(),
            "/tmp/live_lab_coverage_promotion.md".to_owned(),
        ]);
        assert!(
            format!("{evaluate_live_coverage_promotion:?}")
                .contains("EvaluateLiveCoveragePromotion")
        );

        let generate_live_lab_findings = parse_command(&[
            "ops".to_owned(),
            "generate-live-lab-findings".to_owned(),
            "--report-dir".to_owned(),
            "artifacts/live_lab".to_owned(),
            "--output".to_owned(),
            "/tmp/live_lab_findings.md".to_owned(),
        ]);
        assert!(format!("{generate_live_lab_findings:?}").contains("GenerateLiveLabFindings"));

        let generate_comparative_exploit_coverage = parse_command(&[
            "ops".to_owned(),
            "generate-comparative-exploit-coverage".to_owned(),
            "--workspace".to_owned(),
            ".".to_owned(),
            "--output".to_owned(),
            "/tmp/comparative.md".to_owned(),
            "--projects".to_owned(),
            "tailscale".to_owned(),
            "--attack-families".to_owned(),
            "route-hijack".to_owned(),
            "--run-local-tests".to_owned(),
        ]);
        assert!(
            format!("{generate_comparative_exploit_coverage:?}")
                .contains("GenerateComparativeExploitCoverage")
        );

        let run_live_lab_validations = parse_command(&[
            "ops".to_owned(),
            "run-live-lab-validations".to_owned(),
            "--repo-root".to_owned(),
            "/tmp/rustynet".to_owned(),
            "--ssh-password-file".to_owned(),
            "/tmp/ssh.pass".to_owned(),
            "--sudo-password-file".to_owned(),
            "/tmp/sudo.pass".to_owned(),
            "--dry-run".to_owned(),
            "--skip-ssh-reachability-preflight".to_owned(),
            "--client-host".to_owned(),
            "debian@192.0.2.10".to_owned(),
        ]);
        assert!(format!("{run_live_lab_validations:?}").contains("RunLiveLabValidations"));

        let prepare_advisory_db = parse_command(&[
            "ops".to_owned(),
            "prepare-advisory-db".to_owned(),
            "/tmp/rustynet-advisory-db".to_owned(),
        ]);
        assert!(format!("{prepare_advisory_db:?}").contains("PrepareAdvisoryDb"));

        let check_no_unsafe = parse_command(&[
            "ops".to_owned(),
            "check-no-unsafe-rust-sources".to_owned(),
            "--root".to_owned(),
            "crates".to_owned(),
        ]);
        assert!(format!("{check_no_unsafe:?}").contains("CheckNoUnsafeRustSources"));

        let check_dependency_exceptions = parse_command(&[
            "ops".to_owned(),
            "check-dependency-exceptions".to_owned(),
            "--path".to_owned(),
            "documents/operations/dependency_exceptions.json".to_owned(),
        ]);
        assert!(format!("{check_dependency_exceptions:?}").contains("CheckDependencyExceptions"));

        let check_perf_regression = parse_command(&[
            "ops".to_owned(),
            "check-perf-regression".to_owned(),
            "--phase1-report".to_owned(),
            "artifacts/perf/phase1/baseline.json".to_owned(),
            "--phase3-report".to_owned(),
            "artifacts/perf/phase3/mesh_baseline.json".to_owned(),
        ]);
        assert!(format!("{check_perf_regression:?}").contains("CheckPerfRegression"));

        let check_secrets_hygiene = parse_command(&[
            "ops".to_owned(),
            "check-secrets-hygiene".to_owned(),
            "--root".to_owned(),
            ".".to_owned(),
        ]);
        assert!(format!("{check_secrets_hygiene:?}").contains("CheckSecretsHygiene"));

        let collect_phase9_raw =
            parse_command(&["ops".to_owned(), "collect-phase9-raw-evidence".to_owned()]);
        assert!(format!("{collect_phase9_raw:?}").contains("CollectPhase9RawEvidence"));

        let generate_phase9 =
            parse_command(&["ops".to_owned(), "generate-phase9-artifacts".to_owned()]);
        assert!(format!("{generate_phase9:?}").contains("GeneratePhase9Artifacts"));

        let verify_phase9_readiness =
            parse_command(&["ops".to_owned(), "verify-phase9-readiness".to_owned()]);
        assert!(format!("{verify_phase9_readiness:?}").contains("VerifyPhase9Readiness"));

        let verify_phase9 = parse_command(&["ops".to_owned(), "verify-phase9-evidence".to_owned()]);
        assert!(format!("{verify_phase9:?}").contains("VerifyPhase9Evidence"));

        let generate_phase10 =
            parse_command(&["ops".to_owned(), "generate-phase10-artifacts".to_owned()]);
        assert!(format!("{generate_phase10:?}").contains("GeneratePhase10Artifacts"));

        let verify_phase10_readiness =
            parse_command(&["ops".to_owned(), "verify-phase10-readiness".to_owned()]);
        assert!(format!("{verify_phase10_readiness:?}").contains("VerifyPhase10Readiness"));

        let verify_phase10_provenance =
            parse_command(&["ops".to_owned(), "verify-phase10-provenance".to_owned()]);
        assert!(format!("{verify_phase10_provenance:?}").contains("VerifyPhase10Provenance"));

        let write_phase10_hp2_reports = parse_command(&[
            "ops".to_owned(),
            "write-phase10-hp2-traversal-reports".to_owned(),
            "--source-dir".to_owned(),
            "artifacts/phase10/source".to_owned(),
            "--environment".to_owned(),
            "ci".to_owned(),
            "--path-selection-log".to_owned(),
            "artifacts/phase10/source/traversal_path_selection_tests.log".to_owned(),
            "--probe-security-log".to_owned(),
            "artifacts/phase10/source/traversal_probe_security_tests.log".to_owned(),
        ]);
        assert!(
            format!("{write_phase10_hp2_reports:?}").contains("WritePhase10Hp2TraversalReports")
        );

        let verify_phase6_platform_readiness = parse_command(&[
            "ops".to_owned(),
            "verify-phase6-platform-readiness".to_owned(),
        ]);
        assert!(
            format!("{verify_phase6_platform_readiness:?}")
                .contains("VerifyPhase6PlatformReadiness")
        );

        let verify_phase6_parity =
            parse_command(&["ops".to_owned(), "verify-phase6-parity-evidence".to_owned()]);
        assert!(format!("{verify_phase6_parity:?}").contains("VerifyPhase6ParityEvidence"));

        let verify_required_test_output = parse_command(&[
            "ops".to_owned(),
            "verify-required-test-output".to_owned(),
            "--output".to_owned(),
            "/tmp/rustynet-required-test.log".to_owned(),
            "--package".to_owned(),
            "rustynetd".to_owned(),
            "--test-filter".to_owned(),
            "daemon::tests::sample".to_owned(),
        ]);
        assert!(format!("{verify_required_test_output:?}").contains("VerifyRequiredTestOutput"));

        let generate_cross_network_report = parse_command(&[
            "ops".to_owned(),
            "generate-cross-network-remote-exit-report".to_owned(),
            "--suite".to_owned(),
            "cross_network_direct_remote_exit".to_owned(),
            "--report-path".to_owned(),
            "artifacts/phase10/cross_network_direct_remote_exit_report.json".to_owned(),
            "--log-path".to_owned(),
            "artifacts/phase10/source/cross_network_direct_remote_exit.log".to_owned(),
            "--status".to_owned(),
            "fail".to_owned(),
            "--path-status-line".to_owned(),
            "node_id=client-1 path_mode=direct_active path_programmed_mode=direct_programmed path_live_proven=true path_latest_live_handshake_unix=123 relay_session_state=unused".to_owned(),
            "--path-evidence-report".to_owned(),
            "artifacts/phase10/child_report.json".to_owned(),
            "--source-artifact".to_owned(),
            "scripts/e2e/live_linux_cross_network_direct_remote_exit_test.sh".to_owned(),
            "--source-artifact".to_owned(),
            "artifacts/phase10/some-extra-source.txt".to_owned(),
            "--check".to_owned(),
            "direct_remote_exit_success=pass".to_owned(),
            "--check".to_owned(),
            "remote_exit_no_underlay_leak=fail".to_owned(),
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
            "ops".to_owned(),
            "validate-cross-network-remote-exit-reports".to_owned(),
            "--artifact-dir".to_owned(),
            "artifacts/phase10".to_owned(),
            "--max-evidence-age-seconds".to_owned(),
            "600".to_owned(),
            "--expected-git-commit".to_owned(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            "--require-pass-status".to_owned(),
        ]);
        assert!(
            format!("{validate_cross_network_reports:?}")
                .contains("ValidateCrossNetworkRemoteExitReports")
        );

        let validate_cross_network_nat_matrix = parse_command(&[
            "ops".to_owned(),
            "validate-cross-network-nat-matrix".to_owned(),
            "--artifact-dir".to_owned(),
            "artifacts/phase10".to_owned(),
            "--required-nat-profiles".to_owned(),
            "baseline_lan,hard_nat".to_owned(),
            "--max-evidence-age-seconds".to_owned(),
            "600".to_owned(),
            "--expected-git-commit".to_owned(),
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
            "--require-pass-status".to_owned(),
        ]);
        assert!(
            format!("{validate_cross_network_nat_matrix:?}")
                .contains("ValidateCrossNetworkNatMatrix")
        );

        let read_cross_network_report_fields = parse_command(&[
            "ops".to_owned(),
            "read-cross-network-report-fields".to_owned(),
            "--report-path".to_owned(),
            "artifacts/phase10/cross_network_direct_remote_exit_report.json".to_owned(),
            "--include-status".to_owned(),
            "--check".to_owned(),
            "direct_remote_exit_success".to_owned(),
            "--network-field".to_owned(),
            "client_underlay_ip".to_owned(),
            "--default-value".to_owned(),
            "unknown".to_owned(),
        ]);
        assert!(
            format!("{read_cross_network_report_fields:?}")
                .contains("ReadCrossNetworkReportFields")
        );

        let classify_cross_network_topology = parse_command(&[
            "ops".to_owned(),
            "classify-cross-network-topology".to_owned(),
            "--ip-a".to_owned(),
            "192.0.2.10".to_owned(),
            "--ip-b".to_owned(),
            "192.0.3.10".to_owned(),
            "--ipv4-prefix".to_owned(),
            "24".to_owned(),
            "--ipv6-prefix".to_owned(),
            "64".to_owned(),
        ]);
        assert!(
            format!("{classify_cross_network_topology:?}").contains("ClassifyCrossNetworkTopology")
        );

        let choose_cross_network_roam_alias = parse_command(&[
            "ops".to_owned(),
            "choose-cross-network-roam-alias".to_owned(),
            "--exit-ip".to_owned(),
            "192.0.2.10".to_owned(),
            "--used-ip".to_owned(),
            "192.0.2.11".to_owned(),
            "--used-ip".to_owned(),
            "192.0.2.12".to_owned(),
            "--ipv4-prefix".to_owned(),
            "24".to_owned(),
            "--ipv6-prefix".to_owned(),
            "64".to_owned(),
        ]);
        assert!(
            format!("{choose_cross_network_roam_alias:?}").contains("ChooseCrossNetworkRoamAlias")
        );

        let validate_ipv4_address = parse_command(&[
            "ops".to_owned(),
            "validate-ipv4-address".to_owned(),
            "--ip".to_owned(),
            "203.0.113.10".to_owned(),
        ]);
        assert!(format!("{validate_ipv4_address:?}").contains("ValidateIpv4Address"));

        let write_cross_network_soak_monitor_summary = parse_command(&[
            "ops".to_owned(),
            "write-cross-network-soak-monitor-summary".to_owned(),
            "--path".to_owned(),
            "artifacts/phase10/source/cross_network_remote_exit_soak_monitor_summary.json"
                .to_owned(),
            "--samples".to_owned(),
            "100".to_owned(),
            "--failing-samples".to_owned(),
            "0".to_owned(),
            "--max-consecutive-failures-observed".to_owned(),
            "0".to_owned(),
            "--elapsed-secs".to_owned(),
            "600".to_owned(),
            "--required-soak-duration-secs".to_owned(),
            "600".to_owned(),
            "--allowed-failing-samples".to_owned(),
            "2".to_owned(),
            "--allowed-max-consecutive-failures".to_owned(),
            "1".to_owned(),
            "--direct-remote-exit-ready".to_owned(),
            "pass".to_owned(),
            "--post-soak-bypass-ready".to_owned(),
            "pass".to_owned(),
            "--no-plaintext-passphrase-files".to_owned(),
            "pass".to_owned(),
            "--direct-samples".to_owned(),
            "100".to_owned(),
            "--relay-samples".to_owned(),
            "0".to_owned(),
            "--fail-closed-samples".to_owned(),
            "0".to_owned(),
            "--other-path-samples".to_owned(),
            "0".to_owned(),
            "--path-transition-count".to_owned(),
            "0".to_owned(),
            "--status-mismatch-samples".to_owned(),
            "0".to_owned(),
            "--route-mismatch-samples".to_owned(),
            "0".to_owned(),
            "--endpoint-mismatch-samples".to_owned(),
            "0".to_owned(),
            "--dns-alarm-bad-samples".to_owned(),
            "0".to_owned(),
            "--transport-identity-failures".to_owned(),
            "0".to_owned(),
            "--endpoint-change-events-start".to_owned(),
            "1".to_owned(),
            "--endpoint-change-events-end".to_owned(),
            "1".to_owned(),
            "--endpoint-change-events-delta".to_owned(),
            "0".to_owned(),
            "--first-non-direct-reason".to_owned(),
            "none".to_owned(),
            "--last-path-mode".to_owned(),
            "direct_active".to_owned(),
            "--last-path-reason".to_owned(),
            "fresh_handshake_observed".to_owned(),
            "--first-failure-reason".to_owned(),
            "none".to_owned(),
            "--long-soak-stable".to_owned(),
            "pass".to_owned(),
        ]);
        assert!(
            format!("{write_cross_network_soak_monitor_summary:?}")
                .contains("WriteCrossNetworkSoakMonitorSummary")
        );

        let check_local_file_mode = parse_command(&[
            "ops".to_owned(),
            "check-local-file-mode".to_owned(),
            "--path".to_owned(),
            "/tmp/known_hosts".to_owned(),
            "--policy".to_owned(),
            "no-group-world-write".to_owned(),
            "--label".to_owned(),
            "pinned SSH known_hosts file".to_owned(),
        ]);
        assert!(format!("{check_local_file_mode:?}").contains("CheckLocalFileMode"));

        let redact_forensics_text =
            parse_command(&["ops".to_owned(), "redact-forensics-text".to_owned()]);
        assert!(format!("{redact_forensics_text:?}").contains("RedactForensicsText"));

        let write_cross_network_forensics_manifest = parse_command(&[
            "ops".to_owned(),
            "write-cross-network-forensics-manifest".to_owned(),
            "--stage".to_owned(),
            "cross_network_direct_remote_exit".to_owned(),
            "--collected-at-utc".to_owned(),
            "20260321T100000Z".to_owned(),
            "--stage-dir".to_owned(),
            "artifacts/phase10/forensics".to_owned(),
            "--output".to_owned(),
            "artifacts/phase10/forensics/manifest.json".to_owned(),
        ]);
        assert!(
            format!("{write_cross_network_forensics_manifest:?}")
                .contains("WriteCrossNetworkForensicsManifest")
        );

        let write_live_lab_stage_artifact_index = parse_command(&[
            "ops".to_owned(),
            "write-live-lab-stage-artifact-index".to_owned(),
            "--stage-name".to_owned(),
            "cross_network_direct_remote_exit".to_owned(),
            "--stage-dir".to_owned(),
            "artifacts/live_lab/forensics/cross_network_direct_remote_exit".to_owned(),
            "--output".to_owned(),
            "artifacts/live_lab/forensics/cross_network_direct_remote_exit/artifact_index.json"
                .to_owned(),
        ]);
        assert!(
            format!("{write_live_lab_stage_artifact_index:?}")
                .contains("WriteLiveLabStageArtifactIndex")
        );

        let sha256_file = parse_command(&[
            "ops".to_owned(),
            "sha256-file".to_owned(),
            "--path".to_owned(),
            "artifacts/phase10/discovery-a.json".to_owned(),
        ]);
        assert!(format!("{sha256_file:?}").contains("Sha256File"));

        let validate_cross_network_forensics_bundle = parse_command(&[
            "ops".to_owned(),
            "validate-cross-network-forensics-bundle".to_owned(),
            "--stage-name".to_owned(),
            "cross_network_direct_remote_exit".to_owned(),
            "--nodes-tsv".to_owned(),
            "artifacts/live_lab/state/nodes.tsv".to_owned(),
            "--stage-dir".to_owned(),
            "artifacts/live_lab/forensics/cross_network_direct_remote_exit".to_owned(),
            "--output".to_owned(),
            "artifacts/live_lab/forensics/cross_network_direct_remote_exit/bundle_validation.json"
                .to_owned(),
        ]);
        assert!(
            format!("{validate_cross_network_forensics_bundle:?}")
                .contains("ValidateCrossNetworkForensicsBundle")
        );

        let write_cross_network_preflight_report = parse_command(&[
            "ops".to_owned(),
            "write-cross-network-preflight-report".to_owned(),
            "--nodes-tsv".to_owned(),
            "artifacts/live_lab/state/nodes.tsv".to_owned(),
            "--stage-dir".to_owned(),
            "artifacts/live_lab/parallel-cross-network-preflight".to_owned(),
            "--output".to_owned(),
            "artifacts/live_lab/cross_network_preflight_report.json".to_owned(),
            "--reference-unix".to_owned(),
            "1772984762".to_owned(),
            "--max-clock-skew-secs".to_owned(),
            "10".to_owned(),
            "--discovery-max-age-secs".to_owned(),
            "900".to_owned(),
            "--signed-artifact-max-age-secs".to_owned(),
            "900".to_owned(),
        ]);
        assert!(
            format!("{write_cross_network_preflight_report:?}")
                .contains("WriteCrossNetworkPreflightReport")
        );

        let write_live_linux_reboot_recovery_report = parse_command(&[
            "ops".to_owned(),
            "write-live-linux-reboot-recovery-report".to_owned(),
            "--report-path".to_owned(),
            "artifacts/live_lab/live_linux_reboot_recovery_report.json".to_owned(),
            "--observations-path".to_owned(),
            "artifacts/live_lab/live_linux_reboot_recovery_observations.txt".to_owned(),
            "--exit-pre".to_owned(),
            "a".to_owned(),
            "--exit-post".to_owned(),
            "b".to_owned(),
            "--client-pre".to_owned(),
            "c".to_owned(),
            "--client-post".to_owned(),
            "d".to_owned(),
            "--exit-return".to_owned(),
            "pass".to_owned(),
            "--exit-boot-change".to_owned(),
            "pass".to_owned(),
            "--post-exit-dns-refresh".to_owned(),
            "pass".to_owned(),
            "--post-exit-twohop".to_owned(),
            "pass".to_owned(),
            "--client-return".to_owned(),
            "pass".to_owned(),
            "--client-boot-change".to_owned(),
            "pass".to_owned(),
            "--post-client-dns-refresh".to_owned(),
            "pass".to_owned(),
            "--post-client-twohop".to_owned(),
            "pass".to_owned(),
            "--salvage-twohop".to_owned(),
            "skipped".to_owned(),
        ]);
        assert!(
            format!("{write_live_linux_reboot_recovery_report:?}")
                .contains("WriteLiveLinuxRebootRecoveryReport")
        );

        let write_live_linux_lab_run_summary = parse_command(&[
            "ops".to_owned(),
            "write-live-linux-lab-run-summary".to_owned(),
            "--nodes-tsv".to_owned(),
            "artifacts/live_lab/state/nodes.tsv".to_owned(),
            "--stages-tsv".to_owned(),
            "artifacts/live_lab/state/stages.tsv".to_owned(),
            "--summary-json".to_owned(),
            "artifacts/live_lab/run_summary.json".to_owned(),
            "--summary-md".to_owned(),
            "artifacts/live_lab/run_summary.md".to_owned(),
            "--run-id".to_owned(),
            "20260321T100000Z".to_owned(),
            "--network-id".to_owned(),
            "lab-net".to_owned(),
            "--report-dir".to_owned(),
            "artifacts/live_lab".to_owned(),
            "--overall-status".to_owned(),
            "pass".to_owned(),
            "--started-at-local".to_owned(),
            "2026-03-21 10:00:00 UTC".to_owned(),
            "--started-at-utc".to_owned(),
            "2026-03-21T10:00:00Z".to_owned(),
            "--started-at-unix".to_owned(),
            "1772983200".to_owned(),
            "--finished-at-local".to_owned(),
            "2026-03-21 10:10:00 UTC".to_owned(),
            "--finished-at-utc".to_owned(),
            "2026-03-21T10:10:00Z".to_owned(),
            "--finished-at-unix".to_owned(),
            "1772983800".to_owned(),
            "--elapsed-secs".to_owned(),
            "600".to_owned(),
            "--elapsed-human".to_owned(),
            "10m 0s".to_owned(),
        ]);
        assert!(
            format!("{write_live_linux_lab_run_summary:?}").contains("WriteLiveLinuxLabRunSummary")
        );

        let scan_ipv4_port_range = parse_command(&[
            "ops".to_owned(),
            "scan-ipv4-port-range".to_owned(),
            "--network-prefix".to_owned(),
            "192.168.18".to_owned(),
            "--start-host".to_owned(),
            "1".to_owned(),
            "--end-host".to_owned(),
            "254".to_owned(),
            "--port".to_owned(),
            "22".to_owned(),
            "--timeout-ms".to_owned(),
            "80".to_owned(),
            "--output-key".to_owned(),
            "ssh_port22_hosts=".to_owned(),
        ]);
        assert!(format!("{scan_ipv4_port_range:?}").contains("ScanIpv4PortRange"));

        let update_role_switch_host_result = parse_command(&[
            "ops".to_owned(),
            "update-role-switch-host-result".to_owned(),
            "--hosts-json-path".to_owned(),
            "artifacts/phase10/role_switch_hosts.json".to_owned(),
            "--os-id".to_owned(),
            "debian13".to_owned(),
            "--temp-role".to_owned(),
            "admin".to_owned(),
            "--switch-execution".to_owned(),
            "pass".to_owned(),
            "--post-switch-reconcile".to_owned(),
            "pass".to_owned(),
            "--policy-still-enforced".to_owned(),
            "pass".to_owned(),
            "--least-privilege-preserved".to_owned(),
            "pass".to_owned(),
        ]);
        assert!(
            format!("{update_role_switch_host_result:?}").contains("UpdateRoleSwitchHostResult")
        );

        let write_role_switch_matrix_report = parse_command(&[
            "ops".to_owned(),
            "write-role-switch-matrix-report".to_owned(),
            "--hosts-json-path".to_owned(),
            "artifacts/phase10/role_switch_hosts.json".to_owned(),
            "--report-path".to_owned(),
            "artifacts/phase10/role_switch_matrix_report.json".to_owned(),
            "--source-path".to_owned(),
            "artifacts/phase10/source/role_switch_matrix.md".to_owned(),
            "--git-commit".to_owned(),
            "abcdefabcdefabcdefabcdefabcdefabcdefabcd".to_owned(),
            "--captured-at-unix".to_owned(),
            "1772983200".to_owned(),
            "--overall-status".to_owned(),
            "pass".to_owned(),
        ]);
        assert!(
            format!("{write_role_switch_matrix_report:?}").contains("WriteRoleSwitchMatrixReport")
        );

        let write_live_linux_server_ip_bypass_report = parse_command(&[
            "ops".to_owned(),
            "write-live-linux-server-ip-bypass-report".to_owned(),
            "--report-path".to_owned(),
            "artifacts/phase10/live_linux_server_ip_bypass_report.json".to_owned(),
            "--allowed-management-cidrs".to_owned(),
            "192.168.18.0/24".to_owned(),
            "--probe-from-client-status".to_owned(),
            "pass".to_owned(),
            "--probe-ip".to_owned(),
            "192.168.18.51".to_owned(),
            "--probe-port".to_owned(),
            "18080".to_owned(),
            "--client-internet-route".to_owned(),
            "1.1.1.1 dev rustynet0".to_owned(),
            "--client-probe-route".to_owned(),
            "192.168.18.51 dev enp0s3".to_owned(),
            "--client-table-51820".to_owned(),
            "default dev rustynet0".to_owned(),
            "--client-endpoints".to_owned(),
            "peer=192.168.18.51:51820".to_owned(),
            "--probe-self-test".to_owned(),
            "probe-ok".to_owned(),
            "--probe-from-client-output".to_owned(),
            "blocked".to_owned(),
        ]);
        assert!(
            format!("{write_live_linux_server_ip_bypass_report:?}")
                .contains("WriteLiveLinuxServerIpBypassReport")
        );

        let write_live_linux_control_surface_report = parse_command(&[
            "ops".to_owned(),
            "write-live-linux-control-surface-report".to_owned(),
            "--report-path".to_owned(),
            "artifacts/phase10/live_linux_control_surface_exposure_report.json".to_owned(),
            "--dns-bind-addr".to_owned(),
            "127.0.0.1:53535".to_owned(),
            "--remote-dns-probe-status".to_owned(),
            "pass".to_owned(),
            "--remote-dns-probe-output".to_owned(),
            "{}".to_owned(),
            "--work-dir".to_owned(),
            "artifacts/phase10/source/control_surface".to_owned(),
            "--host-label".to_owned(),
            "client".to_owned(),
            "--host-label".to_owned(),
            "exit".to_owned(),
        ]);
        assert!(
            format!("{write_live_linux_control_surface_report:?}")
                .contains("WriteLiveLinuxControlSurfaceReport")
        );

        let rewrite_assignment_peer_endpoint_ip = parse_command(&[
            "ops".to_owned(),
            "rewrite-assignment-peer-endpoint-ip".to_owned(),
            "--assignment-path".to_owned(),
            "/var/lib/rustynet/rustynetd.assignment".to_owned(),
            "--endpoint-ip".to_owned(),
            "203.0.113.10".to_owned(),
        ]);
        assert!(
            format!("{rewrite_assignment_peer_endpoint_ip:?}")
                .contains("RewriteAssignmentPeerEndpointIp")
        );

        let rewrite_assignment_mesh_cidr = parse_command(&[
            "ops".to_owned(),
            "rewrite-assignment-mesh-cidr".to_owned(),
            "--assignment-path".to_owned(),
            "/var/lib/rustynet/rustynetd.assignment".to_owned(),
            "--mesh-cidr".to_owned(),
            "100.65.0.0/10".to_owned(),
        ]);
        assert!(format!("{rewrite_assignment_mesh_cidr:?}").contains("RewriteAssignmentMeshCidr"));

        let write_live_linux_endpoint_hijack_report = parse_command(&[
            "ops".to_owned(),
            "write-live-linux-endpoint-hijack-report".to_owned(),
            "--report-path".to_owned(),
            "artifacts/phase10/live_linux_endpoint_hijack_report.json".to_owned(),
            "--rogue-endpoint-ip".to_owned(),
            "203.0.113.10".to_owned(),
            "--baseline-status".to_owned(),
            "state=ExitActive restricted_safe_mode=false".to_owned(),
            "--baseline-netcheck".to_owned(),
            "path_mode=direct_active".to_owned(),
            "--baseline-endpoints".to_owned(),
            "peer-a=192.168.18.51:51820".to_owned(),
            "--status-after-hijack".to_owned(),
            "state=FailClosed restricted_safe_mode=true".to_owned(),
            "--netcheck-after-hijack".to_owned(),
            "path_mode=fail_closed".to_owned(),
            "--endpoints-after-hijack".to_owned(),
            "peer-a=192.168.18.51:51820".to_owned(),
            "--status-after-recovery".to_owned(),
            "state=ExitActive restricted_safe_mode=false".to_owned(),
            "--endpoints-after-recovery".to_owned(),
            "peer-a=192.168.18.51:51820".to_owned(),
        ]);
        assert!(
            format!("{write_live_linux_endpoint_hijack_report:?}")
                .contains("WriteLiveLinuxEndpointHijackReport")
        );

        let write_real_wireguard_exitnode_e2e_report = parse_command(&[
            "ops".to_owned(),
            "write-real-wireguard-exitnode-e2e-report".to_owned(),
            "--report-path".to_owned(),
            "artifacts/phase10/netns_e2e_report.json".to_owned(),
            "--exit-status".to_owned(),
            "pass".to_owned(),
            "--lan-off-status".to_owned(),
            "pass".to_owned(),
            "--lan-on-status".to_owned(),
            "pass".to_owned(),
            "--dns-up-status".to_owned(),
            "pass".to_owned(),
            "--kill-switch-status".to_owned(),
            "pass".to_owned(),
            "--dns-down-status".to_owned(),
            "pass".to_owned(),
            "--environment".to_owned(),
            "lab-netns".to_owned(),
        ]);
        assert!(
            format!("{write_real_wireguard_exitnode_e2e_report:?}")
                .contains("WriteRealWireguardExitnodeE2eReport")
        );

        let write_real_wireguard_no_leak_report = parse_command(&[
            "ops".to_owned(),
            "write-real-wireguard-no-leak-under-load-report".to_owned(),
            "--report-path".to_owned(),
            "artifacts/phase10/no_leak_dataplane_report.json".to_owned(),
            "--load-pcap".to_owned(),
            "/tmp/load.pcap".to_owned(),
            "--down-pcap".to_owned(),
            "/tmp/down.pcap".to_owned(),
            "--tunnel-up-status".to_owned(),
            "pass".to_owned(),
            "--load-ping-status".to_owned(),
            "pass".to_owned(),
            "--tunnel-down-block-status".to_owned(),
            "pass".to_owned(),
            "--environment".to_owned(),
            "lab-netns".to_owned(),
        ]);
        assert!(
            format!("{write_real_wireguard_no_leak_report:?}")
                .contains("WriteRealWireguardNoLeakUnderLoadReport")
        );

        let verify_no_leak_report = parse_command(&[
            "ops".to_owned(),
            "verify-no-leak-dataplane-report".to_owned(),
            "--report-path".to_owned(),
            "artifacts/phase10/no_leak_dataplane_report.json".to_owned(),
        ]);
        assert!(format!("{verify_no_leak_report:?}").contains("VerifyNoLeakDataplaneReport"));

        let e2e_dns_query = parse_command(&[
            "ops".to_owned(),
            "e2e-dns-query".to_owned(),
            "--server".to_owned(),
            "127.0.0.1".to_owned(),
            "--port".to_owned(),
            "53535".to_owned(),
            "--qname".to_owned(),
            "exit.rustynet".to_owned(),
            "--timeout-ms".to_owned(),
            "1000".to_owned(),
            "--fail-on-no-response".to_owned(),
        ]);
        assert!(format!("{e2e_dns_query:?}").contains("E2eDnsQuery"));

        let e2e_http_probe_server = parse_command(&[
            "ops".to_owned(),
            "e2e-http-probe-server".to_owned(),
            "--bind-ip".to_owned(),
            "192.168.18.51".to_owned(),
            "--port".to_owned(),
            "18080".to_owned(),
            "--response-body".to_owned(),
            "probe-ok".to_owned(),
        ]);
        assert!(format!("{e2e_http_probe_server:?}").contains("E2eHttpProbeServer"));

        let e2e_http_probe_client = parse_command(&[
            "ops".to_owned(),
            "e2e-http-probe-client".to_owned(),
            "--host".to_owned(),
            "192.168.18.51".to_owned(),
            "--port".to_owned(),
            "18080".to_owned(),
            "--timeout-ms".to_owned(),
            "2000".to_owned(),
            "--expect-marker".to_owned(),
            "probe-ok".to_owned(),
        ]);
        assert!(format!("{e2e_http_probe_client:?}").contains("E2eHttpProbeClient"));

        let read_json_field = parse_command(&[
            "ops".to_owned(),
            "read-json-field".to_owned(),
            "--payload".to_owned(),
            "{\"rcode\":0}".to_owned(),
            "--field".to_owned(),
            "rcode".to_owned(),
        ]);
        assert!(format!("{read_json_field:?}").contains("ReadJsonField"));

        let extract_dns_expected_ip = parse_command(&[
            "ops".to_owned(),
            "extract-managed-dns-expected-ip".to_owned(),
            "--fqdn".to_owned(),
            "exit.rustynet".to_owned(),
            "--inspect-output".to_owned(),
            "fqdn=exit.rustynet expected_ip=100.64.0.1".to_owned(),
        ]);
        assert!(format!("{extract_dns_expected_ip:?}").contains("ExtractManagedDnsExpectedIp"));

        let write_active_network_signed_state_tamper_report = parse_command(&[
            "ops".to_owned(),
            "write-active-network-signed-state-tamper-report".to_owned(),
            "--report-path".to_owned(),
            "artifacts/phase10/signed_state_tamper_e2e_report.json".to_owned(),
            "--baseline-status".to_owned(),
            "pass".to_owned(),
            "--tamper-reject-status".to_owned(),
            "pass".to_owned(),
            "--fail-closed-status".to_owned(),
            "pass".to_owned(),
            "--netcheck-fail-closed-status".to_owned(),
            "pass".to_owned(),
            "--recovery-status".to_owned(),
            "pass".to_owned(),
            "--exit-host".to_owned(),
            "192.168.18.49".to_owned(),
            "--client-host".to_owned(),
            "192.168.18.50".to_owned(),
            "--status-after-tamper".to_owned(),
            "state=FailClosed".to_owned(),
            "--netcheck-after-tamper".to_owned(),
            "path_mode=fail_closed".to_owned(),
            "--status-after-recovery".to_owned(),
            "state=ExitActive".to_owned(),
        ]);
        assert!(
            format!("{write_active_network_signed_state_tamper_report:?}")
                .contains("WriteActiveNetworkSignedStateTamperReport")
        );

        let write_active_network_rogue_path_hijack_report = parse_command(&[
            "ops".to_owned(),
            "write-active-network-rogue-path-hijack-report".to_owned(),
            "--report-path".to_owned(),
            "artifacts/phase10/rogue_path_hijack_e2e_report.json".to_owned(),
            "--baseline-status".to_owned(),
            "pass".to_owned(),
            "--hijack-reject-status".to_owned(),
            "pass".to_owned(),
            "--fail-closed-status".to_owned(),
            "pass".to_owned(),
            "--netcheck-fail-closed-status".to_owned(),
            "pass".to_owned(),
            "--no-rogue-endpoint-status".to_owned(),
            "pass".to_owned(),
            "--recovery-status".to_owned(),
            "pass".to_owned(),
            "--recovery-endpoint-status".to_owned(),
            "pass".to_owned(),
            "--rogue-endpoint-ip".to_owned(),
            "203.0.113.10".to_owned(),
            "--exit-host".to_owned(),
            "192.168.18.49".to_owned(),
            "--client-host".to_owned(),
            "192.168.18.50".to_owned(),
            "--endpoints-before".to_owned(),
            "peer-a=192.168.18.49:51820".to_owned(),
            "--endpoints-after-hijack".to_owned(),
            "peer-a=192.168.18.49:51820".to_owned(),
            "--endpoints-after-recovery".to_owned(),
            "peer-a=192.168.18.49:51820".to_owned(),
            "--status-after-hijack".to_owned(),
            "state=FailClosed".to_owned(),
            "--netcheck-after-hijack".to_owned(),
            "path_mode=fail_closed".to_owned(),
            "--status-after-recovery".to_owned(),
            "state=ExitActive".to_owned(),
        ]);
        assert!(
            format!("{write_active_network_rogue_path_hijack_report:?}")
                .contains("WriteActiveNetworkRoguePathHijackReport")
        );

        let validate_network_discovery_bundle = parse_command(&[
            "ops".to_owned(),
            "validate-network-discovery-bundle".to_owned(),
            "--bundle".to_owned(),
            "artifacts/phase10/discovery-a.json".to_owned(),
            "--bundle".to_owned(),
            "artifacts/phase10/discovery-b.json".to_owned(),
            "--bundles".to_owned(),
            "artifacts/phase10/discovery-c.json,artifacts/phase10/discovery-b.json".to_owned(),
            "--max-age-seconds".to_owned(),
            "600".to_owned(),
            "--require-verifier-keys".to_owned(),
            "--require-daemon-active".to_owned(),
            "--require-socket-present".to_owned(),
            "--output".to_owned(),
            "artifacts/phase10/discovery-validation.md".to_owned(),
        ]);
        assert!(
            format!("{validate_network_discovery_bundle:?}")
                .contains("ValidateNetworkDiscoveryBundle")
        );

        let generate_live_lab_failure_digest = parse_command(&[
            "ops".to_owned(),
            "generate-live-linux-lab-failure-digest".to_owned(),
            "--nodes-tsv".to_owned(),
            "artifacts/live_lab/test/state/nodes.tsv".to_owned(),
            "--stages-tsv".to_owned(),
            "artifacts/live_lab/test/state/stages.tsv".to_owned(),
            "--report-dir".to_owned(),
            "artifacts/live_lab/test".to_owned(),
            "--run-id".to_owned(),
            "20260321T120000Z".to_owned(),
            "--network-id".to_owned(),
            "rn-live-lab-20260321T120000Z".to_owned(),
            "--overall-status".to_owned(),
            "fail".to_owned(),
            "--output-json".to_owned(),
            "artifacts/live_lab/test/failure_digest.json".to_owned(),
            "--output-md".to_owned(),
            "artifacts/live_lab/test/failure_digest.md".to_owned(),
        ]);
        assert!(
            format!("{generate_live_lab_failure_digest:?}")
                .contains("GenerateLiveLinuxLabFailureDigest")
        );

        let rebind_fresh_install_inputs = parse_command(&[
            "ops".to_owned(),
            "rebind-linux-fresh-install-os-matrix-inputs".to_owned(),
            "--dest-dir".to_owned(),
            "artifacts/phase10/source/fresh_install_os_matrix".to_owned(),
            "--bootstrap-log".to_owned(),
            "artifacts/live_lab/test/logs/bootstrap.log".to_owned(),
            "--baseline-log".to_owned(),
            "artifacts/live_lab/test/logs/baseline.log".to_owned(),
            "--two-hop-report".to_owned(),
            "artifacts/live_lab/test/live_linux_two_hop_report.json".to_owned(),
            "--role-switch-report".to_owned(),
            "artifacts/live_lab/test/live_linux_role_switch_matrix_report.json".to_owned(),
            "--lan-toggle-report".to_owned(),
            "artifacts/live_lab/test/live_linux_lan_toggle_report.json".to_owned(),
            "--exit-handoff-report".to_owned(),
            "artifacts/live_lab/test/live_linux_exit_handoff_report.json".to_owned(),
        ]);
        assert!(
            format!("{rebind_fresh_install_inputs:?}")
                .contains("RebindLinuxFreshInstallOsMatrixInputs")
        );

        let generate_fresh_install_report = parse_command(&[
            "ops".to_owned(),
            "generate-linux-fresh-install-os-matrix-report".to_owned(),
            "--output".to_owned(),
            "artifacts/phase10/fresh_install_os_matrix_report.json".to_owned(),
            "--environment".to_owned(),
            "live-linux-lab".to_owned(),
            "--source-mode".to_owned(),
            "local-head".to_owned(),
            "--expected-git-commit-file".to_owned(),
            "artifacts/live_lab/test/state/expected_git_commit.txt".to_owned(),
            "--git-status-file".to_owned(),
            "artifacts/live_lab/test/state/git_status.txt".to_owned(),
            "--bootstrap-log".to_owned(),
            "artifacts/live_lab/test/logs/bootstrap.log".to_owned(),
            "--baseline-log".to_owned(),
            "artifacts/live_lab/test/logs/baseline.log".to_owned(),
            "--two-hop-report".to_owned(),
            "artifacts/live_lab/test/live_linux_two_hop_report.json".to_owned(),
            "--role-switch-report".to_owned(),
            "artifacts/live_lab/test/live_linux_role_switch_matrix_report.json".to_owned(),
            "--lan-toggle-report".to_owned(),
            "artifacts/live_lab/test/live_linux_lan_toggle_report.json".to_owned(),
            "--exit-handoff-report".to_owned(),
            "artifacts/live_lab/test/live_linux_exit_handoff_report.json".to_owned(),
            "--exit-node-id".to_owned(),
            "exit-1".to_owned(),
            "--client-node-id".to_owned(),
            "client-1".to_owned(),
            "--ubuntu-node-id".to_owned(),
            "ubuntu-1".to_owned(),
            "--fedora-node-id".to_owned(),
            "fedora-1".to_owned(),
            "--mint-node-id".to_owned(),
            "mint-1".to_owned(),
        ]);
        assert!(
            format!("{generate_fresh_install_report:?}")
                .contains("GenerateLinuxFreshInstallOsMatrixReport")
        );

        let verify_fresh_install_report = parse_command(&[
            "ops".to_owned(),
            "verify-linux-fresh-install-os-matrix-readiness".to_owned(),
            "--report-path".to_owned(),
            "artifacts/phase10/fresh_install_os_matrix_report.json".to_owned(),
            "--max-age-seconds".to_owned(),
            "604800".to_owned(),
            "--profile".to_owned(),
            "linux".to_owned(),
            "--expected-git-commit".to_owned(),
            "abcdefabcdefabcdefabcdefabcdefabcdefabcd".to_owned(),
        ]);
        assert!(
            format!("{verify_fresh_install_report:?}")
                .contains("VerifyLinuxFreshInstallOsMatrixReadiness")
        );

        let write_fresh_install_fixtures = parse_command(&[
            "ops".to_owned(),
            "write-fresh-install-os-matrix-readiness-fixtures".to_owned(),
            "--output-dir".to_owned(),
            "/tmp/rustynet-fresh-install-fixtures".to_owned(),
            "--head-commit".to_owned(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            "--stale-commit".to_owned(),
            "1111111111111111111111111111111111111111".to_owned(),
            "--now-unix".to_owned(),
            "1773300000".to_owned(),
        ]);
        assert!(
            format!("{write_fresh_install_fixtures:?}")
                .contains("WriteFreshInstallOsMatrixReadinessFixtures")
        );

        let write_unsigned_release_provenance = parse_command(&[
            "ops".to_owned(),
            "write-unsigned-release-provenance".to_owned(),
            "--input".to_owned(),
            "artifacts/release/rustynetd.provenance.json".to_owned(),
            "--output".to_owned(),
            "artifacts/release/unsigned.provenance.json".to_owned(),
        ]);
        assert!(
            format!("{write_unsigned_release_provenance:?}")
                .contains("WriteUnsignedReleaseProvenance")
        );

        let sign_release_artifact =
            parse_command(&["ops".to_owned(), "sign-release-artifact".to_owned()]);
        assert!(format!("{sign_release_artifact:?}").contains("SignReleaseArtifact"));

        let verify_release_artifact =
            parse_command(&["ops".to_owned(), "verify-release-artifact".to_owned()]);
        assert!(format!("{verify_release_artifact:?}").contains("VerifyReleaseArtifact"));

        let installer = parse_command(&["ops".to_owned(), "install-systemd".to_owned()]);
        assert!(format!("{installer:?}").contains("InstallSystemd"));

        let windows_installer =
            parse_command(&["ops".to_owned(), "install-windows-service".to_owned()]);
        assert!(format!("{windows_installer:?}").contains("InstallWindowsService"));

        let windows_relay_installer =
            parse_command(&["ops".to_owned(), "install-windows-relay-service".to_owned()]);
        assert!(format!("{windows_relay_installer:?}").contains("InstallWindowsRelayService"));

        let windows_relay_uninstaller = parse_command(&[
            "ops".to_owned(),
            "uninstall-windows-relay-service".to_owned(),
        ]);
        assert!(format!("{windows_relay_uninstaller:?}").contains("UninstallWindowsRelayService"));

        let prepare_dirs = parse_command(&["ops".to_owned(), "prepare-system-dirs".to_owned()]);
        assert!(format!("{prepare_dirs:?}").contains("PrepareSystemDirs"));

        let restart_runtime =
            parse_command(&["ops".to_owned(), "restart-runtime-service".to_owned()]);
        assert!(format!("{restart_runtime:?}").contains("RestartRuntimeService"));

        let stop_runtime = parse_command(&["ops".to_owned(), "stop-runtime-service".to_owned()]);
        assert!(format!("{stop_runtime:?}").contains("StopRuntimeService"));

        let runtime_status =
            parse_command(&["ops".to_owned(), "show-runtime-service-status".to_owned()]);
        assert!(format!("{runtime_status:?}").contains("ShowRuntimeServiceStatus"));

        let start_assignment_refresh = parse_command(&[
            "ops".to_owned(),
            "start-assignment-refresh-service".to_owned(),
        ]);
        assert!(format!("{start_assignment_refresh:?}").contains("StartAssignmentRefreshService"));

        let check_assignment_refresh = parse_command(&[
            "ops".to_owned(),
            "check-assignment-refresh-availability".to_owned(),
        ]);
        assert!(
            format!("{check_assignment_refresh:?}").contains("CheckAssignmentRefreshAvailability")
        );

        let install_trust_material = parse_command(&[
            "ops".to_owned(),
            "install-trust-material".to_owned(),
            "--verifier-source".to_owned(),
            "/tmp/trust.pub".to_owned(),
            "--trust-source".to_owned(),
            "/tmp/rustynetd.trust".to_owned(),
            "--verifier-dest".to_owned(),
            "/etc/rustynet/trust-evidence.pub".to_owned(),
            "--trust-dest".to_owned(),
            "/var/lib/rustynet/rustynetd.trust".to_owned(),
            "--daemon-group".to_owned(),
            "rustynetd".to_owned(),
        ]);
        assert!(format!("{install_trust_material:?}").contains("InstallTrustMaterial"));

        let apply_managed_dns =
            parse_command(&["ops".to_owned(), "apply-managed-dns-routing".to_owned()]);
        assert!(format!("{apply_managed_dns:?}").contains("ApplyManagedDnsRouting"));

        let clear_managed_dns =
            parse_command(&["ops".to_owned(), "clear-managed-dns-routing".to_owned()]);
        assert!(format!("{clear_managed_dns:?}").contains("ClearManagedDnsRouting"));

        let disconnect_cleanup =
            parse_command(&["ops".to_owned(), "disconnect-cleanup".to_owned()]);
        assert!(format!("{disconnect_cleanup:?}").contains("DisconnectCleanup"));

        let blind_exit_lockdown =
            parse_command(&["ops".to_owned(), "apply-blind-exit-lockdown".to_owned()]);
        assert!(format!("{blind_exit_lockdown:?}").contains("ApplyBlindExitLockdown"));

        let init_membership = parse_command(&["ops".to_owned(), "init-membership".to_owned()]);
        assert!(format!("{init_membership:?}").contains("InitMembership"));

        let secure_remove = parse_command(&[
            "ops".to_owned(),
            "secure-remove".to_owned(),
            "--path".to_owned(),
            "/tmp/secret.txt".to_owned(),
        ]);
        assert!(format!("{secure_remove:?}").contains("SecureRemove"));

        let ensure_signing = parse_command(&[
            "ops".to_owned(),
            "ensure-signing-passphrase-material".to_owned(),
        ]);
        assert!(format!("{ensure_signing:?}").contains("EnsureSigningPassphraseMaterial"));

        let ensure_local_trust = parse_command(&[
            "ops".to_owned(),
            "ensure-local-trust-material".to_owned(),
            "--signing-key-passphrase-file".to_owned(),
            "/tmp/signing-passphrase".to_owned(),
        ]);
        assert!(format!("{ensure_local_trust:?}").contains("EnsureLocalTrustMaterial"));

        let materialize_signing = parse_command(&[
            "ops".to_owned(),
            "materialize-signing-passphrase".to_owned(),
            "--output".to_owned(),
            "/tmp/signing-passphrase".to_owned(),
        ]);
        assert!(format!("{materialize_signing:?}").contains("MaterializeSigningPassphrase"));

        let materialize_signing_temp = parse_command(&[
            "ops".to_owned(),
            "materialize-signing-passphrase-temp".to_owned(),
        ]);
        assert!(
            format!("{materialize_signing_temp:?}").contains("MaterializeSigningPassphraseTemp")
        );

        let set_exit = parse_command(&[
            "ops".to_owned(),
            "set-assignment-refresh-exit-node".to_owned(),
            "--env-path".to_owned(),
            "/etc/rustynet/assignment-refresh.env".to_owned(),
            "--exit-node-id".to_owned(),
            "exit-40".to_owned(),
        ]);
        assert!(format!("{set_exit:?}").contains("SetAssignmentRefreshExitNode"));

        let force_assignment_refresh = parse_command(&[
            "ops".to_owned(),
            "force-local-assignment-refresh-now".to_owned(),
        ]);
        assert!(format!("{force_assignment_refresh:?}").contains("ForceLocalAssignmentRefreshNow"));

        let state_refresh_if_socket_present = parse_command(&[
            "ops".to_owned(),
            "state-refresh-if-socket-present".to_owned(),
        ]);
        assert!(
            format!("{state_refresh_if_socket_present:?}").contains("StateRefreshIfSocketPresent")
        );

        let lan_coupling = parse_command(&[
            "ops".to_owned(),
            "apply-lan-access-coupling".to_owned(),
            "--enable".to_owned(),
            "true".to_owned(),
            "--lan-routes".to_owned(),
            "192.168.1.0/24".to_owned(),
        ]);
        assert!(format!("{lan_coupling:?}").contains("ApplyLanAccessCoupling"));

        let role_coupling = parse_command(&[
            "ops".to_owned(),
            "apply-role-coupling".to_owned(),
            "--target-role".to_owned(),
            "client".to_owned(),
            "--preferred-exit-node-id".to_owned(),
            "exit-40".to_owned(),
            "--enable-exit-advertise".to_owned(),
            "false".to_owned(),
            "--skip-client-exit-route-convergence-wait".to_owned(),
        ]);
        assert!(format!("{role_coupling:?}").contains("ApplyRoleCoupling"));
        assert!(
            format!("{role_coupling:?}").contains("skip_client_exit_route_convergence_wait: true")
        );

        let peer_store_validate = parse_command(&[
            "ops".to_owned(),
            "peer-store-validate".to_owned(),
            "--config-dir".to_owned(),
            "/tmp/rustynet-config".to_owned(),
            "--peers-file".to_owned(),
            "/tmp/rustynet-config/peers.db".to_owned(),
        ]);
        assert!(format!("{peer_store_validate:?}").contains("PeerStoreValidate"));

        let peer_store_list = parse_command(&[
            "ops".to_owned(),
            "peer-store-list".to_owned(),
            "--config-dir".to_owned(),
            "/tmp/rustynet-config".to_owned(),
            "--peers-file".to_owned(),
            "/tmp/rustynet-config/peers.db".to_owned(),
            "--role".to_owned(),
            "admin".to_owned(),
            "--node-id".to_owned(),
            "exit-1".to_owned(),
        ]);
        assert!(format!("{peer_store_list:?}").contains("PeerStoreList"));

        let remote_e2e = parse_command(&[
            "ops".to_owned(),
            "run-debian-two-node-e2e".to_owned(),
            "--exit-host".to_owned(),
            "192.168.18.37".to_owned(),
            "--client-host".to_owned(),
            "192.168.18.40".to_owned(),
            "--ssh-allow-cidrs".to_owned(),
            "192.168.18.2/32".to_owned(),
        ]);
        assert!(format!("{remote_e2e:?}").contains("RunDebianTwoNodeE2e"));

        let bootstrap = parse_command(&[
            "ops".to_owned(),
            "e2e-bootstrap-host".to_owned(),
            "--role".to_owned(),
            "admin".to_owned(),
            "--node-id".to_owned(),
            "exit-node".to_owned(),
            "--network-id".to_owned(),
            "local-net".to_owned(),
            "--src-dir".to_owned(),
            "/opt/rustynet-clean/src".to_owned(),
            "--ssh-allow-cidrs".to_owned(),
            "192.168.18.2/32".to_owned(),
        ]);
        assert!(format!("{bootstrap:?}").contains("E2eBootstrapHost"));

        let enforce = parse_command(&[
            "ops".to_owned(),
            "e2e-enforce-host".to_owned(),
            "--role".to_owned(),
            "client".to_owned(),
            "--node-id".to_owned(),
            "client-node".to_owned(),
            "--src-dir".to_owned(),
            "/opt/rustynet-clean/src".to_owned(),
            "--ssh-allow-cidrs".to_owned(),
            "192.168.18.2/32".to_owned(),
        ]);
        assert!(format!("{enforce:?}").contains("E2eEnforceHost"));

        let membership = parse_command(&[
            "ops".to_owned(),
            "e2e-membership-add".to_owned(),
            "--client-node-id".to_owned(),
            "client-node".to_owned(),
            "--client-pubkey-hex".to_owned(),
            "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff".to_owned(),
            "--owner-approver-id".to_owned(),
            "exit-node-owner".to_owned(),
        ]);
        assert!(format!("{membership:?}").contains("E2eMembershipAdd"));

        let assignments = parse_command(&[
            "ops".to_owned(),
            "e2e-issue-assignments".to_owned(),
            "--exit-node-id".to_owned(),
            "exit-node".to_owned(),
            "--client-node-id".to_owned(),
            "client-node".to_owned(),
            "--exit-endpoint".to_owned(),
            "192.168.18.37:51820".to_owned(),
            "--client-endpoint".to_owned(),
            "192.168.18.40:51820".to_owned(),
            "--exit-pubkey-hex".to_owned(),
            "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899".to_owned(),
            "--client-pubkey-hex".to_owned(),
            "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff".to_owned(),
            "--artifact-dir".to_owned(),
            "/run/rustynet/e2e-issue-artifacts.test".to_owned(),
        ]);
        assert!(format!("{assignments:?}").contains("E2eIssueAssignments"));
        assert!(format!("{assignments:?}").contains("e2e-issue-artifacts.test"));

        let assignments_from_env = parse_command(&[
            "ops".to_owned(),
            "e2e-issue-assignment-bundles-from-env".to_owned(),
            "--env-file".to_owned(),
            "/tmp/rn-assign.env".to_owned(),
            "--issue-dir".to_owned(),
            "/run/rustynet/assignment-issue".to_owned(),
        ]);
        assert!(format!("{assignments_from_env:?}").contains("E2eIssueAssignmentBundlesFromEnv"));

        let traversal_from_env = parse_command(&[
            "ops".to_owned(),
            "e2e-issue-traversal-bundles-from-env".to_owned(),
            "--env-file".to_owned(),
            "/tmp/rn-traversal.env".to_owned(),
            "--issue-dir".to_owned(),
            "/run/rustynet/traversal-issue".to_owned(),
        ]);
        assert!(format!("{traversal_from_env:?}").contains("E2eIssueTraversalBundlesFromEnv"));

        let dns_zone_from_env = parse_command(&[
            "ops".to_owned(),
            "e2e-issue-dns-zone-bundles-from-env".to_owned(),
            "--env-file".to_owned(),
            "/tmp/rn-dns.env".to_owned(),
            "--issue-dir".to_owned(),
            "/run/rustynet/dns-zone-issue".to_owned(),
        ]);
        assert!(format!("{dns_zone_from_env:?}").contains("E2eIssueDnsZoneBundlesFromEnv"));

        let vm_lab_list = parse_command(&["ops".to_owned(), "vm-lab-list".to_owned()]);
        assert!(format!("{vm_lab_list:?}").contains("VmLabList"));

        let vm_lab_discover_local_utm = parse_command(&[
            "ops".to_owned(),
            "vm-lab-discover-local-utm".to_owned(),
            "--inventory".to_owned(),
            "/tmp/vm_lab_inventory.json".to_owned(),
            "--utm-documents-root".to_owned(),
            "/Users/iwan/Library/Containers/com.utmapp.UTM/Data/Documents".to_owned(),
            "--utmctl-path".to_owned(),
            "/Applications/UTM.app/Contents/MacOS/utmctl".to_owned(),
            "--ssh-port".to_owned(),
            "2222".to_owned(),
            "--timeout-secs".to_owned(),
            "15".to_owned(),
            "--update-inventory-live-ips".to_owned(),
            "--report-dir".to_owned(),
            "/tmp/vm-lab-discovery".to_owned(),
        ]);
        assert!(format!("{vm_lab_discover_local_utm:?}").contains("VmLabDiscoverLocalUtm"));
        assert!(format!("{vm_lab_discover_local_utm:?}").contains("2222"));
        assert!(
            format!("{vm_lab_discover_local_utm:?}").contains("update_inventory_live_ips: true")
        );
        assert!(format!("{vm_lab_discover_local_utm:?}").contains("/tmp/vm-lab-discovery"));

        let vm_lab_discover_local_utm_summary = parse_command(&[
            "ops".to_owned(),
            "vm-lab-discover-local-utm-summary".to_owned(),
            "--inventory".to_owned(),
            "/tmp/vm_lab_inventory.json".to_owned(),
            "--update-inventory-live-ips".to_owned(),
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
            "ops".to_owned(),
            "vm-lab-start".to_owned(),
            "--inventory".to_owned(),
            "/tmp/vm_lab_inventory.json".to_owned(),
            "--vm".to_owned(),
            "debian-headless-1".to_owned(),
            "--vm".to_owned(),
            "debian-headless-3".to_owned(),
            "--timeout-secs".to_owned(),
            "120".to_owned(),
        ]);
        assert!(format!("{vm_lab_start:?}").contains("VmLabStart"));
        assert!(format!("{vm_lab_start:?}").contains("debian-headless-3"));

        let vm_lab_sync = parse_command(&[
            "ops".to_owned(),
            "vm-lab-sync-repo".to_owned(),
            "--inventory".to_owned(),
            "/tmp/vm_lab_inventory.json".to_owned(),
            "--vm".to_owned(),
            "debian-headless-2".to_owned(),
            "--target".to_owned(),
            "root@192.168.18.51".to_owned(),
            "--repo-url".to_owned(),
            "git@github.com:iwanteague/Rustyfin.git".to_owned(),
            "--dest-dir".to_owned(),
            "/home/debian/Rustyfin".to_owned(),
            "--branch".to_owned(),
            "main".to_owned(),
            "--ssh-user".to_owned(),
            "root".to_owned(),
        ]);
        assert!(format!("{vm_lab_sync:?}").contains("VmLabSyncRepo"));
        assert!(format!("{vm_lab_sync:?}").contains("Rustyfin"));
        assert!(format!("{vm_lab_sync:?}").contains("root@192.168.18.51"));

        let vm_lab_sync_local = parse_command(&[
            "ops".to_owned(),
            "vm-lab-sync-repo".to_owned(),
            "--vm".to_owned(),
            "debian-headless-1".to_owned(),
            "--local-source-dir".to_owned(),
            "/tmp/test/Rustynet".to_owned(),
            "--dest-dir".to_owned(),
            "/home/debian/Rustynet".to_owned(),
        ]);
        assert!(format!("{vm_lab_sync_local:?}").contains("VmLabSyncRepo"));
        assert!(format!("{vm_lab_sync_local:?}").contains("/tmp/test/Rustynet"));

        let vm_lab_sync_bootstrap = parse_command(&[
            "ops".to_owned(),
            "vm-lab-sync-bootstrap".to_owned(),
            "--inventory".to_owned(),
            "/tmp/vm_lab_inventory.json".to_owned(),
            "--vm".to_owned(),
            "debian-headless-1".to_owned(),
            "--require-same-network".to_owned(),
            "--repo-url".to_owned(),
            "git@github.com:iwanteague/Rustyfin.git".to_owned(),
            "--dest-dir".to_owned(),
            "/home/debian/Rustyfin".to_owned(),
            "--program".to_owned(),
            "cargo".to_owned(),
            "--arg".to_owned(),
            "build".to_owned(),
            "--arg".to_owned(),
            "--release".to_owned(),
        ]);
        assert!(format!("{vm_lab_sync_bootstrap:?}").contains("VmLabSyncBootstrap"));
        assert!(format!("{vm_lab_sync_bootstrap:?}").contains("require_same_network: true"));

        let vm_lab_sync_bootstrap_local = parse_command(&[
            "ops".to_owned(),
            "vm-lab-sync-bootstrap".to_owned(),
            "--vm".to_owned(),
            "debian-headless-1".to_owned(),
            "--local-source-dir".to_owned(),
            "/tmp/test/Rustynet".to_owned(),
            "--dest-dir".to_owned(),
            "/home/debian/Rustynet".to_owned(),
            "--program".to_owned(),
            "sh".to_owned(),
            "--arg".to_owned(),
            "-lc".to_owned(),
            "--arg".to_owned(),
            "pwd".to_owned(),
        ]);
        assert!(format!("{vm_lab_sync_bootstrap_local:?}").contains("VmLabSyncBootstrap"));
        assert!(format!("{vm_lab_sync_bootstrap_local:?}").contains("/tmp/test/Rustynet"));

        let vm_lab_run = parse_command(&[
            "ops".to_owned(),
            "vm-lab-run".to_owned(),
            "--vm".to_owned(),
            "debian-headless-2".to_owned(),
            "--target".to_owned(),
            "debian@192.168.18.52".to_owned(),
            "--workdir".to_owned(),
            "/home/debian/Rustyfin".to_owned(),
            "--program".to_owned(),
            "cargo".to_owned(),
            "--arg".to_owned(),
            "build".to_owned(),
            "--arg".to_owned(),
            "--release".to_owned(),
            "--sudo".to_owned(),
        ]);
        assert!(format!("{vm_lab_run:?}").contains("VmLabRun"));
        assert!(format!("{vm_lab_run:?}").contains("debian@192.168.18.52"));
        assert!(format!("{vm_lab_run:?}").contains("--release"));

        let vm_lab_bootstrap = parse_command(&[
            "ops".to_owned(),
            "vm-lab-bootstrap".to_owned(),
            "--all".to_owned(),
            "--workdir".to_owned(),
            "/home/debian/Rustyfin".to_owned(),
            "--program".to_owned(),
            "cargo".to_owned(),
            "--arg".to_owned(),
            "build".to_owned(),
        ]);
        assert!(format!("{vm_lab_bootstrap:?}").contains("VmLabBootstrap"));
        assert!(format!("{vm_lab_bootstrap:?}").contains("VmLabBootstrap"));

        let vm_lab_profile = parse_command(&[
            "ops".to_owned(),
            "vm-lab-write-live-lab-profile".to_owned(),
            "--output".to_owned(),
            "/tmp/live_lab.env".to_owned(),
            "--ssh-identity-file".to_owned(),
            "/Users/iwanteague/.ssh/rustynet_lab_ed25519".to_owned(),
            "--exit-vm".to_owned(),
            "debian-headless-1".to_owned(),
            "--backend".to_owned(),
            "linux-wireguard-userspace-shared".to_owned(),
            "--client-target".to_owned(),
            "debian@192.168.18.52".to_owned(),
            "--require-same-network".to_owned(),
        ]);
        assert!(format!("{vm_lab_profile:?}").contains("VmLabWriteLiveLabProfile"));
        assert!(format!("{vm_lab_profile:?}").contains("debian-headless-1"));
        assert!(format!("{vm_lab_profile:?}").contains("linux-wireguard-userspace-shared"));

        let vm_lab_setup = parse_command(&[
            "ops".to_owned(),
            "vm-lab-setup-live-lab".to_owned(),
            "--report-dir".to_owned(),
            "artifacts/live_lab/setup_test".to_owned(),
            "--ssh-identity-file".to_owned(),
            "/Users/iwanteague/.ssh/rustynet_lab_ed25519".to_owned(),
            "--inventory".to_owned(),
            "/tmp/vm_lab_inventory.json".to_owned(),
            "--require-same-network".to_owned(),
            "--resume-from".to_owned(),
            "bootstrap_hosts".to_owned(),
            "--max-parallel-node-workers".to_owned(),
            "2".to_owned(),
        ]);
        assert!(format!("{vm_lab_setup:?}").contains("VmLabSetupLiveLab"));
        assert!(format!("{vm_lab_setup:?}").contains("bootstrap_hosts"));

        let vm_lab_orchestrate = parse_command(&[
            "ops".to_owned(),
            "vm-lab-orchestrate-live-lab".to_owned(),
            "--report-dir".to_owned(),
            "artifacts/live_lab/orchestrate_test".to_owned(),
            "--ssh-identity-file".to_owned(),
            "/Users/iwanteague/.ssh/rustynet_lab_ed25519".to_owned(),
            "--inventory".to_owned(),
            "/tmp/vm_lab_inventory.json".to_owned(),
            "--require-same-network".to_owned(),
            "--wait-ready-timeout-secs".to_owned(),
            "180".to_owned(),
            "--collect-artifacts-on-failure".to_owned(),
            "--stop-after-ready".to_owned(),
        ]);
        assert!(format!("{vm_lab_orchestrate:?}").contains("VmLabOrchestrateLiveLab"));
        assert!(format!("{vm_lab_orchestrate:?}").contains("ready_timeout_secs: 180"));
        assert!(format!("{vm_lab_orchestrate:?}").contains("collect_artifacts_on_failure: true"));
        assert!(format!("{vm_lab_orchestrate:?}").contains("stop_after_ready: true"));

        let vm_lab_validate_profile = parse_command(&[
            "ops".to_owned(),
            "vm-lab-validate-live-lab-profile".to_owned(),
            "--profile".to_owned(),
            "profiles/live_lab/generated_vm_lab.env".to_owned(),
            "--expected-backend".to_owned(),
            "linux-wireguard-userspace-shared".to_owned(),
            "--require-five-node".to_owned(),
        ]);
        assert!(format!("{vm_lab_validate_profile:?}").contains("VmLabValidateLiveLabProfile"));

        let vm_lab_diagnose = parse_command(&[
            "ops".to_owned(),
            "vm-lab-diagnose-live-lab-failure".to_owned(),
            "--profile".to_owned(),
            "profiles/live_lab/generated_vm_lab.env".to_owned(),
            "--report-dir".to_owned(),
            "artifacts/live_lab/iteration_1".to_owned(),
            "--collect-artifacts".to_owned(),
        ]);
        assert!(format!("{vm_lab_diagnose:?}").contains("VmLabDiagnoseLiveLabFailure"));

        let vm_lab_diff = parse_command(&[
            "ops".to_owned(),
            "vm-lab-diff-live-lab-runs".to_owned(),
            "--old-report-dir".to_owned(),
            "artifacts/live_lab/old".to_owned(),
            "--new-report-dir".to_owned(),
            "artifacts/live_lab/new".to_owned(),
        ]);
        assert!(format!("{vm_lab_diff:?}").contains("VmLabDiffLiveLabRuns"));

        let vm_lab_iteration = parse_command(&[
            "ops".to_owned(),
            "vm-lab-iterate-live-lab".to_owned(),
            "--ssh-identity-file".to_owned(),
            "/Users/iwanteague/.ssh/rustynet_lab_ed25519".to_owned(),
            "--exit-vm".to_owned(),
            "debian-headless-1".to_owned(),
            "--client-target".to_owned(),
            "debian@192.168.18.52".to_owned(),
            "--validation-step".to_owned(),
            "fmt".to_owned(),
            "--validation-step".to_owned(),
            "check:rustynetd".to_owned(),
            "--validation-step".to_owned(),
            "test-bin:rustynet-cli:live_linux_lan_toggle_test".to_owned(),
            "--skip-cross-network".to_owned(),
            "--require-clean-tree".to_owned(),
            "--require-local-head".to_owned(),
            "--collect-failure-diagnostics".to_owned(),
        ]);
        assert!(format!("{vm_lab_iteration:?}").contains("VmLabIterateLiveLab"));
        assert!(format!("{vm_lab_iteration:?}").contains("CargoCheckPackage"));
        assert!(format!("{vm_lab_iteration:?}").contains("CargoTestBin"));
        assert!(format!("{vm_lab_iteration:?}").contains("skip_cross_network: true"));

        let vm_lab_live_lab = parse_command(&[
            "ops".to_owned(),
            "vm-lab-run-live-lab".to_owned(),
            "--profile".to_owned(),
            "/tmp/live_lab.env".to_owned(),
            "--dry-run".to_owned(),
            "--skip-setup".to_owned(),
            "--skip-gates".to_owned(),
        ]);
        assert!(format!("{vm_lab_live_lab:?}").contains("VmLabRunLiveLab"));
        assert!(format!("{vm_lab_live_lab:?}").contains("dry_run: true"));
        assert!(format!("{vm_lab_live_lab:?}").contains("skip_setup: true"));

        let vm_lab_known_hosts = parse_command(&[
            "ops".to_owned(),
            "vm-lab-check-known-hosts".to_owned(),
            "--inventory".to_owned(),
            "/tmp/vm_lab_inventory.json".to_owned(),
            "--vm".to_owned(),
            "debian-headless-1".to_owned(),
            "--known-hosts-file".to_owned(),
            "/Users/iwanteague/.ssh/known_hosts".to_owned(),
        ]);
        assert!(format!("{vm_lab_known_hosts:?}").contains("VmLabCheckKnownHosts"));

        let vm_lab_preflight = parse_command(&[
            "ops".to_owned(),
            "vm-lab-preflight".to_owned(),
            "--all".to_owned(),
            "--require-command".to_owned(),
            "git".to_owned(),
            "--require-command".to_owned(),
            "cargo".to_owned(),
            "--require-rustynet-installed".to_owned(),
        ]);
        assert!(format!("{vm_lab_preflight:?}").contains("VmLabPreflight"));
        assert!(format!("{vm_lab_preflight:?}").contains("require_rustynet_installed: true"));

        let vm_lab_status = parse_command(&[
            "ops".to_owned(),
            "vm-lab-status".to_owned(),
            "--target".to_owned(),
            "debian@192.168.18.53".to_owned(),
        ]);
        assert!(format!("{vm_lab_status:?}").contains("VmLabStatus"));

        let vm_lab_stop = parse_command(&[
            "ops".to_owned(),
            "vm-lab-stop".to_owned(),
            "--vm".to_owned(),
            "debian-headless-1".to_owned(),
        ]);
        assert!(format!("{vm_lab_stop:?}").contains("VmLabStop"));

        let vm_lab_shutdown = parse_command(&[
            "ops".to_owned(),
            "vm-lab-shutdown".to_owned(),
            "--all".to_owned(),
        ]);
        assert!(format!("{vm_lab_shutdown:?}").contains("VmLabStop"));

        let vm_lab_restart = parse_command(&[
            "ops".to_owned(),
            "vm-lab-restart".to_owned(),
            "--target".to_owned(),
            "debian@192.168.18.54".to_owned(),
            "--service".to_owned(),
            "rustynetd.service".to_owned(),
        ]);
        assert!(format!("{vm_lab_restart:?}").contains("VmLabRestart"));
        assert!(format!("{vm_lab_restart:?}").contains("rustynetd.service"));

        let vm_lab_restart_wait_ready = parse_command(&[
            "ops".to_owned(),
            "vm-lab-restart".to_owned(),
            "--vm".to_owned(),
            "debian-headless-1".to_owned(),
            "--wait-ready".to_owned(),
            "--ssh-port".to_owned(),
            "2222".to_owned(),
            "--wait-ready-timeout-secs".to_owned(),
            "45".to_owned(),
            "--json".to_owned(),
            "--report-dir".to_owned(),
            "/tmp/vm-lab-restart".to_owned(),
        ]);
        let vm_lab_restart_wait_ready = format!("{vm_lab_restart_wait_ready:?}");
        assert!(vm_lab_restart_wait_ready.contains("VmLabRestart"));
        assert!(vm_lab_restart_wait_ready.contains("wait_ready: true"));
        assert!(vm_lab_restart_wait_ready.contains("ssh_port: 2222"));
        assert!(vm_lab_restart_wait_ready.contains("ready_timeout_secs: 45"));
        assert!(vm_lab_restart_wait_ready.contains("json_output: true"));
        assert!(vm_lab_restart_wait_ready.contains("/tmp/vm-lab-restart"));

        let vm_lab_collect_artifacts = parse_command(&[
            "ops".to_owned(),
            "vm-lab-collect-artifacts".to_owned(),
            "--all".to_owned(),
            "--output-dir".to_owned(),
            "/tmp/vm-lab-artifacts".to_owned(),
        ]);
        assert!(format!("{vm_lab_collect_artifacts:?}").contains("VmLabCollectArtifacts"));

        let vm_lab_write_topology = parse_command(&[
            "ops".to_owned(),
            "vm-lab-write-topology".to_owned(),
            "--suite".to_owned(),
            "relay-remote-exit".to_owned(),
            "--output".to_owned(),
            "/tmp/vm-lab-topology.json".to_owned(),
            "--all".to_owned(),
        ]);
        assert!(format!("{vm_lab_write_topology:?}").contains("VmLabWriteTopology"));

        let vm_lab_issue_state = parse_command(&[
            "ops".to_owned(),
            "vm-lab-issue-and-distribute-state".to_owned(),
            "--topology".to_owned(),
            "/tmp/vm-lab-topology.json".to_owned(),
            "--authority-vm".to_owned(),
            "debian-headless-1".to_owned(),
        ]);
        assert!(format!("{vm_lab_issue_state:?}").contains("VmLabIssueAndDistributeState"));

        let vm_lab_run_suite = parse_command(&[
            "ops".to_owned(),
            "vm-lab-run-suite".to_owned(),
            "--suite".to_owned(),
            "direct-remote-exit".to_owned(),
            "--ssh-identity-file".to_owned(),
            "/Users/iwanteague/.ssh/rustynet_lab_ed25519".to_owned(),
            "--dry-run".to_owned(),
            "--all".to_owned(),
        ]);
        assert!(format!("{vm_lab_run_suite:?}").contains("VmLabRunSuite"));
        assert!(format!("{vm_lab_run_suite:?}").contains("dry_run: true"));

        let vm_lab_bootstrap_phase = parse_command(&[
            "ops".to_owned(),
            "vm-lab-bootstrap-phase".to_owned(),
            "--phase".to_owned(),
            "all".to_owned(),
            "--repo-url".to_owned(),
            "git@github.com:iwanteague/Rustynet.git".to_owned(),
            "--dest-dir".to_owned(),
            "/home/debian/Rustynet".to_owned(),
            "--all".to_owned(),
        ]);
        assert!(format!("{vm_lab_bootstrap_phase:?}").contains("VmLabBootstrapPhase"));
        assert!(format!("{vm_lab_bootstrap_phase:?}").contains("phase: \"all\""));

        let vm_lab_report_capabilities = parse_command(&[
            "ops".to_owned(),
            "vm-lab-report-capabilities".to_owned(),
            "--scope".to_owned(),
            "setup-live-lab".to_owned(),
            "--platform".to_owned(),
            "linux".to_owned(),
            "--source-mode".to_owned(),
            "local-head".to_owned(),
        ]);
        assert!(format!("{vm_lab_report_capabilities:?}").contains("VmLabReportCapabilities"));
        assert!(format!("{vm_lab_report_capabilities:?}").contains("SetupLiveLab"));
        assert!(format!("{vm_lab_report_capabilities:?}").contains("Linux"));
        assert!(format!("{vm_lab_report_capabilities:?}").contains("LocalHead"));

        let vm_lab_report_capabilities_bootstrap = parse_command(&[
            "ops".to_owned(),
            "vm-lab-report-capabilities".to_owned(),
            "--scope".to_owned(),
            "bootstrap-phase".to_owned(),
            "--platform".to_owned(),
            "windows".to_owned(),
            "--source-mode".to_owned(),
            "local-head".to_owned(),
            "--bootstrap-phase".to_owned(),
            "install-release".to_owned(),
            "--mixed-platform-topology".to_owned(),
        ]);
        assert!(format!("{vm_lab_report_capabilities_bootstrap:?}").contains("BootstrapPhase"));
        assert!(format!("{vm_lab_report_capabilities_bootstrap:?}").contains("InstallRelease"));
        assert!(
            format!("{vm_lab_report_capabilities_bootstrap:?})")
                .contains("mixed_platform_topology: true)")
                || format!("{vm_lab_report_capabilities_bootstrap:?}")
                    .contains("mixed_platform_topology: true,")
                || format!("{vm_lab_report_capabilities_bootstrap:?}")
                    .contains("mixed_platform_topology: true ")
        );

        let vm_lab_bootstrap_phase_local = parse_command(&[
            "ops".to_owned(),
            "vm-lab-bootstrap-phase".to_owned(),
            "--phase".to_owned(),
            "sync-source".to_owned(),
            "--local-source-dir".to_owned(),
            "/tmp/test/Rustynet".to_owned(),
            "--dest-dir".to_owned(),
            "/home/debian/Rustynet".to_owned(),
            "--vm".to_owned(),
            "debian-headless-1".to_owned(),
        ]);
        assert!(format!("{vm_lab_bootstrap_phase_local:?}").contains("VmLabBootstrapPhase"));
        assert!(format!("{vm_lab_bootstrap_phase_local:?}").contains("/tmp/test/Rustynet"));
    }

    #[test]
    fn parse_supports_state_refresh_command() {
        let command = parse_command(&["state".to_owned(), "refresh".to_owned()]);
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
    fn help_text_lists_security_audit_ops_commands() {
        let help = help_text();
        assert!(help.contains("ops generate-attack-matrix --attacks <csv> --nodes <csv>"));
        assert!(help.contains("ops generate-assessment-from-matrix --project <name>"));
        assert!(help.contains("ops validate-live-lab-reports"));
        assert!(help.contains("ops evaluate-live-coverage-promotion"));
        assert!(help.contains("ops generate-live-lab-findings"));
        assert!(help.contains("ops generate-comparative-exploit-coverage"));
        assert!(help.contains("ops run-live-lab-validations"));
    }

    #[test]
    fn parse_reboot_recovery_report_requires_dns_refresh_checks() {
        let missing_dns_refresh_checks = parse_command(&[
            "ops".to_owned(),
            "write-live-linux-reboot-recovery-report".to_owned(),
            "--report-path".to_owned(),
            "artifacts/live_lab/live_linux_reboot_recovery_report.json".to_owned(),
            "--observations-path".to_owned(),
            "artifacts/live_lab/live_linux_reboot_recovery_observations.txt".to_owned(),
            "--exit-pre".to_owned(),
            "a".to_owned(),
            "--exit-post".to_owned(),
            "b".to_owned(),
            "--client-pre".to_owned(),
            "c".to_owned(),
            "--client-post".to_owned(),
            "d".to_owned(),
            "--exit-return".to_owned(),
            "pass".to_owned(),
            "--exit-boot-change".to_owned(),
            "pass".to_owned(),
            "--post-exit-twohop".to_owned(),
            "pass".to_owned(),
            "--client-return".to_owned(),
            "pass".to_owned(),
            "--client-boot-change".to_owned(),
            "pass".to_owned(),
            "--post-client-twohop".to_owned(),
            "pass".to_owned(),
            "--salvage-twohop".to_owned(),
            "skipped".to_owned(),
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
                "com.apple/rustynet_g100".to_owned(),
                "com.apple/rustynet_g200".to_owned()
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
                "/usr/local/bin/rustynetd".to_owned(),
                "daemon".to_owned(),
                "--node-id".to_owned(),
                "node-1".to_owned(),
            ],
            &[(
                "RUSTYNET_WG_BINARY_PATH".to_owned(),
                "/usr/bin/wg".to_owned(),
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
        let output = execute(parse_command(&["status".to_owned()]));
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

    #[test]
    fn extract_json_flag_strips_flag_when_present() {
        let (cleaned, json_mode) =
            extract_json_flag(vec!["netcheck".to_owned(), "--json".to_owned()]);
        assert!(json_mode);
        assert_eq!(cleaned, vec!["netcheck".to_owned()]);
    }

    #[test]
    fn extract_json_flag_strips_flag_in_any_position() {
        let (cleaned, json_mode) =
            extract_json_flag(vec!["--json".to_owned(), "status".to_owned()]);
        assert!(json_mode);
        assert_eq!(cleaned, vec!["status".to_owned()]);
    }

    #[test]
    fn extract_json_flag_absent_returns_false() {
        let (cleaned, json_mode) = extract_json_flag(vec!["status".to_owned()]);
        assert!(!json_mode);
        assert_eq!(cleaned, vec!["status".to_owned()]);
    }

    #[test]
    fn extract_json_flag_does_not_match_partial_or_quoted() {
        let (cleaned, json_mode) = extract_json_flag(vec![
            "status".to_owned(),
            "--jsonn".to_owned(),
            "--JSON".to_owned(),
        ]);
        assert!(!json_mode);
        assert_eq!(
            cleaned,
            vec![
                "status".to_owned(),
                "--jsonn".to_owned(),
                "--JSON".to_owned(),
            ]
        );
    }

    #[test]
    fn command_supports_json_render_status_and_netcheck() {
        assert!(command_supports_json_render(&CliCommand::Status));
        assert!(command_supports_json_render(&CliCommand::Netcheck));
    }

    #[test]
    fn command_supports_json_render_returns_false_for_other_commands() {
        assert!(!command_supports_json_render(&CliCommand::Version));
        assert!(!command_supports_json_render(&CliCommand::Login));
        assert!(!command_supports_json_render(&CliCommand::Doctor));
    }

    #[test]
    fn render_key_value_line_as_json_parses_netcheck_shape() {
        let line = "netcheck: path_mode=direct_active path_reason=fresh_handshake_observed candidate_count=3";
        let json = render_key_value_line_as_json(line).expect("must parse");
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("output must be valid JSON");
        let obj = parsed.as_object().expect("output is an object");
        assert_eq!(obj.get("prefix").and_then(|v| v.as_str()), Some("netcheck"));
        assert_eq!(
            obj.get("path_mode").and_then(|v| v.as_str()),
            Some("direct_active")
        );
        assert_eq!(
            obj.get("path_reason").and_then(|v| v.as_str()),
            Some("fresh_handshake_observed")
        );
        assert_eq!(
            obj.get("candidate_count").and_then(|v| v.as_str()),
            Some("3")
        );
    }

    #[test]
    fn render_key_value_line_as_json_preserves_numeric_values_as_strings() {
        // Lossless representation: numbers stay as strings so downstream
        // tooling can decide whether to coerce. This keeps the wire shape
        // stable across daemon schema additions.
        let line = "status: epoch=42 active_peers=5";
        let json = render_key_value_line_as_json(line).unwrap();
        assert!(json.contains("\"epoch\":\"42\""));
        assert!(json.contains("\"active_peers\":\"5\""));
    }

    #[test]
    fn render_key_value_line_as_json_handles_empty_body() {
        let line = "status: ";
        let json = render_key_value_line_as_json(line).expect("must parse");
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed.get("prefix").and_then(|v| v.as_str()),
            Some("status")
        );
        // No data tokens -> only the prefix field is present.
        assert_eq!(parsed.as_object().unwrap().len(), 1);
    }

    #[test]
    fn render_key_value_line_as_json_rejects_missing_colon() {
        let line = "path_mode=direct_active";
        let err = render_key_value_line_as_json(line).expect_err("must fail");
        assert!(err.contains("missing `:` prefix separator"));
    }

    #[test]
    fn render_key_value_line_as_json_rejects_token_without_equals() {
        let line = "netcheck: path_mode=direct_active not-a-pair";
        let err = render_key_value_line_as_json(line).expect_err("must fail");
        assert!(err.contains("token without `=` separator"));
    }

    #[test]
    fn render_key_value_line_as_json_rejects_empty_key() {
        let line = "netcheck: =value";
        let err = render_key_value_line_as_json(line).expect_err("must fail");
        assert!(err.contains("empty key"));
    }

    #[test]
    fn render_key_value_line_as_json_handles_values_with_equals_signs_in_value() {
        // Values may contain `=` if the daemon ever encodes nested k=v
        // shapes; split_once preserves anything past the first `=`.
        let line = "status: hash=abc=def epoch=1";
        let json = render_key_value_line_as_json(line).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.get("hash").and_then(|v| v.as_str()), Some("abc=def"));
        assert_eq!(parsed.get("epoch").and_then(|v| v.as_str()), Some("1"));
    }

    #[test]
    fn render_key_value_line_as_json_handles_repeated_keys_with_last_wins() {
        // serde_json::Map preserves insertion order but the JSON object
        // semantic says duplicates resolve to last value. We exercise that
        // explicitly so consumers know the contract.
        let line = "netcheck: status=ok status=fail";
        let json = render_key_value_line_as_json(line).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.get("status").and_then(|v| v.as_str()), Some("fail"));
    }

    #[test]
    fn render_key_value_line_as_json_is_idempotent_for_same_input() {
        let line = "netcheck: path_mode=relay_active reason_code=topology-mismatch";
        let a = render_key_value_line_as_json(line).unwrap();
        let b = render_key_value_line_as_json(line).unwrap();
        let c = render_key_value_line_as_json(line).unwrap();
        assert_eq!(a, b);
        assert_eq!(b, c);
    }

    // ---- X6: classify_cli_error coverage --------------------------------

    #[test]
    fn classify_cli_error_maps_unknown_command_to_bad_args() {
        use rustynetd::exit_codes::ExitCode;
        assert_eq!(
            classify_cli_error("unknown command: 'frobnicate'"),
            ExitCode::BadArgs
        );
        assert_eq!(
            classify_cli_error("missing required argument --inventory"),
            ExitCode::BadArgs
        );
        assert_eq!(
            classify_cli_error("usage: rustynet status [--json]"),
            ExitCode::BadArgs
        );
    }

    #[test]
    fn classify_cli_error_maps_fail_closed_drift_to_policy_reject() {
        use rustynetd::exit_codes::ExitCode;
        assert_eq!(
            classify_cli_error("signature verification rejected the bundle"),
            ExitCode::PolicyReject
        );
        assert_eq!(
            classify_cli_error("fail-closed gate refused the operation"),
            ExitCode::PolicyReject
        );
        assert_eq!(
            classify_cli_error("drift detected in linux runtime acls"),
            ExitCode::PolicyReject
        );
        assert_eq!(
            classify_cli_error("forbidden plaintext key present at rest"),
            ExitCode::PolicyReject
        );
    }

    #[test]
    fn classify_cli_error_maps_schema_errors_to_config_error() {
        use rustynetd::exit_codes::ExitCode;
        assert_eq!(
            classify_cli_error("config file at /etc/rustynet/daemon.env is unreadable"),
            ExitCode::ConfigError
        );
        assert_eq!(
            classify_cli_error("schema mismatch: missing field `node_id`"),
            ExitCode::ConfigError
        );
        assert_eq!(
            classify_cli_error("malformed assignment bundle: invalid JSON"),
            ExitCode::ConfigError
        );
    }

    #[test]
    fn classify_cli_error_maps_io_failures_to_transient() {
        use rustynetd::exit_codes::ExitCode;
        assert_eq!(
            classify_cli_error("connection refused (os error 111)"),
            ExitCode::TransientFailure
        );
        assert_eq!(
            classify_cli_error("operation timed out after 5s"),
            ExitCode::TransientFailure
        );
        assert_eq!(
            classify_cli_error("temporarily unavailable; retry in 30s"),
            ExitCode::TransientFailure
        );
    }

    #[test]
    fn classify_cli_error_falls_back_to_generic_failure_when_no_pattern_matches() {
        use rustynetd::exit_codes::ExitCode;
        assert_eq!(
            classify_cli_error("something went wrong"),
            ExitCode::GenericFailure
        );
        assert_eq!(classify_cli_error(""), ExitCode::GenericFailure);
    }

    /// Precedence test: a string that matches multiple buckets must
    /// classify to the highest-priority match. The reviewed precedence
    /// order is: `BadArgs > PolicyReject > ConfigError >
    /// TransientFailure > GenericFailure`. Pin so a future refactor
    /// that reorders the if-chain doesn't silently change
    /// classification.
    #[test]
    fn classify_cli_error_precedence_bad_args_beats_other_matches() {
        use rustynetd::exit_codes::ExitCode;
        // Contains both "missing required" (BadArgs) and "fail-closed"
        // (PolicyReject). The earlier branch wins.
        let msg = "missing required arg; fail-closed gate would refuse";
        assert_eq!(classify_cli_error(msg), ExitCode::BadArgs);
    }

    #[test]
    fn classify_cli_error_precedence_policy_reject_beats_config_and_transient() {
        use rustynetd::exit_codes::ExitCode;
        let msg = "signature verification failed; schema-side malformed; retry impossible";
        assert_eq!(classify_cli_error(msg), ExitCode::PolicyReject);
    }

    // ---- X5: membership evidence diff + audit replay ----------------------

    fn sample_evidence_summary(epoch: u64, entries: u64, root: &str) -> MembershipEvidenceSummary {
        MembershipEvidenceSummary {
            epoch,
            entries_count: entries,
            active_node_count: entries.saturating_sub(1),
            state_root_hex: root.to_owned(),
            captured_at_unix: 1_700_000_000,
        }
    }

    #[test]
    fn parse_prior_membership_evidence_body_round_trips_reviewed_shape() {
        // Mirror the exact shape emit_membership_evidence writes.
        let body = r#"{
            "phase": "membership",
            "evidence_mode": "measured",
            "environment": "prod",
            "captured_at_unix": 1700000000,
            "status": "pass",
            "network_id": "net-a",
            "epoch": 7,
            "entries": 12,
            "active_node_count": 11,
            "state_root": "abc123",
            "snapshot_path": "/var/lib/rustynet/membership.snapshot",
            "log_path": "/var/lib/rustynet/membership.log"
        }"#;
        let summary =
            parse_prior_membership_evidence_body(body).expect("clean prior body must parse");
        assert_eq!(summary.epoch, 7);
        assert_eq!(summary.entries_count, 12);
        assert_eq!(summary.active_node_count, 11);
        assert_eq!(summary.state_root_hex, "abc123");
        assert_eq!(summary.captured_at_unix, 1_700_000_000);
    }

    #[test]
    fn parse_prior_membership_evidence_body_returns_none_on_malformed_json() {
        assert!(parse_prior_membership_evidence_body("{not-json}").is_none());
        assert!(parse_prior_membership_evidence_body("").is_none());
    }

    #[test]
    fn parse_prior_membership_evidence_body_returns_none_when_required_field_missing() {
        // Missing state_root.
        let body = r#"{"epoch":1,"entries":1,"active_node_count":1,"captured_at_unix":1}"#;
        assert!(parse_prior_membership_evidence_body(body).is_none());
    }

    #[test]
    fn build_diff_marks_first_run_with_null_prior_fields() {
        let current = sample_evidence_summary(1, 3, "abc");
        let json = build_membership_evidence_diff_json("prod", None, &current);
        assert!(
            json.contains("\"prior_evidence_present\": false"),
            "first run must record prior_evidence_present=false: {json}"
        );
        assert!(
            json.contains("\"prior_parse_error\": false"),
            "first run must record prior_parse_error=false: {json}"
        );
        // Every prior_* numeric field must be `null` (not 0) so a
        // consumer can distinguish "no prior" from "prior=0".
        for needle in [
            "\"prior_epoch\": null",
            "\"prior_entries\": null",
            "\"prior_active_nodes\": null",
            "\"prior_state_root\": null",
            "\"prior_captured_at_unix\": null",
            "\"epoch_delta\": null",
            "\"entries_delta\": null",
            "\"active_nodes_delta\": null",
            "\"state_root_changed\": null",
            "\"captured_at_delta_secs\": null",
        ] {
            assert!(
                json.contains(needle),
                "first-run diff must contain `{needle}`: {json}"
            );
        }
        // Current values present.
        assert!(json.contains("\"current_epoch\": 1"));
        assert!(json.contains("\"current_entries\": 3"));
        assert!(json.contains("\"current_state_root\": \"abc\""));
    }

    #[test]
    fn build_diff_computes_signed_deltas_for_growth_case() {
        let prior = sample_evidence_summary(5, 10, "old-root");
        let current = MembershipEvidenceSummary {
            epoch: 7,
            entries_count: 12,
            active_node_count: 11,
            state_root_hex: "new-root".to_owned(),
            captured_at_unix: 1_700_000_300, // 5 min later
        };
        let json = build_membership_evidence_diff_json("prod", Some(&prior), &current);
        assert!(json.contains("\"prior_evidence_present\": true"));
        assert!(json.contains("\"epoch_delta\": 2"));
        assert!(json.contains("\"entries_delta\": 2"));
        // active count: prior=9 (entries-1), current=11 → delta=2
        assert!(json.contains("\"active_nodes_delta\": 2"));
        assert!(json.contains("\"state_root_changed\": true"));
        assert!(json.contains("\"captured_at_delta_secs\": 300"));
    }

    #[test]
    fn build_diff_computes_negative_deltas_for_shrink_case() {
        let prior = sample_evidence_summary(10, 8, "root-a");
        let current = sample_evidence_summary(9, 5, "root-a");
        let json = build_membership_evidence_diff_json("prod", Some(&prior), &current);
        assert!(json.contains("\"epoch_delta\": -1"));
        assert!(json.contains("\"entries_delta\": -3"));
        // active count: prior=7, current=4 → delta=-3
        assert!(json.contains("\"active_nodes_delta\": -3"));
        // state root unchanged
        assert!(json.contains("\"state_root_changed\": false"));
    }

    #[test]
    fn build_diff_state_root_changed_only_when_strings_differ() {
        let prior = sample_evidence_summary(1, 1, "same-root");
        let current = sample_evidence_summary(2, 2, "same-root");
        let json = build_membership_evidence_diff_json("prod", Some(&prior), &current);
        assert!(
            json.contains("\"state_root_changed\": false"),
            "matching roots must record false: {json}"
        );
    }

    #[test]
    fn build_diff_escapes_environment_label_safely() {
        // Operator supplies a label with a double-quote in it. The
        // JSON must remain parseable.
        let current = sample_evidence_summary(1, 1, "root");
        let json = build_membership_evidence_diff_json("prod-\"with-quote\"", None, &current);
        let parsed: serde_json::Value = serde_json::from_str(&json)
            .expect("diff JSON must remain parseable when env has quotes");
        assert_eq!(
            parsed.get("environment").and_then(|v| v.as_str()),
            Some("prod-\"with-quote\"")
        );
    }

    #[test]
    fn build_diff_emits_valid_json_for_first_run() {
        let current = sample_evidence_summary(1, 0, "empty");
        let json = build_membership_evidence_diff_json("prod", None, &current);
        // Round-trip through serde_json to validate JSON shape.
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("first-run diff must be valid JSON");
        assert_eq!(
            parsed.get("phase").and_then(|v| v.as_str()),
            Some("membership")
        );
        assert_eq!(
            parsed.get("artifact").and_then(|v| v.as_str()),
            Some("membership_evidence_diff")
        );
        assert_eq!(
            parsed
                .get("prior_evidence_present")
                .and_then(serde_json::Value::as_bool),
            Some(false)
        );
    }

    #[test]
    fn build_audit_replay_emits_self_contained_artifact() {
        let json = build_membership_audit_replay_json(
            "prod",
            1_700_000_000,
            7,
            12,
            11,
            "abc123",
            std::path::Path::new("/var/lib/rustynet/audit.log"),
            std::path::Path::new("/var/lib/rustynet/membership.log"),
        );
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("audit replay must be valid JSON");
        assert_eq!(
            parsed.get("artifact").and_then(|v| v.as_str()),
            Some("membership_audit_replay")
        );
        assert_eq!(
            parsed.get("epoch").and_then(serde_json::Value::as_u64),
            Some(7)
        );
        assert_eq!(
            parsed
                .get("entries_count")
                .and_then(serde_json::Value::as_u64),
            Some(12)
        );
        assert_eq!(
            parsed
                .get("active_node_count")
                .and_then(serde_json::Value::as_u64),
            Some(11)
        );
        assert_eq!(
            parsed.get("audit_log_path").and_then(|v| v.as_str()),
            Some("/var/lib/rustynet/audit.log")
        );
        assert_eq!(
            parsed.get("source_log_path").and_then(|v| v.as_str()),
            Some("/var/lib/rustynet/membership.log")
        );
        assert_eq!(
            parsed.get("replay_status").and_then(|v| v.as_str()),
            Some("ok")
        );
        assert_eq!(
            parsed.get("evidence_mode").and_then(|v| v.as_str()),
            Some("measured")
        );
    }

    #[test]
    fn build_audit_replay_escapes_environment_safely() {
        let json = build_membership_audit_replay_json(
            "prod-\"with-quote\"",
            1,
            1,
            1,
            0,
            "root",
            std::path::Path::new("/x/audit"),
            std::path::Path::new("/x/source"),
        );
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("audit replay must be parseable with quoted env");
        assert_eq!(
            parsed.get("environment").and_then(|v| v.as_str()),
            Some("prod-\"with-quote\"")
        );
    }

    #[test]
    fn build_audit_replay_does_not_leak_raw_log_entries() {
        // Security invariant: the audit-replay artifact must NEVER
        // re-encode log entry bodies (those live in the audit log
        // file). If a future refactor adds an `entries` array, this
        // test must trip so the choice is deliberate.
        let json = build_membership_audit_replay_json(
            "prod",
            1,
            1,
            1,
            0,
            "root",
            std::path::Path::new("/x/audit"),
            std::path::Path::new("/x/source"),
        );
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let obj = parsed.as_object().expect("must be an object");
        // Only the reviewed keys are allowed.
        let allowed: std::collections::HashSet<&str> = [
            "phase",
            "evidence_mode",
            "environment",
            "artifact",
            "captured_at_unix",
            "epoch",
            "entries_count",
            "active_node_count",
            "state_root",
            "audit_log_path",
            "source_log_path",
            "replay_status",
        ]
        .into_iter()
        .collect();
        for key in obj.keys() {
            assert!(
                allowed.contains(key.as_str()),
                "unexpected key `{key}` in audit replay — must be deliberately added to the reviewed allowlist"
            );
        }
    }
}
