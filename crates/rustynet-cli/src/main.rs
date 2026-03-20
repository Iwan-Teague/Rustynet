#![forbid(unsafe_code)]

mod env_file;
mod ops_e2e;
mod ops_install_systemd;
mod ops_peer_store;
mod ops_phase1;
mod ops_phase9;

use std::collections::{HashMap, HashSet};
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
use rand::{RngCore, rngs::OsRng};
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
    canonicalize_dns_zone_name, parse_dns_zone_verifying_key, parse_signed_dns_zone_bundle_wire,
    verify_signed_dns_zone_bundle as verify_dns_zone_bundle,
};
use rustynet_local_security::{
    validate_owner_only_socket, validate_root_managed_shared_runtime_socket,
};
use rustynet_policy::{PolicyRule, PolicySet, Protocol, RuleAction};
use rustynetd::daemon::{
    DEFAULT_AUTO_TUNNEL_MAX_AGE_SECS, DEFAULT_DNS_RESOLVER_BIND_ADDR, DEFAULT_DNS_ZONE_NAME,
    DEFAULT_MEMBERSHIP_LOG_PATH, DEFAULT_MEMBERSHIP_SNAPSHOT_PATH, DEFAULT_SOCKET_PATH,
    DEFAULT_TRAVERSAL_MAX_AGE_SECS, DEFAULT_WG_ENCRYPTED_PRIVATE_KEY_PATH, DEFAULT_WG_INTERFACE,
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum CliCommand {
    Status,
    Login,
    Netcheck,
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum OpsCommand {
    RefreshTrust,
    RefreshSignedTrust,
    BootstrapTunnelCustody,
    RefreshAssignment,
    CollectPhase1MeasuredInput,
    RunPhase1Baseline,
    CollectPhase9RawEvidence,
    GeneratePhase9Artifacts,
    VerifyPhase9Evidence,
    GeneratePhase10Artifacts,
    VerifyPhase10Provenance,
    VerifyPhase6ParityEvidence,
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
    MaterializeSigningPassphrase {
        output_path: PathBuf,
    },
    SetAssignmentRefreshExitNode {
        env_path: PathBuf,
        exit_node_id: Option<String>,
    },
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
    let parser = OptionParser::parse(&args[1..])?;
    match subcommand {
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
        "verify-phase10-provenance" => {
            if args.len() != 1 {
                return Err("ops verify-phase10-provenance does not accept options".to_string());
            }
            Ok(OpsCommand::VerifyPhase10Provenance)
        }
        "verify-phase6-parity-evidence" => {
            if args.len() != 1 {
                return Err("ops verify-phase6-parity-evidence does not accept options".to_string());
            }
            Ok(OpsCommand::VerifyPhase6ParityEvidence)
        }
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
        "materialize-signing-passphrase" => Ok(OpsCommand::MaterializeSigningPassphrase {
            output_path: parser.required_path("--output")?,
        }),
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
            records_path: parser.required_path("--records-json")?,
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
            OsRng.fill_bytes(secret.as_mut_slice());
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
    ensure_regular_file_no_symlink(&records_path, "dns zone records json")?;
    let records = load_dns_zone_records_json(&records_path)?;
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
            OsRng.fill_bytes(&mut seed);
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
        OpsCommand::RefreshTrust => execute_ops_refresh_trust(),
        OpsCommand::RefreshSignedTrust => execute_ops_refresh_signed_trust(),
        OpsCommand::BootstrapTunnelCustody => execute_ops_bootstrap_wireguard_custody(),
        OpsCommand::RefreshAssignment => execute_ops_refresh_assignment(),
        OpsCommand::CollectPhase1MeasuredInput => {
            ops_phase1::execute_ops_collect_phase1_measured_input()
        }
        OpsCommand::RunPhase1Baseline => ops_phase1::execute_ops_run_phase1_baseline(),
        OpsCommand::CollectPhase9RawEvidence => {
            ops_phase9::execute_ops_collect_phase9_raw_evidence()
        }
        OpsCommand::GeneratePhase9Artifacts => ops_phase9::execute_ops_generate_phase9_artifacts(),
        OpsCommand::VerifyPhase9Evidence => ops_phase9::execute_ops_verify_phase9_evidence(),
        OpsCommand::GeneratePhase10Artifacts => {
            ops_phase9::execute_ops_generate_phase10_artifacts()
        }
        OpsCommand::VerifyPhase10Provenance => ops_phase9::execute_ops_verify_phase10_provenance(),
        OpsCommand::VerifyPhase6ParityEvidence => {
            ops_phase9::execute_ops_verify_phase6_parity_evidence()
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
        OpsCommand::MaterializeSigningPassphrase { output_path } => {
            execute_ops_materialize_signing_passphrase(output_path)
        }
        OpsCommand::SetAssignmentRefreshExitNode {
            env_path,
            exit_node_id,
        } => execute_ops_set_assignment_refresh_exit_node(env_path, exit_node_id),
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
        } => execute_ops_apply_role_coupling(
            target_role,
            preferred_exit_node_id,
            enable_exit_advertise,
            assignment_refresh_env_path,
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
    }
}

fn execute_ops_refresh_trust() -> Result<String, String> {
    require_root_execution()?;

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

    collect_platform_probe_artifact()?;

    for platform in Phase6Platform::all() {
        let raw_path = raw_dir.join(platform.raw_filename());
        let inbox_path = inbox_dir.join(platform.raw_filename());
        if !raw_path.exists() && inbox_path.exists() {
            fs::copy(&inbox_path, &raw_path).map_err(|err| {
                format!(
                    "copy platform probe from inbox failed ({} -> {}): {err}",
                    inbox_path.display(),
                    raw_path.display()
                )
            })?;
        }
        if !raw_path.exists() {
            return Err(format!(
                "missing platform parity probe for {}: expected {} or {}",
                platform.as_str(),
                raw_path.display(),
                inbox_path.display()
            ));
        }
    }

    let report_path = generate_platform_parity_report_artifact()?;
    phase6_validate_platform_parity_report(report_path.as_path())?;
    ops_phase9::write_phase6_parity_evidence_attestation(report_path.as_path())?;
    ops_phase9::execute_ops_verify_phase6_parity_evidence()?;

    Ok("phase6 platform parity bundle generated from probes".to_string())
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
        Phase6Platform::Macos => (
            phase6_command_succeeds("route", &["-n", "get", "default"]),
            phase6_command_succeeds("scutil", &["--dns"]),
            phase6_command_succeeds("pfctl", &["-s", "info"]),
            "route -n get default".to_string(),
            "scutil --dns".to_string(),
            "pfctl -s info".to_string(),
        ),
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

fn phase6_validate_platform_parity_report(report_path: &Path) -> Result<(), String> {
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

    ensure_systemd_resolved_active()?;
    let interface = managed_dns_interface_name_from_env()?;
    run_resolvectl_action(&["revert", interface.as_str()])?;

    Ok(format!(
        "managed DNS routing cleared: interface={interface}"
    ))
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
        if let Ok(metadata) = fs::metadata(candidate.as_path()) {
            if metadata.is_file() && (metadata.mode() & 0o111) != 0 {
                return Ok(candidate);
            }
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
    OsRng.fill_bytes(&mut random_bytes);
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

    let rewritten = rewrite_assignment_refresh_lan_routes(
        existing.as_str(),
        if enable { lan_routes.as_slice() } else { &[] },
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
        let blackhole_routes = if lan_routes.is_empty() {
            previous_lan_routes.as_slice()
        } else {
            lan_routes.as_slice()
        };
        apply_lan_blackhole_routes(blackhole_routes, true)?;
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

fn execute_ops_apply_role_coupling(
    target_role: String,
    preferred_exit_node_id: Option<String>,
    enable_exit_advertise: bool,
    assignment_refresh_env_path: PathBuf,
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

fn force_local_assignment_refresh_now_ops() -> Result<(), String> {
    let bundle_path = env_path_or_default(
        "RUSTYNET_AUTO_TUNNEL_BUNDLE",
        DEFAULT_AUTO_TUNNEL_BUNDLE_PATH,
    )?;
    let watermark_path = env_path_or_default(
        "RUSTYNET_AUTO_TUNNEL_WATERMARK",
        DEFAULT_AUTO_TUNNEL_WATERMARK_PATH,
    )?;
    let socket_path = env_path_or_default("RUSTYNET_SOCKET", DEFAULT_DAEMON_SOCKET_PATH)?;

    remove_file_if_present(bundle_path.as_path())?;
    remove_file_if_present(watermark_path.as_path())?;
    run_systemctl_action("start", "rustynetd-assignment-refresh.service")?;
    run_systemctl_action("restart", "rustynetd.service")?;
    wait_for_socket_path(socket_path.as_path(), Duration::from_secs(20))?;
    Ok(())
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
    OsRng.fill_bytes(&mut random_bytes);
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
        OsRng.fill_bytes(&mut random_bytes);
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
        OsRng.fill_bytes(&mut random_bytes);
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

fn load_dns_zone_records_json(path: &Path) -> Result<Vec<DnsZoneRecordSpec>, String> {
    let contents = fs::read_to_string(path)
        .map_err(|err| format!("read dns zone records json failed: {err}"))?;
    let value: Value = serde_json::from_str(&contents)
        .map_err(|err| format!("parse dns zone records json failed: {err}"))?;
    let Value::Array(entries) = value else {
        return Err("dns zone records json must be an array".to_string());
    };
    if entries.is_empty() {
        return Err("dns zone records json must contain at least one record".to_string());
    }

    let mut records = Vec::with_capacity(entries.len());
    for (index, entry) in entries.into_iter().enumerate() {
        let Value::Object(mut object) = entry else {
            return Err(format!("dns zone record {index} must be a JSON object"));
        };
        let label = match object.remove("label") {
            Some(Value::String(value)) => value,
            _ => return Err(format!("dns zone record {index} missing string label")),
        };
        let target_node_id = match object.remove("target_node_id") {
            Some(Value::String(value)) => value,
            _ => {
                return Err(format!(
                    "dns zone record {index} missing string target_node_id"
                ));
            }
        };
        let ttl_secs = match object.remove("ttl_secs") {
            Some(Value::Number(value)) => value.as_u64().ok_or_else(|| {
                format!("dns zone record {index} ttl_secs must be an unsigned integer")
            })?,
            _ => return Err(format!("dns zone record {index} missing integer ttl_secs")),
        };
        let aliases = match object.remove("aliases") {
            Some(Value::Array(values)) => values
                .into_iter()
                .map(|value| match value {
                    Value::String(alias) => Ok(alias),
                    _ => Err(format!("dns zone record {index} aliases must be strings")),
                })
                .collect::<Result<Vec<_>, _>>()?,
            None => Vec::new(),
            _ => return Err(format!("dns zone record {index} aliases must be an array")),
        };
        if !object.is_empty() {
            return Err(format!(
                "dns zone record {index} contains unsupported fields"
            ));
        }
        records.push(DnsZoneRecordSpec {
            label,
            target_node_id,
            ttl_secs,
            aliases,
        });
    }

    Ok(records)
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
        "  operator menu",
        "  exit-node select <node>",
        "  exit-node off",
        "  lan-access on|off",
        "  dns inspect",
        "  dns zone issue --signing-secret <path> --signing-secret-passphrase-file <path> --subject-node-id <id> --nodes <node_specs> --allow <allow_specs> --records-json <path> --output <path> [--zone-name <name>] [--ttl-secs <secs>] [--generated-at <unix>] [--nonce <n>] [--verifier-key-output <path>]",
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
        "  ops refresh-signed-trust",
        "  ops bootstrap-wireguard-custody",
        "  ops refresh-assignment",
        "  ops collect-phase1-measured-input",
        "  ops run-phase1-baseline",
        "  ops collect-phase9-raw-evidence",
        "  ops generate-phase9-artifacts",
        "  ops verify-phase9-evidence",
        "  ops generate-phase10-artifacts",
        "  ops verify-phase10-provenance",
        "  ops verify-phase6-parity-evidence",
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
        "  ops materialize-signing-passphrase --output <absolute-path>",
        "  ops set-assignment-refresh-exit-node [--env-path <absolute-path>] [--exit-node-id <id>]",
        "  ops apply-lan-access-coupling --enable <true|false> [--lan-routes <cidr[,cidr...]>] [--env-path <absolute-path>]",
        "  ops apply-role-coupling --target-role <admin|client> [--preferred-exit-node-id <id>] [--enable-exit-advertise <true|false>] [--env-path <absolute-path>]",
        "  ops peer-store-validate --config-dir <absolute-path> --peers-file <absolute-path>",
        "  ops peer-store-list --config-dir <absolute-path> --peers-file <absolute-path> [--role <role>] [--node-id <id>]",
        "  ops run-debian-two-node-e2e --exit-host <host|user@host> --client-host <host|user@host> --ssh-allow-cidrs <cidr[,cidr...]> [--ssh-user <user>] [--ssh-sudo <auto|always|never>] [--sudo-password-file <path>] [--ssh-port <port>] [--ssh-identity <path>] [--ssh-known-hosts-file <path>] [--exit-node-id <id>] [--client-node-id <id>] [--network-id <id>] [--remote-root <abs-path>] [--repo-ref <git-ref>] [--skip-apt] [--report-path <path>]",
    ]
    .join("\n")
}

#[cfg(test)]
mod tests {
    use super::{
        contains_ip_rule_lookup_table, detect_tampered_log, execute, is_interface_absent_detail,
        launchd_xml_escape, load_dns_zone_records_json, load_signing_key,
        managed_dns_resolver_server_arg, parse_bool_value, parse_bundle_u64_field, parse_command,
        parse_managed_pf_anchors, parse_wireguard_go_pids_from_ps,
        persist_encrypted_secret_material, phase6_validate_platform_parity_report,
        render_launchd_plist, required_macos_tunnel_keychain_account,
        rewrite_assignment_refresh_exit_node, rewrite_assignment_refresh_lan_routes,
        rewrite_env_key_value, validate_control_socket_security,
    };
    use std::fs;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;

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
            "--records-json".to_string(),
            "/tmp/dns-records.json".to_string(),
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
    fn dns_zone_records_json_rejects_unknown_fields() {
        let base = std::env::temp_dir().join(format!(
            "rustynet-dns-zone-records-{}-{}",
            std::process::id(),
            super::generate_assignment_nonce()
        ));
        fs::create_dir_all(&base).expect("temp dir should exist");
        let path = base.join("records.json");
        fs::write(
            &path,
            r#"[{"label":"app","target_node_id":"node-a","ttl_secs":60,"aliases":["ssh"],"unexpected":true}]"#,
        )
        .expect("records json should be written");
        let err = load_dns_zone_records_json(&path).expect_err("unknown fields must fail");
        assert!(err.contains("unsupported fields"));
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

        let collect_phase9_raw =
            parse_command(&["ops".to_string(), "collect-phase9-raw-evidence".to_string()]);
        assert!(format!("{collect_phase9_raw:?}").contains("CollectPhase9RawEvidence"));

        let generate_phase9 =
            parse_command(&["ops".to_string(), "generate-phase9-artifacts".to_string()]);
        assert!(format!("{generate_phase9:?}").contains("GeneratePhase9Artifacts"));

        let verify_phase9 =
            parse_command(&["ops".to_string(), "verify-phase9-evidence".to_string()]);
        assert!(format!("{verify_phase9:?}").contains("VerifyPhase9Evidence"));

        let generate_phase10 =
            parse_command(&["ops".to_string(), "generate-phase10-artifacts".to_string()]);
        assert!(format!("{generate_phase10:?}").contains("GeneratePhase10Artifacts"));

        let verify_phase10_provenance =
            parse_command(&["ops".to_string(), "verify-phase10-provenance".to_string()]);
        assert!(format!("{verify_phase10_provenance:?}").contains("VerifyPhase10Provenance"));

        let verify_phase6_parity = parse_command(&[
            "ops".to_string(),
            "verify-phase6-parity-evidence".to_string(),
        ]);
        assert!(format!("{verify_phase6_parity:?}").contains("VerifyPhase6ParityEvidence"));

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

        let materialize_signing = parse_command(&[
            "ops".to_string(),
            "materialize-signing-passphrase".to_string(),
            "--output".to_string(),
            "/tmp/signing-passphrase".to_string(),
        ]);
        assert!(format!("{materialize_signing:?}").contains("MaterializeSigningPassphrase"));

        let set_exit = parse_command(&[
            "ops".to_string(),
            "set-assignment-refresh-exit-node".to_string(),
            "--env-path".to_string(),
            "/etc/rustynet/assignment-refresh.env".to_string(),
            "--exit-node-id".to_string(),
            "exit-40".to_string(),
        ]);
        assert!(format!("{set_exit:?}").contains("SetAssignmentRefreshExitNode"));

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
        ]);
        assert!(format!("{role_coupling:?}").contains("ApplyRoleCoupling"));

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
    fn control_socket_validator_accepts_owner_only_socket() {
        use std::os::unix::fs::PermissionsExt;

        let unique = format!(
            "rnc-sock-ok-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let dir = PathBuf::from("/tmp").join(unique);
        std::fs::create_dir_all(&dir).expect("test dir should exist");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .expect("test dir permissions should be strict");
        let socket = dir.join("rustynetd.sock");
        let listener = UnixListener::bind(&socket).expect("socket should bind");
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
            .expect("socket mode should be owner-only");

        let result = validate_control_socket_security(&socket, "daemon socket");
        assert!(result.is_ok(), "owner-only socket should validate");

        drop(listener);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn control_socket_validator_rejects_group_writable_parent_directory() {
        use std::os::unix::fs::PermissionsExt;

        let unique = format!(
            "rnc-sock-parent-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let dir = PathBuf::from("/tmp").join(unique);
        std::fs::create_dir_all(&dir).expect("test dir should exist");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o770))
            .expect("test dir permissions should be set");
        let socket = dir.join("rustynetd.sock");
        let listener = UnixListener::bind(&socket).expect("socket should bind");
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
            .expect("socket mode should be owner-only");

        let err = validate_control_socket_security(&socket, "daemon socket")
            .expect_err("group-writable parent must fail");
        assert!(err.contains("parent directory has insecure permissions"));

        drop(listener);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn control_socket_validator_rejects_symlink_path() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let unique = format!(
            "rnc-sock-link-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let dir = PathBuf::from("/tmp").join(unique);
        std::fs::create_dir_all(&dir).expect("test dir should exist");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .expect("test dir permissions should be strict");
        let socket = dir.join("rustynetd.sock");
        let symlink_path = dir.join("rustynetd.sock.link");
        let listener = UnixListener::bind(&socket).expect("socket should bind");
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
            .expect("socket mode should be owner-only");
        symlink(&socket, &symlink_path).expect("symlink should be created");

        let err = validate_control_socket_security(&symlink_path, "daemon socket")
            .expect_err("symlink socket path must fail");
        assert!(err.contains("must not be a symlink"));

        drop(listener);
        let _ = std::fs::remove_dir_all(dir);
    }
}
