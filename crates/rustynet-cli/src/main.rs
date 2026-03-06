#![forbid(unsafe_code)]

mod ops_install_systemd;

use std::collections::{HashMap, HashSet};
use std::fs;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};
use nix::unistd::{Gid, Group, Uid, chown};
use rand::{RngCore, rngs::OsRng};
use rustynet_control::membership::{
    MembershipApprover, MembershipApproverRole, MembershipApproverStatus, MembershipNode,
    MembershipNodeStatus, MembershipOperation, MembershipReplayCache, MembershipUpdateRecord,
    SignedMembershipUpdate, append_membership_log_entry, apply_signed_update, decode_signed_update,
    decode_update_record, encode_signed_update, encode_update_record, load_membership_log,
    load_membership_snapshot, persist_membership_snapshot, replay_membership_snapshot_and_log,
    sign_update_record, write_membership_audit_log,
};
use rustynet_control::{AutoTunnelBundleRequest, ControlPlaneCore, NodeMetadata};
use rustynet_crypto::{
    KeyCustodyPermissionPolicy, read_encrypted_key_file, write_encrypted_key_file,
};
use rustynet_policy::{PolicyRule, PolicySet, Protocol, RuleAction};
use rustynetd::daemon::{
    DEFAULT_MEMBERSHIP_LOG_PATH, DEFAULT_MEMBERSHIP_SNAPSHOT_PATH, DEFAULT_SOCKET_PATH,
};
use rustynetd::ipc::{IpcCommand, IpcResponse};
use rustynetd::key_material::{read_passphrase_file_explicit, remove_file_if_present};
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Clone, PartialEq, Eq)]
enum CliCommand {
    Status,
    Login,
    Netcheck,
    ExitNodeSelect(String),
    ExitNodeOff,
    LanAccessOn,
    LanAccessOff,
    DnsInspect,
    RouteAdvertise(String),
    KeyRotate,
    KeyRevoke,
    Assignment(Box<AssignmentCommand>),
    Membership(Box<MembershipCommand>),
    Trust(Box<TrustCommand>),
    Ops(Box<OpsCommand>),
    Help,
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum OpsCommand {
    RefreshTrust,
    RefreshAssignment,
    InstallSystemd,
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
        [cmd, subcmd, node] if cmd == "exit-node" && subcmd == "select" => {
            CliCommand::ExitNodeSelect(node.clone())
        }
        [cmd, subcmd] if cmd == "exit-node" && subcmd == "off" => CliCommand::ExitNodeOff,
        [cmd, subcmd] if cmd == "lan-access" && subcmd == "on" => CliCommand::LanAccessOn,
        [cmd, subcmd] if cmd == "lan-access" && subcmd == "off" => CliCommand::LanAccessOff,
        [cmd, subcmd] if cmd == "dns" && subcmd == "inspect" => CliCommand::DnsInspect,
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
    match args {
        [subcmd] if subcmd == "refresh-trust" => Ok(OpsCommand::RefreshTrust),
        [subcmd] if subcmd == "refresh-assignment" => Ok(OpsCommand::RefreshAssignment),
        [subcmd] if subcmd == "install-systemd" => Ok(OpsCommand::InstallSystemd),
        [subcmd, ..] => Err(format!("unknown ops subcommand: {subcmd}")),
        _ => Err("ops subcommand is required".to_string()),
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
        _ => Err(format!("unknown trust subcommand: {subcommand}")),
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
    }
}

fn execute_ops(command: OpsCommand) -> Result<String, String> {
    match command {
        OpsCommand::RefreshTrust => execute_ops_refresh_trust(),
        OpsCommand::RefreshAssignment => execute_ops_refresh_assignment(),
        OpsCommand::InstallSystemd => ops_install_systemd::execute_ops_install_systemd(),
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

    validate_root_owned_encrypted_signing_file(&trust_signer_key_path, "trust signer key")?;
    validate_root_owned_passphrase_file(
        &trust_signing_key_passphrase_path,
        "trust signer key passphrase file",
    )?;

    let target_dir = trust_evidence_path.parent().ok_or_else(|| {
        format!(
            "trust evidence path has no parent: {}",
            trust_evidence_path.display()
        )
    })?;

    let trust_group_gid = group_gid_or_root(daemon_group.as_str())?;
    let trust_mode = if trust_group_gid == Gid::from_raw(0) {
        0o644
    } else {
        0o640
    };
    ensure_directory_exists(target_dir, 0o750, Uid::from_raw(0), trust_group_gid)?;

    let record_tmp = create_secure_temp_file(target_dir, "rustynetd-trust-record.")?;
    let issue_result = execute_trust(TrustCommand::Issue {
        signing_key_path: trust_signer_key_path,
        signing_key_passphrase_path: trust_signing_key_passphrase_path,
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
        &trust_evidence_path,
        Uid::from_raw(0),
        trust_group_gid,
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
            "target node id contains unsupported characters: {}",
            target_node_id
        ));
    }

    let nodes_spec = env_required_nonempty("RUSTYNET_ASSIGNMENT_NODES", "assignment node map")?;
    let allow_spec = env_required_nonempty("RUSTYNET_ASSIGNMENT_ALLOW", "assignment allow rules")?;
    let exit_node_id = env_optional_string("RUSTYNET_ASSIGNMENT_EXIT_NODE_ID")?;
    if let Some(exit_node_id_value) = exit_node_id.as_deref() {
        if !is_valid_node_id(exit_node_id_value) {
            return Err(format!(
                "exit node id contains unsupported characters: {}",
                exit_node_id_value
            ));
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
            "assignment ttl must be an integer in range 60-86400 seconds: {}",
            ttl_secs
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
    if bundle_path.exists() {
        if let Some(current_expires_at) =
            read_bundle_u64_field_optional(&bundle_path, "expires_at_unix")?
        {
            if current_expires_at > now_unix.saturating_add(min_remaining_secs) {
                let remaining_secs = current_expires_at.saturating_sub(now_unix);
                return Ok(format!(
                    "[assignment-refresh] current assignment expires in {}s; skip refresh.",
                    remaining_secs
                ));
            }
        }
    }

    let bundle_group_gid = group_gid_or_root(daemon_group.as_str())?;

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
            lan_routes: Vec::new(),
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
    let path = PathBuf::from(env_string_or_default(key, default)?);
    if !path.is_absolute() {
        return Err(format!("path must be absolute: {}", path.display()));
    }
    Ok(path)
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

fn group_gid_or_root(group_name: &str) -> Result<Gid, String> {
    match Group::from_name(group_name)
        .map_err(|err| format!("resolve group {group_name} failed: {err}"))?
    {
        Some(group) => Ok(group.gid),
        None => Ok(Gid::from_raw(0)),
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
            "{label} file permissions must be owner-only (0600); found {:03o}",
            mode,
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
            "target node {} is not present in --nodes",
            target_node_id
        ));
    }
    match exit_node_id {
        Some(exit_node_id) if !node_ids.contains(exit_node_id) => {
            return Err(format!(
                "exit node {} is not present in --nodes",
                exit_node_id
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

fn send_command(command: IpcCommand) -> Result<IpcResponse, String> {
    send_command_with_socket(command, daemon_socket_path())
}

fn send_command_with_socket(
    command: IpcCommand,
    socket_path: PathBuf,
) -> Result<IpcResponse, String> {
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
        "  exit-node select <node>",
        "  exit-node off",
        "  lan-access on|off",
        "  dns inspect",
        "  route advertise <cidr>",
        "  key rotate",
        "  key revoke",
        "  assignment issue --target-node-id <id> --nodes <node_specs> --allow <allow_specs> --signing-secret <path> --signing-secret-passphrase-file <path> --output <path> [--verifier-key-output <path>] [--mesh-cidr <cidr>] [--exit-node-id <id>] [--lan-routes <csv>] [--ttl-secs <secs>] [--generated-at <unix>] [--nonce <n>]",
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
        "  ops refresh-trust",
        "  ops refresh-assignment",
        "  ops install-systemd",
    ]
    .join("\n")
}

#[cfg(test)]
mod tests {
    use super::{
        detect_tampered_log, execute, load_signing_key, parse_bool_value, parse_bundle_u64_field,
        parse_command, persist_encrypted_secret_material,
    };

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
    fn parse_supports_key_commands() {
        let rotate = parse_command(&["key".to_string(), "rotate".to_string()]);
        assert!(format!("{rotate:?}").contains("KeyRotate"));

        let revoke = parse_command(&["key".to_string(), "revoke".to_string()]);
        assert!(format!("{revoke:?}").contains("KeyRevoke"));
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

        let assignment = parse_command(&["ops".to_string(), "refresh-assignment".to_string()]);
        assert!(format!("{assignment:?}").contains("RefreshAssignment"));

        let installer = parse_command(&["ops".to_string(), "install-systemd".to_string()]);
        assert!(format!("{installer:?}").contains("InstallSystemd"));
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
}
