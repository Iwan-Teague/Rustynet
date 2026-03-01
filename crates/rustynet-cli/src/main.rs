#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use rustynet_control::membership::{
    MembershipApprover, MembershipApproverRole, MembershipApproverStatus, MembershipNode,
    MembershipNodeStatus, MembershipOperation, MembershipReplayCache, MembershipUpdateRecord,
    SignedMembershipUpdate, append_membership_log_entry, apply_signed_update, decode_signed_update,
    decode_update_record, encode_signed_update, encode_update_record, load_membership_log,
    load_membership_snapshot, persist_membership_snapshot, replay_membership_snapshot_and_log,
    sign_update_record, write_membership_audit_log,
};
use rustynetd::daemon::{
    DEFAULT_MEMBERSHIP_LOG_PATH, DEFAULT_MEMBERSHIP_SNAPSHOT_PATH, DEFAULT_SOCKET_PATH,
};
use rustynetd::ipc::{IpcCommand, IpcResponse};

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
    Membership(Box<MembershipCommand>),
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
        [cmd, rest @ ..] if cmd == "membership" => match parse_membership_command(rest) {
            Ok(command) => CliCommand::Membership(Box::new(command)),
            Err(_) => CliCommand::Help,
        },
        _ => CliCommand::Help,
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
        CliCommand::Membership(command) => execute_membership(*command),
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
            output_path,
            merge_from,
        } => {
            let record_payload = fs::read_to_string(&record_path)
                .map_err(|err| format!("read record failed: {err}"))?;
            let record = decode_update_record(&record_payload).map_err(|err| err.to_string())?;
            let signing_key = load_signing_key(&signing_key_path)?;
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
    } else {
        fs::remove_file(&tampered_path).ok();
        return Err("membership log does not contain expected entry markers".to_string());
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

fn load_signing_key(path: &Path) -> Result<SigningKey, String> {
    let content = fs::read_to_string(path).map_err(|err| format!("read key failed: {err}"))?;
    let key_line = content
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
        .ok_or_else(|| "signing key file is empty".to_string())?;
    let bytes = decode_hex_to_32(key_line)?;
    Ok(SigningKey::from_bytes(&bytes))
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

fn split_csv(value: String) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(ToString::to_string)
        .collect()
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
        CliCommand::Login | CliCommand::Help | CliCommand::Membership(_) => {
            IpcCommand::Unknown("unsupported".to_string())
        }
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
        "  membership status [--snapshot <path>] [--log <path>]",
        "  membership propose-add --node-id <id> --node-pubkey <hex> --owner <owner> --output <path> [--roles <csv>] [--reason <code>] [--policy-context <ctx>] [--expires-in <secs>] [--update-id <id>] [--snapshot <path>] [--log <path>]",
        "  membership propose-remove --node-id <id> --output <path> [--reason <code>] [--expires-in <secs>] [--snapshot <path>] [--log <path>]",
        "  membership propose-revoke --node-id <id> --output <path> [--reason <code>] [--expires-in <secs>] [--snapshot <path>] [--log <path>]",
        "  membership propose-restore --node-id <id> --output <path> [--reason <code>] [--expires-in <secs>] [--snapshot <path>] [--log <path>]",
        "  membership propose-rotate-key --node-id <id> --new-pubkey <hex> --output <path> [--reason <code>] [--expires-in <secs>] [--snapshot <path>] [--log <path>]",
        "  membership propose-set-quorum --threshold <n> --output <path> [--reason <code>] [--expires-in <secs>] [--snapshot <path>] [--log <path>]",
        "  membership propose-rotate-approver --approver-id <id> --approver-pubkey <hex> --role <owner|guardian> --status <active|revoked> --output <path> [--reason <code>] [--expires-in <secs>] [--snapshot <path>] [--log <path>]",
        "  membership sign-update --record <path> --approver-id <id> --signing-key <path> --output <path> [--merge-from <signed-update-path>]",
        "  membership verify-update --signed-update <path> [--snapshot <path>] [--log <path>] [--now <unix>] [--dry-run]",
        "  membership apply-update --signed-update <path> [--snapshot <path>] [--log <path>] [--now <unix>] [--dry-run]",
        "  membership verify-log [--snapshot <path>] [--log <path>] [--audit-output <path>] [--now <unix>]",
        "  membership generate-evidence [--snapshot <path>] [--log <path>] [--output-dir <dir>] [--environment <label>] [--now <unix>]",
    ]
    .join("\n")
}

#[cfg(test)]
mod tests {
    use super::{execute, parse_command};

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
    fn execute_reports_error_when_daemon_is_unreachable() {
        let output = execute(parse_command(&["status".to_string()]));
        assert!(output.is_err());
        let message = output.expect_err("daemon-unreachable path should fail");
        assert!(message.starts_with("daemon unreachable:"));
    }
}
