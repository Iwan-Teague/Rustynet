#![forbid(unsafe_code)]

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use rustynet_control::membership::{
    MEMBERSHIP_SCHEMA_VERSION, MembershipApprover, MembershipApproverRole,
    MembershipApproverStatus, MembershipNode, MembershipNodeStatus, MembershipOperation,
    MembershipReplayCache, MembershipState, MembershipUpdateRecord, SignedMembershipUpdate,
    append_membership_log_entry, apply_signed_update, load_membership_log,
    load_membership_snapshot, persist_membership_snapshot, replay_membership_snapshot_and_log,
    sign_update_record, write_membership_audit_log,
};
use rustynet_crypto::NodeKeyPair;
use rustynet_policy::{AccessRequest, PolicyRule, PolicySet, Protocol, RuleAction};

fn main() {
    if let Err(err) = run() {
        eprintln!("rustynet-control startup failed: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match args.as_slice() {
        [flag, output_dir] if flag == "--emit-membership-evidence" => {
            emit_membership_evidence(output_dir)
        }
        [] => print_scaffold_ready(),
        _ => Err(help_text()),
    }
}

fn print_scaffold_ready() -> Result<(), String> {
    let policy = PolicySet {
        rules: vec![PolicyRule {
            src: "group:family".to_string(),
            dst: "tag:servers".to_string(),
            protocol: Protocol::Any,
            action: RuleAction::Allow,
        }],
    };

    let decision = policy.evaluate(&AccessRequest {
        src: "group:family".to_string(),
        dst: "tag:servers".to_string(),
        protocol: Protocol::Udp,
    });

    let keypair = NodeKeyPair::from_raw([11; 32], [13; 32]).map_err(|err| err.to_string())?;

    println!(
        "rustynet-control scaffold ready: decision={decision:?}, signing_pubkey_prefix={}",
        keypair.public_key.as_bytes()[0]
    );

    Ok(())
}

fn emit_membership_evidence(output_dir: &str) -> Result<(), String> {
    fs::create_dir_all(output_dir)
        .map_err(|err| format!("create output directory failed: {err}"))?;
    let output_dir_path = Path::new(output_dir);
    let tmp_dir = output_dir_path.join("tmp_membership");
    fs::create_dir_all(&tmp_dir).map_err(|err| format!("create temp directory failed: {err}"))?;

    let snapshot_path = tmp_dir.join("membership.snapshot");
    let log_path = tmp_dir.join("membership.log");
    let audit_path = output_dir_path.join("membership_audit_integrity.log");

    let owner_key = SigningKey::from_bytes(&[1; 32]);
    let guardian_key = SigningKey::from_bytes(&[2; 32]);
    let now = unix_now();

    let state = MembershipState {
        schema_version: MEMBERSHIP_SCHEMA_VERSION,
        network_id: "net-evidence".to_string(),
        epoch: 1,
        nodes: vec![MembershipNode {
            node_id: "daemon-local".to_string(),
            node_pubkey_hex: hex_encode(&[9; 32]),
            owner: "owner@example.local".to_string(),
            status: MembershipNodeStatus::Active,
            roles: vec!["tag:servers".to_string()],
            joined_at_unix: now,
            updated_at_unix: now,
        }],
        approver_set: vec![
            MembershipApprover {
                approver_id: "owner-1".to_string(),
                approver_pubkey_hex: hex_encode(owner_key.verifying_key().as_bytes()),
                role: MembershipApproverRole::Owner,
                status: MembershipApproverStatus::Active,
                created_at_unix: now,
            },
            MembershipApprover {
                approver_id: "guardian-1".to_string(),
                approver_pubkey_hex: hex_encode(guardian_key.verifying_key().as_bytes()),
                role: MembershipApproverRole::Guardian,
                status: MembershipApproverStatus::Active,
                created_at_unix: now,
            },
        ],
        quorum_threshold: 2,
        metadata_hash: None,
    };
    persist_membership_snapshot(&snapshot_path, &state).map_err(|err| err.to_string())?;
    init_secure_log(&log_path)?;

    let mut candidate = state.clone();
    let new_node = MembershipNode {
        node_id: "node-exit".to_string(),
        node_pubkey_hex: hex_encode(&[11; 32]),
        owner: "owner@example.local".to_string(),
        status: MembershipNodeStatus::Active,
        roles: vec!["tag:exit".to_string()],
        joined_at_unix: now,
        updated_at_unix: now,
    };
    candidate.nodes.push(new_node.clone());
    candidate.epoch = state.epoch.saturating_add(1);

    let record = MembershipUpdateRecord {
        network_id: state.network_id.clone(),
        update_id: format!("update-{}", now),
        operation: MembershipOperation::AddNode(new_node),
        target: "node-exit".to_string(),
        prev_state_root: state.state_root_hex().map_err(|err| err.to_string())?,
        new_state_root: candidate.state_root_hex().map_err(|err| err.to_string())?,
        epoch_prev: state.epoch,
        epoch_new: state.epoch.saturating_add(1),
        created_at_unix: now,
        expires_at_unix: now.saturating_add(300),
        reason_code: "membership_evidence".to_string(),
        policy_context: Some("ci".to_string()),
    };
    let signed = SignedMembershipUpdate {
        record: record.clone(),
        approver_signatures: vec![
            sign_update_record(&record, "owner-1", &owner_key).map_err(|err| err.to_string())?,
            sign_update_record(&record, "guardian-1", &guardian_key)
                .map_err(|err| err.to_string())?,
        ],
    };

    append_membership_log_entry(&log_path, &signed).map_err(|err| err.to_string())?;
    let entries = load_membership_log(&log_path).map_err(|err| err.to_string())?;
    write_membership_audit_log(&audit_path, &entries).map_err(|err| err.to_string())?;

    let loaded_snapshot =
        load_membership_snapshot(&snapshot_path).map_err(|err| err.to_string())?;
    let replayed = replay_membership_snapshot_and_log(&loaded_snapshot, &entries, unix_now())
        .map_err(|err| format!("membership replay failed while emitting evidence: {err}"))?;
    let replayed_root = replayed.state_root_hex().map_err(|err| err.to_string())?;

    if !replayed
        .nodes
        .iter()
        .any(|node| node.node_id == "node-exit")
    {
        return Err("conformance failed: expected node-exit in replayed state".to_string());
    }

    let mut replay_cache = MembershipReplayCache::default();
    let under_threshold = SignedMembershipUpdate {
        record: record.clone(),
        approver_signatures: vec![
            sign_update_record(&record, "owner-1", &owner_key).map_err(|err| err.to_string())?,
        ],
    };
    let under_threshold_rejected = apply_signed_update(
        &state,
        &under_threshold,
        now.saturating_add(1),
        &mut replay_cache,
    )
    .is_err();

    let mut replay_cache_tamper = MembershipReplayCache::default();
    let mut tampered = signed.clone();
    tampered.record.target = "node-tampered".to_string();
    let tampered_rejected = apply_signed_update(
        &state,
        &tampered,
        now.saturating_add(1),
        &mut replay_cache_tamper,
    )
    .is_err();

    let mut replay_cache_expired = MembershipReplayCache::default();
    let expired_rejected = apply_signed_update(
        &state,
        &signed,
        signed.record.expires_at_unix.saturating_add(1),
        &mut replay_cache_expired,
    )
    .is_err();

    let tampered_log_path = tmp_dir.join("membership.log.tampered");
    fs::copy(&log_path, &tampered_log_path).map_err(|err| err.to_string())?;
    let mut tampered_body =
        fs::read_to_string(&tampered_log_path).map_err(|err| err.to_string())?;
    tampered_body = tampered_body.replace("entry=0|", "entry=1|");
    fs::write(&tampered_log_path, tampered_body).map_err(|err| err.to_string())?;
    let recovery_detected = load_membership_log(&tampered_log_path).is_err();

    let conformance_report = format!(
        "{{\"status\":\"pass\",\"network_id\":\"{}\",\"epoch\":{},\"entries\":{},\"state_root\":\"{}\"}}\n",
        replayed.network_id,
        replayed.epoch,
        entries.len(),
        replayed_root
    );
    let negative_report = format!(
        "{{\"status\":\"{}\",\"under_threshold_rejected\":{},\"tampered_rejected\":{},\"expired_rejected\":{}}}\n",
        if under_threshold_rejected && tampered_rejected && expired_rejected {
            "pass"
        } else {
            "fail"
        },
        under_threshold_rejected,
        tampered_rejected,
        expired_rejected
    );
    let recovery_report = format!(
        "{{\"status\":\"{}\",\"tampered_log_detected\":{},\"snapshot\":\"{}\",\"log\":\"{}\"}}\n",
        if recovery_detected { "pass" } else { "fail" },
        recovery_detected,
        snapshot_path.display(),
        log_path.display()
    );

    fs::write(
        output_dir_path.join("membership_conformance_report.json"),
        conformance_report,
    )
    .map_err(|err| err.to_string())?;
    fs::write(
        output_dir_path.join("membership_negative_tests_report.json"),
        negative_report,
    )
    .map_err(|err| err.to_string())?;
    fs::write(
        output_dir_path.join("membership_recovery_report.json"),
        recovery_report,
    )
    .map_err(|err| err.to_string())?;

    if !(under_threshold_rejected && tampered_rejected && expired_rejected && recovery_detected) {
        return Err("membership evidence checks failed".to_string());
    }

    Ok(())
}

fn init_secure_log(path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    }
    let mut options = OpenOptions::new();
    options.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|err| err.to_string())?;
    file.write_all(b"version=1\n")
        .map_err(|err| err.to_string())
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn help_text() -> String {
    [
        "rustynet-control usage:",
        "  rustynet-control",
        "  rustynet-control --emit-membership-evidence <output-dir>",
    ]
    .join("\n")
}
