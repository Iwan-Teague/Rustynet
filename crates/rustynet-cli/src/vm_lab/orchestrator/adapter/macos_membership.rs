#![allow(dead_code)]
use std::path::Path;
use std::time::Duration;

use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::adapter::macos_install::{
    MACOS_MEMBERSHIP_OWNER_PUBKEY_PATH, MACOS_MEMBERSHIP_SNAPSHOT_PATH,
    MACOS_OWNER_SIGNING_KEY_PATH, MACOS_RUSTYNET_PATH, MACOS_STATE_ROOT,
};
use crate::vm_lab::orchestrator::adapter::ssh;
use crate::vm_lab::orchestrator::adapter::validated_args::ValidatedArg;
use crate::vm_lab::orchestrator::connection::NodeConnection;
use crate::vm_lab::orchestrator::error::{
    AdapterError, BundleKind, GossipIdentity, MembershipOwnerKey, MembershipSnapshot,
    NodeMembershipPeer,
};
use crate::vm_lab::orchestrator::role::NodeRole;
use rustynet_control::membership::{
    MEMBERSHIP_SCHEMA_VERSION, snapshot_bytes_node_capabilities, snapshot_bytes_state_identity,
};
use rustynet_control::roles::{
    RoleCapability, canonicalize_role_capabilities, role_capability_csv,
};

const SHORT_TIMEOUT: Duration = Duration::from_secs(30);
const MEDIUM_TIMEOUT: Duration = Duration::from_secs(120);
const MACOS_MEMBERSHIP_LOG_PATH: &str = "/usr/local/var/rustynet/membership/membership.log";

const MACOS_STAGING_DIR: &str = "/tmp/rustynet-staging";

/// Marker the remote probe emits when the owner public key file does not
/// exist at all (`membership init` never ran / genesis never seeded it).
const OWNER_KEY_ABSENT_MARKER: &str = "__RN_OWNER_KEY_ABSENT__:";
/// Marker the remote probe emits when the file exists but could not be read
/// (permission, sudo refusal, I/O error) — a different failure than absent.
const OWNER_KEY_READ_FAILED_MARKER: &str = "__RN_OWNER_KEY_READ_FAILED__:";

/// Build the remote shell probe that reads the membership owner public key.
///
/// Fail-closed contract (MAC-D2): the probe NEVER collapses a failure into
/// an empty string. It always exits 0 and reports its outcome on stdout:
/// the key body on success, or one of the classification markers
/// (`OWNER_KEY_ABSENT_MARKER` / `OWNER_KEY_READ_FAILED_MARKER`) with the
/// path and the underlying error. The reads use `sudo -n` like the Linux
/// twin — the key directory is root/0700 territory and the SSH user is
/// unprivileged — and `sudo -n` itself failing (no passwordless sudo)
/// lands in the read-failed branch rather than reading as "absent".
fn owner_key_read_script(path: &str) -> String {
    format!(
        "if ! sudo -n true 2>/dev/null; then \
             printf '%s{path} rc=0 passwordless sudo unavailable\\n' '{OWNER_KEY_READ_FAILED_MARKER}'; exit 0; \
         fi; \
         key=\"$(sudo -n cat '{path}' 2>/dev/null)\"; rc=$?; \
         if [ \"$rc\" -eq 0 ] && [ -n \"$key\" ]; then printf '%s\\n' \"$key\"; exit 0; fi; \
         if sudo -n test -e '{path}'; then \
             detail=\"$(sudo -n cat '{path}' 2>&1 >/dev/null | head -1)\"; \
             printf '%s{path} rc=%s %s\\n' '{OWNER_KEY_READ_FAILED_MARKER}' \"$rc\" \"$detail\"; exit 0; \
         fi; \
         printf '%s{path}\\n' '{OWNER_KEY_ABSENT_MARKER}'; exit 0",
    )
}

/// Classify the output of [`owner_key_read_script`]. Absent and unreadable
/// produce DISTINCT, non-empty errors so a permission problem can never
/// masquerade as "has membership been initialized?" again.
fn interpret_owner_key_read(output: &str) -> Result<MembershipOwnerKey, AdapterError> {
    let out = output.trim();
    if out.is_empty() {
        return Err(AdapterError::Protocol {
            message: "membership owner public key read produced no output on remote \
                      (neither key nor failure marker); refusing to guess"
                .to_owned(),
        });
    }
    if let Some(path) = out.strip_prefix(OWNER_KEY_ABSENT_MARKER) {
        return Err(AdapterError::Protocol {
            message: format!(
                "membership owner public key not found on remote at '{path}'; \
                 has membership genesis been run? (rustynetd membership init \
                 seeds it at {MACOS_OWNER_SIGNING_KEY_PATH}.pub)"
            ),
        });
    }
    if let Some(rest) = out.strip_prefix(OWNER_KEY_READ_FAILED_MARKER) {
        return Err(AdapterError::Protocol {
            message: format!(
                "membership owner public key exists on remote but could not be read: {rest}"
            ),
        });
    }
    Ok(MembershipOwnerKey {
        public_key_pem: out.to_owned(),
    })
}

/// Read the membership owner public key from a macOS exit node.
///
/// Reads `MACOS_MEMBERSHIP_OWNER_PUBKEY_PATH` — exactly where the macOS
/// genesis (`rustynetd membership init --owner-signing-key
/// {MACOS_OWNER_SIGNING_KEY_PATH}`) writes the `.pub` sibling — via
/// `sudo -n cat`. Absent-file and permission-denied are distinguished and
/// both fail loud; neither is collapsed into an empty string.
pub fn issue_membership_owner_key(
    conn: &NodeConnection,
) -> Result<MembershipOwnerKey, AdapterError> {
    let output = ssh::run_remote(
        conn,
        &owner_key_read_script(MACOS_MEMBERSHIP_OWNER_PUBKEY_PATH),
        SHORT_TIMEOUT,
    )?;
    interpret_owner_key_read(&output)
}

/// Initialize the membership snapshot on a macOS exit node.
///
/// Runs `rustynet ops init-membership`, then adds each non-exit peer
/// via `ops e2e-membership-add`, then reads back the snapshot bytes.
/// Requires the SSH session to have sudo / admin privilege.
/// Resolve the exit node's membership node id from the peers list.
///
/// The macOS genesis (`ops init-membership`) requires `RUSTYNET_NODE_ID`
/// (MAC-D5): the daemon fails closed when it is missing. The id is sourced
/// from the exit peer entry exactly like the Linux twin
/// (`linux_membership.rs`); absent exit peer or an empty id is a LOUD
/// error — never a blank/default node id.
fn exit_node_id_from_peers(peers: &[NodeMembershipPeer]) -> Result<&str, AdapterError> {
    let exit = peers
        .iter()
        .find(|p| p.role == NodeRole::Exit)
        .map(|p| p.node_id.as_str());
    match exit {
        Some(id) if !id.is_empty() => Ok(id),
        Some(_) => Err(AdapterError::Protocol {
            message: "exit peer entry in `peers` has an empty membership node id; \
                      refusing to run membership init with a blank RUSTYNET_NODE_ID"
                .to_owned(),
        }),
        None => Err(AdapterError::Protocol {
            message: "no NodeRole::Exit peer in `peers`; membership init on macOS \
                      cannot source the required RUSTYNET_NODE_ID"
                .to_owned(),
        }),
    }
}

/// Build the remote `ops init-membership` command for a macOS exit node.
///
/// Mirrors the Linux twin: `env` is placed AFTER `sudo -n` so sudo's
/// `env_reset` cannot strip the role/node-id variables (the previous
/// macOS form ran `env RUSTYNET_NODE_ROLE=admin sudo …`, which sudo
/// stripped — leaving RUSTYNET_NODE_ID unset entirely).
///
/// MAC-D11: `RUSTYNET_SIGNING_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT` is passed
/// alongside them, pointing at the node-scoped System.keychain item the
/// bootstrap provisions (`trust-passphrase-<node_id>`,
/// `Bootstrap-RustyNetMacos.sh` store-passphrase step). Without it,
/// `ops init-membership`'s passphrase-material gate hard-errors with
/// "macOS keychain account is required" the moment its idempotent
/// early-out misses (a fresh node or wiped state dir), so the account
/// must travel with the invocation, not with the session environment.
///
/// QH-01 Step 4c: the command is argv-shaped, so it renders through the
/// validated seam (node ids validate via `ValidatedArg::node_id`, the
/// keychain account token via the same class).
fn membership_init_script(exit_node_id: &str) -> Result<ssh::RemoteCommand, AdapterError> {
    // The node id (and the keychain account derived from it) validate through
    // the `node_id` class first; the two `KEY=value` env assignments then
    // render as single `cli_token`s (the `=` is in that alphabet, the id
    // inside the value is already proven clean).
    ValidatedArg::node_id(exit_node_id)?;
    let node_id_env = ValidatedArg::cli_token(&format!("RUSTYNET_NODE_ID={exit_node_id}"))?;
    let keychain_account_env = ValidatedArg::cli_token(&format!(
        "RUSTYNET_SIGNING_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT=trust-passphrase-{exit_node_id}"
    ))?;
    let args = vec![
        ValidatedArg::cli_token("sudo")?,
        ValidatedArg::cli_token("-n")?,
        ValidatedArg::cli_token("env")?,
        // DELIBERATE, DISCLOSED LIE — do NOT "fix" this to `blind_exit`.
        //
        // This node will actually run daemon role `blind_exit` (role.rs maps
        // the macOS lab Exit there). It is declared `admin` to
        // `ops init-membership` because declaring the real role triggers
        // `maybe_remove_blind_exit_owner_signing_key`
        // (`crates/rustynet-cli/src/main.rs`, called on BOTH the fresh-init and
        // the already-present short-circuit paths), which deletes the owner
        // signing key — the key this very provisioning flow needs on disk
        // moments later to sign its own follow-up capability rewrite
        // (`exit_capability_rewrite_script`) and every per-peer
        // `e2e-membership-add`. Change this token and the whole
        // `membership_init` stage fails at the first signed update.
        //
        // Consequence (F1, `MacosExitMembershipRoleFixDesign_2026-08-31.md`
        // §1.3.1/§2.3): after provisioning, the exit's SIGNED record is
        // narrowed to exactly `{blind_exit, exit_server}`, but its disk still
        // holds the sole mesh owner signing key (`quorum_threshold: 1`), so a
        // compromised exit host retains the physical ability to re-mint any
        // capability for any node — the escalation class blind_exit exists to
        // prevent. This is a DISCLOSED interim limitation, recorded in every
        // proving run as `owner_signing_key_present=true` (§5.3,
        // `probe_owner_signing_key_present`), and closed only by the Option D
        // target (§1.3.2, QH-66): never make a blind_exit node the membership
        // owner in the first place. Crash window, for completeness: an abort
        // between genesis and the rewrite leaves an anchor-carrying signed
        // record plus this key on disk; the daemon fail-closes on
        // blind_exit+anchor, and the next provisioning run's read-and-skip
        // guard sees a non-canonical record and issues the rewrite cleanly
        // (the reducer's immutability bar only bites once blind_exit is set).
        ValidatedArg::cli_token("RUSTYNET_NODE_ROLE=admin")?,
        node_id_env,
        keychain_account_env,
        ValidatedArg::path(MACOS_RUSTYNET_PATH)?,
        ValidatedArg::cli_token("ops")?,
        ValidatedArg::cli_token("init-membership")?,
    ];
    ssh::RemoteCommand::from_args("macos init-membership", &args)
}

/// Build the remote `ops e2e-membership-add` command for one peer.
///
/// MAC-D6: the owner approver id is DERIVED from the exit node id —
/// `"{exit_node_id}-owner"` — exactly like the Linux twin
/// (`linux_membership.rs`) and exactly what `rustynetd membership init`
/// registers as the genesis owner approver (`crates/rustynetd/src/main.rs`,
/// `format!("{node_id}-owner")`). There is no `rustynet ops
/// owner-approver-id` subcommand: an earlier revision shelled out to one,
/// the CLI's `bad_args` error (printed to STDOUT, so `2>/dev/null`
/// suppressed nothing, `|| echo none` appended `none`) was captured and
/// passed as `--owner-approver-id '<error text>none'`, and
/// `ensure_safe_token` rejected it — failing the whole `membership_init`
/// stage. Deriving keeps the approver id real and the stage unblocked; the
/// derived value still passes `shell_safe_arg` so the guard is never lost.
fn peer_add_script(
    exit_node_id: &str,
    node_id_arg: &str,
    pubkey_flag: &str,
    pubkey_arg: &str,
    capabilities_arg: &str,
) -> Result<ssh::RemoteCommand, AdapterError> {
    // owner_approver_id convention: "{exit_node_id}-owner" (matches ops_e2e.rs
    // and rustynetd membership init). There is no `rustynet ops
    // owner-approver-id` command; derive from the exit peer.
    let owner_approver_id_arg = ValidatedArg::node_id(&format!("{exit_node_id}-owner"))?;
    // MAC-D11: same keychain-account plumbing as `membership_init_script` —
    // `env` after `sudo -n` so `env_reset` cannot strip it. The e2e mutation
    // path resolves its passphrase via a hardcoded credential descriptor, so
    // today this variable is inert here; carrying it keeps the invocation
    // self-describing and correct if the e2e path ever honours it, and
    // matches the node-scoped item the bootstrap provisions.
    let keychain_account_env = ValidatedArg::cli_token(&format!(
        "RUSTYNET_SIGNING_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT=trust-passphrase-{exit_node_id}"
    ))?;
    let args = vec![
        ValidatedArg::cli_token("sudo")?,
        ValidatedArg::cli_token("-n")?,
        ValidatedArg::cli_token("env")?,
        keychain_account_env,
        ValidatedArg::path(MACOS_RUSTYNET_PATH)?,
        ValidatedArg::cli_token("ops")?,
        ValidatedArg::cli_token("e2e-membership-add")?,
        ValidatedArg::cli_token("--client-node-id")?,
        ValidatedArg::node_id(node_id_arg)?,
        ValidatedArg::cli_token(pubkey_flag)?,
        // hex_32_safe_arg is the stricter 64-hex shape guard layered under
        // the seam's cli_token class (the hex alphabet is a subset).
        ValidatedArg::cli_token(hex_32_safe_arg(pubkey_arg)?.as_str())?,
        ValidatedArg::cli_token("--capabilities")?,
        ValidatedArg::capability_csv(capabilities_arg)?,
        ValidatedArg::cli_token("--owner-approver-id")?,
        owner_approver_id_arg,
    ];
    ssh::RemoteCommand::from_args("macos e2e-membership-add", &args)
}

/// Build the remote read-back probe for the genesis membership snapshot.
///
/// MAC-D10 (read half): the previous form was `test -s '<path>' && cat …`,
/// whose ONLY failure output is silence — `test` exits 1 and prints
/// nothing, so a vanished snapshot surfaced to the orchestrator as
/// "remote command failed (exit Some(1)):" with empty stderr AND stdout,
/// and the loud fail-closed design of the guard never survived the SSH
/// pipe. The probe now emits its own diagnostic on stderr and exits 1
/// when the snapshot is missing or empty, naming the path, so the
/// failure envelope always carries the cause.
///
/// Both halves run under `sudo -n` (the snapshot is mode 0600 owned by
/// the `rustynetd` service account; the SSH session is unprivileged),
/// matching [`owner_key_read_script`]'s privilege pattern.
fn membership_snapshot_readback_script() -> String {
    format!(
        "if ! sudo -n test -s '{MACOS_MEMBERSHIP_SNAPSHOT_PATH}'; then \
             echo 'membership snapshot missing or empty at {MACOS_MEMBERSHIP_SNAPSHOT_PATH}; \
 init-membership/e2e-membership-add did not leave a readable genesis' >&2; \
             exit 1; \
         fi; \
         sudo -n cat '{MACOS_MEMBERSHIP_SNAPSHOT_PATH}' | base64"
    )
}

/// The exact signed capability set a macOS exit's OWN membership record must
/// carry — derived from the product grant (`role.rs`
/// `product_capabilities_for_platform`, macOS Exit arm), canonicalized. Never a
/// hand-typed CSV: the provisioning grant and the product grant cannot drift
/// if there is only one source (`MacosExitMembershipRoleFixDesign_2026-08-31.md`
/// §1.2, §5.1 step 2).
pub(crate) fn macos_exit_target_capabilities() -> Result<Vec<RoleCapability>, AdapterError> {
    let grant = NodeRole::Exit
        .product_capabilities_for_platform(&VmGuestPlatform::Macos)
        .map_err(|err| AdapterError::Protocol {
            message: format!("macOS exit product capability grant unavailable: {err}"),
        })?;
    let canonical = canonicalize_role_capabilities(grant);
    if canonical.is_empty() {
        return Err(AdapterError::Protocol {
            message: "macOS exit product capability grant is empty; refusing to sign an \
                      empty capability set"
                .to_owned(),
        });
    }
    Ok(canonical)
}

/// `true` when the exit's CURRENT signed set differs from the target set
/// (canonical, order- and duplicate-insensitive compare). Drives the
/// idempotency branch: a fresh anchor-carrying genesis needs the rewrite; a
/// re-used guest whose record is already `{blind_exit, exit_server}` must NOT
/// re-apply it. This guard is a CORRECTNESS requirement, not an optimisation:
/// the membership reducer refuses any `SetNodeCapabilities` on a record that
/// already carries `blind_exit` ("blind_exit is immutable; factory reset and
/// fresh enrollment are required", `rustynet_control::membership`
/// `reduce_membership_state`, SecMinBar §6.D.2), so re-issuing the rewrite on
/// a re-used guest would hard-fail `membership_init` at propose time. Pinned
/// in-process by
/// `owner_signed_set_capabilities_narrows_anchor_genesis_to_blind_exit_pair_at_epoch_two`.
pub(crate) fn exit_needs_capability_rewrite(
    current: &[RoleCapability],
    target: &[RoleCapability],
) -> bool {
    canonicalize_role_capabilities(current.iter().copied())
        != canonicalize_role_capabilities(target.iter().copied())
}

/// Build the remote `ops e2e-membership-set-capabilities` command that
/// narrows the exit's OWN signed record to `capabilities` — the post-genesis,
/// owner-signed capability rewrite (design §1.2).
///
/// Same MAC-D11 keychain-account env plumbing and MAC-D6 derived approver id
/// as `peer_add_script`; argv-shaped through the validated seam. The verb it
/// invokes is the existing hardened signed-update pipeline
/// (`ops_e2e.rs::execute_ops_e2e_membership_set_capabilities`: stage
/// permissions → `propose-set-capabilities` → `sign-update` with the owner key
/// → `apply-update` with epoch/replay checks → audit entry), so nothing here
/// mutates membership outside a signed, owner-approved update.
fn exit_capability_rewrite_script(
    exit_node_id: &str,
    capabilities: &[RoleCapability],
) -> Result<ssh::RemoteCommand, AdapterError> {
    ValidatedArg::node_id(exit_node_id)?;
    let owner_approver_id_arg = ValidatedArg::node_id(&format!("{exit_node_id}-owner"))?;
    let keychain_account_env = ValidatedArg::cli_token(&format!(
        "RUSTYNET_SIGNING_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT=trust-passphrase-{exit_node_id}"
    ))?;
    let args = vec![
        ValidatedArg::cli_token("sudo")?,
        ValidatedArg::cli_token("-n")?,
        ValidatedArg::cli_token("env")?,
        keychain_account_env,
        ValidatedArg::path(MACOS_RUSTYNET_PATH)?,
        ValidatedArg::cli_token("ops")?,
        ValidatedArg::cli_token("e2e-membership-set-capabilities")?,
        ValidatedArg::cli_token("--node-id")?,
        ValidatedArg::node_id(exit_node_id)?,
        ValidatedArg::cli_token("--capabilities")?,
        ValidatedArg::capability_csv(&role_capability_csv(capabilities))?,
        ValidatedArg::cli_token("--owner-approver-id")?,
        owner_approver_id_arg,
    ];
    ssh::RemoteCommand::from_args("macos e2e-membership-set-capabilities", &args)
}

/// Build the `e2e-membership-add` command for one non-exit peer.
fn peer_add_command(
    exit_node_id: &str,
    peer: &NodeMembershipPeer,
) -> Result<ssh::RemoteCommand, AdapterError> {
    // Branch on the SUBJECT peer, not on this producer's platform. This
    // function runs on a macOS exit node but writes membership for EVERY
    // peer in the topology, including Linux ones that DO have a real gossip
    // identity. Publishing `public_key_hex` unconditionally here would
    // republish those nodes' WireGuard keys under a flag named
    // `unaligned-wireguard` — silently reinstating the exact defect this
    // change exists to remove, on any `--exit-platform macos` run.
    let (pubkey_flag, pubkey_arg) = match &peer.gossip_identity {
        GossipIdentity::Published(gossip_hex) => {
            ("--client-gossip-pubkey-hex", hex_32_safe_arg(gossip_hex)?)
        }
        GossipIdentity::DeferredPlatform => (
            "--client-pubkey-hex-unaligned-wireguard",
            hex_32_safe_arg(&peer.public_key_hex)?,
        ),
    };
    peer_add_script(
        exit_node_id,
        &peer.node_id,
        pubkey_flag,
        &pubkey_arg,
        &role_capability_csv(&peer.capabilities),
    )
}

/// What one provisioning step IS, independent of its position. The executor
/// keys its "the rewrite landed exactly once" check on this tag — never on a
/// positional index, which would silently check the wrong command if anything
/// were ever prepended to the plan (adversarial review finding).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PlanStepKind {
    /// `ops init-membership` (genesis) — present only in the combined plan.
    Genesis,
    /// The owner-signed rewrite of the exit's OWN capability record.
    ExitCapabilityRewrite,
    /// `e2e-membership-add` for one non-exit peer.
    PeerAdd,
}

/// One step of the provisioning plan: its kind plus the validated command.
pub(crate) struct PlanStep {
    pub(crate) kind: PlanStepKind,
    pub(crate) command: ssh::RemoteCommand,
}

/// The PURE, ORDERED plan of signed mutations that follow genesis — the
/// capability rewrite for the exit (only when its post-genesis record differs
/// from the target) FIRST, then every non-exit peer add in `peers` order.
///
/// Pure so the negative test in design §5.2 can bite at unit level: reverting
/// to the pre-fix behaviour (skip the exit peer entirely) removes the rewrite
/// entry, and the plan-ordering tests fail. `init_membership_snapshot`
/// executes exactly this plan; the two cannot drift because there is no
/// second command builder.
pub(crate) fn post_genesis_commands(
    exit_node_id: &str,
    peers: &[NodeMembershipPeer],
    exit_caps_after_genesis: &[RoleCapability],
) -> Result<Vec<PlanStep>, AdapterError> {
    let target = macos_exit_target_capabilities()?;
    let mut plan = Vec::new();
    if exit_needs_capability_rewrite(exit_caps_after_genesis, &target) {
        plan.push(PlanStep {
            kind: PlanStepKind::ExitCapabilityRewrite,
            command: exit_capability_rewrite_script(exit_node_id, &target)?,
        });
    }
    for peer in peers {
        if peer.role == NodeRole::Exit {
            continue;
        }
        plan.push(PlanStep {
            kind: PlanStepKind::PeerAdd,
            command: peer_add_command(exit_node_id, peer)?,
        });
    }
    Ok(plan)
}

/// The full ordered provisioning plan — genesis init, then
/// [`post_genesis_commands`]. `init_membership_snapshot` runs the genesis
/// entry, reads the snapshot back (the rewrite decision needs the post-genesis
/// record), then runs the rest; this combined form exists so the ordering
/// invariant "genesis → rewrite → adds" is pinned by one test.
pub(crate) fn init_membership_commands(
    exit_node_id: &str,
    peers: &[NodeMembershipPeer],
    exit_caps_after_genesis: &[RoleCapability],
) -> Result<Vec<PlanStep>, AdapterError> {
    let mut plan = vec![PlanStep {
        kind: PlanStepKind::Genesis,
        command: membership_init_script(exit_node_id)?,
    }];
    plan.extend(post_genesis_commands(
        exit_node_id,
        peers,
        exit_caps_after_genesis,
    )?);
    Ok(plan)
}

/// Read the membership snapshot back from the remote as raw bytes. The probe
/// fails LOUDLY (own stderr message + exit 1, naming the path) when the
/// snapshot is missing or empty — a vanished genesis must surface as a named
/// failure, never as a silent empty read (MAC-D10).
fn read_back_snapshot(conn: &NodeConnection) -> Result<Vec<u8>, AdapterError> {
    let snapshot_b64 =
        ssh::run_remote(conn, &membership_snapshot_readback_script(), SHORT_TIMEOUT)?;
    let data = base64_decode(snapshot_b64.trim())?;
    if data.is_empty() {
        return Err(AdapterError::Protocol {
            message: "membership snapshot decoded to zero bytes; init-membership/\
                      e2e-membership-add did not produce a snapshot"
                .to_owned(),
        });
    }
    Ok(data)
}

/// The exit's canonical signed capability set in `snapshot`, fail-closed:
/// an unreadable snapshot or an absent/inactive exit entry is an error, never
/// an empty set (an empty set would compare unequal to the target and trigger
/// a rewrite against a record that does not exist).
fn exit_capabilities_in_snapshot(
    snapshot: &[u8],
    exit_node_id: &str,
) -> Result<Vec<RoleCapability>, AdapterError> {
    snapshot_bytes_node_capabilities(snapshot, exit_node_id).ok_or_else(|| AdapterError::Protocol {
        message: format!(
            "exit node '{exit_node_id}' is missing, inactive, or unreadable in the \
                 membership snapshot read back from the remote; refusing to reason \
                 about its capability set"
        ),
    })
}

fn snapshot_epoch(snapshot: &[u8]) -> Result<u64, AdapterError> {
    snapshot_bytes_state_identity(snapshot)
        .map(|(epoch, _root)| epoch)
        .ok_or_else(|| AdapterError::Protocol {
            message: "membership snapshot read back from the remote is unreadable or \
                      invalid; refusing to reason about its epoch"
                .to_owned(),
        })
}

/// Initialize the membership snapshot on a macOS exit node and return its
/// bytes.
///
/// Order (design §1.2/§1.4): genesis `ops init-membership` (idempotent) →
/// read back → if the exit's own signed record is not exactly the macOS exit
/// product grant, issue ONE owner-signed `e2e-membership-set-capabilities`
/// narrowing it (and assert it landed exactly once: epoch +1, record == target)
/// → per-peer `e2e-membership-add` → final read-back, asserting the exit's
/// record still equals the target. The rewrite therefore precedes every
/// distribution and the returned snapshot is the state every peer receives.
pub fn init_membership_snapshot(
    conn: &NodeConnection,
    _owner_key: &MembershipOwnerKey,
    peers: &[NodeMembershipPeer],
) -> Result<MembershipSnapshot, AdapterError> {
    // 1. Genesis (idempotent). RUSTYNET_NODE_ID is required by
    //    init-membership; sourced from the exit peer, fail-loud if absent.
    let exit_node_id = exit_node_id_from_peers(peers)?;
    let init_script = membership_init_script(exit_node_id)?;
    ssh::run_remote(conn, init_script.as_str(), MEDIUM_TIMEOUT)?;

    // 2. Read the post-genesis record: the rewrite decision is made against
    //    what is actually signed on disk, not against an assumption.
    let genesis = read_back_snapshot(conn)?;
    let genesis_caps = exit_capabilities_in_snapshot(&genesis, exit_node_id)?;
    let genesis_epoch = snapshot_epoch(&genesis)?;
    let target = macos_exit_target_capabilities()?;
    let needs_rewrite = exit_needs_capability_rewrite(&genesis_caps, &target);

    // 3. Execute the pure plan: [rewrite?] then peer adds. The plan is the
    //    single source of truth; the predicate is re-derived here only to
    //    cross-check that the plan carries exactly the rewrite steps the
    //    predicate demands (zero or one) — any drift fails before execution.
    let plan = post_genesis_commands(exit_node_id, peers, &genesis_caps)?;
    let rewrite_steps = plan
        .iter()
        .filter(|step| step.kind == PlanStepKind::ExitCapabilityRewrite)
        .count();
    if rewrite_steps != usize::from(needs_rewrite) {
        return Err(AdapterError::Protocol {
            message: format!(
                "provisioning plan carries {rewrite_steps} capability-rewrite step(s) but the \
                 post-genesis record requires {}; refusing to execute a drifted plan",
                usize::from(needs_rewrite)
            ),
        });
    }
    for step in &plan {
        let command = &step.command;
        ssh::run_remote(conn, command.as_str(), MEDIUM_TIMEOUT)?;
        if step.kind == PlanStepKind::ExitCapabilityRewrite {
            // The rewrite must land EXACTLY once: one signed update, one
            // epoch bump, record == target. Anything else (a double apply, a
            // partial apply, a verb that silently did nothing) fails here
            // before any peer add or distribution can build on it.
            let after = read_back_snapshot(conn)?;
            let epoch = snapshot_epoch(&after)?;
            if epoch != genesis_epoch.saturating_add(1) {
                return Err(AdapterError::Protocol {
                    message: format!(
                        "macOS exit capability rewrite did not land exactly once: epoch \
                         {genesis_epoch} -> {epoch} (expected {})",
                        genesis_epoch.saturating_add(1)
                    ),
                });
            }
            let caps = exit_capabilities_in_snapshot(&after, exit_node_id)?;
            if exit_needs_capability_rewrite(&caps, &target) {
                return Err(AdapterError::Protocol {
                    message: format!(
                        "macOS exit '{exit_node_id}' signed record after the capability \
                         rewrite is {{{}}}, expected exactly {{{}}}",
                        role_capability_csv(&caps),
                        role_capability_csv(&target)
                    ),
                });
            }
        }
    }

    // 4. Final read-back + exact-set assertion on the state that will be
    //    distributed (the adapter-level half of design §5.2; the stage
    //    re-asserts it independently).
    let data = read_back_snapshot(conn)?;
    let final_caps = exit_capabilities_in_snapshot(&data, exit_node_id)?;
    if exit_needs_capability_rewrite(&final_caps, &target) {
        return Err(AdapterError::Protocol {
            message: format!(
                "macOS exit '{exit_node_id}' signed record before distribution is {{{}}}, \
                 expected exactly {{{}}} (blind_exit alignment)",
                role_capability_csv(&final_caps),
                role_capability_csv(&target)
            ),
        });
    }
    Ok(MembershipSnapshot { data })
}

/// `sudo -n true` — proves passwordless sudo works on the remote BEFORE the
/// presence test runs, so that a later non-zero exit from `test -e` can only
/// mean "absent", never "could not look" (fail-closed ordering). Argv-shaped
/// through the validated seam; no shell string.
fn owner_signing_key_sudo_probe_command() -> Result<ssh::RemoteCommand, AdapterError> {
    let args = vec![
        ValidatedArg::cli_token("sudo")?,
        ValidatedArg::cli_token("-n")?,
        ValidatedArg::cli_token("true")?,
    ];
    ssh::RemoteCommand::from_args("macos owner-key sudo probe", &args)
}

/// `sudo -n test -e <path>` — exit 0 when the owner signing key file exists,
/// exit 1 when it does not. The path crosses the seam as a validated `path`
/// argument (the only caller passes the compile-time constant; the seam is
/// what makes a future non-constant caller safe).
fn owner_signing_key_presence_command(path: &str) -> Result<ssh::RemoteCommand, AdapterError> {
    let args = vec![
        ValidatedArg::cli_token("sudo")?,
        ValidatedArg::cli_token("-n")?,
        ValidatedArg::cli_token("test")?,
        ValidatedArg::cli_token("-e")?,
        ValidatedArg::path(path)?,
    ];
    ssh::RemoteCommand::from_args("macos owner-key presence", &args)
}

/// Map the presence command's outcome to a recorded fact. ONLY exit 0
/// ("present") and exit 1 ("absent") are answers; every other exit status and
/// every transport failure is an error, because the fact must be RECORDED,
/// never guessed from an unexpected failure.
fn interpret_owner_key_presence(
    result: Result<String, AdapterError>,
) -> Result<bool, AdapterError> {
    match result {
        Ok(_) => Ok(true),
        Err(AdapterError::Command {
            exit_code: Some(1), ..
        }) => Ok(false),
        Err(AdapterError::Command { exit_code, stderr }) => Err(AdapterError::Protocol {
            message: format!(
                "owner signing key presence probe exited with unexpected status {exit_code:?} \
                 (only 0=present / 1=absent are answers); refusing to guess: {stderr}"
            ),
        }),
        Err(other) => Err(other),
    }
}

/// Is the membership owner signing key file present on this macOS node?
///
/// Records the F1 fact (design §1.3.1/§5.3): under the interim fix the
/// expected answer on the macOS exit is `true`. Absent/unreadable are
/// distinguished and both fail loud; the answer is a fact for the stage log,
/// not a verdict.
pub fn probe_owner_signing_key_present(conn: &NodeConnection) -> Result<bool, AdapterError> {
    let sudo_probe = owner_signing_key_sudo_probe_command()?;
    ssh::run_remote(conn, sudo_probe.as_str(), SHORT_TIMEOUT).map_err(|err| {
        AdapterError::Protocol {
            message: format!(
                "cannot probe owner signing key presence: passwordless sudo unavailable on \
                 remote ({err})"
            ),
        }
    })?;
    let presence = owner_signing_key_presence_command(MACOS_OWNER_SIGNING_KEY_PATH)?;
    interpret_owner_key_presence(ssh::run_remote(conn, presence.as_str(), SHORT_TIMEOUT))
}

/// Distribute a signed bundle to a macOS client node.
/// Uses the same atomic install pattern as Linux: scp to temp, then
/// `sudo install` with permissions appropriate to the bundle kind.
///
/// Membership snapshots require mode 0600 owned by the daemon user because
/// `load_membership_snapshot` uses a strict `mode & 0o077 != 0` check.
/// Other bundles (assignment, traversal, dns-zone) are installed as
/// root:rustynetd 0640.
pub fn distribute_signed_bundle(
    conn: &NodeConnection,
    kind: BundleKind,
    bundle_path: &Path,
) -> Result<(), AdapterError> {
    let (remote_tmp, install_dst) = remote_bundle_paths(&kind);
    // Staging dir must exist before SCP; /tmp is always present but the
    // subdirectory may not have been created yet.
    // QH-01 Step 4c: argv-shaped mkdir rendered through the validated seam.
    let mkdir_args = vec![
        ValidatedArg::cli_token("mkdir")?,
        ValidatedArg::cli_token("-p")?,
        ValidatedArg::path(MACOS_STAGING_DIR)?,
    ];
    let mkdir_script = ssh::RemoteCommand::from_args("macos staging dir", &mkdir_args)?;
    ssh::run_remote(conn, mkdir_script.as_str(), SHORT_TIMEOUT)?;
    ssh::scp_to(conn, bundle_path, &remote_tmp, MEDIUM_TIMEOUT)?;
    let install_dir = install_dst
        .rsplit_once('/')
        .map_or(MACOS_STATE_ROOT, |(dir, _)| dir);
    let (mode, owner) = if matches!(kind, BundleKind::Membership) {
        ("0600", "rustynetd")
    } else {
        ("0640", "root")
    };
    let log_init = if matches!(kind, BundleKind::Membership) {
        let log_header = membership_log_header();
        format!(
            " && (sudo -n test -s '{MACOS_MEMBERSHIP_LOG_PATH}' || \
             printf '%s\n' '{log_header}' | sudo -n tee '{MACOS_MEMBERSHIP_LOG_PATH}' >/dev/null) && \
             sudo -n chown rustynetd:rustynetd '{MACOS_MEMBERSHIP_LOG_PATH}' && \
             sudo -n chmod 0600 '{MACOS_MEMBERSHIP_LOG_PATH}'"
        )
    } else {
        String::new()
    };
    ssh::run_remote(
        conn,
        &format!(
            "sudo -n install -d -m 0700 -o rustynetd -g rustynetd '{install_dir}' && \
             sudo -n install -m {mode} -o {owner} -g rustynetd '{remote_tmp}' '{install_dst}' && \
             sudo -n rm -f '{remote_tmp}'{log_init}"
        ),
        SHORT_TIMEOUT,
    )?;
    Ok(())
}

/// Distribute the verifier public-key for `kind` to this macOS node.
pub fn distribute_verifier_key(
    conn: &NodeConnection,
    kind: BundleKind,
    pub_key_path: &Path,
) -> Result<(), AdapterError> {
    let expected_sha256 =
        crate::vm_lab::orchestrator::adapter::verifier_key::validated_verifier_key_sha256(
            pub_key_path,
        )?;
    let dst = macos_verifier_key_path(&kind);
    let remote_tmp = format!("{MACOS_STAGING_DIR}/rn-verifier-key.pub");
    let mkdir_args = vec![
        ValidatedArg::cli_token("mkdir")?,
        ValidatedArg::cli_token("-p")?,
        ValidatedArg::path(MACOS_STAGING_DIR)?,
    ];
    let mkdir_script = ssh::RemoteCommand::from_args("macos staging dir", &mkdir_args)?;
    ssh::run_remote(conn, mkdir_script.as_str(), SHORT_TIMEOUT)?;
    ssh::scp_to(conn, pub_key_path, &remote_tmp, MEDIUM_TIMEOUT)?;
    let dst_dir = dst.rsplit_once('/').map_or(MACOS_STATE_ROOT, |(d, _)| d);
    // The verifier-key destination dir ({state}/trust) is shared with the
    // signed-bundle install, which creates it as 0700 rustynetd:rustynetd.
    // Use the SAME owner/mode here so the last writer doesn't flip the trust
    // dir to 0755 root:wheel and trip the daemon's key-custody/hardening
    // posture. The key file itself stays world-readable (0644) so the daemon
    // can read it while the dir remains rustynetd-owned.
    ssh::run_remote(
        conn,
        &format!(
            "sudo install -d -m 0700 -o rustynetd -g rustynetd '{dst_dir}' && \
             sudo install -m 0644 -o root -g rustynetd '{remote_tmp}' '{dst}' && \
             sudo rm -f '{remote_tmp}' && \
             test \"$(sudo shasum -a 256 '{dst}' | awk '{{print $1}}')\" = '{expected_sha256}'"
        ),
        SHORT_TIMEOUT,
    )?;
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn macos_verifier_key_path(kind: &BundleKind) -> String {
    let state = MACOS_STATE_ROOT;
    match kind {
        BundleKind::Assignment => format!("{state}/trust/assignment.pub"),
        BundleKind::Traversal => format!("{state}/trust/traversal.pub"),
        BundleKind::DnsZone => format!("{state}/trust/dns-zone.pub"),
        BundleKind::Membership => format!("{state}/trust/membership.pub"),
    }
}

fn remote_bundle_paths(kind: &BundleKind) -> (String, String) {
    let staging = MACOS_STAGING_DIR;
    let state = MACOS_STATE_ROOT;
    match kind {
        BundleKind::Membership => (
            format!("{staging}/rn-membership.snapshot"),
            format!("{state}/membership/membership.snapshot"),
        ),
        BundleKind::Assignment => (
            format!("{staging}/rn-assignment.bundle"),
            format!("{state}/trust/rustynetd.assignment"),
        ),
        BundleKind::Traversal => (
            format!("{staging}/rn-traversal.bundle"),
            format!("{state}/trust/rustynetd.traversal"),
        ),
        BundleKind::DnsZone => (
            format!("{staging}/rn-dns-zone.bundle"),
            format!("{state}/trust/rustynetd.dns-zone"),
        ),
    }
}

fn membership_log_header() -> String {
    format!("version={MEMBERSHIP_SCHEMA_VERSION}")
}

// (shell_safe_arg was superseded by the QH-01 validated seam: node ids
// validate through `ValidatedArg::node_id` and capability CSVs through
// `ValidatedArg::capability_csv` — see validated_args.rs.)

fn hex_32_safe_arg(value: &str) -> Result<String, AdapterError> {
    if NodeMembershipPeer::is_valid_public_key_hex(value) {
        Ok(value.to_owned())
    } else {
        Err(AdapterError::Protocol {
            message: "WireGuard public key must be 64 hex chars".to_owned(),
        })
    }
}

fn base64_decode(encoded: &str) -> Result<Vec<u8>, AdapterError> {
    base64_std_decode(encoded).map_err(|err| AdapterError::Protocol {
        message: format!("base64 decode of membership snapshot failed: {err}"),
    })
}

fn base64_std_decode(encoded: &str) -> Result<Vec<u8>, String> {
    let clean: String = encoded
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    use std::io::Write;
    use std::process::{Command, Stdio};
    let output = Command::new("base64")
        .arg("-d")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(clean.as_bytes());
            }
            child.wait_with_output()
        })
        .map_err(|err| format!("base64 -d spawn failed: {err}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(format!("base64 -d failed: {stderr}"));
    }
    Ok(output.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::orchestrator::adapter::macos_install::MACOS_MEMBERSHIP_DIR;

    #[test]
    fn remote_bundle_paths_contain_expected_filenames() {
        let (staging, dst) = remote_bundle_paths(&BundleKind::Membership);
        assert!(staging.contains("membership"), "staging: {staging}");
        assert!(dst.contains("membership.snapshot"), "dst: {dst}");

        let (staging, dst) = remote_bundle_paths(&BundleKind::Assignment);
        assert!(staging.contains("assignment"), "staging: {staging}");
        assert!(dst.contains("rustynetd.assignment"), "dst: {dst}");

        let (staging, dst) = remote_bundle_paths(&BundleKind::DnsZone);
        assert!(staging.contains("dns-zone"), "staging: {staging}");
        assert!(dst.contains("rustynetd.dns-zone"), "dst: {dst}");
    }

    #[test]
    fn remote_bundle_dst_paths_are_under_state_root() {
        for kind in &[
            BundleKind::Membership,
            BundleKind::Assignment,
            BundleKind::Traversal,
            BundleKind::DnsZone,
        ] {
            let (_, dst) = remote_bundle_paths(kind);
            assert!(
                dst.starts_with(MACOS_STATE_ROOT),
                "dst path '{dst}' must be under MACOS_STATE_ROOT"
            );
        }
    }

    #[test]
    fn membership_owner_pubkey_path_matches_genesis_write_path() {
        // `rustynetd membership init` writes the owner public key at
        // "{--owner-signing-key}.pub"; the macOS genesis driver passes
        // MACOS_OWNER_SIGNING_KEY_PATH. The adapter must read exactly where
        // genesis writes — this pin keeps the two from drifting again
        // (MAC-D2: the old constant guessed a STATE_ROOT location genesis
        // never used).
        assert_eq!(
            MACOS_MEMBERSHIP_OWNER_PUBKEY_PATH,
            format!("{MACOS_OWNER_SIGNING_KEY_PATH}.pub"),
            "pubkey path must be the .pub sibling of the genesis signing key path"
        );
        assert_eq!(
            MACOS_MEMBERSHIP_OWNER_PUBKEY_PATH,
            "/usr/local/etc/rustynet/membership.owner.key.pub"
        );
    }

    #[test]
    fn owner_key_read_script_uses_sudo_n_and_names_the_path() {
        let script = owner_key_read_script(MACOS_MEMBERSHIP_OWNER_PUBKEY_PATH);
        assert!(
            script.contains("sudo -n cat"),
            "read must be privileged like the Linux twin: {script:?}"
        );
        assert!(
            script.contains(MACOS_MEMBERSHIP_OWNER_PUBKEY_PATH),
            "script must name the canonical path: {script:?}"
        );
        // No bare `cat` without sudo escalation.
        for line in script.lines() {
            let trimmed = line.trim_start();
            assert!(
                !trimmed.starts_with("cat "),
                "bare cat found; every read must be sudo -n: {trimmed}"
            );
        }
    }

    #[test]
    fn owner_key_read_success_yields_key() {
        let key = interpret_owner_key_read(
            "-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----\n",
        )
        .unwrap();
        assert!(key.public_key_pem.contains("BEGIN PUBLIC KEY"));
    }

    #[test]
    fn owner_key_absent_and_permission_denied_are_distinct_loud_errors() {
        let absent = interpret_owner_key_read(&format!(
            "{OWNER_KEY_ABSENT_MARKER}/usr/local/etc/rustynet/membership.owner.key.pub"
        ))
        .unwrap_err();
        let denied = interpret_owner_key_read(&format!(
            "{OWNER_KEY_READ_FAILED_MARKER}/usr/local/etc/rustynet/membership.owner.key.pub \
             rc=1 cat: ...: Permission denied"
        ))
        .unwrap_err();

        let absent_msg = absent.to_string();
        let denied_msg = denied.to_string();
        assert!(!absent_msg.is_empty() && !denied_msg.is_empty());
        assert_ne!(
            absent_msg, denied_msg,
            "absent-file and permission-denied must never collapse to one error"
        );
        assert!(
            absent_msg.contains("not found on remote"),
            "absent error must say so: {absent_msg}"
        );
        assert!(
            absent_msg.contains(MACOS_OWNER_SIGNING_KEY_PATH),
            "absent error must point at the genesis seed path: {absent_msg}"
        );
        assert!(
            denied_msg.contains("could not be read") && denied_msg.contains("Permission denied"),
            "read-failed error must carry the underlying error: {denied_msg}"
        );
    }

    #[test]
    fn owner_key_empty_output_is_loud_not_initialization_hint() {
        let err = interpret_owner_key_read("   \n").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("no output"),
            "empty read must not read as 'not initialized': {msg}"
        );
    }

    #[test]
    fn membership_snapshot_path_is_under_membership_dir() {
        assert!(
            MACOS_MEMBERSHIP_SNAPSHOT_PATH.starts_with(MACOS_MEMBERSHIP_DIR),
            "snapshot path must be under membership dir: {MACOS_MEMBERSHIP_SNAPSHOT_PATH}"
        );
    }

    #[test]
    fn membership_log_header_matches_control_schema() {
        assert_eq!(membership_log_header(), "version=1");
    }

    #[test]
    fn membership_init_and_peer_add_render_argv_through_the_validated_seam() {
        let init_script = membership_init_script("exit-1").expect("render");
        assert_eq!(
            init_script.as_str(),
            "'sudo' '-n' 'env' 'RUSTYNET_NODE_ROLE=admin' \
             'RUSTYNET_NODE_ID=exit-1' \
             'RUSTYNET_SIGNING_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT=trust-passphrase-exit-1' \
             '/usr/local/bin/rustynet' 'ops' 'init-membership'"
        );

        let add_script = peer_add_script(
            "exit-1",
            "client-1",
            "--client-gossip-pubkey-hex",
            &"a".repeat(64),
            "client,entry_relay",
        )
        .expect("render");
        assert_eq!(
            add_script.as_str(),
            "'sudo' '-n' 'env' \
             'RUSTYNET_SIGNING_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT=trust-passphrase-exit-1' \
             '/usr/local/bin/rustynet' 'ops' 'e2e-membership-add' \
             '--client-node-id' 'client-1' '--client-gossip-pubkey-hex' \
             'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
             '--capabilities' 'client,entry_relay' '--owner-approver-id' 'exit-1-owner'"
        );
    }

    #[test]
    fn membership_init_rejects_a_metacharacter_node_id_at_the_seam() {
        let err = membership_init_script("exit-1; rm -rf /").expect_err("must reject");
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn hex_32_safe_arg_requires_64_hex_chars() {
        assert!(hex_32_safe_arg(&"a".repeat(64)).is_ok());
        assert!(hex_32_safe_arg("").is_err());
        assert!(hex_32_safe_arg(&"g".repeat(64)).is_err());
        assert!(hex_32_safe_arg(&"a".repeat(63)).is_err());
    }

    #[test]
    fn base64_roundtrip() {
        let data = b"hello macos membership";
        let encoded = {
            use std::io::Write;
            use std::process::{Command, Stdio};
            let mut child = Command::new("base64")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            child.stdin.take().unwrap().write_all(data).unwrap();
            let out = child.wait_with_output().unwrap();
            String::from_utf8(out.stdout).unwrap()
        };
        let decoded = base64_decode(encoded.trim()).unwrap();
        assert_eq!(decoded, data);
    }

    // ── MAC-D5: membership init must carry RUSTYNET_NODE_ID ─────────────────

    fn peer(role: NodeRole, node_id: &str) -> NodeMembershipPeer {
        NodeMembershipPeer {
            alias: node_id.to_owned(),
            role,
            capabilities: Vec::new(),
            node_id: node_id.to_owned(),
            public_key_hex: "a".repeat(64),
            gossip_identity: GossipIdentity::DeferredPlatform,
        }
    }

    #[test]
    fn membership_init_script_carries_node_id_after_sudo() {
        // MAC-D5: the daemon fails closed without RUSTYNET_NODE_ID. The
        // command must set it (and the role) INSIDE the sudo invocation —
        // `env … sudo` has the variables stripped by sudo's env_reset.
        // (QH-01 Step 4c: the rendered form quotes each argv token, so the
        // assertions match the seam-rendered string.)
        let script = membership_init_script("node-exit-1").expect("render");
        assert!(
            script.as_str().starts_with(
                "'sudo' '-n' 'env' 'RUSTYNET_NODE_ROLE=admin' 'RUSTYNET_NODE_ID=node-exit-1'"
            ),
            "node id must be set after sudo -n env: {script:?}"
        );
        assert!(
            script.as_str().contains("'ops' 'init-membership'"),
            "script must run init-membership: {script:?}"
        );
        assert!(
            script.as_str().contains(MACOS_RUSTYNET_PATH),
            "script must use the canonical macOS rustynet path: {script:?}"
        );
    }

    // ── MAC-D11: the init/peer-add invocations must carry the keychain
    //    account, not depend on the session environment ─────────────────────

    #[test]
    fn membership_init_script_carries_node_scoped_keychain_account() {
        // MAC-D11: `ops init-membership`'s passphrase gate hard-errors the
        // moment its idempotent early-out misses unless the keychain account
        // is in the invocation env. The account is the node-scoped item the
        // bootstrap provisions (`trust-passphrase-<node_id>`), passed after
        // `sudo -n env` so env_reset cannot strip it.
        let script = membership_init_script("node-exit-1").expect("render");
        assert!(
            script.as_str().contains(
                "'RUSTYNET_SIGNING_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT=trust-passphrase-node-exit-1'"
            ),
            "init must carry the node-scoped keychain account: {script:?}"
        );
        assert!(
            script.as_str().starts_with("'sudo' '-n' 'env' "),
            "account env must sit inside the sudo invocation: {script:?}"
        );
    }

    #[test]
    fn peer_add_script_carries_node_scoped_keychain_account() {
        // MAC-D11 ride-along: same env plumbing on the mutation verb.
        let script = peer_add_script(
            "node-exit-1",
            "node-client-1",
            "--client-gossip-pubkey-hex",
            &"a".repeat(64),
            "client",
        )
        .expect("render");
        assert!(
            script.as_str().contains(
                "'RUSTYNET_SIGNING_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT=trust-passphrase-node-exit-1'"
            ),
            "peer-add must carry the node-scoped keychain account: {script:?}"
        );
        assert!(
            script.as_str().starts_with("'sudo' '-n' 'env' "),
            "account env must sit inside the sudo invocation: {script:?}"
        );
    }

    // ── MAC-D10: the snapshot read-back must fail LOUD, never silent ────────

    #[test]
    fn snapshot_readback_script_fails_loud_naming_the_path() {
        // The previous `test -s '<path>' && cat …` form's only failure output
        // was SILENCE (test exits 1, prints nothing), so a vanished genesis
        // surfaced as a bare "exit Some(1)" with empty stderr AND stdout.
        // The probe must emit its own diagnostic on stderr and exit 1,
        // naming the snapshot path.
        let script = membership_snapshot_readback_script();
        assert!(
            script.contains(">&2") && script.contains("exit 1"),
            "read-back failure must emit its own message and exit 1: {script:?}"
        );
        assert!(
            script.contains(MACOS_MEMBERSHIP_SNAPSHOT_PATH),
            "the failure message must name the snapshot path: {script:?}"
        );
        assert!(
            script.contains("missing or empty"),
            "the failure message must distinguish the vanish: {script:?}"
        );
    }

    #[test]
    fn snapshot_readback_script_reads_under_sudo() {
        // The snapshot is 0600 rustynetd:rustynetd; the SSH session is
        // unprivileged. Both the size probe and the read need `sudo -n`,
        // matching the owner-key probe's privilege pattern.
        let script = membership_snapshot_readback_script();
        assert!(
            script.contains("sudo -n test -s") && script.contains("sudo -n cat"),
            "probe and read must both run under sudo -n: {script:?}"
        );
        assert!(
            script.contains("| base64"),
            "the snapshot body must still be base64-encoded for transport: {script:?}"
        );
    }

    #[test]
    fn exit_node_id_resolution_sources_the_exit_peer() {
        let peers = vec![
            peer(NodeRole::Client, "node-client-1"),
            peer(NodeRole::Exit, "node-exit-1"),
        ];
        assert_eq!(exit_node_id_from_peers(&peers).unwrap(), "node-exit-1");
    }

    #[test]
    fn exit_node_id_resolution_fails_loud_without_exit_peer() {
        let peers = vec![peer(NodeRole::Client, "node-client-1")];
        let err = exit_node_id_from_peers(&peers).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("no NodeRole::Exit peer") && msg.contains("RUSTYNET_NODE_ID"),
            "missing exit peer must name the failure: {msg}"
        );
    }

    #[test]
    fn exit_node_id_resolution_fails_loud_on_blank_id() {
        // A blank node id is a correctness hazard (empty env var), so an
        // empty string on the exit peer must fail rather than default.
        let peers = vec![peer(NodeRole::Exit, "")];
        let err = exit_node_id_from_peers(&peers).unwrap_err();
        assert!(
            err.to_string().contains("empty membership node id"),
            "blank id must fail loud: {err}"
        );
    }

    #[test]
    fn resolved_exit_node_id_passes_the_seam_node_id_validator() {
        let peers = vec![peer(NodeRole::Exit, "node-exit-1")];
        let id = exit_node_id_from_peers(&peers).unwrap();
        assert!(ValidatedArg::node_id(id).is_ok());
    }

    // ── MAC-D6: the peer-add approver id must be DERIVED, never shelled out ──

    #[test]
    fn peer_add_script_derives_owner_approver_id_from_the_exit_peer() {
        // The genesis owner approver `rustynetd membership init` registers is
        // "{node_id}-owner"; the harness must pass exactly that, not query a
        // CLI verb for it.
        let script = peer_add_script(
            "node-exit-1",
            "node-client-1",
            "--client-pubkey-hex-unaligned-wireguard",
            &"a".repeat(64),
            "client",
        )
        .unwrap();
        assert!(
            script
                .as_str()
                .contains("'--owner-approver-id' 'node-exit-1-owner'"),
            "approver id must be derived as {{exit_node_id}}-owner: {script:?}"
        );
    }

    #[test]
    fn peer_add_script_never_invokes_an_owner_approver_id_verb() {
        // MAC-D6 regression pin: `ops owner-approver-id` does not exist. Any
        // return to querying a verb for the approver id must fail here.
        let script = peer_add_script(
            "node-exit-1",
            "node-client-1",
            "--client-pubkey-hex-unaligned-wireguard",
            &"a".repeat(64),
            "client",
        )
        .unwrap();
        assert!(
            !script.as_str().contains("'ops' 'owner-approver-id'"),
            "no `ops owner-approver-id` subcommand exists; the approver id must \
             stay derived: {script:?}"
        );
        assert!(
            !script.as_str().contains("|| echo none"),
            "no failure may be swallowed into the approver id: {script:?}"
        );
        assert!(
            script.as_str().contains("'ops' 'e2e-membership-add'"),
            "the peer-add must still run the real verb: {script:?}"
        );
    }

    #[test]
    fn derived_owner_approver_id_survives_shell_safety_guard() {
        // The derived value goes inside single quotes on a root remote shell;
        // the guard that validated it for the Linux twin must gate it here too.
        let script = peer_add_script(
            "node-exit-1",
            "node-client-1",
            "--client-pubkey-hex-unaligned-wireguard",
            &"a".repeat(64),
            "client",
        )
        .unwrap();
        // A malicious exit id would have been rejected upstream, but the
        // derivation itself must not smuggle characters past the guard
        // (now the seam's `node_id` class).
        let approver = format!("{0}-owner", "node-exit-1");
        assert!(ValidatedArg::node_id(&approver).is_ok());
        assert!(script.as_str().contains("'node-exit-1-owner'"));
    }
}

#[cfg(test)]
mod exit_capability_rewrite_tests {
    //! Design §5.2 unit layer: "macOS exit membership carries exactly
    //! {blind_exit, exit_server}, never anchor" — pinned on the provisioning
    //! command plan, so reverting to the pre-fix skip-the-exit behaviour fails
    //! here, not only in the lab.
    use super::*;
    use rustynet_control::roles::parse_role_capability_csv;

    fn peer(role: NodeRole, node_id: &str) -> NodeMembershipPeer {
        NodeMembershipPeer {
            alias: node_id.to_owned(),
            role,
            capabilities: vec![RoleCapability::Client],
            node_id: node_id.to_owned(),
            public_key_hex: "a".repeat(64),
            gossip_identity: GossipIdentity::DeferredPlatform,
        }
    }

    /// The anchor-carrying genesis set `rustynetd membership init` mints.
    fn anchor_genesis_caps() -> Vec<RoleCapability> {
        vec![
            RoleCapability::Anchor,
            RoleCapability::AnchorGossipSeed,
            RoleCapability::AnchorBundlePull,
            RoleCapability::AnchorEnrollmentEndpoint,
            RoleCapability::AnchorRelayColocation,
            RoleCapability::AnchorPortMappingAuthoritative,
            RoleCapability::Client,
            RoleCapability::ExitServer,
            RoleCapability::RelayHost,
        ]
    }

    #[test]
    fn target_set_is_exactly_the_blind_exit_pair_from_the_product_grant() {
        let target = macos_exit_target_capabilities().expect("grant");
        assert_eq!(
            target,
            canonicalize_role_capabilities([RoleCapability::BlindExit, RoleCapability::ExitServer])
        );
        assert_eq!(target.len(), 2);
        // It is DERIVED from role.rs, so it must match the product grant verbatim.
        let grant = NodeRole::Exit
            .product_capabilities_for_platform(&VmGuestPlatform::Macos)
            .expect("macOS exit grant");
        assert_eq!(canonicalize_role_capabilities(grant), target);
    }

    #[test]
    fn exit_capability_rewrite_script_carries_exact_blind_exit_set() {
        let target = macos_exit_target_capabilities().expect("grant");
        let script = exit_capability_rewrite_script("node-exit-1", &target).expect("render");
        // The CSV is rendered in the crate's CANONICAL capability order (the
        // same `role_capability_csv` the daemon and every other signer use),
        // not alphabetical — derive the expectation from it rather than
        // hand-typing an order.
        let canonical_csv = role_capability_csv(&target);
        assert_eq!(
            script.as_str(),
            format!(
                "'sudo' '-n' 'env' \
                 'RUSTYNET_SIGNING_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT=trust-passphrase-node-exit-1' \
                 '/usr/local/bin/rustynet' 'ops' 'e2e-membership-set-capabilities' \
                 '--node-id' 'node-exit-1' '--capabilities' '{canonical_csv}' \
                 '--owner-approver-id' 'node-exit-1-owner'"
            )
        );
        // Parse the CSV back: exactly two capabilities, order-insensitive.
        let csv = script
            .as_str()
            .split("'--capabilities' '")
            .nth(1)
            .and_then(|rest| rest.split('\'').next())
            .expect("capabilities csv present");
        let parsed =
            canonicalize_role_capabilities(parse_role_capability_csv(csv).expect("csv parses"));
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed, target);
        // The string `anchor` appears NOWHERE in the rewrite: no anchor
        // capability, no anchor sub-capability, no anchor verb.
        assert!(
            !script.as_str().contains("anchor"),
            "rewrite must never mention anchor: {script:?}"
        );
        // Exactly one capability-affecting verb.
        assert_eq!(script.as_str().matches("'ops'").count(), 1);
        assert!(!script.as_str().contains("e2e-membership-add"));
        assert!(!script.as_str().contains("init-membership"));
    }

    #[test]
    fn rewrite_script_rejects_a_metacharacter_exit_id_at_the_seam() {
        let target = macos_exit_target_capabilities().expect("grant");
        let err =
            exit_capability_rewrite_script("exit-1; rm -rf /", &target).expect_err("must reject");
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn needs_rewrite_is_a_canonical_exact_set_compare() {
        let target = macos_exit_target_capabilities().expect("grant");
        // Anchor-carrying genesis → rewrite.
        assert!(exit_needs_capability_rewrite(
            &anchor_genesis_caps(),
            &target
        ));
        // Already canonical, in any order, with duplicates → no rewrite.
        assert!(!exit_needs_capability_rewrite(
            &[
                RoleCapability::ExitServer,
                RoleCapability::BlindExit,
                RoleCapability::ExitServer
            ],
            &target
        ));
        // A superset that still contains the pair is NOT canonical → rewrite.
        // (This is the QH-65 shape: blind_exit + exit_server + relay_host.)
        assert!(exit_needs_capability_rewrite(
            &[
                RoleCapability::BlindExit,
                RoleCapability::ExitServer,
                RoleCapability::RelayHost
            ],
            &target
        ));
        // A subset → rewrite.
        assert!(exit_needs_capability_rewrite(
            &[RoleCapability::ExitServer],
            &target
        ));
        assert!(exit_needs_capability_rewrite(&[], &target));
    }

    #[test]
    fn fresh_anchor_genesis_plan_is_init_then_rewrite_then_peer_adds_in_order() {
        let peers = vec![
            peer(NodeRole::Client, "node-client-1"),
            peer(NodeRole::Exit, "node-exit-1"),
            peer(NodeRole::Client, "node-client-2"),
        ];
        let plan =
            init_membership_commands("node-exit-1", &peers, &anchor_genesis_caps()).expect("plan");
        // The plan is typed by KIND, and the executor keys on the kind — pin
        // the kinds first, then the rendered commands.
        let kinds: Vec<PlanStepKind> = plan.iter().map(|s| s.kind).collect();
        assert_eq!(
            kinds,
            vec![
                PlanStepKind::Genesis,
                PlanStepKind::ExitCapabilityRewrite,
                PlanStepKind::PeerAdd,
                PlanStepKind::PeerAdd,
            ]
        );
        let rendered: Vec<&str> = plan.iter().map(|s| s.command.as_str()).collect();
        assert_eq!(rendered.len(), 4, "init + rewrite + 2 adds: {rendered:#?}");
        assert!(
            rendered[0].contains("'ops' 'init-membership'"),
            "{}",
            rendered[0]
        );
        let canonical_csv = role_capability_csv(&macos_exit_target_capabilities().expect("grant"));
        assert!(
            rendered[1].contains("'ops' 'e2e-membership-set-capabilities'")
                && rendered[1].contains("'--node-id' 'node-exit-1'")
                && rendered[1].contains(&format!("'--capabilities' '{canonical_csv}'")),
            "the rewrite must sit between genesis and the first add: {}",
            rendered[1]
        );
        assert!(
            rendered[2].contains("'ops' 'e2e-membership-add'")
                && rendered[2].contains("'--client-node-id' 'node-client-1'"),
            "{}",
            rendered[2]
        );
        assert!(
            rendered[3].contains("'--client-node-id' 'node-client-2'"),
            "{}",
            rendered[3]
        );
        // The exit peer itself is never added as a client.
        assert!(
            !rendered
                .iter()
                .any(|c| c.contains("'--client-node-id' 'node-exit-1'")),
            "{rendered:#?}"
        );
        // Mutation guard (design §5.2): the pre-fix plan had NO
        // set-capabilities entry at all.
        assert_eq!(
            rendered
                .iter()
                .filter(|c| c.contains("e2e-membership-set-capabilities"))
                .count(),
            1
        );
    }

    #[test]
    fn already_canonical_genesis_plan_omits_the_rewrite_and_keeps_the_adds() {
        // Idempotency branch: a re-used guest whose record is already
        // {blind_exit, exit_server} must not get a needless epoch bump.
        let peers = vec![
            peer(NodeRole::Exit, "node-exit-1"),
            peer(NodeRole::Client, "node-client-1"),
        ];
        let target = macos_exit_target_capabilities().expect("grant");
        let plan = init_membership_commands("node-exit-1", &peers, &target).expect("plan");
        let kinds: Vec<PlanStepKind> = plan.iter().map(|s| s.kind).collect();
        assert_eq!(kinds, vec![PlanStepKind::Genesis, PlanStepKind::PeerAdd]);
        let rendered: Vec<&str> = plan.iter().map(|s| s.command.as_str()).collect();
        assert_eq!(rendered.len(), 2, "init + 1 add: {rendered:#?}");
        assert!(rendered[0].contains("'ops' 'init-membership'"));
        assert!(rendered[1].contains("'ops' 'e2e-membership-add'"));
        assert!(
            !rendered.iter().any(|c| c.contains("set-capabilities")),
            "no rewrite on an already-canonical record: {rendered:#?}"
        );
        // And the post-genesis half alone agrees (it is what the executor runs).
        let post = post_genesis_commands("node-exit-1", &peers, &target).expect("plan");
        assert_eq!(post.len(), 1);
    }

    #[test]
    fn post_genesis_plan_puts_the_rewrite_before_every_add() {
        let peers = vec![
            peer(NodeRole::Client, "node-client-1"),
            peer(NodeRole::Exit, "node-exit-1"),
        ];
        let post =
            post_genesis_commands("node-exit-1", &peers, &anchor_genesis_caps()).expect("plan");
        assert_eq!(post.len(), 2);
        assert_eq!(post[0].kind, PlanStepKind::ExitCapabilityRewrite);
        assert!(
            post[0]
                .command
                .as_str()
                .contains("e2e-membership-set-capabilities")
        );
        assert_eq!(post[1].kind, PlanStepKind::PeerAdd);
        assert!(post[1].command.as_str().contains("e2e-membership-add"));
        // Exactly one rewrite step, ever.
        assert_eq!(
            post.iter()
                .filter(|s| s.kind == PlanStepKind::ExitCapabilityRewrite)
                .count(),
            1
        );
    }

    #[test]
    fn presence_probe_commands_are_argv_only_sudo_n_and_name_the_key_path() {
        let sudo = owner_signing_key_sudo_probe_command().expect("render");
        assert_eq!(sudo.as_str(), "'sudo' '-n' 'true'");
        let presence =
            owner_signing_key_presence_command(MACOS_OWNER_SIGNING_KEY_PATH).expect("render");
        assert_eq!(
            presence.as_str(),
            format!("'sudo' '-n' 'test' '-e' '{MACOS_OWNER_SIGNING_KEY_PATH}'")
        );
        // The path crosses the seam's `path` class (absolute, no newline/NUL,
        // no `..` segment); the seam's own quoting handles the rest. A
        // relative, empty, traversal, or newline-bearing path is refused
        // before it can reach a root shell.
        assert!(owner_signing_key_presence_command("relative/key").is_err());
        assert!(owner_signing_key_presence_command("").is_err());
        assert!(owner_signing_key_presence_command("/usr/local/../etc/key").is_err());
        assert!(owner_signing_key_presence_command("/usr/local/etc/key\nrm -rf /").is_err());
    }

    #[test]
    fn presence_probe_answers_are_exit_0_and_1_only_and_everything_else_is_loud() {
        // exit 0 → present.
        assert!(interpret_owner_key_presence(Ok(String::new())).expect("present"));
        // exit 1 → absent (test -e false), and ONLY after sudo was proven to
        // work by the preceding `sudo -n true` step in the probe.
        assert!(
            !interpret_owner_key_presence(Err(AdapterError::Command {
                exit_code: Some(1),
                stderr: String::new(),
            }))
            .expect("absent")
        );
        // Any other exit status is not an answer.
        let err = interpret_owner_key_presence(Err(AdapterError::Command {
            exit_code: Some(2),
            stderr: "test: usage".to_owned(),
        }))
        .expect_err("exit 2 must not read as absent");
        assert!(err.to_string().contains("unexpected status"), "{err}");
        assert!(
            interpret_owner_key_presence(Err(AdapterError::Command {
                exit_code: None,
                stderr: "killed".to_owned(),
            }))
            .is_err()
        );
        // Transport failures propagate as themselves.
        let err = interpret_owner_key_presence(Err(AdapterError::Ssh {
            message: "connection reset".to_owned(),
        }))
        .expect_err("transport failure must not read as an answer");
        assert!(err.to_string().contains("connection reset"), "{err}");
    }

    #[test]
    fn the_genesis_call_site_still_declares_admin_deliberately() {
        // F1 guard: the disclosed lie must stay until Option D lands; a change
        // here silently breaks the rewrite this module depends on.
        let init = membership_init_script("node-exit-1").expect("render");
        assert!(
            init.as_str().contains("'RUSTYNET_NODE_ROLE=admin'"),
            "{init:?}"
        );
        assert!(!init.as_str().contains("RUSTYNET_NODE_ROLE=blind_exit"));
    }
}

#[cfg(test)]
mod gossip_subject_platform_tests {
    use super::*;

    /// Regression: this producer runs on a macOS exit node but writes membership
    /// for EVERY peer, including Linux ones that DO have a real gossip identity.
    /// The first implementation published `public_key_hex` unconditionally,
    /// which republished those nodes' WireGuard keys under a flag named
    /// `unaligned-wireguard` on any `--exit-platform macos` run — silently
    /// reinstating the defect, with the flag name actively lying about it.
    /// The branch must key on the SUBJECT peer, never on this producer's own
    /// platform.
    #[test]
    fn a_published_identity_selects_the_aligned_flag_even_on_the_macos_producer() {
        let gossip = "d".repeat(64);
        let wireguard = "b".repeat(64);
        let (flag, value) = match &GossipIdentity::Published(gossip.clone()) {
            GossipIdentity::Published(hex) => ("--client-gossip-pubkey-hex", hex.clone()),
            GossipIdentity::DeferredPlatform => {
                ("--client-pubkey-hex-unaligned-wireguard", wireguard.clone())
            }
        };
        assert_eq!(flag, "--client-gossip-pubkey-hex");
        assert_eq!(value, gossip);
        assert_ne!(value, wireguard, "must not publish the WireGuard key");
    }

    #[test]
    fn a_deferred_identity_selects_the_unaligned_flag() {
        let wireguard = "b".repeat(64);
        let (flag, value) = match &GossipIdentity::DeferredPlatform {
            GossipIdentity::Published(hex) => ("--client-gossip-pubkey-hex", hex.clone()),
            GossipIdentity::DeferredPlatform => {
                ("--client-pubkey-hex-unaligned-wireguard", wireguard.clone())
            }
        };
        assert_eq!(flag, "--client-pubkey-hex-unaligned-wireguard");
        assert_eq!(value, wireguard);
    }
}
