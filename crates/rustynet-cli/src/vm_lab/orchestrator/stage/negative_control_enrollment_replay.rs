#![allow(dead_code)]
//! QH-89 `negative_control_enrollment_token_replay` — the live replay attack
//! against the anchor's pre-auth enrollment listener.
//!
//! `NodeEngineAttackCoverageHandover_2026-09-11.md` §QH-89 (tough-policy audit
//! H): the live suites prove enrollment POSTURE (`live_enrollment_restart_…`
//! drives the IPC path on the anchor itself) and library-level replay
//! rejection (`enrollment_token.rs` unit tests), but nothing ever delivers a
//! replayed token to a LIVE daemon over the wire. This control does exactly
//! that: it enables the daemon's loopback anchor-enrollment TCP listener
//! (`bind_anchor_enrollment_listener` — opt-in, off by default in the lab
//! units), enrols a throwaway enrollee ONCE through the real listener, then
//! replays the same token sequentially AND as two overlapping concurrent
//! delivers (the RSA-0023 single-use race that `acquire_ledger_lock` closed;
//! the daemon serves at most one enrollment connection per poll iteration, so
//! the two connects may serialize — each response is adjudicated
//! independently, so a serialized double-accept is still caught).
//!
//! ## The inversion (same shape as `negative_control.rs`)
//!
//! The control returns [`StageOutcome::Passed`] iff the daemon REJECTED every
//! replay fail-closed (`ERR enrollment token rejected`, the handler's
//! fixed-vocabulary refusal that collapses `EnrollmentTokenError::
//! AlreadyConsumed`), the on-disk ledger gained EXACTLY ONE consumed row for
//! this token, the mesh membership snapshot did not move across the replays,
//! and the genuine (first) consume still succeeded — the accept-leg. Any
//! replay accepted, any wrong-reason refusal, a second ledger row, or snapshot
//! drift is a control FAIL (a detected fail-open), never a pass.
//!
//! ## Independent detection (tough-policy rule 2)
//!
//! No verdict input comes from a daemon self-report of "attack blocked":
//!   * the refusal lines are what the ATTACKER observed on its own socket;
//!   * `already_consumed=true` comes from `rustynet enrollment verify` reading
//!     the ON-DISK ledger (the inspect path — makes no ledger change);
//!   * the consumed-row count comes from parsing the on-disk ledger spool;
//!   * snapshot immutability is an on-disk sha256 before vs after the replays
//!     (state the replay would have had to move to matter).
//!
//! The daemon's overall_ok is never consulted.
//!
//! ## Sabotage lifecycle (rule 4 + the planted-residue teardown bar)
//!
//! Enabling the listener is a **drop-in** (`rustynetd.service.d/…conf` adding
//! `RUSTYNET_ANCHOR_ENROLLMENT_ADDR=127.0.0.1:<port>` — the daemon reads the
//! addr from that env var alone, so the reviewed `ExecStart` argv is never
//! rewritten). The drop-in is guarded: a pre-existing drop-in is an ambiguous
//! leftover and fails the control; teardown deletes it, reloads, restarts, and
//! VERIFIES the unit is active and the drop-in is gone. A teardown leak
//! dominates every other verdict.
//!
//! All guest-side values reach the attack script as `bash -c <script> <args>`
//! argv elements (the backend single-quotes each), and every fixed path is a
//! module constant — no shell string is ever built from a run-time value.

use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::adapter::node_adapter::NodeAdapter;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::remote_shell::RemoteShellHost;
use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// QH-89: the replay control's on-disk pass witness — the attack transcript
/// (request/response lines the attacker observed) plus every independent
/// detection datum, written by the ONLY pass path. The catalog row declares
/// this exact path; the runner demotes an unwitnessed `Passed`.
pub(crate) const REPLAY_TRANSCRIPT_RELATIVE: &str =
    "negative_control/negative_control_enrollment_token_replay/replay_transcript.txt";

pub struct NegativeControlEnrollmentTokenReplayStage;

impl OrchestrationStage for NegativeControlEnrollmentTokenReplayStage {
    fn id(&self) -> StageId {
        StageId::NegativeControlEnrollmentTokenReplay
    }
    fn name(&self) -> &str {
        "negative_control_enrollment_token_replay"
    }
    fn dependencies(&self) -> &[StageId] {
        &[]
    }
    fn applies_to_roles(&self) -> &[crate::vm_lab::orchestrator::role::NodeRole] {
        &[]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::Once
    }
    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        let dir = control_workdir(&ctx.report_dir, self.name());
        // Topology gaps are named, never absorbed (tough-policy rule 4): the
        // control needs (a) a Linux guest to host the listener and (b) an
        // `aux` enrollee role, exactly like `live_enrollment_restart_…`.
        if let Some(reason) = enrollment_replay::precondition_gap(&ctx.assignments, &|alias| {
            ctx.adapters.get(alias).map(|a| a.platform())
        }) {
            return StageOutcome::Skipped(reason);
        }
        let target =
            match enrollment_replay::select_linux_enrollment_target(&ctx.assignments, &|alias| {
                ctx.adapters.get(alias).map(|a| a.platform())
            }) {
                Ok(alias) => alias.to_owned(),
                Err(reason) => return StageOutcome::Failed(reason),
            };
        let Some(adapter) = ctx.adapters.get(&target) else {
            return StageOutcome::Failed(format!(
                "enrollment-replay negative control: selected target '{target}' has no adapter \
                 (fail closed)"
            ));
        };
        // The enrollee's gossip push host: the orchestrator's OWN collection
        // (CollectPubkeys mesh IP, then the endpoint's host part) — never a
        // daemon status field.
        let enrollee_alias =
            enrollment_replay::select_aux_alias(&ctx.assignments).unwrap_or_default();
        let enrollee_host = ctx
            .mesh_ips
            .get(enrollee_alias.as_str())
            .cloned()
            .or_else(|| {
                ctx.endpoints.get(enrollee_alias.as_str()).map(|e| {
                    e.rsplit_once(':')
                        .map(|(h, _)| h.to_owned())
                        .unwrap_or_else(|| e.clone())
                })
            })
            .unwrap_or_default();
        enrollment_replay::run_enrollment_replay_control(
            &dir,
            &ctx.report_dir,
            &target,
            adapter.as_ref(),
            &enrollee_host,
        )
    }
}

fn control_workdir(report_dir: &Path, stage_name: &str) -> PathBuf {
    report_dir.join("negative_control").join(stage_name)
}

pub(crate) mod enrollment_replay {
    //! The live replay-attack body + its pure adjudication.
    use super::*;
    use crate::vm_lab::orchestrator::evidence::append_stage_evidence_line;
    use crate::vm_lab::orchestrator::remote_shell::RemoteExitStatus;

    /// The lab Linux daemon unit the drop-in scopes.
    pub(crate) const RUSTYNETD_UNIT: &str = "rustynetd";
    /// Absolute CLI path (sudo secure_path omits /usr/local/bin on RHEL).
    pub(crate) const REMOTE_CLI: &str = "/usr/local/bin/rustynet";
    /// Lab admin-node enrollment secret (live_lab_support contract).
    pub(crate) const ENROLLMENT_SECRET_PATH: &str = "/var/lib/rustynet/keys/enrollment.secret";
    /// Lab consumed-token ledger spool (live_lab_support contract).
    pub(crate) const ENROLLMENT_LEDGER_PATH: &str = "/var/lib/rustynet/rustynetd.enrollment.ledger";
    /// On-disk signed membership snapshot (anchor.rs Linux contract).
    pub(crate) const MEMBERSHIP_SNAPSHOT_PATH: &str = "/var/lib/rustynet/membership.snapshot";
    /// Loopback addr the drop-in hands the daemon via
    /// `RUSTYNET_ANCHOR_ENROLLMENT_ADDR` (env-only config; the reviewed
    /// ExecStart argv is never rewritten). Distinct from bundle-pull's 51822
    /// and the NAS default 51823.
    pub(crate) const LISTENER_ADDR: &str = "127.0.0.1:51831";
    pub(crate) const LISTENER_PORT: &str = "51831";
    /// The gossip push port the enrolled peer is registered under (the same
    /// `RUSTYNET_GOSSIP_PORT` the restart stage uses).
    pub(crate) const GOSSIP_PORT: u16 = 51821;
    /// Drop-in file + its scratch staging path (user-writable, installed by
    /// root). Name is control-namespaced so a leak is identifiable forever.
    pub(crate) const DROPIN_DIR: &str = "/etc/systemd/system/rustynetd.service.d";
    pub(crate) const DROPIN_PATH: &str =
        "/etc/systemd/system/rustynetd.service.d/99-nc-enrollment-replay.conf";
    pub(crate) const DROPIN_STAGE_PATH: &str = "/tmp/rustynet-nc-enrollment-replay-dropin.conf";
    /// The drop-in body: env-only listener enablement.
    pub(crate) const DROPIN_CONTENT: &str = "# QH-89 negative_control_enrollment_token_replay\n\
         [Service]\n\
         Environment=RUSTYNET_ANCHOR_ENROLLMENT_ADDR=127.0.0.1:51831\n";
    /// The handler's fixed-vocabulary refusal for every token-level rejection
    /// (`ConsumeError::Token(_)` collapses to this string — daemon.rs
    /// `handle_enrollment_consume`). A replay MUST be refused with exactly it.
    pub(crate) const TOKEN_REJECTED_REFUSAL: &str = "ERR enrollment token rejected";
    /// Fixed seed for the throwaway enrollee key (negative_control.rs corpus
    /// doctrine: in-process keys, deterministic evidence, no product crypto
    /// touched).
    const ENROLLEE_KEY_SEED: [u8; 32] = [23u8; 32];

    /// Wait budget for the post-restart unit-active loop.
    const WAIT_TRIES: u32 = 30;

    /// The throwaway enrollee pubkey, base64 (standard, padded) — the daemon
    /// requires 32 bytes that decompress to a valid Ed25519 point, so a real
    /// key is minted host-side instead of raw random bytes.
    pub(crate) fn enrollee_pubkey_b64() -> String {
        use base64::Engine as _;
        use ed25519_dalek::SigningKey;
        let signing = SigningKey::from_bytes(&ENROLLEE_KEY_SEED);
        base64::engine::general_purpose::STANDARD.encode(signing.verifying_key().as_bytes())
    }

    // ── pure topology helpers (unit-tested) ──────────────────────────────

    /// Named topology gaps (rule 4): the control needs a Linux guest AND an
    /// `aux` enrollee role. `Some(reason)` ⇒ the stage MUST report
    /// `Skipped(reason)`; `None` ⇒ the topology can host the attack.
    pub(crate) fn precondition_gap(
        assignments: &[NodeRoleAssignment],
        platform_of: &dyn Fn(&str) -> Option<VmGuestPlatform>,
    ) -> Option<String> {
        if !assignments
            .iter()
            .any(|a| platform_of(&a.alias) == Some(VmGuestPlatform::Linux))
        {
            return Some(
                "no Linux node in the topology; the enrollment-replay control attacks a \
                 Linux anchor's enrollment listener"
                    .to_owned(),
            );
        }
        if select_aux_alias(assignments).is_none() {
            return Some(
                "no node in this topology is assigned the aux role; the enrollment-replay \
                 control needs an enrollee"
                    .to_owned(),
            );
        }
        None
    }

    /// The `aux`-role alias (the enrollee slot the token is minted FOR). The
    /// enrollee's daemon is never contacted — the key material is a throwaway
    /// minted host-side — but the role's presence is the topology's
    /// declaration that an enrollee slot exists.
    pub(crate) fn select_aux_alias(assignments: &[NodeRoleAssignment]) -> Option<String> {
        assignments
            .iter()
            .find(|a| a.role.as_str() == "aux")
            .map(|a| a.alias.clone())
    }

    /// Pick the node hosting the anchor enrollment listener: a **Linux** node
    /// with the `anchor` role, falling back to the Linux `exit` node (the lab
    /// co-locates the anchor on the exit and seeds the enrollment secret
    /// there — the same admin node `live_enrollment_restart_…` drives).
    /// Non-Linux candidates are never eligible (the drop-in + unit contract
    /// is Linux systemd). No candidate ⇒ `Err` (a control FAIL), never a
    /// skip-to-green: the Linux+aux gates above already passed, so an
    /// unhostable attack is a plan defect, not a topology gap.
    pub(crate) fn select_linux_enrollment_target<'a>(
        assignments: &'a [NodeRoleAssignment],
        platform_of: &dyn Fn(&str) -> Option<VmGuestPlatform>,
    ) -> Result<&'a str, String> {
        for role in ["anchor", "exit"] {
            for assignment in assignments {
                if assignment.role.as_str() == role
                    && platform_of(&assignment.alias) == Some(VmGuestPlatform::Linux)
                {
                    return Ok(assignment.alias.as_str());
                }
            }
        }
        Err(
            "enrollment-replay negative control: no Linux anchor/exit node to host the \
             enrollment listener (fail closed)"
                .to_owned(),
        )
    }

    // ── the attack script ─────────────────────────────────────────────────

    /// One guest-side script that runs the WHOLE attack against the loopback
    /// listener and reports through `nc_*` tokens. Invoked as
    /// `bash -c <script> nc-replay <token_hex> <secret> <ledger> <snapshot>
    /// <listener_port> <push_addr> <pubkey_b64> <token>` — every value an
    /// argv element (single-quoted by the backend), the script body a fixed
    /// literal. Always exits 0; a non-zero exit is script-infrastructure
    /// failure and refuses adjudication.
    ///
    /// Sequencing invariants (pinned by `script_binds_the_attack_sequence…`):
    /// 1. the listener is proven bound BEFORE any token byte is spent;
    /// 2. the pre-attack ledger row count + snapshot digest are captured
    ///    BEFORE the genuine consume (baseline);
    /// 3. the genuine consume precedes the replays and the post-genuine
    ///    snapshot digest is captured (the accept-leg legitimately moves
    ///    state; only the REPLAYS must leave it fixed);
    /// 4. the two concurrent replays overlap (both started before either is
    ///    waited on);
    /// 5. `enrollment verify` (inspect-only), the on-disk ledger count, the
    ///    token-row count, and the post-replay snapshot digest run last.
    pub(crate) const ATTACK_SCRIPT: &str = r#"set -u
token_hex="$1"
secret="$2"
ledger="$3"
snapshot="$4"
port="$5"
push_addr="$6"
pubkey_b64="$7"
token="$8"

# One wire consume over the loopback listener. All values argv; body fixed.
wire_consume() {
  bash -c '
    token="$1"; pk="$2"; push="$3"; port="$4"
    exec 3<>/dev/tcp/127.0.0.1/"$port" || exit 9
    printf "enrollment consume %s %s %s\n" "$token" "$pk" "$push" >&3
    IFS= read -r -t 5 line <&3 || exit 8
    printf "%s" "$line"
    exec 3>&- 3<&-
  ' nc-wire "$1" "$2" "$3" "$port"
}

tries=0
until bash -c 'exec 3<>"/dev/tcp/127.0.0.1/$1"' nc-probe "$port" 2>/dev/null; do
  tries=$((tries+1))
  if [ "$tries" -ge 30 ]; then printf 'nc_abort=listener_not_bound\n'; exit 0; fi
  sleep 1
done
printf 'nc_listener_bound=true\n'

ledger_before_rows="$(sed -n 's/^consumed_exp=//p' "$ledger" | tr ',' '\n' | grep -c .)"
printf 'nc_ledger_rows_before=%s\n' "$ledger_before_rows"
snap_before="$(sha256sum "$snapshot" | cut -d" " -f1)"
printf 'nc_snapshot_sha_before=%s\n' "$snap_before"

genuine="$(wire_consume "$token" "$pubkey_b64" "$push_addr")"
printf 'nc_genuine_response=%s\n' "$genuine"
sleep 1
snap_after_genuine="$(sha256sum "$snapshot" | cut -d" " -f1)"
printf 'nc_snapshot_sha_after_genuine=%s\n' "$snap_after_genuine"

seq_resp="$(wire_consume "$token" "$pubkey_b64" "$push_addr")"
printf 'nc_replay_seq_response=%s\n' "$seq_resp"

wire_consume "$token" "$pubkey_b64" "$push_addr" > /tmp/nc-c1.$$ 2>/dev/null &
c1=$!
wire_consume "$token" "$pubkey_b64" "$push_addr" > /tmp/nc-c2.$$ 2>/dev/null &
c2=$!
wait "$c1"; wait "$c2"
printf 'nc_replay_c1_response=%s\n' "$(cat /tmp/nc-c1.$$)"
printf 'nc_replay_c2_response=%s\n' "$(cat /tmp/nc-c2.$$)"
rm -f /tmp/nc-c1.$$ /tmp/nc-c2.$$

verify_out="$(/usr/local/bin/rustynet enrollment verify --secret "$secret" --token "$token" --ledger "$ledger" 2>&1)"
printf 'nc_verify_output=%s\n' "$(printf '%s' "$verify_out" | tr -d '\r' | tr ' ' '\n' | grep -E '^(already_consumed|valid)=' | tr '\n' ' ')"

ledger_after_rows="$(sed -n 's/^consumed_exp=//p' "$ledger" | tr ',' '\n' | grep -c .)"
printf 'nc_ledger_rows_after=%s\n' "$ledger_after_rows"
token_rows="$(sed -n 's/^consumed_exp=//p' "$ledger" | tr ',' '\n' | grep -c "^$token_hex:")"
printf 'nc_token_rows=%s\n' "$token_rows"

snap_after="$(sha256sum "$snapshot" | cut -d" " -f1)"
printf 'nc_snapshot_sha_after=%s\n' "$snap_after"

if systemctl is-active --quiet rustynetd; then
  printf 'nc_unit_after=active\n'
else
  printf 'nc_unit_after=inactive\n'
fi
exit 0
"#;

    /// What the transcript parser may conclude. Only a fully-parsed
    /// [`ReplayObservation`] is adjudicable; every hole is fail-closed.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) enum ReplayParse {
        Observed(ReplayObservation),
        NotAdjudicable { reason: String },
    }

    /// One parsed attack transcript. Every field is an independent detection
    /// datum; the adjudicator consumes all of them.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct ReplayObservation {
        pub(crate) listener_bound: bool,
        pub(crate) ledger_rows_before: usize,
        pub(crate) snapshot_sha_before: String,
        pub(crate) genuine_response: String,
        pub(crate) snapshot_sha_after_genuine: String,
        pub(crate) replay_seq_response: String,
        pub(crate) replay_c1_response: String,
        pub(crate) replay_c2_response: String,
        pub(crate) verify_already_consumed: Option<bool>,
        pub(crate) verify_valid: Option<bool>,
        pub(crate) ledger_rows_after: usize,
        pub(crate) token_rows: usize,
        pub(crate) snapshot_sha_after: String,
        pub(crate) unit_after: String,
    }

    /// Parse the `nc_*` token transcript. Garbled/contradictory transcripts
    /// are `NotAdjudicable` (never adjudicated into a pass).
    pub(crate) fn parse_replay_transcript(exit_code: i32, stdout: &str) -> ReplayParse {
        if exit_code != 0 {
            return ReplayParse::NotAdjudicable {
                reason: format!("attack script infrastructure failed (exit {exit_code})"),
            };
        }
        let mut map = std::collections::HashMap::new();
        for line in stdout.lines() {
            if let Some((key, value)) = line.trim().split_once('=')
                && key.starts_with("nc_")
            {
                map.insert(key.trim_start_matches("nc_"), value);
            }
        }
        if let Some(abort) = map.get("abort") {
            return ReplayParse::NotAdjudicable {
                reason: format!("attack script aborted: {abort}"),
            };
        }
        let mut holes: Vec<String> = Vec::new();
        let need = |key: &str, holes: &mut Vec<String>| -> Option<String> {
            match map.get(key) {
                Some(v) => Some((*v).to_owned()),
                None => {
                    holes.push(format!("missing nc_{key} token"));
                    None
                }
            }
        };
        let listener_bound = match need("listener_bound", &mut holes).as_deref() {
            Some("true") => true,
            Some(other) => {
                holes.push(format!("nc_listener_bound={other:?} is not true"));
                false
            }
            None => false,
        };
        let parse_usize = |raw: Option<String>, key: &str, holes: &mut Vec<String>| -> usize {
            match raw.and_then(|v| v.parse::<usize>().ok()) {
                Some(v) => v,
                None => {
                    holes.push(format!("nc_{key} is missing or not a row count"));
                    0
                }
            }
        };
        let ledger_rows_before = parse_usize(
            need("ledger_rows_before", &mut holes),
            "ledger_rows_before",
            &mut holes,
        );
        let ledger_rows_after = parse_usize(
            need("ledger_rows_after", &mut holes),
            "ledger_rows_after",
            &mut holes,
        );
        let token_rows = parse_usize(need("token_rows", &mut holes), "token_rows", &mut holes);
        let _genuine_required = need("genuine_response", &mut holes);
        let verify_output = need("verify_output", &mut holes);
        let flag = |prefix: &str| -> Option<bool> {
            verify_output.as_deref().and_then(|out| {
                out.split_whitespace()
                    .find_map(|field| field.strip_prefix(prefix).map(|v| v == "true"))
            })
        };
        let verify_already_consumed = flag("already_consumed=");
        if verify_already_consumed.is_none() {
            holes.push("verify output carries no already_consumed field".to_owned());
        }
        let verify_valid = flag("valid=");
        if verify_valid.is_none() {
            holes.push("verify output carries no valid field".to_owned());
        }
        if !holes.is_empty() {
            return ReplayParse::NotAdjudicable {
                reason: format!("garbled transcript: {}", holes.join("; ")),
            };
        }
        let str_field = |key: &str| map.get(key).map(|v| (*v).to_owned()).unwrap_or_default();
        ReplayParse::Observed(ReplayObservation {
            listener_bound,
            ledger_rows_before,
            snapshot_sha_before: str_field("snapshot_sha_before"),
            genuine_response: str_field("genuine_response"),
            snapshot_sha_after_genuine: str_field("snapshot_sha_after_genuine"),
            replay_seq_response: str_field("replay_seq_response"),
            replay_c1_response: str_field("replay_c1_response"),
            replay_c2_response: str_field("replay_c2_response"),
            verify_already_consumed,
            verify_valid,
            ledger_rows_after,
            token_rows,
            snapshot_sha_after: str_field("snapshot_sha_after"),
            unit_after: map
                .get("unit_after")
                .map(|v| (*v).to_owned())
                .unwrap_or_else(|| "unknown".to_owned()),
        })
    }

    // ── pure adjudication (the inversion) ────────────────────────────────

    /// The control verdict. Pass requires ALL of: listener proven bound;
    /// genuine consume `OK …`; BOTH replays (sequential + both concurrent)
    /// refused with the handler's exact fixed-vocabulary rejection; verify
    /// reports `already_consumed=true valid=false` from the on-disk ledger;
    /// the ledger gained EXACTLY ONE row and this token's id appears exactly
    /// once; the membership snapshot is byte-identical across the replays;
    /// the daemon unit is still active (teardown bar).
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) enum ReplayControlOutcome {
        /// Every detection half held AND the accept-leg fired. Control PASSES.
        ReplayRejectedLedgerSingleton,
        /// A replay was ACCEPTED — the fail-open this control exists to catch.
        ReplayAccepted {
            which: &'static str,
            response: String,
        },
        /// Rejected, but not with the named fixed-vocabulary refusal.
        WrongReasonRejection {
            which: &'static str,
            response: String,
        },
        /// The genuine (first) consume did not succeed — the accept-leg is
        /// broken, so "replays rejected" is vacuous.
        GenuineConsumeBroken { response: String },
        /// The on-disk ledger does not show exactly one consumed row for this
        /// token (double-consume, or the verify flag disagrees with the spool).
        LedgerNotSingleton { detail: String },
        /// The membership snapshot moved across the replays (state changed).
        SnapshotDrift { before: String, after: String },
        /// The inspect path did not report already_consumed=true + valid=false.
        VerifyFlagMismatch {
            already_consumed: Option<bool>,
            valid: Option<bool>,
        },
        /// Precondition of the attack itself unmet (listener not bound).
        ListenerNeverBound,
        /// The daemon was left inactive by the attack.
        UnitNotActiveAfter,
    }

    impl ReplayControlOutcome {
        pub(crate) fn is_control_pass(&self) -> bool {
            matches!(self, ReplayControlOutcome::ReplayRejectedLedgerSingleton)
        }
    }

    pub(crate) fn adjudicate_replay(o: &ReplayObservation) -> ReplayControlOutcome {
        if !o.listener_bound {
            return ReplayControlOutcome::ListenerNeverBound;
        }
        if !o.genuine_response.starts_with("OK ") {
            return ReplayControlOutcome::GenuineConsumeBroken {
                response: o.genuine_response.clone(),
            };
        }
        for (which, response) in [
            ("sequential", &o.replay_seq_response),
            ("concurrent_1", &o.replay_c1_response),
            ("concurrent_2", &o.replay_c2_response),
        ] {
            if response.starts_with("OK ") {
                return ReplayControlOutcome::ReplayAccepted {
                    which,
                    response: response.clone(),
                };
            }
            if response != TOKEN_REJECTED_REFUSAL {
                return ReplayControlOutcome::WrongReasonRejection {
                    which,
                    response: response.clone(),
                };
            }
        }
        if o.verify_already_consumed != Some(true) || o.verify_valid != Some(false) {
            return ReplayControlOutcome::VerifyFlagMismatch {
                already_consumed: o.verify_already_consumed,
                valid: o.verify_valid,
            };
        }
        if o.ledger_rows_after != o.ledger_rows_before + 1 || o.token_rows != 1 {
            return ReplayControlOutcome::LedgerNotSingleton {
                detail: format!(
                    "rows {} -> {} (expected +1), token id appears {} time(s) (expected 1)",
                    o.ledger_rows_before, o.ledger_rows_after, o.token_rows
                ),
            };
        }
        if o.snapshot_sha_after != o.snapshot_sha_after_genuine {
            return ReplayControlOutcome::SnapshotDrift {
                before: o.snapshot_sha_after_genuine.clone(),
                after: o.snapshot_sha_after.clone(),
            };
        }
        if o.unit_after != "active" {
            return ReplayControlOutcome::UnitNotActiveAfter;
        }
        ReplayControlOutcome::ReplayRejectedLedgerSingleton
    }

    // ── teardown adjudication (the drop-in lifecycle) ────────────────────

    /// Verified drop-in teardown: the file must be ABSENT and the unit ACTIVE
    /// after the restore restart, else the guest is left sabotaged (a leak
    /// named loudly). Idempotent-delete semantics: a failed `rm` with the file
    /// verifiably absent is fine.
    pub(crate) fn adjudicate_teardown(
        rm_exit: i32,
        stat_present: Option<bool>,
        unit_active: bool,
    ) -> Result<(), String> {
        match stat_present {
            None => Err(
                "teardown unverifiable (fail closed): cannot stat the drop-in after delete"
                    .to_owned(),
            ),
            Some(true) => Err(format!(
                "TEARDOWN LEAK: drop-in {DROPIN_PATH} is still installed after delete \
                 (rm exit {rm_exit}) — the guest's daemon keeps the enrollment listener"
            )),
            Some(false) if !unit_active => Err(format!(
                "TEARDOWN LEAK: drop-in removed but {RUSTYNETD_UNIT} is not active after \
                 the restore restart — the guest is left degraded"
            )),
            Some(false) => Ok(()),
        }
    }

    // ── remote plumbing ───────────────────────────────────────────────────

    struct RemoteCommandOutput {
        code: i32,
        stdout: String,
        stderr: String,
    }

    impl RemoteCommandOutput {
        fn from_status(status: RemoteExitStatus) -> Self {
            RemoteCommandOutput {
                code: status.code,
                stdout: String::from_utf8_lossy(&status.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&status.stderr).into_owned(),
            }
        }
        fn render(&self, label: &str) -> String {
            format!(
                "## {label}\nexit={}\n--- stdout ---\n{}\n--- stderr ---\n{}\n",
                self.code, self.stdout, self.stderr
            )
        }
    }

    fn run_remote_argv(
        shell: &Arc<dyn RemoteShellHost>,
        argv: &[&str],
    ) -> Result<RemoteCommandOutput, String> {
        shell
            .run_argv(argv, &[], &[])
            .map(RemoteCommandOutput::from_status)
            .map_err(|err| format!("transport failure running {argv:?}: {err}"))
    }

    fn write_evidence(dir: &Path, name: &str, contents: &str) -> Result<(), String> {
        std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        let path = dir.join(name);
        std::fs::write(&path, contents).map_err(|e| format!("write {}: {e}", path.display()))
    }

    fn unit_is_active(shell: &Arc<dyn RemoteShellHost>) -> Result<bool, String> {
        let active = run_remote_argv(shell, &["systemctl", "is-active", RUSTYNETD_UNIT])?;
        Ok(active.code == 0 && active.stdout.trim() == "active")
    }

    fn restart_and_wait_unit(shell: &Arc<dyn RemoteShellHost>) -> Result<(), String> {
        let _ = run_remote_argv(shell, &["systemctl", "reset-failed", RUSTYNETD_UNIT])?;
        let restart = run_remote_argv(shell, &["systemctl", "restart", RUSTYNETD_UNIT])?;
        if restart.code != 0 {
            return Err(format!(
                "systemctl restart {RUSTYNETD_UNIT} exited {} (stderr: {:?})",
                restart.code,
                restart.stderr.trim()
            ));
        }
        for _ in 0..WAIT_TRIES {
            if unit_is_active(shell)? {
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        Err(format!(
            "{RUSTYNETD_UNIT} did not reach active within {WAIT_TRIES}s of the restart"
        ))
    }

    /// The transcript file name, shared by the writer and the catalog pin.
    pub(crate) const REPLAY_TRANSCRIPT_FILE: &str = "replay_transcript.txt";

    /// The (QH-89) control body. A working control returns
    /// [`StageOutcome::Passed`] (the induced replays were all rejected and
    /// every independent detection datum held).
    pub(crate) fn run_enrollment_replay_control(
        workdir: &Path,
        report_dir: &Path,
        target_alias: &str,
        adapter: &dyn NodeAdapter,
        enrollee_host: &str,
    ) -> StageOutcome {
        let fail = |reason: String| {
            StageOutcome::Failed(format!(
                "enrollment-replay negative control [target {target_alias}]: {reason}"
            ))
        };
        if adapter.platform() != VmGuestPlatform::Linux {
            return fail(format!(
                "target platform {:?} cannot host the systemd drop-in + listener attack \
                 (fail closed)",
                adapter.platform()
            ));
        }
        let shell = match adapter.shell_host() {
            Ok(shell) => shell,
            Err(err) => return fail(format!("no remote shell host: {err}")),
        };

        // 1. Baseline: unit active, secret present, snapshot + ledger
        //    readable, and NO leftover drop-in (ambiguity guard).
        let baseline_unit = match unit_is_active(&shell) {
            Ok(active) => active,
            Err(err) => return fail(err),
        };
        if !baseline_unit {
            return fail(format!(
                "baseline not applicable: {RUSTYNETD_UNIT} is not active (must be active \
                 before the attack, fail closed)"
            ));
        }
        let secret = match run_remote_argv(&shell, &["test", "-s", ENROLLMENT_SECRET_PATH]) {
            Ok(out) => out,
            Err(err) => return fail(err),
        };
        if secret.code != 0 {
            // Topology/config gap: this node carries no anchor enrollment
            // state, so the attack target does not exist here. Named skip.
            return StageOutcome::Skipped(format!(
                "no enrollment secret at {ENROLLMENT_SECRET_PATH} on {target_alias}; this \
                 node carries no anchor enrollment state"
            ));
        }
        for (label, path) in [
            ("membership snapshot", MEMBERSHIP_SNAPSHOT_PATH),
            ("enrollment ledger", ENROLLMENT_LEDGER_PATH),
        ] {
            let probe = match run_remote_argv(&shell, &["test", "-f", path]) {
                Ok(out) => out,
                Err(err) => return fail(err),
            };
            if probe.code != 0 {
                return fail(format!(
                    "baseline not applicable: {label} missing at {path} (fail closed)"
                ));
            }
        }
        let leftover = match run_remote_argv(&shell, &["test", "-e", DROPIN_PATH]) {
            Ok(out) => out,
            Err(err) => return fail(err),
        };
        if leftover.code == 0 {
            return fail(format!(
                "ambiguous leftover: drop-in {DROPIN_PATH} already exists (a prior control \
                 leaked) — refusing to adjudicate"
            ));
        }

        // 2. Enable the listener: stage the drop-in, install as root,
        //    reload, restart, and verify the listener came up.
        if let Err(err) = shell.write_file(DROPIN_STAGE_PATH, DROPIN_CONTENT.as_bytes(), 0o644) {
            return fail(format!("stage drop-in at {DROPIN_STAGE_PATH}: {err}"));
        }
        let mkdir = match run_remote_argv(&shell, &["mkdir", "-p", DROPIN_DIR]) {
            Ok(out) => out,
            Err(err) => return fail(err),
        };
        if mkdir.code != 0 {
            return fail(format!(
                "cannot create {DROPIN_DIR}: {} (fail closed)",
                mkdir.stderr.trim()
            ));
        }
        let install = match run_remote_argv(
            &shell,
            &["install", "-m", "0644", DROPIN_STAGE_PATH, DROPIN_PATH],
        ) {
            Ok(out) => out,
            Err(err) => return fail(err),
        };
        if install.code != 0 {
            let teardown = best_effort_disable(&shell);
            return fail(format!(
                "cannot install drop-in {DROPIN_PATH}: {} (fail closed); teardown: {}",
                install.stderr.trim(),
                teardown.err().unwrap_or_else(|| "verified".to_owned())
            ));
        }
        if let Err(err) = run_remote_argv(&shell, &["systemctl", "daemon-reload"]) {
            let teardown = best_effort_disable(&shell);
            return fail(format!(
                "systemctl daemon-reload failed: {err} (fail closed); teardown: {}",
                teardown.err().unwrap_or_else(|| "verified".to_owned())
            ));
        }
        if let Err(err) = restart_and_wait_unit(&shell) {
            let teardown = best_effort_disable(&shell);
            return fail(format!(
                "{err} (fail closed); teardown: {}",
                teardown.err().unwrap_or_else(|| "verified".to_owned())
            ));
        }
        let probe = run_remote_argv(
            &shell,
            &[
                "bash",
                "-c",
                "exec 3<>/dev/tcp/127.0.0.1/\"$1\" && exec 3>&- 3<&-",
                "nc-probe",
                LISTENER_PORT,
            ],
        );
        match probe {
            Ok(out) if out.code == 0 => {}
            Ok(out) => {
                let teardown = best_effort_disable(&shell);
                return fail(format!(
                    "listener {LISTENER_ADDR} did not come up after the drop-in restart \
                     (probe exit {}) — the attack cannot be delivered (fail closed); \
                     teardown: {}",
                    out.code,
                    teardown.err().unwrap_or_else(|| "verified".to_owned())
                ));
            }
            Err(err) => {
                let teardown = best_effort_disable(&shell);
                return fail(format!(
                    "listener probe transport failure: {err} (fail closed); teardown: {}",
                    teardown.err().unwrap_or_else(|| "verified".to_owned())
                ));
            }
        }

        // 3. Mint the token (admin CLI on the anchor itself) and derive the
        //    token id hex host-side so the ledger row can be bound to THIS
        //    token.
        let mint = match run_remote_argv(
            &shell,
            &[
                REMOTE_CLI,
                "enrollment",
                "mint",
                "--secret",
                ENROLLMENT_SECRET_PATH,
                "--ttl",
                "300",
            ],
        ) {
            Ok(out) => out,
            Err(err) => {
                let teardown = best_effort_disable(&shell);
                return fail(format!(
                    "{err}; teardown: {}",
                    teardown.err().unwrap_or_else(|| "verified".to_owned())
                ));
            }
        };
        let token = mint.stdout.trim().to_owned();
        if token.is_empty() || token.split_whitespace().count() != 1 {
            let teardown = best_effort_disable(&shell);
            return fail(format!(
                "enrollment mint did not return a bare token (stdout: {:?}); teardown: {}",
                mint.stdout,
                teardown.err().unwrap_or_else(|| "verified".to_owned())
            ));
        }
        let token_id_hex = match rustynetd::enrollment_token::decode_token(&token) {
            Ok(t) => t
                .token_id
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            Err(err) => {
                let teardown = best_effort_disable(&shell);
                return fail(format!(
                    "cannot decode minted token to bind its ledger row: {err}; teardown: {}",
                    teardown.err().unwrap_or_else(|| "verified".to_owned())
                ));
            }
        };
        if enrollee_host.is_empty() {
            let teardown = best_effort_disable(&shell);
            return fail(format!(
                "no endpoint recorded for the aux enrollee (orchestrator collection empty); \
                 cannot form the push address (fail closed); teardown: {}",
                teardown.err().unwrap_or_else(|| "verified".to_owned())
            ));
        }
        let push_addr = format!("{enrollee_host}:{GOSSIP_PORT}");
        let pubkey_b64 = enrollee_pubkey_b64();

        // 4. Deliver the attack. From here teardown is mandatory + verified
        //    on every path.
        let script_status = shell.run_argv(
            &[
                "bash",
                "-c",
                ATTACK_SCRIPT,
                "nc-replay",
                token_id_hex.as_str(),
                ENROLLMENT_SECRET_PATH,
                ENROLLMENT_LEDGER_PATH,
                MEMBERSHIP_SNAPSHOT_PATH,
                LISTENER_PORT,
                push_addr.as_str(),
                pubkey_b64.as_str(),
                token.as_str(),
            ],
            &[],
            &[],
        );
        let (script_exit, script_stdout, script_stderr) = match script_status {
            Ok(status) => (
                status.code,
                String::from_utf8_lossy(&status.stdout).into_owned(),
                String::from_utf8_lossy(&status.stderr).into_owned(),
            ),
            Err(err) => {
                let (teardown_evidence, teardown_verdict) = teardown_dropin_verified(&shell);
                let _ = write_evidence(
                    workdir,
                    REPLAY_TRANSCRIPT_FILE,
                    &format!("## attack delivery\ntransport failure: {err}\n{teardown_evidence}"),
                );
                return fail(format!(
                    "transport failure delivering the attack: {err}; teardown: {}",
                    teardown_verdict
                        .err()
                        .unwrap_or_else(|| "verified".to_owned())
                ));
            }
        };
        let mut evidence = format!(
            "## attack delivery\nexit={script_exit}\n--- stdout ---\n{script_stdout}\n--- \
             stderr ---\n{script_stderr}\n"
        );

        // 5. Verified teardown — a leak dominates every other verdict.
        let (teardown_evidence, teardown_verdict) = teardown_dropin_verified(&shell);
        evidence.push_str(&teardown_evidence);
        if let Err(err) = teardown_verdict {
            evidence.push_str("## adjudication\nnot run (teardown leak)\n");
            let _ = write_evidence(workdir, REPLAY_TRANSCRIPT_FILE, &evidence);
            return fail(err);
        }

        // 6. Adjudicate the attack + persist the declared witness.
        let observation = match parse_replay_transcript(script_exit, &script_stdout) {
            ReplayParse::Observed(o) => o,
            ReplayParse::NotAdjudicable { reason } => {
                evidence.push_str(&format!("## adjudication\nnot adjudicable: {reason}\n"));
                let _ = write_evidence(workdir, REPLAY_TRANSCRIPT_FILE, &evidence);
                return fail(format!(
                    "{reason}; the attack was delivered but the outcome is not provable \
                     (fail closed)"
                ));
            }
        };
        let verdict = adjudicate_replay(&observation);
        evidence.push_str(&format!("## adjudication\n{verdict:?}\n"));
        if let Err(err) = write_evidence(workdir, REPLAY_TRANSCRIPT_FILE, &evidence) {
            return fail(format!(
                "evidence not persisted: {err} (fail closed; the witness is the declared \
                 File artifact)"
            ));
        }
        match verdict {
            ReplayControlOutcome::ReplayRejectedLedgerSingleton => {
                // QH-83 stage-log witness: the inversion line on the ONLY
                // pass arm.
                if let Err(err) = append_stage_evidence_line(
                    report_dir,
                    StageId::NegativeControlEnrollmentTokenReplay.as_str(),
                    &format!(
                        "negative_control=enrollment_token_replay target={target_alias} \
                         sabotage=token_replay_sequential_and_concurrent_over_live_listener \
                         detection=replays_rejected_ledger_singleton_snapshot_fixed \
                         accept_leg=genuine_consume_ok teardown=verified"
                    ),
                ) {
                    return StageOutcome::Failed(format!(
                        "enrollment-replay negative control: witness write failed: {err}"
                    ));
                }
                StageOutcome::Passed
            }
            ReplayControlOutcome::ReplayAccepted { which, response } => fail(format!(
                "FAIL-OPEN — the {which} replay was ACCEPTED ({response:?}); a single-use \
                 token was redeemed twice on the live listener"
            )),
            ReplayControlOutcome::WrongReasonRejection { which, response } => fail(format!(
                "the {which} replay was rejected for the WRONG reason — expected \
                 {TOKEN_REJECTED_REFUSAL:?}, got {response:?}"
            )),
            ReplayControlOutcome::GenuineConsumeBroken { response } => fail(format!(
                "positive control broken — the genuine first consume did not succeed \
                 ({response:?}); the replays prove nothing"
            )),
            ReplayControlOutcome::LedgerNotSingleton { detail } => fail(format!(
                "the consumed-token ledger is not a singleton for this token: {detail}"
            )),
            ReplayControlOutcome::SnapshotDrift { before, after } => fail(format!(
                "the membership snapshot MOVED across the replays (sha {before} -> {after})"
            )),
            ReplayControlOutcome::VerifyFlagMismatch {
                already_consumed,
                valid,
            } => fail(format!(
                "enrollment verify (on-disk inspect) did not report \
                 already_consumed=true/valid=false (got {already_consumed:?}/{valid:?})"
            )),
            ReplayControlOutcome::ListenerNeverBound => fail(
                "the listener was never proven bound — the attack was never delivered (fail \
                 closed)"
                    .to_owned(),
            ),
            ReplayControlOutcome::UnitNotActiveAfter => fail(format!(
                "{RUSTYNETD_UNIT} is not active after the attack — the daemon did not \
                 survive its own replay defence (teardown bar)"
            )),
        }
    }

    /// Drop-in removal for early-return paths — VERIFIED, best-effort in
    /// effect only: it deletes the drop-in, reloads, restarts, and re-checks
    /// absence + unit active. A residual error is returned so EVERY caller
    /// can append it to its fail reason (a leak must dominate and be named,
    /// tough-policy rule 4); it never silently swallows a leak.
    fn best_effort_disable(shell: &Arc<dyn RemoteShellHost>) -> Result<(), String> {
        let rm = run_remote_argv(shell, &["rm", "-f", DROPIN_PATH]);
        let rm_exit = rm.as_ref().map(|o| o.code).unwrap_or(-1);
        if let Err(err) = run_remote_argv(shell, &["systemctl", "daemon-reload"]) {
            return Err(format!("daemon-reload after rm failed: {err}"));
        }
        let unit_active = restart_and_wait_unit(shell);
        let stat = run_remote_argv(shell, &["test", "-e", DROPIN_PATH]);
        let stat_present = match &stat {
            Ok(out) => Some(out.code == 0),
            Err(_) => None,
        };
        adjudicate_teardown(rm_exit, stat_present, unit_active.is_ok())
    }

    /// Verified teardown: delete the drop-in, reload, restart, then assert
    /// (a) the drop-in is absent (stat) and (b) the unit is active. Returns
    /// the evidence rendering + the verdict.
    fn teardown_dropin_verified(shell: &Arc<dyn RemoteShellHost>) -> (String, Result<(), String>) {
        let rm = run_remote_argv(shell, &["rm", "-f", DROPIN_PATH]);
        let rm_exit = rm.as_ref().map(|o| o.code).unwrap_or(-1);
        let mut evidence = match &rm {
            Ok(out) => out.render(&format!("rm -f {DROPIN_PATH}")),
            Err(err) => format!("## rm -f {DROPIN_PATH}\n{err}\n"),
        };
        if let Err(err) = run_remote_argv(shell, &["systemctl", "daemon-reload"]) {
            evidence.push_str(&format!("## systemctl daemon-reload\n{err}\n"));
        }
        let restart = restart_and_wait_unit(shell);
        if let Err(err) = &restart {
            evidence.push_str(&format!("## restore restart\n{err}\n"));
        }
        let stat = run_remote_argv(shell, &["test", "-e", DROPIN_PATH]);
        let stat_present = match &stat {
            Ok(out) => Some(out.code == 0),
            Err(_) => None,
        };
        let unit_active = restart.is_ok();
        let verdict = adjudicate_teardown(rm_exit, stat_present, unit_active);
        evidence.push_str(&format!("## teardown verdict\n{verdict:?}\n"));
        (evidence, verdict)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn observation() -> ReplayObservation {
            ReplayObservation {
                listener_bound: true,
                ledger_rows_before: 4,
                snapshot_sha_before: "aaa".to_owned(),
                genuine_response: "OK enrollment accepted node=abcd1234 expires_at_unix=1"
                    .to_owned(),
                snapshot_sha_after_genuine: "bbb".to_owned(),
                replay_seq_response: TOKEN_REJECTED_REFUSAL.to_owned(),
                replay_c1_response: TOKEN_REJECTED_REFUSAL.to_owned(),
                replay_c2_response: TOKEN_REJECTED_REFUSAL.to_owned(),
                verify_already_consumed: Some(true),
                verify_valid: Some(false),
                ledger_rows_after: 5,
                token_rows: 1,
                snapshot_sha_after: "bbb".to_owned(),
                unit_after: "active".to_owned(),
            }
        }

        fn transcript(o: &ReplayObservation) -> String {
            format!(
                "nc_listener_bound={}\n\
                 nc_ledger_rows_before={}\n\
                 nc_snapshot_sha_before={}\n\
                 nc_genuine_response={}\n\
                 nc_snapshot_sha_after_genuine={}\n\
                 nc_replay_seq_response={}\n\
                 nc_replay_c1_response={}\n\
                 nc_replay_c2_response={}\n\
                 nc_verify_output=already_consumed={} valid={}\n\
                 nc_ledger_rows_after={}\n\
                 nc_token_rows={}\n\
                 nc_snapshot_sha_after={}\n\
                 nc_unit_after={}\n",
                o.listener_bound,
                o.ledger_rows_before,
                o.snapshot_sha_before,
                o.genuine_response,
                o.snapshot_sha_after_genuine,
                o.replay_seq_response,
                o.replay_c1_response,
                o.replay_c2_response,
                o.verify_already_consumed.unwrap(),
                o.verify_valid.unwrap(),
                o.ledger_rows_after,
                o.token_rows,
                o.snapshot_sha_after,
                o.unit_after,
            )
        }

        #[test]
        fn healthy_attack_is_a_control_pass() {
            let o = observation();
            let parsed = match parse_replay_transcript(0, &transcript(&o)) {
                ReplayParse::Observed(o) => o,
                other => panic!("healthy transcript must parse, got {other:?}"),
            };
            assert_eq!(parsed, o);
            assert!(adjudicate_replay(&parsed).is_control_pass());
        }

        #[test]
        fn mutation_replay_accepted_is_the_fail_open_not_a_pass() {
            // The detection half this control exists for: a daemon that
            // redeems the token twice must turn the control RED.
            let mut o = observation();
            o.replay_seq_response =
                "OK enrollment accepted node=abcd1234 expires_at_unix=1".to_owned();
            let verdict = adjudicate_replay(&o);
            assert!(!verdict.is_control_pass());
            assert!(matches!(
                verdict,
                ReplayControlOutcome::ReplayAccepted {
                    which: "sequential",
                    ..
                }
            ));
        }

        #[test]
        fn mutation_concurrent_double_accept_is_caught() {
            let mut o = observation();
            o.replay_c2_response =
                "OK enrollment accepted node=abcd1234 expires_at_unix=1".to_owned();
            assert!(matches!(
                adjudicate_replay(&o),
                ReplayControlOutcome::ReplayAccepted {
                    which: "concurrent_2",
                    ..
                }
            ));
        }

        #[test]
        fn mutation_wrong_reason_rejection_is_not_a_pass() {
            let mut o = observation();
            o.replay_seq_response = "ERR enrollee pubkey decode failed".to_owned();
            assert!(matches!(
                adjudicate_replay(&o),
                ReplayControlOutcome::WrongReasonRejection { .. }
            ));
        }

        #[test]
        fn mutation_genuine_broken_is_not_a_pass() {
            let mut o = observation();
            o.genuine_response = TOKEN_REJECTED_REFUSAL.to_owned();
            assert!(matches!(
                adjudicate_replay(&o),
                ReplayControlOutcome::GenuineConsumeBroken { .. }
            ));
        }

        #[test]
        fn mutation_ledger_double_row_is_not_a_pass() {
            let mut o = observation();
            o.ledger_rows_after = 6;
            assert!(matches!(
                adjudicate_replay(&o),
                ReplayControlOutcome::LedgerNotSingleton { .. }
            ));
            let mut o2 = observation();
            o2.token_rows = 2;
            assert!(matches!(
                adjudicate_replay(&o2),
                ReplayControlOutcome::LedgerNotSingleton { .. }
            ));
        }

        #[test]
        fn mutation_snapshot_drift_is_not_a_pass() {
            let mut o = observation();
            o.snapshot_sha_after = "ccc".to_owned();
            assert!(matches!(
                adjudicate_replay(&o),
                ReplayControlOutcome::SnapshotDrift { .. }
            ));
        }

        #[test]
        fn mutation_verify_flag_mismatch_is_not_a_pass() {
            let mut o = observation();
            o.verify_already_consumed = Some(false);
            assert!(matches!(
                adjudicate_replay(&o),
                ReplayControlOutcome::VerifyFlagMismatch { .. }
            ));
        }

        #[test]
        fn guard_listener_never_bound_and_dead_unit_are_not_passes() {
            let mut o = observation();
            o.listener_bound = false;
            assert!(!adjudicate_replay(&o).is_control_pass());
            let mut o2 = observation();
            o2.unit_after = "inactive".to_owned();
            assert!(!adjudicate_replay(&o2).is_control_pass());
        }

        #[test]
        fn guard_infra_failures_refuse_adjudication() {
            let healthy = transcript(&observation());
            let no_genuine = healthy.replace("nc_genuine_response=OK", "nc_genuine=OK");
            for (exit, stdout) in [
                (1, healthy.as_str()),
                (0, "no tokens at all\n"),
                (0, "nc_listener_bound=true\n"),
                (0, no_genuine.as_str()),
            ] {
                let parsed = parse_replay_transcript(exit, stdout);
                assert!(
                    matches!(parsed, ReplayParse::NotAdjudicable { .. }),
                    "exit={exit} stdout={stdout:?} must not adjudicate"
                );
            }
        }

        #[test]
        fn guard_abort_token_refuses_adjudication() {
            let parsed = parse_replay_transcript(0, "nc_abort=listener_not_bound\n");
            let ReplayParse::NotAdjudicable { reason } = parsed else {
                panic!("abort must refuse adjudication");
            };
            assert!(reason.contains("listener_not_bound"), "{reason}");
        }

        #[test]
        fn script_binds_the_attack_sequence_and_detection_fields() {
            // Listener proven before any token byte is spent.
            let bind = ATTACK_SCRIPT
                .find("nc_listener_bound=")
                .expect("bind marker");
            let ledger_before = ATTACK_SCRIPT
                .find("nc_ledger_rows_before=")
                .expect("baseline marker");
            let genuine = ATTACK_SCRIPT
                .find("nc_genuine_response=")
                .expect("genuine marker");
            let snap_genuine = ATTACK_SCRIPT
                .find("nc_snapshot_sha_after_genuine=")
                .expect("post-genuine marker");
            let replay = ATTACK_SCRIPT
                .find("nc_replay_seq_response=")
                .expect("replay marker");
            let verify = ATTACK_SCRIPT
                .find("nc_verify_output=")
                .expect("verify marker");
            let token_rows = ATTACK_SCRIPT
                .find("nc_token_rows=")
                .expect("token-rows marker");
            assert!(
                bind < ledger_before && ledger_before < genuine,
                "listener proof + ledger baseline must precede the genuine consume"
            );
            assert!(
                genuine < snap_genuine,
                "the post-genuine snapshot digest follows the accept"
            );
            assert!(
                snap_genuine < replay,
                "the genuine consume must precede the replays"
            );
            assert!(
                replay < verify,
                "the verify (inspect) + ledger counts run last"
            );
            assert!(
                token_rows > verify,
                "the token-row count is a post-replay datum"
            );
            // The two concurrent replays both START before either is waited on.
            let c1 = ATTACK_SCRIPT.find("c1=$!").expect("c1 start");
            let c2 = ATTACK_SCRIPT.find("c2=$!").expect("c2 start");
            let wait = ATTACK_SCRIPT.find("wait \"$c1\"").expect("wait");
            assert!(
                c1 < c2 && c2 < wait,
                "both replays must start before either is waited"
            );
            // The independent-detection fields exist in the wire format the
            // daemon serves and the ledger spool the stage parses.
            assert!(ATTACK_SCRIPT.contains("already_consumed"));
            assert!(ATTACK_SCRIPT.contains("consumed_exp="));
        }

        #[test]
        fn enrollee_pubkey_decodes_to_a_valid_ed25519_point() {
            // The daemon's handler runs VerifyingKey::from_bytes and rejects
            // invalid points; the throwaway key must be a REAL key.
            use base64::Engine as _;
            use ed25519_dalek::VerifyingKey;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(enrollee_pubkey_b64())
                .expect("b64");
            assert_eq!(bytes.len(), 32);
            VerifyingKey::from_bytes(&bytes.try_into().unwrap()).expect("valid point");
        }

        #[test]
        fn target_selection_prefers_anchor_then_exit_and_requires_linux() {
            use crate::vm_lab::orchestrator::role::NodeRole;
            fn assignment(alias: &str, role: NodeRole) -> NodeRoleAssignment {
                NodeRoleAssignment {
                    alias: alias.to_owned(),
                    role,
                }
            }
            let linux = |alias: &str| match alias {
                "mac-exit" => Some(VmGuestPlatform::Macos),
                _ => Some(VmGuestPlatform::Linux),
            };
            let both = vec![
                assignment("exit-1", NodeRole::Exit),
                assignment("anchor-1", NodeRole::Anchor),
            ];
            assert_eq!(
                select_linux_enrollment_target(&both, &linux),
                Ok("anchor-1"),
                "the dedicated anchor role wins"
            );
            let exit_only = vec![
                assignment("mac-exit", NodeRole::Exit),
                assignment("exit-1", NodeRole::Exit),
            ];
            assert_eq!(
                select_linux_enrollment_target(&exit_only, &linux),
                Ok("exit-1"),
                "the Linux exit wins over a non-Linux exit"
            );
            let none = vec![assignment("client-1", NodeRole::Client)];
            assert!(select_linux_enrollment_target(&none, &linux).is_err());
        }

        #[test]
        fn precondition_gaps_are_named_not_absorbed() {
            use crate::vm_lab::orchestrator::role::NodeRole;
            fn assignment(alias: &str, role: NodeRole) -> NodeRoleAssignment {
                NodeRoleAssignment {
                    alias: alias.to_owned(),
                    role,
                }
            }
            let linux = |alias: &str| match alias {
                "m" | "m-aux" => Some(VmGuestPlatform::Macos),
                _ => Some(VmGuestPlatform::Linux),
            };
            // No Linux node.
            let mac_only = vec![
                assignment("m", NodeRole::Exit),
                assignment("m-aux", NodeRole::Aux),
            ];
            let gap = precondition_gap(&mac_only, &linux).expect("no-linux gap");
            assert!(gap.contains("no Linux node"), "{gap}");
            // Linux but no aux role.
            let no_aux = vec![assignment("exit-1", NodeRole::Exit)];
            let gap = precondition_gap(&no_aux, &linux).expect("no-aux gap");
            assert!(gap.contains("aux role"), "{gap}");
            // Both present.
            let full = vec![
                assignment("exit-1", NodeRole::Exit),
                assignment("aux-1", NodeRole::Aux),
            ];
            assert!(precondition_gap(&full, &linux).is_none());
            assert_eq!(select_aux_alias(&full).as_deref(), Some("aux-1"));
        }

        #[test]
        fn teardown_leak_and_unverifiable_fail_closed() {
            assert_eq!(adjudicate_teardown(0, Some(false), true), Ok(()));
            let leak = adjudicate_teardown(1, Some(true), true).expect_err("leak must fail");
            assert!(leak.contains("TEARDOWN LEAK"), "{leak}");
            let degraded =
                adjudicate_teardown(0, Some(false), false).expect_err("dead unit must fail");
            assert!(degraded.contains("not active"), "{degraded}");
            assert!(
                adjudicate_teardown(0, None, true).is_err(),
                "unverifiable must fail"
            );
        }

        #[test]
        fn stage_id_and_name_match_the_catalog() {
            use crate::vm_lab::orchestrator::stage::StageEvidence;
            let stage = NegativeControlEnrollmentTokenReplayStage;
            assert_eq!(stage.id(), StageId::NegativeControlEnrollmentTokenReplay);
            assert_eq!(stage.name(), "negative_control_enrollment_token_replay");
            assert_eq!(stage.fanout(), StageFanout::Once);
            assert!(stage.dependencies().is_empty());
            // The declared witness is the transcript this control writes on
            // its only pass path.
            assert_eq!(
                stage.id().evidence(),
                StageEvidence::File(REPLAY_TRANSCRIPT_RELATIVE)
            );
            assert!(REPLAY_TRANSCRIPT_RELATIVE.ends_with(REPLAY_TRANSCRIPT_FILE));
        }
    }
}
