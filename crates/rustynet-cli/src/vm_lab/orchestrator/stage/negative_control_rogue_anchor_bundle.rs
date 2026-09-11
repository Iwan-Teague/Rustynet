//! QH-87: the rogue anchor bundle negative control.
//!
//! The documented attack (FIS-0020 / A4 family): an attacker who can reach a
//! node's bundle-pull path presents a ROGUE membership bundle — self-consistent
//! but signed by attacker keys, a tampered state carrying a genuine
//! attestation, an epoch regression against the persisted watermark, or a
//! stale attestation — hoping the puller writes attacker-controlled membership
//! state to disk. The whole security claim of `rustynet anchor pull-bundle`
//! is the A4 enforcement point: the bundle is verified against the pinned
//! owner key and the persistent watermark BEFORE a single byte reaches the
//! output path ("no bytes written").
//!
//! The control mints exactly those forgeries IN-PROCESS (throwaway signing
//! keys, the real `rustynet-control` mint path: `sign_head_attestation` +
//! `render_membership_snapshot_body`), serves each one from a stage-run
//! loopback listener, and drives the REAL
//! `rustynet anchor pull-bundle` CLI against it on a lab node. Tough-policy
//! rule 2: detection is the puller's own exit status, its stderr, and
//! orchestrator-computed file hashes — never a daemon self-report.
//!
//! The inversion: the control returns [`StageOutcome::Passed`] iff (a) every
//! forgery pull exits non-zero, names the expected rejection class, and
//! leaves BOTH the guard output file and the watermark byte-identical, and
//! (b) the genuinely-signed control bundle is ACCEPTED end-to-end by the same
//! puller (bytes land, watermark persists). Any guest command error is
//! `Failed` (not adjudicable — fail closed). Offline triage: the same minted
//! bytes are run through `rustynet_control::membership::verify_attested_snapshot`
//! host-side so the expected rejection class is proven before shipping.

use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};
use crate::vm_lab::{VmGuestPlatform, sha256_hex_bytes};
use std::path::Path;

/// QH-87: the bypass control's on-disk pass witness — the per-forgery pull
/// transcripts, the rejection classes, the guard/watermark hashes, and the
/// control-accept proof, written by the ONLY pass path. The catalog row
/// declares this exact path; the runner demotes an unwitnessed `Passed`.
pub(crate) const ROGUE_BUNDLE_TRANSCRIPT_RELATIVE: &str =
    "negative_control/negative_control_rogue_anchor_bundle/rogue_bundle_transcript.txt";

pub struct NegativeControlRogueAnchorBundleStage;

impl OrchestrationStage for NegativeControlRogueAnchorBundleStage {
    fn id(&self) -> StageId {
        StageId::NegativeControlRogueAnchorBundle
    }
    fn name(&self) -> &str {
        "negative_control_rogue_anchor_bundle"
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
        let dir = ctx.report_dir.join("negative_control").join(self.name());
        // Topology gaps are named, never absorbed (tough-policy rule 4): the
        // live pull leg needs a Linux guest to run the real CLI + listeners.
        if let Some(reason) = rogue_anchor_bundle::precondition_gap(&ctx.assignments, &|alias| {
            ctx.adapters.get(alias).map(|a| a.platform())
        }) {
            return StageOutcome::Skipped(reason);
        }
        let target =
            match crate::vm_lab::orchestrator::stage::negative_control::select_linux_control_target(
                &ctx.assignments,
                &|alias| ctx.adapters.get(alias).map(|a| a.platform()),
            ) {
                Ok(alias) => alias.to_owned(),
                Err(reason) => {
                    return StageOutcome::Failed(format!(
                        "rogue-anchor-bundle negative control: {reason}"
                    ));
                }
            };
        let Some(adapter) = ctx.adapters.get(&target) else {
            return StageOutcome::Failed(format!(
                "rogue-anchor-bundle negative control: selected target '{target}' has no \
                 adapter (fail closed)"
            ));
        };
        rogue_anchor_bundle::run_rogue_anchor_bundle_control(
            &dir,
            &ctx.report_dir,
            &target,
            adapter.as_ref(),
        )
    }
}

pub(crate) mod rogue_anchor_bundle {
    //! The live rogue-bundle attack body + its pure adjudication.
    use super::*;
    use crate::vm_lab::orchestrator::adapter::node_adapter::NodeAdapter;
    use crate::vm_lab::orchestrator::evidence::append_stage_evidence_line;
    use crate::vm_lab::orchestrator::remote_shell::RemoteShellHost;
    use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use ed25519_dalek::SigningKey;
    use rustynet_control::membership::{
        MEMBERSHIP_HEAD_ATTESTATION_MAX_AGE_SECS, MEMBERSHIP_SCHEMA_VERSION, MembershipApprover,
        MembershipApproverRole, MembershipApproverStatus, MembershipHeadAttestation,
        MembershipNode, MembershipNodeStatus, MembershipSignature, MembershipState,
        render_membership_snapshot_body, sign_head_attestation, verify_attested_snapshot,
    };
    use rustynet_control::roles::RoleCapability;
    use std::sync::Arc;

    /// Transcript file name, shared by the writer and the catalog pin.
    pub(crate) const ROGUE_BUNDLE_TRANSCRIPT_FILE: &str = "rogue_bundle_transcript.txt";

    /// The real CLI on the lab guest (same seam as the enrollment replay
    /// control; the lab installs the release binary there).
    pub(crate) const REMOTE_CLI: &str = "/usr/local/bin/rustynet";

    /// Fixed loopback ports for the five one-shot rogue listeners. High,
    /// outside the lab's 51820-51822 daemon range.
    pub(crate) const PULL_PORTS: [u16; 5] = [51841, 51842, 51843, 51844, 51845];

    /// The puller's success marker (exact text from `main.rs`).
    pub(crate) const PULL_SUCCESS_MARKER: &str = "anchor bundle pulled and verified";
    /// The A4 enforcement point's error prefix — proof verification ran and
    /// stopped BEFORE the output write.
    pub(crate) const NO_BYTES_PREFIX: &str =
        "anchor bundle-pull verification failed (no bytes written)";

    /// Per-forgery expected rejection class (substring of the puller's
    /// stderr, ultimately the `MembershipError` Display string).
    pub(crate) const CLASS_F1_WRONG_PIN: &str = "pinned owner key mismatch";
    pub(crate) const CLASS_F2_TAMPERED: &str = "does not attest this snapshot state";
    pub(crate) const CLASS_F3_REGRESSION: &str = "membership epoch regression";
    pub(crate) const CLASS_F4_STALE: &str = "membership head attestation is stale";

    /// Guard file body: deliberately not a membership snapshot, so the
    /// puller's FIS-0020 `have` shortcut never fires and every pull is a
    /// full fetch.
    pub(crate) const GUARD_BODY: &str = "nc-guard-not-a-membership-snapshot\n";

    // ── mint helpers (pure, host-side) ───────────────────────────────────

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn unix_now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn approver_entry(
        approver_id: &str,
        key: &SigningKey,
        role: MembershipApproverRole,
    ) -> MembershipApprover {
        MembershipApprover {
            approver_id: approver_id.to_owned(),
            approver_pubkey_hex: hex_encode(&key.verifying_key().to_bytes()),
            role,
            status: MembershipApproverStatus::Active,
            created_at_unix: 100,
        }
    }

    fn node_entry(node_id: &str, pubkey: &[u8; 32]) -> MembershipNode {
        MembershipNode {
            node_id: node_id.to_owned(),
            node_pubkey_hex: hex_encode(pubkey),
            owner: "owner@example.local".to_owned(),
            status: MembershipNodeStatus::Active,
            roles: vec!["tag:servers".to_owned()],
            capabilities: vec![RoleCapability::Anchor],
            joined_at_unix: 100,
            updated_at_unix: 100,
        }
    }

    fn mesh_state(
        network_id: &str,
        epoch: u64,
        approvers: Vec<MembershipApprover>,
        node: MembershipNode,
        quorum: u8,
    ) -> MembershipState {
        MembershipState {
            schema_version: MEMBERSHIP_SCHEMA_VERSION,
            network_id: network_id.to_owned(),
            epoch,
            nodes: vec![node],
            approver_set: approvers,
            quorum_threshold: quorum,
            metadata_hash: None,
            tombstones: Vec::new(),
        }
    }

    fn attest_state(
        state: &MembershipState,
        attested_at_unix: u64,
        signers: &[(&str, &SigningKey)],
    ) -> Result<MembershipHeadAttestation, String> {
        let state_root_hex = state
            .state_root_hex()
            .map_err(|e| format!("state root: {e}"))?;
        let mut approver_signatures: Vec<MembershipSignature> = Vec::new();
        for (approver_id, key) in signers {
            let sig = sign_head_attestation(
                &state.network_id,
                state.epoch,
                &state_root_hex,
                attested_at_unix,
                approver_id,
                key,
            )
            .map_err(|e| format!("sign as {approver_id}: {e}"))?;
            approver_signatures.push(sig);
        }
        approver_signatures.sort_by(|a, b| a.approver_id.cmp(&b.approver_id));
        Ok(MembershipHeadAttestation {
            network_id: state.network_id.clone(),
            epoch: state.epoch,
            state_root_hex,
            attested_at_unix,
            approver_signatures,
        })
    }

    fn render(state: &MembershipState, att: Option<&MembershipHeadAttestation>) -> Vec<u8> {
        render_membership_snapshot_body(state, att)
            .expect("test-minted states always render")
            .into_bytes()
    }

    /// The exactly-one control scenario: a genuine owner-signed mesh the pin
    /// trusts. `owner` + `guardian` sign; quorum 2.
    pub(crate) struct MintedCorpus {
        pub(crate) pin_owner_hex: String,
        pub(crate) control_bundle: Vec<u8>,
        pub(crate) control_root: String,
        pub(crate) epoch2_bundle: Vec<u8>,
        pub(crate) epoch2_root: String,
        pub(crate) f1_wrong_pin_bundle: Vec<u8>,
        pub(crate) f2_tampered_bundle: Vec<u8>,
        pub(crate) f4_stale_bundle: Vec<u8>,
    }

    impl MintedCorpus {
        /// Host-side sha256 (hex) of the bundle each tag must be SERVED —
        /// pinned against the guest-echoed `rb_bundle_sha_*` so the
        /// adjudication can only ever describe THIS minted attack
        /// (GLM review #3).
        pub(crate) fn bundle_digests(&self) -> Vec<(&'static str, String)> {
            vec![
                ("f1", sha256_hex_bytes(&self.f1_wrong_pin_bundle)),
                ("f2", sha256_hex_bytes(&self.f2_tampered_bundle)),
                ("f3", sha256_hex_bytes(&self.control_bundle)),
                ("f4", sha256_hex_bytes(&self.f4_stale_bundle)),
                ("ctrl", sha256_hex_bytes(&self.control_bundle)),
            ]
        }
    }

    /// Mint the full forgery corpus at `now_unix`. Every forgery reaches the
    /// verifier's SPECIFIC rejection path (the offline corpus lesson: raw
    /// garbage would collapse to one "invalid format" rubber stamp).
    pub(crate) fn mint_corpus(now_unix: u64) -> Result<MintedCorpus, String> {
        let owner_a = SigningKey::from_bytes(&[11u8; 32]);
        let guardian_a = SigningKey::from_bytes(&[12u8; 32]);
        let attacker_owner = SigningKey::from_bytes(&[21u8; 32]);
        let attacker_guardian = SigningKey::from_bytes(&[22u8; 32]);
        let pin_owner_hex = hex_encode(&owner_a.verifying_key().to_bytes());

        // Genuine control mesh at epoch 1.
        let control_state = mesh_state(
            "net-nc-qh87",
            1,
            vec![
                approver_entry("owner-a", &owner_a, MembershipApproverRole::Owner),
                approver_entry("guardian-a", &guardian_a, MembershipApproverRole::Guardian),
            ],
            node_entry("node-nc-a", &owner_a.verifying_key().to_bytes()),
            2,
        );
        let control_att = attest_state(
            &control_state,
            now_unix,
            &[("guardian-a", &guardian_a), ("owner-a", &owner_a)],
        )?;
        let control_root = control_state.state_root_hex().map_err(|e| e.to_string())?;
        let control_bundle = render(&control_state, Some(&control_att));

        // Genuine epoch-2 mesh (same signers) — only its watermark/bundle
        // pairing drives F3's regression leg.
        let epoch2_state = mesh_state(
            "net-nc-qh87",
            2,
            vec![
                approver_entry("owner-a", &owner_a, MembershipApproverRole::Owner),
                approver_entry("guardian-a", &guardian_a, MembershipApproverRole::Guardian),
            ],
            node_entry("node-nc-a", &owner_a.verifying_key().to_bytes()),
            2,
        );
        let epoch2_att = attest_state(
            &epoch2_state,
            now_unix,
            &[("guardian-a", &guardian_a), ("owner-a", &owner_a)],
        )?;
        let epoch2_root = epoch2_state.state_root_hex().map_err(|e| e.to_string())?;
        let epoch2_bundle = render(&epoch2_state, Some(&epoch2_att));

        // F1: a fully self-consistent ATTACKER mesh — correct signatures,
        // quorum met — but the pinned owner key is not part of it.
        let f1_state = mesh_state(
            "net-nc-qh87",
            1,
            vec![
                approver_entry(
                    "attacker-owner",
                    &attacker_owner,
                    MembershipApproverRole::Owner,
                ),
                approver_entry(
                    "attacker-guardian",
                    &attacker_guardian,
                    MembershipApproverRole::Guardian,
                ),
            ],
            node_entry("node-rogue", &attacker_owner.verifying_key().to_bytes()),
            2,
        );
        let f1_att = attest_state(
            &f1_state,
            now_unix,
            &[
                ("attacker-guardian", &attacker_guardian),
                ("attacker-owner", &attacker_owner),
            ],
        )?;
        let f1_bundle = render(&f1_state, Some(&f1_att));

        // F2: tampered state spliced with the ORIGINAL control attestation
        // lines — the attestation no longer binds to the state it rides on.
        let mut tampered = control_state.clone();
        if let Some(node) = tampered.nodes.first_mut() {
            node.owner = "attacker@example.local".to_owned();
        }
        let tampered_body = render(&tampered, None);
        let mut tampered_lines: Vec<String> = std::str::from_utf8(&tampered_body)
            .map_err(|e| format!("tampered body utf8: {e}"))?
            .lines()
            .map(|l| l.to_owned())
            .collect();
        if tampered_lines.len() < 3 {
            return Err("tampered body unexpectedly short".to_owned());
        }
        tampered_lines.truncate(3);
        let control_text =
            std::str::from_utf8(&control_bundle).map_err(|e| format!("control body utf8: {e}"))?;
        let attestation_lines: Vec<&str> = control_text
            .lines()
            .skip(3)
            .filter(|l| l.starts_with("attestation."))
            .collect();
        if attestation_lines.is_empty() {
            return Err("control body carries no attestation lines".to_owned());
        }
        tampered_lines.extend(attestation_lines.iter().map(|l| (*l).to_owned()));
        tampered_lines.push(String::new());
        let f2_bundle = tampered_lines.join("\n").into_bytes();

        // F4: genuine state + genuine signers, attested far outside the
        // freshness window (7 days + 1 hour).
        let stale_att = attest_state(
            &control_state,
            now_unix.saturating_sub(MEMBERSHIP_HEAD_ATTESTATION_MAX_AGE_SECS + 3600),
            &[("guardian-a", &guardian_a), ("owner-a", &owner_a)],
        )?;
        let f4_bundle = render(&control_state, Some(&stale_att));

        Ok(MintedCorpus {
            pin_owner_hex,
            control_bundle,
            control_root,
            epoch2_bundle,
            epoch2_root,
            f1_wrong_pin_bundle: f1_bundle,
            f2_tampered_bundle: f2_bundle,
            f4_stale_bundle: f4_bundle,
        })
    }

    /// The persistent watermark bytes the puller itself writes/reads
    /// (`persist_membership_watermark` format): epoch + state root identity.
    pub(crate) fn watermark_bytes(epoch: u64, state_root_hex: &str) -> Vec<u8> {
        format!("version=1\nepoch={epoch}\nstate_root={state_root_hex}\n").into_bytes()
    }

    // ── the attack script ────────────────────────────────────────────────

    /// One guest-side run: stage files, then per-tag (fresh one-shot nc
    /// listener + real pull CLI). Emits `rb_*` key=value transcript lines on
    /// stdout. `__REMOTE_CLI__` is substituted by [`attack_script`].
    pub(crate) const ATTACK_SCRIPT_TEMPLATE: &str = r#"
rb_work=/tmp/rustynet-nc-qh87.$$
mkdir -p "$rb_work" && chmod 700 "$rb_work" || { echo rb_error_stage_failed=1; exit 1; }
trap 'rm -rf "$rb_work"' EXIT
TOKEN="$1"; PIN_B64="$2"; GUARD_B64="$3"; WM_B64="$4"; WM_E2_B64="$5"
shift 5
printf '%s' "$PIN_B64" | base64 -d > "$rb_work/pin" 2>/dev/null
printf '%s' "$GUARD_B64" | base64 -d > "$rb_work/guard" 2>/dev/null
printf '%s' "$WM_B64" | base64 -d > "$rb_work/wm" 2>/dev/null
printf '%s' "$WM_E2_B64" | base64 -d > "$rb_work/wm_e2" 2>/dev/null
if [ ! -s "$rb_work/pin" ] || [ ! -s "$rb_work/guard" ] || [ ! -s "$rb_work/wm" ] || [ ! -s "$rb_work/wm_e2" ]; then
  echo rb_error_stage_failed=1
  exit 1
fi
wm_for() { [ "$1" = f3 ] && { echo "$rb_work/wm_e2"; return; }; echo "$rb_work/wm"; }
i=0
for t in f1 f2 f3 f4 ctrl; do
  i=$((i+1))
  eval "port=\${$((2*i-1))}"
  eval "b64=\${$((2*i))}"
  printf '%s' "$b64" | base64 -d > "$rb_work/bundle.$t" 2>/dev/null
  if [ ! -s "$rb_work/bundle.$t" ]; then echo rb_error_stage_failed=1; exit 1; fi
  echo "rb_bundle_sha_$t=$(sha256sum "$rb_work/bundle.$t" | cut -d' ' -f1)"
  echo "rb_bundle_bytes_$t=$(wc -c < "$rb_work/bundle.$t")"
done
run_pull() {
  tag="$1"
  port="$2"
  wmpath=$(wm_for "$tag")
  attempt=0
  rc=1
  while [ $attempt -lt 5 ]; do
    attempt=$((attempt+1))
    ( printf 'OK %s\n' "$(wc -c < "$rb_work/bundle.$tag")"
        cat "$rb_work/bundle.$tag" ) | nc -l -p "$port" -s 127.0.0.1 >/dev/null 2>&1 &
    _rb_lpid=$!
    sleep 0.5
    "__REMOTE_CLI__" anchor pull-bundle --addr "127.0.0.1:$port" --token "$TOKEN" \
      --output "$rb_work/guard" --owner-key-pub "$rb_work/pin" \
      --watermark-path "$wmpath" \
      >"$rb_work/out.$tag" 2>"$rb_work/err.$tag"
    rc=$?
    kill "$_rb_lpid" 2>/dev/null
    wait "$_rb_lpid" 2>/dev/null
    if [ "$rc" -eq 0 ] || ! grep -qiE 'refused|connect anchor bundle-pull failed' "$rb_work/err.$tag" 2>/dev/null; then
      break
    fi
  done
  echo "rb_${tag}_rc=$rc"
  echo "rb_${tag}_out_b64=$(base64 -w0 < "$rb_work/out.$tag" 2>/dev/null)"
  echo "rb_${tag}_err_b64=$(base64 -w0 < "$rb_work/err.$tag" 2>/dev/null)"
  echo "rb_${tag}_guard_sha_after=$(sha256sum "$rb_work/guard" | cut -d' ' -f1)"
  echo "rb_${tag}_wm_sha_after=$(sha256sum "$wmpath" | cut -d' ' -f1)"
}
echo "rb_guard_sha_before=$(sha256sum "$rb_work/guard" | cut -d' ' -f1)"
echo "rb_wm_sha_before=$(sha256sum "$rb_work/wm" | cut -d' ' -f1)"
echo "rb_wm2_sha_before=$(sha256sum "$rb_work/wm_e2" | cut -d' ' -f1)"
echo "rb_guest_unix=$(date +%s)"
run_pull f1 "$1" ; shift 2
run_pull f2 "$1" ; shift 2
run_pull f3 "$1" ; shift 2
run_pull f4 "$1" ; shift 2
run_pull ctrl "$1" ; shift 2
echo "rb_done=1"
exit 0
"#;

    /// The delivered script: `__REMOTE_CLI__` replaced with the real path.
    pub(crate) fn attack_script() -> String {
        ATTACK_SCRIPT_TEMPLATE.replace("__REMOTE_CLI__", REMOTE_CLI)
    }

    fn b64(data: &[u8]) -> String {
        STANDARD.encode(data)
    }

    // ── witness field parsing ────────────────────────────────────────────

    pub(crate) struct PullObservation {
        pub(crate) tag: &'static str,
        pub(crate) rc: i64,
        pub(crate) stdout: String,
        pub(crate) stderr: String,
        pub(crate) guard_sha_after: String,
        pub(crate) wm_sha_after: String,
    }

    pub(crate) struct RogueObservation {
        pub(crate) pulls: Vec<PullObservation>,
        pub(crate) bundle_shas: Vec<(&'static str, String)>,
        pub(crate) guard_sha_before: String,
        pub(crate) wm_sha_before: String,
        pub(crate) wm2_sha_before: String,
        /// Guest epoch at transcript time — log-only diagnosability for the
        /// host/guest clock-skew failure mode (GLM review #4).
        pub(crate) guest_unix: Option<u64>,
    }

    pub(crate) enum RogueParse {
        Observed(RogueObservation),
        NotAdjudicable { reason: String },
    }

    fn field<'a>(stdout: &'a str, key: &str) -> Option<&'a str> {
        let prefix = format!("{key}=");
        stdout.lines().find_map(|line| line.strip_prefix(&prefix))
    }

    const TAGS: [&str; 5] = ["f1", "f2", "f3", "f4", "ctrl"];

    /// Parse the attack transcript. Any hard-error field or missing field is
    /// NotAdjudicable (fail closed).
    pub(crate) fn parse_transcript(_exit_code: i32, stdout: &str) -> RogueParse {
        if field(stdout, "rb_error_stage_failed").is_some() {
            return RogueParse::NotAdjudicable {
                reason: "guest staging failed (base64 decode or file write)".to_owned(),
            };
        }
        let missing = |key: &str| RogueParse::NotAdjudicable {
            reason: format!("attack transcript has no `{key}` field"),
        };
        let mut pulls = Vec::new();
        let mut bundle_shas = Vec::new();
        for tag in TAGS {
            let rc = match field(stdout, &format!("rb_{tag}_rc")) {
                Some(v) => match v.trim().parse::<i64>() {
                    Ok(rc) => rc,
                    Err(_) => {
                        return RogueParse::NotAdjudicable {
                            reason: format!("rb_{tag}_rc is not numeric: {v}"),
                        };
                    }
                },
                None => return missing(&format!("rb_{tag}_rc")),
            };
            let decode = |key: &str| -> Result<String, RogueParse> {
                match field(stdout, key) {
                    Some(v) => STANDARD
                        .decode(v.trim())
                        .map(|raw| String::from_utf8_lossy(&raw).into_owned())
                        .map_err(|_| RogueParse::NotAdjudicable {
                            reason: format!("{key} is not valid base64"),
                        }),
                    None => Err(missing(key)),
                }
            };
            let out = match decode(&format!("rb_{tag}_out_b64")) {
                Ok(v) => v,
                Err(p) => return p,
            };
            let err = match decode(&format!("rb_{tag}_err_b64")) {
                Ok(v) => v,
                Err(p) => return p,
            };
            let guard_sha_after = match field(stdout, &format!("rb_{tag}_guard_sha_after")) {
                Some(v) if !v.trim().is_empty() => v.trim().to_owned(),
                _ => return missing(&format!("rb_{tag}_guard_sha_after")),
            };
            let wm_sha_after = match field(stdout, &format!("rb_{tag}_wm_sha_after")) {
                Some(v) if !v.trim().is_empty() => v.trim().to_owned(),
                _ => return missing(&format!("rb_{tag}_wm_sha_after")),
            };
            let sha = match field(stdout, &format!("rb_bundle_sha_{tag}")) {
                Some(v) if !v.trim().is_empty() => v.trim().to_owned(),
                _ => return missing(&format!("rb_bundle_sha_{tag}")),
            };
            bundle_shas.push((tag, sha));
            pulls.push(PullObservation {
                tag,
                rc,
                stdout: out,
                stderr: err,
                guard_sha_after,
                wm_sha_after,
            });
        }
        let guard_sha_before = match field(stdout, "rb_guard_sha_before") {
            Some(v) if !v.trim().is_empty() => v.trim().to_owned(),
            _ => return missing("rb_guard_sha_before"),
        };
        let wm_sha_before = match field(stdout, "rb_wm_sha_before") {
            Some(v) if !v.trim().is_empty() => v.trim().to_owned(),
            _ => return missing("rb_wm_sha_before"),
        };
        let wm2_sha_before = match field(stdout, "rb_wm2_sha_before") {
            Some(v) if !v.trim().is_empty() => v.trim().to_owned(),
            _ => return missing("rb_wm2_sha_before"),
        };
        if field(stdout, "rb_done").is_none() {
            return missing("rb_done");
        }
        let guest_unix = field(stdout, "rb_guest_unix").and_then(|v| v.trim().parse::<u64>().ok());
        RogueParse::Observed(RogueObservation {
            pulls,
            bundle_shas,
            guard_sha_before,
            wm_sha_before,
            wm2_sha_before,
            guest_unix,
        })
    }

    // ── pure adjudication ────────────────────────────────────────────────

    /// Which staged watermark a pull must leave byte-identical.
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(crate) enum WmFile {
        Common,
        Epoch2,
    }

    pub(crate) struct ForgeryExpectation {
        pub(crate) tag: &'static str,
        pub(crate) class: &'static str,
        pub(crate) wm: WmFile,
    }

    pub(crate) const FORGERIES: [ForgeryExpectation; 4] = [
        ForgeryExpectation {
            tag: "f1",
            class: CLASS_F1_WRONG_PIN,
            wm: WmFile::Common,
        },
        ForgeryExpectation {
            tag: "f2",
            class: CLASS_F2_TAMPERED,
            wm: WmFile::Common,
        },
        ForgeryExpectation {
            tag: "f3",
            class: CLASS_F3_REGRESSION,
            wm: WmFile::Epoch2,
        },
        ForgeryExpectation {
            tag: "f4",
            class: CLASS_F4_STALE,
            wm: WmFile::Common,
        },
    ];

    #[derive(Debug)]
    pub(crate) enum RogueBundleControlOutcome {
        /// Every forgery was rejected for the NAMED reason with zero bytes
        /// landing, and the genuine control bundle was accepted end-to-end.
        AllForgeriesRejectedAndControlAccepted,
        /// A forgery pull SUCCEEDED — the puller wrote attacker bytes (or
        /// claimed success). Fail-open.
        ForgeryAccepted {
            tag: &'static str,
        },
        /// Rejected, but not for the expected class — the adjudication would
        /// be a rubber stamp.
        WrongReasonRejection {
            tag: &'static str,
            actual: String,
        },
        /// The guard output file changed under a forgery pull — bytes landed
        /// despite the rejection.
        GuardFileDrift {
            tag: &'static str,
        },
        /// A watermark file changed under a pull that must not touch it.
        WatermarkDrift {
            tag: &'static str,
        },
        /// The genuine control pull did not succeed.
        ControlPullFailed {
            detail: String,
        },
        /// The control pull succeeded but the landed bytes are not the minted
        /// bundle.
        ControlBytesMismatch,
        /// F3 was not served the genuine epoch-1 bundle.
        ServedBundleMismatch,
        /// The bytes the guest served are not the minted corpus — the
        /// transcript does not describe THIS attack (GLM review #3).
        ServedDigestMismatch {
            tag: &'static str,
            expected: String,
            served: String,
        },
        NotAdjudicable {
            reason: String,
        },
    }

    impl RogueBundleControlOutcome {
        pub(crate) fn is_control_pass(&self) -> bool {
            matches!(
                self,
                RogueBundleControlOutcome::AllForgeriesRejectedAndControlAccepted
            )
        }
    }

    fn pull<'a>(obs: &'a RogueObservation, tag: &str) -> Result<&'a PullObservation, String> {
        obs.pulls
            .iter()
            .find(|p| p.tag == tag)
            .ok_or_else(|| format!("no pull observation for {tag}"))
    }

    fn bundle_sha<'a>(obs: &'a RogueObservation, tag: &str) -> Result<&'a str, String> {
        obs.bundle_shas
            .iter()
            .find(|(t, _)| *t == tag)
            .map(|(_, s)| s.as_str())
            .ok_or_else(|| format!("no bundle sha for {tag}"))
    }

    /// The pure inversion: forgeries must fail LOUDLY and BY NAME, guards
    /// must not move, the SERVED bytes must be the minted corpus, and the
    /// genuine bundle must still pull.
    pub(crate) fn adjudicate(
        obs: &RogueObservation,
        expected_digests: &[(&'static str, String)],
    ) -> RogueBundleControlOutcome {
        if obs.guard_sha_before.is_empty() {
            return RogueBundleControlOutcome::NotAdjudicable {
                reason: "guard sha before is empty".to_owned(),
            };
        }
        // The bytes each guest listener served must be byte-identical to the
        // host-minted bundle — otherwise the transcript describes a foreign
        // exercise and no verdict on THIS attack is provable.
        for (tag, digest) in expected_digests {
            match bundle_sha(obs, tag) {
                Ok(served) if served == digest => {}
                Ok(served) => {
                    return RogueBundleControlOutcome::ServedDigestMismatch {
                        tag,
                        expected: digest.clone(),
                        served: served.to_owned(),
                    };
                }
                Err(reason) => return RogueBundleControlOutcome::NotAdjudicable { reason },
            }
        }
        // F3 must be served the genuine epoch-1 (control) bundle against the
        // epoch-2 watermark — the regression is in the PAIRING. (Redundant
        // with the digest pinning above; kept as an explicit pairing check.)
        match (bundle_sha(obs, "f3"), bundle_sha(obs, "ctrl")) {
            (Ok(f3), Ok(ctrl)) if f3 == ctrl => {}
            _ => return RogueBundleControlOutcome::ServedBundleMismatch,
        }
        for forgery in FORGERIES {
            let p = match pull(obs, forgery.tag) {
                Ok(p) => p,
                Err(reason) => return RogueBundleControlOutcome::NotAdjudicable { reason },
            };
            if p.rc == 0 || p.stdout.contains(PULL_SUCCESS_MARKER) {
                return RogueBundleControlOutcome::ForgeryAccepted { tag: forgery.tag };
            }
            if !p.stderr.contains(NO_BYTES_PREFIX) || !p.stderr.contains(forgery.class) {
                return RogueBundleControlOutcome::WrongReasonRejection {
                    tag: forgery.tag,
                    actual: p.stderr.lines().last().unwrap_or("").to_owned(),
                };
            }
            if p.guard_sha_after != obs.guard_sha_before {
                return RogueBundleControlOutcome::GuardFileDrift { tag: forgery.tag };
            }
            let expected_wm = match forgery.wm {
                WmFile::Common => &obs.wm_sha_before,
                WmFile::Epoch2 => &obs.wm2_sha_before,
            };
            if &p.wm_sha_after != expected_wm {
                return RogueBundleControlOutcome::WatermarkDrift { tag: forgery.tag };
            }
        }
        let ctrl = match pull(obs, "ctrl") {
            Ok(p) => p,
            Err(reason) => return RogueBundleControlOutcome::NotAdjudicable { reason },
        };
        if ctrl.rc != 0 || !ctrl.stdout.contains(PULL_SUCCESS_MARKER) {
            return RogueBundleControlOutcome::ControlPullFailed {
                detail: ctrl.stderr.lines().last().unwrap_or("").to_owned(),
            };
        }
        let ctrl_sha = match bundle_sha(obs, "ctrl") {
            Ok(s) => s,
            Err(reason) => return RogueBundleControlOutcome::NotAdjudicable { reason },
        };
        if ctrl.guard_sha_after != ctrl_sha {
            return RogueBundleControlOutcome::ControlBytesMismatch;
        }
        if ctrl.wm_sha_after != obs.wm_sha_before {
            return RogueBundleControlOutcome::WatermarkDrift { tag: "ctrl" };
        }
        RogueBundleControlOutcome::AllForgeriesRejectedAndControlAccepted
    }

    // ── the control body (side-effectful) ────────────────────────────────

    fn run_remote_argv(
        shell: &Arc<dyn RemoteShellHost>,
        argv: &[&str],
    ) -> Result<RemoteCommandOutput, String> {
        let status = shell
            .run_argv(argv, &[], &[])
            .map_err(|err| format!("transport failure running {argv:?}: {err}"))?;
        Ok(RemoteCommandOutput {
            code: status.code,
            stdout: String::from_utf8_lossy(&status.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&status.stderr).into_owned(),
        })
    }

    struct RemoteCommandOutput {
        code: i32,
        stdout: String,
        stderr: String,
    }

    fn write_evidence(dir: &Path, name: &str, contents: &str) -> Result<(), String> {
        std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        let path = dir.join(name);
        std::fs::write(&path, contents).map_err(|e| format!("write {}: {e}", path.display()))
    }

    /// Topology precondition: at least one Linux node must be assigned, or
    /// the attack cannot run anywhere (named skip; tough-policy rule 4).
    pub(crate) fn precondition_gap(
        assignments: &[NodeRoleAssignment],
        platform_of: &dyn Fn(&str) -> Option<VmGuestPlatform>,
    ) -> Option<String> {
        let linux = assignments
            .iter()
            .any(|a| platform_of(&a.alias) == Some(VmGuestPlatform::Linux));
        if linux {
            None
        } else {
            Some(
                "no Linux node in the topology; the rogue-bundle attack needs a Linux guest \
                 to run the real `rustynet anchor pull-bundle` CLI"
                    .to_owned(),
            )
        }
    }

    /// The (QH-87) control body. A working control returns
    /// [`StageOutcome::Passed`] (every forgery rejected by name with zero
    /// bytes landing, and the genuine bundle accepted end-to-end).
    pub(crate) fn run_rogue_anchor_bundle_control(
        workdir: &Path,
        report_dir: &Path,
        target_alias: &str,
        adapter: &dyn NodeAdapter,
    ) -> StageOutcome {
        let fail = |reason: String| {
            StageOutcome::Failed(format!(
                "rogue-anchor-bundle negative control [target {target_alias}]: {reason}"
            ))
        };
        if adapter.platform() != VmGuestPlatform::Linux {
            return fail(format!(
                "target platform {:?} cannot host the rogue-bundle pull attack (fail closed)",
                adapter.platform()
            ));
        }
        let shell = match adapter.shell_host() {
            Ok(shell) => shell,
            Err(err) => return fail(format!("no remote shell host: {err}")),
        };

        // 1. Mint the corpus and prove every forgery's rejection class
        //    offline BEFORE shipping (triage witness).
        let corpus = match mint_corpus(unix_now()) {
            Ok(c) => c,
            Err(err) => return fail(format!("corpus mint failed: {err}")),
        };
        let expected_digests = corpus.bundle_digests();
        let max_age = MEMBERSHIP_HEAD_ATTESTATION_MAX_AGE_SECS;
        let now = unix_now();
        let offline = format!(
            "## offline triage (rustynet_control::membership::verify_attested_snapshot)\n\
             control={:?}\n\
             f1_wrong_pin={:?}\n\
             f2_tampered={:?}\n\
             f3_regression={:?}\n\
             f4_stale={:?}\n",
            verify_attested_snapshot(
                &corpus.control_bundle,
                &corpus.pin_owner_hex,
                now,
                None,
                max_age
            )
            .map(|s| s.epoch),
            verify_attested_snapshot(
                &corpus.f1_wrong_pin_bundle,
                &corpus.pin_owner_hex,
                now,
                None,
                max_age
            )
            .err()
            .map(|e| e.to_string()),
            verify_attested_snapshot(
                &corpus.f2_tampered_bundle,
                &corpus.pin_owner_hex,
                now,
                None,
                max_age
            )
            .err()
            .map(|e| e.to_string()),
            verify_attested_snapshot(
                &corpus.control_bundle,
                &corpus.pin_owner_hex,
                now,
                Some(&(2u64, corpus.epoch2_root.clone())),
                max_age
            )
            .err()
            .map(|e| e.to_string()),
            verify_attested_snapshot(
                &corpus.f4_stale_bundle,
                &corpus.pin_owner_hex,
                now,
                None,
                max_age
            )
            .err()
            .map(|e| e.to_string()),
        );

        // 2. Deliver the attack (stage files → 5 pulls → hashes).
        let token = format!("nc-qh87-{}", hex_encode(&unix_now().to_le_bytes()));
        let script = attack_script();
        let ports: Vec<String> = PULL_PORTS.iter().map(|p| p.to_string()).collect();
        let bundles = [
            b64(&corpus.f1_wrong_pin_bundle),
            b64(&corpus.f2_tampered_bundle),
            b64(&corpus.control_bundle),
            b64(&corpus.f4_stale_bundle),
            b64(&corpus.control_bundle),
        ];
        let pin_b64 = b64(corpus.pin_owner_hex.as_bytes());
        let guard_b64 = b64(GUARD_BODY.as_bytes());
        let wm_b64 = b64(&watermark_bytes(1, &corpus.control_root));
        let wm2_b64 = b64(&watermark_bytes(2, &corpus.epoch2_root));
        let mut argv: Vec<&str> = vec![
            "bash",
            "-c",
            script.as_str(),
            "nc-rogue-bundle",
            token.as_str(),
            pin_b64.as_str(),
            guard_b64.as_str(),
            wm_b64.as_str(),
            wm2_b64.as_str(),
        ];
        for (idx, bundle) in bundles.iter().enumerate() {
            argv.push(ports[idx].as_str());
            argv.push(bundle.as_str());
        }
        let script_status = run_remote_argv(&shell, &argv);
        let (script_exit, script_stdout, script_stderr) = match script_status {
            Ok(out) => (out.code, out.stdout, out.stderr),
            Err(err) => {
                let _ = write_evidence(
                    workdir,
                    ROGUE_BUNDLE_TRANSCRIPT_FILE,
                    &format!("{offline}\n## attack delivery\ntransport failure: {err}\n"),
                );
                return fail(format!("transport failure delivering the attack: {err}"));
            }
        };
        let mut evidence = format!(
            "{offline}\n## attack delivery (linux pull leg, target {target_alias})\n\
             exit={script_exit}\n--- stdout ---\n{script_stdout}\n--- stderr ---\n\
             {script_stderr}\n"
        );

        // 3. Adjudicate (pure).
        let observation = match parse_transcript(script_exit, &script_stdout) {
            RogueParse::NotAdjudicable { reason } => {
                evidence.push_str(&format!("## adjudication\nnot adjudicable: {reason}\n"));
                let _ = write_evidence(workdir, ROGUE_BUNDLE_TRANSCRIPT_FILE, &evidence);
                return fail(format!(
                    "{reason}; the attack ran but the outcome is not provable (fail closed)"
                ));
            }
            RogueParse::Observed(o) => o,
        };
        let verdict = adjudicate(&observation, &expected_digests);
        let mut digest_lines = String::new();
        for (tag, expected) in &expected_digests {
            let served = observation
                .bundle_shas
                .iter()
                .find(|(t, _)| t == tag)
                .map(|(_, s)| s.as_str())
                .unwrap_or("<missing>");
            digest_lines.push_str(&format!("served_sha_{tag}={served} expected={expected}\n"));
        }
        evidence.push_str(&format!(
            "## adjudication (linux pull leg)\nremote_cli={REMOTE_CLI}\nports={:?}\n\
             host_unix={now}\nguest_unix={:?}\n\
             guard_sha_before={}\nwm_sha_before={}\nwm2_sha_before={}\n{digest_lines}{verdict:?}\n",
            PULL_PORTS,
            observation.guest_unix,
            observation.guard_sha_before,
            observation.wm_sha_before,
            observation.wm2_sha_before,
        ));

        // 4. Persist the declared witness + the pass verdict.
        if let Err(err) = write_evidence(workdir, ROGUE_BUNDLE_TRANSCRIPT_FILE, &evidence) {
            return fail(format!(
                "evidence not persisted: {err} (fail closed; the witness is the declared \
                 File artifact)"
            ));
        }
        match verdict {
            RogueBundleControlOutcome::AllForgeriesRejectedAndControlAccepted => {
                if let Err(err) = append_stage_evidence_line(
                    report_dir,
                    StageId::NegativeControlRogueAnchorBundle.as_str(),
                    &format!(
                        "negative_control=rogue_anchor_bundle target={target_alias} \
                         forgeries=wrong_pin,tampered_state,epoch_regression,stale_attestation \
                         detection=puller_rejected_before_write_guards_unmoved \
                         control_genuine_bundle_accepted=true"
                    ),
                ) {
                    return StageOutcome::Failed(format!(
                        "rogue-anchor-bundle negative control: witness write failed: {err}"
                    ));
                }
                StageOutcome::Passed
            }
            RogueBundleControlOutcome::ForgeryAccepted { tag } => fail(format!(
                "FAIL-OPEN — forgery pull '{tag}' SUCCEEDED; the puller accepted a rogue \
                 bundle and wrote bytes (A4 verify-before-write did not hold)"
            )),
            RogueBundleControlOutcome::WrongReasonRejection { tag, actual } => fail(format!(
                "forgery '{tag}' was rejected for the WRONG reason ({actual}); the \
                 adjudication must name the specific rejection class"
            )),
            RogueBundleControlOutcome::GuardFileDrift { tag } => fail(format!(
                "the guard output file changed under forgery pull '{tag}' — bytes landed \
                 despite the rejection (verify-before-write violated)"
            )),
            RogueBundleControlOutcome::WatermarkDrift { tag } => fail(format!(
                "a watermark file changed under pull '{tag}' without a verified acceptance"
            )),
            RogueBundleControlOutcome::ControlPullFailed { detail } => fail(format!(
                "the genuine control bundle was NOT accepted end-to-end ({detail}); the \
                 attack environment is broken, so the forgery rejections prove nothing"
            )),
            RogueBundleControlOutcome::ControlBytesMismatch => fail(
                "the control pull succeeded but the landed bytes are not the minted bundle"
                    .to_owned(),
            ),
            RogueBundleControlOutcome::ServedBundleMismatch => fail(
                "F3 was not served the genuine epoch-1 bundle; the regression pairing is \
                 broken (fail closed)"
                    .to_owned(),
            ),
            RogueBundleControlOutcome::ServedDigestMismatch {
                tag,
                expected,
                served,
            } => fail(format!(
                "forgery leg '{tag}' was served bytes that are NOT the minted corpus \
                 (expected sha {expected}, served {served}); the transcript does not \
                 describe this attack (fail closed)"
            )),
            RogueBundleControlOutcome::NotAdjudicable { reason } => fail(format!(
                "{reason}; the outcome is not provable (fail closed)"
            )),
        }
    }

    // ── tests ────────────────────────────────────────────────────────────

    #[cfg(test)]
    mod tests {
        use super::*;
        use rustynet_control::membership::MembershipError;

        const NOW: u64 = 1_800_000_000;

        fn corpus() -> MintedCorpus {
            mint_corpus(NOW).expect("mint")
        }

        fn verify_err(bytes: &[u8], pin: &str, prior: Option<&(u64, String)>) -> String {
            verify_attested_snapshot(
                bytes,
                pin,
                NOW,
                prior,
                MEMBERSHIP_HEAD_ATTESTATION_MAX_AGE_SECS,
            )
            .unwrap_err()
            .to_string()
        }

        #[test]
        fn control_bundle_verifies_against_its_pin() {
            let c = corpus();
            let state = verify_attested_snapshot(
                &c.control_bundle,
                &c.pin_owner_hex,
                NOW,
                None,
                MEMBERSHIP_HEAD_ATTESTATION_MAX_AGE_SECS,
            )
            .expect("genuine bundle must verify");
            assert_eq!(state.epoch, 1);
            assert_eq!(state.network_id, "net-nc-qh87");
        }

        #[test]
        fn f1_self_consistent_attacker_mesh_rejected_on_pin() {
            let c = corpus();
            assert!(
                verify_err(&c.f1_wrong_pin_bundle, &c.pin_owner_hex, None)
                    .contains(CLASS_F1_WRONG_PIN)
            );
        }

        #[test]
        fn f2_tampered_state_rejected_on_attestation_binding() {
            let c = corpus();
            assert!(
                verify_err(&c.f2_tampered_bundle, &c.pin_owner_hex, None)
                    .contains(CLASS_F2_TAMPERED)
            );
        }

        #[test]
        fn f2_keeps_the_original_attestation_lines() {
            let c = corpus();
            let text = std::str::from_utf8(&c.f2_tampered_bundle).expect("utf8");
            let lines: Vec<&str> = text.lines().collect();
            assert_eq!(lines[0], format!("version={MEMBERSHIP_SCHEMA_VERSION}"));
            assert!(lines[1].starts_with("state_hex="));
            assert!(lines[2].starts_with("digest="));
            assert!(lines.iter().skip(3).all(|l| l.starts_with("attestation.")));
            assert!(lines.len() > 4);
        }

        #[test]
        fn f3_epoch_regression_rejected_against_epoch2_watermark() {
            let c = corpus();
            let prior = (2u64, c.epoch2_root.clone());
            assert!(
                verify_err(&c.control_bundle, &c.pin_owner_hex, Some(&prior))
                    .contains(CLASS_F3_REGRESSION)
            );
        }

        #[test]
        fn f4_stale_attestation_rejected_on_freshness() {
            let c = corpus();
            assert!(
                verify_err(&c.f4_stale_bundle, &c.pin_owner_hex, None).contains(CLASS_F4_STALE)
            );
        }

        #[test]
        fn epoch2_bundle_verifies_standing_alone() {
            let c = corpus();
            verify_attested_snapshot(
                &c.epoch2_bundle,
                &c.pin_owner_hex,
                NOW,
                None,
                MEMBERSHIP_HEAD_ATTESTATION_MAX_AGE_SECS,
            )
            .expect("epoch-2 bundle must verify");
        }

        #[test]
        fn watermark_bytes_match_the_persist_format() {
            let wm = watermark_bytes(3, "ab");
            assert_eq!(wm, b"version=1\nepoch=3\nstate_root=ab\n");
        }

        fn observation_from(stdout: &str, exit_code: i32) -> RogueObservation {
            match parse_transcript(exit_code, stdout) {
                RogueParse::Observed(o) => o,
                RogueParse::NotAdjudicable { reason } => {
                    panic!("unexpected not-adjudicable: {reason}")
                }
            }
        }

        fn happy_transcript() -> String {
            let sha = |s: &str| {
                // Not a real sha — the adjudicator only compares equality.
                format!("{:016x}{:016x}{:016x}{:016x}", s.len(), 1, 2, 3)
            };
            let guard = sha("guard");
            let wm = sha("wm");
            let wm2 = sha("wm2");
            // f3 is served the CONTROL bundle and the control pull lands the
            // same bytes into the guard file: one shared digest for the pair.
            let served = sha("served-control-bundle");
            let mut out = String::new();
            for t in TAGS {
                let bundle_sha = if t == "f3" || t == "ctrl" {
                    served.clone()
                } else {
                    sha(t)
                };
                out.push_str(&format!("rb_bundle_sha_{t}={bundle_sha}\n"));
                if t == "ctrl" {
                    // The control's pull fields come from the success block
                    // below; the loop must not emit duplicates.
                    continue;
                }
                out.push_str(&format!("rb_bundle_bytes_{t}=100\n"));
                out.push_str(&format!("rb_{t}_rc=1\n"));
                out.push_str(&format!("rb_{t}_out_b64={}\n", STANDARD.encode("")));
                let class = FORGERIES
                    .iter()
                    .find(|f| f.tag == t)
                    .map(|f| f.class)
                    .unwrap_or("accepted");
                out.push_str(&format!(
                    "rb_{t}_err_b64={}\n",
                    STANDARD.encode(format!("{NO_BYTES_PREFIX}: {class}: boom"))
                ));
                out.push_str(&format!("rb_{t}_guard_sha_after={guard}\n"));
                out.push_str(&format!(
                    "rb_{t}_wm_sha_after={}\n",
                    if t == "f3" { wm2.clone() } else { wm.clone() }
                ));
            }
            out.push_str(&format!("rb_guard_sha_before={guard}\n"));
            out.push_str(&format!("rb_wm_sha_before={wm}\n"));
            out.push_str(&format!("rb_wm2_sha_before={wm2}\n"));
            // Control success shape: the guard file now holds the bundle.
            out.push_str("rb_ctrl_rc=0\n");
            out.push_str(&format!(
                "rb_ctrl_out_b64={}\n",
                STANDARD.encode(format!("{PULL_SUCCESS_MARKER}: 100 bytes written"))
            ));
            out.push_str(&format!("rb_ctrl_err_b64={}\n", STANDARD.encode("")));
            out.push_str(&format!("rb_ctrl_guard_sha_after={served}\n"));
            out.push_str(&format!("rb_ctrl_wm_sha_after={wm}\n"));
            out.push_str("rb_done=1\n");
            out
        }

        /// Expected digests derived FROM the observation itself: the digest
        /// pinning then passes trivially, so each mutation test exercises ITS
        /// specific failure arm. The production caller passes the MINTED
        /// corpus digests instead.
        fn digests_of(obs: &RogueObservation) -> Vec<(&'static str, String)> {
            obs.bundle_shas.clone()
        }

        #[test]
        fn happy_path_is_a_control_pass() {
            let obs = observation_from(&happy_transcript(), 0);
            assert!(adjudicate(&obs, &digests_of(&obs)).is_control_pass());
        }

        #[test]
        fn served_digest_mismatch_fails() {
            let obs = observation_from(&happy_transcript(), 0);
            let mut expected = digests_of(&obs);
            expected[0].1 = "0".repeat(64);
            match adjudicate(&obs, &expected) {
                RogueBundleControlOutcome::ServedDigestMismatch { tag, .. } => {
                    assert_eq!(tag, "f1")
                }
                other => panic!("wrong outcome: {other:?}"),
            }
        }

        #[test]
        fn before_hashes_are_captured_before_the_first_pull() {
            // GLM review #1 regression pin: the before-hashes must be echoed
            // BEFORE any pull runs, or the control pull itself moves the
            // guard file and the inversion can never pass.
            let script = attack_script();
            let before = script
                .find("rb_guard_sha_before=")
                .expect("before-hash echo present");
            let first_pull = script.find("run_pull f1").expect("first pull present");
            assert!(before < first_pull);
        }

        #[test]
        fn forgery_accepted_is_a_fail_open() {
            let mut out = happy_transcript();
            out = out.replace("rb_f1_rc=1", "rb_f1_rc=0");
            let obs = observation_from(&out, 0);
            match adjudicate(&obs, &digests_of(&obs)) {
                RogueBundleControlOutcome::ForgeryAccepted { tag } => assert_eq!(tag, "f1"),
                other => panic!("wrong outcome: {other:?}"),
            }
        }

        #[test]
        fn wrong_reason_rejection_fails() {
            // The transcript carries base64-encoded stderr, so mutate f1's
            // ENCODED line (replacing the plaintext constant would no-op).
            let f1_err = STANDARD.encode(format!("{NO_BYTES_PREFIX}: {CLASS_F1_WRONG_PIN}: boom"));
            let out = happy_transcript().replace(
                &format!("rb_f1_err_b64={f1_err}"),
                &format!(
                    "rb_f1_err_b64={}",
                    STANDARD.encode("invalid membership format: x")
                ),
            );
            let obs = observation_from(&out, 0);
            assert!(matches!(
                adjudicate(&obs, &digests_of(&obs)),
                RogueBundleControlOutcome::WrongReasonRejection { tag: "f1", .. }
            ));
        }

        #[test]
        fn guard_drift_fails() {
            let out =
                happy_transcript().replace("rb_f2_guard_sha_after=", "rb_f2_guard_sha_after=X");
            let obs = observation_from(&out, 0);
            assert!(matches!(
                adjudicate(&obs, &digests_of(&obs)),
                RogueBundleControlOutcome::GuardFileDrift { tag: "f2" }
            ));
        }

        #[test]
        fn watermark_drift_on_regression_leg_fails() {
            let out = happy_transcript().replace("rb_f3_wm_sha_after=", "rb_f3_wm_sha_after=Y");
            let obs = observation_from(&out, 0);
            assert!(matches!(
                adjudicate(&obs, &digests_of(&obs)),
                RogueBundleControlOutcome::WatermarkDrift { tag: "f3" }
            ));
        }

        #[test]
        fn control_pull_failure_fails() {
            let out = happy_transcript().replace("rb_ctrl_rc=0", "rb_ctrl_rc=9");
            let obs = observation_from(&out, 0);
            assert!(matches!(
                adjudicate(&obs, &digests_of(&obs)),
                RogueBundleControlOutcome::ControlPullFailed { .. }
            ));
        }

        #[test]
        fn served_bundle_mismatch_fails() {
            let out = happy_transcript().replace("rb_bundle_sha_f3=", "rb_bundle_sha_f3=Z");
            let obs = observation_from(&out, 0);
            assert!(matches!(
                adjudicate(&obs, &digests_of(&obs)),
                RogueBundleControlOutcome::ServedBundleMismatch
            ));
        }

        #[test]
        fn garbled_transcript_is_not_adjudicable() {
            assert!(matches!(
                parse_transcript(0, "rb_f1_rc=1\n"),
                RogueParse::NotAdjudicable { .. }
            ));
        }

        #[test]
        fn stage_failed_marker_is_not_adjudicable() {
            assert!(matches!(
                parse_transcript(1, "rb_error_stage_failed=1\n"),
                RogueParse::NotAdjudicable { .. }
            ));
        }

        #[test]
        fn attack_script_is_fully_substituted() {
            let script = attack_script();
            assert!(!script.contains("__REMOTE_CLI__"));
            assert!(script.contains(REMOTE_CLI));
            for port in PULL_PORTS {
                // Ports arrive as argv; the script must not hardcode them.
                assert!(!script.contains(&format!("{port}")));
            }
            assert!(script.contains("pull-bundle"));
        }

        #[test]
        fn precondition_gap_names_the_missing_linux_node() {
            let mut assignments = Vec::new();
            assert!(precondition_gap(&assignments, &|_| Some(VmGuestPlatform::Macos)).is_some());
            assignments.push(NodeRoleAssignment {
                alias: "linux-a".to_owned(),
                role: crate::vm_lab::orchestrator::role::NodeRole::Client,
            });
            assert!(
                precondition_gap(&assignments, &|a| {
                    if a == "linux-a" {
                        Some(VmGuestPlatform::Linux)
                    } else {
                        None
                    }
                })
                .is_none()
            );
        }

        #[test]
        fn membership_error_display_strings_are_stable_anchors() {
            assert_eq!(
                MembershipError::AttestationStale.to_string(),
                "membership head attestation is stale"
            );
            assert_eq!(
                MembershipError::SignatureInvalid.to_string(),
                "signature verification failed"
            );
        }
    }
}
