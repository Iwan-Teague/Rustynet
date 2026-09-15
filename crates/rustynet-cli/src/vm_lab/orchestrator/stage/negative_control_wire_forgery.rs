//! QH-88: the wire-forgery negative control.
//!
//! The documented attack (NodeEngineAttackCoverageHandover 2026-09-11): an
//! attacker with raw network or local-IPC reach to a node's daemon but NO
//! membership authority injects forged control-plane wire material —
//! (WF-A) a signed membership update minted under an attacker key, delivered
//!      as a raw UDP datagram to the gossip socket — the datagram is
//!      protocol-alien to the gossip frame format, so this leg proves
//!      wire-FORMAT rejection (the frame gate rejects it and the daemon logs
//!      `gossip_recv_error`); it does not exercise the membership signature
//!      gate over UDP;
//! (WF-B) a valid-but-superseded membership update replayed the same way;
//! (WF-C) the same forged update over the local IPC `membership apply` verb
//!      from a root caller (root passes the peer-credential gate, so ONLY
//!      the signature/quorum gate stands between root and state) — this leg
//!      DOES reach the signature/authorization gate, because the IPC apply
//!      path decodes a well-formed envelope;
//! (WF-D) a superseded update over the same IPC verb;
//! (WF-E) a candidate-format gossip bundle signed by an unknown key over the
//!      IPC `gossip push` verb.
//! The security claim is that NONE of these move membership state: every
//! forged wire is rejected, the on-disk snapshot/watermark/log stay
//! byte-identical on the attacked node, a SECOND node's converged view stays
//! byte-identical, the epoch never moves, and the daemon never flaps into
//! restricted safe mode.
//!
//! Tough-policy rule 2: detection is INDEPENDENT of the daemon's self-report.
//! The IPC legs are adjudicated by the attacker-observed `err|` reply, the
//! UDP legs by the daemon's own `gossip_recv_error` journal line, and the
//! immobility legs by orchestrator-computed file hashes on BOTH nodes —
//! never by `overall_ok`.
//!
//! Chain-correct forgery: phase 1 reads the target's REAL persisted snapshot
//! (network_id, epoch, canonical state payload) so the forged records carry
//! the correct network id, prev state root (sha256 over the decoded payload
//! — the same value `MembershipState::state_root_hex` derives) and epoch
//! chain. Only the SIGNER is unauthorized (WF-C) or the chain superseded
//! (WF-D), so the observed rejection class is exactly the gate the attack is
//! meant to prove: the signature/quorum gate, not an earlier format gate.
//! Offline triage re-runs `apply_signed_update` host-side BEFORE shipping to
//! pin the expected rejection class of each forgery.

use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};
use crate::vm_lab::{VmGuestPlatform, sha256_hex_bytes};
use std::path::Path;

/// QH-88: the control's on-disk pass witness — per-forgery transcripts,
/// rejection classes, both nodes' snapshot/watermark/log hashes, the journal
/// counters, and the offline triage verdicts, written by the ONLY pass path.
/// The catalog row declares this exact path; the runner demotes an
/// unwitnessed `Passed`.
pub(crate) const WIRE_FORGERY_TRANSCRIPT_RELATIVE: &str =
    "negative_control/negative_control_wire_forgery/wire_forgery_transcript.txt";

pub struct NegativeControlWireForgeryStage;

impl OrchestrationStage for NegativeControlWireForgeryStage {
    fn id(&self) -> StageId {
        StageId::NegativeControlWireForgery
    }
    fn name(&self) -> &str {
        "negative_control_wire_forgery"
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
        // The UDP legs must come from OUTSIDE the daemon (a second node over
        // the mesh) or they prove nothing about wire-level rejection
        // (tough-policy rule 4): a topology without a second Linux node is a
        // named skip, never an absorbed gap.
        if let Some(reason) = wire_forgery::topology_gap(&ctx.assignments, &|alias| {
            ctx.adapters.get(alias).map(|a| a.platform())
        }) {
            return StageOutcome::Skipped(reason);
        }
        let target = match wire_forgery::select_linux_authority_target(&ctx.assignments, &|alias| {
            ctx.adapters.get(alias).map(|a| a.platform())
        }) {
            Ok(alias) => alias.to_owned(),
            Err(reason) => {
                return StageOutcome::Failed(format!("wire-forgery negative control: {reason}"));
            }
        };
        let aux = wire_forgery::select_aux_target(&ctx.assignments, &target, &|alias| {
            ctx.adapters.get(alias).map(|a| a.platform())
        });
        let Some(target_adapter) = ctx.adapters.get(&target) else {
            return StageOutcome::Failed(format!(
                "wire-forgery negative control: selected target '{target}' has no adapter \
                 (fail closed)"
            ));
        };
        let aux_adapter = aux.and_then(|alias| ctx.adapters.get(alias));
        if aux.is_some() && aux_adapter.is_none() {
            return StageOutcome::Failed(format!(
                "wire-forgery negative control: aux node '{:?}' has no adapter (fail closed)",
                aux
            ));
        }
        wire_forgery::run_wire_forgery_control(
            &dir,
            &target,
            target_adapter.as_ref(),
            aux_adapter.map(|a| a.as_ref()),
        )
    }
}

pub(crate) mod wire_forgery {
    //! The live wire-forgery attack body + its pure adjudication.
    use super::*;
    use crate::vm_lab::orchestrator::adapter::node_adapter::NodeAdapter;
    use crate::vm_lab::orchestrator::remote_shell::RemoteShellHost;
    use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::SigningKey;
    use rustynet_control::membership::{
        MEMBERSHIP_SCHEMA_VERSION, MembershipApprover, MembershipApproverRole,
        MembershipApproverStatus, MembershipError, MembershipNode, MembershipNodeStatus,
        MembershipOperation, MembershipReplayCache, MembershipState, MembershipUpdateRecord,
        apply_signed_update, decode_signed_update, encode_signed_update, sign_update_record,
    };
    use rustynet_control::roles::RoleCapability;
    use rustynetd::dataplane_candidates::CandidateSet;
    use rustynetd::gossip_transport::RUSTYNET_GOSSIP_PORT;
    use rustynetd::peer_gossip::{mint_bundle_with_timestamp, serialise_bundle};
    use std::sync::Arc;

    /// Transcript file name, shared by the writer and the catalog pin.
    pub(crate) const WIRE_FORGERY_TRANSCRIPT_FILE: &str = "wire_forgery_transcript.txt";

    /// The IPC socket path (Linux `DEFAULT_SOCKET_PATH`; pinned by the
    /// `rustynetd.service` unit's `RUSTYNET_SOCKET` environment).
    pub(crate) const IPC_SOCKET: &str = "/run/rustynet/rustynetd.sock";

    /// Linux default membership state files (`rustynetd/src/daemon.rs`
    /// DEFAULT_MEMBERSHIP_* consts; the lab installs no overrides).
    pub(crate) const SNAPSHOT_PATH: &str = "/var/lib/rustynet/membership.snapshot";
    pub(crate) const WATERMARK_PATH: &str = "/var/lib/rustynet/membership.watermark";
    pub(crate) const LOG_PATH: &str = "/var/lib/rustynet/membership.log";

    fn unix_now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn b64(data: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(data)
    }

    // ── topology selection ───────────────────────────────────────────────

    /// Topology precondition: at least one Linux node must be assigned at
    /// all, or the attack cannot run anywhere (named skip; tough-policy
    /// rule 4).
    pub(crate) fn topology_gap(
        assignments: &[NodeRoleAssignment],
        platform_of_fn: &dyn Fn(&str) -> Option<VmGuestPlatform>,
    ) -> Option<String> {
        let linux = assignments
            .iter()
            .any(|a| platform_of_fn(&a.alias) == Some(VmGuestPlatform::Linux));
        if linux {
            None
        } else {
            Some(
                "no Linux node in the topology; the wire-forgery attack needs a Linux guest \
                 hosting a rustynetd authority (anchor/exit) to attack"
                    .to_owned(),
            )
        }
    }

    /// The node hosting the membership authority: a **Linux** `anchor` node,
    /// falling back to the Linux `exit` node (the lab co-locates the anchor
    /// on the exit). Non-Linux candidates are never eligible (the IPC socket
    /// + systemd journal contract is Linux).
    ///
    /// A missing candidate is `Err` (a control FAIL), never a skip-to-green:
    /// the Linux gate above passed, so an unhostable attack is a plan
    /// defect, not a topology gap.
    pub(crate) fn select_linux_authority_target<'a>(
        assignments: &'a [NodeRoleAssignment],
        platform_of_fn: &dyn Fn(&str) -> Option<VmGuestPlatform>,
    ) -> Result<&'a str, String> {
        for role in ["anchor", "exit"] {
            for assignment in assignments {
                if assignment.role.as_str() == role
                    && platform_of_fn(&assignment.alias) == Some(VmGuestPlatform::Linux)
                {
                    return Ok(assignment.alias.as_str());
                }
            }
        }
        Err(
            "wire-forgery negative control: no Linux anchor/exit node to host the attacked \
             daemon (fail closed)"
                .to_owned(),
        )
    }

    /// The second (external attacker) node: a Linux assignment DISTINCT from
    /// the target. `None` ⇒ the caller skips (named topology gap).
    pub(crate) fn select_aux_target<'a>(
        assignments: &'a [NodeRoleAssignment],
        target: &str,
        platform_of_fn: &dyn Fn(&str) -> Option<VmGuestPlatform>,
    ) -> Option<&'a str> {
        assignments
            .iter()
            .find(|a| a.alias != target && platform_of_fn(&a.alias) == Some(VmGuestPlatform::Linux))
            .map(|a| a.alias.as_str())
    }

    // ── guest scripts ────────────────────────────────────────────────────

    /// Phase-1 probe: hash the three membership state files, dump the
    /// snapshot's `state_hex` line, and stamp the epoch-second window start.
    /// Emits `wf_*` tokens only; never exits non-zero for absent files
    /// (absence is reported as `absent` and adjudicated host-side).
    pub(crate) const PROBE_SCRIPT: &str = r#"set -u
snap="$1"; wm="$2"; mlog="$3"
hash_file() { if [ -f "$1" ]; then sha256sum "$1" | cut -d" " -f1; else echo absent; fi; }
echo "wf_snap_sha=$(hash_file "$snap")"
echo "wf_wm_sha=$(hash_file "$wm")"
echo "wf_log_sha=$(hash_file "$mlog")"
echo "wf_epoch_sec=$(date +%s)"
if [ -f "$snap" ]; then
  echo "wf_state_hex=$(sed -n 's/^state_hex=//p' "$snap" | head -1)"
else
  echo "wf_state_hex="
fi
"#;

    /// Phase-2 target script: send the three IPC forgeries, query the daemon
    /// status verb for the restricted-safe-mode observable, re-hash the state
    /// files, then count the daemon's `gossip_recv_error` journal lines in
    /// the TWO disjoint windows the aux sender carved out (forged window
    /// `[t0, mid]`, superseded window `[mid, ∞)`) with a bounded poll so a
    /// slow main-loop drain cannot flake the count to zero. Every value
    /// arrives as an argv element; the body is a fixed literal.
    pub(crate) const TARGET_ATTACK_SCRIPT: &str = r#"set -u
sock="$1"; t0="$2"; snap="$3"; wm="$4"; mlog="$5"; forged_b64="$6"; superseded_b64="$7"; gossip_b64="$8"; mid="$9"
command -v socat >/dev/null 2>&1 || { echo "wf_error_no_socat=1"; exit 3; }
command -v sudo >/dev/null 2>&1 || { echo "wf_error_no_sudo=1"; exit 3; }
command -v journalctl >/dev/null 2>&1 || { echo "wf_error_no_journalctl=1"; exit 3; }
ipc() { printf '%s\n' "$2" | sudo socat -T 10 - UNIX-CONNECT:"$sock"; }
echo "wf_ipc_forged=$(ipc x "membership apply $forged_b64")"
echo "wf_ipc_superseded=$(ipc x "membership apply $superseded_b64")"
echo "wf_ipc_gossip=$(ipc x "gossip push $gossip_b64")"
wf_status_reply=$(ipc x "status")
echo "wf_safe_flaps=$(printf '%s' "$wf_status_reply" | grep -c 'restricted_safe_mode=true' || true)"
hash_file() { if [ -f "$1" ]; then sha256sum "$1" | cut -d" " -f1; else echo absent; fi; }
echo "wf_snap_sha2=$(hash_file "$snap")"
echo "wf_wm_sha2=$(hash_file "$wm")"
echo "wf_log_sha2=$(hash_file "$mlog")"
poll_hits() {
  n=0; i=0
  while [ "$i" -lt 15 ]; do
    n=$(sudo journalctl -u rustynetd --since "@$1" --until "@$2" 2>/dev/null | grep -c 'gossip_recv_error' || true)
    [ "${n:-0}" -ge 1 ] && break
    i=$((i + 1)); sleep 1
  done
  echo "${n:-0}"
}
echo "wf_udp_forged_hits=$(poll_hits "$t0" "$mid")"
echo "wf_udp_superseded_hits=$(poll_hits "$mid" "$(date +%s)")"
"#;

    /// Phase-2 aux script: fire the two protocol-alien UDP datagrams at the
    /// target's gossip socket from OUTSIDE the daemon (over the mesh), carve
    /// the two journal windows the target will count (`wf_mid_ts` separates
    /// the forged datagram's window from the superseded one), then re-hash
    /// THIS node's state files so the orchestrator can prove the second
    /// node's converged view stayed byte-identical. Each send is one
    /// datagram; a send failure is reported, never absorbed.
    pub(crate) const AUX_ATTACK_SCRIPT: &str = r#"set -u
gossip_ip="$1"; port="$2"; forged="$3"; superseded="$4"; snap="$5"; wm="$6"; mlog="$7"
command -v socat >/dev/null 2>&1 || { echo "wf_error_no_socat=1"; exit 3; }
printf '%s' "$forged" | socat -T 5 - "UDP-DATAGRAM:$gossip_ip:$port"
echo "wf_udp_forged_sent=$?"
sleep 6
echo "wf_mid_ts=$(date +%s)"
printf '%s' "$superseded" | socat -T 5 - "UDP-DATAGRAM:$gossip_ip:$port"
echo "wf_udp_superseded_sent=$?"
hash_file() { if [ -f "$1" ]; then sha256sum "$1" | cut -d" " -f1; else echo absent; fi; }
echo "wf_snap_sha=$(hash_file "$snap")"
echo "wf_wm_sha=$(hash_file "$wm")"
echo "wf_log_sha=$(hash_file "$mlog")"
"#;

    // ── parsing ──────────────────────────────────────────────────────────

    fn field<'a>(stdout: &'a str, key: &str) -> Option<&'a str> {
        stdout
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{key}=")))
            .map(str::trim)
    }

    fn require<'a>(stdout: &'a str, key: &str) -> Result<&'a str, String> {
        field(stdout, key).ok_or_else(|| format!("probe output missing required token '{key}='"))
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct NodeStateHashes {
        pub(crate) snap: String,
        pub(crate) wm: String,
        pub(crate) mlog: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct TargetProbe {
        pub(crate) hashes: NodeStateHashes,
        pub(crate) epoch_sec: u64,
        pub(crate) state_hex: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct TargetPost {
        pub(crate) hashes: NodeStateHashes,
        pub(crate) ipc_forged: String,
        pub(crate) ipc_superseded: String,
        pub(crate) ipc_gossip: String,
        pub(crate) udp_forged_hits: u64,
        pub(crate) udp_superseded_hits: u64,
        pub(crate) safe_flaps: u64,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct AuxPost {
        pub(crate) hashes: NodeStateHashes,
        pub(crate) udp_forged_sent: String,
        pub(crate) udp_superseded_sent: String,
        /// Epoch second between the two sends — the journal-window split the
        /// target counts each datagram's rejection in.
        pub(crate) mid_ts: u64,
    }

    pub(crate) fn parse_probe(stdout: &str) -> Result<TargetProbe, String> {
        Ok(TargetProbe {
            hashes: NodeStateHashes {
                snap: require(stdout, "wf_snap_sha")?.to_owned(),
                wm: require(stdout, "wf_wm_sha")?.to_owned(),
                mlog: require(stdout, "wf_log_sha")?.to_owned(),
            },
            epoch_sec: require(stdout, "wf_epoch_sec")?
                .parse()
                .map_err(|e| format!("wf_epoch_sec not a number: {e}"))?,
            state_hex: field(stdout, "wf_state_hex").unwrap_or("").to_owned(),
        })
    }

    /// Named-tool preflight: the scripts emit `wf_error_no_<tool>=1` (and
    /// exit 3) when a required tool is absent, so a degraded guest produces
    /// a named cause instead of an empty-output parse error.
    fn named_tool_error(stdout: &str) -> Option<String> {
        for tool in ["socat", "sudo", "journalctl"] {
            if field(stdout, &format!("wf_error_no_{tool}")).is_some() {
                return Some(format!("required tool '{tool}' absent on guest"));
            }
        }
        None
    }

    pub(crate) fn parse_target_post(stdout: &str) -> Result<TargetPost, String> {
        if let Some(err) = named_tool_error(stdout) {
            return Err(err);
        }
        Ok(TargetPost {
            hashes: NodeStateHashes {
                snap: require(stdout, "wf_snap_sha2")?.to_owned(),
                wm: require(stdout, "wf_wm_sha2")?.to_owned(),
                mlog: require(stdout, "wf_log_sha2")?.to_owned(),
            },
            ipc_forged: require(stdout, "wf_ipc_forged")?.to_owned(),
            ipc_superseded: require(stdout, "wf_ipc_superseded")?.to_owned(),
            ipc_gossip: require(stdout, "wf_ipc_gossip")?.to_owned(),
            udp_forged_hits: require(stdout, "wf_udp_forged_hits")?
                .parse()
                .map_err(|e| format!("wf_udp_forged_hits not a number: {e}"))?,
            udp_superseded_hits: require(stdout, "wf_udp_superseded_hits")?
                .parse()
                .map_err(|e| format!("wf_udp_superseded_hits not a number: {e}"))?,
            safe_flaps: require(stdout, "wf_safe_flaps")?
                .parse()
                .map_err(|e| format!("wf_safe_flaps not a number: {e}"))?,
        })
    }

    pub(crate) fn parse_aux_post(stdout: &str) -> Result<AuxPost, String> {
        if let Some(err) = named_tool_error(stdout) {
            return Err(err);
        }
        Ok(AuxPost {
            hashes: NodeStateHashes {
                snap: require(stdout, "wf_snap_sha")?.to_owned(),
                wm: require(stdout, "wf_wm_sha")?.to_owned(),
                mlog: require(stdout, "wf_log_sha")?.to_owned(),
            },
            udp_forged_sent: require(stdout, "wf_udp_forged_sent")?.to_owned(),
            udp_superseded_sent: require(stdout, "wf_udp_superseded_sent")?.to_owned(),
            mid_ts: require(stdout, "wf_mid_ts")?
                .parse()
                .map_err(|e| format!("wf_mid_ts not a number: {e}"))?,
        })
    }

    // ── minting ──────────────────────────────────────────────────────────

    /// Parsed identity of the target's persisted membership state: everything
    /// a chain-correct forgery must echo.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct LiveStateIdentity {
        pub(crate) network_id: String,
        pub(crate) epoch: u64,
        pub(crate) prev_state_root: String,
        /// Live quorum, mirrored into the offline-triage synthetic state so
        /// the triaged rejection class is the class the LIVE daemon names
        /// (with quorum ≥ 2 the threshold gate fires before signer
        /// authorization; with quorum 1 the signer gate decides).
        pub(crate) quorum_threshold: u64,
    }

    /// Derive the state identity from the snapshot's hex-encoded canonical
    /// payload. `prev_state_root` is sha256 over the decoded payload bytes —
    /// the exact value `MembershipState::state_root_hex()` derives (it
    /// hashes the canonical payload text), so a forged record carrying it
    /// gets PAST the prev-state-root gate and is judged by the signature
    /// gate, which is the gate QH-88 exists to prove.
    pub(crate) fn state_identity_from_snapshot(
        state_hex: &str,
    ) -> Result<LiveStateIdentity, String> {
        if state_hex.is_empty() {
            return Err(
                "target snapshot carries no state_hex line (not a membership \
                        authority?)"
                    .to_owned(),
            );
        }
        let payload_bytes = decode_hex_str(state_hex)?;
        let payload = String::from_utf8(payload_bytes.clone()).map_err(|_| {
            "snapshot state_hex does not decode to UTF-8 canonical payload".to_owned()
        })?;
        let network_id = payload
            .lines()
            .find_map(|l| l.strip_prefix("network_id="))
            .ok_or_else(|| "canonical payload missing network_id=".to_owned())?
            .trim()
            .to_owned();
        let epoch = payload
            .lines()
            .find_map(|l| l.strip_prefix("epoch="))
            .ok_or_else(|| "canonical payload missing epoch=".to_owned())?
            .trim()
            .parse()
            .map_err(|e| format!("epoch not a number: {e}"))?;
        let quorum_threshold = payload
            .lines()
            .find_map(|l| l.strip_prefix("quorum_threshold="))
            .ok_or_else(|| "canonical payload missing quorum_threshold=".to_owned())?
            .trim()
            .parse()
            .map_err(|e| format!("quorum_threshold not a number: {e}"))?;
        if quorum_threshold == 0 || quorum_threshold > u64::from(u8::MAX) {
            return Err("live quorum_threshold outside the u8 state field range".to_owned());
        }
        Ok(LiveStateIdentity {
            network_id,
            epoch,
            prev_state_root: sha256_hex_bytes(&payload_bytes),
            quorum_threshold,
        })
    }

    /// Mint ONE signed membership update record. `epoch_new` selects the
    /// forgery class: `epoch+1` = chain-correct forged update (WF-C/WF-A),
    /// `epoch` = superseded/replayed chain (WF-D/WF-B). Always signed by the
    /// throwaway attacker key — never a real approver key (the control mints
    /// forgeries, not authority).
    pub(crate) fn mint_forged_update(
        identity: &LiveStateIdentity,
        epoch_new: u64,
        attacker_key: &SigningKey,
        now_unix: u64,
    ) -> Result<String, String> {
        let record = MembershipUpdateRecord {
            network_id: identity.network_id.clone(),
            update_id: format!("wf-forged-{now_unix}-{epoch_new}"),
            operation: MembershipOperation::AddNode(MembershipNode {
                node_id: "wf-attacker-node".to_owned(),
                node_pubkey_hex: hex(&attacker_key.verifying_key().to_bytes()),
                owner: "wf-attacker@example.invalid".to_owned(),
                status: MembershipNodeStatus::Active,
                roles: vec!["tag:servers".to_owned()],
                capabilities: vec![RoleCapability::Anchor],
                joined_at_unix: now_unix,
                updated_at_unix: now_unix,
            }),
            target: "wf-attacker-node".to_owned(),
            prev_state_root: identity.prev_state_root.clone(),
            new_state_root: identity.prev_state_root.clone(),
            epoch_prev: if epoch_new == identity.epoch + 1 {
                identity.epoch
            } else {
                identity.epoch.saturating_sub(1)
            },
            epoch_new,
            created_at_unix: now_unix,
            expires_at_unix: now_unix + 600,
            reason_code: "wf-forgery".to_owned(),
            policy_context: None,
        };
        let signature = sign_update_record(&record, "wf-attacker-approver", attacker_key)
            .map_err(|e| format!("sign forged record: {e}"))?;
        let signed = rustynet_control::membership::SignedMembershipUpdate {
            record,
            approver_signatures: vec![signature],
        };
        encode_signed_update(&signed).map_err(|e| format!("encode forged update: {e}"))
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Plain positional hex decode (no custom cryptography — base-16 is a
    /// transport encoding, not a primitive).
    fn decode_hex_str(s: &str) -> Result<Vec<u8>, String> {
        let s = s.trim();
        if !s.len().is_multiple_of(2) {
            return Err("hex string has odd length".to_owned());
        }
        let byte = |hi: u8, lo: u8| -> Result<u8, String> {
            let nib = |c: u8| match c {
                b'0'..=b'9' => Ok(c - b'0'),
                b'a'..=b'f' => Ok(c - b'a' + 10),
                b'A'..=b'F' => Ok(c - b'A' + 10),
                _ => Err(format!("invalid hex nibble '{c}'")),
            };
            Ok(nib(hi)? * 16 + nib(lo)?)
        };
        s.as_bytes()
            .chunks(2)
            .map(|pair| byte(pair[0], pair[1]))
            .collect()
    }

    /// Offline triage: apply a minted forgery against a minimal synthetic
    /// state that carries the SAME network id, epoch and quorum as the live
    /// target (the approver roster is synthetic and deliberately does NOT
    /// contain the attacker's approver — mirroring the live daemon, where
    /// the attacker is unknown; the class-determining gates — network id,
    /// expiry, prev root, epoch chain, quorum/signer authorization — are
    /// state-shape independent because `apply_signed_update` checks them in
    /// that order).
    /// Returns the rejection class the live daemon MUST name.
    ///
    /// Note: the live daemon adjudicates against
    /// `replay_membership_snapshot_and_log(snapshot, log)`, not the raw
    /// snapshot. In steady state the replay folds only NEW log entries
    /// (entries with `epoch_prev` below the snapshot epoch are skipped), so
    /// the snapshot-derived identity is exact; a crash-window log tail could
    /// make an earlier gate fire first — the stage would then FAIL (fail
    /// closed), which is acceptable for a control.
    pub(crate) fn offline_triage(
        identity: &LiveStateIdentity,
        envelope: &str,
        now_unix: u64,
    ) -> Result<String, String> {
        let signed =
            decode_signed_update(envelope).map_err(|e| format!("triage decode failed: {e}"))?;
        // A filler roster as large as the live quorum keeps the synthetic
        // state valid; none of the fillers is the attacker's approver.
        let approver_set: Vec<MembershipApprover> = (0..identity.quorum_threshold)
            .map(|i| {
                // Per-index seeds: state validation rejects a pubkey reused
                // across approver ids, so fillers must not share one key.
                let mut seed = [7u8; 32];
                seed[0] = u8::try_from(i).unwrap_or(u8::MAX);
                MembershipApprover {
                    approver_id: format!("wf-filler-{i}"),
                    approver_pubkey_hex: hex(&SigningKey::from_bytes(&seed)
                        .verifying_key()
                        .to_bytes()),
                    role: MembershipApproverRole::Owner,
                    status: MembershipApproverStatus::Active,
                    created_at_unix: 100,
                }
            })
            .collect();
        let synthetic = MembershipState {
            schema_version: MEMBERSHIP_SCHEMA_VERSION,
            network_id: identity.network_id.clone(),
            epoch: identity.epoch,
            nodes: Vec::new(),
            approver_set,
            quorum_threshold: u8::try_from(identity.quorum_threshold)
                .map_err(|_| "triage quorum outside u8".to_owned())?,
            metadata_hash: None,
            tombstones: Vec::new(),
        };
        // The synthetic state's own root differs from the live one; patch the
        // record's prev root to the synthetic root so the prev-root gate
        // passes and the class is decided by the QUORUM/SIGNER gate (the
        // gate under test), mirroring the live target where prev root
        // matches.
        let mut triage_signed = signed.clone();
        triage_signed.record.prev_state_root = synthetic
            .state_root_hex()
            .map_err(|e| format!("triage synthetic root: {e}"))?;
        let mut cache = MembershipReplayCache::default();
        match apply_signed_update(&synthetic, &triage_signed, now_unix, &mut cache) {
            Ok(_) => Err(
                "triage: forged update was ACCEPTED by the synthetic state — the \
                          control would be vacuous; refusing to ship"
                    .to_owned(),
            ),
            Err(err) => Ok(class_of(&err)),
        }
    }

    /// The stable rejection-class substring an error maps to. The order
    /// mirrors `verify_membership_signatures`: the distinct-signer/quorum
    /// threshold is checked before per-signer authorization, and both fire
    /// before the cryptographic signature verify.
    pub(crate) fn class_of(err: &MembershipError) -> String {
        let text = err.to_string();
        if text.contains("threshold signature requirements not met") {
            "threshold signature requirements not met".to_owned()
        } else if text.contains("signer is not authorized") {
            "signer is not authorized".to_owned()
        } else if text.contains("signature verification failed") {
            "signature verification failed".to_owned()
        } else if text.contains("epoch chain mismatch") {
            "epoch chain mismatch".to_owned()
        } else {
            text
        }
    }

    // ── expectations + adjudication ──────────────────────────────────────

    /// What each vector must show for the control to pass.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct ForgeryExpectation {
        pub(crate) tag: &'static str,
        pub(crate) rejection_class: &'static str,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct WireForgeryOutcome {
        pub(crate) verdicts: Vec<(&'static str, bool, String)>,
        pub(crate) pass: bool,
    }

    impl WireForgeryOutcome {
        pub(crate) fn is_control_pass(&self) -> bool {
            self.pass
        }
    }

    pub(crate) const ROLE_DENIAL_MARKER: &str = "command denied";

    /// Pure adjudication. IPC legs: the attacker-observed reply must be an
    /// `err|…` REJECTION in one of the two accepted families — either the
    /// triaged membership/gossip rejection class (signature / epoch gate) or
    /// `command denied: current node role does not permit this operation`
    /// (the daemon's per-role IPC authorization gate, which on a non-admin
    /// node fires BEFORE the membership gates and is the stricter default-
    /// deny outcome; live-run livelab-1789430002-b0aba24a2721 showed the
    /// exit-role daemon denies the command outright). Success replies or
    /// non-rejection noise fail the leg. UDP legs: each datagram was sent
    /// (exit 0) AND the daemon's journal shows `gossip_recv_error` at least
    /// once in THAT datagram's own disjoint window. Immobile-state legs:
    /// snapshot/watermark/log hashes byte-identical on BOTH nodes; the
    /// daemon's `status` reply contains no `restricted_safe_mode=true`.
    /// Any miss is a named verdict; `pass` is the AND.
    pub(crate) fn adjudicate(
        forged_class: &str,
        superseded_class: &str,
        pre_target: &TargetProbe,
        post_target: &TargetPost,
        pre_aux: &NodeStateHashes,
        post_aux: &AuxPost,
    ) -> WireForgeryOutcome {
        let mut verdicts: Vec<(&'static str, bool, String)> = Vec::new();
        let mut v = |tag: &'static str, ok: bool, detail: String| verdicts.push((tag, ok, detail));

        v(
            "WF-A_udp_forged_rejected",
            post_aux.udp_forged_sent == "0" && post_target.udp_forged_hits >= 1,
            format!(
                "udp sent={} journal gossip_recv_error hits in [t0,mid]={}",
                post_aux.udp_forged_sent, post_target.udp_forged_hits
            ),
        );
        v(
            "WF-B_udp_superseded_rejected",
            post_aux.udp_superseded_sent == "0" && post_target.udp_superseded_hits >= 1,
            format!(
                "udp sent={} journal gossip_recv_error hits in [mid,now]={}",
                post_aux.udp_superseded_sent, post_target.udp_superseded_hits
            ),
        );
        let ipc_ok = |reply: &str, class: &str| {
            reply.starts_with("err|")
                && (reply.contains(class) || reply.contains(ROLE_DENIAL_MARKER))
        };
        v(
            "WF-C_ipc_forged_rejected",
            ipc_ok(&post_target.ipc_forged, forged_class),
            format!(
                "reply={} expected_class={forged_class} (or role-gate {})",
                post_target.ipc_forged, ROLE_DENIAL_MARKER
            ),
        );
        v(
            "WF-D_ipc_superseded_rejected",
            ipc_ok(&post_target.ipc_superseded, superseded_class),
            format!(
                "reply={} expected_class={superseded_class} (or role-gate {})",
                post_target.ipc_superseded, ROLE_DENIAL_MARKER
            ),
        );
        v(
            "WF-E_ipc_gossip_forged_rejected",
            post_target.ipc_gossip.starts_with("err|")
                && (post_target.ipc_gossip.starts_with("err|gossip rejected:")
                    || post_target.ipc_gossip.contains(ROLE_DENIAL_MARKER)),
            format!("reply={}", post_target.ipc_gossip),
        );
        v(
            "target_state_immobile",
            pre_target.hashes == post_target.hashes,
            format!(
                "snap {}/{} wm {}/{} log {}/{}",
                pre_target.hashes.snap,
                post_target.hashes.snap,
                pre_target.hashes.wm,
                post_target.hashes.wm,
                pre_target.hashes.mlog,
                post_target.hashes.mlog
            ),
        );
        v(
            "aux_view_unchanged",
            *pre_aux == post_aux.hashes,
            format!(
                "snap {}/{} wm {}/{} log {}/{}",
                pre_aux.snap,
                post_aux.hashes.snap,
                pre_aux.wm,
                post_aux.hashes.wm,
                pre_aux.mlog,
                post_aux.hashes.mlog
            ),
        );
        v(
            "no_restricted_safe_mode_flap",
            post_target.safe_flaps == 0,
            format!("safe_flaps={}", post_target.safe_flaps),
        );

        let pass = verdicts.iter().all(|(_, ok, _)| *ok);
        WireForgeryOutcome { verdicts, pass }
    }

    // ── transport ────────────────────────────────────────────────────────

    fn run_remote_argv(
        shell: &Arc<dyn RemoteShellHost>,
        argv: &[&str],
    ) -> Result<(i32, String, String), String> {
        let status = shell
            .run_argv(argv, &[], &[])
            .map_err(|err| format!("transport failure running {argv:?}: {err}"))?;
        Ok((
            status.code,
            String::from_utf8_lossy(&status.stdout).into_owned(),
            String::from_utf8_lossy(&status.stderr).into_owned(),
        ))
    }

    // ── the control body ─────────────────────────────────────────────────

    /// The (QH-88) control body. A working control returns
    /// [`StageOutcome::Passed`] (every forgery rejected by name with zero
    /// state movement on either node).
    pub(crate) fn run_wire_forgery_control(
        workdir: &Path,
        target_alias: &str,
        target_adapter: &dyn NodeAdapter,
        aux_adapter: Option<&dyn NodeAdapter>,
    ) -> StageOutcome {
        let fail = |reason: String| {
            StageOutcome::Failed(format!(
                "wire-forgery negative control [target {target_alias}]: {reason}"
            ))
        };
        if target_adapter.platform() != VmGuestPlatform::Linux {
            return fail(format!(
                "target platform {:?} cannot host the wire-forgery attack (fail closed)",
                target_adapter.platform()
            ));
        }
        let Some(aux_adapter) = aux_adapter else {
            return StageOutcome::Skipped(
                "wire-forgery negative control: no second Linux node for the external UDP \
                 leg; a same-node-only attack cannot prove wire-level rejection (rule 4)"
                    .to_owned(),
            );
        };
        if aux_adapter.platform() != VmGuestPlatform::Linux {
            return fail(format!(
                "aux platform {:?} cannot host the external UDP leg (fail closed)",
                aux_adapter.platform()
            ));
        }
        let target_shell = match target_adapter.shell_host() {
            Ok(shell) => shell,
            Err(err) => return fail(format!("no remote shell host on target: {err}")),
        };
        let aux_shell = match aux_adapter.shell_host() {
            Ok(shell) => shell,
            Err(err) => return fail(format!("no remote shell host on aux: {err}")),
        };
        let target_mesh_ip = match target_adapter.collect_mesh_ip() {
            Ok(ip) => ip,
            Err(err) => return fail(format!("target mesh ip: {err}")),
        };

        // 1. Phase-1 probe on BOTH nodes (baseline hashes + target state).
        let target_probe_out = match run_remote_argv(
            &target_shell,
            &[
                "bash",
                "-c",
                PROBE_SCRIPT,
                "wf-probe",
                SNAPSHOT_PATH,
                WATERMARK_PATH,
                LOG_PATH,
            ],
        ) {
            Ok((0, out, _)) => out,
            Ok((code, _, err)) => {
                return fail(format!("target probe exited {code}: {err}"));
            }
            Err(err) => return fail(err),
        };
        let target_probe = match parse_probe(&target_probe_out) {
            Ok(p) => p,
            Err(err) => return fail(format!("target probe parse: {err}")),
        };
        let aux_probe_out = match run_remote_argv(
            &aux_shell,
            &[
                "bash",
                "-c",
                PROBE_SCRIPT,
                "wf-probe",
                SNAPSHOT_PATH,
                WATERMARK_PATH,
                LOG_PATH,
            ],
        ) {
            Ok((0, out, _)) => out,
            Ok((code, _, err)) => return fail(format!("aux probe exited {code}: {err}")),
            Err(err) => return fail(err),
        };
        let aux_probe = match parse_probe(&aux_probe_out) {
            Ok(p) => p,
            Err(err) => return fail(format!("aux probe parse: {err}")),
        };
        if aux_probe.state_hex.is_empty() {
            return StageOutcome::Skipped(
                "wire-forgery negative control: aux node carries no membership snapshot; \
                 'second node's converged view unchanged' cannot be adjudicated (rule 4)"
                    .to_owned(),
            );
        }

        // 2. Mint the chain-correct forgeries against the LIVE identity and
        //    prove each expected rejection class offline BEFORE shipping.
        let identity = match state_identity_from_snapshot(&target_probe.state_hex) {
            Ok(i) => i,
            Err(err) => return fail(err),
        };
        let attacker_key = SigningKey::from_bytes(&[0xA5u8; 32]);
        let now = unix_now();
        let forged_envelope =
            match mint_forged_update(&identity, identity.epoch + 1, &attacker_key, now) {
                Ok(e) => e,
                Err(err) => return fail(format!("mint forged: {err}")),
            };
        let superseded_envelope =
            match mint_forged_update(&identity, identity.epoch, &attacker_key, now) {
                Ok(e) => e,
                Err(err) => return fail(format!("mint superseded: {err}")),
            };
        let forged_class = match offline_triage(&identity, &forged_envelope, now) {
            Ok(c) => c,
            Err(err) => return fail(err),
        };
        let superseded_class = match offline_triage(&identity, &superseded_envelope, now) {
            Ok(c) => c,
            Err(err) => return fail(err),
        };

        // WF-E: a candidate-format gossip bundle under the attacker key —
        // unknown to the daemon's known-peer roster (which is loaded from the
        // signed membership snapshot the attacker cannot write).
        let gossip_bundle = match mint_bundle_with_timestamp(
            &attacker_key,
            1,
            now,
            identity.epoch,
            CandidateSet::default(),
        ) {
            Ok(b) => serialise_bundle(&b),
            Err(err) => return fail(format!("mint gossip bundle: {err}")),
        };

        // 3. Fire. UDP legs FIRST from the aux node (their journal evidence
        //    is read by the target script whose windows start at phase-1 t0
        //    and split at the aux-reported mid stamp).
        let aux_out = match run_remote_argv(
            &aux_shell,
            &[
                "bash",
                "-c",
                AUX_ATTACK_SCRIPT,
                "wf-aux",
                &target_mesh_ip,
                &RUSTYNET_GOSSIP_PORT.to_string(),
                &forged_envelope,
                &superseded_envelope,
                SNAPSHOT_PATH,
                WATERMARK_PATH,
                LOG_PATH,
            ],
        ) {
            Ok((0, out, _)) => out,
            Ok((code, out, err)) => {
                // A named tool preflight (exit 3) puts its cause on stdout;
                // surface it before falling back to the exit code.
                if let Some(cause) = named_tool_error(&out) {
                    return fail(format!("aux attack preflight: {cause}"));
                }
                return fail(format!("aux attack exited {code}: {err}"));
            }
            Err(err) => return fail(err),
        };
        let aux_post = match parse_aux_post(&aux_out) {
            Ok(p) => p,
            Err(err) => return fail(format!("aux attack parse: {err}")),
        };

        let target_out = match run_remote_argv(
            &target_shell,
            &[
                "bash",
                "-c",
                TARGET_ATTACK_SCRIPT,
                "wf-target",
                IPC_SOCKET,
                &target_probe.epoch_sec.to_string(),
                SNAPSHOT_PATH,
                WATERMARK_PATH,
                LOG_PATH,
                &b64(forged_envelope.as_bytes()),
                &b64(superseded_envelope.as_bytes()),
                &b64(&gossip_bundle),
                &aux_post.mid_ts.to_string(),
            ],
        ) {
            Ok((0, out, _)) => out,
            Ok((code, out, err)) => {
                if let Some(cause) = named_tool_error(&out) {
                    return fail(format!("target attack preflight: {cause}"));
                }
                return fail(format!("target attack exited {code}: {err}"));
            }
            Err(err) => return fail(err),
        };
        let target_post = match parse_target_post(&target_out) {
            Ok(p) => p,
            Err(err) => return fail(format!("target attack parse: {err}")),
        };

        // 4. Adjudicate (pure) and write the witness on the ONLY pass path.
        let outcome = adjudicate(
            &forged_class,
            &superseded_class,
            &target_probe,
            &target_post,
            &aux_probe.hashes,
            &aux_post,
        );
        let transcript = render_transcript(
            &TranscriptFacts {
                identity: &identity,
                forged_class: &forged_class,
                superseded_class: &superseded_class,
                pre_target: &target_probe,
                post_target: &target_post,
                pre_aux: &aux_probe.hashes,
                post_aux: &aux_post,
            },
            &outcome,
        );
        if !outcome.pass {
            return fail(format!(
                "control inverted: one or more forgeries moved state or was not rejected; \
                 transcript follows\n{transcript}"
            ));
        }
        if let Err(err) = std::fs::create_dir_all(workdir)
            .map_err(|e| format!("create {}: {e}", workdir.display()))
            .and_then(|_| {
                std::fs::write(workdir.join(WIRE_FORGERY_TRANSCRIPT_FILE), &transcript)
                    .map_err(|e| format!("write transcript: {e}"))
            })
        {
            return fail(format!("witness write failed (pass unwitnessed): {err}"));
        }
        StageOutcome::Passed
    }

    /// Everything the transcript renders from, bundled to keep the renderer's
    /// signature small.
    struct TranscriptFacts<'a> {
        identity: &'a LiveStateIdentity,
        forged_class: &'a str,
        superseded_class: &'a str,
        pre_target: &'a TargetProbe,
        post_target: &'a TargetPost,
        pre_aux: &'a NodeStateHashes,
        post_aux: &'a AuxPost,
    }

    fn render_transcript(facts: &TranscriptFacts<'_>, outcome: &WireForgeryOutcome) -> String {
        let TranscriptFacts {
            identity,
            forged_class,
            superseded_class,
            pre_target,
            post_target,
            pre_aux,
            post_aux,
        } = *facts;
        let mut out = String::new();
        out.push_str("QH-88 wire-forgery negative control — PASS transcript\n");
        out.push_str(&format!(
            "target identity: network_id={} epoch={} prev_state_root={}\n",
            identity.network_id, identity.epoch, identity.prev_state_root
        ));
        out.push_str(&format!(
            "expected forged rejection class: {forged_class}\n"
        ));
        out.push_str(&format!(
            "expected superseded rejection class: {superseded_class}\n\n"
        ));
        for (tag, ok, detail) in &outcome.verdicts {
            out.push_str(&format!(
                "[{}] {tag}: {detail}\n",
                if *ok { "PASS" } else { "FAIL" }
            ));
        }
        out.push_str("\n## target pre hashes\n");
        out.push_str(&format!("snapshot {}\n", pre_target.hashes.snap));
        out.push_str(&format!("watermark {}\n", pre_target.hashes.wm));
        out.push_str(&format!("log {}\n", pre_target.hashes.mlog));
        out.push_str("## target post hashes\n");
        out.push_str(&format!("snapshot {}\n", post_target.hashes.snap));
        out.push_str(&format!("watermark {}\n", post_target.hashes.wm));
        out.push_str(&format!("log {}\n", post_target.hashes.mlog));
        out.push_str("## aux pre hashes\n");
        out.push_str(&format!("snapshot {}\n", pre_aux.snap));
        out.push_str(&format!("watermark {}\n", pre_aux.wm));
        out.push_str(&format!("log {}\n", pre_aux.mlog));
        out.push_str("## aux post hashes\n");
        out.push_str(&format!("snapshot {}\n", post_aux.hashes.snap));
        out.push_str(&format!("watermark {}\n", post_aux.hashes.wm));
        out.push_str(&format!("log {}\n", post_aux.hashes.mlog));
        out.push_str("## attacker-observed IPC replies\n");
        out.push_str(&format!("forged: {}\n", post_target.ipc_forged));
        out.push_str(&format!("superseded: {}\n", post_target.ipc_superseded));
        out.push_str(&format!("gossip: {}\n", post_target.ipc_gossip));
        out
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const NOW: u64 = 1_773_000_000;

        fn hashes(tag: &str) -> NodeStateHashes {
            NodeStateHashes {
                snap: format!("{tag}-snap"),
                wm: format!("{tag}-wm"),
                mlog: format!("{tag}-log"),
            }
        }

        fn sample_identity() -> LiveStateIdentity {
            LiveStateIdentity {
                network_id: "wf-net".to_owned(),
                epoch: 3,
                prev_state_root: "abc".to_owned(),
                quorum_threshold: 1,
            }
        }

        fn hex_encode(bytes: &[u8]) -> String {
            bytes.iter().map(|b| format!("{b:02x}")).collect()
        }

        #[test]
        fn decode_hex_round_trip_and_errors() {
            let bytes = b"network_id=wf-net";
            assert_eq!(decode_hex_str(&hex_encode(bytes)).unwrap(), bytes.to_vec());
            assert!(decode_hex_str("abc").is_err());
            assert!(decode_hex_str("zz").is_err());
            assert!(decode_hex_str("").unwrap().is_empty());
        }

        #[test]
        fn state_identity_parses_payload_fields() {
            let payload = "network_id=wf-net\nepoch=3\nquorum_threshold=1\n";
            let state_hex = hex_encode(payload.as_bytes());
            let identity = state_identity_from_snapshot(&state_hex).unwrap();
            assert_eq!(identity.network_id, "wf-net");
            assert_eq!(identity.epoch, 3);
            assert_eq!(identity.quorum_threshold, 1);
            assert_eq!(
                identity.prev_state_root,
                sha256_hex_bytes(payload.as_bytes())
            );
        }

        #[test]
        fn state_identity_rejects_missing_or_bad_payload() {
            assert!(state_identity_from_snapshot("").is_err());
            let no_quorum = hex_encode(b"network_id=n\nepoch=1\n");
            assert!(
                state_identity_from_snapshot(&no_quorum)
                    .unwrap_err()
                    .contains("quorum_threshold")
            );
            let zero_quorum = hex_encode(b"network_id=n\nepoch=1\nquorum_threshold=0\n");
            assert!(
                state_identity_from_snapshot(&zero_quorum)
                    .unwrap_err()
                    .contains("outside the u8")
            );
        }

        /// Regression pin for the review BLOCKER: the aux attack script's
        /// stdout MUST carry the post-attack state hashes; a parser that
        /// accepts output without them would silently drop the
        /// `aux_view_unchanged` leg.
        #[test]
        fn parse_aux_post_requires_hash_tokens() {
            let mut out = String::from("wf_udp_forged_sent=0\nwf_udp_superseded_sent=0\n");
            assert!(parse_aux_post(&out).is_err());
            out.push_str(&format!(
                "wf_mid_ts={NOW}\nwf_snap_sha=a\nwf_wm_sha=b\nwf_log_sha=c\n"
            ));
            let parsed = parse_aux_post(&out).unwrap();
            assert_eq!(parsed.hashes.snap, "a");
            assert_eq!(parsed.hashes.wm, "b");
            assert_eq!(parsed.hashes.mlog, "c");
            assert_eq!(parsed.mid_ts, NOW);
        }

        #[test]
        fn parse_target_post_split_windows_and_preflight() {
            let full = "\
wf_ipc_forged=err|membership apply rejected: signer is not authorized
wf_ipc_superseded=err|membership apply rejected: epoch chain mismatch
wf_ipc_gossip=err|gossip rejected: unknown-peer
wf_safe_flaps=0
wf_snap_sha2=a2
wf_wm_sha2=b2
wf_log_sha2=c2
wf_udp_forged_hits=1
wf_udp_superseded_hits=2
";
            let parsed = parse_target_post(full).unwrap();
            assert_eq!(parsed.udp_forged_hits, 1);
            assert_eq!(parsed.udp_superseded_hits, 2);
            assert_eq!(parsed.hashes.snap, "a2");
            assert_eq!(parsed.safe_flaps, 0);

            assert!(parse_target_post("wf_ipc_forged=x\n").is_err());
            let no_socat = "wf_error_no_socat=1\n";
            assert!(parse_target_post(no_socat).unwrap_err().contains("socat"));
        }

        #[test]
        fn parse_target_post_field_prefixes_do_not_collide() {
            // wf_snap_sha must not satisfy wf_snap_sha2 and vice versa.
            let out = "wf_snap_sha=x\nwf_snap_sha2=y\nwf_wm_sha2=y\nwf_log_sha2=y\n\
wf_ipc_forged=f\nwf_ipc_superseded=s\nwf_ipc_gossip=g\nwf_safe_flaps=0\n\
wf_udp_forged_hits=0\nwf_udp_superseded_hits=0\n";
            assert_eq!(parse_target_post(out).unwrap().hashes.snap, "y");
            assert_eq!(
                parse_aux_post(
                    "wf_snap_sha=x\nwf_wm_sha=x\nwf_log_sha=x\n\
wf_udp_forged_sent=0\nwf_udp_superseded_sent=0\nwf_mid_ts=5\n"
                )
                .unwrap()
                .hashes
                .snap,
                "x"
            );
        }

        #[test]
        fn triage_pins_rejection_classes_per_quorum() {
            let attacker_key = SigningKey::from_bytes(&[0xA5u8; 32]);
            let now = NOW;
            for (quorum, expected_forged, expected_superseded) in [
                (1u64, "signer is not authorized", "epoch chain mismatch"),
                (
                    2u64,
                    "threshold signature requirements not met",
                    "epoch chain mismatch",
                ),
            ] {
                let mut identity = sample_identity();
                identity.quorum_threshold = quorum;
                let forged =
                    mint_forged_update(&identity, identity.epoch + 1, &attacker_key, now).unwrap();
                assert_eq!(
                    offline_triage(&identity, &forged, now).unwrap(),
                    expected_forged,
                    "quorum {quorum} forged class"
                );
                let superseded =
                    mint_forged_update(&identity, identity.epoch, &attacker_key, now).unwrap();
                assert_eq!(
                    offline_triage(&identity, &superseded, now).unwrap(),
                    expected_superseded,
                    "quorum {quorum} superseded class"
                );
            }
        }

        fn all_pass_artifacts() -> (TargetProbe, TargetPost, NodeStateHashes, AuxPost) {
            let pre = hashes("pre");
            let post = hashes("pre");
            let probe = TargetProbe {
                hashes: pre.clone(),
                epoch_sec: NOW,
                state_hex: String::new(),
            };
            let target_post = TargetPost {
                hashes: post.clone(),
                ipc_forged: "err|membership apply rejected: signer is not authorized: x".to_owned(),
                ipc_superseded: "err|membership apply rejected: epoch chain mismatch".to_owned(),
                ipc_gossip: "err|gossip rejected: unknown-peer".to_owned(),
                udp_forged_hits: 1,
                udp_superseded_hits: 1,
                safe_flaps: 0,
            };
            let aux_post = AuxPost {
                hashes: post,
                udp_forged_sent: "0".to_owned(),
                udp_superseded_sent: "0".to_owned(),
                mid_ts: NOW,
            };
            (probe, target_post, pre, aux_post)
        }

        fn adjudicate_all_pass() -> WireForgeryOutcome {
            let (probe, target_post, aux_pre, aux_post) = all_pass_artifacts();
            adjudicate(
                "signer is not authorized",
                "epoch chain mismatch",
                &probe,
                &target_post,
                &aux_pre,
                &aux_post,
            )
        }

        #[test]
        fn adjudicate_all_pass_is_control_pass() {
            let outcome = adjudicate_all_pass();
            assert!(outcome.pass, "fixture verdicts: {outcome:?}");
            assert_eq!(outcome.verdicts.len(), 8);
        }

        #[test]
        fn adjudicate_accepts_role_gate_denial_as_rejection() {
            // Live evidence (livelab-1789430002-b0aba24a2721): a non-admin
            // daemon's role gate denies the IPC command outright, BEFORE the
            // membership gates. That is a valid rejection family.
            let (probe, mut target_post, aux_pre, aux_post) = all_pass_artifacts();
            target_post.ipc_forged =
                "err|command denied: current node role does not permit this operation".to_owned();
            target_post.ipc_superseded =
                "err|command denied: current node role does not permit this operation".to_owned();
            target_post.ipc_gossip =
                "err|command denied: current node role does not permit this operation".to_owned();
            let outcome = adjudicate(
                "signer is not authorized",
                "epoch chain mismatch",
                &probe,
                &target_post,
                &aux_pre,
                &aux_post,
            );
            assert!(outcome.pass, "role-denial fixture verdicts: {outcome:?}");
        }

        #[test]
        fn adjudicate_rejects_unrelated_error_reply() {
            // A rejection is required: an unrelated err| text that is neither
            // the triaged class nor a role denial must fail EVERY IPC leg.
            for (tag, reply) in [
                ("WF-C_ipc_forged_rejected", "err|internal error: disk full"),
                (
                    "WF-D_ipc_superseded_rejected",
                    "err|internal error: disk full",
                ),
                ("WF-E_ipc_gossip_forged_rejected", "err|confused noise"),
            ] {
                let (probe, mut target_post, aux_pre, aux_post) = all_pass_artifacts();
                if tag == "WF-C_ipc_forged_rejected" {
                    target_post.ipc_forged = reply.to_owned();
                } else if tag == "WF-D_ipc_superseded_rejected" {
                    target_post.ipc_superseded = reply.to_owned();
                } else {
                    target_post.ipc_gossip = reply.to_owned();
                }
                let outcome = adjudicate(
                    "signer is not authorized",
                    "epoch chain mismatch",
                    &probe,
                    &target_post,
                    &aux_pre,
                    &aux_post,
                );
                assert!(!outcome.pass, "{tag} must fail on unrelated err reply");
                let leg = outcome
                    .verdicts
                    .iter()
                    .find(|(leg_tag, _, _)| *leg_tag == tag)
                    .unwrap();
                assert!(!leg.1, "{tag} verdict must itself be false");
            }
        }

        #[test]
        fn adjudicate_inverts_on_each_leg() {
            // Missing journal evidence in ONE window must fail ONLY that leg.
            let (probe, mut target_post, aux_pre, aux_post) = all_pass_artifacts();
            target_post.udp_superseded_hits = 0;
            let outcome = adjudicate(
                "signer is not authorized",
                "epoch chain mismatch",
                &probe,
                &target_post,
                &aux_pre,
                &aux_post,
            );
            assert!(!outcome.pass);
            let wf_b = outcome
                .verdicts
                .iter()
                .find(|(tag, _, _)| *tag == "WF-B_udp_superseded_rejected")
                .unwrap();
            assert!(!wf_b.1);
            assert!(
                outcome
                    .verdicts
                    .iter()
                    .find(|(tag, _, _)| *tag == "WF-A_udp_forged_rejected")
                    .unwrap()
                    .1
            );

            // Accepted IPC forgery must fail the control.
            let (probe, mut target_post, aux_pre, aux_post) = all_pass_artifacts();
            target_post.ipc_forged = "ok|applied".to_owned();
            assert!(
                !adjudicate(
                    "signer is not authorized",
                    "epoch chain mismatch",
                    &probe,
                    &target_post,
                    &aux_pre,
                    &aux_post,
                )
                .pass
            );

            // State movement on either node must fail the control.
            let (probe, mut target_post, aux_pre, aux_post) = all_pass_artifacts();
            target_post.hashes.snap = "moved".to_owned();
            assert!(
                !adjudicate(
                    "signer is not authorized",
                    "epoch chain mismatch",
                    &probe,
                    &target_post,
                    &aux_pre,
                    &aux_post,
                )
                .pass
            );
            let (probe, target_post, aux_pre, mut aux_post) = all_pass_artifacts();
            aux_post.hashes.mlog = "moved".to_owned();
            assert!(
                !adjudicate(
                    "signer is not authorized",
                    "epoch chain mismatch",
                    &probe,
                    &target_post,
                    &aux_pre,
                    &aux_post,
                )
                .pass
            );

            // A safe-mode flap must fail the control.
            let (probe, mut target_post, aux_pre, aux_post) = all_pass_artifacts();
            target_post.safe_flaps = 1;
            assert!(
                !adjudicate(
                    "signer is not authorized",
                    "epoch chain mismatch",
                    &probe,
                    &target_post,
                    &aux_pre,
                    &aux_post,
                )
                .pass
            );
        }

        #[test]
        fn class_of_maps_gates_in_fire_order() {
            assert_eq!(
                class_of(&MembershipError::ThresholdNotMet),
                "threshold signature requirements not met"
            );
            assert_eq!(
                class_of(&MembershipError::SignerNotAuthorized(
                    "wf-attacker-approver".to_owned()
                )),
                "signer is not authorized"
            );
            assert_eq!(
                class_of(&MembershipError::SignatureInvalid),
                "signature verification failed"
            );
            assert_eq!(
                class_of(&MembershipError::InvalidTransition(
                    "epoch chain mismatch for membership update"
                )),
                "epoch chain mismatch"
            );
        }
    }
}
