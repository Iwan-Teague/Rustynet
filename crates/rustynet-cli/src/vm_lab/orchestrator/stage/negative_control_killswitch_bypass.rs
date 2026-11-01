//! QH-90: the killswitch-bypass negative control.
//!
//! The documented attack (RN-27 / PF-05 family): anyone with root on the node
//! can insert ONE permissive rule ABOVE the killswitch's terminal drop — on
//! Linux `nft insert rule inet rustynet_g* killswitch index 0 accept`, on
//! macOS a `pass out quick all` above `block drop out quick all` — and the
//! killswitch silently stops containing egress, because nftables is
//! first-match-wins within a chain and pf's `quick` wins outright. The
//! permissive rule defeats the drop WITHOUT removing it, so every presence
//! check still sees a "killswitch".
//!
//! The control plants exactly that fault LIVE from outside the daemon
//! (orchestrator-driven, tough-policy rule 3), on the node's real ruleset,
//! and then runs the SAME shared precedence evaluators the daemon's runtime
//! assertions use (`rustynetd::killswitch_precedence::
//! evaluate_linux_killswitch_chain_precedence` and `rustynetd::
//! macos_exit_killswitch_precedence::
//! evaluate_macos_killswitch_rules_acknowledging`) on lab-captured dumps.
//! Tough-policy rule 2: detection is the orchestrator's own capture plus the
//! product evaluator — never a daemon self-report.
//!
//! The inversion: the control returns [`StageOutcome::Passed`] iff the
//! evaluator (a) accepts the CLEAN baseline, (b) FAILS the planted ruleset
//! naming the unreachable terminal drop, and (c) accepts the ruleset again
//! after the planted rule is deleted by handle and the deletion is verified
//! in a fresh capture. Any guest command error is `Failed` (not adjudicable
//! — fail closed), and the planting is reverted by an EXIT trap plus an
//! explicit, verified teardown on every path. A macOS node in the topology
//! runs the pf variant of the same attack; its failure fails the stage (its
//! absence is recorded in the transcript, and the Linux nft leg carries the
//! overall verdict).
//!
//! QH-90 settlement discipline: the sibling daemon-kill control (and the
//! chaos daemon-fault stage) SIGKILLs `rustynetd` on the SAME node and
//! systemd restarts it within seconds — the control used to run one second
//! later, read `nft list tables` mid-rebuild with a loose in-script
//! substring selector, and SKIP with "no killswitch chain". Now the
//! orchestrator (a) waits, bounded, for the daemon to be active with a
//! generation table carrying the killswitch chain, (b) picks the table
//! itself (exact `rustynet_g<digits>` shape, newest generation,
//! deterministically) and delivers it as `$1` to the attack script, which
//! re-validates but never discovers, and (c) the daemon-kill stage declares
//! an ORDERING-ONLY edge (`ordering_after`) so the bypass control runs
//! BEFORE the kill on the same target — no pass-gate, no skip-cascade.

use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::adapter::node_adapter::NodeAdapter;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::remote_shell::RemoteShellHost;
use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};
use std::path::Path;
use std::sync::Arc;

/// QH-90: the bypass control's on-disk pass witness — the captured chain
/// bodies (before / planted / after), the evaluator verdicts, the handle
/// used, and the teardown proof, written by the ONLY pass path. The catalog
/// row declares this exact path; the runner demotes an unwitnessed `Passed`.
pub(crate) const BYPASS_TRANSCRIPT_RELATIVE: &str =
    "negative_control/negative_control_killswitch_bypass/bypass_transcript.txt";

pub struct NegativeControlKillswitchBypassStage;

impl OrchestrationStage for NegativeControlKillswitchBypassStage {
    fn id(&self) -> StageId {
        StageId::NegativeControlKillswitchBypass
    }
    fn name(&self) -> &str {
        "negative_control_killswitch_bypass"
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
        // Linux nft leg needs a Linux guest running the daemon's inet
        // `rustynet_g*` killswitch table.
        if let Some(reason) = killswitch_bypass::precondition_gap(&ctx.assignments, &|alias| {
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
                        "killswitch-bypass negative control: {reason}"
                    ));
                }
            };
        let Some(adapter) = ctx.adapters.get(&target) else {
            return StageOutcome::Failed(format!(
                "killswitch-bypass negative control: selected target '{target}' has no \
                 adapter (fail closed)"
            ));
        };
        let macos = ctx
            .adapters
            .iter()
            .find(|(_, a)| a.platform() == VmGuestPlatform::Macos)
            .map(|(alias, a)| (alias.clone(), a.as_ref() as &dyn NodeAdapter));
        killswitch_bypass::run_killswitch_bypass_control(
            &dir,
            &ctx.report_dir,
            &target,
            adapter.as_ref(),
            macos.as_ref().map(|(alias, a)| (alias.as_str(), *a)),
        )
    }
}

pub(crate) mod killswitch_bypass {
    //! The live killswitch-bypass attack body + its pure adjudication.
    use super::*;
    use crate::vm_lab::orchestrator::evidence::append_stage_evidence_line;
    use base64::Engine as _;
    use rustynetd::killswitch_precedence::evaluate_linux_killswitch_chain_precedence;
    use rustynetd::macos_exit_killswitch_precedence::evaluate_macos_killswitch_rules_acknowledging;

    /// Transcript file name, shared by the writer and the catalog pin.
    pub(crate) const BYPASS_TRANSCRIPT_FILE: &str = "bypass_transcript.txt";

    /// The planted Linux rule: a bare, unqualified `accept` inserted at the
    /// TOP of the live killswitch chain. nftables is first-match-wins, so
    /// this fires before everything beneath it and the terminal drop never
    /// does — while the drop itself stays literally present.
    pub(crate) const PLANTED_NFT_RULE: &str = "accept";

    /// The planted macOS rule: a `quick` pass above the pf terminator. pf's
    /// `quick` wins outright regardless of what is beneath it.
    pub(crate) const PLANTED_PF_RULE: &str = "pass out quick all";

    /// The Linux attack script (guest-side, one `bash -c` under the POSIX
    /// backend's `sudo -n` wrap). Emits `nc_…=value` witness fields; the
    /// ruleset captures are base64 (single-line) so the rest-of-line field
    /// parser stays trivial. No `set -e`: every step's outcome is recorded
    /// and adjudicated; the EXIT trap reverts the plant by handle if the
    /// explicit delete did not happen.
    pub(crate) const ATTACK_SCRIPT_LINUX: &str = r#"
emit() { printf '%s\n' "$1"; }
cleanup() {
  if [ -n "${NC_HANDLE:-}" ] && [ "${NC_DELETED:-0}" != "1" ]; then
    nft delete rule inet "$NC_TABLE" killswitch handle "$NC_HANDLE" >/dev/null 2>&1 || true
    emit "nc_trap_fired=1"
  fi
}
trap cleanup EXIT
# QH-90 selector discipline: the table is CHOSEN BY THE ORCHESTRATOR (the
# settle loop) and delivered as $1; the script only re-validates it
# fail-closed against the exact daemon-generation shape. It deliberately
# performs NO discovery of its own — the old in-script
# `grep 'table inet rustynet_g' | head -1` could land on a non-daemon
# table (rustynet_g1_dns) or on a mid-restart table set.
NC_TABLE="${1:-}"
if ! printf '%s' "$NC_TABLE" | grep -Eq '^rustynet_g[0-9]+$'; then
  emit "nc_no_table=1"; exit 0
fi
emit "nc_table=$NC_TABLE"
WG_IFS="$(wg show interfaces 2>/dev/null || true)"
emit "nc_wg_ifs=$WG_IFS"
if ! nft list table inet "$NC_TABLE" 2>/dev/null | grep -q 'chain killswitch'; then
  emit "nc_chain_missing=1"; exit 0
fi
emit "nc_chain_present=1"
BEFORE="$(nft list table inet "$NC_TABLE" 2>/dev/null)"
if [ -z "$BEFORE" ]; then emit "nc_error_baseline_capture_empty=1"; exit 1; fi
emit "nc_b64_before=$(printf '%s' "$BEFORE" | base64 -w0)"
if ! nft insert rule inet "$NC_TABLE" killswitch index 0 accept 2>/dev/null; then
  emit "nc_error_plant_failed=1"; exit 1
fi
NC_PLANTED=1
emit "nc_plant_rc=0"
PLANTED="$(nft list table inet "$NC_TABLE" 2>/dev/null)"
emit "nc_b64_planted=$(printf '%s' "$PLANTED" | base64 -w0)"
NC_HANDLE="$(nft -a list chain inet "$NC_TABLE" killswitch 2>/dev/null | awk '$1=="accept"{for(i=1;i<=NF;i++) if($i=="handle"){print $(i+1); exit}}')"
if [ -z "$NC_HANDLE" ]; then
  # Teardown duty before the fail-closed exit: the plant is in the chain
  # and the handle read failed — attempt the index-0 delete regardless.
  nft delete rule inet "$NC_TABLE" killswitch index 0 >/dev/null 2>&1 || true
  emit "nc_error_handle_missing=1"; exit 1
fi
emit "nc_handle=$NC_HANDLE"
if ! nft delete rule inet "$NC_TABLE" killswitch handle "$NC_HANDLE" 2>/dev/null; then
  emit "nc_error_delete_failed=1"; exit 1
fi
NC_DELETED=1
emit "nc_delete_rc=0"
AFTER="$(nft list table inet "$NC_TABLE" 2>/dev/null)"
emit "nc_b64_after=$(printf '%s' "$AFTER" | base64 -w0)"
TEARDOWN_GREP="$(nft -a list chain inet "$NC_TABLE" killswitch 2>/dev/null | grep -Ec '^[[:space:]]*accept([[:space:]]|$)' || true)"
emit "nc_teardown_grep=$TEARDOWN_GREP"
emit "nc_chain_after_present=$(nft list table inet "$NC_TABLE" 2>/dev/null | grep -c 'chain killswitch')"
emit "nc_done=1"
"#;

    /// The macOS pf variant (same attack shape against the live
    /// `com.apple/rustynet_g*` anchor: capture → prepend `pass out quick
    /// all` → reload → capture → restore baseline → capture). Runs only
    /// when a macOS node is in the topology; its failure fails the stage.
    pub(crate) const ATTACK_SCRIPT_MACOS: &str = r#"
emit() { printf '%s\n' "$1"; }
# PF-10 discipline: NO predictable /tmp paths for the root `pfctl -f`
# consume — mktemp (O_EXCL, 0600) or nothing.
PFBASE=""
PFPLANT=""
NC_ANCHOR=""
cleanup() {
  if [ -n "$NC_ANCHOR" ] && [ "${NC_MAC_PLANTED:-0}" = "1" ] && [ "${NC_MAC_RESTORED:-0}" != "1" ]; then
    if [ -n "$PFBASE" ]; then pfctl -a "$NC_ANCHOR" -f "$PFBASE" >/dev/null 2>&1 || true; fi
    emit "nc_mac_trap_fired=1"
  fi
  if [ -n "$PFBASE" ]; then rm -f "$PFBASE" 2>/dev/null || true; fi
  if [ -n "$PFPLANT" ]; then rm -f "$PFPLANT" 2>/dev/null || true; fi
}
trap cleanup EXIT
PFBASE="$(mktemp /tmp/rustynet-nc-qh90.XXXXXX)" || { emit "nc_mac_error_tmp=1"; exit 1; }
PFPLANT="$(mktemp /tmp/rustynet-nc-qh90.XXXXXX)" || { emit "nc_mac_error_tmp=1"; exit 1; }
chmod 600 "$PFBASE" "$PFPLANT" 2>/dev/null || true
NC_ANCHOR="$(pfctl -s Anchors 2>/dev/null | grep 'com.apple/rustynet_g' | head -1 | awk '{print $1}')"
if [ -z "$NC_ANCHOR" ]; then emit "nc_mac_no_anchor=1"; exit 0; fi
emit "nc_mac_anchor=$NC_ANCHOR"
BASE="$(pfctl -a "$NC_ANCHOR" -s rules 2>/dev/null)"
if [ -z "$BASE" ]; then emit "nc_mac_error_baseline_empty=1"; exit 1; fi
printf '%s\n' "$BASE" > "$PFBASE"
emit "nc_mac_b64_baseline=$(printf '%s\n' "$BASE" | base64 | tr -d '\n')"
{ printf 'pass out quick all\n'; cat "$PFBASE"; } > "$PFPLANT"
if ! pfctl -a "$NC_ANCHOR" -f "$PFPLANT" >/dev/null 2>&1; then
  pfctl -a "$NC_ANCHOR" -f "$PFBASE" >/dev/null 2>&1 || true
  emit "nc_mac_error_plant_failed=1"; exit 1
fi
NC_MAC_PLANTED=1
emit "nc_mac_plant_rc=0"
PLANTED="$(pfctl -a "$NC_ANCHOR" -s rules 2>/dev/null)"
emit "nc_mac_b64_planted=$(printf '%s\n' "$PLANTED" | base64 | tr -d '\n')"
if ! pfctl -a "$NC_ANCHOR" -f "$PFBASE" >/dev/null 2>&1; then
  emit "nc_mac_error_restore_failed=1"; exit 1
fi
NC_MAC_RESTORED=1
emit "nc_mac_restore_rc=0"
AFTER="$(pfctl -a "$NC_ANCHOR" -s rules 2>/dev/null)"
emit "nc_mac_b64_after=$(printf '%s\n' "$AFTER" | base64 | tr -d '\n')"
emit "nc_mac_done=1"
"#;

    /// The QH-90 settle probe (guest-side, one `bash -c` under the POSIX
    /// backend's `sudo -n` wrap). Reports ONLY: is `rustynetd` active, and
    /// what does `nft list tables` currently show (base64, single-line).
    /// ALL selection happens in Rust on this transcript — the probe has no
    /// selection logic to get wrong. An unparseable/partial transcript is
    /// simply a not-settled observation (the loop retries until the bound).
    pub(crate) const SETTLE_PROBE_SCRIPT: &str = r#"
emit() { printf '%s\n' "$1"; }
if systemctl is-active --quiet rustynetd 2>/dev/null; then
  emit "nc_daemon_active=1"
else
  emit "nc_daemon_active=0"
fi
TABLES="$(nft list tables 2>/dev/null)"
emit "nc_b64_tables=$(printf '%s' "$TABLES" | base64 -w0)"
emit "nc_settle_probe_done=1"
"#;

    struct RemoteCommandOutput {
        code: i32,
        stdout: String,
        stderr: String,
    }

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
                "no Linux node in the topology; the killswitch-bypass nft attack needs a \
                 Linux guest running the daemon's inet rustynet_g* killswitch table"
                    .to_owned(),
            )
        }
    }

    // ── witness field parsing ────────────────────────────────────────────

    pub(crate) struct LinuxObservation {
        pub(crate) table: String,
        pub(crate) wg_ifs: String,
        pub(crate) chain_present: bool,
        pub(crate) b64_before: String,
        pub(crate) b64_planted: String,
        pub(crate) b64_after: String,
        pub(crate) handle: String,
        pub(crate) delete_rc: Option<i64>,
        pub(crate) teardown_grep: Option<i64>,
        pub(crate) chain_after_present: Option<i64>,
        pub(crate) trap_fired: bool,
    }

    pub(crate) enum LinuxParse {
        Observed(LinuxObservation),
        /// Named environment gap: the attack target does not exist here.
        Skipped {
            reason: String,
        },
        /// The script reported a hard error (or its output is unusable):
        /// the outcome is not provable.
        NotAdjudicable {
            reason: String,
        },
    }

    fn field<'a>(stdout: &'a str, key: &str) -> Option<&'a str> {
        let prefix = format!("{key}=");
        stdout.lines().find_map(|line| line.strip_prefix(&prefix))
    }

    fn field_num(stdout: &str, key: &str) -> Option<i64> {
        field(stdout, key)?.trim().parse::<i64>().ok()
    }

    /// Parse the attack transcript. `exit_code == 0` is required for the
    /// success shape; an error-field shape is NotAdjudicable even at exit 0.
    pub(crate) fn parse_linux_transcript(exit_code: i32, stdout: &str) -> LinuxParse {
        if field(stdout, "nc_no_table").is_some() {
            return LinuxParse::Skipped {
                reason: "the delivered table failed the attack script's own fail-closed \
                         `rustynet_g<digits>` validation (nothing settled was passed to \
                         attack)"
                    .to_owned(),
            };
        }
        if field(stdout, "nc_chain_missing").is_some() {
            return LinuxParse::Skipped {
                reason: "the inet rustynet_g* table has no `killswitch` chain on the target: \
                         the daemon killswitch chain is not applied (precise precondition)"
                    .to_owned(),
            };
        }
        let missing = |key: &str| LinuxParse::NotAdjudicable {
            reason: format!("attack transcript has no `{key}` field"),
        };
        if field(stdout, "nc_error_baseline_capture_empty").is_some() {
            return LinuxParse::NotAdjudicable {
                reason: "baseline `nft list table` capture came back empty".to_owned(),
            };
        }
        if field(stdout, "nc_error_plant_failed").is_some() {
            return LinuxParse::NotAdjudicable {
                reason: "the `nft insert rule … index 0 accept` plant failed".to_owned(),
            };
        }
        if field(stdout, "nc_error_handle_missing").is_some() {
            return LinuxParse::NotAdjudicable {
                reason: "the planted rule's handle could not be read back via `nft -a list \
                         chain`"
                    .to_owned(),
            };
        }
        if field(stdout, "nc_error_delete_failed").is_some() {
            return LinuxParse::NotAdjudicable {
                reason: "the `nft delete rule … handle` removal failed (teardown \
                         unresolved; fail closed)"
                    .to_owned(),
            };
        }
        let table = match field(stdout, "nc_table") {
            Some(t) if !t.trim().is_empty() => t.trim().to_owned(),
            _ => return missing("nc_table"),
        };
        let b64_before = match field(stdout, "nc_b64_before") {
            Some(v) if !v.trim().is_empty() => v.trim().to_owned(),
            _ => return missing("nc_b64_before"),
        };
        let b64_planted = match field(stdout, "nc_b64_planted") {
            Some(v) if !v.trim().is_empty() => v.trim().to_owned(),
            _ => return missing("nc_b64_planted"),
        };
        let b64_after = match field(stdout, "nc_b64_after") {
            Some(v) if !v.trim().is_empty() => v.trim().to_owned(),
            _ => return missing("nc_b64_after"),
        };
        let handle = match field(stdout, "nc_handle") {
            Some(h) if !h.trim().is_empty() => h.trim().to_owned(),
            _ => return missing("nc_handle"),
        };
        let Some(plant_rc) = field_num(stdout, "nc_plant_rc") else {
            return missing("nc_plant_rc");
        };
        let Some(delete_rc) = field_num(stdout, "nc_delete_rc") else {
            return missing("nc_delete_rc");
        };
        let Some(teardown_grep) = field_num(stdout, "nc_teardown_grep") else {
            return missing("nc_teardown_grep");
        };
        let Some(chain_after_present) = field_num(stdout, "nc_chain_after_present") else {
            return missing("nc_chain_after_present");
        };
        let Some(done) = field_num(stdout, "nc_done") else {
            return LinuxParse::NotAdjudicable {
                reason: "attack transcript has no `nc_done` field (script aborted early)"
                    .to_owned(),
            };
        };
        if exit_code != 0 || done != 1 || plant_rc != 0 || delete_rc != 0 {
            return LinuxParse::NotAdjudicable {
                reason: format!(
                    "attack script did not complete cleanly (exit={exit_code}, \
                     nc_done={done}, nc_plant_rc={plant_rc}, nc_delete_rc={delete_rc})"
                ),
            };
        }
        LinuxParse::Observed(LinuxObservation {
            table,
            wg_ifs: field(stdout, "nc_wg_ifs")
                .unwrap_or_default()
                .trim()
                .to_owned(),
            chain_present: field_num(stdout, "nc_chain_present").unwrap_or(0) == 1,
            b64_before,
            b64_planted,
            b64_after,
            handle,
            delete_rc: Some(delete_rc),
            teardown_grep: Some(teardown_grep),
            chain_after_present: Some(chain_after_present),
            trap_fired: field(stdout, "nc_trap_fired").is_some(),
        })
    }

    // ── ruleset parsing + acknowledgment derivation (pure) ───────────────

    /// Mirror of the daemon's own chain extractor (`phase10.rs`
    /// `nft_chain_lines`): strip quotes per line, find `chain <name>`,
    /// collect trimmed non-`}` lines until brace depth returns to 0.
    pub(crate) fn nft_chain_lines(ruleset: &str, chain_name: &str) -> Option<Vec<String>> {
        let mut in_chain = false;
        let mut depth = 0usize;
        let mut lines = Vec::new();
        for raw_line in ruleset.lines() {
            let normalized = raw_line.replace('"', "");
            let trimmed = normalized.trim();
            if !in_chain {
                if trimmed.starts_with(&format!("chain {chain_name}")) {
                    in_chain = true;
                    depth = depth
                        .saturating_add(trimmed.matches('{').count())
                        .saturating_sub(trimmed.matches('}').count());
                }
                continue;
            }
            depth = depth
                .saturating_add(trimmed.matches('{').count())
                .saturating_sub(trimmed.matches('}').count());
            if trimmed != "}" {
                lines.push(trimmed.to_owned());
            }
            if depth == 0 {
                return Some(lines);
            }
        }
        None
    }

    fn decode_b64(value: &str) -> Result<String, String> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(value.trim())
            .map_err(|e| format!("base64 decode of ruleset capture failed: {e}"))?;
        String::from_utf8(bytes).map_err(|_| "ruleset capture is not valid UTF-8".to_owned())
    }

    /// A bare, unqualified accept line (quote-stripped, trimmed) — the
    /// exact planted shape, and the shape the evaluator classifies as an
    /// escape.
    pub(crate) fn contains_bare_accept(chain_lines: &[String]) -> bool {
        chain_lines.iter().any(|line| line == "accept")
    }

    /// Capture-derived mirror of the daemon's runtime acknowledgment
    /// (phase10 `assert_firewall_ruleset`): the wide-open
    /// `oifname "<egress>" accept` the daemon installs while NAT forwarding
    /// is active is ACKNOWLEDGED so it stops masking rules beneath it. The
    /// derivation reads the captured chain (tough-policy rule 2), never a
    /// daemon status field. Anything narrower (saddr/daddr/ct state/limit)
    /// or the tunnel-scoped accept is NOT acknowledged.
    pub(crate) fn derive_linux_ack(chain_lines: &[String], tunnel_interface: &str) -> Vec<String> {
        let mut ack: Vec<String> = Vec::new();
        for line in chain_lines {
            let lowered = line.replace('"', "").to_ascii_lowercase();
            let is_accept = lowered.split_whitespace().last() == Some("accept");
            let narrow = [
                "ip saddr",
                "ip daddr",
                "ip6 saddr",
                "ip6 daddr",
                "ct state",
                "limit",
            ]
            .iter()
            .any(|tok| lowered.contains(tok));
            if !is_accept || narrow || lowered.contains("policy") {
                continue;
            }
            if let Some(pos) = lowered.find("oifname") {
                let mut rest = lowered[pos + "oifname".len()..].split_whitespace();
                if let Some(iface) = rest.next() {
                    let iface = iface.trim();
                    // The evaluator's ContainedInterfaces::default() already
                    // credits loopback and this project's tunnel-name
                    // families — acknowledging them would mask nothing and
                    // only widen the reference. The daemon acknowledges ONLY
                    // its NAT-egress hole (an underlay name), so mirror that.
                    let contained_family = iface == "lo"
                        || ["rustynet", "wg", "utun", "tun"]
                            .iter()
                            .any(|p| iface.starts_with(p));
                    if !contained_family
                        && iface != tunnel_interface
                        && !ack.iter().any(|a| a == iface)
                    {
                        ack.push(iface.to_owned());
                    }
                }
            }
        }
        ack
    }

    /// Pick the tunnel interface from `wg show interfaces` output
    /// (independent of any daemon status): prefer the rustynet-prefixed
    /// name, else the first, else empty (the evaluator then credits no
    /// contained interface — stricter, never looser).
    pub(crate) fn pick_tunnel_interface(wg_ifs: &str) -> String {
        let names: Vec<&str> = wg_ifs.split_whitespace().collect();
        if names.is_empty() {
            return String::new();
        }
        names
            .iter()
            .find(|n| n.starts_with("rustynet"))
            .map(|n| (*n).to_owned())
            .unwrap_or_else(|| names[0].to_owned())
    }

    // ── adjudication (pure) ──────────────────────────────────────────────

    #[derive(Debug)]
    pub(crate) enum KillswitchControlOutcome {
        /// The inversion held end-to-end: clean baseline accepted, planted
        /// ruleset REJECTED naming the unreachable terminal drop, and the
        /// ruleset accepted again after verified removal.
        BypassDetectedThenRejected,
        /// FAIL-OPEN: the evaluator ACCEPTED the planted ruleset.
        AcceptedWhilePlanted,
        /// The planted ruleset was rejected but not for the named reason —
        /// a wrong-reason pass is no evidence the precedence walk works.
        WrongReasonRejection { evaluator: String },
        /// The baseline itself already violates precedence: the control
        /// cannot establish a clean reference (fail closed).
        DirtyBaseline { evaluator: String },
        /// The ruleset was still broken after the planted rule was deleted.
        BypassPersistedAfterRemoval { evaluator: String },
        /// Missing/garbled evidence: the outcome is not provable.
        NotAdjudicable { reason: String },
    }

    impl KillswitchControlOutcome {
        pub(crate) fn is_control_pass(&self) -> bool {
            matches!(self, KillswitchControlOutcome::BypassDetectedThenRejected)
        }
    }

    pub(crate) fn adjudicate_linux(obs: &LinuxObservation) -> KillswitchControlOutcome {
        let fail = |reason: String| KillswitchControlOutcome::NotAdjudicable { reason };
        if !obs.chain_present {
            return fail("witness says the killswitch chain was absent at attack time".to_owned());
        }
        if obs.trap_fired {
            return fail(
                "the EXIT trap had to revert the plant (explicit delete did not complete; \
                 fail closed)"
                    .to_owned(),
            );
        }
        let Some(delete_rc) = obs.delete_rc else {
            return fail("no delete exit recorded".to_owned());
        };
        if delete_rc != 0 {
            return fail(format!("rule delete exited {delete_rc} (fail closed)"));
        }
        let Some(teardown_grep) = obs.teardown_grep else {
            return fail("no teardown grep count recorded".to_owned());
        };
        if teardown_grep != 0 {
            return fail(format!(
                "teardown not verified: {teardown_grep} bare-accept handle line(s) still \
                 present after removal (fail closed)"
            ));
        }
        let Some(chain_after_present) = obs.chain_after_present else {
            return fail("no post-teardown chain-presence count recorded".to_owned());
        };
        if chain_after_present < 1 {
            return fail(
                "the killswitch chain is GONE after the control (the daemon's own posture \
                 must stay intact; fail closed)"
                    .to_owned(),
            );
        }
        let before = match decode_b64(&obs.b64_before) {
            Ok(v) => v,
            Err(e) => return fail(e),
        };
        let planted = match decode_b64(&obs.b64_planted) {
            Ok(v) => v,
            Err(e) => return fail(e),
        };
        let after = match decode_b64(&obs.b64_after) {
            Ok(v) => v,
            Err(e) => return fail(e),
        };
        let Some(before_chain) = nft_chain_lines(&before, "killswitch") else {
            return fail("killswitch chain not found in the baseline capture".to_owned());
        };
        let Some(planted_chain) = nft_chain_lines(&planted, "killswitch") else {
            return fail("killswitch chain not found in the planted capture".to_owned());
        };
        let Some(after_chain) = nft_chain_lines(&after, "killswitch") else {
            return fail("killswitch chain not found in the post-removal capture".to_owned());
        };
        let tunnel = pick_tunnel_interface(&obs.wg_ifs);
        // The plant must be VISIBLE in the capture before the evaluator's
        // failure counts as detection (a capture that lost the rule would
        // make any verdict meaningless).
        if !contains_bare_accept(&planted_chain) {
            return fail(
                "the planted bare accept is not visible in the planted capture — cannot \
                 prove the evaluator saw the fault (fail closed)"
                    .to_owned(),
            );
        }
        // (a) Clean baseline: accepted with the capture-derived acknowledgment.
        let ack: Vec<String> = derive_linux_ack(&before_chain, &tunnel);
        let ack_refs: Vec<&str> = ack.iter().map(String::as_str).collect();
        let before_body = before_chain.join("\n");
        if let Err(e) = evaluate_linux_killswitch_chain_precedence(&before_body, &tunnel, &ack_refs)
        {
            return KillswitchControlOutcome::DirtyBaseline { evaluator: e };
        }
        // (b) The planted ruleset must be REJECTED, naming the unreachable
        //     terminal drop. A rejection that does not name the escape is a
        //     wrong reason (guard B).
        let planted_body = planted_chain.join("\n");
        if let Err(e) =
            evaluate_linux_killswitch_chain_precedence(&planted_body, &tunnel, &ack_refs)
        {
            let lowered = e.to_ascii_lowercase();
            if !(lowered.contains("unreachable") && lowered.contains("accept")) {
                return KillswitchControlOutcome::WrongReasonRejection { evaluator: e };
            }
        } else {
            return KillswitchControlOutcome::AcceptedWhilePlanted;
        }
        // (c) After verified removal the evaluator must accept again — and
        //     the fresh capture must show no bare accept.
        if contains_bare_accept(&after_chain) {
            return KillswitchControlOutcome::BypassPersistedAfterRemoval {
                evaluator: "bare accept still present in the post-removal capture".to_owned(),
            };
        }
        let after_body = after_chain.join("\n");
        if let Err(e) = evaluate_linux_killswitch_chain_precedence(&after_body, &tunnel, &ack_refs)
        {
            return KillswitchControlOutcome::BypassPersistedAfterRemoval { evaluator: e };
        }
        KillswitchControlOutcome::BypassDetectedThenRejected
    }

    // ── settle (QH-90 race fix, pure selection core) ─────────────────────

    /// How long the control waits for the daemon + its generation tables to
    /// come back after any recent restart, and how often it re-probes.
    const SETTLE_BOUND: std::time::Duration = std::time::Duration::from_secs(60);
    const SETTLE_POLL: std::time::Duration = std::time::Duration::from_secs(2);

    /// One settle observation: the daemon's systemd active state plus the
    /// verbatim `nft list tables` listing at probe time.
    pub(crate) struct SettleObservation {
        pub(crate) daemon_active: bool,
        pub(crate) tables_listing: String,
    }

    pub(crate) enum SettleVerdict {
        /// The daemon is active AND a generation table carries the
        /// killswitch chain; `table` is the deterministic newest pick.
        Settled {
            table: String,
        },
        NotSettled {
            reason: String,
        },
    }

    /// True iff `table` is EXACTLY a daemon generation table name:
    /// `rustynet_g` + digits. Deliberately rejects `rustynet_g1_dns` and
    /// `rustynet_nat_g1` — the substring shapes the old in-script
    /// `grep 'table inet rustynet_g' | head -1` selector could land on.
    pub(crate) fn is_daemon_generation_table(table: &str) -> bool {
        let Some(suffix) = table.strip_prefix("rustynet_g") else {
            return false;
        };
        !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit())
    }

    /// Extract the daemon generation tables from a verbatim
    /// `nft list tables` listing: family must be `inet`, name must be
    /// EXACTLY `rustynet_g<digits>`. Dedup, then deterministic
    /// numeric-suffix order (g2 before g10 — never a string compare).
    pub(crate) fn daemon_generation_table_candidates(listing: &str) -> Vec<String> {
        let mut tables: Vec<String> = Vec::new();
        for line in listing.lines() {
            let mut tokens = line.split_whitespace();
            if tokens.next() != Some("table") {
                continue;
            }
            if tokens.next() != Some("inet") {
                continue;
            }
            let Some(name) = tokens.next() else {
                continue;
            };
            if !is_daemon_generation_table(name) {
                continue;
            }
            if !tables.iter().any(|t| t == name) {
                tables.push(name.to_owned());
            }
        }
        tables.sort_by(|a, b| {
            numeric_suffix(a)
                .cmp(&numeric_suffix(b))
                .then_with(|| a.cmp(b))
        });
        tables
    }

    fn numeric_suffix(table: &str) -> u64 {
        table
            .rsplit(|c: char| !c.is_ascii_digit())
            .next()
            .and_then(|digits| digits.parse::<u64>().ok())
            .unwrap_or(0)
    }

    /// Does an `nft list table` dump contain a `killswitch` chain? A
    /// trimmed line whose first token is `chain` and second is
    /// `killswitch` — quote- and indent-tolerant, never a substring hit.
    pub(crate) fn dump_has_killswitch_chain(dump: &str) -> bool {
        dump.lines().any(|line| {
            let mut tokens = line.split_whitespace();
            tokens.next() == Some("chain") && tokens.next() == Some("killswitch")
        })
    }

    /// Parse a [`SETTLE_PROBE_SCRIPT`] transcript. `None` = unusable probe
    /// (missing sentinel, bad active flag, empty/undecodable listing): the
    /// caller treats that as not-settled and retries until the bound.
    pub(crate) fn parse_settle_probe(stdout: &str) -> Option<SettleObservation> {
        if field(stdout, "nc_settle_probe_done")?.trim() != "1" {
            return None;
        }
        let daemon_active = match field(stdout, "nc_daemon_active")?.trim() {
            "1" => true,
            "0" => false,
            _ => return None,
        };
        let listing_b64 = field(stdout, "nc_b64_tables")?.trim();
        if listing_b64.is_empty() {
            return None;
        }
        let tables_listing = decode_b64(listing_b64).ok()?;
        Some(SettleObservation {
            daemon_active,
            tables_listing,
        })
    }

    /// The settle decision (pure): settled iff the daemon is active AND at
    /// least one generation table carries the killswitch chain. Among the
    /// chain-carrying candidates the NEWEST generation wins — max by
    /// (numeric suffix, name) — so a restarted daemon's fresh table set is
    /// preferred and the pick is deterministic + recorded either way.
    pub(crate) fn settle_verdict(
        obs: &SettleObservation,
        chain_of: &dyn Fn(&str) -> bool,
    ) -> SettleVerdict {
        if !obs.daemon_active {
            return SettleVerdict::NotSettled {
                reason: "rustynetd is not active (recently restarted or stopped); the \
                         daemon killswitch posture cannot be assumed settled"
                    .to_owned(),
            };
        }
        let candidates = daemon_generation_table_candidates(&obs.tables_listing);
        if candidates.is_empty() {
            return SettleVerdict::NotSettled {
                reason: "no `table inet rustynet_g<digits>` daemon generation table exists \
                         yet (tables still building after a restart)"
                    .to_owned(),
            };
        }
        let carrying: Vec<&String> = candidates.iter().filter(|t| chain_of(t)).collect();
        if carrying.is_empty() {
            return SettleVerdict::NotSettled {
                reason: format!(
                    "generation tables {candidates:?} exist but none carries a \
                     `killswitch` chain yet"
                ),
            };
        }
        // carrying is non-empty, but no expect() (§10.2): a None here is
        // the fail-closed shape instead of a panic in the control body.
        let table = match carrying.into_iter().max_by(|a, b| {
            numeric_suffix(a)
                .cmp(&numeric_suffix(b))
                .then_with(|| (*a).cmp(b))
        }) {
            Some(t) => (*t).clone(),
            None => {
                return SettleVerdict::NotSettled {
                    reason: "no chain-carrying candidate remained; refusing to pick (fail \
                             closed)"
                        .to_owned(),
                };
            }
        };
        SettleVerdict::Settled { table }
    }

    /// Bounded settle loop (the race fix): poll [`SETTLE_PROBE_SCRIPT`]
    /// every [`SETTLE_POLL`] until [`SETTLE_BOUND`] expires, probing each
    /// candidate table with `nft list table inet <table>` (argv only — no
    /// shell construction with the table name). Bound expiry is a NAMED
    /// skip carrying the last observed table listing (the daemon never
    /// settled — adjudicating then would re-introduce the race); a
    /// transport failure is Failed (fail loud, never absorbed).
    pub(crate) enum SettleResult {
        Settled { table: String },
        Expired { last_listing: String },
        Transport(String),
    }

    pub(crate) fn settle_before_attack(shell: &Arc<dyn RemoteShellHost>) -> SettleResult {
        let deadline = std::time::Instant::now() + SETTLE_BOUND;
        let mut last_listing = String::new();
        loop {
            let probe = match run_remote_argv(
                shell,
                &["bash", "-c", SETTLE_PROBE_SCRIPT, "nc-settle-probe"],
            ) {
                Ok(probe) => probe,
                Err(err) => return SettleResult::Transport(err),
            };
            if let Some(obs) = parse_settle_probe(&probe.stdout) {
                last_listing = obs.tables_listing.clone();
                let chain_of = |table: &str| -> bool {
                    match run_remote_argv(shell, &["nft", "list", "table", "inet", table]) {
                        Ok(dump) => dump_has_killswitch_chain(&dump.stdout),
                        // A table listed but not listable (vanishing
                        // mid-restart): treat as not carrying, keep polling.
                        Err(_) => false,
                    }
                };
                if let SettleVerdict::Settled { table } = settle_verdict(&obs, &chain_of) {
                    return SettleResult::Settled { table };
                }
            }
            if std::time::Instant::now() >= deadline {
                return SettleResult::Expired { last_listing };
            }
            std::thread::sleep(SETTLE_POLL);
        }
    }

    // ── the control body (side-effectful) ────────────────────────────────

    /// The (QH-90) control body. A working control returns
    /// [`StageOutcome::Passed`] (the evaluator caught the planted bypass and
    /// cleared the restored ruleset).
    pub(crate) fn run_killswitch_bypass_control(
        workdir: &Path,
        report_dir: &Path,
        target_alias: &str,
        adapter: &dyn NodeAdapter,
        macos: Option<(&str, &dyn NodeAdapter)>,
    ) -> StageOutcome {
        let fail = |reason: String| {
            StageOutcome::Failed(format!(
                "killswitch-bypass negative control [target {target_alias}]: {reason}"
            ))
        };
        if adapter.platform() != VmGuestPlatform::Linux {
            return fail(format!(
                "target platform {:?} cannot host the nft killswitch attack (fail closed)",
                adapter.platform()
            ));
        }
        let shell = match adapter.shell_host() {
            Ok(shell) => shell,
            Err(err) => return fail(format!("no remote shell host: {err}")),
        };

        // 0. Settle (QH-90 race fix): wait, bounded, for rustynetd to be
        //    active AND a generation table to carry its killswitch chain —
        //    the daemon-kill control (and the chaos daemon-fault stage) may
        //    have restarted the daemon seconds ago, and attacking a table
        //    set mid-rebuild is exactly the SKIP seen at 01:13:42Z. All
        //    table selection happens here, in Rust, deterministically.
        let settled_table = match settle_before_attack(&shell) {
            SettleResult::Settled { table } => table,
            SettleResult::Expired { last_listing } => {
                let bound = SETTLE_BOUND;
                let reason = format!(
                    "the daemon did not settle within {bound:?}: no active rustynetd \
                     generation table carrying a `killswitch` chain (last observed `nft \
                     list tables`: {last_listing:?}); refusing to attack a mid-restart \
                     ruleset"
                );
                let _ = write_evidence(
                    workdir,
                    BYPASS_TRANSCRIPT_FILE,
                    &format!("## settle\nexpired: {reason}\n"),
                );
                return StageOutcome::Skipped(reason);
            }
            SettleResult::Transport(err) => {
                let _ = write_evidence(
                    workdir,
                    BYPASS_TRANSCRIPT_FILE,
                    &format!("## settle\ntransport failure: {err}\n"),
                );
                return fail(format!("settle probe transport failure: {err}"));
            }
        };

        // 1. Deliver the attack (plant → capture → delete → capture, with
        //    the EXIT trap reverting the plant if the delete never runs).
        //    The settled table is delivered as $1; the script re-validates
        //    it fail-closed and performs NO discovery of its own.
        let script_status = run_remote_argv(
            &shell,
            &[
                "bash",
                "-c",
                ATTACK_SCRIPT_LINUX,
                "nc-killswitch-bypass",
                settled_table.as_str(),
            ],
        );
        let (script_exit, script_stdout, script_stderr) = match script_status {
            Ok(out) => (out.code, out.stdout, out.stderr),
            Err(err) => {
                let _ = write_evidence(
                    workdir,
                    BYPASS_TRANSCRIPT_FILE,
                    &format!("## attack delivery\ntransport failure: {err}\n"),
                );
                return fail(format!("transport failure delivering the attack: {err}"));
            }
        };
        let mut evidence = format!(
            "## attack delivery (linux nft leg)\nexit={script_exit}\n--- stdout ---\n\
             {script_stdout}\n--- stderr ---\n{script_stderr}\n"
        );

        // 2. Adjudicate (pure).
        let observation = match parse_linux_transcript(script_exit, &script_stdout) {
            LinuxParse::Skipped { reason } => {
                evidence.push_str(&format!("## skip\n{reason}\n"));
                let _ = write_evidence(workdir, BYPASS_TRANSCRIPT_FILE, &evidence);
                return StageOutcome::Skipped(reason);
            }
            LinuxParse::NotAdjudicable { reason } => {
                evidence.push_str(&format!("## adjudication\nnot adjudicable: {reason}\n"));
                let _ = write_evidence(workdir, BYPASS_TRANSCRIPT_FILE, &evidence);
                return fail(format!(
                    "{reason}; the attack ran but the outcome is not provable (fail closed)"
                ));
            }
            LinuxParse::Observed(o) => o,
        };
        let verdict = adjudicate_linux(&observation);
        evidence.push_str(&format!(
            "## adjudication (linux nft leg)\ntable={}\ntunnel_interface={}\nplanted_rule=\
             {PLANTED_NFT_RULE}\nhandle={}\n{verdict:?}\n",
            observation.table,
            pick_tunnel_interface(&observation.wg_ifs),
            observation.handle,
        ));

        // 3. macOS pf leg — the same attack against the pf anchor when a
        //    macOS node is in the topology; its failure fails the stage,
        //    its absence is recorded (the Linux leg carries the verdict).
        match macos {
            Some((mac_alias, mac_adapter)) => match run_macos_leg(mac_adapter) {
                MacosLeg::Ran {
                    verdict: mac_verdict,
                } => {
                    evidence.push_str(&format!(
                        "## adjudication (macos pf leg, {mac_alias})\nplanted_rule=\
                         {PLANTED_PF_RULE}\n{mac_verdict:?}\n"
                    ));
                    if !mac_verdict.is_control_pass() {
                        let reason = format!(
                            "macOS pf leg failed ({mac_verdict:?}); the pf killswitch did \
                             not catch the planted quick-pass bypass (fail loud)"
                        );
                        evidence.push_str(&format!("## stage verdict\n{reason}\n"));
                        let _ = write_evidence(workdir, BYPASS_TRANSCRIPT_FILE, &evidence);
                        return fail(reason);
                    }
                }
                MacosLeg::NoAnchor => {
                    evidence.push_str(&format!(
                        "## macos pf leg ({mac_alias})\nskipped: no com.apple/rustynet_g* \
                         pf anchor on this node (no active macOS killswitch to attack)\n"
                    ));
                }
                MacosLeg::Transport(err) => {
                    let reason = format!("macOS pf leg transport failure: {err}");
                    evidence.push_str(&format!("## stage verdict\n{reason}\n"));
                    let _ = write_evidence(workdir, BYPASS_TRANSCRIPT_FILE, &evidence);
                    return fail(reason);
                }
            },
            None => {
                evidence.push_str(
                    "## macos pf leg\nnot run: no macOS node in this run's topology (the \
                     Linux nft leg carries the overall verdict)\n",
                );
            }
        }

        // 4. Persist the declared witness + the pass verdict.
        if let Err(err) = write_evidence(workdir, BYPASS_TRANSCRIPT_FILE, &evidence) {
            return fail(format!(
                "evidence not persisted: {err} (fail closed; the witness is the declared \
                 File artifact)"
            ));
        }
        match verdict {
            KillswitchControlOutcome::BypassDetectedThenRejected => {
                if let Err(err) = append_stage_evidence_line(
                    report_dir,
                    StageId::NegativeControlKillswitchBypass.as_str(),
                    &format!(
                        "negative_control=killswitch_bypass target={target_alias} table={} \
                         sabotage=bare_accept_above_terminal_drop \
                         detection=precedence_evaluator_rejected_planted_ruleset \
                         teardown=verified_by_handle_and_recapture",
                        observation.table
                    ),
                ) {
                    return StageOutcome::Failed(format!(
                        "killswitch-bypass negative control: witness write failed: {err}"
                    ));
                }
                StageOutcome::Passed
            }
            KillswitchControlOutcome::AcceptedWhilePlanted => fail(
                "FAIL-OPEN — the precedence evaluator ACCEPTED the planted ruleset; a bare \
                 accept above the killswitch terminal drop went undetected"
                    .to_owned(),
            ),
            KillswitchControlOutcome::WrongReasonRejection { evaluator } => fail(format!(
                "the planted ruleset was rejected for the WRONG reason ({evaluator:?}); the \
                 precedence walk must name the unreachable terminal drop"
            )),
            KillswitchControlOutcome::DirtyBaseline { evaluator } => fail(format!(
                "the baseline ruleset already violates precedence ({evaluator:?}); no clean \
                 reference, refusing to adjudicate (fail closed)"
            )),
            KillswitchControlOutcome::BypassPersistedAfterRemoval { evaluator } => fail(format!(
                "the killswitch was still broken after the planted rule was deleted \
                     ({evaluator:?}); teardown failed to restore containment"
            )),
            KillswitchControlOutcome::NotAdjudicable { reason } => fail(format!(
                "{reason}; the outcome is not provable (fail closed)"
            )),
        }
    }

    enum MacosLeg {
        Ran { verdict: KillswitchControlOutcome },
        NoAnchor,
        Transport(String),
    }

    pub(crate) struct MacosObservation {
        pub(crate) b64_baseline: String,
        pub(crate) b64_planted: String,
        pub(crate) b64_after: String,
        pub(crate) plant_rc: i64,
        pub(crate) restore_rc: i64,
        pub(crate) done: i64,
        pub(crate) trap_fired: bool,
        pub(crate) error: Option<String>,
    }

    fn run_macos_leg(adapter: &dyn NodeAdapter) -> MacosLeg {
        let shell = match adapter.shell_host() {
            Ok(shell) => shell,
            Err(err) => return MacosLeg::Transport(err.to_string()),
        };
        let out = match run_remote_argv(&shell, &["bash", "-c", ATTACK_SCRIPT_MACOS, "mac-nc"]) {
            Ok(out) => out,
            Err(err) => return MacosLeg::Transport(err),
        };
        let missing = |key: &str| MacosLeg::Ran {
            verdict: KillswitchControlOutcome::NotAdjudicable {
                reason: format!("macOS leg transcript has no `{key}` field"),
            },
        };
        if field(&out.stdout, "nc_mac_no_anchor").is_some() {
            return MacosLeg::NoAnchor;
        }
        let error = [
            "nc_mac_error_tmp",
            "nc_mac_error_baseline_empty",
            "nc_mac_error_plant_failed",
            "nc_mac_error_restore_failed",
        ]
        .iter()
        .find(|k| field(&out.stdout, k).is_some())
        .map(|k| (*k).to_string());
        let Some(b64_baseline) = field(&out.stdout, "nc_mac_b64_baseline").map(str::to_owned)
        else {
            return missing("nc_mac_b64_baseline");
        };
        let Some(b64_planted) = field(&out.stdout, "nc_mac_b64_planted").map(str::to_owned) else {
            return missing("nc_mac_b64_planted");
        };
        let Some(b64_after) = field(&out.stdout, "nc_mac_b64_after").map(str::to_owned) else {
            return missing("nc_mac_b64_after");
        };
        let observation = MacosObservation {
            b64_baseline,
            b64_planted,
            b64_after,
            plant_rc: field_num(&out.stdout, "nc_mac_plant_rc").unwrap_or(-1),
            restore_rc: field_num(&out.stdout, "nc_mac_restore_rc").unwrap_or(-1),
            done: field_num(&out.stdout, "nc_mac_done").unwrap_or(0),
            trap_fired: field(&out.stdout, "nc_mac_trap_fired").is_some(),
            error,
        };
        MacosLeg::Ran {
            verdict: adjudicate_macos(&observation),
        }
    }

    pub(crate) fn adjudicate_macos(obs: &MacosObservation) -> KillswitchControlOutcome {
        let fail = |reason: String| KillswitchControlOutcome::NotAdjudicable { reason };
        if let Some(err) = &obs.error {
            return fail(format!("macOS pf script error: {err} (fail closed)"));
        }
        if obs.trap_fired {
            return fail(
                "the macOS EXIT trap had to restore the anchor ruleset (explicit restore \
                 did not complete; fail closed)"
                    .to_owned(),
            );
        }
        if obs.done != 1 || obs.plant_rc != 0 || obs.restore_rc != 0 {
            return fail(format!(
                "macOS pf script did not complete cleanly (done={}, plant_rc={}, \
                 restore_rc={})",
                obs.done, obs.plant_rc, obs.restore_rc
            ));
        }
        let (baseline, planted, after) = match (
            decode_b64(&obs.b64_baseline),
            decode_b64(&obs.b64_planted),
            decode_b64(&obs.b64_after),
        ) {
            (Ok(b), Ok(p), Ok(a)) => (b, p, a),
            (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => return fail(e),
        };
        // Capture-derived acknowledgment: the daemon's own wide-open quick
        // pass on its egress interface (PF-01) must not mask the verdict.
        let ack = derive_macos_ack(&baseline);
        let ack_refs: Vec<&str> = ack.iter().map(String::as_str).collect();
        if let Err(e) = evaluate_macos_killswitch_rules_acknowledging(&baseline, &ack_refs) {
            return KillswitchControlOutcome::DirtyBaseline { evaluator: e };
        }
        let planted_normalized = planted
            .lines()
            .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
            .collect::<Vec<_>>();
        if !planted_normalized.iter().any(|l| l == PLANTED_PF_RULE) {
            return fail(
                "the planted `pass out quick all` is not visible in the planted capture \
                 (fail closed)"
                    .to_owned(),
            );
        }
        if let Err(e) = evaluate_macos_killswitch_rules_acknowledging(&planted, &ack_refs) {
            let lowered = e.to_ascii_lowercase();
            // Guard B (wrong-reason): the evaluator's Escaped suffix always
            // says "pass", so require the message to name THE planted rule.
            if !(lowered.contains("verification failed") && lowered.contains("pass out quick all"))
            {
                return KillswitchControlOutcome::WrongReasonRejection { evaluator: e };
            }
        } else {
            return KillswitchControlOutcome::AcceptedWhilePlanted;
        }
        if let Err(e) = evaluate_macos_killswitch_rules_acknowledging(&after, &ack_refs) {
            return KillswitchControlOutcome::BypassPersistedAfterRemoval { evaluator: e };
        }
        KillswitchControlOutcome::BypassDetectedThenRejected
    }

    /// Capture-derived mirror of the pf PF-01 acknowledgment: a wide-open
    /// interface-scoped quick pass (`pass out quick on <egress> …`) in the
    /// baseline is acknowledged so it cannot mask the verdict.
    pub(crate) fn derive_macos_ack(baseline_rules: &str) -> Vec<String> {
        let mut ack = Vec::new();
        for line in baseline_rules.lines() {
            let normalized = line.split_whitespace().collect::<Vec<_>>().join(" ");
            let lowered = normalized.to_ascii_lowercase();
            if !lowered.starts_with("pass") || !lowered.contains("quick") {
                continue;
            }
            // Interface-scoped wide-open pass: `on <if>` with no narrower
            // qualifier (no proto/port/from/to constraining it beyond `all`).
            let narrow = ["proto", "port ", "from ", "to "]
                .iter()
                .any(|tok| lowered.contains(tok));
            if narrow {
                continue;
            }
            if let Some(pos) = lowered.find(" on ") {
                let rest = &lowered[pos + 4..];
                if let Some(iface) = rest.split_whitespace().next() {
                    let iface = iface.trim_end_matches(',');
                    if !ack.iter().any(|a| a == iface) {
                        ack.push(iface.to_owned());
                    }
                }
            }
        }
        ack
    }
}

#[cfg(test)]
mod tests {
    use super::killswitch_bypass::*;
    use super::killswitch_bypass::{MacosObservation, adjudicate_macos};
    use crate::vm_lab::VmGuestPlatform;
    use crate::vm_lab::orchestrator::role::NodeRole;

    fn nft_ruleset(chain_body: &[&str]) -> String {
        let mut out = String::from("table inet rustynet_g1 {\n\tchain killswitch {\n");
        out.push_str("\t\ttype filter hook output priority 0; policy drop;\n");
        for line in chain_body {
            out.push_str(&format!("\t\t{line}\n"));
        }
        out.push_str(
            "\t}\n\n\tchain forward {\n\t\ttype filter hook forward priority 0; policy \
             drop;\n\t}\n}\n",
        );
        out
    }

    fn b64(text: &str) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(text)
    }

    fn obs_before_planted_after(before: &str, planted: &str, after: &str) -> LinuxObservation {
        LinuxObservation {
            table: "rustynet_g1".to_owned(),
            wg_ifs: "rustynet0".to_owned(),
            chain_present: true,
            b64_before: b64(before),
            b64_planted: b64(planted),
            b64_after: b64(after),
            handle: "9".to_owned(),
            delete_rc: Some(0),
            teardown_grep: Some(0),
            chain_after_present: Some(1),
            trap_fired: false,
        }
    }

    fn clean_baseline() -> String {
        nft_ruleset(&[r#"oifname "lo" accept"#, r#"oifname "rustynet0" accept"#])
    }

    fn planted() -> String {
        nft_ruleset(&[
            "accept",
            r#"oifname "lo" accept"#,
            r#"oifname "rustynet0" accept"#,
        ])
    }

    #[test]
    fn chain_lines_mirror_the_daemon_parser() {
        let ruleset = nft_ruleset(&[r#"oifname "lo" accept"#]);
        let chain = nft_chain_lines(&ruleset, "killswitch").expect("chain found");
        assert_eq!(chain.len(), 2);
        assert!(chain[0].contains("policy drop"));
        assert_eq!(chain[1], r#"oifname lo accept"#);
        assert!(nft_chain_lines(&ruleset, "nosuch").is_none());
    }

    #[test]
    fn tunnel_interface_prefers_the_rustynet_name() {
        assert_eq!(pick_tunnel_interface("eth0 rustynet0"), "rustynet0");
        assert_eq!(pick_tunnel_interface("eth0 wg0"), "eth0");
        assert_eq!(pick_tunnel_interface(""), "");
    }

    #[test]
    fn wide_open_egress_accept_is_acknowledged_tunnel_accept_is_not() {
        let chain = vec![
            r#"oifname "lo" accept"#.to_owned(),
            r#"oifname "eth0" accept"#.to_owned(),
            r#"oifname "rustynet0" accept"#.to_owned(),
            "ip saddr 10.0.0.0/8 accept".to_owned(),
        ];
        let ack = derive_linux_ack(&chain, "rustynet0");
        assert_eq!(ack, vec!["eth0".to_owned()]);
    }

    #[test]
    fn control_passes_on_the_full_inversion() {
        let outcome = adjudicate_linux(&obs_before_planted_after(
            &clean_baseline(),
            &planted(),
            &clean_baseline(),
        ));
        assert!(outcome.is_control_pass(), "{outcome:?}");
    }

    #[test]
    fn control_fails_closed_when_the_plant_is_not_in_the_capture() {
        // Fail-open guard: a capture that lost the planted rule must NOT
        // produce a pass (any verdict from it would be meaningless).
        let outcome = adjudicate_linux(&obs_before_planted_after(
            &clean_baseline(),
            &clean_baseline(),
            &clean_baseline(),
        ));
        assert!(!outcome.is_control_pass());
        assert!(matches!(
            outcome,
            KillswitchControlOutcome::NotAdjudicable { .. }
        ));
    }

    #[test]
    fn control_refuses_a_dirty_baseline() {
        // A pre-existing wide-open accept (here: a bare one) means no clean
        // reference exists — the control must fail closed, not adjudicate.
        let dirty = nft_ruleset(&["accept"]);
        let outcome = adjudicate_linux(&obs_before_planted_after(
            &dirty,
            &planted(),
            &clean_baseline(),
        ));
        assert!(!outcome.is_control_pass());
        assert!(matches!(
            outcome,
            KillswitchControlOutcome::DirtyBaseline { .. }
        ));
    }

    #[test]
    fn control_fails_when_the_bypass_persists_after_removal() {
        let outcome = adjudicate_linux(&obs_before_planted_after(
            &clean_baseline(),
            &planted(),
            &planted(),
        ));
        assert!(!outcome.is_control_pass());
        assert!(matches!(
            outcome,
            KillswitchControlOutcome::BypassPersistedAfterRemoval { .. }
        ));
    }

    #[test]
    fn control_fails_closed_on_a_teardown_leak() {
        let mut obs = obs_before_planted_after(&clean_baseline(), &planted(), &clean_baseline());
        obs.teardown_grep = Some(1);
        let outcome = adjudicate_linux(&obs);
        assert!(!outcome.is_control_pass());
        assert!(matches!(
            outcome,
            KillswitchControlOutcome::NotAdjudicable { .. }
        ));
        let mut obs = obs_before_planted_after(&clean_baseline(), &planted(), &clean_baseline());
        obs.trap_fired = true;
        assert!(!adjudicate_linux(&obs).is_control_pass());
        let mut obs = obs_before_planted_after(&clean_baseline(), &planted(), &clean_baseline());
        obs.chain_after_present = Some(0);
        assert!(!adjudicate_linux(&obs).is_control_pass());
    }

    #[test]
    fn transcript_parser_names_every_gap() {
        let good = format!(
            "nc_table=rustynet_g1\nnc_wg_ifs=rustynet0\nnc_chain_present=1\n\
             nc_b64_before={}\nnc_b64_planted={}\nnc_b64_after={}\nnc_plant_rc=0\n\
             nc_handle=9\nnc_delete_rc=0\nnc_teardown_grep=0\nnc_chain_after_present=1\n\
             nc_done=1\n",
            b64(&clean_baseline()),
            b64(&planted()),
            b64(&clean_baseline()),
        );
        assert!(matches!(
            parse_linux_transcript(0, &good),
            LinuxParse::Observed(_)
        ));
        assert!(matches!(
            parse_linux_transcript(0, "nc_no_table=1\n"),
            LinuxParse::Skipped { .. }
        ));
        assert!(matches!(
            parse_linux_transcript(0, "nc_chain_missing=1\n"),
            LinuxParse::Skipped { .. }
        ));
        assert!(matches!(
            parse_linux_transcript(1, &good),
            LinuxParse::NotAdjudicable { .. }
        ));
        let dropped_handle = good.replace("nc_handle=9\n", "");
        assert!(matches!(
            parse_linux_transcript(0, &dropped_handle),
            LinuxParse::NotAdjudicable { .. }
        ));
        let dropped_done = good.replace("nc_done=1\n", "");
        assert!(matches!(
            parse_linux_transcript(0, &dropped_done),
            LinuxParse::NotAdjudicable { .. }
        ));
        assert!(matches!(
            parse_linux_transcript(0, "nc_error_plant_failed=1\n"),
            LinuxParse::NotAdjudicable { .. }
        ));
        assert!(matches!(
            parse_linux_transcript(0, "nc_error_delete_failed=1\n"),
            LinuxParse::NotAdjudicable { .. }
        ));
    }

    #[test]
    fn macos_leg_adjudication_full_inversion() {
        let baseline = "block drop out quick all\n".to_owned();
        let planted = format!("pass out quick all\n{baseline}");
        let mk = |b: &str, p: &str, a: &str| MacosObservation {
            b64_baseline: b64(b),
            b64_planted: b64(p),
            b64_after: b64(a),
            plant_rc: 0,
            restore_rc: 0,
            done: 1,
            trap_fired: false,
            error: None,
        };
        let outcome = adjudicate_macos(&mk(&baseline, &planted, &baseline));
        assert!(outcome.is_control_pass(), "{outcome:?}");
        // Fail-open mutation: the planted capture LOST the plant.
        let outcome = adjudicate_macos(&mk(&baseline, &baseline, &baseline));
        assert!(!outcome.is_control_pass());
        // Trap-fired leak.
        let mut leaked = mk(&baseline, &planted, &baseline);
        leaked.trap_fired = true;
        assert!(!adjudicate_macos(&leaked).is_control_pass());
        // Persisted bypass after "restore".
        let outcome = adjudicate_macos(&mk(&baseline, &planted, &planted));
        assert!(!outcome.is_control_pass());
    }

    #[test]
    fn macos_ack_derives_the_wide_open_egress_pass_only() {
        let baseline = "pass out quick on en0 inet all keep state\nblock drop out quick all\n";
        assert_eq!(derive_macos_ack(baseline), vec!["en0".to_owned()]);
        assert!(derive_macos_ack("block drop out quick all\n").is_empty());
    }

    #[test]
    fn precondition_gap_names_a_missing_linux_node() {
        use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;
        let assignments = vec![NodeRoleAssignment {
            alias: "mac-only".to_owned(),
            role: NodeRole::Client,
        }];
        let platform_of = |alias: &str| (alias == "mac-only").then_some(VmGuestPlatform::Macos);
        let gap = precondition_gap(&assignments, &platform_of);
        assert!(gap.expect("gap expected").contains("no Linux node"));
        let assignments = vec![NodeRoleAssignment {
            alias: "deb-1".to_owned(),
            role: NodeRole::Client,
        }];
        let platform_of = |alias: &str| (alias == "deb-1").then_some(VmGuestPlatform::Linux);
        assert!(precondition_gap(&assignments, &platform_of).is_none());
    }

    // ── QH-90 settle witnesses ───────────────────────────────────────────

    /// The two `nft list tables` listings observed live on box-l3b
    /// (2026-09-26): steady state, and the reordered set seconds after the
    /// daemon-kill control SIGKILLed rustynetd and systemd restarted it.
    fn live_listing_steady() -> String {
        "table inet rustynet_boot\n\
         table inet rustynet_g1\n\
         table ip rustynet_nat_g1\n\
         table inet rustynet_g1_dns\n"
            .to_owned()
    }

    fn live_listing_post_restart() -> String {
        "table ip rustynet_nat_g1\n\
         table inet rustynet_boot\n\
         table inet rustynet_g1_dns\n\
         table inet rustynet_g1\n"
            .to_owned()
    }

    #[test]
    fn generation_candidates_are_exact_shape_and_order_independent() {
        // Both captured live orders must yield exactly the ONE daemon
        // generation table — never rustynet_g1_dns, never rustynet_nat_g1
        // (an `ip`-family table the old loose selector's substring could
        // have matched had its grep crossed families).
        for listing in [live_listing_steady(), live_listing_post_restart()] {
            assert_eq!(
                daemon_generation_table_candidates(&listing),
                vec!["rustynet_g1".to_owned()],
                "listing:\n{listing}"
            );
        }
    }

    #[test]
    fn the_old_loose_selector_would_have_picked_the_dns_table() {
        // Witness for the selector half of the fix: with the dns table
        // listed FIRST (exactly the post-restart ordering shape), the old
        // in-script `grep 'table inet rustynet_g' | head -1` lands on
        // rustynet_g1_dns; the exact-shape selector must not.
        let listing = "table inet rustynet_g1_dns\ntable inet rustynet_g1\n";
        let old_pick = listing
            .lines()
            .find(|l| l.contains("table inet rustynet_g"))
            .map(|l| l.split_whitespace().nth(2).unwrap_or_default());
        assert_eq!(old_pick, Some("rustynet_g1_dns"));
        assert_eq!(
            daemon_generation_table_candidates(listing),
            vec!["rustynet_g1".to_owned()]
        );
    }

    #[test]
    fn only_a_non_generation_table_yields_no_candidates() {
        assert!(daemon_generation_table_candidates("table inet rustynet_g1_dns\n").is_empty());
        assert!(daemon_generation_table_candidates("").is_empty());
        assert!(daemon_generation_table_candidates("table inet rustynet_boot\n").is_empty());
        assert!(
            daemon_generation_table_candidates("table inet rustynet_nat_g1\n").is_empty(),
            "ip-family tables are rejected by exact-name shape, not family alone"
        );
    }

    #[test]
    fn generation_candidates_sort_numerically_not_lexically() {
        // g10 must sort AFTER g9 (a string compare would put "g10" first).
        let listing = "table inet rustynet_g10\ntable inet rustynet_g9\n";
        assert_eq!(
            daemon_generation_table_candidates(listing),
            vec!["rustynet_g9".to_owned(), "rustynet_g10".to_owned()]
        );
        assert_eq!(
            daemon_generation_table_candidates(listing),
            daemon_generation_table_candidates(&{
                let mut lines: Vec<&str> = listing.lines().collect();
                lines.reverse();
                format!("{}\n", lines.join("\n"))
            }),
            "input order must not change the output order"
        );
    }

    #[test]
    fn generation_table_shape_rejects_every_lookalike() {
        for ok in ["rustynet_g1", "rustynet_g10", "rustynet_g007"] {
            assert!(is_daemon_generation_table(ok), "{ok}");
        }
        for bad in [
            "rustynet_g1_dns",
            "rustynet_nat_g1",
            "rustynet_boot",
            "rustynet_g",
            "rustynet_g1x",
            "rustynet_gx1",
            "",
        ] {
            assert!(!is_daemon_generation_table(bad), "{bad:?}");
        }
    }

    #[test]
    fn chain_detection_is_line_shaped_not_substring() {
        assert!(dump_has_killswitch_chain(
            "table inet rustynet_g1 {\n\tchain killswitch {\n"
        ));
        assert!(dump_has_killswitch_chain("chain killswitch {"));
        assert!(dump_has_killswitch_chain("   chain killswitch   {"));
        assert!(!dump_has_killswitch_chain("chain forward {"));
        assert!(!dump_has_killswitch_chain("chainkillswitch {"));
        // The substring trap: a forward chain whose body mentions killswitch.
        assert!(!dump_has_killswitch_chain(
            "chain forward {\n\tip daddr killswitch-host accept\n}"
        ));
        assert!(!dump_has_killswitch_chain(""));
    }

    fn settle_obs(daemon_active: bool, listing: &str) -> SettleObservation {
        SettleObservation {
            daemon_active,
            tables_listing: listing.to_owned(),
        }
    }

    #[test]
    fn settle_verdict_needs_an_active_daemon() {
        let chain_of = |t: &str| t == "rustynet_g1";
        let verdict = settle_verdict(&settle_obs(false, &live_listing_steady()), &chain_of);
        assert!(matches!(verdict, SettleVerdict::NotSettled { .. }));
    }

    #[test]
    fn settle_verdict_needs_a_generation_table_with_a_chain() {
        let chain_of = |t: &str| t == "rustynet_g1";
        // Only non-generation tables exist → not settled (the old control
        // would have skipped here only AFTER the script picked the dns
        // table and found no chain; the settle loop now refuses earlier).
        let verdict = settle_verdict(
            &settle_obs(
                true,
                "table inet rustynet_g1_dns\ntable inet rustynet_boot\n",
            ),
            &chain_of,
        );
        assert!(matches!(verdict, SettleVerdict::NotSettled { .. }));
        // Generation tables exist but none carries the chain yet (tables
        // rebuilding after restart).
        let verdict = settle_verdict(&settle_obs(true, "table inet rustynet_g1\n"), &|_| false);
        assert!(matches!(verdict, SettleVerdict::NotSettled { .. }));
        // Settled: exact pick, recorded.
        let verdict = settle_verdict(&settle_obs(true, &live_listing_steady()), &chain_of);
        assert!(matches!(
            verdict,
            SettleVerdict::Settled { ref table } if table == "rustynet_g1"
        ));
    }

    #[test]
    fn settle_verdict_prefers_the_newest_chain_carrying_generation() {
        let listing = "table inet rustynet_g1\ntable inet rustynet_g2\n";
        // Old generation mid-teardown (no chain), new generation settled.
        let verdict = settle_verdict(&settle_obs(true, listing), &|t: &str| t == "rustynet_g2");
        assert!(matches!(
            verdict,
            SettleVerdict::Settled { ref table } if table == "rustynet_g2"
        ));
        // Both carrying: the deterministic max (newest generation) wins.
        let verdict = settle_verdict(&settle_obs(true, listing), &|_| true);
        assert!(matches!(
            verdict,
            SettleVerdict::Settled { ref table } if table == "rustynet_g2"
        ));
        // Numeric, not lexical: g10 beats g9.
        let listing = "table inet rustynet_g9\ntable inet rustynet_g10\n";
        let verdict = settle_verdict(&settle_obs(true, listing), &|_| true);
        assert!(matches!(
            verdict,
            SettleVerdict::Settled { ref table } if table == "rustynet_g10"
        ));
    }

    #[test]
    fn settle_probe_parser_reads_the_captured_transcript() {
        use base64::Engine as _;
        let listing_b64 =
            base64::engine::general_purpose::STANDARD.encode(live_listing_post_restart());
        let stdout =
            format!("nc_daemon_active=1\nnc_b64_tables={listing_b64}\nnc_settle_probe_done=1\n");
        let obs = parse_settle_probe(&stdout).expect("probe parses");
        assert!(obs.daemon_active);
        assert_eq!(
            daemon_generation_table_candidates(&obs.tables_listing),
            vec!["rustynet_g1".to_owned()],
            "the post-restart ordering must still select the exact table"
        );
        // Daemon down mid-restart.
        let stdout =
            format!("nc_daemon_active=0\nnc_b64_tables={listing_b64}\nnc_settle_probe_done=1\n");
        let obs = parse_settle_probe(&stdout).expect("probe parses");
        assert!(!obs.daemon_active);
        // Unusable probes: missing sentinel, bad flag, empty listing.
        assert!(parse_settle_probe("nc_daemon_active=1\n").is_none());
        assert!(parse_settle_probe("nc_daemon_active=maybe\nnc_settle_probe_done=1\n").is_none());
        assert!(
            parse_settle_probe("nc_daemon_active=1\nnc_b64_tables=\nnc_settle_probe_done=1\n")
                .is_none()
        );
    }

    #[test]
    fn daemon_kill_orders_the_bypass_before_itself_without_gating_on_it() {
        use crate::vm_lab::orchestrator::stage::OrchestrationStage;
        use crate::vm_lab::orchestrator::stage::StageId;
        use crate::vm_lab::orchestrator::stage::negative_control::NegativeControlDaemonKillMidStageStage;
        let stage = NegativeControlDaemonKillMidStageStage;
        assert_eq!(
            stage.ordering_after(),
            &[StageId::NegativeControlKillswitchBypass],
            "the bypass control must be ORDERED before the daemon-kill control"
        );
        assert!(
            stage.dependencies().is_empty(),
            "ordering, not a truth prerequisite: a bypass skip must never \
             skip-cascade the daemon-kill control"
        );
    }
}
