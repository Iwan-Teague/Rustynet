#![allow(dead_code)]
//! Cross-OS security-audit validation for the standard orchestrator.
//!
//! Folds the eight Tier-0 Linux adversarial daemon self-audits into a standard
//! [`OrchestrationStage`](crate::vm_lab::orchestrator::stage::OrchestrationStage)
//! so the Rust `--node` engine proves them, not just the bash live suite. Each
//! audit runs `rustynetd <check>-audit --no-fail-on-drift` over the hardened
//! [`RemoteShellHost`] seam and is accepted ONLY by the SAME typed evaluator the
//! bash live-suite applies (`evaluate_*` in `vm_lab`), which fails closed on an
//! empty corpus, a vacuous (reject-all / no-baseline) result, a too-thin
//! adversarial battery, or any `overall_ok`/`violations` inconsistency — so a
//! broken, stripped, or vacuous audit fails the stage rather than silently
//! passing.

use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::remote_shell::{RemoteShellError, RemoteShellHost};

/// Signature every Tier-0 audit evaluator shares:
/// `(node_alias, raw_json) -> Ok(summary) | Err(reason)`. These evaluators are
/// the SAME pure functions the bash live-suite applies (in `vm_lab`), so both
/// engines enforce byte-identical acceptance criteria.
type AuditEvaluator = fn(&str, &str) -> Result<String, String>;

/// The eight Tier-0 daemon self-audit subcommands `rustynetd` actually exposes
/// (see the dispatch table in `crates/rustynetd/src/main.rs`), as
/// `(matrix-friendly label, daemon subcommand, typed evaluator)`. The labels
/// mirror the `linux_*` run-matrix security columns.
///
/// NOTE — subcommand names are ground-truthed against the daemon dispatch, not
/// the column labels: the signature battery is `membership-signature-audit`
/// (the column is `..._signature_forgery`), and `hello_limiter_flood` is NOT a
/// daemon self-audit — it is proven by a separate live flood test, so this
/// stage carries `blind-exit-reversal-audit` (a real daemon audit with its own
/// `linux_blind_exit_reversal_denied` column) as the eighth instead.
///
/// DEPTH PARITY: the evaluator is the SAME pure function the bash live-suite
/// uses (`crate::vm_lab::evaluate_*`), so the Rust `--node` engine now enforces
/// the FULL depth — beyond the daemon's own `overall_ok`, each rejects an empty
/// corpus, a vacuous (reject-all / no-baseline) result, a too-thin adversarial
/// battery, and any `overall_ok`/`violations` inconsistency. A stripped or
/// vacuous audit therefore fails the stage instead of trivially passing.
pub const LINUX_SECURITY_AUDITS: &[(&str, &str, AuditEvaluator)] = &[
    (
        "membership_revoke_applies",
        "membership-revoke-audit",
        crate::vm_lab::evaluate_membership_revoke_audit_report,
    ),
    (
        "revoked_peer_denied_e2e",
        "revoked-peer-denied-audit",
        crate::vm_lab::evaluate_revoked_peer_denied_report,
    ),
    (
        "membership_signature_forgery",
        "membership-signature-audit",
        crate::vm_lab::evaluate_membership_signature_audit_report,
    ),
    (
        "privileged_helper_allowlist",
        "privileged-helper-allowlist-audit",
        crate::vm_lab::evaluate_privileged_helper_allowlist_report,
    ),
    (
        "policy_default_deny",
        "policy-default-deny-audit",
        crate::vm_lab::evaluate_policy_default_deny_report,
    ),
    (
        "gossip_revoked_readmit",
        "gossip-revoked-readmit-audit",
        crate::vm_lab::evaluate_gossip_revoked_readmit_report,
    ),
    (
        "enrollment_replay",
        "enrollment-replay-audit",
        crate::vm_lab::evaluate_enrollment_replay_report,
    ),
    (
        "blind_exit_reversal_denied",
        "blind-exit-reversal-audit",
        crate::vm_lab::evaluate_blind_exit_reversal_report,
    ),
];

/// True on every desktop platform: the audits dispatch through the adapter's
/// [`RemoteShellHost`] seam, which Linux, macOS and Windows all implement.
///
/// Do not read this as "live-proven on all three". It is a *runtime-support*
/// gate, not an evidence claim. Measured 2026-08-10: **macOS has executed this
/// stage and passed** — e.g. run `live-lab-direct-1784500192` (2026-07-19, five
/// Linux nodes plus one macOS) recorded `security_audit_validation = pass` with
/// NO `reported_skips.json`, and `outcome_for` forces `Skipped` whenever any
/// node is reported-skipped, so the macOS node was genuinely audited. **Windows
/// has not**, because no Windows node has yet reached this stage in a recorded
/// `--node` run. A non-desktop platform (iOS/Android) has no daemon audit
/// surface and is reported-skipped — named on disk, never a silent pass.
pub fn security_audit_runtime_implemented(platform: VmGuestPlatform) -> bool {
    matches!(
        platform,
        VmGuestPlatform::Linux | VmGuestPlatform::Macos | VmGuestPlatform::Windows
    )
}

/// The verdict for ONE Tier-0 audit on ONE node.
///
/// `Blocked` is deliberately distinct from `Failed`: it means the control was
/// never exercised (the daemon subcommand could not be dispatched at all), which
/// is not the same evidentiary claim as "the control was exercised and the
/// daemon violated it". Both fail the stage; only `Failed` asserts a violation.
/// Collapsing the two would let an unreachable host read as eight security
/// failures, or — worse, in the other direction — let an unexercised control
/// inherit a neighbouring control's pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditVerdict {
    Passed,
    Failed(String),
    Blocked(String),
}

impl AuditVerdict {
    /// The run-matrix status string this verdict records. `blocked` outranks
    /// both `skip` and `pass` in the recorder's precedence (see `status_rank`),
    /// so an unexercised control can never let a platform read green.
    pub fn matrix_status(&self) -> &'static str {
        match self {
            AuditVerdict::Passed => "pass",
            AuditVerdict::Failed(_) => "fail",
            AuditVerdict::Blocked(_) => "blocked",
        }
    }

    pub fn detail(&self) -> Option<&str> {
        match self {
            AuditVerdict::Passed => None,
            AuditVerdict::Failed(detail) | AuditVerdict::Blocked(detail) => Some(detail.as_str()),
        }
    }

    pub fn is_ok(&self) -> bool {
        matches!(self, AuditVerdict::Passed)
    }
}

/// One audit's outcome on one node, in the shape the per-control artifact and
/// the run-matrix recorder both consume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditResult {
    /// The matrix-friendly label — byte-identical to the `{platform}_{label}`
    /// run-matrix column suffix.
    pub audit_id: &'static str,
    pub verdict: AuditVerdict,
}

/// True for a dispatch error that is a property of the HOST rather than of this
/// particular audit — the transport is down, or the connection failed. Such an
/// error will recur identically for every remaining audit, so re-attempting them
/// buys no evidence and costs one full transport timeout each (180 s apiece, and
/// the stage deadline is opt-in). An audit-specific error is not host-level and
/// does not stop the sweep.
fn is_host_level_dispatch_error(err: &RemoteShellError) -> bool {
    matches!(
        err,
        RemoteShellError::Transport { .. } | RemoteShellError::Network { .. }
    )
}

/// Run all eight daemon self-audits through the shell seam, applying each
/// audit's typed evaluator, and return a verdict for EVERY audit.
///
/// "Pass" means the evaluator's full contract (`overall_ok` AND the anti-vacuity
/// guards: no empty corpus, no vacuous/reject-all baseline, no too-thin battery),
/// not merely the daemon's `overall_ok` flag.
///
/// RUN-ALL, NOT FAIL-FAST — a deliberate change from the earlier fail-fast loop,
/// and the reason it is safe: fail-closed is a property of the STAGE outcome,
/// which [`security_audits_ok`] still derives from "did every audit pass". It was
/// never a property of the loop. Stopping at the first failure left the other
/// seven controls with no verdict at all, and the run matrix then recorded them
/// as `not_run` — a column value that asserts "no node of this platform was in
/// the run", which is false and materially misleading on a run where the node was
/// present and the control simply was not reached.
pub fn run_security_audits(
    shell: &dyn RemoteShellHost,
    daemon_path: &str,
    alias: &str,
) -> Vec<AuditResult> {
    let mut results = Vec::with_capacity(LINUX_SECURITY_AUDITS.len());
    let mut host_down: Option<String> = None;
    for (label, subcommand, evaluate) in LINUX_SECURITY_AUDITS {
        // Once the host itself is unreachable, every remaining audit gets a
        // verdict WITHOUT another 180 s transport timeout. The verdict is still
        // `Blocked`, so the columns behave identically; only the cost changes.
        if let Some(cause) = &host_down {
            results.push(AuditResult {
                audit_id: label,
                verdict: AuditVerdict::Blocked(format!(
                    "{label}: not attempted after a host-level dispatch failure ({cause})"
                )),
            });
            continue;
        }
        let argv = [daemon_path, *subcommand, "--no-fail-on-drift"];
        let verdict = match shell.run_argv(&argv, &[], &[]) {
            Err(err) => {
                if is_host_level_dispatch_error(&err) {
                    host_down = Some(format!("on `{subcommand}`: {err}"));
                }
                AuditVerdict::Blocked(format!("{label}: dispatch of `{subcommand}` failed: {err}"))
            }
            Ok(out) => {
                // A non-zero exit from the audit itself arrives here as `Ok`, so
                // a real violation reaches the typed evaluator and is recorded
                // `Failed`. Only a dispatch-level error yields `Blocked`.
                let stdout = String::from_utf8_lossy(&out.stdout);
                match evaluate(alias, &stdout) {
                    Ok(_) => AuditVerdict::Passed,
                    Err(detail) => {
                        AuditVerdict::Failed(format!("{label} (`{subcommand}`): {detail}"))
                    }
                }
            }
        };
        results.push(AuditResult {
            audit_id: label,
            verdict,
        });
    }
    results
}

/// Fail-closed reduction of a node's audit results to the stage's verdict:
/// `Err` with every non-passing audit's detail if ANY audit did not pass.
pub fn security_audits_ok(results: &[AuditResult]) -> Result<(), String> {
    // Default-deny on a short result set: a caller that produced fewer verdicts
    // than there are audits has not exercised the full battery, and an empty
    // set must never reduce to "everything passed" (§10.4).
    if results.len() != LINUX_SECURITY_AUDITS.len() {
        return Err(format!(
            "security-audit battery incomplete: {} of {} controls produced a verdict",
            results.len(),
            LINUX_SECURITY_AUDITS.len()
        ));
    }
    let problems: Vec<String> = results
        .iter()
        .filter_map(|result| result.verdict.detail().map(str::to_owned))
        .collect();
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("; "))
    }
}

/// Back-compatible wrapper: run every audit and reduce to the fail-closed
/// stage verdict, discarding the per-control detail.
pub fn validate_linux_security_audits(
    shell: &dyn RemoteShellHost,
    daemon_path: &str,
    alias: &str,
) -> Result<(), String> {
    security_audits_ok(&run_security_audits(shell, daemon_path, alias))
}

// ── Substrate-transit control (Linux, vxlan runs) ────────────────────────────
//
// A dedicated control for the vxlan lab substrate's transit firewall rules —
// deliberately NOT a member of [`LINUX_SECURITY_AUDITS`]: that battery is
// per-audit-id × per-platform run-matrix columns, and a substrate control only
// applies to Linux runs that declared the vxlan substrate. A ninth entry would
// force a new column onto every platform's matrix and read `not_run` (or worse,
// `blocked`) on every macOS/Windows row. Instead it is evaluated per Linux node
// inside `SecurityAuditValidationStage`, fail-closed into the same stage
// outcome, with its own evidence line.
//
// Contract (design D, killswitch + transit design 2026-10-03): the control
// passes iff (the run declared + provisioned the vxlan substrate) == (the
// daemon's status shows `substrate_transit=lab-active`). When active, every
// `rustynet_substrate_transit` rule in the nft ruleset must render EXACTLY the
// daemon's installed shape against the ATTESTED underlay, the per-table rule
// count must equal the attested peer count, the counters must be readable and
// non-zero (anti-vacuity: a control that never saw a packet proves nothing),
// and the rules must live in BOTH the `rustynet_g<N>` group table and the
// `rustynet_boot` boot table.

/// The comment the daemon stamps on every substrate-transit rule.
pub const SUBSTRATE_TRANSIT_RULE_COMMENT: &str = "rustynet_substrate_transit";

/// The `substrate_transit=` line parsed out of `rustynet status` output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubstrateTransitStatus {
    pub overlay_interface: String,
    pub underlay_interface: String,
    pub peers: u32,
}

/// Parse the `substrate_transit` field out of the daemon status.
///
/// The daemon's `rustynet status` response is ONE line of space-separated
/// `key=value` tokens, and the lab field is appended at the very END of it
/// (after the gossip suffix): `... gossip_transport_error=none
/// substrate_transit=lab-active overlay=<o> underlay=<u> peers=<n>`
/// (`rustynetd::lab_substrate_transit::SubstrateTransit::status_field`). This
/// parser therefore scans TOKENS, not lines: a token whose key is exactly
/// `substrate_transit` starts the field, and for `lab-active` the next three
/// tokens must be exactly `overlay=`, `underlay=`, `peers=` in the daemon's
/// order and nothing may follow them on the line.
///
/// `Ok(None)` = the field is absent, i.e. transit is OFF. A PRESENT field that
/// does not parse is `Err` — fail closed, never "unreadable, assume off". Two
/// `substrate_transit` fields anywhere in the output are also `Err`.
pub fn parse_substrate_transit_status(
    status_stdout: &str,
) -> Result<Option<SubstrateTransitStatus>, String> {
    let mut parsed: Option<SubstrateTransitStatus> = None;
    let mut seen = false;
    for line in status_stdout.lines() {
        let mut tokens = line.split_whitespace();
        while let Some(token) = tokens.next() {
            let Some(("substrate_transit", state)) = token.split_once('=') else {
                continue;
            };
            if seen {
                return Err("duplicate substrate_transit status field".to_owned());
            }
            seen = true;
            if state != "lab-active" {
                // Explicitly off is equivalent to the field being absent, but a
                // payload alongside a non-active state is malformed.
                if tokens.any(|extra| extra.contains('=')) {
                    return Err(format!("malformed substrate_transit status field: {line}"));
                }
                parsed = None;
                break;
            }
            let mut take = |want: &str| -> Result<String, String> {
                let field = tokens.next().ok_or_else(|| {
                    format!("substrate_transit status missing {want}= in `{line}`")
                })?;
                match field.split_once('=') {
                    Some((key, value)) if key == want && !value.is_empty() => Ok(value.to_owned()),
                    _ => Err(format!(
                        "malformed substrate_transit status field `{field}` (expected {want}=)"
                    )),
                }
            };
            let overlay = take("overlay")?;
            let underlay = take("underlay")?;
            let peers = take("peers")?
                .parse::<u32>()
                .map_err(|_| format!("malformed peers value in `{line}`"))?;
            // The daemon appends this field LAST; anything after it is not
            // something this reader understands, so refuse rather than guess.
            if let Some(extra) = tokens.next() {
                return Err(format!(
                    "unexpected token `{extra}` after the substrate_transit status field"
                ));
            }
            parsed = Some(SubstrateTransitStatus {
                overlay_interface: overlay,
                underlay_interface: underlay,
                peers,
            });
            break;
        }
    }
    Ok(parsed)
}

/// Evidence from a passing substrate-transit ruleset evaluation: which tables
/// carried rules, how many rules, and the smallest packet counter observed
/// (the anti-vacuity witness).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubstrateTransitEvidence {
    pub tables: Vec<String>,
    pub rule_count: usize,
    pub min_packets: u64,
}

/// Parse ONE rendered nft rule against the attested underlay. The rendered
/// form is
/// `oifname "<underlay>" ip daddr <peer> udp sport 4789 udp dport 4789
/// counter packets <N> bytes <M> accept comment "rustynet_substrate_transit"`.
/// Returns `(daddr, packets)`. Anything else — wrong underlay, other ports,
/// zero/unreadable counters, missing or different comment — is a hard error.
fn parse_substrate_transit_rule(
    line: &str,
    expected_underlay: &str,
) -> Result<(String, u64), String> {
    let expected_prefix = format!("oifname \"{expected_underlay}\" ip daddr ");
    let rest = line.strip_prefix(&expected_prefix).ok_or_else(|| {
        format!(
            "rule does not match the attested shape (expected `oifname \"{expected_underlay}\" ip daddr <peer> ...`): {line}"
        )
    })?;
    let mut parts = rest.splitn(2, ' ');
    let daddr = parts.next().unwrap_or_default();
    let daddr: std::net::Ipv4Addr = daddr
        .parse()
        .map_err(|_| format!("substrate rule peer `{daddr}` is not an IPv4 address: {line}"))?;
    let Some(rest) = parts.next() else {
        return Err(format!("substrate rule truncated: {line}"));
    };
    let rest = rest
        .strip_prefix("udp sport 4789 udp dport 4789 counter packets ")
        .ok_or_else(|| {
            format!("substrate rule does not pin udp 4789→4789 with a counter: {line}")
        })?;
    let mut parts = rest.splitn(2, ' ');
    let packets = parts
        .next()
        .unwrap_or_default()
        .parse::<u64>()
        .map_err(|_| format!("substrate rule counter unreadable: {line}"))?;
    let Some(rest) = parts.next() else {
        return Err(format!("substrate rule truncated: {line}"));
    };
    let rest = rest
        .strip_prefix("bytes ")
        .ok_or_else(|| format!("substrate rule missing byte counter: {line}"))?;
    let mut parts = rest.splitn(2, ' ');
    let _bytes = parts
        .next()
        .unwrap_or_default()
        .parse::<u64>()
        .map_err(|_| format!("substrate rule byte counter unreadable: {line}"))?;
    let Some(rest) = parts.next() else {
        return Err(format!("substrate rule truncated: {line}"));
    };
    if rest != format!("accept comment \"{SUBSTRATE_TRANSIT_RULE_COMMENT}\"") {
        return Err(format!(
            "substrate rule verdict/comment does not match `accept comment \"{SUBSTRATE_TRANSIT_RULE_COMMENT}\"`: {line}"
        ));
    }
    Ok((daddr.to_string(), packets))
}

/// Split an `nft list ruleset` dump into `(table name, body lines)` pairs by
/// brace-depth line scanning (`table inet <name> {` … matching `}`).
fn substrate_tables(ruleset: &str) -> Vec<(String, Vec<String>)> {
    let mut tables: Vec<(String, Vec<String>)> = Vec::new();
    let mut depth: usize = 0;
    let mut current: Option<(String, Vec<String>)> = None;
    for raw in ruleset.lines() {
        let trimmed = raw.trim();
        if depth == 0 && trimmed.starts_with("table ") && trimmed.ends_with('{') {
            let rest = trimmed["table ".len()..].trim();
            let rest = rest.trim_end_matches('{').trim();
            // `table inet <name> {` — the family token precedes the name.
            let mut parts = rest.split_whitespace();
            let _family = parts.next();
            let name = parts.next().unwrap_or(rest).to_owned();
            current = Some((name, Vec::new()));
            depth += trimmed.matches('{').count();
            depth = depth.saturating_sub(trimmed.matches('}').count());
            continue;
        }
        if depth == 0 {
            continue;
        }
        if let Some((_, body)) = current.as_mut() {
            body.push(trimmed.to_owned());
        }
        depth += trimmed.matches('{').count();
        depth = depth.saturating_sub(trimmed.matches('}').count());
        if depth == 0 {
            if let Some(table) = current.take() {
                tables.push(table);
            }
        }
    }
    tables
}

/// Evaluate the full ruleset for an ACTIVE substrate node: every substrate
/// rule must render the attested shape with a non-zero counter, per-table
/// counts must equal the attested peer count with distinct peers, and the
/// rules must live in a `rustynet_g<N>` table AND `rustynet_boot` — nothing
/// else. Returns the evidence on success; every defect found, joined.
pub fn evaluate_substrate_transit_ruleset(
    underlay: &str,
    peers: u32,
    ruleset: &str,
) -> Result<SubstrateTransitEvidence, String> {
    let mut errors: Vec<String> = Vec::new();
    let mut group_tables = 0usize;
    let mut boot_tables = 0usize;
    let mut evidence_tables: Vec<String> = Vec::new();
    let mut rule_count = 0usize;
    let mut min_packets: Option<u64> = None;
    for (name, body) in substrate_tables(ruleset) {
        let rules: Vec<&String> = body
            .iter()
            .filter(|l| l.contains(SUBSTRATE_TRANSIT_RULE_COMMENT))
            .collect();
        if rules.is_empty() {
            continue;
        }
        let is_group = name.starts_with("rustynet_g");
        let is_boot = name == "rustynet_boot";
        if is_group {
            group_tables += 1;
        }
        if is_boot {
            boot_tables += 1;
        }
        if !is_group && !is_boot {
            errors.push(format!("substrate rule found in unexpected table `{name}`"));
            continue;
        }
        if rules.len() != peers as usize {
            errors.push(format!(
                "table `{name}` carries {} substrate rules but peers={peers} are attested",
                rules.len()
            ));
        }
        let mut daddrs: Vec<String> = Vec::new();
        for rule in &rules {
            match parse_substrate_transit_rule(rule, underlay) {
                Ok((daddr, packets)) => {
                    if packets == 0 {
                        errors.push(format!(
                            "table `{name}`: rule for {daddr} has counter packets=0 — the transit control was never exercised"
                        ));
                    }
                    min_packets = Some(match min_packets {
                        Some(seen) => seen.min(packets),
                        None => packets,
                    });
                    daddrs.push(daddr);
                }
                Err(e) => errors.push(format!("table `{name}`: {e}")),
            }
        }
        daddrs.sort();
        daddrs.dedup();
        if daddrs.len() != rules.len() {
            errors.push(format!(
                "table `{name}`: duplicate peer addresses across substrate rules"
            ));
        }
        rule_count += rules.len();
        evidence_tables.push(name);
    }
    if group_tables == 0 {
        errors.push("no substrate rules found in any `rustynet_g<N>` table".to_owned());
    }
    if boot_tables == 0 {
        errors.push("no substrate rules found in the `rustynet_boot` table".to_owned());
    }
    if errors.is_empty() {
        Ok(SubstrateTransitEvidence {
            tables: evidence_tables,
            rule_count,
            min_packets: min_packets.unwrap_or(0),
        })
    } else {
        Err(errors.join("; "))
    }
}

/// True when this run declared AND provisioned the vxlan substrate — the
/// posture that must agree with the daemon's live status line.
pub fn substrate_transit_declared(
    record: Option<&crate::vm_lab::orchestrator::stage::cross_network::substrate::SubstrateRecord>,
) -> bool {
    matches!(record, Some(record) if record.substrate_id == "vxlan" && record.provisioned)
}

/// The substrate-transit control, pure decision core:
/// pass iff declared == active; when active, the ruleset must satisfy
/// [`evaluate_substrate_transit_ruleset`]. Returns the evidence for the pass.
pub fn substrate_transit_scoped(
    declared: bool,
    observed: Option<&SubstrateTransitStatus>,
    ruleset: &str,
) -> Result<SubstrateTransitEvidence, String> {
    match (declared, observed) {
        (false, None) => Ok(SubstrateTransitEvidence {
            tables: Vec::new(),
            rule_count: 0,
            min_packets: 0,
        }),
        (true, Some(status)) => {
            evaluate_substrate_transit_ruleset(&status.underlay_interface, status.peers, ruleset)
        }
        (true, None) => Err(
            "run declared the vxlan substrate but the daemon status shows no \
             substrate_transit=lab-active line"
                .to_owned(),
        ),
        (false, Some(_)) => Err(
            "daemon status reports substrate_transit=lab-active but this run \
             did not declare a vxlan substrate"
                .to_owned(),
        ),
    }
}

/// Render the evidence line appended to the stage log for one node.
pub fn substrate_transit_evidence_line(
    observed: Option<&SubstrateTransitStatus>,
    evidence: &SubstrateTransitEvidence,
) -> String {
    match observed {
        None => "substrate_transit=inactive rules=0".to_owned(),
        Some(status) => format!(
            "substrate_transit=active underlay={} peers={} rules={} min_packets={} tables={}",
            status.underlay_interface,
            status.peers,
            evidence.rule_count,
            evidence.min_packets,
            evidence.tables.join(","),
        ),
    }
}

/// Live dispatch of the substrate-transit control for one Linux node: query
/// `rustynet status` (socket env pinned, `sudo -n`), and when transit is
/// active, `nft list ruleset`. Returns the evidence line on PASS.
pub fn run_substrate_transit_control(
    shell: &dyn RemoteShellHost,
    declared: bool,
) -> Result<String, String> {
    use crate::vm_lab::LINUX_RUSTYNET_CLI_PATH;
    const DAEMON_SOCKET: &str = "/run/rustynet/rustynetd.sock";
    let env_pair = format!("RUSTYNET_DAEMON_SOCKET={DAEMON_SOCKET}");
    let status_argv: [&str; 6] = [
        "sudo",
        "-n",
        "env",
        env_pair.as_str(),
        LINUX_RUSTYNET_CLI_PATH,
        "status",
    ];
    let status_out = shell
        .run_argv(&status_argv, &[], &[])
        .map_err(|e| format!("`rustynet status` dispatch failed: {e}"))?;
    if !status_out.is_success() {
        return Err(format!(
            "`rustynet status` exited {} — substrate posture unverifiable",
            status_out.code
        ));
    }
    let stdout = String::from_utf8_lossy(&status_out.stdout).into_owned();
    let status = parse_substrate_transit_status(&stdout)?;
    let evidence = match &status {
        None => substrate_transit_scoped(declared, None, "")?,
        Some(active) => {
            let ruleset_out = shell
                .run_argv(&["sudo", "-n", "nft", "list", "ruleset"], &[], &[])
                .map_err(|e| format!("`nft list ruleset` dispatch failed: {e}"))?;
            if !ruleset_out.is_success() {
                return Err(format!(
                    "`nft list ruleset` exited {} — substrate rules unverifiable",
                    ruleset_out.code
                ));
            }
            let ruleset = String::from_utf8_lossy(&ruleset_out.stdout).into_owned();
            substrate_transit_scoped(declared, Some(active), &ruleset)?
        }
    };
    Ok(substrate_transit_evidence_line(status.as_ref(), &evidence))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_implemented_linux_macos_and_windows() {
        assert!(security_audit_runtime_implemented(VmGuestPlatform::Linux));
        assert!(security_audit_runtime_implemented(VmGuestPlatform::Macos));
        assert!(security_audit_runtime_implemented(VmGuestPlatform::Windows));
        assert!(!security_audit_runtime_implemented(VmGuestPlatform::Ios));
        assert!(!security_audit_runtime_implemented(
            VmGuestPlatform::Android
        ));
    }

    #[test]
    fn covers_all_eight_tier0_audits() {
        let labels: Vec<&str> = LINUX_SECURITY_AUDITS.iter().map(|(l, _, _)| *l).collect();
        assert_eq!(labels.len(), 8);
        for expected in [
            "membership_revoke_applies",
            "revoked_peer_denied_e2e",
            "membership_signature_forgery",
            "privileged_helper_allowlist",
            "policy_default_deny",
            "gossip_revoked_readmit",
            "enrollment_replay",
            "blind_exit_reversal_denied",
        ] {
            assert!(labels.contains(&expected), "missing audit: {expected}");
        }
        // Every subcommand is a distinct `*-audit` that the daemon dispatch in
        // rustynetd/src/main.rs actually exposes.
        let daemon_subcommands = [
            "membership-revoke-audit",
            "revoked-peer-denied-audit",
            "membership-signature-audit",
            "privileged-helper-allowlist-audit",
            "policy-default-deny-audit",
            "gossip-revoked-readmit-audit",
            "enrollment-replay-audit",
            "blind-exit-reversal-audit",
        ];
        for (_, sub, _) in LINUX_SECURITY_AUDITS {
            assert!(sub.ends_with("-audit"), "not an audit subcommand: {sub}");
            assert!(
                daemon_subcommands.contains(sub),
                "subcommand not in the rustynetd dispatch table: {sub}"
            );
        }
    }

    use crate::vm_lab::orchestrator::remote_shell::{MockShellHost, RemoteExitStatus};

    const TEST_DAEMON: &str = "/usr/local/bin/rustynetd";

    fn audit_argv(subcommand: &str) -> [&str; 3] {
        // Mirrors the argv `validate_linux_security_audits` dispatches.
        [TEST_DAEMON, subcommand, "--no-fail-on-drift"]
    }

    fn exit_ok(stdout: &str) -> RemoteExitStatus {
        RemoteExitStatus {
            code: 0,
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        }
    }

    #[test]
    fn validate_fails_closed_when_first_audit_report_is_invalid() {
        // Program the FIRST audit (membership-revoke) with a structurally
        // invalid report. Its typed evaluator must reject it, and the loop must
        // return that failure prefixed with the matrix label — proving the
        // dispatch calls the right evaluator and fails closed (not the old
        // overall_ok-only acceptance).
        let mock = MockShellHost::new();
        let argv = audit_argv("membership-revoke-audit");
        mock.program_run_response(&argv, exit_ok(r#"{"schema_version": 999}"#));
        let err = validate_linux_security_audits(&mock, TEST_DAEMON, "deb-1")
            .expect_err("an invalid audit report must fail the stage");
        assert!(
            err.contains("membership_revoke_applies"),
            "error must name the failing audit: {err}"
        );
        assert!(
            err.contains("membership-revoke-audit"),
            "error must name the subcommand: {err}"
        );
    }

    #[test]
    fn validate_fails_closed_on_dispatch_error() {
        // No programmed response and no default → the shell seam errors on the
        // first audit; that must surface as a fail-closed dispatch error, never
        // a pass.
        let mock = MockShellHost::new();
        let err = validate_linux_security_audits(&mock, TEST_DAEMON, "deb-1")
            .expect_err("a dispatch error must fail the stage");
        assert!(
            err.contains("dispatch of `membership-revoke-audit` failed"),
            "error must attribute the dispatch failure: {err}"
        );
    }

    #[test]
    fn every_audit_gets_a_verdict_even_when_the_first_one_fails() {
        // The regression this pins: the loop used to stop at the first failure,
        // so seven controls got no verdict at all and the run matrix recorded
        // them as `not_run` — a value that asserts no node of that platform was
        // in the run. Here the node IS in the run and every control must be
        // accounted for.
        let mock = MockShellHost::new();
        let results = run_security_audits(&mock, TEST_DAEMON, "deb-1");
        assert_eq!(
            results.len(),
            LINUX_SECURITY_AUDITS.len(),
            "every audit must produce a verdict, not just the ones before the first failure"
        );
        for (result, (label, _, _)) in results.iter().zip(LINUX_SECURITY_AUDITS) {
            assert_eq!(result.audit_id, *label, "verdicts must stay in audit order");
            assert!(
                matches!(result.verdict, AuditVerdict::Blocked(_)),
                "an undispatchable audit is BLOCKED (not exercised), never failed or passed: {:?}",
                result.verdict
            );
        }
        // Fail-closed is preserved at the stage level regardless.
        assert!(security_audits_ok(&results).is_err());
    }

    #[test]
    fn a_failing_audit_does_not_stop_the_remaining_seven() {
        // The regression the run-all change exists to prevent, on the branch the
        // other test cannot reach. `every_audit_gets_a_verdict_even_when_the_first_one_fails`
        // uses an unprogrammed mock, so all eight verdicts are Blocked and a
        // fail-fast-on-Failed mutation survives it. Here audit #1 is programmed
        // with a report its typed evaluator REJECTS, and the remaining seven
        // must still be dispatched and recorded.
        let mock = MockShellHost::new();
        mock.program_run_response(
            &audit_argv("membership-revoke-audit"),
            exit_ok(r#"{"schema_version": 999}"#),
        );
        let results = run_security_audits(&mock, TEST_DAEMON, "deb-1");
        assert_eq!(
            results.len(),
            LINUX_SECURITY_AUDITS.len(),
            "a FAILED audit must not truncate the battery"
        );
        assert!(
            matches!(results[0].verdict, AuditVerdict::Failed(_)),
            "audit #1 was exercised and rejected, so it is Failed (not Blocked): {:?}",
            results[0].verdict
        );
        for result in &results[1..] {
            assert!(
                matches!(result.verdict, AuditVerdict::Blocked(_)),
                "audits after a FAILED one must still be attempted: {} was {:?}",
                result.audit_id,
                result.verdict
            );
        }
        assert!(security_audits_ok(&results).is_err());
    }

    #[test]
    fn a_host_level_dispatch_failure_stops_re_dialling_but_still_verdicts_every_control() {
        // A dead host must cost ONE transport timeout, not eight — while every
        // control still gets a Blocked verdict so no column falls back to
        // `not_run` (which would assert the node was never in the run).
        let mock = MockShellHost::new();
        let results = run_security_audits(&mock, TEST_DAEMON, "deb-1");
        assert_eq!(results.len(), LINUX_SECURITY_AUDITS.len());
        assert!(
            results
                .iter()
                .all(|r| matches!(r.verdict, AuditVerdict::Blocked(_)))
        );
        // Exactly one audit was actually dialled; the rest are marked
        // not-attempted rather than each paying its own timeout.
        let not_attempted = results
            .iter()
            .filter(|r| {
                r.verdict.detail().is_some_and(|d| {
                    d.contains("not attempted after a host-level dispatch failure")
                })
            })
            .count();
        assert_eq!(
            not_attempted,
            LINUX_SECURITY_AUDITS.len() - 1,
            "only the first audit should have been dialled against a dead host"
        );
    }

    #[test]
    fn an_incomplete_battery_is_denied_rather_than_reduced_to_ok() {
        // Default-deny: a short result set must never reduce to "all passed".
        assert!(security_audits_ok(&[]).is_err());
        assert!(
            security_audits_ok(&[AuditResult {
                audit_id: "policy_default_deny",
                verdict: AuditVerdict::Passed,
            }])
            .is_err()
        );
    }

    #[test]
    fn a_blocked_audit_is_never_reported_as_a_pass() {
        let results = vec![
            AuditResult {
                audit_id: "policy_default_deny",
                verdict: AuditVerdict::Passed,
            },
            AuditResult {
                audit_id: "enrollment_replay",
                verdict: AuditVerdict::Blocked("dispatch failed".into()),
            },
        ];
        assert_eq!(results[0].verdict.matrix_status(), "pass");
        assert_eq!(results[1].verdict.matrix_status(), "blocked");
        assert!(security_audits_ok(&results).is_err());
    }

    #[test]
    fn validate_rejects_vacuous_signature_audit_via_typed_evaluator() {
        // Prove the depth-parity win directly: a membership-signature report the
        // daemon calls overall_ok=true but which is VACUOUS (no valid baseline
        // accepted) must still fail. The old overall_ok-only check would have
        // passed it; the typed evaluator this stage now dispatches to does not.
        let vacuous = serde_json::json!({
            "schema_version": 1,
            "total_cases": 12,
            "baseline_accepted": 0,
            "forgeries_rejected": 12,
            "overall_ok": true,
            "violations": []
        })
        .to_string();
        let err = crate::vm_lab::evaluate_membership_signature_audit_report("deb-1", &vacuous)
            .expect_err("a no-baseline (vacuous) signature audit must be rejected");
        assert!(err.contains("vacuous"), "{err}");
    }

    // ── substrate-transit control ────────────────────────────────────────────

    const ATTESTED_UNDERLAY: &str = "mgmt0";

    fn rendered_rule(daddr: &str, packets: u64) -> String {
        format!(
            "oifname \"{ATTESTED_UNDERLAY}\" ip daddr {daddr} udp sport 4789 udp dport 4789 \
             counter packets {packets} bytes 400 accept comment \"{SUBSTRATE_TRANSIT_RULE_COMMENT}\""
        )
    }

    fn good_ruleset() -> String {
        format!(
            "table inet rustynet_g2 {{\n    chain forward {{\n        type filter hook forward priority filter; policy accept;\n        {}\n        {}\n    }}\n}}\ntable inet rustynet_boot {{\n    chain forward {{\n        {}\n        {}\n    }}\n}}\n",
            rendered_rule("192.168.64.11", 5),
            rendered_rule("192.168.64.10", 7),
            rendered_rule("192.168.64.11", 5),
            rendered_rule("192.168.64.10", 7),
        )
    }

    fn active_status() -> Option<SubstrateTransitStatus> {
        Some(SubstrateTransitStatus {
            overlay_interface: "rustynet-vx0".to_owned(),
            underlay_interface: ATTESTED_UNDERLAY.to_owned(),
            peers: 2,
        })
    }

    #[test]
    fn substrate_status_parses_the_active_line() {
        let out = "mesh_ip=10.7.0.1\n\
                   substrate_transit=lab-active overlay=rustynet-vx0 underlay=mgmt0 peers=2\n\
                   role=anchor\n";
        let parsed = parse_substrate_transit_status(out).expect("parse");
        assert_eq!(parsed.as_ref(), active_status().as_ref());
    }

    /// A realistic daemon status line: ONE line, the shape `rustynet status`
    /// prints (`IpcResponse::ok(format!(..))` in `rustynetd/src/daemon.rs`,
    /// ending `local_wg_public_key=<key>{gossip_suffix}{lab_substrate_suffix}`),
    /// with the lab field appended last, exactly as the daemon does.
    const REAL_STATUS_PREFIX: &str = "node_id=client-1 node_role=client state=FullTunnel \
        generation=4 exit_node=exit-1 selected_exit_peer_endpoint=192.168.64.20:51820 \
        selected_exit_peer_endpoint_error=none managed_peer_endpoints=2 \
        managed_peer_endpoints_error=none serving_exit_node=false lan_access=false \
        restricted_safe_mode=false restriction_mode=None bootstrap_error=none \
        reconcile_attempts=7 reconcile_failures=0 last_reconcile_unix=1759500000 \
        last_reconcile_error=none encrypted_key_store=true auto_tunnel_enforce=true \
        path_mode=direct path_reason=direct_handshake_fresh membership_epoch=3 \
        membership_active_nodes=5 dns_scoped_apply_degraded=false \
        local_wg_public_key=Zm9vYmFyYmF6cXV4Zm9vYmFyYmF6cXV4Zm9vYmFyYmE= \
        gossip_state=active gossip_accepted_total=3 gossip_minted_total=2 \
        gossip_push_failures_total=0 gossip_recv_errors_total=0 gossip_rejected_total=0 \
        gossip_reject_reasons=none gossip_peers_registered=4 gossip_local_epoch=3 \
        gossip_identity_mismatch=none gossip_transport_error=none";

    /// The daemon's lab field, golden-copied from the daemon's own test
    /// (`rustynetd/src/lab_substrate_transit.rs`, `status_field` assertion).
    const GOLDEN_ACTIVE_FIELD: &str =
        "substrate_transit=lab-active overlay=rustynet-vx0 underlay=eth0 peers=2";

    fn real_status_line(lab_field: Option<&str>) -> String {
        match lab_field {
            Some(field) => format!("{REAL_STATUS_PREFIX} {field}\n"),
            None => format!("{REAL_STATUS_PREFIX}\n"),
        }
    }

    #[test]
    fn substrate_status_parses_the_real_single_line_daemon_status() {
        let line = real_status_line(Some(GOLDEN_ACTIVE_FIELD));
        assert_eq!(line.lines().count(), 1, "the daemon status is ONE line");
        assert_eq!(
            parse_substrate_transit_status(&line).expect("parse"),
            Some(SubstrateTransitStatus {
                overlay_interface: "rustynet-vx0".to_owned(),
                underlay_interface: "eth0".to_owned(),
                peers: 2,
            })
        );
        // The same line without the lab suffix (a default node, or a lab
        // build with no attestation) means transit is OFF.
        assert_eq!(
            parse_substrate_transit_status(&real_status_line(None)).expect("absent"),
            None
        );
        // The veth overlay spelling parses too.
        let veth = real_status_line(Some(
            "substrate_transit=lab-active overlay=rustynet-vxl underlay=enp0s9 peers=1",
        ));
        assert_eq!(
            parse_substrate_transit_status(&veth)
                .expect("parse")
                .map(|status| (status.overlay_interface, status.peers)),
            Some(("rustynet-vxl".to_owned(), 1))
        );
        // Malformed fields on the REAL line fail closed.
        for bad in [
            "substrate_transit=lab-active overlay=rustynet-vx0 underlay=eth0",
            "substrate_transit=lab-active overlay=rustynet-vx0 underlay=eth0 peers=x",
            "substrate_transit=lab-active underlay=eth0 overlay=rustynet-vx0 peers=2",
            "substrate_transit=lab-active overlay=rustynet-vx0 underlay=eth0 peers=2 extra=1",
            "substrate_transit=lab-active overlay= underlay=eth0 peers=2",
            "substrate_transit=lab-active overlay=rustynet-vx0 underlay=eth0 peers=2 \
             substrate_transit=lab-active overlay=rustynet-vx0 underlay=eth0 peers=2",
        ] {
            assert!(
                parse_substrate_transit_status(&real_status_line(Some(bad))).is_err(),
                "must reject: {bad}"
            );
        }
    }

    /// The golden field above must be exactly what the daemon's own formatter
    /// emits, and the full line built with the daemon's formatter must parse:
    /// the audit control and the daemon can never drift apart silently.
    #[cfg(target_os = "linux")]
    #[test]
    fn substrate_status_parses_the_daemons_own_formatter_output() {
        use rustynetd::lab_substrate_transit::parse_attestation;
        let transit = parse_attestation(
            "version=1\noverlay_interface=rustynet-vx0\nunderlay_interface=eth0\n\
             peer=192.168.0.32\npeer=192.168.122.31\n",
        )
        .expect("daemon parses");
        let field = transit.status_field();
        assert_eq!(field, GOLDEN_ACTIVE_FIELD);
        let parsed = parse_substrate_transit_status(&real_status_line(Some(&field)))
            .expect("parse")
            .expect("active");
        assert_eq!(parsed.overlay_interface, transit.overlay_interface());
        assert_eq!(parsed.underlay_interface, transit.underlay_interface());
        assert_eq!(parsed.peers as usize, transit.peers().len());
    }

    #[test]
    fn substrate_status_absent_means_inactive_and_malformed_fails_closed() {
        assert_eq!(
            parse_substrate_transit_status("mesh_ip=10.7.0.1\nrole=anchor\n").expect("absent"),
            None
        );
        for bad in [
            "substrate_transit=lab-active overlay=rustynet-vx0 underlay=mgmt0 peers=x\n",
            "substrate_transit=lab-active overlay=rustynet-vx0 underlay=mgmt0\n",
            "substrate_transit=lab-active overlay=rustynet-vx0 underlay=mgmt0 peers=2 extra=1\n",
            "substrate_transit=lab-active overlay=rustynet-vx0 underlay=mgmt0 peers=2\n\
             substrate_transit=lab-active overlay=rustynet-vx0 underlay=mgmt0 peers=2\n",
            "substrate_transit=lab-active overlay=rustynet-vx0 underlay=mgmt0 peers=2 rogue=3\n",
        ] {
            assert!(
                parse_substrate_transit_status(bad).is_err(),
                "must reject: {bad}"
            );
        }
        // Explicit off-state with no payload reads as inactive.
        assert_eq!(
            parse_substrate_transit_status("substrate_transit=off\n").expect("off"),
            None
        );
    }

    #[test]
    fn substrate_rule_must_render_the_exact_attested_shape() {
        let (daddr, packets) =
            parse_substrate_transit_rule(&rendered_rule("192.168.64.11", 5), ATTESTED_UNDERLAY)
                .expect("exact shape parses");
        assert_eq!(daddr, "192.168.64.11");
        assert_eq!(packets, 5);
        // Wrong underlay, wrong port, non-IPv4 peer, mutated comment: all refuse.
        for bad in [
            rendered_rule("192.168.64.11", 5).replace("mgmt0", "eth0"),
            rendered_rule("192.168.64.11", 5).replace("udp dport 4789", "udp dport 4790"),
            rendered_rule("not-an-ip", 5),
            rendered_rule("192.168.64.11", 5)
                .replace(SUBSTRATE_TRANSIT_RULE_COMMENT, "some_other_comment"),
            rendered_rule("192.168.64.11", 5).replace("accept", "drop"),
        ] {
            assert!(
                parse_substrate_transit_rule(&bad, ATTESTED_UNDERLAY).is_err(),
                "must reject: {bad}"
            );
        }
    }

    #[test]
    fn ruleset_evaluation_proves_both_tables_counts_and_counters() {
        let evidence = evaluate_substrate_transit_ruleset(ATTESTED_UNDERLAY, 2, &good_ruleset())
            .expect("good ruleset passes");
        assert_eq!(evidence.rule_count, 4);
        assert_eq!(evidence.min_packets, 5);
        assert_eq!(evidence.tables, vec!["rustynet_g2", "rustynet_boot"]);

        // Boot table missing.
        let ruleset = good_ruleset();
        let no_boot = ruleset.split_once("table inet rustynet_boot").unwrap().0;
        let err = evaluate_substrate_transit_ruleset(ATTESTED_UNDERLAY, 2, no_boot)
            .expect_err("missing boot table must fail");
        assert!(err.contains("rustynet_boot"), "{err}");

        // Per-table count ≠ attested peers.
        let err = evaluate_substrate_transit_ruleset(ATTESTED_UNDERLAY, 3, &good_ruleset())
            .expect_err("count mismatch must fail");
        assert!(err.contains("peers=3"), "{err}");
    }

    #[test]
    fn ruleset_evaluation_rejects_stray_tables_and_vacuous_counters() {
        let stray = format!(
            "table inet rustynet_g2 {{\n    {}\n}}\ntable inet rustynet_boot {{\n    {}\n}}\ntable inet other {{\n    {}\n}}\n",
            rendered_rule("192.168.64.11", 5),
            rendered_rule("192.168.64.11", 5),
            rendered_rule("192.168.64.11", 5),
        );
        let err = evaluate_substrate_transit_ruleset(ATTESTED_UNDERLAY, 1, &stray)
            .expect_err("a substrate rule outside g<N>/boot must fail");
        assert!(err.contains("unexpected table `other`"), "{err}");

        // Anti-vacuity: counters present but zero → the control proved nothing.
        let vacuous = format!(
            "table inet rustynet_g2 {{\n    {}\n}}\ntable inet rustynet_boot {{\n    {}\n}}\n",
            rendered_rule("192.168.64.11", 0),
            rendered_rule("192.168.64.11", 9),
        );
        let err = evaluate_substrate_transit_ruleset(ATTESTED_UNDERLAY, 1, &vacuous)
            .expect_err("packets=0 is vacuous");
        assert!(err.contains("never exercised"), "{err}");

        // Wrong underlay on one rule poisons the table.
        let wrong = format!(
            "table inet rustynet_g2 {{\n    {}\n}}\ntable inet rustynet_boot {{\n    {}\n}}\n",
            rendered_rule("192.168.64.11", 5).replace("mgmt0", "wan0"),
            rendered_rule("192.168.64.11", 5),
        );
        let err = evaluate_substrate_transit_ruleset(ATTESTED_UNDERLAY, 1, &wrong)
            .expect_err("unattested underlay must fail");
        assert!(err.contains("does not match the attested shape"), "{err}");

        // Duplicate peers inflate the count without covering more ground.
        let dup = format!(
            "table inet rustynet_g2 {{\n    {}\n    {}\n}}\ntable inet rustynet_boot {{\n    {}\n}}\n",
            rendered_rule("192.168.64.11", 5),
            rendered_rule("192.168.64.11", 6),
            rendered_rule("192.168.64.11", 5),
        );
        let err = evaluate_substrate_transit_ruleset(ATTESTED_UNDERLAY, 2, &dup)
            .expect_err("duplicate daddrs must fail");
        assert!(err.contains("duplicate peer addresses"), "{err}");
    }

    #[test]
    fn substrate_transit_scoped_requires_declared_and_active_to_agree() {
        assert!(substrate_transit_scoped(false, None, "").is_ok());
        assert!(
            substrate_transit_scoped(true, None, "").is_err(),
            "declared but inactive must fail"
        );
        assert!(
            substrate_transit_scoped(false, active_status().as_ref(), "").is_err(),
            "active but undeclared must fail"
        );
        let ok = substrate_transit_scoped(true, active_status().as_ref(), &good_ruleset());
        assert_eq!(ok.expect("declared+active+clean").rule_count, 4);
        assert!(
            substrate_transit_scoped(
                true,
                active_status().as_ref(),
                "table inet rustynet_g2 {\n}\n"
            )
            .is_err(),
            "declared+active with no rules must fail"
        );
    }

    #[test]
    fn substrate_transit_declared_derives_from_a_provisioned_vxlan_record() {
        use crate::vm_lab::orchestrator::stage::cross_network::substrate::SubstrateRecord;
        let record = |substrate_id: &str, provisioned: bool| SubstrateRecord {
            substrate_id: substrate_id.to_owned(),
            topology_digest: "d".to_owned(),
            provisioned,
            participants: Vec::new(),
        };
        assert!(substrate_transit_declared(Some(&record("vxlan", true))));
        assert!(!substrate_transit_declared(Some(&record("vxlan", false))));
        assert!(!substrate_transit_declared(Some(&record("netns", true))));
        assert!(!substrate_transit_declared(None));
    }

    #[test]
    fn live_substrate_control_proves_the_witness_line_and_fails_closed() {
        use crate::vm_lab::orchestrator::remote_shell::MockShellHost;

        let sock_env = "RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock";
        let status_argv = [
            "sudo",
            "-n",
            "env",
            sock_env,
            "/usr/local/bin/rustynet",
            "status",
        ];
        let status_stdout = &real_status_line(Some(
            "substrate_transit=lab-active overlay=rustynet-vx0 underlay=mgmt0 peers=2",
        ));

        let mock = MockShellHost::new();
        mock.program_run_response(&status_argv, exit_ok(status_stdout));
        mock.program_run_response(
            &["sudo", "-n", "nft", "list", "ruleset"],
            exit_ok(&good_ruleset()),
        );
        let line = run_substrate_transit_control(&mock, true).expect("control passes");
        assert!(line.contains("substrate_transit=active"), "{line}");
        assert!(
            line.contains("peers=2") && line.contains("min_packets=5"),
            "{line}"
        );
        assert!(
            line.contains("rustynet_g2") && line.contains("rustynet_boot"),
            "{line}"
        );

        // Daemon status contradicts the run's declared posture → fail.
        let mock = MockShellHost::new();
        mock.program_run_response(&status_argv, exit_ok(status_stdout));
        mock.program_run_response(
            &["sudo", "-n", "nft", "list", "ruleset"],
            exit_ok(&good_ruleset()),
        );
        let err = run_substrate_transit_control(&mock, false).expect_err("undeclared+active");
        assert!(err.contains("did not declare a vxlan substrate"), "{err}");

        // Undispatchable status → fail-closed, never a pass.
        let mock = MockShellHost::new();
        let err = run_substrate_transit_control(&mock, false).expect_err("no dispatch");
        assert!(err.contains("`rustynet status` dispatch failed"), "{err}");

        // Non-zero status exit → unverifiable, fail closed.
        let mock = MockShellHost::new();
        mock.program_run_response(
            &status_argv,
            RemoteExitStatus {
                code: 1,
                stdout: Vec::new(),
                stderr: b"daemon down".to_vec(),
            },
        );
        let err = run_substrate_transit_control(&mock, true).expect_err("status failed");
        assert!(err.contains("substrate posture unverifiable"), "{err}");

        // Inactive + undeclared → pass with an inactive evidence line.
        let mock = MockShellHost::new();
        mock.program_run_response(&status_argv, exit_ok(&real_status_line(None)));
        let line = run_substrate_transit_control(&mock, false).expect("inactive pass");
        assert!(line.contains("substrate_transit=inactive"), "{line}");

        // Declared vxlan run but the REAL status shows no transit → fail
        // (the control must never pass a run whose transit is not active).
        let mock = MockShellHost::new();
        mock.program_run_response(&status_argv, exit_ok(&real_status_line(None)));
        let err = run_substrate_transit_control(&mock, true).expect_err("declared+inactive");
        assert!(err.contains("substrate_transit=lab-active"), "{err}");
    }
}
