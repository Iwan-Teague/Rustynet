#![allow(dead_code)]
use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::evidence::append_stage_evidence_line;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;
use crate::vm_lab::orchestrator::stage::{
    OrchestrationStage, StageFanout, StageId, desktop_platform_tag, resolve_ssh_user,
};
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

/// QH-83 F1: the LAN-toggle stage's pass witness. The `live_lan_toggle`
/// binary writes this report on every success path, so a Passed verdict is
/// only proven when this artifact exists and is non-empty.
pub(crate) const LAN_TOGGLE_REPORT_RELATIVE: &str = "live_lan_toggle_report.json";

/// QH-83 F1: fail a success exit whose pass witness artifact is missing or
/// empty instead of declaring Passed without evidence on disk.
fn verify_report_artifact(report_dir: &std::path::Path) -> Result<(), String> {
    let path = report_dir.join(LAN_TOGGLE_REPORT_RELATIVE);
    match std::fs::metadata(&path) {
        Ok(meta) if meta.len() > 0 => Ok(()),
        Ok(_) => Err(format!("pass witness artifact {path:?} is empty")),
        Err(err) => Err(format!("pass witness artifact {path:?} missing: {err}")),
    }
}

pub struct LiveLanToggleValidationStage;

impl OrchestrationStage for LiveLanToggleValidationStage {
    fn id(&self) -> StageId {
        StageId::LiveLanToggleValidation
    }
    fn name(&self) -> &str {
        "live_lan_toggle_validation"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::LiveEnrollmentRestartValidation]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::Once
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        if let Some(skip) = crate::vm_lab::orchestrator::stage::exit_only_topology_skip(
            ctx,
            "LAN-toggle validation",
        ) {
            return skip;
        }
        let exit_params = match ssh_params_for_role(ctx, "exit") {
            Ok(p) => p,
            Err(e) => return StageOutcome::Failed(e),
        };
        let client_params = match ssh_params_for_role(ctx, "client") {
            Ok(p) => p,
            Err(e) => return StageOutcome::Failed(e),
        };
        // The LAN-toggle scenario drives THREE nodes: exit, client, and a
        // Linux aux/extra node it promotes to the blind_exit posture
        // (the test binary requires --blind-exit-host). A 2-node topology
        // cannot exercise it — skip rather than fail-closed, matching the
        // two_hop / enrollment-restart / soak / mixed-topology
        // incomplete-topology skips.
        let blind_exit_params = match find_blind_exit(ctx) {
            Ok(p) => p,
            Err(_) => {
                return StageOutcome::Skipped(
                    "no blind_exit node is available in this topology".to_owned(),
                );
            }
        };
        let platform = match platform_for_node(ctx, &exit_params.alias) {
            Ok(tag) => tag,
            Err(reason) => return StageOutcome::Failed(reason),
        };
        let exit_node_id = node_id_for_alias(ctx, &exit_params.alias);
        let client_node_id = node_id_for_alias(ctx, &client_params.alias);
        let blind_exit_node_id = node_id_for_alias(ctx, &blind_exit_params.alias);
        let exit_target = format!("{}@{}", exit_params.user, exit_params.host);
        let client_target = format!("{}@{}", client_params.user, client_params.host);
        let blind_exit_target = format!("{}@{}", blind_exit_params.user, blind_exit_params.host);
        let identity_file = exit_params.identity_file.to_string_lossy().into_owned();
        let report_path = ctx
            .report_dir
            .join(LAN_TOGGLE_REPORT_RELATIVE)
            .to_string_lossy()
            .into_owned();
        let log_path = ctx
            .report_dir
            .join("live_lan_toggle.log")
            .to_string_lossy()
            .into_owned();

        // QH-57: fail before touching any node if the run context cannot
        // supply a usable management CIDR - the two_hop stage's precedent.
        // The binary re-validates (it is the choke point for every spawner);
        // this stage-side check just turns the error into a clean stage
        // failure with no cargo spawn.
        let ssh_allow_cidrs = match stage_ssh_allow_cidrs(&ctx.ssh_allow_cidrs) {
            Ok(value) => value,
            Err(reason) => return StageOutcome::Failed(reason),
        };

        let mut cmd = Command::new("cargo");
        cmd.args([
            "run",
            "--quiet",
            "-p",
            "rustynet-cli",
            "--features",
            "vm-lab",
            "--bin",
            "live_linux_lan_toggle_test",
            "--",
        ])
        .arg("--platform")
        .arg(platform)
        .arg("--ssh-identity-file")
        .arg(&identity_file)
        .arg("--exit-host")
        .arg(&exit_target)
        .arg("--client-host")
        .arg(&client_target)
        .arg("--blind-exit-host")
        .arg(&blind_exit_target)
        .arg("--exit-node-id")
        .arg(&exit_node_id)
        .arg("--client-node-id")
        .arg(&client_node_id)
        .arg("--blind-exit-node-id")
        .arg(&blind_exit_node_id)
        .arg("--ssh-allow-cidrs")
        .arg(&ssh_allow_cidrs)
        .arg("--report-path")
        .arg(&report_path)
        .arg("--log-path")
        .arg(&log_path);

        // `.output()` not `.status()`: `.status()` discards the binary's
        // stdout/stderr, so a failure could only ever report an exit code. That
        // is what produced "exited with exit status: 1" beside a 0-byte log, with
        // the actual reason unrecoverable from the run's own evidence.
        match cmd.output() {
            Ok(output) if output.status.success() => {
                if let Err(e) = verify_report_artifact(&ctx.report_dir) {
                    return StageOutcome::Failed(e);
                }
                // Review finding 4 (blind-exit candidate, 2026-10-03): the
                // binary's own exit code is not the postcondition. The
                // scenario's cleanup restores interfaces and DNS but NOT the
                // promoted node's role, so a node left permanently
                // fail-closed (katana-u37) used to pass here and poison
                // every later stage. Verify the whole mesh is healthy
                // before declaring Passed.
                if let Err(e) =
                    verify_mesh_postcondition(ctx, &blind_exit_params.alias, self.name())
                {
                    return StageOutcome::Failed(format!(
                        "postcondition violated after LAN toggle: {e}"
                    ));
                }
                // xnet-186: the postcondition PROVED the daemon holds the
                // promoted blind_exit role; reconcile the orchestrator's
                // static role snapshot so every later stage that mints
                // capabilities from ctx.assignments (refresh_signed_bundles
                // et al) sees the role the node actually holds. A snapshot
                // that cannot legally hold this promotion fails the stage
                // closed instead of minting a mismatched bundle later.
                match reconcile_promoted_role_snapshot(
                    &mut ctx.assignments,
                    &blind_exit_params.alias,
                ) {
                    Ok(previous_role) => {
                        // Best-effort pointer line; the reconcile itself
                        // already succeeded.
                        let _ = append_stage_evidence_line(
                            &ctx.report_dir,
                            self.name(),
                            &format!(
                                "role_snapshot_reconciled alias={} from={} to={}",
                                blind_exit_params.alias, previous_role, PROMOTED_BLIND_EXIT_ROLE
                            ),
                        );
                    }
                    Err(e) => return StageOutcome::Failed(e),
                }
                StageOutcome::Passed
            }
            Ok(output) => StageOutcome::Failed(
                // QH-09: name the binary's own complete log (--log-path above)
                // so the clip disclosure cannot read as evidence loss when the
                // unclipped output sits beside it.
                crate::vm_lab::orchestrator::stage::format_stage_binary_failure_with_log(
                    "live_linux_lan_toggle_test",
                    output.status,
                    &output.stdout,
                    &output.stderr,
                    Some(&log_path),
                ),
            ),
            Err(e) => {
                StageOutcome::Failed(format!("failed to run live_linux_lan_toggle_test: {e}"))
            }
        }
    }
}

/// QH-57: the run's management CIDRs, validated for the two lethal shapes
/// before any node is touched. Empty means the orchestrator could not derive
/// them; a default-route entry cannot scope the full-tunnel management
/// bypass. Kept as its own function so the rejection is unit-testable.
fn stage_ssh_allow_cidrs(ctx_value: &str) -> Result<String, String> {
    let value = ctx_value.trim();
    if value.is_empty() {
        return Err(
            "lan-toggle requires the run's management CIDRs (ctx.ssh_allow_cidrs \
             is empty); refusing to fall back to a stale default (QH-57)"
                .to_owned(),
        );
    }
    for entry in value.split(',') {
        let entry = entry.trim();
        if entry == "0.0.0.0/0" || entry == "::/0" {
            return Err(format!(
                "lan-toggle refuses management CIDR entry {entry}: a default \
                 route cannot scope the full-tunnel management bypass (QH-57)"
            ));
        }
    }
    Ok(value.to_owned())
}

struct ResolvedParams {
    alias: String,
    host: String,
    user: String,
    identity_file: PathBuf,
}

fn alias_matching_label(ctx: &OrchestrationContext, label: &str) -> Result<ResolvedParams, String> {
    let assignment = ctx
        .assignments
        .iter()
        .find(|a| a.role.as_str() == label)
        .ok_or_else(|| format!("no node assigned to label {label}"))?;
    let adapter = ctx
        .adapters
        .get(assignment.alias.as_str())
        .ok_or_else(|| format!("no adapter for {}", assignment.alias))?;
    let params = adapter
        .ssh_connection_params()
        .ok_or_else(|| format!("no SSH params for {}", assignment.alias))?;
    let user = resolve_ssh_user(params.user.as_deref(), adapter.platform());
    Ok(ResolvedParams {
        alias: assignment.alias.clone(),
        host: params.host.clone(),
        user,
        identity_file: params.identity_file.clone(),
    })
}

fn ssh_params_for_role(ctx: &OrchestrationContext, label: &str) -> Result<ResolvedParams, String> {
    alias_matching_label(ctx, label)
}

/// xnet-186 root-cause fix: the LAN-toggle scenario legitimately promotes its
/// chosen aux/extra node to the `blind_exit` daemon role, but the
/// orchestrator's `ctx.assignments` snapshot kept the static `aux` role.
/// Every later stage that mints bundle capabilities from that snapshot —
/// notably `refresh_signed_bundles` via `build_bundle_env` — then shipped
/// `client`-only capabilities to a node the daemon had already promoted to
/// `blind_exit`, and rustynetd's
/// `validate_auto_tunnel_role_membership_alignment` fail-closed the node
/// PERMANENTLY (the refresh swap's health gate timed out with
/// `restricted_safe_mode=true`).
///
/// Reconcile the snapshot to the role the postcondition just PROVED live.
/// Only an `aux`/`extra` snapshot may promote (the scenario's own contract —
/// see [`BLIND_EXIT_CANDIDATE_LABELS`]); a snapshot in any other role means
/// the harness disagrees with itself, so the stage fails closed instead of
/// papering over it. A snapshot already carrying `blind_exit` is a no-op
/// (idempotent). Every other assignment is left untouched.
///
/// `pub(crate)` so the refresh stage's tests can pin the full xnet-186 loop
/// (reconcile → mint → capability CSV).
pub(crate) fn reconcile_promoted_role_snapshot(
    assignments: &mut [NodeRoleAssignment],
    alias: &str,
) -> Result<String, String> {
    let assignment = assignments
        .iter_mut()
        .find(|a| a.alias == alias)
        .ok_or_else(|| {
            format!("role snapshot reconcile: no assignment for promoted node {alias}")
        })?;
    match assignment.role {
        NodeRole::BlindExit => Ok(NodeRole::BlindExit.as_str().to_owned()),
        NodeRole::Aux | NodeRole::Extra => {
            let previous = assignment.role.as_str().to_owned();
            assignment.role = NodeRole::BlindExit;
            Ok(previous)
        }
        ref other => Err(format!(
            "role snapshot reconcile for {alias}: snapshot role {} is neither aux \
             nor extra; refusing to reconcile it to {}",
            other.as_str(),
            PROMOTED_BLIND_EXIT_ROLE
        )),
    }
}

/// LAN-toggle promotes its third node to the `blind_exit` daemon role. An
/// `entry`-role node must never be picked: entry memberships are minted from
/// the admin-owner capability set (which carries `anchor`), and rustynetd
/// hard-rejects a `blind_exit` role whose membership carries `anchor`,
/// permanently fail-closing the node mid-run. That silently removes the
/// exit's entry peer and fails every later handshake-liveness stage
/// (katana-u37-anchor-b78). Aux/extra nodes carry client-only memberships
/// and promote cleanly via the blind_exit warn-and-continue path.
const BLIND_EXIT_CANDIDATE_LABELS: &[&str] = &["aux", "extra"];

fn find_blind_exit(ctx: &OrchestrationContext) -> Result<ResolvedParams, String> {
    for label in BLIND_EXIT_CANDIDATE_LABELS {
        let assignment = ctx.assignments.iter().find(|a| a.role.as_str() == *label);
        if let Some(assignment) = assignment {
            let adapter = ctx
                .adapters
                .get(assignment.alias.as_str())
                .ok_or_else(|| format!("no adapter for {}", assignment.alias))?;
            if adapter.platform() == VmGuestPlatform::Linux {
                let params = adapter
                    .ssh_connection_params()
                    .ok_or_else(|| format!("no SSH params for {}", assignment.alias))?;
                return Ok(ResolvedParams {
                    alias: assignment.alias.clone(),
                    host: params.host.clone(),
                    user: resolve_ssh_user(params.user.as_deref(), adapter.platform()),
                    identity_file: params.identity_file.clone(),
                });
            }
        }
    }
    Err("no Linux node found for blind_exit role among aux/extra".to_owned())
}

/// The platform label fed to the validation binary's `--platform` argv
/// (audit I3): desktop platforms tag through the shared exhaustive
/// [`desktop_platform_tag`]; a missing adapter or a never-hosted platform is
/// an `Err` the caller must fail the stage on — never a silent `linux` stamp.
fn platform_for_node(ctx: &OrchestrationContext, alias: &str) -> Result<&'static str, String> {
    let adapter = ctx
        .adapters
        .get(alias)
        .ok_or_else(|| format!("{alias}: no adapter for platform labelling"))?;
    desktop_platform_tag(adapter.platform(), "lan-toggle validation")
}

fn node_id_for_alias(ctx: &OrchestrationContext, alias: &str) -> String {
    ctx.node_ids
        .get(alias)
        .cloned()
        .unwrap_or_else(|| alias.to_owned())
}

/// Postcondition poll (review finding 4): after the toggle and its cleanup,
/// every mesh member must be reachable and healthy. The daemon may need a
/// few reconcile cycles to settle after the role promotion, so poll across
/// the same deadline the mesh-status stage uses for live handshakes.
const POSTCONDITION_DEADLINE: Duration = Duration::from_secs(120);
const POSTCONDITION_POLL_INTERVAL: Duration = Duration::from_secs(10);

/// The role the LAN-toggle scenario intends for the promoted node
/// (`live_linux_lan_toggle_test` enforces the blind-exit host into the
/// `blind_exit` daemon role); the postcondition requires the promoted node
/// to still hold it after cleanup.
const PROMOTED_BLIND_EXIT_ROLE: &str = "blind_exit";

/// Single evidence lines are capped (the chaos binary's precedent) so a
/// pathological daemon status cannot flood the stage log.
const POSTCONDITION_EVIDENCE_CAP: usize = 8192;

/// One field of a `rustynet status` single line. The real daemon prints
/// `bootstrap_error` UNQUOTED (katana-u37: `bootstrap_error=membership role
/// mismatch: ...`), so an unquoted value yields only its first token here
/// (`membership`), which is enough to differ from `none` and fail the stage;
/// the full reason is in the lan-toggle binary's own report snapshot. A value
/// that starts with a double quote is re-joined across whitespace as a
/// defensive measure (the daemon does not emit that shape today); an
/// unterminated quote keeps what was captured (still failing closed
/// downstream, since it can never equal `none`).
fn parse_status_field(status_line: &str, key: &str) -> Option<String> {
    let mut tokens = status_line.split_whitespace();
    while let Some(token) = tokens.next() {
        let Some((field, value)) = token.split_once('=') else {
            continue;
        };
        if field != key {
            continue;
        }
        if !value.starts_with('"') {
            return Some(value.to_owned());
        }
        let mut quoted = value[1..].to_owned();
        while !quoted.ends_with('"') {
            match tokens.next() {
                // Quote continuation tokens carry no `=` (e.g. `failure`
                // in `bootstrap_error="reconcile failure ..."`), so the
                // RAW token is appended, not a split field/value.
                Some(next_token) => {
                    quoted.push(' ');
                    quoted.push_str(next_token);
                }
                None => break,
            }
        }
        if quoted.ends_with('"') {
            quoted.pop();
        }
        return Some(quoted);
    }
    None
}

/// Cap a status-derived value embedded in a violation/evidence string.
fn cap_status_field(value: &str) -> String {
    const FIELD_CAP: usize = 200;
    if value.len() <= FIELD_CAP {
        value.to_owned()
    } else {
        let mut cut = FIELD_CAP;
        while !value.is_char_boundary(cut) {
            cut -= 1;
        }
        format!("{}…", &value[..cut])
    }
}

/// Replace line breaks and cap the length so the result is always a legal
/// single evidence line (append_stage_evidence_line refuses newlines).
fn sanitize_status_text(text: &str) -> String {
    let single_line = text.replace(['\n', '\r'], " ");
    if single_line.len() <= POSTCONDITION_EVIDENCE_CAP {
        single_line
    } else {
        let mut cut = POSTCONDITION_EVIDENCE_CAP;
        while !single_line.is_char_boundary(cut) {
            cut -= 1;
        }
        single_line[..cut].to_owned()
    }
}

/// What one node looked like when its daemon status was evaluated, plus the
/// reasons it failed the postcondition (empty when healthy). Fields carry
/// `<missing>`/`<unavailable>` placeholders when the status could not be
/// parsed, so the evidence line still names the node's observed state.
#[derive(Debug)]
struct PostconditionObservation {
    alias: String,
    state: String,
    node_role: String,
    restriction_mode: String,
    violations: Vec<String>,
}

/// Evaluate ONE node's daemon status line against the LAN-toggle
/// postcondition. Fail-closed shapes: an empty/whitespace status, any
/// required field missing, `restricted_safe_mode` not exactly `false`,
/// `bootstrap_error` not exactly `none`, a `FailClosed` state, and — for
/// the promoted node — a missing or wrong `node_role`.
fn evaluate_postcondition_status(
    alias: &str,
    status_line: &str,
    expected_role: Option<&str>,
) -> PostconditionObservation {
    let mut violations = Vec::new();
    if status_line.trim().is_empty() {
        violations.push("daemon status line is empty".to_owned());
        return PostconditionObservation {
            alias: alias.to_owned(),
            state: "<unavailable>".to_owned(),
            node_role: "<unavailable>".to_owned(),
            restriction_mode: "<unavailable>".to_owned(),
            violations,
        };
    }
    let state = parse_status_field(status_line, "state");
    let node_role = parse_status_field(status_line, "node_role");
    let restriction_mode = parse_status_field(status_line, "restriction_mode");
    let restricted = parse_status_field(status_line, "restricted_safe_mode");
    let bootstrap_error = parse_status_field(status_line, "bootstrap_error");

    match &restricted {
        None => violations.push("restricted_safe_mode missing from daemon status".to_owned()),
        Some(value) if value == "false" => {}
        Some(value) => violations.push(format!(
            "restricted_safe_mode={} (must be false)",
            cap_status_field(value)
        )),
    }
    match &bootstrap_error {
        None => violations.push("bootstrap_error missing from daemon status".to_owned()),
        Some(value) if value == "none" => {}
        Some(value) => violations.push(format!(
            "bootstrap_error={} (must be none)",
            cap_status_field(value)
        )),
    }
    if let Some(value) = &state {
        if value == "FailClosed" {
            violations.push("state=FailClosed".to_owned());
        }
    } else {
        violations.push("state missing from daemon status".to_owned());
    }
    if let Some(role) = expected_role {
        match &node_role {
            None => violations.push(format!(
                "node_role missing from daemon status (expected {role})"
            )),
            Some(value) if value != role => violations.push(format!(
                "node_role={} (expected {role}: the promoted node must keep the blind-exit role)",
                cap_status_field(value)
            )),
            Some(_) => {}
        }
    }
    PostconditionObservation {
        alias: alias.to_owned(),
        state: state.map_or_else(|| "<missing>".to_owned(), |value| cap_status_field(&value)),
        node_role: node_role
            .map_or_else(|| "<missing>".to_owned(), |value| cap_status_field(&value)),
        restriction_mode: restriction_mode
            .map_or_else(|| "<missing>".to_owned(), |value| cap_status_field(&value)),
        violations,
    }
}

/// One node's collected daemon status for a sweep; `Err` is a collection
/// failure (unreachable node, unsupported platform, no adapter) and counts
/// as a violation rather than being skipped.
#[derive(Debug)]
struct PostconditionSample {
    alias: String,
    collected: Result<String, String>,
}

/// Why a sweep failed: every violation (collection failures included),
/// plus the per-node observations so the caller can record what each node
/// actually looked like in the stage log.
#[derive(Debug)]
struct PostconditionSweepFailure {
    observations: Vec<PostconditionObservation>,
    failures: Vec<String>,
}

/// Evaluate every node of the run. Collection failures and status
/// violations are ALL reported (never first-fail), each naming its node.
/// `Ok` only when every node passed.
fn postcondition_sweep(
    samples: &[PostconditionSample],
    promoted_alias: &str,
) -> Result<Vec<PostconditionObservation>, PostconditionSweepFailure> {
    let mut observations = Vec::new();
    let mut failures = Vec::new();
    for sample in samples {
        match &sample.collected {
            Ok(status) => {
                let expected_role =
                    (sample.alias == promoted_alias).then_some(PROMOTED_BLIND_EXIT_ROLE);
                let observation =
                    evaluate_postcondition_status(&sample.alias, status, expected_role);
                failures.extend(
                    observation
                        .violations
                        .iter()
                        .map(|violation| format!("{}: {violation}", sample.alias)),
                );
                observations.push(observation);
            }
            Err(err) => failures.push(format!(
                "{}: daemon status could not be collected: {}",
                sample.alias,
                cap_status_field(err)
            )),
        }
    }
    if failures.is_empty() {
        Ok(observations)
    } else {
        Err(PostconditionSweepFailure {
            observations,
            failures,
        })
    }
}

/// One JSON evidence line per node per sweep: check name, alias, observed
/// state, and any violations. Always a single line (sanitized) so the
/// stage log stays line-oriented.
fn postcondition_evidence_line(observation: &PostconditionObservation) -> String {
    let payload = serde_json::json!({
        "check": "lan_toggle_postcondition",
        "alias": observation.alias,
        "healthy": observation.violations.is_empty(),
        "state": observation.state,
        "node_role": observation.node_role,
        "restriction_mode": observation.restriction_mode,
        "violations": observation.violations,
    });
    sanitize_status_text(&payload.to_string())
}

/// Poll every node's daemon status until the whole mesh passes the
/// postcondition or the deadline expires; a poll that never passes fails
/// the stage with every node's last violations (fail-closed, the
/// `poll_live_handshake` precedent). Each node's observed state is recorded
/// in the stage log on every sweep, pass or fail.
fn verify_mesh_postcondition(
    ctx: &OrchestrationContext,
    promoted_alias: &str,
    stage_name: &str,
) -> Result<(), String> {
    let mut aliases: Vec<&str> = Vec::new();
    for assignment in &ctx.assignments {
        if !aliases.contains(&assignment.alias.as_str()) {
            aliases.push(assignment.alias.as_str());
        }
    }
    let deadline = Instant::now() + POSTCONDITION_DEADLINE;
    loop {
        let mut samples = Vec::new();
        for alias in &aliases {
            let collected = match ctx.adapters.get(*alias) {
                Some(adapter) => adapter.collect_daemon_status().map_err(|e| e.to_string()),
                None => Err("no adapter for node".to_owned()),
            };
            samples.push(PostconditionSample {
                alias: (*alias).to_owned(),
                collected,
            });
        }
        let (observations, failures) = match postcondition_sweep(&samples, promoted_alias) {
            Ok(observations) => (observations, Vec::new()),
            Err(sweep_failure) => (sweep_failure.observations, sweep_failure.failures),
        };
        for observation in &observations {
            let line = postcondition_evidence_line(observation);
            append_stage_evidence_line(&ctx.report_dir, stage_name, &line)
                .map_err(|e| format!("postcondition evidence could not be recorded: {e}"))?;
        }
        if failures.is_empty() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "{} (after {}s)",
                failures.join("; "),
                POSTCONDITION_DEADLINE.as_secs()
            ));
        }
        std::thread::sleep(POSTCONDITION_POLL_INTERVAL);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn stage_ssh_allow_cidrs_fails_closed_on_empty_and_default_route() {
        assert!(super::stage_ssh_allow_cidrs("").is_err());
        assert!(super::stage_ssh_allow_cidrs("  ").is_err());
        assert!(super::stage_ssh_allow_cidrs("0.0.0.0/0").is_err());
        assert!(super::stage_ssh_allow_cidrs("192.168.64.0/24,::/0").is_err());
        assert_eq!(
            super::stage_ssh_allow_cidrs(" 192.168.64.0/24 ").as_deref(),
            Ok("192.168.64.0/24")
        );
    }

    use super::*;

    #[test]
    fn stage_id_is_live_lan_toggle() {
        assert_eq!(
            LiveLanToggleValidationStage.id(),
            StageId::LiveLanToggleValidation
        );
    }

    #[test]
    fn stage_name_is_lowercase_kebab() {
        assert_eq!(
            LiveLanToggleValidationStage.name(),
            "live_lan_toggle_validation"
        );
    }

    #[test]
    fn depends_on_live_enrollment_restart() {
        assert_eq!(
            LiveLanToggleValidationStage.dependencies(),
            &[StageId::LiveEnrollmentRestartValidation]
        );
    }

    #[test]
    fn fanout_is_once() {
        assert_eq!(LiveLanToggleValidationStage.fanout(), StageFanout::Once);
    }

    /// The regression this stage actually died on: a Fedora guest reached over
    /// SSH as `debian`. The inventory carries the right username; the resolver
    /// must use it rather than a per-platform guess.
    #[test]
    fn inventory_username_wins_over_the_platform_default() {
        assert_eq!(
            resolve_ssh_user(Some("fedora"), VmGuestPlatform::Linux),
            "fedora"
        );
        assert_eq!(
            resolve_ssh_user(Some("rocky"), VmGuestPlatform::Linux),
            "rocky"
        );
        assert_eq!(
            resolve_ssh_user(Some("ubuntu"), VmGuestPlatform::Linux),
            "ubuntu"
        );
        // A Windows guest with an explicit username is not overridden either.
        assert_eq!(
            resolve_ssh_user(Some("labadmin"), VmGuestPlatform::Windows),
            "labadmin"
        );
    }

    /// Absent or blank inventory data falls back to the previous hardcoded
    /// values, so this fix cannot regress a topology that relied on them.
    #[test]
    fn missing_or_blank_username_falls_back_to_the_platform_default() {
        assert_eq!(resolve_ssh_user(None, VmGuestPlatform::Linux), "debian");
        assert_eq!(resolve_ssh_user(None, VmGuestPlatform::Windows), "admin");
        // Whitespace-only is treated as absent, not dialled as an empty user.
        assert_eq!(
            resolve_ssh_user(Some("   "), VmGuestPlatform::Linux),
            "debian"
        );
        assert_eq!(
            resolve_ssh_user(Some(""), VmGuestPlatform::Windows),
            "admin"
        );
    }

    /// Surrounding whitespace in an inventory value must not reach the SSH
    /// target string, where it would produce `" fedora"@host`.
    #[test]
    fn inventory_username_is_trimmed() {
        assert_eq!(
            resolve_ssh_user(Some("  fedora \n"), VmGuestPlatform::Linux),
            "fedora"
        );
    }

    #[test]
    fn live_lan_toggle_declared_witness_matches_its_artifact_path() {
        use crate::vm_lab::orchestrator::stage::StageEvidence;

        assert_eq!(
            StageId::LiveLanToggleValidation.evidence(),
            StageEvidence::File(LAN_TOGGLE_REPORT_RELATIVE),
            "the catalog must declare the LAN-toggle report as the pass witness"
        );
    }

    #[test]
    fn live_lan_toggle_pass_without_report_artifact_is_fatal() {
        let dir = std::env::temp_dir().join(format!(
            "lan_toggle_witness_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap_or_default();
        let result = verify_report_artifact(&dir);
        assert!(result.is_err(), "an empty report dir must not pass");
        assert!(
            result.unwrap_err().contains(LAN_TOGGLE_REPORT_RELATIVE),
            "the failure must name the missing witness artifact"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Regression guard for katana-u37-anchor-b78: the entry lab role carries
    /// an admin-owner (anchor-capable) membership, which blind_exit can never
    /// lawfully hold, so the entry node must not be a promotion candidate.
    #[test]
    fn blind_exit_candidates_exclude_entry_role_nodes() {
        assert!(!super::BLIND_EXIT_CANDIDATE_LABELS.contains(&"entry"));
    }

    fn status_line(
        state: &str,
        node_role: &str,
        restricted_safe_mode: &str,
        restriction_mode: &str,
        bootstrap_error: &str,
    ) -> String {
        format!(
            "node_id=n-{node_role} node_role={node_role} state={state} generation=7 \
             restricted_safe_mode={restricted_safe_mode} restriction_mode={restriction_mode} \
             bootstrap_error={bootstrap_error} path_live_peer_count=2 now_unix=1759500000"
        )
    }

    fn healthy_status(node_role: &str) -> String {
        status_line("Active", node_role, "false", "None", "none")
    }

    fn sample(alias: &str, collected: Result<String, String>) -> super::PostconditionSample {
        super::PostconditionSample {
            alias: alias.to_owned(),
            collected,
        }
    }

    #[test]
    fn parse_status_field_reads_bare_quoted_and_absent_values() {
        let line = status_line("Active", "exit", "false", "None", "none");
        assert_eq!(
            super::parse_status_field(&line, "state").as_deref(),
            Some("Active")
        );
        assert_eq!(
            super::parse_status_field(&line, "bootstrap_error").as_deref(),
            Some("none")
        );
        assert!(super::parse_status_field(&line, "no_such_field").is_none());
        // A quoted multi-word value re-joins instead of truncating at the
        // first space. Defensive only: the real daemon prints bootstrap_error
        // unquoted (see the doc comment), so this shape is synthetic.
        let quoted = status_line(
            "FailClosed",
            "entry",
            "true",
            "Permanent",
            "\"reconcile failure threshold exceeded: 102\"",
        );
        assert_eq!(
            super::parse_status_field(&quoted, "bootstrap_error").as_deref(),
            Some("reconcile failure threshold exceeded: 102")
        );
    }

    /// The intended postoutcome: promoted node keeps blind_exit, everyone
    /// healthy — the sweep must pass.
    #[test]
    fn healthy_mesh_passes_the_postcondition_sweep() {
        let samples = vec![
            sample("exit-node", Ok(healthy_status("exit"))),
            sample("client-node", Ok(healthy_status("client"))),
            sample("aux-node", Ok(healthy_status("blind_exit"))),
        ];
        let observations =
            super::postcondition_sweep(&samples, "aux-node").expect("healthy mesh must pass");
        assert_eq!(observations.len(), 3);
        assert!(observations.iter().all(|o| o.violations.is_empty()));
        assert_eq!(observations[2].node_role, "blind_exit");
    }

    /// The katana-u37 witness: a bystander left permanently fail-closed
    /// (restricted, Permanent restriction, bootstrap error, FailClosed) must
    /// FAIL the stage and the failure must name the poisoned node.
    #[test]
    fn permanently_restricted_bystander_fails_the_stage_naming_the_node() {
        let poisoned = status_line(
            "FailClosed",
            "entry",
            "true",
            "Permanent",
            "\"reconcile failure threshold exceeded: 102\"",
        );
        let samples = vec![
            sample("exit-node", Ok(healthy_status("blind_exit"))),
            sample("entry-node", Ok(poisoned)),
        ];
        let failure = super::postcondition_sweep(&samples, "exit-node")
            .expect_err("a permanently restricted bystander must fail the stage");
        assert_eq!(failure.failures.len(), 3, "every violation reported");
        assert!(
            failure
                .failures
                .iter()
                .all(|f| f.starts_with("entry-node: ")),
            "each violation must name the poisoned node: {:?}",
            failure.failures
        );
        assert!(
            failure
                .failures
                .iter()
                .any(|f| f.contains("restricted_safe_mode=true")),
            "{:?}",
            failure.failures
        );
        assert!(
            failure
                .failures
                .iter()
                .any(|f| f.contains("reconcile failure threshold exceeded")),
            "the bootstrap error text must survive into the failure: {:?}",
            failure.failures
        );
    }

    #[test]
    fn empty_status_fails_closed() {
        let observation = super::evaluate_postcondition_status("n1", "   ", None);
        assert!(!observation.violations.is_empty());
        assert_eq!(observation.state, "<unavailable>");
        let failure = super::postcondition_sweep(&[sample("n1", Ok("   ".to_owned()))], "n1")
            .expect_err("an empty status must fail the stage");
        assert!(failure.failures.iter().any(|f| f.contains("empty")));
    }

    #[test]
    fn malformed_status_missing_required_fields_fails_closed() {
        // state and restricted_safe_mode missing entirely.
        let samples = vec![sample(
            "n1",
            Ok("node_id=n-1 node_role=entry bootstrap_error=none".to_owned()),
        )];
        let failure = super::postcondition_sweep(&samples, "n1")
            .expect_err("a status missing required fields must fail the stage");
        assert!(
            failure.failures.iter().any(|f| f.contains("state missing")),
            "{:?}",
            failure.failures
        );
        assert!(
            failure
                .failures
                .iter()
                .any(|f| f.contains("restricted_safe_mode missing")),
            "{:?}",
            failure.failures
        );
    }

    /// The promoted node lost its blind_exit role during cleanup (or was
    /// never promoted): the stage must fail even though the node itself is
    /// healthy.
    #[test]
    fn promoted_node_losing_the_blind_exit_role_fails_the_stage() {
        let samples = vec![sample("aux-node", Ok(healthy_status("entry")))];
        let failure = super::postcondition_sweep(&samples, "aux-node")
            .expect_err("the promoted node must keep the blind_exit role");
        assert!(
            failure
                .failures
                .iter()
                .any(|f| f.contains("node_role=entry") && f.contains("blind_exit")),
            "{:?}",
            failure.failures
        );
    }

    #[test]
    fn unparseable_restricted_safe_mode_fails_closed() {
        let samples = vec![sample(
            "n1",
            Ok(status_line("Active", "client", "yes", "None", "none")),
        )];
        let failure = super::postcondition_sweep(&samples, "n1")
            .expect_err("restricted_safe_mode must be exactly false");
        assert!(
            failure
                .failures
                .iter()
                .any(|f| f.contains("restricted_safe_mode=yes")),
            "{:?}",
            failure.failures
        );
    }

    #[test]
    fn sweep_reports_every_failing_node_not_just_the_first() {
        let samples = vec![
            sample("bad-a", Ok("   ".to_owned())),
            sample(
                "bad-b",
                Ok(status_line(
                    "FailClosed",
                    "entry",
                    "true",
                    "Permanent",
                    "boom",
                )),
            ),
            sample("good", Ok(healthy_status("blind_exit"))),
        ];
        let failure = super::postcondition_sweep(&samples, "good")
            .expect_err("both failing nodes must be reported");
        assert!(
            failure.failures.iter().any(|f| f.starts_with("bad-a: ")),
            "{:?}",
            failure.failures
        );
        assert!(
            failure.failures.iter().any(|f| f.starts_with("bad-b: ")),
            "{:?}",
            failure.failures
        );
        assert!(
            !failure.failures.iter().any(|f| f.starts_with("good")),
            "a healthy node must not appear in the failures: {:?}",
            failure.failures
        );
    }

    /// A node whose daemon status cannot be collected at all (unreachable,
    /// unsupported platform) counts as a violation — never skipped.
    #[test]
    fn collection_failure_counts_as_a_violation() {
        let failure = super::postcondition_sweep(
            &[sample(
                "dark-node",
                Err("ssh: connection refused".to_owned()),
            )],
            "dark-node",
        )
        .expect_err("an uncollectable status must fail the stage");
        assert!(
            failure
                .failures
                .iter()
                .any(|f| f.contains("dark-node") && f.contains("connection refused")),
            "{:?}",
            failure.failures
        );
        assert!(failure.observations.is_empty());
    }
    /// Evidence lines must be single lines and bounded: whatever a status
    /// carries (newlines, megabytes of junk) cannot forge extra log lines
    /// or flood the stage log.
    #[test]
    fn evidence_line_is_single_line_and_capped() {
        let observation = super::PostconditionObservation {
            alias: "n1".to_owned(),
            state: "FailClosed".to_owned(),
            node_role: "entry".to_owned(),
            restriction_mode: "Permanent".to_owned(),
            violations: vec![format!(
                "bootstrap_error={} evil\nline\rbreak",
                "x".repeat(super::POSTCONDITION_EVIDENCE_CAP * 2)
            )],
        };
        let line = super::postcondition_evidence_line(&observation);
        assert!(!line.contains('\n'), "no raw newline may survive");
        assert!(!line.contains('\r'), "no raw CR may survive");
        assert!(
            line.len() <= super::POSTCONDITION_EVIDENCE_CAP,
            "line len {} exceeds the cap",
            line.len()
        );
        assert!(line.contains("\"alias\":\"n1\""));
        assert!(line.contains("\"healthy\":false"));
        assert!(line.contains("FailClosed"));
    }

    // ── xnet-186: role-snapshot reconcile ─────────────────────────────

    use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment as TestNodeRoleAssignment;

    fn snap_assignment(alias: &str, role: NodeRole) -> TestNodeRoleAssignment {
        TestNodeRoleAssignment {
            alias: alias.to_owned(),
            role,
        }
    }

    /// The xnet-186 fix itself: an aux snapshot promotes to blind_exit and
    /// every other assignment stays exactly as it was.
    #[test]
    fn reconcile_promotes_aux_snapshot_and_leaves_other_entries_untouched() {
        let mut assignments = vec![
            snap_assignment("exit-1", NodeRole::Exit),
            snap_assignment("aux-1", NodeRole::Aux),
            snap_assignment("client-1", NodeRole::Client),
        ];
        let previous = super::reconcile_promoted_role_snapshot(&mut assignments, "aux-1")
            .expect("an aux snapshot must promote");
        assert_eq!(previous, "aux");
        assert_eq!(
            assignments
                .iter()
                .find(|a| a.alias == "aux-1")
                .unwrap()
                .role,
            NodeRole::BlindExit
        );
        assert_eq!(
            assignments
                .iter()
                .find(|a| a.alias == "exit-1")
                .unwrap()
                .role,
            NodeRole::Exit
        );
        assert_eq!(
            assignments
                .iter()
                .find(|a| a.alias == "client-1")
                .unwrap()
                .role,
            NodeRole::Client
        );
    }

    /// `extra` is the scenario's second candidate label (see
    /// BLIND_EXIT_CANDIDATE_LABELS) and must promote the same way.
    #[test]
    fn reconcile_promotes_extra_snapshot_too() {
        let mut assignments = vec![snap_assignment("extra-1", NodeRole::Extra)];
        let previous = super::reconcile_promoted_role_snapshot(&mut assignments, "extra-1")
            .expect("an extra snapshot must promote");
        assert_eq!(previous, "extra");
        assert_eq!(assignments[0].role, NodeRole::BlindExit);
    }

    /// The snapshot contract: only aux/extra may promote. A snapshot in any
    /// other role means the harness disagrees with itself — the stage must
    /// fail CLOSED (never silently mint capabilities for a role the snapshot
    /// forbids), and the offending entry must stay untouched.
    #[test]
    fn reconcile_rejects_non_aux_extra_snapshots_fail_closed() {
        for role in [
            NodeRole::Client,
            NodeRole::Exit,
            NodeRole::Entry,
            NodeRole::Relay,
        ] {
            let mut assignments = vec![snap_assignment("n1", role.clone())];
            let err = super::reconcile_promoted_role_snapshot(&mut assignments, "n1")
                .expect_err("a non-aux/extra snapshot must fail the stage closed");
            assert!(
                err.contains(&format!("snapshot role {}", role.as_str())),
                "the rejection must name the snapshot role: {err}"
            );
            assert_eq!(
                assignments[0].role, role,
                "a rejected reconcile must leave the snapshot untouched"
            );
        }
    }

    /// Idempotence: a snapshot already carrying blind_exit reconciles as a
    /// no-op success (the live role was still re-proven by the postcondition
    /// before this runs).
    #[test]
    fn reconcile_is_a_noop_when_the_snapshot_already_holds_blind_exit() {
        let mut assignments = vec![snap_assignment("aux-1", NodeRole::BlindExit)];
        let previous = super::reconcile_promoted_role_snapshot(&mut assignments, "aux-1")
            .expect("an already-reconciled snapshot is a success");
        assert_eq!(previous, "blind_exit");
        assert_eq!(assignments[0].role, NodeRole::BlindExit);
    }

    /// A promoted alias with no snapshot entry is a harness bug: fail closed
    /// naming the alias, never silently succeed.
    #[test]
    fn reconcile_names_a_missing_alias() {
        let mut assignments = vec![snap_assignment("other", NodeRole::Aux)];
        let err = super::reconcile_promoted_role_snapshot(&mut assignments, "aux-1")
            .expect_err("a missing snapshot entry must fail the stage closed");
        assert!(err.contains("aux-1"), "{err}");
    }

    /// Pin: the reconcile runs ONLY on the success path, AFTER the mesh
    /// postcondition proved the live blind_exit role and BEFORE the stage
    /// declares Passed. Reconciling without proof would mint capabilities
    /// for a role the node does not hold (the exact inverse of xnet-186).
    #[test]
    fn snapshot_reconcile_follows_the_postcondition_and_precedes_passed() {
        let source = crate::vm_lab::implementation_source_slice(include_str!(
            "live_lan_toggle_validation.rs"
        ))
        .expect("live_lan_toggle_validation.rs implementation slice must parse");
        let execute_start = source
            .find("fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {")
            .expect("execute() must exist");
        let execute_body = &source[execute_start..];
        let postcondition = execute_body
            .find("verify_mesh_postcondition(ctx, &blind_exit_params.alias")
            .expect("the postcondition call must exist");
        let reconcile = execute_body
            .find("reconcile_promoted_role_snapshot(\n                    &mut ctx.assignments")
            .expect("the snapshot reconcile call must exist");
        let passed = execute_body
            .find("StageOutcome::Passed")
            .expect("the Passed arm must exist");
        assert!(
            postcondition < reconcile && reconcile < passed,
            "the snapshot reconcile must follow the postcondition ({postcondition}) and \
             precede Passed ({passed}); found at {reconcile}"
        );
        // Review R2 (glm-review-xnet-w12-role-snapshot-sync): the Err arm at
        // the call site is the fail-closed half of the fix. A later edit that
        // ignores the reconcile error (`let _ = reconcile...`) would keep every
        // unit test green, so pin the arm itself, searched AFTER the reconcile
        // offset (the same needle appears in execute()'s earlier arms).
        let err_arm = execute_body[reconcile..]
            .find("Err(e) => return StageOutcome::Failed(e),")
            .map(|offset| reconcile + offset)
            .expect("the reconcile Err arm must fail the stage closed");
        assert!(
            err_arm < passed,
            "a failed reconcile must fail the stage ({err_arm}) before Passed ({passed})"
        );
    }
}
