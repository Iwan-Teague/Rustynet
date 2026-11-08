#![allow(dead_code)]
use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::remote_shell::RemoteShellHost;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::cross_network::substrate;
use crate::vm_lab::orchestrator::stage::node_diagnostics;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

/// QH-83 F1: the reboot-recovery stage's pass witness. The
/// `live_reboot_recovery` binary writes this report on every success path,
/// so a Passed verdict is only proven when this artifact exists and is
/// non-empty.
pub(crate) const REBOOT_RECOVERY_REPORT_RELATIVE: &str = "live_reboot_recovery_report.json";

/// QH-83 F1: fail a success exit whose pass witness artifact is missing or
/// empty instead of declaring Passed without evidence on disk.
fn verify_report_artifact(report_dir: &std::path::Path) -> Result<(), String> {
    let path = report_dir.join(REBOOT_RECOVERY_REPORT_RELATIVE);
    match std::fs::metadata(&path) {
        Ok(meta) if meta.len() > 0 => Ok(()),
        Ok(_) => Err(format!("pass witness artifact {path:?} is empty")),
        Err(err) => Err(format!("pass witness artifact {path:?} missing: {err}")),
    }
}

/// The reboot binary's flag that leaves the post-reboot assignment refresh to
/// this stage. Passed ONLY when the run provisioned a lab substrate: its
/// overlay is volatile guest state, so after the binary's reboot rustynetd
/// cannot start until [`substrate::reprovision_and_verify_after_reboot`] has
/// re-created it, and the refresh's `systemctl restart rustynetd` (what
/// katana-xnet-994 ran straight after each boot) fails in that window.
pub(crate) const DEFER_POST_REBOOT_REFRESH_FLAG: &str = "--defer-post-reboot-refresh";

/// Mirrors the reboot binary's `ASSIGNMENT_REFRESH_ENV_PATH`: the refresh
/// timer's environment file, installed by the two-hop stage. Absent means this
/// lab setup never provisioned assignment refresh and there is nothing to
/// refresh after the reboot.
const ASSIGNMENT_REFRESH_ENV_PATH: &str = "/etc/rustynet/assignment-refresh.env";

/// Canonical guest path of the `rustynet` CLI (the substrate and install
/// modules mirror the same literal; the install one is binary-only).
const GUEST_RUSTYNET_CLI: &str = "/usr/local/bin/rustynet";

/// Diagnostics phase tags (file-name components, see
/// [`node_diagnostics::is_safe_component`]).
const PHASE_BINARY_FAILURE: &str = "reboot-recovery-failure";
const PHASE_REPROVISION_FAILURE: &str = "reboot-recovery-reprovision-failure";
const PHASE_REFRESH_FAILURE: &str = "reboot-recovery-refresh-failure";

/// True when this run provisioned a lab substrate overlay on the guests.
fn substrate_is_provisioned(ctx: &OrchestrationContext) -> bool {
    ctx.substrate_record
        .as_ref()
        .is_some_and(|record| record.provisioned)
}

/// Extra reboot-binary arguments for this run. The deferral flag is passed iff
/// the substrate is provisioned (a plain lab keeps the binary's own refresh).
fn reboot_binary_extra_args(defer_post_reboot_refresh: bool) -> &'static [&'static str] {
    if defer_post_reboot_refresh {
        &[DEFER_POST_REBOOT_REFRESH_FLAG]
    } else {
        &[]
    }
}

/// How the reboot binary ended.
enum BinaryRun {
    Succeeded,
    /// Exited non-zero; carries the stage's formatted failure text.
    Failed(String),
}

/// What the stage needs to know to conclude after the binary has exited.
struct PostBinaryPlan<'a> {
    /// The aliases the binary rebooted (exit, client).
    rebooted: &'a [&'a str],
    /// The run provisioned a lab substrate overlay.
    substrate_provisioned: bool,
    /// The binary was told to leave the post-reboot refresh to the stage.
    defer_post_reboot_refresh: bool,
}

/// Everything the stage does AFTER the reboot binary has exited, behind one
/// seam so the ordering and the failure branch are unit-testable without
/// cargo or ssh. `LiveSteps` is the real implementation. Every `Err` names the
/// alias it is about (the stage joins them into one failure text).
trait RebootStageSteps {
    /// Re-create the overlay on `rebooted`, restart their daemons and verify
    /// them ([`substrate::reprovision_and_verify_after_reboot`]).
    fn reprovision(&mut self, rebooted: &[&str]) -> Result<(), String>;
    /// Whether the overlay device exists on `alias` right now.
    fn overlay_present(&mut self, alias: &str) -> Result<bool, String>;
    /// Whether `alias` carries the assignment-refresh environment file.
    fn refresh_env_present(&mut self, alias: &str) -> Result<bool, String>;
    /// Run `ops force-local-assignment-refresh-now` on `alias`.
    fn force_refresh(&mut self, alias: &str) -> Result<(), String>;
    /// Best-effort diagnostics for `alias` (never changes a verdict).
    fn capture_diagnostics(&mut self, alias: &str, phase: &str);
    /// Append one evidence line to this stage's log.
    fn record_evidence(&mut self, line: &str) -> Result<(), String>;
    /// The binary's pass witness artifact must exist and be non-empty.
    fn verify_report(&mut self) -> Result<(), String>;
}

/// Collapse newlines so an error text fits one evidence line.
fn single_line(text: &str) -> String {
    text.replace(['\n', '\r'], " ")
}

fn csv_or_none(items: &[&str]) -> String {
    if items.is_empty() {
        "none".to_owned()
    } else {
        items.join(",")
    }
}

fn capture_diagnostics_for(steps: &mut dyn RebootStageSteps, aliases: &[&str], phase: &str) {
    for &alias in aliases {
        steps.capture_diagnostics(alias, phase);
    }
}

/// Conclude the stage from how the binary ended. The ORDER is the contract:
/// on success the substrate is re-provisioned FIRST, then the deferred refresh
/// runs, then the pass witness is checked; on failure the verdict is always
/// `Failed`, and recovery only ever repairs a lost overlay.
fn conclude_after_binary(
    steps: &mut dyn RebootStageSteps,
    plan: &PostBinaryPlan<'_>,
    run: BinaryRun,
) -> StageOutcome {
    match run {
        BinaryRun::Succeeded => conclude_succeeded_binary(steps, plan),
        BinaryRun::Failed(binary_failure) => conclude_failed_binary(steps, plan, binary_failure),
    }
}

fn conclude_succeeded_binary(
    steps: &mut dyn RebootStageSteps,
    plan: &PostBinaryPlan<'_>,
) -> StageOutcome {
    // u41-r2: the binary's reboot loses the vxlan overlay on the guests while
    // the persistent attestation survives, so the daemon cannot come back on
    // its own. Restore the overlay and REFUSE to pass while any rebooted
    // node's daemon is still down (the binary's post-reboot checks are skipped
    // for these guests, so this is the only gate). Runs BEFORE the artifact
    // check: a stage that cannot restore the substrate has failed, whatever
    // the binary's own report says.
    if let Err(err) = steps.reprovision(plan.rebooted) {
        capture_diagnostics_for(steps, plan.rebooted, PHASE_REPROVISION_FAILURE);
        return StageOutcome::Failed(err);
    }
    // The refresh the binary deferred runs only now that rustynetd can start.
    let refresh = if plan.defer_post_reboot_refresh {
        run_deferred_refresh(steps, plan.rebooted)
    } else {
        Ok(())
    };
    if let Err(err) = refresh {
        capture_diagnostics_for(steps, plan.rebooted, PHASE_REFRESH_FAILURE);
        return StageOutcome::Failed(err);
    }
    match steps.verify_report() {
        Ok(()) => StageOutcome::Passed,
        Err(err) => StageOutcome::Failed(err),
    }
}

/// The failure branch. The verdict is `Failed` whatever recovery achieves;
/// recovery only removes the cascade (a persistent attestation outliving a
/// volatile overlay keeps rustynetd down for every later stage). It touches
/// ONLY nodes whose overlay is actually missing, so a binary that died before
/// rebooting anything never bounces a live overlay under a running daemon.
fn conclude_failed_binary(
    steps: &mut dyn RebootStageSteps,
    plan: &PostBinaryPlan<'_>,
    binary_failure: String,
) -> StageOutcome {
    // The state exactly as the failed binary left it, BEFORE any recovery.
    capture_diagnostics_for(steps, plan.rebooted, PHASE_BINARY_FAILURE);
    if !plan.substrate_provisioned {
        return StageOutcome::Failed(binary_failure);
    }
    let note = recover_missing_overlays(steps, plan.rebooted);
    // Best effort: the verdict is already Failed and must carry the binary's
    // own failure text whether or not this line could be written.
    let _ = steps.record_evidence(&single_line(&format!(
        "reboot recovery binary failed; {note}"
    )));
    StageOutcome::Failed(format!("{binary_failure}\n{note}"))
}

/// Re-provision the overlay on the rebooted nodes that LOST it and report
/// what was done, node by node.
fn recover_missing_overlays(steps: &mut dyn RebootStageSteps, rebooted: &[&str]) -> String {
    let mut missing: Vec<&str> = Vec::new();
    let mut intact: Vec<&str> = Vec::new();
    let mut unknown: Vec<String> = Vec::new();
    for &alias in rebooted {
        match steps.overlay_present(alias) {
            Ok(true) => intact.push(alias),
            Ok(false) => missing.push(alias),
            // Cannot tell: never touch a node whose overlay may be live.
            Err(err) => unknown.push(err),
        }
    }
    let mut parts: Vec<String> = Vec::new();
    if !intact.is_empty() {
        parts.push(format!(
            "overlay still present, left untouched: {}",
            intact.join(",")
        ));
    }
    if !unknown.is_empty() {
        parts.push(format!(
            "overlay state could not be read, left untouched: {}",
            unknown.join("; ")
        ));
    }
    if missing.is_empty() {
        parts.push("no rebooted node had lost its overlay, nothing re-provisioned".to_owned());
    } else {
        match steps.reprovision(&missing) {
            Ok(()) => parts.push(format!(
                "overlay re-provisioned and rustynetd recovered on: {}",
                missing.join(",")
            )),
            Err(err) => parts.push(format!(
                "re-provision of {} FAILED: {err}",
                missing.join(",")
            )),
        }
    }
    format!(
        "substrate recovery after the failed reboot stage ({}); the stage verdict stays FAILED",
        parts.join("; ")
    )
}

/// The assignment refresh the binary deferred (`--defer-post-reboot-refresh`),
/// run after the substrate is back. A node without the refresh environment
/// file keeps the binary's own "not provisioned" meaning (nothing to refresh);
/// a node WITH it must refresh successfully, and an environment probe that
/// cannot answer fails closed.
fn run_deferred_refresh(steps: &mut dyn RebootStageSteps, rebooted: &[&str]) -> Result<(), String> {
    let mut refreshed: Vec<&str> = Vec::new();
    let mut env_absent: Vec<&str> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    for &alias in rebooted {
        match steps.refresh_env_present(alias) {
            Ok(true) => match steps.force_refresh(alias) {
                Ok(()) => refreshed.push(alias),
                Err(err) => errors.push(err),
            },
            Ok(false) => env_absent.push(alias),
            Err(err) => errors.push(err),
        }
    }
    if !errors.is_empty() {
        return Err(format!(
            "deferred post-reboot assignment refresh failed after the substrate was \
             re-provisioned: {}",
            errors.join("; ")
        ));
    }
    let verified = if refreshed.is_empty() {
        "none".to_owned()
    } else {
        format!("verified:{}", refreshed.join(","))
    };
    // Evidence only after every refresh passed, and only claims that are true
    // at write time. The substrate glue's own line still says
    // `post_reboot_dns_refresh=not-verified` because it is written before this
    // refresh ran; the `deferred_refresh=` token here is the authoritative one.
    steps.record_evidence(&format!(
        "deferred post-reboot assignment refresh ran after the substrate re-provision: \
         deferred_refresh={verified} refresh_env_absent={}",
        csv_or_none(&env_absent)
    ))
}

/// The real [`RebootStageSteps`]: guest commands go through the adapter's
/// hardened remote shell, the substrate glue and the evidence log are the
/// ones the rest of the lab already uses.
struct LiveSteps<'a> {
    ctx: &'a mut OrchestrationContext,
}

impl LiveSteps<'_> {
    fn shell(&self, alias: &str) -> Result<std::sync::Arc<dyn RemoteShellHost>, String> {
        let adapter = self
            .ctx
            .adapters
            .get(alias)
            .ok_or_else(|| format!("{alias}: no adapter for the post-reboot steps"))?;
        adapter
            .shell_host()
            .map_err(|err| format!("{alias}: remote shell unavailable: {err}"))
    }

    /// `test <flag> <path>` on the guest. `test` prints nothing when the
    /// condition is false, so exit 1 with EMPTY stderr is a clean "no"; exit 1
    /// with anything on stderr is `sudo` (or the shell) failing and is an
    /// error, never an answer. A transport failure is an error too.
    fn guest_test(&self, alias: &str, flag: &str, path: &str) -> Result<bool, String> {
        let shell = self.shell(alias)?;
        let status = shell
            .run_argv(&["test", flag, path], &[], &[])
            .map_err(|err| format!("{alias}: `test {flag} {path}`: {err}"))?;
        match status.code {
            0 => Ok(true),
            1 if status.stderr.iter().all(u8::is_ascii_whitespace) => Ok(false),
            code => Err(format!(
                "{alias}: `test {flag} {path}` exited {code}: {}",
                first_line(&status.stderr)
            )),
        }
    }
}

/// The first non-empty line of a command's stderr, clipped (or a marker).
fn first_line(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("(no stderr)")
        .chars()
        .take(300)
        .collect()
}

impl RebootStageSteps for LiveSteps<'_> {
    fn reprovision(&mut self, rebooted: &[&str]) -> Result<(), String> {
        substrate::reprovision_and_verify_after_reboot(self.ctx, rebooted)
    }

    fn overlay_present(&mut self, alias: &str) -> Result<bool, String> {
        let device = format!("/sys/class/net/{}", substrate::VXLAN_LINK_NAME);
        self.guest_test(alias, "-e", &device)
    }

    fn refresh_env_present(&mut self, alias: &str) -> Result<bool, String> {
        self.guest_test(alias, "-f", ASSIGNMENT_REFRESH_ENV_PATH)
    }

    fn force_refresh(&mut self, alias: &str) -> Result<(), String> {
        let shell = self.shell(alias)?;
        let argv = [
            GUEST_RUSTYNET_CLI,
            "ops",
            "force-local-assignment-refresh-now",
        ];
        let status = shell
            .run_argv(&argv, &[], &[])
            .map_err(|err| format!("{alias}: assignment refresh: {err}"))?;
        if status.is_success() {
            return Ok(());
        }
        let detail = if status.stderr.iter().all(u8::is_ascii_whitespace) {
            String::from_utf8_lossy(&status.stdout).trim().to_owned()
        } else {
            String::from_utf8_lossy(&status.stderr).trim().to_owned()
        };
        Err(format!(
            "{alias}: `rustynet ops force-local-assignment-refresh-now` exited {}: {}",
            status.code,
            detail.chars().take(600).collect::<String>()
        ))
    }

    fn capture_diagnostics(&mut self, alias: &str, phase: &str) {
        // The shared, scrubbed network snapshot (nft ruleset, wg, routes and
        // the last ten minutes of the rustynetd journal, which carries the
        // daemon's own start-refusal reason) ...
        node_diagnostics::capture_node_diagnostics(self.ctx, alias, phase);
        // ... plus the reboot-specific facts that snapshot lacks.
        let state_phase = format!("{phase}-state");
        if !node_diagnostics::is_safe_component(alias)
            || !node_diagnostics::is_safe_component(&state_phase)
        {
            return;
        }
        let body = match self.shell(alias) {
            Ok(shell) => render_reboot_state(shell.as_ref(), alias, phase),
            Err(err) => format!(
                "# reboot-recovery state\nnode: {alias}\nphase: {phase}\ncapture error: {err}\n"
            ),
        };
        write_state_file(&self.ctx.report_dir, &state_phase, alias, &body);
    }

    fn record_evidence(&mut self, line: &str) -> Result<(), String> {
        crate::vm_lab::orchestrator::evidence::append_stage_evidence_line(
            &self.ctx.report_dir,
            StageId::LiveRebootRecoveryValidation.as_str(),
            line,
        )
    }

    fn verify_report(&mut self) -> Result<(), String> {
        verify_report_artifact(&self.ctx.report_dir)
    }
}

/// The reboot-specific guest facts captured on a failure: the unit's state
/// (no journal lines), the substrate attestation directory, the overlay link,
/// the nftables table names, and the rustynetd journal lines of this boot that
/// name the overlay or the attestation (the start-refusal reason). Every
/// command is bounded by a remote `timeout`; none can print key material.
const REBOOT_STATE_COMMANDS: &[(&str, &[&str])] = &[
    (
        "systemctl status rustynetd (unit state, no journal lines)",
        &[
            "timeout",
            "10",
            "systemctl",
            "status",
            "rustynetd",
            "--no-pager",
            "-l",
            "-n",
            "0",
        ],
    ),
    (
        "ls -l /etc/rustynet/lab (substrate attestation)",
        &["timeout", "10", "ls", "-l", "/etc/rustynet/lab"],
    ),
    // No `-d`: the detailed form prints the vxlan underlay (`local <addr>`
    // and the underlay device), addressing that `render_reboot_state` does not
    // pass through `node_diagnostics::Scrubber`. The plain form still answers
    // the question (does the link exist, is it up, its MTU).
    (
        "overlay link",
        &[
            "timeout",
            "10",
            "ip",
            "-o",
            "link",
            "show",
            "dev",
            substrate::VXLAN_LINK_NAME,
        ],
    ),
    (
        "nft list tables",
        &["timeout", "10", "nft", "list", "tables"],
    ),
    (
        "journalctl rustynetd (this boot, overlay/attestation lines)",
        &[
            "timeout",
            "15",
            "journalctl",
            "-u",
            "rustynetd",
            "-b",
            "--no-pager",
            "-n",
            "20",
            "--grep",
            "overlay device|lab substrate transit",
        ],
    ),
];

/// Per-command output caps (lines, characters per line).
const REBOOT_STATE_MAX_LINES: usize = 120;
const REBOOT_STATE_MAX_LINE_CHARS: usize = 400;

/// Run [`REBOOT_STATE_COMMANDS`] over `shell` and render the evidence file.
/// Best effort: a command's non-zero exit is recorded (`rc=N`, the exit code
/// of `systemctl status` on a failed unit or `ip` on a missing link IS the
/// finding), a transport failure ends the capture, and nothing here can change
/// a verdict. Lines mentioning key material are dropped as defence in depth.
fn render_reboot_state(shell: &dyn RemoteShellHost, alias: &str, phase: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "# reboot-recovery state");
    let _ = writeln!(out, "node: {alias}");
    let _ = writeln!(out, "phase: {phase}");
    for (label, argv) in REBOOT_STATE_COMMANDS {
        let _ = writeln!(out, "== {label} ==");
        let status = match shell.run_argv(argv, &[], &[]) {
            Ok(status) => status,
            Err(err) => {
                let _ = writeln!(out, "capture error: {}", single_line(&err.to_string()));
                let _ = writeln!(
                    out,
                    "capture error: remaining commands skipped after transport failure"
                );
                return out;
            }
        };
        let _ = writeln!(out, "rc={}", status.code);
        let text = format!(
            "{}\n{}",
            String::from_utf8_lossy(&status.stdout),
            String::from_utf8_lossy(&status.stderr)
        );
        let mut kept = 0usize;
        for line in text.lines().filter(|line| !line.trim().is_empty()) {
            if is_key_material_line(line) || kept >= REBOOT_STATE_MAX_LINES {
                continue;
            }
            kept += 1;
            let clipped: String = line
                .chars()
                .filter(|c| !c.is_control() || *c == '\t')
                .take(REBOOT_STATE_MAX_LINE_CHARS)
                .collect();
            let _ = writeln!(out, "{clipped}");
        }
        if kept == 0 {
            let _ = writeln!(out, "(no output)");
        }
    }
    out
}

/// Lines that may carry key material (the same needles as
/// `node_diagnostics`): dropped wherever they appear. `pub(crate)` so the
/// relay-forward evidence scrub shares this ONE needle list instead of a
/// second list that can drift.
pub(crate) fn is_key_material_line(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    [
        "secret",
        "token",
        "authkey",
        "tskey-",
        "passphrase",
        "private",
        "preshared",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

/// Write `body` to `<report_dir>/logs/diag_<phase>_<alias>.txt`, mode 0600
/// (raw node state is operator-only). Best effort: a write failure is reported
/// on stderr and never changes a verdict.
fn write_state_file(report_dir: &std::path::Path, phase: &str, alias: &str, body: &str) {
    use std::io::Write as _;
    #[cfg(unix)]
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let logs_dir = report_dir.join("logs");
    if let Err(err) = std::fs::create_dir_all(&logs_dir) {
        eprintln!("live_reboot_recovery: cannot create logs dir: {err}");
        return;
    }
    let path = logs_dir.join(format!("diag_{phase}_{alias}.txt"));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);
    let written = options.open(&path).and_then(|mut file| {
        #[cfg(unix)]
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        file.write_all(body.as_bytes())
    });
    if let Err(err) = written {
        eprintln!("live_reboot_recovery: write failed for {alias}: {err}");
    }
}

pub struct LiveRebootRecoveryValidationStage;

impl OrchestrationStage for LiveRebootRecoveryValidationStage {
    fn id(&self) -> StageId {
        StageId::LiveRebootRecoveryValidation
    }
    fn name(&self) -> &str {
        "live_reboot_recovery_validation"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::LiveNetworkFlapValidation]
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
            "reboot-recovery validation",
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

        // The helper binary is Linux-only; never point it at a macOS/Windows node.
        match crate::vm_lab::orchestrator::stage::non_linux_node_skip(
            ctx,
            "reboot-recovery validation",
            &[exit_params.alias.as_str(), client_params.alias.as_str()],
        ) {
            Ok(Some(skip)) => return skip,
            Ok(None) => {}
            Err(unresolved) => return StageOutcome::Failed(unresolved),
        }

        let exit_node_id = match ctx.node_ids.get(&exit_params.alias) {
            Some(id) => id.clone(),
            None => return StageOutcome::Failed("exit node_id not found".into()),
        };
        let client_node_id = match ctx.node_ids.get(&client_params.alias) {
            Some(id) => id.clone(),
            None => return StageOutcome::Failed("client node_id not found".into()),
        };

        let report_path = ctx.report_dir.join(REBOOT_RECOVERY_REPORT_RELATIVE);
        let log_path = ctx.report_dir.join("live_reboot_recovery.log");

        let exit_target = format!("{}@{}", exit_params.user, exit_params.host);
        let client_target = format!("{}@{}", client_params.user, client_params.host);

        let report_path_str = match crate::vm_lab::orchestrator::stage::require_utf8_path(
            &report_path,
            "report path",
        ) {
            Ok(value) => value,

            Err(err) => return StageOutcome::Failed(err),
        };
        let log_path_str =
            match crate::vm_lab::orchestrator::stage::require_utf8_path(&log_path, "log path") {
                Ok(value) => value,
                Err(err) => return StageOutcome::Failed(err),
            };
        let identity_file = match crate::vm_lab::orchestrator::stage::require_utf8_path(
            &exit_params.identity_file,
            "identity file",
        ) {
            Ok(value) => value,
            Err(err) => return StageOutcome::Failed(err),
        };

        // Lab substrate (vxlan): the overlay is volatile guest state, so after
        // the binary's reboot rustynetd cannot start until this stage has
        // re-created the overlay. The binary must therefore NOT restart the
        // daemon (its post-reboot assignment refresh does) before that; the
        // stage runs the refresh itself afterwards (`conclude_after_binary`).
        let substrate_provisioned = substrate_is_provisioned(ctx);
        let defer_post_reboot_refresh = substrate_provisioned;

        let result = {
            let mut args: Vec<&str> = vec![
                "run",
                "--quiet",
                "-p",
                "rustynet-cli",
                "--features",
                "vm-lab",
                "--bin",
                "live_linux_reboot_recovery_test",
                "--",
                "--ssh-identity-file",
                identity_file,
                // QH-57 class sweep: the binary's nested two-hop subcheck
                // enforces this value; the binary now requires it.
                "--ssh-allow-cidrs",
                &ctx.ssh_allow_cidrs,
                "--exit-host",
                &exit_target,
                "--exit-node-id",
                &exit_node_id,
                "--client-host",
                &client_target,
                "--client-node-id",
                &client_node_id,
                "--report-path",
                report_path_str,
                "--log-path",
                log_path_str,
            ];
            args.extend_from_slice(reboot_binary_extra_args(defer_post_reboot_refresh));
            std::process::Command::new("cargo").args(&args).output()
        };

        let run = match result {
            Ok(output) if output.status.success() => BinaryRun::Succeeded,
            Ok(output) => BinaryRun::Failed(
                // QH-09: name the binary's own complete log (--log-path
                // above) so the clip disclosure cannot read as evidence
                // loss when the unclipped output sits beside it.
                crate::vm_lab::orchestrator::stage::format_stage_binary_failure_with_log(
                    "live_reboot_recovery binary",
                    output.status,
                    &output.stdout,
                    &output.stderr,
                    Some(log_path_str),
                ),
            ),
            Err(e) => {
                return StageOutcome::Failed(format!(
                    "live_reboot_recovery binary invocation failed: {e}"
                ));
            }
        };
        let rebooted = [exit_params.alias.as_str(), client_params.alias.as_str()];
        let plan = PostBinaryPlan {
            rebooted: &rebooted,
            substrate_provisioned,
            defer_post_reboot_refresh,
        };
        conclude_after_binary(&mut LiveSteps { ctx }, &plan, run)
    }
}

struct ResolvedParams {
    alias: String,
    host: String,
    user: String,
    identity_file: std::path::PathBuf,
    known_hosts: std::path::PathBuf,
}

fn alias_matching_label(ctx: &OrchestrationContext, label: &str) -> Option<String> {
    ctx.assignments
        .iter()
        .find(|a| a.role.as_str() == label)
        .map(|a| a.alias.clone())
}

fn ssh_params_for_role(ctx: &OrchestrationContext, label: &str) -> Result<ResolvedParams, String> {
    let alias = alias_matching_label(ctx, label)
        .ok_or_else(|| format!("no node with role label '{label}' in assignments"))?;
    let adapter = ctx
        .adapters
        .get(alias.as_str())
        .ok_or_else(|| format!("no adapter for {alias} (label '{label}')"))?;
    let params = adapter
        .ssh_connection_params()
        .ok_or_else(|| format!("{alias} ({label}): no SSH connection params available"))?;
    let user = params.user.unwrap_or_else(|| {
        match adapter.platform() {
            VmGuestPlatform::Linux => "root",
            VmGuestPlatform::Macos => "admin",
            VmGuestPlatform::Windows => "administrator",
            _ => "root",
        }
        .to_owned()
    });
    Ok(ResolvedParams {
        alias,
        host: params.host,
        user,
        identity_file: params.identity_file,
        known_hosts: params.known_hosts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::orchestrator::remote_shell::{RemoteExitStatus, RemoteShellError};
    use crate::vm_lab::orchestrator::stage::node_diagnostics::test_support::{
        EventLog, Responder, ScriptedShell, ShellAdapter, ctx_with_adapters, ok, rc, scratch_dir,
        transport_err,
    };
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    #[test]
    fn stage_id_is_live_reboot_recovery() {
        let stage = LiveRebootRecoveryValidationStage;
        assert_eq!(stage.id(), StageId::LiveRebootRecoveryValidation);
    }

    #[test]
    fn stage_name_is_lowercase_kebab() {
        let stage = LiveRebootRecoveryValidationStage;
        assert_eq!(stage.name(), "live_reboot_recovery_validation");
    }

    #[test]
    fn depends_on_live_network_flap() {
        assert_eq!(
            LiveRebootRecoveryValidationStage.dependencies(),
            &[StageId::LiveNetworkFlapValidation]
        );
    }

    #[test]
    fn fanout_is_once() {
        assert_eq!(
            LiveRebootRecoveryValidationStage.fanout(),
            StageFanout::Once
        );
    }

    #[test]
    fn live_reboot_recovery_declared_witness_matches_its_artifact_path() {
        use crate::vm_lab::orchestrator::stage::StageEvidence;

        assert_eq!(
            StageId::LiveRebootRecoveryValidation.evidence(),
            StageEvidence::File(REBOOT_RECOVERY_REPORT_RELATIVE),
            "the catalog must declare the reboot-recovery report as the pass witness"
        );
    }

    #[test]
    fn live_reboot_recovery_pass_without_report_artifact_is_fatal() {
        let dir = std::env::temp_dir().join(format!(
            "reboot_recovery_witness_{}_{}",
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
            result
                .unwrap_err()
                .contains(REBOOT_RECOVERY_REPORT_RELATIVE),
            "the failure must name the missing witness artifact"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// u41-r3 (review mutant m11), kept and strengthened: the substrate fix
    /// is a call that no mock-driven test can notice disappearing from the
    /// REAL wiring (the stage would pass a vxlan run with the overlay down and
    /// the daemons latched). Pin it at source level, production half only:
    /// `execute` hands the real steps to the conclusion, the real
    /// `reprovision` step IS the substrate glue, and inside the success branch
    /// the glue call precedes the Passed verdict. (The mock tests below pin
    /// the same order behaviourally.)
    #[test]
    fn stage_execute_calls_the_substrate_reprovision_glue_before_the_passed_verdict() {
        let source = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/vm_lab/orchestrator/stage/live_reboot_recovery_validation.rs"
        ));
        let production = &source[..source
            .find("#[cfg(test)]")
            .expect("the test module marker exists")];
        assert!(
            production.contains("conclude_after_binary(&mut LiveSteps { ctx }, &plan, run)"),
            "execute must conclude through the real steps"
        );
        assert!(
            production
                .contains("substrate::reprovision_and_verify_after_reboot(self.ctx, rebooted)"),
            "the real reprovision step must be the substrate glue"
        );
        let branch = &production[production
            .find("fn conclude_succeeded_binary")
            .expect("the success branch exists")..];
        let call = branch
            .find("steps.reprovision(plan.rebooted)")
            .expect("the success branch must re-provision the substrate");
        let passed = branch
            .find("StageOutcome::Passed")
            .expect("the Passed verdict exists");
        assert!(call < passed, "the glue must run BEFORE the stage can pass");
    }

    // ── post-binary conclusion: failure branch, call order, deferred refresh ──

    /// Scripted steps: every call is recorded, in order, with a benign default
    /// (overlay present, refresh env present, everything succeeds) that a test
    /// overrides per alias.
    #[derive(Default)]
    struct RecordingSteps {
        calls: Vec<String>,
        evidence: Vec<String>,
        overlay: HashMap<String, Result<bool, String>>,
        refresh_env: HashMap<String, Result<bool, String>>,
        refresh: HashMap<String, Result<(), String>>,
        reprovision: Option<Result<(), String>>,
        verify: Option<Result<(), String>>,
    }

    impl RebootStageSteps for RecordingSteps {
        fn reprovision(&mut self, rebooted: &[&str]) -> Result<(), String> {
            self.calls
                .push(format!("reprovision:{}", rebooted.join(",")));
            self.reprovision.clone().unwrap_or(Ok(()))
        }
        fn overlay_present(&mut self, alias: &str) -> Result<bool, String> {
            self.calls.push(format!("overlay_present:{alias}"));
            self.overlay.get(alias).cloned().unwrap_or(Ok(true))
        }
        fn refresh_env_present(&mut self, alias: &str) -> Result<bool, String> {
            self.calls.push(format!("refresh_env_present:{alias}"));
            self.refresh_env.get(alias).cloned().unwrap_or(Ok(true))
        }
        fn force_refresh(&mut self, alias: &str) -> Result<(), String> {
            self.calls.push(format!("force_refresh:{alias}"));
            self.refresh.get(alias).cloned().unwrap_or(Ok(()))
        }
        fn capture_diagnostics(&mut self, alias: &str, phase: &str) {
            self.calls.push(format!("diagnostics:{phase}:{alias}"));
        }
        fn record_evidence(&mut self, line: &str) -> Result<(), String> {
            self.calls.push("evidence".to_owned());
            self.evidence.push(line.to_owned());
            Ok(())
        }
        fn verify_report(&mut self) -> Result<(), String> {
            self.calls.push("verify_report".to_owned());
            self.verify.clone().unwrap_or(Ok(()))
        }
    }

    const REBOOTED: [&str; 2] = ["exit-1", "client-1"];

    fn plan(
        substrate_provisioned: bool,
        defer_post_reboot_refresh: bool,
    ) -> PostBinaryPlan<'static> {
        PostBinaryPlan {
            rebooted: &REBOOTED,
            substrate_provisioned,
            defer_post_reboot_refresh,
        }
    }

    fn index_of(calls: &[String], call: &str) -> usize {
        calls
            .iter()
            .position(|c| c == call)
            .unwrap_or_else(|| panic!("call {call:?} not made: {calls:?}"))
    }

    fn made(calls: &[String], prefix: &str) -> bool {
        calls.iter().any(|c| c.starts_with(prefix))
    }

    fn failed_text(outcome: StageOutcome) -> String {
        match outcome {
            StageOutcome::Failed(text) => text,
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    /// katana-xnet-994: the binary failed after rebooting exit and client, the
    /// old failure branch did nothing, and both daemons stayed dead behind a
    /// persistent attestation for the rest of the run. The node that LOST its
    /// overlay is re-provisioned, the one that kept it is not touched, and the
    /// verdict stays Failed with the binary's own text. Mutants killed: delete
    /// the failure-branch recovery; re-provision every alias; return Passed.
    #[test]
    fn failed_binary_reprovisions_only_the_node_that_lost_its_overlay_and_stays_failed() {
        let mut steps = RecordingSteps::default();
        steps.overlay.insert("exit-1".into(), Ok(false));
        steps.overlay.insert("client-1".into(), Ok(true));
        let text = failed_text(conclude_after_binary(
            &mut steps,
            &plan(true, true),
            BinaryRun::Failed("live_reboot_recovery binary failed (exit 1): boom".into()),
        ));
        assert!(
            text.contains("live_reboot_recovery binary failed (exit 1): boom"),
            "{text}"
        );
        assert!(
            text.contains("overlay re-provisioned and rustynetd recovered on: exit-1"),
            "{text}"
        );
        assert!(
            text.contains("overlay still present, left untouched: client-1"),
            "{text}"
        );
        assert!(text.contains("the stage verdict stays FAILED"), "{text}");
        let reprovisions: Vec<&String> = steps
            .calls
            .iter()
            .filter(|c| c.starts_with("reprovision:"))
            .collect();
        assert_eq!(reprovisions, ["reprovision:exit-1"], "{:?}", steps.calls);
        assert!(!made(&steps.calls, "verify_report"), "{:?}", steps.calls);
        assert!(!made(&steps.calls, "force_refresh"), "{:?}", steps.calls);
        assert_eq!(steps.evidence.len(), 1, "{:?}", steps.evidence);
        assert!(!steps.evidence[0].contains('\n'), "one evidence line");
    }

    /// A binary that died before rebooting anything must not bounce a live
    /// overlay under a running daemon (b115 review finding 3).
    #[test]
    fn failed_binary_with_every_overlay_present_never_bounces_a_live_overlay() {
        let mut steps = RecordingSteps::default();
        let text = failed_text(conclude_after_binary(
            &mut steps,
            &plan(true, true),
            BinaryRun::Failed("binary boom".into()),
        ));
        assert!(!made(&steps.calls, "reprovision"), "{:?}", steps.calls);
        assert!(text.contains("binary boom"), "{text}");
        assert!(text.contains("nothing re-provisioned"), "{text}");
    }

    /// No substrate, no overlay to repair: the failure text is the binary's
    /// own, unchanged, and nothing is probed on the guests.
    #[test]
    fn failed_binary_without_a_substrate_neither_probes_nor_recovers() {
        let mut steps = RecordingSteps::default();
        let text = failed_text(conclude_after_binary(
            &mut steps,
            &plan(false, false),
            BinaryRun::Failed("binary boom".into()),
        ));
        assert_eq!(text, "binary boom");
        assert!(!made(&steps.calls, "overlay_present"), "{:?}", steps.calls);
        assert!(!made(&steps.calls, "reprovision"), "{:?}", steps.calls);
        assert!(steps.evidence.is_empty());
    }

    /// A recovery that itself fails is named next to the binary's text; it can
    /// never turn the verdict into a pass.
    #[test]
    fn failed_binary_recovery_failure_is_named_and_the_verdict_stays_failed() {
        let mut steps = RecordingSteps::default();
        steps.overlay.insert("exit-1".into(), Ok(false));
        steps.reprovision = Some(Err("exit-1: rustynetd restart failed".into()));
        let text = failed_text(conclude_after_binary(
            &mut steps,
            &plan(true, true),
            BinaryRun::Failed("binary boom".into()),
        ));
        assert!(text.contains("binary boom"), "{text}");
        assert!(
            text.contains("re-provision of exit-1 FAILED: exit-1: rustynetd restart failed"),
            "{text}"
        );
    }

    /// An overlay probe that cannot answer leaves the node alone (it may be
    /// live) and says so.
    #[test]
    fn failed_binary_unreadable_overlay_is_left_untouched_and_named() {
        let mut steps = RecordingSteps::default();
        steps
            .overlay
            .insert("exit-1".into(), Err("exit-1: ssh timed out".into()));
        let text = failed_text(conclude_after_binary(
            &mut steps,
            &plan(true, true),
            BinaryRun::Failed("binary boom".into()),
        ));
        assert!(!made(&steps.calls, "reprovision"), "{:?}", steps.calls);
        assert!(
            text.contains("overlay state could not be read, left untouched: exit-1: ssh timed out"),
            "{text}"
        );
    }

    /// W4: the guests are captured as the failed binary left them, BEFORE the
    /// recovery changes anything, for every rebooted node.
    #[test]
    fn failed_binary_captures_diagnostics_before_any_recovery() {
        let mut steps = RecordingSteps::default();
        steps.overlay.insert("exit-1".into(), Ok(false));
        let _ = conclude_after_binary(
            &mut steps,
            &plan(true, true),
            BinaryRun::Failed("binary boom".into()),
        );
        let first_probe = index_of(&steps.calls, "overlay_present:exit-1");
        let recover = index_of(&steps.calls, "reprovision:exit-1");
        for alias in REBOOTED {
            let capture = index_of(
                &steps.calls,
                &format!("diagnostics:{PHASE_BINARY_FAILURE}:{alias}"),
            );
            assert!(
                capture < first_probe && capture < recover,
                "{:?}",
                steps.calls
            );
        }
    }

    /// The deferred refresh belongs to a passing binary: after a failure the
    /// stage neither refreshes nor probes for the refresh environment.
    #[test]
    fn failed_binary_never_runs_the_deferred_refresh() {
        let mut steps = RecordingSteps::default();
        steps.overlay.insert("exit-1".into(), Ok(false));
        let _ = conclude_after_binary(
            &mut steps,
            &plan(true, true),
            BinaryRun::Failed("binary boom".into()),
        );
        assert!(!made(&steps.calls, "force_refresh"), "{:?}", steps.calls);
        assert!(
            !made(&steps.calls, "refresh_env_present"),
            "{:?}",
            steps.calls
        );
    }

    /// W2, the call order: the refresh the binary deferred runs AFTER the
    /// overlay is re-provisioned (the same call that restarts and verifies
    /// the daemons) and BEFORE the pass is decided. Mutants killed: refresh
    /// before the re-provision (the xnet-994 order); no refresh at all.
    #[test]
    fn deferred_refresh_runs_after_the_reprovision_and_before_the_pass() {
        let mut steps = RecordingSteps::default();
        let outcome = conclude_after_binary(&mut steps, &plan(true, true), BinaryRun::Succeeded);
        assert_eq!(outcome, StageOutcome::Passed);
        assert_eq!(
            steps.calls,
            [
                "reprovision:exit-1,client-1",
                "refresh_env_present:exit-1",
                "force_refresh:exit-1",
                "refresh_env_present:client-1",
                "force_refresh:client-1",
                "evidence",
                "verify_report",
            ]
        );
        let reprovision = index_of(&steps.calls, "reprovision:exit-1,client-1");
        for alias in REBOOTED {
            assert!(reprovision < index_of(&steps.calls, &format!("force_refresh:{alias}")));
        }
        assert_eq!(
            steps.evidence,
            [
                "deferred post-reboot assignment refresh ran after the substrate re-provision: \
                 deferred_refresh=verified:exit-1,client-1 refresh_env_absent=none"
            ]
        );
    }

    /// The stage fails when the deferred refresh fails: the check the binary
    /// used to own is not dropped, only moved behind the re-provision.
    #[test]
    fn deferred_refresh_failure_fails_the_stage() {
        let mut steps = RecordingSteps::default();
        steps.refresh.insert(
            "client-1".into(),
            Err(
                "client-1: `rustynet ops force-local-assignment-refresh-now` exited 1: boom".into(),
            ),
        );
        let text = failed_text(conclude_after_binary(
            &mut steps,
            &plan(true, true),
            BinaryRun::Succeeded,
        ));
        assert!(
            text.contains("deferred post-reboot assignment refresh failed"),
            "{text}"
        );
        assert!(text.contains("exited 1: boom"), "{text}");
        assert!(!made(&steps.calls, "verify_report"), "{:?}", steps.calls);
        assert!(steps.evidence.is_empty(), "no pass evidence on a failure");
        for alias in REBOOTED {
            index_of(
                &steps.calls,
                &format!("diagnostics:{PHASE_REFRESH_FAILURE}:{alias}"),
            );
        }
    }

    /// An environment probe that cannot answer is not "absent": fail closed.
    #[test]
    fn deferred_refresh_env_probe_error_fails_closed() {
        let mut steps = RecordingSteps::default();
        steps.refresh_env.insert(
            "exit-1".into(),
            Err("exit-1: `test -f` exited 1: sudo: a password is required".into()),
        );
        let text = failed_text(conclude_after_binary(
            &mut steps,
            &plan(true, true),
            BinaryRun::Succeeded,
        ));
        assert!(text.contains("a password is required"), "{text}");
        assert!(
            !made(&steps.calls, "force_refresh:exit-1"),
            "{:?}",
            steps.calls
        );
    }

    /// A node that never had assignment refresh provisioned keeps the
    /// binary's meaning (nothing to refresh); the evidence says which.
    #[test]
    fn deferred_refresh_skips_nodes_without_the_refresh_env_and_records_it() {
        let mut steps = RecordingSteps::default();
        steps.refresh_env.insert("client-1".into(), Ok(false));
        let outcome = conclude_after_binary(&mut steps, &plan(true, true), BinaryRun::Succeeded);
        assert_eq!(outcome, StageOutcome::Passed);
        assert!(
            !made(&steps.calls, "force_refresh:client-1"),
            "{:?}",
            steps.calls
        );
        assert!(made(&steps.calls, "force_refresh:exit-1"));
        assert!(
            steps.evidence[0]
                .contains("deferred_refresh=verified:exit-1 refresh_env_absent=client-1"),
            "{:?}",
            steps.evidence
        );
    }

    #[test]
    fn deferred_refresh_with_no_refresh_env_anywhere_runs_nothing_and_says_so() {
        let mut steps = RecordingSteps::default();
        steps.refresh_env.insert("exit-1".into(), Ok(false));
        steps.refresh_env.insert("client-1".into(), Ok(false));
        let outcome = conclude_after_binary(&mut steps, &plan(true, true), BinaryRun::Succeeded);
        assert_eq!(outcome, StageOutcome::Passed);
        assert!(!made(&steps.calls, "force_refresh"), "{:?}", steps.calls);
        assert!(
            steps.evidence[0].contains("deferred_refresh=none refresh_env_absent=exit-1,client-1"),
            "{:?}",
            steps.evidence
        );
    }

    /// A plain lab (no substrate) is untouched: no deferral, no extra probes,
    /// the same two steps as before this change.
    #[test]
    fn non_deferred_success_never_touches_the_refresh() {
        let mut steps = RecordingSteps::default();
        let outcome = conclude_after_binary(&mut steps, &plan(false, false), BinaryRun::Succeeded);
        assert_eq!(outcome, StageOutcome::Passed);
        assert_eq!(
            steps.calls,
            ["reprovision:exit-1,client-1", "verify_report"]
        );
    }

    /// A re-provision that fails on the success path is still the stage's
    /// failure, with its own text, and the refresh is not attempted.
    #[test]
    fn failed_reprovision_on_success_fails_without_refreshing() {
        let mut steps = RecordingSteps {
            reprovision: Some(Err("rebooted-node recovery failed: exit-1: no unit".into())),
            ..RecordingSteps::default()
        };
        let text = failed_text(conclude_after_binary(
            &mut steps,
            &plan(true, true),
            BinaryRun::Succeeded,
        ));
        assert_eq!(text, "rebooted-node recovery failed: exit-1: no unit");
        assert!(!made(&steps.calls, "force_refresh"), "{:?}", steps.calls);
        assert!(!made(&steps.calls, "verify_report"), "{:?}", steps.calls);
    }

    /// The pass witness is still required, and it is checked last.
    #[test]
    fn missing_report_artifact_fails_after_the_refresh() {
        let mut steps = RecordingSteps {
            verify: Some(Err("pass witness artifact \"x\" missing".into())),
            ..RecordingSteps::default()
        };
        let text = failed_text(conclude_after_binary(
            &mut steps,
            &plan(true, true),
            BinaryRun::Succeeded,
        ));
        assert!(text.contains("pass witness artifact"), "{text}");
        assert!(
            index_of(&steps.calls, "force_refresh:client-1")
                < index_of(&steps.calls, "verify_report")
        );
    }

    /// The deferral flag reaches the binary iff the substrate is provisioned,
    /// and the provisioned state comes from the persisted record.
    #[test]
    fn deferral_flag_is_passed_iff_the_substrate_is_provisioned() {
        assert_eq!(
            reboot_binary_extra_args(true),
            ["--defer-post-reboot-refresh"]
        );
        assert!(reboot_binary_extra_args(false).is_empty());

        let dir = scratch_dir("reboot_flag");
        let mut ctx = ctx_with_adapters(&dir, Vec::new());
        assert!(
            !substrate_is_provisioned(&ctx),
            "no record: not provisioned"
        );
        let record = |provisioned: bool| substrate::SubstrateRecord {
            substrate_id: "vxlan".to_owned(),
            topology_digest: "digest".to_owned(),
            provisioned,
            participants: Vec::new(),
        };
        ctx.substrate_record = Some(record(false));
        assert!(!substrate_is_provisioned(&ctx), "recorded no-op substrate");
        ctx.substrate_record = Some(record(true));
        assert!(substrate_is_provisioned(&ctx));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Source pin on the one line a mock cannot see: `execute` must extend the
    /// binary's argv with the flag derived from the substrate state.
    #[test]
    fn execute_extends_the_binary_argv_with_the_deferral_flag() {
        let source = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/vm_lab/orchestrator/stage/live_reboot_recovery_validation.rs"
        ));
        let production = &source[..source
            .find("#[cfg(test)]")
            .expect("the test module marker exists")];
        assert!(production.contains("let defer_post_reboot_refresh = substrate_provisioned;"));
        assert!(production.contains(
            "args.extend_from_slice(reboot_binary_extra_args(defer_post_reboot_refresh));"
        ));
    }

    // ── the real steps over a scripted guest shell ──

    fn live_ctx(tag: &str, responder: Arc<Responder>) -> (OrchestrationContext, EventLog) {
        let dir = scratch_dir(tag);
        let log: EventLog = Arc::new(Mutex::new(Vec::new()));
        let ctx = ctx_with_adapters(&dir, vec![ShellAdapter::new("exit-1", &log, responder)]);
        (ctx, log)
    }

    fn status(code: i32, stdout: &str, stderr: &str) -> Result<RemoteExitStatus, RemoteShellError> {
        Ok(RemoteExitStatus {
            code,
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        })
    }

    /// `test -e` answers by exit code; exit 1 WITH stderr is sudo failing, not
    /// "the overlay is gone" (that misread would re-provision a live overlay),
    /// and a transport failure is an error, never an answer.
    #[test]
    fn live_overlay_probe_reads_the_exit_code_and_refuses_to_guess() {
        let cases: [(&str, i32, &str, Option<bool>); 5] = [
            ("present", 0, "", Some(true)),
            ("missing", 1, "", Some(false)),
            ("missing, blank stderr", 1, "\n", Some(false)),
            ("sudo failed", 1, "sudo: a password is required", None),
            ("no test binary", 127, "sh: test: not found", None),
        ];
        for (name, code, stderr, expected) in cases {
            let responder: Arc<Responder> = Arc::new(move |_: &[String]| status(code, "", stderr));
            let (mut ctx, log) = live_ctx("overlay_probe", responder);
            let answer = LiveSteps { ctx: &mut ctx }.overlay_present("exit-1");
            match expected {
                Some(want) => assert_eq!(answer, Ok(want), "{name}"),
                None => assert!(answer.is_err(), "{name}: {answer:?}"),
            }
            assert_eq!(
                log.lock().unwrap().as_slice(),
                ["shell:test -e /sys/class/net/rustynet-vx0"],
                "{name}"
            );
        }
        let responder: Arc<Responder> = Arc::new(|_: &[String]| transport_err());
        let (mut ctx, _log) = live_ctx("overlay_probe_transport", responder);
        let answer = LiveSteps { ctx: &mut ctx }.overlay_present("exit-1");
        assert!(answer.is_err(), "{answer:?}");
        let answer = LiveSteps { ctx: &mut ctx }.overlay_present("nobody");
        assert!(
            answer.is_err(),
            "an alias with no adapter is an error: {answer:?}"
        );
    }

    #[test]
    fn live_refresh_env_probe_tests_the_refresh_env_file() {
        let responder: Arc<Responder> = Arc::new(|_: &[String]| rc(1, ""));
        let (mut ctx, log) = live_ctx("env_probe", responder);
        let answer = LiveSteps { ctx: &mut ctx }.refresh_env_present("exit-1");
        assert_eq!(answer, Ok(false));
        assert_eq!(
            log.lock().unwrap().as_slice(),
            ["shell:test -f /etc/rustynet/assignment-refresh.env"]
        );
    }

    /// The deferred refresh runs the binary's exact command with the binary's
    /// pass criterion (exit 0), and a failure carries the command's own text.
    #[test]
    fn live_force_refresh_runs_the_exact_cli_verb_and_reports_failure() {
        let responder: Arc<Responder> = Arc::new(|_: &[String]| ok("refreshed\n"));
        let (mut ctx, log) = live_ctx("refresh_ok", responder);
        assert_eq!(LiveSteps { ctx: &mut ctx }.force_refresh("exit-1"), Ok(()));
        assert_eq!(
            log.lock().unwrap().as_slice(),
            ["shell:/usr/local/bin/rustynet ops force-local-assignment-refresh-now"]
        );

        let responder: Arc<Responder> =
            Arc::new(|_: &[String]| status(1, "", "systemctl restart rustynetd.service failed"));
        let (mut ctx, _log) = live_ctx("refresh_fail", responder);
        let err = LiveSteps { ctx: &mut ctx }
            .force_refresh("exit-1")
            .expect_err("a non-zero exit must fail");
        assert!(err.contains("exit-1"), "{err}");
        assert!(err.contains("exited 1"), "{err}");
        assert!(
            err.contains("systemctl restart rustynetd.service failed"),
            "{err}"
        );
    }

    /// W4: the reboot-state file records the command, its exit code and its
    /// output, including the findings that arrive as a NON-ZERO exit (a failed
    /// unit, a missing link), and drops lines that look like key material.
    #[test]
    fn reboot_state_capture_records_exit_codes_and_output_and_drops_key_lines() {
        let log: EventLog = Arc::new(Mutex::new(Vec::new()));
        let responder: Arc<Responder> = Arc::new(|argv: &[String]| {
            if argv.iter().any(|a| a == "systemctl") {
                status(
                    3,
                    "Active: failed (Result: exit-code)\nExecStartPre status=78",
                    "",
                )
            } else if argv.iter().any(|a| a == "ip") {
                status(1, "", "Device \"rustynet-vx0\" does not exist.")
            } else if argv.iter().any(|a| a == "journalctl") {
                status(
                    0,
                    "rustynetd: lab substrate transit attestation rejected: overlay device rustynet-vx0 does not exist\nprivate-key line\n",
                    "",
                )
            } else {
                status(0, "ok\n", "")
            }
        });
        let shell = ScriptedShell {
            log: Arc::clone(&log),
            responder,
        };
        let body = render_reboot_state(&shell, "exit-1", PHASE_BINARY_FAILURE);
        assert!(body.contains("node: exit-1"), "{body}");
        assert!(body.contains("== systemctl status rustynetd"), "{body}");
        assert!(
            body.contains("rc=3\nActive: failed (Result: exit-code)"),
            "{body}"
        );
        assert!(
            body.contains("rc=1\nDevice \"rustynet-vx0\" does not exist."),
            "{body}"
        );
        assert!(
            body.contains("overlay device rustynet-vx0 does not exist"),
            "{body}"
        );
        assert!(
            !body.contains("private-key"),
            "key-material lines are dropped: {body}"
        );
        let calls = log.lock().unwrap().clone();
        assert_eq!(calls.len(), REBOOT_STATE_COMMANDS.len(), "{calls:?}");
        assert!(
            calls.iter().all(|c| c.starts_with("shell:timeout ")),
            "{calls:?}"
        );
        assert!(
            calls
                .iter()
                .any(|c| c == "shell:timeout 10 ip -o link show dev rustynet-vx0"),
            "{calls:?}"
        );
        assert!(calls.iter().any(|c| c.contains("ls -l /etc/rustynet/lab")));
        assert!(calls.iter().any(|c| c.contains("nft list tables")));
    }

    /// The reboot-state file is written without the diagnostics scrubber, so
    /// none of its commands may print underlay addressing. `ip -d` on the
    /// vxlan link does (`local <addr>` and the underlay device); the plain
    /// form is what the file records.
    #[test]
    fn reboot_state_commands_never_ask_ip_for_link_details() {
        let mut ip_commands = 0usize;
        for (label, argv) in REBOOT_STATE_COMMANDS {
            if !argv.contains(&"ip") {
                continue;
            }
            ip_commands += 1;
            assert!(
                !argv
                    .iter()
                    .any(|arg| matches!(*arg, "-d" | "-detail" | "-details")),
                "{label}: `ip` must not print link details (underlay addressing): {argv:?}"
            );
        }
        assert_eq!(ip_commands, 1, "only the overlay link uses `ip`");
    }

    /// A transport failure ends the capture with a recorded error instead of
    /// burning one transport timeout per remaining command.
    #[test]
    fn reboot_state_capture_stops_at_a_transport_failure() {
        let log: EventLog = Arc::new(Mutex::new(Vec::new()));
        let shell = ScriptedShell {
            log: Arc::clone(&log),
            responder: Arc::new(|_: &[String]| transport_err()),
        };
        let body = render_reboot_state(&shell, "exit-1", PHASE_BINARY_FAILURE);
        assert!(body.contains("capture error:"), "{body}");
        assert!(body.contains("remaining commands skipped"), "{body}");
        assert_eq!(log.lock().unwrap().len(), 1, "only the first command ran");
    }

    /// End to end through the adapter seam: both files land under logs/ (the
    /// shared snapshot and the reboot-state file), mode 0600, and a hostile
    /// alias cannot escape.
    #[cfg(unix)]
    #[test]
    fn live_capture_writes_the_reboot_state_file_privately() {
        use std::os::unix::fs::PermissionsExt;
        let responder: Arc<Responder> = Arc::new(|_: &[String]| status(0, "ok\n", ""));
        let (mut ctx, _log) = live_ctx("capture_files", responder);
        let dir = ctx.report_dir.clone();
        LiveSteps { ctx: &mut ctx }.capture_diagnostics("exit-1", PHASE_BINARY_FAILURE);
        let state = dir.join("logs/diag_reboot-recovery-failure-state_exit-1.txt");
        let body = std::fs::read_to_string(&state).expect("reboot-state file");
        assert!(body.contains("== overlay link =="), "{body}");
        let mode = std::fs::metadata(&state).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert!(
            dir.join("logs/diag_reboot-recovery-failure_exit-1.txt")
                .exists(),
            "the shared node snapshot is captured too"
        );
        LiveSteps { ctx: &mut ctx }.capture_diagnostics("../escape", PHASE_BINARY_FAILURE);
        assert!(!dir.join("escape").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Evidence lines go to this stage's own log and a newline is refused.
    #[test]
    fn live_evidence_lines_land_in_the_stage_log() {
        let responder: Arc<Responder> = Arc::new(|_: &[String]| ok(""));
        let (mut ctx, _log) = live_ctx("evidence", responder);
        let dir = ctx.report_dir.clone();
        let mut steps = LiveSteps { ctx: &mut ctx };
        steps
            .record_evidence("deferred_refresh=verified:exit-1")
            .expect("evidence line");
        assert!(steps.record_evidence("a\nb").is_err());
        let log = std::fs::read_to_string(dir.join("logs/live_reboot_recovery_validation.log"))
            .expect("stage log");
        assert!(log.contains("deferred_refresh=verified:exit-1"), "{log}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
