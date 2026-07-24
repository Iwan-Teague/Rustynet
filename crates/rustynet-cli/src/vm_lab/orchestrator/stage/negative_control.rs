#![allow(dead_code)]
//! # T5 negative-control suite — the adjudication half of the G1 trust bar
//!
//! `NodeEngineAcceptanceSpec_2026-07-23.md` §3-T5 / §5. A2 (the independent
//! evidence verifier) proves a GREEN is *trustworthy*; T5 proves the engine
//! can be **made to fail correctly** — for each injected fault, the specific
//! targeted stage must terminate a NON-pass for the *named* reason
//! (RED-for-the-right-reason). Without T5 an engine that rubber-stamps every
//! stage green would clear the bar.
//!
//! ## The inversion (the load-bearing design constraint)
//!
//! [`StageOutcome`] is binary — there is no "expect-RED" outcome, and
//! `overall_result` is fail-dominated (any hard [`StageOutcome::Failed`] fails
//! the run). So a negative control cannot simply plant a fault and let the
//! target stage fail in the normal pipeline. Instead each control **plants its
//! fault, exercises the targeted operation, and ADJUDICATES that the target's
//! outcome is a non-pass for the specific expected reason**. The control itself
//! returns [`StageOutcome::Passed`] iff the target failed correctly, and
//! [`StageOutcome::Failed`] if the target unexpectedly passed (a fail-open) OR
//! failed for the wrong reason.
//!
//! This binds to the A2 verifier's exit-code semantics
//! (`crates/rustynet-cli/src/bin/live_lab_evidence_verifier.rs`): a
//! correctly-adjudicated RED is a *valid non-pass* (verifier exit 2), distinct
//! from broken evidence (exit 1). A control that passes is asserting the
//! engine produced a valid-non-pass on its targeted stage.
//!
//! ## GUARD — never loosen what counts as a rejection
//!
//! A control asserts REAL fail-closed behavior against the *named* expected
//! rejection. It must never accept "any error", nor accept a weak/wrong
//! rejection to make itself pass — a lenient control is itself a rubber-stamp
//! and is worse than no control. Every adjudicator here distinguishes
//! `RejectedAsExpected` from `RejectedWrongReason` and from
//! `AcceptedButMustReject`, and only the first is a control pass.
//!
//! ## What runs locally vs on a live guest (A3a + the D2 live bodies)
//!
//! - **(b) signed-bundle rejection** and **(d) wrong-node substitution** drive
//!   the real `verify_signed_assignment_state_artifact` verifier against forged
//!   assignment bundles minted in-process — fully local, no guest, so their
//!   [`OrchestrationStage::execute`] adjudicates for real.
//! - **(a) planted residue** and **(c) daemon-killed-mid-stage** inject their
//!   fault on a LIVE Linux guest at execute() time (the D2 bodies in
//!   [`planted_residue`] / [`daemon_kill`], per
//!   `LiveT5NegativeControlProofPlan_2026-07-24.md` §2). Their pure
//!   adjudicators remain the final classifiers; the fail-closed binding
//!   guards layered around them (plant-took, name-bound `Err`, kill-took,
//!   socket-bound probe, unreachable/ambiguous → `Failed`) are unit-tested
//!   here, and the guest-side effects are proven in the live-verify phase.
use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::adapter::linux_traffic::parse_node_clean_probe;
use crate::vm_lab::orchestrator::adapter::node_adapter::NodeAdapter;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};
use std::path::{Path, PathBuf};

// ── The four control StageIds ────────────────────────────────────────────────

/// (b) Signed-bundle rejection — drives `verify_signed_assignment_state_artifact`
/// against a forged-bundle corpus; passes iff every forgery is rejected
/// fail-closed matching its NAMED rejection AND a genuine bundle is accepted.
/// Runs locally.
pub struct NegativeControlSignedBundleRejectionStage;

/// (a) Planted residue → clean-assert FAIL *naming the plant* — plants a
/// `rustynet_planted` nft table on a live Linux guest, drives the REAL
/// [`NodeAdapter::assert_node_clean`] path, and passes iff the assert rejects
/// the node with an error naming that exact table (differential + name-bound,
/// plan §2a). Teardown is Drop-guarded and verified. Live body in
/// [`planted_residue`].
pub struct NegativeControlPlantedResidueStage;

/// (d) Wrong-node substitution → validator FAIL — drives
/// `verify_signed_assignment_state_artifact` with a mismatched
/// `expected_node_id`; passes iff the mismatch is rejected AND the matching id
/// is accepted. Runs locally at the verify-path level (see the
/// orchestrator-threading note on [`NegativeControlWrongNodeSubstitutionStage`]).
pub struct NegativeControlWrongNodeSubstitutionStage;

/// (c) Daemon-killed-mid-stage → daemon-dependent probe not pass — runs ONE
/// guest-side script on a live Linux guest that proves the daemon-socket
/// probe answers, SIGKILLs `rustynetd`, immediately re-probes inside the
/// `RestartSec=2s` self-heal window, and trap-restarts the unit. Passes iff
/// the probe FAILS under the kill (mapped through the pure
/// [`adjudicate_daemon_kill_outcome`]); a probe that answers is a false-green
/// and fails the control. Live body in [`daemon_kill`] (the kill script is
/// re-rendered inline — `live_chaos_daemon_fault_test`'s
/// `render_remote_kill_script` is bin-private and unimportable, plan §2c).
pub struct NegativeControlDaemonKillMidStageStage;

// ── Suite dependency shape ───────────────────────────────────────────────────
//
// The controls are self-contained (offline crypto for b/d; deferred for a/c),
// so they carry no stage dependencies — the opt-in suite can run in a filtered
// plan without a full live topology having been brought up first.
const NO_DEPS: &[StageId] = &[];
const NO_ROLES: &[NodeRole] = &[];

impl OrchestrationStage for NegativeControlSignedBundleRejectionStage {
    fn id(&self) -> StageId {
        StageId::NegativeControlSignedBundleRejection
    }
    fn name(&self) -> &str {
        "negative_control_signed_bundle_rejection"
    }
    fn dependencies(&self) -> &[StageId] {
        NO_DEPS
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        NO_ROLES
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::Once
    }
    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        let dir = control_workdir(ctx, self.name());
        signed_bundle::run_signed_bundle_control(&dir)
    }
}

impl OrchestrationStage for NegativeControlWrongNodeSubstitutionStage {
    fn id(&self) -> StageId {
        StageId::NegativeControlWrongNodeSubstitution
    }
    fn name(&self) -> &str {
        "negative_control_wrong_node_substitution"
    }
    fn dependencies(&self) -> &[StageId] {
        NO_DEPS
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        NO_ROLES
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::Once
    }
    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        let dir = control_workdir(ctx, self.name());
        signed_bundle::run_wrong_node_control(&dir)
    }
}

impl OrchestrationStage for NegativeControlPlantedResidueStage {
    fn id(&self) -> StageId {
        StageId::NegativeControlPlantedResidue
    }
    fn name(&self) -> &str {
        "negative_control_planted_residue"
    }
    fn dependencies(&self) -> &[StageId] {
        NO_DEPS
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        NO_ROLES
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::Once
    }
    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        let dir = control_workdir(ctx, self.name());
        let target = match select_linux_control_target(&ctx.assignments, &|alias| {
            ctx.adapters.get(alias).map(|adapter| adapter.platform())
        }) {
            Ok(alias) => alias.to_owned(),
            Err(reason) => {
                return StageOutcome::Failed(format!("planted-residue negative control: {reason}"));
            }
        };
        let Some(adapter) = ctx.adapters.get(&target) else {
            return StageOutcome::Failed(format!(
                "planted-residue negative control: selected target '{target}' has no adapter \
                 (fail closed)"
            ));
        };
        planted_residue::run_planted_residue_control(&dir, &target, adapter.as_ref())
    }
}

impl OrchestrationStage for NegativeControlDaemonKillMidStageStage {
    fn id(&self) -> StageId {
        StageId::NegativeControlDaemonKillMidStage
    }
    fn name(&self) -> &str {
        "negative_control_daemon_kill_mid_stage"
    }
    fn dependencies(&self) -> &[StageId] {
        NO_DEPS
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        NO_ROLES
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::Once
    }
    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        let dir = control_workdir(ctx, self.name());
        let target = match select_linux_control_target(&ctx.assignments, &|alias| {
            ctx.adapters.get(alias).map(|adapter| adapter.platform())
        }) {
            Ok(alias) => alias.to_owned(),
            Err(reason) => {
                return StageOutcome::Failed(format!("daemon-kill negative control: {reason}"));
            }
        };
        let Some(adapter) = ctx.adapters.get(&target) else {
            return StageOutcome::Failed(format!(
                "daemon-kill negative control: selected target '{target}' has no adapter \
                 (fail closed)"
            ));
        };
        daemon_kill::run_daemon_kill_control(&dir, &target, adapter.as_ref())
    }
}

/// Per-control scratch directory under the run's report dir.
fn control_workdir(ctx: &OrchestrationContext, stage_name: &str) -> PathBuf {
    ctx.report_dir.join("negative_control").join(stage_name)
}

// ── Live-guest control target selection (shared by (a) and (c)) ─────────────

/// Pick the live-guest target for a fault-injection control: a **Linux** node
/// (preferring a `Client` role, the smallest blast radius), fail-closed when
/// none exists.
///
/// Linux is load-bearing, not a preference: the [`NodeAdapter`] trait default
/// for `assert_node_clean` is `Ok(())`, so injecting the fault on a non-Linux
/// target would silently HIDE it and turn the control into a rubber-stamp
/// (plan §8 M1). No Linux adapter ⇒ the control cannot prove anything ⇒
/// `Err` (a control `Failed`), never a skip-to-green.
///
/// Rebuild-set caveat (plan §8 S3): `--rebuild-nodes` is threaded into the
/// cleanup/bootstrap stages at plan-construction time (`plan.rs`), not into
/// [`OrchestrationContext`], so an execute()-time stage cannot read it.
/// Every adapter in `ctx.adapters` belongs to a `--node` assignment of THIS
/// run, and in the default `rebuild_only = None` mode (the mode
/// negative-control runs use) that set IS the rebuild set. The controls'
/// own mandatory, verified teardown (Drop-guarded delete + re-list;
/// trap-restart + restored-unit check) is what protects a node that a
/// `--rebuild-nodes`-restricted later run would not re-clean.
pub(crate) fn select_linux_control_target<'a>(
    assignments: &'a [NodeRoleAssignment],
    platform_of: &dyn Fn(&str) -> Option<VmGuestPlatform>,
) -> Result<&'a str, String> {
    // Prefer a Client; else a non-disruptive Linux role; fall back to a
    // disruptive role (Exit/Anchor/BlindExit/Entry — killing or dirtying one
    // tears down exit NAT / authority, a wider blast radius) only if nothing
    // else is available. (§8 M2)
    let mut preferred: Option<&NodeRoleAssignment> = None;
    let mut last_resort: Option<&NodeRoleAssignment> = None;
    for assignment in assignments {
        if platform_of(&assignment.alias) != Some(VmGuestPlatform::Linux) {
            continue;
        }
        if assignment.role == NodeRole::Client {
            return Ok(assignment.alias.as_str());
        }
        let disruptive = matches!(
            assignment.role,
            NodeRole::Exit | NodeRole::Anchor | NodeRole::BlindExit | NodeRole::Entry
        );
        if disruptive {
            if last_resort.is_none() {
                last_resort = Some(assignment);
            }
        } else if preferred.is_none() {
            preferred = Some(assignment);
        }
    }
    preferred
        .or(last_resort)
        .map(|a| a.alias.as_str())
        .ok_or_else(|| {
            "no assigned node has a Linux adapter; a non-Linux target's default \
             assert_node_clean() is Ok(()) and would silently hide the injected fault \
             (fail closed)"
                .to_owned()
        })
}

/// Write one evidence artifact under the control's workdir. The workdir sits
/// inside the run's report dir, so the pre/post listings and probe
/// transcripts land in the collected evidence (§5 acceptance: the bound
/// strings must be reviewable). A write failure is returned to the caller to
/// fold into a control FAIL — never silently dropped.
fn write_control_evidence(dir: &Path, name: &str, contents: &str) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let path = dir.join(name);
    std::fs::write(&path, contents).map_err(|e| format!("write {}: {e}", path.display()))
}

// ── (a) planted-residue adjudication (pure) ──────────────────────────────────

/// Outcome of adjudicating control (a) against a clean-probe line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ResidueControlOutcome {
    /// The planted residue was detected (the clean-assert parser returned
    /// `Err`). The control PASSES: the residue stage would correctly FAIL.
    ResidueDetected(String),
    /// The parser passed a node that carries planted residue — a fail-OPEN.
    /// The control FAILS: this is exactly the defect the residue control
    /// exists to catch (the historical Pair-1 `rustynet_boot` false-clean).
    FailOpenResidueMissed,
}

impl ResidueControlOutcome {
    pub(crate) fn is_control_pass(&self) -> bool {
        matches!(self, ResidueControlOutcome::ResidueDetected(_))
    }
}

/// Adjudicate control (a): a DIRTY clean-probe output (a leftover `rustynet*`
/// nft table, a daemon still up, or a leftover `rustynet*` interface) MUST
/// drive the pure [`parse_node_clean_probe`] to `Err`. The control passes iff
/// the residue is detected; a probe that reports a residue-carrying node clean
/// is a fail-open and fails the control.
pub(crate) fn adjudicate_planted_residue(dirty_probe_output: &str) -> ResidueControlOutcome {
    match parse_node_clean_probe(dirty_probe_output) {
        Err(err) => ResidueControlOutcome::ResidueDetected(err.to_string()),
        Ok(()) => ResidueControlOutcome::FailOpenResidueMissed,
    }
}

// ── (c) daemon-kill adjudication (pure) ──────────────────────────────────────

/// Outcome of adjudicating control (c) against a stage's recorded outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum KillControlOutcome {
    /// The targeted stage recorded a non-pass terminal state under the
    /// mid-stage kill. The control PASSES.
    StageDidNotPass,
    /// The targeted stage reported `Passed` despite the daemon being killed
    /// mid-stage — a false-green. The control FAILS.
    FalseGreenUnderKill,
}

impl KillControlOutcome {
    pub(crate) fn is_control_pass(&self) -> bool {
        matches!(self, KillControlOutcome::StageDidNotPass)
    }
}

/// Adjudicate control (c): under a mid-stage daemon kill the targeted stage's
/// recorded outcome MUST NOT be a pass. Any non-pass terminal state
/// (`Failed`/`Skipped`/`NotRun`/`Reused`) satisfies the control; a `Passed`
/// under the kill is a false-green and fails the control.
///
/// Note the strictness: a `Reused` outcome is NOT a pass and so satisfies the
/// control, but it must never be *read as* a fresh pass — matching the §4.2
/// terminal-state taxonomy the A2 verifier enforces.
pub(crate) fn adjudicate_daemon_kill_outcome(recorded: &StageOutcome) -> KillControlOutcome {
    match recorded {
        StageOutcome::Passed => KillControlOutcome::FalseGreenUnderKill,
        StageOutcome::Failed(_)
        | StageOutcome::Skipped
        | StageOutcome::NotRun
        | StageOutcome::Reused { .. } => KillControlOutcome::StageDidNotPass,
    }
}

// ── (a) planted-residue live control ─────────────────────────────────────────

pub(crate) mod planted_residue {
    //! The live (a) body: differential, name-bound, Drop-guard-torn-down
    //! (plan §2a, corrected per the §8 review).
    //!
    //! The control runs at its catalog position immediately before `Cleanup`,
    //! when the guest is legitimately DIRTY (daemon up, real `rustynet*`
    //! tables) — so "any `Err` from the clean-probe" is vacuous (§8 B1).
    //! Instead the control plants a distinctly-named `rustynet_planted` nft
    //! table, proves the plant took (differential pre/post listings), drives
    //! the REAL [`NodeAdapter::assert_node_clean`] path, and passes ONLY when
    //! the rejection names that exact table (tolerant of co-present real
    //! dirt, never satisfied by it). Every ambiguous rung — unlistable
    //! tables, pre-existing plant name, un-plantable fault, wrong-reason
    //! `Err`, `Ok(())` fail-open, unverified teardown — is a control FAIL.
    use super::*;
    use crate::vm_lab::orchestrator::remote_shell::{RemoteExitStatus, RemoteShellHost};
    use std::sync::Arc;

    /// The planted table name. Matches the clean-probe's `^rustynet` residue
    /// pattern (so the production probe reports it) while colliding with no
    /// real runtime table (`rustynet_boot`, `rustynet_g<N>`), so the
    /// adjudication can bind to THIS plant and nothing else.
    pub(crate) const PLANTED_TABLE: &str = "rustynet_planted";

    /// `nft` argv for the plant lifecycle. Argv-only via
    /// [`RemoteShellHost::run_argv`], which runs each command under `sudo -n`
    /// with the sudoers `secure_path` (where `/usr/sbin/nft` resolves — the
    /// same trust base as the production reset/probe commands in
    /// `linux_traffic.rs`). Every element is a fixed literal: no run-time
    /// value ever reaches the remote argv.
    const NFT_LIST_TABLES: &[&str] = &["nft", "list", "tables"];
    const NFT_ADD_PLANTED: &[&str] = &["nft", "add", "table", "inet", PLANTED_TABLE];
    const NFT_DELETE_PLANTED: &[&str] = &["nft", "delete", "table", "inet", PLANTED_TABLE];

    /// Decoded output of one remote command.
    pub(crate) struct RemoteCommandOutput {
        pub(crate) code: i32,
        pub(crate) stdout: String,
        pub(crate) stderr: String,
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

    /// Exact-name membership test over `nft list tables` output (lines like
    /// `table inet rustynet_boot`). Exact name + family so a co-present
    /// `rustynet_planted_old`-style leftover can never satisfy (or trip) the
    /// plant checks.
    pub(crate) fn listing_names_inet_table(listing: &str, table: &str) -> bool {
        listing.lines().any(|line| {
            let mut tokens = line.split_whitespace();
            tokens.next() == Some("table")
                && tokens.next() == Some("inet")
                && tokens.next() == Some(table)
        })
    }

    /// Exact-token test for the planted name inside a clean-assert error
    /// message. The probe formatter joins dirty table names with commas
    /// (`nftables table(s): rustynet_planted,rustynet_boot; …`), so split on
    /// the formatter's delimiters and require an exact token — `.contains()`
    /// would let a hypothetical `rustynet_planted_old` leftover satisfy the
    /// name-binding (§4: never soften what counts as the named rejection).
    fn message_names_planted_table(message: &str) -> bool {
        message
            .split(|c: char| c.is_whitespace() || matches!(c, ',' | ';' | ':'))
            .any(|token| token == PLANTED_TABLE)
    }

    /// Final classification of the LIVE `assert_node_clean` result under the
    /// plant — the same layering as [`signed_bundle::classify_rejection`]:
    /// the pure fail-open taxonomy decides pass/fail shape, the name-binding
    /// decides *right reason*. Coherence with the pure adjudicator
    /// [`adjudicate_planted_residue`] (identical fail-open posture; the `Err`
    /// text classified here is exactly what that adjudicator's parser
    /// produces) is pinned by
    /// `live_classifier_binds_to_the_pure_residue_adjudicator`.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) enum PlantedAssertCheck {
        /// `Err` naming the planted table — RED for the right reason
        /// (co-present real dirt in the same message is tolerated). The
        /// control PASSES.
        DetectedNamingPlant { message: String },
        /// `Err` NOT naming the plant: the node was rejected only for other
        /// reasons, so the probe did not demonstrably catch OUR fault. The
        /// control FAILS (guard: "any error" is never accepted).
        DetectedWrongReason { actual: String },
        /// `Ok(())` on a node verifiably carrying the plant — a fail-OPEN,
        /// the exact Pair-1 false-clean class. The control FAILS.
        FailOpenPassedPlantedNode,
    }

    impl PlantedAssertCheck {
        pub(crate) fn is_control_pass(&self) -> bool {
            matches!(self, PlantedAssertCheck::DetectedNamingPlant { .. })
        }
    }

    pub(crate) fn classify_planted_clean_assert(result: Result<(), String>) -> PlantedAssertCheck {
        match result {
            Ok(()) => PlantedAssertCheck::FailOpenPassedPlantedNode,
            Err(message) if message_names_planted_table(&message) => {
                PlantedAssertCheck::DetectedNamingPlant { message }
            }
            Err(actual) => PlantedAssertCheck::DetectedWrongReason { actual },
        }
    }

    /// Adjudicate teardown. Absence in the post-delete re-list is the
    /// AUTHORITATIVE fact: a missing-table delete error is idempotence, not
    /// failure, iff the re-list proves the table absent; an unverifiable
    /// re-list fails closed; a present table is a LEAK named loudly.
    pub(crate) fn adjudicate_teardown(
        delete_exit: i32,
        delete_stderr: &str,
        relist_after_delete: &Result<String, String>,
    ) -> Result<(), String> {
        match relist_after_delete {
            Err(err) => Err(format!(
                "teardown unverifiable (fail closed): could not re-list nft tables after \
                 deleting '{PLANTED_TABLE}': {err}"
            )),
            Ok(listing) if listing_names_inet_table(listing, PLANTED_TABLE) => Err(format!(
                "TEARDOWN LEAK: planted nft table '{PLANTED_TABLE}' is still present after \
                 delete (delete exit {delete_exit}, stderr: {:?}) — the guest is left dirty",
                delete_stderr.trim()
            )),
            Ok(_) => Ok(()),
        }
    }

    /// Deletes the planted table when the control unwinds. `panic = "unwind"`
    /// (the workspace sets no `panic = "abort"` profile), so `Drop` runs on
    /// unwind and a panic between plant and teardown still removes the table
    /// best-effort (§8 S3). The normal path calls [`Self::teardown_verified`]
    /// — delete + re-list + [`adjudicate_teardown`], folded into the verdict
    /// — after which `Drop` is a no-op. `Drop` itself must never panic (a
    /// second panic during unwind aborts the process), so it swallows every
    /// error.
    pub(crate) struct PlantedTableGuard {
        shell: Arc<dyn RemoteShellHost>,
        torn_down: bool,
    }

    impl PlantedTableGuard {
        fn new(shell: Arc<dyn RemoteShellHost>) -> Self {
            PlantedTableGuard {
                shell,
                torn_down: false,
            }
        }

        /// Explicit, verified teardown. Marks the guard done regardless of
        /// the verdict: the delete has been attempted, and re-attempting it
        /// from `Drop` cannot improve on a verified failure that the control
        /// is already reporting loudly.
        fn teardown_verified(&mut self) -> (String, Result<(), String>) {
            let delete = match run_remote_argv(&self.shell, NFT_DELETE_PLANTED) {
                Ok(out) => out,
                Err(err) => {
                    // §8 M1: transport failure — the delete argv may never have
                    // run; leave `torn_down` false so Drop still best-effort
                    // retries the delete on unwind.
                    return (
                        format!("## nft delete table inet {PLANTED_TABLE}\n{err}\n"),
                        Err(format!("teardown unverifiable (fail closed): {err}")),
                    );
                }
            };
            // §8 M1: the delete argv executed (any exit code) — mark done; a
            // Drop retry cannot improve on the verified verdict reported below.
            self.torn_down = true;
            let relist = run_remote_argv(&self.shell, NFT_LIST_TABLES);
            let relist_result: Result<String, String> = match &relist {
                Ok(out) if out.code == 0 => Ok(out.stdout.clone()),
                Ok(out) => Err(format!(
                    "re-list exited {} (stderr: {:?})",
                    out.code,
                    out.stderr.trim()
                )),
                Err(err) => Err(err.clone()),
            };
            let verdict = adjudicate_teardown(delete.code, &delete.stderr, &relist_result);
            let mut evidence = delete.render(&format!("nft delete table inet {PLANTED_TABLE}"));
            match &relist {
                Ok(out) => evidence.push_str(&out.render("nft list tables (after teardown)")),
                Err(err) => {
                    evidence.push_str(&format!("## nft list tables (after teardown)\n{err}\n"))
                }
            }
            evidence.push_str(&format!("## teardown verdict\n{verdict:?}\n"));
            (evidence, verdict)
        }
    }

    impl Drop for PlantedTableGuard {
        fn drop(&mut self) {
            if self.torn_down {
                return;
            }
            // Unwind path: best-effort delete; swallow every error — this
            // Drop must never panic.
            let _ = self.shell.run_argv(NFT_DELETE_PLANTED, &[], &[]);
        }
    }

    /// The (a) control body. See the module doc for the mechanism; the
    /// verdict inversion (`negative_control.rs` header) means the induced
    /// clean-assert RED stays inside this control — a working control returns
    /// [`StageOutcome::Passed`].
    pub(crate) fn run_planted_residue_control(
        workdir: &Path,
        target_alias: &str,
        adapter: &dyn NodeAdapter,
    ) -> StageOutcome {
        let fail = |reason: String| {
            StageOutcome::Failed(format!(
                "planted-residue negative control [target {target_alias}]: {reason}"
            ))
        };

        // §8 M1: the fault is only observable through the Linux clean-probe;
        // a non-Linux adapter's default assert_node_clean() is Ok(()) and
        // would read as a fail-open. The selector already filtered — this
        // re-assert makes a future selector regression fail loudly instead of
        // hiding the fault.
        if adapter.platform() != VmGuestPlatform::Linux {
            return fail(format!(
                "target platform {:?} cannot observe the fault: the non-Linux \
                 assert_node_clean() default is Ok(()) (fail closed)",
                adapter.platform()
            ));
        }

        let shell = match adapter.shell_host() {
            Ok(shell) => shell,
            Err(err) => return fail(format!("no remote shell host: {err}")),
        };

        // 1. Pre-list: the planted name must NOT already exist.
        let pre = match run_remote_argv(&shell, NFT_LIST_TABLES) {
            Ok(out) => out,
            Err(err) => return fail(err),
        };
        if let Err(err) = write_control_evidence(
            workdir,
            "nft_tables_before_plant.txt",
            &pre.render("nft list tables (before plant)"),
        ) {
            return fail(err);
        }
        if pre.code != 0 {
            return fail(format!(
                "cannot enumerate nft tables (exit {}, stderr: {:?}) — the guest is \
                 unverifiable (fail closed)",
                pre.code,
                pre.stderr.trim()
            ));
        }
        if listing_names_inet_table(&pre.stdout, PLANTED_TABLE) {
            return fail(format!(
                "ambiguous leftover: nft table '{PLANTED_TABLE}' already exists before \
                 planting (a prior control leaked, or the name is in real use) — refusing \
                 to adjudicate"
            ));
        }

        // 2. Plant — Drop guard registered FIRST, so even an ambiguous
        //    transport error (or a later panic) still deletes best-effort.
        let mut guard = PlantedTableGuard::new(Arc::clone(&shell));
        let plant = match run_remote_argv(&shell, NFT_ADD_PLANTED) {
            Ok(out) => out,
            Err(err) => return fail(err),
        };
        if plant.code != 0 {
            return fail(format!(
                "un-plantable fault: `nft add table inet {PLANTED_TABLE}` exited {} \
                 (stderr: {:?}) (fail closed)",
                plant.code,
                plant.stderr.trim()
            ));
        }

        // 3. Re-list: the plant must verifiably be present.
        let planted = match run_remote_argv(&shell, NFT_LIST_TABLES) {
            Ok(out) => out,
            Err(err) => return fail(err),
        };
        if let Err(err) = write_control_evidence(
            workdir,
            "nft_tables_after_plant.txt",
            &planted.render("nft list tables (after plant)"),
        ) {
            return fail(err);
        }
        if planted.code != 0 {
            return fail(format!(
                "plant unverifiable: post-plant `nft list tables` exited {} (stderr: {:?}) \
                 (fail closed)",
                planted.code,
                planted.stderr.trim()
            ));
        }
        if !listing_names_inet_table(&planted.stdout, PLANTED_TABLE) {
            return fail(format!(
                "un-plantable fault: '{PLANTED_TABLE}' is absent from the post-plant \
                 listing (fail closed)"
            ));
        }

        // 4. Drive the REAL cleanup-time assertion under the plant. From here
        //    there is NO early return: teardown must run and be verified on
        //    every path.
        let mut evidence_errors: Vec<String> = Vec::new();
        let assert_result = adapter.assert_node_clean().map_err(|e| e.to_string());
        let assert_rendering = match &assert_result {
            Ok(()) => "assert_node_clean() = Ok(()) — the probe PASSED a node carrying \
                       the plant (fail-open)"
                .to_owned(),
            Err(err) => format!("assert_node_clean() = Err: {err}"),
        };
        if let Err(err) =
            write_control_evidence(workdir, "clean_assert_under_plant.txt", &assert_rendering)
        {
            evidence_errors.push(err);
        }
        let check = classify_planted_clean_assert(assert_result);

        // 5. Verified teardown — a leak or an unverifiable delete dominates
        //    every other verdict (a control that dirties the fleet must never
        //    pass).
        let (teardown_evidence, teardown_verdict) = guard.teardown_verified();
        if let Err(err) = write_control_evidence(workdir, "teardown.txt", &teardown_evidence) {
            evidence_errors.push(err);
        }
        if let Err(err) = teardown_verdict {
            return fail(format!("{err}; clean-assert adjudication was {check:?}"));
        }
        if !evidence_errors.is_empty() {
            return fail(format!(
                "evidence not persisted: {} (fail closed; §5 acceptance requires \
                 reviewable evidence)",
                evidence_errors.join("; ")
            ));
        }

        match check {
            PlantedAssertCheck::DetectedNamingPlant { .. } => StageOutcome::Passed,
            PlantedAssertCheck::DetectedWrongReason { actual } => fail(format!(
                "clean-assert rejected the node for the WRONG reason — the error does not \
                 name '{PLANTED_TABLE}': {actual:?}"
            )),
            PlantedAssertCheck::FailOpenPassedPlantedNode => fail(format!(
                "FAIL-OPEN — assert_node_clean() returned Ok(()) on a node verifiably \
                 carrying planted nft table '{PLANTED_TABLE}' (the exact false-clean class \
                 this control exists to catch)"
            )),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        // ── listing parser ──────────────────────────────────────────────────

        #[test]
        fn listing_parser_finds_exact_inet_table() {
            let listing = "table ip filter\ntable inet rustynet_boot\ntable inet rustynet_planted\ntable ip6 mangle\n";
            assert!(listing_names_inet_table(listing, PLANTED_TABLE));
            assert!(listing_names_inet_table(listing, "rustynet_boot"));
            assert!(!listing_names_inet_table(listing, "filter"));
        }

        #[test]
        fn listing_parser_binds_to_the_exact_name_and_family() {
            // A prefix/suffix cousin or a non-inet family must never satisfy
            // the plant checks.
            assert!(!listing_names_inet_table(
                "table inet rustynet_planted_old\n",
                PLANTED_TABLE
            ));
            assert!(!listing_names_inet_table(
                "table inet rustynet_plant\n",
                PLANTED_TABLE
            ));
            assert!(!listing_names_inet_table(
                "table ip rustynet_planted\n",
                PLANTED_TABLE
            ));
            assert!(!listing_names_inet_table("", PLANTED_TABLE));
        }

        // ── live clean-assert classifier ────────────────────────────────────

        #[test]
        fn err_naming_the_plant_passes_even_with_co_present_real_dirt() {
            let message = "node still dirty after cleanup: nftables table(s): \
                           rustynet_planted,rustynet_boot; rustynetd or rustynet-relay \
                           still running; interface(s): rustynet0";
            let check = classify_planted_clean_assert(Err(message.to_owned()));
            assert!(check.is_control_pass(), "got {check:?}");
        }

        #[test]
        fn guard_err_not_naming_the_plant_is_wrong_reason_not_a_pass() {
            // The control runs on a legitimately dirty guest (§8 B1): a real
            // rustynet_boot rejection WITHOUT the plant must never satisfy it.
            let message = "node still dirty after cleanup: nftables table(s): \
                           rustynet_boot; rustynetd or rustynet-relay still running";
            let check = classify_planted_clean_assert(Err(message.to_owned()));
            assert!(
                matches!(check, PlantedAssertCheck::DetectedWrongReason { .. }),
                "got {check:?}"
            );
            assert!(!check.is_control_pass());
        }

        #[test]
        fn guard_name_binding_is_exact_not_substring() {
            // A message naming only a cousin table carries the planted name as
            // a SUBSTRING; the classifier must not be satisfied by it.
            let message = "node still dirty after cleanup: nftables table(s): \
                           rustynet_planted_old";
            let check = classify_planted_clean_assert(Err(message.to_owned()));
            assert!(
                matches!(check, PlantedAssertCheck::DetectedWrongReason { .. }),
                "got {check:?}"
            );
        }

        #[test]
        fn guard_ok_on_a_planted_node_is_fail_open_not_a_pass() {
            let check = classify_planted_clean_assert(Ok(()));
            assert_eq!(check, PlantedAssertCheck::FailOpenPassedPlantedNode);
            assert!(!check.is_control_pass());
        }

        #[test]
        fn live_classifier_binds_to_the_pure_residue_adjudicator() {
            // The live path classifies the Err STRING that
            // `assert_node_clean` surfaces, which is produced by the same
            // parser the pure adjudicator wraps. Drive the pure adjudicator
            // with a planted-and-dirty probe line and prove its error is (1)
            // the documented formatter shape and (2) classified as the named
            // detection here — so a formatter rename cannot silently
            // downgrade the live control to DetectedWrongReason.
            let dirty_probe = "nft=rustynet_planted,rustynet_boot, daemon=up iface=rustynet0,";
            let outcome = adjudicate_planted_residue(dirty_probe);
            let ResidueControlOutcome::ResidueDetected(message) = outcome else {
                panic!("pure adjudicator must detect the planted residue, got {outcome:?}");
            };
            assert!(
                message.contains("node still dirty after cleanup:"),
                "formatter prefix drifted (§8 M5): {message}"
            );
            let check = classify_planted_clean_assert(Err(message));
            assert!(
                matches!(check, PlantedAssertCheck::DetectedNamingPlant { .. }),
                "got {check:?}"
            );
        }

        // ── teardown adjudication ───────────────────────────────────────────

        #[test]
        fn teardown_deleted_and_absent_is_ok() {
            let relist = Ok("table inet rustynet_boot\n".to_owned());
            assert_eq!(adjudicate_teardown(0, "", &relist), Ok(()));
        }

        #[test]
        fn teardown_missing_table_delete_error_is_idempotent_when_absent() {
            // `nft delete` on an already-absent table errors; absence in the
            // authoritative re-list makes that idempotence, not failure.
            let relist = Ok("table inet rustynet_boot\n".to_owned());
            assert_eq!(
                adjudicate_teardown(
                    1,
                    "Error: Could not process rule: No such file or directory",
                    &relist
                ),
                Ok(())
            );
        }

        #[test]
        fn guard_teardown_leak_fails_naming_the_table() {
            let relist = Ok(format!("table inet {PLANTED_TABLE}\n"));
            let err = adjudicate_teardown(0, "", &relist).expect_err("leak must fail");
            assert!(err.contains("TEARDOWN LEAK"), "got: {err}");
            assert!(err.contains(PLANTED_TABLE), "got: {err}");
        }

        #[test]
        fn guard_unverifiable_teardown_fails_closed() {
            let relist = Err(
                "transport failure running [\"nft\", \"list\", \"tables\"]: \
                              transport error"
                    .to_owned(),
            );
            let err = adjudicate_teardown(0, "", &relist).expect_err("must fail closed");
            assert!(err.contains("teardown unverifiable"), "got: {err}");
        }
    }
}

// ── (c) daemon-kill live control ─────────────────────────────────────────────

pub(crate) mod daemon_kill {
    //! The live (c) body: one guest-side kill-window script + a socket-bound
    //! probe (plan §2c, corrected per the §8 review).
    //!
    //! `ctx.outcome_of` only sees stages that already ran with the daemon
    //! alive (§8 B2), and a mesh ping keeps working with `rustynetd` dead
    //! (kernel WireGuard) — so the control runs ITS OWN probe whose success
    //! requires a live daemon: `rustynet status` against the daemon control
    //! socket (`RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock`), the
    //! same §4.7 identity-challenge query `query_live_identity` uses, chosen
    //! precisely because "a hung/absent daemon must FAIL the challenge". Only
    //! CONNECTIVITY (the probe's exit status) is adjudicated — no status
    //! field, and explicitly never `path_live_proven` (a shared-transport
    //! reporting artifact that is false even on healthy tunnels, §8 M3).
    //!
    //! The whole sequence is ONE script (baseline-prove → SIGKILL → immediate
    //! re-probe inside the `Restart=on-failure`/`RestartSec=2s` self-heal
    //! window → trap-restart) so no SSH round-trip can straddle the window.
    //! It is re-rendered inline because `live_chaos_daemon_fault_test`'s
    //! `render_remote_kill_script` is bin-private and unimportable; the trap
    //! prologue mirrors that audited script.
    use super::*;
    use std::collections::HashMap;

    /// Fixed guest-side identities the script binds to. Unit tests pin the
    /// script text to these consts so they cannot drift apart.
    pub(crate) const RUSTYNETD_UNIT: &str = "rustynetd";
    pub(crate) const DAEMON_SOCKET_PATH: &str = "/run/rustynet/rustynetd.sock";
    pub(crate) const RUSTYNET_CLI_PATH: &str = "/usr/local/bin/rustynet";

    /// The kill-window script. Executed as `sh -c <script>` via
    /// [`RemoteShellHost::run_argv`] (which wraps it in `sudo -n`, so it runs
    /// as root: `systemctl` and the root-owned daemon socket need no further
    /// escalation). Every value is a fixed literal — no run-time value is
    /// interpolated. The script always exits 0 and reports through `nc_*`
    /// tokens; a non-zero exit is script infrastructure failure, which the
    /// parser refuses to adjudicate.
    ///
    /// Sequencing invariants (pinned by tests):
    /// 1. the restart trap is registered BEFORE the fault;
    /// 2. baseline (`is-active` + socket probe answers) is proven BEFORE the
    ///    kill — a post-kill probe failure is otherwise unbindable to the
    ///    kill (§8 S4);
    /// 3. the re-probe runs IMMEDIATELY after `systemctl kill -s KILL`
    ///    (inside the 2s `RestartSec` window; a unix-socket connect to a dead
    ///    listener fails in milliseconds);
    /// 4. the unit is restarted and awaited at the end regardless of outcome.
    pub(crate) const KILL_WINDOW_SCRIPT: &str = r#"set -u
unit=rustynetd
socket=/run/rustynet/rustynetd.sock
cli=/usr/local/bin/rustynet
finish() {
  systemctl start "$unit" >/dev/null 2>&1 || true
}
trap finish EXIT
printf 'nc_teardown_registered=true\n'
if [ ! -x "$cli" ]; then
  printf 'nc_abort=cli_missing\n'
  exit 0
fi
base_state="$(systemctl is-active "$unit" 2>/dev/null || true)"
printf 'nc_baseline_unit=%s\n' "${base_state:-unknown}"
if [ "$base_state" != "active" ]; then
  printf 'nc_abort=baseline_unit_not_active\n'
  exit 0
fi
base_out="$(RUSTYNET_DAEMON_SOCKET="$socket" "$cli" status 2>&1)"
base_rc=$?
if [ "$base_rc" -eq 0 ]; then
  printf 'nc_baseline_probe=answered\n'
else
  printf 'nc_baseline_probe=failed\n'
  printf 'nc_baseline_probe_detail=%s\n' "$(printf '%s' "$base_out" | head -n 1 | tr -d '\r' | cut -c1-200)"
  printf 'nc_abort=baseline_probe_failed\n'
  exit 0
fi
kill_unix="$(date +%s)"
systemctl kill -s KILL "$unit"
kill_rc=$?
printf 'nc_kill_exit=%s\n' "$kill_rc"
printf 'nc_kill_unix=%s\n' "$kill_unix"
if [ "$kill_rc" -ne 0 ]; then
  printf 'nc_abort=kill_not_taken\n'
  exit 0
fi
probe_out="$(RUSTYNET_DAEMON_SOCKET="$socket" "$cli" status 2>&1)"
probe_rc=$?
probe_done_unix="$(date +%s)"
if [ "$probe_rc" -eq 0 ]; then
  printf 'nc_probe_under_kill=answered\n'
else
  printf 'nc_probe_under_kill=failed\n'
fi
printf 'nc_probe_exit=%s\n' "$probe_rc"
printf 'nc_probe_done_unix=%s\n' "$probe_done_unix"
printf 'nc_probe_detail=%s\n' "$(printf '%s' "$probe_out" | head -n 1 | tr -d '\r' | cut -c1-200)"
post_state="$(systemctl is-active "$unit" 2>/dev/null || true)"
printf 'nc_post_kill_unit=%s\n' "${post_state:-unknown}"
systemctl start "$unit" >/dev/null 2>&1 || true
tries=0
while [ "$tries" -lt 30 ]; do
  if systemctl is-active --quiet "$unit"; then
    break
  fi
  tries=$((tries+1))
  sleep 1
done
final_state="$(systemctl is-active "$unit" 2>/dev/null || true)"
printf 'nc_final_unit=%s\n' "${final_state:-unknown}"
exit 0
"#;

    /// What the kill-window transcript proves. Only the two probe outcomes
    /// carry adjudicable meaning; everything else is fail-closed.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) enum KillWindowObservation {
        /// Baseline proven, kill taken, probe transport-successful and FAILED
        /// — the daemon was dead when a daemon-dependent operation ran.
        ProbeFailedUnderKill { detail: String },
        /// Baseline proven, kill taken, probe ANSWERED under the kill.
        ProbeAnsweredUnderKill { detail: String },
        /// Anything else: baseline not applicable, kill not taken, tokens
        /// missing/garbled, script infra failure, node not restored. NEVER
        /// fed to the adjudicator (plan §2c: an SSH/transport/ambiguous
        /// result is a control FAIL, not a stage outcome).
        NotAdjudicable { reason: String },
    }

    /// Parse the script's `nc_*` token transcript, fail-closed at every hole.
    pub(crate) fn parse_kill_window_transcript(
        exit_code: i32,
        transcript: &str,
    ) -> KillWindowObservation {
        let not_adjudicable = |reason: String| KillWindowObservation::NotAdjudicable { reason };
        if exit_code != 0 {
            return not_adjudicable(format!(
                "kill-window script infrastructure failed (exit {exit_code})"
            ));
        }
        let mut tokens: HashMap<&str, &str> = HashMap::new();
        for line in transcript.lines() {
            if let Some((key, value)) = line.trim().split_once('=')
                && key.starts_with("nc_")
            {
                tokens.insert(key, value);
            }
        }
        let tok = |key: &str| tokens.get(key).copied();

        if let Some(abort) = tok("nc_abort") {
            return not_adjudicable(match abort {
                "cli_missing" => format!(
                    "control CLI {RUSTYNET_CLI_PATH} is missing on the guest — the \
                     daemon-dependent probe cannot run"
                ),
                "baseline_unit_not_active" => format!(
                    "baseline not applicable: {RUSTYNETD_UNIT} is '{}' (must be active for \
                     the kill to be meaningful, §8 S4)",
                    tok("nc_baseline_unit").unwrap_or("unknown")
                ),
                "baseline_probe_failed" => format!(
                    "baseline not applicable: the daemon-socket probe failed BEFORE the \
                     kill ({:?}) — a post-kill probe failure could not be bound to the kill",
                    tok("nc_baseline_probe_detail").unwrap_or("")
                ),
                "kill_not_taken" => format!(
                    "kill not taken: `systemctl kill -s KILL` exited {}",
                    tok("nc_kill_exit").unwrap_or("unknown")
                ),
                other => format!("script aborted: {other}"),
            });
        }
        if tok("nc_teardown_registered") != Some("true") {
            return not_adjudicable(
                "restart trap was not registered before the fault (transcript missing \
                 nc_teardown_registered=true)"
                    .to_owned(),
            );
        }
        // Belt-and-braces re-checks: the abort tokens above are the primary
        // gate; a transcript that skipped them without asserting these is
        // garbled and must not be adjudicated.
        if tok("nc_baseline_unit") != Some("active") {
            return not_adjudicable(format!(
                "garbled transcript: nc_baseline_unit={:?}",
                tok("nc_baseline_unit")
            ));
        }
        if tok("nc_baseline_probe") != Some("answered") {
            return not_adjudicable(format!(
                "garbled transcript: nc_baseline_probe={:?}",
                tok("nc_baseline_probe")
            ));
        }
        if tok("nc_kill_exit") != Some("0") {
            return not_adjudicable(format!(
                "garbled transcript: nc_kill_exit={:?}",
                tok("nc_kill_exit")
            ));
        }
        // Restore is mandatory + verified (teardown bar): a control that
        // leaves the daemon dead must fail even when the probe behaved.
        if tok("nc_final_unit") != Some("active") {
            return not_adjudicable(format!(
                "node not restored: {RUSTYNETD_UNIT} is {:?} after the trap-restart \
                 (probe result was {:?})",
                tok("nc_final_unit").unwrap_or("<missing>"),
                tok("nc_probe_under_kill").unwrap_or("<missing>")
            ));
        }

        let Some(probe_exit) = tok("nc_probe_exit") else {
            return not_adjudicable("garbled transcript: nc_probe_exit missing".to_owned());
        };
        let detail = tok("nc_probe_detail")
            .unwrap_or("(no probe detail captured)")
            .to_owned();
        match tok("nc_probe_under_kill") {
            Some("failed") => {
                if probe_exit == "0" {
                    return not_adjudicable(
                        "garbled transcript: nc_probe_under_kill=failed but nc_probe_exit=0"
                            .to_owned(),
                    );
                }
                KillWindowObservation::ProbeFailedUnderKill {
                    detail: format!("probe exit {probe_exit}: {detail}"),
                }
            }
            Some("answered") => {
                if probe_exit != "0" {
                    return not_adjudicable(format!(
                        "garbled transcript: nc_probe_under_kill=answered but \
                         nc_probe_exit={probe_exit}"
                    ));
                }
                KillWindowObservation::ProbeAnsweredUnderKill { detail }
            }
            other => not_adjudicable(format!(
                "probe result token missing/unrecognised: {other:?}"
            )),
        }
    }

    /// Fold the observation into the control verdict. ONLY the two
    /// transport-successful probe outcomes are mapped into a [`StageOutcome`]
    /// and adjudicated by the pure [`adjudicate_daemon_kill_outcome`] (the
    /// final classifier); every other observation fails the control WITHOUT
    /// consulting the adjudicator — so a transport failure can never be
    /// laundered into a `StageDidNotPass` control pass.
    pub(crate) fn kill_control_verdict(observation: KillWindowObservation) -> StageOutcome {
        match observation {
            KillWindowObservation::ProbeFailedUnderKill { detail } => {
                let recorded = StageOutcome::Failed(format!(
                    "daemon-socket probe failed under mid-stage SIGKILL ({detail})"
                ));
                match adjudicate_daemon_kill_outcome(&recorded) {
                    KillControlOutcome::StageDidNotPass => StageOutcome::Passed,
                    // Defensive: unreachable for a Failed input today, but a
                    // future adjudicator regression must fail the control,
                    // never panic a live run.
                    KillControlOutcome::FalseGreenUnderKill => StageOutcome::Failed(
                        "adjudicator classified a Failed probe outcome as a false-green \
                         (adjudication regression; fail closed)"
                            .to_owned(),
                    ),
                }
            }
            KillWindowObservation::ProbeAnsweredUnderKill { detail } => {
                match adjudicate_daemon_kill_outcome(&StageOutcome::Passed) {
                    KillControlOutcome::FalseGreenUnderKill => StageOutcome::Failed(format!(
                        "FALSE-GREEN — the daemon-socket probe ANSWERED under a mid-stage \
                         SIGKILL ({detail}); a daemon-dependent stage could record a pass \
                         with {RUSTYNETD_UNIT} dead"
                    )),
                    KillControlOutcome::StageDidNotPass => StageOutcome::Failed(
                        "adjudicator accepted a Passed-under-kill as a non-pass \
                         (adjudication regression; fail closed)"
                            .to_owned(),
                    ),
                }
            }
            KillWindowObservation::NotAdjudicable { reason } => StageOutcome::Failed(format!(
                "not adjudicable — {reason}; the fault was not provably injected and \
                 bound, so no outcome is fed to the adjudicator (fail closed)"
            )),
        }
    }

    /// The (c) control body. A working control returns
    /// [`StageOutcome::Passed`] (the induced probe-RED stays inside the
    /// control, §5).
    pub(crate) fn run_daemon_kill_control(
        workdir: &Path,
        target_alias: &str,
        adapter: &dyn NodeAdapter,
    ) -> StageOutcome {
        let fail = |reason: String| {
            StageOutcome::Failed(format!(
                "daemon-kill negative control [target {target_alias}]: {reason}"
            ))
        };

        // The script's unit/socket/CLI paths are the LINUX daemon contract;
        // on any other platform the fault would be unbindable.
        if adapter.platform() != VmGuestPlatform::Linux {
            return fail(format!(
                "target platform {:?} cannot run the systemd kill-window script (fail closed)",
                adapter.platform()
            ));
        }

        let shell = match adapter.shell_host() {
            Ok(shell) => shell,
            Err(err) => return fail(format!("no remote shell host: {err}")),
        };
        if let Err(err) =
            write_control_evidence(workdir, "kill_window_script.sh", KILL_WINDOW_SCRIPT)
        {
            return fail(err);
        }
        let status = match shell.run_argv(&["sh", "-c", KILL_WINDOW_SCRIPT], &[], &[]) {
            Ok(status) => status,
            Err(err) => {
                return fail(format!(
                    "transport failure running the kill-window script: {err} — control \
                     FAILED without adjudication (a transport failure is never mapped to \
                     a stage outcome)"
                ));
            }
        };
        let stdout = String::from_utf8_lossy(&status.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&status.stderr).into_owned();
        if let Err(err) = write_control_evidence(
            workdir,
            "kill_window_transcript.txt",
            &format!(
                "exit={}\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}\n",
                status.code
            ),
        ) {
            return fail(err);
        }
        match kill_control_verdict(parse_kill_window_transcript(status.code, &stdout)) {
            StageOutcome::Failed(reason) => fail(reason),
            other => other,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        // ── script invariants ───────────────────────────────────────────────

        #[test]
        fn script_binds_to_the_fixed_unit_socket_and_cli() {
            assert!(KILL_WINDOW_SCRIPT.contains(&format!("unit={RUSTYNETD_UNIT}\n")));
            assert!(KILL_WINDOW_SCRIPT.contains(&format!("socket={DAEMON_SOCKET_PATH}\n")));
            assert!(KILL_WINDOW_SCRIPT.contains(&format!("cli={RUSTYNET_CLI_PATH}\n")));
            // Socket-bound probe (§8 M3): the daemon control socket, never a
            // status field — path_live_proven must not appear.
            assert!(
                KILL_WINDOW_SCRIPT.contains("RUSTYNET_DAEMON_SOCKET=\"$socket\" \"$cli\" status")
            );
            assert!(!KILL_WINDOW_SCRIPT.contains("path_live_proven"));
        }

        #[test]
        fn script_sequences_trap_baseline_kill_probe_restart() {
            let idx = |needle: &str| {
                KILL_WINDOW_SCRIPT
                    .find(needle)
                    .unwrap_or_else(|| panic!("script must contain {needle:?}"))
            };
            let trap = idx("trap finish EXIT");
            let baseline_probe = idx("nc_baseline_probe=");
            let kill = idx("systemctl kill -s KILL");
            let probe_under_kill = idx("nc_probe_under_kill=");
            // First occurrence of the restart command is the trap function
            // body (registered up top); the LAST is the explicit end-of-script
            // restart.
            let restart = KILL_WINDOW_SCRIPT
                .rfind("systemctl start \"$unit\"")
                .expect("script must contain the explicit restart");
            assert!(
                trap < kill,
                "restart trap must be registered before the fault"
            );
            assert!(
                baseline_probe < kill,
                "baseline must be proven before the kill (§8 S4)"
            );
            assert!(
                kill < probe_under_kill,
                "the adjudicated probe must run after the kill"
            );
            assert!(probe_under_kill < restart, "explicit restart comes last");
            // The re-probe is IMMEDIATE: nothing sleeps between the kill and
            // the probe (the 2s RestartSec window must not be slept away).
            let window = &KILL_WINDOW_SCRIPT[kill..probe_under_kill];
            assert!(
                !window.contains("sleep"),
                "no sleep may sit inside the kill window: {window}"
            );
        }

        // ── transcript parsing ──────────────────────────────────────────────

        fn transcript(probe: &str, probe_exit: &str, final_unit: &str) -> String {
            format!(
                "nc_teardown_registered=true\n\
                 nc_baseline_unit=active\n\
                 nc_baseline_probe=answered\n\
                 nc_kill_exit=0\n\
                 nc_kill_unix=1780000000\n\
                 nc_probe_under_kill={probe}\n\
                 nc_probe_exit={probe_exit}\n\
                 nc_probe_done_unix=1780000001\n\
                 nc_probe_detail=error: connect to daemon socket \
                 /run/rustynet/rustynetd.sock: Connection refused\n\
                 nc_post_kill_unit=activating\n\
                 nc_final_unit={final_unit}\n"
            )
        }

        #[test]
        fn probe_failed_under_kill_is_adjudicable_and_passes_the_control() {
            let obs = parse_kill_window_transcript(0, &transcript("failed", "1", "active"));
            let KillWindowObservation::ProbeFailedUnderKill { detail } = &obs else {
                panic!("expected ProbeFailedUnderKill, got {obs:?}");
            };
            assert!(detail.contains("Connection refused"), "got: {detail}");
            // The pure adjudicator is the final classifier: a Failed recorded
            // outcome is StageDidNotPass, so the control passes.
            assert_eq!(
                adjudicate_daemon_kill_outcome(&StageOutcome::Failed("probe failed".to_owned())),
                KillControlOutcome::StageDidNotPass
            );
            assert_eq!(kill_control_verdict(obs), StageOutcome::Passed);
        }

        #[test]
        fn guard_probe_answered_under_kill_is_a_false_green_control_fails() {
            let obs = parse_kill_window_transcript(0, &transcript("answered", "0", "active"));
            assert!(matches!(
                obs,
                KillWindowObservation::ProbeAnsweredUnderKill { .. }
            ));
            let verdict = kill_control_verdict(obs);
            let StageOutcome::Failed(reason) = verdict else {
                panic!("a probe answering under kill must fail the control, got {verdict:?}");
            };
            assert!(reason.contains("FALSE-GREEN"), "got: {reason}");
        }

        #[test]
        fn guard_transport_and_infra_failures_are_never_adjudicated() {
            // A non-zero script exit (or any not-adjudicable observation)
            // must FAIL the control — even though feeding a Failed-shaped
            // outcome to the adjudicator would have PASSED it. The verdict
            // message pins that no adjudication happened.
            let obs = parse_kill_window_transcript(255, &transcript("failed", "1", "active"));
            assert!(matches!(obs, KillWindowObservation::NotAdjudicable { .. }));
            let StageOutcome::Failed(reason) = kill_control_verdict(obs) else {
                panic!("infra failure must fail the control");
            };
            assert!(
                reason.contains("no outcome is fed to the adjudicator"),
                "got: {reason}"
            );
        }

        #[test]
        fn baseline_not_active_or_probe_dead_before_kill_is_not_adjudicable() {
            let dead_unit = "nc_teardown_registered=true\n\
                             nc_baseline_unit=inactive\n\
                             nc_abort=baseline_unit_not_active\n";
            let obs = parse_kill_window_transcript(0, dead_unit);
            let KillWindowObservation::NotAdjudicable { reason } = &obs else {
                panic!("expected NotAdjudicable, got {obs:?}");
            };
            assert!(reason.contains("baseline not applicable"), "got: {reason}");

            let dead_probe = "nc_teardown_registered=true\n\
                              nc_baseline_unit=active\n\
                              nc_baseline_probe=failed\n\
                              nc_baseline_probe_detail=connect refused\n\
                              nc_abort=baseline_probe_failed\n";
            let obs = parse_kill_window_transcript(0, dead_probe);
            let KillWindowObservation::NotAdjudicable { reason } = &obs else {
                panic!("expected NotAdjudicable, got {obs:?}");
            };
            assert!(
                reason.contains("could not be bound to the kill"),
                "got: {reason}"
            );
        }

        #[test]
        fn kill_not_taken_is_not_adjudicable() {
            let t = "nc_teardown_registered=true\n\
                     nc_baseline_unit=active\n\
                     nc_baseline_probe=answered\n\
                     nc_kill_exit=1\n\
                     nc_abort=kill_not_taken\n";
            let obs = parse_kill_window_transcript(0, t);
            let KillWindowObservation::NotAdjudicable { reason } = &obs else {
                panic!("expected NotAdjudicable, got {obs:?}");
            };
            assert!(reason.contains("kill not taken"), "got: {reason}");
        }

        #[test]
        fn guard_unrestored_node_fails_even_when_the_probe_behaved() {
            // Teardown is mandatory + verified: a correct probe-RED with the
            // daemon left dead must still fail the control.
            let obs = parse_kill_window_transcript(0, &transcript("failed", "1", "failed"));
            let KillWindowObservation::NotAdjudicable { reason } = &obs else {
                panic!("expected NotAdjudicable, got {obs:?}");
            };
            assert!(reason.contains("node not restored"), "got: {reason}");
            assert!(matches!(kill_control_verdict(obs), StageOutcome::Failed(_)));
        }

        #[test]
        fn garbled_or_contradictory_transcripts_fail_closed() {
            // Missing probe token entirely.
            let missing = "nc_teardown_registered=true\n\
                           nc_baseline_unit=active\n\
                           nc_baseline_probe=answered\n\
                           nc_kill_exit=0\n\
                           nc_final_unit=active\n";
            assert!(matches!(
                parse_kill_window_transcript(0, missing),
                KillWindowObservation::NotAdjudicable { .. }
            ));
            // Contradiction: "failed" with exit 0.
            assert!(matches!(
                parse_kill_window_transcript(0, &transcript("failed", "0", "active")),
                KillWindowObservation::NotAdjudicable { .. }
            ));
            // Contradiction: "answered" with a non-zero exit.
            assert!(matches!(
                parse_kill_window_transcript(0, &transcript("answered", "1", "active")),
                KillWindowObservation::NotAdjudicable { .. }
            ));
            // Missing trap registration.
            let no_trap = "nc_baseline_unit=active\n\
                           nc_baseline_probe=answered\n\
                           nc_kill_exit=0\n\
                           nc_probe_under_kill=failed\n\
                           nc_probe_exit=1\n\
                           nc_final_unit=active\n";
            assert!(matches!(
                parse_kill_window_transcript(0, no_trap),
                KillWindowObservation::NotAdjudicable { .. }
            ));
            // Empty transcript.
            assert!(matches!(
                parse_kill_window_transcript(0, ""),
                KillWindowObservation::NotAdjudicable { .. }
            ));
        }
    }
}

// ── (b) + (d) signed-bundle forgery corpus + adjudication ────────────────────

pub(crate) mod signed_bundle {
    //! Drives the REAL `verify_signed_assignment_state_artifact`
    //! (`crates/rustynetd/src/daemon.rs`) against assignment-bundle forgeries.
    //!
    //! The forgery taxonomy mirrors the `live_signed_state_chaos` corpus
    //! (`bin/live_signed_state_chaos/mod.rs`, `ALL_SCENARIOS`): each scenario
    //! carries a corpus id + the corpus `expected_rejection` label. The corpus
    //! fixture BYTES are format-agnostic JSON blobs (a truncated `{`, a
    //! future-dated JSON object, …) — fed raw to the assignment verifier they
    //! would ALL collapse to a single `invalid format` error, which cannot
    //! distinguish future-dated from forged-signature from replay and would
    //! make the control a rubber-stamp (the guard forbids "accepts any
    //! error"). So each scenario is realised as a *properly assignment-shaped*
    //! forgery that reaches the verifier's SPECIFIC rejection path, and the
    //! adjudicator asserts the actual error names that specific reason.
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rustynetd::daemon::verify_signed_assignment_state_artifact;

    /// hex([9u8; 32]) — the daemon's known-good genuine-bundle peer key.
    const PEER_PUBLIC_KEY_HEX: &str =
        "0909090909090909090909090909090909090909090909090909090909090909";
    /// Freshness envelope the genuine bundle sits well inside.
    const MAX_AGE_SECS: u64 = 300;
    const MAX_CLOCK_SKEW_SECS: u64 = 60;
    /// Signing seed for the authorised signer (matches the daemon's test
    /// helper `write_auto_tunnel_file`, so the genuine bundle loads).
    const AUTHORISED_SIGNER_SEED: [u8; 32] = [19u8; 32];
    /// A DIFFERENT, unauthorised signer used for the forged-signature case.
    const UNAUTHORISED_SIGNER_SEED: [u8; 32] = [7u8; 32];
    /// The node the genuine/forged bundles are minted for.
    const BUNDLE_NODE_ID: &str = "nc-node-local";

    fn hex_encode(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    fn unix_now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// The daemon's known-good signed-assignment payload (the exact shape
    /// `write_auto_tunnel_file` mints, which loads + passes route-intent), with
    /// the node id / freshness parametrised.
    fn genuine_payload(node_id: &str, generated_at: u64, expires_at: u64, nonce: u64) -> String {
        format!(
            "version=1\n\
             node_id={node_id}\n\
             node_capabilities=anchor,client\n\
             mesh_cidr=100.64.0.0/10\n\
             assigned_cidr=100.64.0.1/32\n\
             exit_node_id=node-exit\n\
             exit_node_capabilities=exit_server\n\
             traffic_route_policy=mesh_or_relay_or_exit_node\n\
             generated_at_unix={generated_at}\n\
             expires_at_unix={expires_at}\n\
             nonce={nonce}\n\
             peer_count=1\n\
             peer.0.node_id=node-exit\n\
             peer.0.capabilities=exit_server\n\
             peer.0.endpoint=203.0.113.20:51820\n\
             peer.0.public_key_hex={PEER_PUBLIC_KEY_HEX}\n\
             peer.0.allowed_ips=0.0.0.0/0,100.64.0.2/32\n\
             route_count=2\n\
             route.0.destination_cidr=100.64.0.2/32\n\
             route.0.via_node=node-exit\n\
             route.0.kind=mesh\n\
             route.1.destination_cidr=0.0.0.0/0\n\
             route.1.via_node=node-exit\n\
             route.1.kind=exit_default\n"
        )
    }

    /// Sign `payload` with `seed` and append the `signature=` line.
    fn sign_bundle(payload: &str, seed: &[u8; 32]) -> String {
        let signing_key = SigningKey::from_bytes(seed);
        let signature = signing_key.sign(payload.as_bytes());
        format!("{payload}signature={}\n", hex_encode(&signature.to_bytes()))
    }

    /// The verifier-key file content for the AUTHORISED signer.
    fn authorised_verifier_key() -> String {
        let signing_key = SigningKey::from_bytes(&AUTHORISED_SIGNER_SEED);
        format!("{}\n", hex_encode(signing_key.verifying_key().as_bytes()))
    }

    /// A version-2 assignment watermark file whose `generated_at_unix` sits at
    /// `watermark_generated_at` (the payload digest is a benign constant — the
    /// verifier only consults it on the equal-watermark branch, which none of
    /// these scenarios exercises).
    fn watermark_file(watermark_generated_at: u64) -> String {
        format!(
            "version=2\n\
             generated_at_unix={watermark_generated_at}\n\
             nonce=1\n\
             payload_digest_sha256={}\n",
            "0".repeat(64)
        )
    }

    /// One forged assignment bundle bound to a specific named rejection.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct BundleScenario {
        /// The `live_signed_state_chaos` corpus scenario id this mirrors.
        pub(crate) corpus_id: &'static str,
        /// The corpus `expected_rejection` label (the NAMED rejection).
        pub(crate) expected_rejection: &'static str,
        /// How the assignment bundle is corrupted.
        pub(crate) kind: ForgeryKind,
        /// The substring the verifier's error MUST contain for the rejection
        /// to count as the *named* rejection (the guard: a weak/wrong reason
        /// does not satisfy the control).
        pub(crate) required_error_substr: &'static str,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum ForgeryKind {
        /// A single `{` byte — a truncated bundle.
        TruncatedOneByte,
        /// The first half of the genuine payload, no signature.
        TruncatedHalfLength,
        /// A well-formed, correctly-signed bundle dated beyond the clock skew.
        FutureDated,
        /// A well-formed bundle signed by an unauthorised key.
        ForgedSignature,
        /// A genuine, current bundle presented against a strictly-newer
        /// persisted watermark (an anti-replay regression).
        Replay,
    }

    /// The assignment-scoped forgery corpus, keyed off `ALL_SCENARIOS`.
    ///
    /// The corpus's `quorum_starved_update` scenario is deliberately absent:
    /// quorum is a MEMBERSHIP-layer concept, and `verify_signed_assignment_state_artifact`
    /// (an assignment-bundle verifier) has no quorum code path. Forcing a
    /// synthetic "quorum" rejection onto the assignment verifier would be a
    /// fabricated control; that fault class is adjudicated on the membership
    /// path (the offline `chaos_signed_state_adversarial` corpus + the
    /// `validate_linux_membership_signature_forgery` audit), not here.
    pub(crate) const SCENARIOS: &[BundleScenario] = &[
        BundleScenario {
            corpus_id: "truncated_one_byte",
            expected_rejection: "malformed_truncated_one_byte",
            kind: ForgeryKind::TruncatedOneByte,
            required_error_substr: "invalid format",
        },
        BundleScenario {
            corpus_id: "truncated_half_length",
            expected_rejection: "malformed_truncated_half_length",
            kind: ForgeryKind::TruncatedHalfLength,
            required_error_substr: "invalid format",
        },
        BundleScenario {
            corpus_id: "future_dated_assignment",
            expected_rejection: "future_dated_signed_state",
            kind: ForgeryKind::FutureDated,
            required_error_substr: "future dated",
        },
        BundleScenario {
            corpus_id: "forged_signature_attempt",
            expected_rejection: "unauthorised_signature",
            kind: ForgeryKind::ForgedSignature,
            required_error_substr: "signature verification failed",
        },
        BundleScenario {
            corpus_id: "replay_watermarked_membership",
            expected_rejection: "replay_watermark_regression",
            kind: ForgeryKind::Replay,
            required_error_substr: "replay detected",
        },
    ];

    /// Per-scenario classification (the inversion: only `RejectedAsExpected`
    /// is a control pass).
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) enum RejectionCheck {
        /// Rejected fail-closed with an error naming the expected reason.
        RejectedAsExpected,
        /// ACCEPTED — a fail-open. The control FAILS.
        AcceptedButMustReject,
        /// Rejected, but not for the named reason (the guard: a weak/wrong
        /// rejection is not a control pass).
        RejectedWrongReason { actual: String },
    }

    impl RejectionCheck {
        pub(crate) fn is_control_pass(&self) -> bool {
            matches!(self, RejectionCheck::RejectedAsExpected)
        }
    }

    /// Positive-control classification for the genuine bundle.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) enum AcceptanceCheck {
        /// Accepted, as a genuine bundle must be.
        AcceptedAsExpected,
        /// Rejected — the verifier is over-strict / the positive control is
        /// broken; the control FAILS (a control that rejects everything,
        /// including valid input, is not proving fail-CLOSED, it is broken).
        RejectedButMustAccept { actual: String },
    }

    impl AcceptanceCheck {
        pub(crate) fn is_control_pass(&self) -> bool {
            matches!(self, AcceptanceCheck::AcceptedAsExpected)
        }
    }

    /// Write the three artifacts for a scenario and return the bundle,
    /// verifier-key and watermark paths.
    fn write_scenario(dir: &Path, kind: ForgeryKind) -> Result<Fixture, String> {
        std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        let now = unix_now();
        let (bundle_body, watermark_generated_at) = match kind {
            ForgeryKind::TruncatedOneByte => ("{".to_owned(), 1),
            ForgeryKind::TruncatedHalfLength => {
                let payload = genuine_payload(BUNDLE_NODE_ID, now, now + 300, 7);
                let half = payload.len() / 2;
                (payload[..half].to_owned(), 1)
            }
            ForgeryKind::FutureDated => {
                let generated = now + 100_000;
                let payload = genuine_payload(BUNDLE_NODE_ID, generated, generated + 300, 7);
                (sign_bundle(&payload, &AUTHORISED_SIGNER_SEED), 1)
            }
            ForgeryKind::ForgedSignature => {
                let payload = genuine_payload(BUNDLE_NODE_ID, now, now + 300, 7);
                (sign_bundle(&payload, &UNAUTHORISED_SIGNER_SEED), 1)
            }
            ForgeryKind::Replay => {
                let payload = genuine_payload(BUNDLE_NODE_ID, now, now + 300, 7);
                // Persisted watermark strictly newer than this bundle ⇒ the
                // incoming bundle regresses the anti-replay watermark.
                (sign_bundle(&payload, &AUTHORISED_SIGNER_SEED), now + 100)
            }
        };
        write_fixture(dir, &bundle_body, watermark_generated_at)
    }

    /// A genuine, current, authorised bundle with a benign (older) watermark.
    fn write_genuine(dir: &Path, node_id: &str) -> Result<Fixture, String> {
        std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        let now = unix_now();
        let payload = genuine_payload(node_id, now, now + 300, 7);
        let body = sign_bundle(&payload, &AUTHORISED_SIGNER_SEED);
        write_fixture(dir, &body, 1)
    }

    struct Fixture {
        bundle: PathBuf,
        verifier_key: PathBuf,
        watermark: PathBuf,
    }

    fn write_fixture(
        dir: &Path,
        bundle_body: &str,
        watermark_generated_at: u64,
    ) -> Result<Fixture, String> {
        let bundle = dir.join("assignment.bundle");
        let verifier_key = dir.join("assignment.verifier.pub");
        let watermark = dir.join("assignment.watermark");
        std::fs::write(&bundle, bundle_body)
            .map_err(|e| format!("write {}: {e}", bundle.display()))?;
        std::fs::write(&verifier_key, authorised_verifier_key())
            .map_err(|e| format!("write {}: {e}", verifier_key.display()))?;
        std::fs::write(&watermark, watermark_file(watermark_generated_at))
            .map_err(|e| format!("write {}: {e}", watermark.display()))?;
        Ok(Fixture {
            bundle,
            verifier_key,
            watermark,
        })
    }

    /// Run the assignment verifier against a fixture with the given
    /// `expected_node_id`.
    fn verify(fixture: &Fixture, expected_node_id: Option<&str>) -> Result<(), String> {
        verify_signed_assignment_state_artifact(
            &fixture.bundle,
            &fixture.verifier_key,
            &fixture.watermark,
            MAX_AGE_SECS,
            MAX_CLOCK_SKEW_SECS,
            expected_node_id,
        )
        .map(|_report| ())
    }

    /// Adjudicate one forgery scenario.
    pub(crate) fn adjudicate_scenario(dir: &Path, scenario: &BundleScenario) -> RejectionCheck {
        let fixture = match write_scenario(dir, scenario.kind) {
            Ok(fixture) => fixture,
            // A fixture we could not even stage is a wrong-reason rejection, not
            // a pass — never silently swallow it into a control pass.
            Err(err) => {
                return RejectionCheck::RejectedWrongReason {
                    actual: format!("fixture staging failed: {err}"),
                };
            }
        };
        classify_rejection(verify(&fixture, None), scenario.required_error_substr)
    }

    /// Pure classifier: given the verifier's result and the required named
    /// reason, decide the control verdict.
    pub(crate) fn classify_rejection(
        result: Result<(), String>,
        required_error_substr: &str,
    ) -> RejectionCheck {
        match result {
            Ok(()) => RejectionCheck::AcceptedButMustReject,
            Err(err) => {
                if err.contains(required_error_substr) {
                    RejectionCheck::RejectedAsExpected
                } else {
                    RejectionCheck::RejectedWrongReason { actual: err }
                }
            }
        }
    }

    /// Adjudicate the genuine positive control.
    pub(crate) fn adjudicate_genuine(dir: &Path) -> AcceptanceCheck {
        let fixture = match write_genuine(dir, BUNDLE_NODE_ID) {
            Ok(fixture) => fixture,
            Err(err) => {
                return AcceptanceCheck::RejectedButMustAccept {
                    actual: format!("genuine fixture staging failed: {err}"),
                };
            }
        };
        match verify(&fixture, None) {
            Ok(()) => AcceptanceCheck::AcceptedAsExpected,
            Err(err) => AcceptanceCheck::RejectedButMustAccept { actual: err },
        }
    }

    /// The (b) control: adjudicate the whole forgery corpus + the genuine
    /// positive control, and fold into a single [`StageOutcome`].
    ///
    /// Passes iff EVERY forgery is `RejectedAsExpected` AND the genuine bundle
    /// is `AcceptedAsExpected`.
    pub(crate) fn run_signed_bundle_control(dir: &Path) -> StageOutcome {
        let mut failures: Vec<String> = Vec::new();

        for scenario in SCENARIOS {
            let scenario_dir = dir.join(scenario.corpus_id);
            match adjudicate_scenario(&scenario_dir, scenario) {
                RejectionCheck::RejectedAsExpected => {}
                RejectionCheck::AcceptedButMustReject => failures.push(format!(
                    "{} ({}): FAIL-OPEN — forged bundle was ACCEPTED but must be rejected",
                    scenario.corpus_id, scenario.expected_rejection
                )),
                RejectionCheck::RejectedWrongReason { actual } => failures.push(format!(
                    "{} ({}): rejected for the WRONG reason — expected {:?}, got {:?}",
                    scenario.corpus_id,
                    scenario.expected_rejection,
                    scenario.required_error_substr,
                    actual
                )),
            }
        }

        match adjudicate_genuine(&dir.join("genuine")) {
            AcceptanceCheck::AcceptedAsExpected => {}
            AcceptanceCheck::RejectedButMustAccept { actual } => failures.push(format!(
                "positive control: genuine bundle was REJECTED but must be accepted: {actual}"
            )),
        }

        if failures.is_empty() {
            StageOutcome::Passed
        } else {
            StageOutcome::Failed(format!(
                "signed-bundle negative control: {} of {} check(s) failed: {}",
                failures.len(),
                SCENARIOS.len() + 1,
                failures.join("; ")
            ))
        }
    }

    // ── (d) wrong-node substitution ─────────────────────────────────────────

    /// Classification of the wrong-node substitution control.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) enum WrongNodeCheck {
        /// A substituted node id was rejected AND the matching id accepted.
        RejectedSubstitutionAcceptedMatch,
        /// The substituted node id was ACCEPTED — a fail-open. Control FAILS.
        AcceptedSubstitution,
        /// The substitution was rejected, but not for the node-id mismatch
        /// reason (guard: wrong reason is not a pass).
        RejectedWrongReason { actual: String },
        /// The matching id was rejected — the positive control is broken.
        MatchRejected { actual: String },
    }

    impl WrongNodeCheck {
        pub(crate) fn is_control_pass(&self) -> bool {
            matches!(self, WrongNodeCheck::RejectedSubstitutionAcceptedMatch)
        }
    }

    /// Pure classifier for the wrong-node control given both verifier results.
    pub(crate) fn classify_wrong_node(
        substituted: Result<(), String>,
        matching: Result<(), String>,
    ) -> WrongNodeCheck {
        match substituted {
            Ok(()) => WrongNodeCheck::AcceptedSubstitution,
            Err(err) if err.contains("node_id mismatch") => match matching {
                Ok(()) => WrongNodeCheck::RejectedSubstitutionAcceptedMatch,
                Err(actual) => WrongNodeCheck::MatchRejected { actual },
            },
            Err(actual) => WrongNodeCheck::RejectedWrongReason { actual },
        }
    }

    /// The (d) control: a genuine bundle minted for [`BUNDLE_NODE_ID`] must be
    /// REJECTED when verified against a *different* `expected_node_id`
    /// (substituted node) and ACCEPTED against its own id (positive control).
    ///
    /// NOTE (orchestrator threading — now landed; live proof deferred): this
    /// control adjudicates the assignment-VERIFY path
    /// (`assignment verify --expected-node-id`). The complementary
    /// orchestrator-level §4.7 challenge is now wired into every typed role
    /// validator (`node_adapter::enforce_identity_challenge`), so a substituted
    /// node also fails the validator itself — proven at the dispatch level by
    /// `node_adapter::tests::challenge_gate_rejects_substituted_node_*` and
    /// bound to this classifier by
    /// `classifier_binds_to_the_orchestrator_identity_challenge_error`. The
    /// remaining follow-on is the LIVE substituted-node stage run on a real
    /// guest (deferred to the Step-B live-verification phase, alongside the
    /// other T5 live proofs).
    pub(crate) fn run_wrong_node_control(dir: &Path) -> StageOutcome {
        let fixture = match write_genuine(dir, BUNDLE_NODE_ID) {
            Ok(fixture) => fixture,
            Err(err) => {
                return StageOutcome::Failed(format!(
                    "wrong-node negative control: fixture staging failed: {err}"
                ));
            }
        };
        let substituted = verify(&fixture, Some("nc-node-substituted-imposter"));
        let matching = verify(&fixture, Some(BUNDLE_NODE_ID));
        match classify_wrong_node(substituted, matching) {
            WrongNodeCheck::RejectedSubstitutionAcceptedMatch => StageOutcome::Passed,
            WrongNodeCheck::AcceptedSubstitution => StageOutcome::Failed(
                "wrong-node negative control: FAIL-OPEN — a bundle for a different node_id was \
                 ACCEPTED under a substituted expected_node_id"
                    .to_owned(),
            ),
            WrongNodeCheck::RejectedWrongReason { actual } => StageOutcome::Failed(format!(
                "wrong-node negative control: substituted node rejected for the WRONG reason \
                 (expected a node_id mismatch): {actual}"
            )),
            WrongNodeCheck::MatchRejected { actual } => StageOutcome::Failed(format!(
                "wrong-node negative control: positive control broken — the matching node_id was \
                 REJECTED: {actual}"
            )),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn tempdir(label: &str) -> PathBuf {
            let dir = std::env::temp_dir().join(format!(
                "rustynet-nc-signed-bundle-{label}-{}-{}",
                std::process::id(),
                unix_now()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            dir
        }

        #[test]
        fn genuine_bundle_is_accepted_positive_control() {
            let dir = tempdir("genuine");
            assert_eq!(
                adjudicate_genuine(&dir),
                AcceptanceCheck::AcceptedAsExpected
            );
            let _ = std::fs::remove_dir_all(&dir);
        }

        #[test]
        fn every_forgery_is_rejected_for_its_named_reason() {
            for scenario in SCENARIOS {
                let dir = tempdir(scenario.corpus_id);
                let check = adjudicate_scenario(&dir, scenario);
                assert_eq!(
                    check,
                    RejectionCheck::RejectedAsExpected,
                    "scenario {} must be rejected fail-closed for {:?}, got {:?}",
                    scenario.corpus_id,
                    scenario.required_error_substr,
                    check
                );
                let _ = std::fs::remove_dir_all(&dir);
            }
        }

        #[test]
        fn scenario_taxonomy_mirrors_the_live_signed_state_chaos_corpus() {
            // The `live_signed_state_chaos` corpus lives in a *bin* module
            // (`src/bin/live_signed_state_chaos/mod.rs`), which the library
            // crate cannot import — so the corpus contract is pinned here as
            // the reviewed `(id, expected_rejection)` set and this test binds
            // the assignment-scoped forgery set to it. If the corpus
            // `ALL_SCENARIOS` ever changes, update this pin in lockstep.
            const CORPUS: &[(&str, &str)] = &[
                ("truncated_one_byte", "malformed_truncated_one_byte"),
                ("truncated_half_length", "malformed_truncated_half_length"),
                ("future_dated_assignment", "future_dated_signed_state"),
                ("forged_signature_attempt", "unauthorised_signature"),
                (
                    "replay_watermarked_membership",
                    "replay_watermark_regression",
                ),
                ("quorum_starved_update", "partial_quorum_not_accepted"),
            ];
            for scenario in SCENARIOS {
                let (_, expected) = CORPUS
                    .iter()
                    .find(|(id, _)| *id == scenario.corpus_id)
                    .unwrap_or_else(|| {
                        panic!("scenario {} is not in the corpus", scenario.corpus_id)
                    });
                assert_eq!(
                    *expected, scenario.expected_rejection,
                    "scenario {} must reuse the corpus expected_rejection label",
                    scenario.corpus_id
                );
            }
            // Every corpus scenario is covered EXCEPT the documented
            // membership-only quorum case — so the assignment control cannot
            // silently drop coverage without this test noticing.
            let covered: std::collections::BTreeSet<&str> =
                SCENARIOS.iter().map(|s| s.corpus_id).collect();
            let uncovered: Vec<&str> = CORPUS
                .iter()
                .map(|(id, _)| *id)
                .filter(|id| !covered.contains(id))
                .collect();
            assert_eq!(
                uncovered,
                vec!["quorum_starved_update"],
                "the only corpus scenario the assignment verifier does not adjudicate is the \
                 membership-layer quorum case"
            );
        }

        #[test]
        fn guard_a_fail_open_accept_fails_the_control() {
            // If a "forgery" were actually accepted, the classifier must call
            // it a fail-open, never a pass.
            let check = classify_rejection(Ok(()), "future dated");
            assert_eq!(check, RejectionCheck::AcceptedButMustReject);
            assert!(!check.is_control_pass());
        }

        #[test]
        fn guard_a_wrong_reason_rejection_fails_the_control() {
            // Rejected, but not for the named reason ⇒ NOT a control pass. This
            // is the exact corruption the spec forbids: loosening "what counts
            // as a rejection".
            let check = classify_rejection(
                Err("auto-tunnel bundle is stale".to_owned()),
                "future dated",
            );
            assert!(matches!(check, RejectionCheck::RejectedWrongReason { .. }));
            assert!(!check.is_control_pass());
        }

        #[test]
        fn signed_bundle_control_passes_end_to_end() {
            let dir = tempdir("control-pass");
            assert_eq!(run_signed_bundle_control(&dir), StageOutcome::Passed);
            let _ = std::fs::remove_dir_all(&dir);
        }

        #[test]
        fn wrong_node_control_passes_end_to_end() {
            let dir = tempdir("wrong-node-pass");
            assert_eq!(run_wrong_node_control(&dir), StageOutcome::Passed);
            let _ = std::fs::remove_dir_all(&dir);
        }

        #[test]
        fn wrong_node_classifier_rejects_fail_open_and_wrong_reason() {
            // Substituted node accepted ⇒ fail-open ⇒ control fails.
            assert_eq!(
                classify_wrong_node(Ok(()), Ok(())),
                WrongNodeCheck::AcceptedSubstitution
            );
            // Substituted node rejected for some OTHER reason ⇒ not a pass.
            assert!(matches!(
                classify_wrong_node(
                    Err("auto-tunnel signature verification failed".to_owned()),
                    Ok(())
                ),
                WrongNodeCheck::RejectedWrongReason { .. }
            ));
            // Correct mismatch rejection + matching accept ⇒ control passes.
            assert_eq!(
                classify_wrong_node(
                    Err("assignment bundle node_id mismatch: expected a, got b".to_owned()),
                    Ok(())
                ),
                WrongNodeCheck::RejectedSubstitutionAcceptedMatch
            );
            // Correct mismatch but the matching positive control is broken.
            assert!(matches!(
                classify_wrong_node(
                    Err("assignment bundle node_id mismatch: expected a, got b".to_owned()),
                    Err("something".to_owned())
                ),
                WrongNodeCheck::MatchRejected { .. }
            ));
        }

        #[test]
        fn classifier_binds_to_the_orchestrator_identity_challenge_error() {
            // The wrong-node control adjudicates the assignment-VERIFY path. The
            // orchestrator's §4.7 role-validator challenge is a SECOND mechanism
            // (see node_adapter::enforce_identity_challenge): a substituted node
            // makes the live daemon report its own id, which the adjudicator
            // rejects. Prove that challenge error, as a string, is classified as
            // a correct substitution rejection here too — so the two mechanisms
            // stay bound and a future rename of either error cannot silently
            // downgrade the T5 verdict to RejectedWrongReason.
            use crate::vm_lab::orchestrator::role_validation::identity_challenge::{
                IdentityEvidence, adjudicate_identity,
            };
            let substituted = adjudicate_identity(
                Some("nc-node-substituted-imposter"),
                &IdentityEvidence::live("real-node"),
            )
            .map_err(|e| e.to_string());
            assert!(substituted.is_err());
            assert_eq!(
                classify_wrong_node(substituted, Ok(())),
                WrongNodeCheck::RejectedSubstitutionAcceptedMatch
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_ids_and_names_match_the_catalog() {
        assert_eq!(
            NegativeControlSignedBundleRejectionStage.id(),
            StageId::NegativeControlSignedBundleRejection
        );
        assert_eq!(
            NegativeControlSignedBundleRejectionStage.name(),
            "negative_control_signed_bundle_rejection"
        );
        assert_eq!(
            NegativeControlPlantedResidueStage.id(),
            StageId::NegativeControlPlantedResidue
        );
        assert_eq!(
            NegativeControlWrongNodeSubstitutionStage.id(),
            StageId::NegativeControlWrongNodeSubstitution
        );
        assert_eq!(
            NegativeControlDaemonKillMidStageStage.id(),
            StageId::NegativeControlDaemonKillMidStage
        );
    }

    #[test]
    fn controls_carry_no_dependencies_and_run_once() {
        for (deps, fanout) in [
            (
                NegativeControlSignedBundleRejectionStage.dependencies(),
                NegativeControlSignedBundleRejectionStage.fanout(),
            ),
            (
                NegativeControlPlantedResidueStage.dependencies(),
                NegativeControlPlantedResidueStage.fanout(),
            ),
        ] {
            assert!(deps.is_empty());
            assert_eq!(fanout, StageFanout::Once);
        }
    }

    // ── (a) planted-residue adjudication ─────────────────────────────────────

    #[test]
    fn planted_residue_dirty_probe_is_detected_control_passes() {
        // Each planted-residue dimension the probe reports must be caught.
        for dirty in [
            "nft=rustynet_boot, daemon=down iface=-", // leftover killswitch table
            "nft=- daemon=up iface=-",                // daemon still running
            "nft=- daemon=down iface=rustynet0,",     // leftover interface
            "nft=rustynet_g1, daemon=up iface=rustynet0,", // all three
        ] {
            let outcome = adjudicate_planted_residue(dirty);
            assert!(
                outcome.is_control_pass(),
                "planted residue {dirty:?} must be detected (control passes), got {outcome:?}"
            );
        }
    }

    #[test]
    fn planted_residue_unverifiable_probe_is_detected_fail_closed() {
        // A garbled/truncated probe (fail-closed) must also read as dirty, so
        // the control passes: an unverifiable node is never treated clean.
        assert!(adjudicate_planted_residue("garbled noise no tokens").is_control_pass());
        assert!(adjudicate_planted_residue("nft=unknown daemon=down iface=-").is_control_pass());
    }

    #[test]
    fn guard_a_genuinely_clean_probe_is_a_control_fail_not_a_pass() {
        // The residue control's job is to catch a probe that PASSES a
        // residue-carrying node. A genuinely clean probe (which the parser
        // correctly passes) means "no residue was planted / detected" ⇒ the
        // control did NOT observe the target failing ⇒ control FAILS. This
        // pins that the adjudicator is not vacuously "always pass".
        let outcome = adjudicate_planted_residue("nft=- daemon=down iface=-\n");
        assert_eq!(outcome, ResidueControlOutcome::FailOpenResidueMissed);
        assert!(!outcome.is_control_pass());
    }

    // ── (c) daemon-kill adjudication ─────────────────────────────────────────

    #[test]
    fn daemon_kill_non_pass_outcomes_pass_the_control() {
        for recorded in [
            StageOutcome::Failed("daemon killed".to_owned()),
            StageOutcome::Skipped,
            StageOutcome::NotRun,
            StageOutcome::Reused {
                evidence_sha256: "abc".to_owned(),
            },
        ] {
            assert!(
                adjudicate_daemon_kill_outcome(&recorded).is_control_pass(),
                "a {recorded:?} under a mid-stage kill must satisfy the control"
            );
        }
    }

    #[test]
    fn guard_c_a_pass_under_kill_is_a_false_green_control_fails() {
        let outcome = adjudicate_daemon_kill_outcome(&StageOutcome::Passed);
        assert_eq!(outcome, KillControlOutcome::FalseGreenUnderKill);
        assert!(!outcome.is_control_pass());
    }

    // ── live-control target selection (shared by (a) + (c)) ──────────────────

    fn assignment(alias: &str, role: NodeRole) -> NodeRoleAssignment {
        NodeRoleAssignment {
            alias: alias.to_owned(),
            role,
        }
    }

    #[test]
    fn target_selection_prefers_a_linux_client() {
        let assignments = vec![
            assignment("exit-1", NodeRole::Exit),
            assignment("mac-client", NodeRole::Client),
            assignment("deb-client", NodeRole::Client),
        ];
        let platform_of = |alias: &str| match alias {
            "exit-1" | "deb-client" => Some(VmGuestPlatform::Linux),
            "mac-client" => Some(VmGuestPlatform::Macos),
            _ => None,
        };
        assert_eq!(
            select_linux_control_target(&assignments, &platform_of),
            Ok("deb-client")
        );
    }

    #[test]
    fn target_selection_falls_back_to_any_linux_node() {
        let assignments = vec![
            assignment("mac-client", NodeRole::Client),
            assignment("exit-1", NodeRole::Exit),
        ];
        let platform_of = |alias: &str| match alias {
            "exit-1" => Some(VmGuestPlatform::Linux),
            "mac-client" => Some(VmGuestPlatform::Macos),
            _ => None,
        };
        assert_eq!(
            select_linux_control_target(&assignments, &platform_of),
            Ok("exit-1")
        );
    }

    #[test]
    fn target_selection_deprioritizes_disruptive_roles() {
        // §8 M2: with no Client, prefer a non-disruptive Linux role (Relay)
        // over a disruptive one (Exit) — smaller blast radius — regardless of
        // assignment order (disruptive listed first here).
        let assignments = vec![
            assignment("exit-1", NodeRole::Exit),
            assignment("relay-1", NodeRole::Relay),
        ];
        let platform_of = |alias: &str| match alias {
            "exit-1" | "relay-1" => Some(VmGuestPlatform::Linux),
            _ => None,
        };
        assert_eq!(
            select_linux_control_target(&assignments, &platform_of),
            Ok("relay-1")
        );
    }

    #[test]
    fn guard_target_selection_fails_closed_without_a_linux_adapter() {
        // §8 M1: a non-Linux target's default assert_node_clean() is Ok(())
        // — running the control there would HIDE the fault. An assignment
        // with no constructed adapter (platform unknown) must not qualify
        // either.
        let assignments = vec![
            assignment("mac-client", NodeRole::Client),
            assignment("ghost-node", NodeRole::Client),
        ];
        let platform_of = |alias: &str| match alias {
            "mac-client" => Some(VmGuestPlatform::Macos),
            _ => None,
        };
        let err = select_linux_control_target(&assignments, &platform_of)
            .expect_err("no Linux adapter must fail closed");
        assert!(err.contains("fail closed"), "got: {err}");
        assert!(err.contains("assert_node_clean"), "got: {err}");
    }
}
