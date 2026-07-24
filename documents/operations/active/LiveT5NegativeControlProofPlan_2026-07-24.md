# Live T5 Negative-Control Proof Plan (disposition D2) — 2026-07-24

**Owner:** WS-D (task-session under `orchestrator_charter.md` §7).
**Status:** PLAN v2 — **fable-adversarial-reviewed; two blockers + four serious
findings folded in** (§8). Build-ready. Live-verify blocked on the `mac-lab-token`
(WS-A/`two_hop`, same host); build proceeds in a WS-D scratch worktree, held
uncommitted until live-validated.
**Disposition:** D2 in `NodeEngineFlipDispositions_2026-07-24.md` — the two
live-guest T5 controls are `Skipped`, not yet proven RED-for-the-right-reason.

## 1. What already exists (A3a — do not rebuild)
`crates/rustynet-cli/src/vm_lab/orchestrator/stage/negative_control.rs` (merged,
`1b9e2c0`) ships four T5 controls; signed-bundle + wrong-node are proven in-pipeline.
The other two return `StageOutcome::Skipped`, with only pure adjudicators built:
`adjudicate_planted_residue` (`:213`) and `adjudicate_daemon_kill_outcome` (`:247`).
**D2 = implement the two `execute()` bodies with live fault injection + the binding
guards below, and prove each drives a real, bound RED.**

Feasibility confirmed: `OrchestrationContext` exposes `adapters: HashMap<String,
Box<dyn NodeAdapter>>` (`context.rs:167`), populated per assigned node in
`native.rs:447-475` before the runner is built — so at execute() time the stage can
reach, per node: `assert_node_clean()` (`node_adapter.rs:369`), `shell_host().run_argv`
for arbitrary remote commands (`node_adapter.rs:327`), and `start/stop/restart_daemon`.

## 2. Corrected fault-injection design (per §8 review)
### (a) planted residue → clean-assert must FAIL *naming the plant*
The controls run immediately before `Cleanup` (`stage/mod.rs:243`/`:247`) when the
guest is **already dirty** (daemon up, real `rustynet*` tables) — so "any `Err` from
the probe" is vacuous (B1). Adjudicate **differentially and name-bound**, inside
`execute()`:
1. Pick a **Linux** adapter in the rebuild set (fail-closed if none — `assert_node_clean`'s
   trait default is `Ok(())`, so a non-Linux target would silently hide the fault, M1).
2. Pre-list `sudo -n nft list tables`; it MUST NOT already contain `rustynet_planted`
   → else control `Failed` (ambiguous leftover).
3. Plant `sudo -n nft add table inet rustynet_planted`; re-list and confirm present →
   else control `Failed` (un-plantable fault, fail-closed per §4).
4. Call `adapter.assert_node_clean()`; require `Err` whose message **contains
   `rustynet_planted`** (the formatter names dirty tables: `node still dirty after
   cleanup: nftables table(s): …`, `linux_traffic.rs:182/:200`). An `Err` that does
   NOT name it = wrong-reason → control `Failed`; `Ok(())` = fail-open → control
   `Failed` (`FailOpenResidueMissed`).
5. **Drop-guard teardown** (see S3): `nft delete table inet rustynet_planted`
   (idempotent — guard the missing-table error), then re-list to confirm absence;
   a leak → control `Failed` naming it.

### (c) daemon killed mid-probe → a daemon-dependent probe must FAIL
`ctx.outcome_of` only sees stages already run with the daemon alive (B2), and a mesh
ping keeps working with `rustynetd` dead (kernel WireGuard) — so the control must run
**its own** probe whose success *requires a live daemon*, killing inside the daemon's
`Restart=on-failure`/`RestartSec=2s` self-heal window (`scripts/systemd/rustynetd.service`).
One guest-side script (re-rendered inline — `render_remote_kill_script` is bin-private,
`:415`, unimportable):
1. Baseline: `systemctl is-active rustynetd` == active AND the daemon control socket
   answers → else control `Failed` (fault not meaningfully applicable, S4).
2. `systemctl kill -s KILL rustynetd`; check the kill's exit status.
3. Immediately (inside the 2s window) run a **daemon-socket / live-identity query**
   (the `rustynet status` / `query_live_identity` class — the §4.7 probe path), bound
   to **socket connectivity only, never `path_live_proven`** (a shared-transport
   reporting artifact that is false even on healthy tunnels, M3).
4. Trap-restart `rustynetd` at script end regardless of outcome.
5. Map ONLY a transport-successful probe into a `StageOutcome` for
   `adjudicate_daemon_kill_outcome`: probe fails because the daemon is dead → `Failed`
   → `StageDidNotPass` → control passes; probe answers under the kill → `Passed` →
   `FalseGreenUnderKill` → control **fails**. An SSH/transport failure is control
   `Failed`, never fed to the adjudicator.

## 3. Verdict logic (corrected — §3 v1 was wrong)
v1 said "reuse adjudicators verbatim, no new verdict logic" — untenable and
self-contradicting §4 (S1). The pure adjudicators are the **final classifiers**;
the fail-closed binding checks around them (plant-took, name-bound `Err`, kill-took,
socket-bound probe, unreachable/ambiguous → `Failed`) are **new, unit-tested verdict
logic in `negative_control.rs`** — mirroring how the signed-bundle control layers
`classify_rejection` under scenario staging (`:556-586`).

## 4. Guards (anti-softening bar — do not weaken)
Bind to the **specific** planted fault, never "any error"; fail-closed on
un-plantable/unreachable/ambiguous; teardown mandatory + verified; no
`path_live_proven` dependence. A vacuous or wrong-reason pass is the exact corruption
T5 exists to prevent.

## 5. Acceptance (corrected — §8 S2)
A working control records **`Passed`**; the induced target-RED stays *inside* the
control (the inversion — `negative_control.rs:11-27`), never a run-level stage fail
(that would poison the fail-dominated run verdict). So acceptance is **NOT** a
run-level RED. It is: the control's row = `pass` in `stages.tsv`; the A2 verifier
reports `valid=true` (exit ∈ {0,2}); and the control's log carries the bound strings
(the named table; the socket-failure reason).

## 6. Scope / ownership (charter §3.5)
WS-D owns `negative_control.rs` — all corrected designs need **zero edits outside it**
(confirmed §8). Read-only trait use of `assert_node_clean`/`shell_host`. Commit via a
WS-D scratch worktree off `origin/main`, `push …:main` ff under the integration token,
author `Iwan-Teague`, **no** `Co-Authored-By` trailer.

## 7. Sequence + blocker
Plan (this) → fable review (done, §8) → **build the two `execute()` bodies + binding
guards + unit tests, held uncommitted** → live-verify on Mac UTM (needs
`mac-lab-token`, serialize with WS-A) with `--enable-negative-control` → commit via
scratch worktree → flip D2 "Skipped" → "proven live". Step-3 is the only lab-blocked
part.

## 8. Fable adversarial review — incorporated (2026-07-24)
Verdict: not sound as written; feasibility OK but both mechanisms broken; corrected
designs code-supported. Folded in:
- **B1** residue vacuous at its catalog position (probe dirty regardless of plant) →
  differential + name-bound adjudication (§2a). Verified: rows 242-247, adjudicator
  `:213`, error names tables `:182/:200`.
- **B2** kill had no "target stage" mechanism (`outcome_of` = pre-kill stages) + mesh
  probe survives a dead daemon + `render_remote_kill_script` bin-private → own
  daemon-dependent probe in one kill-window script (§2c). Verified `:227`, `:415`,
  `RestartSec=2s`.
- **S1** rewrote §3 (binding checks ARE new verdict logic). **S2** corrected §5
  acceptance (control passes; not a run-level RED). **S3** Drop-guard teardown
  (`panic=unwind` confirmed → Drop runs on unwind), target from rebuild set (nodes
  outside it are never cleaned). **S4** kill must prove baseline-active + kill-took.
- Minor: M1 explicit Linux target (default `Ok(())` hides non-Linux); M3 socket-bound
  not `path_live_proven`; M5 exact prefix `node still dirty after cleanup:`.

## 9. Adversarial review of the BUILT code — incorporated (2026-07-24)
Independent fable review of commit `3acb2b9c`: **safe to live-verify and merge — no
blockers, no serious findings.** It stress-tested name-binding cousins, teardown leak on
unwind, the socket probe against a stale socket / rogue listener, the kill-window vs the
2s restart, and transcript token-injection — every hole lands fail-closed. Four minor
findings (numbering is this build review's own, distinct from §8):
- **M1 — folded (`1d6a788e`):** `teardown_verified` marked `torn_down` *before* the
  delete argv, forfeiting the Drop retry on a transport-failed delete. Now marks it only
  after the delete executes.
- **M2 — folded (`1d6a788e`):** target fallback could pick the Exit/Anchor daemon
  (wider blast radius). Now prefers a non-disruptive Linux role over
  Exit/Anchor/BlindExit/Entry; +1 pinning test.
- **M3 — live-verify constraint (no code):** do NOT combine `--rebuild-nodes` with
  `--enable-negative-control` — restricting the rebuild set also restricts the same-run
  `Cleanup`, the one config where a failed-teardown residual is not scrubbed in-run. The
  D2 live-verify run must NOT restrict rebuild nodes.
- **M4 — by-design residue (documented):** if the SSH transport dies inside the
  kill-window script, the `EXIT` trap may not fire and `rustynetd` stays down until
  systemd's `Restart=on-failure` (~2s) revives it. The control correctly reports transport
  `Failed`; the residue self-heals. Acceptable within the self-heal-window design.

Post-review build state: `3acb2b9c` (bodies) + `1d6a788e` (M1/M2) on branch
`claude/wsd-t5-negative-control-live`; **43** negative_control tests, default + vm-lab
builds + fmt + clippy all green. Ready for live-verify.
