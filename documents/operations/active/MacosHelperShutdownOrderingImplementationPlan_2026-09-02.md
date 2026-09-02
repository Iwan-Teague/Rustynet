# macOS Helper Shutdown Ordering — Implementation Plan (2026-09-02)

Implements the unimplemented half of [`MacOsHelperShutdownOrderingDesign_2026-08-27.md`](./MacOsHelperShutdownOrderingDesign_2026-08-27.md): §2 teardown-ordering repair and §3 helper rollback lease. The design's §1 (QH-40 durable residue marker), §1.6 (startup reports-not-refuses), and §8.7 (helper/daemon timeout-pair alignment) are already implemented and are cited as done, not re-proposed here.

Driven by a live-lab failure observed 2026-09-02, run `livelab-1788325534-2e7bdaf7bf57`, guest `macos-utm-1`, daemon log `/usr/local/var/log/rustynet/rustynetd-error.log`.

---

## 0) Decision summary

**Adopt design §3 Option A (helper rollback lease) as the primary fix, with Option B (daemon-side bounded retry-with-deadline on helper connect during rollback) as defense-in-depth. Lab-only ordering repair (Option C) is done as a hygiene item but is explicitly NOT the production fix.**

Rationale in one paragraph: the 2026-09-02 failure is a completion-order race — launchd delivered SIGTERM to the daemon, the daemon's shutdown rollback needed the privileged helper to tear down pf/DNS protection, and the helper was already gone (bootout is asynchronous; launchd SIGKILLs 5 s after SIGTERM; at two of the four teardown sites the helper is stopped back-to-back with, or before the daemon finishes, deterministically). No launchd mechanism can order one daemon's teardown against another service, so ordering must be established in our own code: the daemon holds a short, explicitly-scoped, self-expiring lease for the duration of its shutdown rollback and the helper defers its exit until the lease closes or a bounded timeout under the measured 5 s launchd kill ceiling expires. The QH-40 residue marker stays exactly as it is — a rollback that still cannot reach the helper must keep failing closed and keep writing the marker.

Layering:

| Layer | Fix | Status in this plan |
| --- | --- | --- |
| Production root cause | A: helper rollback lease (design §3) | S/M1–S/M6, primary |
| Defense-in-depth | B: bounded retry-with-deadline on helper connect during rollback | S/M5, secondary |
| Teardown-site hygiene (all four sites) | bounded post-bootout wait for daemon exit, paired with residue check (design §2 Option A poll) | S/M6 |
| Lab-only ordering | C: fix `MACOS_LAUNCHD_STOP_COMMAND` ordering | S/M6 (same sites), never primary |

---

## 1) Reproduction narrative (from evidence, with exact code path)

Observed 2026-09-02 on `macos-utm-1`, run `livelab-1788325534-2e7bdaf7bf57`:

1. `EnforceBaselineRuntimeStage::execute` (`crates/rustynet-cli/src/vm_lab/orchestrator/stage/enforce_runtime.rs`) fans out per node to the macOS adapter's `enforce_runtime`, which restarts the daemon: bootout of `system/com.rustynet.daemon` (`adapter/macos_install.rs:487`), then `sudo -n launchctl bootstrap system '/Library/LaunchDaemons/com.rustynet.daemon.plist' 2>/dev/null || sudo -n launchctl kickstart system/com.rustynet.daemon` (`adapter/macos_install.rs:412-422`). `launchctl bootout` returns once SIGTERM is delivered, not when the job exits (design §2). The adapter does not bootstrap or kickstart the helper anywhere (grep of `adapter/macos*.rs` for `com.rustynet.privileged-helper` bootstrap/kickstart: no matches; helper lifecycle in the lab is installer bootstrap at `Install-RustyNetMacosService.sh:609-614` and traffic-adapter stop at `adapter/macos_traffic.rs:49-50`).
2. launchd's SIGTERM reaches the running daemon. The daemon's unix signal gate (`crates/rustynetd/src/daemon.rs:12226`, `if shutdown_signals.requested()`) calls `runtime.controller.shutdown()`.
3. `Phase10Controller::shutdown` (`crates/rustynetd/src/phase10.rs:7797`) runs `rollback_generation_best_effort(active_stages, RollbackIntent::CleanShutdown)`. The DNS stage marker routes to `self.system.rollback_dns_protection()` (`crates/rustynetd/src/phase10.rs:6981`), which must reach the privileged helper to remove the pf anchor and restore resolver state.
4. The helper was not reachable: the daemon log recorded `rollback dns protection: rollback failed: firewall apply failed: i/o failed: privileged helper connect failed (/private/var/run/rustynet/rustynetd-privileged.sock)` (error text composed at `crates/rustynetd/src/phase10.rs:459`). This is the §2 completion race: at the lab's stop path the helper bootout sits in the same back-to-back `;`-chain as the daemon bootout (`adapter/macos_traffic.rs:46-58`, `MACOS_LAUNCHD_STOP_COMMAND`, run at `:432`), and the production uninstall path has no wait at all (`crates/rustynet-cli/src/install/uninstall.rs:70-75`, bare bootout loop over `[daemon, helper]`). The helper (`crates/rustynetd/src/privileged_helper.rs:675`, plain accept loop, no SIGTERM handling, no lease, no idle exit) dies on launchd's default 5 s exit ceiling (design §8.1, measured on `macos-utm-1`), while the daemon's rollback is still dialing.
5. The daemon failed closed exactly as designed: `transition_to(DataplaneState::FailClosed, "shutdown_cleanup_failed")`, the error propagated to `daemon.rs`, and `record_shutdown_rollback_residue` (`daemon.rs:11679`, called at `~:12235` inside the signal gate) wrote the QH-40 durable marker before launchd's SIGKILL. Key scrub (`scrub_runtime_wireguard_key_after_bootstrap`, `daemon.rs:~12409`) still runs before the `ShutdownRollbackResidue` error return (`daemon.rs:2806`, `~:12414`) — that ordering is load-bearing and must not change.
6. The daemon restarted (KeepAlive `true`, `scripts/launchd/com.rustynet.daemon.plist:13-14`; helper KeepAlive rendered by `Install-RustyNetMacosService.sh:580`) carrying residue, with `/etc/resolv.conf` still holding the rustynet protected-mode loopback line. `validate_baseline_runtime` then failed `macos-utm-1/DnsFailclosed: validation not passed` (drift: loopback resolver not advertised, no rustynet pf anchor with DNS block rules, Ethernet not loopback-only).

Net: the fail-closed machinery worked; the failure is that a *clean, planned restart* was indistinguishable from an attack because the teardown ordering made rollback failure likely. The fix makes rollback success the expected outcome of a clean restart while keeping every failure path fail-closed.

---

## 2) Options ranked

### Option A — helper rollback lease (design §3) — **RECOMMENDED, primary**

The daemon opens a short-lived, explicitly-scoped rollback lease with the helper before shutdown rollback begins; the helper defers its SIGTERM exit while any lease is open, until the lease closes or a bounded timeout expires.

Constraints (non-negotiable, AGENTS.md §4 / design §3):

- **No privilege widening.** Same listener, same peer-credential check (`peer_uid` == `allowed_uid` or root, `privileged_helper.rs` accept loop), same argv-only exec allowlist, same `--allowed-uid`/`--allowed-gid` resolved via dscl at install time (`Install-RustyNetMacosService.sh:487-493`). The lease changes *when the helper exits*, never *what it will do* or *for whom*.
- **Bounded and self-releasing.** The lease deadline must fit under the launchd kill ceiling: helper defer budget ≤ `MACOS_LAUNCHD_EXIT_TIMEOUT_MS` (5000) minus the helper's own teardown margin. A wedged daemon must not pin the privileged process past the ceiling — launchd's SIGKILL is the outer bound and the helper must treat it as expected, not as an error to fight.
- **Only an already-authorised peer may hold a lease.** Lease acquisition is just another authenticated helper request through the existing socket; unauthorised peers get the existing rejection, not a lease.
- **Fail closed on lease ambiguity.** If the daemon cannot acquire a lease (helper already gone, connect refused), rollback proceeds exactly as today: error, FailClosed, residue marker. The lease is a way to *win* the race, never a way to *mask* it.

Implementation shape:

- Wire protocol: one new request kind in the existing framed protocol (e.g. `AcquireRollbackLease{ttl_ms}` / `ReleaseRollbackLease{lease_id}`), served by the accept loop. Helper tracks at most one live lease holder (peer credential must match the lease owner); `Acquire` while a lease is open either renews-for-same-peer or is refused — never queues.
- Helper SIGTERM handling: install a handler that, on SIGTERM, stops accepting and (a) exits immediately if no lease is open, (b) polls lease state on a short tick and exits when the lease closes **or** the defer deadline (bounded under the 5 s ceiling) expires. Deferred exit is still a normal exit: launchd sees the job terminate inside its ceiling.
- Daemon side: `runtime.controller.shutdown()` acquires the lease first (best-effort, bounded by the existing client timeout pair from §8.7 — 3000 ms daemon default, already validated against the ceiling), releases it in all paths after rollback completes or fails, and never treats "could not acquire" as a reason to skip rollback or the marker.

### Option B — daemon-side retry-with-deadline on helper connect during rollback — defense-in-depth

Where rollback dials the helper (`firewall apply failed: i/o failed: privileged helper connect failed`), add a short bounded retry loop with deadline — total retry window small enough to fit inside the daemon's own 5 s SIGTERM-to-SIGKILL budget (e.g. deadline 1500 ms, small backoff). This converts a single lost race into a likely success *if* the helper is merely mid-exit, and is cheap. It does NOT fix the deterministic ordering defects (a helper killed before the daemon even starts rolling back will not come back), so it cannot be primary. It also must not turn into an unbounded stall: the deadline is hard, and on expiry the path is unchanged — error, FailClosed, residue marker.

### Option C — lab-side ordering only — explicitly NOT the production fix

Repairing only `MACOS_LAUNCHD_STOP_COMMAND` (and the lab scripts) would make the lab pass while every production teardown site (`uninstall.rs`, the installer's `sleep 1`, any operator-driven restart) stays racy. The 2026-09-02 failure happened through the lab's daemon restart path, but the same race is reachable in production through `uninstall.rs:70-75`. C is done as part of the site hygiene in S/M6 but is disqualified as a primary fix: it fixes the lab, not the product.

### What does NOT change

- The QH-40 residue marker (`shutdown_residue.rs`, never auto-cleared, `--acknowledge`-only removal, exit 78 PolicyReject, `shutdown_rollback_residue_detected` log token) is untouched. No option adds a path that skips, softens, or auto-clears it.
- §8.7's timeout pair (helper 2000 ms / daemon 3000 ms derived, ceiling-validated) is untouched; this plan *consumes* it, and the lease defer budget is a separate constant validated against the same ceiling.

---

## 3) Invariants — enforcement point + verification test each

| # | Invariant | Enforcement point | Test |
| --- | --- | --- | --- |
| I-1 | The helper never exits while a lease it granted is unreleased, except when the bounded defer deadline expires. | Helper SIGTERM path: defer-exit loop around lease state (`crates/rustynetd/src/privileged_helper.rs`, new handler beside the accept loop at `:675`). | Unit: SIGTERM with open lease → helper remains accepting until `Release` (or deadline); SIGTERM with no lease → immediate exit. |
| I-2 | A rollback that cannot reach the helper still writes the residue marker, unchanged. | Unchanged code path: `record_shutdown_rollback_residue` (`daemon.rs:11679`/`~:12235`) behind `controller.shutdown()` Err. | Existing QH-40 tests keep passing + new negative test: with lease acquisition refused, rollback failure still records the marker and returns `ShutdownRollbackResidue` (`daemon.rs:2806`) after key scrub. |
| I-3 | A lease outliving its daemon expires bounded — never pins the helper past the launchd ceiling. | Lease TTL + defer deadline both bounded by a new constant ≤ `MACOS_LAUNCHD_EXIT_TIMEOUT_MS − margin`; helper-side deadline is the real enforcer (daemon may die before releasing). | Unit: lease acquired, daemon "crashes" (no release), deadline fires → helper exits within defer budget; property-style test that `defer_budget + helper_teardown_margin ≤ MACOS_LAUNCHD_EXIT_TIMEOUT_MS`. |
| I-4 | The lease grants no new privileged operation — allowlist, peer check, and argv-only exec unchanged. | Lease requests route through the existing authenticated request dispatcher; no new exec branch. | Boundary test: unauthorised peer cannot acquire/renew/release a lease; allowlist assertion test that lease handling introduces no new command name; `scripts/ci/check_backend_boundary_leakage.sh` + security gates stay green. |
| I-5 | Only the lease's owning peer may release or renew it. | Helper stores owning peer credential with the lease; release/renew mismatched peer → refused. | Unit: second authorised-but-different peer cannot release another's lease. |
| I-6 | Every teardown site waits for the daemon to actually exit before stopping the helper, bounded, with the wait paired to the residue check. | Shared bounded wait helper used by `uninstall.rs:70-75`, `Install-RustyNetMacosService.sh` (`:545-552` region), `Bootstrap-RustyNetMacos.sh:753-760`, `MACOS_LAUNCHD_STOP_COMMAND` (`macos_traffic.rs:46-58`). | Per-site render/pin tests (existing shapes at `macos_traffic.rs:821-875` and `macos_install.rs:2379-2408` updated): order and bounded poll present; uninstall integration test asserts daemon-exit-then-helper-stop. |

---

## 4) Migration steps (tests first; S = shipping code, M = lab/mechanism)

**S/M0 — Ceiling + constants (test-first).** Add `MACOS_HELPER_ROLLBACK_LEASE_DEFER_MS` (value: 3000 — leaves ≥2000 ms of the 5000 ms ceiling for helper teardown) and `MACOS_HELPER_ROLLBACK_LEASE_TTL_MS` (≤ defer). Validator mirroring §8.7's style: reject defer > ceiling − margin, reject TTL > defer. Tests: boundary values rejected/accepted; macOS-only validation like `validate_macos_privileged_helper_shutdown_budget` (`privileged_helper.rs:150-157`).

**S1 — Lease protocol + helper SIGTERM defer (I-1, I-3, I-4, I-5).** Tests first: lease acquire/release/renew happy path, unauthorized-peer refusal, second-peer release refusal, SIGTERM defer matrix (no lease → immediate; open lease → defer until release/deadline; deadline math vs ceiling). Then implement handler in `privileged_helper.rs`.

**S2 — Daemon acquires/releases lease around shutdown rollback (I-2 preserved).** Tests first: rollback succeeds with lease; helper-absent at acquire → identical failure signature to today (error text, FailClosed transition, marker); release on all paths (success, rollback error, acquire error). Implement in the shutdown gate (`daemon.rs:12226` region) and/or `Phase10Controller::shutdown` (`phase10.rs:7797`) — acquire before `rollback_generation_best_effort`, release after, no unwrap/expect (AGENTS.md §10.2).

**S3 — Option B retry-with-deadline at the helper connect site.** Tests first: first dial fails, second succeeds within deadline → rollback proceeds; deadline expiry → unchanged failure path. Implement where `firewall apply failed` composes (`phase10.rs:459` path).

**M1 — launchd plist / installer changes.** No plist structural change required by the lease (helper stays KeepAlive, no ExitTimeOut — ceiling stays launchd default 5 s per design §8.1). If the defer budget needs plist visibility, render a `--rollback-lease-defer-ms` daemon→helper argument via the existing installer heredoc (`Install-RustyNetMacosService.sh:558-597`, `--timeout-ms` precedent at `:575`) with the same rejection-not-warning derivation used for the timeout pair (`:149-162`). Update render tests (`macos_install.rs:2379-2408`).

**M2 — Teardown-site ordering repair (I-6, includes Option C sites).** Shared "wait for `launchctl print system/com.rustynet.daemon` to report exit, bounded at the 5 s ceiling, paired with the residue-marker check" (design §2: the poll cannot distinguish clean exit from SIGKILL, so the residue check is mandatory, not optional). Apply at: `uninstall.rs:70-75`; installer stop region `Install-RustyNetMacosService.sh:545-552` (replace bare `sleep 1`); `Bootstrap-RustyNetMacos.sh:753-760`; `MACOS_LAUNCHD_STOP_COMMAND` (`macos_traffic.rs:46-58`) — reorder helper stop after the daemon-exit wait, update pin tests (`:821-875`). Note for `MACOS_LAUNCHD_STOP_COMMAND`: the `pkill -TERM -f …privileged-helper` fallback (`:58`) must stay *after* the helper bootout in any repaired ordering, since KeepAlive (`Install-RustyNetMacosService.sh:580`) would respawn a SIGTERMed helper whose job is still bootstrapped.

**S/M4 — Docs + ledger.** Update the design doc §status, `documents/CODE_MAP.md` for new helper lease symbols, and this plan's status tracker.

Each step lands independently; S1+S2 together are the minimum for the live-proof stage.

---

## 5) Live proof (FAIL-LOUD; dry-run is not evidence)

Target cell: `macos_exit`/`macos_relay`-style focused run or full macOS pass on `macos-utm-1`, `--node` engine, per `CrossPlatformRoleParityRefresh_2026-07-23.md`.

| Stage | Must show | Evidence artifact |
| --- | --- | --- |
| `enforce_baseline_runtime` (macOS) | pass; daemon restart completes without rollback failure | stage row `status=pass` in run's `state/stages.tsv` |
| `validate_baseline_runtime` (macOS) | `macos-utm-1/DnsFailclosed: validation not passed` does NOT recur; loopback resolver advertised, rustynet pf anchor present with DNS block rules, Ethernet loopback-only | same artifact, stage `validate_baseline_runtime=pass` |
| Clean-restart residue check | `shutdown_rollback_residue_detected` does NOT appear in `/usr/local/var/log/rustynet/rustynetd-error.log` for the run's restarts; QH-40 marker file absent on the guest | fetched daemon log + marker-path absence, attached under the run's report dir |
| Negative-path re-proof | forced helper death during rollback still yields FailClosed + residue marker (fail-closed unchanged) | fetched daemon log showing marker write, attached same dir |

Ledger: confirm the appended row in `documents/operations/live_lab_node_run_matrix.csv` (§10.9) exists at the proving commit, then take pass/fail from the stage's own report artifact, never the column alone.

---

## 6) Risks, open questions, required adversarial pass

**Open questions (answer before code lands):**

- Q-1: Which exact stop sub-path did run `livelab-1788325534-2e7bdaf7bf57` execute for the daemon restart (adapter daemon-only bootout at `macos_install.rs:487` vs full `MACOS_LAUNCHD_STOP_COMMAND`)? Verified today: the adapter has no helper bootstrap/kickstart, and `MACOS_LAUNCHD_STOP_COMMAND` is invoked from the traffic adapter (`macos_traffic.rs:432`). Confirm from the run's stage logs; the narrative in §1 holds under either answer, but the lab-side ordering fix must target whichever path ran.
- Q-2: Does the helper's KeepAlive respawn interact with lease state on restart? A bootout-then-bootstrap cycle destroys lease state; the daemon must treat "lease vanished" identically to "helper gone" (fail closed). Confirm no code path assumes lease persistence across helper restarts.
- Q-3: Lease TTL vs §8.7 client timeout (3000 ms daemon default): acquisition must complete inside the existing client budget or the acquire call itself times out — pick TTL ≥ client timeout so a granted lease is never orphaned by its own acquisition call.

**Risks:**

- R-1: Deferring helper exit could mask a genuinely hung rollback, keeping the privileged process alive longer. Mitigation: hard defer deadline under the ceiling (I-3); launchd SIGKILL as outer bound; defer is bounded regardless of daemon behavior.
- R-2: New protocol surface = new attack surface on a privileged socket. Mitigation: I-4/I-5 boundary tests, reuse of existing auth path, security gates (`run_security_gates` equivalent) on the diff, adversarial refute pass below.
- R-3: Retry-with-deadline (B) could convert fast-fail into slow-fail and push rollback past SIGKILL. Mitigation: deadline well inside the daemon's 5 s budget; deadline expiry restores today's exact failure path.
- R-4: Ordering repair in shell scripts is easy to regress silently. Mitigation: pin tests at `macos_traffic.rs:821-875` / `macos_install.rs:2379-2408` assert the *repaired* order, not just the presence of commands.

**Required adversarial refute pass (before any code change):** 3–5 concurrent refutations of the lease design via the ai-agent MCP (`ai_read`, e.g. "REFUTE: helper lease under launchd 5 s ceiling does not widen privilege or mask residue"), grounded with `ai_agent` against this plan + `privileged_helper.rs` + `daemon.rs` shutdown gate. Disagreement = dig deeper before S1.

---

## 7) Out of scope

- DNS backup volatility across reboot (SC DNS persists while `/private/var/run` backups do not — observed in `AutonomousManagerLog_2026-09-01.md:171`) → separate `MacosDnsBackupRebootSurvivalPlan_2026-09-02.md`.
- §8.7 timeout-pair alignment (done, branch `work/helper-timeout-mismatch`); only consumed here.
- Any change to residue-marker semantics (`--acknowledge`-only removal, exit 78) — invariant, not scope.
- Windows/Linux teardown ordering — different supervisors, separate cells.

---

## Status tracker

| Item | Status |
| --- | --- |
| Plan written | 2026-09-02 |
| Adversarial refute pass | pending |
| S/M0 constants | pending |
| S1 helper lease | pending |
| S2 daemon lease lifecycle | pending |
| S3 connect retry | pending |
| M1 installer rendering | pending |
| M2 site ordering repair | pending |
| Live proof (§5) | pending |
