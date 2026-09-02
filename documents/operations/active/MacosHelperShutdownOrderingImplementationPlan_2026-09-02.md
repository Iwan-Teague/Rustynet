# macOS Helper Shutdown Ordering — Implementation Plan (2026-09-02)

Implements the unimplemented half of [`MacOsHelperShutdownOrderingDesign_2026-08-27.md`](./MacOsHelperShutdownOrderingDesign_2026-08-27.md): §2 teardown-ordering repair and §3 helper rollback lease. The design's §1 (QH-40 durable residue marker), §1.6 (startup reports-not-refuses), and §8.7 (helper/daemon timeout-pair alignment) are already implemented and are cited as done, not re-proposed here.

Driven by a live-lab failure observed 2026-09-02, run `livelab-1788325534-2e7bdaf7bf57`, guest `macos-utm-1`, daemon log `/usr/local/var/log/rustynet/rustynetd-error.log`.

---

## 0) Decision summary

**Adopt design §3 Option A (helper rollback lease) as the primary fix, with Option B (daemon-side bounded retry-with-deadline on helper connect during rollback) as defense-in-depth. Lab-only ordering repair (Option C) is done as a hygiene item but is explicitly NOT the production fix.**

Rationale in one paragraph: the 2026-09-02 failure is a completion-order race — launchd delivered SIGTERM to the daemon, the daemon's shutdown rollback needed the privileged helper to tear down pf/DNS protection, and the helper was already gone (bootout is asynchronous; launchd SIGKILLs 5 s after SIGTERM; at two of the four teardown sites the helper is stopped back-to-back with, or before the daemon finishes, deterministically). No launchd mechanism can order one daemon's teardown against another service, so ordering must be established in our own code: the daemon holds a short, explicitly-scoped, self-expiring lease for the duration of its shutdown rollback and the helper defers its exit until the lease closes or a bounded timeout under the measured 5 s launchd kill ceiling expires. The QH-40 residue marker stays exactly as it is — a rollback that still cannot reach the helper must keep failing closed and keep writing the marker.

**Sign-off gate:** design §3 is marked "DEFERRED — SIGN-OFF REQUIRED" and §3.2 recommends the callers-wait repair *before* the lease. This plan inverts that priority deliberately: the lease is chosen as primary because it is the only option that helps under supervisors the caller does not control (system reboot path, design §2 mechanism 5), while the teardown-site repair covers only the four listed sites. The inversion and this rationale require owner sign-off recorded here before S1; without it, S/M0 is the only step that may proceed (constants are inert). **Recorded status: the inversion is a deliberate manager decision, pending the owner's sign-off — it is not a silent drop of the design's gate.**

**Q-1 disposition (resolved 2026-09-02 from the failing run's logs, before S1 — citations in "Q-1 evidence" below):** the failing restart ran through `enforce_baseline_runtime`'s daemon-only `restart_daemon` path (`adapter/macos_install.rs:484-494`), not a `MACOS_LAUNCHD_STOP_COMMAND` stop — answer (b)'s locus. `MACOS_LAUNCHD_STOP_COMMAND` never executed anywhere in the failing run (`traffic_test_matrix`, the only stage that drives its call site `macos_traffic.rs:432`, was skipped), and no stage log records any helper bootout, so the review's pure-(b) precondition ("helper job already removed by an earlier stop") is not evidenced either and the helper's actual liveness at the failure instant is not decidable from the run logs alone. Chosen primary fix: the lease (S1+S2) as primary, **plus** the A1 answer-(b) fallback folded in as S2b — before `restart_daemon`, the adapter probes the helper (`launchctl print system/com.rustynet.privileged-helper`) and, if absent, re-bootstraps it and waits for the socket per `Install-RustyNetMacosService.sh:614-625` — probe-gated so it is a no-op when the helper is alive. §1 step 4's "same back-to-back chain" narrative therefore applies to the traffic-adapter stop path and the production uninstall path, not to the run that failed; the correction is recorded at that step.

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
4. The helper was not reachable: the daemon log recorded `rollback dns protection: rollback failed: firewall apply failed: i/o failed: privileged helper connect failed (/private/var/run/rustynet/rustynetd-privileged.sock)` (error text composed at `crates/rustynetd/src/phase10.rs:459`). This is the §2 completion race: at the lab's stop path the helper bootout sits in the same back-to-back `;`-chain as the daemon bootout (`adapter/macos_traffic.rs:46-78`, `MACOS_LAUNCHD_STOP_COMMAND`, run at `:432`), and the production uninstall path has no wait at all (`crates/rustynet-cli/src/install/uninstall.rs:70-75`, bare bootout loop over `[daemon, helper]`). The helper (`crates/rustynetd/src/privileged_helper.rs:675`, plain accept loop, no SIGTERM handling, no lease, no idle exit) dies on launchd's default 5 s exit ceiling (design §8.1, measured on `macos-utm-1`), while the daemon's rollback is still dialing.

(Q-1 correction, 2026-09-02: the failing run did NOT execute this traffic-adapter chain — `enforce_baseline_runtime`'s daemon-only `restart_daemon` ran instead, and `MACOS_LAUNCHD_STOP_COMMAND` never executed because `traffic_test_matrix` was skipped; the chain description above applies to the traffic-adapter stop path and to `uninstall.rs:70-75`, both still in scope for M2. Also per review F4(1), verified on this tree: the connect-failed text composes at `privileged_helper.rs:467`, wrapped by `firewall apply failed` at `phase10.rs:458-460` — `phase10.rs:459` alone is the wrapper arm, not the connect text. See "Q-1 evidence".)
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

- **Lease holding mechanism (normative, A5):** lease state is memory inside the running helper process (owning peer credential + deadline); the framed connection is the channel. There is deliberately **no lease file and no daemon-side lease state**: daemon SIGKILL closes the socket fds (kernel-guaranteed), the helper observes EOF, and the helper-side deadline is the sole remaining bound — so no stale-lease cleanup path can ever be needed. Helper death destroys the lease; a respawned helper starts with none. Any implementation that persists lease state to disk or into the daemon reopens the stale-cleanup and spoofing failure modes and is rejected in review.
- Wire protocol: one new request kind in the existing framed protocol (e.g. `AcquireRollbackLease{ttl_ms}` / `ReleaseRollbackLease{lease_id}`), served by the accept loop. Helper tracks at most one live lease holder (peer credential must match the lease owner); `Acquire` while a lease is open either renews-for-same-peer or is refused — never queues.
- Helper SIGTERM handling: install a handler that, on SIGTERM, stops accepting and (a) exits immediately if no lease is open, (b) polls lease state on a short tick and exits when the lease closes **or** the defer deadline (bounded under the 5 s ceiling) expires. Deferred exit is still a normal exit: launchd sees the job terminate inside its ceiling.
- Daemon side: `runtime.controller.shutdown()` acquires the lease first (best-effort, bounded by the existing client timeout pair from §8.7 — 3000 ms daemon default, already validated against the ceiling), releases it in all paths after rollback completes or fails, and never treats "could not acquire" as a reason to skip rollback or the marker.

### Option B — daemon-side retry-with-deadline on helper connect during rollback — defense-in-depth

Where rollback dials the helper (`firewall apply failed: i/o failed: privileged helper connect failed`), add a short bounded retry loop with deadline — total retry window small enough to fit inside the daemon's own 5 s SIGTERM-to-SIGKILL budget. The retry budget is **rollback-global, not per-call** (A7): one deadline (e.g. 1500 ms total) is established at `Phase10Controller::shutdown` entry and consumed across every helper dial in that rollback (the pf apply and the SC resolver restore are separate dials — `phase10.rs:6980-6982` → `phase10.rs:958`, SC side at `macos_dns_sc_protect.rs:1473`). Each attempt's timeout is `min(client_timeout, remaining_deadline)`, so a wedged-but-alive helper cannot burn the full 3000 ms client timeout inside a 1500 ms window. On expiry the path is unchanged: error, FailClosed, residue marker. This converts a single lost race into a likely success *if* the helper is merely mid-exit, and is cheap. It does NOT fix the deterministic ordering defects (a helper killed before the daemon even starts rolling back will not come back), so it cannot be primary. It also must not turn into an unbounded stall: the deadline is hard, and on expiry the path is unchanged — error, FailClosed, residue marker.

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
| I-6 | Every teardown site waits for the daemon to actually exit before stopping the helper, bounded, with the wait paired to the residue check. | Shared bounded wait helper used by `uninstall.rs:70-75`, `Install-RustyNetMacosService.sh` (`:604-611` region — corrected from the design's stale `:545-552` cite, which is the dscl uid/gid block), `Bootstrap-RustyNetMacos.sh:753-760`, `MACOS_LAUNCHD_STOP_COMMAND` (`macos_traffic.rs:46-78`). | Per-site render/pin tests (existing shapes at `macos_traffic.rs:821-875` and `macos_install.rs:2379-2408` updated): order and bounded poll present; uninstall integration test asserts daemon-exit-then-helper-stop. |

---

## 4) Migration steps (tests first; S = shipping code, M = lab/mechanism)

**Fail-closed tests required before S1 code (authoritative, from review §10 — every step below builds on these):**

1. `lease_acquire_unauthorized_peer_refused` — connect as a uid that is neither `allowed_uid` nor root; assert the existing unauthorized response and that no lease state exists afterwards (I-4's enforcement is the `privileged_helper.rs:685` peer gate; this is its verification).
2. `lease_second_peer_cannot_release_or_renew` — two distinct authorized peers; owner-only release/renew (I-5).
3. `sigterm_with_open_lease_defers_until_release_or_deadline` — real `SIGTERM`, in-process server: no lease ⇒ immediate exit; open lease ⇒ serves until `Release`; open lease, no release ⇒ exit inside the defer budget (I-1/I-3).
4. `defer_budget_plus_margin_fits_measured_ceiling` — compile-time/const assertion `MACOS_HELPER_ROLLBACK_LEASE_DEFER_MS + margin ≤ MACOS_LAUNCHD_EXIT_TIMEOUT_MS` (I-3's property test), mirroring `validate_macos_privileged_helper_shutdown_budget` (`privileged_helper.rs:150`) and the installer's ceiling rejection (`Install-RustyNetMacosService.sh:160-163`).
5. `helper_absent_rollback_fails_closed_unchanged` — helper job absent at acquire: identical error composition (`privileged_helper.rs:467` + `phase10.rs:458-460`), `FailClosed` transition, `record_shutdown_rollback_residue` marker written, `ShutdownRollbackResidue` returned after the key scrub (`daemon.rs:12415` after `:11782`/`:11790`) (I-2, and the Q-1 answer-(b) guard).
6. `acquire_timeout_race_leaves_no_dangling_assumption` — the A6 edge: acquire times out client-side; daemon proceeds unleased; no code path assumes a lease exists.
7. `retry_deadline_is_rollback_global` — two helper dials inside one rollback with a wedged second dial: total retry spend ≤ the global deadline; expiry restores today's exact failure (A7).
8. `macos_launchd_stop_command_has_no_early_helper_bootout` — pin test asserting no `bootout …privileged-helper` occurrence before the daemon-exit wait in the rendered constant (A8), extending the existing shapes at `macos_traffic.rs:821-875` and `macos_install.rs:2379-2408`.
9. `residue_marker_not_cleared_by_any_lease_path` — after every lease outcome (granted/refused/timed-out/released/renewed), `shutdown_residue::scan` still reports a previously written marker; only `--acknowledge` removes it (`shutdown_residue.rs:264`, guard test at `:451`).

**S/M0 — Ceiling + constants (test-first).** Add `MACOS_HELPER_ROLLBACK_LEASE_DEFER_MS` (value: 3000 — leaves ≥2000 ms of the 5000 ms ceiling for helper teardown) and `MACOS_HELPER_ROLLBACK_LEASE_TTL_MS` (≤ defer). Validator mirroring §8.7's style: reject defer > ceiling − margin, reject TTL > defer. Tests: boundary values rejected/accepted; macOS-only validation like `validate_macos_privileged_helper_shutdown_budget` (`privileged_helper.rs:150-157`).

**S1 — Lease protocol + helper SIGTERM defer (I-1, I-3, I-4, I-5).** Tests first: lease acquire/release/renew happy path, unauthorized-peer refusal, second-peer release refusal, SIGTERM defer matrix (no lease → immediate; open lease → defer until release/deadline; deadline math vs ceiling). Then implement handler in `privileged_helper.rs`.

**S2 — Daemon acquires/releases lease around shutdown rollback (I-2 preserved).** Tests first: rollback succeeds with lease; helper-absent at acquire → identical failure signature to today (error text, FailClosed transition, marker); release on all paths (success, rollback error, acquire error — including the A6 timed-out-acquire case). Implement the acquire/release **inside `Phase10Controller::shutdown` (`phase10.rs:7797`)** (A4) so every `RollbackIntent::CleanShutdown` path is covered, including the non-signal error rollbacks (`bootstrap_apply_failed`, `membership_reconcile_failed` — design §3.3); the signal gate at `daemon.rs:12226` then needs no lease code of its own. Acquire before `rollback_generation_best_effort`, release after, no unwrap/expect (AGENTS.md §10.2).

**S2b — Helper-liveness restore on the daemon-restart path (A1 answer-(b) fallback; probe-gated).** Before `restart_daemon` (`adapter/macos_install.rs:494`), the adapter checks `launchctl print system/com.rustynet.privileged-helper`; if the job is absent it re-`bootstrap`s the helper and applies the post-bootstrap socket-wait from `Install-RustyNetMacosService.sh:614-625` before restarting the daemon, then proceeds to the same residue check as design §2 Option A. No-op when the helper is alive. Tests: helper-present → no bootstrap issued; helper-absent → bootstrap + bounded wait + daemon restart; wait expiry → fail closed (marker path unchanged).

**S3 — Option B retry-with-deadline at the helper connect site.** Tests first: first dial fails, second succeeds within deadline → rollback proceeds; deadline expiry → unchanged failure path. Implement where `firewall apply failed` composes (`phase10.rs:459` path).

**M1 — launchd plist / installer changes.** No plist structural change required by the lease (helper stays KeepAlive, no ExitTimeOut — ceiling stays launchd default 5 s per design §8.1). If the defer budget needs plist visibility, render a `--rollback-lease-defer-ms` daemon→helper argument via the existing installer heredoc (`Install-RustyNetMacosService.sh:558-597`, `--timeout-ms` precedent at `:575`) with the same rejection-not-warning derivation used for the timeout pair (`:149-162`). Update render tests (`macos_install.rs:2379-2408`).

**M2 — Teardown-site ordering repair (I-6, includes Option C sites).** Shared "wait for `launchctl print system/com.rustynet.daemon` to report exit, bounded at the 5 s ceiling, paired with the residue-marker check" (design §2: the poll cannot distinguish clean exit from SIGKILL, so the residue check is mandatory, not optional). Apply at: `uninstall.rs:70-75`; installer stop region `Install-RustyNetMacosService.sh:604-611` (replace bare `sleep 1`; the design's `:545-552` cite is stale — that region is the dscl uid/gid derivation block, review F4(2)); `Bootstrap-RustyNetMacos.sh:753-760`; `MACOS_LAUNCHD_STOP_COMMAND` (`macos_traffic.rs:46-78`): the constant already contains the daemon-exit wait (`:60-66`) and a post-wait helper bootout (`:67`); the repair is to **delete the early helper bootout pair (`:49-50`)** so the post-wait bootout at `:67` is the only helper stop, and to leave the wait predicate per-service (the current loop polls `pgrep -x rustynetd`/`rustynet-relay` only). Update the pin tests (`macos_traffic.rs:821-875`) to assert the *absence* of any helper bootout before the daemon-exit wait, not merely the order of present commands. Note the constant spans `:46-78`, not `:46-58`. (Line numbers verified on this tree; the review's `:59-67`/`:68` are off by one here.) In §5, the Clean-restart residue check requires the N ≥ 20-trial form of review §F8(3) with the trial count recorded in the evidence artifact. Note for `MACOS_LAUNCHD_STOP_COMMAND`: the `pkill -TERM -f …privileged-helper` fallback (`:58`) must stay *after* the helper bootout in any repaired ordering, since KeepAlive (`Install-RustyNetMacosService.sh:580`) would respawn a SIGTERMed helper whose job is still bootstrapped.

**S/M4 — Docs + ledger.** Update the design doc §status, `documents/CODE_MAP.md` for new helper lease symbols, and this plan's status tracker.

Each step lands independently; S1+S2 together are the minimum for the live-proof stage.

---

## 5) Live proof (FAIL-LOUD; dry-run is not evidence)

Target cell: `macos_exit`/`macos_relay`-style focused run or full macOS pass on `macos-utm-1`, `--node` engine, per `CrossPlatformRoleParityRefresh_2026-07-23.md`.

| Stage | Must show | Evidence artifact |
| --- | --- | --- |
| `enforce_baseline_runtime` (macOS) | pass; daemon restart completes without rollback failure | stage row `status=pass` in run's `state/stages.tsv` |
| `validate_baseline_runtime` (macOS) | `macos-utm-1/DnsFailclosed: validation not passed` does NOT recur; loopback resolver advertised, rustynet pf anchor present with DNS block rules, Ethernet loopback-only | same artifact, stage `validate_baseline_runtime=pass` |
| Clean-restart residue check | `shutdown_rollback_residue_detected` does NOT appear in `/usr/local/var/log/rustynet/rustynetd-error.log` for the run's restarts; QH-40 marker file absent on the guest. **Must use the N ≥ 20-trial deterministic form (A8/review §F8(3))**: per trial, one ssh command runs `launchctl bootout system/com.rustynet.daemon; launchctl bootout system/com.rustynet.privileged-helper` back-to-back, then the daemon is re-bootstrapped and rollback success asserted; the trial count N is recorded in the evidence artifact — a stage row that does not state N has not run the test | fetched daemon log + marker-path absence + trial count, attached under the run's report dir |
| Negative-path re-proof | forced helper death during rollback still yields FailClosed + residue marker (fail-closed unchanged); must additionally exercise a **wedged-but-alive** helper (accepting, not reading) per A3 | fetched daemon log showing marker write, attached same dir |

§3.3 caveat disposition (A3): the 2026-09-02 signature is connect-class (`privileged helper connect failed`, composed at `privileged_helper.rs:467`), not the read-class `truncated frame header` timeout that refuted the prior remedy, so the ordering hypothesis is the right one for this run. The Negative-path re-proof row must additionally exercise a **wedged-but-alive** helper (accepting, not reading) to prove the lease/marker machinery does not silently depend on the helper dying.

Ledger: confirm the appended row in `documents/operations/live_lab_node_run_matrix.csv` (§10.9) exists at the proving commit, then take pass/fail from the stage's own report artifact, never the column alone.

---

## 6) Risks, open questions, required adversarial pass

**Open questions (answer before code lands):**

- Q-1: Which exact stop sub-path did run `livelab-1788325534-2e7bdaf7bf57` execute for the daemon restart (adapter daemon-only bootout at `macos_install.rs:487` vs full `MACOS_LAUNCHD_STOP_COMMAND`)? Verified today: the adapter has no helper bootstrap/kickstart, and `MACOS_LAUNCHD_STOP_COMMAND` is invoked from the traffic adapter (`macos_traffic.rs:432`). Confirm from the run's stage logs **before S1**. The two answers are not equivalent for the lease: if the failing restart's helper job had already been `bootout`ed by an earlier `MACOS_LAUNCHD_STOP_COMMAND`, no lease exists to acquire and the lease cannot fix the observed failure — S1/S2 then do not address the driving incident, and the primary fix must additionally restore helper liveness on the daemon-restart path (adapter-side `launchctl bootstrap system/com.rustynet.privileged-helper` + the socket-wait from `Install-RustyNetMacosService.sh:614-625` before `restart_daemon`, with the wait and residue check per design §2 Option A). Record the resolved answer and the chosen primary fix in §0 before S1 lands.
  - **Resolved 2026-09-02 (see "Q-1 evidence" below): answer (b)-locus.** The failing restart was `enforce_baseline_runtime`'s daemon-only `restart_daemon`; `MACOS_LAUNCHD_STOP_COMMAND` never ran in this run (`traffic_test_matrix` skipped) and no stage log records a helper bootout, so the helper's liveness at the failure instant is undetermined from the run logs. The S2b fallback above is folded into the primary fix, probe-gated.
- Q-2: Does the helper's KeepAlive respawn interact with lease state on restart? A bootout-then-bootstrap cycle destroys lease state; the daemon must treat "lease vanished" identically to "helper gone" (fail closed). Confirm no code path assumes lease persistence across helper restarts.
- Q-3: Lease TTL vs §8.7 client timeout (3000 ms daemon default): acquisition must complete inside the existing client budget or the acquire call itself times out — pick TTL ≥ client timeout so a granted lease is never orphaned by its own acquisition call. With TTL = defer = 3000 ms and client timeout 3000 ms, an acquire that times out client-side may still have been granted server-side (response racing the deadline). The daemon must treat "acquire timed out" as "no lease" for its own rollback decisions while the helper's defer fires naturally at the deadline; the S2 release-on-all-paths test must include the timed-out-acquire case (A6).

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

## Review disposition (adversarial review 2026-09-02 — A1..A8)

The review ([`MacosHelperShutdownOrderingImplementationPlanAdversarialReview_2026-09-02.md`](./MacosHelperShutdownOrderingImplementationPlanAdversarialReview_2026-09-02.md)) verdict was READY-WITH-AMENDMENTS. All eight amendments are folded:

- A1: folded — §6 Q-1 bullet now gates on the run's stage logs **before S1** with the two-answers-are-not-equivalent language and the answer-(b) fallback; the fallback is implemented as S2b and the resolved answer + chosen primary fix are recorded in §0 and below ("Q-1 evidence").
- A2: folded — sign-off gate block added to §0 after the rationale; the design §3 priority inversion is recorded as a deliberate manager decision pending owner sign-off (not a silent drop); the status tracker gains a sign-off row that blocks S1 (only S/M0 may proceed).
- A3: folded — §3.3 caveat disposition added to §5 after the table (connect-class vs read-class signature); the negative-path re-proof row now additionally requires a wedged-but-alive helper.
- A4: folded — S2's lease scope pinned **inside `Phase10Controller::shutdown` (`phase10.rs:7797`)** covering the non-signal error rollbacks; the `daemon.rs:12226` signal gate needs no lease code of its own.
- A5: folded — normative lease-holding-mechanism bullet added at the head of §2 Option A "Implementation shape": lease state is memory in the running helper; no lease file, no daemon-side state; persisting lease state is rejected in review.
- A6: folded — Q-3 acquire-timeout orphan case appended; the S2 release-on-all-paths tests and tests-first item 6 cover the timed-out-acquire case.
- A7: folded — Option B's parenthetical deadline replaced by the rollback-global budget with per-attempt `min(client_timeout, remaining_deadline)`; tests-first item 7 covers it.
- A8: folded — M2 restated as a **deletion** of the early helper bootout pair (not a reorder), pin tests must assert absence before the daemon-exit wait, constant span `:46-78` noted; §5 Clean-restart check requires N ≥ 20 trials with the count recorded. Line numbers corrected against this tree (wait `:60-66`, post-wait bootout `:67`; the review cited `:59-67`/`:68` from its tree), and M2's installer stop-region cite corrected `:545-552` → `:604-611` (review F4(2)).

### Q-1 evidence (failing run, guest `macos-utm-1`; orchestrator job `labrun-1788324867343-41411-0`, run id `livelab-1788325534-2e7bdaf7bf57`)

**Answer: (b)-locus.** The failing restart was `enforce_baseline_runtime`'s daemon-only `restart_daemon` (`adapter/macos_install.rs:484-494`, which bootouts only `system/com.rustynet.daemon`); answer (a)'s traffic-adapter stop (`MACOS_LAUNCHD_STOP_COMMAND` chaining daemon + helper bootout) never ran in this run. **The review's pure-(b) precondition is NOT evidenced either**: no stage log records any helper bootout, so whether the helper job was alive (bootstrapped at install, KeepAlive) or already dead at the failure instant is not decidable from the run logs — only the guest's own daemon/helper state would decide. Hence the probe-gated S2b fallback plus tests-first item 5 cover both sub-cases.

Citations (run report dir `state/deepseek-lab-labrun-1788324867343-41411-0/`, orchestrator log `state/deepseek-mcp-jobs/labrun-1788324867343-41411-0.log`):

- Orchestrator log lines 33-34: `[stage] 2026-09-02T05:04:58Z enforce_baseline_runtime started` / `[stage] 2026-09-02T05:05:21Z enforce_baseline_runtime pass` — the only stage executing on `macos-utm-1` at 05:05:12Z (unix 1788325512, the daemon's failing rollback) and 05:05:13Z (daemon restart). The stage's per-node work is the adapter's `enforce_runtime` daemon restart: `stop_daemon` (`launchctl bootout system/com.rustynet.daemon` only, `macos_install.rs:486-492`) + `start_daemon` bootstrap‖kickstart (`:413-423`), wrapped by `restart_daemon` (`:494`); no helper touch anywhere in the adapter (grep-verified).
- Same log line 38: `[stage] 2026-09-02T05:05:23Z validate_baseline_runtime fail: macos-utm-1/DnsFailclosed: validation not passed` — the downstream symptom, two seconds after the restart.
- Same log line 50: `[stage] 2026-09-02T05:05:24Z traffic_test_matrix skipped: dependency validate_baseline_runtime did not pass, so this stage never ran` — the only stage driving `MACOS_LAUNCHD_STOP_COMMAND`'s call site (`macos_traffic.rs:432`) never executed; its early helper-bootout pair (`macos_traffic.rs:49-50`) was never issued in this run.
- Case-insensitive grep for `helper|launchctl|bootout` across every stage log in the report dir's `logs/` and the orchestrator log: zero matches for any helper/bootstrap/bootout activity — no earlier stage booted out the helper.
- Stage log `logs/enforce_baseline_runtime.log` contains only `[stage:enforce_baseline_runtime] pass (rust --node engine)` — per-command detail lives in the adapter code, cited above.

Residual uncertainty is recorded rather than papered over: run logs prove *which stop path ran* (decisive for (a) vs (b)-locus) but not *helper liveness at that instant*. The plan therefore carries both halves: the lease (engages if the helper was alive) and S2b + test 5 (guard the helper-absent case).

---

## Status tracker

| Item | Status |
| --- | --- |
| Plan written | 2026-09-02 |
| Adversarial refute pass | complete 2026-09-02 (review doc READY-WITH-AMENDMENTS; A1–A8 folded — see Review disposition) |
| Q-1 resolution (A1 gate) | complete 2026-09-02 — answer (b)-locus; helper liveness undetermined from run logs; see Q-1 evidence |
| Owner sign-off per design §3 (A2 gate) | pending — **BLOCKS S1; only S/M0 may proceed until recorded here** |
| S/M0 constants | pending |
| S1 helper lease | pending (blocked on sign-off) |
| S2 daemon lease lifecycle | pending (blocked on sign-off) |
| S2b helper-liveness restore (A1 fallback) | implemented on branch (2026-09-02) — lab-adapter side only; live proof pending |
| S3 connect retry | pending |
| M1 installer rendering | pending |
| M2 site ordering repair | implemented on branch (2026-09-02) — `MACOS_LAUNCHD_STOP_COMMAND`, `uninstall.rs`, both installer stop regions; live proof pending |
| Live proof (§5) | pending |
