# macOS Enforce-Refresh Parity Plan — 2026-09-02

Status: ACTIVE — reviewed; Gap B re-scoped to diagnose-first per the 2026-09-02 review (verdict ACCEPT-WITH-AMENDMENTS, findings F-1..F-6 folded). Scope: documents only — no code in this change.
Evidence base: live-lab run `labrun-1788332375714-1644-0` (macOS client `macos-utm-1`, Linux exit `debian-headless-4`, Linux client `debian-headless-2`), plus source reads at base commit `f6b8fdab` (this worktree, clean).

## 0) Failure signature

`validate_baseline_runtime` fails with `macos-utm-1/DnsFailclosed: validation not passed` ~2 s after `enforce_baseline_runtime` passes. After the enforce restart the macOS `rustynetd` logs `rustynetd startup: runtime bootstrap complete` and then nothing; the Linux client, over the same window, logs `signed state refresh completed (reason=command)` immediately after its own enforce restart and passes.

## 1) Root cause (evidence-cited)

Both gaps are real; neither alone is the whole story.

### 1.1 Gap A — orchestrator parity gap (lab-side)

- Linux adapter `enforce_daemon` (`crates/rustynet-cli/src/vm_lab/orchestrator/adapter/linux_install.rs:152`): `build_enforce_script` (fn at :231) ends at `rustynet ops e2e-enforce-host --role {role_str} --node-id '{node_id}' --src-dir ... --ssh-allow-cidrs ...` (script lines :248-253). Nothing is chained after the restart.
- macOS adapter `enforce_daemon` (`crates/rustynet-cli/src/vm_lab/orchestrator/adapter/macos_install.rs:752-834`): scp's `Install-RustyNetMacosService.sh` (:801-811), runs `build_auto_tunnel_enforce_install_script` (:817-824; script ends :730-734 with `--fail-closed-ssh-allow*`), runs over 60 s (:825), then only `wait_for_macos_daemon_socket` (:832). No `state refresh` anywhere. Its own doc comment (:738-751) admits: "production daemons rely on periodic refresh timers that do not exist in the lab".
- `execute_ops_e2e_enforce_host` itself (`crates/rustynet-cli/src/ops_e2e.rs:771` non-Windows; `:1086` Windows) refreshes trust evidence PRE-restart only and waits for the socket post-restart (`wait_for_macos_daemon_socket`, :1063-1075, called at :968). It never issues `state refresh` on ANY platform.
- Linux posture at startup is re-established by the bootstrap apply itself (review F-1/F-4): the Linux pass does not depend on the timer for posture; the timer provides signed-state freshness and makes the pass deterministic, which is exactly what Gap A's enforce-path refresh would hard-wire for both platforms. Gap A remains justified for determinism/parity, not for posture correctness. The timer facts stand: `scripts/systemd/rustynetd-trust-refresh.timer` (`OnBootSec=45s`, `OnUnitActiveSec=60s`) → `rustynetd-trust-refresh.service` `ExecStartPost=/usr/local/bin/rustynet ops state-refresh-if-socket-present` (`crates/rustynet-cli/src/main.rs`, `execute_ops_state_refresh_if_socket_present` :9768: skip if daemon socket absent, else IPC `state refresh`); in the harvest its refresh landed 0.1 s after bootstrap. macOS has no launchd counterpart (guest LaunchDaemons are `com.rustynet.anchor`, `.daemon`, `.exit`, `.privileged-helper`; the macOS bootstrap installs no refresh timer), so no external refresh arrives after restart.

### 1.2 Gap B — undiagnosed macOS startup-posture failure (re-scoped per review F-1)

`bootstrap()` (daemon.rs:8623, called at daemon.rs:11812) applies the full dataplane generation at every startup — `apply_dataplane_generation(trust, …, ApplyOptions{ protected_dns: true })` at daemon.rs:8878-8889, whose protected_dns arm runs `apply_dns_protection()` (phase10.rs:6852-6853) on both platforms — re-deriving trust/membership from `load_verified_trust`/`load_verified_membership` with no network dependency. The observed macOS DnsFailclosed failure therefore indicates the bootstrap apply failed or was silently insufficient on macOS, or the verifier races/mis-checks it — not a missing startup apply. Re-classify the Linux trust-refresh timer as redundancy (defense-in-depth on the *signed-state freshness* axis), not as the mechanism masking a fail-open window; the plan's Linux "same fail-open window" sentence is retracted.

Supporting facts that survive the correction (verified by the 2026-09-02 adversarial review):

- Startup order (`crates/rustynetd/src/daemon.rs` ~:11770-11850): the cfg(macos) block runs `run_startup_dns_recovery` (M1 guard) at :11789 — BEFORE `bootstrap()` at :11812 — restoring the backed-up service DNS from the durable backup (QH-40 sibling marker; `MacosDnsBackupRebootSurvivalPlan_2026-09-02` invariant 6). An M1-recovery/bootstrap-apply interaction is one diagnosis candidate (F-1 (c)).
- The S1 posture reconciler `maybe_assert_dns_posture` (`daemon.rs:10810` cfg + `:10811-10837`, `#[cfg(target_os = "macos")]`) is re-ASSERT-only: it skips unless `controller.dns_protected()` (:10823). It cannot create posture, only reconcile it.
- The signed-state refresh path independently re-applies posture: `refresh_signed_state_with_reason` (`daemon.rs:6018`; reasons `Command`/`PreExpiry`/`endpoint_change`) → `apply_dataplane_generation` (`crates/rustynetd/src/phase10.rs:6535`; production call sites :8878 inside `bootstrap()`, :10568 refresh path) whose `protected_dns` arm applies the networksetup loopback pin + pf DNS block anchor. `PreExpiry` auto-refresh (:6216) fires only near expiry.
- On apply failure inside `bootstrap()` the daemon restricts (`restrict_recoverable("dataplane bootstrap apply failed")` + `force_fail_closed_or_restrict("bootstrap_apply_failed")`, daemon.rs:8907-8928) and returns normally — so BOTH restricted and healthy outcomes can print `runtime bootstrap complete` (daemon.rs:11816-11819 logs `(restricted: {err})` only when `bootstrap_error` is set).

## 2) Precedence decision (Requirements.md > SecurityMinimumBar.md > active scope docs)

**Ratified: the fail-open window is a product defect the daemon must close, not a lab artifact to route around.**

Clause citations, in precedence order:

- `documents/Requirements.md:90` — "DNS fail-close behavior must prevent DNS leakage outside Rustynet policy when VPN mode requires protected DNS." A macOS client whose protected DNS mode is persisted but not established — as observed, despite the startup bootstrap apply carrying `protected_dns: true` (review F-1) — leaks DNS outside Rustynet policy until the defect is diagnosed and repaired. That directly violates this clause for as long as the posture is absent.
- `documents/Requirements.md:186` — "VPN operating modes requiring protected routing must fail closed for traffic and DNS on tunnel failure." Restart is a hard tunnel-failure event; the requirement is fail closed, not "fail closed once a timer gets around to re-signing state". Restoring the operator's pre-protection DNS at startup (M1) and waiting for an external refresh is the opposite of fail-closed-on-failure.
- `documents/Requirements.md:197` — "Trusted-signing/authorization state must fail closed: when trust state cannot be loaded or persisted, trust-required connectivity must be denied with explicit operator-visible errors." The stale-state case is the mirror image: when trust state CAN be loaded and it declares protected posture, the posture must be enforced, and when the enforcement cannot be established, the failure must be operator-visible and closed — not silently deferred to an out-of-process timer.
- `documents/SecurityMinimumBar.md:240-243` — control 8, "Data-plane leak prevention": "DNS fail-close behavior in protected DNS modes." The bar is a continuous property of the mode, not a property of the most recent IPC command.
- `documents/SecurityMinimumBar.md:283` — "Leak tests for tunnel and DNS fail-close behavior" — requires the verification method this plan's §3.2 tests provide.
- `documents/Requirements.md:146` — the cross-platform parity mandate lists "DNS fail-closed" among the per-role platform-native dataplane capabilities that must be proven live on macOS/Windows. Today the macOS proof depends on the absence of a timer the Linux proof silently enjoys — the parity run as configured measures different properties on the two platforms.

Consequences of the precedence order (rewritten per review F-1):

1. **Primary fix (product, diagnose-first):** diagnose why the macOS bootstrap apply did not establish what the `DnsFailclosed` verifier checks, then repair THAT path (§3.2 Phase 1 → Phase 2). The startup apply already exists on both platforms (daemon.rs:8878 with `protected_dns: true`), so NO second startup apply path is added. Candidates: (a) the bootstrap apply failed and the daemon restricted, with the `(restricted: {err})` log variant misread as a plain completion (pin daemon.rs:11816-11819 first); (b) the QH-39 `DnsFailclosed` verifier checks something the apply does not establish, or races it (pf anchor load / networksetup latency inside a ~2 s window); (c) the M1 startup recovery (daemon.rs:11789, before bootstrap) restores state the apply re-derives differently. Required by Requirements.md:90/:186/:197 regardless of any lab consideration.
2. **Secondary fix (lab parity/proof enabler, unchanged):** the enforce paths issue a post-restart `state refresh` (§3.1). This is not the fix — it restores the lab's ability to PROVE the product property deterministically instead of racing a timer, and removes the macOS/Linux proof asymmetry.
3. **Linux timer reclassification (per review F-1/F-4):** `rustynetd-trust-refresh.timer` is redundancy (defense-in-depth on the *signed-state freshness* axis), not the mechanism that closes a fail-open window — the bootstrap apply already re-establishes the Linux posture at every startup. The lab docs should stop treating it as the mechanism that closes the window.

## 3) Implementation plan (offline-testable core first)

### 3.1 Orchestrator layer (lab parity / proof enabler)

Goal: both platforms' `enforce_daemon` issue a post-restart `state refresh`, making the enforce path self-contained instead of timer-lucky.

**Status: LANDED (offline-tested), awaiting live proof.** macOS side: `macos_install::enforce_daemon` issues `sudo -n env RUSTYNET_DAEMON_SOCKET=/private/var/run/rustynet/rustynetd.sock /usr/local/bin/rustynet state refresh` through the validated-argument seam after `wait_for_macos_daemon_socket`, via the closure driver `drive_enforce_post_restart_refresh` (pins: `enforce_state_refresh_command_pins_exact_argv`, `enforce_refresh_runs_only_after_socket_wait_and_propagates_refresh_error`). Linux side: `execute_ops_e2e_enforce_host` (non-Windows, Linux arm) waits on `/run/rustynet/rustynetd.sock` (`wait_for_daemon_socket_locally`) then issues the same IPC refresh through the worker pattern (`refresh_signed_state_via_ipc` — the IPC client is bin-local, so the lib drives the identical `state refresh` command via the established `execute_ops_e2e_worker_refresh_signed_state` self-program path), ordered by `drive_post_restart_state_refresh` (pin: `enforce_refresh_sequences_socket_wait_before_refresh`). Both sides: one attempt, a non-zero refresh result fails the enforce. Remaining: a live-lab run proving `validate_baseline_runtime` passes with the refresh exercised (`macos-utm-1` DnsFailclosed cell).

- Seam (verified): per QH-01 Step 4d, new remote commands go through `RemoteCommand::from_args` (`crates/rustynet-cli/src/vm_lab/orchestrator/adapter/validated_args.rs` — the single constructor; `validated_args.rs:656` pins that only `ssh.rs` may construct `RemoteCommand` directly, and `:614-638` extends the QH-01 scanner pin to `.as_str()` sinks so a `format!` bypass cannot hide). Arguments are typed via `ValidatedArg` constructors (`ValidatedArg::node_id`/`::path`/`::utun`, validated_args.rs:420-450) and each token is single-quote-wrapped by `from_args` (:290-315). The readiness probe to chain after is the existing `wait_for_macos_daemon_socket` (adapter call `macos_install.rs:832`; impl `ops_e2e.rs:1063-1075`, 45 s fail-closed poll).
- Order to pin by unit test: restart → socket wait (`wait_for_macos_daemon_socket`) → `state refresh` → a non-zero refresh result FAILS enforce.
- macOS precedent for the refresh-after-restart seam already exists: the mac role-transition path (`vm_lab/mod.rs:14753`, script `sudo $RN state refresh` at `vm_lab/mod.rs:14835-14837`) and the live test binaries' post-restart refresh helpers (`live_linux_two_hop_test.rs:1841`, `live_linux_lan_toggle_test.rs:1957`, `live_linux_exit_handoff_test.rs:1564`).
- Existing worker `execute_ops_e2e_worker_refresh_signed_state` (`ops_e2e.rs:7471-7487`; wired `main.rs:1472/5616/9315-9319`) shows the target command shape; the adapters currently never call it.

### 3.2 Product layer (primary fix — diagnose-first, re-scoped per review F-2)

Goal: diagnose why the existing bootstrap apply (daemon.rs:8878, `protected_dns: true`) did not establish the `DnsFailclosed` posture on macOS, and repair that path in place if defective.

Phase 1: diagnose why the existing bootstrap apply (daemon.rs:8878, protected_dns: true) did not establish the DnsFailclosed posture on macOS — pin the restricted-vs-plain log variant (daemon.rs:11816-11819), instrument the apply outcome, and check the QH-39 verifier's probe against what the apply establishes. Phase 2: repair in place if defective. A second startup apply path is admitted only if Phase 1 proves bootstrap's apply structurally insufficient, and then only for the local protective posture (DNS block + loopback pin + killswitch) with peers/routes left exclusively to the signed-state refresh path, all freshness gates (PreExpiry, replay watermarks, RUSTYNET_*_MAX_AGE_SECS) intact.

Security floor for any direct apply of persisted state (review F-2):

- must go through `apply_dataplane_generation`'s `validate_trust` (`phase10.rs:6543`) — never a pre-verified bypass;
- freshness gates stay binding: PreExpiry (`daemon.rs:6216`), replay watermarks, `RUSTYNET_*_MAX_AGE_SECS` — a startup path must not weaken or reset expiry timers;
- strictest-secure scope: only the *local deny-direction protective posture* — pf/nft DNS block, loopback DNS pin, killswitch — is safe to apply when the persisted mode says protected, because it cannot leak traffic on stale state. Peers/routes must never come from unrefreshed persisted trust; they stay with the refresh path (Gap A work), which is where signed, fresh state is re-validated.

- Tests (offline, DryRunSystem): assert `apply_dns_protection` appears exactly once during a startup bootstrap (mirrors `daemon.rs:18216-18221`); zero ops when the posture is absent (pattern `dns_posture_assert_skipped_when_not_dns_protected` `daemon.rs:18270`); `DryRunSystem::default().fail_on("apply_dns_protection")` produces the fail-closed/restricted outcome.
- Gating: macOS-cfg for the DNS posture arm (networksetup/pf), with the Linux equivalent evaluated for parity (nft/resolv) so the fix is not another platform asymmetry.
- Live-lab proof: `validate_baseline_runtime` macOS `DnsFailclosed` passes on the rank-1 cell with the enforce refresh NOT yet exercised — proving the repaired product path alone establishes the posture; then with 3.1 landed, both hold.

## 4) Risks and collisions

- S2b helper-liveness `restart_daemon` (`macos_install.rs`) — enforce restart path interacts with helper liveness checks; the added refresh step must not run before the daemon socket is live (already ordered after `wait_for_macos_daemon_socket`).
- M1 DNS-backup startup recovery — M1 (daemon.rs:11789) runs BEFORE the bootstrap apply (:11812); ordering in the product is already correct. If a Phase 2 apply is ever added it must come after recovery, or M1 restore would undo the posture. An M1/bootstrap-apply interaction is itself a diagnosis candidate (F-1 (c)).
- S1 `maybe_assert_dns_posture` — after a Phase 2 apply, `dns_protected()` becomes true and S1 starts reconciling; verify the apply seeds whatever S1 compares (posture fingerprint) so the first assert does not read its own fresh apply as drift.
- QH-01 Step 4d — no `format!`-built shell for the new remote refresh command; typed argv seam only.
- QH-55 restricted-bootstrap — if `runtime.bootstrap()` reports restricted, any Phase 2 apply must not pretend success; log and fail closed consistent with the existing `(restricted: {err})` path.
- PreExpiry interplay — any Phase 2 direct apply of persisted state is not a refresh and must not reset expiry timers (security floor, review F-2).

## 5) Unknown — needs a live probe

- **unknown-0 (review F-5 — the first diagnostic step):** which log variant the harvest actually showed — plain `runtime bootstrap complete` vs `(restricted: {err})`. Pull the raw daemon log line and confirm whether `bootstrap_error` was set (daemon.rs:11816-11819); `bootstrap()` returns normally in both cases. This decides between F-1 candidates (a) and (b)/(c).
- Whether the persisted state on disk after a protected-mode refresh carries everything `apply_dataplane_generation`'s `protected_dns` arm needs at startup without network I/O — ANSWERED by review F-1: bootstrap already applies the generation from `load_verified_trust` + `load_verified_membership` with no network I/O required (fetch `Skipped` falls through to disk load).
- Linux startup ordering: exact point where nft killswitch + resolv restore happen relative to first packet — the bootstrap apply (`:8878`) establishes them; the timer is redundancy, not a window-mask.
- Whether `state-refresh-if-socket-present` racing the bootstrap apply shortly after restart is harmless — review analysis: the refresh is an idempotent re-apply of already-verified state and skips without a socket; treated harmless.

## 6) Deliverable checklist

- [x] Root cause, evidence-cited (§1).
- [x] Precedence decision with exact clause citations (§2).
- [x] Implementation plan skeleton, offline-testable core first (§3).
- [x] Risks/collisions enumerated (§4).
- [x] Unknown-needs-live-probe list (§5).
- [x] Index entry in `documents/operations/active/README.md`.

## 7) Review fold record

Folded from `MacosEnforceRefreshParityPlanAdversarialReview_2026-09-02.md` (verdict ACCEPT-WITH-AMENDMENTS; Gap A and §3.1 verified sound and kept, apart from F-3):

- **F-1 (CRITICAL)** — §1.2 replaced with the corrected statement: `bootstrap()` (daemon.rs:8623, called at :11812) applies the full dataplane generation at every startup on both platforms (daemon.rs:8878-8889 with `protected_dns: true` → `apply_dns_protection` phase10.rs:6852-6853); the "no startup re-apply / fail-open window" claim and the Linux "same fail-open window" sentence retracted. §2 consequences rewritten to diagnose-first (candidates a/b/c); Linux timer reclassified as redundancy (§2.3, §1.1). §5 unknowns annotated answered.
- **F-2 (HIGH)** — §3.2 re-scoped: Phase 1 diagnose (pin restricted-vs-plain log variant, instrument apply outcome, check the QH-39 verifier probe) → Phase 2 repair in place; second startup apply admitted only if Phase 1 proves structural insufficiency. Security floor written in: `validate_trust` (phase10.rs:6543) mandatory, PreExpiry/replay/`RUSTYNET_*_MAX_AGE_SECS` gates binding, expiry timers never reset, scope limited to the local deny-direction posture (DNS block, loopback pin, killswitch) with peers/routes left to the signed-state refresh. §4 risk bullets reworded to reference any Phase 2 apply.
- **F-3 (MEDIUM)** — §3.1 precedent anchor corrected: `adapter/mod.rs:14753` / `:14835-14837` → `vm_lab/mod.rs:14753` / `vm_lab/mod.rs:14835-14837`.
- **F-4 (MEDIUM)** — §1.1 Linux analysis reworded: the Linux pass does not depend on the timer for posture; the timer provides signed-state freshness/determinism, which Gap A's enforce-path refresh would hard-wire for both platforms. Gap A stays justified for determinism/parity.
- **F-5 (LOW)** — §5 unknown-0 added: pin which log variant the harvest showed (plain vs `(restricted: {err})`; daemon.rs:11816-11819).
- **F-6 (LOW)** — line-range nits: `maybe_assert_dns_posture` is daemon.rs:10810 (cfg) + :10811-10837 (fn), not :10811-10847; `execute_ops_state_refresh_if_socket_present` is main.rs:9768, not ~:9767.
