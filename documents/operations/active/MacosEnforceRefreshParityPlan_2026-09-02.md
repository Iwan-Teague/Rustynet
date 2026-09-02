# macOS Enforce-Refresh Parity Plan — 2026-09-02

Status: ACTIVE (planning; Phase A+B doc-only). Scope: documents only — no code in this change.
Evidence base: live-lab run `labrun-1788332375714-1644-0` (macOS client `macos-utm-1`, Linux exit `debian-headless-4`, Linux client `debian-headless-2`), plus source reads at base commit `f6b8fdab` (this worktree, clean).

## 0) Failure signature

`validate_baseline_runtime` fails with `macos-utm-1/DnsFailclosed: validation not passed` ~2 s after `enforce_baseline_runtime` passes. After the enforce restart the macOS `rustynetd` logs `rustynetd startup: runtime bootstrap complete` and then nothing; the Linux client, over the same window, logs `signed state refresh completed (reason=command)` immediately after its own enforce restart and passes.

## 1) Root cause (evidence-cited)

Both gaps are real; neither alone is the whole story.

### 1.1 Gap A — orchestrator parity gap (lab-side)

- Linux adapter `enforce_daemon` (`crates/rustynet-cli/src/vm_lab/orchestrator/adapter/linux_install.rs:152`): `build_enforce_script` (fn at :231) ends at `rustynet ops e2e-enforce-host --role {role_str} --node-id '{node_id}' --src-dir ... --ssh-allow-cidrs ...` (script lines :248-253). Nothing is chained after the restart.
- macOS adapter `enforce_daemon` (`crates/rustynet-cli/src/vm_lab/orchestrator/adapter/macos_install.rs:752-834`): scp's `Install-RustyNetMacosService.sh` (:801-811), runs `build_auto_tunnel_enforce_install_script` (:817-824; script ends :730-734 with `--fail-closed-ssh-allow*`), runs over 60 s (:825), then only `wait_for_macos_daemon_socket` (:832). No `state refresh` anywhere. Its own doc comment (:738-751) admits: "production daemons rely on periodic refresh timers that do not exist in the lab".
- `execute_ops_e2e_enforce_host` itself (`crates/rustynet-cli/src/ops_e2e.rs:771` non-Windows; `:1086` Windows) refreshes trust evidence PRE-restart only and waits for the socket post-restart (`wait_for_macos_daemon_socket`, :1063-1075, called at :968). It never issues `state refresh` on ANY platform.
- Therefore Linux's pass is NOT enforce-path design: it is the systemd trust-refresh timer, external to enforce. `scripts/systemd/rustynetd-trust-refresh.timer` (`OnBootSec=45s`, `OnUnitActiveSec=60s`) → `rustynetd-trust-refresh.service` `ExecStartPost=/usr/local/bin/rustynet ops state-refresh-if-socket-present` (`crates/rustynet-cli/src/main.rs`, `execute_ops_state_refresh_if_socket_present` ~:9767: skip if daemon socket absent, else IPC `state refresh`). In the harvest the timer's refresh landed 0.1 s after bootstrap — a race Linux happened to win. macOS has no launchd counterpart (guest LaunchDaemons are `com.rustynet.anchor`, `.daemon`, `.exit`, `.privileged-helper`; the macOS bootstrap installs no refresh timer), so the refresh never comes and the macOS client's signed state stays stale → `DnsFailclosed`.

### 1.2 Gap B — product startup-posture gap (both platforms)

After ANY restart the daemon does not re-apply persisted protected-DNS posture at startup:

- macOS startup (`crates/rustynetd/src/daemon.rs` ~:11770-11850): the cfg(macos) block runs `run_startup_dns_recovery` (M1 guard, before `run_preflight_checks`) which RESTORES the backed-up service DNS from the durable backup (QH-40 sibling marker; `MacosDnsBackupRebootSurvivalPlan_2026-09-02` invariant 6) — i.e. startup actively removes protection residue rather than re-establishing it. Then key prep → preflight → `DaemonRuntime::new` → `runtime.bootstrap()` → the `runtime bootstrap complete` log. No protected-DNS/dataplane-posture re-apply occurs anywhere in this region.
- The S1 posture reconciler `maybe_assert_dns_posture` (`daemon.rs:10811-10847`, `#[cfg(target_os = "macos")]`) is re-ASSERT-only: it skips unless `controller.dns_protected()`. Its own comment states a node whose posture was never applied "has nothing to drift from, and protected-mode entry re-applies it anyway". After a restart with no refresh, `dns_protected()` is false → it no-ops.
- Protection is (re)applied only inside the signed-state refresh path: `refresh_signed_state_with_reason` (`daemon.rs:6018`; reasons `Command`/`PreExpiry`/`endpoint_change`) → `apply_dataplane_generation` (`crates/rustynetd/src/phase10.rs:6535`; daemon.rs call sites :8878, :10568) whose `protected_dns` arm applies the networksetup loopback pin + pf DNS block anchor. `PreExpiry` auto-refresh (:6216) fires only near expiry — not shortly after restart.
- Linux equivalent at startup: nft killswitch + resolv restore are re-established without a refresh. The same fail-open window exists there; the systemd timer merely masks it in the lab.

Net: on Linux the timer usually closes the window ≤60 s after restart; on macOS nothing ever closes it.

## 2) Precedence decision (Requirements.md > SecurityMinimumBar.md > active scope docs)

**Ratified: the fail-open window is a product defect the daemon must close, not a lab artifact to route around.**

Clause citations, in precedence order:

- `documents/Requirements.md:90` — "DNS fail-close behavior must prevent DNS leakage outside Rustynet policy when VPN mode requires protected DNS." A restarted client whose protected DNS mode is persisted but not re-applied leaks DNS outside Rustynet policy for the entire window until the next refresh (on macOS, indefinitely). That directly violates this clause for the window's duration.
- `documents/Requirements.md:186` — "VPN operating modes requiring protected routing must fail closed for traffic and DNS on tunnel failure." Restart is a hard tunnel-failure event; the requirement is fail closed, not "fail closed once a timer gets around to re-signing state". Restoring the operator's pre-protection DNS at startup (M1) and waiting for an external refresh is the opposite of fail-closed-on-failure.
- `documents/Requirements.md:197` — "Trusted-signing/authorization state must fail closed: when trust state cannot be loaded or persisted, trust-required connectivity must be denied with explicit operator-visible errors." The stale-state case is the mirror image: when trust state CAN be loaded and it declares protected posture, the posture must be enforced, and when the enforcement cannot be established, the failure must be operator-visible and closed — not silently deferred to an out-of-process timer.
- `documents/SecurityMinimumBar.md:240-243` — control 8, "Data-plane leak prevention": "DNS fail-close behavior in protected DNS modes." The bar is a continuous property of the mode, not a property of the most recent IPC command.
- `documents/SecurityMinimumBar.md:283` — "Leak tests for tunnel and DNS fail-close behavior" — requires the verification method this plan's §3.2 tests provide.
- `documents/Requirements.md:146` — the cross-platform parity mandate lists "DNS fail-closed" among the per-role platform-native dataplane capabilities that must be proven live on macOS/Windows. Today the macOS proof depends on the absence of a timer the Linux proof silently enjoys — the parity run as configured measures different properties on the two platforms.

Consequences of the precedence order:

1. **Primary fix (product, both platforms):** the daemon re-applies its persisted protected posture at startup, fail-closed on apply failure (§3.2). This is required by Requirements.md:90/:186/:197 regardless of any lab consideration.
2. **Secondary fix (lab parity/proof enabler):** the enforce paths issue a post-restart `state refresh` (§3.1). This is not the fix — it restores the lab's ability to PROVE the product property deterministically instead of racing a timer, and removes the macOS/Linux proof asymmetry.
3. **Linux timer reclassification:** `rustynetd-trust-refresh.timer` is itself a fail-open window (up to 60 s of unprotected posture after every restart, currently load-bearing). Once §3.2 lands it becomes benign redundancy (defense in depth); the lab docs should stop treating it as the mechanism that closes the window.

## 3) Implementation plan (offline-testable core first)

### 3.1 Orchestrator layer (lab parity / proof enabler)

Goal: both platforms' `enforce_daemon` issue a post-restart `state refresh`, making the enforce path self-contained instead of timer-lucky.

- Seam: per QH-01 Step 4d, new remote commands use `RemoteCommand::from_args` / the macOS readiness-probe pattern in `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/validated_args.rs` (typed argv; no `format!`-built shell).
  <!-- PENDING: verify exact fn names/shape in validated_args.rs before finalising. -->
- Order to pin by unit test: restart → socket wait (`wait_for_macos_daemon_socket`) → `state refresh` → a non-zero refresh result FAILS enforce.
- macOS precedent for the refresh-after-restart seam already exists: the mac role-transition path (`adapter/mod.rs:14753`, script `sudo $RN state refresh` at :14835-14837) and the live test binaries' post-restart refresh helpers (`live_linux_two_hop_test.rs:1841`, `live_linux_lan_toggle_test.rs:1957`, `live_linux_exit_handoff_test.rs:1564`).
- Existing worker `execute_ops_e2e_worker_refresh_signed_state` (`ops_e2e.rs:7471-7487`; wired `main.rs:1472/5616/9315-9319`) shows the target command shape; the adapters currently never call it.

### 3.2 Product layer (primary fix)

Goal: at daemon startup, if the persisted trust state says this node's protected posture should be present, re-apply it; fail closed if the re-apply fails.

- Where: in `run_daemon` after `runtime.bootstrap()` (post M1 `run_startup_dns_recovery` — re-apply must come AFTER backup restore, never before, or M1 would wipe the just-applied posture).
- What state: the persisted signed/dataplane generation (the same input `apply_dataplane_generation` consumes during refresh); re-use the `protected_dns` arm (`phase10.rs:6535`) rather than a new apply path.
- Fail-closed: apply failure at startup must surface (restriction/fail-closed state + loud log), never silent continue.
- Tests (offline, DryRunSystem): count `apply_dns_protection` ops issued at startup when persisted protected posture is present; zero ops when absent; failure injection produces the fail-closed outcome.
- Gating: macOS-cfg for the DNS posture arm (networksetup/pf), with the Linux equivalent evaluated for parity (nft/resolv) so the fix is not another platform asymmetry.
- Live-lab proof: `validate_baseline_runtime` macOS `DnsFailclosed` passes on the rank-1 cell with the enforce refresh NOT yet exercised — proving the product fix alone closes the window; then with 3.1 landed, both hold.

## 4) Risks and collisions

- S2b helper-liveness `restart_daemon` (`macos_install.rs`) — enforce restart path interacts with helper liveness checks; the added refresh step must not run before the daemon socket is live (already ordered after `wait_for_macos_daemon_socket`).
- M1 DNS-backup startup recovery — ordering constraint above; re-apply after recovery. If reversed, M1 restore would undo the posture.
- S1 `maybe_assert_dns_posture` — after a startup re-apply, `dns_protected()` becomes true and S1 starts reconciling; verify the re-apply seeds whatever S1 compares (posture fingerprint) so the first assert does not read its own fresh apply as drift.
- QH-01 Step 4d — no `format!`-built shell for the new remote refresh command; typed argv seam only.
- QH-55 restricted-bootstrap — if `runtime.bootstrap()` reports restricted, startup re-apply must not pretend success; log and fail closed consistent with the existing `(restricted: {err})` path.
- PreExpiry interplay — the startup re-apply is not a refresh and must not reset expiry timers; it applies posture from already-verified persisted state.

## 5) Unknown — needs a live probe

- Exact clause text of the Requirements.md / SecurityMinimumBar.md fail-closed provisions (doc citation task, in progress — no code probe needed).
- `validated_args.rs` seam exact API (`RemoteCommand::from_args` signature; macOS readiness-probe helper names).
- Whether the persisted state on disk after a protected-mode refresh carries everything `apply_dataplane_generation`'s `protected_dns` arm needs at startup without network I/O (or whether a refresh is genuinely required for posture, which would re-weight 3.1 vs 3.2).
- Linux startup ordering: exact point where nft killswitch + resolv restore happen relative to first packet, to size the Linux-side window the timer currently masks.
- Whether `state-refresh-if-socket-present` would race the product startup re-apply (both firing shortly after restart) and whether that is harmless.

## 6) Deliverable checklist

- [x] Root cause, evidence-cited (§1).
- [ ] Precedence decision with exact clause citations (§2 — pending read).
- [x] Implementation plan skeleton, offline-testable core first (§3).
- [x] Risks/collisions enumerated (§4).
- [x] Unknown-needs-live-probe list (§5).
- [ ] Index entry in `documents/operations/active/README.md`.
