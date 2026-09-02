# MacosEnforceRefreshParityPlan Phase B Adversarial Review — 2026-09-02

- **Status:** Complete.
- **Subject:** Adversarial verification of `MacosEnforceRefreshParityPlan_2026-09-02.md` (Phase B review, per that plan's §6 checklist).
- **Scope:** Docs-only. No code changes, no lab run. Every code anchor re-checked by direct file read against the worktree at base commit `9c907071` (branch `ai-edit/edit-1788368507314-4519-0`).
- **Method note:** The planned cheap sub-agent fan-out was unavailable (`Model not found: opencode/deepseek-v4-flash-free`); all verification was performed directly by the reviewing agent. The finding set below is the agent's own; treat it as untrusted-adjacent and re-check any claim you act on.

## Verdict

**ACCEPT-WITH-AMENDMENTS** — with one CRITICAL, blocking amendment (F-1) and one HIGH amendment (F-2). Gap A (enforce-path refresh parity) and §3.1's design are verified sound and keep. Gap B's central claim — *no startup path re-applies the protected-DNS posture* — is **wrong**: `DaemonRuntime::bootstrap()` already re-applies the full dataplane generation, protected-DNS arm included, at every startup on both platforms. The plan must be amended to diagnose why the observed macOS bootstrap apply did not satisfy the verifier before prescribing a second apply path.

## Findings

### F-1 — CRITICAL (blocking amendment): Gap B's central claim is wrong; bootstrap already re-applies the protected posture at every startup

**Claim under test (plan §1.2):** *"No protected-DNS/dataplane-posture re-apply occurs anywhere in this region"* — i.e. between M1 recovery and the first signed-state refresh, the daemon applies no posture, leaving a fail-open window on **both** platforms that the Linux timer masks.

**Evidence against it (all read directly in this worktree):**

- `daemon.rs:11789` → `:11802` (M1 recovery, then preflight) → `:11804` (`DaemonRuntime::new`) → `:11812` `runtime.bootstrap()`. The function called at `:11812` is `daemon.rs:8623 fn bootstrap(&mut self)` — the same function the plan cites *only* as a refresh-side call-site container (`daemon.rs:8878`).
- `bootstrap()` (daemon.rs:8623–8928): fetches trust/traversal/dns-zone (`Skipped` → "continue to disk load"; hard `Err` → restrict + return), then `daemon.rs:8766 let trust = match self.load_verified_trust()` (fn at `daemon.rs:5359`; `Err` → `restrict_recoverable("trust_bootstrap_failed")` + return), then `daemon.rs:8775` `load_verified_membership`, route sanitization, then **`daemon.rs:8878` `self.controller.apply_dataplane_generation(trust, RuntimeContext{…}, peers, routes, ApplyOptions{ … })`** — with **`daemon.rs:8889` literally `protected_dns: true,`**. On apply `Err`: `restrict_recoverable("dataplane bootstrap apply failed")` + `force_fail_closed_or_restrict("bootstrap_apply_failed")` + return (`daemon.rs:8907-8928`).
- `phase10.rs:6535 pub fn apply_dataplane_generation(` → first line `:6543` `validate_trust(&self.trust_policy, evidence)?` (verify-before-apply inside apply) → **`phase10.rs:6852-6853` `if options.protected_dns { self.system.apply_dns_protection()?; }`**.
- macOS `apply_dns_protection` = `phase10.rs:4609-4613` (`impl DataplaneSystem for MacosCommandSystem`, impl block `:4346`): sets `dns_protected = true` (`:4610`), `apply_pf_rules(false)` (`Err` → `dns_protected = false` + `DnsApplyFailed`), then the M1 networksetup loopback pin with backup-capture guard (`:4615-4660+`). Linux `apply_dns_protection` = `phase10.rs:3281+`, keyed off `firewall_table` ("killswitch table missing" error). Both platforms therefore re-establish DNS fail-close (and on Linux the killswitch table) inside the same bootstrap apply.
- Corroboration in the codebase's own test commentary: `daemon.rs:18216-18221` — "the controller's apply path asserts the posture at apply time too (`phase10.rs` `apply_dataplane_generation`, protected_dns arm), so an APPLY pass legitimately records exactly one `assert_dns_protection` op".

**Consequences for the plan:**

1. "The daemon never re-applies persisted protected-DNS posture at startup" is false on **both** platforms. The startup sequence the plan walks (daemon.rs ~:11770–11850) ends in an apply that carries `protected_dns: true`.
2. The Linux framing collapses: there is no 60 s fail-open window for the systemd timer to mask, because the timer (`OnUnitActiveSec=60s`) is *redundancy*, not the mechanism. The plan's own §1.2 Linux bullet ("nft killswitch + resolv restore are re-established without a refresh") was already inconsistent with its "same fail-open window" sentence; the code says the Linux posture is re-established by the bootstrap apply itself.
3. Plan §5 unknown-1 is moot (bootstrap already applies the generation from `load_verified_trust` + `load_verified_membership` with no network I/O required — fetch `Skipped` falls through to disk load), and unknown-2 is answered (posture applied inside the `:8878` bootstrap apply, before the reconcile loop / port-mapping; see the comment at `daemon.rs:11822-11825`).

**What this leaves genuinely unexplained (must be diagnosed, not prescribed around):** the observed failure signature — `macos-utm-1/DnsFailclosed: validation not passed` ~2 s after a *plain* `runtime bootstrap complete` log line. Candidates, in order of plausibility:

- (a) The macOS bootstrap apply **failed** and the daemon restricted — but the log quote must be pinned first: `daemon.rs:11816-11819` logs `"(restricted: {err})"` when `bootstrap_error` is set, else the plain line. Note `force_fail_closed_or_restrict` *inside* `bootstrap()` returns normally, so **both** outcomes can print a "bootstrap complete" line; which variant the harvest actually showed decides whether the daemon restricted (agent-visible state) or genuinely completed with the posture absent.
- (b) The QH-39 `DnsFailclosed` verifier (probe at `vm_lab/mod.rs:10143`; labels `:10155` "dns-failclosed", `:10232` "linux-dns-failclosed-check", `:10263` "windows-dns-failclosed-check") checks something the apply does not establish, or races it (pf anchor load / networksetup latency inside a ~2 s window).
- (c) M1 startup recovery (`daemon.rs:11789`, runs *before* bootstrap) restores state that the apply re-derives differently — an ordering or backup-content interaction, not a missing apply.

**Amendment (exact text for the plan):**

> In §1.2, replace the claim "No protected-DNS/dataplane-posture re-apply occurs anywhere in this region" and its both-platform fail-open framing with: "`bootstrap()` (daemon.rs:8623, called at daemon.rs:11812) applies the full dataplane generation at every startup — `apply_dataplane_generation(trust, …, ApplyOptions{ protected_dns: true })` at daemon.rs:8878-8889, whose protected_dns arm runs `apply_dns_protection()` (phase10.rs:6852-6853) on both platforms — re-deriving trust/membership from `load_verified_trust`/`load_verified_membership` with no network dependency. The observed macOS DnsFailclosed failure therefore indicates the bootstrap apply failed or was silently insufficient on macOS, or the verifier races/mis-checks it — not a missing startup apply. Re-classify the Linux trust-refresh timer as redundancy (defense-in-depth on the *signed-state freshness* axis), not as the mechanism masking a fail-open window; the plan's Linux 'same fail-open window' sentence is retracted."

**Severity rationale:** CRITICAL because the ratified decision (product startup re-apply = PRIMARY fix) prescribes building a **second** apply path that duplicates the existing one; a second path diverging from `bootstrap()`'s would be worse than the defect it claims to fix, and the actual macOS defect would remain undiagnosed underneath it.

### F-2 — HIGH: §3.2's "re-apply from persisted state" must be re-scoped to diagnosis-first; any future apply must never carry peers/routes from stale trust

**Claim under test (plan §3.2):** add a post-`bootstrap()` startup re-apply re-using "the persisted signed/dataplane generation — same input `apply_dataplane_generation` consumes", fail-closed on failure.

**Problem:** after F-1, this path duplicates `bootstrap()`'s existing apply. Kept verbatim it is dead weight at best; if it ever runs with different inputs it becomes a divergence hazard. Two guarded amendments:

1. **Re-scope (now):** the primary §3.2 deliverable becomes *diagnose and, if defective, repair the existing bootstrap apply on macOS* (candidates in F-1), verified by the DryRunSystem op-count tests below. Only if diagnosis proves bootstrap's apply is structurally absent/insufficient on some platform does a new path enter scope — and then:
2. **Security floor (any direct apply of persisted state, ever):**
   - must go through `apply_dataplane_generation`'s `validate_trust` (`phase10.rs:6543`) — never a pre-verified bypass;
   - freshness gates stay binding: PreExpiry (`daemon.rs:6216`), replay watermarks, `RUSTYNET_*_MAX_AGE_SECS` — a startup path must not weaken or reset expiry timers (plan §4's PreExpiry-non-reset risk is already correct; keep it);
   - **strictest-secure scope:** only the *local protective posture* — pf/nft DNS block, loopback DNS pin, killswitch — is safe to apply unconditionally when the persisted mode says protected, because it is deny-direction and cannot leak traffic on stale state. **Peers/routes must never come from unrefreshed persisted trust**; they stay with the refresh path (Gap A work), which is where signed, fresh state is re-validated.

**Amendment (exact text for the plan):**

> In §3.2, replace "add a startup re-apply that re-uses the persisted signed/dataplane generation" with: "Phase 1: diagnose why the existing bootstrap apply (daemon.rs:8878, protected_dns: true) did not establish the DnsFailclosed posture on macOS — pin the restricted-vs-plain log variant (daemon.rs:11816-11819), instrument the apply outcome, and check the QH-39 verifier's probe against what the apply establishes. Phase 2: repair in place if defective. A second startup apply path is admitted only if Phase 1 proves bootstrap's apply structurally insufficient, and then only for the local protective posture (DNS block + loopback pin + killswitch) with peers/routes left exclusively to the signed-state refresh path, all freshness gates (PreExpiry, replay watermarks, RUSTYNET_*_MAX_AGE_SECS) intact."

### F-3 — MEDIUM: stale precedent anchor — `adapter/mod.rs` should be `vm_lab/mod.rs`

Plan §3.1 cites "adapter/mod.rs:14753, script sudo $RN state refresh at :14835-14837". No "state refresh" string exists anywhere in `adapter/mod.rs`. The mac role-transition refresh precedent lives in **`vm_lab/mod.rs`**: the doc comment "…runs `state refresh` (the…" is at `vm_lab/mod.rs:14753`, and the script with `if ! REFRESH_OUT="$(sudo $RN state refresh 2>&1)"` / errors "state refresh after role transition failed" / success "role transition proven: … state refresh ok" is at `vm_lab/mod.rs:14835-14837` (further refs at `:18405`, `:18792`). Right lines, wrong file.

**Amendment:** replace both `adapter/mod.rs:14753` and `:14835-14837` cites with `vm_lab/mod.rs:14753` and `vm_lab/mod.rs:14835-14837`.

### F-4 — MEDIUM: §1.1 overstates the Linux timer's role in the Linux pass

Plan §1.1: "Linux's pass is NOT enforce-path design… a timer race Linux happened to win". With F-1 in place, the Linux `DnsFailclosed` check would pass without the timer: the bootstrap apply re-establishes the posture directly. The timer's refresh is about **signed-state freshness/determinism** (and it did land 0.1 s after bootstrap in the harvest), not about posture existence.

**Amendment:** reword §1.1's Linux analysis to "the Linux pass does not depend on the timer for posture; the timer provides signed-state freshness and makes the pass deterministic, which is exactly what Gap A's enforce-path refresh would hard-wire for both platforms. Gap A remains justified for determinism/parity, not for posture correctness."

### F-5 — LOW: §0's log quote must be pinned to the restricted-or-plain variant before it means anything

`daemon.rs:11816-11819` prints `"(restricted: {err})"` when `bootstrap_error` is set and the plain `runtime bootstrap complete` otherwise — and `bootstrap()` can return normally in **both** cases (internal `force_fail_closed_or_restrict` returns normally). The harvest quote ("plain… then nothing") is therefore ambiguous between "daemon restricted, agent ignored/misread the line" and "daemon completed with the posture genuinely absent". This decides between F-1's candidates (a) and (b)/(c) and must be the first diagnostic step.

**Amendment:** add to §5 (unknowns) as unknown-0: "which log variant the harvest actually showed — pull the raw daemon log line and confirm whether `bootstrap_error` was set."

### F-6 — LOW: line-range nits

- `maybe_assert_dns_posture` is `daemon.rs:10810` (cfg) + `:10811-10837` (fn), not `:10811-10847`.
- `execute_ops_state_refresh_if_socket_present` is `main.rs:9768`, not `~:9767` (±1; harmless but pin it).

## Per-anchor verification table

| Plan anchor | Verdict | Actual | Note |
| --- | --- | --- | --- |
| `linux_install.rs:152` `pub fn enforce_daemon(` | VERIFIED | same | |
| `linux_install.rs:231` `fn build_enforce_script(` | VERIFIED | same | |
| `linux_install.rs:248-253` script ends `ops e2e-enforce-host ...`, nothing after restart | VERIFIED | :248-252 tail, :253 closes `format!` | Gap A premise holds for Linux. |
| `macos_install.rs:752-834` macOS `enforce_daemon` issues no state refresh | VERIFIED | fn ends :834 `Ok(())` | No refresh anywhere in the fn. |
| `macos_install.rs:749-751` doc comment "periodic refresh timers that do not exist in the lab" | VERIFIED | :738-751 block | Verbatim. |
| `macos_install.rs:801-811` scp Install-RustyNetMacosService.sh | VERIFIED | same | |
| `macos_install.rs:817-824` `build_auto_tunnel_enforce_install_script` | VERIFIED | same | |
| `macos_install.rs:730-734` `--fail-closed-ssh-allow*` flags | VERIFIED | same | |
| `macos_install.rs:825` 60s `run_remote` | VERIFIED | `Duration::from_secs(60)` | |
| `macos_install.rs:832` `wait_for_macos_daemon_socket(conn)?` | VERIFIED | comment :826-831, call :832 | |
| `macos_install.rs:668` `restart_daemon` helper exists (plan §4 S2b) | VERIFIED | same | |
| `ops_e2e.rs:771` non-Win `execute_ops_e2e_enforce_host` / `:1086` Win arm | VERIFIED | same | |
| `ops_e2e.rs:968` socket wait after restart | VERIFIED | same | |
| `ops_e2e.rs:1063-1075` 45s wait, fail-closed on timeout | VERIFIED | :1063-1079, err "daemon socket ... did not reappear within 45s" | |
| `ops_e2e.rs` enforce host refreshes trust PRE-restart only | VERIFIED | | Confirmed by reading the fn. |
| systemd timer `OnBootSec=45s`, `OnUnitActiveSec=60s` | VERIFIED | + `RandomizedDelaySec=10s`, `AccuracySec=5s`, `Persistent=true` | Plan omitted the randomization; immaterial. |
| service `ExecStartPost=rustynet ops state-refresh-if-socket-present` | VERIFIED | `ExecStart=ops refresh-trust` | |
| `main.rs:~9767` `execute_ops_state_refresh_if_socket_present` | VERIFIED | :9768 | F-6. |
| `main.rs:1472/:5616/:9315-9319` e2e-worker-refresh-signed-state wiring | VERIFIED | same | |
| `ops_e2e.rs:7471-7487` `execute_ops_e2e_worker_refresh_signed_state` | VERIFIED | root, 20x2s socket wait, RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock | |
| `live_linux_two_hop_test.rs:1841` refresh fn | VERIFIED | same | |
| `live_linux_lan_toggle_test.rs:1957` refresh fn | VERIFIED | same | |
| `live_linux_exit_handoff_test.rs:1564` refresh fn | VERIFIED | same | |
| `adapter/mod.rs:14753` / `:14835-14837` mac role-transition `state refresh` | **WRONG** | `vm_lab/mod.rs:14753` / `:14835-14837`; also :18405, :18792 | F-3. |
| `validated_args.rs:656` `RemoteCommand(` scanner | VERIFIED | `!source.contains("RemoteCommand(")` | |
| `validated_args.rs:614-638` `.as_str()` sinks | VERIFIED | 2 hits | |
| `validated_args.rs:420-450` `ValidArg` ctors (node_id :425, path :430) | VERIFIED | same | |
| `validated_args.rs:290-315` single-quote wrapping | VERIFIED | 4 hits | |
| Req:90 / Req:146 / Req:186 / Req:197 | VERIFIED | verbatim | All six doc cites. |
| SecBar:240-243 control 8 / SecBar:283 leak tests | VERIFIED | verbatim | |
| `daemon.rs:6018` `refresh_signed_state_with_reason` | VERIFIED | same | |
| `daemon.rs:6216` PreExpiry auto-refresh | VERIFIED | `maybe_preexpiry_refresh_traversal` :6208-6221 | |
| `daemon.rs:8878` / `:10568` production `apply_dataplane_generation` call sites | VERIFIED | 8878 is inside `bootstrap()` (:8623) — the plan missed this; 10568 refresh path. Other hits are tests. | Basis of F-1. |
| `phase10.rs:6535` `apply_dataplane_generation` | VERIFIED | `validate_trust` first line :6543 | Verify-before-apply inside apply. |
| `phase10.rs:6852-6853` `protected_dns` arm → `apply_dns_protection` | VERIFIED | `if options.protected_dns { self.system.apply_dns_protection()?; }` | Basis of F-1. |
| `daemon.rs:10811-10847` `maybe_assert_dns_posture` re-assert-only | VERIFIED | :10810 cfg, :10811-10837; :10823 `if !self.controller.dns_protected() { return; }` | F-6 nit. |
| `daemon.rs:~11770-11850` startup: M1 recovery → preflight → `DaemonRuntime::new` (:11804) → `bootstrap()` (:11812) | VERIFIED | recovery :11789; "preflight checks passed" :11802 | M1-before-bootstrap confirmed. |
| `daemon.rs:11816-11819` plain "runtime bootstrap complete" log | VERIFIED | else-branch of `bootstrap_error` check; restricted variant logs `(restricted: {err})` | F-5 ambiguity. |
| `daemon.rs` `dns_protected()` persisted-derived | VERIFIED (claim correct) | macOS :4605-4607 live flag; trait default false :682-684; DryRunSystem :948-951/:964-966 | Live-apply-derived, as plan said. |

## Considered, no defect

- Gap A core claim: neither enforce path chains a state refresh after restart — true on both platforms (Linux `:248-253`, macOS fn `:752-834`).
- `wait_for_macos_daemon_socket` is genuinely fail-closed (45s deadline, non-zero exit).
- Timer/service unit contents cited accurately (modulo the omitted randomization fields).
- `execute_ops_e2e_worker_refresh_signed_state` exists as cited and is indeed never called by the enforce adapters.
- QH-55 restricted-bootstrap risk is real and correctly cited (`:11813-11817`).
- M1-before-bootstrap ordering claim is correct; §4's M1-ordering risk is valid.
- S1 re-assert-only characterization is correct (`:10823` skip gate).
- `dns_protected()` live-apply-derived claim is correct.
- §3.1 design is sound as drafted: order pin (restart → socket wait → refresh → fail non-zero), `RemoteCommand::from_args` seam, Linux enforce parity, refresh failure fails the enforce. The refresh is an idempotent re-apply of already-verified state and `state-refresh-if-socket-present` skips without a socket — race with product startup is harmless.
- §4 risk list is sound (with F-2 adding the stale-trust floor to §3.2).

## Answers to the eight tasked questions

1. **Code anchors:** ~35 of 37 verified at file:line; one WRONG (adapter→vm_lab/mod.rs, F-3), three ±1-2 line nits (F-6).
2. **Gap B central claim:** REFUTED (F-1). `bootstrap()` (`daemon.rs:8623`, called `:11812` on every startup) applies the full dataplane generation — `:8878` with `protected_dns: true` (`:8889`) — from `load_verified_trust` (`:8766`) + `load_verified_membership` (`:8775`) before the reconcile loop; the `protected_dns` arm runs `apply_dns_protection()` (`phase10.rs:6852-6853`). `dns_protected()` is live-apply-derived (macOS `:4605-4607`), not persisted-derived — the plan is right on that sub-point only. No startup path before first refresh re-applies posture? Wrong: bootstrap IS that path, on both platforms (Linux `phase10.rs:3281+`, same apply pipeline).
3. **Linux startup:** killswitch + DNS posture are re-established inside the bootstrap apply (`:8878`), not by the systemd timer; the "same fail-open window, timer load-bearing" framing is unsupported (F-4). The timer is redundancy/determinism.
4. **§3.2 vs stale signed state:** as drafted ("re-use persisted generation") it is unsafe without the F-2 floor: any direct apply must keep `validate_trust` (`phase10.rs:6543`), PreExpiry/replay checks (`:6216`), and must never apply peers/routes from unrefreshed persisted trust; strictest-secure scope is local deny-direction posture only, and expiry timers must not reset (plan §4 already correct there).
5. **Ordering:** M1-backup-restore-before-re-apply is correctly identified and holds (`:11789` → `:11812`); S1 interplay correctly characterized. With F-1, the actual repair target is the bootstrap apply itself; M1 ordering concerns remain valid for it.
6. **§3.1:** seam and order pin verified as above; failure semantics (non-zero refresh fails enforce) correct; Linux enforce parity is a real gap (verified — no refresh chained); race harmlessness argued above.
7. **Offline test plan:** feasible. `DryRunSystem` records ops via `step()` into an operations log (`phase10.rs:941-951`, `:976-977`); the macOS test runtime uses it (`daemon.rs:11526+`), exposed via `dns_posture_test_runtime` (`daemon.rs:18227`, wrapping `build_runtime_with_custom_relay` `:22187`). Concrete fns: assert `apply_dns_protection` appears exactly once during a startup bootstrap (mirrors the existing one-assert comment `daemon.rs:18216-18221`); zero-op when posture absent (pattern: `dns_posture_assert_skipped_when_not_dns_protected` `:18270`); `DryRunSystem::default().fail_on("apply_dns_protection")` (model `:36061`) → expect restriction/fail-closed.
8. **Fail-closed weakening:** none proposed by the plan that survives review, but F-2's floor must be written into §3.2 before implementation; the amended §3.2 (diagnose-first) removes the only path that could have applied stale signed state at startup.
