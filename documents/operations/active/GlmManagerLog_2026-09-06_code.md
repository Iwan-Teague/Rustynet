# GLM Manager C Log — CODE stream (2026-09-06)

Scope: code fixes only. NO lab runs, NO SSH to guests/hosts, NO VM control, NO host pfctl/sudo.
Worktree: `state/edit-worktrees/edit-1788730584891-34192-0`, branch `ai-edit/edit-1788730584891-34192-0`.
Baseline chain: `ai-edit/edit-1788704035701-95384-0` @ `092e94cf` (WIP automatic checkpoint, timed_out).
Toolchain: pinned 1.88.0 (`PATH=$HOME/.rustup/toolchains/1.88.0-aarch64-apple-darwin/bin:$PATH`).
`CARGO_TARGET_DIR=/Users/iwan/Desktop/Rustynet/target-pinned-c`.

## Plan (crash-safe; written before each step)

- TASK 0: merge-readiness @092e94cf — fmt / clippy -p rustynet-cli / test -p rustynet-cli (crate only). Fix trivial fmt/clippy only; commit separately.
- TASK 1: failure-time tunnel capture in `traffic_test_matrix.rs` before Failed return (~line 209). Per-node files `logs/traffic_test_matrix.failure_capture.<alias>.txt` + one-line summary appended to failure message. No semantic change; capture errors logged, never mask failure. Unit test with stub adapter.
- TASK 2: macOS failure-diagnostics collector empty tarball (run 130201, native.rs:917/:966). Collect launchd state, pfctl anchors+rules, daemon log, `rustynet status`, `netstat -rn`, `scutil --dns`; FAIL LOUD when nothing collected. Unit-test file-list/command builder.
- TASK 3: cross-bridge reachability preflight in `stage/preflight.rs` from LIVE ssh_target IPs. WARN when plan lacks dataplane stages; HARD FAIL naming CP-1 + blocker doc §9 + `scripts/vm_lab/cross_vmnet_pf_override.pf` when plan has traffic_test_matrix / live_two_hop_validation / live_managed_dns_validation / relay_forwards_frame_validation. macOS control-plane cells must keep running across split. Pure decision fn, unit-tested.
- TASK 4: macOS adapter cleanup (`adapter/macos.rs` ~line 305): flush every `com.rustynet/*` pf anchor (`pfctl -sA`, then `pfctl -a <anchor> -F all`), argv-only, validate anchor name `^com\.rustynet/[A-Za-z0-9_.-]+$`. Lab-robot only. Unit-test builder + validator.
- TASK 5: QH-70..73 entries in `QualityHardeningTodo_2026-07-25.md` (existing format); mark 71-73 fixed-in-branch once landed.
- After each task: fmt check, clippy -p rustynet-cli, targeted test, commit. Adversarial review of TASK 1-4 diffs by glm-5.3 (ai_read; stdio fallback).

## merge-readiness @092e94cf

Step 0.1 (running): `cargo fmt --all -- --check`, then `cargo clippy -p rustynet-cli --all-targets --all-features -- -D warnings`, then `cargo test -p rustynet-cli --all-targets --all-features` (crate only; first build cold).

Step 0.2 (results @092e94cf, all green):
- `cargo fmt --all -- --check` → RC=0 (clean).
- `cargo clippy -p rustynet-cli --all-targets --all-features -- -D warnings` → RC=0, finished in 48.23s.
- `cargo test -p rustynet-cli --all-targets --all-features` → RC=0; 93 test-result lines, all `0 failed` (53 bins with 0 tests; others pass, e.g. 60/48/22/22 per bin).

Verdict: baseline merge-ready. No fmt/clippy fixes required; no trivial-fix commit needed. Proceeding to TASK 1.

## TASK 1 — failure-time tunnel capture (traffic_test_matrix.rs)

Step 1.1 (plan, written before implementation): insert `capture_failure_state(ctx) -> Vec<String>` called ONLY on the Failed path (before `StageOutcome::Failed(errors.join("; "))`, ~line 206-210). For each topology alias in ctx.assignments with an adapter: call existing trait methods only — collect_mesh_ip(), collect_active_tunnels(), collect_daemon_failure_reason() — and write `logs/traffic_test_matrix.failure_capture.<alias>.txt` under ctx.report_dir with labeled sections; per-collector Err recorded in-file as `capture error: {e}` (never masks the stage failure; file-write errors ignored via `let _ =`). Returns one summary line per node, appended to the failure message after errors.join. Pass path untouched → pass/fail semantics unchanged. No new trait methods; no shell_host dispatch.

Step 1.2 (tests): FakeCaptureAdapter stub in the tests mod (required-methods pattern from FakeSshAdapter, rest unimplemented!()). Ok-path stub: collect_mesh_ip→"100.64.0.x" (mesh re-collect loop exits immediately), collect_active_tunnels→known lines, collect_daemon_failure_reason→Some("reason"), ping_mesh_peer→Blocked (forces Failed). Assert message contains "[failure-capture" and per-node file exists with expected lines. Err-path stub: collectors return Err(AdapterError::Ssh) → file contains "capture error:", original ping error still in message, no panic.

Step 1.3 (results): implemented `capture_failure_state(ctx) -> Vec<String>` + Failed-branch wiring + FakeCaptureAdapter tests in traffic_test_matrix.rs. Gates: fmt RC=0; clippy -p rustynet-cli -D warnings RC=0 (16.19s); targeted `cargo test ... traffic_test_matrix` → 3 passed (empty_assignments_no_mesh_ips_fails unchanged, failure_capture_writes_per_node_file_on_failed_stage, failure_capture_errors_do_not_mask_stage_failure), 0 failed. Pass/fail semantics unchanged (capture only on Failed branch, early-return path untouched). Committing.

## TASK 2 — macOS failure-diagnostics collector: empty-tarball root cause + FAIL LOUD

Step 2.1 (root cause, from code read): `macos_traffic.rs::collect_artifacts` (:487-522) tars `MACOS_STATE_ROOT` + `/usr/local/var/log/rustynet` with `2>/dev/null || tar -czf <tmp> --files-from /dev/null`. When either path is missing (the log dir does not exist on macos-utm-1), the first tar exits 1 and the fallback creates a VALID EMPTY tarball (exit 0) → scp pulls it → `verify_no_key_material_tarball` passes → silently empty artifact in run 130201. Windows already FAILs LOUD (`build_diag_archive_script` throws on 0-of-N copies); macOS must match that philosophy.

Step 2.2 (plan, written before implementation): in `macos_traffic.rs` add (a) `pub fn macos_diagnostic_collectors() -> Vec<(&'static str, &'static str)>` — (file-stem, command) pairs: `sudo -n launchctl print system/<label>` for com.rustynet.{daemon,anchor,relay,exit,privileged-helper}; `sudo -n pfctl -s Anchors`; per-anchor `sudo -n pfctl -a <a> -s rules` loop over rustynet anchors (enumerated, never fixed names); `/usr/local/bin/rustynet status`; `netstat -rn`; `scutil --dns`; guarded daemon-log tail of /usr/local/var/log/rustynet. (b) `fn build_diag_archive_script(remote_tar: &str) -> String` — stage each collector into `/tmp/rn_diag_capture/<name>.txt` (`{ cmd; } > file 2>&1`, always succeeds), then tar staging + `[ -d ]`-guarded MACOS_STATE_ROOT + log dir with the existing key excludes (`keys`, `*.priv`, `*.key`, `*.pem`), then in-script non-empty assertion (`tar -tzf | grep -vc '/$'` == 0 → `exit 42`). (c) rewrite `collect_artifacts` to run the builder script (run_remote Err on exit 42 → map to clear "empty diagnostics archive" error), keep scp_from + validated rm cleanup + `verify_no_key_material_tarball`, and add LOCAL non-empty assertion helper `assert_tarball_non_empty` (tar -tzf, non-directory member count > 0) so both an in-script and a post-transfer guard exist. Errors surface through diagnostics.rs `artifact_error` (stage-level warning in report) — FAIL LOUD satisfied without touching wiring. Unit tests: collector list covers required surfaces; script stages every collector + excludes keys material + carries exit-42 assertion.

Step 2.3 (results): implemented in `macos_traffic.rs`: `macos_diagnostic_collectors()` (11 read-only collectors: launchctl print ×5 labels, pfctl -s Anchors, per-rustynet-anchor `pfctl -a "$a" -s rules` loop, `/usr/local/bin/rustynet status` (pinned to MACOS_RUSTYNET_PATH by test), netstat -rn, scutil --dns, guarded daemon-log tail); `build_diag_archive_script(remote_tar)` (stages each collector to /tmp/rn_diag_capture/<name>.txt, tars staging + [ -d ]-guarded state/log roots with keys/*.priv/*.key/*.pem excludes, in-script `members=$(tar -tzf|grep -vc '/$'); [ >0 ] || exit 42`); `assert_tarball_non_empty(path)` local non-dir member assertion; `collect_artifacts` rewritten to use the builder (exit 42 → AdapterError::Protocol "archive is empty"), keeps scp_from + validated rm + verify_no_key_material_tarball, then asserts non-empty locally. Empty-but-valid-tarball class eliminated at two layers. Gates: fmt RC=0; clippy -p rustynet-cli -D warnings RC=0 (15.35s); targeted `cargo test ... macos_traffic` → 29 passed 0 failed ×2 targets incl. 3 new tests (collectors cover required surfaces; script stages every collector + no --files-from fallback + exit 42; non-empty rejects dir-only/missing). Committing.

## TASK 3 — cross-bridge reachability preflight (preflight.rs)

Step 3.1 (plan, written before implementation): add to `stage/preflight.rs` a cross-bridge block between the clock-skew loop and `StageOutcome::Passed` (execute() :322, Passed at :493): (a) pure `classify_subnet_split(targets: &[(alias, host)]) -> Vec<SubnetGroup{subnet: [u8;4], aliases: Vec<String>}>` — strip optional `:port` from host (SshConnectionParams stores bare IP in adapters but be defensive), parse as Ipv4Addr, mask /24; unparseable/IPv6 entries noted as excluded; groups sorted by subnet, aliases sorted within. (b) pure `cross_bridge_probe_argv(platform, ip) -> Vec<String>` — Linux: `timeout 10 bash -c "exec 3<>/dev/tcp/{ip}/22"`; macOS: `nc -z -G 5 {ip} 22`; Windows: `powershell.exe -NoProfile -NonInteractive -Command (Test-NetConnection -ComputerName {ip} -Port 22).TcpTestSucceeded`; default arm → Linux argv. ip always a validated Ipv4Addr display string → no injection surface. (c) pure decision: `enum CrossBridgeOutcome { NoSplit, Pass, Warn(String), Fail(String) }` + `decide_cross_bridge(split, probe_failures, planned)` — ≤1 subnet → NoSplit; no failures → Pass; failures + plan contains any of TrafficTestMatrix | LiveTwoHopValidation | LiveManagedDnsValidation | RelayForwardsFrameValidation → Fail naming "CP-1", "MacosCrossNetworkTrafficBlocker_2026-09-03 §9", "scripts/vm_lab/cross_vmnet_pf_override.pf"; else → Warn (control-plane cells keep running; WARN = eprintln + recorded, stage stays Passed since StageOutcome has no warn variant). (d) execute() wiring: gather (alias, host) via adapter.ssh_connection_params(); classify; if ≥2 subnets probe each pair both directions (first alias of each subnet → first alias of the other) with source adapter shell_host().run_argv(probe argv); non-zero/Err → failure line "{src} → {dst} ({ip}):22 cross-bridge unreachable ({detail})"; write logs/cross_bridge_preflight.txt (targets, subnets, probe results, decision; write errors eprintln-only, never mask); Fail → StageOutcome::Failed; Warn → eprintln + Passed; Pass/NoSplit → record + Passed. (e) `PreflightStage` gains `pub planned_stage_ids: Vec<StageId>`; plan.rs `PlanBuilder::build()` computes `let planned: Vec<StageId> = StageId::ALL.iter().filter(|id| include(id)).copied().collect();` BEFORE the map closure and passes `planned.clone()` into PreflightStage; update the 2 test literals in preflight.rs tests. (f) unit tests: classify (split/group/exclude/sort), probe argv per platform incl. embedded ip, decide (NoSplit; Pass; Fail ×4 dataplane stages w/ CP-1 + §9 + .pf name; Warn for control-plane-only plan; Warn for empty plan).

### Step 3.2 — implementation

- `PreflightStage` gains `planned_stage_ids: Vec<StageId>`; plan.rs materializes the planned set first (`let planned: Vec<StageId> = StageId::ALL.iter().filter(include).cloned().collect()`) and passes `planned.clone()` into the preflight arm. StageId is Clone but NOT Copy (corrected during compile).
- After the clock-skew loop, execute() now delegates the final verdict to `cross_bridge_preflight(ctx)`:
  - `classify_subnet_split` groups live `ssh_connection_params().host` values by /24 (port-stripped; non-IPv4/IPv6 excluded and reported).
  - >=2 groups: probes each subnet pair BOTH directions (first alias per group) guest→guest TCP/22 via the source adapter's `shell_host().run_argv` — Linux `timeout 10 bash -c 'exec 3<>/dev/tcp/IP/22'`, macOS `nc -z -G 5 IP 22`, Windows `Test-NetConnection` (success additionally requires stdout True).
  - Report written to `logs/cross_bridge_preflight.txt` in the report dir (write errors eprintln-only, never mask).
  - `decide_cross_bridge`: NoSplit / Pass / Warn (no dataplane stage planned — macOS control-plane cells keep running) / Fail naming CP-1, MacosCrossNetworkTrafficBlocker_2026-09-03 §9, scripts/vm_lab/cross_vmnet_pf_override.pf when any of traffic_test_matrix / live_two_hop_validation / live_managed_dns_validation / relay_forwards_frame_validation is planned.

### Step 3.3 — verification

- `cargo fmt --all -- --check` → RC=0.
- `cargo clippy -p rustynet-cli --all-targets --all-features -- -D warnings` → clean (fixed: StageId not Copy → .cloned(); CrossBridgeOutcome derives Debug/Clone/PartialEq/Eq; test loop uses stage.clone()).
- `cargo test -p rustynet-cli --all-targets --all-features preflight` → 34 passed, 0 failed (8 new: classify×3, probe argv×1, decide×3 + helper; both pre-existing PreflightStage literals updated with planned_stage_ids: Vec::new()).

## TASK 4 — flush com.rustynet/* pf anchors on macOS cleanup + uninstall

Step 4.1 — root cause (read of adapter/macos.rs, macos_install.rs, macos_traffic.rs):
- adapter/macos.rs:157 uninstall_daemon delegates to macos_install::uninstall_daemon; :305
  cleanup_runtime_state delegates to macos_traffic::cleanup_runtime_state.
- macos_install.rs:1155 uninstall_daemon stops the daemon then rm's binaries/plist/state dirs.
  It NEVER flushes pf anchors and never calls cleanup_runtime_state — so a loaded anchor
  (live finding: com.rustynet/blind_exit with `block drop out quick all`) survives uninstall.
- macos_traffic.rs cleanup_runtime_state runs MACOS_RESET_COMMAND, which DOES enumerate
  (`sudo -n pfctl -s Anchors | sed | grep -i rustynet || true`) and flush each anchor
  (`sudo -n pfctl -a "$a" -F all 2>/dev/null || true`), but every error is swallowed by
  `|| true` / `let _ =` — a `sudo -n` denial is indistinguishable from success.
- The strict task regex `^com\.rustynet/[A-Za-z0-9_.-]+$` does NOT match the killswitch
  family com.apple/rustynet_g<N>, so the broad shell pass stays; the argv-only strict pass
  is added as defense in depth with surfaced errors.

Step 4.2 — plan:
- macos_traffic.rs: add `is_rustynet_pf_anchor(name)` (charset-validated
  com.rustynet/<non-empty [A-Za-z0-9_.-]> suffix), `parse_pfctl_anchor_list(output)`,
  `build_anchor_flush_args(anchor) -> Result<Vec<ValidatedArg>, AdapterError>` (Err on
  invalid anchor), `flush_rustynet_pf_anchors_argv(conn) -> Result<usize, AdapterError>`:
  enumerate anchors via ssh, parse, filter strict names, flush each through
  RemoteCommand::from_args + run_remote (argv-only, per-anchor errors eprintln'd, count
  returned). cleanup_runtime_state calls it best-effort after MACOS_RESET_COMMAND.
- macos_install.rs: uninstall_daemon calls flush_rustynet_pf_anchors_argv best-effort
  after the rm pass — the actual gap fix.
- Unit tests: validator accept/reject (incl. crafted `com.rustynet/x;reboot`,
  traversal `com.rustynet/../../etc`, space, empty, wrong prefix), parser trim/drop-empty,
  builder Err-on-invalid + exact argv for valid, source pin that uninstall_daemon wires
  the flush.

### Step 4.3 — Results (2026-09-06)

- macos_traffic.rs: 4 new pub fns (is_rustynet_pf_anchor :658, parse_pfctl_anchor_list :672, build_anchor_flush_args :684, flush_rustynet_pf_anchors_argv :708) + WIRE A (cleanup_runtime_state calls strict argv-only flush after MACOS_RESET_COMMAND, errors eprintln'd) + 5 unit tests.
- macos_install.rs: WIRE B — uninstall_daemon now flushes com.rustynet/* pf anchors best-effort after removing binaries/state (root cause of the surviving com.rustynet/blind_exit `block drop out quick all` anchor: uninstall never touched pf at all).
- Compile fix: AdapterError::Protocol is a struct variant — `Protocol { message: ... }`, not tuple form.
- Gates: fmt --check RC=0; clippy -p rustynet-cli --all-targets --all-features -D warnings RC=0 (21.65s); `cargo test -p rustynet-cli --all-targets --all-features macos` RC=0, 0 failed everywhere (372 passed lib target incl. the 5 new tests, 328 passed second target).
- New tests: rustynet_pf_anchor_validator_accepts_strict_names, rustynet_pf_anchor_validator_rejects_crafted_names, pfctl_anchor_list_parser_trims_and_drops_empty_lines, anchor_flush_args_reject_invalid_and_build_valid, uninstall_daemon_flushes_rustynet_pf_anchors (source pin).

## TASK 5 — QH-70..73 register entries

- Step 5.1 (2026-09-06): Filed QH-70..QH-73 in
  `documents/operations/active/QualityHardeningTodo_2026-07-25.md` in the
  existing entry format (header count 69 -> 73).
  - QH-70 OPEN: `mesh_status_validation` false-green — PASSED run 130201 with
    all four tunnel legs dead; checks configured peers, not handshakes or
    traffic. Fix needs an owner decision on owning crate (rustynetd validator
    vs rustynet-cli stage reading `wg show`); this stream may not edit those
    crates, so direction proposed in the entry only.
  - QH-71 FIXED-in-branch `b221cad1` (TASK 2): macOS diagnostics empty-tarball.
  - QH-72 FIXED-in-branch `ba3ff9a3` (TASK 3): cross-bridge preflight.
  - QH-73 FIXED-in-branch `229ba864` (TASK 4): com.rustynet/* pf anchor flush
    on uninstall + strict argv-only validated cleanup pass.

## RESUME — 2026-09-06 (late)

### Step R.1 — checkpoint 7fde653e inspection (decision: KEEP)

`git show --stat 7fde653e`: one file, +7/−2, `macos_install.rs::uninstall_daemon`.
The edit is COMPLETE, not half-done: it captures the rm result without `?`, runs
the com.rustynet/* pf anchor flush regardless (so a wedged daemon that failed rm
still gets its anchors flushed), then propagates `rm_result?` at the end. Correct
ordering semantics, no dangling state. Verified against the surrounding code in
the diff itself. Kept as-is; no revert. It will be covered by the end-of-run
clippy/test gates and by the TASK 4 adversarial review context below.

### Step R.2 — adversarial security review of TASK 1-4 diffs (glm-5.3)

Plan: one `ai_read` (model glm-5.3) per commit — 9d25e652, b221cad1, ba3ff9a3,
229ba864 — prompt "REFUTE this patch: find fail-open paths, unvalidated input
reaching argv/shell, changed pass/fail semantics, panics in production paths",
context = the commit's `git show` diff only (checkpoint 7fde653e appended to the
TASK 4 context since it touches the same function).

### Step R.2a — 9d25e652 (TASK 1 traffic_test_matrix failure capture) review

glm-5.3 verdict: sound on the four axes (no fail-open, no shell/argv, no
production panics, pass/fail semantics unchanged). Findings + disposition:

- FINDING (security, low): alias used unvalidated as filename component —
  `logs/traffic_test_matrix.failure_capture.{alias}.txt` lets a malformed
  topology alias (`../..`, `/`) escape the report dir via std::fs::write.
  APPLIED: `is_safe_capture_alias` gate (rejects empty / `/` / `\` / `..`)
  + skip with eprintln; unit test `capture_alias_safety_rejects_path_fragments`.
- FINDING (evidence integrity): remote-controlled strings (tunnel lines,
  daemon reason, collector error text) written verbatim — embedded `\n` can
  forge evidence lines. APPLIED: `single_line()` newline collapsing on all
  three; unit test `single_line_collapses_newlines_from_remote_output`.
- FINDING (diagnostics correctness): collector Err summarized as
  `0 tunnel line(s)` — reads as "no tunnels" when state is unknown. APPLIED:
  `tunnels=error` distinct label; test assertion updated.
- FINDING (contract drift / style, REJECTED): appended `; [failure-capture …]`
  segments could break downstream failure-message parsers — checked: stage
  messages are recorded verbatim in stage logs, no parser splits on "; " in
  this path; eprintln! consistent with surrounding orchestrator code.
- Scoped test: `cargo test -p rustynet-cli --all-targets --all-features
  --features vm-lab traffic_test_matrix` → 7 passed / 0 failed (lib).

### Step R.2b — b221cad1 (TASK 2 macOS diagnostics fail-loud) review

glm-5.3 verdict: core fail-loud logic sound; no unvalidated input reaches the
shell (all collector strings compile-time constants); no production panics;
empty-archive class closed at two layers. Findings + disposition:

- FINDING (operational): no per-collector timeout — `rustynet status` against
  the wedged daemon (the exact scenario triggering collection) hangs the whole
  script to MEDIUM_TIMEOUT, losing every collector's output. APPLIED: sh
  watchdog per collector in build_diag_archive_script —
  `( { cmd; } & p=$!; ( sleep 20; kill $p ) >/dev/null 2>&1 & wait $p )` —
  macOS ships no `timeout`. Test pins `sleep 20; kill $p` in the script.
- FINDING (security): `launchctl print` dumps each service's environment dict
  verbatim into the archive; tar excludes are name-based and
  verify_no_key_material_tarball reads member NAMES only (confirmed at
  macos_traffic.rs:1086 — `tar -tzf` listing check), so a secret env var in a
  plist would ship unfiltered. APPLIED: sed range-delete of the
  `environment = { ... }` block on all 5 launchctl collectors + coverage test
  asserting every launchctl_ collector carries the redaction.
- FINDING (test quality): dir-only case re-implemented the count inline and
  asserted on the copy — would pass if the function were wrong. APPLIED:
  test now builds a real dir-only tarball fixture and asserts
  `assert_tarball_non_empty(...).is_err()`.
- FINDING (minor): exit-42 path orphaned the remote tarball in /tmp. APPLIED:
  rm_cmd built up front; best-effort cleanup runs before propagating the
  diag error.
- FLAG (accepted risk): predictable /tmp/rn_diag_capture + tarball paths are
  symlink/TOCTOU-able by a local user; single-user lab VM threat model —
  accepted, noted here for anyone copying the pattern elsewhere.
- Scoped test: `cargo test -p rustynet-cli ... --features vm-lab macos` →
  372 passed / 0 failed (lib) + all other targets ok.

### Step R.2c — ba3ff9a3 (TASK 3 cross-bridge preflight) review

glm-5.3 verdict: NOT sound — 2 fail-open defects + 1 latent + drift hazard
(all verified against the code before applying):

- FINDING (fail-open, Windows): probe gated on stdout `contains("True")`;
  Test-NetConnection prints `PingSucceeded : True` on ICMP-reachable hosts,
  so TCP/22-blocked-but-pingable (the CP-1 pf shape) false-passed. APPLIED:
  Windows argv now `if ((...).TcpTestSucceeded) { exit 0 } else { exit 1 }`,
  exit code is the sole discriminator, stdout check deleted; new test
  `cross_bridge_windows_probe_exits_on_tcp_result`.
- FINDING (fail-open, gate bypass): non-IPv4 ssh hosts (IPv6/hostname) went
  to `excluded` and never influenced the decision — split fleets carrying
  one read as clean NoSplit/Pass. APPLIED: `decide_cross_bridge` now takes
  `excluded`; any excluded target under a dataplane plan → Fail
  ("unprovable"), control-plane plans → Warn (never clean Pass); new test
  `decide_cross_bridge_excluded_targets_never_pass_cleanly`; 3 existing
  call sites/tests updated.
- FINDING (latent fail-open): adapter-miss pair did `continue` → zero
  failures → Pass claiming probes that never ran. APPLIED: pushes
  "probe skipped: adapter missing … unproven" as a probe failure
  (fail-closed).
- FINDING (drift hazard): hardcoded 4-StageId list. PARTIALLY APPLIED:
  renames are compile-pinned (match arms); added doc note that ADDING a new
  cross-bridge dataplane StageId requires extending the list in the same
  change. A mechanical guard is impossible without stage-registry metadata
  this stream should not add.
- FINDING (spurious hard-fail on exec errors, REJECTED): distinguishing
  "inconclusive" (missing nc/powershell, spawn error) from "blocked" would
  downgrade a fail-closed gate; keeping tooling errors as failures is the
  conservative direction. Logged for the owner.
- MINOR APPLIED: strip_ssh_port doc corrected (IPv6 CAN end in a numeric
  group; safety comes from the later Ipv4 parse, not the strip); probe
  stderr control-chars sanitized (`sanitize_probe_text`); report states
  one-alias-per-/24 sampling.
- Scoped test: cross_bridge filter → 6 passed / 0 failed.

### Step R.2d — 229ba864 + 7fde653e (TASK 4 pf anchor flush on uninstall) review

glm-5.3 verdict: argv-only + charset validation sound (no injection, no
production panics, deferred rm ordering correct), but 2 real defects + 1
verification requirement:

- FINDING (fail-open): uninstall_daemon only eprintln'd the flush error and
  returned Ok — a sudo -n denial left `com.rustynet/blind_exit`
  `block drop out quick all` live on a "cleanly uninstalled" machine (the
  original incident, now with a stderr note). APPLIED: uninstall propagates
  the flush error (`flush_rustynet_pf_anchors_argv(conn)?` before
  `rm_result?`); source-pin test extended to pin BOTH the call and the
  propagation. cleanup_runtime_state stays best-effort by design (documented).
- FINDING (lost signal): `Result<usize>` counted successes only — callers
  could not distinguish "0 anchors present" from "present but flush-denied".
  APPLIED: signature now `Result<(found, flushed), AdapterError>` and returns
  Err naming failed anchors whenever any observed anchor survives; all anchors
  are still attempted before erroring.
- FINDING (conditional): "errors are surfaced" rested on run_remote exit-code
  semantics. VERIFIED SAFE: ssh.rs run_remote_inner returns
  Err(AdapterError::Command) on any nonzero exit (checked at :715-722), so a
  sudo denial during anchor LISTING propagates; only the per-anchor flush
  step had the gap (closed above).
- MINOR (logged, no change): `com.rustynet/..` passes the charset validator —
  harmless (argv-only exec, pfctl does not path-normalize anchor names;
  validator is defense-in-depth); strict pass covers fewer anchors than the
  broad shell pass by design (killswitch family excluded);
  `pfctl -F all` leaves the anchor listed so counts are not residue
  indicators across runs.
- Scoped: macos test filter 372 passed / 0 failed (lib); clippy
  -p rustynet-cli --all-targets --all-features --features vm-lab -D warnings RC=0.
