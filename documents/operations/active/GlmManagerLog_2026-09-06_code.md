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
