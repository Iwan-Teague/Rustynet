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
