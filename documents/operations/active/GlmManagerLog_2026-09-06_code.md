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
