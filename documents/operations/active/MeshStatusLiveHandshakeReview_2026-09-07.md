# QH-70 Review — Live-Handshake Evidence in `mesh_status_validation` (2026-09-07)

Adversarial read-only review of `git diff 1efc8376..HEAD -- crates/` (5 commits, 9 files, +512/−12, all under `crates/rustynet-cli/src/vm_lab/`). Scope question: can the stage still pass with dead tunnels; does the poll fail closed; unwrap/expect in non-test code; secret leakage in the Windows/macOS status path.

## Answers to the specific questions

**Can the stage still pass with all tunnels dead?** No for the all-dead case, with one residual gap (F1, partial mesh). Grounding: the daemon itself only counts a peer live when its handshake is fresh — `rustynetd/src/daemon.rs:8444-8445` (`let handshake_fresh = self.traversal_handshake_is_fresh(handshake_unix, now_unix)`, `crates/rustynetd/src/daemon.rs:8090-8094`), and `path_latest_live_handshake_unix` prints `none` when no live handshake exists (`daemon.rs:7156-7158`), which `count_field`'s `parse::<u64>()` rejects → fail-closed. A status line missing any of the three fields, or a parse quirk, returns `Err` (`mesh_status.rs` `count_field`: "`{key}` is not a count"), never "no peers observed, so pass". `expected_live_peers` is 0 only when `ctx.assignments.len() == 1` (`stage/mesh_status_validation.rs:69`: `assignments.len().saturating_sub(1)`), i.e. genuinely single-node — not reachable on a multi-node run.

**Does the poll time out fail-closed?** Yes. `poll_live_handshake` (`stage/mesh_status_validation.rs:115-141`) returns `Err(...(after 120s))` when the deadline expires, and every non-passing outcome (transport error, clock error, evaluator error) is an `Err` that re-enters the retry loop, never an `Ok`. Deadline check happens after the failing attempt, so at least one attempt always runs; overshoot is bounded by one `SHORT_TIMEOUT` SSH call.

**unwrap/expect in non-test code in the diff?** None. The only closers are `unwrap_or("absent")` (echo-only relay fields) and `saturating_sub`. (The two `expect()` calls at `daemon.rs:8464`/`8485` are pre-existing daemon code, not in this diff.)

**Secret leak via Windows/macOS status query into the evidence string?** No. Windows: `windows_traffic.rs:167-175` builds the script from `ValidatedArg::windows_path(WINDOWS_RUSTYNET_PATH)` + `cli_token("status")` — no password, no shell interpolation, no untrusted argv. Linux/macOS: `DAEMON_STATUS_COMMAND` is a compile-time const (`linux_traffic.rs:388-391`, `macos_traffic.rs:340-345`), socket path + `sudo -n`, no interpolation. Stage failure strings embed only parsed field values and the relay echo (`relay_session_state`/`relay_session_established_peers` — daemon counters, not secrets); the full status text is never echoed into a failure. Status text does contain `local_wg_public_key=` — a public key, not secret material.

**relay_session fields gating instead of echoing?** They echo only: `field(&tokens, "relay_session_state").unwrap_or("absent")` is formatted into `relay_evidence`, used exclusively inside failure messages; no gate references them. Correct — relay deploys two stages later.

## Findings

### F1 — blocker: `expected_live_peers` is used only as a zero/non-zero flag; a single dead tunnel pair still passes on ≥3-node runs

`stage/mesh_status_validation.rs:69` computes `expected_live_peers = assignments.len() - 1` and the comment claims "Every OTHER assigned node must be live: full mesh is the run's own contract" — but `evaluate_live_handshake_status` (`role_validation/mesh_status.rs`) never compares `live` against `expected_live_peers`. Every clause tests `expected_live_peers > 0` (existence of any expectation) and then only `live == 0` / `programmed == 0`. `live >= 1` with a fresh handshake passes for any multi-node run.

Failure scenario: 3-node run (A, B, C). Tunnel A↔C is dead; A↔B and B↔C are alive. Polling A: `path_live_peer_count=1` (≠0), `path_programmed_peer_count=2` (≠0), handshake to B fresh → `Ok`. Polling C: symmetric → `Ok`. B: `live=2` → `Ok`. Stage passes with one of three tunnels dead — the exact false-green class QH-70 exists to kill, one level up. The existing per-node snapshot validator does not cover it (membership is converged; only reachability is broken).

Fix (one line): gate `if (live as u32) < expected_live_peers { return fail(...) }` after the `== 0` check (keep zero-check for single-node), and test with a 3-peer status line where `live < expected`.

### F2 — should-fix: host-clock vs guest-clock skew makes the handshake gate a flaky false-fail

`poll_live_handshake` compares the daemon's guest-side handshake timestamp against the orchestrator host clock (`SystemTime::now()` at `stage/mesh_status_validation.rs:125-129`). The daemon's own freshness uses the guest clock (`daemon.rs:8090-8094`). After a lab VM pause/resume or NTP drift >180 s, a genuinely live tunnel fails as "future-dated" (guest ahead) or "{age}s old" (guest behind) — a false failure of a healthy dataplane; the 120 s poll cannot repair a persistent skew. This is fail-loud, not fail-open, so severity is should-fix, but it will burn runs as unexplained flakes and invites someone later "softening" the check. Fix: derive `now_unix` from a node-reported field (e.g. parse `last_reconcile_unix`-adjacent generation time) or add a bounded skew tolerance (e.g. treat `handshake > now + 300` as future-dated).

### F3 — nit: relay echo-only path has no negative test

`LIVE_STATUS` (test fixture) always carries `relay_session_state=none relay_session_established_peers=0`. No test strips the relay fields to prove `unwrap_or("absent")` keeps a pass a pass (the echo-only contract the doc comment promises). A regression that starts gating on `relay_session_state` would still pass the current suite. Fix: add `evaluate_live_handshake_status("n1", &status_without("relay_session_state"), 1, NOW)` → must be `Ok`.

### F4 — nit: `field`/`count_field` take the first matching token

`mesh_status.rs` `field()` uses `.iter().find()` — first occurrence wins. `rustynet status` emits the daemon's single status line (one occurrence per field, `daemon.rs:9259`), so no decoy exists today; if the CLI ever grows multi-line output (e.g. per-peer blocks), a repeated `path_live_peer_count=` earlier in the output would silently mask the aggregate. Fix: `find` → detect duplicates and fail (`itertools`-free: collect matches, `assert len == 1`), or assert the token set is unique.

### F5 — nit: serialized per-node polling multiplies worst-case stage wall clock

`execute` polls nodes sequentially (`for alias in &aliases { ... poll_live_handshake(...) }`), each up to 120 s on top of the snapshot validator. A 3-node run where every node is dead adds ~6 min before the stage fails; a 7-node run ~14 min. Pure performance/latency, semantics correct. Fix: `rayon`/`std::thread` fan-out per node, join failures — or accept and document.

### F6 — nit (informational, no action): reported-skip path still bypasses live evidence for non-desktop platforms

`supports_role_validator(MeshStatus)` (`node_adapter.rs:301-313`) returns true only for Linux/macOS/Windows; any other platform node is reported-skipped and never polled, while still counted in `expected_live_peers` — so if a non-desktop node ever joined `assignments`, desktop nodes would false-fail waiting for its handshake. No such node exists in the current inventory; the default `collect_daemon_status` already fails closed (`UnsupportedPlatform`, tested at `node_adapter.rs` `collect_daemon_status_defaults_to_unsupported_platform`). Recorded so the invariant is explicit: `expected_live_peers` must only count poll-eligible nodes if the inventory ever changes.

## Verification notes

- Parser contract matches the real producer: all three required fields exist verbatim in the daemon status line (`daemon.rs:9259`), `relay_session_state`/`relay_session_established_peers` included; `none` sentinel (used for absent handshake in the netcheck line, `daemon.rs:7156-7158`) fails `parse::<u64>()` → fail-closed.
- Windows/macOS/Linux all reach the poll: `supports_role_validator` covers all three desktop platforms, and each overrides `collect_daemon_status`; the trait default is `Err(UnsupportedPlatform)` — fail-closed, with a test pinning it.
- Command surfaces unchanged in trust shape: Linux/macOS hoisted the pre-existing literal command into `DAEMON_STATUS_COMMAND` byte-identically (diff confirms); Windows reuses the reviewed `live_identity_status_script` argv seam. Each carries a mutation-guard test (`daemon_status_command_pins_socket_env_and_status_verb`).
- Boundary/scope: all changes confined to `crates/rustynet-cli/src/vm_lab/` (lab tooling, `vm-lab`-gated). No shipped-path, scripts/, or .opencode/ files touched. No `ssh_password` appears in any new error string.
- Poll deadline math: `Instant::now() + 120s` checked only after a failed attempt; `sleep(10s)` between attempts; returns the accumulated error on expiry — no path returns `Ok` without `evaluate_live_handshake_status` passing.

## Verdict

`VERDICT: MERGE-WITH-FIXES` — F1 leaves the exact false-green class QH-70 targets reachable on any ≥3-node run with a single dead tunnel pair, because `expected_live_peers` is computed but never compared against `path_live_peer_count`.
