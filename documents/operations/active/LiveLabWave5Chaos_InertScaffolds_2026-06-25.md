# Live-Lab Wave 5 (chaos) — Implement the 3 Inert Chaos Scaffolds — Plan + Spec — 2026-06-25

Parent: `LiveLabCoverageAndHonestyAudit_2026-06-25.md` (§4 finding: 3 chaos tests
inert on ALL OSes; §5.4 chaos best-practice). Author: Iwan-Teague. **Code-only.**

## 0. The problem
`live_chaos_clock_attack_test` (34 lines), `live_chaos_crash_recovery_test` (34),
`live_chaos_resource_exhaustion_test` (44) declare their `ChaosStage`s but then call
the generic `live_chaos_support::run_category`, which on a live run writes
`status:"fail" … "live chaos injection for this category is not enabled by this
scaffold slice"` and **touches no host**. So clock-skew, crash-recovery, and
resource-exhaustion resilience of the signed-trust system are **unproven on every
OS**. The other 5 chaos tests are real (daemon_fault 1011, network_impairment 898,
membership_adversarial 765, privileged_boundary 461, signed_state_adversarial 330) —
they are the templates.

## 1. Deliverable + honest status
Replace each stub's `run_category` call with a REAL inline implementation modeled on
the closest real chaos template: live fault injection over the chaos harness's
SSH/host seam + a fail-closed assertion per stage + the JSON report the real ones
emit. **Status produced = "code-complete + unit-tested, LIVE-RUN-PENDING."** These
are Linux-targeted live tests (the chaos suite runs against Linux lab hosts — accepted
scope); they COMPILE + their pure evaluators UNIT-TEST here, and the live fault
injection runs in the user's Linux lab. No cross-OS/builder gate.

## 2. Methodology per stage (grounded in the research §5.4)
### clock_attack — template: `live_chaos_signed_state_adversarial_test.rs`
Per-process clock control via **`libfaketime`** (`LD_PRELOAD` + `FAKETIME`) on the
guest daemon — surgical, isolates one process, no global VM clock change (research
F15). Stages (already declared):
- `chaos_clock_jump_forward_past_max_age`: start the daemon under a clock jumped
  PAST a signed bundle's max-age → assert future-dated/expired bundles are REJECTED
  (TUF freeze defense, F10), and after clock resync the daemon recovers.
- `chaos_clock_jump_backward_past_replay_window`: jump the clock BACKWARD beyond the
  replay watermark window → assert the replay watermark is NOT regressed and a stale
  (superseded-epoch) bundle is rejected (TUF rollback defense, F8).
- `chaos_clock_skew_slow_drift`: drift within accepted skew → tolerated; out-of-window
  → fail-closed (F16 realistic-skew tolerance).

### crash_recovery — template: `live_chaos_daemon_fault_test.rs`
**`kill -9`** the daemon at trust-state PERSISTENCE boundaries (mid bundle-apply /
watermark write / keystore write — kill-on-fsync style, research F17/F18). Assert on
restart: the on-disk trust state is ATOMIC old-or-new, **NEVER a torn/partially-applied
bundle that downgrades the replay watermark**; the daemon re-handshakes + re-applies
signed state and converges within the recovery deadline. (Pair with the file-corruption
nemesis idea: a truncated/partial bundle on restart must be rejected, not applied.)

### resource_exhaustion — template: `signed_state_adversarial` + `network_impairment`
Feed the control-plane ingest paths (bundle / gossip / IPC) **oversized / endless /
decompression-bomb** payloads (research F24/F25, TUF endless-data cap). Assert:
declared-size + hard cap REJECTS before allocation; the daemon does NOT panic/OOM and
stays responsive (rate-limits/drops); pair with the existing `ipc_parse_command` fuzz
target's crash-safety. A malformed/oversized payload must fail-closed, never crash.

## 3. Non-negotiable honesty rules (carry from Waves 0–2)
- **No fake-pass.** A never-run/unverifiable injection = FAIL (mirror the
  `probe_attempted` discipline). The whole point of this wave is that "not enabled"
  must become a real injected fault + a real assertion.
- **Fail-closed.** If the daemon accepts a future-dated/rolled-back/torn/oversized
  state, that's a FAIL the test must catch.
- **Unit-test the pure evaluators** (the verifiable part here): the report/verdict
  logic, any parser of daemon status / watermark / `dns inspect` / size output. The
  live injection itself runs in the lab.
- Study the closest real template for the SSH/host-seam + report shape; reuse
  `parse_config` / `ChaosStage` / the JSON report shape so the run-matrix tooling
  still ingests the output.

## 4. Agent ownership (DISJOINT — one binary each; do NOT touch the shared harness)
- **W5-A clock_attack** — OWNS `crates/rustynet-cli/src/bin/live_chaos_clock_attack_test.rs`.
- **W5-B crash_recovery** — OWNS `crates/rustynet-cli/src/bin/live_chaos_crash_recovery_test.rs`.
- **W5-C resource_exhaustion** — OWNS `crates/rustynet-cli/src/bin/live_chaos_resource_exhaustion_test.rs`.
- **SHARED (do NOT edit):** `crates/rustynet-cli/src/bin/live_chaos_support/mod.rs`
  (each bin includes it via `mod live_chaos_support;`). If an agent needs a new harness
  helper, it adds it INLINE in its own binary or FLAGS it for the reviewer — never edits
  the shared module (collides + changes all chaos bins).

## 5. Per-agent contract
- Replace the `run_category(config)` call with a real `run_<category>(config)` that
  injects each declared `ChaosStage`'s fault over the host seam (study the template),
  asserts the pass-criterion fail-closed, and writes the same JSON report shape (so
  `--dry-run` still produces a scaffold-validated report, and a live run produces real
  per-stage pass/fail).
- Keep `--dry-run` working (scaffold-validates without mutating a host) — the
  orchestrator uses it.
- Unit-test every pure evaluator/parser inline `#[cfg(test)]`.
- Use argv-only host invocation; no shell construction with untrusted values; never log
  secrets/tokens (chaos tests handle signed state — secrets hygiene applies).
- GATES: `cargo fmt --all`; `cargo check -p rustynet-cli --bin <your_bin>`;
  `cargo clippy -p rustynet-cli --bin <your_bin> --all-features -- -D warnings`;
  `cargo test -p rustynet-cli --bin <your_bin>`.
- Commit in your worktree (no Co-Authored-By trailer; `-c commit.gpgsign=false`). Report:
  branch, SHA, `git show --stat HEAD`, the injection method + per-stage assertion, the
  pure evaluators + their tests, any `// REVIEW:` flagged uncertainty, anything
  incomplete. Do NOT push; do NOT edit the shared harness or any other file.

## 7. OUTCOME — Wave 5 chaos COMPLETE (2026-06-25)

Three parallel worktree agents (disjoint binaries) + reviewer merge/gate. On `main`:
- `f06c46e` **W5-A clock_attack** (+1196): libfaketime per-process clock skew via a
  transient systemd drop-in (`LD_PRELOAD`+`FAKETIME`, `trap` teardown-before-fault).
  Asserts against REAL daemon status observables (`membership_epoch`,
  `traversal_{future_dated,stale,replay}_rejections` — verified against `daemon.rs`):
  forward-jump → future-dated rejected + epoch held; backward-jump → watermark not
  regressed; drift → within-window tolerated / out-of-window fail-closed. 24 new tests.
- `609c1e4` **W5-B crash_recovery** (+1272): kill-on-fsync (`kill -9` loop while a
  bundle/watermark/keystore write is in flight). Asserts atomic old-or-new on restart
  — reads on-disk `assignment=<u64>` (`fetcher.rs WatermarkStore`) to catch a
  watermark DOWNGRADE, rejects a truncated/empty bundle (`version=1`+`signature=`
  parse) and torn keystore, and requires mesh re-convergence. 120 tests.
- `ad601fb` **W5-C resource_exhaustion** (+1152): guest-side IPC/gossip floods beyond
  the 4096-byte caps + endless stream; asserts cap-rejects-before-alloc + daemon
  responsive + no panic/OOM (PID-stable + RSS≤64 MiB) + injection-actually-ran.
  21 new tests.

Gate on merged tree: fmt + clippy `-D warnings` clean; **338 tests across the 3 bins,
0 failed**; `--dry-run` smoke preserved (`overall_status:"skipped"`, exit 0, no host
mutation) so the orchestrator scaffold contract is unchanged. No fake-pass: each bin
has explicit fail-closed tests for "daemon accepted the bad state" AND "injection
never ran". These are Linux-targeted live tests — **code-complete + unit-tested here,
the actual fault injection runs in the Linux lab**.

### Honest scope note — W5-C re-declared its stages
W5-C replaced the original *host-resource* exhaustion stages
(`chaos_disk_full_signed_state_write`, `chaos_readonly_filesystem_state`,
`chaos_inotify_watch_exhaustion`, `chaos_file_descriptor_exhaustion`) with
*control-plane INGEST* exhaustion stages (IPC/gossip oversized + endless + bomb), per
this spec's §2 methodology (TUF endless-data / decompression-bomb). Verified safe: the
orchestrator + run-matrix key only on the **category** `chaos_resource_exhaustion` (+
the binary), never the sub-stage names, so nothing breaks. The ingest-DoS class is the
more security-relevant attack surface; disk-full-mid-write overlaps W5-B's torn-state
coverage. **Follow-up (tracked, not silently dropped):** the host-resource exhaustion
class (fd-limit / inotify-watch / read-only-fs robustness) is now uncovered and should
be a separate test or added stages.

## 6. Definition of done (Wave 5 chaos)
- Each of the 3 binaries injects its declared faults for real and asserts the
  security property fail-closed; none calls the inert `run_category` live path.
- `--dry-run` still scaffold-validates; pure evaluators unit-tested; gates green.
- Committed as Iwan-Teague, pushed. **Live runs against the Linux lab remain the human
  step** (these are live fault-injection tests; the sandbox compiles + unit-tests them
  but cannot run the injection).
