Paste this as the first message in a fresh Claude Code session, started from
`/Users/iwan/Desktop/Rustynet` (or any checkout of the Rustynet repo).

---

Read `AGENTS.md`/`CLAUDE.md` first (repo-wide operating contract — Rust-first,
security-first, mandatory gates in §7, Definition of Done in §9), then read
`documents/operations/active/ParallelAgentWorkPlan_2026-07-01.md` in full for
context on why you're one of 3 parallel jobs and the collision-avoidance rules
you must follow.

Set up your isolated workspace first — **branch from `origin/main`, not the
bare `main` ref**: the local `main` branch is checked out in a separate
worktree and is stale (20 commits behind `origin/main` as of 2026-07-01);
branching from it would silently drop GM-1, RT-2, the Tier-0 stages, and the
daemon-security-validator wiring.
```
git -C /Users/iwan/Desktop/Rustynet fetch origin main --quiet
git -C /Users/iwan/Desktop/Rustynet worktree add \
  /Users/iwan/Desktop/Rustynet/.claude/worktrees/hp3-relay-forwarding \
  -b claude/hp3-relay-forwarding origin/main
cd /Users/iwan/Desktop/Rustynet/.claude/worktrees/hp3-relay-forwarding
```
Do all your work in this worktree. Do not touch
`/Users/iwan/Desktop/Rustynet` itself — another process may be actively
editing files there (as of 2026-07-01 it's building `DOS-1`/`hello_limiter_audit.rs`
in `crates/rustynet-relay/`, uncommitted — a different file within the same
crate you're working in; your worktree won't see that uncommitted state, but
expect a merge interaction once it lands too). Commit in small logical
increments as you go (imperative mood, what *and* why — `CLAUDE.md` §10.10),
and run scoped gates continuously (`cargo check -p rustynet-relay`, targeted
`cargo test`) rather than only at the very end (§5).

## Your job: HP-3 — prove the relay actually forwards packets

This is flagged in three separate ledgers as the single biggest "looks done
but isn't" gap in the whole codebase:
- `documents/operations/active/MasterWorkPlan_2026-03-22.md` — item HP-3,
  "Production Relay Transport Service... the most substantial remaining code
  item... relay path is just a routing label, no actual packets are relayed."
- `documents/operations/active/CrossPlatformRoleParityRoadmap_2026-06-22.md`
  §4 "RELAY (both OS) — GATED on HP-3."
- `documents/operations/active/LiveLabSecurityTestCoverage_2026-06-22.md`
  Tier 1 priority #8 (RPT-01), with a correction note right below the table
  explaining exactly what's proven today vs. not.

**What exists today (read these before writing anything):**
- `crates/rustynet-cli/src/vm_lab/orchestrator/role_validation/relay.rs`
  (~1190 lines) — proves the `rustynet-relay` service starts, binds its
  datapath (`:4500`) and health (`:4501`) ports, `/healthz` answers `ok`, and
  all of that tears down cleanly on stop/restart. **It never drives a peer's
  traffic through the relay.**
- `crates/rustynet-relay/src/{transport,session,rate_limit}.rs` — the actual
  forwarding code. Read these to understand what's implemented vs. what
  still needs building for a live two-peer-through-relay path.
- `crates/rustynet-cli/src/bin/live_linux_two_hop_test.rs` — a *different*
  subsystem (exit-role chaining: `client → entry(also serving exit) →
  final_exit → internet`), not the dedicated relay service. Don't confuse
  the two; the roadmap explicitly warns about this.

**What "done" looks like — build a new live orchestrator stage
(`validate_linux_relay_forwards_frame`, or name it to match convention) that:**
1. Sets up two peers where one has **no direct/traversal path** to the other
   — the only route is through a `rustynet-relay` node.
2. Sends real traffic between them (ping or a small payload is fine — this
   doesn't need to be a throughput benchmark).
3. Asserts, from the relay's own observable state (metrics, logs, or a
   counter you add), that frames were actually forwarded (bytes moved) — not
   just that the service is "active."
4. Asserts the relay cannot read the plaintext payload (RPT-01,
   ciphertext-only property) — this is the adversarial half, not just the
   functional half.
5. Registers cleanly through the FAIL-LOUD contract: the live result is the
   only thing that produces Pass/Fail; there is no dry-run-as-pass path.
   Read `CrossPlatformRoleParityRoadmap_2026-06-22.md` §7 for the exact spec
   every parity/security stage must follow.

**Non-negotiable security guardrail — read this twice.** The single most
important property here is that the relay stays a dumb, honest forwarder.
**Do not add any decrypt / plaintext-inspection capability to the relay, not
even behind a test-only flag, not even to make step 4's assertion "easier to
prove."** Prove ciphertext-only from the *outside*: the sender/receiver (who
hold the keys) can assert what they sent/received; the relay may only expose
forwarding evidence that doesn't require reading payload content — byte
counts, frame counts, a counter you add that increments without touching the
`transport.rs`/`session.rs` payload path. If you find yourself wanting the
relay to decrypt something to make the test pass, that's a sign the test is
wrong, not that the relay needs a new capability — this exact category of
mistake (adding an inspection backdoor "just for testing") is precisely what
`CLAUDE.md` §3's "no runtime fallback, downgrade, or legacy branch in
production paths" and the whole point of RPT-01 exist to prevent. This also
means: no `unwrap()`/`expect()` in whatever new relay code you add (§10.2),
and the new counter/observability hook is itself a security-relevant piece
of code — it needs the same "1 enforcement point + 1 verification test"
treatment as anything else (§4), not a quick unreviewed instrumentation hack.

**Wiring (mirror this session's pattern exactly, don't invent a new one):**
new stage registration in `crates/rustynet-cli/src/vm_lab/mod.rs`, plus the
CSV/GUI/MCP surfaces: `crates/rustynet-cli/src/live_lab_run_matrix.rs`
(`DEFAULT_MATRIX_COLUMNS` + `set_special_stage_values`, with a unit test),
`crates/rustynet-lab-monitor/src/data/run_matrix.rs` (`LINUX_ONEOFF_COLUMNS`,
bump the two hardcoded matrix-total test assertions), `crates/rustynet-mcp/src/bin/lab_state.rs`
(`STAGE_INFO` array + a covering test), `crates/rustynet-mcp/src/bin/repo_context.rs`
(the orchestrator-stages markdown table). **Append only** — add your entries
at the end of each array/match statement, never reorder or reformat existing
entries; two other agents are doing the same append pattern in parallel and
this keeps the eventual merge trivial.

**Get it live-green on Linux first.** Per the roadmap: once a real Linux
two-peer forwarding stage is green, Windows/macOS relay-forwarding parity
"becomes a port" — that's out of scope for you, just get the Linux proof
solid and correct.

**Explicitly excluded / already done — do not touch or duplicate:**
- `ENR-1`/`TOCTOU-1` (`validate_linux_enrollment_replay`,
  `validate_linux_enrollment_concurrent_consume`) — another process may still
  be landing this; grep for it on `main` before you start and leave it alone
  either way.
- `DOS-1` (`validate_linux_relay_hello_node_id_flood`, `crates/rustynet-relay/src/hello_limiter_audit.rs`) —
  also confirmed in-flight elsewhere (same crate you're working in, different
  file/feature: the relay's `HelloLimiter` flood protection in `transport.rs`,
  not the forwarding path you're building). Not your job even if it looks
  related — HP-3 is about session forwarding, DOS-1 is about connection-rate
  limiting.
- GM-1, RT-2, Tier-0 (RSA-0009/DD-03), and the 9 daemon-security-validator
  observability stages are already on `main` (commit `3432a79` or later) —
  don't re-implement.
- Relay *lifecycle* (start/stop/`/healthz`) is already live-proven on
  Linux+macOS — you're proving *forwarding*, not lifecycle. Don't touch
  `role_validation/relay.rs`'s existing lifecycle assertions except to add
  what you need alongside them.

**Before finishing:**
- Run the full gate list (`cargo fmt --all -- --check`,
  `cargo check --workspace --all-targets --all-features`,
  `cargo test --workspace --all-targets --all-features`; clippy may show
  pre-existing lints from the local toolchain-version skew on lines you didn't
  touch — verify with `git diff --stat` before treating it as a blocker).
- No TODO/FIXME/placeholder in what you deliver — a stage that's registered
  but not actually gated on the live result, or a "forwarding proof" that
  only checks the service is running, is not done (`CLAUDE.md` §3/§9).
- Run the new stage live and confirm the row lands in
  `documents/operations/live_lab_run_matrix.csv`.
- Update the ledgers: flip HP-3 in `MasterWorkPlan_2026-03-22.md`, the
  relay-forwarding-gated notes in `CrossPlatformRoleParityRoadmap_2026-06-22.md`
  §4, and RPT-01/Tier-1-item-#8 in `LiveLabSecurityTestCoverage_2026-06-22.md`
  §2.4 from open to done-with-evidence. Don't leave a ledger describing a gap
  your own commit just closed (`CLAUDE.md` §5/§6).

**Landing:** do NOT push to `main` or `claude/cross-platform-parity-hardening`
directly. When done and gated:
```
git push origin claude/hp3-relay-forwarding
```
and report the branch name + a summary of what you built and the live-run
evidence. The user will fast-forward it into
`claude/cross-platform-parity-hardening` themselves.
