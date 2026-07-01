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
  /Users/iwan/Desktop/Rustynet/.claude/worktrees/security-hardening-batch1 \
  -b claude/security-hardening-batch1 origin/main
cd /Users/iwan/Desktop/Rustynet/.claude/worktrees/security-hardening-batch1
```
Do all your work in this worktree. Do not touch
`/Users/iwan/Desktop/Rustynet` itself — another process may be actively
editing files there (as of 2026-07-01 it's building `DOS-1` in
`crates/rustynet-relay/` — see the exclusion list below, this was originally
in your scope and has been removed). Commit in small logical increments as
you go (imperative mood, what *and* why — `CLAUDE.md` §10.10), and run scoped
gates continuously (`cargo check -p rustynetd`, targeted `cargo test`) rather
than only at the very end (§5).

**A note on priority, since this job is numbered "3 of 3":** don't read that
as "least important." Per-item severity in `LiveLabSecurityTestCoverage_2026-06-22.md`
§2.4 (not the summary near the top) skews more severe here than in the other
two jobs — FCF-1 below is `high/large`, the single most expensive item across
all 3 jobs. If time runs short, this job's items close more standing
rated-severity gaps per unit of work than the other two.

## Your job: a batch of Tier-1 adversarial stages, one template

Source of truth: `documents/operations/active/LiveLabSecurityTestCoverage_2026-06-22.md` —
read the "Tier 1 — adversarial stages that attack a control, not just
exercise it" table near the top, and §2.4 for the full spec + bite-test of
every ID below (these are already fully designed; you're implementing, not
designing).

**Read the reference pattern before writing anything** — this session just
built this exact template for 9 other stages:
`crates/rustynetd/src/membership_revoke_audit.rs` (daemon-side audit module
shape) and `crates/rustynet-cli/src/live_lab_run_matrix.rs`'s
`set_special_stage_values` (the CSV wiring, including the
`daemon_security_validator_stages_map_to_dedicated_csv_columns` test showing
exactly how to test it). Every stage below is: a new `rustynetd` probe/audit
module → CLI subcommand → orchestrator stage in `vm_lab/mod.rs` that dispatches
it over SSH and evaluates the JSON output → CSV/GUI/MCP wiring. Don't invent
a new shape.

**Build these Tier-1 IDs (all Linux, all currently zero live coverage —
severity/effort tags are from §2.4, the authoritative source, not the
summary near the top of the ledger):**

1. **FCF-1/2/3** — `validate_linux_crash_midapply_failclosed` (`high/large`),
   `_corrupt_state_failclosed` (`high/medium`), `_keystore_unavailable_failclosed`
   (`medium/medium`). Three scenarios, one theme: `kill -9` mid-signed-state-write,
   a truncated trust state file, a locked/unavailable keystore. In all three
   the daemon must refuse to boot into an inconsistent trust state — assert
   fail-closed, not silent continuation with stale-but-valid-looking state.
   **Do FCF-1 first — it's the single most severe item across all 3 parallel
   jobs.**
2. **RR-01** — `validate_linux_replay_persistence` (`medium/medium`; +
   traversal/enrollment variants if you have time, the base case is the
   priority). The anti-replay watermark is in-memory only (RSA-0029) — prove
   a stale/consumed bundle replayed *after a daemon reboot* is still
   rejected, not just rejected in the same process lifetime. **Naming
   quirk:** the curated Tier-1 list at the top of the ledger calls this
   `RR-01`; the raw backlog table in §2.4 calls the identical stage `FCF-4`
   — cross-reference by stage *name*, not by assuming the two ID schemes
   line up.
3. **CNT-1** — `validate_linux_upnp_ssrf` (`high/large`). Confirmed-present
   SSDP LOCATION/controlURL SSRF (RSA-0035) — find the UPnP/port-mapper code
   (`crates/rustynetd/src/port_mapper.rs` is your starting point) and prove
   the adversarial SSDP response corpus is rejected.
4. **PH-2/PH-3** — `validate_linux_privileged_helper_socket_fuzz` /
   `_peer_authz` (both `high/medium`). Today's helper coverage
   (`privileged_helper_allowlist_audit.rs`, already live on Linux) is
   argv-only — nothing attacks the live socket itself. Build a
   fuzz/adversarial-input pass against the actual running IPC socket, plus a
   cross-UID rejection test (a process running as a different UID must not
   be able to invoke the privileged helper). PH-4 (`_socket_perms`) and PH-5
   (`_binary_integrity`) are the same theme, also `high/medium`, and a
   natural extension if you have time — not required.

**~~DOS-1~~ (`validate_linux_relay_hello_node_id_flood`) was in this job's
original scope and has been removed** — confirmed in-flight elsewhere as of
2026-07-01 (`crates/rustynet-relay/src/hello_limiter_audit.rs`, looks
functionally complete). Grep for it before you start; if it's landed on
`origin/main`, it's done and not yours to redo — if it's still uncommitted
elsewhere, still don't build it, someone else owns it. (For the record: the
real `HelloLimiter` type lives in `crates/rustynet-relay/src/transport.rs`,
not `rate_limit.rs` — worth knowing if you ever do end up needing it.)

**If a stage exposes that the daemon does NOT actually fail closed in one of
these scenarios, that's a real bug — fix it first (`CLAUDE.md` §3, "fail
closed when trust/security state is missing, invalid, stale, or unavailable"
is non-negotiable), then build the stage proving the fix.** Don't assume the
happy path already holds and write a validator that would rubber-stamp
broken behavior — this is exactly the same "find bug → fix → prove live"
shape as this session's GM-1/RT-2/RSA-0009/DD-03 work, not "add a test for
existing correct behavior." For CNT-1 and PH-2/PH-3 in particular, apply
`CLAUDE.md` §10.4's default-deny discipline: the first case you write should
be "malformed/adversarial input → deny", not "does the happy path still
work" — a corpus that only exercises the happy path can pass vacuously.

If you finish all of the above with time to spare, pull the next items off
the Tier-1 list in `LiveLabSecurityTestCoverage_2026-06-22.md` in priority
order (S3-10, RSA-0063, KC-04 are macOS/Windows and belong to the optional
4th job — skip those; KL-2/3/4 and KC-07 likewise. Stay Linux-focused, stay
in the Tier-1 list, and check the plan doc's "Job 4" section before picking
up anything platform-specific in case that job is also running.)

**Wiring (append-only, mirror this session's pattern exactly):** new stage
registrations in `crates/rustynet-cli/src/vm_lab/mod.rs` (after the existing
daemon-security-validator chain — don't interleave with it), plus:
`crates/rustynet-cli/src/live_lab_run_matrix.rs` (`DEFAULT_MATRIX_COLUMNS` +
new `set_special_stage_values` match arms, with a unit test per stage or one
covering all of them — mirror `daemon_security_validator_stages_map_to_dedicated_csv_columns`),
`crates/rustynet-lab-monitor/src/data/run_matrix.rs` (`LINUX_ONEOFF_COLUMNS`,
bump the two hardcoded matrix-total test assertions accordingly),
`crates/rustynet-mcp/src/bin/lab_state.rs` (`STAGE_INFO` array + a covering
test proving `explain_stage` resolves each one), `crates/rustynet-mcp/src/bin/repo_context.rs`
(the "Daemon Security-Validator Stages (Linux)" table). Two other agents are
appending to these same 4-5 files in parallel — add your entries at the very
end of each array/match statement, never reorder or reformat existing
entries, so the eventual 3-way merge stays trivial.

**Explicitly excluded / already done — do not touch or duplicate:**
- `ENR-1`/`TOCTOU-1` (`validate_linux_enrollment_replay`,
  `validate_linux_enrollment_concurrent_consume`) — another process may
  still be landing this; grep for it on `main` before you start and leave it
  alone either way.
- `DOS-1` (`validate_linux_relay_hello_node_id_flood`) — see above, removed
  from your scope, confirmed in-flight elsewhere.
- GM-1, RT-2, Tier-0 (RSA-0009/DD-03), and the 9 daemon-security-validator
  observability stages (runtime_acls, key_custody, service_hardening,
  authenticode, privileged_helper_allowlist, membership_signature_forgery,
  policy_default_deny, membership_genesis, mesh_status) are already on
  `main` (commit `3432a79` or later) — don't re-implement, but do treat them
  as your template.
- Note the known gap from this session: none of the existing 11 daemon-
  security-validator stages (2 Tier-0 + 9 observability) are wired into
  `direct_platform_stage()` in `live_lab_run_matrix.rs`, so their CSV
  columns don't actually populate from a live run yet. You are not required
  to fix that for the existing 11, but make sure YOUR new stages don't
  silently inherit the same gap if you can close it cheaply while you're in
  that file — check with the user first if it looks like a bigger change
  than a one-line addition per stage.

**Before finishing:**
- Run the full gate list (`cargo fmt --all -- --check`,
  `cargo check --workspace --all-targets --all-features`,
  `cargo test --workspace --all-targets --all-features`; clippy may show
  pre-existing lints from the local toolchain-version skew on lines you
  didn't touch — verify with `git diff --stat` before treating it as a
  blocker).
- No TODO/FIXME/placeholder, no `unwrap()`/`expect()` in the new
  probe/audit code (`CLAUDE.md` §10.2) — a panic in a fail-closed check is
  itself a fail-open bug (the daemon crashing mid-check is not the same as
  the daemon deliberately refusing to boot). Each new control needs both an
  enforcement point in code and a verification test (§4) — if you find a
  real gap, the fix belongs in the daemon/relay code, the stage is the
  verification, not a substitute for the fix.
- Run the new stages live and confirm the rows land in
  `documents/operations/live_lab_run_matrix.csv`.
- Update `LiveLabSecurityTestCoverage_2026-06-22.md` — flip each completed
  ID (in both the curated Tier-1 table near the top AND its corresponding
  row in the §2.4 backlog-by-surface table, remembering they may use
  different ID labels for the same stage per the RR-01/FCF-4 naming quirk
  above) from open to done-with-evidence. Don't leave a ledger describing a
  gap your own commit just closed (`CLAUDE.md` §5/§6).

**Landing:** do NOT push to `main` or `claude/cross-platform-parity-hardening`
directly. When done and gated:
```
git push origin claude/security-hardening-batch1
```
and report the branch name + which stages you completed with live-run
evidence for each. The user will fast-forward it into
`claude/cross-platform-parity-hardening` themselves.
