OPTIONAL — only use this if you're running 4 agents instead of 3. It has the
highest collision risk with Job 3 (same daemon-audit-module pattern, same
wiring files). Read `documents/operations/active/ParallelAgentWorkPlan_2026-07-01.md`
§2 for the tradeoff before deciding to run this alongside Job 3.

Paste this as the first message in a fresh Claude Code session, started from
`/Users/iwan/Desktop/Rustynet` (or any checkout of the Rustynet repo).

---

Read `AGENTS.md`/`CLAUDE.md` first (repo-wide operating contract — Rust-first,
security-first, mandatory gates in §7, Definition of Done in §9), then read
`documents/operations/active/ParallelAgentWorkPlan_2026-07-01.md` in full for
context on why you're a parallel job and the collision-avoidance rules you
must follow.

Set up your isolated workspace first — **branch from `origin/main`, not the
bare `main` ref**: the local `main` branch is checked out in a separate
worktree and is stale (20 commits behind `origin/main` as of 2026-07-01);
branching from it would silently drop GM-1, RT-2, the Tier-0 stages, and the
daemon-security-validator wiring.
```
git -C /Users/iwan/Desktop/Rustynet fetch origin main --quiet
git -C /Users/iwan/Desktop/Rustynet worktree add \
  /Users/iwan/Desktop/Rustynet/.claude/worktrees/security-platform-ports \
  -b claude/security-platform-ports origin/main
cd /Users/iwan/Desktop/Rustynet/.claude/worktrees/security-platform-ports
```
Do all your work in this worktree. Do not touch
`/Users/iwan/Desktop/Rustynet` itself — another process may be actively
editing files there. Commit in small logical increments as you go (imperative
mood, what *and* why — `CLAUDE.md` §10.10), and run scoped gates continuously
rather than only at the very end (§5).

## Your job: port already-proven Linux security checks to macOS/Windows

Source of truth: `documents/operations/active/LiveLabSecurityTestCoverage_2026-06-22.md`
Tier 1 table, items 9-14, plus §2.4 for full specs.

**Do this one first — it's the most urgent item in the whole backlog:**

1. **RSA-0063** (`validate_macos_bootstrap_privesc_residue`) — one of only 2
   standing **High**-severity findings in the entire 74-finding audit ledger
   (`SecurityAuditLedger_2026-06-18.md`), confirmed-present, zero coverage.
   The macOS bootstrap script leaves a `NOPASSWD: ALL` sudoers file behind
   after a failed Homebrew install — a real local-privesc path. Find the
   bootstrap script (search for Homebrew install + sudoers in
   `scripts/e2e/` or wherever the macOS bootstrap lives), fix the residue
   (the sudoers grant must not survive a failed install), and build the
   live stage that proves it: attempt a bootstrap that fails partway through
   Homebrew install, then assert no `NOPASSWD` sudoers file remains.

**Then, in priority order, as many of these as you have time for:**

2. **S3-10** — `validate_macos_codesign` + a Windows Authenticode
   deploy-time equivalent. Today's binary-signature checks are CI-gate-only;
   build the live version that catches a tampered/unsigned binary landing on
   a node.
3. **KC-04** — Windows key-custody negative path. `validate_key_custody_permissions`
   no-ops on non-Unix (RSA-0002) — a world-readable private key silently
   passes on Windows today. Fix the check to actually assert Windows ACLs,
   then build the live negative-path proof.
4. **PH-7** — `validate_macos_privileged_helper_allowlist`. Port the exact
   Linux adversarial argv corpus (already live-proven —
   `privileged_helper_allowlist_audit.rs`) to macOS's `pfctl` privileged
   boundary.
5. **KL-2/KL-3/KL-4** — macOS/Windows killswitch-leak parity. Linux has full
   v4+v6 active-probe + capture coverage (`validate_linux_ipv6_leak` and its
   IPv4 sibling); the other two OSes don't. Port the pattern.
6. **KC-07** — macOS/Windows secrets-not-in-logs parity. Linux-only today.
   **While you're in this area, also check RSA-0080**: the macOS bootstrap
   script currently `rm -f`'s the WireGuard passphrase with no secure-erase.
   The ledger reported the Linux secrets-hygiene gate
   (`scripts/ci/secrets_hygiene_gates.sh`) RED because of this as of
   2026-06-21 — verify current status first (don't assume either way; a
   scoped run during this doc's 2026-07-01 review passed cleanly but may not
   exercise this specific check). If it's still broken, fix the secure-erase
   and confirm the gate goes green; if it's already fixed, just note that in
   your report instead of redoing it.

**Wiring (append-only, mirror this session's pattern exactly):** new stage
registrations in `crates/rustynet-cli/src/vm_lab/mod.rs`
(`run_macos_orchestration_stages` / `run_windows_orchestration_stages_with_options`),
plus `crates/rustynet-cli/src/live_lab_run_matrix.rs`,
`crates/rustynet-lab-monitor/src/data/run_matrix.rs` (`MACOS_ONEOFF_COLUMNS`/
`WINDOWS_ONEOFF_COLUMNS`), `crates/rustynet-mcp/src/bin/lab_state.rs`
(`STAGE_INFO`), `crates/rustynet-mcp/src/bin/repo_context.rs`. **This is the
job most likely to collide with Job 3 at the tail end of these same files —
append at the very end, never reorder existing entries, and expect to
rebase onto whichever of you lands second.**

**Explicitly excluded / already done — do not touch or duplicate:**
- `ENR-1`/`TOCTOU-1`, GM-1, RT-2, Tier-0, and the 9 Linux daemon-security-
  validator stages — see the plan doc for the full already-done list.
- The equivalent Linux versions of every check above are already built and
  live-proven — read them as your reference pattern, don't re-derive from
  scratch.

**Before finishing:** run the full gate list (`cargo fmt --all -- --check`,
`cargo check --workspace --all-targets --all-features`,
`cargo test --workspace --all-targets --all-features`; clippy may show
pre-existing lints from the local toolchain-version skew on lines you didn't
touch — verify with `git diff --stat` before treating it as a blocker),
confirm `scripts/ci/secrets_hygiene_gates.sh` is green if you touched RSA-0080,
then run the new stages live and confirm the rows land in
`documents/operations/live_lab_run_matrix.csv`.

**Landing:** do NOT push to `main` or `claude/cross-platform-parity-hardening`
directly. When done and gated:
```
git push origin claude/security-platform-ports
```
and report the branch name + which items you completed with live-run
evidence for each. The user will fast-forward it into
`claude/cross-platform-parity-hardening` themselves.
