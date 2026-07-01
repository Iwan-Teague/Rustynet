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
  /Users/iwan/Desktop/Rustynet/.claude/worktrees/role-transitions-anchor \
  -b claude/parity-role-transitions-and-anchor origin/main
cd /Users/iwan/Desktop/Rustynet/.claude/worktrees/role-transitions-anchor
```
Do all your work in this worktree. Do not touch
`/Users/iwan/Desktop/Rustynet` itself — another process may be actively
editing files there. Commit in small logical increments as you go (imperative
mood, what *and* why — `CLAUDE.md` §10.10), and run scoped gates continuously
(`cargo check -p rustynetd`, `cargo check -p rustynet-cli`, targeted `cargo
test`) rather than only at the very end (§5).

## Your job: two parity cells that are now unblocked

Source of truth:
`documents/operations/active/CrossPlatformRoleParityPlan_2026-06-21.md` (§1
mandate, §3 status matrix) and
`documents/operations/active/CrossPlatformRoleParityRoadmap_2026-06-22.md`
(§2 remaining-work table, §3 the four-layer seam every role follows, §4
dependency analysis, §7 the FAIL-LOUD spec). Read both before writing code —
the roadmap in particular explains exactly which files each layer lives in
and calls out two concrete anti-patterns you must not repeat.

**Why these two, why now:** admin (mint/issue signed bundles) is now
live-proven on both macOS and Windows (2026-06-22/27) — that was the
dependency blocking both cells below. Read roadmap §4 "ADMIN (both OS)" for
why the old "self-mint deliberately disabled" note was stale and never
actually backed by code.

### Part A — Cross-OS live role transitions (macOS + Windows)
Today `role_switch_matrix` only proves tunnels stay active across a role
change — it never drives a *real* flip. Design already exists:
`documents/operations/active/CrossOsRoleSwitchPlan_2026-06-24.md` — read it
in full, it's not a stub. Reuse the single verified apply path:
- `crates/rustynetd/src/daemon.rs` — `refresh_signed_state_with_reason`
  (re-fetch trust → traversal → assignment → dns_zone, fail-closed on every
  error). This is the *only* path to use; do not add a second/weaker apply
  branch. (Was cited as line 4487-4526 in the design doc from 2026-06-24;
  it's drifted to ~4588 as of `main` `3432a79` and will keep drifting as
  other jobs land commits — grep for the function name, don't trust a
  hardcoded line number.)
- `crates/rustynetd/src/ipc.rs` (`StateRefresh` enum variant + its CLI-parse
  arm) + `daemon.rs`'s `IpcCommand::StateRefresh =>` dispatch arm — the
  `StateRefresh` IPC trigger. Same caveat: grep for `StateRefresh`, don't
  trust a hardcoded line number.
- Per-OS role-flip mechanics: macOS launchd plist rewrite +
  `launchctl bootout`/`bootstrap` (same pattern already proven for the
  macOS exit-activation stage — `launchctl kickstart -k` does NOT re-read an
  edited plist, you must bootout+bootstrap); Windows `windows_service`
  StateRefresh (see `crates/rustynetd/src/windows_service.rs`).
Build the live stage that drives a real role flip on a macOS node and a
Windows node, asserting the new role's dataplane actually comes up (not just
"tunnel survived").

**Non-negotiable ordering rules — `CLAUDE.md` §10.7 and §10.5, both apply
directly to this job, don't treat them as generic boilerplate:**
- **§10.7 (role transitions are not just string changes):** if the flip
  *adds* a serving capability (e.g. `serves_relay`), deploy the service
  BEFORE emitting the signed bundle that advertises it; if it *removes* one,
  undeploy/stop the service BEFORE the revocation bundle goes out; exit-NAT
  teardown must complete BEFORE the exit capability is removed (residue is a
  release-blocker, not a cleanup nice-to-have); every transition must emit an
  append-only audit log entry. Get this ordering right for whichever role
  pair(s) your transition stage actually exercises.
- **§10.5 (signed state — verify before apply):** verify the signature
  FIRST, check epoch/replay-watermark SECOND, apply THIRD — this is exactly
  what `refresh_signed_state_with_reason` already does; your job is to drive
  it correctly, not to add a parallel apply path that skips or reorders these
  checks "to make the transition simpler."

### Part B — Windows anchor: contract validator → live bundle-serving
`validate_windows_anchor_bundle_pull_plan_contract` (grep for it in
`crates/rustynet-cli/src/vm_lab/mod.rs` — cited as line 9516 in the roadmap
doc, drifted to ~11322 as of `main` `3432a79`) runs entirely in-process
against repo files, never touching the guest. The
roadmap calls this out by name as **the exact anti-pattern to never repeat**
(§3, right after describing SSH composition rules) — sitting right next to
`validate_macos_anchor_bundle_pull`'s prior dry-run-as-pass bug, which is
already fixed and now the reference for what "live" looks like. Upgrade the
Windows one to match: elect a Windows node into the anchor role, have a real
peer pull a bundle from it over the network, assert byte-for-byte content +
token-gate enforcement + LAN-bind-refused + secrets hygiene (same four
assertions the macOS live test makes — read
`crates/rustynet-cli/src/bin/live_macos_anchor_test.rs` as your template and
port the pattern, not the platform-specific bits).

**SSH composition reminder (roadmap §3):** the inventory carries `ssh_target`
and `ssh_user` as separate fields; always compose via
`remote_target_from_inventory_entry` / `normalized_ssh_target` — never
hardcode the user. This exact mistake (hardcoded `iwan@` instead of the
guest's real user) cost a full live-run cycle on the macOS anchor cell.

**Wiring (mirror this session's pattern, append-only):** new stage
registrations in `crates/rustynet-cli/src/vm_lab/mod.rs`
(`run_macos_orchestration_stages` — cited at line 7897 in the roadmap doc,
drifted to ~8399 as of `main` `3432a79`; `run_windows_orchestration_stages_with_options` —
cited at 9851, drifted to ~12124 — grep for the function names, these will
keep moving as commits land),
plus the CSV/GUI/MCP surfaces: `crates/rustynet-cli/src/live_lab_run_matrix.rs`,
`crates/rustynet-lab-monitor/src/data/run_matrix.rs` (this time you likely
want the macOS/Windows one-off column lists, not `LINUX_ONEOFF_COLUMNS`),
`crates/rustynet-mcp/src/bin/lab_state.rs`,
`crates/rustynet-mcp/src/bin/repo_context.rs`. Add your entries at the end of
each array/match statement — two other agents are appending to these same
files in parallel; don't reorder or reformat existing entries.

**Explicitly excluded / already done — do not touch or duplicate:**
- `ENR-1`/`TOCTOU-1` (`validate_linux_enrollment_replay`,
  `validate_linux_enrollment_concurrent_consume`) — another process may
  still be landing this; grep for it on `main` before you start and leave it
  alone either way.
- GM-1, RT-2, Tier-0 (RSA-0009/DD-03), and the 9 daemon-security-validator
  observability stages are already on `main` (commit `3432a79` or later).
- admin (macOS + Windows), macOS blind_exit, macOS relay lifecycle, and
  macOS anchor bundle-pull are already live-proven — don't re-implement
  those; you're building on top of them.
- Windows exit and Windows relay-forwarding parity are **out of scope for
  you** — the former is blocked on a lab-environment gap (no WinNAT-capable
  guest, not a code gap), the latter is blocked on HP-3 (a different
  parallel job is doing that).

**Before finishing:**
- Run the full gate list (`cargo fmt --all -- --check`,
  `cargo check --workspace --all-targets --all-features`,
  `cargo test --workspace --all-targets --all-features`; clippy may show
  pre-existing lints from the local toolchain-version skew on lines you
  didn't touch — verify with `git diff --stat` before treating it as a
  blocker).
- No TODO/FIXME/placeholder, no `unwrap()`/`expect()` in the new production
  code paths (`CLAUDE.md` §10.2) — the DPAPI/keychain custody paths and the
  signed-state apply path are exactly where a panic would be a real
  denial-of-service, not just a bad look.
- Run each new stage live (one macOS, one Windows for Part A; one Windows
  for Part B) and confirm the rows land in
  `documents/operations/live_lab_run_matrix.csv`.
- Update the ledgers: flip the relevant cells in
  `CrossPlatformRoleParityPlan_2026-06-21.md` §3 (the live-proven status
  matrix) and `CrossPlatformRoleParityRoadmap_2026-06-22.md` §2/§5 (the
  remaining-work table and ranked roadmap) from ❌/🟠 to ✅ with the run ID as
  evidence, and mark `CrossOsRoleSwitchPlan_2026-06-24.md` as implemented.
  Don't leave a ledger describing a gap your own commit just closed
  (`CLAUDE.md` §5/§6).

**Landing:** do NOT push to `main` or `claude/cross-platform-parity-hardening`
directly. When done and gated:
```
git push origin claude/parity-role-transitions-and-anchor
```
and report the branch name + a summary of what you built and the live-run
evidence for both parts. The user will fast-forward it into
`claude/cross-platform-parity-hardening` themselves.
