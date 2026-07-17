# Parallel Agent Work Plan — 2026-07-01

Status: **active**. Purpose: partition the current backlog into independent,
big-enough jobs so 3 agents can work concurrently on `claude/cross-platform-parity-hardening`
(equivalently, current `main`, commit `3432a79` at time of writing) without
stepping on each other or on in-flight work. This doc is the source of truth
for that partition; the ready-to-paste prompts are in `documents/operations/active/ParallelAgentPrompts_2026-07-01/`.

## 0) Baseline

**Branch from `origin/main`, never the local `main` branch ref.** `main` is
checked out in a separate worktree (`.claude/worktrees/lab-main`) and is
**stale** — as of this writing, local `main` sits at `d3750b7` while
`origin/main` is 20 commits ahead at `3432a79` (that push updated the remote
ref directly; nothing fast-forwards the local `main` branch until someone
runs it from the worktree that has it checked out). If you `git worktree add
-b <branch> main`, you silently start 20 commits behind — missing GM-1, RT-2,
the Tier-0 stages, and the daemon-security-validator wiring. Always:
```
git -C /Users/iwan/Desktop/Rustynet fetch origin main --quiet
git -C /Users/iwan/Desktop/Rustynet worktree add <path> -b <branch> origin/main
```
Re-check `git rev-parse origin/main` right before starting — if it has moved
past `3432a79`, that's fine, branch from whatever it now is.

## 1) Known in-flight work — do NOT duplicate

As of this writing, `/Users/iwan/Desktop/Rustynet` (the primary, non-worktree
checkout) has **uncommitted, live-in-progress** work building at least two
things simultaneously (grep for these before starting; if either has since
landed on `origin/main`, skip it — if not, still don't build it, someone
else owns it):
- `ENR-1` (`validate_linux_enrollment_replay`) and `TOCTOU-1`
  (`validate_linux_enrollment_concurrent_consume`) —
  `crates/rustynetd/src/enrollment_replay_audit.rs` + wiring in `vm_lab/mod.rs`,
  `lib.rs`, `main.rs`, `Cargo.toml`.
- **`DOS-1`** (`validate_linux_relay_hello_node_id_flood` / RSA-0037) —
  `crates/rustynet-relay/src/hello_limiter_audit.rs` (189 lines, looks
  functionally complete: flood + baseline cases, a `run_hello_limiter_flood_audit`
  entry point) + a new `hello-limiter-audit` CLI subcommand wired into
  `crates/rustynet-relay/src/main.rs` and `lib.rs`, plus changes to
  `transport.rs` (where the real `HelloLimiter` type lives — **not**
  `rate_limit.rs`, despite that being the more obvious-sounding home) and
  `crates/rustynet-cli/Cargo.toml`/`vm_lab/mod.rs`. This was discovered
  mid-session (2026-07-01) after this plan's first draft, which had DOS-1 in
  Job 3's scope — **it has been removed from Job 3 below; do not re-add it.**

Also already **DONE and on `main`**: Tier-0 (RSA-0009, DD-03), GM-1, RT-2, and
the daemon-security-validator observability wiring (9 stages: runtime_acls,
key_custody, service_hardening, authenticode, privileged_helper_allowlist,
membership_signature_forgery, policy_default_deny, membership_genesis,
mesh_status). Don't re-do these.

## 2) Why 3 agents, not 2 or 4

The backlog has more than 4 "big jobs" worth of work (see
`LiveLabSecurityTestCoverage_2026-06-22.md` §2.4's 111-gap backlog and
`CrossPlatformRoleParityRoadmap_2026-06-22.md` §2/§5), so headroom isn't the
constraint. The constraint is **shared-file collision**: every new live-lab
stage — regardless of which job it belongs to — needs a registration point in
the same five hotspot files (`crates/rustynet-cli/src/vm_lab/mod.rs`,
`crates/rustynet-cli/src/live_lab_run_matrix.rs`,
`crates/rustynet-lab-monitor/src/data/run_matrix.rs`,
`crates/rustynet-mcp/src/bin/lab_state.rs`,
`crates/rustynet-mcp/src/bin/repo_context.rs`). This is a known, documented
architectural gap (`LiveLabSecurityTestCoverage_2026-06-22.md` §9: "there is no
single canonical stage registry"), not something these jobs should try to fix
as a side effect. 2 jobs is fewer than the real backlog supports; 4 jobs
means 4-way contention on those 5 files at merge time for comparatively
thinner per-job scope. 3 is the balance: each job below is genuinely
substantial (multiple days), thematically coherent, and mostly touches
distinct *implementation* files even though all 3 touch the same *wiring*
files at the tail end.

A natural 4th job exists (macOS/Windows security-validator ports — S3-10,
RSA-0063, KC-04, PH-7, KL-2/3/4, KC-07) and is listed as a bonus at the end
if you want to run 4 anyway.

## 3) Git mechanics

Each agent works in its own git worktree on its own branch, both created
fresh at the start of its prompt (not pre-created by this doc, so branches
never go stale waiting for a human to press go):

```
git -C /Users/iwan/Desktop/Rustynet fetch origin main --quiet
git -C /Users/iwan/Desktop/Rustynet worktree add \
  /Users/iwan/Desktop/Rustynet/.claude/worktrees/<worktree-name> \
  -b claude/<branch-name> origin/main
```

**Branch from `origin/main`, not the bare `main` ref** — see §0, the local
`main` branch is stale and worktree-locked elsewhere. Each job's prompt
specifies its own `<worktree-name>` / `<branch-name>`.

Commit in small logical increments inside your worktree as you go (imperative
mood, what *and* why — `CLAUDE.md` §10.10), not one giant commit at the end.
Run scoped gates continuously during implementation (`cargo check -p <crate>`,
targeted `cargo test -p <crate>`) — `CLAUDE.md` §5 requires gates *during*
implementation, not only at the end — then the full mandatory gate list (§7)
before you finish.

**Do not push directly to `main` or to `claude/cross-platform-parity-hardening`.**
Push your own branch (`git push origin claude/<branch-name>`) and report the
branch name back — the user fast-forwards each one into
`claude/cross-platform-parity-hardening` (then `main`) sequentially, resolving
the tail-end wiring-file conflicts one at a time. This keeps the no-PR /
direct-fast-forward workflow intact while avoiding 3 processes racing to
write the same ref.

**Collision discipline inside the wiring files:** append only. New CSV
columns go at the end of `DEFAULT_MATRIX_COLUMNS` / `LINUX_ONEOFF_COLUMNS` (or
the macOS/Windows equivalents); new `StageInfo` entries go at the end of the
`STAGE_INFO` array; new stage registrations in `vm_lab/mod.rs` go after the
existing daemon-security-validator chain, not interleaved with it. Never
reorder or reformat existing entries in these files — that turns a 3-way
append-only merge into a real conflict. Job 1 also touches
`crates/rustynet-relay/src/transport.rs` — the in-flight DOS-1 work (§1) is
touching the same file right now, uncommitted; since worktrees only see
*committed* state, this isn't a live editing collision for Job 1, but expect
a real merge interaction once DOS-1 lands too.

## 3.1) Security is not "job 3 of 3" — read this before assigning by number

Per-item severity in `LiveLabSecurityTestCoverage_2026-06-22.md` §2.4 (the
authoritative severity source, not this summary): **Job 3's items skew more
severe than Jobs 1/2's**. FCF-1 (crash-midapply) is `high/large` — the single
most expensive item in this entire plan; FCF-2 (corrupt-state), PH-2 (helper
socket fuzz), and PH-3 (cross-UID rejection) are all `high/medium`; CNT-1
(UPnP SSRF) is `high/large`. Only FCF-3 (keystore-unavailable) and the
replay-persistence item are `medium/medium`. Job 4's RSA-0063 is one of only
2 standing **High**-severity findings in the entire 74-finding audit ledger.
Job 1 (HP-3) is high-*impact* (biggest coverage gap) but its own severity
framing is architectural/functional, not a rated CWE-backed finding the way
Job 3's items are. **If only one job can start today, or the whole run has
to be cut short, Job 3 closes more standing rated-severity gaps per unit of
work than Job 1 or Job 2 — do not treat its "#3" position in this doc as a
priority ranking.**

## 4) The three jobs

### Job 1 — HP-3: real relay packet-forwarding proof
**Why it matters:** flagged independently in three ledgers
(`MasterWorkPlan_2026-03-22.md` HP-3, `CrossPlatformRoleParityRoadmap_2026-06-22.md`
§4, `LiveLabSecurityTestCoverage_2026-06-22.md` Tier 1 #8/RPT-01) as *the*
single biggest "looks done but isn't" gap. No stage on any OS has ever driven
a real peer's session through the `rustynet-relay` service and proven a frame
was forwarded — existing "relay" coverage is lifecycle-only (service starts,
`/healthz` answers, stops cleanly). This blocks Windows relay parity and
macOS/Windows relay-forwarding parity outright.
**Scope:** build a live orchestrator stage that forces two peers to
communicate *only* via the relay (one has no direct/traversal path), sends
real traffic, and asserts on the relay side that frames were forwarded (byte
counts move) while asserting the relay cannot read plaintext (RPT-01,
ciphertext-only). Implementation surface: `crates/rustynet-relay/src/{transport,session,rate_limit}.rs`,
the existing lifecycle validator at
`crates/rustynet-cli/src/vm_lab/orchestrator/role_validation/relay.rs`, plus a
new `validate_linux_relay_forwards_frame` stage wired into `vm_lab/mod.rs` and
the CSV/GUI/MCP surfaces (same pattern as this session's daemon-security-validator
wiring — mirror it exactly). Get it live-green on Linux first; the doc says
once that's true, Windows/macOS relay-forwarding parity becomes "a port."
**Size:** the largest single job — expect multi-day.

### Job 2 — Cross-OS role transitions + Windows anchor live bundle-serving
**Why it matters:** the release-blocking mandate
(`CrossPlatformRoleParityPlan_2026-06-21.md` §1) requires every role live-proven
on macOS AND Windows. Admin is now unblocked on both (live-proven 2026-06-22/27),
which was the dependency blocking this work.
**Scope, two parts:**
1. **Role transitions (macOS + Windows).** Design already exists in
   `CrossOsRoleSwitchPlan_2026-06-24.md` — read it first. Build the stage that
   drives a real role flip (not just "tunnel stays up", which is all
   `role_switch_matrix` proves today) reusing the single verified apply path
   `refresh_signed_state_with_reason` in `crates/rustynetd/src/daemon.rs`
   and the `StateRefresh` IPC trigger in `ipc.rs`/`daemon.rs` (line numbers
   cited in the design doc as 4487-4526 / 44,201 / 7156 have drifted — grep
   for the function/enum names against current `main`, don't trust hardcoded
   line numbers, they'll keep moving as these jobs land commits).
2. **Windows anchor: contract → live.** `validate_windows_anchor_bundle_pull_plan_contract`
   (grep in `vm_lab/mod.rs` — cited at 9516, drifted to ~11322) runs in-process against repo files without touching
   the guest — the exact anti-pattern the roadmap calls out (§3, "anti-pattern
   to never repeat"). Upgrade it to a live bundle-serving stage matching the
   macOS anchor pattern already live-proven (`validate_macos_anchor_bundle_pull`).
**Read first:** `CrossPlatformRoleParityRoadmap_2026-06-22.md` §3 (the 4-layer
seam every role follows — role-transition planner in `role_cli.rs`, per-OS
service installer, dataplane adapter, live-lab stage) and §7 (the FAIL-LOUD
spec every parity stage must follow — live result is authoritative, dry-run
is never a Pass).
**Size:** substantial, ~2-4 days per the roadmap's own estimate for the
transitions half alone, plus the anchor upgrade.

### Job 3 — Security hardening: state-durability + fail-closed + DoS/injection batch
**Why it matters:** these are Tier-1 adversarial stages from
`LiveLabSecurityTestCoverage_2026-06-22.md` — real attacks on controls, not
just exercises of them. All follow the exact template this session just used
for the 9 daemon-security-validator stages (rustynetd probe/audit module →
`vm_lab/mod.rs` stage registration → CSV/GUI/MCP wiring) — read
`crates/rustynetd/src/membership_revoke_audit.rs` and
`crates/rustynet-cli/src/live_lab_run_matrix.rs`'s `set_special_stage_values`
as the reference pattern before starting.
**Scope — pick up these Tier-1 IDs (all Linux, all currently zero-coverage;
severity from §2.4, not the summary table near the top of the ledger):**
- **FCF-1/2/3** (`validate_linux_crash_midapply_failclosed` `high/large` /
  `_corrupt_state_failclosed` `high/medium` / `_keystore_unavailable_failclosed`
  `medium/medium`) — `kill -9` mid-signed-state-write, a truncated trust-state
  file, a locked keystore; the daemon must refuse to boot into an
  inconsistent trust state in all three, not silently continue. **FCF-1 is
  the single most severe item in this whole plan — do it first.**
- **RR-01** / the anti-replay-persistence item (`validate_linux_replay_persistence`,
  `medium/medium`; + traversal/enrollment variants if time permits) — the
  anti-replay watermark is in-memory only (RSA-0029); prove a stale/consumed
  bundle replayed after a daemon reboot is still rejected. **Naming quirk:**
  the curated Tier-1 list at the top of the ledger calls this `RR-01`; the
  raw backlog table in §2.4 calls the identical stage `FCF-4` — cross-reference
  by stage *name*, the two ID schemes don't line up 1:1.
- **CNT-1** (`validate_linux_upnp_ssrf`, `high/large`) — confirmed-present
  SSDP LOCATION/controlURL SSRF (RSA-0035), zero live coverage.
- **PH-2/PH-3** (`validate_linux_privileged_helper_socket_fuzz` /
  `_peer_authz`, both `high/medium`) — privileged-helper live IPC socket
  fuzz + cross-UID rejection (today's helper coverage is argv-only; nothing
  attacks the live socket itself). PH-4 (`_socket_perms`) and PH-5
  (`_binary_integrity`) are the same theme, also `high/medium`, and a natural
  extension if time permits — not required.
- ~~**DOS-1**~~ removed from scope — confirmed in-flight elsewhere as of
  2026-07-01, see §1. Do not build it.
Full spec + bite-test for every one of these IDs already exists in
`LiveLabSecurityTestCoverage_2026-06-22.md` §2.4 — this is implementation of
an already-designed backlog, not new design work. **If a stage exposes that
the daemon does NOT actually fail closed in one of these scenarios, that's a
real bug — fix it first (CLAUDE.md §3, non-negotiable), then build the stage
proving the fix. Don't assume the happy path already holds and write a
validator that would rubber-stamp broken behavior** (the same "find bug → fix
→ prove live" shape as this session's GM-1/RT-2/Tier-0 work, not just "add a
test for existing correct behavior").
**Size:** ~8-9 stages total but same template repeated — expect it to move
faster per-stage than Jobs 1/2 once the first one is done.

### Optional Job 4 (bonus, only if you want 4) — macOS/Windows security-validator ports
Port the already-proven Linux security checks to macOS/Windows:
**RSA-0063** (macOS bootstrap leaves a `NOPASSWD:ALL` sudoers file behind on a
failed Homebrew install — one of only 2 standing **High**-severity findings in
the entire 74-finding audit ledger, confirmed-present, zero coverage — do this
one first if you run this job at all), **S3-10** (macOS codesign / Windows
Authenticode deploy-time check, today CI-gate-only), **KC-04** (Windows
key-custody negative path — `validate_key_custody_permissions` no-ops on
non-Unix, RSA-0002, a world-readable key silently passes on Windows), **PH-7**
(port the Linux privileged-helper allowlist audit to macOS `pfctl`), **KL-2/3/4**
(macOS/Windows killswitch-leak parity — Linux has full v4+v6 active-probe
coverage, others don't), **KC-07** (macOS/Windows secrets-not-in-logs parity —
RSA-0080 is **no longer part of this job — applied 2026-07-17**. The
open question this doc correctly flagged (was the gate really red, or did the
2026-07-01 scoped run just miss the check?) is now settled: it WAS red, and the
scanner was additionally catching only 1 of the 4 sensitive `rm -f` sites. Both
are fixed — `secure_remove_file` covers all four, the scanner no longer misses
variable-named ones, and `secrets_hygiene_gates.sh` exits 0).
This is the job most likely to collide with Job 3 (same daemon-audit-module
pattern, same wiring files) — run it only if 4-way parallelism is genuinely
wanted; otherwise fold RSA-0063 into a follow-up after Job 3 lands.

## 5) Acceptance bar (all jobs)

Per `CLAUDE.md` §9 Definition of Done:
- **Gates green**, run continuously during implementation (§5), not just at
  the end: `cargo fmt --all -- --check`, `cargo check --workspace --all-targets --all-features`,
  `cargo test --workspace --all-targets --all-features` (clippy may show the
  known pre-existing local-toolchain-version lints unrelated to your diff —
  verify via `git diff --stat` that flagged lines aren't yours before
  treating clippy as green).
- **No TODO/FIXME/placeholder** in the delivered stages (§3/§9) — a stage
  that's half-wired (e.g. registered but not gated correctly, or a validator
  that always passes) is not done.
- **Fail-closed, not fail-open** (§3/§10.1) — every new probe/audit path
  must handle its error/ambiguous case by denying or refusing to boot, never
  by defaulting to a permissive state. No `unwrap()`/`expect()` in the new
  production code paths (§10.2) — tests and one-shot CLI entry points are
  the only exemption.
- **Each new security control needs both an enforcement point in code and a
  verification method** (§4) — for these jobs, the verification method is
  the new live-lab stage; if a stage reveals the enforcement point doesn't
  actually exist or doesn't fail closed, that's a bug to fix, not a footnote.
- **A live run proving the new stage(s) actually pass/fail correctly** — not
  dry-run-as-pass (`CLAUDE.md` §12.3 and the FAIL-LOUD spec referenced in
  Job 2). Verify the row lands in `documents/operations/live_lab_run_matrix.csv`
  after any live evidence run.
- **Update the owning ledger(s)** before reporting done (§5: "keep the
  owning ledger or work document current"; §6: "keep documentation
  synchronized with implementation"). At minimum, flip the relevant row(s)
  in `LiveLabSecurityTestCoverage_2026-06-22.md` (§2.4 and/or the Tier-1
  table) from open to done-with-evidence, and for Job 2 also
  `CrossPlatformRoleParityPlan_2026-06-21.md` §3 / `CrossPlatformRoleParityRoadmap_2026-06-22.md`
  §2. Don't leave the ledgers describing a gap your own commit just closed.
