# Overnight Autonomous Verified-Plane March

**Date:** 2026-06-08
**Status:** Proposal (v2 — agent-driven rewrite; supersedes the v1 "Rust binary + one-shot LLM patch" design described in §13)
**Owning Agent:** iwan

## 1. Problem Statement

The goal is to **march the verified-working plane to green** — every role
(client, admin, exit, relay, anchor) proven live on every OS that supports it
(Linux, macOS, Windows) — **unattended, overnight, with no human in the loop**.
Some progress per night is acceptable and preferred over none; this is the
track that warrants the most compute.

Two facts shape the design:

1. **The blocker is mostly net-new implementation, not bug-patching.** Re-running
   the orchestrator on already-green cells finds nothing new, and unsupported
   role/OS combos *skip* rather than fail (see
   [`deploy_relay.rs:155`](../../../crates/rustynet-cli/src/vm_lab/orchestrator/stage/deploy_relay.rs),
   [`relay_validation.rs:65`](../../../crates/rustynet-cli/src/vm_lab/orchestrator/stage/relay_validation.rs)).
   The real frontier is missing adapters and substages: Windows relay (pending
   its SCM install — [`deploy_relay.rs:53`](../../../crates/rustynet-cli/src/vm_lab/orchestrator/stage/deploy_relay.rs)),
   anchor deferred substages
   ([`anchor_validation.rs:330`](../../../crates/rustynet-cli/src/vm_lab/orchestrator/stage/anchor_validation.rs)),
   macOS dataplane depth, coordinated multi-node traffic. **Marching the plane
   means an agent that can implement, not just patch.**

2. **The verification oracle is already built and objective.** A live-lab stage
   goes green on real VMs or it does not. This collapses the central risk of
   unattended autonomous coding — self-deception — to a bounded failure mode:
   the worst an overnight run can do is produce a throwaway branch and waste
   compute. It can never silently break `main`. This oracle is what makes the
   ambitious version viable here when it would not be elsewhere.

The existing single-cycle live-lab tooling (`start_live_lab_run`,
`get_run_result`, `rebuild_nodes`, etc.) and the loop primitives added in
`bc9753b` (durable journal, `preflight_check`, the `overnight-live-lab-loop`
prompt) are the right substrate. What is missing is a **coverage-driven
scheduler** and a **driver that spawns a real engineering agent per work-unit**
instead of a fixed state machine calling a one-shot LLM.

## 2. Goal and Non-Goals

### Goal
An unattended overnight system that, for 10+ hours with zero human input:
- Tracks a typed **frontier backlog** of every (OS, role) cell and what state
  it is in (`verified` / `red` / `flaky` / `unbuilt`).
- Picks the highest-value not-yet-green cell each work-unit.
- Spawns a **fresh tool-using agent session** to implement or fix that cell,
  using the existing MCP servers as its toolset and the journal as its memory.
- Verifies every claimed green by re-running the live-lab stage (the oracle).
- Commits incremental progress to an isolated branch — never `main`, never
  pushed.
- Rotates breadth-first so one hard cell cannot consume the whole night.
- Leaves a morning artifact: newly-green cells, a progress journal, and a
  parked/escalated list.

### Non-Goals
- **No merge to `main` without human review** (see §10). The run is unattended;
  accepting the work is the operator's morning step.
- **No autonomous `git push` or any destructive remote op.**
- **No autonomous mutation of security-sensitive crates** without the extra
  adversarial-review gate (§10.2).
- Not a flake-hunter. Soak/flake surfacing on already-green cells is valuable
  but is a separate mode tracked under §12 future work — this system's job is
  forward coverage.

## 3. Key Enabler: The Live Lab as Objective Oracle

Autonomous overnight *feature-building* normally fails because the agent claims
success while actually breaking things, with no objective check. Rustynet has a
strong, pre-built, objective oracle: the orchestrator runs the role on real VMs
and the stage is green or it is not.

Consequences for the design:
- **Every claimed fix is verified by re-running the stage**, not by the agent's
  self-assessment.
- **Blast radius is bounded.** All work lands on an isolated branch behind
  mandatory gates. Worst case = a branch you delete in the morning.
- **Partial credit is measurable.** "Compiles + gates pass but stage still red"
  vs "stage advanced from 3/7 to 5/7 substages" are distinguishable signals the
  scheduler can use to prioritize and to decide continue-vs-park.

## 4. Architecture — Agent-Driven, Three Layers

```
┌──────────────────────────────────────────────────────────────┐
│  Layer 1: Thin Driver  (rustynet-cli: ops vm-lab-overnight)    │
│  • owns the frontier backlog + scheduler                       │
│  • branch isolation, per-cell attempt budget, anti-tarpit      │
│  • spawns ONE fresh agent per work-unit (argv-only exec)       │
│  • NO LLM HTTP client, NO embedded patch logic                 │
└───────────────┬───────────────────────────────┬───────────────┘
                │ spawns (claude -p, headless)   │ verifies
                ▼                                 ▼
┌───────────────────────────────┐   ┌────────────────────────────┐
│ Layer 2: Fresh Agent Session  │   │ Live-Lab Oracle             │
│ (one per work-unit; fresh     │   │ start_live_lab_run /        │
│  context every time)          │   │ rebuild_nodes → stage green │
│ • reads cell spec + journal   │   │ (objective ground truth)    │
│ • uses repo-context MCP for    │  └────────────────────────────┘
│   priors, lab-state MCP to run │
│ • implements / fixes the cell  │
│ • gates → live-verify → commit │
│ • journals progress + next-step│
└───────────────┬───────────────┘
                │ append-only
                ▼
┌──────────────────────────────────────────────────────────────┐
│ Layer 3: Shared State (filesystem, survives context + crash)   │
│ • frontier-backlog.json   (typed cells, NEW)                   │
│ • mcp-loop-journal.jsonl  (EXISTS, bc9753b)                    │
│ • overnight branch        (isolated, never pushed)             │
│ • run manifest + parked list                                   │
└──────────────────────────────────────────────────────────────┘
```

**Why fresh-agent-per-work-unit.** The v1 design (and the original problem
statement) names context-window exhaustion as the blocker: a single agent
fills up after 3–5 hard iterations. The fix is not a smaller, dumber LLM call —
it is a *fresh* full-capability agent per work-unit. Each starts clean, reads
the journal to learn what prior units did, does one bounded increment, commits,
and exits. Unbounded total work, bounded per-session context.

### 4.1 What Already Exists vs What Is New

| Capability | Status | Source |
|---|---|---|
| Durable append-only journal (`write_loop_note` / `get_loop_journal`) | **EXISTS** | [`lab_state.rs:1309`](../../../crates/rustynet-mcp/src/bin/lab_state.rs) |
| Loop-start go/no-go (`preflight_check`) | **EXISTS** | bc9753b |
| `overnight-live-lab-loop` agent playbook prompt | **EXISTS** | [`lab_state.rs:1799`](../../../crates/rustynet-mcp/src/bin/lab_state.rs) |
| Deploy preview / run diff (`what_will_deploy`, `diff_runs`) | **EXISTS** | bc9753b |
| Live-lab run + fast re-verify (`start_live_lab_run`, `rebuild_nodes`) | **EXISTS** | [`lab_state.rs`](../../../crates/rustynet-mcp/src/bin/lab_state.rs) |
| Agent priors (`get_orchestrator_stages`, `get_role_transition`, `get_architecture_constraints`, `which_crate`, `get_security_controls`) | **EXISTS** | [`repo_context.rs`](../../../crates/rustynet-mcp/src/bin/repo_context.rs) |
| Role-arg parsing (`parse_node_role_arg`) | **EXISTS** | [`role_assignment.rs`](../../../crates/rustynet-cli/src/vm_lab/orchestrator/role_assignment.rs) |
| Frontier backlog (typed cell state + value ranking) | **NEW** | §6 |
| Thin driver: scheduler, branch isolation, attempt budget, anti-tarpit | **NEW** | §7, §9 |
| Per-unit fresh-agent spawner (headless `claude -p`) | **NEW** | §8 |
| Safety rails: security-crate denylist, worktree isolation, autonomy dial | **NEW** | §10 |

The hard, high-value substrate (journal, oracle, MCP toolset, playbook) is
already in the tree. The build is mostly the backlog + a thin driver + rails.

## 5. The Work-Unit Loop

```
preflight_check()                       // EXISTS — host tools, lab reachability go/no-go
checkout_or_create_branch("overnight/<date>_<run_id>")   // isolated, never main

backlog = load_or_build_frontier_backlog(inventory, platform_matrix)

while time_remaining() && backlog.has_actionable_cell() {
    // --- pick highest-value not-green cell within budget ---
    cell = backlog.next_actionable()        // breadth-first; skips parked/over-budget
    if cell.is_none() { break }

    // --- per-cell health pre-flight (reuse) ---
    health = preflight_for_cell(cell)
    if !health.ok { backlog.park(cell, "lab unhealthy"); continue }

    // --- spawn ONE fresh engineering agent for this cell ---
    let unit_prompt = render_unit_prompt(cell, backlog.summary(), journal_pointer);
    let agent_result = spawn_headless_agent(unit_prompt, mcp_config, allowed_tools)?;
    //  the agent, inside its own fresh context:
    //    1. get_role_transition / get_orchestrator_stages / which_crate  (priors)
    //    2. read the existing sibling adapter (e.g. Linux relay) for the pattern
    //    3. implement or fix the missing piece on the overnight branch
    //    4. run gates (fmt → check → clippy → test) via gate-runner MCP
    //    5. live-verify: start_live_lab_run / rebuild_nodes for THIS cell only
    //    6. commit if green; write_loop_note(progress, next_step) either way; exit

    // --- driver evaluates by the ORACLE, not the agent's word ---
    match verify_cell_via_oracle(cell) {
        Green => {
            backlog.mark_verified(cell);
            append_matrix_row(cell, "VERIFIED");
        }
        Advanced { from, to } => {                 // partial credit
            backlog.record_progress(cell, from, to);   // stays actionable, attempt++
        }
        NoProgress => {
            backlog.attempt_failed(cell);
            if backlog.over_budget(cell) {
                backlog.park(cell, "attempt budget exhausted");
                write_checkpoint(cell);            // morning escalation
            }
        }
    }
    enforce_clean_tree_or_revert();                // §10.3 — uncommitted work discarded
}

write_run_manifest();                              // morning artifact
```

The driver runs no LLM logic of its own. Its intelligence is *scheduling*; the
agent's intelligence is *engineering*; the oracle's authority is *truth*.

## 6. Frontier Backlog — The Core New Structure

The backlog is the thing that converts blind round-robin (the v1 flaw) into
actual forward progress. It is a persisted JSON document of every cell:

```json
{
  "built_at": "2026-06-09T00:00:00Z",
  "cells": [
    {
      "os": "linux", "role": "relay",
      "state": "verified",       // verified | red | flaky | unbuilt | parked
      "last_run": "cycle_0007",
      "stage": "relay_validation",
      "progress": "6/6 substages",
      "value": 0,                // 0 = nothing to do; higher = more valuable to attempt
      "attempts": 1,
      "notes": "live-wired Linux; green r33"
    },
    {
      "os": "windows", "role": "relay",
      "state": "unbuilt",
      "stage": "deploy_relay_service",
      "progress": "0/1 — no SCM relay-deploy adapter",
      "value": 90,               // high: net-new adapter, clear sibling to copy
      "attempts": 0,
      "blocked_by": "windows SCM relay install adapter",
      "sibling_reference": "crates/.../adapter/linux.rs relay deploy"
    },
    {
      "os": "macos", "role": "blind_exit",
      "state": "parked",
      "value": 0,
      "notes": "EXCLUDED — irreversible identity wipe, single macOS VM (role_presets.rs:438)"
    }
  ]
}
```

### 6.1 How cells are derived
- The cell universe = `get_orchestrator_stages` × the platform-support matrix
  (the same `NodeRole::is_supported_for_platform` posture the orchestrator
  already enforces — the driver reads it, never hardcodes the table).
- Initial state is seeded by replaying the most recent live-lab run matrix
  (`live_lab_run_matrix.csv`) and the orchestrator skip/fail reasons: a stage
  that *skips* with "no adapter" → `unbuilt`; a stage that *fails* → `red`; a
  green stage → `verified`.

### 6.2 Value ranking (breadth-first, "some progress over none")
`value` is high when a cell is: not green, has a clear sibling implementation to
pattern-match (e.g. Windows relay can copy the live Linux/macOS relay adapter),
and is not blocked by an external dependency. The scheduler always takes the
highest-value actionable cell, and **rotates off** a cell once it hits its
attempt budget so the night spreads across the frontier rather than drowning in
one tarpit.

### 6.3 blind_exit is excluded
`blind_exit` is irreversible — it **wipes node identity and requires a factory
reset to leave** ([`role_presets.rs:438`](../../../crates/rustynet-control/src/role_presets.rs),
`anything_to_blind_exit_is_irreversible` test at
[`role_presets.rs:737`](../../../crates/rustynet-control/src/role_presets.rs)). On the
single macOS VM, an unattended transition into `blind_exit` ends the night. It
is permanently parked with `value: 0` and never scheduled.

## 7. The Thin Driver

A Rust command (`ops vm-lab-overnight`) in `rustynet-cli`, consistent with the
Rust-first constraint and able to call orchestrator internals
(`parse_node_role_arg`, the platform-support posture, `rebuild_nodes`) directly.

Responsibilities — and *only* these:
- Build/load and persist the frontier backlog (§6).
- Branch isolation: create/checkout `overnight/<date>_<run_id>`, assert it is
  not `main`, never push.
- Per-work-unit: render the cell prompt, **spawn a fresh headless agent via
  argv-only exec** (no shell string construction with cell values — §10),
  wait, then verify via the oracle.
- Scheduler + anti-tarpit (§9): attempt budgets, park/rotate, breadth-first.
- Enforce clean-tree-or-revert between units (§10.3).
- Emit the run manifest + checkpoints.

The driver contains **no LLM client and no patch parser**. That entire v1
surface is deleted (§13).

## 8. The Per-Unit Agent Session

For each cell the driver spawns a fresh headless Claude Code agent
(`claude -p "<unit_prompt>" --mcp-config <rustynet-mcp.json> --allowedTools …`),
argv-only.

What the agent receives:
- The **cell spec**: target (os, role), the failing/absent stage, the current
  progress string, and the `sibling_reference` (the already-working adapter to
  copy the pattern from).
- The three MCP servers as its toolset: `rustynet-repo-context` (priors:
  `get_role_transition`, `get_architecture_constraints`, `which_crate`,
  `get_security_controls`), `rustynet-lab-state` (run + verify + journal), and
  `rustynet-gate-runner` (gates).
- A pointer to the journal (`get_loop_journal`) so it learns what prior units
  tried and where they got to.
- The `overnight-live-lab-loop` playbook as its operating procedure.

What the agent does in its own fresh context:
1. Pull priors and read the sibling adapter for the pattern.
2. Implement the missing adapter / fix the broken stage on the overnight branch.
3. Run gates via the gate-runner MCP.
4. Live-verify the **single** cell (`rebuild_nodes` fast path where possible).
5. If the oracle says green → commit (`overnight: <os>/<role> → <stage> green`).
   Either way → `write_loop_note` with hypothesis, what changed, result, and the
   **explicit next step** so the next session (or next night) continues a large
   cell from where this one stopped.
6. Exit. Context is discarded; durable progress lives in git + journal.

This is the design's core bet: the part that actually fixes rustynet-class bugs
and builds adapters is a *full investigating agent with the live lab and the
repo-context priors* — not a 100-line log tail fed to a one-shot JSON patcher.

## 9. Scheduler and Anti-Tarpit

- **Per-cell attempt budget** (`--max-attempts-per-cell`, default 3). On exhaust,
  the cell is parked and a checkpoint written for morning review.
- **Breadth-first rotation.** After each unit the scheduler re-ranks and may move
  to a different cell, so a hard cell cannot monopolize the night.
- **Partial-credit progress.** If the oracle reports the stage advanced (more
  substages passing) the cell stays actionable and the attempt counter is
  forgiven once — real progress earns another session. Genuine no-progress
  attempts count against the budget.
- **Time budget.** `--max-duration-secs`; the loop finishes the current unit and
  writes the manifest rather than starting a unit it cannot complete.

## 10. Safety Envelope (unattended, nothing human-reviewed until morning)

### 10.1 Branch isolation
All work on `overnight/<date>_<run_id>`. The driver asserts the branch is not
`main` before any commit, and **never** runs `git push`. Morning review merges.

### 10.2 Security-sensitive crate denylist + adversarial review
Cells whose fix would touch `rustynet-policy`, trust-state / signed-bundle
paths, key-custody, or crypto code are flagged. For those, the agent's diff is
**not auto-committed** — a second, independent review agent must adversarially
confirm it preserves default-deny / fail-closed / verify-before-apply
(CLAUDE.md §10.4/§10.5) before the commit lands; otherwise the cell escalates.
Non-security cells commit on green directly.

### 10.3 No dirty tree ever survives a unit
Between units the driver guarantees a clean starting point. Revert is
`git reset --hard <unit_base> && git clean -fd` (scoped to the worktree) — note
this is stronger than v1's `git checkout -- .`, which left untracked files from
a bad attempt behind. Optionally each unit runs in a git **worktree** so a
wedged attempt cannot corrupt the primary tree at all.

### 10.4 Gates are mandatory and authoritative
`fmt → check → clippy -D warnings → test` via the gate-runner MCP before any
live-verify. A commit requires gates green **and** the live-lab oracle green.

### 10.5 Key custody (LLM/agent credentials)
The headless agent authenticates via the operator's existing Claude Code
credentials — no new API-key handling is introduced by this system. If a raw
provider key is ever used, follow AGENTS.md §4 (OS keychain → env → arg),
never logged, never journaled, redacted in tracing.

### 10.6 Autonomy dial
The default boundary: **run unattended, merge by morning review** (a ~5-minute
look). For closer-to-zero-touch, `--auto-merge-safe-cells` will fast-forward a
cell into `main` only when *all* hold: touched no denylisted crate, full gates
green, live-lab green on re-run, and the adversarial reviewer passed. Everything
else escalates. Security crates are never auto-merged.

### 10.7 Emergency stop
`stop_overnight` (MCP) → SIGTERM → the driver finishes the current unit's
revert-to-clean and writes the manifest.

## 11. Pre-Flight and Health (reuse)

- Loop start: `preflight_check` (host tools + lab reachability go/no-go).
- Per cell: power-state + SSH reachability; stuck Linux VM →
  `recover_stuck_vms` / `probe_and_recover_local_utm.sh`; stopped VM →
  `power_on_vm`; unreachable after recovery → park the cell for this run.
- Every Nth unit (default 20): deep pass — full discovery JSON,
  `host_disk_status`, `validate_inventory` — to catch IP drift / killswitch SSH
  lockouts before wasting a run.

## 12. Configuration Interface

```
ops vm-lab-overnight
  [--inventory <path>]
  --ssh-identity-file <path>
  [--known-hosts-file <path>]
  [--branch-prefix <name>]               # default: overnight
  [--backlog <path>]                     # persisted frontier backlog
  [--max-duration-secs <secs>]           # wall-clock budget for the whole run
  [--max-attempts-per-cell <N>]          # default 3
  [--rotation deep-first|breadth-first]  # default breadth-first
  [--auto-merge-safe-cells]              # autonomy dial (§10.6), off by default
  [--agent-cmd <path>]                   # headless agent binary (default: claude)
  [--agent-timeout-secs <secs>]          # per work-unit
  [--dry-run]                            # build + print the backlog & schedule, exit
```

Morning artifact location: `artifacts/overnight/<date>_<run_id>/` containing
the run manifest, per-cell checkpoints for escalations, and a copy of the
journal slice for the run.

## 13. What This Supersedes (v1)

The v1 draft proposed a standalone Rust binary embedding its own LLM HTTP
client that, on failure, sent a ~100-line log tail to a one-shot completion and
applied a JSON patch. That design is **dropped** because:

- It under-powers the one part that needs the most power. The real rustynet
  fixes (DNS fail-closed resolver binding `:53`, NRPT via `reg.exe` argv,
  in-memory key custody) required cross-component investigation, not a log-tail
  patch. A fresh investigating agent with the repo-context priors and the live
  lab is strictly stronger.
- It reinvents (weakly) the agent loop the tree already has (journal, playbook,
  preflight, MCP toolset).
- Specific v1 defects now removed: `NodeAssignment` (a type that does not
  exist), the MCP server mislabeled as `rustynet-cli` (it is the `rustynet-mcp`
  crate, bins `lab_state.rs` + `repo_context.rs`), the `mod loop;` reserved-
  keyword module name, the incomplete `git checkout -- .` revert, blind_exit in
  the rotation, and the round-robin rotation that re-ran already-green cells.

## 14. Realistic Yield

Set expectations honestly:
- **Built-but-broken cells** (given a full investigating agent + the oracle, not
  a one-shot patch) → good chance of autonomous green.
- **Large missing subsystems** (Windows relay SCM adapter) → partial but real
  forward motion: scaffold, compiles, gates green, some substages green;
  finished across several nights via the journal's next-step continuation.
- **Genuinely blocked cells** (irreversible transitions, platform limits) →
  cleanly parked/escalated, no wasted night.

Morning artifact over a single night: an isolated branch with N newly-green
cells, a journal of what advanced and the next step for each in-flight cell, and
a parked list. Over multiple nights this genuinely walks the plane toward
all-roles-all-OS green — while feature work you do during the day removes the
hard external blockers (e.g. provisioning a WinNAT-capable Windows guest).

## 15. Risks and Mitigations

| Risk | Mitigation |
|---|---|
| Agent claims green but stage isn't | Driver verifies via the oracle (re-run), never the agent's word |
| Agent writes plausible-but-wrong code | Mandatory gates + live-lab verify; isolated branch bounds blast radius to a throwaway branch |
| Security-crate regression slips in | Denylist → adversarial second-agent review before commit; never auto-merged (§10.2) |
| Large cell consumes the whole night | Per-cell attempt budget + breadth-first rotation (§9) |
| Bad attempt leaves a dirty tree | `git reset --hard && git clean -fd` (+ optional worktree isolation) between units (§10.3) |
| Context exhaustion (v1's named blocker) | Fresh agent per work-unit; durable progress in git + journal |
| Lab VM unreachable mid-run | Per-cell pre-flight + recovery; unrecoverable → park the cell |
| Irreversible role bricks a VM | blind_exit permanently excluded from the backlog (§6.3) |

## 16. Out of Scope (Future)

- **Soak/flake mode** — once the frontier is green, repeat top combos to surface
  timing/nondeterminism (NAT rebind, ICE, relay reconnect, DNS races). Real
  value, separate mode.
- **Multi-night trend analysis** — track per-cell pass-rate and progress
  velocity across nights.
- **Auto-provisioning blocked prerequisites** (e.g. a WinNAT-capable Windows
  guest). Stays a human/day-job task.

## 17. Definition of Done

- [x] `ops vm-lab-overnight --dry-run` builds the frontier backlog from the
      inventory + platform matrix and prints the cell states and the schedule,
      then exits. (Run-matrix auto-seeding deferred — see §18; manual
      `--seed-status` implemented.)
- [x] Frontier backlog correctly types cells: a supported Linux relay reads
      `unknown` (or `verified` when seeded), Windows relay reads `unbuilt`,
      macOS `blind_exit` reads permanently `parked` and is never scheduled.
      (Unit tests + observed in the live `--dry-run`.)
- [x] Branch isolation verified: the driver refuses to run on `main` /
      `master` / `release` / `prod` (`assert_safe_target_branch` + tests); the
      `LiveExecutor` contains no `git push` path. (Live commit flow unexercised —
      §18.)
- [x] A single-cell end-to-end test (mock executor) drives pick → run-agent →
      oracle-verify → mark verified, plus the security-revert, fail-closed, and
      partial-credit paths (`drive_unit` tests).
- [x] Revert-on-failure verified: the revert sequence is `git reset --hard &&
      git clean -fd` (removes untracked residue, not just `checkout`), asserted
      by `revert_to_clean_argv` test; `drive_unit` reverts whenever nothing was
      committed.
- [x] Anti-tarpit verified: a cell that never progresses is parked after
      `--max-attempts-per-cell` and the scheduler advances to the next cell
      (`run_loop_escalates_budget_exhausted_cell`, scheduler tests).
- [x] Security-denylist verified: a committed diff touching a denylisted crate
      is reverted and escalated, never auto-committed
      (`green_committed_but_security_diff_is_reverted_and_escalated`).
- [ ] Pre-flight catches an unreachable VM (powered off before the run) and
      parks the affected cells. **Not yet built** — per-cell VM health
      pre-flight/recovery is part of the live path (§18).
- [x] `cargo fmt --all -- --check`, `cargo check`, `cargo clippy … -D warnings`,
      and `cargo test` pass on the new code. (1618 `rustynet-cli` tests pass,
      60 new; clippy/fmt/check clean — 2026-06-09.)
- [x] `documents/operations/active/README.md` entry updated to describe this
      (agent-driven) design.

## 18. Implementation Status (2026-06-09)

Driver implemented and verified **without running the autonomous loop**.

**Built + tested** (`crates/rustynet-cli/src/vm_lab/overnight/`, 60 unit tests,
all gates green):
- `backlog.rs` — typed frontier (`MarchRole` × `VmGuestPlatform`), state
  classification from the real `is_supported_for_platform` /
  `is_lab_assignable_for_platform` matrix, blind_exit permanent exclusion,
  `--seed-status` parsing, JSON persistence/round-trip.
- `scheduler.rs` — value ranking, attempt budget, breadth-first vs deep-first
  rotation, anti-tarpit, `dry_run_plan` projection.
- `safety.rs` — protected-branch refusal, security-crate denylist
  (`rustynet-policy`/`-control`/`-crypto`/`-local-security`/`-dns-zone` + path
  fragments), fail-closed-on-empty, `git reset --hard && git clean -fd` revert
  argv.
- `agent.rs` — argv-only headless-agent argv builder, cell-spec prompt renderer.
- `manifest.rs` — run manifest + escalation checkpoints, filesystem writers.
- `executor.rs` — the `WorkUnitExecutor` trait, the `drive_unit` state machine,
  and `run_loop`, all exercised via a mock executor (the oracle decides cell
  state; security diffs revert+escalate; clean-tree invariant; time budget;
  escalation collection).
- CLI: `ops vm-lab-overnight [...] [--dry-run]` wired in `main.rs`; `--dry-run`
  runs end-to-end against the real inventory.

**Implemented but intentionally unexercised** (the live path — running it *is*
running the loop): `LiveExecutor` (argv-only `claude -p` spawn, git commit/diff
detection, conservative orchestrate-CLI oracle mapping exit-code →
Green/NoProgress) and the non-`--dry-run` branch of `execute_ops_vm_lab_overnight`.
Type-checked and clippy-clean; never invoked by tests or by hand.

**Not yet built** (next increments, all on the live path):
- Per-cell VM health pre-flight + recovery (proposal §11) — reuse
  `preflight_check` / `recover_stuck_vms`.
- Substage-level `Advanced` (partial-credit) detection in the live oracle —
  currently only the mock emits it.
- The adversarial second-review agent (§10.2) — the *gate* (revert+escalate on a
  security diff) is built; the reviewing agent is not.
- `--auto-merge-safe-cells` autonomy dial (§10.6) — flag parsed/reported; the
  auto-merge action is not wired (everything escalates for now).
- Run-matrix auto-seeding of prior verdicts (§6.1) — `--seed-status` is the
  manual stand-in.
