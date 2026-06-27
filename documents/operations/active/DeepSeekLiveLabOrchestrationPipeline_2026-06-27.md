# DeepSeek Live-Lab Orchestration Pipeline — Design

- Status: **BUILDING — Layer A + the rigid triage pipeline landed & live-verified; the v4-pro lab-orchestration launch is the next phase** (2026-06-27)
- Owner surface: `crates/rustynet-mcp` (the `rustynet-mcp-deepseek` server, binary `bin/rustynet-mcp-deepseek`)
- Related: [§12.5 DeepSeek MCP](../../../CLAUDE.md) · [LiveLabExecutionEfficiencyPlan](LiveLabExecutionEfficiencyPlan_2026-06-20.md) · [CrossPlatformRoleParityPlan](CrossPlatformRoleParityPlan_2026-06-21.md) · [CrossPlatformRoleParityRoadmap](CrossPlatformRoleParityRoadmap_2026-06-22.md)

## 0. Implementation status (2026-06-27)

Landed + verified on `claude/cross-platform-parity-hardening`:
- **Layer A** (`82a9bfa`): canonical `deepseek-v4-pro` / `deepseek-v4-flash` ids; `reasoning_effort:"max"` on every Pro call (the highest level per the Thinking-Mode docs — confirmed accepted by the live endpoint); a unit test locking the proxy tools out of any agent's tool-set.
- **The rigid triage pipeline** (`e98b919`): `run_triage()` runs Flash research → Flash verify → v4-pro(max) review as deterministic control flow (never model-chosen); each step is a read-only grounded agent reusing the generalized `run_grounded()` loop. Exposed as the **`deepseek_live_lab`** MCP tool (v1 triages a caller-supplied `failure_context`). Per-step stderr tracing (`[live-lab] agent '<role>' step n/N → tools`) for live observability; a `strip_dsml_markup` guard cleans DeepSeek-native tool markup that leaks into budget-exhausted answers. **Live-verified end-to-end over real MCP** against the macOS-relay false-fail: all three sub-agents launch in order and ground themselves in the real repo *and* lab (`find_files`/`grep`/`read_file`/`find_definition`/`git` + `lab_run_status`/`lab_inventory`/`lab_run_detail`/`lab_stage_log`), producing a correct, file:line-cited root-cause report.
- **Async execution** (`4a1e4fc`): the pipeline runs for minutes (v4-pro at max reasoning has unpredictable ~70s–200s+ latency), past the MCP request timeout — so `deepseek_live_lab` returns a `job_id` immediately and the new `deepseek_live_lab_result(job_id)` tool polls non-blocking (the report when done, else a "still running" status). Same async job pattern as the lab-state MCP; jobs are in-memory (lost on a server reload → re-run on miss). Verified live over real MCP: 0.4s call return, poll → full report at ~195s.

Next phase (the launch half of §6/§7 below — designed, not yet built): the **v4-pro lab-orchestration launch** — the confined lab-action tools (`lab_run_stage`/`lab_recover_vm`/`lab_clean_env`/…) + the stage-by-stage orchestration loop so `deepseek_live_lab` also *runs* the lab (setup/run-split profile invocation), with the first full live run as the verification trigger.

## 1. Intent

Push the **token-heavy, mechanical, error-prone live-lab run+triage loop down to DeepSeek**, so the main agent (Claude) spends its context only on the code change, the security call, and the final disposition. Every live-lab cycle becomes: *the main agent calls one MCP function → DeepSeek orchestrates the lab and triages any failure through a rigid multi-review pipeline → the main agent receives a single verified report → it makes the code change → repeat.*

The main agent **stops hand-driving the orchestrator**. It hands a target ("prove macOS relay", "re-run the Linux exit NAT teardown stage") to DeepSeek v4-pro and waits for a report it can act on.

## 2. Agent hierarchy & capability matrix

Three tiers. **No DeepSeek tier may write the repo, run gates, or make a security/merge decision.** Those are the main agent's, always.

| Tier | Model | Role | Repo | Lab actions | Code changes |
|---|---|---|---|---|---|
| **Top — main agent** | Claude | Ultimate control. Decides when to invoke. Verifies the returned report against real code. Makes all code changes + security calls. | read/**write** | may, but delegates | **yes (only this tier)** |
| **Mid — orchestrator** | `deepseek-v4-pro` (max reasoning) | Runs/orchestrates the live lab for a target area. Handles contingencies (restart VM, clean env, link nodes, progress stages). Final reviewer of the triage report. | **read-only** | **yes — confined allowlist** | **never** |
| **Low — sub-agents** | `deepseek-v4-flash` | Disposable research + verification workers spawned by the orchestrator during failure triage. | **read-only** | no | **never** |

Confirmed model facts (probed 2026-06-27 against `api.deepseek.com`):
- Canonical ids are `deepseek-v4-pro` and `deepseek-v4-flash` (the code's `deepseek-chat`/`deepseek-reasoner` are back-compat aliases — to be pinned to the canonical ids).
- Both support OpenAI-style **tool-calling** (`finish_reason: tool_calls`) — so a Pro tool-driven orchestrator is viable.
- `deepseek-v4-pro` **reasons by default** (always emits `reasoning_content`). There is **no separate "max"/effort dial that demonstrably changes behavior** — `reasoning_effort`/`reasoning`/thinking-budget params are accepted-but-ignored. "v4 Pro Max on high reasoning" therefore = **use `deepseek-v4-pro`**; reasoning is inherent.

## 3. The single entry point

One new MCP tool on `rustynet-mcp-deepseek`:

```
deepseek_live_lab(
  target:        string,        // what to test next, e.g. "macos relay lifecycle" or a stage name
  brief:         string|null,   // OPTIONAL main-agent-provided "what to do next" (overrides auto-fetch)
  prompt_tweak:  string|null,   // OPTIONAL main-agent addendum to the structured runbook prompt
  options:       { ... }        // skip-soak, source-mode, target OS/role, etc. — orchestrator passthrough
) -> StructuredReport
```

Calling it runs the **entire pipeline** server-side and returns one verified report. The main agent awaits it (likely as a long-running background task, as orchestrator runs are today).

**Two ways the orchestrator learns "what's next" (both supported):**
1. **Provided** (default, most common): the main agent passes `brief` ("prove the macOS relay cell; relay_capable was false in inventory but the cross-OS stage exercises it"). v4-pro orchestrates exactly that.
2. **Fetched**: if `brief` is null, the orchestrator reads the parity ledgers (`CrossPlatformRoleParityPlan`/`Roadmap`, the §3 matrix, the run matrix) via its read tools and **proposes** the next untested cell — the main agent still owns whether to accept it.

## 4. The structured orchestrator runbook (the v4-pro system prompt)

Pre-existing, version-controlled, **optionally tweaked per-call** via `prompt_tweak`. It is a *runbook*: it tells v4-pro which function to call for every situation. Draft v1 (refined during build):

> You are the RustyNet live-lab orchestrator. You are READ-ONLY on the repo and may NEVER edit code, run gates, or decide a fix is correct — you orchestrate the lab and report. Drive the target area to a live verdict using ONLY the provided functions.
>
> **To run:** `lab_status` first (inventory + VM power + reachability). Then `lab_orchestrate`/`lab_run_stage` for the target. Progress stage-by-stage; after each stage call `lab_run_progress`/`lab_report` to read the result before deciding the next.
>
> **If a VM is unreachable / SSH times out but it's in `arp`:** `lab_recover_vm` (probe-and-recover) before retrying. If still dead: `lab_restart_vm`, then `lab_status` to confirm.
>
> **If a node's environment is dirty / stale build:** `lab_clean_env` (cleanup_hosts / rebuild_nodes) for that node, then re-run the stage.
>
> **To wire nodes together:** follow the membership/enrollment functions in order; verify with `lab_status` before progressing.
>
> **On a stage PASS:** record evidence, continue to the next stage in the target.
>
> **On a stage FAIL:** stop progressing and enter the triage pipeline (§5) — do not attempt code fixes.
>
> **If you hit something you cannot recover or do not understand (early infra failure, missing precondition, ambiguous state):** STOP and report it up to the main agent with what you saw. Do not loop blindly. Bounded: at most N stage-attempts / M recovery-attempts per run.

## 5. The rigid multi-review failure-triage pipeline (NON-NEGOTIABLE)

On **any lab failure**, the orchestrator runs this exact, baked-in sequence. It is rigid — no step may be skipped, and "verify as much as possible" is the governing principle.

```
                    LAB FAIL (stage X)
                          │
        ┌─────────────────▼──────────────────┐
        │ STEP 1 — Flash research              │  deepseek-v4-flash, repo+lab grounded
        │ Why did it fail? Where? What         │  tools: read_file/grep/find_definition/git
        │ happened? (may suggest a fix —        │       + lab_report/lab_stage_log/lab_guest_exec
        │ more info is better.) Cite evidence.  │  → Draft Report (claims + citations [+ fix idea])
        └─────────────────┬──────────────────┘
        ┌─────────────────▼──────────────────┐
        │ STEP 2 — Flash verification          │  deepseek-v4-flash, repo+lab grounded
        │ Scrutinize EVERY claim in the draft:  │  "is it actually at file:line it says?
        │ is it really there? did that part     │   did that stage really fail that way?"
        │ actually happen? Correct/flag any     │  → Revised Report (claims confirmed/refuted)
        │ claim not grounded in truth.          │
        └─────────────────┬──────────────────┘
        ┌─────────────────▼──────────────────┐
        │ STEP 3 — v4-pro orchestrator review  │  deepseek-v4-pro, repo+lab grounded
        │ Re-reads the repo, re-verifies the    │  Independently checks the revised claims +
        │ claims, judges whether the suggested  │  whether the proposed fix is actually the
        │ fix is the BEST one. NO code changes.  │  best option. → FINAL Report
        └─────────────────┬──────────────────┘
                          ▼
                  MAIN AGENT (Claude)
        verifies independently → makes the code change → re-invokes
```

Each step is **grounded** — every agent has the read-only repo+lab tools and is required to cite file:line / log evidence, never opine on memory. The triple pass (research → independent verify → Pro re-verify) exists specifically to drive out the false-positive triage that an ungrounded single LLM pass produces. The output the main agent receives should almost always be *useful* — but it **certifies nothing**; the main agent's own verification stays mandatory before any code change.

**On lab PASS:** no triage needed; the orchestrator returns a lighter structured pass report (stages passed, evidence paths, run dir, matrix row) for the main agent to confirm.

## 6. The confined lab-action tool surface (what v4-pro may execute)

v4-pro orchestrates by calling **only** these allowlisted, argv-validated functions — never arbitrary shell, never repo writes. Each maps to an existing, already-hardened capability:

| Tool | Action | Backed by |
|---|---|---|
| `lab_status` | inventory + VM power + reachability + current run state | `ops vm-lab-discover-local-utm-summary`, lab-state `get_inventory`/`get_lab_status`/`check_vm_reachable` |
| `lab_orchestrate` / `lab_run_stage` | launch the orchestrator for a target / single stage (blocks for that stage, returns result) | `ops vm-lab-orchestrate-live-lab` + setup/run split + single-stage wrapper (EfficiencyPlan) |
| `lab_run_progress` | poll a running orchestration's progress / tail job log | lab-state `get_run_progress`/`tail_job_log` |
| `lab_recover_vm` | probe-and-recover a stuck guest | `scripts/vm_lab/probe_and_recover_local_utm.sh`, lab-state `recover_stuck_vms`/`reset_vm_network` |
| `lab_restart_vm` / `lab_power` | restart / power a guest | lab-state `restart_vm`/`power_on_vm`/`power_off_vm` |
| `lab_clean_env` | clean/rebuild a node's environment | orchestrator `cleanup_hosts`/`rebuild_nodes` (EfficiencyPlan) |
| `lab_guest_exec` | ONE fixed read-only diagnostic command on a guest | existing `lab_guest_exec` (already confined) |
| `lab_report` | read run report / stage log / grep report | lab-state `read_report_artifact`/`get_stage_log`/`grep_report` |
| repo read set | `read_file`/`grep`/`find_definition`/`git`/`find_files` | existing `deepseek_agent` read tools |

Confinement rules (mirroring the existing read-only agent): path-jailed, argv-only, no shell construction, no write to the repo, **lab actions only mutate the lab harness** (VMs/orchestration state), never the product source. The action set is fixed in code — v4-pro cannot invent new actions.

## 7. Execution model (long runs)

A full run is 20–40 min; a single stage is minutes. The orchestrator works **stage-by-stage**: each `lab_run_stage` blocks server-side for that one stage and returns its result, so v4-pro regains control between stages to read results, recover a VM, clean an env, or stop. This keeps any single tool call bounded to one stage rather than one 40-min monolith, and gives v4-pro the contingency control the runbook requires.

- The overall `deepseek_live_lab` MCP call is long-running (the whole pipeline) — like the gate-runner's long calls. The main agent awaits it as a background task.
- Bounded: a generous step budget + per-run wall-clock cap + max recovery-attempts. On exhaustion or an unrecoverable/early failure, v4-pro **stops and reports up** rather than looping.
- **Lab is a singleton.** The function coordinates through the existing job tracking so it never collides with a run the main agent (or another invocation) launched — one orchestrator on the VMs at a time.

## 8. Security & boundaries (hard, non-negotiable)

- **No DeepSeek tier writes the repo, runs gates, or makes the security/merge call.** Ever. (§3/§4 of the operating contract.) DeepSeek *proposes*; the main agent *verifies and disposes*.
- v4-pro's only mutations are to the **lab harness** via the fixed allowlisted action set — not the product, not production.
- All agents are **grounded** (real repo+lab read tools) and must cite evidence; ungrounded claims are a verification failure.
- The final report is **untrusted**. The triple-review reduces false positives; it does not certify. The main agent's independent verification before any code change is mandatory.
- API key resolves from `DEEPSEEK_API_KEY` / `~/Desktop/deepseek_api.md`; **never committed, logged, or written into the repo or any artifact**. If the server/key is unavailable, the main agent falls back to driving the lab directly.

## 9. Output schema (StructuredReport)

The function returns one validated object (JSON-schema enforced at the tool layer):

```
{
  target, invoked_with: {brief?, prompt_tweak?, options},
  outcome: "pass" | "fail" | "aborted_early",
  stages: [{ name, status, evidence_paths[], run_dir, matrix_row }],
  // present iff outcome == fail:
  triage: {
    draft:   { claims[], suspected_fix?, citations[] },          // Flash #1
    verified:{ claims[]:{text, confirmed:bool, note}, ... },     // Flash #2
    final:   { root_cause, where:file:line[], best_fix, confidence, dissent? } // v4-pro
  },
  // present iff aborted_early:
  blocker: { what, where, what_was_tried, why_stuck },
  audit_trace: [ per-agent tool-call log ]
}
```

## 10. Implementation plan (build after this doc is reviewed)

1. **Model ids** — pin `deepseek-v4-pro`/`deepseek-v4-flash` (replace the stale aliases) server-wide. Tiny, safe, independent.
2. **Lab-action tool layer** — implement the §6 confined action tools (argv-validated wrappers over the existing orchestrator/recovery/lab-state entry points) + a confinement unit test (default-deny out-of-allowlist; no repo write path).
3. **Orchestrator loop** — a v4-pro-driven, stage-by-stage tool-calling loop with the §4 runbook system prompt, bounded, with the stop-and-report path.
4. **Triage pipeline** — the rigid §5 Flash→Flash→v4-pro sequence as deterministic server control flow (the steps are NOT optional/model-chosen — they are hard-coded), each step a grounded agent call, output validated to the §9 schema.
5. **Entry tool** — `deepseek_live_lab` wiring `brief`/`prompt_tweak`/auto-fetch + singleton coordination + the long-running execution.
6. **Tests** — confinement test, schema-validation test, a pipeline-shape test (fail path always runs all three review steps), and a dry-run against a known stage.
7. **Docs** — update `CLAUDE.md`/`AGENTS.md` §12.5 + the active README index; record first live invocation in the run matrix.

## 11. Open decisions (for review before build)
- Step budget / wall-clock cap / max recovery-attempts values (start conservative, tune).
- Whether the auto-fetch (`brief == null`) path ships in v1 or v2 (provided-brief is the common case).
- Whether `lab_clean_env`/`lab_restart_vm` need an extra confirmation gate even within the lab harness (default: no — lab-only, reversible).
