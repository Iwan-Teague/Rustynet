# Live-Lab Stage Triage Ledger — Plan (2026-07-16)

Status: **PROPOSED** — schema + phases agreed, implementation pending.
Engine scope: **Rust `--node` engine only.**

## 1. Problem

When a live-lab stage fails, the *symptom* is durably recorded but the
*attempted remedy* is not. An agent picking up a failed stage days later — or a
second agent working the same stage concurrently — has no way to learn what has
already been tried, and re-derives (or repeats) a fix that has already been
attempted. In one session alone, two hypotheses were pursued and disproved
(`receiver_index` inbound dispatch; "workspace exclusion means the monitor is
ungated") at the cost of a live-lab cycle each. Nothing in the repository
records that they were tried.

## 2. What already exists — do not rebuild

| artifact | holds | keyed by | gap |
| --- | --- | --- | --- |
| [`live_lab_node_stage_results.csv`](../live_lab_node_stage_results.csv) | `status`, `error_detail`, `git_commit`, `run_id`, `report_dir` | `stage` × `os_family` × `run_id` | none — this **is** the error half, already automatic |
| [`live_lab_node_run_matrix.csv`](../live_lab_node_run_matrix.csv) | per-run `--node` evidence | `run_id` | per-run, not per-attempt |
| `state/mcp-loop-journal.jsonl` (`write_loop_note`) | free-form iteration prose | chronological | **gitignored** (`.gitignore:46 /state/**`) → machine-local, invisible to other agents; not keyed by stage/OS |

The `--node` engine already populates `error_detail` on every stage failure
(verified: 22/22 `live_two_hop_validation` failures populated). **No engine
change is required to capture the error.** The only missing datum is the patch.

## 3. Design

### 3.1 Ledger — `documents/operations/live_lab_stage_triage.jsonl`

Append-only JSONL, **committed** (unlike `state/`, so other agents and other
machines see it). One record per `(run_id, stage)` failure — collapsed across
nodes, because a topology-scoped stage such as `live_two_hop_validation` writes
one CSV row per participating node and would otherwise emit 4–5 identical stubs
per failure.

```json
{
  "schema": 1,
  "stub_id": "livelab-1784204238-bab155abd7cc::live_two_hop_validation",
  "ts_utc": "2026-07-16T12:17:17Z",
  "engine": "node",
  "run_id": "livelab-1784204238-bab155abd7cc",
  "run_commit": "bab155abd7cc797d7f235015eca2cec48e5ef272",
  "stage": "live_two_hop_validation",
  "stage_scope": "topology",
  "os_family": ["debian", "rocky", "ubuntu", "fedora"],
  "error": "live_two_hop binary failed (exit status: 1): sudo: rustynet: command not found; enforce-host failed for rocky@192.168.64.105:22 with status 1",
  "patch": null
}
```

Two fields only, per the operating decision: **what failed** (auto) and **our
patch** (agent). There is deliberately **no `outcome` field** — see §3.4.

`error` is the verbatim `error_detail` from the run, not a paraphrase: an exact
string is what makes "have I seen this failure before" answerable.

### 3.2 Writer — auto-stub (engine)

At evidence finalization — the same point the `--node` engine writes
`live_lab_node_stage_results.csv` — append one stub per failed stage with
`patch: null`. Idempotent on `stub_id`: re-finalizing a run must never duplicate
a stub.

### 3.3 Filler — agent, before the verification run

The agent logs the patch it is about to test, in 2–3 sentences, via
`record_stage_patch`. Because the agent fills the stub *before* committing the
fix, **the ledger row's own commit is the patch commit** — recoverable with
`git log -- documents/operations/live_lab_stage_triage.jsonl`. No SHA field is
needed, and none can go stale.

Declining to patch is a valid, deliberate answer and keeps the gate honest:

```json
"patch": "none: environmental — ubuntu hypervisor VM-reset hang (~16min) after a clean guest shutdown; not a Rustynet defect. Workaround: target reboot stages at the debian guests."
```

### 3.4 Outcome is derived, never recorded

If a patch works the stage goes green in the next run; if it fails, a new stub
opens against a new commit, which itself evidences that a patch landed in
between. Outcome is therefore a **join**, not a field — it cannot drift from
reality, and there is no state to maintain.

`stage_triage_history` derives, for each stub, from the next `--node` run that
exercised the same stage:

| next run's stage status | rendered as |
| --- | --- |
| `pass` | FIXED by this patch |
| `fail`, byte-identical `error` | did NOT fix — identical failure |
| `fail`, different `error` | ADVANCED — new failure surfaced (see next stub) |
| stage absent / `skip` | UNVERIFIED — no run has exercised it since |
| no later run | PENDING VERIFICATION |

### 3.5 MCP tools — `rustynet-mcp-lab-state`

- **`stage_triage_history(stage, os?, engine?, limit?)`** — joins the stub chain
  against `live_lab_node_stage_results.csv` and renders the attempt history
  chronologically with the derived outcome per attempt. Defaults to
  `engine=node`; reading the frozen bash archive requires an explicit opt-in.
  **The engines' stage vocabularies do not overlap** (`live_two_hop_validation`
  vs the archive's `linux_stage_two_hop`), so a blended history would be
  meaningless — this mirrors the run-matrix split.
- **`record_stage_patch(stub_id | (run_id, stage), patch)`** — fills `patch`.
  Validates the stub exists and is unfilled; rejects an empty string.

### 3.6 Gate — the orchestrator refuses to launch with an unfilled stub

**Decided:** enforcement lives in the `--node` orchestrator, not in a
pre-commit hook.

Before a run starts, the engine checks the ledger for any stub whose `stage` is
in this run's plan and whose `patch` is `null`. If one exists, the run **fails
closed at launch** and names the offending `stub_id`s.

This matches the intent precisely — the thing to prevent is *verifying without
having recorded what you are verifying* — and it blocks only the agent driving
the lab. A repo-wide pre-commit hook was rejected: it would block concurrent
sessions' unrelated commits (a doc-only commit from another agent would be
held hostage by this agent's pending stub).

Because the check is scoped to *stages in the current plan*, an unfilled stub
for a stage you are not exercising never blocks you; and a stage you have
decided not to fix is unblocked by the deliberate `"none: <reason>"` answer
(§3.3) rather than by an exception mechanism.

A `scripts/ci/live_lab_triage_gates.sh` wrapper may still be added later as a
push-time backstop, but it is not the primary enforcement point.

## 4. Phases

| phase | deliverable |
| --- | --- |
| T1 | Ledger schema + append/parse module + `stub_id` idempotency, unit-tested |
| T2 | Engine auto-stub at evidence finalization (collapsed per `(run_id, stage)`) |
| T3 | Launch-time gate in the `--node` orchestrator (fail closed, name the `stub_id`s) |
| T4 | MCP `stage_triage_history` + `record_stage_patch` |
| T5 | Backfill this session's fixes; update `documents/operations/README.md` + `LiveLabRunMatrix.md` |

## 5. Decisions taken

- **Gate fires at orchestrator launch** (§3.6), not at commit. Rejected the
  pre-commit hook because it would block concurrent sessions' unrelated
  commits.
- **No `outcome` field** (§3.4) — derived from the run matrix, so it cannot
  drift.
- **No patch-commit SHA field** (§3.3) — the ledger row's own commit is the
  patch commit.
- **`--node` engine only** — the engines' stage vocabularies do not overlap.

## 6. Related

- [LiveLabRunMatrix.md](../LiveLabRunMatrix.md) — the two-ledger split and why
  engine results must never blend.
- [LiveLabExecutionEfficiencyPlan_2026-06-20.md](./LiveLabExecutionEfficiencyPlan_2026-06-20.md)
  — the live-lab iteration loop this ledger serves.
