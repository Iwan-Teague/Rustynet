# G3 Full Sweep Diff (A3) — matched-topology functional parity, bash vs `--node`

**Artifact class: MUST-KEEP (survives the harness deletion).** The Phase-A/A3 mechanical sweep of
`BashOrchestratorRetirementProgram_2026-08-22.md`, completing the outcome half of
`NodeEngineAcceptanceSpec_2026-07-23.md` §8 (the enumeration half is
`G3EnumerationDiff_2026-07-23.md`). Raw diff output archived alongside as
`G3FullSweepDiff_2026-08-22_parity_diff.json`.

**SCOPE STATEMENT (mandatory per A3): this sweep discharges §8 ONLY for the stages present in
the matched topology below — a Linux exit+client run. It structurally CANNOT name the
macOS/Windows/cross-OS role cells (a single green-able topology contains none of them); those
are enumerated by the A4 ledger-wide comparison
(`BashRetirementGapEnumeration_2026-08-22.md`) and dispositioned via Phase B
(`BashRetirementDispositions_2026-08-22.md`).**

## The two source runs (A1, executed 2026-08-26)

Matched topology on both engines: `debian-headless-4` = exit, `debian-headless-2` = client
(UTM lab, same guests, back-to-back, `--source-mode working-tree`).

| engine | run / ledger row | commit | dirty | stages.tsv | outcome |
|---|---|---|---|---|---|
| bash (`--legacy-bash-orchestrator`) | `livelab-1787765081-25d49e20fa09` (bash archive ledger) | `25d49e20` | clean | 15 rows, **15/15 pass** | orchestrator `run_summary.md`: **pass** (11m 23s) |
| `--node` (default engine) | `livelab-1787765751-43a3788da537` (node ledger) | `43a3788d` | dirty:worktree* | 59 rows, **37 pass / 22 skip / 0 fail** | `partial` (skips only — strict-`pass` requires zero skips) |

*The node run deployed the working tree carrying the uncommitted C-STUN macOS/Windows edits
(committed immediately after); the dirty set did not touch the engine's stage logic.

Flag mutual-exclusions verified live the same day (A1 acceptance):
`--legacy-bash-orchestrator` + `--node` → hard error; `--legacy-bash-orchestrator` +
`--setup-only`/`--run-only` → hard error (enforced at `vm_lab/mod.rs` config validation).

## Sweep invocation

```bash
RUSTYNET_BIN=target/debug/rustynet-cli \
scripts/e2e/orchestrator_parity_diff.sh \
  state/g3-a1-bash-1787764349 state/g3-a1-node-1787764349 state/g3-a2-parity_diff.json
```

`--mode functional` (strict is unsatisfiable across dialects by design). Non-zero exit is
expected while diffs are open; the populated diff below is the gate.

## Results

- **`overall_functional_parity_pass: false`** — driven entirely by the two bookkeeping rows
  below, NOT by any shared-stage behavioural difference.
- **14 shared stages, `matches:true` on ALL 14, `matches:false` on ZERO:**
  `discover_local_utm`, `preflight`, `prepare_source_archive`, `verify_ssh_reachability`,
  `cleanup_hosts`, `bootstrap_hosts`, `collect_pubkeys`, `membership_init`,
  `distribute_membership`, `distribute_assignments`, `distribute_traversal`,
  `distribute_dns_zone`, `enforce_baseline_runtime`, `validate_baseline_runtime`.
  Everything both engines executed on this topology, they adjudicated identically.
- **`stages_only_in_left` (bash-only) — 3 rows, all harness/meta, none a capability:**
  - `macos_preflight_check` — the bash script's benign Linux-preflight artifact ("no macOS
    nodes in topology — skipping"); the `--node` engine plans macOS stages only when a macOS
    node exists. Not a coverage drop.
  - `prime_remote_access` — a bash setup convenience step (SSH key priming); the `--node`
    engine performs the equivalent inside bootstrap. Not a coverage drop.
  - `vm_lab_run_live_lab` — the bash path's meta/wrapper stage for the run itself; the
    `--node` engine has no such self-row. Bookkeeping, not a capability. (This same wrapper
    row is why the bash ledger row records `fail` while the orchestrator's own
    `run_summary.md` records `pass`: the wrapper's post-run JSON parse hiccuped on prompt
    noise. The engine-level stage evidence — 15/15 pass — is the authoritative signal here.)
- **`stages_only_in_right` (`--node`-only) — 46 rows:** the `--node` engine's richer stage
  vocabulary (the full 59-stage plan with per-stage terminal statuses, including every
  role/validation/cross-network stage recorded as an explicit skip with reason, where bash
  simply writes nothing). Extra coverage on the surviving engine — not diffs to close.
- **`overall_status_match: false`** (left `failed` / right `partial`): left is the wrapper
  bookkeeping row above; right is the zero-skip strict-pass scoring rule
  (`live_lab_run_matrix.rs::overall_result`). Neither is a shared-stage behavioural
  difference.

## Direction verdicts (Spec §8 — bash is not the oracle)

Every diff row above resolves as: **no genuine `--node` coverage drop exists on this
topology.** The three bash-only rows are harness bookkeeping (dispositioned in Phase B's
ledger as part of the A3-union — see `BashRetirementDispositions_2026-08-22.md`); the 46
node-only rows are the surviving engine's superset coverage. The mac/win/cross-OS cells are
Phase-B territory via A4, per the scope statement.

## Cross-references

- Enumeration half (flip precondition, complete): `G3EnumerationDiff_2026-07-23.md`.
- Ledger-wide per-cell worklist (the Phase-B input): `BashRetirementGapEnumeration_2026-08-22.md`.
- Disposition ledger: `BashRetirementDispositions_2026-08-22.md`.
- Raw output: `G3FullSweepDiff_2026-08-22_parity_diff.json` (this directory).
