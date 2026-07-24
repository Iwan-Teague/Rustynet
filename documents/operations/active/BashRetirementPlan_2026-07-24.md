# Bash Retirement Plan (W5.7) — 2026-07-24

**Owner:** WS-D draft (window work while the D2 live-verify ran). **Status:** PLAN —
W5.7 not started; a separate, later gate after the landed W5.6 flip. Governed by
**G3** of `NodeEngineAcceptanceSpec_2026-07-23.md` §8. This is a *coordination-heavy
deletion* touching shared code — it must be run once, by one integrator, with the
labs quiet and the integration token held.

## 0. Where W5.7 sits
- **W5.6 (flip) LANDED** — the Rust `--node` engine is the default; `--legacy-bash-
  orchestrator` is the rollback lever. **Deleting bash removes that rollback**, so
  W5.7 must not proceed until `--node` trust is high enough that rollback is unneeded
  (G1 satisfied + a soak period of green default-`--node` runs; G2 progressing).
- **G3 enumeration half already done** as a flip precondition:
  `G3EnumerationDiff_2026-07-23.md` (zero silently-dropped coverage). W5.7 needs the
  **full** differential sweep + **owner-signed dispositions** (spec §8), not just the
  enumeration.

## 1. The G3 gate (spec §8) — what must be true before deletion
For **every** stage bash proved GREEN that `--node` has not, either **(a)** prove it on
`--node`, or **(b)** record an **owner-signed disposition**. Plus:
- Run `vm-lab-diff-orchestrator-parity` / `scripts/e2e/orchestrator_parity_diff.sh` for
  the full sweep; **archive the diff output as a permanent artifact** (it must survive
  even after the harness is deleted — spec §8).
- No un-dispositioned `--node` coverage **drop** remains.

## 2. Direction-diagnosis mandate (spec §8 + owner standing guidance — NON-NEGOTIABLE)
**bash is NOT the oracle.** `--node` has diverged from bash on purpose. Every bash↔`--node`
diff is a *question, not a verdict*:
- `--node` may be the **correction** — a vuln bash rubber-stamped, an OS case bash
  mishandled, a fail-closed path bash left fail-open, a stage bash never had. A bash
  `pass` is not proof of correctness (this repo has real bash false-greens — spec §0
  notes bash claims 52 `two_hop` passes `--node` never produced).
- For each diff, first determine **which engine is right**. Only a genuine `--node`
  coverage *drop* is a `--node` gap to fix (option a). When `--node` is the correction,
  the disposition is **"node supersedes bash" with the recorded reason** (option b).
- **Never silently make `--node` match bash to close a diff** — that re-introduces the
  exact legacy defect the divergence fixed.

## 3. Deletion inventory (what goes, what stays) — grounded
**Delete (the bash orchestrator surface):**
- Scripts: `scripts/e2e/live_linux_lab_orchestrator.sh` (the bash orchestrator),
  `scripts/e2e/orchestrator_parity_diff.sh` (the diff tool — after archiving its final
  output), `scripts/ci/orchestrator_engine_gates.sh` (bash-engine gates).
- Code: the `--legacy-bash-orchestrator` flag + its plumbing (`main.rs`); the bash
  branches in `live_lab_stage_manifest.rs` (the `active_plan=None` first-writer-wins
  bash path vs the `--node` membership-driven path), `live_lab_run_matrix.rs` (the
  frozen bash-ledger *writer* + routing), `vm_lab/orchestrator/parity.rs`,
  `live_lab_coverage.rs`, and the bash arms in `native.rs` / `vm_lab/mod.rs` /
  `vm_lab/topology.rs` / `bin/live_lab_support`.
- The `run_command`/dialect that routes to bash.

**Keep (do NOT delete):**
- **The frozen bash ledger** `documents/operations/live_lab_run_matrix.csv` (~1 MB) —
  historical evidence; archived, never crossed with the `--node` ledger.
- The archived G3 diff artifact (§1).
- The entire `--node` engine, the acceptance spec (native-spec, survives bash by
  design), and `live_lab_node_run_matrix.csv` (the ledger that counts).

## 4. Order of operations
1. Confirm the deletion preconditions of §0 (G1 held; a soak of green default-`--node`
   runs; owner comfortable losing the rollback lever).
2. Full G3 sweep (§1); **archive the diff**.
3. Direction-diagnose every diff (§2); record owner-signed dispositions in a named
   ledger (mirror the D1/D2/D3 flip-disposition pattern).
4. Verify no un-dispositioned `--node` coverage drop.
5. Delete the §3 bash surface in ONE reviewable change (integration token held, labs
   quiet, all workers idle — this touches files across WS-A/WS-B/WS-C scopes).
6. Verify post-deletion: **default (no-feature) build** compiles, `--features vm-lab`
   builds, `fmt`/`clippy --exclude rustynet-mcp`/`test` green, and a `--node` live-lab
   run is still green (the deletion must not perturb the `--node` path).
7. Mark spec §8 (G3) satisfied; retire this plan.

## 5. Risks / watch
- **Rollback loss** — after W5.7 there is no bash fallback. Gate on real `--node`
  confidence, not calendar.
- **Divergent-vocabulary diffs** (spec §0: ledgers disagree, bash `two_hop` passes
  `--node` never produced) — these are the direction-diagnosis cases; do not chase them
  into re-growing bash quirks on `--node`.
- **Cross-scope deletion** — the bash code is threaded through files several workers
  own; W5.7 is an orchestrator-coordinated single pass, not a per-worker edit.

## 6. Definition of done
G3 full sweep run + diff archived; every bash-GREEN/`--node`-not diff either proven on
`--node` or owner-signed-dispositioned; bash orchestrator surface (§3) deleted; the
rollback lever removed; default + `--node` builds/gates green; a green post-deletion
`--node` live run; frozen bash ledger + G3 diff kept as archives; spec §8 marked
satisfied.
