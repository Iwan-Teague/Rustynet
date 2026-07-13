# Track-C Bash-Orchestrator Defect Log — 2026-07-13

The W5.7 plan retires the legacy bash orchestrator
(`scripts/e2e/live_linux_lab_orchestrator.sh`). Track C pairs it against the
Rust `--node` engine per the §0.a functional-parity spec. Per owner decision
(2026-07-13): **document the legacy path's defects and form pairs only on
topologies bash handles cleanly** — do NOT invest in fixing the path being
removed. A bash defect where Rust is correct is evidence the Rust engine is
at-or-better, which supports the retirement; it is recorded here, not patched.

Every claim below is first-hand from a live run.

## BASH-DEF-1 — role collocation: one node bootstrapped under two roles

**Run:** `state/bash-baseline-1783932078` (commit `cf904d7`, invoked
`--exit-vm debian-headless-2 --client-vm debian-headless-4 --legacy-bash-orchestrator`).

**Observed.** The bash orchestrator bootstrapped `debian-headless-4` (192.168.64.10)
**twice** — once as `client-1` (client) and once as `client-3` (aux):
```
e2e bootstrap host complete: role=client node_id=client-3 src_dir=/home/debian/Rustynet   # aux slot, same guest
```
It pulled `debian-headless-4` into the `aux` slot because that guest's inventory
`lab_role` is `aux`, even though it was ALSO the explicit `--client-vm`. The
Rust `--node` engine takes roles only from the explicit `--node alias:role`
pairs and never auto-expands from `lab_role`, so it ran a clean 2-node
exit+client topology on the same flags. **Rust-correct, bash-defective** (a
node should not be admitted under two roles; the resolver should dedup or
reject).

## BASH-DEF-2 — dns-zone pubkey staging race on collocated roles

**Downstream of BASH-DEF-1.** With `client-1` and `client-3` on the SAME guest,
the `refresh_dns_zone_before_validate` step raced on a shared per-host staging
path and the aux pass failed:
```
[parallel:refresh_dns_zone_before_validate] aux debian@192.168.64.10 rc=1
install: cannot stat '/tmp/rn-dns-zone.pub': No such file or directory
```
`/tmp/rn-dns-zone.pub` is a fixed host-global temp path; two roles on one guest
clobber/miss it. This fail-closed `validate_baseline_runtime` (rc=1) — the ONLY
stage the bash run failed; every setup stage through `enforce_baseline_runtime`
passed. The Rust engine writes per-node collision-free staging
(`write_secure_temp_file`, RNQ-18) and passed `validate_baseline_runtime` on the
paired topology.

## BASH-DEF-3 — run-matrix mislabels a green bash run as `aborted`

**Run:** `state/pair-bash-1783936989` (the CLEAN 2-node re-run after the
`lab_role` fix). The bash run is GREEN on its own evidence — `run_summary.json`
`overall_status=pass`, `state/stages.tsv` = 22 pass / 31 skip / **0 fail / 0
abort**. Yet its appended `live_lab_run_matrix.csv` row records
`overall_result=aborted`, `linux_exit=aborted`, `linux_client=not_run`,
`linux_anchor=aborted`. The equivalent 2-node **Rust** run
(`green-row-1783931195`) records the accurate `overall_result=partial`,
`linux_exit=pass`, `linux_client=pass`, `linux_anchor=skip`.

**Cause.** The shared run-matrix appender resolves role cells + overall status
by mapping the run's stage names through the stage oracle, which (post-RNQ-16)
derives from the Rust `StageId` vocabulary. The **bash dialect's** stage names
(`live_exit_handoff`, `membership_setup`, …) are not in that vocabulary, so the
appender cannot map the bash run's exit/anchor proof stages to their cells and
degrades them to `aborted`/`not_run`, which then dominates overall → `aborted`.
This is the same dialect-divergence root cause that makes mechanical stage-ID
parity unsatisfiable — surfaced in the role-cell layer. It is NOT a product
abort and NOT a Rust regression (Rust classifies correctly).

**Spec consequence (fixed 2026-07-13).** §0.a G2 originally compared *raw*
matrix role cells across the two rows — unreliable, because the bash row's cells
are dialect-mislabelled. G2 was corrected to derive role-cell outcomes from the
dialect-**normalized** `parity_input.json` (the `emit-parity-input` output both
sides already go through for G1), not from raw matrix cells. The raw bash matrix
row is retained as evidence of BASH-DEF-3, not used as the G2 source of truth.

## TRACKC-FIX-1 — shared registry was missing the bash stage `cross_network_daemon_path`

**Not a bash-script defect — a gap in the SHARED Rust registry, fixed.** The
legacy bash orchestrator emits a terminal stage `cross_network_daemon_path` (a
single warn-level Linux netns daemon-path proof). It was NOT in
`live_lab_stage_registry.rs`. The run-matrix completeness gate
(`live_lab_run_matrix.rs`: "run evidence contains terminal stages outside the
registry") therefore rejected the matrix append for EVERY bash run, and the
finalize forces `overall_status=Fail` whenever the matrix append errors
(`mod.rs:5584` — `overall = Fail if matrix_error.is_some()`, independent of
stage outcomes). So a fully-green bash run (23 pass / 59 skip / **0 fail**,
`run_summary=pass`, `report_state.run_passed=true`) had its
`orchestrate_result.json` `overall_status` forced to `fail`, which
`emit-parity-input` reads → `parity_input.overall=Failed` → the functional diff
reports `overall_status_match=false` against Rust's `Partial`. **This is why the
first pair's G1 failed even though both engines ran green.**

**Fix (2026-07-13):** registered `cross_network_daemon_path` as a bash-dialect
StageSpec (`logical=cross_network`, `AllPlatforms` to satisfy the oracle drift
gate, `Soft` severity — it is warn-level). The registry is the UNION of both
engines' stage vocabularies; a bash-only stage must be registered so the
completeness gate + finalize don't spuriously fail bash runs. 23 registry drift
tests green. A fresh bash run now appends its matrix row and finalizes
`overall` from real outcomes (`Partial`, matching Rust). Note: the finalize's
"matrix-append-error ⇒ Fail" rule is correct fail-closed behaviour for the
PROMOTED (Rust) engine (an evidence-recording failure must block a pass); the
registry gap was the real bug, not that rule.

## Parity implication

The bash `validate_baseline_runtime` failure is NOT a Rust regression — it is
BASH-DEF-1/2, i.e. the legacy path mis-resolving the topology and racing its own
temp file. A pair on this exact invocation cannot reach
`overall_functional_parity_pass=true` (the shared `validate_baseline_runtime`
diverges: bash=fail, rust=pass) — but the divergence is a documented bash defect,
recorded here as evidence FOR retirement, not against the Rust engine.

## "Pair where clean" remediation (config, not bash-code)

`debian-headless-4`'s inventory `lab_role` was the stale/inaccurate `aux`
(it is the client in every Rust run, and debian-headless-2's was the equally
inaccurate `client` while it serves as exit). Correcting `debian-headless-4`
`lab_role` → `client` removes the bash aux-auto-pull, so bash resolves a clean
2-node exit+client topology matching the Rust `--node` run — a legitimate
inventory correction, not a patch to the retiring bash code. The paired
bash↔Rust run is then formed at a single shared commit with a clean tree per
§0.a (G5). BASH-DEF-1/2 remain documented defects of the legacy path.
