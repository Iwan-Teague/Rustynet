# Live-Lab Stage Pass-Likelihood — Linux (2026-09-01)

Docs-only analysis of the Linux live-lab stages that appear to have never genuinely
passed on the Rust `--node` engine (the engine of record). Written from the evidence
ledger, the stage registry, and the run-matrix schema while the lab is DOWN; no live
run was launched and no stage is claimed to pass based on anything recorded here.
Every verdict below is grounded in (a) the stage's own recorded status in the
`--node` evidence ledger, (b) the stage registry that defines what each stage is and
when it is scheduled, or (c) the schema tests that pin which stage populates which
CSV column.

## Method and evidence sources

- **Evidence ledger:** `documents/operations/live_lab_node_run_matrix.csv` — the live
  Rust `--node` engine ledger (242 rows, parsed with a quote-aware CSV reader per
  QH-07). The frozen bash archive `live_lab_run_matrix.csv` is NEVER used as evidence
  here; its 52 `two_hop` passes are legacy-bash results the `--node` engine never
  achieved (documented in `live_lab_run_matrix.rs:425-452`).
- **Stage definitions:** `crates/rustynet-cli/src/live_lab_stage_registry.rs` (which
  stages exist, their logical/cross-OS/special column mappings, and their enable
  rules) and the `StageId` enum in
  `crates/rustynet-cli/src/vm_lab/orchestrator/stage/mod.rs` (which stages the Rust
  state machine can actually dispatch).
- **Column schema:** `crates/rustynet-cli/src/live_lab_run_matrix.rs`
  (`DEFAULT_MATRIX_COLUMNS`, lines 49-230+) and its mapping tests (lines 3261-3360,
  4764-4867) that pin the stage→column relationships.
- **Access limitation, stated honestly:** the one recorded
  `blind_exit_dataplane_check` failure's report directory
  (`state/mesh-shared-verify4-1783795905`, run `livelab-1783796395-696b8c5293c2`)
  sits outside this analysis worktree and could not be read from here; that stage's
  per-check artifacts are cited by ledger row and `failure_digest.json` path only.
- **Predecessor analyses:** QH-07 in
  `documents/operations/active/QualityHardeningTodo_2026-07-25.md` (entry at line
  535), its re-verification in
  `documents/operations/active/RepoStateAssessmentAndNextSteps_2026-08-19.md` (line
  63), and `documents/operations/active/BashRetirementDispositions_2026-08-22.md`
  (line 174: verdicts come from per-stage report artifacts, never from an aliased
  roll-up column).

## Headline

Of the Linux stage cells that look never-passed, **most are not code defects and not
even Linux failures**:

1. **`linux_stage_two_hop` is NOT never-passed — it is genuinely green today.** The
   famous contamination (QH-07) masked this. After the 2026-07-27 alias removal, 26
   of the ledger's 148 post-removal rows record `linux_stage_two_hop = pass`
   (26 pass / 8 fail / 86 skip / 28 not_run), including both 2026-08-16 Run-44 rows
   (`livelab-1786904758-2b205ca6d49c`, `livelab-1786908269-5510b726035e`) from the
   first zero-failure full Linux suite. The never-passed residue is a *different*
   stage id that shares the same roll-up column: the cross-OS wrapper
   `live_two_hop_validation`, whose lifetime per-stage record is 0 passes.
2. **`mixed_topology` is topology-gated by design, not broken.** Both of its stage
   ids hard-require all three OSes live; a Linux-only run can never satisfy it.
3. **The chaos suite is an opt-in selector that no recorded run has ever selected**
   (242/242 rows `not_run`). The stages and the selector exist; there is simply zero
   recorded evidence.
4. **`blind_exit_dataplane_check` has exactly one recorded attempt** (2026-07-11,
   fail) plus universal skip/not_run; its report artifacts are outside this
   worktree's readable scope, so its one failure is cited but not root-caused here.
5. **The 8 "dead legacy bash columns" suspicion is REFUTED.** All 8 bare
   `linux_*` columns belong to the *current* `--node` schema. None of them is a
   bash-dialect relic. Seven are duplicate/superseded evidence columns whose only
   registered producers (`validate_linux_*` registry entries) have no `StageId`
   variant and are therefore unreachable under the only engine — the live proof
   they nominally represent already runs under Rust-native stage ids that write the
   `linux_stage_*_check` columns, which do pass. One (`linux_relay_forwards_frame`)
   belongs to a real, opt-in Disruptive-tier stage that no recorded run has
   scheduled.

Zero of the findings below is a proven CODE-DEFECT blocker. The genuine gap class
for Linux today is **scheduling/gating**: stages that exist, have runners and schema
columns, but which the recorded runs never dispatched.

## Per-stage analysis

### 1. `linux_stage_two_hop` — genuinely passing via `live_two_hop` (pass likelihood: HIGH; not in the never-passed bucket)

**Status + citation.** Ledger, post-removal rows only (148 rows after 2026-07-27):
`pass 26 / fail 8 / skip 86 / not_run 28`. Lifetime pre-removal passes (35 of 94
rows at commit `9cdd660f`) are the QH-07 contamination and are permanently
disregarded.

**Why it is green.** Two distinct stage ids map to the logical column `two_hop`
(`live_lab_stage_registry.rs`):

- `live_two_hop` (line ~1943): `logical = Some("two_hop")`, enable
  `EnableRule::LinuxLiveSuite`, part of the standard Linux live suite block
  (neighbours `live_relay`, `live_exit_handoff`, `live_lan_toggle`,
  `live_role_switch_matrix`). This is the chained-exit proof every full Linux suite
  run dispatches, and it is the producer of the 26 post-removal pass rows —
  including both Run-44 (2026-08-16) rows where the whole Linux suite went green.
- `live_two_hop_validation` (line ~921): `state_machine_only = true`,
  `logical = Some("two_hop")`, `PlatformRule::AllPlatforms`; the comment at line
  ~916 describes it as "Rust-native live two-hop: delegates to the proven
  `live_linux_two_hop_test` binary (cross-OS via `--platform`)". This wrapper's own
  lifetime per-stage record, counted in the QH-07 comment block
  (`live_lab_run_matrix.rs:443-452`, data from `live_lab_node_stage_results.csv` at
  commit `9cdd660f`), is **222 skip / 81 fail / 0 pass**.

**Classification.** `live_two_hop`: green, done. `live_two_hop_validation`:
CONTAMINATION-adjacent WIRING/GATE residue — a cross-OS acceptance wrapper that
inherits the roll-up column's good name while never having passed itself. The
migration risk is exactly the one QH-07 warned about, now narrowed to a single
stage id: a reader of the `two_hop` column cannot tell which producer wrote a pass.
QH-07(b) (synonym table) and QH-07(c) (schema migration) remain the tracked fix.

**Pass likelihood.** For Linux `two_hop` as a capability: **High** (already
proven, repeatedly, post-removal). For `live_two_hop_validation` as a stage id:
**Low today** — it is a cross-OS cell, and the macOS/Windows role cells are
themselves ~0% proven on this engine per
`CrossPlatformRoleParityRefresh_2026-07-23.md`. It greens automatically once a
3-OS mesh run is achieved; no Linux-side work is owed.

**Caveat, stated honestly.** The lab being down, the 26 post-removal passes are
attributed to `live_two_hop` by scheduling logic (it is the only one of the two ids
in the standard LinuxLiveSuite plan) rather than by reading each run's stage-log
file names. Per `BashRetirementDispositions_2026-08-22.md:174`, a per-run pin-down
would read each run's own stage artifacts; that remains possible on the next lab-up
day and should confirm the attribution, but the scheduling argument plus Run-44's
full-suite green makes the conclusion robust.

### 2. `linux_stage_mixed_topology` — topology-gated by design (pass likelihood: LOW)

**Status + citation.** Ledger lifetime: `skip 205 / not_run 37`, **0 pass, 0 fail**
in 242 rows. Post-removal: `skip 120 / not_run 28`.

**What it is.** Two stage ids share logical `mixed_topology`:

- `live_mixed_topology_validation` (registry line ~2030): `state_machine_only`,
  `PlatformRule::AllPlatforms`, tier T3CrossOs
  (`stage/mod.rs` line 256). The anti-drift gate at
  `live_lab_stage_registry.rs:3075-3092` states it plainly:
  `live_mixed_topology_validation` "**hard-requires Linux+macOS+Windows**" and
  carries the cross-OS acceptance bar — re-tiering it away would silently empty the
  T3CrossOs tier.
- `live_mixed_topology` (line ~2038): `cross_os = Some("cross_os_peer_visibility")`,
  `EnableRule::LinuxLiveSuite`, AllPlatforms — the one-node-per-OS mutual
  visibility + datapath freshness test.

**Classification.** GATING/BY-DESIGN (not a defect). A Linux-only topology cannot
satisfy a hard all-3-OS requirement; the 0-pass record is the honest reading of a
cell that has never had its precondition met.

**Pass likelihood: Low.** Blocked on macOS and Windows nodes reaching live,
mesh-joined, evidence-producing state — the entire cross-platform parity program
(`CrossPlatformRoleParityPlan_2026-06-21.md` mandate, current status in
`CrossPlatformRoleParityRefresh_2026-07-23.md`). No Linux-side change helps.

**Improvement (sized: process, not code).** When the lab returns and any 3-OS
topology run is attempted, mixed_topology is already in the plan — nothing to wire.
The cheapest first proof is a 3-node run with the two desktop nodes in *any* role;
the stage does not require specific roles, only three live OSes.

### 3. `linux_stage_blind_exit_dataplane_check` — one recorded attempt, rest skip (pass likelihood: MEDIUM-LOW)

**Status + citation.** Ledger lifetime: `skip 204 / not_run 37 / fail 1`, **0
pass**. Post-removal: `skip 120 / not_run 28`. The single fail is run
`livelab-1783796395-696b8c5293c2` (started 2026-07-11T18:52:29Z, commit
`696b8c5293c2…`, branch main, dirty:recorded, 2-node topology
debian-headless-2 + debian-headless-4, profile `mgmt_shared_smoke_v1`,
`first_failed_stage=blind_exit_dataplane_validation`, passed=29 failed=1
skipped=28); its report dir is `state/mesh-shared-verify4-1783795905`
(`failure_digest.json` + evidence bundle), which is outside this worktree's
readable scope — cited, not root-caused, here.

**What it is.** Stage `blind_exit_dataplane_validation` (registry line ~909):
`state_machine_only`, group Live, logical `blind_exit_dataplane_check`,
AllPlatforms; five hardened subchecks — ruleset captured, mesh-scoped forward, no
NAT, no unrestricted forward, no own-egress. The node-side validator
`validate_linux_blind_exit_dataplane` also exists in the registry's Linux stream
(first_failed_stage extras list at `live_lab_stage_registry.rs:2678` knows
`debian-headless-4::validate_linux_blind_exit_dataplane`).

**Classification.** MIXED — most likely WIRING/GATE for the skips (the stage is
`state_machine_only`: it only dispatches when the plan elects a blind-exit node,
and on the one recorded attempt the same row shows `linux_stage_blind_exit = skip`,
i.e. the blind-exit role was not fully elected in that 2-node topology) with a
possible real CODE-DEFECT component in the single failure that cannot be excluded
without the run's artifacts.

**Pass likelihood: Medium-Low.** The subcheck machinery exists and is schema-pinned;
but there is zero positive evidence ever recorded, and the one negative datum (a
fail on a 2-node topology where the role election itself skipped) is unresolved.

**Improvement (sized: S — one focused lab run, no expected code change).** On the
next lab-up window, run a focused Linux cell with the blind-exit role explicitly
elected (the inventory's blind-exit-capable node is debian-headless-4) and capture
`blind_exit_dataplane_validation`'s five subcheck artifacts. If the 2026-07-11
failure reproduces, its per-check artifact turns the open question into a
concrete defect; if it passes, the cell greens in one run. Either outcome resolves
the oldest genuine unknown in this bucket.

### 4. Chaos suite — opt-in selector, never once selected (pass likelihood: MEDIUM for first evidence, with caveats)

**Status + citation.** All chaos roll-up rows: `not_run 242/242`. The registry
defines `StageGroup::Chaos`, a `chaos_suite: bool` selector, and
`EnableRule::ChaosSuite` (skip reason "chaos suite not selected"); the nine chaos
stage ids are `chaos_clock_attack`, `chaos_crash_recovery`, `chaos_daemon_fault`,
`chaos_daemon_sigstop_sigcont`, `chaos_membership_adversarial`,
`chaos_network_impairment`, `chaos_privileged_boundary`,
`chaos_resource_exhaustion`, `chaos_signed_state_adversarial` (all logical
`chaos`). An additional opt-in control suite ("Opt-in (like chaos)") exists after
registry line ~2166. Stage implementations live under
`crates/rustynet-cli/src/vm_lab/orchestrator/stage/chaos.rs` and the prefix
fallback mapping (`chaos_*` → chaos, registry lines ~2441-2512).

**Classification.** WIRING/GATE (scheduling): the machinery exists end-to-end —
stages, selector, enable rule, dispatch mapping — but no recorded run has ever
turned the selector on. This is the largest *cheaply obtainable* evidence gap in
the Linux bucket: not_run is not pass, and right now the chaos suite has literally
no live verdict of any kind.

**Pass likelihood: Medium**, with an honesty caveat: likelihood here means "the
single flag flip plus a lab window is the only thing between us and a first
verdict"; it is NOT a prediction that nine adversarial stages will all pass
first try. Failures, if they come, are by design the suite working.

**Improvement (sized: S — one focused run; M if first failures need triage).**
Select the chaos suite on the next full Linux suite run (the selector already
exists; no code change expected). Budget triage time for first-contact findings —
adversarial suites earn their keep by failing things.

## The "dead legacy columns" — suspicion refuted, mapping pinned

The working hypothesis entering this analysis was that the eight columns

`linux_runtime_acls`, `linux_service_hardening`, `linux_authenticode`,
`linux_key_custody`, `linux_membership_genesis`, `linux_mesh_status`,
`linux_hello_limiter_flood`, `linux_relay_forwards_frame`

(all `not_run: 242/242` in the ledger) were bash-dialect columns the `--node`
engine never populates. **The code refutes this.** All eight are in the *current*
`--node` schema (`DEFAULT_MATRIX_COLUMNS`, `live_lab_run_matrix.rs:219-229`), and
mapping tests pin each one to a registered producer stage
(`daemon_security_validator_stages_map_to_dedicated_csv_columns` at
`live_lab_run_matrix.rs:3261-3299`; `oracle_special_column` at 4839-4867).
The correct classification is subtler: seven of the eight have producers that are
**registry entries without a `StageId` variant** — the Rust state machine
(`StageId::ALL`, `stage/mod.rs`) has no `validate_linux_*` variants, so those
producer names can never enter a plan and the columns can never be written. The
live proof those validators represent instead runs under Rust-native stage ids
that write the separate `linux_stage_*_check` columns (lines 153-166 of the
schema; oracle mapping at `live_lab_run_matrix.rs:4767-4771`), and those columns
DO record passes in real `--node` runs (e.g. every subcheck column reads `pass` on
the 2026-07-11 blind-exit row).

| Bare column (not_run 242/242) | Registered producer (no StageId → unreachable) | Rust-native stage that runs today | Column the live proof writes | Classification |
| --- | --- | --- | --- | --- |
| `linux_runtime_acls` | `validate_linux_runtime_acls` (registry ~1809) | `runtime_acls_validation` (StageId, Live/T4Security) | `linux_stage_runtime_acls_check` | dead-by-supersession (duplicate evidence column) |
| `linux_service_hardening` | `validate_linux_service_hardening` (~1818) | `service_hardening_validation` | `linux_stage_service_hardening_check` | dead-by-supersession |
| `linux_authenticode` | `validate_linux_authenticode` (~1827) | `authenticode_validation` | `linux_stage_authenticode_check` | dead-by-supersession |
| `linux_key_custody` | `validate_linux_key_custody` (~1836) | `key_custody_validation` | `linux_stage_key_custody_check` | dead-by-supersession |
| `linux_mesh_status` | `validate_linux_mesh_status` (~1856) | `mesh_status_validation` (Live/T0Core) | `linux_stage_mesh_status_check` | dead-by-supersession |
| `linux_membership_genesis` | `validate_linux_membership_genesis` (~1845) | genesis/membership proof runs under other ids (membership_init etc.) | n/a (no direct twin) | dead-by-supersession (no exact twin; nearest live coverage under different ids) |
| `linux_hello_limiter_flood` | `validate_linux_hello_limiter_flood` (~1893) | `live_hello_limiter_flood_validation` (StageId, Live/T4Security) | `linux_stage_hello_limiter_flood` (skip on recorded rows; stage exists, rarely elected) | dead-by-supersession (duplicate of the same-named special) |
| `linux_relay_forwards_frame` | `validate_linux_relay_forwards_frame` (~1900) + `relay_forwards_frame_validation` (StageId, **Disruptive**/T1Role, registry `stage/mod.rs` line 266) | exists, but Disruptive tier = opt-in; never scheduled in recorded runs | same column, per HP-3 (`live_lab_run_matrix.rs:4865-4867`: the `--node` engine's disruptive opt-in stage folds into the same evidence column) | genuinely-never-run opt-in stage (NOT dead) |

**Implication for the doc-consumer:** never report these eight as "Linux stages
that fail to pass" — they record no verdicts at all, and for seven of them the
underlying security property is already being proven (green) one column over.
**Improvement (sized: S–M, docs+schema only):** this is exactly QH-07(b)/(c)
territory — the synonym table and schema migration already tracked in
`QualityHardeningTodo_2026-07-25.md`. The cleanest end state removes the seven
duplicate columns and keeps one column family per property (the
`linux_stage_*_check` family that actually fills), so no future reader re-derives
this mapping. `linux_relay_forwards_frame` stays: its producer is real and
opt-in.

## Ranked quickest-to-green

1. **`two_hop` on Linux — already green.** No action; the only owed work is the
   per-run attribution double-check on the next lab-up day (read stage-log names
   in the Run-44 report artifacts) and finishing QH-07(b)/(c) so the column
   unambiguously names its producer.
2. **Chaos suite — cheapest NEW evidence.** One selector flip on a scheduled run;
   all nine stages have implementations. First verdict of any kind in a single lab
   window. Expect first-contact failures; that is the suite succeeding.
3. **`blind_exit_dataplane_check` — one focused run.** Elect the blind-exit role
   explicitly, capture the five subcheck artifacts, resolve the 2026-07-11
   unknown. No expected code change; S if it passes, M triage if it fails.
4. **`linux_relay_forwards_frame` — schedule the Disruptive stage once** when a
   lab window has slack. Opt-in by design; one run records the first verdict in
   the column.
5. **`live_two_hop_validation` / `mixed_topology` — blocked on cross-OS parity,
   correctly.** Both hard-require macOS+Windows live nodes. They are not Linux
   work; they green as a by-product of the mac/win role cells reaching live
   parity (`CrossPlatformRoleParityRefresh_2026-07-23.md`). Do not spend Linux
   lab time on them.
6. **The seven duplicate bare columns — schema migration (QH-07(b)/(c)), not lab
   work.** Any lab time spent "making them pass" is wasted; the properties are
   already proven in the `linux_stage_*_check` family.

## What this analysis does not claim

- No stage is claimed to pass based on this document; the lab was down throughout.
- The `live_two_hop` attribution for the 26 post-removal passes rests on plan
  membership plus Run-44's full-suite green, not on per-run artifact reads; that
  pin-down is a listed follow-up.
- The single `blind_exit_dataplane_check` failure is cited from its ledger row and
  report path only; its root cause is explicitly unresolved here.
- Chaos-suite implementation quality is unassessed (no live evidence exists to
  assess it against); only its wiring and schedulability are claimed.
