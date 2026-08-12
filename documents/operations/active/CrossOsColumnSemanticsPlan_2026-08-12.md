# Cross-OS ledger columns measure the wrong thing — plan — 2026-08-12

> **REVISION 2 — adversarially reviewed; 2 blockers and 3 majors folded in.** The diagnosis
> survived intact, including every lifetime figure and the mechanism (an alternative
> hypothesis — that the 10 passes came from single-platform runs where the two-platform guard
> short-circuited — was tested and **refuted**: all 10 rows are two-platform with a real macOS
> guest, and 9 of them carry `cross_os_peer_visibility = fail` on the *same row*). The remedy
> did not survive. Corrections:
>
> 1. **C3's invariant flags SIX stages, not four** — and the two extras are
>    `validate_macos_mesh_join` and `validate_windows_mesh_join`, both `StageGroup::Bootstrap`,
>    both feeding `cross_os_peer_visibility`, the one column §0 credits as honest. The rule as
>    written would have broken it. **`StageGroup` is not a proxy for "measures a real
>    property"** — that was an unstated assumption and these two are the counter-example. The
>    criterion is the *direction of the proof*: a stage whose success is a host→guest **push**
>    may not feed a guest↔guest column; a stage that validates guest-side state may.
> 2. **C1 DOES break a CI gate; §3's claim that it cannot is false.**
>    `oracle_cross_os_column` (`live_lab_run_matrix.rs:4225`) is a hand-maintained mirror of
>    this mapping, pinned by `registry_matches_historical_rust_native_and_cross_os_and_special`
>    (`:4419`), which runs as a named gate at `scripts/ci/orchestrator_engine_gates.sh:59`. It
>    reads the *registry*, not the ledger — which is why "nothing reads the ledger" was true and
>    irrelevant. **QH-07 hit this exact trap** and its commit warns that editing both sides at
>    once leaves all six equivalence tests green, so the oracle edit must be paired with a
>    spec-side assertion.
> 3. **THREE columns become unfed, not two.** Verified: the 107-value vectors of
>    `cross_os_direct_path`, `cross_os_dns` and `cross_os_membership_convergence` are
>    **byte-identical**. `cross_os_dns`'s "three real validators" are all
>    `state_machine_only: false` — bash-dialect names the `--node` engine never emits — so the
>    push has been the only thing that ever wrote it.
> 4. **Unfed columns are not inert.** `find_untested_work` (`lab_state.rs:2323-2414`) sorts
>    every coverage column into never_run/never_passed/… and emits a *suggested next lab
>    target*, which the autonomous loop consumes. Unfed columns become permanently
>    unsatisfiable targets. The precedent already exists: `cross_os_anchor_enrollment` has zero
>    feeders and reads `not_run` on **107/107** rows.
> 5. **Proposed test 4 already exists** verbatim at `live_lab_stage_registry.rs:2469`, with a
>    sharper rationale (`cross_os` is `traffic_test_matrix`'s only check-qualifying field, so
>    dropping it would silently demote the stage to not-a-check). Dropped.
> 6. **QH-41 is the blocker on the owed validators** — the mac/QEMU vmnet split is a permanent
>    backend property, so no real `cross_os_direct_path` validator can pass in this lab until it
>    is resolved. C2's "marks where a validator is owed" is right but the debt is blocked.

**Status: PLAN (REVISION 2), reviewed.** Written against `HEAD = 56919423`, clean tree. Every number
below was produced by parsing the ledger with `csv.DictReader` or by reading the registry at
that commit.

## 0. The defect, quantified

Three `cross_os_*` columns are fed **only by Bootstrap-group distribution stages** — host→guest
SSH pushes of signed bundles. They report "we pushed a bundle" under names that promise a
dataplane or convergence property. The one column fed by a real reachability validator tells
the opposite story:

| column | lifetime | sole/primary feeder | what the feeder actually proves |
| --- | --- | --- | --- |
| `cross_os_direct_path` | **10 pass** | `distribute_traversal` (Bootstrap) — **only feeder** | a traversal bundle was copied to the guest |
| `cross_os_membership_convergence` | **10 pass** | `membership_init` + `distribute_membership` (Bootstrap) | membership was written to the guest |
| `cross_os_dns` | **10 pass** | `distribute_dns_zone` (Bootstrap) **plus** three real validators | mixed: a push can carry the column green |
| `cross_os_relay_path` | **3 pass** | `deploy_relay_service`, `relay_validation`, the lifecycle validators | the relay service started and bound ports |
| **`cross_os_peer_visibility`** | **0 pass / 9 fail** | `traffic_test_matrix`, `live_mixed_topology`, the mesh-join validators | **actual guest-to-guest reachability** |

So the matrix simultaneously asserts `cross_os_direct_path = pass` ten times and
`cross_os_peer_visibility = fail` nine times — for the same fleet. A reader concludes cross-OS
direct paths work. **They have never worked.**

**Why the pushes pass through a total severance:** the orchestrator host owns *both* vmnet
bridges, so a host→guest SSH push succeeds regardless of whether the guests can reach each
other. `distribute_traversal` therefore cannot fail for the reason its column name implies.

`cross_os_relay_path` is the same shape one step removed: lifecycle stages prove the service
runs, while relay frame forwarding (HP-3) has **never been proven on any OS or engine**.

## 1. This is the third instance of one class

- **QH-07** — `traffic_test_matrix` carried a `logical` alias onto `two_hop`, so 35 rows read
  `two_hop=pass` for a stage with 0 lifetime passes. Fixed by removing the alias at source;
  forward-only.
- **QH-37** — a merged column let one `pass` outrank nine `skip`s. Fixed by precedence.
- **This** — a column's *name* promises a property its *feeder* does not measure.

The first two were fixed at the registry, and that is the precedent to follow: **change what
feeds the column, not how the column is rendered.**

**Nothing guards this today.** `every_registry_stage_column_reference_exists_in_the_csv_schema`
checks a column *exists*; `cross_os_family_stages_are_tiered_t3_cross_os` checks *tiering*.
Neither asks whether a feeder measures what its column claims.

## 2. The change

### C1 — stop distribution stages feeding reachability columns

Remove `cross_os` from the four Bootstrap-group distribution specs:
`distribute_traversal`, `distribute_dns_zone`, `membership_init`, `distribute_membership`.

`cross_os_bootstrap` is **deliberately left alone**: its six feeders are all Pre/Bootstrap
setup stages and its name says exactly that. It is the one honest aggregate here.

### C2 — accept that two columns become unfed, and say so

After C1, `cross_os_direct_path` has **no feeder at all** and
`cross_os_membership_convergence` has none either. That is the correct state: nothing in the
current stage set measures either property.

**Do not delete the columns.** They stay in the schema reading `not_run`, which is now the
truth — "nothing measured this" — and they mark where a real validator is owed. Deleting them
would erase the gap rather than expose it. Record in the register which validator each is
waiting for.

### C3 — a structural guard, on the right axis

**Not** "no Pre/Bootstrap stage may feed a cross-OS column" — that flags the two mesh-join
validators, which legitimately measure a guest-side property.

The invariant is the **direction of the proof**: a stage whose success only demonstrates a
host→guest transfer may not feed a column asserting guest↔guest reachability. Encoded as a
characterization test with an explicit, commented allow-list of the Bootstrap-group stages
permitted to feed a cross-OS column (`validate_macos_mesh_join`, `validate_windows_mesh_join`)
and an assertion that the four distribution stages feed none. A future stage must add itself
to the list consciously.

### C3b — edit the oracle in lockstep, and assert the spec side

`oracle_cross_os_column` (`live_lab_run_matrix.rs:4225`) must lose the same four arms, or
`scripts/ci/orchestrator_engine_gates.sh:59` goes red. Per QH-07's own warning, editing both
sides alone proves nothing — so C3's assertion must read the **registry spec**, not the
oracle.

### C4 — `cross_os_relay_path` is a DECISION, not obviously a fix

Its feeders prove lifecycle, not forwarding. Renaming it (`..._service_lifecycle`) or
unfeeding it are both defensible, and both are schema-visible. **This plan does not take that
decision** — it is a judgement about what the column is *for*, and the evidence (HP-3 never
proven) argues the name oversells while the lifecycle signal is still genuinely useful.
Flagged for the operator.

## 3. Blast radius

- **Forward-only**, exactly as QH-07 and QH-37 were. The 10 historical `pass` values in each
  affected column stay wrong and must not be read as evidence. Record that boundary.
- **Future runs report `not_run`** on those columns instead of `pass`. That is a *reduction* in
  apparent coverage and an *increase* in accuracy. Say so plainly rather than letting it look
  like a regression.
- **No stage stops running.** The distribution stages keep their own `logical` columns; only
  the cross-OS roll-up mapping is removed.
- **Nothing gates on these columns today** — no CI step reads the ledger — so the change
  cannot break a gate. It changes what a human or tool concludes.

## 4. Tests, each with the mutation that proves it discriminates

1. No Pre/Bootstrap stage declares a non-`cross_os_bootstrap` mapping. *Mutation:* restore
   `cross_os: Some("cross_os_direct_path")` on `distribute_traversal` → fails.
2. `cross_os_bootstrap` still has its six Pre/Bootstrap feeders. *Mutation:* also strip them →
   fails. Pins the deliberate exception so a blunter rule cannot be substituted.
3. `cross_os_direct_path` and `cross_os_membership_convergence` remain in the schema with zero
   feeders. *Mutation:* delete either column → the existing schema test fails; *mutation:*
   re-feed either → test 1 fails.
4. `cross_os_peer_visibility` keeps its reachability feeders. *Mutation:* remove
   `traffic_test_matrix`'s mapping → fails. Guards the one column that works.

## 5. Definition of done

All §7 gates green; every test mutation-proven; a register entry recording the forward-only
boundary and which validator each unfed column awaits; and §0's table reproducible with
`csv.DictReader`.
