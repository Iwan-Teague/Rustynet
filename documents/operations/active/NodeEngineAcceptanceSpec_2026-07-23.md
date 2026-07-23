# `--node` Engine Acceptance Spec (Track B) — 2026-07-23

**Status:** **SIGNED OFF 2026-07-23** (owner approved draft 2; §10 checkboxes
all approved). Track B deliverable from
`RustNodeOrchestratorCompletionBrief_2026-07-12.md`. Adversarially reviewed
2026-07-23 (findings B1–B6 / S1–S5 folded in; changelog §11). This bar now
governs: **G1 → the W5.6 lab-default flip; G2 → release; G3 → W5.7 bash deletion.**

Written as a **`--node`-native acceptance bar**, not a bash↔Rust parity gate.
Once signed, it is a **living document** — the permanent acceptance/regression bar
the engine is held to for the life of the project.

---

## 0. The decision this records (native-spec, not bash-parity)

- **Strict (bash-parity)** — correct = *reproduces what bash did.* Rejected as the
  standing gate: bash is being **deleted** (W5.7), so a parity gate expires with
  its reference, makes bash's quirks the spec, and is already mechanically
  unsatisfiable (divergent stage vocabularies; the ledgers disagree — bash claims
  52 `two_hop` passes `--node` never produced).
- **Pragmatic (native spec)** — correct = *meets this independently-authored bar.*
  **Chosen.** The bar survives bash, encodes what *should* be true, and grows with
  the project.
- Strict is demoted to a **one-time migration safety net** (§8): a single
  differential sweep against bash *before bash is deleted*. It is a checklist run
  once, never a standing gate.

## 1. THREE gates — do not conflate (revised per review B6)

The original draft fused "trust the engine" with "the product is done." They are
separate. There are three gates:

| # | Gate | Question | Reference | Governs |
|---|---|---|---|---|
| **G1** | **Engine-adjudication trust** | Does `--node` correctly report BOTH pass *and* fail — i.e. can it be believed? | This spec §5 (adjudication bar) | The lab **default flip** (W5.6) |
| **G2** | **Parity attainment** | Are all in-scope role×OS cells actually GREEN? | This spec §6 (attainment bar) | Product **release** (the parity mandate) |
| **G3** | **Bash-retirement** | Is it safe to *delete* bash? | One-time differential sweep vs bash (§8) | Bash **deletion** (W5.7) |

The critical reframe: **G1 does not wait on G2.** An engine that correctly reports
a real product gap RED is *doing its job* — it should be trusted (and made default)
on that basis, not blocked until the product is finished. Chaining the flip to the
months-long parity program would keep the *worse* (bash) engine the default the
longest. Release waits on G2; the lab default does not.

## 2. Definitions

- **Cell** = (role, OS). Roles: `client`, `admin`, `anchor`, `exit`,
  `blind_exit`, `relay` (+ `nas`, `llm` when they land). OSes: Linux, macOS,
  Windows.
- **Stage** = a `StageId` from the authoritative registry
  (`crates/rustynet-cli/src/live_lab_stage_registry.rs`, `StageId::ALL`) — the
  single source of the stage vocabulary.
- **GREEN** = terminal status is **exactly `Pass`** (by reference to the registry
  status enum: `Pending/Running/Pass/Fail/Skipped/NotRun/Reused/NotApplicable/
  TimedOut/Aborted`). Every non-`Pass` value — including `Reused`, `Skipped`,
  `NotApplicable`, `TimedOut`, `Aborted` — is **not** GREEN. *(Revised per S4: the
  earlier draft excluded a status that does not exist and left three real ones
  unclassified.)*
- **RED-for-the-right-reason** = a stage that should fail terminates `Fail` (or
  `TimedOut`/`Aborted` where that is the correct outcome) **on the specific stage
  the fault targets**, not merely "the run wasn't green."
- **Valid run** = a run satisfying every §4 evidence property, **as recomputed by
  the independent verifier (§4.8)**, not as self-reported by `--node`.

## 3. Stage tiers (which stages a cell must exercise, by scope)

The `StageId → tier` mapping is **machine-readable and owned by the registry
crate** (**built 2026-07-23 / increment A1**: a required `Tier` field on every
`define_stage_catalog!` row, so a missing tier is a **compile error** — totality is
enforced by construction, strictly stronger than a runtime gate; pinned by
`every_stage_id_has_a_reachable_tier`). The map, not this prose, is authoritative;
the descriptions below are illustrative. *(The earlier draft's B4 note about
"omitted `cross_os_*` stages" was itself corrected by A1 — see T3.)* Tiers:

- **T0 — Core (every cell):** bootstrap, baseline-runtime enforce+validate, signed
  membership/trust/traversal/dns distribution, traffic reachability, clean teardown
  (residue-asserted).
- **T1 — Role (the cell's own capability), live:** anchor→validation+bundle-pull+
  enrollment; exit→NAT+handoff+dns-failclosed+demotion-residue; relay→service-
  lifecycle+frame-forward; blind_exit→dataplane+irreversibility; admin→mint/issue
  signed bundle; client→managed-tunnel+two-hop.
- **T2 — Resilience (per OS):** reboot_recovery, network_flap, extended_soak, chaos.
- **T3 — Cross-OS:** the `--node` cross-OS stage — `live_mixed_topology_validation`
  (requires Linux + macOS + Windows all present; proves shared signed membership +
  fresh cross-OS handshakes). **Drift correction (A1):** the `cross_os_*` names in
  the run-matrix CSV (`cross_os_bootstrap`…`cross_os_lan_toggle`) are **bash-dialect
  aggregate columns, NOT `--node` StageIds** — the `--node` engine carries cross-OS
  via mixed-topology, a deliberate dialect difference. Do **not** force bash's
  `cross_os_*` vocabulary onto `--node` (this is exactly the direction-diagnosis
  rule, §8: a bash↔node difference is a question, and here `--node`'s own vocabulary
  is correct). The T3 tier is armed for any future `cross_os_*`-prefixed `--node`
  stage but is carried today solely by `live_mixed_topology_validation`.
- **T4 — Security / adversarial:** the security-stage family (ipv6_leak,
  dns_failclosed, killswitch, privileged-helper allowlist, revocation,
  security_audit, …) as tagged in the map.
- **T5 — Negative controls / ADJUDICATION (new, per review B1):** injected-fault
  runs that MUST produce RED-for-the-right-reason. This tier is what proves the
  engine can be believed. Minimum set, per §5:
  - planted killswitch/NAT/interface residue → the cleanup/residue stage must FAIL;
  - corrupted / stale / wrong-signer signed bundle → the distribute/verify stage
    must FAIL (fail-closed);
  - daemon (or relay) killed mid-stage → that stage must NOT report pass;
  - wrong-node substitution → the role validator must FAIL (see §4.7 challenge).

## 4. Evidence properties — what makes a run VALID

A `Pass` counts toward any bar only when the run also satisfies **all** of the
following, **as recomputed by the independent verifier (§4.8)** from the raw report
artifacts — never as self-reported by the engine under evaluation:

1. Run-scoped **stage manifest** emitted; **every planned stage has a terminal
   status** (no silent evaporation).
2. **Terminal-state taxonomy** honored — failure dominates; `Reused`/`NotRun`/
   `TimedOut`/`Aborted` never read as pass.
3. **Cleanup GREEN** — `assert_node_clean` confirms no residue. Proven detective
   by the T5 residue injection, not merely asserted.
4. **No fail-open** on any trust/security path. Proven by the T5 fault injections,
   not merely asserted (a fail-open *looks* green — §4 alone cannot see it).
5. **Run-matrix row** appended to `live_lab_node_run_matrix.csv`, and the row is
   **digest-bound** to its manifest + report_dir (§4.8) so a column-shift in the
   ~260-column positional CSV, or a swapped row, is detected *(S3)*.
6. **Marker-last finalizer** honored (crash before the commit marker ⇒ non-passed).
7. **Node identity ASSERTED, not just recorded** *(revised per S2)* — the validator
   proves it exercised the intended node via an expected-node-id challenge in the
   probe itself; a name logged post-hoc is insufficient (the historical MeshStatus
   false-green was exactly a right-name/wrong-exercise pass).

### 4.8 Independent verification (new, per review B2)

Every property in §4 is otherwise **self-attested by the engine being judged** — a
rubber-stamping engine emits perfect evidence by construction, and the CSV is an
unsigned, hand-editable file. Therefore a **separate verifier binary/gate** (not
part of the orchestrator's own pass/fail path) recomputes §4.1/4.2/4.5/4.6 from the
raw report_dir artifacts, cross-checks `manifest ↔ CSV row ↔ report_dir` by digest,
and is the authority on "valid run." The orchestrator's self-report is advisory
only. Bar-counting runs must also **archive their evidence bundle** — `report_dir`
lives under gitignored `state/` and can otherwise vanish while its "permanent" row
stands *(S3)*.

## 5. G1 — the engine-adjudication trust bar (gates the default flip, W5.6)

`--node` is **TRUSTED** (eligible for the W5.6 default flip) when, on the cells
that exist today (not the full parity set):

1. **Positive:** T0 + T1 GREEN under valid runs (§4), on real guests.
2. **Negative (the new, load-bearing half):** the **T5** injected-fault suite
   produces RED-for-the-right-reason for every fault class in §3-T5. *An engine
   that cannot be made to fail correctly is not trusted, regardless of how many
   greens it shows.*
3. **Independently verified:** every counted run passes the §4.8 verifier, not the
   engine's self-report.
4. **Stable (revised per review B5 — the old "two consecutive" was arithmetically
   refuted):** greens are counted over an **N-of-N window sized by flake history**
   — default 3-of-3, and **5-of-5 for any stage with a recorded flake** (a 1-in-4
   flake survives 2-in-a-row 56% of the time; 5-of-5 drives that to ~24%, and any
   red inside the window **requires a root-caused disposition before the counter
   resets** — no "rerun until two line up" stopping-rule exploit). Both/all greens
   must be at the **same clean commit that is the flip candidate** (the ledger's
   recent rows are `dirty:worktree` — two greens at two uncommitted states do not
   count).

G1 concerns whether the engine can be *believed*. It deliberately does **not**
require macOS/Windows parity attainment (that is G2).

## 6. G2 — parity attainment (gates release, not the flip)

Release requires every **in-scope** cell GREEN (or dispositioned per §6.1):

- **In scope:** Linux + macOS + Windows, all roles — the release-blocking mandate
  (`CrossPlatformRoleParityPlan_2026-06-21.md` §3).
- **`network_flap` (revised per B6):** for **G1** it must be **correctly
  adjudicated** — RED-for-the-right-reason with the right digest — until the daemon
  traversal-self-sustenance fix (`TraversalSelfSustenancePlan_2026-07-23.md`) lands;
  then GREEN for **G2**. This removes the perverse incentive to *weaken the flap
  validator* to unblock the flip — the exact corruption this spec exists to
  prevent.

### 6.1 Dispositions (revised per review B3 — the escape hatch is fenced)

A red cell may be dispositioned out-of-scope only under all of:
- recorded in a **named disposition ledger** (not free-text in a run);
- **owner sign-off per disposition**, with a stated reason;
- an **expiry / re-review date** (no permanent silent exemptions);
- **T4 (security) is NOT dispositionable below owner level** — no loop operator may
  exempt a security cell.
- **Deferrals take effect only when mirrored into this spec's list** *(S5)* — a
  pointer to "whatever the roadmap parks" must not silently shrink this bar from
  another document.

Deferred-with-reason today: `nas`/`llm` (separate program); roadmap-parked cells
(relay frame-forward HP-3, Windows-exit pending WinNAT, Windows `blind_exit`) —
each mirrored here so a red cell is a *known* deferral, never an unexplained gap.

## 7. (reserved)

## 8. G3 — bash-retirement differential sweep (one-time; gates deletion only)

Before **deleting** bash: run `vm-lab-diff-orchestrator-parity`; for every stage
bash proved GREEN that `--node` has not, either (a) prove it on `--node`, or
(b) record an **owner-signed** disposition. *(Revised per S1:)* the **enumeration
half runs at W5.6 as a flip precondition** (diff only, no lab time — it is the sole
detector of silently-dropped coverage, so it cannot wait until after the flip); the
full sweep + signed dispositions gate W5.7; and the **diff output is archived as an
artifact even after the harness is deleted.** This is a one-time checklist, never a
standing gate.

**Diagnose the DIRECTION of every diff — bash is not the oracle.** `--node` has
been in heavy use and diverges from bash *on purpose* in places. A bash↔`--node`
difference is a question, not a verdict: `--node` may be the *correction* — a
vulnerability bash rubber-stamped, an OS-specific case bash mishandled, a
fail-closed path bash left fail-open, a stage bash never had. **A bash `pass` is not
proof of correctness** (this repo has real bash false-greens). So for each diff,
first determine which engine is right; only a genuine `--node` coverage *drop* is a
`--node` gap to fix (option a). When `--node` is the correction, the disposition is
**"node supersedes bash" with the recorded reason** (the OS case, the vuln, the
closed fail-open) — option (b). **Never silently make `--node` match bash to close a
diff** — that would re-introduce exactly the legacy defect the divergence fixed.

## 9. Living-document discipline + the totality gate

- The `StageId → tier` map is **machine-readable in the registry crate**; a CI gate
  fails when any `StageId::ALL` member is unmapped (B4) and when the T5 fault
  classes have no corresponding negative-control stage. This spec references the
  map; it never hand-copies the stage list.
- New role/OS/stage → add its cell + map entry; the gate enforces totality.
- The spec states the *bar*; the run-matrix rows + the §4.8 verifier state
  *attainment*. Do not record attainment by editing prose here.

## 10. Owner sign-off — APPROVED 2026-07-23

- [x] Approved: the **three-gate model** (§1) — engine-adjudication trust (G1)
  gates the default flip **independently of** parity attainment (G2), which gates
  release.
- [x] Approved: making **adjudication (T5 negative controls + §4.8 independent
  verifier)** a hard part of the trust bar — the engine must be provably able to
  report RED correctly, not just show greens.
- [x] Approved: the **N-of-N flake-sized stability rule at a clean flip-candidate
  commit** (§5.4), replacing "two consecutive."
- [x] Approved: the **fenced disposition process** (§6.1) — named ledger, per-item
  owner sign-off, expiry, T4 not dispositionable, deferrals only via mirror.
- [x] Approved: the **§6 scope** and the `network_flap` correctly-adjudicated-then-
  green treatment (§6 / B6).

Once signed: G1 governs W5.6 (default flip); G2 governs release; G3 governs W5.7
(bash deletion).

## 11. Changelog

- **2026-07-23 draft 1** — initial native-spec bar.
- **2026-07-23 — increment A1 landed + drift correction.** The machine-readable
  `StageId → tier` map is built (compile-time totality, 66 stages classified, 3
  pinning tests; merged `83c60aa`→`d2feee5`). Building it surfaced and corrected a
  drift the prose had inherited from bash: `cross_os_*` are **bash-dialect CSV
  aggregate columns, not `--node` StageIds** — `--node`'s cross-OS carrier is
  `live_mixed_topology_validation` (§3-T3 rewritten; the direction-diagnosis rule
  applied — `--node`'s own vocabulary kept, not forced to match bash).
- **2026-07-23 draft 2** — adversarial review folded in: added the
  adjudication dimension (T5 negative-control tier §3, independent verifier §4.8) so
  the bar tests that the engine can correctly *fail*, not only pass (B1/B2); split
  engine-trust from parity attainment into three gates so the flip is not hostage to
  the product/parity program (B6); machine-readable total `StageId→tier` map + gate,
  and recorded that the prose list had already drifted (B4); fenced the disposition
  escape hatch (B3); replaced "two consecutive" with flake-sized N-of-N at a clean
  commit (B5); GREEN = exactly `Pass` by enum reference (S4); identity asserted not
  recorded (S2); digest-bound row↔manifest + archived evidence (S3); sweep
  enumeration as a flip precondition + signed dispositions + kept artifact (S1);
  deferrals only via mirror (S5). Confirmed-sound and kept: two/three-gate
  separation, `reused`/`skip` excluded from GREEN, marker-last + cleanup primitives,
  native-spec over bash-parity.

## 12. References

- Owning brief: `RustNodeOrchestratorCompletionBrief_2026-07-12.md`.
- Parity mandate + role×OS matrix: `CrossPlatformRoleParityPlan_2026-06-21.md`.
- Stage vocabulary + tier map (built, A1): `live_lab_stage_registry.rs`.
- Evidence ledger: `documents/operations/live_lab_node_run_matrix.csv`.
- Live product gap in scope: `TraversalSelfSustenancePlan_2026-07-23.md`.
