# Live-Lab Stage Coverage Gap Plan — `--node` engine — 2026-08-10

## Provenance and review status — READ FIRST

**Drafted by a sub-agent that had been instructed to stay read-only, and wrote this
file anyway.** It is landed because its claims were re-verified independently, not
because it was trusted. Treat the same way you would any unreviewed input: the
verification below is the reason to believe it, not the byline.

**Independently re-verified 2026-08-10 at `27e49d54`** (the original was written
against `bb5d467b`; the tree moved under it):

| Claim | Verdict | How re-checked |
| --- | --- | --- |
| G1 — no nas/llm live stages on any engine | **HOLDS** | 0 stage wire-names and 0 registry `name:` entries match `nas`/`llm` on a word boundary |
| G3 — per-control security columns unreachable | **HOLDS in the ledger** | `linux_membership_revoke_applies`, `linux_policy_default_deny` and their macOS/Windows triplets are `not_run` in all **106** rows |
| G4 — chaos never dispatched on `--node` | **HOLDS** | the one chaos-bearing run (`phase31_mixed_os`, 8 chaos stages) carries no `run_note`, so it is a legacy/bash run; across 12 `--node` runs, none contains a `chaos_*` stage |
| G2 — no relay frame-forwarding proof on `--node` | **HOLDS** | `validate_linux_relay_forwards_frame` exists only as a bash-dialect registry name feeding `special: linux_relay_forwards_frame` |

**I1 IS ALREADY IMPLEMENTED — do not action it.** Concurrent work landed it in
`27e49d54` ("Record the eight Tier-0 security audits per control, not just in
aggregate"): `PER_CONTROL_FILENAME`, the per-audit result vector,
`write_per_control_evidence` and the `audit_id` rows all exist. The artifact name
matches this plan's proposal **verbatim**
(`security_audit_validation.per_control.json`), so the design below was evidently the
input to that work rather than a competing proposal. **The producer side is done; the
ledger still reads `not_run` only because no run has happened since.** The remaining
step for G3 is a run, not code.

**A caution on verifying this document.** Re-checking G1 naively with `grep -i llm`
returns `live_linux_enrollment_restart_test.rs` — "enro**llm**ent". The counts above
use word boundaries for that reason. Anyone re-running these checks should do the
same.

Sections 2 onward (I2 relay frame-forwarding, I3 nas/llm stages, I4 suite profile)
were **not** re-verified line by line and remain pre-review.

---

**Status: PLAN, pre-review.** Written against `HEAD = bb5d467b`, clean tree.
Every claim below was verified by reading the code or parsing the ledger at that
commit; the verification method is named inline so a reviewer can re-run it. Where
a claim is inferred rather than executed, it is tagged **INFERRED**.

## 0. Why this plan exists, and what it corrects

The prevailing account in the doc tree is that live-lab stage coverage is missing
in bulk: `FullTodoInventory_2026-07-28.md` §Wave-3 records the cross-OS
adversarial security stages as "OPEN entirely … none ported to macOS/Windows",
and lists HP-3 relay packet-forwarding and the nas/llm live evidence chain as the
two largest unbuilt items.

**That account is partly stale.** Three of its four claims do not survive contact
with the code at `bb5d467b`:

1. The cross-OS adversarial security stages **are** ported and **do** run on the
   engine of record. `security_audit_validation` executes the eight Tier-0 daemon
   self-audits on Linux, macOS **and** Windows
   (`stage/security_audit_validation.rs:52-98`; the platform gate
   `security_audit_runtime_implemented` admits all three,
   `role_validation/security_audit.rs:90-95`). It passed in the most recent run.
2. The three formerly-inert chaos scaffolds are **implemented** — 1223, 1296 and
   1169 lines respectively — and the `--node` engine carries all nine
   `chaos_*` StageIds (`stage/mod.rs`), delegating to those binaries
   (`stage/chaos.rs:60-189`).
3. `extended_soak`, the negative-control suite and the cross-network suite all
   exist in the `--node` vocabulary.

What is *actually* missing is narrower, and one item is not a coverage gap at all
but a **recording** gap that makes the ledger under-report work the engine really
does. That distinction is the reason this plan exists: the previous ledger defect
(QH-37) made columns read **greener** than reality; G3 below is its mirror image,
making them read **redder**. Both corrupt the same evidence base.

### Verification commands used

- Ledger tallies: quote-aware `csv.DictReader` over
  `documents/operations/live_lab_node_run_matrix.csv` (106 rows). Per §12.3, a
  `awk -F,` read of this file is wrong by construction.
- Stage vocabulary: the `=> "…"` wire-name arms in
  `crates/rustynet-cli/src/vm_lab/orchestrator/stage/mod.rs`.
- Dispatch reality: `stages[]` in
  `artifacts/live_lab/gossip-convergence-stage-20260809/run_summary.json`
  (59 stages, the 2026-08-09 run at `f3b89f01`).

## 1. The gaps, with evidence

### G1 — nas / llm have zero live stages on any engine

**VERIFIED.** No `StageId`, no stage module, no registry entry, and no
`live_*` binary matches `nas` or `llm`. The `--node` wire-name list contains
neither. Both product crates exist and are gated
(`rustynet-nas`, `rustynet-llm-gateway`, plus `nas_default_deny_gates.sh`,
`llm_default_deny_gates.sh`, `llm_exit_coexistence_gates.sh`), so this is
missing **stage** code, not missing product code. Matches
`ServiceHostingRolesRoadmap_2026-06-11.md` §7 row M5, still `☐ open`.

### G2 — no relay frame-forwarding proof on the `--node` engine (HP-3)

**VERIFIED.** `relay_validation` proves **lifecycle only** — its own doc comment
says so: service active, datapath UDP port bound, health TCP port bound,
`/healthz` returns ok, then stop/restart
(`stage/relay_validation.rs:10-34`). No frame is ever forwarded.

The bash dialect has a forwarding stage — `validate_linux_relay_forwards_frame`
(registry line 1849, `proves: PROVES_RELAY_FORWARDING = ["HP-3", "RPT-01"]`),
implemented at `vm_lab/mod.rs:16459` (`exercise_linux_relay_forwards_frame`). It
has **never run**: `linux_relay_forwards_frame` is `not_run` in **all 106** rows.
So relay forwarding is unproven on every OS and every engine — consistent with
the doc tree calling HP-3 "the single biggest looks-done-but-isn't gap".

### G3 — 40+ ledger columns are structurally unreachable on `--node` (recording gap)

**VERIFIED, and this is the highest-value item.** Every per-control check column
is `not_run` in all 106 rows — including all 24 cells of the eight Tier-0 audits
× three platforms:

```
linux_membership_revoke_applies      not_run ×106
linux_policy_default_deny            not_run ×106
linux_privileged_helper_allowlist    not_run ×106
… and the macos_* / windows_* triplets of each, plus
linux_relay_forwards_frame           not_run ×106
```

The work **is being done**. `validate_linux_security_audits` runs eight named
audits whose identifiers are byte-identical to the column suffixes —
`membership_revoke_applies`, `revoked_peer_denied_e2e`,
`membership_signature_forgery`, `privileged_helper_allowlist`,
`policy_default_deny`, `gossip_revoked_readmit`, `enrollment_replay`,
`blind_exit_reversal_denied` (`role_validation/security_audit.rs:44-80`) — and
each is accepted only on its typed evaluator's full contract, not merely the
daemon's `overall_ok` flag (`:97-102`).

The columns stay empty because `special:` is declared on the **bash-dialect**
stage names (`validate_linux_membership_revoke_applies`, …) which the `--node`
engine never emits. The engine emits one aggregate stage, `security_audit_validation`,
which owns **no** column at all — there is no `*_security_audit*` column in the
ledger.

Consequence: a reviewer reading the `--node` ledger concludes eight security
controls are unproven on all three platforms, when in fact they passed. This
is QH-37 inverted, and it is worse for release decisions than QH-37 was, because
it hides *real* evidence rather than inventing fake evidence.

### G4 — chaos, negative-control and soak have never been dispatched

**VERIFIED as a selection gap, not a code gap.** `chaos` is `not_run` in
106/106 rows on all three platforms; `extended_soak` has never passed on any OS.
Their `EnableRule`s (`ChaosSuite`, `NegativeControlSuite`, `SoakSuite`) are
opt-in and no recorded run selected them. `SoakSuite` additionally ANDs with
`!skip_linux_live_suite` (`live_lab_stage_registry.rs:329-331`), so a targeted
mac/win run can never carry soak by design.

Nothing needs writing here. What is missing is a **run profile** that turns them
on, which is a prerequisite for the 24/7 goal: an unattended loop that never
selects the chaos or soak suites cannot converge them.

### G5 — cross-OS relay is posture-gated off, not unimplemented

**VERIFIED.** `deploy_relay_service` and `relay_validation` report-skip macOS and
Windows relay nodes on `NodeRole::is_supported_for_platform`
(`stage/relay_validation.rs:31-34`), named in a `reported_skips.json`, never a
silent pass. So the mac/win relay cells are gated by a posture flag awaiting
evidence, not by absent code. **INFERRED:** flipping that flag without the
evidence it gates would be a fail-open change; this plan does not touch it.

## 2. Non-goals

- Do **not** flip `is_supported_for_platform` (G5) — that flag gates on evidence
  this plan does not produce.
- Do **not** re-run or re-interpret `live_two_hop_validation`: 0 lifetime passes,
  and 35 historical `two_hop=pass` rows are contaminated by the alias removed in
  QH-37.
- Do **not** touch the frozen bash archive or the bash-dialect stages. Bash is
  being retired (`BashRetirementPlan_2026-07-24.md`); adding to it is waste.
- No product-code change. Every increment here is orchestrator/stage/recorder
  code plus tests.

## 3. Increments, in dependency order

Each increment is independently committable and independently gated. Ordering is
by evidence-value per unit of risk: G3 first because it costs the least and
unblocks honest reading of every subsequent run.

### I1 — Make the eight Tier-0 audits addressable per control, per platform (G3)

**Problem restated:** one aggregate stage outcome cannot populate 24 per-control
columns.

1. Change `validate_linux_security_audits` to return a per-audit result vector
   (`Vec<(&'static str /*audit id*/, AuditOutcome)>`) instead of collapsing to
   `Result<(), String>`. The fail-closed contract is preserved: the caller still
   fails the stage if **any** audit failed.
2. `SecurityAuditValidationStage::execute` writes
   `security_audit_validation.per_control.json` into the report directory:
   `{alias, platform, audit_id, status, detail}` per row.
3. Teach the run-matrix recorder to populate `{platform}_{audit_id}` from that
   artifact.

**The column-resolution rule, stated so a reviewer can attack it:**

- `pass` — that audit ran on at least one node of that platform and every node
  of that platform passed it.
- `fail` — that audit ran on ≥1 node of that platform and any node failed it.
- `skip` — a node of that platform was in the run but the audit was
  reported-skipped for it.
- `not_run` — no node of that platform was in the run.

**`fail` outranks `pass`, and `skip` outranks `pass`** — the QH-37 precedence,
applied deliberately rather than inherited. A partial platform must never read
green.

**Acceptance:** a Linux `--node` run at HEAD populates 8 Linux columns with
`pass` and leaves the 16 macOS/Windows cells `not_run`. Unit tests cover all four
resolution branches plus the mixed pass/fail-across-nodes case.

**Risk:** this makes previously-empty columns carry values, so any tooling that
reads "`not_run` everywhere" as a sentinel will change behaviour. Grep for
readers of these column names before landing.

### I2 — Relay frame-forwarding stage on the `--node` engine (G2)

1. New `StageId::RelayForwardingValidation` → wire name
   `relay_forwarding_validation`, group `Live`, tier `T4Security`,
   `dependencies: [RelayValidation]`, `fanout: PerNode` over `Relay`-role nodes.
2. Implementation ports the proof shape of `exercise_linux_relay_forwards_frame`
   (`vm_lab/mod.rs:16459`) onto the adapter `RemoteShellHost` seam so it is
   cross-OS by construction rather than Linux-only.
3. The assertion must be **ciphertext-only forwarding**: a frame submitted at one
   peer emerges at the other, and the relay never observes plaintext. A stage
   that proves only "bytes moved" does not discharge HP-3/RPT-01.
4. `proves: PROVES_RELAY_FORWARDING`. Registry entry with a `special` column
   `{platform}_relay_forwards_frame`, resolved by the I1 rule.
5. Report-skip macOS/Windows on the same posture gate as `relay_validation`
   (per §2 non-goal — named skip, never silent).

**Acceptance:** with a Linux relay elected, the stage runs and its outcome
reaches `linux_relay_forwards_frame`. A run with no relay node is a skip-noop
pass, matching `relay_validation`'s empty-assignment behaviour.

**Risk:** this is the first stage to assert on datapath payload rather than
posture; if the existing bash exercise depends on Linux-only tooling, the
cross-OS seam is more work than a port. **INFERRED** — confirm by reading
`exercise_linux_relay_forwards_frame` fully before writing.

### I3 — nas and llm live stages (G1)

Two role deployments and two validations, mirroring the relay pair:

1. `deploy_nas_service` / `nas_validation`; `deploy_llm_service` /
   `llm_validation`. StageIds, modules, registry entries, columns
   `{platform}_stage_nas` / `_llm`.
2. Validation asserts, per the roles' own security bar (`SecurityMinimumBar` §6.E,
   E1–E4): **default-deny** reachability (an unauthorised peer is refused),
   **tunnel-only** exposure (no LAN-bound listener), and for `llm` the
   exit-coexistence guard.
3. The default-deny assertion is the primary one and must be a **negative**
   test — proving refusal, not merely proving the service answers.

**Acceptance:** with a nas (resp. llm) node elected, both stages run green on
Linux; the default-deny assertion is shown to fail when the deny rule is removed
(mutation-proven, per §0 of the 2026-08-07 handover — a green gate is not proof).

**Risk:** highest-effort increment. If the role cannot be elected by an existing
selector, this also needs a topology selector, which widens the change surface
into the wrapper.

### I4 — A suite profile that the 24/7 loop can select (G4)

Add a single selector that turns on chaos + negative-control + soak together for
an unattended full run, so the autonomous loop has one thing to choose. No new
stage code.

**Acceptance:** a dry-run plan at HEAD lists the nine chaos stages, the four
negative-control stages and `extended_soak` as enabled.

**Risk:** low code risk, but the first real chaos dispatch in 106 runs will
likely surface stage-level failures. That is the point; it must not be
pre-emptively softened into a warning.

## 4. Definition of done

Per §9 of the operating contract, and additionally:

- No increment records a column as `pass` that a partial or skipped run produced
  (the QH-37 invariant, in both directions).
- Every new stage names its `proves:` control IDs.
- Each increment's claim is backed by a gate run **and**, for the security
  assertions in I1–I3, a verified mutation: break the control, watch the stage go
  red, restore it. Commit messages state the mutation that was actually run, not
  one that was planned.
- `documents/operations/active/README.md` updated in the same change.

## 5. What this plan explicitly does not close

Even fully executed, the following remain open and no increment here touches
them: Windows has never bootstrapped on `--node`; `live_mixed_topology_validation`
is 0-for-106 because it was never attempted; macOS exit/blind_exit/anchor have
never been elected on `--node`. Those are run-and-triage work, not stage-authoring
work, and they dominate the remaining distance to G2 parity.
