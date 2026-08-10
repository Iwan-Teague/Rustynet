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

**Status: REVISION 2 — adversarially reviewed, one blocker and four material
errors folded in. Increment I1 is IMPLEMENTED (`27e49d54`); I2–I4 are specified
and open.**

Revision 1 was written against `bb5d467b` and adversarially reviewed the same
day. The review returned **1 BLOCKER, 4 MAJOR, 4 MINOR**, and confirmed eight
claims that survived attack. Corrections are folded in below and tagged
**[REVIEW]** rather than silently applied, because on this document family the
transferable lesson has always been *which* claim broke.

> Revision 1 was also destroyed on disk mid-session by a concurrent agent's
> working-tree operation before it was ever committed. It was reconstructed from
> the review. Commit a plan document as soon as it is written; an uncommitted
> file in this repository is not durable.

## 0. Why this plan exists, and what it corrects

The prevailing account in the doc tree is that live-lab stage coverage is missing
in bulk: `FullTodoInventory_2026-07-28.md` records the cross-OS adversarial
security stages as "OPEN entirely … none ported to macOS/Windows", and lists
HP-3 relay packet-forwarding and the nas/llm live evidence chain as the two
largest unbuilt items.

**That account is partly stale.** Verified at `bb5d467b`:

1. The cross-OS adversarial security stages **are** ported and **do** run on the
   engine of record. `security_audit_validation` dispatches the eight Tier-0
   daemon self-audits, and its platform gate admits Linux, macOS and Windows
   (`role_validation/security_audit.rs:93-98`).
   **[REVIEW — M3]** The gate is *runtime support*, not evidence. Only Linux has
   ever executed this stage in a recorded run: the run cited as proof
   (`gossip-convergence-stage-20260809`) had two Debian nodes and nothing else.
   Revision 1 stated this as "executes on Linux, macOS and Windows", which
   overclaims. The review also found **two doc comments asserting the opposite of
   their own code** — both claimed macOS/Windows are reported-skipped on a gate
   that has admitted all three since `6429a872`. Both corrected in `27e49d54`.
2. The formerly-inert chaos scaffolds are **implemented** and the `--node` engine
   carries all nine `chaos_*` StageIds, dispatching real fault-injection
   binaries (`stage/chaos.rs:133-190`, correctly passing `--features vm-lab`).
   **[REVIEW — MINOR]** At least **five** scaffolds were converted, not three:
   `live_chaos_privileged_boundary_test.rs:5` and
   `live_chaos_membership_adversarial_test.rs:5` also record the conversion.
3. `extended_soak`, the negative-control suite and the cross-network suite all
   exist in the `--node` vocabulary.

What is actually missing is narrower, and the largest item is not a coverage gap
at all but a **recording** gap that made the ledger under-report work the engine
really does. QH-37 made columns read **greener** than reality; G3 below was its
mirror image, making them read **redder**.

### How to re-verify

- Ledger tallies: quote-aware `csv.DictReader` over
  `documents/operations/live_lab_node_run_matrix.csv` (106 rows, 267 columns).
  Per §12.3 an `awk -F,` read of this file is wrong by construction.
- Stage vocabulary: the `=> "…"` wire-name arms in
  `vm_lab/orchestrator/stage/mod.rs`.
- Dispatch reality: `stages[]` in a run's `run_summary.json`.

## 1. The gaps

### G1 — nas / llm have zero live stages on any engine

**VERIFIED, survived review.** No `StageId`, no stage module, no registry entry,
no binary. Both product crates exist and are gated
(`nas_default_deny_gates.sh`, `llm_default_deny_gates.sh`,
`llm_exit_coexistence_gates.sh`), so this is missing **stage** code, not missing
product code. Matches `ServiceHostingRolesRoadmap_2026-06-11.md` §7 row M5.

### G2 — no relay frame-forwarding proof on the `--node` engine (HP-3)

**VERIFIED, survived review.** `relay_validation` proves lifecycle only — service
active, ports bound, `/healthz` ok, stop/restart (`stage/relay_validation.rs:10-34`;
zero occurrences of forward/frame/payload/plaintext in the validator body). The
bash dialect's `validate_linux_relay_forwards_frame` (registry `:1849`, impl
`vm_lab/mod.rs:16459`) has **never run** — `linux_relay_forwards_frame` is
`not_run` in all 106 rows.

**[REVIEW — MINOR]** `role_validation/relay.rs:142-144` already documents this
gap and scopes the forwarded-frame proof to "Wave 4". Cite it rather than
inferring.

### G3 — ledger columns structurally unreachable on `--node` (recording gap)

**VERIFIED, survived review, and CLOSED for the audit family by I1.**

All 24 `{platform}_{audit_id}` cells and `linux_relay_forwards_frame` were
`not_run` in all 106 rows. The work was being done: the eight audit identifiers
in `LINUX_SECURITY_AUDITS` are byte-identical to the column suffixes, and each is
accepted only on its typed evaluator's full contract, not the daemon's
`overall_ok` flag. The columns stayed empty because `special:` is declared on the
**bash-dialect** stage names, which the `--node` engine never emits, while the
aggregate stage it does emit owns no column at all — the registry's own comment
at `live_lab_stage_registry.rs:685-696` calls the mapping "a follow-up".

**[REVIEW — M4]** Revision 1 said "40+ columns" and scoped I1 to 24 without
naming the remainder. **I1 closes 24 of roughly 49.** Still open, same root
cause, not covered: `linux_{runtime_acls, service_hardening, authenticode,
key_custody, membership_genesis, mesh_status}`, the macOS/Windows counterparts of
those, `{linux,macos,windows}_hello_limiter_flood`, `macos_pf_killswitch`,
`macos_keychain_key_custody`, `windows_named_pipe_acl`,
`windows_dpapi_key_custody`. The sharpest case is `linux_key_custody`: the
2026-08-09 run **produced `live_key_custody_report.json`** and the column still
reads `not_run` in every row. Tracked as **I5** below.

### G4 — chaos, negative-control and soak have never been dispatched

**VERIFIED as never-dispatched — but the cause was wrong.**

**[REVIEW — B1, BLOCKER]** Revision 1 said "nothing needs writing here; what is
missing is a run profile". False. All nine chaos stages declare
`dependencies: &[StageId::LiveMixedTopologyValidation]` (`stage/chaos.rs:48-50`),
and the runner skips any stage whose dependency failed or skipped
(`orchestrator/runner.rs:32`). `live_mixed_topology_validation` has **never
passed** — `skip 97 / not_run 9` on Linux — and was `skipped` in the most recent
run. So flipping the chaos selector produces **nine cascade-skips**, and
revision 1's acceptance criterion ("a dry-run plan lists them as enabled") is
satisfiable while the actual goal is not. **Enabled ≠ dispatched.**

Corrected: I4 must first make `live_mixed_topology_validation` pass, or
deliberately re-parent the chaos dependency. Its acceptance is a **chaos report
artifact with a non-skipped outcome**, never a plan listing.

### G5 — cross-OS relay is posture-gated off, not unimplemented

**VERIFIED.** `deploy_relay_service` and `relay_validation` report-skip macOS and
Windows relay nodes on `NodeRole::is_supported_for_platform`, named in a
`reported_skips.json`, never a silent pass. Gated by a flag awaiting evidence,
not by absent code. This plan does not touch that flag — flipping it without the
evidence it gates would be a fail-open change.

## 2. Non-goals

Reviewed and confirmed honest.

- Do not flip `is_supported_for_platform` (G5).
- Do not re-run or re-interpret `live_two_hop_validation`: 0 lifetime passes, and
  35 historical `two_hop=pass` rows are contaminated by the alias removed in
  QH-37.
- Do not extend the frozen bash archive or its dialect — bash is being retired
  (`BashRetirementPlan_2026-07-24.md`).
- No product-code change. Every increment is orchestrator/stage/recorder code
  plus tests.

## 3. Increments

### I1 — Per-control recording for the eight Tier-0 audits — **DONE** (`27e49d54`)

Landed:

1. `run_security_audits` returns a verdict for **every** audit; `security_audits_ok`
   reduces to the fail-closed stage verdict. The old fail-fast loop left seven
   controls with no verdict, which is precisely how they were recorded `not_run`.
2. A third verdict, `Blocked`, distinct from `Failed` — **[REVIEW — M1]** revision
   1's four-value rule had no branch for an audit that was never reached, so the
   natural implementation would have left those columns at `not_run`, which
   asserts "no node of that platform was in the run" about a run where the node
   was present. `blocked` maps to the recorder's existing rank-5 status, above
   both `skip` and `pass`.
3. The stage writes `security_audit_validation.per_control.json`; the recorder
   populates `{platform}_{audit_id}` from it. Multi-node resolution reuses
   `set_status`'s worst-wins merge, so one node failing a control keeps that
   platform's column from reading green — the QH-37 precedence, applied
   deliberately. **[REVIEW — item 6]** confirmed this matches `fdbdee18` rather
   than contradicting it.
4. A stale artifact cannot manufacture evidence: columns are populated only when
   the stage actually appears in the run's stage list.
5. Two doc comments that contradicted their own code, corrected (M3).

**[REVIEW — item 7]** confirmed I1 was implementable as designed: the recorder
already receives `report_dir` and already reads per-stage artifacts from it, so
this is an established pattern, not new plumbing. The review named this "the
sharpest available blocker and it does not land."

**[REVIEW — MINOR]** The `skip` branch of the original rule is dead on the three
desktop platforms — `reported_skips` populates only for iOS/Android, which have
no columns. The implementation therefore does not emit `skip` at all.

**The implementation was itself adversarially reviewed** (`8de6f497` folds the
result in). The review's flagged priority — whether recording a dispatch error as
`blocked` is a fail-open downgrade of a real security failure — was **refuted,
with proof**: `posix_run_argv` wraps the remote command as
`set +e; …; rc=$?; printf 'CODE:%d\n' "$rc"`, so a non-zero exit from an audit
returns `Ok(RemoteExitStatus { code })` and **never** `Err`. A daemon that runs
and violates a control therefore reaches the typed evaluator and is recorded
`Failed`; a missing daemon (rc=127) and a `sudo -n` refusal (rc=1) likewise. Only
transport-level errors yield `Blocked`. Also confirmed under attack: `blocked`
ranks 5, above `skip` 4 and `pass` 3; all 24 columns exist; no caller depended on
fail-fast; `StageFanout::PerNode` does not re-execute the stage per node, so the
single end-of-stage write cannot be clobbered; no secrets reach the artifact's
`detail`; no `unwrap`/`expect` in the new production paths.

Three majors did land and are fixed in `8de6f497`:

1. **A stale artifact could green-wash a reused report directory.** The write was
   guarded on a non-empty verdict list, so a rerun into the same report dir with
   every node unreachable left the *previous* invocation's artifact for the
   recorder to read as this run's evidence — `pass` for controls never exercised,
   on a run whose stage failed. Report-dir reuse is a supported flow
   (resume / rerun-stage / run-only). The write is now unconditional.
2. **The tests did not discriminate the regression the change exists to prevent.**
   The old loop fail-fasted on *both* a dispatch error and an evaluator
   rejection; the run-all test used an unprogrammed mock, so all eight verdicts
   were `Blocked` and a mutation that fail-fasts only on `Failed` **survived the
   entire suite**. Now covered by `a_failing_audit_does_not_stop_the_remaining_seven`.
3. **Run-all multiplied a dead host's cost eightfold** (180 s transport timeout
   each, stage deadline opt-in). A host-level dispatch error now stops
   re-dialling and marks the rest `Blocked` as not-attempted — same verdicts, one
   timeout.

Plus, from the same review: the reduction denies a short result set instead of
reducing an empty one to `Ok`; `platform_tag` returns `Option` from an exhaustive
match so a future platform cannot be charged to the linux columns; the evidence
write is atomic and its failure fails the stage; the reader rejects an
unrecognised `schema_version`; and the second stale doc comment — which
`27e49d54`'s message wrongly claimed to have fixed — is fixed.

Evidence: 30 tests, and **nine** mutations verified to discriminate. Original
four: `Blocked→"pass"`, dispatch-guard removed, fail-fast restored (1 verdict vs
8), single-row truncation. Post-review five: conditional write restored (fails
`a_run_that_exercises_nothing_still_overwrites_a_stale_artifact`), fail-fast on
`Failed` only (fails `a_failing_audit_does_not_stop_the_remaining_seven`, 1 vs 8 —
**this is the mutation that previously survived**), schema gate removed, fail-open
`_ => Some("linux")` platform default, host-level early-stop removed.

**Still open from the review, not fixed here:** `blocked` is not in the lab
monitor's `is_decisive` set (`rustynet-lab-monitor/src/data/run_matrix.rs:601`),
so it is dropped from `total_stages` and renders as `NotRun` — an unexercised
control currently makes the TUI's completion ratio look *better*, and the
fail-vs-not-exercised distinction is invisible there. This change is `blocked`'s
first writer into these columns, so the defect is newly reachable. That crate is
workspace-excluded and gated separately (`./scripts/ci/lab_monitor_gates.sh`).

### I2 — Relay frame-forwarding stage on `--node` (G2)

1. New `StageId::RelayForwardingValidation`, `dependencies: [RelayValidation]`,
   per-node over `Relay`-role nodes.
2. Port the proof shape of `exercise_linux_relay_forwards_frame` onto the adapter
   `RemoteShellHost` seam so it is cross-OS by construction.
3. The assertion must be **ciphertext-only forwarding** — a frame submitted at
   one peer emerges at the other and the relay never observes plaintext. "Bytes
   moved" does not discharge HP-3/RPT-01.
4. `proves: PROVES_RELAY_FORWARDING`.

**[REVIEW — M2, MAJOR]** Revision 1 asked for a `special` column templated per
platform. `StageSpec.special` is `Option<&'static str>` — **one fixed column
string** (`live_lab_stage_registry.rs:390`); every existing per-platform security
column is a separate bash-dialect StageSpec. Also, only
`linux_relay_forwards_frame` exists: `macos_` and `windows_` counterparts are
**absent from `DEFAULT_MATRIX_COLUMNS`**. So I2 must (a) add the missing columns
to `DEFAULT_MATRIX_COLUMNS`, and (b) pick **one** mechanism — three
`direct_platform` specs, or the I1 artifact reader — not `special`. The schema
change is loud, not silent (`every_registry_stage_column_reference_exists_in_the_csv_schema`
fails), but it was unplanned work.

### I3 — nas and llm live stages (G1)

`deploy_nas_service` / `nas_validation`, `deploy_llm_service` / `llm_validation`,
mirroring the relay pair. Validation asserts, per `SecurityMinimumBar` §6.E
(E1–E4): **default-deny** reachability, **tunnel-only** exposure, and for `llm`
the exit-coexistence guard. The default-deny assertion is primary and must be a
**negative** test — proving refusal, not that the service answers.

Same M2 correction applies: no `{platform}_stage_nas` / `_llm` column exists;
adding them to `DEFAULT_MATRIX_COLUMNS` is part of the increment.

Highest-effort increment. If the role cannot be elected by an existing selector,
this also needs a topology selector, widening the change into the wrapper.

### I4 — Make chaos / negative-control / soak actually dispatch (G4)

**Reordered by the review from "trivial" to "gated".** First establish why
`live_mixed_topology_validation` has never passed — it has never been *attempted*,
so step one is run-and-triage, not fix. Then either make it pass or re-parent the
chaos dependency deliberately. Only then is a suite selector meaningful.

Acceptance: a chaos report artifact with a non-skipped outcome. Not a plan
listing.

Note `SoakSuite` additionally ANDs with `!skip_linux_live_suite`
(`live_lab_stage_registry.rs:329-331`), so a targeted mac/win run can never carry
soak by design.

### I5 — Generalise the artifact→column mechanism to the remaining ~25 columns

**[REVIEW — M4]** I1 fixed the audit family by hand. The same root cause leaves
roughly 25 further columns unreachable, `linux_key_custody` being the clearest
(its report artifact is produced and the column still reads `not_run`). Either
generalise the per-control artifact convention to every validator stage, or
enumerate the remainder and map them individually. Do not leave this implicit —
it is the difference between "the ledger under-reports one family" and "the
ledger under-reports half the security surface".

## 4. Definition of done

Per §9 of the operating contract, and additionally:

- No increment records a column as `pass` that a partial or skipped run produced
  (the QH-37 invariant, in both directions).
- Every new stage names its `proves:` control IDs.
- Each increment's claim is backed by a gate run **and** a verified mutation:
  break the control, watch the stage go red, restore it. Commit messages state
  the mutation that was actually run, not one that was planned.
- Doc indexes updated in the same change.

## 5. What this plan does not close

Even fully executed: Windows has never bootstrapped on `--node`;
`live_mixed_topology_validation` is 0-for-106 because it was never attempted;
macOS exit/blind_exit/anchor have never been elected on `--node`. Those are
run-and-triage work, not stage-authoring work, and they dominate the remaining
distance to G2 parity. I4 now depends on the second of them.
