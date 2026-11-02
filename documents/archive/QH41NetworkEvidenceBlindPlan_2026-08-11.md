# QH-41 — the network evidence artifact is recorded blind — plan (revision 3) — 2026-08-11

> **OUTCOME 2026-08-11: the one-line flip proposed here was REFUTED and NOT implemented.**
> Review established that the audit runs *before* readiness, so collecting guests there would
> record healthy-but-unpowered guests as unreachable, arm an unbounded SSH before shutdown
> handlers and stage deadlines exist, turn `--dry-run` into a live fleet sweep, and use the
> operator's `~/.ssh/known_hosts` rather than the run's.
>
> What shipped instead is disclosure: the artifact now carries `guest_observation` and, when
> skipped, an `evidence_limitations` entry naming the unevaluated finding class. A first
> attempt also downgraded `overall_status`, which was reverted — three callers hardcode
> `--skip-guests` and the orchestrate gate stops on any non-`pass`, so it made
> `ensure_lab_ready(profile=…)` permanently unsatisfiable once the stale labels are repaired.
>
> **Filed as QH-42**, not QH-41 — QH-41 is the vmnet bridge split, a different defect the two
> were conflated with. Commits `9dd878ca`, `6cb4a8b5`, `a14c5227`.

**Status: PLAN — superseded by the outcome note above.** Written against `HEAD = 667723db`, clean tree. Supersedes
`QH41CrossBackendL2SplitPlan_2026-08-11.md`, both revisions of which were refuted — revision 1
proposed building a preflight that exists, revision 2 claimed nothing runs it when the
orchestrate path already does. Read that document's refutation header before this one; the
two errors it records are the reason this plan is deliberately one line of behaviour change.

## 0. What is actually true, verified

| claim | evidence |
| --- | --- |
| The audit engine already runs on every orchestrate run | `native.rs:1023` `execute_ops_vm_lab_network_audit(...)` inside `ensure_orchestration_network_profile_record` (`:987`), reached from `native.rs:147` (`--node`) and `mod.rs:11990` |
| It already enforces fail-closed when a profile is explicit | `native.rs:1043-1071` `if record.enforced { … return Err("… the run stops before deployment") }`; `enforced: !derived` (`network_profile.rs:1248`) |
| **It runs blind** | `native.rs:1031` passes `skip_guests: true` |
| Blind means the L2 findings cannot fire | with `skip_guests`, every guest is emitted `status: "skipped"` (`network_audit.rs:1805-1817`), and `detect_offfleet_subnet_findings` skips any guest not `collected` (`:879-881`) |
| Measured on the run that motivated QH-41 | `artifacts/live_lab/percontrol-rebaseline-20260811/orchestration/vm_network_evidence.json`: **11/11 guests `"skipped"`, zero `off_fleet_subnet`**, `overall_status: fail` on the 3 `stale_network_group` errors only |
| Credentials are not the reason for the flag | `ssh_identity_file: None` falls back to `default_lab_ssh_identity_path` (`network_audit.rs:2019-2023`), which is why the standalone command collects 5 guests without being given one |

## 1. The defect, stated precisely

This is **not** "a missing gate". It is **misleading recorded evidence**, the same class as
QH-37, QH-22 and QH-39.

Every orchestrate run writes `orchestration/vm_network_evidence.json` and 103 of 107 ledger
rows carry the profile id and digest. That artifact asserts a network observation was made.
It was not: every guest is stamped `"skipped"` and the only findings it can ever emit are the
inventory-metadata ones. A reader — human or tool — sees network evidence attached to a run
and reasonably concludes the underlay was checked. It never was, and on 2026-08-11 the thing
it would have caught cost a whole run.

## 2. The change

**One line: `skip_guests: true` → `false` at `native.rs:1031`.**

That is the entire behaviour change. It makes the artifact report what it claims to report.

### What this deliberately does NOT change

**The enforcement default stays exactly as it is.** `enforced: !derived` means a run without
an explicit `--network-profile` records and proceeds. This plan does not touch that, for a
reason worth stating rather than assuming: with guests collected, the five `off_fleet_subnet`
errors become real, and an explicitly-profiled run would then stop. Today that is 4 of 107
rows, so the blast radius is small — but changing evidence quality and changing gating in one
step is how the previous two attempts went wrong. **Make the evidence true first; decide
gating against true evidence afterwards.**

## 3. Risks, stated as choices

1. **Cost.** Guest collection SSHes to each guest; the standalone command measured **26.8 s**.
   That is added to every orchestrate startup. Against ~20 minutes lost to a partition
   discovered at `traffic_test_matrix`, it is worth it — but it is not free and belongs in the
   record.
2. **An unreachable guest silently drops out.** `observe_guest` returns an observation, never
   an error (`network_audit.rs:1567-1571`), so a guest that cannot be reached is simply not
   `collected` and its `off_fleet_subnet` finding does not fire. **This is a fail-open in the
   finding**, it is pre-existing, and this plan does not fix it — but flipping the flag is
   what makes it reachable, so it must be named. A follow-up should decide whether
   "elected-and-uncollectable" is itself a finding.
3. **Explicit-profile runs may newly fail.** Stated above; accepted deliberately, and the
   reason those runs *should* fail is that the condition is real.
4. **The finding's own definition is questionable and out of scope here.**
   `off_fleet_subnet` compares each guest against a majority-derived "fleet management plane",
   which the four remote KVM guests currently dominate — so every local UTM guest is reported
   off-plane even when the elected nodes can reach each other. That is worth revisiting, but
   it is a change to a shipped finding's semantics and does not belong in a one-line evidence
   fix.

## 4. Tests

1. With `skip_guests: false`, guests reachable → observations carry `status: "collected"` and
   `off_fleet_subnet` findings can be produced. *Mutation:* revert the flag → every guest
   `skipped` → test fails.
2. The orchestrate call site passes `skip_guests: false`. *Mutation:* set it back to `true` →
   fails. Pins the specific regression, since the flag is a single bool that is easy to flip
   back without noticing.
3. A guest that cannot be observed is recorded not-`collected` and does not abort the audit.
   *Mutation:* make `observe_guest` propagate an error → fails. Pins risk 2's shape so a later
   change cannot turn one unreachable guest into a failed run without a deliberate decision.
4. Enforcement behaviour is unchanged: a derived profile still records and proceeds.
   *Mutation:* set `enforced: true` unconditionally → fails.

## 5. Definition of done

All §7 gates green; each test mutation-proven; and the claim in §0 re-verifiable by re-running
the orchestrate path and confirming the emitted `vm_network_evidence.json` now carries
`collected` guests rather than 11/11 `skipped`.
