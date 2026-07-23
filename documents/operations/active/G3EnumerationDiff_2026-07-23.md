# G3 Enumeration Diff — silently-dropped-coverage precondition (2026-07-23)

**Status: enumeration half COMPLETE — result = ZERO silently-dropped stage
coverage (as scoped in §1).** This is the `NodeEngineAcceptanceSpec_2026-07-23.md`
§8 flip precondition ("the enumeration half runs at W5.6 … the sole detector of
silently-dropped coverage, so it cannot wait until after the flip"). Diff-only,
no lab time. This document IS the archived diff artifact §8 requires.

Adversarially reviewed 2026-07-23 (findings + resolutions in §5).

## 1. What this checks (and what it deliberately does NOT)

The one question the flip precondition must answer: **is there any logical stage
the bash orchestrator proved GREEN that the `--node` engine has no way to run at
all** — a stage silently dropped in the migration?

- **In scope:** stage *coverage capability* — does a wired `--node` `StageId`
  exist for every stage bash proved GREEN. A missing/dead StageId = a real drop =
  a flip blocker (fix on `--node`, or record an owner-signed disposition, §8).
- **Explicitly OUT of scope (NOT drops; do not block the flip — G1≠G2):**
  - **Attainment** — a stage `--node` *can* run (wired StageId exists) but has
    not yet recorded GREEN in its ledger. That is the G2/Step-B "drive it green"
    work. Several Linux stages that bash proved are in this bucket on `--node`
    today (§3.2, §3.5) — capability present, green pending.
  - **Per-stage DEPTH** — whether a `--node` stage asserts exactly what the bash
    stage it replaced did. A quality question, verified live (see the
    `role_switch_matrix` caveat, §3.6).

## 2. Method (reproducible, no lab)

Two independent diffs, because neither source alone is complete:

- **Diff A — CSV columns.** Every result column in the frozen bash archive
  `documents/operations/live_lab_run_matrix.csv` (549 rows) that recorded `pass`
  in ≥1 run = "bash proved this stage GREEN." Blind spot: a bash stage that never
  became a CSV column is invisible here (hence Diff B).
- **Diff B — authoritative bash script.** Every `run_stage <sev> <name>` /
  `record_stage[_skip] <name>` literal in `scripts/e2e/*.sh` (the actual bash
  orchestrator) = the true bash stage set (54 names). This catches stages with no
  CSV column (§3.5).
- **Right side (`--node`):** the authoritative `StageId::as_str` vocabulary
  (`crates/rustynet-cli/src/vm_lab/orchestrator/stage/mod.rs`, 72 stages), each
  confirmed **wired into a plan** (`plan.rs` registers all of `StageId::ALL`, with
  a gate asserting full registration — no dead StageIds). **Note:** map via
  `as_str`, NOT the enum variant name (e.g. `StageId::LiveExtendedSoakValidation`
  ⇒ `"extended_soak"`; a variant-name grep falsely reads it as absent).
- Normalize the 5 known bash→canonical aliases via
  `orchestrator::parity::canonical_stage_id`.

The exact mapping script is archived in §7 (re-running it against the two CSVs +
the bash scripts reproduces the result). Because it is script-produced, §3 groups
the mappings by *category* rather than exhaustively listing all 125 green columns.

## 3. Result — every bash-proven stage maps to a wired `--node` StageId

Diff A: 125 bash result-columns proved green, all mapped. Diff B: 54 bash stage
names; the `live_*`-prefixed ones map 1:1 to `live_*_validation` StageIds, leaving
the four §3.5 candidates. The mappings fall into these categories — **none is a
dropped stage:**

### 3.1 Direct StageId equivalents (dialect naming only)
The coarse lifecycle + traffic stages and the security `*_check` columns map
1:1: e.g. `bootstrap→bootstrap_hosts`, `membership[_genesis]→membership_init`,
`assignments→distribute_assignments`, `baseline_runtime→validate_baseline_runtime`,
`anchor→anchor_validation`, `relay_service_lifecycle→relay_validation`,
`two_hop→live_two_hop_validation`, `lan_toggle→live_lan_toggle_validation`,
`managed_dns→live_managed_dns_validation`,
`mixed_topology→live_mixed_topology_validation`,
`reboot_recovery→live_reboot_recovery_validation`, `extended_soak→extended_soak`,
`chaos→chaos_*` (family), `traversal→distribute_traversal`,
`cross_network→cross_network_*` (family), `admin→admin_issue`, `cleanup→cleanup`,
and `{authenticode,key_custody,mesh_status,dns_failclosed,ipv6_leak,runtime_acls,
service_hardening,blind_exit_dataplane,exit_demotion_residue,exit_nat_lifecycle,
exit_dns_failclosed}_check → *_validation`, plus the per-OS role-validator columns
(`<os>_{authenticode,mesh_status,runtime_acls,service_hardening}`,
`windows_dpapi_key_custody`, `windows_named_pipe_acl`) → their `*_validation`
StageIds' per-OS paths. **Direction: dialect difference; coverage present.**

### 3.2 Consolidation — bash's 8 Linux security stages → ONE `--node` stage
`policy_default_deny`, `privileged_helper_allowlist`,
`membership_signature_forgery`, `membership_revoke_applies`,
`revoked_peer_denied_e2e`, `enrollment_replay`, `gossip_revoked_readmit`,
`blind_exit_reversal_denied` — bash ran these as 8 separate stages; `--node` folds
all 8 into `security_audit_validation`. Evidence: `LINUX_SECURITY_AUDITS`
(`role_validation/security_audit.rs:42`) is exactly these 8 tuples, each driven as
a daemon sub-audit and accepted only on explicit `overall_ok` (fail-closed),
pinned by the test at `:136`. **Direction: consolidated (8→1), NOT dropped.**

> **Correction (review #1):** an earlier draft claimed these "record GREEN on
> `--node` under `security_audit_validation`." That is **false** — the `--node`
> ledger has **no** `security_audit` column and the 8 per-audit columns show **0
> passes** there (verified). So on `--node` this is **coverage-present but
> attainment-pending** (a Step-B "drive it green" item), exactly like §3.4 — not a
> coverage drop, but not yet a ledger green either. Consequence for W5.7: the
> outcome-level sweep cannot read these 8 from the `--node` ledger yet; it must
> read the run's report artifact or wait for Step-B greens.

### 3.3 Cross-OS dialect aggregates (spec §3-T3)
`cross_os_{bootstrap,direct_path,dns,membership_convergence,relay_path,
anchor_bundle_pull,peer_visibility}` — **bash-dialect aggregate CSV columns, NOT
`--node` StageIds** (already recorded in the acceptance spec §3-T3). Verified as
derived aggregate columns fed by underlying stages via
`live_lab_stage_registry.rs` `cross_os_column` — no independent bash *stage* hides
behind them. `--node`'s cross-OS carrier is the single
`live_mixed_topology_validation`. **Direction: bash dialect; `--node`'s own
vocabulary is correct (drift rule — do not force `cross_os_*` onto `--node`).**

### 3.4 macOS/Windows role-parity ATTAINMENT (G2, not coverage)
`macos_{anchor,exit,relay,blind_exit}`, `windows_{admin,anchor,relay,client}`,
etc. — per-(OS,role) cells bash proved but `--node` has not yet driven green.
**Direction: G2 parity ATTAINMENT** (`CrossPlatformRoleParityPlan_2026-06-21.md`),
gating *release*, not the *flip* (G1). A known, tracked deferral.

### 3.5 Dispositions — bash meta-stages with no CSV column AND no `--node` StageId (review #2)
Diff B (the script) surfaced two bash stages structurally invisible to Diff A:
- **`fresh_install_os_matrix_report`** (`live_linux_lab_orchestrator.sh`, `hard`)
  — generates a commit-bound fresh-install OS-matrix **report** by aggregating the
  `live_two_hop` output; **self-skips without the full 5-node topology.** It is a
  **report-aggregation meta-stage**, not an independent live proof. `--node`'s
  equivalent is its own evidence pipeline (`orchestrator/evidence.rs` + the
  run-matrix row + the §4.8 A2 verifier). **Disposition: `--node` supersedes with
  a native evidence pipeline; no per-stage proof is dropped.** (Fresh-install
  itself is proven on a separate `ops` surface, out of the live-lab stage set.)
- **`local_full_gate_suite`** (`hard`) — runs the local cargo security/CI **gate
  suite** (fmt/clippy/test/audit/deny). A **CI-gate meta-stage**, not a lab-node
  proof; the gates still run, independently, per `CLAUDE.md §7`. **Disposition:
  not a live-lab stage; gate coverage is unchanged (runs outside the orchestrator).**

Both dispositions are **owner-sign-off items for W5.7** (bash deletion), recorded
here so they are known, not hidden. Neither blocks the W5.6 flip. The other two
Diff-B non-`live_*` names are benign: `macos_preflight_check` (a preflight
sub-step, covered by `--node` `preflight`/`cross_network_preflight`) and
`upgrade_admin_node_membership` (setup for `role_switch_matrix`, §3.6).

### 3.6 Depth caveat — `role_switch_matrix` (review #3, honest flag)
The stage exists and is wired on both sides (not an enumeration drop). But the
`--node` `role_switch_matrix` (`stage/role_switch_matrix.rs`) verifies "tunnels
survived role distribution," which **may be shallower** than the bash pairing of
`role_switch_matrix` + its `upgrade_admin_node_membership` setup (which promoted
admin→anchor and exercised a fuller transition matrix). This is a **DEPTH**
question (§1, out of enumeration scope; a G2/live-verification item), recorded so
the depth difference is a KNOWN gap, not one hidden behind stage-name parity.

## 4. Conclusion

**Zero silently-dropped stages, as scoped (§1).** Every stage the bash
orchestrator proved GREEN maps to a wired `--node` `StageId`; `plan.rs` registers
all of `StageId::ALL` with a no-dead-stage gate. The §8 enumeration precondition
is **SATISFIED** for the W5.6 flip. Remaining bash↔`--node` differences are all
dialect naming (§3.1), deliberate consolidation (§3.2), dialect aggregates (§3.3),
G2 attainment (§3.4/§3.2), or dispositioned meta-stages (§3.5) — never a dropped
stage. Two items carry to W5.7 for owner sign-off (§3.5); one depth caveat carries
to G2 (§3.6).

The **full G3 sweep** (outcome-level GREEN proof or signed disposition **per
stage**) still gates **bash DELETION (W5.7)** and is separate from this
enumeration half. Nothing here authorizes deleting bash.

## 5. Adversarial review (2026-07-23) — findings + resolutions

A tight-scoped adversarial agent was tasked to BREAK "zero dropped coverage."
Verdict: **the core claim HOLDS as scoped** (it enumerated all 549 rows, confirmed
every ≥1-pass column maps to a wired StageId, confirmed the 8→1 consolidation is
honest via `LINUX_SECURITY_AUDITS`, and confirmed no dead StageIds). Findings, all
folded in above:
1. **False evidence** — the "record GREEN on `--node`" claim for the 8 audits was
   unsupported (0 ledger passes). **Fixed** in §3.2 (coverage-present /
   attainment-pending; W5.7-sweep consequence noted).
2. **Real Diff-A blind spot** — `fresh_install_os_matrix_report` +
   `local_full_gate_suite` are CSV-invisible. **Dispositioned** explicitly in §3.5
   (meta-stages; owner sign-off for W5.7).
3. **Depth, not enumeration** — `role_switch_matrix` may be shallower on `--node`.
   **Flagged** in §3.6 as a G2 depth item.
4. **Stale doc in a cited file** — `security_audit_validation.rs:28-32`'s
   mac/win "reported-skipped" comment is internally inconsistent with its runtime
   gate. This artifact therefore cites `LINUX_SECURITY_AUDITS`
   (`role_validation/security_audit.rs:42`, the authoritative 8-set + `:136` pin),
   not that doc comment. The stale comment is a pre-existing doc bug in that file,
   noted for a separate cleanup (not this artifact's scope).
5. **two_hop/attainment escape hatch** — reviewed as *used, not abused* (the
   StageId exists and is wired; `--node`'s never-green two_hop is genuinely G2).

## 6. (reserved)

## 7. Archived mapping method (reproducible)

```python
# Left A: bash archive green columns. Left B: bash script stage names.
# Right: StageId::as_str (mod.rs), all confirmed plan-wired.
# For each bash-proven stage: map to a StageId via the alias/consolidation table
# (canonical_stage_id + the documented dialect/8→1/cross_os/role-cell mappings).
# UNMAPPED with a `pass` = a candidate real drop. Result: NONE.
#   Diff A over live_lab_run_matrix.csv (549 rows): 0 unmapped.
#   Diff B over scripts/e2e/*.sh run_stage/record_stage names (54): the 4
#   non-live_* candidates dispositioned in §3.5/§3.6; 0 dropped proofs.
# Full script text: loop journal note (rustynet-lab-state get_loop_journal) +
# this commit. Re-run against the two CSVs + the bash scripts to reproduce.
```

## 8. References
- `NodeEngineAcceptanceSpec_2026-07-23.md` §8 (precondition), §3-T3 (cross_os), §1 (G1≠G2), §6.1 (dispositions).
- `crates/rustynet-cli/src/vm_lab/orchestrator/stage/mod.rs` (`StageId::ALL`/`as_str`), `plan.rs` (registration + no-dead-stage gate).
- `crates/rustynet-cli/src/vm_lab/orchestrator/parity.rs` (`canonical_stage_id`).
- `crates/rustynet-cli/src/vm_lab/orchestrator/role_validation/security_audit.rs:42` (`LINUX_SECURITY_AUDITS`, the 8→1 set).
- `scripts/e2e/live_linux_lab_orchestrator.sh` (authoritative bash stage set).
- `documents/operations/live_lab_run_matrix.csv` (frozen bash archive), `live_lab_node_run_matrix.csv` (`--node` ledger).
