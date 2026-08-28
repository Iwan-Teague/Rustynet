# Bash-Retirement Gap Enumeration (A4) — ledger-wide, per-cell

**Artifact class: MUST-KEEP (survives the harness deletion).** Produced by Phase A / task A4 of
`BashOrchestratorRetirementProgram_2026-08-22.md`. This is the definitive per-cell worklist that
Phase B adjudicates — the A3 matched-topology sweep structurally cannot name these cells (its
single green-able topology contains no macOS/Windows/cross-OS role cell), so THIS enumeration,
not A3, is the Phase-B input.

- **Generated:** 2026-08-26, on commit `b727df36` (clean tree).
- **Method:** quote-aware `csv.DictReader` comparison (never `awk -F,` — QH-07) of
  `documents/operations/live_lab_run_matrix.csv` (bash archive, 549 rows) against
  `documents/operations/live_lab_node_run_matrix.csv` (`--node` ledger, 151 rows at the time
  of this enumeration; **178** as re-counted 2026-08-28 at `34a9e6f8` — the ledger is append-only,
  so re-derive before citing), over the 246
  shared stage/cell columns (metadata + `*_present` excluded). A **gap column** is one where
  bash `pass ≥ 1` and `--node` `pass == 0`.
- **Result: 56 raw gap columns — 12 ledger-dialect false gaps + 44 real gaps** (matches the GAP
  survey's expected shape).

## Mandatory caveats (baked in per A4)

1. **A ledger column is not proof.** For any `two_hop`-flavored claim, do NOT read the aliased
   column: 35 historical `--node` rows carry `traffic_test_matrix` masking
   `live_two_hop_validation` (the alias was removed forward-only 2026-07-27; contaminated rows
   are permanent). Take `two_hop` pass counts from the disambiguated stage id / its report
   artifact only. The bash archive's `52 two_hop passes` figure carries the same taint class on
   the bash side.
2. **Bash is not the oracle.** Every row below is a *question, not a verdict*
   (`NodeEngineAcceptanceSpec` §8 direction-diagnosis). Phase B decides, per cell, whether the
   difference is a genuine `--node` coverage drop (prove-on-node) or `--node` superseding a bash
   false-green / bash-dialect quirk (owner-signed disposition).

## The 56 gap columns → Phase-B bucket assignment

Every column maps to exactly one Phase-B ledger entry in
`BashRetirementDispositions_2026-08-22.md` (mechanical check at B-final).

### B1 — ledger-dialect FALSE gaps (12): proven on `--node` under a different column name

| bash-dialect column | bash pass | proven `--node` column | `--node` pass |
|---|---|---|---|
| `linux_runtime_acls` | 2 | `linux_stage_runtime_acls_check` | 116 |
| `linux_service_hardening` | 2 | `linux_stage_service_hardening_check` | 116 |
| `linux_authenticode` | 2 | `linux_stage_authenticode_check` | 115 |
| `linux_key_custody` | 2 | `linux_stage_key_custody_check` | 116 |
| `linux_mesh_status` | 2 | `linux_stage_mesh_status_check` | 115 |
| `linux_membership_genesis` | 2 | `linux_stage_membership` | 136 |
| `linux_hello_limiter_flood` | 2 | `linux_stage_hello_limiter_flood` | 45 |
| `macos_hello_limiter_flood` | 13 | `macos_stage_hello_limiter_flood` | 6 |
| `macos_runtime_acls` | 15 | `macos_stage_runtime_acls_check` | 15 |
| `macos_service_hardening` | 12 | `macos_stage_service_hardening_check` | 15 |
| `macos_mesh_status` | 12 | `macos_stage_mesh_status_check` | 15 |
| `macos_authenticode` | 15 | `macos_stage_authenticode_check` | 15 |

(`windows_hello_limiter_flood` is NOT in this bucket — no `--node` Windows equivalent has ever
passed; it is a real gap behind CP-4, listed in B2.)

### B2 — Windows column, gated behind `windows_stage_bootstrap` / CP-4 (31)

`windows_stage_cleanup` (3 `--node` passes) is the only Windows stage `--node` has ever passed;
`windows_stage_bootstrap` is 0-pass on `--node` (66 bash passes) and gates every cell below.
Security (T4) cells are **bolded** — owner-level sign-off only (Spec §6.1).

`windows_client` (65), `windows_admin` (2), `windows_relay` (19)*, `windows_anchor` (24),
`windows_stage_bootstrap` (66), `windows_stage_membership` (50), `windows_stage_assignments`
(50), `windows_stage_baseline_runtime` (66), `windows_stage_anchor` (24),
`windows_stage_relay_service_lifecycle` (18), `windows_stage_managed_dns` (9),
`windows_stage_mixed_topology` (43), `windows_named_pipe_acl` (13), `windows_dpapi_key_custody`
(13), `windows_stage_traversal` (7), **`windows_membership_revoke_applies`** (11),
**`windows_membership_signature_forgery`** (11), **`windows_gossip_revoked_readmit`** (10),
**`windows_enrollment_replay`** (10), `windows_hello_limiter_flood` (8), `windows_mesh_status`
(11), **`windows_privileged_helper_allowlist`** (11), **`windows_policy_default_deny`** (11),
**`windows_revoked_peer_denied_e2e`** (11), **`windows_blind_exit_reversal_denied`** (11),
`windows_stage_dns_failclosed_check` (6), `windows_stage_runtime_acls_check` (6),
`windows_stage_service_hardening_check` (6), `windows_stage_key_custody_check` (6),
`windows_stage_mesh_status_check` (6), `windows_stage_authenticode_check` (6).

*`windows_relay` is also named by B5 (role summary vs lifecycle split); its single ledger entry
lives in B5 with a B2 gate note. Windows `exit` (CP-3 WinNAT hardware) and Windows `blind_exit`
(design-excluded, `main.rs` hard-error) have **zero bash passes** so they are not A4 rows, but
B2 dispositions them anyway for completeness.

### B3 — macOS role cells, prove-on-node commitments (7)

| column | bash pass | Phase-C task |
|---|---|---|
| `macos_client` | 113 | C1 (macOS `two_hop` triage → fix) |
| `macos_exit` | 7 | C3 (election + end-to-end egress assertion) |
| `macos_stage_exit_handoff` | 14 | C3 |
| `macos_blind_exit` | 4 | C3 (irreversible — owner-authorized sacrificial guest) |
| `macos_stage_blind_exit` | 4 | C3 |
| `macos_anchor` | 31 | C2/C3 (election + `mesh_join`; `gossip_seed`/`enrollment_endpoint` split to a code-gap deferral) |
| `macos_stage_anchor` | 23 | C2/C3 |

### B4 — cross-OS cells (3 A4 rows + never-attempted cells)

| column | bash pass | note |
|---|---|---|
| `cross_os_peer_visibility` | 98 | real dataplane fail on `--node` (16 fail / 0 pass) → C5 |
| `cross_os_anchor_bundle_pull` | 31 | never attempted on `--node` — gated on B2 (Windows bootstrap) + B3 (macOS election) |
| `macos_stage_mixed_topology` | 80 | `--node` 3-OS carrier `live_mixed_topology_validation` transitively blocked by CP-4 |

Not A4 rows (no bash-green baseline) but dispositioned in B4: `cross_os_exit_path` (0/0 on BOTH
engines — unproven, never claim a bash baseline), `cross_os_role_switch` / `cross_os_lan_toggle`
/ `cross_os_anchor_enrollment` (never attempted on either engine's `--node` era rows).
`cross_os_bootstrap` (17), `cross_os_direct_path`/`dns`/`membership_convergence` (10 each),
`cross_os_relay_path` (6) already pass on `--node` Linux+macOS pairs — the wall is narrower than
"0-proven".

### B5 — relay role summaries: lifecycle proven, frame-forwarding (HP-3) parked (2)

| column | bash pass | proven lifecycle column | HP-3 status |
|---|---|---|---|
| `macos_relay` | 69 | `macos_stage_relay_service_lifecycle` (6 pass) | frame-forwarding parked cross-OS |
| `windows_relay` | 19 | `windows_stage_relay_service_lifecycle` 0-pass, gated on CP-4 | parked |

(`linux_relay` is NOT a gap — 46 `--node` passes; named here so the B5 per-OS trio is complete.)

### B6 — residual Linux, out of mac/win/cross-OS scope (2)

| column | bash pass | direction |
|---|---|---|
| `linux_stage_blind_exit` | 8 | `--node` deliberately `skip`s it (irreversible blind_exit would brick a lab node) → "node supersedes bash" |
| `linux_stage_chaos` | 12 | never run on `--node` → deferred, out of program scope |

## Bucket arithmetic

12 (B1) + 31 (B2) + 7 (B3) + 3 (B4) + 2 (B5) + 2 (B6) − 1 (`windows_relay` counted in both B2
and B5, single ledger entry in B5) = **56**. ✓

## Reproduction

```bash
python3 - <<'PY'
import csv
def load(p):
    with open(p) as f: return list(csv.DictReader(f))
bash = load('documents/operations/live_lab_run_matrix.csv')
node = load('documents/operations/live_lab_node_run_matrix.csv')
meta = {'run_id','run_started_utc','run_finished_utc','git_commit','git_branch',
        'git_dirty_state','operator','profile_path','inventory_path','report_dir',
        'run_command','topology_summary','overall_result','first_failed_stage',
        'failure_digest_path','evidence_bundle_path','notes'}
shared = [c for c in bash[0] if c in node[0] and c not in meta and not c.endswith('_present')]
p = lambda rows, c: sum(1 for r in rows if (r.get(c) or '').strip().lower()=='pass')
for c in shared:
    b, n = p(bash, c), p(node, c)
    if b >= 1 and n == 0:
        print(f"{c},{b},{n}")
PY
```
