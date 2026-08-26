# Bash Orchestrator Retirement — `--node`-Sole-Engine Program

**Delegatable execution plan. Owner: repo owner. Executor: Ox Alpha sub-agent, one task at a time.**
**Governing docs (read in full before Phase A):** `documents/operations/active/NodeEngineAcceptanceSpec_2026-07-23.md` §8 (G3), §6.1, §4.8; `documents/operations/active/BashRetirementPlan_2026-07-24.md` (deletion mechanics); `documents/operations/active/CrossPlatformRoleParityRefresh_2026-07-23.md` (per-cell status).

---

## DOC PLACEMENT — read first (advisory to the owner, not a delegate task)

**Recommendation: create this as a NEW orchestration ledger; do NOT fold it into `BashRetirementPlan_2026-07-24.md`, and do NOT create a competing deletion inventory.**

`BashRetirementPlan_2026-07-24.md` already owns the *deletion mechanics* (its §3 inventory + §4 order are the authoritative, verified-against-tree deletion surface). This program is strictly broader — it sequences the parity-attainment (per-cell) and engineering-blocker work that BashRetirementPlan only names as a §0 precondition. Two docs, one scope each:

- **This program doc** (`documents/operations/active/BashOrchestratorRetirementProgram_2026-08-22.md`): the phase spine A→F. It *references* BashRetirementPlan §3/§4 for the deletion step; it does not re-list files.
- **`BashRetirementPlan_2026-07-24.md`**: unchanged as the deletion-phase sub-plan. Add one header line pointing up to this program doc as its parent. When the program completes, move BashRetirementPlan to `documents/operations/done/`.

**Index + mirror duties triggered by creating this doc (do in the same change that lands it):**
- Add the new doc to `documents/operations/active/README.md`.
- **AGENTS.md / CLAUDE.md are byte-for-byte mirrored.** Any edit to one (e.g. adding this program to the §2 ledger list) MUST be applied identically to the other, and the change must finish with `cmp AGENTS.md CLAUDE.md` printing nothing (§14). Nothing mechanically enforces this — the delegate verifies by hand.
- If §2's "legacy bash-orchestrator archive" / `--legacy-bash` wording changes as a result of the program, both files change together.

---

## 0) What `--node` lacks today (authoritative up-front summary)

`--node` is the engine of record post-W5.6 flip, but on the current ledger (`live_lab_node_run_matrix.csv`, **151 rows**) it has **0 overall-pass runs** (130 fail / 21 partial) and the bash archive is the sole evidence for every mac/Windows/cross-OS role cell. Concrete lacks, in the order they gate everything else:

1. **No passing Windows bootstrap, ever.** `windows_stage_bootstrap` = 5 fail / 0 pass / 146 not_run. This one stage gates the *entire* Windows column (~30 cells). Root cause is unverified — code vs guest health — on a thin single-day signal (CP-4). Two standing code gaps persist *behind* bootstrap and cannot be "fixed" in this program: Windows has no gossip transport (`windows.rs:157-160`, `DeferredPlatform`) and cannot self-issue signed bundles (`windows.rs:288-311`, ephemeral local mint). These cap Windows anchor/gossip cells regardless and must be dispositioned.
2. **macOS exit / blind_exit / anchor never elected on `--node`.** Election machinery is wired and tested (`is_lab_assignable_for_platform`, the `MacosExit`/`AnchorPlatform`/`BlindExitPlatform` selectors) but no recorded run ever drove `--macos-promote-exit` / `--blind-exit-platform macos` / `--anchor-platform macos` green. `macos_exit`/`macos_blind_exit` = 151 not_run; `macos_anchor` = 0 pass. Anchor `gossip_seed` / `enrollment_endpoint` additionally lack live proof (`enrollment_endpoint` = zero runtime enforcement, a code gap — disposition, not prove-on-node).
3. **macOS `two_hop` fails 8/8 → caps every overall macOS verdict** (CP-1). Diagnosis is UNVERIFIED (the "userspace shared-socket handshake" hypothesis is imported from a different stage) — first action is fresh triage, not the stale fix.
4. **Cross-OS mixed-topology never completed.** `cross_os_peer_visibility` fails (16 fail / 0 pass); `cross_os_exit_path` (0/0 on BOTH engines — unproven, not a bash-green gap) / `anchor_bundle_pull` / `role_switch` / `lan_toggle` / `anchor_enrollment` never attempted (skip/not_run). The 3-OS carrier is transitively blocked by (1). Several cross-OS cells now DO pass on Linux+macOS pairs — bootstrap 17, direct_path/dns/membership 10 each, relay 6 — so the wall is narrower than "0-proven."

**Linux is not the blocker.** `linux_stage_two_hop` now passes (52 lifetime). The residual Linux overall-pass gap is `network_flap` / `lan_toggle` / `enrollment_restart`, out of this program's mac/win/cross-OS scope.

**Consequence for this program:** most bash-green/`--node`-not cells resolve to **owner-signed dispositions** ("deferred G2 attainment" or "node supersedes bash"), not prove-on-node. That disposition workload — plus the §0 trust/soak precondition — is the gate, not the G3 tooling (which is ready).

---

## PHASE A — G3 sweep + ledger enumeration → the two authoritative artifacts

Phase A produces TWO distinct artifacts, and the plan is wrong if it conflates them:

- **A3 = the §8 mechanical sweep** — a functional diff of two matched-topology *report dirs* (one bash, one `--node`) on a topology both engines can drive green. It discharges G3's "no un-dispositioned coverage drop" **only for the stages present in that topology** (a Linux `exit+client` run). It structurally CANNOT name the macOS/Windows/cross-OS role cells, because a single green-able topology contains none of them.
- **A4 = the per-cell disposition worklist** — a ledger-wide comparison of the two evidence CSVs, which is the ONLY surface that enumerates every bash-green/`--node`-not cell. **A4, not A3, is the Phase-B input.** Failing to add A4 lets the DoD be "satisfied" against a handful of Linux stages while every real gap goes undispositioned.

Phase A blocks on the §0 preconditions below.

### A0 — Confirm deletion preconditions (governance gate; NOT self-approvable)
- **Delegate prep (self-checkable):** from `live_lab_node_run_matrix.csv`, using a **quote-aware reader** (never `awk -F,` — see §12.3), enumerate and list every green default-`--node` run since the W5.6 flip (flip-candidate commit `a414ceb`): count, commit, date, verifier-recomputed status. Confirm G1 held, labs quiet, integration token held, all workers idle. Hand this evidence to the owner.
- **Owner decision (not the delegate's):** whether the soak count is high enough to lose the rollback lever. The delegate STOPS here; it never records this gate as met.
- **Acceptance:** the four facts are recorded in the disposition ledger with the delegate's evidence and an owner `APPROVED <date>` line. If any is false or unsigned, STOP — Phase A does not proceed to deletion (A1–A4 analysis MAY run; nothing is deleted).

### A1 — Drive the two paired live runs on a matched topology
- **Task:** on one matched topology (e.g. exit + single client, so both go green), run the bash engine (`rustynet ops vm-lab-orchestrate-live-lab … --legacy-bash-orchestrator …`) and the `--node` engine (same topology, no legacy flag). Both must produce a report dir containing `state/stages.tsv`.
- **Acceptance:** two report dirs exist, each with a non-empty `state/stages.tsv`; both runs reached a terminal (non-crashed) state. Confirm `--legacy-bash-orchestrator` is mutually exclusive with `--node`/`--setup-only`/`--run-only` — the bash run must reject those combos, not silently ignore them.

### A2 — Run the full sweep, functional mode
- **Task:** `scripts/e2e/orchestrator_parity_diff.sh <bash_report_dir> <rust_report_dir> <out.json>` (or `ops vm-lab-diff-orchestrator-parity --left … --right … --mode functional`). `--mode strict` is UNSATISFIABLE across dialects — must be `functional`. Requires `$RUSTYNET_BIN` = a `--features vm-lab` build.
- **Acceptance:** the command exits and writes `<out.json>`; the JSON carries `overall_functional_parity_pass`, `stages_only_in_left`, and per-shared-stage `matches`. A non-zero exit is expected while diffs are open — the populated diff is the gate, not the exit code.

### A3 — Archive the sweep diff as a permanent artifact
- **Task:** commit the raw `parity_diff.json` PLUS a markdown archive (`documents/operations/active/G3FullSweepDiff_2026-08-22.md`), mirroring the enumeration-half precedent `G3EnumerationDiff_2026-07-23.md`. It must live in the tracked tree, never only under gitignored `state/`.
- **Acceptance:** both files are `git add`-ed and present; the markdown names its date, the two source commits, the matched topology, and enumerates every `stages_only_in_left` entry and every `matches:false` shared stage. This artifact is on the MUST-KEEP-forever list. **State explicitly in the doc that A3 discharges §8 only for the matched-topology stages; the mac/win/cross-OS cells are dispositioned via A4/Phase B.**

### A4 — Ledger-wide gap enumeration → the Phase-B worklist (NEW; the real disposition input)
- **Task:** with a **quote-aware `csv.DictReader`** (or `live_lab_evidence_verifier` — never `awk -F,`, which reads the wrong column on the quoted comma-bearing fields), compare `live_lab_run_matrix.csv` (bash archive) against `live_lab_node_run_matrix.csv` (`--node`). Emit the definitive per-cell gap list: every column where bash `pass ≥ 1` and `--node` `pass == 0`. Commit it as a section of the A3 markdown (or a sibling `documents/operations/active/BashRetirementGapEnumeration_2026-08-22.md`).
- **Two mandatory caveats baked into the enumeration:**
  - **A ledger column is not proof.** For `two_hop`, do NOT read the aliased column — 35 historical rows are `traffic_test_matrix` masking `live_two_hop_validation`; take the pass count from the disambiguated stage id / its report artifact (§12.3, QH-07).
  - **Bash is not the oracle.** The list names *questions*, not verdicts; direction-diagnosis happens in Phase B.
- **Acceptance:** the enumeration lists every gap column with its bash-pass and `--node`-pass counts; the current expected shape is ~56 raw columns (of which ~12 are ledger-dialect false gaps and ~44 are real, per the GAP survey). Every listed column MUST map to exactly one Phase-B ledger entry (mechanical check in Phase B). This artifact is MUST-KEEP.

---

## PHASE B — Per-cell adjudication (each cell: prove-on-node OR owner-signed disposition)

**Input = the A4 enumeration (union with any A3 `matches:false` / `stages_only_in_left` rows).** For **every** gap cell, produce exactly one disposition. **Bash is not the oracle** — a difference is a question, not a verdict. Record each in a named ledger `documents/operations/active/BashRetirementDispositions_2026-08-22.md`, mirroring the `NodeEngineFlipDispositions_2026-07-24.md` D1/D2/D3 template.

Phase B runs in two passes: **B-initial** (commitments + non-code dispositions, before Phase C) and **B-final** (after Phase C, convert every unmet prove-on-node commitment to an owner-signed "deferred G2 attainment"). No cell may remain un-adjudicated after B-final.

### B-RULE (applies to every B entry)
Each ledger entry MUST carry: (a) cell/stage id + sweep/ledger status + root cause; (b) direction verdict — either "genuine `--node` drop → prove on node at run `<id>`" **or** "node supersedes bash: `<the OS case / vuln / closed fail-open>`"; (c) owner sign-off line with date; (d) expiry / re-review date (no permanent silent exemptions); (e) for any T4 **security** cell, owner-level sign-off is mandatory and NOT delegable. Every deferral must also be mirrored into `NodeEngineAcceptanceSpec` §6.1's list.
- **Forbidden move (auto-reject):** never silently edit `--node` to match bash to close a diff. That re-introduces the exact legacy defect the divergence may have fixed.
- **Phase acceptance (mechanical):** every A4 column and every A3 `matches:false`/`stages_only_in_left` row maps to exactly one signed B ledger entry; zero un-dispositioned cells remain.

### B1 — Drop the ~12 ledger-dialect false gaps (do NOT chase)
- **Task:** for each bash-dialect column already proven under a differently-named `--node` column (`macos_authenticode`→`macos_stage_authenticode_check`, the five `linux_*`→`linux_stage_*_check`, `*_hello_limiter_flood`, `linux_membership_genesis`→`linux_stage_membership`, the macOS `mesh_status`/`runtime_acls`/`service_hardening` pairs, etc.), record a "node proves this under `<column>`; not a real gap" disposition.
- **Acceptance:** ~12 entries, each naming the `--node` column and its current pass count; none scheduled for prove-on-node work.

### B2 — Windows column (~30 cells) → dispositions behind CP-4 + code gaps
- **Task:** record all Windows cells past `present`/`cleanup` as one grouped disposition: "gated behind `windows_stage_bootstrap` (CP-4). Prove-on-node deferred to Phase C bootstrap triage; if unresolved, owner-signed 'deferred G2 attainment'." Then, separately:
  - **Windows `exit`** carries a SECOND obstacle (CP-3 WinNAT — needs physical `windows-x86-1`) → disposition as hardware-gated.
  - **Windows `blind_exit`** is **design-excluded** (`main.rs:13957` hard-errors) → disposition "🚫 not a gap." (`windows_blind_exit_reversal_denied` is the negative assertion that the refusal holds — gated behind bootstrap, not excluded.)
  - **Windows `anchor` / gossip cells** carry code gaps *independent* of bootstrap: no gossip transport (`windows.rs:157-160`), no self-issued signed bundles (`windows.rs:288-311`). Disposition: "code gap / intended-divergence — deferred G2, not fixable in this program."
- **Acceptance:** ledger shows the CP-4 group entry, the CP-3 Windows-exit entry, the design-excluded blind_exit entry, and the two Windows code-gap (gossip/bundle) entries. Each Windows **security** cell (`windows_membership_revoke_applies`, `_signature_forgery`, `windows_policy_default_deny`, `windows_privileged_helper_allowlist`, `windows_revoked_peer_denied_e2e`, `windows_blind_exit_reversal_denied`, etc.) is flagged T4 → owner-level sign-off required.

### B3 — macOS roles → prove-on-node commitments (feed Phase C)
- **Task:** for `macos_exit`+`macos_stage_exit_handoff`, `macos_blind_exit`+`macos_stage_blind_exit`, `macos_anchor`+`macos_stage_anchor`, and `macos_client` (CP-1), record "genuine — commit to prove-on-node" with a pointer to the specific Phase-C task id. Split the anchor entry: **election + `mesh_join`** are prove-on-node (C2/C3); **`gossip_seed` / `enrollment_endpoint`** lack runtime enforcement and are a separate owner-signed "deferred — code gap" disposition, NOT prove-on-node. `macos_blind_exit` explicitly flags the transition as irreversible/destructive (sacrificial guest required, owner-authorized). If Phase C fails to land a green in scope, B-final converts the commitment to owner-signed "deferred G2 attainment" — never silent match-to-bash.
- **Acceptance:** four prove-on-node entries each naming their Phase-C task id + the green acceptance criterion; one anchor `gossip_seed`/`enrollment_endpoint` deferral entry.

### B4 — Cross-OS cells → dispositions gated on B2+B3
- **Task:**
  - `cross_os_peer_visibility` (real dataplane fail, bash 98 / node 0) → commit to Phase-C prove-on-node (C5).
  - `cross_os_anchor_bundle_pull` / `role_switch` / `lan_toggle` / `anchor_enrollment` (skip / not_run, never attempted) → "gated on macOS election (B3) + Windows bootstrap (B2); prove-after-unblock or defer."
  - `cross_os_exit_path` is **0/0 on BOTH engines** — unproven, not a bash-green gap; disposition says so and does not claim a bash baseline.
- **Acceptance:** five entries; each names its blocking dependency; none claims a bash-green baseline that does not exist.

### B5 — Relay frame-forwarding (HP-3) → parked disposition
- **Task:** `macos_relay` / `windows_relay` / `linux_relay` (role summaries, bash-green / node 0) are MIXED: relay **lifecycle** is already `--node`-proven (`*_stage_relay_service_lifecycle`, e.g. macOS 6 pass); only **frame-forwarding = HP-3** is unproven, and it is parked on ALL OS. Record: "lifecycle proven under `<column>`; frame-forwarding = HP-3 parked cross-OS → owner-signed deferred, not a macOS/Windows-election gap."
- **Acceptance:** three entries (one per OS), each naming the proven lifecycle column and the HP-3 park.

### B6 — Residual Linux gap cells (in raw diff, out of prove-on-node scope)
- **Task:** `linux_stage_blind_exit` (bash 8 / node 0 — `--node` deliberately `skip`s it; running an irreversible blind_exit would brick a lab node) → "node supersedes bash: deliberate drift-correction, not a defect." `linux_stage_chaos` (bash 12 / node 0 — never run on `--node`) → "deferred / out of mac-win-cross-OS scope."
- **Acceptance:** two entries; the `linux_stage_blind_exit` one is an explicit option-(b) "node supersedes bash," not a prove-on-node.

---

## PHASE C — Stabilize the named engineering blockers

Executes the engineering for every B "prove-on-node" commitment. Order is by independence (cheapest/lowest-risk first), not by cell. Each task has a self-checkable green, verifier-recomputed — never self-reported.

### C-STUN — Thread `RUSTYNET_TRAVERSAL_STUN_SERVERS` in the node-deploy path (low-risk hygiene; NOT on the in-scope critical path)
- **Task:** the orchestrator sets STUN nowhere (`vm_lab/` grep = 0 non-test hits); empty disables srflx candidate gathering (`daemon.rs:4364-4370`). Thread a lab STUN endpoint (e.g. `100.64.0.254:3478`) into the Linux/macOS/Windows node-deploy env. **Scope note:** the in-scope prove-on-node greens (C1 macOS two_hop, C3 macOS exit, C5 cross_os_peer_visibility) are same-LAN and satisfied by host candidates, so C-STUN does NOT gate them. It is a prerequisite ONLY for any *cross-network* exit cell — which are out of scope here (vxlan needs a real 2nd physical network). Land it as hygiene so a future cross-network exit is not silently proven via LAN-host shortcuts; do not block Phase C on it.
- **Acceptance:** a deployed daemon in a lab run logs a non-empty `traversal_stun_servers` and schedules `next_stun_refresh_at`; the STUN observation task is not filtered off. Gate: `cargo test -p rustynet-cli --all-targets --all-features` green after the wiring.

### C1 — CP-1 macOS `two_hop` fresh triage → fix
- **Task:** pull a CURRENT macOS `two_hop` report (not the stale hypothesis), triage root cause, fix. §13.2 security-sensitive (dataplane) — run the security review checklist.
- **Acceptance:** a `--node` macOS run shows `two_hop=pass` (and consequently `traffic_test_matrix≠fail`), row verified in `live_lab_node_run_matrix.csv` and recomputed by `live_lab_evidence_verifier`. If triage concludes `--node` is correct and bash was a false-green, that becomes a B3 "node supersedes bash" disposition instead — no code change forced.

### C2 — macOS anchor `mesh_join` retry-budget flake
- **Task:** `validate_macos_mesh_join` fails intermittently on anchor elections (6-attempt budget too tight for `deploy_macos_anchor_profile` + membership-distribution latency). Raise the anchor-topology retry budget or cut deploy latency (`live_lab_stage_registry.rs:1018`).
- **Acceptance:** 5 consecutive `--anchor-platform macos` `--node` runs show `validate_macos_mesh_join` pass (was 3/5); no regression to non-anchor budgets.

### C3 — Drive macOS exit / blind_exit / anchor elections green
- **Task:** run the never-exercised selectors (`--macos-promote-exit`/`--exit-platform macos`, `--blind-exit-platform macos` on a sacrificial guest, `--anchor-platform macos`) to green. macOS exit needs the end-to-end **egress assertion** (a client's packets provably egress the macOS exit to an external target) — lifecycle/NAT-teardown proof alone does NOT satisfy G2.
- **Acceptance:** `macos_exit`+`macos_stage_exit_handoff`, `macos_anchor`+`macos_stage_anchor` each show ≥1 `pass` in `live_lab_node_run_matrix.csv`, verifier-recomputed; the macOS exit run's report contains the egress assertion, not just NAT lifecycle. `macos_blind_exit` proven on a guest that is then factory-reset (irreversible — owner must authorize the sacrificial guest before this runs). `gossip_seed`/`enrollment_endpoint` are NOT claimed green here (B3 defers them).

### C4 — CP-4 Windows bootstrap triage (gates the whole Windows column)
- **Task:** triage `windows_stage_bootstrap` (5 fail / 0 pass) — determine code vs guest-health. The install path is code-complete (`windows_install.rs:133,200-269`); the guest is x86-emulated on Apple Silicon. If code, fix; if guest-health, that is a lab-substrate disposition (needs `windows-x86-1`).
- **Acceptance:** EITHER a `--node` run shows `windows_stage_bootstrap=pass` (verifier-recomputed) → unblocks B2 Windows cells for prove-on-node; OR a signed disposition records the concrete environmental cause + the hardware needed. The standing code gaps behind bootstrap (no gossip transport `windows.rs:157-160`; no self-issued bundles `windows.rs:288-311`) are NOT in scope to fix — they stay dispositioned per B2.

### C5 — `cross_os_peer_visibility` dataplane fix
- **Task:** on a Linux+macOS pair that reaches `cross_os_bootstrap=pass`, the cross-OS mesh does not fully ping (`traffic_test_matrix`, 16 fail / 0 pass). Triage and fix the real cross-OS reachability defect. **Direction-diagnosis applies:** if triage shows `--node` is correct and the bash green was invalid, that is a B4 "node supersedes bash" disposition, not a forced code change.
- **Acceptance:** a **multi-OS** `--node` run shows `cross_os_peer_visibility=pass`, verifier-recomputed. (Single-OS runs write no column — confirm the green is a genuine multi-OS run.)

**Out-of-scope for C (disposition-only, do not attempt to fix here):** CP-3 WinNAT (hardware), Windows blind_exit (design-excluded), Windows gossip/bundle-issuance code gaps (B2), HP-3 relay frame-forwarding (parked, B5), anchor `enrollment_endpoint` runtime enforcement (B3), the vxlan cross-network suite (needs a real 2nd physical network), `slirp` cross-OS smoke (unimplemented dispatch arm — flag as a known code gap, not a program deliverable).

---

## PHASE D — Owner sign-off (NONE self-approvable by the delegate)

The delegate PREPARES these for signature and STOPS; it never marks them approved itself.

- **D1 — Loss of the rollback lever.** Owner signs explicit comfort that Phase E removes `--legacy-bash-orchestrator` with no fallback.
- **D2 — Every option-(b) disposition, individually.** Owner signs each "node supersedes bash" / "deferred G2 attainment" line with reason + expiry (includes the B-final conversions of unmet C commitments).
- **D3 — Every T4 security-cell disposition, at owner level.** Not dispositionable below owner (Spec §6.1).
- **D4 — The spec-side mirror.** Owner approves that the full disposition set is mirrored into `NodeEngineAcceptanceSpec` §6.1/§6, not only in the standalone B ledger.
- **D5 — Final G3-satisfied sign-off.** Owner signs that the A3 sweep ran + is archived, the A4 enumeration is complete, and every A4 gap cell is proven-on-node or owner-signed-dispositioned.
- **Acceptance:** each of D1–D5 carries a dated `APPROVED <date> (owner …)` line authored by the owner; the delegate's role is complete when the prepared, unsigned ledger is handed back — a delegate-authored approval line is an automatic program failure.

---

## PHASE E — The ONE cross-scope code deletion

A single atomic, integrator-run, reviewable commit (touches WS-A/WS-B/WS-C). Execute exactly the `BashRetirementPlan_2026-07-24.md` §3 inventory as refined by the verify-not-trust corrections below. **All Phase-A archives (A3 + A4) must exist and D5 must be signed before this starts.**

### E-corrections (verified against tree — override any conflicting seed reading)
- **`scripts/e2e/live_lab_common.sh` is RETAINED,** not deleted — it is `source`d by 9 surviving cross-network scripts (8 `live_linux_cross_network_*_test.sh` + `test_live_lab_ssh_windows.sh`). Deleting it breaks them. (Owner may expand scope via the decision block; default is retain.)
- **`scripts/ci/orchestrator_engine_gates.sh` is REWIRED,** not deleted — it gates the surviving **Rust** engine. Remove only the `run_orch "bash_registry" …every_bash_orchestrator_stage_literal_is_registered` line (~62-63) + its comment.
- **`scripts/ci/anchor_live_lab_gates.sh:13` is REWIRED** — drop the `rg -q 'stage_run_live_anchor' …live_linux_lab_orchestrator.sh` assertion; keep the Rust anchor gate.
- **The `include_str!` pins in `macos_install.rs` are `#[cfg(test)]` and are TWO distinct pins — delete only the orchestrator one.** Delete the `LIVE_LINUX_LAB_ORCHESTRATOR` pin (`macos_install.rs:49-50`) and only the content-parity tests that reference `LIVE_LINUX_LAB_ORCHESTRATOR` (~lines 1123-1497). **KEEP the `LIVE_LAB_COMMON` pin (`macos_install.rs:51-52`) and its tests (~lines 1156-1607)** because `live_lab_common.sh` is retained — deleting the whole ~1123-1607 block (as an earlier reading proposed) destroys valid tests for a retained file and is a compile/coverage regression. KEEP the `MACOS_/WINDOWS_BOOTSTRAP_WRAPPER` blocks. (If the owner picks Option B and deletes `live_lab_common.sh`, then and only then also delete the `LIVE_LAB_COMMON` pin + its tests.)
- **The frozen ledger stays; only the WRITER dies.** Keep `default_live_lab_run_matrix_path()` (`live_lab_run_matrix.rs:421`) and `LedgerEngine::BashArchive` (`rustynet-mcp/src/lib.rs:388-468`) — the MCP `bash_archive` reader is live. Delete the bash writer/routing only.
- **`native.rs` lives at `orchestrator/native.rs`, not `adapter/native.rs`.** The bash orchestrator has **5 entrypoints**, not one (E-entrypoints).

### E-tasks (all in the one commit; must compile+test together)
- **E-scripts:** delete `live_linux_lab_orchestrator.sh`, `orchestrator_parity_diff.sh` (only after A3 archive); rewire the two ci gate scripts; update `scripts/e2e/README.md`; **retain** `live_lab_common.sh`.
- **E-compile-couplings [same commit mandatory]:** the `LIVE_LINUX_LAB_ORCHESTRATOR` `include_str!` pin + its content-parity tests in `macos_install.rs` (per E-corrections precision); the `every_bash_orchestrator_stage_literal_is_registered` self-test (`live_lab_stage_registry.rs:2793`) + its bash-dialect comment. Keep `every_rust_state_machine_stage_id_is_registered` + `every_monitor_fallback_catalog_stage_is_registered`.
- **E-flag:** remove `--legacy-bash-orchestrator` end to end — `main.rs:4496,20638`; `vm_lab/mod.rs:1254,1365-1378,11891-11950`; `topology.rs:909`; the mutual-exclusion checks; the lab-monitor launch path `crates/rustynet-lab-monitor/src/control/launcher.rs` + `config.rs`/`data/run_verification.rs` (workspace-excluded — gate separately); **and `rustynet-mcp/src/bin/ai_agent.rs`** (the `--legacy-bash` / `n:true` selector docs + arg-forwarding). **KEEP `LedgerEngine::BashArchive` in `lib.rs:388-468`** (frozen-ledger reader).
- **E-entrypoints (5, not 1):** `LinuxBashOrchestrator` + `trait StageOrchestrator` (`mod.rs:10512-10574`); `execute_ops_vm_lab_run_live_lab` + `vm-lab-run-live-lab`; the bash tail of `execute_ops_vm_lab_setup_live_lab` (REWIRE — keep `--node` setup); `vm-lab-iterate-live-lab`; the bash branch of `execute_ops_vm_lab_orchestrate_live_lab` (`mod.rs:11951+`, becomes native-only, drop `script_path` plumbing); the `full-live-lab` arm of `build_suite_command`.
- **E-writer/dialect/parity:** drop `OrchestratorDialect::LegacyBash` (`context.rs:22-33`); delete the bash EXIT-trap writer `execute_ops_append_orchestrator_run_to_matrix` + `append-orchestrator-run-to-matrix`; collapse the `is_node_run?` branch in `append_live_lab_run_matrix_row` (route unconditionally to the node path) and update the `default_live_lab_run_matrix_path()` doc-comment to "read-only via MCP bash_archive"; delete the **functional** half of `parity.rs` (`canonical_stage_id` bash-alias map + `diff_live_lab_reports_functional` + tests) — **KEEP the Strict rust-vs-rust diff**; remove `vm-lab-diff-orchestrator-parity` only after A3; remove the `active_plan=None` "BASH PATH" branch + its tests in `live_lab_stage_manifest.rs`; verify (do not blind-delete) the `live_lab_run_matrix.rs` negative-vocabulary test region (4409-4429) is a bash-only guard before removing; doc-comment cleanups in `native.rs`/`bin/live_lab_support`/`role_assignment.rs`/`live_lab_coverage.rs`. **KEEP the `/bin/bash -lc` guest-exec in `bin/live_lab_support`** (runs commands on Linux guests, unrelated to the engine).
- **E-comment-refs (update, don't delete):** `role_assignment.rs:8`, `bin/live_linux_two_hop_test.rs:177`, `bin/live_linux_managed_dns_test.rs:2811`, `rustynetd/src/linux_runtime_acls.rs:15` — restate/drop the dead script refs (the last two reference `live_lab_common.sh`; leave as-is under Option A, update under Option B).
- **E-docs:** move `documents/operations/LiveLinuxLabOrchestrator.md` → `documents/archive/`; update `LiveLabRunMatrix.md`, both `README.md` indexes, `rustynet_live_lab_loop_prompt.md`; sweep the active ledgers that describe *current* behavior via the script (`CrossPlatformRoleParityRoadmap`, `CrossNetworkSubstrateIntegrationSpec`, `DeepSeekLiveLabOrchestrationPipeline`, `LiveLabFindings`, etc.) — leave `documents/archive/*` untouched; update the §2/§12.5 "legacy bash-orchestrator archive" wording in **both** `CLAUDE.md` and `AGENTS.md` [mirror — finish with `cmp AGENTS.md CLAUDE.md`].
- **Acceptance:** the deletion is ONE commit; `git grep -n 'legacy_bash_orchestrator\|--legacy-bash-orchestrator\|live_linux_lab_orchestrator.sh'` returns only intended survivors (frozen-ledger reader comments, retained cross-network scripts, archive docs); the tree compiles under both default-feature and `--features vm-lab`.

### DECISION REQUIRED (owner) — cross-network bash suite scope
`build_suite_command`'s cross-network arms + the 8 `scripts/e2e/live_linux_cross_network_*_test.sh` + `test_live_lab_ssh_windows.sh` + `live_lab_common.sh` are a SECOND bash surface BashRetirementPlan §3 does not enumerate. They are the only proof for the `cross_os_*` bash-only cells.
- **Option A (default, plan-literal):** delete only the `full-live-lab` arm; RETAIN the cross-network suite + `live_lab_common.sh` (+ its `macos_install.rs:51-52` pin/tests + the E-comment-refs). Smallest blast radius.
- **Option B (full retirement):** requires the `cross_os_*` cells first proven on `--node` (C5 + C-STUN) or owner-dispositioned, THEN delete the whole suite (and the `LIVE_LAB_COMMON` pin/tests + F3-equivalent comment refs).
Recommend Option A unless Phase-B/C already cover the cross_os cells — Option B otherwise silently drops their only evidence.

---

## PHASE F — Post-deletion verification

The deletion must not perturb the `--node` path.
- **F1 — Builds:** `cargo check --workspace --all-targets --all-features` AND a bare default-feature `cargo build -p rustynet-cli` (shipped binary carries no `vm-lab`). Both exit 0.
- **F2 — Gates:** `cargo fmt --all -- --check`; `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`; `cargo test --workspace --all-targets --all-features`; `cargo audit --deny warnings`; `cargo deny check bans licenses sources advisories`; `./scripts/ci/lab_monitor_gates.sh` (E touched the workspace-excluded crate). All green.
- **F3 — Rewired gates:** `scripts/ci/orchestrator_engine_gates.sh` and `anchor_live_lab_gates.sh` both green with no bash refs.
- **F4 — Green `--node` live run:** drive one via the engine of record; verify the appended row in `live_lab_node_run_matrix.csv` AND recompute it with `live_lab_evidence_verifier` (Spec §4.8 — a run counts only as verifier-recomputed, never self-reported).
- **F5 — Close-out:** mark Spec §8 (G3) satisfied; move `BashRetirementPlan_2026-07-24.md` and this program doc to `documents/operations/done/`; update `active/README.md`; `cmp AGENTS.md CLAUDE.md` clean.
- **Acceptance:** F1–F4 all pass on the post-deletion tree; F5 index/mirror clean.

---

## DEFINITION OF DONE

All true:
1. **Bash orchestrator deleted** — the BashRetirementPlan §3 surface (as E-refined) is gone in one reviewable commit; `git grep` shows only intended survivors.
2. **`--node` is the sole engine** — no `--legacy-bash-orchestrator`, no bash dispatch, no rollback lever.
3. **All gates pass** — the full §7 list (F2) green, including the workspace-excluded lab-monitor crate.
4. **A green `--node` live run** — F4, verifier-recomputed, row present in the `--node` ledger.
5. **G3 satisfied** — the A3 matched-topology sweep ran + is archived, the A4 ledger enumeration is complete + archived, and **every A4 gap cell** (not merely the A3 report-diff rows) is proven-on-node or owner-signed-dispositioned, with the disposition set mirrored into Spec §6.1.
6. **Archives kept** (below), plan retired, indexes + AGENTS/CLAUDE mirror synced.

---

## MUST-KEEP — never delete (Spec §8 / BashRetirementPlan §3)

- `documents/operations/live_lab_run_matrix.csv` — frozen bash ledger (~1 MB). Historical evidence; **never crossed with the `--node` ledger.**
- The archived G3 artifacts — the enumeration half `G3EnumerationDiff_2026-07-23.md`, the Phase-A sweep `G3FullSweepDiff_2026-08-22.md` + raw `parity_diff.json`, AND the A4 ledger-gap enumeration. Must survive the harness deletion.
- `default_live_lab_run_matrix_path()` (`live_lab_run_matrix.rs:421`) + `LedgerEngine::BashArchive` (`rustynet-mcp/src/lib.rs:388-468`) — read-only frozen-ledger accessors (MCP `engine=bash_archive`, lab-monitor archive view).
- The entire `--node` engine, `orchestrator/native.rs`, `live_lab_node_run_matrix.csv`, `NodeEngineAcceptanceSpec` (native-spec — survives bash by design).
- `parity.rs` **Strict** (rust-vs-rust determinism) diff; the Rust halves of `orchestrator_engine_gates.sh` / `anchor_live_lab_gates.sh`.
- `MACOS_/WINDOWS_BOOTSTRAP_WRAPPER` `include_str!` pins + tests in `macos_install.rs`; the `LIVE_LAB_COMMON` pin + tests (Option A); `/bin/bash -lc` guest-exec in `bin/live_lab_support`; `scripts/e2e/live_lab_common.sh` and the cross-network suite (unless owner picks Option B).
- The disposition ledger `BashRetirementDispositions_2026-08-22.md` + `NodeEngineFlipDispositions_2026-07-24.md`.

---

## OWNER-SIGN-OFF GATES — a sub-agent MUST NOT self-approve

The delegate prepares evidence and STOPS at each; it never writes an approval line itself:

1. **A0 deletion preconditions** — G1 + soak (delegate presents the enumerated green-run count; owner judges sufficiency) + rollback-lever-loss comfort + labs-quiet/token-held.
2. **Each option-(b) disposition** (D2) — one owner signature per "node supersedes bash" / "deferred G2" line, with reason + expiry (incl. B-final conversions).
3. **Every T4 security-cell disposition** (D3) — owner level only; not delegable.
4. **The Spec §6.1 mirror** (D4).
5. **Final G3-satisfied sign-off** (D5) and the Phase-E go-ahead (the atomic deletion is integrator-run under the held token).
6. **The cross-network suite scope decision** (Option A vs B).
7. **Authorizing the sacrificial macOS guest** for the irreversible `macos_blind_exit` proof (C3).

A delegate-authored approval on any of these is an automatic program failure. Deleting the rollback lever (Phase E) is irreversible — it proceeds only on the owner's D1+D5 signatures, never on the delegate's judgment.

---

**Files this program creates/moves (for the landing change):** new `documents/operations/active/BashOrchestratorRetirementProgram_2026-08-22.md` (this doc) + `active/README.md` entry + AGENTS/CLAUDE §2 mirror; Phase A creates `G3FullSweepDiff_2026-08-22.md` + `parity_diff.json` + the A4 ledger-gap enumeration; Phase B creates `BashRetirementDispositions_2026-08-22.md`; Phase F moves this doc + `BashRetirementPlan_2026-07-24.md` to `done/`.

---

**Summary of corrections applied to the draft:**
1. **(a/c) Surface/dependency fix — the biggest hole:** added **A4 (ledger-wide gap enumeration)** as Phase B's actual input and re-scoped A3 to "matched-topology mechanical §8 gate only." The draft drove Phase B off A3, whose single green-able topology can never name a mac/win/cross-OS cell — making DoD #5 falsely satisfiable. Rewrote Phase B input, B-RULE acceptance, DoD #5, and D5 accordingly.
2. **(a) Missed disposition cells:** added **B5** (relay frame-forwarding HP-3, all 3 OS), **B6** (`linux_stage_blind_exit` drift-correction + `linux_stage_chaos`), the missing cross-OS cells `lan_toggle`/`anchor_enrollment` in B4, and the anchor `gossip_seed`/`enrollment_endpoint` + Windows gossip/bundle code-gap dispositions in B2/B3 — so "every gap row disposed" is actually reachable.
3. **(a/d) Delete-too-much bug:** corrected the `macos_install.rs` E-correction to delete only the `LIVE_LINUX_LAB_ORCHESTRATOR` pin+tests and **keep** the `LIVE_LAB_COMMON` pin+tests (retained file) — the draft's "~1123-1607 block" would have destroyed valid tests for a must-keep script.
4. **(a) Missed deletion site:** added `rustynet-mcp/src/bin/ai_agent.rs` `--legacy-bash` selector removal (keeping `BashArchive` reader) + the two bin-test comment refs + `linux_runtime_acls.rs:15` + the broader active-ledger doc sweep.
5. **(b) Vague acceptance:** made A0 a concrete delegate-prep task (enumerate green `--node` runs since flip commit `a414ceb`, quote-aware) with the sufficiency judgment left to the owner; baked the quote-aware-reader + two_hop-alias caveats into A4; clarified C-STUN is off the in-scope critical path; added the direction-diagnosis escape to C5; split Phase B into B-initial/B-final so unmet prove-on-node commitments convert to signed deferrals rather than dangling.