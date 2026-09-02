# Live-Lab Stage Pass-Likelihood — Cross-OS Summary — 2026-09-01

**Status:** docs-only consolidation of the three same-day bucket analyses (macOS+cross-OS,
Windows, Linux) into one ranked cross-OS picture. No code changed; every verdict below is a
prediction with citations to the bucket docs, not a live observation.

**Engine of record:** the Rust `--node` orchestrator. The bash archive
(`live_lab_run_matrix.csv`) is not evidence anywhere in this document.

**Lab status at time of writing: DOWN. Nothing here is a live pass claim.**

**The cross-OS picture in one paragraph.** Linux is essentially green — its headline
finding is that `linux_stage_two_hop` is genuinely passing post-alias-removal (26
post-removal run passes, 130 per-stage Linux node-row passes, written by the only two-hop
`StageId`, `live_two_hop_validation`), and its genuine gaps are scheduling/gating: an
opt-in chaos suite never once selected, one unresolved `blind_exit_dataplane_check`
failure, an opt-in Disruptive relay stage never scheduled, and seven duplicate-by-supersession
bare columns. macOS is mostly WIRING skips behind the `--skip-linux-live-suite` fast path
(~17 cells whose stages pass on Linux), one big ENVIRONMENTAL blocker (CP-1: no L3 path
between the macOS UTM Shared-NAT subnet and bridge100, measured live 2026-08-29), and about
six Linux-only validator/adapter gaps (the exit-family validators and the orchestrator's
active-exit-serving adapter are Linux-only, `active_exit.rs:184`). Windows is a
bootstrap-gated cascade: `windows_stage_bootstrap` is 5 fail / 0 pass (3 real, 2
run-scoped-preflight-poisoned), holding ~30 downstream 0-pass columns, with the §4.7
`status`-subcommand identity gate waiting behind it for the entire per-node `_check`
family.

All three bucket docs were merged the same day after verification; per-stage citations are
treated as verified here. One correction is already applied in the Linux bucket doc and is
carried forward: the 26 post-removal `linux_stage_two_hop` passes are written by
`live_two_hop_validation` (the ONLY two-hop StageId, `stage/mod.rs:238`; 130 Linux pass
node-rows in `live_lab_node_stage_results.csv`), NOT by the bash-dialect `live_two_hop`
registry spec — and the "0 pass lifetime" figure for that stage id is a stale 2026-07-27
count quoted in the `live_lab_run_matrix.rs` doc-comment (lines ~443-452, counted at commit
`9cdd660f`).

---

## 1. Ranked table — Highest-leverage fixes, cross-OS

Ordered by (cells unlocked × pass-likelihood) / effort. Kind: NO-CODE RUN (a lab run with
selectors only), OPERATOR (human/physical action, explicit authorization where noted), CODE
(a code change), DESIGN-GATED (behind an owner-gated design). Cells are exact
`live_lab_node_run_matrix.csv` column names. Every row traces to a bucket-doc entry.

| Rank | Action | Kind | Cells it unlocks | Root-cause class | Size | Pass-likelihood after | Source |
|---|---|---|---|---|---|---|---|
| 1 | One full-suite macOS client run (no `--skip-linux-live-suite`), no code changes | NO-CODE RUN | `macos_stage_role_switch_matrix`, `macos_stage_reboot_recovery`, `macos_stage_secrets_not_in_logs`, `macos_stage_key_custody`, `cross_os_role_switch` | WIRING/GATE | S | High | macOS §1, §2, §5#1 |
| 2 | `anchor_platform=macos` re-run (fixes landed: `e3297391`, `451f9730`) harvesting the already-proven MAC-D1 stages | NO-CODE RUN | `macos_stage_anchor` (via `anchor_validation` + `cross_os_anchor_bundle_pull`, both already 1-pass proven) | WIRING/GATE | S | High for `anchor_validation`/`bundle_pull`; Medium overall until the authority cell | macOS §1, §5#4 |
| 3 | Chaos-suite selector flip (`--enable-chaos-suite`) on a scheduled run | NO-CODE RUN | `macos_stage_chaos` + the nine Linux chaos stage ids (all 242/242 `not_run`) | WIRING/GATE | S | Medium (first run is triage; adversarial suites earn their keep by failing) | macOS §1; Linux §4 |
| 4 | Focused Linux `blind_exit_dataplane` run with the role explicitly elected (`debian-headless-4`) | NO-CODE RUN | `linux_stage_blind_exit_dataplane_check` (one 2026-07-11 fail, rest skip) | WIRING/GATE (possible code component in the one fail, unresolved) | S | Medium-Low (resolves the oldest genuine unknown either way) | Linux §3 |
| 5 | `relay_forwards_frame` Disruptive opt-in (`--enable-relay-forwarding-validation`) once, in a lab window with slack | NO-CODE RUN | `linux_relay_forwards_frame` | WIRING/GATE (opt-in by design, never scheduled) | S | Medium (first verdict of any kind) | Linux table §"dead legacy columns"; Refresh §1 relay row |
| 6 | mac `blind_exit` topology in a full-suite run | NO-CODE RUN | `macos_stage_lan_toggle` | WIRING/GATE | S | Medium | macOS §1, §5#5 |
| 7 | Same full-suite run, add an `aux`-role node | NO-CODE RUN | `macos_stage_enrollment_restart` | WIRING/GATE | S | Medium-High | macOS §2, §5#2 |
| 8 | CP-1: operator `prepare_lab_network` bridged re-attach of macos-utm-1 onto the 192.168.64.0/24 segment (explicit operator authorization per the LiveLabVmConnectivityRulebook — never an autonomous mutation), then a focused `rebuild_nodes` macOS run | OPERATOR | `macos_stage_two_hop` (first-ever macOS dispatch of `live_two_hop_validation`), `cross_os_peer_visibility`, `macos_client`/`traffic_test_matrix` face | ENVIRONMENTAL | S-M | High | macOS §1, §5#3; Refresh CP-1 verdict 2026-08-29 |
| 9 | W-FIX-4: UTM-console remediation of windows-utm-1 (enable sshd + firewall rule, `w32tm /resync`), then minimal topology `debian-headless-2:exit` + `windows-utm-1:client` re-run | OPERATOR | `windows_stage_bootstrap` + ~30 downstream `windows_stage_*` columns (skip-cascade) | WIRING/GATE (guest remediation; W-FIX-1 landed but never lab-verified) | M | Medium | Windows §3.1, §4#1 |
| 10 | W-FIX-5: restore `ubuntu-kvm-1` (tailnet `100.117.1.47` and LAN `172.23.56.5` both dead on TCP/22) | OPERATOR | windows-x86-1 admin/exit/anchor slots; unlocks failure #5's report (`/home/ubuntu-server/lab-reports/winnat-*`) | ENVIRONMENTAL | S | n/a directly (evidence + guest access; failure #5 may name a second defect) | Windows §2, §4#3 |
| 11 | CP-3: procure/allocate a physical Windows 11 Pro/Enterprise ARM device | OPERATOR (hardware) | `windows_stage_exit`, the exit `_check` trio (`windows_stage_ipv6_leak_check`, `windows_stage_exit_demotion_residue_check`, `windows_stage_exit_dns_failclosed_check`, `windows_stage_exit_nat_lifecycle_check`) | HARDWARE | L | ~Zero in current lab; this is the only path (code path `promote_windows_exit_active` already complete) | Windows §3.4, §4#4 |
| 12 | Windows `status` subcommand (live node identity + role emission, cross-platform key=value contract); do NOT widen the identity gate | CODE | all 11 `windows_stage_*_check` columns + the validator-backed specials (`windows_dpapi_key_custody` etc.) | CODE-DEFECT (deferred §4.7 gap at `node_adapter.rs:516-524`) | M | Low today → the family becomes runnable once bootstrap is green; the gate's fail-closed posture is the control being tested | Windows §3.2, §4#2 |
| 13 | macOS exit-serving adapter on the orchestrator (`active_exit.rs:184` + `adapter/macos.rs`), with the S2 end-to-end egress assertion (not a mechanism-translated nft assertion) | CODE | `macos_stage_exit_handoff`, `cross_os_exit_path` | CODE-DEFECT (adapter is Linux+Windows only) | M-L | Low until CP-1; Medium once adapter + network land (overall exit green still needs #19) | macOS §1 exit_handoff, §5#9 |
| 14 | pf ports of the four Linux-only validators: `exit_nat_lifecycle` (two-phase), `exit_demotion_residue`, `blind_exit_dataplane` (sequence after a Linux green), `ipv6_leak` (pre-check lab v6 egress first — may be environmental) | CODE | `macos_stage_exit_nat_lifecycle_check`, `macos_stage_exit_demotion_residue_check`, `macos_stage_blind_exit_dataplane_check`, `macos_stage_ipv6_leak_check` | CODE-DEFECT (deliberate fail-closed Linux-only stubs, `role_validation/*.rs` predicates) | S-M each | Low each (need the role elected first) | macOS §2 |
| 15 | ~~Wire an `--enable-soak-suite` selector through `TargetSelectors`/orchestrator flags + mac/win target keys~~ — **Corrected 2026-09-02: RETRACTED — premise refuted.** No action: `extended_soak` already dispatches in the default Linux full-suite plan (`plan.rs` `include()`: `StageSuite::Soak => !skip_live_suite && !skip_soak`; `--skip-soak` opts out); the per-stage ledger records 40 Linux pass node-rows (348 Linux skip) and the roll-up records 8 `linux_stage_extended_soak` run-level passes; the mac/win skips (15/2) are the `--skip-linux-live-suite` fast path by design | RETRACTED | ~~`macos_stage_extended_soak` (zero rows on every platform — never dispatched)~~ — per-stage truth: Linux 40 pass / 348 skip, macOS 15 skip, Windows 2 skip; the stage HAS dispatched and passed on Linux | ~~WIRING/GATE (missing enable flag; `live_lab_stage_registry.rs:336-346`)~~ — no missing flag; the `SoakSuite` rule (registry `:347`) already enables it in default Linux full-suite runs | S | ~~Medium (first dispatch is an unknown-unknown; expect a triage pass)~~ — n/a (retracted); the first macOS dispatch awaits a full-suite run, not a flag | macOS §1 extended_soak, §5#6 |
| 16 | Add `cross_os: Some("cross_os_lan_toggle")` to the `--node` `live_lan_toggle_validation` registry spec | CODE | `cross_os_lan_toggle` (structurally unfed: only the bash-dialect `live_lan_toggle` spec, registry `:1951`, feeds it) | CONTAMINATION/DEAD-COLUMN (unfed aggregate) | S | Medium (inherits lan_toggle's Medium once it runs cross-platform) | macOS §3, §5#6 |
| 17 | Confirm-then-fix: verify a `--node` StageId dispatches the mac role-transition cell when `--role-switch-platform macos` is set; if only in the legacy wrapper vocabulary, add the StageId + plan arm before spending a lab run | CODE | `macos_stage_role_transition` (242/242 not_run both OS) | WIRING/GATE (election knob exists at `live_lab_stage_registry.rs:1235-1236`; `--node` dispatch unconfirmed) | S | Medium (first run is triage) | macOS §1 role_transition, §5#6 |
| 18 | Refresh the stale QH-07 "0 pass" doc-comment in `live_lab_run_matrix.rs` (~443-452) with the Linux doc's correction (small docs/comment change, tracked with QH-07(b)/(c)) | CODE (comment) | none directly — prevents future `two_hop` misattribution | CONTAMINATION/DEAD-COLUMN (stale 2026-07-27 count at commit `9cdd660f`) | S | n/a (docs hygiene) | Linux §1 |
| 19 | macOS DNS fail-closed enforcement design (scoped resolvers / pf redirect to the daemon's resolver, killswitch-consistent; disposition `1278af04`), THEN the six-artifact macOS evaluator — never a validator that greens against unenforced posture | DESIGN-GATED | `macos_stage_exit_dns_failclosed_check`; last blocker for any overall-green macOS exit run | CODE-DEFECT under an owner-gated design (`MacosDnsFailclosedEnforcementGap_2026-08-28.md`) | L | Lowest in the macOS set until the design lands | macOS §2 exit_dns_failclosed, §5#10 |
| 20 | `anchor.port_mapping_authoritative` signed-capability rewrite folded into `MacosExitMembershipRoleFixDesign_2026-08-31.md` (not an ad-hoc patch) | DESIGN-GATED | the port-mapping-authority cell of `macos_stage_anchor` (`validate_macos_anchor_port_mapping_authority`) | CODE-DEFECT under an owner-gated design (macOS anchor's signed membership lacks the capability; Linux exit won the authority election) | M | Low until the rewrite; High for the rest of the anchor cell (row 2) | macOS §1 anchor, §5#4 |
| 21 | Windows gossip transport + self-issued signed bundles (deferred-by-design, `adapter/windows.rs:158-160`, `:288-311`) | DESIGN-GATED | windows anchor/gossip cells (`windows_stage_anchor` and the gossip-flavored specials) even after CP-4 | DESIGN-GATED (capability caps, not defects) | L | Low; correctly sequenced last | Windows §3.3, §4#5 |

Notes on two rows where bucket docs could be misread together: rows 1 and 7 are the same
run (the mac bucket doc prices them as one full-suite run plus an aux-role node), and row
13's cells additionally need row 8 (CP-1) for the traffic-facing half — the exit-handoff
validator itself is the adapter gap.

---

## 2. Phase C candidate queue — the top 6 CODE rows, expanded

These feed adversarial review before any implementation. File:line anchors are copied from
the bucket docs.

**1. Windows `status` subcommand (§4.7 identity gate).** Change: implement a `status`
subcommand on the Windows control CLI emitting live node identity + role as the
cross-platform `key=value` contract (e.g. `node_role=blind_exit`-style single-line
output), so `enforce_identity_challenge`
(`crates/rustynet-cli/src/vm_lab/orchestrator/adapter/node_adapter.rs:516-524`) accepts
real `LiveAssertion` evidence from a Windows node. The gate itself is the control under
test: it must stay fail-closed — it rejects `Unverifiable`, `NodeIdMismatch`, and
`NotLiveAssertion` before every role validator runs, and the test
`challenge_gate_rejects_non_live_config_file_identity` (`node_adapter.rs:685-697`) proves
that. Never work around it by widening the gate. Offline-testable core: the key=value
emission contract and its parser round-trip, plus the existing gate rejection tests
extended with a Windows-emitting fixture. Live proof that closes it: the
`windows_stage_*_check` family (`live_lab_stage_registry.rs:753-916`) dispatching and
passing on a bootstrapped Windows node — which requires row 9 (W-FIX-4) first.

**2. macOS exit-serving adapter (S2).** Change: implement the orchestrator's
active-exit-serving methods for macOS in `adapter/macos.rs` and extend the predicate in
`active_exit.rs` (currently Linux + Windows only — `active_exit.rs:177-201`, test
`runtime_implemented_linux_and_windows_not_macos`; skip text at `active_exit.rs:88-92`),
driving and asserting the product daemon's existing enforce-time `pf` NAT (refresh §6).
Per S2, the assertion must be an equivalent-strength end-to-end egress proof, not a
mechanism-translated nft assertion. Also fold in the `macos_pf_killswitch` coverage gap —
the bucket doc flags that killswitch-precedence proof on a macOS exit has NO live
`--node` successor today. Offline-testable core: predicate matrix + a unit-tested
pf-output parse (synthetic `pfctl -s nat`/`-s rules` fixtures). Fail-closed: keep
`active_exit_runtime_implemented` returning `false` for macOS until the adapter is real —
skip-with-reason, never an assumed pass. Live proof: `macos_stage_exit_handoff` and
`cross_os_exit_path` first dispatches, after CP-1 (row 8); overall exit green still waits
on row 19.

**3. pf ports of the four Linux-only validators.** Change four validator modules under
`crates/rustynet-cli/src/vm_lab/orchestrator/role_validation/`: `exit_nat_lifecycle.rs`
(`:15-17`; pf two-phase snapshot — `pfctl -s nat` during active exit, daemon stop, second
snapshot, merge + evaluate, mirroring `validate_linux_exit_nat_lifecycle`'s shape),
`exit_demotion_residue.rs` (`:23-24`; assert the pf NAT anchor is gone and
`net.inet.ip.forwarding` restored with the daemon still running),
`blind_exit_dataplane.rs` (`:14-16`; `pfctl -s rules` capture + the five subchecks:
mesh-scoped forward, no NAT, no unrestricted forward, no own-egress), and
`ipv6_leak.rs` (`:17-19`; probe a global v6 address while capturing on the egress
interface, `tcpdump -i en0 ip6` + utun check). Each extends its
`*_runtime_implemented` predicate to `Macos`. Order: sequence the
`blind_exit_dataplane` port AFTER a Linux green exists (the stage is 0 pass everywhere —
12 skip / 2 fail on Linux — so the macOS port must not be the first-ever run), and
pre-check whether the UTM guest even has upstream IPv6 before writing the `ipv6_leak`
probe — if the lab NAT offers no v6 egress, the honest disposition is a recorded
skip-with-reason, not a new validator. Offline-testable core: each validator's
evaluate-over-synthetic-pfctl-output logic. Fail-closed: predicates stay Linux-only until
each port lands; no validator greens against unenforced posture (that is why the
`exit_dns_failclosed` evaluator is deferred behind row 19, not part of this item). Live
proof: each `macos_stage_*_check` column's first real pass with the role elected.

> **Corrected 2026-09-02:** Candidate 4 is **WITHDRAWN** — its premise is refuted. `extended_soak` is NOT missing an enable flag: `plan.rs`'s `include()` has `StageSuite::Soak => !skip_live_suite && !skip_soak`, so the stage is in the DEFAULT plan of every full-suite run (`--skip-soak` opts out), and the per-stage ledger (`live_lab_node_stage_results.csv`) records Linux 40 pass / 348 skip (macOS 15 skip, Windows 2 skip) — the stage HAS dispatched and passed on Linux under `--node`. The roll-up agrees: `linux_stage_extended_soak` = 8 pass / 113 skip / 121 not_run. The mac/win all-skip columns are the `--skip-linux-live-suite` fast path by design; the real macOS gap is a full-suite run electing macOS (with the second client `live_extended_soak_validation.rs:44-47` requires), not a flag. A soak opt-in flag would have REMOVED soak from the default plan — rejected. The original (retracted) text follows unchanged.

**4. `--enable-soak-suite` selector.** Change: wire a `--enable-soak-suite` flag through
`TargetSelectors`/`resolves` (the registry defines SoakSuite as
`soak_suite && !skip_linux_live_suite` at `live_lab_stage_registry.rs:336-346` with the
comment that `extended_soak` "only ever dispatches as part of the Linux live suite") and
through the orchestrator flags and the mac/win target keys, noting
`live_extended_soak_validation.rs:44-47` additionally requires a second client.
`--skip-soak` is exposed today but no enable flag is. Offline-testable core: selector
resolution tests — a plan with the flag set includes `extended_soak`, without it the
stage stays out (mirror the chaos-selector inclusion test shape). Fail-closed: the flag
is opt-in; default plans unchanged. Live proof: the stage's FIRST dispatch anywhere (zero
per-stage rows on every platform), then a graded run — the bucket doc expects a triage
pass on first contact.

**5. `cross_os` field on the `--node` `live_lan_toggle_validation` spec.** Change: add
`cross_os: Some("cross_os_lan_toggle")` to the `--node` registry spec (the
`:2019-2024` region of `live_lab_stage_registry.rs`; today only the bash-dialect
`live_lan_toggle` at `:1951` carries the field, so the schema column at
`live_lab_run_matrix.rs:206` has no `--node` feeder). Offline-testable core: a
schema-mapping test pinning the `--node` spec → `cross_os_lan_toggle` column
relationship (same shape as the existing oracle mapping tests at
`live_lab_run_matrix.rs:4764-4867`). Fail-closed: the column remains empty until the
stage actually runs cross-platform — adding the feeder must not fabricate a verdict.
Live proof: the column's first populated row on the next cross-platform full-suite run
(after row 6 elects a mac blind_exit).

**6. Confirm-then-fix the `--role-switch-platform macos` `--node` dispatch.** Change
(small, verify-first): confirm a `--node` StageId actually dispatches the mac
role-transition cell when `--role-switch-platform macos` is set — the election gate
exists (`EnableRule::RoleSwitchPlatform("macos")`,
`live_lab_stage_registry.rs:1235-1236`; the skip reason at `vm_lab/mod.rs:12676` proves
the orchestrator evaluates it) but the macOS-specific `validate_macos_role_transition`
registry spec has no dedicated StageId, so election wiring on the `--node` path is the
thing to confirm. If dispatch only exists in the legacy wrapper vocabulary, add the
StageId + plan arm BEFORE spending a lab run. Offline-testable core: a plan-builder test
that a topology with `role_switch_platform = macos` yields a plan containing the
role-transition stage. Fail-closed: the transition validator stays `transition_plan`-backed;
no shortcut past the signed-transition path. Live proof: `macos_stage_role_transition`'s
first-ever `--node` run on either OS (242/242 not_run today), treated as triage.

---

## 3. Do not chase — dead, superseded, or design-excluded columns

Consolidated across all three bucket docs. None of these should be reported as "stages
that never pass" or attract lab/code effort.

**macOS (bucket: macOS+cross-OS §4).** Six bash-dialect `special` columns are DEAD (no
`StageId`; live work moved to `--node` stages that already pass):
`macos_keychain_key_custody`, `macos_runtime_acls`, `macos_service_hardening`,
`macos_mesh_status`, `macos_authenticode`, `macos_hello_limiter_flood` — superseded by
`macos_stage_{runtime_acls,service_hardening,mesh_status,authenticode,key_custody}_check`
(18 pass each) and `macos_stage_hello_limiter_flood` (6 pass). Plus
`cross_os_anchor_enrollment` — DEAD, no feeder in any dialect, superseded by
`cross_os_anchor_bundle_pull` (1 pass, the MAC-D1 milestone). One caveat cuts against a
clean sweep: `macos_pf_killswitch` is DEAD **with a coverage caveat** — its
killswitch-precedence proof has NO live `--node` successor, so it is a real coverage gap
to fold into the macOS exit-serving work (row 13), not a clean supersession. Contrast
(the bucket doc is explicit): the other eight macOS special columns
(`macos_membership_revoke_applies`, `macos_membership_signature_forgery`,
`macos_gossip_revoked_readmit`, `macos_enrollment_replay`,
`macos_privileged_helper_allowlist`, `macos_policy_default_deny`,
`macos_revoked_peer_denied_e2e`, `macos_blind_exit_reversal_denied`) are LIVE — 11 pass
each via `SecurityAuditValidation`. Not dead; do not list them as debt either.

**Linux (bucket: Linux §"dead legacy columns").** Seven bare `linux_*` columns are
duplicate-by-supersession: `linux_runtime_acls`, `linux_service_hardening`,
`linux_authenticode`, `linux_key_custody`, `linux_membership_genesis`,
`linux_mesh_status`, `linux_hello_limiter_flood`. All are in the CURRENT `--node`
schema; their registered producers (`validate_linux_*`) have no `StageId` variant and
are unreachable, while the live proof runs green one column over in the
`linux_stage_*_check` family. QH-07(b)/(c) (synonym table + schema migration) is the
tracked end state. **`linux_relay_forwards_frame` is explicitly NOT dead** — its
producer `relay_forwards_frame_validation` is a real Disruptive-tier opt-in StageId
(stage/mod.rs line 266); it is row 5 of the table above, not a do-not-chase item. Any
lab time spent "making the seven pass" is wasted.

**Windows (bucket: Windows §3.5, §3.3).** `windows_stage_blind_exit` and
`windows_stage_blind_exit_dataplane_check` are DESIGN-EXCLUDED on Windows (a hard error
in main.rs per the refresh doc) — never expected to pass, not debt;
`windows_blind_exit_reversal_denied` may legitimately stay not_run for the same reason.
Conversely, the twelve "dead-looking" special columns — `windows_dpapi_key_custody`,
`windows_membership_revoke_applies`, `windows_membership_signature_forgery`,
`windows_gossip_revoked_readmit`, `windows_enrollment_replay`,
`windows_hello_limiter_flood`, `windows_mesh_status`,
`windows_privileged_helper_allowlist`, `windows_policy_default_deny`,
`windows_revoked_peer_denied_e2e`, `windows_blind_exit_reversal_denied`,
`windows_named_pipe_acl` — are explicitly LIVE-but-never-run: each maps to a real
registry stage (`live_lab_stage_registry.rs:1383-1675`, `EnableRule::WantsWindows`)
populated via `set_special_stage_values` (`live_lab_run_matrix.rs:2247-2258`). They are
all-not_run because their stages have never run (bootstrap cascade), not because they
are unwired.

---

## 4. Ledger-reading rules applied

- **Quote-aware CSV only.** Every count in the bucket docs comes from a quote-aware parse
  (`python3 csv.DictReader`) of the ledgers; `awk -F,` silently misreads the quoted,
  comma-bearing fields (QH-07) and has already produced a confidently wrong conclusion
  once.
- **Column-vs-artifact.** A roll-up column's status is never taken as the pass/fail
  claim; the claim comes from the stage's own report/per-stage rows in
  `live_lab_node_stage_results.csv` (its `status` plus data block). The 8
  `macos_stage_two_hop=fail` rows are the canonical example — written by
  `traffic_test_matrix` (mesh-ping matrix), while the chained-exit validator
  `live_two_hop_validation` has only ever skipped on macOS (32/32).
- **The two_hop producer correction.** The 26 post-removal `linux_stage_two_hop` passes
  were written by `live_two_hop_validation` — the ONLY two-hop StageId
  (`LiveTwoHopValidation`, `stage/mod.rs:238`; 130 Linux pass node-rows) — not by the
  bash-dialect `live_two_hop` registry spec (`live_lab_stage_registry.rs:1943`), which
  has no StageId and can never produce a `--node` row. The "0 pass lifetime" figure for
  the stage id is a stale 2026-07-27 count (commit `9cdd660f`) quoted in the
  `live_lab_run_matrix.rs` doc-comment (~443-452).
- **The never-appended MAC-D1 row.** The 2026-08-31 milestone run
  (`labrun-1788266019601-1574-3`, commit `451f9730`) passed
  `deploy_macos_anchor_profile` + `validate_macos_anchor_bundle_pull` + `anchor_validation`,
  but the detached `ai_lab_run` orchestrator did not auto-append the tracked run-matrix
  row — so `macos_stage_anchor` reading "71 skip, 0 pass" in the ledger is stale, not
  current truth.
- **Run-scoped preflight poisoning (W-FIX-3, forward-only).** Only 3 of the 5
  `windows_stage_bootstrap` fail rows are real bootstrap failures; two runs died in the
  run-scoped `preflight` stage (topology validation; 3602 s guest clock skew) and, at the
  time, a run-scoped preflight failure wrote a fail verdict into every OS bootstrap
  column in the row. W-FIX-3 (the `run_scoped` flag, landed 2026-08-28) fixed this
  forward-only: the 5 historical rows are not evidence bootstrap failed five times, and
  forward rows are trustworthy.
- **A "never dispatched" claim needs the per-stage ledger, not the roll-up column.**
  (Corrected 2026-09-02.) A run-matrix column that reads all-skip/not_run can still
  describe a stage that HAS dispatched and passed on another platform: the
  `macos_stage_extended_soak` (15 skip / 227 not_run) and
  `windows_stage_extended_soak` (2 skip / 240 not_run) columns led the 2026-09-01
  docs to call `extended_soak` "never dispatched on any platform", but
  `live_lab_node_stage_results.csv` shows Linux 40 pass / 348 skip — the stage runs
  in every default Linux full-suite run (`plan.rs` `include()`: `StageSuite::Soak =>
  !skip_live_suite && !skip_soak`) and the mac/win cells skip it only via
  `--skip-linux-live-suite`. Join per-stage rows on `stage`+`platform` before
  asserting a stage has never run.

---

## 5. References

- Bucket docs (the per-stage evidence base, all 2026-09-01):
  `LiveLabStagePassLikelihood_macOS_CrossOS_2026-09-01.md`,
  `LiveLabStagePassLikelihood_Windows_2026-09-01.md`,
  `LiveLabStagePassLikelihood_Linux_2026-09-01.md`.
- Parity mandate and status: `CrossPlatformRoleParityPlan_2026-06-21.md` (the decree),
  `CrossPlatformRoleParityRefresh_2026-07-23.md` (the `--node` status of record; §1
  matrix, CP-1/CP-3/CP-4 verdicts),
  `CrossPlatformRoleParityRoadmap_2026-06-22.md` (historical bash record + per-cell
  design detail).
- Ledgers: `documents/operations/live_lab_node_run_matrix.csv` (engine of record, 242
  rows at analysis time) and `documents/operations/live_lab_node_stage_results.csv`
  (per-stage truth, 35,585 rows). The bash archive `live_lab_run_matrix.csv` is frozen
  history and was not consulted as evidence.
- Owner-gated designs referenced: `MacosDnsFailclosedEnforcementGap_2026-08-28.md`,
  `MacosExitMembershipRoleFixDesign_2026-08-31.md`,
  `WindowsNodeBootstrapTriageVerdict_2026-08-28.md`,
  `TraversalSelfSustenancePlan_2026-07-23.md`,
  `QualityHardeningTodo_2026-07-25.md` (QH-07 / QH-07(b)/(c)).
