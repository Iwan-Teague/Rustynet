# Bash-Retirement Dispositions (G3 / Spec §8) — per-cell adjudication ledger

**Named disposition ledger** for the W5.7 bash deletion, mirroring the
`NodeEngineFlipDispositions_2026-07-24.md` template. Per `NodeEngineAcceptanceSpec_2026-07-23.md`
§6.1/§8, every bash-green/`--node`-not cell from the A4 enumeration
(`BashRetirementGapEnumeration_2026-08-22.md`, 56 columns) receives exactly one entry here:
either **(a) prove-on-node** (a committed Phase-C task with a named green criterion) or
**(b) an owner-signed disposition** ("node supersedes bash" / "deferred G2 attainment") with
reason + expiry. **Bash is not the oracle** — each entry records a direction verdict, never a
silent `--node`-matches-bash edit.

**Status: B-INITIAL (drafted 2026-08-26 on commit `27e59c7d`). Every owner sign-off line below
is UNSIGNED — the delegate prepares, the owner signs (D2/D3). B-final converts any unmet
Phase-C commitment to an owner-signed "deferred G2 attainment" after Phase C completes.**

T4 security cells are marked **[T4]** — owner-level sign-off only, not delegable (§6.1).

---

## A0 — Deletion-precondition evidence (delegate prep; owner decision PENDING)

Delegate-enumerated facts (quote-aware reader, node ledger @ 151 rows, 2026-08-26):

1. **Green default-`--node` runs since the W5.6 flip (`a414ceb`, 2026-07-24): ZERO rows with
   `overall_result=pass`.** Lifetime ledger: 0 pass / 131 fail / 21 partial (now 151 rows).
   Context the owner needs to weigh this: `overall_result=pass` requires **zero
   skipped stages** (`live_lab_run_matrix.rs::overall_result` — any `skip`/`not_run` in the
   plan → `partial`), and every realistic topology skips role-not-assigned + vxlan-substrate
   stages, so `pass` is structurally out of reach for routine runs. The honest soak signal is
   **`partial` with 0 failed stages**: e.g. run `livelab-1787698271-6ccc9b1a5c9c`
   (2026-08-25T22:31, commit `6ccc9b1a`, clean) — 37 pass / 0 fail / 22 topology-conditioned
   skips, including `live_network_flap_validation=pass` and `live_reboot_recovery=pass`.
   The peer-landed egress fix (`7901939a`+`b727df36`, 2026-08-26) addresses the
   `network_flap` fail class seen 2026-08-26 (run `livelab-1787762750`).
2. **G1 held:** the flip stands — owner-signed 2026-07-23 (Spec §10), 5-of-5 stability at
   clean `a414ceb`, flip dispositions signed 2026-07-24. No engine-trust regression recorded
   since.
3. **Labs quiet / integration token / workers idle: NOT currently true and must be re-checked
   at Phase-E time.** At drafting time two other agent sessions were actively committing and
   driving the lab (commits `7901939a`/`b727df36`; a concurrent `--node` run on
   debian-headless-2/-4). One uncommitted ledger row (`livelab-1787762750-f9bce05446b1`,
   2026-08-26T16:32, fail on `live_network_flap_validation`) was lost from the working-tree
   CSV during that concurrency; its report dir survives at `state/live-lab-bash-1787761894`.
   These preconditions are point-in-time facts about the deletion moment, not about today.
4. **Owner decision (NOT the delegate's):** whether a soak with zero strict-`pass` rows but
   accumulating 0-fail partials is sufficient to lose the `--legacy-bash-orchestrator`
   rollback lever, or whether N consecutive 0-fail runs at one clean commit are required
   first (and what N is).

**Owner A0 sign-off:** PENDING — Phase E does not start without an `APPROVED <date>` line here.

---

## B1 — Ledger-dialect FALSE gaps (12 entries): proven on `--node` under a different column

Direction verdict for all 12: **not a real gap** — the bash-dialect column name differs from
the `--node` StageId-derived column; the capability is `--node`-proven under the column named.
No prove-on-node work is scheduled. (Counts from the A4 enumeration, node ledger @ 151 rows.)

| # | bash column (pass) | `--node` proof column (pass) | owner sign-off |
|---|---|---|---|
| B1.1 | `linux_runtime_acls` (2) | `linux_stage_runtime_acls_check` (116) | PENDING |
| B1.2 | `linux_service_hardening` (2) | `linux_stage_service_hardening_check` (116) | PENDING |
| B1.3 | `linux_authenticode` (2) | `linux_stage_authenticode_check` (115) | PENDING |
| B1.4 | `linux_key_custody` (2) | `linux_stage_key_custody_check` (116) | PENDING |
| B1.5 | `linux_mesh_status` (2) | `linux_stage_mesh_status_check` (115) | PENDING |
| B1.6 | `linux_membership_genesis` (2) | `linux_stage_membership` (136) | PENDING |
| B1.7 | `linux_hello_limiter_flood` (2) | `linux_stage_hello_limiter_flood` (45) | PENDING |
| B1.8 | `macos_hello_limiter_flood` (13) | `macos_stage_hello_limiter_flood` (6) | PENDING |
| B1.9 | `macos_runtime_acls` (15) | `macos_stage_runtime_acls_check` (15) | PENDING |
| B1.10 | `macos_service_hardening` (12) | `macos_stage_service_hardening_check` (15) | PENDING |
| B1.11 | `macos_mesh_status` (12) | `macos_stage_mesh_status_check` (15) | PENDING |
| B1.12 | `macos_authenticode` (15) | `macos_stage_authenticode_check` (15) | PENDING |

- Expiry/re-review: none needed — these are naming-dialect facts, re-derivable from the ledgers
  at any time via the A4 reproduction script.

---

## B2 — Windows column (grouped + specific entries)

### B2.G — the CP-4 bootstrap group (grouped disposition)
- **Cells:** `windows_client` (65), `windows_admin` (2), `windows_anchor` (24)*,
  `windows_stage_bootstrap` (66), `windows_stage_membership` (50), `windows_stage_assignments`
  (50), `windows_stage_baseline_runtime` (66), `windows_stage_anchor` (24)*,
  `windows_stage_relay_service_lifecycle` (18), `windows_stage_managed_dns` (9),
  `windows_stage_mixed_topology` (43), `windows_named_pipe_acl` (13), `windows_dpapi_key_custody`
  (13), `windows_stage_traversal` (7)*, `windows_hello_limiter_flood` (8), `windows_mesh_status`
  (11), `windows_stage_dns_failclosed_check` (6), `windows_stage_runtime_acls_check` (6),
  `windows_stage_service_hardening_check` (6), `windows_stage_key_custody_check` (6),
  `windows_stage_mesh_status_check` (6), `windows_stage_authenticode_check` (6).
  (*anchor/gossip cells additionally carry B2.C code gaps.)
- **Root cause:** `windows_stage_bootstrap` = 0 pass on `--node` (5 fail / 146 not_run; thin
  single-day fail signal, root cause unverified — CP-4). The entire column is unreachable until
  bootstrap passes.
- **Direction verdict:** genuine unproven-on-node territory, gated. **Prove-on-node deferred to
  Phase-C task C4 (bootstrap triage).** If C4 resolves to an environmental/hardware cause, this
  group converts at B-final to owner-signed "deferred G2 attainment" with the concrete cause
  recorded.
- **Owner sign-off:** PENDING
- **Expiry/re-review:** at C4 completion, or the G2 release gate, whichever first.

### B2.T4 — Windows security cells **[T4]** (individual owner-level sign-offs)
Same CP-4 gate as B2.G, but T4 — each line requires an individual owner signature (D3):

| cell (bash pass) | owner sign-off |
|---|---|
| `windows_membership_revoke_applies` (11) **[T4]** | PENDING |
| `windows_membership_signature_forgery` (11) **[T4]** | PENDING |
| `windows_gossip_revoked_readmit` (10) **[T4]** | PENDING |
| `windows_enrollment_replay` (10) **[T4]** | PENDING |
| `windows_privileged_helper_allowlist` (11) **[T4]** | PENDING |
| `windows_policy_default_deny` (11) **[T4]** | PENDING |
| `windows_revoked_peer_denied_e2e` (11) **[T4]** | PENDING |
| `windows_blind_exit_reversal_denied` (11) **[T4]** | PENDING |

(`windows_blind_exit_reversal_denied` is the negative assertion that the design-refusal holds —
gated behind bootstrap, NOT design-excluded itself.)

### B2.X — Windows exit (CP-3, hardware-gated)
- **Cell:** Windows `exit` (0 bash passes — not an A4 row; dispositioned for completeness).
- **Root cause:** `promote_windows_exit_active` is code-complete but needs `MSFT_NetNat`/HNS,
  impossible in UTM on Apple Silicon; requires physical `windows-x86-1` (CP-3).
- **Direction verdict:** hardware-gated deferral — "deferred G2 attainment, hardware blocker".
- **Owner sign-off:** PENDING · **Expiry:** when `windows-x86-1` exists.

### B2.D — Windows blind_exit (design-excluded)
- **Cell:** Windows `blind_exit` (0 bash passes — not an A4 row).
- **Direction verdict:** 🚫 **not a gap** — hard-errored by design (`main.rs` blind_exit
  Windows refusal); the refusal itself is proven by `windows_blind_exit_reversal_denied` (B2.T4).
- **Owner sign-off:** PENDING · **Expiry:** none (design fact).

### B2.C — Windows anchor/gossip code gaps (independent of bootstrap)
- **Cells:** the anchor/gossip halves of `windows_anchor` / `windows_stage_anchor` /
  `windows_stage_traversal`.
- **Root cause:** two standing code gaps that bootstrap cannot unblock: no Windows gossip
  transport (`windows.rs:157-160`, `DeferredPlatform`) and no self-issued signed bundles
  (`windows.rs:288-311`, ephemeral local mint).
- **Direction verdict:** "code gap / intended-divergence — deferred G2 attainment, not fixable
  in this program" (per program §0.1).
- **Owner sign-off:** PENDING · **Expiry:** the G2 release gate.

---

## B3 — macOS role cells: prove-on-node COMMITMENTS (feed Phase C)

Direction verdict for B3.1–B3.4: **genuine `--node` gaps — commit to prove-on-node.** No
signature needed while the commitment stands; each converts to an owner-signed deferral at
B-final only if Phase C cannot land the green.

- **B3.1 `macos_client` (bash 113)** → **C1** (fresh macOS `two_hop` triage → fix).
  Green criterion: a `--node` macOS run with `two_hop=pass` whose
  `live_two_hop_report.json` shows `end_to_end_reachable=true`, `baseline_reply_ttl=64`,
  `per_hop_ttl_decrement=1` — the report, never the aliased ledger column (QH-07; the
  flip-dispositions D1 proved the column is a false-green vehicle on both engines).
  Verifier-recomputed.
- **B3.2 `macos_exit` + `macos_stage_exit_handoff` (bash 7/14)** → **C3**. Green criterion:
  ≥1 verifier-recomputed pass of `macos_exit` + `macos_stage_exit_handoff` in the node ledger,
  AND the run report carries the end-to-end **egress assertion** (client packets provably
  egress the macOS exit to an external target) — `pf`-mechanism divergence does NOT waive it
  (Refresh §6/S2). Lifecycle/NAT-teardown proof alone does not satisfy G2.
- **B3.3 `macos_blind_exit` + `macos_stage_blind_exit` (bash 4/4)** → **C3**. **Irreversible —
  requires owner-authorized sacrificial guest (sign-off gate 7); the guest is factory-reset
  after.** Green criterion: ≥1 verifier-recomputed pass on the sacrificial guest.
- **B3.4 `macos_anchor` + `macos_stage_anchor` — election + `mesh_join` half (bash 31/23)** →
  **C2/C3**. Green criterion: 5 consecutive `--anchor-platform macos` runs with
  `validate_macos_mesh_join=pass` (C2 flake bar) and ≥1 `macos_stage_anchor=pass`,
  verifier-recomputed.
- **B3.5 anchor `gossip_seed` / `enrollment_endpoint` half — owner-signed deferral (NOT
  prove-on-node).** `enrollment_endpoint` has zero runtime enforcement (code gap;
  Refresh §5); `gossip_seed` substrate exists in the daemon but has no live anchor-gossip
  proof. Direction verdict: "deferred G2 attainment — code gap".
  **Owner sign-off:** PENDING · **Expiry:** the G2 release gate.

---

## B4 — Cross-OS cells (5 entries)

- **B4.1 `cross_os_peer_visibility` (bash 98, node 16 fail / 0 pass)** — real dataplane fail →
  **prove-on-node, C5**. Green criterion: a genuine **multi-OS** `--node` run (single-OS runs
  write no column) with `cross_os_peer_visibility=pass`, verifier-recomputed. Direction-diagnosis
  escape: if triage shows the bash green was invalid, this converts to "node supersedes bash".
- **B4.2 `cross_os_anchor_bundle_pull` (bash 31, node never attempted)** — gated on B3 (macOS
  election) + B2 (Windows bootstrap); prove-after-unblock or defer at B-final.
  **Owner sign-off:** PENDING (if deferred) · **Expiry:** G2.
- **B4.3 `macos_stage_mixed_topology` (bash 80) / the `--node` 3-OS carrier
  `live_mixed_topology_validation`** — transitively blocked by CP-4 (needs all three platforms
  healthy). First action after unblock is "run once and triage" (never attempted — no signal).
  **Owner sign-off:** PENDING (if deferred) · **Expiry:** G2.
- **B4.4 `cross_os_role_switch` / `cross_os_lan_toggle` / `cross_os_anchor_enrollment`** —
  never attempted on `--node` (skip/not_run); no bash-green baseline claimed for
  `lan_toggle`/`anchor_enrollment` beyond the archive's aggregate rows. Gated on B2+B3.
  **Owner sign-off:** PENDING (if deferred) · **Expiry:** G2.
- **B4.5 `cross_os_exit_path`** — **0/0 on BOTH engines**: unproven everywhere, NOT a
  bash-green gap; this entry exists to prevent anyone claiming a bash baseline that does not
  exist. Additionally requires the vxlan cross-network substrate (out of program scope).
  **Owner sign-off:** PENDING · **Expiry:** the cross-network program.

---

## B5 — Relay role summaries: lifecycle proven, frame-forwarding (HP-3) parked (3 entries)

Direction verdict: MIXED cells — relay **lifecycle** is `--node`-proven; only **frame-forwarding
(HP-3)** is unproven, and HP-3 is parked on ALL OS (not a macOS/Windows-election gap).

| # | cell (bash pass) | lifecycle proof on `--node` | HP-3 | owner sign-off |
|---|---|---|---|---|
| B5.1 | `macos_relay` (69) | `macos_stage_relay_service_lifecycle` (6 pass) | parked | PENDING |
| B5.2 | `windows_relay` (19) | `windows_stage_relay_service_lifecycle` 0-pass — ALSO gated by B2.G/CP-4 | parked | PENDING |
| B5.3 | `linux_relay` — NOT a gap (46 `--node` passes) | `linux_stage_relay_service_lifecycle` (46) | parked | PENDING |

- **Expiry/re-review:** HP-3 un-park decision at the G2 release gate.

---

## B6 — Residual Linux cells, out of mac/win/cross-OS scope (2 entries)

- **B6.1 `linux_stage_blind_exit` (bash 8, node deliberate `skip`)** — **explicit option-(b)
  "node supersedes bash: deliberate drift-correction, not a defect."** Running an irreversible
  blind_exit inside routine lab runs would brick a lab node; `--node` skipping it is the
  correction, bash running it was the hazard. A dedicated sacrificial-guest proof exists as the
  C3 pattern if ever needed on Linux.
  **Owner sign-off:** PENDING · **Expiry:** none (standing design position).
- **B6.2 `linux_stage_chaos` (bash 12, node never run)** — "deferred / out of
  mac-win-cross-OS program scope"; the chaos tier belongs to the resilience program.
  **Owner sign-off:** PENDING · **Expiry:** the T2 resilience program.

---

## Mechanical completeness check (B-RULE)

- A4 columns mapped: 12 (B1) + 30 (B2.G 22 + B2.T4 8) + 7 (B3.1–B3.4) + 3 (B4.1–B4.3) +
  2 (B5.1–B5.2) + 2 (B6) = **56 ✓** (B5.2 `windows_relay` carries its B2 gate note here;
  B2.X/B2.D/B2.C/B4.4/B4.5/B5.3 disposition non-A4 cells for completeness).
- Zero un-adjudicated A4 columns remain.
- **A3 union (sweep landed 2026-08-26, `G3FullSweepDiff_2026-08-22.md`): zero `matches:false`
  shared stages; three `stages_only_in_left` rows, adjudicated as B7 below.**

---

## B7 — A3 sweep-diff rows (3 entries): bash-only harness/meta stages

Direction verdict for all three: **not a capability — harness bookkeeping**; the `--node`
engine either performs the equivalent inside another stage or has no need of a self-row.
No prove-on-node work is scheduled.

| # | bash-only stage | verdict | owner sign-off |
|---|---|---|---|
| B7.1 | `macos_preflight_check` | benign bash Linux-preflight artifact; `--node` plans macOS stages only when a macOS node exists | PENDING |
| B7.2 | `prime_remote_access` | bash SSH-priming convenience; equivalent inside `--node` bootstrap | PENDING |
| B7.3 | `vm_lab_run_live_lab` | bash meta/wrapper self-row; no `--node` equivalent by design | PENDING |

- Expiry/re-review: none needed — vocabulary facts, re-derivable from the archived sweep diff.

## Mirror duty (Spec §6.1 rule e)

Every option-(b) deferral above must be mirrored into `NodeEngineAcceptanceSpec_2026-07-23.md`
§6.1's deferred-with-reason list **when signed** (D4). Unsigned entries are not yet effective
deferrals.

---

## PHASE D — owner sign-off package (prepared by the delegate; NOTHING below is self-approved)

- **D1 — loss of the rollback lever.** Phase E removes `--legacy-bash-orchestrator` with no
  fallback. Evidence for the comfort decision is the A0 section above (zero strict-`pass` soak
  rows; the honest signal is 0-fail partials, including the A1 node run 37/0/22 and the
  2026-08-25 37-pass run) plus the A3 sweep (zero shared-stage mismatches on the matched
  topology).
  **D1 owner sign-off:** PENDING
- **D2 — every option-(b) disposition, individually.** The signable lines are the PENDING
  entries in B1 (12), B2.G/B2.X/B2.D/B2.C, B3.5, B4.2–B4.5, B5 (3), B6 (2), B7 (3), plus any
  B-final conversions of unmet Phase-C commitments.
  **D2 owner sign-off:** PENDING (sign each line in place)
- **D3 — every T4 security cell, owner level (not delegable):** the 8 bolded B2.T4 lines.
  **D3 owner sign-off:** PENDING (sign each line in place)
- **D4 — the Spec §6.1 mirror.** On D2/D3 signature, the signed set is mirrored into
  `NodeEngineAcceptanceSpec_2026-07-23.md` §6.1 (the delegate performs the mechanical mirror
  edit after signatures; the owner approves the mirrored text).
  **D4 owner sign-off:** PENDING
- **D5 — final G3-satisfied sign-off.** A3 ran + is archived (`G3FullSweepDiff_2026-08-22.md` +
  raw JSON), A4 is complete + archived (`BashRetirementGapEnumeration_2026-08-22.md`), and every
  A4 gap cell maps to a signed B entry (mechanical check in this file). Phase E starts only on
  D5 + D1 + the A0 `APPROVED` line.
  **D5 owner sign-off:** PENDING
- **Gate 6 — cross-network bash suite scope: Option A (default, retain the cross-network suite +
  `live_lab_common.sh`) vs Option B (full retirement — requires the `cross_os_*` cells proven or
  dispositioned first).** Delegate recommendation: **Option A** (the cross_os cells are
  disposition-territory, not proven; Option B would delete their only evidence).
  **Owner decision:** PENDING
- **Gate 7 — sacrificial macOS guest for the irreversible `macos_blind_exit` proof (C3/B3.3).**
  Not authorized ⇒ B3.3 converts to a deferral at B-final.
  **Owner decision:** PENDING
