# M-3 Verification — Anchor Pin-Rotation Grace Residual

Date: 2026-08-31
Subject: finding M-3 from `LiveLabCoverageGapAudit_2026-08-31.md` (L26, L52, L91; control
text cited from `SecurityMinimumBar.md` §3.2 pin-rotation grace paragraph, the "ADDED
2026-07-27" block, and `rustynet-control/src/membership.rs:1308–1346`)
Method: read-only code tracing against the working tree; no code changed, no gates, no
lab runs. Every claim below carries a file:line read first-hand this session.

## Verdict

**PARTIAL — medium-high confidence.** The audit's *enforcement description* and *live-gap
observation* are correct; its **"NEW" classification and release-blocking placement are
over-claimed**, and its *mechanism framing* ("grace window" with an "expiry boundary") is
imprecise against the actual code.

Component-by-component:

1. **"A revoked former-owner key is still accepted while an Active owner co-signs" —
   CONFIRMED.** The grace path is real and behaves exactly as the audit describes. See
   traced path below.
2. **"No adversarial stage anywhere" for the residual — CONFIRMED on the live axis.**
   Zero `chaos_membership_adversarial` rows of any status in the live `--node` ledger
   (`documents/operations/live_lab_node_run_matrix.csv`, grep count 0), and the one
   rotation-adjacent chaos slice self-declares its live portion `skipped`
   (`live_chaos_membership_adversarial_test.rs:19–22`). But the *unit* coverage is
   stronger than M-3's framing suggests: two of the three assertions M-3 proposes for
   the new live stage are already unit-proven at exactly the cited lines' function
   (below).
3. **"NEW" / release-blocking — OVER-CLAIMED.** The residual M-3 surfaces is not an
   undiscovered gap: it is **verbatim documented in the very control text M-3 cites**.
   `SecurityMinimumBar.md`, the "ADDED 2026-07-27" paragraph, states: *"a compromised
   old owner key can still satisfy this grace path on any device that never received
   the new pin."* The code's own doc comment says the same
   (`membership.rs:1353–1359`) and points to the membership-transparency track
   (`FableForkConsistentMembershipTransparency_2026-07-01.md`), whose threat model
   opens with the compromised-admin-key case (L23) and bounds its honest residuals at
   L556–559. A consciously documented, accepted residual is TRACKED-as-accepted, not
   NEW. What is genuinely untracked is narrower: **no live-lab stage exercises pin
   rotation** — that coverage absence has no owner in the QH ledger, the Discovery
   docs, or the SecurityAuditLedger.

**Release-blocking: NO.** The contract is enforced in production code with negative
unit tests, the residual is a documented design limit whose full remediation (key
compromise survival) is owned by the separate transparency track, and the grace
mechanism itself is structurally fail-closed — its only relaxation (Active co-sign)
*strengthens*, never weakens, the default path.

**Already tracked: YES (the residual itself) / NO (the live-stage absence).** Residual:
`SecurityMinimumBar.md` ADDED-2026-07-27 paragraph + `membership.rs:1353–1359` +
`FableForkConsistentMembershipTransparency_2026-07-01.md`. Live-stage absence:
unowned. This verification doc is the first record of it; the fair disposition is a
proposed-stage backlog entry, not a P0.

## The claim, restated

> [HIGH, NEW — M-3] Pin-rotation grace residual untested live. A revoked former-owner
> key is still accepted while an Active owner co-signs (`membership.rs:1308–1346`;
> SecurityMinimumBar L155–174) — and the residual (compromised old key satisfying grace
> on a device that never received the new pin) has no adversarial stage anywhere.

Audit §8 places M-3 in the P0 / release-blocking tier alongside M-1 and M-2 (L91). M-1
was confirmed as a real product gap; M-2 was refuted (enforced AND live-proven). M-3
sits between them: the control is enforced, the residual is real but
documented-as-accepted, and the live-stage absence is genuine but narrower than the
release-blocking framing.

## Which mechanism M-3 names

Anchor **membership-owner-key rotation in the bundle-pull head-attestation path** —
not gossip signing keys, not membership epoch keys. The pin is the device's
out-of-band-pinned membership Owner public key
(`verify_attested_snapshot(bytes, pinned_owner_pubkey_hex, …)`, `membership.rs:1360`).
When the mesh rotates an Owner key, the old key becomes `Revoked` in the attested
approver set while the device still pins it; the grace path decides whether that stale
pin may still accept a bundle.

## Traced path (first-hand reads)

`crates/rustynet-control/src/membership.rs`, `verify_attested_snapshot`:

- `:1353–1359` — doc comment states the grace rule and the residual verbatim: a
  pinned key matching a REVOKED former Owner is accepted **only** when a current
  ACTIVE Owner also signed the same attestation; otherwise the caller is told to
  re-deliver the pin out of band. The compromised-old-key limit is named here and
  scoped to the membership-transparency track.
- `:1360–1374` — fail-closed preamble: unusable pin or out-of-range freshness window
  (`max_age_secs` must lie in `1..=MEMBERSHIP_HEAD_ATTESTATION_MAX_AGE_SECS`, so the
  window can only be tightened, never disabled) rejects before any payload touch.
- `:1421–1437` — every signature is verified (`verify_strict`) against the ATTESTED
  approver set; Active-Owner signatures are counted and flagged
  (`active_owner_signed`, `:1421`), and any signature from the pinned key sets
  `pinned_key_signed`.
- `:1452–1473` — the pin is classified in the attested roster: `pinned_active_owner`
  vs `pinned_revoked_owner` (`:1465`); not-in-roster, not-an-Owner, and
  no-signature-from-pin are each hard rejects (`:1474–1483`).
- `:1485–1491` — **THE grace gate**: `if !pinned_active_owner && !active_owner_signed`
  → `PinnedOwnerKeyMismatch("pinned membership owner key was rotated … no current
  active owner co-signed the attestation; re-deliver the membership owner public key
  out of band")`. This is the only accept path for a revoked pin, and it still
  requires the old key's own valid signature (`pinned_key_signed`, `:1480–1483`) — a
  third-party cannot forge it.
- `:1452` region + `:237–260` (pubkey-uniqueness gate, per SecurityMinimumBar) — a
  hostile roster cannot list the same key twice to satisfy both classifications.

Anti-replay across rotation is independent of the grace path and enforced: epoch
non-regression and same-epoch-different-root fork detection against the previously
verified bundle (`membership.rs:1349–1351`, items 6–8 of the doc comment), plus the
key-rotation watermark machinery in `crates/rustynet-control/src/key_rotation.rs`
(audited PASS in `SecurityAuditLedger_2026-06-18.md` L223; RSA-0009's
rotation-non-functional defect fixed and re-verified in committed code 2026-07-27,
L42).

## Grace/overlap bounds — what "grace" actually is

M-3's proposed stage asserts "grace expiry boundary enforced" and its scenario says
"grace window". **There is no time-bounded grace window in the code.** The grace is
*structural*, not temporal:

- A revoked pin is accepted indefinitely — on every pull — but only when an Active
  Owner co-signed that specific attestation. There is no counter, no timer, and no
  expiry to bound; the "boundary" is the binary co-sign condition
  (`membership.rs:1485–1491`).
- The only temporal bound in the path is attestation freshness: `attested_at_unix`
  within a caller-supplied `max_age_secs` that is itself hard-capped at
  `MEMBERSHIP_HEAD_ATTESTATION_MAX_AGE_SECS` (default 7 days per SecurityMinimumBar;
  clamp enforced at `membership.rs:1366–1374`, tighten-only, no bypass flag) plus
  clock-skew future-dating rejection. That bound applies to every acceptance, grace or
  not.
- Consequence for the residual: the compromised-old-key acceptance does not decay with
  time on a device that never receives the new pin — it persists exactly as long as
  the pin does. This is the honest shape of the documented residual; an "expiry
  boundary" test as M-3 proposes would assert a property the design does not have.

## Test reality

Enforced-but-untested-live vs not-enforced: this is **enforced-but-untested-live**,
with substantial unit backing:

- `verify_attested_snapshot_accepts_rotated_pin_with_active_owner_cosignature`
  (`membership.rs:6062`) — old pin + Active co-sign accepted (the documented
  contract); new pin accepted directly. This is M-3's proposed live assertion #1,
  already unit-proven.
- `verify_attested_snapshot_rejects_rotated_pin_without_active_owner_cosignature`
  (`membership.rs:6097`) — old-owner + guardian signatures meet quorum but no ACTIVE
  Owner signed → rejected with re-delivery guidance. This is M-3's proposed live
  assertion #2 (stale-pin + old-key-ONLY signature → rejected), already unit-proven.
- Rotation reducer/authorization coverage: `owner_signature_required_for_rotate_approver`
  (`:3885`), `owner_signature_required_for_rotate_node_key` (`:4038`),
  `owner_signed_rotate_node_key_is_accepted` (`:4066`),
  `rsa0009_rotate_key_applies_when_created_at_differs_from_apply_time` (`:5247`),
  watermark cases `pre_rotation_bundle_verifies_against_archived_verifier_within_watermark`
  (`:6470`) / `post_rotation_bundle_signed_by_new_key_verifies` (`:6484`).

Live reality:

- **No stage in the `--node` stage registry exercises pin rotation or the grace
  path.** Grep of `crates/rustynet-cli/src/live_lab_stage_registry.rs` for
  rotation/grace/pin returns only revoked-**peer** stages
  (`validate_*_gossip_revoked_readmit`, `validate_*_revoked_peer_denied_e2e`) — mesh
  membership revocation, a different surface from owner-key rotation + bundle-pull
  pin grace.
- The chaos catalog entry `ChaosMembershipAdversarial`
  (`crates/rustynet-cli/src/vm_lab/orchestrator/stage/mod.rs:296`) nominally carries
  an owner-key-rotation slice (STAGE_OWNER_KEY, fault "rotate owner key while
  submitting updates from old key", `live_chaos_membership_adversarial_test.rs:538–543`),
  but (a) it targets the membership apply-update path, not the bundle-pull pin-grace
  path — M-3's residual is not even specced in it; and (b) the binary's own scope
  note (`:19–22`) records the live-injection remainder, owner-key rotation against a
  running daemon included, as **`skipped` — never claimed as passed**.
- Ledger: zero `chaos_membership_adversarial` rows of any status in
  `documents/operations/live_lab_node_run_matrix.csv` — consistent with the audit's
  own baseline that the chaos suite has zero ledger rows (audit §3.1, W-1/G2 —
  TRACKED, and the dominant reason the live gap persists: the machinery exists and
  does not run).

So the true live gap is a **strict subset** of the already-tracked W-1/G2 chaos
non-execution plus a stage-spec delta: even if chaos ran tomorrow, it would still not
exercise the pin-grace residual, because no stage specs it. The audit's proposed
`anchor_pin_rotation_validation` stage is a reasonable spec — minus the "grace expiry
boundary" assertion (no timer exists) and with the note that assertions #1 and #2
duplicate existing unit proofs, so the live stage's unique value is rotation *timing*
under a running mesh and cross-node pin redelivery, not the accept/reject logic
itself.

## Release-blocking judgment

**No.** Reasoning:

1. The enforcement point exists in production code, is fail-closed in ordering
   (pin/freshness checks precede any accept; every failure mode rejects before any
   byte is written — `membership.rs:1360–1491`, and the ordering integration test
   `pull_bundle_never_writes_unverified_bytes` in `crates/rustynet-cli/src/main.rs`
   per SecurityMinimumBar).
2. The residual is a documented, accepted design limit recorded at the three
   authoritative places (SecurityMinimumBar control text, code doc comment,
   transparency-track threat model). M-3's own risk text ("no proof it behaves as
   documented under live rotation timing") describes a *coverage* debt, not an
   *enforcement* absence — the two release-blocking M-findings before it were of a
   different class (M-1: no enforcement at all; M-2: refuted).
3. The full fix for the residual (surviving old-key compromise) is an open research
   track (`FableForkConsistentMembershipTransparency_2026-07-01.md`: witness
   cosigning, witness rotation, thresholds — L473–475), not a live-stage-sized item;
   no live stage could close it, only observe it.
4. The genuinely missing proof — rotation executed live mid-mesh with a stale-pin
   device — is valuable but sits behind the already-tracked chaos-suite execution
   blocker (W-1/G2, release-blocking *as that tracked item*). Filing M-3 as a second,
   independent P0 double-counts the same blocker.

## Already-tracked cross-check

- `SecurityMinimumBar.md` — the ADDED-2026-07-27 paragraph documents the residual
  verbatim and explicitly instructs that the acceptance list "is NOT exhaustive; see
  the pin-rotation grace path recorded below". M-3 cites this same range (L155–174),
  so the audit read the text that already tracks the finding it labels NEW.
- `crates/rustynet-control/src/membership.rs:1353–1359` — code-level documentation of
  the residual, pointing to the transparency track.
- `FableForkConsistentMembershipTransparency_2026-07-01.md` — the owning track for
  key-compromise-class threats (L23 threat model; L556–559 claimed-scope honesty;
  L473–475 witness rotation composing with `key_rotation`).
- `SecurityAuditLedger_2026-06-18.md` — `key_rotation.rs` (control + daemon) audited
  PASS with strong negative tests (L223, L262); RSA-0009 (rotation non-functional)
  fixed, re-verified 2026-07-27 (L42). No open finding names the pin-grace residual.
- `QualityHardeningTodo_2026-07-25.md` — QH-36 (RESOLVED `e4de5502`) covered the
  *gossip* consequence of node-key rotation (stale peer registration); nothing tracks
  the bundle-pull pin-grace live stage. **This is the one unowned piece.**
- `AdversarialSecurityRemediation_2026-07-29.md` — no rotation/grace item.

## Honest residuals (what M-3 gets right, stated without over-claim)

1. **Real, unowned live-coverage gap:** no `--node` stage exercises anchor owner-key
   rotation with a stale-pinned device, and the existing chaos rotation slice is
   both mis-scoped (apply-update, not pin grace) and unexecuted (skipped live, zero
   ledger rows). A correctly-specced `anchor_pin_rotation_validation` stage — live
   rotation mid-mesh; stale-pin + co-sign → accepted; stale-pin + old-key-ONLY →
   rejected; freshness boundary re-asserted under real rotation timing — is a
   legitimate backlog item, best filed under the W-1/G2 chaos-execution acceptance
   rather than as an independent P0.
2. **The residual persists on non-redelivered devices with no time decay** — worth
   saying plainly because the absence of a grace timer means "eventually expires" is
   not among its mitigations. Mitigation is operational: out-of-band pin redelivery.
3. **The "grace expiry boundary" assertion in M-3's proposed stage is unsatisfiable
   as written** — there is no grace timer to expire; the equivalent real property is
   the freshness `max_age_secs` cap, which already has unit enforcement
   (`membership.rs:1366–1374`).
4. **Unit coverage is not live coverage** — the two grace unit tests fix
   `attested_at_unix` and rotate in-process; they cannot observe a real signing
   session, real rotation propagation timing, or a real device pulling through
   `anchor pull-bundle`. That is the irreducible core of M-3, and it is a Medium
   coverage gap, not a High release blocker.
