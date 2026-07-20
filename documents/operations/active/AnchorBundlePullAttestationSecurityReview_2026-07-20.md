# Anchor Bundle-Pull Attestation: Design, Implementation, and Security Review (2026-07-20)

**Status: implementation complete on branch `security/a4-membership-head-attestation` (5 commits), all mandatory gates green, one High-severity finding remains open and unresolved (§6). Not merged. Do not treat this as closed until §6 is dispositioned.**

## 1) Why this document exists

This records the full depth of the work that closed (mostly) the "A4" finding from the
2026-07-20 security audit: `AnchorCommand::PullBundle` wrote a fetched membership snapshot
to disk with **zero cryptographic authentication**. The audit branch
(`ai-edit/edit-1784569658514-92435-3` → `42901a0`) deliberately did not attempt a fix — it
investigated, found the obvious "just reuse `apply_signed_update`" remedy doesn't
architecturally work, and flagged the gap in `SecurityMinimumBar.md` rather than rush an
unreviewed fix. This document is the trail for everything that happened after that
deliberate stop: an independent design pass, a from-scratch implementation, three
independent adversarial reviews run in parallel against the actual code (not the design,
not the implementer's own report), one real defect those reviews found and fixed, and one
real defect they found that is **still open**.

The point of writing this down at this level of detail is that several things went further,
or differently, than initially expected — see §7. Those are exactly the details that are
easy to lose once a PR is squashed and merged, and exactly the details someone auditing this
control in six months will want.

## 2) The original gap (recap)

`crates/rustynet-cli/src/main.rs` (`AnchorCommand::PullBundle`, pre-fix) fetched a
membership-state snapshot over loopback TCP, checked only the wire-framing size, and wrote
the bytes straight to `output_path`. No digest check even existed at the content level for
this specific path (contrary to an earlier assumption in this session — see §7.1), no
signature check ever existed. `Requirements.md` line 43 promises anchor-mediated bootstrap
"does not bypass signature verification." It did.

## 3) Design (independent pass, before any code was written)

A design-only agent (Claude, model `fable`, `subagent_type: Plan` — read/grep/bash access,
no write access) was given the problem statement, the hard constraints (no custom
cryptography, no hand-rolled protocol, `ed25519-dalek`/`sha2` are the only approved crypto
deps, fail closed, preserve the no-central-authority multi-anchor model), and explicitly
told **not** to assume any particular solution shape, including not assuming
`apply_signed_update` reuse. It was asked to threat-model, produce multiple candidate
designs with trade-offs, and recommend one.

**Key finding the design pass surfaced, which the original audit under-weighted:** the
system already mandates exactly one piece of pre-trusted state on every new device — the
membership owner's public key, delivered out-of-band per `SecurityMinimumBar.md` §6.B,
before the daemon ever loads signed state. `AnchorNodeRoleDesign_2026-05-21.md` §5.2's own
Track B pass criterion already said the pulled bundle should be "verified against the public
key" — that verification was designed and documented in 2026-05 and never implemented. The
fix wires a dead, already-mandated control into the verification path; it does not invent a
new root of trust.

**Recommended design ("membership head attestation"), accepted and implemented as-is:**

- A new signed artifact, `MembershipHeadAttestation`, binds `(network_id, epoch,
  state_root_hex, attested_at_unix)`, minted in the SAME signing session as every normal
  membership-update signature (near-zero marginal cost — the signing key is already
  unlocked). It rides inside the existing `SignedMembershipUpdate` envelope as an optional
  per-signer field, so it travels through the existing apply/log/persist machinery for free.
- The anchor daemon materializes the attestation that arrived *with* an applied update into
  the snapshot file it persists — it never mints one itself (it holds no signing keys at that
  point, and even if it did, minting-at-the-anchor would make the anchor a trust authority,
  which `SecurityMinimumBar.md` §6.C explicitly forbids).
- The client (`anchor pull-bundle`) verifies, before writing anything: the state root/epoch/
  network_id the attestation claims match the offered state exactly; the §6.B pinned owner
  key is an *Owner* in the attested roster **and** its private key actually signed (roster
  presence alone proves nothing — a forged roster can *list* the real key without ever
  producing its signature); quorum among distinct active signers is met; the attestation is
  fresh (bounded window, tighten-only, no bypass); not future-dated; and the epoch does not
  regress against the client's own previously-verified local bundle.
- Rotation grace: a pin naming a since-revoked former Owner is still accepted **if and only
  if** a current active Owner also co-signed the same attestation — otherwise a clear
  "re-deliver the pin out of band" rejection.

**Candidates considered and rejected**, with reasons (kept here because "why not the obvious
alternative" is exactly what gets lost otherwise):

- *Full signed-log replay from genesis* — `apply_signed_update` rejects any update whose
  `expires_at_unix` has passed (default ~1hr TTL); replaying history means every historical
  entry is expired by construction, which would require semantic surgery on the single most
  security-critical function in the crate. Also doesn't solve first-contact trust on its own
  (genesis itself would still need the same attestation this design adds).
- *State-root commitment embedded in the enrollment/join token* — the token-minting secret
  lives on the anchor; a compromised anchor (exactly the attacker this control defends
  against) can mint a token committing to its own forged root. Fails exactly when needed.
- *HMAC/channel authentication of the TCP response* — hand-rolled protocol authentication,
  forbidden outright by `CLAUDE.md` §3, and it authenticates the *anchor* rather than the
  *state*, which again makes the anchor a trust authority.

## 4) Implementation

Branch `security/a4-membership-head-attestation`, worktree
`state/edit-worktrees/a4-head-attestation`, branched from the audit branch tip (`42901a0`).
Implemented by a Claude agent (`fable`), in **full/unattended mode** (deliberately — see
§7.2 for why, and why the trade-off was covered by independent review rather than real-time
supervision).

Commits `bba9983` (schema + the single enforcement point,
`rustynet_control::membership::verify_attested_snapshot`), `f5d528f` (minting at every
signing site — `sign-update`, `apply-update`, enrollment `admit`, `membership init` genesis,
plus the new `membership attest` re-mint verb — and materialization at the daemon's
`handle_membership_apply`), `3e41ea6` (client enforcement in `anchor pull-bundle`, both
FIS-0020 `have`/`UNCHANGED` interlocks, integration tests), `a5675a4` (docs —
`SecurityMinimumBar.md` §3 control 2, `AnchorNodeRoleDesign_2026-05-21.md` §5.2/§8).

Rotation grace was implemented in full, not deferred — the design's own fallback ("implement
core verification first, attempt rotation-grace as a follow-up if it doesn't fit cleanly")
turned out not to be needed.

**Deviations from the design, all deliberate:** `attestation.network_id=` persisted (design
omitted it; without it the network-id cross-check would be vacuous); a `ForkDetected`
error variant added (same-epoch-different-root needs a typed carrier for both roots, the
design only listed five error variants); two extra signing sites covered
(`rustynetd membership add-peer`, `enrollment admit --apply`) beyond the design's explicit
list, because skipping them would silently strip attestations on those paths; freshness
bound (`1..=604800`) re-enforced inside the library function itself, not just the CLI flag,
as defense in depth.

Tests added: 16 unit tests in `rustynet-control` (later 18 — see §5), 5 integration tests in
`rustynet-cli`, 1 in `rustynetd`. Full list and what each proves is in the commit messages;
the headline ones are named in §5.

## 5) Independent adversarial review (three reviewers, parallel, against the actual code)

Per `CLAUDE.md` §12.5's own standing guidance ("before committing a security-sensitive
patch — 3–5 concurrent REFUTE-this-patch cross-checks"), three separate review agents were
launched in parallel, each told to try to **defeat** the implementation, not summarize it,
each with a distinct lens, each explicitly instructed to trace the real code and — where
practical — run or build proof-of-concept code rather than reason from the report.

### Reviewer 1 — bypass hunting (7 checks)

Confusable-encoding attacks on the state root, the "roster-lists-key-without-signing" bypass,
`verify()` vs `verify_strict()`, domain separation between update and head-attestation
payloads, write-before-verify ordering in `PullBundle`, quorum double-counting, and panics on
attacker input.

**Result: 6 of 7 NOT DEFEATED (clean), 1 DEFEATED, proven live with a standalone PoC.**

The defeated one: **quorum counted by signature *slot* (`approver_id`), not by distinct
signing key.** Nothing in `MembershipState::validate()` prevented two `approver_id`s from
being assigned the same underlying pubkey. Since ed25519 signing here is deterministic, one
real signature is byte-identical every time it's produced — the reviewer built a roster with
two `Active`/`Owner` approver entries sharing one key, `quorum_threshold: 2`, signed once,
copied the signature hex under the second id with no private key needed, and
`verify_attested_snapshot` accepted it. Caveat noted by the reviewer at the time: exploiting
it required a roster that already had the duplicate-key shape (an attacker cannot forge that
roster into existence without a SHA-256 preimage — it would have to arise from a legitimate,
already-quorum-signed operator mistake), but the underlying gap was real, and the reviewer
separately noted the identical architectural gap pre-exists, unrelated to this branch, in
`verify_membership_signatures` (the regular membership-update quorum check).

### Reviewer 2 — fail-closed ordering and test honesty (7 checks)

Actually ran the new tests (not trusted from the implementer's report), checked whether the
headline enforcement-ordering and "roster subtlety" tests are realistic or strawmen, traced
the daemon's attestation-materialization path for legacy updates, checked the FIS-0020
interlocks, reproduced the fast gates directly, and checked backward-compatibility claims
against real round-trip tests.

**Result: 5 of 7 fully verified clean; 1 correct-by-trace but with a real test-coverage gap
(`handle_membership_apply` has zero direct test coverage — the daemon integration test
persists via a helper that bypasses it); 1 real, still-open finding — see §6.**

### Reviewer 3 — cryptographic correctness (7 checks)

Confirmed the exact `ed25519-dalek` version and checked its actual verification API
semantics against the vendored source; verified `verify_strict()` (not the weaker `verify()`)
is used everywhere, matching the codebase's pre-existing baseline; public-key parsing never
panics on malformed input; zero `.unwrap()` added anywhere, all 75 added `.expect()` calls
are test-only (verified by line position against each file's `mod tests` boundary);
domain-separation is structurally guaranteed (both canonical payloads start with hardcoded,
non-attacker-influenceable literals); timestamp arithmetic uses `saturating_add` throughout,
with the staleness and future-dating checks proven complementary across the full `u64` value
space (traced the `attested_at_unix = u64::MAX` edge case explicitly); the age-ceiling is
enforced at both the CLI and the library layer independently.

**Result: 7 of 7 clean.** One low-severity, non-exploitable note: some public-value
comparisons (`==` on public keys/roots/digests) aren't constant-time — noted as matching the
codebase's existing pattern for this kind of check (only actual signature verification, which
IS the security-relevant comparison, is delegated to `ed25519-dalek`), not a real weakness.

## 6) Still open: stale-cache rollback (High severity, unresolved)

**This is reviewer 2's finding, and it is the more serious of the two the adversarial pass
surfaced — it hits the primary use case this entire control exists for.**

Epoch-regression protection (`verify_attested_snapshot`'s step 9) is checked against
`prior_identity`, which the client derives **fresh, on every single invocation**, by
re-verifying its own on-disk local file against `now_unix`. A brand-new device — the
scenario `anchor pull-bundle` primarily exists to serve — has no local file at all, so
`prior_identity` is `None` and the entire regression check is skipped. The same thing happens
to an existing device whose local cache has simply aged past the 7-day freshness default (a
device that runs `anchor pull-bundle` infrequently).

When that check is skipped, `verify_attested_snapshot` judges the offered snapshot purely on
its own embedded roster. Nothing anywhere ties an attestation's `attested_at_unix` to the
real historical time of the epoch it covers — `sign_head_attestation` will happily sign
`(epoch=3, root)` with a brand-new "now" timestamp just as readily as it signs the current
epoch. So: take an old, superseded epoch (say epoch 3, before some node was revoked at epoch
5). At epoch 3, the key that later got revoked was still a legitimate Active Owner **in that
old epoch's own roster**. The holder of that now-revoked key can mint a freshly-timestamped
attestation over the old `(epoch=3, root)` pair, at any point in the future, and it passes
every single check cleanly — the freshness check sees a "now" timestamp, the pin check sees
an Active Owner in the (old, offered) roster, quorum is whatever it was back then. **No
rotation-grace codepath is even needed** for this — from the offered snapshot's own point of
view, that key was never revoked.

The practical effect: a new device (or a device with a stale cache) can be handed a resurrect
of a superseded epoch — potentially reinstating a node or approver that was legitimately
revoked — with no signal to the device that anything is wrong.

**What closing this needs:** a persistent, monotonic anti-rollback watermark, independent of
attestation freshness, that survives an empty or stale local cache. This is a real design
decision (where does the watermark live, what happens on a genuinely fresh install vs. a
reset, how does it interact with the existing FIS-0020 `have`-optimization identity) — not
something to patch reflexively. It has deliberately **not** been implemented as part of this
branch. Track this as a High-severity item requiring the explicit, documented risk acceptance
`SecurityMinimumBar.md` §2 calls for before this control can be considered fully closed for
release purposes.

## 7) Depth notes — things that went further, or differently, than expected

These are the details worth preserving precisely because they're easy to lose in a squash-merge summary.

### 7.1 The original task brief was wrong about the snapshot format version

The design brief (written before the design pass ran) asserted the on-disk snapshot format
was "version=2/3 internally." The design agent re-verified this against the actual code
before accepting it and found `MEMBERSHIP_SCHEMA_VERSION = 1` — the version=2/3 confusion
traced back to an unrelated field (a key-rotation generation record) in a different part of
the codebase. The design was written against the format the code actually has, not the
format the brief assumed. This is recorded because it's a concrete example of why "verify
against the real code, not the task description" matters even when the task description
comes from careful prior investigation — that prior investigation had its own small error.

### 7.2 The implementation was deliberately run unattended, and that trade-off was made explicit

The implementation agent ran in **full (unattended) mode** rather than edit-by-edit
supervision. This was a conscious choice: earlier restricted-mode runs in this same session
had repeatedly hit their overall wall-clock timeout not because the model was slow to think,
but because the *human-approval latency* between proposed edits counted against the same
clock. Given the implementer's demonstrated track record on adjacent work in this session
(correct self-corrections, thorough tests, proper fail-closed reasoning), the trade-off made
was: run unattended to avoid wasting the job's clock on approval latency, and **substitute
real-time supervision with a mandatory, independent, adversarial multi-reviewer pass on the
finished diff** rather than skipping review altogether. §5-§6 are the direct result of
honoring that substitution — it is not a formality; it found and this document reports a real
defect that got fixed and a real one that remains open.

### 7.3 The quorum-counting fix went further than its own commit intended

The fix for reviewer 1's finding (§5) was added at the single most structural point available
— `MembershipState::validate()` — specifically to close both the new head-attestation quorum
path and the pre-existing `verify_membership_signatures` quorum path in one change, rather
than adding dedup-by-key logic separately to each counting site.

While writing the regression test for this fix, it became clear the fix reaches **further
than intended**: `MembershipState::canonical_payload()` calls `self.validate()?` internally
(this predates the fix — it was already there), and essentially everything that ever needs a
state root — `state_root_hex()`, every signing helper, and
`persist_membership_snapshot_with_attestation` — depends on `canonical_payload()`. The
practical consequence: a roster with a duplicated approver pubkey can no longer be
*serialized, hashed, or signed* anywhere in the crate, by any code path, not merely rejected
at the final `verify_attested_snapshot` check. The originally-planned end-to-end regression
test (build the attack roster → sign it → persist it → assert `verify_attested_snapshot`
rejects the bytes) had to be rewritten, because the attack roster can no longer even be
*constructed* through any of the crate's own legitimate encode paths — `state_root_hex()`
itself now fails closed the moment the roster is formed
(`verify_attested_snapshot_rejects_quorum_inflation_via_duplicate_approver_pubkey`,
`crates/rustynet-control/src/membership.rs`, asserts exactly this). This is a stronger
guarantee than "the read path checks for it" — it means there is no reachable byte sequence a
legitimate signer's own tooling could ever produce for that roster shape in the first place.

Fixed in commit `3c1ae84` on this branch, with two tests: `validate_rejects_duplicate_approver_pubkeys`
(direct unit proof of the enforcement point) and
`verify_attested_snapshot_rejects_quorum_inflation_via_duplicate_approver_pubkey` (the
reviewer's exact PoC roster shape, reproduced, asserting root derivation itself now fails).
Full gate suite (fmt, workspace check, workspace clippy excluding the known pre-existing
`rustynet-mcp` toolchain-pin issue, full workspace test — zero failures, `cargo audit`,
`cargo deny`) re-run and green after this fix.

## 8) Branch state as of this document

`security/a4-membership-head-attestation` merged to `main` (fast-forward, `e1d2a8b`), followed
by three independent adversarial reviews (§5) which found and this branch's follow-up fixed one
real defect (quorum counted by signer slot, closed in `3c1ae84`) and surfaced §6's stale-cache
rollback as a separate open item. §6 has since been investigated and CLOSED — see
[`AnchorBundlePullRollbackWatermarkInvestigation_2026-07-20.md`](./AnchorBundlePullRollbackWatermarkInvestigation_2026-07-20.md)
and `SecurityMinimumBar.md` control 2, both updated 2026-07-20 (commit `e0cc8e5`). This review
trail document is kept as-written for the historical record of what the three reviewers found and
why each finding was disposed the way it was.
