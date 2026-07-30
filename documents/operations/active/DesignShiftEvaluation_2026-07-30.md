# Design-shift evaluation — 2026-07-30

Five candidate design shifts were proposed while Tier 1 of the adversarial
remediation was being mapped, on the question: *what is worth changing now,
earlier in development, because it gets harder later?*

They were then adversarially reviewed. **Two of the five are rejected, one is
downgraded, and the review found a live defect in already-landed work** — which
is recorded here because the finding matters more than any of the proposals.

Status of this document: **evaluation complete for proposals 1, 2 and 5;
partial for 3 and 4** (see *Evidence limits* at the bottom — the review agents
died mid-run and their conclusions were only partly salvaged). Nothing here has
been implemented except where a commit is cited.

---

## 0. The finding that came out of reviewing the proposals

**Adversarial review of proposal 1 found that the ENR-01/ENR-03 fix landed
earlier the same day (`c36edc97`) was incomplete.** Fixed in `1801ca35`.

`MembershipState::validate` was chosen as the guard point because it runs inside
both `canonical_payload` and `decode_membership_state`, and `c36edc97`'s message
claimed on that basis that no writer could reach the signed text without passing
it. That claim was true of the snapshot and **false of the update record.**

There are **three** encoders emitting the same line-oriented `key=value` framing:

| Encoder | Guarded by `MembershipState::validate`? | Signed? |
| --- | --- | --- |
| `MembershipState::canonical_payload` | yes | yes (state root) |
| `MembershipUpdateRecord::canonical_payload` | **no** | **yes — this is the text approver signatures cover** |
| `SignedMembershipUpdate::canonical_envelope` | **no** | wraps the above |

The update record validated only `trim().is_empty()` on `network_id`,
`update_id` and `target` — precisely the weak guard ENR-01 was raised about —
and `reason_code` and `policy_context` had **no validation at all**. All of
`--update-id`, `--reason`, `--policy-context` and `--approver-id` are operator
flags, so a newline in any of them forged a line inside a signed artifact.

The envelope hex-frames the record payload, so the record genuinely cannot
reframe the envelope — the original review credited that correctly — but it
writes signature identities raw, carrying the same defect through a third field.

**The lesson is about the shape of the fix, not the bug.** Guarding a chokepoint
was right; the error was asserting a chokepoint covered writers it never saw.
This is the same drift the codebase keeps producing — the role→capability table
had two copies that disagreed, and the presence-versus-precedence class had five
sites. *"I fixed it at the chokepoint"* needs the follow-up question *"how many
chokepoints are there?"*

---

## 1. Replace the hand-rolled canonical encoding — **REJECTED**

**Proposal.** Replace the line-oriented `key=value` signed format with a
length-prefixed or explicitly-escaped encoding, making injection structurally
impossible rather than guarded. Claimed M.

**Verdict: REJECTED as stated.** Reasons, in descending weight:

1. **The compliant migration is a flag-day.** A transition period accepting both
   formats is the obvious approach and is **forbidden** by the engineering
   contract (§3: *no runtime fallback, downgrade, or legacy branch in production
   paths*). So the real options are a simultaneous cutover of every signature,
   state root and persisted snapshot — strictly more expensive than the "M"
   claimed — or a contract violation.
2. **The replacement is itself a high-risk security change.** Canonical *binary*
   encodings carry well-documented signature-malleability failure modes: map
   ordering, duplicate keys, non-minimal integer encodings, length-prefix
   ambiguity. A strictly-validated text format is not obviously worse than a
   library format used carelessly.
3. **The residual it removes is now small.** After `c36edc97` and `1801ca35` all
   three encoders reject the framing bytes. What remains is the risk that a
   *future field* forgets the guard — real, but narrow.

**Do this instead (cheaper, captures most of the value):** route every encoder
write through a single validated `write_field()` helper, so a new field cannot
be added without inheriting the guard. That converts "remember to validate" from
a convention into a type-level default. Estimated S. **Not yet implemented — and
note it is exactly the mitigation whose absence caused the §0 defect.**

## 2. Generation counter in every signed artefact (CTL-06) — **REJECTED as coupled; revisit standalone**

**Proposal.** Add a generation/anti-rollback counter to signed artefacts,
justified partly as riding along free with proposal 1.

**Verdict: REJECTED as framed.** The coupling was doing the persuading, and it
dissolves once proposal 1 is rejected. Two further objections:

- A generation **field** without an enforcement point — a persisted high-water
  mark and a fail-closed check on regression — is *worse than nothing*, because
  it presents as anti-rollback while providing none. The field is the easy half.
- CTL-06 is rated **L** and parked as a DECISION for good reason: it needs the
  enforcement semantics decided first (per-artefact? per-node monotonic? who
  refuses a regression?).

Anti-rollback remains a genuine gap. It should be taken as its own scoped piece
of work with the enforcement designed first, not smuggled in behind an encoding
change.

## 3. Tri-state validator results — **DO, scoped; premise verified**

**Proposal.** Validators cannot express *"I could not determine"*, so
"no leak detected" reads identically to "we never looked" (finding IPV-05).

**Premise verified by measurement.** In
`crates/rustynet-cli/src/vm_lab/orchestrator/role_validation/` there are **33
production validators**: **28 return `Result<(), String>`, 5 return
`Result<String, String>`** — every one binary. (A first pass reported 87, which
wrongly counted 54 test functions; the corrected split is 33 production / 54
test.) So the gap is real, and the size is **S–M**, not the large sweep first
implied.

**Verdict: DO — but the enum is the easy half.** The load-bearing part is the
**recorder contract**: an `Indeterminate` that the stage recorder or run matrix
maps to `pass` or `skip` buys exactly nothing. CLAUDE.md §12.3 documents a real
incident where alias handling masked 35 run-matrix rows — the same failure mode
this proposal is trying to fix. Any implementation must pin, by test, that the
third state cannot be read as success.

**This is harness, not product** — see §6 on why that distinction decides
ordering.

## 4. One role→capability table, enforced by a CI gate — **DO (evaluation partial)**

Two copies of the operator-string→`RoleCapability` mapping existed and had
drifted to *different* coverage; one granted `Anchor` from four tokens the
canonical parser rejects. The decode-side copy was deleted in `93dbd421`.

**Verdict: DO**, mirroring `check_backend_boundary_leakage.sh`. Claimed XS; the
sizing was **not independently verified** before the review agents died.

**Unresolved objection, recorded honestly:** the gate may false-positive on
legitimate presentation or display mappings, and a noisy gate gets disabled —
which would be worse than no gate, since it would also be *believed*. Enumerate
the legitimate mappings before writing it.

## 5. Derive the remediation-ledger summary from the rows — **DO (trivial)**

Four row-vs-summary disagreements were found in one session (ENR-02, RLY-15,
ENR-05, CRY-05), **all understating what had been done**, each costing
re-derivation. The summary block is hand-maintained; the rows are reliable.

**Verdict: DO.** ~20 lines, docs-only, no security surface. Lowest value of the
five but also the lowest cost and risk.

---

## 6. The ordering principle worth keeping

The proposals were argued on "what gets harder later". Reviewing them produced a
sharper rule:

- **Harness changes must land before the live-lab loops.** They change what is
  *measured*. Proposal 3 and the IPV-05 fix are in this class — landing them
  afterwards means the lab produced evidence about a measuring instrument that
  has since changed.
- **Product changes merely invalidate a run.** Costly, but recoverable by
  re-running.

Harness fixes invalidate the *conclusion*; product fixes invalidate the *run*.

---

## 7. Evidence limits

State this plainly rather than presenting the evaluation as more complete than
it is:

- Both adversarial review agents, and all four Tier 1 mapping agents, **died to
  a stream-watchdog stall** before producing final reports. Their partial
  conclusions were salvaged from transcripts.
- **Salvaged and independently confirmed:** the §0 encoder gap (found by the
  security reviewer, verified by reading, fixed in `1801ca35`).
- **Salvaged but NOT yet confirmed** — carried forward as open questions:
  - An agent reported *"Confirmed regression"* investigating whether IPV-04's
    family-agnostic case was **introduced by** `f2e084d9`. If true, a fix that
    landed for IPV-03 caused a regression, which would be significant. **Not
    verified. Do not act on it without reproducing it.**
  - The cost/opportunity-cost review of all five proposals never ran. The
    sizings for proposals 3 and 4 are the proposer's own measurements, not
    independent ones.
- Proposal 1's rejection rests on reading the engineering contract and the three
  encoders, not on an attempted migration.
