# Membership Tombstone Design (2026-09-08)

**Status:** BUILT 2026-09-09 (manager-implemented, `rustynet-control/src/membership.rs`; owner decisions OD-1/OD-2/OD-3 taken as recommended — D3 in `ManagerHandover_2026-09-08.md`). Landed exactly as §4 describes: `MembershipTombstoneRecord`/`TombstoneAuthority`, the always-written `tombstone_*` canonical section (schema stays 1; a snapshot without `tombstone_count` is refused with a named diagnostic), tombstone writes in `RemoveNode`/`RevokeNode`/`RotateNodeKey` with `MAX_MEMBERSHIP_TOMBSTONE_COUNT` refusing at the cap, the `AddNode` owner-gate on a tombstoned id or (case-insensitive) pubkey inside `requires_owner_signer`, and the owner-only `PruneTombstones { older_than_unix }` operation (CLI: `membership propose-prune-tombstones --older-than-unix`). Authority is derived from `requires_owner_signer(operation, pre-state)` at reduce time so proposer preview and applier recompute agree. The §7 tests landed under the names given there (plus `prune_refuses_a_future_cutoff`, `owner_gated_removal_stamps_owner_authority`, `tombstone_table_at_cap_refuses_another_removal`); `prune_tombstones_requires_owner` was written against the guard whose `_` catch-all was already removed in `8c7a692d`, so the new variant was a compile error until its explicit `=> true` arm landed. Review corrections applied: the operation enum has EIGHT arms — `RotateApprover` and `SetQuorum` are owner-only unconditionally and mutate the approver set, not node identity, so they are outside tombstone scope; and the mixed-fleet refusal on a pre-upgrade node surfaces as `PrevStateRootMismatch`/`NewStateRootMismatch` (an integrity error, not a named "upgrade required" diagnostic) — refresh the fleet in one wave. Mutation-proven 2026-09-09: with the `RemoveNode` tombstone write reverted, `removed_identity_cannot_be_reminted_without_owner`, `removed_key_on_new_id_requires_owner` and `tombstoned_pubkey_bypass_by_hex_case_is_refused` fail while `prune_tombstones_requires_owner` stays green (the guard, not the write, is what it tests). Full workspace gate on the landing: 13,558 tests, clippy clean. Original design text follows unchanged. Follow-up to `14b174c4` ("Require the owner to mint or retire a node carrying mesh authority") and `8d82ff53` ("Compare node pubkeys case-insensitively and test the two untested arms"), whose commit message and review both name durable tombstoning as the tracked residual (`OwnerSignerSplitReview_2026-09-08.md` §1.5, findings register "Info (accepted)").

---

## 1. DECISION

**Close the gap. Add membership tombstones.** A removed or revoked node leaves a durable record of its identity (node id + pubkey) in `MembershipState`. Re-adding a tombstoned identity without the owner's signature is refused. The owner's signature is the only path back in — which is exactly the authority that removal already required for privileged nodes, and more than it required for plain clients (the gap being closed).

Rationale in one paragraph: today, after a legitimate `RemoveNode`, the identity vanishes from `state.nodes`, and the `14b174c4` pubkey-reuse clause scans only present nodes. A guardian quorum may then re-mint the same `node_id` + `node_pubkey_hex` as a `{Client}` node, owner-free — re-admitting an identity the owner (or the governance process) deliberately retired. `8d82ff53`'s case-insensitive compare does not help here: the identity is not present to compare against. The residual is bounded today (removing a *privileged* node needs the owner, so only plain-client removals open the door, and a re-minted node is `{Client}`-only so escalation from there stays owner-gated), but the RT-2 posture "factory reset + fresh enrollment under a NEW identity" (`OwnerSignerSplitReview_2026-09-08.md` §1.5) is not mechanically enforceable while a removed identity is freely re-mintable. Identity is the mesh's unit of trust attribution; its reuse should cost the owner's key. The cost is a signed-state shape change, analyzed in §4; it is the same class of change the `capabilities` field already shipped (§4.1), so the mechanism is precedented.

Rejected alternative — do nothing: "not worth it" is defensible while the fleet is lab-scale and every removal is effectively owner-supervised, but the guard's own design intent (owner authority for identity-affecting operations) is incomplete without it, and the fix is additive state, not a protocol change.

---

## 2. GROUNDING

All `membership.rs` citations are read directly from the current worktree HEAD (post-`8d82ff53`). Review-doc citations marked "(at `14b174c4`)" are from `OwnerSignerSplitReview_2026-09-08.md`, which reviewed the tree at that commit; line numbers there can drift a few lines from HEAD.

Current guard and state shape:

- `MEMBERSHIP_SCHEMA_VERSION: u8 = 1` — `membership.rs:21`. Never bumped.
- `MembershipState` — `membership.rs:185-193`: `schema_version`, `network_id`, `epoch`, `nodes: Vec<MembershipNode>`, `approver_set`, `quorum_threshold`, `metadata_hash`. No tombstone field today.
- `canonical_payload()` — `membership.rs:307-366`: validates, sorts nodes by `node_id`, writes a deterministic byte string covering version/network/epoch/quorum/metadata, every node field, and every approver field.
- `state_root_hex()` — `membership.rs:368-371`: `sha256_hex(canonical_payload().as_bytes())`.
- `requires_owner_signer(&self, state: &MembershipState)` — the split guard from `14b174c4`: `AddNode` arm returns true if caps are not exactly-unprivileged or if any present node's pubkey matches (case-insensitive per `8d82ff53`); `RemoveNode` arm returns true for a privileged present target or an unknown target (fail-closed); call site in `verify_membership_signatures` around `membership.rs:2023`.
- `is_unprivileged_capability_set` — `!caps.is_empty() && all(== Client)` (empty set treated privileged, default-deny on unusual shape).
- Reducers (`reduce_membership_state`, `membership.rs:2140-2268` at HEAD): `AddNode` refuses duplicate `node_id` → `InvalidTransition`, validates pubkey via `decode_hex_to_fixed::<32>`, refuses `BlindRelay`, pushes the node; `RemoveNode` (`:2202-2208`) is a bare `retain` by `node_id` — the identity leaves no trace; `RevokeNode`/`RestoreNode` flip `status` only, node stays in state; `RotateNodeKey` (`:2233-2245` at HEAD) replaces `node_pubkey_hex` — the retired key is silently forgotten.
- `apply_signed_update` — `membership.rs:1108-1152`: validates state → checks `network_id`, `expires_at`, `created_at` skew (`MEMBERSHIP_CLOCK_SKEW_SECS = 90`, `membership.rs:22`) → `prev_state_root` must equal current root → strict epoch `+1` chain → `verify_membership_signatures` (where the owner guard lives) → reduce → re-validate → computed root must equal `record.new_state_root` → replay cache observe. Consequence: **any change to `canonical_payload` changes every computed state root**, and an update minted by new code carries a `new_state_root` that old code computes differently (§4.3).
- Parse side — `parse_membership_state_payload` (`membership.rs:2270+`): `version != 1` → `UnsupportedVersion`; every field `required_field`; `node_count` bounded by `MAX_MEMBERSHIP_NODE_COUNT = 65_536` (`membership.rs:70`).
- The `capabilities` precedent — `membership.rs:2900-2925` at HEAD: the field was added to `MembershipNode` **without** a schema bump; `canonical_payload` always writes it; pre-capabilities snapshots now fail **closed** on parse with a named diagnostic ("capabilities are never inferred from roles — re-issue the membership snapshot"); explicit-but-empty decodes fine; only absence is refused. The accepted residual is stated in the code comment: a genuine pre-capabilities snapshot no longer loads and its node fails closed.
- `validate()` — `membership.rs:196-305`: rejects duplicate `node_id`, dedupes/rejects approver pubkey reuse across approver ids (`:265-290`), enforces quorum bounds and `≥1` active approver, and rejects an **Active** node with an empty capability set (via `validate_membership_node_capabilities`, `membership.rs:2778-2785` per the review doc at `14b174c4`). Notably there is **no** duplicate-pubkey-across-nodes check in `validate` — that lives only in the guard at `AddNode` time.

From the review doc (independent confirmation of the attack surface): every `nodes`-mutating reducer path was enumerated at `14b174c4` — `AddNode` (guarded), `SetNodeCapabilities` (owner-gated unconditionally, `blind_exit` immutable), `RemoveNode` (guarded), `RevokeNode` (status-only; a quorum **can** revoke a privileged node owner-free — ordinary governance, and the follow-up `RemoveNode` stays owner-gated because the guard reads capabilities, not status), `RestoreNode` (grants nothing), `RotateNodeKey` (owner-gated unconditionally) (`OwnerSignerSplitReview_2026-09-08.md` §1.3, §2). The precise residual: (a) re-minting a removed identity as `{Client}` owner-free; (b) re-minting a removed **key** onto a **different** `node_id` (§1.5, §4).

UNVERIFIED (not read directly in this session; verify before implementing): the exact CLI enrolment call chain (`execute_enrollment_admit` → `build_add_node_record_for_enrollee`, `rustynet-cli/src/main.rs:8313`, `enrollment.rs:157-213` per the review doc §2) — the design does not change enrolment behavior, but implementers should confirm the admit flow needs no changes for tombstone-bearing states.

---

## 3. RESIDUAL GAP — WHAT TODAY'S GUARD STILL ALLOWS

Given both halves of the `14b174c4` guard (caps split + present-pubkey reuse) and the `8d82ff53` case fix, the remaining hole is exactly:

1. **Quorum re-mints a removed identity owner-free.** `RemoveNode` of a `{Client}` node is correctly owner-free (the non-goal). After it, `state.nodes` holds no trace. A guardian quorum signs `AddNode` with the same `node_id` + `node_pubkey_hex` + `{Client}`: the caps arm passes (unprivileged), the pubkey arm finds nothing to compare against, the reducer's duplicate-`node_id` check finds nothing → applied. The removed node's operator — or whoever holds that WireGuard identity — is back on the mesh as a client with no owner knowledge. Attribution confusion: mesh logs attribute activity to that identity, which the governance process believed retired.
2. **Quorum re-mints a removed key under a new id owner-free.** Same trace with a fresh `node_id` and the removed `node_pubkey_hex`. Two Active nodes sharing one WireGuard identity is the exact substitution the pubkey clause exists to prevent (for *present* nodes it is dead; for removed ones it is open).
3. **RotateNodeKey forgets the retired key.** Owner-signed rotation replaces the pubkey; the old key is recorded nowhere. If the old key's bytes later reappear (new node, quorum-minted), nothing notices. Lower severity — the rotation itself was owner-approved — but it is the same "identity leaves no trace" shape.

Not reachable (both guard halves hold): re-granting capabilities owner-free; duplicating a *present* node's key or id; escalating a re-minted `{Client}` node (every capability writer stays owner-gated).

Worth closing: yes — the fix makes "removed" mean "removed" rather than "removed until someone re-types the identity", at additive-state cost.

---

## 4. THE DESIGN

### 4.1 State shape

```rust
pub const MEMBERSHIP_SCHEMA_VERSION: u8 = 1; // unchanged — see below

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TombstoneAuthority { Owner, Quorum }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MembershipTombstoneRecord {
    pub node_id: String,
    pub node_pubkey_hex: String,      // stored canonical lowercase
    pub removed_at_unix: i64,         // from record.created_at_unix of the tombstone-writing update
    pub authority: TombstoneAuthority, // derived from requires_owner_signer at reduce time, not from message content
}

pub struct MembershipState {
    // ...existing fields...
    pub tombstones: Vec<MembershipTombstoneRecord>,
}
```

Keying: a tombstone row is the `(node_id, node_pubkey_hex)` pair. Re-tombstoning an identical pair replaces the existing row (latest removal wins). `RotateNodeKey` writes a row `(node_id, old_pubkey)` — a distinct pair from the node's live `(node_id, new_pubkey)`, so rotation and removal records coexist.

`MEMBERSHIP_SCHEMA_VERSION` stays `1`. The `capabilities` precedent (`membership.rs:2900-2925`) is the model: `canonical_payload` **always** writes the tombstone section, the parser **requires** it, absence fails closed with a named diagnostic ("tombstones are never inferred — re-issue the membership snapshot"). No schema bump is needed to get precise diagnostics, and staying at 1 keeps all five existing version comparisons (`:1274`, `:1857`, `:1959`, `:2394`, `:2273`) untouched. Owner decision OD-1 confirms this.

`canonical_payload` gains, after the approver section (append-only ordering keeps existing bytes stable for tombstone-free states up to the new trailing section — the section itself changes the bytes, that is the point):

```
tombstone_count=<n>
tombstone.{i}.node_id=...
tombstone.{i}.node_pubkey_hex=...   (canonical lowercase)
tombstone.{i}.removed_at_unix=...
tombstone.{i}.authority=owner|quorum
```

Rows sorted by `(node_id, node_pubkey_hex)` — same deterministic-sort discipline as nodes/approvers.

### 4.2 Guard and reducer changes

- **`AddNode` reducer** (`:2140-2158` at HEAD): after the existing duplicate-`node_id` check, consult tombstones. If `node_id` matches any tombstone, **or** `node_pubkey_hex` matches case-insensitively (`eq_ignore_ascii_case`, the `8d82ff53` discipline) any tombstone's pubkey, the add is refused with `InvalidTransition` naming the tombstone — **unless the update carries the owner signature**. The owner-override reads the same signal the guard uses; plumbing the "owner signed" bit into the reducer is the one new signature-level input (implementation detail: check belongs in `verify_membership_signatures`/`requires_owner_signer` so a non-owner update never even reaches the reducer — mirror the existing guard structure rather than trusting a flag through the call chain).
- **`requires_owner_signer`**: unchanged for existing arms. A tombstone-blocked `AddNode` is refused by the *reducer* (transition-level), not by demanding the owner up front — demanding owner for every add would re-create the over-widening the regression test `enrolling_a_plain_client_stays_owner_free` (`membership.rs:4432-4461` per review doc §5 F5) exists to kill. A *new* arm is added for the new operation (below).
- **`RemoveNode`** (`:2202-2208` at HEAD): retain, and push the tombstone `(node_id, removed node's pubkey, record.created_at_unix, authority = if owner_signed { Owner } else { Quorum })`. Cap: `MAX_MEMBERSHIP_TOMBSTONE_COUNT = 65_536` (mirrors `MAX_MEMBERSHIP_NODE_COUNT`); at cap, refuse the removal (`InvalidTransition`) — fail closed, never silently drop protection.
- **`RevokeNode`**: also writes the tombstone. The node stays in state (dup-`node_id` already blocks re-add while present), so this is belt-and-braces for the revoke→remove→re-add chain and for any future status-shape change. Same authority derivation.
- **`RotateNodeKey`** (`:2233-2245` at HEAD): push `(node_id, old_pubkey, created_at, Owner)` before replacing the key. Rotation is already owner-gated unconditionally, so the authority is always `Owner`.

### 4.3 What breaks — signed state, roots, signatures

Every claim here follows from `apply_signed_update` (`:1108-1152`) + `canonical_payload` (`:307-366`) + `state_root_hex` (`:368-371`):

1. **`canonical_payload` bytes change** for every state (the new section is always written, even empty). Therefore **every `state_root_hex` changes**, therefore every `new_state_root` recorded on a future update, and every head attestation that binds `(network_id, epoch, state_root)` via `persist_membership_snapshot` (`:1154+`), must be computed by tombstone-aware code.
2. **Per-update signatures are unaffected in mechanism** — they cover the operation payload (`MembershipOperation::canonical_payload`, `:567`), whose `add_node`/`remove_node` arms (`:644`/`:675`) gain no fields in this design. Signatures verify; roots are what move.
3. **Mixed-version fleet fails closed, loudly.** An update minted by tombstone-aware code carries a `new_state_root` computed over tombstone-bearing canonical bytes. Old code reducing the same operation computes a different root → `new_state_root` mismatch → the update is **refused** on that node. This starts with the *first* update applied anywhere by new code, not the first tombstone. Mitigation is the same as the capabilities rollout: refresh the fleet in one wave (re-mint the head snapshot, re-distribute membership). This is the accepted break — see OD-1.
4. **Test fixtures with hardcoded state-root hex strings** must be re-minted. Mechanical but broad; it is the bulk of the mechanical effort in §7.
5. **`MEMBERSHIP_SCHEMA_VERSION` stays 1**; old *snapshots* (state payloads) fail at parse with a named field error, exactly like pre-capabilities snapshots. No migration code is written — re-issuance is the migration.

### 4.4 Pruning — and why pruning cannot become the bypass

Tombstones grow monotonically with removals/rotations. Unbounded growth is bounded in practice by removal rate, hard-capped by `MAX_MEMBERSHIP_TOMBSTONE_COUNT` (at cap, removals fail closed — visible, not silent).

Pruning is a **new signed operation**, not an automatic background behavior:

```rust
MembershipOperation::PruneTombstones { older_than_unix: i64 }
```

- `requires_owner_signer` returns **true** for it — a quorum can never prune.
- It removes only rows with `removed_at_unix < older_than_unix`; the parser requires the field; validation refuses `older_than_unix > created_at_unix + MEMBERSHIP_CLOCK_SKEW_SECS` (a future cutoff is malformed, refuse the update).
- The guard consults tombstones **with no age exemption**. Age never weakens enforcement; pruning removes rows only by an owner-signed state transition (epoch +1, quorum/owner signatures, committed root). Since overriding a tombstone requires the owner *and* pruning requires the owner, pruning can never grant a quorum anything it could not otherwise do — the bypass requires the owner's key, at which point the owner could simply sign the `AddNode` override directly.

**Rejected mechanism (zero-effort-permissive):** automatic age-based expiry inside the reducer or the loader ("tombstones older than T stop being consulted"). This is the no-check-proceed shape: no signature, no transition, no record — the protection silently lapses at time T and any attacker simply waits. Rejected on the house rule (recent precedent: a proposal cut for an omittable precondition = no check, proceed).

---

## 5. FAIL-CLOSED ANALYSIS

Every new field/declaration/message, across the four failure axes. The rule (AGENTS.md §3/§10.1): absent, malformed, stale, or unauthorized → refuse, never default.

| New thing | ABSENT | MALFORMED | STALE | UNAUTHORIZED |
|---|---|---|---|---|
| `tombstones` section in a state snapshot | Parse refuses; named diagnostic ("tombstones are never inferred — re-issue the membership snapshot"); node fails closed (capabilities precedent, `:2900-2925`) | Row pubkey fails `decode_hex_to_fixed::<32>`, empty `node_id`, unknown `authority` string, or duplicate `(node_id, pubkey)` rows → `validate()` rejects the whole state → every update refuses to apply on it | N/A — rows carry no expiry; an old row enforces exactly as strongly as a new one | Rows enter state only via signed epoch+1 updates that pass `verify_membership_signatures`; no other writer exists |
| `authority` field | Required by parser; absent row = malformed state = refuse | Unknown enum string → refuse | N/A | Derived at reduce time from `requires_owner_signer` of the update being applied; a quorum-signed removal stamps `Quorum` even if the drafter claims otherwise — the tag is not attacker-settable |
| `removed_at_unix` | Required by parser → refuse | Non-integer → refuse; cannot exceed `created_at + 90s` skew (source is `record.created_at_unix`, already skew-checked in `apply_signed_update` :1108-1152) | Old timestamp = older tombstone = *more* enforcement, never less; only an owner-signed `PruneTombstones` removes it | Copied from the signed update's checked `created_at_unix`; not independently signable |
| Tombstone check in `AddNode` reducer | State built by new code always carries the vec (empty ok); a state missing the field cannot reach the reducer (parse refuses first) | Pubkey compare is `eq_ignore_ascii_case` over validated-decodable hex (state-level validation decoded it); id compare exact | No age gate on the check — stale rows bind | Override requires the owner signature verified in `verify_membership_signatures` (:2023 area); a quorum update to a tombstoned identity → `InvalidTransition` naming the tombstone |
| `PruneTombstones { older_than_unix }` | Field required → refuse | `older_than_unix` in the future (beyond skew) → refuse the update | Pruning an old row still needs the owner's fresh signature — staleness of the *request* is bounded by the existing `expires_at`/skew checks on the update itself | `requires_owner_signer` → true; quorum-signed prune → `OwnerSignatureRequired` before the reducer runs |
| `MAX_MEMBERSHIP_TOMBSTONE_COUNT` at cap | Constant, compile-time | N/A | N/A | At cap, `RemoveNode`/`RevokeNode`/`RotateNodeKey` refuse with `InvalidTransition` — fail closed; the owner must prune first (owner-signed) |

Zero-effort-permissive mechanisms **rejected** by this design: automatic tombstone expiry (§4.4); inferring `tombstones: []` when the snapshot section is absent (that would let a pre-upgrade snapshot silently strip protection — absence must refuse); trusting a drafter-supplied authority string (derived instead); age-based exemption inside the guard (stale must bind).

---

## 6. WHAT IT DOES NOT SOLVE

- **Key compromise without removal.** A compromised key that is never rotated (owner-gated) or its node removed never gets a tombstone. Tombstoning records *governance decisions*; it does not detect theft.
- **Fresh-identity re-entry.** A returning attacker who mints a brand-new key + id as `{Client}` is unaffected — that is the owner-free enrolment non-goal by design. Tombstones enforce identity reuse policy, not admission policy.
- **RT-2's "fresh enrollment" half.** The posture demands re-enrollment under a NEW identity; tombstones make re-use of the OLD identity owner-gated, but cannot force the new enrollment to happen, nor vouch for its hygiene.
- **Quorum removals still create the tombstone (OD-2).** A quorum that removes a `{Client}` node creates a tombstone only the owner can override — a one-way door in quorum hands. Assessed acceptable (removal already had that authority; the tombstone just makes the consequence honest), but it is a real governance consequence, listed as a decision, not hidden.
- **Offline / stale-snapshot nodes.** A node that never receives post-removal snapshots keeps enforcing the old node list. Distribution liveness is out of scope; the epoch chain and replay cache handle what they already handle.
- **Owner-key compromise.** The owner can override any tombstone and prune them all. Owner compromise is already game-over (owner can mint anything); tombstones add nothing against it and claim nothing.

---

## 7. TEST PLAN

Every test names the mutation it kills. House rule (repo precedent: `8d82ff53`'s tests were mutation-proven; the review doc §5 documented shipped tests that passed with the fix reverted).

| Test | Catches the mutation |
|---|---|
| `removed_identity_cannot_be_reminted_without_owner` — remove a `{Client}` node (quorum-signed), then quorum-signed `AddNode` with same id+key → refused | Delete the tombstone write from `RemoveNode` (restore bare `retain`, `:2202-2208`) → test fails. This is THE test: it fails on the exact pre-fix code. |
| `removed_key_on_new_id_requires_owner` — remove node, quorum re-adds *key* under fresh id → refused | Guard drops the pubkey-coordinate match (matches `node_id` only) → fails |
| `tombstoned_pubkey_bypass_by_hex_case_is_refused` — tombstone stores lowercase; re-add uses uppercased hex → refused | `eq_ignore_ascii_case` on the tombstone compare reverted to `==` → fails (fixture must assert the two spellings differ, per `8d82ff53`'s self-guarding pattern) |
| `owner_signed_add_overrides_tombstone` — same replay with owner co-signature → applies | Override arm deleted (owner also refused) → fails |
| `quorum_override_of_tombstone_refused` — negative twin of the above | Override condition inverted/loosened (any signature passes) → fails |
| `revoke_then_remove_then_readd_requires_owner` — revoke (quorum), remove, re-add → refused | Tombstone write deleted from `RevokeNode` → fails |
| `rotate_node_key_retires_the_old_key` — owner rotates, quorum re-adds old key under new id → refused | Tombstone write deleted from `RotateNodeKey` → fails |
| `prune_tombstones_requires_owner` — quorum-signed prune → `OwnerSignatureRequired` | `requires_owner_signer` returns `false` for `PruneTombstones` → fails |
| `prune_is_age_bounded_and_recent_tombstones_still_bind` — prune old rows; old identity now re-adds owner-free (documented consequence); recent tombstone still refuses | Prune ignores the cutoff (removes everything) → fails |
| `parse_refuses_snapshot_without_tombstone_section` — strip the section from a serialized snapshot → named parse error | Parser defaults absent section to empty vec → fails |
| `validate_rejects_malformed_and_duplicate_tombstones` — bad hex / empty id / unknown authority / duplicate row → validation error, update refused | Any validation branch skipped → fails |
| `canonical_payload_is_deterministic_with_tombstones` — round-trip + sort-order stability | Unsorted iteration or field reorder → fails |
| `enrolling_a_plain_client_stays_owner_free` (existing, `:4432-4461` per review doc) must stay green | Over-widening: guard/ reducer consulting tombstones on never-removed identities → fails |

Regression guard for the whole feature: revert the `AddNode` tombstone check entirely → first three tests fail simultaneously.

---

## 8. EFFORT

**Total: ~3.5 days.**

Mechanical (~2.0 d): struct + enum + parser + `canonical_payload` section + `validate` checks + tombstone writes in the three reducers + guard consult + `MAX_MEMBERSHIP_TOMBSTONE_COUNT` + `PruneTombstones` plumbing + tests for parse/validate/determinism + **re-minting every hardcoded state-root fixture** (the long pole; broad but zero judgement). Gates after: scoped `cargo test -p rustynet-control --all-targets --all-features`, then the full §7 list.

Judgement (~1.5 d): plugging the owner-signature signal into the reducer override without widening the guard (the over-widening tripwire is the trap); mutation-testing the suite (run each kill, confirm); verifying the mixed-fleet fail-closed behavior on a two-version lab pair rather than asserting it; docs (CODE_MAP entry, this doc's status update, ledger line).

---

## 9. OWNER DECISIONS

**OD-1 — Accept the signed-state break without a schema bump?** Recommended: yes — version stays 1, named parse errors give precise diagnostics (capabilities precedent, `:2900-2925`), and the mixed-version refusal is root-mismatch (loud, deterministic) until the fleet is refreshed in one wave. Options: (a) as recommended; (b) bump to 2 — old nodes report `UnsupportedVersion` instead of a root mismatch; marginally clearer diagnostics, touches five version-comparison sites, breaks the precedent's consistency. Consequence of either: no rolling upgrade; a fleet-wide membership refresh is required on deploy.

**OD-2 — Do quorum-signed removals write tombstones?** Recommended: yes, stamped `Quorum` (strictest; removal authority already existed, and the owner override is the recovery path). Options: (a) as recommended; (b) only owner-signed removals write tombstones — preserves today's "client removal is fully forgettable" semantics, leaves the gap open for exactly the owner-free removals that motivate the design (weaker fix); (c) quorum removal writes a tombstone that expires — rejected here as the automatic-expiry anti-pattern (§4.4), listed only for completeness. Consequence of (a): a quorum can create a one-way door (removed client identity returns only with the owner's key) — governance-visible, honest.

**OD-3 — Prune policy and lifetime.** Recommended: owner-signed `PruneTombstones { older_than_unix }` + `MAX_MEMBERSHIP_TOMBSTONE_COUNT = 65_536` (at cap, removals fail closed until the owner prunes). Options: (a) as recommended; (b) never prune — unbounded growth is bounded by removal rate and the cap converts to a permanent removal freeze, simplest and most conservative, worst operational ergonomics on a long-lived mesh with churn; (c) fixed retention window with automatic expiry — rejected (§4.4: check-free, silently lapses). Consequence of (a): two owner-signed operations exist where none did before; the owner is the only actor who can ever weaken identity protection, which is the design's thesis.
