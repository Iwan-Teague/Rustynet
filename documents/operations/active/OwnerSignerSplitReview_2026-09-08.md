# Owner-Signer Split Review — Adversarial Verification of `14b174c4` (2026-09-08)

**Status:** UNTRUSTED adversarial review (docs-only, no code changed). Reviewed commit `14b174c4` ("Require the owner to mint or retire a node carrying mesh authority") against the tree at that commit.

**Verdict up front:** `VERDICT: SAFE-WITH-FIXES` — the remove-then-re-add privilege-escalation hole is genuinely closed on the direct axis and on every alternative mutator path this review could construct, and the non-goal (owner-free client enrolment) survives both the default and `quorum_threshold > 1`. One real bypass of the new pubkey-reuse clause exists (hex case, §4/F1), one guard arm is completely untested (§5/F4), and two smaller test/doc weaknesses are catalogued. None of the findings reopen the escalation hole.

---

## 1. Is the hole actually closed? — VERDICT: CLOSED (with F1 bypass of the pubkey clause; tombstone residual acknowledged)

### 1.1 The guard sees the right state

`requires_owner_signer(&self, state: &MembershipState)` is evaluated inside `verify_membership_signatures` at `membership.rs:2023`, and `apply_signed_update` passes the **current, pre-apply** state (`apply_signed_update` body: `verify_membership_signatures(state, signed_update, ...)` precedes `reduce_membership_state(state, ...)`). Log replay chains intermediate states correctly: `membership.rs:1917` reassigns `state = apply_signed_update(&state, ...)` per entry, so a split round trip across two epochs is re-evaluated against the updated state each time. There is no way to launder a two-step escalation through a batch.

### 1.2 The direct round trip is dead

Trace the original attack against the new code. Start: `node-a` carries `{BlindExit, ExitServer}` (or `{Anchor}`, etc.).

- `RemoveNode { node_id: "node-a" }` signed by a guardian-only quorum: the guard's RemoveNode arm finds the node in `state.nodes`, `is_unprivileged_capability_set` returns false (contains non-`Client`), so owner is required → `MembershipError::OwnerSignatureRequired` before the reducer runs. The attack cannot even start.
- Attempting the add half alone (`AddNode` with privileged caps, leaving the original in place): the AddNode arm returns true on caps → owner required. The reducer would additionally reject the duplicate `node_id` at `membership.rs:2137-2145`, but the guard fires first regardless.

### 1.3 Every other `nodes`-mutating path was checked

The full reducer set (`reduce_membership_state`, `membership.rs:2136-2256`) writes `nodes` in exactly these places:

- **AddNode** (`:2136-2158`) — writes caps + pubkey. Guarded (caps clause + pubkey clause).
- **SetNodeCapabilities** (`:2160-2192`) — writes caps. Owner-gated unconditionally (first match arm, `membership.rs:493-495`), plus the `blind_exit` immutability check at `:2178-2182`. Notably the guard now requires the owner even for a capabilities write on a NON-blind_exit node — consistent with `SecurityMinimumBar` "capability changes need an owner-signed bundle"; pre-existing behavior, unchanged by this commit.
- **RemoveNode** (`:2193-2198`) — bare `retain`. Guarded.
- **RevokeNode** (`:2200-2211`, the operation this review was asked to check specifically) — **status-only**: sets `status = Revoked`, leaves capabilities and pubkey in place. A quorum CAN revoke a `blind_exit` node owner-free (a denial-of-service on that node's service, which is ordinary quorum governance, not escalation). The follow-up `RemoveNode` of the now-revoked node is still owner-gated because the guard reads **capabilities, not status** — the caps survive revocation. `RestoreNode` (`:2212-2223`) likewise only flips status back; it grants nothing the node did not already carry. **No hole here.**
- **RotateNodeKey** (`:2224-2236`) — writes pubkey. Owner-gated unconditionally. Without this, a quorum could rotate a live node's key away and sidestep the pubkey clause; it cannot.
- **RotateApprover / SetQuorum** (`:2237-2256`) — do not touch `nodes`; owner-gated as before.

### 1.4 Escalation after a fresh `{Client}` add

Could a quorum mint a fresh `{Client}` node owner-free and then escalate it by some non-`SetNodeCapabilities` path? The only capability writer is `SetNodeCapabilities` (owner-gated). `RestoreNode`, `RevokeNode`, `RemoveNode` (of the now-`{Client}` node — owner-free, correctly), `AddNode` (new ids only) grant nothing. **No.**

### 1.5 Residual gap (documented, accepted)

The pubkey-reuse clause scans only **current** nodes; the commit message itself states "durable tombstoning is a follow-up." Precise residual: after an owner-signed `RemoveNode` of a privileged node, that node's `node_pubkey_hex` (and `node_id`) leave no trace, so a guardian quorum may re-mint the same identity as `{Client}` owner-free. Impact: a removed node's operator (or whoever holds the key) returns as an unprivileged client without owner knowledge, and the RT-2 "factory reset + fresh enrollment under a NEW identity" posture (`membership.rs:2169-2177`) is not mechanically enforceable against re-use of the *removed* identity. Moderate severity, correctly disclosed, follow-up tracked. Not a re-opening of the privilege hole — the re-minted node is `{Client}`-only, and escalation from there remains owner-gated (§1.4).

### 1.6 F1 — the pubkey-reuse clause is bypassable by hex case (REAL DEFECT)

The clause compares raw strings: `existing.node_pubkey_hex == node.node_pubkey_hex` (`membership.rs:508`, inside the `AddNode` arm). But hex encoding is not canonical in this codebase:

- `decode_hex_nibble` (`membership.rs:2977-2986`) accepts `a-f` **and** `A-F`, so `decode_hex_to_fixed::<32>` — the reducer's only pubkey validation, at `:2146` — accepts mixed/upper-case encodings of the same 32 bytes.
- No producer is forced to lowercase on this path; the CLI `propose-add` passes `--node-pubkey` through verbatim (`rustynet-cli/src/main.rs:5860`).

**Concrete bypass:** with `state.nodes[0].node_pubkey_hex = "ab01…"` (lowercase, as `hex_encode` produces), a guardian-only quorum submits `AddNode(node-b)` with `node_pubkey_hex = "AB01…"` (same key, uppercased) and capabilities `["client"]`. Both guard arms pass (caps unprivileged; string compare misses), the reducer accepts, and the mesh now holds two Active nodes sharing one WireGuard identity — exactly the identity substitution the clause exists to prevent (`membership.rs:500-507` states the purpose). The added node is client-only, so this is impersonation/attribution confusion, not privilege escalation — but the clause is defeated as written.

**Fix (small):** compare decoded bytes (`decode_hex_to_fixed::<32>` on both sides — the reducer already decodes the offered key at `:2146`, so hoist or repeat) or `eq_ignore_ascii_case` after trimming, plus a length guard. Add a test using an uppercased key.

---

## 2. Is anything new broken? — VERDICT: NO (the state-aware guard is correctly narrow; flows verified)

The guard runs on every update, but only the `AddNode`/`RemoveNode` arms consult state; the four pre-existing operations return `true` exactly as before (`membership.rs:493-495`), and the catch-all `_ => false` preserves the old default for everything else (`RevokeNode`, `RestoreNode`, etc.). Production callers enumerated:

- **Enrolment admit** (`crates/rustynet-cli/src/main.rs:8313` `execute_enrollment_admit` → `build_add_node_record_for_enrollee`, `crates/rustynet-control/src/enrollment.rs:157-213`): capabilities come from `enrollee_capabilities_from_roles` (`enrollment.rs:234-266`), which defaults to exactly `{Client}` when no roles are requested (`:251-256`) and expands `blind_exit`→`+exit_server`, `entry_relay`→`+client` otherwise. Default client admit: unprivileged → owner-free, unchanged. Privileged `--roles` admit now needs an Owner-role signature at apply time — intended, and the failure is an explicit `OwnerSignatureRequired`, not a silent misapply. The admit flow signs under "the operator's approver key" (`main.rs:8377-8382`) and supports co-signing via `membership sign-update --merge-from` when quorum > 1 (`main.rs:8399-8402`), so the owner can co-sign a privileged enrolment through the shipped flow.
- **quorum_threshold > 1 + unattended client enrolment:** the threshold count check (`membership.rs:2001-2003`) is independent of the owner check; the new regression test proves a two-guardian quorum (no owner signature) applies a plain-client `AddNode` successfully. Confirmed true in the default AND at quorum > 1.
- **CLI `membership propose-add` / `propose-remove`** (`rustynet-cli/src/main.rs:5855-5886`, and the generic `propose` variants at `:6034-6062`): these only *draft* a record; the guard acts at apply time. A guardian drafting a privileged add now gets a loud `OwnerSignatureRequired` at apply instead of a silent grant — the desired behavior change, no flow broken.
- **`rustynetd` `add-peer`-style subcommand** (`crates/rustynetd/src/main.rs:4183-4192`): builds `AddNode` with `roles: ["tag:members"]` and parsed capabilities (default client); signs with the operator's key. Client-only usage unaffected.
- **Automated/gossip paths:** the only `AddNode`/`RemoveNode` constructions in `rustynetd/src/daemon.rs` (`:37582`, `:37589`) are inside the test module. Gossip transports signed updates; it does not construct them. The doc comment's claim that "nothing on the automated paths" breaks holds.
- **Fail-closed unknown-target remove** (`None => true`): a typo'd remove now demands the owner instead of returning `NotFound`. Safe-direction cost only (see F4 for the test gap).

One behavioral note, not a break: `RemoveNode` of a **revoked** privileged node also requires the owner (guard reads caps, ignores status). Arguably correct — retiring a privileged identity is exactly the owner's call.

---

## 3. Is the capability classification right? — VERDICT: YES (structurally sound; empty-set arm is belt-and-braces)

`is_unprivileged_capability_set` (`membership.rs:534-537`): `!capabilities.is_empty() && capabilities.iter().all(|c| *c == RoleCapability::Client)`.

- **`Client` is genuinely powerless.** `RoleCapability` has 15 variants (`crates/rustynet-control/src/roles.rs:6-41`); every variant except `Client` gates some serving/authority behavior (anchor sub-caps, `RelayHost`, `EntryRelay`, `ExitServer`, `BlindExit`, `ServesNas`/`ServesLlm`, port-mapping authority). `RoleCapability::Client` appears 27× in `rustynetd/src/daemon.rs` only as the baseline membership marker; `rustynet-policy` references it zero times. There is no "looks-privileged-but-isn't" trap in the other direction either: `AnchorPortMappingPinned` is only a *preference* selector (`roles.rs:24-29`), and the helper still classifies it privileged — conservative, correct.
- **The classification cannot be evaded by an untested variant.** Because the helper is `all(== Client)` and not a blocklist, any future capability variant is privileged by construction. The test `an_empty_capability_set_is_treated_as_privileged` covers only 6 of the 14 non-Client variants, but that is a coverage nicety, not a soundness requirement.
- **Empty-as-privileged is correct and doubly fail-closed.** `validate_membership_node_capabilities` (`membership.rs:2778-2785`, invoked from `MembershipState::validate` via `:251`) rejects any **Active** node with an empty canonicalized capability set. So even a *willing owner* cannot land an empty-cap node through `AddNode` — the guard demands the owner first, then `next.validate()` in `apply_signed_update` rejects it anyway. The commit-message rationale ("an unusual input should ask for the owner") slightly overstates the arm's effect — the owner cannot actually complete such an add — but the direction is fail-closed both ways and no shipped path produces an empty set (`enrollment.rs:251-256` defaults to Client; CLI defaults to `["client"]`).

One pre-existing hygiene note (not introduced here, worth a follow-up): the `AddNode` reducer pushes the offered capability vector **verbatim** (`:2158`) — it does not `canonicalize_role_capabilities` the way `SetNodeCapabilities` does (`:2190`). A quorum can therefore mint a node with a non-canonical vector like `[Client, Client]` owner-free (the helper correctly calls it unprivileged — it grants nothing extra; validation canonicalizes only for its own checks at `:2779`). No privilege effect; it is a state-normalization wart that the guard now depends on reading sensibly.

---

## 4. The pubkey-reuse clause — VERDICT: RIGHT IDEA, WEAK COMPARISON (F1)

Beyond F1 (case normalization, §1.6) and the tombstone residual (§1.5):

- **Length/malformation cannot smuggle anything:** the guard runs before the reducer's `decode_hex_to_fixed::<32>` (`:2146`); a malformed-length key merely evades the compare and is then rejected. No admission path.
- **Scanning only current nodes:** see §1.5 — precisely, the residual allows (a) re-minting a removed identity as `{Client}` owner-free, and (b) re-minting a *removed* key onto a *different* id. What it does NOT allow: duplicating the key of any **present** node (clause, modulo F1) or granting any non-Client capability (caps clause). Bounded and disclosed.
- The reducer's refusal of duplicate `node_id`s (`:2137-2145`) covers revoked-but-present nodes too — revocation does not free an id.

---

## 5. The tests — VERDICT: 3 OF 4 CLAUSES GENUINELY KILLED; TWO ARMS UNTESTED

Mental single-clause reverts, with the expected failure:

- Revert the **RemoveNode caps clause** → `removing_a_privileged_node_requires_the_owner` (`membership.rs:4375-4404`): the guardian-only update applies successfully, `expect_err` fails. Kills it. Real behavior (full `apply_signed_update`), and it asserts the fixture actually holds `{Anchor}` first — good self-check.
- Revert the **AddNode caps clause** → `adding_a_privileged_node_requires_the_owner` (`:4406-4430`) fails identically. Kills it.
- Revert the **pubkey clause** → `readmitting_a_known_pubkey_requires_the_owner_even_as_a_plain_client` (`:4463-4489`) fails. Kills it — **but only for a byte-identical string.** The test reuses `state.nodes[0].node_pubkey_hex` verbatim, so an uppercased-key bypass (F1) sails through the entire suite. The test needs a `.to_uppercase()` variant (or a decoded-bytes comparison in the fix makes case moot).
- Revert the **empty-set arm** (`!capabilities.is_empty()`) → caught by `an_empty_capability_set_is_treated_as_privileged` (`:4491-4506`) — which unit-asserts the helper directly. This is the one **partially self-proving** test: it pins the helper's shape, not behavior through the guard. An end-to-end empty-set test is impossible anyway (state validation rejects the node even owner-signed, §3), so a helper-level test is the honest maximum; say so in the test doc rather than implying guard coverage.
- **F4 — the `None => true` unknown-target arm has NO test.** Revert it to `None => false` and all 583 lib tests still pass (verified: full `cargo test -p rustynet-control --lib` green at 583, including the five new tests). The arm is the guard's only fail-closed-on-uncertainty branch and is currently load-bearing by convention only.
- **F5 — the non-goal's remove half is untested.** `enrolling_a_plain_client_stays_owner_free` (`:4432-4461`) is a genuine over-widening tripwire (gating both operations unconditionally fails it, exactly as its doc claims), and it proves the add half of owner-free client flows. The remove half — a quorum removing a plain-`{Client}` node without the owner — has no test; a regression that gated all removes would not be caught by the suite. The full lib suite (`583 passed`) includes all five new tests green.

---

## 6. Misc — unwrap/expect, clippy, doc claims

- No `unwrap()`/`expect()` added in production code; the helper is a pure function over a slice. Clippy-relevant: none observed (no needless borrow, no `match`-on-bool); the full lib test build is warning-clean.
- Doc comment on the guard (`membership.rs:462-482`) is accurate on the attack, the rule, and the D5 handoff rationale. One overstatement: the empty-set rationale in the helper's doc ("asks for the owner rather than being waved through") reads as if the owner could complete such an add; state validation forbids it (`membership.rs:2780-2784`). Cosmetic.
- The commit message's factual claims all check out against the code (reducer writes caps+pubkey at `:2158`; RemoveNode bare `retain` at `:2195`; reducer refuses duplicate id but never inspects the key; tombstone caveat present).
- Note the `blind_relay` design-only gate (`:2153-2157`) means the helper's privilege treatment of `BlindRelay` is unreachable in production state — harmless.

---

## Findings register

| ID | Severity | Summary | Where |
| --- | --- | --- | --- |
| F1 | **Medium** | Pubkey-reuse clause compares raw hex strings; `decode_hex_nibble` accepts `A-F`, so an uppercased re-encoding of a live node's key evades the clause and a quorum mints a duplicate-key `Client` node owner-free. Fix: compare decoded bytes (already decoded at `:2146`) or case-insensitive compare; add an uppercased-key test. | `membership.rs:508`, `:2977-2986` |
| F4 | Low | `None => true` fail-closed arm of the RemoveNode guard is untested; reverting it to `None => false` passes the whole suite. | `membership.rs:510-519` |
| F5 | Low | No test that removing a plain-`{Client}` node stays owner-free (remove half of the non-goal). | tests, `membership.rs:4432-4461` |
| — | Info | Empty-set guard arm is unreachable-in-success (`state.validate` rejects Active empty-cap nodes); helper doc slightly overstates. | `membership.rs:2780-2784` |
| — | Info | `AddNode` reducer does not canonicalize the capability vector (`[Client, Client]` can enter state non-canonical, owner-free, granting nothing extra). Pre-existing. | `membership.rs:2158` vs `:2190` |
| — | Info (accepted) | Tombstone residual: removed identities re-mintable as `{Client}` owner-free until durable tombstoning lands. Disclosed in the commit. | commit message, §1.5 |

## VERDICT: SAFE-WITH-FIXES

The split guard closes the remove-then-re-add escalation on every path this review could construct and keeps client enrolment owner-free, but the pubkey-reuse clause needs decoded/case-normalized comparison (F1) and the `None => true` arm needs a test (F4) before the clause set can be called fully enforced.
