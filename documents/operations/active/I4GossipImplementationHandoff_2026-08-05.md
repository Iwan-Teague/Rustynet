# Reconciliation — read this before §0 below

Added by the author of the source plans after this handoff was generated. The body below
was produced by a fan-out of extraction agents, each attacked by a verification agent
whose corrections are marked `[VC]` inline. **That process is sound and the body is
worth executing — but it is internally inconsistent in three places, because the source
plan reached revision 3 while this document was being written.** Those three are resolved
here, and this section wins wherever it conflicts with the body.

## Provenance of this document

- The **body** (§0 onward) is agent-generated and agent-verified. Its `[V]` / `[VC]` /
  `[U]` tags are the verifiers' own. I have not personally re-read all 19 items.
- **This section** is mine, and every claim in it I verified against the code myself at
  commit `51de6452`.
- Treat any unmarked assertion in the body as unverified until you check it. The single
  most repeated failure in this work has been trusting a signal for its name.

## R1 — items 4, 5 and 6 build a design that is retracted. Do not build them as written.

Items 4 and 6 implement **A3.3** (split the race reason into attributed vs unattributed).
The body itself notes the retraction at two places — see the `[VC]` notes referring to
`I4TraversalAttestationPlan_2026-08-05.md` §0 — and then still presents A3.3 as
"landable now". Both statements cannot hold.

**Resolution.** A3.3 is retracted **as a sufficient fix**, for two verified reasons:

- The proof surface is **reason-blind**: `live_proven: live_peer_count ==
  programmed_peer_count && programmed_peer_count > 0` (`crates/rustynetd/src/daemon.rs:7461`).
  Splitting the reason does not change what reports as proven.
- A3.3 *creates* the mixed-reason case whose aggregate is a hard-coded literal
  (`crates/rustynetd/src/daemon.rs:7398`), so on its own it would misreport.

**But items 4 and 6 are not wasted.** They are the *reason plumbing* the surviving chain
needs, and item 6's `[VC]` already requires deleting the `:7398` literal — which is part
of the fix, not part of the retracted design. So:

> Execute items 4 and 6 **as plumbing**, in a commit whose message states they are
> insufficient alone. Do **not** describe them as closing the mislabelling. They must be
> followed by R2 below before any consumer may treat a reason as proof.

Item 5 stays as the body describes it: dead defensive code until A3.2, valuable as the
guard that makes A3.2 safe to switch on. Its `[VC]`-corrected proof obligation is right —
the original was unwritable.

## R2 — the missing item: the proof surface itself

**Nothing in the body addresses `live_proven`.** I grepped all 91k characters for `7461`,
`live_proven` and `path_live_proven`: zero hits. This is the gap that makes R1 matter.

Add as a required item, ordered **after** items 4 and 6:

- `live_proven` (`crates/rustynetd/src/daemon.rs:7461`) is computed from live-vs-programmed
  peer counts, where "live" is path mode plus handshake freshness — never the reason. So
  after items 4 and 6, a peer whose Direct endpoint came from the unattributed `pairs[0]`
  fallback still reports `path_live_proven=true`. `[verified]`
- It must stop counting an unattributed Direct endpoint as proven, and the hard-coded
  `"fresh_handshake_observed"` fallback at `:7398` must go in the same change.
- **Proof obligation:** a peer whose only Direct status carries the unattributed reason
  must report `path_live_proven=false`. Reverting the predicate makes that assertion fail.
  Note the platform caveat the body records: the daemon test module is
  `#[cfg(all(test, not(windows)))]`.

Until this lands, the strongest proof-named surface in the tree still lies, and the
attestation work in items 17–19 would be built on it.

## R3 — §0's flagged conflict is settled; do not escalate it to the operator

§0 below records a conflict between two reviewers about whether the empirical question —
can a per-public-key handshake counter advance from an endpoint other than the one just
probed — gates the attribution work, and asks the operator to resolve it.

**It is resolved, against the "it gates everything" reading.** `send_probe` reprograms the
backend endpoint for **every** pair before any poll
(`crates/rustynetd/src/phase10.rs:102-108`, called in the send loop at
`crates/rustynetd/src/traversal.rs:1706-1710`) `[verified]`. So the endpoint "just probed"
at poll time is `pairs[last]`, while `pairs[0]` is the endpoint credited. **Misattribution
follows from the send loop alone and needs no roaming assumption at all.**

So:
- Do **not** hold items 4, 5, 6 or R2 pending an experiment. They are unblocked.
- The empirical question remains genuinely open and worth answering, but only for scoping
  A3.2 — not as a gate on the reason plumbing or the proof surface.
- Related nuance the body does not carry: `supports_roaming` is `false` on the
  userspace-shared backends, so any A3.2 design must not assume roaming behaviour
  uniformly across backends. `[agent-reported]`

## R4 — the ordering that survived two adversarial reviews

The body's item 2 discussion (in §3, "not landable as an isolated edit") is correct that
closing the fail-closed arm has obstacles. But the surviving chain from the source plan's
§9 is specific, and the body does not state it as a chain:

1. **Close the fail-closed arm** (`crates/rustynetd/src/phase10.rs:6109-6131`) so the
   producer stops programming `max_by_key(priority)` — the sender's own integer.
2. **Then** A3.1 — an unattributed handshake is not a `Direct` decision. This is safe only
   after step 1, because A3.1 alone reroutes every unattributed race **into** that arm.
   And it does not cost connectivity: `ExistingFreshHandshake` returns `Direct` without
   entering the race (`crates/rustynetd/src/phase10.rs:5979-5981`) `[verified]`.
3. **Then** R2's proof-surface change.

Items 4 and 6 are compatible with this chain and can land first as plumbing.

**This chain has not itself been adversarially reviewed.** On this document family's
record — every previously unreviewed recommendation here has been refuted, twice on
claims tagged as verified — that is a live caveat, not a formality. Attack it before
building it.

---

# I4 Traversal Attestation and Gossip Identity — Implementation Handoff

Provenance tag on every claim: **[V]** verified against code by a reviewer who read the line, **[VC]** verifier-corrected (the first extraction was wrong; the corrected form is what appears here), **[U]** unresolved — nobody has established it.

Anchors are `file:line` at commit `e82e2190`. Lines drift. Locate by symbol and quoted text, never by seeking to a line number.

---

## 0. Read this before writing any code: the empirical question is unsettled

**The question:** can a per-public-key handshake counter advance from an endpoint other than the one that was just probed? Concretely, can WireGuard's `latest-handshakes` for a peer move forward because of traffic on an endpoint the local probe did not send to?

**Status: [U] unresolved.** Nothing in the repository settles it. No reviewer ran anything. It was recorded as `[open]` in the source plan's §11 and remains open.

**Why it is load-bearing.** The entire §3 attribution line of work — A3.2 (`handshake_endpoint` on the production backend), A3.3 (the unattributed reason variants), the attestation store, and the attested predicate — exists because the race currently treats "the handshake counter moved" as "the endpoint I picked is the endpoint that worked". If the counter can only advance from the probed endpoint, that inference is already sound and the attribution work is unmotivated.

**It cannot be settled on the origin host.** cargo is unusable there under macOS Gatekeeper saturation (see §5). Settling it requires a real Linux WireGuard host, two endpoints for one peer key, and observation of `latest-handshakes` while traffic arrives on the endpoint that was not probed.

**A conflict you must resolve, not paper over. [U]** One reviewer holds the question still gates the whole §3 line. A second reviewer found the plan document retracts its own contingency at `documents/operations/active/I4TraversalAttestationPlan_2026-08-05.md:66-72` ("**RETRACTED — §3.4 overstated its own contingency**" … "it is no longer load-bearing"), confirmed at `:550-552`. Both reviewers read real lines. Nobody reconciled them. **Resolve this with the operator before writing attribution code.** Do not pick a side silently.

**What is safe to do while it is open.** Items 1–9 below change labels, tests, and validation, not the inference. They are safe regardless of the answer. Items marked blocked on §3 are not.

---

## 1. Ordered execution list

Order is dependency-correct. Every proof obligation is stated as: break the production rule, this **specific named test** must fail, restore it. If you cannot produce that, do not land the change (see §5).

---

### 1. Cold-start deadlock regression test — no production change

**Landable now. [V]**

**What changes:** nothing in production. Add a regression test that pins the constraint every future deny must satisfy.

**The chain, all four links verified. [V]**
1. `sync_traversal_runtime_state` returns early, after clearing statuses, unless the controller is `DataplaneApplied|ExitActive` — `crates/rustynetd/src/daemon.rs:6441`, `:6443`, `:6445`.
2. The controller is constructed at `DataplaneState::Init` — `crates/rustynetd/src/phase10.rs:5132`.
3. The only first entry into the started set is `apply_dataplane_generation` — `crates/rustynetd/src/phase10.rs:5323`, `:5327`. The two other transitions that reach a started state sit behind `ensure_started()` — `crates/rustynetd/src/phase10.rs:5571`, `:5600`, definition at `:6269`. **[VC]** the function holding the `ExitActive` transition at `phase10.rs:5595` is `set_exit_node` (`crates/rustynetd/src/phase10.rs:5565`). There is no `select_exit_node`; the first extraction named a symbol that does not exist.
4. `apply_dataplane_generation` runs only after `apply_traversal_authority_to_peers` returns `Ok`, at both call sites — `crates/rustynetd/src/daemon.rs:7728` → `:7747`, and `:9323` → `:9352`.

So an unconditional deny cannot be escaped: no status without started, no started without `Ok`, no `Ok` without a status. The reconcile arm then escalates — `crates/rustynetd/src/daemon.rs:9331`, `:9332` — and flips to permanent restriction at `crates/rustynetd/src/daemon.rs:9598`.

**Proof obligation:** drive N+1 reconcile ticks from `Init` with enforcement on and empty statuses; assert `restriction_mode` never becomes `Permanent`. **[VC]** N is 5: `DEFAULT_MAX_RECONCILE_FAILURES = 5` at `crates/rustynetd/src/daemon.rs:338`. The source plan listed this constant as unread. Reverting the gate added in item 9 must make this test fail via `daemon.rs:9598`.

**[VC] Platform caveat for every daemon.rs unit test in this handoff:** the daemon test module is `#[cfg(all(test, not(windows)))]` — `crates/rustynetd/src/daemon.rs:15917`. Nothing you write there is compiled on Windows.

---

### 2. Record where attestation writes may live — constraint, not a change

**Landable now, but its proof is not revert-detectable. [VC]**

**What it establishes:** `apply_traversal_authority_to_peers` is `&self` (`crates/rustynetd/src/daemon.rs:6959`), so it can read but never record, refresh, expire or clear. All attestation writes belong in `sync_traversal_runtime_state`, which is `&mut self` (`crates/rustynetd/src/daemon.rs:6344`), at the post-report block beside the existing `statuses.insert` (`crates/rustynetd/src/daemon.rs:6763`; statuses moved into `self` at `:6785`).

**The `!probe_due` retained branch must never write attestation. [V]** It clones the previous status forward while re-deriving `selected_endpoint` from what is merely *programmed* (`crates/rustynetd/src/daemon.rs:6637`) and makes the stamp sticky — `latest_handshake_unix.or(retained.latest_handshake_unix)` at `crates/rustynetd/src/daemon.rs:6640`, `:6641`. Once `Some`, never `None` again.

**[VC] Do not repeat the borrow-checker rationale.** The first extraction claimed `&membership_directory` is borrowed out of `self`-derived state at both call sites, so `&mut self` would not compile. That is false: it is a plain local at both, built by `membership_directory_from_state` (`crates/rustynetd/src/daemon.rs:9208`, and the sibling near `:7652`), moved into `self.membership_directory` only later. With `peers` moved in, `&mut self` would compile. Keep the recommendation if you like the shape, but not on borrow-checker grounds — the false reason will stop you from even trying.

**[VC] Proof obligation is a mutation-only guard.** The stated proof ("revert a write added to the retained branch") cannot be reverted, because no such write exists today. Write it as: add a write to the retained branch, the test must fail; remove it, pass. Not revert-detectable, and say so in the commit body.

---

### 3. Repair the test that looks like the 33-byte HKDF-input pin and is not

**Landable now. [V] with two corrections that change the instructions.**

**The defect. [V]** `build_gossip_node_derives_gossip_only_subkey_from_encrypted_secret` (`crates/rustynetd/src/daemon.rs:20156`) claims to pin `decrypt_private_key`'s conditional newline append (`crates/rustynetd/src/key_material.rs:539`). Its fixture is 31 `'A'` plus `\n` — 32 bytes ending `0x0a`, counted programmatically — so the append is a no-op and deleting the append leaves the test green. This is worse than no test: the name and comment tell a reviewer the behaviour is covered.

**What changes:**
- Give the fixture bytes that do not end `0x0a`, and assert that property inside the test.
- **[VC] You must also change the expected-value computation.** Expected is derived from the *raw* fixture at `crates/rustynetd/src/daemon.rs:20191` (`let expected = derive_gossip_signing_key(plaintext_secret.to_vec());`). Change the fixture alone and expected derives over 32 bytes while `build_gossip_node` derives over 33 — the test goes red immediately, for a reason unrelated to the pin. Compute expected over the newline-appended input, e.g. `derive_gossip_signing_key([plaintext_secret.as_slice(), b"\n"].concat())`.
- Correct the comment.

**[VC] Do NOT drop the `not(target_os = "macos")` half of the cfg gate.** The first extraction said to. The test calls the real `encrypt_private_key` (`crates/rustynetd/src/daemon.rs:20174`), which on macOS reaches an unconditional error — `crates/rustynetd/src/key_material.rs:730` — and dies at the `.expect` on `:20179` before any derivation. `key_custody_manager` forces `RequireOsSecureStore` on macOS. The test's own doc comment already gives this reason. Keep the gate.

**Proof obligation:** delete the conditional newline append at `crates/rustynetd/src/key_material.rs:539` (and its guard line). The repaired test **must** fail. Today it passes. Also confirm `derive_gossip_signing_key_is_domain_separated` (`crates/rustynet-control/src/lib.rs:8011`) does not cover this — it uses a deliberately 32-byte secret and never calls `decrypt_private_key`.

**Two wrong fixes to refuse:** reverting the fixture (restores the vacuous pin this item exists to kill), and deriving expected from `decrypt_private_key` (tautological — both sides then share the append, deleting `:539` stays green, and the proof obligation silently becomes untestable).

---

### 4. A3.3 part 1 — `TraversalDecisionReason` gains an unattributed variant

**Landable now. [V]**

**What changes:** in `crates/rustynetd/src/traversal.rs` the race reports the same reason whether the winning endpoint came from `runtime.handshake_endpoint()` or from the `pairs[0]` fallback, so phase10 cannot tell attributed from unattributed. Add one variant to `TraversalDecisionReason` (e.g. `IcePairRaceHandshakeUnattributed`) at `crates/rustynetd/src/traversal.rs:615`/`:625`, add its arm to the exhaustive `as_str()` (`crates/rustynetd/src/traversal.rs:643`) with a new string, and select the reason in the same `match runtime.handshake_endpoint()?` that selects the endpoint — `crates/rustynetd/src/traversal.rs:1725`, `:1728`, `:1734`. `Some(endpoint)` keeps `IcePairRaceHandshakeObserved`; `None` takes the new variant.

Endpoint value, attempts, `latest_handshake_unix`, the `Direct` decision and every `send_probe` call are untouched. Connectivity is byte-for-byte identical.

**Blast radius, by symbol. [V]** `as_str` (`traversal.rs:643`) is exhaustive and must gain an arm. The trait default returning `Ok(None)` is at `crates/rustynetd/src/traversal.rs:714`. No crate outside `crates/rustynetd/src/{traversal.rs,phase10.rs}` and `crates/rustynetd/tests/ice_pair_race.rs` references the type.

**[VC] The relay-mapping `_ =>` arm at `crates/rustynetd/src/phase10.rs:6098` is not a risk.** The first extraction flagged it as a silent-mislabel hazard. It provably cannot be reached: `relay_or_fail_closed_for_race` has exactly three call sites, each passing a hard-coded relay reason, and it is the only constructor of `TraversalDecision::Relay` in the race path, while the new variant is constructed only at `traversal.rs:1734`. Making the mapping exhaustive is tidiness. Do not present it as a fix.

**Proof obligation:** extend `ice_race_falls_back_to_top_priority_when_runtime_lacks_endpoint_attribution` (`crates/rustynetd/tests/ice_pair_race.rs:391`) to also assert the reason is the new unattributed variant. Reverting `traversal.rs` makes that assertion fail while the attributed test still passes — that pair is what distinguishes this change from a blanket rename.

**[VC] Nothing to add at `ice_pair_race.rs:156`.** The first extraction asked for a new assertion in `ice_race_picks_highest_priority_winning_endpoint`. It already exists at `crates/rustynetd/tests/ice_pair_race.rs:219`.

**Same-commit update:** `ice_pair_race_final_round_observation_window_yields_direct` asserts `IcePairRaceHandshakeObserved` at `crates/rustynetd/src/traversal.rs:3271` with a runtime that has no `handshake_endpoint` override, so its expectation flips to the new variant in this commit.

---

### 5. Validate the attributed endpoint against the probed pairs

**Landable now, but it is dead defensive code until A3.2. [VC]**

**Prereq:** item 4.

**What changes:** at `crates/rustynetd/src/traversal.rs:1726`, a `Some(endpoint)` from `runtime.handshake_endpoint()` is used verbatim with no check that it is one of the endpoints just probed (pairs built near `crates/rustynetd/src/traversal.rs:1706`). Add the check: if the reported endpoint is not among the probed pairs, treat the outcome as unattributed (item 4's variant) rather than trusting the runtime.

**[VC] Two things the first extraction glossed:**
- `handshake_endpoint` has no production implementation, so this guard is unreachable until A3.2 lands. It is the guard that makes A3.2 safe to switch on later, not a live fix. Say that in the commit body.
- The comparison needs a type conversion: pairs hold `SocketAddr`, the runtime returns `SocketEndpoint`. Use `crate::ice_priority::socket_addr_to_socket_endpoint`.

**[VC] The proof obligation as first written is not writable.** `PlantedRuntime::send_probe` materialises `handshake_unix` only when the probed endpoint equals `winning_endpoint` — `crates/rustynetd/tests/ice_pair_race.rs:94`. Plant a winner that is not among the remote candidates and no probe matches, the stamp stays `None`, `handshake_advanced` is false, and the race never reaches the `Direct` arm at all. The proposed assertions are unreachable.

**Corrected proof obligation:** write a new runtime that decouples the two — the handshake advances off a *probed* endpoint while `handshake_endpoint` reports an off-set address. Model it on the bespoke runtime near `crates/rustynetd/tests/ice_pair_race.rs:480`. Assert the reason is the unattributed variant and the endpoint is the `pairs[0]` fallback. Reverting the validation makes the off-set endpoint be returned as attributed.

---

### 6. A3.3 part 2 — `TraversalProbeReason` gains the variant, phase10 stops discarding the engine reason, and the hard-coded aggregate literal goes

**Landable now. [V] with one required edit site the first extraction omitted.**

**Prereq:** item 4.

**What changes in `crates/rustynetd/src/phase10.rs`:**
- Add one variant to `TraversalProbeReason` (`crates/rustynetd/src/phase10.rs:266`), e.g. `UnattributedHandshakeObserved`.
- Add its arm to the exhaustive `as_str` (`crates/rustynetd/src/phase10.rs:279`) with a new status string.
- At the `Direct` arm of `evaluate_traversal_probes`, replace the discarded `reason: _` (`crates/rustynetd/src/phase10.rs:6073`) with a binding and map: `IcePairRaceHandshakeObserved` → `FreshHandshakeObserved`; the new engine variant → the new probe variant; everything else → the new probe variant as a conservative default (`crates/rustynetd/src/phase10.rs:6081`). Programming calls are untouched.

**[VC] REQUIRED third edit the first extraction missed.** `path_reason` is not purely fed from `direct_live_reasons`. The `direct_active` branch uses the collected reason only when exactly one distinct reason exists; every other case — zero live-direct statuses, or two-or-more distinct reasons — hard-codes the literal `"fresh_handshake_observed"` at `crates/rustynetd/src/daemon.rs:7398`. The source plan requires removing it (`documents/operations/active/I4TraversalAttestationPlan_2026-08-05.md:537`). Land A3.3 without touching `:7398` and a multi-peer fleet keeps reporting `path_reason=fresh_handshake_observed` while every race was unattributed — exactly the mislabelling this item exists to remove. The sibling `.unwrap_or` at `:7395` is dead code (inside the `len() == 1` guard, so `.next()` is always `Some`); only `:7398` is live.

**Consequence to state up front. [V]** `handshake_endpoint` has no non-test implementation — the `SimultaneousOpenRuntime` impl for `Phase10PeerRuntime` at `crates/rustynetd/src/phase10.rs:96` defines only `send_probe` and `latest_handshake_unix`, so the `Ok(None)` default applies. `FreshHandshakeObserved` therefore becomes unreachable at runtime and every production race reports the new variant.

**[VC] Operator visibility is narrower than first claimed.** `traversal_probe_reason=` (fed at `crates/rustynetd/src/daemon.rs:6768`) renders the per-peer reason only when exactly one probe status exists. With two or more, `traversal_probe_summary` returns the constant `"multi_peer_summary"` — `crates/rustynetd/src/daemon.rs:7194`. On a multi-peer node neither status field necessarily shows the new variant. Do not promise operators a visible signal that is not there.

**Downstream string consumers, checked by symbol. [V]** `crates/rustynet-cli/src/ops_cross_network_reports.rs` requires only that `last_path_reason` be non-empty and `first_non_direct_reason == "none"`. The live soak script classifies on `path_mode` (`direct_active`), never on the reason string. No gate keys off the old string.

**Proof obligation. [VC]** Update the existing assertion at `crates/rustynetd/src/phase10.rs:11312` — that update *is* the proof. Do not add the "new unit test beside `phase10.rs:11246`" the first extraction asked for; it would be the same test, same runtime, same race. Reverting the phase10 mapping makes the updated assertion fail.

**Same-commit updates, each independently revert-detectable:**
- `crates/rustynetd/src/phase10.rs:11312`.
- `daemon_runtime_auto_tunnel_periodic_reprobe_recovers_direct_after_relay`, near `crates/rustynetd/src/daemon.rs:24368`.
- `daemon_runtime_auto_tunnel_traversal_probe_recovers_direct_when_handshake_arrives`, near `crates/rustynetd/src/daemon.rs:24964`, which asserts both `path_reason=fresh_handshake_observed` and `traversal_probe_reason=fresh_handshake_observed`.

---

### 7. Stop the cross-session prior store learning the unattributed endpoint as a win

**Landable now. [V] Separate commit — this is behaviour change beyond A3.3.**

**Prereq:** item 6.

**What changes:** `race_outcome_classes` is called at `crates/rustynetd/src/daemon.rs:6744` and its winner predicate at `crates/rustynetd/src/daemon.rs:15901` is `decision == Direct && handshake_fresh` — it never consults `reason`. The misattributed `pairs[0]` class is persisted as a success and re-promoted on later races via `prior_rerank_pairs` (`crates/rustynetd/src/traversal.rs:1682`). Thread the reason (or an `attributed: bool`) into `race_outcome_classes` (signature near `crates/rustynetd/src/daemon.rs:15882`) and require an attributed reason for `winning` to be `Some`. `tried` is unaffected.

Programming is still untouched, but what the daemon *learns* changes. That is why this is not folded into A3.3, and why the commit body must not repeat A3.3's "byte-for-byte identical" claim.

**Proof obligation:** extend `race_outcome_classes_maps_decisions_to_prior_evidence` (near `crates/rustynetd/src/daemon.rs:15922`) with a case: `Direct` + fresh handshake + unattributed reason must yield `winning == None`, `tried` unchanged. Reverting the predicate makes `winning` `Some(class)`.

---

### 8. Stop the non-due clone-forward stripping endpoint attribution from the status

**Landable now. [V] with a corrected proof recipe.**

**What changes:** in the `!probe_due` branch of `sync_traversal_runtime_state` (`crates/rustynetd/src/daemon.rs:6637`–`:6641`), the retained status keeps `decision`, `reason` and `attempts` from an arbitrarily old pass while `selected_endpoint` is **overwritten** with `self.controller.managed_peer_endpoint(...)` (read at `crates/rustynetd/src/daemon.rs:6613`) and the stamp is refreshed from the backend by node_id only. So `(reason = FreshHandshakeObserved, fresh stamp, selected_endpoint = whatever is programmed now)` is reachable with the reason earned at a *different* endpoint. The §4 invariant is endpoint attribution, not freshness.

Pick one, self-contained in `daemon.rs`, no wire, no gossip, no backend:
- (a) do not overwrite `retained.selected_endpoint`, and downgrade `reason` to a non-attesting variant when `managed_peer_endpoint != retained.selected_endpoint`; or
- (b) carry an explicit `attributed_endpoint` + `last_attributed_unix` on `TraversalProbeStatus` (`crates/rustynetd/src/daemon.rs:2159`) that the clone-forward never rewrites.

Note the stamp is sticky by construction (`crates/rustynetd/src/daemon.rs:6640`, `:6641`).

**[VC] The proof recipe as first written never exercises the branch.** `traversal_probe_due_decision` returns true immediately when the currently programmed endpoint is not itself one of the offered direct candidates — `crates/rustynetd/src/daemon.rs:2201` — and again unless the effective handshake is fresh. So `probe_due` is true for an arbitrary E2 and control never reaches the clone-forward.

**Corrected proof obligation:** (1) drive one due probe to an attesting `Direct` status at endpoint E1; (2) reprogram the managed peer endpoint to E2, **where E2 is a direct candidate of the same signed bundle**, keeping a fresh handshake stamp; (3) run `sync_traversal_runtime_state` with the probe not due; assert the retained status does not simultaneously report an attesting reason and `selected_endpoint == E2`. Pacing scaffolding for a not-due pass exists at `crates/rustynetd/src/daemon.rs:24405`. Reverting the change makes the status read `(attesting reason, E2)`.

---

### 9. The per-peer deny predicate that gates any future deny

**Landable now. [VC] — the first extraction marked this blocked; the blocker was retired.**

**What changes:** the plan's gate is `matches!(self.controller.state(), DataplaneApplied | ExitActive)` — the same condition the early return in `sync_traversal_runtime_state` already uses (`crates/rustynetd/src/daemon.rs:6441`, `:6443`, `:6445`). `Controller::state()` is `&self` (`crates/rustynetd/src/phase10.rs:5158`), so it is readable from `&self`.

**A state-only gate is a new-peer brick. [V]** The status map is populated per peer from `self.controller.managed_peer_ids()` (`crates/rustynetd/src/daemon.rs:6473`), which is the keys of `managed_peers` from the last applied generation (`crates/rustynetd/src/phase10.rs:6155`). The `peers` argument to `apply_traversal_authority_to_peers` comes from the freshly verified bundle (`crates/rustynetd/src/daemon.rs:9266`, feeding expected peers at `crates/rustynetd/src/daemon.rs:6980`). A peer newly added to the bundle has no status even in `DataplaneApplied`. The predicate must be **per peer**: deny only when started **and** that peer was already in the managed set; otherwise fall through.

**[VC] This is not a finding the plan omits.** The plan states it verbatim: `documents/operations/active/I4TraversalAttestationPlan_2026-08-05.md:56` ("**RETRACTED — §7's \"the two conditions agree by construction\" is false**") and "a correct design needs a per-peer skip for never-yet-programmed peers, not a global state gate" at `:63-64`, repeated at `:546-547`. Do not present it as new.

**[VC] The live-read-vs-snapshot question is decided, not open.** `apply_dataplane_generation` only inserts into `managed_peers` (`crates/rustynetd/src/phase10.rs:5370`) and never prunes. The only key removals are `apply_revocation` (`crates/rustynetd/src/phase10.rs:5812`, reached from `crates/rustynetd/src/daemon.rs:8825`, outside reconcile), `shutdown` (`crates/rustynetd/src/phase10.rs:6205`), and the single-peer rollback (`crates/rustynetd/src/phase10.rs:5538`). Nothing mutates the key set between the sync at `crates/rustynetd/src/daemon.rs:9246` and the apply at `:9323`. **Read `managed_peer_ids()` live at apply time. No snapshot field is needed.**

**Ordering already favourable, needs no change. [V]** `refresh_traversal_hint_state` — the sole production caller of `sync_traversal_runtime_state` (`crates/rustynetd/src/daemon.rs:4978`) — runs at `crates/rustynetd/src/daemon.rs:7703` before the bootstrap apply at `:7728`, and at `:9246` before the reconcile apply at `:9323`.

**Proof obligation, two tests:**
- (a) Cold start: controller in `Init`, enforcement on, non-empty bundle peers, empty statuses. Apply must succeed with the static bundle endpoint and the controller must reach `DataplaneApplied`. Reverting the gate to an unconditional deny must make this fail (permanent restriction).
- (b) New peer: controller already `DataplaneApplied` with peer A managed, bundle now lists A and B, statuses hold A only. B must be programmed from the bundle. Reverting the per-peer half to a state-only check must make (b) fail.

**The plan wants a per-peer skip, not a vector-fatal `Err`. [VC]** One peer failing fails the whole peer vector into `crates/rustynetd/src/daemon.rs:9330-9332`. The plan objects to exactly that blast radius (`documents/operations/active/I4TraversalAttestationPlan_2026-08-05.md:63-64`). Whatever you write must skip the peer, not the pass.

---

### 10. Turn the static-endpoint else branch into a gated deny

**Blocked. See §2 and §3. [VC]**

**What would change:** the else arm of the per-peer loop in `apply_traversal_authority_to_peers`. Today if a probe status exists the peer endpoint comes from it (`crates/rustynetd/src/daemon.rs:7013`, `:7014`); otherwise from the signed bundle via `static_traversal_endpoint` (`crates/rustynetd/src/daemon.rs:7016`). That arm becomes conditional on item 9's predicate. Everything else in the function stays byte-for-byte, including the enforcement short-circuit, the hint-error arm, the missing-envelope arm and the index build.

**[VC] Why it is blocked, corrected on two counts:**
- The first extraction listed `a3.3-reason-split` as the prereq. **That design is retracted** at `documents/operations/active/I4TraversalAttestationPlan_2026-08-05.md:43` ("**RETRACTED — A3.3 does not achieve its stated goal**"), because the proof surface is reason-blind, the aggregate literal is hard-coded (`daemon.rs:7395`, `:7398`), and it breaks named in-tree assertions. §9 repeats it at `:519-520`. The surviving chain is item 2 plus A3.1 plus a proof-surface change (`:525-538`). Do not build against the retracted design.
- **With item 9's per-peer refinement the deny is unreachable in production**, so as specified it is a no-op whose proof cannot fail on revert. A successful sync inserts a status for every managed peer (loop at `crates/rustynetd/src/daemon.rs:6500`, inserts at `:6642` and `:6763`); a failed sync sets `traversal_hint_error` (`crates/rustynetd/src/daemon.rs:4979`) so apply already `Err`s before the loop; not-started and never-yet-managed peers are exempted. Both call sites refresh immediately before applying. **Consequence: the control-plane endpoint is still programmed once for every peer at first contact, so the §2.1 fail-open is not closed by this item.**

**Corrected proof obligation if it is ever unblocked:** call `apply_traversal_authority_to_peers` **directly** with hand-built state. Driving it through the reconcile path re-populates the status and the test passes either way.

---

### 11. Add an explicit-passphrase decrypt primitive

**Landable now. [VC] — this item did not exist in the first extraction, and five items depend on it.**

**What changes:** add `decrypt_private_key_with_passphrase(encrypted_key_path, passphrase_path, explicit_passphrase_path)` to `crates/rustynetd/src/key_material.rs`, calling `read_passphrase_file_explicit` plus `key_custody_manager`, mirroring the existing `encrypt_private_key_with_passphrase`.

**Why it is required. [VC]** The only decrypt function in the file is `decrypt_private_key` (near `crates/rustynetd/src/key_material.rs:529`, `:538`). It resolves the passphrase through `read_passphrase_file` → `resolve_passphrase_source`, which **refuses** the configured path — `crates/rustynetd/src/key_material.rs:761`. The explicit escape hatch exists only on the encrypt side. The repo documents this hazard itself near `crates/rustynetd/src/main.rs:508-510`, which is why the mint threads `Some(passphrase_path)` explicitly. Without this primitive, item 12's `--passphrase-file` flag is inert and the verb hard-fails for exactly the root operator who needs it.

**Proof obligation:** a `key_material` unit test that encrypts with an explicit passphrase path and decrypts through the new function with the same explicit path, with neither `CREDENTIALS_DIRECTORY` nor the credential-path env var set. Remove the explicit-path plumbing and it must fail with the refusal error at `key_material.rs:761`.

---

### 12. Add the missing export primitive: print the derived gossip verifying key

**Landable after item 11. [VC] — the first extraction marked it landable; it was not.**

**Prereq:** item 11.

**What changes:** a fourth `key` subcommand, sibling of `init-gossip`, taking `--gossip-signing-secret <abs path>` and `--passphrase-file <abs path>`. It calls the new explicit-passphrase decrypt then `derive_gossip_signing_key` **unmodified**, and prints `verifying_key().to_bytes()` as lowercase hex. Extend the `match args[0]` dispatch and the "key subcommand is required" error string at `crates/rustynetd/src/main.rs:460`, `:466`, and add a `help_text()` line beside `init-gossip` at `crates/rustynetd/src/main.rs:4354`.

**Hard requirements. [V]**
- Never print the secret.
- Three distinguishable errors: not-minted, cannot-read, and the Windows DPAPI self-test failure inherited from `crates/rustynetd/src/key_material.rs:529`, which runs before custody opens.
- Do **not** re-implement HKDF.
- Do **not** strip the trailing newline. `decrypt_private_key` conditionally appends `b'\n'`, so the daemon's HKDF input is 33 bytes for 255 of 256 minted secrets.

**[VC] Put the inner function in the lib crate, not in `main.rs`.** `crates/rustynetd/src/main.rs:1` is `#![forbid(unsafe_code)]`, which — unlike a `deny` — cannot be locally overridden by `#[allow]`. `main.rs` declares no modules. Cargo edition is 2024, where `std::env::set_var` is unsafe. So a test that must set the passphrase credential env var cannot be written in `main.rs`. It is also process-global and would race the parallel test binary. Take an explicit passphrase path (item 11) and host the inner function in the lib crate; then no env var is needed.

**Proof obligation:** encrypt a fixture secret whose final byte is **not** `0x0a` (assert that in the test), run the export verb's inner function, and assert its output equals hex of the `local_node_id` derived from `derive_gossip_signing_key(decrypt_...(...))`. No independent crypto in the test. Two mutations must make it fail: (a) the verb strips the trailing newline before deriving; (b) the verb re-implements HKDF instead of calling `derive_gossip_signing_key`. A fixture ending `0x0a` makes mutation (a) pass vacuously — that exact trap already shipped (item 3).

---

### 13. `enrollment admit --pubkey` carries the enrollee's derived gossip key, and gains point validation

**Landable after item 12. [V] with corrected anchors.**

**Prereq:** item 12.

**What changes.** `execute_enrollment_admit` base64-decodes `--pubkey`, checks length 32, hex-encodes, and hands it to `EnrolleeAdmitContext.node_pubkey_hex`, which `build_add_node_record_for_enrollee` writes into the `AddNode` node. The field's own doc already claims a 32-byte Ed25519 verifying key — the contract exists, only the value is wrong. Two changes: (1) document and operationally require that the operator obtain the value from the enrollee's own export verb — today nothing in the repo computes it except `random_url_safe_pubkey()` in a lab bin; (2) add `VerifyingKey::from_bytes` validation on the admit side.

**The two halves currently disagree. [V]** `enrollment consume` rejects a non-point in the daemon at `crates/rustynetd/src/daemon.rs:8610`; `admit` checks base64 and length only.

**[VC] Corrected anchors — all four `rustynet-cli/src/main.rs` anchors in the first extraction were stale.** `fn execute_enrollment_admit` is at `crates/rustynet-cli/src/main.rs:8406`; the length check at `:8417`; the hex encode at `:8423`; `node_pubkey_hex: pubkey_hex,` at `:8458` (correct). The context field's doc line is at `crates/rustynet-control/src/enrollment.rs:63`, not `:64`. Related drift in other items, confirmed by symbol: `peer_gossip.rs:662` (not `:657`), `daemon.rs:5712` (not `:5711`), `membership.rs:1825` (not `:1824`).

**Proof obligation:** make `enrollment admit` accept a non-canonical point; the new admit-side validation test must fail. **Match the runtime rule, not the spec. [V]** `ed25519_dalek::VerifyingKey::from_bytes` (pinned 2.2.0) does decompression only — no small-order rejection; that happens later at `verify_strict`, reached at `crates/rustynetd/src/peer_gossip.rs:515`. A test written from "canonical point" would be stricter than the consumer.

---

### 14. Validate the value `RotateNodeKey` installs

**Landable after item 12. [V] with a corrected anchor.**

**Prereq:** item 12.

**What changes.** `MembershipOperation::RotateNodeKey { node_id, new_pubkey_hex }` writes `node.node_pubkey_hex = new_pubkey_hex.clone()` in the reducer, validated only by `decode_hex_to_fixed::<32>`. The value arrives through a field named `new_pubkey_hex` and a flag named `--new-pubkey`, invisible to a `node_pubkey_hex` grep and to greps for the four other flag spellings — which is why every earlier enumeration pass missed it. Nothing constrains what an operator passes, so the mechanism meant to *fix* the wrong-key problem can install another wrong key.

Whatever validation lands must cover all three sites carrying this field: `MembershipState::validate` (`crates/rustynet-control/src/membership.rs:240`), the `AddNode` reducer arm (`:1948`), and the `RotateNodeKey` reducer arm (`:2012`). Both CLI routes reach it: `membership propose-rotate-key` (`crates/rustynet-cli/src/main.rs:6004`) and `membership propose --operation rotate-node-key|rotate-key` (`:6183`). Operation anchors: `crates/rustynet-control/src/membership.rs:417`, `:419`, `:2018`.

**[VC] The `:546` "canonical-payload validator" cite is wrong twice.** `membership.rs:546` is inside the **AddNode** arm. The RotateNodeKey arm's corresponding call is `crates/rustynet-control/src/membership.rs:585`. And `validate_membership_payload_field` only checks length and rejects the framing bytes `\n`, `\r`, `=`; it takes a bare `&str` with no key semantics and is shared with node ids, owners and roles. It is a framing guard, not a key validator — adding curve validation there is the wrong layer. Use `:585` or drop the addendum.

**Proof obligation:** a migration passes a WireGuard (X25519) public key to `--new-pubkey`; the new validation on the RotateNodeKey path must reject it.

**Do not oversell this. [V]** Both X25519 and Ed25519 public keys are 32 bytes, so length can never separate them, and a decompression check discriminates exactly half (`8ℓ/2^256 = 0.5` in closed form). Independently reproduced: `[7u8;32]` and `[2u8;32]` are not points; `[9]`, `[10]`, `[11]`, `[1]`, `0xaa/0xbb/0xcc/0x0a` repeated all are; all-zero decompresses but is small order. A WireGuard key that happens to decompress still passes. The real gate stays `gossip_identity_mismatch` (`crates/rustynetd/src/daemon.rs:5698`), which compares against the node's own derived key.

---

### 15. Re-byte the fixtures a point tripwire breaks

**Landable after item 14. [VC] — "exactly two fixtures" was false; at least six break, four on positive paths.**

**Prereq:** item 14.

**Fixtures that must be given new bytes:**
- `crates/rustynet-control/src/membership.rs:2867` — `hex_encode(&[7; 32])`, not a point. **[V]**
- `crates/rustynet-control/src/enrollment.rs:559` — `hex_lower(&[2u8; 32])`, not a point. **[V]**
- **[VC]** `crates/rustynet-control/src/enrollment.rs:490` — a second `[7u8; 32]` in the same file, feeding `build_add_node_record_for_enrollee(...).expect(...)`, an explicitly **positive** assertion that reaches `MembershipState::validate` and the AddNode decode.
- **[VC]** `crates/rustynet-control/src/membership.rs:2838` and `:2844` — `active_node("node-b", 7)` twice in `canonical_state_and_root_are_deterministic`, both flowing into `canonical_payload().expect(...)`. Hidden from the first sweep because they go through a parameterised `active_node(id, byte)` helper rather than a literal.
- **[VC]** `crates/rustynet-control/src/membership.rs:4913` — `active_node("node-evil", 66)`; byte 66 is not a point. (127 of 256 repeated bytes fail decompression.)
- **[VC] Worst hit, an entire target type the sweep missed:** `crates/rustynet-control/examples/perfprobe_membership.rs:44` builds 50 nodes via `pubkey_hex(seed) = seed ^ i`; 20 of the 50 fail decompression, and the example calls `state.canonical_payload().expect(...)`. An `examples/` target is neither `#[cfg(test)]` nor library production code — the same hiding mechanism as `src/bin/` in item 16.

**Small-order cases, distinct from non-points. [VC]** `crates/rustynet-cli/src/main.rs:22250` uses `"00".repeat(32)` (inside `#[cfg(test)]`), and `crates/rustynetd/src/gossip_runtime.rs:2080` builds an all-zero pubkey. Both decompress but are small order: they pass a decompression tripwire and would fail any `verify_strict`-grade strengthening.

**Not affected. [V]** The three shipped audit binaries: their `MembershipNode` constructors are parameterised on `pubkey_byte` and the values actually passed are 9, 9 and 10 — all valid non-small-order points. Their `#[cfg(test)]` blocks begin **after** those constructors (`crates/rustynetd/src/membership_signature_audit.rs:562`, `crates/rustynetd/src/membership_revoke_audit.rs:396`, `crates/rustynetd/src/blind_exit_reversal_audit.rs:228`), so the constructors are production code, and all three are dispatched as real verbs (`crates/rustynetd/src/main.rs:240`).

**Proof obligation:** after adding the tripwire, `rustynetd membership-signature-audit`, `rustynetd membership-revoke-audit` and `rustynetd blind-exit-reversal-audit` must all still pass unchanged. Each re-byted fixture must still exercise the same reject path it exercises today — verify by reading each test's assertion, not by the test merely going green.

---

### 16. The shipped lab binary that admits a random 32-byte value

**Landable after items 12, 13, 14. [VC] — prereqs were incomplete.**

**Prereqs:** item 12 (the value must come from somewhere), item 13 (this bin passes it to `enrollment admit --pubkey`), item 14.

**What changes.** `crates/rustynet-cli/src/bin/live_linux_anchor_test.rs:1394` calls `random_url_safe_pubkey()` — 32 random bytes, base64url — and passes it as `--pubkey` at three call sites (`:1469`, `:1529`, `:1572`). This is a real bin target, not a `#[cfg(test)]` fixture, and it appears in no row of the design document's producer table. It survived every previous enumeration because it lives in `src/bin/` and uses the fifth flag spelling. Two consequences: under alignment it must present the enrollee's real derived gossip key; under a decompression tripwire, random 32 bytes are a valid point with probability exactly 1/2, making this a 50%-flaky live-lab failure.

**Proof obligation:** run the positive-admit leg 20 times with the tripwire in place; it must pass every time. Today, with random bytes, roughly half fail. The negative legs (`:1770`, `:1774` — wrong-secret token, bad-approver token) must still reject for their **original** reason — a token/approver reject, not a pubkey reject — otherwise the tripwire has made two adversarial cases vacuous.

**[VC] The wrong fix to refuse:** hardcoding some valid point to make the run green. That converts a 50%-flaky failure into a permanently *wrong* published key — the exact defect class this whole work area exists to remove.

---

### 17. Read-time hold bound

**Landable after item 10 and the store. [VC] — the first extraction marked it blocked on TTLs it could not find; they are locatable.**

**Prereqs:** the attestation store (§2), item 10.

**What changes.** The bound is evaluated where the deny is decided, in `apply_traversal_authority_to_peers` (`&self`, read-only): a peer is holdable iff a record exists, the record is within the bound, **and** the record's endpoint matches the endpoint about to be programmed. Because it is derived at read time, a peer that stops gossiping ages out with no expiry write and no candidate expiry.

**[VC] The TTLs the §6 invariant means are the 120 s / 300 s signed-state windows, not the 30 s probe windows.** `DEFAULT_TRAVERSAL_MAX_AGE_SECS = 120` at `crates/rustynetd/src/daemon.rs:251`; the 300 s trust/auto-tunnel/dns max ages at `crates/rustynetd/src/daemon.rs:223`, `:298`, `:355`. The sibling doc names them at `documents/operations/active/TraversalSelfSustenancePlan_2026-07-23.md:58`, and the invariant text lives at `:380`. Clamping the hold to the 30 s handshake-freshness / reprobe defaults (`crates/rustynetd/src/daemon.rs:310`, `:311`) makes the persistent store near-useless: the reprobe floor is itself 30 s, so every peer ages out inside one reprobe period. Both probe windows are operator-tunable via CLI (`crates/rustynetd/src/main.rs:3374`), so express the bound relative to the chosen window or clamp it — do not hard-code.

**Do not source the timestamp from `TraversalProbeStatus::latest_handshake_unix`.** It is sticky through the `.or(...)` on the non-due path (`crates/rustynetd/src/daemon.rs:6641`), so reading the field rather than comparing it inherits a permanently-populated value.

**Proof obligation:** attest a peer, advance the clock past the bound with no new attestation, assert the peer is denied on the next apply while a peer attested within the bound is held. Widening the bound past the chosen window must fail a companion assertion.

---

### 18. Clear attestation on revocation and on peers leaving the managed set

**Landable after the store. [V] with a corrected placement.**

**Two clear sites, both `&mut self`:**
1. Revocation: the teardown loop in `handle_membership_apply` (`crates/rustynetd/src/daemon.rs:8680`; loop at `:8802`) calls `self.controller.apply_revocation(&peer_id)` at `crates/rustynetd/src/daemon.rs:8825`. The record must be removed in the same block, before the calls at `crates/rustynetd/src/daemon.rs:8836`, so a re-admitted node cannot inherit a stale proof. `apply_revocation` lives on the controller while the store lives on the daemon runtime, so the clear cannot go inside `apply_revocation`.
2. Peers dropping out of the managed set: `sync_traversal_runtime_state` already computes `stale_probe_peers` and closes their relay sessions (`crates/rustynetd/src/daemon.rs:6475`, `:6481`, `:6482`), matching how `poll_path_quality` retains only live peers (`crates/rustynetd/src/daemon.rs:6801`).

**[VC] The clear must precede the managed-set guard at `crates/rustynetd/src/daemon.rs:8822`.** `apply_revocation` at `:8825` sits *after* an early `continue` that skips every peer the controller does not currently manage. Put the clear at `:8825` and a revoked node holding a persisted record but no live managed peer keeps its record — precisely the stale-proof case this item exists to close.

**[VC] Site (2) does not cover bundle removal.** Because an apply never prunes `managed_peers` (`crates/rustynetd/src/phase10.rs:5370` inserts only), a peer dropped from the bundle stays in `managed_peer_ids()` indefinitely, so `stale_probe_peers` rarely fires. Do not rely on it.

**Also decide explicitly** what the roughly eleven `self.traversal_probe_statuses.clear()` error paths do to the attestation store (`crates/rustynetd/src/daemon.rs:4936`, `:4953`, `:4966`, `:4975`, `:6445`, `:6452`, `:6459`, `:6490`, `:6502`, `:6515`, `:6541`). Clearing is the fail-closed direction and is safe, but state the choice.

**Proof obligation:** attest peer P, apply a membership update flipping P off Active, assert P's record is gone and P is denied on the next apply. Removing the clear must make it fail.

---

### 19. Only the §4-conforming arms may write attestation

**Blocked on §3, and on the store. [V] arm enumeration; [VC] blocker and attesting set.**

**The enum is closed. [V]** `TraversalProbeReason` at `crates/rustynetd/src/phase10.rs:266`, no `FromStr`, no serde. Its only construction sites are `crates/rustynetd/src/phase10.rs:5981`, `:6000`, `:6016`, `:6081`, `:6096`, `:6098`, `:6126`. That is the complete set.

**The four non-attesting arms must never write:** `NoDirectCandidatesRelayArmed` (`:6000`, remapped `:6096`), `CoordinationRequiredRelayArmed` (`:6016`), `DirectProbeExhaustedRelayArmed` (`:6098`), `DirectProbeExhaustedUnprovenDirect` (`:6126`).

**[VC] `ExistingFreshHandshake` is also non-attesting and must be excluded or repaired.** Its report (`crates/rustynetd/src/phase10.rs:5981`, `:5983`) sets `selected_endpoint` from `backend.current_peer_endpoint(node_id)` — a read of the **cached configured value**, confirmed at `crates/rustynet-backend-wireguard/src/linux_command.rs:494` (`Ok(self.peers.get(node_id).map(|peer| peer.endpoint))`) — and the stamp from `peer_latest_handshake_unix`, keyed by node_id only. Its only guard is that the cached endpoint appears somewhere in the direct candidates. That is exactly the `(reason, fresh stamp, endpoint nothing proved)` tuple §4 forbids, reachable on any due probe, with no clone-forward involved. Fixing item 8 does not close it.

**[VC] The blocker cited in the first extraction is retracted.** §3.4's empirical contingency is retracted at `documents/operations/active/I4TraversalAttestationPlan_2026-08-05.md:66-72` and confirmed at `:550-552`. The real blocker is that `FreshHandshakeObserved` (`:6081`, `:6083`) takes its endpoint from the race's own `Direct { endpoint }`, which is unsound until A3.2/A3.3 land — and A3.2 needs an off-limits crate. See also the unresolved conflict in §0.

**Freshness re-check, and its own weakness. [V]** The write must re-check with `traversal_handshake_is_fresh` (`crates/rustynetd/src/daemon.rs:6944`, `:6946`), noting `now_unix.saturating_sub(timestamp)` yields 0 for a future-dated stamp — a future-dated handshake reads as permanently fresh and must be rejected explicitly before it is persisted.

**Proof obligation:** a table-driven test over all `TraversalProbeReason` variants asserting only the admitted set writes a record. Adding `DirectProbeExhaustedUnprovenDirect` to the write set must make it fail.

---

## 2. Do not do this

Each of these already cost a round. They are listed because the shape of the mistake recurs, not because anyone is careless.

**Do not delete the ICE-race attribution fallback.** At `crates/rustynetd/src/traversal.rs:1725-1739` the race falls back to `pairs[0]` when `runtime.handshake_endpoint()` returns `None`. `handshake_endpoint` has **no production implementation** — the `Phase10PeerRuntime` impl at `crates/rustynetd/src/phase10.rs:96` defines only `send_probe` and `latest_handshake_unix`, so the `Ok(None)` trait default at `crates/rustynetd/src/traversal.rs:714` applies to every production race. Delete the fallback and the race never returns a `Direct` decision, on any node, ever. That removes direct connectivity fleet-wide. The correct move is to **relabel** it (item 4), not remove it. **[V]**

**Do not implement a per-peer "hold" that falls through to the static endpoint.** Silently keeping the control-plane endpoint from `static_traversal_endpoint` (`crates/rustynetd/src/daemon.rs:7016`) when attestation is missing is a fail-open dressed as a hold. A hold that programs the unproven endpoint anyway has proven nothing. **[V]**

**Do not deny on missing attestation at cold start.** The four-link chain in item 1 makes an unconditional deny inescapable, and the reconcile arm escalates to **permanent** restriction after 5 failures (`crates/rustynetd/src/daemon.rs:9598`, `DEFAULT_MAX_RECONCILE_FAILURES = 5` at `:338`). This is a brick, not a degraded mode. Any deny needs item 9's per-peer predicate first. **[V]**

**Do not establish call sites from one grep pattern.** This has already shipped a fleet-brick. Concrete recurrence in this very work: a non-generic grep for `TunnelBackend for` finds `in_memory.rs:419`, `userspace_shared/mod.rs:425`, `userspace_shared_macos/mod.rs:510` and **misses the three production command backends**, which are written `impl<R: WireguardCommandRunner + Send + Sync> TunnelBackend for ...` — `crates/rustynet-backend-wireguard/src/linux_command.rs:400`, `macos_command.rs:546`, `windows_command.rs:409`. Those are the `DaemonBackend::Linux`/`::Macos`/`::Windows` variants, i.e. the primary Linux production path. A defaulted trait method leaves all three returning `Ok(None)` silently. **Enumerate by symbol, then count, then state the count.** **[VC]**

**Do not trust a dispatch-layer pin to catch a missing backend impl.** `crates/rustynetd/src/daemon.rs:19733` is a source-text pin on the `DaemonBackend` dispatch block only. A defaulted `Ok(None)` one layer down passes it silently. That is exactly the retry22-31 regression: a defaulted trait method no-opping through `DaemonBackend`. **[VC]**

**Do not `git checkout -- <file>` to undo a mutation before committing.** It restores to the last commit and takes uncommitted work with it. This destroyed a patch three times in one session per `HANDOVER_2026-08-05.md:137` (AGENTS.md records four at `AGENTS.md:112` — the discrepancy is unresolved; either way, **commit before you mutate**). **[VC]**

**Do not use `git commit -F -` with a heredoc.** It hangs. Write the message to a file and use `git commit -F <file>`. **[V]**

**Do not add a Claude or co-author trailer to any commit.** See §5. **[V]**

**Do not drop the macOS cfg gate on the encrypted-custody tests** (item 3). **[VC]**

**Do not report a workspace-wide green run as covering `gui/`, `fuzz/`, or `crates/rustynet-lab-monitor/`.** See §5. **[V]**

---

## 3. Blocked on

### 3a. Blocked on unimplemented design work

**Item 2 of the source plan — close the fail-closed arm so the producer stops programming unproven endpoints.** Not landable as an isolated edit. `crates/rustynetd/src/phase10.rs:6109`–`:6131` currently picks `max_by_key(priority)` — the **sender's** integer carried verbatim from the signed bundle — then programs it and reports `Direct` / `DirectProbeExhaustedUnprovenDirect` (`:6113`, `:6120`, `:6122`, `:6126`). Four obstacles:
- No representable "nothing was programmed" value. `TraversalProbeReport.selected_endpoint` is non-`Option` (`crates/rustynetd/src/phase10.rs:301`) and `TraversalProbeDecision` is only `Direct|Relay` (`:251`, `as_str` at `:259`).
- Returning `Err` instead is a fleet hazard, not a fix. `sync_traversal_runtime_state` propagates per-peer errors with `?` (`crates/rustynetd/src/daemon.rs:6702-6707`) and its caller at `:4978` responds in enforced mode with `restrict_recoverable` + `force_fail_closed_or_restrict("traversal_runtime_sync_failed")`. One peer's exhausted race would fail-close the whole node, and because `statuses` is a local moved into `self` only at `:6785`, the whole pass's status map is discarded too. Per-peer denial without that deadlock is item 4 of the plan, listed as not landable.
- Not programming does not unprogram. `send_probe` already called `reconfigure_managed_peer` for every probed pair (`crates/rustynetd/src/phase10.rs:103`), so the backend holds `pairs[last]`. Closing the arm honestly needs an explicit revert, and no helper does this; the closest is `apply_revocation`, which removes the peer wholesale.
- The plan's "for gossip-sourced candidates" scoping is inexpressible: `TraversalCandidate` (`crates/rustynetd/src/traversal.rs:35`) has `endpoint`/`source`/`priority`/`observed_at_unix` and no provenance field. `CandidateSource` is ICE candidate *type*, not gossip provenance. **[V]**

**[VC] Two corrections to that item's own reasoning.** (i) The arm is **not** reached only after an exhausted race. `execute_ice_pair_race` also short-circuits to `relay_or_fail_closed_for_race` with attempts 0 when local or remote direct candidates are empty — `crates/rustynetd/src/traversal.rs:1649` — and again when pair generation yields nothing. `all_local_candidates` returns an empty Vec when there are no usable host interfaces and no STUN candidates, so this is a production path. In that case phase10 programs the sender-supplied max-priority endpoint having sent **zero** probes, and obstacle 3 does not apply because nothing was programmed. (ii) `TraversalDecision::FailClosed` is constructed at three sites, not one: `crates/rustynetd/src/traversal.rs:1528`, `:1585`, `:1782`. The first two are in `execute_simultaneous_open`, which has no non-test caller today — harmless, but an unenumerated "only" is the error class this review exists to catch.

**Its prerequisite — give the report a way to say "nothing was programmed".** Either a third `TraversalProbeDecision` variant or `Option<SocketEndpoint>`. **[VC]** the ripple lists in the first extraction are both wrong. The `==` comparison sites are **eight**, not seven, and one of them is a `matches!` on `Option<TraversalProbeDecision>` rather than an `==`: `crates/rustynetd/src/daemon.rs:6354`, `:6581`, `:6708`, `:6727`, `:6797`, `:7152`, `:7157`, `:15901`. The `Option`-ing ripple additionally touches the clone-forward write at `crates/rustynetd/src/daemon.rs:6638` and `race_outcome_classes`' own signature and comparison near `:15885` and `:15905`. Since this item's whole value is that it enumerates by symbol, an incomplete ripple list is the defect. Landing the variant alone adds an unconstructed state and eight unreviewed comparison sites. **Only meaningful together with the item above.**

**Item 3 of the source plan — the attested predicate.** Blocked. Today `apply_traversal_authority_to_peers` trusts mere existence of a status (`crates/rustynetd/src/daemon.rs:7013`, `:7014`). There is no attested predicate anywhere over traversal probe status. **[VC] three corrections:** the proposed attesting set still admits a non-attesting arm via `ExistingFreshHandshake` (see item 19); the predicate makes reconcile a **second, contradicting endpoint writer** — `apply_traversal_authority_to_peers` runs every reconcile tick (`crates/rustynetd/src/daemon.rs:9323`) and its output feeds `configure_peer`, while the probe path programs the raced endpoint inside the same pass, so a rejected status means reconcile overwrites the just-programmed endpoint every tick while the probe reprograms it whenever due (endpoint churn between two writers, the handshake-collision family the repo already regressed on — see the pacing comments near `crates/rustynetd/src/daemon.rs:24406`); and the predicate has **no time value in scope** — `apply_traversal_authority_to_peers` (`crates/rustynetd/src/daemon.rs:6958`) takes `&self`, peers and the membership directory only, and neither caller passes a `now_unix`, so either call `unix_now()` internally or add a parameter (reconcile already computes one near `:9241`). That choice decides whether the proof test can pin a deterministic stamp. **[VC] the first extraction also mis-attributed `attest` grep results** — `linux_authenticode.rs`, `macos_authenticode.rs` and `main.rs` also hit. The conclusion survives.

**Item 5 of the source plan — the persisted attestation store.** Blocked on a representation decision. **[VC] `endpoint: SocketEndpoint` cannot be serialized where the item puts it.** `SocketEndpoint` derives only `Debug, Clone, Copy, PartialEq, Eq` (`crates/rustynet-backend-api/src/lib.rs:32`), has no manual serde impl anywhere in the tree, and `crates/rustynet-backend-api/Cargo.toml` has an **empty** `[dependencies]`. `PeerTraversalPrior` sidesteps this by storing only local and std types. So this needs either serde added to a dependency-free crate plus a derive on a public backend-API type (unmentioned, and a public-type change), or a serde-able representation with conversion. Decide with the operator.

The rest of the store shape is sound. New module `crates/rustynetd/src/peer_traversal_attestation.rs`, declared beside `pub mod peer_traversal_prior;` at `crates/rustynetd/src/lib.rs:17`. Mirror `PeerPriorStore`'s on-disk discipline exactly: one JSON body line plus a `digest_sha256=` line, persist via a `create_new` temp file opened with `options.mode(0o600)` then `fs::rename`, `create_dir_all` on the parent first — `crates/rustynetd/src/peer_traversal_prior.rs:161`, `:196`, `:223`, `:227`, `:239`. Field beside `peer_prior_store` (`crates/rustynetd/src/daemon.rs:3720`), constructed in the same initializer with the same path derivation (`crates/rustynetd/src/daemon.rs:4209`, `:4212`). **Reusing `PeerTraversalPrior` is explicitly wrong:** its fields are `last_success_class` (which class, never when), per-class Beta posteriors, `observed_nat` and `updated_at_unix` (`crates/rustynetd/src/peer_traversal_prior.rs:89`, `:91`, `:94`), and `updated_at_unix` is bumped unconditionally at the end of `update()` (`:137`), including on pure-failure races. **[V]** **[VC]** the cited mirror test asserts mode `0o600` (`crates/rustynetd/src/peer_traversal_prior.rs:429-432`) but does **not** assert that no temp file survives; do not claim it does.

**Fail-closed load.** `PeerPriorStore::load_or_empty` swallows every failure into an empty store (`crates/rustynetd/src/peer_traversal_prior.rs:169`, `:170`), with `try_load` returning `None` on missing file, short file, missing digest prefix, digest mismatch, bad JSON or version mismatch (`:181`, `:185`); the module header states the fail-open choice as intentional (`:11`, `:14`) and tests assert it (`:388`). The attestation loader must not copy that. Persist must also differ from `crates/rustynetd/src/daemon.rs:6757`, `:6758`, where a failed persist is logged and ignored under "Fail-open: the prior is an optimization cache."

**[VC] Two unresolved problems with fail-closed load.** (i) The proof as first written is not constructible: the store is loaded exactly once, in the constructor (single production site `crates/rustynetd/src/daemon.rs:4209`, inside `DaemonRuntime::new -> Result<Self, DaemonError>` at `:4110`), where the controller is `Init` and no peer is managed — so an erroring loader **aborts boot** rather than denying peers, and under item 9's per-peer gate a corrupt store denies nothing. No test hook forces controller state. Only a **store-level loader unit test** can fail when swapped to `unwrap_or_default()`. (ii) "must not be silently overwritten by the next persist" contradicts clear-then-persist: `persist()` rewrites the whole body, so the first revocation after a corrupt-file boot launders the tamper. **Nobody has resolved which wins. [U]**

**Genesis, orchestrator, and migration items.** See 3c — they are blocked on operator decisions, not on design.

### 3b. Blocked on an off-limits crate

**A3.2 — implement `handshake_endpoint` for `Phase10PeerRuntime`.** This is the correct fix and it is blocked. It requires editing `crates/rustynet-backend-wireguard`, which this work must not touch.

**Why nothing existing can answer the question. [V]** `current_peer_endpoint` returns the cached configured value (`crates/rustynet-backend-wireguard/src/linux_command.rs:494`); `peer_latest_handshake_unix` is keyed by node_id only; `PeerPathSample` (`crates/rustynet-backend-api/src/lib.rs:134`) carries loss/rtt/rttvar/latest_handshake and no endpoint.

**Full change set. [VC]** A new defaulted trait method in `crates/rustynet-backend-api/src/lib.rs` near `:213`; a dispatch arm in `impl TunnelBackend for DaemonBackend` (`crates/rustynetd/src/daemon.rs:3102`) for all six variants; the phase10 runtime method (`crates/rustynetd/src/phase10.rs:111`); and **real impls in all six `TunnelBackend` impls inside `rustynet-backend-wireguard`**, not the three the first extraction listed: `in_memory.rs:419`, `userspace_shared/mod.rs:425`, `userspace_shared_macos/mod.rs:510`, **plus `linux_command.rs:400`, `macos_command.rs:546`, `windows_command.rs:409`** — the three production command backends behind `DaemonBackend::Linux`/`::Macos`/`::Windows`. The tree has **14 `TunnelBackend` impls across 5 crates** (backend-api contract tests, -stub, -userspace, -wireguard, rustynetd), not "11 across 8". A defaulted method keeps them all compiling while silently returning `None`.

**Proof obligation, two tests. [V]** (1) A source-text dispatch pin modelled on `daemon_backend_impl_dispatches_initiate_peer_handshake_to_variants` (`crates/rustynetd/src/daemon.rs:19733`), asserting all six `DaemonBackend` variants dispatch. **[VC] That test alone is insufficient** — see §2; add a per-backend test that fails when a command backend keeps the default. (2) A phase10 test with a backend reporting a handshake at `E_actual` while the top-priority pair is `E_top`, asserting `report.selected_endpoint == E_actual`.

**Also gated on §0.** A negative answer to the empirical question removes the motivation for A3.2 entirely.

### 3c. Blocked on operator decisions — an implementing agent must NOT decide these

**D1 — migrate the existing fleet, or enforce for new nodes only?** Phase 1 recommended measuring first via `gossip_identity_mismatch` (`crates/rustynetd/src/daemon.rs:5698`, `:5699`, and the derived check at `:5712`). That recommendation predates the finding that genesis publishes a key with no private counterpart, which weakens "new nodes only": that policy still leaves every existing node's record unusable. Measure-first still holds for **sequencing**; it no longer implies migration is optional. The measurement surface is three-valued and reports `unknown` when either input is absent — and per D4 it measures **nothing** on macOS or Windows. **Gates the migration sequencing item. [V]**

**D2 — genesis mint ordering, and which non-Linux paths genesis a node.** On the lab path the ordering is already correct: `key init-gossip` runs before `membership init` inside one closure of `execute_ops_e2e_bootstrap_host` (`crates/rustynet-cli/src/ops_e2e.rs:206`, `:471`, `:574`), same process, same machine — so genesis could publish the real key with no reordering. On the product path `rustynet install` never runs genesis (`membership` appears zero times in `crates/rustynet-cli/src/install/live_linux.rs`; it terminates at `awaiting_enrollment_message`, see `:45`, `:49`, `:305`). But genesis **is** reachable from the shipped product binary via the ungated `ops init-membership` verb, so this is product work. The deliberate gating contrast that makes it a real finding: `E2eBootstrapMacos` and `E2eBootstrapWindows` are `#[cfg(feature = "vm-lab")]`-gated, while `InitMembership` (`crates/rustynet-cli/src/main.rs:1412`) sits between two ungated neighbours with no gate at parse, dispatch or help (`:20459`). Genuinely open: whether any non-Linux or anchor/founder install path genesises a node, and whether operators actually run `ops init-membership` in the field — its only in-repo callers are the vm-lab adapters and no runbook was found. **[V]/[U]**

**D3 — does `--force` on the gossip mint stay unconditional?** `key init-gossip` already refuses to overwrite an existing secret without `--force`, with a comment naming exactly this hazard (`crates/rustynetd/src/main.rs:553`, `:555`). Both mint callers pass `--force` unconditionally (`crates/rustynet-cli/src/install/live_linux.rs:180`, `crates/rustynet-cli/src/ops_e2e.rs:476`), so a re-run silently rotates the node's gossip identity while membership still publishes the old key. Post-alignment that becomes a self-inflicted `gossip_identity_mismatch=true` and a node dropped from the epidemic — loud rather than silent, but still an outage. Options: make the mint refuse to overwrite (drop `--force` from the callers), or require a membership rotation to accompany any re-mint. It is a decision because the first option changes installer behaviour. **Related structural defect, recorded and not fixed here:** `register_peer` is a plain additive insert and `unregister_peer` has one production caller (revoked ids only), so nothing prunes a peer that merely **changed** key; any rotation leaves the old key registered for the process lifetime on already-synced peers, which weakens `RotateNodeKey` as a response to key compromise. **[V]**

**D4 — what do macOS and Windows nodes publish? The hardest blocker.** Confirmed against code. **Windows cannot hold a gossip identity at all:** the daemon rejects any configured gossip secret under `#[cfg(not(unix))]` with "the gossip transport is unix-only" — `crates/rustynetd/src/daemon.rs:11539`, `:11544`. **macOS never mints one:** `init-gossip` appears zero times in `install/live_macos.rs` and `install/live_windows.rs`; the mint exists only at `crates/rustynet-cli/src/install/live_linux.rs:175` and `crates/rustynet-cli/src/ops_e2e.rs:471` (see also `crates/rustynet-cli/src/install/live_macos.rs:224`). **And nothing excludes them from the peer set:** `gossip_peer_registrations_from_membership` filters only on Active status, not-self by node_id, hex-decodability, not-self by gossip id, `VerifyingKey::from_bytes` success, and presence of an overlay address — `crates/rustynetd/src/gossip_runtime.rs:838`, `:846`, `:858`. There is no platform or capability term. So macOS and Windows membership entries **do** become candidate gossip peers on every Linux node, and whatever they publish is consumed as a verifying key by peers that can never receive a valid signature from them. "They are not gossip participants anyway" is not available as an answer. Options: (a) leave the field as-is per platform (defeats the contract); (b) publish a documented sentinel so `gossip_identity_mismatch` can distinguish "wrong key" from "no gossip on this platform"; (c) extend the mint to macOS, leaving only Windows special. **Do not invent a sentinel. Do not silently leave the adapters publishing WireGuard keys.** Consequence for proof: the gossip status tests are predominantly `#[cfg(unix)]`, so a test written to match its neighbours leaves the Windows path unproven, and `gossip_identity_mismatch` returns `unknown` on both platforms (`crates/rustynetd/src/daemon.rs:5700`). **[V]**

**D5 — should rotating the gossip trust anchor be owner-gated?** `requires_owner_signer` matches only `RotateApprover` and `SetQuorum` (`crates/rustynet-control/src/membership.rs:441`, `:444`), so `RotateNodeKey` needs quorum but not the owner. Once `node_pubkey_hex` **is** the gossip trust anchor, rotating it is arguably as sensitive as rotating an approver. If taken, the change is one `matches!` arm at `:444`, enforced at `crates/rustynet-control/src/membership.rs:1825` **[VC — not `:1824`, which is blank]**. Raising the bar has operational cost: every migration rotation would then need the owner signer, which interacts directly with migration sequencing. The signing path needs no new machinery — `verify_membership_signatures` (`crates/rustynet-control/src/membership.rs:1789`) already checks duplicate signer ids, quorum threshold, active-approver lookup, `verify_strict` per signature, and the owner requirement. **Do not add the arm on your own judgement. [V]**

### 3d. Items blocked by the above, described so they are not re-derived

**Genesis must stop publishing raw CSPRNG bytes.** `run_membership_init` allocates 32 raw CSPRNG bytes, hex-encodes them straight into `node_pubkey_hex`, and zeroizes them — `crates/rustynetd/src/main.rs:3993`, `:4119`, `:4129`. The bytes are never persisted and never sign anything. Contrast `approver_key_bytes`, which goes through `.verifying_key()` at `:4128` and whose private half is persisted at `:4132`. So the genesis record is not a mis-derived key; **it is a public key for which no private key exists anywhere, and no migration can recover it.** Genesis must publish the node's derived gossip verifying key instead, and must fail closed when no gossip secret is minted rather than inventing one. Three invocation sites must keep working: the ungated `rustynet ops init-membership`, the Windows PowerShell bootstrap (`scripts/bootstrap/windows/Install-RustyNetWindowsAnchorService.ps1:182`), and the lab e2e bootstrap (`crates/rustynet-cli/src/ops_e2e.rs:471`, `:577`). Also `crates/rustynetd/src/main.rs:4161`, `:4232`; CLI routes at `crates/rustynet-cli/src/main.rs:1412`, `:13906`, `:20459`. **Blocked on D2 and D4.** Proof, when unblocked: mint a gossip secret, run genesis, assert the snapshot's own-node `node_pubkey_hex` decodes to the derived verifying key; mutation is reverting to `encode_hex(&node_key_bytes)`. Separately assert genesis **fails** when no gossip secret is minted. **[V]**

**Bind `enrollment consume --pubkey` to the same value admit publishes.** There are two independent gossip peer-registration authorities and revocation reaches only one. `consume_and_register_peer` registers the enrollee under the key supplied on `enrollment consume --pubkey`, taken at face value (`crates/rustynetd/src/enrollment_consume.rs:30`, `:219`, `:220`; CLI at `crates/rustynet-cli/src/main.rs:6515`), while revocation is computed from membership's `node_pubkey_hex` (`crates/rustynetd/src/daemon.rs:5552`, `:5555`, `:8615`). Two separate operator invocations of two separate `--pubkey` flags with nothing binding them. Result: a peer registered via enrollment clears the unknown-source gate, its signature verifies under its own real key, the revoked-set check consults membership-derived ids, misses, and the bundle is **accepted** (`crates/rustynetd/src/peer_gossip.rs:603`, `:605`; `crates/rustynetd/src/gossip_runtime.rs:619`). Nothing prunes a peer merely absent from membership. Aligning both paths closes it; aligning only one re-opens it. The accept is time-bounded, not permanent — the epoch skew window ages it out after two further membership updates — a mitigation, not a fix, and timing-dependent. **[V]**

**[VC] Its proof cannot be discharged by extending `rustynetd gossip-revoked-readmit-audit`.** The first extraction called that "cheaper than a new harness". It is backwards. `run_case` takes two u8 seeds and a bool, builds two signing keys, calls `receiver.register_peer(...)` at `crates/rustynetd/src/gossip_revoked_readmit_audit.rs:109` and `set_revoked_peer_ids` directly at `:110`. There is no `MembershipState`, no `node_pubkey_hex`, and no `enrollment_consume` anywhere in the module. The §3.4 case is precisely a divergence between an enrollment-registered gossip id and membership's `node_pubkey_hex`, so it is inexpressible there without adding a membership fixture, `revoked_peer_ids_from_membership`, and ideally `consume_and_register_peer` — which needs an enrollment token, a ledger, a secret file and a push addr, i.e. **filesystem fixtures inside a shipped fail-loud production verb** (dispatched at `crates/rustynetd/src/main.rs:252`). Adding a third case also breaks the `total_cases` assertion near `:201` and contradicts the module's field docs. **A harness for this proof is unresolved. [U]** (Side note: the audit is immune to any point tripwire because no `node_pubkey_hex` exists in it, not because its keys are proper.)

**Split the one collected WireGuard key into two values across the orchestrator and lab paths.** This is not a value swap. The same collected map feeds two sinks: membership (`crates/rustynet-cli/src/vm_lab/orchestrator/stage/membership_init.rs:92`, `:118`) and the real WireGuard assignment bundle (`crates/rustynet-cli/src/vm_lab/orchestrator/stage/distribute_assignments.rs:70`). A second collected value — each guest's gossip verifying key, via the export verb over SSH — must be plumbed alongside, and **only the membership sink switched**. Affected, five flag spellings across two binaries and two scripting languages: `adapter/linux_membership.rs:86`, `adapter/macos_membership.rs:78`, `adapter/windows_membership.rs:308`, `vm_lab/mod.rs:13847` (macOS) and `:24609` (Windows), `ops_e2e.rs:4065` and the pass-through at `ops_e2e.rs:1953`, `scripts/e2e/live_linux_lab_orchestrator.sh:3584`, plus `scripts/vm_lab/netns_daemon_path.sh:218`, `:226`. **Blocked on D4** for the macOS and Windows adapters. **[V]**

**[VC] The context anchor was misattributed, and it hides real work.** `crates/rustynet-cli/src/vm_lab/orchestrator/context.rs:40` is a field of the **private serde struct** `PersistedOrchestrationContext`, the on-disk snapshot form. The live runtime field is `crates/rustynet-cli/src/vm_lab/orchestrator/context.rs:175` — a `HashMap`, not the `BTreeMap` the first extraction asserted. `collected_pubkeys` is **persisted and reloaded** through a digest-bound, schema-versioned envelope, so plumbing a second map also requires: a field on `PersistedOrchestrationContext` (`:40`), the save conversion (`:239`), the load conversion (`:320`), and a decision on the schema version (`:16`, currently 3) whose load gate at `:291` is **exact equality** — a bump makes every in-flight persisted lab context unloadable, while omitting the bump without `#[serde(default)]` breaks deserialization. An agent that adds the field to `:175` alone gets a context that **silently drops the gossip keys across any resume**, and the payload digest check at `:306` will not catch it because the new field is simply not in the payload.

**Proof obligation:** `build_membership_peers_threads_real_pubkeys_for_non_exit_peers` (`crates/rustynet-cli/src/vm_lab/orchestrator/stage/membership_init.rs:155`, fixture at `:171`) currently asserts the peer's `public_key_hex` equals the collected **WireGuard** key. Re-point it at the new gossip map; it must fail if the WireGuard map is used. Mutation: revert the membership sink to `ctx.collected_pubkeys`. End-to-end: on a live Linux lab run, `gossip_identity_mismatch` must read `false` on every Linux node's status surface (`crates/rustynetd/src/daemon.rs:5698`). **Land these with the product paths, not before** — otherwise the lab goes green while product stays broken.

**Migration sequencing — N separate `RotateNodeKey` updates advance the epoch by N.** No new operation is needed: `RotateNodeKey` exists and the value sits **inside** the signed canonical payload (`crates/rustynet-control/src/membership.rs:333`, parsed back at `:2070`), so it cannot be edited in place — it must go through a signed, approver-authorised update. The constraint is sequencing. The accept window is ±2 (`crates/rustynetd/src/peer_gossip.rs:147`, `:162`, and the window check at `:662` **[VC — not `:657`]**), with the local epoch taken from the verified snapshot at `crates/rustynetd/src/daemon.rs:5528`. Migrating N nodes as N separate updates advances the epoch by N, so for N > 2 with staggered distribution any node whose snapshot lags more than 2 epochs has its inbound bundles rejected **and** its own rejected by updated peers — gossip stops mesh-wide until snapshots land. Transient and symmetric, so an outage window rather than a brick. Batch rotations into few epoch bumps, or sequence distribution to keep skew inside 2. **Blocked on D1. And whether a real migration distributes per-rotation or once at the end is not derivable from code — no migration sequencing exists anywhere in the tree. The batching design must be chosen, not inferred. [U]**

---

## 4. What is landable right now, in order

Assuming a host that can run cargo (see §5), and treating the §0 conflict as resolved in favour of proceeding with labelling-only work:

1. Cold-start deadlock regression test (§1.1)
2. Attestation write-site constraint, as a mutation-only guard (§1.2)
3. Repair the 33-byte derivation pin (§1.3)
4. A3.3 part 1 — engine reason variant (§1.4)
5. Race-winner-in-probed-set validation (§1.5) — dead code until A3.2; say so
6. A3.3 part 2 — probe reason variant **plus `daemon.rs:7398`** (§1.6)
7. Prior store stops learning unattributed wins (§1.7) — separate commit
8. Clone-forward attribution fix (§1.8)
9. Per-peer deny predicate (§1.9)
10. Explicit-passphrase decrypt primitive (§1.11)
11. Export verb (§1.12)
12. `enrollment admit` derived key plus point validation (§1.13)
13. `RotateNodeKey` value validation (§1.14)
14. Fixture re-bytes (§1.15)
15. Lab anchor bin stops using random bytes (§1.16)

Everything else is in §3.

---

## 5. Operational rules

### Before committing

**Prove the checkout is not behind origin. [V]** `git fetch origin`, then require `git rev-list --count HEAD..origin/main` to be 0. A pre-commit hook enforces this and is active on the origin clone (`git config core.hooksPath` returns `scripts/git-hooks`). `RUSTYNET_ALLOW_STALE_COMMIT=1 git commit` is the documented deliberate override; the hook's own text says to say why in the message (`AGENTS.md:94`, `:102`, `scripts/git-hooks/pre-commit:28`, `:38`). Measure your own edits with `git diff` against HEAD, never against `origin/main`.

**[VC] The hook is weaker than "enforces exactly this".** It compares `HEAD..@{upstream}` (`scripts/git-hooks/pre-commit:35`), not literally `origin/main`. On a detached HEAD or a branch with no upstream it exits 0 **silently** at `:36`. `git commit --no-verify` also bypasses it. Do not rely on the hook as your only check.

### Gates

**`AGENTS.md` §7 is authoritative** (`AGENTS.md:140`, `:143`, `:145`, and the statement that §7 is authoritative at `AGENTS.md:515`). Six commands: `cargo fmt --all -- --check`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`; `cargo check --workspace --all-targets --all-features`; `cargo test --workspace --all-targets --all-features`; `cargo audit --deny warnings`; `cargo deny check bans licenses sources advisories`.

Add `--locked` locally: every CI validation leg runs with it (`AGENTS.md:165`, `.github/workflows/cross-platform-ci.yml:34`), so a local run that refreshes `Cargo.lock` can pass on a commit CI then fails. cargo-nextest is what CI and xtask actually run. **A nextest failure is a real failure — never re-run it under `cargo test` to turn it green** (`AGENTS.md:205`). Stop the UTM VMs first (`utmctl stop`): measured 128 s versus 668 s for the test stage.

**[VC] Proof of a run is runner-conditional.** nextest prints `Summary` with a pass count; `cargo test` prints `test result: ok. N passed` and never prints `Summary`. Accept either, matched to the runner you used. Absence of the runner's own summary line means the gate did not run — a killed run leaves a log with no summary and zero FAIL lines and reads exactly like a clean run. (xtask always produces `Summary`; it exits 2 rather than falling back.)

**`--workspace` is not the whole repo. [V]** Root `Cargo.toml` excludes `gui/` and `crates/rustynet-lab-monitor/`; `fuzz/` declares its own `[workspace]` and nothing in `.github/workflows/` gates it (`AGENTS.md:149`, `:160`, `.github/workflows/cross-platform-ci.yml:80`). If the change touches the lab monitor, additionally run `./scripts/ci/lab_monitor_gates.sh`, which must print `rustynet-lab-monitor standalone gates: PASS` (`scripts/ci/lab_monitor_gates.sh:35`) — a workspace-only run cannot produce that line. If you touch `fuzz/` or `gui/`, gate by hand and say so.

**Secrets hygiene runs cargo internally — 16 tests, 33 cargo invocations, and it cannot be narrowed. [V]** The wrapper is `exec cargo run ... --bin secrets_hygiene_gates` (`scripts/ci/secrets_hygiene_gates.sh:2`). The binary iterates 16 `REQUIRED_TESTS` and spawns `cargo test` per test plus a verify-output run per test plus one scan (`crates/rustynet-cli/src/bin/secrets_hygiene_gates.rs:323`, `:369`). `run()` collects argv into `let _args` and never reads it (`:107`), so there is no `--scan-only` flag. A genuine run prints `Secrets hygiene gate: PASS (18 checks)`. Any smaller count is a claim about a gate that did not fully run.

**The scan half is partly separable. [V]** The filesystem/tracked-artifact scan is a first-class subcommand, `ops check-secrets-hygiene [--root <path>]` (`crates/rustynet-cli/src/main.rs:2685`, `:20426`, implemented at `crates/rustynet-cli/src/ops_phase1.rs:2017`), not feature-gated. The second scan — no inline `ssh_password` in tracked inventories — exists **only** inside the gate binary (`crates/rustynet-cli/src/bin/secrets_hygiene_gates.rs:183`, `:187`, `:230`) with no ops subcommand. Reproducing its logic read-only (`git ls-files -z -- '*vm_lab_inventory*.json'`, fail on any non-empty `entries[].ssh_password`) is evidence about repo state, not a gate run. Neither substitutes for the 18-check PASS line.

**Backend boundary gate. [V]** For any change touching backend types, run `./scripts/ci/check_backend_boundary_leakage.sh`. Its binary spawns no cargo internally: it needs `rg` and runs one case-insensitive scan for `(wireguard|wg[-_]|wgctrl)` over five crate `src` trees. Exit semantics are inverted — rg matches means reject; rg exit 1 means `Backend boundary leakage checks: PASS` (`crates/rustynet-cli/src/bin/check_backend_boundary_leakage.rs:57`, `:79`, and `AGENTS.md:531`). Output must be the literal PASS line; an `rg` that fails to run yields exit 2 and silence is not a pass. **[VC]** the wrapper script itself is `exec cargo run --quiet ...` (`scripts/ci/check_backend_boundary_leakage.sh:2`), so only invoking `target/debug/check_backend_boundary_leakage` directly avoids cargo (`repo_root()` is baked from `CARGO_MANIFEST_DIR`, so it scans the real repo from any cwd).

**Two gate lists exist and they differ. [V]** `HANDOVER_2026-08-05.md:180`–`:184` lists five commands and omits `cargo audit` and `cargo deny`, which §7 requires. Conversely §7 does not list the two security scripts. The handover's own §13.1 warns its excerpt is not a competing list (`AGENTS.md:1164`). **Run the union, and name in the ledger exactly which commands ran.** **[VC]** audit and deny run on **three** CI legs (macOS, Debian, Windows), not two. There are four CI jobs: macOS, Debian 13, `linux_e2e` (real WireGuard), and Windows — **Windows covers a package subset only**, because `rustynet-cli` cannot build there, so a Windows regression outside that subset is not caught by CI at all (`.github/workflows/cross-platform-ci.yml:5`, `:202`).

**The xtask runner dirties the tree. [V]** `cargo run -p rustynet-xtask -- gates` appends a row per stage to the **tracked** `documents/operations/gate_timings.csv`, written by `TimingRunMeta::record` — `crates/rustynet-xtask/src/main.rs:641` (**[VC]** there is no `TimingRecorder`; that symbol does not exist). Commit or `git restore` that file before taking any dirty-state reading used as live-lab evidence, and never let it ride along in an unrelated commit.

### Docs-only changes

**No test parses tracked documentation. [V]** Verified four ways: no `include_str!` of a `.md` (54 sites, all `.rs`/`.sql`/JSON/plists/units/scripts — **[VC]** 54, not 40); the 65 literal `documents/…` and `"*.md"` strings inside `#[cfg(test)]` are all CSV/JSONL ledgers, inventory paths, or temp artifacts; `AGENTS.md`/`CLAUDE.md`/`README.md` are read only by non-test runtime code in `crates/rustynet-mcp/src/bin/repo_context.rs:1125`; the nearest-looking anti-drift test parses an in-source table (`crates/rustynet-mcp/src/bin/repo_context.rs:2267`), not a file; and `ops check-secrets-hygiene` never reads `.md` content (`crates/rustynet-cli/src/ops_phase1.rs:2079`, `:2154`).

**[VC] But a docs-only change is NOT gate-neutral, and the rename-fragile set is larger than four files.** Three additional consumers, none in `scripts/ci/`, none reachable by a script-level grep:
- The Phase-1 CI gate verb runs `rg '\[\[UNRESOLVED\]\]|\{\{UNRESOLVED\}\}'` over `["crates","documents"]` and fails with "Documentation hygiene gate failed" — `crates/rustynet-cli/src/ops_ci_release_perf.rs:143`. **A prose edit that introduces a placeholder token breaks a gate.** None exist today.
- The Phase-9 CI gate `require_file`s **eight** named documents under `documents/operations/` — `crates/rustynet-cli/src/ops_ci_release_perf.rs:265`. All eight are present today. Renaming or archiving any breaks it. Phase-9 also invokes Phase-1, inheriting the UNRESOLVED scan.
- A `ComparativeCommandSpec` in the security-audit catalog greps `documents/operations/SecurityHardeningBacklog_2026-03-09.md` — `crates/rustynet-cli/src/security_audit_catalog.rs:693`. **That path does not exist at HEAD**; only `done/` and `active/…_2026-06-01.md` are tracked. A doc archival has already rotted this consumer. Treat it as a live counterexample to any "confined to N files" claim.

**Three scope gate scripts also read tracked docs. [V]** `scripts/ci/role_taxonomy_gates.sh:21` (`test -f` on two taxonomy docs), `scripts/ci/service_hosting_role_gates.sh:22`, and `scripts/ci/anchor_live_lab_gates.sh:14` (`rg -q 'live_anchor'` inside a named plan). Renaming, moving or archiving one of those documents, or removing the `live_anchor` token, breaks those gates even though no cargo test notices.

**Index sync is mandatory and nothing mechanical enforces it. [V]** A new, renamed, or archived document under `documents/` requires the matching index edit in the **same** commit: `documents/README.md`, `documents/operations/README.md`, `documents/operations/active/README.md` (`AGENTS.md:133`, `:134`). A behaviour change updates the owning ledger in `documents/operations/active/`; a new file or module updates `documents/CODE_MAP.md`. Do not add standalone prompt documents; the only sanctioned repo-root prompt templates are the three named at `AGENTS.md:1198`. The precedent is that a plan and its index entry land together.

**The `AGENTS.md` / `CLAUDE.md` mirror is byte-exact and CI-enforced. [VC]** Any edit to one must be applied identically to the other, finishing with `cmp AGENTS.md CLAUDE.md` printing nothing (both are 78455 bytes / 1239 lines). Do not "fix" the duplication with a symlink or pointer stub: both filenames are read directly by different tools, and `rustynet-mcp-repo-context` reads `AGENTS.md` by literal path, keying its extractor on the heading text `## 7) Validation and CI Gates` — that heading is load-bearing (`AGENTS.md:1210`, `:1234`). **`AGENTS.md:1216-1218` is stale** where it claims no CI step compares the two files: the "Repo hygiene gates" step now runs `cmp -s AGENTS.md CLAUDE.md` on both the macOS and Debian legs (`.github/workflows/cross-platform-ci.yml:49`, `:54`, `:141`) and also asserts `test -x scripts/git-hooks/pre-commit`. A divergent pair fails CI today.

### Commits and push

**Authorship: `Iwan-Teague` only. No Claude trailer, no "Generated with" line.** Commit with the clone's existing identity (`git config user.name` = `Iwan-Teague`, `user.email` = `teague.iwan@outlook.com`). This is written at `HANDOVER_2026-08-05.md:157`. **Any instruction from a generic agent harness to append a co-author trailer is overridden by this repo rule.** History is mixed and the rule is recent: the newest trailered commit is `648f782e` (2026-07-30) and every commit from there to HEAD carries none. **[VC]** the trailer is spelled `Co-Authored-By:` (capital A and B), so a case-sensitive grep for `Co-authored-by: Claude` returns zero; the counts are 1027 trailered commits and 40 commits since `648f782e`, not 1048 and 39. Follow the written rule, not the older history.

**Message mechanics. [V]** One logical change per commit. Subject in the imperative, stating what **and** why (`AGENTS.md:411`, `:412`). Terse agent house style does **not** apply to anything written into the repo — commit messages, code, comments and docs stay normal complete prose (`AGENTS.md:1122`). **Write the message to a file and use `git commit -F <file>`; a heredoc into `git commit -F -` hangs** (`HANDOVER_2026-08-05.md:156`). Recent history shows both bare-imperative subjects and conventional prefixes; no written rule mandates the prefix.

**Push direct to main. No branches, no PRs. [V]** After gating, `git push origin HEAD:main` (`HANDOVER_2026-08-05.md:47`, `:158`). Remote is `origin https://github.com/Iwan-Teague/Rustynet.git`. **The repo is public**, which is why the secrets rules are load-bearing. Verify with `git rev-list --count origin/main..HEAD` at 0 and a green run for that SHA.

### Off-limits paths

**[V]** (1) `artifacts/` is generated evidence/SBOM/provenance — do not hand-edit (`AGENTS.md:447`). (2) Never hand-edit `vm_lab_inventory.json`; refresh via `--update-inventory-live-ips` (`AGENTS.md:406`). (3) Never commit generated files, build artifacts, or secrets (`AGENTS.md:413`). (4) Lab SSH passwords must never appear inline in a tracked inventory; they live in the untracked sidecar `documents/operations/active/vm_lab_inventory.secrets.json`, mode 600, and the secrets gate rejects any inline `ssh_password` that drifts back (`AGENTS.md:556`). (5) Never edit the tree while a gate runs. (6) `documents/operations/live_lab_run_matrix.csv` is a frozen bash-orchestrator archive; current work appends only to `live_lab_node_run_matrix.csv` — never read a stage result from one ledger as evidence for the other engine (`HANDOVER_2026-08-05.md:53`). (7) `third_party/` types must not leak past the backend boundary.

**`crates/rustynet-backend-wireguard/` — confirm before working in it. [U]** The handover reserves it for a second agent (`HANDOVER_2026-08-05.md:153`), but commits touching that crate have since landed and HEAD equalled origin/main at handoff. **Ask the operator rather than assuming either way.** A3.2 (§3b) needs this crate; that is the main reason it matters.

### The standing rule that overrides scope

**A behaviour change that cannot be mutation-proven does not ship. [V]** The mutation step is: break the production rule, confirm the **specific named test** fails, restore. On the origin host cargo wedges for hours under macOS Gatekeeper saturation. The current top-of-main commits invoke this rule explicitly to ship design and docs only — `e82e2190`'s body records that nothing was compiled or tested because cargo is unusable there, so by the standing rule no behaviour change shipped from that pass (`documents/operations/active/I4TraversalAttestationPlan_2026-08-05.md:544` **[VC — locate by the string `cargo wedges`; the first extraction quoted text that appears nowhere in the file]**, and `AGENTS.md:112`, `HANDOVER_2026-08-05.md:31`).

So: **every behaviour change in §1 must be mutation-verified on a host that can execute the test suite before it ships.** If the suite cannot run, restrict the pass to documentation and design, and say so in the commit body. Do not land unverified behaviour.

**Corollary: commit before you mutate.** `git checkout -- <file>` restores to the last commit and takes uncommitted work with it.

---

## 6. Unresolved, listed so nobody smooths over them

1. Whether a per-public-key handshake counter can advance from an endpoint other than the one just probed. **Gates the whole §3 line, or does not — see the reviewer conflict in §0.**
2. Whether the §3.4 contingency retraction (`documents/operations/active/I4TraversalAttestationPlan_2026-08-05.md:66-72`) makes item 1 above non-load-bearing. Two reviewers disagree on real evidence.
3. How to represent a persisted endpoint given `SocketEndpoint` has no serde and `rustynet-backend-api` has no dependencies (§3a).
4. Whether a corrupt attestation file must survive un-overwritten, versus clear-then-persist rewriting the whole body. The two requirements contradict and no item resolves it (§3a).
5. What harness can prove the enrollment/membership registration divergence, given the named audit verb cannot express it (§3d).
6. Whether a real key migration distributes per rotation or once at the end. No migration sequencing exists in the tree to read (§3d).
7. D1 through D5 (§3c) — five operator decisions. Do not decide any of them silently.
8. Whether `crates/rustynet-backend-wireguard/` is still reserved for another agent (§5).