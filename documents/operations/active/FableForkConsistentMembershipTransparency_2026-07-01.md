# Fable 5 Deep-Dive: Fork-Consistent Membership via a Witnessed Merkle Transparency Log — 2026-07-01

> **STATUS: SPECULATIVE R&D — UNSCHEDULED, SELF-AUTHORED EXPLORATION.** This is a
> single-topic, expert-depth design study authored directly by the Fable 5 main
> agent (not a multi-agent fan-out; grounding was read first-hand against the
> code on 2026-07-01). It is **not** committed work, **not** in-flight, and
> **not** part of the live-lab acceptance matrix (`CrossPlatformRoleParityPlan_2026-06-21.md`
> §3 is unaffected). It proposes closing one specific, currently-unaddressed
> class of attack against the trust-state pipeline. Every current-behavior claim
> cites the code; line numbers drift, re-verify before building. Effort sizes use
> the `SecurityRemediationPlan_2026-06-19.md` key (S ≤ ½ day, M ~1–2 days,
> L ≥ 3 days or needs a design decision).

---

## 0. One-paragraph thesis

Rustynet's membership pipeline is a **signed, hash-chained, per-node linear
log**. Every local check it performs — `prev_state_root` linkage, `epoch_prev`/
`epoch_new` chaining, the `MembershipReplayCache` monotonic-epoch guard — answers
exactly one question: *"is the update I am being handed a valid linear successor
of the state I currently hold?"* None of them answers the question that a
compromised admin key, a coerced operator, a malicious anchor, or even a benign
concurrent-signing race can violate: *"is the history I am being shown the **same
history** every other honest node is being shown?"* A signer who produces **two
distinct-but-each-internally-valid** epoch N→N+1 updates and routes them to
different nodes **forks the mesh silently**: each node's local chain is pristine,
each replay cache is happy, and the two halves diverge with no cryptographic
alarm anywhere. This document proposes importing the mechanism the key-transparency
field built for precisely this threat — an **append-only Merkle history tree
(RFC 6962 / Crosby–Wallach) that yields O(log n) consistency and inclusion
proofs**, **gossip-based fork detection** (SUNDR fork-consistency, CONIKS/CT
gossip) that makes any equivocation self-evident the moment two honest nodes
compare notes, and **decentralized witness cosigning** (CoSi / Sigsum / Parakeet)
that escalates detection into *prevention* — adapted correctly to a 2–50-node,
Pi-class, no-external-CA home mesh, sitting entirely on top of the Ed25519 and
SHA-256 primitives already in the tree, granting no capability and failing closed.

---

## 1. Grounded problem statement (what the code does today)

The membership state machine lives in `crates/rustynet-control/src/membership.rs`.
Read first-hand, the relevant surface is:

- **State fingerprint is a flat hash.** `MembershipState::state_root_hex`
  (membership.rs:307) is `sha256_hex(canonical_payload)` — a single SHA-256 over
  the *entire* canonical serialization of the current roster
  (`canonical_payload`, membership.rs:246). It is a whole-state fingerprint, not a
  structure that supports partial proofs.
- **Updates form a per-node linear hash chain.** `MembershipUpdateRecord`
  (membership.rs:389) carries `prev_state_root`, `new_state_root`, `epoch_prev`,
  `epoch_new`. `apply_signed_update` (membership.rs:693) enforces, in order:
  network-id match, expiry/future-dating, `record.prev_state_root ==
  state.state_root_hex()` (membership.rs:713), `epoch_prev == state.epoch &&
  epoch_new == epoch+1` (membership.rs:716), quorum signature verification
  (`verify_membership_signatures`), deterministic re-derivation of
  `new_state_root` (membership.rs:730), and finally `replay_cache.observe`.
- **Anti-replay/rollback is local and monotonic.** `MembershipReplayCache`
  (membership.rs:546) holds `seen_update_ids: HashSet<String>` and `max_epoch:
  u64`; `observe` (membership.rs:552) rejects a re-used `update_id` or any
  `epoch_new <= max_epoch`. This prevents a node from being walked *backwards* — it
  does nothing about being walked *sideways*.
- **The local audit log is already a hash chain.** `append_membership_log_entry`
  (membership.rs:808) builds `entry_hash = sha256(index | previous_hash |
  encoded_update_hex)`; `load_membership_log` (membership.rs:837) re-verifies the
  chain (`verify_membership_log_chain`). This is a tamper-evident *local* log —
  the seed of a transparency log, but it is never compared across nodes.
- **Distribution is single-source pull.** Nodes acquire membership state by
  pulling a signed bundle from an anchor: `StateFetcher` (`crates/rustynetd/src/
  fetcher.rs`, "pull-based signed bundle retrieval") over the anchor bundle-pull
  listener (`load_anchor_bundle_pull_bundle` / `handle_anchor_bundle_pull_stream`,
  daemon.rs:984/1085). A node trusts whatever single bundle its configured anchor
  hands it; there is no cross-anchor or cross-peer agreement step.
- **The word "fork" already appears — as a *local* check only.** The test at
  membership.rs:2560 (`apply_signed_update_rejects_prev_state_root_mismatch`)
  comments that a prev-root mismatch "is a rollback/fork attempt." True, but it
  only catches an update that fails to chain onto *this node's* current state. An
  equivocation in which each fork is internally well-chained sails straight
  through.

**Confirmed absent (grep, 2026-07-01):** no Merkle tree, no consistency proof, no
inclusion proof, no signed-tree-head, no cross-node log-head gossip, and no
witness or cosigning protocol anywhere in the workspace (`fn witness` / `struct
Witness` / `Cosign` return nothing; the incidental "witness" string hits are
unrelated).

### 1.1 The attack, concretely

Let the current committed state be epoch `N` with root `R_N`. A signer able to
produce quorum signatures (a stolen admin key, a legally/physically coerced
operator, a compromised anchor that also holds a signing key, or two admins
concurrently signing without coordination) constructs **two** valid signed
updates:

```
U_A : epoch_prev=N, prev_state_root=R_N, new_state_root=R_{N+1}^A   (adds node X)
U_B : epoch_prev=N, prev_state_root=R_N, new_state_root=R_{N+1}^B   (does NOT add X;
                                                                     revokes Y instead)
```

Both satisfy every check in `apply_signed_update`. `U_A` is delivered (via the
anchor bundle-pull that node's fetcher hits) to nodes {P1, P2}; `U_B` to {P3, P4}.
Now:

- P1/P2 believe X is a member (and route/trust it); P3/P4 believe Y is revoked and
  X was never admitted.
- Each node's `MembershipReplayCache` is satisfied — `max_epoch` advanced N→N+1
  exactly once on each side.
- Each node's local hash-chained log is internally valid.
- **Nothing in the system will ever flag this.** The mesh is partitioned into two
  trust realms that disagree about who is a member and what capabilities exist,
  and the split is *cryptographically invisible* to every participant.

This is the textbook **equivocation / fork attack**, and it is the raison d'être
of the entire key-transparency literature (SUNDR, CT, CONIKS, Parakeet). It is
strictly outside what local rollback protection can catch, because forking never
requires rolling any single victim backwards.

### 1.2 Why this matters at *home-mesh* scale (honest threat framing)

A fair objection: "if the admin key is stolen, the attacker can do anything —
why single out forking?" Three answers make this a real, distinct gap rather than
a subset of key-compromise:

1. **Coercion / split-view compulsion.** The canonical CONIKS threat: an operator
   is compelled (legal order, coercion) to admit a surveillance node *for one
   target only* while showing everyone else an unchanged roster. A witnessed
   transparency log makes that split **undeniable** — the coerced signer cannot
   produce a consistent, witnessed history that hides it. This is a property no
   amount of "protect the key" achieves, because the key holder is the adversary.
2. **Malicious/buggy anchor as distribution MITM.** Even with an *uncompromised*
   admin key, the anchor is the single distribution point (`fetcher.rs`); a
   malicious or buggy anchor can serve stale bundle B to P3/P4 while P1/P2 get the
   fresh bundle A. Gossip-based STH comparison catches this with no admin-key
   compromise at all.
3. **Accidental forks from concurrency.** Two admins (the design supports a
   multi-approver `quorum_threshold`, membership.rs:160) signing epoch N→N+1
   concurrently on different machines produce an *accidental* fork. Today it splits
   the mesh silently; with consistency checking it fails **closed** and surfaces
   the race instead of corrupting trust state. This benefit accrues even with zero
   adversary.

Detection (Layers 1–2 below) is cheap and valuable at any size ≥2. Prevention
(Layer 3, witness cosigning) needs ≥~5 nodes to have ≥2 *independent* witnesses
and is proposed as an opt-in that degrades gracefully to detection-only on smaller
meshes — stated honestly, not hidden.

---

## 2. The mechanism (named prior art + the Rustynet adaptation)

Three composable layers, each a recognized construction, each mapped onto
structures that already exist in `membership.rs`.

### 2.1 Layer 1 — Append-only Merkle history tree (RFC 6962 / Crosby–Wallach 2009)

**Prior art.** RFC 6962 (Certificate Transparency; Laurie, Langley, Kasper 2013)
and Crosby & Wallach, *"Efficient Data Structures for Tamper-Evident Logging"*
(USENIX Security 2009), define an append-only Merkle tree over an ordered list of
leaves that supports two logarithmic-size proofs:

- **Inclusion proof** `PATH(i, D_n)`: proves leaf *i* is committed by the tree
  head of size *n* — O(log n) hashes.
- **Consistency proof** `PROOF(m, D_n)`: proves the tree of size *m* (root `R_m`)
  is an exact **prefix** of the tree of size *n* (root `R_n`) — i.e. the log was
  only *appended to*, never rewritten, reordered, or truncated — O(log n) hashes.

The Merkle Tree Hash uses domain-separated hashing to prevent leaf/interior
second-preimage collisions:

```
MTH(∅)      = SHA256("")                                  // empty
MTH({d0})   = SHA256(0x00 ‖ d0)                            // leaf
MTH(D[0:n]) = SHA256(0x01 ‖ MTH(D[0:k]) ‖ MTH(D[k:n]))    // k = largest power of 2 < n
```

**Rustynet adaptation.** The membership *log of updates* is exactly an ordered
append-only list — it is already hash-chained in `append_membership_log_entry`.
Promote it to a Merkle history tree:

- **Leaf `i`** = `SHA256(0x00 ‖ canonical_leaf_i)` where `canonical_leaf_i` binds
  the committed transition at epoch `i`: `network_id ‖ epoch_i ‖ new_state_root_i ‖
  update_id_i`. Using `new_state_root_i` (already computed and checked at
  membership.rs:730) as the leaf's payload means the history tree commits to the
  full sequence of *state fingerprints* — the STH at size *n* is a single hash
  binding the entire membership history through epoch *n*.
- The existing flat `state_root_hex` is **unchanged and retained** — it remains
  the per-snapshot fingerprint and the `prev_state_root`/`new_state_root` chain
  link. The Merkle root is a *new, orthogonal* commitment to the *sequence*, not a
  replacement for the per-state hash.
- New pure module `crates/rustynet-control/src/merkle_log.rs` (domain crate,
  transport-agnostic — it is only data + SHA-256):
  ```rust
  pub struct MerkleHistory { /* incremental node cache: Vec<[u8;32]> per level */ }
  impl MerkleHistory {
      pub fn append_leaf(&mut self, leaf_payload: &[u8]) -> u64;      // returns new tree_size
      pub fn root(&self) -> [u8;32];                                  // MTH of current size
      pub fn inclusion_proof(&self, i: u64) -> InclusionProof;        // PATH(i, D_n)
      pub fn consistency_proof(&self, m: u64) -> ConsistencyProof;    // PROOF(m, D_n)
  }
  pub fn verify_inclusion(root:&[u8;32], size:u64, i:u64, leaf:&[u8;32], p:&InclusionProof)->bool;
  pub fn verify_consistency(old:&[u8;32], old_size:u64,
                            new:&[u8;32], new_size:u64, p:&ConsistencyProof)->bool;
  ```
  Storage is O(n) leaf hashes plus the standard O(log n) "right-edge" node cache
  for incremental appends (the Crosby–Wallach tree-hash-cache trick), so an append
  is O(log n) and never re-hashes the whole log — critical for a Pi-class anchor
  that appends on every membership change.

### 2.2 Layer 2 — Signed Tree Head + gossip-based fork detection (SUNDR, CT gossip)

**Prior art.** SUNDR (Mazières & Shasha, *"Building Secure File Systems out of
Byzantine Storage"*, PODC 2002; Li et al. OSDI 2004) formalized **fork
consistency**: an equivocating server can partition honest clients into disjoint
fork sets, but (a) can never *reunite* a forked client with the main history
without detection, and (b) any two clients in different fork sets detect the fork
the instant they compare state — **without trusting each other or any third
party**. CT-gossip (Nordberg et al., IETF draft; Chuat et al., *"Efficient Gossip
Protocols for Verifying the Consistency of CT Logs"*, IEEE CNS 2015) is the
concrete realization: participants exchange Signed Tree Heads and demand
consistency proofs between them.

**Rustynet adaptation.**

- **Signed Tree Head (STH)** — new signed artifact:
  ```rust
  pub struct SignedTreeHead {
      pub network_id: String,
      pub tree_size: u64,          // == committed epoch count
      pub root_hash_hex: String,   // MTH over the history tree at tree_size
      pub timestamp_unix: u64,
      pub approver_signatures: Vec<MembershipSignature>,  // SAME quorum + keys as updates
  }
  ```
  The STH is signed by the **existing** approver quorum using the **existing**
  Ed25519 path (`sign_update_record` / `verify_membership_signatures`) over a
  canonical STH encoding. **No new key material, no new signature scheme.** An STH
  is minted whenever the log advances (once per committed epoch) and cached
  alongside the snapshot.
- **Gossip carriage.** STHs piggyback on the **existing** peer-gossip channel.
  The last grounding pass established that gossip today carries only endpoint
  candidates (`GossipBundle`, peer_gossip.rs) — this adds a second, small,
  independent gossip message `GossipSthAdvert { network_id, tree_size,
  root_hash_hex }` (≈ 44 bytes + framing). It is **unsigned in transit** because
  it is only a *hint*: acting on it always requires pulling and verifying the
  actual signed STH + a consistency proof (mirrors the fail-closed digest design
  in the FIS-0003 gossip anti-entropy proposal — a hint can only trigger a
  verified pull, never a state change).
- **The detection rule (the whole point).** When node P (local STH size `m`, root
  `R_m`) learns of a peer's STH advert (size `n`, root `R_n`):
  - If `m == n` and `R_m != R_n` → **immediate, unforgeable fork evidence.** Two
    validly-signed tree heads of the *same size* with *different roots* can only
    exist if the signer equivocated. P persists both signed STHs as a
    **fork-evidence bundle** and enters **fork-halt** (see §2.4).
  - If `m != n` (say `m < n`) → P requests a **consistency proof** `PROOF(m, n)`
    from the peer/anchor and runs `verify_consistency`. Success ⇒ the two views
    are on one history (P is simply behind); P may fast-forward by pulling the
    intervening signed updates and re-verifying each with the *unchanged*
    `apply_signed_update`. **Failure ⇒ fork evidence** (the histories are not
    prefix-compatible) ⇒ fork-halt.
- **Interaction with the existing replay watermark.** Orthogonal and
  complementary: `MembershipReplayCache.max_epoch` continues to forbid *backward*
  motion locally; the consistency proof forbids *sideways* motion globally. An
  update must now pass **both** — local monotonicity **and** proof that the new STH
  is a consistent extension of the last STH this node acted on. Neither subsumes
  the other.

Layer 2 alone delivers **fork consistency**: it cannot stop a determined signer
from momentarily forking two node sets, but it guarantees the fork is detected as
soon as any two honest nodes across the divide exchange gossip (seconds, on the
existing gossip cadence), and it fails closed on detection. At home-mesh sizes
where "any two honest nodes gossip regularly" is essentially always true, this
turns a silent permanent split into a loud, evidence-backed halt.

### 2.3 Layer 3 — Decentralized witness cosigning (CoSi / Sigsum / Parakeet)

**Prior art.** Syta et al., *"Keeping Authorities 'Honest or Bust' with
Decentralized Witness Cosigning"* (IEEE S&P 2016 — CoSi); its production
descendants: the Sigsum log's independent-witness API, Google Trillian witnesses,
and the auditor/witness model in Meta's and Apple's key-transparency deployments
(Parakeet, Tomescu et al.). The shared idea: a statement (here, an STH) is only
**promotable** once a threshold *w* of independent **witnesses** have each
cosigned it, and a witness cosigns an STH **only after verifying a consistency
proof from the last STH it cosigned**. Because an honest witness will never
cosign two size-equal divergent heads, an equivocator cannot assemble a
*witnessed* head for both forks without also compromising *w* witnesses.

**Rustynet adaptation — turning detection into prevention.**

- **Witnesses are existing mesh nodes, holding no capability.** A witness is any
  configured stable node (naturally: anchors and long-lived clients). A witness
  key is an Ed25519 key **distinct from the admin approver keys** (independence is
  the whole value). Crucially — and this is why it fits Rustynet's hard
  constraints perfectly — **a witness can only ever *refuse* to cosign; it can
  never *authorize* anything.** Making a node a witness grants it zero capability;
  its signature is a consistency attestation, not a trust grant. This is the exact
  shape the project's "advisory subsystem may recommend/block, never grant" rule
  wants.
- **Witness cosign protocol** (per new/candidate STH, over existing transport):
  1. Proposer (admin/anchor) sends the candidate `SignedTreeHead` (size `n`) +
     `ConsistencyProof(w_last → n)` to each witness, where `w_last` is the size
     that witness last cosigned.
  2. Witness verifies: quorum signature on the STH (existing path), `n >=
     w_last`, and `verify_consistency`. If all pass, it appends a `MembershipSignature`
     (its witness key) and updates its stored `w_last := n`. Otherwise it refuses
     and (on a consistency failure) emits fork evidence.
  3. A **WitnessedTreeHead** = STH + ≥ `witness_threshold` witness cosignatures.
- **Promotion rule (fail-closed).** A node treats a new membership epoch as
  *promotable / actionable* only when it holds a `WitnessedTreeHead` covering that
  epoch. An update that is admin-quorum-valid but **not yet witnessed** is held in
  a pending buffer, not applied to live trust state. This raises the equivocation
  bar from "one admin quorum" to "admin quorum **and** `witness_threshold`
  independent witness keys."
- **Graceful degradation (honest about small meshes).** With `witness_threshold =
  0` (default on ≤3-node meshes where independence is impossible) Layer 3 is off
  and the system runs Layer 1+2 = fork **detection** only. The operator opts into
  prevention by configuring witnesses once the mesh is large enough (≥5 nodes for a
  2-of-3 witness set with real independence). The doc must ship with this default
  and say plainly that prevention is a large-mesh feature.

### 2.4 Fork-halt semantics (fail-closed, never fail-open)

On fork evidence (Layer 2 or a Layer-3 witness refusal), the node:

1. **Freezes membership at the last consistent epoch.** It keeps operating on the
   last-known-good state (existing trust decisions stand — default-deny is
   preserved) but **refuses to apply any further membership update** until an
   operator intervenes. It does **not** pick a side, does **not** roll back, does
   **not** guess. Freezing forward on the last consistent state is the fail-closed
   choice: no new capability is granted while trust state is in dispute.
2. **Persists the fork-evidence bundle** (both signed STHs, or the STH + failing
   consistency proof) — a compact, self-verifying, non-repudiable artifact proving
   the signer equivocated. This is durable evidence an operator (or an external
   auditor) can verify offline.
3. **Raises a loud, distinct alarm** to the operator surface (tracing error +
   status-line flag + operator-menu red state), reusing existing status plumbing.

This is deliberately the CT/CONIKS response: the log *cannot un-equivocate*, and
the moment it tries, honest nodes stop and shout with proof, rather than silently
converging on an attacker-chosen branch.

---

## 3. Why this is the intelligent version (vs. what exists)

- Today the strongest trust-state guarantee is **local linear validity**. This
  upgrades it to **fork consistency** (Layer 1+2) and, on adequately-sized meshes,
  **non-equivocation** (Layer 3) — a strictly stronger, formally-named property
  hierarchy straight out of the SUNDR→CONIKS→CoSi line.
- It reuses structures already in the tree: the update log is *already* an
  append-only hash chain (membership.rs:808); this makes it a *provable* one. The
  approver quorum and Ed25519 path are reused verbatim for STH signing. No new
  cryptographic primitive is introduced — a Merkle tree is structured SHA-256, and
  the project already hashes with SHA-256 and signs with Ed25519.
- It closes a gap that "protect the admin key" **cannot** close: coercion /
  split-view compulsion, malicious-anchor distribution MITM, and accidental
  concurrent-signing forks (§1.2) — all of which are invisible today and become
  loud, evidence-backed halts.
- Honest scale caveat: fork *detection* (Layer 1+2) pays for itself at any size ≥2
  and is cheap; fork *prevention* (Layer 3) is a real win only at ≥5 nodes with
  independent witnesses. The design front-loads the cheap, universally-valuable
  half and makes the expensive half opt-in.

---

## 4. Cost / tradeoffs (at Rustynet's actual scale)

- **Wire bytes.** STH advert on gossip ≈ 44 B + framing, at most once per gossip
  cycle per peer — negligible next to the existing endpoint gossip. A full signed
  STH ≈ 120 B + 64 B/approver-sig. Consistency/inclusion proofs are O(log n) × 32 B
  — at 50 committed epochs, ≤ 6 × 32 = 192 B. Witness cosign round-trips (Layer 3)
  are one small request+proof+signature per witness per epoch — with a 2-of-3
  witness set that is ~6 tiny messages per membership change, which happens rarely
  (membership changes are human-paced, not per-packet).
- **CPU.** Merkle append is O(log n) SHA-256 (single-digit hashes at n≤50);
  proof verification is O(log n). All trivial on Pi-class hardware; membership
  changes are infrequent so even the constant factors are irrelevant.
- **Memory / disk.** O(n) leaf hashes + O(log n) right-edge cache. At n≤~10⁴
  (orders of magnitude beyond a home mesh's lifetime membership-change count) this
  is well under 1 MB. Fork-evidence bundles are a few hundred bytes each.
- **New failure modes.**
  - *False fork-halt from a genuine bug in proof code* → the mesh freezes
    membership advance. Mitigated by: shipping Layer 1 (the proof code) behind a
    long report-only bake (§6 Phase 1–2) with the halt disabled until the proof
    engine is proven against RFC 6962 test vectors and the existing corpus.
  - *Liveness cost of Layer 3* → if `witness_threshold` witnesses are offline,
    membership changes cannot be *promoted*. This is a deliberate fail-closed
    liveness/safety trade; the mitigation is a small threshold and choosing
    highly-available nodes (anchors) as witnesses, plus an operator override that
    is itself logged.
- **New attack surface.** Two new message types (STH advert, witness cosign
  request). Both are bounded-size, rate-limited (reusing the relay/gossip
  rate-limiter pattern), and — critically — **cannot grant anything**; the worst a
  malicious STH advert achieves is triggering a verified pull that then fails
  verification. Witness keys, if stolen, let an attacker *withhold* cosignatures
  (a liveness DoS on promotion, mitigated by threshold) or cosign an equivocation
  *if and only if* the admin quorum is also compromised — they never independently
  authorize state.
- **Operational complexity.** A `witness_threshold` config knob, a witness key per
  witness node, and an operator runbook for the fork-halt state. This is real
  added operator surface and is the main honest cost; it is why Layer 3 is opt-in.

---

## 5. Constraint check (explicit, against CLAUDE.md §3/§4/§8)

1. **No custom crypto / no VPN-protocol invention — PASS.** Merkle history trees
   are structured SHA-256 (already the repo's state-root hash); STH and witness
   cosignatures use the existing Ed25519 approver path verbatim. Nothing touches
   WireGuard or the dataplane; this is entirely control-plane trust state. The
   only "new" hashing detail is RFC 6962's `0x00`/`0x01` leaf/interior domain
   separation, which is a *strengthening* of the current undifferentiated
   `sha256(index|prev|hex)` chain, not a new primitive.
2. **Default-deny / fail-closed — PASS (structural).** Fork evidence → freeze on
   last-consistent state, apply nothing, grant nothing (§2.4). Missing/stale STH,
   missing witness quorum, unverifiable proof → the update is *not promoted*, i.e.
   the safe no-op. A witness can only *refuse*; it can never *grant*. Elevated
   capability still requires the admin approver quorum — this layer can only add a
   *second* gate (witnesses) that must also pass, never remove the first.
3. **Rust-first, no new runtime dependency category — PASS.** Pure Rust SHA-256 +
   Ed25519 (both already dependencies). No stats/ML runtime, no external log
   server, no CA. The Merkle log is ~a few hundred lines of `no_std`-friendly Rust.
4. **Domain crates stay transport-agnostic — PASS.** `merkle_log.rs`, the STH
   structs, and all proof verification live in `rustynet-control` and are pure
   data + hashing (no I/O, no transport). The *gossip carriage* of STH adverts and
   the *witness request/response network calls* live in `rustynetd`, exactly where
   the analogous gossip and bundle-pull code already lives. No transport type
   crosses into the domain crate.
5. **Home-lab / Pi-class / 2–50 nodes — PASS with the stated degradation.**
   Costs (§4) are trivial at this scale. Layer 3 is explicitly opt-in and
   defaults off below ~5 nodes; the design never assumes a datacenter, a dedicated
   log server, or thousands of participants (contrast a full CT deployment — this
   is the down-scaled peer-witness variant, cited as such).

**Novelty-honesty.** Searched the active ledgers: the closest prior mention is
`AnchorLiveLabAndCrossPlatformRoleDeltaPlan_2026-05-23.md` §C (adversarial/
signed-state-forgery chaos tests) and the sibling FIS-0002 formal-spec proposal
in `FableIntelligentSystemsProposals_2026-07-01.md` — but both target *local*
apply/replay correctness. **Neither addresses cross-node equivocation / fork
consistency**, which is a distinct property (a formally-correct local reducer can
still be forked). This proposal composes with FIS-0002: the TLA+ model would gain
a genuine new invariant to check (`NoUndetectedFork`), and the Merkle/STH
structures give that invariant a concrete enforcement point.

---

## 6. Incremental build path (no rewrite; each phase live-lab-provable)

- **Phase 1 — Pure Merkle history library (M).** `crates/rustynet-control/src/
  merkle_log.rs`: `MerkleHistory`, inclusion + consistency proof generation and
  verification, RFC 6962 domain separation. Unit tests against the published
  RFC 6962 test vectors **plus** property tests (proptest) asserting: any prefix is
  consistency-provable; any tampered/reordered/truncated log fails; inclusion holds
  for every leaf. **Zero wiring into live paths** — library + tests only. Falsifiable
  in isolation.
- **Phase 2 — STH minting + local log-as-tree, report-only (M).** Mint a
  `SignedTreeHead` whenever the membership log advances; persist it beside the
  snapshot. Emit the STH root in the daemon status line. **No gossip, no halt** —
  purely observational, so a bug cannot freeze a real mesh. Backtest: replay the
  existing membership logs through the tree and confirm STH roots are stable and
  reproducible.
- **Phase 3 — STH gossip + fork *detection*, report-only then enforcing (L).**
  Add the `GossipSthAdvert` message and the consistency-proof request/response on
  the existing gossip/anchor transport. First ship in **report-only** mode (log
  "would-halt" on fork evidence, take no action) for a bake period; then flip the
  fail-closed **fork-halt** on. Live-lab stage: an **equivocation-injection**
  harness (a deliberately-malicious test anchor that signs two divergent epoch
  N→N+1 updates and feeds them to disjoint node sets) must produce a fork-halt +
  a verifiable fork-evidence bundle on every OS. This is the headline acceptance
  test.
- **Phase 4 — Witness cosigning / fork *prevention* (L, needs a design
  decision).** Witness key management (issuance, rotation — composes with the
  existing `key_rotation` module), the cosign request/response protocol, the
  `witness_threshold` config + graceful-degradation default, and the promotion
  gate. The design decision to settle first: witness-set membership governance —
  is the witness set itself part of signed membership state (bootstrapping
  question: who witnesses the witness-set change?) or a separately-pinned operator
  config? (Leaning: pin the initial witness set at genesis like the initial
  approver set, and make witness-set changes themselves require a witnessed STH —
  the same recursion CT solves by pinning the log's key.)

Phases 1–3 deliver the universally-valuable detection half with no dependence on
Phase 4; Phase 4 is separable and gated behind the mesh-size and governance
decision.

---

## 7. How you'd know it worked / what would falsify it

- **Works if:** the Phase-3 equivocation-injection live-lab stage reliably halts
  the forked nodes and emits an offline-verifiable fork-evidence bundle, while a
  *legitimate* linear sequence of updates (the normal case) never triggers a halt
  across a long soak (zero false positives is the bar — a false fork-halt is a
  self-inflicted membership outage). With Phase 4, a witnessed run must make the
  injected equivocation *unpromotable* (the malicious anchor cannot gather
  `witness_threshold` cosignatures for both branches).
- **Falsified if:** (a) the false-positive rate under normal operation is nonzero
  after the Phase-2/3 bake — meaning proof/gossip timing races manufacture spurious
  forks, which would make the fail-closed halt worse than the disease; (b) at the
  realistic mesh sizes the project targets, meshes essentially never run ≥5 nodes
  with independent witnesses, making Phase 4 dead weight (in which case ship
  Phases 1–3 only and stop); (c) a security review shows the STH-gossip hint path
  can be abused to *force* a halt cheaply (a fork-halt DoS) faster than it can be
  rate-limited and evidence-gated — that would demote the halt to an alarm-only
  posture; (d) the Merkle proof engine cannot be made to agree with RFC 6962 test
  vectors without bespoke tweaks, which would mean the "no custom crypto" claim is
  false and the whole thing needs re-scoping.

---

## 8. Prior art

- Laurie, Langley, Kasper, **RFC 6962** *Certificate Transparency* (2013) — Merkle
  tree hash, inclusion (audit) and consistency proofs, Signed Tree Head, the
  `0x00`/`0x01` domain separation this design adopts.
- Crosby & Wallach, **"Efficient Data Structures for Tamper-Evident Logging"**
  (USENIX Security 2009) — the incremental append-only history tree and the
  right-edge node cache making appends O(log n).
- Mazières & Shasha, **"Building Secure File Systems out of Byzantine Storage"**
  (PODC 2002) and Li, Krohn, Mazières, Shasha, **SUNDR** (OSDI 2004) — the formal
  definition of **fork consistency**, the property Layer 2 delivers.
- Melara, Blankstein, Bonneau, Felten, Freedman, **CONIKS** (USENIX Security 2015)
  — key transparency with gossip-based non-equivocation for exactly the
  coercion/split-view threat model in §1.2.
- Chuat, Szalachowski, Perrig, Laurie, Messeri, **"Efficient Gossip Protocols for
  Verifying the Consistency of CT Logs"** (IEEE CNS 2015) and Nordberg et al.
  CT-gossip IETF drafts — the STH-exchange + consistency-proof-on-contact
  mechanics Layer 2 adapts to peer gossip.
- Syta, Tamas, Visher, Wolinsky, Jovanovic, Gasser, Gailly, Khoffi, Ford,
  **"Keeping Authorities 'Honest or Bust' with Decentralized Witness Cosigning"
  (CoSi)** (IEEE S&P 2016) — the witness-cosigning model Layer 3 adapts.
- **Sigsum** log design (independent-witness cosigning API), Google **Trillian**
  witnesses, and Tomescu et al. / Meta **Parakeet**, Apple key-transparency
  auditor model — production descendants confirming the peer/witness pattern
  scales down to "a few independent witnesses," which is what a home mesh can
  muster.

---

## 9. Honest weakest points (self-assessment)

1. **Layer 3's value is scale-gated and I will not pretend otherwise.** Below ~5
   nodes there is no independent witness set, so prevention degrades to detection.
   The universally-valuable content is Phases 1–3; Phase 4 must justify itself
   against real deployment sizes and may end up shelved.
2. **Fail-closed fork-halt is a liveness gun.** A bug in the proof engine, or a
   cheap way to inject spurious fork evidence, converts a safety feature into a
   self-inflicted membership outage. The multi-phase report-only bake and strict
   RFC-6962-test-vector conformance before enabling the halt are load-bearing, not
   optional — this is the single most important risk to retire before enforcement.
3. **Witness-set governance is a genuine bootstrapping recursion** (who witnesses a
   change to the witness set?) deferred to the Phase-4 design decision. The pin-at-
   genesis + witnessed-witness-set-change approach is the intended answer, mirroring
   how CT pins the log key, but it needs to be worked through fully before Phase 4.
4. **This does not defend against a fully compromised admin quorum *plus* a
   compromised witness threshold simultaneously** — nothing short of a fundamentally
   different trust model does. It raises the bar and makes equivocation *evident*;
   it does not make a total key compromise survivable. Claimed scope is
   fork-*evidence* and *raising the equivocation bar*, not omnipotence.

---

*Authored by Claude Fable 5, 2026-07-01, as a self-directed deep-dive companion to
`FableIntelligentSystemsProposals_2026-07-01.md`. Speculative R&D; unscheduled; no
code was written or changed. All current-behavior citations verified against the
repository on this date — re-verify line numbers before implementation.*
