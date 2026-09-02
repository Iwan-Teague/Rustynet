# Adversarial Review — Receiver-Index Demux Inverse-Map Plan — 2026-09-02

Refute pass against [`ReceiverIndexDemuxInversePlan_2026-09-02.md`](./ReceiverIndexDemuxInversePlan_2026-09-02.md),
required by that plan's §0/§7 and the audit's "Adversarial review needed: yes"
(`HotPathCloneAudit_2026-09-01.md:51-54`). Doc-only; no code changed. Every claim
below was re-verified against the tree on 2026-09-02 with the commands listed in
§"Verified anchors" at the end; line numbers are from this tree.

Method: each plan section is stated as claim → what was checked → verdict
(CONFIRMED / REFUTED / UNVERIFIABLE). The five assigned attack angles are then
treated in depth in §"The five attacks". The verdict is **READY-WITH-AMENDMENTS**:
the design direction is sound and survives attack, but one sequencing defect
(A1) breaks the plan's own fail-closed table if implemented as written, one
migration claim is false as written (A2), and one production-path panic must not
become more load-bearing (A3).

## Per-section adjudication

### Plan §0 (decision summary)

- Claim: the map "never becomes authoritative, every miss falls through to the
  endpoint fallback exactly as today, and any index/staleness anomaly fails
  closed (unknown index ⇒ drop, never misattribute)".
- Checked: current miss semantics at `engine.rs:851-863` (scan miss → `None` →
  endpoint fallback at `engine.rs:652-662`, both-miss → `Ok(None)` at
  `engine.rs:657-658`). A map with the same key domain reproduces this exactly
  as long as no two live peers share a `tunnel_index` — which the monotonic
  counter guarantees (`engine.rs:318`, `engine.rs:783-791`: `next_tunnel_index`
  starts at 1, is only ever advanced by `checked_add`, and is never decremented
  or reset anywhere in the crate — verified by grepping every
  `tunnel_index`/`allocate_tunnel_index`/`next_tunnel_index` occurrence; all 16
  hits are in `engine.rs`, listed in the anchors section).
- **CONFIRMED**, with the caveat that A1 below is required for "any anomaly
  fails closed" to survive the plan's own collision-refusal error path.

### Plan §1.1 / §1.2 (current scan + caller)

- Claim: verbatim code blocks, the O(n)-scan + `String`-clone cost, the
  "unavoidably owned" comment at `engine.rs:604-609`, the split borrow at
  `engine.rs:640-648`, the dispatch match at `engine.rs:651-666`, the `expect`
  at `engine.rs:666`, the clone-free endpoint fallback via
  `endpoint_index_lookup` (`engine.rs:825-832`).
- Checked: read `engine.rs:589-681` and `engine.rs:825-863`. Every quoted block
  matches the tree verbatim; `expect("matched peer state should exist")` is at
  `engine.rs:666`; `NodeId` is `pub struct NodeId(String)` with derived
  `Hash`/`Ord` at `crates/rustynet-backend-api/src/lib.rs:8-9`.
- **CONFIRMED.**

### Plan §1.3 (tunnel_index provenance + mutation sites)

- Claim: exactly three touching sites (configure_peer rebuild, remove_peer,
  update_peer_endpoint non-mutating), counter starts at 1, `checked_add`
  fail-closed.
- Checked: crate-wide grep (all hits in `engine.rs`); `configure_peer`
  allocates at `engine.rs:372` and inserts at `engine.rs:408-417`;
  `remove_peer` removes at `engine.rs:555-568` (unlink at `:563`);
  `update_peer_endpoint` (`engine.rs:425-439`) rewrites only `endpoint` and is
  proven not to touch `tunnel_index` by the existing test at
  `engine.rs:1520-1555` (`endpoint_only_change_moves_the_peer_and_keeps_its_session`,
  asserting `state.tunnel_index == index_before` across `EndpointMoved`).
- **CONFIRMED.** One nit: the plan cites `remove_peer` as `engine.rs:555-566`
  and the unlink arm as `557-563`; in this tree the function body ends at 568
  and the `unlink_endpoint` call is at 563. Same content.

### Plan §1.4 (the "rotates on rekey" premise is false)

This is the plan's most load-bearing negative claim, and the assigned task says
to verify it in the vendored boringtun rather than trust it.

- Checked `third_party/boringtun/src/noise/mod.rs`:
  - `Tunn::new` constructs the handshake with `index << 8`
    (`noise/mod.rs:209`), where `index` is the engine-supplied
    `tunnel_index` — matching `engine.rs:138-146`'s documented contract.
  - Every handshake initiation takes its local index from
    `Handshake::inc_index` (`noise/handshake.rs:471-476`):
    `self.next_index = (index & !0xff) | u32::from(idx8.wrapping_add(1))` —
    only the **low 8 bits** advance; the high 24 bits (the engine's
    `tunnel_index`) never change for the life of the `Tunn`. Both the
    initiation (`handshake.rs:733`) and the response-side session
    (`handshake.rs:828`, `Session::new(local_index, ...)` at `:889`) use this
    value, so rekeys re-issue indexes that differ only below bit 8.
  - Inbound matching agrees: the handshake state machine compares the full
    `receiver_idx` against `local_index` (`handshake.rs:581-582`, `:669`), a
    data packet is validated against the session's stored
    `receiving_index` (`noise/session.rs:242`), and boringtun's own device
    demux keys on `receiver_idx >> 8` for exactly the three packet types the
    engine scans for (`device/mod.rs:633-635`). `engine.rs:858`'s
    `receiver_idx >> 8` is therefore correct for every session of the tunnel.
- Consequence: a rekey produces a new `receiver_idx` whose `>> 8` is
  unchanged, so the inverse map needs no rekey-time update path, exactly as
  the plan concludes; the only retiring events are the `Replaced` rebuild
  (`engine.rs:403-407`) and `remove_peer`.
- **CONFIRMED.** The audit's own fix sketch ("updated where `tunnel_index` is
  assigned/rotated (rekey churn)", `HotPathCloneAudit_2026-09-01.md:47`) is
  the false premise; the plan is right to correct it.

### Plan §2 (invariants (a)-(e))

- (a) checker + fuzz-mirror shape: the cited precedent exists
  (`endpoint_index_agrees_with_linear_scan_reference_under_random_mutations`,
  fn at `engine.rs:1883`, with the linear `reference_lookup` closure at
  `engine.rs:1913-1920`). Shape is sound. **CONFIRMED.**
- (b) two mutation sites, one helper pair: site list confirmed (§1.3 above);
  "no other code may touch `receiver_index`" is enforceable by privacy plus
  the (a) fuzz. **CONFIRMED**, subject to A1 (the helper must be sequenced so
  its fallible refusal precedes every other mutation).
- (c) unknown/stale ⇒ drop: current miss semantics confirmed (§0 above). But
  the plan *retains* `expect` at `engine.rs:666` as "belt-and-braces" — that
  is the one place the invariant chain ends in a panic instead of a drop. See
  A3; as written this invariant's enforcement is **REFUTED as fail-closed**
  under CLAUDE.md §10.2 and must be amended to debug-assert + drop.
- (d) no shared index + collision refusal: structural impossibility is
  confirmed (monotonic, never-reused, `checked_add` fail-closed,
  `engine.rs:783-791`). The refusal itself is **REFUTED AS SEQUENCED** — see
  A1: as specified, the refusal fires *after* `peer_states.insert`, so the
  error path leaves the engine half-mutated.
- (e) teardown ordering in `remove_peer`: the `Some(removed_state)` arm at
  `engine.rs:558-565` is single-threaded (the engine is owned by the one
  worker thread — `engine.rs:126`, "Owned by the single worker thread"), has
  no early return between the statements, and adding
  `clear_tunnel_index(removed_state.tunnel_index)` beside
  `unlink_endpoint(removed_state.endpoint, node_id)` (`engine.rs:563`) is
  exactly the existing pattern. **CONFIRMED.**

### Plan §3.1 (map type; the borrow question)

- Claim: the `:604` "unavoidably owned" comment describes an artifact of the
  scan implementation, not a borrow-checker law; a disjoint-field read inside
  the split borrow returns `&NodeId` with no clone, mirroring
  `endpoint_index_lookup`.
- Checked: the destructuring at `engine.rs:645-652` already splits
  `peer_states` (mut) from `endpoint_index` (shared); adding `receiver_index`
  to the same destructure is the same disjointness. The `#[cfg(test)]`
  recorded-ingress block (`engine.rs:619-633`) currently runs *before* the
  destructure and clones `receiver_index_match`; the plan's stated restructure
  (read the free function on the destructured field) requires moving that
  block after the destructure and adding `receiver_index` (and, on the test
  path, `recorded_peer_ciphertext_ingress`) to it — feasible, semantics
  preserved (nothing mutates the indexes between record and dispatch; the
  buffer comment at `engine.rs:611-618` already states this). `Arc<str>`
  rejection is consistent with scope: `NodeId(String)` is a public domain type
  in `rustynet-backend-api`.
- **CONFIRMED.**

### Plan §3.2 (helper pair + call sites)

- **REFUTED in one respect (A1).** The ordering as written —
  `peer_states.insert` first (`engine.rs:408-417`), then
  `clear_tunnel_index(previous.tunnel_index)`, then
  `set_tunnel_index(...)` — makes the *only fallible* helper the *last*
  mutation. If `set_tunnel_index` ever returns its `BackendError::internal`
  collision refusal, the engine is left with the peer's state already
  replaced (new `tunnel_index` live at `engine.rs:415`) while the map holds
  neither the old nor the new entry — precisely the divergence invariant (a)
  forbids — *and* `configure_peer` returns `Err`, so the caller believes the
  reconfigure failed while the engine has already discarded the live session.
  The plan's own §4 row 7 ("the insert + index writes are infallible after
  that point") is false under its own invariant (d). A1 gives exact
  replacement sequencing.
- The Replaced-path capture of `previous.tunnel_index` alongside
  `previous_endpoint` (`engine.rs:399-402`) is straightforward — the same
  `peer_states.get` already there. CONFIRMED.
- `update_peer_endpoint` correctly gets no call (§1.3 site 3, and the
  regression test at `engine.rs:1520-1555` pins it). CONFIRMED.

### Plan §3.3 (consistency checker)

- Claim: `#[cfg(any(test, debug_assertions))]` checker; release builds
  compile it out; fail-closed behaviour never depends on it.
- Checked: consistent with the repo's debug-assert convention and with the
  fact that the release hot path must stand on the helper-pair sequencing
  alone. Note the interplay with A1: if the checker is invoked "between the
  two writes" as §3.2's prose suggests, it would fire on the legitimate
  mid-reconfigure ordering; it must be invoked at function boundaries only.
  Folded into A1.
- **CONFIRMED with that clarification.**

### Plan §4 (fail-closed table)

- Row 1 (retired index → miss → fallback/drop): confirmed equivalent to
  today's scan-miss (`engine.rs:857-863` → `engine.rs:652-658`).
- Row 2 (live foreign index → attribute then authenticate): confirmed. A map
  hit hands the datagram to that peer's `Tunn.decapsulate`
  (`engine.rs:667-670`); boringtun validates the full session index and keys
  (`noise/session.rs:242`, counter anti-replay at `session.rs:246-252`), so a
  wrong-key datagram dies in crypto. Same as today.
- Row 3 (future forgotten site → loud test failure): confirmed via the (a)
  fuzz template.
- Row 4 (`expect` fires → worker panic → "recoverable"): **the recovery claim
  is overstated and the posture needs amending (A3).** What is true: worker
  death surfaces as a `BackendError` matched by prefix in
  `is_runtime_worker_unavailable`
  (`crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs:162-175`)
  and `with_runtime_recovery` (`mod.rs:276-286`) restarts the runtime and
  retries once. What the plan omits: recovery rebuilds the engine from the
  key file (`start_runtime` → `UserspaceEngine::from_private_key_file`,
  `mod.rs:196-199`), discarding **every** peer's live session — one
  invariant-(a) bug turns into a fleet-wide tunnel reset, not a localized
  drop. And CLAUDE.md §10.2 is explicit that panics in security-sensitive
  production paths are DoS vectors. A3 replaces the panic with a
  debug-assert + drop-to-fallback.
- Row 5 (u32 exhaustion): confirmed pre-existing and unchanged
  (`engine.rs:785-789`).
- Row 6 (collision refused): refusal confirmed as defence-in-depth, but see
  A1 — as sequenced it does not fail closed for *both* peers.
- Row 7 (no partial write on configure failure): **REFUTED as written** — the
  fallible `set_tunnel_index` is sequenced after infallible mutations (A1).
  With A1's ordering the row becomes true.
- **Verdict: rows 1/2/3/5 CONFIRMED; rows 4/6/7 REFUTED as written, repaired
  by A1/A3.**

### Plan §5 (migration)

- **REFUTED in one respect (A2):** S2 claims the existing test
  `inbound_dispatch_uses_receiver_index_independent_of_source_address`
  (`engine.rs:1222-1299`) "keeps passing unmodified — it asserts behaviour,
  not the lookup mechanism". False: that test calls
  `engine.find_node_id_by_receiver_index(...)` **directly, three times**
  (`engine.rs:1283-1297`), so deleting the function in the same step breaks
  compilation of the test. It is a mechanical fix (point the assertions at
  the new `pub(crate)` probe seam, the same carve-out
  `find_node_id_by_endpoint` already has at `engine.rs:834-840`), but the
  plan must say so — "unmodified" is exactly the kind of claim this review
  exists to catch. No other caller exists (crate-wide grep: the only
  references are the definition, the `:609` call site, and the test).
- Tests-first order, S1→S4 increment shapes, and the S2 "delete the scan, no
  dead legacy branch" rule (AGENTS.md §3 one-hardened-path): otherwise
  CONFIRMED.

### Plan §6 (verification)

- Bench anchors verified: `bench_has_endpoint_miss_peers64` fn at
  `benches/dataplane_engine.rs:112`,
  `bench_find_node_id_by_endpoint_hit_peers64` at `:128` (probing the
  last-sorting filler — the mirror for a receiver-index hit bench is exactly
  as described); `criterion` dep at `Cargo.toml:39` with
  `default-features = false`, `[[bench]]` at `:44`.
- Gate plan (scoped xtask with flags, then full §7 list, backend-boundary
  script) matches AGENTS.md §7/§12. Docs-only here, so no gates were run for
  this review beyond the tree checks recorded below.
- **CONFIRMED.**

### Plan §7 (open questions) — answered

1. Attribution-semantics drift on early returns: **no drift possible.**
   `Unchanged` (`engine.rs:361`) and `EndpointMoved` (`engine.rs:368-369`)
   make no `tunnel_index` write and the state's index is unchanged, so the
   map entry (written at the last rebuild) still names the live state —
   identical to what the scan finds. `Replaced` retires the old index in both
   worlds. See "The five attacks" §5 for the full argument.
2. The `:666` expect: **must not stay a panic** — A3.
3. HashDoS: **not a concern**, with the bound made explicit — see "The five
   attacks" §3.
4. P4 interaction: agree — leave parallel, no abstraction for two sites. No
   objection.
5. Kernel parity: confirmed structural. The userspace engine is the only
   engine with the scan (`userspace_shared_macos/` contains only
   `mod.rs`/`runtime.rs`/`socket.rs`/`tun.rs` and no `engine.rs` — the macOS
   backend reuses this shared engine — and crate-wide grep shows no other
   `receiver_idx >> 8` demux); the kernel backend delegates demux to the
   kernel. The asymmetry is a property of where demux lives, not a coverage
   gap.

## The five attacks

### 1) Any path where the map can disagree with the scan?

Enumerated every early return and error path in `configure_peer`
(`engine.rs:330-423`) and `remove_peer` (`engine.rs:555-568`):

- `allowed_ips` parse error (`engine.rs:336-340`): returns before any
  mutation. No divergence.
- `allocate_tunnel_index` error (`engine.rs:372`): returns before any map or
  state mutation (it has only bumped `next_tunnel_index`, which is not part
  of either structure). No divergence.
- `Unchanged` (`:361`), `EndpointMoved` (`:368-369`): no index writes; the
  live state keeps its `tunnel_index`; the map entry from the last rebuild
  remains correct. No divergence.
- `Replaced` (`:403-407`): old index must be cleared and new set — the plan
  covers it, but in the wrong order relative to the fallible helper (A1).
- `remove_peer` `None` arm (`:566-567`): nothing to clear. No divergence.
- The one **REFUTED** path: `set_tunnel_index`'s collision refusal firing
  after `peer_states.insert` (A1). With A1's ordering, there is no path on
  which map and `peer_states` disagree at an observation point.

Conclusion: the only disagreement path is introduced by the plan's own
sequencing, and A1 removes it. After A1, the map's predicate is provably the
scan's predicate: map lookup returns `node` for `idx` iff some live state has
`tunnel_index == idx`, and (invariant (d), structurally guaranteed) at most
one such state exists, so the scan's "first match" tie-break is never
exercised — there is never a second match to tie-break.

### 2) Panic vs drop-and-count at the map-hit/`get_mut` boundary

The plan retains `expect("matched peer state should exist")`
(`engine.rs:666`) and, in §7.2, leans "fail-closed-and-loud". Refuted as the
default, for four reasons:

1. CLAUDE.md §10.2: "unwrap() and expect() are panics. In security-sensitive
   code, panics are denial-of-service vectors." This is the per-datagram
   inbound path — the most attacker-reachable line in the backend.
2. The blast radius is not "denial of the demux path" (§4 row 4) but total:
   worker death → `is_runtime_worker_unavailable`
   (`userspace_shared/mod.rs:162-175`) → `recover_runtime_after_worker_exit`
   rebuilds the engine from disk (`mod.rs:196-199`), dropping **every**
   peer's session and waiting for full re-handshakes fleet-wide.
3. The panic is unreachable without invariant-(a) breakage, and (a) is
   enforced by same-critical-section helpers plus a debug checker; a panic
   adds no enforcement, only a worse failure mode for the bug that already
   failed loudly in debug/CI.
4. Fail-closed means *no misattribution* — it does not require a crash. On a
   map hit whose state is missing, dropping (endpoint fallback, else
   `Ok(None)`) preserves the no-misattribution property: any endpoint-fallback
   attribution is still authenticated inside that peer's `Tunn.decapsulate`
   (`engine.rs:667-670`; `noise/session.rs:242`), so a wrong attribution
   cannot decrypt.

A3 gives the exact replacement. Note the same `expect` already guards the
endpoint-fallback path today (`endpoint_index` hit → `get_mut`), so the
amendment hardens the existing line rather than adding a new one — in scope,
because this change is what makes that line second-guessed.

### 3) HashDoS

Keys in the map are only ever `allocate_tunnel_index` output
(`engine.rs:783-791`) — locally generated monotonic counters. An attacker
supplies `receiver_idx` values on the wire (`noise/mod.rs:146/152/157` —
attacker-controlled bytes), but those are only ever **lookup probes**, never
insertions: `set_tunnel_index` is private and called only from
`configure_peer`, which is reached from the control plane
(`Backend::configure_peer`; the daemon-side removal analogue is
`crates/rustynetd/src/phase10.rs:7400` and the revocation loop at
`:7059`), never from a datagram path. std's `HashMap` uses SipHash-1-3 with a
per-process random seed, so probe-side collisions against a fixed key set
average O(1) and an off-path attacker cannot induce the collision pattern
that degrades the table (they do not choose the stored keys). Map size is
bounded by invariant (a) — at most one entry per live `peer_states` entry —
and peers are configured only by authenticated control state, so the
attacker cannot grow the map. **CONFIRMED: no HashDoS exposure**, provided
the amendment records the bound (A5) so a future editor does not add a
datagram-fed insertion.

### 4) Collision semantics — wrap, reuse, and who fails closed

- Wrap: impossible; `checked_add` errors at `u32::MAX`
  (`engine.rs:785-789`) before any reuse.
- Reuse after `remove_peer`: impossible; the counter is never decremented or
  reset (crate-wide grep; also the existing assertion
  `assert_ne!(idx_a, idx_b, "each peer gets a distinct tunnel index")` at
  `engine.rs:1262-1264` and the stable-index test at `engine.rs:1542-1554`).
- Today's behaviour if two peers *did* share an index: the scan would take
  the lowest-`NodeId` match silently (`engine.rs:859-862` — `.find` over a
  `BTreeMap` in ascending key order), i.e. today's failure mode is silent
  misattribution. The plan's refusal is strictly better *if* it fails closed
  for both peers.
- As specified it does not: the refusal fires after `peer_states.insert`
  (A1), leaving the *new* peer half-configured (state replaced, map entry
  absent) while the *existing* peer's map entry stays — a third variant of
  divergence. A1's ordering makes the refusal a pure no-op rejection: the
  check happens before any mutation, `configure_peer` returns `Err`, the
  existing peer's state and map entry are untouched, and no new state was
  created for the incoming peer. That is fail-closed for both.

### 5) Observable attribution change (trust binding)

Attempted to construct a sequence where the map attributes differently from
today's scan; none exists:

- Same key domain: `receiver_idx >> 8` for the same three packet types
  (`engine.rs:852-858`; `device/mod.rs:633-635`), `HandshakeInit` and
  unparsable datagrams → `None` in both worlds.
- Same hit set: map keys ≡ live `tunnel_index` values (invariant (a));
  scan finds a state iff its `tunnel_index` matches. Uniqueness (attack §4)
  makes "first match" ≡ "the match".
- Same miss behaviour: miss → endpoint fallback → `Ok(None)`
  (`engine.rs:652-658`), byte-identical fall-through.
- Transition instants are unobservable: the engine is single-owner
  (`engine.rs:126`), so no datagram is processed between the helper writes
  and the state write within one `configure_peer`/`remove_peer` call.

The only behavioural difference in the entire surface is the collision
handling (error vs silent lowest-NodeId pick) — an unreachable input either
way, and the plan's variant is the safer one. **Attribution is observably
identical; the trust-binding property is preserved.**

## Verdict

**READY-WITH-AMENDMENTS.** The core design (disjoint-field inverse map,
helper-pair maintenance at the two existing sites, invariant (a) fuzz,
split-borrow clone-free lookup) survives every attack; the boringtun staleness
analysis is confirmed against the vendored source; no HashDoS exposure; no
observable attribution change. Three amendments are required before code, two
minor anchor/wording corrections recommended.

## Amendments (apply to `ReceiverIndexDemuxInversePlan_2026-09-02.md`)

1. **A1 (required) — sequence the fallible helper before every mutation.**
   Replace the §3.2 bullet "configure_peer rebuild path: `set_tunnel_index(...)
   immediately after `peer_states.insert` (`engine.rs:408-417`). When the
   disposition is `Replaced`, the orphaned old index is cleared first via
   `clear_tunnel_index(previous.tunnel_index)` ... but clear-then-set keeps the
   (a) checker trivially satisfied at the hook between the two writes." with:

   > Mutating block order (after `allocate_tunnel_index` at `engine.rs:372`
   > and `Tunn::new` at `engine.rs:373-395` succeed):
   > 1. `set_tunnel_index(&peer.node_id, tunnel_index)` — its collision check
   >    runs before it inserts, so on refusal it returns
   >    `BackendError::internal` with **no mutation performed**;
   > 2. on `Replaced`, `clear_tunnel_index(previous.tunnel_index)` (captured
   >    beside `previous_endpoint` at `engine.rs:399-402`);
   > 3. `peer_states.insert(...)` (`engine.rs:408-417`);
   > 4. `unlink_endpoint`/`link_endpoint` (`engine.rs:418-421`).
   > Rationale: `set_tunnel_index` is the only fallible step after
   > allocation, so it must precede every other mutation — restoring §4 row
   > 7's "no partial write" guarantee. A collision refusal now fails closed
   > for both peers: the existing peer's state and map entry are untouched
   > and no state exists for the incoming peer. The transient states between
   > steps 1-3 (map entry present without state, or both old and new index
   > present) are unobservable: the engine is single-owner
   > (`engine.rs:126`) and no read path runs mid-statement. The §3.3 checker
   > is invoked at `configure_peer`/`remove_peer` **function boundaries
   > only**, never between these steps.

2. **A2 (required) — correct the S2 test claim.** Replace in §5 S2:
   "Existing test `inbound_dispatch_uses_receiver_index_independent_of_source_address` ... keeps passing unmodified — it asserts behaviour, not the
   lookup mechanism" with:

   > Existing test `inbound_dispatch_uses_receiver_index_independent_of_source_address`
   > (`engine.rs:1222-1299`) keeps its assertions but NOT its text unmodified:
   > it calls `find_node_id_by_receiver_index` directly three times
   > (`engine.rs:1283-1297`), so S2 must repoint those calls at the new
   > `pub(crate)` probe seam (same `cfg(any(test, feature = "test-harness"))`
   > carve-out `find_node_id_by_endpoint` already has, `engine.rs:834-840`)
   > in the same step as the deletion. The assertion content (foreign source
   → index routing, unknown index → `None`, handshake init → `None`) is
   > unchanged.

3. **A3 (required) — no panic in the inbound path.** Replace §2 (c)'s
   sentence "The existing `expect(\"matched peer state should exist\")`
   (`engine.rs:666`) is retained as the belt-and-braces proof ..." and §4 row
   4's panic posture with:

   > The dispatch resolves the peer with a guarded get, not a panic:
   >
   > ```rust
   > let node_id: &NodeId = match mapped {
   >     Some(node_id) if peer_states.contains_key(node_id) => node_id,
   >     Some(_) => {
   >         debug_assert!(false, "receiver_index named a peer with no live state (invariant (a) broken)");
   >         Self::endpoint_index_lookup(endpoint_index, remote_addr)
   >             .ok_or(())? // → `return Ok(None)`, datagram dropped
   >     }
   >     None => Self::endpoint_index_lookup(endpoint_index, remote_addr)
   >         .ok_or(())?,
   > };
   > ```
   >
   > (Borrows are disjoint: the matched id borrows `receiver_index`, the
   > guard reads `peer_states` shared, the later `get_mut` takes `peer_states`
   > mutable.) A map hit whose state is missing is treated exactly like a
   > miss — endpoint fallback, else drop — plus a `debug_assert!` so the
   > invariant break is loud in debug/CI. Rationale: CLAUDE.md §10.2 forbids
   > panics in attacker-reachable production paths; a worker panic here is
   > recovered only by a full engine rebuild (`userspace_shared/mod.rs:162-175`,
   > `:196-199`, `:276-286`), dropping every peer's session. Drop preserves
   > the fail-closed property (no misattribution: endpoint-fallback
   > attribution is still authenticated inside `Tunn.decapsulate`,
   > `engine.rs:667-670`). The pre-existing `expect` at `engine.rs:666` is
   > replaced by this guard on the same line's responsibility, so the change
   * removes a panic from the inbound path rather than adding one.

4. **A4 (recommended) — anchor drift.** Correct three line references:
   §4 row 7's "`engine.rs:339-346` parse" → `engine.rs:336-340` (the
   `AllowedIpNetwork::parse` map); §6's "`update_peer_endpoint_moves_peer_between_reverse_index_entries`
   at `engine.rs:1765`" → `engine.rs:1764`; §1.2's "split borrow
   (`engine.rs:640-648`)" → the comment starts at 640, the destructuring
   proper is `engine.rs:645-652`. §1.3's `remove_peer` range: `555-568`
   (unlink at 563).

5. **A5 (recommended) — state the HashDoS bound in §3.1.** Append:

   > The map's keys are only ever `allocate_tunnel_index` output — locally
   > generated, monotonic, never attacker-chosen; datagram-supplied
   > `receiver_idx` values are lookup probes only and can never become keys
   > (`set_tunnel_index` is private, called only from `configure_peer`, which
   > only the control plane reaches). Map size is bounded by invariant (a) to
   > `peer_states.len()`, so an attacker can neither grow the table nor
   > degrade std SipHash's probe cost by key choice.

## Fail-closed tests the implementation MUST write first

Ordered; T1-T3 gate S1 exactly as the plan says, with T3 strengthened per A1
and T4 added per A3:

1. **T1 `stale_receiver_index_after_rebuild_is_not_attributed`** (plan §5, as
   written, plus the §7.1 extension): configure → capture index →
   re-`configure_peer` with changed key material (`Replaced`) → old index
   resolves `None` (endpoint fallback aside), never the peer; new index
   resolves the peer; then `update_peer_endpoint` (roam) → the *same* index
   still resolves the peer (endpoint-moved-then-old-index case).
2. **T2 `removed_peer_receiver_index_entry_is_gone`** (plan §5, as written):
   after `remove_peer`, retired index ⇒ `None`;
   `receiver_index.len() == peer_states.len()`.
3. **T3 `duplicate_tunnel_index_collision_refusal_is_a_clean_no_op`**
   (strengthens plan §5 T3 per A1): drive the collision (test-only direct
   helper call) and assert — error returned; `peer_states` **byte-identical**
   to before the attempt; `receiver_index` **byte-identical** to before; the
   existing (non-colliding) peer still resolves. The plan's "map unchanged"
   is necessary but not sufficient: without A1's ordering the *state* map
   would have mutated, and this test is what proves the amendment.
4. **T4 `receiver_index_dispatch_never_panics_on_divergence`** (new, per A3):
   test-only construction of a divergent state (map entry naming a node with
   no `peer_states` entry — reachable via the test-harness seam), then a
   dispatch of a datagram carrying that index must return `Ok(None)` (or the
   endpoint-fallback outcome) and **not panic**, in a release-profile test
   build (`debug_assert` compiled out).
5. **T5 `receiver_index_agrees_with_peer_states_under_random_mutations`**
   (plan S3): the fuzz mirror of `engine.rs:1883`, driving
   configure/rebuild/remove/roam over N names against the linear-scan
   reference closure, checker invoked after every mutation.

## Verified anchors

All verified 2026-09-02 in this worktree (`rg` = ripgrep; `sed -n A,Bp`):

- `find_node_id_by_receiver_index` + `receiver_idx >> 8` + scan + clone:
  `sed -n 851,863p crates/rustynet-backend-wireguard/src/userspace_shared/engine.rs`
- Caller, owned match, `#[cfg(test)]` record, split borrow, dispatch match,
  `expect` at 666, endpoint fallback:
  `sed -n 589,681p ...engine.rs`
- `configure_peer` (parse 336-340, guard 350-370, allocate 372, Tunn::new
  373-395, capture 399-402, insert 408-417, relink 418-421),
  `update_peer_endpoint` 425-439, `remove_peer` 555-568, link/unlink 571-587:
  `sed -n 300,587p ...engine.rs`
- `allocate_tunnel_index` (start 318; checked_add 783-791),
  `endpoint_index_lookup` 825-832, `find_node_id_by_endpoint` + bench_support
  seam comment 834-840: `sed -n 315,328p` + `sed -n 783,840p ...engine.rs`
- `tunnel_index` field + contract 132-148, `endpoint_index` field + lockstep
  doc 99-115: `sed -n 99,148p ...engine.rs`
- Mutation-site completeness:
  `grep -rn "tunnel_index|allocate_tunnel_index|next_tunnel_index" crates/rustynet-backend-wireguard/src`
  → 16 hits, all `engine.rs`
- Other callers of the scan:
  `grep -rn "find_node_id_by_receiver_index" crates/` → definition + `:609`
  call + test only
- Tests: dispatch test 1222-1299 (direct calls 1283-1297), roam-stable-index
  test 1520-1555, tie-break region 1755-1775, fuzz fn 1883 +
  `reference_lookup` 1913-1920: `sed -n` over each range
- Benches: `sed -n 105,140p crates/rustynet-backend-wireguard/benches/dataplane_engine.rs`
  (fn at 112, fn at 128); `grep -n "bench|criterion" .../Cargo.toml` → 39, 44
- `NodeId`: `sed -n 1,15p crates/rustynet-backend-api/src/lib.rs` (derive :8,
  `pub struct NodeId(String)` :9)
- boringtun: `index << 8` at `noise/mod.rs:209`; `receiver_idx` parse sites
  `noise/mod.rs:98-157`; `inc_index` low-8-only bump
  `noise/handshake.rs:471-476` (uses at `:733`, `:828`, `Session::new` `:889`);
  full-index handshake match `handshake.rs:581-582`, `:669`; data-packet
  session index check `noise/session.rs:242`; device demux `receiver_idx >> 8`
  `device/mod.rs:633-635`
- Worker-death recovery: `is_runtime_worker_unavailable`
  `userspace_shared/mod.rs:162-175`; `with_runtime_recovery` `:276-286`;
  engine rebuild in `start_runtime` `:196-199` (plus the macOS twin at
  `userspace_shared_macos/mod.rs:175`)
- Daemon removal path: `crates/rustynetd/src/phase10.rs:7400`
  (`self.backend.remove_peer(node_id)`), revocation loop `:7059`;
  `crates/rustynetd/src/revoked_peer_denied_audit.rs` exists
- Audit cross-references: `HotPathCloneAudit_2026-09-01.md` P2 §:25-54
  ("Adversarial review needed: **yes** ... trust binding" at `:51-54`; the
  stale line hint and the rekey premise the plan corrects at `:27`, `:47`);
  `DataplanePerfBacklog_2026-06-12.md:186` (worker-death string-match
  contract)
- No macOS engine duplicate:
  `ls crates/rustynet-backend-wireguard/src/userspace_shared_macos/` →
  `mod.rs runtime.rs socket.rs tun.rs` (no `engine.rs`)
