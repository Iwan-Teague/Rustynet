# Receiver-Index Demux Inverse-Map Plan — 2026-09-02

Implementation plan for the P2 finding "Inbound demux does a linear scan + heap-clone
`NodeId` per datagram" from [`HotPathCloneAudit_2026-09-01.md`](./HotPathCloneAudit_2026-09-01.md)
(§"New findings", first P2). Docs-only plan; no Rust change is made here. Scope is the
userspace engine only (`crates/rustynet-backend-wireguard/src/userspace_shared/engine.rs`);
the kernel backend has no such scan.

Note on the audit's line hint: the audit pointed at "~lines 1918–1935" for
`find_node_id_by_receiver_index`; that range actually holds the linear *reference
lookup* of the endpoint-index consistency test (`reference_lookup`,
`engine.rs:1914-1920`). The real function is at `engine.rs:851-863`. The audit's
substance is correct; only the hint was stale. Anchors in this plan were re-verified
against the tree on 2026-09-02.

## 0) Decision summary

Replace the per-inbound-datagram linear scan over `peer_states` (and its `NodeId`
heap clone) with a second reverse index, `receiver_index: HashMap<u32, NodeId>`,
maintained alongside the authoritative `peer_states` map at the same two mutation
sites that already maintain `endpoint_index` (`configure_peer`, `remove_peer`) via a
single helper pair (`set_tunnel_index` / `clear_tunnel_index`). Because the lookup
becomes a read of a field disjoint from `peer_states`, it joins the existing
split-borrow in `process_inbound_ciphertext` and returns a `&NodeId` directly —
eliminating both the O(n) scan and the per-packet clone; the "unavoidably owned"
premise of the current caller comment (`engine.rs:604-608`) dissolves rather than
being worked around. The map is an internal performance structure of the userspace
engine only: it never becomes authoritative, every miss falls through to the
endpoint fallback exactly as today, and any index/staleness anomaly fails closed
(unknown index ⇒ drop, never misattribute). An adversarial (refute) review is
required before code (§7); the audit marks this finding as trust-binding.

## 1) Current behaviour

### 1.1 The scan + clone (`engine.rs:851-863`)

```rust
    fn find_node_id_by_receiver_index(&self, payload: &[u8]) -> Option<NodeId> {
        let receiver_idx = match Tunn::parse_incoming_packet(payload).ok()? {
            Packet::HandshakeResponse(packet) => packet.receiver_idx,
            Packet::PacketCookieReply(packet) => packet.receiver_idx,
            Packet::PacketData(packet) => packet.receiver_idx,
            Packet::HandshakeInit(_) => return None,
        };
        let tunnel_index = receiver_idx >> 8;
        self.peer_states
            .iter()
            .find(|(_node_id, peer_state)| peer_state.tunnel_index == tunnel_index)
            .map(|(node_id, _peer_state)| node_id.clone())
    }
```

(`engine.rs:859` is `let tunnel_index = receiver_idx >> 8;`, the scan is
`engine.rs:860-862`.) Cost per inbound `Packet::Data` / `HandshakeResponse` /
`CookieReply`: O(n) over `peer_states` plus one `String` duplicate — `NodeId` is a
newtype over `String` (`crates/rustynet-backend-api/src/lib.rs:9`,
`pub struct NodeId(String)`; `Hash`/`Ord` derived at `lib.rs:8`).

### 1.2 The caller (`process_inbound_ciphertext`, `engine.rs:589-680`)

The dispatch prefers the receiver index and falls back to the endpoint match:

```rust
        // `receiver_index_match` is unavoidably owned — `find_node_id_by_receiver_index`
        // does its own linear scan-and-clone and is out of scope for this change (P4
        // only replaces the endpoint-keyed lookup). The endpoint fallback below is
        // resolved separately, after the split-borrow, as a `&NodeId` straight out of
        // `endpoint_index` — no clone on that path.
        let receiver_index_match = self.find_node_id_by_receiver_index(payload);
```

(`engine.rs:604-609`.) Under `#[cfg(test)]` the match is recorded into the
observability buffer (`recorded_match`, `engine.rs:622-624`), then released builds
destructure the engine for a split borrow:

```rust
        let Self {
            peer_states,
            endpoint_index,
            recorded_tunnel_plaintext_packets,
            decrypt_scratch,
            decrypt_follow_up_scratch,
            ..
        } = self;
```

(`engine.rs:640-648`) and pick the peer:

```rust
        let node_id: &NodeId = match &receiver_index_match {
            Some(node_id) => node_id,
            None => {
                let Some(node_id) = Self::endpoint_index_lookup(endpoint_index, remote_addr) else {
                    return Ok(None);
                };
                node_id
            }
        };

        let peer_state = peer_states
            .get_mut(node_id)
            .expect("matched peer state should exist");
```

(`engine.rs:651-666`; the `expect` at `engine.rs:666` is the existing "a matched id
always has state" assertion). The endpoint fallback already returns a clone-free
`&NodeId` out of the split-borrowed `endpoint_index` via the free function
`endpoint_index_lookup` (`engine.rs:825-832`) — the exact pattern this plan extends
to the receiver index.

### 1.3 Where `tunnel_index` comes from and every site that touches it

`tunnel_index: u32` lives on `PeerEngineState` (`engine.rs:147`) with its contract
documented at `engine.rs:139-146`: it is handed to `Tunn::new` as the local session
index (boringtun stores `index << 8`), and inbound packets echo it back in
`receiver_idx` (`receiver_idx >> 8 == tunnel_index`). The counter starts at 1
(`engine.rs:318`, `next_tunnel_index: 1`) and is handed out by
`allocate_tunnel_index` (`engine.rs:783-790`), which fails closed with
`checked_add` when `u32` space is exhausted (`engine.rs:785-788`).

**Mutation sites (complete list — verified by grepping every `tunnel_index` and
`allocate_tunnel_index` occurrence in the crate):**

1. **`configure_peer`, rebuild path** — `engine.rs:372` allocates; `engine.rs:408-417`
   inserts the new `PeerEngineState` carrying `tunnel_index` (`engine.rs:415`), then
   relinks the endpoint index (`engine.rs:418-421`). Reaching this path means the
   peer's key material or allowed-IPs changed (`engine.rs:350-358` guard), so this is
   the "Replaced" rebuild: the peer's **old** `tunnel_index` is orphaned and a fresh
   one takes over. Note this is the *reconfigure/rebuild* site, not a rekey: see
   1.4.
2. **`remove_peer`** — `engine.rs:555-566` removes the state (`engine.rs:557`) and
   unlinks the endpoint from `removed_state.endpoint`. This is the single teardown
   choke point; the daemon-side revocation/removal path reaches it via
   `Backend::remove_peer` (`crates/rustynetd/src/phase10.rs:7400`, and the
   revocation loop at `crates/rustynetd/src/phase10.rs:7059`).
3. **`update_peer_endpoint`** — `engine.rs:425-437` moves the endpoint and **does not
   touch `tunnel_index`** (roaming deliberately keeps the live session). Not a
   mutation site; listed so the plan's coverage claim is checkable.

### 1.4 The "rotates on rekey" premise is false here — and that matters

The audit/task framing says the index must track rekey rotation. In *this* engine it
does not: a WireGuard rekey rotates **session keys inside the existing `Tunn`**;
`tunnel_index` is the stable per-tunnel base passed once at `Tunn::new`
(`engine.rs:376-395`) and is never rewritten after the `peer_states.insert` at
`engine.rs:408`. There is no `set_tunnel_index`-shaped code anywhere today. The only
event that retires an index is the `configure_peer` **Replaced** rebuild (1.3 site
1), which discards the old tunnel entirely — and because `allocate_tunnel_index`
is a monotonic never-reused counter (1.3, `engine.rs:783-790`), a retired index can
never be reissued to a different peer. Consequences for the design: (a) the inverse
map needs no rekey-time update path; (b) its only churn is insert-on-rebuild and
clear-on-remove; (c) "staleness across rekey" reduces to "an attacker speaks a
retired index" — which must still fail closed, §4.

## 2) Invariants, enforcement points, tests

The map must hold, at every observation point, that
`receiver_index: tunnel_index → NodeId` is exactly the image of the live
`peer_states` entries. Each invariant gets one enforcement point and one named
verification. (Precedent for the shape of (a): the endpoint index already has
`endpoint_index_agrees_with_linear_scan_reference_under_random_mutations`,
`engine.rs:1883+`, which fuzzes mutations against a linear reference lookup — the
same technique is reused.)

**(a) Index ⊆ `peer_states` at all times** — the map never names a peer that has no
state, and every live state's index is present.
Enforcement: a `debug_assert`-plus-test-only consistency checker
(`verify_receiver_index_consistent`, called at the top and bottom of
`configure_peer`/`remove_peer` under `#[cfg(any(test, debug_assertions))]`, and from
a randomized mutation test) that asserts set-equality between
`receiver_index.iter()` and `peer_states.iter().map(|(id, ps)| (ps.tunnel_index, id))`.
Verification: `receiver_index_agrees_with_peer_states_under_random_mutations` — a
mirror of the endpoint-index fuzz test at `engine.rs:1883`, driving
configure/rebuild/remove sequences over N names and comparing against the linear
scan reference.

**(b) Every `tunnel_index` mutation site updates the index in the same critical
section** — there are exactly two (1.3 sites 1 and 2); both must go through the one
helper pair, and no other code may touch `receiver_index`.
Enforcement: private helpers `fn set_tunnel_index(&mut self, node_id: &NodeId, index: u32)`
and `fn clear_tunnel_index(&mut self, index: u32)` are the only writers; both are
called from inside `configure_peer` (after the fallible steps, immediately beside the
existing `peer_states.insert` / `unlink_endpoint`/`link_endpoint` block,
`engine.rs:405-421`) and `remove_peer` (beside `unlink_endpoint`,
`engine.rs:557-563). Privacy (`fn`, not `pub(crate)`) plus the (a) checker makes a
forgotten site a loud test failure rather than a silent drift.
Verification: unit tests named below, plus the (a) fuzz test, which would catch any
future mutation site added without a helper call.

**(c) Unknown/stale index ⇒ drop, never attribute to a stale peer.**
Enforcement: the lookup in `process_inbound_ciphertext` (§3.2) returns `None` for an
unknown index and falls through to the endpoint fallback exactly as
`find_node_id_by_receiver_index` does today (`engine.rs:857-863`: miss → `None` →
endpoint fallback at `engine.rs:652-658`; a miss on *both* returns `Ok(None)` =
drop, `engine.rs:655-657`). The map never contains a retired index (invariants
(a)/(b): cleared at rebuild/remove), so "stale index" and "unknown index" are the
same lookup outcome. The existing `expect("matched peer state should exist")`
(`engine.rs:666`) is retained as the belt-and-braces proof that a map hit implies
live state; if it could ever fire, that is invariant-(a) breakage, and the fail-closed
posture is to treat it as a bug, not to add a fallback branch.
Verification: `stale_receiver_index_after_rebuild_is_not_attributed` (§5, T1) —
after a Replaced rebuild, a datagram carrying the *old* index resolves to `None`
(endpoint fallback aside) and never to the rebuilt peer.

**(d) Two peers can never share a `tunnel_index`.**
Today: guaranteed structurally — the monotonic counter (`engine.rs:318`, `:783-790`)
never reuses a value and fails closed at `u32` exhaustion, so a collision cannot
arise; the old linear scan would simply have taken the first (lowest-`NodeId`) match
had one ever existed, silently. The plan does not rely on the scan's silent
tie-break: `set_tunnel_index` refuses a key collision with a *different* `NodeId`
with a hard error (`BackendError::internal`), and `debug_assert`s it.
Enforcement: the collision check inside `set_tunnel_index`.
Verification: `duplicate_tunnel_index_collision_is_refused` (§5, T3) — drives
`set_tunnel_index` twice with different node ids for one index and asserts the
error and that neither map entry changed; a comment at the counter
(`allocate_tunnel_index`, `engine.rs:783`) records that the refusal is
defence-in-depth, not the primary guard.

**(e) Removal/revocation clears the index entry before the peer state is dropped
(teardown-before-revoke ordering).**
Enforcement: `remove_peer` (`engine.rs:555-566`) calls
`clear_tunnel_index(removed_state.tunnel_index)` inside the same `Some(removed_state)`
arm that already calls `unlink_endpoint` (`engine.rs:557-563`), i.e. the index entry
is gone in the same critical section that retires the state, before the function
returns and the state is dropped. Ordering is observable to no one between the two
statements (single-threaded worker, no early-return between them), which is the same
reasoning the endpoint unlink already relies on.
Verification: `removed_peer_receiver_index_entry_is_gone` (§5, T2) — after
`remove_peer`, the retired index is `None` and the map size equals the
`peer_states` size; the revocation integration path is exercised by the existing
daemon revocation tests that drive `Backend::remove_peer`
(`crates/rustynetd/src/revoked_peer_denied_audit.rs`).

## 3) Design

### 3.1 Map type and key ownership

`receiver_index: HashMap<u32, NodeId>` as a field of `UserspaceEngine`, beside
`endpoint_index` (`engine.rs:118`). `u32` keys are trivially hashable;
`NodeId` derives `Hash`/`Clone` (`backend-api/src/lib.rs:8`).

**Can the caller take a borrow, given the `:604` "unavoidably owned" comment? Yes.**
The ownership was an artifact of the *implementation*, not a borrow-checker law: the
scan needed `&self.peer_states` *before* the split-borrow destructuring at
`engine.rs:640-648` takes `peer_states` mutably, so the result had to be an owned
`NodeId` to survive that transition. Once the lookup is a read of a **different,
disjoint field**, it can be performed *inside* the split borrow exactly the way the
endpoint fallback already is (`endpoint_index_lookup`,
`engine.rs:825-832`, called at `engine.rs:653`): destructure `receiver_index`
alongside `peer_states` in the `let Self { .. } = self;` block, run a free function
`receiver_index_lookup(&HashMap<u32, NodeId>, tunnel_index) -> Option<&NodeId>`, and
the `&NodeId` feeds `peer_states.get_mut(node_id)` at `engine.rs:665` with **no
clone on either path**. `tunnel_index` extraction stays up-front (it only needs
`Tunn::parse_incoming_packet` on `payload`, which borrows neither field), so the
sequence becomes: parse receiver_idx → split-borrow → index lookup (cheap) →
endpoint fallback (unchanged) → `get_mut`. The `#[cfg(test)]` recorded-ingress block
(`engine.rs:614-633`, `recorded_match` at `engine.rs:622`) keeps its semantics by
reading the same free function on the destructured field before the mutable use
(the buffer comment at `engine.rs:611-613` already documents that nothing mutates
the indexes between record and dispatch).

`Arc<str>`/interned-key alternatives were considered and rejected: they change a
public domain type (`NodeId(String)` in `rustynet-backend-api`) or thread an
allocation strategy through trust-boundary code to solve a problem the field-level
borrow already eliminates; the P3 fair-drain item may still choose interning for
*its* `FlowKey` (`HotPathCloneAudit_2026-09-01.md` §P3) — that decision is
independent and out of scope here (§8).

### 3.2 Single maintenance helper pair

```rust
fn set_tunnel_index(&mut self, node_id: &NodeId, index: u32) { /* insert + collision refusal (inv. d) + cfg-checker hook */ }
fn clear_tunnel_index(&mut self, index: u32) { /* remove; no-op on absent (idempotent) */ }
```

Call sites — and only these (invariant (b)):
- `configure_peer` rebuild path: `set_tunnel_index(&peer.node_id, tunnel_index)`
  immediately after `peer_states.insert` (`engine.rs:408-417`). When the disposition
  is `Replaced`, the orphaned old index is cleared first via
  `clear_tunnel_index(previous.tunnel_index)` (captured from
  `self.peer_states.get(&peer.node_id)` where `previous_endpoint` is already read,
  `engine.rs:402-404`) — monotonic allocation means old ≠ new, so ordering inside
  the block is not load-bearing, but clear-then-set keeps the (a) checker trivially
  satisfied at the hook between the two writes.
- `remove_peer`: `clear_tunnel_index(removed_state.tunnel_index)` beside
  `unlink_endpoint` (`engine.rs:557-563`) — invariant (e).

`update_peer_endpoint` (`engine.rs:425-437`) deliberately gets no call: it does not
mutate `tunnel_index` (1.3 site 3).

### 3.3 Consistency checker

`#[cfg(any(test, debug_assertions))] fn verify_receiver_index_consistent(&self)` —
asserts the bijection of invariant (a) (same size; every `(index, node_id)` pair in
the map is present in `peer_states` and vice versa). Invoked from the (a) fuzz test
after every mutation, and cheap enough to also call at the end of
`configure_peer`/`remove_peer` in debug builds. Release builds compile it out;
the fail-closed behaviour never depends on it — it exists to make drift loud.

## 4) Fail-closed analysis

Paths where the index could go stale or wrong, and the observable outcome. In every
row the outcome is **drop (or correct attribution), never misattribution**:

| # | Path | Mechanism | Observable outcome |
|---|------|-----------|--------------------|
| 1 | Attacker speaks a retired index (post-rebuild or post-removal) | Cleared by `set`/`clear` (inv. b/e); lookup misses | Falls to endpoint fallback; if that also misses, `Ok(None)` ⇒ drop (`engine.rs:652-657`) — identical to today's scan-miss |
| 2 | Attacker speaks a *live* foreign index | Map hit attributes the datagram to that live peer — but this is exactly today's behaviour (scan would find the same peer; WireGuard's own `peers_by_idx` demux has the same property) and is subsequently authenticated by the tunnel's session keys inside `Tunn::decapsulate` (`engine.rs:667-674`), so a wrong-key datagram is rejected by crypto, not by demux | Unchanged from today; no new exposure |
| 3 | Forgotten update at a future mutation site | (a) fuzz test fails in CI; debug checker asserts | Loud test failure, not production drift |
| 4 | Map/`peer_states` divergence somehow escapes checks and the `expect` at `engine.rs:666` fires | Panic in the worker thread — the runtime already treats worker death as recoverable (`is_runtime_worker_unavailable` string-match contract, `DataplanePerfBacklog_2026-06-12.md` §3) | Loud failure (denial of the demux path), which is fail-closed; never silent misattribution |
| 5 | `u32` index-space exhaustion | Pre-existing: `allocate_tunnel_index` errors (`engine.rs:785-788`) | Unchanged; peer configure fails, no index written |
| 6 | Collision (two peers, one index) | Structurally impossible (monotonic counter); `set_tunnel_index` additionally refuses with `BackendError::internal` (inv. d) | Configure error, no index written |
| 7 | `configure_peer` fails partway (bad allowed-IP parse, allocation error) | Fallible steps all complete *before* the first mutation (`engine.rs:339-346` parse; `engine.rs:372` allocate), and the insert + index writes are infallible after that point | No partial write; index and state never diverge |

The trust-binding property this preserves: an inbound ciphertext datagram is
attributed to a peer iff its `tunnel_index` is that peer's **currently live** index —
the same predicate the linear scan computes, computed from a structure that is
proven (a) to mirror `peer_states`.

## 5) Migration steps

Tests are written FIRST, against the new seam, and fail before the change (the first
three exercise fail-closed behaviour):

- **T1** `stale_receiver_index_after_rebuild_is_not_attributed` — configure peer;
  capture index; re-`configure_peer` with changed key material (Replaced path);
  datagram carrying the old index ⇒ lookup `None` (or endpoint-fallback outcome),
  never the peer; new index ⇒ the peer. *(S)*
- **T2** `removed_peer_receiver_index_entry_is_gone` — configure; `remove_peer`;
  old index ⇒ `None`; `receiver_index.len() == peer_states.len()`. *(S)*
- **T3** `duplicate_tunnel_index_collision_is_refused` — second `set_tunnel_index`
  with a different `NodeId` for a live index ⇒ `BackendError::internal`, map
  unchanged. *(S)*
- **S1** — add the `receiver_index` field, helper pair, collision refusal; wire the
  two call sites (`configure_peer`, `remove_peer`). Tests T1-T3 green. *(S)*
- **S2** — add `receiver_index_lookup` free function + consistency checker; extend
  the `let Self { .. }` destructuring (`engine.rs:640-648`); switch the dispatch
  match (`engine.rs:651-659`) to consult the map first and delete
  `find_node_id_by_receiver_index` (the audit's finding is only closed if the scan
  is *removed*, per the one-hardened-path rule — no dead legacy branch kept).
  Update the `#[cfg(test)]` recorded-ingress block (`engine.rs:614-633`) to the
  same free function. Existing test
  `inbound_dispatch_uses_receiver_index_independent_of_source_address`
  (`engine.rs:1222-1299`) keeps passing unmodified — it asserts behaviour, not the
  lookup mechanism (it reads `tunnel_index` off `peer_states` and builds raw
  packets, `engine.rs:1250-1299`). *(M)*
- **S3** — add the randomized fuzz test
  `receiver_index_agrees_with_peer_states_under_random_mutations` (mirror of
  `engine.rs:1883`), reusing its configure/rebuild/remove mutation driver and a
  linear-scan reference closure. *(M)*
- **S4** — bench (§6), ledger row, and a one-line status note in
  `HotPathCloneAudit_2026-09-01.md` §"New findings" marking the P2 as implemented
  with the verifying evidence. *(S)*

S-sizes: S1-S4 are each a small, independently verifiable increment; S2 is the only
medium step (touching the hot dispatch) and is gated by T1-T3 being green first.

## 6) Verification

- **Existing tests that must keep passing (unmodified):**
  `inbound_dispatch_uses_receiver_index_independent_of_source_address`
  (`engine.rs:1222`), the endpoint-index suite (`update_peer_endpoint_moves_peer_between_reverse_index_entries`
  at `engine.rs:1765`, the shared-endpoint tie-break tests at `engine.rs:1636-1824`,
  the consistency fuzz at `engine.rs:1883`), the fair-drain flow-key tests that call
  `flow_key_for_remote` (`engine.rs:797-806`), and the daemon revocation tests via
  `Backend::remove_peer` (`crates/rustynetd/src/revoked_peer_denied_audit.rs`).
- **Bench:** the backend crate already benches this layer —
  `crates/rustynet-backend-wireguard/benches/dataplane_engine.rs`
  (`bench_has_endpoint_miss_peers64` at `:112`,
  `bench_find_node_id_by_endpoint_hit_peers64` at `:128`; `[[bench]]` wired in the
  crate `Cargo.toml:44`, criterion at `:39`). Add
  `bench_find_node_id_by_receiver_index_hit_peers64` mirroring `:128` (N=64 peers,
  probe the index of the peer whose datagram the old scan would walk furthest to
  reach), exposed through the existing `cfg(any(test, feature = "test-harness"))`
  probe seam (`engine.rs:833-838` documents the pattern). Record before/after
  numbers in the S4 ledger note; criterion baselines make regression visible in
  later runs.
- **Gates:** the change is confined to one crate —
  `cargo run -p rustynet-xtask -- gates -p rustynet-backend-wireguard` (fmt →
  clippy → test, flags appended), then the full §7 AGENTS.md list before landing
  (clippy/test with `--locked`), plus `scripts/ci/check_backend_boundary_leakage.sh`
  (no new cross-boundary types — `receiver_index` stays inside the backend crate —
  but the gate is cheap insurance for a trust-binding change).

## 7) Risks + open questions (for the mandatory adversarial/refute pass)

1. **Attribution semantics drift.** The plan claims the map reproduces the scan's
   predicate exactly. Refute angle: any sequence where map and scan disagree —
   in particular the Replaced rebuild window (old index cleared, new set) and the
   `Unchanged`/`EndpointMoved` early-return paths (`engine.rs:351-361`), which make
   *no* index writes: is there any state in which an early return leaves a stale
   entry? (Analysis says no — those paths don't retire the tunnel — but the refute
   pass must confirm, and T1 should be extended with an
   endpoint-moved-then-old-index case.)
2. **The `expect` at `engine.rs:666` becomes load-bearing for a map hit.** Today a
   scan hit cannot miss `get_mut` (same map); with the inverse map, a hit does
   require invariant (a). The fail-closed posture (§4 row 4) accepts a loud panic
   over silent misattribution — is that acceptable, or should the refuter demand a
   drop-on-divergence instead? (House rules lean fail-closed-and-loud; confirm.)
3. **HashDoS / key control.** Index keys are attacker-influenced (they arrive in
   datagrams) but the map only ever contains locally allocated counter values, so
   lookup probes arbitrary keys but never inserts them — SipHash on `u32` is fine.
   Refute: any path where a datagram-supplied value becomes a *key*? (None known;
   `set_tunnel_index` is called only with `allocate_tunnel_index` output.)
4. **Interaction with P4.** Both indexes now live on the struct and are maintained
   in `configure_peer`/`remove_peer`. They stay separate structures (different key
   types, different semantics — endpoint tie-break vs unique index), but the
   maintenance *point* is shared, and the (a)-style fuzz for one is a template for
   the other. Open question for review: worth extracting a tiny shared
   "reverse-index maintained-in-lockstep" comment/test convention, or leave
   parallel? (Lean: leave parallel; no abstraction for two sites.)
5. **Kernel-backend parity.** `UserspaceEngine` is one of two backends; the kernel
   backend delegates demux to the kernel and has no scan (nothing to fix), but the
   audit's P2 is userspace-only — confirm the refuter agrees the asymmetry is
   structural, not a gap.

Per the audit: "Adversarial review needed: yes." No code lands before a refute pass
against this section.

## 8) Explicitly out of scope

- The **vendored boringtun P2** (`queue_packet` `to_vec()` per outbound packet,
  `third_party/boringtun/src/noise/mod.rs:524`, call at `:265`) — report-only;
  requires a vendoring decision, not this plan.
- The **P3 fair-drain `FlowKey` clone**
  (`crates/rustynet-backend-wireguard/src/userspace_shared/fair_drain.rs:202,233`) —
  separate finding; its intern-`u32`/`Arc<str>` fix is independent (§3.1), and its
  audit entry already marks it "no adversarial review required".
- The **P4 endpoint→peer reverse index** — already implemented
  (`endpoint_index`, `engine.rs:103-118`; backlog item
  `DataplanePerfBacklog_2026-06-12.md` §P4). This plan is the *receiver-index*
  sibling the audit says is "adjacent to P4, not covered by it". Distinctness:
  P4's index keys on `SocketAddr` with a lowest-`NodeId` tie-break for duplicate
  endpoints; this map keys on the locally allocated `u32` session index, which is
  unique by construction and needs no tie-break. They share only the maintenance
  *sites* (`configure_peer`/`remove_peer`) and the split-borrow lookup pattern
  (§7.4); no shared data structure is proposed.
- Any change to `NodeId`'s representation (`Arc<str>` interning) — rejected for this
  scope (§3.1); revisitable only if a future finding shows a remaining clone at a
  path a field borrow cannot reach.
