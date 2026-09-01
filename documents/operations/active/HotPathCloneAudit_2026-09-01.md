# Hot-Path Clone Audit — 2026-09-01

Docs-only audit. Scope: avoidable `.clone()` / `to_vec()` / `to_owned()` allocations on
**per-packet, per-frame, or per-tick production hot paths** in `crates/rustynetd/src/`,
`crates/rustynet-relay/src/`, `crates/rustynet-backend-wireguard/src/`, and (read-only)
`third_party/boringtun`. Cold paths (setup, config, CLI, handshake-rate control traffic)
are explicitly out of scope: a once-per-run clone is noise, not a finding.

Ground picked up from `RepoCodeWorkHunt_2026-09-01.md`, which listed the hot-path
`.clone()` sweep as un-sampled. Method: every candidate site was opened and read in
context before judging; cheap `Copy`/`Arc` clones are not findings; `#[cfg(test)]` sites
are excluded. Everything already tracked in `DataplanePerfBacklog_2026-06-12.md`,
`FullTodoInventory_2026-07-28.md`, or the efficiency catalog is recorded below as a
dedup line, not re-reported.

## Headline

**The relay forward path and the daemon tick are clean. The userspace engine has one
genuine untracked per-packet allocation (inbound demux), and vendored boringtun has one
known-shaped pre-session queue copy. Two new findings total (P2 + vendored P2) and one
P3; everything else inspected is either tight, test-only, or already tracked.**

## New findings

### P2 — Inbound demux does a linear scan + heap-clone `NodeId` per datagram

- File: `crates/rustynet-backend-wireguard/src/userspace_shared/engine.rs`
  (`find_node_id_by_receiver_index`, ~lines 1918–1935)
- Hot path: **per inbound datagram** (`Packet::Data`, `HandshakeResponse`, `CookieReply`
  all pass through receiver-index demux).
- Code (verbatim):

  ```rust
  self.peer_states
      .iter()
      .find(|(_, ps)| ps.tunnel_index == tunnel_index)
      .map(|(node_id, _)| node_id.clone())
  ```

- Cost class: per-packet O(n) scan plus a heap allocation — `NodeId` is a newtype over
  `String` (`crates/rustynet-backend-api/src/lib.rs:9`, `pub struct NodeId(String)`), so
  every inbound packet pays a string duplicate even when the scan is short.
- Status: **known-but-untracked.** A caller comment acknowledges the scan is "out of
  scope for this change (P4 only replaces the endpoint-keyed lookup)" — the backlog's
  P4 covers the *endpoint→peer* reverse index only; the *receiver-index→peer* path has
  no tracked item. Adjacent to P4, not covered by it.
- Concrete fix: maintain a `HashMap<u32, NodeId>` (tunnel_index → peer) inverse index
  alongside `peer_states`, updated where `tunnel_index` is assigned/rotated (rekey
  churn), so demux is a single hash lookup returning a clone-free borrow where the
  call site allows it.
- Adversarial review needed: **yes** — this is an inbound demux change affecting trust
  binding (which peer a ciphertext datagram is attributed to). Index staleness across
  rekey must fail closed (unknown index → drop), and the index must never outlive the
  authoritative `peer_states` entry.

### P2 (vendored — report only, do not edit) — Pre-session `queue_packet` copies every outbound packet

- File: `third_party/boringtun/src/noise/mod.rs` (`queue_packet`, line 524; call at line 265)
- Hot path: **per outbound packet while no session is established** (handshake window,
  rekey gap): `Tunn::send` falls through to `self.queue_packet(src)` →
  `self.packet_queue.push_back(packet.to_vec())` (line 527), `VecDeque<Vec<u8>>`.
- Cost class: per-packet `Vec` allocation, bounded by `MAX_QUEUE_DEPTH`
  (`requeue_packet` drops the oldest when full on the error path).
- Status: untracked anywhere; vendored code is read-only for this audit, so this is
  recorded as an upstream-shaped issue only. Fix (if ever taken upstream): hand the
  queue a reusable slot/`BytesMut` or store `&[u8]` slices against the caller's buffer
  lifetime. Not actionable in this repo without a vendoring decision; no review
  required since nothing is changed.

### P3 — Fair-drain backpressure path heap-clones the flow key per stashed/served packet

- File: `crates/rustynet-backend-wireguard/src/userspace_shared/fair_drain.rs`
  (`stash` line 202, `next_to_process` line 233)
- Hot path: **per stashed packet under output backpressure** (`entry(key.clone())`)
  and per served packet in the DRR loop (`self.active.front()?.clone()`).
- Code (verbatim):

  ```rust
  let flow = self.flows.entry(key.clone()).or_default();
  ```

  ```rust
  let key = self.active.front()?.clone();
  ```

- Cost class: per-packet-under-congestion. `FlowKey` is
  `enum FlowKey { Peer(NodeId), Unclassified }` and `NodeId(String)` is a heap string,
  so each stash/serve step duplicates a node-id string. Steady-state (no backlog) this
  path does not run, hence P3 rather than P2.
- Concrete fix: make `FlowKey` cheap to clone — intern the peer as a small slot id
  (`u32`) resolved once at flow creation, or hold `Arc<str>` instead of `String` inside
  `NodeId` for key positions. Either keeps allocation off the congestion path.
- Adversarial review needed: **no** — allocation-shape change only; DRR ordering,
  caps, and drop semantics are untouched.

## Already tracked (dedup — do not re-report)

- P1 outcome-sink `packet.to_vec()` at the `WriteToNetwork` / `WriteToTunnelV4/V6`
  arms + outcome `Vec` allocs — `DataplanePerfBacklog_2026-06-12.md` P1.
- P4 endpoint→peer reverse index (`find_node_id_by_endpoint`) — backlog P4. The
  receiver-index finding above is the *other* half of demux and is NOT this item.
- Relay rate limiter per-frame `node_id.to_owned()` entry key — backlog §1.5 / catalog
  RLY-1; verified still present at `crates/rustynet-relay/src/rate_limit.rs:31-47` with
  an in-code warning comment declaring the current form best-available (do not
  "simplify" it back) — tracked and documented, left alone here.
- Relay `NonceStore::insert` whole-map clone per accepted hello — `FullTodoInventory`
  (handshake-rate, not per-frame).
- Deferred §1.6 items #7 (runtime-fingerprint memoize) and #9 (gossip candidate-build
  gate, `candidates.clone()` at `gossip_runtime.rs:1928`) — backlog, still open.
- macOS utun readv/writev (`third_party/rustynet-tun`) — backlog P3.
- Efficiency-catalog items (ICE serial gather, dual STUN impls, single-thread reactor,
  unconditional reload per tick) — `FullTodoInventory` / catalog.

## Cleared with evidence (do not re-read next audit)

- **Relay per-frame forward path** (`crates/rustynet-relay/src/transport.rs`
  `forward_packet` 626–745 + `main.rs` `spawn_forward_task` 1104–1201): zero-copy
  forward, `RelayForwardTarget` carries no payload, owned-socket `recv_from().await`
  per port, keepalive short-circuit, cached paired-session fast path with `&str`
  compare. The owned-key fallback clones fire only on first-packet-after-pairing —
  amortized per session, not per frame. Error-class prune (RLY-02) in place.
- **`rate_limit.rs` `check_packet`**: takes `&str`; the tracked entry-key clone is the
  only alloc and is deliberately documented (see dedup).
- **`engine.rs:757` `path_quality.entry(node_id.clone())`**: doc comment states it runs
  at the daemon's poll cadence via a runtime request — never per-packet/per-tick.
- **`engine.rs` `select_peer_for_destination`** (longest-prefix scan + `NodeId` clone):
  sole production caller chain is `inject_plaintext_packet` (line 684), which is
  `#[cfg_attr(not(test), allow(dead_code))]` — test-only. Not a production hot path.
- **`engine.rs` `#[cfg(test)]` ingress recording** (`payload.to_vec()` into
  `recorded_peer_ciphertext_ingress`): compiled out of production.
- **`runtime.rs`**: lines 754/798 payload recording are both `#[cfg(test)]`; line 442
  `worker_gone_error` clone is an error path (worker already gone); 596–597 /
  1554 are configure/setup; 136–140 are test-thread setup.
- **`stun_client.rs`**: line 143 clones a message on the `SocketConfig` error branch;
  line 1875 is a test. Gathering path alloc-free.
- **`gossip_runtime.rs`**: clones are per-gossip-round builders (496/500/642/702/708,
  917/952) and setup (303); gossip exchange is seconds-scale, not per-packet. The one
  hot-adjacent clone (1928 `candidates.clone()`) is tracked item #9 above.
- **`relay_client.rs`** (2609 lines, 43 clones): hello/establish (529–577, 1330),
  maintenance sweeps (669–740), and test fixtures (1698+) — no per-frame data-path
  clones; frame send is borrow-based.
- **`tun.rs` / `fair_drain.rs` steady state**: pooled buffers (`pool.take`) carry
  packets without per-packet copies; only the backpressure key clone above was found.
- **`boringtun` beyond `queue_packet`**: `handshake.rs:149` `data.to_owned()` is per
  handshake message (low rate); `device/mod.rs`, `drop_privileges`, `peer.rs` are
  setup; `tun_linux.rs:112` is a trivial `name.clone()`.
- **`relay/session.rs`, `relay/keepalive.rs`, `socket.rs`**: zero production `.clone()`
  sites on hot paths (grep-verified, hits opened).

## Verdict

Two new trackable items: the **receiver-index demux** (P2, engine-owned, fix is a
mirror of the already-planned P4 inverse-index pattern) and the **vendored
`queue_packet` copy** (report-only). The fair-drain key clone is a small P3. No
production code was modified by this audit; the relay forward path — the highest-rate
path in the system — is confirmed tight.
