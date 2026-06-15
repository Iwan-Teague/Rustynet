# Dataplane Performance Backlog

- Date: 2026-06-12
- Status: active (remaining items from the dataplane hot-path performance pass)
- Owner: Rustynet
- Context: the 2026-06-11/12 perf pass mapped every per-packet allocation, copy, lock, and syscall on the two Rust packet paths — the userspace-shared boringtun pump (`crates/rustynet-backend-wireguard/src/userspace_shared{,_macos}/`) and the relay forwarder (`crates/rustynet-relay`) — and landed the high-impact items. This ledger tracks what remains, with the measurement harnesses to use and the invariants any implementation must not move. `phase10.rs` / `dataplane.rs` are control-plane only; packets never transit them — do not "optimize" or benchmark there.

## 1) Landed (for reference)

| Commit | Change | Measured |
|---|---|---|
| `6045ba7` | Engine scratch-buffer reuse (3× 64KiB zeroed Vec/frame removed); redundant per-result handshake observation dropped | encrypt 3.19→2.22 µs (−31%); forward round-trip 7.01→4.43 µs (−37%) |
| `611dc29` | Worker zero-timeout when a poll pass consumes its full 64-frame budget (lifts ~6.4k pps/direction ceiling + up-to-10ms idle latency); `local_addr` cached at bind (−2 getsockname/frame); socket/TUN recv into long-lived scratch + engine `&[u8]` ingest (−2× 64KiB allocs/frame). Both platforms. | loop-level (validated by budget-pin tests; engine bench unchanged) |
| `71255b5` | Relay zero-copy forward (`RelayForwardTarget` carries no payload; daemon sends `&buf[..len]`); paired-session-id cache (−2 String allocs + owned-key probe/frame); per-tick socket-probe RwLock+getsockname removed; `set_rate_limits` operator tuning | `relay_forward_packet_1400b` ≈ 187 ns/frame |

Benches: `cargo bench -p rustynet-backend-wireguard --features test-harness` (engine encrypt + forward round-trip) and `cargo bench -p rustynet-relay` (relay forward). criterion is a flagged dev-only dependency (`default-features = false`). Capture before/after for every backlog item below.

## 1.5) Three-dimension baseline (2026-06-12, Apple Silicon dev host)

Measured with the `perfprobe_*` fixed-work example binaries (release build)
under `/usr/bin/time -l`; allocations counted by the dev-only
`third_party/rustynet-alloc-meter` counting global allocator (internal crate,
no external code — flagged; needed because `GlobalAlloc` requires `unsafe`,
which first-party crates forbid). Reproduce with:

```sh
cargo build --release -p rustynet-backend-wireguard --features test-harness --example perfprobe_engine
cargo build --release -p rustynet-relay --example perfprobe_relay
/usr/bin/time -l target/release/examples/perfprobe_engine
/usr/bin/time -l target/release/examples/perfprobe_relay
```

| Probe | SPEED (wall/op) | MEMORY (allocs/op · bytes/op · peak RSS) | HARDWARE (instr/op · cycles/op · user CPU/op · sys) |
|---|---|---|---|
| engine forward (encrypt+decrypt, 1400B, 200k ops) | 4,890 ns | 8.00 · 3,204 B · 2.0 MB | ≈76,200 · ≈21,000 · ≈4.7 µs · 0.01 s total |
| relay forward (1400B, 2M ops) | 156 ns | 1.00 · ≈1 B · 1.8 MB | ≈2,886 · ≈661 · ≈157 ns · 0.00 s total |

Syscalls: zero on both probed paths by construction (pure in-memory seams);
the per-frame syscall counts for the full loops are code-verified in the
hot-path map (Linux verification path: `strace -c` around the live-lab run).
Criterion SPEED cross-check: `engine_forward_one_1400b` 4.43 µs,
`engine_encrypt_outbound_1400b` 2.22 µs, `relay_forward_packet_1400b` 187 ns.

Baseline observations feeding §2: the engine's 8 allocs/op are the P1
outcome-sink copies (now quantified); the relay's single remaining alloc/op
is the rate limiter's `node_id.to_owned()` `entry()` key — see the
opportunity list.

## 2) Remaining items (ordered)

### P1 — Engine outcome sink (remove the last per-frame copy in each direction)
- **What:** `handle_single_tunn_result` still copies the boringtun result slice into `EngineProcessingOutcome` (`packet.to_vec()` at the `WriteToNetwork` and `WriteToTunnelV4/V6` arms in `crates/rustynet-backend-wireguard/src/userspace_shared/engine.rs`), plus the outcome's two `Vec`s allocate per frame, only for `apply_engine_processing_outcome` (`userspace_shared/runtime.rs`) to send/write and drop them.
- **Fix:** pass a sink (trait or closure pair) into `drive_inbound_result`/`drive_outbound_result` that sends `WriteToNetwork` results via `AuthoritativeSocket::send_to` and writes `WriteToTunnelV4/V6` results to `TunDevice::send_packet` immediately, borrowing the result slice. Keep `authenticated_handshake` as the return value.
- **Expected:** −1 alloc + −1 full-frame copy per direction per frame; removes the outcome Vec allocations.
- **Risks/must-hold:** emission ORDER must be byte-identical (multi-result outcomes: all ciphertext sends then plaintext writes per outcome today; handshake-completion-with-queued-packets is the tricky case); a `send_to` error must keep today's early-abort semantics; `cfg(test)` egress recording (`runtime.rs` `recorded_peer_ciphertext_egress`) must record the same frames; mirror into `userspace_shared_macos/runtime.rs`.
- **Measure:** `engine_forward_one_1400b` (expect a further drop from 4.43 µs).

### P2 — Relay await-based recv (kill the 100µs poll + per-frame global lock)
- **What:** the per-port forward task in `crates/rustynet-relay/src/main.rs` (`spawn_forward_task`) polls `try_recv_from` and sleeps 100µs per idle tick, and takes the global `transport.write().await` for EVERY frame (serialising all ports through one lock).
- **Fix (two steps):** (a) replace the poll+sleep with `socket.recv_from(&mut buf).await` on the owned socket per task (needs a socket handle owned by the task or `Arc<UdpSocket>` — restructure `allocated_sockets` so removal aborts the task instead of the task discovering removal via map lookup); (b) shrink the transport lock: the keepalive `touch` and `forward_packet` are short, but a sharded/per-session structure or `parking_lot`-style fast path would stop one busy port stalling all others.
- **Expected:** removes ≤100µs added latency per frame at low rate, the idle wakeups, and cross-port lock contention under load.
- **Risks/must-hold:** task shutdown semantics (today the loop exits when the socket leaves the map — an awaited recv never observes that; needs explicit abort/cancellation on deallocation); `prune_inactive_allocated_sockets` ct_eq retention; keepalive classification (`len == 5 && buf[0] == RELAY_KEEPALIVE_MSG_TYPE`) and the silent-drop semantics must be unchanged. This is the one item that changes loop semantics — its own reviewed change with explicit shutdown tests.
- **Measure:** end-to-end relay RTT in the live lab (the criterion bench does not cover the loop).

### P3 — macOS utun framing via readv/writev (remove one full-packet copy per direction)
- **What:** `third_party/rustynet-tun/src/lib.rs` macOS path allocates a framed buffer and copies the whole packet to add/strip the 4-byte utun AF header on every send/recv.
- **Fix:** `libc::readv`/`writev` with an iovec pair `[4-byte header][payload]` — same syscall count, zero extra copies.
- **Expected:** −1 alloc + −1 full-packet copy per direction per packet on the mission-canonical macOS backend.
- **Risks/must-hold:** requires `unsafe`/libc in a `third_party` crate (workspace forbids unsafe in first-party code — confirm the crate's lint posture and FLAG before implementing); `packet_address_family` validation must still run before send and reject non-IP frames identically; short-read/short-write accounting (the `saturating_sub(UTUN_HEADER_LEN)` return contract) must stay equivalent.
- **Measure:** macOS live-lab throughput; no unit bench covers this layer.

### P4 — Endpoint→peer index for inbound dispatch (only matters at >10 peers)
- **What:** `find_node_id_by_endpoint` / `select_peer_for_destination` (`userspace_shared/engine.rs`) linearly scan `peer_states` and clone the matched `NodeId` per packet.
- **Fix:** maintain a `BTreeMap<SocketAddr, NodeId>` reverse index updated in `configure_peer`/`update_peer_endpoint`/`remove_peer`; return borrows via split-borrow.
- **Expected:** O(peers)→O(log n) + clone removal; negligible at the 2–3 peer home-mesh scale, real at >10.
- **Risks/must-hold:** CRITICAL edge case — duplicate endpoints across peers resolve to the LOWEST NodeId today (BTreeMap iteration order); the reverse map must reproduce that tie-break exactly, including on removal; `has_endpoint` (feeds the `reject_round_trip_target` fail-closed check) must give identical answers.
- **Measure:** engine bench with N=64 configured peers (add a parameterised bench case).

## 3) Invariant pins (apply to every item above)

- Unknown-source ciphertext silently dropped (`engine.rs` `find_node_id_by_endpoint` miss → empty outcome): matching semantics byte-identical, including the lowest-NodeId duplicate-endpoint tie-break.
- Cryptokey-routing drops are matched on LITERAL error strings (`should_drop_tun_plaintext_packet_error`, both runtimes) — changing either side turns a per-packet drop into worker death.
- boringtun anti-replay (`Session.receiving_key_counter` Mutex) and the `Some(remote_addr.ip())` decapsulate argument must never be bypassed or reordered.
- Per-tick budgets `MAX_*_PER_TICK = 64` and the commands-first worker loop are the DoS fairness bound — the idle sleep may be skipped (already is, on backlog), the budgets may not grow.
- Relay: source-tuple binding before rate limiting before pair resolution; nonce persisted to the replay store BEFORE session creation; rejects stay single generic message; ct_eq comparisons stay constant-time.
- Worker-death recovery is string-matched (`is_runtime_worker_unavailable`) — error text feeding worker exit paths must not change.

## 4) Cross-references

- Memory of the full cost map: workflow output `wf_c6c3af6e` (session artifact) — per-cost file:line classification both paths.
- [`RustynetDataplaneExecutionPlan_2026-05-18.md`](./RustynetDataplaneExecutionPlan_2026-05-18.md) — dataplane track this serves.
- `documents/SecurityMinimumBar.md` §5 — performance minimum bar.
