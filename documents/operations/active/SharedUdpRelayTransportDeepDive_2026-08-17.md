# Shared UDP / Relay Transport Deep Dive — 2026-08-17

Status: design and source review only. No product code changed by this investigation.

This dated standalone document consolidates today's shared UDP transport lifecycle and relay-recovery
work: source findings, external-practice research, implementation contracts, adversarial corrections,
and required acceptance tests. The hardening ledger remains historical context; this is the
implementation reference for this slice.

## Scope

D3 requires peer ciphertext, STUN, relay bootstrap, and relay maintenance to use one backend-owned
authoritative UDP socket. Review covered worker-loss rollover, STUN candidate validity, relay hello
ambiguity, stale ACKs, token consumption, relay restart/liveness, wire evolution, rollout, and
Linux/macOS parity.

Not in scope: product implementation, live fault injection, changing normal keepalive timings, or
P3 multi-caller queue work.

## How to use this report

Every recommended change below is a **proposal**, not an approved implementation. Source evidence
establishes current behavior and risk; it does not prove a proposed API, wire format, timer, or
rollout is optimal. A later reviewer/implementer must challenge alternatives, validate assumptions
against current code, and satisfy the listed gate before changing production behavior.

Terminology:

- **Observed** — source-backed current behavior or limitation.
- **Proposal** — recommended direction; may change after design review.
- **Explore** — unresolved choice or threat model requiring another focused review.
- **Gate** — test, migration, or live-lab evidence required before merge/enablement.

No claim here authorizes transparent retry, protocol downgrade, new fault-control surface, or live
network experiment. Preserve fail-closed behavior if any proposal cannot meet its gate.

## Issue → proposed improvement → further exploration register

| Issue / observation | Proposal | Explore before implementation | Gate |
| --- | --- | --- | --- |
| One D3 UDP owner is correct but rollover is hidden | Expose process-local incarnation and explicit lifecycle state | API compatibility for command/Windows backends; status consumers | Linux/macOS same-port rollover, coherent one-snapshot status |
| Generic recovery replays relay hello | Failure latch + daemon-only recovery; return `WorkerUnavailable` / indeterminate | Whether a smaller error taxonomy can retain all causal detail | Held-ACK + worker-death test; no duplicate hello |
| Path query can hide rollover | Latch every runtime-dispatch call; coordinator runs before later traversal I/O | Complete audit of controller/daemon call sites | Query-fault test: no I0 keepalive/candidate publication |
| I0 relay endpoint is replayed into I1 | Split immutable validated baseline from traversal endpoint overlay | Exact Phase10/backend API split; safe disabled posture where no direct endpoint exists | I1 timer/handshake never targets stale allocated relay port |
| Peer activation/switch can precede correct endpoint policy | Common staged activation transaction for initial apply, endpoint change, recovery | Pre-authorisation/rollback semantics per OS; interaction with worker-loss latch | New endpoint never egresses before its bypass/PF policy; failure never leaves divergent backend/system state |
| Recovery bypasses endpoint-route/attestation path | Whole-runtime quiesced recovery barrier before route/exit-policy attest | QH-48/QH-46 ordering, full-tunnel behavior, failure rollback | No I1 peer/relay/STUN ingress-processing or egress before attest; route failure remains quiesced |
| Send success is mistaken for relay liveness | Track local send, probe reachability, authenticated peer reachability separately | Exact semantic handshake capture and relay-control-authentication design | Relay restart + spoofed ACK cannot promote peer reachability/control confirmation |
| Handshake timestamp is cached, approximate telemetry | Semantic session-established event with monotonic overlay/session-bound epoch | Wrapper predicate vs upstream BoringTun event; all result variants | Cookie/data/error/old-port traffic never refreshes attested selected-path reachability |
| Generic round trip cannot touch peer endpoint | Narrow typed V2 mux with full expected-ACK comparison | API shape that remains backend-owned and cannot become arbitrary interception callback | Interleaved ciphertext/wrong ACK reaches WireGuard engine |
| V2 probe could first-bind a session tuple | Probe accepts only already-bound exact tuple | Separate security design for existing ciphertext first-bind rule | Attacker probe race cannot bind allocation |
| Hello ACK has no request correlation | V2 ACK echoes token nonce | Whether signed relay ACK is worth a later protocol version | Delayed ACK N cannot complete attempt N+1 |
| Probe ACK is forgeable after nonce observation | Label it unauthenticated reachability only | Authenticated relay-control response options; threat model for on-path actors | Only current-overlay endpoint-bound I1 handshake promotes selected-path peer reachability |
| Relay has no signing identity for control ACKs | Defer control-session confirmation; retain separate evidence labels | Dedicated key distribution/rotation/cost design, if product needs claim | No policy treats unsigned ACK or peer handshake as relay-control proof |
| One runtime round-trip slot | Incarnation-scoped scheduler/permit; typed pre-admission `Busy` | Permit lifetime/cancel/recovery semantics; scheduling priorities under load | Busy sends nothing, deletes no token, counts no miss |
| Desired replay can fail mid-recovery | Revisioned convergent baseline reconciliation | Durable vs memory-only desired revision persistence | Kill worker after Nth replay; later recovery converges |
| Pre-issued token inventory is advisory | Claim token only after admission permit; report inventory | Durable reservation/lease only if operations truly needs guarantee | Busy/fault paths do not reuse/delete wrong artifact |
| Fleet v1 is strict | Separate signed capability + explicit signed protocol policy | Whether time-bounded legacy compatibility is permitted by requirements | Watermark replay/rollback + strict/legacy old/new matrix |
| V2 requires shared backend mux | Gate V2 on Ready transport + backend mux capability | In-memory/test semantics and Windows/command compatibility | No `0x11`/`0x13` from unsupported backend |
| Hello/token parser permits trailing bytes | Exact full-frame parser consumption for v1 and v2 | Canonical extension strategy if protocol later needs fields | Corpus rejects trailing/duplicate/unknown input |
| Normal timer values are environment-dependent | Immediate rate-limited recovery only; defer normal interval change | `--node` NAT coverage, packet/battery cost, operator policy | Lab evidence; separate policy review |
| P3 queue pressure is not current incident | Defer; later bounded admission + priority shutdown lane | Actual concurrent caller model and benchmark sizing | Flood/fairness/shutdown tests before enabling |

For every accepted row, implementation PR must link: source evidence, explicit decision record,
changed invariants, deterministic tests, compatibility migration, and any required `--node` proof.

## Confirmed architecture

The userspace runtime owns one `AuthoritativeSocket`. Peer WireGuard ciphertext, STUN
request/response, relay hello, and relay maintenance use it. Production `RelayClient` has no
private UDP fallback; daemon supplies backend round-trip/send closures. Command-only backends are
blocked rather than pretending a second same-port socket is authoritative.

Each authoritative socket has process-local `transport_generation`. A recovered runtime can bind
same local IP/port with a different generation. Generic late round-trip responses are constrained
by remote address plus current generation. This is good internal isolation, but generation is not
currently visible through backend identity, daemon status, or netcheck.

Generic authoritative round trip rejects configured peer endpoint. Keep this rule: generic response
delivery runs before WireGuard ciphertext demux, so relaxing it can consume peer traffic.

Primary source areas:

- `crates/rustynet-backend-api/src/lib.rs`
- `crates/rustynet-backend-wireguard/src/userspace_shared/{socket,runtime,mod,engine}.rs`
- `crates/rustynet-backend-wireguard/src/userspace_shared_macos/`
- `crates/rustynetd/src/{daemon,phase10,relay_client}.rs`
- `crates/rustynet-relay/src/{transport,main}.rs`
- `crates/rustynet-control/src/lib.rs`

## Findings

### P0 — generic worker recovery cannot retry relay protocol I/O

`with_runtime_recovery` recreates runtime then reruns arbitrary closure. It wraps authoritative
round trips/sends and non-authoritative query paths on Linux/macOS.

Relay hello is non-idempotent. Client consumes a one-use token artifact, sends hello, then waits.
Relay records nonce before allocating session. Worker death after send plus lost ACK means:

1. Relay may have accepted/allocated session.
2. Client outcome is indeterminate.
3. Same-token retry is rejected as replay.
4. Fresh-token retry creates another externally visible attempt without proving first outcome.

Therefore: never transparently retry relay hello, registration, allocation, probe, keepalive, or
WireGuard handshake send. Return typed worker-loss/indeterminate outcome, quarantine state, recover
once, then schedule fresh high-level operation only where explicitly safe.

`userspace_shared/runtime.rs:695-745` sends before waiter installation. The post-send/pre-reply
window is real; missing ACK does not prove request failed.

### P0 — every recovery source must reach one coordinator first

Daemon path-quality polling runs before relay maintenance. Current non-authoritative calls also
hide recovery. A query can recreate socket, reuse port, and leave old relay/STUN state live before
later keepalive.

No backend operation may recreate runtime implicitly. A daemon-owned coordinator must quarantine
traversal state before explicit recovery. Backend failure latch makes missed future call sites fail
closed.

### P0 — local UDP send does not prove live relay allocation

Current relay keepalive is 5-byte fire-and-forget; client updates `last_activity` after local send
success, while relay sends no ACK. Sessions/allocated sockets are process memory but nonce store may
survive restart. Relay can restart, client can remain I0, local send can succeed, and stale session
can look active until token refresh.

Relay needs bounded reachability evidence plus endpoint-bound authenticated handshake evidence for
selected-path peer reachability; a separate authenticated control design is needed for relay-session
ownership. Local send is only a local send fact.

### P0 — allocated-port probe cannot use generic round trip

Allocated relay port is configured WireGuard peer endpoint. Generic round trip correctly rejects it.
If relaxed, waiter can intercept arbitrary peer datagrams before engine demux.

V2 liveness requires narrow backend-owned multiplexed control. It must not be generic exception or
caller-supplied response predicate.

### P0 — recovery must not replay I0 relay endpoint

Current backend `desired_peers` retains selected endpoint, while Phase10 `ManagedPeer` retains
relay endpoint and `path=Relay`. Relay selection writes allocated relay port through
`reconfigure_managed_peer`; ordinary recovery replay would therefore configure I1 with I0's dead or
unproven relay allocation before fresh registration. Worker timers or handshake sends could then
emit I1 traffic to the stale endpoint, defeating quarantine.

Split immutable validated baseline peer desired state from transient traversal endpoint overlay.
Baseline contains key, allowed IPs, keepalive, and only a separately validated stable direct endpoint
when one exists. Overlay contains dynamic direct/relay candidates, selected path, selected endpoint,
and authoritative incarnation. Before reconstruction coordinator must clear relay overlay and stage
baseline/direct endpoint in Phase10 and backend desired state **without runtime I/O**. Recovery
replays only baseline revision. Install relay endpoint only after fresh I1 registration; tag it I1.
If no safe baseline endpoint exists, require explicit disabled/quiesced backend posture; do not invent
placeholder endpoint.

#### Focus exploration: baseline vs traversal-overlay split

**Observed.** `recover_runtime_after_worker_exit` reconfigures every stored `desired_peers` value
before returning (`userspace_shared/mod.rs:239-249`). `PeerConfig.endpoint` is mandatory. Phase10
keeps `configured.endpoint`, `direct_endpoint`, `relay_endpoint`, and `path` together; a relay
transition writes selected endpoint into `configured` then calls backend update
(`phase10.rs:406-413,5992-6024,6378-6401`). That makes current desired state unsuitable as both
durable peer intent and disposable traversal selection.

**Proposal.** Make the separation explicit, rather than relying on callers to remember which
endpoint is transient:

```text
BaselinePeerDesiredState {
  peer_crypto_and_routes: PeerConfig minus transient endpoint,
  validated_baseline_direct_endpoint: Option<ValidatedEndpoint>,
  desired_revision,
}

TraversalEndpointOverlay {
  direct_candidates: Vec<EndpointCandidate { endpoint, trust_source, signed_bundle_fingerprint,
                                             expiry, candidate_revision }>,
  selected_direct_endpoint,
  relay_endpoint,
  selected_path,
  transport_incarnation,
  overlay_revision,
}
```

`PeerConfig` can remain internally required by constructing it only at runtime-apply time. A
validated baseline direct endpoint produces normal `PeerConfig`; no baseline endpoint produces a
formal quiesced peer transport mode that retains cryptographic configuration but suppresses
endpoint-driven timers/handshakes. Placeholder/loopback/relay endpoints are prohibited.

Add three deliberately distinct operations, names illustrative and subject to API review:

1. `stage_baseline_peer_revision(...)`: pure desired-state mutation; no worker or network I/O.
2. `apply_traversal_overlay(...)`: applies a selected direct or I<n> relay endpoint to healthy
   runtime, then records overlay as applied.
3. `quarantine_traversal_overlay_for_recovery(I0)`: pure mutation which removes I0 relay overlay,
   resets current path to validated-baseline-direct or quiesced, and invalidates route/attestation cache for
   refresh after I1 is ready.

Coordinator calls (3) while backend latch blocks runtime work, then calls explicit recovery.
Recovery builds runtime only from latest baseline revision; it does not know relay candidates. Fresh
I1 relay registration later calls (2). `Phase10Controller::reconfigure_managed_peer` cannot be
reused for (3): it queries/updates backend and therefore violates no-runtime-I/O quarantine.

**Critical correction — `ManagedPeer.direct_endpoint` is not baseline.** Current traversal code
mutates it whenever a supplied direct endpoint arrives, including while relay is selected
(`phase10.rs:5992-6022`, especially `:6004-6008`). It carries no source, expiry, signed-bundle
fingerprint, or overlay/session epoch. Therefore it is a dynamic candidate cache, not stable desired
state; recovery must never use it as a baseline merely because it is named `direct_endpoint`.

**Explore before choosing exact types.** Identify whether any endpoint meets immutable baseline
criteria after signature/freshness validation, whether that provenance must be durable, whether
quiesced mode must suppress backend-native persistent keepalive and route bypass, and how
attest/route refresh behaves while no endpoint is applied. Prefer a small explicit
`PeerTransportMode::Quiesced` over a magic endpoint. A second review must compare this model with
storing overlay solely in daemon and reconstructing Phase10 after recovery; choose the variant that
preserves route fail-closed behavior with least duplicated state. `UserspaceEngine::configure_peer`
constructs `Tunn` with configured persistent keepalive and runtime timer polling drives those
tunnels (`engine.rs:285-377`; `runtime.rs:830-855`), so quiesced cannot be represented as ordinary
`PeerConfig` with dummy endpoint.

**Additional ordering risk.** Normal Phase10 endpoint change calls backend update then
`refresh_peer_endpoint_routes_and_attest`, which rolls routes back, applies peer-endpoint bypass
routes, reapplies routes, and asserts exit policy (`phase10.rs:6378-6412`). Runtime recovery instead
starts worker and configures stored peers directly (`userspace_shared/mod.rs:220-249`), bypassing
that system transition. A newly configured peer with persistent keepalive can emit timer traffic
before bypass/attestation refresh completes.

**Proposal to explore.** Add a recovery barrier. Prefer applying/attesting staged baseline endpoint
routes while no worker exists, then construct/configure fresh runtime; this avoids a new paused-worker
API if route policy does not require fresh socket state. If that ordering is not valid, create fresh
runtime in a **whole-runtime quiesced** mode, apply/attest routes, configure baseline peers, then
release runtime traffic. Timer/explicit-handshake suppression alone is insufficient: UDP polling can
accept a WireGuard initiation and `process_inbound_ciphertext` can emit a response, while TUN polling
can call `inject_plaintext_packet` and emit ciphertext (`runtime.rs:865-905,923+`; `engine.rs:555-620`).
Until release, do not poll peer UDP/TUN engine paths and reject/defer all authoritative STUN/relay
control admission; configuration/reconciliation commands may run only if they cannot send. On system
route/attestation failure, do not create runtime or stop/retain it quiesced and report fail-closed
recovery failure. Relay/STUN work begins only after barrier success. This is a sequencing proposal,
not permission to change firewall/route ordering without QH-48/QH-46 invariants review.

**Gate.** Instrument operation order under full-tunnel and direct modes. Assert no peer ciphertext,
persistent keepalive, relay hello, or STUN leaves I1 before baseline bypass/exit-policy attest
succeeds. While paused, inject a WireGuard initiation and TUN plaintext: neither may call
`RuntimeIoSink::send_ciphertext`, decrypt/forward peer traffic, or establish a control wait. Inject
route-refresh failure and assert no egress plus visible quiesced state.

**Gate.** Fault with relay selected; assert pure quarantine changes no socket traffic, I1 recovery
configures only independently validated baseline or quiesced state, engine timers/handshakes never
use old allocated relay port or an un-revalidated dynamic direct candidate, and fresh relay selection
is I1-tagged. Repeat with absent baseline endpoint, expired/cross-bundle dynamic candidate, and
route/attestation refresh failure.

### P0 — endpoint transition currently refreshes policy from stale peer state

**Observed.** `Phase10Controller::reconfigure_managed_peer` builds an updated local `peer`, calls
`backend.update_peer_endpoint(node_id, endpoint)`, then calls
`refresh_peer_endpoint_routes_and_attest()`, which derives its peer list from the unchanged
`self.managed_peers`; only after that does it insert the updated peer
(`phase10.rs:6378-6412`). Thus the backend may use new endpoint **E1** while system bypass/PF
policy is calculated from old endpoint **E0**. On macOS, this is an exact `SocketAddr` PF egress
allow-list, so E1 can be dropped by fail-closed policy (`phase10.rs:3515-3534`). Linux/Windows
also derive endpoint bypass routes from supplied peer endpoints (`phase10.rs:2181-2210,4487-4510`).

This is not only an endpoint-change or recovery concern. Initial
`apply_generation_stages` configures every peer in live backend before it rolls back/applies endpoint
bypass and system routes (`phase10.rs:5509-5535`). Once the configure reply returns, worker polling
can drive timer, inbound-UDP response, or TUN-originated ciphertext paths. A recovery-only barrier
would leave initial apply with the same pre-policy egress window.

Direct roaming and relay selection call the same endpoint helper.
Several traversal paths make a second `reconfigure_managed_peer` call after the first update; that
does not repair policy because the second call sees backend already at E1 and returns after merely
storing state (`phase10.rs:5992-6022,6070-6160,6190-6250`). If route refresh/assertion fails,
backend endpoint has already changed and `rollback_routes` may have removed prior policy. Do not
use the current helper as recovery-barrier evidence.

**Proposal — candidate-state endpoint transaction.** Replace update-then-refresh with one explicit
operation, shared by initial apply, endpoint change, and recovery, that owns both a prospective
`ManagedPeer` snapshot and host policy transition. Exact API and order require review, but it must
meet these invariants:

1. Validate candidate endpoint/path and construct `next_managed_peers` before backend I/O.
2. Prepare endpoint bypass/PF policy from an explicit snapshot containing E1. During transition it
   may need a constrained union of E0 and E1 so existing authenticated traffic does not lose its
   bypass before backend commit; never permit an arbitrary caller-provided endpoint.
3. Apply/attest candidate system policy before allowing backend endpoint E1 to send. Then update
   backend endpoint and commit in-memory endpoint state as one logical generation.
4. Prune E0 only after backend confirms E1 and post-commit policy attests. If backend update is
   indeterminate/worker-loss, preserve enough restrictive policy to quarantine, latch recovery,
   and avoid a speculative runtime rollback send.
5. Any pre-commit policy error leaves backend E0 and state unchanged. Any later error exposes a
   typed quiesced/faulted outcome; never claim route policy or path commit succeeded.

This describes required properties, not a permission to pre-allow E1 or change firewall ordering.
E1 must already have passed signed/traversal validation. A reviewer must decide whether temporary
E0+E1 policy is acceptable under each OS's least-privilege model, or whether peer egress must be
paused during an atomic replacement. Initial apply, endpoint updates, and recovery need this common
transaction or a separately proven common paused mode; none may call existing configure/reconfigure
helpers unchanged.

**Gate.** Linux/macOS/Windows mock-system ordering tests assert: candidate E1 policy installation
and `assert_exit_policy` precede the first E1-capable backend send; policy input includes E1, not
only E0; route/PF prepare failure makes zero backend mutation; failure after backend dispatch
latches/quarantines rather than reports path success; cleanup only removes E0 after E1 is committed.
Add initial-apply, direct-roam, relay-selection, and recovery cases, including full-tunnel
PF/killswitch state. Mock operation order alone is insufficient: instrument worker
`RuntimeIoSink::send_ciphertext`/authoritative sends and show zero pre-commit engine/control egress.
A source-inspection regression should fail if `refresh_peer_endpoint_routes_and_attest` still reads a
map updated only after the backend endpoint mutation.

### P1 — hello ACK lacks attempt correlation

Current ACK is 19 bytes: type, session ID, allocated port. No token nonce/attempt ID. Delayed old
ACK from same relay address can satisfy later wait. Echoing fresh signed token nonce solves
correlation, not authentication. Retain source filtering; never claim nonce echo authenticates relay.

### P1 — socket incarnation, not address, is lifecycle boundary

IP/port/label equality is not continuity proof. Add opaque incarnation to identity/receipts/status.
`Known(u64)` is assigned on every socket creation, including initial start. Changed value following
explicit recovery is replacement. `Unobservable` is capability, not change event; repeated reads
must never create rollover storm.

### P1 — desired state needs pre-dispatch staging

Current userspace desired maps update after runtime reply. A convergent mutation can run then worker
die before reply, leaving no intent to restore. Validate pure input and stage desired intent before
dispatch. Retain it on worker loss; reconcile it to convergence during recovery. Recovery itself can
die after a mutation but before reply, so reconciliation is at-least-once across recovery attempts,
never globally exactly once. Track monotonic desired revision and per-runtime applied revision;
commit `Ready(I1)` only after every baseline item reaches latest desired revision. Roll back only
definite pre-admission/validation error. Never call ambiguous result success.

### P2 — pre-issued token scan is not reserve

Artifact validation/removal is actual claim. Directory count is advisory. Report matching inventory,
low watermark, earliest expiry per `(node, peer, relay)`. Do not reuse indeterminate token or fall
back to local signing. Guaranteed reserve needs a separate durable claim/lease/crash design.

### P2 — queue work deferred

Runtime command channel is unbounded and controls drain before timers/UDP/TUN. Production currently
has one mutable backend owner; command flood is not claimed as present incident. If sharing arrives,
add bounded admission, per-tick budget, priority shutdown/recovery lane, closing admission bit,
acknowledgements, fairness tests. Do not add caller timeouts before acknowledgement semantics.

## Research constraints

Tailscale documents same-socket STUN/tunnel use because different sockets can receive different NAT
mappings, with relay fallback necessary in difficult networks
([NAT traversal guide](https://tailscale.com/blog/how-nat-traversal-works)).

Cloudflare explains UDP tuple changes break tuple-only tracking; QUIC survives via separately
authenticated connection identifier. Rustynet relay is tuple-bound and has no equivalent migration
ID, so rollover must reset/re-register rather than invent continuity
([Cloudflare QUIC analysis](https://blog.cloudflare.com/the-road-to-quic/)).

RFC 4787 treats UDP mappings as session/tuple properties and permits port preservation or change
([RFC 4787](https://datatracker.ietf.org/doc/html/rfc4787)). Cloudflare reports arbitrary/short
timeouts; Tailscale currently re-STUNs roughly 20–26 seconds. Do not copy a universal timer:
recovery gets immediate rate-limited re-probe; normal interval needs `--node` measurements,
packet-budget and battery analysis.

Fortinet exposes UDP timers and session limits in CGNAT/firewall products
([session timers](https://docs.fortinet.com/document/fortigate/7.4.6/fortinet-carrier-grade-nat-field-reference-architecture-guide/863546/session-timers)).
Bound local port cannot prove NAT/relay liveness.

AWS idempotency needs server identity, parameters, and outcome atomically bound
([AWS idempotent APIs](https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/)).
Rustynet nonce store lacks durable session/allocation/ACK state, so nonce-only hello idempotency is
unsafe. STUN's transaction-ID echo is the safe correlation contrast
([RFC 8489](https://datatracker.ietf.org/doc/html/rfc8489)).

## Required backend contract

### Typed failure and lifecycle state

Add `BackendErrorKind::WorkerUnavailable` and `BackendErrorKind::Busy` plus constructors.
`WorkerUnavailable` means operation might be unstarted, sent, or applied but unacknowledged.
`Busy` means authoritative request was rejected before admission/send and may be deferred by its
specific scheduler. Retain causal OS/channel text for logs. No string matching. Generic `Internal`
remains non-retryable.

Every error that terminates worker must surface as `WorkerUnavailable` with cause:

- request/reply loss after worker exit;
- outstanding round trip failed by worker exit;
- authoritative socket poll error terminating worker;
- TUN poll error terminating worker; and
- timer error terminating worker.

Per-request send failure leaving worker alive, timeout, relay rejection, malformed packet, normal
local validation remain their own errors. Criterion is worker survival, not I/O origin.

Replace optional identity status with:

```text
AuthoritativeTransportState =
  Ready(AuthoritativeTransportIdentity)
| Faulted { prior_identity, since }
| Unsupported { blocker }
```

Do not map fault to `None`; `None` also means unsupported. State read is coordinator/backend
snapshot, available while latch blocks runtime dispatch.

Extend identity with:

```text
TransportIncarnation = Known(u64) | Unobservable
```

Incarnation is not credential, persistent identity, or wire value.

### Failure latch and explicit recovery

Add:

```text
TunnelBackend::recover_authoritative_transport(&mut self)
  -> Result<AuthoritativeTransportIdentity, BackendError>
```

Default fails closed/unsupported. Shared userspace backends implement it. It must:

- reject healthy/unlatched invocation (`AlreadyRunning` or explicit no-change receipt);
- reconstruct only fault-latched runtime;
- reconcile baseline desired revision to convergence; repeated recovery attempts may replay it;
- clear latch/commit Ready only after full current revision applies successfully;
- retain latch on recovery failure; and
- never transmit STUN/relay frames, invoke daemon callback, or replay original closure.

Replace `with_runtime_recovery` Linux/macOS with non-retrying dispatch helper. On worker loss, set
latch before return. While latched, every call dispatching runtime work returns typed worker error
without socket I/O or `ensure_runtime_control`.

`Phase10Controller` and `DaemonBackend` forward explicit recovery. `RelayClientError` must retain
typed `BackendError`, not flatten it to string before daemon can route it.

## Daemon coordinator

`DaemonRuntime` owns one private gate, e.g.
`handle_authoritative_transport_fault(operation, backend_error)`. It runs immediately whenever
`WorkerUnavailable` escapes any controller operation, including path-quality/status/handshake query.

Required serialized flow:

```text
0. Accept only WorkerUnavailable. Other errors use normal policy.
1. Capture prior transport state once; record operation, cause, time, metric.
2. Quarantine before recovery:
   - close local relay sessions;
   - clear relay keepalive/probe state;
   - suppress relay endpoint selection;
   - remove I0 STUN observations/candidates from publication;
   - clear Phase10 relay overlay, reset path to validated baseline or quiesced, and stage this in backend desired
     state without runtime I/O;
   - mark traversal transport_indeterminate;
   - send no old-session keepalive.
3. Complete recovery barrier: stage baseline endpoint state; apply/attest baseline routes before
   runtime creation, or hold new runtime peer egress paused until that succeeds. Failure leaves
   quiesced state with bounded retry/backoff/operator visibility.
4. Call explicit controller recovery once for this fault episode, using baseline state only.
   Validate candidate I1 differs from prior known identity; for Unobservable use explicit recovery
   event, never polling inference. I1 remains `Recovering`, not `Ready`, until barrier completes.
5. Verify latest baseline desired revision converged during this recovery attempt, release egress
   only after route/attestation barrier, then publish `Ready(I1)`.
   If worker dies during replay, retain desired revision and repeat on next recovery; never report
   original ambiguous operation successful. Do not replay transient I0 relay overlay.
6. Schedule traversal work independently:
   - fresh relay registration using fresh token;
   - fresh STUN transaction/observation;
   - no publication/selection until artifacts tagged I1.
7. Resolve original operation:
   - protocol send/round trip/handshake send: Indeterminate; never replay;
   - read query: unavailable for this tick; next poll uses I1;
   - staged convergent setter: result only after desired revision converges, not original closure.
```

Relay registration must not wait for STUN success. STUN produces candidate advertisements; relay is
fallback and starts when I1 is usable.

Status/metrics: prior/current incarnation, operation/cause, count/time, relay quiesce reason, stale
artifact count, STUN freshness, registration state, matching token inventory. Capture one status
snapshot per render.

## Relay v2 protocol

### Frames

Keep v1 immutable. Current ACK remains:

```text
0x02 | session_id[16] | allocated_port_be[2]
```

Reserve:

```text
0x11 RelayHelloV2    = canonical signed-token hello body, new type byte
0x12 RelayHelloAckV2 = type | session_id[16] | allocated_port_be[2] | token_nonce[16]  (35 B)
0x13 RelayProbeV2    = type | session_id[16] | probe_nonce[16]                         (33 B)
0x14 RelayProbeAckV2 = type | session_id[16] | probe_nonce[16]                         (33 B)
```

Client retains issued token nonce until ACK handling. Accept V2 ACK only from exact relay address,
with exact type/length, non-zero session/port, and exact pending nonce. V1 stays 19 bytes and
rejects V2 frames. Nonce echo is correlation only.

### Session and liveness evidence

Replace `RelayClientSession.last_activity` with:

```text
transport_incarnation
wire_version
state = Establishing | Active | Suspect | Quiesced
last_datagram_sent
last_probe_reachability
last_authenticated_selected_endpoint_peer_event
pending_probe { nonce, sent_at, deadline }?
```

Probe ACK is **unauthenticated reachability**, not relay-control confirmation or authenticated
selected-path peer reachability: an observer able to learn session/probe nonce can spoof valid-shaped
ACK. It may schedule another probe or defer immediate re-registration, but cannot promote a
trusted/available path, satisfy fail-closed policy, or reset an authentication freshness deadline.
An endpoint-bound I1 WireGuard session event can support only selected-path peer reachability;
capture source endpoint plus incarnation when engine establishes session. A peer handshake timestamp
without that endpoint binding is insufficient.

**Observed telemetry gap.** Current engine returns only `(NodeId, unix_timestamp)` after inbound
authentication, while runtime has `remote_addr` and `transport_generation` then discards both when
recording handshake telemetry (`engine.rs:528-565`; `runtime.rs:865-905`; `handshake.rs:15+`).
Current `peer_latest_handshake_unix` cannot prove selected relay endpoint or incarnation.

**Proposal.** Do not derive trusted evidence from `time_since_last_handshake` at all. Introduce an
internal, process-local semantic event/epoch, illustrative shape:

```text
AuthenticatedSessionEstablished {
  node_id,
  remote_addr,
  transport_incarnation,
  handshake_evidence_epoch, // monotonic, not wall-clock proof
  observed_at: Instant,
}
```

Current source supports a narrow predicate to investigate: pre-parse only a WireGuard
`HandshakeInit` or `HandshakeResponse`; call BoringTun; emit event only for the successful,
session-establishing result (currently `WriteToNetwork`). Vendored BoringTun stores a session then
returns `WriteToNetwork` for valid init and valid response; invalid handling is `TunnResult::Err`
(`third_party/boringtun/src/noise/mod.rs:320-369`). Do **not** use `not Err` alone. Current
`drive_inbound_result` returns a cached `authenticated_handshake_unix` after every decapsulation
path, including data/cookie/old session and its error path (`engine.rs:555-620,916-938`), so it is
not a fresh-handshake event. It can re-record a historical approximate Unix second without any new
session.

Backend event carries exact remote address/incarnation; daemon validates it against its own current
traversal overlay while serializing session replacement. It must bind promotion to selected relay
path, exact allocated endpoint, I1 incarnation, exact `relay_session_id`, `overlay_revision`, and
local `handshake_evidence_epoch`. Invalidate/advance overlay state before every relay-session
replacement, endpoint/path change, close, quarantine, and I1 recovery. Incarnation plus endpoint
alone is insufficient: an old event can otherwise be mistaken for a same-I session refresh or
allocated-port reuse. Keep engine demux behavior intact: receiver-index responses intentionally
route before endpoint match; a valid delayed old-port response may be processed by engine but must
never attest current relay overlay.

**Claim boundary.** An endpoint-bound WireGuard session event proves only
`AuthenticatedPeerReachableViaSelectedEndpoint`: the configured peer authenticated over that UDP
endpoint. It does **not** prove that a particular relay process owns/retains the current control
allocation: session ID is not authenticated inside WireGuard traffic, and current ProbeAck/hello
nonce echo are correlation/reachability, not relay authentication. Therefore do not call this event
`RelayTrustedLive`. Define `RelayControlSessionConfirmed` only after a separate authenticated
relay-control design exists (for example, relay identity-bound response reviewed under a future
protocol version). Any policy needing both properties must require both; current V2 can report data
plane reachability and unauthenticated probe reachability separately, never silently merge them.

Do not manufacture evidence from outbound initiation/timer work. Current
`drive_outbound_result`/`update_peer_timers` reads `time_since_last_handshake` after emitting a
keepalive/rekey, which can repeat a prior handshake timestamp without new peer authentication
(`engine.rs:396-475,916-938,1006-1014`).

**Explore/Gate.** This wrapper-level semantic predicate needs an implementation review against all
BoringTun result variants/version upgrades; an upstream explicit session-established event may be
clearer. Preserve privacy in status, use monotonic age rather than wall time for in-process liveness,
and never classify direct handshake as relay-session success. Inject successful init/response,
cookie, data, malformed packet, keepalive/rekey, and delayed response from old allocated port across
I0/I1 and same-I relay refresh. Only successful current-I1/current-session/current-overlay
exact-endpoint event may promote **authenticated selected-endpoint peer reachability**; all other
packets may retain normal engine handling but must not refresh it. Add forced same-I allocated-port
reuse/session replacement: prior evidence cannot promote new session.

Allow one pending probe/session, one synchronous probe/traversal tick, bounded deadline. Exact ACK
records unauthenticated reachability. Wrong source/length/session/nonce or timeout does not.
Bounded misses move `Active -> Suspect -> Quiesced` only under explicit policy; local send and probe
ACK alone cannot assert authenticated peer reachability or relay-control confirmation. Local send
updates only `last_datagram_sent`.

#### Deferred design: authenticated relay-control session confirmation

**Observed.** Current relay configuration contains a control-plane **verifier** public key and no
relay signing/identity key (`rustynet-relay/src/main.rs:140-180,423-448`). The relay uses that key to
admit signed client tokens, then emits an unsigned hello ACK containing session ID and allocated port
(`main.rs:680-720`). Current V2 nonce echo would improve attempt correlation only; it cannot prove
relay identity or session ownership. Giving relay the control-plane signing key is prohibited: it
would blur a verifier-only forwarding service into a control-plane authority.

**Proposal status: defer; not a V2 prerequisite unless product policy explicitly needs this claim.**
The safe immediate vocabulary is: `LocalSend`, `UnauthenticatedProbeReachability`, and
`AuthenticatedPeerReachableViaSelectedEndpoint`. Do not synthesize a fourth "confirmed relay" state
from these. Existing peer reachability may be sufficient to decide whether ciphertext is flowing;
control-session ownership is a stronger distinct property.

If a future requirement truly needs `RelayControlSessionConfirmed`, first create a dedicated design
review covering identity provisioning, rotation/revocation, endpoint binding, key custody, DoS cost,
and old-client policy. One candidate is a **new, separately versioned** relay identity public key
bound to relay ID/endpoint in signed fleet/capability state, with a relay signature over a canonical
fresh control transcript. That is only a candidate: per-probe signature cost and key distribution may
make it unsuitable. Do not derive an HMAC/MAC from token nonce/session ID: these travel in plaintext
and do not establish a relay-held secret. Do not add an unreviewed custom crypto construction or
smuggle a TLS/QUIC side channel around D3 ownership.

**Gate before any future implementation.** Require a threat model plus signed-key anti-rollback/
rotation tests; exact canonical transcript and domain-separation tests; replay across session,
endpoint, relay ID, incarnation, and probe nonce; invalid/old key and restart behavior; rate/CPU
limits; and strict/legacy client matrix. Until then no policy may use control-session confirmation as
an availability proof, and V2's unsigned ProbeAck stays explicitly unauthenticated.

### Narrow allocated-port control multiplexer

Probe must target allocated port, not control port: endpoint-dependent NAT can map same local socket
differently per destination, so control-port success does not prove allocated-port liveness.

Add typed backend request:

```text
AuthoritativeControlKind::RelayLivenessV2 {
  target,
  probe: exact 33-byte 0x13 frame,
  expected_ack: exact 33-byte 0x14 | session_id | probe_nonce
}
```

Only this kind can target configured peer endpoint. Generic round-trip endpoint rejection remains.
Runtime completes probe only if:

- remote equals target;
- socket generation equals request generation;
- length is exactly 33;
- discriminator is `0x14`; and
- full payload equals expected ACK.

All nonmatches, including ciphertext and wrong/malformed `0x14`, continue to
`engine.process_inbound_ciphertext`. Do not expose arbitrary callback/prefix matcher.

Allocated-port task handles `0x13` only for live/unexpired **already-bound exact source tuple**.
Probe must never establish first binding. Unbound session remains `Establishing` and probe silently
drops until a separately authenticated binding mechanism exists. Existing relay first-ciphertext
same-IP binding (`transport.rs:635-647`) is a pre-existing residual threat that needs its own
security design; V2 probe must not expose a cheap new binding primitive to same-NAT/on-path/spoofed
source attackers. Unknown, expired, unbound, or unauthorized source silently drops. One request
yields at most one same-size ACK; no amplifier/error response.

Create typed pending control entry before `send_to` as one worker-thread transaction; on send
failure remove that exact entry before returning error. Current worker normally does not poll socket
between generic send and waiter installation, but new mux must preserve this atomicity under future
refactor. Test an immediate exact ACK, send failure cleanup, timeout cleanup, and a later matching
frame reaching engine rather than stale waiter.

Relay restart removes session/allocation, so no ACK. Client must quiesce and re-register.

### One shared outstanding-round-trip slot

Runtime currently has one `round_trip_in_flight` atomic and one
`OutstandingRoundTripState` (`userspace_shared/runtime.rs:295-309,390-402,529`; macOS parity).
STUN, relay hello, and V2 probe must all consume this **same** slot. Do not add a parallel probe
waiter: two waiters on one socket would reintroduce ambiguous demux/ordering and race generic
response delivery.

Change current "another round trip is already in flight" `Internal` result to a typed pre-admission
`Busy` result. It means no request datagram was accepted for that operation; it is neither worker
failure nor liveness loss. Daemon scheduler defers the specific STUN/hello/probe job to a later tick
with bounded jitter/backoff. A Busy probe does not increment miss count, mark relay suspect, trigger
recovery, or consume token inventory.

Pre-issued relay registration needs an admission permit before token claim: reserve the sole
authoritative round-trip slot, issue/validate token only after permit succeeds, construct hello,
then submit through that permit. Permit is non-copyable and releases slot on all paths before send.
This avoids deleting an artifact merely because another STUN/relay operation owns slot. All daemon
uses of authoritative round trip must route through this scheduler; tests inject Busy immediately
before token issue and assert no artifact deletion/no UDP send. Current single mutable daemon owner
makes overlap uncommon, but runtime already protects this invariant and new protocol must preserve
it.

**Permit lifecycle is part of correctness, not ergonomics.** Current runtime reserves an atomic
slot before enqueuing (`runtime.rs:295-309,390-399`), and worker sends before waiter installation
(`:690-745`). Pre-issued issuer removes the artifact before transport (`relay_client.rs:169-228`).
The proposal therefore needs an explicit, incarnation-scoped ownership model, e.g.:

```text
RoundTripAdmissionPermit {
  runtime_instance_id, transport_incarnation, permit_id,
  acquired_at, deadline,
  phase: Held | TokenClaimed | Submitted | Resolved | Cancelled,
}
```

`Drop`/cancel may release only matching `(runtime_instance_id, permit_id)`, never a bare global
boolean; a late I0 permit release must not clear I1 admission. Bound holding time and reject an
expired unsubmitted permit so token-spool scan/validation cannot monopolize the sole slot. Submission
uses the already-owned permit, not a second acquire. No opaque queued request survives deadline,
cancel, or recovery.

Outcomes are deliberately asymmetric:

- `Busy` before claim: no artifact deletion, no this-job datagram, no liveness miss.
- cancellation/expiry before claim: same; release matching permit.
- worker loss after artifact claim but before known send: artifact remains permanently retired;
  report a non-successful indeterminate/consumed operation and never reuse it.
- worker loss after send or before ACK: protocol attempt indeterminate; same token never retries.
- recovery replacement invalidates all I0 permits; fresh I1 scheduling starts from state, not a
  destructor/queued I0 command.

This is a proposal. Review whether a durable reservation is justified; do not pretend deletion can
be reversed safely after an uncertain worker failure.

The runtime state must represent generic and V2 control waits as variants of one
`OutstandingRoundTripState`, not two optional fields. Daemon scheduler keeps no unbounded request
queue. It coalesces work and selects at most one blocking request per traversal turn, in this order:
fault-recovery relay registration, required V2 re-registration, due V2 liveness probe, then STUN.
Fresh relay registration still does not wait for STUN. Probe deadline is independently configured
and bounded; it must not reuse hello's ten-second session timeout by accident. A delayed/lost
queued job is rescheduled from state, not retained as an opaque runtime request after its deadline.

## Fleet rollout

Signed relay fleet is strict v1; unknown fields/other versions reject. Do not append optional v2
field or publish fleet-v2 in place: older daemons fail closed on sole traversal bundle.

Recommended zero-outage path: separate same-trust-root signed capabilities bundle. Canonical record
binds exact relay ID + endpoint to bounded sorted supported wire versions plus version/generated/
expiry/nonce/signature. This needs a separately signed protocol-policy decision; do **not** make
missing/expired/invalid V2 capability automatically mean V1 after a V2-required path was selected.
Requirements prohibit parallel direct/relay legacy-fallback runtime logic and require authenticated,
fresh traversal endpoint state plus leak prevention (`documents/Requirements.md:67,202-203,239`).

Proposed policy modes, subject to product/security review:

- `V2Required`: requires verified v1 fleet membership, fresh matching V2 capability,
  `AuthoritativeTransportState::Ready(I<n>)`, and narrow-mux backend support. Any missing/invalid
  prerequisite makes relay unavailable/quiesced with operator-visible reason; no V1 datagram is
  emitted as fallback.
- `LegacyCompatibility`: an explicit, signed, scoped, time-bounded migration policy selected before
  any relay attempt. It selects V1 only, records `legacy_unconfirmed`, and cannot satisfy V2
  recovery/liveness guarantees, authenticated relay-control confirmation, or protected-mode
  availability claims. It is not an automatic retry/downgrade from a failed V2 attempt.

Whether `LegacyCompatibility` is acceptable at all needs an explicit Requirements decision; safest
end-state is `V2Required` only. Existing old daemons may ignore a separate capability artifact, but
they must be contained by rollout policy rather than used to justify a hidden new-client fallback.

Capabilities bundle needs same persisted, digest-aware anti-rollback watermark as current signed
relay fleet: reject lower `{generated_at, nonce}`, reject equal watermark with differing payload
digest, and retain watermark across daemon restart. Reuse fleet bootstrap trust/clock/max-age checks;
do not make capability a weaker parallel trust path. Tests cover stale, equal-different, replayed,
and restarted daemon cases.

V2 negotiation additionally requires all `V2Required` prerequisites above. Command/opaque
backends, including current Windows command backend, advertise no mux and must never emit `0x11`,
`0x13`, or V2 endpoint selection even if signed fleet capability says V2. Under `V2Required`, that
is a quiesced relay outcome, not a V1 retry; under an explicitly selected legacy policy, V1 is chosen
before dispatch and remains visibly unconfirmed.

Deployment:

1. Deploy relay supporting v1/v2; signed policy remains explicit V1-only legacy compatibility.
2. Deploy daemon/control parser plus capability/protocol-policy verifier; do not auto-negotiate
   fallback on errors.
3. Publish short-lived signed capability records after endpoint verification.
4. Canary `V2Required` only where all prerequisites are present; fault/missing capability quiesces.
5. Keep V1 only under explicitly scoped legacy policy, labeled `legacy_unconfirmed`; it makes no
   trusted-liveness/protected-mode claim.
6. Retire V1 via explicit maintenance policy after telemetry proves no legacy-policy clients.

Capability, V2 hello, and V2 probe are one feature gate. Upgraded client does not send `0x11`
merely because binary supports it.

## Token and server-idempotency constraints

For indeterminate hello, claim fresh matching token. If unavailable, remain quiesced with explicit
`token_inventory_exhausted_after_indeterminate_hello`. Never reuse artifact or local-sign fallback.

Do not implement nonce-only server idempotency. Durable nonce can outlive memory sessions/allocation
tasks; historical ACK can point to dead allocation after restart. Future idempotency requires atomic
durable nonce, canonical request digest, session/allocation lifecycle, response, restart policy.

V1 and V2 hello parsers, including embedded token parser, must consume their input exactly. Reject
trailing outer bytes, trailing token bytes, duplicate/unknown extensions, and noncanonical framing
before signature validation, nonce insertion, or session allocation. Current relay parser accepts
some trailing bytes (`rustynet-relay/src/main.rs:1249-1260,1347-1364`); V2 must fix both versions,
not introduce stricter rules only for new clients.

## Acceptance tests

Add deterministic Linux/macOS test-only fault points; no timing sleeps:

```text
BeforeCommandDequeue
AfterCommandDequeueBeforeSend
AfterDatagramSendBeforeReplyOrWaiter
```

Required gates:

1. Backend errors/latch: all runtime-dispatch operations latch; only explicit recovery clears;
   healthy recovery rejects; I1 reported; Linux/macOS parity.
2. Terminal worker errors: socket/TUN/timer exit reports `WorkerUnavailable` with cause.
3. Daemon: query-triggered loss quarantines before keepalive; no I0 candidate publish/relay send;
   relay registration starts even if STUN fails; status coherent. Fault while relay selected must
   replay validated baseline/quiesced state only: I1 timer/handshake traffic never targets I0 relay
   port or an un-revalidated dynamic direct candidate.
   Peer activation is separately transactional: initial apply, E1 transition, and recovery all bind
   bypass/PF policy plus exit-policy assertion before backend E1 can emit. Pre-commit policy failure
   makes no backend change; post-dispatch worker loss is visibly latched/quiesced. Run initial,
   direct-roam, relay-selection, recovery, and full-tunnel cases on Linux/macOS/Windows system mocks
   with runtime egress instrumentation, not only recorded system operations.
4. Hello: accepted first send + held ACK + worker death gives no automatic duplicate; fresh token
   recovery; stale ACK N rejected while N+1 pending.
5. Parsers: v1 exact 19-byte compatibility; v2 exact length/source/session/nonce behavior; v1/v2
   outer hello and embedded token consume complete input, rejecting trailing/duplicate/unknown bytes.
6. Mux: generic peer-endpoint round trip remains rejected. While v2 probe outstanding, ciphertext
   and wrong ACK frames reach engine; only byte-for-byte expected ACK completes control.
   STUN/hello/probe share one global slot; injected Busy sends nothing, consumes no pre-issued token,
   and does not count as a liveness miss or worker failure. Permit lifecycle: cancel/expiry before
   claim releases matching I<n> permit only; worker loss after claim retires artifact; late I0 Drop
   cannot release I1 slot; no permit/job survives recovery or deadline.
7. Relay: V2 probe exact-bound tuple success; unbound/other/expired/unknown silent; one response
   no larger than request; restart produces no ACK. V2 probe never first-binds: attacker probe race
   cannot bind allocation ahead of legitimate ciphertext. Existing ciphertext first-bind is tracked
   as a separate residual-security case, not expanded by probe.
8. End-to-end: hello/held-ACK/worker death/I1/fresh token; stale packet injection; authenticated
   peer reachability bound to selected endpoint then relay restart; bounded quiesce/re-registration.
   Run both backends and pre-issued/local issuers. Do not call this relay-control confirmation.
9. Control: capability canonicalization, duplicate/unknown field, signature, expiry, ID/endpoint
   mismatch, persisted watermark replay/rollback across restart, command/Windows no-mux gate, and
   old/new client × v1/v2 relay matrix under both `V2Required` and explicitly signed legacy policy.
   Assert strict missing/invalid/unsupported states quiesce without V1 control datagram; assert
   legacy policy selects only V1 before attempt and never promotes trusted/live. Spoofed valid-shaped ProbeAck cannot promote
   authenticated peer reachability or relay-control confirmation. Cookie/data/error,
   old-port delayed response, timer/keepalive, and same-I old-overlay session traffic cannot refresh
   selected-endpoint peer-reachability state; only semantic session-established event bound to
   current I1/session/endpoint/overlay epoch can.

`--node` live-lab comes after deterministic proof. Capture before/unavailable/after incarnation,
candidate ages, STUN count, relay registration, probe reachability, endpoint-bound authenticated
handshake, token inventory, endpoint. Lab validates environment, not state-machine correctness.

## Adversarial review record

Five read-only adversarial reviews ran. Corrections incorporated:

- generic retry unsafe for relay hello;
- query recovery can roll socket before relay work;
- relay restart defeats send-success liveness;
- unobservable identity must not cause repeated rollover;
- STUN cannot gate relay re-registration;
- nonce echo is correlation, not authentication;
- token count is advisory, not reservation;
- generic allocated-port round trip would intercept ciphertext;
- terminal worker I/O/TUN/timer errors need typed worker loss;
- optional identity cannot hide fault as unsupported;
- desired intent needs pre-reply staging;
- healthy recovery cannot manufacture new incarnation.
- recovery must not replay stale I0 relay endpoint; split baseline desired peer state from overlay;
- V2 probe is never first-bind authority; existing first-ciphertext binding remains separate risk;
- probe ACK is unauthenticated reachability, not selected-path peer reachability or relay-control
  confirmation;
- desired-state recovery is revisioned at-least-once convergence, not globally exactly once;
- capability bundle needs persisted digest-aware anti-rollback watermark and backend mux gate;
- v1/v2 hello and embedded token parsers must consume complete canonical input; and
- generic/control waits share one slot, with a pre-token admission permit and typed Busy outcome.
- endpoint transition cannot refresh policy from stale managed-peer state: use candidate snapshot,
  explicit common initial/transition/recovery transaction, and fail-closed/quiesced failure
  semantics; timer-only runtime pause also leaks via UDP/TUN engine paths.
- cached `ManagedPeer.direct_endpoint` is dynamic candidate state, not recovery baseline; preserve
  candidate provenance/expiry and revalidate or quiesce.
- WireGuard session evidence proves peer reachability at selected endpoint, not relay-control session
  ownership; bind semantic session event to I<n>, relay session ID, overlay revision, endpoint, and
  local epoch.
- admission permit needs matching instance/permit release, deadline/cancel rules, I0 invalidation,
  and irreversible post-claim token semantics.
- missing/invalid V2 capability needs explicit strict-versus-time-bounded-legacy policy, never
  automatic V2-attempt fallback.

Fourth-review evidence: shared backend recovery reconfigures stored peers
(`userspace_shared/mod.rs:239-249`) while endpoint updates persist selected endpoint in
`desired_peers` (`:462-485`); Phase10 retains `ManagedPeer` direct/relay/path overlay
(`phase10.rs:406-413`) and writes endpoint through `reconfigure_managed_peer` (`:6378-6399`).
Generic runtime has one slot/state (`runtime.rs:295-309,390-402,529`; macOS parity); normal current
worker execution does not poll socket between its send and state installation, but typed V2 mux must
retain one atomic pending-entry/send transaction under future refactor. Existing relay first binds
same-IP ciphertext source (`transport.rs:635-647`), so V2 probe must not duplicate that authority.
Fleet watermark uses digest-aware order (`daemon.rs:14107-14126`); capabilities need same persistent
guard. Relay outer hello/token parsing currently accepts trailing bytes
(`rustynet-relay/src/main.rs:1249-1260,1347-1364`). Existing command/opaque backend guard remains fail-closed around
`daemon.rs:6941-6949`. Review made no code/test changes.

Fifth-review evidence: `reconfigure_managed_peer` updates backend endpoint before route/PF refresh,
but refresh reads pre-update `managed_peers` and insertion happens last
(`phase10.rs:6378-6412`). macOS endpoint policy is an exact socket egress allow-list
(`phase10.rs:3515-3534`); Linux/Windows derive endpoint bypass policy from the supplied peer list
(`phase10.rs:2181-2210,4487-4510`). Initial apply configures peers before bypass/system routes
(`phase10.rs:5509-5535`). Worker UDP ingress and TUN ingress can each emit peer ciphertext, not just
timer polling (`runtime.rs:830-955,1164-1178`). `ManagedPeer.direct_endpoint` mutates from supplied
traversal candidate (`phase10.rs:5992-6022`), so it lacks baseline provenance. Current decap result
reports cached stats after any decap (`engine.rs:528-620,1006-1014`), whereas vendored BoringTun
valid init/response stores session and returns `WriteToNetwork`
(`third_party/boringtun/src/noise/mod.rs:318-369`). Existing receiver-index demux admits
pre-endpoint responses (`engine.rs:536-542`). Pre-issued token artifact is deleted before transport
(`relay_client.rs:169-228`). Requirements prohibit a hidden legacy/fallback traversal path and
require authenticated/fresh endpoint state and leak protection (`Requirements.md:67,202-203,239`).
Review conclusion: recovery barrier must not rely on current helpers until prospective-state
transaction, full runtime pause, provenance, session evidence, permit lifecycle, and strict rollout
semantics are independently designed and tested.

## Baseline evidence

Passed before design work; baseline only, not proof of proposed behavior:

```text
cargo test -p rustynet-relay --lib --locked test_replayed_nonce_rejected
cargo test -p rustynetd --lib --locked preissued_relay_session_token_issuer_consumes_matching_signed_token
cargo test -p rustynet-backend-wireguard --lib --all-features --locked \
  linux_userspace_shared_backend_relay_round_trip_and_send_use_same_transport_generation_as_peer_path
cargo test -p rustynet-backend-wireguard --lib --all-features --locked transport_generation
```

No source implementation/new tests were added by this investigation.

## Recommended merge order

1. Fix common initial-apply/endpoint-transition/recovery candidate-state policy transaction, with
   Linux/macOS/Windows runtime-egress and failure tests. Do not build recovery barrier on current
   helpers.
2. Typed worker loss, failure latch, staged desired state, coordinator tests.
3. Incarnation/status contract and Linux/macOS recovery parity.
4. V2 hello ACK correlation plus parser/server tests.
5. Narrow V2 allocated-port mux plus ciphertext-interleaving tests.
6. Relay liveness/restart tests.
7. Signed capability artifact and staged rollout.
8. Controlled `--node` live-lab validation.

Keep P3 queue/backpressure independent from this P0/P1 reliability change.
