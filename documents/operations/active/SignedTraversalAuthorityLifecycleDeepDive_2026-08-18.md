# Signed Traversal-Authority Lifecycle Deep Dive — 2026-08-18

Status: source/design review only. Independent adversarial source review completed 2026-08-18. No product
code, live-lab state, keys, or network configuration changed by this investigation.

## Scope

This is a separate review from shared UDP/relay socket lifecycle. It examines how Rustynet authorizes
and renews peer reachability data: signed traversal bundles, self-signed gossip candidate sets,
membership epoch/revocation coupling, replay persistence, candidate-to-endpoint mutation, and
fail-closed expiry. It does not redesign WireGuard, relay protocol, routes, or normal timer values.

## How to use this report

Every recommendation is a **proposal**, not approved implementation. Each source-backed fact is
labelled **Observed**; unresolved choices are **Explore**; required proof before merge is **Gate**.
Do not treat a report suggestion as authorization for a fallback path, endpoint mutation, key-custody
expansion, or live-network experiment. Preserve signed-state validation, anti-replay, ACL/default-deny,
and fail-closed behavior.

## Why this slice matters

The project already identifies a production gap: default enforced traversal authority expires around
120 seconds when no component reissues it, causing a healthy mesh to fail closed. The approved
direction in `TraversalSelfSustenancePlan_2026-07-23.md` is peer self-signed candidate gossip rather
than placing a mesh-root signing key on an anchor/daemon. This review tests lifecycle seams around
that direction before implementation.

## Initial source map

- `documents/Requirements.md` §3.2/§6.2 — signed, fresh traversal hints; deterministic direct/relay
  controller; no policy bypass on path transition.
- `documents/operations/active/TraversalSelfSustenancePlan_2026-07-23.md` — approved direction and
  existing design-review corrections.
- `crates/rustynetd/src/{daemon,peer_gossip,gossip_runtime,gossip_transport,dataplane_candidates,
  ice_priority,traversal}.rs` — acceptance, replay, candidate gathering, publication, consumption.
- `crates/rustynet-control/src/membership.rs` — verified membership epoch and node identity authority.

## Initial issue register

| Observation | Proposal direction | Explore before implementation | Gate |
| --- | --- | --- | --- |
| Enforced control bundle expires without reissue | Self-signed per-peer candidate authority, membership-authorized | Authority handoff/feature cutover; no parallel legacy path | Default mesh survives expiry only through verified fresh peer authority |
| Candidate signer is peer, not control root | Bind candidate to verified membership identity + epoch/revocation view | Exact epoch-window semantics under benign membership churn | Revoked/rotated identity cannot refresh endpoint |
| Candidate reachability is untrusted network assertion | Validate syntax, scope, ACL, plausibility, freshness, replay, then verify reachability before mutation | Which checks are pre- vs post-probe; resource limits | No gossip input directly programs endpoint |
| Per-source sequence must survive restart | Persist monotonic watermarks atomically before acceptance | Crash point / durability policy; key rotation handling | Replayed/reordered bundle rejected after restart |
| Candidate freshness needs repeated minting | Rate-limited renewal plus change-triggered publish | Clock rollback/forward jump; rejoin/reboot behavior | Expiry/loss/clock tests are deterministic, no sleep proof |
| Membership epoch changes frequently | Reconcile epoch binding without mesh-wide blackhole | Bounded previous-epoch acceptance and revocation proof | Benign join does not remove healthy paths; revocation does |
| Candidate-to-endpoint apply is security boundary | Transactional verified-index-to-Phase10 handoff | Provenance/lifetime retention through async path selection | Endpoint mutation cites exact accepted candidate record |

## First confirmed facts

**Observed.** `TraversalSelfSustenancePlan_2026-07-23.md` identifies default
`EnforcedV1` authority as custody-file-only, freshness-bounded to roughly 120 seconds, while daemon
path application fails closed without valid signed traversal state. Its selected Design A makes each
peer sign its own candidate set with a membership-authorized gossip identity; candidate data states how
it can be reached. The plan explicitly rejects putting the mesh-root signing key on a running anchor/
daemon.

**Observed.** Candidate gossip has a versioned canonical signed preimage, source sequence, timestamp,
membership epoch, candidate set, and Ed25519 signature (`peer_gossip.rs`). Candidate types include
host and server-reflexive v4/v6 values (`dataplane_candidates.rs`). Existing documents already require
epoch binding, per-source replay persistence, ACL scope, plausibility/rate limits, return routability,
and a staged enforcement flip.

**Design boundary.** A peer signature authenticates who asserted a candidate; it does not prove the
candidate is currently reachable or policy-permitted. Candidate gossip must remain evidence input,
not a direct endpoint-programming capability. Verification must carry provenance into the eventual
Phase10 mutation and fail closed when that provenance expires or is invalidated.

## Next focused questions

1. Does current candidate acceptance bind the signing key to the verified membership node identity at
   every post-restart/rotation path, or only at initial gossip ingest?
2. Is sequence watermark persistence ordered safely relative to verified-index mutation and endpoint
   application?
3. Can an accepted old-epoch candidate survive benign epoch churn too broadly, or revoked key
   rotation too long?
4. Does candidate provenance survive ICE prioritization, probing, path selection, and Phase10 update?
5. Are clock failure semantics fail-closed without a self-inflicted renewal storm?

## Evidence limits

No build/test run for this report pass, respecting active benchmark resource constraints. Future
acceptance gates listed here require deterministic unit/integration proof before `--node` lab work.

## 1. Current implementation boundary

**Observed.** Candidate gossip is already partially implemented, not merely planned. A configured
gossip-only signing key builds `GossipNode`; a verified membership commit then binds the gossip socket,
registers membership-derived peers, and the main loop mints/accepts candidate bundles
(`daemon.rs:4303-4318,5513-5607,10659-10669`). The bundle has a versioned canonical signed preimage,
source key, sequence, timestamp, membership epoch, candidate set, and Ed25519 signature
(`peer_gossip.rs:5-52,111-176,383-496`).

**Observed.** This subsystem is *not* yet Phase10 endpoint authority. `applied_endpoints` is an
in-memory `HashMap<gossip_key, Vec<SocketAddr>>` written by inbound acceptance
(`gossip_runtime.rs:218-220,648-660`). A scoped source search found no production Phase10/controller
consumer. Existing `apply_traversal_authority_to_peers` instead reads V1 signed traversal bundles
(`daemon.rs:7017-7075`). This is a safety boundary: the findings below block the planned authority
cutover; they do not claim that current gossip directly changes production peer endpoints.

**Observed.** In enforced mode, the daemon rejects absent/invalid traversal state and requires an exact
managed-peer/traversal-index match before probing or initial peer configuration
(`daemon.rs:6449-6467,7017-7063`). This meets the current V1 fail-closed requirement, but explains why
a 120-second custody artifact expiry is a product availability gap.

**Proposal.** Treat V1 and peer-signed authority as formats of one authority state machine, not two live
endpoint-selection implementations. A staged rollout/control flag is permissible; after PeerSignedV2 is
enforced, a V1 artifact, static assignment, last endpoint, or raw cache must not quietly program an
endpoint. The only restart aid may be a revalidated record of the same signed peer authority.

**Explore.** Define an explicit `TraversalAuthoritySource`/generation at every controller mutation:
`ControlV1` during compatibility rollout, then `PeerSignedV2`; no value means no mutation. Decide
network-wide, per-node capability, or maintenance-window activation with the owning design reviewers.

**Gate.** Feed missing, expired, malformed, wrong-membership, replayed, and valid records into both
modes. In enforced PeerSignedV2 mode, every non-valid case must leave the controller fail closed; no
V1/static branch may reappear as rescue. Re-run the shared-UDP lifecycle tests because the endpoint
mutation still crosses the same route-policy/egress barrier.

## 2. P0 — removal and key rotation leave residual gossip authority

### Evidence

**Observed.** `MembershipOperation::RemoveNode` deletes the member entirely, while
`RotateNodeKey` replaces `node_pubkey_hex` in-place (`membership.rs:2002-2044`). That public key is
documented in code as the gossip trust anchor (`membership.rs:455-457,3464-3466`).

**Observed.** On a verified membership update, `sync_gossip_data_plane` derives only
Revoked/Quarantined keys, unregisters only those keys, then additively registers current active members.
Its documented contract intentionally says members absent from membership are not unregistered
(`daemon.rs:5488-5512,5543-5607`). `GossipNode::unregister_peer` removes only routing/verifier state;
it intentionally retains replay state and does not remove `applied_endpoints`
(`gossip_runtime.rs:323-331,648-660`).

**Observed.** A removed member's old key, or replaced key after owner-signed rotation, can therefore
remain in `GossipNode.peers`; `known_peer_keys()` exposes it to signature verification
(`gossip_runtime.rs:307-321,566-660`). Neither operation puts the departed old key in
`revoked_peer_ids_from_membership`, because the key is absent/replaced in the new snapshot.

**Adversarial correction (source-confirmed).** This is not limited to the old epoch/freshness window.
`sync_gossip_data_plane` stamps the current verified membership epoch into the local `GossipNode` before
checking only a warning-level local membership-key mismatch (`daemon.rs:5513-5570`). A removed node that
still receives a new membership snapshot, or a rotated-out daemon whose NodeId remains but key changed,
can mint with its old key at the *current* epoch. Peers retaining that old key accept it as known, so epoch
binding does not withdraw this residual authorization. Exact active-key reconciliation plus local
mint/accept activation gating is mandatory.

**Adversarial correction (source-confirmed).** Gate *all* local candidate-authority activity, not mint
only. Current attachment/mint requires only a gossip node plus transport; local-node absence/status/key
is not an activation guard (`daemon.rs:5520-5546,5567-5582,5804-5818`). Inbound acceptance likewise
checks remote source authorization but not whether this receiving daemon remains an active member
(`gossip_runtime.rs:577-627`). A removed daemon could otherwise accept, cache, and re-push candidate
metadata after it learns a current membership snapshot. The activation predicate must be exactly:
local NodeId exists in verified membership, status is Active, and membership gossip key equals local
signer key. False/unknown blocks mint, accept, cache retention, re-push, and any later program path.

### Risk boundary

**Observed.** Today this retains a gossip cache/routing entry only; it does not currently update a
Phase10 endpoint. If PeerSignedV2 consumes this map without a new authorization transition, a removed or
rotated-out key can keep submitting fresh, current-epoch valid candidates when it receives membership
updates, and it can leave old cached candidates behind. That violates immediate withdrawal of candidate
authority.

### Proposed direction — review before implementation

**Proposal.** Replace additive peer registration with one atomic, verified authorization snapshot:

```text
member NodeId -> exactly one active gossip verifying key -> peer routing address
gossip verifying key -> exactly one active NodeId
```

At membership commit, derive the entire new snapshot, validate it, calculate removed/replaced keys, then
atomically remove unauthorized verifier/routing entries; purge their candidate records, pending probes,
selected traversal overlays, and re-push destinations; withdraw any endpoint citing the removed key;
install the new snapshot; and retain replay high-watermarks separately from authorization.

**Explore.** Current additive retention preserves D2.7 in-flight enrollment. Do not weaken removal to
preserve it. Model bootstrap identities separately: single-use, expiry-bounded, purpose-limited, and
unable to mint, accept, re-push, or program traversal candidates until normal membership admission.
Decide whether removed keys need persisted withdrawal tombstones with membership/key-rotation owners.

**Gate.** Deterministically prove:

- `RemoveNode`: old key is rejected; routing/cache is gone; it cannot re-push, probe, or mutate endpoint.
- `RotateNodeKey`: same NodeId rejects old key immediately; new key has no endpoint before a fresh
  candidate and exact-pair reachability proof.
- removed/rotated-out daemon receives a current membership epoch: its old key cannot mint, and retained
  peers cannot accept it.
- removed/rotated local daemon cannot mint, accept, cache, or re-push any candidate after receiving that
  snapshot; no eventual endpoint/program state survives its authority loss.
- membership-commit failure at each transition step leaves no mixed old/new authorization snapshot.
- restore/re-enrollment preserves replay protection while explicitly re-admitted identity can progress.

## 2a. P0 — enrollment bootstrap currently grants full gossip authority

**Adversarial evidence (source-confirmed).** The D2.7 exception is more than retained routing. Enrollment consume creates a normal GossipPeer through register_peer before membership admission (enrollment_consume.rs:201-226; daemon.rs:8658-8671). The same peers map supplies known-source verification and epidemic push/re-push topology (gossip_runtime.rs:307-321,379-388,592-605,688-715). A not-yet-member key can therefore present a signed candidate bundle with a guessed in-window epoch and be accepted/re-pushed; it is not confined to receiving bootstrap traffic.

**Risk boundary.** This does not currently program Phase10, but it violates the intended rule that verified membership authorizes candidate assertion and expands candidate metadata propagation before admission. It also means “leave absent peers registered for enrollment” is not a safe substitute for an authority lifecycle.

**Proposal.** Split bootstrap recipient delivery from active candidate authority. A bootstrap entry must carry its enrollment-token binding, narrow purpose, deadline, and explicit removal; it may receive only the exact required bootstrap material. It must never appear in known_peer_keys, accept/re-push third-party candidates, mint candidate authority, retain candidate cache, or reach coordinator endpoint consumption. Active gossip verifier/recipient state is derived only from the exact verified active membership authorization snapshot.

**Explore.** Establish the minimum initial delivery that actually needs a pre-admission encrypted-mesh destination. If a bootstrap record needs a transmission exception, make it direct, single-use, address-minimized, and auditable; do not reintroduce generic epidemic forwarding. Confirm token expiry/cancel/replay behavior with enrollment owners.

**Gate.** Pre-admission key cannot appear in source-verifier map, send topology, cache, or endpoint authority. It receives no third-party candidate bundle. Required initial delivery succeeds only inside its token-bound deadline and is removed after admission, expiry, cancel, or failure.


## 3. P1 — duplicate active gossip keys collapse member identity

**Observed.** `MembershipState::validate` rejects duplicate `node_id`, but only checks that every
`node_pubkey_hex` decodes as 32-byte hex; it does not reject duplicate gossip keys or validate an
Ed25519 point (`membership.rs:225-252`). Gossip registration later drops invalid points, sorts unstably
by key, and deduplicates; an equal-key survivor is not a specified principal selection. Meanwhile,
`applied_endpoints` is keyed only by that key (`gossip_runtime.rs:218-220,825-872`).

**Risk.** Two active member IDs sharing one signing key cannot have distinct candidate authority. A future
NodeId-to-candidate lookup could apply one member's assertion to the other. This is an operator-signed
invalid-roster shape today, not an unsigned remote-input bypass; it becomes endpoint-integrity critical
when candidate authority is enabled.

**Proposal.** Reject non-Ed25519 gossip keys and duplicate active gossip keys during signed membership
snapshot validation, then construct a bijective `NodeId <-> GossipKey` index before accepting or consuming
PeerSignedV2 records. Never rely on sort/dedup or HashMap insertion order to choose a principal.

**Explore.** Decide strictness for inactive historical records and staged key migration. The secure default
for the active authority set is one key per active member. Any deliberate overlap needs explicit
activation/revocation semantics, not current deduplication.

**Gate.** A snapshot containing two active NodeIds sharing one valid public key fails before gossip
registration changes. A duplicate introduced by update fails atomically; neither member receives a
candidate endpoint from the other.

## 4. P0 cutover gate — raw candidates cannot reach Phase10

**Observed.** Inbound acceptance verifies source key, canonical signature, count/scope, timestamp,
bounded epoch, strict source sequence, revoked-source status, and per-source rate budget before advancing
the durable watermark and writing the cache (`peer_gossip.rs:584-662`; `gossip_runtime.rs:564-660`).
Private addresses remain allowed for same-LAN operation; loopback, link-local, multicast, broadcast, and
unspecified candidates are rejected (`peer_gossip.rs:548-580`).

**Observed.** These checks authenticate an assertion; they do not prove dialing it reaches the asserted
peer. A compromised, still-authorized member can advertise another host's routable address. The approved
self-sustenance plan already requires return routability before programming.

**Proposal.** Introduce an immutable `VerifiedCandidateRecord`, not `Vec<SocketAddr>`, as the only gossip
handoff type. Bind remote `NodeId` and current key; membership generation; canonical signed bundle digest,
sequence, timestamp, expiry, accept time; typed candidate class; and candidate/evidence generations. Only
the traversal coordinator may convert it to a transient endpoint overlay. It rechecks current authorization
and freshness immediately before mutation, then uses the shared-UDP route-policy and egress barrier before
any endpoint overlay is visible.

**Adversarial correction (source-confirmed).** A candidate record cannot call every host candidate an
exact endpoint. Host addresses serialize with port zero; only server-reflexive candidates carry a port,
and `flatten_endpoints` produces `SocketAddr(ip, 0)` for host entries
(`peer_gossip.rs:370-382,413-419,912-927`). Model `HostAddress` and `ServerReflexiveEndpoint` separately.
Forbid port-zero handoff/programming. A host address needs a separate authenticated, explicit
host-port-resolution rule and then its own exact-pair evidence; a server-reflexive endpoint needs its own
exact-port evidence. Do not smuggle a presumed WireGuard port into `SocketAddr` provenance.

**Explore.** Define exact-pair proof precisely. Local UDP send, STUN-shaped reply, or stale WireGuard
timestamp is insufficient. Prefer a current authenticated session/handshake event bound to selected
endpoint, candidate-record generation, and authoritative socket incarnation. Reuse the shared-UDP report
constraints; do not create a second control path.

**Gate.** Instrument endpoint update. Assert raw cache has no call path to it; accepted-but-unprobed
candidate cannot change endpoint; incorrect endpoint/incarnation cannot attest; revocation, rotation,
expiry, or route-policy failure withdraws overlay before peer ciphertext egress.

**Adversarial correction (source-confirmed).** This needs an API boundary, not instrumentation alone.
`GossipNode.applied_endpoints` is public and public ingest summaries export `Vec<SocketAddr>` from public
ingest APIs (`gossip_runtime.rs:218-220,517-549,902-925`). A future caller could bypass the proposed
record merely by naming those public values. Make raw accepted-cache storage private/test-only; replace
the public summary with an opaque verified-record handle; expose coordinator-only consume capability.
Compile-time visibility must prevent Phase10 from naming a raw gossip endpoint; runtime instrumentation
remains defense in depth.

**Gate.** Supply host and server-reflexive inputs independently. A host candidate with port zero must
never update/program an endpoint until explicit port provenance and exact-pair proof exist. Server-reflexive
candidate proof must bind its advertised port; cross-type substitution must fail.

**Gate.** Add a compile-time boundary check: production Phase10/controller modules cannot access raw
gossip endpoint fields or construct a consume handle. Then retain endpoint-boundary instrumentation as a
separate runtime assertion.

## 4a. P1 — current gossip dissemination is membership-wide, not ACL-scoped

**Observed.** gossip_peer_registrations_from_membership creates registrations for every active member with a verified overlay address; it has no policy/ACL input (gossip_runtime.rs:825-901). On accepted inbound gossip, ordered_peer_ids_for_rebroadcast selects every registered peer except source/immediate sender, and the runtime forwards the complete signed bundle (gossip_runtime.rs:537-555,678-716). Candidate bundles contain host and server-reflexive addresses, which can disclose LAN and public reachability metadata even when addresses are redacted from logs.

**Observed.** The approved self-sustenance plan explicitly requires ACL-scoped gossip application and propagation as a privacy control. Current all-member dissemination exists today whenever optional gossip is configured; it is not merely a future Phase10 issue. It does not itself grant traffic authorization, but it widens who learns reachability metadata.

**Proposal.** After the bijective NodeId <-> GossipKey identity map exists, derive a verified, recipient-scoped candidate-distribution policy from the same signed membership/policy state that controls mesh access. Apply it twice: before accepting/retaining a remote member's candidates locally, and before forwarding candidates to another member. Default-deny on missing, stale, ambiguous, or non-permitting policy. Do not infer permission from transport reachability or membership activity.

**Explore.** Epidemic forwarding through a non-authorized intermediary conflicts with endpoint minimization because the intermediary receives the full bundle. Decide whether permitted recipients receive direct source fan-out, whether a narrowly scoped relay/seed exception is needed, and how any exception avoids becoming broad endpoint disclosure. This may change the selected dissemination topology; do not implement it as a post-hoc filter only at Phase10.

**Gate.** Use three members with asymmetric signed policy. Prove unauthorized member receives neither raw candidate bundle nor cache record and cannot re-push it; permitted member receives it and can progress only through the independent reachability gate. Cover policy revoke, change, stale/missing policy, anchor/seed selection, and no-log-address regression.


## 5. P1 — durable replay watermark versus volatile candidate cache/restart bootstrap

**Observed.** On inbound acceptance, `GossipNode` writes the proposed highest-seen sequence atomically before assigning the in-memory `applied_endpoints` map (`gossip_runtime.rs:648-660`). The spool uses a same-directory temporary file, file `sync_all`, rename, and parent-directory `sync_all` on Unix (`gossip_runtime.rs:1142-1240`). This is correct anti-replay ordering.

**Observed.** The cache itself is not persisted. After daemon crash/restart, the same signed bundle is rejected as non-monotonic while the endpoint cache starts empty. A healthy publisher unconditionally re-mints every 30 seconds, in addition to candidate-change publishing (`gossip_runtime.rs:67-72,390-455`), so normal convergence can refill it; this is bounded availability, not crash-atomic candidate state.

**Risk.** After PeerSignedV2 is sole authority, a cold restart after V1 expiry cannot assume it has an overlay tunnel through which gossip travels. Persisting only the watermark preserves security but may require a re-mint that cannot arrive until reachability is restored. Persisting a naked socket address would solve neither provenance nor anti-replay safely.

**Adversarial correction (source-confirmed).** This is also an endpoint-drift/path-loss problem, not only a restart problem. Peer registration deliberately sends gossip to a verified overlay address and forbids raw-Internet fallback (`gossip_runtime.rs:825-830`); gossip transport runs after the WireGuard tunnel exists (`gossip_transport.rs:5-12`). If the old traversal endpoint stops working, gossip cannot deliver new candidate information needed to repair that path. A cache helps only while an old route remains usable. PeerSignedV2 gossip alone is therefore not a complete self-sustaining rediscovery mechanism.

**Proposal.** Choose and prove one restart design before cutover. The conservative candidate is a durable, encrypted/permission-checked cache of the complete signed candidate record, keyed by source key and membership generation. Prefer one atomic durable authority-state transaction for watermark plus cache. If separate, load only when cache source, sequence, and canonical digest exactly equal the persisted highest accepted value for that source: lower sequence means discard/resync; higher sequence is inconsistency and must not advance replay state. Then re-verify canonical signature, current membership/key binding, expiry, and withdrawal state; do **not** treat equality with seen watermark as a new accept; require a new exact-pair reachability proof before programming. It remains PeerSignedV2 state, not V1/static fallback.

**Explore.** Evaluate an explicit authenticated resync path instead of persistent candidates. It must not depend on the endpoint it is rediscovering, require mesh-root signing material on a daemon, or violate the no-parallel-traversal-path rule. Set privacy/storage bounds and custodianship before choosing either path.

**Gate.** Fault-inject after watermark persistence but before cache publication, and after cache staging but before watermark publication. Restart with equal/newer/lower cache sequence, digest mismatch, expired record, revoked key, rotated key, and no network. Prove superseded/stale cache never restores; new valid record converges within a declared bound; post-expiry cold restart either restores a newly revalidated PeerSignedV2 route or stays visibly fail closed. Add explicit re-enrollment policy proof for same-key sequence continuity/reset: retaining watermark rejects reset signer, clearing it reopens replay.

**Gate.** After V1 expiry, force loss/drift of the programmed endpoint rather than only process restart. Prove the chosen authenticated bootstrap/resync mechanism reacquires a fresh authorized candidate and passes exact-pair validation, or reports the path unavailable without claiming gossip self-sustenance.

## 6. P1 — bind, delivery, and usable authority are different states

**Observed.** Gossip transport attaches only at a signed-state commit seam. Bind failure is recorded and retried only by a later call to that seam (`daemon.rs:5473-5562`), not a dedicated transport supervisor. `gossip_state=active` explicitly means a socket is bound, not that it remains healthy. Mint send failures are logged/counted while the send loop continues (`daemon.rs:5680-5825`).

**Risk.** Bound UDP or successful local `send_to` is not proof that any peer received fresh authority. Treating either as PeerSignedV2 readiness hides the partition that later ends in authority expiry. Temporary gossip outage also must not cause V1/static endpoint downgrade.

**Proposal.** Expose independently: transport bound, watermark health, local identity/member-key match, last mint, last accepted candidate per authorized peer, last authenticated exact-pair evidence, and controller authority state. Define classified fatal local socket I/O as a transition: detach/close transport, set degraded status, then bounded-backoff rebind after verified membership exists. Do not treat ordinary remote loss or unconfirmed UDP push failure as proof that socket recreation is needed; distinguish each from expired/missing authority.

**Explore.** Decide which absence fails closed immediately and which can retain an already-proven, still-fresh record. Do not call a path “healthy” because a datagram was queued locally.

**Gate.** Force bind failure before/after membership commit, then free the port without a new membership event. Inject classified fatal receive/send socket paths after attach and prove detach, close, bounded rebind, and accurate status. Also blackhole pushes: bound counters/logs, avoid false local recovery, and require peer-side accepted or handshake evidence before reporting usable authority. No mutation while authority is unavailable and no automatic fallback.

## 6a. P1 — gossip socket is wildcard-bound despite overlay-only intent

**Adversarial evidence (source-confirmed).** Default runtime bind address is 0.0.0.0:51821 (daemon.rs:4315-4318), and Unix transport directly uses UdpSocket::bind (gossip_transport.rs:126-138). The daemon notes that any UDP sender can reach this input path (daemon.rs:5628-5637). Signature verification prevents an unauthenticated sender from gaining candidate authority, but it still exposes parsing, signature-work, wakeup, and bounded-drain capacity to arbitrary network traffic.

**Proposal.** Before PeerSignedV2 enforcement, constrain ingress to the verified mesh/overlay address or an equivalent explicit host firewall policy. Rebinding/recovery must preserve that scope. Treat public wildcard bind as development/legacy state, not PeerSignedV2 authority readiness.

**Explore.** Verify platform-specific overlay binding semantics and whether an ingress firewall is needed in addition to binding. Preserve legitimate encrypted overlay delivery; do not “fix” the exposure by trusting a source address in place of signature/membership verification.

**Gate.** Direct LAN/public UDP sender is rejected before candidate parse/verification while an authorized overlay peer still exchanges bundles. Cover socket recovery/rebind, interface change, flood accounting, and no accidental wildcard bind in enforced mode.


## 7. P1 — clock and gossip-key activation are deployment gates

**Observed.** Candidate freshness accepts timestamps in a symmetric five-minute window and otherwise returns `TimestampOutsideWindow`; this source slice has no separate candidate-clock health state (`peer_gossip.rs:113-119,352-359,584-623`). Repository requirements separately require clock skew/drift handling for monotonic-counter-dependent handshake logic (`documents/Requirements.md:201`).

**Observed.** The gossip seed is encrypted, HKDF-derived, and zeroized. The daemon warns when derived key differs from its own membership `node_pubkey_hex`, but attachment can continue (`main.rs:474-488,552-579`; `daemon.rs:5570-5600,5684-5725`). The CLI permits explicit `key init-gossip --force`, changing identity without itself publishing membership rotation (`main.rs:549-556`). No endpoint changes today because gossip remains pre-I4 authority.

**Proposal.** Before PeerSignedV2 becomes enforced endpoint authority, make local gossip-key/membership-key mismatch fail closed for candidate mint/consumption. Use a separately reviewed owner-signed key rotation transaction rather than forced local replacement as normal operation. Add a candidate-specific clock-health outcome: anomaly blocks new candidate authority loudly; policy for retaining an already-proven fresh record must be explicit.

**Explore.** A safe transition may need staged old/new verification-key semantics. Do not use implicit overlap/HashMap residue. Find and integrate with an existing daemon clock supervisor if one exists rather than creating an incompatible second clock policy.

**Gate.** Inject backward/forward wall-clock jumps, pre-epoch failure, key mismatch, secret rotation before membership rotation, membership rotation before new key is live, and repaired rotation. Do not sleep for expiry. Assert logs/status reveal no secret seed, full candidate addresses, or needless identity data.

## 8. Standards and industry precedent — context only

These sources support verified candidate-pair checks, not an automatic choice of Rustynet protocol, timer, cryptography, or fallback policy.

- [RFC 8445 (ICE)](https://www.rfc-editor.org/rfc/rfc8445.html) defines a valid candidate pair through successful connectivity checks and requires candidate maintenance/refresh. This supports separating advertisement from exact-pair validation; Rustynet retains its own membership authorization, WireGuard semantics, and fail-closed policy.
- [RFC 7675 (consent freshness)](https://www.rfc-editor.org/rfc/rfc7675.html) distinguishes request/response consent evidence from one-way keepalives. This supports not treating local UDP send success as peer liveness; it does not specify Rustynet relay/gossip behavior.
- [Tailscale control/data-plane documentation](https://tailscale.com/docs/concepts/control-data-planes) distinguishes coordination state from encrypted data-plane traffic and notes that a control outage can preserve existing paths while blocking new state. Useful precedent only: it does not authorize Rustynet to cache/downgrade trust state.
- [Tailscale DERP documentation](https://tailscale.com/docs/reference/derp-servers) separates direct discovery/negotiation from relay fallback. It reinforces explicit traversal-authority, liveness-evidence, and relay-selection states instead of overloading a UDP send result.

## 9. Recommended implementation order

1. **Block raw consumption.** Privatize raw cache/ingest endpoint data and add an opaque coordinator-only handle. Keep PeerSignedV2 disabled as endpoint authority until every later item lands.
2. **Fix identity lifecycle.** Build exact active `NodeId <-> GossipKey` authorization; reject invalid/duplicate keys; require active local identity for every authority action; separate token-bound bootstrap delivery; atomically purge removed/rotated authority; retain replay watermarks independently.
3. **Constrain dissemination and ingress.** Derive ACL-scoped recipients before gossip retains/forwards metadata; resolve seed/relay topology exception explicitly; bind/firewall gossip to verified overlay ingress.
4. **Create typed candidate records.** Carry identity, membership generation, signed payload, expiry, and selection generation. Distinguish host address from server-reflexive endpoint; no port-zero or `SocketAddr`-only handoff.
5. **Define exact-pair evidence.** Reuse authoritative-UDP socket-incarnation and egress-barrier rules; prove authenticated session establishment at selected endpoint before overlay mutation.
6. **Solve cache, restart, and path loss.** Atomically bind cache to replay watermark or choose an independent authenticated resync design. Do not claim gossip heals a lost path it depends on.
7. **Add liveness supervision.** Add fatal-I/O detach/rebind, bounded backoff, and honest status. Do not broaden timers or add static fallback.
8. **Cut over exclusively.** Only a green deterministic fault matrix authorizes replacing V1 in a controlled rollout; live `--node` proof comes last.

## 10. Review limits and next questions

This is an evidence-backed design review, not approved implementation. It has not proved the final bootstrap/resync mechanism, wire format, cross-platform support, or staged key rotation policy. An independent adversarial source review completed on 2026-08-18; corrections are marked in sections 2, 2a, 3, 4, 5, and 6. Before code authorization, a design owner must still decide the bootstrap/resync channel, enrollment exception, and exact-pair evidence contract.

1. Can enrollment bootstrap be narrowed to a non-gossip capability without blocking D2.7 ordering?
2. Does membership/auto-tunnel commit permit one atomic traversal-authority generation?
3. Which restart approach avoids insecure cached endpoints and overlay-gossip bootstrap loop?
4. Which daemon clock supervisor, if any, owns candidate-freshness health?
5. Can PeerSignedV2 be platform-independent while gossip transport is Unix-only?
