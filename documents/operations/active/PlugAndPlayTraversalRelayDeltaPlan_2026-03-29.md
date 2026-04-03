# Rustynet Plug-and-Play Connectivity Delta Plan (UDP Hole Punching + Relay Fallback)
**Generated:** 2026-03-29
**Repository Root:** `/Users/iwanteague/Desktop/Rustynet`
**Scope:** Production-grade, secure, plug-and-play cross-network connectivity with direct UDP when possible and ciphertext-only relay fallback when direct is not provable.

## Execution Scope
```text
You are the implementation agent for the remaining plug-and-play connectivity work in this repository.
Repository root: /Users/iwanteague/Desktop/Rustynet
Output file to keep updated during the work: /Users/iwanteague/Desktop/Rustynet/documents/operations/active/PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md

Mission:
Implement the remaining code, tests, gates, and evidence needed for secure, plug-and-play cross-network Rustynet connectivity without relying on manual consumer-router port forwarding as the correctness path. The target product behavior is:
- users join a Rustynet,
- an authorized node can be selected as an exit,
- Rustynet automatically establishes either a direct UDP path or a relay path,
- traffic remains encrypted end-to-end,
- security controls remain fail-closed,
- users are not required to understand NAT, firewalls, or port forwarding.

Mandatory reading order:
1. /Users/iwanteague/Desktop/Rustynet/AGENTS.md
2. /Users/iwanteague/Desktop/Rustynet/CLAUDE.md
3. /Users/iwanteague/Desktop/Rustynet/README.md
4. /Users/iwanteague/Desktop/Rustynet/documents/Requirements.md
5. /Users/iwanteague/Desktop/Rustynet/documents/SecurityMinimumBar.md
6. /Users/iwanteague/Desktop/Rustynet/documents/phase10.md
7. /Users/iwanteague/Desktop/Rustynet/documents/operations/active/UdpHolePunchingAndRelayTraversalPlan_2026-03-07.md
8. /Users/iwanteague/Desktop/Rustynet/documents/operations/active/UdpHolePunchingHP2IngestionPlan_2026-03-07.md
9. /Users/iwanteague/Desktop/Rustynet/documents/operations/active/MasterWorkPlan_2026-03-22.md
10. /Users/iwanteague/Desktop/Rustynet/documents/operations/active/CrossNetworkRemoteExitNodePlan_2026-03-16.md
11. This document
12. The code you touch

Hard truth you must respect:
- Membership and signed control state do not create reachability by themselves.
- Plug-and-play across arbitrary user networks requires direct-first transport plus a real relay fallback.
- NAT-PMP/PCP/UPnP are optimizations only.
- Manual router port forwarding must not be the baseline correctness path.
- Users must not need networking expertise to obtain connectivity.
- The production relay data plane for this scope is allocated-port demultiplexing, not authenticated per-packet framing.

Non-negotiables:
- Keep one hardened execution path for every security-sensitive workflow.
- Fail closed on missing, stale, invalid, replayed, malformed, or unauthorized state.
- Do not add legacy fallback branches, insecure compatibility paths, or router-dependent correctness assumptions.
- Do not mark any path as active/live unless measured liveness proof exists.
- Do not describe Rustynet as plug-and-play across the internet unless both direct and relay outcomes are honestly implemented and evidenced.
- Do not weaken tests or gates to pass.
- Do not leave TODO/FIXME/placeholders for in-scope deliverables.
- Do not replace the allocated-port relay plan in this document with a different production data-plane design unless the document, tests, and security rationale are updated together in one change.

Execution workflow:
1. Reconcile stale or conflicting traversal/relay status text in docs with current code and runtime evidence before adding new claims.
2. Fix correctness defects in candidate acquisition and transport socket binding first.
3. Finish the missing direct-path runtime behavior needed for real WAN simultaneous-open.
4. Finish the relay runtime so `relay_programmed` can become `relay_active` with real session and traffic proof.
5. Finish public relay server/runtime wiring and operator deployment path.
6. Harden token/session refresh, failover/failback, and roaming behaviors.
7. Update tests, CI gates, live scripts, and evidence artifacts so they fail closed on unproven path states.
8. Keep this document updated as implementation progresses; do not maintain a private checklist.

Repository-standard validation for substantial code work:
- cargo fmt --all -- --check
- cargo clippy --workspace --all-targets --all-features -- -D warnings
- cargo check --workspace --all-targets --all-features
- cargo test --workspace --all-targets --all-features
- cargo audit --deny warnings
- cargo deny check bans licenses sources advisories

Scope-specific validation:
- ./scripts/ci/phase10_hp2_gates.sh
- ./scripts/ci/phase10_gates.sh
- ./scripts/ci/phase10_cross_network_exit_gates.sh
- ./scripts/ci/membership_gates.sh
- targeted rustynetd traversal, phase10, relay_client, rustynet-relay transport, and control-plane token tests
- live cross-network direct, relay, failback, DNS, adversarial, and soak scripts when the environment exists

Definition of done for this document:
- direct candidate acquisition is correct and no longer assumes a guessed public port,
- direct probing uses the right transport/socket semantics for real WAN simultaneous-open,
- relay runtime can establish, refresh, and use authenticated ciphertext-only relay sessions,
- `path_mode` and `path_live_proven` are honest for both direct and relay,
- plug-and-play cross-network connectivity works without manual router port forwarding as the correctness path,
- all required tests/gates/evidence are present and passing,
- no in-scope items are deferred.
```

## Execution And Progress Contract
This file must also function as the implementation ledger for the agent carrying out the work.

Execution rules:
1. Treat every checklist item in this document as public state, not private scratch work.
2. Keep the relevant checklist item unchecked until the completion criteria below are fully satisfied, then update it from `[ ]` to `[x]`.
3. Never mark an item complete based on code edits alone. A checkbox may be marked complete only when:
   - code is implemented,
   - the relevant tests/gates were run and passed,
   - the evidence entry for that item is updated in this file.
4. If an item is partially complete or blocked, leave it unchecked and add a short `Blocked:` or `In progress:` note under the phase or in the progress ledger.
5. If the implementation changes scope or invalidates an earlier claim, update this document immediately before continuing.
6. Do not maintain a separate hidden checklist. This file is the source of truth for progress.

Required progress hygiene:
- Keep the phase checklists in Section 12 current.
- Keep the evidence ledger in Section 18 current.
- For every completed slice, record:
  - files changed,
  - tests/gates run,
  - live evidence or artifacts produced,
  - any security invariants explicitly verified.

## 1. Executive Summary
This document is the delta plan for making Rustynet behave like a plug-and-play mesh VPN across unrelated networks.

The key conclusion is simple:
- **Direct UDP hole punching is necessary but not sufficient.**
- **Ciphertext-only relay fallback is mandatory for robust plug-and-play behavior.**
- **Manual router port forwarding may remain an optional power-user optimization, but it must not be the baseline correctness path.**

The repository already contains significant traversal and relay groundwork, but it is not yet a finished, user-transparent transport system. The highest-value remaining work is:
1. correct public candidate acquisition using the right socket and the right mapped port,
2. full WAN simultaneous-open behavior on the active runtime path,
3. real relay runtime integration and live relay transport,
4. measured evidence and gates for both direct and relay outcomes.

## 2. What This Document Resolves
This document exists because the repository contains both real implementation progress and stale or optimistic status text.

Current authoritative truth must come from:
1. `documents/Requirements.md`
2. `documents/SecurityMinimumBar.md`
3. `documents/phase10.md`
4. current runtime evidence
5. lower-precedence active plans only insofar as they still match code reality

Supporting implementation plan for the remaining production shared-transport delta:
- [ProductionTransportOwningWireGuardBackendPlan_2026-03-31.md](./ProductionTransportOwningWireGuardBackendPlan_2026-03-31.md)

Where documents conflict:
- [README.md](/Users/iwanteague/Desktop/Rustynet/README.md) and [phase10.md](/Users/iwanteague/Desktop/Rustynet/documents/phase10.md) currently state that full production WAN simultaneous-open and full relay transport are still open work.
- some lower-precedence active traversal notes claim more completion than current live evidence supports.
- this document resolves those conflicts in favor of the stricter, runtime-proven interpretation.

## 3. Product Outcome We Are Targeting
The target user experience is:
1. user installs Rustynet,
2. user joins a Rustynet using accepted credentials,
3. another authorized node is selected as an exit,
4. Rustynet automatically establishes transport:
   - direct UDP if possible,
   - relay if direct is not proven quickly,
5. traffic routes through the exit node securely,
6. the user never has to manually configure a home router or understand NAT.

The user should not need to know whether the transport is:
- direct to exit, or
- relayed to exit.

Diagnostics may expose that distinction, but the baseline UX must not depend on user networking knowledge.

## 4. Non-Negotiable Architecture Rules
1. **Exit node and relay are different roles.**
   - exit node terminates the encrypted tunnel and forwards internet/LAN traffic,
   - relay only forwards ciphertext packets to help two peers reach each other.
2. **Relay is not optional for plug-and-play.**
   - some real user networks will never support direct P2P reliably.
3. **Direct path is an optimization; relay is the correctness fallback.**
4. **NAT-PMP/PCP/UPnP are opportunistic only.**
5. **No unsigned endpoint mutation.**
6. **No programmed-vs-live confusion in status or gates.**
7. **One hardened path only.**
   - `verified traversal state -> deterministic controller decision -> transport/backend apply`
8. **Allocated-port relay demux is the chosen production fallback design for this scope.**
   - authenticated-framing relay transport is explicitly out of scope for the current implementation plan.

## 5. External Standards and Primary References
These references define the network reality and security expectations that Rustynet must respect:

- RFC 8445 (ICE): candidate gathering, candidate pairs, connectivity checks, nomination, consent model
  - https://www.rfc-editor.org/rfc/rfc8445
- RFC 5389 (STUN): server reflexive discovery primitives
  - https://www.rfc-editor.org/rfc/rfc5389
- RFC 8656 (TURN): relay allocation and relayed transport model
  - https://www.rfc-editor.org/rfc/rfc8656
- RFC 7675 (STUN Consent Freshness): ongoing consent/liveness requirements on an active 5-tuple
  - https://www.rfc-editor.org/rfc/rfc7675
- RFC 4787: NAT UDP behavior variability and mapping/filtering constraints
  - https://www.rfc-editor.org/rfc/rfc4787
- RFC 5128: P2P across NATs, including when UDP hole punching fails
  - https://www.rfc-editor.org/rfc/rfc5128
- RFC 6887 (PCP): optional port mapping as an optimization, not a universal solution
  - https://www.rfc-editor.org/rfc/rfc6887
- Tailscale engineering write-up on NAT traversal: practical direct-first plus relay fallback operating model
  - https://tailscale.com/blog/how-nat-traversal-works
- Tailscale DERP documentation: public relay fleet behavior, encrypted relay semantics, directory-distributed region selection
  - https://tailscale.com/docs/reference/derp-servers

Primary implications for Rustynet:
- direct success depends on NAT behavior and cannot be guaranteed,
- server-reflexive candidates must represent the actual socket/port pair that will later exchange peer traffic,
- relaying is a standard, necessary fallback for hard NAT cases,
- auto port mapping can help but cannot be the main connectivity design,
- active paths need a consent/liveness mechanism that is bound to the actual transport 5-tuple,
- best-in-class systems use relay as a transparent correctness fallback and upgrade to direct only after measured proof.

## 6. Current Repository State
### 6.1 What Exists Today
The following capabilities already exist in the codebase:

#### Control Plane / Signed State
- signed endpoint-hint bundles and traversal coordination records in [crates/rustynet-control/src/lib.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-control/src/lib.rs)
- relay session token type and signature verification in [crates/rustynet-control/src/lib.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-control/src/lib.rs)
- endpoint-hint signing key derivation reuse via `derive_endpoint_hint_signing_key(...)`

#### Daemon / Traversal Runtime
- traversal hint validation, watermark/replay checks, and authoritative indexing in [crates/rustynetd/src/daemon.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/daemon.rs)
- traversal engine and deterministic direct probe planning in [crates/rustynetd/src/traversal.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/traversal.rs)
- traversal probe evaluation and path commit in [crates/rustynetd/src/phase10.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/phase10.rs)
- explicit programmed/live path reporting in [crates/rustynetd/src/daemon.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/daemon.rs)
- STUN client wiring and `stun_candidates` status exposure in [crates/rustynetd/src/stun_client.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/stun_client.rs) and [crates/rustynetd/src/daemon.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/daemon.rs)

#### Relay Pieces
- relay client module in [crates/rustynetd/src/relay_client.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/relay_client.rs)
- relay transport auth/forwarding core in [crates/rustynet-relay/src/transport.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-relay/src/transport.rs)
- relay fleet selection primitives in [crates/rustynet-relay/src/lib.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-relay/src/lib.rs)

#### Operational Surface
- direct, relay, failback, DNS, adversarial, and soak live scripts under [scripts/e2e](/Users/iwanteague/Desktop/Rustynet/scripts/e2e)
- phase10 and HP2 gates under [scripts/ci](/Users/iwanteague/Desktop/Rustynet/scripts/ci)

### 6.2 What Is Honest and Working Today
These things are materially implemented and should be treated as existing baseline, not future work:
- signed traversal validation and replay bounds
- live/proven vs programmed/path-state truthfulness in `status` and `netcheck`
- bounded traversal probe planning
- relay session token cryptography and relay transport core security controls
- daemon-side relay client scaffolding and token refresh timing model

### 6.3 What Is Still Missing or Incomplete
These items are still missing, incomplete, or not yet proven live enough for plug-and-play claims:
- correct srflx candidate acquisition on the actual transport socket/port
- end-to-end production WAN simultaneous-open behavior on the active runtime path
- fully live relay path in daemon/runtime with measured traffic proof
- production relay service binary/runtime (not just library primitives)
- operator deployment path for a reachable relay fleet
- live cross-network evidence that does not depend on manual router work

## 7. Current Live Evidence and What It Proves
The recent cross-network lab produced these facts:
- signed membership/assignment/traversal state worked,
- client selected the exit correctly,
- direct probe attempts occurred,
- neither side achieved a live handshake,
- both sides observed outbound attempts,
- neither side observed reliable inbound WireGuard packets,
- client ended in `path_mode=relay_programmed` with `relay_session_disabled`.

What this proves:
- the policy plane is not the blocker,
- the transport plane is the blocker,
- direct WAN traversal is not yet robust in the tested topology,
- relay fallback is still not live enough to recover when direct fails,
- the current product cannot yet claim plug-and-play cross-network behavior.

What this does **not** prove:
- that direct traversal would fail for all real physical hosts,
- that traversal logic is absent,
- that relay transport core cryptography is missing.

## 8. Critical Current Defects That Must Be Fixed First
These are not optional improvements. They are correctness bugs or architectural gaps.

### 8.1 STUN Candidate Port Is Currently Guessed, Not Discovered
**Files:**
- [crates/rustynetd/src/stun_client.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/stun_client.rs)
- [crates/rustynetd/src/daemon.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/daemon.rs)

**Current behavior:**
- `StunClient::query_stun_server(...)` binds `0.0.0.0:0`, i.e. an ephemeral port.
- `gather_public_ips()` returns only `IpAddr`, not full mapped `SocketAddr`.
- `poll_stun_results()` later reconstructs srflx candidates by attaching `self.wg_listen_port` to the discovered public IP.

**Why this is wrong:**
- the NAT mapping observed by STUN is for the ephemeral STUN socket, not necessarily the WireGuard socket,
- the NAT may not preserve the local port,
- attaching `wg_listen_port` to the public IP is a guess, not a measured mapped endpoint,
- this can produce false srflx candidates and failed direct probes.

**Required fix:**
- STUN gathering must return the full mapped public `SocketAddr`, not just IP,
- the STUN probe must use the same UDP socket or the same bound local port that later carries peer traffic,
- candidate publication must stop assuming the public port equals `wg_listen_port`.

**Minimum implementation direction:**
1. redesign [crates/rustynetd/src/stun_client.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/stun_client.rs) to return `Vec<SocketAddr>` or richer candidate structs,
2. stop using `SocketAddr::new(ip, self.wg_listen_port)` in daemon runtime,
3. tie candidate discovery to the active transport socket semantics.

### 8.2 Relay Client Binds a Separate Ephemeral Socket Despite Its Own Security Comment
**Files:**
- [crates/rustynetd/src/relay_client.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/relay_client.rs)
- [crates/rustynetd/src/daemon.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/daemon.rs)

**Current behavior:**
- `RelayClient::bind(...)` documentation says it should use the same socket as WireGuard traffic so NAT mappings are shared.
- `load_relay_client(...)` currently binds `UdpSocket::bind(..., 0)`, i.e. another ephemeral socket.

**Why this is wrong:**
- relay session establishment occurs on a different socket identity than the socket used for actual peer traffic,
- NAT bindings and public source tuples will diverge,
- relay hello/session allocation may not correspond to the transport socket that later sends packets.

**Required fix:**
- relay session establishment and relay transport usage must share the active transport socket identity,
- or the backend must be explicitly redesigned so the same socket handles both direct and relay transport.

### 8.3 `rustynet-relay` Main Binary Is Still a Placeholder, Not a Production Relay Service
**Files:**
- [crates/rustynet-relay/src/main.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-relay/src/main.rs)
- [crates/rustynet-relay/src/lib.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-relay/src/lib.rs)
- [crates/rustynet-relay/src/transport.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-relay/src/transport.rs)

**Current behavior:**
- the `main.rs` binary only selects a relay from an in-memory fleet and prints a startup line,
- it does not bind a public UDP port,
- it does not deserialize `RelayHello`, manage live sockets, or forward packets between actual peers.

**Required fix:**
- implement a real relay daemon binary with public UDP listener(s), hello/ack wire handling, session table, transport forwarding loop, metrics, config, and clean shutdown.

### 8.4 Relay Runtime Exists But Is Not Yet the Product-Correct Fallback Path
**Files:**
- [crates/rustynetd/src/daemon.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/daemon.rs)
- [crates/rustynetd/src/phase10.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/phase10.rs)
- [crates/rustynetd/src/relay_client.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/relay_client.rs)

**Current symptom:**
- live runs end in `relay_programmed` / `relay_session_disabled` or otherwise unproven relay state instead of `relay_active` with liveness proof.

**Required fix:**
- a relay candidate must be backed by a real reachable relay server,
- a relay path must only be considered live when:
  - session token is valid,
  - relay session is established,
  - traffic or fresh handshake proof exists through the relay,
  - no policy or kill-switch invariant is bypassed.

### 8.5 Relay Data-Plane Demultiplexing and On-Wire Session Semantics Are Still Underspecified
**Files:**
- [crates/rustynet-relay/src/transport.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-relay/src/transport.rs)
- [crates/rustynet-relay/src/session.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-relay/src/session.rs)
- [crates/rustynet-relay/src/main.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-relay/src/main.rs)
- [crates/rustynetd/src/relay_client.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/relay_client.rs)

**Current behavior:**
- `RelayTransport::forward_packet(...)` expects the caller to already know which `session_id` owns an incoming datagram.
- `RelaySession` tracks identity, peer, allocation, and expiry metadata, but not the full live ingress/egress UDP dispatch contract for a running server.
- `main.rs` does not yet define how incoming UDP packets are mapped to sessions on the public listener.

**Why this is a problem:**
- the relay wire model is not yet specific enough for an implementation agent to safely fill in the missing pieces without guessing,
- a guessed demultiplexing scheme risks creating multiple transport paths, inconsistent NAT behavior, or a security bug in packet attribution,
- without an explicit dispatch contract, it is easy to accidentally build an open proxy or a session-confusion bug.

**Required fix:**
- define one hardened relay data-plane contract and implement only that contract.
- for this scope, the chosen contract is **allocated-port relay demultiplexing**.
- the contract must specify, at minimum:
  1. which UDP port(s) receive hello/auth traffic,
  2. which UDP port(s) receive relayed ciphertext traffic,
  3. how an inbound datagram is attributed to exactly one authenticated relay session by allocated relay port,
  4. how the server distinguishes pre-allocation control traffic from post-allocation ciphertext forwarding traffic,
  5. how the server binds a session to the observed peer transport tuple and refreshes or rejects tuple changes,
  6. how replay, spoofing, stale tuple reuse, and session cross-talk are rejected.

**Implementation constraint:**
- implement allocated-port demultiplexing only in production paths for this scope.
- do not add authenticated per-packet relay framing as a second production path.
- if authenticated-framing is ever explored later, it must be introduced only by a new design/change document with separate security review and tests.

## 9. Desired End-State Architecture
### 9.1 User-Visible Model
The user model must be:
- join network,
- select exit,
- Rustynet connects,
- traffic works.

The user must not be asked to:
- configure router port forwards,
- understand STUN, NAT, ICE, TURN, or relays,
- paste public IPs,
- manually choose direct vs relay.

### 9.2 Runtime Transport State Machine
The runtime should converge through a single deterministic controller.

Required logical states:
- `direct_programmed`
- `direct_active`
- `relay_programmed`
- `relay_active`
- `mixed_active` only if strictly necessary during transitions and never as a persistent ambiguity
- `fail_closed`

Required transition rules:
1. start with signed traversal authority only,
2. gather fresh local candidates,
3. attempt direct via candidate pairs,
4. if direct is not proven within bounded policy, establish relay,
5. once relay is live, route via relay,
6. keep reprobeing direct in the background,
7. fail back to direct only after fresh proof,
8. close stale relay sessions after successful direct recovery,
9. fail closed if neither trusted direct nor trusted relay is available.

Active-path liveness requirement:
- Rustynet must maintain ongoing proof that the currently selected path is still permitted and live.
- If Rustynet adopts STUN consent freshness directly, it must follow a request/response model bound to the active 5-tuple.
- If Rustynet instead uses a WireGuard-native or Rustynet-native liveness mechanism, the implementation must document and test why that mechanism is equivalent in security outcome for continuing to send traffic.
- In all cases, the implementation must stop transmitting on an unproven path within a bounded timeout.

### 9.3 Candidate Model
Required candidate classes:
- `host`
- `srflx`
- `relay`

Candidate requirements:
- bounded count
- bounded serialized size
- no duplicates
- no RFC1918/CGNAT relay transport candidates for public relay use
- no guessed port numbers
- freshness-bounded signed publication
- no endpoint mutation from unsigned or stale candidate sets

### 9.4 Relay Model
Relay is **not** the exit node.
Relay is a ciphertext forwarder between client and exit.

Path options:
- direct: `client <-> exit`
- relayed: `client <-> relay <-> exit`

Security requirements:
- relay sees ciphertext only,
- relay never decrypts or rewrites inner payloads,
- relay is token-scoped to specific node pairs and relay IDs,
- relay is not an open proxy,
- relay is bounded and rate-limited.

Chosen v1 relay data-plane design:
- post-authentication forwarding uses an **allocated relay UDP port** returned by the relay server,
- the client/backend targets `relay_ip:allocated_port` as the relay endpoint for ciphertext transport,
- the relay attributes inbound ciphertext datagrams to sessions by allocated relay port and session ownership rules,
- authenticated per-packet outer relay framing is **not** part of the v1 production design.

Why this choice is correct for the product:
- it matches the current repo shape (`allocated_port` already exists in session and ack models),
- it minimizes custom transport invention,
- it reduces per-packet complexity and MTU overhead,
- it is easier to integrate with the current backend endpoint model,
- it is operationally sufficient for the intended residential/small-network scale.

## 10. File-by-File Delta Plan
This section is the most important implementation map in the document.

### 10.1 [crates/rustynetd/src/stun_client.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/stun_client.rs)
**Current role**
- basic STUN binding request/response parser
- returns public IPs only
- binds ephemeral socket itself
- IPv4-only

**Problems**
- wrong abstraction: returns IP instead of mapped endpoint
- wrong socket ownership: STUN client owns its own socket
- wrong NAT semantics for srflx publication
- no IPv6 support
- not suitable for real ICE-like checks

**Required changes**
1. Replace `gather_public_ips()` with an API that returns measured mapped endpoints and metadata.
2. Accept a caller-provided UDP socket or transport binding instead of creating an unrelated ephemeral socket.
3. Return `SocketAddr`, not just `IpAddr`.
4. Preserve enough metadata to distinguish candidates by source and family.
5. Add IPv6 XOR-MAPPED-ADDRESS support if IPv6 is intended to be first-class; otherwise make IPv6 fail-closed policy explicit.
6. Bound parsing strictly and fuzz/negative-test malformed attributes.

**Correct result**
- srflx candidate = actual public endpoint for the transport socket that will later attempt peer traffic.

### 10.2 [crates/rustynetd/src/traversal.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/traversal.rs)
**Current role**
- candidate validation
- probe plan generation
- `execute_simultaneous_open(...)`
- NAT profile logic and tests

**What exists**
- deterministic direct probe planning
- local+remote candidate pairing
- relay fallback decision when direct fails
- adversarial/hard-NAT tests exist

**What still needs work**
1. Reconcile current runtime behavior with the stated simultaneous-open design so the active runtime is not effectively one-sided.
2. Ensure the probe runtime uses the correct socket semantics and true candidate endpoints.
3. Add stronger coordination schedule semantics if current schedule values are placeholders.
4. Ensure simultaneous-open decisions are driven by measured transport reality, not just synthetic endpoint programming.
5. Add explicit per-candidate-pair audit reason codes for rejection.
6. Add stronger NAT profile classification and diagnostics tied to live evidence.

**What to avoid**
- a second endpoint authority path,
- assignment-endpoint fallback,
- speculative “direct_active” claims without handshake proof.

### 10.3 [crates/rustynetd/src/phase10.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/phase10.rs)
**Current role**
- path controller
- probe evaluation integration
- peer reconfiguration

**What exists**
- direct/relay decision commit into the managed peer controller
- reconfigure peer endpoint on decision
- current path transitions preserve controller ownership

**What still needs work**
1. Ensure direct and relay transports are modeled as real transport paths, not just endpoint swaps.
2. Add transition invariants covering continuous encryption, ACL persistence, DNS fail-close persistence, and kill-switch persistence.
3. Add tests for direct->relay->direct transitions under live traffic.
4. Add tests that direct and relay active states require proof, not just programming.
5. Ensure relay path transitions do not accidentally destroy or bypass active WireGuard session semantics.

### 10.4 [crates/rustynetd/src/daemon.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/daemon.rs)
**Current role**
- runtime orchestration
- STUN result polling
- relay client loading
- signed traversal lifecycle
- status/netcheck output
- refresh cadence and reprobes

**Current strengths**
- path-state truthfulness is much better than before
- traversal/relay/session diagnostics exist
- relay client refresh hooks exist

**Required changes**
1. Stop reconstructing srflx candidates by guessed port.
2. Rework STUN and relay socket ownership to use the active transport socket model.
3. Make `relay_session_disabled` an opt-in operator state only; it must not be the default result of a supposedly plug-and-play cross-network path when relay is configured.
4. Add relay fleet/directory loading and policy selection for real relay candidates.
5. Make relay session establishment mandatory before `relay_programmed` is surfaced as usable.
6. Ensure status/netcheck report `relay_active` only with real liveness proof.
7. Add explicit metrics and audit logs for:
   - session establishment
   - session refresh
   - session expiry
   - relay->direct failback
   - direct->relay failover reason

### 10.5 [crates/rustynetd/src/relay_client.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/relay_client.rs)
**Current role**
- client-side relay hello/session establishment
- session refresh/cleanup
- keepalive model

**Strengths**
- solid security model in comments and token handling
- token refresh timing helper
- bounded config and tests

**Required changes**
1. Stop using a dedicated ephemeral socket for relay establishment.
2. Bind direct-path STUN and probing to the real transport socket identity.
3. For relay, implement the allocated-port transport path defined in this document and ensure its transport identity rules are explicit and test-backed.
4. Add explicit packet I/O APIs or transport shims if backend needs to send/receive through relay in a controlled way.
5. Add tests that session establishment, refresh, and live traffic operate on the documented transport identity model and do not silently split across multiple socket identities.

### 10.6 [crates/rustynet-relay/src/transport.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-relay/src/transport.rs)
**Current role**
- secure relay transport core
- token auth
- session establishment semantics
- in-memory forwarding/session cleanup

**Strengths**
- constant-time auth checks
- replay protection
- rate limiting
- capacity limits
- ciphertext-only forwarding model

**Still needed**
1. Integrate with a real relay daemon network loop.
2. Add exact allocated-port dispatch and socket handling for real UDP traffic.
3. Add metrics hooks and operational visibility.
4. Add abuse controls beyond per-node/session caps where required by deployment.
5. Add cluster/fleet-facing concerns only after single-node correctness is solid.
6. Add tests proving that one inbound datagram can map to only one authenticated session and can never be forwarded cross-session.

### 10.7 [crates/rustynet-relay/src/main.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-relay/src/main.rs)
**Current role**
- placeholder selection demo

**Required changes**
1. Replace with a real relay daemon binary.
2. Add config/env parsing for:
   - UDP bind addresses
   - control verifier key path
   - relay ID
   - region/metadata
   - rate-limit/session-cap config
   - metrics/logging bind addresses if present
3. Implement real receive loop:
   - parse hello
   - send ack/reject
   - allocate and manage relay UDP ports
   - accept ciphertext packets on allocated relay ports
   - dispatch via `RelayTransport`
4. Add graceful shutdown and periodic cleanup.
5. Add operator-safe logs with no secret leakage.

### 10.8 [crates/rustynet-control/src/lib.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-control/src/lib.rs)
**Current role**
- endpoint-hint issuance/verification
- relay session token definitions and signing

**Required changes**
1. Make relay directory/fleet data a real signed control-plane object, not just a library primitive elsewhere.
2. Ensure relay candidate publication is based on real reachable relay infrastructure.
3. Add explicit relay selection policy inputs if needed:
   - preferred region
   - allowed regions
   - health state
4. Keep relay token signing scoped to ciphertext-forward-only semantics.
5. If the control-plane surface grows beyond maintainability, split relay-specific control-plane logic into a dedicated module under `crates/rustynet-control/src/`.

### 10.9 [crates/rustynet-relay/src/lib.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-relay/src/lib.rs)
**Current role**
- fleet selection primitives

**Required changes**
1. Keep selection primitives but ensure they are not mistaken for a full relay service.
2. Extend only as necessary for runtime relay directory consumption and health scoring.
3. Avoid growing transport/runtime logic into this file; keep that in dedicated modules.

### 10.10 [crates/rustynetd/src/main.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/main.rs)
**Required changes**
- add/verify config flags and env support for:
  - relay directory path / verifier path if separate from traversal bundle
  - relay bind/metrics config if the daemon must know them
  - explicit socket ownership model for STUN/relay/backend integration
  - optional NAT-PMP/PCP/UPnP knobs as opportunistic helpers only
- fail closed on invalid combinations

### 10.11 [scripts/e2e](/Users/iwanteague/Desktop/Rustynet/scripts/e2e)
**Required changes**
Update or create live scripts so they prove the actual product promise:
- direct remote exit works when NATs permit,
- relay remote exit works when direct does not,
- relay->direct failback works when direct later becomes healthy,
- adversarial traversal inputs are rejected,
- DNS remains fail-closed during path churn,
- soak remains stable over expiry/refresh windows.

At minimum, keep these scripts current:
- [live_linux_cross_network_direct_remote_exit_test.sh](/Users/iwanteague/Desktop/Rustynet/scripts/e2e/live_linux_cross_network_direct_remote_exit_test.sh)
- [live_linux_cross_network_relay_remote_exit_test.sh](/Users/iwanteague/Desktop/Rustynet/scripts/e2e/live_linux_cross_network_relay_remote_exit_test.sh)
- [live_linux_cross_network_failback_roaming_test.sh](/Users/iwanteague/Desktop/Rustynet/scripts/e2e/live_linux_cross_network_failback_roaming_test.sh)
- [live_linux_cross_network_remote_exit_dns_test.sh](/Users/iwanteague/Desktop/Rustynet/scripts/e2e/live_linux_cross_network_remote_exit_dns_test.sh)
- [live_linux_cross_network_remote_exit_soak_test.sh](/Users/iwanteague/Desktop/Rustynet/scripts/e2e/live_linux_cross_network_remote_exit_soak_test.sh)
- [live_linux_cross_network_traversal_adversarial_test.sh](/Users/iwanteague/Desktop/Rustynet/scripts/e2e/live_linux_cross_network_traversal_adversarial_test.sh)

### 10.12 [scripts/ci](/Users/iwanteague/Desktop/Rustynet/scripts/ci)
**Required changes**
Gates must fail closed on:
- guessed public candidates,
- `relay_programmed` without session/liveness proof,
- `direct_active` without handshake proof,
- stale commit-bound artifacts,
- cross-network reports claiming success from programmed state only.

Keep current gates current:
- [phase10_hp2_gates.sh](/Users/iwanteague/Desktop/Rustynet/scripts/ci/phase10_hp2_gates.sh)
- [phase10_cross_network_exit_gates.sh](/Users/iwanteague/Desktop/Rustynet/scripts/ci/phase10_cross_network_exit_gates.sh)
- [phase10_gates.sh](/Users/iwanteague/Desktop/Rustynet/scripts/ci/phase10_gates.sh)
- [membership_gates.sh](/Users/iwanteague/Desktop/Rustynet/scripts/ci/membership_gates.sh)

## 11. What Already Exists vs What Must Be Built
### 11.1 Already Exists
- signed traversal state
- candidate typing (`host`, `srflx`, `relay`)
- traversal probe planning
- programmed/live status honesty
- relay session token cryptography
- relay transport security core
- relay client scaffolding

### 11.2 Must Be Built or Corrected
- correct srflx endpoint acquisition on the right socket
- true runtime socket-sharing model for STUN, relay, and peer traffic
- production relay server binary/runtime
- full relay path integration in daemon/backend/runtime
- measured live relay fallback and failback
- live physical-network/WAN evidence

## 12. Implementation Order (Strict)
### Phase A: Correct Candidate Acquisition and Socket Identity
This phase must happen first because bad candidates poison everything above them.

Tasks:
- [x] Fix STUN to return full mapped endpoints.
- [x] Stop guessing public port from `wg_listen_port`.
- [ ] Align STUN gathering with actual transport socket identity.
  - Verified 2026-03-31: [crates/rustynet-backend-api/src/lib.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-api/src/lib.rs), [crates/rustynetd/src/stun_client.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/stun_client.rs), [crates/rustynetd/src/phase10.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/phase10.rs), and [crates/rustynetd/src/daemon.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/daemon.rs) now define and consume an explicit backend-owned authoritative shared-transport round-trip contract for STUN refresh plus transport-identity diagnostics, and the in-memory backend proves that path under test; current production WireGuard backends still report an opaque-socket blocker, so live completion remains unresolved until a production backend mode actually owns peer datagrams.
  - Verified 2026-03-31: non-default backend mode names `linux-wireguard-userspace-shared` and `macos-wireguard-userspace-shared` now parse in [crates/rustynetd/src/main.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/main.rs) and survive host-profile enforcement in [start.sh](/Users/iwanteague/Desktop/Rustynet/start.sh), but [crates/rustynetd/src/daemon.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/daemon.rs) still rejects them fail-closed with a precise blocker because no production transport-owning backend exists in-tree yet.
- [ ] Align relay session establishment with the documented transport identity model.
  - Verified 2026-03-31: [crates/rustynet-backend-api/src/lib.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-api/src/lib.rs), [crates/rustynetd/src/relay_client.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/relay_client.rs), [crates/rustynetd/src/phase10.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/phase10.rs), and [crates/rustynetd/src/daemon.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/daemon.rs) now route relay hello/refresh and keepalive through the same backend-owned authoritative shared-transport contract when a backend provides it, and the in-memory backend proves that establish/keepalive path under test; production WireGuard backends still surface an opaque-socket blocker and remain unresolved until a production backend mode actually owns peer datagrams.
- [x] Add unit tests and live diagnostics proving candidate correctness.
  - Verified 2026-03-30: [stun_client.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/stun_client.rs) now has mock-server and malformed-response coverage for provided-socket identity and strict bounds checking, and [daemon.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/daemon.rs) now exposes `stun_candidate_local_addrs` and `stun_transport_port_binding` in status/netcheck so transport-identity mismatches are explicit.

Success criteria:
- published srflx candidates correspond to measured public socket tuples,
- status/netcheck report actual tuples, not reconstructed guesses.

### Phase B: Finish Direct WAN Simultaneous-Open on the Live Runtime Path
Tasks:
- [x] Reconcile traversal engine design with active runtime behavior.
  - Verified 2026-03-30: [daemon.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/daemon.rs), [phase10.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/phase10.rs), and [traversal.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/traversal.rs) now carry validated signed coordination from the signed traversal bundle set into live direct-probe execution; the runtime no longer fabricates a zeroed `CoordinationSchedule`.
- [x] Ensure direct probe executor is truly two-sided where required.
  - Verified 2026-03-30: coordinated simultaneous-open is now only attempted when a validated signed coordination schedule exists for the local/remote node pair; otherwise the runtime declines direct and stays on relay, or fail-closes when no relay exists.
- [x] Make the active runtime prove direct path using fresh handshake evidence.
  - Verified: handshake_is_fresh() checks timestamp before declaring success
- [ ] Add roaming and re-probe correctness tests.
  - In progress 2026-03-30: relay->direct recovery and live-handshake retention regression coverage now use fresh signed coordination refreshes, but broader roaming/network-change coverage is still open.
- [x] Add active-path liveness / consent-equivalent expiry tests for direct mode.
  - Verified 2026-03-30: `daemon_runtime_auto_tunnel_direct_liveness_expiry_falls_back_to_relay` proves stale direct handshake evidence demotes runtime state back to relay-programmed/unproven instead of retaining a stale `direct_active` claim.

Success criteria:
- direct path succeeds in permissive NAT scenarios without manual router work,
- direct failure is honest and bounded,
- direct-active means proven, not programmed.

### Phase C: Finish Relay Runtime Integration
Tasks:
- [x] Implement real relay daemon binary/runtime.
  - Added: crates/rustynet-relay/src/main.rs with full daemon implementation
  - Uses allocated-port demultiplexing per design
  - Parses RelayHello, allocates ports, forwards ciphertext
- [x] Define and implement the allocated-port relay data-plane contract.
  - Verified 2026-03-30: `crates/rustynet-relay/src/session.rs`, `crates/rustynet-relay/src/transport.rs`, and `crates/rustynet-relay/src/main.rs` now keep tuple attribution single-authority inside `RelayTransport`, bind the post-allocation dataplane tuple only from the hello-observed source IP, reject later tuple changes and unauthorized keepalive, replace same-pair sessions deterministically, and clear attribution before port reuse.
- [ ] Wire daemon relay client to real relay infrastructure.
  - In progress 2026-03-31: `crates/rustynetd/src/relay_client.rs`, `crates/rustynetd/src/phase10.rs`, and `crates/rustynetd/src/daemon.rs` now execute relay hello/refresh and keepalive through the explicit backend-owned authoritative shared-transport contract when available, and the in-memory backend proves the same-authority transport model under test; full completion still requires a production backend mode because current Linux/macOS WireGuard backends expose only opaque OS-managed peer-traffic sockets.
- [ ] Ensure relay session establishment and refresh are live.
  - In progress 2026-03-30: local runtime tests cover establishment, refresh, fail-closed failure, and relay-active truthfulness, but full completion still depends on the shared backend transport-socket identity from Phase A plus live cross-network evidence.
- [ ] Ensure backend traffic can actually traverse the relay path.
  - In progress 2026-03-30: `relay_active` now requires the selected backend endpoint to match the authenticated relay session endpoint plus fresh handshake evidence; end-to-end live dataplane proof is still pending shared-socket wiring and lab validation.
- [ ] Prove relay-active with traffic/handshake evidence.
  - In progress 2026-03-30: local backend-handshake proof is enforced and tested, but no fresh live cross-network artifact for commit `06e3e2ed745b4439505991bea775246cde8ed653` exists yet.

Success criteria:
- when direct fails, relay goes live automatically,
- `relay_session_disabled` is not the normal result for a configured relay-capable deployment,
- traffic continues through relay without policy bypass.

### Phase D: Failover / Failback / Roaming Hardening
Tasks:
- [ ] Direct->relay failover with no leak.
  - In progress 2026-03-30: `crates/rustynetd/src/daemon.rs` now has `daemon_runtime_auto_tunnel_direct_liveness_expiry_falls_back_to_relay`, which proves stale direct handshake evidence drops the runtime back to `relay_programmed` with `path_live_proven=false` instead of retaining a stale `direct_active` claim. Fresh live cross-network failover evidence is still missing.
- [ ] Relay->direct failback on fresh proof.
  - In progress 2026-03-30: `scripts/e2e/live_linux_cross_network_failback_roaming_test.sh` now records failback only when `rustynet netcheck` reports `path_mode=direct_active` and `path_live_proven=true`; a fresh measured failback artifact for the current commit is still required.
- [ ] Session/token refresh across long-running uptime.
  - In progress 2026-03-30: local runtime coverage from earlier slices still exercises relay session establishment and refresh, but this document does not yet have a long-running live uptime artifact for the current commit.
- [ ] Network-change / IP-change reprobe correctness.
  - In progress 2026-03-30: `scripts/e2e/live_linux_cross_network_failback_roaming_test.sh` now requires fresh live direct proof plus healthy signed-state alarms before endpoint-roam recovery can pass, but no fresh roaming artifact exists yet.
- [x] Active-path consent/liveness expiry behaves fail-closed across transitions.
  - Verified 2026-03-30: `daemon_runtime_auto_tunnel_direct_liveness_expiry_falls_back_to_relay` proves stale direct liveness demotes the path to relay-programmed/unproven instead of overclaiming continued direct reachability.

Success criteria:
- path transitions preserve encryption, ACL, DNS fail-close, and kill-switch.

### Phase E: Evidence and Gates
Tasks:
- [x] Update/extend live scripts.
  - Verified 2026-03-30: `scripts/e2e/live_linux_cross_network_direct_remote_exit_test.sh`, `scripts/e2e/live_linux_cross_network_relay_remote_exit_test.sh`, and `scripts/e2e/live_linux_cross_network_failback_roaming_test.sh` now use `rustynet netcheck` and refuse pass states unless the selected path is live-proven and the signed traversal/DNS state is healthy.
- [x] Update CI gates.
  - Verified 2026-03-30: `crates/rustynet-cli/src/ops_cross_network_reports.rs` now makes pass reports fail closed unless they contain `path_reason`, healthy path alarms, `traversal_error=none`, and the suite-specific measured child artifacts that prove the claimed direct/relay/failback/DNS/soak outcome.
- [ ] Generate commit-bound artifacts.
  - Blocked 2026-03-30: `./scripts/ci/phase10_cross_network_exit_gates.sh` correctly fails because the six canonical live cross-network report artifacts are absent for the current commit.
- [x] Require both direct and relay evidence before internet-reachability claims.
  - Verified 2026-03-30: canonical report validation now rejects pass reports that rely on a final steady-state snapshot without the measured suite artifacts and healthy live path proof.
- [x] Update this document's progress ledger with final evidence.
  - Verified 2026-03-30: Section 18 now records the final audited gate/artifact state for `HEAD` instead of relying on older intermediate slice notes.

Success criteria:
- the documented scripts and gates prove the product promise honestly.

## 13. Security Requirements for the Final Design
### 13.1 Direct Path Security
- all endpoint hints signed and freshness-bounded
- anti-replay watermarks
- no mutation from assignment `peer.N.endpoint` once enforced traversal mode is active
- bounded probe fanout and timing
- no shell-built probe logic

### 13.2 Relay Security
- ciphertext-only forwarding
- signed session tokens
- constant-time auth comparisons
- nonce replay rejection
- relay binding (`relay_id`)
- peer binding (`node_id`, `peer_node_id`)
- strict scope (`forward_ciphertext_only`)
- rate limits, session caps, idle expiry, max packet bounds
- relay never acts as generic open UDP proxy
- session attribution is deterministic and cannot be confused across peers or tuples
- allocated relay ports are bound to exactly one live authorized session at a time
- expired or cleaned-up relay ports are never reused without clearing prior attribution state

### 13.3 Transition Security
During direct<->relay transitions:
- no cleartext packet escape
- no ACL bypass
- no DNS leak
- no kill-switch disable window
- no unsigned path switch
- no status optimism without proof

### 13.4 Active Path Consent / Liveness Security
- the selected path must have a bounded-expiry proof that the remote side is still willing and able to receive traffic,
- liveness/consent state must be tied to the actual 5-tuple or transport identity in use,
- if consent/liveness expires, Rustynet must stop sending on that path and either fail over or fail closed,
- refresh transactions, if any, must not expose reusable transaction identifiers or secrets to untrusted control-plane or scripting inputs.

## 14. What Correct and Working Looks Like
### 14.1 Direct Success Case
A correct direct success looks like:
- both peers gather valid local + srflx candidates,
- signed traversal bundles contain correct tuples,
- traversal probe picks a direct pair,
- backend handshake becomes fresh,
- `path_mode=direct_active`,
- `path_live_proven=true`,
- relay not required.

### 14.2 Relay Fallback Case
A correct relay fallback looks like:
- direct probing fails or is denied by NAT profile reality,
- runtime establishes relay session automatically,
- backend sends encrypted traffic through relay endpoint,
- relay forwards ciphertext only,
- traffic flows,
- `path_mode=relay_active`,
- `relay_session_state=live`,
- `path_live_proven=true`.

### 14.3 Failback Case
A correct failback looks like:
- direct path becomes healthy later,
- runtime proves fresh direct handshake,
- transport switches back without policy/leak regression,
- relay session is closed or retained safely until no longer needed,
- status changes honestly to `direct_active`.

## 15. What To Avoid
Do **not** do any of the following:
- do not require manual consumer-router port forwarding for baseline connectivity,
- do not claim “works from anywhere” based only on direct-friendly home NATs,
- do not guess public ports,
- do not use separate ephemeral sockets where transport identity must be shared,
- do not treat relay fleet-selection code as a real relay service,
- do not mark `relay_programmed` as success,
- do not reintroduce assignment-endpoint fallback as runtime authority,
- do not create a second unsigned mutation path,
- do not introduce authenticated per-packet relay framing into the production path for this scope,
- do not add TODO/FIXME markers instead of finishing in-scope work.

## 16. Test and Evidence Matrix
### 16.1 Unit and Adversarial Tests
Must exist and pass for:
- STUN parsing and mapped endpoint correctness
- NAT profile handling and candidate validation
- relay token signature verification and replay rejection
- relay session establishment and refresh
- direct/relay decision truthfulness in status/netcheck
- failover/failback invariants

### 16.2 Integration Tests
Must exist and pass for:
- direct cross-network remote exit
- relay cross-network remote exit
- failback and roaming
- traversal adversarial rejection
- DNS fail-close during path churn
- soak across token/bundle expiry windows

### 16.3 Live Evidence
Before product claims are updated, evidence must show:
- one measured direct success case,
- one measured relay fallback success case,
- one measured relay->direct failback case,
- one measured adversarial rejection case,
- one measured managed DNS fail-close correctness case,
- one measured soak case.

## 17. Immediate Next Code Work
If implementation starts from this document, the first code slices should be:
1. **Backend-owned shared transport slice**
   - implement a backend-owned multiplexed transport capability that can safely carry peer traffic, STUN, and relay control on the same authoritative socket identity
2. **Live-lab evidence slice**
   - generate the six canonical cross-network reports for current `HEAD`
3. **Fresh-install evidence slice**
   - regenerate `artifacts/phase10/fresh_install_os_matrix_report.json` for current `HEAD`
4. **Final release validation slice**
   - rerun `phase10_gates.sh`, `phase10_cross_network_exit_gates.sh`, and `membership_gates.sh` on the regenerated evidence set

## 18. Progress Ledger
Use this section as the execution log while implementing the plan.

### 18.1 Phase Status
- [ ] Phase A complete
  - [x] Fix STUN to return full mapped endpoints (stun_client.rs)
  - [x] Update daemon.rs to use actual mapped endpoints
  - [x] Make the fail-closed blocker explicit and test-backed: a same-local-port daemon side socket is not authoritative backend transport identity
  - [ ] Production WireGuard backends are still command-only adapters over OS-managed peer-traffic sockets, so daemon STUN gathering remains blocked pending a backend-owned datagram multiplexer or equivalent authoritative packet-I/O capability
  - [ ] Production WireGuard backends still lack that backend-owned transport capability for relay establishment, so the daemon now refuses to auto-bind a second relay client socket and leaves relay bootstrap blocked instead
  - [x] Added and ran candidate-correctness parser/diagnostic tests for the current STUN path
- [ ] Phase B complete
  - [x] Audit rollback resolved: active phase10 traversal now consumes validated signed coordination schedule instead of a fabricated zeroed schedule
  - [x] Runtime declines direct or fail-closes when signed coordination is missing, stale, replayed, malformed, forged, or for the wrong node pair
  - [x] Confirmed probe executor still uses WireGuard handshake freshness for proof
  - [x] Added direct-liveness expiry regression coverage proving stale direct proof demotes back to relay-programmed/unproven state
  - [ ] Add roaming/re-probe tests
- [ ] Phase C complete
  - [x] Implemented real relay daemon binary with allocated-port demux
  - [x] Audit rollback resolved: allocated-port relay tuple-binding, cleanup, and stale port reuse are now hardened and test-backed
  - [x] Runtime path reporting no longer promotes relay sessions to `relay_active` without selected-endpoint match plus fresh handshake proof
  - [ ] Wire to real relay infrastructure
  - [ ] Prove relay-active with live traffic
- [ ] Phase D complete
  - [x] Direct-path liveness expiry now falls back to relay-programmed/unproven state under test
  - [ ] Fresh live failover artifact
  - [ ] Fresh live failback/roaming artifact
  - [ ] Long-uptime session/token refresh artifact
- [ ] Phase E complete
  - [x] Live scripts now require `rustynet netcheck` live path proof and healthy signed-state alarms before pass
  - [x] Canonical report validation now requires suite-specific measured child artifacts and healthy path alarms for pass reports
  - [x] Progress ledger updated with final audited gate and artifact state for current `HEAD`
  - [x] Root-caused and fixed the hidden single-thread gate regressions in STUN provided-socket identity testing and session-snapshot lock contention
  - [ ] Generate six canonical commit-bound cross-network reports for current `HEAD`
  - [ ] Resolve the unrelated stale fresh-install artifact blocker in `./scripts/ci/phase10_gates.sh` or regenerate that evidence as a separate task

### 18.2 Evidence Entries
For each completed slice, append an entry using this format:

```text
Date: 2026-03-30
Phase / Slice: Audit rollback before continued implementation
Files reviewed:
  - crates/rustynetd/src/stun_client.rs
  - crates/rustynetd/src/daemon.rs
  - crates/rustynetd/src/traversal.rs
  - crates/rustynetd/src/phase10.rs
  - crates/rustynetd/src/relay_client.rs
  - crates/rustynet-relay/src/main.rs
  - crates/rustynet-relay/src/transport.rs
Findings:
  - Phase A socket-identity claims were optimistic: daemon STUN discovery still calls `gather_mapped_endpoints(None)` and relay session establishment still binds a separate relay socket.
  - Phase B coordination claims were optimistic: the active phase10 path still passes a zeroed `CoordinationSchedule` instead of validated signed coordination timing/state.
  - Phase C allocated-port contract claims were optimistic: the relay daemon allocates ports, but source-tuple binding/rejection and cleanup attribution are not hardened to the document's required contract yet.
Security invariants verified:
  - Direct and relay live-state claims still depend on fresh handshake evidence in runtime status.
  - No unsigned endpoint-mutation path was introduced by the audited transport code.
Notes / blockers:
  - Actual backend transport-socket identity is still not exposed to traversal/STUN code in the current runtime shape.
  - Continue from Phase A with candidate-correctness tests/diagnostics and keep later phases unchecked until runtime wiring is real.
```

```text
Date: 2026-03-30
Phase / Slice: Phase A - candidate correctness tests and diagnostics
Files changed:
  - crates/rustynetd/src/stun_client.rs
    - Hardened binding-response parsing to reject attributes that run past the declared message boundary.
    - Added IPv6 XOR-MAPPED-ADDRESS decoding for parser coverage.
    - Added a loopback mock-server test proving `gather_mapped_endpoints(Some(&socket))` preserves the caller's socket identity.
    - Added malformed-response coverage for truncated STUN attributes.
  - crates/rustynetd/src/daemon.rs
    - Retained full STUN observations in runtime instead of only the mapped endpoints.
    - Added `stun_candidate_local_addrs` and `stun_transport_port_binding` diagnostics to status/netcheck output.
    - Added test coverage for the new STUN transport-port diagnostic helpers and status/netcheck reporting path.
Tests and gates run:
  - `rustfmt --edition 2024 crates/rustynetd/src/stun_client.rs crates/rustynetd/src/daemon.rs`
  - `cargo test -p rustynetd test_gather_mapped_endpoints_uses_provided_socket_identity -- --nocapture`
  - `cargo test -p rustynetd test_parse_xor_mapped_address_extracts_ipv6_endpoint -- --nocapture`
  - `cargo test -p rustynetd test_parse_binding_response_rejects_attribute_past_message_boundary -- --nocapture`
  - `cargo test -p rustynetd stun_local_port_match_state_reports_mismatch_when_observed_port_differs -- --nocapture`
  - `cargo test -p rustynetd daemon_runtime_auto_tunnel_traversal_probe_falls_back_to_relay_without_handshake_evidence -- --nocapture`
  - `cargo check -p rustynetd`
  - `./scripts/ci/phase10_hp2_gates.sh` (pass)
  - `./scripts/ci/phase10_gates.sh` (fails outside this slice in `scripts/ci/fresh_install_os_matrix_release_gate.sh`: stale child report `git_commit` mismatch)
Live evidence / artifacts:
  - Status/netcheck now emit transport-identity diagnostics for the STUN worker (`stun_candidate_local_addrs`, `stun_transport_port_binding`).
Security invariants verified:
  - STUN parsing now fails closed on malformed attribute bounds instead of silently accepting an incomplete message.
  - Candidate diagnostics now make STUN-vs-WireGuard port mismatches explicit instead of hiding them behind only the mapped endpoint list.
Notes / blockers:
  - This slice does not resolve the underlying backend transport-socket identity gap.
  - Phase A remains incomplete until STUN and relay establishment are bound to the real transport identity used by backend peer traffic.
  - `phase10_gates.sh` is currently blocked by stale fresh-install fixture evidence, not by the STUN/parser changes in this slice.
```

```text
Date: 2026-03-30
Phase / Slice: Phase A - STUN correctness
Files changed:
  - crates/rustynetd/src/stun_client.rs
    - Added StunResult struct with full mapped_endpoint, server, local_addr
    - Added gather_mapped_endpoints() method returning Vec<StunResult>
    - Added query_stun_server_full() with optional socket parameter
    - Deprecated gather_public_ips() in doc comments
    - Added unit tests for endpoint extraction
  - crates/rustynetd/src/daemon.rs
    - Changed stun_result_rx type from Receiver<Vec<IpAddr>> to Receiver<Vec<StunResult>>
    - Updated STUN worker to use gather_mapped_endpoints()
    - Removed incorrect port guessing in poll_stun_results()
    - Now uses actual mapped_endpoint.port() instead of wg_listen_port
Tests and gates run:
  - rustfmt --check passed after formatting
  - Compilation requires Linux target (not available on Windows dev env)
Live evidence / artifacts:
  - Pending: requires deployment to Linux environment
Security invariants verified:
  - No unsigned endpoint mutation introduced
  - Mapped endpoints now reflect actual NAT observation
Notes / blockers:
  - Windows dev environment cannot compile/test Linux-only crates
  - Full validation requires Linux VM deployment
```

```text
Date: 2026-03-30
Phase / Slice: Phase B - Traversal verification
Files reviewed:
  - crates/rustynetd/src/traversal.rs
    - execute_simultaneous_open() correctly implements probe-then-check pattern
    - Uses WireGuard handshake timestamps as proof of connectivity
    - Correctly falls back to relay when direct exhausted
  - crates/rustynetd/src/phase10.rs
    - SimultaneousOpenRuntime implementation uses reconfigure_managed_peer()
    - latest_handshake_unix() reads WireGuard peer state
    - Probe sends reconfigure peer endpoint, WG sends handshake initiation
Security invariants verified:
  - Direct path requires fresh handshake proof (handshake_is_fresh check)
  - Relay fallback only triggers after bounded probe attempts
  - No speculative direct_active without handshake evidence
Notes:
  - Two-sided behavior depends on both peers running traversal
  - Coordination schedule synchronizes probe timing
```

```text
Date: 2026-03-30
Phase / Slice: Phase C - Relay daemon implementation
Files changed:
  - crates/rustynet-relay/Cargo.toml
    - Added tokio, tracing, sha2 optional dependencies
    - Added daemon feature flag
    - Added binary target with required-features
  - crates/rustynet-relay/src/main.rs
    - Replaced 33-line placeholder with ~550-line production daemon
    - Implemented RelayConfig with CLI argument parsing
    - Implemented RelayDaemon with control socket + allocated ports
    - Implemented parse_relay_hello() wire format deserialization
    - Implemented parse_relay_token() wire format deserialization
    - Implemented serialize_relay_hello_ack() and serialize_relay_reject()
    - Added session cleanup task
    - Added forward task per allocated port
Tests and gates run:
  - rustfmt passed
  - Compilation requires Linux target with daemon feature
Live evidence / artifacts:
  - Pending: requires Linux deployment and verifier key setup
Security invariants verified:
  - Uses RelayTransport.handle_hello() for all token verification
  - Ciphertext-only forwarding via forward_packet()
  - Per-session allocated port isolation
Notes:
  - Daemon listens on control port (default 4500)
  - Allocates ports from configurable range (default 50000-59999)
  - Graceful shutdown on SIGINT
```

```text
Date: 2026-03-30
Phase / Slice: Phase B - signed coordination wired into live direct traversal
Files changed:
  - crates/rustynetd/src/daemon.rs
    - Extended the signed traversal bundle-set parser to ingest signed traversal coordination sections alongside endpoint-hint sections on the same authority path.
    - Indexed signed coordination records by node pair and validated them just-in-time with the traversal replay window before live direct probes.
    - Added daemon/runtime tests for mixed artifact ingestion, coordination-required relay fallback, and coordinated relay->direct recovery with fresh signed refreshes.
  - crates/rustynetd/src/phase10.rs
    - Removed the fabricated zeroed `CoordinationSchedule` from `evaluate_traversal_probes()`.
    - Required a validated coordination schedule before coordinated direct probing, returning relay when armed or fail-closing when no relay exists.
    - Preserved fresh WireGuard handshake evidence as the only basis for `direct_active`.
  - crates/rustynetd/src/traversal.rs
    - Added adversarial coverage for expired, wrong-node, and malformed signed coordination records in addition to the existing forged-signature and replay tests.
Tests and gates run:
  - `rustfmt --edition 2024 crates/rustynetd/src/daemon.rs crates/rustynetd/src/phase10.rs crates/rustynetd/src/traversal.rs`
  - `cargo check -p rustynetd`
  - `cargo test -p rustynetd coordination_record_validation_and_execute_simultaneous_open_behaviour -- --nocapture`
  - `cargo test -p rustynetd test_a4_ -- --nocapture`
  - `cargo test -p rustynetd phase10::tests::traversal_probe_ -- --nocapture`
  - `cargo test -p rustynetd traversal_bundle_set_accepts_signed_coordination_and_rejects_malformed_section -- --nocapture`
  - `cargo test -p rustynetd daemon_runtime_requires_signed_coordination_for_direct_probe_attempts -- --nocapture`
  - `cargo test -p rustynetd daemon_runtime_auto_tunnel_traversal_probe_falls_back_to_relay_without_handshake_evidence -- --nocapture`
  - `cargo test -p rustynetd daemon_runtime_auto_tunnel_periodic_reprobe_recovers_direct_after_relay -- --nocapture`
  - `cargo test -p rustynetd daemon_runtime_auto_tunnel_direct_health_uses_live_handshake_without_forced_reprobe -- --nocapture`
  - `cargo test -p rustynetd daemon_runtime_auto_tunnel_traversal_probe_recovers_direct_when_handshake_arrives -- --nocapture`
  - `./scripts/ci/phase10_hp2_gates.sh` (pass)
  - `./scripts/ci/phase10_gates.sh` (fails in `scripts/ci/fresh_install_os_matrix_release_gate.sh`)
Live evidence / artifacts:
  - `artifacts/phase10/source/traversal_path_selection_report.json`
  - `artifacts/phase10/source/traversal_probe_security_report.json`
Security invariants verified:
  - The live runtime no longer synthesizes a zeroed coordination schedule for simultaneous-open.
  - Signed coordination is consumed only on the existing hardened path: signed traversal artifact -> daemon validation/replay window -> deterministic phase10 decision -> backend apply.
  - Direct promotion still requires fresh handshake proof; a validated schedule alone is insufficient.
  - Missing, stale, replayed, malformed, forged, and wrong-node coordination records now decline direct probing or fail closed instead of silently downgrading to an invented schedule.
Residual risks / blockers:
  - Coordinated reprobes now require freshly issued signed coordination records; reusing the same nonce is rejected by design. Full startup/network-change/pre-expiry coordination refresh publication remains broader Phase B/Phase D work.
  - `./scripts/ci/phase10_gates.sh` is still blocked outside this slice by stale fresh-install evidence: `artifacts/phase10/fresh_install_os_matrix_report.json` is bound to commit `c86a62a766b8af8382dfa57805aec8b4cad284ff` while `HEAD` is `06e3e2ed745b4439505991bea775246cde8ed653`.
```

```text
Date: 2026-03-30
Phase / Slice: Phase C - allocated-port relay contract hardening and relay_active truthfulness
Files changed:
  - crates/rustynet-relay/src/session.rs
    - Added hello-observed source tuple, bound dataplane tuple, and signed-session expiry to `RelaySession`.
  - crates/rustynet-relay/src/transport.rs
    - Made `RelayTransport` the single authority for tuple attribution and relay forwarding decisions.
    - Added fail-closed forwarding errors for missing, expired, and unauthorized session activity.
    - Bound post-allocation dataplane traffic only when the first ciphertext packet matches the hello-observed source IP, rejected later tuple changes, ignored unbound keepalive, replaced same-pair sessions deterministically, and expired/cleaned sessions before reuse.
    - Added adversarial tests for wrong source tuple, stale tuple reuse after cleanup, cross-session forwarding attempts, unauthorized keepalive, expired session forwarding, and same-pair replacement.
  - crates/rustynet-relay/src/main.rs
    - Removed duplicate peer-address/session-port authority from the daemon loop.
    - Forwarding now obeys only the `RelayTransport`-selected target tuple/port.
    - Added immediate and periodic pruning of inactive allocated sockets so removed sessions lose port attribution before reuse.
  - crates/rustynet-relay/src/lib.rs
    - Exported relay forwarding decision/error types used by the hardened daemon loop.
  - crates/rustynetd/src/relay_client.rs
    - Added helpers to distinguish expired sessions and selected-endpoint match against the backend.
  - crates/rustynetd/src/daemon.rs
    - Tightened `runtime_path_state_summary()` so `relay_active` requires both an authenticated relay session whose effective endpoint matches the currently selected backend endpoint and a fresh backend handshake on that endpoint.
    - Added runtime tests proving relay stays programmed without proof, becomes live only with selected-endpoint plus fresh handshake, and drops back to unproven when the selected endpoint no longer matches the authenticated relay session.
Tests and gates run:
  - `rustfmt --edition 2024 crates/rustynet-relay/src/main.rs crates/rustynet-relay/src/transport.rs crates/rustynet-relay/src/session.rs crates/rustynet-relay/src/lib.rs crates/rustynetd/src/relay_client.rs crates/rustynetd/src/daemon.rs`
  - `cargo check -p rustynet-relay`
  - `cargo check -p rustynetd`
  - `cargo test -p rustynet-relay -- --nocapture`
  - `cargo test -p rustynetd relay_client::tests -- --nocapture`
  - `cargo test -p rustynetd daemon::tests::daemon_runtime_relay_ -- --nocapture`
  - `cargo test -p rustynetd daemon::tests::daemon_runtime_auto_tunnel_periodic_reprobe_recovers_direct_after_relay -- --nocapture`
  - `cargo test -p rustynetd daemon::tests::daemon_runtime_auto_tunnel_traversal_probe_recovers_direct_when_handshake_arrives -- --nocapture`
  - `./scripts/ci/phase10_hp2_gates.sh` (pass)
  - `./scripts/ci/phase10_gates.sh` (fails in `scripts/ci/fresh_install_os_matrix_release_gate.sh`)
Live evidence / artifacts:
  - `artifacts/phase10/source/traversal_path_selection_report.json`
  - `artifacts/phase10/source/traversal_probe_security_report.json`
Security invariants verified:
  - One allocated relay port now maps to exactly one live authorized session at a time.
  - Source-tuple spoofing, stale tuple reuse after cleanup, unauthorized keepalive, session cross-talk, and expired-session forwarding all fail closed under test.
  - The relay daemon remains ciphertext-only; no open-proxy or alternate framing path was introduced.
  - `relay_active` now requires real selected-endpoint consistency plus fresh backend handshake proof; a stored session object or programmed relay endpoint alone is insufficient.
Residual risks / blockers:
  - `crates/rustynetd/src/daemon.rs` no longer binds the relay client on a separate socket in `load_relay_client()`, but current production WireGuard backends still expose only opaque OS-managed peer-traffic sockets. A backend-owned multiplexed transport interface is still required before relay establishment can honestly share the authoritative transport identity. That remains open Phase A work and limits completion of Phase C's live-runtime claims.
  - Fresh live cross-network evidence for commit `06e3e2ed745b4439505991bea775246cde8ed653` is still required before claiming end-to-end relay runtime completion.
  - `./scripts/ci/phase10_gates.sh` is still blocked outside this slice by stale fresh-install evidence: `artifacts/phase10/fresh_install_os_matrix_report.json` is bound to commit `c86a62a766b8af8382dfa57805aec8b4cad284ff` while `HEAD` is `06e3e2ed745b4439505991bea775246cde8ed653`.
```

```text
Date: 2026-03-30
Phase / Slice: Phase D/E - failover truthfulness and canonical evidence hardening
Files changed:
  - crates/rustynetd/src/daemon.rs
    - Added `daemon_runtime_auto_tunnel_direct_liveness_expiry_falls_back_to_relay`, which proves stale direct handshake proof demotes runtime state back to relay-programmed/unproven instead of retaining a stale `direct_active` claim.
  - crates/rustynet-cli/src/ops_cross_network_reports.rs
    - Added suite-specific required pass artifacts for the six canonical cross-network report families.
    - Extended `path_evidence` parsing/validation to require `path_reason`, healthy traversal/DNS alarm states, and `traversal_error=none` for pass reports.
    - Added validator tests that reject failback pass reports without measured child artifacts and reject pass reports with critical path alarms.
  - scripts/e2e/live_linux_cross_network_direct_remote_exit_test.sh
    - Direct pass now requires `rustynet netcheck` to show `path_mode=direct_active`, `path_live_proven=true`, and healthy signed-state alarms.
  - scripts/e2e/live_linux_cross_network_relay_remote_exit_test.sh
    - Relay pass now requires `path_mode=relay_active`, `path_live_proven=true`, `relay_session_state=live`, and healthy signed-state alarms.
  - scripts/e2e/live_linux_cross_network_failback_roaming_test.sh
    - Failback/roam success now records a switch only on fresh live direct proof and only passes final roam recovery when the post-roam path is direct-active/live-proven with healthy signed-state alarms.
Tests and gates run:
  - `rustfmt --edition 2024 crates/rustynetd/src/daemon.rs crates/rustynet-cli/src/ops_cross_network_reports.rs`
  - `bash -n scripts/e2e/live_linux_cross_network_direct_remote_exit_test.sh`
  - `bash -n scripts/e2e/live_linux_cross_network_relay_remote_exit_test.sh`
  - `bash -n scripts/e2e/live_linux_cross_network_failback_roaming_test.sh`
  - `cargo check -p rustynetd`
  - `cargo test -p rustynetd daemon_runtime_auto_tunnel_direct_liveness_expiry_falls_back_to_relay -- --nocapture`
  - `cargo test -p rustynet-cli --bin rustynet-cli validate_report_payload_rejects_failback_pass_without_measured_child_artifacts -- --nocapture`
  - `cargo test -p rustynet-cli --bin rustynet-cli validate_report_payload_rejects_pass_status_with_critical_path_alarm -- --nocapture`
  - `cargo test -p rustynet-cli --bin rustynet-cli validate_cross_network_remote_exit_readiness_accepts_complete_canonical_reports -- --nocapture`
  - `./scripts/ci/phase10_hp2_gates.sh` (pass)
  - `./scripts/ci/phase10_cross_network_exit_gates.sh` (fails closed because the canonical live reports are absent for the current commit)
  - `./scripts/ci/phase10_gates.sh` (fails outside this slice in `scripts/ci/fresh_install_os_matrix_release_gate.sh`: stale child report `git_commit` mismatch)
Live evidence / artifacts:
  - No fresh live cross-network artifacts were generated in this local session.
  - `./scripts/ci/phase10_cross_network_exit_gates.sh` now fails closed on the missing canonical reports instead of permitting proof-less success:
    - `artifacts/phase10/cross_network_direct_remote_exit_report.json`
    - `artifacts/phase10/cross_network_relay_remote_exit_report.json`
    - `artifacts/phase10/cross_network_failback_roaming_report.json`
    - `artifacts/phase10/cross_network_traversal_adversarial_report.json`
    - `artifacts/phase10/cross_network_remote_exit_dns_report.json`
    - `artifacts/phase10/cross_network_remote_exit_soak_report.json`
Security invariants verified:
  - Stale direct liveness proof no longer preserves a direct-active claim under test.
  - Direct, relay, and failback pass conditions in the live scripts now require live `rustynet netcheck` proof instead of a programmed steady-state snapshot.
  - Canonical pass reports now require suite-specific measured child artifacts, so a final steady-state report without measured failback/relay/DNS/soak evidence is rejected.
  - Critical traversal alarms, critical DNS alarms, and non-`none` traversal errors now block pass reports.
Residual risks / blockers:
  - `./scripts/ci/phase10_cross_network_exit_gates.sh` remains blocked until fresh live-lab runs generate the six canonical cross-network reports for the current commit.
  - `./scripts/ci/phase10_gates.sh` remains blocked outside this slice because `artifacts/phase10/fresh_install_os_matrix_report.json` is still bound to commit `c86a62a766b8af8382dfa57805aec8b4cad284ff` while `HEAD` is `06e3e2ed745b4439505991bea775246cde8ed653`.
  - Phase A remains incomplete because STUN candidate gathering and relay establishment are still not tied to the backend transport socket identity; that still limits full end-to-end plug-and-play claims.
```

```text
Date: 2026-03-31
Phase / Slice: Phase A hardening - explicit backend transport-socket blocker enforcement
Files changed:
  - crates/rustynet-backend-api/src/lib.rs
    - Added `TunnelBackend::transport_socket_identity_blocker()` so production backends can explicitly declare when the authoritative peer-traffic socket is backend-owned and opaque to daemon STUN/relay bootstrap.
  - crates/rustynet-backend-wireguard/src/lib.rs
    - Linux and macOS WireGuard backends now report the exact blocker: peer traffic is delegated to an OS-managed WireGuard / `wireguard-go` UDP socket, so daemon-side shared-socket traversal/relay bootstrap needs a backend-owned multiplexed transport interface.
  - crates/rustynetd/src/relay_client.rs
    - Added `RelayClient::is_bound()` and kept new clients unbound until an authoritative transport socket is supplied.
  - crates/rustynetd/src/daemon.rs
    - Stopped auto-binding a separate relay client UDP socket in `load_relay_client()`.
    - Stopped starting the production STUN worker when the active backend reports an opaque transport-socket blocker.
    - Added `transport_socket_identity_state` / `transport_socket_identity_error` diagnostics to status and netcheck.
    - Added fail-closed runtime handling so a configured relay path reports `blocked_transport_identity` instead of silently treating a second daemon-owned socket as authoritative.
    - Added `daemon_runtime_transport_socket_identity_blocker_fail_closes_relay_bootstrap`.
  - README.md
    - Reconciled the repo-level transport status text to explain that production WireGuard backends now explicitly block separate-socket STUN/relay bootstrap and still need a backend-owned shared transport interface.
Tests and gates run:
  - `rustfmt --edition 2024 crates/rustynet-backend-api/src/lib.rs crates/rustynet-backend-wireguard/src/lib.rs crates/rustynetd/src/relay_client.rs crates/rustynetd/src/daemon.rs`
  - `cargo fmt --all -- --check`
  - `cargo check -p rustynet-backend-api`
  - `cargo check -p rustynet-backend-wireguard`
  - `cargo check -p rustynetd`
  - `cargo test -p rustynetd daemon_runtime_transport_socket_identity_blocker_fail_closes_relay_bootstrap -- --nocapture`
  - `cargo test -p rustynetd relay_client_new_creates_empty_session_map -- --nocapture`
  - `cargo test -p rustynetd daemon_runtime_relay_client_upgrades_relay_candidate_endpoint -- --nocapture`
  - `cargo test -p rustynetd daemon_runtime_relay_session_becomes_live_only_with_selected_endpoint_and_fresh_handshake -- --nocapture`
  - `./scripts/ci/phase10_hp2_gates.sh` (pass)
  - `./scripts/ci/phase10_cross_network_exit_gates.sh` (fails closed on the six missing canonical cross-network reports)
  - `./scripts/ci/phase10_gates.sh` (fails closed on stale `fresh_install_os_matrix_report.json` commit binding)
Live evidence / artifacts:
  - No fresh live cross-network artifacts were generated in this local session.
  - `artifacts/phase10/source/traversal_path_selection_report.json` and `artifacts/phase10/source/traversal_probe_security_report.json` were regenerated by `./scripts/ci/phase10_hp2_gates.sh`.
Security invariants verified:
  - Production WireGuard backends no longer let the daemon infer authority from a second UDP socket for STUN or relay bootstrap.
  - Relay runtime truthfulness remains proof-based: `relay_active` still requires authenticated session consistency plus fresh backend handshake evidence.
  - When the authoritative backend transport socket is unavailable to the daemon, runtime status now reports that blocker explicitly and the configured relay path fails closed instead of bootstrapping on a separate socket.
Residual risks / blockers:
  - This slice does not create the missing backend-owned shared transport interface; Phase A remains incomplete until a backend can safely multiplex peer traffic, STUN, and relay control on the same authoritative transport identity.
  - `./scripts/ci/phase10_cross_network_exit_gates.sh` still fails only because the six canonical live cross-network reports are absent for `06e3e2ed745b4439505991bea775246cde8ed653`.
  - `./scripts/ci/phase10_gates.sh` still fails only because `artifacts/phase10/fresh_install_os_matrix_report.json` is commit-stale (`c86a62a766b8af8382dfa57805aec8b4cad284ff` vs `06e3e2ed745b4439505991bea775246cde8ed653`).
```

```text
Date: 2026-03-31
Phase / Slice: Pre-live-lab hardening - gate regression cleanup and validation
Files changed:
  - crates/rustynet-backend-api/src/lib.rs
    - Tightened the transport-identity blocker contract so a same-local-port daemon side socket is explicitly rejected as non-authoritative.
  - crates/rustynet-backend-wireguard/src/lib.rs
    - Updated Linux/macOS blocker text and tests to match the stricter authoritative-transport rule.
  - crates/rustynetd/src/daemon.rs
    - Fixed traversal rejection-counter fixture timing so replay/freshness accounting stays deterministic under long serial gate runs.
  - crates/rustynetd/src/relay_client.rs
    - Tightened relay-client binding semantics so `local_port` remains a hint only and never implies authoritative transport identity.
  - crates/rustynetd/src/stun_client.rs
    - Reworked the provided-socket STUN identity test to use a scripted socket instead of sandbox-sensitive loopback binds.
  - crates/rustynetd/src/resilience.rs
    - Replaced the fixed 500 ms snapshot lock budget with a deadline-based wait window and added a lock-contention regression test.
  - README.md
    - Reconciled repo-level transport status text with the stricter same-port/non-authoritative rule.
Tests and gates run:
  - `rustfmt --edition 2024 crates/rustynet-backend-api/src/lib.rs crates/rustynet-backend-wireguard/src/lib.rs crates/rustynetd/src/daemon.rs crates/rustynetd/src/relay_client.rs crates/rustynetd/src/stun_client.rs crates/rustynetd/src/resilience.rs`
  - `cargo fmt --all -- --check`
  - `cargo check -p rustynet-backend-api`
  - `cargo check -p rustynet-backend-wireguard`
  - `cargo check -p rustynetd`
  - `cargo test -p rustynet-backend-wireguard transport_socket_identity_blocker -- --nocapture`
  - `cargo test -p rustynetd stun_client::tests::test_gather_mapped_endpoints_uses_provided_socket_identity -- --exact --nocapture`
  - `RUST_TEST_THREADS=1 cargo test -p rustynetd stun_client::tests::test_gather_mapped_endpoints_uses_provided_socket_identity -- --exact --nocapture`
  - `cargo test -p rustynetd daemon::tests::daemon_runtime_traversal_rejection_counters_increment_for_stale_replay_and_future_dated -- --exact --nocapture`
  - `cargo test -p rustynetd resilience::tests::concurrent_persist_keeps_snapshot_integrity -- --exact --nocapture`
  - `RUST_TEST_THREADS=1 cargo test -p rustynetd resilience::tests::concurrent_persist_keeps_snapshot_integrity -- --exact --nocapture`
  - `cargo test -p rustynetd resilience::tests::persist_waits_for_brief_lock_contention -- --exact --nocapture`
  - `RUST_TEST_THREADS=1 cargo test -p rustynetd resilience::tests::persist_waits_for_brief_lock_contention -- --exact --nocapture`
  - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
  - `cargo check --workspace --all-targets --all-features`
  - `cargo test --workspace --all-targets --all-features`
  - `cargo audit --deny warnings`
  - `cargo deny check bans licenses sources advisories`
  - `./scripts/ci/phase10_hp2_gates.sh` (pass)
  - `./scripts/ci/phase10_cross_network_exit_gates.sh` (fails closed on the six missing canonical reports)
  - `./scripts/ci/phase10_gates.sh` (fails closed on stale `fresh_install_os_matrix_report.json` commit binding)
  - `./scripts/ci/membership_gates.sh` rerun advanced past the previous hidden `phase8`/STUN/resilience regressions and through the repeated workspace validation stack; the remaining blocker is inherited Phase 10 evidence gating, validated separately via `./scripts/ci/phase10_gates.sh`
Artifacts / evidence:
  - No fresh live cross-network artifacts were generated in this slice.
  - `artifacts/phase10/source/traversal_path_selection_report.json` and `artifacts/phase10/source/traversal_probe_security_report.json` were regenerated by `./scripts/ci/phase10_hp2_gates.sh`.
Security invariants verified:
  - Production runtime still fails closed when the authoritative backend transport socket is opaque to the daemon.
  - A daemon-owned second socket, including one bound to the same local port, is never treated as authoritative transport identity.
  - Direct and relay truthfulness semantics remain proof-based while the new gate fixes remove false negatives rather than softening enforcement.
Residual risks / blockers:
  - The backend-owned shared transport interface is still not implemented; STUN gathering and relay establishment remain architecture-blocked in production backends.
  - `./scripts/ci/phase10_cross_network_exit_gates.sh` still fails only because the six canonical live cross-network reports are absent for `06e3e2ed745b4439505991bea775246cde8ed653`.
  - `./scripts/ci/phase10_gates.sh` still fails only because `artifacts/phase10/fresh_install_os_matrix_report.json` is commit-stale (`c86a62a766b8af8382dfa57805aec8b4cad284ff` vs `06e3e2ed745b4439505991bea775246cde8ed653`).
  - `./scripts/ci/membership_gates.sh` no longer reproduces the earlier hidden runtime/test regressions, but because it delegates into the same Phase 10 CI path its remaining red state is the inherited stale fresh-install evidence blocker until that artifact is regenerated honestly.
```

### 18.3 Final Audited Artifact and Gate State
- Current `HEAD`: `06e3e2ed745b4439505991bea775246cde8ed653`
- Canonical cross-network report artifact expectation and current state:
  - `artifacts/phase10/cross_network_direct_remote_exit_report.json`: missing
  - `artifacts/phase10/cross_network_relay_remote_exit_report.json`: missing
  - `artifacts/phase10/cross_network_failback_roaming_report.json`: missing
  - `artifacts/phase10/cross_network_traversal_adversarial_report.json`: missing
  - `artifacts/phase10/cross_network_remote_exit_dns_report.json`: missing
  - `artifacts/phase10/cross_network_remote_exit_soak_report.json`: missing
- Non-canonical cross-network artifacts currently present under `artifacts/phase10`:
  - `cross_network_direct_remote_exit_report_64_to_18.json`
  - `cross_network_remote_exit_schema_validation.md`
  - These do not satisfy the canonical gate contract and are intentionally ignored by the canonical report collector.
- Fresh-install matrix artifact state:
  - `artifacts/phase10/fresh_install_os_matrix_report.json`: present
  - embedded `git_commit`: `c86a62a766b8af8382dfa57805aec8b4cad284ff`
  - current `HEAD`: `06e3e2ed745b4439505991bea775246cde8ed653`
  - result: stale and correctly rejected by `./scripts/ci/phase10_gates.sh`
- Gate outcomes re-verified on 2026-03-31:
  - `cargo clippy --workspace --all-targets --all-features -- -D warnings`: pass
  - `cargo check --workspace --all-targets --all-features`: pass
  - `cargo test --workspace --all-targets --all-features`: pass
  - `cargo audit --deny warnings`: pass
  - `cargo deny check bans licenses sources advisories`: pass
  - `./scripts/ci/phase10_hp2_gates.sh`: pass
  - `./scripts/ci/phase10_cross_network_exit_gates.sh`: fail closed on the six missing canonical reports
  - `./scripts/ci/phase10_gates.sh`: fail closed on stale `fresh_install_os_matrix_report.json` commit binding
  - `./scripts/ci/membership_gates.sh`: the prior hidden runtime/test failures are cleared; remaining red state is inherited from the same stale Phase 10 fresh-install evidence gate
- Final honest closeout status:
  - The validator and gate path now matches the strict product claim surface: missing or stale evidence stays red, production backends do not bootstrap STUN or relay on a second daemon-owned socket, and the earlier hidden single-thread gate regressions have been removed.
  - This plan is not complete. Remaining prerequisites are a backend-owned shared transport capability that includes authoritative packet-I/O or a backend-owned datagram multiplexer, fresh commit-bound live cross-network artifacts, and a fresh-install matrix report for the current commit.

```text
Date: 2026-03-31
Phase / Slice: Pre-live-lab backend-mode plumbing and membership gate regression cleanup
Files changed:
  - crates/rustynetd/src/daemon.rs
    - Added explicit `linux-wireguard-userspace-shared` and `macos-wireguard-userspace-shared` backend modes, precise fail-closed blocker text, and config/runtime validation that rejects those modes until a production transport-owning backend exists.
  - crates/rustynetd/src/main.rs
    - Added daemon CLI parsing/help coverage for the new backend mode values.
  - start.sh
    - Updated host-profile enforcement so Linux/macOS accept either the existing command-only mode or the matching non-default `*-userspace-shared` mode name without silently rewriting it.
  - crates/rustynet-cli/src/main.rs
    - Fixed the VM-lab module path so the inherited `membership_gates.sh` compile blocker no longer hides the real pre-live validation state.
  - crates/rustynet-cli/src/vm_lab/mod.rs
    - Applied narrow clippy-driven cleanups so the VM-lab code no longer fails the membership gate workspace lint path.
  - README.md
    - Reconciled the repo-level transport status text to mention the explicit non-default backend mode names and their current fail-closed blocker status.
Tests and gates run:
  - `rustfmt --edition 2024 crates/rustynet-cli/src/vm_lab/mod.rs crates/rustynetd/src/main.rs crates/rustynetd/src/daemon.rs`
  - `cargo fmt --all -- --check`
  - `cargo check -p rustynetd`
  - `cargo check -p rustynet-cli --bin rustynet-cli`
  - `cargo clippy -p rustynet-cli --bin rustynet-cli -- -D warnings`
  - `cargo test -p rustynetd validate_daemon_config_rejects_linux_userspace_shared_backend_with_precise_blocker -- --nocapture`
  - `cargo test -p rustynetd validate_daemon_config_rejects_macos_userspace_shared_backend_with_precise_blocker -- --nocapture`
  - `cargo test -p rustynetd daemon_runtime_production_backend_transport_identity_blocker_disables_stun_worker -- --nocapture`
  - `cargo test -p rustynetd parse_daemon_config_accepts_userspace_shared_backend_values -- --nocapture`
  - `./scripts/ci/phase10_hp2_gates.sh` (pass)
  - `./scripts/ci/phase10_cross_network_exit_gates.sh` (fails closed on the six missing canonical live cross-network reports)
  - `./scripts/ci/phase10_gates.sh` (fails closed on stale `artifacts/phase10/fresh_install_os_matrix_report.json` commit binding)
  - `./scripts/ci/membership_gates.sh` rerun advanced through the previous missing-module/clippy blockers and through the full workspace lint/check/test stack; because [crates/rustynet-cli/src/ops_ci_release_perf.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-cli/src/ops_ci_release_perf.rs) delegates the tail of that gate into the same Phase 10 readiness path, its remaining red state is the separately verified stale fresh-install evidence blocker rather than the old CLI regression.
Artifacts / evidence:
  - No new live cross-network artifacts were generated in this slice.
  - `artifacts/phase10/source/traversal_path_selection_report.json` and `artifacts/phase10/source/traversal_probe_security_report.json` were regenerated by `./scripts/ci/phase10_hp2_gates.sh`.
Security invariants verified:
  - Explicit `*-userspace-shared` mode names do not widen capability claims; production runtime still fails closed until a transport-owning backend exists.
  - Host-profile/start parsing now preserves an explicitly selected non-default backend mode instead of silently rejecting or rewriting it.
  - The prior membership gate failure was a real CLI/module-path regression and is now removed without weakening any traversal, relay, or evidence gates.
Residual risks / blockers:
  - The actual production transport-owning backend runtime is still absent; the new mode names remain intentionally blocked.
  - `./scripts/ci/phase10_cross_network_exit_gates.sh` still fails only because the six canonical live cross-network reports are absent for `06e3e2ed745b4439505991bea775246cde8ed653`.
  - `./scripts/ci/phase10_gates.sh` still fails only because `artifacts/phase10/fresh_install_os_matrix_report.json` is commit-stale (`c86a62a766b8af8382dfa57805aec8b4cad284ff` vs `06e3e2ed745b4439505991bea775246cde8ed653`).
```

```text
Date: 2026-03-31
Phase / Slice: Shared-transport authoritative backend contract implementation and post-fix validation
Files changed:
  - crates/rustynet-backend-api/src/lib.rs
    - Added an explicit backend-owned authoritative shared-transport contract for identity, round-trip operations, and one-way sends so STUN and relay control no longer have to infer authority from daemon-owned sockets.
  - crates/rustynet-backend-wireguard/src/lib.rs
    - Implemented the authoritative shared-transport contract for the in-memory backend, added operation recording/script hooks, and kept production Linux/macOS backends fail-closed behind the existing opaque-socket blocker.
  - crates/rustynetd/src/phase10.rs
    - Threaded the backend-owned authoritative shared-transport contract through the controller surface without leaking backend-specific types into transport-agnostic layers.
  - crates/rustynetd/src/stun_client.rs
    - Added authoritative round-trip STUN gathering so candidate publication and diagnostics can consume measured tuples from the backend-owned transport path.
  - crates/rustynetd/src/relay_client.rs
    - Added authoritative relay establish/keepalive APIs and restored the scripted test path so test-only relay establishment does not require a bound socket.
  - crates/rustynetd/src/daemon.rs
    - Replaced daemon-owned STUN worker socket assumptions with backend-owned authoritative transport refresh, routed relay hello/refresh/keepalive through the same contract, exposed transport-identity diagnostics, and fixed the endpoint-mismatch regression test so it exercises the intended selected-endpoint branch with authoritative transport present.
  - README.md
    - Reconciled the repo-level transport status paragraph to state that the daemon now consumes an explicit backend-owned shared-transport contract when available, while production command-only WireGuard modes remain architecture-blocked.
  - documents/operations/active/PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md
    - Updated Phase A and Phase C checklist text plus this evidence ledger entry to match the implemented contract and the remaining production/backend blockers honestly.
Tests and gates run:
  - `rustfmt --edition 2024 crates/rustynetd/src/relay_client.rs crates/rustynetd/src/daemon.rs`
  - `cargo fmt --all -- --check`
  - `cargo check -p rustynet-backend-api`
  - `cargo check -p rustynet-backend-wireguard`
  - `cargo check -p rustynetd`
  - `cargo test -p rustynet-backend-wireguard authoritative_transport -- --nocapture`
  - `cargo test -p rustynetd authoritative_stun_refresh_uses_backend_shared_transport_identity -- --nocapture`
  - `cargo test -p rustynetd relay_establish_and_keepalive_use_backend_shared_transport_identity -- --nocapture`
  - `cargo test -p rustynetd relay_client_establish_session_with_round_trip_uses_provided_transport -- --nocapture`
  - `cargo test -p rustynetd relay_client_send_keepalive_with_sender_uses_allocated_port -- --nocapture`
  - `cargo test -p rustynetd test_gather_mapped_endpoints_with_round_trip_uses_authoritative_local_addr -- --nocapture`
  - `cargo test -p rustynetd daemon_runtime_transport_socket_identity_blocker_fail_closes_relay_bootstrap -- --nocapture`
  - `cargo test -p rustynetd daemon_runtime_transport_socket_identity_blocker_rejects_bound_relay_side_socket -- --nocapture`
  - `cargo test -p rustynetd daemon_runtime_relay_session_is_programmed_but_not_live_without_fresh_handshake -- --nocapture`
  - `cargo test -p rustynetd daemon_runtime_relay_session_becomes_live_only_with_selected_endpoint_and_fresh_handshake -- --nocapture`
  - `cargo test -p rustynetd daemon_runtime_relay_session_endpoint_mismatch_is_not_live -- --nocapture`
  - `cargo test -p rustynetd relay_client_scripted_establish_session_success -- --nocapture`
  - `cargo test -p rustynetd relay_client_scripted_establish_session_failure_then_success -- --nocapture`
  - `cargo test -p rustynetd relay_client_close_session_removes_from_map -- --nocapture`
  - `cargo test -p rustynetd --lib`
  - `cargo check --workspace --all-targets --all-features`
  - `cargo test --workspace --all-targets --all-features`
  - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
  - `cargo audit --deny warnings`
  - `cargo deny check bans licenses sources advisories`
  - `./scripts/ci/phase10_hp2_gates.sh` (pass)
  - `./scripts/ci/phase10_cross_network_exit_gates.sh` (fails closed only on the six missing canonical live cross-network reports)
  - `cargo run --quiet -p rustynet-cli --bin phase10_gates --` (fails closed only on stale fresh-install matrix child-commit evidence for current `HEAD`)
  - `./scripts/ci/membership_gates.sh` (fails after the shared-transport/runtime checks stay green because the current CLI tree has unrelated `OpsCommand::VmLabSyncBootstrap` / `VmLabWriteLiveLabProfile` / `VmLabRunLiveLab` variants that are not yet handled exhaustively in [crates/rustynet-cli/src/main.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-cli/src/main.rs))
Artifacts / evidence:
  - No new live cross-network artifacts were generated in this slice.
  - `./scripts/ci/phase10_hp2_gates.sh` now passes with the shared-transport-backed traversal/relay non-live contract in place.
  - `./scripts/ci/phase10_cross_network_exit_gates.sh` still fails only because the six canonical cross-network reports are absent for current `HEAD`.
  - `cargo run --quiet -p rustynet-cli --bin phase10_gates --` still fails only because the fresh-install readiness fixture detects stale child-report commit binding.
Security invariants verified:
  - STUN round trips now use an explicit backend-owned authoritative transport contract when a backend exposes one; the daemon no longer treats a second daemon-owned socket as authoritative transport identity.
  - Relay hello/refresh and keepalive now use that same backend-owned authoritative transport contract when available; same-local-port side sockets are still rejected as non-authoritative.
  - Production Linux/macOS WireGuard adapters remain fail-closed and truthfully blocked because they are still command-only wrappers over OS-managed peer sockets without authoritative packet I/O or a backend-owned datagram multiplexer.
  - `direct_active` and `relay_active` semantics remain proof-based: relay liveness still requires authenticated session/selected-endpoint consistency plus fresh backend handshake evidence.
Residual risks / blockers:
  - This slice does not create a production backend mode that owns peer datagrams; the in-memory/test backend proves the contract, but production Linux/macOS command-only modes remain architecture-blocked and intentionally fail closed.
  - Fresh live cross-network evidence and fresh-install matrix evidence for current `HEAD` remain separate release blockers.
  - `./scripts/ci/membership_gates.sh` is currently blocked by an unrelated CLI compile regression in [crates/rustynet-cli/src/main.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-cli/src/main.rs) around new VM-lab `OpsCommand` variants; that blocker is outside this shared-transport write slice and does not come from the shared-transport runtime changes above.
```

```text
Date: 2026-03-31
Phase / Slice: Shared-transport architecture audit - precise backend blocker reconciliation
Files changed:
  - crates/rustynet-backend-api/src/lib.rs
    - Tightened the transport-socket blocker contract to state that a safe shared-transport solution needs backend-owned packet I/O or a backend-owned datagram multiplexer, not just a second socket on the same local port.
  - crates/rustynet-backend-wireguard/src/lib.rs
    - Tightened Linux/macOS blocker strings and tests to record the real architecture limit precisely: current production adapters are command-only wrappers over OS-managed peer sockets and do not expose authoritative packet I/O or multiplexed datagram transport.
  - README.md
    - Reconciled the repo-level transport status text to match the stricter architecture finding.
  - documents/operations/active/PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md
    - Updated the Phase A blocker text and final closeout status to describe the exact shared-transport prerequisite honestly.
Tests and gates run:
  - `rustfmt --edition 2024 crates/rustynet-backend-api/src/lib.rs crates/rustynet-backend-wireguard/src/lib.rs`
  - `cargo fmt --all -- --check`
  - `cargo check -p rustynet-backend-api`
  - `cargo check -p rustynet-backend-wireguard`
  - `cargo test -p rustynet-backend-wireguard transport_socket_identity_blocker -- --nocapture`
  - `./scripts/ci/phase10_hp2_gates.sh` (pass)
  - `./scripts/ci/phase10_cross_network_exit_gates.sh` (fails closed only on the six missing canonical live reports)
  - `./scripts/ci/phase10_gates.sh` (fails closed only on stale `artifacts/phase10/fresh_install_os_matrix_report.json` commit binding)
Artifacts / evidence:
  - No new live artifacts were generated in this slice.
Security invariants verified:
  - The repository now records the remaining shared-transport blocker precisely enough that same-port side sockets, command-runner shims, and other pseudo-authority paths are explicitly out of bounds.
  - Production runtime behavior remains fail-closed: no second daemon-owned socket is treated as authoritative for STUN or relay bootstrap.
Residual risks / blockers:
  - This slice does not implement the missing backend-owned datagram multiplexer or equivalent authoritative packet-I/O capability; Linux kernel WireGuard and macOS `wireguard-go` remain command-only/OS-managed in the current architecture.
  - Fresh live cross-network artifacts and the stale fresh-install matrix artifact remain separate evidence blockers.
```

```text
Date: 2026-03-31
Phase / Slice: Production transport-owning backend plan - Phase 1 crate restructure and dependency introduction
Files changed:
  - Cargo.lock
    - Locked the newly introduced released userspace-backend dependencies and their transitive graph for the current tree.
  - crates/rustynet-backend-wireguard/Cargo.toml
    - Added released pinned dependencies `boringtun = "0.7.0"` and `tun-rs = "2.8.2"` for the future userspace-shared backend implementation.
  - crates/rustynet-backend-wireguard/src/lib.rs
    - Kept the crate root as a stable module boundary with public re-exports for the existing in-memory and command-only backend types.
  - crates/rustynet-backend-wireguard/src/in_memory.rs
    - Preserved the in-memory backend implementation and tests under its own module without widening product claims.
  - crates/rustynet-backend-wireguard/src/linux_command.rs
    - Preserved the Linux command-only backend implementation and blocker behavior under its own module.
  - crates/rustynet-backend-wireguard/src/macos_command.rs
    - Preserved the macOS command-only backend implementation and blocker behavior under its own module.
  - crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs
    - Added the Phase 1 userspace-shared module boundary root with test-backed ownership scaffolding for future Linux/macOS shared backend modes.
  - crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs
    - Added the Phase 1 runtime ownership boundary scaffold for a single backend-owned worker.
  - crates/rustynet-backend-wireguard/src/userspace_shared/socket.rs
    - Added the Phase 1 authoritative socket boundary scaffold expressing single-owner transport and one outstanding round-trip at a time.
  - crates/rustynet-backend-wireguard/src/userspace_shared/engine.rs
    - Added the Phase 1 userspace WireGuard engine boundary scaffold without exposing backend-internal engine types outside the backend crate.
  - crates/rustynet-backend-wireguard/src/userspace_shared/tun.rs
    - Added the Phase 1 TUN lifecycle boundary scaffold, including the rule that helper-assisted setup must not become helper-owned runtime datapath.
  - crates/rustynet-backend-wireguard/src/userspace_shared/handshake.rs
    - Added the Phase 1 authenticated handshake telemetry boundary scaffold so later phases keep handshake freshness sourced from userspace-engine evidence only.
  - documents/operations/active/ProductionTransportOwningWireGuardBackendPlan_2026-03-31.md
    - Marked Phase 1 complete with exact validation and remaining-open scope.
Tests and validation run:
  - `rustfmt --edition 2024 crates/rustynet-backend-wireguard/src/lib.rs crates/rustynet-backend-wireguard/src/in_memory.rs crates/rustynet-backend-wireguard/src/linux_command.rs crates/rustynet-backend-wireguard/src/macos_command.rs crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs crates/rustynet-backend-wireguard/src/userspace_shared/socket.rs crates/rustynet-backend-wireguard/src/userspace_shared/engine.rs crates/rustynet-backend-wireguard/src/userspace_shared/tun.rs crates/rustynet-backend-wireguard/src/userspace_shared/handshake.rs crates/rustynet-backend-wireguard/tests/conformance.rs`
  - `cargo fmt --all -- --check`
  - `cargo check -p rustynet-backend-wireguard`
  - `cargo test -p rustynet-backend-wireguard --tests -- --nocapture`
Validation outcomes:
  - `cargo fmt --all -- --check`: pass
  - `cargo check -p rustynet-backend-wireguard`: pass
  - `cargo test -p rustynet-backend-wireguard --tests -- --nocapture`: pass
  - backend crate unit tests: 20 passed
  - backend crate conformance tests: 3 passed
Security invariants verified:
  - Phase 1 does not introduce a fake userspace backend or widen any product/runtime claim.
  - Linux and macOS production command-only backends remain fail-closed and continue to report blocker behavior unchanged.
  - The future shared-backend module tree now records the intended single-owner runtime, authoritative socket, TUN, engine, and handshake boundaries without adding a second transport-authority path.
  - The future shared-backend boundary tests explicitly reject fallback-by-shape design drift such as command-backend fallback or helper-owned runtime datapath.
What Phase 1 completed:
  - backend crate restructure into intentional modules
  - released dependency introduction for the future userspace-shared backend
  - preserved current behavior for in-memory/Linux/macOS backends
What remains for Phase 2:
  - build the real Linux userspace-shared runtime worker
  - own the authoritative UDP socket
  - start/stop resource lifecycle
  - authoritative identity only after successful start
  - no hidden fallback on partial startup failure
Residual risks / blockers:
  - This slice does not implement a transport-owning backend yet; it only prepares the crate and dependency substrate for that work.
  - macOS shared-backend parity remains intentionally unclaimed.
  - Live cross-network evidence and fresh-install matrix evidence remain separate blockers outside this Phase 1 slice.
```

```text
Date: 2026-04-01
Phase / Slice: Production transport-owning backend plan - Phase 2 Linux userspace-shared runtime skeleton
Files changed:
  - crates/rustynet-backend-wireguard/src/lib.rs
    - Re-exported the new Linux userspace-shared backend type without changing daemon wiring or default backend behavior.
  - crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs
    - Replaced the Phase 1 scaffold root with a real `LinuxUserspaceSharedBackend` implementation that validates inputs, binds runtime startup/shutdown to a worker-owned resource model, exposes authoritative transport identity only while running, and keeps later-phase workflows fail-closed.
  - crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs
    - Implemented the single-owner runtime worker, explicit request/reply control path, worker-owned transport/peer/handshake containers, ready handshake, and deterministic shutdown/join behavior.
  - crates/rustynet-backend-wireguard/src/userspace_shared/socket.rs
    - Implemented the real authoritative UDP socket binder and local-address identity reporting for the configured listen port.
  - crates/rustynet-backend-wireguard/src/userspace_shared/engine.rs
    - Implemented the real `boringtun`-backed key-material wrapper that reads the configured private key and owns the future peer engine state container inside the backend crate.
  - crates/rustynet-backend-wireguard/src/userspace_shared/handshake.rs
    - Replaced the scaffold with the owned handshake telemetry container required for later authenticated handshake evidence.
  - crates/rustynet-backend-wireguard/tests/conformance.rs
    - Added lifecycle coverage for the new Linux userspace-shared backend and explicit regression checks that the command-only Linux/macOS blocker strings remain unchanged.
  - documents/operations/active/ProductionTransportOwningWireGuardBackendPlan_2026-03-31.md
    - Marked Phase 2 complete with exact validation outcomes and Phase 3 remaining-open scope.
Tests and validation run:
  - `rustfmt --edition 2024 crates/rustynet-backend-wireguard/src/lib.rs crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs crates/rustynet-backend-wireguard/src/userspace_shared/socket.rs crates/rustynet-backend-wireguard/src/userspace_shared/engine.rs crates/rustynet-backend-wireguard/src/userspace_shared/handshake.rs crates/rustynet-backend-wireguard/tests/conformance.rs`
  - `cargo fmt --all -- --check`
  - `cargo check -p rustynet-backend-wireguard`
  - `cargo test -p rustynet-backend-wireguard --tests -- --nocapture`
  - `CARGO_TARGET_DIR=/tmp/rustynet-phase2-target-escalated cargo test -p rustynet-backend-wireguard --tests -- --nocapture`
  - `CARGO_TARGET_DIR=/tmp/rustynet-phase2-check cargo check -p rustynet-backend-wireguard`
Validation outcomes:
  - `rustfmt --edition 2024 ...`: pass
  - `cargo fmt --all -- --check`: fails on unrelated pre-existing formatting drift in [mod.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-cli/src/vm_lab/mod.rs)
  - `cargo check -p rustynet-backend-wireguard`: pass
  - sandboxed `cargo test -p rustynet-backend-wireguard --tests -- --nocapture`: blocked by sandbox `EPERM` on real UDP socket binds
  - unsandboxed backend-only rerun with isolated target dir: pass
  - final isolated-target backend `cargo check`: pass
  - backend crate unit tests: 22 passed
  - backend crate conformance tests: 6 passed
Security invariants verified:
  - The new Linux userspace-shared backend owns a real authoritative UDP socket and exposes its identity only after successful start; no daemon-owned or helper-owned side socket was introduced.
  - The runtime worker is the single owner of the authoritative socket, peer engine container, endpoint table, outstanding round-trip container, and handshake telemetry container; the public backend object does not duplicate transport ownership.
  - Startup failure after socket bind but before full runtime readiness rolls back cleanly and releases the port with no hidden fallback to command-only mode.
  - Later-phase transport-sensitive methods still fail closed with precise errors rather than pretending to provide STUN, relay, peer ciphertext, TUN, or handshake liveness features that Phase 2 does not implement.
What Phase 2 completed:
  - real `linux-wireguard-userspace-shared` backend type inside the backend crate
  - real authoritative UDP socket binding on `start(...)`
  - real worker thread plus request/reply control path
  - authoritative transport identity only after successful start
  - deterministic shutdown and partial-start rollback
  - unchanged fail-closed blocker behavior for command-only Linux/macOS backends
What remains for Phase 3:
  - authoritative transport round-trip/send implementation on the same socket
  - one-outstanding-round-trip enforcement and peer-endpoint rejection
  - same-socket STUN and relay control proof
Residual risks / blockers:
  - This slice does not yet wire STUN, relay control, peer ciphertext, TUN datapath, or authenticated handshake advancement into the new backend; those remain later phases.
  - Daemon/start/install selection surfaces are still intentionally untouched in this slice, so product/runtime behavior remains unchanged and the new mode is not yet selectable end-to-end.
  - The untouched Phase 1 [tun.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/tun.rs) scaffold still emits non-blocking dead-code warnings until the real TUN phase lands.
```

```text
Date: 2026-04-01
Phase / Slice: Production transport-owning backend plan - Phase 3 same-socket STUN and relay control
Files changed:
  - crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs
    - Replaced the earlier Phase 2 fail-closed authoritative round-trip/send stubs with real delegation into the userspace-shared runtime and added backend-slice tests for STUN, relay, concurrency, target rejection, timeout cleanup, and transport-generation proof.
  - crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs
    - Implemented real authoritative round-trip/send runtime messages, single in-flight generic round-trip enforcement, configured-peer target rejection, same-socket response demultiplexing, peer-path ingress routing for all non-round-trip datagrams, authoritative transport-generation recording, and waiter cleanup on timeout/shutdown/worker exit.
  - crates/rustynet-backend-wireguard/src/userspace_shared/socket.rs
    - Added authoritative socket send/receive helpers plus a monotonic authoritative transport-generation token so tests can prove same-socket identity without relying on same-port inference.
  - crates/rustynet-backend-wireguard/src/userspace_shared/engine.rs
    - Added conservative peer ciphertext ingress accounting at the engine boundary so non-round-trip datagrams are not dropped and the backend can prove they used the same authoritative transport generation as STUN and relay control.
  - documents/operations/active/ProductionTransportOwningWireGuardBackendPlan_2026-03-31.md
    - Marked Phase 3 complete with exact validation results and remaining Phase 4 scope.
Tests and validation run:
  - `rustfmt --edition 2024 crates/rustynet-backend-wireguard/src/userspace_shared/socket.rs crates/rustynet-backend-wireguard/src/userspace_shared/engine.rs crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs`
  - `cargo fmt --all -- --check`
  - `cargo check -p rustynet-backend-wireguard`
  - `cargo test -p rustynet-backend-wireguard --tests -- --nocapture`
  - `cargo test -p rustynetd daemon_runtime_authoritative_stun_refresh_uses_backend_shared_transport_identity -- --nocapture`
  - `cargo test -p rustynetd daemon_runtime_relay_establish_and_keepalive_use_backend_shared_transport_identity -- --nocapture`
  - `cargo test -p rustynetd daemon_runtime_production_backend_transport_identity_blocker_disables_stun_worker -- --nocapture`
  - `cargo test -p rustynetd daemon_runtime_transport_socket_identity_blocker_fail_closes_relay_bootstrap -- --nocapture`
Validation outcomes:
  - `cargo fmt --all -- --check`: pass
  - `cargo check -p rustynet-backend-wireguard`: pass
  - `cargo test -p rustynet-backend-wireguard --tests -- --nocapture`: pass
  - backend crate unit tests: 30 passed
  - backend crate conformance tests: 6 passed
  - targeted daemon authoritative-transport compatibility tests: 4 passed
  - non-blocking warning only: untouched Phase 1 [tun.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/tun.rs) scaffold still emits dead-code warnings because the TUN phase remains intentionally open
Security invariants verified:
  - STUN round trips, relay hello/refresh round trips, relay keepalive sends, and peer ciphertext ingress accounting all use the same backend-owned authoritative socket generation rather than a daemon-owned or same-port side socket.
  - The runtime worker remains the sole owner of authoritative socket state, peer engine state, endpoint state, outstanding generic round-trip state, and handshake telemetry state.
  - Only one generic authoritative round trip is allowed at a time; concurrent attempts are rejected fail-closed.
  - Generic authoritative round trips that target configured peer endpoints are rejected fail-closed to avoid ambiguity with peer ciphertext.
  - Timed-out or canceled round trips do not leave stale waiter attribution behind; late packets fall through to peer-path accounting instead of satisfying an old waiter.
  - Command-only Linux/macOS backends remain unchanged and still report precise blocker behavior.
What Phase 3 completed:
  - authoritative round-trip support on the Linux userspace-shared backend
  - authoritative one-way send support on the same backend-owned socket
  - strict one-outstanding-generic-round-trip enforcement
  - configured-peer-endpoint rejection for generic round trips
  - same-transport-generation proof across STUN, relay control, relay keepalive, and peer-path ingress accounting
What remains for Phase 4:
  - authenticated userspace-engine handshake truth
  - full peer ciphertext engine integration beyond conservative ingress accounting
  - TUN datapath ownership and later daemon/install/start selection work
Residual risks / blockers:
  - This slice does not yet provide authenticated handshake timestamps, full peer ciphertext datapath parity, or TUN lifecycle ownership; `direct_active` and `relay_active` truthfulness still depend on later phases.
  - Daemon/start/install selection surfaces remain intentionally untouched, so the new Linux userspace-shared backend is still not selectable end-to-end.
  - macOS userspace-shared parity remains unimplemented and unclaimed.
```

```text
Date: 2026-04-01
Phase / Slice: Production transport-owning backend plan - Phase 6 simulated proof and pre-live-lab validation
Files changed:
  - crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs
    - Added test-only recording of real peer-ciphertext egress on the authoritative socket so the proof bundle can assert the actual authoritative transport generation used by the peer path rather than inferring from receive-side coincidence.
  - crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs
    - Added the local multi-peer simulated proof test showing one Linux userspace-shared backend instance using the same authoritative transport generation for peer ciphertext, STUN round trip, relay round trip, and relay keepalive, and added the stronger restart/rollover regression that cancels stale round-trip state across same-port socket-generation rollover.
  - documents/operations/active/ProductionTransportOwningWireGuardBackendPlan_2026-03-31.md
    - Marked Phase 6 complete with exact validation outcomes and Phase 7 remaining-open scope.
Tests and validation run:
  - `rustfmt --edition 2024 crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs`
  - `cargo fmt --all -- --check`
  - `cargo check -p rustynet-backend-wireguard`
  - `cargo test -p rustynet-backend-wireguard --tests -- --nocapture`
Validation outcomes:
  - `cargo fmt --all -- --check`: pass
  - `cargo check -p rustynet-backend-wireguard`: pass
  - `cargo test -p rustynet-backend-wireguard --tests -- --nocapture`: pass
  - backend crate unit tests: 42 passed
  - backend crate conformance tests: 6 passed
  - targeted daemon validation: intentionally not rerun because no daemon code changed in this slice
Security invariants verified:
  - The authoritative transport proof is now generation-level rather than local-address-only, so same-port coincidence is not treated as authority.
  - One Linux userspace-shared backend instance now has local simulated proof that peer ciphertext, STUN, relay round trip, and relay keepalive all traverse the same authoritative transport generation on the production backend path.
  - Restart on the same local port advances the authoritative transport generation, cancels stale in-flight round-trip state, and prevents late packets from the old socket generation from satisfying stale waiters.
  - Existing fail-closed negative coverage remains intact for no identity before start, no identity after shutdown, concurrent round-trip rejection, round-trip-to-peer-endpoint rejection, no handshake from programmed state, and command-only backend blockers.
What Phase 6 completed:
  - local multi-peer simulated same-generation proof for peer ciphertext, STUN, and relay control on the production Linux userspace-shared backend path
  - explicit negative proof that same-port-after-restart is a different authoritative socket generation
  - explicit negative proof that transport-generation rollover invalidates stale round-trip state
  - preservation of truthful, conservative product claims while strengthening pre-lab confidence
What remains for Phase 7:
  - the broader regression stack and targeted daemon/backend/workspace validation required by Phase 7
  - CI gate execution
  - later live-lab evidence generation and artifact refresh
Residual risks / blockers:
  - The new Linux userspace-shared backend now has strong local simulated proof, but the final Phase 7 regression/gate pass still needs to confirm no broader workspace regressions remain.
  - No live evidence or artifact refresh was attempted in this slice, so repo-level completion claims remain intentionally conservative.
  - macOS userspace-shared parity remains unimplemented and unclaimed.
```

```text
Date: 2026-04-01
Phase / Slice: Production transport-owning backend plan - Phase 5 TUN lifecycle, helper boundary, and selection surfaces
Files changed:
  - crates/rustynet-backend-wireguard/src/userspace_shared/tun.rs
    - Replaced the Phase 1 scaffold with a real Linux TUN lifecycle abstraction, including direct backend-owned setup, helper-assisted host setup, deterministic cleanup, and test hooks that prove TUN ownership transfer and rollback without introducing a helper-owned datapath.
  - crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs
    - Wired the Linux userspace-shared backend through the new TUN lifecycle, kept startup fail-closed on TUN/socket/runtime failure, added deterministic shutdown cleanup, and expanded backend tests for TUN failure, rollback, authoritative transport state, and no silent downgrade.
  - crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs
    - Made the runtime worker the long-lived owner of the opened TUN device in addition to the authoritative socket, engine state, endpoint table, round-trip state, and handshake telemetry.
  - crates/rustynet-backend-wireguard/tests/conformance.rs
    - Updated the userspace-shared conformance path to use the test TUN lifecycle while preserving the command-only blocker coverage.
  - crates/rustynetd/src/daemon.rs
    - Replaced the old Linux userspace-shared blocker path with real backend construction on Linux, honest config validation, no-silent-downgrade startup behavior, and targeted runtime/status tests for authoritative backend shared transport reporting.
  - crates/rustynetd/src/privileged_helper.rs
    - Added the narrow `ip tuntap add dev <iface> mode tun user <uid> group <gid>` validation path required for helper-assisted Linux TUN creation.
  - crates/rustynet-cli/src/ops_install_systemd.rs
    - Added a service-template regression test that preserves explicit backend mode selection and verifies `/dev/net/tun` access remains present in the generated systemd unit.
  - scripts/systemd/rustynetd.service
    - Preserved `RUSTYNET_BACKEND` passthrough while adding explicit `/dev/net/tun` access for the daemon service template without changing the default backend.
  - documents/operations/active/ProductionTransportOwningWireGuardBackendPlan_2026-03-31.md
    - Marked Phase 5 complete with exact validation outcomes and Phase 6 remaining-open scope.
Tests and validation run:
  - `rustfmt --edition 2024 crates/rustynet-backend-wireguard/src/userspace_shared/tun.rs crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs crates/rustynet-backend-wireguard/tests/conformance.rs crates/rustynetd/src/daemon.rs crates/rustynetd/src/privileged_helper.rs crates/rustynet-cli/src/ops_install_systemd.rs`
  - `cargo fmt --all -- --check`
  - `cargo check -p rustynet-backend-wireguard`
  - `cargo check -p rustynetd`
  - `cargo check -p rustynet-cli --bin rustynet-cli`
  - `cargo test -p rustynet-backend-wireguard --tests -- --nocapture`
  - `cargo test -p rustynetd validate_daemon_config_accepts_linux_userspace_shared_backend -- --nocapture`
  - `cargo test -p rustynetd daemon_runtime_production_backend_transport_identity_blocker_disables_stun_worker -- --nocapture`
  - `cargo test -p rustynetd daemon_runtime_linux_userspace_shared_backend_reports_authoritative_transport_state -- --nocapture`
  - `cargo test -p rustynet-cli --bin rustynet-cli rustynetd_service_template_preserves_backend_env_and_tun_device_access -- --nocapture`
Validation outcomes:
  - `cargo fmt --all -- --check`: pass
  - `cargo check -p rustynet-backend-wireguard`: pass
  - `cargo check -p rustynetd`: pass
  - `cargo check -p rustynet-cli --bin rustynet-cli`: pass
  - `cargo test -p rustynet-backend-wireguard --tests -- --nocapture`: pass
  - backend crate unit tests: 40 passed
  - backend crate conformance tests: 6 passed
  - targeted daemon construction/status/blocker tests: 3 passed
  - targeted CLI service-template regression test: pass
Security invariants verified:
  - The backend runtime, not the daemon or helper, is now the long-lived owner of the TUN handle, authoritative UDP socket, userspace WireGuard engine state, endpoint table, round-trip state, and handshake telemetry.
  - Helper involvement remains narrow and host-setup only; the helper never owns long-lived packet forwarding, authoritative transport identity, STUN/relay control traffic, or the userspace engine.
  - TUN setup or later startup failure tears down partial state deterministically and never silently downgrades to the command-only backend.
  - Explicit `linux-wireguard-userspace-shared` selection now survives daemon/config/install/start/systemd surfaces unchanged while Linux/macOS default backend selection remains `linux-wireguard` and `macos-wireguard`.
  - Command-only Linux/macOS backends remain unchanged and continue to fail closed on authoritative transport identity.
  - Unsupported capability claims, including `auto_port_forward_exit`, remain unchanged and unclaimed for the userspace-shared backend.
What Phase 5 completed:
  - real Linux TUN lifecycle support for the userspace-shared backend
  - helper-assisted host setup without helper-owned datapath or authority
  - end-to-end explicit mode selection for `linux-wireguard-userspace-shared` across daemon/config/install/start/systemd surfaces
  - authoritative backend shared transport status reporting for the real Linux userspace-shared backend
  - deterministic startup rollback and shutdown cleanup with no silent downgrade
What remains for Phase 6:
  - simulated multi-peer proof that peer ciphertext, STUN, relay round trips, and relay keepalive all share the same authoritative transport generation on the production Linux backend path
  - integrated negative proof for same-port-new-socket rejection, transport-generation rollover cleanup, and stale-handshake invalidation on the production Linux backend path
  - later full regression, gate, and live-evidence work
Residual risks / blockers:
  - The new Linux userspace-shared backend is now selectable, but the Phase 6 simulated-proof bundle still needs to prove the full same-generation invariant end-to-end before final completion claims are justified.
  - macOS userspace-shared parity remains unimplemented and unclaimed.
  - README and repo-level completion claims remain intentionally conservative until later proof, gate, and live-evidence phases land.
```

```text
Date: 2026-04-01
Phase / Slice: Production transport-owning backend plan - Phase 4 userspace engine integration and handshake telemetry
Files changed:
  - crates/rustynet-backend-wireguard/src/userspace_shared/engine.rs
    - Replaced the Phase 3 ingress-only engine boundary with real per-peer `boringtun::noise::Tunn` ownership, endpoint/allowed-IP matching, inbound ciphertext decapsulation, outbound plaintext encapsulation from the backend-internal test boundary, authenticated handshake observation extraction, and honest byte accounting.
  - crates/rustynet-backend-wireguard/src/userspace_shared/handshake.rs
    - Tightened handshake telemetry so it records monotonic per-peer timestamps only from authenticated engine evidence and clears that state on peer replacement or removal.
  - crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs
    - Wired runtime-owned peer state, endpoint mutation, authenticated handshake propagation, honest peer/stats queries, and the backend-internal plaintext injection path into the single-owner worker without weakening Phase 3 authoritative socket behavior.
  - crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs
    - Added Phase 4 backend tests for authenticated handshake advancement, negative handshake cases, peer replacement/removal, honest endpoint reporting, honest stats, and restart freshness reset.
  - documents/operations/active/ProductionTransportOwningWireGuardBackendPlan_2026-03-31.md
    - Marked Phase 4 complete with exact validation outcomes and Phase 5 remaining-open scope.
Tests and validation run:
  - `rustfmt --edition 2024 crates/rustynet-backend-wireguard/src/userspace_shared/engine.rs crates/rustynet-backend-wireguard/src/userspace_shared/handshake.rs crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs`
  - `cargo fmt --all -- --check`
  - `cargo check -p rustynet-backend-wireguard`
  - `cargo test -p rustynet-backend-wireguard --tests -- --nocapture`
  - `cargo test -p rustynetd daemon_runtime_relay_session_becomes_live_only_with_selected_endpoint_and_fresh_handshake -- --nocapture`
  - `cargo test -p rustynetd daemon_runtime_relay_session_endpoint_mismatch_is_not_live -- --nocapture`
  - `cargo test -p rustynetd daemon_runtime_auto_tunnel_direct_health_uses_live_handshake_without_forced_reprobe -- --nocapture`
  - `cargo test -p rustynetd daemon_runtime_auto_tunnel_direct_liveness_expiry_falls_back_to_relay -- --nocapture`
Validation outcomes:
  - `cargo fmt --all -- --check`: pass
  - `cargo check -p rustynet-backend-wireguard`: pass
  - `cargo test -p rustynet-backend-wireguard --tests -- --nocapture`: pass
  - backend crate unit tests: 38 passed
  - backend crate conformance tests: 6 passed
  - targeted daemon truthfulness regression tests: 4 passed
Security invariants verified:
  - The runtime worker remains the sole owner of authoritative socket state, per-peer userspace engine state, endpoint state, round-trip state, and handshake telemetry.
  - Authenticated handshake freshness now advances only from userspace-engine evidence; configuration changes, endpoint programming, STUN traffic, relay control traffic, and backend startup do not fabricate handshake proof.
  - Phase 3 same-socket authoritative transport behavior remains intact while peer ciphertext and plaintext test-boundary traffic now traverse the same backend-owned engine/runtime boundary.
  - Peer removal and peer replacement clear prior handshake telemetry so stale authenticated state is not preserved across runtime-owned peer mutations or backend restart.
  - Stats and current-endpoint queries report runtime-owned state honestly and do not overclaim relay or live-path facts.
What Phase 4 completed:
  - runtime-owned per-peer userspace WireGuard engine state
  - authenticated handshake telemetry sourced from engine evidence only
  - honest `configure_peer(...)`, `update_peer_endpoint(...)`, `current_peer_endpoint(...)`, `peer_latest_handshake_unix(...)`, `remove_peer(...)`, and `stats(...)` behavior on the Linux userspace-shared backend
  - backend-internal plaintext-to-ciphertext proof path without widening host TUN or daemon mode-selection claims
What remains for Phase 5:
  - host TUN lifecycle and helper-boundary integration
  - daemon/install/start selection-surface wiring for `linux-wireguard-userspace-shared`
  - end-to-end mode activation and later live evidence/gate work
Residual risks / blockers:
  - The Phase 4 plaintext path is still the backend-internal test boundary rather than the final host TUN lifecycle, so full Linux runtime dataplane parity remains incomplete.
  - The new Linux userspace-shared backend is still intentionally not wired into daemon/install/start selection surfaces in this slice.
  - macOS userspace-shared parity remains unimplemented and unclaimed.
```

```text
Date: 2026-04-01
Phase / Slice: Production transport-owning backend plan - Phase 7 final regression and gate validation
Files changed:
  - documents/operations/active/ProductionTransportOwningWireGuardBackendPlan_2026-03-31.md
    - Recorded the full Phase 7 validation order, reruns, outcomes, and exact pre-live-lab blockers without widening any completion claim.
  - documents/operations/active/PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md
    - Added the public Phase 7 validation evidence entry with exact pass/fail classification and blocker prerequisites.
Commands run:
  - `rustfmt --edition 2024 crates/rustynet-backend-wireguard/src/lib.rs crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs crates/rustynet-backend-wireguard/src/userspace_shared/socket.rs crates/rustynet-backend-wireguard/src/userspace_shared/engine.rs crates/rustynet-backend-wireguard/src/userspace_shared/handshake.rs crates/rustynet-backend-wireguard/src/userspace_shared/tun.rs crates/rustynet-backend-wireguard/tests/conformance.rs crates/rustynetd/src/daemon.rs crates/rustynetd/src/main.rs crates/rustynetd/src/privileged_helper.rs crates/rustynetd/src/stun_client.rs crates/rustynetd/src/relay_client.rs crates/rustynet-cli/src/main.rs crates/rustynet-cli/src/ops_write_daemon_env.rs crates/rustynet-cli/src/ops_install_systemd.rs`
  - `cargo fmt --all -- --check`
  - `cargo check -p rustynet-backend-wireguard`
  - `cargo check -p rustynetd`
  - `cargo test -p rustynet-backend-wireguard --tests -- --nocapture`
  - `cargo test -p rustynetd daemon_runtime_ -- --nocapture`
  - `cargo check --workspace --all-targets --all-features`
  - `cargo test --workspace --all-targets --all-features`
  - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
  - `cargo audit --deny warnings`
  - `cargo deny check bans licenses sources advisories`
  - `./scripts/ci/phase10_hp2_gates.sh`
  - `./scripts/ci/membership_gates.sh`
  - `./scripts/ci/phase10_cross_network_exit_gates.sh`
  - `./scripts/ci/phase10_gates.sh`
Reruns performed:
  - No code-regression reruns were required in this validation pass.
  - `membership_gates.sh` was allowed to run to completion so the tail failure could be classified precisely instead of being mistaken for a userspace-shared runtime regression.
Validation outcomes:
  - `cargo fmt --all -- --check`: pass
  - `cargo check -p rustynet-backend-wireguard`: pass
  - `cargo check -p rustynetd`: pass
  - targeted backend tests: pass
  - targeted daemon runtime tests: pass
  - `cargo check --workspace --all-targets --all-features`: pass
  - `cargo test --workspace --all-targets --all-features`: pass
  - `cargo clippy --workspace --all-targets --all-features -- -D warnings`: pass
  - `cargo audit --deny warnings`: fail
    - root cause: `tun-rs 2.8.2` pulls `route_manager` and `netconfig-rs`, which pull `netlink-packet-core`, which still depends on unmaintained `paste 1.0.15` (`RUSTSEC-2024-0436`)
  - `cargo deny check bans licenses sources advisories`: fail
    - root cause: same `paste 1.0.15` advisory plus license-policy rejection of `BSD-2-Clause` and `ISC` licenses introduced by the new `boringtun` / `tun-rs` dependency chain; the rejecting crates observed in this run were `ip_network`, `ip_network_table`, `libloading`, `ring`, and `untrusted`
  - `./scripts/ci/phase10_hp2_gates.sh`: pass
  - `./scripts/ci/membership_gates.sh`: fail only because it delegates into the stale fresh-install evidence gate already proven by `phase10_gates.sh`; no hidden userspace-shared backend regression was observed
  - `./scripts/ci/phase10_cross_network_exit_gates.sh`: fail only because the six canonical live cross-network reports are still missing for current `HEAD`
  - `./scripts/ci/phase10_gates.sh`: fail only because `artifacts/phase10/fresh_install_os_matrix_report.json` is stale for current `HEAD`
    - exact gate output: `report=c86a62a766b8af8382dfa57805aec8b4cad284ff expected=06e3e2ed745b4439505991bea775246cde8ed653`
Security invariants re-verified:
  - The Linux userspace-shared backend still owns the authoritative UDP socket, TUN runtime state, userspace engine state, round-trip control state, and handshake telemetry without daemon-side or helper-side transport authority.
  - Command-only Linux/macOS backends remain unchanged and still fail closed on authoritative shared transport.
  - `direct_active` still requires fresh handshake proof.
  - `relay_active` still requires fresh handshake proof plus authenticated relay-session consistency.
  - No validation result showed second-socket authority, silent downgrade from userspace-shared to command-only, or weakened gate semantics.
  - Evidence gates remain fail-closed on missing or stale artifacts.
What Phase 7 established:
  - The Phases 1 through 6 backend/runtime work is present and regression-clean under fmt, check, test, clippy, targeted daemon truthfulness tests, and Phase 10 HP2 traversal gates.
  - The remaining blockers before honest pre-live-lab readiness are no longer runtime-behavior ambiguities; they are now explicit dependency-policy blockers and explicit stale/missing evidence blockers.
What remains before claiming pre-live-lab readiness:
  - remove or replace the `tun-rs 2.8.2` dependency path that introduces unmaintained `paste 1.0.15`, or land a policy-approved secure alternative without weakening audit/deny gates
  - resolve the repository license-policy failures introduced by the `boringtun` / `tun-rs` dependency chain without weakening the deny gate
  - regenerate `artifacts/phase10/fresh_install_os_matrix_report.json` for current `HEAD`
  - run the live lab on `linux-wireguard-userspace-shared` and generate the six canonical cross-network reports for current `HEAD`
Residual risks / blockers:
  - Phase 7 cannot be declared cleanly complete while `cargo audit` and `cargo deny` are red on the new userspace-shared dependency chain.
  - `membership_gates.sh` remains red until the stale fresh-install evidence blocker is resolved; the current failure is inherited from the fresh-install release gate rather than from the backend implementation itself.
  - The repo is not yet pre-live-lab ready because the fresh-install evidence still points at an older commit and the six canonical live cross-network reports are still absent for current `HEAD`.
  - macOS userspace-shared parity remains out of scope, blocked, and unclaimed.
```

```text
Date: 2026-04-02
Phase / Slice: Linux userspace-shared live-lab delta Phase 1 backend route programming
Files changed:
  - crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs
    - Made `linux-wireguard-userspace-shared` `apply_routes(...)` real, kept `set_exit_mode(...)` fail-closed for the next delta phase, and added backend tests for route reconciliation, rollback, invalid-route rejection, and transport-identity preservation.
  - crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs
    - Moved userspace-shared route reconciliation into the single-owner runtime worker, added runtime-owned current-route state, and replaced the old `apply_routes` placeholder request path with real runtime reconciliation.
  - crates/rustynet-backend-wireguard/src/userspace_shared/tun.rs
    - Added shared TUN lifecycle ownership, helper/direct/backend route reconciliation with rollback, explicit skipping of `RouteKind::ExitNodeDefault` on both add and stale-delete paths, and lower-level route-runner regression coverage.
  - documents/operations/active/LinuxUserspaceSharedLiveLabReadinessDelta_2026-04-02.md
    - Marked Delta Phase 1 code-complete and updated the remaining-gap description so only `set_exit_mode(...)` remains as the backend runtime placeholder.
  - documents/operations/active/PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md
    - Added this public evidence entry for the Delta Phase 1 route-programming slice.
Commands run:
  - `rustfmt --edition 2024 crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs crates/rustynet-backend-wireguard/src/userspace_shared/tun.rs`
  - `cargo fmt --all -- --check`
  - `cargo check -p rustynet-backend-wireguard`
  - `cargo test -p rustynet-backend-wireguard --tests -- --nocapture`
  - `cargo check -p rustynetd`
  - `cargo test -p rustynetd apply_rollback_forces_fail_closed_when_system_step_fails -- --nocapture`
  - `cargo test -p rustynetd daemon_runtime_linux_userspace_shared_backend_reports_authoritative_transport_state -- --nocapture`
Validation outcomes:
  - `cargo fmt --all -- --check`: pass
  - `cargo check -p rustynet-backend-wireguard`: pass
  - `cargo test -p rustynet-backend-wireguard --tests -- --nocapture`: pass
    - backend unit tests: `48` passed
    - backend conformance tests: `6` passed
  - `cargo check -p rustynetd`: pass
  - `cargo test -p rustynetd apply_rollback_forces_fail_closed_when_system_step_fails -- --nocapture`: pass
  - `cargo test -p rustynetd daemon_runtime_linux_userspace_shared_backend_reports_authoritative_transport_state -- --nocapture`: pass
Security invariants re-verified:
  - The userspace-shared backend still keeps authoritative UDP socket ownership, userspace engine ownership, and TUN/runtime ownership inside the backend/runtime path.
  - `apply_routes(...)` now mutates only backend-owned interface route state; default-route, firewall, NAT, DNS-protection, and killswitch logic remain in the existing system layer.
  - `RouteKind::ExitNodeDefault` is still not treated as backend interface-route authority.
  - Invalid route state, replace-side failures, and stale-delete failures all fail closed without silently downgrading to the command-only backend.
  - Route reconciliation does not change authoritative transport identity or transport generation.
What Delta Phase 1 completed:
  - `linux-wireguard-userspace-shared` no longer fail-closes on backend `apply_routes(...)`.
  - Runtime-owned route state is now reconciled and rolled back deterministically through the shared TUN lifecycle.
  - Existing daemon fail-closed reconciliation semantics remain unchanged under targeted regression tests.
What remains before the next reduced live-lab rerun:
  - implement honest `set_exit_mode(...)` for `linux-wireguard-userspace-shared`
  - keep route/exit-mode state consistent with rollback and shutdown behavior
  - rerun the reduced five-node helper lab only after Delta Phase 2 lands
Residual risks / blockers:
  - Delta Phase 1 is code-complete, but it is not yet live-proven because the reduced live-lab rerun still depends on the missing exit-mode programming slice.
  - Dependency-policy and evidence blockers from the earlier Phase 7 validation remain unresolved and unchanged.
  - macOS userspace-shared parity remains out of scope, blocked, and unclaimed.
```

```text
Date: 2026-04-02
Phase / Slice: Linux userspace-shared live-lab delta Phase 2 backend exit-mode programming
Files changed:
  - crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs
    - Made `linux-wireguard-userspace-shared` `set_exit_mode(...)` real, removed the later-phase placeholder path, updated Linux userspace-shared capabilities to truthfully advertise exit-node and LAN-route support, and added backend tests for full-tunnel apply, off-mode clearing, rollback failure handling, shutdown clearing, and no-downgrade behavior.
  - crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs
    - Replaced the old fail-closed `SetExitMode` placeholder request with real runtime-owned exit-mode reconciliation, added runtime-owned current-exit-mode state, and made worker shutdown explicitly clear backend exit-mode state before teardown.
  - crates/rustynet-backend-wireguard/src/userspace_shared/tun.rs
    - Added backend exit-mode reconcile/rollback for direct, helper-backed, and test TUN lifecycles, including the Linux command-backend parity `ip rule` sequence for table `51820`, test-side exit-mode mutation recording, and lower-level exit-mode regression coverage.
  - crates/rustynet-backend-wireguard/tests/conformance.rs
    - Added conformance coverage proving Linux userspace-shared now supports the combined route and exit-mode lifecycle honestly under backend-crate tests.
  - documents/operations/active/LinuxUserspaceSharedLiveLabReadinessDelta_2026-04-02.md
    - Marked Delta Phase 2 code-complete and updated the remaining delta so the next step is the reduced five-node rerun rather than another backend placeholder removal.
  - documents/operations/active/PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md
    - Added this public evidence entry for the Delta Phase 2 exit-mode-programming slice.
Commands run:
  - `rustfmt --edition 2024 crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs crates/rustynet-backend-wireguard/src/userspace_shared/tun.rs crates/rustynet-backend-wireguard/tests/conformance.rs`
  - `cargo fmt --all -- --check`
  - `cargo check -p rustynet-backend-wireguard`
  - `cargo test -p rustynet-backend-wireguard --tests -- --nocapture`
  - `cargo check -p rustynetd`
  - `cargo test -p rustynetd apply_rollback_forces_fail_closed_when_system_step_fails -- --nocapture`
  - `cargo test -p rustynetd daemon_runtime_linux_userspace_shared_backend_reports_authoritative_transport_state -- --nocapture`
  - `cargo test -p rustynetd daemon_runtime_relay_session_becomes_live_only_with_selected_endpoint_and_fresh_handshake -- --nocapture`
  - `cargo test -p rustynetd daemon_runtime_relay_session_endpoint_mismatch_is_not_live -- --nocapture`
  - `cargo test -p rustynetd daemon_runtime_auto_tunnel_direct_health_uses_live_handshake_without_forced_reprobe -- --nocapture`
  - `cargo test -p rustynetd daemon_runtime_auto_tunnel_direct_liveness_expiry_falls_back_to_relay -- --nocapture`
Validation outcomes:
  - `cargo fmt --all -- --check`: pass
  - `cargo check -p rustynet-backend-wireguard`: pass
  - `cargo test -p rustynet-backend-wireguard --tests -- --nocapture`: pass
    - backend unit tests: `55` passed
    - backend conformance tests: `7` passed
  - `cargo check -p rustynetd`: pass
  - `cargo test -p rustynetd apply_rollback_forces_fail_closed_when_system_step_fails -- --nocapture`: pass
  - `cargo test -p rustynetd daemon_runtime_linux_userspace_shared_backend_reports_authoritative_transport_state -- --nocapture`: pass
  - `cargo test -p rustynetd daemon_runtime_relay_session_becomes_live_only_with_selected_endpoint_and_fresh_handshake -- --nocapture`: pass
  - `cargo test -p rustynetd daemon_runtime_relay_session_endpoint_mismatch_is_not_live -- --nocapture`: pass
  - `cargo test -p rustynetd daemon_runtime_auto_tunnel_direct_health_uses_live_handshake_without_forced_reprobe -- --nocapture`: pass
  - `cargo test -p rustynetd daemon_runtime_auto_tunnel_direct_liveness_expiry_falls_back_to_relay -- --nocapture`: pass
Security invariants re-verified:
  - The userspace-shared backend still keeps authoritative UDP socket ownership, userspace engine ownership, and long-lived TUN/runtime ownership inside the backend/runtime path.
  - Exit-mode state is now runtime-owned and reconciled through the shared TUN lifecycle; shutdown clears backend exit-mode state deterministically before runtime teardown.
  - Full-tunnel rule programming mirrors the Linux command backend table `51820` behavior without introducing helper-owned transport authority, a second socket, or a daemon-owned side path.
  - Exit-mode failures, delete-side failures, and add-side failures all fail closed without silently downgrading to the command-only backend.
  - Route and exit-mode mutation do not change authoritative transport identity, transport generation, `direct_active` truthfulness, or `relay_active` truthfulness.
What Delta Phase 2 completed:
  - `linux-wireguard-userspace-shared` no longer fail-closes on backend `set_exit_mode(...)`.
  - Linux userspace-shared backend route application and exit-mode programming are now code-complete locally and validated under targeted backend/daemon tests.
  - Rollback and shutdown now clear backend-owned exit-mode state deterministically through the runtime-owned TUN lifecycle.
What remains before the next reduced live-lab rerun:
  - rerun the reduced five-node helper lab on the current committed tree and confirm `enforce_baseline_runtime` now succeeds on all nodes
  - if that rerun exposes a new fail-closed reconcile blocker, fix that exact blocker rather than reopening the completed route/exit-mode slice
  - after the reduced rerun is clean, resume the already-documented dependency-policy and evidence blocker cleanup
Residual risks / blockers:
  - Delta Phase 2 is code-complete and locally validated, but it is not yet real-host-proven because the reduced five-node rerun has not been repeated against the new exit-mode code.
  - Dependency-policy blockers from the earlier Phase 7 validation remain unresolved and unchanged.
  - macOS userspace-shared parity remains out of scope, blocked, and unclaimed.
```

```text
Date: 2026-04-02
Phase / Slice: Reduced five-node live-lab reruns on committed `main` after userspace-shared selection/helper fixes
Files changed:
  - crates/rustynetd/src/daemon.rs
    - Extended runtime WireGuard key preparation and scrubbing to include `linux-wireguard-userspace-shared`, and added daemon regression coverage so the encrypted-key runtime file is materialized for the userspace backend before startup instead of failing on missing `/run/rustynet/wireguard.key`.
  - scripts/systemd/rustynetd-privileged-helper.service
    - Added `/dev/net/tun` bind/access inside the privileged-helper private device namespace so helper-assisted `ip tuntap add ...` can open the host TUN device.
  - crates/rustynet-cli/src/ops_install_systemd.rs
    - Added a regression test proving the privileged-helper service template preserves `/dev/net/tun` access while keeping `PrivateDevices=true`.
  - documents/operations/active/ProductionTransportOwningWireGuardBackendPlan_2026-03-31.md
    - Corrected the production-backend plan status so it no longer implies “policy blockers only”; the new live-lab evidence proves a remaining route/exit-mode implementation gap.
  - documents/operations/active/PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md
    - Added this public evidence entry for the reduced live-lab reruns and the newly proven blocker.
Commands run:
  - `cargo fmt --all -- --check`
  - `cargo check -p rustynetd`
  - `cargo test -p rustynetd runtime_key_ -- --nocapture`
  - `cargo test -p rustynetd validate_daemon_config_accepts_linux_userspace_shared_backend -- --nocapture`
  - `cargo check -p rustynet-cli --bin rustynet-cli`
  - `cargo test -p rustynet-cli --bin rustynet-cli rustynetd_service_template_preserves_backend_env_and_tun_device_access -- --nocapture`
  - `cargo test -p rustynet-cli --bin rustynet-cli privileged_helper_service_template_preserves_tun_device_access_for_helper_owned_setup -- --nocapture`
  - `cargo run --quiet -p rustynet-cli -- ops vm-lab-write-live-lab-profile --inventory documents/operations/active/vm_lab_inventory.json --output profiles/live_lab/generated_vm_lab_5node.env --ssh-identity-file /Users/iwanteague/.ssh/rustynet_lab_ed25519 --ssh-known-hosts-file /Users/iwanteague/.ssh/known_hosts --exit-vm debian-headless-1 --client-vm debian-headless-2 --entry-vm debian-headless-3 --aux-vm debian-headless-4 --extra-vm debian-headless-5 --require-same-network --backend linux-wireguard-userspace-shared --source-mode local-head --repo-ref HEAD`
  - `cargo run --quiet -p rustynet-cli -- ops vm-lab-preflight --inventory documents/operations/active/vm_lab_inventory.json --all --known-hosts-file /Users/iwanteague/.ssh/known_hosts --require-command git --require-command cargo --require-command systemctl --timeout-secs 120`
  - `cargo run --quiet -p rustynet-cli -- ops vm-lab-run-live-lab --profile profiles/live_lab/generated_vm_lab_5node.env --skip-gates --skip-soak --skip-cross-network`
  - `ssh debian-headless-1 'sudo -n systemctl status rustynetd-managed-dns.service --no-pager -l ...'`
  - `ssh debian-headless-1 'sudo -n /usr/local/bin/rustynet status ...'`
  - `ssh debian-headless-3 'sudo -n systemctl status rustynetd-managed-dns.service --no-pager -l ...'`
Validation and live-lab outcomes:
  - The reduced helper flow now preserves `RUSTYNET_BACKEND=linux-wireguard-userspace-shared` into `/etc/default/rustynetd`, and the userspace backend no longer fails on missing runtime key material.
  - The first rerun after the daemon key fix advanced past the old startup crash and proved the next blocker was helper-side `/dev/net/tun` access.
  - The second rerun after the helper-unit fix advanced through:
    - `bootstrap_hosts`
    - `collect_pubkeys`
    - `membership_setup`
    - `distribute_membership_state`
    - `issue_and_distribute_assignments`
    - `issue_and_distribute_traversal`
  - The lab still failed at `enforce_baseline_runtime`, with artifacts captured under:
    - `artifacts/live_lab/20260402T111820Z`
    - `artifacts/live_lab/20260402T113358Z`
  - On failing nodes, `rustynetd-managed-dns.service` is only the visible symptom:
    - exit/admin now fails with `resolvectl default-route rustynet0 no failed: Failed to resolve interface "rustynet0": No such device`
    - `rustynet status` on the exit node reports `last_reconcile_error=reconcile dataplane apply failed: backend error: Internal: linux userspace-shared backend does not yet implement route application; later production transport-owning phases remain open`
  - Mixed node results make the current blocker precise rather than ambiguous:
    - `entry` and `aux` completed `e2e enforce host`
    - `exit`, `client`, and `extra` remained fail-closed during baseline runtime enforcement
Security invariants re-verified:
  - No daemon-owned or helper-owned side socket was introduced.
  - The userspace backend still fails closed rather than faking route or exit-node success.
  - Command-only backend modes remain unchanged.
  - Managed-DNS enforcement still fails closed when the dataplane interface is not present.
What this live-lab slice actually proved:
  - The earlier helper-path blockers are resolved:
    - userspace backend selection survives the five-node helper flow
    - runtime WireGuard key material is prepared correctly for the userspace backend
    - the privileged helper can now open `/dev/net/tun` for helper-assisted TUN creation
  - The remaining blocker is a real backend implementation gap, not a harness bug or evidence-policy issue:
    - Linux userspace-shared still does not honestly implement `apply_routes(...)`
    - exit-mode / baseline dataplane programming therefore still fail closed under real enforcement
What remains before the reduced live lab can complete honestly:
  - implement Linux userspace-shared route application and exit-mode programming in the backend/runtime path
  - rerun the reduced five-node helper lab until `enforce_baseline_runtime` succeeds on all nodes
  - only after that resume the stale fresh-install evidence regeneration and the six canonical live cross-network report runs
Residual risks / blockers:
  - The repo is still not ready for an honest live-lab completion claim because the production Linux userspace-shared backend remains incomplete for route/exit-mode programming.
  - Dependency-policy blockers from the Phase 7 validation run remain unresolved and still must be fixed before final gate-clean status can be claimed.
  - macOS userspace-shared parity remains out of scope, blocked, and unclaimed.
```

```text
Date: 2026-04-02
Phase / Slice: Linux userspace-shared live-lab delta - Rust role-switch host-key candidate alignment and fresh reduced rerun
Files changed:
  - crates/rustynet-cli/src/bin/live_lab_bin_support/mod.rs
    - Replaced raw-host-only pinned `known_hosts` validation with effective SSH target candidate validation (`hostkeyalias`, raw host, resolved hostname, and port-aware bracket form) and added unit coverage for candidate construction.
  - crates/rustynet-cli/src/bin/live_lab_support/mod.rs
    - Applied the same effective SSH target candidate validation to the `LiveLabContext`-based live-lab binaries so later live stages do not regress to raw-host-only pinning checks.
  - documents/operations/active/LinuxUserspaceSharedLiveLabReadinessDelta_2026-04-02.md
    - Reopened Delta Phase 3 honestly and recorded that the current fresh rerun is now blocked by exit-node restricted-safe / traversal-reconcile instability rather than the old role-switch `known_hosts` precheck.
  - documents/operations/active/PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md
    - Added this evidence entry.
Commands run:
  - `rustfmt --edition 2024 crates/rustynet-cli/src/bin/live_lab_bin_support/mod.rs crates/rustynet-cli/src/bin/live_lab_support/mod.rs`
  - `bash -n scripts/e2e/live_linux_lab_orchestrator.sh`
  - `cargo test -p rustynet-cli --bin live_linux_role_switch_matrix_test -- --nocapture`
  - `cargo test -p rustynet-cli --bin live_linux_managed_dns_test -- --nocapture`
  - `cargo fmt --all -- --check`
  - `cargo run --quiet -p rustynet-cli -- ops vm-lab-run-live-lab --profile profiles/live_lab/generated_vm_lab_5node_phase3_replayfix.env --skip-gates --skip-soak --skip-cross-network --source-mode working-tree --timeout-secs 7200`
  - `ssh ... debian@debian-headless-1 'sudo -n env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet status'`
  - `ssh ... debian@debian-headless-1 'sudo -n journalctl -u rustynetd.service -n 80 --no-pager --output=short-iso | tail -n 80'`
  - `ssh ... debian@debian-headless-1 'sudo -n env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet state refresh && rustynet status'`
  - `ssh ... debian@debian-headless-1 'for i in 1 2 3 4 5 6; do rustynet status ...; sleep 2; done'`
Validation and live-lab outcomes:
  - The Rust live-lab support modules now validate pinned host keys against the effective SSH target rather than the raw host token only, matching the already-hardened shell helper logic.
  - Targeted CLI tests passed:
    - `live_linux_role_switch_matrix_test`: 8 passed
    - `live_linux_managed_dns_test`: 21 passed
  - `cargo fmt --all -- --check` passed after the support-module edits.
  - The fresh reduced five-node rerun at `artifacts/live_lab/phase3_worktree_rerun_replayfix` advanced through:
    - `bootstrap_hosts`
    - `collect_pubkeys`
    - `membership_setup`
    - `distribute_membership_state`
    - `issue_and_distribute_assignments`
    - `issue_and_distribute_traversal`
  - The same rerun failed at `enforce_baseline_runtime`, not at `live_role_switch_matrix`.
  - The exact failure is now:
    - `error: daemon is in restricted-safe mode`
    - triggered by the exit-node `rustynet route advertise 0.0.0.0/0` step after the fresh signed traversal redistribution and `state refresh`
  - Exit-node status captured immediately after the failure reported:
    - `restricted_safe_mode=true`
    - `last_reconcile_error=traversal authority rejected reconcile apply: traversal authority requires valid signed traversal state: traversal authority failed to program peer client-1: traversal probe failed: traversal failed closed: DirectProbeExhaustedFailClosed`
  - A manual `rustynet state refresh` can transiently report `restricted_safe_mode=false`, but repeated polling shows the daemon falls back into restricted-safe mode and route advertisement remains denied. This is not a stable workaround.
Security invariants re-verified:
  - SSH pinning was not weakened; the fix widened lookup candidates to the actual resolved SSH target but continued to require a pinned host key in the pinned `known_hosts` file.
  - No daemon-owned or helper-owned side socket was introduced.
  - Restricted-safe semantics remain fail-closed; the daemon still denies route advertisement while restricted instead of accepting an unsafe mutation.
  - The old route-application and exit-mode placeholder failures remain absent from the current tree.
What this slice completed:
  - The Rust live-lab host-key lookup path now matches the secure shell-helper behavior and is locally unit-tested.
  - The previous role-switch `known_hosts` blocker is no longer the current first blocker on the reduced five-node path.
What remains blocked:
  - The next real blocker is stable exit-node signed-state / traversal recovery before `rustynet route advertise 0.0.0.0/0` during `enforce_baseline_runtime`.
  - The reduced helper flow still has not reached `live_role_switch_matrix` on the current tree, so the host-key candidate fix is not yet live-proven end-to-end.
  - Repo-level dependency-policy blockers and evidence blockers remain unchanged and fail-closed.
```

```text
Date: 2026-04-02
Phase / Slice: Linux userspace-shared live-lab delta - Delta Phase 3 focused validation and reduced five-node rerun
Files changed:
  - scripts/e2e/live_linux_lab_orchestrator.sh
    - Refactored traversal-bundle issuance/distribution into a reusable helper, reissued fresh signed traversal bundles after baseline enforcement, added a second signed-state refresh before exit-route advertisement, and tightened `validate_baseline_runtime` so it explicitly enforces the actual Phase 3 contract instead of relying on weak bare `[[ ... ]]` expressions.
  - documents/operations/active/LinuxUserspaceSharedLiveLabReadinessDelta_2026-04-02.md
    - Marked Delta Phase 3 complete for the baseline-runtime slice and recorded that the next blocker moved forward to `live_role_switch_matrix` pinned host-key handling.
  - documents/operations/active/PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md
    - Added this public evidence entry for the completed Delta Phase 3 rerun.
Commands run:
  - `bash -n scripts/e2e/live_linux_lab_orchestrator.sh`
  - `cargo run --quiet -p rustynet-cli -- ops vm-lab-run-live-lab --profile profiles/live_lab/generated_vm_lab_5node_phase3_replayfix.env --skip-gates --skip-soak --skip-cross-network --source-mode working-tree --timeout-secs 7200`
  - `ssh ... debian-headless-{1,2,4} 'sudo env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet status'`
  - `ssh ... debian-headless-{1,2,4} 'sudo env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet netcheck'`
  - `ssh ... debian-headless-{1,2} 'sudo env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet state refresh && rustynet status && rustynet netcheck'`
  - artifact inspection under `artifacts/live_lab/phase3_worktree_rerun_replayfix`
Validation and live-lab outcomes:
  - The reduced five-node rerun at `artifacts/live_lab/phase3_worktree_rerun_replayfix` now passes:
    - `enforce_baseline_runtime`
    - `validate_baseline_runtime`
  - The fresh traversal redistribution inside `stage_enforce_baseline_runtime` eliminated the earlier expired-coordination failure and moved the reduced helper flow beyond the old route/exit-mode runtime blocker.
  - `validate_baseline_runtime.log` proves the exact Delta Phase 3 contract on the live nodes:
    - `transport_socket_identity_state=authoritative_backend_shared_transport`
    - `transport_socket_identity_error=none`
    - `encrypted_key_store=true`
    - `auto_tunnel_enforce=true`
    - `membership_active_nodes=5`
    - client route lookups resolve through `dev rustynet0`
    - `no-plaintext-passphrase-files`
    - exit NAT/forward rules include `masquerade` and `iifname "rustynet0"`
  - The baseline-runtime logs do not contain the old route/exit-mode placeholder failures.
  - The same rerun now first fails later at `live_role_switch_matrix` with:
    - `pinned known_hosts file lacks host key for debian-headless-2`
Security invariants re-verified:
  - No daemon-owned or helper-owned side socket was introduced.
  - Signed traversal coordination was refreshed with newly issued signed state rather than by stretching the coordination TTL or weakening traversal validation.
  - Authoritative transport identity remained backend-owned and unchanged through the live baseline-runtime stages.
  - The baseline validator now enforces the documented Phase 3 contract explicitly and fail-closed.
What Delta Phase 3 completed:
  - Real-host proof that the completed Linux userspace-shared route and exit-mode runtime slices are sufficient for baseline enforcement on the reduced five-node lab.
  - Honest proof that the previous first blocker is no longer route/exit-mode programming.
  - Honest narrowing of the next blocker to the later role-switch host-key stage.
Residual risks / blockers:
  - The reduced helper flow still does not complete end-to-end because `live_role_switch_matrix` is now blocked by pinned temporary `known_hosts` generation.
  - Repo-level dependency-policy blockers and live-evidence blockers remain unchanged and still must stay fail-closed.
  - macOS userspace-shared parity remains out of scope, blocked, and unclaimed.
```

```text
Date: 2026-04-02
Phase / Slice: Linux userspace-shared live-lab delta - host-only signed traversal direct-programmed fallback and fresh reduced rerun
Files changed:
  - crates/rustynetd/src/phase10.rs
    - Added an explicit `DirectProbeExhaustedUnprovenDirect` traversal probe reason and changed the valid-coordination/no-relay direct-probe exhaustion path to keep the signed direct endpoint programmed and unproven instead of failing traversal state closed.
  - crates/rustynetd/src/daemon.rs
    - Added a host-only traversal+coordination fixture helper and a daemon regression test proving that host-only signed traversal with exhausted direct probes stays programmed without entering restricted-safe mode.
  - documents/operations/active/LinuxUserspaceSharedLiveLabReadinessDelta_2026-04-02.md
    - Updated the active delta document so it now records that baseline runtime and role-switch proof are complete and that the next blocker moved forward to `live_exit_handoff`.
  - documents/operations/active/PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md
    - Added this evidence entry.
Commands run:
  - `rustfmt --edition 2024 crates/rustynetd/src/phase10.rs crates/rustynetd/src/daemon.rs`
  - `cargo fmt --all -- --check`
  - `cargo check -p rustynetd`
  - `cargo test -p rustynetd traversal_probe_keeps_signed_direct_programmed_when_handshake_does_not_advance_and_no_relay_exists -- --nocapture`
  - `cargo test -p rustynetd daemon_runtime_host_only_signed_direct_probe_exhaustion_stays_programmed_without_restricting -- --nocapture`
  - `cargo test -p rustynetd daemon_runtime_relay_session_becomes_live_only_with_selected_endpoint_and_fresh_handshake -- --nocapture`
  - `cargo test -p rustynetd daemon_runtime_relay_session_endpoint_mismatch_is_not_live -- --nocapture`
  - `cargo test -p rustynetd daemon_runtime_auto_tunnel_direct_health_uses_live_handshake_without_forced_reprobe -- --nocapture`
  - `cargo test -p rustynetd daemon_runtime_auto_tunnel_direct_liveness_expiry_falls_back_to_relay -- --nocapture`
  - `cargo run --quiet -p rustynet-cli -- ops vm-lab-run-live-lab --profile profiles/live_lab/generated_vm_lab_5node_phase3_replayfix.env --skip-gates --skip-soak --skip-cross-network --source-mode working-tree --timeout-secs 7200`
Validation and live-lab outcomes:
  - The new phase10 regression passed and now proves that valid signed host-only traversal with coordination and no relay keeps the peer on a signed `direct_programmed` path without fabricating liveness.
  - The new daemon regression passed and proves the runtime no longer enters restricted-safe mode just because host-only signed direct probes exhaust without a relay fallback.
  - Existing direct/relay truthfulness regressions remained green, so `direct_active` still requires fresh handshake proof and `relay_active` still requires fresh handshake proof plus relay-session consistency.
  - The fresh reduced five-node rerun at `artifacts/live_lab/phase3_worktree_rerun_replayfix` now passes:
    - `enforce_baseline_runtime`
    - `validate_baseline_runtime`
    - `live_role_switch_matrix`
  - Live status on the fresh rerun now shows the intended non-live-safe direct state instead of restricted fail-closed:
    - `restricted_safe_mode=false`
    - `path_mode=direct_programmed`
    - `path_reason=direct_handshake_unproven`
    - `traversal_probe_reason=direct_probe_exhausted_unproven_direct`
  - The next blocker moved forward to `live_exit_handoff`, which now fails with:
    - `error: issue assignment bundle failed: assignment error: requested node endpoint is invalid`
Security invariants re-verified:
  - No daemon-owned or helper-owned side socket was introduced.
  - Exhausted direct probes still do not fabricate handshake freshness or `direct_active`; the path remains programmed and explicitly unproven.
  - Signed traversal state remains enforced; the fix applies only when the traversal bundle and coordination are valid and the direct candidate is already signed authority state.
  - Route advertisement is no longer blocked by a false restricted-safe transition in this host-only signed traversal case.
What this slice completed:
  - The earlier `DirectProbeExhaustedFailClosed` baseline-runtime blocker is fixed for the reduced Linux live topology.
  - The previously landed role-switch host-key alignment is now live-proven because `live_role_switch_matrix` passes on the fresh rerun.
What remains blocked:
  - The next real blocker is later in the live helper flow: `live_exit_handoff` currently rejects the requested node endpoint while issuing handoff assignments.
  - Repo-level dependency-policy and evidence blockers remain unchanged and fail-closed.
```

```text
Date: 2026-04-03
Phase / Slice: Linux userspace-shared live-lab delta - backend-authoritative exit-handoff endpoint proof correction
Files changed:
  - crates/rustynetd/src/phase10.rs
    - Exposed a narrow `Phase10Controller::current_peer_endpoint(...)` accessor so daemon status can read the backend's actual programmed peer endpoint without leaking backend-specific types.
  - crates/rustynetd/src/daemon.rs
    - Added parseable `selected_exit_peer_endpoint` and `selected_exit_peer_endpoint_error` fields to `rustynet status`, sourced from the backend's current programmed endpoint for the selected exit peer.
    - Added a daemon regression assertion proving the selected-exit endpoint field is present on a real programmed-path status response.
  - crates/rustynet-cli/src/bin/live_linux_exit_handoff_test.rs
    - Switched the `exit_b_endpoint_visible` proof from `wg show rustynet0 endpoints` to the daemon's backend-authoritative `selected_exit_peer_endpoint` status field.
    - Kept raw `wg show` capture only as a debug artifact and added a unit test for deterministic status-field parsing.
  - documents/operations/active/LinuxUserspaceSharedLiveLabReadinessDelta_2026-04-02.md
    - Updated the delta document so it now records that the userspace-shared handoff endpoint proof source is patched locally and still awaits a fresh rerun for live evidence.
  - documents/operations/active/PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md
    - Added this evidence entry.
Commands run:
  - `rustfmt --edition 2024 crates/rustynetd/src/phase10.rs crates/rustynetd/src/daemon.rs crates/rustynet-cli/src/bin/live_linux_exit_handoff_test.rs`
  - `cargo test -p rustynetd daemon_runtime_auto_tunnel_traversal_probe_falls_back_to_relay_without_handshake_evidence -- --nocapture`
  - `cargo test -p rustynet-cli --bin live_linux_exit_handoff_test -- --nocapture`
Validation outcomes:
  - The daemon regression passed with the new status-field assertions, so `rustynet status` now exposes a backend-owned selected-exit peer endpoint on a real programmed path.
  - `live_linux_exit_handoff_test` unit coverage passed, including the new parser coverage and existing handoff helper regressions.
  - No deploy or live-lab rerun was performed in this slice; this was a code-only proof-source correction.
Security invariants re-verified:
  - No daemon-owned or helper-owned side socket was introduced.
  - The fix does not weaken the handoff proof; it replaces a kernel-only visibility check with a backend-authoritative programmed-endpoint check for `linux-wireguard-userspace-shared`.
  - Direct/relay truthfulness semantics remain unchanged because the new field reports programmed peer endpoint state only; it does not claim live handshake proof.
What this slice completed:
  - The reduced-live-lab handoff check no longer treats empty `wg show rustynet0 endpoints` output as dispositive for the userspace-shared backend.
  - The next honest step remains a fresh reduced five-node rerun on the current committed tree.
What remains blocked:
  - `live_exit_handoff` still needs fresh operational proof on the current committed tree.
  - Repo-level dependency-policy and evidence blockers remain unchanged and fail-closed.
```

```text
Date: 2026-04-03
Phase / Slice: Linux userspace-shared live-lab delta - Rust live-lab SSH-target endpoint resolution fix
Files changed:
  - crates/rustynet-cli/src/bin/live_lab_bin_support/mod.rs
    - Added an `ssh -G`-backed target resolver for live-lab binaries that use the lightweight helper module and added unit coverage proving it prefers the effective SSH `hostname` while falling back to the raw target host only when no resolved hostname is present.
  - crates/rustynet-cli/src/bin/live_lab_support/mod.rs
    - Added the same `ssh -G`-backed target resolver for `LiveLabContext` users and matching unit coverage.
  - crates/rustynet-cli/src/bin/live_linux_exit_handoff_test.rs
    - Switched signed handoff assignment `NODES_SPEC` construction from raw `target_address(...)` aliases to resolved effective SSH host endpoints.
  - crates/rustynet-cli/src/bin/live_linux_two_hop_test.rs
    - Switched signed topology construction to resolved effective SSH host endpoints.
  - crates/rustynet-cli/src/bin/live_linux_lan_toggle_test.rs
    - Switched signed topology construction to resolved effective SSH host endpoints.
  - crates/rustynet-cli/src/bin/live_linux_managed_dns_test.rs
    - Switched signed mesh peer endpoint construction to resolved effective SSH host endpoints.
  - crates/rustynet-cli/src/bin/live_linux_control_surface_exposure_test.rs
    - Switched remote DNS probe target selection to the resolved effective SSH host endpoint.
  - crates/rustynet-cli/src/bin/live_linux_server_ip_bypass_test.rs
    - Switched default underlay probe bind target selection to the resolved effective SSH host endpoint.
  - documents/operations/active/LinuxUserspaceSharedLiveLabReadinessDelta_2026-04-02.md
    - Updated the active delta document so it records that the handoff endpoint-construction bug is now patched locally and that the next required proof is a fresh reduced rerun.
  - documents/operations/active/PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md
    - Added this evidence entry.
Commands run:
  - `rustfmt --edition 2024 crates/rustynet-cli/src/bin/live_lab_bin_support/mod.rs crates/rustynet-cli/src/bin/live_lab_support/mod.rs crates/rustynet-cli/src/bin/live_linux_exit_handoff_test.rs crates/rustynet-cli/src/bin/live_linux_two_hop_test.rs crates/rustynet-cli/src/bin/live_linux_lan_toggle_test.rs crates/rustynet-cli/src/bin/live_linux_control_surface_exposure_test.rs crates/rustynet-cli/src/bin/live_linux_server_ip_bypass_test.rs crates/rustynet-cli/src/bin/live_linux_managed_dns_test.rs`
  - `cargo fmt --all -- --check`
  - `cargo check -p rustynet-cli --bins`
  - `cargo test -p rustynet-cli --bin live_linux_exit_handoff_test -- --nocapture`
  - `cargo test -p rustynet-cli --bin live_linux_managed_dns_test -- --nocapture`
Validation outcomes:
  - `cargo fmt --all -- --check` passed after formatting the touched CLI files.
  - `cargo check -p rustynet-cli --bins` passed, so the widened resolver use compiles across the affected live-lab binaries.
  - `cargo test -p rustynet-cli --bin live_linux_exit_handoff_test -- --nocapture` passed, including the new `live_lab_bin_support` resolver tests and the existing handoff helper regressions.
  - `cargo test -p rustynet-cli --bin live_linux_managed_dns_test -- --nocapture` passed, including the new `live_lab_support` resolver tests and the existing managed-DNS helper regressions.
Security invariants re-verified:
  - Control-plane assignment and traversal issuance remain fail-closed on invalid endpoints; the strict `SocketAddr` validator in `rustynet-control` was not softened.
  - No daemon-owned or helper-owned side socket was introduced.
  - The fix only changes how Rust live-lab helpers derive concrete underlay host endpoints from SSH targets; it does not widen transport authority, weaken signed-bundle validation, or bypass endpoint verification.
What this slice completed:
  - The Rust-side live-lab caller bug that built signed topology specs from raw SSH alias tokens is fixed locally.
  - The previously captured `live_exit_handoff` failure cause (`requested node endpoint is invalid`) is now patched in code rather than documented as an unexplained operational blocker.
What remains blocked:
  - A fresh reduced five-node rerun is still required to prove `live_exit_handoff` on the current committed tree and to capture the next blocker honestly if a later stage fails.
  - Repo-level dependency-policy and evidence blockers remain unchanged and fail-closed.
```

```text
Date: 2026-04-03
Phase / Slice: Linux userspace-shared live-lab delta - LAN-toggle traversal refresh proof and fresh five-node rerun
Files changed:
  - crates/rustynet-cli/src/bin/live_linux_lan_toggle_test.rs
    - Replaced the one-shot traversal issue/install logic with a shared refresh helper that reissues signed traversal bundles, redistributes them to all three LAN-toggle participants, and forces signed-state reload on each host.
    - Added periodic refresh during the LAN-toggle wait loops so the stage no longer outlives the signed traversal coordination window and fail-closes spuriously on expired coordination.
    - Added unit coverage for the coordination refresh interval calculation.
  - documents/operations/active/LinuxUserspaceSharedLiveLabReadinessDelta_2026-04-02.md
    - Updated the current truth so the delta document now records that `live_exit_handoff` and `live_two_hop` are live-proven on the current working tree and that the first blocker has moved to real LAN dataplane reachability during `lan_access=on`.
  - documents/operations/active/PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md
    - Added this evidence entry.
Commands run:
  - `rustfmt --edition 2024 crates/rustynet-cli/src/bin/live_linux_lan_toggle_test.rs`
  - `cargo fmt --all -- --check`
  - `cargo check -p rustynet-cli --bin live_linux_lan_toggle_test`
  - `cargo test -p rustynet-cli --bin live_linux_lan_toggle_test -- --nocapture`
  - `cargo run --quiet -p rustynet-cli -- ops vm-lab-write-live-lab-profile --inventory documents/operations/active/vm_lab_inventory.json --output profiles/live_lab/generated_vm_lab_5node_20260403_lantogglefix.env --ssh-identity-file /Users/iwanteague/.ssh/rustynet_lab_ed25519 --ssh-known-hosts-file /Users/iwanteague/.ssh/known_hosts --exit-vm debian-headless-1 --client-vm debian-headless-2 --entry-vm debian-headless-3 --aux-vm debian-headless-4 --extra-vm debian-headless-5 --require-same-network --backend linux-wireguard-userspace-shared --source-mode working-tree`
  - `cargo run --quiet -p rustynet-cli -- ops vm-lab-preflight --inventory documents/operations/active/vm_lab_inventory.json --all --known-hosts-file /Users/iwanteague/.ssh/known_hosts --require-same-network --require-command git --require-command cargo --require-rustynet-installed`
  - `cargo run --quiet -p rustynet-cli -- ops vm-lab-run-live-lab --profile profiles/live_lab/generated_vm_lab_5node_20260403_lantogglefix.env --skip-gates --skip-soak --skip-cross-network --source-mode working-tree --report-dir artifacts/live_lab/20260403T212500Z_lantogglefix --timeout-secs 7200`
Validation and live-lab outcomes:
  - Targeted CLI formatting, check, and unit tests passed after the LAN-toggle refresh patch.
  - The fresh reduced five-node rerun at `artifacts/live_lab/20260403T212500Z_lantogglefix` now passes:
    - `live_exit_handoff`
    - `live_two_hop`
  - The old `live_lan_toggle` traversal-expiry failure is removed:
    - client status during `lan_access=on` stays `restricted_safe_mode=false`
    - the client no longer reports `coordination record is expired`
    - the client route to `192.168.1.1` remains via `rustynet0`
  - The rerun still fails at `live_lan_toggle`, but only on `lan_on_allows`:
    - `lan_access=on` is set
    - the client remains on a healthy signed `direct_programmed` path
    - the route to the synthetic LAN probe is installed via `rustynet0`
    - the actual LAN probe never becomes reachable
Security invariants re-verified:
  - No daemon-owned or helper-owned side socket was introduced.
  - The LAN-toggle fix did not weaken traversal expiry enforcement; it keeps the stage on the existing hardened path of reissued signed traversal bundles plus explicit daemon signed-state refresh.
  - The rerun still does not fabricate handshake liveness or `direct_active`; the path remains explicitly programmed and unproven.
  - Fail-closed behavior remains intact for blind-exit LAN coupling denial.
What this slice completed:
  - The later-stage `live_two_hop` proof bug is now live-proven clean on the current working tree.
  - The `live_lan_toggle` traversal-coordination-expiry failure is fixed under real helper execution.
What remains blocked:
  - The current first live blocker is now narrower and later: `live_lan_toggle` still fails `lan_on_allows` because end-to-end LAN probe reachability is missing even though route selection and signed-state health remain correct.
  - Repo-level dependency-policy and evidence blockers remain unchanged and fail-closed.
```

```text
Date: 2026-03-30
Phase / Slice: Final closeout honesty pass
Files changed:
  - documents/operations/active/PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md
    - Reconciled stale checklist state, added the final audited artifact/gate inventory, and recorded the current `HEAD` blocker set explicitly.
  - README.md
    - Downgraded the traversal/relay status paragraph so it matches audited runtime and evidence reality instead of older HP2/HP3 wording.
Tests and gates run:
  - `./scripts/ci/phase10_hp2_gates.sh` (pass)
  - `./scripts/ci/phase10_cross_network_exit_gates.sh` (fails closed: six canonical cross-network reports missing)
  - `./scripts/ci/phase10_gates.sh` (fails closed: `artifacts/phase10/fresh_install_os_matrix_report.json` git_commit mismatch)
Artifact audit:
  - Verified canonical cross-network report paths are still absent for current `HEAD`.
  - Verified `artifacts/phase10/fresh_install_os_matrix_report.json` exists but is stale: `git_commit=c86a62a766b8af8382dfa57805aec8b4cad284ff`, expected `06e3e2ed745b4439505991bea775246cde8ed653`.
  - Verified canonical live-script output paths still match the gate contract even though the measured artifacts themselves are not present.
Security invariants verified:
  - The closeout gate surface remains fail-closed on missing canonical evidence, stale commit-bound evidence, and unproven live path claims.
  - No softer product claim survived in the plan ledger or README transport-status summary.
Residual risks / blockers:
  - Fresh live-lab execution is still required to generate the six canonical cross-network reports for current `HEAD`.
  - Fresh-install matrix evidence still needs regeneration on current `HEAD`; the stale report remains intentionally blocking.
  - Phase A transport-socket identity work remains incomplete and still limits end-to-end plug-and-play completion claims.
```

## 19. Definition of Done for This Document
This delta is complete only when all are true:
- direct path uses correct measured candidates,
- relay path is a real production path, not a programmed placeholder,
- users do not need manual router port forwarding for baseline connectivity,
- status/netcheck and CI gates are honest and fail closed,
- direct and relay are both evidenced under real cross-network conditions,
- security invariants are preserved across all path transitions,
- no in-scope work is deferred.

## 20. Operator Note
Power-user router forwarding, NAT-PMP, PCP, or UPnP may still be valuable accelerators.
They should remain optional features, not required setup steps.

The product-correct baseline is:
- direct when possible,
- relay when not,
- no router expertise required.
