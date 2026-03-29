# Rustynet Plug-and-Play Connectivity Delta Plan (UDP Hole Punching + Relay Fallback)
**Generated:** 2026-03-29
**Repository Root:** `/Users/iwanteague/Desktop/Rustynet`
**Scope:** Production-grade, secure, plug-and-play cross-network connectivity with direct UDP when possible and ciphertext-only relay fallback when direct is not provable.

## AI Implementation Prompt
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
9. /Users/iwanteague/Desktop/Rustynet/documents/operations/active/CrossNetworkConnectivityImplementationPlan_2026-03-27.md
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

## AI Agent Execution and Progress Contract
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
- [ ] Fix STUN to return full mapped endpoints.
- [ ] Stop guessing public port from `wg_listen_port`.
- [ ] Align STUN gathering with actual transport socket identity.
- [ ] Align relay session establishment with the documented transport identity model.
- [ ] Add unit tests and live diagnostics proving candidate correctness.

Success criteria:
- published srflx candidates correspond to measured public socket tuples,
- status/netcheck report actual tuples, not reconstructed guesses.

### Phase B: Finish Direct WAN Simultaneous-Open on the Live Runtime Path
Tasks:
- [ ] Reconcile traversal engine design with active runtime behavior.
- [ ] Ensure direct probe executor is truly two-sided where required.
- [ ] Make the active runtime prove direct path using fresh handshake evidence.
- [ ] Add roaming and re-probe correctness tests.
- [ ] Add active-path liveness / consent-equivalent expiry tests for direct mode.

Success criteria:
- direct path succeeds in permissive NAT scenarios without manual router work,
- direct failure is honest and bounded,
- direct-active means proven, not programmed.

### Phase C: Finish Relay Runtime Integration
Tasks:
- [ ] Implement real relay daemon binary/runtime.
- [ ] Define and implement the allocated-port relay data-plane contract.
- [ ] Wire daemon relay client to real relay infrastructure.
- [ ] Ensure relay session establishment and refresh are live.
- [ ] Ensure backend traffic can actually traverse the relay path.
- [ ] Prove relay-active with traffic/handshake evidence.

Success criteria:
- when direct fails, relay goes live automatically,
- `relay_session_disabled` is not the normal result for a configured relay-capable deployment,
- traffic continues through relay without policy bypass.

### Phase D: Failover / Failback / Roaming Hardening
Tasks:
- [ ] Direct->relay failover with no leak.
- [ ] Relay->direct failback on fresh proof.
- [ ] Session/token refresh across long-running uptime.
- [ ] Network-change / IP-change reprobe correctness.
- [ ] Active-path consent/liveness expiry behaves fail-closed across transitions.

Success criteria:
- path transitions preserve encryption, ACL, DNS fail-close, and kill-switch.

### Phase E: Evidence and Gates
Tasks:
- [ ] Update/extend live scripts.
- [ ] Update CI gates.
- [ ] Generate commit-bound artifacts.
- [ ] Require both direct and relay evidence before internet-reachability claims.
- [ ] Update this document's progress ledger with final evidence.

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
1. **STUN correctness slice**
   - fix srflx endpoint acquisition in `stun_client.rs` and `daemon.rs`
2. **Socket-identity slice**
   - align relay client and transport socket usage with backend socket semantics
3. **Relay daemon slice**
   - replace `rustynet-relay/src/main.rs` placeholder with real public UDP service using allocated relay ports
4. **Live relay runtime slice**
   - make relay-active genuinely achievable in `rustynetd`
5. **Evidence slice**
   - update scripts/gates and regenerate artifacts

## 18. Progress Ledger
Use this section as the execution log while implementing the plan.

### 18.1 Phase Status
- [ ] Phase A complete
- [ ] Phase B complete
- [ ] Phase C complete
- [ ] Phase D complete
- [ ] Phase E complete

### 18.2 Evidence Entries
For each completed slice, append an entry using this format:

```text
Date:
Phase / Slice:
Files changed:
Tests and gates run:
Live evidence / artifacts:
Security invariants verified:
Notes / blockers:
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
