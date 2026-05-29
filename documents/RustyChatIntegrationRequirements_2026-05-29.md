# RustyChat ⇄ Rustynet Integration Requirements

Status: design / scoping (no implementation committed yet)
Created: 2026-05-29
Owning track: Application Integration (forward-looking; not yet a dataplane ledger item)

## Companion Document Notice

This document is one half of a **two-repo pair** in the same overall project:

- **Rustynet** (`Iwan-Teague/Rustynet`) — the secure mesh-VPN substrate. This
  copy lives here.
- **RustyChat** (`Iwan-Teague/rustychat`) — a highly secure encrypted
  messaging service for nodes on a Rustynet. Early development.

A companion copy of this document should be placed in the RustyChat repo (for
example `docs/RustynetIntegrationRequirements.md`) so both sides of the project
share one source of truth for the integration seam. At the time of writing this
copy, the authoring agent's tooling was scoped to the Rustynet repository only
and could not write into RustyChat directly, so the RustyChat copy must be
added manually (or by an agent with RustyChat write access). Keep the two
copies aligned the same way `AGENTS.md` and `CLAUDE.md` are mirrored.

## Purpose

Answer one question: **what does Rustynet need to be capable of so that
RustyChat — a highly secure, end-to-end encrypted messaging service for nodes
on a Rustynet — can be built on top of it?**

This is a capability gap analysis, not an implementation plan. It records:

1. what RustyChat gets "for free" from Rustynet as it exists today,
2. the gaps that Rustynet would need to close (prioritised),
3. what stays RustyChat's responsibility and must **not** leak into Rustynet's
   transport-agnostic core (per `CLAUDE.md` §3 / §8).

## Mental Model

Rustynet is an **L3 encrypted overlay**: WireGuard behind a stable backend
abstraction (`rustynet-backend-api`), with strong Ed25519 node identity,
default-deny policy, signed coordination/gossip, and OS-keychain key custody.

For RustyChat that means the hard transport/security substrate already exists:
two enrolled nodes get an authenticated, encrypted IP path to each other and
can open ordinary sockets across it. What is missing is an **application-facing
seam** — there is no way today for an on-host application to ask the daemon
"who am I, who are my peers, sign/derive a key for me, and gate my service
port." RustyChat would either be built entirely *on top of* the overlay
(treating it as a dumb secure pipe alongside the daemon) or Rustynet grows a
small, deliberate integration surface. This document argues for the latter, in
a minimal additive form.

## 1. What RustyChat Gets For Free (today)

| Need | Rustynet provides | Key location |
|---|---|---|
| Authenticated node identity | Ed25519 keypair per node; identity *is* the verifying key | `crates/rustynet-crypto/src/lib.rs` (`NodeKeyPair`, `Ed25519SigningProvider`) |
| Onboarding / trust root | One-time HMAC enrollment tokens; signed membership directory with revocation | `crates/rustynetd/src/enrollment_token.rs`, `crates/rustynet-control/src/membership.rs` |
| Encrypted transport | WireGuard tunnel; NAT traversal (STUN/ICE); relay fallback. Any node → any node's mesh IP | `crates/rustynet-backend-wireguard`, `crates/rustynet-relay`, `crates/rustynetd/src/traversal.rs` |
| Mesh addressing | Nodes get stable mesh IPv4 (`allowed_ips`, `DnsTargetAddrKind::MeshIpv4`) | `crates/rustynet-backend-api` (`PeerConfig`), `crates/rustynet-control` |
| Name → node mapping | Signed DNS zone bundles (A records, TTL ≤ 300s) | `crates/rustynet-dns-zone/src/lib.rs` |
| Node-to-node access control | Default-deny ACL: `src`/`dst`/`protocol`/`action`, tags/groups, revocation pre-gate | `crates/rustynet-policy/src/lib.rs` |
| Peer discovery / liveness signal | Signed gossip bundles with endpoint candidates, anti-replay, freshness window | `crates/rustynetd/src/peer_gossip.rs`, `crates/rustynetd/src/gossip_runtime.rs` |
| Crypto building blocks | Ed25519, X/ChaCha20-Poly1305, AES-256-GCM, HKDF-SHA256, Argon2id; algorithm allow/deny policy | `crates/rustynet-crypto/src/lib.rs` |
| Key custody | OS keychain (DPAPI / macOS Keychain / Secret Service) + encrypted-file fallback with startup permission checks | `crates/rustynet-crypto` (`KeyCustodyManager`) |

**Net effect:** RustyChat could run today as — each node opens a TCP/UDP
listener on its mesh IP; peers connect over the WireGuard-encrypted path; ACLs
gate who may reach the chat port. That already provides transport encryption +
authenticated reachability + instant revocation. A real foundation, but a thin
one for *end-to-end* messaging.

## 2. Gaps — What Rustynet Would Need To Provide

The current local IPC surface (`crates/rustynetd/src/ipc.rs`) is
operator/control oriented: `status`, `netcheck`, `state refresh`,
`exit-node`, `lan-access`, `dns inspect`, `route advertise/retract`,
`key rotate/revoke`, `PushGossipBundle`, `EnrollmentConsume`,
`MembershipApply`. There is **no application integration API**. The gaps below
are ordered by how much they unblock RustyChat.

### Gap 1 — Local app-identity / discovery API (highest priority)

A reviewed local IPC (unix socket / Windows named pipe, staying inside the
existing local-credential trust model) where an on-host app can ask:

- `whoami` → this node's mesh IP(s) and node identity (public key / fingerprint).
- `peers` → current peers: node ID, public key, mesh IP, name, liveness.
- `resolve <name>` → name → node / mesh IP (reading the signed zone bundle on
  the app's behalf).

Today an app would have to scrape the text `status` response and parse zone
bundles itself. A typed query API is the single biggest enabler and is purely
additive. It must remain read-only and local-credential gated; it must not
become an unauthenticated network RPC.

### Gap 2 — App-scoped end-to-end key story

The node private key is correctly **not** exported. For true E2E messaging
(content unreadable by relays, anchors, or even a malicious node operator),
RustyChat needs per-conversation keys with a verifiable binding back to the
enrolled node identity. Rustynet should offer **one** of:

- a **key-derivation / attestation service** over the local API:
  - "sign this RustyChat app public key with my node key" (attestation), and/or
  - "give me an HKDF-derived, context-labelled app key bound to node identity"
  so RustyChat keys are provably tied to the enrolled node without exposing the
  node secret; **or**
- a documented pattern + helper in `crates/rustynet-crypto` for apps to mint and
  custody their own keys in the same OS keychain with the same permission
  checks.

Either way the requirement is the same: a verifiable binding between *node
identity in the mesh* and *messaging identity in RustyChat*, so peer
authentication rides on enrollment rather than a second, unrelated trust root.

Constraint: per `CLAUDE.md` §3, RustyChat must use a vetted E2E protocol
(e.g. Noise / Double-Ratchet) over these keys — no custom crypto protocol
invention on either side.

### Gap 3 — App-aware policy / service-port reservation

Today ACLs are node-pair + protocol + port (enough to gate "may node A reach
node B's chat port"). Worth adding: a **named-service** concept (e.g. tag a port
as `service:rustychat`) so policy can be written about the app rather than a
magic port number, and so RustyChat can register its listener with the daemon
and inherit fail-closed default-deny automatically.

### Gap 4 — Liveness / presence feed (fast follow)

The gossip layer already knows reachability and endpoint changes
(`peer_gossip.rs`). Exposing a **read-only presence/online feed** (subscribe to
peer up/down) over the app API saves RustyChat from building its own heartbeat
layer and keeps a single source of truth for "who is online."

### Gap 5 — Offline delivery / store-and-forward (genuine design decision)

Messaging usually needs store-and-forward when a peer is offline. Rustynet's
relay / anchor / home-server-as-zero-ingress-relay roles (per
`operations/active/RustynetDataplaneExecutionPlan_2026-05-18.md`, D2–D12) relay
**packets**, not **messages** — they are not mailboxes. Two options:

- **(Preferred)** RustyChat builds an encrypted mailbox service that runs as an
  ordinary node, keeping Rustynet protocol-agnostic.
- Rustynet's anchor role grows an explicit, encrypted, opaque store-and-forward
  primitive.

This is the one capability that is a real architectural decision rather than
plumbing; defaulting to the RustyChat-side mailbox preserves Rustynet's
transport-agnostic boundary.

## 3. What Stays RustyChat's Responsibility

To respect Rustynet's architecture rules (transport-agnostic core; no app
leakage into control/policy/domain crates — `CLAUDE.md` §3, §8), these belong
in RustyChat, **not** Rustynet:

- message framing, ordering, retransmission, the chat wire protocol;
- the E2E session protocol (a vetted Noise / Double-Ratchet design over the
  derived/attested keys — not custom crypto);
- conversation and group semantics, message history, UI;
- per-message authorisation beyond node-pair reachability;
- presence display logic (consuming, not defining, the Rustynet liveness feed).

## 4. Recommended Minimum Viable Set

To unblock RustyChat with the least change to Rustynet's hardened core:

1. **`whoami` + `peers` + `resolve`** local app query API (additive to
   `ipc.rs`, read-only, local-credential gated) — Gap 1.
2. **Node→app key binding** (attestation or derived-key helper) so messaging
   identity inherits enrollment trust — Gap 2.
3. **Service-tag policy + listener registration** so RustyChat ports are
   default-deny gated by name — Gap 3.

Fast follow: presence feed (Gap 4). Deliberate decision, default to
RustyChat-side: offline mailbox (Gap 5).

## 5. Security Notes (must hold for any of the above)

Per `documents/SecurityMinimumBar.md` and `CLAUDE.md` §4, any new surface must:

- stay local-only and local-credential gated (no new unauthenticated network
  RPC); preserve fail-closed behaviour when trust state is missing/stale;
- never export the node private key and never log secrets or key material;
- carry an enforcement point in code **and** a verification method (unit /
  integration / negative test or gate check) for every control;
- keep all WireGuard-specific behaviour behind the backend abstraction — no
  backend leakage into a RustyChat-facing API.

## 6. Open Questions For The RustyChat Side

- Is messaging identity 1:1 with node identity, or per-user-on-node? (Affects
  Gap 2 and whether shared-node users must be isolated.)
- Is offline delivery in scope for the first milestone? (Decides whether Gap 5
  is needed early.)
- Group messaging semantics — out of scope for Rustynet entirely; confirm it
  is owned by RustyChat.

## References (Rustynet code)

- `crates/rustynet-crypto/src/lib.rs` — identity keys, AEAD, HKDF, Argon2, key custody, algorithm policy
- `crates/rustynet-backend-api/src/lib.rs` — `TunnelBackend`, `PeerConfig`, `allowed_ips`
- `crates/rustynet-policy/src/lib.rs` — default-deny ACL, rules, membership gate
- `crates/rustynet-dns-zone/src/lib.rs` — signed zone bundles, `DnsTargetAddrKind::MeshIpv4`
- `crates/rustynetd/src/ipc.rs` — current local IPC command surface
- `crates/rustynetd/src/peer_gossip.rs`, `gossip_runtime.rs` — signed gossip / discovery
- `crates/rustynetd/src/enrollment_token.rs`, `crates/rustynet-control/src/membership.rs` — enrollment + membership/revocation
- `crates/rustynet-relay/src/lib.rs`, `crates/rustynetd/src/traversal.rs` — relay + NAT traversal
- `documents/operations/active/RustynetDataplaneExecutionPlan_2026-05-18.md` — relay/anchor roles (D2–D12)
