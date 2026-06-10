# Rustynet LLM Node Role Design

- Date: 2026-06-11
- Status: active (design source-of-truth for the `llm` node role)
- Owner: Rustynet
- Parent doc: [`NodeRoleTaxonomyExtension_2026-06-11.md`](./NodeRoleTaxonomyExtension_2026-06-11.md) — `llm` is one of the two new service-hosting presets defined there. This document is the deep dive for the `llm` preset and inherits the secure-exposure model (parent §5) and the service-hosting security-control category (parent §8).
- Sibling doc: [`NasNodeRoleDesign_2026-06-11.md`](./NasNodeRoleDesign_2026-06-11.md).

---

## 0) Purpose of this document

Define the **LLM node** role end-to-end: a dedicated AI box that runs models and exposes an inference API which **RustyAI** clients (a future Claude-Code / ChatGPT / Codex-style text UI) call over the mesh. This document covers the new Rust sibling service (`rustynet-llm-gateway`), exactly how inference traffic is moved **securely and fast** without an API key, how a user can keep their **internet traffic on an exit node while their LLM traffic stays intra-mesh**, how an **admin governs who may use the LLM**, the node-side RustyAI interface contract, per-platform notes, security controls, and the build plan.

It directly answers the design questions raised on 2026-06-11:

1. **How does Rustynet provide the data, securely?** — §3, §4. The mesh tunnel is the secure channel; inference rides it.
2. **Is there something quicker than an API key, lower-level / speedier, without compromising security?** — §4, §5. Yes: derive identity from the authenticated tunnel (no API key), stream tokens over gRPC/HTTP-2 as plaintext **inside** the WireGuard tunnel (no double-encryption).
3. **Seamless for the user?** — §4.4. Zero credential management; open RustyAI and it just works, because membership *is* the credential.
4. **Exit node while using the LLM?** — §6. Internet egresses the exit; LLM traffic stays peer-to-peer via an overlay-route exception.
5. **Admin controls who can use the LLM?** — §7. Default-deny signed policy the admin mints; per-user / per-group, revocable, fail-closed.
6. **How do industry titans solve this?** — §2 surveys Tailscale, SPIFFE/SPIRE, and modern LLM streaming transports, and maps each lesson to a Rustynet decision.

If a later document or commit conflicts with this design, this document is the source of truth for the `llm` role until explicitly superseded.

---

## 1) Role definition

An **LLM node** is a `rustynetd` instance whose signed membership entry carries `Capability::ServesLlm` (`serves_llm`). When that capability is present and verified, the daemon co-runs `rustynet-llm-gateway` (a thin Rust gateway in front of a co-located inference engine), binds the inference API to the **mesh tunnel address only**, and admits a peer's request only if signed policy authorises `(peer, TrafficContext::LlmService) = Allow` — default-deny otherwise. It is `NodeRole::Admin` + `serves_llm`; not a new `NodeRole` primary. The capability is signed by the membership owner — a node cannot self-promote into an LLM host.

The defining property is the same as the NAS node: **the inference endpoint has no off-mesh surface and is default-deny even on-mesh.** The difference is the workload — streaming token generation, which makes transport latency and seamless auth first-order concerns, hence the extra depth in §2–§6.

---

## 2) How industry titans solve this (and what Rustynet borrows)

Three bodies of practice are directly relevant. Each lesson maps to a concrete Rustynet decision.

### 2.1 Tailscale — identity from the tunnel, not from a secret

Tailscale builds a WireGuard mesh where each device has a machine key pair; the control plane distributes public keys and every connection is mutually authenticated by those keys. Access is **default-deny** and expressed as "grants"/ACLs over **identities**, not shared secrets. For services, **Tailscale Serve** injects identity headers (`Tailscale-User-Login`, etc.) into requests to the backend, and the critical hardening rule is that **the backend must listen on localhost only** — otherwise anyone who can reach it could spoof those headers. Tailscale strips client-supplied identity headers to prevent spoofing. Tailscale SSH extends this to "no SSH keys to manage" — the mesh identity *is* the credential.

> **Rustynet decision:** derive the caller identity from the **authenticated tunnel source** (overlay IP ↔ signed node identity in membership), exactly as Tailscale derives it from the WireGuard node key. The gateway binds **tunnel-interface-only** (the generalisation of "localhost-only") and trusts only the daemon-asserted identity, never a client-supplied header or key. **No API key.** (§4)

### 2.2 SPIFFE / SPIRE — short-lived attested identity, not long-lived keys

SPIFFE/SPIRE give each workload a short-lived **SVID** (X.509 or JWT) issued after *attestation*, used to establish mTLS, with **no static secrets**. Identity is verified at runtime and credentials are short-lived, so a leaked credential expires quickly and authorisation can be revoked centrally.

> **Rustynet decision:** where the gateway needs an in-band token for an application session (defence-in-depth on top of the tunnel), issue a **short-lived, single-audience, node-signed capability token** (SPIFFE-style), re-checked against current signed policy on every use — never a long-lived bearer API key. A token can never outlive the peer's authorisation (parent §8 control E4). Use `rustynet-crypto` primitives; **no custom crypto, no new PKI** — the membership signing root is the trust anchor. (§5.3)

### 2.3 Modern LLM streaming transports — stream tokens, don't re-handshake

Current practice for low-latency token delivery: **gRPC over HTTP/2** gives ~25–35% lower streaming latency and large bandwidth savings via binary framing/Protobuf, with multiplexed streams over one persistent connection (no per-request connection setup); **SSE over HTTP/2** is the simpler, battle-tested browser-facing option; **HTTP/3/QUIC** avoids TCP head-of-line blocking on lossy links (e.g. cellular). And on the crypto side: **running plaintext inside an already-encrypted WireGuard tunnel avoids the double-encryption cost of TLS-over-WireGuard** — WireGuard's ChaCha20-Poly1305 is cheap, and a second TLS layer is redundant work for peers already inside the tunnel.

> **Rustynet decision:** the gateway speaks **gRPC/HTTP-2 with token streaming over a persistent connection, as plaintext inside the tunnel** (the tunnel is the crypto). This is the "lower-level, speedier path that doesn't compromise security": fewer handshakes, no double-encrypt, binary frames, tokens stream as generated. Offer SSE as the RustyAI-web fallback and HTTP/3/QUIC as the cellular-resilience option. (§4, §5)

---

## 3) `rustynet-llm-gateway` — the sibling service

A new Rust crate, co-deployed as a sibling service alongside `rustynetd` (same lifecycle pattern as `rustynet-relay`). It is a **thin, hardened gateway**, not an inference engine.

### 3.1 Architecture: gateway in front of a co-located engine

```
   RustyAI client (peer)                LLM node (this host)
   ────────────────────                 ───────────────────────────────
   [RustyAI UI] ──gRPC/HTTP2 token stream──▶ [rustynet-llm-gateway]
        ▲          (plaintext INSIDE the       │  (Rust, tunnel-bound)
        │           WireGuard tunnel)           │  - identity from tunnel
        │                                       │  - signed-policy gate
        └──────── streamed tokens ◀─────────────┤  - rate/quota/audit
                                                ▼
                                     [inference engine: localhost only]
                                     llama.cpp / Ollama / vLLM / MLX, etc.
```

The gateway owns the mesh-facing protocol, the identity/authorisation decision, rate limiting, model routing, and audit. The **inference engine runs behind a process boundary, bound to host loopback only** — it is never on the tunnel and never on the LAN. The engine is swappable (keeps the Rust-first wrapper thin and the model runtime replaceable, satisfying the architecture constraint that we wrap rather than reimplement). This mirrors Tailscale Serve's "backend on localhost, gateway mediates identity" topology.

### 3.2 Responsibilities

- Terminate the mesh-facing inference API (gRPC/HTTP-2 streaming; SSE + HTTP/3 options) on the **tunnel address only**.
- Obtain the **verified peer identity from `rustynetd`** (the daemon authenticated the WireGuard handshake and checked signed policy); bind every request to that identity. The gateway authenticates nobody from scratch and accepts **no** client-supplied identity header or API key as a trust source.
- Enforce **default-deny** per-peer access via `ContextualPolicySet::evaluate_with_membership` for `TrafficContext::LlmService`; empty/missing/stale policy ⇒ `Decision::Deny`.
- Enforce admin-configured **per-peer / per-group rate limits, token quotas, and model allow-lists** (§7).
- Proxy to the local inference engine, stream tokens straight back as they generate, and tear the stream down if authorisation changes mid-request.
- Report health so the fail-closed gate drops the endpoint if the engine is down, the model is unloaded, or the accelerator is unavailable.

### 3.3 What it does NOT do

- Does **not** implement a model runtime or train anything.
- Does **not** open any LAN/public listener; the engine is loopback-only, the gateway is tunnel-only.
- Does **not** mint or sign membership/policy, and does **not** hold the membership-root key.
- Does **not** terminate its own TLS for mesh peers (the tunnel is the channel) — TLS to the engine over loopback is unnecessary; an optional defence-in-depth token is §5.3.

---

## 4) Secure, seamless, fast data path (the core answer)

### 4.1 The tunnel is the secure channel

Every byte between the RustyAI client and the LLM node already travels inside the WireGuard tunnel: mutually authenticated at handshake by node keys, encrypted + integrity-protected with ChaCha20-Poly1305. There is **no weaker path** — the gateway has no LAN/public listener, so an attacker cannot reach the inference API without first being an enrolled, signed mesh peer whose handshake succeeded. This is how Rustynet "provides the data securely": confidentiality and peer authentication are inherited from the existing dataplane, with no new transport crypto (architecture constraint satisfied).

### 4.2 Identity from the tunnel — no API key (faster + seamless)

The gateway maps the **authenticated tunnel source address → signed node identity** from the membership snapshot the daemon already holds. That *is* the caller's identity. Consequences:

- **No API key** to issue, store, rotate, leak, or paste. This is strictly faster than a bearer-key model (no per-request secret lookup, no key DB) and removes an entire class of credential-theft risk.
- **Spoofing-proof**, because identity comes from the tunnel handshake the daemon verified, not from a header the client sets — the same property Tailscale gets by listening on localhost and stripping client headers. Rustynet's generalisation: gateway binds tunnel-only + uses only daemon-asserted identity (parent §8 control E1 makes a non-tunnel bind a fail-closed startup error).
- **Seamless:** the user opens RustyAI, it resolves `brain.llm.<mesh>` via MagicDNS, connects over the tunnel, and is identified automatically by virtue of being an enrolled device. Nothing to configure — membership is the credential (the Tailscale-SSH "no keys to manage" experience).

### 4.3 Speedier transport that doesn't compromise security

- **Plaintext inside the tunnel, not TLS-over-WireGuard.** Because the tunnel already encrypts, the gateway speaks plaintext gRPC/HTTP-2 to mesh peers. This removes the redundant TLS handshake + double-encrypt overhead while losing **no** security (the only observers are inside an already-encrypted, peer-authenticated tunnel). Industry confirms WireGuard's cipher is cheap and a second TLS layer is redundant for in-tunnel peers.
- **Persistent, multiplexed streaming.** gRPC/HTTP-2 keeps one persistent connection and streams tokens as binary frames — no per-request connection setup, ~25–35% lower streaming latency, large bandwidth savings vs JSON. Tokens flow the instant the engine emits them.
- **Cellular resilience option.** HTTP/3/QUIC eliminates TCP head-of-line blocking for mobile RustyAI clients on lossy links; the gateway can offer a QUIC listener on the tunnel as an alternative stream transport.
- **Browser fallback.** If a RustyAI build is web-based, SSE over HTTP/2 is the simpler token-streaming path; same identity + policy gate.

### 4.4 Net user experience

Install RustyAI on an enrolled device → it discovers `brain.llm.<mesh>` → streams a chat response with first-token latency dominated by the model, not by auth/handshake/TLS. No API key, no login wall for the transport (the device is the identity), no config. If the admin has not authorised the device, it is cleanly told "your admin hasn't enabled LLM access for this device" — default-deny, not a confusing failure.

---

## 5) Interface contract for RustyAI (node-side only)

RustyAI (the future client UI — chat, file upload, and project-editing on the connecting machine, like Claude Code/Codex) is out of scope to design here; this pins the **contract the LLM node exposes** so RustyAI can be built against a stable surface. RustyAI is "just a client."

### 5.1 Transport & discovery

RustyAI connects to `brain.llm.<mesh>` (stable MagicDNS overlay name) over the tunnel via gRPC/HTTP-2 (SSE or HTTP/3 optional). It never connects off-mesh; if the device is not enrolled, the first step is enrollment, not an LLM-specific path.

### 5.2 Identity & authorisation

The device is already a verified mesh peer; reachability is decided by signed policy on the LLM node. RustyAI presents **no API key**. On stream open the gateway resolves identity from the tunnel and evaluates signed policy; denied devices get a clear, fail-closed refusal.

### 5.3 Optional in-band session token (defence-in-depth)

For app-session continuity (and to bind a long-lived RustyAI "project edit" session), the gateway may issue a **short-lived, single-audience, node-signed capability token** (SPIFFE-style SVID analogue) on stream open. It is re-validated against current signed policy on every use and cannot exceed what policy allows (parent §8 E4). It is **never** a substitute for tunnel identity — only an additional check. No long-lived bearer keys.

### 5.4 API surface (stable contract)

| Operation | Shape | Notes |
|---|---|---|
| `hello` | peer → node | negotiate protocol + transport (gRPC/SSE/QUIC), receive model allow-list, quota, optional session token |
| `list-models` | per-peer | only models the peer's policy permits |
| `chat` / `complete` (streaming) | request → token stream | tokens streamed as generated; cancellable mid-stream |
| `embed` | request → vector | optional |
| `upload-context` | chunked file → context handle | for RustyAI file-upload / project context; size-bounded; stored per-peer, tunnel-only, evicted on session end |
| `usage` | per-peer | token/rate accounting for admin quotas |

**Versioning + hardening:** `hello` carries a protocol version; unknown majors are refused fail-closed. Wire parsing follows the project serialization-hardening posture (length-bounded, no unbounded allocation, deny on malformed) — relevant because inference payloads (prompts, uploaded context) are attacker-influenced input.

**What RustyAI must NOT assume:** reachability is not permanent (policy can revoke mid-session → stream severed), model access is policy-scoped, quotas are enforced node-side, and there is no off-mesh path. The client is untrusted; the node enforces. RustyAI's own architecture (UI, file watching, project-edit application, local diffing) is a separate future document.

---

## 6) Using an exit node while using the LLM (simultaneous)

The user wants their **internet traffic to egress an exit node** while still **using the LLM**. This is the well-understood "exit node + intra-mesh service coexistence" problem; Tailscale solves it with an exit-node LAN-access exception and **route precedence** (the exit node carries `0.0.0.0/0`, but more-specific routes — LAN, mesh subnet — are excepted and stay local/on-tunnel). Rustynet applies the same principle to the overlay:

**Rule: the mesh overlay CIDR is always excepted from the exit node's default route.** When a client selects an exit node, the daemon installs the exit's `0.0.0.0/0` for general internet egress **but** keeps a more-specific route for the Rustynet overlay CIDR pointing peer-to-peer (direct, or via relay). Longest-prefix match guarantees the more-specific overlay route wins, so:

- **Internet traffic** (web, app updates, general browsing) → encrypted to the exit node → egresses there. The user's public IP is the exit's.
- **LLM traffic** to `brain.llm.<mesh>` → stays **intra-mesh**, peer-to-peer to the LLM node (or via relay if no direct path) → **never hairpinned through the exit node.** Lower latency, and the prompt/response never leaves the mesh or transits the exit.

This must be explicit in the dataplane route logic: `sanitize_dataplane_routes_for_node_role` and the exit-route application path (`crates/rustynetd/src/daemon.rs`) must guarantee the overlay (and the LLM node's overlay address specifically) is **never** swallowed by the exit's `0.0.0.0/0`. A test pins it: with an exit selected, a packet to the LLM overlay address egresses the tunnel to the LLM peer, while a packet to a public address egresses via the exit.

Security notes for this mode:

- Routing LLM traffic intra-mesh (not through the exit) is the **more** private choice — the exit node operator never sees inference traffic, and inference stays end-to-end inside the tunnel between client and LLM node.
- If an operator deliberately *wants* LLM traffic to also traverse the exit (unusual), that is a policy choice, not the default; the default keeps service traffic intra-mesh for latency and least-exposure.
- This composes cleanly with `--exit-node-allow-lan-access`-style local exceptions; the overlay exception is independent of the LAN exception.

---

## 7) Admin governs who may use the LLM

"Admins must be able to configure whether users can use the LLM" is exactly the **default-deny signed-policy** model (Tailscale "grants"/ACLs; SPIFFE central authorisation). Concretely:

- A fresh LLM node authorises **nobody**. Internet/mesh reachability is necessary but not sufficient — the admin (membership owner) must sign a policy granting `(<peer or group> → LlmService) = Allow`. This is the parent §5 rule 2/3 and §8 control E2.
- **Granularity:** per-device or per-group (reuse the existing policy group machinery). The admin can also attach, in the same signed policy, a **model allow-list**, a **token/request rate quota**, and **time-of-day** scoping per peer/group — the gateway enforces all of these node-side.
- **Admin UX:** `rustynet policy` verbs (signed by the owner key) add/remove LLM access; a convenience wrapper `rustynet llm allow <peer|group> [--models …] [--quota …]` / `rustynet llm deny <peer|group>` emits the unsigned record for owner signing, mirroring the existing assignment/capability flow. `rustynet llm access list` shows who is currently authorised (read-only, available to `Client` for transparency).
- **Revocation is fail-closed and immediate.** A signed policy update removing a peer is applied through the existing membership/policy path; on apply, the gateway **severs any in-flight stream** for that peer before the change lands, and refuses new connects (parent §8 control E3 + E4 for any outstanding session token). A higher-epoch signed state is required (replay/rollback protection), so a revoked user cannot present stale "allow" state.
- **Capability is not authority.** `serves_llm` says a node *offers* inference; it never decides *who* — that is always the signed policy the admin controls. The verifier never consults `serves_llm` before validating signatures.

---

## 8) Per-platform implementation

Same host/consume split as the other host-capable roles; the LLM role adds an **accelerator** dimension.

### 8.1 Linux (primary host; GPU/accelerator)

- `rustynet-llm-gateway` runs as a systemd sibling (`rustynet-llm-gateway.service`), co-deployed by the role-transition orchestrator on entering `llm` (extends the existing Rust `ops install-systemd` co-deploy path — no new shell logic). The inference engine runs as its own loopback-only unit the gateway supervises/depends on.
- GPU/accelerator access is a host concern; the gateway health-gates on engine + accelerator availability (fail-closed if the model can't load).
- Tunnel-only bind on the overlay interface; nftables emitter adds an LLM table accepting the inference port **only** from the tunnel interface; the engine's loopback port is never exposed.

### 8.2 macOS (secondary host; Apple-silicon inference; pending green run)

- launchd sibling (`com.rustynet.llm-gateway.plist`); engine (e.g. MLX/llama.cpp/Ollama) loopback-only. Apple-silicon unified memory makes macOS a strong LLM host.
- PF scopes the inference port to the tunnel. `⛔ fail-closed` in the matrix until live evidence (same discipline as relay/anchor on macOS).

### 8.3 Windows (gated on D7/D9 dataplane parity)

- `rustynet-llm-gateway.exe` as a Windows service via SCM; engine loopback-only; WFP scopes the inference port to the tunnel (consistent with the WFP killswitch direction). Blocked in the wizard until role parity; fail-closed on `role set llm`.

### 8.4 iOS / Android (consume-only — RustyAI client)

- Cannot host (no accelerator-grade 24/7 availability, OS lifecycle, sandbox). Mobile runs the **RustyAI client** against an LLM node hosted elsewhere; HTTP/3/QUIC transport (§4.3) is the recommended mobile path for cellular resilience.
- `rustynet-mobile-core` carries the RustyAI transport client (tunnel-scoped, identity-from-tunnel); mobile `role set` refuses anything but `client` (mobile role lock).

---

## 9) Security controls (enforcement + verification)

Inherits all parent §8 controls (E1–E4) and §6.D transition controls. LLM-specific enforcement:

| Control | Enforcement | Verification |
|---|---|---|
| `serves_llm` requires owner signature | `apply_signed_update` rejects unsigned/invalid bundles | Unit test: tampered `serves_llm` flag invalidates signature → reducer rejects |
| Gateway binds tunnel-only; engine loopback-only | bind addresses validated at startup; non-tunnel gateway bind or non-loopback engine bind rejected fail-closed | Negative test: LAN/public packet to inference port → dropped; engine reachable only on loopback |
| Identity from tunnel, never from client input | gateway uses daemon-asserted peer identity; client-supplied identity headers/keys ignored/stripped | Test: forged identity header → ignored; unauthenticated tunnel source → no identity → deny |
| Default-deny per-peer access | `ContextualPolicySet::evaluate_with_membership` for `LlmService`; empty/missing/stale ⇒ `Decision::Deny` | Truth table: fresh LLM node → all denied; signed allow → that peer; revoke → denied |
| Admin model/quota/rate scoping | gateway enforces signed per-peer model allow-list + quota + rate | Test: peer requests a non-allowed model → denied; over-quota → throttled/denied |
| Session token ≤ signed policy | short-lived node-signed token re-checked vs policy each use | Test: revoke peer → token use denied before TTL expiry; stream severed |
| Teardown precedes revocation | listener + in-flight streams torn down before `serves_llm` leaves local state | Integration test: revoke mid-generation → stream severed, new connect refused, then bundle drops flag |
| Exit-node coexistence keeps LLM intra-mesh | overlay CIDR excepted from exit `0.0.0.0/0`; longest-prefix wins | Test: exit selected → packet to LLM overlay addr egresses to LLM peer; public addr egresses via exit |
| No custom crypto | tunnel provides confidentiality/auth; tokens use `rustynet-crypto`; plaintext-in-tunnel, no bespoke handshake | Code review: no new crypto/PKI in `rustynet-llm-gateway` |
| Prompt/upload input hardening | wire + upload parsing length-bounded, no unbounded alloc, deny on malformed | Fuzz/property tests on the gateway protocol decoder |
| No secret/content in logs | log peer-id + token thumbprint + token counts; never prompt text, completions, uploaded context, or tokens | Redaction test extended to LLM surfaces |
| Capability is not authority | verifiers never consult `serves_llm` before signature validation | Code review: no `serves_llm` gates signature verification |
| Deploy-before-advertise | orchestrator verifies gateway + engine healthy before emitting the signed bundle | Integration test: engine-load failure → no signed bundle; previous state preserved |

---

## 10) Build slices (maps to D13.d)

| Slice | Scope | Pass criterion |
|---|---|---|
| **D13.d.1** | `rustynet-llm-gateway` crate: gRPC/HTTP-2 streaming, engine proxy (loopback), identity-from-tunnel handoff, model/quota/rate enforcement, audit; SSE + HTTP/3 transports behind a flag | Unit/property tests green; streaming token path works against a mock engine; malformed wire → deny |
| **D13.d.2** | Daemon integration: tunnel-only listener, `TrafficContext::LlmService` gate, fail-closed health, teardown-before-revoke, session-token issue/verify | Integration test: default-deny → signed-allow → revoke with stream severance |
| **D13.d.3** | Exit-node coexistence: overlay-CIDR route exception in exit-route application + `sanitize_dataplane_routes_for_node_role` | Test: exit selected → LLM traffic intra-mesh, internet via exit |
| **D13.d.4** | `llm` preset wiring + admin UX (`rustynet llm allow/deny/access list`, model/quota flags); eight-preset table/transition tests | `role set llm` then `set admin` round-trips; admin can grant/revoke a device |
| **D13.d.5** | Linux service install + nftables LLM table; platform-matrix row; macOS launchd + Windows SCM scaffolds (gated) | Linux live evidence; macOS/Windows `⛔` until green run |

Standard workspace gates + `service_hosting_role_gates.sh` (LLM cases) + eight-preset `role_taxonomy_gates.sh` + new `llm_default_deny_gates.sh` (§9 truth table) + `llm_exit_coexistence_gates.sh` (§6 route-precedence test).

---

## 11) Refactor inventory (LLM-specific delta)

| File | Change |
|---|---|
| `crates/rustynet-llm-gateway/` (new crate) | The sibling gateway service |
| `crates/rustynet-control/src/role_presets.rs` | `ServesLlm` capability, `llm` preset row, `requires_llm_binary`, transition flags |
| `crates/rustynet-control/src/roles.rs` | `RoleCapability::ServesLlm` + parse/`as_str` + tests |
| `crates/rustynet-control/src/membership.rs` | `serves_llm` in `node_capabilities` canonical pre-image (append-only) |
| `crates/rustynet-policy/src/lib.rs` | `TrafficContext::LlmService`; model/quota scoping fields; truth-table tests |
| `crates/rustynetd/src/daemon.rs` | LLM listener lifecycle, access gate, health gate, teardown-before-revoke, **overlay-CIDR exit-route exception** |
| `crates/rustynet-cli/src/role_set.rs` | `llm` deploy/undeploy orchestration |
| `crates/rustynet-cli/src/ops_install_systemd.rs` | Optional `rustynet-llm-gateway.service` co-deploy |
| `crates/rustynet-cli/src/main.rs` | `rustynet llm allow/deny/access list` admin verbs |
| `crates/rustynet-operator/src/role.rs` | `llm` per-platform eligibility |
| `crates/rustynetd/src/linux_runtime_nftables.rs` | LLM-port tunnel-scoping table |
| `start.sh`, operator menu | `llm` wizard option + accelerator + "no device authorised yet" guidance |
| `documents/operations/PlatformSupportMatrix.md` | `llm` row |
| `documents/operations/RustynetdServiceHardening.md` | LLM hardening section |
| `documents/operations/SecretRedactionCoverage.md` | LLM log surfaces (prompts/completions/context never logged) |
| `documents/Requirements.md` §6.1 | `rustynet-llm-gateway` component |
| `documents/SecurityMinimumBar.md` §6.E | service-hosting controls (shared with NAS) |

Deliberately unchanged: `NodeRole` enum, WireGuard backend + tunnel crypto, signing root, trust verifiers, `rustynet-relay`, `rustynet-nas`.

---

## 12) Open questions

| Question | Default | Re-open trigger |
|---|---|---|
| gRPC vs SSE as the primary RustyAI transport? | gRPC/HTTP-2 for native clients (lowest streaming latency, multiplexed); SSE for any web RustyAI; HTTP/3/QUIC for mobile/cellular. | If a single transport must cover all clients, pick SSE-over-HTTP/2 for simplicity at a small latency cost. |
| Does the gateway embed a Rust inference engine, or proxy to a separate one? | Proxy to a co-located engine behind a loopback boundary (swappable engine, thin Rust gateway). | If a first-class pure-Rust inference path is wanted, revisit; the gateway interface stays the same. |
| Should LLM traffic ever traverse the exit node? | No — intra-mesh by default (lower latency, least exposure, exit operator never sees inference). | An explicit operator policy could route it via the exit; never the default. |
| Per-model authorisation granularity? | Yes — signed policy carries a per-peer/group model allow-list, enforced by the gateway. | n/a (already general). |
| Should mobile ever host `llm`? | No — consume-only via RustyAI. Accelerator + lifecycle constraints. | Stable OS constraints; not expected to change. |

---

## 13) Definition of done

The `llm` role is "done" when:

- D13.d.1–5 land on `main` with passing gates.
- A GPU/accelerator Linux host runs `rustynet role set llm`, ending with `rustynet-llm-gateway` + engine healthy, `serves_llm` advertised in signed membership, inference API bound tunnel-only, engine loopback-only, **default-deny** (no device reaches it yet).
- The admin signs a policy authorising one device (optionally model/quota-scoped); a RustyAI client on that device streams a chat completion over the tunnel **with no API key**, identity derived from the tunnel; an un-authorised mesh peer is denied; an off-mesh attempt has no surface.
- With an exit node selected on the client, internet traffic egresses the exit while LLM traffic stays intra-mesh (route-precedence test green).
- Revoking the device (owner-signed) severs the in-flight stream and refuses reconnect before the capability drops.
- Logs contain no prompts, completions, uploaded context, or tokens.
- `PlatformSupportMatrix.md` `llm` row, `SecurityMinimumBar.md` §6.E, and `Requirements.md` §6.1 reflect reality.
- This document remains the source-of-truth for the role.

---

## 14) Cross-references

- [`NodeRoleTaxonomyExtension_2026-06-11.md`](./NodeRoleTaxonomyExtension_2026-06-11.md) — parent; secure-exposure model (§5) and §6.E controls.
- [`NasNodeRoleDesign_2026-06-11.md`](./NasNodeRoleDesign_2026-06-11.md) — sibling service-hosting role.
- [`NodeRoleTaxonomy_2026-05-21.md`](./NodeRoleTaxonomy_2026-05-21.md) — base taxonomy.
- [`AnchorNodeRoleDesign_2026-05-21.md`](./AnchorNodeRoleDesign_2026-05-21.md) — co-deployed-sibling pattern template.
- [`MagicDnsSignedZoneSchema_2026-03-09.md`](./MagicDnsSignedZoneSchema_2026-03-09.md) — stable overlay name (`brain.llm.<mesh>`).
- [`CrossNetworkRemoteExitNodePlan_2026-03-16.md`](./CrossNetworkRemoteExitNodePlan_2026-03-16.md) — exit-node dataplane the §6 coexistence rule extends.
- [`SerializationFormatHardeningPlan_2026-03-25.md`](./SerializationFormatHardeningPlan_2026-03-25.md) — wire-format hardening for the gateway protocol + uploads.
- [`RustynetDataplaneExecutionPlan_2026-05-18.md`](./RustynetDataplaneExecutionPlan_2026-05-18.md) — D13.d.
- [`../PlatformSupportMatrix.md`](../PlatformSupportMatrix.md) · [`../RustynetdServiceHardening.md`](../RustynetdServiceHardening.md) · [`../MacosLaunchdServiceManagement.md`](../MacosLaunchdServiceManagement.md) · [`../SecretRedactionCoverage.md`](../SecretRedactionCoverage.md)
- [`../../Requirements.md`](../../Requirements.md) §6.1 · [`../../SecurityMinimumBar.md`](../../SecurityMinimumBar.md) §6.E

### Industry references (§2)

- Tailscale ACLs / grants (default-deny, identity-based): https://tailscale.com/kb/1018/acls · https://tailscale.com/blog/app-capabilities
- Tailscale identity (WireGuard node keys as identity): https://tailscale.com/docs/concepts/tailscale-identity
- Tailscale Serve identity headers (backend-on-localhost anti-spoofing): https://tailscale.com/kb/1312/serve
- Tailscale exit nodes + LAN access coexistence: https://tailscale.com/docs/features/exit-nodes
- SPIFFE/SPIRE workload identity (short-lived SVIDs, no static secrets): https://spiffe.io/docs/latest/spire-about/use-cases/ · https://www.redhat.com/en/topics/security/spiffe-and-spire
- LLM streaming transports (gRPC vs SSE vs HTTP/3): https://procedure.tech/blogs/the-streaming-backbone-of-llms-why-server-sent-events-(sse)-still-wins-in-2025
- WireGuard performance / avoiding double-encryption: https://www.wireguard.com/performance/ · https://blog.howardjohn.info/posts/wireguard-tls/
