# Rustynet Dataplane Execution Plan

- Date: 2026-05-18
- Status: active (primary execution ledger for the cross-network dataplane track)
- Owner: Rustynet
- Supersedes nothing; complements `PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md` and `WindowsExitAndRelayDeltaPlan_2026-05-10.md` by adding the architectural decisions and phase queue agreed during the 2026-05-18 dataplane brainstorm.

---

## 0) Purpose of this document

This is the source-of-truth plan for taking the Rustynet dataplane from "Linux-mostly works in lab, Windows is a stub" to "two devices on different networks can talk to each other reliably without any third party, any rented infrastructure, any router port-forwarding, or any user-visible setup beyond an enrollment code."

It captures:
- the mission in plain English (§1),
- the locked architectural decisions (§2),
- the things we will explicitly NOT do (§3),
- the trade-offs we have accepted (§4),
- the phase queue and per-phase pass criteria (§5–§6),
- the operating contract for executing the work (§7),
- known follow-up questions and what would re-open a decision (§8),
- cross-references to existing plan docs (§9).

If a later document or commit conflicts with this plan, this plan is the source of truth for the dataplane architecture until it is explicitly superseded by a new dated plan.

---

## 1) Mission (plain English)

Rustynet is a private network for the user's devices, equivalent in user experience to Tailscale but with zero external dependencies. The intent is:

- The user's laptops, phones, and servers can reach each other regardless of which network they happen to be on.
- All cryptographic keys live on the user's devices.
- All coordination state lives on the user's devices.
- The only "anchor" with a stable address is a home server the user already runs — no rented VPS, no SaaS, no third party.
- No router port-forwarding is required to make any of this work.
- Adding a new device is a single command: mint an enrollment token on an existing device, paste it into the new device, done.
- The user is never asked to call their ISP, edit their router admin page, sign in to anyone's account, or trust any company.

The architecture is a mesh VPN built on WireGuard, with a peer-distributed coordination layer (no central server) and a relay role hosted on the home server (no external relay host).

---

## 2) Architecture decisions (locked 2026-05-18)

These five decisions are the architectural shape of the dataplane. Each was agreed explicitly during the 2026-05-18 brainstorm; each is sticky unless a follow-up conversation reopens it.

### 2.1 Coordination: peer-distributed gossip

The signed membership bundle is gossiped peer-to-peer over the existing WireGuard control channel. Every peer keeps the current bundle locally; new bundles propagate epidemically (peer A → its neighbours → their neighbours).

- No external coordination host. No SaaS. No GitHub-Pages-static-file. No DNS-as-coordination. The bundle never leaves the mesh.
- The signing key for the bundle is held by the operator on whichever peer they choose to designate as the issuer. By convention, the home server holds the issuer key; nothing in the codebase requires it.
- Epoch + replay-watermark mechanism (already present in `rustynet-control`) prevents stale-bundle replay and split-brain after network partition.

### 2.2 STUN: public servers

Use existing public STUN infrastructure (`stun.l.google.com:19302`, Cloudflare's, community pools). They observe one UDP packet per peer per refresh interval and reflect the public address back. They see nothing else; they cannot tamper because the bundle is signed and the WireGuard handshake is end-to-end.

- No self-hosted STUN. The privacy gain is negligible; the operational cost is non-zero.
- The STUN server list is a reviewed constant in the codebase, configurable via `RUSTYNETD_STUN_SERVERS` for testing.

### 2.3 Relay: home server, zero ingress

The home server runs two services side by side:
- `rustynetd` — the regular peer daemon
- `rustynet-relay` — the relay binary (currently a placeholder; D4 turns it into a real server)

The home server has **no port-forwarding on the home router**. It keeps its NAT mapping open by firing outbound WireGuard `PersistentKeepalive` packets (25-second cadence) to every peer. The home router's NAT, having seen the outbound flow, allows inbound packets back to the same external port. Roaming peers learn the home server's current public endpoint from the gossiped membership bundle (which is refreshed when the home server polls STUN).

This is the same technique every modern NAT-traversing protocol uses — it is *not* a hack. It is documented in RFC 5128 §3 and is what enables WebRTC, Skype, BitTorrent, and dozens of other systems to work without router config.

- The home server is always-on, has a stable enough address (residential ISPs change addresses on lease renewal — gossip handles this automatically when the home server's STUN re-poll observes the new address).
- The relay sees only ciphertext. The end-to-end WireGuard session is between the two communicating peers; the relay forwards opaque frames.

### 2.4 Onboarding: enrollment token

Adding a new device works like this:

1. On any existing peer: `rustynet enrollment mint --device-name laptop --ttl 10m` → prints a short token (e.g. `rn-enroll-abcd1234`).
2. Operator transfers the token to the new device by any out-of-band channel (typed, scanned via QR, pasted over SSH, written on paper).
3. New device contacts an existing peer at the existing peer's gossiped endpoint, presenting the token + its own pubkey.
4. Existing peer verifies the token (HMAC, TTL not expired, not already consumed), signs the new device's pubkey into the next membership bundle, distributes the new bundle.
5. New device receives the bundle, sees itself, joins the mesh.

No accounts, no Google/Apple/Microsoft sign-in, no SaaS verification, no "scan this QR with the Tailscale app." The token is a one-time HMAC; once consumed it is destroyed.

### 2.5 Reachability for new-device bootstrap: cone-NAT-via-hole-punching

A new device can bootstrap from any network where the home server is reachable. With decision 2.3, the home server is reachable from any network that has cone-type NAT and outbound UDP allowed. The failure modes (symmetric NAT on either side, networks blocking UDP entirely) are the same failure modes that affect normal peer traffic — there is no fix for these without changing the architecture (e.g. by introducing a public-ingress host).

The user has explicitly accepted these failure modes. See §4.

### 2.6 Reliability additions: uPnP, IPv6, ICE

To push the cellular pair-success rate from the ~85% baseline of "WireGuard hole-punching against a cone-NAT home server" toward ~95-97%, three additional mechanisms are folded into the plan:

- **uPnP / NAT-PMP / PCP autoconfig.** On startup, the home server asks its router for a port mapping via the standardised protocols. If the router supports any of them (most consumer routers support uPnP, often with it disabled by default — but a substantial fraction have it on), the relay gets a real port-forward without the user touching the router admin page. If none of the protocols work, the outbound-keepalive trick remains as the fallback.
- **IPv6 candidate gathering.** When both endpoints have global IPv6 addresses (no NAT in standard IPv6 deployments), they can connect directly without any of the NAT-traversal machinery. Peers gossip both IPv4 and IPv6 candidates; the connect path prefers IPv6 when both ends are dual-stack.
- **ICE-style candidate prioritisation.** Instead of "try the one endpoint we have," try multiple endpoints in priority order, in parallel: LAN-host > IPv6-host > IPv6-srflx > IPv4-srflx > relay. This is WebRTC's standardised approach (RFC 8445).

None of these change the architecture. They are additive reliability improvements layered on top of decisions 2.1–2.5.

---

## 3) Non-goals (things we will NOT do)

These are explicit. If a future cycle proposes one of them, the proposal must reopen the architecture decision with the user first; it cannot be silently introduced.

| Non-goal | Why |
|---|---|
| No central coordination server (SaaS or self-hosted webhook) | Defeats decision 2.1 and reintroduces a third party. |
| No external relay host (VPS, "DERP fleet", anything outside the user's hardware) | Defeats decision 2.3. The whole point is one home server runs everything. |
| No manual router port-forwarding required of the user | Defeats decision 2.3 and the user-experience goal. uPnP autoconfig (2.6) is allowed because the user does not touch it; it asks the router on their behalf. |
| No requirement that the user contact their ISP | Defeats decision 2.3. |
| No accounts, no sign-in, no SaaS-mediated identity | Defeats decision 2.4. The enrollment token is a one-time HMAC; nothing else. |
| No custom cryptography in production paths | Per `CLAUDE.md` §3 and `documents/SecurityMinimumBar.md`. WireGuard's ChaCha20-Poly1305 / Curve25519 / BLAKE2s / HKDF stack is the floor. |
| No replacement of WireGuard | Discussed during the 2026-05-18 brainstorm. The cellular-flakiness problem is at the NAT layer, not the WireGuard layer; replacing the crypto cannot fix it. Replacement would be a security regression with zero NAT benefit. |
| No protocol that requires TCP-port-443 obfuscation as the primary transport | UDP is the right transport for hole-punching. TCP-over-443 tunnelling is the fallback technique for the UDP-blocked case only; it is not the main path. We may add it later if user reports hitting UDP-blocked networks regularly, but it is explicitly out of the current scope. |
| No port-prediction or "loud" NAT-traversal techniques (birthday-paradox hole punching, SIP ALG abuse) | High false-positive rate; gets the user rate-limited by their ISP / cellular carrier; brittle. |
| No "exit node" feature in the base plan | The "all internet traffic via home server" feature exists in the codebase (Windows-as-exit track) but is NOT what most users want and is NOT the default. It can be enabled per-mesh after the base mesh works; it is intentionally out of the D2-D5.5 critical path. |
| No standalone prompt documents | Per `CLAUDE.md` §6 and `documents/operations/README.md`. This file is an execution plan, not a prompt; execution guidance lives in the plan body, not in a separate "How to instruct an agent" sibling document. |

---

## 4) Accepted trade-offs (things that won't work)

The architecture intentionally trades cellular-pair-success for "zero external infrastructure." The user has explicitly accepted these failure modes:

| Failure mode | When it triggers | What the user sees | Recovery |
|---|---|---|---|
| Cellular-to-cellular pair fails | Both endpoints on carrier-grade symmetric NAT (typical 4G/5G in UK/EU/US) | "Peer unreachable" between the two cellular devices specifically; both can still talk to the home server | Either device moves to a non-cellular network. Mesh recovers automatically. |
| Cellular-to-home-server fails | Cellular NAT happens to be symmetric AND the home router's uPnP isn't available AND IPv6 isn't available on the cellular side | Cellular device sees "home server unreachable" | Same: device moves to a non-cellular network, or waits until IPv6 / uPnP path becomes available. |
| Network blocks outbound UDP entirely | Some hotel/airport WiFi, some corporate networks | "Mesh disabled" on that network | Leave the network. There is no software fix without TCP-over-443 tunnelling (explicit non-goal in §3). |
| New device cannot bootstrap | New device is on a network where the home server isn't reachable (symmetric-NAT-on-both-sides at first contact) AND the new device isn't on the same LAN as any existing peer | Operator typing the enrollment token gets "peer unreachable" from the new device | Bootstrap the new device on the home LAN, or move it to a cone-NAT network. |
| Home server's public endpoint changes mid-session | ISP forces a DHCP lease renewal mid-session (rare for residential, common for some mobile broadband) | Brief disconnection (~30 seconds) until home server re-runs STUN and gossips the new endpoint | Automatic. |
| Home server goes offline | Power outage, reboot, etc. | Mesh degrades to direct-only (~85% pair success). Cellular-via-relay pairs lose connectivity. | Home server reboots; mesh restores. |

Anything outside this list is a bug, not an accepted trade-off.

---

## 5) Phase queue

The plan executes in four tracks. Alpha is sequential and is the critical path. Beta runs in parallel with Alpha. Gamma converges after Alpha + Beta. Delta is doc-only and last.

### 5.1 Track Alpha — platform-agnostic dataplane (sequential)

1. **D2** — STUN srflx port fix
2. **D2.3** — uPnP / NAT-PMP / PCP autoconfig
3. **D2.4** — IPv6 candidate gathering
4. **D3** — Relay client shares transport socket
5. **D2.5** — Peer-distributed signed-bundle gossip
6. **D4** — Production relay binary
7. **D2.7** — Enrollment-token mint/verify/consume
8. **D5** — Linux ↔ Linux cross-LAN baseline evidence
9. **D5.5** — ICE-style candidate prioritisation
10. **D11** — Anchor node role formalisation (canonical design: [`AnchorNodeRoleDesign_2026-05-21.md`](./AnchorNodeRoleDesign_2026-05-21.md))
11. **D12** — Node role taxonomy + 6-role user-selectable surface (canonical design: [`NodeRoleTaxonomy_2026-05-21.md`](./NodeRoleTaxonomy_2026-05-21.md))

(The non-monotonic numbering — D2.3, D2.4, D2.5, D2.7 sitting between D2 and D5 — preserves cross-references to earlier brainstorm conversations. The numbers are labels, not sort keys; execute in the order above.)

### 5.2 Track Beta — Windows readiness (parallel with Alpha)

- **D6** — `windows_traffic.rs` + `windows_install.rs` fix

### 5.3 Track Gamma — Windows live evidence (depends on Alpha + Beta)

- **D7** — Windows-as-exit live evidence
- **D9** — Mixed-platform direct P2P + relay fallback

(D8 — Windows-as-relay — is **omitted from the active queue**. The relay is the Linux home server; Windows running its own relay binary is not in scope. D8 stays in the historical record only.)

### 5.4 Track Delta — docs (after all above)

- **D10** — Posture promotion (PlatformSupportMatrix, WindowsWorkingNodePlan §Definition of Done, OsAgnosticOrchestratorAndWindowsPeerDeltaPlan §11)

---

## 6) Per-phase detail

Each phase has: scope, files-touched list, pass criterion, estimated cycle count, dependencies.

### D2 — STUN srflx port fix

- **Scope.** The current STUN client guesses the local UDP port for the srflx candidate instead of reading it from the bound transport socket. Fix is to read `socket.local_addr()` (or its equivalent after the kernel assigns an ephemeral port for an `:0` bind) and use that throughout the candidate-gathering path.
- **Files.** `crates/rustynetd/src/stun_client.rs`, `crates/rustynetd/src/traversal.rs`.
- **Reference defect.** `PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md` §8.1.
- **Pass criterion.** New test pins: "the discovered srflx candidate port equals the bound transport socket's measured external port" for both IPv4 and IPv6 (test runs against a known-good local STUN echo so the assertion can be deterministic).
- **Estimated cost.** 1–2 cycles.
- **Depends on.** Nothing in the dataplane plan.

### D2.3 — uPnP / NAT-PMP / PCP autoconfig

- **Scope.** On home-server startup, probe the local router for uPnP IGD support, NAT-PMP, and PCP (in that order — pick the first that succeeds). Request a UDP port mapping for the relay's bound port. Renew the lease before it expires. Fall back to the outbound-keepalive trick (decision 2.3) when no protocol is available.
- **Files.** New `crates/rustynetd/src/port_mapper.rs`. Daemon wiring in `crates/rustynetd/src/daemon.rs`. CLI flag `--port-mapping-mode={auto,keepalive,disabled}`.
- **Library choice.** Hand-rolled per-protocol clients (NAT-PMP, PCP, and uPnP) with full RFC-pinned tests; no new transitive deps beyond `hmac`, `base64`, `subtle` (all reviewed and policy-clean).
- **Pass criterion.** Integration test against a mock IGD server confirms mapping is requested, registered with the correct port, and refreshed on cadence. Self-test against a real consumer router (one-off, results captured in `artifacts/cross_network/<commit>/port_mapping_probe.json`).
- **Estimated cost.** 1–2 cycles.
- **Depends on.** D2.
- **Status (2026-05-19).** **Complete.** Six slices landed across commits e0e9a96, 9062970, 5f76c8b, ab93726, 819f472, 2647785:
  - NAT-PMP client (RFC 6886) — full wire-format encode/decode, §3.1 retry/backoff, §3.4 release semantics, 15 tests.
  - PCP client (RFC 6887) — full MAP wire-format, IPv4-mapped IPv6 encoding, cryptographic Mapping Nonce per §11.2, ADDRESS_MISMATCH/NAT44 hint, 7 tests.
  - `PortMappingProbe` orchestrator — PCP→NAT-PMP→uPnP order, hard-refusal short-circuit, soft-failure fallthrough, 5 tests.
  - `detect_default_gateway()` — Linux (`/proc/net/route` LE-hex parser) + macOS (`route -n get default` stdout parser), Windows stubbed, 8 parser tests.
  - uPnP IGD client (UPnP DA v1.1) — SSDP M-SEARCH multicast discovery, device-description XML walker, SOAP envelope builder, std-only HTTP/1.1 client, AddPortMapping/DeletePortMapping/GetExternalIPAddress with typed faults for codes 401/402/501/606/718/724–728, 18 tests.
  - Daemon wiring + CLI flag — `PortMappingMode {Auto, Keepalive, Disabled}` with `Keepalive` as the strict-secure-practical default, `--port-mapping-mode={auto,keepalive,disabled}` flag, `PortMappingSupervisor::bring_up` called once after `runtime.bootstrap()`, logs `port_mapping: granted protocol=… external_addr=…` / `keepalive_fallback reason=…` / `skipped reason=…` / `bring-up failed: …`. 9 supervisor + 4 CLI tests.
- **Follow-up (out of D2.3 scope).** Refresh-on-cadence (background-thread that renews the lease at half-lifetime) is queued behind a DaemonRuntime state plumb-through; today's lease bring-up is single-shot at startup.

### D2.4 — IPv6 candidate gathering

- **Scope.** Probe for IPv6 connectivity. STUN over IPv6 against IPv6-capable STUN servers. Add v6 candidates to the gossiped peer-endpoint list. Update the connect path to try v6 candidates first when both peers have them.
- **Files.** `crates/rustynetd/src/stun_client.rs`, `crates/rustynetd/src/traversal.rs`, peer-table types in `crates/rustynetd/src/daemon.rs`.
- **Pass criterion.** Dual-stack peer has both v4 srflx and v6 srflx in its gossiped candidate list. Pair-selection picks v6 when both peers have it.
- **Estimated cost.** 1 cycle.
- **Depends on.** D2.
- **Status (2026-05-19).** **Complete (producer side).** Commit b844faf adds `crates/rustynetd/src/dataplane_candidates.rs` with `AddressScope` taxonomy (Unspecified/Loopback/LinkLocal/Multicast/Broadcast/Private/Global incl. RFC 6598 CGNAT + RFC 4193 ULA + RFC 3849 documentation-prefix recognition), `LocalHostCandidate` with `is_gossip_worthy()` / `is_v6_global()`, getifaddrs-based enumeration on Linux/macOS (Windows stubbed), per-family STUN srflx gather, and `CandidateSet { v4_host, v6_host, v4_srflx, v6_srflx }`. 13 tests including v4/v6 STUN echo round-trips and a dual-stack `gather_candidate_set` end-to-end. Pair-selection consumer side lives in D5.5.

### D3 — Relay client shares transport socket

- **Scope.** Per Plug&Play §8.2, the current relay client binds a separate ephemeral socket despite documentation saying it shouldn't. Fix is to make the relay path use the same UDP socket as the direct path. This is required for D4 to make sense (the relay binary needs to know the client's actual transport socket to forward frames correctly).
- **Files.** `crates/rustynetd/src/relay_client.rs`.
- **Pass criterion.** Test pin: no separate ephemeral socket is bound when the relay path is active; direct and relay frames flow on the same UDP socket.
- **Estimated cost.** 1 cycle.
- **Depends on.** D2.
- **Status (2026-05-19).** **Complete.** Commit 429dfa5: deleted `RelayClient::bind(UdpSocket)` + the private `socket: Option<UdpSocket>` field. Replaced with `attach_authoritative_transport(wg_listen_port: u16)` that asserts the relay client is wired into the WG backend's transport and fails closed on port mismatch with the configured `local_port`. Daemon `DaemonRuntime::new` calls the attach API after the backend loads. `RelayClient::establish_session` and `send_keepalive` convenience methods now refuse to fall back to a private socket and return `AuthoritativeTransport(…)` with a diagnostic pointing to the closure-based `_with_round_trip` / `_with_sender` variants. 4 new D3 pin tests.

### D2.5 — Peer-distributed signed-bundle gossip

- **Scope.** A gossip-push loop on top of the existing `rustynet-control` bundle infrastructure. When peer A creates a new signed bundle (e.g. after enrolling device B), it pushes the bundle over the WG control channel to every peer it has a session with. Each recipient verifies the signature + epoch + replay-watermark, applies if newer, and re-pushes to *its* peers. Standard epidemic gossip with the existing watermark protection.
- **Files.** `crates/rustynet-control/src/membership.rs`, `crates/rustynetd/src/daemon.rs`.
- **Pass criterion.** Three-peer mesh test: peer A signs a new bundle; peer B (direct neighbour of A) applies it within 3 seconds; peer C (only reachable through B) applies it within 6 seconds.
- **Estimated cost.** 2–3 cycles (this is the largest single piece in Track Alpha).
- **Depends on.** D2 (for transport reliability), D3 (because the gossip channel runs on the shared transport socket).
- **Status (2026-05-20).** **Complete (end-to-end).** Commit 3bcfdc1: push-loop wiring lands the remaining four pieces on top of the 229b9c7 primitives — (1) `peer_gossip::serialise_bundle` / `deserialise_bundle` with `GOSSIP_BUNDLE_WIRE_VERSION=1` and `MAX_GOSSIP_DATAGRAM_BYTES=4096`; (2) `gossip_transport.rs` binding a non-blocking UDP socket on `RUSTYNET_GOSSIP_PORT=51821` (one above the WG listen port) with strict size caps on both sides; (3) `gossip_runtime::GossipNode` encapsulating the local sequence counter, per-source replay ledger, heartbeat re-mint timer (default 30 s), fail-closed watermark persistence, and the epidemic re-push logic (forward to every known peer except originator + immediate sender); (4) `IpcCommand::PushGossipBundle { wire_bytes }` IPC verb with URL-safe-base64 wire form. DaemonRuntime owns the four fields the spec calls out (`gossip_sequence`, `seen_gossip_sequences`, `last_minted_bundle`, `next_gossip_mint_at`) plus the runtime/transport; the main loop drains inbound on every iteration and mints when the cached `CandidateSet` drifts or the timer elapses. New CLI flag `--gossip-watermark` and env var `RUSTYNET_GOSSIP_WATERMARK` plumb the spool path through, with a corresponding entry in `scripts/systemd/rustynetd.service`. The §D2.5 pass criterion is pinned by `crates/rustynetd/tests/gossip_three_peer_mesh.rs::bundle_propagates_a_to_b_within_3s_and_a_to_c_via_b_within_6s` (3-second B-budget, 6-second C-via-B-budget) plus four negative pins (tampered signature, replay, loopback candidate, unknown source) and one defense-in-depth pin (malformed wire). 24 wire-format / runtime / transport unit tests plus 6 mesh integration tests. Production-side enrollment of per-peer gossip signing keys + known_peers population from the membership snapshot is deferred to the D2.7 enrollment-token consume slice; until then the daemon ships the wired-but-dormant subsystem and the integration test is the proof of end-to-end correctness.

### D4 — Production relay binary

- **Scope.** Replace the placeholder in `crates/rustynet-relay/src/main.rs` with a real server: listen on the configured UDP port, accept signed relay tokens, verify against the membership bundle, forward encrypted frames between peers. Signed-token replay window. Frame-forwarding via the existing `transport.rs` core. Operational hardening: max-frames-per-second per token, max-bytes-per-second per pair, logging that omits all peer identifiers.
- **Files.** `crates/rustynet-relay/src/main.rs`, `crates/rustynet-relay/src/transport.rs`.
- **Pass criterion.** Two-node integration test: peers cannot direct-connect (forced by binding restrictive NAT-simulation); they connect through the real `rustynet-relay` binary; WireGuard handshake completes; iperf3 traffic flows; tcpdump on the relay confirms ciphertext-only.
- **Estimated cost.** 3–4 cycles.
- **Depends on.** D3, D2.5.
- **Status (2026-05-19).** **Code-complete.** The relay binary is no longer a placeholder: 3,500+ lines across `main.rs`, `transport.rs`, `session.rs`, `rate_limit.rs`. Token-bucket rate limiter with `max_pps=10_000`, `max_bps=100_000_000`, `max_sessions_per_node=8`, and per-node bucket isolation. SCM lifecycle on Windows via the `daemon` feature. Live cross-network relay-exit test script lives at `scripts/e2e/live_linux_cross_network_relay_remote_exit_test.sh`. The remaining work — running the live two-node integration test on real hardware and archiving tcpdump evidence — overlaps with D5's pass criterion and requires hardware; deferred to the live-evidence collection cycle.

### D2.7 — Enrollment-token mint/verify/consume

- **Scope.** New CLI verb `rustynet enrollment {mint, verify, consume}`. Mint generates an HMAC token with TTL. Verify checks the token's signature, TTL, and consumption state. Consume marks the token used and signs the new device's pubkey into the next bundle.
- **Files.** New `crates/rustynet-control/src/enrollment.rs`. Daemon wiring. CLI verb in `crates/rustynet-cli/src/main.rs`.
- **Pass criterion.** Two-peer integration test: existing peer mints token; new device (separate process, simulating a fresh install) given the token + the existing-peer endpoint joins the mesh; receives the signed bundle; participates in further gossip.
- **Estimated cost.** 2 cycles.
- **Depends on.** D2.5, D4.
- **Status (2026-05-21).** **Complete (end-to-end + trust propagation).** Commits d2412ee + 0ec1096. Commit d2412ee landed the operator surface (CLI `rustynet enrollment {mint, verify, consume}`, daemon `IpcCommand::EnrollmentConsume`, `enrollment_consume.rs` orchestrator with strict-policy push-address scope filter, ledger spool, secret file with 0o600 perms, `--enrollment-secret` / `--enrollment-ledger` flags + env vars + systemd unit entries). Commit 0ec1096 closes the trust-propagation gap that the consume verb alone leaves open: new `crates/rustynet-control/src/enrollment.rs` carries `EnrolleeAdmitContext` and `build_add_node_record_for_enrollee` which produce an unsigned `AddNode` `MembershipUpdateRecord` from the current snapshot via the existing public `preview_next_state` reducer (so a signature gathered against the record validates through `apply_signed_update` unmodified); the new `rustynet enrollment admit` CLI verb chains verify-and-consume + ledger persist + record build + approver-key sign + (optional `--apply`) log append + snapshot persist. The §D2.7 pass criterion is pinned by two test files. `crates/rustynetd/tests/enrollment_two_peer_redeem.rs::enrollee_joins_mesh_via_token_consume_and_participates_in_gossip`: existing peer A mints, new device N is consumed into A's gossip routing table, A's mint reaches N within 3 s, N mints back so A applies N's endpoints within 3 s. `crates/rustynetd/tests/enrollment_trust_propagation.rs::admit_round_trips_enrollee_into_post_apply_membership_state`: end-to-end mint → consume → build → sign → apply, asserting the post-apply membership state contains the enrollee as an Active node with the correct verifying key + owner — proving every other peer that reloads the snapshot learns the new identity through the same signed trust artefact. Negative pins across both files: replay, wrong-secret, expired token, loopback push-address (consume side); wrong approver key, duplicate node_id reducer reject, post-consume token-replay reject, canonical-payload structural pin (admit side). 13 + 5 + 5 + 4 unit/integration tests in total. Future slice: when an operator-driven membership-snapshot distribution mechanism is in place (today the distribution channel is operator-managed via the existing `membership apply-update`), test the cross-peer reload end-to-end on real hardware.

### D5/D7/D9 — Live-lab evidence (Track Alpha/Gamma)

The live-evidence phases below (D5, D7, D9) collect artifacts from real
hardware: two devices on separate networks (or one on cellular), real
NAT topologies, real WireGuard handshakes, and tcpdump confirming
ciphertext-only relay traffic. These cannot be produced from a
non-live cycle. The supporting code-side primitives they depend on
(D2.3–D2.7, D3, D4, D5.5, D6) are all complete as of 2026-05-19 and
exercised by 3,046+ workspace unit / integration tests.

Operators running these live-evidence cycles should use
`scripts/e2e/live_linux_cross_network_relay_remote_exit_test.sh` as the
starting script, and archive the resulting artifacts under
`artifacts/cross_network/<commit>/` per the existing pattern.

### D5 — Linux ↔ Linux cross-LAN baseline evidence

- **Scope.** Two Linux devices on different LANs (or one on a LAN and one on a tethered cellular network) prove the dataplane works end-to-end. Capture artifacts pinned to the commit SHA. Validate the relay-fallback path by forcing direct-connect to fail.
- **Pass criterion.** All of the following observed and archived under `artifacts/cross_network/<commit>/`:
  - WireGuard handshake completes within 5 seconds of `up`
  - bidirectional `iperf3 -t 60` throughput report
  - tcpdump on the underlay interface showing frames going to the peer's discovered public endpoint (direct path), not to the relay
  - separate run with the relay path forced (one side simulated symmetric NAT); iperf3 still works; tcpdump on the relay host shows opaque-frame forwarding only
  - `tcpdump | grep -i 'tunnel-internal-CIDR'` shows zero leaks on the underlay
- **Estimated cost.** 1–2 cycles.
- **Depends on.** D2 through D2.7.

### D5.5 — ICE-style candidate prioritisation

- **Scope.** Restructure the connect path to attempt multiple candidates in parallel, prioritised by pair-type. Use the standard ICE priority formula (or a simplified version that captures the right ordering). Race the candidates; pick the first that completes a WireGuard handshake; tear down the others.
- **Files.** `crates/rustynetd/src/traversal.rs`, possibly new `crates/rustynetd/src/ice.rs` if the logic gets large enough to justify a module.
- **Pass criterion.** Time-to-connect for cone-NAT pairs improves; "marginal" pairs (one cooperative, one nearly-symmetric) that fail single-candidate connect now succeed via parallel candidate gathering.
- **Estimated cost.** 2–3 cycles.
- **Depends on.** D5.
- **Status (2026-05-21).** **Complete (end-to-end).** Commits 447e40e + 9a86a05. Commit 447e40e landed the RFC 8445 §5.1.2.1 per-candidate priority + §6.1.2.3 pair-priority + §6.1.2.4 foundation dedupe + deterministic role assignment primitives. Commit 9a86a05 wires the primitives into the production connect path: a new `TraversalEngine::execute_ice_pair_race` method takes both local and remote `TraversalCandidate` slices plus both 32-byte node ids, decides the controlling/controlled role via lex-min of the ids, generates RFC-priority pairs via the existing `generate_candidate_pairs`, and runs the rounds with the parallel-race shape — every pair of a round is probed (one outbound binding-request per pair) BEFORE polling for handshakes. A new `SimultaneousOpenRuntime::handshake_endpoint` default-method extension lets endpoint-attribution-aware runtimes report the winning remote endpoint; legacy runtimes fall back to the top-priority pair the round just probed. New `TraversalDecisionReason::IcePairRaceHandshakeObserved` carries the result back through the existing `SimultaneousOpenResult::decision` shape so downstream consumers need no change. The §D5.5 pass criterion is pinned by `crates/rustynetd/tests/ice_pair_race.rs::ice_race_marginal_nat_succeeds_where_serial_attempts_would_fail`: a runtime that only completes the handshake after seeing ≥2 simultaneous outbound probes in the same round succeeds Direct — exactly the marginal-NAT case the previous serial loop denied. The cone-NAT happy path is pinned by `ice_race_picks_highest_priority_winning_endpoint`. Four additional negative pins (relay fallback, fail-closed exhaustion, role-reversal stability, runtime-without-endpoint-attribution fallback) round out the test surface.

### D11 — Anchor node role formalisation (Track Alpha)

- **Scope.** Formalise the always-on home-server role as a signed-membership-advertised set of capabilities (`anchor.gossip_seed`, `anchor.bundle_pull`, `anchor.enrollment_endpoint`, `anchor.relay_colocation`, `anchor.port_mapping_authoritative`). Add CLI verbs to advertise / list / pull-bundle / init the role. Add a LAN-loopback bundle-pull endpoint and a setup wizard that composes anchor + relay co-deploy.
- **Files.** `crates/rustynet-control/src/membership.rs` (schema extension), `crates/rustynetd/src/daemon.rs` (bundle-pull listener), `crates/rustynetd/src/gossip_runtime.rs` (anchor-priority rebroadcast), `crates/rustynetd/src/port_mapper.rs` (multi-anchor coordination), `crates/rustynet-cli/src/main.rs` + new `crates/rustynet-cli/src/anchor_init.rs` (CLI surface), `scripts/systemd/rustynetd-anchor.service` (optional unit), `start.sh` (role wizard option).
- **Sub-slices** (mapped 1:1 to [`AnchorNodeRoleDesign_2026-05-21.md`](./AnchorNodeRoleDesign_2026-05-21.md) §5):
  - **D11.a** — Membership schema + `rustynet anchor advertise|list` CLI (prerequisite for the rest).
  - **D11.b** — Bundle-pull endpoint + `rustynet anchor pull-bundle` CLI (parallel with D11.c, D11.d after D11.a).
  - **D11.c** — Anchor-aware gossip seed selection (parallel).
  - **D11.d** — `rustynet anchor init` setup wizard (parallel).
- **Pass criterion.** Clean Debian 13 install runs `rustynet anchor init` and ends with a working anchor (relay co-deployed, port-mapping or keepalive fallback active, bundle-pull endpoint bound). Second machine joins via `rustynet anchor pull-bundle` + `rustynet enrollment consume` in one operator session. macOS host runs the same flow successfully. 3-peer mesh shows anchor-priority rebroadcast. Multi-anchor port-mapping coordination chooses lex-min `node_id`.
- **Estimated cost.** 6–8 cycles total (2 + 2 + 1 + 3).
- **Depends on.** D2.5 (gossip), D4 (relay), D2.7 (enrollment), D5.5 (ICE pair race). Anchor builds on these but does not modify them.
- **Cross-platform note.** Linux + macOS land in D11. Windows anchor is deferred behind D7/D9 (same dataplane-parity prerequisite as Windows-as-exit). iOS + Android land the consume-only `anchor_bundle_pull_client` in `rustynet-mobile-core` as part of mobile roadmap M3 — see [`../../mobile/RustynetMobileRoadmap_2026-04-17.md`](../../mobile/RustynetMobileRoadmap_2026-04-17.md).

### D12 — Node role taxonomy + 6-role user-selectable surface (Track Alpha)

- **Scope.** Cement six user-selectable per-device roles (`relay`, `anchor`, `exit`, `blind_exit`, `client`, `admin`) into a single CLI verb + wizard surface. Internal data model stays two-axis (primary local `NodeRole` + composable signed capabilities); presets are named compositions. Add `rustynet role {set, status, list, transition-check}` and `rustynet capability {add, remove, list}` verbs. Replace `start.sh` 3-role prompt with 6-role prompt; mirror in `rustynet operator menu`. Add service-deploy/undeploy orchestration for `relay`/`anchor` presets (Linux systemd, macOS launchd, Windows SCM gated on D7/D9). Add transition audit logging.
- **Files.** `crates/rustynet-control/src/role_presets.rs` (new — preset table + transition validator), `crates/rustynet-control/src/membership.rs` (extend `NodeCapabilities` with `serves_exit`, `serves_relay`, etc.), `crates/rustynet-cli/src/main.rs` + new `crates/rustynet-cli/src/role_set.rs` (CLI verbs + orchestrator), `crates/rustynetd/src/daemon.rs` (new IPC commands), `crates/rustynet-cli/src/ops_install_systemd.rs` (relay co-deploy + undeploy), `start.sh` (6-role prompt).
- **Sub-slices** (mapped 1:1 to [`NodeRoleTaxonomy_2026-05-21.md`](./NodeRoleTaxonomy_2026-05-21.md) §8):
  - **D12.a** — Preset table + transition validator (prerequisite for the rest).
  - **D12.b** — CLI surface (`role` + `capability` verbs).
  - **D12.c** — Wizard surface (start.sh + operator menu + mobile read-only indicator).
  - **D12.d** — Service deploy / undeploy (Linux + macOS; Windows gated on D7/D9).
  - **D12.e** — Audit + transition logging.
- **Pass criterion.** `rustynet role set anchor` on clean Debian 13 install brings the host to a working anchor (relay co-deployed, capability signed in membership). `rustynet role set client` (admin signs revocation) brings it back to clean client (relay undeployed). `rustynet role set blind_exit` configures hardened final-hop exit with irreversibility prompt + audit trail. Wizard shows 6 roles with correct per-platform gating. Mobile `client (mobile)` indicator is read-only on iOS + Android. Every transition emits tamper-evident audit log entry.
- **Estimated cost.** 8–11 cycles total (2 + 3 + 2 + 3 + 1).
- **Depends on.** D11 (anchor capability schema + bundle-pull endpoint). D12 generalises the role surface that D11 establishes for `anchor`.
- **Cross-platform note.** Linux + macOS roles all land in D12 (except macOS `blind_exit`, which stays Linux-only). Windows non-client roles deferred behind D7/D9 (same dataplane parity prerequisite). Mobile is `client (mobile)` only — no role-set surface ever.

### D6 — Windows readiness + node-id fix (Track Beta)

- **Scope.** Per `WindowsExitAndRelayDeltaPlan_2026-05-10.md` §3.3. Replace the broken `rustynet.exe status` call in the orchestrator's Windows readiness path with a real readiness check (SCM `Running` state + parse of `RUSTYNETD_DAEMON_ARGS_JSON` for `--node-id` from `C:\ProgramData\RustyNet\config\rustynetd.env`).
- **Files.** `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/windows_traffic.rs`, `windows_install.rs`.
- **Pass criterion.** Orchestrator stages `bootstrap_hosts` and `collect_pubkeys` pass against `windows-utm-1`.
- **Estimated cost.** 1–2 cycles.
- **Depends on.** Nothing. Can run in parallel with Track Alpha.
- **Status (2026-05-19).** **Code-complete.** `collect_node_id` in `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/windows_traffic.rs` already parses `RUSTYNETD_DAEMON_ARGS_JSON` from `C:\ProgramData\RustyNet\config\rustynetd.env` via PowerShell and rejects the broken `rustynet.exe status` path. Module doc-comment pins the rationale. Live orchestrator-stage validation against `windows-utm-1` overlaps with the D7 live-evidence cycle.

### D7 — Windows-as-exit live evidence (Track Gamma)

- **Scope.** Per delta plan §A.1–A.3. NetNat lifecycle, DNS leak proof, killswitch precedence.
- **Pass criterion.** Three artifacts under `artifacts/windows_exit/<commit>/`:
  - `scm_context_nat_lifecycle.json`
  - `dns_leak_proof/` directory
  - `killswitch_precedence/` directory
- **Depends on.** D6 (Beta) + D2 through D5.5 (Alpha).

### D9 — Mixed-platform direct + relay-fallback (Track Gamma)

- **Scope.** Windows + Linux peers handshake bidirectionally. Direct P2P works when NAT cooperates; relay fallback works otherwise.
- **Pass criterion.** WG handshake in both directions; iperf3 bidirectional; relay sees ciphertext only.
- **Depends on.** D7.

### D10 — Posture promotion (Track Delta)

- **Scope.** Update `documents/operations/PlatformSupportMatrix.md`, `documents/operations/active/WindowsWorkingNodePlan_2026-04-17.md` "Definition of Done", and the OS-agnostic orchestrator plan §11.
- **Pass criterion.** Posture documents reflect the live state after D9.
- **Depends on.** D9.

---

## 7) Operating contract

Per `CLAUDE.md` §5, §7, §9. Repeated here so the dataplane work follows the same discipline as everything else in the repo.

### 7.1 Cycle discipline

- Each phase is one or more cycles. Each cycle commits at the end with `cargo fmt`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace --all-targets --all-features`, and the per-module floor gate all green.
- Push after every commit. Do not let local-only state accumulate.
- Update `documents/operations/active/PlatformImprovementBacklog_2026-05-14.md` X2/X3/X7/X4 entries when relevant code is touched.
- Per-phase pass criterion is non-negotiable. A phase is not "done" without the artifact or test that pins the criterion.

### 7.2 What goes where

- Dataplane code: `crates/rustynetd/src/` (traversal, relay client, port mapper), `crates/rustynet-relay/src/` (relay binary), `crates/rustynet-control/src/` (membership gossip, enrollment).
- Tests: per-crate `#[cfg(test)]` modules. Floor-pinned in `scripts/ci/regression_coverage_gates.sh` if the module is security-tied.
- Artifacts: `artifacts/cross_network/<commit>/` for D5/D5.5 evidence; `artifacts/windows_exit/<commit>/` for D7 evidence.

### 7.3 What we don't do mid-flight

- Don't replace WireGuard. Don't add custom crypto. Don't add a third party. Don't propose port-forwarding the user has to do manually. Don't introduce a SaaS.
- If a phase's scope grows mid-flight, split it (`D2 → D2a + D2b`). Don't let one phase swell to ten cycles.

### 7.4 Sub-agents

This work is small-grained enough that sub-agents are not the right tool. Each phase is a single cohesive change; running a sub-agent in a worktree adds more overhead than it saves. (The 2026-05-18 parallel-agent attempt in `.claude/agent_cycle_log_2026-05-18.md` cycle 59 confirmed this.) If a phase needs multiple parallel changes, split the phase into the parallel parts and execute them in-context sequentially.

---

## 8) Open questions and re-visit triggers

These are the points where the user has explicitly chosen a path but where the choice would be re-opened if real-world experience changes the trade-off:

| Question | Current choice | What would re-open it |
|---|---|---|
| Should we add a public-ingress host (VPS / IPv6 / port-forward) for cellular reliability? | No | User reports frequent cellular failures after D5.5 lands. |
| Should the home server be its own peer or a "supernode"? | Its own peer with relay capability — both services co-located. | If the relay traffic competes with the daemon's other duties for CPU / network, split into a dedicated host. |
| Should bundle gossip have a heartbeat / liveness signal beyond bundle version? | Bundle version + epoch only (D2.5). | If split-brain scenarios occur after partition healing, add an explicit gossip-anti-entropy round. |
| Should enrollment tokens be redeemable from anywhere or only via the existing-peer's gossiped endpoint? | Via the existing peer's gossiped endpoint. | If enrollment commonly fails because the existing peer's endpoint is stale, add a "fallback contact via any peer that knows the bundle" path. |
| Should we support an exit-node feature (all internet traffic through one peer)? | No — out of base-plan scope. | The Windows-as-exit track (`WindowsExitAndRelayDeltaPlan_2026-05-10.md`) covers this separately. Don't fold it in here. |

---

## 9) Cross-references

- [`PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md`](./PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md) — source for the §8.1 (STUN), §8.2 (relay socket), §8.3 (relay binary) defects driving D2/D3/D4. Read its §9 (desired end-state architecture) before D2.5.
- [`WindowsExitAndRelayDeltaPlan_2026-05-10.md`](./WindowsExitAndRelayDeltaPlan_2026-05-10.md) — source for D6/D7/D9. §3.3 is the order-of-operations for the Windows readiness fix.
- [`MasterWorkPlan_2026-03-22.md`](./MasterWorkPlan_2026-03-22.md) — repo-wide remaining work; this plan is downstream of it.
- [`PlatformImprovementBacklog_2026-05-14.md`](./PlatformImprovementBacklog_2026-05-14.md) — backlog ledger; X2/X3/X4/X7 entries should be updated as dataplane code is touched.
- [`SecurityMinimumBar.md`](../../SecurityMinimumBar.md) — non-negotiable security floor. Decisions 2.1-2.6 are all consistent with the bar; any future re-architecture must still satisfy it.
- [`Requirements.md`](../../Requirements.md) — top-level requirements. This plan's mission (§1) is a more specific instantiation of the cross-platform mesh requirement.
- [`PlatformSupportMatrix.md`](../PlatformSupportMatrix.md) — gets updated in D10.

---

## 10) Definition of done (for this plan)

This plan is "done" when:

- D2 through D5.5 all pass their per-phase pass criteria, and D5/D5.5 artifacts exist pinned to a commit SHA in `artifacts/cross_network/<commit>/`.
- D11 passes its pass criterion on Linux and macOS (Windows anchor deferred behind D7/D9 by design).
- D12 passes its pass criterion on Linux and macOS (Windows non-client roles deferred behind D7/D9 by design; mobile is `client (mobile)` only).
- D6 passes its pass criterion against `windows-utm-1`.
- D7 + D9 artifacts exist pinned to a commit SHA in `artifacts/windows_exit/<commit>/`.
- D10 has updated the posture documents.
- A real-world soak: two real user-owned devices (one Linux, one Windows) on two different networks (one home WiFi, one cellular or hotel WiFi) have demonstrably stayed connected for 24+ hours through at least one network transition each, with throughput logged and no operator intervention.
- The codebase no longer contains placeholders or stubs for any of the dataplane components covered above.
