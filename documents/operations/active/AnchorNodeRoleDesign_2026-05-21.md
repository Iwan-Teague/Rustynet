# Rustynet Anchor Node Role Design

- Date: 2026-05-21
- Status: active (design source-of-truth for the anchor-node role)
- Owner: Rustynet
- Parent doc: [`NodeRoleTaxonomy_2026-05-21.md`](./NodeRoleTaxonomy_2026-05-21.md) — anchor is one of the six user-selectable node-role presets cemented in the taxonomy doc. This document is the deep dive for the `anchor` preset specifically.
- Supersedes nothing. Complements [`RustynetDataplaneExecutionPlan_2026-05-18.md`](./RustynetDataplaneExecutionPlan_2026-05-18.md) §2.3 (relay) and §2.4 (enrollment) by formalising the runtime role that ties them together. Adds D11 to the dataplane phase queue (§7 here).

---

## 0) Purpose of this document

This document defines the **anchor node** role: what it is, what it is not, why we add it, and exactly what needs to change across the codebase and platforms to ship it. It exists because the existing operational pattern of "one always-on home server that holds relay + enrollment + gossip seed responsibilities" is implicit and scattered today. Formalising it gives:

- a single capability flag in signed membership state ("this peer is an anchor"),
- a deterministic bootstrap target for new devices (no more "you have to know where the relay lives" tribal knowledge),
- a co-deployment surface that bundles relay + bundle-pull + enrollment endpoint + gossip seed in one well-understood role,
- a clear boundary for what does NOT change — anchor does **not** centralise trust, does **not** gate gossip, does **not** become a SaaS coordination server.

If a later document or commit conflicts with this design, this document is the source of truth for the anchor role until it is explicitly superseded by a new dated plan.

---

## 1) Why "anchor" and not "hub" / "coordinator" / "supernode"

| Candidate | Rejected because |
|---|---|
| **Hub** | Connotes traffic-pivot. Relay already pivots traffic, separately. "Hub" overstates the anchor's runtime role and understates the relay's. |
| **Coordinator** | SaaS-flavoured. Implies central authority. Anchor has no privileged trust position — every peer still verifies signatures independently. |
| **Supernode** | Skype/Bitcoin-era term. Implies privileged routing. Anchor does not route differently from any other peer; it just has higher uptime + a stable LAN endpoint. |
| **Home node** | Existing informal term. Too vague — does not name what the role *does*. |
| **Issuer node** | Too narrow. Only describes the bundle-mint role. Conflates with the offline admin signing root. |

**Anchor** = a stable peer that other peers orient around. Not authoritative, not privileged, just structurally reliable. Multiple anchors are supported (no SPOF). Anchors can come and go without breaking the mesh.

---

## 2) Role definition

An **anchor node** is a `rustynetd` instance that is marked, in signed membership state, as carrying one or more of the following capabilities:

| Capability | What it provides |
|---|---|
| `anchor.gossip_seed` | Stable bootstrap target for gossip — other peers prefer it as a re-broadcast destination during initial sync and after long offline periods. Lower jitter on re-broadcast. |
| `anchor.bundle_pull` | Exposes a token-gated LAN-loopback endpoint that serves the current signed membership bundle, so new devices can pull a fresh copy at enrollment time instead of waiting for gossip to converge. |
| `anchor.enrollment_endpoint` | Exposes a token-gated LAN-loopback endpoint that accepts `EnrollmentConsume` requests from new devices on the same LAN (or, optionally, from any peer with a valid token). |
| `anchor.relay_colocation` | Indicates `rustynet-relay` runs on the same host. Other peers learn relay reachability from this flag rather than from a separate config file. |
| `anchor.port_mapping_authoritative` | Indicates this anchor has a stable LAN/router boundary and is allowed to host the uPnP/PCP/NAT-PMP lease (one lease per LAN — multiple anchors on the same LAN coordinate via signed precedence rather than racing). |

These capabilities are **independent**. An anchor MAY hold any subset. A typical home deployment co-locates all five on one box; a multi-anchor deployment splits them.

**Anchor is orthogonal to `NodeRole`.** The existing `NodeRole` (`Admin` / `Client` / `BlindExit` in `crates/rustynetd/src/daemon.rs:960`) is about *local CLI permissions and dataplane posture*. Anchor is about *mesh-level capabilities* and lives in the signed membership bundle, not in local config. Practically:

- A home-server is typically `NodeRole::Admin` + anchor (all five capabilities).
- A laptop is typically `NodeRole::Client` and not an anchor.
- A `NodeRole::BlindExit` host is typically not an anchor (anchor capabilities require LAN-exposed endpoints; blind-exit is hardened against any local-control surface beyond its exit-serving duty).

Nothing prevents a `NodeRole::Client` peer from being a `anchor.gossip_seed` if the operator deliberately configures it. The orthogonality is by design.

---

## 3) Anchor vs the four other roles in Rustynet

Read this table once. Then never confuse them again.

| Role | What it is | Trust position | Lifetime | Holds keys? | Forwards traffic? |
|---|---|---|---|---|---|
| **Membership owner** (offline admin) | The human + the encrypted signing key under their custody | Root of trust | Indefinite (ideally cold) | Yes — the *only* place the membership-root private key lives | No |
| **Anchor node** | A 24/7 `rustynetd` with `anchor.*` capabilities advertised in signed membership state | Same as any other peer — verifies signatures, no privileged auth | As long as it stays up; lose it, mesh keeps working | Yes — its own peer identity key (Ed25519/Curve25519), nothing else | Through normal WireGuard pair forwarding only |
| **Relay process** (`rustynet-relay`) | A separate binary that forwards encrypted UDP between peer pairs that cannot direct-connect | Untrusted for traffic confidentiality (forwards ciphertext only) | Per-session forwarding state | Its own ciphertext-forwarding token signing key (per-session, short-lived) | Yes — opaque ciphertext only |
| **Exit node** | A `rustynetd` with `serving_exit_node=true` in policy | Same as any other peer; **decrypts** traffic and re-emits to internet (or LAN) | As long as it's running | Yes — its own peer key | Yes — decrypted internet egress traffic |
| **Admin CLI session** | `rustynet` invocations against the local IPC socket; gated by `NodeRole::Admin` | Operates within the running daemon's already-established trust state | Per command | No — operates on existing trust state | No |

**Critical confusion to avoid:** anchor ≠ relay. The relay co-locates with the anchor by *convention*, but they are separate processes with separate sockets and separate trust shapes. An anchor without relay (`anchor.relay_colocation=false`) is valid: it just means the relay lives on a different peer.

---

## 4) What already exists in code (no new code needed)

Most plumbing is already in tree. The anchor role mostly *labels* and *composes* it.

| Capability | Existing code | Notes |
|---|---|---|
| Gossip seed behaviour | `crates/rustynetd/src/peer_gossip.rs`, `crates/rustynetd/src/gossip_runtime.rs`, `crates/rustynetd/src/gossip_transport.rs` | Every peer already rebroadcasts. Anchor just gets priority-seed treatment in the bootstrap path. |
| Bundle mint + sign | `crates/rustynet-control/src/membership.rs` (`apply_signed_update`, `preview_next_state`), `crates/rustynet-control/src/enrollment.rs` (`build_add_node_record_for_enrollee`) | Already production. Anchor does not change signing; it changes *where* the signature happens to be invoked. |
| Enrollment token mint / verify / consume | `crates/rustynetd/src/enrollment_token.rs`, `crates/rustynetd/src/enrollment_consume.rs`, `rustynet enrollment {mint,verify,consume,admit}` CLI verbs | D2.7 landed end-to-end. Anchor adds: an enrollment-redemption endpoint on a LAN-loopback socket (the IPC path already exists; just needs LAN exposure gated by token). |
| Relay binary | `crates/rustynet-relay/src/{main,transport,session,rate_limit}.rs` (3500+ lines, D4) | Already production. Anchor co-deploys it; no change to the relay code. |
| Port-mapping (uPnP / NAT-PMP / PCP) | `crates/rustynetd/src/port_mapper.rs` (D2.3) | Already production. Anchor takes lease ownership; multi-anchor coordination is the only new piece. |
| Signed membership bundle wire format | `crates/rustynet-control/src/membership.rs` | Already production. Anchor adds a new optional `node_capabilities` field per node entry. |
| NodeRole (orthogonal local role) | `crates/rustynetd/src/daemon.rs:960` | Untouched. Anchor capabilities live in membership, not in local NodeRole. |
| STUN srflx discovery | `crates/rustynetd/src/stun_client.rs`, `crates/rustynetd/src/dataplane_candidates.rs` (D2, D2.4) | Already production. Anchor does the same STUN refresh as any other peer. |
| Keep-alive to keep NAT mapping open | WireGuard `PersistentKeepalive=25` on every peer | Already production. Anchor is just the peer that benefits most from it (because remote peers find it via gossiped srflx). |

**Bottom line:** zero new crates. The anchor role is a thin layer on top of existing primitives.

---

## 5) What needs building

Concrete code-level work, split into four tracks. Each track stands alone; they can land in parallel.

### 5.1 Track A — Membership schema + signed advertisement

| File | Change |
|---|---|
| `crates/rustynet-control/src/membership.rs` | Add `NodeCapabilities { anchor_gossip_seed: bool, anchor_bundle_pull: bool, anchor_enrollment_endpoint: bool, anchor_relay_colocation: bool, anchor_port_mapping_authoritative: bool }` struct as an optional field on each node entry. Optional = legacy bundles missing the field continue to validate; only newer bundles carry it. |
| `crates/rustynet-control/src/membership.rs` | Extend the canonical-payload pre-image to include `node_capabilities` after existing fields (append-only — never reshuffle). |
| `crates/rustynet-control/src/membership.rs` | Tests: round-trip a bundle with capabilities; reject a bundle where capabilities-field tampering invalidates the signature. |
| `crates/rustynet-cli/src/main.rs` | New CLI subcommand: `rustynet anchor advertise --capabilities gossip_seed,bundle_pull,enrollment_endpoint,relay_colocation,port_mapping_authoritative` produces an unsigned MembershipUpdateRecord (uses `preview_next_state` like the enrollment-admit verb does). |
| `crates/rustynet-cli/src/main.rs` | New CLI subcommand: `rustynet anchor list` parses the local signed membership snapshot and prints all anchors + their capabilities. Available to `NodeRole::Client` (read-only) and `NodeRole::Admin`. |

Pass criterion: a 3-peer mesh where peer A advertises `anchor.gossip_seed` and the other two peers reload the bundle, both see A as an anchor, and `rustynet anchor list` on all three matches.

Estimated cost: 2 cycles.

### 5.2 Track B — Bundle-pull endpoint

| File | Change |
|---|---|
| `crates/rustynetd/src/daemon.rs` | New optional listener: when `anchor.bundle_pull` is advertised, bind a token-gated LAN-loopback socket (`127.0.0.1:51822` default, configurable) that serves the current signed membership bundle over a minimal request/response (binary, no HTTP — same wire format as gossip but pull-shaped). Anchor authenticates the requester via an enrollment-token signature (single-use, TTL-bounded). |
| `crates/rustynetd/src/daemon.rs` | New flag: `--anchor-bundle-pull-bind 127.0.0.1:51822`, `--anchor-bundle-pull-disable`. Default bound to loopback only; explicit LAN-IP bind requires an additional `--anchor-bundle-pull-lan-bind` argument with documented operator acknowledgement. |
| `crates/rustynet-cli/src/main.rs` | New CLI verb: `rustynet anchor pull-bundle --anchor-endpoint <ip:port> --token <enrollment-token>` for new-device first-time pull. |
| `scripts/systemd/rustynetd.service` | New env entries: `RUSTYNET_ANCHOR_BUNDLE_PULL_BIND`, `RUSTYNET_ANCHOR_BUNDLE_PULL_DISABLE`. |

Pass criterion: integration test — anchor A is up; new device N has the membership owner public key but no bundle; N runs `rustynet anchor pull-bundle` with a valid token; N obtains the bundle, verifies it against the public key, and joins gossip.

Estimated cost: 2 cycles.

### 5.3 Track C — Anchor-aware gossip seed selection

| File | Change |
|---|---|
| `crates/rustynetd/src/gossip_runtime.rs` | When constructing the rebroadcast set on local mint, prefer anchors (capability `gossip_seed`) for the first wave; remaining peers picked up on the second wave. |
| `crates/rustynetd/src/gossip_runtime.rs` | When *receiving* a bundle that supersedes our current state, prefer pulling from an anchor next time (anti-entropy bias). |
| `crates/rustynetd/src/gossip_runtime.rs` | Tests: with 1 anchor + 4 non-anchors, observe anchor rebroadcasts first; with 0 anchors, fall back to flat rebroadcast (no regression). |

Pass criterion: a 5-peer mesh where the anchor is the only peer with all four others as direct neighbours; mint at the anchor propagates to all four within the existing 3-second budget; remove the anchor; mint at a leaf propagates to all four within 6 seconds (existing two-hop budget).

Estimated cost: 1 cycle.

### 5.4 Track D — `rustynet anchor init` setup wizard

| File | Change |
|---|---|
| `crates/rustynet-cli/src/main.rs` | New CLI verb: `rustynet anchor init --hostname <name> --membership-owner-key-out <path> [--co-deploy-relay] [--co-deploy-enrollment-endpoint] [--co-deploy-port-mapping]`. |
| `crates/rustynet-cli/src/anchor_init.rs` (new) | Orchestrator: generate membership owner key (or detect existing), generate node identity, generate first bundle marking this node with selected capabilities, write systemd / launchd / SCM unit files, install `rustynet-relay` if `--co-deploy-relay`, print operator instructions for token mint. |
| `scripts/systemd/rustynetd-anchor.service` (new) | Optional alternative unit that loads anchor env file + relay co-deploy hooks. |
| `start.sh` | New top-level option in the role-selection wizard: `anchor` joins `admin` / `client` / `blind_exit`. Maps to `NodeRole::Admin` + anchor capabilities by default. |

Pass criterion: a clean Debian 13 install runs `rustynet anchor init` and at the end of the wizard has: signed membership bundle in canonical custody, `rustynetd` running with `anchor.*` advertised, `rustynet-relay` running, port-mapping lease either granted or in keepalive fallback, ready to accept enrollment tokens. New-device join is a one-liner from another machine on the same LAN.

Estimated cost: 3 cycles.

---

## 6) Per-platform implementation requirements

The anchor role has different platform completeness depending on whether the platform can *host* an anchor or only *consume* anchor services. iOS and Android are consumer-only by OS constraint; the rest can host.

### 6.1 Linux (anchor-eligible — primary host platform)

**Hosts every anchor capability.**

Existing path that needs anchor wiring:

- `rustynetd` already runs as `systemd` service per `scripts/systemd/rustynetd.service`; new optional service `rustynetd-anchor.service` (Track D) layers anchor env on top.
- `rustynet-relay` already builds and runs on Linux (D4 complete); anchor co-deploys it by adding a `rustynet-relay.service` unit.
- Port-mapping (D2.3) already runs on Linux; multi-anchor coordination logic added in Track A.
- Bundle-pull endpoint (Track B) uses standard async UDP; no Linux-specific work.
- Anchor advertise via `rustynet anchor advertise` reuses the same signing path as `rustynet assignment issue` (already Linux-tested end-to-end).

Refactor needs on Linux:

- `scripts/systemd/install_rustynetd_service.sh` (which is already a thin wrapper to `rustynet ops install-systemd`) extended to install `rustynet-relay.service` when anchor co-deploys it. **No new shell logic** — extend the existing Rust ops command.
- nftables ruleset emitter (`crates/rustynetd/src/linux_runtime_nftables.rs`, L2 evaluator) extended with anchor-specific table for: LAN-loopback bundle-pull port (default deny inbound from non-loopback unless explicitly LAN-bound), gossip port reachability.
- `documents/operations/RustynetdServiceHardening.md` runbook section: anchor-mode service hardening — same systemd hardening flags as the regular daemon, plus capability advertisement is local-config-only (cannot self-promote into the signed bundle).

### 6.2 macOS (anchor-eligible — secondary host platform)

**Hosts every anchor capability.** Userspace WireGuard (`wireguard-go`) + privileged-helper mediation works the same for an anchor as for a regular peer.

Existing path that needs anchor wiring:

- `launchctl bootstrap` lifecycle (`MacosLaunchdServiceManagement.md`) extended to a `rustynetd-anchor.plist` variant that pre-loads anchor env.
- `rustynet-relay` needs to be built for macOS as part of the relay-co-deploy track (it currently builds; verify dataplane parity in D7-style live evidence cycle).
- Port-mapping detection on macOS already uses `route -n get default` (D2.3); no extra work.
- Bundle-pull endpoint binds the same way on macOS as Linux.
- PF anchor pruning (`documents/operations/PlatformSupportMatrix.md` macOS row) extended to prune anchor-specific PF anchors on dataplane apply.

Refactor needs on macOS:

- macOS keychain custody (`rustynet.wg_passphrase`) extended to a separate `rustynet.anchor_enrollment_secret` keychain item for the enrollment-endpoint HMAC secret (so anchor secrets do not co-mingle with passphrase custody).
- `start.sh` host-profile checks (`HOST_PROFILE=macos`) extended to accept anchor role under the macOS compatibility runtime, with anchor bundle-pull endpoint bound to user-scoped paths (`~/Library/Application Support/Rustynet/`).

### 6.3 Windows (anchor-eligible — tertiary host platform; tracks Windows readiness)

**Hosts every anchor capability once Windows reaches dataplane parity.** Currently Windows is `runtime-host-capable only` per `PlatformSupportMatrix.md`; anchor-mode on Windows depends on `windows-wireguard-nt` reaching live-evidence parity (D7/D9 in the dataplane plan).

Existing path that needs anchor wiring (gated behind D7):

- Windows service (`rustynetd --windows-service --env-file`) extended with anchor env file: `RUSTYNET_ANCHOR_*` plumbed through the SCM-managed env in `C:\ProgramData\RustyNet\config\rustynetd.env`.
- `rustynet-relay` already builds for Windows with the `daemon` feature (SCM lifecycle landed in D4); anchor co-deploys `rustynet-relay.exe` as a separate Windows service.
- Port-mapping: `port_mapper.rs` Windows gateway detection is currently stubbed; anchor on Windows needs that completed or falls back to keepalive-only (acceptable, behaviour matches Linux when no router supports the protocols).
- Bundle-pull endpoint binds the same way; Win32 socket bind via standard Rust `std::net`. No extra Win32 FFI.
- Windows registry ACL collector (W4, implemented) extended to verify `HKLM\Software\Rustynet\Anchor` keys (if used) are SYSTEM/Administrators-only.

Refactor needs on Windows:

- DPAPI-protected `.dpapi` blob path under `C:\ProgramData\RustyNet\secrets\` extended to anchor enrollment secret (`anchor_enrollment_secret.dpapi`) and anchor bundle-pull access list (`anchor_bundle_pull_acl.dpapi`).
- Windows install helper (`scripts/bootstrap/windows/`) extended with `Install-RustyNetAnchorRole.ps1` that installs both `rustynetd` and `rustynet-relay` services.
- `WindowsWorkingNodePlan_2026-04-17.md` Definition of Done extended with anchor-mode live evidence (parallel work to Windows-as-exit and Windows-as-peer evidence cycles).

### 6.4 iOS (anchor-bootstrap-client only — cannot host)

**Cannot host any anchor capability.** OS constraints:

- App lifecycle: iOS suspends `NEPacketTunnelProvider` aggressively; no 24/7 availability.
- No stable address: cellular + Wi-Fi handoffs change IP frequently.
- No background socket bind: iOS does not permit foreground/background bind on arbitrary ports.
- Sandboxed file paths: cannot host LAN-exposed endpoints.

**Consumes anchor services:**

- Enrollment flow: iOS client receives an enrollment token out-of-band (QR code, paste, MDM). At first launch it contacts the configured anchor's bundle-pull endpoint over the LAN (when on home Wi-Fi) or via the anchor's gossiped public endpoint (when remote).
- Subsequent operation: iOS client gossips with anchors preferentially, falls back to other peers if anchors are unreachable.
- Mobile crate split per `RustynetMobileArchitectureDesign_2026-04-17.md`: `rustynet-mobile-core` carries the bundle-pull client logic (no change to mobile FFI; reuses the same signed-bundle verification path).

Refactor needs on iOS:

- `rustynet-mobile-core` adds an `anchor_bundle_pull_client` module that mirrors the `rustynet anchor pull-bundle` CLI verb, callable from FFI.
- Mobile roadmap M3 (shared client capability baseline) extended with anchor-bootstrap as a first-class enrollment path. M3 already covers enrollment; anchor-bundle-pull is the LAN-fast-path inside M3.
- iOS `NEPacketTunnelProvider` UI presents anchor-list (read-only) so the user can see which peers are anchors and prefer them when choosing initial contact.

### 6.5 Android (anchor-bootstrap-client only — cannot host)

**Same constraint shape as iOS.** Android *technically* permits more (foreground service, more relaxed background sockets), but in practice:

- Doze + App Standby kill long-running services on consumer Android.
- Network changes (Wi-Fi → cellular) trigger `VpnService.Builder` reinitialisation.
- Not "always on" reliably enough to anchor a mesh.

**Consumes anchor services:** same as iOS.

Refactor needs on Android:

- `rustynet-mobile-core` (shared with iOS) — same `anchor_bundle_pull_client` module.
- Kotlin shell layer surfaces "Anchor endpoint" in the connection-state UI (read-only, no admin actions).
- Mobile roadmap M3 includes anchor-bootstrap as the LAN-fast-path; M4 (hardening) validates anchor-bootstrap reconnect after long doze periods.

---

## 7) Insertion into the dataplane execution plan

Add **D11 — Anchor node role formalisation** to `RustynetDataplaneExecutionPlan_2026-05-18.md` §5.1 (Track Alpha) immediately after D5.5. D11 has four slices that map 1:1 to §5 of this document:

- **D11.a** — Membership schema + advertise CLI (§5.1 here)
- **D11.b** — Bundle-pull endpoint (§5.2 here)
- **D11.c** — Anchor-aware gossip seed selection (§5.3 here)
- **D11.d** — `rustynet anchor init` setup wizard (§5.4 here)

D11.a is a prerequisite for D11.b/c/d. The remaining three can run in parallel.

D11 sits ahead of D7/D9 because anchor-bundle-pull is a useful enrollment fast-path before Windows live evidence; nothing in D7/D9 depends on D11.

---

## 8) Security controls

Each anchor capability has an enforcement point + a verification method.

| Control | Enforcement | Verification |
|---|---|---|
| Anchor capabilities require valid signature | `apply_signed_update` in `crates/rustynet-control/src/membership.rs` rejects unsigned/invalid bundles regardless of capabilities field | Unit test: tampered `node_capabilities` invalidates the signature → reducer rejects |
| Bundle-pull endpoint requires valid enrollment token | Same token-verify path as `enrollment_consume.rs`; single-use ledger pinned across bundle-pull + enrollment-consume so a token cannot be used for both | Integration test: replay-consumed token against bundle-pull → reject |
| Bundle-pull endpoint default-deny non-loopback | `--anchor-bundle-pull-bind` defaults to `127.0.0.1:51822`; LAN bind requires explicit `--anchor-bundle-pull-lan-bind` with documented operator ack | Unit test: default config + LAN packet → drop; explicit LAN bind + LAN packet + valid token → accept |
| Anchor advertisement is local-config-only | Local CLI cannot self-promote into signed bundle; only the membership owner signing key can mint a bundle that includes anchor capabilities | Test: `rustynet anchor advertise` produces only an unsigned record; signing requires `--signing-secret` to the owner key |
| Anchor secret custody on Linux | systemd `LoadCredentialEncrypted` (or `/etc/rustynet/credentials/anchor_enrollment_secret.cred`); persistent plaintext rejected | Startup permission check refuses to start if the secret file is world-readable |
| Anchor secret custody on macOS | Keychain item `rustynet.anchor_enrollment_secret`; persistent plaintext rejected by startup preflight | Same preflight that already validates `rustynet.wg_passphrase` |
| Anchor secret custody on Windows | DPAPI-protected `.dpapi` blob under `C:\ProgramData\RustyNet\secrets\`; plaintext rejected by W4 verifier | W4 verifier already covers `secrets\` ACLs; extend to include anchor secret |
| Multi-anchor port-mapping coordination | Anchors with `port_mapping_authoritative=true` use signed precedence (lex-min node_id wins) rather than racing the router | Integration test: two anchors on the same simulated LAN — only the lex-min one requests the lease |
| Anchor logs never contain PII | Bundle-pull request logging records only token thumbprint (not the token) + duration; no peer-identifier logging beyond what gossip already does | `documents/operations/SecretRedactionCoverage.md` extended to cover anchor surfaces; redaction test in `crates/rustynetd/src/peer_gossip.rs` extended to anchor-bundle-pull |
| Anchor downgrade is fail-closed | A peer that previously saw anchor capabilities advertised cannot accept a newer bundle that *removes* anchors without a higher epoch; signed-state replay is rejected as today | Existing membership replay-watermark tests cover this; verify the anchor-capabilities field is included in the canonical payload |
| Anchor is not a trust authority | Verifier modules in `rustynet-control` do not consult anchor flags before validating signatures — anchor is metadata, not authority | Code review: search for `anchor` references in `crates/rustynet-control/src/membership.rs`; none may gate signature verification |

---

## 9) Refactor inventory

What gets touched that already exists, separated from net-new code.

| File | Change category | Reason |
|---|---|---|
| `crates/rustynet-control/src/membership.rs` | Schema extension (append-only) | Add `node_capabilities` field; preserve legacy-bundle compat |
| `crates/rustynetd/src/daemon.rs` | Add optional listener | Bundle-pull endpoint bind + lifecycle |
| `crates/rustynetd/src/gossip_runtime.rs` | Behavioural extension | Anchor-priority rebroadcast |
| `crates/rustynetd/src/port_mapper.rs` | Behavioural extension | Multi-anchor lease coordination |
| `crates/rustynetd/src/linux_runtime_nftables.rs` | Ruleset extension | Anchor bundle-pull port rules |
| `crates/rustynet-cli/src/main.rs` | Five new subcommands | `anchor advertise`, `anchor list`, `anchor pull-bundle`, `anchor init`, `anchor status` |
| `crates/rustynet-cli/src/anchor_init.rs` | New module | Wizard orchestrator |
| `scripts/systemd/rustynetd.service` | Env entries | `RUSTYNET_ANCHOR_*` |
| `scripts/systemd/rustynetd-anchor.service` | New unit | Optional alternative |
| `scripts/systemd/install_rustynetd_service.sh` | Wrapper extension | Install relay co-deploy when requested |
| `start.sh` | Wizard option | `anchor` role choice |
| `documents/operations/PlatformSupportMatrix.md` | New row | Anchor capability per platform |
| `documents/operations/RustynetdServiceHardening.md` | New section | Anchor service hardening |
| `documents/operations/SecretRedactionCoverage.md` | New entries | Anchor secret + log surfaces |
| `documents/operations/MacosLaunchdServiceManagement.md` | New section | Anchor `.plist` variant |
| `documents/operations/WindowsWorkingNodeBringUpRunbook.md` | New section | Anchor bring-up walkthrough |
| `documents/operations/active/WindowsExitAndRelayDeltaPlan_2026-05-10.md` | Cross-ref | D11 ↔ Windows live evidence dependency |
| `documents/Requirements.md` §6.1 | New component entry | Anchor node listed alongside `rustynet-control`, `rustynetd`, etc. |
| `documents/SecurityMinimumBar.md` §6.B | Cross-ref to anchor controls | Anchor secret custody + capability signing |
| `documents/mobile/README.md` | Add anchor-consumer note | iOS/Android consume but do not host |
| `documents/mobile/RustynetMobileArchitectureDesign_2026-04-17.md` | Add `anchor_bundle_pull_client` to mobile-core | Mobile-core module list |
| `documents/mobile/RustynetMobileRoadmap_2026-04-17.md` | M3 extension | Anchor-bootstrap fast-path |
| `documents/operations/active/RustynetDataplaneExecutionPlan_2026-05-18.md` | D11 phase | Adds anchor formalisation |

What does NOT get refactored (deliberately preserved):

- **`NodeRole` enum** stays at `Admin / Client / BlindExit`. Anchor is orthogonal.
- **`rustynet-relay` binary** unchanged. Anchor co-deploys it; relay code stays untouched.
- **Signing root + canonical signing flow** unchanged. Anchor advertisement uses the same `--signing-secret` + `--signing-secret-passphrase-file` path as assignment/DNS-zone bundles.
- **Gossip wire format `GOSSIP_BUNDLE_WIRE_VERSION=1`** unchanged. Anchor metadata travels *inside* the membership bundle, which is already gossiped; the gossip wire format is unaware of anchor specifics.
- **Trust verifier modules** unchanged. Anchor flags are never consulted before signature verification.

---

## 10) Gates

Anchor work must pass the standard workspace gates plus three anchor-specific gates.

Standard:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo check --workspace --all-targets --all-features`
- `cargo test --workspace --all-targets --all-features`
- `cargo audit --deny warnings`
- `cargo deny check bans licenses sources advisories`
- `./scripts/ci/membership_gates.sh`

Anchor-specific (new):

- `./scripts/ci/anchor_role_gates.sh` (new) — runs:
  - 3-peer mesh gossip-seed-priority test
  - bundle-pull endpoint integration test
  - multi-anchor port-mapping coordination test
  - cross-platform anchor-bundle-pull-client smoke (Linux + macOS; Windows added when D7 lands)
- `./scripts/ci/anchor_secret_redaction_gates.sh` (new) — verifies no anchor enrollment secret material appears in stdout, structured logs, or systemd journal across all anchor lifecycle operations.
- `./scripts/ci/anchor_downgrade_gates.sh` (new) — verifies a bundle that removes anchor capabilities from a previously-anchored node without a higher epoch is rejected fail-closed by the membership reducer.

---

## 11) Open questions

| Question | Default choice | What would re-open it |
|---|---|---|
| Should the anchor list also be served outside the LAN (e.g. via the relay)? | No. LAN-loopback + LAN-bind only. New devices must first reach the LAN. | If new-device-from-anywhere bootstrap becomes a hard product requirement, add a relay-mediated bundle-pull path (the relay forwards the request as opaque ciphertext, anchor authenticates as today). Defeats some of the LAN-only security simplicity. |
| Should anchors auto-elect a primary when multiple exist? | No. Multi-anchor coordination uses lex-min for port-mapping only. Bundle-pull + enrollment endpoint can run in parallel on every anchor; clients pick any. | If parallel anchors cause user-visible inconsistency (e.g. enrollment-token double-consume races), add a primary-anchor election. Existing single-use ledger should prevent this. |
| Should anchor capabilities be revocable by anyone other than the membership owner? | No. Capability changes require an owner-signed bundle, same as any other membership change. | If an anchor goes rogue and the membership owner is unreachable, currently the only mitigation is `rustynetd` runtime detection (anchor flags it does not trust → it stops gossip-priority-treating it but cannot remove it from the bundle). This matches the existing trust shape and should not change. |
| Should anchor advertise/list be available to `NodeRole::Client`? | Read (`list`, `status`): yes. Write (`advertise`): no. | Matches the existing CLI-role gating. Clients should be able to see which peers are anchors (for diagnosis); only admins can mint new bundles that advertise anchor capabilities. |
| Does mobile *need* to know about anchor capabilities? | Yes — read-only. The UI shows which peers are anchors so the user picks a sensible first-contact target. | Removing this would simplify the mobile crate, but harm UX. The information is already in the signed bundle the mobile client has; surfacing it costs almost nothing. |

---

## 12) Definition of done

The anchor role is "done" when:

- D11.a-d all land on main with passing gates.
- A clean Debian 13 install runs `rustynet anchor init`, ends with a working anchor (relay co-deployed, port-mapping or keepalive fallback active, bundle-pull endpoint bound), and a second machine joins via `rustynet anchor pull-bundle` + `rustynet enrollment consume` in a single operator session.
- A macOS host runs the same anchor init flow successfully (or fails with documented platform-specific deferral if Windows readiness blocks the relay co-deploy).
- `PlatformSupportMatrix.md` has an Anchor row showing the per-platform state honestly.
- Mobile crates (`rustynet-mobile-core`) carry the `anchor_bundle_pull_client` module and a unit test exercising it against a mock anchor.
- `documents/Requirements.md` §6.1 lists the anchor role alongside `rustynet-control`, `rustynetd`, `rustynet`, and `rustynet-relay`.
- `documents/SecurityMinimumBar.md` §6.B cross-references the anchor secret-custody controls.
- This document remains the source-of-truth for the role.

---

## 13) Operational hardening: anchor address stability

An anchor's value is its stability, so the operator should make its address as stable as the design allows. Two cases, two different answers.

**LAN IP (fully solvable — do this).** Give the anchor a **DHCP reservation** on the router (bind its MAC → a fixed LAN IP). A reboot then never changes the LAN address, which:
- keeps any uPnP/NAT-PMP port-forward lease valid (the lease points at an internal IP; if that IP moves, inbound WAN traffic breaks until the `anchor.port_mapping_authoritative` re-lease lands — see §5/D11 and `crates/rustynetd/src/port_mapper.rs`),
- keeps the gossiped LAN-host candidate stable so same-LAN peers and new-device enrollment never miss a beat,
- makes the "stable LAN/router boundary" assumption in §2 literally true.

This is operator-side configuration, not a code change. It removes the LAN variant of the "anchor endpoint changes while offline" trade-off in [`RustynetDataplaneExecutionPlan_2026-05-18.md`](./RustynetDataplaneExecutionPlan_2026-05-18.md) §4 entirely.

**WAN/public IP (not fully solvable in code — by design).** A residential WAN IP can change on ISP lease renewal, and the zero-ingress architecture (§3 of the dataplane plan) forbids the things that would pin it (DDNS-as-dependency, a rendezvous host, contacting the ISP). The mesh already converges automatically when at least one peer is online to receive the re-gathered srflx (the daemon forces an immediate STUN re-gather on a detected local endpoint change — see `maybe_trigger_endpoint_change_refresh` in `crates/rustynetd/src/daemon.rs`). The residual, **inherent** gap is the *all-peers-offline* case: if the WAN IP changes while every peer is offline, a returning remote peer has only a stale endpoint and no live gossip source. Mitigations are architectural, not a patch:
- **Run a second anchor at a different site.** Multiple anchors are first-class (§2 — "multiple anchors are supported, no SPOF"). A remote peer then always has at least one stable-enough gossip source, and the two anchors cross-gossip each other's current endpoints.
- **Relay fallback** covers the transient window for peers that can reach *a* relay but not the moved anchor directly.

Do **not** "fix" the WAN case by adding a fixed hostname / DDNS dependency or a public ingress — that re-opens the §3 non-goals and the §8 open question (public-ingress host), which stays answered "No" until the documented re-visit trigger fires.

---

## 14) Cross-references

- [`NodeRoleTaxonomy_2026-05-21.md`](./NodeRoleTaxonomy_2026-05-21.md) — parent doc. Anchor is one of six user-selectable presets; this document is the deep dive.
- [`RustynetDataplaneExecutionPlan_2026-05-18.md`](./RustynetDataplaneExecutionPlan_2026-05-18.md) — adds D11 in §5.1; anchor builds on D2-D5.5 primitives.
- [`PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md`](./PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md) — anchor co-locates the relay this plan formalises.
- [`MasterWorkPlan_2026-03-22.md`](./MasterWorkPlan_2026-03-22.md) — anchor is downstream of cross-network track; ledger updated when D11 lands.
- [`../PlatformSupportMatrix.md`](../PlatformSupportMatrix.md) — gets anchor row in D11.d.
- [`../RustynetdServiceHardening.md`](../RustynetdServiceHardening.md) — anchor service hardening section.
- [`../MacosLaunchdServiceManagement.md`](../MacosLaunchdServiceManagement.md) — anchor `.plist` variant.
- [`../WindowsWorkingNodeBringUpRunbook.md`](../WindowsWorkingNodeBringUpRunbook.md) — anchor bring-up on Windows once D7/D9 land.
- [`./WindowsExitAndRelayDeltaPlan_2026-05-10.md`](./WindowsExitAndRelayDeltaPlan_2026-05-10.md) — Windows anchor depends on the same dataplane parity work.
- [`../../mobile/RustynetMobileArchitectureDesign_2026-04-17.md`](../../mobile/RustynetMobileArchitectureDesign_2026-04-17.md) — mobile-core extension.
- [`../../mobile/RustynetMobileRoadmap_2026-04-17.md`](../../mobile/RustynetMobileRoadmap_2026-04-17.md) — M3 extension.
- [`../../Requirements.md`](../../Requirements.md) — §6.1 component entry.
- [`../../SecurityMinimumBar.md`](../../SecurityMinimumBar.md) — §6.B cross-ref.
