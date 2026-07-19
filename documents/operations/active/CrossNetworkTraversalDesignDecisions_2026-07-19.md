# Cross-Network Traversal — Design Decisions (2026-07-19)

**Status: DESIGN PROPOSAL / owner-decision framing. No production code written.** Resolves the open
design questions the unified TODO ledger §8 (lines ~449-461) leaves for the four NAT-traversal items,
so they can move from "decide whether to authorize" to a reviewable spec. Companion to
`RustynetDataplaneExecutionPlan_2026-05-18.md` §D14 (which owns the slice IDs D14.a–f, the NAT
vocabulary, and the §3 bans) — that plan is the *what/why*; this doc is the *how would we actually build
it, and which fork does the owner have to pick*.

Two of these (D14.e port-delta prediction, D14.f endpoint mailbox) are **GATED on explicit owner
sign-off** in the dataplane plan and stay gated here — this doc frames the decision with the risk
analysis; it does not greenlight a build. D14.c/D14.d are un-gated but touch production trust-sensitive
daemon paths (STUN discovery, signed gossip), so they get a spec-before-code treatment.

Precedence check (CLAUDE.md §3/§4): every proposal below is fail-closed and default-deny — a
NAT-classification result is **advisory only, never an authorization input** (§D14.c), a punch-timing
message is signed + replay-protected + freshness-bounded before it schedules anything (§D14.d), and the
two gated items remain OFF until signed off. No custom crypto: everything reuses the existing
Ed25519 / SHA-256 / replay-window primitives.

---

## 1. Current state (verified against code, 2026-07-19)

| Capability | Where | Reality |
| --- | --- | --- |
| STUN client | `rustynetd/src/stun_client.rs` | Transport only: sends RFC 5389 Binding Requests to N servers, parses (XOR-)MAPPED-ADDRESS. **No NAT classification** — zero RFC 5780 CHANGE-REQUEST, no filtering probe. |
| NAT profile types | `rustynetd/src/traversal.rs:977` | `NatMappingBehavior`/`NatFilteringBehavior`/`NatProfile` + `direct_udp_viable()` exist, but **nothing in production constructs a `NatProfile` from a live probe** (only `#[cfg(test)]` literals). |
| Lab NAT classifier | `rustynet-netns-probe` `nat-classify` | A crude multi-server port-comparison heuristic — but it exists to verify a *simulated* NAT in the lab, not to run on a real anchor. |
| Gossip messages | `rustynetd/src/peer_gossip.rs:106` | `GossipBundle`: single fixed-layout wire format, **no type-discriminator byte**, version hard-rejected on mismatch. Replay: per-source monotonic `sequence` + 300s freshness + domain-separated signing. |
| Traversal coordination | `rustynet-control/src/lib.rs:1613` | `SignedTraversalCoordinationRecord` already carries `probe_start_unix`, `node_a`/`node_b`, `nonce`, expiry — **functionally a punch-now message** — with a working replay window (`traversal.rs::CoordinationReplayWindow`). BUT it is file-distributed, signed by ONE authority for BOTH peers, and minted only by lab code (`ops_e2e.rs`). |
| Port-mapping mode | `rustynetd/src/port_mapper.rs:2151` | uPnP/NAT-PMP/PCP clients complete; default is `Keepalive` unconditionally (`:4262`), no role-conditional `Auto`. |
| Port-delta prediction | — | **100% greenfield.** Zero code, zero schema, anywhere. |
| Endpoint mailbox | — | **100% greenfield.** Zero code, zero schema, anywhere. |

The single most important structural fact: **there are two parallel signed-artifact systems** (the D2.5
self-signed `GossipBundle`, and the older authority-signed `SignedTraversalCoordinationRecord`), and
D14.d must pick which one owns punch timing. That choice is the load-bearing decision in this document.

---

## 2. D14.c — Honest NAT behavior discovery + CGNAT detection (un-gated; spec-before-code)

**The hard part is not the code, it's that public STUN servers don't cooperate.** Textbook NAT-behavior
discovery (RFC 5780) needs the server to honor CHANGE-REQUEST (reply from a different IP/port) so the
client can probe filtering behavior. The dataplane plan §2.2 locked us to *public* STUN servers, which
almost never implement CHANGE-REQUEST. So the design cannot be "implement RFC 5780"; it must be a
**heuristic that extracts maximum signal from vanilla Binding Requests only**:

- **Mapping behavior** (endpoint-independent vs address/port-dependent) — probe ≥2 distinct STUN servers
  (already supported by `gather_mapped_endpoints_batched`) and compare the reflexive port. Same external
  port across servers → endpoint-independent mapping (cone-ish); differing ports → address/port-dependent
  (symmetric-ish). This is the same comparison the lab `nat-classify` already does; promote its *logic*
  (not its lab binary) into a pure `classify_mapping(observations: &[StunObservation]) -> MappingBehavior`
  in `rustynetd`.
- **CGNAT detection** — two independent signals, either sufficient: (a) STUN-reflexive address in
  `100.64.0.0/10` (RFC 6598 shared address space); (b) mismatch between the uPnP/NAT-PMP
  `GetExternalIPAddress` (the local edge router's WAN) and the STUN-reflexive address (a second NAT above
  the home router = carrier-grade). Both are pure comparisons over data we can already fetch.
- **Filtering behavior** — honestly unknowable from public STUN without CHANGE-REQUEST. **Record it as
  `Unknown` rather than guessing** (fail-closed on the *classification*, not the connection): a
  `NatProfile` with `filtering: Unknown` must make `direct_udp_viable()` return the conservative answer
  (assume address-dependent filtering → prefer coordinated punch / relay), never the optimistic one.

**Enforcement / advisory boundary (CLAUDE.md §3):** the resulting `NatProfile` is surfaced in
`rustynet status`, the anchor wizard, diagnostics, and (later, D14.d) gossip metadata — but it is
**observational**. It must never gate membership, ACL, or route decisions. A peer lying "I'm a full cone"
can at worst waste a punch attempt that fails closed to relay; it can never gain access. Add a negative
test pinning that a forged/optimistic `NatProfile` does not change any authorization outcome.

**Files:** new `rustynetd/src/nat_discovery.rs` (pure classifier + CGNAT detector, heavily unit-tested
offline); wire the constructor into the existing STUN gather path; extend the `status` reporter. The
gossip-metadata surfacing is deliberately **deferred to D14.d** because it changes the versioned wire
format (see §3). Verdict: **buildable now as a self-contained advisory module**; the only subtlety is the
public-STUN limitation, which the `Unknown`-is-conservative rule handles honestly.

---

## 3. D14.d — Signed, replay-protected, gossip-coordinated punch timing (un-gated; DECISION REQUIRED)

Goal: two peers behind port-restricted-cone NATs agree on a wall-clock instant to simultaneously send
hole-punch packets, so each NAT sees an outbound packet first and admits the other's inbound — the
Tailscale-DISCO technique the plan cites. The mechanics (a scheduled `probe_start_unix`, a wait, a burst)
already exist end-to-end on the *consumption* side (`CoordinationSchedule` → `SimultaneousOpenRuntime`).
**What's missing is the trust model for who signs the "punch now at T" proposal, and it is a real fork:**

### The fork

- **Option A — self-signed proposal, unilateral accept (RECOMMENDED).** Peer X, over the existing D2.5
  gossip, sends a *new message type* it signs with its own node key: "X proposes X↔Y punch at T=…,
  nonce=…". Y verifies X's signature (X is a known mesh member — its verify key is already in membership),
  checks freshness + replay, and either honors T or ignores it. Symmetric: each peer signs only its own
  proposal; no third party signs anything. **This is consistent with decision 2.1 ("no central
  coordination host") and with how `GossipBundle` already works (each peer self-signs its own data).**
  Abuse ceiling: a malicious member can at most make a peer emit a punch packet toward another member at a
  chosen instant — a packet that reveals only what a normal punch reveals, toward a peer already in the
  mesh. That is a negligible escalation and it fails closed (a mistimed punch just fails → relay).

- **Option B — reuse `SignedTraversalCoordinationRecord` (authority-signed for the pair).** Keep the
  existing type/replay-window and have an admin/anchor authority sign the pairwise schedule. **Rejected
  as the primary path:** it reintroduces a coordination authority the architecture explicitly removed, it
  does not ride gossip (it's file-distributed today), and it makes punch timing depend on an online signer
  — a liveness regression. Its *primitives* (the nonce replay window `CoordinationReplayWindow`, the
  `probe_start_unix` field, `SimultaneousOpenRuntime`) are still reused by Option A; only its
  trust/distribution model is dropped.

### Why the message can't just be a new `GossipBundle` field

`GossipBundle`'s wire format is fixed-offset with **no type-discriminator byte** and a version that is
hard-rejected on mismatch (`peer_gossip.rs`). So Option A needs a genuine protocol step: bump the gossip
wire version and add a leading **message-type tag** (`0x01 = bundle` for back-compat, `0x02 = punch
proposal`), then branch `serialise`/`deserialise` and the transport `recv` on the tag. Reuse — do not
reimplement — the `SeenSequenceState` monotonic-sequence guard, the 300s freshness window, and a **new
domain-separation constant** (`b"rustynet:punch_proposal:v1"`, distinct from the bundle's, so a signature
can never be cross-replayed between message types). Persist the punch-proposal replay watermark alongside
the existing `GossipWatermark` (fail-closed on write failure, same as today).

**Verdict:** the low-level primitives are all present and reusable; the deliverable is (1) the owner
picks Option A vs B (recommendation: A), (2) a small but real gossip-wire-version protocol change with a
type tag, (3) reuse of the replay/freshness/domain-separation patterns. This is **protocol design that
needs the fork resolved before code**, not a mechanical task — but it is bounded and un-gated once the
fork is picked.

---

## 4. D14.e — Quiet sequential port-delta prediction (GATED, owner sign-off required)

For a NAT that allocates external ports sequentially, a peer can sometimes predict the *next* port instead
of the currently-mapped one, punching a symmetric NAT that endpoint-independent techniques can't. The
dataplane plan **bans broad port spraying** (§3) and gates this narrow "quiet" form on field evidence
(from D14.c telling us how common sequential-allocation NATs actually are) + explicit sign-off.

**Framing for the decision (not a build):**
- It is 100% greenfield — no code, no schema.
- The line between "quiet sequential-delta prediction" (send to `observed_port + k` for small `k`) and
  "spraying" (banned) is a **policy** line that must be encoded as a hard cap (e.g. `k ≤ 4`, single
  attempt, no repetition) with a test that the cap cannot be exceeded, or it silently becomes spraying.
- **Recommendation: do not schedule until D14.c is live and has produced field evidence** that
  sequential-allocation NATs are common enough to justify the abuse surface. Prediction against a
  wrongly-classified NAT is wasted packets at best; the value is unproven until we can measure NAT types
  in the wild. Keep gated.

---

## 5. D14.f — Opt-in encrypted endpoint mailbox recovery (GATED, owner sign-off required)

When gossip can't reach a peer whose endpoint changed (the §4.1.2 "gossip-needs-connectivity
circularity" — e.g. an anchor renumbered and no one knows its new address), a peer could publish its
current endpoint to an out-of-band **encrypted mailbox** (the plan floats a dynDNS TXT record or the
BitTorrent Mainline DHT) that a searching peer reads and decrypts. The plan is explicit that this
**reopens the §3 third-party-dependency exclusion** and so is the most heavily gated item.

**Framing for the decision (not a build):**
- 100% greenfield.
- This is fundamentally a **threat-model + policy decision, not an engineering one.** The engineering
  (encrypt an endpoint blob under a mesh key, publish, poll, decrypt) is straightforward; the hard part
  is the metadata/availability/abuse/replay/privacy/kill-switch analysis the ledger item itself demands:
  a public mailbox leaks "these node-ids are looking for each other and roughly when," a third-party DHT
  is an availability and censorship dependency, and a stale mailbox entry is a replay vector.
- **Recommendation: keep gated; if pursued, spec the threat model FIRST** (what an observer of the
  mailbox learns, how a kill-switch disables it, how staleness/replay is bounded) and require the whole
  feature to be **opt-in and off by default** — never a silent fallback. Do not build ahead of that
  threat model.

---

## 6. Adjacent, cheapest item — D14.a anchor port-mapping default flip

Not one of the four, but the nearest ungated win: flip `PortMappingMode::default()` to `Auto` **only for
anchor-role nodes** (`port_mapper.rs:2151`, wired at `daemon.rs:1833`). The uPnP/NAT-PMP/PCP machinery is
already complete (D2.3), so this is a default-value + role-conditional change with a role-conditional
test — gated only on real-router acceptance evidence per the plan. Smallest, safest, most
implementation-ready of everything in this space; a reasonable first thing to actually build once
real-router acceptance is confirmed.

---

## 7. Summary — build vs decide

| Item | Class | Blocker before code |
| --- | --- | --- |
| D14.a port-mapping default | Implementation | Real-router acceptance evidence (small) |
| D14.c NAT discovery + CGNAT | Advisory module, buildable now | None — the public-STUN limit is handled by `Unknown`-is-conservative |
| D14.d punch timing | Protocol design | **Owner picks Option A vs B (recommend A)**, then a bounded gossip-wire-version change |
| D14.e port-delta prediction | Greenfield, **gated** | Owner sign-off + D14.c field evidence; keep gated |
| D14.f endpoint mailbox | Greenfield, **gated** | Owner sign-off + a written threat model FIRST; keep gated |

The one decision that unblocks the most is **D14.d Option A vs B** — recommended **A** (self-signed
proposal over gossip, unilateral accept), because it is the only option consistent with the
"no coordination host" architecture and it reuses every existing primitive except the trust model of the
lab-only `SignedTraversalCoordinationRecord`.
