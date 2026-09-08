# Relay Election Policy Design (2026-09-08)

Status: DESIGN ONLY. No code changed by this document. It decides the relay
election policy the traversal authority and daemon must implement, names the
fail-closed rules that come with it, and scopes the lab-side producer whose
absence is QH-80.

Precedence: `documents/Requirements.md`, `documents/SecurityMinimumBar.md`, then
this document. Governing context: `UdpHolePunchingAndRelayTraversalPlan_2026-03-07.md`
(the ICE-model decision and the "one controller" constraint),
`RustynetDataplaneExecutionPlan_2026-05-18.md` D3/D4/D9,
`BlindRelayRoleDesign_2026-08-27.md` (relay-side protocol future),
`QualityHardeningTodo_2026-07-25.md` QH-80 (the producer gap).

## 0) Decision summary

1. **Signal:** a relay candidate is minted into a pair's signed traversal bundle
   as a *standing fallback* for every pair the policy admits — the signal to
   *use* it is the daemon's already-implemented direct-probe failure counter
   (3 consecutive failed direct probe rounds, `traversal.rs:65`,
   `traversal.rs:910`). NAT classification is NOT an input: the daemon has no
   NAT-behavior classifier today (verified §1.4). An explicit authority
   override exists as the relay-only bundle (§3.4).
2. **Who decides / who mints:** split. The **authority mints** (which relay,
   which TTL, whether the pair may relay at all); the **daemon's Phase 10
   controller decides when to program it** from locally observed probe
   failures. Peers never mint, never request, and cannot influence which relay
   they get (§3.2).
3. **Which relay:** the authority picks from the signed relay fleet bundle at
   mint time — highest `priority` among `enabled` relays matching the pair's
   region tag, falling back to highest `priority` globally (§3.3).
4. **TTL/scope:** bundle-borne, authority-set, bounded by the existing
   endpoint-hint TTL cap (≤ 86400 s, `rustynet-control/src/lib.rs:2876`);
   session tokens stay at the existing 120 s max with the 15 s refresh margin
   (`lib.rs:1726`, `daemon.rs:386-387`). Mid-session expiry is handled by the
   existing pre-expiry refresh + fail-closed stale rejection (§3.5).
5. **Failback:** unchanged — the existing one-controller reprobe design already
   does it (paced direct reprobes on the relay arm, session close on direct
   recovery, FIS-0010 flap breaker, FIS-0013 quality re-race) (§3.6).
6. **What the relay is told:** nothing new. `RelayHello` + `RelaySessionToken`
   (pair- and relay-scoped, 120 s, nonce-replay-protected) as today; the fleet
   bundle stays daemon-side (§3.7).
7. **Required hardening found while designing:** a relay candidate in a bundle
   with NO verified relay fleet on the daemon is currently accepted
   (`daemon.rs:8013` passes `Option`, the `None` arm skips the fleet check at
   `daemon.rs:16720`) — this design makes the fleet MANDATORY whenever a
   relay candidate is present (§4, FC-1).
8. **Lab blocker found while designing:** the QH-80 sketched fix (mint a Relay
   candidate with the lab relay's live address `192.168.64.10:4500`) is
   rejected by production validation — `validate_runtime_relay_candidate_endpoint`
   (`daemon.rs:16789-16815`) refuses RFC 1918/CGNAT/ULA relay endpoints,
   unconditionally, with no lab escape. The lab must number its relay in a
   non-private range (TEST-NET-3 recommended) or the owner must decide a
   signed lab profile (§7, OD-1).

## 1) Grounding: what the code does today

Every claim below was read on this branch's tree.

### 1.1 Types and minting (control plane)

- `EndpointHintCandidate { candidate_type: Host|ServerReflexive|Relay, endpoint:
  String, relay_id: Option<String>, priority: u16 }` —
  `crates/rustynet-control/src/lib.rs:1471-1491` (`EndpointHintCandidateType` at
  `:1471-1475`, its `as_str` at `:1477-1483`, the candidate struct at `:1486-1491`).
- `EndpointHintBundleRequest { source, target, generated_at_unix, ttl_secs,
  nonce, candidates }` — `lib.rs:1486-1494`. `SignedEndpointHintBundle` carries
  `expires_at_unix` — `lib.rs:1505-1512`.
- Issuance validation (`ControlPlaneCore::signed_endpoint_hint_bundle`,
  `lib.rs:2865`): TTL must be > 0 and ≤ 86400 ("endpoint hint ttl exceeds max
  supported value", `lib.rs:2876`); pair policy default-deny gate
  `policy_allows_node_pair` (`lib.rs:3501`; "endpoint hints denied by policy",
  `lib.rs:2920`); relay candidates REQUIRE a non-empty `relay_id`
  canonicalizable via `canonical_relay_id_from_label` (`lib.rs:1730-1746`;
  error at `:2945`); non-relay candidates must NOT carry `relay_id`
  ("relay_id is only valid for relay candidates", `lib.rs:2951`); canonical
  payload ordering is priority-desc, type-asc, endpoint-asc, relay_id-asc
  (pinned by test at `lib.rs:6586+`).
- `RelayFleetNodeDescriptor { relay_id, region, priority, capacity, enabled }`
  — `lib.rs:1516-1523`; `SignedRelayFleetBundle` wire version 1 with nonce,
  TTL, relay_count — `lib.rs:1525-1532`, parser at `:1534+`.
- `RelaySessionToken { node_id, peer_node_id, relay_id [u8;16], scope,
  issued_at, expires_at, nonce, signature }` — `lib.rs:1751-1762`;
  `MAX_RELAY_SESSION_TOKEN_TTL_SECS = 120` — `lib.rs:1726`; issuer
  `issue_relay_session_token` at `lib.rs:3073` enforces the cap (`:3087`).
- **Production mint sites that exist:** the manual authority CLI
  `execute_traversal_issue` (`crates/rustynet-cli/src/main.rs:7022-7127`) —
  takes candidates (including type + relay_id) from flags, signs under the
  assignment signing secret, writes the bundle + verifier key. The lab
  producer `traversal_candidates_for_target` (`crates/rustynet-cli/src/ops_e2e.rs:3939-3958`)
  emits only Host (priority 900) and ServerReflexive (800), never Relay. All
  other `TraversalCandidate { candidate_type: Relay, .. }` constructions are
  inside `#[cfg(test)]` (control `lib.rs` ~5930/6087/6109/6579/6611; daemon
  `daemon.rs:34083`). This is QH-80's verified gap: no producer mints a relay
  candidate.

### 1.2 Consumption (daemon)

- `select_runtime_traversal_endpoints` (`daemon.rs:16664-16686`): direct =
  highest-priority non-Relay candidate; relay = highest-priority Relay
  candidate. This is the ICE-style prioritisation.
- `select_runtime_relay_candidate_with_verified_fleet` (`daemon.rs:16699-16723`):
  requires `relay_id` on the relay candidate (error at `:16713`), validates
  the endpoint, and — if a fleet is provided (`if let Some(relay_fleet)` at
  `:16720`) — requires the relay_id AND endpoint to appear in the signed
  fleet (`ensure_runtime_relay_candidate_in_verified_fleet`,
  `daemon.rs:16726-16739`; empty enabled fleet is an error,
  `verified_relay_fleet_endpoint_index` at `:16740`).
- `validate_runtime_relay_candidate_endpoint` (`daemon.rs:16789-16815`):
  rejects port 0, unspecified/loopback/multicast, and **private / link-local /
  broadcast / CGNAT IPv4 and ULA / link-local IPv6 relay endpoints**. No
  override exists (three call sites, all unconditional).
- Relay client gating (`load_relay_client`, `daemon.rs:4983-5041`): returns
  `Some` only with (a) a preissued token spool dir + traversal verifier key,
  or (b) signing secret + passphrase + `relay_session_local_token_issuer_enabled`,
  which errors unless explicitly set, with the message that it is "only for
  reviewed lab/control-plane-collocated deployments" (`daemon.rs:5008-5016`).
  Combining spool + local issuer is `InvalidConfig` (`daemon.rs:4988-4994`).
- Fleet loading (`load_optional_relay_fleet`, `daemon.rs:5091-5119`): requires
  the traversal verifier key, a persistent watermark (anti-rollback), and max
  age; missing file → `Ok(None)`.
- Reconcile (`sync_traversal_runtime_state`, read at `daemon.rs:7560-7660`):
  per managed peer, takes direct candidates and the relay endpoint from the
  bundle; a bundle with neither direct nor relay endpoints fails closed
  ("contains no usable runtime endpoints", `:7600-7606`); **removal of the
  relay candidate while a peer is actively relay-routed is a hard failure**
  ("traversal authority removed the relay candidate required for active relay
  peer", `:7618-7630`); relay sessions close for stale peers (`:7560-7566`).
- Session lifecycle (`daemon.rs:8005-8079`): `relay_session_refresh_due`
  refreshes when the endpoint, relay_id, or token margin changes;
  `resolve_relay_client_endpoint` establishes via
  `establish_session_with_round_trip` on the shared authoritative transport;
  establishment failure propagates as a traversal runtime sync failure
  (fail-closed in enforced mode, per HP-4 status in the hole-punching plan).
- Probe policy (`traversal_probe_due_decision`, `daemon.rs:3097-3155`): one
  state machine over `PathMode::Direct|Relay`; direct arm re-races immediately
  when a fresh handshake goes stale, paced by `next_reprobe_unix` when it was
  already stale; relay arm is paced by `next_reprobe_unix`. Defaults:
  `DEFAULT_TRAVERSAL_PROBE_RELAY_SWITCH_AFTER_FAILURES = 3`
  (`traversal.rs:65`), `DEFAULT_TRAVERSAL_PROBE_HANDSHAKE_FRESHNESS_SECS = 30`
  and `DEFAULT_TRAVERSAL_PROBE_REPROBE_INTERVAL_SECS = 30` (`daemon.rs:454-455`),
  probe max candidates 8 / max pairs 24 / 3 simultaneous-open rounds / 80 ms
  spacing (`traversal.rs:61-64`). The relay arm engages once
  `consecutive_direct_failures >= relay_switch_after_failures`
  (`traversal.rs:910`), and the config refuses zero (`traversal.rs:1364-1366`).
- FIS-0010 flap breaker withholds direct re-races while open
  (`daemon.rs:7637-7648`), flag `traversal_flap_breaker` **defaults to false**
  (`daemon.rs:2689`). FIS-0013 pending quality re-race forces a probe through
  (`daemon.rs:7625-7627`).
- Session constants: token TTL default 120 s, refresh margin 15 s, idle
  timeout 30 s (`daemon.rs:386-388`).

### 1.3 What the relay enforces (already shipped, HP-3)

Constant-time token field comparisons, 240 s replay window, 5 hellos/s per
node, token-bucket packet rate, per-node session caps (default 8), idle 30 s /
half-open 60 s timeouts, 64 KB max packet, ciphertext-only forwarding
(`UdpHolePunchingAndRelayTraversalPlan_2026-03-07.md` HP-3 status, lines
223-238). The relay does not evaluate pair policy; it trusts the token issuer
(`BlindRelayRoleDesign_2026-08-27.md` §1.2-1.3).

### 1.4 NAT classification: what actually exists

- The daemon classifies address RANGES for routing purposes — CGNAT
  100.64.0.0/10 treated as private — in `crates/rustynetd/src/dataplane_candidates.rs:125-126,
  558`. This is dataplane route classification, not a traversal NAT-behaviour
  detector.
- `stun_client.rs` gathers mapped endpoints (`gather_mapped_endpoints`,
  `stun_client.rs:320`) — addresses only. No symmetric-NAT or
  mapping-filtering behaviour test exists in the daemon.
- A NAT heuristic exists ONLY in lab tooling: `NatClassHeuristic` in
  `crates/rustynet-cli/src/ops_cross_network_preflight.rs:127` (and
  `NatClassCode` in `rustynet-advisor/src/lib.rs:40`). UNVERIFIED that either
  feeds any production decision; neither is in the daemon's traversal path.

**Consequence:** any policy that gates relay use on "the daemon detects CGNAT /
symmetric NAT" is unimplementable today. The honest, observable signal is the
probe outcome itself.

## 2) The problem, precisely

The consumer half is complete and fail-closed. What is missing is a PRODUCER
with a POLICY: no code path decides "this pair gets a relay candidate, naming
relay R, with priority P and TTL T" and signs it. The manual
`ops traversal-issue` CLI can express it but nothing automates or governs it,
and the lab never exercises it (QH-80, verified 2026-09-08: every minted
candidate is `relay_id: None`; no `relay_fleet`/session material is ever
distributed).

## 3) The policy

### 3.1 Shape: standing fallback, not reactive minting

**Decision:** every pair whose policy allows communication gets a Relay
candidate in its signed traversal bundle whenever the fleet contains an
enabled relay — minted at bundle (re)issue time, not in reaction to failure.
Priority is strictly below every direct candidate the same bundle carries
(concrete numbers: direct Host = 900, Srflx = 800 as the lab already uses
(`ops_e2e.rs:3941-3956`); Relay = 100).

Why standing rather than reactive:

- The daemon already implements the timing decision (probe failures → switch;
  recovery → failback). A reactive minter would duplicate that state machine on
  the authority side, where the failure signal does not exist (§3.2).
- ICE's own model: relay candidates are gathered up front and simply rank
  below direct ones; connectivity checks choose. This is the model the
  hole-punching plan already commits to (§3 of that plan, "Follow ICE-style
  candidate/check model and relay fallback semantics").
- Fail-closed: a pair that loses direct connectivity between bundle refreshes
  still has a relay path WITHOUT needing the authority to notice and re-mint —
  the authority noticing is the thing that cannot be relied on.

The losing alternative — authority mints relay candidates only after learning
a pair is failing — requires the authority to observe per-pair handshake
freshness, which lives in the daemon's backend (`managed_peer_latest_handshake_unix`,
`daemon.rs:7592-7599` area) and is not reported to the authority today.
Building that telemetry is a larger change with a worse trust property (the
authority reacting to peer-supplied liveness claims invites a peer-supplied
"we're failing, give us your relay" steering attack). Rejected.

### 3.2 Who decides, who mints

**Decision: the authority mints and permits; the daemon elects (times the use
of) what the authority already permitted.**

- MINT (authority, signed): which pairs may use a relay at all (the existing
  `policy_allows_node_pair` default-deny gate at `lib.rs` issuance), which
  relay, the candidate's priority, the bundle TTL. The signing key is the
  assignment/endpoint-hint key — the same custody chain as every other
  endpoint mutation, satisfying "signed control/trust state validation before
  mutation" (CLAUDE.md §4).
- ELECT (daemon, local): WHEN the relay candidate is programmed — after
  `relay_switch_after_failures = 3` consecutive direct probe failures
  (`traversal.rs:65,910`), when the flap breaker permits, with paced
  reprobes for failback (`daemon.rs:3097-3155`). The peer cannot mint, cannot
  choose a different relay than the signed one, and cannot skip a relay the
  authority ranked highest — `select_runtime_traversal_endpoints` takes the
  max-priority Relay candidate and cross-checks it against the signed fleet
  (`daemon.rs:16699-16723`), and the relay itself rejects tokens whose
  relay_id/scope/nonce do not verify.

Trust argument, stated plainly. A peer-decided relay path means a peer
influences its own routing: it could prefer a relay it controls (or has
compromised) to position itself for traffic analysis of the peer's leg, or to
burn a third party's bandwidth. An authority-decided path needs the authority
to observe failure it cannot see directly — so pure authority-decided TIMING is
unimplementable (§3.1). The split removes both: the peer only ever executes a
signed instruction, and the authority never needs failure telemetry. This is
the same trust boundary the daemon already enforces everywhere else: "signed
traversal state still remains the only endpoint-mutation authority" (HP-4
status, hole-punching plan lines 253-255).

### 3.3 Which relay

**Decision: authority-side deterministic selection from the signed fleet at
mint time.** Input: the `SignedRelayFleetBundle` (already typed, signed,
watermark-protected — `lib.rs:1516-1532`, `daemon.rs:5091-5119`). Rule:

1. Filter `enabled == true` and `capacity > 0` (capacity 0 is already invalid
   at `daemon.rs:16784`).
2. Prefer relays whose `region` equals the pair's shared region tag (region
   tag on membership metadata; if either peer has no region tag, treat as no
   match).
3. Among the preferred set (or the whole enabled set if none match), take
   highest `priority`; tie-break by lexicographically smallest `relay_id` for
   determinism.
4. Mint exactly ONE Relay candidate. Multiple relay candidates per bundle buy
  little (the daemon takes max-priority anyway) and enlarge the signed payload.

Who supplies the input: the fleet bundle is signed by the same authority and
distributed alongside the traversal bundle (the lab gap QH-80 names — nothing
distributes it today). The daemon's fleet cross-check (`daemon.rs:16726-16739`)
remains the enforcement backstop: even a minter bug cannot program a relay
absent from the signed fleet.

Capacity-based load balancing is explicitly OUT (see §6): the `capacity` field
is advisory metadata today; nothing consumes it for admission.

### 3.4 Explicit authority override (forced relay)

An operator/authority decision to force a pair onto relay is expressed by
minting a bundle containing ONLY the Relay candidate (no Host/Srflx). The
daemon already handles this shape: `traversal_direct_probe_candidates` filters
Relay out (`daemon.rs:16816-16830`), `select_runtime_traversal_endpoints`
yields direct=None, and the "no usable runtime endpoints" failure does not
trigger because the relay endpoint exists (`daemon.rs:7596-7606`). No new
field, no new code path, no omittable declaration. The inverse (forcing
direct-only) is simply a bundle with no Relay candidate — which for an
actively-relayed peer is the existing hard failure at `daemon.rs:7618-7630`;
an operator intending "drop relay" must accept the pair falls back to direct
probing only after the controller re-races, and an operator intending
"disrupt" gets a loud failure, which is the correct fail-closed behavior.

### 3.5 TTL and scope

- **Bundle (the permission):** authority-set, existing bounds `0 < ttl ≤ 86400`
  (`lib.rs:2876`). Recommended mint cadence: re-issue at the same cadence
  as the assignment/traversal refresh the deployment already runs (lab: re-mint
  per stage per `TraversalBundleFreshnessPlan_2026-09-07.md`, which exists
  because lab bundles are minted at 120 s). The permission is pair-scoped by
  construction (`source_node_id`/`target_node_id` on the bundle) and
  replay-protected by nonce + watermark + freshness on the daemon side
  (existing).
- **Session token (the usage):** unchanged — 120 s max (`lib.rs:1726`), daemon
  refresh margin 15 s (`daemon.rs:387`), refresh handled by
  `relay_session_refresh_due` (`daemon.rs:8005-8027`).
- **Mid-session expiry:** two cases, both already fail-closed. Token expiry →
  pre-expiry refresh; if refresh fails, establishment failure propagates as a
  traversal sync failure (enforced mode fails closed; there is no
  direct-fallback bypass of signed state — direct re-entry only via the
  controller's own probe path). Bundle expiry → the existing stale-rejection
  path (netcheck `traversal_stale_rejections`; enforced mode refuses to act on
  expired traversal state). A pair whose bundle expires mid-relay-session
  therefore loses its path loudly rather than silently downgrading — correct,
  and the fix is operationally the mint cadence, not a daemon change.

### 3.6 Failback (the "one controller" constraint)

Unchanged, by design. The Phase 10 controller owns `PathMode`; direct and
relay are states of one state machine (`phase10.rs:331`; the hole-punching
plan's §4 rule 5). On the relay arm, `traversal_probe_due_decision` paces
direct reprobes via `next_reprobe_unix` (`daemon.rs:3146-3148`); on direct
recovery the relay session closes (`close_relay_session`; stale peers at
`daemon.rs:7560-7566`); the FIS-0010 flap breaker (opt-in today,
`daemon.rs:2689`) withholds direct re-races while open to prevent ping-pong;
FIS-0013 quality re-races are the escape hatch. This design adds NO second
controller and NO fallback branch — it only fills the candidate list the
existing controller reads.

### 3.7 What the relay is told, and by whom

Nothing beyond today's protocol. The relay receives `RelayHello` carrying the
pair-scoped `RelaySessionToken` minted/refreshed by the token issuer (control
plane `lib.rs:3073`, or the lab-only daemon-local issuer). The relay never
receives the traversal bundle, the fleet bundle, or the pair's policy — it
validates the token (signature, scope, relay binding, TTL, nonce) and its own
admission limits (§1.3). The fleet bundle is consumed daemon-side only
(`load_optional_relay_fleet`). Interaction with `BlindRelayRoleDesign_2026-08-27.md`:
that design replaces token/hello v1 with identity-free v2 for `blind_relay`
nodes and moves pair authorization wholly to the issuer; this document's
election policy is upstream of and compatible with both token generations —
v2 changes what the relay LEARNS, not who elects.

## 4) Fail-closed analysis (mandatory)

Existing mechanisms (verified, keep): malformed/absent relay_id rejected at
issuance AND at daemon selection (`lib.rs:2945-2951`, `daemon.rs:16713`);
private/CGNAT relay endpoint rejected (`daemon.rs:16789-16815`); relay-id/endpoint
absent from signed fleet rejected (`daemon.rs:16726-16739`); relay candidate
removed while relay-active = hard failure (`daemon.rs:7618-7630`); token
replay/expiry/forgery rejected relay-side (§1.3); spool+local-issuer
combination rejected (`daemon.rs:4988-4994`).

New/changed mechanisms introduced by this design:

| # | Field/decision | ABSENT | MALFORMED | STALE | SET BY WRONG ACTOR |
|---|---|---|---|---|---|
| FC-1 | Relay candidate in bundle, daemon has NO verified fleet | **NEW RULE: reject the candidate and surface a traversal sync failure** — closes today's `None`-fleet skip (`daemon.rs:8013` passes `Option`; `:16720` skips the check). Zero-effort path must be the closed one. | n/a (absence case) | stale fleet (watermark/max-age) already rejected at load (`daemon.rs:5091-5119`) → same rejection | fleet is signed by the authority key; a node-served fleet fails signature |
| FC-2 | Relay candidate priority (100) | absent candidate = pair simply has no relay fallback (today's behavior; direct-only is a legal signed state) | non-numeric priority already fails bundle parsing | priority is inside the signed payload; tamper fails signature | only the authority signs; see §5 for the malicious-authority case |
| FC-3 | Region tag input to selection | no region tag → deterministic global highest-priority fallback (§3.3 step 3) — no deny-hole, just a coarser choice | malformed region already rejected in fleet descriptors (`daemon.rs:16765-16784`, region at `:16781`) | tags ride membership freshness | a peer's OWN tag steers only which relay the authority would pick for pairs involving it — bounded by the fleet signature; see §5 |
| FC-4 | Forced-relay (relay-only) bundle | not minted → normal standing-fallback behavior | malformed → existing bundle parse failures | stale → existing stale rejection | authority-only (signed) |
| FC-5 | Lab distribution of fleet + token spool | absent → `load_relay_client` returns `None`, relay stays disabled (`daemon.rs:4983`) — and with FC-1, a relay-carrying bundle then FAILS CLOSED instead of silently ignoring the relay candidate | corrupt spool → `PreissuedRelaySessionTokenIssuer` construction error (`daemon.rs:4996-5000`) | stale tokens → relay rejects (TTL) | spool is root-owned local custody; verifier key pins the issuer |

FC-1 is the one genuine code change this design demands on the daemon side,
and it is a tightening: today a relay candidate without any configured fleet
would be programmed with only signature protection. That was defensible when
no producer existed (the case was unreachable); once candidates exist, the
fleet membership check must not be skippable by omission. This mirrors the
repo's rejection of the omittable-precondition pattern (a recent proposal was
cut for exactly that shape).

## 5) Security analysis

**What ciphertext-only forwarding bounds — and what it does not.** It bounds
payload confidentiality and integrity: WireGuard encrypts end-to-end; the
relay sees frames it cannot read, cannot inject (no keys), and cannot
selectively modify undetectably (AEAD). It does NOT bound: (a) traffic
analysis — the relay observes both legs, packet sizes, timing, volume,
duration (explicitly conceded as BR-R1 in `BlindRelayRoleDesign_2026-08-27.md`
§3.3); (b) availability — the relay can drop, throttle, or priority-shape
either leg; (c) resource abuse — bounded only by the shipped rate limits and
session caps (§1.3), which protect the relay, not the pair; (d) metadata
association — a single-hop relay necessarily knows the two legs are one
circuit (BlindRelayRoleDesign §3.4). A relay election policy therefore chooses
WHO gets to see this metadata; it cannot reduce what is visible.

**Malicious or compromised authority steering pairs through its own relay.**
The authority already signs membership, assignments, and traversal endpoints —
it can already direct a peer's direct endpoint anywhere the fleet rules allow.
Adding relay minting extends the SAME capability class, with one genuine
increment: an authority-operated relay gains standing visibility of pair flows
it would not see on direct paths. Mitigations that hold: relay candidates must
reference the signed fleet (FC-1 makes this unconditional), the fleet is a
separately-signed artifact an operator can audit, and region/priority choices
are deterministic and reviewable. What does NOT hold: cryptographic protection
against the authority itself — by the repo's own model the authority is the
trust root for routing. ACCEPTED, with the audit consequence stated: fleet
bundle issuance should be logged like other signed-state mutations (append-only
audit trail, CLAUDE.md §10.7 pattern), so a post-hoc review can see which
relays the authority ever elected. If an operator's threat model cannot accept
authority-visible flow metadata, the mitigation is operational (operator-run
relays outside the authority's control, still fleet-signed) — noted as OD-4.

**A node using a relay it should not.** Three locks, independent: (1) the node
cannot mint — no signing key; the daemon-local issuer is config-gated to
"reviewed lab/control-plane-collocated deployments" (`daemon.rs:5008-5016`)
and this design requires that gate to stay closed in production presets; (2)
the daemon programs only fleet-verified candidates (FC-1); (3) the relay
admits only correctly-signed, pair-scoped, fresh, non-replayed tokens (§1.3).
A node CAN influence its region tag (FC-3), which nudges which relay is
elected for its pairs — the bounded residual: the chosen relay is still
authority-signed and fleet-listed, so the worst case is a peer steering itself
onto a legitimate-but-preferred relay (e.g., one geographically convenient for
correlation with a vantage point it holds near that relay). Accepted; noted
here so it is a known residual, not a surprise.

**DoS of election machinery.** Minting is authority-side and offline to the
data path; a peer cannot trigger minting (no relay-request message exists —
deliberately). Probe-driven election is the daemon's existing bounded loop
(max pairs 24, max candidates 8, paced rounds). No new remotely-triggerable
work is introduced.

## 6) What this design does NOT solve

- **Relay capacity / load balancing.** `capacity` stays advisory; no
  admission control consumes it. A fleet with one hot relay stays hot.
- **Blind-relay privacy (BR-P1).** Separate design, already owns token v2.
- **NAT-behaviour classification.** Nothing here adds a symmetric-NAT
  detector; election remains outcome-driven.
- **Multi-hop / split-trust relaying.** Non-goal per BlindRelayRoleDesign §3.4.
- **Authority compromise detection.** Audit logging creates the trail; it does
  not detect or prevent a live malicious authority.
- **The lab's private-address blocker.** This design exposes it (§0.8) and
  recommends the TEST-NET-3 fix, but the lab rework itself is QH-80's fix, not
  done here.
- **IPv6 relay fleet policy.** Fleet endpoints may be IPv6 and pass
  validation (`daemon.rs:16808` rejects only link-local/ULA); no
  IPv6-specific election preference is defined.

## 7) Owner decisions (required before implementation)

- **OD-1 — lab relay addressing (blocks QH-80's fix).** Options: (a) number
  the lab relay in TEST-NET-3 (203.0.113.0/24) inside the lab's netns
  substrate — passes `daemon.rs:16789` unchanged, zero code, but makes the
  relay address unreachable from the RFC 1918 lab LAN unless the substrate
  routes it (needs a lab-network owner check); (b) a signed lab profile
  permitting a lab subnet for relay endpoints — code change in the validation
  path, weakens a production check unless carefully scoped to a signed
  artifact, and re-opens exactly the fail-closed posture this repo enforces;
  (c) run a lab relay on a genuinely public address (cost, external
  dependency). Recommendation: (a); (b) only if (a) proves unroutable, and
  then gated on the fleet signature, never an env var.
- **OD-2 — flap breaker default.** `traversal_flap_breaker` defaults false
  (`daemon.rs:2689`). With real relay fallback, flapping pairs will ping-pong
  without it. Flip the default after the first live relay-failback evidence,
  or keep opt-in? Recommendation: flip after QH-80's fix passes
  `relay_forwards_frame_validation` live.
- **OD-3 — region taxonomy.** Region matching needs a convention for region
  tags on membership metadata (what string set, who validates). Until decided,
  ship priority-only selection (§3.3 step 3 fallback as the only rule).
- **OD-4 — authority-visible flow metadata acceptance.** §5 states the
  residual explicitly; the owner should accept it on record or require
  operator-run relays before relay election ships in any production preset.

## 8) Test plan (each test names the mutation it catches)

1. `relay_candidate_without_fleet_fails_closed` — daemon-side unit test:
   bundle with a Relay candidate, `relay_fleet = None` → traversal sync
   failure. Mutation caught: reverting FC-1 (restoring the `None`-skip at
   `daemon.rs:16720`) makes the candidate program — test fails. This is the
   test that pins the omittable-fleet hole shut.
2. `relay_election_picks_enabled_highest_priority_then_region` — control-side
   unit test over the selection function with a fixed fleet: disabled relays
   skipped, priority wins, region match preferred, deterministic tie-break.
   Mutations caught: sorting by `capacity`; including `enabled == false`;
   non-deterministic tie-break (test runs both orders).
3. `forced_relay_bundle_programs_relay_only` — daemon test: relay-only bundle
   → direct candidates empty, relay endpoint selected, no "no usable runtime
   endpoints" failure. Mutation caught: any new code that requires ≥1 direct
   candidate (would break forced relay).
4. `standing_relay_priority_below_direct` — issuance test: a minted bundle for
   an admitted pair carries Relay priority < every direct priority.
   Mutation caught: priority inversion (relay outranking direct silently
   changes election semantics).
5. `lab_relay_forwards_frame_validation` (existing stage, currently failing —
   QH-80) — after the lab producer fix: blocks direct UDP, expects
   relay-routed session within the stage window. Mutation caught: orchestrator
   stops distributing the fleet bundle or token spool → stage fails again
   (exactly the QH-80 regression, now detectable).
6. `local_issuer_refused_without_explicit_flag` — exists in substance
   (`daemon.rs:5008-5016` error path); add the production-preset assertion.
   Mutation caught: defaulting the flag true.
7. `fleet_audit_log_records_elected_relay` (with §5's audit logging) —
   issuance writes an append-only entry naming pair + relay_id. Mutation
   caught: minting without audit (silent authority steering).

Tests 1-4 are new; 5 exists; 6-7 extend existing surfaces. Each names its
mutation; none can pass with its target defect reverted.

## 9) Effort

| Slice | Nature | Days |
|---|---|---|
| FC-1 daemon hardening + tests 1 | mechanical (small, one code path + tests) | 0.5 |
| Selection function in control + issuance wiring + tests 2,4 | mechanical with a little judgement (determinism, tie-breaks) | 1 |
| Lab producer: fleet bundle + token spool distribution, candidate mint in `traversal_candidates_for_target`, TEST-NET-3 numbering (post OD-1) + test 5 | mechanical, orchestrator-side | 2-3 |
| Forced-relay shape + test 3 | mechanical | 0.5 |
| Audit logging + test 7 | judgement (what the ledger records, where) | 1 |
| Production mint cadence into the authority refresh loop (real deployments) | judgement (cadence, failure handling) | 2-3 |
| Live evidence: relay fallback + failback under FIS-0010 (OD-2), mac/win cells | lab time | 2 |

Total ≈ 9-11 days, roughly split 5 mechanical / 4-6 judgement-and-lab.

## 10) Implementation surface (for the executor)

- `crates/rustynet-control/src/lib.rs` — selection helper (pure, deterministic,
  testable) next to the fleet types; issuance includes the elected Relay
  candidate for admitted pairs when a fleet input is provided.
- `crates/rustynetd/src/daemon.rs` — FC-1: `sync_traversal_runtime_state` /
  `select_runtime_relay_candidate_with_verified_fleet` call sites
  (`daemon.rs:8013`, `:8037`) must treat a relay-carrying bundle with
  `relay_fleet == None` as a sync failure.
- `crates/rustynet-cli/src/ops_e2e.rs` — lab producer:
  `traversal_candidates_for_target` (`:3939`) appends the Relay candidate;
  distribution stages ship fleet bundle + spool (QH-80's scoped fix, as
  revised by OD-1).
- `crates/rustynet-cli/src/main.rs` — `execute_traversal_issue` (`:7022`)
  gains an optional `--relay-fleet <path>` input so the manual authority verb
  applies the same election rule (explicit flag, never inferred).

No protocol changes, no new wire formats, no new crypto, no backend-boundary
changes. The policy rides entirely inside already-signed artifacts.
