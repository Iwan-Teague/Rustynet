# D14.d — self-renewing traversal candidates (revision 2)

**Status:** spec, pre-code. Revision 2, after adversarial review refuted revision 1.
**Precedence:** CLAUDE.md §3/§4 — fail-closed, default-deny, no custom crypto, no
runtime fallback.

---

## 0. What revision 1 got wrong, recorded so it is not re-proposed

Revision 1 specced a gossip wire-version bump with a new message type to publish
reflexive candidates. **That work is unnecessary and was partly unsafe.** Kept
here because the errors are instructive and the discarded design is the obvious
one to re-invent:

1. **The daemon already publishes reflexive candidates over gossip.**
   `build_candidate_set_from_cache` (`rustynetd/src/daemon.rs:5367-5391`) reads
   `local_stun_candidates`, applies a `Global | Private` scope filter, and emits
   `v4_srflx`/`v6_srflx` alongside the host lanes. The serve loop calls it every
   reconcile (`:10431`, `:10680`), and `serialise_bundle` already carries all
   four lanes (`peer_gossip.rs:720-739`). Revision 1 proposed building what
   ships.
2. **Its central safety claim was false by arithmetic.** It asserted an old node
   would reject new tags because "`0x01`/`0x02`/`0x03`, none of which equal `2`".
   `0x02` **is** `2`, and `GOSSIP_BUNDLE_WIRE_VERSION = 2`
   (`peer_gossip.rs:77`) — so the very message it said would ship first would
   have passed an old node's version check and been parsed as a bundle. It also
   missed that the length check precedes the version check
   (`peer_gossip.rs:749-760`), and never analysed the reverse direction.
3. **It violated its own §5.1** by feeding self-asserted candidates into
   issuance, which is the laundering step (§3 below).
4. **It asserted a rate limiter that does not exist**, and inherited a false
   claim about the endpoint-hint key verbatim from a source document without
   checking it (§2.3).

**The real gap is local wiring inside the daemon, not a protocol change.**

## 1. The actual problem

Candidates are published and received. What does not happen is that a
**gossip-learned peer candidate set is never fed into the endpoint-hint
issuance/consumption path**. So the addresses a node has already learned cannot
become the endpoints it programs; that still requires an operator hand-filling
`SRFLX_SPEC` and re-minting.

Consequence, measured 2026-07-30: `fedora-x86-1` sits `FailClosed`,
`restriction_mode=Permanent`, `traversal_alarm_reason=traversal_bundle_is_stale`
— a hand-minted mesh that reached its TTL with no way to renew itself.

**Not in scope, because already fixed:** §4.4b (same-site peers needing
hairpinning) is closed and live-proven — `traversal_candidates_for_target`
(`rustynet-cli/src/ops_e2e.rs:3620-3638`) emits `Host` at priority 900 plus
`ServerReflexive` at 800, dropping a srflx equal to the host. Revision 1 claimed
this as new work by quoting a superseded block.
**Doc defect to fix separately:** `CrossNetworkTraversalEvidence_2026-07-29.md`
contains duplicated, contradictory §4.3/§4.4/§4.4b blocks — one pair "OPEN", a
newer pair "FIXED". Revision 1 read the stale copy. Deduplicate that document.

## 2. Scope

**D14.d1 — bridge, validate, bound.** No wire change. No flag day. Ships alone.
**D14.d2 — punch timing.** The only genuine new message type. Deferred until d1
is live-proven; specced in §6 so its wire needs are designed once.

### 2.1 The bridge (the deliverable)

Feed accepted gossip `CandidateSet`s into the endpoint-hint path so a node's
programmed endpoints follow the addresses it has already learned.

Reuse `accept_bundle_with_now` unchanged — it already enforces
membership-derived verifying keys, freshness (`DEFAULT_FRESHNESS_WINDOW_SECS`
= 300, `peer_gossip.rs:120`), the **two-sided** epoch window
(`GOSSIP_EPOCH_SKEW_WINDOW = 2` behind, `GOSSIP_EPOCH_FUTURE_TOLERANCE = 2`
ahead, `:147`/`:162`), monotonic `SeenSequenceState` (`:309`), fail-closed
watermark persistence (`gossip_runtime.rs:632`), and a **revoked-source refusal
after signature verification and before any mutation**
(`gossip_runtime.rs:553-561`).

> Revision 1 specified a *strict* "reject any epoch older than current" rule.
> That would re-create the mesh-wide fail-closed churn cliff on every membership
> change that the two-sided window exists to prevent — the code comment at
> `peer_gossip.rs:131-146` says so explicitly. Use the existing window.

**Target the product issuer, not the lab one.** `issue_traversal_bundle_artifacts`
lives in `rustynet-cli/src/ops_e2e.rs`, which is orchestrator tooling —
`#[cfg(feature = "vm-lab")]` in `lib.rs:72`, and `main.rs:35` carries
`#[cfg_attr(not(feature = "vm-lab"), allow(dead_code))]` with a comment noting
its lab-facing `OpsCommand` surface is gated. Wiring the bridge there would ship
nothing. Name the production issuance path before writing code; **if none
exists, that is the finding and this spec stops until it is resolved.**

### 2.2 Validation — the part that makes the bridge safe

Today a self-asserted address becomes issuer-signed traversal authority only if a
human types it into `SRFLX_SPEC`. **The bridge removes the human, so the
validation the human was implicitly performing must become code.**

`signed_endpoint_hint_bundle` (`rustynet-control/src/lib.rs:2800-2925`) validates
only: TTL in `1..=86400`; `generated_at_unix != 0`; 1..=8 candidates; node-id
text; `relay_id` present iff `Relay`; endpoint parses as `SocketAddr`; port != 0;
no duplicate `(type, endpoint, relay_id)`. It does **not** reject loopback,
link-local, multicast, unspecified, or an address belonging to another node.
`0.0.0.0:1`, `127.0.0.1:1` and `169.254.169.254:80` all get signed today.

Required, at **both** ends (receiver-side is the load-bearing one — an issuer
fix alone leaves the learned-candidate path unguarded):

1. **Scope filter.** Reuse `classify_ip` / `AddressScope`; admit
   `Global | Private` only, matching what `build_candidate_set_from_cache`
   already does on the emit side (`daemon.rs:5372-5375`, `:5383-5386`).
2. **Self-assertion only.** A candidate learned from peer *X* may only ever be
   used as an endpoint **for X**. It must never become a candidate for any other
   node. This is the anti-laundering rule.
3. **Never displaces a policy-derived host candidate.** An auto-supplied
   candidate is additive and lower-priority; it cannot outrank or replace an
   operator/policy-configured endpoint.
4. **Advisory, never authorization.** A learned candidate may change *which
   endpoint is probed*. It must never widen ACL, membership, route, or exit
   authority — the same rule `NatProfile` already follows.

### 2.3 Do not reuse the endpoint-hint key for self-assertion

The endpoint-hint key is derived separately from the control-plane secret
(`rustynet-control/src/lib.rs:2278-2292`) — but it is **not** verify-only. It
**signs** endpoint-hint bundles (`:2917`), relay fleet bundles (`:2996`), relay
session tokens (`:3052`), and coordination records (`:3136`); the daemon holds a
signing copy (`daemon.rs:3980`) to issue relay session tokens. A relay session
token authorizes relay forwarding, so this is a **capability-granting** key.

Node self-assertions are already signed by the **node** key via the existing
gossip path, whose verifying keys come from membership. Keep it that way.
Reusing the endpoint-hint key for self-assertion would be privilege escalation.

> Revision 1 said the daemon "uses that key only to verify coordination
> records", copied from a source doc without verification. False.

### 2.4 Rate limiting — must be built, not reused

There is **no** gossip rate limiter. Grepping `rate.?limit|throttl|token.?bucket|
cooldown|budget` across `peer_gossip.rs`, `gossip_runtime.rs` and
`gossip_transport.rs` returns nothing; the only cadence control is
`GOSSIP_REMINT_INTERVAL_SECS = 30` (`gossip_runtime.rs:72`), a *sender-side*
heartbeat an attacker ignores.

This matters because gossip **re-pushes epidemically** — an accepted bundle is
forwarded to every known peer except sender and originator
(`gossip_runtime.rs:466-481`) — and the probe path emits up to
`MAX_PAIRS × SIMULTANEOUS_OPEN_ROUNDS` packets per peer per cycle
(`traversal.rs:61-64`: `MAX_CANDIDATES = 8`, `MAX_PAIRS = 24`, rounds 3). One
attacker datagram can therefore induce many members to probe an address it
named, from **their** source IPs. Required: a **per-source publication rate
limit** and a **per-source probe budget**, both new.

The §2.2 scope filter is what stops a *victim* address being named at all; the
limiter bounds the cost of everything else.

### 2.5 Candidate expiry — bind to rebind, not to a clock

A learned candidate must expire on **NAT-rebind signal**, not merely on a timer:
the address changes when the mapping is rebuilt, and a 30 s heartbeat leaves
peers probing a dead mapping until it fires. The trigger already exists —
`maybe_trigger_endpoint_change_refresh` (`daemon.rs:10424`), with
`traversal_endpoint_change_events` and `traversal_endpoint_fingerprint`
(`daemon.rs:6088`). Wire re-publication to it and keep the heartbeat as backstop.

Additionally bound learned candidates by a clock **strictly shorter than the
issued bundle TTL**, so a stale learned candidate can never outlive the authority
that would have replaced it.

## 3. Why there is no flag day now — and when that would change

d1 adds no message type and no version bump, so mixed-version concerns do not
arise.

Worth recording for whoever proposes one later: "gossip is not the dataplane" is
true **today** (gossip drain/mint run in the serve loop at `daemon.rs:10429-10432`,
outside `reconcile()`, and no gossip error increments `reconcile_failures`) —
but it **inverts** once the bridge lands. Then gossip starvation becomes
traversal-bundle starvation: `sync_traversal_runtime_state` errors on "contains
no usable runtime endpoints" (`daemon.rs:6330-6336`) →
`reconcile_failures++` → `promote_to_permanent_if_over_limit` at
`DEFAULT_MAX_RECONCILE_FAILURES = 5` (`daemon.rs:338`) → `restrict_permanent`
(`:9385-9389`), which is **not self-clearing**. That is the `fedora-x86-1`
failure mode, and a version split would apply it fleet-wide simultaneously.
**Any future gossip wire change must be justified against that, not against
"gossip is only discovery".**

Correspondingly, revision 1's §5.2 claim that "absence of candidates ⇒ host-only"
is false: the real behaviour is the hard error above plus a fail-closed
restriction (`daemon.rs:4948-4955`). A node with no usable candidates fails
closed; it does not silently degrade.

## 4. Test plan (every behaviour change mutation-verified)

| Test | Mutation that must make it fail |
| --- | --- |
| `learned_candidate_only_used_for_its_asserting_peer` | allow a candidate learned from X to be used for Y — **the laundering rule, §2.2.2** |
| `non_global_scope_candidate_is_refused` | drop the `classify_ip` filter; `127.0.0.1`, `169.254.169.254`, `0.0.0.0` accepted |
| `learned_candidate_never_displaces_policy_host_candidate` | let an auto candidate outrank a configured one |
| `learned_candidate_changes_no_authorization_outcome` | let candidates reach an ACL/membership/route path |
| `revoked_source_candidates_are_refused` | drop the revoked-source check |
| `epoch_window_stays_two_sided` | replace with a strict rule — re-creates the churn cliff |
| `per_source_publication_rate_limit_enforced` | remove the limiter |
| `per_source_probe_budget_enforced` | remove the budget |
| `candidate_expires_on_endpoint_fingerprint_change` | expire only on the timer |
| `learned_candidate_ttl_shorter_than_bundle_ttl` | allow it to outlive the bundle |
| `gossip_starvation_does_not_increment_reconcile_failures` | let it — proves §3's inversion is handled |

Existing tests that already cover revision 1's proposals, not to be rewritten:
`ops_e2e.rs:7662`, `:7667` (host preferred; srflx-equal-to-host dropped).

## 5. Acceptance — what actually proves d1

Not "the mesh re-forms". The deliverable is **self-renewal**, so:

> **Force a NAT rebind on one node, make no operator change, and require the
> peer to re-establish using a freshly discovered reflexive address.**

Surviving a TTL only proves bundle refresh; it does not prove the refreshed
bundle carries a *newly discovered* address, which is the entire point.

**Honest note on the venue:** the `xnet2` topology cannot prove the headline
cross-network case as it stands — its Mac guests are `fedora-utm-1` /
`rocky-utm-1` (currently stopped), and the Mac routes its default through a
Tailscale exit node (`server`, `100.123.146.3`, confirmed active 2026-07-30), so
it measures that node's **cone** NAT rather than the Mac's **symmetric** one.
Either clear the exit node for the test or state plainly that the symmetric case
remains unproven.

## 6. D14.d2 — punch timing (deferred, unchanged in substance)

Option A as selected: peer X self-signs "X proposes X↔Y punch at T, nonce=N";
Y verifies against membership, checks freshness and replay, and either honours T
or ignores it. Reuse `CoordinationReplayWindow`, `probe_start_unix`,
`SimultaneousOpenRuntime`. Domain constant `b"rustynet:punch_proposal:v1"`.

**Note the scope limit on the owner's decision:** the Option A/B fork in
`CrossNetworkTraversalDesignDecisions_2026-07-19.md` §3 was posed for **punch
timing only**. It does not authorise a candidate-publication protocol, which is
why d1 above uses the existing gossip path instead.

This *is* a genuine new message type. Requirements when it is built:

- Tag values must be **un-aliasable with any version byte** — high-bit-set
  (`0xA3`), never `0x01`/`0x02`/`0x03`, which collide with real wire versions
  (`peer_gossip.rs:69`, `:77`).
- The property to prove is "**no new-type datagram passes an old node's version
  check**", verified for every tag *and* every length, given the length check
  precedes the version check.
- The reverse direction must be analysed too: what a new node does with a legacy
  bundle.
- All **three** parse entry points must be updated, plus re-push:
  `GossipTransport::recv_bundle` (`gossip_transport.rs:203`),
  `GossipNode::ingest_wire_bundle` (`gossip_runtime.rs:436`),
  `IpcCommand::PushGossipBundle` (`ipc.rs:60-69`), and the epidemic forward
  (`gossip_runtime.rs:466-481`) must be told what to do with a non-bundle type.
- Justify the flag day against §3's inversion, not against "gossip is only
  discovery".

## 7. Still open

1. **Key rotation.** No rotation handling exists in `peer_gossip.rs` /
   `gossip_runtime.rs`, though `IpcCommand::KeyRotate` does (`ipc.rs:58`).
   Rotation invalidates in-flight publications and per-source
   `SeenSequenceState`. Decide whether the sequence resets, and what stops
   rotation becoming a replay-window reset primitive.
2. **IPv6.** v6-only nodes, v4/v6 racing, and interaction with the explicit
   IPv6-drop killswitch work at `c1e446a4`.
3. **Cap reconciliation.** The issuer caps candidates at 8
   (`rustynet-control/src/lib.rs:2884-2888`); gossip caps at 32
   (`peer_gossip.rs:126`). The issuer's 8 is binding — state the relationship
   rather than letting the mismatch surface as silent truncation.
4. **Production issuance path** (§2.1) — must be identified before code.
