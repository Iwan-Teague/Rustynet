# Relay Election Policy Design — Adversarial Review (2026-09-08)

**UNTRUSTED adversarial review (docs-only, no code changed) of
[`RelayElectionPolicyDesign_2026-09-08.md`](./RelayElectionPolicyDesign_2026-09-08.md)**,
verified against the tree at commit `c8c10d20`.

**VERDICT: BUILD-WITH-CHANGES.** The design's load-bearing claims are real: the
daemon already implements the switch/failback timing it relies on, the standing-
fallback + authority-mints/daemon-elects split is the right architecture, and the
rejection of reactive minting is sound. But four of its supporting arguments are
wrong or imprecise in ways that would misdirect the implementer: the §3.1
priority justification is semantically inert in the actual election code (and
test 4's mutation claim is false as stated), FC-1's blast radius couples relay
absence to DIRECT-arm teardown (an availability coupling the design never
states), FC-5's "silently ignoring" cell misdescribes the code path, and OD-1
mis-locates the lab fix in the netns substrate when the relay stage runs on
plain VMs of the flat 192.168.64.0/24 LAN. Required changes in §7; none change
the architecture.

---

## 1. Method

Every file:line claim in the design was read against the tree. The five attack
questions were answered by reading the actual selection, sync, validation, and
stage code (`daemon.rs`, `traversal.rs`, `lib.rs`, `main.rs`, `ops_e2e.rs`,
`relay_forwards_frame_validation.rs`, `network_profile.rs`), not by trusting the
design's characterization of them. Review dimensions: (A) is the problem
statement true; (B) does the chosen option beat the rejected alternatives;
(C) fail-closed on absent/malformed/stale/wrong-actor; (D) implementable as
specified; (E) what the design missed; (F) is the effort estimate believable.

## 2. Claim verification matrix

| # | Design claim | Verified evidence | Verdict |
|---|---|---|---|
| 1 | Daemon implements 3-failure switch to relay | `traversal.rs:904-923` (`on_direct_probe_timeout` engages `PathMode::Relay` when `consecutive_direct_failures >= relay_switch_after_failures`, comparison at `:910`); `RELAY_SWITCH_AFTER_FAILURES=3` at `traversal.rs:65` | ✅ TRUE |
| 2 | Failback on direct success | `traversal.rs` `on_direct_probe_success` (~:890-902) resets the failure counter → PathMode returns to direct | ✅ TRUE |
| 3 | Paced reprobes / FIS-0010 / FIS-0013 | `daemon.rs:3097-3159` (`traversal_probe_due_decision`: fresh-handshake-gone-stale re-races immediately at :3151-3153, stale paced by `next_reprobe_unix` at :3154, relay arm paced at :3156); FIS-0010 breaker withholds re-race `daemon.rs:7648-7657`; FIS-0013 forced re-race `:7637-7639` | ✅ TRUE |
| 4 | RFC1918 relay endpoint rejected | `daemon.rs:16789-16814` (`validate_runtime_relay_candidate_endpoint`): IPv4 rejects `is_private()‖is_link_local()‖is_broadcast()‖is_shared_carrier_grade_nat_ipv4` at :16798-16805 | ✅ TRUE (cite range 16815 in design is off by one, trivial) |
| 5 | TEST-NET-3 203.0.113.0/24 passes that validator | Not private, not link-local, not broadcast, not CGNAT → passes; called unconditionally at three sites (candidate, fleet index, fleet endpoint) | ✅ TRUE |
| 6 | Fleet check is skippable when fleet absent (FC-1 target) | `daemon.rs:16720` `if let Some(relay_fleet)` inside `select_runtime_relay_candidate_with_verified_fleet` (:16699-16724); both runtime callers pass `self.relay_fleet.as_ref()` (`daemon.rs:8013`, `:8037` region) | ✅ TRUE |
| 7 | Authority cannot see handshake freshness | `managed_peer_latest_handshake_unix` read at `daemon.rs:7613-7621` — daemon-side state, not authority-visible | ✅ TRUE |
| 8 | Bundle bounds: ≤8 candidates, TTL ≤86400, relay_id rules, policy gate | `lib.rs:2889-2893` (≤8), `:2874-2878` (TTL err, exact message matches), `:2941-2948` (relay requires canonicalizable relay_id), `:2949-2953` (non-relay with relay_id rejected), `:2918-2922` (policy gate) | ✅ TRUE |
| 9 | Session token TTL 120s, scope `forward_ciphertext_only` | `lib.rs:1726` (`MAX_RELAY_SESSION_TOKEN_TTL_SECS=120`), `:1723` (scope const) | ✅ TRUE |
| 10 | CLI `ops traversal-issue` can express a relay candidate manually | `main.rs:7022-7108` (`execute_traversal_issue`): candidates with `candidate_type` + `relay_id` from flags map straight to `EndpointHintCandidate`, signed under the assignment secret. No fleet input today — §10's proposed `--relay-fleet` flag is honest about that | ✅ TRUE |
| 11 | Lab mint sites never produce Relay | `ops_e2e.rs:3939-3958` (`traversal_candidates_for_target`: Host 900, Srflx 800, `relay_id: None`); mint sites `:3773/:3792/:3946` all `relay_id: None` | ✅ TRUE (QH-80's producer gap confirmed) |
| 12 | QH-80 relay healthy at RFC1918 bind | `QualityHardeningTodo_2026-07-25.md:6678-6743`: relay up at `RUSTYNET_RELAY_BIND=192.168.64.10:4500`, stage failed ~90s in, no Relay candidate in any bundle, `relay_session_configured=false` | ✅ TRUE |
| 13 | Flap breaker default off | `daemon.rs:2689` (`traversal_flap_breaker: false`) | ✅ TRUE |
| 14 | §3.1: relay priority "strictly below direct" orders election | `daemon.rs:16664-16684` (`select_runtime_traversal_endpoints`): direct = max-priority non-Relay, relay = max-priority Relay — **the two arms are never priority-compared against each other**; cross-arm election is purely the PathMode failure-counter state machine | ❌ FALSE as stated — see F1 |
| 15 | Test 4: raising relay priority above direct "silently changes election semantics" | Consequence of #14: priority only tie-breaks WITHIN an arm; a relay candidate outranking all direct candidates changes nothing about when relay engages | ❌ FALSE as stated — see F1 |
| 16 | FC-5: without a relay client the daemon "silently ignores" the relay endpoint | `daemon.rs:7661-7689`: with `relay_client` None the else-branch keeps the bundle's relay endpoint and it IS programmed via `configure_traversal_paths` at `:7691-7698` | ❌ IMPRECISE — see F3 |
| 17 | OD-1(a): fix goes "inside the lab's netns substrate" | `relay_forwards_frame_validation.rs:1-160`: the stage runs on PLAIN Linux VMs over SSH (assigned relay + two peers, nft direct-UDP block, SSH-direct helper chain) — not the netns substrate; the substrate's own address plan is `172.20.0.0/16` sites + `198.18.0.0/15` transit (`network_profile.rs:1298-1301`), which does not use TEST-NET-3 | ❌ MIS-LOCATED — see F4 |

Minor drift: two daemon.rs cites are ~5 lines off (no-usable-endpoints error is
at `:7601-7607` not 7596-7606; relay-removed hard failure at `:7623-7633` not
7618-7630). Substance unaffected.

## 3. Findings

### F1 (HIGH, documentation correctness): the priority justification is inert — priority never arbitrates relay-vs-direct

The design's §3.1 justifies priority 100 (below Host 900 / Srflx 800) as making
the relay "strictly the fallback," and its test 4 claims a mutation that raises
relay priority above direct "silently changes election semantics." Both are
wrong about this codebase. `select_runtime_traversal_endpoints`
(`daemon.rs:16664-16684`) picks the best non-Relay candidate for the direct arm
and the best Relay candidate for the relay arm independently; WHEN each arm is
used is decided exclusively by the `PathMode` state machine driven by
`consecutive_direct_failures` (`traversal.rs:904-923`). Candidate priority is
consumed in exactly two places: (a) within-arm max-priority selection
(`daemon.rs:16664-16684`), and (b) the direct arm's ICE pair ordering during
simultaneous open — where `ice_priority::CandidatePair` ordering applies and the
FIS-0009 `prior_rerank_pairs` (`traversal.rs:1299`, ±2-slot prior-modulated
re-rank, default OFF via `traversal_prior_rerank=false` at `daemon.rs:2688`) can
secondarily adjust it. Over-limit candidates are not truncated by priority —
they ERROR (`traversal.rs:1840-1851`, `CandidateCountExceeded`), so there is no
priority-ordered cut either.

The numbers themselves are fine and consistent with ICE convention (RFC 8445
§5.1.2.1 ordering spirit; RFC 5245 §4.1.2.1 type preferences 126/110/100/0 map
to the design's 900/800/100 shape; u16 vs the RFC's 31-bit priority is
irrelevant since this is an internal field, never ICE wire). The fix is
wording, not architecture: state that priority is (i) a within-arm tie-break,
(ii) documentation/convention signaling relay's fallback status, and (iii) an
input to direct-arm pair ordering where Relay candidates never appear
(`traversal_direct_probe_candidates`, `daemon.rs:16816-16839`, filters Relay out
— verified). Test 4 should assert within-arm semantics (relay arm selects the
highest-priority relay when several exist) rather than a cross-arm claim the
code cannot exhibit.

### F2 (HIGH, availability coupling): FC-1 as specified converts a fleet-distribution omission into whole-pair sync failure — including the DIRECT arm

FC-1 requires: a relay-carrying bundle with no verified fleet fails closed. The
sync path it hardens (`sync_traversal_runtime_state`, `daemon.rs:7556-7689`)
resolves the relay candidate via `select_runtime_relay_candidate_with_verified_fleet`;
today a `None` fleet skips the check (`daemon.rs:16720`). Making that check
unconditional means: any node whose fleet bundle file is absent (the normal
cause — `load_optional_relay_fleet` returns `Ok(None)` on missing file,
`daemon.rs:5098-5100`) but whose traversal bundle carries a relay candidate now
fails the ENTIRE sync (`TraversalSyncFailure::invalid`), tearing down the direct
paths too. That is an availability coupling the design never names. Three
concrete hazards follow:

1. **Rollout ordering.** The moment any authority mints relay candidates into
   bundles, every node that has not yet received fleet distribution hard-fails
   sync. A fleet-first, bundles-second rollout ordering must be a stated
   requirement of FC-1, not an implementation detail discovered in production.
2. **Fleet rotation/revocation.** Removing a relay from the fleet breaks sync
   for every node whose bundle still names it (fleet lookup error → whole-sync
   failure) until re-mint. The design's own TTL discipline (≤86400s) bounds the
   window but does not make it zero; the re-mint-before-rotation ordering used
   for traversal bundles (TraversalBundleFreshnessPlan precedent) needs stating.
3. **Scope.** For a peer not currently relay-active, failing ONLY the relay arm
   (log-loud, metric-flagged, direct continues) is the availability-preserving
   form; the existing hard failure for a peer whose ACTIVE path is relay
   (`daemon.rs:7623-7633`, "traversal authority removed the relay candidate
   required for active relay peer") already covers the case where it matters
   most. A fail-everything rule is defensible only as a deliberate
   strictest-secure choice with the coupling written down (AGENTS.md §2:
   ambiguity → strictest secure default, documented). The design does neither —
   it presents FC-1 as costless hardening ("0.5d mechanical").

### F3 (MEDIUM): FC-5's "silently ignoring" cell misdescribes the code — the relay endpoint is programmed even without a relay client

At `daemon.rs:7661-7689`, `let relay_endpoint = if self.relay_client.is_some()
{ …resolve… } else { relay_endpoint }`: with no relay client the bundle's relay
endpoint survives the else-branch and is passed to `configure_traversal_paths`
(`:7691-7698`). It is not ignored. An implementer working from the FC-5 cell
would believe FC-1 alone fences the fleet-absent case; in reality the
controller can still hold a relay endpoint programmed from a bundle even with
`relay_client: None`. Whether that residual is harmful depends on what the
controller does with a relay path it cannot session-establish (`relay_session_
refresh_due` returns `Ok(false)` when client None, `daemon.rs:8004-8026`) — but
the review standard here is accuracy of the design's own fail-closed table, and
this cell is wrong. It should read: "endpoint still programmed into controller
paths; no session can be established; FC-1 does not fence this — decide
explicitly whether a fleet-less relay endpoint may be programmed at all."

### F4 (HIGH, implementability): OD-1 mis-locates the lab fix — the relay stage is not in the netns substrate, and the substrate doesn't number anything in TEST-NET-3

The design's OD-1(a) says the fix is "inside the lab's netns substrate."
Verified against the stage: `relay_forwards_frame_validation`
(`orchestrator/stage/relay_forwards_frame_validation.rs:1-160`) runs on plain
Linux VMs over SSH — the run's assigned relay node plus two spare Linux peers on
the UTM shared LAN (192.168.64.0/24 flat L2 bridge), nft-blocking direct UDP,
restarting peer daemons, asserting relay-routed forwarding via the SSH-direct
helper chain. The netns substrate is a different facility with its own address
plan (`site_subnet_pool 172.20.0.0/16`, `transit_subnet 198.18.0.0/15`,
`network_profile.rs:1298-1301`) that does not use TEST-NET-3 at all. TEST-NET-3
IS the repo's established "public" convention (the endpoint-hijack stage's
`DEFAULT_ROGUE_ENDPOINT_IP=203.0.113.44`, relay daemon tests), so the choice is
right — but the mechanism must be restated for where the stage actually runs:

- the relay VM takes a secondary `ip addr add 203.0.113.x/32` on its existing
  NIC (Linux answers ARP for local addresses on the flat bridge, so no new L2
  infrastructure is needed), and peers reach it via host routes
  (`ip route add 203.0.113.x dev <nic>`) — or proxy ARP as the alternative;
- the HP-3 provisioner currently writes the relay bind as the guest's LIVE
  RFC1918 address (QH-80's record: `RUSTYNET_RELAY_BIND=192.168.64.10:4500`) —
  it must bind the TEST-NET-3 address instead, or the candidate minted at
  203.0.113.x will not match the listener;
- peer killswitch/DNS-failclosed posture must admit egress to 203.0.113.x
  (default-deny otherwise blocks it — that is the posture working as designed,
  so the lab profile needs the allowance stated, not the product weakened);
- the minted candidate must name `203.0.113.x:4500`, which passes
  `validate_runtime_relay_candidate_endpoint` (verified, matrix #5).

None of this is large, but as written the design sends the implementer to the
wrong facility. OD-1(b) (signed lab profile relaxing the validator) was
correctly rejected — weakening product validation for lab convenience is the
anti-pattern; keep that rejection.

### F5 (MEDIUM, missed interaction): per-node relay session cap becomes binding under correlated direct failure

The design adds a standing relay candidate to every bundle but never examines
the per-node relay SESSION limit (default 8, same family as
`MAX_CANDIDATES=8`/`MAX_PAIRS=24`, `traversal.rs:61-63`). A node with more than
8 managed peers that suffers correlated direct-path failure (the exact scenario
standing fallback exists for — e.g. a shared NAT middlebox change) will fail
over peer-by-peer and be REFUSED the 9th relay session. The design should state
the cap, state whether relay sessions are counted against it, and either raise
it for the relay path or document the bound as accepted.

### F6 (MEDIUM, under-weighted cost): standing candidates maximize fleet-wide metadata exposure over time

§5's traffic-analysis concessions (relay sees pair membership, timing, sizes;
ciphertext-only limits but does not remove metadata exposure) are honest as far
as they go. What is missing is the temporal argument: a standing candidate in
EVERY bundle means every pair maintains relay material at all times, so the
expected fleet-wide exposure window is "always," versus "only while failed
over" for reactive minting. With `forward_ciphertext_only` scope and 120s token
TTL (verified, matrix #9) the content risk is bounded; the metadata
relationship (who-pairs-with-whom, visible to a compromised relay even when
idle) is permanent. This does not flip the decision — reactive minting was
correctly rejected (F2's authority-blindness: the authority cannot see
`managed_peer_latest_handshake_unix`, `daemon.rs:7613-7621`, and peer-supplied
liveness would be a steering attack surface) — but the design should carry the
permanent-metadata line item in §5 so the owner decision (OD-4) is made with
the cost stated at full weight.

### F7 (LOW): compromised/coerced relay gains under standing — bounded, and mostly already covered

A compromised relay gains: (a) pair membership metadata for every pair whose
bundle names it (standing = all pairs), (b) forwarding visibility into
timing/size for pairs actively on relay, (c) denial-of-service by refusing to
forward (detectable via the daemon's session round-trip establishment —
`establish_session_with_round_trip` failure surfaces as sync failure,
`daemon.rs:8028-8082`). It does NOT gain: plaintext (ciphertext-only scope),
the ability to become a candidate (fleet membership is authority-signed;
`validate_runtime_relay_fleet_descriptor` enforces non-empty region ≤64 ASCII
and capacity>0, `daemon.rs:16765-16787`), or the ability to outrank within the
arm without the authority minting it so. Resource exhaustion at the relay is
bounded by capacity in the signed descriptor and the token TTL. This is an
acceptable residual profile; the design states most of it.

### F8 (LOW): effort table

FC-1 at "0.5d mechanical" is right about the diff and wrong about the
surrounding work: it must also decide the F2 scope question, thread the rollout
ordering into the distribution plan, and add the F2 failure-mode tests — call
it 1-1.5d. The selection-function and mint-side items are plausible at stated
size. The 2-3d lab-producer estimate holds ONLY under F4's flat-bridge
secondary-IP mechanism; had the fix genuinely required netns-substrate rework,
it would be larger. Total ≈9-11d remains believable.

## 4. Answers to the five attack questions

1. **Standing vs reactive minting.** Standing is correct. Reactive was rejected
   for the right reason (authority cannot observe handshake freshness —
   verified; peer-supplied liveness would let a peer steer relay placement).
   The under-weighted costs of standing are F2 (availability coupling via FC-1)
   and F6 (permanent fleet-wide metadata exposure) — both fixable by scoping
   and documentation, neither flips the decision. Ciphertext-only IS sufficient
   for content; it is NOT sufficient for metadata, and §5 should say the
   exposure is permanent under standing (F6).
2. **Does the daemon really implement switch/failback timing?** YES —
   matrix #1-#3: `on_direct_probe_timeout` engages relay at ≥3 consecutive
   failures (`traversal.rs:904-923`), success resets and fails back
   (~:890-902), reprobes are paced with FIS-0010/0013 hooks
   (`daemon.rs:3097-3159`, `:7637-7657`). Zero-refusal at config parse
   (`traversal.rs:1364-1366`). The design's central implementation claim holds.
3. **Priority numbers vs code and RFC 8445.** Numbers are conventionally sound
   (900/800/100 mirrors RFC 5245 §4.1.2.1's 126/110/…/0 shape; RFC 8445
   §5.1.2.1's ordering spirit), but the design's claim that they ORDER the
   relay-vs-direct election is false — see F1. Priority is a within-arm
   tie-break plus convention; the election is the failure-counter state
   machine.
4. **Can `ops traversal-issue` express a relay manually?** YES — matrix #10
   (`main.rs:7022-7108`): `--candidate` entries carry type and `relay_id`,
   signed under the assignment secret. Fleet material has no CLI input today;
   §10's `--relay-fleet` flag proposal is honest about that gap.
5. **OD-1: RFC1918 rejection + TEST-NET-3 routability.** Rejection verified
   (`daemon.rs:16789-16814`); TEST-NET-3 passes validation (verified). But the
   fix is mis-located (F4): the stage runs on the flat 192.168.64.0/24 VM LAN,
   not the netns substrate, so the mechanism is secondary /32 + peer host
   routes (+ provisioner binding the TEST-NET-3 address + killswitch egress
   allowance). Salvageable with the mechanism restated; option (b) product
   weakening correctly rejected.

## 5. Fail-closed review (C dimension)

| Input | Design's posture | Verified / corrected |
|---|---|---|
| Fleet absent + relay candidate present | FC-1 fails closed | Correct target (`daemon.rs:16720` today skips) — but scope the failure (F2) or document the direct-arm coupling |
| Fleet malformed | descriptor/endpoint validation errs | `daemon.rs:16740-16787` — empty enabled fleet errs, per-descriptor region/capacity validated ✅ |
| Candidate endpoint RFC1918/loopback/multicast/etc | rejected | `daemon.rs:16789-16814` ✅ (three unconditional call sites) |
| relay_id absent on Relay candidate | err | `daemon.rs:16726-16738` ✅ |
| Bundle over-limit / TTL over / policy deny / relay_id on non-relay | err | `lib.rs:2889-2961` ✅ |
| Stale bundles | TTL + watermark discipline | `daemon.rs:5091-5121` (verifier key + watermark + max age) ✅ |
| Relay client absent, bundle has relay endpoint | FC-5 "silently ignored" | WRONG — endpoint still programmed (`daemon.rs:7661-7689`, `:7691-7698`); restate (F3) |
| Active-relay peer loses candidate | hard failure | `daemon.rs:7623-7633` ✅ (pre-existing, correctly cited) |

## 6. Disposition of the design's FC/OD items

- **FC-1** — BUILD-WITH-CHANGES: keep the fail-closed direction; decide and
  document scope (relay-arm-only vs whole-sync), make fleet-first rollout
  ordering an explicit requirement, cover rotation, and correct the effort.
- **FC-2/FC-3/FC-4** (mint-side validation, deterministic selection, TTL
  riding existing bounds) — BUILD-AS-WRITTEN; all bounds verified (matrix #8,
  #9), selection determinism (enabled → region → highest priority → smallest
  relay_id) is implementable in `select_runtime_relay_candidate_with_verified_
  fleet` as specified.
- **FC-5** — restate per F3 before implementation.
- **OD-1** — TEST-NET-3 stands; rewrite the mechanism per F4 (flat-bridge
  secondary address, provisioner bind, killswitch allowance). Option (b)
  rejection stands.
- **OD-2 (flap-breaker default)** — legitimate open decision; the default-off
  (`daemon.rs:2689`) is the conservative status quo and the switch/failback
  counters already damp single-probe flapping.
- **OD-3 (region taxonomy)** — orthogonal, safe to defer; descriptor
  validation already constrains the field shape.
- **OD-4 (authority-visible flow metadata)** — keep, but carry F6's
  permanent-exposure line item into the decision.

## 7. Required changes (the WITH-CHANGES list)

1. Rewrite §3.1's priority justification and test 4 per F1: priority =
   within-arm tie-break + convention; test asserts within-arm selection
   semantics.
2. FC-1: name and decide the availability coupling (F2). Whichever scope is
   chosen, add fleet-first rollout ordering and rotation-before-revocation to
   the rollout section, and add failure-mode tests for both.
3. Correct the FC-5 fail-closed table row per F3.
4. Rewrite OD-1(a) per F4: mechanism = secondary TEST-NET-3 /32 on the relay
   VM's NIC + peer host routes on the flat 192.168.64.0/24 bridge (or proxy
   ARP), HP-3 provisioner binds the TEST-NET-3 address, peer killswitch egress
   allowance for 203.0.113.0/24, candidate minted at that address.
5. Add the relay session cap interaction (F5) to §10's rollout notes.
6. Add the permanent-metadata-exposure line to §5/OD-4 (F6).
7. Bump FC-1 effort to 1-1.5d (F8); total stays ≈9-11d.

None of these change the architecture: standing fallback, authority-mints /
daemon-elects, deterministic fleet selection, existing TTL bounds, and
unchanged failback all stand as designed.

## 8. Evidence audit

All citations above were read directly on this tree at `c8c10d20` (worktree
`state/edit-worktrees/edit-1788880189340-75210-0`). Key files:
`crates/rustynetd/src/daemon.rs` (:2688-2693, :3097-3159, :4983-5041,
:5091-5121, :7556-7698, :8004-8082, :13206-13218, :16664-16839),
`crates/rustynetd/src/traversal.rs` (:61-65, :890-923, :1299-1324, :1364-1366,
:1840-1851), `crates/rustynetd/src/lib.rs` (:1723-1747, :2865-2961),
`crates/rustynet-cli/src/main.rs` (:7022-7108),
`crates/rustynet-cli/src/vm_lab/ops_e2e.rs` (:3773-3792, :3939-3958),
`crates/rustynet-cli/src/vm_lab/orchestrator/stage/relay_forwards_frame_validation.rs`
(:1-160), `crates/rustynet-cli/src/vm_lab/network_profile.rs` (:1298-1301),
`documents/operations/active/QualityHardeningTodo_2026-07-25.md` (:6678-6743).
This review is UNTRUSTED output; re-verify citations before implementing.
