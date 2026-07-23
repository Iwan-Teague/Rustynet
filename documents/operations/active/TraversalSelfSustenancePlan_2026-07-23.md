# Traversal Self-Sustenance Plan — Autonomous Signed-Traversal Re-Issuance — 2026-07-23

**Status:** APPROVED design, implementation not started. This is the execution
plan for closing the sole remaining Linux `--node` live-lab failure
(`live_network_flap_validation`), which is the canary for a **real production
gap**: on default config a Rustynet mesh fails closed ~120 s after setup because
nothing re-issues the signed traversal-authority state.

Owning failure: `live_network_flap_validation`. Acceptance: that stage goes
**green in a real `--node` live-lab run** (mesh self-sustains through the
unattended >120 s window), with all §7 gates passing.

Design provenance: root-caused + designed 2026-07-22/23 (loop journal
#388–#402). Design reviewed by an independent model pass (confirmed Design A,
added the epoch-binding / ACL-scoping / rate-limit hardening). **Adversarially
reviewed 2026-07-23** — two blockers and four serious findings folded in before
any code: B1 (guard-ordering window — guards now land before the enforcement
flip, I3 → I4), B2 (`register_peer` push_addr has no membership source + circular
cold-start — now I1d), S1 (load a derived gossip-only sub-key, not the raw
`node_identity` secret — I1a), S3 (return-routability required before programming
a self-asserted endpoint — I3), S2 (epoch-binding is propagation-bounded, not an
independent timer; needs a skew window — I2), S4 (dual path made exclusive +
independently fail-closed — I4). Anti-replay parity and revocation-epoch coupling
were checked and confirmed intact.

---

## 1. Problem statement (the real gap, not a lab artifact)

A production mesh on default config **self-destructs 120 s after the last
control-plane distribution**, with no orchestrator present to re-issue. This is
NOT NAT traversal failing — the mesh literally fail-closes because its signed
traversal-authority state goes stale.

`live_network_flap_validation` is the first and only live-lab stage that runs the
daemon **continuously unattended for >120 s** (it waits up to 300 s for a
baseline handshake, blocks WG udp/51820, waits for recovery). Every earlier stage
passes only because the orchestrator keeps restarting daemons and re-distributing
bundles during setup. So the stage is a genuine canary, and the fix is a product
mechanism, not a lab hack.

## 2. Root cause (definitive, file:line)

1. Hardened daemon is a pure local-custody consumer BY DESIGN:
   `StateFetcher::new_from_daemon` (`crates/rustynetd/src/daemon.rs:427`) forces
   `trust_url`/`traversal_url`/`assignment_url`/`dns_zone_url = None`
   ("Hardened daemon paths only consume pinned local custody artifacts").
   `fetch_traversal` therefore always returns `Skipped` — the daemon never
   self-fetches signed state over the network.
2. `refresh_traversal_hint_state` (`daemon.rs:4701`) populates `traversal_hints`
   **only** from `load_traversal_bundle_set(&self.traversal_bundle_path, …,
   self.traversal_max_age_secs, …)` — the custody file, 120 s freshness enforced.
3. `apply_traversal_authority_to_peers` (`daemon.rs:6463`) uses **only**
   `traversal_hints`; None/stale → error "traversal authority requires valid
   signed traversal state" → fail-closed. STUN probe results
   (`traversal_probe_statuses`) can only refine the *endpoint* within an
   already-valid authority; they do not keep the authority alive.
4. `DEFAULT_TRAVERSAL_MAX_AGE_SECS = 120` (`daemon.rs:251`);
   trust/auto-tunnel/dns = 300 s.
5. Enforcement is on by default: `impl Default for DaemonConfig` sets
   `auto_tunnel_enforce: true` (`daemon.rs:1701-1730`) →
   `traversal_authority_mode()` returns `EnforcedV1`
   (`daemon.rs:6455-6460`) unless explicitly overridden.
6. The authority bundle is minted **control-plane-side** — `ControlPlaneCore`
   (`crates/rustynet-control/src/lib.rs:2234`) holds an `endpoint_hint_signing_key`
   derived from the mesh root `signing_secret` (`lib.rs:2260-2293`); the lab minter
   is `ops_e2e.rs::issue_traversal_bundle_artifacts` (~3522), per-pair
   (source→target), distributed ONCE by the Bootstrap-group `distribute_traversal`
   stage. There is no autonomous re-issuance anywhere in the daemon.
7. NOT clock skew (guests read UTC == host). NOT a flap-recovery bug (both nodes
   are already permanently FailClosed before the flap block is applied).

## 3. Design decision — hardened Design A (per-node self-signed)

**Chosen: A.** Each node **self-signs its own** traversal candidates with its
node identity key and gossips them; membership authorizes *who* is a peer, the
self-signed candidate provides *how to reach* it. Rejected alternative **B**
(anchor re-mints + delivers the control-plane bundle) because B requires putting
the **mesh root signing secret on a running daemon** — a key-custody expansion
the architecture deliberately avoids (the daemon holds only its own node key) —
and makes the authority a freshness SPOF. A adds no new secret, reuses the
already-built D2.5 gossip data plane, self-sustains via epidemic gossip, and is
the unique factorization consistent with "root secret never online, zero
external infrastructure, peer-distributed."

Why A is safe on the trust model: per-pair endpoint-hint authority was **never
access control** — the default-deny ACL (`rustynet-policy`) + WG static keys
decide who may talk to whom. The hint was only ever "where to try dialing." A
node self-asserting its own reachability is legitimate (it controls its own
traffic).

### 3.1 Mandatory hardening (from the design review — all in scope)

- **Epoch-bind every CandidateSet** (reinforces revocation; NOT an independent
  timer). Fold the membership epoch into the signed preimage and verify on accept.
  Because the signer of a freshness proof is the peer itself (it never voluntarily
  goes silent), revocation must ride a positive signal; epoch-binding means an
  epoch advance makes prior-epoch sets unverifiable, so revocation propagation also
  expires the traversal assertions. **Caveat (review S2):** the epoch bumps on
  *every* membership update, so the accept rule needs an epoch-skew window (or a
  coarser revocation-scoped counter) to avoid a mesh-wide fail-closed churn cliff
  on benign joins — and expiry is bounded by membership-propagation latency, not a
  clock. See I2.
- **Return-routability before programming** (review S3). Never program a
  gossip-sourced endpoint until a probe round-trip confirms the peer answers there.
  Plausibility alone cannot stop a member from asserting a *victim's* public IP
  (which passes as "valid"), turning peers into WG-handshake-init reflectors. See
  I3.
- **ACL-scope gossip application/propagation** (Tailscale-netmap style) — apply
  and re-push a peer's candidates only to nodes with an ACL right to reach it.
  Prevents epidemic disclosure of every member's home/cellular endpoints to
  members with no reason to have them. (A privacy control, not an authorization
  one.)
- **Per-origin rate limit + candidate plausibility checks** — bound how often a
  source can mint and reject implausible candidates (loopback/reserved/etc.), so a
  compromised member cannot watermark-fast-forward to flood gossip.

## 4. Grounding (resolved before implementation)

- **Q1a key binding = YES.** A node's membership `public_key` (`[u8;32]`,
  `rustynet-control/src/lib.rs:1344/1379/2064`) is its **Ed25519 identity
  verifying key** (enrollment binds `enrollee_key.verifying_key()`), which is
  exactly the gossip identity (`GossipNode` `local_node_id =
  signing_key.verifying_key()`; `mint_bundle_with_timestamp` sets
  `source_node_id = signing_key.verifying_key()`, `peer_gossip.rs:369-386`). The
  node_id → key mapping comes from the verified membership snapshot; **two caveats
  from review:** verification uses the derived **gossip sub-key**, not the raw
  identity key (S1 / I1a); and `register_peer` also needs a `push_addr` that
  membership does **not** carry — its provenance + cold-start bootstrap are
  specified in I1d (B2), not assumed.
- **Q1b anti-replay parity = YES.** Gossip anti-replay is a per-source
  strict-monotonic `sequence: u64` persisted in `SeenSequenceState`
  (`peer_gossip.rs:219-249`), mirroring the membership watermark spool. Per-source
  is exactly right for self-signed candidates.
- **Gossip DRIVE is already wired in prod.** The main loop already calls
  `drain_gossip_inbound()` + (gated by `gossip_mint_attached()`)
  `maybe_run_gossip_mint(cached_candidates)` (`daemon.rs:10036-10039` and
  `10285-10288`). `attach_gossip_runtime` (`daemon.rs:5230`) is the seam; its only
  non-test call is `daemon.rs:24983` (a test, with a throwaway key).
- **Daemon is a pure verifier today.** It loads WG keys + public verifier keys
  and signs nothing; `--signing-key`/`--owner-signing-key` belong to
  `run_membership_add_peer` (admin CLI), not the daemon. Node identity private-key
  custody exists in `rustynet-crypto` (`store/load_private_key("node_identity")`)
  but the daemon does not load it. **Giving the daemon a signing identity is a
  prerequisite (I1a below) and is itself security-sensitive.**

## 5. Implementation increments

Each increment: scoped `cargo check`/`test` while editing; the full §7 gate list
before landing; commit as one logical change. No TTL widening in any increment.
Fail-closed posture preserved throughout (missing/stale/unverifiable → deny).

### I1 — Activate the gossip data plane in the production daemon

- **I1a (security-sensitive): daemon GOSSIP-ONLY signing sub-key** *(revised per
  review S1 — do NOT load the raw `node_identity` secret).* The node's
  `node_identity` private key is its **core control-plane authenticator** (its
  verifying key authorizes traversal/assignment bundles to remote admins). Loading
  that raw secret into the long-lived, network-exposed daemon would let a daemon
  compromise forge the node's control-plane identity — a smaller re-run of the very
  objection used to reject Design B. Instead **derive a domain-separated
  gossip-only sub-key** from `node_identity` (mirror
  `derive_endpoint_hint_signing_key`, `rustynet-control/src/lib.rs:3527`, with a
  distinct `GOSSIP_SIGNING_SEED_INFO_V1`) and load ONLY that into the daemon.
  Publish the gossip sub-key's verifying key in membership as a separate field (or
  derive-and-verify it deterministically from the node's identity verifying key) so
  peers verify gossip against the sub-key, not the identity key. Full §4 custody
  bar on whatever secret the daemon does hold — OS-secure storage or
  encrypted-at-rest fallback, strict perms, startup permission checks, passphrase,
  `zeroize`, never logged. Enforcement point + negative test (group/world-readable
  key → fail closed at startup).
- **I1b: construct + attach.** In `run_daemon`/`DaemonRuntime::new`
  (`daemon.rs:9742`) build `GossipNode::new(node_identity_signing_key,
  gossip_watermark_path)` + a `GossipTransport` bound on the gossip port (51821),
  and call `attach_gossip_runtime`. Guard: only when membership/identity are
  present; fail closed otherwise. The `--gossip-watermark` flag already exists
  (`main.rs:2920`).
- **I1c: register peers from membership.** Each reconcile, populate
  `register_peer` (node_id → gossip-subkey verifying key) from the verified
  membership snapshot, and drive `set_revoked_peer_ids` /
  `set_anchor_gossip_seed_peer_ids` from the same snapshot (helpers already exist,
  `anchor_gossip_seed_peer_ids_from_membership`, `gossip_runtime.rs:570`).
- **I1d: peer transport addressing + first-candidate bootstrap** *(new, per review
  B2 — MUST land before the I3 fail-closed rewire).* `register_peer` requires a
  `push_addr: SocketAddr` (`gossip_runtime.rs:227`), but **`MembershipNode`
  (`rustynet-control/src/membership.rs:154-163`) carries no address field** — the
  data source named in an earlier draft does not exist. Specify push_addr
  provenance explicitly: the gossip push destination is the peer's **overlay
  (tunnel) address** for already-established peers, so gossip rides the encrypted
  mesh (not a raw-Internet address that wouldn't traverse NAT anyway). Resolve the
  circular cold-start — an orphaned NAT'd node has no bundle AND no gossip candidate
  yet, and cannot receive a tunnel-addressed push before its tunnel exists: on
  first join a node still gets its initial traversal state through the existing
  control-plane distribution / enrollment path (I3 keeps that path, see below), and
  the anchor/relay seed set (`set_anchor_gossip_seed_peer_ids`) provides the
  reachable gossip entry point until the direct mesh converges. Document + test the
  bootstrap ordering: control-plane/enrollment seeds the first valid state → gossip
  takes over sustenance once a tunnel + peers exist. No node is ever left with
  neither source.
- Acceptance: a running lab daemon mints + ingests gossip (non-zero
  `accepted_count`, peers registered from membership); no behavior change to
  enforcement yet.

### I2 — Epoch-bind the CandidateSet

- Add the membership epoch to `signing_preimage` (`peer_gossip.rs:295-316`) and to
  mint/accept; bump `GOSSIP_BUNDLE_WIRE_VERSION` (`peer_gossip.rs:61`). Update the
  D2.5 wire/runtime tests.
- **Granularity — resolve before coding (per review S2).** The membership epoch
  increments by exactly 1 on **every** update, not just revocations
  (`membership.rs:453`). So a naive "reject epoch < local verified epoch" would
  invalidate every peer's prior-epoch CandidateSet mesh-wide on any join or
  capability change, forcing a re-mint + gossip re-converge with a fail-closed
  traversal window on **each** membership change — a churn cliff the 120 s freshness
  bound may not absorb. Two acceptable resolutions, pick during implementation:
  (i) accept a small **epoch skew window** (current or previous N epochs) so a
  single membership change does not blackhole traversal, with the independent 120 s
  freshness check still bounding staleness; or (ii) bind to a **coarser
  revocation-scoped counter** (bumped only on revoke) rather than the every-update
  epoch. Revocation is already epoch-coupled (a revoke is a `MembershipUpdateRecord`
  that bumps the epoch, and `accept_bundle` already drops revoked sources via
  `set_revoked_peer_ids`, `gossip_runtime.rs:469`), so epoch-binding *reinforces*
  revocation but is **not** an independent time bound — it expires a revoked peer's
  assertions only as fast as epoch-advance *propagation* (same channel as the
  revocation itself). Do not describe it as more than that. A co-partitioned victim
  still at epoch E remains exposed to a revoked-but-uninformed peer's E-bound set
  until it learns E+1 — the residual, accepted, bounded by membership propagation.
- Acceptance: a CandidateSet older than the accepted epoch window fails
  verification; a single benign membership change does NOT blackhole the whole mesh.

> **Ordering rule (per review B1): every guard below lands BEFORE enforcement is
> flipped to program from gossip.** The guards (I3 — ACL-scope, plausibility,
> rate-limit, return-routability) filter the verified index while programming is
> still off, so there is no interval where `apply_traversal_authority_to_peers`
> writes an unvalidated `peer.endpoint`. I4 flips the switch only once all of I3 is
> active. Do NOT land the enforcement flip first "for back-compat."

### I3 — Candidate validation pipeline (guards, landed while programming is OFF)

All applied at gossip ingestion / to the verified candidate index, before any
enforcement consumes it. Each independently testable with programming still off.

- **ACL-scope.** Apply/re-push a peer's candidates only to nodes with a
  `rustynet-policy` default-deny ACL right to reach it (netmap-style). A node with
  no ACL path to P neither indexes, programs, nor re-pushes P's candidates —
  prevents epidemic disclosure of every member's endpoints.
- **Plausibility.** Reject a candidate whose endpoint is loopback / unspecified /
  reserved / link-local as a *reachable* endpoint (reuse
  `dataplane_candidates::AddressScope`).
- **Return-routability (per review S3 — mandatory, not optional).** A member may
  self-assert a **victim's** public IP as its own endpoint, which a pure
  plausibility check passes (it is a "valid" public IP) — turning every peer into a
  WG-handshake-init reflector at the victim (N-amplification DoS). So **never
  program a gossip-sourced endpoint until a probe round-trip confirms the peer
  actually answers there** — gate programming on the existing
  `traversal_probe_statuses` / STUN-handshake path (`daemon.rs:6518`), which already
  attests reachability. A self-asserted endpoint that does not answer is never
  written to `peer.endpoint`.
- **Per-origin rate limit + fast-forward guard.** Bound mint-accept rate per source;
  guard against watermark fast-forward flooding.
- Acceptance: a candidate that is out-of-ACL-scope, implausible,
  non-return-routable, or flooding is dropped from the index — verified while
  enforcement still uses the control-plane path (no programming from gossip yet).

### I4 — Flip the fail-closed enforcement (exclusive path)

- Teach `apply_traversal_authority_to_peers` (`daemon.rs:6463`) to source each
  managed peer's reachability from **that peer's fresh, epoch-current, self-signed,
  return-routable, ACL-scoped gossip candidate** (the I3-validated index), gated by:
  (a) peer is an authorized member, (b) signed by that peer's gossip sub-key,
  (c) freshness within bound, (d) anti-replay via the per-source sequence,
  (e) return-routability confirmed. Missing/stale/unverifiable/unconfirmed → fail
  closed.
- **Exclusive precedence, both fail-closed (per review S4).** The gossip path and
  the residual control-plane bundle path are **not** accept-via-either. Define a
  single explicit precedence (gossip-preferred once converged; control-plane only as
  the bootstrap/first-state seed per I1d), and require **each** path to fail closed
  independently on absent/stale — never let the weaker source silently satisfy the
  gate. The control-plane path remains only as the I1d cold-start seed, not a
  standing parallel authority.
- Acceptance: with gossip converged, a peer with a fresh validated candidate is
  programmable past 120 s with no control-plane re-distribution; with none, fail
  closed; the two paths never combine into a fail-open.

### I5 — Integration test + gates

- `crates/rustynetd/tests/`: a 3-peer mesh **sustains traversal past 120 s with
  no re-distribution** (extend the existing `gossip_three_peer_mesh` shape).
  Negative pins: stale-epoch, wrong-signer, replayed-sequence, ACL-scoped-out,
  implausible-candidate, **non-return-routable (victim-IP) candidate**, and
  **dual-path never-fail-open** → deny. Full §7 gate list green.

### I6 — Live-lab verification

- Run the Linux `--node` suite; `live_network_flap_validation` must go **green**
  (mesh self-sustains through the unattended window). Verify the appended row in
  `documents/operations/live_lab_node_run_matrix.csv`. Note: a *failing*
  network_flap costs ~3.5 h (giant baseline-wait loop); a passing one is fast.
  Also stabilize the flaky `anchor_validation` loopback tcp probe (nc-free
  `/dev/tcp` "exit None" signal-kill under a tight SSH-command timeout) so it does
  not add noise to the verification run.

## 6. Security invariants that MUST hold (do not regress)

- Fail closed on missing/stale/unverifiable traversal state (no fail-open path),
  including the dual gossip/control-plane path: exclusive precedence, each side
  fails closed independently (I4 / review S4).
- No guard-free programming window: every ingestion guard (ACL-scope, plausibility,
  return-routability, rate-limit) is active BEFORE enforcement programs from gossip
  (I3 before I4 / review B1).
- Never program a self-asserted endpoint that has not passed return-routability
  (review S3) — closes the WG-handshake reflection/DoS vector.
- No widening of the 120 s / 300 s TTLs (anti-replay/freshness).
- Anti-replay preserved: per-source strict-monotonic sequence, persisted;
  `unregister_peer` retains the seen-sequence ledger (revocation must not enable
  a later Restore replay — see `gossip_runtime.rs:244`).
- Revocation is epoch-coupled and reinforced by epoch-binding, but bounded by
  membership-propagation latency, NOT an independent timer (review S2). Do not
  claim more.
- Daemon holds only a domain-separated **gossip-only sub-key**, never the raw
  `node_identity` control-plane secret (review S1); §4 custody bar, never logged,
  `zeroize`d.
- No secret material in gossip payloads or logs (§10.6).

## 7. References

- Root cause + design: loop journal #388–#402 (`rustynet-mcp-lab-state`
  `get_loop_journal`).
- Dataplane traversal track: `RustynetDataplaneExecutionPlan_2026-05-18.md`
  (D2.5 gossip is "Complete (end-to-end)" but was wired-but-dormant; this plan is
  the activation + traversal-enforcement integration).
- Parity mandate: `CrossPlatformRoleParityPlan_2026-06-21.md` (network_flap is the
  last Linux `--node` red).
