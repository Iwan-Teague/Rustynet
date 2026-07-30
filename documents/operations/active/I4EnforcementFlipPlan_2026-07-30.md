# I4 — flip traversal enforcement to gossip (revision 2: WITHDRAWN, with findings)

**Status: WITHDRAWN before implementation.** Revision 1 was adversarially
reviewed and found not merely incomplete but **actively harmful**: implemented
as written it would have shipped the S3 victim-IP reflector it was designed to
close. Nothing was built.

This file is now a **findings record**. It exists so the next attempt starts from
what is true about the code rather than from the plausible-sounding model that
revision 1 assumed. Parent (still authoritative):
`TraversalSelfSustenancePlan_2026-07-23.md`.

---

## 1. The finding that matters most — "a probe status means the endpoint was proven" is FALSE

Revision 1's entire design rested on this sentence:

> "When a probe status exists the endpoint has been confirmed reachable."

**It is false.** `phase10.rs:6109-6131`, the `TraversalDecision::FailClosed` arm
— reached when the ICE race is exhausted and *nothing answered*:

```rust
TraversalDecision::FailClosed { reason, .. } => {
    let endpoint = evaluation.direct_candidates.iter()
        .max_by_key(|candidate| candidate.priority)      // straight from the bundle
        .map(|candidate| candidate.endpoint)...?;
    self.reconfigure_managed_peer(node_id, endpoint, PathMode::Direct)?;  // PROGRAMMED
    Ok(TraversalProbeReport {
        decision: TraversalProbeDecision::Direct,
        reason: TraversalProbeReason::DirectProbeExhaustedUnprovenDirect,
        ...
```

The failure path **programs the highest-priority candidate anyway** and reports
`decision: Direct`. `TraversalProbeDecision` has only `Direct | Relay`
(`phase10.rs:250-254`) — there is no failure variant to observe. Existing
behaviour is pinned by
`daemon_runtime_host_only_signed_direct_probe_exhaustion_stays_programmed_without_restricting`
(`daemon.rs:23907`), which asserts exactly this: status present,
`decision == Direct`, `latest_handshake_unix.is_none()`, endpoint programmed.

Worse, on a non-due probe the retained status's `selected_endpoint` is
**overwritten with the currently programmed endpoint** (`daemon.rs:6446-6459`).
So the status tracks **what is programmed, not what was proven**.

**The attack revision 1 would have enabled.** `priority` is an attacker-chosen
field on the candidate (`daemon.rs:2105`). A member asserts a victim's IP at max
priority; the race fails because the victim does not speak WireGuard; the
FailClosed arm programs the victim's IP; a status now exists; revision 1's
"Attested → program it" rule then programs it. **That is S3 — delivered by the
guard written to prevent S3.**

### What "attested" must actually mean

`decision == Direct` **and** `reason ∈ {ExistingFreshHandshake,
FreshHandshakeObserved}` **and** `traversal_handshake_is_fresh(latest_handshake_unix, now)`
(`daemon.rs:6760-6764`). A `Relay` decision attests the *relay*, not the peer.

And separately: **`phase10.rs:6109-6131` must stop programming unproven
endpoints for gossip-sourced candidates at all** — a phase10 change revision 1
never scoped. Gating only the consumer leaves the producer programming victim
IPs on its own.

## 2. The other fatal findings

### 2.1 "Per-peer instead of set-equality" is a fail-open

`PeerConfig.endpoint` is **non-optional** (`rustynet-backend-api/src/lib.rs:72-83`)
and arrives **already populated from the control-plane assignment bundle**
(`daemon.rs:9077`). `apply_traversal_authority_to_peers` exists to *overwrite* it.

So a per-peer "Pending → don't error, hold" leaves the **control-plane endpoint**
programmed. That is precisely "gossip missing → silently use control-plane" —
the accept-via-either fail-open that revision 1's own §2.3 and the parent
review's S4 forbid. Revision 1 proposed the anti-pattern it named two sections
earlier, because it never stated what `peer.endpoint` contains on entry.

### 2.2 "Status is rebuilt each pass" is wrong — and the error causes a deadlock

Revision 1 cited `daemon.rs:3779-3781` for this. That is a **doc comment on a
different field** (`keepalive_estimators`). In fact the status is cloned forward
on a non-due probe (`daemon.rs:6446-6459`).

So "no status" is **not** the common transient case; it is **structurally the
cold-start path**. `sync_traversal_runtime_state` returns early unless the
controller is `DataplaneApplied | ExitActive` (`daemon.rs:6257-6263`); the
controller starts at `Init` (`phase10.rs:5132`) and reaches `DataplaneApplied`
only inside `apply_dataplane_generation` (`phase10.rs:5327`), which runs **after**
`apply_traversal_authority_to_peers` returns `Ok` (`daemon.rs:9134 → 9163`).

**Hard bootstrap deadlock under revision 1:** no status → Pending → nothing
previously programmed to hold → cannot program → apply never reaches
`DataplaneApplied` → never gets a status. On every cold start, every restart, and
after every fail-closed.

### 2.3 The bootstrap provenance label needs a signed wire change

No provenance field exists on `TraversalBundle`, `TraversalCandidate`, or either
envelope (`daemon.rs:2101-2143`). The parser uses a strict allow-list
(`is_allowed_traversal_key`, `:12587-12617`), rejects unknown keys outright
(`:13997-14001`), pins `version == "1"` (`:14028-14032`), and the signature
covers every non-signature line.

The label **must be inside the signed payload** — an unsigned one is forgeable,
and an attacker labelling its own candidate "control-plane seed" walks straight
back into the unattested branch. That is a versioned wire-format change with a
mixed-fleet migration story (an old daemon rejects a new-format bundle whole),
none of which revision 1 scoped.

### 2.4 The plumbing this plan assumed does not exist

The gossip ingest result is **discarded** — `let _ = node.ingest_inbound_bundle(...)`
(`daemon.rs:5587`). `applied_endpoints` has no production reader outside a
self-audit module. Both `build_verified_traversal_index` (`:6902-6936`) and
`traversal_direct_probe_candidates` (`:14648`, called `:6326`) read the **signed
control-plane envelope**. Revision 1 reasoned throughout about a gossip-sourced
index that is not wired to anything.

### 2.5 Data-model mismatch

`CandidateSet` (`dataplane_candidates.rs:293-298`) is `v4_host`/`v6_host` as
`Vec<IpAddr>` — **no port** — plus `v4_srflx`/`v6_srflx` as `Vec<SocketAddr>`.
It carries **no priority, no candidate type, and no relay lane**.
`TraversalCandidate` needs all of them. Priority is not cosmetic: it drives both
the race order and the FailClosed `max_by_key` selection in §1.

## 3. Corrections to revision 1's own claims

- **`restrict_permanent` is not "not self-clearing".** A fully successful
  reconcile apply resets `restriction_mode = None` (`daemon.rs:9225-9227`). The
  real bite is different and worth stating correctly: while restricted, **every
  mutating IPC command is refused except `StateRefresh`** (`daemon.rs:7716-7719`),
  so the remediation surface collapses fleet-wide.
- **Patching one function does not remove the outage.**
  `sync_traversal_runtime_state` has **parallel** fail-closed set checks
  (`daemon.rs:6301-6311`, `:6317-6323`, `:6330-6336`) which clear the status map
  and return `Err`, firing `restrict_recoverable` + `force_fail_closed_or_restrict`
  at `:4948-4954`. That forces FailClosed, which arms the counting path anyway.
- **Two different set comparisons were conflated.** `apply_...` compares the
  index against the incoming **assignment** peer list (`:6796-6820`);
  `sync_traversal_runtime_state` compares it against
  `controller.managed_peer_ids()` (`:6289-6311`).
- **The `fedora-x86-1` 3,220-failure incident could not be verified from a
  repo artifact.** It was observed live in this session, and the *mechanism* is
  confirmed by code — but no citable artifact exists, so it should be described
  as an observation, not a record.

## 4. What a correct I4 requires — the real scope

In dependency order. Items 1–2 are prerequisites revision 1 assumed were done.

1. **Wire gossip candidates into an index at all** (§2.4), including the
   `CandidateSet` → `TraversalCandidate` mapping: host-candidate port source,
   priority assignment, relay lane, address family (§2.5).
2. **Close `phase10.rs:6109-6131` for gossip-sourced candidates** so the producer
   stops programming unproven endpoints (§1).
3. **Redefine "attested" as handshake-proven** — decision *and* reason *and*
   freshness (§1).
4. **Specify the not-yet-attested case explicitly** as "read the controller's
   programmed endpoint (`phase10.rs:5887-5891`), and **deny when there is none**"
   — and solve the cold-start deadlock (§2.2). Note this needs `&mut self`;
   `apply_traversal_authority_to_peers` currently takes `&self` (`daemon.rs:6775`).
5. **Bound the hold on attestation age, not candidate freshness.** If a peer
   stops gossiping there is no new candidate whose freshness expires — the bound
   must come from when it was last *proven*, which implies persistent attestation
   state.
6. **Extend the fix to `sync_traversal_runtime_state`'s parallel checks** (§3).
7. **Build a gossip status surface.** `rejected_counts` (`gossip_runtime.rs:242`)
   has no production reader, so a frozen peer would be indistinguishable from a
   healthy one. Extending the existing netcheck fields
   (`traversal_probe_result` / `traversal_probe_reason` / `path_live_proven`,
   `daemon.rs:6088`) is cheap. **Ship-blocker, not a nice-to-have.**
8. **Reconcile with the 2026-07-30 operator decision** that ACL scoping ships in
   two modes (`GossipCandidateScopingPlan_2026-07-30.md` §2) — the mode changes
   what "missing from the index" means.

Unaddressed and still open: relay fallback (`daemon.rs:6352-6362` errors when an
active-relay peer loses its relay candidate), membership-epoch interaction, exit
nodes mid-flip, and IPv6 family selection
(`select_runtime_traversal_endpoints`, `:14496-14516`, does no family filtering).

## 5. The lesson worth keeping

Both times a guard was designed in this area, it would have introduced the harm
it targeted — the co-location gate rewarded S3, and this plan's "attested" rule
programmed the S3 endpoint. The shared cause is the same:

> **A signal was trusted because of what it is named, not because of what it
> proves.** `TraversalProbeStatus` sounds like proof of reachability. It is a
> record of what was programmed, and it is written on the failure path too.

The check that would have caught both, cheaply: before relying on any signal,
read the code that *writes* it — especially its failure branch.
