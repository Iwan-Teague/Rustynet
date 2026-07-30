# D14.d — label disambiguation, punch timing, and refuted designs (revision 3)

**Status:** revision 3. Revisions 1 and 2 were both substantially wrong and are
recorded in §3 so their designs are not re-derived.

**Read this first:** the candidate-self-sustenance problem is **already solved on
paper**, by an approved plan this document does not replace and must not
duplicate:

> `documents/operations/active/TraversalSelfSustenancePlan_2026-07-23.md`
> — *APPROVED design, implementation not started.* Design A (per-node
> self-signed), adversarially reviewed 2026-07-23 with two blockers and four
> serious findings folded in before any code. Increments **I1–I6**, acceptance
> criteria, and §6 security invariants are all specified there.

**That plan is the authority.** This document contributes only three things it
does not cover: the `D14.d` label split (§1), the punch-timing spec (§2), and the
record of what was refuted (§3).

---

## 1. The label split

`D14.d` names two different deliverables across two documents:

| Source | Meaning |
| --- | --- |
| `CrossNetworkTraversalEvidence_2026-07-29.md` §4.4 | candidate **publication** |
| `CrossNetworkTraversalDesignDecisions_2026-07-19.md` §3 | punch **timing** |

Resolved:

- **D14.d1 — candidate publication ⇒ this is `TraversalSelfSustenancePlan`
  Design A.** Not new work, and **not to be re-specced here.** Track it there.
- **D14.d2 — punch timing.** Genuinely separate, genuinely unbuilt, specced in
  §2 below. **Strictly after d1**, because knowing precisely *when* to punch at
  an address you do not have is worth nothing.

Note the scope limit on the owner's Option A/B decision: the fork in
`CrossNetworkTraversalDesignDecisions_2026-07-19.md` §3 was posed for **punch
timing only**. It does not authorise a candidate-publication protocol.

## 2. D14.d2 — punch timing (deferred until d1 is live-proven)

Option A as selected: peer X self-signs "X proposes X↔Y punch at T, nonce=N".
Y verifies against membership, checks freshness and replay, then either honours
T or ignores it. Symmetric; no third party signs anything. Reuse
`CoordinationReplayWindow`, `probe_start_unix`, `SimultaneousOpenRuntime` — the
consumption side already exists. Domain constant
`b"rustynet:punch_proposal:v1"`, distinct from every other.

This **is** a genuine new gossip message type. Hard requirements, derived from
revision 1's failures:

- **Tag values must be un-aliasable with any wire version byte.** Use high-bit-set
  (e.g. `0xA3`). Never `0x01`/`0x02`/`0x03`: `0x02` **equals**
  `GOSSIP_BUNDLE_WIRE_VERSION = 2` (`peer_gossip.rs:77`) and `0x01` is a real
  historical version (`:69`). Revision 1's central safety claim failed on exactly
  this arithmetic.
- **The property to prove** is "no new-type datagram passes an old node's version
  check", verified for **every tag and every length** — the length check runs
  *before* the version check (`peer_gossip.rs:749-760`), so a short datagram
  returns `WireTruncated`, never `WireVersionMismatch`.
- **Analyse the reverse direction too:** what a new node does with a legacy v2
  bundle. Revision 1 never did.
- **All three parse entry points** plus re-push must handle the tag:
  `GossipTransport::recv_bundle` (`gossip_transport.rs:203`),
  `GossipNode::ingest_wire_bundle` (`gossip_runtime.rs:436`),
  `IpcCommand::PushGossipBundle` (`ipc.rs:60-69`), and the epidemic forward
  (`gossip_runtime.rs:466-481`).
- **Justify the flag day against §2.1 below**, not against "gossip is only
  discovery".

### 2.1 The flag-day argument that must be met

"Gossip is not the dataplane" is true **today** — gossip drain/mint run in the
serve loop (`daemon.rs:10429-10432`), outside `reconcile()`, and no gossip error
increments `reconcile_failures`. It **inverts** once Design A lands: gossip
starvation becomes traversal-bundle starvation → `sync_traversal_runtime_state`
errors (`daemon.rs:6330-6336`) → `reconcile_failures++` →
`promote_to_permanent_if_over_limit` at `DEFAULT_MAX_RECONCILE_FAILURES = 5`
(`daemon.rs:338`) → `restrict_permanent` (`:9385-9389`), which is **not
self-clearing**. That is the observed `fedora-x86-1` failure mode, and a version
split would apply it fleet-wide at once.

## 3. Refuted designs — recorded so they are not re-derived

### 3.1 Revision 1 — a new gossip message type for candidate publication. REFUTED.

- **Its safety claim was false by arithmetic** (`0x02 == 2`), so the message it
  said would ship first would have passed an old node's version check and been
  parsed as a bundle.
- **It violated its own anti-laundering rule** by feeding self-asserted
  candidates into issuance.
- **It asserted a gossip rate limiter that does not exist** — grepping
  `rate.?limit|throttl|token.?bucket|cooldown|budget` across `peer_gossip.rs`,
  `gossip_runtime.rs`, `gossip_transport.rs` returns nothing.
- It inherited a false claim about the endpoint-hint key verbatim from a source
  document without verifying it.

### 3.2 Revision 2 — "the daemon already publishes, just add a bridge". ALSO WRONG.

Revision 2 claimed the daemon already publishes candidates over gossip and only
local wiring was missing. **It builds them but never publishes them:**
`build_candidate_set_from_cache` (`daemon.rs:5367-5391`) runs every reconcile,
but **`attach_gossip_runtime` (`daemon.rs:5422`) has no production call site** —
its only caller is `daemon.rs:25776`, inside `mod tests` (starts `:15707`).
**Gossip is dormant in production.** Activating it is `TraversalSelfSustenancePlan`
increment **I1**, not a bridge.

### 3.3 The three issuance options. ALL THREE REFUTED on security grounds.

Proposed after finding that `rustynetd` never issues (zero hits for
`signed_endpoint_hint_bundle` under `crates/rustynetd/src/`) while the product
issuer is the operator-run CLI `execute_traversal_issue` (`main.rs:7057`,
ungated). All three were rejected by adversarial review:

| Option | Verdict |
| --- | --- |
| 1 — daemon self-issues | Least-bad, still fails §4 custody. A genuine **new** signing capability: on default config the daemon signs nothing (the `daemon.rs:3980` key path is doubly gated and `relay_session_local_token_issuer_enabled` defaults **false**, documented "only for reviewed lab/control-plane-collocated deployments"). |
| 2 — daemon exports, automation invokes the CLI | **Worse.** `execute_traversal_issue` calls `ControlPlaneCore::new`, deriving **all four** keys — the mesh root on the node. And its policy gate is decorative: roster and ACL come from argv, `set_membership_directory` is never called, so the RSA-0008 gate is skipped and an automated caller **authorizes itself**. Precedent exists and was deliberately disabled (`RUSTYNET_ASSIGNMENT_AUTO_REFRESH` defaults false). |
| 3 — anchor-side issuance | **Worst.** Already rejected twice in project docs; violates decision 2.1 ("no central coordination host"); mesh-wide steering authority from one node's compromise. **Degrades security even when honest** — re-issuance strips each candidate's cryptographic self-attestation (`source_node_id` *is* the signer's verifying key) and replaces it with "the authority says so". |

**Shared fatal property:** the signed payload
(`serialize_endpoint_hint_payload`, `rustynet-control/src/lib.rs:3904-3960`) has
**no per-candidate node attribution** — it binds candidates to a node *pair*, not
to an asserting node. `traversal_remote_node_id` (`daemon.rs:7293-7306`) accepts
a bundle if *either* id is local and infers the other as the peer, so it will
consume the mirror direction and apply candidates to the wrong node.
`build_verified_traversal_index` (`daemon.rs:6902-6936`) performs **zero
address→node binding**. And the endpoint-hint key is quadruple-purpose — it also
signs relay session tokens (`lib.rs:3052`) and relay fleet bundles (`:2996`), the
latter being the **only** allow-list constraining relay candidates
(`daemon.rs:14552-14569`). Any option that places it on a node hands out
relay-forwarding authority as a side effect.

**Design A avoids all of this by construction:** `source_node_id` *is* the
verifying key (`peer_gossip.rs:480`, `:503-517`), so a node cannot speak for
another, and it uses a domain-separated gossip-only sub-key
(`derive_gossip_signing_key`, `lib.rs:3565-3571`) built so a daemon compromise
cannot recover the identity secret.

### 3.4 A correction to a premise used throughout revisions 1–2

**Receivers DO validate candidate scope.** `validate_traversal_candidate_ip`
(`daemon.rs:14446-14494`, called `:14165`) rejects unspecified, loopback,
multicast, v4 link-local/broadcast, and v6 link-local/ULA; `srflx` must be global
unicast; `relay` must appear in a signed relay fleet. Earlier revisions claimed
no validation existed.

**But scope validation is not ownership validation.** A `Host` candidate may be
any global public address, so **a victim's public IP passes cleanly** — which is
precisely why `TraversalSelfSustenancePlan` §3.1 makes **return-routability
mandatory before programming** (review finding S3). That guard is the one that
matters, and it is not built.

## 4. Preconditions on Design A that are not yet built

Flagged here because they gate d2 as well. All three belong to
`TraversalSelfSustenancePlan`; none is new work invented by this document.

1. **Gossip activation (I1).** Dormant in production — see §3.2.
2. **Return-routability before programming (I3, review S3).** Mandatory. Without
   it Design A carries the *same* victim-IP reflector vector as the refuted
   options.
3. **`Private`-scope candidates need an explicit decision.** Accepted today
   (`peer_gossip.rs:571`, mirrored `daemon.rs:5373-5375`), which lets a member
   steer a peer at an RFC1918 address on that peer's own LAN — an internal-probe
   primitive. Return-routability mitigates it; the decision should be recorded
   rather than inherited.

Also note the **cold-start circularity** (plan I1d): the control-plane issuance
path cannot be deleted, so §3's no-fallback rule means the two paths must be
**exclusive with independent fail-closed**, never accept-via-either (plan S4).
The plan calls this the highest-risk implementation detail in the design.

## 5. Doc defect to fix separately

`CrossNetworkTraversalEvidence_2026-07-29.md` contains duplicated, contradictory
§4.3/§4.4/§4.4b blocks — one pair marked OPEN, a newer pair marked FIXED.
Revision 1 read the stale copy and claimed already-closed work as new.
Deduplicate it.
