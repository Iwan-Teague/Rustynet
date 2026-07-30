# Gossip candidate scoping — ACL-scope mode, and a co-location gate that must wait

**Status:** plan, revised after adversarial review. **Increment A (co-location
gate) is WITHDRAWN — do not build it as specified.** The operator decision in §2
stands and is unaffected.
**Parent:** `TraversalSelfSustenancePlan_2026-07-23.md`.
**Precedence:** CLAUDE.md §3/§4 — fail-closed, default-deny, no runtime fallback.

---

## -1. Why the co-location gate was withdrawn (read before re-proposing it)

Three independent findings, each fatal on its own. All verified against code.

**1. Its only input is attacker-chosen.** The rule was "accept a private host
candidate from P only if P's advertised srflx shares an IP with ours". `v4_srflx`
is a plain field in the bundle P signs. The signature proves the bundle came
from P — **not that the srflx is P's real mapping**. Nothing corroborates it:
gossip pushes to the peer's *overlay* address, so the datagram source is a mesh
IP, never a public one. A member reads the victim's public IP from the victim's
own gossip bundle and mints `{v4_host: [192.168.1.50], v4_srflx: [<victim's
public IP>, <its own real srflx>]}` — 32 candidates are allowed, so it keeps its
own reachability. Gate passes. **This is the parent plan's own review finding
S3, and the gate was built on the exact field S3 warns about — it does not merely
fail to stop the S3 assertion, it *rewards* it, converting "claim a victim's IP"
from a reflection trick into a capability unlock.**

**2. It would be a no-op today, and only contingently useful later.** The
gossip-admitted index is not the probe source. `applied_endpoints` has **no
production reader** (only the self-audit module
`gossip_revoked_readmit_audit.rs:132-133`); the daemon discards the ingest
summary (`let _ = node.ingest_inbound_bundle(...)`, `daemon.rs:5587`). Probes are
planned from the **signed traversal envelope**
(`traversal_direct_probe_candidates`, `daemon.rs:6326`). So filtering the gossip
index stops no probe that exists. After I4 it becomes useful only if I4 sources
from the *filtered* index — a dependency the plan never stated.

**3. Its fail-closed rule would have been a self-inflicted outage.**
`local_stun_candidates` is empty on a default node: `poll_stun_results` returns
early when there is a transport blocker **or** `stun_servers.is_empty()`
(`daemon.rs:5748-5752`), and `traversal_stun_servers` defaults empty. The
project's own evidence records that NAT traversal needs a userspace backend at
all. "Absence denies" is the right instinct when absence is *exceptional*; here
absence is **the default**, so the rule would have denied 100% of private
candidates permanently — breaking the same-LAN fast path that the plan's own
test existed to protect, and re-opening the §4.4b regression.

**Two further bypasses**, either of which defeats it even once 1–3 are fixed:
- **Wrong lane.** The rule scoped to *host* candidates, but `Private` is accepted
  across all four lanes, srflx included. `192.168.1.50:8080` in `v4_srflx` never
  meets a host-only gate.
- **Wrong family.** §5 claimed IPv6 ULA is "refused outright". It is **accepted**
  — `fc00::/7` classifies as `Private` and is allowed, pinned by
  `accept_bundle_allows_private_and_global_candidates`. A v4-only guard is
  bypassed on day one by moving the target into `v6_host`.

### What a real co-location gate would require

**Its input must be something the sender cannot choose.** The only such signal
available is the **observed source address of a return-routability probe** —
which means such a gate lands **after I4**, not before it, and is built on the
probe result rather than on a self-asserted field. Anything keyed on bundle
contents is self-attestation wearing a gate's clothing.

Also required whenever it is built: cover **all four lanes and both families**
with family correspondence (a v6 srflx match must not license a v4 private
candidate), and build a gossip status surface — `rejected_counts` is a `pub`
map with **no reader**, so "observable rather than silent" is not currently true
of any gossip counter.

### Corrections to the withdrawn text, so they are not inherited
- `v4_srflx`/`v6_srflx` live at `dataplane_candidates.rs:296-297`, not
  `peer_gossip.rs`. The gate must read `bundle.candidates`, **not**
  `flatten_endpoints`, which flattens all four lanes into one `Vec<SocketAddr>`
  and destroys the host/srflx distinction it needed.
- Re-push is `gossip_runtime.rs:507-522`, and it forwards the **original,
  unfiltered** bundle — so receiver-side filtering is per-node opt-out, never
  containment.
- Return-routability cannot bound a *probe* harm: it is established **by** the
  probe and gates *programming*. Listing it as a bound on CGNAT risk was circular.
- `ipv6_parity_supported` is **not** an operator posture selector (its default
  `false` is the strict branch); it is a capability attestation. Only
  `fail_closed_ssh_allow` stands as precedent in §2.
- This gate was a **new fifth guard**, not part of parent-plan I3. I3's four are
  ACL-scope (§2 below), plausibility (already done, stricter), return-routability
  (I4), and the per-origin rate limit (landed, `021c1ef0`).

---

## 0. Two harms that are constantly conflated

`Private`-scope candidates (RFC1918: `192.168.x`, `10.x`) create **two
different** problems. Almost every muddle in this area comes from treating them
as one.

| | Harm | Who is hurt | Fixed by |
| --- | --- | --- | --- |
| **H1 privacy** | every member learns my home/office LAN address | me | ACL scoping (§2) |
| **H2 recon** | a member makes *my* node probe addresses inside *my own* network | me, silently | **unsolved** — needs a post-I4 gate keyed on probe-observed source (§-1) |

They need different mechanisms, and a fix for one does not fix the other.

## 1. The co-location gate (H2) — ~~RECEIVER-side~~ **WITHDRAWN**

> **WITHDRAWN 2026-07-30 — everything in §1 below is superseded by §-1 and must
> not be implemented.** It is retained verbatim because it is the design a later
> reader will re-derive independently, and §-1's three refutations are only
> legible against the text they refute. The rule below is unsafe (its input is
> attacker-chosen), ineffective (it filters an index nothing probes), and its
> fail-closed clause is an outage on default configuration. Several of its
> file:line citations are also wrong — see §-1's correction list.

### 1.1 Correction to the original proposal

The gate was first described as sender-side: "only send my private address to
peers on my network." **That cannot work here.** Gossip re-pushes epidemically
(`gossip_runtime.rs:466-481`), so a sender cannot control who ultimately
receives a bundle. Sender-side gating would need a pairwise channel — a new
message type and wire version, which was already specced, reviewed and rejected
(`D14dGossipCandidateAndPunchSpec_2026-07-30.md` §3).

**Receiver-side gating needs none of that, and it is sufficient for H2**, which
is the harm actually raised. The recon harm is not that an attacker's address is
*disclosed*; it is that *my* node is induced to *probe* my own network. A
receiver that refuses to act on such a candidate is not probing anything —
regardless of what reached the wire.

Stated plainly so it is not re-litigated: **this fixes H2, not H1.** H1 is §2.

### 1.2 The rule

> Accept a `Private`-scope **host** candidate from peer P only if P's advertised
> server-reflexive address shares an IP with one of ours. Otherwise drop **that
> candidate**, keep the rest of the bundle.

The data exists on both sides already — no protocol change:
- Our own reflexive address: `local_stun_candidates` (`daemon.rs:3744`),
  populated by the existing STUN path.
- The peer's: `v4_srflx` / `v6_srflx`, carried in every bundle
  (`peer_gossip.rs:296-297`), visible at `flatten_endpoints` (`:917`).

Two nodes reporting the same public IP are behind the same NAT, so a private
address from such a peer is plausibly on our LAN. A node on another network
cannot satisfy this without controlling our public IP.

### 1.3 Per-candidate, NOT whole-bundle — and why that differs from plausibility

The neighbouring plausibility guard (`reject_unreachable_candidates`,
`peer_gossip.rs:560`) rejects a bundle **whole**, and the parent plan is explicit
that whole-bundle rejection is the stricter, correct default there.

**This guard must not copy that**, and the reason is not squeamishness about
strictness:

> A perfectly honest peer on another network *legitimately* advertises a private
> host candidate — it is genuinely its LAN address, it is simply useless to us.
> Rejecting the bundle whole would discard that peer's **srflx** candidate too,
> which is the one we actually need to reach it. Whole-bundle rejection here
> would break normal cross-network operation, and would be reverted.

The distinction: plausibility rejects candidates that are *never valid for
anyone* (loopback, multicast, unspecified) — hostile or malformed. Co-location
rejects candidates that are *valid for the sender but unusable by this
receiver*. Different classes, different dispositions. Record this next to the
code; it is exactly the kind of asymmetry a later reader "tidies up".

### 1.4 Residual risk, accepted explicitly

**CGNAT.** Many unrelated subscribers share one carrier public IP. Two mesh
members behind the same CGNAT would pass the gate without being on the same
LAN. Bounded by: both are already mesh members; the candidate is only *probed*,
never programmed, until return-routability confirms it (§1.5); and the probe
targets an RFC1918 address inside a network both already sit in. Materially
smaller than today's "any member can point any peer at any private address", but
**not zero**, and it should not be described as zero.

### 1.5 Dependency — this is half a control

The co-location gate stops the *probe*. It does **not** authorise *use*.
Programming a gossip-sourced endpoint remains gated on return-routability
(parent plan I3/I4, review finding S3): an endpoint is never written to
`peer.endpoint` until a probe round-trip proves the peer answers there. Both are
required; neither substitutes for the other.

## 2. ACL scoping (H1) — BOTH modes, operator-selectable

**Operator decision, 2026-07-30: both modes must exist and the choice is the
user's.** Recorded here because it is a standing requirement, not an
implementation detail to be resolved by whoever writes the code.

| Mode | Behaviour | Trade |
| --- | --- | --- |
| **`repush` (DEFAULT)** | R forwards P's candidates to Q only if **Q** may reach P — R evaluates the ACL from each recipient's perspective | Best privacy: a member never learns the endpoints of members it has no right to reach. Slower convergence — fewer nodes hold any given address, so a permitted pair may need more gossip rounds to connect |
| **`index`** | R indexes P's candidates only if **R** may reach P; re-push unrestricted | Faster convergence, simpler. Weaker: every member learns every member's endpoints, filtering only at point of use |

**Default is `repush`** — the safe posture, per §3's strictest-practical-default
rule. `index` must be an explicit opt-in.

Why this is a legitimate knob and not a §3 violation: §3 forbids **runtime
fallback** — silently degrading to a weaker path when the strong one fails. This
is a deployment posture chosen at configuration time and enforced consistently,
which the codebase already does elsewhere (`fail_closed_ssh_allow`,
`ipv6_parity_supported`).

**Two cautions to carry into implementation, not to forget:**
1. **Precedent is poor.** `allow_egress_interface=true` is, per the security
   review, "a one-boolean full-IPv4 killswitch off-switch" (PF-01). A weakening
   boolean in this codebase has form. `index` mode must be loud in status
   output, not silent.
2. **Two paths, two test matrices**, on top of a parity matrix already spanning
   role × OS. Both modes need coverage; a mode that is never exercised is a mode
   that rots.

## 3. Implementation

**Increment A (co-location gate): WITHDRAWN.** See §-1. Any future version is
post-I4 and keyed on probe-observed source addresses.

**Increment B (ACL mode, §2): the remaining work.** Config knob (`repush`
default | `index`), the daemon computing scoped sets and pushing them into the
`GossipNode` via setters — mirroring how `set_revoked_peer_ids` is already fed
from `sync_gossip_data_plane` — plus a per-target allow matrix for `repush`.
Prerequisite: a gossip status surface, since `index` mode must be loud and no
gossip counter is currently readable.

## 4. Test plan — for Increment B (the Increment A suite is withdrawn with it)

| Test | Mutation that must make it fail |
| --- | --- |
| `private_host_candidate_from_non_colocated_peer_is_dropped` | remove the srflx-match check — the recon primitive returns |
| `private_host_candidate_from_colocated_peer_is_kept` | over-tighten to drop all private candidates — breaks the same-LAN fast path (the §4.4b regression, already fixed once) |
| `non_colocated_peer_keeps_its_srflx_candidate` | switch to whole-bundle rejection — **§1.3's anti-revert test**; cross-network operation breaks |
| `empty_local_reflexive_set_denies_all_private_candidates` | default to accept when the local set is unknown |
| `global_scope_candidates_are_unaffected_by_the_gate` | apply the gate to public addresses too |
| `dropped_private_candidates_are_counted` | drop silently |

## 5. Open, deliberately

- **IPv6 ULA (`fc00::/7`)** is the v6 analogue of RFC1918 and is currently
  refused outright by the plausibility guard. Confirm before implementing
  whether the co-location gate should admit ULA under the same rule, or whether
  the existing refusal is the intended posture. Do not change v6 behaviour by
  accident while editing the v4 path.
- **Multiple local reflexive addresses** (multi-homed, or v4+v6): decide whether
  matching *any* is sufficient or the family must correspond. Recommend
  family-corresponding — a v6 srflx match should not license a v4 private
  candidate.
