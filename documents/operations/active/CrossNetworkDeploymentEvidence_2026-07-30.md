# Live deployment + fleet state — 2026-07-30

Records a real deploy of `efee52c1` to the `xnet3` pair and the fleet state
found while doing it. Written because the session's biggest open risk was
resolved here empirically, and because two long-standing beliefs about the lab
turned out to be stale.

## 1. What was deployed, and the risk it retired

`93dbd421` made membership decoding strictly stricter: a node whose persisted
snapshot lacks a `capabilities` field now **refuses to load it and fails
closed**. That was argued safe from reading code — nothing in the repo *writes*
such a file — but "nothing in the repo does" and "nothing on those machines
does" are different claims, and only the second decides whether a fleet boots.

Deployed `efee52c1` (release, 5,927,104 bytes, built on `ubuntu-kvm-1`) to both
`xnet3` guests, one at a time, keeping the second as a live control. Old binary
backed up on each as `/usr/local/bin/rustynetd.bak.<epoch>`.

**Result: the break is retired.** Both nodes reloaded their existing snapshots
across a real daemon restart.

| Check | `xnet3-ubu-b` (.137) | `xnet3-ubu-a` (.26) |
| --- | --- | --- |
| `state` | `DataplaneApplied` | `DataplaneApplied` |
| `bootstrap_error` / `last_reconcile_error` | none / none | none / none |
| `reconcile_failures` | 0 | 0 |
| `membership_epoch` / `active_nodes` | 2 / 2 | 2 / 2 |
| `path_live_proven` / `direct_peers` | true / 1 | true / 1 |
| membership-error lines in journal | 0 | 0 |

Verified with **real traffic, not the status fields**: `ping` across the mesh
addresses `100.92.185.100 → 100.95.237.46` returned **5/5 packets, 0% loss,
15.193 ms avg**. That distinction matters — §4.3 of
`CrossNetworkTraversalEvidence_2026-07-29.md` records `path_live_*` disagreeing
with observable reality, so the self-report alone is not evidence.

`wg show` returns nothing on these guests; they run the **userspace** backend
(`transport_socket_identity_label=wireguard-linux-userspace-shared-authoritative-transport`),
so there is no kernel device to query. Not a failure.

**What this does NOT prove.** Both guests sit on `192.168.121.0/24` behind one
KVM host, so this is a **same-subnet** validation, not a cross-network one. And
it exercises none of the session's IPv6 verifier work: production hardcodes
`ipv6_parity_supported: false`, so `hard_disable_ipv6_egress()` always runs and
the nft branch stays dormant. Unit tests remain that work's only proof.

## 2. Fleet state found

Two **separate meshes**, not one:

- **`xnet3`** — `xnet3-ubu-a` ↔ `xnet3-ubu-b`, both KVM guests on
  `192.168.121.0/24`. Healthy, 0 failures in 57,217 reconcile attempts, live
  handshakes. **Same host, same subnet — not a cross-network mesh.**
- **`xnet2`** — `fedora-x86-1` plus the Mac `Fedora` / `rocky_10` guests. This
  *was* the cross-network mesh. Now `FailClosed`,
  `restriction_mode=Permanent`, `bootstrap_error=reconcile failure threshold
  exceeded: 3220`, `traversal_alarm_reason=traversal_bundle_is_stale`.

`xnet2` failed on its own — 3,220 accumulated failures and 654 pre-expiry
refresh attempts over days, bundles long past the 120 s TTL. Its two Mac peers
were later stopped during unrelated resource cleanup, so restoring it needs
those guests restarted **and** a re-mint.

## 3. Does the mesh depend on Tailscale? No — measured

Asked directly, and answered with evidence rather than architecture diagrams:

- Peer endpoint actually in use: `192.168.121.26:51820` — a **local** address,
  not a `100.x` tailnet address.
- Route taken: `192.168.121.26 dev enp1s0 src 192.168.121.137` — straight out
  the guest's own NIC. No tunnel, no gateway hop.
- **Tailscale is not installed on the guests at all**: no binary, zero
  interfaces.

So disconnecting the tailnet would not affect the `xnet3` dataplane. It would
remove the *operator's* ability to reach and observe the machines. The
separation is: **rustynet connects nodes to each other; Tailscale connects the
operator to the nodes.** The operator's machine is not a mesh member — this Mac
runs no `rustynetd` and has no `/var/lib/rustynet` — which is precisely why the
tailnet is needed to administer the lab.

## 4. Two stale beliefs corrected

- **The Mac and `ubuntu-kvm-1` repo lineages have converged.** They were
  recorded as mutually unknown. `f22be5af` is now a clean **ancestor** of
  `efee52c1`; the box fast-forwarded 97 commits with no merge. Both sides are on
  the same commit for the first time in this programme.
- **"Everything will be stale" was wrong.** The `xnet3` pair had been running
  since 2026-07-29 23:42 and was still holding fresh handshakes and refreshing
  its own credentials. Only `xnet2` had decayed.

## 5. What cross-network still needs — the real blocker

Per §4.4 of `CrossNetworkTraversalEvidence_2026-07-29.md`, the mechanism is
proven but **the automation is not**. A node discovers its own reflexive address
(`netcheck` reports it, correctly bound to the WG listen port) and **nothing
carries it to the issuer**. It must be hand-collected into `SRFLX_SPEC`, and it
changes whenever a NAT binding is rebuilt. That is why a cross-network mesh
decays into `FailClosed` unattended, which is exactly what `xnet2` did.

§4.4b has the same root: only one candidate per peer is ever published, so
same-site peers hold only each other's public address and need NAT hairpinning,
which many routers refuse. The bundle format already carries a candidate *list*
(`Host | ServerReflexive | Relay`); nothing populates it.

Publishing discovered candidates over gossip (**D14.d**) closes both. The
primitive exists and is unused: `signed_endpoint_hint_bundle` is signed with a
separate endpoint-hint key derived from the control-plane secret, and the daemon
currently uses that key only to verify coordination records.

**Also still open (§5 of the same doc):** the Mac routes its default through a
Tailscale exit node, confirmed still active today (`server`, `100.123.146.3`;
default route via `utun8`). Mac egress therefore presents that node's **cone**
NAT, not the Mac's own **symmetric** one. The hard traversal case has never been
exercised.
