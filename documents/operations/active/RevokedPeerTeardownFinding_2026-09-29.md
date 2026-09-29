# PF-1: a revoked peer keeps tunnel access to client nodes (2026-09-29)

**Status.** Product security finding, CONFIRMED by code reading and by an independent adversarial review. Live effect not yet observed; the new stage `live_owner_key_rotation_validation` (S1 of `LinuxSecurityStagesPlan_2026-09-29.md`) is built to witness it. Fix: option 1 below, being prepared in a fleet lane; it lands only after an independent review, the full gates, and the owner's confirmation.

## What happens

When membership revokes a node, the admin node tears the revoked peer down at once, but a client-role Linux node does not:

1. **Client nodes adopt membership only from file.** The client role refuses IPC `MembershipApply` (`crates/rustynetd/src/daemon.rs` `allows_command`, ~2298). `rustynet membership apply-update` writes the snapshot and log (`crates/rustynet-cli/src/main.rs` ~8098-8127), and the daemon adopts it on its next reconcile.
2. **That reconcile fails before any teardown.** `load_verified_membership` succeeds and persists the new watermark (`daemon.rs` ~5580-5592). `load_verified_auto_tunnel` then fails at `policy_gate_auto_tunnel`, because the node's still-valid assignment bundle names the revoked peer (~5646-5663). The error arm calls `force_fail_closed_or_restrict("auto_tunnel_reconcile_failed")` and returns (~10646-10666).
3. **Fail-closed does not cut the tunnel.** `force_fail_closed` (`crates/rustynetd/src/phase10.rs` ~8384-8391) only appends one terminal `drop` to the killswitch chain (`block_all_egress`, ~3918-3936). The chain already accepts established/related traffic and all egress on the tunnel interface (~3399-3412), so fail-closed stops only off-tunnel egress. That is the killswitch's documented purpose, and RN-03 (`daemon.rs` ~11278-11296) deliberately forbids tearing the dataplane down here.
4. **Nothing removes the peer.** `apply_revocation` (`phase10.rs` ~8694-8709, `backend.remove_peer`) runs only from the IPC apply path's newly-revoked diff (`daemon.rs` ~10199-10231). The backends have no fail-closed concept, gossip carries only an epoch stamp, and nothing re-mints assignment bundles on revocation (the issuer is operator-driven, `crates/rustynet-cli/src/ops_e2e.rs` ~3043).

## Severity

Anyone holding the revoked node's WireGuard key keeps encrypted tunnel reachability to and from every client-role peer that still lists it, in both directions. The window has no bound: WireGuard keys do not expire, and nothing re-issues the bundles. The same reconcile wedge also blocks every later membership or assignment update on those clients until an operator re-mints and distributes a bundle pair without the peer. Admin nodes, and exit egress through the authority, are not affected.

This contradicts the stated bar: Requirements ("rapid revocation/offboarding"; "key revocation propagation" as a security test) and SecurityMinimumBar (teardown before capability revocation). It is the peer-teardown analogue of the "state machine exists, wired on one path only" pattern recorded under §6.E.

## Fix options

1. **Recommended.** Extract the newly-revoked diff loop from the IPC apply path (`daemon.rs` ~10199-10231) into a helper, and run it in reconcile right after `load_verified_membership` succeeds, before `load_verified_auto_tunnel`. It calls `controller.apply_revocation` for each newly revoked managed peer. The revoked peer then leaves the interface on the first tick. The stale bundle still denies, so the node stays fail-closed until re-mint, but with no live revoked peer. This reuses existing, reviewed semantics, and the admin path's behaviour is unchanged.
2. On `PolicyDenied` naming a revoked peer, remove that peer and retry the bundle load once. Rejected: it parses error strings and leaves partial state.
3. Per-peer nft drops keyed on allowed IPs. Rejected: a new rule class, and the largest surface.

Open question for the owner: accept option 1, and confirm that fail-closed's "tunnel traffic keeps flowing" behaviour must exclude revoked peers.

## Evidence

- Found by: the S1 implementation lane (b43c), from code reading.
- Independent review: charter/reviews/REVIEW-pf1-revoked-peer-teardown-2026-09-29.md (CONFIRMED). The manager also checked the fail-closed rule order and the append-only drop in `phase10.rs`.
- Live proof: the S1 stage's verdict V6 ("every peer drops the revoked node within a stated bound") is expected to fail before the fix and to pass after it.
