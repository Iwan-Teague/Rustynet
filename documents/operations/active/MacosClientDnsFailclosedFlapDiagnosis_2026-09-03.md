# macOS-client validate_baseline_runtime DnsFailclosed — multi-factor diagnosis (2026-09-03)

**Status: OPEN. Two merged fixes (551efad7 resolver ordering, c53fb247 in-bootstrap ScopedResolverOnly) are correct + live-confirmed but do NOT close this. The remaining failure is multi-factor.**

## What is proven (validate-time guest sampler, macos-utm-1, runs labrun-1788399658718 / -1788401031069 / -1788402302075)
1. Fix-A works: `/etc/resolver/rustynet` (scoped mesh resolver → 127.0.0.1:53535) is PRESENT at validate.
2. The pf DNS-block floor is NEVER installed: `pf-rules: 0`, `apple-g: 0`, check reports "anchors scanned: []" — in every run, including during the pinned window.
3. The primary resolver stays the LAN ("Home") — general DNS untouched (correct for ScopedResolverOnly).
4. POSTURE FLAP: the daemon starts running (sampler line 7048), then at line 7163 (~02:35:32) PINS Ethernet DNS → 127.0.0.1 for ~13s (7 of 1162 samples), then UNPINS it (reverts to "none set"). The pin appears AFTER the daemon is running — the daemon applied it, not prior-run residue. During the pinned window pf-rules is STILL 0.

## Interpretation
- The macOS node is intended as a plain mesh CLIENT (bootstrap defer log: "deferred scoped_resolver_only", exit off ⇒ ScopedResolverOnly), so pf-floor-absent is correct for the stable posture.
- But the daemon briefly transitions toward FullyProtected (pins Ethernet — a FullyProtected-only action) then rolls back. Most likely an unstable auto-exit selection (the cross-network exit debian-headless-4 @192.168.65.x flapping) drives exit_mode Off→FullTunnel→Off, so macos_dns_posture flaps ScopedResolverOnly→FullyProtected→ScopedResolverOnly. During the FullyProtected attempt the pf floor does not install (pf-rules 0) — so it is a HALF/failed FullyProtected apply that rolls back (pins applied before/around the floor step, or the floor never persists on macOS).

## Two independent defects to fix
- **D1 (orchestrator, primary):** the live-lab DnsFailclosed probe runs `macos-dns-failclosed-check` with NO `--posture` (crates/rustynet-cli/src/vm_lab/mod.rs:10298, via `build_argv`; `build_argv_with_extra_args` at :10191 is the mechanism to add it), so it DEFAULTS to fully_protected (crates/rustynetd/src/macos_dns_failclosed.rs:150). A ScopedResolverOnly node can NEVER pass a fully_protected check. Fix: pass `--posture` matching each node's EXPECTED posture (scoped-resolver-only for a plain client; fully-protected for an exit/full-tunnel node) — validator CORRECTNESS, not weakening; MUST derive per-node so an exit node's missing floor is still caught. The check accepts the flag (rustynetd main.rs:2532).
- **D2 (daemon, secondary/root):** a plain macOS client should NOT flap to FullyProtected. Either the auto-exit selection is wrongly/unstably selecting the cross-network exit, or the FullyProtected pf-floor apply on macOS is not persisting (apply_pf_rules/verify_live_pf_dns_floor, phase10.rs ~4971/5058). The flap leaves a transient stranded Ethernet pin that fails even the scoped check in its ~13s window. Even with D1 fixed, validate is FLAKY if it lands in the flap window; D2 is the root fix. NEVER report a FullyProtected node healthy without the pf floor.

## Next
Delegated a grounded analysis to map D2's root path (auto_exit/desired_exit_mode/reconcile posture transition + macOS pf-floor apply). D1 is the clearest safe win to implement + re-prove first.
