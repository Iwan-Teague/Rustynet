# macOS pf DNS-Block Floor Persistence — Root Cause + Minimal Fix (2026-09-03)

Status: root-caused from code (all paths cited file:line); minimal fail-closed fix
implemented in `crates/rustynetd/src/phase10.rs` (§4). Context: tick 43 of
`AutonomousManagerLog_2026-09-01.md`, `D2RootCauseAndFix_2026-09-03.md`,
`MacosClientDnsFailclosedFlapDiagnosis_2026-09-03.md`.

Live signature being explained (macos-utm-1, FULL-TUNNEL client ⇒ posture
`FullyProtected`): the FullyProtected apply runs, pins Ethernet DNS to loopback, and
PASSES `apply_pf_rules` + `verify_live_pf_dns_floor` — so the pf DNS-block floor was
live at apply time (the pin loop runs AFTER the floor + verify, §2). By
`validate_baseline_runtime` the floor is gone: `pfctl -a com.rustynet -s rules` = 0,
`pfctl -a com.apple/rustynet_g -s rules` = 0, and `macos-dns-failclosed-check`
reports `"pf DNS block floor not verified ... anchors scanned: []"`. No
`DnsApplyFailed`/rollback anywhere in the daemon log. The anchor is FLUSHED between a
successful apply and validate, leaving pin-without-floor.

## 1. Q1 — How the `com.apple/rustynet_g{N}` anchor is loaded

- **Anchor name.** `current_anchor_name()` (`phase10.rs:3880-3885`) returns
  `com.apple/rustynet_g{self.generation}` (blind-exit override first). The
  generation number comes from `set_generation` (`phase10.rs:4796-4798`); the Linux
  side's parallel name is `rustynet_g{N}` (`phase10.rs:2610`).
- **Load call.** `apply_pf_rules` (`phase10.rs:4031-4067`) does NOT run `pfctl`
  itself. It encodes a structured `MacosPfLoadSpec::Killswitch { generation,
  strict_fail_closed, spec }` (built from `killswitch_spec()`,
  `phase10.rs:3900-3921`) and invokes the privileged `MacosPfLoad` helper builtin
  (`phase10.rs:4054-4062`). The helper re-renders the rule text from the reviewed
  builders (`execute_macos_pf_load`, `privileged_helper.rs:1249-1263`), writes it to
  a root-owned temp under `/var/run/rustynet-pf` (`MACOS_PF_SPOOL_DIR`,
  `privileged_helper.rs:1605-1619`), and loads it with
  `pfctl -n -a <anchor> -f <tmp>` (syntax pre-check) then
  `pfctl -a <anchor> -f <tmp>` (`run_macos_pfctl_load`,
  `privileged_helper.rs:1705-1712`).
- **Under Apple's parent anchor — yes.** The anchor is `com.apple/rustynet_g{N}`, so
  it is a sub-anchor of the system's own `com.apple` namespace.
- **Evaluated — yes, while loaded.** Stock macOS `/etc/pf.conf` carries the wildcard
  reference `anchor "com.apple/*"`, which evaluates every sub-anchor under
  `com.apple` (confirmed in-repo: `AdversarialSecurityReview_2026-07-29.md:1501`;
  `macos_ipv6_leak.rs:265` renders its terminal block against that same wildcard).
  So once loaded, the floor's `block drop` rules are live filter rules.
- **Persisted — no.** Nothing on disk references `rustynet_g{N}`: there is no
  `load anchor` entry for it in any pf.conf, and the rendered rules text lives only
  in the (deleted) root-owned temp. The anchor is kernel-resident only. It survives
  until ANY later full ruleset operation that does not re-include it — `pfctl -f`
  (whose man page on macOS warns: "could result in flushing of rules present in the
  main ruleset added by the system at startup"), `pfctl -F all`, or a
  `pfctl -a com.apple -f …` parent reload. Persistence is therefore whatever the
  kernel keeps, not a config file.

## 2. Q2 — What flushes it between apply and validate

First, the proof the floor WAS live at apply time: `apply_dns_protection`
(`phase10.rs:5075-5101`) runs `apply_pf_rules(false)` then
`verify_live_pf_dns_floor()` (`phase10.rs:4770-4792` — queries
`pfctl -a com.apple/rustynet_g{N} -s rules` and demands both labeled block rules)
and rolls back on failure — all BEFORE the networksetup pin loop
(`phase10.rs:5103+`; ends `dns_posture = FullyProtected`, `phase10.rs:5225`). So "pins exist ⇒
floor was verified live moments earlier" is code-ordered.

Enumerating the candidates:

- **(a) External macOS pf reload — the only remaining candidate.** The guest
  evidence is a TOTAL wipe of rustynet-owned anchors ("anchors scanned: []" covers
  both `com.apple/rustynet_g*` AND `com.rustynet/…`, §(d)) with zero daemon-side
  error. macOS re-applies `/etc/pf.conf` on network-configuration changes, and the
  FullyProtected apply itself churns the SystemConfiguration store right after the
  floor is verified: every `networksetup -setdnsservers` pin write in the pin loop
  (`phase10.rs:5103+`) fires a configd network-change event. A reload triggered in
  that window drops the just-verified anchor kernel-side, silently — matching the
  tick-43 observation exactly (floor live at apply, gone by validate, no
  `DnsApplyFailed`, no rollback). Cheap falsification probe on the guest:
  `sudo pfctl -s Anchors` immediately before/after a no-op `networksetup
  -setdnsservers` write, and after an explicit `sudo pfctl -f /etc/pf.conf`.
- **(b) The daemon's own `prune_owned_tables` — excluded.** Since the D2 fix it
  re-establishes the floor immediately after flushing:
  `phase10.rs:4817-4826` flushes every owned anchor, then
  `if self.has_live_loopback_dns_pins() { self.apply_pf_rules(false)?; }`
  (`phase10.rs:4839-4840`). On a FullyProtected node `dns_protected` short-circuits
  the pin probe true (`phase10.rs:3927-3933`), so every prune re-renders WITH the
  floor (M3 latch, `killswitch_spec`, `phase10.rs:3900-3919`). Prune runs only
  inside the generation apply, before the DNS arm (`phase10.rs:7209` vs
  `7444`), and a re-render failure propagates ⇒ rollback ⇒ `DnsApplyFailed` —
  which the log does not show.
- **(c) The enforce restart — excluded.** The restart re-prunes only as part of the
  post-restart generation apply, which re-floors before the DNS arm (same ordering
  as (b): `prune_owned_tables` at `phase10.rs:7209`, DNS arm at
  `7444`). A restart alone never flushes without a following re-render.
- **(d) Generation churn / stale-N — excluded.** The verifier does not look at a
  fixed N: it scans ALL rustynet-owned anchors by prefix
  (`MACOS_RUSTYNET_OWNED_ANCHOR_PREFIXES = [com.apple/…, com.rustynet/]`,
  `macos_dns_failclosed.rs:76-83`) and reports what it scanned
  (`pf_anchors_scanned`). "anchors scanned: []" therefore means ZERO owned anchors
  existed — not a wrong N. Any `rustynet_g{M}` would have counted.

## 3. Q3 — The reconcile loop does NOT re-assert a flushed floor (the real gap)

`maybe_assert_dns_posture` (`daemon.rs:10890-10935`) re-asserts DNS posture every
`DEFAULT_DNS_POSTURE_ASSERT_INTERVAL_SECS = 30` (`daemon.rs:527`) while the node is
healthy and `dns_protected()`. On drift it records the reason and schedules exactly
one re-apply via `dns_posture_reassert_pending` (`daemon.rs:10933-10935`), which
re-enters the normal generation apply (`daemon.rs:10491-10499`) — that ladder is
sound.

But the macOS assert it calls, `MacosCommandSystem::assert_dns_protection`
(`phase10.rs:5250-5319`, `FullyProtected` arm), verifies only:

1. the in-memory `dns_protected` flag (`phase10.rs:5261-5266`),
2. the RENDERED spec text — `render_pf_rules(false)` checked for the pass/block
   rules (`phase10.rs:5266-5275`) — pure in-memory text, no `pfctl` query,
3. the system-configuration pins (`phase10.rs:5286-5303`).

The LIVE anchor is never queried. This is precisely the limitation the S1/S4 design
review already disclosed: "the assert's pf half validates the **rendered** ruleset …
S1 therefore re-detects SC posture drift and renderer drift, but not an
externally-flushed anchor on a healthy node"
(`MacosDnsFailclosedS1S4DesignAdversarialReview_2026-08-31.md:64`;
`MacosDnsFailclosedS1S4FixDesign_2026-08-31.md:74`). At the time it was deemed
acceptable because "the next generation apply re-renders" — but a FullyProtected
node that does not change generations NEVER re-renders, so the disclosed blind spot
is exactly the tick-43 failure: the floor is externally flushed, the periodic assert
passes on stale evidence, no re-apply is ever scheduled, and pin-without-floor holds
indefinitely.

## 4. The fix (implemented, fail-closed, no check weakened)

The unambiguous repair is to close the disclosed blind spot: the `FullyProtected`
arm of `MacosCommandSystem::assert_dns_protection` now ends with
`self.verify_live_pf_dns_floor()?` (the existing post-apply verifier,
`phase10.rs:4770-4792`, reused verbatim — `pfctl -a <anchor> -s rules`, both labeled
block rules required). Effects:

- An externally flushed floor now FAILS the 30-second periodic assert; the existing
  reconcile machinery (`daemon.rs:10927-10935`) schedules the single re-apply, and
  the normal generation apply re-installs floor + pins fail-closed. No new failure
  path, no escalation change.
- The assert call inside the apply flow (`phase10.rs:7444`) double-verifies the
  floor it just applied — harmless (same query `apply_dns_protection` already ran).
- The node must actually HOLD the floor: pin-without-floor degrades to a ≤30 s
  window followed by a fail-closed re-apply, instead of persisting to validate.
- Verification: source-pinned unit test
  `macos_assert_dns_protection_verifies_live_pf_floor_while_fully_protected`
  (`phase10.rs`, tests module) asserts the live-floor check sits inside the
  `FullyProtected` arm, after the render-text and SC-pin halves, gating the assert's
  success. The pre-existing floor message was made context-neutral
  ("pf DNS-block floor not live …", no longer "after apply") since the verifier now
  serves both the apply and assert paths; no test or gate pinned the old string.

## 5. Remaining open sub-question

The exact external trigger of the flush (configd re-applying `/etc/pf.conf` on the
network-change events the pin loop itself fires vs. another guest actor) is
identified only circumstantially (§2a). The fix above makes the daemon hold the
floor regardless of the trigger; the guest-side falsification probe in §2a should be
run on the next re-prove to name the trigger definitively in this document.
