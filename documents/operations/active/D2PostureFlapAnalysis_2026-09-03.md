# D2 Posture-Flap Analysis — macOS Plain-Client DNS FullyProtected Flap (2026-09-03)

Status: analysis (read-only code trace; no code changed).
Scope: observed live-lab behavior on `macos-utm-1` (plain macOS mesh client, exit off).
Symptom: while running, the daemon briefly PINNED the Ethernet service's DNS to
`127.0.0.1` (a FullyProtected-only action) for ~13 seconds with pf rules apparently
absent, then UNPINNED Ethernet back to "no DNS servers set". Posture flapped
ScopedResolverOnly → (FullyProtected attempt) → ScopedResolverOnly; the
FullyProtected attempt never appeared to install the pf DNS-block floor.

All paths below are relative to `crates/rustynetd/src/` unless noted.

---

## 1. The posture rule

`macos_dns_posture(exit_mode, serve_exit_node)` — `phase10.rs:801-807`:
returns `FullyProtected` iff `exit_mode == ExitMode::FullTunnel || serve_exit_node`,
otherwise `ScopedResolverOnly`. `Untouched` is reserved for the
`protected_dns=false` opt-out at the apply site, never produced by this function
(unit tests `phase10.rs:810-859` pin the truth table).

For a plain client, `serve_exit_node` is false: `is_serving_exit_node()`
(`daemon.rs:11011-11017`) is true only for the `blind_exit` role or an admin
advertising the blind-exit default route. Therefore the observed flap to
FullyProtected means, exactly:

> `reconcile_exit_mode` flipped `Off` → `FullTunnel` → `Off`,
> i.e. the effective "route through exit" selection flipped
> `None` → `Some(..)` → `None`.

## 2. Root cause 1 — the flap source: `selected_exit_node` instability

### 2.1 What drives exit mode at reconcile

`fn reconcile` (`daemon.rs:10405`) loads the **signed auto-tunnel assignment
bundle** (only when `self.auto_tunnel_enforce`, `daemon.rs:10455-10473`) and takes

- `auto_exit = envelope.bundle.selected_exit_node.clone()` (`daemon.rs:10530`)

then computes (`daemon.rs:10623-10633`):

- blind_exit → `Off`
- `auto_tunnel_enforce` → `FullTunnel` iff `auto_exit.is_some()`, else `Off`
- otherwise → `desired_exit_mode()` (`daemon.rs:11003-11009`), which is
  `FullTunnel` iff `self.selected_exit_node.is_some()`

and derives the DNS posture on macOS (`daemon.rs:10634-10638`) via
`macos_dns_posture(reconcile_exit_mode, serve_exit_node)`. On success under
`auto_tunnel_enforce` it commits `selected_exit_node = auto_exit`
(`daemon.rs:10736` None-arm, `10740` Some-arm). The bootstrap path mirrors this:
`daemon.rs:8802` (`envelope.bundle.selected_exit_node.clone()`), exit-mode check
at `daemon.rs:8886`, posture at `daemon.rs:8895`.

Conclusion: in an auto-tunnel-managed headless lab client, **the signed
assignment bundle's `selected_exit_node` field is the sole flap driver**. Every
`Some↔None` transition of that field between reconciles flips
`reconcile_exit_mode` and therefore the DNS posture. The ~13 s observed window is
consistent with one assignment watermark interval (the bundle is only re-applied
when `envelope.watermark != last_applied_assignment`, `daemon.rs:10475-10477`).

### 2.2 The bundle field and its validation

The daemon-side artifact structs:

- `AutoTunnelBundle` (`daemon.rs:2973-2983`) carries both
  `signed_exit_node_id: Option<String>` (2980) and
  `selected_exit_node: Option<String>` (2982).
- `AutoTunnelBundleEnvelope` (`daemon.rs:2967-2970`) wraps bundle + watermark.
- Artifact on guest: `{MACOS_STATE_ROOT}/trust/rustynetd.assignment` (+ `.watermark`)
  — see the purge list in
  `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/macos_traffic.rs:527-528`.
- Loader/verifier: `load_auto_tunnel_bundle` via
  `verify_signed_assignment_state_artifact` (`daemon.rs:3450-3507`), which
  surfaces `selected_exit_node` in `SignedAssignmentVerificationReport`
  (`daemon.rs:3371-3379`, conversion at 3505) and is logged verbatim by the CLI
  (`crates/rustynet-cli/src/main.rs:7103-7109`).

Note: `rustynet-control`'s `SignedAutoTunnelBundle` wire type has **no**
`selected_exit_node` field (routes use `AutoTunnelRouteKind{Mesh,ExitNodeLan,ExitNodeDefault}`,
`crates/rustynet-control/src/lib.rs:2132-2166`, builder 2635-2796) — the field is a
daemon-side assignment-artifact extension, so its value is whatever the
admin-side assignment emitter last signed into `rustynetd.assignment`. The
daemon refuses inconsistent values fail-closed: a `blind_exit` node may never
consume a `selected_exit_node` assignment, and a `Some(exit)` must match the
signed exit intent, else `"assignment selected_exit_node does not match signed
exit intent"` (`daemon.rs:2448-2462`).

### 2.3 Alternative triggers (examined, not the cause here)

- Manual selection: `IpcCommand::ExitNodeSelect` (`daemon.rs:9364-9388`) /
  `ExitNodeOff` (9389-9398). The lab client runs headless auto mode; no IPC
  select/off was issued, so this is not the trigger.
- Crash-residue restore: `resilience.rs:39` persists `selected_exit_node` in the
  snapshot ("selected_exit_node=none|<val>", `resilience.rs:112-179`), restored at
  `daemon.rs:10389`. This explains boot-time residue, not a mid-run flap — but it
  is the same residue class the orchestrator already hit live: the macOS rebuild
  adapter purges `rustynetd.state` precisely because "a May-31
  `selected_exit_node=exit-1` survived a clean rebuild" and reconcile failed
  closed with "selected exit node is not active: exit-1"
  (`macos_traffic.rs:496-506`). **Stale/unstable exit selection is a
  previously-observed, documented failure mode of this exact field.**

### 2.4 Verdict for root cause 1

The plain client's exit selection (`selected_exit_node` from the signed
assignment bundle) flipped `Some↔None` between two consecutive reconciles. Each
flip propagated: bundle → `auto_exit` (10530) → `reconcile_exit_mode`
(10623-10633) → `macos_dns_posture` (phase10.rs:801-807, applied via the DNS arm
`phase10.rs:7390-7414`) → full DNS-protection apply/rollback. Evidence that the
selection itself is unstable (rather than the posture code) comes from the
already-recorded live residue incident (`macos_traffic.rs:496-506`) and from the
mesh-status evaluator deliberately excluding `selected_exit_node` drift from its
contract (`crates/rustynetd/src/linux_mesh_status.rs:440-457`) — drift here is
known and expected to be noisy.

## 3. Root cause 2 — "pinned with pf rules = 0": no persistent half-state exists

The apply/rollback ordering in `MacosCommandSystem` makes a durable
pin-without-floor state unreachable:

1. `apply_dns_protection` (`phase10.rs:5058-5210`) orders strictly:
   verify loopback resolver live (5066) → `apply_pf_rules(false)` floor (5068;
   failure aborts **before any pin**) → `verify_live_pf_dns_floor` (5076;
   failure → `rollback_after_failed_apply`, still no pins) → backup capture with
   the M1 residue guard refusing loopback in the baseline (5100-5141) → **pin
   loop** `networksetup setdnsservers 127.0.0.1` per service (5151-5164; failure
   → rollback) → resolv.conf (5180-5187) → scoped file (5200-5207) → posture set
   (5208). Floor-first is invariant.
2. `verify_live_pf_dns_floor` (`phase10.rs:4770-4792`) queries the **pf anchor**
   ruleset (`pfctl -a <anchor> -s rules`) and requires the udp+tcp block/53
   rules — the floor lives in an anchor, NOT the main ruleset.
3. Rollback unpins **before** unflooring: `rollback_dns_protection`
   (`phase10.rs:5291-5319`) restores per-service DNS from backup first (5301),
   resolv.conf (5306) and scoped file (5313) best-effort, and drops the pf floor
   LAST (5317). `rollback_after_failed_apply` (4675-4680) delegates to it.
4. The M3 latch keeps the floor rendered whenever pins are live:
   `dns_protected: self.dns_protected || self.has_live_loopback_dns_pins()`
   (`phase10.rs:3911`, probe at 3927-3961, fail-closed on unreadable SC).
5. Drift detectors: `assert_dns_protection` (5233-5289) demands floor + all pins
   for FullyProtected; `apply_scoped_resolver_only` (4701-4731) **refuses** to
   run Scoped while any service still pins loopback; `assert_scoped_resolver_posture`
   (4738-4764) errors on pin-without-floor drift under Scoped.

Given that, the sighting has two consistent explanations:

- **(a) Observation methodology (most likely).** The pf floor is installed in an
  anchor (`phase10.rs:4774-4776`). A collector reading the main ruleset
  (`pfctl -s rules`) reports "0 rules" while the anchor floor is live. The
  pinned ~13 s window is then simply a **successful** FullyProtected apply
  (floor + pins), ending when the next reconcile flipped back to Scoped and
  `rollback_dns_protection` restored the Ethernet service to its backed-up
  baseline — an empty DHCP DNS set, i.e. the observed "no DNS servers set"
  (5301). The unpin-to-empty final state is exactly what a restore-from-backup
  produces, not a degradation.
- **(b) Transitional window inside one generation apply.** Within a single
  generation, `prune_owned_tables` (`phase10.rs:4817-4826`, which flushes ALL
  owned anchors, `pfctl -a <anchor> -F all`, and clears the anchor name) runs at
  `phase10.rs:7177-7187` — BEFORE the DNS posture arm at 7390-7414. If the
  previous posture was FullyProtected (pins live) and a sample lands between
  prune and the floor re-verify inside `apply_dns_protection`, anchors read 0
  while pins from the previous posture still exist. This window closes at the
  next pf render via the M3 latch (3911), or by rollback (5291-5319) if the
  apply fails, or by `force_fail_closed` on stage failure (7147-7155,
  7166-7174, 7178-7197). It is transient, bounded by one apply, and leaves no
  residue — but it is a real pin-without-floor interval.

## 4. Where the half-state invariant is NOT enforced during transition

- **Prune-vs-floor gap (§3b).** `prune_owned_tables` (4817-4826, call site
  7177-7187) wipes anchors without checking `has_live_loopback_dns_pins()`;
  nothing re-establishes the floor until the DNS arm's `apply_pf_rules`
  (5068). Fail-closed fix: after prune, if pins are live, immediately re-apply
  the pf floor before continuing (or prune after the DNS arm).
- **Posture flap amplification.** Each `selected_exit_node` flip triggers a full
  apply→(possibly)rollback cycle; the defer flag (`phase10.rs:7396-7408`) can
  additionally skip the Scoped sub-apply when the caller defers, leaving the
  prior posture running one more generation. This is fail-safe but noisy, and it
  is what makes the 13 s fully-protected window visible on a client that should
  never leave ScopedResolverOnly.
- Everything else is enforced: floor-first (5068→5076→5151), unpin-before-unfloor
  (5301 vs 5317), M3 latch (3911), M1 capture guard (5100-5141), scoped residue
  guard (4701-4731), drift asserts (4738-4764, 5233-5289), assignment validation
  (`daemon.rs:2448-2462`).

## 5. Minimal fix directions (fail-closed; no weakening)

1. **Posture-transition hysteresis in the daemon (primary).** Under
   `auto_tunnel_enforce`, only route `FullTunnel` into `ApplyOptions` when
   `envelope.bundle.selected_exit_node` is `Some(same node)` in **two
   consecutive** assignment watermarks (N and N−1); a flip, or
   Some→None/None→Some oscillation, resolves to `Off`/ScopedResolverOnly until
   stable. Flapping thus converges to the safer posture instead of thrashing
   full apply/rollback. Enforce at the `reconcile_exit_mode` computation
   (`daemon.rs:10623-10633`) and the bootstrap analog (`daemon.rs:8886`).
2. **Re-establish the floor after prune.** In the generation flow
   (`phase10.rs:7177-7187`), if `has_live_loopback_dns_pins()` is true after
   `prune_owned_tables`, re-apply the pf DNS floor before proceeding to the DNS
   arm, closing the §3b window. (M3 latch already guarantees the next render;
   this just closes the gap at prune time.)
3. **Anchor-visible verification/logging.** Stage collectors and operator-facing
   verification must query `pfctl -a <anchor> -s rules` (the rule
   `verify_live_pf_dns_floor` enforces, `phase10.rs:4770-4792`), and log line
   should say so explicitly, so "pf-rules 0" sightings are not misread as a
   missing floor.
4. **Keep every existing guard.** Floor-first ordering, unpin-before-unfloor,
   M1/M3, both residue guards, and the assignment validation
   (`daemon.rs:2448-2462`) stay untouched — they are what bounds the incident to
   13 seconds with zero residue.

## 6. Answer summary

1. **Why does a plain client flap to FullyProtected?** Its signed auto-tunnel
   assignment bundle's `selected_exit_node` flipped `Some↔None` between
   reconciles (`daemon.rs:10530` → `10623-10638`; posture rule
   `phase10.rs:801-807`). No other path sets `FullTunnel` for an unconfigured
   client: `desired_exit_mode` (11003-11009) mirrors `self.selected_exit_node`
   (manual IPC 9364-9398 unused here), `serve_exit_node` is false for a plain
   client (11011-11017), and the crash-snapshot restore (10389) is boot-time
   only. Instability of this field is a previously observed live failure
   (`macos_traffic.rs:496-506`).
2. **How could pins exist with pf-rules 0?** They durably cannot: floor is
   applied and live-verified before the first pin (5068/5076 vs 5151-5164),
   rollback unpins before unflooring (5301 vs 5317), and the M3 latch (3911)
   re-renders the floor while pins live. The sighting was either a main-ruleset
   read of an anchor-resident floor (4770-4792) or a sample inside the
   transient prune→DNS-apply gap (4817-4826 called at 7177-7187 before 7390-7414).
3. **Transition residue?** None persists; the only unenforced transitional
   window is prune-vs-floor (§4), closable per fix 2, with hysteresis (fix 1)
   removing the flap itself.
