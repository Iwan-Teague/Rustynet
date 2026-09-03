# D2 Root Cause And Fix — macOS Plain-Client DNS Posture Flap (2026-09-03)

Status: root-caused from code (all paths cited); minimal fail-closed fix implemented in
`crates/rustynetd/src/phase10.rs` (see §4). Companion analysis:
`D2PostureFlapAnalysis_2026-09-03.md`; multi-factor diagnosis:
`MacosClientDnsFailclosedFlapDiagnosis_2026-09-03.md`.

## 1. Answer to the bounded question

**The plain client flaps because it is not actually unassigned, and because the daemon's
enforcement mode transitions mid-run.** There is no intermittent exit *selection*: the
signed assignment bundle permanently names an exit for every plain client, and the
bootstrap→enforce transition flips the posture decision input once, after which every
failed FullyProtected apply re-enters the flap loop on its own.

### 1.1 The lab always assigns the primary exit to every plain client

`build_bundle_env` (`crates/rustynet-cli/src/vm_lab/orchestrator/stage/distribute_assignments.rs:127-156`)
emits `ASSIGNMENTS_SPEC` with:

```rust
let exit_part = if matches!(a.role, NodeRole::Exit | NodeRole::BlindExit) {
    "-"
} else {
    exit_node_id.as_str()
};
```

Every `Client` node — including `macos-utm-1` — is assigned to the run's single exit
node (`debian-headless-4` in the flapping runs). There is no "plain client with no exit
assignment" in this pipeline; the stage fails closed without an exit
(`distribute_assignments.rs:171-174`).

### 1.2 The daemon derives `selected_exit_node` from the bundle's exit routes

The signed wire bundle has no `selected_exit_node` field; the daemon-side parser derives
it from route kinds (`crates/rustynetd/src/daemon.rs:15280-15289`):

```rust
if matches!(kind, RouteKind::ExitNodeDefault | RouteKind::ExitNodeLan) {
    ...
    selected_exit_node = Some(via);
}
```

The exit-node assignment produces `exit_default` routes for assigned clients (pinned by
`crates/rustynet-cli/src/ops_e2e.rs:8130`), so `bundle.selected_exit_node` is
**always `Some(exit_node_id)`** for `macos-utm-1`, stable across reconciles. The
validation at `daemon.rs:2448-2462` only rejects *inconsistent* values (blind-exit
consumers, mismatched signed intent); a consistent `Some` is by-design accepted.

### 1.3 The posture input toggles once: bootstrap (non-enforcing) → enforce

- Bootstrap installs the macOS daemon with `--auto-tunnel-enforce false`
  (`crates/rustynet-cli/src/vm_lab/orchestrator/adapter/macos_install.rs:812-836`).
  Non-enforcing, bootstrap and reconcile take `desired_exit_mode()`
  (`daemon.rs:8891-8892`, `10631-10632`; `11003-11009`), which is `Off` because
  `self.selected_exit_node` is `None` (state purged on rebuild,
  `macos_traffic.rs:496-540`). `macos_dns_posture(Off, false)` = `ScopedResolverOnly`
  (`phase10.rs:801-807`) — the ~80% unpinned window, and the "deferred
  scoped_resolver_only" bootstrap log.
- `EnforceBaselineRuntime` re-installs the plist with `--auto-tunnel-enforce true` and
  bounces the daemon (`macos_install.rs:845-867`, restart + state-refresh at
  `1008-1029`). From then on, bootstrap (`daemon.rs:8885-8890`) and every generation
  apply (`daemon.rs:10625-10630`) compute `ExitMode::FullTunnel` whenever
  `auto_exit.is_some()` — which is **always** (§1.1-1.2). `macos_dns_posture(FullTunnel,
  false)` = `FullyProtected` → the pin loop (`phase10.rs:5151-5164`) pins Ethernet to
  `127.0.0.1`. This is the pinned window the sampler photographed.

### 1.4 Why the pinned state reverts (the visible flap)

The FullyProtected apply does not hold on this guest. Any failure after the pins —
notably `assert_dns_protection`'s demand that *every* enabled network service advertise
only loopback (`phase10.rs:5268-5285`), run immediately after the apply at
`phase10.rs:7410-7412` — fails the generation. The rollback restores each service's
backed-up DNS **before** dropping the pf floor (`rollback_dns_protection`,
`phase10.rs:5291-5319`; unpin at 5301, floor drop last at 5317), which is exactly the
observed revert to the DHCP baseline ("no DNS servers set"). The daemon then restricts
and retries (`daemon.rs:10795-10800`, re-entry via `will_apply_generation`,
`daemon.rs:10491-10499`), producing repeated short pinned windows until
`promote_to_permanent_if_over_limit` stops the ladder.

Two corroborating observations fall out of this loop rather than needing extra causes:

- **"pf-rules: 0 during the pinned window"**: the DNS-block floor lives in a pf
  *anchor* (`verify_live_pf_dns_floor`, `phase10.rs:4770-4792`); a collector reading the
  main ruleset sees 0 while the anchor floor is live (transitional-window variant:
  §3b of the companion analysis).
- **The harvest's "plain client, no exit assigned"**: `self.selected_exit_node` is only
  committed on a *fully successful* apply (`daemon.rs:10740`). A node stuck in the
  apply↔rollback flap never commits, so mesh status reports `none` — the "no exit
  assigned" reading is a **symptom** of the flap loop, not evidence about the bundle.

### 1.5 Paths enumerated and excluded

- Manual `ExitNodeSelect`/`ExitNodeOff` IPC (`daemon.rs:9364-9398`): not issued in the
  headless lab run.
- Crash-snapshot restore of `selected_exit_node` (`daemon.rs:10389`,
  `resilience.rs:112-179`): boot-time only, and the state file is purged on rebuild.
- Traversal/membership-derived selection: none exists — `desired_exit_mode()` mirrors
  only `self.selected_exit_node`; `serve_exit_node` is false for a plain client
  (`daemon.rs:11011-11017`). Membership flapping *does* gate bundle *verification*
  (`policy_gate_auto_tunnel`, `daemon.rs:5487-5550`) and would restrict the node, but
  restriction alone neither pins nor unpins; it cannot produce the observed posture.
- `rustynetd.state` residue: excluded — the macOS rebuild adapter purges it
  (`macos_traffic.rs:496-540`) and the guest file was absent.

## 2. Root cause of the invariant violation (pin-without-floor sighting)

The generation flow flushes **all** owned pf anchors in `prune_owned_tables`
(`phase10.rs:4817-4826`) *before* the DNS arm re-renders (`phase10.rs:7177` vs
`7390-7414`). Loopback service pins are system-configuration state that prune never
touches, so from the prune until the DNS arm's floor render — and for good, when that
apply fails and rolls back — the node sits in the **pin-without-floor half state** the
DnsPosture invariant forbids. The M3 latch (`killswitch_spec`,
`phase10.rs:3900-3919`) already guarantees every *subsequent* render carries the floor
while pins persist; the gap is the prune→DNS-arm interval itself.

## 3. Why the posture selection was NOT changed

Under `auto_tunnel_enforce`, a client with a signed exit assignment legitimately runs
the FullyProtected posture — that is the designed enforcement path and Linux parity
depends on it. Gating `FullTunnel` off a "plain client" (e.g. by role) would weaken
signed-assignment enforcement, and hysteresis on the assignment watermark would mask a
real assignment change. No selection-side change is made; the invariant repair below is
the minimal fail-closed fix.

## 4. Fix implemented

`MacosCommandSystem::prune_owned_tables` (`crates/rustynetd/src/phase10.rs`) now
re-establishes the pf DNS floor immediately after the anchor flush whenever live
loopback pins exist (`has_live_loopback_dns_pins()`), before returning success:

- The M3 latch puts the floor into that render (`killswitch_spec`), so one
  `apply_pf_rules(false)` closes the prune→DNS-arm gap.
- Failure propagates: the generation flow rolls the apply back fail-closed
  (`phase10.rs:7178-7187`), and rollback restores pins **before** dropping the floor
  (`5291-5319`) — so no error path can strand pins over a dropped floor, and a failed
  FullyProtected attempt can no longer leave a stranded half state.
- Off-macOS the pins probe is `false` (`phase10.rs:3937-3940`), so other platforms'
  prune behavior is unchanged. No other production caller of `prune_owned_tables`
  exists (verified: the only call site is the generation flow at `phase10.rs:7177`).

Verification: `macos_prune_owned_tables_reestablishes_dns_floor_while_pins_live`
(source-pinned ordering test, same rationale as
`macos_apply_writes_backup_before_first_mutation_argv` — exercising the ordering
behaviorally requires the live privileged helper, which only exists on a lab guest).

## 5. Remaining (out of scope here)

- D1: the orchestrator's DnsFailclosed probe must pass an explicit `--posture` per
  node (`MacosClientDnsFailclosedFlapDiagnosis_2026-09-03.md` §"Two independent
  defects") — validator correctness, unchanged by this fix.
- Why the FullyProtected apply ultimately fails on this guest (which sub-step of the
  pin/assert sequence errors) requires the guest journal; the invariant repair holds
  regardless of which step fails.
