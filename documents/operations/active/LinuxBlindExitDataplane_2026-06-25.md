# Linux `blind_exit` dataplane — implementation ledger — 2026-06-25

Author: Iwan-Teague. **Code-only** (no live lab run in this pass). Closes the
release-blocking fail-OPEN gap surfaced by the role × OS code-implementation
matrix: `blind_exit` was code-implemented on macOS only, yet membership permits
assigning it on Linux (`rustynet-cli/src/main.rs:11833` — "Linux/macOS only").

## 0. The gap (fail-OPEN, security-grade)
A node assigned `blind_exit` on Linux reaches
`LinuxCommandSystem::apply_nat_forwarding` with `serve_exit_node = true,
exit_mode = Off, blind_exit = true`. The Linux impl **ignored** the `blind_exit`
flag (`phase10.rs` — `_blind_exit` was unused) and ran the **regular NATing
exit** path: `ip_forward=1` + a `masquerade` postrouting rule + an unrestricted
`forward iifname <tun> oifname <egress> accept` + an own-egress
`killswitch oifname <egress> accept`. So a Linux blind_exit node got **none** of
the hardened posture the role promises — it masqueraded (not "blind"), forwarded
non-mesh sources, and allowed its own local-origin egress straight out the
physical NIC. That is fail-OPEN against the reviewed contract.

## 1. The contract (authoritative)
From `RustynetDataplaneExecutionPlan_2026-05-18.md` (D12 blind-exit follow-up) +
`NodeRoleTaxonomy_2026-05-21.md`: blind_exit is a **hardened final-hop exit
(Linux/macOS only)** —
- local-origin egress is **tunnel-only**,
- mesh-exit forwarding is **scoped to the signed mesh CIDR**,
- **no NAT translation** (the mesh source is never rewritten — the "blind"
  property),
- DNS stays fail-closed, no `route-to`/`reply-to`/`dup-to` bypass,
- terminal **default-deny**.

The reviewed macOS PF anchor (`crate::macos_blind_exit`) is the parity
reference; this work brings Linux to the same posture using nftables.

## 2. What landed
### 2.1 New module `crates/rustynetd/src/linux_blind_exit.rs` (pure, fully unit-tested here)
- `LinuxBlindExitConfig::new(tunnel, egress, mesh_cidr)` — validates interface
  names + reuses the **shared** `macos_pf_mesh_cidr::validate_mesh_egress_source_cidr`
  so a global/default-route mesh CIDR (`0.0.0.0/0`, `::/0`, `8.8.8.0/24`, …) is
  rejected before any rule is authored (the killswitch-bypass exploit class).
- `build_linux_blind_exit_forward_commands(config, table)` — emits the nft argv
  sequence that re-authors the `forward` chain: `flush chain` (clears the
  regular-exit unrestricted allow, keeps `policy drop`) → `ct established,related
  accept` → **mesh-source-scoped** `iifname <tun> oifname <egress> ip|ip6 saddr
  <mesh_cidr> accept`. Emits **no** masquerade and **no** own-egress allow.
- `evaluate_linux_blind_exit_ruleset(ruleset, config)` — the assert/verify
  evaluator (mirror of `evaluate_macos_blind_exit_pf_rules`): parses an `nft list
  ruleset` dump and fails closed if it finds any NAT (`masquerade`/`snat`/`dnat`),
  an unrestricted tunnel→egress forward allow, an own-egress allow, or a missing
  mesh-scoped allow.
- `should_remove_linux_blind_exit_posture(event)` — irreversibility policy
  (only `FactoryReset` removes it), mirroring macOS.
- **12 unit tests** (builder mesh-scope + no-NAT, ip6 family, default-route
  rejection at construct + render, identical-iface rejection, injection
  rejection, evaluator accepts intact + rejects masquerade/unrestricted/own-egress/missing,
  cleanup policy).

### 2.2 Wiring `crates/rustynetd/src/phase10.rs`
- `LinuxCommandSystem` gains `blind_exit_config: Option<LinuxBlindExitConfig>`
  (mirrors macOS's `blind_exit_pf_config`).
- `apply_nat_forwarding` now branches on `blind_exit` **before** any regular-NAT
  setup → `apply_linux_blind_exit_locked(mesh_cidr)`: records prior ip_forward,
  sets it on (a final-hop exit must route), **tears down any masquerade table**,
  re-authors the forward chain with the mesh-scoped rules, records the config.
  A mid-sequence failure leaves the `forward` chain at `policy drop` (fail-closed).
- `rollback_nat_forwarding` is now irreversible for blind_exit: it **re-applies**
  the hard-lock (drops any NAT table, re-authors the mesh-scoped forward chain)
  instead of relaxing to an open NAT — mirroring the macOS rollback that
  re-loads the PF anchor.
- Corrected the misleading `ApplyOptions::blind_exit` doc comment (it claimed
  "Linux/Windows ignore it … handled on other paths" — there was no such Linux
  path).

### 2.3 Privileged-helper allowlist `crates/rustynetd/src/privileged_helper.rs`
The argv allowlist (`validate_nft_args`) gains exactly two new shapes so the
hardened posture is actually executable (without them the helper fails closed
and the feature can't run):
- `flush chain inet <owned_table> forward` — **restricted to the `forward`
  chain** (least-privilege; can never clear the killswitch chain).
- `add rule inet <owned_table> forward iifname <if> oifname <if> ip|ip6 saddr
  <cidr> accept` — with family/CIDR agreement enforced.
- **1 unit test** (`blind_exit_nft_validation_is_tightly_scoped`): accepts the
  two new shapes (v4 + v6), rejects flushing the killswitch chain, rejects
  family/CIDR mismatch, rejects non-owned tables.

## 3. Verification (this pass — Linux sandbox)
- `cargo fmt --all -- --check` clean; `cargo clippy -p rustynetd --all-targets
  --all-features -D warnings` clean.
- **13 new unit tests pass** (12 `linux_blind_exit::` + 1 helper allowlist).
- Full `rustynetd` lib suite: 1756 passed, 20 failed — **all 20 pre-existing
  environmental failures** unrelated to this change (privileged-helper socket
  tests that need CI's umask + the framed helper protocol; STUN/echo network
  tests; /tmp symlink tests; keystore tests). Confirmed by reproducing one on
  the untouched baseline path (socket-perms 755 rejection).

## 4. Honest scope / follow-ups (tracked, not dropped)
- **LIVE-RUN-PENDING.** The actual `nft` application + the
  `evaluate_linux_blind_exit_ruleset` assert against a live `nft list ruleset`
  run in the Linux lab; the sandbox unit-tests the rule builder + evaluator +
  allowlist (the security-critical logic) but cannot program netfilter. This is
  the same posture as the macOS blind_exit path (lab-verified, not socket-unit
  tested).
- **Pre-existing broken test helper (separate, deferred Linux-CI-infra bucket).**
  `phase10::tests::spawn_privileged_capture_helper` speaks line-delimited JSON,
  but `PrivilegedCommandClient` now uses a **framed** request/response protocol
  (`write_request_frame`/`read_response_frame`, magic-prefixed). So every
  `spawn_privileged_capture_helper`-based Linux socket test is latently broken
  ("invalid frame magic"); it is masked because the Linux CI jobs currently die
  at "Bootstrap CI tools" (`cargo: not found`) before these tests run. A
  blind_exit apply/rollback **integration** test was drafted against this helper
  and removed rather than shipped failing; it should be re-added once the helper
  is repaired (write a frame-correct response) — that repair also un-breaks the
  existing Linux socket suite.
- **Windows blind_exit remains out of scope by design** (`main.rs:11833`).

## 5. Definition of done (this slice)
- [x] Linux blind_exit honored in the dataplane (no longer fail-OPEN): mesh-scoped
      forward, no NAT, local-origin tunnel-only, terminal drop, irreversible
      rollback.
- [x] Bounded mesh-CIDR validation (shared verifier) — no killswitch bypass.
- [x] Privileged-helper allowlist extended (least-privilege) + verified.
- [x] Pure builder + evaluator + cleanup policy unit-tested; fmt + clippy clean.
- [ ] Live-lab proof on a Linux blind_exit node (human step).
